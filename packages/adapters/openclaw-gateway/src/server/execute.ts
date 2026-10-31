import type {
  AdapterExecutionContext,
  AdapterExecutionResult,
  AdapterRuntimeServiceReport,
} from "@paperclipai/adapter-utils";
import { asNumber, asString, buildPaperclipEnv, parseObject } from "@paperclipai/adapter-utils/server-utils";
import crypto, { randomUUID } from "node:crypto";
import { WebSocket } from "ws";
import { GATEWAY_PROTOCOL_VERSION, parseConnectChallenge } from "./protocol.js";

type SessionKeyStrategy = "fixed" | "issue" | "run";

type WakePayload = {
  runId: string;
  agentId: string;
  companyId: string;
  taskId: string | null;
  issueId: string | null;
  wakeReason: string | null;
  wakeCommentId: string | null;
  approvalId: string | null;
  approvalStatus: string | null;
  issueIds: string[];
};

type GatewayDeviceIdentity = {
  deviceId: string;
  publicKeyRawBase64Url: string;
  privateKeyPem: string;
  source: "configured" | "ephemeral";
};

type GatewayRequestFrame = {
  type: "req";
  id: string;
  method: string;
  params?: unknown;
};

type GatewayResponseFrame = {
  type: "res";
  id: string;
  ok: boolean;
  payload?: unknown;
  error?: {
    code?: unknown;
    message?: unknown;
  };
};

type GatewayEventFrame = {
  type: "event";
  event: string;
  payload?: unknown;
  seq?: number;
};

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  expectFinal: boolean;
  onAccepted?: (payload: Record<string, unknown> | null) => void;
  timer: ReturnType<typeof setTimeout> | null;
};

type GatewayResponseError = Error & {
  gatewayCode?: string;
  gatewayDetails?: Record<string, unknown>;
  gatewayPayload?: Record<string, unknown>;
};

type GatewayConnectChallenge = {
  nonce: string;
  ts: number;
};

type GatewayClientOptions = {
  url: string;
  headers: Record<string, string>;
  onEvent: (frame: GatewayEventFrame) => Promise<void> | void;
  onLog: AdapterExecutionContext["onLog"];
};

type GatewayClientRequestOptions = {
  timeoutMs: number;
  /**
   * Two-phase request (the v4 `agent` method): the gateway first answers with
   * `status: "accepted"` and later sends a second `res` with the same id that
   * carries the terminal outcome. The accepted ack goes to `onAccepted`; the
   * promise settles on the terminal frame.
   */
  expectFinal?: boolean;
  onAccepted?: (payload: Record<string, unknown> | null) => void;
};

const DEFAULT_SCOPES = ["operator.admin"];
const DEFAULT_CLIENT_ID = "gateway-client";
const DEFAULT_CLIENT_MODE = "backend";
const DEFAULT_CLIENT_VERSION = "paperclip";
const DEFAULT_ROLE = "operator";

const SENSITIVE_LOG_KEY_PATTERN =
  /(^|[_-])(auth|authorization|token|secret|password|api[_-]?key|private[_-]?key)([_-]|$)|^x-openclaw-(auth|token)$/i;

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function parseOptionalPositiveInteger(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(1, Math.floor(value));
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) return Math.max(1, Math.floor(parsed));
  }
  return null;
}

function parseBoolean(value: unknown, fallback = false): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1") return true;
    if (normalized === "false" || normalized === "0") return false;
  }
  return fallback;
}

function normalizeSessionKeyStrategy(value: unknown): SessionKeyStrategy {
  const normalized = asString(value, "issue").trim().toLowerCase();
  if (normalized === "fixed" || normalized === "run") return normalized;
  return "issue";
}

function resolveSessionKey(input: {
  strategy: SessionKeyStrategy;
  configuredSessionKey: string | null;
  runId: string;
  issueId: string | null;
}): string {
  const fallback = input.configuredSessionKey ?? "paperclip";
  if (input.strategy === "run") return `paperclip:run:${input.runId}`;
  if (input.strategy === "issue" && input.issueId) return `paperclip:issue:${input.issueId}`;
  return fallback;
}

function isLoopbackHost(hostname: string): boolean {
  const value = hostname.trim().toLowerCase();
  return value === "localhost" || value === "127.0.0.1" || value === "::1";
}

function toStringRecord(value: unknown): Record<string, string> {
  const parsed = parseObject(value);
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    if (typeof entry === "string") out[key] = entry;
  }
  return out;
}

function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .filter((entry): entry is string => typeof entry === "string")
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeScopes(value: unknown): string[] {
  const parsed = toStringArray(value);
  return parsed.length > 0 ? parsed : [...DEFAULT_SCOPES];
}

function uniqueScopes(scopes: string[]): string[] {
  return Array.from(new Set(scopes.map((scope) => scope.trim()).filter(Boolean)));
}

function headerMapGetIgnoreCase(headers: Record<string, string>, key: string): string | null {
  const match = Object.entries(headers).find(([entryKey]) => entryKey.toLowerCase() === key.toLowerCase());
  return match ? match[1] : null;
}

function headerMapHasIgnoreCase(headers: Record<string, string>, key: string): boolean {
  return Object.keys(headers).some((entryKey) => entryKey.toLowerCase() === key.toLowerCase());
}

function getGatewayErrorDetails(err: unknown): Record<string, unknown> | null {
  if (!err || typeof err !== "object") return null;
  const candidate = (err as GatewayResponseError).gatewayDetails;
  return asRecord(candidate);
}

function extractPairingRequestId(err: unknown): string | null {
  const details = getGatewayErrorDetails(err);
  const fromDetails = nonEmpty(details?.requestId);
  if (fromDetails) return fromDetails;
  const message = err instanceof Error ? err.message : String(err);
  const match = message.match(/requestId\s*[:=]\s*([A-Za-z0-9_-]+)/i);
  return match?.[1] ?? null;
}

function toAuthorizationHeaderValue(rawToken: string): string {
  const trimmed = rawToken.trim();
  if (!trimmed) return trimmed;
  return /^bearer\s+/i.test(trimmed) ? trimmed : `Bearer ${trimmed}`;
}

function tokenFromAuthHeader(rawHeader: string | null): string | null {
  if (!rawHeader) return null;
  const trimmed = rawHeader.trim();
  if (!trimmed) return null;
  const match = trimmed.match(/^bearer\s+(.+)$/i);
  return match ? nonEmpty(match[1]) : trimmed;
}

function resolveAuthToken(config: Record<string, unknown>, headers: Record<string, string>): string | null {
  const explicit = nonEmpty(config.authToken) ?? nonEmpty(config.token);
  if (explicit) return explicit;

  const tokenHeader = headerMapGetIgnoreCase(headers, "x-openclaw-token");
  if (nonEmpty(tokenHeader)) return nonEmpty(tokenHeader);

  const authHeader =
    headerMapGetIgnoreCase(headers, "x-openclaw-auth") ??
    headerMapGetIgnoreCase(headers, "authorization");
  return tokenFromAuthHeader(authHeader);
}

function isSensitiveLogKey(key: string): boolean {
  return SENSITIVE_LOG_KEY_PATTERN.test(key.trim());
}

function sha256Prefix(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 12);
}

function redactSecretForLog(value: string): string {
  return `[redacted len=${value.length} sha256=${sha256Prefix(value)}]`;
}

function truncateForLog(value: string, maxChars = 320): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}... [truncated ${value.length - maxChars} chars]`;
}

function redactForLog(value: unknown, keyPath: string[] = [], depth = 0): unknown {
  const currentKey = keyPath[keyPath.length - 1] ?? "";
  if (typeof value === "string") {
    if (isSensitiveLogKey(currentKey)) return redactSecretForLog(value);
    return truncateForLog(value);
  }
  if (typeof value === "number" || typeof value === "boolean" || value == null) {
    return value;
  }
  if (Array.isArray(value)) {
    if (depth >= 6) return "[array-truncated]";
    const out = value.slice(0, 20).map((entry, index) => redactForLog(entry, [...keyPath, `${index}`], depth + 1));
    if (value.length > 20) out.push(`[+${value.length - 20} more items]`);
    return out;
  }
  if (typeof value === "object") {
    if (depth >= 6) return "[object-truncated]";
    const entries = Object.entries(value as Record<string, unknown>);
    const out: Record<string, unknown> = {};
    for (const [key, entry] of entries.slice(0, 80)) {
      out[key] = redactForLog(entry, [...keyPath, key], depth + 1);
    }
    if (entries.length > 80) {
      out.__truncated__ = `+${entries.length - 80} keys`;
    }
    return out;
  }
  return String(value);
}

function stringifyForLog(value: unknown, maxChars: number): string {
  const text = JSON.stringify(value);
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}... [truncated ${text.length - maxChars} chars]`;
}

function buildWakePayload(ctx: AdapterExecutionContext): WakePayload {
  const { runId, agent, context } = ctx;
  return {
    runId,
    agentId: agent.id,
    companyId: agent.companyId,
    taskId: nonEmpty(context.taskId) ?? nonEmpty(context.issueId),
    issueId: nonEmpty(context.issueId),
    wakeReason: nonEmpty(context.wakeReason),
    wakeCommentId: nonEmpty(context.wakeCommentId) ?? nonEmpty(context.commentId),
    approvalId: nonEmpty(context.approvalId),
    approvalStatus: nonEmpty(context.approvalStatus),
    issueIds: Array.isArray(context.issueIds)
      ? context.issueIds.filter(
          (value): value is string => typeof value === "string" && value.trim().length > 0,
        )
      : [],
  };
}

function resolvePaperclipApiUrlOverride(value: unknown): string | null {
  const raw = nonEmpty(value);
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function buildPaperclipEnvForWake(ctx: AdapterExecutionContext, wakePayload: WakePayload): Record<string, string> {
  const paperclipApiUrlOverride = resolvePaperclipApiUrlOverride(ctx.config.paperclipApiUrl);
  const paperclipEnv: Record<string, string> = {
    ...buildPaperclipEnv(ctx.agent),
    PAPERCLIP_RUN_ID: ctx.runId,
  };

  if (paperclipApiUrlOverride) {
    paperclipEnv.PAPERCLIP_API_URL = paperclipApiUrlOverride;
  }
  if (wakePayload.taskId) paperclipEnv.PAPERCLIP_TASK_ID = wakePayload.taskId;
  if (wakePayload.wakeReason) paperclipEnv.PAPERCLIP_WAKE_REASON = wakePayload.wakeReason;
  if (wakePayload.wakeCommentId) paperclipEnv.PAPERCLIP_WAKE_COMMENT_ID = wakePayload.wakeCommentId;
  if (wakePayload.approvalId) paperclipEnv.PAPERCLIP_APPROVAL_ID = wakePayload.approvalId;
  if (wakePayload.approvalStatus) paperclipEnv.PAPERCLIP_APPROVAL_STATUS = wakePayload.approvalStatus;
  if (wakePayload.issueIds.length > 0) {
    paperclipEnv.PAPERCLIP_LINKED_ISSUE_IDS = wakePayload.issueIds.join(",");
  }

  return paperclipEnv;
}

function buildWakeText(payload: WakePayload, paperclipEnv: Record<string, string>): string {
  const claimedApiKeyPath = "~/.openclaw/workspace/paperclip-claimed-api-key.json";
  const orderedKeys = [
    "PAPERCLIP_RUN_ID",
    "PAPERCLIP_AGENT_ID",
    "PAPERCLIP_COMPANY_ID",
    "PAPERCLIP_API_URL",
    "PAPERCLIP_TASK_ID",
    "PAPERCLIP_WAKE_REASON",
    "PAPERCLIP_WAKE_COMMENT_ID",
    "PAPERCLIP_APPROVAL_ID",
    "PAPERCLIP_APPROVAL_STATUS",
    "PAPERCLIP_LINKED_ISSUE_IDS",
  ];

  const envLines: string[] = [];
  for (const key of orderedKeys) {
    const value = paperclipEnv[key];
    if (!value) continue;
    envLines.push(`${key}=${value}`);
  }

  const issueIdHint = payload.taskId ?? payload.issueId ?? "";
  const apiBaseHint = paperclipEnv.PAPERCLIP_API_URL ?? "<set PAPERCLIP_API_URL>";

  const lines = [
    "Paperclip wake event for a cloud adapter.",
    "",
    "Run this procedure now. Do not guess undocumented endpoints and do not ask for additional heartbeat docs.",
    "",
    "Set these values in your run context:",
    ...envLines,
    `PAPERCLIP_API_KEY=<token from ${claimedApiKeyPath}>`,
    "",
    `Load PAPERCLIP_API_KEY from ${claimedApiKeyPath} (the token you saved after claim-api-key).`,
    "",
    `api_base=${apiBaseHint}`,
    `task_id=${payload.taskId ?? ""}`,
    `issue_id=${payload.issueId ?? ""}`,
    `wake_reason=${payload.wakeReason ?? ""}`,
    `wake_comment_id=${payload.wakeCommentId ?? ""}`,
    `approval_id=${payload.approvalId ?? ""}`,
    `approval_status=${payload.approvalStatus ?? ""}`,
    `linked_issue_ids=${payload.issueIds.join(",")}`,
    "",
    "HTTP rules:",
    "- Use Authorization: Bearer $PAPERCLIP_API_KEY on every API call.",
    "- Use X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID on every mutating API call.",
    "- Use only /api endpoints listed below.",
    "- Do NOT call guessed endpoints like /api/cloud-adapter/*, /api/cloud-adapters/*, /api/adapters/cloud/*, or /api/heartbeat.",
    "",
    "Workflow:",
    "1) GET /api/agents/me",
    `2) Determine issueId: PAPERCLIP_TASK_ID if present, otherwise issue_id (${issueIdHint}).`,
    "3) If issueId exists:",
    "   - POST /api/issues/{issueId}/checkout with {\"agentId\":\"$PAPERCLIP_AGENT_ID\",\"expectedStatuses\":[\"todo\",\"backlog\",\"blocked\"]}",
    "   - GET /api/issues/{issueId}",
    "   - GET /api/issues/{issueId}/comments",
    "   - Execute the issue instructions exactly.",
    "   - If instructions require a comment, POST /api/issues/{issueId}/comments with {\"body\":\"...\"}.",
    "   - PATCH /api/issues/{issueId} with {\"status\":\"done\",\"comment\":\"what changed and why\"}.",
    "4) If issueId does not exist:",
    "   - GET /api/companies/$PAPERCLIP_COMPANY_ID/issues?assigneeAgentId=$PAPERCLIP_AGENT_ID&status=todo,in_progress,blocked",
    "   - Pick in_progress first, then todo, then blocked, then execute step 3.",
    "",
    "Useful endpoints for issue work:",
    "- POST /api/issues/{issueId}/comments",
    "- PATCH /api/issues/{issueId}",
    "- POST /api/companies/{companyId}/issues (when asked to create a new issue)",
    "",
    "Complete the workflow in this run.",
  ];
  return lines.join("\n");
}

function appendWakeText(baseText: string, wakeText: string): string {
  const trimmedBase = baseText.trim();
  return trimmedBase.length > 0 ? `${trimmedBase}\n\n${wakeText}` : wakeText;
}

function joinWakePayloadSections(structuredWakePrompt: string, structuredWakeJson: string): string {
  const sections = [
    structuredWakePrompt.trim(),
    "Structured wake payload JSON:",
    "```json",
    structuredWakeJson,
    "```",
  ].filter((entry) => entry.trim().length > 0);
  return sections.join("\n");
}

function normalizeUrl(input: string): URL | null {
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function rawDataToString(data: unknown): string {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (Array.isArray(data)) {
    return Buffer.concat(
      data.map((entry) => (Buffer.isBuffer(entry) ? entry : Buffer.from(String(entry), "utf8"))),
    ).toString("utf8");
  }
  return String(data ?? "");
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

function derivePublicKeyRaw(publicKeyPem: string): Buffer {
  const key = crypto.createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" }) as Buffer;
  if (
    spki.length === ED25519_SPKI_PREFIX.length + 32 &&
    spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return spki.subarray(ED25519_SPKI_PREFIX.length);
  }
  return spki;
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function signDevicePayload(privateKeyPem: string, payload: string): string {
  const key = crypto.createPrivateKey(privateKeyPem);
  const sig = crypto.sign(null, Buffer.from(payload, "utf8"), key);
  return base64UrlEncode(sig);
}

function buildDeviceAuthPayloadV3(params: {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token?: string | null;
  nonce: string;
  platform?: string | null;
  deviceFamily?: string | null;
}): string {
  const scopes = params.scopes.join(",");
  const token = params.token ?? "";
  const platform = params.platform?.trim() ?? "";
  const deviceFamily = params.deviceFamily?.trim() ?? "";
  return [
    "v3",
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    token,
    params.nonce,
    platform,
    deviceFamily,
  ].join("|");
}

function resolveDeviceIdentity(config: Record<string, unknown>): GatewayDeviceIdentity {
  const configuredPrivateKey = nonEmpty(config.devicePrivateKeyPem);
  if (configuredPrivateKey) {
    const privateKey = crypto.createPrivateKey(configuredPrivateKey);
    const publicKey = crypto.createPublicKey(privateKey);
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const raw = derivePublicKeyRaw(publicKeyPem);
    return {
      deviceId: crypto.createHash("sha256").update(raw).digest("hex"),
      publicKeyRawBase64Url: base64UrlEncode(raw),
      privateKeyPem: configuredPrivateKey,
      source: "configured",
    };
  }

  const generated = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = generated.publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = generated.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const raw = derivePublicKeyRaw(publicKeyPem);
  return {
    deviceId: crypto.createHash("sha256").update(raw).digest("hex"),
    publicKeyRawBase64Url: base64UrlEncode(raw),
    privateKeyPem,
    source: "ephemeral",
  };
}

function isResponseFrame(value: unknown): value is GatewayResponseFrame {
  const record = asRecord(value);
  return Boolean(record && record.type === "res" && typeof record.id === "string" && typeof record.ok === "boolean");
}

function isEventFrame(value: unknown): value is GatewayEventFrame {
  const record = asRecord(value);
  return Boolean(record && record.type === "event" && typeof record.event === "string");
}

class GatewayWsClient {
  private ws: WebSocket | null = null;
  private pending = new Map<string, PendingRequest>();
  private challengePromise: Promise<GatewayConnectChallenge>;
  private resolveChallenge!: (challenge: GatewayConnectChallenge) => void;
  private rejectChallenge!: (err: Error) => void;

  constructor(private readonly opts: GatewayClientOptions) {
    this.challengePromise = new Promise<GatewayConnectChallenge>((resolve, reject) => {
      this.resolveChallenge = resolve;
      this.rejectChallenge = reject;
    });
    this.challengePromise.catch(() => {});
  }

  async connect(
    buildConnectParams: (challenge: GatewayConnectChallenge) => Record<string, unknown>,
    timeoutMs: number,
  ): Promise<Record<string, unknown> | null> {
    this.ws = new WebSocket(this.opts.url, {
      headers: this.opts.headers,
      maxPayload: 25 * 1024 * 1024,
    });

    const ws = this.ws;

    ws.on("message", (data) => {
      this.handleMessage(rawDataToString(data));
    });

    ws.on("close", (code, reason) => {
      const reasonText = rawDataToString(reason);
      const err = new Error(`gateway closed (${code}): ${reasonText}`);
      this.failPending(err);
      this.rejectChallenge(err);
    });

    ws.on("error", (err) => {
      const message = err instanceof Error ? err.message : String(err);
      void this.opts.onLog("stderr", `[openclaw-gateway] websocket error: ${message}\n`);
    });

    await withTimeout(
      new Promise<void>((resolve, reject) => {
        const onOpen = () => {
          cleanup();
          resolve();
        };
        const onError = (err: Error) => {
          cleanup();
          reject(err);
        };
        const onClose = (code: number, reason: Buffer) => {
          cleanup();
          reject(new Error(`gateway closed before open (${code}): ${rawDataToString(reason)}`));
        };
        const cleanup = () => {
          ws.off("open", onOpen);
          ws.off("error", onError);
          ws.off("close", onClose);
        };
        ws.once("open", onOpen);
        ws.once("error", onError);
        ws.once("close", onClose);
      }),
      timeoutMs,
      "gateway websocket open timeout",
    );

    const challenge = await withTimeout(this.challengePromise, timeoutMs, "gateway connect challenge timeout");
    const signedConnectParams = buildConnectParams(challenge);

    const hello = await this.request<Record<string, unknown> | null>("connect", signedConnectParams, {
      timeoutMs,
    });

    return hello;
  }

  async request<T>(
    method: string,
    params: unknown,
    opts: GatewayClientRequestOptions,
  ): Promise<T> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("gateway not connected");
    }

    const id = randomUUID();
    const frame: GatewayRequestFrame = {
      type: "req",
      id,
      method,
      params,
    };

    const payload = JSON.stringify(frame);
    const requestPromise = new Promise<T>((resolve, reject) => {
      const timer =
        opts.timeoutMs > 0
          ? setTimeout(() => {
              this.pending.delete(id);
              reject(new Error(`gateway request timeout (${method})`));
            }, opts.timeoutMs)
          : null;

      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
        expectFinal: opts.expectFinal === true,
        onAccepted: opts.onAccepted,
        timer,
      });
    });

    this.ws.send(payload);
    return requestPromise;
  }

  close() {
    if (!this.ws) return;
    this.ws.close(1000, "paperclip-complete");
    this.ws = null;
  }

  private failPending(err: Error) {
    for (const [, pending] of this.pending) {
      if (pending.timer) clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pending.clear();
  }

  private handleMessage(raw: string) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }

    if (isEventFrame(parsed)) {
      if (parsed.event === "connect.challenge") {
        const challenge = parseConnectChallenge(parsed.payload);
        if ("error" in challenge) {
          this.rejectChallenge(new Error(challenge.error));
        } else {
          this.resolveChallenge(challenge);
        }
        return;
      }
      void Promise.resolve(this.opts.onEvent(parsed)).catch(() => {
        // Ignore event callback failures and keep stream active.
      });
      return;
    }

    if (!isResponseFrame(parsed)) return;

    const pending = this.pending.get(parsed.id);
    if (!pending) return;

    const payload = asRecord(parsed.payload);
    const status = nonEmpty(payload?.status)?.toLowerCase();
    if (pending.expectFinal && parsed.ok && status === "accepted") {
      try {
        pending.onAccepted?.(payload);
      } catch {
        // An observer failure must not drop the terminal response.
      }
      return;
    }

    if (pending.timer) clearTimeout(pending.timer);
    this.pending.delete(parsed.id);

    if (parsed.ok) {
      pending.resolve(parsed.payload ?? null);
      return;
    }

    const errorRecord = asRecord(parsed.error);
    const message =
      nonEmpty(errorRecord?.message) ??
      nonEmpty(errorRecord?.code) ??
      "gateway request failed";
    const err = new Error(message) as GatewayResponseError;
    const code = nonEmpty(errorRecord?.code);
    const details = asRecord(errorRecord?.details);
    if (code) err.gatewayCode = code;
    if (details) err.gatewayDetails = details;
    if (payload) err.gatewayPayload = payload;
    pending.reject(err);
  }
}

async function autoApproveDevicePairing(params: {
  url: string;
  headers: Record<string, string>;
  connectTimeoutMs: number;
  clientId: string;
  clientMode: string;
  clientVersion: string;
  role: string;
  scopes: string[];
  authToken: string | null;
  password: string | null;
  requestId: string | null;
  deviceId: string | null;
  onLog: AdapterExecutionContext["onLog"];
}): Promise<{ ok: true; requestId: string } | { ok: false; reason: string }> {
  if (!params.authToken && !params.password) {
    return { ok: false, reason: "shared auth token/password is missing" };
  }

  const approvalScopes = uniqueScopes([...params.scopes, "operator.pairing"]);
  const client = new GatewayWsClient({
    url: params.url,
    headers: params.headers,
    onEvent: () => {},
    onLog: params.onLog,
  });

  try {
    await params.onLog(
      "stdout",
      "[openclaw-gateway] pairing required; attempting automatic pairing approval via gateway methods\n",
    );

    await client.connect(
      () => ({
        minProtocol: GATEWAY_PROTOCOL_VERSION,
        maxProtocol: GATEWAY_PROTOCOL_VERSION,
        client: {
          id: params.clientId,
          version: params.clientVersion,
          platform: process.platform,
          mode: params.clientMode,
        },
        role: params.role,
        scopes: approvalScopes,
        auth: {
          ...(params.authToken ? { token: params.authToken } : {}),
          ...(params.password ? { password: params.password } : {}),
        },
      }),
      params.connectTimeoutMs,
    );

    let requestId = params.requestId;
    if (!requestId) {
      const listPayload = await client.request<Record<string, unknown>>("device.pair.list", {}, {
        timeoutMs: params.connectTimeoutMs,
      });
      const pending = Array.isArray(listPayload.pending) ? listPayload.pending : [];
      const pendingRecords = pending
        .map((entry) => asRecord(entry))
        .filter((entry): entry is Record<string, unknown> => Boolean(entry));
      const matching =
        (params.deviceId
          ? pendingRecords.find((entry) => nonEmpty(entry.deviceId) === params.deviceId)
          : null) ?? pendingRecords[pendingRecords.length - 1];
      requestId = nonEmpty(matching?.requestId);
    }

    if (!requestId) {
      return { ok: false, reason: "no pending device pairing request found" };
    }

    await client.request(
      "device.pair.approve",
      { requestId },
      {
        timeoutMs: params.connectTimeoutMs,
      },
    );

    return { ok: true, requestId };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  } finally {
    client.close();
  }
}

function parseUsage(value: unknown): AdapterExecutionResult["usage"] | undefined {
  const record = asRecord(value);
  if (!record) return undefined;

  const inputTokens = asNumber(record.inputTokens ?? record.input, 0);
  const outputTokens = asNumber(record.outputTokens ?? record.output, 0);
  const cachedInputTokens = asNumber(
    record.cachedInputTokens ?? record.cached_input_tokens ?? record.cacheRead ?? record.cache_read,
    0,
  );

  if (inputTokens <= 0 && outputTokens <= 0 && cachedInputTokens <= 0) {
    return undefined;
  }

  return {
    inputTokens,
    outputTokens,
    ...(cachedInputTokens > 0 ? { cachedInputTokens } : {}),
  };
}

function extractRuntimeServicesFromMeta(meta: Record<string, unknown> | null): AdapterRuntimeServiceReport[] {
  if (!meta) return [];
  const reports: AdapterRuntimeServiceReport[] = [];

  const runtimeServices = Array.isArray(meta.runtimeServices)
    ? meta.runtimeServices.filter((entry): entry is Record<string, unknown> => Boolean(asRecord(entry)))
    : [];
  for (const entry of runtimeServices) {
    const serviceName = nonEmpty(entry.serviceName) ?? nonEmpty(entry.name);
    if (!serviceName) continue;
    const rawStatus = nonEmpty(entry.status)?.toLowerCase();
    const status =
      rawStatus === "starting" || rawStatus === "running" || rawStatus === "stopped" || rawStatus === "failed"
        ? rawStatus
        : "running";
    const rawLifecycle = nonEmpty(entry.lifecycle)?.toLowerCase();
    const lifecycle = rawLifecycle === "shared" ? "shared" : "ephemeral";
    const rawScopeType = nonEmpty(entry.scopeType)?.toLowerCase();
    const scopeType =
      rawScopeType === "project_workspace" ||
      rawScopeType === "execution_workspace" ||
      rawScopeType === "agent"
        ? rawScopeType
        : "run";
    const rawHealth = nonEmpty(entry.healthStatus)?.toLowerCase();
    const healthStatus =
      rawHealth === "healthy" || rawHealth === "unhealthy" || rawHealth === "unknown"
        ? rawHealth
        : status === "running"
          ? "healthy"
          : "unknown";

    reports.push({
      id: nonEmpty(entry.id),
      projectId: nonEmpty(entry.projectId),
      projectWorkspaceId: nonEmpty(entry.projectWorkspaceId),
      issueId: nonEmpty(entry.issueId),
      scopeType,
      scopeId: nonEmpty(entry.scopeId),
      serviceName,
      status,
      lifecycle,
      reuseKey: nonEmpty(entry.reuseKey),
      command: nonEmpty(entry.command),
      cwd: nonEmpty(entry.cwd),
      port: parseOptionalPositiveInteger(entry.port),
      url: nonEmpty(entry.url),
      providerRef: nonEmpty(entry.providerRef) ?? nonEmpty(entry.previewId),
      ownerAgentId: nonEmpty(entry.ownerAgentId),
      stopPolicy: asRecord(entry.stopPolicy),
      healthStatus,
    });
  }

  const previewUrl = nonEmpty(meta.previewUrl);
  if (previewUrl) {
    reports.push({
      serviceName: "preview",
      status: "running",
      lifecycle: "ephemeral",
      scopeType: "run",
      url: previewUrl,
      providerRef: nonEmpty(meta.previewId) ?? previewUrl,
      healthStatus: "healthy",
    });
  }

  const previewUrls = Array.isArray(meta.previewUrls)
    ? meta.previewUrls.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    : [];
  previewUrls.forEach((url, index) => {
    reports.push({
      serviceName: index === 0 ? "preview" : `preview-${index + 1}`,
      status: "running",
      lifecycle: "ephemeral",
      scopeType: "run",
      url,
      providerRef: `${url}#${index}`,
      healthStatus: "healthy",
    });
  });

  return reports;
}

function extractResultText(value: unknown): string | null {
  const record = asRecord(value);
  if (!record) return null;

  const payloads = Array.isArray(record.payloads) ? record.payloads : [];
  const texts = payloads
    .map((entry) => {
      const payload = asRecord(entry);
      return nonEmpty(payload?.text);
    })
    .filter((entry): entry is string => Boolean(entry));

  if (texts.length > 0) return texts.join("\n\n");
  return nonEmpty(record.text) ?? nonEmpty(record.summary) ?? null;
}

type AssistantTextAccumulator = {
  apply: (data: Record<string, unknown>) => void;
  text: () => string;
};

/**
 * Rebuilds assistant text from v4 `agent` events with `stream: "assistant"`.
 * Each event belongs to an assistant item (`data.itemId`); `data.delta` appends,
 * `data.text` is an authoritative snapshot of the item that already includes
 * the delta, and `data.replace` replaces the item text. Items are kept separate
 * and joined in arrival order.
 */
export function createAssistantTextAccumulator(): AssistantTextAccumulator {
  const order: string[] = [];
  const items = new Map<string, string>();
  return {
    apply(data) {
      const itemId = typeof data.itemId === "string" ? data.itemId : "";
      if (!items.has(itemId)) {
        order.push(itemId);
        items.set(itemId, "");
      }
      if (typeof data.text === "string") {
        items.set(itemId, data.text);
        return;
      }
      const delta = typeof data.delta === "string" ? data.delta : "";
      items.set(itemId, data.replace === true ? delta : `${items.get(itemId) ?? ""}${delta}`);
    },
    text() {
      return order
        .map((itemId) => (items.get(itemId) ?? "").trim())
        .filter(Boolean)
        .join("\n\n");
    },
  };
}

/**
 * v4 assistant events repeat the whole item snapshot in `data.text` next to
 * each `data.delta`. Logging the snapshot with every delta grows the run log
 * quadratically and, past the log line cap, truncates the JSON so the
 * transcript parser can no longer read the delta. Log the snapshot only when
 * the event has no delta to carry (snapshots and replacements).
 */
export function projectAssistantEventForLog(data: Record<string, unknown>): Record<string, unknown> {
  const hasDelta = typeof data.delta === "string" && data.delta.length > 0;
  if (!hasDelta || data.replace === true) return data;
  const { text: _snapshot, ...rest } = data;
  return rest;
}

/**
 * The gateway's terminal `agent` payload carries a status word in `summary`
 * ("completed" / "failed" / "aborted"). Paperclip reads `resultJson.summary` as
 * the run's reply text (and may post it to the issue), so keep the status word
 * under `gatewaySummary` instead.
 */
function toRunResultJson(payload: unknown): Record<string, unknown> | null {
  const record = asRecord(payload);
  if (!record) return null;
  const { summary, ...rest } = record;
  return summary === undefined ? rest : { ...rest, gatewaySummary: summary };
}

const AGENT_WAIT_PENDING_POLL_MS = 1_000;

/**
 * Waits for a run through `agent.wait` until it reaches a terminal status or
 * the wait budget runs out. `agent.wait` answers `pending` immediately while
 * the run is queued behind another turn, so that status is polled.
 */
async function waitForAgentRun(
  client: GatewayWsClient,
  runId: string,
  waitTimeoutMs: number,
  requestSlackMs: number,
): Promise<Record<string, unknown> | null> {
  const deadline = Date.now() + waitTimeoutMs;
  while (true) {
    const remainingMs = Math.max(0, deadline - Date.now());
    const waitPayload = await client.request<Record<string, unknown> | null>(
      "agent.wait",
      { runId, timeoutMs: remainingMs },
      { timeoutMs: remainingMs + requestSlackMs },
    );
    const status = nonEmpty(waitPayload?.status)?.toLowerCase();
    if (status !== "pending") return waitPayload;
    if (Date.now() + AGENT_WAIT_PENDING_POLL_MS >= deadline) {
      return { ...(waitPayload ?? {}), runId, status: "timeout" };
    }
    await new Promise((resolve) => setTimeout(resolve, AGENT_WAIT_PENDING_POLL_MS));
  }
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const urlValue = asString(ctx.config.url, "").trim();
  if (!urlValue) {
    return {
      exitCode: 1,
      signal: null,
      timedOut: false,
      errorMessage: "OpenClaw gateway adapter missing url",
      errorCode: "openclaw_gateway_url_missing",
    };
  }

  const parsedUrl = normalizeUrl(urlValue);
  if (!parsedUrl) {
    return {
      exitCode: 1,
      signal: null,
      timedOut: false,
      errorMessage: `Invalid gateway URL: ${urlValue}`,
      errorCode: "openclaw_gateway_url_invalid",
    };
  }

  if (parsedUrl.protocol !== "ws:" && parsedUrl.protocol !== "wss:") {
    return {
      exitCode: 1,
      signal: null,
      timedOut: false,
      errorMessage: `Unsupported gateway URL protocol: ${parsedUrl.protocol}`,
      errorCode: "openclaw_gateway_url_protocol",
    };
  }

  const timeoutSec = Math.max(0, Math.floor(asNumber(ctx.config.timeoutSec, 120)));
  const timeoutMs = timeoutSec > 0 ? timeoutSec * 1000 : 0;
  const connectTimeoutMs = timeoutMs > 0 ? Math.min(timeoutMs, 15_000) : 10_000;
  const waitTimeoutMs = parseOptionalPositiveInteger(ctx.config.waitTimeoutMs) ?? (timeoutMs > 0 ? timeoutMs : 30_000);

  const payloadTemplate = parseObject(ctx.config.payloadTemplate);
  const transportHint = nonEmpty(ctx.config.streamTransport) ?? nonEmpty(ctx.config.transport);

  const headers = toStringRecord(ctx.config.headers);
  const authToken = resolveAuthToken(parseObject(ctx.config), headers);
  const password = nonEmpty(ctx.config.password);
  const deviceToken = nonEmpty(ctx.config.deviceToken);

  if (authToken && !headerMapHasIgnoreCase(headers, "authorization")) {
    headers.authorization = toAuthorizationHeaderValue(authToken);
  }

  const clientId = nonEmpty(ctx.config.clientId) ?? DEFAULT_CLIENT_ID;
  const clientMode = nonEmpty(ctx.config.clientMode) ?? DEFAULT_CLIENT_MODE;
  const clientVersion = nonEmpty(ctx.config.clientVersion) ?? DEFAULT_CLIENT_VERSION;
  const role = nonEmpty(ctx.config.role) ?? DEFAULT_ROLE;
  const scopes = normalizeScopes(ctx.config.scopes);
  const deviceFamily = nonEmpty(ctx.config.deviceFamily);
  const disableDeviceAuth = parseBoolean(ctx.config.disableDeviceAuth, false);

  const wakePayload = buildWakePayload(ctx);
  const paperclipEnv = buildPaperclipEnvForWake(ctx, wakePayload);
  const wakeText = buildWakeText(wakePayload, paperclipEnv);

  const sessionKeyStrategy = normalizeSessionKeyStrategy(ctx.config.sessionKeyStrategy);
  const configuredSessionKey = nonEmpty(ctx.config.sessionKey);
  const sessionKey = resolveSessionKey({
    strategy: sessionKeyStrategy,
    configuredSessionKey,
    runId: ctx.runId,
    issueId: wakePayload.issueId,
  });

  const templateMessage = nonEmpty(payloadTemplate.message) ?? nonEmpty(payloadTemplate.text);
  const message = templateMessage ? appendWakeText(templateMessage, wakeText) : wakeText;
  const agentParams: Record<string, unknown> = {
    ...payloadTemplate,
    message,
    sessionKey,
    idempotencyKey: ctx.runId,
  };
  // `text` is folded into `message` above. `paperclip` is not part of the
  // gateway's `agent` params schema, which rejects unknown properties
  // (additionalProperties: false); the Paperclip context the agent needs is
  // carried in the wake text.
  delete agentParams.text;
  delete agentParams.paperclip;

  const configuredAgentId = nonEmpty(ctx.config.agentId);
  if (configuredAgentId && !nonEmpty(agentParams.agentId)) {
    agentParams.agentId = configuredAgentId;
  }

  if (typeof agentParams.timeout !== "number") {
    // The gateway reads `agent.timeout` in seconds and ends the run itself
    // (terminal status `timeout`) when it elapses.
    agentParams.timeout = Math.ceil(waitTimeoutMs / 1000);
  }

  if (ctx.onMeta) {
    await ctx.onMeta({
      adapterType: "openclaw_gateway",
      command: "gateway",
      commandArgs: ["ws", parsedUrl.toString(), "agent"],
      context: ctx.context,
    });
  }

  const outboundHeaderKeys = Object.keys(headers).sort();
  await ctx.onLog(
    "stdout",
    `[openclaw-gateway] outbound headers (redacted): ${stringifyForLog(redactForLog(headers), 4_000)}\n`,
  );
  await ctx.onLog(
    "stdout",
    `[openclaw-gateway] outbound payload (redacted): ${stringifyForLog(redactForLog(agentParams), 12_000)}\n`,
  );
  await ctx.onLog("stdout", `[openclaw-gateway] outbound header keys: ${outboundHeaderKeys.join(", ")}\n`);
  if (transportHint) {
    await ctx.onLog(
      "stdout",
      `[openclaw-gateway] ignoring streamTransport=${transportHint}; gateway adapter always uses websocket protocol\n`,
    );
  }
  if (parsedUrl.protocol === "ws:" && !isLoopbackHost(parsedUrl.hostname)) {
    await ctx.onLog(
      "stdout",
      "[openclaw-gateway] warning: using plaintext ws:// to a non-loopback host; prefer wss:// for remote endpoints\n",
    );
  }

  const autoPairOnFirstConnect = parseBoolean(ctx.config.autoPairOnFirstConnect, true);
  let autoPairAttempted = false;
  let latestResultPayload: unknown = null;

  while (true) {
    const trackedRunIds = new Set<string>([ctx.runId]);
    const assistantText = createAssistantTextAccumulator();
    let lifecycleError: string | null = null;
    let deviceIdentity: GatewayDeviceIdentity | null = null;
    // Set from the `onAccepted` callback; held in an object so the later read
    // is not narrowed to the initial null.
    const accepted: { payload: Record<string, unknown> | null } = { payload: null };

    const onEvent = async (frame: GatewayEventFrame) => {
      if (frame.event !== "agent") {
        if (frame.event === "shutdown") {
          await ctx.onLog(
            "stdout",
            `[openclaw-gateway] gateway shutdown notice: ${stringifyForLog(frame.payload ?? {}, 2_000)}\n`,
          );
        }
        return;
      }

      const payload = asRecord(frame.payload);
      if (!payload) return;

      const runId = nonEmpty(payload.runId);
      if (!runId || !trackedRunIds.has(runId)) return;

      const stream = nonEmpty(payload.stream) ?? "unknown";
      const data = asRecord(payload.data) ?? {};
      const logData = stream === "assistant" ? projectAssistantEventForLog(data) : data;
      await ctx.onLog(
        "stdout",
        `[openclaw-gateway:event] run=${runId} stream=${stream} data=${stringifyForLog(logData, 8_000)}\n`,
      );

      if (stream === "assistant") {
        assistantText.apply(data);
        return;
      }

      if (stream === "error") {
        lifecycleError = nonEmpty(data.error) ?? nonEmpty(data.message) ?? lifecycleError;
        return;
      }

      if (stream === "lifecycle") {
        const phase = nonEmpty(data.phase)?.toLowerCase();
        if (phase === "error" || phase === "failed" || phase === "cancelled") {
          lifecycleError = nonEmpty(data.error) ?? nonEmpty(data.message) ?? lifecycleError;
        }
      }
    };

    const client = new GatewayWsClient({
      url: parsedUrl.toString(),
      headers,
      onEvent,
      onLog: ctx.onLog,
    });

    try {
      deviceIdentity = disableDeviceAuth ? null : resolveDeviceIdentity(parseObject(ctx.config));
      if (deviceIdentity) {
        await ctx.onLog(
          "stdout",
          `[openclaw-gateway] device auth enabled keySource=${deviceIdentity.source} deviceId=${deviceIdentity.deviceId}\n`,
        );
      } else {
        await ctx.onLog("stdout", "[openclaw-gateway] device auth disabled\n");
      }

      await ctx.onLog("stdout", `[openclaw-gateway] connecting to ${parsedUrl.toString()}\n`);

      const hello = await client.connect((challenge) => {
        const connectParams: Record<string, unknown> = {
          minProtocol: GATEWAY_PROTOCOL_VERSION,
          maxProtocol: GATEWAY_PROTOCOL_VERSION,
          client: {
            id: clientId,
            version: clientVersion,
            platform: process.platform,
            ...(deviceFamily ? { deviceFamily } : {}),
            mode: clientMode,
          },
          role,
          scopes,
          auth:
            authToken || password || deviceToken
              ? {
                  ...(authToken ? { token: authToken } : {}),
                  ...(deviceToken ? { deviceToken } : {}),
                  ...(password ? { password } : {}),
                }
              : undefined,
        };

        if (deviceIdentity) {
          // The gateway verifies the signature against the challenge it issued:
          // `signedAt` is the challenge `ts`, and the signed token is the one it
          // reads from `auth` (token, else deviceToken).
          const payload = buildDeviceAuthPayloadV3({
            deviceId: deviceIdentity.deviceId,
            clientId,
            clientMode,
            role,
            scopes,
            signedAtMs: challenge.ts,
            token: authToken ?? deviceToken,
            nonce: challenge.nonce,
            platform: process.platform,
            deviceFamily,
          });
          connectParams.device = {
            id: deviceIdentity.deviceId,
            publicKey: deviceIdentity.publicKeyRawBase64Url,
            signature: signDevicePayload(deviceIdentity.privateKeyPem, payload),
            signedAt: challenge.ts,
            nonce: challenge.nonce,
          };
        }
        return connectParams;
      }, connectTimeoutMs);

      await ctx.onLog(
        "stdout",
        `[openclaw-gateway] connected protocol=${asNumber(asRecord(hello)?.protocol, GATEWAY_PROTOCOL_VERSION)}\n`,
      );

      // Protocol v4 `agent` is a two-phase request: an `accepted` ack, then a
      // second `res` with the same id carrying the terminal outcome and the run
      // result (payloads, meta, usage). The gateway enforces `agent.timeout`
      // itself; the local deadline only backstops a lost terminal frame.
      let terminalPayload: Record<string, unknown> | null;
      try {
        terminalPayload = await client.request<Record<string, unknown> | null>("agent", agentParams, {
          timeoutMs: waitTimeoutMs + connectTimeoutMs,
          expectFinal: true,
          onAccepted: (payload) => {
            accepted.payload = payload;
            latestResultPayload = payload;
            const acceptedRunId = nonEmpty(payload?.runId);
            if (acceptedRunId) trackedRunIds.add(acceptedRunId);
            void ctx.onLog(
              "stdout",
              `[openclaw-gateway] agent accepted runId=${acceptedRunId ?? ctx.runId} status=accepted\n`,
            );
          },
        });
      } catch (err) {
        // A failed run still ends with a terminal frame for the accepted run
        // (ok:false with a `{ runId, status, summary }` payload). Errors without
        // one, such as a rejected request, are request failures.
        const failedPayload = (err as GatewayResponseError | null)?.gatewayPayload ?? null;
        if (!failedPayload || !nonEmpty(failedPayload.status)) throw err;
        terminalPayload = failedPayload;
      }

      latestResultPayload = terminalPayload;
      const runId = nonEmpty(terminalPayload?.runId) ?? nonEmpty(accepted.payload?.runId) ?? ctx.runId;
      trackedRunIds.add(runId);
      let status = nonEmpty(terminalPayload?.status)?.toLowerCase() ?? "";
      let failureMessage = nonEmpty(terminalPayload?.error) ?? nonEmpty(terminalPayload?.summary);

      if (status === "in_flight") {
        // The idempotency key matched a run that is still executing (for
        // example a retried Paperclip run); its terminal frame belongs to the
        // original request, so wait on the run instead.
        await ctx.onLog("stdout", `[openclaw-gateway] run ${runId} already in flight; waiting via agent.wait\n`);
        const waitPayload = await waitForAgentRun(client, runId, waitTimeoutMs, connectTimeoutMs);
        latestResultPayload = waitPayload;
        status = nonEmpty(waitPayload?.status)?.toLowerCase() ?? "";
        failureMessage = nonEmpty(waitPayload?.error) ?? nonEmpty(waitPayload?.summary);
      }

      if (status === "timeout") {
        return {
          exitCode: 1,
          signal: null,
          timedOut: true,
          errorMessage: failureMessage && failureMessage !== "aborted"
            ? `OpenClaw gateway run timed out: ${failureMessage}`
            : `OpenClaw gateway run timed out after ${waitTimeoutMs}ms`,
          errorCode: "openclaw_gateway_wait_timeout",
          resultJson: toRunResultJson(latestResultPayload),
        };
      }

      if (status === "error") {
        // Rejected runs carry the rendered error in `summary`; runs that ended
        // with a failed outcome carry the generic summary "failed" and the
        // detail in the result meta or the lifecycle stream.
        const resultError = nonEmpty(
          asRecord(asRecord(asRecord(asRecord(latestResultPayload)?.result)?.meta)?.error)?.message,
        );
        const specificFailure = failureMessage && failureMessage !== "failed" ? failureMessage : null;
        return {
          exitCode: 1,
          signal: null,
          timedOut: false,
          errorMessage: specificFailure ?? resultError ?? lifecycleError ?? "OpenClaw gateway run failed",
          errorCode: "openclaw_gateway_agent_error",
          resultJson: toRunResultJson(latestResultPayload),
        };
      }

      if (status !== "ok") {
        return {
          exitCode: 1,
          signal: null,
          timedOut: false,
          errorMessage: `Unexpected OpenClaw gateway agent status: ${status || "missing"}`,
          errorCode: "openclaw_gateway_wait_status_unexpected",
          resultJson: toRunResultJson(latestResultPayload),
        };
      }

      // The terminal payload's own `summary` is a status word ("completed"),
      // not reply text; the reply is in `result.payloads`.
      const terminalResult = asRecord(asRecord(latestResultPayload)?.result);
      const summary = extractResultText(terminalResult) ?? (assistantText.text() || null);

      const latestPayload = asRecord(latestResultPayload);
      const meta = asRecord(terminalResult?.meta) ?? asRecord(latestPayload?.meta) ?? {};
      const agentMeta = asRecord(meta.agentMeta);
      const usage = parseUsage(agentMeta?.usage ?? meta.usage);
      const runtimeServices = extractRuntimeServicesFromMeta(agentMeta ?? meta);
      const provider = nonEmpty(agentMeta?.provider) ?? nonEmpty(meta.provider) ?? "openclaw";
      const model = nonEmpty(agentMeta?.model) ?? nonEmpty(meta.model) ?? null;
      const costUsd = asNumber(agentMeta?.costUsd ?? meta.costUsd, 0);

      await ctx.onLog(
        "stdout",
        `[openclaw-gateway] run completed runId=${Array.from(trackedRunIds).join(",")} status=ok\n`,
      );

      return {
        exitCode: 0,
        signal: null,
        timedOut: false,
        provider,
        ...(model ? { model } : {}),
        ...(usage ? { usage } : {}),
        ...(costUsd > 0 ? { costUsd } : {}),
        resultJson: toRunResultJson(latestPayload),
        ...(runtimeServices.length > 0 ? { runtimeServices } : {}),
        ...(summary ? { summary } : {}),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const lower = message.toLowerCase();
      const timedOut = lower.includes("timeout");
      const pairingRequired = lower.includes("pairing required");

      if (
        pairingRequired &&
        !disableDeviceAuth &&
        autoPairOnFirstConnect &&
        !autoPairAttempted &&
        (authToken || password)
      ) {
        autoPairAttempted = true;
        const pairResult = await autoApproveDevicePairing({
          url: parsedUrl.toString(),
          headers,
          connectTimeoutMs,
          clientId,
          clientMode,
          clientVersion,
          role,
          scopes,
          authToken,
          password,
          requestId: extractPairingRequestId(err),
          deviceId: deviceIdentity?.deviceId ?? null,
          onLog: ctx.onLog,
        });
        if (pairResult.ok) {
          await ctx.onLog(
            "stdout",
            `[openclaw-gateway] auto-approved pairing request ${pairResult.requestId}; retrying\n`,
          );
          continue;
        }
        await ctx.onLog(
          "stderr",
          `[openclaw-gateway] auto-pairing failed: ${pairResult.reason}\n`,
        );
      }

      const detailedMessage = pairingRequired
        ? `${message}. Approve the pending device in OpenClaw (for example: openclaw devices approve --latest --url <gateway-ws-url> --token <gateway-token>) and retry. Ensure this agent has a persisted adapterConfig.devicePrivateKeyPem so approvals are reused.`
        : message;

      await ctx.onLog("stderr", `[openclaw-gateway] request failed: ${detailedMessage}\n`);

      return {
        exitCode: 1,
        signal: null,
        timedOut,
        errorMessage: detailedMessage,
        errorCode: timedOut
          ? "openclaw_gateway_timeout"
          : pairingRequired
            ? "openclaw_gateway_pairing_required"
            : "openclaw_gateway_request_failed",
        resultJson: asRecord(latestResultPayload),
      };
    } finally {
      client.close();
    }
  }
}
