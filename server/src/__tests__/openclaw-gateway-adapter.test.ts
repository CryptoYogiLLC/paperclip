import { afterEach, describe, expect, it } from "vitest";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { execute, testEnvironment } from "@paperclipai/adapter-openclaw-gateway/server";
import {
  buildOpenClawGatewayConfig,
  parseOpenClawGatewayStdoutLine,
} from "@paperclipai/adapter-openclaw-gateway/ui";
import type { AdapterExecutionContext } from "@paperclipai/adapter-utils";

function buildContext(
  config: Record<string, unknown>,
  overrides?: Partial<AdapterExecutionContext>,
): AdapterExecutionContext {
  return {
    runId: "run-123",
    agent: {
      id: "agent-123",
      companyId: "company-123",
      name: "OpenClaw Gateway Agent",
      adapterType: "openclaw_gateway",
      adapterConfig: {},
    },
    runtime: {
      sessionId: null,
      sessionParams: null,
      sessionDisplayId: null,
      taskKey: null,
    },
    config,
    context: {
      taskId: "task-123",
      issueId: "issue-123",
      wakeReason: "issue_assigned",
      issueIds: ["issue-123"],
    },
    onLog: async () => {},
    ...overrides,
  };
}

// Fields of the OpenClaw 2026.10 (protocol v4) `agent` params schema that this
// adapter may send. The real schema sets additionalProperties: false, so the
// mock rejects anything else the same way.
const V4_AGENT_PARAM_KEYS = new Set([
  "message",
  "agentId",
  "provider",
  "model",
  "sessionId",
  "sessionKey",
  "thinking",
  "deliver",
  "channel",
  "timeout",
  "lane",
  "cwd",
  "extraSystemPrompt",
  "idempotencyKey",
  "label",
]);

const CHALLENGE_TS = 1_767_225_600_000;

type MockFrame = { type: string; id: string; method: string; params?: Record<string, unknown> };
type Send = (frame: Record<string, unknown>) => void;

type MockAgentRun = (input: { frame: MockFrame; runId: string; send: Send }) => void | Promise<void>;

function sendAgentEvent(send: Send, runId: string, seq: number, stream: string, data: Record<string, unknown>) {
  send({ type: "event", event: "agent", payload: { runId, seq, stream, ts: Date.now(), data } });
}

function acceptAndFinish(result: Record<string, unknown>, events?: Array<[string, Record<string, unknown>]>): MockAgentRun {
  return ({ frame, runId, send }) => {
    send({
      type: "res",
      id: frame.id,
      ok: true,
      payload: { runId, sessionKey: frame.params?.sessionKey, status: "accepted", acceptedAt: Date.now() },
    });
    (events ?? []).forEach(([stream, data], index) => sendAgentEvent(send, runId, index + 1, stream, data));
    send({
      type: "res",
      id: frame.id,
      ok: true,
      payload: { runId, status: "ok", summary: "completed", result },
    });
  };
}

async function createMockGatewayServer(options?: {
  challenge?: Record<string, unknown>;
  agentRun?: MockAgentRun;
  waitPayloads?: Array<Record<string, unknown>>;
  requirePairing?: boolean;
}) {
  const server = createServer();
  const wss = new WebSocketServer({ server });

  let agentPayload: Record<string, unknown> | null = null;
  const connectParams: Array<Record<string, unknown>> = [];
  const methods: string[] = [];
  const waitPayloads = [...(options?.waitPayloads ?? [])];
  let approved = false;
  const pendingRequestId = "req-1";
  let lastSeenDeviceId: string | null = null;

  wss.on("connection", (socket) => {
    const send: Send = (frame) => socket.send(JSON.stringify(frame));
    send({
      type: "event",
      event: "connect.challenge",
      payload: options?.challenge ?? { nonce: "nonce-123", ts: CHALLENGE_TS },
    });

    socket.on("message", async (raw) => {
      const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
      const frame = JSON.parse(text) as MockFrame;
      if (frame.type !== "req") return;
      methods.push(frame.method);

      if (frame.method === "connect") {
        const params = frame.params ?? {};
        connectParams.push(params);
        const min = Number(params.minProtocol);
        const max = Number(params.maxProtocol);
        if (!(min <= 4 && max >= 4)) {
          send({
            type: "res",
            id: frame.id,
            ok: false,
            error: {
              code: "INVALID_REQUEST",
              message: "protocol mismatch",
              details: { code: "PROTOCOL_MISMATCH", clientMinProtocol: min, clientMaxProtocol: max, expectedProtocol: 4 },
            },
          });
          socket.close(1002, "protocol mismatch");
          return;
        }

        const device = params.device as Record<string, unknown> | undefined;
        const deviceId = typeof device?.id === "string" ? device.id : null;
        if (deviceId) lastSeenDeviceId = deviceId;
        if (options?.requirePairing && deviceId && !approved) {
          send({
            type: "res",
            id: frame.id,
            ok: false,
            error: {
              code: "NOT_PAIRED",
              message: "pairing required",
              details: { code: "PAIRING_REQUIRED", requestId: pendingRequestId, reason: "not-paired" },
            },
          });
          socket.close(1008, "pairing required");
          return;
        }

        send({
          type: "res",
          id: frame.id,
          ok: true,
          payload: {
            type: "hello-ok",
            protocol: 4,
            server: { version: "2026.10.9", connId: "conn-1" },
            features: {
              methods: ["connect", "agent", "agent.wait", "device.pair.list", "device.pair.approve"],
              events: ["agent", "chat"],
            },
            snapshot: { version: 1, ts: Date.now() },
            auth: { role: "operator", scopes: ["operator.admin"] },
            policy: { maxPayload: 26_214_400, maxBufferedBytes: 52_428_800, tickIntervalMs: 15_000 },
          },
        });
        return;
      }

      if (frame.method === "device.pair.list") {
        send({
          type: "res",
          id: frame.id,
          ok: true,
          payload: {
            pending: approved ? [] : [{ requestId: pendingRequestId, deviceId: lastSeenDeviceId ?? "device-unknown" }],
            paired: approved && lastSeenDeviceId ? [{ deviceId: lastSeenDeviceId }] : [],
          },
        });
        return;
      }

      if (frame.method === "device.pair.approve") {
        approved = frame.params?.requestId === pendingRequestId;
        send({
          type: "res",
          id: frame.id,
          ok: approved,
          ...(approved
            ? { payload: { requestId: pendingRequestId, device: { deviceId: lastSeenDeviceId } } }
            : { error: { code: "INVALID_REQUEST", message: "unknown requestId" } }),
        });
        return;
      }

      if (frame.method === "agent") {
        agentPayload = frame.params ?? null;
        const unknownKeys = Object.keys(agentPayload ?? {}).filter((key) => !V4_AGENT_PARAM_KEYS.has(key));
        if (unknownKeys.length > 0) {
          send({
            type: "res",
            id: frame.id,
            ok: false,
            error: {
              code: "INVALID_REQUEST",
              message: `invalid agent params: at root: unexpected property '${unknownKeys[0]}'`,
            },
          });
          return;
        }
        const runId =
          typeof frame.params?.idempotencyKey === "string" ? frame.params.idempotencyKey : "run-123";
        const run =
          options?.agentRun ??
          acceptAndFinish(
            { payloads: [{ text: "chachacha" }], meta: { agentMeta: { provider: "openai", model: "gpt-6.1-terra" } } },
            [["assistant", { itemId: "item-1", delta: "cha", text: "cha" }]],
          );
        await run({ frame, runId, send });
        return;
      }

      if (frame.method === "agent.wait") {
        const next = waitPayloads.shift() ?? { status: "ok", startedAt: 1, endedAt: 2 };
        send({ type: "res", id: frame.id, ok: true, payload: { runId: frame.params?.runId, ...next } });
      }
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to resolve test server address");
  }

  return {
    url: `ws://127.0.0.1:${address.port}`,
    getAgentPayload: () => agentPayload,
    getConnectParams: () => connectParams,
    getMethods: () => methods,
    close: async () => {
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

afterEach(() => {
  // no global mocks
});

describe("openclaw gateway ui stdout parser", () => {
  it("parses assistant deltas from gateway event lines", () => {
    const ts = "2026-03-06T15:00:00.000Z";
    const line =
      '[openclaw-gateway:event] run=run-1 stream=assistant data={"delta":"hello"}';

    expect(parseOpenClawGatewayStdoutLine(line, ts)).toEqual([
      {
        kind: "assistant",
        ts,
        text: "hello",
        delta: true,
      },
    ]);
  });
});

const WAKE_CONTEXT = {
  taskId: "task-123",
  issueId: "issue-123",
  wakeReason: "issue_assigned",
  issueIds: ["issue-123"],
  paperclipWorkspace: {
    cwd: "/tmp/worktrees/pap-123",
    strategy: "git_worktree",
    branchName: "pap-123-test",
  },
  paperclipWorkspaces: [{ id: "workspace-1", cwd: "/tmp/project" }],
  paperclipRuntimeServiceIntents: [{ name: "preview", lifecycle: "ephemeral" }],
  paperclipWake: {
    reason: "issue_commented",
    issue: {
      id: "issue-123",
      identifier: "PAP-874",
      title: "chat-speed issues",
      status: "in_progress",
      priority: "medium",
    },
    commentIds: ["comment-1", "comment-2"],
    latestCommentId: "comment-2",
    comments: [
      {
        id: "comment-1",
        issueId: "issue-123",
        body: "First comment",
        bodyTruncated: false,
        createdAt: "2026-03-28T14:35:00.000Z",
        author: { type: "user", id: "user-1" },
      },
      {
        id: "comment-2",
        issueId: "issue-123",
        body: "Second comment",
        bodyTruncated: false,
        createdAt: "2026-03-28T14:35:10.000Z",
        author: { type: "user", id: "user-1" },
      },
    ],
    commentWindow: { requestedCount: 2, includedCount: 2, missingCount: 0 },
    truncated: false,
    fallbackFetchNeeded: false,
  },
};

const GATEWAY_TOKEN_CONFIG = { headers: { "x-openclaw-token": "gateway-token" } };

describe("openclaw gateway adapter execute", () => {
  it("connects with protocol v4 and signs the device proof with the challenge ts", async () => {
    const gateway = await createMockGatewayServer();
    const { privateKey } = generateKeyPairSync("ed25519");
    const devicePrivateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

    try {
      const result = await execute(
        buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, devicePrivateKeyPem, waitTimeoutMs: 2000 }),
      );
      expect(result.exitCode).toBe(0);

      const [connect] = gateway.getConnectParams();
      expect(connect.minProtocol).toBe(4);
      expect(connect.maxProtocol).toBe(4);
      const device = connect.device as Record<string, unknown>;
      expect(device.signedAt).toBe(CHALLENGE_TS);
      expect(device.nonce).toBe("nonce-123");

      // Verify exactly as the gateway does: the v3 payload over the challenge
      // ts and nonce, signed with the token it reads from auth.token.
      const client = connect.client as Record<string, unknown>;
      const signed = [
        "v3",
        device.id,
        client.id,
        client.mode,
        connect.role,
        (connect.scopes as string[]).join(","),
        String(CHALLENGE_TS),
        (connect.auth as Record<string, unknown>).token,
        "nonce-123",
        client.platform,
        "",
      ].join("|");
      const publicKey = createPublicKey({
        key: Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          Buffer.from(String(device.publicKey), "base64url"),
        ]),
        format: "der",
        type: "spki",
      });
      expect(verify(null, Buffer.from(signed), publicKey, Buffer.from(String(device.signature), "base64url"))).toBe(
        true,
      );
    } finally {
      await gateway.close();
    }
  });

  it("rejects a connect challenge without a valid ts", async () => {
    const gateway = await createMockGatewayServer({ challenge: { nonce: "nonce-123" } });
    try {
      const result = await execute(buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, waitTimeoutMs: 2000 }));
      expect(result.exitCode).toBe(1);
      expect(result.errorMessage).toContain("connect.challenge is missing a valid ts");
      expect(gateway.getConnectParams()).toHaveLength(0);
    } finally {
      await gateway.close();
    }
  });

  it("sends schema-valid agent params and resolves on the terminal agent response", async () => {
    const gateway = await createMockGatewayServer({
      agentRun: acceptAndFinish(
        {
          payloads: [{ text: "Checked out PAP-874 and posted the fix." }],
          meta: {
            agentMeta: {
              provider: "openai",
              model: "gpt-6.1-terra",
              usage: { input: 1200, output: 340, cacheRead: 800, cacheWrite: 0, total: 2340 },
            },
          },
        },
        [
          ["lifecycle", { phase: "start" }],
          ["assistant", { itemId: "item-1", delta: "Checked out", text: "Checked out" }],
          ["assistant", { itemId: "item-1", delta: " PAP-874", text: "Checked out PAP-874" }],
        ],
      ),
    });
    const logs: string[] = [];

    try {
      const result = await execute(
        buildContext(
          {
            url: gateway.url,
            ...GATEWAY_TOKEN_CONFIG,
            payloadTemplate: { message: "wake now", paperclip: { legacy: true } },
            waitTimeoutMs: 90_500,
          },
          {
            onLog: async (_stream, chunk) => {
              logs.push(chunk);
            },
            context: WAKE_CONTEXT,
          },
        ),
      );

      expect(result.exitCode).toBe(0);
      expect(result.timedOut).toBe(false);
      expect(result.summary).toBe("Checked out PAP-874 and posted the fix.");
      expect(result.provider).toBe("openai");
      expect(result.model).toBe("gpt-6.1-terra");
      expect(result.usage).toEqual({ inputTokens: 1200, outputTokens: 340, cachedInputTokens: 800 });
      expect(gateway.getMethods()).toEqual(["connect", "agent"]);
      // Paperclip treats resultJson.summary as reply text; the gateway's status
      // word must not land there.
      expect(result.resultJson?.summary).toBeUndefined();
      expect(result.resultJson?.gatewaySummary).toBe("completed");
      expect(result.resultJson?.status).toBe("ok");

      const payload = gateway.getAgentPayload();
      expect(payload).toBeTruthy();
      expect(Object.keys(payload ?? {}).sort()).toEqual(["idempotencyKey", "message", "sessionKey", "timeout"]);
      expect(payload?.idempotencyKey).toBe("run-123");
      expect(payload?.sessionKey).toBe("paperclip:issue:issue-123");
      expect(payload?.timeout).toBe(91);
      const message = String(payload?.message ?? "");
      expect(message).toContain("wake now");
      expect(message).toContain("PAPERCLIP_RUN_ID=run-123");
      expect(message).toContain("PAPERCLIP_TASK_ID=task-123");

      const assistantLogs = logs.filter((entry) => entry.includes("[openclaw-gateway:event] run=run-123 stream=assistant"));
      expect(assistantLogs).toHaveLength(2);
      // Delta events are logged without the repeated item snapshot.
      expect(assistantLogs[1]).toContain('"delta":" PAP-874"');
      expect(assistantLogs[1]).not.toContain('"text"');
      expect(logs.some((entry) => entry.includes("agent accepted runId=run-123 status=accepted"))).toBe(true);
    } finally {
      await gateway.close();
    }
  });

  it("falls back to streamed assistant items when the result has no payload text", async () => {
    const gateway = await createMockGatewayServer({
      agentRun: acceptAndFinish({ payloads: [], meta: {} }, [
        ["assistant", { itemId: "item-1", delta: "Hel", text: "Hel" }],
        ["assistant", { itemId: "item-1", delta: "lo", text: "Hello" }],
        ["assistant", { itemId: "item-1", delta: "", text: "Hello there", replace: true }],
        ["assistant", { itemId: "item-2", delta: "Done.", text: "Done." }],
      ]),
    });

    try {
      const result = await execute(buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, waitTimeoutMs: 2000 }));
      expect(result.exitCode).toBe(0);
      expect(result.summary).toBe("Hello there\n\nDone.");
    } finally {
      await gateway.close();
    }
  });

  it("fails immediately when the terminal agent response reports an error", async () => {
    const gateway = await createMockGatewayServer({
      agentRun: ({ frame, runId, send }) => {
        send({ type: "res", id: frame.id, ok: true, payload: { runId, status: "accepted", acceptedAt: Date.now() } });
        send({
          type: "res",
          id: frame.id,
          ok: false,
          payload: { runId, status: "error", summary: "Unknown model: openai/gpt-5.5" },
          error: { code: "UNAVAILABLE", message: "Unknown model: openai/gpt-5.5" },
        });
      },
    });

    try {
      const startedAt = Date.now();
      const result = await execute(buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, waitTimeoutMs: 60_000 }));
      expect(Date.now() - startedAt).toBeLessThan(5_000);
      expect(result.exitCode).toBe(1);
      expect(result.timedOut).toBe(false);
      expect(result.errorCode).toBe("openclaw_gateway_agent_error");
      expect(result.errorMessage).toBe("Unknown model: openai/gpt-5.5");
    } finally {
      await gateway.close();
    }
  });

  it("reports a gateway-enforced run timeout as timed out", async () => {
    const gateway = await createMockGatewayServer({
      agentRun: ({ frame, runId, send }) => {
        send({ type: "res", id: frame.id, ok: true, payload: { runId, status: "accepted", acceptedAt: Date.now() } });
        send({
          type: "res",
          id: frame.id,
          ok: true,
          payload: { runId, status: "timeout", summary: "aborted", stopReason: "timeout", result: { payloads: [] } },
        });
      },
    });

    try {
      const result = await execute(buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, waitTimeoutMs: 2000 }));
      expect(result.exitCode).toBe(1);
      expect(result.timedOut).toBe(true);
      expect(result.errorCode).toBe("openclaw_gateway_wait_timeout");
    } finally {
      await gateway.close();
    }
  });

  it("surfaces a rejected agent request as a request failure", async () => {
    const gateway = await createMockGatewayServer();
    try {
      const result = await execute(
        buildContext({
          url: gateway.url,
          ...GATEWAY_TOKEN_CONFIG,
          payloadTemplate: { metadata: { team: "platform" } },
          waitTimeoutMs: 2000,
        }),
      );
      expect(result.exitCode).toBe(1);
      expect(result.errorCode).toBe("openclaw_gateway_request_failed");
      expect(result.errorMessage).toContain("unexpected property 'metadata'");
    } finally {
      await gateway.close();
    }
  });

  it("waits through agent.wait when the run is already in flight", async () => {
    const gateway = await createMockGatewayServer({
      agentRun: ({ frame, runId, send }) => {
        send({ type: "res", id: frame.id, ok: true, payload: { runId, status: "in_flight" } });
      },
      waitPayloads: [
        { status: "pending", timeoutPhase: "queue", providerStarted: false },
        { status: "ok", startedAt: 1, endedAt: 2 },
      ],
    });

    try {
      const result = await execute(buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, waitTimeoutMs: 10_000 }));
      expect(result.exitCode).toBe(0);
      expect(gateway.getMethods()).toEqual(["connect", "agent", "agent.wait", "agent.wait"]);
    } finally {
      await gateway.close();
    }
  });

  it("fails fast when url is missing", async () => {
    const result = await execute(buildContext({}));
    expect(result.exitCode).toBe(1);
    expect(result.errorCode).toBe("openclaw_gateway_url_missing");
  });

  it("returns adapter-managed runtime services from gateway result meta", async () => {
    const gateway = await createMockGatewayServer({
      agentRun: acceptAndFinish({
        payloads: [{ text: "preview ready" }],
        meta: {
          runtimeServices: [
            {
              name: "preview",
              scopeType: "run",
              url: "https://preview.example/run-123",
              providerRef: "sandbox-123",
              lifecycle: "ephemeral",
            },
          ],
        },
      }),
    });

    try {
      const result = await execute(buildContext({ url: gateway.url, ...GATEWAY_TOKEN_CONFIG, waitTimeoutMs: 2000 }));

      expect(result.exitCode).toBe(0);
      expect(result.runtimeServices).toEqual([
        expect.objectContaining({
          serviceName: "preview",
          scopeType: "run",
          url: "https://preview.example/run-123",
          providerRef: "sandbox-123",
          lifecycle: "ephemeral",
          status: "running",
        }),
      ]);
    } finally {
      await gateway.close();
    }
  });

  it("auto-approves pairing once and retries the run", async () => {
    const gateway = await createMockGatewayServer({ requirePairing: true });
    const logs: string[] = [];

    try {
      const result = await execute(
        buildContext(
          { url: gateway.url, ...GATEWAY_TOKEN_CONFIG, payloadTemplate: { message: "wake now" }, waitTimeoutMs: 2000 },
          {
            onLog: async (_stream, chunk) => {
              logs.push(chunk);
            },
          },
        ),
      );

      expect(result.exitCode).toBe(0);
      expect(result.summary).toBe("chachacha");
      expect(logs.some((entry) => entry.includes("pairing required; attempting automatic pairing approval"))).toBe(
        true,
      );
      expect(logs.some((entry) => entry.includes("auto-approved pairing request"))).toBe(true);
      expect(gateway.getConnectParams().every((params) => params.minProtocol === 4 && params.maxProtocol === 4)).toBe(
        true,
      );
      expect(gateway.getAgentPayload()).toBeTruthy();
    } finally {
      await gateway.close();
    }
  });
});

describe("openclaw gateway ui build config", () => {
  it("parses payload template and runtime services json", () => {
    const config = buildOpenClawGatewayConfig({
      adapterType: "openclaw_gateway",
      cwd: "",
      promptTemplate: "",
      model: "",
      thinkingEffort: "",
      chrome: false,
      dangerouslySkipPermissions: false,
      search: false,
      dangerouslyBypassSandbox: false,
      command: "",
      args: "",
      extraArgs: "",
      envVars: "",
      envBindings: {},
      url: "wss://gateway.example/ws",
      payloadTemplateJson: JSON.stringify({
        agentId: "remote-agent-123",
        metadata: { team: "platform" },
      }),
      runtimeServicesJson: JSON.stringify({
        services: [
          {
            name: "preview",
            lifecycle: "shared",
          },
        ],
      }),
      bootstrapPrompt: "",
      maxTurnsPerRun: 0,
      heartbeatEnabled: true,
      intervalSec: 300,
    });

    expect(config).toEqual(
      expect.objectContaining({
        url: "wss://gateway.example/ws",
        payloadTemplate: {
          agentId: "remote-agent-123",
          metadata: { team: "platform" },
        },
        workspaceRuntime: {
          services: [
            {
              name: "preview",
              lifecycle: "shared",
            },
          ],
        },
      }),
    );
  });
});

describe("openclaw gateway testEnvironment", () => {
  it("probes the gateway with protocol v4", async () => {
    const gateway = await createMockGatewayServer();
    try {
      const result = await testEnvironment({
        companyId: "company-123",
        adapterType: "openclaw_gateway",
        config: { url: gateway.url, authToken: "gateway-token" },
      });
      expect(result.checks.some((check) => check.code === "openclaw_gateway_probe_ok")).toBe(true);
      const [connect] = gateway.getConnectParams();
      expect(connect.minProtocol).toBe(4);
      expect(connect.maxProtocol).toBe(4);
    } finally {
      await gateway.close();
    }
  });

  it("reports missing url as failure", async () => {
    const result = await testEnvironment({
      companyId: "company-123",
      adapterType: "openclaw_gateway",
      config: {},
    });

    expect(result.status).toBe("fail");
    expect(result.checks.some((check) => check.code === "openclaw_gateway_url_missing")).toBe(true);
  });
});
