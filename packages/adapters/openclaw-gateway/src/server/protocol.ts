/**
 * OpenClaw gateway WebSocket protocol version this adapter speaks
 * (openclaw `packages/gateway-protocol/src/version.ts`).
 *
 * Gateways from 2026.10 set `MIN_CLIENT_PROTOCOL_VERSION = 4`: operator and
 * backend clients must include v4 in their `minProtocol..maxProtocol` range and
 * are rejected with `PROTOCOL_MISMATCH` otherwise. Only node clients and
 * lightweight restart probes keep the N-1 (v3) window.
 */
export const GATEWAY_PROTOCOL_VERSION = 4;

/**
 * Reads the `connect.challenge` event payload. Protocol v4 requires a nonce and
 * a non-negative integer `ts`; device-auth clients sign with that `ts` as
 * `device.signedAt`, and a challenge with an absent or malformed `ts` is
 * invalid.
 */
export function parseConnectChallenge(
  payload: unknown,
): { nonce: string; ts: number } | { error: string } {
  const record =
    typeof payload === "object" && payload !== null && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : null;
  const nonce = typeof record?.nonce === "string" ? record.nonce.trim() : "";
  if (!nonce) return { error: "gateway connect.challenge is missing a nonce" };
  const ts = record?.ts;
  if (typeof ts !== "number" || !Number.isSafeInteger(ts) || ts < 0) {
    return { error: "gateway connect.challenge is missing a valid ts" };
  }
  return { nonce, ts };
}
