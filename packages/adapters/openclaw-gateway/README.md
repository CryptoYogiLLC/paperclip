# OpenClaw Gateway Adapter

This document describes how `@paperclipai/adapter-openclaw-gateway` invokes OpenClaw over the Gateway protocol.

## Transport

This adapter always uses WebSocket gateway transport.

- URL must be `ws://` or `wss://`
- Speaks gateway protocol v4 (OpenClaw 2026.10+, which rejects v3 operator clients with `PROTOCOL_MISMATCH`)
- Connect flow follows gateway protocol:
1. receive `connect.challenge` (`nonce` + `ts`)
2. send `req connect` (protocol/client/auth/device payload; the device signature uses the challenge `ts` as `signedAt`)
3. send `req agent`; the gateway acks with `status: "accepted"`, then sends a second `res` for the same request with the terminal status (`ok` / `error` / `timeout`) and the run result
4. if the ack reports `status: "in_flight"` (the idempotency key matches a run that is still executing), wait for it via `req agent.wait`
5. stream `event agent` frames into Paperclip logs/transcript parsing

## Auth Modes

Gateway credentials can be provided in any of these ways:

- `authToken` / `token` in adapter config
- `headers.x-openclaw-token`
- `headers.x-openclaw-auth` (legacy)
- `password` (shared password mode)

When a token is present and `authorization` header is missing, the adapter derives `Authorization: Bearer <token>`.

## Device Auth

By default the adapter sends a signed `device` payload in `connect` params.

- set `disableDeviceAuth=true` to omit device signing
- set `devicePrivateKeyPem` to pin a stable signing key
- without `devicePrivateKeyPem`, the adapter generates an ephemeral Ed25519 keypair per run
- when `autoPairOnFirstConnect` is enabled (default), the adapter handles one initial `pairing required` by calling `device.pair.list` + `device.pair.approve` over shared auth, then retries once.

## Session Strategy

The adapter supports the same session routing model as HTTP OpenClaw mode:

- `sessionKeyStrategy=issue|fixed|run`
- `sessionKey` is used when strategy is `fixed`

Resolved session key is sent as `agent.sessionKey`.

## Payload Mapping

The agent request is built as:

- required fields:
  - `message` (wake text plus optional `payloadTemplate.message`/`payloadTemplate.text` prefix)
  - `idempotencyKey` (Paperclip `runId`)
  - `sessionKey` (resolved strategy)
- optional additions:
  - all `payloadTemplate` fields merged in (they must be valid gateway `agent` params; the schema rejects unknown properties)
  - `agentId` from config if set and not already in template
  - `timeout` (seconds) from `waitTimeoutMs` unless the template sets it

## Timeouts

- `timeoutSec` controls adapter-level request budget
- `waitTimeoutMs` (default `timeoutSec * 1000`) is the run budget; it is sent to the gateway as `agent.timeout` in seconds, and the gateway ends the run with status `timeout` when it elapses

If the run ends with status `timeout`, the adapter returns `openclaw_gateway_wait_timeout`; status `error` returns `openclaw_gateway_agent_error`.

## Result Mapping

- `summary`: text of the terminal result `payloads`, falling back to the assistant text streamed in `event agent` frames
- `usage`, `provider`, `model`, `costUsd`: from the terminal result `meta.agentMeta`

## Log Format

Structured gateway event logs use:

- `[openclaw-gateway] ...` for lifecycle/system logs
- `[openclaw-gateway:event] run=<id> stream=<stream> data=<json>` for `event agent` frames

UI/CLI parsers consume these lines to render transcript updates.
