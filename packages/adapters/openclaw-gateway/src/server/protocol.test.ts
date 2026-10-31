import { describe, expect, it } from "vitest";
import { GATEWAY_PROTOCOL_VERSION, parseConnectChallenge } from "./protocol.js";

describe("gateway protocol", () => {
  it("speaks protocol v4", () => {
    expect(GATEWAY_PROTOCOL_VERSION).toBe(4);
  });

  it("parses a v4 connect challenge", () => {
    expect(parseConnectChallenge({ nonce: " abc ", ts: 1737264000000 })).toEqual({ nonce: "abc", ts: 1737264000000 });
  });

  it("rejects a challenge without a nonce", () => {
    expect(parseConnectChallenge({ ts: 1 })).toEqual({ error: "gateway connect.challenge is missing a nonce" });
  });

  it.each([undefined, null, -1, 1.5, "1737264000000"])("rejects a challenge with ts=%s", (ts) => {
    expect(parseConnectChallenge({ nonce: "abc", ts })).toEqual({
      error: "gateway connect.challenge is missing a valid ts",
    });
  });
});
