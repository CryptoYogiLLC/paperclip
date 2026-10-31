import { describe, expect, it } from "vitest";
import {
  createAssistantTextAccumulator,
  projectAssistantEventForLog,
  resolveSessionKey,
} from "./execute.js";

describe("resolveSessionKey", () => {
  it("prefixes run-scoped session keys with the configured agent", () => {
    expect(
      resolveSessionKey({
        strategy: "run",
        configuredSessionKey: null,
        agentId: "meridian",
        runId: "run-123",
        issueId: null,
      }),
    ).toBe("agent:meridian:paperclip:run:run-123");
  });

  it("prefixes issue-scoped session keys with the configured agent", () => {
    expect(
      resolveSessionKey({
        strategy: "issue",
        configuredSessionKey: null,
        agentId: "meridian",
        runId: "run-123",
        issueId: "issue-456",
      }),
    ).toBe("agent:meridian:paperclip:issue:issue-456");
  });

  it("prefixes fixed session keys with the configured agent", () => {
    expect(
      resolveSessionKey({
        strategy: "fixed",
        configuredSessionKey: "paperclip",
        agentId: "meridian",
        runId: "run-123",
        issueId: null,
      }),
    ).toBe("agent:meridian:paperclip");
  });

  it("does not double-prefix an already-routed session key", () => {
    expect(
      resolveSessionKey({
        strategy: "fixed",
        configuredSessionKey: "agent:meridian:paperclip",
        agentId: "meridian",
        runId: "run-123",
        issueId: null,
      }),
    ).toBe("agent:meridian:paperclip");
  });
});

describe("createAssistantTextAccumulator", () => {
  it("appends deltas and treats text as the authoritative item snapshot", () => {
    const acc = createAssistantTextAccumulator();
    acc.apply({ itemId: "a", delta: "Hel", text: "Hel" });
    acc.apply({ itemId: "a", delta: "lo", text: "Hello" });
    expect(acc.text()).toBe("Hello");
  });

  it("appends bare deltas and honors replace without a snapshot", () => {
    const acc = createAssistantTextAccumulator();
    acc.apply({ itemId: "a", delta: "draft" });
    acc.apply({ itemId: "a", delta: " one" });
    expect(acc.text()).toBe("draft one");
    acc.apply({ itemId: "a", delta: "final", replace: true });
    expect(acc.text()).toBe("final");
  });

  it("applies an empty replacement snapshot", () => {
    const acc = createAssistantTextAccumulator();
    acc.apply({ itemId: "a", delta: "secret", text: "secret" });
    acc.apply({ itemId: "a", delta: "", text: "", replace: true });
    expect(acc.text()).toBe("");
  });

  it("keeps assistant items separate in arrival order", () => {
    const acc = createAssistantTextAccumulator();
    acc.apply({ itemId: "run:0", delta: "Checking", text: "Checking" });
    acc.apply({ itemId: "run:1", delta: "Done", text: "Done" });
    acc.apply({ itemId: "run:0", delta: " the issue", text: "Checking the issue" });
    expect(acc.text()).toBe("Checking the issue\n\nDone");
  });
});

describe("projectAssistantEventForLog", () => {
  it("drops the repeated snapshot from delta events", () => {
    expect(projectAssistantEventForLog({ itemId: "a", delta: "lo", text: "Hello" })).toEqual({
      itemId: "a",
      delta: "lo",
    });
  });

  it("keeps the snapshot when the event carries no delta or replaces the item", () => {
    expect(projectAssistantEventForLog({ itemId: "a", text: "Hello" })).toEqual({ itemId: "a", text: "Hello" });
    expect(projectAssistantEventForLog({ itemId: "a", delta: "", text: "Hi", replace: true })).toEqual({
      itemId: "a",
      delta: "",
      text: "Hi",
      replace: true,
    });
  });
});
