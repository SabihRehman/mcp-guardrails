import { strict as assert } from "node:assert";
import { describe, it, beforeEach } from "node:test";
import { MemoryAuditSink, REDACTED, redactArgs } from "../src/audit.js";
import { Guard, textResult } from "../src/guard.js";
import { PolicyEngine } from "../src/policy.js";
import type { Policy } from "../src/types.js";

const policy: Policy = {
  defaultDecision: "deny",
  rules: [
    { tool: "safe.read", decision: "allow" },
    { tool: "safe.write", decision: "allow" },
    { tool: "risky.close", decision: "confirm", reason: "Needs a human" },
    { tool: "forbidden.delete", decision: "deny", reason: "Never" },
  ],
};

function setup(dryRun = false) {
  const audit = new MemoryAuditSink();
  const guard = new Guard({ policy: new PolicyEngine(policy), audit, dryRun });
  return { audit, guard };
}

describe("Guard", () => {
  let calls: string[];

  beforeEach(() => {
    calls = [];
  });

  it("executes an allowed call and logs it as ok", async () => {
    const { guard, audit } = setup();
    const handler = guard.wrap("safe.read", false, async () => {
      calls.push("ran");
      return textResult("content");
    });

    const result = await handler({});
    assert.equal(result.content[0]?.text, "content");
    assert.deepEqual(calls, ["ran"]);

    const [entry] = await audit.read(1);
    assert.equal(entry?.tool, "safe.read");
    assert.equal(entry?.decision, "allow");
    assert.equal(entry?.outcome, "ok");
  });

  it("does not run the implementation when the policy denies", async () => {
    const { guard, audit } = setup();
    const handler = guard.wrap("forbidden.delete", true, async () => {
      calls.push("ran");
      return textResult("deleted");
    });

    const result = await handler({});
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? "", /Refused: Never/);
    assert.deepEqual(calls, [], "implementation must not be reached");

    const [entry] = await audit.read(1);
    assert.equal(entry?.outcome, "blocked");
    assert.equal(entry?.decision, "deny");
  });

  it("tells the agent a refusal is not worth retrying", async () => {
    const { guard } = setup();
    const handler = guard.wrap("forbidden.delete", true, async () => textResult("x"));
    const result = await handler({});
    assert.match(result.content[0]?.text ?? "", /retrying the same call will be refused/i);
  });

  it("holds a confirm-tier call and echoes the arguments for review", async () => {
    const { guard, audit } = setup();
    const handler = guard.wrap("risky.close", true, async () => {
      calls.push("ran");
      return textResult("closed");
    });

    const result = await handler({ id: 42 });
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? "", /Needs human confirmation/);
    assert.match(result.content[0]?.text ?? "", /"id": 42/);
    assert.deepEqual(calls, []);

    const [entry] = await audit.read(1);
    assert.equal(entry?.decision, "confirm");
    assert.equal(entry?.outcome, "blocked");
  });

  it("denies an unlisted tool without running it", async () => {
    const { guard } = setup();
    const handler = guard.wrap("never.declared", true, async () => {
      calls.push("ran");
      return textResult("x");
    });
    const result = await handler({});
    assert.equal(result.isError, true);
    assert.deepEqual(calls, []);
  });

  it("converts a thrown error into an error result and logs it", async () => {
    const { guard, audit } = setup();
    const handler = guard.wrap("safe.read", false, async () => {
      throw new Error("disk on fire");
    });

    const result = await handler({});
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? "", /disk on fire/);

    const [entry] = await audit.read(1);
    assert.equal(entry?.outcome, "error");
    assert.equal(entry?.error, "disk on fire");
  });

  it("records a duration and a unique request id per call", async () => {
    const { guard, audit } = setup();
    const handler = guard.wrap("safe.read", false, async () => textResult("ok"));

    await handler({});
    await handler({});

    const entries = await audit.read(2);
    assert.equal(entries.length, 2);
    assert.notEqual(entries[0]?.requestId, entries[1]?.requestId);
    for (const e of entries) {
      assert.equal(typeof e.durationMs, "number");
      assert.ok(e.durationMs >= 0);
    }
  });

  describe("dry run", () => {
    it("skips mutating calls but still logs them", async () => {
      const { guard, audit } = setup(true);
      const handler = guard.wrap("safe.write", true, async () => {
        calls.push("ran");
        return textResult("written");
      });

      const result = await handler({ path: "src/a.ts" });
      assert.match(result.content[0]?.text ?? "", /Dry run — not executed/);
      assert.deepEqual(calls, []);

      const [entry] = await audit.read(1);
      assert.equal(entry?.outcome, "dry-run");
    });

    it("still runs read-only calls, so inspection stays useful", async () => {
      const { guard } = setup(true);
      const handler = guard.wrap("safe.read", false, async () => {
        calls.push("ran");
        return textResult("content");
      });

      const result = await handler({});
      assert.equal(result.content[0]?.text, "content");
      assert.deepEqual(calls, ["ran"]);
    });
  });
});

describe("redaction", () => {
  it("masks credential-shaped keys at any depth", () => {
    const out = redactArgs({
      path: "src/a.ts",
      apiKey: "sk-live-123",
      nested: { authToken: "abc", keep: "visible" },
      list: [{ password: "hunter2" }],
    });

    assert.equal(out["path"], "src/a.ts");
    assert.equal(out["apiKey"], REDACTED);
    assert.deepEqual(out["nested"], { authToken: REDACTED, keep: "visible" });
    assert.deepEqual(out["list"], [{ password: REDACTED }]);
  });

  it("matches key names case-insensitively and with separators", () => {
    const out = redactArgs({
      API_KEY: "x",
      "api-key": "x",
      Authorization: "x",
      secret_value: "x",
    });
    for (const v of Object.values(out)) assert.equal(v, REDACTED);
  });

  it("leaves ordinary values untouched", () => {
    const out = redactArgs({ id: 7, body: "hello", flag: true, nil: null });
    assert.deepEqual(out, { id: 7, body: "hello", flag: true, nil: null });
  });

  it("redacts before the audit log sees the arguments", async () => {
    const audit = new MemoryAuditSink();
    const guard = new Guard({ policy: new PolicyEngine(policy), audit });
    const handler = guard.wrap("safe.read", false, async () => textResult("ok"));

    await handler({ token: "sk-live-should-never-be-logged" });

    const [entry] = await audit.read(1);
    assert.equal(entry?.args["token"], REDACTED);
    assert.ok(
      !JSON.stringify(entry).includes("sk-live-should-never-be-logged"),
      "raw credential must not appear anywhere in the entry",
    );
  });
});
