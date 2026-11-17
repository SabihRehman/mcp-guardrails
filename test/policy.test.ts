import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { PolicyEngine, checkConstraint, normalisePath } from "../src/policy.js";
import type { Policy } from "../src/types.js";

const policy: Policy = {
  defaultDecision: "deny",
  rules: [
    { tool: "issues.list", decision: "allow" },
    { tool: "issues.close", decision: "confirm", reason: "Visible to the team" },
    { tool: "repo.delete", decision: "deny", reason: "Never delegated" },
    {
      tool: "issues.comment",
      decision: "allow",
      constraints: { body: { maxLength: 10 } },
      rateLimit: { perMinute: 2 },
    },
    {
      tool: "workspace.write",
      decision: "allow",
      constraints: { path: { pathPrefix: ["src/"], pathDeny: [".env"] } },
    },
  ],
};

describe("PolicyEngine", () => {
  it("allows a tool the policy allows", () => {
    const engine = new PolicyEngine(policy);
    assert.equal(engine.evaluate("issues.list", {}).decision, "allow");
  });

  it("denies an unlisted tool rather than falling open", () => {
    const engine = new PolicyEngine(policy);
    const verdict = engine.evaluate("issues.nuke", {});
    assert.equal(verdict.decision, "deny");
    assert.equal(verdict.matchedTool, null);
    assert.match(verdict.reason, /policy default/);
  });

  it("honours an explicit allow-by-default policy", () => {
    const engine = new PolicyEngine({ defaultDecision: "allow", rules: [] });
    assert.equal(engine.evaluate("anything", {}).decision, "allow");
  });

  it("returns confirm for tools that need a human", () => {
    const engine = new PolicyEngine(policy);
    const verdict = engine.evaluate("issues.close", { id: 1 });
    assert.equal(verdict.decision, "confirm");
    assert.equal(verdict.reason, "Visible to the team");
  });

  it("carries the rule's reason into a denial", () => {
    const engine = new PolicyEngine(policy);
    assert.equal(engine.evaluate("repo.delete", {}).reason, "Never delegated");
  });

  it("downgrades allow to deny when a constraint is violated", () => {
    const engine = new PolicyEngine(policy);
    assert.equal(
      engine.evaluate("issues.comment", { body: "short" }).decision,
      "allow",
    );
    const tooLong = engine.evaluate("issues.comment", {
      body: "this body is far too long to pass",
    });
    assert.equal(tooLong.decision, "deny");
    assert.match(tooLong.reason, /limit is 10/);
  });

  it("never lets a constraint loosen a deny", () => {
    const engine = new PolicyEngine({
      rules: [
        {
          tool: "repo.delete",
          decision: "deny",
          constraints: { path: { pathPrefix: ["src/"] } },
        },
      ],
    });
    // Even a perfectly valid path stays denied.
    assert.equal(engine.evaluate("repo.delete", { path: "src/a.ts" }).decision, "deny");
  });

  describe("rate limiting", () => {
    it("blocks once the per-minute budget is spent", () => {
      const engine = new PolicyEngine(policy);
      const t0 = 1_000_000;

      assert.equal(engine.evaluate("issues.comment", { body: "a" }, t0).decision, "allow");
      engine.recordCall("issues.comment", t0);
      assert.equal(engine.evaluate("issues.comment", { body: "a" }, t0).decision, "allow");
      engine.recordCall("issues.comment", t0);

      const third = engine.evaluate("issues.comment", { body: "a" }, t0);
      assert.equal(third.decision, "deny");
      assert.match(third.reason, /Rate limit/);
    });

    it("lets the window roll over after a minute", () => {
      const engine = new PolicyEngine(policy);
      const t0 = 1_000_000;

      engine.recordCall("issues.comment", t0);
      engine.recordCall("issues.comment", t0);
      assert.equal(engine.evaluate("issues.comment", { body: "a" }, t0).decision, "deny");

      // 61 seconds later the earlier calls have aged out.
      assert.equal(
        engine.evaluate("issues.comment", { body: "a" }, t0 + 61_000).decision,
        "allow",
      );
    });

    it("does not spend budget on a call that was refused", () => {
      const engine = new PolicyEngine(policy);
      const t0 = 2_000_000;

      // A constraint violation is refused before recordCall would be reached.
      assert.equal(
        engine.evaluate("issues.comment", { body: "way too long to allow" }, t0).decision,
        "deny",
      );
      // Budget is untouched, so two good calls still go through.
      assert.equal(engine.evaluate("issues.comment", { body: "ok" }, t0).decision, "allow");
      engine.recordCall("issues.comment", t0);
      assert.equal(engine.evaluate("issues.comment", { body: "ok" }, t0).decision, "allow");
    });
  });

  it("reports the tools it knows about", () => {
    const engine = new PolicyEngine(policy);
    assert.deepEqual(engine.knownTools().sort(), [
      "issues.close",
      "issues.comment",
      "issues.list",
      "repo.delete",
      "workspace.write",
    ]);
  });
});

describe("normalisePath", () => {
  it("collapses . and redundant separators", () => {
    assert.equal(normalisePath("src/./a//b.ts"), "src/a/b.ts");
  });

  it("collapses .. inside the root", () => {
    assert.equal(normalisePath("src/sub/../a.ts"), "src/a.ts");
  });

  it("rejects paths that climb out of the root", () => {
    assert.equal(normalisePath("../etc/passwd"), null);
    assert.equal(normalisePath("src/../../etc/passwd"), null);
  });

  it("rejects absolute paths, POSIX and Windows", () => {
    assert.equal(normalisePath("/etc/passwd"), null);
    assert.equal(normalisePath("C:\\Windows\\System32"), null);
  });

  it("treats backslashes as separators", () => {
    assert.equal(normalisePath("src\\a.ts"), "src/a.ts");
  });
});

describe("checkConstraint", () => {
  it("passes over absent values and leaves requiredness to the schema", () => {
    assert.equal(checkConstraint("body", undefined, { maxLength: 1 }), null);
    assert.equal(checkConstraint("body", null, { maxLength: 1 }), null);
  });

  it("enforces maxLength, maxNumber and oneOf", () => {
    assert.equal(checkConstraint("b", "ab", { maxLength: 1 })?.includes("limit is 1"), true);
    assert.equal(checkConstraint("n", 11, { maxNumber: 10 })?.includes("limit is 10"), true);
    assert.match(
      checkConstraint("s", "x", { oneOf: ["a", "b"] }) ?? "",
      /must be one of a, b/,
    );
  });

  it("enforces a regular expression", () => {
    assert.equal(checkConstraint("s", "abc", { matches: "^a" }), null);
    assert.notEqual(checkConstraint("s", "zbc", { matches: "^a" }), null);
  });

  it("blocks a prefix bypass via ..", () => {
    // The whole reason paths are normalised before the prefix test.
    const violation = checkConstraint("path", "src/../.env", {
      pathPrefix: ["src/"],
    });
    assert.notEqual(violation, null);
  });

  it("blocks denied path fragments even under an allowed prefix", () => {
    const violation = checkConstraint("path", "src/.env", {
      pathPrefix: ["src/"],
      pathDeny: [".env"],
    });
    assert.match(violation ?? "", /denied path pattern/);
  });

  it("accepts a legitimate path under an allowed prefix", () => {
    assert.equal(
      checkConstraint("path", "src/tools/issues.ts", {
        pathPrefix: ["src/", "test/"],
        pathDeny: [".env"],
      }),
      null,
    );
  });

  it("rejects an escape attempt outright", () => {
    assert.match(
      checkConstraint("path", "../../etc/passwd", { pathPrefix: ["src/"] }) ?? "",
      /escapes the workspace root/,
    );
  });
});
