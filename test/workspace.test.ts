import { strict as assert } from "node:assert";
import { describe, it, after } from "node:test";
import { mkdtemp, rm, writeFile, mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileAuditSink } from "../src/audit.js";
import { safeResolve } from "../src/tools/workspace.js";

const roots: string[] = [];

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "mcp-guardrails-"));
  roots.push(root);
  return root;
}

after(async () => {
  await Promise.all(roots.map((r) => rm(r, { recursive: true, force: true })));
});

describe("safeResolve", () => {
  it("resolves a path inside the root", async () => {
    const root = await makeRoot();
    assert.equal(safeResolve(root, "src/a.ts"), join(root, "src/a.ts"));
  });

  it("allows the root itself", async () => {
    const root = await makeRoot();
    assert.equal(safeResolve(root, "."), root);
  });

  it("throws on an absolute path", async () => {
    const root = await makeRoot();
    assert.throws(() => safeResolve(root, "/etc/passwd"), /absolute or escapes/);
  });

  it("throws when .. climbs out of the root", async () => {
    const root = await makeRoot();
    assert.throws(() => safeResolve(root, "../../etc/passwd"), /absolute or escapes/);
  });

  it("does not confuse a sibling directory with the root prefix", async () => {
    // A naive startsWith(root) check passes "/tmp/root-evil" when root is
    // "/tmp/root". The separator check is what stops it.
    const root = await makeRoot();
    assert.throws(() => safeResolve(root, "../" + "evil/secrets"), /escapes|outside/);
  });
});

describe("FileAuditSink", () => {
  it("appends one JSON object per line and reads the tail back", async () => {
    const root = await makeRoot();
    const path = join(root, "nested", "audit.jsonl");
    const sink = new FileAuditSink(path);

    for (let i = 1; i <= 3; i++) {
      await sink.write({
        ts: new Date(i * 1000).toISOString(),
        requestId: `req-${i}`,
        tool: "safe.read",
        args: { i },
        decision: "allow",
        reason: "ok",
        outcome: "ok",
        durationMs: i,
      });
    }

    const raw = await readFile(path, "utf8");
    assert.equal(raw.trim().split("\n").length, 3, "one line per entry");

    const tail = await sink.read(2);
    assert.deepEqual(
      tail.map((e) => e.requestId),
      ["req-2", "req-3"],
      "newest last",
    );
  });

  it("creates the parent directory on first write", async () => {
    const root = await makeRoot();
    const sink = new FileAuditSink(join(root, "a", "b", "c", "audit.jsonl"));
    await sink.write({
      ts: new Date().toISOString(),
      requestId: "r",
      tool: "t",
      args: {},
      decision: "allow",
      reason: "r",
      outcome: "ok",
      durationMs: 0,
    });
    assert.equal((await sink.read(10)).length, 1);
  });

  it("returns an empty tail when the log does not exist yet", async () => {
    const root = await makeRoot();
    const sink = new FileAuditSink(join(root, "missing.jsonl"));
    assert.deepEqual(await sink.read(10), []);
  });

  it("skips a corrupted line rather than throwing", async () => {
    const root = await makeRoot();
    const path = join(root, "audit.jsonl");
    await mkdir(root, { recursive: true });
    await writeFile(
      path,
      '{"ts":"t","requestId":"a","tool":"x","args":{},"decision":"allow","reason":"r","outcome":"ok","durationMs":1}\n' +
        "{ this is not json\n" +
        '{"ts":"t","requestId":"b","tool":"x","args":{},"decision":"allow","reason":"r","outcome":"ok","durationMs":1}\n',
      "utf8",
    );

    const entries = await new FileAuditSink(path).read(10);
    assert.deepEqual(
      entries.map((e) => e.requestId),
      ["a", "b"],
    );
  });
});
