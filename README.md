# mcp-guardrails

An MCP server that puts a **policy layer** and an **append-only audit trail** in front of the tools an AI agent is allowed to call.

The useful question about an agent integration is rarely "can it call the API?" — it's **what is it allowed to do, what is it not, and can you prove afterwards what it did?** This server answers those three questions as a reusable layer rather than as conditionals scattered through tool handlers.

```
agent ──▶ MCP tool call ──▶ [ policy engine ] ──▶ implementation
                                   │                     │
                                   └──────▶ audit log ◀──┘
```

Every call takes the same path: evaluate, log, then execute or refuse. The implementation is only reachable through the guard closure, so there is no code path that reaches a side effect without passing the policy first.

## Why this shape

**Capability is data, not code.** What an agent may do lives in one JSON file a reviewer can read in a minute. The alternative — permission checks inline in each handler — means the real answer to "what can this agent do?" is spread across a codebase and nobody is certain.

**Unlisted means denied.** The default decision is `deny`. Adding a tool to the server does not make it callable; adding it to the policy does. A new tool that someone forgot to think about fails closed.

**Three tiers, not two.** `allow` / `deny` is too coarse for the operations that are legitimate but consequential — closing someone's ticket, writing to a shared branch. Those get `confirm`: the call is logged with its arguments and refused, so a human can look at exactly what was proposed.

**A refusal is not an error.** When the policy says no, the agent is told so explicitly, including that retrying will not help. Agents handed a bare failure tend to retry in a loop; being told *"this is a policy decision, ask a human to change the policy"* ends the loop and gives the model something useful to relay.

**The audit log is safe to share by construction.** Credential-shaped argument names (`token`, `apiKey`, `authorization`, `password`, …) are redacted recursively before anything is written. The log is the artefact most likely to end up pasted into a ticket, so it shouldn't depend on the person remembering to scrub it.

**Constraints only ever tighten.** A constraint can turn an `allow` into a `deny`, never the reverse. There is no ordering puzzle where an argument rule accidentally grants access.

## Quick start

```bash
npm install
cp policy.example.json policy.json
npm test          # builds, then runs 45 tests
npm start         # serves over stdio
```

Point an MCP client at it:

```json
{
  "mcpServers": {
    "guardrails": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-guardrails/dist/src/index.js"],
      "env": {
        "MCP_GUARDRAILS_POLICY": "/absolute/path/to/policy.json",
        "MCP_GUARDRAILS_ROOT": "/absolute/path/to/a/workspace"
      }
    }
  }
}
```

| Variable | Default | Purpose |
|---|---|---|
| `MCP_GUARDRAILS_POLICY` | `./policy.json` | Policy file. Startup fails loudly if it's missing or malformed. |
| `MCP_GUARDRAILS_ROOT` | cwd | Directory the workspace tools are confined to. |
| `MCP_GUARDRAILS_AUDIT` | `.audit/calls.jsonl` | Audit log path, or `none` to keep it in memory. |
| `MCP_GUARDRAILS_DRY_RUN` | off | `1` logs and describes mutating calls without executing them. |

## Writing a policy

```json
{
  "defaultDecision": "deny",
  "rules": [
    { "tool": "issues.list", "decision": "allow" },

    {
      "tool": "issues.comment",
      "decision": "allow",
      "reason": "Commenting is reversible and useful",
      "constraints": { "body": { "maxLength": 2000 } },
      "rateLimit": { "perMinute": 5 }
    },

    {
      "tool": "issues.close",
      "decision": "confirm",
      "reason": "Closing an issue is visible to the whole team"
    },

    {
      "tool": "workspace.write",
      "decision": "allow",
      "constraints": {
        "path": { "pathPrefix": ["src/", "test/"], "pathDeny": [".env", "secret"] },
        "content": { "maxLength": 100000 }
      }
    }
  ]
}
```

Constraints: `maxLength`, `maxNumber`, `oneOf`, `matches` (regex source), `pathPrefix`, `pathDeny`.

### The path check, specifically

Path arguments are **normalised before** the prefix test. This matters more than it looks:

```
src/../.env   →  normalises to  .env   →  fails the "src/" prefix rule
```

A naive `path.startsWith("src/")` accepts that string, and the consequence is reading a credentials file. Absolute paths and anything climbing above the root are rejected outright. The workspace tools then *independently* resolve-and-compare against the root, including the trailing-separator check that stops `/tmp/root-evil` passing for `/tmp/root`. Two layers, because a prefix rule in a config file is easy to get subtly wrong and the blast radius is secrets.

## Tools included

The tools are a realistic demonstration surface; the guard layer is the reusable part. Swapping the in-memory issue store for Jira or Linear means replacing four functions and changing nothing about policy or audit.

| Tool | Policy name | Mutating |
|---|---|---|
| `issues_list` | `issues.list` | no |
| `issues_comment` | `issues.comment` | yes |
| `issues_close` | `issues.close` | yes |
| `workspace_list` | `workspace.list` | no |
| `workspace_read` | `workspace.read` | no |
| `workspace_write` | `workspace.write` | yes |
| `audit_tail` | `audit.tail` | no |

`audit_tail` deliberately exposes the trail back to the agent. An agent that can see *why* it was refused can explain it to the user instead of silently retrying, and the log is already redacted — there is nothing in it a caller couldn't learn by making the same calls.

## Audit format

One JSON object per line, opened in append mode per write — greppable, `tail -f`-able, survives restarts, and awkward to rewrite after the fact.

```json
{"ts":"2026-11-16T09:08:29.359Z","requestId":"3f2a…","tool":"issues.comment","args":{"id":1,"body":"note"},"decision":"deny","reason":"Rate limit reached for \"issues.comment\": at most 5 call(s) per minute","outcome":"blocked","durationMs":0}
```

`decision` is what the policy said; `outcome` is what happened (`ok`, `blocked`, `error`, `dry-run`). They're separate fields because "allowed but then threw" and "never allowed" are different failures and you want to tell them apart at 3am.

## Tests

```
$ npm test
# tests 45
# pass 45
# fail 0
```

Node's built-in runner, no test framework dependency. The clock is injectable, so the rate-limit tests assert window roll-over without sleeping. Coverage worth calling out:

- unlisted tools fail closed
- constraints can tighten `allow` → `deny` but never loosen a `deny`
- a refused call doesn't consume rate-limit budget
- the `src/../.env` prefix bypass is rejected
- a sibling directory doesn't satisfy the root-prefix check
- credentials are redacted before the sink sees them, verified by asserting the raw secret appears nowhere in the serialised entry
- a corrupted audit line is skipped rather than throwing

## Limitations

Worth stating plainly rather than discovering later:

- **Rate limits are per-process and in-memory.** Restarting resets them; two instances don't share a window. Fine for a single stdio server, wrong for a multi-replica deployment — that needs a shared store.
- **`confirm` has no approval channel.** It refuses and records the arguments; wiring it to Slack or a web approval step is integration-specific and deliberately out of scope here.
- **The policy is matched on exact tool names.** No globs. Adding them would mean precedence rules, which is exactly the complexity this design avoids.
- **The issue store is in memory.** Restarting loses comments. It's a demonstration surface, not a tracker.

## Licence

MIT
