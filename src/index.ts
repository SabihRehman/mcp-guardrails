#!/usr/bin/env node
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { FileAuditSink, MemoryAuditSink } from "./audit.js";
import { Guard } from "./guard.js";
import { PolicyEngine } from "./policy.js";
import { IssueStore, registerIssueTools } from "./tools/issues.js";
import { registerWorkspaceTools } from "./tools/workspace.js";
import { registerAuditTools } from "./tools/audit-tool.js";
import type { AuditSink } from "./types.js";

/**
 * mcp-guardrails — entry point.
 *
 * Configuration comes from the environment so the server can be dropped into a
 * client config (Claude Desktop, Claude Code, any MCP host) without wrapper
 * scripts:
 *
 *   MCP_GUARDRAILS_POLICY    path to the policy JSON   (default ./policy.json)
 *   MCP_GUARDRAILS_ROOT      workspace root            (default cwd)
 *   MCP_GUARDRAILS_AUDIT     audit log path            (default ./.audit/calls.jsonl)
 *   MCP_GUARDRAILS_DRY_RUN   "1" to execute nothing that mutates state
 */

function env(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

/** Load the policy, or print a useful message and stop. */
function loadPolicyOrExit(policyPath: string): PolicyEngine {
  try {
    return PolicyEngine.fromFile(policyPath);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // stderr, never stdout: stdout is the JSON-RPC channel.
    process.stderr.write(
      `mcp-guardrails: could not load policy from ${policyPath}\n` +
        `  ${message}\n` +
        `  Copy policy.example.json to policy.json to get started.\n`,
    );
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const policyPath = resolve(env("MCP_GUARDRAILS_POLICY", "policy.json"));
  const workspaceRoot = resolve(env("MCP_GUARDRAILS_ROOT", process.cwd()));
  const auditPath = env("MCP_GUARDRAILS_AUDIT", ".audit/calls.jsonl");
  const dryRun = process.env["MCP_GUARDRAILS_DRY_RUN"] === "1";

  const policy = loadPolicyOrExit(policyPath);

  const audit: AuditSink =
    auditPath === "none" ? new MemoryAuditSink() : new FileAuditSink(resolve(auditPath));

  const guard = new Guard({ policy, audit, dryRun });

  const server = new McpServer(
    { name: "mcp-guardrails", version: "0.1.0" },
    {
      instructions:
        "Tools here are mediated by a policy. A refusal is a deliberate decision, " +
        "not a transient error: do not retry a refused call with the same arguments. " +
        "Use audit_tail to see what was decided and why, and report that to the user.",
    },
  );

  const issues = new IssueStore([
    { title: "Retry storm when the upstream API 502s", state: "open", labels: ["bug"] },
    { title: "Add OpenTelemetry spans around tool calls", state: "open", labels: ["observability"] },
    { title: "Document the policy file format", state: "closed", labels: ["docs"] },
  ]);

  registerIssueTools(server, guard, issues);
  registerWorkspaceTools(server, guard, { root: workspaceRoot });
  registerAuditTools(server, guard, audit);

  process.stderr.write(
    `mcp-guardrails 0.1.0 ready\n` +
      `  policy:    ${policyPath} (${policy.knownTools().length} rule(s))\n` +
      `  workspace: ${workspaceRoot}\n` +
      `  audit:     ${auditPath}\n` +
      `  dry run:   ${dryRun ? "ON — nothing that mutates state will execute" : "off"}\n`,
  );

  await server.connect(new StdioServerTransport());
}

main().catch((err) => {
  process.stderr.write(
    `mcp-guardrails: fatal: ${err instanceof Error ? err.stack : String(err)}\n`,
  );
  process.exit(1);
});
