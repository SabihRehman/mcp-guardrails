import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { type Guard, textResult } from "../guard.js";
import type { AuditSink } from "../types.js";

/**
 * Exposes the audit trail back to the agent.
 *
 * This is intentional: an agent that can see it was refused, and why, can
 * explain the refusal to the person instead of silently retrying. The log is
 * already redacted, so there is nothing here a caller could not learn by
 * making the same calls itself.
 */
export function registerAuditTools(
  server: McpServer,
  guard: Guard,
  audit: AuditSink,
): void {
  server.registerTool(
    "audit_tail",
    {
      title: "Read recent audit entries",
      description:
        "Show the most recent guarded tool calls: what was called, what the policy decided, " +
        "and why. Credential-shaped values are redacted.",
      inputSchema: {
        limit: z
          .number()
          .int()
          .min(1)
          .max(200)
          .default(20)
          .describe("How many entries to return, newest last"),
      },
      annotations: { readOnlyHint: true },
    },
    guard.wrap("audit.tail", false, async (args: { limit?: number }) => {
      const entries = await audit.read(args.limit ?? 20);
      if (entries.length === 0) return textResult("Audit log is empty.");
      return textResult(
        entries
          .map(
            (e) =>
              `${e.ts}  ${e.tool.padEnd(18)} ${e.decision.padEnd(8)} ${e.outcome.padEnd(8)} ${e.durationMs}ms  ${e.reason}` +
              (e.error ? `\n    error: ${e.error}` : ""),
          )
          .join("\n"),
      );
    }),
  );
}
