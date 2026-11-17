import { randomUUID } from "node:crypto";
import { redactArgs } from "./audit.js";
import type { PolicyEngine } from "./policy.js";
import type { AuditSink, Decision } from "./types.js";

export interface GuardOptions {
  policy: PolicyEngine;
  audit: AuditSink;
  /**
   * When true, calls that the policy would allow are logged and described but
   * never executed. Useful for reviewing what an agent is about to do to a real
   * system before letting it.
   */
  dryRun?: boolean;
}

/**
 * What a guarded handler returns: the MCP tool-result shape.
 *
 * The index signature is what the SDK's `CallToolResult` expects, so a guarded
 * handler can be passed straight to `registerTool` without a cast.
 */
export interface ToolResult {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
}

export function textResult(text: string, isError = false): ToolResult {
  return { content: [{ type: "text", text }], ...(isError ? { isError } : {}) };
}

/**
 * Wrap a tool implementation with policy evaluation and audit logging.
 *
 * Every call takes the same path: evaluate, log, then execute or refuse. There
 * is no way to reach the implementation without passing the policy, because the
 * implementation is only reachable through the returned closure.
 */
export class Guard {
  private readonly policy: PolicyEngine;
  private readonly audit: AuditSink;
  private readonly dryRun: boolean;

  constructor(opts: GuardOptions) {
    this.policy = opts.policy;
    this.audit = opts.audit;
    this.dryRun = opts.dryRun ?? false;
  }

  get isDryRun(): boolean {
    return this.dryRun;
  }

  /**
   * @param tool        policy name for this tool, e.g. "issues.close"
   * @param mutating    whether the call changes state; only mutating calls are
   *                    skipped in dry-run mode, so reads stay useful.
   * @param impl        the actual work
   */
  wrap<A extends Record<string, unknown>>(
    tool: string,
    mutating: boolean,
    impl: (args: A) => Promise<ToolResult> | ToolResult,
  ): (args: A) => Promise<ToolResult> {
    return async (args: A): Promise<ToolResult> => {
      const requestId = randomUUID();
      const startedAt = Date.now();
      const safeArgs = redactArgs(args ?? {});
      const verdict = this.policy.evaluate(tool, args ?? {});

      const log = (
        outcome: "ok" | "blocked" | "error" | "dry-run",
        decision: Decision,
        reason: string,
        error?: string,
      ) =>
        this.audit.write({
          ts: new Date(startedAt).toISOString(),
          requestId,
          tool,
          args: safeArgs,
          decision,
          reason,
          outcome,
          durationMs: Date.now() - startedAt,
          ...(error ? { error } : {}),
        });

      if (verdict.decision === "deny") {
        await log("blocked", "deny", verdict.reason);
        return textResult(
          `Refused: ${verdict.reason}\n\n` +
            `This is a policy decision, not a transient failure — retrying the ` +
            `same call will be refused again. Ask a human to change the policy ` +
            `if this tool should be available.`,
          true,
        );
      }

      if (verdict.decision === "confirm") {
        await log("blocked", "confirm", verdict.reason);
        return textResult(
          `Needs human confirmation: ${verdict.reason}\n\n` +
            `The call was not executed. Arguments recorded for review ` +
            `(request ${requestId}):\n${JSON.stringify(safeArgs, null, 2)}`,
          true,
        );
      }

      if (this.dryRun && mutating) {
        await log("dry-run", verdict.decision, verdict.reason);
        return textResult(
          `Dry run — not executed. Would have called ${tool} with:\n` +
            JSON.stringify(safeArgs, null, 2),
        );
      }

      this.policy.recordCall(tool);

      try {
        const result = await impl(args);
        await log("ok", verdict.decision, verdict.reason);
        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await log("error", verdict.decision, verdict.reason, message);
        return textResult(`${tool} failed: ${message}`, true);
      }
    };
  }
}
