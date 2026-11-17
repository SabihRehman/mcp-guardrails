/**
 * Core types for the guardrail layer.
 *
 * The design goal: an agent's capability should be described in data, not
 * scattered through handler code. A reviewer should be able to read one JSON
 * file and know exactly what the agent can and cannot do.
 */

/** What the policy engine decided about a single tool call. */
export type Decision = "allow" | "deny" | "confirm";

/** Constraints applied to a single argument of a tool call. */
export interface ArgConstraint {
  /** Reject strings longer than this. */
  maxLength?: number;
  /** Reject numbers above this. */
  maxNumber?: number;
  /** Value must be one of these. */
  oneOf?: (string | number)[];
  /** Path must start with one of these prefixes (after normalisation). */
  pathPrefix?: string[];
  /** Path must not match any of these substrings. Cheap, predictable, no glob engine. */
  pathDeny?: string[];
  /** String must match this regular expression (given as a source string). */
  matches?: string;
}

export interface RateLimit {
  /** Maximum number of successful calls to this tool per rolling minute. */
  perMinute: number;
}

export interface PolicyRule {
  /** Tool name this rule applies to, e.g. "issues.close". */
  tool: string;
  decision: Decision;
  /** Human-readable justification, surfaced to the agent and written to the audit log. */
  reason?: string;
  /** Per-argument constraints. A violation turns an "allow" into a "deny". */
  constraints?: Record<string, ArgConstraint>;
  rateLimit?: RateLimit;
}

export interface Policy {
  /** Applied when no rule matches. Defaults to "deny" — an unlisted tool is not callable. */
  defaultDecision?: Decision;
  rules: PolicyRule[];
}

/** The outcome of evaluating a call against the policy. */
export interface PolicyVerdict {
  decision: Decision;
  reason: string;
  /** Which rule matched, for the audit log. `null` when the default applied. */
  matchedTool: string | null;
}

/** One line in the audit log. Append-only, one JSON object per line. */
export interface AuditEntry {
  ts: string;
  requestId: string;
  tool: string;
  /** Arguments after redaction of anything that looks like a credential. */
  args: Record<string, unknown>;
  decision: Decision;
  reason: string;
  outcome: "ok" | "blocked" | "error" | "dry-run";
  durationMs: number;
  error?: string;
}

export interface AuditSink {
  write(entry: AuditEntry): Promise<void>;
  /** Most recent entries, newest last. Used by the audit.tail tool and by tests. */
  read(limit: number): Promise<AuditEntry[]>;
}
