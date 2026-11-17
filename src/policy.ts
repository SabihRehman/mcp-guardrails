import { readFileSync } from "node:fs";
import type {
  ArgConstraint,
  Policy,
  PolicyRule,
  PolicyVerdict,
} from "./types.js";

/**
 * The policy engine.
 *
 * Deliberately boring: first matching rule wins, unknown tools are denied, and
 * every decision carries a reason string. There is no inheritance, no wildcard
 * precedence puzzle and no implicit allow — the failure mode of a clever policy
 * language is that nobody can say for certain what an agent is permitted to do.
 */
export class PolicyEngine {
  private readonly rules: Map<string, PolicyRule>;
  private readonly defaultDecision: PolicyVerdict["decision"];
  /** tool -> timestamps (ms) of recent counted calls, for rate limiting. */
  private readonly recentCalls = new Map<string, number[]>();

  constructor(policy: Policy) {
    this.rules = new Map(policy.rules.map((r) => [r.tool, r]));
    this.defaultDecision = policy.defaultDecision ?? "deny";
  }

  static fromFile(path: string): PolicyEngine {
    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as Policy;
    if (!parsed || !Array.isArray(parsed.rules)) {
      throw new Error(
        `Policy file ${path} must be an object with a "rules" array`,
      );
    }
    return new PolicyEngine(parsed);
  }

  /** Tool names the policy mentions, whatever their decision. */
  knownTools(): string[] {
    return [...this.rules.keys()];
  }

  /**
   * Evaluate a call. Pure apart from the rate-limit clock, so it is easy to test.
   *
   * @param now injectable clock, in ms, so rate-limit tests don't need to sleep.
   */
  evaluate(
    tool: string,
    args: Record<string, unknown>,
    now: number = Date.now(),
  ): PolicyVerdict {
    const rule = this.rules.get(tool);

    if (!rule) {
      return {
        decision: this.defaultDecision,
        reason:
          this.defaultDecision === "allow"
            ? `No rule for "${tool}"; policy default allows it`
            : `No rule for "${tool}"; denied by policy default`,
        matchedTool: null,
      };
    }

    if (rule.decision === "deny") {
      return {
        decision: "deny",
        reason: rule.reason ?? `Policy denies "${tool}"`,
        matchedTool: tool,
      };
    }

    // Constraints can only ever tighten a decision, never loosen it.
    if (rule.constraints) {
      for (const [argName, constraint] of Object.entries(rule.constraints)) {
        const violation = checkConstraint(argName, args[argName], constraint);
        if (violation) {
          return {
            decision: "deny",
            reason: `Argument check failed for "${tool}": ${violation}`,
            matchedTool: tool,
          };
        }
      }
    }

    if (rule.rateLimit && this.isRateLimited(tool, rule.rateLimit.perMinute, now)) {
      return {
        decision: "deny",
        reason: `Rate limit reached for "${tool}": at most ${rule.rateLimit.perMinute} call(s) per minute`,
        matchedTool: tool,
      };
    }

    return {
      decision: rule.decision,
      reason: rule.reason ?? `Policy allows "${tool}"`,
      matchedTool: tool,
    };
  }

  /**
   * Record a call against the rate-limit window. Called only once a call is
   * actually going through, so a denied call never consumes budget.
   */
  recordCall(tool: string, now: number = Date.now()): void {
    const window = this.recentCalls.get(tool) ?? [];
    window.push(now);
    this.recentCalls.set(tool, pruneWindow(window, now));
  }

  private isRateLimited(tool: string, perMinute: number, now: number): boolean {
    const window = pruneWindow(this.recentCalls.get(tool) ?? [], now);
    this.recentCalls.set(tool, window);
    return window.length >= perMinute;
  }
}

const ONE_MINUTE_MS = 60_000;

function pruneWindow(window: number[], now: number): number[] {
  return window.filter((t) => now - t < ONE_MINUTE_MS);
}

/**
 * Returns a human-readable violation message, or null when the argument passes.
 * Absent arguments are not the constraint layer's problem — the tool's own
 * schema decides whether something is required.
 */
export function checkConstraint(
  argName: string,
  value: unknown,
  c: ArgConstraint,
): string | null {
  if (value === undefined || value === null) return null;

  if (c.maxLength !== undefined && typeof value === "string") {
    if (value.length > c.maxLength) {
      return `${argName} is ${value.length} characters, limit is ${c.maxLength}`;
    }
  }

  if (c.maxNumber !== undefined && typeof value === "number") {
    if (value > c.maxNumber) {
      return `${argName} is ${value}, limit is ${c.maxNumber}`;
    }
  }

  if (c.oneOf !== undefined) {
    if (
      (typeof value === "string" || typeof value === "number") &&
      !c.oneOf.includes(value)
    ) {
      return `${argName} must be one of ${c.oneOf.join(", ")}`;
    }
  }

  if (c.matches !== undefined && typeof value === "string") {
    if (!new RegExp(c.matches).test(value)) {
      return `${argName} does not match ${c.matches}`;
    }
  }

  if (typeof value === "string" && (c.pathPrefix || c.pathDeny)) {
    const normalised = normalisePath(value);

    if (normalised === null) {
      return `${argName} escapes the workspace root`;
    }

    if (c.pathDeny?.some((bad) => normalised.includes(bad))) {
      return `${argName} ("${normalised}") matches a denied path pattern`;
    }

    if (c.pathPrefix && !c.pathPrefix.some((p) => normalised.startsWith(p))) {
      return `${argName} ("${normalised}") must start with one of: ${c.pathPrefix.join(", ")}`;
    }
  }

  return null;
}

/**
 * Collapse a relative path and reject anything that climbs out of the root or
 * is absolute. Returns null when the path is not acceptable at all.
 *
 * Path checks are done on the normalised form so that "src/../.env" cannot slip
 * past a "src/" prefix rule — the single most common way a prefix check fails.
 */
export function normalisePath(input: string): string | null {
  if (input.startsWith("/") || /^[A-Za-z]:[\\/]/.test(input)) return null;

  const segments: string[] = [];
  for (const segment of input.replace(/\\/g, "/").split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (segments.length === 0) return null; // escaped the root
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return segments.join("/");
}
