import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEntry, AuditSink } from "./types.js";

/**
 * Keys whose values never reach the log. Matched case-insensitively against the
 * argument name, so `authToken`, `API_KEY` and `password` are all covered.
 */
const SENSITIVE_KEY = /token|secret|password|passwd|api[-_]?key|authorization|cookie|credential/i;

export const REDACTED = "[redacted]";

/**
 * Replace credential-shaped values with a placeholder, recursively.
 *
 * The audit log is the one artefact a reviewer is most likely to paste into a
 * ticket, so it must be safe to share by construction rather than by habit.
 */
export function redact(value: unknown, keyHint?: string): unknown {
  if (keyHint && SENSITIVE_KEY.test(keyHint)) return REDACTED;

  if (Array.isArray(value)) return value.map((v) => redact(v));

  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redact(v, k);
    }
    return out;
  }

  return value;
}

export function redactArgs(
  args: Record<string, unknown>,
): Record<string, unknown> {
  return redact(args) as Record<string, unknown>;
}

/**
 * Append-only JSONL audit log.
 *
 * One JSON object per line, opened in append mode for every write. That makes
 * the file greppable, tail-able, survivable across restarts, and awkward to
 * rewrite after the fact — which is the point of an audit trail.
 */
export class FileAuditSink implements AuditSink {
  /** Created once, on the first write, then reused. */
  private ready: Promise<void> | undefined;

  constructor(private readonly path: string) {}

  private ensureDir(): Promise<void> {
    if (this.ready === undefined) {
      this.ready = mkdir(dirname(this.path), { recursive: true }).then(
        () => undefined,
      );
    }
    return this.ready;
  }

  async write(entry: AuditEntry): Promise<void> {
    await this.ensureDir();
    await appendFile(this.path, JSON.stringify(entry) + "\n", "utf8");
  }

  async read(limit: number): Promise<AuditEntry[]> {
    let raw: string;
    try {
      raw = await readFile(this.path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }

    const lines = raw.split("\n").filter((l) => l.trim() !== "");
    return lines
      .slice(-limit)
      .map((line) => {
        try {
          return JSON.parse(line) as AuditEntry;
        } catch {
          return null;
        }
      })
      .filter((e): e is AuditEntry => e !== null);
  }
}

/** In-memory sink, for tests and for `--no-audit-file` runs. */
export class MemoryAuditSink implements AuditSink {
  readonly entries: AuditEntry[] = [];

  async write(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  async read(limit: number): Promise<AuditEntry[]> {
    return this.entries.slice(-limit);
  }
}
