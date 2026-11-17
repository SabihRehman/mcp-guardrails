import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { type Guard, textResult } from "../guard.js";

/**
 * A small issue tracker, in memory.
 *
 * The point of this repo is the guardrail layer, so the backing store is
 * deliberately trivial — swapping it for Jira or Linear means replacing the
 * four functions below and changing nothing about policy or audit.
 */

export interface Issue {
  id: number;
  title: string;
  state: "open" | "closed";
  labels: string[];
  comments: string[];
}

export class IssueStore {
  private issues = new Map<number, Issue>();
  private nextId = 1;

  constructor(seed: Omit<Issue, "id" | "comments">[] = []) {
    for (const s of seed) {
      const id = this.nextId++;
      this.issues.set(id, { id, comments: [], ...s });
    }
  }

  list(state?: "open" | "closed"): Issue[] {
    const all = [...this.issues.values()];
    return state ? all.filter((i) => i.state === state) : all;
  }

  get(id: number): Issue {
    const issue = this.issues.get(id);
    if (!issue) throw new Error(`No issue with id ${id}`);
    return issue;
  }

  comment(id: number, body: string): Issue {
    const issue = this.get(id);
    issue.comments.push(body);
    return issue;
  }

  close(id: number): Issue {
    const issue = this.get(id);
    if (issue.state === "closed") throw new Error(`Issue ${id} is already closed`);
    issue.state = "closed";
    return issue;
  }
}

export function registerIssueTools(
  server: McpServer,
  guard: Guard,
  store: IssueStore,
): void {
  server.registerTool(
    "issues_list",
    {
      title: "List issues",
      description:
        "List issues in the tracker, optionally filtered by state. Read-only.",
      inputSchema: {
        state: z
          .enum(["open", "closed"])
          .optional()
          .describe("Filter by issue state. Omit for all issues."),
      },
      annotations: { readOnlyHint: true },
    },
    guard.wrap("issues.list", false, async (args: { state?: "open" | "closed" }) => {
      const issues = store.list(args.state);
      if (issues.length === 0) return textResult("No issues match that filter.");
      return textResult(
        issues
          .map(
            (i) =>
              `#${i.id} [${i.state}] ${i.title}` +
              (i.labels.length ? ` (${i.labels.join(", ")})` : "") +
              (i.comments.length ? ` — ${i.comments.length} comment(s)` : ""),
          )
          .join("\n"),
      );
    }),
  );

  server.registerTool(
    "issues_comment",
    {
      title: "Comment on an issue",
      description:
        "Add a comment to an issue. Subject to a length limit and a rate limit, so " +
        "an agent in a retry loop cannot flood a thread.",
      inputSchema: {
        id: z.number().int().positive().describe("Issue number"),
        body: z.string().min(1).describe("Comment text"),
      },
      annotations: { readOnlyHint: false, idempotentHint: false },
    },
    guard.wrap("issues.comment", true, async (args: { id: number; body: string }) => {
      const issue = store.comment(args.id, args.body);
      return textResult(
        `Commented on #${issue.id}. The thread now has ${issue.comments.length} comment(s).`,
      );
    }),
  );

  server.registerTool(
    "issues_close",
    {
      title: "Close an issue",
      description:
        "Close an issue. Configured to require human confirmation by default — " +
        "closing someone else's issue is visible to the whole team and annoying to undo.",
      inputSchema: {
        id: z.number().int().positive().describe("Issue number"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true },
    },
    guard.wrap("issues.close", true, async (args: { id: number }) => {
      const issue = store.close(args.id);
      return textResult(`Closed #${issue.id}: ${issue.title}`);
    }),
  );
}
