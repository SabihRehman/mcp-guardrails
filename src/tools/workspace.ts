import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { type Guard, textResult } from "../guard.js";
import { normalisePath } from "../policy.js";

/**
 * Workspace file tools.
 *
 * Two independent layers stop a path escaping the workspace:
 *
 *   1. the policy's pathPrefix / pathDeny constraints, which are declarative
 *      and visible to a reviewer in the policy file; and
 *   2. the resolve-and-compare check below, which is unconditional.
 *
 * Belt and braces is the right call here: a prefix rule in a config file is
 * easy to get subtly wrong, and the consequence is reading a credentials file.
 */

export interface WorkspaceOptions {
  /** Absolute path the agent is confined to. */
  root: string;
}

/** Resolve a caller-supplied path inside the root, or throw. */
export function safeResolve(root: string, candidate: string): string {
  const normalised = normalisePath(candidate);
  if (normalised === null) {
    throw new Error(`Path "${candidate}" is absolute or escapes the workspace root`);
  }

  const absoluteRoot = resolve(root);
  const target = resolve(absoluteRoot, normalised);

  if (target !== absoluteRoot && !target.startsWith(absoluteRoot + sep)) {
    throw new Error(`Path "${candidate}" resolves outside the workspace root`);
  }

  return target;
}

export function registerWorkspaceTools(
  server: McpServer,
  guard: Guard,
  opts: WorkspaceOptions,
): void {
  server.registerTool(
    "workspace_list",
    {
      title: "List a workspace directory",
      description: "List file and directory names at a path inside the workspace. Read-only.",
      inputSchema: {
        path: z.string().default(".").describe("Directory path, relative to the workspace root"),
      },
      annotations: { readOnlyHint: true },
    },
    guard.wrap("workspace.list", false, async (args: { path?: string }) => {
      const target = safeResolve(opts.root, args.path ?? ".");
      const entries = await readdir(target, { withFileTypes: true });
      if (entries.length === 0) return textResult("(empty directory)");
      return textResult(
        entries
          .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
          .sort()
          .join("\n"),
      );
    }),
  );

  server.registerTool(
    "workspace_read",
    {
      title: "Read a workspace file",
      description:
        "Read a UTF-8 file inside the workspace. The policy restricts which paths are readable.",
      inputSchema: {
        path: z.string().describe("File path, relative to the workspace root"),
      },
      annotations: { readOnlyHint: true },
    },
    guard.wrap("workspace.read", false, async (args: { path: string }) => {
      const target = safeResolve(opts.root, args.path);
      const content = await readFile(target, "utf8");
      return textResult(content);
    }),
  );

  server.registerTool(
    "workspace_write",
    {
      title: "Write a workspace file",
      description:
        "Create or overwrite a UTF-8 file inside the workspace. The policy restricts which " +
        "paths are writable and how large the content may be.",
      inputSchema: {
        path: z.string().describe("File path, relative to the workspace root"),
        content: z.string().describe("Full file content to write"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true },
    },
    guard.wrap(
      "workspace.write",
      true,
      async (args: { path: string; content: string }) => {
        const target = safeResolve(opts.root, args.path);
        await mkdir(dirname(target), { recursive: true });
        await writeFile(target, args.content, "utf8");
        return textResult(
          `Wrote ${args.content.length} bytes to ${join(".", normalisePath(args.path) ?? args.path)}`,
        );
      },
    ),
  );
}
