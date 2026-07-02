/**
 * Maps a tool call to the two facts the decision engine needs: its coarse
 * capability (read / mutate / exec) and the concrete resource it touches
 * (command / paths / none). Built-in tool names are lowercase (verified
 * against `core/tools/*.ts`): `bash read edit write grep find ls`.
 *
 * Positioning: this is an approval guardrail, not a security boundary (see
 * ./types.ts). It is pure and total — malformed / missing args never throw,
 * they degrade to an empty-paths or `none` resource so the engine can still
 * reach a conservative decision.
 */

import { analyzeBashCommand } from "./command-analyzer.ts";
import type { Capability, Resource } from "./types.ts";

/** Built-in read-only tools (spec §8): capability `read`, paths = the touched path. */
const READ_TOOLS: ReadonlySet<string> = new Set(["read", "ls", "grep", "find"]);

/** Built-in filesystem-mutating tools (spec §8): capability `mutate`, paths = the target. */
const MUTATE_TOOLS: ReadonlySet<string> = new Set(["edit", "write"]);

/**
 * Coarse capability of a tool call (spec §8):
 * - `read`   — `read` / `ls` / `grep` / `find`
 * - `mutate` — `edit` / `write`
 * - `exec`   — `bash`, plus any custom / extension / unknown tool (default).
 */
export function getToolCapability(toolName: string): Capability {
	if (READ_TOOLS.has(toolName)) return "read";
	if (MUTATE_TOOLS.has(toolName)) return "mutate";
	// `bash` and every unknown/custom/extension tool fall back to `exec` (spec §8/§17).
	return "exec";
}

/**
 * Reads a string field off a validated-but-possibly-malformed args object,
 * mirroring the spec's `String((args as any)?.field ?? "")`: a missing or
 * nullish value becomes "", never throws, and non-object args (null,
 * primitives) degrade to "".
 */
function readStringArg(args: unknown, key: string): string {
	if (args !== null && typeof args === "object" && key in args) {
		const value = (args as Record<string, unknown>)[key];
		return value == null ? "" : String(value);
	}
	return "";
}

/**
 * Extracts the {@link Resource} a tool call touches (spec §8):
 * - `bash` → `{ kind: "command", command, accesses }` (per-subcommand analysis).
 * - `read`/`ls`/`grep`/`find` → `{ kind: "paths", paths }` (empty when no path).
 * - `edit`/`write` → `{ kind: "paths", paths: [target] }` (empty-string target if absent).
 * - anything else (custom/extension/unknown) → `{ kind: "none" }`.
 *
 * The canonical single-path field is `path` for every built-in file tool
 * (the `file_path` alias is render-layer only, never in the validated schema).
 */
export function extractResource(toolName: string, args: unknown): Resource {
	if (toolName === "bash") {
		const command = readStringArg(args, "command");
		return { kind: "command", command, accesses: analyzeBashCommand(command) };
	}
	if (READ_TOOLS.has(toolName)) {
		const path = readStringArg(args, "path");
		return { kind: "paths", paths: path ? [path] : [] };
	}
	if (MUTATE_TOOLS.has(toolName)) {
		const path = readStringArg(args, "path");
		return { kind: "paths", paths: [path] };
	}
	return { kind: "none" };
}
