import { analyzeBashCommand } from "./command-analyzer.ts";
import type { Capability, Resource } from "./types.ts";

const READ_TOOLS: ReadonlySet<string> = new Set(["read", "ls", "grep", "find"]);

const MUTATE_TOOLS: ReadonlySet<string> = new Set(["edit", "write"]);

export function getToolCapability(toolName: string): Capability {
	if (READ_TOOLS.has(toolName)) return "read";
	if (MUTATE_TOOLS.has(toolName)) return "mutate";
	return "exec";
}

function readStringArg(args: unknown, key: string): string {
	if (args !== null && typeof args === "object" && key in args) {
		const value = (args as Record<string, unknown>)[key];
		return value == null ? "" : String(value);
	}
	return "";
}

export function extractResource(toolName: string, args: unknown, homeDir?: string): Resource {
	if (toolName === "bash") {
		const command = readStringArg(args, "command");
		return { kind: "command", command, accesses: analyzeBashCommand(command, homeDir) };
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
