import { describe, expect, test } from "vitest";
import { parseArgs } from "../../src/cli/args.ts";

describe("parseArgs permission flags", () => {
	describe("--permission-mode", () => {
		test("parses a valid mode", () => {
			const result = parseArgs(["--permission-mode", "acceptEdits"]);
			expect(result.permissionMode).toBe("acceptEdits");
			expect(result.diagnostics.filter((d) => d.type === "error")).toEqual([]);
		});

		test("rejects an invalid mode", () => {
			const result = parseArgs(["--permission-mode", "nope"]);
			expect(result.permissionMode).toBeUndefined();
			expect(result.diagnostics.some((d) => d.type === "error")).toBe(true);
		});

		test("reports a missing value", () => {
			const result = parseArgs(["--permission-mode"]);
			expect(result.permissionMode).toBeUndefined();
			expect(result.diagnostics.some((d) => d.type === "error")).toBe(true);
		});
	});

	describe("--allow / --deny", () => {
		test("builds cli-scoped allow and deny rules", () => {
			const result = parseArgs(["--allow", "bash(git push *)", "--deny", "read(.env)"]);
			expect(result.permissionRules).toEqual([
				{ raw: "bash(git push *)", tool: "bash", specifier: "git push *", list: "allow", scope: "cli" },
				{ raw: "read(.env)", tool: "read", specifier: ".env", list: "deny", scope: "cli" },
			]);
		});

		test("is repeatable", () => {
			const result = parseArgs(["--allow", "bash(git status)", "--allow", "bash(ls *)"]);
			expect(result.permissionRules).toHaveLength(2);
			expect(result.permissionRules?.every((r) => r.list === "allow" && r.scope === "cli")).toBe(true);
		});

		test("omits specifier for a bare tool name", () => {
			const result = parseArgs(["--allow", "bash"]);
			expect(result.permissionRules).toEqual([{ raw: "bash", tool: "bash", list: "allow", scope: "cli" }]);
		});

		test("reports a missing value", () => {
			const result = parseArgs(["--allow"]);
			expect(result.permissionRules).toBeUndefined();
			expect(result.diagnostics.some((d) => d.type === "error")).toBe(true);
		});
	});
});
