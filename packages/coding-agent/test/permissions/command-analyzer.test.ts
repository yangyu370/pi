import { describe, expect, it } from "vitest";
import {
	analyzeBashCommand,
	isReadonlyGitSubcommand,
	READONLY_COMMANDS,
} from "../../src/core/permissions/command-analyzer.ts";

describe("analyzeBashCommand", () => {
	it("splits on top-level && || ; and newline", () => {
		const a = analyzeBashCommand("cd x && git status; ls -la");
		expect(a.map((c) => c.command)).toEqual(["cd x", "git status", "ls -la"]);
	});
	it("marks built-in read-only commands", () => {
		expect(analyzeBashCommand("ls -la")[0].readonly).toBe(true);
		expect(analyzeBashCommand("git status")[0].readonly).toBe(true);
		expect(analyzeBashCommand("git push")[0].readonly).toBe(false);
	});
	it("find/sed are not read-only", () => {
		expect(analyzeBashCommand("find . -name x")[0].readonly).toBe(false);
		expect(analyzeBashCommand("sed -i s/a/b/ f")[0].readonly).toBe(false);
	});
	it("high-risk structures collapse to a single high-risk access", () => {
		const piped = analyzeBashCommand("cat x | grep y");
		expect(piped).toHaveLength(1);
		expect(piped[0].highRiskReason).toBeTruthy();
		expect(piped[0].readonly).toBe(false);
		expect(analyzeBashCommand("find . -delete")[0].highRiskReason).toBeTruthy();
	});
	it("detects circuit breaker on rm of / and ~", () => {
		expect(analyzeBashCommand("rm -rf /")[0].circuitBreakerReason).toBeTruthy();
		expect(analyzeBashCommand("rm -rf ~")[0].circuitBreakerReason).toBeTruthy();
		expect(analyzeBashCommand("rm -rf ./build")[0].circuitBreakerReason).toBeFalsy();
	});
	it("extracts simple read file args", () => {
		expect(analyzeBashCommand("cat .env")[0].readPaths).toContain(".env");
	});
});

// Additional coverage for the two helpers the brief exports explicitly "for reuse/tests"
// (not exercised by the behavioral cases above, which only assert through analyzeBashCommand).
describe("READONLY_COMMANDS / isReadonlyGitSubcommand", () => {
	it("READONLY_COMMANDS contains the fixed built-in read-only set", () => {
		for (const cmd of ["ls", "cat", "echo", "pwd", "head", "tail", "grep", "wc", "which", "diff", "stat", "du"]) {
			expect(READONLY_COMMANDS.has(cmd)).toBe(true);
		}
		expect(READONLY_COMMANDS.has("rm")).toBe(false);
		expect(READONLY_COMMANDS.has("find")).toBe(false);
	});
	it("isReadonlyGitSubcommand recognizes status/diff/log/show, rejects mutating subcommands", () => {
		expect(isReadonlyGitSubcommand(["status"])).toBe(true);
		expect(isReadonlyGitSubcommand(["diff", "--stat"])).toBe(true);
		expect(isReadonlyGitSubcommand(["log"])).toBe(true);
		expect(isReadonlyGitSubcommand(["show", "HEAD"])).toBe(true);
		expect(isReadonlyGitSubcommand(["push"])).toBe(false);
		expect(isReadonlyGitSubcommand([])).toBe(false);
	});
});
