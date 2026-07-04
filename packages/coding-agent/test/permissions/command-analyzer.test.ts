import { describe, expect, it } from "vitest";
import {
	analyzeBashCommand,
	isReadonlyGitSubcommand,
	READONLY_COMMANDS,
} from "../../src/core/permissions/command-analyzer.ts";

const BRACED_HOME = "$" + "{HOME}";

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
		expect(analyzeBashCommand("rm -rf ~/.ssh")[0].circuitBreakerReason).toBeTruthy();
		expect(analyzeBashCommand("rm -rf $HOME/.ssh")[0].circuitBreakerReason).toBeTruthy();
		expect(analyzeBashCommand(`rm -rf ${BRACED_HOME}`)[0].circuitBreakerReason).toBeTruthy();
		expect(analyzeBashCommand(`rm -rf ${BRACED_HOME}/.ssh`)[0].circuitBreakerReason).toBeTruthy();
		expect(analyzeBashCommand("rm -rf //etc")[0].circuitBreakerReason).toBeTruthy();
		for (const path of ["/var", "/boot", "/dev", "/root"]) {
			expect(analyzeBashCommand(`rm -rf ${path}`)[0].circuitBreakerReason).toBeTruthy();
		}
		expect(analyzeBashCommand("rm -rf ./build")[0].circuitBreakerReason).toBeFalsy();
	});
	it("extracts simple read file args", () => {
		expect(analyzeBashCommand("cat .env")[0].readPaths).toContain(".env");
	});
	it("normalizedCommand collapses redundant whitespace", () => {
		expect(analyzeBashCommand("ls   -la    /tmp")[0].normalizedCommand).toBe("ls -la /tmp");
	});
	it("extracts mutate targets for mv and cp", () => {
		expect(analyzeBashCommand("mv a b")[0].mutatePaths).toEqual(["a", "b"]);
		expect(analyzeBashCommand("cp a b")[0].mutatePaths).toEqual(["a", "b"]);
	});
});

describe("analyzeBashCommand — quoting (regression: double quotes do not suppress command substitution)", () => {
	it("double-quoted $() / backtick command substitution is high-risk, not read-only", () => {
		const sub = analyzeBashCommand('echo "$(rm -rf /)"');
		expect(sub).toHaveLength(1);
		expect(sub[0].highRiskReason).toBeTruthy();
		expect(sub[0].readonly).toBe(false);

		const backtick = analyzeBashCommand('echo "`rm -rf /`"');
		expect(backtick).toHaveLength(1);
		expect(backtick[0].highRiskReason).toBeTruthy();
		expect(backtick[0].readonly).toBe(false);
	});
	it("single quotes stay fully literal — no command substitution detected", () => {
		const a = analyzeBashCommand("echo '$(rm -rf /)'");
		expect(a).toHaveLength(1);
		expect(a[0].highRiskReason).toBeFalsy();
		expect(a[0].readonly).toBe(true);
	});
	it("double-quoted && does not split into multiple accesses", () => {
		const a = analyzeBashCommand('echo "a && b"');
		expect(a).toHaveLength(1);
		expect(a[0].command).toBe('echo "a && b"');
	});

	it("escaped quotes do not hide top-level command separators", () => {
		const a = analyzeBashCommand(String.raw`echo \"; rm -rf /etc\"`);
		expect(a).toHaveLength(2);
		expect(a[0].readonly).toBe(true);
		expect(a[1].readonly).toBe(false);
	});
});

describe("analyzeBashCommand — redirection (regression)", () => {
	it("top-level redirection is high-risk and never read-only", () => {
		const r = analyzeBashCommand("echo x > f");
		expect(r).toHaveLength(1);
		expect(r[0].highRiskReason).toBeTruthy();
		expect(r[0].readonly).toBe(false);
		expect(analyzeBashCommand("echo x >> f")[0].highRiskReason).toBeTruthy();
		expect(analyzeBashCommand("ls 2> err")[0].highRiskReason).toBeTruthy();
		expect(analyzeBashCommand("cat < f")[0].highRiskReason).toBeTruthy();
	});
	it("redirect operator and target do not leak into readPaths/mutatePaths", () => {
		const c = analyzeBashCommand("cat a > b");
		expect(c[0].readPaths).toEqual([]);
		expect(c[0].mutatePaths).toEqual([]);
	});
});

describe("analyzeBashCommand — path extraction (regression: flag values / grep pattern must not leak)", () => {
	it("value-consuming flags of head/tail do not leak their values", () => {
		expect(analyzeBashCommand("head -n 5 file.txt")[0].readPaths).toEqual(["file.txt"]);
		expect(analyzeBashCommand("tail -c 100 log.txt")[0].readPaths).toEqual(["log.txt"]);
	});
	it("grep drops its search pattern and -A/-B/-C/-m/-e values", () => {
		expect(analyzeBashCommand("grep -A 3 pat file.txt")[0].readPaths).toEqual(["file.txt"]);
		expect(analyzeBashCommand("grep pat file.txt")[0].readPaths).toEqual(["file.txt"]);
		// -e supplies the pattern, so the first positional is a real file, not the pattern
		expect(analyzeBashCommand("grep -e pat file.txt")[0].readPaths).toEqual(["file.txt"]);
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
