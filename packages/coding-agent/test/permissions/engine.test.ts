import { describe, expect, it } from "vitest";
import { check, suggestBashSpecifier } from "../../src/core/permissions/engine.ts";
import { extractResource, getToolCapability } from "../../src/core/permissions/tool-metadata.ts";
import type { PolicySnapshot, Resource, Rule } from "../../src/core/permissions/types.ts";

function snap(over: Partial<PolicySnapshot> & { tool: string; resource: Resource }): PolicySnapshot {
	return {
		capability: getToolCapability(over.tool),
		mode: "default",
		trusted: false,
		rules: [],
		cwd: "/proj/pkg",
		home: "/Users/a",
		workspaceRoot: "/proj",
		...over,
	};
}

const bash = (command: string) => extractResource("bash", { command });
const rule = (list: Rule["list"], tool: string, specifier?: string): Rule => ({
	raw: specifier === undefined ? `${list} ${tool}` : `${list} ${tool}(${specifier})`,
	tool,
	specifier,
	list,
	scope: "user",
});

describe("engine.check — pipeline order (spec §10)", () => {
	it("1. deny rule beats everything, even bypass", () => {
		const rules = [rule("deny", "bash", "git push *"), rule("allow", "bash", "git push *")];
		expect(
			check(snap({ tool: "bash", resource: bash("git push origin main"), mode: "bypass", rules })).decision,
		).toBe("deny");
	});

	it("1. bare `deny bash` (no specifier) denies any bash", () => {
		const rules = [rule("deny", "bash")];
		expect(check(snap({ tool: "bash", resource: bash("ls -la"), mode: "bypass", rules })).decision).toBe("deny");
	});

	it("1. bash readPaths hitting a read(...) deny → deny (relative path resolved to cwd)", () => {
		const rules = [rule("deny", "read", ".env")];
		expect(check(snap({ tool: "bash", resource: bash("cat .env"), mode: "bypass", rules })).decision).toBe("deny");
	});

	it("2. circuit breaker asks even under bypass and beats an explicit allow", () => {
		const rules = [rule("allow", "bash", "rm *")];
		const res = check(snap({ tool: "bash", resource: bash("rm -rf ~"), mode: "bypass", rules }));
		expect(res.decision).toBe("ask");
		expect(res.reason).toMatch(/home directory/i);
	});

	it("3. ask rule beats allow rule (broad ask masks narrow allow)", () => {
		const rules = [rule("ask", "bash", "git *"), rule("allow", "bash", "git push *")];
		expect(check(snap({ tool: "bash", resource: bash("git push"), mode: "bypass", rules })).decision).toBe("ask");
	});

	it("3. bash readPaths hitting a read(...) ask → ask (not deny)", () => {
		const rules = [rule("ask", "read", "secrets/**")];
		expect(check(snap({ tool: "bash", resource: bash("cat secrets/key.pem"), mode: "bypass", rules })).decision).toBe(
			"ask",
		);
	});

	it("4. allow rule allows a mutate/exec that would otherwise ask", () => {
		const rules = [rule("allow", "bash", "npm run *")];
		expect(check(snap({ tool: "bash", resource: bash("npm run build"), mode: "default", rules })).decision).toBe(
			"allow",
		);
	});

	it("4. bare `allow bash` (no specifier) allows", () => {
		const rules = [rule("allow", "bash")];
		expect(check(snap({ tool: "bash", resource: bash("git push"), mode: "default", rules })).decision).toBe("allow");
	});

	it("4. high-risk: a prefix/wildcard allow does NOT pass → ask", () => {
		const rules = [rule("allow", "bash", "cat *")];
		expect(check(snap({ tool: "bash", resource: bash("cat x | grep y"), mode: "default", rules })).decision).toBe(
			"ask",
		);
	});

	it("4. high-risk: an exact allow (no wildcard) passes → allow", () => {
		const rules = [rule("allow", "bash", "cat x | grep y")];
		expect(check(snap({ tool: "bash", resource: bash("cat x | grep y"), mode: "default", rules })).decision).toBe(
			"allow",
		);
	});
});

describe("engine.check — read-capable tools (step 5a)", () => {
	it("read/ls/grep/find allow by default, in any mode", () => {
		for (const tool of ["read", "ls", "grep", "find"]) {
			const resource = extractResource(tool, { path: "/proj/x.ts", pattern: "y" });
			expect(check(snap({ tool, resource, mode: "default" })).decision).toBe("allow");
			expect(check(snap({ tool, resource, mode: "dontAsk" })).decision).toBe("allow");
			expect(check(snap({ tool, resource, mode: "plan" })).decision).toBe("allow");
		}
	});

	it("a read(...) deny still overrides read-tool auto-allow", () => {
		const rules = [rule("deny", "read", ".env")];
		expect(check(snap({ tool: "read", resource: extractResource("read", { path: ".env" }), rules })).decision).toBe(
			"deny",
		);
	});

	it("a read(...) ask still overrides read-tool auto-allow", () => {
		const rules = [rule("ask", "read", ".env")];
		expect(check(snap({ tool: "read", resource: extractResource("read", { path: ".env" }), rules })).decision).toBe(
			"ask",
		);
	});
});

describe("engine.check — readonly bash (step 5b)", () => {
	it("built-in read-only bash is allowed in every mode", () => {
		for (const mode of ["default", "dontAsk", "plan", "acceptEdits"] as const) {
			expect(check(snap({ tool: "bash", resource: bash("git status"), mode })).decision).toBe("allow");
			expect(check(snap({ tool: "bash", resource: bash("ls -la"), mode })).decision).toBe("allow");
		}
	});
});

describe("engine.check — mode defaults (step 6)", () => {
	it("plan blocks mutate and exec", () => {
		expect(
			check(snap({ tool: "edit", resource: extractResource("edit", { path: "/proj/x.ts" }), mode: "plan" }))
				.decision,
		).toBe("deny");
		expect(check(snap({ tool: "bash", resource: bash("git push"), mode: "plan" })).decision).toBe("deny");
	});

	it("acceptEdits: in-root mutate allowed, out-of-root asks, exec asks", () => {
		expect(
			check(
				snap({ tool: "edit", resource: extractResource("edit", { path: "/proj/src/x.ts" }), mode: "acceptEdits" }),
			).decision,
		).toBe("allow");
		expect(
			check(snap({ tool: "edit", resource: extractResource("edit", { path: "/etc/passwd" }), mode: "acceptEdits" }))
				.decision,
		).toBe("ask");
		expect(check(snap({ tool: "bash", resource: bash("npm run build"), mode: "acceptEdits" })).decision).toBe("ask");
	});

	it("acceptEdits: relative in-cwd path resolves under workspaceRoot → allow", () => {
		expect(
			check(snap({ tool: "write", resource: extractResource("write", { path: "out.txt" }), mode: "acceptEdits" }))
				.decision,
		).toBe("allow");
	});

	it("default: mutate asks, exec asks", () => {
		expect(
			check(snap({ tool: "edit", resource: extractResource("edit", { path: "/proj/x.ts" }), mode: "default" }))
				.decision,
		).toBe("ask");
		expect(check(snap({ tool: "bash", resource: bash("npm run build"), mode: "default" })).decision).toBe("ask");
	});

	it("dontAsk denies mutate/exec but readonly bash still allowed", () => {
		expect(
			check(snap({ tool: "edit", resource: extractResource("edit", { path: "/proj/x.ts" }), mode: "dontAsk" }))
				.decision,
		).toBe("deny");
		expect(check(snap({ tool: "bash", resource: bash("npm run build"), mode: "dontAsk" })).decision).toBe("deny");
		expect(check(snap({ tool: "bash", resource: bash("ls -la"), mode: "dontAsk" })).decision).toBe("allow");
	});

	it("bypass allows ordinary mutate/exec", () => {
		expect(
			check(snap({ tool: "edit", resource: extractResource("edit", { path: "/etc/passwd" }), mode: "bypass" }))
				.decision,
		).toBe("allow");
		expect(check(snap({ tool: "bash", resource: bash("npm run build"), mode: "bypass" })).decision).toBe("allow");
	});
});

describe("engine.check — composite commands (spec §10 combine)", () => {
	it("any-ask wins: git commit allowed but git push still asks", () => {
		const rules = [rule("allow", "bash", "git commit *")];
		expect(
			check(snap({ tool: "bash", resource: bash("git commit -m x && git push"), mode: "default", rules })).decision,
		).toBe("ask");
	});

	it("any-deny wins over allow/ask siblings", () => {
		const rules = [rule("deny", "bash", "git push *"), rule("allow", "bash", "git commit *")];
		expect(
			check(snap({ tool: "bash", resource: bash("git commit -m x && git push origin main"), mode: "bypass", rules }))
				.decision,
		).toBe("deny");
	});

	it("all-allow → allow (readonly subcommands)", () => {
		expect(
			check(snap({ tool: "bash", resource: bash("git status && ls -la && pwd"), mode: "default" })).decision,
		).toBe("allow");
	});
});

describe("engine.check — custom/extension tools (none resource)", () => {
	it("default asks; matching allow/deny tool rules win; mode defaults apply", () => {
		const resource = extractResource("db_query", { sql: "select 1" });
		expect(check(snap({ tool: "db_query", resource, mode: "default" })).decision).toBe("ask");
		expect(check(snap({ tool: "db_query", resource, mode: "bypass" })).decision).toBe("allow");
		expect(check(snap({ tool: "db_query", resource, mode: "dontAsk" })).decision).toBe("deny");
		expect(
			check(snap({ tool: "db_query", resource, mode: "default", rules: [rule("allow", "db_query")] })).decision,
		).toBe("allow");
		expect(
			check(snap({ tool: "db_query", resource, mode: "bypass", rules: [rule("deny", "db_query")] })).decision,
		).toBe("deny");
	});

	it("tool-name glob rules match custom tools", () => {
		const resource = extractResource("db_query", {});
		expect(
			check(snap({ tool: "db_query", resource, mode: "default", rules: [rule("allow", "db_*")] })).decision,
		).toBe("allow");
	});
});

describe("engine.check — suggestedRules on ask", () => {
	it("bash ask suggests a bash allow specifier (first ≤2 tokens + *)", () => {
		const res = check(snap({ tool: "bash", resource: bash("npm run build"), mode: "default" }));
		expect(res.decision).toBe("ask");
		expect(res.suggestedRules).toEqual([{ tool: "bash", specifier: "npm run *", list: "allow" }]);
	});

	it("high-risk bash ask suggests the exact command", () => {
		const res = check(snap({ tool: "bash", resource: bash("cat x | grep y"), mode: "default" }));
		expect(res.decision).toBe("ask");
		expect(res.suggestedRules).toEqual([{ tool: "bash", specifier: "cat x | grep y", list: "allow" }]);
	});

	it("composite ask suggests only the subcommand needing approval", () => {
		const rules = [rule("allow", "bash", "git commit *")];
		const res = check(snap({ tool: "bash", resource: bash("git commit -m x && git push"), mode: "default", rules }));
		expect(res.decision).toBe("ask");
		expect(res.suggestedRules).toEqual([{ tool: "bash", specifier: "git push *", list: "allow" }]);
	});

	it("paths ask suggests the tool + resolved target path", () => {
		const res = check(
			snap({ tool: "edit", resource: extractResource("edit", { path: "/etc/passwd" }), mode: "default" }),
		);
		expect(res.decision).toBe("ask");
		expect(res.suggestedRules).toEqual([{ tool: "edit", specifier: "/etc/passwd", list: "allow" }]);
	});

	it("allow/deny decisions carry no suggestedRules", () => {
		expect(
			check(snap({ tool: "read", resource: extractResource("read", { path: "/proj/x.ts" }) })).suggestedRules,
		).toBe(undefined);
	});
});

describe("suggestBashSpecifier", () => {
	it("high-risk → the exact normalized command", () => {
		const resource = extractResource("bash", { command: "cat x | grep y" });
		if (resource.kind !== "command") throw new Error("expected command");
		const access = resource.accesses[0];
		expect(access.highRiskReason).toBeTruthy();
		expect(suggestBashSpecifier(access)).toBe(access.normalizedCommand);
	});

	it("ordinary → first ≤2 tokens + ' *'", () => {
		const res = extractResource("bash", { command: "git push origin main" });
		if (res.kind !== "command") throw new Error("expected command");
		expect(suggestBashSpecifier(res.accesses[0])).toBe("git push *");
	});
});

describe("engine.check — totality", () => {
	it("never throws on odd resources/snapshots", () => {
		expect(() => check(snap({ tool: "bash", resource: { kind: "none" }, mode: "default" }))).not.toThrow();
		expect(() =>
			check(snap({ tool: "read", resource: { kind: "paths", paths: [] }, mode: "acceptEdits" })),
		).not.toThrow();
		expect(() =>
			check(snap({ tool: "weird", resource: { kind: "paths", paths: [""] }, mode: "default" })),
		).not.toThrow();
	});
});
