import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendProjectLocalRules, loadProjectLocalRules, mergeRules } from "../../src/core/permissions/rule-store.ts";
import type { Rule } from "../../src/core/permissions/types.ts";

const rule = (list: Rule["list"], tool: string, specifier: string | undefined, scope: Rule["scope"]): Rule => ({
	raw: specifier === undefined ? `${tool}` : `${tool}(${specifier})`,
	tool,
	...(specifier !== undefined ? { specifier } : {}),
	list,
	scope,
});

describe("rule-store — project-local persistence", () => {
	let tempDir: string;
	let agentDir: string;
	let dirA: string;
	let dirB: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `rulestore-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		dirA = join(tempDir, "projA");
		dirB = join(tempDir, "projB");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(dirA, { recursive: true });
		mkdirSync(dirB, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("append then load round-trips a rule under its canonical dir", () => {
		const r = rule("allow", "edit", "/foo.ts", "project-local");
		appendProjectLocalRules(agentDir, dirA, [r]);
		const loaded = loadProjectLocalRules(agentDir, dirA);
		expect(loaded).toHaveLength(1);
		expect(loaded[0]).toMatchObject({ raw: "edit(/foo.ts)", tool: "edit", specifier: "/foo.ts", list: "allow" });
	});

	it("keeps rules from different dirs isolated", () => {
		appendProjectLocalRules(agentDir, dirA, [rule("allow", "edit", "/a.ts", "project-local")]);
		appendProjectLocalRules(agentDir, dirB, [rule("allow", "edit", "/b.ts", "project-local")]);
		expect(loadProjectLocalRules(agentDir, dirA).map((x) => x.raw)).toEqual(["edit(/a.ts)"]);
		expect(loadProjectLocalRules(agentDir, dirB).map((x) => x.raw)).toEqual(["edit(/b.ts)"]);
	});

	it("dedups identical rules on append (by raw + list)", () => {
		const r = rule("allow", "bash", "git push *", "project-local");
		appendProjectLocalRules(agentDir, dirA, [r]);
		appendProjectLocalRules(agentDir, dirA, [r]);
		expect(loadProjectLocalRules(agentDir, dirA)).toHaveLength(1);
	});

	it("returns [] for an absent permissions file (no throw)", () => {
		expect(loadProjectLocalRules(agentDir, dirA)).toEqual([]);
	});

	it("returns [] for corrupt JSON (no throw)", () => {
		writeFileSync(join(agentDir, "permissions.json"), "{ not json ", "utf8");
		expect(() => loadProjectLocalRules(agentDir, dirA)).not.toThrow();
		expect(loadProjectLocalRules(agentDir, dirA)).toEqual([]);
	});

	it("throws when the target file cannot be written", () => {
		// Make permissions.json a directory so writeFileSync fails.
		mkdirSync(join(agentDir, "permissions.json"), { recursive: true });
		expect(() =>
			appendProjectLocalRules(agentDir, dirA, [rule("allow", "edit", "/x.ts", "project-local")]),
		).toThrow();
	});

	it("persists a nested map keyed by canonical dir", () => {
		appendProjectLocalRules(agentDir, dirA, [rule("allow", "edit", "/foo.ts", "project-local")]);
		const raw = JSON.parse(readFileSync(join(agentDir, "permissions.json"), "utf8"));
		expect(Object.keys(raw)).toEqual([dirA]);
		expect(raw[dirA][0].raw).toBe("edit(/foo.ts)");
	});
});

describe("mergeRules — layering + dedup", () => {
	it("concatenates layers in priority order session -> cli -> projectLocal -> user", () => {
		const merged = mergeRules({
			session: [rule("allow", "bash", "s *", "session")],
			cli: [rule("allow", "bash", "c *", "cli")],
			projectLocal: [rule("allow", "bash", "p *", "project-local")],
			user: [rule("allow", "bash", "u *", "user")],
		});
		expect(merged.map((r) => r.specifier)).toEqual(["s *", "c *", "p *", "u *"]);
	});

	it("dedups identical rules across layers, keeping the highest-priority copy", () => {
		const merged = mergeRules({
			session: [rule("allow", "bash", "git push *", "session")],
			user: [rule("allow", "bash", "git push *", "user")],
		});
		expect(merged).toHaveLength(1);
		expect(merged[0].scope).toBe("session");
	});

	it("keeps a deny from any layer alongside a same-target allow (different lists survive)", () => {
		const merged = mergeRules({
			session: [rule("allow", "bash", "rm *", "session")],
			user: [rule("deny", "bash", "rm *", "user")],
		});
		expect(merged).toHaveLength(2);
		expect(merged.some((r) => r.list === "deny")).toBe(true);
		expect(merged.some((r) => r.list === "allow")).toBe(true);
	});

	it("treats missing layers as empty", () => {
		expect(mergeRules({})).toEqual([]);
	});
});
