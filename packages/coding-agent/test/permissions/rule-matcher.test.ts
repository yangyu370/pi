import { describe, expect, it } from "vitest";
import {
	matchBashCommand,
	matchPath,
	matchToolName,
	parseRule,
	specifierHasWildcard,
} from "../../src/core/permissions/rule-matcher.ts";

describe("matchBashCommand", () => {
	it("* matches anywhere including spaces", () => {
		expect(matchBashCommand("git *", "git log --oneline")).toBe(true);
		expect(matchBashCommand("npm run *", "npm run build")).toBe(true);
	});
	it("space-before-* enforces a word boundary", () => {
		expect(matchBashCommand("ls *", "ls -la")).toBe(true);
		expect(matchBashCommand("ls *", "lsof")).toBe(false);
	});
	it("no space before * matches the raw prefix", () => {
		expect(matchBashCommand("ls*", "lsof")).toBe(true);
		expect(matchBashCommand("ls*", "ls -la")).toBe(true);
	});
	it("trailing :* is equivalent to a trailing space-star", () => {
		expect(matchBashCommand("git push:*", "git push origin main")).toBe(true);
		expect(matchBashCommand("git push:*", "git pushx")).toBe(false); // requires the boundary
	});
	it("a colon elsewhere is literal", () => {
		expect(matchBashCommand("foo:bar", "foo:bar")).toBe(true);
		expect(matchBashCommand("foo:bar", "foo bar")).toBe(false);
	});
	it("exact specifier (no star) requires full match", () => {
		expect(matchBashCommand("git status", "git status")).toBe(true);
		expect(matchBashCommand("git status", "git status -s")).toBe(false);
	});
});

describe("matchPath (gitignore 4 anchors)", () => {
	const anchors = { cwd: "/proj/pkg", home: "/Users/a", workspaceRoot: "/proj" };
	it("//abs is filesystem-absolute", () => {
		expect(matchPath("//Users/a/secrets/**", "/Users/a/secrets/x.txt", anchors)).toBe(true);
	});
	it("~/ is home-relative", () => {
		expect(matchPath("~/.ssh/**", "/Users/a/.ssh/id_rsa", anchors)).toBe(true);
	});
	it("/x is project-root-relative", () => {
		expect(matchPath("/src/**/*.ts", "/proj/src/a/b.ts", anchors)).toBe(true);
	});
	it("bare name matches at any depth", () => {
		expect(matchPath(".env", "/proj/pkg/nested/.env", anchors)).toBe(true);
		expect(matchPath("./.env", "/proj/pkg/.env", anchors)).toBe(true);
	});
	it("* is a single segment, ** crosses directories", () => {
		expect(matchPath("/src/*.ts", "/proj/src/a/b.ts", anchors)).toBe(false);
		expect(matchPath("/src/**", "/proj/src/a/b.ts", anchors)).toBe(true);
	});
});

describe("matchToolName / parseRule / specifierHasWildcard", () => {
	it("matchToolName supports glob", () => {
		expect(matchToolName("*", "bash")).toBe(true);
		expect(matchToolName("db_*", "db_query")).toBe(true);
		expect(matchToolName("db_*", "http_get")).toBe(false);
	});
	it("parseRule splits tool and specifier", () => {
		expect(parseRule("bash(git push *)")).toEqual({ tool: "bash", specifier: "git push *" });
		expect(parseRule("read(./.env)")).toEqual({ tool: "read", specifier: "./.env" });
		expect(parseRule("bash")).toEqual({ tool: "bash", specifier: undefined });
	});
	it("specifierHasWildcard", () => {
		expect(specifierHasWildcard("git push *")).toBe(true);
		expect(specifierHasWildcard("git status")).toBe(false);
	});
});
