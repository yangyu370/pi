import { describe, expect, it } from "vitest";
import { extractResource, getToolCapability } from "../../src/core/permissions/tool-metadata.ts";

describe("getToolCapability", () => {
	it("maps read-ish built-ins to read", () => {
		expect(getToolCapability("read")).toBe("read");
		expect(getToolCapability("ls")).toBe("read");
		expect(getToolCapability("grep")).toBe("read");
		expect(getToolCapability("find")).toBe("read");
	});
	it("maps edit/write to mutate", () => {
		expect(getToolCapability("edit")).toBe("mutate");
		expect(getToolCapability("write")).toBe("mutate");
	});
	it("maps bash to exec", () => {
		expect(getToolCapability("bash")).toBe("exec");
	});
	it("defaults custom/extension/unknown tools to exec", () => {
		expect(getToolCapability("myext")).toBe("exec");
		expect(getToolCapability("db_query")).toBe("exec");
		expect(getToolCapability("")).toBe("exec");
	});
});

describe("extractResource", () => {
	it("bash → command with analyzed accesses", () => {
		const r = extractResource("bash", { command: "git status && git push" });
		expect(r.kind).toBe("command");
		if (r.kind !== "command") throw new Error("expected command");
		expect(r.command).toBe("git status && git push");
		expect(r.accesses.map((a) => a.command)).toEqual(["git status", "git push"]);
	});
	it("read/ls/grep/find → paths (present)", () => {
		expect(extractResource("read", { path: "/proj/a.ts" })).toEqual({ kind: "paths", paths: ["/proj/a.ts"] });
		expect(extractResource("grep", { pattern: "x", path: "/proj/src" })).toEqual({
			kind: "paths",
			paths: ["/proj/src"],
		});
		expect(extractResource("find", { pattern: "*.ts", path: "/proj" })).toEqual({ kind: "paths", paths: ["/proj"] });
	});
	it("read/ls/grep/find → empty paths when path absent", () => {
		expect(extractResource("ls", {})).toEqual({ kind: "paths", paths: [] });
		expect(extractResource("grep", { pattern: "x" })).toEqual({ kind: "paths", paths: [] });
	});
	it("edit/write → paths with the target (empty string if absent)", () => {
		expect(extractResource("edit", { path: "/proj/a.ts" })).toEqual({ kind: "paths", paths: ["/proj/a.ts"] });
		expect(extractResource("write", { path: "/proj/b.ts", content: "x" })).toEqual({
			kind: "paths",
			paths: ["/proj/b.ts"],
		});
		expect(extractResource("edit", {})).toEqual({ kind: "paths", paths: [""] });
	});
	it("unknown tool → none", () => {
		expect(extractResource("myext", { foo: 1 })).toEqual({ kind: "none" });
	});
	it("malformed args never throw — degrade to empty/none", () => {
		expect(() => extractResource("bash", null)).not.toThrow();
		expect(extractResource("bash", null)).toEqual({ kind: "command", command: "", accesses: expect.any(Array) });
		expect(extractResource("read", undefined)).toEqual({ kind: "paths", paths: [] });
		expect(extractResource("read", "not-an-object")).toEqual({ kind: "paths", paths: [] });
		expect(extractResource("edit", 42)).toEqual({ kind: "paths", paths: [""] });
		expect(extractResource("myext", null)).toEqual({ kind: "none" });
	});
});
