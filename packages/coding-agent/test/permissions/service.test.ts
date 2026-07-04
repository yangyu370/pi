import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PermissionService, type PermissionServiceConfig } from "../../src/core/permissions/service.ts";
import { FakeApprovalProvider } from "./fake-approval-provider.ts";

describe("PermissionService", () => {
	let tempDir: string;
	let agentDir: string;
	let cwd: string;
	let canonical: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `perm-svc-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		cwd = join(tempDir, "project");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(cwd, { recursive: true });
		canonical = realpathSync(cwd);
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	const make = (over: Partial<PermissionServiceConfig> = {}): PermissionService =>
		new PermissionService({
			agentDir,
			cwd,
			enabled: true,
			isTrusted: () => false,
			...over,
		});

	const permissionsFile = () => join(agentDir, "permissions.json");

	describe("mode", () => {
		it("defaults to `default` when untrusted", () => {
			expect(make({ isTrusted: () => false }).mode).toBe("default");
		});

		it("defaults to `acceptEdits` when trusted", () => {
			expect(make({ isTrusted: () => true }).mode).toBe("acceptEdits");
		});

		it("honors a modeOverride and setMode", () => {
			const svc = make({ isTrusted: () => true, modeOverride: "plan" });
			expect(svc.mode).toBe("plan");
			svc.setMode("bypass");
			expect(svc.mode).toBe("bypass");
		});
	});

	describe("buildSnapshot", () => {
		it("derives capability + command resource for bash", () => {
			const snap = make().buildSnapshot("bash", { command: "ls -la" });
			expect(snap.capability).toBe("exec");
			expect(snap.resource.kind).toBe("command");
			expect(snap.mode).toBe("default");
		});

		it("derives read capability + paths resource for read", () => {
			const snap = make().buildSnapshot("read", { path: "x.ts" });
			expect(snap.capability).toBe("read");
			expect(snap.resource).toEqual({ kind: "paths", paths: ["x.ts"] });
		});

		it("reflects trust in mode + trusted flag", () => {
			const snap = make({ isTrusted: () => true }).buildSnapshot("edit", { path: "x.ts", edits: [] });
			expect(snap.capability).toBe("mutate");
			expect(snap.mode).toBe("acceptEdits");
			expect(snap.trusted).toBe(true);
		});
	});

	describe("evaluate", () => {
		it("allows a read in default mode without asking (undefined)", async () => {
			const svc = make();
			expect(await svc.evaluate({ name: "read" }, { path: "x.ts" })).toBeUndefined();
		});

		it("persists a re-anchored project-local rule on always-allow", async () => {
			const provider = new FakeApprovalProvider([
				(req) => ({ type: "always-allow", rules: req.alwaysAllowChoices[0].rules }),
			]);
			const resolutions: unknown[] = [];
			const svc = make({
				approvalProvider: provider,
				approvalObserver: (resolution) => resolutions.push(resolution),
			});
			const result = await svc.evaluate(
				{ name: "edit" },
				{ path: "foo.ts", edits: [{ oldText: "a", newText: "b" }] },
			);
			expect(result).toBeUndefined();

			const stored = JSON.parse(readFileSync(permissionsFile(), "utf8"));
			expect(Object.keys(stored)).toEqual([canonical]);
			expect(stored[canonical][0]).toMatchObject({
				raw: "edit(/foo.ts)",
				tool: "edit",
				specifier: "/foo.ts",
				list: "allow",
				scope: "project-local",
			});
			// The suggested specifier was re-anchored to project-root-relative, not a bare abs path.
			expect(provider.requests[0].alwaysAllowChoices[0].rules[0].specifier).toBe("/foo.ts");
			expect(resolutions).toHaveLength(1);
			expect(resolutions[0]).toMatchObject({ outcome: { type: "always-allow" }, persistResult: "persisted" });
		});

		it("blocks when the provider denies", async () => {
			const provider = new FakeApprovalProvider([{ type: "deny", reason: "nope" }]);
			const svc = make({ approvalProvider: provider });
			const result = await svc.evaluate({ name: "edit" }, { path: "foo.ts", edits: [] });
			expect(result).toEqual({ block: true, reason: "nope" });
			expect(existsSync(permissionsFile())).toBe(false);
		});

		it("does not persist on allow-once", async () => {
			const provider = new FakeApprovalProvider([{ type: "allow-once" }]);
			const svc = make({ approvalProvider: provider });
			expect(await svc.evaluate({ name: "edit" }, { path: "foo.ts", edits: [] })).toBeUndefined();
			expect(existsSync(permissionsFile())).toBe(false);
		});

		it("headless: default-mode edit asks, then bypass allows (undefined)", async () => {
			const svc = make({ nonInteractiveDefault: "bypass" });
			expect(await svc.evaluate({ name: "edit" }, { path: "foo.ts", edits: [] })).toBeUndefined();
		});

		it("headless: dontAsk default blocks an ask", async () => {
			const svc = make({ nonInteractiveDefault: "dontAsk" });
			const result = await svc.evaluate({ name: "edit" }, { path: "foo.ts", edits: [] });
			expect(result?.block).toBe(true);
		});

		it("headless: circuit-breaker blocks even under bypass", async () => {
			const svc = make({ nonInteractiveDefault: "bypass" });
			const result = await svc.evaluate({ name: "bash" }, { command: "rm -rf ~" });
			expect(result?.block).toBe(true);
			expect(result?.reason).toMatch(/home directory/i);
		});
	});

	describe("buildApprovalRequest", () => {
		it("builds a real line-numbered diff preview for edit approvals", () => {
			writeFileSync(join(cwd, "foo.ts"), "one\nold value\nthree\n", "utf8");
			const svc = make();
			const args = { path: "foo.ts", edits: [{ oldText: "old value", newText: "new value" }] };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("edit", args), args, []);

			expect(req.display.diffPreview).toContain("-2 old value");
			expect(req.display.diffPreview).toContain("+2 new value");
			expect(req.display.diffPreview).toContain(" 1 one");
			expect(req.display.diffPreview).toContain(" 3 three");
		});

		it("marks unmatched edit previews instead of showing a misleading replacement", () => {
			writeFileSync(join(cwd, "foo.ts"), "one\nold value\nthree\n", "utf8");
			const svc = make();
			const args = { path: "foo.ts", edits: [{ oldText: "missing value", newText: "new value" }] };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("edit", args), args, []);

			expect(req.display.diffPreview).toContain("edit 1: no match found");
			expect(req.display.diffPreview).not.toContain("- missing value\n+ new value");
		});

		it("builds a real diff preview for write approvals over existing files", () => {
			writeFileSync(join(cwd, "foo.ts"), "old\n", "utf8");
			const svc = make();
			const args = { path: "foo.ts", content: "new\n" };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("write", args), args, []);

			expect(req.display.diffPreview).toContain("-1 old");
			expect(req.display.diffPreview).toContain("+1 new");
		});

		it("warns when a write approval overwrites an existing file too large to diff", () => {
			writeFileSync(join(cwd, "large.txt"), "x".repeat(1024 * 1024 + 1), "utf8");
			const svc = make();
			const args = { path: "large.txt", content: "replacement\n" };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("write", args), args, []);

			expect(req.display.diffPreview).toContain("overwrites existing 1048577-byte file");
			expect(req.display.diffPreview).toContain("current content too large to diff");
			expect(req.display.diffPreview).toContain("+1 replacement");
			expect(req.display.diffTruncated).toBe(true);
		});

		it("keeps full write previews for the UI to expand", () => {
			const svc = make();
			const content = Array.from({ length: 25 }, (_, index) => `line ${index + 1}`).join("\n");
			const args = { path: "new.ts", content };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("write", args), args, []);

			expect(req.display.diffPreview).toContain("+25 line 25");
			expect(req.display.diffTruncated).toBeUndefined();
		});

		it("omits duplicate command detail when the title already shows the whole command", () => {
			const svc = make();
			const args = { command: "ls -la" };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("bash", args), args, []);

			expect(req.display.title).toBe("Run: ls -la");
			expect(req.display.detail).toBe("");
		});

		it("shows formatted args for resource-less extension tools", () => {
			const svc = make();
			const args = { channel: "#general", text: "deploy?" };
			const req = svc.buildApprovalRequest(svc.buildSnapshot("slack_send", args), args, [
				{ tool: "slack_send", list: "allow" },
			]);

			expect(req.display.detail).toContain('"channel": "#general"');
			expect(req.display.detail).toContain('"text": "deploy?"');
			expect(req.alwaysAllowChoices[0].label).toBe("Always allow `slack_send` (all inputs)");
		});

		it("offers exact + widened choices for an edit, capped at 3", () => {
			const svc = make();
			const snap = svc.buildSnapshot("edit", { path: "src/foo.ts", edits: [{ oldText: "a", newText: "b" }] });
			const req = svc.buildApprovalRequest(snap, { path: "src/foo.ts", edits: [{ oldText: "a", newText: "b" }] }, [
				{ tool: "edit", specifier: join(cwd, "src/foo.ts"), list: "allow" },
			]);
			expect(req.alwaysAllowChoices.length).toBeGreaterThanOrEqual(1);
			expect(req.alwaysAllowChoices.length).toBeLessThanOrEqual(3);
			expect(req.alwaysAllowChoices[0].rules[0].specifier).toBe("/src/foo.ts");
			// A widen-to-directory choice exists for a mutate capability.
			expect(req.alwaysAllowChoices.some((c) => c.rules[0].specifier === "/src/**")).toBe(true);
		});

		it("does not offer a whole-workspace (/**) widen for a root-level file", () => {
			const svc = make();
			const snap = svc.buildSnapshot("write", { path: "foo.ts", content: "new\n" });
			const req = svc.buildApprovalRequest(snap, { path: "foo.ts", content: "new\n" }, [
				{ tool: "write", specifier: join(cwd, "foo.ts"), list: "allow" },
			]);

			// Editing a root-level file would widen to `/**` (the entire workspace),
			// which is far broader than the resource — that choice must not be offered.
			expect(req.alwaysAllowChoices.some((choice) => choice.rules[0].specifier === "/**")).toBe(false);
			// The exact single-file allow is still there.
			expect(req.alwaysAllowChoices.some((choice) => choice.rules[0].specifier === "/foo.ts")).toBe(true);
		});

		it("passes bash specifiers through unchanged and flags circuit-breaker danger", () => {
			const svc = make();
			const snap = svc.buildSnapshot("bash", { command: "rm -rf ~" });
			const req = svc.buildApprovalRequest(snap, { command: "rm -rf ~" }, [
				{ tool: "bash", specifier: "rm -rf ~", list: "allow" },
			]);
			expect(req.display.danger?.level).toBe("circuit-breaker");
			expect(req.alwaysAllowChoices[0].rules[0].specifier).toBe("rm -rf ~");
		});

		it("titles a resource-less extension/custom tool as `Run <tool>`, not an empty edit", () => {
			const svc = make();
			const snap = svc.buildSnapshot("slack_send", { channel: "#general" });
			expect(snap.resource.kind).toBe("none");
			const req = svc.buildApprovalRequest(snap, { channel: "#general" }, []);
			expect(req.display.title).toBe("Run slack_send");
		});
	});

	describe("persistRules", () => {
		it("does not throw on write failure and keeps rules in the session layer", async () => {
			// Make permissions.json a directory so the append write fails.
			mkdirSync(permissionsFile(), { recursive: true });
			const logged: string[] = [];
			const svc = make({ logger: (m) => logged.push(m) });
			await expect(
				svc.persistRules([
					{ raw: "edit(/x.ts)", tool: "edit", specifier: "/x.ts", list: "allow", scope: "project-local" },
				]),
			).resolves.toBe("session-only");
			expect(logged.length).toBeGreaterThan(0);
			// The kept-in-session rule now participates in snapshots, labelled as a session rule.
			const snap = svc.buildSnapshot("edit", { path: "x.ts", edits: [] });
			const kept = snap.rules.find((r) => r.raw === "edit(/x.ts)");
			expect(kept).toBeDefined();
			expect(kept?.scope).toBe("session");
		});

		it("returns persisted when project-local rules are saved", async () => {
			const svc = make();
			await expect(
				svc.persistRules([
					{ raw: "edit(/x.ts)", tool: "edit", specifier: "/x.ts", list: "allow", scope: "project-local" },
				]),
			).resolves.toBe("persisted");
		});
	});

	describe("rules lifecycle", () => {
		it("lists effective rules and removes project-local rules immediately", async () => {
			const svc = make({
				cliRules: [{ raw: "bash(npm run *)", tool: "bash", specifier: "npm run *", list: "allow", scope: "cli" }],
			});
			const projectRule = {
				raw: "bash(git push *)",
				tool: "bash",
				specifier: "git push *",
				list: "allow",
				scope: "project-local",
			} as const;
			await svc.persistRules([projectRule]);

			expect(svc.listEffectiveRules().map((rule) => rule.raw)).toEqual(["bash(npm run *)", "bash(git push *)"]);

			svc.removeProjectLocalRules([projectRule]);

			expect(svc.listEffectiveRules().map((rule) => rule.raw)).toEqual(["bash(npm run *)"]);
		});
	});
});
