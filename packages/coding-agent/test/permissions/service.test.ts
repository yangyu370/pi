import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
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
			const svc = make({ approvalProvider: provider });
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
			).resolves.toBeUndefined();
			expect(logged.length).toBeGreaterThan(0);
			// The kept-in-session rule now participates in snapshots.
			const snap = svc.buildSnapshot("edit", { path: "x.ts", edits: [] });
			expect(snap.rules.some((r) => r.raw === "edit(/x.ts)")).toBe(true);
		});
	});
});
