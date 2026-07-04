import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PermissionService, type PermissionServiceConfig } from "../../src/core/permissions/service.ts";
import type { Rule } from "../../src/core/permissions/types.ts";
import { FakeApprovalProvider } from "./fake-approval-provider.ts";

describe("permission layer e2e", () => {
	let tempDir: string;
	let agentDir: string;
	let cwd: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "perm-e2e-"));
		agentDir = join(tempDir, "agent");
		cwd = join(tempDir, "project");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(cwd, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	const make = (over: Partial<PermissionServiceConfig> = {}): PermissionService =>
		new PermissionService({ agentDir, cwd, enabled: true, isTrusted: () => true, ...over });

	it("plan mode allows reads but blocks edits, writes, and non-readonly bash", async () => {
		const svc = make({ modeOverride: "plan" });
		expect(
			await svc.evaluate({ name: "edit" }, { path: "src/x.ts", edits: [{ oldText: "a", newText: "b" }] }),
		).toMatchObject({ block: true });
		expect(await svc.evaluate({ name: "write" }, { path: "src/x.ts", content: "hi" })).toMatchObject({ block: true });
		expect(await svc.evaluate({ name: "bash" }, { command: "npm install" })).toMatchObject({ block: true });
		expect(await svc.evaluate({ name: "read" }, { path: "src/x.ts" })).toBeUndefined();
		expect(await svc.evaluate({ name: "bash" }, { command: "git status" })).toBeUndefined();
	});

	it("a deny read(./.env) rule blocks a direct read of .env", async () => {
		const rules: Rule[] = [{ raw: "read(./.env)", tool: "read", specifier: "./.env", list: "deny", scope: "user" }];
		const svc = make({ userRules: rules });
		expect(await svc.evaluate({ name: "read" }, { path: ".env" })).toMatchObject({ block: true });
	});

	it("a deny read(.env) rule also binds a bash command that reads .env", async () => {
		const rules: Rule[] = [{ raw: "read(.env)", tool: "read", specifier: ".env", list: "deny", scope: "user" }];
		const svc = make({ userRules: rules });
		expect(await svc.evaluate({ name: "bash" }, { command: "cat .env" })).toMatchObject({ block: true });
	});

	it("allow bash(git commit *) permits matching commands while git push still asks", async () => {
		const rules: Rule[] = [
			{ raw: "bash(git commit *)", tool: "bash", specifier: "git commit *", list: "allow", scope: "user" },
		];

		const allowMatch = make({ modeOverride: "default", userRules: rules });
		expect(await allowMatch.evaluate({ name: "bash" }, { command: "git commit -m x" })).toBeUndefined();

		const denied = make({
			modeOverride: "default",
			userRules: rules,
			approvalProvider: new FakeApprovalProvider([{ type: "deny" }]),
		});
		expect(await denied.evaluate({ name: "bash" }, { command: "git push" })).toMatchObject({ block: true });

		const alwaysAllow = make({
			modeOverride: "default",
			userRules: rules,
			approvalProvider: new FakeApprovalProvider([
				(req) => ({ type: "always-allow", rules: req.alwaysAllowChoices[0].rules }),
			]),
		});
		expect(await alwaysAllow.evaluate({ name: "bash" }, { command: "git push" })).toBeUndefined();
	});

	it("headless bypass still trips the circuit breaker but allows benign commands", async () => {
		const svc = make({ nonInteractiveDefault: "bypass" });
		const blocked = await svc.evaluate({ name: "bash" }, { command: "rm -rf ~" });
		expect(blocked?.block).toBe(true);
		expect(blocked?.reason).toMatch(/home directory/i);
		expect(await svc.evaluate({ name: "bash" }, { command: "ls" })).toBeUndefined();
	});
});
