import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getModel } from "@earendil-works/pi-ai/compat";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AgentSession } from "../../src/core/agent-session.ts";
import { PermissionService, type PermissionServiceConfig } from "../../src/core/permissions/service.ts";
import type { Rule } from "../../src/core/permissions/types.ts";
import { DefaultResourceLoader } from "../../src/core/resource-loader.ts";
import { createAgentSession } from "../../src/core/sdk.ts";
import { SessionManager } from "../../src/core/session-manager.ts";
import { SettingsManager } from "../../src/core/settings-manager.ts";
import { createTestExtensionsResult, createTestResourceLoader } from "../utilities.ts";
import { FakeApprovalProvider } from "./fake-approval-provider.ts";

type GateResult = { block?: boolean; reason?: string } | undefined;

/** Records forwarded tool calls so a test can assert whether the gate reached the extension runner. */
class RecordingRunner {
	readonly calls: unknown[] = [];
	private readonly handlers: boolean;
	private readonly result: GateResult;
	constructor(handlers: boolean, result: GateResult) {
		this.handlers = handlers;
		this.result = result;
	}
	hasHandlers(_eventType: string): boolean {
		return this.handlers;
	}
	emitToolCall(payload: unknown): Promise<GateResult> {
		this.calls.push(payload);
		return Promise.resolve(this.result);
	}
}

/**
 * Mirror of the `beforeToolCall` closure installed by AgentSession: the permission
 * gate prepended to the existing extension-runner forward. Kept in lockstep with
 * `_installAgentToolHooks` so the fine-grained interaction (shortcircuit on deny,
 * fall-through on allow) can be asserted without a full live session.
 */
function makeGate(permissions: PermissionService | undefined, runner: RecordingRunner) {
	return async ({
		toolCall,
		args,
	}: {
		toolCall: { name: string; id: string };
		args: unknown;
	}): Promise<GateResult> => {
		if (permissions) {
			const outcome = await permissions.evaluate(toolCall, args);
			if (outcome) return outcome;
		}
		if (!runner.hasHandlers("tool_call")) {
			return undefined;
		}
		return runner.emitToolCall({
			type: "tool_call",
			toolName: toolCall.name,
			toolCallId: toolCall.id,
			input: args as Record<string, unknown>,
		});
	};
}

describe("AgentSession permission wiring", () => {
	let tempDir: string;
	let agentDir: string;
	let cwd: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-perm-wiring-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		cwd = join(tempDir, "project");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(cwd, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	const makeService = (over: Partial<PermissionServiceConfig> = {}): PermissionService =>
		new PermissionService({
			agentDir,
			cwd,
			enabled: true,
			isTrusted: () => true,
			nonInteractiveDefault: "bypass",
			...over,
		});

	async function buildSession(settingsManager: SettingsManager): Promise<AgentSession> {
		const resourceLoader = new DefaultResourceLoader({ cwd, agentDir, settingsManager });
		await resourceLoader.reload();
		const { session } = await createAgentSession({
			cwd,
			agentDir,
			model: getModel("anthropic", "claude-sonnet-4-5")!,
			settingsManager,
			sessionManager: SessionManager.inMemory(),
			resourceLoader,
		});
		return session;
	}

	const callGate = (session: AgentSession, name: string, args: unknown): Promise<GateResult> =>
		session.agent.beforeToolCall!({ toolCall: { name, id: "call-1", arguments: args }, args } as any);

	describe("SettingsManager permission getters", () => {
		it("default to enabled with no rules", () => {
			const sm = SettingsManager.inMemory({});
			expect(sm.getPermissionsEnabled()).toBe(true);
			expect(sm.getPermissionRules()).toEqual([]);
		});

		it("reflect configured permission settings", () => {
			const rule: Rule = { raw: "bash(ls)", tool: "bash", specifier: "ls", list: "allow", scope: "user" };
			const sm = SettingsManager.inMemory({ permissions: { enabled: false, rules: [rule] } });
			expect(sm.getPermissionsEnabled()).toBe(false);
			expect(sm.getPermissionRules()).toEqual([rule]);
		});
	});

	describe("installed beforeToolCall gate", () => {
		it("blocks a circuit-breaker command", async () => {
			const session = await buildSession(SettingsManager.inMemory({}, { projectTrusted: false }));
			try {
				expect(await callGate(session, "bash", { command: "rm -rf /" })).toMatchObject({ block: true });
			} finally {
				session.dispose();
			}
		});

		it("allows a benign read-only command", async () => {
			const session = await buildSession(SettingsManager.inMemory({}, { projectTrusted: true }));
			try {
				expect(await callGate(session, "bash", { command: "ls -la" })).toBeUndefined();
			} finally {
				session.dispose();
			}
		});

		it("applies user-scope deny rules from settings", async () => {
			const denyRule: Rule = {
				raw: "bash(git push *)",
				tool: "bash",
				specifier: "git push *",
				list: "deny",
				scope: "user",
			};
			const session = await buildSession(
				SettingsManager.inMemory({ permissions: { rules: [denyRule] } }, { projectTrusted: true }),
			);
			try {
				expect(await callGate(session, "bash", { command: "git push origin main" })).toMatchObject({ block: true });
			} finally {
				session.dispose();
			}
		});

		it("does not gate when permissions are disabled", async () => {
			const session = await buildSession(
				SettingsManager.inMemory({ permissions: { enabled: false } }, { projectTrusted: false }),
			);
			try {
				expect(await callGate(session, "bash", { command: "rm -rf /" })).toBeUndefined();
			} finally {
				session.dispose();
			}
		});
	});

	describe("gate interaction with the extension runner", () => {
		it("deny shortcircuits before the extension runner", async () => {
			const denyRule: Rule = {
				raw: "bash(git push *)",
				tool: "bash",
				specifier: "git push *",
				list: "deny",
				scope: "user",
			};
			const runner = new RecordingRunner(true, { block: true, reason: "extension blocked" });
			const gate = makeGate(makeService({ userRules: [denyRule] }), runner);

			const result = await gate({ toolCall: { name: "bash", id: "c1" }, args: { command: "git push origin main" } });

			expect(result?.block).toBe(true);
			expect(result?.reason).not.toBe("extension blocked");
			expect(runner.calls).toHaveLength(0);
		});

		it("allow falls through so an extension can still block", async () => {
			const runner = new RecordingRunner(true, { block: true, reason: "extension blocked" });
			const gate = makeGate(makeService(), runner);

			const result = await gate({ toolCall: { name: "bash", id: "c1" }, args: { command: "ls -la" } });

			expect(runner.calls).toHaveLength(1);
			expect(result).toEqual({ block: true, reason: "extension blocked" });
		});

		it("provider always-allow persists a rule that allows an identical later call", async () => {
			const provider = new FakeApprovalProvider([
				(req) => ({ type: "always-allow", rules: req.alwaysAllowChoices[0].rules }),
			]);
			const runner = new RecordingRunner(false, undefined);
			const gate = makeGate(makeService({ approvalProvider: provider }), runner);
			const editArgs = { path: "/etc/hosts", edits: [{ oldText: "a", newText: "b" }] };

			const first = await gate({ toolCall: { name: "edit", id: "c1" }, args: editArgs });
			expect(first).toBeUndefined();
			expect(provider.requests).toHaveLength(1);
			expect(existsSync(join(agentDir, "permissions.json"))).toBe(true);

			const second = await gate({ toolCall: { name: "edit", id: "c2" }, args: editArgs });
			expect(second).toBeUndefined();
			// The persisted allow rule short-circuits to allow, so the provider is not consulted again.
			expect(provider.requests).toHaveLength(1);
		});

		it("deny short-circuits before a real extension tool_call handler", async () => {
			const denyRule: Rule = {
				raw: "bash(git push *)",
				tool: "bash",
				specifier: "git push *",
				list: "deny",
				scope: "user",
			};
			const handlerCalls: unknown[] = [];
			const resourceLoader = createTestResourceLoader({
				extensionsResult: await createTestExtensionsResult(
					[
						(pi) => {
							pi.on("tool_call", async (event) => {
								handlerCalls.push(event);
								return undefined;
							});
						},
					],
					cwd,
				),
			});
			const { session } = await createAgentSession({
				cwd,
				agentDir,
				model: getModel("anthropic", "claude-sonnet-4-5")!,
				settingsManager: SettingsManager.inMemory({ permissions: { rules: [denyRule] } }, { projectTrusted: true }),
				sessionManager: SessionManager.inMemory(),
				resourceLoader,
			});
			try {
				// A permitted call falls through to the extension handler, proving it is wired.
				expect(await callGate(session, "bash", { command: "ls -la" })).toBeUndefined();
				expect(handlerCalls).toHaveLength(1);
				// A denied call is blocked by the permission gate and never forwarded.
				expect(await callGate(session, "bash", { command: "git push origin main" })).toMatchObject({ block: true });
				expect(handlerCalls).toHaveLength(1);
			} finally {
				session.dispose();
			}
		});
	});
});
