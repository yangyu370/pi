/**
 * The stateful permission service: the bridge between the pure decision engine
 * (`./engine.ts`) and the running agent. It owns session state (mode override,
 * in-memory session rules), resolves the workspace root + canonical project
 * dir, assembles a {@link PolicySnapshot} per tool call, runs the engine, and
 * turns an `ask` outcome into either an interactive approval request (when a
 * provider is wired) or a non-interactive default decision.
 *
 * Fail-safe posture (spec §18): the engine already fails safe to `ask`, and
 * this service wraps `check` in a try/catch that fails closed — an interactive
 * session re-asks, a headless one denies. A circuit-breaker `ask` denies in
 * headless mode even under `bypass`.
 *
 * Positioning: this is an approval guardrail, not a security boundary (see
 * ./types.ts).
 */

import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { check } from "./engine.ts";
import { appendProjectLocalRules, loadProjectLocalRules, mergeRules } from "./rule-store.ts";
import { extractResource, getToolCapability } from "./tool-metadata.ts";
import type {
	AlwaysAllowChoice,
	ApprovalDisplay,
	CheckResult,
	PermissionApprovalProvider,
	PermissionApprovalRequest,
	PermissionMode,
	PolicySnapshot,
	Resource,
	Rule,
	SuggestedRule,
} from "./types.ts";

/** Everything the service needs; the mode layer (PR5) injects the concrete wiring. */
export interface PermissionServiceConfig {
	agentDir: string;
	cwd: string;
	enabled: boolean;
	/** Resolved "is the current project trusted" signal (e.g. SettingsManager.isProjectTrusted). */
	isTrusted: () => boolean;
	/** User-scope rules, injected (do NOT couple the service to SettingsManager here). */
	userRules?: Rule[];
	/** CLI `--allow`/`--deny` rules for this run. */
	cliRules?: Rule[];
	/** Session rules (grows when a persist fails or `/allow`-in-session is used). */
	sessionRules?: Rule[];
	/** Interactive approval UI; absent ⇒ headless. */
	approvalProvider?: PermissionApprovalProvider;
	/** Forces the session mode; absent ⇒ derived from trust. */
	modeOverride?: PermissionMode;
	/** What a headless `ask` resolves to (`bypass` ⇒ allow, anything else ⇒ deny). */
	nonInteractiveDefault?: PermissionMode;
	logger?: (msg: string) => void;
}

/** Max "always allow" choices offered per request (spec §24.1). */
const MAX_CHOICES = 3;

function toPosix(p: string): string {
	return p.replace(/\\/g, "/");
}

/**
 * Re-anchors an engine-resolved ABSOLUTE path specifier into a form the
 * rule-matcher reads back correctly (carry-forward from PR3): a path under the
 * workspace root becomes project-root-relative (`/<rel>`); anything else
 * becomes filesystem-absolute (`//<abs>`). A bare `/abs/...` is never persisted
 * — `matchPath` would misread it as project-root-relative.
 */
function reanchorPathSpecifier(absPath: string, workspaceRoot: string): string {
	const abs = toPosix(absPath);
	const root = toPosix(workspaceRoot).replace(/\/+$/, "");
	if (root !== "" && (abs === root || abs.startsWith(`${root}/`))) {
		const rel = abs === root ? "" : abs.slice(root.length + 1);
		return `/${rel}`;
	}
	return `//${abs.replace(/^\/+/, "")}`;
}

/** Widens a re-anchored path specifier to its containing directory glob (`<dir>/**`). */
function widenToDirectory(specifier: string): string {
	const slash = specifier.lastIndexOf("/");
	return `${specifier.slice(0, slash < 0 ? 0 : slash)}/**`;
}

function makeSuggestedRule(tool: string, specifier: string | undefined): SuggestedRule {
	return {
		raw: specifier === undefined ? tool : `${tool}(${specifier})`,
		tool,
		...(specifier !== undefined ? { specifier } : {}),
		list: "allow",
		scope: "project-local",
	};
}

/** The circuit-breaker reason of the first tripped access, if any. */
function firstCircuitBreaker(resource: Resource): string | undefined {
	if (resource.kind !== "command") return undefined;
	for (const access of resource.accesses) {
		if (access.circuitBreakerReason) return access.circuitBreakerReason;
	}
	return undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
	return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

export class PermissionService {
	readonly enabled: boolean;

	private readonly agentDir: string;
	private readonly cwd: string;
	private readonly isTrusted: () => boolean;
	private readonly userRules: Rule[];
	private readonly cliRules: Rule[];
	/** Mutable: a failed persist falls back to appending here. */
	private readonly sessionRules: Rule[];
	private approvalProvider?: PermissionApprovalProvider;
	private readonly nonInteractiveDefault?: PermissionMode;
	private readonly logger?: (msg: string) => void;

	private modeOverride?: PermissionMode;
	private cachedWorkspaceRoot?: string;

	constructor(cfg: PermissionServiceConfig) {
		this.enabled = cfg.enabled;
		this.agentDir = cfg.agentDir;
		this.cwd = cfg.cwd;
		this.isTrusted = cfg.isTrusted;
		this.userRules = cfg.userRules ?? [];
		this.cliRules = cfg.cliRules ?? [];
		this.sessionRules = [...(cfg.sessionRules ?? [])];
		this.approvalProvider = cfg.approvalProvider;
		this.modeOverride = cfg.modeOverride;
		this.nonInteractiveDefault = cfg.nonInteractiveDefault;
		this.logger = cfg.logger;
	}

	/** Session-scoped mode: an explicit override, else derived from trust. */
	get mode(): PermissionMode {
		return this.modeOverride ?? (this.isTrusted() ? "acceptEdits" : "default");
	}

	/** Sets the session mode (not persisted across sessions). */
	setMode(mode: PermissionMode): void {
		this.modeOverride = mode;
	}

	/** Injects the interactive approval UI after construction (the TUI outlives session construction). */
	setApprovalProvider(provider: PermissionApprovalProvider): void {
		this.approvalProvider = provider;
	}

	/** Git toplevel of `cwd`, falling back to `cwd` on any error; cached. */
	private resolveWorkspaceRoot(): string {
		if (this.cachedWorkspaceRoot !== undefined) return this.cachedWorkspaceRoot;
		let root = this.cwd;
		try {
			const top = execFileSync("git", ["rev-parse", "--show-toplevel"], {
				cwd: this.cwd,
				encoding: "utf8",
				stdio: ["ignore", "pipe", "ignore"],
			}).trim();
			if (top) root = top;
		} catch {
			// Not a git repo / git absent: fall back to cwd.
		}
		this.cachedWorkspaceRoot = root;
		return root;
	}

	/** Canonical (symlink-resolved) workspace root — the key under which rules persist. */
	private canonicalDir(): string {
		const root = this.resolveWorkspaceRoot();
		try {
			return realpathSync(root);
		} catch {
			return resolve(root);
		}
	}

	/** Assembles the full snapshot the engine needs for one tool call. */
	buildSnapshot(toolName: string, args: unknown): PolicySnapshot {
		const workspaceRoot = this.resolveWorkspaceRoot();
		const projectLocal = loadProjectLocalRules(this.agentDir, this.canonicalDir());
		const rules = mergeRules({
			session: this.sessionRules,
			cli: this.cliRules,
			projectLocal,
			user: this.userRules,
		});
		return {
			tool: toolName,
			capability: getToolCapability(toolName),
			resource: extractResource(toolName, args),
			mode: this.mode,
			trusted: this.isTrusted(),
			rules,
			cwd: this.cwd,
			home: homedir(),
			workspaceRoot,
		};
	}

	/** Runs `check`, failing closed on any unexpected throw (ask if interactive, else deny). */
	private safeCheck(snapshot: PolicySnapshot): CheckResult {
		try {
			return check(snapshot);
		} catch (err) {
			this.logger?.(`permission check failed: ${String(err)}`);
			return this.approvalProvider
				? { decision: "ask", reason: "permission check failed; asking to be safe" }
				: { decision: "deny", reason: "permission check failed; denying to be safe" };
		}
	}

	/**
	 * The entry point PR5's `beforeToolCall` calls. Resolves to `undefined`
	 * (proceed) or `{ block, reason }` (blocked). An `ask` becomes an
	 * interactive prompt when a provider is present, otherwise a non-interactive
	 * default — with the one exception that a circuit-breaker `ask` always blocks
	 * headlessly, even under `bypass`.
	 */
	async evaluate(
		toolCall: { name: string },
		args: unknown,
	): Promise<{ block?: boolean; reason?: string } | undefined> {
		const snapshot = this.buildSnapshot(toolCall.name, args);
		const result = this.safeCheck(snapshot);

		if (result.decision === "deny") return { block: true, reason: result.reason };
		if (result.decision === "allow") return undefined;

		// decision === "ask".
		if (this.approvalProvider) {
			const request = this.buildApprovalRequest(snapshot, args, result.suggestedRules);
			const outcome = await this.approvalProvider.requestApproval(request);
			if (outcome.type === "deny") return { block: true, reason: outcome.reason };
			if (outcome.type === "always-allow") {
				await this.persistRules(outcome.rules);
				return undefined;
			}
			return undefined; // allow-once
		}

		// Headless: a circuit-breaker denies even under bypass.
		const circuitBreaker = firstCircuitBreaker(snapshot.resource);
		if (circuitBreaker) return { block: true, reason: circuitBreaker };
		if (this.nonInteractiveDefault === "bypass") return undefined;
		return { block: true, reason: result.reason ?? "approval required (non-interactive)" };
	}

	/** Builds the display + "always allow" choices for an interactive prompt. */
	buildApprovalRequest(
		snapshot: PolicySnapshot,
		args: unknown,
		suggested?: CheckResult["suggestedRules"],
	): PermissionApprovalRequest {
		return {
			display: this.buildDisplay(snapshot, args),
			alwaysAllowChoices: this.buildChoices(snapshot, suggested ?? []),
		};
	}

	/** Persists always-allow rules; on failure keeps them in-session and logs (never throws). */
	async persistRules(rules: SuggestedRule[]): Promise<void> {
		if (rules.length === 0) return;
		try {
			appendProjectLocalRules(this.agentDir, this.canonicalDir(), rules as Rule[]);
		} catch (err) {
			for (const rule of rules) this.sessionRules.push(rule as Rule);
			this.logger?.(`failed to persist permission rules, kept for this session only: ${String(err)}`);
		}
		return Promise.resolve();
	}

	private buildChoices(
		snapshot: PolicySnapshot,
		suggested: NonNullable<CheckResult["suggestedRules"]>,
	): AlwaysAllowChoice[] {
		const choices: AlwaysAllowChoice[] = [];
		const isCommand = snapshot.resource.kind === "command";
		const isMutate = snapshot.capability === "mutate";
		let id = 0;
		for (const s of suggested) {
			if (choices.length >= MAX_CHOICES) break;
			// Bash specifiers pass through; path specifiers (resolved absolute) are re-anchored.
			const specifier =
				isCommand || s.specifier === undefined
					? s.specifier
					: reanchorPathSpecifier(s.specifier, snapshot.workspaceRoot);
			const exact = makeSuggestedRule(s.tool, specifier);
			choices.push({ id: `allow-${id++}`, label: `Always allow \`${specifier ?? s.tool}\``, rules: [exact] });

			if (isMutate && specifier !== undefined && choices.length < MAX_CHOICES) {
				const wide = widenToDirectory(specifier);
				choices.push({
					id: `allow-${id++}`,
					label: `Always allow edits under \`${wide}\``,
					rules: [makeSuggestedRule(s.tool, wide)],
				});
			}
		}
		return choices;
	}

	private buildDisplay(snapshot: PolicySnapshot, args: unknown): ApprovalDisplay {
		const danger = this.buildDanger(snapshot);
		const diffPreview = this.buildDiffPreview(snapshot.tool, args);
		return {
			toolName: snapshot.tool,
			capability: snapshot.capability,
			title: this.buildTitle(snapshot),
			detail: this.buildDetail(snapshot),
			...(diffPreview !== undefined ? { diffPreview } : {}),
			...(danger !== undefined ? { danger } : {}),
		};
	}

	private buildTitle(snapshot: PolicySnapshot): string {
		const { resource, capability, tool } = snapshot;
		if (resource.kind === "command") return `Run: ${resource.command}`;
		// Extension/MCP/custom tools carry no resource; name the tool instead of mislabeling it an edit.
		if (resource.kind === "none") return `Run ${tool}`;
		const path = resource.paths[0] ?? "";
		if (capability === "read") return `Read ${path}`;
		return tool === "write" ? `Write ${path}` : `Edit ${path}`;
	}

	private buildDetail(snapshot: PolicySnapshot): string {
		const { resource } = snapshot;
		if (resource.kind === "command") return resource.command;
		if (resource.kind === "paths") return resource.paths.join("\n");
		return "";
	}

	private buildDiffPreview(tool: string, args: unknown): string | undefined {
		const record = asRecord(args);
		if (tool === "edit") {
			const edits = record.edits;
			if (!Array.isArray(edits)) return undefined;
			return edits
				.map((e) => {
					const edit = asRecord(e);
					return `- ${String(edit.oldText ?? "")}\n+ ${String(edit.newText ?? "")}`;
				})
				.join("\n");
		}
		if (tool === "write") {
			const content = record.content;
			return typeof content === "string" ? content.split("\n").slice(0, 20).join("\n") : undefined;
		}
		return undefined;
	}

	private buildDanger(snapshot: PolicySnapshot): ApprovalDisplay["danger"] {
		const circuitBreaker = firstCircuitBreaker(snapshot.resource);
		if (circuitBreaker) return { level: "circuit-breaker", reason: circuitBreaker };
		// A read only reaches an approval prompt via an explicit ask/deny rule.
		if (snapshot.capability === "read") {
			return { level: "sensitive", reason: "read of a protected path requires approval" };
		}
		return undefined;
	}
}
