import { execFileSync } from "node:child_process";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import {
	applyEditsToNormalizedContent,
	type Edit,
	generateDiffString,
	normalizeToLF,
	stripBom,
} from "../tools/edit-diff.ts";
import { check } from "./engine.ts";
import { appendProjectLocalRules, loadProjectLocalRules, mergeRules, removeProjectLocalRules } from "./rule-store.ts";
import { extractResource, getToolCapability } from "./tool-metadata.ts";
import type {
	AlwaysAllowChoice,
	ApprovalDisplay,
	CheckResult,
	PermissionApprovalOutcome,
	PermissionApprovalProvider,
	PermissionApprovalRequest,
	PermissionMode,
	PolicySnapshot,
	Resource,
	Rule,
	SuggestedRule,
} from "./types.ts";

export interface PermissionServiceConfig {
	agentDir: string;
	cwd: string;
	enabled: boolean;
	isTrusted: () => boolean;
	userRules?: Rule[];
	cliRules?: Rule[];
	sessionRules?: Rule[];
	approvalProvider?: PermissionApprovalProvider;
	modeOverride?: PermissionMode;
	nonInteractiveDefault?: PermissionMode;
	approvalObserver?: PermissionApprovalObserver;
	logger?: (msg: string) => void;
}

const MAX_CHOICES = 3;
const DIFF_PREVIEW_MAX_BYTES = 1024 * 1024;
const DETAIL_MAX_CHARS = 2000;

export type PersistRulesResult = "persisted" | "session-only";

export interface PermissionApprovalResolution {
	display: ApprovalDisplay;
	outcome: PermissionApprovalOutcome;
	persistResult?: PersistRulesResult;
}

export type PermissionApprovalObserver = (resolution: PermissionApprovalResolution) => void;

interface DiffPreviewResult {
	diffPreview: string;
	diffTruncated?: boolean;
}

function toPosix(p: string): string {
	return p.replace(/\\/g, "/");
}

function reanchorPathSpecifier(absPath: string, workspaceRoot: string): string {
	const abs = toPosix(absPath);
	const root = toPosix(workspaceRoot).replace(/\/+$/, "");
	if (root !== "" && (abs === root || abs.startsWith(`${root}/`))) {
		const rel = abs === root ? "" : abs.slice(root.length + 1);
		return `/${rel}`;
	}
	return `//${abs.replace(/^\/+/, "")}`;
}

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

function prefixLines(prefix: string, text: string): string {
	return normalizeToLF(text)
		.split("\n")
		.map((line) => `${prefix} ${line}`)
		.join("\n");
}

function truncateText(text: string, maxChars: number): { text: string; truncated: boolean } {
	if (text.length <= maxChars) {
		return { text, truncated: false };
	}
	return { text: `${text.slice(0, maxChars)}\n... truncated`, truncated: true };
}

function stringifyArgs(args: unknown): string {
	try {
		return JSON.stringify(args, null, 2) ?? "<args unavailable>";
	} catch {
		return "<args unavailable>";
	}
}

function normalizeEditInput(value: unknown): Edit | undefined {
	const edit = asRecord(value);
	const oldText = edit.oldText;
	const newText = edit.newText;
	if (typeof oldText !== "string" || typeof newText !== "string") {
		return undefined;
	}
	return { oldText, newText };
}

function fallbackEditPreview(edits: Edit[], previewOnly: boolean): string {
	const lines = previewOnly ? ["(preview only)"] : [];
	for (const edit of edits) {
		lines.push(prefixLines("-", edit.oldText));
		lines.push(prefixLines("+", edit.newText));
	}
	return lines.join("\n");
}

function previewErrorMessage(error: unknown): string {
	const message = error instanceof Error ? error.message : String(error);
	const indexed = message.match(/edits\[(\d+)\]/);
	if (message.includes("Could not find")) {
		const index = indexed ? Number.parseInt(indexed[1], 10) + 1 : 1;
		return `edit ${index}: no match found`;
	}
	return message;
}

export class PermissionService {
	readonly enabled: boolean;

	private readonly agentDir: string;
	private readonly cwd: string;
	private readonly isTrusted: () => boolean;
	private readonly userRules: Rule[];
	private readonly cliRules: Rule[];
	private readonly sessionRules: Rule[];
	private approvalProvider?: PermissionApprovalProvider;
	private readonly nonInteractiveDefault?: PermissionMode;
	private readonly logger?: (msg: string) => void;
	private approvalObserver?: PermissionApprovalObserver;

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
		this.approvalObserver = cfg.approvalObserver;
		this.logger = cfg.logger;
	}

	get mode(): PermissionMode {
		return this.modeOverride ?? (this.isTrusted() ? "acceptEdits" : "default");
	}

	setMode(mode: PermissionMode): void {
		this.modeOverride = mode;
	}

	setApprovalProvider(provider: PermissionApprovalProvider): void {
		this.approvalProvider = provider;
	}

	setApprovalObserver(observer: PermissionApprovalObserver): void {
		this.approvalObserver = observer;
	}

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
			// ignore
		}
		this.cachedWorkspaceRoot = root;
		return root;
	}

	private canonicalDir(): string {
		const root = this.resolveWorkspaceRoot();
		try {
			return realpathSync(root);
		} catch {
			return resolve(root);
		}
	}

	buildSnapshot(toolName: string, args: unknown): PolicySnapshot {
		const workspaceRoot = this.resolveWorkspaceRoot();
		return {
			tool: toolName,
			capability: getToolCapability(toolName),
			resource: extractResource(toolName, args),
			mode: this.mode,
			trusted: this.isTrusted(),
			rules: this.listEffectiveRules(),
			cwd: this.cwd,
			home: homedir(),
			workspaceRoot,
		};
	}

	listEffectiveRules(): Rule[] {
		const projectLocal = loadProjectLocalRules(this.agentDir, this.canonicalDir());
		return mergeRules({
			session: this.sessionRules,
			cli: this.cliRules,
			projectLocal,
			user: this.userRules,
		});
	}

	removeProjectLocalRules(rules: Rule[]): void {
		removeProjectLocalRules(this.agentDir, this.canonicalDir(), rules);
	}

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

	async evaluate(
		toolCall: { name: string },
		args: unknown,
	): Promise<{ block?: boolean; reason?: string } | undefined> {
		const snapshot = this.buildSnapshot(toolCall.name, args);
		const result = this.safeCheck(snapshot);

		if (result.decision === "deny") return { block: true, reason: result.reason };
		if (result.decision === "allow") return undefined;

		if (this.approvalProvider) {
			const request = this.buildApprovalRequest(snapshot, args, result.suggestedRules);
			const outcome = await this.approvalProvider.requestApproval(request);
			if (outcome.type === "deny") {
				this.approvalObserver?.({ display: request.display, outcome });
				return { block: true, reason: outcome.reason };
			}
			if (outcome.type === "always-allow") {
				const persistResult = await this.persistRules(outcome.rules);
				this.approvalObserver?.({ display: request.display, outcome, persistResult });
				return undefined;
			}
			this.approvalObserver?.({ display: request.display, outcome });
			return undefined; // allow-once
		}

		const circuitBreaker = firstCircuitBreaker(snapshot.resource);
		if (circuitBreaker) return { block: true, reason: circuitBreaker };
		if (this.nonInteractiveDefault === "bypass") return undefined;
		return { block: true, reason: result.reason ?? "approval required (non-interactive)" };
	}

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

	async persistRules(rules: SuggestedRule[]): Promise<PersistRulesResult> {
		if (rules.length === 0) return "persisted";
		try {
			appendProjectLocalRules(this.agentDir, this.canonicalDir(), rules as Rule[]);
			return "persisted";
		} catch (err) {
			for (const rule of rules) this.sessionRules.push({ ...rule, scope: "session" } as Rule);
			this.logger?.(`failed to persist permission rules, kept for this session only: ${String(err)}`);
			return "session-only";
		}
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
			const specifier =
				isCommand || s.specifier === undefined
					? s.specifier
					: reanchorPathSpecifier(s.specifier, snapshot.workspaceRoot);
			const exact = makeSuggestedRule(s.tool, specifier);
			const label =
				snapshot.resource.kind === "none" && specifier === undefined
					? `Always allow \`${s.tool}\` (all inputs)`
					: `Always allow \`${specifier ?? s.tool}\``;
			choices.push({ id: `allow-${id++}`, label, rules: [exact] });

			if (isMutate && specifier !== undefined && choices.length < MAX_CHOICES) {
				const wide = widenToDirectory(specifier);
				// Editing a workspace-root-level file widens to `/**` (the entire
				// workspace) — far broader than the resource in front of the user, so
				// we don't offer it. Only the exact single-file allow remains.
				if (wide !== "/**") {
					choices.push({
						id: `allow-${id++}`,
						label: `Always allow edits under \`${wide}\``,
						rules: [makeSuggestedRule(s.tool, wide)],
					});
				}
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
			detail: this.buildDetail(snapshot, args),
			...(diffPreview !== undefined ? { diffPreview: diffPreview.diffPreview } : {}),
			...(diffPreview?.diffTruncated ? { diffTruncated: true } : {}),
			...(danger !== undefined ? { danger } : {}),
		};
	}

	private buildTitle(snapshot: PolicySnapshot): string {
		const { resource, capability, tool } = snapshot;
		if (resource.kind === "command") {
			const [firstLine = ""] = resource.command.split("\n");
			return `Run: ${firstLine}${firstLine.length === resource.command.length ? "" : " ..."}`;
		}
		if (resource.kind === "none") return `Run ${tool}`;
		const path = resource.paths[0] ?? "";
		if (capability === "read") return `Read ${path}`;
		return tool === "write" ? `Write ${path}` : `Edit ${path}`;
	}

	private buildDetail(snapshot: PolicySnapshot, args: unknown): string {
		const { resource } = snapshot;
		if (resource.kind === "command") {
			return resource.command.includes("\n") ? resource.command : "";
		}
		if (resource.kind === "paths") return resource.paths.join("\n");
		return truncateText(stringifyArgs(args), DETAIL_MAX_CHARS).text;
	}

	private buildDiffPreview(tool: string, args: unknown): DiffPreviewResult | undefined {
		const record = asRecord(args);
		if (tool === "edit") {
			return this.buildEditDiffPreview(record);
		}
		if (tool === "write") {
			return this.buildWriteDiffPreview(record);
		}
		return undefined;
	}

	private buildEditDiffPreview(record: Record<string, unknown>): DiffPreviewResult | undefined {
		const path = record.path;
		const rawEdits = record.edits;
		if (typeof path !== "string" || !Array.isArray(rawEdits)) return undefined;
		const edits = rawEdits.map(normalizeEditInput);
		if (edits.some((edit) => edit === undefined)) return undefined;
		const normalizedEdits = edits as Edit[];
		const absolutePath = resolve(this.cwd, path);
		try {
			if (statSync(absolutePath).size > DIFF_PREVIEW_MAX_BYTES) {
				return { diffPreview: fallbackEditPreview(normalizedEdits, true), diffTruncated: true };
			}
			const { text } = stripBom(readFileSync(absolutePath, "utf8"));
			const normalizedContent = normalizeToLF(text);
			const { baseContent, newContent } = applyEditsToNormalizedContent(normalizedContent, normalizedEdits, path);
			return { diffPreview: generateDiffString(baseContent, newContent, 2).diff };
		} catch (err) {
			const message = previewErrorMessage(err);
			if (message.includes("no match found")) {
				return { diffPreview: message };
			}
			return {
				diffPreview: `${message}\n${fallbackEditPreview(normalizedEdits, true)}`,
			};
		}
	}

	private buildWriteDiffPreview(record: Record<string, unknown>): DiffPreviewResult | undefined {
		const path = record.path;
		const content = record.content;
		if (typeof path !== "string" || typeof content !== "string") return undefined;

		const normalizedContent = normalizeToLF(content);
		const contentLimit = truncateText(normalizedContent, DIFF_PREVIEW_MAX_BYTES);
		const nextContent = contentLimit.text;
		const absolutePath = resolve(this.cwd, path);
		try {
			const existingSize = statSync(absolutePath).size;
			if (existingSize > DIFF_PREVIEW_MAX_BYTES) {
				// Avoid showing a large overwrite as a brand-new file.
				const notice = `(overwrites existing ${existingSize}-byte file; current content too large to diff — it will be replaced)`;
				return {
					diffPreview: `${notice}\n${generateDiffString("", nextContent, 2).diff}`,
					diffTruncated: true,
				};
			}
			const { text } = stripBom(readFileSync(absolutePath, "utf8"));
			return {
				diffPreview: generateDiffString(normalizeToLF(text), nextContent, 2).diff,
				...(contentLimit.truncated ? { diffTruncated: true } : {}),
			};
		} catch {
			return {
				diffPreview: generateDiffString("", nextContent, 2).diff,
				...(contentLimit.truncated ? { diffTruncated: true } : {}),
			};
		}
	}

	private buildDanger(snapshot: PolicySnapshot): ApprovalDisplay["danger"] {
		const circuitBreaker = firstCircuitBreaker(snapshot.resource);
		if (circuitBreaker) return { level: "circuit-breaker", reason: circuitBreaker };
		if (snapshot.capability === "read") {
			return { level: "sensitive", reason: "read of a protected path requires approval" };
		}
		return undefined;
	}
}
