/**
 * Core permission/approval domain types for pi's coding-agent tool-approval layer.
 *
 * This module is intentionally pure: types plus the approval contract marker.
 * It defines the contract shared by the command analyzer, metadata engine,
 * rule store, service, approval overlay, and CLI/slash wiring.
 *
 * Positioning: this is an approval guardrail, not a security boundary.
 */

export const PERMISSION_APPROVAL_CONTRACT_VERSION = 1;

/** What a tool call is doing, at a coarse level. */
export type Capability = "read" | "mutate" | "exec";

/** The three outcomes a permission check can resolve to. */
export type Decision = "allow" | "deny" | "ask";

/**
 * Session-scoped permission mode (not persisted across sessions; rules persist separately).
 * - plan: read-only exploration; read and built-in read-only exec allowed, everything else denied.
 * - default: standard; first write/exec per tool category asks.
 * - acceptEdits: auto-accept edit/write within the workspace root; everything else asks.
 * - dontAsk: auto-deny unless pre-approved by an allow rule.
 * - bypass: skip ordinary prompts; circuit-breaker still asks in interactive mode and denies headlessly.
 */
export type PermissionMode = "plan" | "default" | "acceptEdits" | "dontAsk" | "bypass";

/** Which list a rule belongs to. */
export type RuleList = "allow" | "ask" | "deny";

/** Where a rule came from / where it is persisted. */
export type Scope = "cli" | "project-local" | "user" | "session";

/** A single per-tool specifier rule, e.g. `bash(git push *)`, `read(./.env)`. */
export interface Rule {
	/** Original raw text, e.g. "bash(git push *)", "read(./.env)". */
	raw: string;
	/** Tool name; deny/ask may use a glob such as "*"; allow must name a concrete tool. */
	tool: string;
	/** Contents of the parens; omitted means "matches every call to this tool". */
	specifier?: string;
	list: RuleList;
	scope: Scope;
}

/** A single command (or sub-command of a composite) analyzed for its resource access. */
export interface CommandAccess {
	/** Original sub-command or full command text. */
	command: string;
	/** Normalized command text used for bash(...) specifier matching. */
	normalizedCommand: string;
	/** Simple non-flag file arguments extracted from read-ish commands. */
	readPaths: string[];
	/** Simple write/delete target arguments; used for circuit-breaker/display. */
	mutatePaths: string[];
	readonly: boolean;
	/** Set when this command trips the rm/rmdir-on-critical-path circuit breaker. */
	circuitBreakerReason?: string;
	/** Set when this command is a high-risk structure. */
	highRiskReason?: string;
}

/** The resource a tool call touches, used to match path/command rules against. */
export type Resource =
	| { kind: "command"; command: string; accesses: CommandAccess[] }
	| { kind: "paths"; paths: string[] }
	| { kind: "none" };

/**
 * Everything engine.check() needs to decide one tool call.
 * The engine derives path-match anchors `{ cwd, home, workspaceRoot }` from this snapshot.
 */
export interface PolicySnapshot {
	tool: string;
	capability: Capability;
	resource: Resource;
	mode: PermissionMode;
	trusted: boolean;
	/** Rules already merged across scopes and de-duplicated. */
	rules: Rule[];
	cwd: string;
	home: string;
	/** Project root (git toplevel, falling back to session cwd); acceptEdits' edit boundary. */
	workspaceRoot: string;
}

/** Result of engine.check(). */
export interface CheckResult {
	decision: Decision;
	reason?: string;
	/** On "ask", candidate rules the service can offer as "always allow" choices. */
	suggestedRules?: Array<Pick<Rule, "tool" | "specifier" | "list">>;
}

/** What to show the user when asking for approval. */
export interface ApprovalDisplay {
	toolName: string;
	capability: Capability;
	title: string;
	detail: string;
	diffPreview?: string;
	danger?: {
		level: "circuit-breaker" | "sensitive";
		reason: string;
	};
}

/** A rule the service is offering to persist on behalf of the user. */
export interface SuggestedRule {
	raw: string;
	tool: string;
	specifier?: string;
	list: "allow";
	scope: Extract<Scope, "project-local">;
}

/** One "always allow" option, bundling one or more suggested rules under a single label. */
export interface AlwaysAllowChoice {
	id: string;
	label: string;
	rules: SuggestedRule[];
}

/** The full request handed to a PermissionApprovalProvider. */
export interface PermissionApprovalRequest {
	display: ApprovalDisplay;
	alwaysAllowChoices: AlwaysAllowChoice[];
}

/** What the user, or a non-interactive default, decided. */
export type PermissionApprovalOutcome =
	| { type: "allow-once" }
	| { type: "always-allow"; rules: SuggestedRule[] }
	| { type: "deny"; reason?: string };

/** Pluggable approval UI; interactive mode injects an overlay-backed implementation. */
export interface PermissionApprovalProvider {
	requestApproval(request: PermissionApprovalRequest): Promise<PermissionApprovalOutcome>;
}
