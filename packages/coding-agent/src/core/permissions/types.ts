export const PERMISSION_APPROVAL_CONTRACT_VERSION = 1;

export type Capability = "read" | "mutate" | "exec";

export type Decision = "allow" | "deny" | "ask";

export type PermissionMode = "plan" | "default" | "acceptEdits" | "dontAsk" | "bypass";

export type RuleList = "allow" | "ask" | "deny";

export type Scope = "cli" | "project-local" | "user" | "session";

export interface Rule {
	raw: string;
	tool: string;
	specifier?: string;
	list: RuleList;
	scope: Scope;
}

export interface CommandAccess {
	command: string;
	normalizedCommand: string;
	readPaths: string[];
	mutatePaths: string[];
	readonly: boolean;
	circuitBreakerReason?: string;
	highRiskReason?: string;
}

export type Resource =
	| { kind: "command"; command: string; accesses: CommandAccess[] }
	| { kind: "paths"; paths: string[] }
	| { kind: "none" };

export interface PolicySnapshot {
	tool: string;
	capability: Capability;
	resource: Resource;
	mode: PermissionMode;
	trusted: boolean;
	rules: Rule[];
	cwd: string;
	home: string;
	workspaceRoot: string;
}

export interface CheckResult {
	decision: Decision;
	reason?: string;
	suggestedRules?: Array<Pick<Rule, "tool" | "specifier" | "list">>;
}

export interface ApprovalDisplay {
	toolName: string;
	capability: Capability;
	title: string;
	detail: string;
	diffPreview?: string;
	diffTruncated?: boolean;
	danger?: {
		level: "circuit-breaker" | "sensitive";
		reason: string;
	};
}

export interface SuggestedRule {
	raw: string;
	tool: string;
	specifier?: string;
	list: "allow";
	scope: Extract<Scope, "project-local">;
}

export interface AlwaysAllowChoice {
	id: string;
	label: string;
	rules: SuggestedRule[];
}

export interface PermissionApprovalRequest {
	display: ApprovalDisplay;
	alwaysAllowChoices: AlwaysAllowChoice[];
}

export type PermissionApprovalOutcome =
	| { type: "allow-once" }
	| { type: "always-allow"; rules: SuggestedRule[] }
	| { type: "deny"; reason?: string };

export interface PermissionApprovalProvider {
	requestApproval(request: PermissionApprovalRequest): Promise<PermissionApprovalOutcome>;
}
