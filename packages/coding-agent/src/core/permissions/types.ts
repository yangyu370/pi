export const PERMISSION_APPROVAL_CONTRACT_VERSION = 1;

export type Capability = "read" | "mutate" | "exec";

export type Scope = "cli" | "project-local" | "user" | "session";

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
