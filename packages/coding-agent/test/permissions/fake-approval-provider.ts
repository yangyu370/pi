import type {
	PermissionApprovalOutcome,
	PermissionApprovalProvider,
	PermissionApprovalRequest,
} from "../../src/core/permissions/types.ts";

/** A scripted outcome, or a function that derives one from the request (e.g. echo back a choice's rules). */
export type ScriptedOutcome =
	| PermissionApprovalOutcome
	| ((request: PermissionApprovalRequest) => PermissionApprovalOutcome);

/**
 * Test double for {@link PermissionApprovalProvider}: returns pre-scripted
 * outcomes in order (defaulting to `deny` once exhausted) and records every
 * request it received for assertions.
 */
export class FakeApprovalProvider implements PermissionApprovalProvider {
	readonly requests: PermissionApprovalRequest[] = [];
	private readonly scripted: ScriptedOutcome[];

	constructor(scripted: ScriptedOutcome[] = []) {
		this.scripted = [...scripted];
	}

	requestApproval(request: PermissionApprovalRequest): Promise<PermissionApprovalOutcome> {
		this.requests.push(request);
		const next = this.scripted.shift();
		const outcome: PermissionApprovalOutcome =
			typeof next === "function" ? next(request) : (next ?? { type: "deny" });
		return Promise.resolve(outcome);
	}
}
