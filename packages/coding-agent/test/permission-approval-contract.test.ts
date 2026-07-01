import { describe, expect, it } from "vitest";
import type {
	AlwaysAllowChoice,
	ApprovalDisplay,
	PermissionApprovalOutcome,
	PermissionApprovalProvider,
	PermissionApprovalRequest,
	SuggestedRule,
} from "../src/index.ts";
import { PERMISSION_APPROVAL_CONTRACT_VERSION } from "../src/index.ts";

class FakeApprovalProvider implements PermissionApprovalProvider {
	private readonly outcome: PermissionApprovalOutcome;

	constructor(outcome: PermissionApprovalOutcome) {
		this.outcome = outcome;
	}

	requestApproval(_request: PermissionApprovalRequest): Promise<PermissionApprovalOutcome> {
		return Promise.resolve(this.outcome);
	}
}

describe("permission approval shared contract", () => {
	it("exports the approval contract runtime marker", () => {
		expect(PERMISSION_APPROVAL_CONTRACT_VERSION).toBe(1);
	});

	it("allows UI providers to return a selected core-provided always-allow choice", async () => {
		const display: ApprovalDisplay = {
			toolName: "bash",
			capability: "exec",
			title: "Run: git push origin main",
			detail: "git push origin main",
		};
		const rule: SuggestedRule = {
			raw: "bash(git push *)",
			tool: "bash",
			specifier: "git push *",
			list: "allow",
			scope: "project-local",
		};
		const choice: AlwaysAllowChoice = {
			id: "default",
			label: "Always allow git push *",
			rules: [rule],
		};
		const provider = new FakeApprovalProvider({ type: "always-allow", rules: choice.rules });

		const outcome = await provider.requestApproval({
			display,
			alwaysAllowChoices: [choice],
		});

		expect(outcome).toEqual({ type: "always-allow", rules: [rule] });
	});
});
