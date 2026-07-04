import type { ApprovalDisplay, PermissionApprovalRequest } from "../../src/core/permissions/index.ts";

/** Builds a representative approval request for TUI-side tests (no permission engine needed). */
export function makeApprovalRequest(over?: Partial<ApprovalDisplay>): PermissionApprovalRequest {
	return {
		display: { toolName: "bash", capability: "exec", title: "Run: git push", detail: "git push", ...over },
		alwaysAllowChoices: [
			{
				id: "default",
				label: "Always allow git push *",
				rules: [
					{
						raw: "bash(git push *)",
						tool: "bash",
						specifier: "git push *",
						list: "allow",
						scope: "project-local",
					},
				],
			},
		],
	};
}
