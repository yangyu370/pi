import type { PermissionMode } from "../../core/permissions/index.ts";

export function nextPermissionModeForCycle(current: PermissionMode): PermissionMode {
	if (current === "default") {
		return "acceptEdits";
	}
	if (current === "acceptEdits") {
		return "plan";
	}
	return "default";
}
