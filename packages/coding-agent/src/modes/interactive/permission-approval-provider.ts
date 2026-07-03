import type { OverlayHandle, TUI } from "@earendil-works/pi-tui";
import type {
	PermissionApprovalOutcome,
	PermissionApprovalProvider,
	PermissionApprovalRequest,
} from "../../core/permissions/index.ts";
import { ApprovalOverlayComponent } from "./components/approval-overlay.ts";

const DENY_REASON = "Denied by user";

/**
 * Bridges the frozen {@link PermissionApprovalProvider} contract to the TUI overlay.
 * Concurrent asks are serialized (one overlay at a time), and any failure resolves
 * to a deny — the contract forbids rejecting.
 */
export class InteractiveApprovalProvider implements PermissionApprovalProvider {
	private queue: Promise<unknown> = Promise.resolve();
	private readonly ui: TUI;

	constructor(ui: TUI) {
		this.ui = ui;
	}

	requestApproval(request: PermissionApprovalRequest): Promise<PermissionApprovalOutcome> {
		const run = (): Promise<PermissionApprovalOutcome> =>
			new Promise<PermissionApprovalOutcome>((resolve) => {
				let handle: OverlayHandle | undefined;
				const done = (outcome: PermissionApprovalOutcome): void => {
					handle?.hide();
					resolve(outcome);
				};
				const component = new ApprovalOverlayComponent({
					request,
					onSubmit: done,
					onCancel: () => done({ type: "deny", reason: DENY_REASON }),
				});
				handle = this.ui.showOverlay(component, { anchor: "center" });
				handle.focus();
			});

		const result = this.queue.then(run, run).catch(
			(error: unknown): PermissionApprovalOutcome => ({
				type: "deny",
				reason: error instanceof Error ? error.message : "Approval overlay failed",
			}),
		);
		// Keep the tail settled so a rejection can never wedge later approvals.
		this.queue = result.then(
			() => undefined,
			() => undefined,
		);
		return result;
	}
}
