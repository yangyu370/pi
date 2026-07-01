import type { Component, OverlayHandle, OverlayOptions, TUI } from "@earendil-works/pi-tui";
import type {
	PermissionApprovalOutcome,
	PermissionApprovalProvider,
	PermissionApprovalRequest,
} from "../../core/permissions/index.ts";
import { ApprovalOverlayComponent } from "./components/approval-overlay.ts";

export type ApprovalOverlayHost = Pick<TUI, "showOverlay">;

interface PendingApproval {
	request: PermissionApprovalRequest;
	resolve: (outcome: PermissionApprovalOutcome) => void;
	handle?: OverlayHandle;
	settled: boolean;
}

export class InteractiveApprovalProvider implements PermissionApprovalProvider {
	private readonly host: ApprovalOverlayHost;
	private active: PendingApproval | undefined;
	private readonly queue: PendingApproval[] = [];

	constructor(host: ApprovalOverlayHost) {
		this.host = host;
	}

	requestApproval(request: PermissionApprovalRequest): Promise<PermissionApprovalOutcome> {
		return new Promise<PermissionApprovalOutcome>((resolve) => {
			this.queue.push({ request, resolve, settled: false });
			this.startNext();
		});
	}

	abortPending(reason = "Aborted"): void {
		const outcome: PermissionApprovalOutcome = { type: "deny", reason };
		const active = this.active;
		this.active = undefined;
		if (active) {
			this.finish(active, outcome, { startNext: false });
		}
		for (const pending of this.queue.splice(0)) {
			this.finish(pending, outcome, { startNext: false });
		}
	}

	private startNext(): void {
		if (this.active) {
			return;
		}
		const pending = this.queue.shift();
		if (!pending) {
			return;
		}
		this.active = pending;
		const done = (outcome: PermissionApprovalOutcome) => {
			this.finish(pending, outcome, { startNext: true });
		};
		try {
			const component: Component = new ApprovalOverlayComponent({
				request: pending.request,
				onSubmit: done,
				onCancel: () => done({ type: "deny", reason: "Denied by user" }),
			});
			const options: OverlayOptions = { anchor: "center" };
			pending.handle = this.host.showOverlay(component, options);
			pending.handle.focus();
		} catch (error) {
			done({
				type: "deny",
				reason: error instanceof Error ? error.message : "Approval overlay failed",
			});
		}
	}

	private finish(pending: PendingApproval, outcome: PermissionApprovalOutcome, options: { startNext: boolean }): void {
		if (pending.settled) {
			return;
		}
		pending.settled = true;
		pending.resolve(outcome);
		this.hideOverlay(pending);
		if (this.active === pending) {
			this.active = undefined;
		}
		if (options.startNext) {
			this.startNext();
		}
	}

	private hideOverlay(pending: PendingApproval): void {
		try {
			pending.handle?.hide();
		} catch {
			// Approval resolution must not depend on overlay teardown succeeding.
		}
	}
}
