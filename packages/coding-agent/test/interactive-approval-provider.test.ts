import { type Component, type OverlayHandle, type OverlayOptions, setKeybindings } from "@earendil-works/pi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import type { PermissionApprovalRequest } from "../src/index.ts";
import { ApprovalOverlayComponent } from "../src/modes/interactive/components/approval-overlay.ts";
import { InteractiveApprovalProvider } from "../src/modes/interactive/permission-approval-provider.ts";
import { initTheme } from "../src/modes/interactive/theme/theme.ts";

function makeApprovalRequest(): PermissionApprovalRequest {
	return {
		display: {
			toolName: "bash",
			capability: "exec",
			title: "Run: git push",
			detail: "git push",
		},
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

class FakeOverlayHost {
	handles: OverlayHandle[] = [];
	components: Component[] = [];
	optionsList: Array<OverlayOptions | undefined> = [];

	showOverlay(component: Component, options?: OverlayOptions): OverlayHandle {
		const handle: OverlayHandle = {
			hide: vi.fn(),
			setHidden: vi.fn(),
			isHidden: () => false,
			focus: vi.fn(),
			unfocus: vi.fn(),
			isFocused: () => true,
		};
		this.components.push(component);
		this.optionsList.push(options);
		this.handles.push(handle);
		return handle;
	}
}

describe("InteractiveApprovalProvider", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	beforeEach(() => {
		setKeybindings(new KeybindingsManager());
	});

	it("shows the approval overlay and resolves with the submitted outcome", async () => {
		const host = new FakeOverlayHost();
		const provider = new InteractiveApprovalProvider(host);
		const request = makeApprovalRequest();

		const result = provider.requestApproval(request);
		expect(host.components[0]).toBeInstanceOf(ApprovalOverlayComponent);
		expect(host.optionsList[0]).toMatchObject({ anchor: "center" });
		expect(host.handles[0]?.focus).toHaveBeenCalledOnce();

		(host.components[0] as ApprovalOverlayComponent).handleInput("\x1b[B");
		(host.components[0] as ApprovalOverlayComponent).handleInput("\r");

		await expect(result).resolves.toEqual({
			type: "always-allow",
			rules: request.alwaysAllowChoices[0]?.rules,
		});
		expect(host.handles[0]?.hide).toHaveBeenCalledOnce();
	});

	it("resolves cancel as deny", async () => {
		const host = new FakeOverlayHost();
		const provider = new InteractiveApprovalProvider(host);

		const result = provider.requestApproval(makeApprovalRequest());
		(host.components[0] as ApprovalOverlayComponent).handleInput("\x1b");

		await expect(result).resolves.toEqual({ type: "deny", reason: "Denied by user" });
		expect(host.handles[0]?.hide).toHaveBeenCalledOnce();
	});

	it("serializes concurrent approval requests", async () => {
		const host = new FakeOverlayHost();
		const provider = new InteractiveApprovalProvider(host);
		const first = provider.requestApproval(makeApprovalRequest());
		const second = provider.requestApproval(makeApprovalRequest());

		expect(host.components).toHaveLength(1);

		(host.components[0] as ApprovalOverlayComponent).handleInput("\r");
		await expect(first).resolves.toEqual({ type: "allow-once" });

		expect(host.components).toHaveLength(2);
		(host.components[1] as ApprovalOverlayComponent).handleInput("\r");
		await expect(second).resolves.toEqual({ type: "allow-once" });
	});

	it("aborts current and queued approval requests", async () => {
		const host = new FakeOverlayHost();
		const provider = new InteractiveApprovalProvider(host);
		const first = provider.requestApproval(makeApprovalRequest());
		const second = provider.requestApproval(makeApprovalRequest());

		provider.abortPending("Aborted");

		await expect(first).resolves.toEqual({ type: "deny", reason: "Aborted" });
		await expect(second).resolves.toEqual({ type: "deny", reason: "Aborted" });
		expect(host.handles[0]?.hide).toHaveBeenCalledOnce();
		expect(host.components).toHaveLength(1);
	});

	it("resolves deny when the overlay cannot be shown", async () => {
		const provider = new InteractiveApprovalProvider({
			showOverlay: () => {
				throw new Error("TUI unavailable");
			},
		});

		await expect(provider.requestApproval(makeApprovalRequest())).resolves.toEqual({
			type: "deny",
			reason: "TUI unavailable",
		});
	});

	it("still resolves and aborts queued approvals when closing the active overlay fails", async () => {
		const host = new FakeOverlayHost();
		const provider = new InteractiveApprovalProvider(host);
		const first = provider.requestApproval(makeApprovalRequest());
		const second = provider.requestApproval(makeApprovalRequest());
		const hide = host.handles[0]?.hide;
		if (!hide) {
			throw new Error("expected active overlay handle");
		}
		vi.mocked(hide).mockImplementationOnce(() => {
			throw new Error("close failed");
		});

		provider.abortPending("Aborted");

		await expect(first).resolves.toEqual({ type: "deny", reason: "Aborted" });
		await expect(second).resolves.toEqual({ type: "deny", reason: "Aborted" });
		expect(host.components).toHaveLength(1);
	});
});
