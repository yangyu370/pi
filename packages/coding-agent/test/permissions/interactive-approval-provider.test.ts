import type { TUI } from "@earendil-works/pi-tui";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { InteractiveApprovalProvider } from "../../src/modes/interactive/permission-approval-provider.ts";
import { initTheme } from "../../src/modes/interactive/theme/theme.ts";
import { makeApprovalRequest } from "./approval-fixtures.ts";

const AFTER_GRACE_MS = 251;

// The overlay component styles text via the theme singleton, initialized once at startup in production.
beforeAll(() => initTheme("dark"));

interface CapturedOverlay {
	component: { handleInput(key: string): void };
	handle: { hide: ReturnType<typeof vi.fn>; focus: ReturnType<typeof vi.fn> };
}

function makeFakeUi(over?: { throwOnShow?: boolean }) {
	const captured: CapturedOverlay[] = [];
	const ui = {
		showOverlay(component: unknown) {
			if (over?.throwOnShow) throw new Error("overlay boom");
			const handle = { hide: vi.fn(), focus: vi.fn() };
			captured.push({ component: component as CapturedOverlay["component"], handle });
			return handle;
		},
	} as unknown as TUI;
	return { ui, captured };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("InteractiveApprovalProvider", () => {
	it("resolves allow-once when the overlay confirms the first option", async () => {
		const { ui, captured } = makeFakeUi();
		let now = 0;
		const provider = new InteractiveApprovalProvider(ui, { now: () => now });
		const pending = provider.requestApproval(makeApprovalRequest());
		await tick();
		now += AFTER_GRACE_MS;
		captured[0].component.handleInput("\n");
		expect(await pending).toEqual({ type: "allow-once" });
		expect(captured[0].handle.hide).toHaveBeenCalled();
	});

	it("propagates the rules of an always-allow choice", async () => {
		const { ui, captured } = makeFakeUi();
		let now = 0;
		const provider = new InteractiveApprovalProvider(ui, { now: () => now });
		const pending = provider.requestApproval(makeApprovalRequest());
		await tick();
		captured[0].component.handleInput("j");
		now += AFTER_GRACE_MS;
		captured[0].component.handleInput("\n");
		expect(await pending).toEqual({
			type: "always-allow",
			rules: [
				{ raw: "bash(git push *)", tool: "bash", specifier: "git push *", list: "allow", scope: "project-local" },
			],
		});
	});

	it("resolves deny on cancel", async () => {
		const { ui, captured } = makeFakeUi();
		let now = 0;
		const provider = new InteractiveApprovalProvider(ui, { now: () => now });
		const pending = provider.requestApproval(makeApprovalRequest());
		await tick();
		now += AFTER_GRACE_MS;
		captured[0].component.handleInput("\x1b");
		expect(await pending).toEqual({ type: "deny", reason: "Denied by user" });
	});

	it("serializes concurrent requests: the second overlay opens only after the first closes", async () => {
		const { ui, captured } = makeFakeUi();
		let now = 0;
		const provider = new InteractiveApprovalProvider(ui, { now: () => now });
		const first = provider.requestApproval(makeApprovalRequest());
		const second = provider.requestApproval(makeApprovalRequest());
		await tick();
		expect(captured).toHaveLength(1);
		now += AFTER_GRACE_MS;
		captured[0].component.handleInput("\n");
		await first;
		await tick();
		expect(captured).toHaveLength(2);
		now += AFTER_GRACE_MS;
		captured[1].component.handleInput("\n");
		await second;
	});

	it("never rejects: an overlay error resolves to deny", async () => {
		const { ui } = makeFakeUi({ throwOnShow: true });
		const provider = new InteractiveApprovalProvider(ui);
		const outcome = await provider.requestApproval(makeApprovalRequest());
		expect(outcome.type).toBe("deny");
	});
});
