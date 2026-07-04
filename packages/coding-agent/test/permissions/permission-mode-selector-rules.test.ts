import { setKeybindings } from "@earendil-works/pi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../../src/core/keybindings.ts";
import { PermissionModeSelectorComponent } from "../../src/modes/interactive/components/permission-mode-selector.ts";
import { initTheme } from "../../src/modes/interactive/theme/theme.ts";

describe("PermissionModeSelectorComponent rules entry", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	beforeEach(() => {
		setKeybindings(new KeybindingsManager({ "tui.select.confirm": [] }));
	});

	it("offers a manage-rules entry", () => {
		const onManageRules = vi.fn();
		const selector = new PermissionModeSelectorComponent({
			current: "default",
			onSelect: () => {},
			onManageRules,
			onCancel: () => {},
		});

		for (let i = 0; i < 5; i++) {
			selector.handleInput("\x1b[B");
		}
		selector.handleInput("\r");

		expect(onManageRules).toHaveBeenCalledOnce();
	});
});
