import { setKeybindings } from "@earendil-works/pi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../../src/core/keybindings.ts";
import { PermissionModeSelectorComponent } from "../../src/modes/interactive/components/permission-mode-selector.ts";
import { initTheme } from "../../src/modes/interactive/theme/theme.ts";

describe("PermissionModeSelectorComponent", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	beforeEach(() => {
		setKeybindings(new KeybindingsManager({ "tui.select.confirm": [] }));
	});

	it("accepts raw carriage return as confirm", () => {
		const onSelect = vi.fn();
		const selector = new PermissionModeSelectorComponent({
			current: "default",
			onSelect,
			onCancel: () => {},
		});

		selector.handleInput("\r");

		expect(onSelect).toHaveBeenCalledWith("default");
	});
});
