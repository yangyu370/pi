import { Container, getKeybindings, Spacer, Text } from "@earendil-works/pi-tui";
import type { PermissionMode } from "../../../core/permissions/index.ts";
import { theme } from "../theme/theme.ts";
import { DynamicBorder } from "./dynamic-border.ts";
import { keyHint, rawKeyHint } from "./keybinding-hints.ts";

interface ModeOption {
	mode: PermissionMode;
	description: string;
}

const MODE_OPTIONS: ModeOption[] = [
	{ mode: "plan", description: "Read-only exploration; writes and exec denied." },
	{ mode: "default", description: "Standard; first write/exec per tool category asks." },
	{ mode: "acceptEdits", description: "Auto-accept edits/writes in the workspace; else ask." },
	{ mode: "dontAsk", description: "Auto-deny unless pre-approved by an allow rule." },
	{ mode: "bypass", description: "Skip ordinary prompts; circuit-breaker still guards." },
];

export interface PermissionModeSelectorOptions {
	current: PermissionMode;
	onSelect: (mode: PermissionMode) => void;
	onCancel: () => void;
}

export class PermissionModeSelectorComponent extends Container {
	private readonly current: PermissionMode;
	private readonly onSelect: (mode: PermissionMode) => void;
	private readonly onCancel: () => void;
	private readonly listContainer: Container;
	private selectedIndex: number;

	constructor(options: PermissionModeSelectorOptions) {
		super();
		this.current = options.current;
		this.onSelect = options.onSelect;
		this.onCancel = options.onCancel;
		this.selectedIndex = Math.max(
			0,
			MODE_OPTIONS.findIndex((option) => option.mode === options.current),
		);

		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new Text(theme.fg("accent", theme.bold("Permission mode")), 1, 0));
		this.addChild(new Spacer(1));

		this.listContainer = new Container();
		this.addChild(this.listContainer);
		this.addChild(new Spacer(1));
		this.addChild(
			new Text(
				`${rawKeyHint("↑↓", "navigate")}  ${keyHint("tui.select.confirm", "select")}  ${keyHint("tui.select.cancel", "cancel")}`,
				1,
				0,
			),
		);
		this.addChild(new Spacer(1));
		this.addChild(new DynamicBorder());

		this.updateList();
	}

	private updateList(): void {
		this.listContainer.clear();
		for (let i = 0; i < MODE_OPTIONS.length; i++) {
			const option = MODE_OPTIONS[i];
			const isSelected = i === this.selectedIndex;
			const isCurrent = option.mode === this.current;
			const checkmark = isCurrent ? theme.fg("success", " ✓") : "";
			const prefix = isSelected ? theme.fg("accent", "→ ") : "  ";
			const label = isSelected ? theme.fg("accent", option.mode) : theme.fg("text", option.mode);
			this.listContainer.addChild(new Text(`${prefix}${label}${checkmark}`, 1, 0));
			this.listContainer.addChild(new Text(theme.fg("muted", `    ${option.description}`), 1, 0));
		}
	}

	handleInput(keyData: string): void {
		const kb = getKeybindings();
		if (kb.matches(keyData, "tui.select.up") || keyData === "k") {
			this.selectedIndex = Math.max(0, this.selectedIndex - 1);
			this.updateList();
		} else if (kb.matches(keyData, "tui.select.down") || keyData === "j") {
			this.selectedIndex = Math.min(MODE_OPTIONS.length - 1, this.selectedIndex + 1);
			this.updateList();
		} else if (kb.matches(keyData, "tui.select.confirm") || keyData === "\n") {
			this.onSelect(MODE_OPTIONS[this.selectedIndex].mode);
		} else if (kb.matches(keyData, "tui.select.cancel")) {
			this.onCancel();
		}
	}
}
