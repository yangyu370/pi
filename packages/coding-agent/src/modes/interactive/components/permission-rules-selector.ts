import { Container, getKeybindings, Spacer, Text, TruncatedText } from "@earendil-works/pi-tui";
import type { Rule, Scope } from "../../../core/permissions/index.ts";
import { theme } from "../theme/theme.ts";
import { DynamicBorder } from "./dynamic-border.ts";
import { keyHint, rawKeyHint } from "./keybinding-hints.ts";

const SCOPE_ORDER: Scope[] = ["project-local", "session", "cli", "user"];

const SCOPE_LABELS: Record<Scope, string> = {
	"project-local": "project-local",
	session: "session",
	cli: "cli (--allow)",
	user: "user",
};

interface RuleItem {
	rule: Rule;
	index: number;
}

export interface PermissionRulesSelectorOptions {
	projectPath: string;
	rules: Rule[];
	onDelete: (rules: Rule[]) => void;
	onCancel: () => void;
}

export class PermissionRulesSelectorComponent extends Container {
	private readonly projectPath: string;
	private readonly onDelete: (rules: Rule[]) => void;
	private readonly onCancel: () => void;
	private readonly listContainer: Container;
	private rules: Rule[];
	private selectedIndex = 0;
	private confirmingDelete = false;

	constructor(options: PermissionRulesSelectorOptions) {
		super();
		this.projectPath = options.projectPath;
		this.rules = options.rules;
		this.onDelete = options.onDelete;
		this.onCancel = options.onCancel;

		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new Text(theme.fg("accent", theme.bold(`Permission rules - ${this.projectPath}`)), 1, 0));
		this.addChild(new Spacer(1));
		this.listContainer = new Container();
		this.addChild(this.listContainer);
		this.addChild(new Spacer(1));
		this.addChild(
			new Text(
				`${rawKeyHint("↑↓", "navigate")}  ${rawKeyHint("d/del", "delete")}  ${keyHint("tui.select.cancel", "close")}`,
				1,
				0,
			),
		);
		this.addChild(new Spacer(1));
		this.addChild(new DynamicBorder());
		this.updateList();
	}

	// Items are laid out in the same grouped order they render in, so selectedIndex
	// (moved by ↑↓) always matches the visible top-to-bottom position of the cursor.
	private getItems(): RuleItem[] {
		const items: RuleItem[] = [];
		for (const scope of SCOPE_ORDER) {
			for (const rule of this.rules) {
				if (rule.scope === scope) items.push({ rule, index: items.length });
			}
		}
		return items;
	}

	private selectedItem(): RuleItem | undefined {
		return this.getItems()[this.selectedIndex];
	}

	private updateList(): void {
		this.listContainer.clear();
		const items = this.getItems();
		this.selectedIndex = Math.max(0, Math.min(items.length - 1, this.selectedIndex));
		if (items.length === 0) {
			this.listContainer.addChild(new Text(theme.fg("muted", "No rules for this project"), 1, 0));
			return;
		}

		let lastScope: Scope | undefined;
		for (const item of items) {
			if (item.rule.scope !== lastScope) {
				lastScope = item.rule.scope;
				this.listContainer.addChild(new Text(theme.fg("muted", SCOPE_LABELS[lastScope]), 1, 0));
			}
			this.listContainer.addChild(new TruncatedText(this.formatRule(item), 1, 0));
		}
	}

	private formatRule(item: RuleItem): string {
		const selected = item.index === this.selectedIndex;
		const prefix = selected ? theme.fg("accent", "> ") : "  ";
		const readonly = item.rule.scope === "project-local" ? "" : " (read-only here)";
		const base = `${item.rule.list} ${item.rule.raw}${readonly}`;
		if (selected && this.confirmingDelete && item.rule.scope === "project-local") {
			return `${prefix}${theme.fg("error", `${base} delete? (y/n)`)}`;
		}
		const color = selected ? "accent" : "text";
		return `${prefix}${theme.fg(color, base)}`;
	}

	private moveSelection(delta: number): void {
		const items = this.getItems();
		if (items.length === 0) return;
		this.selectedIndex = Math.max(0, Math.min(items.length - 1, this.selectedIndex + delta));
		this.confirmingDelete = false;
		this.updateList();
	}

	private requestDelete(): void {
		const item = this.selectedItem();
		if (!item || item.rule.scope !== "project-local") return;
		this.confirmingDelete = true;
		this.updateList();
	}

	private confirmDelete(): void {
		const item = this.selectedItem();
		if (!item || item.rule.scope !== "project-local") return;
		this.confirmingDelete = false;
		this.onDelete([item.rule]);
	}

	refresh(rules: Rule[]): void {
		this.rules = rules;
		this.confirmingDelete = false;
		this.updateList();
	}

	handleInput(keyData: string): void {
		const kb = getKeybindings();
		if (this.confirmingDelete) {
			if (keyData.toLowerCase() === "y") {
				this.confirmDelete();
			} else if (keyData.toLowerCase() === "n" || kb.matches(keyData, "tui.select.cancel")) {
				this.confirmingDelete = false;
				this.updateList();
			}
			return;
		}
		if (kb.matches(keyData, "tui.select.up") || keyData === "k") {
			this.moveSelection(-1);
		} else if (kb.matches(keyData, "tui.select.down") || keyData === "j") {
			this.moveSelection(1);
		} else if (keyData === "d" || keyData === "\x7f") {
			this.requestDelete();
		} else if (kb.matches(keyData, "tui.select.cancel")) {
			this.onCancel();
		}
	}
}
