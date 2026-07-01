import { Container, getKeybindings, Spacer, Text, TruncatedText } from "@earendil-works/pi-tui";
import type {
	AlwaysAllowChoice,
	PermissionApprovalOutcome,
	PermissionApprovalRequest,
} from "../../../core/permissions/index.ts";
import { theme } from "../theme/theme.ts";
import { DynamicBorder } from "./dynamic-border.ts";
import { keyHint, rawKeyHint } from "./keybinding-hints.ts";

export interface ApprovalOverlayOptions {
	request: PermissionApprovalRequest;
	onSubmit: (outcome: PermissionApprovalOutcome) => void;
	onCancel: () => void;
}

type ApprovalOption =
	| { type: "allow-once"; label: string }
	| { type: "always-allow"; label: string; choice: AlwaysAllowChoice }
	| { type: "deny"; label: string };

const MAX_DETAIL_LINES = 2;
const MAX_DANGER_LINES = 1;
const MAX_DIFF_LINES = 3;
const MAX_RULE_LINES = 1;
export class ApprovalOverlayComponent extends Container {
	private selectedIndex = 0;
	private readonly listContainer: Container;
	private readonly options: ApprovalOverlayOptions;

	constructor(options: ApprovalOverlayOptions) {
		super();
		this.options = options;
		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new Text(theme.fg("accent", theme.bold("Permission required")), 1, 0));
		this.addChild(new Spacer(1));
		this.addRequestDetails();
		this.addChild(new Spacer(1));
		this.listContainer = new Container();
		this.addChild(this.listContainer);
		this.addChild(new Spacer(1));
		this.addChild(
			new Text(
				rawKeyHint("↑↓", "navigate") +
					"  " +
					keyHint("tui.select.confirm", "confirm") +
					"  " +
					keyHint("tui.select.cancel", "deny"),
				1,
				0,
			),
		);
		this.addChild(new Spacer(1));
		this.addChild(new DynamicBorder());
		this.updateList();
	}

	private addRequestDetails(): void {
		const { display } = this.options.request;
		const title = `[${display.capability}] ${display.title}`;
		const titleColor = display.danger?.level === "circuit-breaker" ? "error" : "text";
		this.addChild(new TruncatedText(theme.fg(titleColor, title), 1, 0));
		if (display.detail.length > 0) {
			this.addPreviewText(display.detail, MAX_DETAIL_LINES, "detail", "muted");
		}
		if (display.danger) {
			this.addPreviewText(display.danger.reason, MAX_DANGER_LINES, "warning", "error");
		}
		if (display.diffPreview !== undefined && display.diffPreview.length > 0) {
			this.addChild(new Text(theme.fg("muted", "diff"), 1, 0));
			this.addPreviewText(display.diffPreview, MAX_DIFF_LINES, "diff", "text");
		}
	}

	private addPreviewText(text: string, maxLines: number, label: string, color: "error" | "muted" | "text"): void {
		const lines = text.split("\n");
		for (const line of lines.slice(0, maxLines)) {
			this.addChild(new TruncatedText(theme.fg(color, line), 1, 0));
		}
		const hiddenCount = lines.length - maxLines;
		if (hiddenCount > 0) {
			this.addChild(new TruncatedText(theme.fg("muted", `${hiddenCount} more ${label} lines hidden`), 1, 0));
		}
	}

	private getApprovalOptions(): ApprovalOption[] {
		return [
			{ type: "allow-once", label: "Allow once" },
			...this.options.request.alwaysAllowChoices.map((choice) => ({
				type: "always-allow" as const,
				label: choice.label,
				choice,
			})),
			{ type: "deny", label: "Deny" },
		];
	}

	private updateList(): void {
		this.listContainer.clear();
		const approvalOptions = this.getApprovalOptions();
		this.selectedIndex = Math.max(0, Math.min(this.selectedIndex, approvalOptions.length - 1));
		for (let i = 0; i < approvalOptions.length; i++) {
			const option = approvalOptions[i];
			if (!option) {
				continue;
			}
			const isSelected = i === this.selectedIndex;
			const prefix = isSelected ? theme.fg("accent", "→ ") : "  ";
			const label = isSelected ? theme.fg("accent", option.label) : theme.fg("text", option.label);
			this.listContainer.addChild(new TruncatedText(`${prefix}${label}`, 1, 0));
			if (option.type === "always-allow" && option.choice.rules.length > 1) {
				this.addChoiceRules(option.choice, isSelected);
			}
		}
	}

	private addChoiceRules(choice: AlwaysAllowChoice, isSelected: boolean): void {
		if (!isSelected) {
			return;
		}
		for (const rule of choice.rules.slice(0, MAX_RULE_LINES)) {
			this.listContainer.addChild(new TruncatedText(theme.fg("muted", `    ${rule.raw}`), 1, 0));
		}
		const hiddenCount = choice.rules.length - MAX_RULE_LINES;
		if (hiddenCount > 0) {
			this.listContainer.addChild(
				new TruncatedText(
					theme.fg("muted", `    ${hiddenCount} more rule${hiddenCount === 1 ? "" : "s"} will also be saved`),
					1,
					0,
				),
			);
		}
	}

	private moveSelection(delta: number): void {
		const optionCount = this.getApprovalOptions().length;
		this.selectedIndex = Math.max(0, Math.min(optionCount - 1, this.selectedIndex + delta));
		this.updateList();
	}

	private submitSelected(): void {
		const selected = this.getApprovalOptions()[this.selectedIndex];
		if (!selected) {
			return;
		}
		if (selected.type === "allow-once") {
			this.options.onSubmit({ type: "allow-once" });
		} else if (selected.type === "always-allow") {
			this.options.onSubmit({ type: "always-allow", rules: selected.choice.rules });
		} else {
			this.options.onSubmit({ type: "deny", reason: "Denied by user" });
		}
	}

	handleInput(keyData: string): void {
		const kb = getKeybindings();
		if (kb.matches(keyData, "tui.select.up")) {
			this.moveSelection(-1);
		} else if (kb.matches(keyData, "tui.select.down")) {
			this.moveSelection(1);
		} else if (kb.matches(keyData, "tui.select.confirm")) {
			this.submitSelected();
		} else if (kb.matches(keyData, "tui.select.cancel")) {
			this.options.onCancel();
		}
	}
}
