import { Container, getKeybindings, Spacer, Text, TruncatedText } from "@earendil-works/pi-tui";
import type { PermissionApprovalOutcome, PermissionApprovalRequest } from "../../../core/permissions/index.ts";
import { theme } from "../theme/theme.ts";
import { DynamicBorder } from "./dynamic-border.ts";
import { keyHint, rawKeyHint } from "./keybinding-hints.ts";

const DENY_REASON = "Denied by user";
const MAX_DETAIL_LINES = 2;
const MAX_DANGER_LINES = 1;
const MAX_DIFF_LINES = 3;
const MAX_RULE_LINES = 1;

export interface ApprovalOption {
	label: string;
	outcome: PermissionApprovalOutcome;
}

export interface ApprovalOverlayOptions {
	request: PermissionApprovalRequest;
	onSubmit: (outcome: PermissionApprovalOutcome) => void;
	onCancel: () => void;
}

export function buildApprovalOptions(request: PermissionApprovalRequest): ApprovalOption[] {
	const options: ApprovalOption[] = [{ label: "Allow once", outcome: { type: "allow-once" } }];
	for (const choice of request.alwaysAllowChoices) {
		const count = choice.rules.length;
		const label = count > 1 ? `${choice.label} (${count} rules)` : choice.label;
		options.push({ label, outcome: { type: "always-allow", rules: choice.rules } });
	}
	options.push({ label: "Deny", outcome: { type: "deny", reason: DENY_REASON } });
	return options;
}

export function buildApprovalLines(request: PermissionApprovalRequest): string[] {
	const { display } = request;
	const lines = [`[${display.capability}] ${display.title}`];
	if (display.detail.length > 0) {
		lines.push(...truncatePreview(display.detail, MAX_DETAIL_LINES, "detail"));
	}
	if (display.danger) {
		const label = display.danger.level === "circuit-breaker" ? "CIRCUIT BREAKER" : "Warning";
		lines.push(...truncatePreview(`${label}: ${display.danger.reason}`, MAX_DANGER_LINES, "warning"));
	}
	if (display.diffPreview !== undefined && display.diffPreview.length > 0) {
		lines.push("diff");
		lines.push(...truncatePreview(display.diffPreview, MAX_DIFF_LINES, "diff"));
	}
	return lines;
}

function truncatePreview(text: string, maxLines: number, label: string): string[] {
	const lines = text.split("\n");
	const shown = lines.slice(0, maxLines);
	const hiddenCount = lines.length - maxLines;
	if (hiddenCount > 0) {
		const suffix = label === "diff" ? "; more lines hidden" : "";
		shown.push(`${hiddenCount} more ${label} lines hidden${suffix}`);
	}
	return shown;
}

export class ApprovalOverlayComponent extends Container {
	private readonly request: PermissionApprovalRequest;
	private readonly options: ApprovalOption[];
	private readonly lines: string[];
	private readonly onSubmit: (outcome: PermissionApprovalOutcome) => void;
	private readonly onCancel: () => void;
	private selectedIndex = 0;

	constructor(options: ApprovalOverlayOptions) {
		super();
		this.request = options.request;
		this.onSubmit = options.onSubmit;
		this.onCancel = options.onCancel;
		this.options = buildApprovalOptions(options.request);
		this.lines = buildApprovalLines(options.request);
		this.update();
	}

	private update(): void {
		this.clear();
		this.selectedIndex = Math.max(0, Math.min(this.options.length - 1, this.selectedIndex));

		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new Text(theme.fg("accent", theme.bold("Permission required")), 1, 0));
		this.addChild(new Spacer(1));

		for (const line of this.lines) {
			const isDanger = line.startsWith("CIRCUIT BREAKER:") || line.startsWith("Warning:");
			const color = isDanger || this.request.display.danger?.level === "circuit-breaker" ? "error" : "text";
			this.addChild(new TruncatedText(theme.fg(color, line), 1, 0));
		}

		this.addChild(new Spacer(1));
		for (let i = 0; i < this.options.length; i++) {
			const option = this.options[i];
			const selected = i === this.selectedIndex;
			const prefix = selected ? theme.fg("accent", "> ") : "  ";
			const label = selected ? theme.fg("accent", option.label) : theme.fg("text", option.label);
			this.addChild(new TruncatedText(`${prefix}${label}`, 1, 0));

			if (selected && option.outcome.type === "always-allow" && option.outcome.rules.length > 1) {
				for (const rule of option.outcome.rules.slice(0, MAX_RULE_LINES)) {
					this.addChild(new TruncatedText(theme.fg("muted", `    ${rule.raw}`), 1, 0));
				}
				const hiddenCount = option.outcome.rules.length - MAX_RULE_LINES;
				if (hiddenCount > 0) {
					this.addChild(
						new TruncatedText(
							theme.fg(
								"muted",
								`    ${hiddenCount} more rule${hiddenCount === 1 ? "" : "s"} will also be saved`,
							),
							1,
							0,
						),
					);
				}
			}
		}

		this.addChild(new Spacer(1));
		this.addChild(
			new Text(
				`${rawKeyHint("up/down", "navigate")}  ${keyHint("tui.select.confirm", "confirm")}  ${keyHint("tui.select.cancel", "deny")}`,
				1,
				0,
			),
		);
		this.addChild(new Spacer(1));
		this.addChild(new DynamicBorder());
	}

	private moveSelection(delta: number): void {
		const next = Math.max(0, Math.min(this.options.length - 1, this.selectedIndex + delta));
		if (next !== this.selectedIndex) {
			this.selectedIndex = next;
			this.update();
		}
	}

	handleInput(keyData: string): void {
		const kb = getKeybindings();
		if (kb.matches(keyData, "tui.select.up") || keyData === "k") {
			this.moveSelection(-1);
		} else if (kb.matches(keyData, "tui.select.down") || keyData === "j") {
			this.moveSelection(1);
		} else if (kb.matches(keyData, "tui.select.confirm") || keyData === "\n" || keyData === "\r") {
			const selected = this.options[this.selectedIndex];
			if (selected) {
				this.onSubmit(selected.outcome);
			}
		} else if (kb.matches(keyData, "tui.select.cancel")) {
			this.onCancel();
		}
	}
}
