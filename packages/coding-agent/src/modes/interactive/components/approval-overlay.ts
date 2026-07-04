import { Container, getKeybindings, Spacer, Text, TruncatedText } from "@earendil-works/pi-tui";
import type { PermissionApprovalOutcome, PermissionApprovalRequest } from "../../../core/permissions/index.ts";
import type { ThemeColor } from "../theme/theme.ts";
import { theme } from "../theme/theme.ts";
import { renderDiff } from "./diff.ts";
import { DynamicBorder } from "./dynamic-border.ts";
import { keyHint, keyText, rawKeyHint } from "./keybinding-hints.ts";

const DENY_REASON = "Denied by user";
const MAX_DETAIL_LINES = 2;
const MAX_DANGER_LINES = 1;
const COLLAPSED_DIFF_LINES = 3;
const OVERLAY_CHROME_ROWS = 18;
const FALLBACK_TERMINAL_ROWS = 24;
const DENY_LABEL = "No, tell pi what to do differently";
const DECISION_GRACE_MS = 250;

type OverlayState = "choosing" | "typing-deny-reason";
type ApprovalLineTone = "title" | "resource" | "text" | "danger" | "diff";

interface ApprovalLine {
	text: string;
	tone: ApprovalLineTone;
}

export interface ApprovalOption {
	label: string;
	outcome: PermissionApprovalOutcome;
}

export interface ApprovalOverlayOptions {
	request: PermissionApprovalRequest;
	onSubmit: (outcome: PermissionApprovalOutcome) => void;
	onCancel: () => void;
	terminalRows?: () => number;
	now?: () => number;
}

export function buildApprovalOptions(request: PermissionApprovalRequest): ApprovalOption[] {
	const options: ApprovalOption[] = [{ label: "Yes", outcome: { type: "allow-once" } }];
	for (const choice of request.alwaysAllowChoices) {
		const count = choice.rules.length;
		const label = count > 1 ? `${choice.label} (${count} rules)` : choice.label;
		options.push({ label, outcome: { type: "always-allow", rules: choice.rules } });
	}
	options.push({ label: DENY_LABEL, outcome: { type: "deny", reason: DENY_REASON } });
	return options;
}

export function buildApprovalLines(
	request: PermissionApprovalRequest,
	options: { expandedDiff?: boolean; terminalRows?: number } = {},
): string[] {
	return buildApprovalLineItems(request, options).map((line) => line.text);
}

function buildApprovalLineItems(
	request: PermissionApprovalRequest,
	options: { expandedDiff?: boolean; terminalRows?: number } = {},
): ApprovalLine[] {
	const { display } = request;
	const lines: ApprovalLine[] = [
		{ text: capabilityTitle(request), tone: "title" },
		{ text: display.title, tone: "resource" },
	];
	if (display.detail.length > 0) {
		lines.push(
			...truncatePreview(display.detail, MAX_DETAIL_LINES, "detail").map((text) => ({
				text,
				tone: "text" as const,
			})),
		);
	}
	if (display.diffPreview !== undefined && display.diffPreview.length > 0) {
		const renderedDiff = renderDiff(display.diffPreview);
		lines.push(
			...truncateDiff(renderedDiff, options.expandedDiff ?? false, options.terminalRows).map((text) => ({
				text,
				tone: "diff" as const,
			})),
		);
		if (display.diffTruncated) {
			lines.push({ text: "Diff preview truncated by core size limit.", tone: "danger" });
		}
	}
	if (display.danger) {
		const label = display.danger.level === "circuit-breaker" ? "CIRCUIT BREAKER" : "Warning";
		lines.push(
			...truncatePreview(`${label}: ${display.danger.reason}`, MAX_DANGER_LINES, "warning").map((text) => ({
				text,
				tone: "danger" as const,
			})),
		);
	}
	return lines;
}

function truncatePreview(text: string, maxLines: number, label: string): string[] {
	const lines = text.split("\n");
	const shown = lines.slice(0, maxLines);
	const hiddenCount = lines.length - maxLines;
	if (hiddenCount > 0) {
		shown.push(`... +${hiddenCount} ${label} lines`);
	}
	return shown;
}

function truncateDiff(text: string, expanded: boolean, terminalRows: number | undefined): string[] {
	const lines = text.split("\n");
	const toggleKey = keyText("app.permission.diff.toggle") || "ctrl+e";
	if (expanded) {
		const budget = Math.max(COLLAPSED_DIFF_LINES, (terminalRows ?? FALLBACK_TERMINAL_ROWS) - OVERLAY_CHROME_ROWS);
		if (lines.length <= budget) {
			return [...lines, `(${toggleKey} to collapse)`];
		}
		return [...lines.slice(0, budget), `... +${lines.length - budget} lines (${toggleKey} to collapse)`];
	}
	if (lines.length <= COLLAPSED_DIFF_LINES) {
		return lines;
	}
	return [
		...lines.slice(0, COLLAPSED_DIFF_LINES),
		`... +${lines.length - COLLAPSED_DIFF_LINES} lines (${toggleKey} to expand)`,
	];
}

function capabilityTitle(request: PermissionApprovalRequest): string {
	const { display } = request;
	if (display.capability === "exec") {
		return "Run command";
	}
	if (display.capability === "mutate") {
		return display.toolName === "write" ? "Write file" : "Edit file";
	}
	return "Read";
}

function capabilityQuestion(request: PermissionApprovalRequest): string {
	const { capability } = request.display;
	if (capability === "exec") {
		return "Do you want to run this command?";
	}
	if (capability === "mutate") {
		return "Do you want to make this edit?";
	}
	return "Do you want to read this?";
}

function isPrintableInput(keyData: string): boolean {
	if (keyData.length === 0) {
		return false;
	}
	for (const char of keyData) {
		if (char < " " || char === "\x7f") {
			return false;
		}
	}
	return true;
}

export class ApprovalOverlayComponent extends Container {
	private readonly request: PermissionApprovalRequest;
	private readonly options: ApprovalOption[];
	private readonly onSubmit: (outcome: PermissionApprovalOutcome) => void;
	private readonly onCancel: () => void;
	private selectedIndex = 0;
	private state: OverlayState = "choosing";
	private denyReason = "";
	private expandedDiff = false;
	private readonly terminalRows: (() => number) | undefined;
	private readonly hasDiff: boolean;
	private readonly now: () => number;
	private readonly openedAt: number;
	private ignoredDecisionInput = false;

	constructor(options: ApprovalOverlayOptions) {
		super();
		this.request = options.request;
		this.onSubmit = options.onSubmit;
		this.onCancel = options.onCancel;
		this.terminalRows = options.terminalRows;
		this.now = options.now ?? Date.now;
		this.openedAt = this.now();
		this.hasDiff = (options.request.display.diffPreview?.length ?? 0) > 0;
		this.options = buildApprovalOptions(options.request);
		this.update();
	}

	private update(): void {
		this.clear();
		this.selectedIndex = Math.max(0, Math.min(this.options.length - 1, this.selectedIndex));

		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new Text(theme.fg("accent", theme.bold("Permission required")), 1, 0));
		this.addChild(new Spacer(1));

		const lines = buildApprovalLineItems(this.request, {
			expandedDiff: this.expandedDiff,
			terminalRows: this.terminalRows?.(),
		});
		for (const line of lines) {
			this.addChild(new TruncatedText(this.formatLine(line), 1, 0));
		}

		this.addChild(new Spacer(1));
		if (this.state === "typing-deny-reason") {
			this.renderDenyReasonInput();
		} else {
			this.renderChoices();
		}
		this.addChild(new Spacer(1));
		this.addChild(new DynamicBorder());
	}

	private formatLine(line: ApprovalLine): string {
		if (line.tone === "diff") {
			return line.text;
		}
		let color: ThemeColor;
		if (line.tone === "title" && this.request.display.danger?.level === "circuit-breaker") {
			color = "error";
		} else if (line.tone === "title") {
			color = "accent";
		} else if (line.tone === "resource") {
			color = "muted";
		} else if (line.tone === "danger") {
			color = "error";
		} else {
			color = "text";
		}
		const text = line.tone === "title" ? theme.bold(line.text) : line.text;
		return theme.fg(color, text);
	}

	private renderChoices(): void {
		this.addChild(new Text(theme.fg("text", capabilityQuestion(this.request)), 1, 0));
		for (let i = 0; i < this.options.length; i++) {
			const option = this.options[i];
			const selected = i === this.selectedIndex;
			const prefix = selected ? theme.fg("accent", `> ${i + 1}. `) : `  ${i + 1}. `;
			const label = selected ? theme.fg("accent", option.label) : theme.fg("text", option.label);
			this.addChild(new TruncatedText(`${prefix}${label}`, 1, 0));

			if (selected && option.outcome.type === "always-allow") {
				for (const rule of option.outcome.rules) {
					this.addChild(new TruncatedText(theme.fg("muted", `    ${rule.raw}`), 1, 0));
				}
			}
		}

		this.addChild(new Spacer(1));
		if (this.ignoredDecisionInput) {
			this.addChild(new Text(theme.fg("warning", "Decision input ignored; try again."), 1, 0));
		}
		const diffHint = this.hasDiff ? `  ${keyHint("app.permission.diff.toggle", "diff")}` : "";
		this.addChild(
			new Text(
				`${rawKeyHint("up/down", "navigate")}  ${rawKeyHint(`1-${this.options.length}`, "choose")}  ${keyHint("tui.select.confirm", "confirm")}  ${keyHint("tui.select.cancel", "deny")}${diffHint}`,
				1,
				0,
			),
		);
	}

	private renderDenyReasonInput(): void {
		this.addChild(new Text(theme.fg("text", "Tell pi what to do differently:"), 1, 0));
		this.addChild(new TruncatedText(`${theme.fg("accent", "> ")}${theme.fg("text", this.denyReason)}`, 1, 0));
		this.addChild(new Spacer(1));
		this.addChild(
			new Text(`${keyHint("tui.select.confirm", "submit")}  ${keyHint("tui.select.cancel", "back")}`, 1, 0),
		);
	}

	private moveSelection(delta: number): void {
		const next = Math.max(0, Math.min(this.options.length - 1, this.selectedIndex + delta));
		if (next !== this.selectedIndex) {
			this.selectedIndex = next;
			this.update();
		}
	}

	private confirmSelected(): void {
		const selected = this.options[this.selectedIndex];
		if (!selected) return;
		if (selected.outcome.type === "deny") {
			this.state = "typing-deny-reason";
			this.denyReason = "";
			this.update();
			return;
		}
		this.onSubmit(selected.outcome);
	}

	private submitDenyReason(): void {
		const reason = this.denyReason.trim();
		this.onSubmit({ type: "deny", reason: reason.length > 0 ? reason : DENY_REASON });
	}

	private isWithinDecisionGracePeriod(): boolean {
		return this.now() - this.openedAt < DECISION_GRACE_MS;
	}

	private ignoreDecisionInput(): void {
		this.ignoredDecisionInput = true;
		this.update();
	}

	private handleDenyReasonInput(keyData: string): void {
		const kb = getKeybindings();
		if (kb.matches(keyData, "tui.select.cancel")) {
			this.state = "choosing";
			this.update();
		} else if (kb.matches(keyData, "tui.select.confirm") || keyData === "\n" || keyData === "\r") {
			this.submitDenyReason();
		} else if (keyData === "\x7f" || keyData === "\b") {
			this.denyReason = this.denyReason.slice(0, -1);
			this.update();
		} else if (isPrintableInput(keyData)) {
			this.denyReason += keyData;
			this.update();
		}
	}

	handleInput(keyData: string): void {
		const kb = getKeybindings();
		if (this.hasDiff && kb.matches(keyData, "app.permission.diff.toggle")) {
			this.expandedDiff = !this.expandedDiff;
			this.update();
		} else if (this.state === "typing-deny-reason") {
			this.handleDenyReasonInput(keyData);
		} else if (kb.matches(keyData, "tui.select.up") || keyData === "k") {
			this.moveSelection(-1);
		} else if (kb.matches(keyData, "tui.select.down") || keyData === "j") {
			this.moveSelection(1);
		} else if (kb.matches(keyData, "tui.select.confirm") || keyData === "\n" || keyData === "\r") {
			if (this.isWithinDecisionGracePeriod()) {
				this.ignoreDecisionInput();
				return;
			}
			this.confirmSelected();
		} else if (/^[1-9]$/.test(keyData)) {
			if (this.isWithinDecisionGracePeriod()) {
				this.ignoreDecisionInput();
				return;
			}
			const index = Number.parseInt(keyData, 10) - 1;
			if (index >= 0 && index < this.options.length) {
				this.selectedIndex = index;
				this.confirmSelected();
			}
		} else if (kb.matches(keyData, "tui.select.cancel")) {
			if (this.isWithinDecisionGracePeriod()) {
				this.ignoreDecisionInput();
				return;
			}
			this.onCancel();
		}
	}
}
