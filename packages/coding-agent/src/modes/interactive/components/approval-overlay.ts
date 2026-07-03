import { Container, getKeybindings, Spacer, Text } from "@earendil-works/pi-tui";
import type { PermissionApprovalOutcome, PermissionApprovalRequest } from "../../../core/permissions/index.ts";
import { theme } from "../theme/theme.ts";
import { DynamicBorder } from "./dynamic-border.ts";
import { keyHint, rawKeyHint } from "./keybinding-hints.ts";

const DENY_REASON = "Denied by user";
const MAX_DIFF_LINES = 20;
const MAX_RULE_LINES = 5;

export interface ApprovalOption {
	label: string;
	outcome: PermissionApprovalOutcome;
}

export interface ApprovalOverlayOptions {
	request: PermissionApprovalRequest;
	onSubmit: (outcome: PermissionApprovalOutcome) => void;
	onCancel: () => void;
}

/**
 * Ordered options for the overlay. Render order and the Enter→outcome mapping
 * are the same list, so the component can index straight into it.
 */
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

/** Unstyled display lines for the request (title with capability badge, detail, danger, diff). */
export function buildApprovalLines(request: PermissionApprovalRequest): string[] {
	const { display } = request;
	const lines = [`[${display.capability}] ${display.title}`];
	if (display.detail) lines.push(display.detail);
	if (display.danger) {
		const marker = display.danger.level === "circuit-breaker" ? "⚠ CIRCUIT BREAKER" : "⚠";
		lines.push(`${marker}: ${display.danger.reason}`);
	}
	if (display.diffPreview) {
		lines.push("── diff ──");
		lines.push(...truncateDiff(display.diffPreview));
	}
	return lines;
}

function truncateDiff(diff: string): string[] {
	const all = diff.split("\n");
	if (all.length <= MAX_DIFF_LINES) return all;
	const shown = all.slice(0, MAX_DIFF_LINES);
	shown.push(`… (${all.length - MAX_DIFF_LINES} more lines)`);
	return shown;
}

/** Single-step approval prompt: renders the request and reports the chosen outcome. Holds no permission logic. */
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
		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new Text(theme.fg("accent", theme.bold("Permission required")), 1, 0));
		this.addChild(new Spacer(1));

		const danger = this.request.display.danger;
		for (const line of this.lines) {
			const isDanger = danger !== undefined && line.startsWith("⚠");
			const styled =
				isDanger && danger?.level === "circuit-breaker"
					? theme.bold(theme.fg("error", line))
					: theme.fg(isDanger ? "error" : "text", line);
			this.addChild(new Text(styled, 1, 0));
		}
		this.addChild(new Spacer(1));

		for (let i = 0; i < this.options.length; i++) {
			const option = this.options[i];
			const selected = i === this.selectedIndex;
			const prefix = selected ? theme.fg("accent", "→ ") : "  ";
			const label = selected ? theme.fg("accent", option.label) : theme.fg("text", option.label);
			this.addChild(new Text(`${prefix}${label}`, 1, 0));
			if (option.outcome.type === "always-allow" && option.outcome.rules.length > 1) {
				for (const rule of option.outcome.rules.slice(0, MAX_RULE_LINES)) {
					this.addChild(new Text(theme.fg("muted", `    ${rule.raw}`), 1, 0));
				}
			}
		}

		this.addChild(new Spacer(1));
		this.addChild(
			new Text(
				`${rawKeyHint("↑↓", "navigate")}  ${keyHint("tui.select.confirm", "confirm")}  ${keyHint("tui.select.cancel", "deny")}`,
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
		} else if (kb.matches(keyData, "tui.select.confirm") || keyData === "\n") {
			this.onSubmit(this.options[this.selectedIndex].outcome);
		} else if (kb.matches(keyData, "tui.select.cancel")) {
			this.onCancel();
		}
	}
}
