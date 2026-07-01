import { setKeybindings } from "@earendil-works/pi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import type { PermissionApprovalRequest } from "../src/index.ts";
import { ApprovalOverlayComponent } from "../src/modes/interactive/components/approval-overlay.ts";
import { initTheme } from "../src/modes/interactive/theme/theme.ts";
import { stripAnsi } from "../src/utils/ansi.ts";

function makeApprovalRequest(overrides: Partial<PermissionApprovalRequest> = {}): PermissionApprovalRequest {
	return {
		display: {
			toolName: "bash",
			capability: "exec",
			title: "Run: git push origin main",
			detail: "git push origin main --force",
			diffPreview: "+ added line\n- removed line",
			danger: { level: "circuit-breaker", reason: "rm -rf ~ triggered circuit breaker" },
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
		...overrides,
	};
}

describe("ApprovalOverlayComponent", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	beforeEach(() => {
		setKeybindings(new KeybindingsManager());
	});

	it("renders approval details and choices", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest(),
			onSubmit: () => {},
			onCancel: () => {},
		});

		const output = stripAnsi(component.render(120).join("\n"));

		expect(output).toContain("Permission required");
		expect(output).toContain("[exec] Run: git push origin main");
		expect(output).toContain("git push origin main --force");
		expect(output).toContain("rm -rf ~ triggered circuit breaker");
		expect(output).toContain("diff");
		expect(output).toContain("+ added line");
		expect(output).toContain("Always allow git push *");
		expect(output).toContain("Deny");
	});

	it("hides always allow options when no choices are available", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({ alwaysAllowChoices: [] }),
			onSubmit: () => {},
			onCancel: () => {},
		});

		const output = stripAnsi(component.render(120).join("\n"));

		expect(output).toContain("Allow once");
		expect(output).not.toContain("Always allow");
		expect(output).toContain("Deny");
	});

	it("shows hidden rule counts for multi-rule choices", () => {
		const request = makeApprovalRequest({
			alwaysAllowChoices: [
				{
					id: "compound",
					label: "Always allow 6 command rules",
					rules: Array.from({ length: 6 }, (_, index) => ({
						raw: `bash(command-${index + 1} *)`,
						tool: "bash",
						specifier: `command-${index + 1} *`,
						list: "allow",
						scope: "project-local",
					})),
				},
			],
		});
		const component = new ApprovalOverlayComponent({
			request,
			onSubmit: () => {},
			onCancel: () => {},
		});

		component.handleInput("\x1b[B");
		const output = stripAnsi(component.render(120).join("\n"));

		expect(output).toContain("bash(command-1 *)");
		expect(output).toContain("5 more rules will also be saved");
		expect(output).not.toContain("bash(command-2 *)");
	});

	it("bounds long request previews so decision controls remain visible", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({
				display: {
					toolName: "edit",
					capability: "mutate",
					title: "Edit src/file.ts",
					detail: [
						`detail 1 ${"x".repeat(500)}`,
						...Array.from({ length: 9 }, (_, index) => `detail ${index + 2}`),
					].join("\n"),
					diffPreview: [
						`diff 1 ${"x".repeat(500)}`,
						...Array.from({ length: 19 }, (_, index) => `diff ${index + 2}`),
					].join("\n"),
				},
			}),
			onSubmit: () => {},
			onCancel: () => {},
		});

		const renderedLines = component.render(80).map(stripAnsi);
		const output = renderedLines.join("\n");

		expect(output).toContain("8 more detail lines hidden");
		expect(output).toContain("17 more diff lines hidden");
		expect(output).toContain("Allow once");
		expect(output).toContain("Always allow git push *");
		expect(output).toContain("Deny");
		expect(renderedLines.findIndex((line) => line.includes("Deny"))).toBeLessThan(24);
		expect(output).not.toContain("detail 10");
		expect(output).not.toContain("diff 20");
	});

	it("keeps controls visible with long previews and a multi-rule selected choice", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({
				display: {
					toolName: "bash",
					capability: "exec",
					title: "Run compound command",
					detail: [
						`detail 1 ${"x".repeat(500)}`,
						...Array.from({ length: 9 }, (_, index) => `detail ${index + 2}`),
					].join("\n"),
					danger: { level: "sensitive", reason: `warning ${"x".repeat(500)}` },
					diffPreview: [
						`diff 1 ${"x".repeat(500)}`,
						...Array.from({ length: 19 }, (_, index) => `diff ${index + 2}`),
					].join("\n"),
				},
				alwaysAllowChoices: [
					{
						id: "compound",
						label: "Always allow 6 command rules",
						rules: Array.from({ length: 6 }, (_, index) => ({
							raw: `bash(command-${index + 1} *)`,
							tool: "bash",
							specifier: `command-${index + 1} *`,
							list: "allow",
							scope: "project-local",
						})),
					},
				],
			}),
			onSubmit: () => {},
			onCancel: () => {},
		});

		component.handleInput("\x1b[B");
		const renderedLines = component.render(80).map(stripAnsi);

		expect(renderedLines.findIndex((line) => line.includes("Deny"))).toBeLessThan(24);
		expect(renderedLines.findIndex((line) => line.includes("enter confirm"))).toBeLessThan(24);
	});

	it("submits allow once by default", () => {
		const onSubmit = vi.fn();
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest(),
			onSubmit,
			onCancel: () => {},
		});

		component.handleInput("\r");

		expect(onSubmit).toHaveBeenCalledWith({ type: "allow-once" });
	});

	it("submits the selected always allow choice", () => {
		const onSubmit = vi.fn();
		const request = makeApprovalRequest();
		const component = new ApprovalOverlayComponent({
			request,
			onSubmit,
			onCancel: () => {},
		});

		component.handleInput("\x1b[B");
		component.handleInput("\r");

		expect(onSubmit).toHaveBeenCalledWith({
			type: "always-allow",
			rules: request.alwaysAllowChoices[0]?.rules,
		});
	});

	it("submits deny on deny selection and cancels on escape", () => {
		const onSubmit = vi.fn();
		const onCancel = vi.fn();
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest(),
			onSubmit,
			onCancel,
		});

		component.handleInput("\x1b[B");
		component.handleInput("\x1b[B");
		component.handleInput("\r");
		component.handleInput("\x1b");

		expect(onSubmit).toHaveBeenCalledWith({ type: "deny", reason: "Denied by user" });
		expect(onCancel).toHaveBeenCalledOnce();
	});
});
