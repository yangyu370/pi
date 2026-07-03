import { setKeybindings } from "@earendil-works/pi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import type { PermissionApprovalRequest } from "../src/index.ts";
import { ApprovalOverlayComponent } from "../src/modes/interactive/components/approval-overlay.ts";
import { initTheme, theme } from "../src/modes/interactive/theme/theme.ts";
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
		expect(output).toContain("Run command");
		expect(output).toContain("Run: git push origin main");
		expect(output).toContain("git push origin main --force");
		expect(output).toContain("rm -rf ~ triggered circuit breaker");
		expect(output).toContain("+ added line");
		expect(output).toContain("Always allow git push *");
		expect(output).toContain("1. Yes");
		expect(output).toContain("3. No, tell pi what to do differently");
		expect(output).toContain("Do you want to run this command?");
	});

	it("hides always allow options when no choices are available", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({ alwaysAllowChoices: [] }),
			onSubmit: () => {},
			onCancel: () => {},
		});

		const output = stripAnsi(component.render(120).join("\n"));

		expect(output).toContain("Yes");
		expect(output).not.toContain("Always allow");
		expect(output).toContain("No, tell pi what to do differently");
	});

	it("shows every rule for multi-rule choices", () => {
		const request = makeApprovalRequest({
			alwaysAllowChoices: [
				{
					id: "compound",
					label: "Always allow 3 command rules",
					rules: Array.from({ length: 3 }, (_, index) => ({
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
		expect(output).toContain("bash(command-2 *)");
		expect(output).toContain("bash(command-3 *)");
		expect(output).not.toContain("more rules will also be saved");
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

		expect(output).toContain("... +8 detail lines");
		expect(output).toContain("... +17 lines (ctrl+e to expand)");
		expect(output).toContain("Yes");
		expect(output).toContain("Always allow git push *");
		expect(output).toContain("No, tell pi what to do differently");
		expect(renderedLines.findIndex((line) => line.includes("No, tell pi"))).toBeLessThan(24);
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
						label: "Always allow 3 command rules",
						rules: Array.from({ length: 3 }, (_, index) => ({
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

		expect(renderedLines.findIndex((line) => line.includes("No, tell pi"))).toBeLessThan(24);
		expect(renderedLines.findIndex((line) => line.includes("enter confirm"))).toBeLessThan(24);
	});

	it("expands and collapses long diff previews", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({
				display: {
					toolName: "edit",
					capability: "mutate",
					title: "Edit src/file.ts",
					detail: "src/file.ts",
					diffPreview: Array.from({ length: 12 }, (_, index) => `+ ${index + 1} changed`).join("\n"),
				},
			}),
			onSubmit: () => {},
			onCancel: () => {},
			terminalRows: () => 40,
		});

		expect(stripAnsi(component.render(80).join("\n"))).toContain("... +9 lines (ctrl+e to expand)");

		component.handleInput("\x05");
		const expanded = stripAnsi(component.render(80).join("\n"));
		expect(expanded).toContain("+ 12 changed");
		expect(expanded).toContain("(ctrl+e to collapse)");

		component.handleInput("\x05");
		expect(stripAnsi(component.render(80).join("\n"))).toContain("... +9 lines (ctrl+e to expand)");
	});

	it("clamps expanded diffs to the terminal height so controls stay visible", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({
				display: {
					toolName: "edit",
					capability: "mutate",
					title: "Edit src/file.ts",
					detail: "src/file.ts",
					diffPreview: Array.from({ length: 200 }, (_, index) => `+ ${index + 1} changed`).join("\n"),
				},
			}),
			onSubmit: () => {},
			onCancel: () => {},
			terminalRows: () => 30,
		});

		component.handleInput("\x05");
		const expanded = stripAnsi(component.render(80).join("\n"));

		expect(expanded).toContain("+ 12 changed");
		expect(expanded).not.toContain("+ 13 changed");
		expect(expanded).toContain("... +188 lines (ctrl+e to collapse)");
		expect(expanded).toContain("No, tell pi what to do differently");
	});

	it("adapts the numeric hint to the option count and hides the diff hint without a diff", () => {
		const withDiff = new ApprovalOverlayComponent({
			request: makeApprovalRequest(),
			onSubmit: () => {},
			onCancel: () => {},
		});
		const withDiffOutput = stripAnsi(withDiff.render(120).join("\n"));
		expect(withDiffOutput).toContain("1-3 choose");
		expect(withDiffOutput).toContain("diff");

		const noDiff = new ApprovalOverlayComponent({
			request: makeApprovalRequest({
				display: {
					toolName: "bash",
					capability: "exec",
					title: "Run: ls",
					detail: "ls",
				},
				alwaysAllowChoices: [],
			}),
			onSubmit: () => {},
			onCancel: () => {},
		});
		const noDiffOutput = stripAnsi(noDiff.render(120).join("\n"));
		expect(noDiffOutput).toContain("1-2 choose");
		expect(noDiffOutput).not.toContain("to expand");

		noDiff.handleInput("\x05");
		expect(stripAnsi(noDiff.render(120).join("\n"))).toBe(noDiffOutput);
	});

	it("accepts pasted multi-character input in the deny reason", () => {
		const onSubmit = vi.fn();
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest(),
			onSubmit,
			onCancel: () => {},
		});

		component.handleInput("3");
		component.handleInput("use git pull --rebase instead");
		component.handleInput("\r");

		expect(onSubmit).toHaveBeenCalledWith({ type: "deny", reason: "use git pull --rebase instead" });
	});

	it("does not color every circuit-breaker detail line as an error", () => {
		const component = new ApprovalOverlayComponent({
			request: makeApprovalRequest({
				display: {
					toolName: "bash",
					capability: "exec",
					title: "Run: git push origin main",
					detail: "git push origin main",
					danger: { level: "circuit-breaker", reason: "rm -rf ~ triggered circuit breaker" },
				},
			}),
			onSubmit: () => {},
			onCancel: () => {},
		});

		const detailLine = component.render(120).find((line) => stripAnsi(line).includes("git push origin main"));

		expect(detailLine).toBeDefined();
		expect(detailLine).not.toContain(theme.fg("error", "git push origin main"));
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

	it("submits numbered choices without enter", () => {
		const onSubmit = vi.fn();
		const request = makeApprovalRequest();
		const component = new ApprovalOverlayComponent({
			request,
			onSubmit,
			onCancel: () => {},
		});

		component.handleInput("2");

		expect(onSubmit).toHaveBeenCalledWith({
			type: "always-allow",
			rules: request.alwaysAllowChoices[0]?.rules,
		});
	});

	it("collects a deny reason and lets escape return from reason input", () => {
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
		expect(stripAnsi(component.render(120).join("\n"))).toContain("Tell pi what to do differently");

		component.handleInput("\x1b");
		expect(stripAnsi(component.render(120).join("\n"))).toContain("No, tell pi what to do differently");
		expect(onCancel).not.toHaveBeenCalled();

		component.handleInput("\r");
		component.handleInput("u");
		component.handleInput("s");
		component.handleInput("e");
		component.handleInput(" ");
		component.handleInput("r");
		component.handleInput("e");
		component.handleInput("a");
		component.handleInput("d");
		component.handleInput("o");
		component.handleInput("n");
		component.handleInput("l");
		component.handleInput("y");
		component.handleInput("\r");

		expect(onSubmit).toHaveBeenCalledWith({ type: "deny", reason: "use readonly" });
		expect(onCancel).not.toHaveBeenCalled();
	});

	it("submits default deny when reason input is empty and cancels from choices on escape", () => {
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
		component.handleInput("\r");

		expect(onSubmit).toHaveBeenCalledWith({ type: "deny", reason: "Denied by user" });
		expect(onCancel).not.toHaveBeenCalled();

		const escapeComponent = new ApprovalOverlayComponent({
			request: makeApprovalRequest(),
			onSubmit,
			onCancel,
		});
		escapeComponent.handleInput("\x1b");

		expect(onCancel).toHaveBeenCalledOnce();
	});
});
