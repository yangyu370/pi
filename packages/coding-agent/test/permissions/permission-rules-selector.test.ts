import { setKeybindings } from "@earendil-works/pi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../../src/core/keybindings.ts";
import type { Rule } from "../../src/core/permissions/index.ts";
import { PermissionRulesSelectorComponent } from "../../src/modes/interactive/components/permission-rules-selector.ts";
import { initTheme } from "../../src/modes/interactive/theme/theme.ts";
import { stripAnsi } from "../../src/utils/ansi.ts";

const rule = (scope: Rule["scope"], raw: string): Rule => ({
	raw,
	tool: raw.slice(0, raw.indexOf("(")),
	specifier: raw.slice(raw.indexOf("(") + 1, -1),
	list: "allow",
	scope,
});

describe("PermissionRulesSelectorComponent", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	beforeEach(() => {
		setKeybindings(new KeybindingsManager());
	});

	it("groups all effective rules by scope and marks non-project scopes read-only", () => {
		const selector = new PermissionRulesSelectorComponent({
			projectPath: "/repo",
			rules: [
				rule("session", "bash(session *)"),
				rule("cli", "bash(cli *)"),
				rule("project-local", "bash(project *)"),
				rule("user", "bash(user *)"),
			],
			onDelete: () => {},
			onCancel: () => {},
		});

		const output = stripAnsi(selector.render(120).join("\n"));

		expect(output).toContain("Permission rules - /repo");
		expect(output).toContain("session");
		expect(output).toContain("cli (--allow)");
		expect(output).toContain("project-local");
		expect(output).toContain("user");
		expect(output).toContain("allow bash(project *)");
		expect(output).toContain("allow bash(cli *) (read-only here)");
		expect(output).toContain("allow bash(user *) (read-only here)");
		expect(output).toContain("allow bash(session *) (read-only here)");
	});

	it("confirms before deleting a project-local rule", () => {
		const onDelete = vi.fn();
		const selector = new PermissionRulesSelectorComponent({
			projectPath: "/repo",
			rules: [rule("project-local", "bash(project *)")],
			onDelete,
			onCancel: () => {},
		});

		selector.handleInput("d");
		expect(stripAnsi(selector.render(120).join("\n"))).toContain("delete? (y/n)");
		expect(onDelete).not.toHaveBeenCalled();

		selector.handleInput("y");

		expect(onDelete).toHaveBeenCalledWith([rule("project-local", "bash(project *)")]);
	});

	it("does not delete read-only rules", () => {
		const onDelete = vi.fn();
		const selector = new PermissionRulesSelectorComponent({
			projectPath: "/repo",
			rules: [rule("cli", "bash(cli *)")],
			onDelete,
			onCancel: () => {},
		});

		selector.handleInput("d");
		selector.handleInput("y");

		expect(onDelete).not.toHaveBeenCalled();
		expect(stripAnsi(selector.render(120).join("\n"))).toContain("read-only here");
	});
});
