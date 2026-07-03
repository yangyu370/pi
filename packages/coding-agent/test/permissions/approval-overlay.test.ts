import { describe, expect, it } from "vitest";
import type { SuggestedRule } from "../../src/core/permissions/index.ts";
import { buildApprovalLines, buildApprovalOptions } from "../../src/modes/interactive/components/approval-overlay.ts";
import { makeApprovalRequest } from "./approval-fixtures.ts";

describe("buildApprovalOptions", () => {
	it("orders Allow once, each choice, then Deny with the right outcomes", () => {
		const options = buildApprovalOptions(makeApprovalRequest());
		expect(options.map((o) => o.label)).toEqual(["Allow once", "Always allow git push *", "Deny"]);
		expect(options[0].outcome).toEqual({ type: "allow-once" });
		expect(options[1].outcome).toEqual({
			type: "always-allow",
			rules: [
				{ raw: "bash(git push *)", tool: "bash", specifier: "git push *", list: "allow", scope: "project-local" },
			],
		});
		expect(options[2].outcome).toEqual({ type: "deny", reason: "Denied by user" });
	});

	it("omits always-allow options when there are no choices", () => {
		const request = makeApprovalRequest();
		request.alwaysAllowChoices = [];
		expect(buildApprovalOptions(request).map((o) => o.label)).toEqual(["Allow once", "Deny"]);
	});

	it("reflects the rule count in a multi-rule choice label", () => {
		const rules: SuggestedRule[] = [
			{ raw: "bash(a)", tool: "bash", specifier: "a", list: "allow", scope: "project-local" },
			{ raw: "bash(b)", tool: "bash", specifier: "b", list: "allow", scope: "project-local" },
		];
		const request = makeApprovalRequest();
		request.alwaysAllowChoices = [{ id: "multi", label: "Always allow", rules }];
		const options = buildApprovalOptions(request);
		expect(options[1].label).toContain("2");
		expect(options[1].outcome).toEqual({ type: "always-allow", rules });
	});
});

describe("buildApprovalLines", () => {
	it("includes a capability badge, the title, and the detail", () => {
		const lines = buildApprovalLines(makeApprovalRequest());
		expect(lines[0]).toContain("[exec]");
		expect(lines[0]).toContain("Run: git push");
		expect(lines).toContain("git push");
	});

	it("includes the danger reason when present", () => {
		const lines = buildApprovalLines(
			makeApprovalRequest({ danger: { level: "circuit-breaker", reason: "rm -rf ~ tripped the circuit breaker" } }),
		);
		expect(lines.some((l) => l.includes("rm -rf ~ tripped the circuit breaker"))).toBe(true);
	});

	it("truncates a long diff preview", () => {
		const diffPreview = Array.from({ length: 40 }, (_, i) => `+ line ${i}`).join("\n");
		const lines = buildApprovalLines(makeApprovalRequest({ diffPreview }));
		expect(lines.some((l) => l.includes("more lines"))).toBe(true);
	});
});
