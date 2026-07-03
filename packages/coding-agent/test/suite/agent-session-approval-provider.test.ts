import { afterEach, describe, expect, it } from "vitest";
import type { PermissionApprovalProvider } from "../../src/index.ts";
import { createHarness, type Harness } from "./harness.ts";

const provider: PermissionApprovalProvider = {
	requestApproval: async () => ({ type: "allow-once" }),
};

describe("AgentSession approval provider", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) {
			harnesses.pop()?.cleanup();
		}
	});

	it("accepts an injected approval provider", async () => {
		const harness = await createHarness({ approvalProvider: provider });
		harnesses.push(harness);

		expect(harness.session.approvalProvider).toBe(provider);
	});

	it("allows the mode layer to replace the approval provider after session creation", async () => {
		const harness = await createHarness();
		harnesses.push(harness);

		harness.session.setApprovalProvider(provider);

		expect(harness.session.approvalProvider).toBe(provider);
	});
});
