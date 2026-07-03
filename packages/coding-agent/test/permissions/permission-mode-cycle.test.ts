import { describe, expect, it } from "vitest";
import { nextPermissionModeForCycle } from "../../src/modes/interactive/permission-mode-cycle.ts";

describe("nextPermissionModeForCycle", () => {
	it("cycles default, acceptEdits, and plan", () => {
		expect(nextPermissionModeForCycle("default")).toBe("acceptEdits");
		expect(nextPermissionModeForCycle("acceptEdits")).toBe("plan");
		expect(nextPermissionModeForCycle("plan")).toBe("default");
	});

	it("leaves dangerous modes by returning default", () => {
		expect(nextPermissionModeForCycle("dontAsk")).toBe("default");
		expect(nextPermissionModeForCycle("bypass")).toBe("default");
	});
});
