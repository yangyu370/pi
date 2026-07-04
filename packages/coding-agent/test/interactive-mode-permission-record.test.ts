import { Container, Spacer, Text } from "@earendil-works/pi-tui";
import { describe, expect, it, vi } from "vitest";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.ts";
import { initTheme } from "../src/modes/interactive/theme/theme.ts";
import { stripAnsi } from "../src/utils/ansi.ts";

interface PermissionRecordHost {
	chatContainer: Container;
	ui: {
		requestRender(): void;
	};
}

describe("InteractiveMode permission records", () => {
	it("appends permission audit lines without replacing prior records", () => {
		initTheme("dark");
		const host: PermissionRecordHost = {
			chatContainer: new Container(),
			ui: { requestRender: vi.fn() },
		};
		const appendPermissionRecord = (
			InteractiveMode.prototype as unknown as {
				appendPermissionRecord(this: PermissionRecordHost, message: string): void;
			}
		).appendPermissionRecord;

		appendPermissionRecord.call(host, "approved: Run: git status");
		appendPermissionRecord.call(host, "denied: Run: git push");

		expect(host.chatContainer.children[0]).toBeInstanceOf(Spacer);
		expect(host.chatContainer.children[1]).toBeInstanceOf(Text);
		expect(host.chatContainer.children[2]).toBeInstanceOf(Spacer);
		expect(host.chatContainer.children[3]).toBeInstanceOf(Text);
		expect(stripAnsi(host.chatContainer.render(120).join("\n"))).toContain("approved: Run: git status");
		expect(stripAnsi(host.chatContainer.render(120).join("\n"))).toContain("denied: Run: git push");
		expect(host.ui.requestRender).toHaveBeenCalledTimes(2);
	});
});
