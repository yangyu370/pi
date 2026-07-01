import type { Model } from "../types.ts";

export const WHITEPOLAR_MODELS = {
	"gpt-5.5": {
		id: "gpt-5.5",
		name: "GPT-5.5",
		api: "openai-completions",
		provider: "whitepolar",
		baseUrl: "https://whitepolar.app/v1",
		compat: { supportsStore: false, supportsDeveloperRole: true, supportsReasoningEffort: true },
		reasoning: true,
		thinkingLevelMap: { off: "none", minimal: "minimal", low: "low", medium: "medium", high: "high", xhigh: "xhigh" },
		input: ["text", "image"],
		cost: {
			input: 5,
			output: 30,
			cacheRead: 0.5,
			cacheWrite: 0,
		},
		contextWindow: 272000,
		maxTokens: 128000,
	} satisfies Model<"openai-completions">,
} as const;
