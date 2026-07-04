import { openAICompletionsApi } from "../api/openai-completions.lazy.ts";
import { envApiKeyAuth } from "../auth/helpers.ts";
import { createProvider, type Provider } from "../models.ts";
import { WHITEPOLAR_MODELS } from "./whitepolar.models.ts";

export function whitepolarProvider(): Provider<"openai-completions"> {
	return createProvider({
		id: "whitepolar",
		name: "白极 (Whitepolar)",
		baseUrl: "https://whitepolar.app/v1",
		auth: { apiKey: envApiKeyAuth("Whitepolar API key", ["WHITEPOLAR_API_KEY"]) },
		models: Object.values(WHITEPOLAR_MODELS),
		api: openAICompletionsApi(),
	});
}
