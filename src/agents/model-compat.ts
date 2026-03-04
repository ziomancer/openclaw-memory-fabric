import type { Api, Model } from "@mariozechner/pi-ai";

function isOpenAiCompletionsModel(model: Model<Api>): model is Model<"openai-completions"> {
  return model.api === "openai-completions";
}

function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "0.0.0.0" || host === "::1";
}

function isLmStudioEndpoint(provider: string, baseUrl: string): boolean {
  if (provider.trim().toLowerCase() === "lmstudio") {
    return true;
  }

  try {
    const url = new URL(baseUrl);
    return isLoopbackHost(url.hostname.toLowerCase()) && url.port === "1234";
  } catch {
    return /(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]):1234/i.test(baseUrl);
  }
}

function isQwen3FamilyModel(model: Model<Api>): boolean {
  const haystack = `${model.id} ${model.name}`.toLowerCase();
  return haystack.includes("qwen3");
}

/**
 * Returns true only for endpoints that are confirmed to be native OpenAI
 * infrastructure and therefore accept the `developer` message role.
 * Azure OpenAI uses the Chat Completions API and does NOT accept `developer`.
 * All other openai-completions backends (proxies, Qwen, GLM, DeepSeek, etc.)
 * only support the standard `system` role.
 */
function isOpenAINativeEndpoint(baseUrl: string): boolean {
  try {
    const host = new URL(baseUrl).hostname.toLowerCase();
    return host === "api.openai.com";
  } catch {
    return false;
  }
}

function isAnthropicMessagesModel(model: Model<Api>): model is Model<"anthropic-messages"> {
  return model.api === "anthropic-messages";
}

/**
 * pi-ai constructs the Anthropic API endpoint as `${baseUrl}/v1/messages`.
 * If a user configures `baseUrl` with a trailing `/v1` (e.g. the previously
 * recommended format "https://api.anthropic.com/v1"), the resulting URL
 * becomes "…/v1/v1/messages" which the Anthropic API rejects with a 404.
 *
 * Strip a single trailing `/v1` (with optional trailing slash) from the
 * baseUrl for anthropic-messages models so users with either format work.
 */
function normalizeAnthropicBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/v1\/?$/, "");
}
export function normalizeModelCompat(model: Model<Api>): Model<Api> {
  const baseUrl = model.baseUrl ?? "";

  // Normalise anthropic-messages baseUrl: strip trailing /v1 that users may
  // have included in their config. pi-ai appends /v1/messages itself.
  if (isAnthropicMessagesModel(model) && baseUrl) {
    const normalised = normalizeAnthropicBaseUrl(baseUrl);
    if (normalised !== baseUrl) {
      return { ...model, baseUrl: normalised } as Model<"anthropic-messages">;
    }
  }

  if (!isOpenAiCompletionsModel(model)) {
    return model;
  }

  const compat = model.compat ?? undefined;
  const compatPatch: NonNullable<typeof compat> = {};

  if (isLmStudioEndpoint(model.provider, baseUrl) && isQwen3FamilyModel(model)) {
    // LM Studio's OpenAI-compatible chat-completions path expects Qwen-family
    // models to use `max_tokens` and Qwen's enable_thinking flag shape.
    if (compat?.maxTokensField === undefined) {
      compatPatch.maxTokensField = "max_tokens";
    }
    if (compat?.thinkingFormat === undefined) {
      compatPatch.thinkingFormat = "qwen";
    }
  }

  // The `developer` message role is an OpenAI-native convention. All other
  // openai-completions backends (proxies, Qwen, GLM, DeepSeek, Kimi, etc.)
  // only recognise `system`. Force supportsDeveloperRole=false for any model
  // whose baseUrl is not a known native OpenAI endpoint, unless the caller
  // has already pinned the value explicitly.
  // When baseUrl is empty the pi-ai library defaults to api.openai.com, so
  // leave compat unchanged and let the existing default behaviour apply.
  // Note: an explicit supportsDeveloperRole: true is intentionally overridden
  // here for non-native endpoints — those backends would return a 400 if we
  // sent `developer`, so safety takes precedence over the caller's hint.
  const needsForce = baseUrl ? !isOpenAINativeEndpoint(baseUrl) : false;
  if (compat?.supportsDeveloperRole !== false && needsForce) {
    compatPatch.supportsDeveloperRole = false;
  }

  if (Object.keys(compatPatch).length === 0) {
    return model;
  }

  // Return a new object — do not mutate the caller's model reference.
  return { ...model, compat: compat ? { ...compat, ...compatPatch } : compatPatch } as typeof model;
}
