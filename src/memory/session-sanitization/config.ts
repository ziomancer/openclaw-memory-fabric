import { resolveSandboxRuntimeStatus } from "../../agents/sandbox/runtime-status.js";
import { parseDurationMs } from "../../cli/parse-duration.js";
import type { OpenClawConfig } from "../../config/config.js";
import { resolveAgentModelPrimaryValue } from "../../config/model-input.js";
import type { AgentModelConfig } from "../../config/types.agents-shared.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { normalizeAgentId } from "../../routing/session-key.js";

const log = createSubsystemLogger("memory/session-sanitization/config");

const DEFAULT_RAW_MAX_AGE = "24h";
const DEFAULT_THINKING = "low";

export type ResolvedSessionSanitizationConfig = {
  enabled: boolean;
  model?: AgentModelConfig;
  thinking: string;
  rawMaxAge: string;
  rawMaxAgeMs: number;
};

export function resolveSessionSanitizationConfig(
  cfg: OpenClawConfig | undefined,
): ResolvedSessionSanitizationConfig {
  const raw = cfg?.memory?.sessions?.sanitization;
  const rawMaxAge = raw?.rawMaxAge?.trim() || DEFAULT_RAW_MAX_AGE;
  let parsedRawMaxAge: number;
  try {
    parsedRawMaxAge = parseDurationMs(rawMaxAge);
  } catch {
    log.warn(`Invalid rawMaxAge value "${rawMaxAge}", falling back to default`, {
      fallback: DEFAULT_RAW_MAX_AGE,
    });
    parsedRawMaxAge = parseDurationMs(DEFAULT_RAW_MAX_AGE);
  }
  return {
    enabled: raw?.enabled === true,
    model: raw?.model ?? cfg?.agents?.defaults?.subagents?.model ?? cfg?.agents?.defaults?.model,
    thinking: raw?.thinking?.trim() || DEFAULT_THINKING,
    rawMaxAge,
    rawMaxAgeMs:
      Number.isFinite(parsedRawMaxAge) && parsedRawMaxAge > 0
        ? parsedRawMaxAge
        : parseDurationMs(DEFAULT_RAW_MAX_AGE),
  };
}

export function buildSessionSanitizationHelperSessionKey(
  agentId: string,
  suffix = "helper",
): string {
  return `agent:${normalizeAgentId(agentId)}:session-memory-${suffix}`;
}

export function resolveSessionSanitizationAvailability(params: {
  cfg?: OpenClawConfig;
  agentId: string;
}): { available: boolean; helperSessionKey: string } {
  const helperSessionKey = buildSessionSanitizationHelperSessionKey(params.agentId);
  const runtime = resolveSandboxRuntimeStatus({
    cfg: params.cfg,
    sessionKey: helperSessionKey,
  });
  return {
    available: runtime.sandboxed,
    helperSessionKey,
  };
}

export function hasConfiguredSessionSanitizationModel(cfg?: OpenClawConfig): boolean {
  return Boolean(resolveAgentModelPrimaryValue(resolveSessionSanitizationConfig(cfg).model));
}
