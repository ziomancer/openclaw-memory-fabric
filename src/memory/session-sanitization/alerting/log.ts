import fs from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "../../../config/paths.js";
import { normalizeAgentId } from "../../../routing/session-key.js";
import type { AlertPayload } from "../types.js";

function resolveAlertLogFile(agentId: string): string {
  return path.join(
    resolveStateDir(process.env),
    "agents",
    normalizeAgentId(agentId),
    "alerts",
    "alerts.jsonl",
  );
}

/**
 * Append an alert payload to the agent's persistent alert log.
 *
 * Always-on delivery channel — writes regardless of rate limits or dedup state.
 * Failures are logged by the caller; this function throws on I/O error.
 */
export async function appendAlertLogEntry(payload: AlertPayload, agentId: string): Promise<void> {
  const filePath = resolveAlertLogFile(agentId);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, JSON.stringify(payload) + "\n", "utf8");
}
