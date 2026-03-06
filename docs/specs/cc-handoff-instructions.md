# MCP Trust Tier — Answers to Read-Back Questions

Good read-back. Here are answers to your questions. Don't start implementing until you've confirmed you understand these.

---

## 1. MCP result handling — where to intercept

Find where MCP tool results enter the manager's message history or context assembly. The intercept point is wherever the raw MCP response gets assembled into the message that enters the manager's conversation context.

If there's a clear single function, hook there. If it's diffuse across multiple paths, propose an intercept architecture and check with me before implementing. Don't guess on this one — get the wiring right before writing the logic.

---

## 2. Trusted server identifier matching

There's no existing MCP server registry in the config. For now, `trustedServers` is a freeform string list under `memory.sessions.sanitization.mcp.trustedServers`. The operator is responsible for making the strings match whatever identifier they use for their MCP servers. Convention-matched, not cross-referenced.

When a proper MCP server config namespace exists later, we can add cross-referencing. Don't build that now.

---

## 3. CRED-008 (entropy analysis)

Implement it. For v1, use a simple scope rule: apply entropy analysis only to string values shorter than 1KB. This naturally excludes file contents and code snippets (typically longer) while catching credential-shaped strings in metadata fields.

Skip tool-type awareness for now — the length heuristic is sufficient. Note the tool-type refinement as a follow-up comment in the code.

Shannon entropy threshold: > 4.5 on any string value > 20 characters and < 1KB.

---

## 4. Temporal checks (Category 8)

Defer all three TEMPORAL patterns. Do not implement.

Add a placeholder module or comment noting where temporal checks will hook in so the architecture accommodates them later. That's it — just the seam, no logic.

Categories 6 (encoding/obfuscation) and 7 (structural topology): implement now alongside categories 1-5.

---

## 5. Tier 1 flag patterns — how to convey annotations to Tier 2

Add a new input file to the materialized workspace:

```
tier1-annotations.json
```

Schema:

```json
{
  "flags": ["ENC-002: 4+ consecutive Unicode escapes in field 'content'"],
  "patternsMatched": ["ENC-002"]
}
```

The workspace now has four files:

- `query.json` — the original tool call (unchanged)
- `mcp-result.json` — the raw result (unchanged)
- `session-context.jsonl` — recent session summary entries (unchanged)
- `tier1-annotations.json` — what Tier 1 noticed (new)

`tier1-annotations.json` is only present when Tier 1 flag-action patterns matched. If no flag patterns triggered (Tier 1 passed clean), omit the file entirely.

Add a small addition to the static MCP mode prompt:

```
If tier1-annotations.json is present, the structural pre-filter flagged
potential concerns that did not meet the threshold for blocking. Consider
these annotations as additional context when evaluating the result. They
are informational signals, not conclusions.
```

Append this after the existing rules block, before the output schema.

---

## 6. session-context.jsonl content

Reuse `readSessionMemorySummaryEntries` with a recency filter:

- Last 10 entries OR entries from the last 30 minutes, whichever yields fewer entries
- Use the existing summary entry shape — no custom format

The point is lightweight context so the sub-agent understands what the session is doing, not full session history.

---

## Build order confirmed

Your proposed build order is correct. Proceed in this sequence:

1. Config
2. Types
3. Storage
4. Tier 1 pre-filter (standalone module, all categories 1-7)
5. Runtime (mcp mode prompt/response)
6. Service (`processMcpToolResult` with full trust-tier routing)
7. MCP hook integration (pending your investigation of the intercept point — check with me first)
8. System prompt update
9. Tests

**Stop after step 3 (Storage) and check in.** I want to see the type definitions and storage layout before you build the logic layers on top.

---

## Reminder

- Tier 1's job is volume reduction, not comprehensive coverage. Err toward false negatives over false positives.
- The sub-agent (Tier 2) runs Qwen3.5-9B locally as the default model. The static prompt and output schema are model-agnostic, but design with local inference latency (~50-100ms) in mind.
- Keep the Tier 1 and Tier 2 inspection logic in clean, separable modules. Don't tangle them with the MCP protocol handling or the storage layer. They will be extracted later.
