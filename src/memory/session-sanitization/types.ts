import { z } from "zod";

export const SESSION_MEMORY_CONFIDENCE_VALUES = ["high", "medium", "low"] as const;
export type SessionMemoryConfidence = (typeof SESSION_MEMORY_CONFIDENCE_VALUES)[number];

export const SESSION_MEMORY_CHILD_MODES = ["write", "recall", "signal", "mcp"] as const;
export type SessionMemoryChildMode = (typeof SESSION_MEMORY_CHILD_MODES)[number];

export type SessionMemoryRawEntry = {
  messageId: string;
  timestamp: string;
  expiresAt: string;
  transcript: string;
  body?: string;
  bodyForAgent?: string;
  from?: string;
  to?: string;
  channelId?: string;
  conversationId?: string;
  senderId?: string;
  senderName?: string;
  senderUsername?: string;
  provider?: string;
  surface?: string;
  mediaPath?: string;
  mediaType?: string;
};

export type SessionMemorySummaryEntry = {
  messageId: string;
  timestamp: string;
  rawExpiresAt: string;
  decisions: string[];
  actionItems: string[];
  entities: string[];
  contextNote?: string;
  discard: boolean;
};

export type SessionMemoryAuditEvent =
  | "write"
  | "discard"
  | "write_failed"
  | "raw_expired"
  | "trusted_pass"
  | "structural_block"
  | "sanitized_pass"
  | "sanitized_block"
  | "mcp_raw_expired";

export type SessionMemoryAuditEntry = {
  event: SessionMemoryAuditEvent;
  timestamp: string;
  messageId?: string;
  reason?: string;
  /** MCP-specific audit fields */
  server?: string;
  toolCallId?: string;
  /** Which tier produced the result: 1 (Tier 1 pre-filter) or 2 (sub-agent). */
  tier?: 1 | 2;
  flags?: string[];
};

export type SessionMemoryMcpRawEntry = {
  toolCallId: string;
  timestamp: string;
  expiresAt: string;
  server: string;
  toolName: string;
  rawResult: unknown;
  sanitizedResult: unknown;
  safe: boolean;
  flags: string[];
};

export type SessionMemoryMcpChildResult = {
  mode: "mcp";
  safe: boolean;
  structuredResult: Record<string, unknown>;
  flags: string[];
  contextNote: string;
};

export type SessionMemoryWriteResult = {
  mode: "write";
  decisions: string[];
  actionItems: string[];
  entities: string[];
  contextNote?: string;
  discard: boolean;
};

export type SessionMemoryRecallChildResult = {
  mode: "recall";
  result: string;
  source: "raw" | "summary";
  matchedSummaryIds: string[];
  usedRawMessageIds: string[];
};

export type SessionMemoryRecallResult = {
  mode: "recall";
  query: string;
  result: string;
  confidence: SessionMemoryConfidence;
  source: "raw" | "summary";
};

export type SessionMemorySignalResult = {
  mode: "signal";
  relevant: string[];
  discarded?: string;
};

const stringArraySchema = z.array(z.string());

export const sessionMemoryWriteResultSchema = z
  .object({
    mode: z.literal("write"),
    decisions: stringArraySchema,
    actionItems: stringArraySchema,
    entities: stringArraySchema,
    contextNote: z.string().optional(),
    discard: z.boolean(),
  })
  .strict();

export const sessionMemoryRecallChildResultSchema = z
  .object({
    mode: z.literal("recall"),
    result: z.string(),
    source: z.enum(["raw", "summary"]),
    matchedSummaryIds: stringArraySchema,
    usedRawMessageIds: stringArraySchema,
  })
  .strict();

export const sessionMemorySignalResultSchema = z
  .object({
    mode: z.literal("signal"),
    relevant: stringArraySchema,
    discarded: z.string().optional(),
  })
  .strict();

export const sessionMemoryRawEntrySchema = z
  .object({
    messageId: z.string(),
    timestamp: z.string(),
    expiresAt: z.string(),
    transcript: z.string(),
    body: z.string().optional(),
    bodyForAgent: z.string().optional(),
    from: z.string().optional(),
    to: z.string().optional(),
    channelId: z.string().optional(),
    conversationId: z.string().optional(),
    senderId: z.string().optional(),
    senderName: z.string().optional(),
    senderUsername: z.string().optional(),
    provider: z.string().optional(),
    surface: z.string().optional(),
    mediaPath: z.string().optional(),
    mediaType: z.string().optional(),
  })
  .strict();

export const sessionMemorySummaryEntrySchema = z
  .object({
    messageId: z.string(),
    timestamp: z.string(),
    rawExpiresAt: z.string(),
    decisions: stringArraySchema,
    actionItems: stringArraySchema,
    entities: stringArraySchema,
    contextNote: z.string().optional(),
    discard: z.boolean(),
  })
  .strict();

export const sessionMemoryAuditEntrySchema = z
  .object({
    event: z.enum([
      "write",
      "discard",
      "write_failed",
      "raw_expired",
      "trusted_pass",
      "structural_block",
      "sanitized_pass",
      "sanitized_block",
      "mcp_raw_expired",
    ]),
    timestamp: z.string(),
    messageId: z.string().optional(),
    reason: z.string().optional(),
    server: z.string().optional(),
    toolCallId: z.string().optional(),
    tier: z.union([z.literal(1), z.literal(2)]).optional(),
    flags: z.array(z.string()).optional(),
  })
  .strict();

export const sessionMemoryMcpRawEntrySchema = z
  .object({
    toolCallId: z.string(),
    timestamp: z.string(),
    expiresAt: z.string(),
    server: z.string(),
    toolName: z.string(),
    rawResult: z.unknown(),
    sanitizedResult: z.unknown(),
    safe: z.boolean(),
    flags: z.array(z.string()),
  })
  .strict();

export const sessionMemoryMcpChildResultSchema = z
  .object({
    mode: z.literal("mcp"),
    safe: z.boolean(),
    structuredResult: z.record(z.string(), z.unknown()),
    flags: z.array(z.string()),
    contextNote: z.string(),
  })
  .strict();
