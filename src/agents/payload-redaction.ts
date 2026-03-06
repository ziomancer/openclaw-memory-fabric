/**
 * Payload redaction utilities for diagnostic logging.
 *
 * These functions strip content that should never appear in debug log files —
 * e.g. large base64 image blobs — while preserving the structural shape of the
 * payload so log consumers can still inspect message roles, tool calls, etc.
 */

function redactImageSource(source: Record<string, unknown>): Record<string, unknown> {
  if (source.type !== "base64" || typeof source.data !== "string") {
    return source;
  }
  // Approximate decoded byte length from base64 length.
  const byteLen = Math.ceil((source.data.length * 3) / 4);
  const kb = Math.round(byteLen / 1024);
  return { ...source, data: `<redacted:${kb}kb>` };
}

function redactContentBlock(block: unknown): unknown {
  if (!block || typeof block !== "object") {
    return block;
  }
  const b = block as Record<string, unknown>;
  if (b.type !== "image" || !b.source || typeof b.source !== "object") {
    return block;
  }
  const redacted = redactImageSource(b.source as Record<string, unknown>);
  if (redacted === b.source) {
    return block;
  }
  return { ...b, source: redacted };
}

function redactMessageContent(content: unknown): unknown {
  if (!Array.isArray(content)) {
    return content;
  }
  const next = content.map(redactContentBlock);
  return next.every((v, i) => v === content[i]) ? content : next;
}

function redactMessage(message: unknown): unknown {
  if (!message || typeof message !== "object") {
    return message;
  }
  const m = message as Record<string, unknown>;
  if (!("content" in m)) {
    return message;
  }
  const content = redactMessageContent(m.content);
  return content === m.content ? message : { ...m, content };
}

/**
 * Return a copy of `payload` with base64 image data replaced by byte-count
 * placeholders. Non-image content is preserved verbatim.
 *
 * The original `payload` reference is never mutated; if no images are present
 * the same reference is returned (zero allocation).
 */
export function redactImageDataForDiagnostics(payload: unknown): unknown {
  if (!payload || typeof payload !== "object") {
    return payload;
  }
  // Handle a raw messages array passed directly (e.g. from cache-trace path).
  if (Array.isArray(payload)) {
    const messages = payload.map(redactMessage);
    return messages.every((m, i) => m === (payload as unknown[])[i]) ? payload : messages;
  }
  const p = payload as Record<string, unknown>;
  if (!Array.isArray(p.messages)) {
    return payload;
  }
  const messages = p.messages.map(redactMessage);
  if (messages.every((m, i) => m === (p.messages as unknown[])[i])) {
    return payload;
  }
  return { ...p, messages };
}
