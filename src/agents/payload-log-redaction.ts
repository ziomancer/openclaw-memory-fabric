import { redactSensitiveText } from "../logging/redact.js";

function sanitizeString(value: string): string {
  return redactSensitiveText(value, { mode: "tools" });
}

export function sanitizePayloadForLogging<T>(value: T, visited = new WeakSet<object>()): T {
  if (typeof value === "string") {
    return sanitizeString(value) as T;
  }
  if (Array.isArray(value)) {
    if (visited.has(value)) return value;
    visited.add(value);
    return value.map((item) => sanitizePayloadForLogging(item, visited)) as T;
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return value;
  }
  if (visited.has(value as object)) return value;
  visited.add(value as object);

  const sanitizedEntries = Object.entries(value).map(([key, entryValue]) => [
    key,
    sanitizePayloadForLogging(entryValue, visited),
  ]);
  return Object.fromEntries(sanitizedEntries) as T;
}
