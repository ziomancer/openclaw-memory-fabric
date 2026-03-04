import { redactSensitiveText } from "../logging/redact.js";

function sanitizeString(value: string): string {
  return redactSensitiveText(value, { mode: "tools" });
}

export function sanitizePayloadForLogging<T>(value: T): T {
  if (typeof value === "string") {
    return sanitizeString(value) as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizePayloadForLogging(item)) as T;
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return value;
  }

  const sanitizedEntries = Object.entries(value).map(([key, entryValue]) => [
    key,
    sanitizePayloadForLogging(entryValue),
  ]);
  return Object.fromEntries(sanitizedEntries) as T;
}
