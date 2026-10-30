import type { DecisionValue } from "./types";

const DATE_FORMAT = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const DATE_ONLY_FORMAT = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
});

export function toEpochMs(value: number | string | null | undefined): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1_000_000_000_000 ? value : value * 1000;
  }
  if (typeof value === "string" && value) {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

export function formatTimestamp(value: number | string | null | undefined): string {
  const ms = toEpochMs(value);
  if (ms === null) return "—";
  return DATE_FORMAT.format(new Date(ms));
}

export function formatDate(value: number | string | null | undefined): string {
  const ms = toEpochMs(value);
  if (ms === null) return "—";
  return DATE_ONLY_FORMAT.format(new Date(ms));
}

export function formatRelative(value: number | string | null | undefined): string {
  const ms = toEpochMs(value);
  if (ms === null) return "—";
  const delta = Date.now() - ms;
  if (delta < 0) return "in the future";
  if (delta < 15_000) return "just now";
  if (delta < 60_000) return `${Math.floor(delta / 1000)}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return `${Math.floor(delta / 86_400_000)}d ago`;
}

export function formatClock(ms: number | null): string {
  if (ms === null) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(ms));
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatDelta(value: number | null | undefined): string {
  if (value === null || value === undefined) return "no prior window";
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(1)}%`;
}

export function decisionLabel(decision: string): string {
  switch (decision) {
    case "allow":
      return "Allow";
    case "deny":
      return "Deny";
    case "require_approval":
      return "Approval";
    default:
      return titleCase(decision || "unknown");
  }
}

export function decisionShortLabel(decision: string): string {
  switch (decision) {
    case "allow":
      return "ALLOW";
    case "deny":
      return "DENY";
    case "require_approval":
      return "HOLD";
    default:
      return decision.toUpperCase() || "UNKNOWN";
  }
}

export function decisionClass(decision: string): string {
  switch (decision) {
    case "allow":
      return "is-allow";
    case "deny":
      return "is-deny";
    case "require_approval":
      return "is-hold";
    default:
      return "is-neutral";
  }
}

export function sourceLabel(source: string): string {
  switch (source) {
    case "user":
      return "User";
    case "system":
      return "System";
    case "trusted_tool":
      return "Trusted tool";
    case "untrusted":
      return "Untrusted";
    default:
      return titleCase(source || "unknown");
  }
}

export function sourceClass(source: string): string {
  switch (source) {
    case "user":
    case "system":
    case "trusted_tool":
      return "is-trusted";
    case "untrusted":
      return "is-untrusted";
    default:
      return "is-neutral";
  }
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function truncate(value: string, length = 90): string {
  if (value.length <= length) return value;
  return `${value.slice(0, length - 1)}…`;
}

export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function isDecision(value: string): value is DecisionValue {
  return value === "allow" || value === "deny" || value === "require_approval";
}

export function formatDurationMs(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  if (value < 1) return `${value.toFixed(2)} ms`;
  if (value < 1000) return `${value.toFixed(1)} ms`;
  return `${(value / 1000).toFixed(2)} s`;
}
