import { ApiError, type ApiFailure } from "./errors";

const API_BASE = "/api";
const DEFAULT_TIMEOUT_MS = 15_000;

interface ErrorBody {
  detail?: unknown;
  hint?: unknown;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function parseErrorBody(text: string): ErrorBody | null {
  if (!text) return null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as ErrorBody;
    }
  } catch {
    return { detail: text.slice(0, 500) };
  }
  return null;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, DEFAULT_TIMEOUT_MS);

  const onExternalAbort = () => controller.abort();
  signal?.addEventListener("abort", onExternalAbort, { once: true });

  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
      cache: "no-store",
      signal: controller.signal,
    });
  } catch {
    const failure: ApiFailure = timedOut
      ? {
          kind: "timeout",
          status: null,
          message: "The AgentShield gateway did not respond before the timeout.",
        }
      : signal?.aborted
        ? {
            kind: "unknown",
            status: null,
            message: "The request was cancelled.",
          }
        : {
            kind: "network",
            status: null,
            message:
              "The AgentShield gateway is unreachable from the website server.",
          };
    throw new ApiError(failure);
  } finally {
    window.clearTimeout(timer);
    signal?.removeEventListener("abort", onExternalAbort);
  }

  const text = await response.text();
  const body = parseErrorBody(text);

  if (!response.ok) {
    throw new ApiError({
      kind: "http",
      status: response.status,
      message:
        asString(body?.detail) ||
        `The gateway rejected the request (${response.status}).`,
      detail: asString(body?.detail),
      hint: asString(body?.hint),
    });
  }

  if (!text) return undefined as T;

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError({
      kind: "parse",
      status: response.status,
      message: "The gateway returned a response that was not valid JSON.",
      detail: text.slice(0, 300),
    });
  }
}

export function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { method: "GET" }, signal);
}

export function apiPost<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  return request<T>(
    path,
    {
      method: "POST",
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    signal,
  );
}

export interface AdminSessionState {
  authenticated: boolean;
  expires_at: number | null;
  ttl_seconds: number;
  mode: "password" | "unconfigured";
}

export function adminLogin(password: string, signal?: AbortSignal): Promise<AdminSessionState> {
  return apiPost<AdminSessionState>("/admin/login", { password }, signal);
}

export function adminLogout(signal?: AbortSignal): Promise<{ authenticated: boolean }> {
  return apiPost<{ authenticated: boolean }>("/admin/logout", {}, signal);
}

export function adminSession(signal?: AbortSignal): Promise<AdminSessionState> {
  return apiGet<AdminSessionState>("/admin/session", signal);
}

export function buildQuery(
  values: Record<string, string | number | boolean | null | undefined>,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value === null || value === undefined || value === "") continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

export function callPath(callId: string): string {
  return `/v1/approvals/${encodeURIComponent(callId)}`;
}
