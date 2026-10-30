export type ApiFailureKind = "network" | "timeout" | "http" | "parse" | "unknown";

export interface ApiFailure {
  kind: ApiFailureKind;
  status: number | null;
  message: string;
  detail?: string;
  hint?: string;
}

export class ApiError extends Error {
  readonly failure: ApiFailure;

  constructor(failure: ApiFailure) {
    super(failure.message);
    this.name = "ApiError";
    this.failure = failure;
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function toApiFailure(error: unknown): ApiFailure {
  if (isApiError(error)) return error.failure;
  if (error instanceof Error) {
    return {
      kind: error.name === "AbortError" ? "timeout" : "unknown",
      status: null,
      message:
        error.name === "AbortError"
          ? "The request was cancelled before the gateway responded."
          : error.message,
    };
  }
  return {
    kind: "unknown",
    status: null,
    message: "An unexpected error occurred while talking to AgentShield.",
  };
}

export function failureTitle(failure: ApiFailure): string {
  switch (failure.kind) {
    case "network":
      return "Gateway unreachable";
    case "timeout":
      return "Gateway timed out";
    case "http":
      if (failure.status === 401) return "Authentication required";
      if (failure.status === 403) return "Administrator authorization required";
      if (failure.status === 404) return "Endpoint not available";
      if (failure.status === 409) return "The request conflicts with current state";
      if (failure.status === 503) return "Gateway is not ready";
      return `Gateway returned ${failure.status ?? "an error"}`;
    case "parse":
      return "Unexpected gateway response";
    default:
      return "Something went wrong";
  }
}

export function failureHint(failure: ApiFailure): string {
  if (failure.hint) return failure.hint;
  if (failure.status === 401) {
    return "The web server proxy could not authenticate to the gateway. Check AGENTSHIELD_API_KEY in the Next.js server environment (never expose it to the browser).";
  }
  if (failure.status === 403) {
    return "This action is protected by the gateway administrator key. Check AGENTSHIELD_ADMIN_KEY in the Next.js server environment.";
  }
  if (failure.status === 502 || failure.kind === "network") {
    return "Confirm AGENTSHIELD_API_URL points at a running AgentShield gateway and that uvicorn is accepting connections.";
  }
  return "";
}
