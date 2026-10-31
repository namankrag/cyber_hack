import { NextResponse } from "next/server";
import {
  ADMIN_KEY,
  ADMIN_REQUIRED_DETAIL,
  API_KEY,
  GATEWAY,
  csrfFailure,
  declaredBodyTooLarge,
  getSessionToken,
  hasBadSegment,
  isPrivileged,
  jsonContentFailure,
  matchRoute,
  maxBodyBytesFor,
  rawPathHasEncodedTraversal,
  upstreamTimeoutMsFor,
  verifySessionToken,
} from "@/app/api/_lib/proxy-auth";

export const runtime = "nodejs";

async function forward(request: Request, path: string[]) {
  const method = request.method.toUpperCase();

  // Reject traversal and encoded slashes before any routing decision.
  const rawPath = new URL(request.url).pathname;
  if (rawPathHasEncodedTraversal(rawPath) || hasBadSegment(path)) {
    return NextResponse.json({ detail: "Not found" }, { status: 404 });
  }

  // Exact method + route allowlist (no prefix matching).
  if (!matchRoute(method, path)) {
    return NextResponse.json({ detail: "Not found" }, { status: 404 });
  }

  // Same-origin check on mutating requests (F2).
  const csrf = csrfFailure(request);
  if (csrf) return csrf;

  const joined = path.join("/");

  // Privileged gateway routes require a valid admin session (F1). The
  // ADMIN_KEY is attached server-side only; it is never sent to the browser.
  if (isPrivileged(joined, request.method) && !verifySessionToken(getSessionToken(request))) {
    return NextResponse.json({ detail: ADMIN_REQUIRED_DETAIL }, { status: 401 });
  }

  const privileged = isPrivileged(joined, request.method);
  const key = privileged ? ADMIN_KEY || API_KEY : API_KEY;

  // Declared-size pre-check so an oversized body is rejected before buffering.
  const bodyLimit = maxBodyBytesFor(joined);
  const tooLarge = NextResponse.json(
    { detail: `Request body exceeds the ${Math.round(bodyLimit / 1024)}KB proxy limit.` },
    { status: 413 },
  );
  if (declaredBodyTooLarge(request, bodyLimit)) {
    return tooLarge;
  }

  let body: string | undefined;
  if (method !== "GET" && method !== "HEAD") {
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength > bodyLimit) {
      return tooLarge;
    }
    const jsonError = jsonContentFailure(request, buffer.byteLength);
    if (jsonError) return jsonError;
    body = buffer.byteLength > 0 ? Buffer.from(buffer).toString("utf8") : undefined;
  }

  const incoming = new URL(request.url);
  const target = new URL(`${GATEWAY}/${joined}`);
  incoming.searchParams.forEach((value, key) => target.searchParams.set(key, value));

  const headers: Record<string, string> = { Accept: "application/json" };
  if (key) headers["X-API-Key"] = key;
  const contentType = request.headers.get("content-type");
  if (contentType) headers["Content-Type"] = contentType;

  try {
    const response = await fetch(target.toString(), {
      method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(upstreamTimeoutMsFor(joined)),
    });
    const text = await response.text();
    const contentType = response.headers.get("content-type") || "application/json";
    return new NextResponse(text, {
      status: response.status,
      headers: {
        "Content-Type": contentType,
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    const message =
      error instanceof DOMException && error.name === "TimeoutError"
        ? "The gateway did not respond before the timeout."
        : "The AgentShield gateway is unreachable from the website server.";
    return NextResponse.json(
      { detail: message, hint: "Check AGENTSHIELD_API_URL and that uvicorn is running." },
      { status: 502 },
    );
  }
}

export async function GET(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  return forward(request, path);
}

export async function POST(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  return forward(request, path);
}

export async function PUT(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  return forward(request, path);
}

export async function DELETE(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  return forward(request, path);
}
