import { NextResponse } from "next/server";

const GATEWAY = (process.env.AGENTSHIELD_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
const API_KEY = process.env.AGENTSHIELD_API_KEY || "";
const ADMIN_KEY = process.env.AGENTSHIELD_ADMIN_KEY || "";

const ALLOWED_PREFIXES = ["health", "ready", "v1/"];

function isAllowed(path: string[]) {
  const joined = path.join("/");
  return ALLOWED_PREFIXES.some((prefix) => joined === prefix || joined.startsWith(prefix));
}

async function forward(request: Request, path: string[]) {
  if (!isAllowed(path)) {
    return NextResponse.json({ detail: "Not found" }, { status: 404 });
  }

  const incoming = new URL(request.url);
  const target = new URL(`${GATEWAY}/${path.join("/")}`);
  incoming.searchParams.forEach((value, key) => target.searchParams.set(key, value));

  const privileged =
    path.join("/").startsWith("v1/admin") ||
    path.join("/").startsWith("v1/approvals") ||
    path.join("/").startsWith("v1/redteam");
  const key = privileged ? ADMIN_KEY || API_KEY : API_KEY;

  const headers: Record<string, string> = { Accept: "application/json" };
  if (key) headers["X-API-Key"] = key;
  const contentType = request.headers.get("content-type");
  if (contentType) headers["Content-Type"] = contentType;

  let body: string | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.text();
  }

  try {
    const response = await fetch(target.toString(), {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(12_000),
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
