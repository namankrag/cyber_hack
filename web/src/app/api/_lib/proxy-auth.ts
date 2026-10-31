/**
 * Server-only helpers for the /api proxy and the admin session routes.
 *
 * Never import this module from a client component: it reads server-side
 * secrets (ADMIN_PASSWORD, ADMIN_KEY) from the process environment.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";

export const GATEWAY = (process.env.AGENTSHIELD_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
export const API_KEY = process.env.AGENTSHIELD_API_KEY || "";
export const ADMIN_KEY = process.env.AGENTSHIELD_ADMIN_KEY || "";

export const ADMIN_SESSION_COOKIE = "asg_admin";
export const SESSION_TTL_SECONDS = 8 * 60 * 60;
export const MAX_PROXY_BODY_BYTES = 64 * 1024;

/**
 * The Document Lab upload is the one route that carries a whole file (a
 * base64 PDF up to 2MB). It gets its own explicit budget and a longer
 * upstream timeout (the first PatchProof run takes several seconds); every
 * other route keeps the 64KB / 12s defaults.
 */
const DOCUMENT_ANALYZE_ROUTE = "v1/document/analyze";
export const MAX_DOCUMENT_BODY_BYTES = 3 * 1024 * 1024;

export function maxBodyBytesFor(joinedPath: string): number {
  return joinedPath === DOCUMENT_ANALYZE_ROUTE ? MAX_DOCUMENT_BODY_BYTES : MAX_PROXY_BODY_BYTES;
}

export function upstreamTimeoutMsFor(joinedPath: string): number {
  return joinedPath === DOCUMENT_ANALYZE_ROUTE ? 60_000 : 12_000;
}

export const ADMIN_REQUIRED_DETAIL =
  "Administrator login required. Sign in on the Settings page with the admin password, then retry.";

const PRIVILEGED_PREFIXES = ["v1/admin", "v1/approvals", "v1/redteam"];

/**
 * Exact method + route allowlist. No prefix matching: a request is forwarded
 * only when both the method and the full path match an entry below (or the
 * single dynamic approvals decision route handled in matchRoute).
 */
const EXACT_ROUTES = new Set([
  "GET health",
  "GET ready",
  "POST v1/check",
  "GET v1/audit",
  "GET v1/enforce",
  "POST v1/admin/enforce",
  "POST v1/admin/reset",
  "GET v1/approvals",
  "GET v1/approvals/pending",
  "POST v1/approvals/decide",
  "GET v1/evidence",
  "GET v1/bench/latest",
  "GET v1/metrics",
  "GET v1/threats",
  "GET v1/policy",
  "POST v1/policy/preview",
  "GET v1/policy/history",
  "POST v1/admin/policy/publish",
  "POST v1/admin/policy/rollback",
  "GET v1/tools",
  "GET v1/agents",
  "GET v1/corpus",
  "GET v1/redteam/scenarios",
  "GET v1/redteam/history",
  "POST v1/redteam/run",
  "GET v1/evidence/reports",
  "GET v1/document/samples",
  "POST v1/document/analyze",
  "POST v1/mcp/demo",
  "POST v1/mcp/call",
  "POST v1/trust/demo",
  "GET v1/evidence/scorecard",
]);

const CALL_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

export function matchRoute(method: string, segments: string[]): boolean {
  const joined = segments.join("/");
  if (EXACT_ROUTES.has(`${method} ${joined}`)) return true;
  // Single dynamic route: POST /v1/approvals/{call_id}. "decide" and
  // "pending" are reserved words served by their own exact entries above.
  return (
    method === "POST" &&
    segments.length === 3 &&
    segments[0] === "v1" &&
    segments[1] === "approvals" &&
    segments[2] !== "decide" &&
    segments[2] !== "pending" &&
    CALL_ID_RE.test(segments[2])
  );
}

/** Reject paths carrying encoded slashes or backslashes (raw URL check). */
export function rawPathHasEncodedTraversal(rawPath: string): boolean {
  return /%2f|%5c/i.test(rawPath);
}

/** Reject traversal / empty / separator-bearing decoded segments. */
export function hasBadSegment(segments: string[]): boolean {
  return segments.some(
    (segment) =>
      segment === "" ||
      segment === "." ||
      segment === ".." ||
      segment.includes("/") ||
      segment.includes("\\"),
  );
}

export function isPrivileged(joinedPath: string, method = "GET"): boolean {
  // Reading the approval queue is a regular API-key route on the gateway;
  // only deciding an approval needs the admin session + key.
  if (method.toUpperCase() !== "POST" && joinedPath === "v1/approvals") return false;
  return PRIVILEGED_PREFIXES.some(
    (prefix) => joinedPath === prefix || joinedPath.startsWith(`${prefix}/`),
  );
}

/**
 * Same-origin check for browser-issued mutations. Non-browser clients
 * (curl, tests) send no Origin/Referer and are allowed through; a present
 * Origin or Referer must match this server's own origin.
 */
/**
 * The public origin of this site. Behind a hosting proxy request.url carries
 * the internal address, so prefer PUBLIC_ORIGIN, then the forwarded host.
 */
function expectedOrigin(request: Request): string {
  const configured = process.env.PUBLIC_ORIGIN;
  if (configured) return configured.replace(/\/+$/, "");
  const host = request.headers.get("x-forwarded-host") || request.headers.get("host");
  if (host) {
    const proto =
      request.headers.get("x-forwarded-proto") || new URL(request.url).protocol.replace(":", "");
    return `${proto.split(",")[0].trim()}://${host.split(",")[0].trim()}`;
  }
  return new URL(request.url).origin;
}

export function csrfFailure(request: Request): NextResponse | null {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return null;
  const expected = expectedOrigin(request);
  const origin = request.headers.get("origin");
  if (origin) {
    if (origin !== expected) {
      return NextResponse.json({ detail: "Cross-site request rejected." }, { status: 403 });
    }
    return null;
  }
  const referer = request.headers.get("referer");
  if (referer) {
    let parsed: URL;
    try {
      parsed = new URL(referer);
    } catch {
      return NextResponse.json({ detail: "Cross-site request rejected." }, { status: 403 });
    }
    if (parsed.origin !== expected) {
      return NextResponse.json({ detail: "Cross-site request rejected." }, { status: 403 });
    }
  }
  return null;
}

/**
 * Mutations carrying a body must declare application/json. Empty-body
 * POSTs (for example /v1/admin/reset) carry no Content-Type and pass.
 */
export function jsonContentFailure(request: Request, bodyBytes: number): NextResponse | null {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return null;
  if (bodyBytes === 0) return null;
  const contentType = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    return NextResponse.json(
      { detail: "Mutating requests must use Content-Type: application/json." },
      { status: 415 },
    );
  }
  return null;
}

/** Pre-read body cap from the declared Content-Length, when present. */
export function declaredBodyTooLarge(
  request: Request,
  limit: number = MAX_PROXY_BODY_BYTES,
): boolean {
  const declared = request.headers.get("content-length");
  return declared !== null && /^\d+$/.test(declared.trim()) && Number(declared) > limit;
}

function adminPassword(): string {
  return process.env.ADMIN_PASSWORD || "";
}

export function adminPasswordConfigured(): boolean {
  return adminPassword().length > 0;
}

export function passwordOk(provided: unknown): boolean {
  const expected = adminPassword();
  if (!expected || typeof provided !== "string" || !provided) return false;
  const actual = createHash("sha256").update(provided, "utf8").digest();
  const wanted = createHash("sha256").update(expected, "utf8").digest();
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}

export function mintSessionToken(nowSec: number = Math.floor(Date.now() / 1000)): string {
  const exp = nowSec + SESSION_TTL_SECONDS;
  const body = String(exp);
  const sig = createHmac("sha256", adminPassword()).update(`asg-admin.${body}`, "utf8").digest("hex");
  return `${body}.${sig}`;
}

export function verifySessionToken(token: string | null): boolean {
  if (!token || !adminPasswordConfigured()) return false;
  const match = /^(\d+)\.([0-9a-f]{64})$/.exec(token.trim());
  if (!match) return false;
  if (revokedTokens.has(match[2])) return false;
  const exp = Number(match[1]);
  if (!Number.isSafeInteger(exp) || exp * 1000 <= Date.now()) return false;
  let expected: string;
  try {
    expected = createHmac("sha256", adminPassword()).update(`asg-admin.${match[1]}`, "utf8").digest("hex");
  } catch {
    return false;
  }
  const provided = Buffer.from(match[2], "utf8");
  const wanted = Buffer.from(expected, "utf8");
  return provided.length === wanted.length && timingSafeEqual(provided, wanted);
}

/**
 * Login attempt throttling. The gateway rate limiter does not see
 * this route (different server), so failed password guesses are capped
 * per client IP here: 10 failures per 10 minutes, then HTTP 429.
 * Single-instance memory only — see note on revokedTokens below.
 */
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_MAX_FAILURES = 10;
const loginFailures = new Map<string, { windowStart: number; count: number }>();

export function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0].trim();
    if (first) return first;
  }
  return "unknown";
}

function pruneLoginFailures(): void {
  if (loginFailures.size <= 1024) return;
  for (const key of loginFailures.keys()) {
    loginFailures.delete(key);
    if (loginFailures.size <= 1024) break;
  }
}

export function loginThrottled(ip: string): boolean {
  const now = Date.now();
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (now - entry.windowStart >= LOGIN_WINDOW_MS) {
    loginFailures.delete(ip);
    return false;
  }
  return entry.count >= LOGIN_MAX_FAILURES;
}

export function noteLoginFailure(ip: string): void {
  const now = Date.now();
  const entry = loginFailures.get(ip);
  if (!entry || now - entry.windowStart >= LOGIN_WINDOW_MS) {
    pruneLoginFailures();
    loginFailures.set(ip, { windowStart: now, count: 1 });
    return;
  }
  entry.count += 1;
}

export function noteLoginSuccess(ip: string): void {
  loginFailures.delete(ip);
}

/**
 * Server-side session revocation. Logout clears the cookie, but the
 * bearer token itself stays valid until expiry (up to 8h), so a copied
 * token could otherwise be replayed. Revoked signatures are rejected
 * here until their embedded expiry passes.
 *
 * Single-instance memory only: with several server instances (or
 * serverless isolates) a logout on one instance does not propagate.
 * The 8h TTL still bounds replay, and theft requires cookie compromise
 * (HttpOnly + SameSite). A shared store would be needed for strict
 * multi-instance revocation.
 */
const revokedTokens = new Map<string, number>();

function pruneRevoked(nowSec: number): void {
  for (const [sig, exp] of revokedTokens) {
    if (exp <= nowSec) revokedTokens.delete(sig);
  }
  while (revokedTokens.size > 2048) {
    const oldest = revokedTokens.keys().next();
    if (oldest.done) break;
    revokedTokens.delete(oldest.value);
  }
}

export function revokeSessionToken(token: string | null): void {
  if (!token) return;
  const match = /^(\d+)\.([0-9a-f]{64})$/.exec(token.trim());
  if (!match) return;
  pruneRevoked(Math.floor(Date.now() / 1000));
  revokedTokens.set(match[2], Number(match[1]));
}

export function getSessionToken(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === ADMIN_SESSION_COOKIE) {
      const value = part.slice(index + 1).trim();
      return value || null;
    }
  }
  return null;
}

export function buildSessionCookie(token: string | null): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  if (!token) {
    return `${ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=0`;
  }
  return `${ADMIN_SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${SESSION_TTL_SECONDS}`;
}
