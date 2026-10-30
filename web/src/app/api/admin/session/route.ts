import { NextResponse } from "next/server";
import {
  SESSION_TTL_SECONDS,
  adminPasswordConfigured,
  getSessionToken,
  verifySessionToken,
} from "@/app/api/_lib/proxy-auth";

export const runtime = "nodejs";

/** Read-only admin session state for the Settings page. No secrets included. */
export async function GET(request: Request) {
  const token = getSessionToken(request);
  const authenticated = verifySessionToken(token);
  let expiresAt: number | null = null;
  if (authenticated && token) {
    const exp = Number(token.split(".")[0]);
    if (Number.isSafeInteger(exp)) expiresAt = exp;
  }
  return NextResponse.json(
    {
      authenticated,
      expires_at: expiresAt,
      ttl_seconds: SESSION_TTL_SECONDS,
      mode: adminPasswordConfigured() ? "password" : "unconfigured",
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
