import { NextResponse } from "next/server";
import { buildSessionCookie, csrfFailure, getSessionToken, revokeSessionToken } from "@/app/api/_lib/proxy-auth";

export const runtime = "nodejs";

/** Clear the admin session cookie. */
export async function POST(request: Request) {
  const csrf = csrfFailure(request);
  if (csrf) return csrf;
  revokeSessionToken(getSessionToken(request));
  const response = NextResponse.json({ authenticated: false });
  response.headers.set("Set-Cookie", buildSessionCookie(null));
  return response;
}
