import { NextResponse } from "next/server";
import {
  MAX_PROXY_BODY_BYTES,
  adminPasswordConfigured,
  buildSessionCookie,
  csrfFailure,
  declaredBodyTooLarge,
  jsonContentFailure,
  mintSessionToken,
  passwordOk,
} from "@/app/api/_lib/proxy-auth";

export const runtime = "nodejs";

/**
 * Server-side admin login. Verifies ADMIN_PASSWORD and issues an httpOnly
 * signed session cookie. The gateway ADMIN_KEY is never sent to the browser.
 */
export async function POST(request: Request) {
  const csrf = csrfFailure(request);
  if (csrf) return csrf;

  if (declaredBodyTooLarge(request)) {
    return NextResponse.json(
      { detail: "Request body exceeds the 64KB proxy limit." },
      { status: 413 },
    );
  }
  const buffer = await request.arrayBuffer();
  if (buffer.byteLength > MAX_PROXY_BODY_BYTES) {
    return NextResponse.json(
      { detail: "Request body exceeds the 64KB proxy limit." },
      { status: 413 },
    );
  }
  const jsonError = jsonContentFailure(request, buffer.byteLength);
  if (jsonError) return jsonError;

  if (!adminPasswordConfigured()) {
    return NextResponse.json(
      { detail: "Admin password login is not configured on the server." },
      { status: 503 },
    );
  }

  let password: unknown;
  try {
    const text = buffer.byteLength > 0 ? Buffer.from(buffer).toString("utf8") : "{}";
    password = (JSON.parse(text) as { password?: unknown }).password;
  } catch {
    return NextResponse.json({ detail: "Request body must be valid JSON." }, { status: 400 });
  }

  if (!passwordOk(password)) {
    return NextResponse.json({ detail: "Invalid admin password." }, { status: 401 });
  }

  const response = NextResponse.json({ authenticated: true });
  response.headers.set("Set-Cookie", buildSessionCookie(mintSessionToken()));
  return response;
}
