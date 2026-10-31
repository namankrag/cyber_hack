# Focused security audit — AgentShield console + proxy (`final-merge`)

Local-only audit of the **new web attack surface** landed after the 2026-10-30
master audit (`docs/MASTER_AUDIT_REPORT.md`): Next.js proxy, admin session
cookie, sidebar role switcher, and the redesigned Overview. The master audit
already covers the gateway engine, RAG, PatchProof, MCP, deps and deploy; those
lanes are re-verified here, not re-done. No pushes, no commits, no remotes
touched — every change below is a local working-tree edit.

Stack under audit: Next.js 16 + React 19 (`web/`, prod `next start` on :3000
and :3200) → FastAPI gateway (`agentshield/`, :8000). Single-tenant demo: no
user accounts, no database, no file uploads, no Vite anywhere in the repo
(the brief's Vite/Supabase/Argon2 sections are N/A — justified in §7).

Method: read the code first (`proxy-auth.ts`, `[...path]/route.ts`,
`admin/login|logout|session` routes, `client.ts`, `errors.ts`,
`session-context.tsx`, `role-switcher.tsx`, `use-live-data.ts`,
`next.config.ts`, gateway `app.py` admin endpoints), then live probes against
the running local stack plus `lint` / `typecheck` / `build`. Dangerous checks
ran against isolated throwaway servers where noted; the shared :8000 gateway
was never restarted and no audit data was touched. Findings fixed in-tree and
re-probed. Nothing below is inferred from filenames.

## Findings (new in this audit)

### FA1 — No security response headers on the Next.js frontend (Low) — FIXED
Pages and `/api` responses carried none of `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and disclosed
`X-Powered-By: Next.js`. The gateway sets its own headers (M1), but the
browser-facing app did not.
Evidence (before): `curl -I :3200/workspace` →
`X-Powered-By: Next.js`, no hardening headers; same on `/api/health`.
Fix: `web/next.config.ts` gains `poweredByHeader: false` and a `headers()`
block (nosniff, `DENY` framing, strict referrer policy, minimal
permissions policy) applied to `/workspace/:path*` and `/api/:path*`. No
`script-src` CSP by decision: Next hydration needs inline scripts and a
half-CSP is worse than none.
Evidence (after, live on rebuilt :3200): all four headers present on the
page and on `/api/health`; `X-Powered-By` gone. `lint`/`typecheck`/`build`
green. Test: header curl re-probe (this report, §5).

### FA2 — Unlimited admin-password guessing on `/api/admin/login` (Medium) — FIXED
The login route compared correctly (sha256 + `timingSafeEqual`) but counted
nothing: an attacker could guess `ADMIN_PASSWORD` at network speed with no
lockout. The gateway's own 600/min limiter never sees this route.
Evidence (before): rapid wrong-password POSTs all returned 401, no 429.
Fix: per-IP failure counting in `proxy-auth.ts` — 10 failures per 10-minute
window → HTTP 429; a successful login resets the counter (`noteLoginSuccess`).
Bounded map (1024 entries, oldest evicted). The throttle key uses
`X-Forwarded-For` first entry, else `"unknown"`.
Evidence (after, live): 10 × `401`, 11th → `429 Too many failed sign-in
attempts`. Legit login still `200` and resets the bucket (verified: correct
password accepted immediately after unrelated-bucket failures).
Residuals: XFF spoofing rotates buckets (same accepted class as the
gateway's own limiter — a burst backstop, edge duty in prod); 10 genuine
typos lock the IP for 10 minutes (self-clearing, documented in the message).

### FA3 — Logout did not invalidate the session token (Low) — FIXED
 Logout cleared the `asg_admin` cookie, but the token
(`exp.hmac`, valid up to 8h) stayed verifiable: anyone holding a copied
cookie (shared machine, proxy log) could replay it post-logout.
Evidence (before): login → save cookie → logout → replay cookie on
`/api/admin/session` and a privileged route → still `200`.
Fix: server-side revocation set in `proxy-auth.ts` (`revokeSessionToken`
called on logout; `verifySessionToken` rejects revoked signatures; entries
purged past expiry, set bounded at 2048).
Evidence (after, live): same replay → `authenticated:false` on session and
`401` on the privileged route, while a fresh login works.
Residuals: single-instance memory — with several server instances (or
serverless isolates) a logout on one does not propagate; the 8h TTL still
bounds replay and theft requires cookie compromise (HttpOnly + SameSite).
A shared store would be needed for strict multi-instance revocation.

### FA4 — Live provider keys in an untracked root `.env` (Info) — NO CODE CHANGE
Root `.env` (untracked, gitignored, never committed — history scan clean)
holds real `OPENROUTER`/`SARVAM`/`NVIDIA` keys for live provider smoke
tests, and states its own rotation duty. No key value appears in any tracked
file, build output, or report (this one included).
Recommendation: rotate all three after the hackathon demo; keep them out of
shell history, backups, and screenshots. Do not print them anywhere.

## Re-verified holding (probed live, no change needed)

- **F1** privileged route without session → `401` (`/api/v1/admin/enforce`).
- **F2** cross-site POST (`Origin: https://evil.example`) → `403`.
- **F3** encoded traversal (`/api/v1/%2e%2e/docs`) → `404` (allowlist +
  `%2f/%5c` + segment checks all fire before routing).
- **F4** 70KB JSON body → `413` (declared-length pre-check and post-read
  byte cap both present).
- **401 mapping**: backend/proxy 401s render "Administrator login required"
  with the non-secret hint; no key material in messages.
- **CSRF design**: non-GET requires matching `Origin` (else `Referer`);
  headerless non-browser clients pass but carry no victim cookies; simple
  cross-site form bodies fail the JSON-content check (`415`). Sound.
- **Cookie flags**: `HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`,
  `Secure` in production; logout clears with `Max-Age=0`. No secret in
  `/api/admin/session` output; `no-store` set.
- **Gateway caps**: every `limit` is `ge=1, le=500` server-side and `window`
  is pattern-validated — the proxy's raw query passthrough cannot widen
  samples. Approvals `decide` alias declared before `{call_id}`; red-team run
  is admin-gated, server-scenario-only, rate-limited like everything else.
- **Frontend**: no `dangerouslySetInnerHTML`; React escapes all gateway data
  (audit rows, reasons, metadata); no `NEXT_PUBLIC_*` secrets; client talks
  only to relative `/api` (keys stay server-side); role is server-cookie
  truth, no client `isAdmin` unlock.
- **Secrets/history**: `.env` + audit JSONL untracked and gitignored; only
  `.env.example` files tracked; `git log` + 50-commit grep for key prefixes
  clean; root keys never entered the tree.
- **Deps**: `npm audit` → 0 vulnerabilities. Backend pins unchanged since the
  master-audit lockfile lands (M5/M9 residuals stand: chroma CVEs unreachable
  via embedded-only use; base-image digest still pre-live advice).

## Out-of-scope-by-construction (checked, N/A with reason)

Vite (not present — Next.js instead); user DB/RLS/IDOR (no users, no object
IDs, single tenant); password storage/Argon2 (no user passwords; the single
env secret is HMAC-verified, correct construction); file uploads; custom
crypto (none — `node:crypto` only); mass assignment (pydantic defaults +
response models on the gateway; exact allowlist on the proxy).

## Test record

- `npm run lint` clean, `npx tsc --noEmit` clean, `npm run build` green
  (19 routes) after every fix batch.
- Live curl probes: F1–F4 re-pass; throttle `401×10 → 429`; revocation
  replay `→ 401`; headers present on page + API.
- CDP UI flow on the fixed build: Operator → wrong pw (inline error, stays
  Operator) → login (Administrator, AD avatar, topbar) → enforcement OFF →
  ON (restored) → sign-out (locked) → secret-logout + toggle → expiry
  notice + Operator. Enforcement verified back ON afterwards.
- No maintained TS test harness exists in `web/` (disclosed, not added —
  adding a framework for two server-route fixes is disproportionate; live
  probes above are the verification).

## Remaining risks and limitations

1. Throttle and revocation are single-instance memory (documented in code);
   multi-instance/serverless needs a shared store.
2. XFF spoofing rotates throttle buckets; chunked-without-length 413 bypass
   (master-audit residual) still applies at the edge.
3. Docker image build unverified (no Docker in sandbox); `.dockerignore`
   correctness by inspection (unchanged from master audit).
4. Lockfile/digest pre-live advice and Render-disk audit persistence stand
   from the master audit.
5. This audit did not re-fuzz the engine/detectors/RAG/PatchProof — covered
   by the master audit + suite (101 passed then; backend suite not re-run
   here since no backend file changed).

## Final summary

- New findings: **3 fixed** (1 Medium, 1 Low, 1 Low-hardening) + 1 Info
  (rotation advice, no code change).
- Re-verified holding: F1–F8 fixes, session/cookie/CSRF design, gateway
  caps, secret hygiene, `npm audit` 0 vulns.
- Not verified: multi-instance throttle/revocation propagation; Docker
  build effect.
- Build status: lint + typecheck + prod build green; live UI flow green.
