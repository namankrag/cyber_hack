# Remediation summary — focused web audit (`final-merge`, local only)

What changed, why, and the before/after proof for each fix. All edits are
local working-tree changes; nothing committed, pushed, or deployed.

## FA1 — Security response headers on the Next.js frontend

Files: `web/next.config.ts` (only).
Change: `poweredByHeader: false` + `headers()` returning
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: strict-origin-when-cross-origin`, and a minimal
`Permissions-Policy`, applied to `/workspace/:path*` and `/api/:path*`.
Deliberately no `script-src` CSP (Next hydration needs inline scripts).

| Check | Before | After (live :3200) |
|---|---|---|
| `curl -I /workspace` | `X-Powered-By: Next.js`, no hardening headers | four headers present, no powered-by |
| `curl -I /api/health` | no hardening headers | four headers present |
| `npm run lint/typecheck/build` | — | all green, 19 routes |

## FA2 — Login attempt throttling

Files: `web/src/app/api/_lib/proxy-auth.ts`
(`clientIp/loginThrottled/noteLoginFailure/noteLoginSuccess`),
`web/src/app/api/admin/login/route.ts` (check + record + reset).
Change: >10 failed passwords per IP per 10 min → `429`; success clears the
bucket. Bounded 1024-entry map.

| Check | Before | After (live) |
|---|---|---|
| 11 rapid wrong passwords | 11 × `401` | 10 × `401`, then `429` |
| correct password (fresh bucket) | `200` | `200`, bucket reset |
| UI wrong-password path | inline "Invalid admin password", stays Operator | unchanged (CDP flow green) |

## FA3 — Logout session revocation

Files: `web/src/app/api/_lib/proxy-auth.ts`
(`revokeSessionToken`, revocation set consulted by `verifySessionToken`),
`web/src/app/api/admin/logout/route.ts` (revoke on logout).
Change: logout records the token signature as revoked until its embedded
expiry; verification rejects it. Set bounded (2048, expiry-purged). Code
documents the single-instance limit.

| Check | Before | After (live) |
|---|---|---|
| login → privileged route | `200` | `200` |
| logout | cookie cleared, token still valid | cookie cleared |
| replay old cookie: `/api/admin/session` | `authenticated:true` | `authenticated:false` |
| replay old cookie: privileged route | `200` | `401` |
| fresh login after logout | `200` | `200` |

## Regression proof (nothing else moved)

- F1–F4 probes re-pass (`401/403/404/413`); 401 hint text unchanged.
- CDP full role flow on the fixed build: every step green, enforcement left
  ON (verified `{"enforced":true}` afterwards).
- `:3000` untouched-code path still `200`; gateway :8000 never restarted,
  audit trail intact.
- `npm audit` → 0 vulnerabilities (unchanged).

## Residuals (accepted, documented in code + audit report)

- Throttle/revocation are per-instance memory; XFF is spoofable (backstop,
  not boundary); 10 genuine typos cost a 10-minute wait.
- Root `.env` keys: no code change; rotate after the demo.
