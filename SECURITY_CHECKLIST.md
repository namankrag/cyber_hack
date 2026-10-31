# Security checklist — AgentShield console + proxy

Tick what this audit proved; the operator duties at the end stay with whoever
hosts it. Machine-checked items name their evidence.

## Done and verified (this audit)

- [x] F1 privileged proxy routes need a valid admin session → live `401`
- [x] F2 cross-site POST rejected → live `403`
- [x] F3 encoded traversal rejected → live `404`
- [x] F4 oversized body rejected → live `413` (declared + measured caps)
- [x] 401s map to "Administrator login required", no key material in errors
- [x] CSRF: same-origin/referer gate on mutations; JSON-only bodies (`415`)
- [x] Admin cookie: `HttpOnly`, `SameSite=Lax`, `Secure` in prod, `Max-Age`
      set/cleared; session endpoint leaks no secrets, `no-store`
- [x] FA1 response headers on pages + API (`nosniff/DENY/strict-origin`),
      `X-Powered-By` removed → live `curl -I`
- [x] FA2 login throttling: 10 fails/10min/IP → `429`; success resets → live
- [x] FA3 logout revokes the token server-side; replay → `401` → live
- [x] Exact method+route allowlist; `%2f/%5c` + bad-segment rejection
- [x] Gateway `limit` capped (`1..500`) and `window` validated server-side
- [x] Approvals alias order; red-team run admin-gated + server-scenario-only
- [x] No `dangerouslySetInnerHTML`; no `NEXT_PUBLIC_*`; client uses `/api`
- [x] Git history + tree clean of secrets; `.env`/audit logs untracked+ignored
- [x] `npm audit` → 0 vulnerabilities; lint/typecheck/build green
- [x] Full role flow in a real browser session (CDP): wrong-pw, login,
      toggle OFF→ON, sign-out, expired-session notice; enforcement left ON

## Standing duties (not code — do these at deploy/demo time)

- [ ] Rotate the three provider keys in root `.env` after the hackathon demo
- [ ] Set a strong `ADMIN_PASSWORD` per environment; never reuse the local one
- [ ] Serve only over HTTPS (HSTS comes from TLS termination, not the app)
- [ ] Set `PUBLIC_ORIGIN` to the real origin in production
- [ ] Keep `AGENTSHIELD_ADMIN_KEY` server-side only; keep `/docs` gated outside demos
- [ ] Attach persistent storage (or log shipping) for the JSONL audit trail
- [ ] Edge rate limiting + body caps in front of both servers
- [ ] Re-run `pip-audit`/lockfile review before going live (chroma watch)
- [ ] Pin the base image digest (Renovate) before live
- [ ] Multi-instance hosting needs a shared throttle/revocation store
