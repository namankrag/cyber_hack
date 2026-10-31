# SecureAI — Completion Checklist & Build Prompt (get everything working)

Single source of truth for finishing the project. Part 1 is the honest status
(verified vs. unverified). Part 2 is the checklist to reach "everything works".
Part 3 is the frontend↔backend accuracy matrix. Part 4 is a detailed,
copy-paste **completion prompt** for an agent/teammate running in an environment
where the Next.js frontend can actually be built and opened in a browser.

---

## Part 1 — Status snapshot (what is and isn't verified)

| Area | State | Evidence |
|---|---|---|
| Backend engine + all routes | ✅ WORKING, verified | 223 pytest passing; every `/v1/*` route returns 200 in a smoke test |
| PS-1 (runtime) + PS-2 (code) requirements | ✅ COMPLETE | `docs/JUDGING_CHECKLIST.md` §C/§D maps each to a file |
| Indirect-injection defense + MCP response sanitization | ✅ WORKING | `tests/test_injection_defense.py`, `tests/test_mcp_injection_defense.py` |
| RAG corpus (offline, no model download) | ✅ FIXED today | `agentshield/rag/embedding.py`; RAG/agent/admin tests green |
| Trust/replay demo (needs harness secret) | ✅ FIXED today | entrypoint auto-gen + render/compose set it; verified no-token→deny, token→allow, replay→deny |
| Frontend ↔ backend wiring (routes, proxy, types) | ✅ ACCURATE (static) | every page → a real route via `/api/[...path]`; see Part 3 |
| **Frontend interactivity (clicks/taps)** | ❌ **NOT WORKING** | app-wide: HTML renders, links navigate, but no button/toggle fires, no console errors → client hydration not executing |
| **Frontend served in deploy** | ❌ **MISSING** | deploy configs run only the FastAPI gateway; there is **no Next.js server process** |
| Document Lab UI renders new `ps1.ingestion` fields | ⚠️ PARTIAL | backend exposes hidden-segments/risk/agent-text; UI not yet showing them |

**Architecture (important):** the browser talks ONLY to the Next.js server,
which serves the pages and proxies `/api/*` to the FastAPI gateway
(`AGENTSHIELD_API_URL`, default `http://127.0.0.1:8000`, see
`web/src/app/api/_lib/proxy-auth.ts`). The Next app MUST run as its own Node
process (`next start`). Running only uvicorn serves the API but **no UI**.

**Root-cause hypothesis for "nothing clickable, no errors, both surfaces":**
client hydration is not running. Most likely because the deployed view is not
served by a real `next start` process (so the JS bundle never loads — visible as
`/_next/static/*.js` 404s in the Network tab, not the Console). The component
code itself is correct (handlers wired, `type="button"`, no CSS overlay, no CSP
blocking scripts, valid root layout) — so this is a serving/build issue, not a
code bug. Secondary suspect if assets DO load (200): the
`experimental.optimizePackageImports` flag in `next.config.ts`.

---

## Part 2 — The checklist to "everything works"

### A. CRITICAL — make the frontend interactive (the blocker)
- [ ] Open the failing page → DevTools → **Network** → filter `_next`. Record
      whether `/_next/static/chunks/*.js` are **200** or **404/403**.
- [ ] **If 404/403** (assets not served): run the Next app as its own process
      (`next start` / `next dev`); do NOT route `/_next/*` through FastAPI. See §B.
- [ ] **If 200 but dead:** remove the `experimental.optimizePackageImports`
      block from `next.config.ts`, rebuild, retest. If still dead, bisect by
      temporarily simplifying the root providers and re-adding.
- [ ] **Confirm fixed:** marketing nav close (X) toggles; workspace sidebar
      open/close, user menu, command palette (⌘K), and buttons all respond on
      desktop and mobile widths.

### B. Deploy wiring — serve the frontend for real (so the demo URL works)
- [ ] Add `web/Dockerfile` (multi-stage: `npm ci` → `npm run build` → `next start`).
- [ ] Add a `web` service to `docker-compose.yml`: build `web/`, expose 3000,
      set `AGENTSHIELD_API_URL=http://gateway-a:8000` (compose DNS),
      `NODE_ENV=production`, and the admin env (`ADMIN_PASSWORD`, `ADMIN_KEY`).
- [ ] Add the web service to `render.yaml` / `railway.json` (or a single
      reverse proxy that serves the Next app and routes `/api` to the gateway).
- [ ] Decide the public entrypoint: users hit the **Next** service (port 3000),
      which proxies to the gateway — not the gateway directly.
- [ ] Set `PUBLIC_ORIGIN` for the proxy same-origin check (see `proxy-auth.ts`).

### C. Feature completeness (high demo value, low effort)
- [ ] Document Lab UI: render `ps1.ingestion` (hidden_segments, decoded_segments,
      quoted_segments, risk_score, signals, agent_text_preview) in
      `web/src/components/workspace/document-lab-client.tsx`. Backend already
      returns them.
- [ ] Click-through the 3 star pages (Document Lab, MCP Gateway, Overview) end to
      end against the running gateway.

### D. Operational correctness
- [ ] `AGENTSHIELD_HARNESS_SECRET` set in the deploy env (entrypoint auto-gens one
      if unset; set explicitly for persistence across restarts/replicas).
- [ ] RAG: confirm the Corpus page loads (offline embedding, no download).
- [ ] Re-stamp the PatchProof `patchproof/fixtures.json` digest and the policy
      `AGENTSHIELD_POLICY_SHA256` if any fixture or `policies/default.yaml` was
      edited (otherwise startup/tests fail on the integrity pin).
- [ ] `python -m pytest -q tests/` and `cd patchproof && python -m pytest -q`
      both green on the image that will be deployed.

### E. Judging readiness
- [ ] `docs/JUDGING_CHECKLIST.md` reviewed; 90-sec script matches the live UI.
- [ ] Trust/replay panel works (harness secret present).
- [ ] Rehearse the demo on the deployed URL, not localhost.

---

## Part 3 — Frontend ↔ backend accuracy matrix

| Page (frontend) | Backend route(s) | Wiring | Backend verified |
|---|---|---|---|
| Document Lab | `POST /v1/document/analyze`, `GET /v1/document/samples` | ✅ | ✅ hidden caught, decisions, ps2 verified |
| MCP Gateway | `POST /v1/mcp/demo`, `/v1/mcp/call`, `/v1/trust/demo` | ✅ | ✅ (trust needs harness secret) |
| Overview | `GET /v1/metrics`, `/v1/bench/latest`, `/v1/evidence` | ✅ | ✅ |
| Homepage try-a-decision | `POST /v1/check` | ✅ | ✅ |
| Security Evidence | `GET /v1/evidence/scorecard`, `/v1/evidence/reports` | ✅ | ✅ |
| Approval Center | `GET /v1/approvals(/pending)`, `POST /v1/approvals/decide`, `/{call_id}` | ✅ | ✅ |
| Red Team Lab | `GET /v1/redteam/scenarios`, `POST /v1/redteam/run` | ✅ | ✅ on/off/comparison |
| Policy Manager | `GET /v1/policy` | ✅ | ✅ |
| Audit & Forensics | `GET /v1/audit` | ✅ | ✅ |
| Activity/Agents/Analytics/Corpus/Threats/Tools/Settings | `/v1/agents`, `/v1/threats`, `/v1/tools`, `/v1/corpus`, `/v1/enforce`, admin | ✅ | ✅ respond |

Response shapes are typed in `web/src/lib/api/types.ts` and match the backend
models. The **only** unverified layer is in-browser rendering/interactivity
(Part 2 §A).

---

## Part 4 — Detailed completion prompt (run where the frontend can be built)

> Copy everything below to an agent working in a checkout of `cyber_hack`
> (branch `tiktoktik`) on a machine with Node + Python where `cd web && npm ci`
> and a browser are available.

> **Context.** Monorepo: `agentshield/` (FastAPI gateway + policy engine, PS-1),
> `patchproof/` (PS-2), `secureai/` (integration), `web/` (Next.js 16.4.3
> frontend — a MODIFIED Next build; READ `web/AGENTS.md` and the guides it points
> to before changing any frontend code). The browser hits the Next server, which
> serves pages and proxies `/api/*` to the gateway via
> `web/src/app/api/[...path]/route.ts` (`AGENTSHIELD_API_URL`, default
> `http://127.0.0.1:8000`). Backend is fully green (223 tests). The problem:
> the frontend renders HTML but is NOT interactive — app-wide, no console
> errors, buttons/toggles dead, links still navigate. Component handlers are
> correct; there is no CSP and no click-eating overlay. Do NOT rewrite working
> code; extend and fix minimally.
>
> **Task 1 — make the frontend interactive (blocker).**
> 1. `cd web && npm ci`. Start it: `npm run dev` (and separately a built run:
>    `npm run build && npm run start`). In the browser, DevTools → Network →
>    filter `_next`, reload. Note if `/_next/static/chunks/*.js` are 200 or 404.
> 2. If assets 404 in the deployed/built path: the app isn't being served by a
>    real `next start`. Fix the serving (Task 2), not the code.
> 3. If assets are 200 but still nothing hydrates: remove
>    `experimental.optimizePackageImports` from `next.config.ts`, rebuild, retest.
>    If still dead, temporarily reduce the root tree (providers) to bisect the
>    component that aborts hydration; fix it per the Next 16 guide. Keep all
>    `"use client"` directives intact.
> 4. Done when: the marketing nav X/close toggles, and in `/workspace` the
>    sidebar open/close, overlay-close, user menu, command palette (⌘K), role
>    switcher, and page buttons all respond at desktop AND mobile widths.
>
> **Task 2 — serve the frontend in the deploy (so the public URL is interactive).**
> Add a production Next server and make it the public entrypoint; the gateway
> stays internal. Minimal, verified pieces:
> - `web/Dockerfile` (multi-stage): `FROM node:20-slim` → copy `web/`,
>   `npm ci`, `npm run build`, `EXPOSE 3000`, `CMD ["npm","run","start"]`
>   (use Next 16's standalone output if the guide recommends it).
> - `docker-compose.yml`: add service `web` (build `./web`), `ports: 3000:3000`,
>   `environment: AGENTSHIELD_API_URL=http://gateway-a:8000`,
>   `NODE_ENV=production`, plus `ADMIN_PASSWORD`/`ADMIN_KEY`. `depends_on: gateway-a`.
> - `render.yaml` / `railway.json`: add the web service (or a reverse proxy that
>   serves Next and routes `/api` → gateway). Public traffic hits the web
>   service, not uvicorn.
> - Set `PUBLIC_ORIGIN` to the public URL so the proxy same-origin check passes.
> Verify: open the web service URL; confirm the pages load AND are interactive,
> and that `/api/v1/health` (proxied) returns 200.
>
> **Task 3 — Document Lab UI: show the ingestion findings.**
> In `web/src/components/workspace/document-lab-client.tsx`, read
> `response.ps1.ingestion` and render: a "Hidden/obfuscated content" panel
> listing `hidden_segments` (reason + text) and `decoded_segments`, the
> `risk_score` + `signals`, the `quoted_segments`, and the `agent_text_preview`
> (what the model is allowed to see). Add the matching type to
> `web/src/lib/api/types.ts`. Keep styling consistent with the page.
>
> **Task 4 — operational correctness + verification.**
> - Ensure `AGENTSHIELD_HARNESS_SECRET` is set in every run env (container
>   entrypoint auto-generates one; set it explicitly in render/compose).
> - If any fixture or `policies/default.yaml` changed: re-stamp
>   `patchproof/fixtures.json` (its tool) and update `AGENTSHIELD_POLICY_SHA256`.
> - Run `python -m pytest -q tests/` and `cd patchproof && python -m pytest -q`;
>   both must be fully green on the deploy image.
> - Smoke the proxied API from the web service: `/api/v1/health`,
>   `/api/v1/policy`, `POST /api/v1/document/analyze {"sample_id":"poisoned-vendor-report"}`,
>   `POST /api/v1/trust/demo` (expect the 3-row no-token/token/replay result).
>
> **Acceptance criteria (everything works).**
> - Every page in Part 3 loads AND is fully interactive on the deployed URL.
> - The three star demos (Document Lab, MCP Gateway incl. trust/replay, Overview)
>   run live end to end.
> - Document Lab shows the ingestion/hidden-content findings.
> - Both pytest suites green; trust/replay works; RAG corpus loads offline.
> - No regressions; changes are minimal and respect the modified Next 16.
>
> **Constraints.** Reuse the existing stack; no unrelated rewrites; respect the
> modified Next 16 (read `web/AGENTS.md`); coordinate pushes on the shared
> `tiktoktik` branch; never commit real secrets.

---

### Why I (the cloud agent) could not finish the frontend here
The sandbox has no `web/node_modules` installed and no browser, and this Next
build is modified — so I can verify the backend and the static wiring, but I
cannot build/run the Next app or confirm an in-browser fix. Pushing an unverified
frontend/build change to the shared demo branch would risk breaking a working
build before judging, so this prompt hands the browser-dependent steps to a run
where they can be verified. Everything backend-side is already done and green.
