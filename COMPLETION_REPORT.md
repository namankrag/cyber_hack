# AgentShield Web Console — Completion Report

**Date:** 2026-10-31
**Scope:** Next.js App Router front end in `web/`, backed by the FastAPI gateway in `agentshield/gateway/`.
**Build status:** `npm run typecheck`, `npm run lint`, and `npm run build` all pass.
**Runtime:** web dev server on `http://127.0.0.1:3000`, gateway on `http://127.0.0.1:8000`.

---

## 1. Fully implemented

### Public experiences (preserved marketing site)

| Area | Status |
| --- | --- |
| Homepage sections (`#home`, `#platform`, `#how-it-works`, `#security`, `#documentation`, `#request-demo`) | Preserved, responsive, unchanged visual identity |
| Product explanation / how it works / architecture and threat-model content | Present in the homepage sections and linked in-repo docs |
| Documentation section | Code samples, quickstart and reference links rendered from `docs-code.tsx` |
| Decision Lab | Interactive scripted pipeline, explicitly labelled `SANDBOX`; not presented as live backend output |
| Request Demo | Form now composes a pre-filled `mailto:` request to `security@agentshield.dev` and tells the user to send it; no simulated success |
| Navigation | Desktop and mobile menus, active-section highlighting, keyboard/Escape handling, focus return, skip link |
| Workspace entry points | Added to desktop nav, mobile menu and homepage footer |
| Footer status | Replaced the static "All systems operational" claim with a link to live workspace status |

### Workspace (13 pages, all wired to the gateway through the server proxy)

| Page | Implemented behavior |
| --- | --- |
| **Overview** (`/workspace`) | Live metrics for `1h/24h/7d/30d/all`, security pipeline, metric cards with real sparklines, signal strip, decision distribution and volume buckets, pending approvals, recent threats and audit records, enforcement ON/OFF toggle with confirmation and audit-visible change |
| **Analytics** (`/workspace/analytics`) | Deeper live read of the same metrics: per-decision trends, real sparklines, provenance split, detector breakdown, top tools/sessions and recent decisions; shares the header time window with Overview |
| **Activity Monitor** (`/workspace/activity`) | Audit search/filter/detail, provenance and decision badges, `POST /v1/check` boundary-check form with real gateway verdict and reason list |
| **Agents & Sessions** (`/workspace/agents`) | Sessions projected from audit `metadata.agent` + `session_id`, search, per-session tool/provenance/count inspector |
| **Tools & Permissions** (`/workspace/tools`) | Active policy tool inventory joined with recent audit usage, requirements/sources/sensitivity, search and detail |
| **Threat Intelligence** (`/workspace/threats`) | Real detector findings from the audit trail, severity/category filters, classification basis, explicit "no fabricated intelligence" note |
| **Approval Center** (`/workspace/approvals`) | Pending/decided views, approve/deny with confirmation and approver field, args-hash and single-use explanation, `409` re-decision surfaced, no permanent-access implication |
| **Policy Manager** (`/workspace/policy`) | Read-only YAML, defaults, evaluation order, per-tool permissions, SHA-256 digest, provenance state, explicit explanation that no publish endpoint exists |
| **Red Team Lab** (`/workspace/redteam`) | Admin-gated scenarios, editable payload, isolated ON/OFF run, comparison panel, stage breakdown, `global_enforcement_unchanged` confirmation, dedicated `audit.redteam.jsonl` |
| **RAG Corpus Explorer** (`/workspace/corpus`) | All docs with `trust: UNTRUSTED` banner, language/label/channel filters, search, document inspector, confirmed re-ingest action (backend currently fails, see blockers) |
| **Audit & Forensics** (`/workspace/audit`) | Filterable/searchable audit table, approval chain, reasons, detectors, arguments/metadata/full-record JSON, copy actions |
| **Security Evidence** (`/workspace/evidence`) | Historical artifacts separated from live runtime evidence, freshness notes, Semgrep/pytest baseline, live `/v1/evidence` snapshot |
| **Gateway & Configuration** (`/workspace/settings`) | Live runtime status, endpoint catalog with auth level, read/admin capability probes, detector and provenance state, config actions, environment-variable guidance |

### Cross-cutting behavior

- **Typed API layer:** `src/lib/api/types.ts`, `client.ts`, `errors.ts`, `format.ts`. All workspace data goes through the existing `/api/[...path]` proxy; no direct browser-to-gateway calls.
- **Workspace shell:** navy sidebar grouped into Overview / Security / Testing / System, sticky header with breadcrumb, gateway and enforcement indicators, user menu, and a navigation-only command palette (`⌘K` / `Ctrl+K`). The time-window control lives in the header and appears only on Overview and Analytics, backed by a shared `TimeWindowProvider`.
- **Design system:** the workspace UI is a single scoped stylesheet (`src/app/workspace.css`) with cream/navy/purple/lime tokens, a genuine 12-column desktop grid, 16–22 px radii, restrained borders/shadows, subtle motion, and a `prefers-reduced-motion` fallback. Settings deep links (`#health`, `#configuration`) scroll to their sections.
- **Polling:** `useLiveData` pauses when the tab is hidden, keeps the last good snapshot marked stale on failure, keys snapshots by request path, and exposes manual refresh.
- **States:** loading, empty, error, stale, disconnected gateway, malformed/non-JSON response, timeout, `401/403/404/409/5xx` all render distinct UI.
- **Secret handling:** gateway URL and API/admin keys stay server-side in the proxy. A production bundle scan found no key values, only environment-variable names in help text.
- **Accessibility/responsive:** labelled controls, `aria-live` regions, dialog roles, focus handling, visible focus styles; verified no horizontal overflow at 390 px and correct menu open/close behavior.
- **Proxy routing:** read endpoints use `AGENTSHIELD_API_KEY`; `v1/admin/*`, `v1/approvals/*`, `v1/redteam/*` use `AGENTSHIELD_ADMIN_KEY` (verified with mock keys).
- **Quality gates:** strict TypeScript, ESLint flat config, production build succeeds; all 13 workspace routes and the homepage were smoke-tested in headless Chromium with zero console errors/exceptions.

---

## 2. Partially implemented

| Item | What exists | Limitation |
| --- | --- | --- |
| **Public Decision Lab** | Fully interactive, accessible, clearly marked `SANDBOX` | It is a scripted demonstration, not connected to `POST /v1/check`. This preserves the original marketing component but means public results are illustrative, not live. |
| **Request Demo** | Working `mailto:` handoff with all form fields pre-filled, plus fallback address | No backend/CRM endpoint exists; delivery depends on the visitor's mail client. It no longer claims a request was received. |
| **Workspace authentication/roles** | Admin capability inferred by probing admin-gated endpoints; secrets held server-side | No login, session, or role model. In the current dev backend `auth_required` is `false`, so the UI labels it "open dev gateway". |
| **Agents & Sessions** | Real projection from audit metadata | No dedicated sessions/agents store; only sessions present in the retained audit sample appear. |
| **Threat Intelligence** | Real detector findings, severity and presentation categories | Categories are presentation grouping only; no external threat feed or IOC enrichment. The page states this. |
| **Approval expiry** | Expiry field rendered when available | Backend returns `expired: null`; the UI shows "unknown" rather than inventing a deadline. |
| **Security Evidence** | Historical artifacts and live state shown separately with source/commit/reproduce commands | Historical reports are committed artifacts served by the backend, not re-executed on page load (intentional and labelled). |
| **RAG Corpus reset** | Confirmed action wired to `POST /v1/admin/reset`, error state rendered | Cannot complete until the backend environment can import `chromadb` (see blockers). |
| **Audit/approval pagination** | Limit-based queries up to backend caps (500) | No cursor pagination; pages read the capped sample and say so. |
| **Documentation** | Full documentation section on the homepage with code and links | No standalone `/docs` route; content lives in the marketing page. |
| **Policy Manager** | Read-only view with digest and integrity state | Policy publishing is intentionally absent because no secure publish endpoint exists. |
| **Automated web tests** | Typecheck, lint, production build, scripted browser verification | No committed unit/E2E suite; verification was manual/CDP-driven. |

---

## 3. Backend blockers

| Blocker | Impact | Evidence |
| --- | --- | --- |
| **`chromadb` not installed** | `POST /v1/admin/reset` returns `500 Internal Server Error`; corpus re-ingest cannot run | `ModuleNotFoundError: No module named 'chromadb'` from `agentshield/rag/store.py`. The venv also lacks `langgraph`, `langgraph-checkpoint-sqlite` and `mcp` from `requirements.txt`; the host runs Python 3.14, so wheel availability for `chromadb==1.5.9` is unconfirmed. |
| **No policy publish endpoint** | Policy Manager must stay read-only | No write/publish route exists in `agentshield/gateway/app.py`. |
| **No auth/session/role endpoints** | Workspace cannot implement sign-in, users, or RBAC | Only API-key dependencies (`require_api_key`, `require_api_admin`) exist. Admin status is inferred by probing. |
| **No demo-request endpoint** | Demo form cannot submit to the product backend | No route accepts demo requests; `mailto:` is the honest fallback. |
| **No dedicated agents/sessions store** | Session history is limited to audit metadata | `/v1/agents` is a projection over the audit trail. |
| **No threat-feed integration** | Threat page can only show detector findings | No IOC/enrichment endpoint exists. |
| **No latency/cost fields in the audit schema** | Overview and Activity cannot show processing time or cost | The UI deliberately omits them and explains why. |
| **Approval expiry not populated** | Expiry state cannot be displayed | `/v1/approvals` returns `expired: null`. |
| **No cursor pagination** | Large histories are sampled | Endpoints cap `limit` (audit max 500; other lists max 500). |

---

## 4. Unverified behavior

These were not exercised against a production-like environment and should not be treated as proven:

1. **Real keyed authentication** — 401/403 UI states were not tested against a gateway with `AGENTSHIELD_API_KEY`/`AGENTSHIELD_ADMIN_KEY` actually enforced. Proxy key routing itself was verified with mock keys.
2. **LLM detector path** — only the `heuristic` detector is installed; LLM detector rendering and failures are untested.
3. **HMAC provenance enforcement** — current backend runs `provenance_dev_mode: true`; the verified-token path is untested.
4. **Corpus reset success path** — blocked by missing `chromadb`; only the 500 error state is verified.
5. **Demo email delivery** — `mailto:` handoff is verified in-browser; actual delivery to `security@agentshield.dev` is outside the app.
6. **Concurrent approval decisions** — sequential single-use behavior and `409` on re-decision are verified; a simultaneous double-approve race is untested.
7. **Long-running polling/stale recovery** — hidden-tab pause and stale-on-error logic were reviewed and short-tested, not soak-tested.
8. **Cross-browser and assistive technology** — verified in headless Chromium only; Firefox/Safari and full screen-reader passes are untested.
9. **Tablet breakpoints** — 390, 768, 1024, 1200 and 1440 px were checked across all workspace routes; widths between those points were not exhaustively tested.
10. **High-volume performance** — datasets were small (14 corpus docs, tens of audit entries); rendering at the 500-entry cap was not benchmarked.
11. **Production deployment** — `next start` served `/` and `/workspace` successfully after the final build, but no container/hosted deployment was performed.

---

## Verification summary

Commands run from `web/`:

```bash
npm run typecheck   # pass
npm run lint        # pass
npm run build       # pass, 16 routes generated
```

Browser checks (headless Chromium via CDP):

- Homepage and all 13 workspace routes at 1440, 1200, 1024, 768 and 390 px: zero console errors/exceptions and zero document-level horizontal overflow.
- Desktop layout confirmed as a real 12-column grid; the security pipeline renders five nodes in one row and the header controls share one vertical center line.
- Command palette opens with `⌘K`/`Ctrl+K`, filters results, closes on Escape/backdrop, and performs navigation only. User/settings menu opens and closes without navigating.
- Header time-window control is present on Overview and Analytics only and switching to `7D` refetches the live metrics.
- Settings `#configuration` deep link scrolls to the configuration card with header offset; nav active state follows the hash.
- Workspace drawer: `aria-expanded` and `.ws-sidebar.is-open` toggle correctly; overlay appears.
- Boundary check through the UI returned a real `ALLOW` verdict for `search_web`.
- Red Team Lab run through the UI returned a real comparison with `global_enforcement_unchanged: true`; global switch restored to ON.
- Approval deny through the UI removed the pending item and appended the rejection; re-decision returned `409`.
- Enforcement OFF/ON through the UI changed the backend and the topbar badge stayed in sync; final state restored to ON.
- Corpus reset through the UI rendered the backend `500` error instead of a false success.
- Gateway stopped: workspace rendered `GATEWAY OFFLINE` / `502` states. Mock non-JSON gateway: rendered "not valid JSON" state.
- Proxy credential routing with mock keys: read endpoints received the read key; admin/approvals/redteam endpoints received the admin key.
- Bundle scan: no API key values or secret-like tokens in `.next/static`.

---

## Repository state

All work is **uncommitted**. Current `git status`:

```
 M .gitignore
 M agentshield/gateway/app.py
?? COMPLETION_REPORT.md
?? agentshield/gateway/evidence.py
?? agentshield/gateway/insights.py
?? agentshield/gateway/redteam.py
?? web/
```

`web/.gitignore` excludes `node_modules/`, `.next/`, build output, `next-env.d.ts`, `*.tsbuildinfo` and local env files. Root `.gitignore` now also excludes `audit.redteam.jsonl`.

### Run locally

```bash
# gateway
.venv/bin/uvicorn agentshield.gateway.app:app --port 8000 --host 127.0.0.1

# web
cd web && npm run dev
```

Optional server-side env for the proxy: `AGENTSHIELD_API_URL`, `AGENTSHIELD_API_KEY`, `AGENTSHIELD_ADMIN_KEY` (see `web/.env.example`). None are exposed to the browser.
