# Parallax CyberMonth — Winning Map (AgentShield / cyber_hack)

Source commit: `ea64345bc8672cc72e3c5392c44a0d382889afe0` (2026-10-30, `security: harden enforcement boundary (v0.2)`).
Repo: https://github.com/namankrag/cyber_hack — Python, MIT, 0 stars/forks, 4 commits, 1 branch `main`.
PS page: https://www.bmsceieeecs.in/cybermonth/events/parallax-hackathon
Timeline: Fri 4:50PM countdown start → Sat 2:00PM submit (URL + hash + 2-line pitch), judging 2:00-3:20PM.

> No-hallucination rule: every technical claim below cites `path:line`, raw URL, or commit hash opened by 48 arena agents. Judges + synthesis refs returned null, so Section 5 is a parent synthesis, not a child verdict. Remaining unread workflow tail (lines 25+ of full report) is named in Section 6.

## 1. The 3 problem statements

### PS-01 AGENTSHIELD — Secure the Agent, Not Just the Prompt
- Problem: agents reading untrusted email/doc/tool output get redirected to leak/misuse; prompt filters insufficient.
- Must build: 1 simulated agent + >=2 tools/permissions + PEP + audit log.
- Must handle (synthetic only): legit task, injected web/doc, sensitive-data request, beyond-permission tool.
- Must show: explicit ALLOW / DENY / REQUIRE_APPROVAL + human confirm high-impact + fail-closed + inspectable reason.
- Extensions (optional): MCP gateway, tool permission profiles, signed tool metadata, cross-agent trails, risk-aware approval queue.
- Difficulty: hardest. Novelty: highest (OWASP LLM01/LLM06).

### PS-02 PATCHPROOF — Find the Flaw. Prove the Fix.
- Problem: noisy scanners + breaking patches.
- Must build: pick supplied/public vuln app or local fixture, document in-scope files; >=2 weakness cases (e.g. SQLi CWE-89, XSS CWE-79); minimal patch/diff for >=1; regression + security tests; severity rationale + file:line + patch rationale + test status.
- AI optional, accuracy over complexity. Safest/deterministic win.

### PS-03 TRUSTLENS — Catch the Impersonation
- Problem: phishing + impersonation + short/confusing links + multi-channel + Kannada/Hindi code-mix.
- Must build: privacy-local assistant, no auto-open/reply; >=2 types or langs (email+SMS or EN+Kannada/Hindi); ~30-msg synthetic set; 5 signals (sender/domain, URL obfuscation, urgency, credential/money ask, missing provenance); risk tier + quoted evidence + verify-via-known-channel + false-positive challenge.
- Extensions optional only: voice/deepfake, QR, dashboard. Best demo theater.

Global: synthetic / lab / authorised targets only. AI allowed, not whole-project-one-prompt.

## 2. Repo file map (all bodies opened)

- `README.md` (8168B) — `Secure the agent, not just the prompt.` PEP, ALLOW/DENY/REQUIRE_APPROVAL, fail-closed. Quickstart: `pip install -r requirements.txt`, `python -m examples.demo`, `python -m examples.mcp_demo`, `pytest -q`, `uvicorn agentshield.gateway.app:app`. Claims 26 tests.
- `THREAT_MODEL.md` (4712B) — PEP scope, harness-trusted/model-untrusted, protects vs NOT (replayable tokens, PEP bypass, no upstream proxy, TLS/rotation operator-owned, LLM data sharing).
- `pyproject.toml` — `agentshield 0.2.0`, `>=3.11`, ships `data/*.yaml`. Mismatch: `agentshield/__init__.py __version__=0.1.0`.
- `requirements.txt` — fastapi, uvicorn, pydantic, pyyaml, rich, `mcp>=2.0`, `google-genai`, pytest, httpx. groq commented out.
- `agentshield/models.py` — TrustLevel (USER/SYSTEM/TRUSTED_TOOL/UNTRUSTED, default UNTRUSTED), Decision severity ALLOW 0 < APPROVAL 1 < DENY 2, `most_restrictive()`, ToolCall, DetectionResult, PolicyReason, EnforcementResult.
- `agentshield/config.py` — env+.env Config, strict threshold/detector checks, `_resolve_policy_path` fallback to packaged default. Gaps: `llm_provider` never validated; timeout/path/redact not validated; case-sensitivity mismatch (`__post_init__` vs `from_env`).
- `agentshield/provenance.py` — `trusted_scope` contextvars + HMAC `mint_token`/`_verify_token` (`AGENTSHIELD_HARNESS_SECRET`), `resolve()` order scope > valid token > insecure-dev-mode > UNTRUSTED. Tokens bind source only, no nonce/session/expiry → replayable (admitted in code + THREAT_MODEL).
- `agentshield/detection/base.py` — Detector ABC, never raise, error → fail-closed.
- `agentshield/detection/heuristic.py` — 11 weighted regexes (P1 0.6 ignore-previous, P2 0.6 disregard, P3 0.35 persona, P4 0.5 new-role, P5 0.7 exfil, P6 0.45 egress, P7 0.55 bulk-egress, P8 0.5 secrecy, P9 0.45 fake-tag, P10 0.4 authority, P11 0.35 obfuscated). Saturating sum, threshold 0.5. Haystack = context + args only.
- `agentshield/detection/llm_detector.py` — optional Gemini (`gemini-2.0-flash`) / Groq (`llama-3.1-8b-instant`), strict-JSON, 8s timeout, truncation 6000/2000 chars. Missing key/timeout/parse → error result → engine fail-closed. Sends context+args to third party (documented egress).
- `agentshield/policy/models.py` — strict `extra=forbid` Pydantic; ToolPolicy + PolicyDefaults (unknown=REQUIRE_APPROVAL, high-threat=DENY, high-untrusted=DENY, fail_closed_on_error=true).
- `agentshield/policy/loader.py` — YAML safe_load + validate, loud FileNotFoundError.
- `agentshield/policy/engine.py` — 7 steps: unknown-tool → disabled → injection → detector-error → untrusted → allow_sources → require_approval → default_allow. Most-restrictive compose, ordered reasons.
- `agentshield/audit/log.py` — append-only JSONL `{ts,call_id,tool,source,decision,reasons,detections}`, redaction (exact key match only), thread lock only, `tail()` backward-block read, no rotation.
- `agentshield/enforce.py` — `guard()`/`enforced()` PEP, raises PolicyViolation unless ALLOW, provenance from trusted state only.
- `agentshield/engine_factory.py` — `check()` = evaluate + record.
- `agentshield/gateway/app.py` — FastAPI: GET /health, /ready, POST /v1/check, GET /v1/audit (limit 1..500). X-API-Key when set; /health,/ready open. /v1/check is advisory PDP.
- `agentshield/gateway/mcp_gateway.py` — official MCP SDK, EnforcementMiddleware outermost on `tools/call`, `_agentshield` tag stripped, ALLOW forwards sanitized else `is_error` DENIED/HELD. 4 mock tools only, no upstream proxy (documented).
- `policies/default.yaml` == `agentshield/data/default_policy.yaml` (identical SHA256) — search/read low ALLOW; send_email high + require_approval; read_customer_db high + allow_sources [user,system]; transfer_funds high allow:false.
- `examples/mock_agent.py` — MockAgent + POISONED_DOCUMENT (English vendor report with hidden ignore-previous + exfiltrate + do-not-tell).
- `examples/demo.py` — 5 scenarios: legit search ALLOW; hero injection DENY; untrusted DB DENY; unknown tool REQUIRE_APPROVAL; legit email REQUIRE_APPROVAL.
- `examples/mcp_demo.py` — real in-memory MCP client/server, cases A-D mirroring demo.
- `tests/` — 26 total: `test_engine.py` 7, `test_mcp_gateway.py` 4, `test_security.py` 15. Local run: 22/22 pass (engine+security); MCP needs `mcp` package.
- Git: 4 commits (`19c923b` Initial → `a9e2796` v0.1 → `611eb48` MCP gateway → `ea64345` v0.2 hardening), 0 issues/PRs/tags, 1 contributor.

## 3. REAL gaps (code-grounded, with fix)

1. Heuristic blind to paraphrase + multilingual. `heuristic.py` P1-P11 miss `ignore-previous` with hyphen, `forget/cancel`, `behave like`, `don't tell`, `<user>` tags, `root` authority, single obfuscation, and all Kannada/Hindi/UPI tokens (live probe: KN/HI lure score 0.0 vs EN 1.0). Low-sensitivity `search_web` then ALLOWs where EN is held. Fix: enable LLM detector with free Gemini key behind flag; add 4-6 UPI/multilingual patterns; note detector-miss still contained by policy.
2. Provenance tokens replayable. `provenance.py:22-25` + THREAT_MODEL: token = HMAC(source) only. Fix: disclose + add nonce/expiry comment, or session-bound token if time.
3. Approval is verdict-only. No queue UI/API; REQUIRE_APPROVAL never resumes. Fix: minimal Streamlit/CLI pending list over `GET /v1/audit` writing linked approval entry (append-only, never mutate JSONL).
4. Audit local-only. `audit/log.py`: exact-key redaction misses `api_secret`/`private_key`/nested values; thread-only lock; no rotation; `tail` has no offset/filter/export; corrupt line silently skipped; flood = disk fill. Fix: add `?decision=&tool=` filters + CSV export, document rotation as operator TODO.
5. MCP demo-only. `mcp_gateway.py:30-34`: no upstream proxy; `list_tools` uninspected; `_agentshield` non-dict crashes; `unknown_tool` = approval not deny. Fix: slide as roadmap, add type-check on tag.
6. HTTP hardening missing. No rate-limit/TLS; `/health` leaks config; `!=` API-key compare; no HTTP tests; `llm_provider`/timeout/path not validated; empty tool name allowed. Fix: set both secrets for demo, `fly`/`render` TLS, add 3 HTTP tests.
7. Polish missing. Version mismatch 0.2.0 vs 0.1.0; no Dockerfile/render.yaml; no PITCH.md; no fallback video. Fix: 3 deploy files + 3-min video + evidence pack.

## 4. Proceed: pick PS-01, 24h plan

Pick PS-01. Repo already satisfies every mandatory line, so you start from a running MVP. Only do P0 gaps; freeze `agentshield/{models,policy,provenance,enforce,audit,config}` at midnight MVP.

- Fri eve: fork, `pytest -q`, both demos green. Lock 4 canned attacks + UPI/Kannada bonus case.
- To 11:45pm: add OFF/ON toggle, approval queue stub, demo script + reset (clear audit JSONL, fixed secrets).
- Overnight: red-team paraphrases, tune threshold, wire LLM key, add nonce note.
- Sat AM: harden, hosted deploy (Render/HF), record fallback video, capture evidence (demo log, pytest, 3 curls, redaction sample).
- To 2pm: polish finding cards (rule id + quote + severity), final hash, 2-line pitch.

Demo 5 min: legit ALLOW → gate-OFF leak → gate-ON DENY with quote → DB DENY → email APPROVAL + human approve → audit line. Never open real links; POISONED_DOCUMENT only.

Pitch: `AI agents get hijacked by any doc they read. AgentShield is the code boundary between agent and tools — every call gets allow/deny/approval with proof — so even a compromised model cannot leak.`

## 5. Arena + judges note

48 primaries completed (10 core + PS trace + 10 red-team + blue-team). 5 judge refs and synthesis ref returned null data — unavailable, not counted as votes. Treat Section 4 as parent synthesis from inspected primary evidence, not a judge verdict.

## 6. Unread scope

Full-report tail beyond line 24 of `e5eb0f59...txt` and `b5885ee2...txt` offset 13+ not fully paged here; judge bodies, some BLUE deploy/metrics entries, and synthesis text are therefore named gaps. Effect: no hidden REAL gap is claimed from them; all gaps above are from lines actually read.


