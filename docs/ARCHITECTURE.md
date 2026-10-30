# AgentShield end-to-end architecture (muse branch)

One system, three front doors, one decision brain. This doc is the map:
how a tool call flows, which component owns each guarantee, and how to run
everything. Code references are exact; behavior claims are test-pinned
(`pytest tests -q` → 145 passed).

## The one idea

An injection-proof filter is impossible, so AgentShield doesn't filter the
model — it governs the **tool-call boundary** below the model. Every call
becomes a `ToolCall(tool, arguments, source, context, metadata)` and gets
exactly one verdict: **ALLOW** < **REQUIRE_APPROVAL** < **DENY**
(most-restrictive wins, fail-closed). The verdict carries ordered reasons;
every verdict is audit-logged.

## Three front doors, one brain

| Door | Entry point | Enforcement character |
|---|---|---|
| In-process | `AgentShield.check()` + `guard()` in `agentshield/enforce.py` | Advisory PDP + unavoidable PEP: `guard` raises before the body runs (sync and async) |
| HTTP | `agentshield/gateway/app.py` (FastAPI) | PDP over the wire: `POST /v1/check`; admin `POST /v1/admin/enforce|reset`, evidence `GET /v1/evidence`, audit `GET /v1/audit`, liveness `GET /health`, `GET /ready` |
| MCP | `agentshield/gateway/mcp_gateway.py` (official MCP SDK middleware) | Protocol-layer PEP: every `tools/call` adjudicated pre-dispatch; `_agentshield` tag stripped before the tool sees it |

`POST /v1/check` is advisory by nature (a caller can ignore a verdict). The
unavoidable points are `guard()` and the MCP middleware: ALLOW runs, anything
else never reaches the tool body.

## Lifecycle of a call (all doors)

1. **Provenance** (`agentshield/provenance.py`): in-process `trusted_scope`
   wins; else a valid HMAC token (`AGENTSHIELD_HARNESS_SECRET`) for the
   asserted source; else insecure dev mode honors the claim (flagged);
   otherwise **UNTRUSTED**. Non-string tokens are simply invalid.
2. **Normalization** (`heuristic.normalize_text`): NFKC, format-char strip,
   separator fold, fixpoint URL-decode, HTML-entity decode.
3. **Detection** (`agentshield/detection/`): heuristic (keyless, inline) plus
   optional LLM detector; each surface (raw, normalized, glue-free,
   de-hyphenated, decoded, homoglyph/leet folds, base64-decoded, metadata) is
   scanned, signals union by label, saturating sum vs threshold 0.5.
4. **Policy** (`agentshield/policy/`): 8 ordered steps — unknown_tool →
   tool_disabled → detectors → detector_error → untrusted_source →
   allow_sources → require_approval → default_allow. Lookup normalizes case,
   space, and invisible characters on both sides; blank tool names rejected.
5. **Trust root** (`policy/integrity.py`): if `AGENTSHIELD_POLICY_SHA256` is
   set, the exact policy file must match or startup raises
   `PolicyTamperedError` — fail-closed at the root.
6. **Approval** (`approval/queue.py`, human path): REQUIRE_APPROVAL binds
   (tool, arguments, metadata) hash; approvals are single-use and must chain
   to a real hold; the agent graph pauses on `interrupt()` instead.
7. **Audit** (`audit/log.py`): append-only JSONL, secret redaction
   (normalized keys, fragments, provider token shapes, JSON blobs), tail read
   from the end, thread-locked.

## Component map

| Component | File | Owns |
|---|---|---|
| Models | `agentshield/models.py` | `ToolCall`, `Decision`, `TrustLevel`, results |
| Heuristic detector | `agentshield/detection/heuristic.py` | EN + Hindi/Kannada/Tamil/Telugu patterns, evasion surfaces |
| LLM detector (optional) | `agentshield/detection/llm_detector.py` | Gemini/Groq reworded-injection layer; errors fail closed |
| Policy engine | `agentshield/policy/` | YAML schema, loader, 8-step engine, digest pin |
| Provenance | `agentshield/provenance.py` | `trusted_scope`, HMAC mint/verify, dev-mode flag |
| PEP guard | `agentshield/enforce.py` | `guard`/`enforced`, positional binding, forgery mapping |
| RAG store | `agentshield/rag/` | Chroma UNTRUSTED corpus (14 docs), clamped retrieval, sanitized citations |
| Agent graph | `agentshield/agent/graph.py` | retrieve → decide → gate → finalize; verdict registry vs checkpoint flips |
| Approval queue | `agentshield/approval/` | single-use hash-bound approvals over the audit log |
| HTTP gateway | `agentshield/gateway/app.py` | check/evidence/audit/enforce/admin endpoints, key gates |
| MCP gateway | `agentshield/gateway/mcp_gateway.py` | tools/call middleware, tag handling |
| Assembler | `agentshield/engine_factory.py` | config → detectors → policy → engine + audit; ENFORCE switch |
| Config | `agentshield/config.py` | env + `.env`, strict validation, open-gateway warning |

## Agent loop (LangGraph)

`retrieve` fetches UNTRUSTED chunks (`format_chunk` escapes newlines, ids
forced to a safe alphabet) → `decide` runs `shield.check()` and pins the
verdict in a process-local registry keyed by thread_id → `gate` pauses with
`interrupt()` on REQUIRE_APPROVAL → `finalize` denies on any drift between
the checkpointed decision and the pinned one, on swapped tool/arguments, or
on a freshly-denying re-check. Checkpointer is `SqliteSaver` (`:memory:` in
tests). Multi-process deployments need sticky sessions or a shared verdict
store (see THREAT_MODEL.md).

## RAG corpus (14 docs, all UNTRUSTED)

`agentshield/data/rag_corpus.jsonl`: 6 benign EN + 8 suspicious (EN vendor /
lottery / encoded, Hindi + Kannada + Tamil + Telugu UPI lures). Ingest
parses before wiping, rejects duplicate ids, refuses >100KB docs, tags every
record `trust=UNTRUSTED`; retrieval is clamped to 1–50 and always scoped to
the UNTRUSTED tag. Retrieval is not enforcement: chunks are scanned again at
the point of use.

## Configuration (all optional, keyless by default)

| Variable | Default | Effect |
|---|---|---|
| `AGENTSHIELD_DETECTORS` | `heuristic` | `heuristic,llm` enables the LLM layer (needs a provider key) |
| `GEMINI_API_KEY` / `GROQ_API_KEY` | — | provider key for the LLM detector |
| `AGENTSHIELD_HARNESS_SECRET` | — | unset = insecure dev mode (flagged in `/v1/evidence`) |
| `AGENTSHIELD_API_KEY` | — | when set, every HTTP endpoint requires `X-API-Key` |
| `AGENTSHIELD_ADMIN_KEY` | — | when set, `/v1/admin/*` requires it instead of the API key |
| `AGENTSHIELD_ENFORCE` | `1` | `0` = demo OFF mode (explicit `enforcement_disabled` reason) |
| `AGENTSHIELD_POLICY_PATH` | `policies/default.yaml` | policy file ( + `AGENTSHIELD_POLICY_SHA256` pin) |
| `AGENTSHIELD_AUDIT_PATH` | `audit.log.jsonl` | audit trail location |
| `AGENTSHIELD_REDACT_KEYS` | built-ins | extra keys (normalized before matching) |
| `AGENTSHIELD_INJECTION_THRESHOLD` | `0.5` | detector threat cutoff |
| `AGENTSHIELD_LLM_TIMEOUT_S` | `8.0` | LLM detector timeout (fail-closed on expiry) |
| `AGENTSHIELD_RATE_LIMIT_PER_MIN` | `600` | per-IP fixed window; 0 disables; `/health`+`/ready` exempt |
| `AGENTSHIELD_ENABLE_DOCS` | `1` | `0` closes `/docs` + `/redoc` + `/openapi.json` |

## Runbook

```bash
cd cyber_hack
python -m venv .venv && .venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pytest tests -q                      # 145 passed
$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m examples.rag_demo  # 6 beats
powershell -ExecutionPolicy Bypass -File scripts/semgrep_gate.ps1  # 238 rules, 0 findings
uvicorn agentshield.gateway.app:app --host 0.0.0.0 --port ${PORT:-8000}
```

Never install tooling into `cyber_hack/.venv` (Semgrep lives in an isolated
`%TEMP%` venv — it pins a conflicting `mcp` version). Docker (`Dockerfile`)
and `render.yaml` ship for deploy; set `HARNESS_SECRET`/`API_KEY` in the
host dashboard, never in the repo.

## Failure modes (all fail closed)

| Failure | Behavior |
|---|---|
| Unknown tool / blank name | REQUIRE_APPROVAL (hold), never silent allow |
| Detector error (no key, timeout) | escalate per `fail_closed_on_detector_error` |
| Untrusted caller + high-sensitivity tool | DENY, even with clean detectors |
| Policy file tampered (pin set) | `PolicyTamperedError` at startup |
| Broken scope protocol / checkpoint drift / spent approval | UNTRUSTED / denied / re-hold |
| No API key configured | gateway runs OPEN **loudly** (startup warning + `/v1/evidence` flag) |
