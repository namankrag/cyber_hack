# AgentShield Tech Reference — Full Detail (PS-01 + PS-02 borrow)

Commit: `ea64345bc8672cc72e3c5392c44a0d382889afe0` — `security: harden enforcement boundary (v0.2)`.
Repo: friend `cyber_hack` (Python, MIT, 18 files +799/-67). Suite: 22 collected here, 26 claimed (4 MCP need `mcp` pkg).
PS page: Parallax hackathon, Fri 4:50PM → Sat 2PM submit URL + hash + 2-line pitch.

This doc is the later-reference. Every claim cites an opened body or fetched doc URL.
Gaps are listed at the end. No live deploy URLs exist yet.

## 1. Frozen core — reuse verbatim

- `models.py:18-120`: TrustLevel USER/SYSTEM/TRUSTED_TOOL/UNTRUSTED (default UNTRUSTED), Decision ALLOW<REQUIRE_APPROVAL<DENY, `most_restrictive()`, ToolCall id `call_<12hex>`, created_at epoch, DetectionResult, PolicyReason, EnforcementResult.
- `policy/models.py:22-76`: ToolPolicy sensitivity low|high, PolicyDefaults, Policy extra=forbid.
- `policy/engine.py:33-158`: 8 steps unknown_tool → tool_disabled → detectors → detector_error → untrusted_source → allow_sources → require_approval → default_allow. unknown_tool = REQUIRE_APPROVAL + fail_closed True. transfer_funds disabled = DENY.
- `provenance.py:29-126`: trusted_scope contextvars + HMAC mint/verify + insecure_dev_mode fail-closed. Token = HMAC(source) only — replayable, planned fix session/nonce/expiry.
- `enforce.py:34-79`: guard()/enforced() PEP raises before body. Contrast advisory PDP.
- `audit/log.py:28-98`: JSONL append, redact_keys exact lowercased match, tail-from-end block 8192, limit<=500, marker `«redacted»`.
- `gateway/app.py:31-118`: FastAPI GET /health, /ready (503 unless loaded), POST /v1/check CheckRequest/CheckResponse 51-70, GET /v1/audit, require_api_key. Version 0.2.0 (`__init__.py` 0.2.0 matches).
- `gateway/mcp_gateway.py:50-146`: EnforcementMiddleware, build_gateway demo tools only (SCOPE NOTE 30-34). Tag `_agentshield` {source,token,context} stripped pre-tool.
- `detection/heuristic.py:21-73`, `detection/base.py:24-50` lazy imports, `detection/llm_detector.py:42-133`, `config.py:48-104` from_env + strict validation, `engine_factory.py:15-29` check(), `policy/loader.py:11-18`.
- `policies/default.yaml:1-51` = `data/default_policy.yaml` identical wheel copy.
- Stack: fastapi>=0.115 uvicorn[standard]>=0.30 pydantic>=2.7 pyyaml>=6.0.1 rich>=13.7 mcp>=2.0 google-genai>=0.3.0 pytest>=8 httpx>=0.27. pyproject name agentshield 0.2.0 requires-python>=3.11.
- Env `.env.example:1-44`: DETECTORS, LLM_PROVIDER, GEMINI/GROQ keys, INJECTION_THRESHOLD=0.5, POLICY_PATH, AUDIT_PATH, HARNESS_SECRET, API_KEY, REDACT_KEYS, LLM_TIMEOUT_S=8.0.
- Demos: `demo.py:64-138` 5 scenarios, `mock_agent.py:44-53` POISONED_DOCUMENT, `mcp_demo.py:19-86`.

## 2. Chroma local RAG

What: OSS vector DB, local/private-by-default, Apache-2.0. Collections store embeddings+documents+metadata, auto-index.
Why here: keep 12-doc poisoned UNTRUSTED corpus local. No exfiltration. Vector ranking + metadata/full-text pre-filters before policy engine.
Install: `pip install chromadb`. Clients: `Client()` ephemeral, `PersistentClient(path)` on-disk, `HttpClient` + `chroma run --path /db_path`, Cloud `CloudClient(api_key/tenant/database or CHROMA_* env)` default api.trychroma.com us-east-1 ($5 credits) — keep Cloud OUT for poisoned corpus.
Collection names: 3-512 chars, lowercase/digit ends, dots/dashes/underscores inside, no consecutive dots, not IP, unique per DB.
Add: `.add(ids, documents, embeddings, metadatas)` needs documents and/or embeddings, metadatas optional, ids unique strings. Metadata values only str/int/float/bool. Tag every record `{trust:'UNTRUSTED', doc_id, source}`.
Query: `collection.query(query_texts|query_embeddings|query_images|query_uris, n_results=10, ids, where, where_document)`. Get unranked: `collection.get(ids|limit/offset|where|where_document)`.
Where: `{field:value}` = $eq; ops $eq/$ne/$gt/$gte/$lt/$lte/$in/$nin + $and/$or. Always use `where={'trust':'UNTRUSTED'}`.
Where_document: $contains/$not_contains case-sensitive + $regex/$not_regex + $and/$or, combinable with where.
Embeddings: default sentence-transformers all-MiniLM-L6-v2 via DefaultEmbeddingFunction, runs locally, auto-downloads. Swap per collection: OpenAI/HF wrappers or custom subclass + register_embedding_function. embedding=None means caller supplies vectors.
Index: single-node HNSW space l2|cosine|ip, ef_construction 100, ef_search 100, max_neighbors. Embedding space must match.
Refs: manage-collections, add-data, embedding-functions, hf-integration, query-and-get, metadata-filtering, full-text-search, getting-started, clients, client-server, oss pages on docs.trychroma.com; model sbert.net + huggingface all-MiniLM-L6-v2.
Risks: PersistentClient path/lock semantics truncated — confirm clients page before runbook. Sparse/hybrid Search API Cloud-only — do not promise hybrid locally.

## 3. LangGraph orchestration

What: low-level runtime for long-running stateful agents. Mix deterministic hand-coded steps + LLM steps in one graph. Durable execution, streaming, HITL, persistence.
Why: StateGraph wins for unavoidable-PEP demo. Policy/audit/guard nodes stay deterministic. Detector as agentic node. `interrupt()` approval gate before ALLOW. SqliteSaver/PostgresSaver checkpointing proves tamper-evident resume + time-travel. `create_agent` (model+tools+middleware loop) is built ON TOP of LangGraph — use only for single-agent loop.
Versions 2026-10-30 PyPI: langgraph 1.2.18, langchain 1.4.7, crewai 1.15.33, ag2 1.2.2; cross-check langgraph 1.2.15 Oct 12 2026 — re-pin at write time. Joint release Oct 2025: canonical `from langchain.agents import create_agent`; old `from langgraph.prebuilt import create_react_agent` deprecated.
Config: durability = persistence checkpoints each step/super-step by threads (thread_id); InMemorySaver loses state — prod needs PostgresSaver/SqliteSaver; modes exit/async. HITL = `interrupt()` anywhere, JSON payload, saves state, waits indefinitely, resume `Command(resume=...)`; needs checkpointer+thread_id. create_agent HITL via HumanInTheLoopMiddleware per-tool approve/edit/reject/respond.
Rejected: CrewAI HITL only Flows via @human_feedback (>=1.8.0), console-local default, email/webhook Enterprise-only; durability Flows-only via @persist + SQLiteFlowPersistence. AG2 HITL via human_input_mode ALWAYS/NEVER + UserProxy, GroupChat loop, no native per-step checkpoint. AG2 split: `import ag2` = AgentOS v1.0; classic moved to ag2-classic.
Refs: docs.langchain.com langgraph/overview, langchain/agents, persistence, checkpointers, interrupts, human-in-the-loop x2; crewai + platform HITL docs; ag2 docs; pypi ag2/langgraph.

## 4. Detectors

Heuristic 11 weights `heuristic.py:21-46`: 0.6 override-ignore, 0.6 disregard, 0.35 persona, 0.5 new-system-prompt, 0.7 exfil-secret, 0.45 egress-send, 0.55 bulk-egress, 0.5 secrecy, 0.45 fake-delimiter, 0.4 authority, 0.35 obfuscated triple-repeat. Threshold 0.5, saturating sum min(score,1.0)+round3. Haystack = full context + stringified args, NO truncation. All 11 re.I English-only — non-English passes heuristic, depends on LLM.
LLM: provider gemini|groq `llm_detector.py:43-49`, dispatch 81-86. Gemini default `gemini-2.0-flash` via google-genai generate_content (resp.text or ''). Groq default `llama-3.1-8b-instant` via chat.completions temperature=0. Strict JSON + range check 119-133. Currency UNCONFIRMED — recheck models pages (2.0 vs 2.5, groq decommission claims) before freezing.
Timeout 8.0s default via ThreadPoolExecutor result(timeout) → error `timeout after Ns`. Fail-closed: missing key RuntimeError→error, unknown provider ValueError→error, unparse/out-of-range→error. Engine escalates fail_closed_on_detector_error True, decision REQUIRE_APPROVAL, fail_closed True. `_strongest_threat` ignores failed. Egress notice 14-18 + THREAT_MODEL 71-73 + README 138-140. `build_detectors` does NOT forward model override — custom model needs direct construction or config edit.
Config: allowlist {heuristic,llm} strict; shared threshold 0.5; env INJECTION_THRESHOLD, LLM_TIMEOUT_S. SDKs lazy-imported. Test detection-denies-regardless-of-provenance.
Keys: aistudio.google.com/apikey + console.groq.com/keys. Free quotas never pulled — check gemini pricing + rate-limits + groq rate-limits on writing date.

## 5. Semgrep SAST gate (PS-02 borrow)

Python GA. 100+ Pro cross-file rules for Flask/SQLAlchemy/WTForms — OSS gate = intrafile only.
Install: `pipx install semgrep` | `uv tool install semgrep` | `brew install semgrep`; `semgrep --version`; `semgrep login`; `semgrep ci` at root. Needs Python 3.10+. No-login: `semgrep scan --config auto` e.g. `p/default`.
Packs: p/python, p/owasp-top-ten, p/security-audit, p/secrets (+ p/flask, p/django, p/fastapi). Browse semgrep.dev/explore. Rules repo github semgrep/semgrep-rules.
Finding cards: JSON/SARIF carries check_id, path/start file:line, severity, metadata cwe+owasp. Recipe `semgrep scan --config p/python --config p/owasp-top-ten --json -o semgrep.json .` → one card per result.
Exit gate: 0 success/no-blocking (or findings without --error); 1 blocking with --error / blocking ci; 2 fatal. Borrow gate: `pipx install semgrep && semgrep scan --config p/python --config p/owasp-top-ten --config p/security-audit --error --json -o semgrep.json .`; block merge on exit!=0. Red = vulnerable fires exit 1, green = fixed clean exit 0.
Risk: Windows beta needs PYTHONUTF8=1 — prefer Linux/macOS runners. Which p/default Python rules need Pro for interfile not inspected.

## 6. Deploy + demo + evidence

Gateway binds 0.0.0.0; /health liveness, /ready readiness 503 unless loaded.
Render: start `uvicorn agentshield.gateway.app:app --host 0.0.0.0 --port $PORT`, healthCheckPath /health, secrets dashboard env, ephemeral FS (paid disk e.g. /var/data for audit/Chroma).
Fly: `fly launch` Dockerfile+fly.toml, internal_port==uvicorn port, http_checks /health, `fly secrets set` restarts machine, volumes 1:1.
HF Docker Spaces: sdk docker README YAML, app_port 7860, UID 1000, secrets as env, 50GB ephemeral, /data paid persistent, 2vCPU/16GB.
Proposed NOT yet in app.py: OFF/ON `AGENTSHIELD_ENFORCE` + POST /v1/admin/enforce key-gated (still logs enforcement_disabled); RESET POST /v1/admin/reset reload policy + clear demo audit-logged; GET /v1/evidence health+ready, OFF/ON pair, redacted audit tail, pytest log, semgrep summary, URL/SHA/time.
Video: 90-120s OFF-vs-ON + health/tests, unlisted YouTube + mp4, auto-offer after 2 failed /health polls. No live URLs exist yet.

## 7. Risks and gaps

Code-verified: HMAC replayable source-only; dev-mode honors claims flagged /health; /v1/check advisory only, unavoidable = guard + MCP middleware, bypass out-of-scope; redaction exact-match only (variants pass); no rotation/retention/size-cap/permissions/fsync operator-owned; REDACT_KEYS replaces defaults; unknown_tool hold not DENY; version mismatch app/pyproject 0.2.0 vs package 0.1.0.
Open: groq/ gemini model currency truncated; free quotas never pulled; Chroma lock/hybrid truncated; Semgrep Pro-vs-OSS interfile + Windows runner; live deploy + OFF/ON/evidence not implemented; MCP 4 tests unrunnable here (22 vs 26); planned LangGraph/Chroma/key/Semgrep/deploy greenfield (only detector hook + roadmap inspected); 2 primaries null (resolved result 3, 6) — not counted.


