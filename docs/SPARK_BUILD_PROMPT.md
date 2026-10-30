# BUILD PROMPT FOR MUSE SPARK 1.3 — AgentShield PS-01 winning build

You are the builder. I am a 15-year cybersecurity lead. Follow this prompt exactly. Do not redesign the architecture. The design is settled and evidence-backed. Your job is execution plus verification.

## Mission

Win Parallax PS-01 AgentShield at BMSCE CyberMonth (24h, Fri 4:50PM countdown to Sat 2PM submit of repo URL plus final commit hash plus two-line pitch). We start from a working, tested base and add only the gaps. Details and proof for every claim below live in the reference files. Read them first.

## Read these files first, in this order

1. `README.md` — product story, quickstart, architecture, and the `Full reference (muse branch)` section. Ground truth for behavior.
2. `THREAT_MODEL.md` — what we protect, what we explicitly do NOT, operator checklist. Never promise what it excludes.
3. `docs/tech_reference_full.md` — the full later-reference: frozen core with path:line, Chroma RAG, LangGraph, detectors, Semgrep, deploy, demo, risks.
4. `docs/cyber_win_map.md` — the 3 problem statements, repo file map, 7 code-verified gaps, 24h plan.
5. `docs/cyber_win_map.csv` — same map as rows: Area, File_URL, Claim, Provenance, Gap, Fix, Owner, Priority. Work the P0 rows first.
6. `policies/default.yaml` — the policy. Memorize it: search_web/read_document low ALLOW; send_email high plus require_approval; read_customer_db high plus allow_sources [user,system]; transfer_funds high allow:false; unknown_tool require_approval fail-closed.
7. `.env.example`, `examples/demo.py`, `examples/mock_agent.py`, `examples/mcp_demo.py`, `tests/` — demo scenarios and the 26-test contract (7 engine plus 15 security plus 4 MCP).

## Non-negotiables

- Freeze the core: `models.py`, `policy/engine.py`, `policy/models.py`, `provenance.py`, `enforce.py`, `audit/log.py`, `config.py`, packaged default policy. Policy-data rows and demo text may change. No engine refactor, no new decision states, no schema change after the midnight MVP.
- Fail-closed always: unknown tools, detector errors, missing or invalid provenance hold or deny. Never silently allow.
- Provenance comes only from `trusted_scope` or HMAC token, never from request payload. Retrieved RAG chunks stay UNTRUSTED and must pass heuristic plus LLM scan.
- Synthetic data only. POISONED_DOCUMENT style fixtures. No real scanning, no real links, no auto-open or auto-reply.
- Every verdict carries rule id plus quoted evidence plus severity. No black-box outputs.

## Build tasks (in order, P0 first)

1. RAG corpus plus retriever: 12 synthetic docs (6 clean, 6 poisoned: English plus 1 Kannada plus 1 Hindi UPI lure). Local Chroma `PersistentClient`, default all-MiniLM-L6-v2 embedding, every record tagged UNTRUSTED. New low-sensitivity tool `read_rag_docs`. Always query `where={'trust':'UNTRUSTED'}`.
2. LangGraph StateGraph: retrieve → detect → policy engine → `interrupt()` approval gate before ALLOW → guard PEP → audit node. SqliteSaver for dev. Thread id per demo run.
3. Approval queue: minimal pending list over `GET /v1/audit` filtered to REQUIRE_APPROVAL, approve or deny buttons writing linked append-only entries. Never mutate JSONL in place.
4. Demo endpoints (key-gated, audit-logged): `AGENTSHIELD_ENFORCE` OFF/ON toggle plus POST /v1/admin/enforce, POST /v1/admin/reset, GET /v1/evidence (health plus ready JSON, OFF/ON check pair, redacted audit tail, pytest log, semgrep summary, URL/SHA/time).
5. Semgrep gate: `pip install semgrep` then `semgrep scan --config p/python --config p/owasp-top-ten --config p/security-audit --error --json -o semgrep.json .`. Block on exit not equal 0. Render each finding as a card: rule plus CWE/OWASP plus file:line plus severity.
6. Deploy: Dockerfile plus Render config. Start `uvicorn agentshield.gateway.app:app --host 0.0.0.0 --port $PORT`, healthCheckPath /health. Set HARNESS_SECRET plus API_KEY in dashboard env. Bind 0.0.0.0 everywhere.
7. Demo plus evidence: 5-minute deterministic script (legit ALLOW, gate-OFF leak, gate-ON DENY with quote, DB DENY, email APPROVAL plus human approve, audit line). Rehearse 5 times. Record 90-120s fallback video. Set both secrets or the judges see insecure dev mode flagged in /health.

## Verification before you call anything done

- `pytest -q` green (22 runnable here, 26 with `mcp` installed). Quote the terminal output.
- Same poisoned prompt under OFF leaks and under ON is denied or held, with quoted evidence and rule id.
- 3 curls: legit check ALLOW, poisoned check DENY, audit tail auth-gated.
- Semgrep summary plus redacted audit sample in the evidence pack.

## Pitch (use verbatim)

AI agents get hijacked by any doc they read. AgentShield is the code boundary between agent and tools — every call gets allow, deny, or approval with proof — so even a compromised model cannot leak. Q&A answers: false positives go to approval not deny; bypasses require skipping the PEP, which the demo proves; non-goals are exactly the THREAT_MODEL.md list.

Work on the `muse` branch. One commit per task above. Report test output and demo log with every commit.
