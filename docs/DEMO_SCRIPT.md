# Demo + video script (90-120s) and evidence checklist

## Shot list (record in one take; keep the fallback video)

0:00-0:15 — Problem. Show the poisoned vendor doc (agentshield/data/rag_corpus.jsonl,
en-poison-vendor). Say: AI agents get hijacked by any doc they read.
0:15-0:45 — Gate OFF leaks. POST /v1/check with the poisoned send_email call,
enforcement off: ALLOW. Say: without the boundary, the model obeys the document.
0:45-1:15 — Gate ON blocks. Same call: DENY with quoted rule
(injection_detected + untrusted_source). Run examples/rag_demo.py beats 1-3
live: legit ALLOW, poison DENY, email HELD then human-approved.
1:15-1:45 — Proof. pytest -q (81 green), semgrep.json (0 findings, 238 rules),
GET /v1/evidence (health + enforced + audit tail). Say: every verdict carries
rule id plus quoted evidence plus severity.
1:45-2:00 — Pitch. Boundaries are code: every call gets allow, deny, or approval
with proof, so even a compromised model cannot leak.

If the network or projector fails, play the fallback recording (unlisted
YouTube link + local mp4) and walk judges through semgrep.json + pytest log.

## Live demo commands (deterministic order)

1. `.venv\Scripts\python.exe -m examples.rag_demo` (beats 1-6, no server needed)
2. `uvicorn agentshield.gateway.app:app` + curl POST /v1/check (deny),
   POST /v1/admin/enforce {"enabled": false} (allow), flip back (deny)
3. `.venv\Scripts\python.exe -m pytest tests -q` (51 passed)
4. `powershell -ExecutionPolicy Bypass -File scripts/semgrep_gate.ps1` (exit 0)

## Evidence pack (submit alongside repo URL + commit hash + 2-line pitch)

- pytest log (81 passed), semgrep.json (0 findings), demo console log,
  3 curls (check deny, enforce toggle, evidence), redacted audit tail sample.
- State non-goals out loud: replayable tokens (documented), no upstream MCP
  proxy yet, TLS/secrets operator-owned (see THREAT_MODEL.md).
