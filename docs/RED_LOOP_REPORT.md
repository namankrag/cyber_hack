# Red-loop report: 50 attackers → verify → fix → verify

PS-01 AgentShield, `muse` branch. This is the evidence behind the
"0/minimum vulnerabilities" claim: every finding below was reproduced by a
runnable probe, deduplicated into one ledger, fixed or explicitly accepted,
and pinned by a committed test. The machine-readable twin of this report is
[red_loop_ledger.csv](red_loop_ledger.csv) (opens in Excel).

## Objective and stop condition

Attack the agent with 50 smart red-team agents, fix everything confirmed,
repeat until the attackers reach **0 or minimum** vulnerabilities. Read-only
attackers (`%TEMP%` scratch, `AGENTSHIELD_AUDIT_PATH` redirected to temp, no
repo writes except through the single fixer); one fixer; verify waves.

## Wave 1 — 50 attackers, 36-ledger

50 read-only probes across all layers. Synthesis deduplicated them into
**LEDGER-01…36** (all HIGH): heuristic evasion battery (L01–L13: separators,
hidden chars, homoglyphs, leet, paraphrase, comment splits, field splits,
double-encoding, Tamil/Telugu, single blobs, fake roles, secrecy variants,
singular exfil verbs), provenance (L14 dev-mode, L15 replay, L16 scope
laundering), policy (L17 case/space, L18 blank keys), detector-error flags
(L19), kill-switch (L20), PEP gaps (L21 positional args, L22 `__wrapped__`,
L23 unenforced RAG body, L24 forged verdicts), metadata (L25), MCP tags
(L26 crash, L27 blind spots), HTTP surface (L28 open endpoints, L29 empty
key), audit redaction (L30 exact keys, L31 free text), approvals (L32
forgery), checkpoints (L33 rewrite), audit durability (L34), RAG ingest
(L35 labels, L36 unbounded size).

## Fixer-1 + verify — commit `ef9dd3b`

One fixer applied minimal patches (14 files): heuristic evasion surfaces,
Unicode policy lookup, blank-key rejection, detector-exception fail-closed,
positional-arg binding, `__wrapped__` removal, MCP dict guard, redaction+,
approval hash binding, scope re-entrancy, RAG validation, checkpoint
re-verify. Verify wave: **60/60 tests green**, Semgrep 234 rules 0 findings,
demo 6 beats live. Deferred by design: paraphrase (needs semantic layer),
Tamil/Telugu (pattern gap), token replay, dev-mode, kill-switch theater,
auth redesign, RAG design corners, cross-process races.

## Wave 2 — 15 verifiers, 27 entries

15 verifiers re-probed the fixed tree. Verdict: fixes hold; **27
still-open / partial / new** entries (full table in the CSV: L08R
triple-encoding, L09 Tamil/Telugu, L10R short blobs + entities, L16b
out-of-order scope, L17b Unicode policy keys, L24b async forgery, L27b
non-string tokens, L28b shared admin key, L29c CWD `.env`, L31P free text,
L32b repeat approvals, L33b/c low-sens resume + decision-flip, L34b compound
keys, L35b citation forgery, L36b duplicate-id DoS, plus still-open design
items). Wave 3 was skipped on an empty-payload technicality, not on verified
cleanliness — so this wave-2 list became the work queue below, not a
clean bill of health.

## Fix cycles 2–3 — commits `a5a72d2`, `f749cc3`

Every actionable wave-2 item got a minimal fix + committed test (see CSV
`fixed_in`/`test` columns): fixpoint URL decode, HTML-entity surface,
Tamil/Telugu patterns + 2 corpus docs (14 total), NFKC+Cf-stripped
two-sided policy lookup, token type guard, order-checked fail-closed scope
exit, process-local verdict registry, single-use approvals, duplicate/size
RAG guards, citation escaping, fragment + token-shape redaction, split admin
key, trimmed `/health`, no-key startup warning, async-capable guard,
base64 floor 40→20 (padding miscount: a real 40-char blob is 38 payload
chars + `==`, which the old floor never matched).

## Final verification (observed, this tree)

- `pytest tests -q` → **81 passed** (78 + 3 guard tests).
- `scripts/semgrep_gate.ps1` → **238 rules, 0 findings**, exit 0.
- `python -m examples.rag_demo` → all 6 beats correct (ALLOW / DENY with
  quoted rules / HELD→HUMAN-APPROVED / OFF-allow vs ON-deny / Kannada+Tamil
  deny ~300ms with `grounded in: [...]`).
- `git log origin/muse`: `9a28520` (gate evidence) / `f749cc3` (async
  guard) / `a5a72d2` (wave-2 hardening) / `ef9dd3b` (wave-1 hardening).

## Accepted residuals (with containment)

Paraphrase without keywords (L05) and sub-20-char encoded blobs: need the
semantic/LLM layer (no key in this build). Contained: high-sensitivity tools
deny untrusted callers **regardless of detection**, so a missed lure can at
most steer low-sensitivity reads, never execute or exfiltrate. Dev-mode
forgery (L14), empty-key open gateway (L29), `ENFORCE=0` theater (L20):
explicit operator choices, flagged at runtime (`/v1/evidence`,
startup warning) and audit-logged. Token replay (L15), checkpoint auth
(L33b), cross-process audit races (L34), TLS/rotation (THREAT_MODEL): prod
deployment duties, documented with mitigations. Missing-tag low-sens ALLOW
(L27) and unenforced retrieval (L23) follow the documented default policy
(untrusted-low = allow; retrieval is not execution; enforcement at use).

## Reproduce

```bash
cd cyber_hack
.venv\Scripts\python.exe -m pytest tests -q
$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m examples.rag_demo
powershell -ExecutionPolicy Bypass -File scripts/semgrep_gate.ps1
```
