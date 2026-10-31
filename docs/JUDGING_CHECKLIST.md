# SecureAI — Judging Checklist, Feature Inventory & Market Differentiation

**One line:** *Secure the agent, not just the prompt — and harden the code it
runs on.* A two-layer platform that guards an AI agent at the tool-call boundary
at runtime (AgentShield, PS-1) and finds + verifiably fixes vulnerabilities in
the code its tools run on (PatchProof, PS-2), joined by a bridge, a closed
remediation loop, and a scored evaluation harness.

Use this as the pre-demo verification list and the answer key for judge
questions. Items are grouped by **how judges score**, then by **feature area**,
then by **why we win**.

---

## A. How judges will score us — and our evidence for each

| Judging axis | What they look for | Our evidence (verify before demo) |
|---|---|---|
| **Problem fit / impact** | Does it solve a real, costly problem? | Prompt injection = OWASP LLM01; ~2/3 of enterprise agent deployments have no dedicated defense; unpatched code = root cause of ~1/3 of ransomware. See `docs/BUSINESS.md`, `docs/PATCHPROOF_BUSINESS.md`. |
| **Working demo** | Does it actually run, live? | `python -m examples.injection_defense_demo`; `python -m examples.mcp_demo`; `secureai platform`; `secureai eval --once`; web UI (`web/`). |
| **Technical depth** | Is the engineering real, not a wrapper? | Real MCP server middleware + upstream proxy; AST+Semgrep SAST; exploit-verified patch gate; HMAC provenance; signed tool manifest. |
| **Completeness vs. the PS** | Every required item present? | Sections C (PS-1) and D (PS-2) below — each requirement mapped to a file. |
| **Novelty / differentiation** | Is this missing from the market? | Section F. The tool-boundary + response-sanitization + closed loop combination is the moat. |
| **Correctness / rigor** | Proof, not claims | Test suite (25+ test files); evaluation scorecard with acceptance gates + independent grader; benchmark (`docs/BENCHMARK.md`). |
| **Security of the tool itself** | Did they secure their own tool? | `SECURITY_AUDIT_REPORT.md`, `SECURITY_CHECKLIST.md`, `THREAT_MODEL.md`; fail-closed everywhere; redacted audit. |
| **Presentation / clarity** | Can they explain it fast? | `docs/PITCH.md`, `docs/DEMO_SCRIPT.md`, `docs/SECUREAI_90_SECOND_DEMO.md`, architecture SVG/PDF. |
| **Production-readiness** | Could this ship? | Dockerfile, docker-compose, `render.yaml`, `requirements.lock`, audit backends (Postgres/Redis), `docs/SCALABILITY.md`, `docs/DEPLOY.md`. |

---

## B. Core thesis & "why we chose it" (the pitch spine)

- **Why the tool boundary, not the prompt:** prompts are infinite and the model
  can be talked into ignoring in-prompt rules. We **assume the injection
  succeeds** and make sure it still can't *do* anything, because every tool call
  must pass a policy enforced in code, below the model, that it can't see or
  override. *This reframes every prompt-filter competitor as naive.*
- **Why deterministic + contextual, not keyword/LLM-only:** an LLM classifier is
  probabilistic and itself injectable. We pair detectors with **structural
  controls** (destination allow-lists, provenance, least-privilege) that an
  injection cannot argue with.
- **Why two layers:** the agent's tools are just code, and tool/MCP-server code
  is a documented source of real CVEs. We defend the same asset from both sides
  — block the bad tool *call* (runtime) and remove the bad tool *code* (build).
- **Why a closed loop + evaluation:** we don't just claim it works; a runtime
  block triggers a code scan, the fix is exploit-verified and regression-checked,
  and a scorecard enforces acceptance gates via an independent grader.

---

## C. PS-1 (AGENTSHIELD) requirement coverage — checklist

- [ ] **One simulated agent** — `agentshield/agent/graph.py` (LangGraph loop with HITL interrupt).
- [ ] **≥2 tools / permissions** — demo tools: `search_web`, `read_document`, `read_rag_docs`, `send_email`, `read_customer_db`, `read_secret`, `transfer_funds` (`policies/default.yaml`).
- [ ] **Policy enforcement point** — `agentshield/policy/engine.py` (+ `enforce.guard()` PEP, MCP middleware).
- [ ] **Audit log** — `agentshield/audit/log.py` (JSONL + Postgres/Redis backends; secrets redacted).
- [ ] **Scenario: legitimate task** — ALLOW (search). ✔ in demos.
- [ ] **Scenario: prompt-injected content (indirect)** — hidden HTML/comment/zero-width → DENY. `examples/injection_defense_demo.py`.
- [ ] **Scenario: unauthorized sensitive-data request** — untrusted → `read_customer_db` DENY (source allow-list).
- [ ] **Scenario: tool invocation beyond permission** — unknown/disabled tool → fail-closed.
- [ ] **ALLOW / DENY / REQUIRE-APPROVAL** — three explicit outcomes, most-restrictive-wins.
- [ ] **User confirmation for high-impact actions** — `require_approval` + approval queue (`agentshield/approval/`).
- [ ] **Fail-closed under uncertainty** — unknown tool, detector error, bad provenance all escalate.
- [ ] **Inspectable reason per decision** — every `PolicyReason` carries rule + detail.
- [ ] **Enforcement in code, not a system prompt** — PEP wrapper raises before the tool body runs.
- [ ] **Extensions present:** MCP gateway (`gateway/mcp_gateway.py`), signed tool manifest (`policy/manifest.py`), provenance tokens (`provenance.py`), audit trail, approval queue.

### Indirect-injection defense (the focused PS-1 ask) — checklist
- [ ] **Untrusted ingestion path** — `agentshield/ingestion.py` (email/message/doc/web/MCP-response default UNTRUSTED).
- [ ] **Source + trust metadata preserved** — `Provenance(channel, origin, trust)`.
- [ ] **Hidden/obfuscated text handled** — CSS-hidden, hidden attrs, script/style, HTML comments, zero-width, base64.
- [ ] **Quoted content separated** — email reply/forward quoting.
- [ ] **Recent-activity awareness** — `agentshield/activity.py` SessionContext.
- [ ] **Destination allow-list (deterministic)** — `agentshield/extract.py` (structural email/URL extraction over all args).
- [ ] **Exfiltration guard** — egress to non-allow-listed destination under untrusted influence → DENY.
- [ ] **Least-privilege secret access** — `reads_secrets` under untrusted influence → approval.
- [ ] **MCP responses inspected** — tool response sanitized (hidden stripped) + recorded per session; cross-call exfil blocked. `tests/test_mcp_injection_defense.py`.
- [ ] **Docs + limits** — `INJECTION_DEFENSE.md`.

---

## D. PS-2 (PATCHPROOF) requirement coverage — checklist

- [ ] **Deliberately vulnerable app + in-scope files documented** — `patchproof/vulnbank/` + `VULNERABILITIES.md`.
- [ ] **≥2 defensible weaknesses with evidence** — 5 CWE classes: SQLi (89), command injection (78), IDOR (639), path traversal (22), reflected XSS (79).
- [ ] **Find** — AST scanner + Semgrep adapter (`patchproof/scanner.py`, `semgrep_adapter.py`), file:line + CWE + severity.
- [ ] **Prove** — executable exploit confirms each finding (`patchproof/checks.py`); unconfirmed findings dropped (false-positive kill).
- [ ] **Patch** — minimal diff, curated + optional AI-generated (`patches.py`, `ai_patch.py`).
- [ ] **Prove-fixed (the gate)** — accept only if exploit blocked AND regression green (`verifier.py`); a breaking patch is rejected.
- [ ] **Regression + security re-test** — full suite re-run per patch.
- [ ] **Display: severity rationale, exact location, patch rationale, test status** — HTML/JSON report (`report.py`).
- [ ] **Synthetic data only; source fixture never auto-modified** — patches verified on isolated copies.
- [ ] **CLI** — `patchproof scan|run`, exit nonzero unless all `FIXED & VERIFIED`.

---

## E. Integration / platform layer — checklist (SecureAI)

- [ ] **Shared event model** — `secureai/core.py` (`SecurityEvent` for both layers).
- [ ] **Bridge** — `secureai/bridge.py` (runtime block → code scan of that tool's source; findings linked back).
- [ ] **Unified dashboard** — `secureai/dashboard.py` (Runtime + Code, side by side).
- [ ] **Closed remediation loop** — `secureai/loop.py` (block → scan → patch → verify → re-attack until residual vulns = 0; never ships an unverified fix).
- [ ] **Evaluation harness + scorecard + gates** — `secureai/evaluation.py`, `grader.py` (labeled synthetic dataset; metrics; acceptance gates; independent grader; nonzero exit on fail).
- [ ] **CLI** — `secureai platform | runtime | harden | loop | eval | watch`.

---

## F. How we stand out — what's NOT in the market, and why it matters

> The market today is split into **prompt-filters / LLM guardrails** (Lakera,
> NeMo Guardrails, Rebuff, llm-guard) and **SAST/remediation** (Snyk, Semgrep,
> Veracode, Cycode). Each defends ONE layer. Here is what we do that the market
> does not combine:

1. **Enforcement at the tool boundary, below the model (not the prompt).**
   Most "AI firewalls" scan text going into the model. We enforce on the *action
   coming out*, in code, where the model can't reason past it. *Differentiator:
   we survive a successful injection; prompt filters don't.*
2. **Deterministic data-flow controls fused with detection.** Destination
   allow-lists + provenance + least-privilege are structural, not keyword/LLM
   guesses — so they can't be talked around and don't depend on a classifier the
   attacker can also probe. Most guardrail products are classifier-first.
3. **MCP tool *responses* treated as an injection vector and sanitized.** We
   inspect and strip hidden instructions from tool/MCP responses *before they
   re-enter the agent*, and link a poisoned response to a later exfiltration in
   the same session. Almost no shipping product closes the response→action loop.
4. **A real MCP gateway with a signed tool manifest (rug-pull / tool-poisoning
   tripwire).** Drop-in proxy: "change one line in your MCP client config." The
   manifest catches a tool that changes its description/schema after approval —
   a documented 2025/2026 MCP attack class few defenses address.
5. **Two layers, one asset.** We don't just block the bad call; we remove the
   vulnerable tool code behind it. No mainstream product spans runtime agent
   defense *and* verified code remediation.
6. **Proof, not promises — a closed loop + independent-graded scorecard.**
   Runtime detection drives code remediation, every fix is exploit-verified and
   regression-checked, and acceptance gates are enforced by a separate grader.
   Competitors show dashboards; we show a convergent, gated loop.
7. **Honest threat model.** We state exactly what we do and don't protect
   against (`THREAT_MODEL.md`, `INJECTION_DEFENSE.md`). In a security demo,
   stated limits read as maturity and defeat the toughest judge question.

**60-second "why us" line for the judges:** *"Everyone else is trying to stop
the bad prompt — prompts are infinite, you can't filter your way to safety. We
assume the injection works and make sure it still can't act, because every tool
call passes a policy the model can't see. Then we go one layer deeper and
verifiably fix the vulnerable tool code behind it. Here's an attack hidden in a
document getting blocked — and the fix proven with a live exploit."*

---

## G. Demo-readiness checklist (run these before judging)

- [ ] `python -m pytest -q` — core/injection/MCP suites green (RAG/agent tests need network for the embedding model; run offline-safe subset if blocked).
- [ ] `python -m examples.injection_defense_demo` — 4/4 scenarios as designed.
- [ ] `python -m examples.mcp_demo` — MCP allow/block over the real protocol.
- [ ] `secureai platform --report secureai_dashboard.html` — runtime block → bridge → 5 verified code fixes.
- [ ] `secureai eval --once --out-dir reports` — scorecard PASSES all gates, exit 0.
- [ ] Web UI (`web/`) builds and runs; shows live decisions.
- [ ] Docker: `docker compose up` builds clean.
- [ ] Re-stamp the PatchProof fixture digest / policy SHA if any fixture or policy was edited (pins must match).
- [ ] Rehearse the 90-second script (`docs/SECUREAI_90_SECOND_DEMO.md`).

---

## H. Pre-empt the hard judge questions

- *"What if your detector is wrong?"* → Enforcement doesn't depend on the
  detector: provenance + deterministic controls stand alone, and uncertainty
  fails closed to approval/deny.
- *"Can the agent bypass the check?"* → No — it runs in the execution path (PEP /
  MCP middleware), not a system prompt; provenance is HMAC-signed, not
  self-asserted.
- *"Isn't this just regex?"* → No — structural destination extraction +
  provenance + session activity + signed manifest; detectors are one input of
  several, combined most-restrictive-wins.
- *"How is this different from Lakera/Snyk?"* → They defend one layer; we span
  runtime agent defense and verified code remediation, and we close the
  response→action loop. See Section F.
- *"Does it scale?"* → Stateless engine, pluggable audit backends, Docker/deploy
  configs, benchmark numbers. See `docs/SCALABILITY.md`, `docs/BENCHMARK.md`.
- *"What doesn't it do?"* → We answer from `THREAT_MODEL.md` directly — mis-tagged
  provenance, exotic encodings/steganography, distributed session state, and
  detection-is-not-a-guarantee are stated limits with mitigations.
