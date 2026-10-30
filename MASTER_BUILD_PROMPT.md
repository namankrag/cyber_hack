Here's the detailed master build prompt. It specifies exactly what to pull from PS-2 into PS-1, the integration measures, and — the part that's genuinely new beyond what's already in the repo — a **full evaluation framework with two kinds of looping**: a closed remediation loop (block → scan → patch → re-verify → re-attack) and an evaluation harness that loops over a labeled scenario set to produce a scorecard with pass/fail gates.

You can copy this whole thing as a build spec. (Note: the repo already implements the shared core + bridge + unified dashboard; this prompt adds the closed loop + the evaluation harness to make it a "master, fully-evaluated project.")

---

# MASTER BUILD PROMPT — "SecureAI": PS-2 integrated on top of PS-1, as one evaluated, closed-loop platform

## 0. Role & objective
You are building **SecureAI**, a single master project that unifies two layers of AI-agent security and proves it works with a full, looping evaluation:
- **Runtime layer (from PS-1 / AgentShield):** guard a running agent at the tool-call boundary.
- **Code layer (from PS-2 / PatchProof):** find, exploit-prove, patch, and verify vulnerabilities in the code the agent's tools run on.
- **Integration:** a shared core, a bridge connecting the two, a **closed remediation loop**, and an **evaluation harness** that scores the whole system against acceptance gates.
All data is synthetic. The core runs with no API keys; any LLM use is optional and gated.

## 1. Constraints to satisfy (both problem statements, in full)

**PS-1 (runtime) — must deliver ALL of:**
- one simulated agent; at least two tools/permissions; a **policy enforcement point**; an **audit log**.
- four security scenarios: a legitimate task; prompt-injected (indirect) content; an unauthorized sensitive-data request; a tool invocation beyond permission. Synthetic data only.
- explicit **ALLOW / DENY / REQUIRE-APPROVAL** decisions; **user confirmation for high-impact** actions; **fail-closed** when confidence or policy is insufficient.
- an **inspectable reason** for every decision.
- optional extensions to include: MCP gateway, tool permission profiles, signed tool metadata, cross-agent audit trail, risk-aware approval queue.

**PS-2 (code) — must deliver ALL of:**
- a deliberately vulnerable practice app (or local fixture) with **documented in-scope files**.
- at least **two defensible weakness cases** with evidence grounded in source or executable tests.
- a **minimal patch/diff** for at least one verified issue, plus a **regression + security re-test**.
- display: **severity rationale, exact affected location, patch rationale, test status**.

## 2. What exactly to integrate FROM PS-2 INTO PS-1
Bring these PS-2 capabilities into the runtime project as a second defense layer on the **same asset (the agent's tools)**:
1. **The SAST scanner (`find`)** — locate weaknesses in the source of the tools AgentShield governs (file:line, CWE, severity).
2. **The exploit harness (`prove`)** — confirm each finding is real with an executable exploit; drop unconfirmed findings (no scanner-noise).
3. **The patch + verification gate (`patch` + `prove-fixed`)** — apply a minimal diff and accept it **only if** the exploit is blocked **and** the regression suite stays green.
4. **The CWE/severity model + evidence report** — fold into the shared event/report model.
Integration points into PS-1: (a) a **tool→source registry** mapping each governed tool to its implementation file; (b) a **runtime→code trigger** so an AgentShield block kicks off a PatchProof scan of that tool.

## 3. Integration architecture & measures to take
- **Shared core:** one `SecurityEvent` model + an event store; adapters from the runtime `EnforcementResult` and the code `IssueReport`. Both layers write one stream.
- **Bridge:** `harden_tools()` (run PatchProof over governed-tool source) and `on_runtime_block()` (runtime detection → code scan, findings linked back to the trigger).
- **Provenance measure:** trust is never self-asserted — it comes from a trusted harness (HMAC token / in-process scope); default **UNTRUSTED**; fail-closed.
- **Unavoidable enforcement:** the policy check lives in the tool **execution path** (a guard/PEP and/or MCP middleware), not an advisory endpoint.
- **Dependency isolation measure:** if two subprojects need conflicting library versions (e.g., the MCP SDK vs. a scanner's CLI), keep the primary pinned, make the secondary **probe-and-fallback**, and document a **venv-per-subproject** layout. Never let an optional engine break the core.
- **Safety measures:** synthetic data only; secrets redacted in the audit log; exploits/candidate code run only against bundled fixtures in a sandbox; AI candidates parsed/validated before execution.

## 4. The looping & evaluation framework (the "master, fully-evaluated" part)

### 4A. Closed remediation loop (runtime ↔ code)
Implement a loop that proves the two layers reinforce each other:
```
for each governed tool T under an attack scenario:
  1. RUNTIME: AgentShield evaluates the attacking call  → expect BLOCK/HOLD
  2. On block → BRIDGE: scan T's source                → findings
  3. CODE: for each confirmed finding → patch → verify  (exploit blocked AND regression green)
  4. RE-DEPLOY the patched tool implementation (to an isolated copy)
  5. RE-ATTACK at runtime + RE-SCAN the code
  6. ASSERT: the confirmed-vuln count on T strictly decreased (ideally → 0),
             and no regression was introduced
  7. LOG the before/after; repeat until no confirmed vulns remain or MAX_ITERS reached
```
Record per-iteration state so the loop's convergence is visible. Fail-closed: if a patch can't be verified, stop and surface it for human approval — never auto-ship an unverified fix.

### 4B. Evaluation harness (loops over a labeled dataset → scorecard)
- **Datasets (synthetic):**
  - *Runtime set:* N scenarios labeled benign/malicious, covering direct + indirect injection, per-tool, plus legitimate high-impact (should be HELD, not blocked).
  - *Code set:* the planted CWE classes with ground-truth labels.
- **Metrics (computed by looping over the datasets):**
  - Runtime: attack **block rate** (recall on malicious), **false-positive rate** on benign, **approval correctness** (high-impact → HELD), mean decision latency.
  - Code: scanner **recall**, exploit **confirmation rate** (true-positive proof), **patch acceptance rate**, **regression pass rate**, mean verification time.
  - Loop: **iterations to convergence**, residual confirmed vulns.
- **Acceptance gates (the eval must enforce):** e.g. 100% of planted attacks blocked; benign FP ≤ 5%; every confirmed CWE `FIXED & VERIFIED`; 0 regressions; loop converges to 0 residual vulns within MAX_ITERS.
- **Independent grader:** a separate evaluator re-checks outcomes (don't let the system grade itself).
- **Output:** `scorecard.json` + `scorecard.html` (metrics, per-scenario pass/fail, gate results, trend across loop iterations), and a nonzero exit code if any gate fails (CI-ready).
- **Looping modes:** `eval --once` (single pass + scorecard); `eval --tune` (iterate thresholds until gates pass or give up, reporting the search); `watch` (re-run the loop when tool code changes).

## 5. Non-functional constraints (everything)
- Fail-closed, most-restrictive-wins, and an inspectable reason/evidence on **every** decision and fix.
- Core runs with **no API keys**; LLM assistance is optional, gated by the verifier, and fail-safe without a key.
- Full audit of decisions and fixes; sensitive fields redacted.
- Tests for both layers, the bridge, the closed loop, and the eval harness; a CI gate that fails on any acceptance-gate miss.
- Threat model doc (scope + what it does/doesn't protect), LICENSE, reproducible packaging, a one-command demo and a one-command eval.
- Performance: inline enforcement is fast; all code-execution steps are bounded by timeouts and run on isolated copies.

## 6. Deliverables
- Packages: runtime layer, code layer, shared core + bridge, eval harness.
- CLIs: `secureai platform` (run both + bridge + dashboard), `secureai loop` (closed remediation loop), `secureai eval` (scorecard), plus the per-layer commands.
- Artifacts: unified dashboard (Runtime + Code), `scorecard.html/json`, per-layer reports, threat model, README/SECUREAI.md.
- A 90-second demo script and a judge-facing results summary.

## 7. Acceptance criteria (definition of done)
- [ ] All four PS-1 scenarios behave correctly (allow/deny/approve, fail-closed, inspectable reasons).
- [ ] ≥2 PS-2 CWEs found, exploit-confirmed, minimally patched, and verified (exploit blocked + regression green), with the required display fields.
- [ ] Bridge: a runtime block triggers a code scan; findings link back to the trigger.
- [ ] Closed loop converges (residual confirmed vulns → 0) with no regressions.
- [ ] Eval harness produces a scorecard and all acceptance gates pass; the grader is independent; CI exits nonzero on any gate failure.
- [ ] No real data/secrets; core needs no keys; everything reproducible; tests all green.

## 8. Build order (milestones)
1. Confirm PS-1 and PS-2 each pass standalone.
2. Shared core + adapters.
3. Bridge (registry + harden + runtime→code trigger).
4. Platform orchestrator + unified dashboard.
5. **Closed remediation loop** (§4A).
6. **Evaluation harness + scorecard + gates + grader** (§4B).
7. Hardening, docs, CI, demo; final acceptance pass.

## 9. Copy-paste condensed prompt (hand this to a build agent)
> Build "SecureAI": integrate a code-security pipeline (scan → exploit-prove → minimal-patch → verify-gate: accept only if exploit blocked AND regression green) as a second layer on top of an AI-agent runtime enforcer (tool-call boundary: ALLOW/DENY/REQUIRE-APPROVAL, fail-closed, inspectable reasons, audit log, provenance never self-asserted). Add a shared SecurityEvent model, a tool→source bridge where a runtime block auto-triggers a code scan of that tool, and a **closed loop** (block→scan→patch→verify→re-deploy→re-attack until residual confirmed vulns = 0, never shipping an unverified fix). Add an **evaluation harness** that loops over a labeled synthetic dataset (benign/malicious runtime scenarios + planted CWEs) and emits scorecard.html/json with metrics (block rate, false-positive rate, approval correctness, scanner recall, patch acceptance, regression pass, iterations-to-converge) enforced by acceptance gates via an independent grader, exiting nonzero on any failure. Constraints: synthetic data only; no API keys for the core; LLM optional+gated+fail-safe; most-restrictive-wins; redacted audit; isolated/bounded code execution; tests for both layers, the bridge, the loop, and the eval; threat model + LICENSE + reproducible packaging; one-command demo and one-command eval.

---

Two honest notes:
- **Already in your repo (`ps2`):** the shared core, the bridge (incl. runtime→code trigger), the unified dashboard, and the per-layer pipelines. So steps 1–4 are done.
- **New in this prompt:** step 5 (the *full* closed remediation loop with re-deploy/re-attack and convergence) and step 6 (the evaluation harness + scorecard + gates + independent grader). Those are what elevate it to a "master, fully-evaluated" project.

Want me to **(a)** save this as `MASTER_BUILD_PROMPT.md` in the repo, and/or **(b)** actually build the two new pieces — the closed remediation loop and the evaluation harness with the scorecard — so the master project is complete?