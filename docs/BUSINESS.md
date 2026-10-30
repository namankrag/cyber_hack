# SecureAI — business note (PS-01 item 6)

## Problem

Two costs, one architecture. At runtime, AI agents that read documents,
browse, and call tools get hijacked by instructions hidden in content
they were asked to process (indirect prompt injection, OWASP LLM01) and
then abuse over-broad tool powers (excessive agency, OWASP LLM06).
At build time, scanners drown teams in unactioned alerts while patches
ship unproven. Enforcement belongs below the model and after the scan: a policy boundary at the tool call, and a proof gate on every fix. Prompt-level defenses can be talked around; scanner
output nobody trusts gets ignored.

## Buyer

Fintech, banks, and BPOs running customer-data workflows through agents:
KYC lookups, payment operations, support inboxes, vendor-doc processing.
They already live under audit — every allow/deny/approval decision in
AgentShield carries its rule ids plus quoted evidence into an
append-only JSONL trail, which is exactly what their examiners ask for.
The India/Indic angle is concrete, not decorative: UPI-flavored lures
in Hindi, Kannada, Tamil, and Telugu are in the frozen benchmark
(`bench/cases.jsonl`), flagged on the keyless heuristic path, because
BPO and fintech abuse in India arrives in those languages.

## Wedge: the drop-in proxy

AgentShield fronts the tools the agent already calls — over HTTP
(`POST /v1/check`), in-process, or over the MCP protocol — and answers
allow, deny, or require-approval before anything runs. The OFF-vs-ON
beat is the sale: the same poisoned call leaks with enforcement off and
is denied with it on. PatchProof is the second half of the same wedge:
one CI workflow file that turns scanner noise into proven fixes.
Neither wedge asks the buyer to rewrite agents or retrain models.

## Pricing: open core + per-agent SaaS

- **Open core (free, self-hosted):** the PEP gateway, heuristic
  detectors, YAML policy engine, JSONL audit, PatchProof scanner +
  gate + SARIF/HTML reports. Everything in this repo runs keyless.
- **Per-agent SaaS:** hosted policy management, fleet dashboards,
  approval queues with human click-through, audit retention and
  examiner-ready exports, managed detector/rule updates, per-agent
  metering and rate-limit analytics.
- **Enterprise add-ons:** Postgres/Redis-backed audit and approvals
  (already supported), SSO, data-residency options, custom fixture
  onboarding for PatchProof on the customer's own services.

## Moat

1. **Boundary, not prompt:** enforcement sits at the tool call, where
   the model cannot argue with it. Provenance is first-class —
   untrusted content never reaches high-sensitivity tools.
2. **Proof on both ends:** runtime blocks carry quoted rule evidence;
   code fixes carry a live exploit plus a variant corpus plus green
   regressions. Competitors assert; SecureAI shows the replay.
3. **Audit as a feature:** the append-only trail is the compliance
   artifact (DPDP, RBI, EU AI Act logging — see below), not an
   afterthought.
4. **Independent grading:** the scorecard's 8/8 gates are recomputed by
   a grader that re-scans, re-exploits, and replays from raw evidence
   instead of trusting the pipeline's own flags. A buyer can audit the
   audit.

## Compliance mapping

- **OWASP LLM01 (prompt injection) / LLM06 (excessive agency):** the
  primary design targets — provenance + most-restrictive-wins + human
  approval for high-impact calls. Documented in THREAT_MODEL.md with
  non-goals disclosed, not hidden.
- **India DPDP Act:** purpose-limited, logged processing of customer
  data — every tool call on personal data is decided, reasoned, and
  written to the tamper-evident trail.
- **RBI expectations (audit trails, access control):** fail-closed
  defaults, most-restrictive-wins composition, human approval for
  fund movement and egress, append-only evidence per decision.
- **EU AI Act (logging for high-risk systems):** automatic,
  timestamped records of agent tool invocations, detections, blocks,
  approvals, and code remediations — the scorecard and audit log are
  the exportable record.

## Competitors

- **Prompt filters / guardrail APIs:** text in, text out — same layer
  as the attacker. Bypassed by paraphrase (our benchmark's honest
  misses show even our own detector has edges); they have no tool
  boundary and no audit of what the agent *did*.
- **Generic SAST vendors:** find without proving. They sell findings;
  PatchProof sells the funnel (alerts → confirmed → fixed) with the
  exploit as the receipt.
- **GRC/compliance dashboards:** record controls, do not enforce them.
  SecureAI enforces first and the log falls out as evidence.

## 6-month roadmap

1. **Months 1–2 — close the measured gaps:** the benchmark's three
   honest misses (adjective-stacked exfil phrasing, first-person exfil
   framing, pluralized secrets held-not-denied) plus replayable
   provenance tokens (declared non-goal today) so approvals survive
   restarts without weakening containment.
2. **Months 2–3 — upstream MCP proxy:** front real upstream tool
   servers over stdio/HTTP (the compose knobs already exist), so the
   PEP protects production tools, not just demo fixtures.
3. **Months 3–4 — enterprise backends as default-offered:** Postgres
   audit + Redis approvals out of the box, examiner export packs
   (DPDP/RBI/EU AI Act views), SSO.
4. **Months 4–5 — PatchProof depth:** more CWE classes and customer
   fixtures via the manifest pattern, Semgrep-managed rules in SaaS,
   PR comments with exploit evidence inline.
5. **Months 5–6 — per-agent metering and scale:** hosted dashboards,
   rate-limit analytics, multi-replica rollout docs, first two paid
   design partners (one fintech, one BPO) running the proxy + gate
   in shadow mode before enforcement.
