# AgentShield — Threat Model

This document states plainly what AgentShield protects against, what it does
**not**, and the trust assumptions it relies on. Prompt-injection detection is
**defense in depth, not a guarantee** — the enforcement boundary is the part
you should rely on.

## What AgentShield is

A Policy Enforcement Point (PEP) between an AI agent and its tools. Every tool
call is adjudicated — ALLOW / REQUIRE_APPROVAL / DENY — before the tool runs,
with an inspectable, logged reason. It is designed to **contain the blast
radius of a successful prompt injection**, not to perfectly detect injections.

## Assets

- Sensitive tools and the actions they take (send email, query a DB, move funds).
- Sensitive data the agent can reach (customer records, secrets).
- The audit trail (itself sensitive — it records calls and arguments).

## Adversaries & entry points

1. **Indirect prompt injection** — instructions hidden in untrusted content the
   agent processes (web pages, emails, retrieved documents, third-party tool
   output). Primary threat.
2. **Direct prompt injection** — a malicious end-user instruction.
3. **A compromised/hijacked agent** attempting tool calls it should not make.

## Trust boundaries & assumptions

- **The harness is trusted; the model is not.** Provenance (user vs. untrusted)
  is established by the harness that wraps the agent, through channels the model
  cannot reach: an in-process `trusted_scope` (contextvars) or an HMAC token
  minted from `AGENTSHIELD_HARNESS_SECRET`. The agent and any injected content
  can place a `source` claim in a request/tool call, but cannot forge the token,
  so such claims resolve to **UNTRUSTED**.
- **Fail-closed by default.** Unknown tools, detector errors, missing/invalid
  provenance, and (when a secret is set) untokenized trust claims all escalate
  to approval or deny — never silently allow.
- **The policy and the secret are trusted inputs**, provisioned by operators out
  of band, not by the agent.

## What AgentShield protects against

- A tool call driven by injected content reaching a **sensitive** tool → denied.
- Untrusted content attempting to read gated data → denied.
- Calls to tools **not covered by policy** → fail-closed to approval.
- A caller **claiming** a trusted source without the secret → treated as untrusted.
- High-impact actions → routed to human approval even when legitimately requested.

## What AgentShield does NOT protect against (out of scope / limitations)

- **Perfect injection detection.** The heuristic detector is a signal, not proof;
  the optional LLM detector helps but is probabilistic. Enforcement does not
  depend on the detector score alone — provenance and policy stand on their own.
- **A compromised harness or leaked secret.** If `AGENTSHIELD_HARNESS_SECRET`
  leaks, trust claims can be forged. Provenance tokens are single-use (random
  nonce + replay cache), short-lived (expiry), and optionally session-bound:
  a replayed, expired, forged, or session-mismatched token resolves to
  **UNTRUSTED** with an inspectable reason. *Residual:* the replay cache is
  per-process memory — across multiple gateway workers, install a shared
  backend via `provenance.set_replay_cache` (the `ReplayCache` interface is
  small enough for Redis), or a token spent in one worker could still verify
  in another.
- **Tool rug-pulls / tool-poisoning.** Governed tool definitions are
  HMAC-signed at startup into a tool manifest (trust root: the harness
  secret — same as provenance tokens). Every in-process check re-verifies
  the tool's current policy entry; every MCP call re-verifies the live
  description + input schema. A post-registration change (description or
  schema swapped, rules edited in memory) is DENIED with an inspectable
  `tool_manifest_mismatch` reason. With no secret configured the manifest is
  unsigned and verification is skipped — explicitly flagged via
  `manifest_enforced == false` (insecure dev mode, never silent).
- **Tools that bypass the PEP.** AgentShield only governs calls that flow through
  the MCP gateway or the `guard` wrapper. A tool invoked directly, around the
  enforcement point, is not protected. The `/v1/check` HTTP endpoint is a
  *decision* point and is advisory by itself.
- **Upstream MCP passthrough.** The MCP gateway currently registers built-in
  demo tools; proxying an arbitrary upstream MCP server is a planned extension
  (the enforcement model is identical).
- **Transport security & deployment.** TLS, network exposure, process
  permissions, secret storage, and log retention/rotation are the operator's
  responsibility. Do not expose the gateway, `/v1/audit`, or `/v1/evidence`
  publicly without auth (set `AGENTSHIELD_API_KEY`). Set a dedicated
  `AGENTSHIELD_ADMIN_KEY` so a leaked read key cannot flip `/v1/admin/*`.
  `/health` and `/ready` stay unauthenticated by design (liveness only — no
  policy, tool-list, or dev-mode details).
- **Data sharing via the LLM detector.** Enabling it sends tool context and
  arguments to a third-party provider; treat it as a deliberate data-sharing
  feature.

## Cross-agent trace propagation

- `trace_id` / `parent_id` ride the `ToolCall`, every audit JSONL record
  (including approval and admin lines), the HTTP gateway (body fields, else
  the `X-Trace-Id` / `X-Parent-Id` headers — body wins), and the MCP
  `_agentshield` tag. The approval queue binds both IDs into `args_hash`,
  so an approval for one trace does not authorize the same arguments
  replayed under another trace.
- Trace IDs are caller-minted correlation hints (`None` when absent — fully
  backward compatible), **not** trust: enforcement never depends on them.

## Operator checklist

- [ ] Set `AGENTSHIELD_HARNESS_SECRET` (else runs in insecure dev mode — flagged in `/health`).
- [ ] Set `AGENTSHIELD_API_KEY` before exposing the gateway beyond localhost.
- [ ] Set `AGENTSHIELD_ADMIN_KEY` (else the API key alone guards the global
      enforcement switch).
- [ ] Assume checkpoint access (update_state/get_state/resume) is privileged:
      anyone who can write it can rewrite decisions — keep it single-process
      or behind auth, sticky sessions, and a shared verdict store.
- [ ] Review `redact_keys`; restrict permissions and set retention on the audit file.
- [ ] Decide deliberately whether to enable the LLM detector (data leaves your env).
- [ ] Put real tools behind the `guard` PEP or the MCP gateway — never call them around it.

## Roadmap (deferred hardening)

Upstream MCP proxy passthrough (tool manifest already covers registered tools) ·
local-model detector (no data egress) · CI + dependency lockfiles ·
Postgres-backed audit with rotation · OPA policy backend · structured request-id logging.

## SecureAI evaluation and remediation boundary

- **The evaluation dataset is synthetic.** Every scenario uses invented
  vendors, customers, and accounts (e.g. `synthetic@example.test`); no real
  data or production system is ever touched.
- **Only the bundled practice fixture ever executes.** The closed loop runs
  exploit and regression jobs against `patchproof/vulnbank/app.py` or the
  loop's isolated temporary copies
  (`secureai-remediation-*/vulnbank_app.py`) — never against the AgentShield
  runtime source.
- **Bounded, fail-closed execution.** Exploit/regression jobs run in a spawned
  child process with a 10-second deadline; a timeout or error stops the loop
  with `approval_required` for human review — a failed check is never
  auto-deployed.
- **Patches land only in the temp copy.** Accepted patches are written to the
  isolated loop copy; the source fixture is never modified.
- **`secureai watch` monitors only that fixture.** It re-runs evaluation when
  the bundled VulnBank fixture's fingerprint changes, and nothing else.
