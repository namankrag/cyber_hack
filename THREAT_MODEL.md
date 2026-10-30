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
  leaks, trust claims can be forged. Current tokens bind to the asserted source,
  **not** yet to a per-call nonce or session, so a captured token can be
  **replayed**. *Planned hardening:* bind tokens to a session id + nonce + expiry.
- **Tools that bypass the PEP.** AgentShield only governs calls that flow through
  the MCP gateway or the `guard` wrapper. A tool invoked directly, around the
  enforcement point, is not protected. The `/v1/check` HTTP endpoint is a
  *decision* point and is advisory by itself.
- **Upstream MCP passthrough.** The MCP gateway currently registers built-in
  demo tools; proxying an arbitrary upstream MCP server is a planned extension
  (the enforcement model is identical).
- **Transport security & deployment.** TLS, network exposure, process
  permissions, secret storage, and log retention/rotation are the operator's
  responsibility. Do not expose the gateway or `/v1/audit` publicly without auth
  (set `AGENTSHIELD_API_KEY`).
- **Data sharing via the LLM detector.** Enabling it sends tool context and
  arguments to a third-party provider; treat it as a deliberate data-sharing
  feature.

## SecureAI evaluation and remediation boundary

- The evaluation dataset is synthetic. The closed loop accepts only the
  bundled VulnBank fixture registered by SecureAI; patches are applied to a
  temporary copy and never written back to the source fixture.
- Exploit and regression jobs run in a child process with a 10-second timeout.
  A timeout or worker error fails closed and requires human review. This is a
  bounded fixture runner, not an operating-system sandbox for arbitrary code;
  the runner must remain restricted to the bundled practice app.
- The `secureai watch` command monitors that fixture and re-runs the evaluation
  when its contents change. It does not watch arbitrary repositories.

## Operator checklist

- [ ] Set `AGENTSHIELD_HARNESS_SECRET` (else runs in insecure dev mode — flagged in `/health`).
- [ ] Set `AGENTSHIELD_API_KEY` before exposing the gateway beyond localhost.
- [ ] Review `redact_keys`; restrict permissions and set retention on the audit file.
- [ ] Decide deliberately whether to enable the LLM detector (data leaves your env).
- [ ] Put real tools behind the `guard` PEP or the MCP gateway — never call them around it.

## Roadmap (deferred hardening)

Session/nonce-bound provenance tokens · upstream MCP proxy passthrough ·
local-model detector (no data egress) · CI + dependency lockfiles ·
Postgres-backed audit with rotation · OPA policy backend · structured request-id logging.
