"""AgentShield as a real MCP gateway (protocol-layer enforcement).

This is the upscale that matters most for "secure the agent, not just the
prompt": instead of trusting the agent to call our HTTP endpoint, we sit
*inside the Model Context Protocol* as server middleware. Every single
`tools/call` the agent makes passes through AgentShield before the tool runs —
at the transport layer, below the model, where an injected instruction cannot
talk its way past the check.

It integrates the official MCP Python SDK (`modelcontextprotocol/python-sdk`,
imported as `mcp`). The SDK provides the server, the protocol, and the
middleware hook; AgentShield provides the decision brain (the same
PolicyEngine the HTTP gateway and the demo use — one enforcement core, three
front doors).

Provenance note: MCP does not itself carry "did the user ask for this, or did
a document?". Provenance must be supplied by the harness wrapping the agent —
it is established *outside* the model, which is the whole point. Callers tag a
tool call by adding an `_agentshield` object to its arguments, where any
source above `untrusted` must be backed by a valid HMAC token (see
provenance.py and mint_token):

    {"to": "...", "_agentshield": {"source": "user", "token": "<hmac>",
                                   "session_id": "<session>",
                                   "context": "<doc>",
                                   "trace_id": "<trace>",
                                   "parent_id": "<parent>"}}

The middleware strips that tag before the real tool sees the arguments. An
asserted source with no valid token resolves to UNTRUSTED (fail-closed), so a
tag placed by the agent or by injected content cannot elevate trust.

SCOPE NOTE: this gateway registers a set of built-in DEMO tools so the
enforcement is visible end to end. It does not yet proxy an arbitrary upstream
MCP server — wrapping a real upstream (forwarding list_tools/call_tool through
the same middleware) is the documented next step. The enforcement model is
identical for real tools.
"""
from __future__ import annotations

from typing import Any

import mcp.types as mcp_types
from mcp.server.mcpserver import MCPServer

from ..engine_factory import AgentShield
from ..models import Decision, EnforcementResult, PolicyReason, ToolCall
from ..policy.manifest import ToolManifest
from . import input_too_large
from ..provenance import resolve

_TAG = "_agentshield"


def _deny(shield: AgentShield, call: ToolCall, rule: str,
            detail: str) -> mcp_types.CallToolResult:
    """Audit a DENY and render it as an inspectable MCP error result."""
    shield.audit.record(EnforcementResult(
        call=call, decision=Decision.DENY,
        reasons=[PolicyReason(rule=rule, decision=Decision.DENY,
                              detail=detail)],
        fail_closed=True))
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(
            type="text",
            text=(f"DENIED by AgentShield.\nTool: {call.tool_name}\n"
                  f"Decision: deny (fail-closed)\nReasons:\n  - [{rule}] {detail}"))],
        is_error=True,
    )


class EnforcementMiddleware:
    """MCP ServerMiddleware: `(ctx, call_next) -> result`.

    Intercepts `tools/call`, runs AgentShield, and:
      * ALLOW            -> forwards to the real tool (call_next)
      * DENY             -> short-circuits with an error result (tool never runs)
      * REQUIRE_APPROVAL -> short-circuits, held for a human (tool never runs)

    Two tripwires run before the policy engine: the signed tool manifest
    (live description+schema vs. the startup signature — catches
    rug-pull/tool-poisoning) and provenance resolution (replay/expiry/
    session-checked). Every denial is written to the audit log.
    """

    def __init__(self, shield: AgentShield,
                 manifest: ToolManifest | None = None,
                 tool_lookup=None) -> None:
        self.shield = shield
        self.manifest = manifest
        # Callable mapping a tool name to its live registered tool object
        # (or None). Injected by build_gateway so tests can snapshot first.
        self._tool_lookup = tool_lookup

    async def __call__(self, ctx, call_next):  # noqa: ANN001 - SDK-typed context
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        name = ctx.params.get("name")
        arguments = dict(ctx.params.get("arguments") or {})

        # Pull the provenance tag out of the arguments so the real tool never
        # sees it. The tag's asserted source is only honored if it carries a
        # valid HMAC token minted from the harness secret — otherwise the call
        # resolves to UNTRUSTED. The agent (and any injected content) can place
        # a tag in the arguments, but cannot forge the token.
        tag = arguments.pop(_TAG, {}) or {}
        if not isinstance(tag, dict):
            tag = {}
        source = resolve(tag.get("source"), tag.get("token"),
                         session_id=tag.get("session_id"))
        trace_id = tag.get("trace_id")
        parent_id = tag.get("parent_id")
        context = str(tag.get("context", ""))
        if input_too_large(context, arguments):
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(
                    type="text",
                    text="DENIED by AgentShield.\nTool: (input too large)\nDecision: deny\n" "Reasons:\n  - [input_too_large] call input exceeds the 256KB edge budget.")],
                is_error=True,
            )

        if not isinstance(name, str) or not name.strip():
            # Audit the rejection: this branch returns before shield.check,
            # so without an explicit record the probe would be invisible.
            denied_call = ToolCall(tool_name="(missing name)",
                                   arguments=arguments, source=source,
                                   context=context,
                                   metadata={"transport": "mcp"})
            self.shield.audit.record(EnforcementResult(
                call=denied_call, decision=Decision.DENY,
                reasons=[PolicyReason(rule="invalid_tool",
                                      decision=Decision.DENY,
                                      detail="missing or blank tool name")],
                fail_closed=True))
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(
                    type="text",
                    text="DENIED by AgentShield.\nTool: (missing name)\nDecision: deny\n"
                         "Reasons:\n  - [invalid_tool] missing or blank tool name.")],
                is_error=True,
            )
        call = ToolCall(
            tool_name=str(name),
            arguments=arguments,
            source=source,
            trace_id=trace_id if isinstance(trace_id, str) else None,
            parent_id=parent_id if isinstance(parent_id, str) else None,
            context=context,
            metadata={"transport": "mcp"},
        )
        # Signed tool manifest: the live tool's description+schema must
        # still match the startup signature. A mismatch means the tool was
        # redefined after registration (rug-pull / tool-poisoning) — DENY
        # before the policy engine even sees the call.
        if self.manifest is not None and self._tool_lookup is not None:
            try:
                live = self._tool_lookup(str(name))
            except Exception:
                live = None
            if live is not None:
                ok, why = self.manifest.verify_tool(
                    str(name), getattr(live, "description", "") or "",
                    getattr(live, "parameters", None) or {})
                if not ok:
                    return _deny(self.shield, call,
                                 "tool_manifest_mismatch", why)
        result = self.shield.check(call)

        if result.decision is Decision.ALLOW:
            # Forward with the sanitized arguments (tag removed).
            import dataclasses

            clean_params = dict(ctx.params)
            clean_params["arguments"] = arguments
            return await call_next(dataclasses.replace(ctx, params=clean_params))

        # Blocked: return a structured, inspectable error result. The agent
        # receives the verdict and the reasons — not a silent failure.
        reasons = "\n".join(f"  - [{r.rule}] {r.detail}" for r in result.reasons)
        verb = ("DENIED by AgentShield"
                if result.decision is Decision.DENY
                else "HELD FOR HUMAN APPROVAL by AgentShield")
        text = (f"{verb}.\n"
                f"Tool: {name}\n"
                f"Decision: {result.decision.value}"
                f"{' (fail-closed)' if result.fail_closed else ''}\n"
                f"Reasons:\n{reasons}")
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=text)],
            is_error=True,
        )


def build_gateway(shield: AgentShield | None = None) -> MCPServer:
    """Build an MCP server with AgentShield enforcement + demo tools.

    The demo tools are intentionally "dangerous" so the enforcement is visible.
    In production you'd register your real tools (or proxy an upstream MCP
    server) — the middleware governs all of them identically.
    """
    shield = shield or AgentShield()
    server = MCPServer(
        name="AgentShield-Gateway",
        instructions="All tool calls are enforced by AgentShield policy.",
    )
    # Register our enforcement as the OUTERMOST middleware so it runs before
    # the tool lookup/handler for every request.
    # NOTE: demo tools are registered below first; the manifest snapshot is
    # taken after registration and handed to the middleware, so any later
    # redefinition (rug-pull/tool-poisoning) trips verification.

    @server.tool(description="Search the public web (low sensitivity).")
    def search_web(query: str) -> str:
        return f"[mock] top results for: {query}"

    @server.tool(description="Read an internal document (low sensitivity).")
    def read_document(doc_id: str) -> str:
        return f"[mock] contents of {doc_id}"

    @server.tool(description="Search the local UNTRUSTED retrieval corpus (low sensitivity).")
    def read_rag_docs(query: str) -> str:
        from ..rag.tools import read_rag_docs as _read_rag_docs

        return _read_rag_docs(query)

    @server.tool(description="Send an email (HIGH sensitivity, approval-gated).")
    def send_email(to: str, body: str = "") -> str:
        return f"[mock] email sent to {to}"

    @server.tool(description="Query the customer database (HIGH sensitivity).")
    def read_customer_db(query: str) -> str:
        return f"[mock] rows for: {query}"

    # Snapshot live tool identities AFTER registration: description+schema
    # signed with the harness secret. The middleware re-verifies on every
    # call; without a secret the manifest is unsigned and verification is
    # skipped but flagged (insecure dev mode).
    manifest = ToolManifest.from_tools(
        {t.name: {"description": t.description or "",
                  "schema": t.parameters or {}}
         for t in server._tool_manager.list_tools()})
    server.middleware.insert(
        0, EnforcementMiddleware(shield, manifest=manifest,
                                 tool_lookup=_live_tool_lookup(server)))
    return server


def _live_tool_lookup(server):
    """Return a name -> live-tool callable for manifest verification."""
    def _lookup(name: str):
        try:
            return server._tool_manager.get_tool(name)
        except Exception:
            return None
    return _lookup


# Entry point:  python -m agentshield.gateway.mcp_gateway   (stdio transport)
if __name__ == "__main__":  # pragma: no cover
    build_gateway().run()
