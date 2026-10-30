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
tool call by adding an `_agentshield` object to its arguments:

    {"to": "...", "_agentshield": {"source": "untrusted", "context": "<doc>"}}

The middleware strips that tag before the real tool sees the arguments.
Untagged calls default to UNTRUSTED for high-sensitivity tools (fail-closed).
"""
from __future__ import annotations

from typing import Any

import mcp.types as mcp_types
from mcp.server.mcpserver import MCPServer

from ..engine_factory import AgentShield
from ..models import Decision, ToolCall, TrustLevel

_TAG = "_agentshield"


class EnforcementMiddleware:
    """MCP ServerMiddleware: `(ctx, call_next) -> result`.

    Intercepts `tools/call`, runs AgentShield, and:
      * ALLOW            -> forwards to the real tool (call_next)
      * DENY             -> short-circuits with an error result (tool never runs)
      * REQUIRE_APPROVAL -> short-circuits, held for a human (tool never runs)

    Every decision is already written to the audit log by `shield.check`.
    """

    def __init__(self, shield: AgentShield) -> None:
        self.shield = shield

    async def __call__(self, ctx, call_next):  # noqa: ANN001 - SDK-typed context
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        name = ctx.params.get("name")
        arguments = dict(ctx.params.get("arguments") or {})

        # Pull provenance tag out of the arguments (if the harness supplied one)
        # so the real tool never sees it.
        tag = arguments.pop(_TAG, {}) or {}
        source = _coerce_source(tag.get("source"))
        context = str(tag.get("context", ""))

        call = ToolCall(
            tool_name=str(name),
            arguments=arguments,
            source=source,
            context=context,
            metadata={"transport": "mcp"},
        )
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


def _coerce_source(value: Any) -> TrustLevel:
    if value is None:
        # No provenance declared → treat as untrusted so high-sensitivity
        # tools fail closed. Low-sensitivity tools are still allowed by policy.
        return TrustLevel.UNTRUSTED
    try:
        return TrustLevel(str(value))
    except ValueError:
        return TrustLevel.UNTRUSTED


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
    server.middleware.insert(0, EnforcementMiddleware(shield))

    @server.tool(description="Search the public web (low sensitivity).")
    def search_web(query: str) -> str:
        return f"[mock] top results for: {query}"

    @server.tool(description="Read an internal document (low sensitivity).")
    def read_document(doc_id: str) -> str:
        return f"[mock] contents of {doc_id}"

    @server.tool(description="Send an email (HIGH sensitivity, approval-gated).")
    def send_email(to: str, body: str = "") -> str:
        return f"[mock] email sent to {to}"

    @server.tool(description="Query the customer database (HIGH sensitivity).")
    def read_customer_db(query: str) -> str:
        return f"[mock] rows for: {query}"

    return server


# Entry point:  python -m agentshield.gateway.mcp_gateway   (stdio transport)
if __name__ == "__main__":  # pragma: no cover
    build_gateway().run()
