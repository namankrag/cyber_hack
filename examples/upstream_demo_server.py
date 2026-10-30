"""Synthetic upstream MCP server for the AgentShield proxy path.

A tiny, deliberately harmless stdio MCP server (echo / add / now) that the
AgentShield gateway can front as an *upstream*. It exists so the drop-in
proxy story is runnable end to end without any third-party server:

    AGENTSHIELD_UPSTREAM_CMD="python examples/upstream_demo_server.py"

Run from the project root, or point the gateway at any other MCP server
speaking stdio — the gateway lists tools from the upstream and forwards
calls through the same EnforcementMiddleware either way.

Synthetic data only: no network, no credentials, no side effects.
"""
from __future__ import annotations

import time

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="UpstreamDemo",
    instructions="Synthetic upstream: echo, add, now. No side effects.",
)


@server.tool(description="Echo text back unchanged (harmless).")
def echo(text: str) -> str:
    return text


@server.tool(description="Add two numbers and return the sum (harmless).")
def add(a: float, b: float) -> str:
    return str(a + b)


@server.tool(description="Return the current UTC time (harmless).")
def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main() -> None:
    server.run()  # stdio transport: speaks newline-delimited JSON-RPC


if __name__ == "__main__":  # pragma: no cover
    main()
