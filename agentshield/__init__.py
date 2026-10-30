"""AgentShield — secure the agent, not just the prompt.

A policy enforcement point that sits between an AI agent and its tools.
Every tool call is inspected and gets an explicit, logged decision:
ALLOW, DENY, or REQUIRE_APPROVAL — fail-closed by default.
"""

__version__ = "0.1.0"
