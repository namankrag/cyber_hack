"""Server-side 'can the agent fake its way in?' demo.

Two (or three) checks go through the same ``resolve`` path as ``POST /v1/check``.
The request body cannot choose the tool or the token.
"""
from __future__ import annotations

from typing import Any

from ..engine_factory import AgentShield
from ..models import ToolCall
from ..provenance import insecure_dev_mode, mint_token, resolve_detail

_TOOL = "read_customer_db"
_ARGUMENTS = {"query": "SELECT * FROM customers"}
_ASSERTED = "user"


def _row(label: str, token_kind: str, token: str | None,
         shield: AgentShield) -> dict[str, Any]:
    level, reason = resolve_detail(_ASSERTED, token)
    call = ToolCall(
        tool_name=_TOOL,
        arguments=dict(_ARGUMENTS),
        source=level,
        context="",
        metadata={"surface": "trust-demo"},
    )
    result = shield.check(call)
    return {
        "label": label,
        "asserted_source": _ASSERTED,
        "token": token_kind,
        "resolved_source": level.value,
        "resolve_reason": reason,
        "decision": result.decision.value,
        "reasons": [r.model_dump(mode="json") for r in result.reasons],
        "call_id": call.id,
    }


def run(shield: AgentShield) -> dict[str, Any]:
    if insecure_dev_mode():
        raise RuntimeError(
            "Harness secret is not set: claimed sources would be honoured "
            "(dev mode). Set AGENTSHIELD_HARNESS_SECRET and retry.")

    missing = _row("Claimed user, no token", "none", None, shield)
    token = mint_token(_ASSERTED)
    genuine = _row("Claimed user, harness-minted token", "valid", token, shield)
    replayed = _row("Same token replayed", "replayed", token, shield)
    return {
        "tool": _TOOL,
        "arguments": dict(_ARGUMENTS),
        "checks": [missing, genuine, replayed],
    }
