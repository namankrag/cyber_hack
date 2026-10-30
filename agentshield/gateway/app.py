"""FastAPI enforcement gateway.

An agent (or an MCP proxy in front of the agent) POSTs a proposed tool call
to /v1/check *before* executing it. AgentShield returns the decision. The
agent is contractually required to execute only on ALLOW, route
REQUIRE_APPROVAL to a human queue, and drop DENY.

Run:  uvicorn agentshield.gateway.app:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from ..engine_factory import AgentShield
from ..models import PolicyReason, ToolCall, TrustLevel

app = FastAPI(
    title="AgentShield",
    version="0.1.0",
    description="Secure the agent, not just the prompt. "
                "Policy enforcement at the tool-call boundary.",
)

# Single shared runtime; the engine itself is stateless per call.
shield = AgentShield()


class CheckRequest(BaseModel):
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    source: TrustLevel = TrustLevel.USER
    context: str = ""
    metadata: dict = Field(default_factory=dict)


class CheckResponse(BaseModel):
    call_id: str
    decision: str
    fail_closed: bool
    reasons: list[PolicyReason]
    headline: str


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "detectors": [d.name for d in shield.detectors],
        "policy": shield.config.policy_path,
        "tools_governed": sorted(shield.policy.tools.keys()),
    }


@app.post("/v1/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    call = ToolCall(
        tool_name=req.tool_name,
        arguments=req.arguments,
        source=req.source,
        context=req.context,
        metadata=req.metadata,
    )
    result = shield.check(call)
    return CheckResponse(
        call_id=call.id,
        decision=result.decision.value,
        fail_closed=result.fail_closed,
        reasons=result.reasons,
        headline=result.headline(),
    )


@app.get("/v1/audit")
def audit(limit: int = 20) -> dict:
    """Recent decisions — this is what the dashboard will render."""
    return {"entries": shield.audit.tail(limit)}
