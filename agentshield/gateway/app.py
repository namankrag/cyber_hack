"""FastAPI gateway.

Two distinct roles, kept honest:

  * `/v1/check` is a Policy DECISION Point (PDP). It returns a verdict. It is
    advisory: a caller who ignores the verdict is not stopped here. Unavoidable
    enforcement lives at the execution path — the `guard` PEP (agentshield.enforce)
    and the MCP gateway middleware, which run the tool only on ALLOW.

Security controls (from review):
  * Optional API-key auth (AGENTSHIELD_API_KEY). When set, every endpoint —
    including /v1/audit — requires it. The audit trail is sensitive and is not
    exposed unauthenticated.
  * Provenance is resolved from a trusted HMAC token, NOT from a caller-supplied
    `source` field. Without a valid token (and outside insecure dev mode) a call
    is treated as UNTRUSTED. See agentshield.provenance.
  * `limit` on /v1/audit is bounded.

Run:  uvicorn agentshield.gateway.app:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ..engine_factory import AgentShield
from ..models import PolicyReason, ToolCall
from ..provenance import insecure_dev_mode, resolve

app = FastAPI(
    title="AgentShield",
    version="0.2.0",
    description="Secure the agent, not just the prompt. "
                "Policy enforcement at the tool-call boundary.",
)

# Single shared runtime; the engine itself is stateless per call.
shield = AgentShield()


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Gate every endpoint behind an API key when one is configured."""
    configured = shield.config.api_key
    if configured is None:
        return  # no key set -> open (dev); /health flags this
    if not x_api_key or x_api_key != configured:
        raise HTTPException(status_code=401, detail="missing or invalid API key")


class CheckRequest(BaseModel):
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    # A caller may *assert* a source, but it is only honored with a valid
    # provenance_token (minted from the server-side harness secret). Otherwise
    # the call resolves to UNTRUSTED.
    source: str | None = None
    provenance_token: str | None = None
    context: str = ""
    metadata: dict = Field(default_factory=dict)


class CheckResponse(BaseModel):
    call_id: str
    decision: str
    fail_closed: bool
    resolved_source: str
    reasons: list[PolicyReason]
    headline: str


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "detectors": [d.name for d in shield.detectors],
        "policy": shield.config.policy_path,
        "tools_governed": sorted(shield.policy.tools.keys()),
        "auth_required": shield.config.api_key is not None,
        "insecure_provenance_dev_mode": insecure_dev_mode(),
    }


@app.get("/ready")
def ready() -> dict:
    """Readiness: policy loaded and at least one detector active."""
    ok = bool(shield.detectors) and bool(shield.policy)
    if not ok:
        raise HTTPException(status_code=503, detail="not ready")
    return {"ready": True}


@app.post("/v1/check", response_model=CheckResponse,
          dependencies=[Depends(require_api_key)])
def check(req: CheckRequest) -> CheckResponse:
    source = resolve(req.source, req.provenance_token)
    call = ToolCall(
        tool_name=req.tool_name,
        arguments=req.arguments,
        source=source,
        context=req.context,
        metadata=req.metadata,
    )
    result = shield.check(call)
    return CheckResponse(
        call_id=call.id,
        decision=result.decision.value,
        fail_closed=result.fail_closed,
        resolved_source=source.value,
        reasons=result.reasons,
        headline=result.headline(),
    )


@app.get("/v1/audit", dependencies=[Depends(require_api_key)])
def audit(limit: int = Query(default=20, ge=1, le=500)) -> dict:
    """Recent decisions (auth-gated; bounded)."""
    return {"entries": shield.audit.tail(limit)}
