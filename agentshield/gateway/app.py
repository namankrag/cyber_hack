"""FastAPI gateway.

Two distinct roles, kept honest:

  * `/v1/check` is a Policy DECISION Point (PDP). It returns a verdict. It is
    advisory: a caller who ignores the verdict is not stopped here. Unavoidable
    enforcement lives at the execution path — the `guard` PEP (agentshield.enforce)
    and the MCP gateway middleware, which run the tool only on ALLOW.

Security controls (from review):
  * Optional API-key auth (AGENTSHIELD_API_KEY). When set, every endpoint —
    including /v1/audit and /v1/evidence — requires it. The audit trail is
    sensitive and is not exposed unauthenticated.
  * Optional split admin key (AGENTSHIELD_ADMIN_KEY). When set, /v1/admin/*
    requires it instead of the regular API key, so a leaked read key cannot
    flip the global enforcement switch.
  * Provenance is resolved from a trusted HMAC token, NOT from a caller-supplied
    `source` field. Without a valid token (and outside insecure dev mode) a call
    is treated as UNTRUSTED. See agentshield.provenance.
  * `limit` on /v1/audit is bounded.

Run:  uvicorn agentshield.gateway.app:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import hmac
import os
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import MAX_BODY_BYTES
from .dashboard import PAGE as _DASHBOARD_PAGE
from ..engine_factory import AgentShield
from ..models import PolicyReason, ToolCall
from ..provenance import insecure_dev_mode, resolve

_DOCS_ON = os.getenv("AGENTSHIELD_ENABLE_DOCS", "1") != "0"

app = FastAPI(
    title="AgentShield",
    version="0.2.0",
    description="Secure the agent, not just the prompt. "
                "Policy enforcement at the tool-call boundary.",
    # Interactive docs are a demo asset; prod deployments set
    # AGENTSHIELD_ENABLE_DOCS=0 to close the info surface.
    docs_url="/docs" if _DOCS_ON else None,
    redoc_url="/redoc" if _DOCS_ON else None,
    openapi_url="/openapi.json" if _DOCS_ON else None,
)

# Single shared runtime; the engine itself is stateless per call.
shield = AgentShield()


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Non-breaking hardening headers on every response (incl. errors)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.middleware("http")
async def _body_size_limit(request: Request, call_next):
    """Reject oversized bodies with 413 before detection burns CPU.

    The synchronous heuristic scans ~1MB of surfaces per 1MB of input
    (~5s of blocked event loop for 5MB, measured). content-length is
    checked first; length-less chunked streams are an accepted residual
    (edge/infra should cap too). Legit tool calls carry kilobytes.
    """
    if request.method in ("POST", "PUT", "PATCH"):
        declared = request.headers.get("content-length")
        if (declared is not None and declared.isdigit()
                and int(declared) > MAX_BODY_BYTES):
            return JSONResponse({"detail": "request body too large"},
                                status_code=413)
    return await call_next(request)




_RATE_BUCKETS: dict[str, list] = {}  # ip -> [window_minute, count]
_RATE_CAP_IPS = 4096  # bound the table itself: XFF is spoofable


def _rate_limit_per_min() -> int:
    try:
        return max(0, int(os.getenv("AGENTSHIELD_RATE_LIMIT_PER_MIN",
                                    "600") or 0))
    except ValueError:
        return 600


@app.middleware("http")
async def _rate_limit(request: Request, call_next):
    """Fixed-window per-IP backstop (429 + Retry-After).

    Edge/Render does the real limiting; this only stops a burst from
    melting the single demo worker. Liveness probes are exempt so the
    platform never 429s a healthy service into a restart loop. A limit
    of 0 disables the middleware. X-Forwarded-For is honored but
    spoofable — hence backstop, not boundary.
    """
    if request.url.path in ("/health", "/ready"):
        return await call_next(request)
    limit = _rate_limit_per_min()
    if limit > 0:
        fwd = request.headers.get("x-forwarded-for", "")
        ip = ((fwd.split(",")[0].strip() if fwd else "")
              or (request.client.host if request.client else "unknown"))
        now_min = int(time.time() // 60)
        bucket = _RATE_BUCKETS.get(ip)
        if bucket is None or bucket[0] != now_min:
            bucket = [now_min, 0]
            _RATE_BUCKETS[ip] = bucket
            if len(_RATE_BUCKETS) > _RATE_CAP_IPS:
                _RATE_BUCKETS.pop(next(iter(_RATE_BUCKETS)))
        bucket[1] += 1
        if bucket[1] > limit:
            return JSONResponse({"detail": "rate limit exceeded"},
                                status_code=429,
                                headers={"Retry-After": "60"})
    return await call_next(request)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Gate every endpoint behind an API key when one is configured."""
    configured = shield.config.api_key
    if configured is None:
        return  # no key set -> open (dev); /health flags this
    if not _key_ok(x_api_key, configured):
        raise HTTPException(status_code=401, detail="missing or invalid API key")


def _key_ok(provided: str | None, configured: str | None) -> bool:
    if configured is None or not provided:
        return False
    # Constant-time compare: == leaks the key byte-by-byte to timing probes.
    return hmac.compare_digest(provided, configured)


def require_api_admin(x_api_key: str | None = Header(default=None)) -> None:
    """Gate admin endpoints. A dedicated AGENTSHIELD_ADMIN_KEY, when set, is
    required; otherwise the regular API key gates them."""
    admin = shield.config.admin_key
    if admin is not None:
        if not _key_ok(x_api_key, admin):
            raise HTTPException(status_code=401, detail="missing or invalid admin key")
        return
    require_api_key(x_api_key)


class CheckRequest(BaseModel):
    tool_name: str = Field(min_length=1)
    arguments: dict = Field(default_factory=dict)
    # A caller may *assert* a source, but it is only honored with a valid
    # provenance_token (minted from the server-side harness secret). Otherwise
    # the call resolves to UNTRUSTED.
    source: str | None = None
    provenance_token: str | None = None
    # Session the token is bound to (single-use tokens may pin one; a
    # mismatch resolves UNTRUSTED). Optional: unbound tokens verify anywhere.
    session_id: str | None = None
    # Cross-agent correlation IDs, propagated into the ToolCall, every audit
    # record, and the approval args hash. Optional (backward compatible).
    trace_id: str | None = None
    parent_id: str | None = None
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
    # Unauthenticated by design (liveness). No sensitive fields here: the
    # policy path, the governed-tool list, and the dev-mode flag are only
    # visible via the key-gated /v1/evidence endpoint.
    return {
        "status": "ok",
        "detectors": [d.name for d in shield.detectors],
        "auth_required": shield.config.api_key is not None,
    }


@app.get("/ready")
def ready() -> dict:
    """Readiness: policy loaded and at least one detector active."""
    ok = bool(shield.detectors) and bool(shield.policy)
    if not ok:
        raise HTTPException(status_code=503, detail="not ready")
    return {"ready": True}


@app.get("/", include_in_schema=False)
def dashboard() -> HTMLResponse:
    """Live demo dashboard (self-contained HTML, no CDN — works offline)."""
    return HTMLResponse(_DASHBOARD_PAGE)


@app.post("/v1/check", response_model=CheckResponse,
          dependencies=[Depends(require_api_key)])
def check(req: CheckRequest,
          x_trace_id: str | None = Header(default=None),
          x_parent_id: str | None = Header(default=None)) -> CheckResponse:
    # Trace IDs ride in the body first, then the X-Trace-Id / X-Parent-Id
    # headers (agent frameworks that cannot touch the body can still
    # correlate), then absent (None — still fully enforced).
    source = resolve(req.source, req.provenance_token,
                     session_id=req.session_id)
    call = ToolCall(
        tool_name=req.tool_name,
        arguments=req.arguments,
        source=source,
        trace_id=req.trace_id or x_trace_id,
        parent_id=req.parent_id or x_parent_id,
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


class EnforceUpdate(BaseModel):
    enabled: bool


@app.get("/v1/enforce", dependencies=[Depends(require_api_key)])
def enforce_state() -> dict:
    """Current enforcement switch (demo OFF/ON theater)."""
    return {"enforced": shield.enforce}


@app.post("/v1/admin/enforce", dependencies=[Depends(require_api_admin)])
def set_enforce(body: EnforceUpdate) -> dict:
    """Flip the demo OFF/ON switch. Key-gated and audit-logged."""
    import json as _json
    import secrets as _secrets
    import time as _time

    shield.enforce = body.enabled
    note = {
        "ts": _time.time(),
        "call_id": f"admin_{_secrets.token_hex(6)}",
        "trace_id": None,
        "parent_id": None,
        "tool": "admin",
        # Not a hold: without this marker the approval queue would list
        # admin toggle notes as human-approval work items.
        "approval_of": "admin-action-no-hold",
        "arguments": {"action": "set_enforce", "enabled": body.enabled},
        "source": "user",
        "decision": "require_approval",
        "fail_closed": False,
        "reasons": [{"rule": "admin_action",
                     "decision": "require_approval",
                     "detail": f"enforcement {'enabled' if body.enabled else 'disabled'} via admin API"}],
        "detections": [],
        "metadata": {"actor": "admin-api"},
    }
    with shield.audit._lock:
        with shield.audit.path.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps(note) + "\n")
    return {"enforced": shield.enforce}


@app.post("/v1/admin/reset", dependencies=[Depends(require_api_admin)])
def reset_demo() -> dict:
    """Reset demo state: re-ingest the RAG corpus. Audit history is kept."""
    from ..rag.store import default_store

    n = default_store().ingest()
    return {"reset": True, "corpus_docs": n}


class DecideRequest(BaseModel):
    call_id: str = Field(min_length=1)
    verdict: str = Field(min_length=1)
    approver: str = "human"


def _approval_queue():
    from ..approval.queue import ApprovalQueue

    return ApprovalQueue(shield.audit)


@app.get("/v1/approvals/pending", dependencies=[Depends(require_api_key)])
def approvals_pending() -> dict:
    """Held calls awaiting a human decision (auth-gated, like /v1/audit)."""
    from ..approval.queue import args_hash

    out = []
    for e in _approval_queue().pending():
        out.append({"call_id": e.get("call_id"),
                    "tool": e.get("tool"),
                    "arguments": e.get("arguments", {}),
                    "source": e.get("source"),
                    "trace_id": e.get("trace_id"),
                    "parent_id": e.get("parent_id"),
                    "decision": e.get("decision"),
                    "reasons": e.get("reasons", []),
                    "args_hash": args_hash(e.get("tool", ""),
                                           e.get("arguments", {}),
                                           e.get("metadata", {}),
                                           e.get("trace_id"),
                                           e.get("parent_id"))})
    return {"pending": out}


@app.post("/v1/approvals/decide", dependencies=[Depends(require_api_key)])
def approvals_decide(body: DecideRequest) -> dict:
    """Record a single-use human decision on a held call (approve/deny)."""
    if body.verdict not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="verdict must be 'approve' or 'deny'")
    try:
        entry = _approval_queue().decide(body.call_id, body.verdict,
                                         approver=body.approver)
    except ValueError as exc:
        msg = str(exc)
        if "no such held call" in msg:
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=409, detail=msg)
    return {"approval_of": entry["approval_of"], "approval": entry["approval"]}


@app.get("/v1/evidence", dependencies=[Depends(require_api_key)])
def evidence(limit: int = Query(default=20, ge=1, le=500)) -> dict:
    """Evidence pack for judges: health, switch state, recent audit entries."""
    return {"health": health(),
            "enforced": shield.enforce,
            "provenance_dev_mode": insecure_dev_mode(),
            "manifest_enforced": shield.manifest_enforced,
            "entries": shield.audit.tail(limit)}


@app.get("/v1/bench/latest", dependencies=[Depends(require_api_key)])
def bench_latest() -> dict:
    """Newest benchmark scorecard (bench/results_*.json), if any run exists."""
    from .dashboard import latest_bench_results

    return {"latest": latest_bench_results()}
