"""Isolated red-team harness.

Runs the exact same proposed tool call through two fresh in-process runtimes:
one with enforcement ON and one with enforcement OFF. The comparison is
produced by the real detector + policy engine, not by frontend theater.

Safety properties:
  * The global gateway enforcement switch is never touched.
  * Both runs write to a dedicated red-team audit file, not the main trail.
  * The source trust label is established by this server-side harness, never
    by the browser payload directly (the endpoint itself is admin-key gated).
"""
from __future__ import annotations

import dataclasses
import os
import secrets
import time
from pathlib import Path

from ..config import Config
from ..engine_factory import AgentShield
from ..models import ToolCall, TrustLevel
from . import insights


def _redteam_audit_path() -> Path:
    raw = os.getenv("AGENTSHIELD_REDTEAM_AUDIT_PATH", "audit.redteam.jsonl")
    path = Path(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


_RUNTIMES: dict[tuple[int, bool], AgentShield] = {}


def _runtime(shield: AgentShield, enforce: bool) -> AgentShield:
    """Isolated runtimes, built once per gateway shield and reused.

    Both runs write to the dedicated red-team audit file, never the main
    trail, and the global gateway enforcement switch is never touched.
    The cache is keyed by shield identity so test/reload-rebuilt gateways
    get fresh runtimes; it is bounded so stale entries cannot grow it.
    """
    key = (id(shield), enforce)
    runtime = _RUNTIMES.get(key)
    if runtime is None:
        cfg = dataclasses.replace(
            shield.config,
            audit_path=str(_redteam_audit_path()),
            api_key=None,
            admin_key=None,
        )
        runtime = AgentShield(config=cfg, enforce=enforce)
        if len(_RUNTIMES) >= 16:
            _RUNTIMES.clear()
        _RUNTIMES[key] = runtime
    return runtime


def prime(shield: AgentShield) -> None:
    """Build both isolated runtimes once (called at gateway startup)."""
    _runtime(shield, True)
    _runtime(shield, False)


def _scenario_or_raise(scenario_id: str) -> dict:
    scenarios = {s["id"]: s for s in insights.scenarios()["scenarios"]}
    try:
        return scenarios[scenario_id]
    except KeyError:
        raise ValueError(f"unknown scenario_id: {scenario_id!r}") from None


def _audit_record(runtime: AgentShield, call_id: str) -> dict | None:
    for entry in reversed(runtime.audit.tail(20)):
        if entry.get("call_id") == call_id:
            return entry
    return None


def _stages(decision: str, fail_closed: bool, detections: list[dict],
            reasons: list[dict], audit_record: dict | None,
            source: str, enforced: bool, duration_ms: float) -> list[dict]:
    errors = [d for d in detections if d.get("error")]
    threat = [d for d in detections if d.get("is_threat") and not d.get("error")]
    blocked = decision in ("deny", "require_approval")
    return [
        {
            "key": "request",
            "label": "Agent request",
            "status": "complete",
            "detail": "Tool call captured at the boundary.",
        },
        {
            "key": "provenance",
            "label": "Provenance verification",
            "status": "complete",
            "detail": f"Resolved source: {source}.",
        },
        {
            "key": "detection",
            "label": "Threat detection",
            "status": "warning" if errors else "complete",
            "detail": (
                f"{len(threat)} threat signal(s); "
                f"{len(detections)} detector run(s)"
                + (f"; {len(errors)} error(s)" if errors else "")
            ),
        },
        {
            "key": "policy",
            "label": "Policy evaluation",
            "status": "complete",
            "detail": "Rules fired: " + (", ".join(r.get("rule", "rule") for r in reasons) or "none"),
        },
        {
            "key": "decision",
            "label": "Enforcement decision",
            "status": "complete" if enforced else "warning",
            "detail": (
                f"{decision.upper()}"
                + (" · fail-closed" if fail_closed else "")
                + ("" if enforced else " · enforcement bypassed in OFF run")
            ),
            "blocked": blocked,
        },
        {
            "key": "audit",
            "label": "Audit logging",
            "status": "complete" if audit_record else "warning",
            "detail": (
                f"Recorded as {audit_record.get('call_id')}."
                if audit_record else "No audit record was found for this run."
            ),
        },
    ]


def _run(runtime: AgentShield, call: ToolCall, enforced: bool) -> dict:
    started = time.perf_counter()
    result = runtime.check(call)
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    audit_record = _audit_record(runtime, call.id)
    detections = [d.model_dump(mode="json") for d in result.detections]
    reasons = [r.model_dump(mode="json") for r in result.reasons]
    return {
        "enforced": enforced,
        "decision": result.decision.value,
        "fail_closed": result.fail_closed,
        "call_id": call.id,
        "headline": result.headline(),
        "reasons": reasons,
        "detections": detections,
        "duration_ms": duration_ms,
        "audit_record": audit_record,
        "stages": _stages(result.decision.value, result.fail_closed,
                          detections, reasons, audit_record,
                          call.source.value, enforced, duration_ms),
    }


def run(shield: AgentShield, payload: dict) -> dict:
    """Execute one server-side scenario through isolated OFF and ON runtimes.

    The tool call is built ONLY from the server-side scenario definition:
    caller-supplied tool_name/arguments/source/context in the request body
    are ignored, so an untrusted browser cannot escalate the lab run.
    """
    scenario_id = payload.get("scenario_id")
    if not scenario_id:
        raise ValueError("scenario_id is required: the harness executes a "
                         "server-side scenario, never a caller-supplied call")
    scenario = _scenario_or_raise(str(scenario_id))
    tool_name = str(scenario.get("tool_name") or "").strip()
    if not tool_name:
        raise ValueError(f"scenario {scenario_id!r} has no tool_name")
    arguments = scenario.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
    context = str(scenario.get("context") or "")
    source_raw = str(scenario.get("source") or "untrusted")
    try:
        source = TrustLevel(source_raw)
    except ValueError as exc:
        raise ValueError(f"invalid scenario source: {source_raw}") from exc

    run_id = f"rt_{secrets.token_hex(6)}"
    metadata = {
        "agent": "red-team-harness",
        "session_id": run_id,
        "scenario_id": scenario_id,
        "harness": "agentshield-redteam",
    }
    call = ToolCall(tool_name=tool_name, arguments=arguments,
                    source=source, context=context, metadata=metadata)

    # A fresh call ID per run keeps the two audit records distinguishable.
    on_call = call.model_copy(update={"id": f"call_{secrets.token_hex(6)}"})
    off_call = call.model_copy(update={"id": f"call_{secrets.token_hex(6)}"})

    on_result = _run(_runtime(shield, True), on_call, True)
    off_result = _run(_runtime(shield, False), off_call, False)

    return {
        "run_id": run_id,
        "generated_at": time.time(),
        "scenario_id": scenario_id,
        "request": {
            "tool_name": tool_name,
            "arguments": arguments,
            "source": source.value,
            "context": context,
            "metadata": metadata,
        },
        "on": on_result,
        "off": off_result,
        "comparison": {
            "gate_off_permitted": off_result["decision"] == "allow",
            "gate_on_blocked": on_result["decision"] in ("deny", "require_approval"),
            "verdict_changed": off_result["decision"] != on_result["decision"],
        },
        "audit_path": str(_redteam_audit_path()),
        "global_enforcement_unchanged": True,
        "notes": {
            "isolation": "Both runs use fresh in-process runtimes and a dedicated red-team audit file. The global gateway enforcement switch is unchanged.",
            "provenance": "Source is set by the server-side harness for the lab. In production, provenance comes from the trusted harness token/scope, never a browser claim.",
        },
    }


def history(limit: int = 20) -> dict:
    path = _redteam_audit_path()
    from ..audit.log import AuditLog

    audit = AuditLog(path)
    entries = audit.tail(max(2, min(limit * 2, 200)))
    entries.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    return {
        "generated_at": time.time(),
        "path": str(path),
        "entries": entries[:limit],
        "available": path.exists(),
    }
