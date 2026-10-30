"""Shared core — one security-event model for both layers.

AgentShield and PatchProof already share the same DNA: each produces an
inspectable, evidence-backed verdict. This module makes that literal. Both an
AgentShield runtime decision and a PatchProof code finding map onto one
`SecurityEvent`, so the platform can store, link, and render them together.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from . import REPO_ROOT


class Layer(str, Enum):
    RUNTIME = "runtime"   # AgentShield: what the agent tried to DO
    CODE = "code"         # PatchProof: what's wrong in the code it runs on


class Status(str, Enum):
    # Runtime outcomes
    ALLOWED = "allowed"
    HELD = "held"                 # require-approval
    BLOCKED = "blocked"           # denied
    # Code outcomes
    FIXED = "fixed"               # found, exploit-proven, patched, verified
    REJECTED = "rejected"         # a patch that broke the app / didn't hold
    UNCONFIRMED = "unconfirmed"   # scanner flagged, exploit didn't confirm


_RANK = {  # for sorting / headline severity
    Status.BLOCKED: 5, Status.FIXED: 4, Status.REJECTED: 3,
    Status.HELD: 2, Status.UNCONFIRMED: 1, Status.ALLOWED: 0,
}


@dataclass
class SecurityEvent:
    layer: Layer
    status: Status
    title: str
    detail: str
    severity: str = "info"        # critical/high/medium/low/info
    evidence: str = ""
    ref: str = ""                 # tool name, CWE, file:line, call id...
    links: list[str] = field(default_factory=list)   # refs of related events
    ts: float = field(default_factory=time.time)

    @property
    def rank(self) -> int:
        return _RANK.get(self.status, 0)


# --- adapters: each tool's native result -> one shared event --------------
def from_enforcement(result) -> SecurityEvent:
    """AgentShield EnforcementResult -> runtime SecurityEvent."""
    from agentshield.models import Decision
    status = {
        Decision.ALLOW: Status.ALLOWED,
        Decision.REQUIRE_APPROVAL: Status.HELD,
        Decision.DENY: Status.BLOCKED,
    }[result.decision]
    top = result.reasons[-1].detail if result.reasons else ""
    sev = "high" if result.decision is Decision.DENY else (
        "medium" if result.decision is Decision.REQUIRE_APPROVAL else "info")
    return SecurityEvent(
        layer=Layer.RUNTIME, status=status, severity=sev,
        title=f"tool call: {result.call.tool_name}",
        detail=top,
        evidence="; ".join(r.detail for r in result.reasons),
        ref=result.call.tool_name,
    )


def from_issue(issue) -> SecurityEvent:
    """PatchProof IssueReport -> code SecurityEvent."""
    f = issue.finding
    if not issue.confirmed:
        status = Status.UNCONFIRMED
    elif issue.verification and issue.verification.accepted:
        status = Status.FIXED
    else:
        status = Status.REJECTED
    source_path = Path(f.file)
    try:
        location = source_path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except (OSError, ValueError):
        location = str(source_path)
    return SecurityEvent(
        layer=Layer.CODE, status=status, severity=f.severity.value,
        title=f"{f.cwe}: {f.title}",
        detail=(issue.verification.patch_rationale
                if issue.verification else "no patch"),
        evidence=issue.exploit_evidence,
        ref=f"{location}:{f.line}",
    )


class EventStore:
    """A single stream both layers write to."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    def add(self, event: SecurityEvent) -> SecurityEvent:
        self.events.append(event)
        return event

    def by_layer(self, layer: Layer) -> list[SecurityEvent]:
        return [e for e in self.events if e.layer is layer]

    def counts(self) -> dict[str, int]:
        return {
            "runtime_blocked": sum(1 for e in self.events
                                   if e.layer is Layer.RUNTIME and e.status is Status.BLOCKED),
            "code_fixed": sum(1 for e in self.events
                              if e.layer is Layer.CODE and e.status is Status.FIXED),
            "total": len(self.events),
        }
