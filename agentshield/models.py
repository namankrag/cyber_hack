"""Core domain models shared across every layer of AgentShield.

These are deliberately transport-agnostic: the same ToolCall / Decision
objects flow whether a call arrives over the FastAPI gateway, an MCP proxy,
or a direct in-process SDK call. That keeps the enforcement brain in one
place and lets the plumbing change underneath it.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    """Where the instruction that produced this tool call ultimately came from.

    This is the crux of agent security: a tool call the *user* explicitly
    asked for is very different from one that originated in a document the
    agent happened to read. AgentShield treats provenance as a first-class
    input to every decision.
    """

    USER = "user"              # the human operator typed this intent directly
    SYSTEM = "system"          # the app's own trusted configuration
    TRUSTED_TOOL = "trusted_tool"   # output of a tool we vouch for
    UNTRUSTED = "untrusted"    # web page, email, retrieved doc, 3rd-party tool output

    @property
    def is_untrusted(self) -> bool:
        return self is TrustLevel.UNTRUSTED


class Decision(str, Enum):
    """The three outcomes the PS statement requires — plus they're ordered.

    Severity increases ALLOW < REQUIRE_APPROVAL < DENY, so when several rules
    fire we can keep the most restrictive one.
    """

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return {"allow": 0, "require_approval": 1, "deny": 2}[self.value]


def most_restrictive(a: Decision, b: Decision) -> Decision:
    """Combine two decisions by keeping the stricter one (fail-closed bias)."""
    return a if a.severity >= b.severity else b


class ToolCall(BaseModel):
    """A single action the agent wants to take through a tool."""

    id: str = Field(default_factory=lambda: f"call_{uuid.uuid4().hex[:12]}")
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)

    # Provenance of the instruction that led here.
    source: TrustLevel = TrustLevel.USER

    # The raw content the agent was processing when it decided to make this
    # call (e.g. the document body, the web page text). This is what the
    # detectors scan for injected instructions — the "scene of the crime".
    context: str = ""

    # Free-form metadata: agent id, session id, tenant, etc. Useful for
    # multi-tenant audit trails when you scale.
    metadata: dict[str, Any] = Field(default_factory=dict)

    created_at: float = Field(default_factory=time.time)


class DetectionResult(BaseModel):
    """Output of a single detector run against a tool call's context."""

    detector: str                 # e.g. "heuristic", "llm:gemini"
    score: float = 0.0            # 0.0 (clean) .. 1.0 (certain injection)
    is_threat: bool = False       # score >= configured threshold
    signals: list[str] = Field(default_factory=list)   # human-readable hits
    error: str | None = None      # set if the detector failed to run

    @property
    def failed(self) -> bool:
        return self.error is not None


class PolicyReason(BaseModel):
    """One inspectable justification for the final decision.

    The PS statement demands an *inspectable reason*. Rather than a single
    opaque verdict, we attach the ordered list of rules that fired, each
    naming itself, what it saw, and what it decided. This is what makes the
    audit log auditable and the demo convincing.
    """

    rule: str                     # which rule produced this (e.g. "sensitive_tool")
    decision: Decision
    detail: str                   # plain-English explanation


class EnforcementResult(BaseModel):
    """The complete, logged record of one enforcement evaluation."""

    call: ToolCall
    decision: Decision
    reasons: list[PolicyReason] = Field(default_factory=list)
    detections: list[DetectionResult] = Field(default_factory=list)
    matched_policy: str | None = None     # name of the tool policy, if any
    fail_closed: bool = False             # True if we denied/held due to uncertainty
    evaluated_at: float = Field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def headline(self) -> str:
        """One-line summary for logs and the demo console."""
        verb = {
            Decision.ALLOW: "ALLOWED",
            Decision.REQUIRE_APPROVAL: "HELD FOR APPROVAL",
            Decision.DENY: "DENIED",
        }[self.decision]
        top = self.reasons[-1].detail if self.reasons else "no rule fired"
        return f"{verb}: {self.call.tool_name} — {top}"
