"""Policy schema.

A policy is intentionally declarative and data-only so that, as you scale,
it can be authored by security reviewers (not just engineers), version
controlled, and — later — swapped for an Open Policy Agent (OPA) backend
without touching the engine's call sites. The Pydantic models here are the
contract the YAML must satisfy.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from ..models import Decision


class ToolPolicy(BaseModel):
    """Rules for one named tool."""

    sensitivity: str = "low"          # "low" | "high" — high = impactful action
    allow: bool = True                # baseline: is this tool permitted at all?

    # Force a human in the loop for this tool regardless of trust/detection.
    require_approval: bool = False

    # Trust levels permitted to trigger this tool without being escalated.
    # If a call's source is NOT in this list, the tool is escalated per
    # `on_disallowed_source`. Empty list = any source (subject to other rules).
    allow_sources: list[str] = Field(default_factory=list)

    # What to do when the source is not allowed for this tool.
    on_disallowed_source: Decision = Decision.REQUIRE_APPROVAL


class PolicyDefaults(BaseModel):
    """Org-wide fallbacks applied when no tool-specific rule decides."""

    # The heart of fail-closed: how to treat a tool with no policy at all.
    unknown_tool: Decision = Decision.REQUIRE_APPROVAL

    # What a positive detector verdict does, by tool sensitivity.
    on_detector_threat_high_sensitivity: Decision = Decision.DENY
    on_detector_threat_low_sensitivity: Decision = Decision.REQUIRE_APPROVAL

    # What an untrusted source does, by tool sensitivity.
    on_untrusted_high_sensitivity: Decision = Decision.DENY
    on_untrusted_low_sensitivity: Decision = Decision.ALLOW

    # If a detector errors out (e.g. missing API key, timeout), do we treat
    # the uncertainty as safe or escalate? True = escalate = fail closed.
    fail_closed_on_detector_error: bool = True

    # Decision to use when we fail closed due to detector error.
    detector_error_decision: Decision = Decision.REQUIRE_APPROVAL


class Policy(BaseModel):
    version: int = 1
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)

    def for_tool(self, name: str) -> ToolPolicy | None:
        return self.tools.get(name)
