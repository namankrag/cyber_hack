"""Policy schema.

A policy is intentionally declarative and data-only so that, as you scale,
it can be authored by security reviewers (not just engineers), version
controlled, and — later — swapped for an Open Policy Agent (OPA) backend
without touching the engine's call sites. The Pydantic models here are the
contract the YAML must satisfy.
"""
from __future__ import annotations

import unicodedata
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..models import Decision

# Forbid unknown keys everywhere so a typo'd policy fails loudly at startup
# instead of silently doing nothing (e.g. "requires_approval: true" misspelled).
_STRICT = ConfigDict(extra="forbid")


class ToolPolicy(BaseModel):
    """Rules for one named tool."""

    model_config = _STRICT

    # Literal, not free string: an unrecognized sensitivity is now a startup
    # error, not silently treated as low.
    sensitivity: Literal["low", "high"] = "low"
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

    model_config = _STRICT

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


def _norm_tool_key(name: str) -> str:
    """Normalize a tool name for policy lookup.

    Case/whitespace variants previously missed the policy entry and fell
    through to the unknown-tool default (a DENY downgraded to HOLD).
    Invisible format characters (zero-width spaces) are stripped too, and
    stored policy keys are normalized the same way, so neither a padded /
    cased / zero-width caller string nor a cap-key policy entry can dodge
    the intended rule.
    """
    nfkc = unicodedata.normalize("NFKC", name)
    stripped = "".join(c for c in nfkc if unicodedata.category(c) != "Cf")
    return stripped.strip().lower()


class Policy(BaseModel):
    model_config = _STRICT

    version: int = Field(1, ge=1)     # must be a positive, known schema version
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)

    def for_tool(self, name: str) -> ToolPolicy | None:
        if not isinstance(name, str):
            return None
        key = _norm_tool_key(name)
        if not key:
            return None
        for stored, policy in self.tools.items():
            if _norm_tool_key(stored) == key:
                return policy
        return None
