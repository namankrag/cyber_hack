"""The enforcement engine — AgentShield's decision brain.

Given a ToolCall, it runs the detectors and the policy and produces an
EnforcementResult carrying the final Decision plus the ordered list of
reasons that produced it.

Design principles, each of which maps to the PS statement:

  * Decisions compose by *most restrictive wins* — one DENY beats any number
    of ALLOWs. You can never accidentally widen access by adding a rule.
  * Every branch appends a PolicyReason, so the verdict is always inspectable.
  * Uncertainty escalates (fail-closed): unknown tools and detector errors
    default to approval/deny, never to allow.
  * The engine never trusts the agent's own framing — provenance (TrustLevel)
    is an input it is given, established *outside* the model, below where an
    injection could tamper with it.
"""
from __future__ import annotations

from ..detection.base import Detector
from ..models import (
    Decision,
    DetectionResult,
    EnforcementResult,
    PolicyReason,
    ToolCall,
    TrustLevel,
    most_restrictive,
)
from .models import Policy, ToolPolicy


class PolicyEngine:
    def __init__(self, policy: Policy, detectors: list[Detector]) -> None:
        self.policy = policy
        self.detectors = detectors

    def evaluate(self, call: ToolCall) -> EnforcementResult:
        reasons: list[PolicyReason] = []
        decision = Decision.ALLOW
        fail_closed = False

        tool_policy = self.policy.for_tool(call.tool_name)
        defaults = self.policy.defaults

        # --- Step 0: unknown tool → fail closed ---------------------------
        if tool_policy is None:
            d = defaults.unknown_tool
            reasons.append(PolicyReason(
                rule="unknown_tool",
                decision=d,
                detail=(f"'{call.tool_name}' is not in the policy. "
                        f"Fail-closed default applies."),
            ))
            # An unknown tool is inherently uncertain; still run detectors
            # below so the audit log captures why, but mark fail_closed.
            fail_closed = fail_closed or d is not Decision.ALLOW
            decision = most_restrictive(decision, d)

        # --- Step 1: baseline allow flag ----------------------------------
        if tool_policy is not None and not tool_policy.allow:
            reasons.append(PolicyReason(
                rule="tool_disabled",
                decision=Decision.DENY,
                detail=f"Tool '{call.tool_name}' is disabled by policy.",
            ))
            decision = most_restrictive(decision, Decision.DENY)

        # --- Step 2: run detectors ----------------------------------------
        detections = [d.scan(call) for d in self.detectors]
        threat = _strongest_threat(detections)
        errored = [d for d in detections if d.failed]

        sensitivity = tool_policy.sensitivity if tool_policy else "high"
        # Unknown tools are treated as high sensitivity for detector handling.

        if threat is not None:
            if sensitivity == "high":
                d = defaults.on_detector_threat_high_sensitivity
            else:
                d = defaults.on_detector_threat_low_sensitivity
            reasons.append(PolicyReason(
                rule="injection_detected",
                decision=d,
                detail=(f"{threat.detector} flagged injection "
                        f"(score {threat.score}): "
                        f"{'; '.join(threat.signals) or 'no detail'}. "
                        f"Tool sensitivity={sensitivity}."),
            ))
            decision = most_restrictive(decision, d)

        # --- Step 3: detector errors → fail closed ------------------------
        if errored and defaults.fail_closed_on_detector_error:
            d = defaults.detector_error_decision
            names = ", ".join(e.detector for e in errored)
            reasons.append(PolicyReason(
                rule="detector_error_fail_closed",
                decision=d,
                detail=(f"Detector(s) [{names}] could not run "
                        f"({errored[0].error}). Escalating under fail-closed."),
            ))
            fail_closed = True
            decision = most_restrictive(decision, d)

        # --- Step 4: provenance / trust -----------------------------------
        if call.source.is_untrusted:
            if sensitivity == "high":
                d = defaults.on_untrusted_high_sensitivity
            else:
                d = defaults.on_untrusted_low_sensitivity
            if d is not Decision.ALLOW:
                reasons.append(PolicyReason(
                    rule="untrusted_source",
                    decision=d,
                    detail=(f"Call originated from UNTRUSTED content "
                            f"(e.g. a retrieved document), not the user. "
                            f"Tool sensitivity={sensitivity}."),
                ))
                decision = most_restrictive(decision, d)

        # --- Step 5: per-tool source allow-list ---------------------------
        if tool_policy and tool_policy.allow_sources:
            if call.source.value not in tool_policy.allow_sources:
                d = tool_policy.on_disallowed_source
                reasons.append(PolicyReason(
                    rule="source_not_allowed",
                    decision=d,
                    detail=(f"Source '{call.source.value}' is not in this "
                            f"tool's allow-list {tool_policy.allow_sources}."),
                ))
                decision = most_restrictive(decision, d)

        # --- Step 6: explicit human-in-the-loop requirement ---------------
        if tool_policy and tool_policy.require_approval:
            reasons.append(PolicyReason(
                rule="requires_approval",
                decision=Decision.REQUIRE_APPROVAL,
                detail=(f"'{call.tool_name}' is a high-impact action that "
                        f"always requires human approval."),
            ))
            decision = most_restrictive(decision, Decision.REQUIRE_APPROVAL)

        # --- Step 7: nothing fired → explicit allow -----------------------
        if not reasons:
            reasons.append(PolicyReason(
                rule="default_allow",
                decision=Decision.ALLOW,
                detail="No rule objected; call is within policy.",
            ))

        return EnforcementResult(
            call=call,
            decision=decision,
            reasons=reasons,
            detections=detections,
            matched_policy=call.tool_name if tool_policy else None,
            fail_closed=fail_closed,
        )


def _strongest_threat(detections: list[DetectionResult]) -> DetectionResult | None:
    """Return the highest-scoring detector that crossed its threshold."""
    threats = [d for d in detections if d.is_threat and not d.failed]
    if not threats:
        return None
    return max(threats, key=lambda d: d.score)
