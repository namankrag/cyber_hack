"""Wire config → detectors → policy → engine + audit, in one place.

Both the HTTP gateway and the demo build their runtime through here, so the
enforcement behaviour is identical no matter how a call arrives.

`enforce` is the demo OFF/ON switch (env AGENTSHIELD_ENFORCE, default on).
When OFF, check() still evaluates and logs, but returns ALLOW with an
explicit `enforcement_disabled` reason naming the would-be verdict — so the
OFF-vs-ON contrast is provable from the audit trail. OFF is an explicit
operator override for demo theater, never a silent bypass.
"""
from __future__ import annotations

import os

from .audit import AuditLog
from .config import Config
from .detection.base import build_detectors
from .models import Decision, EnforcementResult, PolicyReason, ToolCall
from .policy import PolicyEngine, load_policy
from .policy.integrity import verify_policy_digest


class AgentShield:
    """The assembled runtime: evaluate a ToolCall, log it, return the result."""

    def __init__(self, config: Config | None = None,
                 enforce: bool | None = None) -> None:
        self.config = config or Config.from_env()
        self.policy = load_policy(self.config.policy_path)
        verify_policy_digest(self.config.policy_path)
        self.detectors = build_detectors(self.config)
        self.engine = PolicyEngine(self.policy, self.detectors)
        self.audit = AuditLog(self.config.audit_path,
                              redact_keys=self.config.redact_keys)
        if enforce is None:
            enforce = os.getenv("AGENTSHIELD_ENFORCE", "1") != "0"
        self.enforce = enforce

    def check(self, call: ToolCall) -> EnforcementResult:
        result = self.engine.evaluate(call)
        if not self.enforce:
            result = EnforcementResult(
                call=result.call,
                decision=Decision.ALLOW,
                reasons=[PolicyReason(
                    rule="enforcement_disabled",
                    decision=Decision.ALLOW,
                    detail=(f"Enforcement is OFF (demo mode). "
                            f"Would-be verdict: {result.decision.value}."))],
                detections=result.detections,
                matched_policy=result.matched_policy,
                fail_closed=False,
            )
        self.audit.record(result)
        return result
