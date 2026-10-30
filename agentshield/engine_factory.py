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
from pathlib import Path

from .audit import AuditLog
from .config import Config
from .detection.base import build_detectors
from .models import Decision, EnforcementResult, PolicyReason, ToolCall
from .policy import PolicyEngine
from .policy.integrity import verify_policy_bytes
from .policy.loader import load_policy_text
from .policy.manifest import ToolManifest


class AgentShield:
    @property
    def manifest_enforced(self) -> bool:
        """False in insecure dev mode (no harness secret to sign with)."""
        return self.tool_manifest.enforced
    """The assembled runtime: evaluate a ToolCall, log it, return the result."""

    def __init__(self, config: Config | None = None,
                 enforce: bool | None = None) -> None:
        self.config = config or Config.from_env()
        # Single read, then verify+parse the SAME bytes: a file swapped
        # between a load-read and a digest-read would otherwise let
        # unreviewed rules be enforced (or fail a reviewed file).
        policy_path = Path(self.config.policy_path)
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        raw = policy_path.read_bytes()
        verify_policy_bytes(raw)
        self.policy = load_policy_text(raw.decode("utf-8"),
                                       source=str(policy_path))
        self.detectors = build_detectors(self.config)
        # Signed tool manifest (trust root: the harness secret). With no
        # secret the manifest is unsigned and verification is skipped but
        # flagged via `manifest_enforced` (insecure dev mode philosophy).
        self.tool_manifest = ToolManifest.from_policy(self.policy)
        self.engine = PolicyEngine(self.policy, self.detectors,
                                   manifest=self.tool_manifest)
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
