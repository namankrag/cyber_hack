"""Wire config → detectors → policy → engine + audit, in one place.

Both the HTTP gateway and the demo build their runtime through here, so the
enforcement behaviour is identical no matter how a call arrives.
"""
from __future__ import annotations

from .audit import AuditLog
from .config import Config
from .detection.base import build_detectors
from .models import EnforcementResult, ToolCall
from .policy import PolicyEngine, load_policy


class AgentShield:
    """The assembled runtime: evaluate a ToolCall, log it, return the result."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.from_env()
        self.policy = load_policy(self.config.policy_path)
        self.detectors = build_detectors(self.config)
        self.engine = PolicyEngine(self.policy, self.detectors)
        self.audit = AuditLog(self.config.audit_path)

    def check(self, call: ToolCall) -> EnforcementResult:
        result = self.engine.evaluate(call)
        self.audit.record(result)
        return result
