"""Wire config → detectors → policy → engine + audit, in one place.

Both the HTTP gateway and the demo build their runtime through here, so the
enforcement behaviour is identical no matter how a call arrives.
"""
from __future__ import annotations

from .audit import AuditLog
from .config import Config
from .detection.base import build_detectors
from .ingestion import IngestedContent, Provenance, ingest
from .models import EnforcementResult, ToolCall
from .policy import PolicyEngine, load_policy


class AgentShield:
    """The assembled runtime: inspect content, evaluate a ToolCall, log it."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.from_env()
        self.policy = load_policy(self.config.policy_path)
        self.detectors = build_detectors(self.config)
        self.engine = PolicyEngine(self.policy, self.detectors)
        self.audit = AuditLog(self.config.audit_path,
                              redact_keys=self.config.redact_keys)

    def ingest(self, raw: str, provenance: Provenance, *,
               content_type: str = "text", session=None) -> IngestedContent:
        """Inspect untrusted content before it enters the agent context.

        Runs the same detectors used at the gate over the content (including its
        hidden/obfuscated parts), records the event on `session` if given, and
        returns a provenance-tagged result. Use `.agent_text()` for what the
        model should see; the gate later reasons about what followed.
        """
        result = ingest(raw, provenance, content_type=content_type,
                        detectors=self.detectors)
        if session is not None:
            session.record_ingest(result)
        return result

    def check(self, call: ToolCall, session=None) -> EnforcementResult:
        result = self.engine.evaluate(call, session=session)
        self.audit.record(result)
        if session is not None:
            session.record_tool(call, result.decision.value)
        return result
