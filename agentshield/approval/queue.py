"""Human approval queue over the append-only audit log.

TOCTOU answer: an approval binds the EXACT arguments hash. `authorized()`
re-runs shield.check() on the current call and additionally requires a
matching approval entry with the identical args hash. Swapped arguments,
fresh DENY verdicts, and double approvals all fail closed. Approval entries
are appended as new JSONL lines; history is never mutated.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone

from ..audit.log import AuditLog
from ..engine_factory import AgentShield
from ..models import Decision, ToolCall


def args_hash(tool_name: str, arguments: dict, metadata: dict | None = None) -> str:
    canonical = json.dumps({"tool": tool_name, "arguments": arguments,
                            "metadata": metadata or {}},
                           sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalQueue:
    """Pending approvals live in the audit trail, not in a side database."""

    def __init__(self, audit: AuditLog, window: int = 500) -> None:
        self.audit = audit
        self.window = window

    def _holds_by_id(self, entries: list[dict]) -> dict:
        return {e.get("call_id"): e for e in entries
                if e.get("decision") == Decision.REQUIRE_APPROVAL.value
                and not e.get("approval_of")}

    def _approval_valid(self, entry: dict, entries: list[dict]) -> bool:
        """An approval counts only if it chains to a real held call.

        Forged JSONL lines (approval_of pointing at a nonexistent call, a
        garbage hash, or a non-decision verdict) are ignored: they neither
        authorize execution nor squat the pending queue.
        """
        if entry.get("approval") not in ("approve", "deny"):
            return False
        holds = self._holds_by_id(entries)
        original = holds.get(entry.get("approval_of"))
        if original is None:
            return False
        try:
            expected = args_hash(original.get("tool", ""),
                                 original.get("arguments", {}),
                                 original.get("metadata", {}))
        except Exception:
            return False
        return entry.get("args_hash") == expected

    def _entries(self) -> list[dict]:
        return self.audit.tail(self.window)

    def pending(self) -> list[dict]:
        entries = self._entries()
        decided = {e.get("approval_of") for e in entries
                   if self._approval_valid(e, entries)}
        out = []
        for e in entries:
            if e.get("decision") != Decision.REQUIRE_APPROVAL.value:
                continue
            if e.get("approval_of"):
                continue
            if e.get("call_id") in decided:
                continue
            out.append(e)
        return out

    def _find_original(self, call_id: str) -> dict:
        for e in self._entries():
            if e.get("call_id") == call_id and not e.get("approval_of"):
                return e
        raise ValueError(f"no such held call: {call_id}")

    def decide(self, call_id: str, verdict: str, approver: str = "human") -> dict:
        """Record approve/deny for a held call. One decision per call."""
        if verdict not in ("approve", "deny"):
            raise ValueError("verdict must be 'approve' or 'deny'")
        original = self._find_original(call_id)
        if original.get("decision") != Decision.REQUIRE_APPROVAL.value:
            raise ValueError(f"call {call_id} is not held for approval")
        entries = self._entries()
        if any(e.get("approval_of") == original.get("call_id")
               and self._approval_valid(e, entries) for e in entries):
            raise ValueError(f"call {call_id} already decided")
        entry = {
            "ts": _utcnow(),
            "call_id": f"appr_{secrets.token_hex(6)}",
            "tool": original.get("tool"),
            "arguments": original.get("arguments"),
            "source": "user",
            "metadata": original.get("metadata", {}),
            "decision": Decision.REQUIRE_APPROVAL.value,
            "fail_closed": False,
            "reasons": original.get("reasons", []),
            "detections": [],
            "metadata": {"approver": approver},
            "approval_of": call_id,
            "args_hash": args_hash(original.get("tool", ""),
                                   original.get("arguments", {}),
                                   original.get("metadata", {})),
            "approval": verdict,
        }
        with self.audit._lock:
            with self.audit.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def authorized(self, shield: AgentShield, call: ToolCall) -> tuple[bool, str]:
        """True only if a fresh check passes AND an identical approval exists."""
        fresh = shield.check(call)
        if fresh.decision is Decision.DENY:
            return False, "fresh check denies: execution refused"
        wanted = args_hash(call.tool_name, call.arguments, call.metadata)
        for e in self._entries():
            if (e.get("approval_of") and e.get("approval") == "approve"
                    and e.get("args_hash") == wanted
                    and self._approval_valid(e, self._entries())):
                if fresh.decision is Decision.ALLOW:
                    return True, "fresh check allows"
                return True, "human approval matches exact arguments"
        return False, "no matching human approval for these exact arguments"
