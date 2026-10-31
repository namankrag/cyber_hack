"""Recent-agent-activity tracking for context-aware enforcement.

Indirect prompt injection is a *sequence*: untrusted content enters, and a
little later the agent attempts an action it was never asked for (exfiltrate
data, read a secret, delete something). A stateless, per-call check can't see
that sequence. SessionContext gives the policy gate a bounded memory of what
just happened, so it can treat "egress right after ingesting untrusted content"
as the exfiltration signature it is.

Deliberately small and bounded (a capped deque, time-windowed) — this is a
signal for the gate, not a full event store (that's the audit log's job).
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .models import TrustLevel


@dataclass
class ActivityEvent:
    kind: str                 # "ingest" | "tool"
    ts: float
    trust: TrustLevel
    risk: float = 0.0
    detail: str = ""


@dataclass
class SessionContext:
    session_id: str = "default"
    window_s: float = 600.0                       # how far back "recent" reaches
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    current_task: str = ""                        # what the user actually asked for
    # Reads and writes may race (e.g. Document Lab checks several tool calls
    # concurrently): a lock keeps appends and snapshot-reads consistent.
    _lock: object = field(default_factory=threading.Lock, repr=False, compare=False)

    def record_ingest(self, ingested) -> None:
        with self._lock:
            self.events.append(ActivityEvent(
                kind="ingest", ts=time.time(), trust=ingested.trust,
                risk=ingested.risk_score,
                detail=f"{ingested.provenance.channel.value}"
                       f"{' (hidden content)' if ingested.has_hidden_content else ''}",
            ))

    def record_tool(self, call, decision: str) -> None:
        with self._lock:
            self.events.append(ActivityEvent(
                kind="tool", ts=time.time(), trust=call.source,
                detail=f"{call.tool_name} -> {decision}",
            ))

    def _recent(self):
        cutoff = time.time() - self.window_s
        with self._lock:
            snapshot = list(self.events)   # copy under lock, then iterate freely
        return [e for e in snapshot if e.ts >= cutoff]

    def recent_untrusted_ingests(self) -> list[ActivityEvent]:
        return [e for e in self._recent()
                if e.kind == "ingest" and e.trust is TrustLevel.UNTRUSTED]

    def has_recent_untrusted_content(self, min_risk: float = 0.0) -> bool:
        return any(e.risk >= min_risk for e in self.recent_untrusted_ingests())

    def summary(self) -> str:
        ing = self.recent_untrusted_ingests()
        if not ing:
            return "no recent untrusted content"
        risky = [e for e in ing if e.risk >= 0.5]
        return (f"{len(ing)} recent untrusted ingest(s)"
                + (f", {len(risky)} flagged" if risky else ""))
