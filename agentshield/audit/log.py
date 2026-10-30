"""Append-only, structured audit log.

Every enforcement decision is written as one JSON line. JSONL is chosen on
purpose: it is append-only (tamper-evident-friendly), trivially greppable in
a demo, and streams straight into Postgres / Elastic / S3 when you scale —
no schema migration needed to change what you capture.

Each record is self-contained: the full tool call, the decision, every reason,
and every detector verdict. That's what lets a security reviewer reconstruct
*exactly* why the gateway did what it did, months later.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from ..models import EnforcementResult


class AuditLog:
    def __init__(self, path: str | Path = "audit.log.jsonl") -> None:
        self.path = Path(path)
        self._lock = threading.Lock()  # safe under the async gateway's threadpool

    def record(self, result: EnforcementResult) -> None:
        entry = {
            "ts": result.evaluated_at,
            "call_id": result.call.id,
            "tool": result.call.tool_name,
            "arguments": result.call.arguments,
            "source": result.call.source.value,
            "decision": result.decision.value,
            "fail_closed": result.fail_closed,
            "reasons": [r.model_dump() for r in result.reasons],
            "detections": [d.model_dump() for d in result.detections],
            "metadata": result.call.metadata,
        }
        line = json.dumps(entry, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def tail(self, n: int = 20) -> list[dict]:
        """Read back the last n entries (for the dashboard / API)."""
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-n:]]
