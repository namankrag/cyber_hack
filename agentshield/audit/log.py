"""Append-only, structured audit log.

Every enforcement decision is written as one JSON line. JSONL is append-only,
trivially greppable in a demo, and streams into Postgres / Elastic / S3 when
you scale — no schema migration to change what you capture.

Security notes (from review):
  * Records can contain sensitive tool arguments, so values under configured
    sensitive keys are redacted before they are written. Redaction is a
    best-effort control, not a guarantee — treat the audit file as sensitive,
    restrict its permissions, and set retention/rotation in production.
  * `tail()` reads the file from the end rather than parsing the whole thing,
    so it stays fast as the log grows.
"""
from __future__ import annotations

import json
import re
import os
import threading
from pathlib import Path
from typing import Any

from ..models import EnforcementResult

_REDACTED = "«redacted»"


class AuditLog:
    def __init__(self, path: str | Path = "audit.log.jsonl",
                 redact_keys: list[str] | None = None) -> None:
        self.path = Path(path)
        self.redact_keys = {k.lower() for k in (redact_keys or [])}
        self._normalized_redact = {
            re.sub(r"[-_\s]", "", k) for k in self.redact_keys}
        self._lock = threading.Lock()  # safe under the async gateway's threadpool

    # --- redaction ---------------------------------------------------------
    # Substring fragments that always mark a key as sensitive, even inside
    # compound names (api_secret, password_hash, access_token, ...).
    _SENSITIVE_FRAGMENTS = ("secret", "password", "passwd", "credential",
                            "token", "apikey", "privatekey",
                            "ssn", "cvv", "card", "auth")
    # "card" also matches "discard", "auth" matches "author": accepted —
    # for an audit trail, over-redacting an odd key errs safe, while
    # under-redacting user_auth/card_number leaks. ("pin" is deliberately
    # absent: it matches "mapping"/"opinion" and would nuke benign text.)

    # High-confidence secret shapes in free text: provider-issued tokens have
    # fixed prefixes, so masking them has ~zero false-positive risk even
    # under a benign key.
    _TOKEN_SHAPES = (
        re.compile(r"sk-[A-Za-z0-9]{16,}"),
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    )

    def _sensitive(self, key: str) -> bool:
        k = key.lower()
        if k in self.redact_keys:
            return True
        n = re.sub(r"[-_\s]", "", k)
        if n in self._normalized_redact:
            return True
        return any(f in n for f in self._SENSITIVE_FRAGMENTS)
    # Sensitive "key": value pairs embedded in longer free text, e.g.
    # 'err {"password": "hunter2"} done'. The whole-blob JSON branch below
    # only fires when the entire string parses, so this regex is the net
    # for interior objects. Over-redaction errs safe.
    _SENSITIVE_PAIR = re.compile(
        r'"(?P<key>[^"]+)"\s*:\s*(?P<val>"(?:[^"\\]|\\.)*"'
        r"|\d+(?:\.\d+)?|true|false|null)")

    def _mask_pairs(self, text: str) -> str:
        def rep(m: re.Match) -> str:
            if self._sensitive(m.group("key")):
                return f'"{m.group("key")}": "{_REDACTED}"'
            return m.group(0)
        return self._SENSITIVE_PAIR.sub(rep, text)

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: (_REDACTED if self._sensitive(k) else self._redact(v))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self._redact(v) for v in value]
        if isinstance(value, (set, frozenset)):
            # Deterministic order so identical calls audit identically.
            return [self._redact(v) for v in sorted(value, key=repr)]
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                return _REDACTED
        if isinstance(value, str):
            # Whole-string JSON blobs: parse, redact, re-dump.
            s = value.strip()
            if len(s) >= 2 and s[0] in "{[":
                try:
                    parsed = json.loads(s)
                except Exception:
                    pass
                else:
                    if isinstance(parsed, (dict, list)):
                        return json.dumps(self._redact(parsed), default=str)
            masked = value
            for pat in self._TOKEN_SHAPES:
                masked = pat.sub(_REDACTED, masked)
            return self._mask_pairs(masked)
        return value

    def record(self, result: EnforcementResult) -> None:
        entry = {
            "ts": result.evaluated_at,
            "call_id": result.call.id,
            "trace_id": result.call.trace_id,
            "parent_id": result.call.parent_id,
            "tool": result.call.tool_name,
            "arguments": self._redact(result.call.arguments),
            "source": result.call.source.value,
            "decision": result.decision.value,
            "fail_closed": result.fail_closed,
            "reasons": [r.model_dump() for r in result.reasons],
            "detections": [d.model_dump() for d in result.detections],
            "metadata": self._redact(result.call.metadata),
        }
        line = json.dumps(entry, default=str)
        with self._lock:
            # Audit-write failure must not take the gateway down silently, but
            # it also must not be swallowed — surface it to the caller/logs.
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def tail(self, n: int = 20) -> list[dict]:
        """Return the last `n` entries, reading from the end of the file."""
        if n <= 0 or not self.path.exists():
            return []
        lines = _read_last_lines(self.path, n)
        out = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


def _read_last_lines(path: Path, n: int, block: int = 8192) -> list[str]:
    """Read the last `n` lines without loading the whole file into memory."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        buffer = b""
        newlines = 0
        pos = end
        while pos > 0 and newlines <= n:
            read = min(block, pos)
            pos -= read
            fh.seek(pos)
            chunk = fh.read(read)
            buffer = chunk + buffer
            newlines = buffer.count(b"\n")
        text = buffer.decode("utf-8", errors="replace")
    return text.splitlines()[-n:]
