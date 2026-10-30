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

Scalability (item 5): `AuditSink` is the persistence interface. The default
is the JSONL file (`AuditLog`); Postgres and Redis backends implement the
same interface behind `AGENTSHIELD_AUDIT_BACKEND` with lazy driver imports
(no new dependencies) and fail closed with a clear error when misconfigured
— never a silent downgrade. The decision engine itself is stateless; see
docs/SCALABILITY.md for the statelessness audit.
"""
from __future__ import annotations

import json
import re
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models import EnforcementResult

_REDACTED = "«redacted»"

#: Select the audit backend: "jsonl" (default), "postgres", or "redis".
#: Anything else raises at startup (fail closed) instead of downgrading.
AUDIT_BACKEND_ENV = "AGENTSHIELD_AUDIT_BACKEND"
#: Postgres connection string, required when the backend is "postgres".
POSTGRES_DSN_ENV = "AGENTSHIELD_POSTGRES_DSN"
#: Redis URL, required when the backend is "redis".
REDIS_URL_ENV = "AGENTSHIELD_REDIS_URL"
#: Redis list key holding audit entries (redis backend only).
REDIS_AUDIT_KEY_ENV = "AGENTSHIELD_REDIS_AUDIT_KEY"
_DEFAULT_REDIS_AUDIT_KEY = "agentshield:audit"
#: Redis list cap (redis backend only): old entries past this are trimmed.
REDIS_MAX_ENTRIES_ENV = "AGENTSHIELD_REDIS_MAX_ENTRIES"
_DEFAULT_REDIS_MAX_ENTRIES = 100000


class AuditSink(ABC):
    """Persistence for enforcement decisions.

    `record` persists one decision; `tail` returns the newest `n` entries as
    plain dicts (newest last). Implementations must fail closed: a backend
    that cannot write must raise, never silently drop or downgrade.
    """

    @abstractmethod
    def record(self, result: EnforcementResult) -> None:
        """Persist one enforcement decision (raises on failure)."""

    @abstractmethod
    def tail(self, n: int = 20) -> list[dict]:
        """Return the newest `n` entries as dicts (newest last)."""


# --- redaction (shared by every sink) ---------------------------------------
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
# Sensitive "key": value pairs embedded in longer free text, e.g.
# 'err {"password": "hunter2"} done'. The whole-blob JSON branch below
# only fires when the entire string parses, so this regex is the net
# for interior objects. Over-redaction errs safe.
_SENSITIVE_PAIR = re.compile(
    r'"(?P<key>[^"]+)"\s*:\s*(?P<val>"(?:[^"\\]|\\.)*"'
    r"|\d+(?:\.\d+)?|true|false|null)")


def _normalize_redact_keys(redact_keys: list[str] | None) -> tuple[set[str], set[str]]:
    explicit = {k.lower() for k in (redact_keys or [])}
    normalized = {re.sub(r"[-_\s]", "", k) for k in explicit}
    return explicit, normalized


def _is_sensitive_key(key: str, redact_keys: set[str],
                      normalized: set[str]) -> bool:
    k = key.lower()
    if k in redact_keys:
        return True
    n = re.sub(r"[-_\s]", "", k)
    if n in normalized:
        return True
    return any(f in n for f in _SENSITIVE_FRAGMENTS)


def _mask_pairs(text: str, redact_keys: set[str],
                normalized: set[str]) -> str:
    def rep(m: re.Match) -> str:
        if _is_sensitive_key(m.group("key"), redact_keys, normalized):
            return f'"{m.group("key")}": "{_REDACTED}"'
        return m.group(0)
    return _SENSITIVE_PAIR.sub(rep, text)


def _redact_value(value: Any, redact_keys: set[str],
                  normalized: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _is_sensitive_key(k, redact_keys, normalized)
                else _redact_value(v, redact_keys, normalized))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(v, redact_keys, normalized) for v in value]
    if isinstance(value, (set, frozenset)):
        # Deterministic order so identical calls audit identically.
        return [_redact_value(v, redact_keys, normalized)
                for v in sorted(value, key=repr)]
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
                    return json.dumps(
                        _redact_value(parsed, redact_keys, normalized),
                        default=str)
        masked = value
        for pat in _TOKEN_SHAPES:
            masked = pat.sub(_REDACTED, masked)
        return _mask_pairs(masked, redact_keys, normalized)
    return value


def _entry_for_result(result: EnforcementResult,
                      redact_keys: set[str], normalized: set[str]) -> dict:
    """The canonical audit entry dict every sink persists."""
    redact = lambda v: _redact_value(v, redact_keys, normalized)  # noqa: E731
    return {
        "ts": result.evaluated_at,
        "call_id": result.call.id,
        "trace_id": result.call.trace_id,
        "parent_id": result.call.parent_id,
        "tool": result.call.tool_name,
        "arguments": redact(result.call.arguments),
        "source": result.call.source.value,
        "decision": result.decision.value,
        "fail_closed": result.fail_closed,
        "reasons": [r.model_dump() for r in result.reasons],
        "detections": [d.model_dump() for d in result.detections],
        "metadata": redact(result.call.metadata),
    }


class AuditLog(AuditSink):
    def __init__(self, path: str | Path = "audit.log.jsonl",
                 redact_keys: list[str] | None = None) -> None:
        self.path = Path(path)
        self.redact_keys, self._normalized_redact = _normalize_redact_keys(
            redact_keys)
        self._lock = threading.Lock()  # safe under the async gateway's threadpool

    # --- redaction (thin wrappers; shared core above) ---------------------
    # Class aliases kept for backward compatibility (review notes reference
    # these names on AuditLog).
    _SENSITIVE_FRAGMENTS = _SENSITIVE_FRAGMENTS
    _TOKEN_SHAPES = _TOKEN_SHAPES
    _SENSITIVE_PAIR = _SENSITIVE_PAIR

    def _sensitive(self, key: str) -> bool:
        return _is_sensitive_key(key, self.redact_keys,
                                 self._normalized_redact)

    def _mask_pairs(self, text: str) -> str:
        return _mask_pairs(text, self.redact_keys, self._normalized_redact)

    def _redact(self, value: Any) -> Any:
        return _redact_value(value, self.redact_keys, self._normalized_redact)

    def record(self, result: EnforcementResult) -> None:
        entry = _entry_for_result(result, self.redact_keys,
                                  self._normalized_redact)
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


# --- optional backends (lazy imports: no new dependencies) -------------------
def _require_env(name: str, backend: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(
            f"AGENTSHIELD_AUDIT_BACKEND={backend} needs {name} set "
            f"(got empty). Refusing to downgrade to another backend: "
            f"set {name} or switch the backend explicitly.")
    return value


class PostgresAuditSink(AuditSink):
    """AuditSink over Postgres (JSONB payloads). Opt-in, fail-closed.

    The driver is imported lazily (`psycopg` v3 preferred, `psycopg2`
    accepted) so the gateway has no new hard dependency: without a driver
    installed, or without AGENTSHIELD_POSTGRES_DSN, or when Postgres is
    unreachable, construction raises a clear RuntimeError instead of
    silently falling back to JSONL.
    """

    def __init__(self, dsn: str | None = None,
                 redact_keys: list[str] | None = None,
                 table: str = "agentshield_audit") -> None:
        self._dsn = dsn or _require_env(POSTGRES_DSN_ENV, "postgres")
        self.redact_keys, self._normalized_redact = _normalize_redact_keys(
            redact_keys)
        self._table = table
        self._lock = threading.Lock()
        self._conn: Any = None
        self._connect()  # fail fast: unreachable DB is a startup error

    def _driver_connect(self) -> Any:
        try:
            import psycopg

            return psycopg.connect(self._dsn, autocommit=True)
        except ImportError:
            pass
        try:
            import psycopg2

            conn = psycopg2.connect(self._dsn)
            conn.autocommit = True
            return conn
        except ImportError:
            pass
        raise RuntimeError(
            "AGENTSHIELD_AUDIT_BACKEND=postgres needs a Postgres driver "
            "(neither `psycopg` nor `psycopg2` is installed). Install one "
            "(`pip install \"psycopg[binary]\"`) or switch backends; "
            "refusing to downgrade silently.")

    def _connect(self) -> None:
        try:
            conn = self._driver_connect()
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                "cannot reach Postgres for the audit sink "
                f"({POSTGRES_DSN_ENV}): {exc}. Refusing to downgrade "
                "silently.") from exc
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {self._table} ("  # noqa: S608 - own table name
                    "id BIGSERIAL PRIMARY KEY, "
                    "ts DOUBLE PRECISION, call_id TEXT, tool TEXT, "
                    "decision TEXT, fail_closed BOOLEAN, payload JSONB, "
                    "created_at TIMESTAMPTZ DEFAULT now())")
        except Exception as exc:
            try:
                conn.close()
            except Exception:
                pass
            raise RuntimeError(
                f"Postgres audit sink cannot prepare table {self._table}: "
                f"{exc}") from exc
        self._conn = conn

    def _cursor(self) -> Any:
        with self._lock:
            if self._conn is None:
                self._connect()
            return self._conn.cursor()

    def record(self, result: EnforcementResult) -> None:
        entry = _entry_for_result(result, self.redact_keys,
                                  self._normalized_redact)
        try:
            cur = self._cursor()
            try:
                cur.execute(
                    f"INSERT INTO {self._table} "  # noqa: S608 - own table name
                    "(ts, call_id, tool, decision, fail_closed, payload) "
                    "VALUES (%s, %s, %s, %s, %s, CAST(%s AS JSONB))",
                    (entry["ts"], entry["call_id"], entry["tool"],
                     entry["decision"], entry["fail_closed"],
                     json.dumps(entry, default=str)))
            finally:
                cur.close()
        except Exception as exc:
            with self._lock:
                self._conn = None  # force reconnect next call
            raise RuntimeError(
                f"Postgres audit sink failed to write (fail closed): "
                f"{exc}") from exc

    def tail(self, n: int = 20) -> list[dict]:
        if n <= 0:
            return []
        try:
            cur = self._cursor()
            try:
                cur.execute(
                    f"SELECT payload FROM {self._table} "  # noqa: S608 - own table name
                    "ORDER BY id DESC LIMIT %s", (int(n),))
                rows = cur.fetchall()
            finally:
                cur.close()
        except Exception as exc:
            with self._lock:
                self._conn = None
            raise RuntimeError(
                f"Postgres audit sink failed to read (fail closed): "
                f"{exc}") from exc
        out = []
        for (payload,) in reversed(rows):
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    continue
            if isinstance(payload, dict):
                out.append(payload)
        return out

    def close(self) -> None:
        with self._lock:
            conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


class RedisAuditSink(AuditSink):
    """AuditSink over a Redis list (newest at the tail). Opt-in, fail-closed.

    `redis` (redis-py) is imported lazily so the gateway has no new hard
    dependency. Missing library, missing AGENTSHIELD_REDIS_URL, or an
    unreachable server all raise a clear RuntimeError — never a silent
    downgrade to JSONL.
    """

    def __init__(self, url: str | None = None,
                 redact_keys: list[str] | None = None,
                 key: str | None = None,
                 max_entries: int | None = None) -> None:
        self._url = url or _require_env(REDIS_URL_ENV, "redis")
        self.redact_keys, self._normalized_redact = _normalize_redact_keys(
            redact_keys)
        self._key = (key or os.getenv(REDIS_AUDIT_KEY_ENV)
                     or _DEFAULT_REDIS_AUDIT_KEY)
        self._max_entries = (max_entries if max_entries is not None
                             else _redis_max_entries())
        try:
            import redis  # noqa: PLC0415 - lazy so the core has no new dep

            client = redis.Redis.from_url(self._url, socket_timeout=5.0)
        except ImportError:
            raise RuntimeError(
                "AGENTSHIELD_AUDIT_BACKEND=redis needs the `redis` package "
                "(redis-py is not installed). Install it (`pip install "
                "redis`) or switch backends; refusing to downgrade "
                "silently.") from None
        try:
            client.ping()
        except Exception as exc:
            raise RuntimeError(
                "cannot reach Redis for the audit sink "
                f"({REDIS_URL_ENV}): {exc}. Refusing to downgrade "
                "silently.") from exc
        self._client = client

    def record(self, result: EnforcementResult) -> None:
        entry = _entry_for_result(result, self.redact_keys,
                                  self._normalized_redact)
        try:
            pipe = self._client.pipeline(transaction=False)
            pipe.rpush(self._key, json.dumps(entry, default=str))
            pipe.ltrim(self._key, -self._max_entries, -1)
            pipe.execute()
        except Exception as exc:
            raise RuntimeError(
                f"Redis audit sink failed to write (fail closed): "
                f"{exc}") from exc

    def tail(self, n: int = 20) -> list[dict]:
        if n <= 0:
            return []
        try:
            raw = self._client.lrange(self._key, -int(n), -1)
        except Exception as exc:
            raise RuntimeError(
                f"Redis audit sink failed to read (fail closed): "
                f"{exc}") from exc
        out = []
        for item in raw or []:
            if isinstance(item, bytes):
                item = item.decode("utf-8", errors="replace")
            try:
                entry = json.loads(item)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(entry, dict):
                out.append(entry)
        return out


def _redis_max_entries(default: int = _DEFAULT_REDIS_MAX_ENTRIES) -> int:
    try:
        return max(1, int(os.getenv(REDIS_MAX_ENTRIES_ENV, "") or default))
    except ValueError:
        return default


def audit_sink_from_env(path: str | Path = "audit.log.jsonl",
                        redact_keys: list[str] | None = None) -> AuditSink:
    """Build the configured audit sink. Unknown backends raise (fail closed).

    AGENTSHIELD_AUDIT_BACKEND=jsonl (default) -> AuditLog at `path`.
    =postgres -> PostgresAuditSink (needs AGENTSHIELD_POSTGRES_DSN + driver).
    =redis    -> RedisAuditSink (needs AGENTSHIELD_REDIS_URL + redis-py).
    """
    backend = (os.getenv(AUDIT_BACKEND_ENV, "jsonl") or "jsonl").strip().lower()
    if backend == "jsonl":
        return AuditLog(path, redact_keys=redact_keys)
    if backend == "postgres":
        return PostgresAuditSink(redact_keys=redact_keys)
    if backend == "redis":
        return RedisAuditSink(redact_keys=redact_keys)
    raise RuntimeError(
        f"unknown {AUDIT_BACKEND_ENV}={backend!r} (expected one of "
        "jsonl/postgres/redis). Refusing to guess a backend: fix the env.")
