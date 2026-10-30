"""Human approval queue over the append-only audit log.

TOCTOU answer: an approval binds the EXACT arguments hash. `authorized()`
re-runs shield.check() on the current call and additionally requires a
matching approval entry with the identical args hash. Swapped arguments,
fresh DENY verdicts, and double approvals all fail closed. Approvals are
single-use: a successful authorization consumes the approval, so one human
click cannot authorize unlimited repeat executions. Approval entries are
appended as new JSONL lines; history is never mutated.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from ..audit.log import (
    POSTGRES_DSN_ENV,
    REDIS_URL_ENV,
    AuditLog,
    _require_env,
)
from ..engine_factory import AgentShield
from ..models import Decision, ToolCall


def args_hash(tool_name: str, arguments: dict, metadata: dict | None = None,
                trace_id: str | None = None,
                parent_id: str | None = None) -> str:
    # Trace IDs bind the approval to one cross-agent trace: an approval for
    # trace T does not authorize the same arguments replayed under another
    # trace. The keys are omitted (not null) when absent, so pre-trace audit
    # lines hash exactly as before (backward compatible).
    canonical_obj: dict = {"tool": tool_name, "arguments": arguments,
                           "metadata": metadata or {}}
    if trace_id is not None:
        canonical_obj["trace_id"] = trace_id
    if parent_id is not None:
        canonical_obj["parent_id"] = parent_id
    canonical = json.dumps(canonical_obj, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


#: Select the approval persistence: "audit" (default, JSONL-backed, current
#: behavior), "memory" (ephemeral), "postgres", or "redis". Anything else
#: raises (fail closed) instead of downgrading.
APPROVAL_BACKEND_ENV = "AGENTSHIELD_APPROVAL_BACKEND"
#: Redis list key holding approval entries (redis backend only).
REDIS_APPROVAL_KEY_ENV = "AGENTSHIELD_REDIS_APPROVAL_KEY"
_DEFAULT_REDIS_APPROVAL_KEY = "agentshield:approvals"
#: Redis list cap (redis backend only).
REDIS_APPROVAL_MAX_ENV = "AGENTSHIELD_REDIS_APPROVAL_MAX"
_DEFAULT_REDIS_APPROVAL_MAX = 100000


class ApprovalStore(ABC):
    """Persistence for approval-queue entries (plain JSON dicts).

    `append` persists one entry; `read` returns the newest `window` entries
    (newest last). Implementations must fail closed: a backend that cannot
    persist must raise, never silently drop decisions.
    """

    @abstractmethod
    def append(self, entry: dict) -> None:
        """Persist one approval-queue entry (raises on failure)."""

    @abstractmethod
    def read(self, window: int = 500) -> list[dict]:
        """Return the newest `window` entries (newest last)."""


class InMemoryApprovalStore(ApprovalStore):
    """Ephemeral store: tests and single-process demos. No durability."""

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._lock = threading.Lock()

    def append(self, entry: dict) -> None:
        with self._lock:
            self._entries.append(dict(entry))

    def read(self, window: int = 500) -> list[dict]:
        with self._lock:
            return [dict(e) for e in self._entries[-max(0, window):]]


class AuditLogApprovalStore(ApprovalStore):
    """The historical default: entries live in the JSONL audit trail."""

    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit

    def append(self, entry: dict) -> None:
        with self.audit._lock:
            with self.audit.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(dict(entry), default=str) + "\n")

    def read(self, window: int = 500) -> list[dict]:
        return self.audit.tail(window)


class RedisApprovalStore(ApprovalStore):
    """Approval entries over a Redis list. Opt-in, fail-closed.

    `redis` (redis-py) is imported lazily so the gateway has no new hard
    dependency: a missing library, a missing AGENTSHIELD_REDIS_URL, or an
    unreachable server all raise a clear RuntimeError.
    """

    def __init__(self, url: str | None = None,
                 key: str | None = None,
                 max_entries: int | None = None) -> None:
        self._url = url or _require_env(REDIS_URL_ENV, "approvals/redis")
        self._key = (key or os.getenv(REDIS_APPROVAL_KEY_ENV)
                     or _DEFAULT_REDIS_APPROVAL_KEY)
        self._max_entries = (max_entries if max_entries is not None
                             else _redis_approval_max())
        try:
            import redis  # noqa: PLC0415 - lazy so the core has no new dep

            client = redis.Redis.from_url(self._url, socket_timeout=5.0)
        except ImportError:
            raise RuntimeError(
                "AGENTSHIELD_APPROVAL_BACKEND=redis needs the `redis` "
                "package (redis-py is not installed). Install it (`pip "
                "install redis`) or switch backends; refusing to downgrade "
                "silently.") from None
        try:
            client.ping()
        except Exception as exc:
            raise RuntimeError(
                "cannot reach Redis for the approval store "
                f"({REDIS_URL_ENV}): {exc}. Refusing to downgrade "
                "silently.") from exc
        self._client = client

    def append(self, entry: dict) -> None:
        try:
            pipe = self._client.pipeline(transaction=False)
            pipe.rpush(self._key, json.dumps(dict(entry), default=str))
            pipe.ltrim(self._key, -self._max_entries, -1)
            pipe.execute()
        except Exception as exc:
            raise RuntimeError(
                "Redis approval store failed to write (fail closed): "
                f"{exc}") from exc

    def read(self, window: int = 500) -> list[dict]:
        try:
            raw = self._client.lrange(self._key, -max(0, int(window)), -1)
        except Exception as exc:
            raise RuntimeError(
                "Redis approval store failed to read (fail closed): "
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


class PostgresApprovalStore(ApprovalStore):
    """Approval entries over Postgres (JSONB payloads). Opt-in, fail-closed.

    Lazy driver import (`psycopg` v3 preferred, `psycopg2` accepted):
    missing driver, missing AGENTSHIELD_POSTGRES_DSN, or an unreachable
    server all raise a clear RuntimeError.
    """

    def __init__(self, dsn: str | None = None,
                 table: str = "agentshield_approvals") -> None:
        self._dsn = dsn or _require_env(POSTGRES_DSN_ENV, "approvals/postgres")
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
            "AGENTSHIELD_APPROVAL_BACKEND=postgres needs a Postgres driver "
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
                "cannot reach Postgres for the approval store "
                f"({POSTGRES_DSN_ENV}): {exc}. Refusing to downgrade "
                "silently.") from exc
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {self._table} ("  # noqa: S608 - own table name
                    "id BIGSERIAL PRIMARY KEY, call_id TEXT, "
                    "payload JSONB, created_at TIMESTAMPTZ DEFAULT now())")
        except Exception as exc:
            try:
                conn.close()
            except Exception:
                pass
            raise RuntimeError(
                f"Postgres approval store cannot prepare table "
                f"{self._table}: {exc}") from exc
        self._conn = conn

    def _cursor(self) -> Any:
        with self._lock:
            if self._conn is None:
                self._connect()
            return self._conn.cursor()

    def append(self, entry: dict) -> None:
        try:
            cur = self._cursor()
            try:
                cur.execute(
                    f"INSERT INTO {self._table} "  # noqa: S608 - own table name
                    "(call_id, payload) VALUES (%s, CAST(%s AS JSONB))",
                    (entry.get("call_id"),
                     json.dumps(dict(entry), default=str)))
            finally:
                cur.close()
        except Exception as exc:
            with self._lock:
                self._conn = None
            raise RuntimeError(
                "Postgres approval store failed to write (fail closed): "
                f"{exc}") from exc

    def read(self, window: int = 500) -> list[dict]:
        try:
            cur = self._cursor()
            try:
                cur.execute(
                    f"SELECT payload FROM {self._table} "  # noqa: S608 - own table name
                    "ORDER BY id DESC LIMIT %s", (max(0, int(window)),))
                rows = cur.fetchall()
            finally:
                cur.close()
        except Exception as exc:
            with self._lock:
                self._conn = None
            raise RuntimeError(
                "Postgres approval store failed to read (fail closed): "
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


def _redis_approval_max(default: int = _DEFAULT_REDIS_APPROVAL_MAX) -> int:
    try:
        return max(1, int(os.getenv(REDIS_APPROVAL_MAX_ENV, "") or default))
    except ValueError:
        return default


def approval_store_from_env(audit: AuditLog | None = None,
                            audit_path: str = "audit.log.jsonl"
                            ) -> ApprovalStore:
    """Build the configured approval store. Unknown backends raise.

    AGENTSHIELD_APPROVAL_BACKEND=audit (default) -> AuditLogApprovalStore.
    =memory   -> InMemoryApprovalStore (ephemeral).
    =postgres -> PostgresApprovalStore (needs AGENTSHIELD_POSTGRES_DSN + driver).
    =redis    -> RedisApprovalStore (needs AGENTSHIELD_REDIS_URL + redis-py).
    """
    backend = (os.getenv(APPROVAL_BACKEND_ENV, "audit") or "audit").strip().lower()
    if backend == "audit":
        return AuditLogApprovalStore(audit or AuditLog(audit_path))
    if backend == "memory":
        return InMemoryApprovalStore()
    if backend == "postgres":
        return PostgresApprovalStore()
    if backend == "redis":
        return RedisApprovalStore()
    raise RuntimeError(
        f"unknown {APPROVAL_BACKEND_ENV}={backend!r} (expected one of "
        "audit/memory/postgres/redis). Refusing to guess a backend: fix "
        "the env.")


class ApprovalQueue:
    """Pending approvals live in the audit trail, not in a side database."""

    def __init__(self, audit: AuditLog, window: int = 500,
                 store: ApprovalStore | None = None) -> None:
        self.audit = audit
        self.window = window
        # Pluggable persistence (item 5). Default is the historical
        # JSONL-audit behavior, byte for byte: entries are appended as JSONL
        # lines and read back via tail().
        self.store: ApprovalStore = store or AuditLogApprovalStore(audit)

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
        consumed = {e.get("consumed_by") for e in entries
                    if e.get("approval") == "consumed"}
        if entry.get("call_id") in consumed:
            return False
        holds = self._holds_by_id(entries)
        original = holds.get(entry.get("approval_of"))
        if original is None:
            return False
        try:
            expected = args_hash(original.get("tool", ""),
                                 original.get("arguments", {}),
                                 original.get("metadata", {}),
                                 original.get("trace_id"),
                                 original.get("parent_id"))
        except Exception:
            return False
        return entry.get("args_hash") == expected

    def _entries(self) -> list[dict]:
        """Holds + decisions from the audit trail and the approval store.

        Holds are written by shield.check to the audit trail; decisions are
        written by decide() to the store. The default store IS the audit
        trail, so the union is deduplicated by call_id and behaves exactly
        as before; an external (redis/postgres/memory) store additionally
        sees the holds from the audit trail.
        """
        merged: dict[Any, dict] = {}
        extras: list[dict] = []
        for entry in (list(self.audit.tail(self.window))
                      + list(self.store.read(self.window))):
            cid = entry.get("call_id")
            if cid is None:
                extras.append(entry)
            elif cid not in merged:
                merged[cid] = entry
        return list(merged.values()) + extras

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
        """Record approve/deny for a held call. One live decision per call:
        a consumed (single-use spent) approval returns the hold to pending
        so a repeat execution needs a fresh human decision."""
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
            "trace_id": original.get("trace_id"),
            "parent_id": original.get("parent_id"),
            "decision": Decision.REQUIRE_APPROVAL.value,
            "fail_closed": False,
            "reasons": original.get("reasons", []),
            "detections": [],
            "metadata": {"approver": approver},
            "approval_of": call_id,
            "args_hash": args_hash(original.get("tool", ""),
                                   original.get("arguments", {}),
                                   original.get("metadata", {}),
                                   original.get("trace_id"),
                                   original.get("parent_id")),
            "approval": verdict,
        }
        self.store.append(entry)
        return entry

    def authorized(self, shield: AgentShield, call: ToolCall) -> tuple[bool, str]:
        """True only if a fresh check passes AND an identical approval exists."""
        fresh = shield.check(call)
        if fresh.decision is Decision.DENY:
            return False, "fresh check denies: execution refused"
        wanted = args_hash(call.tool_name, call.arguments, call.metadata,
                         call.trace_id, call.parent_id)
        entries = self._entries()
        for e in entries:
            if (e.get("approval_of") and e.get("approval") == "approve"
                    and e.get("args_hash") == wanted
                    and self._approval_valid(e, entries)):
                if fresh.decision is Decision.ALLOW:
                    return True, "fresh check allows"
                self._consume(e)
                return True, "human approval matches exact arguments (single use)"
        return False, "no matching human approval for these exact arguments"

    def _consume(self, approval: dict) -> None:
        """Spend an approval. Append-only: history is never mutated."""
        entry = {
            "ts": _utcnow(),
            "call_id": f"use_{secrets.token_hex(6)}",
            "tool": approval.get("tool"),
            "arguments": approval.get("arguments", {}),
            "trace_id": approval.get("trace_id"),
            "parent_id": approval.get("parent_id"),
            "source": "user",
            "decision": Decision.REQUIRE_APPROVAL.value,
            "fail_closed": False,
            "reasons": [],
            "detections": [],
            "metadata": {},
            "approval": "consumed",
            "consumed_by": approval.get("call_id"),
            "approval_of": approval.get("approval_of"),
        }
        self.store.append(entry)
