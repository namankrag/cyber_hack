"""Trusted provenance resolution.

THE security fix: provenance (did the *user* ask for this, or did a document?)
must never be taken from the request/tool-call payload, because the agent —
and any injection riding inside the content it processes — can set that
payload. If a caller could just claim `source="user"`, the whole boundary is
theater.

So trust is established *outside* the model, by the harness that wraps the
agent, through one of two channels the model cannot reach:

  1. In-process (the `guard` PEP): a `contextvars` scope the trusted harness
     enters. Code the model does not execute cannot enter it.
  2. Over the network (HTTP / MCP): an HMAC token minted with a server-side
     secret (`AGENTSHIELD_HARNESS_SECRET`) that the harness holds and the
     agent does not. A self-asserted source with no valid token is ignored.

Replay resistance (PS-01 item 3): tokens are single-use and short-lived.
Each token carries a random nonce, an expiry timestamp, and an optional
session binding, all covered by the HMAC:

    v1.<source>.<session>.<nonce>.<exp>.<sig>

`resolve` fails closed on replayed, expired, forged, or session-mismatched
tokens (UNTRUSTED with an inspectable reason via `resolve_detail`). Seen
nonces live in an in-memory `ReplayCache` (pruned periodically, size-bounded);
the cache is a small interface so a Redis backend can replace it for
multi-process deployments — see THREAT_MODEL.md for the residual.

Everything defaults to UNTRUSTED (fail-closed). If no secret is configured,
the gateway runs in an explicit, loudly-flagged *insecure dev mode* where
self-asserted source is honored — never silently.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import os
import secrets
import threading
import time

from .models import TrustLevel

# The trusted harness sets this when it knows a call's real provenance.
# Defaults to None -> UNTRUSTED.
_current_provenance: contextvars.ContextVar[TrustLevel | None] = contextvars.ContextVar(
    "agentshield_provenance", default=None
)


class trusted_scope:
    """Context manager a trusted harness uses to assert provenance in-process.

        with trusted_scope(TrustLevel.USER):
            agent.run(user_request)   # tool calls inside resolve to USER

    The model never runs this code, so it cannot elevate its own calls.
    """

    def __init__(self, source: TrustLevel) -> None:
        self.source = source
        self._tokens: list = []

    def __enter__(self) -> "trusted_scope":
        self._tokens.append(_current_provenance.set(self.source))
        return self

    def __exit__(self, *exc) -> None:
        # Scopes must nest in order (same-object re-entry is supported).
        # A broken protocol (out-of-order or double exit) fails CLOSED to
        # UNTRUSTED instead of raising mid-request or leaking USER.
        if not self._tokens:
            return
        token = self._tokens.pop()
        try:
            if _current_provenance.get() is not self.source:
                raise RuntimeError("trusted_scope exited out of order")
            _current_provenance.reset(token)
        except RuntimeError:
            self._tokens.clear()
            _current_provenance.set(TrustLevel.UNTRUSTED)


def _secret() -> bytes | None:
    s = os.getenv("AGENTSHIELD_HARNESS_SECRET")
    return s.encode() if s else None


# --- replay-resistant token format -------------------------------------------
_TOKEN_VERSION = "v1"
DEFAULT_TOKEN_TTL_S = 300.0
_REPLAY_PRUNE_INTERVAL_S = 60.0
_MAX_REPLAY_ENTRIES = 65536


class ReplayCache:
    """Seen-nonce store. In-memory by default; swap for Redis multi-process.

    A backend only needs these three operations: `seen` must return True
    for a nonce added earlier whose expiry is still in the future, `add`
    records a nonce until `expires_at`, and `clear` drops everything
    (tests / rotation). All checks fail closed: on backend error the
    caller treats the token as replayed.
    """

    def seen(self, nonce: str) -> bool:
        raise NotImplementedError

    def add(self, nonce: str, expires_at: float) -> None:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


class InMemoryReplayCache(ReplayCache):
    """Single-process nonce store with periodic pruning and a size bound."""

    def __init__(self, prune_interval_s: float = _REPLAY_PRUNE_INTERVAL_S,
                 max_entries: int = _MAX_REPLAY_ENTRIES) -> None:
        self._nonces: dict[str, float] = {}
        self._lock = threading.Lock()
        self._prune_interval = prune_interval_s
        self._max_entries = max_entries
        self._last_prune = 0.0

    def _prune_locked(self, now: float) -> None:
        for nonce in [n for n, exp in self._nonces.items() if exp <= now]:
            del self._nonces[nonce]
        if len(self._nonces) > self._max_entries:
            # Evict earliest-expiring first: the closest to useless anyway.
            for nonce, _ in sorted(self._nonces.items(),
                                   key=lambda kv: kv[1])[:len(self._nonces) - self._max_entries]:
                del self._nonces[nonce]
        self._last_prune = now

    def seen(self, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            if now - self._last_prune >= self._prune_interval:
                self._prune_locked(now)
            exp = self._nonces.get(nonce)
            return exp is not None and exp > now

    def add(self, nonce: str, expires_at: float) -> None:
        now = time.time()
        with self._lock:
            if now - self._last_prune >= self._prune_interval:
                self._prune_locked(now)
            self._nonces[nonce] = expires_at
            if len(self._nonces) > self._max_entries:
                self._prune_locked(now)

    def clear(self) -> None:
        with self._lock:
            self._nonces.clear()
            self._last_prune = 0.0


_replay_cache: ReplayCache = InMemoryReplayCache()


def get_replay_cache() -> ReplayCache:
    """Return the active nonce store (a Redis backend can be installed)."""
    return _replay_cache


def set_replay_cache(cache: ReplayCache) -> None:
    """Install a `ReplayCache` backend (e.g. Redis for multi-process)."""
    global _replay_cache
    _replay_cache = cache


def reset_replay_cache() -> None:
    """Restore the default in-memory store, empty (tests / rotation)."""
    global _replay_cache
    _replay_cache = InMemoryReplayCache()


def mint_token(source: TrustLevel | str, secret: str | None = None, *,
               nonce: str | None = None,
               expires_in_s: float = DEFAULT_TOKEN_TTL_S,
               session_id: str | None = None,
               issued_at: float | None = None) -> str:
    """Harness-side: mint a single-use, expiring, session-bindable token.

    `session_id` binds the token to one harness session: `resolve` must be
    given the same session or the token resolves UNTRUSTED. Unbound tokens
    (no session) verify in any session — the pre-item-3 behavior.
    """
    key = (secret.encode() if secret else _secret())
    if not key:
        raise RuntimeError("AGENTSHIELD_HARNESS_SECRET not set; cannot mint token")
    src = source.value if isinstance(source, TrustLevel) else str(source)
    sess = session_id or ""
    for label, value in (("source", src), ("session_id", sess)):
        if "." in value or not value and label == "source":
            raise ValueError(f"token {label} must not contain '.'")
    if not src:
        raise ValueError("token source must not be empty")
    n = nonce or secrets.token_hex(16)
    if "." in n or not n:
        raise ValueError("token nonce must be a non-empty '.'-free string")
    now = issued_at if issued_at is not None else time.time()
    exp = int(now + expires_in_s)
    body = f"{_TOKEN_VERSION}.{src}.{sess}.{n}.{exp}"
    sig = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _parse_token(token: str) -> tuple[str, str, str, int, str] | None:
    """Split a v1 token into (source, session, nonce, exp, sig)."""
    parts = token.split(".")
    if len(parts) != 6 or parts[0] != _TOKEN_VERSION:
        return None
    _, src, sess, nonce, exp_s, sig = parts
    if not src or not nonce or not sig:
        return None
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    return src, sess, nonce, exp, sig


def resolve_detail(
    asserted_source: str | TrustLevel | None = None,
    token: str | None = None,
    session_id: str | None = None,
) -> tuple[TrustLevel, str]:
    """Resolve trust, with an inspectable reason for the verdict.

    Order of authority:
      1. An in-process trusted_scope (most trustworthy; model can't reach it).
      2. A valid single-use, unexpired, session-matching HMAC token.
      3. Insecure dev mode (no secret configured): honor the asserted source,
         but the gateway flags this in /health and /v1/evidence.
      4. Otherwise: UNTRUSTED (fail-closed) with a reason naming the cause:
         missing / legacy / forged token, expiry, replay, session mismatch.
    """
    scoped = _current_provenance.get()
    if scoped is not None:
        return scoped, "in-process trusted scope"

    if asserted_source is None:
        return TrustLevel.UNTRUSTED, "no source asserted"

    src = (asserted_source.value if isinstance(asserted_source, TrustLevel)
           else str(asserted_source))
    try:
        asserted = TrustLevel(src)
    except ValueError:
        return TrustLevel.UNTRUSTED, f"unknown source {src!r}"

    # The user level is the baseline; untrusted is never an "elevation".
    if asserted is TrustLevel.UNTRUSTED:
        return TrustLevel.UNTRUSTED, "untrusted is the baseline"

    def _dev(reason: str) -> tuple[TrustLevel, str]:
        return asserted, f"insecure dev mode ({reason}): honored, flagged in /health"

    if not isinstance(token, str) or not token:
        # A non-string token (list/dict/int smuggled in via JSON args)
        # previously crashed hmac.compare_digest with TypeError inside the
        # enforcement path. It is simply not a valid token: UNTRUSTED.
        if insecure_dev_mode():
            return _dev("no harness secret configured")
        return TrustLevel.UNTRUSTED, "missing provenance token"

    parsed = _parse_token(token)
    if parsed is None:
        # Legacy bare-HMAC tokens and garbage share this fate: UNTRUSTED.
        if insecure_dev_mode():
            return _dev("no harness secret configured")
        return TrustLevel.UNTRUSTED, "unrecognized token format (legacy or forged)"
    tsrc, tsess, nonce, exp, sig = parsed
    if tsrc != src:
        if insecure_dev_mode():
            return _dev("no harness secret configured")
        return TrustLevel.UNTRUSTED, "token source mismatch (forged?)"

    key = _secret()
    if key is None:
        return _dev("no harness secret configured")
    body = ".".join([_TOKEN_VERSION, tsrc, tsess, nonce, str(exp)])
    expected = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return TrustLevel.UNTRUSTED, "invalid token signature (forged?)"

    now = time.time()
    if now > exp:
        return TrustLevel.UNTRUSTED, "provenance token expired"
    if tsess and session_id != tsess:
        return TrustLevel.UNTRUSTED, "token bound to a different session"

    try:
        replayed = _replay_cache.seen(nonce)
    except Exception:
        return TrustLevel.UNTRUSTED, "replay store unavailable (fail closed)"
    if replayed:
        return TrustLevel.UNTRUSTED, "provenance token replay detected (nonce already used)"
    try:
        _replay_cache.add(nonce, float(exp))
    except Exception:
        return TrustLevel.UNTRUSTED, "replay store unavailable (fail closed)"
    return asserted, "valid single-use provenance token"


def insecure_dev_mode() -> bool:
    """True when no harness secret is configured (self-asserted source honored)."""
    return _secret() is None


def resolve(
    asserted_source: str | TrustLevel | None = None,
    token: str | None = None,
    session_id: str | None = None,
) -> TrustLevel:
    """Resolve the trust level for a call (reason available via resolve_detail)."""
    level, _ = resolve_detail(asserted_source, token, session_id=session_id)
    return level
