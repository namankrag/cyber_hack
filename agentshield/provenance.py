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

Everything defaults to UNTRUSTED (fail-closed). If no secret is configured,
the gateway runs in an explicit, loudly-flagged *insecure dev mode* where
self-asserted source is honored — never silently.

Note (documented in THREAT_MODEL.md): the token here binds to the asserted
source, not yet to a per-call nonce or session, so a leaked token could be
replayed. Binding to a session id / nonce is the production hardening; the
mechanism and default-untrusted posture are what close the reviewer's finding.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import os

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
        self._token = None

    def __enter__(self) -> "trusted_scope":
        self._token = _current_provenance.set(self.source)
        return self

    def __exit__(self, *exc) -> None:
        if self._token is not None:
            _current_provenance.reset(self._token)


def _secret() -> bytes | None:
    s = os.getenv("AGENTSHIELD_HARNESS_SECRET")
    return s.encode() if s else None


def mint_token(source: TrustLevel | str, secret: str | None = None) -> str:
    """Harness-side: mint a provenance token for an asserted source."""
    key = (secret.encode() if secret else _secret())
    if not key:
        raise RuntimeError("AGENTSHIELD_HARNESS_SECRET not set; cannot mint token")
    src = source.value if isinstance(source, TrustLevel) else str(source)
    return hmac.new(key, src.encode(), hashlib.sha256).hexdigest()


def _verify_token(source: str, token: str | None) -> bool:
    key = _secret()
    if not key or not token:
        return False
    expected = hmac.new(key, source.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)


def insecure_dev_mode() -> bool:
    """True when no harness secret is configured (self-asserted source honored)."""
    return _secret() is None


def resolve(
    asserted_source: str | TrustLevel | None = None,
    token: str | None = None,
) -> TrustLevel:
    """Resolve the trust level for a call. Order of authority:

      1. An in-process trusted_scope (most trustworthy; model can't reach it).
      2. A valid HMAC token matching the asserted source.
      3. Insecure dev mode (no secret configured): honor the asserted source,
         but the gateway flags this in /health.
      4. Otherwise: UNTRUSTED (fail-closed).
    """
    scoped = _current_provenance.get()
    if scoped is not None:
        return scoped

    if asserted_source is None:
        return TrustLevel.UNTRUSTED

    src = (asserted_source.value if isinstance(asserted_source, TrustLevel)
           else str(asserted_source))
    try:
        asserted = TrustLevel(src)
    except ValueError:
        return TrustLevel.UNTRUSTED

    # The user level is the baseline; untrusted is never an "elevation".
    if asserted is TrustLevel.UNTRUSTED:
        return TrustLevel.UNTRUSTED

    if _verify_token(src, token):
        return asserted
    if insecure_dev_mode():
        return asserted  # dev convenience, surfaced via /health
    return TrustLevel.UNTRUSTED
