"""Trust root for policy: optional pinned SHA-256 digest.

Set AGENTSHIELD_POLICY_SHA256 to the digest of the reviewed policy file
(`sha256sum policies/default.yaml`). At startup AgentShield verifies the exact
file it is about to enforce; a mismatch raises PolicyTamperedError instead of
enforcing unknown rules — fail-closed at the trust root. Unset means dev mode
(no pin), mirroring the harness-secret dev-mode pattern.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class PolicyTamperedError(RuntimeError):
    """Raised when the policy file does not match its pinned digest."""


def digest_of(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_policy_bytes(data: bytes, expected: str | None = None,
                          *, source: str = "<policy>") -> str:
    """Verify already-read bytes against the pinned digest (single-read path).

    Takes the bytes so callers read the file ONCE and verify+parse the same
    bytes — a file swapped between a load-read and a digest-read can
    otherwise enforce unreviewed rules (or fail a reviewed file).
    """
    if expected is None:
        expected = os.getenv("AGENTSHIELD_POLICY_SHA256")
    actual = hashlib.sha256(data).hexdigest()
    if expected and actual != expected.strip().lower():
        raise PolicyTamperedError(
            f"policy digest mismatch for {source}: "
            "refusing to enforce unreviewed rules")
    return actual


def verify_policy_digest(path: str | Path,
                         expected: str | None = None) -> str:
    """Return the file digest; raise PolicyTamperedError on pinned mismatch."""
    return verify_policy_bytes(Path(path).read_bytes(), expected,
                               source=str(path))
