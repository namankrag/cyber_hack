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


def verify_policy_digest(path: str | Path,
                         expected: str | None = None) -> str:
    """Return the file digest; raise PolicyTamperedError on pinned mismatch."""
    if expected is None:
        expected = os.getenv("AGENTSHIELD_POLICY_SHA256")
    actual = digest_of(path)
    if expected and actual != expected.strip().lower():
        raise PolicyTamperedError(
            f"policy digest mismatch for {path}: "
            "refusing to enforce unreviewed rules")
    return actual
