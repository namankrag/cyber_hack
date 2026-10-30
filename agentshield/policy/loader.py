"""Load and validate a policy from YAML."""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import Policy


def load_policy_text(text: str, source: str = "<policy>") -> Policy:
    """Parse and validate policy YAML from already-read text.

    Single-read path: the caller reads the file once, verifies the digest
    of those exact bytes, then parses them here — closing the
    read-verify-read TOCTOU.
    """
    data = yaml.safe_load(text) or {}
    # Pydantic validates the whole structure and fills defaults — a malformed
    # policy fails loudly at startup rather than silently at request time.
    policy = Policy.model_validate(data)
    for key in policy.tools:
        if not key.strip():
            raise ValueError(
                f"Policy {source} has a blank tool name; refusing to load.")
    return policy


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    return load_policy_text(path.read_text(), source=str(path))
