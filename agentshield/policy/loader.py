"""Load and validate a policy from YAML."""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import Policy


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    # Pydantic validates the whole structure and fills defaults — a malformed
    # policy fails loudly at startup rather than silently at request time.
    return Policy.model_validate(data)
