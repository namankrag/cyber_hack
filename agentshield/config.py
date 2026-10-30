"""Runtime configuration, read from environment (with .env support)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    """Minimal .env loader (no extra dependency). Does not override real env."""
    env_path = Path(".env")
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass
class Config:
    detectors: list[str] = field(default_factory=lambda: ["heuristic"])
    llm_provider: str = "gemini"
    injection_threshold: float = 0.5
    policy_path: str = "policies/default.yaml"
    audit_path: str = "audit.log.jsonl"

    @classmethod
    def from_env(cls) -> "Config":
        _load_dotenv()
        detectors = [
            d.strip()
            for d in os.getenv("AGENTSHIELD_DETECTORS", "heuristic").split(",")
            if d.strip()
        ]
        return cls(
            detectors=detectors,
            llm_provider=os.getenv("AGENTSHIELD_LLM_PROVIDER", "gemini"),
            injection_threshold=float(os.getenv("AGENTSHIELD_INJECTION_THRESHOLD", "0.5")),
            policy_path=os.getenv("AGENTSHIELD_POLICY_PATH", "policies/default.yaml"),
            audit_path=os.getenv("AGENTSHIELD_AUDIT_PATH", "audit.log.jsonl"),
        )
