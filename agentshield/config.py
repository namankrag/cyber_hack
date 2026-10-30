"""Runtime configuration, read from environment (with .env support).

Validation is strict and happens at startup: an empty detector list, an
out-of-range threshold, or an unknown detector name raises immediately rather
than silently degrading enforcement.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_VALID_DETECTORS = {"heuristic", "llm"}
_PKG_DIR = Path(__file__).resolve().parent


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


def _resolve_policy_path(raw: str) -> str:
    """Find the policy file. Order: explicit/cwd path, then packaged default.

    Fixes the "relative to the process working directory" fragility: an
    installed wheel still finds its bundled default policy.
    """
    p = Path(raw)
    if p.exists():
        return str(p)
    packaged = _PKG_DIR / "data" / "default_policy.yaml"
    if packaged.exists():
        return str(packaged)
    # Let the loader raise a clear FileNotFoundError on the requested path.
    return raw


@dataclass
class Config:
    detectors: list[str] = field(default_factory=lambda: ["heuristic"])
    llm_provider: str = "gemini"
    injection_threshold: float = 0.5
    policy_path: str = "policies/default.yaml"
    audit_path: str = "audit.log.jsonl"

    # Security / operational
    api_key: str | None = None            # if set, required to call the HTTP gateway
    redact_keys: list[str] = field(default_factory=lambda: [
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "api_secret", "password_hash", "api-key", "api-secret",
        "access_token", "client_secret", "refresh_token", "private_key",
        "session_key", "id_token",
        "authorization", "auth", "credential", "credentials", "ssn",
        "card", "cvv", "pin",
    ])
    llm_timeout_s: float = 8.0

    def __post_init__(self) -> None:
        if not self.detectors:
            raise ValueError(
                "No detectors configured (AGENTSHIELD_DETECTORS is empty). "
                "Refusing to start: a gateway with no detector would silently "
                "under-enforce."
            )
        unknown = sorted(set(self.detectors) - _VALID_DETECTORS)
        if unknown:
            raise ValueError(
                f"Unknown detector(s) {unknown}; valid: {sorted(_VALID_DETECTORS)}"
            )
        if not 0.0 <= self.injection_threshold <= 1.0:
            raise ValueError(
                f"injection_threshold must be in [0.0, 1.0], got "
                f"{self.injection_threshold}"
            )

    @classmethod
    def from_env(cls) -> "Config":
        _load_dotenv()
        detectors = [
            d.strip().lower()
            for d in os.getenv("AGENTSHIELD_DETECTORS", "heuristic").split(",")
            if d.strip()
        ]
        redact_env = os.getenv("AGENTSHIELD_REDACT_KEYS")
        kwargs = dict(
            detectors=detectors,
            llm_provider=os.getenv("AGENTSHIELD_LLM_PROVIDER", "gemini"),
            injection_threshold=float(os.getenv("AGENTSHIELD_INJECTION_THRESHOLD", "0.5")),
            policy_path=_resolve_policy_path(
                os.getenv("AGENTSHIELD_POLICY_PATH", "policies/default.yaml")),
            audit_path=os.getenv("AGENTSHIELD_AUDIT_PATH", "audit.log.jsonl"),
            api_key=os.getenv("AGENTSHIELD_API_KEY") or None,
            llm_timeout_s=float(os.getenv("AGENTSHIELD_LLM_TIMEOUT_S", "8.0")),
        )
        if redact_env is not None:
            kwargs["redact_keys"] = [k.strip().lower() for k in redact_env.split(",") if k.strip()]
        return cls(**kwargs)
