"""SecureAI — one platform, two layers.

Guard the agent while it runs (AgentShield, runtime) AND harden the code it runs
on (PatchProof, build-time). This package is the integration layer: a shared
event model, a bridge that connects runtime detections to code remediation, and
a unified dashboard.

Monorepo path wiring: AgentShield lives at the repo root; PatchProof lives under
`patchproof/`. We add that subdirectory to sys.path so `import patchproof` and
`import vulnbank` work alongside `import agentshield`.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PATCHPROOF_DIR = _ROOT / "patchproof"
if _PATCHPROOF_DIR.is_dir() and str(_PATCHPROOF_DIR) not in sys.path:
    sys.path.insert(0, str(_PATCHPROOF_DIR))


def fixture_path() -> Path:
    """Locate VulnBank in a source checkout or an installed wheel."""
    candidates = (
        _ROOT / "patchproof" / "vulnbank" / "app.py",
        _ROOT / "vulnbank" / "app.py",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def default_policy_path() -> Path:
    """Locate the repo policy, then the packaged AgentShield default."""
    candidates = (
        _ROOT / "policies" / "default.yaml",
        _ROOT / "agentshield" / "data" / "default_policy.yaml",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]

__version__ = "0.1.0"
REPO_ROOT = _ROOT
