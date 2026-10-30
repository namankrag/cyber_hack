"""Trust-root tests: pinned policy digest enforced, tampering refused."""
import shutil

import pytest

from agentshield.config import Config
from agentshield.engine_factory import AgentShield
from agentshield.policy.integrity import (PolicyTamperedError, digest_of,
                                          verify_policy_digest)


def _cfg(tmp_path, **kw):
    p = tmp_path / "policy.yaml"
    shutil.copy("policies/default.yaml", p)
    return Config(detectors=["heuristic"], policy_path=str(p),
                  audit_path=str(tmp_path / "a.jsonl")), str(p)


def test_matching_pin_loads(tmp_path, monkeypatch):
    cfg, path = _cfg(tmp_path)
    monkeypatch.setenv("AGENTSHIELD_POLICY_SHA256", digest_of(path))
    AgentShield(config=cfg)  # must not raise


def test_tampered_policy_refused(tmp_path, monkeypatch):
    cfg, path = _cfg(tmp_path)
    monkeypatch.setenv("AGENTSHIELD_POLICY_SHA256", digest_of(path))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n  evil_tool:\n    sensitivity: low\n    allow: true\n")
    with pytest.raises(PolicyTamperedError):
        AgentShield(config=cfg)


def test_unset_pin_is_dev_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_POLICY_SHA256", raising=False)
    cfg, path = _cfg(tmp_path)
    assert verify_policy_digest(path) == digest_of(path)
    AgentShield(config=cfg)  # must not raise
