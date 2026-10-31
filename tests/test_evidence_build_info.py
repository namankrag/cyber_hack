"""B6 tests: the evidence manifest is build-time data, never git or literals.

- No runtime git calls: the evidence module must not import subprocess and
  must expose build_info().
- Historic cards carry the manifest commit/date and never a hardcoded
  test count or historic SHA.
"""
import importlib
import json
import os


def _gateway(tmp_path, monkeypatch):
    for var in ("AGENTSHIELD_API_KEY", "AGENTSHIELD_ADMIN_KEY",
                "AGENTSHIELD_HARNESS_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENTSHIELD_AUDIT_PATH",
                       os.path.join(str(tmp_path), "audit.jsonl"))
    import agentshield.gateway.evidence as ev
    importlib.reload(ev)
    ev._BUILD_INFO_CACHE = None
    return ev


def test_evidence_module_has_no_runtime_git(tmp_path, monkeypatch):
    import subprocess as _sp  # noqa: F401  (we need the name for the check)
    ev = _gateway(tmp_path, monkeypatch)
    assert "subprocess" not in dir(ev)
    assert callable(ev.build_info)


def test_pytest_card_uses_build_info_count(tmp_path, monkeypatch):
    from agentshield.engine_factory import AgentShield
    from agentshield.config import Config

    ev = _gateway(tmp_path, monkeypatch)
    info = ev.build_info()
    shield = AgentShield(Config(detectors=["heuristic"],
                                policy_path="policies/default.yaml",
                                audit_path=os.path.join(str(tmp_path), "a.jsonl")))
    manifest = ev.reports(shield)
    pytest_card = next(r for r in manifest["reports"] if r["id"] == "pytest")
    recorded = (info.get("pytest") or {}).get("passed")
    if isinstance(recorded, int):
        assert pytest_card["value"] == f"{recorded} passed"
        assert "recorded-pass" in pytest_card["status"]
    else:
        assert pytest_card["value"] == "not recorded"
        assert "81" not in pytest_card["detail"]
    assert pytest_card["recorded_commit"] == info.get("commit")
    assert pytest_card["recorded_date"] == info.get("commit_date")
    # No historic SHA literals survive anywhere in the manifest.
    blob = json.dumps(manifest)
    for stale in ("9a28520", "a5a72d2", "a463013", "81 passed", "81 passing"):
        assert stale not in blob


def test_missing_build_info_degrades_honestly(tmp_path, monkeypatch):
    from agentshield.engine_factory import AgentShield
    from agentshield.config import Config

    ev = _gateway(tmp_path, monkeypatch)
    ev._BUILD_INFO_CACHE = {}
    shield = AgentShield(Config(detectors=["heuristic"],
                                policy_path="policies/default.yaml",
                                audit_path=os.path.join(str(tmp_path), "b.jsonl")))
    manifest = ev.reports(shield)
    pytest_card = next(r for r in manifest["reports"] if r["id"] == "pytest")
    assert pytest_card["value"] == "not recorded"
    assert manifest["repo"]["commit"] is None
