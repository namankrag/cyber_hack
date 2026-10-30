"""HTTP tests for the B5 red-team hardening.

The server-side scenario definition is authoritative: caller-supplied
tool_name/arguments/source/context are ignored, scenario_id is required,
runtimes are built once, and the global enforcement switch never moves.
"""
import importlib
import os

from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    for var in ("AGENTSHIELD_API_KEY", "AGENTSHIELD_ADMIN_KEY",
                "AGENTSHIELD_HARNESS_SECRET", "AGENTSHIELD_RATE_LIMIT_PER_MIN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENTSHIELD_API_KEY", "t")
    monkeypatch.setenv("AGENTSHIELD_AUDIT_PATH",
                       os.path.join(str(tmp_path), "audit.jsonl"))
    monkeypatch.setenv("AGENTSHIELD_REDTEAM_AUDIT_PATH",
                       os.path.join(str(tmp_path), "redteam.jsonl"))
    import agentshield.gateway.app as appmod
    importlib.reload(appmod)
    return TestClient(appmod.app)


KEY = {"X-API-Key": "t"}


def test_run_uses_scenario_definition_not_body(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    before = c.get("/v1/enforce", headers=KEY).json()
    r = c.post("/v1/redteam/run", headers=KEY, json={
        "scenario_id": "malicious-vendor",
        # Forged overrides: must all be ignored.
        "tool_name": "search_web",
        "arguments": {"query": "harmless"},
        "source": "user",
        "context": "nothing to see here",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scenario_id"] == "malicious-vendor"
    assert body["request"]["tool_name"] == "send_email"
    assert body["request"]["source"] == "untrusted"
    assert "Attached" in body["request"]["context"] or \
        "database" in body["request"]["context"]
    assert body["request"]["arguments"] != {"query": "harmless"}
    assert body["global_enforcement_unchanged"] is True
    assert c.get("/v1/enforce", headers=KEY).json() == before
    assert body["on"]["decision"] in ("deny", "require_approval")


def test_run_requires_known_scenario(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.post("/v1/redteam/run", headers=KEY, json={}).status_code == 400
    r = c.post("/v1/redteam/run", headers=KEY,
               json={"scenario_id": "no-such-scenario",
                     "tool_name": "search_web"})
    assert r.status_code == 400
    assert "scenario_id" in r.text or "unknown scenario" in r.text


def test_runtimes_are_built_once(tmp_path, monkeypatch):
    _client(tmp_path, monkeypatch)
    import agentshield.gateway.redteam as rt
    import agentshield.gateway.app as appmod
    assert rt._runtime(appmod.shield, True) is rt._runtime(appmod.shield, True)
    assert rt._runtime(appmod.shield, True) is not rt._runtime(appmod.shield, False)


def test_redteam_run_is_rate_limited(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("AGENTSHIELD_RATE_LIMIT_PER_MIN", "3")
    codes = [c.post("/v1/redteam/run", headers=KEY,
                    json={"scenario_id": "benign-document"}).status_code
             for _ in range(5)]
    assert codes[-1] == 429
