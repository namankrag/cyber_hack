"""Console policy editing: preview is side-effect free, publish is admin-only,
guarded (pin, stale base, validation), versioned, hot-reloaded, reversible."""
import importlib
import os
import re
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
KEY = {"X-API-Key": "t"}
ADMIN = {"X-API-Key": "a"}


def _client(tmp_path, monkeypatch, harness_secret=None, pin=None):
    for var in ("AGENTSHIELD_API_KEY", "AGENTSHIELD_ADMIN_KEY", "AGENTSHIELD_HARNESS_SECRET",
                "AGENTSHIELD_RATE_LIMIT_PER_MIN", "AGENTSHIELD_POLICY_SHA256"):
        monkeypatch.delenv(var, raising=False)
    policy = tmp_path / "policy.yaml"
    shutil.copy(ROOT / "policies" / "default.yaml", policy)
    monkeypatch.setenv("AGENTSHIELD_POLICY_PATH", str(policy))
    monkeypatch.setenv("AGENTSHIELD_API_KEY", "t")
    monkeypatch.setenv("AGENTSHIELD_ADMIN_KEY", "a")
    monkeypatch.setenv("AGENTSHIELD_AUDIT_PATH", os.path.join(str(tmp_path), "audit.jsonl"))
    if harness_secret:
        monkeypatch.setenv("AGENTSHIELD_HARNESS_SECRET", harness_secret)
    if pin:
        monkeypatch.setenv("AGENTSHIELD_POLICY_SHA256", pin)
    import agentshield.gateway.app as appmod
    importlib.reload(appmod)
    return TestClient(appmod.app), policy


def _allow_transfers(text: str) -> str:
    out, n = re.subn(r"(transfer_funds:\s*\n(?:[ \t]+.*\n)*?[ \t]+allow:\s*)false", r"\1true", text)
    assert n == 1
    return out


def test_preview_is_side_effect_free_and_shows_impact(tmp_path, monkeypatch):
    client, policy = _client(tmp_path, monkeypatch)
    original = policy.read_text()
    body = client.post("/v1/policy/preview", headers=KEY, json={"yaml": _allow_transfers(original)}).json()
    assert body["valid"] is True and body["cases"] > 0
    assert any(c["tool"] == "transfer_funds" for c in body["changed"])
    assert "-    allow: false" in body["diff"] and "+    allow: true" in body["diff"]
    assert policy.read_text() == original
    assert client.get("/v1/audit?limit=5", headers=KEY).json()["entries"] == []
    same = client.post("/v1/policy/preview", headers=KEY, json={"yaml": original}).json()
    assert same["identical"] is True and same["changed"] == []


def test_preview_rejects_invalid_drafts(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    for draft in ["tools: [", "tools:\n  send_email:\n    sensitivity: extreme\n", ""]:
        assert client.post("/v1/policy/preview", headers=KEY, json={"yaml": draft}).status_code == 400


def test_publish_needs_the_admin_key(tmp_path, monkeypatch):
    client, policy = _client(tmp_path, monkeypatch)
    text = policy.read_text()
    sha = client.get("/v1/policy/history", headers=KEY).json()["active_sha256"]
    r = client.post("/v1/admin/policy/publish", headers=KEY,
                    json={"yaml": _allow_transfers(text), "base_sha256": sha})
    assert r.status_code in (401, 403)
    assert policy.read_text() == text


def test_publish_hot_reloads_versions_and_rolls_back(tmp_path, monkeypatch):
    client, policy = _client(tmp_path, monkeypatch, harness_secret="s3cret")
    original = policy.read_text()
    sha = client.get("/v1/policy/history", headers=KEY).json()["active_sha256"]
    call = {"tool_name": "search_web", "arguments": {"query": "x"}, "source": "untrusted"}
    assert client.post("/v1/check", headers=KEY, json=call).json()["decision"] == "allow"

    # Disable search_web: the running gateway must enforce it immediately.
    draft = re.sub(r"(search_web:\s*\n[ \t]+sensitivity: low\n[ \t]+allow:\s*)true", r"\1false", original)
    assert draft != original
    published = client.post("/v1/admin/policy/publish", headers=ADMIN,
                            json={"yaml": draft, "base_sha256": sha, "note": "test"}).json()
    assert published["published"] is True and published["from_sha256"] == sha
    assert policy.read_text() == draft
    after = client.post("/v1/check", headers=KEY, json=call).json()
    assert after["decision"] == "deny"
    assert "tool_disabled" in [r["rule"] for r in after["reasons"]]
    # Re-signed manifest: no manifest-mismatch denials on other tools.
    other = client.post("/v1/check", headers=KEY, json={"tool_name": "read_document",
                                                         "arguments": {"doc_id": "a"}, "source": "untrusted"}).json()
    assert other["decision"] == "allow"

    hist = client.get("/v1/policy/history", headers=KEY).json()
    assert hist["changes"][0]["action"] == "publish"
    version = hist["versions"][0]
    rolled = client.post("/v1/admin/policy/rollback", headers=ADMIN,
                         json={"version": version, "base_sha256": hist["active_sha256"]}).json()
    assert rolled["action"] == "rollback"
    assert policy.read_text() == original
    assert client.post("/v1/check", headers=KEY, json=call).json()["decision"] == "allow"


def test_publish_refuses_stale_base_and_pinned_policy(tmp_path, monkeypatch):
    client, policy = _client(tmp_path, monkeypatch)
    text = policy.read_text()
    r = client.post("/v1/admin/policy/publish", headers=ADMIN,
                    json={"yaml": _allow_transfers(text), "base_sha256": "0" * 64})
    assert r.status_code == 409
    import hashlib
    pin = hashlib.sha256(policy.read_bytes()).hexdigest()
    client, policy = _client(tmp_path, monkeypatch, pin=pin)
    r = client.post("/v1/admin/policy/publish", headers=ADMIN,
                    json={"yaml": _allow_transfers(policy.read_text()), "base_sha256": pin})
    assert r.status_code == 409 and "pinned" in r.json()["detail"]
    assert policy.read_text() == text


def test_rollback_rejects_unknown_or_traversal_versions(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    sha = client.get("/v1/policy/history", headers=KEY).json()["active_sha256"]
    for version in ["../../etc/passwd", "nope.yaml", "20261031T000000Z-000000000000.yaml"]:
        r = client.post("/v1/admin/policy/rollback", headers=ADMIN, json={"version": version, "base_sha256": sha})
        assert r.status_code == 400, version
