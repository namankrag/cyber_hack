"""Dashboard (PS-01 item 1) regression tests — served page + approval endpoints."""
import importlib
import os

from fastapi.testclient import TestClient

from agentshield.approval.queue import args_hash
from agentshield.gateway.dashboard import EXPECTED, SCENARIOS


def _client(tmp_path, monkeypatch, api_key=None):
    for var in ("AGENTSHIELD_API_KEY", "AGENTSHIELD_ADMIN_KEY",
                "AGENTSHIELD_HARNESS_SECRET"):
        monkeypatch.delenv(var, raising=False)
    if api_key is not None:
        monkeypatch.setenv("AGENTSHIELD_API_KEY", api_key)
    monkeypatch.setenv("AGENTSHIELD_AUDIT_PATH",
                       os.path.join(str(tmp_path), "audit.jsonl"))
    import agentshield.gateway.app as appmod
    importlib.reload(appmod)
    return TestClient(appmod.app)


def _hold_via_http(c):
    # A genuine user-requested email is high-impact -> REQUIRE_APPROVAL hold.
    r = c.post("/v1/check",
               json={"tool_name": "send_email",
                     "arguments": {"to": "teammate@ourcompany.com",
                                   "body": "Notes from today's sync"},
                     "source": "user",
                     "context": "User: 'email my teammate the sync notes'"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "require_approval"
    return body["call_id"]


def test_dashboard_served_at_root_self_contained(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    html = r.text
    for marker in ("Live decision feed", "Enforcement switch",
                   "Approval queue", "Run scenario",
                   "/v1/evidence", "/v1/approvals/pending",
                   "/v1/approvals/decide", "/v1/admin/enforce"):
        assert marker in html
    # No build step, no CDN: no absolute-URL scripts/styles; page polls
    # same-origin relative paths so the demo works offline.
    assert "<script src" not in html and 'href="http' not in html
    assert 'src="http' not in html
    assert "fetch(\"/v1/" in html
    # The exact scenario payloads the buttons fire are embedded.
    for name, payload in SCENARIOS.items():
        assert payload["tool_name"] in html, name
    # Auto-refresh every ~2s, client-side cap ~100 rows.
    assert "2000" in html and "100" in html
    # No secret is baked into the page: keys live in input fields (memory).
    assert 'type="password"' in html
    # Even with keys configured server-side, their *values* never appear in
    # the served page (naming the env var in help text is fine).
    c2 = _client(tmp_path, monkeypatch, api_key="sekret-test-value-xyz")
    assert "sekret-test-value-xyz" not in c2.get("/").text


def test_dashboard_open_without_key_when_configured(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, api_key="t")
    assert c.get("/").status_code == 200  # static asset, no sensitive data
    assert c.get("/v1/evidence").status_code == 401  # data stays gated
    assert c.get("/v1/evidence", headers={"X-API-Key": "t"}).status_code == 200


def test_scenario_payloads_give_expected_verdicts(tmp_path, monkeypatch):
    # The 4 buttons fire through the real enforcement path (/v1/check).
    c = _client(tmp_path, monkeypatch)
    assert set(SCENARIOS) == {"legit", "injected", "sensitive", "beyond"}
    for name, payload in SCENARIOS.items():
        r = c.post("/v1/check", json=payload)
        assert r.status_code == 200, name
        body = r.json()
        assert body["decision"] == EXPECTED[name], (name, body)
        assert body["reasons"], name  # every verdict carries ordered reasons


def test_injected_scenario_carries_detector_quote(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.post("/v1/check", json=SCENARIOS["injected"])
    call_id = r.json()["call_id"]
    entries = c.get("/v1/evidence?limit=100").json()["entries"]
    match = [e for e in entries if e["call_id"] == call_id]
    assert len(match) == 1
    signals = [s for d in match[0]["detections"] if d["is_threat"]
               for s in d["signals"]]
    assert signals, "feed must show the matched detector quote"


def test_approvals_pending_and_decide_flow(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    call_id = _hold_via_http(c)
    pend = c.get("/v1/approvals/pending").json()["pending"]
    assert [p["call_id"] for p in pend] == [call_id]
    entry = pend[0]
    assert entry["tool"] == "send_email"
    assert entry["decision"] == "require_approval"
    assert entry["reasons"] and entry["reasons"][0]["rule"]
    assert entry["args_hash"] == args_hash(
        "send_email",
        {"to": "teammate@ourcompany.com", "body": "Notes from today's sync"},
        {})
    # Decision consumes the hold: single-use, then gone from pending.
    r = c.post("/v1/approvals/decide",
               json={"call_id": call_id, "verdict": "approve"})
    assert r.status_code == 200
    data = r.json()
    assert data["approval_of"] == call_id and data["approval"] == "approve"
    assert data["entry"]["approval"] == "approve"
    assert data["summary"]["pending"] == 0
    assert c.get("/v1/approvals/pending").json()["pending"] == []
    # A repeat decision on the spent hold is rejected, not double-applied.
    r = c.post("/v1/approvals/decide",
               json={"call_id": call_id, "verdict": "approve"})
    assert r.status_code == 409


def test_approvals_decide_deny_and_error_codes(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    call_id = _hold_via_http(c)
    r = c.post("/v1/approvals/decide",
               json={"call_id": call_id, "verdict": "deny"})
    assert r.status_code == 200
    assert r.json()["approval"] == "deny"
    assert c.get("/v1/approvals/pending").json()["pending"] == []
    assert c.post("/v1/approvals/decide",
                  json={"call_id": "call_doesnotexist",
                        "verdict": "approve"}).status_code == 404
    assert c.post("/v1/approvals/decide",
                  json={"call_id": call_id,
                        "verdict": "maybe"}).status_code == 400


def test_approvals_require_key_when_configured(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, api_key="t")
    assert c.get("/v1/approvals/pending").status_code == 401
    assert c.post("/v1/approvals/decide",
                  json={"call_id": "x", "verdict": "approve"}).status_code == 401
    key = {"X-API-Key": "t"}
    assert c.get("/v1/approvals/pending", headers=key).status_code == 200


def test_beyond_scenario_hold_appears_in_pending(tmp_path, monkeypatch):
    # Panel 4 -> panel 3 wiring: the beyond-permission scenario must show up
    # in the approval queue for a human decision.
    c = _client(tmp_path, monkeypatch)
    r = c.post("/v1/check", json=SCENARIOS["beyond"])
    assert r.json()["decision"] == "require_approval"
    pend = c.get("/v1/approvals/pending").json()["pending"]
    assert [p["call_id"] for p in pend] == [r.json()["call_id"]]
