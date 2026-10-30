"""HTTP tests for the B4 single approvals decision handler.

Covers: GET /v1/approvals (console shape, alias of the pending queue),
POST /v1/approvals/{call_id} (path-addressed decision), POST
/v1/approvals/decide (body-carried alias declared BEFORE the {call_id}
route), and the preserved 404-unknown / 409-decided semantics with the
trace-bound args hash.
"""
import importlib
import os

from fastapi.testclient import TestClient

from agentshield.approval.queue import args_hash


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


def _hold(c, trace_id=None):
    payload = {"tool_name": "send_email",
               "arguments": {"to": "teammate@ourcompany.com",
                             "body": "Notes from today's sync"},
               "source": "user",
               "context": "User: 'email my teammate the sync notes'"}
    if trace_id is not None:
        payload["trace_id"] = trace_id
    r = c.post("/v1/check", json=payload)
    assert r.status_code == 200
    assert r.json()["decision"] == "require_approval"
    return r.json()["call_id"]


def test_get_approvals_is_pending_alias_with_console_shape(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    call_id = _hold(c, trace_id="trace-b4-1")
    body = c.get("/v1/approvals").json()
    assert set(body) >= {"generated_at", "summary", "capabilities",
                         "pending", "recent", "sample", "notes"}
    assert body["summary"]["pending"] == 1
    assert body["capabilities"] == {"decide": True, "single_use": True,
                                    "args_hash_bound": True, "expiry": False}
    assert [p["call_id"] for p in body["pending"]] == [call_id]
    # Legacy projection still agrees.
    pend = c.get("/v1/approvals/pending").json()["pending"]
    assert [p["call_id"] for p in pend] == [call_id]
    # Trace stays bound into the args hash.
    assert body["pending"][0]["args_hash"] == args_hash(
        "send_email",
        {"to": "teammate@ourcompany.com", "body": "Notes from today's sync"},
        {}, "trace-b4-1", None)


def test_decide_by_path_then_alias_conflicts(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    call_id = _hold(c)
    r = c.post(f"/v1/approvals/{call_id}",
               json={"verdict": "approve", "approver": "b4-human"})
    assert r.status_code == 200
    data = r.json()
    assert data["approval_of"] == call_id and data["approval"] == "approve"
    assert data["entry"]["approval"] == "approve"
    assert data["summary"]["pending"] == 0
    assert c.get("/v1/approvals").json()["summary"]["pending"] == 0
    # Spent hold via the body-carried alias -> 409, not a second approval.
    r = c.post("/v1/approvals/decide",
               json={"call_id": call_id, "verdict": "approve"})
    assert r.status_code == 409


def test_decide_alias_first_and_error_codes(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    call_id = _hold(c)
    # "decide" must hit the alias, never the {call_id} route.
    r = c.post("/v1/approvals/decide",
               json={"call_id": call_id, "verdict": "deny"})
    assert r.status_code == 200
    assert r.json()["approval"] == "deny"
    assert r.json()["summary"]["pending"] == 0
    # Unknown holds -> 404 on both spellings.
    assert c.post("/v1/approvals/decide",
                  json={"call_id": "call_nope", "verdict": "approve"}).status_code == 404
    assert c.post("/v1/approvals/call_nope",
                  json={"verdict": "approve"}).status_code == 404
    # Bad verdict -> 400 on both spellings.
    assert c.post("/v1/approvals/decide",
                  json={"call_id": call_id, "verdict": "maybe"}).status_code == 400
    assert c.post(f"/v1/approvals/{call_id}",
                  json={"verdict": "maybe"}).status_code == 400


def test_approvals_endpoints_require_key_when_configured(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, api_key="t")
    assert c.get("/v1/approvals").status_code == 401
    assert c.post("/v1/approvals/call_x",
                  json={"verdict": "approve"}).status_code == 401
