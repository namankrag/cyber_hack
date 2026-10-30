"""Approval CLI tests — list/decide flows end to end."""
import os

from agentshield.approval.cli import main as cli_main
from agentshield.approval.queue import ApprovalQueue
from agentshield.audit.log import AuditLog
from agentshield.config import Config
from agentshield.engine_factory import AgentShield
from agentshield.models import ToolCall, TrustLevel
from agentshield.provenance import trusted_scope


def _seed(tmp_path, monkeypatch):
    audit_path = os.path.join(str(tmp_path), "audit.jsonl")
    monkeypatch.setenv("AGENTSHIELD_AUDIT_PATH", audit_path)
    cfg = Config(detectors=["heuristic"],
                 policy_path="policies/default.yaml",
                 audit_path=audit_path)
    shield = AgentShield(config=cfg)
    with trusted_scope(TrustLevel.USER):
        r = shield.check(ToolCall(tool_name="send_email",
                                  arguments={"to": "boss@corp.com",
                                             "body": "weekly update"},
                                  source=TrustLevel.USER,
                                  context=""))
    assert r.decision.value == "require_approval"
    return r.call.id


def test_cli_list_shows_pending(tmp_path, monkeypatch, capsys):
    call_id = _seed(tmp_path, monkeypatch)
    assert cli_main(["list"]) == 0
    assert call_id in capsys.readouterr().out


def test_cli_approve_clears_pending(tmp_path, monkeypatch, capsys):
    call_id = _seed(tmp_path, monkeypatch)
    assert cli_main(["approve", call_id]) == 0
    assert "approved" in capsys.readouterr().out
    audit = AuditLog(os.path.join(str(tmp_path), "audit.jsonl"))
    assert ApprovalQueue(audit).pending() == []


def test_cli_refuses_unknown_call(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    assert cli_main(["approve", "call_nonexistent"]) == 1
    assert "refused" in capsys.readouterr().out
