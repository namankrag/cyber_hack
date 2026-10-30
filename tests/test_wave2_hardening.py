"""Wave-2 residual hardening regression tests (red-loop round 2).

Each test pins one confirmed wave-2 finding: Unicode policy evasion,
non-string provenance tokens, broken trusted_scope protocol, compound-key
redaction gaps, and known secret shapes in free text.
"""
import os

import pytest

from agentshield.audit.log import _REDACTED, AuditLog
from agentshield.config import Config
from agentshield.engine_factory import AgentShield
from agentshield.models import Decision, ToolCall, TrustLevel
from agentshield.policy.models import Policy, ToolPolicy
from agentshield.provenance import resolve, trusted_scope


def _shield(tmp_path):
    cfg = Config(detectors=["heuristic"],
                 policy_path="policies/default.yaml",
                 audit_path=os.path.join(str(tmp_path), "audit.jsonl"))
    return AgentShield(config=cfg)


def test_tool_lookup_ignores_case_space_and_zero_width(tmp_path):
    # transfer_funds is allow:false -> DENY. Pre-fix, any case/space/
    # zero-width variant missed the entry and fell through to HOLD.
    shield = _shield(tmp_path)
    for variant in ("transfer_funds", "Transfer_Funds", "TRANSFER_FUNDS",
                    " transfer_funds ", "transfer_funds\t",
                    "\u200btransfer_funds\u200b"):
        r = shield.check(ToolCall(tool_name=variant, arguments={},
                                 source=TrustLevel.USER, context=""))
        assert r.decision is Decision.DENY, (variant, r.decision)


def test_cap_key_policy_entry_matches_lowercase_query():
    p = Policy(tools={"Transfer_Funds": ToolPolicy(sensitivity="high", allow=False)})
    assert p.for_tool("transfer_funds") is not None
    assert p.for_tool("TRANSFER_FUNDS ") is not None
    assert p.for_tool("unknown_tool_xyz") is None


def test_non_string_provenance_token_resolves_untrusted(monkeypatch):
    # A list/dict/int smuggled as the token crashed hmac.compare_digest
    # with TypeError inside the enforcement path. Now: simply not valid.
    monkeypatch.setenv("AGENTSHIELD_HARNESS_SECRET", "s3cr3t")
    assert resolve("user", ["not", "a", "string"]) is TrustLevel.UNTRUSTED
    assert resolve("user", {"token": 1}) is TrustLevel.UNTRUSTED
    assert resolve("user", 42) is TrustLevel.UNTRUSTED


def test_trusted_scope_nested_same_object_reentry():
    s = trusted_scope(TrustLevel.USER)
    s.__enter__()
    s.__enter__()
    s.__exit__(None, None, None)
    s.__exit__(None, None, None)
    assert resolve() is TrustLevel.UNTRUSTED


def test_trusted_scope_out_of_order_exit_fails_closed():
    a = trusted_scope(TrustLevel.USER)
    b = trusted_scope(TrustLevel.USER)
    a.__enter__()
    b.__enter__()
    a.__exit__(None, None, None)  # out of order: must not raise, must not leak
    b.__exit__(None, None, None)
    assert resolve() is TrustLevel.UNTRUSTED


def test_compound_secret_keys_redacted(tmp_path):
    log = AuditLog(os.path.join(str(tmp_path), "a.jsonl"))
    red = log._redact({"user_auth": "x", "cvv_code": "123", "user_ssn": "9",
                       "card_number": "4", "query": "vendors"})
    for k in ("user_auth", "cvv_code", "user_ssn", "card_number"):
        assert red[k] == _REDACTED, (k, red[k])
    assert red["query"] == "vendors"


def test_known_token_shapes_masked_in_free_text(tmp_path):
    log = AuditLog(os.path.join(str(tmp_path), "b.jsonl"))
    red = log._redact({"note": "leaked sk-abcdefghijklmnopqr and "
                               "ghp_aaaaaaaaaaaaaaaaaaaa and "
                               "AKIAIOSFODNN7EXAMPLE ok"})
    assert "sk-abcdef" not in red["note"]
    assert "ghp_aaaa" not in red["note"]
    assert "AKIAIOSFODNN7EXAMPLE" not in red["note"]
    assert _REDACTED in red["note"]
    benign = log._redact({"note": "mapping the opinion board"})
    assert benign["note"] == "mapping the opinion board"
