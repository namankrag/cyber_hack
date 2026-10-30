"""Tests for PatchProof: scanning, exploits, the gate, engines, AI, and CLI."""
from pathlib import Path

import pytest

from patchproof import ai_patch, scanner, semgrep_adapter
from patchproof.checks import exploit_for_finding, regression_suite
from patchproof.patches import PATCHES, PATCH_SQLI_BAD
from patchproof.pipeline import run_pipeline
from patchproof.sandbox import client_from_source
from patchproof.scanner import scan, scan_file
from patchproof.verifier import verify_patch, verify_source

TARGET = str(Path(__file__).resolve().parent.parent / "vulnbank" / "app.py")
ALL = {"sqli", "idor", "cmdi", "pathtrav", "xss"}


def _findings():
    # Only the planted vulns: Item-2 decoys scan as `<rule>-decoy` (same
    # CWE) and are pinned separately in test_noise_funnel.py.
    return {f.rule_id: f for f in scan_file(TARGET)
            if not f.rule_id.endswith("-decoy")}


# --- scanner ---------------------------------------------------------------
def test_ast_scanner_finds_all_five():
    assert {f.rule_id for f in scan_file(TARGET)} >= ALL


def test_findings_have_location_and_cwe():
    for f in scan_file(TARGET):
        assert f.line > 0 and f.cwe and f.file.endswith("app.py")


def test_findings_carry_request_shape():
    shapes = _findings()
    assert shapes["sqli"].route == "/login"
    assert shapes["sqli"].method == "POST"
    assert shapes["sqli"].param == "username"
    assert shapes["sqli"].sink == "conn.execute"
    assert shapes["idor"].route == "/accounts/<int:account_id>"
    assert shapes["idor"].method == "GET"
    assert shapes["idor"].param == "account_id"
    assert shapes["cmdi"].route == "/ping" and shapes["cmdi"].param == "host"
    assert shapes["pathtrav"].route == "/files"
    assert shapes["pathtrav"].param == "name"
    assert shapes["xss"].route == "/greet" and shapes["xss"].param == "name"
    for f in shapes.values():
        assert f.route and f.method and f.param and f.sink


def test_scanner_no_false_positive_on_clean_code(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("def f(x):\n    return int(x) + 1\n")
    assert scan_file(clean) == []


def test_pipeline_refuses_to_execute_out_of_scope_files(tmp_path):
    candidate = tmp_path / "outside_scope.py"
    candidate.write_text("raise RuntimeError('must not execute')\n")
    with pytest.raises(ValueError, match="Refusing"):
        run_pipeline(candidate, engine="ast")


# --- exploits + regression on the vulnerable app --------------------------
def test_all_exploits_succeed_on_vulnerable_app():
    src = Path(TARGET).read_text()
    for rule_id, finding in _findings().items():
        assert exploit_for_finding(client_from_source(src),
                                   finding).exploited, f"{rule_id}"


def test_regression_green_on_baseline():
    client = client_from_source(Path(TARGET).read_text())
    assert all(c.passed for c in regression_suite(
        client, list(_findings().values())))


# --- the gate: accept good, reject breaking -------------------------------
def test_curated_patches_accepted_and_block_exploit():
    for rule_id, patch in PATCHES.items():
        v = verify_patch(TARGET, patch)
        assert v.accepted and v.verdict == "FIXED & VERIFIED", rule_id


def test_gate_rejects_breaking_patch():
    v = verify_patch(TARGET, PATCH_SQLI_BAD)
    assert not v.patched_exploited          # it does block the exploit
    assert not v.regression_after_passed    # but breaks login
    assert not v.accepted and v.verdict == "PATCH BREAKS APP"


# --- engines ---------------------------------------------------------------
def test_ast_engine_covers_all():
    assert {f.rule_id for f in scan(TARGET, engine="ast")} >= ALL


@pytest.mark.skipif(not semgrep_adapter.available(), reason="semgrep not installed")
def test_semgrep_engine_runs_and_finds_sqli():
    ids = {f.rule_id for f in scan(TARGET, engine="semgrep")}
    assert "sqli" in ids


def test_both_engine_dedupes():
    fs = scan(TARGET, engine="both")
    keys = [(f.rule_id, f.line) for f in fs]
    assert len(keys) == len(set(keys))      # no duplicate (rule, line)


# --- AI patcher: generate -> gate (mocked model, no key needed) -----------
_GOOD_LOGIN = '''    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        row = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
        if row is None:
            return jsonify(error="invalid credentials"), 401
        return jsonify(token=str(row["id"]), role=row["role"])'''

_BAD_LOGIN = '''    @app.post("/login")
    def login():
        return jsonify(error="invalid credentials"), 401'''


def _sqli_line():
    return next(f for f in scan_file(TARGET) if f.rule_id == "sqli").line


def test_ai_good_patch_is_accepted():
    p = ai_patch.AIPatcher(provider="gemini")
    p.available = lambda: True
    p._complete = lambda prompt: _GOOD_LOGIN
    cand = p.propose(TARGET, "sqli", _sqli_line())
    assert cand is not None
    assert verify_source(TARGET, cand, "sqli").accepted


def test_ai_breaking_patch_is_rejected():
    p = ai_patch.AIPatcher(provider="gemini")
    p.available = lambda: True
    p._complete = lambda prompt: _BAD_LOGIN
    cand = p.propose(TARGET, "sqli", _sqli_line())
    v = verify_source(TARGET, cand, "sqli")
    assert not v.accepted and v.verdict == "PATCH BREAKS APP"


def test_ai_disabled_without_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert ai_patch.AIPatcher(provider="gemini").available() is False


# --- full pipeline ---------------------------------------------------------
def test_pipeline_confirms_and_fixes_all():
    r = run_pipeline(TARGET, engine="ast")
    assert r.confirmed == 5 and r.fixed == 5


def test_target_file_unchanged_after_pipeline():
    before = Path(TARGET).read_text()
    run_pipeline(TARGET, engine="both", use_ai=True)
    assert Path(TARGET).read_text() == before


# --- CLI smoke -------------------------------------------------------------
def test_cli_run_returns_zero_when_all_fixed():
    from patchproof.cli import main
    assert main(["run", TARGET, "--engine", "ast"]) == 0
