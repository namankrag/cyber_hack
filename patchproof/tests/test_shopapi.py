"""Tests for the second fixture (ShopAPI, FastAPI style), the shared per-CWE
templates, and the fixtures-manifest execution gate."""
from pathlib import Path

import pytest

from patchproof.checks import (EXPLOIT_TEMPLATES, exploit_for_finding,
                               regression_suite)
from patchproof.manifest import (assert_bundled_fixture_target, load_manifest,
                                 manifest_path, patchproof_dir)
from patchproof.patches import FIXTURE_PATCHES, patch_for
from patchproof.pipeline import run_pipeline
from patchproof.sandbox import client_from_source
from patchproof.scanner import scan_file
from patchproof.verifier import verify_patch

SHOP = str(Path(__file__).resolve().parent.parent / "shopapi" / "app.py")
VULN = str(Path(__file__).resolve().parent.parent / "vulnbank" / "app.py")
SHOP_ALL = {"sqli", "pickle", "secret"}


def _shop_findings():
    # Only the planted vulns: Item-2 decoys scan as `<rule>-decoy` (same
    # CWE) and are pinned separately in test_noise_funnel.py.
    return {f.rule_id: f for f in scan_file(SHOP)
            if not f.rule_id.endswith("-decoy")}


# --- scanner on the second fixture ----------------------------------------
def test_shop_scanner_finds_all_three():
    assert {f.rule_id for f in scan_file(SHOP)} >= SHOP_ALL


def test_shop_findings_carry_request_shape():
    shapes = _shop_findings()
    assert shapes["sqli"].cwe == "CWE-89"
    assert shapes["sqli"].route == "/auth/login"
    assert shapes["sqli"].method == "POST"
    assert shapes["sqli"].param == "username"
    assert shapes["pickle"].cwe == "CWE-502"
    assert shapes["pickle"].route == "/import"
    assert shapes["pickle"].method == "POST"
    assert shapes["pickle"].param == "blob"
    assert shapes["pickle"].sink == "pickle.loads"
    assert shapes["secret"].cwe == "CWE-798"
    assert shapes["secret"].route == "/admin/report"
    assert shapes["secret"].method == "GET"
    assert shapes["secret"].param == "api_key"


def test_shop_scanner_covers_new_cwe_classes():
    cwes = {f.cwe for f in scan_file(SHOP)}
    assert "CWE-502" in cwes and "CWE-798" in cwes
    assert "CWE-502" not in {f.cwe for f in scan_file(VULN)}
    assert "CWE-798" not in {f.cwe for f in scan_file(VULN)}


# --- templates work on the second fixture ---------------------------------
def test_shop_exploits_succeed_on_vulnerable_app():
    src = Path(SHOP).read_text()
    for rule_id, finding in _shop_findings().items():
        assert exploit_for_finding(client_from_source(src),
                                   finding).exploited, rule_id


def test_shop_regression_green_on_baseline():
    client = client_from_source(Path(SHOP).read_text())
    results = regression_suite(client, list(_shop_findings().values()))
    assert results and all(c.passed for c in results)


def test_sqli_template_is_shared_across_frameworks():
    vuln_sqli = next(f for f in scan_file(VULN) if f.rule_id == "sqli")
    shop_sqli = next(f for f in scan_file(SHOP) if f.rule_id == "sqli")
    assert vuln_sqli.cwe == shop_sqli.cwe == "CWE-89"
    template = EXPLOIT_TEMPLATES["CWE-89"]
    assert exploit_for_finding(
        client_from_source(Path(VULN).read_text()), vuln_sqli).exploited
    assert exploit_for_finding(
        client_from_source(Path(SHOP).read_text()), shop_sqli).exploited
    assert template is EXPLOIT_TEMPLATES[vuln_sqli.cwe]


def test_shop_curated_patches_accepted_and_block_exploit():
    for rule_id in SHOP_ALL:
        patch = patch_for(SHOP, rule_id)
        assert patch is not None, rule_id
        v = verify_patch(SHOP, patch)
        assert v.accepted and v.verdict == "FIXED & VERIFIED", rule_id


def test_shop_pipeline_confirms_and_fixes_all():
    r = run_pipeline(SHOP, engine="ast")
    assert r.confirmed == 3 and r.fixed == 3


def test_shop_patches_are_fixture_specific():
    assert set(FIXTURE_PATCHES) >= {"vulnbank", "shopapi"}
    assert patch_for(VULN, "sqli") is not patch_for(SHOP, "sqli")
    assert patch_for(VULN, "pickle") is None
    assert patch_for(SHOP, "idor") is None


def test_shop_target_file_unchanged_after_pipeline():
    before = Path(SHOP).read_text()
    run_pipeline(SHOP, engine="ast")
    assert Path(SHOP).read_text() == before


# --- fixtures manifest: fail-closed gate -----------------------------------
def test_manifest_lists_both_fixtures_with_valid_hashes():
    import hashlib

    data = load_manifest()
    assert data["version"] == 1
    assert set(data["fixtures"]) >= {"vulnbank", "shopapi"}
    root = patchproof_dir()
    for fixture_id, entry in data["fixtures"].items():
        target = root / entry["dir"] / "app.py"
        assert target.is_file(), fixture_id
        assert entry["files"]["app.py"] == hashlib.sha256(
            target.read_bytes()).hexdigest(), fixture_id


def test_manifest_allows_both_pinned_fixtures():
    assert assert_bundled_fixture_target(VULN).name == "app.py"
    assert assert_bundled_fixture_target(SHOP).name == "app.py"


def test_manifest_refuses_out_of_scope_file(tmp_path):
    candidate = tmp_path / "evil.py"
    candidate.write_text("raise RuntimeError('must not execute')\n")
    with pytest.raises(ValueError, match="Refusing"):
        assert_bundled_fixture_target(candidate)


def test_manifest_refuses_tampered_content(tmp_path):
    import hashlib

    from patchproof.manifest import _hash_ok

    pin = load_manifest()["fixtures"]["vulnbank"]["files"]["app.py"]
    assert _hash_ok(Path(VULN), pin)
    tampered = tmp_path / "app.py"
    tampered.write_bytes(Path(VULN).read_bytes() + b"\n# tampered\n")
    assert not _hash_ok(tampered, pin)
    assert hashlib.sha256(Path(VULN).read_bytes()).hexdigest() == pin


def test_loop_isolated_copies_still_allowed(tmp_path):
    staged = tmp_path / "secureai-remediation-abc123" / "vulnbank_app.py"
    assert assert_bundled_fixture_target(staged).name == "vulnbank_app.py"


def test_manifest_check_command_passes():
    from patchproof.manifest import main
    assert main(["--check"]) == 0
    assert manifest_path().is_file()
