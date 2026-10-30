"""Item 5 — CVSS v3.1 severity per finding + patch minimality.

`cvss31_score` is a pure function tested against published vectors;
`cvss_for_finding` pins one vector + one-line metric justification per CWE.
Diff size (lines added/removed, functions touched) is shown per accepted
patch, and patches over MINIMAL_PATCH_MAX_LINES are flagged "not minimal".
"""
from pathlib import Path

import pytest

from patchproof.models import (MINIMAL_PATCH_MAX_LINES, cvss31_score,
                               cvss_for_finding)
from patchproof.patches import patch_for
from patchproof.scanner import scan_file
from patchproof.verifier import verify_patch, verify_source

VULN = str(Path(__file__).resolve().parent.parent / "vulnbank" / "app.py")
SHOP = str(Path(__file__).resolve().parent.parent / "shopapi" / "app.py")

#: Published CVSS v3.1 vectors and their spec/NVD base scores.
KNOWN_VECTORS = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
    "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0.0,
}

EXPECTED_RULE_VECTORS = {
    "sqli": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "cmdi": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    "pathtrav": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "idor": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "pickle": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "secret": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
}

EXPECTED_DIFF = {
    # rule: (added, removed, handler)
    "sqli": (5, 6, "login"),
    "idor": (3, 2, "get_account"),
    "cmdi": (9, 2, "ping"),
    "pathtrav": (5, 2, "read_file"),
    "xss": (3, 2, "greet"),
}


def _real(target, rule_id):
    return next(f for f in scan_file(target)
                if f.rule_id == rule_id)


# --- pure calculator --------------------------------------------------------
@pytest.mark.parametrize("vector,score", list(KNOWN_VECTORS.items()))
def test_cvss31_score_matches_known_vectors(vector, score):
    assert cvss31_score(vector) == score


def test_cvss31_score_rejects_malformed_input():
    with pytest.raises(ValueError):
        cvss31_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    with pytest.raises(ValueError):
        cvss31_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")


# --- per-finding assessment --------------------------------------------------
def test_cvss_for_finding_pins_vectors_and_justifications():
    seen = set()
    for target in (VULN, SHOP):
        for f in scan_file(target):
            base = f.rule_id[:-len("-decoy")] if f.rule_id.endswith(
                "-decoy") else f.rule_id
            if base in seen:
                continue
            seen.add(base)
            a = cvss_for_finding(f)
            vector, score = EXPECTED_RULE_VECTORS[base]
            assert a.vector == vector, base
            assert a.base_score == score, base
            assert len(a.metrics) == 8, base
            assert all(one and "\n" not in one
                       for one in a.metrics.values()), base
    assert seen == set(EXPECTED_RULE_VECTORS)


def test_decoy_shares_base_rule_vector():
    real = _real(VULN, "sqli")
    decoy = next(f for f in scan_file(VULN) if f.rule_id == "sqli-decoy")
    assert cvss_for_finding(decoy).vector == cvss_for_finding(real).vector


# --- diff size + minimality ---------------------------------------------------
def test_curated_patches_are_minimal_with_pinned_sizes():
    for rule_id, (added, removed, handler) in EXPECTED_DIFF.items():
        v = verify_patch(VULN, patch_for(VULN, rule_id))
        assert v.accepted, rule_id
        assert (v.lines_added, v.lines_removed) == (added, removed), rule_id
        assert handler in v.functions_touched, rule_id
        assert v.is_minimal, rule_id


def test_shop_curated_patches_are_minimal():
    for rule_id in ("sqli", "pickle", "secret"):
        v = verify_patch(SHOP, patch_for(SHOP, rule_id))
        assert v.accepted, rule_id
        assert (v.lines_added + v.lines_removed) <= MINIMAL_PATCH_MAX_LINES
        assert v.is_minimal, rule_id


def test_bloated_patch_is_accepted_but_flagged_not_minimal():
    original = Path(VULN).read_text(encoding="utf-8")
    patched = patch_for(VULN, "sqli").apply(original)
    filler = "".join(f"\n# filler comment line {i}" for i in range(40))
    v = verify_source(VULN, patched + filler, "sqli")
    assert v.accepted and v.verdict == "FIXED & VERIFIED"
    assert v.lines_added >= 40
    assert not v.is_minimal
    assert "<module>" in v.functions_touched


def test_report_dict_carries_cvss_and_size(tmp_path):
    from patchproof.pipeline import run_pipeline
    from patchproof.report import to_dict, write_html

    result = run_pipeline(VULN, engine="ast")
    d = to_dict(result)
    by_route = {i["route"]: i for i in d["issues"]}
    login = by_route["/login"]
    assert login["cvss"]["vector"] == EXPECTED_RULE_VECTORS["sqli"][0]
    assert login["cvss"]["base_score"] == 9.1
    assert len(login["cvss"]["metrics"]) == 8
    assert (login["lines_added"], login["lines_removed"]) == (5, 6)
    assert "login" in login["functions_touched"]
    assert login["is_minimal"] is True
    out = tmp_path / "report.html"
    write_html(result, out)
    html = out.read_text(encoding="utf-8")
    assert "CVSS v3.1" in html and "Patch size" in html
    assert "NOT MINIMAL" not in html
