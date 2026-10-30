"""Item 2 — noise funnel: realistic decoys that scan dirty but prove clean.

Both fixtures carry decoy handlers the AST scanner (and Semgrep rules where
applicable) flags, while every exploit template fails against them. The
pipeline must mark them NOT CONFIRMED, attempt no patch, and report the
funnel raw-alerts N -> confirmed M -> fixed K plus scanner precision before
vs after exploit confirmation.
"""
from pathlib import Path

from patchproof.pipeline import run_pipeline
from patchproof.report import to_dict
from patchproof.scanner import scan_file

VULN = str(Path(__file__).resolve().parent.parent / "vulnbank" / "app.py")
SHOP = str(Path(__file__).resolve().parent.parent / "shopapi" / "app.py")

VULN_DECOY_ROUTES = {
    "/search", "/ping-safe", "/docs", "/hello",
    "/accounts/<int:account_id>/statement",
}
SHOP_DECOY_ROUTES = {"/orders/lookup", "/import/legacy", "/legacy/report"}

VULN_DECOY_RULES = {
    "sqli-decoy", "cmdi-decoy", "pathtrav-decoy", "xss-decoy", "idor-decoy",
}
SHOP_DECOY_RULES = {"sqli-decoy", "pickle-decoy", "secret-decoy"}


def test_decoys_scan_as_suffixed_rules_with_same_cwe():
    vuln = {f.rule_id: f.cwe for f in scan_file(VULN)}
    assert VULN_DECOY_RULES <= set(vuln)
    assert vuln["sqli-decoy"] == vuln["sqli"] == "CWE-89"
    shop = {f.rule_id: f.cwe for f in scan_file(SHOP)}
    assert SHOP_DECOY_RULES <= set(shop)
    assert shop["pickle-decoy"] == shop["pickle"] == "CWE-502"


def _by_route(result):
    return {i.finding.route: i for i in result.issues}


# --- VulnBank funnel -------------------------------------------------------
def test_vulnbank_scanner_flags_five_decoys():
    routes = {f.route for f in scan_file(VULN)}
    assert VULN_DECOY_ROUTES <= routes
    assert len(scan_file(VULN)) == 10  # 5 real + 5 decoys


def test_vulnbank_funnel_marks_decoys_not_confirmed():
    r = run_pipeline(VULN, engine="ast")
    assert r.raw_alerts == 10
    assert r.confirmed == 5
    assert r.fixed == 5
    by_route = _by_route(r)
    for route in VULN_DECOY_ROUTES:
        issue = by_route[route]
        assert not issue.confirmed, route
        assert issue.verification is None, route
        assert issue.status == "NOT CONFIRMED (likely false positive)", route
    for route, issue in by_route.items():
        if route not in VULN_DECOY_ROUTES:
            assert issue.confirmed, route
            assert issue.verification is not None and issue.verification.accepted


def test_vulnbank_precision_before_vs_after():
    r = run_pipeline(VULN, engine="ast")
    assert r.precision_before == 0.5
    assert r.precision_after == 1.0


# --- ShopAPI funnel ---------------------------------------------------------
def test_shopapi_scanner_flags_three_decoys():
    routes = {f.route for f in scan_file(SHOP)}
    assert SHOP_DECOY_ROUTES <= routes
    assert len(scan_file(SHOP)) == 6  # 3 real + 3 decoys


def test_shopapi_funnel_marks_decoys_not_confirmed():
    r = run_pipeline(SHOP, engine="ast")
    assert r.raw_alerts == 6
    assert r.confirmed == 3
    assert r.fixed == 3
    by_route = _by_route(r)
    for route in SHOP_DECOY_ROUTES:
        issue = by_route[route]
        assert not issue.confirmed, route
        assert issue.verification is None, route
        assert issue.status == "NOT CONFIRMED (likely false positive)", route


def test_shopapi_precision_before_vs_after():
    r = run_pipeline(SHOP, engine="ast")
    assert r.precision_before == 0.5
    assert r.precision_after == 1.0


# --- report dicts keep old keys, add the funnel ----------------------------
def test_report_dict_carries_funnel_and_keeps_old_keys():
    r = run_pipeline(VULN, engine="ast")
    d = to_dict(r)
    assert set(d) == {"target", "summary", "issues"}
    s = d["summary"]
    for key in ("confirmed", "fixed", "total_findings"):
        assert key in s  # old keys kept
    assert s["raw_alerts"] == 10
    assert (s["raw_alerts"], s["confirmed"], s["fixed"]) == (10, 5, 5)
    assert s["precision_before"] == 0.5
    assert s["precision_after"] == 1.0


def test_report_html_renders_funnel(tmp_path):
    from patchproof.report import write_html

    r = run_pipeline(SHOP, engine="ast")
    out = tmp_path / "report.html"
    write_html(r, out)
    html = out.read_text(encoding="utf-8")
    assert "Raw alerts <b>6</b>" in html
    assert "confirmed <b>3</b>" in html
    assert "fixed <b>3</b>" in html
    assert "precision before confirmation" in html
