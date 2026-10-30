"""Item 4 — stronger regression (over-blocking pins) + per-function coverage.

Every new probe passes on the vulnerable baseline AND on every curated
patched copy (a patch that over-blocks fails the gate). Coverage is measured
with only the standard library while the patched exploit + regression runs
execute, in a time-bounded child process against an isolated temp copy.
"""
from pathlib import Path

from patchproof.patches import patch_for
from patchproof.verifier import verify_patch

VULN = str(Path(__file__).resolve().parent.parent / "vulnbank" / "app.py")
SHOP = str(Path(__file__).resolve().parent.parent / "shopapi" / "app.py")

VULN_RULES = ["sqli", "idor", "cmdi", "pathtrav", "xss"]
SHOP_RULES = ["sqli", "pickle", "secret"]

#: Patched handler per rule (coverage must name it).
HANDLER = {
    (VULN, "sqli"): "login",
    (VULN, "idor"): "get_account",
    (VULN, "cmdi"): "ping",
    (VULN, "pathtrav"): "read_file",
    (VULN, "xss"): "greet",
    (SHOP, "sqli"): "login",
    (SHOP, "pickle"): "do_import",
    (SHOP, "secret"): "admin_report",
}


def _verified(target, rule_id):
    v = verify_patch(target, patch_for(target, rule_id))
    assert v.accepted and v.verdict == "FIXED & VERIFIED", (target, rule_id)
    return v


EXPECTED_NEW = {
    VULN: {"quote_in_username_no_crash", "unicode_username_no_crash",
           "admin_reads_other_account", "legit_hostname_with_dots_works",
           "nested_public_file_readable", "unicode_greeting_preserved",
           "empty_greeting_works"},
    SHOP: {"quote_in_username_no_crash", "unicode_username_no_crash",
           "empty_import_works", "empty_key_denied"},
}


def test_new_probes_pass_on_baseline_and_every_patch():
    for target, rules in ((VULN, VULN_RULES), (SHOP, SHOP_RULES)):
        for rule_id in rules:
            v = _verified(target, rule_id)
            # The gate's own regression runs (baseline AND patched) include
            # every new probe for this fixture's CWEs — all must pass, so no
            # accepted patch over-blocks legitimate use.
            for run in (v.regression_before, v.regression_after):
                names = {c.name for c in run}
                assert EXPECTED_NEW[target] <= names, (target, rule_id, names)
                failed = [c.name for c in run if not c.passed]
                assert not failed, (target, rule_id, failed)


def test_admin_cross_account_exempt_but_stranger_blocked():
    from patchproof.sandbox import client_from_source

    src = Path(VULN).read_text(encoding="utf-8")
    patched = patch_for(VULN, "idor").apply(src)
    from patchproof.checks import _AUTH_BEARER_1, _fill_route, _json, _status
    from patchproof.checks import _http_get

    for source, stranger_status in ((src, 200), (patched, 403)):
        client = client_from_source(source)
        admin = _http_get(client, _fill_route(
            "/accounts/<int:account_id>", 1002),
            headers={"Authorization": "Bearer 3"})
        assert _status(admin) == 200, source[:40]
        stranger = _http_get(client, _fill_route(
            "/accounts/<int:account_id>", 1002),
            headers=_AUTH_BEARER_1)
        assert _status(stranger) == stranger_status, source[:40]


def test_per_function_coverage_reported_for_every_patch():
    for target, rules in ((VULN, VULN_RULES), (SHOP, SHOP_RULES)):
        for rule_id in rules:
            v = _verified(target, rule_id)
            assert v.coverage, (target, rule_id)
            handler = HANDLER[(target, rule_id)]
            assert handler in v.coverage, (target, rule_id, v.coverage)
            for name, frac in v.coverage.items():
                assert 0.0 < frac <= 1.0, (target, rule_id, name, frac)
            # Exploit + regression exercise the patched handler thoroughly.
            assert v.coverage[handler] > 0.5, (
                target, rule_id, v.coverage)


def test_report_dict_carries_coverage():
    from patchproof.pipeline import run_pipeline
    from patchproof.report import to_dict

    d = to_dict(run_pipeline(VULN, engine="ast"))
    by_route = {i["route"]: i for i in d["issues"]}
    login = by_route["/login"]
    assert login["coverage"] and login["coverage"]["login"] > 0.5
