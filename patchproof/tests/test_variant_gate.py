"""Item 3 — patch robustness: per-CWE payload-variant corpus + BYPASSABLE gate.

Every curated patch is accepted only if ALL corpus variants are blocked on
the patched copy. Deliberately weak blocklist patches stop the canned probe
but fall to a variant, and the gate must reject them with verdict
"PATCH BYPASSABLE" naming the bypassing payload.
"""
from pathlib import Path

import pytest

from patchproof.checks import exploit_variant, variant_payloads
from patchproof.patches import (
    PATCH_CMDI_BLOCKLIST,
    PATCH_PATHTRAV_BLOCKLIST,
    PATCH_SQLI_BLOCKLIST,
    PATCH_XSS_BLOCKLIST,
    WEAK_PATCHES,
    patch_for,
)
from patchproof.sandbox import client_from_source
from patchproof.scanner import scan_file
from patchproof.verifier import verify_patch

VULN = str(Path(__file__).resolve().parent.parent / "vulnbank" / "app.py")
SHOP = str(Path(__file__).resolve().parent.parent / "shopapi" / "app.py")

EXPECTED_SIZES = {
    "CWE-89": 12,
    "CWE-78": 12,
    "CWE-22": 10,
    "CWE-79": 13,
    "CWE-639": 8,
    "CWE-502": 10,
    "CWE-798": 8,
}


def _real(target, rule_id):
    return next(f for f in scan_file(target)
                if f.rule_id == rule_id)


# --- corpus shape ----------------------------------------------------------
def test_variant_corpus_sizes():
    probed = set()
    for target in (VULN, SHOP):
        for f in scan_file(target):
            if f.rule_id.endswith("-decoy") or f.cwe in probed:
                continue
            probed.add(f.cwe)
            assert len(variant_payloads(f)) == EXPECTED_SIZES[f.cwe], f.cwe
    assert probed == set(EXPECTED_SIZES)


# --- key variants exploit the vulnerable baseline --------------------------
@pytest.mark.parametrize(("target", "rule_id", "label"), [
    (VULN, "sqli", "comment-nospace"),
    (VULN, "sqli", "union-admin"),
    (VULN, "sqli", "or-username"),
    (VULN, "cmdi", "and"),
    (VULN, "cmdi", "dollar-paren"),
    (VULN, "cmdi", "backticks"),
    (VULN, "cmdi", "newline"),
    (VULN, "pathtrav", "nested-one"),
    (VULN, "pathtrav", "nested-two-deep"),
    (VULN, "xss", "img-onerror"),
    (VULN, "xss", "svg-onload"),
    (VULN, "idor", "neighbour-victim"),
    (VULN, "idor", "neighbour-admin"),
    (SHOP, "sqli", "comment-nospace"),
    (SHOP, "pickle", "pickle-proto-0"),
    (SHOP, "pickle", "pickle-dict"),
    (SHOP, "secret", "exact-literal"),
])
def test_key_variants_exploit_baseline(target, rule_id, label):
    finding = _real(target, rule_id)
    payload = dict(variant_payloads(finding))[label]
    client = client_from_source(Path(target).read_text())
    assert exploit_variant(client, finding, payload).exploited, label


def test_documented_non_exploiting_variants_fail_on_baseline():
    # Own/missing/negative ids and credential near-misses cannot exploit even
    # the vulnerable app; the gate still pins that patches reject them.
    idor = _real(VULN, "idor")
    client = client_from_source(Path(VULN).read_text())
    for label in ("own", "missing-low", "zero", "negative", "far", "missing"):
        payload = dict(variant_payloads(idor))[label]
        assert not exploit_variant(client, idor, payload).exploited, label
    shop_src = Path(SHOP).read_text()
    secret = _real(SHOP, "secret")
    by_label = dict(variant_payloads(secret))
    client = client_from_source(shop_src)
    for label, payload in by_label.items():
        if label == "exact-literal":
            assert exploit_variant(client, secret, payload).exploited
        else:
            assert not exploit_variant(client, secret, payload).exploited, label


# --- curated patches block every variant ------------------------------------
@pytest.mark.parametrize(("target", "rule_id"), [
    (VULN, "sqli"), (VULN, "idor"), (VULN, "cmdi"),
    (VULN, "pathtrav"), (VULN, "xss"),
    (SHOP, "sqli"), (SHOP, "pickle"), (SHOP, "secret"),
])
def test_curated_patch_blocks_all_variants(target, rule_id):
    patch = patch_for(target, rule_id)
    assert patch is not None
    v = verify_patch(target, patch)
    assert v.variants_total == EXPECTED_SIZES[
        _real(target, rule_id).cwe], rule_id
    assert v.variants_blocked == v.variants_total, rule_id
    assert v.bypass_payload is None, rule_id
    assert v.accepted and v.verdict == "FIXED & VERIFIED", rule_id


# --- weak blocklists are rejected as PATCH BYPASSABLE ------------------------
@pytest.mark.parametrize(("patch", "bypass_label"), [
    (PATCH_SQLI_BLOCKLIST, "comment-nospace"),
    (PATCH_CMDI_BLOCKLIST, "and"),
    (PATCH_XSS_BLOCKLIST, "img-onerror"),
    (PATCH_PATHTRAV_BLOCKLIST, "dotdot-double-slash"),
])
def test_weak_blocklist_patch_is_bypassable(patch, bypass_label):
    v = verify_patch(VULN, patch)
    assert v.baseline_exploited          # original probe works on baseline
    assert not v.patched_exploited       # ... and is stopped by the blocklist
    assert v.regression_after_passed    # app still works: it is a bypass...
    assert not v.accepted
    assert v.verdict == "PATCH BYPASSABLE"
    assert v.bypass_payload is not None
    assert v.bypass_payload.startswith(bypass_label + ":")
    assert v.variants_blocked < v.variants_total


def test_weak_patches_are_never_pipeline_selected():
    for rule_id, weak in WEAK_PATCHES.items():
        assert patch_for(VULN, rule_id) is not weak
    assert set(WEAK_PATCHES) == {"sqli", "cmdi", "xss", "pathtrav"}
