"""The verification gate — the heart of PatchProof.

For one finding + candidate fix it runs the full proof:

  1. Baseline (unpatched): the exploit must SUCCEED  -> finding is real.
                           regression must PASS      -> app works to begin with.
  2. Patched:             the exploit must be BLOCKED -> fix works.
                           regression must still PASS -> fix didn't break anything.

A fix is accepted only if all four hold. This is engine-agnostic about where the
patch came from — a curated diff or an AI-generated one is judged identically.

Findings travel with the jobs so the per-CWE templates are parameterized by
the same request shape on both runs (a patched copy may no longer scan, so the
baseline finding snapshot is reused rather than re-derived).
"""
from __future__ import annotations

import difflib
import time
from pathlib import Path

from .manifest import fixture_id_for_path, load_manifest
from .models import Finding, VerificationResult
from .patches import Patch
from .sandbox import assert_bundled_fixture_target, run_fixture_jobs


def _finding_for(source: str, rule_id: str) -> Finding | None:
    from .scanner import scan_text
    for finding in scan_text(source):
        if finding.rule_id == rule_id:
            return finding
    return None


def _fixture_of(target_file: str | Path) -> str:
    fixture = fixture_id_for_path(target_file)
    if fixture is None:
        stem = Path(target_file).stem
        if stem.endswith("_app"):
            candidate = stem[:-len("_app")]
            if candidate in load_manifest()["fixtures"]:
                fixture = candidate
    return fixture or "vulnbank"


def _verify(target_file: str, original: str, patched_src: str,
            rule_id: str, rationale: str) -> VerificationResult:
    started = time.perf_counter()
    result = VerificationResult(rule_id=rule_id, baseline_exploited=False,
                                patched_exploited=True, patch_rationale=rationale)
    finding = _finding_for(original, rule_id)
    if finding is None:
        result.error = (f"no scanner finding for rule {rule_id!r} in "
                        f"{target_file} (fail-closed: nothing to verify)")
        result.verification_time_ms = round((time.perf_counter() - started) * 1000, 3)
        return result
    try:
        from .scanner import scan_text
        result.diff = _diff(original, patched_src, target_file)
        fixture = _fixture_of(target_file)
        snapshot = finding.to_dict()
        all_findings = [f.to_dict() for f in scan_text(original)]
        checks = run_fixture_jobs([
            {"key": "baseline", "source": original, "rule_id": rule_id,
             "fixture": fixture, "finding": snapshot,
             "findings": all_findings},
            {"key": "patched", "source": patched_src, "rule_id": rule_id,
             "fixture": fixture, "finding": snapshot,
             "findings": all_findings},
        ])
        result.baseline_exploited = checks["baseline"]["exploit"].exploited
        result.regression_before = checks["baseline"]["regressions"]
        result.patched_exploited = checks["patched"]["exploit"].exploited
        result.regression_after = checks["patched"]["regressions"]
    except Exception as exc:  # noqa: BLE001 - surface as ERROR verdict
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.verification_time_ms = round((time.perf_counter() - started) * 1000, 3)
    return result


def verify_patch(target_file: str | Path, patch: Patch) -> VerificationResult:
    """Verify a curated patch (source replacements)."""
    target_file = assert_bundled_fixture_target(target_file)
    started = time.perf_counter()
    original = Path(target_file).read_text(encoding="utf-8")
    try:
        patched_src = patch.apply(original)
    except Exception as exc:  # noqa: BLE001
        r = VerificationResult(rule_id=patch.rule_id, baseline_exploited=False,
                               patched_exploited=True,
                               patch_rationale=patch.rationale)
        r.error = f"{type(exc).__name__}: {exc}"
        r.verification_time_ms = round((time.perf_counter() - started) * 1000, 3)
        return r
    return _verify(str(target_file), original, patched_src,
                   patch.rule_id, patch.rationale)


def verify_source(target_file: str | Path, patched_src: str, rule_id: str,
                  rationale: str = "AI-generated patch") -> VerificationResult:
    """Verify an arbitrary candidate patched source (e.g. from the AI)."""
    target_file = assert_bundled_fixture_target(target_file)
    original = Path(target_file).read_text(encoding="utf-8")
    return _verify(str(target_file), original, patched_src, rule_id, rationale)


def _diff(a: str, b: str, path: str) -> str:
    return "".join(difflib.unified_diff(
        a.splitlines(keepends=True), b.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}",
    ))
