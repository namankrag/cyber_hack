"""The verification gate — the heart of PatchProof.

For one finding + candidate fix it runs the full proof:

  1. Baseline (unpatched): the exploit must SUCCEED  -> finding is real.
                           regression must PASS      -> app works to begin with.
  2. Patched:             the exploit must be BLOCKED -> fix works.
                           regression must still PASS -> fix didn't break anything.

A fix is accepted only if all four hold. This is engine-agnostic about where the
patch came from — a curated diff or an AI-generated one is judged identically.
"""
from __future__ import annotations

import difflib
import time
from pathlib import Path

from .models import VerificationResult
from .patches import Patch
from .sandbox import assert_bundled_fixture_target, run_fixture_jobs


def _verify(target_file: str, original: str, patched_src: str,
            rule_id: str, rationale: str) -> VerificationResult:
    started = time.perf_counter()
    result = VerificationResult(rule_id=rule_id, baseline_exploited=False,
                                patched_exploited=True, patch_rationale=rationale)
    try:
        result.diff = _diff(original, patched_src, target_file)
        checks = run_fixture_jobs([
            {"key": "baseline", "source": original, "rule_id": rule_id},
            {"key": "patched", "source": patched_src, "rule_id": rule_id},
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
