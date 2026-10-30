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
from pathlib import Path

from .checks import EXPLOITS, regression_suite
from .models import VerificationResult
from .patches import Patch
from .sandbox import client_from_source


def _verify(target_file: str, original: str, patched_src: str,
            rule_id: str, rationale: str) -> VerificationResult:
    result = VerificationResult(rule_id=rule_id, baseline_exploited=False,
                                patched_exploited=True, patch_rationale=rationale)
    try:
        base_client = client_from_source(original)
        result.baseline_exploited = EXPLOITS[rule_id](base_client).exploited
        result.regression_before = regression_suite(base_client)

        result.diff = _diff(original, patched_src, target_file)
        patched_client = client_from_source(patched_src)
        result.patched_exploited = EXPLOITS[rule_id](patched_client).exploited
        result.regression_after = regression_suite(patched_client)
    except Exception as exc:  # noqa: BLE001 - surface as ERROR verdict
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def verify_patch(target_file: str | Path, patch: Patch) -> VerificationResult:
    """Verify a curated patch (source replacements)."""
    original = Path(target_file).read_text()
    try:
        patched_src = patch.apply(original)
    except Exception as exc:  # noqa: BLE001
        r = VerificationResult(rule_id=patch.rule_id, baseline_exploited=False,
                               patched_exploited=True,
                               patch_rationale=patch.rationale)
        r.error = f"{type(exc).__name__}: {exc}"
        return r
    return _verify(str(target_file), original, patched_src,
                   patch.rule_id, patch.rationale)


def verify_source(target_file: str | Path, patched_src: str, rule_id: str,
                  rationale: str = "AI-generated patch") -> VerificationResult:
    """Verify an arbitrary candidate patched source (e.g. from the AI)."""
    original = Path(target_file).read_text()
    return _verify(str(target_file), original, patched_src, rule_id, rationale)


def apply_patch_to_disk(target_file: str | Path, patch: Patch) -> str:
    """Actually write a curated patch to the file. Returns the diff."""
    target_file = Path(target_file)
    original = target_file.read_text()
    patched = patch.apply(original)
    target_file.write_text(patched)
    return _diff(original, patched, str(target_file))


def _diff(a: str, b: str, path: str) -> str:
    return "".join(difflib.unified_diff(
        a.splitlines(keepends=True), b.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}",
    ))
