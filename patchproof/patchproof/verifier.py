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

import ast
import difflib
import time
from pathlib import Path

from .manifest import fixture_id_for_path, load_manifest
from .models import MINIMAL_PATCH_MAX_LINES, Finding, VerificationResult
from .patches import Patch
from .sandbox import assert_bundled_fixture_target, run_fixture_jobs

#: Bound for the isolated coverage run (same sandbox discipline as the gate:
#: patched source only ever executes as a temp copy in a child process).
COVERAGE_TIMEOUT_SECONDS = 120.0


def _coverage_worker(send_conn, source: str, finding: dict,
                     findings: list[dict], path: str) -> None:
    """Child-process worker: trace exploit + regression on one patched copy.

    Uses only the standard library (``sys``/``threading.settrace`` — the same
    facility the stdlib ``trace`` module is built on; ``sys.monitoring`` needs
    3.12+ and ``coverage.py`` is not a dependency). Only lines from the temp
    fixture copy are recorded, so framework imports stay untraced and fast.
    """
    try:
        import importlib.util
        import os
        import sys
        import threading

        from .checks import exploit_for_finding, regression_suite
        from .models import Finding as _Finding

        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        target = os.path.abspath(path)
        executed: set[int] = set()

        def _tracer(frame, event, _arg):
            if event == "line":
                try:
                    name = os.path.abspath(frame.f_code.co_filename)
                except (TypeError, ValueError):
                    return _tracer
                if name == target or name == path:
                    executed.add(frame.f_lineno)
            return _tracer

        def _run():
            spec = importlib.util.spec_from_file_location(
                "fixture_coverage_run", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            app = module.create_app()
            if hasattr(app, "test_client"):
                app.testing = True
                client = app.test_client()
            else:
                from fastapi.testclient import TestClient
                client = TestClient(app)
            resolved = _Finding.from_dict(finding)
            all_findings = [_Finding.from_dict(d) for d in findings]
            exploit_for_finding(client, resolved)
            regression_suite(client, all_findings)

        sys.settrace(_tracer)
        threading.settrace(_tracer)
        try:
            _run()
        finally:
            sys.settrace(None)
            threading.settrace(None)
        send_conn.send({"executed": sorted(executed)})
    except BaseException as exc:  # noqa: BLE001 - report, never raise
        send_conn.send({"error": f"{type(exc).__name__}: {exc}"})
    finally:
        send_conn.close()


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
        from .checks import variant_payloads
        from .scanner import scan_text
        result.diff = _diff(original, patched_src, target_file)
        (result.lines_added, result.lines_removed,
         result.functions_touched,
         result.is_minimal) = _diff_stat(original, patched_src)
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
        # Item-4 coverage: trace the patched copy through its exploit +
        # regression run and attribute executed lines to each patched
        # function. Advisory only — never fails the gate (fail-soft {}).
        try:
            result.coverage = _patched_coverage(
                original, patched_src, snapshot, all_findings)
        except Exception:  # noqa: BLE001 - coverage is advisory
            result.coverage = {}
        # Item-3 variant gate: the original probe is blocked and the app
        # still works — now replay the whole payload corpus against the
        # patched copy through the same sandboxed jobs. One surviving
        # variant rejects the patch as PATCH BYPASSABLE.
        if (result.baseline_exploited and not result.patched_exploited
                and result.regression_after_passed):
            corpus = variant_payloads(finding)
            result.variants_total = len(corpus)
            variant_jobs = [
                {"key": f"variant-{index}", "source": patched_src,
                 "rule_id": rule_id, "fixture": fixture,
                 "finding": {**snapshot, "variant": payload},
                 "findings": all_findings}
                for index, (_, payload) in enumerate(corpus)
            ]
            variant_checks = run_fixture_jobs(variant_jobs)
            blocked = 0
            for index, (label, payload) in enumerate(corpus):
                if variant_checks[f"variant-{index}"]["exploit"].exploited:
                    shown = payload if len(payload) <= 80 else payload[:77] + "..."
                    result.bypass_payload = f"{label}: {shown}"
                    break
                blocked += 1
            result.variants_blocked = blocked
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


def _changed_lines(original: str, patched: str) -> set[int]:
    """New-file line numbers the patch touches (for coverage attribution)."""
    a = original.splitlines()
    b = patched.splitlines()
    changed: set[int] = set()
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(
            None, a, b).get_opcodes():
        if tag == "equal":
            continue
        if j1 == j2:
            changed.add(j1 + 1)  # pure deletion: attribute the seam
        else:
            changed.update(range(j1 + 1, j2 + 1))
    return changed


def _touched_functions(patched_src: str, changed: set[int]) -> list[str]:
    """Sorted names of scopes the patch touches (module-level -> "<module>")."""
    tree = ast.parse(patched_src)
    lines = patched_src.splitlines()
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    touched: list[str] = []
    for lineno in sorted(changed):
        if not 1 <= lineno <= len(lines):
            continue
        owners = [n for n in scopes
                  if n.lineno <= lineno <= (n.end_lineno or n.lineno)]
        if not owners:
            name = "<module>"
        else:
            owner = min(owners,
                        key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
            name = owner.name
        if name not in touched:
            touched.append(name)
    return sorted(touched)


def _diff_stat(original: str, patched: str,
               threshold: int = MINIMAL_PATCH_MAX_LINES
               ) -> tuple[int, int, list[str], bool]:
    """(added, removed, touched functions, is-minimal) for a patch diff."""
    a = original.splitlines()
    b = patched.splitlines()
    added = removed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
            None, a, b).get_opcodes():
        if tag == "equal":
            continue
        if tag in ("replace", "insert"):
            added += j2 - j1
        if tag in ("replace", "delete"):
            removed += i2 - i1
    touched = _touched_functions(patched, _changed_lines(original, patched))
    return added, removed, touched, (added + removed) <= threshold


def _coverage_by_function(patched_src: str, changed: set[int],
                          executed: set[int]) -> dict[str, float]:
    """Executed-line fraction per patched function (innermost scope wins)."""
    tree = ast.parse(patched_src)
    lines = patched_src.splitlines()
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    out: dict[str, float] = {}
    for lineno in sorted(changed):
        if not 1 <= lineno <= len(lines):
            continue
        owners = [n for n in scopes
                  if n.lineno <= lineno <= (n.end_lineno or n.lineno)]
        if not owners:
            continue
        owner = min(owners,
                    key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
        if owner.name in out:
            continue
        start, end = owner.lineno, owner.end_lineno or owner.lineno
        code = [ln for ln in range(start, end + 1)
                if lines[ln - 1].strip()
                and not lines[ln - 1].strip().startswith("#")]
        if not code:
            continue
        hits = sum(1 for ln in code if ln in executed)
        out[owner.name] = round(hits / len(code), 3)
    return out


def _patched_coverage(original: str, patched_src: str, finding: dict,
                      findings: list[dict],
                      timeout_s: float = COVERAGE_TIMEOUT_SECONDS
                      ) -> dict[str, float]:
    """Per-function coverage of one patched copy; {} when unmeasurable.

    The patched source only ever executes as a temp copy in a time-bounded
    child process (same sandbox discipline as the gate).
    """
    import multiprocessing
    import tempfile

    changed = _changed_lines(original, patched_src)
    if not changed:
        return {}
    fd, tmppath = tempfile.mkstemp(prefix="patchproof_cov_", suffix="_app.py")
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(patched_src)
        context = multiprocessing.get_context("spawn")
        receive_conn, send_conn = context.Pipe(duplex=False)
        process = context.Process(
            target=_coverage_worker,
            args=(send_conn, patched_src, finding, findings, tmppath),
            daemon=True)
        process.start()
        send_conn.close()
        try:
            if not receive_conn.poll(timeout_s):
                process.terminate()
                process.join(timeout=2)
                return {}
            payload = receive_conn.recv()
            process.join(timeout=2)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            if "error" in payload:
                return {}
            executed = set(payload.get("executed", []))
        finally:
            receive_conn.close()
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
    finally:
        try:
            Path(tmppath).unlink(missing_ok=True)
        except OSError:
            pass
    return _coverage_by_function(patched_src, changed, executed)
