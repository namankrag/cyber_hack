"""Load a (possibly patched) copy of the target app in isolation.

Given the target source text, write it to a temp file, import it under a unique
module name, and return a test client for it. This lets the verifier run the
original and the patched code side by side in the same process without one
polluting the other.

Execution is allowlisted by the fixtures manifest (see
:mod:`patchproof.manifest`): only manifest-pinned fixture files — verified by
sha256 — and SecureAI's isolated remediation copies may run. Jobs carry the
scanner finding that parameterizes the per-CWE exploit/regression templates;
the parent process resolves each job's finding before spawning the sandbox
(never guessing: an unresolvable rule fails the whole batch closed).
"""
from __future__ import annotations

import hashlib
import importlib.util
import multiprocessing
import tempfile
import uuid
from pathlib import Path

from .manifest import (assert_bundled_fixture_target, fixture_id_for_path,
                       load_manifest, patchproof_dir)
from .models import CheckResult, ExploitResult, Finding

__all__ = ["FIXTURE_CHECK_TIMEOUT_SECONDS", "assert_bundled_fixture_target",
           "client_from_source", "run_fixture_jobs"]

FIXTURE_CHECK_TIMEOUT_SECONDS = 10


# --------------------------------------------------------------------------
# Canonical findings: pristine-fixture scans used when a job source no longer
# contains its own finding (e.g. a patched copy) and carries no snapshot.
# --------------------------------------------------------------------------
_canonical: dict[str, list[Finding]] | None = None


def _canonical_registry() -> dict[str, list[Finding]]:
    """Map fixture id -> findings scanned from its pristine manifest files."""
    global _canonical
    if _canonical is None:
        from .scanner import scan_file
        registry: dict[str, list[Finding]] = {}
        root = patchproof_dir()
        for fixture_id, entry in load_manifest()["fixtures"].items():
            for relname in entry.get("files", {}):
                target = root / entry.get("dir", "") / relname
                try:
                    findings = scan_file(target)
                except Exception:
                    findings = []
                registry.setdefault(fixture_id, []).extend(findings)
        _canonical = registry
    return _canonical


def _detect_fixture(source: str) -> str | None:
    """Identify a manifest fixture by exact content hash (pristine copies)."""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    for fixture_id, entry in load_manifest()["fixtures"].items():
        if digest in set(entry.get("files", {}).values()):
            return fixture_id
    return None


def _resolve_job(job: dict) -> dict:
    """Attach the finding (+ regression findings) a job's templates need.

    Precedence per job: explicit snapshot > scan of the job source > pristine
    canonical finding for the rule. Raises RuntimeError (fail-closed) when no
    finding can be resolved — the sandbox never guesses a request shape.
    """
    from .scanner import scan_text

    if "source" not in job or "rule_id" not in job:
        raise RuntimeError(f"malformed fixture job (need source+rule_id): "
                           f"{sorted(job)}")
    source = job["source"]
    rule_id = job["rule_id"]
    fixture = job.get("fixture") or _detect_fixture(source) or "vulnbank"
    try:
        scanned = scan_text(source)
    except Exception:
        scanned = []
    scanned_by_rule = {f.rule_id: f for f in scanned}

    finding: Finding | None = None
    if job.get("finding") is not None:
        finding = Finding.from_dict(dict(job["finding"]))
    elif rule_id in scanned_by_rule:
        finding = scanned_by_rule[rule_id]
    else:
        for candidate in _canonical_registry().get(fixture, []):
            if candidate.rule_id == rule_id:
                finding = candidate
                break
    if finding is None:
        raise RuntimeError(
            f"no finding available for rule {rule_id!r}: refusing to run an "
            "exploit without its request shape (fail-closed)")

    if job.get("findings") is not None:
        reg_findings = [Finding.from_dict(dict(d)) for d in job["findings"]]
    else:
        merged = {f.rule_id: f for f in scanned}
        for candidate in _canonical_registry().get(fixture, []):
            merged.setdefault(candidate.rule_id, candidate)
        reg_findings = list(merged.values())

    resolved = dict(job)
    resolved["fixture"] = fixture
    resolved["finding"] = finding.to_dict()
    resolved["regression_findings"] = [f.to_dict() for f in reg_findings]
    return resolved


def client_from_source(source: str):
    """Return a test client built from the given app source text.

    Supports both fixture styles: a Flask app (``create_app()`` returning an
    object with ``test_client()``) and a FastAPI app (wrapped in Starlette's
    TestClient). No network or ports are used either way.
    """
    tmp = Path(tempfile.gettempdir()) / f"fixture_{uuid.uuid4().hex}.py"
    tmp.write_text(source, encoding="utf-8")
    try:
        mod_name = f"fixture_dyn_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(mod_name, tmp)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        app = module.create_app()
        if hasattr(app, "test_client"):
            app.testing = True
            return app.test_client()
        from fastapi.testclient import TestClient
        return TestClient(app)
    finally:
        tmp.unlink(missing_ok=True)


def _fixture_jobs_worker(send_conn, jobs: list[dict]) -> None:
    """Child-process worker. It imports only the caller-provided fixture copy."""
    try:
        from .checks import exploit_for_finding, regression_suite
        from .models import CheckResult as _CR
        from .models import Finding as _Finding

        results = {}
        for job in jobs:
            key = job["key"]
            try:
                finding = _Finding.from_dict(job["finding"])
                proof = exploit_for_finding(client_from_source(job["source"]),
                                            finding)
                checks = []
                if job.get("regressions", True):
                    reg_findings = [_Finding.from_dict(d)
                                    for d in job.get("regression_findings", [])]
                    checks = regression_suite(
                        client_from_source(job["source"]), reg_findings)
                results[key] = {
                    "exploited": proof.exploited,
                    "evidence": proof.evidence,
                    "regressions": [
                        {"name": item.name, "passed": item.passed,
                         "detail": item.detail}
                        for item in checks
                    ],
                }
            except BaseException as exc:  # report candidate failure to the parent
                results[key] = {"error": f"{type(exc).__name__}: {exc}"}
        send_conn.send({"results": results})
    except BaseException as exc:
        send_conn.send({"error": f"{type(exc).__name__}: {exc}"})
    finally:
        send_conn.close()


def run_fixture_jobs(jobs: list[dict], timeout_s: float = FIXTURE_CHECK_TIMEOUT_SECONDS) -> dict:
    """Run exploit/regression jobs in an isolated, time-bounded child process.

    Jobs are intentionally passed as source strings from a manifest-pinned
    fixture or a temporary patched copy created by PatchProof/SecureAI. If code
    does not finish before the deadline, the worker is terminated and the
    caller gets a TimeoutError; a hanging candidate cannot wedge the evaluator
    or CLI.
    """
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    if not jobs:
        return {}
    prepared = [_resolve_job(dict(job)) for job in jobs]
    receive_conn, send_conn = multiprocessing.get_context("spawn").Pipe(duplex=False)
    process = multiprocessing.get_context("spawn").Process(
        target=_fixture_jobs_worker, args=(send_conn, prepared), daemon=True)
    process.start()
    send_conn.close()
    try:
        if not receive_conn.poll(timeout_s):
            process.terminate()
            process.join(timeout=2)
            raise TimeoutError(f"fixture checks exceeded {timeout_s:.1}s sandbox deadline")
        payload = receive_conn.recv()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        if "error" in payload:
            raise RuntimeError(payload["error"])
        results = payload.get("results", {})
        errors = [f"{key}: {value['error']}" for key, value in results.items()
                  if "error" in value]
        if errors:
            raise RuntimeError("; ".join(errors))
        return {
            key: {
                "exploit": ExploitResult(bool(value["exploited"]), value["evidence"]),
                "regressions": [CheckResult(**item) for item in value["regressions"]],
            }
            for key, value in results.items()
        }
    finally:
        receive_conn.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
