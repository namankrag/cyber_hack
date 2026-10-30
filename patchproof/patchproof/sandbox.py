"""Load a (possibly patched) copy of the target app in isolation.

Given the target source text, write it to a temp file, import it under a unique
module name, and return a fresh Flask test client. This lets the verifier run
the original and the patched code side by side in the same process without one
polluting the other.
"""
from __future__ import annotations

import importlib.util
import multiprocessing
import tempfile
import uuid
from pathlib import Path

from .models import CheckResult, ExploitResult

FIXTURE_CHECK_TIMEOUT_SECONDS = 10


def assert_bundled_fixture_target(path: str | Path) -> Path:
    """Allow execution only for VulnBank or SecureAI's named temporary copy."""
    target = Path(path).resolve()
    bundled = (Path(__file__).resolve().parent.parent / "vulnbank" / "app.py").resolve()
    loop_copy = (target.name == "vulnbank_app.py"
                 and target.parent.name.startswith("secureai-remediation-"))
    if target != bundled and not loop_copy:
        raise ValueError(
            "Exploit and candidate execution is limited to the bundled VulnBank "
            "fixture and SecureAI's isolated remediation copies."
        )
    return target


def client_from_source(source: str):
    """Return a Flask test client built from the given app source text."""
    tmp = Path(tempfile.gettempdir()) / f"vulnbank_{uuid.uuid4().hex}.py"
    tmp.write_text(source, encoding="utf-8")
    try:
        mod_name = f"vulnbank_dyn_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(mod_name, tmp)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        app = module.create_app()
        app.testing = True
        return app.test_client()
    finally:
        tmp.unlink(missing_ok=True)


def _fixture_jobs_worker(send_conn, jobs: list[dict]) -> None:
    """Child-process worker. It imports only the caller-provided fixture copy."""
    try:
        from .checks import EXPLOITS, regression_suite

        results = {}
        for job in jobs:
            key = job["key"]
            try:
                exploit = EXPLOITS.get(job["rule_id"])
                if exploit is None:
                    raise KeyError(f"no exploit registered for {job['rule_id']}")
                proof = exploit(client_from_source(job["source"]))
                checks = (regression_suite(client_from_source(job["source"]))
                          if job.get("regressions", True) else [])
                results[key] = {
                    "exploited": proof.exploited,
                    "evidence": proof.evidence,
                    "regressions": [
                        {"name": item.name, "passed": item.passed, "detail": item.detail}
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

    Jobs are intentionally passed as source strings from the bundled VulnBank
    fixture or a temporary patched copy created by SecureAI. If code does not
    finish before the deadline, the worker is terminated and the caller gets a
    TimeoutError; a hanging candidate cannot wedge the evaluator or CLI.
    """
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    if not jobs:
        return {}
    receive_conn, send_conn = multiprocessing.get_context("spawn").Pipe(duplex=False)
    process = multiprocessing.get_context("spawn").Process(
        target=_fixture_jobs_worker, args=(send_conn, jobs), daemon=True)
    process.start()
    send_conn.close()
    try:
        if not receive_conn.poll(timeout_s):
            process.terminate()
            process.join(timeout=2)
            raise TimeoutError(f"fixture checks exceeded {timeout_s:.1f}s sandbox deadline")
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
