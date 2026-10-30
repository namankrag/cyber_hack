"""Independent scorecard grader.

This module does not consume evaluator-computed metrics or pass flags. It reads
the labeled outcomes, recalculates runtime metrics, and independently repeats
the bundled-fixture exploit and patch checks before deciding the gates.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from . import fixture_path

GROUND_TRUTH = {
    "sqli": "CWE-89",
    "idor": "CWE-639",
    "cmdi": "CWE-78",
    "pathtrav": "CWE-22",
    "xss": "CWE-79",
}


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def _independent_code_recheck() -> dict:
    """Re-scan and re-run each ground-truth exploit/patch from a fresh source."""
    from patchproof.patches import PATCHES
    from patchproof.sandbox import run_fixture_jobs
    from patchproof.scanner import scan

    target = fixture_path()
    source = target.read_text(encoding="utf-8")
    findings = scan(target, engine="ast")
    by_rule = {finding.rule_id: finding for finding in findings}
    cases = []
    jobs = []
    prepared = {}
    for rule_id, cwe in GROUND_TRUTH.items():
        finding = by_rule.get(rule_id)
        patch = PATCHES.get(rule_id)
        patch_error = None
        if patch is not None:
            try:
                patched_source = patch.apply(source)
                prepared[rule_id] = patched_source
                jobs.extend([
                    {"key": f"{rule_id}-baseline", "source": source,
                     "rule_id": rule_id, "regressions": False},
                    {"key": f"{rule_id}-patched", "source": patched_source,
                     "rule_id": rule_id, "regressions": True},
                ])
            except Exception as exc:  # grader records errors as failed evidence
                patch_error = f"{type(exc).__name__}: {exc}"
        prepared[rule_id] = prepared.get(rule_id), patch_error

    sandbox_error = None
    try:
        checks = run_fixture_jobs(jobs)
    except (RuntimeError, TimeoutError) as exc:
        checks = {}
        sandbox_error = f"{type(exc).__name__}: {exc}"

    for rule_id, cwe in GROUND_TRUTH.items():
        finding = by_rule.get(rule_id)
        patched_source, patch_error = prepared[rule_id]
        baseline = checks.get(f"{rule_id}-baseline", {}).get("exploit")
        patched_result = checks.get(f"{rule_id}-patched", {})
        patched_exploit = patched_result.get("exploit")
        regression_after = patched_result.get("regressions", [])
        error = patch_error or sandbox_error
        confirmed = bool(baseline and baseline.exploited)
        fixed = bool(confirmed and patched_exploit and not patched_exploit.exploited
                     and regression_after and all(check.passed for check in regression_after)
                     and error is None)
        cases.append({
            "rule_id": rule_id,
            "cwe": cwe,
            "scanner_found": bool(finding and finding.cwe == cwe),
            "scanner_location": f"{finding.file}:{finding.line}" if finding else "",
            "exploit_confirmed": confirmed,
            "exploit_evidence": baseline.evidence if baseline else (error or "no exploit proof available"),
            "patch_accepted": fixed,
            "patched_exploit_blocked": bool(patched_exploit and not patched_exploit.exploited),
            "regression_passed": bool(regression_after) and all(c.passed for c in regression_after),
            "regression_checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in regression_after
            ],
            "error": error,
        })
    return {"cases": cases, "scanner_findings": len(findings)}


def _independent_loop_recheck(loop: dict) -> dict:
    """Rebuild the temporary deployment from accepted diffs and re-scan it."""
    from patchproof.patches import PATCHES
    from patchproof.sandbox import run_fixture_jobs
    from patchproof.scanner import scan

    source = fixture_path().read_text(encoding="utf-8")
    applied = []
    try:
        for item in loop.get("iterations", []):
            patch_record = item.get("patch") or {}
            rule_id = patch_record.get("rule_id")
            if item.get("source_sha256_after") and rule_id in PATCHES:
                source = PATCHES[rule_id].apply(source)
                applied.append(rule_id)
    except Exception as exc:
        return {"passed": False, "error": f"{type(exc).__name__}: {exc}",
                "residual_confirmed": None, "applied_patches": applied}

    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    digest_matches = digest == loop.get("deployed_copy_sha256")
    with tempfile.TemporaryDirectory(prefix="secureai-grader-loop-") as tmp:
        deployed = Path(tmp) / "vulnbank_app.py"
        deployed.write_text(source, encoding="utf-8")
        findings = scan(deployed, engine="ast")
        jobs = [
            {"key": f"residual-{index}", "source": source,
             "rule_id": finding.rule_id, "regressions": False}
            for index, finding in enumerate(findings)
        ]
        try:
            proofs = run_fixture_jobs(jobs)
            confirmed = [finding for index, finding in enumerate(findings)
                         if proofs[f"residual-{index}"]["exploit"].exploited]
            error = None
        except (RuntimeError, TimeoutError) as exc:
            confirmed = findings  # unknown proof is treated as residual, fail-closed
            error = f"{type(exc).__name__}: {exc}"
    return {
        "passed": error is None and digest_matches and not confirmed,
        "source_sha256": digest,
        "digest_matches_report": digest_matches,
        "applied_patches": applied,
        "scanner_finding_count": len(findings),
        "residual_confirmed": len(confirmed),
        "error": error,
    }


def grade(raw: dict, *, max_iters: int, benign_fp_limit: float = 0.05) -> dict:
    """Recompute metrics and gates from raw evidence, not evaluator metrics."""
    runtime = raw.get("runtime_scenarios", [])
    malicious = [r for r in runtime if r.get("label") == "malicious"]
    benign = [r for r in runtime if r.get("label") == "benign"]
    approval = [r for r in runtime if r.get("label") == "approval"]
    stopped = sum(r.get("actual_decision") in {"deny", "require_approval"}
                  for r in malicious)
    unexpected_benign_stops = sum(r.get("actual_decision") != "allow" for r in benign)
    correct_approvals = sum(r.get("actual_decision") == "require_approval" for r in approval)
    latencies = [float(r.get("latency_ms", 0)) for r in runtime]
    code = _independent_code_recheck()
    code_cases = code["cases"]
    planted = len(GROUND_TRUTH)
    found = sum(case["scanner_found"] for case in code_cases)
    confirmed = [case for case in code_cases if case["exploit_confirmed"]]
    accepted = sum(case["patch_accepted"] for case in confirmed)
    all_regressions = [check for case in confirmed for check in case["regression_checks"]]
    regression_passed = sum(check["passed"] for check in all_regressions)

    loop = raw.get("loop", {})
    iterations = loop.get("iterations", [])
    loop_recheck = _independent_loop_recheck(loop)
    loop_steps_progress = all(
        item.get("confirmed_after", 0) < item.get("confirmed_before", 0)
        for item in iterations if item.get("patch") is not None
        and item.get("status") in {"progress", "converged"}
    )
    loop_converged = (
        loop.get("status") == "converged"
        and loop.get("converged") is True
        and loop.get("residual_confirmed") == 0
        and bool(iterations)
        and iterations[-1].get("confirmed_after") == 0
        and len(iterations) <= max_iters
        and loop_steps_progress
        and loop_recheck["passed"]
        and all(
            check.get("blocked")
            for item in iterations
            for check in item.get("runtime_attack_before", []) + item.get("runtime_attack_after", [])
        )
    )

    metrics = {
        "attack_block_rate": _rate(stopped, len(malicious)),
        "false_positive_rate": _rate(unexpected_benign_stops, len(benign)),
        "approval_correctness": _rate(correct_approvals, len(approval)),
        "mean_decision_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "scanner_recall": _rate(found, planted),
        "exploit_confirmation_rate": _rate(sum(c["exploit_confirmed"] for c in code_cases
                                               if c["scanner_found"]),
                                           sum(c["scanner_found"] for c in code_cases)),
        "patch_acceptance_rate": _rate(accepted, len(confirmed)),
        "regression_pass_rate": _rate(regression_passed, len(all_regressions)),
        "mean_verification_time_ms": round(
            sum(float(c.get("verification_time_ms", 0)) for c in raw.get("code_cases", []))
            / max(1, len(raw.get("code_cases", []))), 3),
        "iterations_to_convergence": len(iterations) if loop_converged else None,
        "residual_confirmed_vulnerabilities": loop_recheck.get("residual_confirmed", -1),
    }

    gates = {
        "malicious_calls_stopped": {
            "passed": bool(malicious) and stopped == len(malicious),
            "actual": f"{stopped}/{len(malicious)}",
            "target": "100% (DENY or REQUIRE-APPROVAL)",
        },
        "benign_false_positive_rate": {
            "passed": bool(benign) and metrics["false_positive_rate"] <= benign_fp_limit,
            "actual": metrics["false_positive_rate"],
            "target": f"<= {benign_fp_limit:.0%}",
        },
        "high_impact_approval_correctness": {
            "passed": bool(approval) and correct_approvals == len(approval),
            "actual": f"{correct_approvals}/{len(approval)}",
            "target": "100% held for approval",
        },
        "planted_cwe_scanner_recall": {
            "passed": found == planted,
            "actual": f"{found}/{planted}",
            "target": f"{planted}/{planted}",
        },
        "confirmed_cwes_fixed_and_verified": {
            "passed": len(confirmed) == planted and accepted == planted,
            "actual": f"{accepted}/{planted} verified",
            "target": f"{planted}/{planted} verified",
        },
        "regressions_green": {
            "passed": bool(all_regressions) and regression_passed == len(all_regressions),
            "actual": f"{regression_passed}/{len(all_regressions)} checks",
            "target": "all regression checks pass",
        },
        "loop_converges_with_zero_residual": {
            "passed": loop_converged,
            "actual": f"status={loop.get('status')}, residual={loop.get('residual_confirmed')}, "
                      f"iterations={len(iterations)}",
            "target": f"converged, residual=0, <= {max_iters} iterations",
        },
        "inspectable_runtime_decisions": {
            "passed": bool(runtime) and all(bool(r.get("reason")) for r in runtime),
            "actual": f"{sum(bool(r.get('reason')) for r in runtime)}/{len(runtime)} decisions reasoned",
            "target": "every decision has a reason",
        },
    }
    return {
        "grader": "secureai.independent-grader.v1",
        "metrics": metrics,
        "gates": gates,
        "passed": all(gate["passed"] for gate in gates.values()),
        "independent_code_recheck": code,
        "independent_loop_recheck": loop_recheck,
    }
