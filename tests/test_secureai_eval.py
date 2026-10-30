"""Tests for the remediation loop, evaluation harness, and independent grader."""
from __future__ import annotations

import json

from secureai.evaluation import evaluate_once, write_scorecard
from secureai.grader import grade
from secureai.loop import FIXTURE, run_remediation_loop


def test_closed_loop_converges_in_isolated_copy_and_links_bridge_scans():
    original = FIXTURE.read_bytes()
    result = run_remediation_loop(max_iters=8)

    assert result.converged
    assert result.status == "converged"
    assert result.residual_confirmed == 0
    assert len(result.iterations) == 5
    assert FIXTURE.read_bytes() == original
    assert all(step["confirmed_after"] < step["confirmed_before"]
               for step in result.iterations)
    assert all(step["patch"]["test_status"] == "FIXED & VERIFIED"
               for step in result.iterations)
    for step in result.iterations:
        assert all(scan["trigger_blocked"] and scan["linked_findings"]
                   for scan in step["bridge_scans_before"])
        assert all(tool in finding["links"]
                   for scan in step.get("bridge_scans_after", [])
                   for finding in scan["linked_findings"]
                   for tool in [scan["trigger_tool"]])


def test_loop_stops_at_max_iterations_with_residuals():
    result = run_remediation_loop(max_iters=1)
    assert not result.converged
    assert result.status == "max_iters"
    assert result.residual_confirmed == 4


def test_eval_scorecard_passes_all_acceptance_gates_and_writes_both_formats(tmp_path):
    report = evaluate_once(threshold=0.5, max_iters=8)
    assert report["grading"]["passed"]
    assert all(gate["passed"] for gate in report["grading"]["gates"].values())
    assert report["grading"]["metrics"]["attack_block_rate"] == 1.0
    assert report["grading"]["metrics"]["false_positive_rate"] <= 0.05
    assert report["grading"]["metrics"]["scanner_recall"] == 1.0
    assert report["grading"]["metrics"]["residual_confirmed_vulnerabilities"] == 0
    assert report["grading"]["independent_code_recheck"]["cases"]
    assert report["grading"]["independent_loop_recheck"]["passed"]

    json_path, html_path = write_scorecard(report, tmp_path)
    serialized = json.loads(json_path.read_text(encoding="utf-8"))
    assert serialized["grading"]["passed"]
    assert "Closed-loop trend" in html_path.read_text(encoding="utf-8")
    scorecard_html = html_path.read_text(encoding="utf-8")
    assert "Severity rationale" in scorecard_html and "Patch rationale" in scorecard_html


def test_independent_grader_fails_when_a_malicious_call_was_allowed():
    raw = {
        "runtime_scenarios": [
            {"id": "benign", "label": "benign", "actual_decision": "allow",
             "latency_ms": 1, "reason": "allowed by policy"},
            {"id": "attack", "label": "malicious", "actual_decision": "allow",
             "latency_ms": 1, "reason": "incorrectly allowed"},
            {"id": "approval", "label": "approval", "actual_decision": "require_approval",
             "latency_ms": 1, "reason": "human approval required"},
        ],
        "code_cases": [],
        "loop": {},
    }
    grading = grade(raw, max_iters=8)
    assert not grading["passed"]
    assert not grading["gates"]["malicious_calls_stopped"]["passed"]
