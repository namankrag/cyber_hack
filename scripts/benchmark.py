"""Benchmark harness (PS-01 item 2): OFF-vs-ON enforcement scorecard.

Runs every case in ``bench/cases.jsonl`` through the REAL enforcement path
(in-process ``AgentShield.check``) twice — once with enforcement ON and once
with enforcement OFF (demo bypass) — and reports:

* attack success rate (malicious cases that were ALLOWED) OFF vs ON
* false-positive rate (benign cases DENIED) and false-hold rate (benign HELD)
* approval correctness (legitimate high-impact cases HELD)
* p50/p95/p99 decision latency (ms) with enforcement ON

Results go to ``bench/results_<UTC-timestamp>.json`` and a Markdown table is
printed to stdout. Exit code is nonzero ONLY when the harness itself errors
(bad cases file, enforcement crash, unwritable output); detector misses are
reported as honest numbers, never as failures.

Keyless heuristic path only (``detectors=["heuristic"]``); synthetic data.

Usage (from repo root)::

    .\\.venv\\Scripts\\python.exe scripts/benchmark.py [--cases bench/cases.jsonl]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agentshield.config import Config
from agentshield.engine_factory import AgentShield
from agentshield.models import ToolCall, TrustLevel

LABELS = {"benign", "malicious", "approval"}
ATTACK_TYPES = {
    "none", "direct_injection", "indirect_injection", "exfil",
    "permission_escalation", "encoded", "obfuscated",
    "i18n-hi", "i18n-kn", "i18n-ta", "i18n-te", "legitimate_high_impact",
}
DECISIONS = {"allow", "deny", "require_approval"}
REQUIRED_FIELDS = {"id", "label", "attack_type", "tool", "source",
                   "arguments", "context", "expected_decision"}


def load_cases(path: Path) -> list[dict]:
    """Parse and strictly validate the cases file (a harness error if bad)."""
    if not path.exists():
        raise FileNotFoundError(f"cases file not found: {path}")
    cases: list[dict] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}")
            missing = REQUIRED_FIELDS - set(case)
            if missing:
                raise ValueError(f"{path}:{lineno}: missing fields {sorted(missing)}")
            if case["id"] in seen:
                raise ValueError(f"{path}:{lineno}: duplicate id {case['id']!r}")
            seen.add(case["id"])
            if case["label"] not in LABELS:
                raise ValueError(f"{path}:{lineno}: bad label {case['label']!r}")
            if case["attack_type"] not in ATTACK_TYPES:
                raise ValueError(f"{path}:{lineno}: bad attack_type {case['attack_type']!r}")
            if case["expected_decision"] not in DECISIONS:
                raise ValueError(f"{path}:{lineno}: bad expected_decision "
                                 f"{case['expected_decision']!r}")
            try:
                TrustLevel(case["source"])
            except ValueError:
                raise ValueError(f"{path}:{lineno}: bad source {case['source']!r}")
            if not isinstance(case["arguments"], dict) or not isinstance(case["context"], str):
                raise ValueError(f"{path}:{lineno}: arguments must be an object, "
                                 f"context a string")
            cases.append(case)
    if not cases:
        raise ValueError(f"{path}: no cases found")
    return cases


def percentile(sorted_vals: list[float], pct: float) -> float:
    """Nearest-rank percentile over an already-sorted list."""
    if not sorted_vals:
        return 0.0
    rank = max(1, min(len(sorted_vals), math.ceil(pct / 100.0 * len(sorted_vals))))
    return sorted_vals[rank - 1]


def make_shield(enforce: bool, audit_path: str) -> AgentShield:
    """One AgentShield runtime on the keyless heuristic path."""
    policy = REPO_ROOT / "policies" / "default.yaml"
    config = Config(detectors=["heuristic"], policy_path=str(policy),
                    audit_path=audit_path)
    return AgentShield(config=config, enforce=enforce)


def run_case(shield: AgentShield, case: dict) -> tuple[str, float]:
    """Evaluate one case through shield.check; return (decision, latency_ms)."""
    call = ToolCall(
        tool_name=case["tool"],
        arguments=dict(case["arguments"]),
        source=TrustLevel(case["source"]),
        context=case["context"],
        metadata={"bench_case": case["id"]},
    )
    start = time.perf_counter()
    result = shield.check(call)
    latency_ms = (time.perf_counter() - start) * 1000.0
    return result.decision.value, latency_ms


def summarize(cases: list[dict], rows: list[dict]) -> dict:
    """Aggregate OFF-vs-ON numbers from per-case rows."""
    by_id = {r["id"]: r for r in rows}
    mal = [c for c in cases if c["label"] == "malicious"]
    ben = [c for c in cases if c["label"] == "benign"]
    appr = [c for c in cases if c["label"] == "approval"]

    def rate(sub: list[dict], pred) -> float | None:
        if not sub:
            return None
        return round(sum(1 for c in sub if pred(by_id[c["id"]])) / len(sub), 4)

    lat_on = sorted(r["latency_ms_on"] for r in rows)
    lat_off = sorted(r["latency_ms_off"] for r in rows)
    return {
        "n_total": len(cases),
        "n_malicious": len(mal),
        "n_benign": len(ben),
        "n_approval": len(appr),
        "attack_success_off": rate(mal, lambda r: r["actual_off"] == "allow"),
        "attack_success_on": rate(mal, lambda r: r["actual_on"] == "allow"),
        "attack_held_on": rate(mal, lambda r: r["actual_on"] == "require_approval"),
        "attack_denied_on": rate(mal, lambda r: r["actual_on"] == "deny"),
        "false_positive_rate_benign": rate(ben, lambda r: r["actual_on"] == "deny"),
        "false_hold_rate_benign": rate(ben, lambda r: r["actual_on"] == "require_approval"),
        "approval_correctness": rate(appr, lambda r: r["actual_on"] == "require_approval"),
        "expected_match_rate_on": rate(cases, lambda r: r["match_on"]),
        "latency_ms_on": {
            "p50": round(percentile(lat_on, 50), 3),
            "p95": round(percentile(lat_on, 95), 3),
            "p99": round(percentile(lat_on, 99), 3),
        },
        "latency_ms_off": {
            "p50": round(percentile(lat_off, 50), 3),
            "p95": round(percentile(lat_off, 95), 3),
            "p99": round(percentile(lat_off, 99), 3),
        },
    }


def markdown_table(summary: dict) -> str:
    """Render the scorecard as a Markdown table for stdout."""
    lat = summary["latency_ms_on"]

    def pct(v) -> str:
        return "n/a" if v is None else f"{v * 100:.1f}%"

    lines = [
        "| metric | OFF (bypass) | ON (enforced) |",
        "|---|---|---|",
        f"| attack success (malicious allowed) | {pct(summary['attack_success_off'])} "
        f"| {pct(summary['attack_success_on'])} |",
        f"| attack held for approval | — | {pct(summary['attack_held_on'])} |",
        f"| attack denied | — | {pct(summary['attack_denied_on'])} |",
        f"| false positives (benign denied) | — | {pct(summary['false_positive_rate_benign'])} |",
        f"| false holds (benign held) | — | {pct(summary['false_hold_rate_benign'])} |",
        f"| approval correctness (high-impact held) | — | {pct(summary['approval_correctness'])} |",
        f"| expected-decision match | — | {pct(summary['expected_match_rate_on'])} |",
        f"| decision latency p50 / p95 / p99 (ms, ON) | — | "
        f"{lat['p50']} / {lat['p95']} / {lat['p99']} |",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentShield OFF-vs-ON benchmark")
    parser.add_argument("--cases", default=str(REPO_ROOT / "bench" / "cases.jsonl"))
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "bench"))
    args = parser.parse_args()

    try:
        cases = load_cases(Path(args.cases))
        # Benchmark audit records go to throwaway temp files so the repo's
        # audit.log.jsonl is never polluted by the harness.
        fd_on, audit_on = tempfile.mkstemp(prefix="bench-on-", suffix=".jsonl")
        fd_off, audit_off = tempfile.mkstemp(prefix="bench-off-", suffix=".jsonl")
        os.close(fd_on)
        os.close(fd_off)
        try:
            shield_on = make_shield(enforce=True, audit_path=audit_on)
            shield_off = make_shield(enforce=False, audit_path=audit_off)
            rows: list[dict] = []
            for case in cases:
                actual_on, lat_on = run_case(shield_on, case)
                actual_off, lat_off = run_case(shield_off, case)
                rows.append({
                    "id": case["id"],
                    "label": case["label"],
                    "attack_type": case["attack_type"],
                    "tool": case["tool"],
                    "source": case["source"],
                    "expected": case["expected_decision"],
                    "actual_on": actual_on,
                    "actual_off": actual_off,
                    "latency_ms_on": round(lat_on, 3),
                    "latency_ms_off": round(lat_off, 3),
                    "match_on": actual_on == case["expected_decision"],
                })
        finally:
            for p in (audit_on, audit_off):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        summary = summarize(cases, rows)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = Path(args.out_dir) / f"results_{stamp}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at_utc": stamp,
            "tool": "scripts/benchmark.py",
            "n_cases": len(cases),
            "config": {"detectors": ["heuristic"], "enforce": "off_vs_on",
                       "synthetic": True, "keyless": True},
            "summary": summary,
            "cases": rows,
        }
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        print(f"# AgentShield benchmark — {summary['n_total']} cases "
              f"({summary['n_malicious']} malicious / {summary['n_benign']} benign / "
              f"{summary['n_approval']} approval)")
        print(f"# results: {out_path.name}")
        print(markdown_table(summary))
        mismatches = [r for r in rows if not r["match_on"]]
        if mismatches:
            print(f"\n# {len(mismatches)} case(s) differ from expected_decision "
                  f"(honest misses, exit still 0):")
            for r in mismatches[:20]:
                print(f"#   {r['id']} ({r['attack_type']}): expected={r['expected']} "
                      f"actual_on={r['actual_on']}")
            if len(mismatches) > 20:
                print(f"#   ... and {len(mismatches) - 20} more (see {out_path.name})")
        return 0
    except Exception as exc:  # harness error only: nonzero exit
        print(f"benchmark harness error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
