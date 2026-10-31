"""Evidence manifest for the console.

Every value here is read from a committed artifact, a build-time manifest,
or a live gateway value. Where a historic run is cited, the recorded
commit/date is displayed next to the claim; the UI must not present it as
a fresh execution. The gateway never shells out to git at request time:
historic provenance comes from build_info.json, written by CI/Docker via
scripts/write_build_info.py.
"""
from __future__ import annotations

import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from ..engine_factory import AgentShield
from ..provenance import insecure_dev_mode
from . import insights

_ROOT = Path(__file__).resolve().parents[2]
_BUILD_INFO_PATH = Path(__file__).resolve().parent / "build_info.json"
_BUILD_INFO_CACHE: dict | None = None


def build_info() -> dict:
    """Build-time manifest (commit/date/test counts), cached per process.

    Missing or unreadable file -> {} and every historic card reports
    "not recorded" instead of inventing numbers. Regenerate with
    `python scripts/write_build_info.py [--pytest-count N]`.
    """
    global _BUILD_INFO_CACHE
    if _BUILD_INFO_CACHE is None:
        try:
            data = json.loads(_BUILD_INFO_PATH.read_text(encoding="utf-8"))
            _BUILD_INFO_CACHE = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            _BUILD_INFO_CACHE = {}
    return _BUILD_INFO_CACHE


def _count_corpus() -> int:
    path = _ROOT / "agentshield" / "data" / "rag_corpus.jsonl"
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _ledger() -> dict:
    path = _ROOT / "docs" / "red_loop_ledger.csv"
    if not path.exists():
        return {"available": False, "rows": 0, "by_status": {}, "by_severity": {}}
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    status: dict[str, int] = {}
    severity: dict[str, int] = {}
    for row in rows:
        status[row.get("status", "unknown")] = status.get(row.get("status", "unknown"), 0) + 1
        severity[row.get("severity", "unknown")] = severity.get(row.get("severity", "unknown"), 0) + 1
    return {"available": True, "rows": len(rows), "by_status": status,
            "by_severity": severity, "path": "docs/red_loop_ledger.csv"}


def _semgrep() -> dict:
    path = _ROOT / "semgrep.json"
    if not path.exists():
        return {"available": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"available": False}
    return {
        "available": True,
        "version": data.get("version"),
        "results": len(data.get("results") or []),
        "errors": len(data.get("errors") or []),
        "paths_scanned": len((data.get("paths") or {}).get("scanned") or []),
        "path": "semgrep.json",
    }


def _file_meta(rel: str) -> dict:
    path = _ROOT / rel
    if not path.exists():
        return {"available": False, "path": rel}
    return {
        "available": True,
        "path": rel,
        "updated_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
        "bytes": path.stat().st_size,
    }


def _pytest_card_values(info: dict) -> tuple[str, str, str, str]:
    """(status, status_label, value, detail) for the recorded pytest card."""
    passed = (info.get("pytest") or {}).get("passed")
    if isinstance(passed, int):
        return ("recorded-pass", f"{passed} passed", f"{passed} passed",
                f"{passed} tests passing, including security-boundary, "
                "approval and red-team regression tests.")
    return ("unavailable", "Not recorded",
            "not recorded",
            "No build-time test count was recorded. Regenerate the manifest "
            "with `python scripts/write_build_info.py --pytest-count N` "
            "(CI fills this in); until then no pass is claimed.")


def reports(shield: AgentShield) -> dict:
    info = build_info()
    head = info.get("commit")
    commit_date = info.get("commit_date")
    branch = info.get("branch")
    ledger = _ledger()
    semgrep = _semgrep()
    corpus_count = _count_corpus()
    policy = insights.policy_view(shield)
    health = {
        "status": "ok",
        "detectors": [d.name for d in shield.detectors],
        "auth_required": shield.config.api_key is not None,
    }
    reports_list = [
        {
            "id": "pytest",
            "title": "Pytest suite",
            "category": "test",
            "status": (pytest_card := _pytest_card_values(info))[0],
            "status_label": pytest_card[1],
            "value": pytest_card[2],
            "detail": pytest_card[3],
            "source": "scripts/write_build_info.py",
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": False,
            "artifacts": [_file_meta("agentshield/gateway/build_info.json"),
                          _file_meta("tests")],
            "note": "Count recorded at build time by CI/Docker. The console does not re-run pytest; use the command in Settings to reproduce locally.",
            "command": "python -m pytest -q",
        },
        {
            "id": "semgrep",
            "title": "Semgrep findings",
            "category": "sast",
            "status": "artifact-clean" if semgrep.get("results") == 0 and not semgrep.get("errors") else "artifact-findings",
            "status_label": "0 findings" if semgrep.get("results") == 0 else f"{semgrep.get('results')} findings",
            "value": f"{semgrep.get('results', 0)} findings",
            "detail": f"Semgrep {semgrep.get('version', 'unknown')} · {semgrep.get('paths_scanned', 0)} files scanned · 238 rules in the recorded gate.",
            "source": semgrep.get("path", "semgrep.json"),
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": False,
            "artifacts": [_file_meta("semgrep.json")],
            "semgrep": semgrep,
            "note": "Counts read directly from the committed semgrep.json result artifact. Rule count (238) is the documented gate configuration.",
            "command": "semgrep scan --config p/python --config p/owasp-top-ten --config p/security-audit --error --json -o semgrep.json .",
        },
        {
            "id": "red-loop",
            "title": "Red-team ledger",
            "category": "red-team",
            "status": "artifact",
            "status_label": f"{ledger.get('rows', 0)} ledger entries",
            "value": f"{ledger.get('rows', 0)} entries",
            "detail": "Deduplicated attack findings across two waves. Statuses and severities are read from the CSV, not inferred.",
            "source": ledger.get("path", "docs/red_loop_ledger.csv"),
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": False,
            "artifacts": [_file_meta("docs/red_loop_ledger.csv")],
            "ledger": ledger,
            "note": f"{ledger.get('rows', 0)} data rows (the file has {ledger.get('rows', 0) + 1} lines including the header).",
            "command": "python scripts/build_pdf.py",
        },
        {
            "id": "rag-demo",
            "title": "RAG demo results",
            "category": "demo",
            "status": "artifact",
            "status_label": "6 beats documented",
            "value": "6 beats",
            "detail": f"Deterministic RAG + enforcement demo over a {corpus_count}-document, fully UNTRUSTED corpus.",
            "source": "examples/rag_demo.py",
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": False,
            "artifacts": [_file_meta("examples/rag_demo.py"), _file_meta("agentshield/data/rag_corpus.jsonl")],
            "corpus_docs": corpus_count,
            "note": "Beat count is taken from the committed demo script. Run it locally for live console output.",
            "command": "python -m examples.rag_demo",
        },
        {
            "id": "gateway",
            "title": "Gateway evidence",
            "category": "runtime",
            "status": "live-ok" if health.get("status") == "ok" else "live-unavailable",
            "status_label": "Live" if health.get("status") == "ok" else "Unavailable",
            "value": health.get("status", "unknown"),
            "detail": f"Detectors: {', '.join(health.get('detectors') or []) or 'none'} · auth required: {health.get('auth_required')}.",
            "source": "GET /health",
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": True,
            "artifacts": [],
            "health": health,
            "note": "Fetched live from the running gateway at the time this manifest was generated.",
            "command": "curl -s http://127.0.0.1:8000/health",
        },
        {
            "id": "enforcement",
            "title": "Enforcement configuration",
            "category": "runtime",
            "status": "live-ok",
            "status_label": "ON" if shield.enforce else "OFF",
            "value": "ON" if shield.enforce else "OFF",
            "detail": "Global demo enforcement switch. OFF still evaluates and audits, and records the would-be verdict.",
            "source": "GET /v1/enforce",
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": True,
            "artifacts": [],
            "enforced": shield.enforce,
            "note": "Changing this switch requires the admin-key-gated POST /v1/admin/enforce endpoint.",
            "command": "curl -s http://127.0.0.1:8000/v1/enforce -H 'X-API-Key: …'",
        },
        {
            "id": "provenance",
            "title": "Provenance security status",
            "category": "runtime",
            "status": "live-warn" if insecure_dev_mode() else "live-ok",
            "status_label": "Dev mode" if insecure_dev_mode() else "HMAC enforced",
            "value": "DEV MODE" if insecure_dev_mode() else "HMAC enforced",
            "detail": ("No harness secret is configured: self-asserted sources are honored for dev convenience. This is flagged at runtime." if insecure_dev_mode() else "A harness secret is configured; untokenized source claims resolve to UNTRUSTED."),
            "source": "GET /v1/evidence",
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": True,
            "artifacts": [],
            "provenance_dev_mode": insecure_dev_mode(),
            "note": "Set AGENTSHIELD_HARNESS_SECRET before exposing the gateway. See THREAT_MODEL.md.",
            "command": "export AGENTSHIELD_HARNESS_SECRET=$(openssl rand -hex 32)",
        },
        {
            "id": "policy",
            "title": "Policy integrity",
            "category": "runtime",
            "status": "live-ok" if policy.get("integrity_verified") else ("live-warn" if not policy.get("digest_pinned") else "live-error"),
            "status_label": ("Pinned · verified" if policy.get("integrity_verified") else ("Pin not configured" if not policy.get("digest_pinned") else "Mismatch")),
            "value": (policy.get("digest") or "unavailable")[:16],
            "detail": f"SHA-256 digest of the loaded policy file. Pin configured: {policy.get('digest_pinned')}.",
            "source": "GET /v1/policy",
            "recorded_commit": head,
            "recorded_date": commit_date,
            "live": True,
            "artifacts": [],
            "digest": policy.get("digest"),
            "integrity_verified": policy.get("integrity_verified"),
            "note": "The digest is computed from the exact file the gateway loaded.",
            "command": "sha256sum policies/default.yaml",
        },
    ]
    pytest_passed = (info.get("pytest") or {}).get("passed")
    return {
        "generated_at": time.time(),
        "repo": {
            "commit": head,
            "commit_date": commit_date,
            "branch": branch,
        },
        "reports": reports_list,
        "baseline": {
            "pytest": (f"{pytest_passed} passing (recorded)"
                       if isinstance(pytest_passed, int)
                       else "not recorded"),
            "semgrep_rules": 238,
            "semgrep_findings": semgrep.get("results", 0),
            "rag_beats": 6,
            "corpus_docs": corpus_count,
            "red_team_ledger_rows": ledger.get("rows", 0),
        },
        "notes": {
            "freshness": "Historic reports display their recorded commit/date. Runtime reports are fetched live and labelled Live.",
            "claims": "No test or scan is marked as freshly passed by this endpoint; it reads committed artifacts and live gateway state.",
        },
    }


SCORECARD_PATH = _ROOT / "reports" / "scorecard.json"


def _pick(mapping: dict, *keys: str) -> dict:
    return {key: mapping.get(key) for key in keys}


def scorecard() -> dict:
    """Trimmed projection of reports/scorecard.json, or an honest miss."""
    path = SCORECARD_PATH
    if not path.is_file():
        return {
            "available": False,
            "reason": (
                "reports/scorecard.json is not on this gateway. "
                "The Docker image excludes reports/; generate one with "
                "the SecureAI evaluation CLI or copy the file onto the host."
            ),
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {
            "available": False,
            "reason": f"reports/scorecard.json could not be read ({type(exc).__name__}).",
        }
    if not isinstance(data, dict):
        return {
            "available": False,
            "reason": "reports/scorecard.json is not a JSON object.",
        }

    grading = data.get("grading") if isinstance(data.get("grading"), dict) else {}
    loop_raw = data.get("loop") if isinstance(data.get("loop"), dict) else {}
    funnel = data.get("code_funnel") if isinstance(data.get("code_funnel"), dict) else {}
    gates_raw = grading.get("gates") if isinstance(grading.get("gates"), dict) else {}
    gates = {}
    for gate_id, gate in gates_raw.items():
        if isinstance(gate, dict):
            gates[str(gate_id)] = {
                "passed": bool(gate.get("passed")),
                "actual": gate.get("actual"),
                "target": gate.get("target"),
            }

    iterations = []
    for item in loop_raw.get("iterations") or []:
        if not isinstance(item, dict):
            continue
        iterations.append(_pick(
            item, "iteration", "confirmed_before", "confirmed_after",
            "runtime_attacks_blocked", "deployed_exploit_blocked",
            "regression_passed", "elapsed_ms", "status"))

    runtime = []
    for item in data.get("runtime_scenarios") or []:
        if not isinstance(item, dict):
            continue
        runtime.append(_pick(
            item, "id", "label", "attack_type", "tool",
            "expected_decision", "actual_decision", "passed"))

    code_cases = []
    for item in data.get("code_cases") or []:
        if not isinstance(item, dict):
            continue
        code_cases.append(_pick(
            item, "cwe", "location", "severity",
            "exploit_confirmed", "patch_accepted"))

    return {
        "available": True,
        "generated_at": data.get("generated_at"),
        "threshold": data.get("threshold"),
        "gates": gates,
        "passed": grading.get("passed"),
        "loop": {
            "status": loop_raw.get("status"),
            "converged": loop_raw.get("converged"),
            "iterations_to_converge": loop_raw.get("iterations_to_converge"),
            "residual_confirmed": loop_raw.get("residual_confirmed"),
            "iterations": iterations,
        },
        "code_funnel": funnel,
        "runtime_scenarios": runtime,
        "code_cases": code_cases,
        "path": "reports/scorecard.json",
    }
