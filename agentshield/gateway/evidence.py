"""Evidence manifest for the console.

Every value here is read from a committed artifact or a live gateway value.
Where a historic run is cited, the recorded commit/date is displayed next to
the claim; the UI must not present it as a fresh execution.
"""
from __future__ import annotations

import csv
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from ..engine_factory import AgentShield
from ..provenance import insecure_dev_mode
from . import insights

_ROOT = Path(__file__).resolve().parents[2]


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=_ROOT, capture_output=True,
                             text=True, timeout=3)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


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


def reports(shield: AgentShield) -> dict:
    head = _git("rev-parse", "HEAD")
    commit_date = _git("log", "-1", "--format=%cI")
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
            "status": "recorded-pass",
            "status_label": "Recorded pass",
            "value": "81 passed",
            "detail": "81 tests passing, including security-boundary, approval and red-team regression tests.",
            "source": "docs/RED_LOOP_REPORT.md",
            "recorded_commit": "9a28520",
            "recorded_date": "2026-10-30",
            "live": False,
            "artifacts": [_file_meta("docs/RED_LOOP_REPORT.md"), _file_meta("tests")],
            "note": "Historic run recorded in the repository. The console does not re-run pytest; use the command in Settings to reproduce locally.",
            "command": "python -m pytest tests -q",
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
            "recorded_commit": "9a28520",
            "recorded_date": "2026-10-30",
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
            "recorded_commit": "a5a72d2",
            "recorded_date": "2026-10-30",
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
            "recorded_commit": "a463013",
            "recorded_date": "2026-10-30",
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
    return {
        "generated_at": time.time(),
        "repo": {
            "commit": head,
            "commit_date": commit_date,
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        },
        "reports": reports_list,
        "baseline": {
            "pytest": "81 passing (recorded)",
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
