"""Semgrep adapter — a real, industry-standard SAST engine as a 'find' source.

Mirrors how a production pipeline would run Semgrep with a local ruleset. It is
optional: if the `semgrep` binary isn't installed (or errors), the pipeline
falls back to the built-in AST scanner, so the tool stays self-contained.

Network checks and metrics are disabled so it runs fully offline.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .models import Finding, Severity

_RULES = Path(__file__).resolve().parent.parent / "semgrep_rules" / "rules.yaml"

_SEVERITY = {
    "sqli": Severity.CRITICAL, "cmdi": Severity.CRITICAL,
    "pathtrav": Severity.HIGH, "idor": Severity.HIGH, "xss": Severity.MEDIUM,
}
_RATIONALE = {
    "sqli": "Pre-auth data exposure / auth bypass; trivially exploitable.",
    "cmdi": "Arbitrary command execution on the host.",
    "pathtrav": "Reads arbitrary files outside the intended directory.",
    "idor": "Authenticated user can access other users' data.",
    "xss": "Reflected script executes in a victim's browser.",
}
_CWE = {"sqli": "CWE-89", "cmdi": "CWE-78", "pathtrav": "CWE-22",
        "idor": "CWE-639", "xss": "CWE-79"}
_TITLE = {
    "sqli": "SQL injection: user input in SQL string",
    "cmdi": "OS command injection: user input in shell command",
    "pathtrav": "Path traversal: user input in a filesystem path",
    "idor": "Broken access control: object returned without ownership check",
    "xss": "Reflected XSS: user input returned in HTML unescaped",
}


def available() -> bool:
    return shutil.which("semgrep") is not None and _RULES.exists()


def scan_file(path: str | Path, timeout: int = 120) -> list[Finding]:
    if not available():
        raise RuntimeError("semgrep not available")
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off")
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULES), "--json",
         "--metrics=off", "--disable-version-check", "--no-git-ignore",
         "--quiet", str(path)],
        capture_output=True, text=True, timeout=timeout, env=env,
    )
    if proc.returncode not in (0, 1):  # 1 = findings present
        raise RuntimeError(f"semgrep failed: {proc.stderr[:200]}")
    data = json.loads(proc.stdout or "{}")
    lines = Path(path).read_text().splitlines()

    findings: list[Finding] = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        rule_id = meta.get("rule_id") or r["check_id"].split(".")[-1]
        if rule_id not in _CWE:
            continue
        line = r["start"]["line"]
        snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        findings.append(Finding(
            rule_id=rule_id, cwe=_CWE[rule_id], title=_TITLE[rule_id],
            severity=_SEVERITY[rule_id], severity_rationale=_RATIONALE[rule_id],
            file=str(path), line=line, snippet=snippet,
            evidence=f"semgrep rule {r['check_id'].split('.')[-1]}",
        ))
    return findings
