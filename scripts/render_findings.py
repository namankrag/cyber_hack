"""Render Semgrep JSON as PS-02-style finding cards (rule + CWE/OWASP + file:line).

Usage: python scripts/render_findings.py [semgrep.json]
Exit 0 always (this renders; the gate in semgrep_gate.ps1 decides pass/fail).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def render(path: str | Path = "semgrep.json") -> str:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data.get("results", [])
    lines = [f"# SAST findings: {len(results)}", ""]
    if data.get("errors"):
        lines.append(f"scan errors: {len(data['errors'])}")
        lines.append("")
    if not results:
        lines.append("Gate clean — no blocking findings.")
        return "\n".join(lines) + "\n"
    for r in results:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        start = r.get("start", {}) or {}
        cwe = meta.get("cwe") or meta.get("CWE") or "-"
        owasp = meta.get("owasp") or meta.get("OWASP") or "-"
        lines.append(f"## {r.get('check_id', 'unknown-rule')}")
        lines.append(f"- location: `{r.get('path')}:{start.get('line', '?')}`")
        lines.append(f"- severity: {extra.get('severity', '-')}")
        lines.append(f"- CWE: {cwe} | OWASP: {owasp}")
        lines.append(f"- message: {extra.get('message', '').strip()}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    print(render(args[0] if args else "semgrep.json"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
