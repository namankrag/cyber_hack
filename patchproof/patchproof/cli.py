"""PatchProof command-line interface.

    patchproof scan <file> [--engine ast|semgrep|both|auto]
    patchproof run  <file> [--engine ...] [--ai] [--provider gemini|groq]
                           [--report report.html]

`scan` lists findings. `run` executes the full find -> prove -> patch ->
prove-fixed pipeline and (optionally) writes an HTML/JSON report.
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table

from .config import load_dotenv

console = Console()


def _cmd_scan(args) -> int:
    from .scanner import scan
    findings = scan(args.file, engine=args.engine)
    t = Table(title=f"Findings — {args.file} (engine: {args.engine})",
              header_style="bold")
    for col in ("CWE", "Severity", "Rule", "Location", "Code"):
        t.add_column(col)
    for f in findings:
        t.add_row(f.cwe, f.severity.value.upper(), f.rule_id,
                  f"{f.file}:{f.line}", f.snippet[:50])
    console.print(t)
    console.print(f"[dim]{len(findings)} finding(s). Note: a finding is only "
                  f"acted on after an exploit confirms it — run `patchproof run`.[/]")
    return 0


def _cmd_run(args) -> int:
    load_dotenv()
    from .pipeline import run_pipeline
    from .report import write_html, write_json

    result = run_pipeline(args.file, engine=args.engine,
                          use_ai=args.ai, ai_provider=args.provider)

    console.print(f"[bold]PatchProof[/] — engine: [cyan]{result.engine}[/]   "
                  f"AI patching: [cyan]{'on' if result.ai_enabled else 'off'}[/]\n")
    t = Table(header_style="bold")
    for col in ("CWE", "Rule", "Confirmed", "Verdict", "Patch"):
        t.add_column(col)
    for i in result.issues:
        confirmed = "[green]yes[/]" if i.confirmed else "[dim]no[/]"
        style = "green" if (i.verification and i.verification.accepted) else "yellow"
        t.add_row(i.finding.cwe, i.finding.rule_id, confirmed,
                  f"[{style}]{i.status}[/]", i.patch_source)
    console.print(t)
    console.print(f"\n[bold]{result.fixed}/{result.confirmed}[/] confirmed issues "
                  f"fixed & verified"
                  + (f"  ([cyan]{result.ai_fixes}[/] by AI)" if result.ai_enabled else ""))

    if args.report:
        write_html(result, args.report)
        write_json(result, args.report.rsplit(".", 1)[0] + ".json")
        console.print(f"[dim]Report written: {args.report}[/]")
    return 0 if result.fixed == result.confirmed else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="patchproof",
                                     description="Find the flaw, prove the fix.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="list findings")
    ps.add_argument("file")
    ps.add_argument("--engine", default="auto",
                    choices=["ast", "semgrep", "both", "auto"])
    ps.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("run", help="full find->prove->patch->prove-fixed pipeline")
    pr.add_argument("file")
    pr.add_argument("--engine", default="auto",
                    choices=["ast", "semgrep", "both", "auto"])
    pr.add_argument("--ai", action="store_true", help="try AI-generated patches")
    pr.add_argument("--provider", default=None, choices=["gemini", "groq"])
    pr.add_argument("--report", default=None, help="write HTML report to this path")
    pr.set_defaults(func=_cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
