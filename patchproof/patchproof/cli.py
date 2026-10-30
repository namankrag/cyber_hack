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
    from .report import write_html, write_json, write_sarif

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
    if args.sarif:
        write_sarif(result, args.sarif)
        console.print(f"[dim]SARIF written: {args.sarif}[/]")
    return 0 if result.fixed == result.confirmed else 1


def _cmd_sarif(args) -> int:
    """Run the pipeline and emit SARIF 2.1.0 for the PR gate.

    Exit 0 only if every confirmed finding is FIXED & VERIFIED (the CI gate
    contract); otherwise exit 1. With --check, validate an existing SARIF
    file's shape instead of running the pipeline.
    """
    from .report import validate_sarif, write_html, write_json, write_sarif

    if args.check:
        import json as _json
        with open(args.check, encoding="utf-8") as handle:
            doc = _json.load(handle)
        errors = validate_sarif(doc)
        if errors:
            console.print("[red]SARIF invalid:[/]")
            for err in errors:
                console.print(f"  - {err}")
            return 1
        console.print("[green]SARIF shape ok[/] "
                      f"({len(doc['runs'][0]['results'])} result(s))")
        return 0

    if not args.file and not args.check:
        console.print("[red]patchproof sarif needs a target file "
                      "(or --check SARIF_FILE to validate)[/]")
        return 2

    load_dotenv()
    from .pipeline import run_pipeline

    result = run_pipeline(args.file, engine=args.engine,
                          use_ai=args.ai, ai_provider=args.provider)
    write_sarif(result, args.output)
    if args.report:
        write_html(result, args.report)
        write_json(result, args.report.rsplit(".", 1)[0] + ".json")

    gate_ok = result.fixed == result.confirmed
    color = "green" if gate_ok else "red"
    console.print(f"[bold]PatchProof SARIF[/] - {result.confirmed} confirmed, "
                  f"{result.fixed} fixed & verified -> "
                  f"[{color}]{'GATE PASS' if gate_ok else 'GATE FAIL'}[/]")
    console.print(f"[dim]SARIF written: {args.output}[/]")
    return 0 if gate_ok else 1


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
    pr.add_argument("--sarif", default=None,
                    help="also write a SARIF 2.1.0 log to this path")
    pr.set_defaults(func=_cmd_run)

    psarif = sub.add_parser("sarif", help="run pipeline, emit SARIF 2.1.0, gate on FIXED & VERIFIED")
    psarif.add_argument("file", nargs="?", default=None)
    psarif.add_argument("--engine", default="auto",
                        choices=["ast", "semgrep", "both", "auto"])
    psarif.add_argument("--ai", action="store_true", help="try AI-generated patches")
    psarif.add_argument("--provider", default=None, choices=["gemini", "groq"])
    psarif.add_argument("--output", default="report.sarif",
                        help="SARIF output path (default: report.sarif)")
    psarif.add_argument("--report", default=None,
                        help="optionally also write an HTML report to this path")
    psarif.add_argument("--check", default=None, metavar="SARIF_FILE",
                        help="validate a SARIF file's shape instead of running")
    psarif.set_defaults(func=_cmd_sarif)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
