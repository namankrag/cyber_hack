"""PatchProof end-to-end demo.

Run from the project root:   python -m examples.run_demo
Scans the vulnerable app, proves each finding with a live exploit, patches it,
and proves the fix holds without breaking the app — then writes report.html.
"""
from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from patchproof.config import load_dotenv
from patchproof.pipeline import run_pipeline
from patchproof.report import write_html, write_json

console = Console()
TARGET = "vulnbank/app.py"
load_dotenv()
# Use AI patches automatically if a key is present; otherwise curated patches.
USE_AI = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GROQ_API_KEY"))

_STATUS_STYLE = {
    "FIXED & VERIFIED": "bold green",
    "PATCH BREAKS APP": "bold yellow",
    "PATCH INEFFECTIVE": "bold red",
    "ERROR": "bold red",
}


def main() -> None:
    console.rule("[bold]PatchProof — find the flaw, prove the fix[/]")
    console.print(f"Target (in-scope): [cyan]{TARGET}[/]   "
                  f"AI patching: [cyan]{'ON' if USE_AI else 'off (no key)'}[/]\n")

    result = run_pipeline(TARGET, engine="auto", use_ai=USE_AI)
    console.print(f"[dim]scan engine: {result.engine}[/]\n")

    for it in result.issues:
        f = it.finding
        style = _STATUS_STYLE.get(it.status, "white")
        body = Table.grid(padding=(0, 1))
        body.add_column(justify="right", style="dim")
        body.add_column()
        body.add_row("cwe / severity", f"[bold]{f.cwe}[/]  ·  {f.severity.value.upper()}")
        body.add_row("location", f"{f.file}:{f.line}")
        body.add_row("code", f"[dim]{f.snippet}[/]")
        body.add_row("1 · FIND", "scanner flagged a dangerous pattern")
        verdict = "✓ exploit succeeded — finding is REAL" if it.confirmed \
            else "exploit failed — treated as false positive, dropped"
        body.add_row("2 · PROVE", verdict)
        body.add_row("", f"[dim]{it.exploit_evidence}[/]")
        if it.verification:
            v = it.verification
            body.add_row("3 · PATCH", "minimal fix applied to an isolated copy")
            reg = f"{sum(c.passed for c in v.regression_after)}/{len(v.regression_after)}"
            blocked = "✓ blocked" if not v.patched_exploited else "✗ still works"
            body.add_row("4 · PROVE-FIXED",
                         f"exploit now: [bold]{blocked}[/]   "
                         f"regression: [bold]{reg} passing[/]")
            body.add_row("patch source", it.patch_source)
        body.add_row("verdict", f"[{style}]{it.status}[/]")
        console.print(Panel(body, title=f"{f.rule_id.upper()} — {f.title}",
                            border_style=style.split()[-1]))
        console.print()

    # Summary
    t = Table(title="Summary", header_style="bold")
    t.add_column("Metric"); t.add_column("Value", justify="right")
    t.add_row("Findings", str(len(result.issues)))
    t.add_row("Confirmed by exploit", str(result.confirmed))
    t.add_row("Fixed & verified", f"[green]{result.fixed}[/]")
    if result.ai_enabled:
        t.add_row("…of which AI-generated", f"[cyan]{result.ai_fixes}[/]")
    console.print(t)

    write_html(result, "report.html")
    write_json(result, "report.json")
    console.print("\n[bold]Reports written:[/] report.html, report.json")
    console.print("[dim]The vulnerable source was left untouched; patches were "
                  "verified on isolated copies.[/]")


if __name__ == "__main__":
    main()
