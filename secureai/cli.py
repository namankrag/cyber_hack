"""SecureAI platform CLI.

    secureai platform [--report dash.html] [--engine ...] [--ai]
        Run both layers + the bridge, render the unified dashboard.
    secureai runtime
        Run the AgentShield runtime scenarios only.
    secureai harden [tools...] [--engine ...] [--ai]
        Harden the implementations of governed tools (PatchProof).
    secureai loop [--max-iters N] [--report PATH]
        Run the closed, isolated remediation loop.
    secureai eval [--once | --tune] [--max-iters N] [--out-dir DIR]
        Evaluate the labeled synthetic dataset and write scorecard.json/html.
    secureai watch [--interval SECONDS] [--out-dir DIR]
        Re-run evaluation when the bundled tool fixture changes.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import time

from rich.console import Console
from rich.table import Table

console = Console()

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
              "low": "blue", "info": "dim"}
_STATUS_STYLE = {"blocked": "bold red", "held": "yellow", "allowed": "green",
                 "fixed": "bold green", "rejected": "yellow", "unconfirmed": "dim"}


def _print_events(events, title):
    t = Table(title=title, header_style="bold")
    for col in ("Layer", "Status", "Severity", "What", "Ref"):
        t.add_column(col)
    for e in events:
        t.add_row(e.layer.value,
                  f"[{_STATUS_STYLE.get(e.status.value,'white')}]{e.status.value}[/]",
                  f"[{_SEV_STYLE.get(e.severity,'white')}]{e.severity}[/]",
                  e.title, e.ref)
    console.print(t)


def _cmd_platform(args) -> int:
    from .platform import run
    from .dashboard import write_html
    console.rule("[bold]SecureAI - guard the agent + harden its tools[/]")
    result = run(engine=args.engine, use_ai=args.ai)
    _print_events(result.runtime, "Runtime | AgentShield")
    _print_events(result.code, "Code | PatchProof (root-cause remediation)")
    c = result.store.counts()
    if result.triggered_scans:
        console.print(f"\n[cyan]Bridge:[/] a runtime block on "
                      f"[bold]{', '.join(result.triggered_scans)}[/] triggered a code "
                      f"scan of its implementation.")
    console.print(f"[bold]{c['runtime_blocked']}[/] runtime attacks blocked | "
                  f"[bold]{c['code_fixed']}[/] code vulns fixed & verified")
    if args.report:
        write_html(result, args.report)
        console.print(f"[dim]Unified dashboard written: {args.report}[/]")
    return 0


def _cmd_runtime(args) -> int:
    from .platform import run
    result = run()
    _print_events(result.runtime, "Runtime | AgentShield")
    return 0


def _cmd_harden(args) -> int:
    from .bridge import harden_tools, TOOL_SOURCES
    from .core import from_issue  # noqa: F401
    tools = args.tools or sorted(set(TOOL_SOURCES))
    events, results = harden_tools(tools, engine=args.engine, use_ai=args.ai)
    _print_events(events, f"Code | hardening tools: {', '.join(tools)}")
    fixed = sum(r.fixed for r in results.values())
    confirmed = sum(r.confirmed for r in results.values())
    console.print(f"[bold]{fixed}/{confirmed}[/] confirmed vulns fixed & verified "
                  f"across {len(results)} tool implementation(s)")
    return 0


def _cmd_loop(args) -> int:
    from .loop import run_remediation_loop, write_loop_json

    result = run_remediation_loop(max_iters=args.max_iters)
    if args.report:
        write_loop_json(result, args.report)
    for iteration in result.iterations:
        patch = iteration.get("patch") or {}
        console.print(
            f"Iteration {iteration['iteration']}: "
            f"{iteration['confirmed_before']} -> {iteration.get('confirmed_after', iteration['confirmed_before'])} "
            f"confirmed; {iteration['status']}"
            + (f" | {patch.get('cwe')} {patch.get('test_status')}" if patch else "")
        )
    console.print(f"[bold]{result.status.upper()}[/] | "
                  f"{result.residual_confirmed} confirmed vulnerabilities remain | "
                  f"{len(result.iterations)} iteration(s)")
    if result.approval_required:
        console.print("[yellow]A patch failed a verification/re-deploy gate; human review is required.[/]")
    if args.report:
        console.print(f"[dim]Loop report written: {args.report}[/]")
    return 0 if result.converged else 1


def _run_eval(args, tuned: bool = False) -> int:
    from .evaluation import evaluate_once, evaluate_tuned, write_scorecard

    report = (evaluate_tuned(max_iters=args.max_iters) if tuned else
              evaluate_once(threshold=args.threshold, max_iters=args.max_iters))
    json_path, html_path = write_scorecard(report, args.out_dir)
    gates = report["grading"]["gates"]
    passed = sum(1 for gate in gates.values() if gate["passed"])
    color = "green" if report["grading"]["passed"] else "red"
    console.print(f"[{color}]Evaluation {'PASSED' if report['grading']['passed'] else 'FAILED'}[/] "
                  f"| {passed}/{len(gates)} gates | threshold {report['threshold']}")
    console.print(f"JSON: {json_path}\nHTML: {html_path}")
    if report.get("tuning_search"):
        for candidate in report["tuning_search"]:
            console.print(f"  threshold {candidate['threshold']}: "
                          f"{candidate['gates_passed']}/{candidate['gate_count']} gates")
    return 0 if report["grading"]["passed"] else 1


def _cmd_eval(args) -> int:
    return _run_eval(args, tuned=args.mode == "tune")


def _fixture_fingerprint() -> str:
    from .loop import FIXTURE
    return hashlib.sha256(FIXTURE.read_bytes()).hexdigest()


def _cmd_watch(args) -> int:
    console.print("Watching the bundled VulnBank tool fixture for changes. Press Ctrl+C to stop.")
    last = _fixture_fingerprint()
    try:
        while True:
            status = _run_eval(args, tuned=False)
            if status:
                return status
            while True:
                time.sleep(args.interval)
                current = _fixture_fingerprint()
                if current != last:
                    last = current
                    console.print("[cyan]Fixture changed; re-running evaluation and remediation loop.[/]")
                    break
    except KeyboardInterrupt:
        console.print("\nWatch stopped.")
        return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secureai",
                                description="Guard the agent + harden its tools.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("platform", help="run both layers + the bridge")
    pp.add_argument("--engine", default="auto")
    pp.add_argument("--ai", action="store_true")
    pp.add_argument("--report", default=None)
    pp.set_defaults(func=_cmd_platform)

    pr = sub.add_parser("runtime", help="AgentShield runtime scenarios only")
    pr.set_defaults(func=_cmd_runtime)

    ph = sub.add_parser("harden", help="harden governed tools' implementations")
    ph.add_argument("tools", nargs="*", help="tool names (default: all mapped)")
    ph.add_argument("--engine", default="auto")
    ph.add_argument("--ai", action="store_true")
    ph.set_defaults(func=_cmd_harden)

    pl = sub.add_parser("loop", help="run the closed remediation loop")
    pl.add_argument("--max-iters", type=int, default=8)
    pl.add_argument("--report", default=None)
    pl.set_defaults(func=_cmd_loop)

    pe = sub.add_parser("eval", help="score the labeled synthetic evaluation set")
    pe.add_argument("--once", dest="mode", action="store_const", const="once")
    pe.add_argument("--tune", dest="mode", action="store_const", const="tune")
    pe.set_defaults(func=_cmd_eval, mode="once")
    pe.add_argument("--max-iters", type=int, default=8)
    pe.add_argument("--threshold", type=float, default=0.5)
    pe.add_argument("--out-dir", default=".")

    pw = sub.add_parser("watch", help="re-evaluate when tool code changes")
    pw.add_argument("--interval", type=float, default=1.0)
    pw.add_argument("--max-iters", type=int, default=8)
    pw.add_argument("--threshold", type=float, default=0.5)
    pw.add_argument("--out-dir", default=".")
    pw.set_defaults(func=_cmd_watch)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
