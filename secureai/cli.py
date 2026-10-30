"""SecureAI platform CLI.

    secureai platform [--report dash.html] [--engine ...] [--ai]
        Run both layers + the bridge, render the unified dashboard.
    secureai runtime
        Run the AgentShield runtime scenarios only.
    secureai harden [tools...] [--engine ...] [--ai]
        Harden the implementations of governed tools (PatchProof).
"""
from __future__ import annotations

import argparse
import sys

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
    console.rule("[bold]SecureAI — guard the agent + harden its tools[/]")
    result = run(engine=args.engine, use_ai=args.ai)
    _print_events(result.runtime, "Runtime · AgentShield")
    _print_events(result.code, "Code · PatchProof (root-cause remediation)")
    c = result.store.counts()
    if result.triggered_scans:
        console.print(f"\n[cyan]Bridge:[/] a runtime block on "
                      f"[bold]{', '.join(result.triggered_scans)}[/] triggered a code "
                      f"scan of its implementation.")
    console.print(f"[bold]{c['runtime_blocked']}[/] runtime attacks blocked · "
                  f"[bold]{c['code_fixed']}[/] code vulns fixed & verified")
    if args.report:
        write_html(result, args.report)
        console.print(f"[dim]Unified dashboard written: {args.report}[/]")
    return 0


def _cmd_runtime(args) -> int:
    from .platform import run
    result = run()
    _print_events(result.runtime, "Runtime · AgentShield")
    return 0


def _cmd_harden(args) -> int:
    from .bridge import harden_tools, TOOL_SOURCES
    from .core import from_issue  # noqa: F401
    tools = args.tools or sorted(set(TOOL_SOURCES))
    events, results = harden_tools(tools, engine=args.engine, use_ai=args.ai)
    _print_events(events, f"Code · hardening tools: {', '.join(tools)}")
    fixed = sum(r.fixed for r in results.values())
    confirmed = sum(r.confirmed for r in results.values())
    console.print(f"[bold]{fixed}/{confirmed}[/] confirmed vulns fixed & verified "
                  f"across {len(results)} tool implementation(s)")
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

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
