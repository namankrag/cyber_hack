"""AgentShield end-to-end demo — runs the four required security scenarios.

Run from the project root:   python -m examples.demo
No API keys required (uses the heuristic detector).

Scenarios (exactly the set the problem statement asks for):
  1. A legitimate task                       -> ALLOW
  2. Prompt-injected document content        -> DENY   (the hero moment)
  3. Unauthorized sensitive-data request     -> DENY
  4. A tool invocation beyond permission     -> REQUIRE_APPROVAL (fail-closed)
  + A high-impact action the user did ask for -> REQUIRE_APPROVAL (human-in-loop)
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentshield.engine_factory import AgentShield
from agentshield.models import Decision, TrustLevel
from examples.mock_agent import POISONED_DOCUMENT, MockAgent

console = Console()

_COLOR = {
    Decision.ALLOW: "bold green",
    Decision.REQUIRE_APPROVAL: "bold yellow",
    Decision.DENY: "bold red",
}
_ICON = {Decision.ALLOW: "✓", Decision.REQUIRE_APPROVAL: "⚠", Decision.DENY: "✗"}


def show(title: str, result, expected: Decision) -> bool:
    ok = result.decision is expected
    color = _COLOR[result.decision]
    body = Table.grid(padding=(0, 1))
    body.add_column(justify="right", style="dim")
    body.add_column()
    body.add_row("tool", f"[bold]{result.call.tool_name}[/]({_short(result.call.arguments)})")
    body.add_row("source", result.call.source.value)
    body.add_row("decision", f"[{color}]{_ICON[result.decision]} {result.decision.value.upper()}[/]")
    if result.fail_closed:
        body.add_row("", "[dim italic]fail-closed: escalated under uncertainty[/]")
    body.add_row("why", "")
    for r in result.reasons:
        body.add_row("", f"[dim]•[/] [italic]{r.rule}[/]: {r.detail}")
    verdict = "[green]PASS[/]" if ok else "[red]UNEXPECTED[/]"
    console.print(Panel(body, title=f"{title}   {verdict}",
                        border_style=color.split()[-1]))
    console.print()
    return ok


def _short(args: dict) -> str:
    out = []
    for k, v in args.items():
        s = str(v)
        if len(s) > 40:
            s = s[:37] + "..."
        out.append(f"{k}={s!r}")
    return ", ".join(out)


def main() -> None:
    shield = AgentShield()
    agent = MockAgent()

    console.rule("[bold]AgentShield — enforcement demo[/]")
    console.print(f"Detectors: [cyan]{', '.join(d.name for d in shield.detectors)}[/]   "
                  f"Policy: [cyan]{shield.config.policy_path}[/]\n")

    results = []

    # 1) Legitimate task: user asks the agent to search the web.
    p = agent.act("search_web", {"query": "best logistics vendors 2026"},
                  source=TrustLevel.USER,
                  narration="User: 'find me logistics vendors'")
    console.print("[dim]1. The user directly asks the agent to search the web.[/]")
    results.append(show("1 · Legitimate task", shield.check(p.call), Decision.ALLOW))

    # 2) HERO: indirect injection. User said "summarize this doc"; the doc
    #    secretly tells the agent to exfiltrate the customer DB by email.
    p = agent.act("send_email",
                  {"to": "ops-review@external-mail.net",
                   "body": "Attached: full customer database export"},
                  source=TrustLevel.UNTRUSTED,          # instruction came from the doc
                  context=POISONED_DOCUMENT,
                  narration="Agent, hijacked by the document, tries to email data out")
    console.print("[dim]2. User only asked to SUMMARIZE a document. Hidden text inside it\n"
                  "   tries to make the agent email the customer database to an outsider.[/]")
    results.append(show("2 · Indirect prompt injection (HERO)",
                        shield.check(p.call), Decision.DENY))

    # 3) Unauthorized sensitive-data request: the poisoned doc also nudges the
    #    agent to read the customer DB. Source is untrusted, tool is gated.
    p = agent.act("read_customer_db",
                  {"query": "SELECT * FROM customers"},
                  source=TrustLevel.UNTRUSTED,
                  context=POISONED_DOCUMENT,
                  narration="Agent tries to dump the customer DB on the doc's say-so")
    console.print("[dim]3. The same document nudges the agent to read the whole customer DB.[/]")
    results.append(show("3 · Unauthorized sensitive-data access",
                        shield.check(p.call), Decision.DENY))

    # 4) Tool beyond permission: a tool not in policy at all -> fail closed.
    p = agent.act("delete_all_backups", {"confirm": True},
                  source=TrustLevel.USER,
                  narration="Agent invents a destructive tool we never declared")
    console.print("[dim]4. The agent calls a tool that isn't in the policy at all.[/]")
    results.append(show("4 · Out-of-permission tool (fail-closed)",
                        shield.check(p.call), Decision.REQUIRE_APPROVAL))

    # 5) Legitimate high-impact action: user genuinely asks to send an email.
    #    Allowed path still routes to a human — showing allow/deny isn't binary.
    p = agent.act("send_email",
                  {"to": "teammate@ourcompany.com", "body": "Notes from today's sync"},
                  source=TrustLevel.USER,
                  context="User: 'email my teammate the sync notes'",
                  narration="A genuine, user-requested email")
    console.print("[dim]5. A genuine user request to send an email — not an attack,\n"
                  "   but high-impact, so it goes to human approval, not a hard block.[/]")
    results.append(show("5 · Legitimate high-impact action",
                        shield.check(p.call), Decision.REQUIRE_APPROVAL))

    # Summary
    passed = sum(results)
    table = Table(title="Summary", show_header=True, header_style="bold")
    table.add_column("Scenario")
    table.add_column("Result")
    labels = ["Legitimate task", "Indirect injection (hero)",
              "Unauthorized data access", "Out-of-permission tool",
              "Legitimate high-impact action"]
    for label, ok in zip(labels, results):
        table.add_row(label, "[green]PASS[/]" if ok else "[red]FAIL[/]")
    console.print(table)
    console.print(f"\n[bold]{passed}/{len(results)} scenarios behaved as designed.[/]")
    console.print(f"[dim]Every decision above was written to "
                  f"{shield.config.audit_path} (append-only JSONL).[/]")


if __name__ == "__main__":
    main()
