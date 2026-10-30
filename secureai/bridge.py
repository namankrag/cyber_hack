"""The bridge — where the two layers actually connect.

Two directions:

  1. harden_tools(): run PatchProof over the *implementation* of the tools that
     AgentShield guards. AgentShield controls which tool calls are allowed at
     runtime; PatchProof proves and fixes the vulnerabilities inside those tools.
     Same asset, defended from both sides.

  2. on_runtime_block(): when AgentShield blocks an attack aimed at a tool at
     runtime, the bridge treats that as a signal and scans that tool's source
     for the root-cause weakness — runtime detection driving code remediation.

The tool -> source mapping is the registry an operator maintains: it says which
file implements each governed tool.
"""
from __future__ import annotations

from pathlib import Path

from . import REPO_ROOT
from .core import Layer, SecurityEvent, Status, from_issue

# Which source file implements each governed tool. In this demo the sensitive
# "banking" tools are backed by the VulnBank service.
TOOL_SOURCES: dict[str, str] = {
    "read_customer_db": "patchproof/vulnbank/app.py",
    "send_email": "patchproof/vulnbank/app.py",
    "transfer_funds": "patchproof/vulnbank/app.py",
}


def _resolve(path: str) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    resolved = REPO_ROOT / p
    if resolved.exists():
        return resolved
    # Wheels install the practice app as the top-level ``vulnbank`` package.
    if path.startswith("patchproof/vulnbank/"):
        return REPO_ROOT / path.removeprefix("patchproof/")
    return resolved


def harden_target(target: str, engine: str = "auto", use_ai: bool = False):
    """Run the full PatchProof pipeline over one tool-implementation file.

    Returns (PipelineResult, [SecurityEvent]). Every confirmed-and-fixed vuln
    becomes a CODE event.
    """
    from patchproof.pipeline import run_pipeline

    result = run_pipeline(str(_resolve(target)), engine=engine, use_ai=use_ai)
    events = [from_issue(i) for i in result.issues]
    return result, events


def harden_tools(tool_names: list[str], engine: str = "auto",
                 use_ai: bool = False) -> tuple[list[SecurityEvent], dict]:
    """Harden the implementations of the named governed tools.

    De-duplicates by source file (several tools may share one backend).
    Returns (events, {source_file: PipelineResult}).
    """
    sources = []
    for name in tool_names:
        src = TOOL_SOURCES.get(name)
        if src and src not in sources:
            sources.append(src)

    events: list[SecurityEvent] = []
    results: dict = {}
    for src in sources:
        res, evs = harden_target(src, engine=engine, use_ai=use_ai)
        results[src] = res
        events.extend(evs)
    return events, results


def on_runtime_block(tool_name: str, engine: str = "ast") -> list[SecurityEvent]:
    """Runtime -> code loop: a block on `tool_name` triggers a code scan of its
    implementation. Returns CODE events, each linked back to the runtime tool.
    """
    src = TOOL_SOURCES.get(tool_name)
    if not src:
        return []
    _res, events = harden_target(src, engine=engine)
    for e in events:
        e.links.append(tool_name)   # trace: this code finding came from a runtime block
    return events


def scan_on_runtime_block(tool_name: str, engine: str = "ast",
                          source_override: str | Path | None = None) -> list[SecurityEvent]:
    """Scan the mapped implementation after a block and link findings to it.

    ``source_override`` is used by the closed-loop runner to scan its isolated
    deployed copy. It cannot change which tool is governed; the tool must
    still exist in the explicit registry above.
    """
    from patchproof.scanner import scan

    registered = TOOL_SOURCES.get(tool_name)
    if not registered:
        return []
    target = Path(source_override) if source_override is not None else _resolve(registered)
    events = []
    for finding in scan(target, engine=engine):
        events.append(SecurityEvent(
            layer=Layer.CODE,
            status=Status.UNCONFIRMED,
            title=f"{finding.cwe}: {finding.title}",
            detail="Static finding opened by the runtime-block bridge; exploit proof follows.",
            severity=finding.severity.value,
            evidence=finding.evidence,
            ref=f"patchproof/vulnbank/app.py:{finding.line}",
            links=[tool_name],
        ))
    return events
