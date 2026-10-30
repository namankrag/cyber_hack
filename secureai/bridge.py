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
    return p if p.is_absolute() else REPO_ROOT / p


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
