"""LangGraph orchestration over the frozen enforcement core.

Named product roles (plain names, no buzzwords):
- retriever: `retrieve` node — fetches UNTRUSTED chunks, cites doc_ids.
- gatekeeper: `decide` + `gate` nodes — policy verdict, human approval pause.
- reporter: `finalize` node — outcome only; enforcement already happened.

Nodes: retrieve -> decide -> gate -> finalize. The graph never reimplements
policy: `decide` calls shield.check(); `gate` pauses on REQUIRE_APPROVAL via
interrupt(); `finalize` only reports. Provenance comes from the harness via
trusted_scope (trusted state only), never from the request payload.
"""
from __future__ import annotations

import sqlite3

from typing_extensions import TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt  # noqa: F401  (Command used by callers)

from ..engine_factory import AgentShield
from ..models import Decision, ToolCall
from ..provenance import resolve
from ..rag.store import RagStore, format_chunk


class AgentState(TypedDict, total=False):
    query: str           # user question; drives RAG retrieval
    tool_name: str       # proposed tool call
    arguments: dict      # proposed tool arguments
    origin: str          # display only: "user" | "untrusted". Never trusted.
    context: str         # caller context; retrieved chunks are appended here
    chunks: list         # retrieved UNTRUSTED chunks
    decision: str        # ALLOW | REQUIRE_APPROVAL | DENY
    decided_tool: str    # tool-name snapshot at decide time (tamper check)
    decided_arguments: dict  # arguments snapshot at decide time (tamper check)
    reasons: list        # ordered rule details from the engine
    approved: str | None  # human verdict after interrupt()
    outcome: str         # allowed | denied | human-approved | human-denied


def _reverify(shield: AgentShield, state: AgentState) -> str | None:
    """Re-check the CURRENT state at finalize time; return a veto or None.

    Checkpoint writes between pause and resume (or tampered transitions)
    must not launder a verdict: swapped arguments, a flipped decision, or
    a freshly-denying re-check all resolve to "denied" instead of executing.
    """
    if (state.get("decided_tool") is not None
            and (state.get("tool_name") != state.get("decided_tool")
                 or dict(state.get("arguments", {}))
                 != dict(state.get("decided_arguments") or {}))):
        return "denied"
    try:
        current = ToolCall(tool_name=state.get("tool_name", "") or "",
                           arguments=dict(state.get("arguments", {})),
                           source=resolve(),
                           context=state.get("context", ""))
        fresh = shield.check(current)
    except Exception:
        return "denied"
    if fresh.decision is Decision.DENY:
        return "denied"
    if state.get("decision") == Decision.DENY.value:
        return "denied"
    return None


_verdicts: dict[str, str] = {}  # thread_id -> decide-time verdict


def _thread_id(config) -> str | None:
    try:
        return (config or {}).get("configurable", {}).get("thread_id")
    except Exception:
        return None


def _record_verdict(config, decision: str) -> None:
    """Pin the decide-time verdict outside checkpointed state.

    Checkpoint writes (update_state) between pause and resume are
    attacker-reachable wherever checkpoint access is exposed, so the
    recorded verdict lives in process memory keyed by thread_id —
    update_state cannot rewrite it. finalize() denies on any drift.
    Single-process only: multi-process deployments need sticky sessions
    or a shared verdict store (documented in THREAT_MODEL).
    """
    tid = _thread_id(config)
    if tid is None:
        return
    if len(_verdicts) > 512:
        # Drop the oldest tenth, not everything: bounded memory without
        # handing one chatty thread a global veto-kill switch. (A missing
        # pin at finalize time still fails closed; see _verdict_drift.)
        for old in list(_verdicts)[: max(1, len(_verdicts) // 10)]:
            del _verdicts[old]
    _verdicts[tid] = decision


def _verdict_drift(config, state: AgentState) -> str | None:
    """Veto decision drift — and missing pins.

    decide() always records before finalize() can run in the same process,
    so a thread with no pin means eviction, a restart, or tampering: fail
    closed. (Multi-process failover therefore needs sticky sessions or a
    shared verdict store, as documented.)
    """
    tid = _thread_id(config)
    if tid is None:
        return None
    recorded = _verdicts.get(tid)
    if recorded is None:
        return "denied"
    if state.get("decision") != recorded:
        return "denied"
    return None


def build_graph(shield: AgentShield | None = None,
                store: RagStore | None = None,
                checkpointer=None):
    """Assemble the agent graph. Inject shield/store/checkpointer for tests."""
    shield = shield or AgentShield()
    store = store or RagStore()
    if store.count == 0:
        store.ingest()

    if checkpointer is None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        checkpointer = SqliteSaver(conn)
        checkpointer.setup()

    def retrieve(state: AgentState) -> dict:
        q = state.get("query", "")
        if not q.strip():
            return {"chunks": [], "context": state.get("context", "")}
        chunks = store.retrieve(q)
        texts = "\n---\n".join(format_chunk(c) for c in chunks)
        base = state.get("context", "")
        context = (base + "\n" + texts).strip() if base else texts
        return {"chunks": chunks, "context": context}

    def decide(state: AgentState, config=None) -> dict:
        call = ToolCall(tool_name=state["tool_name"],
                        arguments=dict(state.get("arguments", {})),
                        source=resolve(),  # trusted state only, never asserted
                        context=state.get("context", ""))
        result = shield.check(call)
        _record_verdict(config, result.decision.value)
        return {"decision": result.decision.value,
                "decided_tool": state["tool_name"],
                "decided_arguments": dict(state.get("arguments", {})),
                "reasons": [f"{r.rule}: {r.detail}" for r in result.reasons]}

    def gate(state: AgentState) -> dict:
        if state.get("decision") != Decision.REQUIRE_APPROVAL.value:
            return {"approved": None}
        answer = interrupt({"tool": state.get("tool_name"),
                            "decision": state.get("decision"),
                            "reasons": state.get("reasons", [])})
        return {"approved": str(answer).strip().lower()}

    def finalize(state: AgentState, config=None) -> dict:
        veto = _verdict_drift(config, state) or _reverify(shield, state)
        if veto is not None:
            return {"outcome": veto}
        d = state.get("decision")
        if d == Decision.DENY.value:
            outcome = "denied"
        elif d == Decision.ALLOW.value:
            outcome = "allowed"
        else:
            outcome = ("human-approved"
                       if state.get("approved") == "approve" else "human-denied")
        return {"outcome": outcome}

    g = StateGraph(AgentState)
    g.add_node("retrieve", retrieve)
    g.add_node("decide", decide)
    g.add_node("gate", gate)
    g.add_node("finalize", finalize)
    g.add_edge(START, "retrieve")
    g.add_edge("retrieve", "decide")
    g.add_edge("decide", "gate")
    g.add_edge("gate", "finalize")
    g.add_edge("finalize", END)
    return g.compile(checkpointer=checkpointer)
