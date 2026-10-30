"""LangGraph orchestration over the frozen enforcement core.

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
from ..rag.store import RagStore


class AgentState(TypedDict, total=False):
    query: str           # user question; drives RAG retrieval
    tool_name: str       # proposed tool call
    arguments: dict      # proposed tool arguments
    origin: str          # display only: "user" | "untrusted". Never trusted.
    context: str         # caller context; retrieved chunks are appended here
    chunks: list         # retrieved UNTRUSTED chunks
    decision: str        # ALLOW | REQUIRE_APPROVAL | DENY
    reasons: list        # ordered rule details from the engine
    approved: str | None  # human verdict after interrupt()
    outcome: str         # allowed | denied | human-approved | human-denied


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
        texts = "\n---\n".join(f"[{c['doc_id']}] {c['text']}" for c in chunks)
        base = state.get("context", "")
        context = (base + "\n" + texts).strip() if base else texts
        return {"chunks": chunks, "context": context}

    def decide(state: AgentState) -> dict:
        call = ToolCall(tool_name=state["tool_name"],
                        arguments=dict(state.get("arguments", {})),
                        source=resolve(),  # trusted state only, never asserted
                        context=state.get("context", ""))
        result = shield.check(call)
        return {"decision": result.decision.value,
                "reasons": [f"{r.rule}: {r.detail}" for r in result.reasons]}

    def gate(state: AgentState) -> dict:
        if state.get("decision") != Decision.REQUIRE_APPROVAL.value:
            return {"approved": None}
        answer = interrupt({"tool": state.get("tool_name"),
                            "decision": state.get("decision"),
                            "reasons": state.get("reasons", [])})
        return {"approved": str(answer).strip().lower()}

    def finalize(state: AgentState) -> dict:
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
