"""Tool body for read_rag_docs — retrieval only, never enforcement.

Callers must adjudicate ``ToolCall(tool_name="read_rag_docs", ...)`` through
``shield.check()`` BEFORE calling :func:`read_rag_docs`. Retrieved chunks are
UNTRUSTED content: they must still pass the detectors + policy engine at the
point of *use* (e.g. when their text lands in a send_email context).
"""
from __future__ import annotations

from .store import RagStore, default_store, format_chunk

_store: RagStore | None = None


def _get_store() -> RagStore:
    global _store
    if _store is None:
        _store = default_store()
        if _store.count == 0:
            _store.ingest()
    return _store


def read_rag_docs(query: str, n: int = 3) -> str:
    """Return formatted UNTRUSTED chunks for a query (tool body)."""
    chunks = _get_store().retrieve(query, n_results=n)
    if not chunks:
        return "[no results]"
    return "\n---\n".join(format_chunk(c) for c in chunks)
