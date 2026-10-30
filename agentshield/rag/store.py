"""Local RAG store over a synthetic, fully UNTRUSTED document corpus.

Every record is tagged ``trust=UNTRUSTED`` at ingest and every query is scoped
with ``where={"trust": "UNTRUSTED"}``. Retrieval never confers trust: chunks
returned here must still pass the detector + policy engine at the point of
*use* (e.g. when their text lands in a send_email context). Embedding runs
locally (Chroma default embedding function); nothing leaves the machine.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_CORPUS = Path(__file__).resolve().parent.parent / "data" / "rag_corpus.jsonl"
_COLLECTION = "agent_docs"
_MAX_RESULTS = 50


def _sanitize_doc_id(doc_id: object) -> str:
    """Doc IDs flow into LLM context as citations; strip control characters
    so a planted doc_id cannot forge citation lines with embedded newlines."""
    return "".join(c if c not in "\r\n" else " " for c in str(doc_id)).strip()


def _coerce_limit(n_results: object) -> int:
    """Validate and bound the result count.

    Negative/zero/wrong-typed counts previously crashed inside Chroma with
    an unhandled TypeError/ValueError after policy had ALLOWED the call, and
    huge counts dumped the whole corpus (including poison docs) at once.
    """
    if isinstance(n_results, bool):
        n = int(n_results)
    elif isinstance(n_results, int):
        n = n_results
    else:
        raise ValueError(
            f"n_results must be an int, got {type(n_results).__name__}")
    if n < 1:
        raise ValueError(f"n_results must be >= 1, got {n}")
    return min(n, _MAX_RESULTS)


class RagStore:
    """Thin wrapper around a Chroma collection of poisoned/benign docs."""

    def __init__(self, path: str | None = None, collection: str = _COLLECTION) -> None:
        import chromadb

        self._collection_name = collection
        if path:
            self._client = chromadb.PersistentClient(path=path)
        else:
            self._client = chromadb.Client()
        self._collection = self._client.get_or_create_collection(self._collection_name)

    @property
    def count(self) -> int:
        return self._collection.count()

    def ingest(self, corpus_path: str | Path = _CORPUS) -> int:
        """(Re)load the synthetic corpus. Idempotent: wipes the collection first."""
        # Parse the corpus BEFORE wiping: a bad path must not destroy the
        # 12 good docs it was meant to replace.
        ids, documents, metadatas = [], [], []
        with open(corpus_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                doc = json.loads(line)
                ids.append(doc["id"])
                documents.append(doc["text"])
                metadatas.append(
                    {
                        "trust": "UNTRUSTED",
                        "doc_id": doc["id"],
                        "lang": doc["lang"],
                        "label": doc["label"],
                        "channel": doc["channel"],
                    }
                )
        try:
            self._client.delete_collection(self._collection_name)
        except Exception:
            pass
        self._collection = self._client.get_or_create_collection(self._collection_name)
        if ids:
            self._collection.add(ids=ids, documents=documents, metadatas=metadatas)
        return len(ids)

    def retrieve(self, query: str, n_results: int = 3) -> list[dict]:
        """Return UNTRUSTED chunks for a query. Never raises on empty store."""
        if self._collection.count() == 0:
            return []
        res = self._collection.query(
            query_texts=[query],
            n_results=_coerce_limit(n_results),
            where={"trust": "UNTRUSTED"},
        )
        out = []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        for text, meta in zip(docs, metas):
            out.append({"text": text, "doc_id": _sanitize_doc_id(meta.get("doc_id", "")),
                        "lang": meta.get("lang", ""), "label": meta.get("label", "")})
        return out


def default_store() -> RagStore:
    """Ephemeral store unless AGENTSHIELD_RAG_PATH is set (then persistent)."""
    return RagStore(path=os.getenv("AGENTSHIELD_RAG_PATH") or None)
