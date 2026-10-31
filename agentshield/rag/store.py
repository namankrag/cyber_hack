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
import re
from pathlib import Path

from chromadb.config import Settings

# Telemetry stays off even if a future chromadb release re-enables the sink:
# the installed 1.5.9 Posthog.capture is already a no-op, but the repo
# documents "nothing leaves the machine", so the posture must not depend
# on an upstream default.
_TELEMETRY_OFF = Settings(anonymized_telemetry=False)

_CORPUS = Path(__file__).resolve().parent.parent / "data" / "rag_corpus.jsonl"
_COLLECTION = "agent_docs"
_MAX_RESULTS = 50
_MAX_DOC_CHARS = 100_000


_DOC_ID_SAFE = re.compile(r"[^A-Za-z0-9_.:-]")


def _sanitize_doc_id(doc_id: object) -> str:
    """Doc IDs flow into LLM context as citations: force a safe alphabet so
    a planted doc_id cannot forge citation structure (newlines, brackets,
    delimiters). Benign ids pass through unchanged."""
    return _DOC_ID_SAFE.sub("_", str(doc_id)).strip("_") or "doc"


def format_chunk(chunk: dict) -> str:
    """Render one retrieved chunk as a citation line.

    Chunk text is attacker-controlled (UNTRUSTED corpus): newlines are
    escaped so a planted doc cannot forge citation delimiters
    ("...\\n---\\n[fake] ...") and smuggle fake grounding into the agent
    context or the demo output.
    """
    text = str(chunk.get("text", "")).replace("\r", " ").replace("\n", "\\n")
    doc_id = _sanitize_doc_id(chunk.get("doc_id", ""))
    return f"[{doc_id}] {text}"


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

        from .embedding import make_embedding_function

        self._collection_name = collection
        # Default: a deterministic offline embedding (no model download, works
        # air-gapped / in CI). AGENTSHIELD_RAG_EMBEDDING=onnx uses Chroma's
        # model-based default instead. None -> Chroma default.
        self._embedding_fn = make_embedding_function()
        if path:
            self._client = chromadb.PersistentClient(path=path,
                                                     settings=_TELEMETRY_OFF)
        else:
            self._client = chromadb.Client(_TELEMETRY_OFF)
        self._collection = self._collection_for(self._collection_name)

    def _collection_for(self, name: str):
        """get_or_create_collection with the configured embedding function."""
        if self._embedding_fn is not None:
            return self._client.get_or_create_collection(
                name, embedding_function=self._embedding_fn)
        return self._client.get_or_create_collection(name)

    @property
    def count(self) -> int:
        return self._collection.count()

    def ingest(self, corpus_path: str | Path = _CORPUS) -> int:
        """(Re)load the synthetic corpus. Idempotent: wipes the collection first."""
        # Parse the corpus BEFORE wiping: a bad path must not destroy the
        # live collection it was meant to replace.
        ids, documents, metadatas = [], [], []
        with open(corpus_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                doc = json.loads(line)
                if len(doc["text"]) > _MAX_DOC_CHARS:
                    continue  # oversized doc: refuse it, don't truncate it
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
        if len(set(ids)) != len(ids):
            # A duplicate id makes Chroma's add() blow up AFTER the wipe
            # below — fail before destroying anything (persistent empty-store
            # DoS otherwise).
            raise ValueError("duplicate doc ids in corpus; refusing to wipe live collection")
        try:
            self._client.delete_collection(self._collection_name)
        except Exception:
            pass
        self._collection = self._collection_for(self._collection_name)
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
