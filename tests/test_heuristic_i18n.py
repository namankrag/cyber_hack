"""Multilingual heuristic coverage over the synthetic RAG corpus.

Every benign corpus doc must score 0 (no false positives); the Hindi/Kannada
poison docs must be flagged (the gap the EN-only patterns left open).
"""
import json
from pathlib import Path

from agentshield.detection.heuristic import HeuristicDetector
from agentshield.models import ToolCall, TrustLevel

_CORPUS = Path(__file__).resolve().parent.parent / "agentshield" / "data" / "rag_corpus.jsonl"


def _docs():
    with open(_CORPUS, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _scan(text):
    return HeuristicDetector().scan(ToolCall(tool_name="search_web",
                                             arguments={},
                                             source=TrustLevel.UNTRUSTED,
                                             context=text))


def test_all_benign_corpus_docs_score_zero():
    benign = [d for d in _docs() if d["label"] == "benign"]
    assert len(benign) == 6
    for d in benign:
        r = _scan(d["text"])
        assert not r.is_threat, (d["id"], r.signals)


def test_hindi_upi_lure_is_flagged():
    docs = {d["id"]: d for d in _docs()}
    r = _scan(docs["hi-poison-upi"]["text"])
    assert r.is_threat, r.signals


def test_kannada_upi_lure_is_flagged():
    docs = {d["id"]: d for d in _docs()}
    r = _scan(docs["kn-poison-upi"]["text"])
    assert r.is_threat, r.signals


def test_kannada_doc_names_kannada_signal():
    docs = {d["id"]: d for d in _docs()}
    r = _scan(docs["kn-poison-upi"]["text"])
    assert any("Kannada" in s or "UPI" in s or "secrecy" in s for s in r.signals)
