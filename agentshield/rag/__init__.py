"""RAG package: local UNTRUSTED retrieval for the agent loop."""
from .store import RagStore, default_store

__all__ = ["RagStore", "default_store"]
