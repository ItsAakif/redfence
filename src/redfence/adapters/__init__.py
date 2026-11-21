"""Adapters: deterministic embedder, in-memory vector store, deterministic generator."""

from redfence.adapters.deterministic_embedder import DeterministicEmbedder, cosine_similarity
from redfence.adapters.deterministic_generator import DeterministicGenerator
from redfence.adapters.in_memory_vector_store import InMemoryVectorStore

__all__ = [
    "DeterministicEmbedder",
    "DeterministicGenerator",
    "InMemoryVectorStore",
    "cosine_similarity",
]
