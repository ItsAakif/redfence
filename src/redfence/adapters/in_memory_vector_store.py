"""In-memory vector store implementing :class:`RetrievalAdapter`.

The store is deliberately dumb: it returns the top-k nearest chunks and knows
nothing about authorization. Access control is enforced by the target (trusted
application code) so that injected faults can disable it in a controlled way.
"""

from __future__ import annotations

from redfence.adapters.deterministic_embedder import DeterministicEmbedder, cosine_similarity
from redfence.core.domain import Chunk, RetrievedChunk


class InMemoryVectorStore:
    def __init__(self, embedder: DeterministicEmbedder | None = None) -> None:
        self._embedder = embedder or DeterministicEmbedder()
        self._chunks: dict[str, Chunk] = {}
        self._deletions: dict[str, int] = {}

    # -- RetrievalAdapter ---------------------------------------------------
    def upsert(self, chunk: Chunk) -> None:
        stored = chunk.model_copy()
        if stored.embedding is None:
            stored.embedding = self._embedder.embed(stored.text)
        self._chunks[stored.id] = stored

    def search(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        query_vector = self._embedder.embed(query)
        scored: list[tuple[float, Chunk]] = []
        for chunk in self._chunks.values():
            if chunk.embedding is None:
                continue
            score = cosine_similarity(query_vector, chunk.embedding)
            scored.append((score, chunk))
        scored.sort(key=lambda item: (-item[0], item[1].id))
        results: list[RetrievedChunk] = []
        for score, chunk in scored[:k]:
            results.append(
                RetrievedChunk(
                    chunk_id=chunk.id,
                    doc_id=chunk.doc_id,
                    tenant_id=chunk.tenant_id,
                    text=chunk.text,
                    score=round(score, 6),
                    acl=chunk.acl,
                    provenance=chunk.provenance,
                )
            )
        return results

    def mark_deleted(self, doc_id: str, epoch: int) -> None:
        """Soft delete: set a flag that readers must honour (AISVS C8.3)."""

        self._deletions[doc_id] = epoch
        for chunk in self._chunks.values():
            if chunk.doc_id == doc_id:
                chunk.deleted = True

    def hard_delete(self, doc_id: str) -> None:
        """Physically remove chunks (cascading deletion)."""

        for chunk_id in [cid for cid, c in self._chunks.items() if c.doc_id == doc_id]:
            del self._chunks[chunk_id]
        self._deletions.pop(doc_id, None)

    def snapshot_state(self) -> dict[str, object]:
        return {
            "chunk_count": len(self._chunks),
            "deleted_doc_ids": sorted(self._deletions),
            "chunks": [
                {
                    "id": chunk.id,
                    "doc_id": chunk.doc_id,
                    "tenant_id": chunk.tenant_id,
                    "deleted": chunk.deleted,
                    "acl_epoch": chunk.acl.epoch,
                    "classification": chunk.acl.classification,
                }
                for chunk in sorted(self._chunks.values(), key=lambda c: c.id)
            ],
        }

    # -- Test/observability helpers ----------------------------------------
    def all_chunks(self) -> list[Chunk]:
        return [self._chunks[key] for key in sorted(self._chunks)]

    def get(self, chunk_id: str) -> Chunk | None:
        return self._chunks.get(chunk_id)
