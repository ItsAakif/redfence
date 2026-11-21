"""Independent authorization recomputation used by oracles and metrics.

This is the *expected* policy, evaluated from first principles and from the
**authoritative** corpus ACL (not the possibly mutated stored chunk ACL). If the
target admits a chunk this function rejects, that is a confirmed boundary
violation. Using the authoritative ACL is what lets the oracle detect lost or
forged chunk-level metadata.
"""

from __future__ import annotations

from redfence.core.domain import ACL, Chunk, Principal, RetrievedChunk


def permits_by_acl(
    principal: Principal, acl: ACL, *, tenant_id: str, deleted: bool = False
) -> bool:
    if deleted:
        return False
    if tenant_id != principal.tenant_id:
        return False
    return acl.permits(principal)


def is_permitted(
    principal: Principal, chunk: Chunk | RetrievedChunk, *, deleted: bool = False
) -> bool:
    """Store-based check (uses the chunk's stored ACL)."""

    return permits_by_acl(principal, chunk.acl, tenant_id=chunk.tenant_id, deleted=deleted)


def document_acl(corpus, doc_id: str) -> ACL | None:
    """Authoritative ACL for a document, from the corpus definition."""

    for document in corpus.documents:
        if document.id == doc_id:
            return document.acl
    return None
