"""Replica, backup and retention stores for deletion-durability evaluation.

The primary vector store is authoritative. A deployment may also keep a
read replica, a backup copy and a retention/archive record of the same chunks.
Deletion is only durable when it reaches every one of those copies; the
per-store configs below let a caller disable propagation so that the stale copy
is observable (and detectable by :mod:`redfence.bench.retention_oracles`).

The stores are deliberately in-memory and deterministic. They never touch the
network or the filesystem, and a replica read applies the chunk ACL itself so
that a stale copy cannot silently bypass authorization.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from redfence.core.domain import Chunk, Principal


class ReplicaConfig(BaseModel):
    """How a read replica reacts to a source-document deletion."""

    model_config = ConfigDict(frozen=True)

    name: str = "replica-1"
    propagate_deletions: bool = True


class BackupConfig(BaseModel):
    """How a backup copy reacts to a source-document deletion."""

    name: str = "backup-1"
    purge_on_delete: bool = True


class RetentionConfig(BaseModel):
    """How a retention/archive record reacts to a source-document deletion."""

    name: str = "retention"
    purge_on_delete: bool = True


class StoreObservation(BaseModel):
    """Readable document ids observed in one store after a deletion."""

    model_config = ConfigDict(frozen=True)

    store: str
    readable_doc_ids: list[str]


class RetentionObservation(BaseModel):
    """Deleted documents and the stores that may still hold them."""

    deleted_doc_ids: list[str]
    stores: list[StoreObservation]


class ReplicaRead(BaseModel):
    """One replica read compared with the primary's authorization decision."""

    model_config = ConfigDict(frozen=True)

    replica: str
    principal_id: str
    chunk_id: str
    primary_allows: bool
    replica_allows: bool


class ReplicaObservation(BaseModel):
    """The replica reads evaluated by the consistency oracle."""

    reads: list[ReplicaRead]


class ReplicaStore:
    """A read replica that holds an independent copy of every ingested chunk."""

    def __init__(self, config: ReplicaConfig | None = None) -> None:
        self.config = config or ReplicaConfig()
        self._chunks: dict[str, Chunk] = {}

    @property
    def name(self) -> str:
        return self.config.name

    def ingest(self, chunk: Chunk) -> None:
        """Copy the chunk on ingest so later primary mutations cannot leak in."""

        self._chunks[chunk.id] = chunk.model_copy(deep=True)

    def read(self, principal: Principal, chunk_id: str) -> Chunk | None:
        """Return the chunk only when it is live and the ACL permits ``principal``."""

        stored = self._chunks.get(chunk_id)
        if stored is None or stored.deleted:
            return None
        if not stored.acl.permits(principal):
            return None
        return stored

    def mark_deleted(self, doc_id: str) -> None:
        """Honour the replica's propagation policy for one deleted document."""

        if not self.config.propagate_deletions:
            # FAULT: the replica keeps serving a copy of the deleted document.
            return
        for chunk in self._chunks.values():
            if chunk.doc_id == doc_id:
                chunk.deleted = True

    def purge(self, doc_id: str) -> None:
        """Physically remove every copy of ``doc_id`` from the replica."""

        for chunk_id in [
            chunk_id
            for chunk_id, chunk in self._chunks.items()
            if chunk.doc_id == doc_id
        ]:
            del self._chunks[chunk_id]

    def readable_doc_ids(self) -> list[str]:
        """Document ids with at least one live chunk, sorted for determinism."""

        return sorted(
            {chunk.doc_id for chunk in self._chunks.values() if not chunk.deleted}
        )


class BackupStore:
    """A backup copy that holds an independent copy of every ingested chunk."""

    def __init__(self, config: BackupConfig | None = None) -> None:
        self.config = config or BackupConfig()
        self._chunks: dict[str, Chunk] = {}

    @property
    def name(self) -> str:
        return self.config.name

    def ingest(self, chunk: Chunk) -> None:
        self._chunks[chunk.id] = chunk.model_copy(deep=True)

    def mark_deleted(self, doc_id: str) -> None:
        """Purge the backup copy unless the configured policy keeps it."""

        if self.config.purge_on_delete:
            self.purge(doc_id)

    def purge(self, doc_id: str) -> None:
        for chunk_id in [
            chunk_id
            for chunk_id, chunk in self._chunks.items()
            if chunk.doc_id == doc_id
        ]:
            del self._chunks[chunk_id]

    def readable_doc_ids(self) -> list[str]:
        return sorted({chunk.doc_id for chunk in self._chunks.values()})


class RetentionStore:
    """A retention/archive record of chunk ids plus deletion tombstones."""

    def __init__(self, config: RetentionConfig | None = None) -> None:
        self.config = config or RetentionConfig()
        self._records: dict[str, list[str]] = {}
        self._tombstones: dict[str, int] = {}

    @property
    def name(self) -> str:
        return self.config.name

    def ingest(self, chunk: Chunk) -> None:
        chunk_ids = self._records.setdefault(chunk.doc_id, [])
        if chunk.id not in chunk_ids:
            chunk_ids.append(chunk.id)

    def mark_deleted(self, doc_id: str) -> None:
        """Record the deletion and purge retained records when configured."""

        if self.config.purge_on_delete:
            self.purge(doc_id)
            return
        # FAULT: a tombstone is written but the retained records stay readable.
        self._tombstones[doc_id] = self._tombstones.get(doc_id, 0) + 1

    def purge(self, doc_id: str) -> None:
        self._records.pop(doc_id, None)
        self._tombstones.setdefault(doc_id, 0)

    def readable_doc_ids(self) -> list[str]:
        """Document ids whose retained records were not purged."""

        return sorted(self._records)

    def tombstoned_doc_ids(self) -> list[str]:
        return sorted(self._tombstones)


__all__ = [
    "BackupConfig",
    "BackupStore",
    "ReplicaConfig",
    "ReplicaObservation",
    "ReplicaRead",
    "ReplicaStore",
    "RetentionConfig",
    "RetentionObservation",
    "RetentionStore",
    "StoreObservation",
]
