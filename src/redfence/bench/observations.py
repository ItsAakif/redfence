"""Typed observation schema for the benchmark scenario.

These ``TypedDict``s describe the frozen dictionaries that scenarios append to a
:class:`~redfence.bench.scenario.ScenarioRun` and that oracles and metrics read
back. They are typing-only: production code still builds plain ``dict`` literals
with the same keys, in the same order, and the isolated-oracle JSON payload is
unchanged.

Every key declared here is produced by the corresponding builder in
``bench/scenario.py`` or ``bench/heldout.py``. All keys are required: the
producers always emit them, so ``total=False`` would only weaken the contract.
"""

from __future__ import annotations

from typing import TypedDict

from redfence.targets.tools import ToolExecution


class ChunkMeta(TypedDict):
    """Frozen chunk identity/ACL metadata attached to an observation."""

    chunk_id: str
    doc_id: str
    tenant_id: str
    classification: str
    deleted: bool


class RetrievalObservation(TypedDict):
    """One retrieval call, with the chunks the target admitted."""

    phase: str
    principal_id: str
    tenant_id: str
    revoked: bool
    query: str
    admitted: list[ChunkMeta]


class AnswerObservation(TypedDict):
    """One answer call, its cache state and the assembled context."""

    phase: str
    principal_id: str
    tenant_id: str
    revoked: bool
    query: str
    cache_hit: bool
    cache_revalidated: bool
    context_chunk_ids: list[str]
    context: list[ChunkMeta]
    canaries_present: list[str]
    cache_doc_versions: dict[str, int]
    current_doc_versions: dict[str, int]
    text_hash: str


class MemoryRecordObservation(TypedDict):
    """One record returned by a memory recall."""

    record_id: str
    tenant_id: str
    principal_id: str
    source: str
    trusted: bool
    expires_at_epoch: int | None
    expired: bool


class MemoryObservation(TypedDict):
    """One memory recall, with every returned record."""

    phase: str
    principal_id: str
    tenant_id: str
    returned: list[MemoryRecordObservation]


class ToolObservation(TypedDict):
    """One tool call and the execution decision/result."""

    phase: str
    principal_id: str
    execution: ToolExecution


class DeletionReplay(TypedDict):
    """The answer replay recorded after a document deletion."""

    cache_hit: bool
    cache_revalidated: bool
    canaries_present: list[str]
    context: list[ChunkMeta]


class DeletionRecallRecord(TypedDict):
    """The minimal record identity/text kept in a deletion observation."""

    record_id: str
    text: str


class DeletionRecall(TypedDict):
    """Memory recall recorded after a document deletion."""

    returned: list[DeletionRecallRecord]


class DeletionPropagation(TypedDict):
    """Cache/memory propagation evidence captured alongside a deletion."""

    pre_delete_query: str
    replay: DeletionReplay
    recall: DeletionRecall


class DeletionObservation(TypedDict):
    """A document deletion and its propagation into retrieval, cache and memory."""

    phase: str
    doc_id: str
    admitted: list[ChunkMeta]
    propagation: DeletionPropagation


__all__ = [
    "AnswerObservation",
    "ChunkMeta",
    "DeletionObservation",
    "DeletionPropagation",
    "DeletionRecall",
    "DeletionRecallRecord",
    "DeletionReplay",
    "MemoryObservation",
    "MemoryRecordObservation",
    "RetrievalObservation",
    "ToolObservation",
]
