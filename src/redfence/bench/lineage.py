"""Build a lineage graph from observations and a read-only target snapshot.

The target is never instrumented (ADR-0014). :func:`build_lineage` accepts any
run that exposes the common observation lists and a ``target.store`` (both
``ScenarioRun`` and ``ContractRun`` satisfy the narrow protocol below). Document
and chunk nodes come from the store; answer, cache, memory and tool-output nodes
come from the observations. A reference that is not in the graph is skipped: the
builder never invents a parent.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from redfence.bench.dataset import Corpus
from redfence.bench.observations import (
    AnswerObservation,
    DeletionObservation,
    MemoryObservation,
    MemoryRecordObservation,
    RetrievalObservation,
    ToolObservation,
)
from redfence.core.domain import Chunk, Document
from redfence.core.ids import content_hash, json_digest
from redfence.core.lineage import Artifact, LineageGraph, Span
from redfence.targets.tools import ToolExecution

_DOC = "document"
_CHUNK = "chunk"


class _ChunkStore(Protocol):
    def all_chunks(self) -> list[Chunk]: ...


class _LineageTarget(Protocol):
    store: _ChunkStore


class _LineageRun(Protocol):
    """The narrow run shape shared by ``ScenarioRun`` and ``ContractRun``."""

    target: _LineageTarget
    retrieval_obs: list[RetrievalObservation]
    answer_obs: list[AnswerObservation]
    memory_obs: list[MemoryObservation]
    tool_obs: list[ToolObservation]
    deletion_obs: list[DeletionObservation]


def build_lineage(run: _LineageRun) -> LineageGraph:
    """Derive a deterministic lineage graph from ``run``.

    An absent or empty store yields an empty graph rather than an exception. A
    deleted document is never removed: if the store no longer holds its chunks,
    the deletion observation still names it and the corpus (when available)
    supplies its tenant and content digest.
    """

    graph = LineageGraph()
    chunks = sorted(run.target.store.all_chunks(), key=lambda chunk: chunk.id)
    if not chunks:
        return graph

    corpus = _corpus(run)
    documents = {document.id: document for document in corpus.documents} if corpus else {}

    chunks_by_doc: dict[str, list[Chunk]] = {}
    for chunk in chunks:
        chunks_by_doc.setdefault(chunk.doc_id, []).append(chunk)

    _add_documents_and_chunks(graph, chunks_by_doc)
    doc_ids = set(chunks_by_doc)
    _add_deleted_documents(graph, run.deletion_obs, doc_ids, documents)

    chunk_ids = {chunk.id for chunk in chunks}
    _add_answers_and_caches(graph, run.answer_obs, chunk_ids)
    _add_memory(graph, run.memory_obs, doc_ids)
    _add_tool_outputs(graph, run.tool_obs, chunks, doc_ids)
    return graph


# -- documents and chunks --------------------------------------------------


def _add_documents_and_chunks(
    graph: LineageGraph, chunks_by_doc: dict[str, list[Chunk]]
) -> None:
    for doc_id in sorted(chunks_by_doc):
        doc_chunks = sorted(
            chunks_by_doc[doc_id], key=lambda chunk: (chunk.position, chunk.id)
        )
        spans = _char_spans(doc_chunks)
        doc_end = max((span.end for span in spans.values()), default=0)
        document_id = f"{_DOC}:{doc_id}"
        graph.add(
            Artifact(
                id=document_id,
                kind="document",
                tenant_id=doc_chunks[0].tenant_id,
                content_hash=json_digest(sorted(chunk.content_hash for chunk in doc_chunks)),
                span=Span(start=0, end=doc_end, unit="char"),
            )
        )
        for chunk in doc_chunks:
            chunk_id = f"{_CHUNK}:{chunk.id}"
            graph.add(
                Artifact(
                    id=chunk_id,
                    kind="chunk",
                    tenant_id=chunk.tenant_id,
                    content_hash=chunk.content_hash,
                    derived_from=[document_id],
                    span=spans[chunk.id],
                )
            )
            graph.edge(document_id, chunk_id, "contains")


def _char_spans(doc_chunks: list[Chunk]) -> dict[str, Span]:
    spans: dict[str, Span] = {}
    offset = 0
    for chunk in doc_chunks:
        start = offset
        end = start + len(chunk.text)
        spans[chunk.id] = Span(start=start, end=end, unit="char")
        offset = end + 1  # line separator in the reconstructed document
    return spans


def _add_deleted_documents(
    graph: LineageGraph,
    deletion_obs: list[DeletionObservation],
    doc_ids: set[str],
    documents: dict[str, Document],
) -> None:
    for observation in deletion_obs:
        doc_id = observation["doc_id"]
        if not doc_id or doc_id in doc_ids:
            continue
        document = documents.get(doc_id)
        graph.add(
            Artifact(
                id=f"{_DOC}:{doc_id}",
                kind="document",
                tenant_id=document.tenant_id if document is not None else "unknown",
                content_hash=(
                    _document_content_hash(document.content)
                    if document is not None
                    else json_digest([])
                ),
                span=(
                    Span(start=0, end=len(document.content), unit="char")
                    if document is not None
                    else None
                ),
            )
        )
        doc_ids.add(doc_id)


def _document_content_hash(content: str) -> str:
    texts = [line.strip() for line in content.splitlines() if line.strip()]
    return json_digest(sorted(content_hash(text) for text in texts))


# -- answers and caches ----------------------------------------------------


def _add_answers_and_caches(
    graph: LineageGraph,
    answer_obs: list[AnswerObservation],
    chunk_ids: set[str],
) -> None:
    for index, observation in enumerate(answer_obs):
        parents = [
            f"{_CHUNK}:{chunk_id}"
            for chunk_id in sorted(set(observation["context_chunk_ids"]))
            if chunk_id in chunk_ids
        ]
        phase = observation["phase"]
        principal = observation["principal_id"]
        answer_id = f"answer:{phase}:{principal}:{index}"
        graph.add(
            Artifact(
                id=answer_id,
                kind="answer",
                tenant_id=observation["tenant_id"],
                content_hash=observation["text_hash"],
                derived_from=parents,
                created_by=principal,
            )
        )
        for parent in parents:
            graph.edge(parent, answer_id, "derived")

        if observation["cache_hit"]:
            cache_id = f"cache:{phase}:{principal}:{index}"
            graph.add(
                Artifact(
                    id=cache_id,
                    kind="cache",
                    tenant_id=observation["tenant_id"],
                    content_hash=observation["text_hash"],
                    derived_from=parents,
                    created_by=principal,
                )
            )
            for parent in parents:
                graph.edge(parent, cache_id, "cached")


# -- memory ----------------------------------------------------------------


def _add_memory(
    graph: LineageGraph,
    memory_obs: list[MemoryObservation],
    doc_ids: set[str],
) -> None:
    for observation in memory_obs:
        for record in observation["returned"]:
            _add_memory_record(graph, record, doc_ids)


def _add_memory_record(
    graph: LineageGraph,
    record: MemoryRecordObservation,
    doc_ids: set[str],
) -> None:
    artifact_id = f"memory:{record['record_id']}"
    parent = _document_parent(record["source"], doc_ids)
    existing = graph.get(artifact_id)
    parents = set(existing.derived_from) if existing is not None else set()
    if parent is not None:
        parents.add(parent)
    graph.add(
        Artifact(
            id=artifact_id,
            kind="memory",
            tenant_id=record["tenant_id"],
            content_hash=json_digest(dict(record)),
            derived_from=sorted(parents),
            created_by=record["principal_id"],
        )
    )
    if parent is not None:
        graph.edge(parent, artifact_id, "remembered")


def _document_parent(source: str, doc_ids: set[str]) -> str | None:
    if source in doc_ids:
        return f"{_DOC}:{source}"
    if source.startswith(f"{_DOC}:"):
        candidate = source[len(_DOC) + 1 :]
        if candidate in doc_ids:
            return source
    return None


# -- tool output -----------------------------------------------------------


def _add_tool_outputs(
    graph: LineageGraph,
    tool_obs: list[ToolObservation],
    chunks: list[Chunk],
    doc_ids: set[str],
) -> None:
    # Chunk ids win by default, but a value that is also a document id is
    # treated as a document reference: contract snapshots use the source id for
    # both, and the document is the authoritative parent.
    known: dict[str, str] = {chunk.id: f"{_CHUNK}:{chunk.id}" for chunk in chunks}
    known.update({doc_id: f"{_DOC}:{doc_id}" for doc_id in doc_ids})
    for artifact_id in list(known.values()):
        known[artifact_id] = artifact_id

    for index, observation in enumerate(tool_obs):
        execution = observation["execution"]
        parents = sorted(
            {
                reference
                for value in _referenced_values(execution)
                for reference in [known.get(value)]
                if reference is not None
            }
        )
        artifact_id = f"tool_output:{observation['phase']}:{index}"
        graph.add(
            Artifact(
                id=artifact_id,
                kind="tool_output",
                tenant_id=execution.tenant_id,
                content_hash=json_digest(execution.model_dump(mode="json")),
                derived_from=parents,
                created_by=execution.principal_id,
            )
        )
        for parent in parents:
            graph.edge(parent, artifact_id, "executed")


def _referenced_values(execution: ToolExecution) -> Iterable[str]:
    for payload in (execution.args, execution.side_effect, execution.state_delta):
        yield from _string_values(payload)


def _string_values(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


# -- helpers ---------------------------------------------------------------


def _corpus(run: _LineageRun) -> Corpus | None:
    value = getattr(run, "corpus", None)
    return value if isinstance(value, Corpus) else None


__all__ = ["build_lineage"]
