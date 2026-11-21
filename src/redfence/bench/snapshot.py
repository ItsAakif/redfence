"""Read-only target snapshot shared by isolated oracles and contract runs.

The isolated-oracle child process and contract runs both need a target-shaped
object that answers ``store.get``, ``cache`` and ``tools.spec`` without the live
:class:`~redfence.targets.rag_target.ConfigurableRAGTarget`. These types were
promoted verbatim from :mod:`redfence.bench.oracle_worker`; behaviour and the
isolated JSON payload are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from redfence.core.domain import CacheEntry, Chunk, ToolSpec
from redfence.targets.config import FaultFlags


class SnapshotStore:
    def __init__(self, chunks: list[Chunk]) -> None:
        self._chunks = {chunk.id: chunk for chunk in chunks}

    def get(self, chunk_id: str) -> Chunk | None:
        return self._chunks.get(chunk_id)

    def all_chunks(self) -> list[Chunk]:
        return [self._chunks[key] for key in sorted(self._chunks)]


class SnapshotTools:
    def __init__(self, specs: list[ToolSpec]) -> None:
        self._specs = {spec.name: spec for spec in specs}

    def spec(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)


@dataclass
class SnapshotTarget:
    faults: FaultFlags
    cache: dict[str, CacheEntry]
    store: SnapshotStore
    tools: SnapshotTools


__all__ = ["SnapshotStore", "SnapshotTarget", "SnapshotTools"]
