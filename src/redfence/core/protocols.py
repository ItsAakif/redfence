"""Small, composable Protocol interfaces (mandate section 6).

Only the adapters required for the initial vertical slice are implemented. Keep
these interfaces narrow; add methods only when a second implementation proves
the seam.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from redfence.core.domain import (
    ACL,
    Answer,
    Chunk,
    Document,
    PolicyDecision,
    Principal,
    RetrievedChunk,
    ToolCall,
)
from redfence.core.evidence import Evidence


@runtime_checkable
class RetrievalAdapter(Protocol):
    """Storage + similarity search. Authorization is NOT performed here."""

    def upsert(self, chunk: Chunk) -> None: ...

    def search(self, query: str, k: int) -> list[RetrievedChunk]: ...

    def mark_deleted(self, doc_id: str, epoch: int) -> None: ...

    def hard_delete(self, doc_id: str) -> None: ...

    def snapshot_state(self) -> dict[str, object]: ...


@runtime_checkable
class AccessPath(Protocol):
    """A named route by which a principal can reach protected information."""

    name: str

    def invoke(self, principal: Principal, query: str) -> Answer: ...


@runtime_checkable
class Scorer(Protocol):
    """A deterministic oracle. Returns typed Evidence, never a bare bool."""

    oracle_id: str
    facet: str

    def score(self, run: object) -> Evidence: ...


@runtime_checkable
class AttackGenerator(Protocol):
    """Phase-A attack generation (static / parameterized / mutation)."""

    attack_id: str
    family: str

    def generate(self, seed: int) -> list[str]: ...


@runtime_checkable
class ToolPolicy(Protocol):
    """Trusted, LLM-independent authorization for tool calls."""

    def decide(
        self, principal: Principal, call: ToolCall, spec_capability: str, high_impact: bool
    ) -> PolicyDecision: ...


@runtime_checkable
class Target(Protocol):
    """A system under test."""

    name: str

    def ingest(self, document: Document, acl: ACL | None = None) -> list[str]: ...

    def answer(self, principal: Principal, query: str, *, use_cache: bool = True) -> Answer: ...

    def snapshot(self) -> dict[str, object]: ...
