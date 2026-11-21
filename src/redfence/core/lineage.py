"""Lineage data model: artifacts, spans, edges and a deterministic graph.

Lineage is *derived*, never instrumented into the target (ADR-0014). This module
is pure data: it has no dependency on :mod:`redfence.bench`, so the target and
the benchmark can both use it without a cycle. Ordering and digests are stable so
two builds of the same observations produce byte-identical output.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redfence.core.ids import json_digest

SpanUnit = Literal["char", "line", "chunk"]
ArtifactKind = Literal["document", "chunk", "answer", "cache", "memory", "tool_output"]
Relation = Literal["contains", "derived", "cached", "remembered", "executed"]

_RELATIONS: dict[str, Relation] = {
    "contains": "contains",
    "derived": "derived",
    "cached": "cached",
    "remembered": "remembered",
    "executed": "executed",
}


class Span(BaseModel):
    """A half-open range inside a parent artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    start: int
    end: int
    unit: SpanUnit


class Artifact(BaseModel):
    """One node in the lineage graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    kind: ArtifactKind
    tenant_id: str
    content_hash: str
    derived_from: list[str] = Field(default_factory=list)
    created_by: str = ""
    epoch: int = 0
    span: Span | None = None


class LineageEdge(BaseModel):
    """A directed parent -> child relation between two artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    parent: str
    child: str
    relation: Relation


class LineageGraph:
    """Deterministic, cycle-safe lineage graph.

    Duplicate edges collapse. Traversals are breadth-first over sorted
    neighbours, so results are sorted and duplicate-free regardless of insertion
    order. A cycle is tolerated: the visited set prevents infinite traversal.
    """

    def __init__(self) -> None:
        self._artifacts: dict[str, Artifact] = {}
        self._edges: dict[tuple[str, str, str], LineageEdge] = {}

    # -- construction ------------------------------------------------------

    def add(self, artifact: Artifact) -> None:
        self._artifacts[artifact.id] = artifact

    def edge(self, parent: str, child: str, relation: str) -> None:
        resolved = _RELATIONS.get(relation)
        if resolved is None:
            raise ValueError(f"unknown lineage relation: {relation!r}")
        key = (parent, child, resolved)
        self._edges[key] = LineageEdge(parent=parent, child=child, relation=resolved)

    # -- queries -----------------------------------------------------------

    def get(self, artifact_id: str) -> Artifact | None:
        return self._artifacts.get(artifact_id)

    def artifacts(self) -> list[Artifact]:
        return [self._artifacts[key] for key in sorted(self._artifacts)]

    def roots(self) -> list[str]:
        children = {child for (_, child, _) in self._edges}
        return [
            artifact_id
            for artifact_id in sorted(self._artifacts)
            if artifact_id not in children
        ]

    def ancestors(self, artifact_id: str) -> list[str]:
        return self._walk(artifact_id, upward=True)

    def descendants(self, artifact_id: str) -> list[str]:
        return self._walk(artifact_id, upward=False)

    def digest(self) -> str:
        """SHA-256 of the canonical ``{artifacts, edges}`` payload."""

        payload = {
            "artifacts": [_canonical_artifact(artifact) for artifact in self.artifacts()],
            "edges": [
                {"parent": parent, "child": child, "relation": relation}
                for (parent, child, relation) in sorted(self._edges)
            ],
        }
        return json_digest(payload)

    # -- internals ---------------------------------------------------------

    def _walk(self, artifact_id: str, *, upward: bool) -> list[str]:
        neighbours: dict[str, set[str]] = {}
        for (parent, child, _) in self._edges:
            source, target = (child, parent) if upward else (parent, child)
            neighbours.setdefault(source, set()).add(target)

        seen = {artifact_id}
        found: set[str] = set()
        stack = [artifact_id]
        while stack:
            current = stack.pop()
            for nxt in sorted(neighbours.get(current, ())):
                if nxt in seen:
                    continue
                seen.add(nxt)
                found.add(nxt)
                stack.append(nxt)
        return sorted(found)


def _canonical_artifact(artifact: Artifact) -> dict[str, object]:
    payload = artifact.model_dump(mode="json")
    payload["derived_from"] = sorted(set(artifact.derived_from))
    return payload


__all__ = [
    "Artifact",
    "ArtifactKind",
    "LineageEdge",
    "LineageGraph",
    "Relation",
    "Span",
    "SpanUnit",
]
