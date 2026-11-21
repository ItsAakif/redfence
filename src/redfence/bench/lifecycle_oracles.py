"""Lifecycle/derivative oracles and their registry.

``oracle.lineage.derivation`` checks that every derived artifact reaches an
authoritative document and that a deleted document has no live derivative. The
two existence oracles live in :mod:`redfence.bench.existence`; this module owns
the :class:`LifecycleOracle` protocol and the registry that groups all three.
``default_oracles()`` is deliberately untouched (ADR-0015).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast

from redfence.bench.existence import (
    PermutationOracle,
    TwinOracle,
    _evidence,
    _no_observation,
)
from redfence.bench.lineage import build_lineage
from redfence.bench.oracles import _verdict
from redfence.core.evidence import Evidence
from redfence.core.lineage import LineageGraph

if TYPE_CHECKING:
    from redfence.bench.contract_runner import ContractRun

_DERIVATIVE_KINDS = frozenset({"cache", "answer", "memory"})


class LifecycleOracle(Protocol):
    """The interface every lifecycle/derivative oracle implements."""

    oracle_id: str
    facet: str

    def score(self, run: ContractRun) -> Evidence: ...


class DerivationOracle:
    """Derived artifacts must be reachable from an authoritative document."""

    oracle_id = "oracle.lineage.derivation"
    facet = "lineage"

    def score(self, run: ContractRun) -> Evidence:
        graph = _graph(run)
        units = [
            artifact
            for artifact in graph.artifacts()
            if artifact.kind in _DERIVATIVE_KINDS and artifact.derived_from
        ]
        unit_ids = {artifact.id for artifact in units}

        violations: list[str] = []
        for artifact in units:
            if not _reaches_document(graph, artifact.id):
                violations.append(f"orphan:{artifact.id}")

        for doc_id in _deleted_documents(run):
            for descendant in graph.descendants(f"document:{doc_id}"):
                descendant_artifact = graph.get(descendant)
                if (
                    descendant in unit_ids
                    and descendant_artifact is not None
                    and descendant_artifact.kind in _DERIVATIVE_KINDS
                ):
                    violations.append(f"deleted-descendant:{doc_id}:{descendant}")

        violations = sorted(set(violations))
        outcome = _verdict(len(units), violations)
        noun = "violation" if len(violations) == 1 else "violations"
        observed = (
            f"{len(violations)} {noun} of {len(units)} derived artifact(s)"
            if units
            else _no_observation("no derived artifact")
        )
        return _evidence(
            run,
            self.oracle_id,
            self.facet,
            "every derived artifact reaches an authoritative document and no "
            "deleted document has a live derivative",
            observed,
            outcome,
            method=(
                "derive the lineage graph from observations, then traverse "
                "ancestors and descendants"
            ),
            events=violations,
        )


def _graph(run: ContractRun) -> LineageGraph:
    if run.lineage is None:
        return _build_lineage(run)
    if isinstance(run.lineage, LineageGraph):
        return run.lineage
    return _build_lineage(run)


def _build_lineage(run: ContractRun) -> LineageGraph:
    # ``build_lineage`` takes a narrow structural run. ``SnapshotTarget.store``
    # is a mutable attribute, so mypy treats it as invariant against the
    # protocol's read-only view; the runtime shape is compatible.
    return build_lineage(cast(Any, run))


def _reaches_document(graph: LineageGraph, artifact_id: str) -> bool:
    for ancestor in graph.ancestors(artifact_id):
        artifact = graph.get(ancestor)
        if artifact is not None and artifact.kind == "document":
            return True
    return False


def _deleted_documents(run: ContractRun) -> list[str]:
    deleted = {observation["doc_id"] for observation in run.deletion_obs}
    for chunk in run.target.store.all_chunks():
        if chunk.deleted:
            deleted.add(chunk.doc_id)
    return sorted(doc_id for doc_id in deleted if doc_id)


def lifecycle_oracles() -> list[LifecycleOracle]:
    """Return the lineage/existence oracle registry in stable order."""

    return [
        DerivationOracle(),
        TwinOracle(),
        PermutationOracle(),
    ]


__all__ = [
    "DerivationOracle",
    "LifecycleOracle",
    "lifecycle_oracles",
]
