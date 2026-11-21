"""Durability oracles for replicas, backups and retention stores.

Both oracles consume frozen observations only. ``oracle.retention.durability``
treats every ``(store, deleted document)`` pair as one unit and flags a pair
when the store still reports the document as readable.
``oracle.replica.consistency`` treats every replica read as one unit and flags a
read that the replica allows while the primary denies. Verdicts follow ADR-0008
through the shared ``_verdict`` helper: zero units is ``UNSUPPORTED``, never a
pass.
"""

from __future__ import annotations

from typing import Protocol

from redfence.bench.oracles import _no_observation, _verdict
from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import stable_id
from redfence.targets.retention import ReplicaObservation, RetentionObservation

_FACET = "retention"


class RetentionOracle(Protocol):
    """The interface every replica/retention oracle implements."""

    oracle_id: str
    facet: str

    def score(self, observation: RetentionObservation | ReplicaObservation) -> Evidence: ...


def _evidence(
    scenario_id: str,
    oracle_id: str,
    expected: str,
    observed: str,
    outcome: Outcome,
    *,
    method: str,
    events: list[str] | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=stable_id("ev", scenario_id, oracle_id),
        scenario_id=scenario_id,
        oracle_id=oracle_id,
        facet=_FACET,
        expected=expected,
        observed=observed,
        outcome=outcome,
        method=method,
        events=events or [],
    )


def _retention_scenario_id(observation: RetentionObservation) -> str:
    store_names = [store.store for store in observation.stores]
    return stable_id("retention", *observation.deleted_doc_ids, *store_names)


def _replica_scenario_id(observation: ReplicaObservation) -> str:
    return stable_id("replica", *[read.replica for read in observation.reads])


class RetentionDurabilityOracle:
    """A deleted document must not stay readable in any configured store."""

    oracle_id = "oracle.retention.durability"
    facet = _FACET

    def score(self, observation: RetentionObservation | ReplicaObservation) -> Evidence:
        if not isinstance(observation, RetentionObservation):
            return _evidence(
                "retention",
                self.oracle_id,
                "a deleted document is not readable in any replica, backup or "
                "retention store",
                _no_observation("no retention observation"),
                _verdict(0, []),
                method="compare each store's readable document ids with the deleted set",
            )

        units = 0
        violations: list[str] = []
        for store in observation.stores:
            readable = set(store.readable_doc_ids)
            for doc_id in observation.deleted_doc_ids:
                units += 1
                if doc_id in readable:
                    violations.append(f"{store.store}:{doc_id}")

        outcome = _verdict(units, violations)
        observed = (
            f"{len(violations)} readable deleted copy/copies across {units} "
            "(store, document) pair(s)"
            if units
            else _no_observation("no deleted document in a configured store")
        )
        return _evidence(
            _retention_scenario_id(observation),
            self.oracle_id,
            "a deleted document is not readable in any replica, backup or "
            "retention store",
            observed,
            outcome,
            method="compare each store's readable document ids with the deleted set",
            events=violations,
        )


class ReplicaConsistencyOracle:
    """A replica must never allow a read that the primary denies."""

    oracle_id = "oracle.replica.consistency"
    facet = _FACET

    def score(self, observation: RetentionObservation | ReplicaObservation) -> Evidence:
        if not isinstance(observation, ReplicaObservation):
            return _evidence(
                "replica",
                self.oracle_id,
                "no replica read is allowed when the primary denies it",
                _no_observation("no replica read"),
                _verdict(0, []),
                method="compare each replica read with the primary's authorization",
            )

        units = len(observation.reads)
        violations = [
            f"{read.replica}:{read.principal_id}:{read.chunk_id}"
            for read in observation.reads
            if read.replica_allows and not read.primary_allows
        ]
        outcome = _verdict(units, violations)
        observed = (
            f"{len(violations)} replica read(s) allowed what the primary denied "
            f"across {units} read(s)"
            if units
            else _no_observation("no replica read")
        )
        return _evidence(
            _replica_scenario_id(observation),
            self.oracle_id,
            "no replica read is allowed when the primary denies it",
            observed,
            outcome,
            method="compare each replica read with the primary's authorization",
            events=violations,
        )


def retention_oracles() -> list[RetentionOracle]:
    """Return the replica/retention oracle registry in stable order."""

    return [
        RetentionDurabilityOracle(),
        ReplicaConsistencyOracle(),
    ]


__all__ = [
    "ReplicaConsistencyOracle",
    "RetentionDurabilityOracle",
    "RetentionOracle",
    "retention_oracles",
]
