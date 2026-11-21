"""Replica/backup/retention durability: store propagation and oracles.

The secured target propagates a deletion to every configured store. Each store
config can disable propagation/purge so the stale copy remains observable; the
durability and consistency oracles then report a violation instead of a pass.
The default constructor (no stores) must stay byte-identical.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redfence.bench.dataset import build_corpus
from redfence.bench.oracles import default_oracles
from redfence.bench.retention_oracles import (
    ReplicaConsistencyOracle,
    RetentionDurabilityOracle,
    retention_oracles,
)
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.domain import Principal
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget
from redfence.targets.retention import (
    BackupConfig,
    BackupStore,
    ReplicaConfig,
    ReplicaObservation,
    ReplicaRead,
    ReplicaStore,
    RetentionConfig,
    RetentionObservation,
    RetentionStore,
    StoreObservation,
)

_SNAPSHOT_KEYS = {
    "name",
    "faults",
    "epoch",
    "store",
    "cache_keys",
    "memory",
    "tools",
    "trace",
}


def _target(
    *,
    replica_config: ReplicaConfig | None = None,
    backup_config: BackupConfig | None = None,
    retention_config: RetentionConfig | None = None,
):
    corpus = build_corpus()
    replica = ReplicaStore(replica_config or ReplicaConfig())
    backup = BackupStore(backup_config or BackupConfig())
    retention = RetentionStore(retention_config or RetentionConfig())
    target = ConfigurableRAGTarget(
        name="retention-test",
        faults=FaultFlags(),
        replicas=[replica],
        backups=[backup],
        retention=retention,
    )
    for document in corpus.documents:
        target.ingest(document)
    return corpus, target, replica, backup, retention


def _doc_chunk_id(target: ConfigurableRAGTarget, doc_id: str) -> str:
    return next(chunk.id for chunk in target.store.all_chunks() if chunk.doc_id == doc_id)


def _retention_observation(
    deleted_doc_ids: list[str],
    *stores: ReplicaStore | BackupStore | RetentionStore,
) -> RetentionObservation:
    return RetentionObservation(
        deleted_doc_ids=deleted_doc_ids,
        stores=[
            StoreObservation(
                store=store.name,
                readable_doc_ids=store.readable_doc_ids(),
            )
            for store in stores
        ],
    )


def _replica_observation(
    target: ConfigurableRAGTarget,
    replica: ReplicaStore,
    principal: Principal,
    chunk_id: str,
) -> ReplicaObservation:
    return ReplicaObservation(
        reads=[
            ReplicaRead(
                replica=replica.name,
                principal_id=principal.id,
                chunk_id=chunk_id,
                primary_allows=target.store.get(chunk_id) is not None,
                replica_allows=replica.read(principal, chunk_id) is not None,
            )
        ]
    )


# ---------------------------------------------------------------------------
# Full propagation
# ---------------------------------------------------------------------------


def test_deletion_propagates_to_every_configured_store():
    corpus, target, replica, backup, retention = _target()
    doc = corpus.confidential_doc(corpus.primary_tenant().id)
    chunk_id = _doc_chunk_id(target, doc.id)

    target.mark_document_deleted(doc.id)

    assert doc.id not in replica.readable_doc_ids()
    assert doc.id not in backup.readable_doc_ids()
    assert doc.id not in retention.readable_doc_ids()
    assert retention.tombstoned_doc_ids() == [doc.id]

    observation = _retention_observation([doc.id], replica, backup, retention)
    evidence = RetentionDurabilityOracle().score(observation)
    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.facet == "retention"

    replica_observation = _replica_observation(
        target, replica, corpus.principal("p_alpha_reader"), chunk_id
    )
    consistency = ReplicaConsistencyOracle().score(replica_observation)
    assert consistency.outcome is Outcome.SATISFIED
    assert replica_observation.reads[0].primary_allows is False
    assert replica_observation.reads[0].replica_allows is False


def test_replica_read_applies_acl_and_deletion():
    corpus, target, replica, _, _ = _target()
    doc = corpus.confidential_doc(corpus.primary_tenant().id)
    chunk_id = _doc_chunk_id(target, doc.id)
    reader = corpus.principal("p_alpha_reader")
    intern = corpus.principal("p_alpha_intern")

    assert replica.read(reader, chunk_id) is not None
    assert replica.read(intern, chunk_id) is None

    target.mark_document_deleted(doc.id)
    assert replica.read(reader, chunk_id) is None


def test_replica_copies_chunks_on_ingest():
    corpus, target, replica, _, _ = _target()
    doc = corpus.confidential_doc(corpus.primary_tenant().id)
    chunk_id = _doc_chunk_id(target, doc.id)
    reader = corpus.principal("p_alpha_reader")
    original = replica.read(reader, chunk_id)
    assert original is not None

    target.store.get(chunk_id).text = "mutated-after-ingest"  # type: ignore[union-attr]

    stored = replica.read(reader, chunk_id)
    assert stored is not None
    assert stored.text == original.text
    assert "mutated-after-ingest" not in stored.text


# ---------------------------------------------------------------------------
# Stale copies (the fault under test)
# ---------------------------------------------------------------------------


def test_replica_without_propagation_is_a_durability_violation():
    corpus, target, replica, backup, retention = _target(
        replica_config=ReplicaConfig(propagate_deletions=False)
    )
    doc = corpus.confidential_doc(corpus.primary_tenant().id)

    target.mark_document_deleted(doc.id)

    assert doc.id in replica.readable_doc_ids()
    assert doc.id not in backup.readable_doc_ids()
    assert doc.id not in retention.readable_doc_ids()

    observation = _retention_observation([doc.id], replica, backup, retention)
    evidence = RetentionDurabilityOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == [f"{replica.name}:{doc.id}"]


def test_replica_read_that_primary_denies_is_a_consistency_violation():
    corpus, target, replica, _, _ = _target(
        replica_config=ReplicaConfig(propagate_deletions=False)
    )
    doc = corpus.confidential_doc(corpus.primary_tenant().id)
    chunk_id = _doc_chunk_id(target, doc.id)

    target.mark_document_deleted(doc.id)

    observation = _replica_observation(
        target, replica, corpus.principal("p_alpha_reader"), chunk_id
    )
    read = observation.reads[0]
    assert read.primary_allows is False
    assert read.replica_allows is True

    evidence = ReplicaConsistencyOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == [f"{replica.name}:p_alpha_reader:{chunk_id}"]


def test_backup_without_purge_is_a_durability_violation():
    corpus, target, replica, backup, retention = _target(
        backup_config=BackupConfig(purge_on_delete=False)
    )
    doc = corpus.confidential_doc(corpus.primary_tenant().id)

    target.mark_document_deleted(doc.id)

    assert doc.id not in replica.readable_doc_ids()
    assert doc.id in backup.readable_doc_ids()
    assert doc.id not in retention.readable_doc_ids()

    observation = _retention_observation([doc.id], replica, backup, retention)
    evidence = RetentionDurabilityOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == [f"{backup.name}:{doc.id}"]


def test_retention_without_purge_is_a_durability_violation():
    corpus, target, replica, backup, retention = _target(
        retention_config=RetentionConfig(purge_on_delete=False)
    )
    doc = corpus.confidential_doc(corpus.primary_tenant().id)

    target.mark_document_deleted(doc.id)

    assert doc.id not in replica.readable_doc_ids()
    assert doc.id not in backup.readable_doc_ids()
    assert doc.id in retention.readable_doc_ids()
    assert retention.tombstoned_doc_ids() == [doc.id]

    observation = _retention_observation([doc.id], replica, backup, retention)
    evidence = RetentionDurabilityOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == [f"{retention.name}:{doc.id}"]


# ---------------------------------------------------------------------------
# Default path identity
# ---------------------------------------------------------------------------


def test_default_constructor_is_byte_identical():
    corpus = build_corpus()
    implicit = ConfigurableRAGTarget(name="default", faults=FaultFlags())
    explicit = ConfigurableRAGTarget(
        name="default",
        faults=FaultFlags(),
        replicas=None,
        backups=None,
        retention=None,
    )
    for document in corpus.documents:
        implicit.ingest(document)
        explicit.ingest(document)

    assert implicit.replicas == []
    assert implicit.backups == []
    assert implicit.retention is None
    assert implicit.snapshot() == explicit.snapshot()
    assert set(implicit.snapshot()) == _SNAPSHOT_KEYS


def test_default_target_keeps_existing_deletion_outcomes():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    evidence = {
        item.oracle_id: item.outcome
        for item in (oracle.score(run) for oracle in default_oracles())
    }

    assert evidence["oracle.index.deletion"] is Outcome.SATISFIED
    assert evidence["oracle.cache.deletion_propagation"] is Outcome.SATISFIED
    assert evidence["oracle.memory.deletion_propagation"] is Outcome.SATISFIED
    assert run.target.replicas == []
    assert run.target.backups == []
    assert run.target.retention is None


# ---------------------------------------------------------------------------
# Vacuity, determinism and model surface
# ---------------------------------------------------------------------------


def test_zero_units_is_unsupported():
    durability = RetentionDurabilityOracle().score(
        RetentionObservation(deleted_doc_ids=["doc_alpha_secret"], stores=[])
    )
    assert durability.outcome is Outcome.UNSUPPORTED
    assert durability.observed.startswith("no evaluable observation:")

    no_deleted = RetentionDurabilityOracle().score(
        RetentionObservation(
            deleted_doc_ids=[],
            stores=[StoreObservation(store="replica", readable_doc_ids=["doc"])],
        )
    )
    assert no_deleted.outcome is Outcome.UNSUPPORTED

    consistency = ReplicaConsistencyOracle().score(ReplicaObservation(reads=[]))
    assert consistency.outcome is Outcome.UNSUPPORTED
    assert consistency.observed.startswith("no evaluable observation:")


def test_oracles_are_deterministic_twice():
    corpus, target, replica, backup, retention = _target(
        replica_config=ReplicaConfig(propagate_deletions=False)
    )
    doc = corpus.confidential_doc(corpus.primary_tenant().id)
    chunk_id = _doc_chunk_id(target, doc.id)
    target.mark_document_deleted(doc.id)

    retention_obs = _retention_observation([doc.id], replica, backup, retention)
    replica_obs = _replica_observation(
        target, replica, corpus.principal("p_alpha_reader"), chunk_id
    )

    durability_first = RetentionDurabilityOracle().score(retention_obs).model_dump()
    durability_second = RetentionDurabilityOracle().score(retention_obs).model_dump()
    consistency_first = ReplicaConsistencyOracle().score(replica_obs).model_dump()
    consistency_second = ReplicaConsistencyOracle().score(replica_obs).model_dump()

    assert durability_first == durability_second
    assert consistency_first == consistency_second


def test_registry_order_and_facet_are_stable():
    oracles = retention_oracles()

    assert [oracle.oracle_id for oracle in oracles] == [
        "oracle.retention.durability",
        "oracle.replica.consistency",
    ]
    assert all(oracle.facet == "retention" for oracle in oracles)


def test_replica_config_and_read_are_frozen():
    with pytest.raises(ValidationError):
        ReplicaConfig(name="x").name = "y"  # type: ignore[misc]

    read = ReplicaRead(
        replica="replica-1",
        principal_id="p_alpha_reader",
        chunk_id="chunk",
        primary_allows=False,
        replica_allows=True,
    )
    with pytest.raises(ValidationError):
        read.replica_allows = False  # type: ignore[misc]
