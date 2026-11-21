"""Memory TTL expiry lifecycle (dimension B: memory expiry)."""

from __future__ import annotations

from redfence.bench.dataset import build_corpus
from redfence.bench.oracles import default_oracles
from redfence.bench.scenario import _memory_obs, run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget


def _fresh_target(faults: FaultFlags | None = None):
    corpus = build_corpus()
    target = ConfigurableRAGTarget(name="memory-expiry", faults=faults or FaultFlags())
    for document in corpus.documents:
        target.ingest(document)
    return corpus, target


def _score(run):
    return {item.oracle_id: item for item in (o.score(run) for o in default_oracles())}


def test_secured_recall_filters_expired_records():
    corpus, target = _fresh_target()
    alpha = corpus.principal_by_role(corpus.primary_tenant().id, "reader")
    target.remember(
        alpha, "alpha temporary note", source="retrieved_document", trusted=True, ttl_epochs=1
    )
    assert target.recall(alpha), "record must be visible before expiry"
    epoch_at_recall = target.advance_epoch("test")
    records = target.recall(alpha)
    assert all(
        record.expires_at_epoch is None or record.expires_at_epoch > epoch_at_recall
        for record in records
    )
    assert all(record.text != "alpha temporary note" for record in records)


def test_expired_record_returned_is_flagged():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(unauthorized_memory_content=True)
    )
    target = run.target
    alpha = run.corpus.principal_by_role(run.corpus.primary_tenant().id, "reader")
    target.remember(
        alpha, "alpha temporary note", source="retrieved_document", trusted=True, ttl_epochs=1
    )
    epoch_at_recall = target.advance_epoch("test")
    records = target.recall(alpha)  # fault returns everything, including expired
    assert any(record.text == "alpha temporary note" for record in records)
    obs = _memory_obs("post_expiry_recall", alpha, records, now_epoch=epoch_at_recall)
    run.memory_obs.append(obs)
    evidence = _score(run)
    assert evidence["oracle.memory.scope"].outcome is Outcome.VIOLATION


def test_snapshot_obs_records_expiry():
    corpus, target = _fresh_target()
    alpha = corpus.principal_by_role(corpus.primary_tenant().id, "reader")
    target.remember(
        alpha, "alpha temporary note", source="retrieved_document", trusted=True, ttl_epochs=1
    )
    epoch_at_recall = target.advance_epoch("test")
    records = target.recall(alpha)  # secured: expired filtered out
    obs = _memory_obs("post_expiry_recall", alpha, records, now_epoch=epoch_at_recall)
    assert obs["returned"] == []
    # With the fault, the expired record carries a frozen expiry flag for the worker.
    faulted_corpus, faulted_target = _fresh_target(
        FaultFlags(unauthorized_memory_content=True)
    )
    faulted_alpha = faulted_corpus.principal_by_role(faulted_corpus.primary_tenant().id, "reader")
    faulted_target.remember(
        faulted_alpha,
        "alpha temporary note",
        source="retrieved_document",
        trusted=True,
        ttl_epochs=1,
    )
    faulted_epoch = faulted_target.advance_epoch("test")
    faulted_records = faulted_target.recall(faulted_alpha)
    faulted_obs = _memory_obs(
        "post_expiry_recall", faulted_alpha, faulted_records, now_epoch=faulted_epoch
    )
    assert any(record["expired"] is True for record in faulted_obs["returned"])
    assert all(
        record["expires_at_epoch"] is not None
        for record in faulted_obs["returned"]
        if record["expired"]
    )
