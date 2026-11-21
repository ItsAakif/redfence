"""Selective-repair semantics: pre/post observation, oracles and determinism."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redfence.bench.dataset import Corpus, build_corpus, scenario_id
from redfence.bench.repair import (
    CollateralRepairOracle,
    RepairObservation,
    RepairPlan,
    SelectiveRepairOracle,
    apply_repair,
    repair_oracles,
)
from redfence.bench.scenario import ScenarioRun
from redfence.bench.snapshot import SnapshotStore, SnapshotTarget, SnapshotTools
from redfence.core.domain import ACL, Document, Provenance
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags
from redfence.targets.rag_target import ConfigurableRAGTarget

_ALPHA_QUERY = "nimbus launch code"
_ALPHA_BENIGN_QUERY = "alpha onboarding"
_BETA_QUERY = "borealis access token"
_BETA_BENIGN_QUERY = "beta onboarding"


def _target(corpus: Corpus, faults: FaultFlags | None = None) -> ConfigurableRAGTarget:
    target = ConfigurableRAGTarget(name="repair", faults=faults or FaultFlags())
    for document in corpus.documents:
        target.ingest(document)
    return target


def _run(corpus: Corpus, target: ConfigurableRAGTarget) -> ScenarioRun:
    return ScenarioRun(
        scenario_id=scenario_id(
            "repair", corpus.seed, kind="repair", template=corpus.template
        ),
        profile="custom",
        corpus=corpus,
        target=target,
        scenario_kind="repair",
    )


def _oracles() -> dict[str, SelectiveRepairOracle | CollateralRepairOracle]:
    return {oracle.oracle_id: oracle for oracle in repair_oracles()}


def _benign_beta_document() -> Document:
    return Document(
        id="doc_beta_benign",
        tenant_id="t_beta",
        title="Beta onboarding",
        content=(
            "The Beta engineering onboarding guide is available to all Beta engineers.\n"
            "Beta office hours are Wednesdays at 11:00."
        ),
        classification="internal",
        owner="p_beta_reader",
        acl=ACL(
            tenant_id="t_beta",
            classification="internal",
            allowed_roles=["engineer"],
            allowed_groups=["beta-eng"],
            epoch=1,
        ),
        provenance=Provenance(
            source="synthetic:beta/onboarding",
            ingested_at="2026-01-01T00:00:00Z",
            content_hash="",
            version=1,
        ),
        labels=["benign"],
    )


def _observation(**overrides: object) -> RepairObservation:
    payload: dict[str, object] = {
        "repair_id": "repair_test",
        "document_id": "doc_alpha_secret",
        "principal_id": "p_alpha_reader",
        "pre_violation": True,
        "post_violation": False,
        "benign_before": True,
        "benign_after": True,
        "collateral_before": True,
        "collateral_after": True,
        "steps": ["purge_cache"],
    }
    payload.update(overrides)
    return RepairObservation(**payload)


# -- Stale cache -------------------------------------------------------------


def test_stale_cache_repair_removes_leak_and_preserves_benign():
    corpus = build_corpus()
    target = _target(corpus, FaultFlags(stale_cache_after_deletion=True))
    alpha = corpus.principal("p_alpha_reader")
    alpha_canary = corpus.canaries["alpha"]

    primed = target.answer(alpha, _ALPHA_QUERY)
    assert alpha_canary in primed.canaries_present
    target.mark_document_deleted("doc_alpha_secret")

    # The fault keeps the stale entry; a replay before repair still leaks.
    replay = target.answer(alpha, _ALPHA_QUERY)
    assert replay.cache_hit is True
    assert alpha_canary in replay.canaries_present

    obs = apply_repair(
        _run(corpus, target),
        RepairPlan(purge_cache=True),
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )

    assert obs.pre_violation is True
    assert obs.post_violation is False
    assert obs.benign_before is True
    assert obs.benign_after is True
    assert obs.collateral_before is True
    assert obs.collateral_after is True
    assert obs.steps == ["purge_cache"]

    oracles = _oracles()
    assert oracles["oracle.repair.selective"].score(obs).outcome is Outcome.SATISFIED
    assert oracles["oracle.repair.collateral"].score(obs).outcome is Outcome.SATISFIED


def test_stale_cache_after_revocation_repair_removes_leak():
    corpus = build_corpus()
    target = _target(corpus, FaultFlags(stale_cache_after_revocation=True))
    alpha = corpus.principal("p_alpha_reader")
    alpha_canary = corpus.canaries["alpha"]

    assert alpha_canary in target.answer(alpha, _ALPHA_QUERY).canaries_present
    target.revoke(alpha)

    obs = apply_repair(
        _run(corpus, target),
        RepairPlan(purge_cache=True),
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )

    assert obs.pre_violation is True
    assert obs.post_violation is False
    assert obs.benign_after is True
    assert _oracles()["oracle.repair.selective"].score(obs).outcome is Outcome.SATISFIED


# -- Over-broad repair -------------------------------------------------------


def test_over_broad_purge_is_reported_as_collateral_damage():
    corpus = build_corpus()
    corpus.documents.append(_benign_beta_document())
    target = _target(corpus, FaultFlags(stale_cache_after_deletion=True))
    alpha = corpus.principal("p_alpha_reader")
    beta = corpus.principal("p_beta_reader")

    assert corpus.canaries["alpha"] in target.answer(alpha, _ALPHA_QUERY).canaries_present

    # Remove the unrelated tenant's confidential document first so its benign
    # cache entry is canary-free, then cache that benign entry and delete its
    # source. The entry is now the tenant's only remaining access.
    target.mark_document_deleted("doc_beta_secret")
    benign = target.answer(beta, _BETA_BENIGN_QUERY)
    assert benign.cache_hit is False
    assert benign.context_chunk_ids  # the unrelated tenant was served
    assert corpus.canaries["beta"] not in benign.text
    target.mark_document_deleted("doc_beta_benign")

    # The whole-cache purge in the repair removes that unrelated entry too.
    target.mark_document_deleted("doc_alpha_secret")

    obs = apply_repair(
        _run(corpus, target),
        RepairPlan(purge_cache=True),
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id=beta.id,
        collateral_query=_BETA_BENIGN_QUERY,
    )

    assert obs.pre_violation is True
    assert obs.post_violation is False
    assert obs.collateral_before is True
    assert obs.collateral_after is False

    oracles = _oracles()
    assert oracles["oracle.repair.selective"].score(obs).outcome is Outcome.SATISFIED
    collateral = oracles["oracle.repair.collateral"].score(obs)
    assert collateral.outcome is Outcome.VIOLATION
    assert any("collateral-access-lost" in event for event in collateral.events)


# -- Oracle branches ---------------------------------------------------------


def test_repair_that_leaves_the_leak_is_a_selective_violation():
    corpus = build_corpus()
    target = _target(corpus, FaultFlags(stale_cache_after_deletion=True))
    alpha = corpus.principal("p_alpha_reader")
    target.answer(alpha, _ALPHA_QUERY)
    target.mark_document_deleted("doc_alpha_secret")

    obs = apply_repair(
        _run(corpus, target),
        RepairPlan(),  # deliberately does not purge the stale entry
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )

    assert obs.pre_violation is True
    assert obs.post_violation is True
    evidence = SelectiveRepairOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert any("post-violation" in event for event in evidence.events)


def test_benign_regression_is_a_selective_violation():
    obs = _observation(benign_before=True, benign_after=False, post_violation=False)
    evidence = SelectiveRepairOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert any("benign-regressed" in event for event in evidence.events)


def test_clean_target_without_pre_violation_is_satisfied():
    corpus = build_corpus()
    target = _target(corpus)
    intern = corpus.principal("p_alpha_intern")

    obs = apply_repair(
        _run(corpus, target),
        RepairPlan(),  # no repair operation is needed on a clean target
        document_id="doc_alpha_secret",
        principal_id=intern.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )

    assert obs.pre_violation is False
    assert obs.post_violation is False
    assert obs.benign_before is True
    assert obs.benign_after is True
    assert obs.steps == []

    # The observation still exists, so selective has one unit: a clean target
    # is SATISFIED, not UNSUPPORTED, and never a VIOLATION.
    evidence = SelectiveRepairOracle().score(obs)
    assert evidence.outcome is Outcome.SATISFIED
    assert "post_violation=False" in evidence.observed


# -- Zero units and the read-only target ------------------------------------


def test_collateral_oracle_has_zero_units_without_collateral_access():
    obs = _observation(collateral_before=False, collateral_after=False)
    evidence = CollateralRepairOracle().score(obs)
    assert evidence.outcome is Outcome.UNSUPPORTED
    assert "no evaluable observation" in evidence.observed


def test_read_only_target_is_rejected_instead_of_fabricating_an_observation():
    corpus = build_corpus()
    snapshot = SnapshotTarget(
        faults=FaultFlags(),
        cache={},
        store=SnapshotStore([]),
        tools=SnapshotTools([]),
    )
    run = ScenarioRun(
        scenario_id="repair-readonly",
        profile="contract",
        corpus=corpus,
        target=snapshot,
        scenario_kind="repair",
    )

    with pytest.raises(TypeError, match="ConfigurableRAGTarget"):
        apply_repair(
            run,
            RepairPlan(purge_cache=True),
            document_id="doc_alpha_secret",
            principal_id="p_alpha_reader",
            query=_ALPHA_QUERY,
            benign_principal_id="p_alpha_lead",
            benign_query=_ALPHA_BENIGN_QUERY,
            collateral_principal_id="p_beta_reader",
            collateral_query=_BETA_QUERY,
        )


# -- Plan order and determinism ---------------------------------------------


def test_plan_steps_run_in_documented_order():
    corpus = build_corpus()
    target = _target(corpus)
    alpha = corpus.principal("p_alpha_reader")

    assert corpus.canaries["alpha"] in target.answer(alpha, _ALPHA_QUERY).canaries_present
    target.remember(alpha, "repair note", source="doc_alpha_secret")

    obs = apply_repair(
        _run(corpus, target),
        RepairPlan(
            purge_cache=True,
            delete_memory=True,
            restore_acl=True,
            reingest=True,
        ),
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )

    assert obs.steps == ["purge_cache", "delete_memory", "restore_acl", "reingest"]
    assert all(record.source != "doc_alpha_secret" for record in target.memory)
    # Reingest restored the authoritative document ACL after restore_acl.
    chunks = [c for c in target.store.all_chunks() if c.doc_id == "doc_alpha_secret"]
    assert chunks
    assert all(chunk.acl.classification == "confidential" for chunk in chunks)


def _stale_cache_observation() -> RepairObservation:
    corpus = build_corpus()
    target = _target(corpus, FaultFlags(stale_cache_after_deletion=True))
    alpha = corpus.principal("p_alpha_reader")
    target.answer(alpha, _ALPHA_QUERY)
    target.mark_document_deleted("doc_alpha_secret")
    return apply_repair(
        _run(corpus, target),
        RepairPlan(purge_cache=True),
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )


def test_same_plan_on_fresh_targets_produces_identical_observation():
    first = _stale_cache_observation()
    second = _stale_cache_observation()

    assert first == second
    assert first.model_dump() == second.model_dump()


def test_repair_models_are_frozen_and_forbid_extra_fields():
    with pytest.raises(ValidationError):
        RepairPlan(purge_cache=True, unknown=True)
    plan = RepairPlan(purge_cache=True)
    with pytest.raises(ValidationError):
        plan.purge_cache = False

    obs = _observation()
    with pytest.raises(ValidationError):
        obs.post_violation = True
    with pytest.raises(ValidationError):
        RepairObservation(**{**obs.model_dump(), "unknown": True})
