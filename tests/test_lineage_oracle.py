"""Derivative-leak oracle: lineage reachability and deleted descendants."""

from __future__ import annotations

from redfence.bench.contract_runner import ContractRun
from redfence.bench.lifecycle_oracles import DerivationOracle, lifecycle_oracles
from redfence.bench.observations import AnswerObservation, DeletionObservation
from redfence.bench.oracles import default_oracles
from redfence.bench.snapshot import SnapshotStore, SnapshotTarget, SnapshotTools
from redfence.core.domain import ACL, Chunk, Provenance
from redfence.core.evidence import Outcome
from redfence.core.ids import content_hash
from redfence.core.lineage import Artifact, LineageGraph
from redfence.targets.config import FaultFlags


def _chunk(
    doc_id: str, *, text: str = "alpha document text", deleted: bool = False
) -> Chunk:
    return Chunk(
        id=f"{doc_id}_c0",
        doc_id=doc_id,
        tenant_id="t_alpha",
        position=0,
        text=text,
        acl=ACL(tenant_id="t_alpha", classification="public", public=True),
        provenance=Provenance(
            source=doc_id, ingested_at="", content_hash=content_hash(text)
        ),
        content_hash=content_hash(text),
        deleted=deleted,
    )


def _answer_obs(
    chunk_ids: list[str], *, cache_hit: bool = False
) -> AnswerObservation:
    return {
        "phase": "authorized",
        "principal_id": "alice",
        "tenant_id": "t_alpha",
        "revoked": False,
        "query": "alpha",
        "cache_hit": cache_hit,
        "cache_revalidated": cache_hit,
        "context_chunk_ids": chunk_ids,
        "context": [],
        "canaries_present": [],
        "cache_doc_versions": {},
        "current_doc_versions": {},
        "text_hash": content_hash("answer"),
    }


def _deletion_obs(doc_id: str) -> DeletionObservation:
    return {
        "phase": "delete",
        "doc_id": doc_id,
        "admitted": [],
        "propagation": {
            "pre_delete_query": "",
            "replay": {
                "cache_hit": False,
                "cache_revalidated": False,
                "canaries_present": [],
                "context": [],
            },
            "recall": {"returned": []},
        },
    }


def _run(
    *,
    chunks: list[Chunk] | None = None,
    answer_obs: list[AnswerObservation] | None = None,
    deletion_obs: list[DeletionObservation] | None = None,
) -> ContractRun:
    return ContractRun(
        contract_id="t6-lineage",
        contract_hash="hash",
        adapter="mock",
        capabilities=frozenset(),
        target=SnapshotTarget(
            faults=FaultFlags(),
            cache={},
            store=SnapshotStore(chunks or []),
            tools=SnapshotTools([]),
        ),
        answer_obs=answer_obs or [],
        deletion_obs=deletion_obs or [],
    )


def test_registry_groups_lineage_and_existence_oracles():
    oracles = lifecycle_oracles()

    assert [oracle.oracle_id for oracle in oracles] == [
        "oracle.lineage.derivation",
        "oracle.existence.twin",
        "oracle.existence.permutation",
    ]
    assert [oracle.facet for oracle in oracles] == ["lineage", "existence", "existence"]
    default_ids = {oracle.oracle_id for oracle in default_oracles()}
    assert default_ids.isdisjoint({oracle.oracle_id for oracle in oracles})


def test_clean_graph_is_satisfied():
    run = _run(
        chunks=[_chunk("doc_alpha")],
        answer_obs=[_answer_obs(["doc_alpha_c0"], cache_hit=True)],
    )
    evidence = DerivationOracle().score(run)

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.facet == "lineage"
    assert evidence.events == []
    assert "2 derived artifact" in evidence.observed


def test_deleted_document_with_live_cache_descendant_is_a_violation():
    run = _run(
        chunks=[_chunk("doc_alpha")],
        answer_obs=[_answer_obs(["doc_alpha_c0"], cache_hit=True)],
        deletion_obs=[_deletion_obs("doc_alpha")],
    )
    evidence = DerivationOracle().score(run)

    assert evidence.outcome is Outcome.VIOLATION
    assert any(
        event.startswith("deleted-descendant:doc_alpha:")
        for event in evidence.events
    )
    assert any("cache:" in event for event in evidence.events)
    assert not any(event.startswith("orphan:") for event in evidence.events)


def test_store_deleted_chunk_is_treated_as_a_deleted_document():
    run = _run(
        chunks=[_chunk("doc_beta", deleted=True)],
        answer_obs=[_answer_obs(["doc_beta_c0"], cache_hit=True)],
    )
    evidence = DerivationOracle().score(run)

    assert evidence.outcome is Outcome.VIOLATION
    assert any(
        event.startswith("deleted-descendant:doc_beta:")
        for event in evidence.events
    )


def test_artifact_without_a_parent_is_not_an_evaluable_unit():
    run = _run(chunks=[_chunk("doc_alpha")], answer_obs=[_answer_obs([])])
    evidence = DerivationOracle().score(run)

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert evidence.observed == "no evaluable observation: no derived artifact"


def test_unparented_artifact_is_ignored_when_a_valid_unit_exists():
    run = _run(
        chunks=[_chunk("doc_alpha")],
        answer_obs=[_answer_obs(["doc_alpha_c0"]), _answer_obs([])],
    )
    evidence = DerivationOracle().score(run)

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.events == []
    assert "1 derived artifact" in evidence.observed


def test_orphan_derivative_is_a_violation():
    graph = LineageGraph()
    graph.add(
        Artifact(
            id="chunk:floating",
            kind="chunk",
            tenant_id="t_alpha",
            content_hash="hash",
        )
    )
    graph.add(
        Artifact(
            id="answer:floating",
            kind="answer",
            tenant_id="t_alpha",
            content_hash="hash",
            derived_from=["chunk:floating"],
        )
    )
    graph.edge("chunk:floating", "answer:floating", "derived")

    run = _run()
    run.lineage = graph
    evidence = DerivationOracle().score(run)

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["orphan:answer:floating"]


def test_zero_units_is_unsupported():
    evidence = DerivationOracle().score(_run())

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert evidence.observed == "no evaluable observation: no derived artifact"
