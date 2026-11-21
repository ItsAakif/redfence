"""Lineage model and observation-derived builder."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redfence.bench.contract_runner import run_contract
from redfence.bench.lineage import build_lineage
from redfence.bench.scenario import run_revocation_scenario
from redfence.contracts.loader import parse_contract
from redfence.contracts.schema import ContractV1
from redfence.contracts.target import MockContractTarget
from redfence.core.lineage import Artifact, LineageGraph, Span
from redfence.targets.config import FaultFlags, SecurityProfile


def _contract() -> ContractV1:
    payload: dict[str, object] = {
        "contract_version": 1,
        "id": "t5-lineage",
        "dataset": {
            "version": "redfencebench-0.4.0",
            "template": "classic",
            "seed": 20260101,
        },
        "identities": [
            {
                "id": "alice",
                "tenant": "t_alpha",
                "roles": ["engineer"],
                "groups": ["alpha-eng"],
                "clearance": "confidential",
            },
            {
                "id": "bob",
                "tenant": "t_beta",
                "roles": ["engineer"],
                "groups": ["beta-eng"],
                "clearance": "confidential",
            },
        ],
        "sources": [
            {
                "id": "doc_alpha_secret",
                "tenant": "t_alpha",
                "classification": "confidential",
                "acl": {"allowed_roles": ["engineer"], "allowed_groups": ["alpha-eng"]},
                "canary_ref": "alpha",
            },
            {
                "id": "doc_beta_secret",
                "tenant": "t_beta",
                "classification": "confidential",
                "acl": {"allowed_groups": ["beta-eng"]},
                "canary_ref": "beta",
            },
        ],
        "matrix": [
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "allow",
            },
            {
                "id": "alice_answers_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "answer",
                "expect": "allow",
            },
            {
                "id": "alice_searches",
                "identity": "alice",
                "action": "tool",
                "tool": "search_documents",
                "expect": "allow",
            },
        ],
        "lifecycle": [],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": []},
        "target": {"adapter": "mock"},
    }
    return parse_contract(payload)


def _classic_run():
    return run_revocation_scenario(SecurityProfile.SECURED)


def test_classic_run_has_document_chunk_cache_and_answer_nodes():
    graph = build_lineage(_classic_run())
    artifacts = graph.artifacts()
    by_id = {artifact.id: artifact for artifact in artifacts}

    assert {"document", "chunk", "cache", "answer"} <= {artifact.kind for artifact in artifacts}

    chunks = [artifact for artifact in artifacts if artifact.kind == "chunk"]
    assert chunks
    for chunk in chunks:
        assert chunk.derived_from
        ancestors = graph.ancestors(chunk.id)
        assert ancestors
        assert all(by_id[ancestor].kind == "document" for ancestor in ancestors)

    caches = [artifact for artifact in artifacts if artifact.kind == "cache"]
    assert caches
    for cache in caches:
        ancestors = graph.ancestors(cache.id)
        assert any(by_id[ancestor].kind == "chunk" for ancestor in ancestors)

    answers_with_context = [
        artifact
        for artifact in artifacts
        if artifact.kind == "answer" and graph.ancestors(artifact.id)
    ]
    assert answers_with_context
    for answer in answers_with_context:
        assert any(by_id[ancestor].kind == "chunk" for ancestor in graph.ancestors(answer.id))


def test_chunk_spans_are_within_their_document():
    graph = build_lineage(_classic_run())
    by_id = {artifact.id: artifact for artifact in graph.artifacts()}

    for artifact in graph.artifacts():
        if artifact.kind != "chunk":
            continue
        assert artifact.span is not None
        assert artifact.span.unit == "char"
        assert 0 <= artifact.span.start <= artifact.span.end
        document = by_id[artifact.derived_from[0]]
        assert document.span is not None
        assert document.span.start <= artifact.span.start
        assert artifact.span.end <= document.span.end


def test_digest_is_stable_and_changes_with_context():
    run = _classic_run()
    first = build_lineage(run)
    second = build_lineage(run)
    assert first.digest() == second.digest()

    run.answer_obs[0]["context_chunk_ids"] = ["chunk_that_does_not_exist"]
    changed = build_lineage(run)
    assert changed.digest() != first.digest()


def test_missing_context_refs_skip_edges_without_inventing_a_parent():
    run = _classic_run()
    run.answer_obs[0]["context_chunk_ids"] = ["chunk_that_does_not_exist"]
    graph = build_lineage(run)

    answer = graph.get("answer:authorized:p_alpha_reader:0")
    assert answer is not None
    assert answer.derived_from == []
    assert graph.ancestors(answer.id) == []


def test_empty_store_returns_an_empty_graph():
    run = _classic_run()
    for document in run.corpus.documents:
        run.target.store.hard_delete(document.id)
    assert run.target.store.all_chunks() == []

    graph = build_lineage(run)
    assert graph.artifacts() == []
    assert graph.roots() == []
    assert graph.digest() == LineageGraph().digest()


def test_contract_run_derives_from_snapshot_chunks():
    contract = _contract()
    result = run_contract(contract, MockContractTarget(contract))
    graph = build_lineage(result.run)
    by_id = {artifact.id: artifact for artifact in graph.artifacts()}

    assert by_id["document:doc_alpha_secret"].kind == "document"
    assert by_id["chunk:doc_alpha_secret"].kind == "chunk"
    assert by_id["chunk:doc_alpha_secret"].derived_from == ["document:doc_alpha_secret"]

    answers = [artifact for artifact in graph.artifacts() if artifact.kind == "answer"]
    assert len(answers) == 1
    assert answers[0].derived_from == ["chunk:doc_alpha_secret"]
    assert graph.ancestors(answers[0].id) == [
        "chunk:doc_alpha_secret",
        "document:doc_alpha_secret",
    ]


def test_contract_memory_and_tool_output_derive_from_named_documents():
    contract = _contract()
    result = run_contract(contract, MockContractTarget(contract))
    result.run.memory_obs.append(
        {
            "phase": "recall",
            "principal_id": "alice",
            "tenant_id": "t_alpha",
            "returned": [
                {
                    "record_id": "mem_alpha",
                    "tenant_id": "t_alpha",
                    "principal_id": "alice",
                    "source": "doc_alpha_secret",
                    "trusted": True,
                    "expires_at_epoch": None,
                    "expired": False,
                }
            ],
        }
    )
    result.run.tool_obs[0]["execution"].args["document"] = "doc_alpha_secret"

    graph = build_lineage(result.run)
    memory = graph.get("memory:mem_alpha")
    assert memory is not None
    assert memory.derived_from == ["document:doc_alpha_secret"]
    assert graph.ancestors(memory.id) == ["document:doc_alpha_secret"]

    tool = graph.get("tool_output:alice_searches:0")
    assert tool is not None
    assert tool.derived_from == ["document:doc_alpha_secret"]
    assert graph.ancestors(tool.id) == ["document:doc_alpha_secret"]


def test_deleted_document_remains_a_root_with_a_live_descendant():
    run = run_revocation_scenario(
        SecurityProfile.SECURED,
        faults=FaultFlags(deleted_doc_retrievable=True),
    )
    graph = build_lineage(run)
    root = f"document:{run.deletion_obs[0]['doc_id']}"

    assert root in graph.roots()
    descendants = graph.descendants(root)
    assert descendants
    assert any(descendant.startswith("chunk:") for descendant in descendants)


def test_hard_deleted_document_is_still_a_root():
    run = _classic_run()
    graph = build_lineage(run)
    root = f"document:{run.deletion_obs[0]['doc_id']}"

    assert graph.get(root) is not None
    assert root in graph.roots()


def test_ancestors_and_descendants_are_sorted_and_cycle_safe():
    graph = LineageGraph()
    for artifact_id in ("a", "b", "c"):
        graph.add(
            Artifact(
                id=artifact_id,
                kind="chunk",
                tenant_id="t_alpha",
                content_hash="hash",
            )
        )
    graph.edge("a", "b", "derived")
    graph.edge("b", "c", "derived")
    graph.edge("c", "a", "derived")  # synthetic cycle

    assert graph.descendants("a") == ["b", "c"]
    assert graph.ancestors("a") == ["b", "c"]
    assert graph.ancestors("b") == ["a", "c"]
    assert graph.descendants("b") == ["a", "c"]


def test_models_are_frozen_and_forbid_extra_fields():
    span = Span(start=0, end=1, unit="char")
    with pytest.raises(ValidationError):
        Span(start=0, end=1, unit="char", extra=True)
    with pytest.raises(ValidationError):
        span.start = 2  # type: ignore[misc]
