"""Agent memory isolation and provenance trust."""

from __future__ import annotations

from redfence.bench.metrics import compute_metrics
from redfence.bench.oracles import MemoryIsolationOracle
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import UNTRUSTED_SOURCES


def _memory_outcome(run) -> Outcome:
    return MemoryIsolationOracle().score(run).outcome


def _synthetic_memory_run(**record_overrides: object):
    run = run_revocation_scenario(SecurityProfile.SECURED)
    alpha = run.corpus.principal_by_role(run.corpus.primary_tenant().id, "reader")
    record: dict[str, object] = {
        "record_id": "mem_synthetic",
        "tenant_id": alpha.tenant_id,
        "principal_id": alpha.id,
        "source": "tool_output",
        "trusted": True,
        "expires_at_epoch": None,
        "expired": False,
    }
    record.update(record_overrides)
    run.memory_obs = [
        {
            "phase": "synthetic_memory",
            "principal_id": alpha.id,
            "tenant_id": alpha.tenant_id,
            "returned": [record],
        }
    ]
    return run


def test_secured_memory_respects_scope():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert _memory_outcome(run) is Outcome.SATISFIED


def test_memory_fault_violates_scope():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(unauthorized_memory_content=True)
    )
    assert _memory_outcome(run) is Outcome.VIOLATION


def test_secured_untrusted_source_is_not_trusted():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    for record in run.target.memory:
        if record.source in UNTRUSTED_SOURCES:
            assert record.trusted is False


def test_vulnerable_untrusted_source_becomes_trusted():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(unauthorized_memory_content=True)
    )
    assert any(
        record.source in UNTRUSTED_SOURCES and record.trusted for record in run.target.memory
    )


def test_metric_and_oracle_agree_on_trusted_untrusted_source():
    run = _synthetic_memory_run(source="tool_output", trusted=True)
    metrics = compute_metrics(run, [])
    evidence = MemoryIsolationOracle().score(run)
    assert metrics.memory_isolation.numerator == 1
    assert metrics.memory_isolation.value == 1.0
    assert evidence.outcome is Outcome.VIOLATION


def test_metric_and_oracle_agree_on_expired_record():
    run = _synthetic_memory_run(
        source="retrieved_document",
        trusted=False,
        expires_at_epoch=1,
        expired=True,
    )
    metrics = compute_metrics(run, [])
    evidence = MemoryIsolationOracle().score(run)
    assert metrics.memory_isolation.numerator == 1
    assert metrics.memory_isolation.value == 1.0
    assert evidence.outcome is Outcome.VIOLATION
