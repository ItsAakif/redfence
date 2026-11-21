"""Stored metadata must not drift from the authoritative document identity."""

from __future__ import annotations

from redfence.bench.oracles import MetadataIntegrityOracle
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile


def test_secured_metadata_integrity_holds():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert MetadataIntegrityOracle().score(run).outcome is Outcome.SATISFIED


def test_mutable_document_metadata_fault_is_detected():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(mutable_document_metadata=True)
    )
    evidence = MetadataIntegrityOracle().score(run)
    assert evidence.outcome is Outcome.VIOLATION
    assert "doc_alpha_benign" in " ".join(evidence.events)
