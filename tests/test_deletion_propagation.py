"""Deletion propagation to cache and memory (closes the measured control gap).

The secured target must purge cached answers and memory records derived from a
deleted document; the two faults disable each half independently and the two
propagation oracles detect each half from frozen observations only.
"""

from __future__ import annotations

import os

from redfence.bench.isolated import run_oracles_isolated
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import run_campaign
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile


def _evidence_map(run):
    return {item.oracle_id: item for item in (oracle.score(run) for oracle in default_oracles())}


def test_secured_deletion_purges_cached_answer():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    propagation = run.deletion_obs[0]["propagation"]
    replay = propagation["replay"]
    assert replay["cache_hit"] is False
    assert replay["canaries_present"] == []
    assert run.corpus.canaries["beta"] not in str(replay["canaries_present"])


def test_secured_deletion_purges_memory_records():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    beta_canary = run.corpus.canaries["beta"]
    recalled = run.deletion_obs[0]["propagation"]["recall"]["returned"]
    assert all(beta_canary not in record["text"] for record in recalled)


def test_deletion_propagation_oracles_satisfied_on_secured_profile():
    result = run_campaign(SecurityProfile.SECURED)
    evidence = {item.oracle_id: item for item in result.evidence}
    assert evidence["oracle.cache.deletion_propagation"].outcome is Outcome.SATISFIED
    assert evidence["oracle.memory.deletion_propagation"].outcome is Outcome.SATISFIED
    assert result.exit_code == 0


def test_stale_cache_after_deletion_fault_is_detected():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(stale_cache_after_deletion=True)
    )
    evidence = _evidence_map(run)
    assert evidence["oracle.cache.deletion_propagation"].outcome is Outcome.VIOLATION


def test_stale_memory_after_deletion_fault_is_detected():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(stale_memory_after_deletion=True)
    )
    evidence = _evidence_map(run)
    assert evidence["oracle.memory.deletion_propagation"].outcome is Outcome.VIOLATION


def test_propagation_oracles_isolated_worker_round_trip():
    """The propagation payload must survive snapshot serialization unchanged."""

    vulnerable_run = run_revocation_scenario(
        SecurityProfile.SECURED,
        faults=FaultFlags(stale_cache_after_deletion=True, stale_memory_after_deletion=True),
    )
    in_process = _evidence_map(vulnerable_run)
    isolated = run_oracles_isolated(vulnerable_run)
    assert isolated.oracle_pid != os.getpid()
    isolated_map = {item.oracle_id: item for item in isolated.evidence}
    assert (
        isolated_map["oracle.cache.deletion_propagation"].outcome
        == in_process["oracle.cache.deletion_propagation"].outcome
        is Outcome.VIOLATION
    )
    assert (
        isolated_map["oracle.memory.deletion_propagation"].outcome
        == in_process["oracle.memory.deletion_propagation"].outcome
        is Outcome.VIOLATION
    )
