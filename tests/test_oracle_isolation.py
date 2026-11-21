"""The oracle must be able to run outside the target process."""

from __future__ import annotations

import os

from redfence.bench.isolated import serialize_run
from redfence.bench.oracle_worker import _reconstruct
from redfence.bench.runner import run_campaign
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile
from redfence.targets.tools import ToolExecution


def test_oracle_runs_in_a_separate_process():
    result = run_campaign(SecurityProfile.SECURED, isolated_oracles=True)
    assert result.oracle_pid is not None
    assert result.oracle_pid != os.getpid()
    assert result.exit_code == 0
    assert result.manifest["oracle_isolation"] == "subprocess"
    assert "oracle_pid" not in result.manifest
    outcomes = {item.oracle_id: item.outcome for item in result.evidence}
    assert outcomes["oracle.index.acl"] is Outcome.SATISFIED


def test_isolated_manifests_are_reproducible():
    first = run_campaign(SecurityProfile.SECURED, isolated_oracles=True)
    second = run_campaign(SecurityProfile.SECURED, isolated_oracles=True)
    assert first.manifest == second.manifest


def test_worker_reconstructs_typed_tool_executions():
    """Regression: the child must rebuild ToolExecution, not leave raw dicts."""

    run = run_revocation_scenario(SecurityProfile.VULNERABLE)
    rebuilt = _reconstruct(serialize_run(run))
    assert rebuilt.tool_obs
    assert all(isinstance(obs["execution"], ToolExecution) for obs in rebuilt.tool_obs)
    # The vulnerable profile bypasses the tool policy.
    assert any(not obs["execution"].policy_checked for obs in rebuilt.tool_obs)


def test_isolated_oracle_detects_vulnerable_profile():
    result = run_campaign(SecurityProfile.VULNERABLE, isolated_oracles=True)
    assert result.oracle_pid is not None
    assert result.oracle_pid != os.getpid()
    assert result.exit_code == 1
    assert any(item.outcome is Outcome.VIOLATION for item in result.evidence)
