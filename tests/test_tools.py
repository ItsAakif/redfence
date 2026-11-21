"""Tool authorization and contained exfiltration."""

from __future__ import annotations

from redfence.bench.oracles import ToolPolicyOracle
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile


def test_secured_tool_policy_holds():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert ToolPolicyOracle().score(run).outcome is Outcome.SATISFIED


def test_secured_no_simulated_egress_occurs():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert run.target.tools.sink == []


def test_tool_policy_bypass_is_detected_and_contained():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(unauthorized_tool_execution=True)
    )
    assert ToolPolicyOracle().score(run).outcome is Outcome.VIOLATION
    # Exfiltration is captured by the controlled sink, never sent externally.
    assert len(run.target.tools.sink) >= 1
