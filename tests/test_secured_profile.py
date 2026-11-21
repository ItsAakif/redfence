"""Secured profile must satisfy every invariant, with no false alarms."""

from __future__ import annotations

from redfence.bench.runner import run_campaign
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile


def test_secured_profile_has_no_violations():
    result = run_campaign(SecurityProfile.SECURED)
    violations = [item.oracle_id for item in result.evidence if item.outcome is Outcome.VIOLATION]
    assert violations == []


def test_secured_profile_exit_code_is_zero():
    result = run_campaign(SecurityProfile.SECURED)
    assert result.exit_code == 0


def test_secured_utility_is_preserved():
    result = run_campaign(SecurityProfile.SECURED)
    utility = next(item for item in result.evidence if item.oracle_id == "oracle.utility.benign")
    assert utility.outcome is Outcome.SATISFIED


def test_secured_deletion_is_cascading():
    result = run_campaign(SecurityProfile.SECURED)
    deletion = next(item for item in result.evidence if item.oracle_id == "oracle.index.deletion")
    assert deletion.outcome is Outcome.SATISFIED
