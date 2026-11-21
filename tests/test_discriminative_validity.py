"""Discriminative validity (G2): inject one fault, detect exactly it."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from redfence.bench.oracles import default_oracles
from redfence.bench.runner import (
    SUPPORTED_FAULTS,
    discriminative_validity,
    run_campaign,
    run_demo,
)
from redfence.bench.scenario import run_revocation_scenario
from redfence.cli import main
from redfence.core.evidence import Outcome
from redfence.targets.config import FAULT_ORACLE, FaultFlags, SecurityProfile


@pytest.mark.parametrize("fault", SUPPORTED_FAULTS)
def test_single_fault_is_detected_by_its_oracle(fault: str):
    flags = FaultFlags(**{fault: True})
    run = run_revocation_scenario(SecurityProfile.SECURED, faults=flags)
    evidence = {
        item.oracle_id: item for item in (oracle.score(run) for oracle in default_oracles())
    }
    assert evidence[FAULT_ORACLE[fault]].outcome is Outcome.VIOLATION


@pytest.mark.parametrize("fault", SUPPORTED_FAULTS)
def test_single_fault_isolated_from_secured(fault: str):
    """The same fault must NOT be reported against the fully secured profile."""

    secured = run_campaign(SecurityProfile.SECURED)
    evidence = {item.oracle_id: item for item in secured.evidence}
    assert evidence[FAULT_ORACLE[fault]].outcome is not Outcome.VIOLATION


def test_demo_discriminative_validity_passes():
    validity, _, _ = run_demo()
    assert validity.overall is True
    assert validity.secured_violations == []


@dataclass
class _FakeEvidence:
    oracle_id: str
    outcome: Outcome


@dataclass
class _FakeResult:
    evidence: list[_FakeEvidence] = field(default_factory=list)
    json_path: None = None
    html_path: None = None

    @property
    def has_violation(self) -> bool:
        return any(item.outcome is Outcome.VIOLATION for item in self.evidence)

    @property
    def has_inconclusive(self) -> bool:
        return any(
            item.outcome in (Outcome.INCONCLUSIVE, Outcome.UNSUPPORTED)
            for item in self.evidence
        )

    @property
    def exit_code(self) -> int:
        if self.has_violation:
            return 1
        if self.has_inconclusive:
            return 2
        return 0


def _mapped_oracle_ids() -> list[str]:
    return sorted({FAULT_ORACLE[fault] for fault in SUPPORTED_FAULTS})


def _uniform_mapped_evidence(
    secured_outcome: Outcome,
    vulnerable_outcome: Outcome = Outcome.VIOLATION,
) -> tuple[_FakeResult, _FakeResult]:
    """Every mapped oracle carries the same outcome on each side."""

    oracle_ids = _mapped_oracle_ids()
    secured = _FakeResult([_FakeEvidence(oracle_id, secured_outcome) for oracle_id in oracle_ids])
    vulnerable = _FakeResult(
        [_FakeEvidence(oracle_id, vulnerable_outcome) for oracle_id in oracle_ids]
    )
    return secured, vulnerable


def _mapped_evidence(secured_outcome: Outcome) -> tuple[_FakeResult, _FakeResult]:
    oracle_ids = _mapped_oracle_ids()
    secured = _FakeResult(
        [
            _FakeEvidence(
                oracle_id,
                Outcome.UNSUPPORTED
                if oracle_id == "oracle.index.acl"
                else secured_outcome,
            )
            for oracle_id in oracle_ids
        ]
    )
    vulnerable = _FakeResult(
        [_FakeEvidence(oracle_id, Outcome.VIOLATION) for oracle_id in oracle_ids]
    )
    return secured, vulnerable


def test_secured_unsupported_makes_check_not_ok_and_demo_exits_two(monkeypatch):
    """An unevaluable secured facet is a failed measurement, not a pass."""

    secured, vulnerable = _mapped_evidence(Outcome.SATISFIED)
    validity = discriminative_validity(secured, vulnerable)
    check = next(
        item for item in validity.checks if item["oracle_id"] == "oracle.index.acl"
    )
    assert check["secured"] == Outcome.UNSUPPORTED.value
    assert check["ok"] is False
    assert validity.overall is False

    monkeypatch.setattr(
        "redfence.cli.run_demo", lambda **_: (validity, secured, vulnerable)
    )
    assert main(["demo"]) == 2


def test_secured_missing_oracle_evidence_makes_check_not_ok():
    """An oracle absent from the secured evidence is unevaluable, not a pass."""

    secured, vulnerable = _uniform_mapped_evidence(Outcome.SATISFIED)
    secured.evidence = [
        item for item in secured.evidence if item.oracle_id != "oracle.index.acl"
    ]
    validity = discriminative_validity(secured, vulnerable)
    check = next(
        item for item in validity.checks if item["oracle_id"] == "oracle.index.acl"
    )
    assert check["secured"] == "missing"
    assert check["ok"] is False
    assert validity.overall is False


def test_secured_inconclusive_makes_check_not_ok():
    """A secured side that could not decide the facet is a failed measurement."""

    secured, vulnerable = _uniform_mapped_evidence(Outcome.SATISFIED)
    secured.evidence = [
        _FakeEvidence(item.oracle_id, Outcome.INCONCLUSIVE)
        if item.oracle_id == "oracle.index.tenant"
        else item
        for item in secured.evidence
    ]
    validity = discriminative_validity(secured, vulnerable)
    check = next(
        item for item in validity.checks if item["oracle_id"] == "oracle.index.tenant"
    )
    assert check["secured"] == Outcome.INCONCLUSIVE.value
    assert check["ok"] is False
    assert validity.overall is False


@pytest.mark.parametrize("outcome", [Outcome.UNSUPPORTED, Outcome.INCONCLUSIVE])
def test_vulnerable_unevaluable_makes_check_not_ok(outcome: Outcome):
    """The vulnerable side must actually violate; unevaluable is not a detection."""

    secured, vulnerable = _uniform_mapped_evidence(Outcome.SATISFIED)
    vulnerable.evidence = [
        _FakeEvidence(item.oracle_id, outcome)
        if item.oracle_id == "oracle.index.tenant"
        else item
        for item in vulnerable.evidence
    ]
    validity = discriminative_validity(secured, vulnerable)
    check = next(
        item for item in validity.checks if item["oracle_id"] == "oracle.index.tenant"
    )
    assert check["vulnerable"] == outcome.value
    assert check["ok"] is False
    assert validity.overall is False

