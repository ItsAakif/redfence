"""Fault/oracle coverage (D7): the mapping is complete and executable.

These tests fail when a ``FaultFlags`` field is added without a ``FAULT_ORACLE``
mapping, when a mapping points at a nonexistent oracle, or when a supported
fault drops out of the single-fault discriminative-validity parametrization.
The parametrization is read from ``tests/test_discriminative_validity.py``
rather than duplicated as a hand-written list so the two cannot drift.

ADR-0008 exempts ``CoverageOracle`` from the vacuity policy because it is a
declaration, not a measurement. Its declaration is asserted separately: when
every supported fault is enabled it must report no unsupported gap.
"""

from __future__ import annotations

from test_discriminative_validity import (
    test_single_fault_is_detected_by_its_oracle as _single_fault_test,
)

from redfence.bench.dataset import build_corpus
from redfence.bench.oracles import CoverageOracle, default_oracles
from redfence.bench.runner import SUPPORTED_FAULTS
from redfence.bench.scenario import ScenarioRun
from redfence.core.evidence import Outcome
from redfence.targets.config import FAULT_ORACLE, UNSUPPORTED_FAULTS, FaultFlags
from redfence.targets.rag_target import ConfigurableRAGTarget


def _parametrized_faults() -> list[str]:
    """Read the fault ids directly from the single-fault parametrization."""

    marks = _single_fault_test.pytestmark
    if not isinstance(marks, list):
        marks = [marks]
    parametrize = [mark for mark in marks if getattr(mark, "name", None) == "parametrize"]
    assert len(parametrize) == 1, "expected exactly one parametrize mark"

    argnames, argvalues = parametrize[0].args
    assert argnames == "fault"

    faults: list[str] = []
    for value in argvalues:
        if isinstance(value, str):
            faults.append(value)
        elif isinstance(value, (tuple, list)) and len(value) == 1 and isinstance(value[0], str):
            faults.append(value[0])
        else:  # pragma: no cover - defensive: unexpected parametrization shape
            raise AssertionError(f"unexpected single-fault parameter: {value!r}")
    return faults


def test_fault_flags_match_fault_oracle_mapping() -> None:
    """Every fault flag has exactly one oracle mapping, and vice versa."""

    assert set(FaultFlags.model_fields) == set(FAULT_ORACLE)


def test_fault_oracle_targets_are_default_oracles() -> None:
    """No mapping may target an oracle id that the default set does not score."""

    oracle_ids = {oracle.oracle_id for oracle in default_oracles()}
    assert set(FAULT_ORACLE.values()) <= oracle_ids


def test_supported_faults_are_mapped_minus_unsupported() -> None:
    assert set(SUPPORTED_FAULTS) == set(FAULT_ORACLE) - set(UNSUPPORTED_FAULTS)


def test_supported_fault_count_is_twelve() -> None:
    assert len(SUPPORTED_FAULTS) == 12


def test_single_fault_parametrization_matches_supported_faults() -> None:
    """The G2 parametrization must cover every supported fault and no others."""

    parametrized = _parametrized_faults()

    assert len(parametrized) == len(set(parametrized)), "duplicate single-fault parameters"
    assert set(parametrized) == set(SUPPORTED_FAULTS)


def test_every_mapped_oracle_is_scored_and_exercised() -> None:
    """Every mapped target is a scored oracle reached by a supported fault.

    The single-fault parametrization runs each supported fault through a real
    secured scenario, so those faults are the scored campaign paths that
    exercise the mapped oracles. The 42-cell sweep is deliberately not run here.
    """

    scored_ids = {
        oracle.oracle_id
        for oracle in default_oracles()
        if oracle.oracle_id != CoverageOracle.oracle_id
    }
    targets = set(FAULT_ORACLE.values())

    assert targets <= scored_ids
    assert {FAULT_ORACLE[fault] for fault in _parametrized_faults()} == targets


def test_coverage_oracle_declares_every_supported_fault() -> None:
    """ADR-0008 exemption: the coverage declaration must show no supported gap."""

    flags = FaultFlags(**{fault: True for fault in SUPPORTED_FAULTS})
    run = ScenarioRun(
        scenario_id="scn_fault_coverage_all_supported",
        profile="fault-coverage",
        corpus=build_corpus(),
        target=ConfigurableRAGTarget(name="fault-coverage", faults=flags),
    )

    evidence = CoverageOracle().score(run)

    assert evidence.oracle_id == CoverageOracle.oracle_id
    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.observed == "no unsupported faults enabled"
