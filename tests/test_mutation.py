"""Mutation-harness self-test (T11 / ADR-0016).

The harness is self-proving: the known-good mutant must be killed by its mapped
oracle and the known-bad mutant must survive. The script's ``main`` returns 2
when either expectation fails.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from redfence.bench.mutation import Mutant, known_bad, known_good, run_registry

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mutation_module():
    return _load_script("run_mutation")


def test_known_good_is_killed():
    report = run_registry(known_good())

    assert report.matched == 1
    assert report.unexpected == 0
    assert report.killed == 1
    assert report.survived == 0
    assert report.score == 1.0
    assert report.results[0].as_expected is True
    assert report.results[0].expected_oracle == "oracle.cache.leak"
    assert report.results[0].observed_outcome == "violation"


def test_known_bad_survives():
    report = run_registry(known_bad())

    assert report.matched == 1
    assert report.unexpected == 0
    assert report.killed == 0
    assert report.survived == 1
    assert report.score == 1.0
    assert report.results[0].as_expected is True
    assert report.results[0].observed_outcome == "satisfied"


def test_empty_registry_scores_zero():
    report = run_registry([])

    assert report.results == []
    assert report.matched == 0
    assert report.unexpected == 0
    assert report.killed == 0
    assert report.survived == 0
    assert report.score == 0.0


def test_registry_is_deterministic():
    first = run_registry(known_good() + known_bad())
    second = run_registry(known_good() + known_bad())

    assert first == second


def test_mismatched_expectation_is_unexpected():
    surviving_known_good = Mutant(
        id="cache-revalidation-bypass",
        description="surviving stand-in for the known-good mutant",
        apply=known_bad()[0].apply,
        expected_oracle="oracle.cache.leak",
        expected_outcome="violation",
    )
    report = run_registry([surviving_known_good])

    assert report.results[0].observed_outcome == "satisfied"
    assert report.results[0].as_expected is False
    assert report.results[0].killed is False
    assert report.results[0].survived is False
    assert report.matched == 0
    assert report.unexpected == 1
    assert report.score == 0.0


def test_script_exits_zero_on_builtin_registry(mutation_module):
    assert mutation_module.main([]) == 0


def test_script_exits_two_when_known_good_survives(mutation_module, monkeypatch):
    surviving_known_good = Mutant(
        id="cache-revalidation-bypass",
        description="surviving stand-in for the known-good mutant",
        apply=known_bad()[0].apply,
        expected_oracle="oracle.cache.leak",
        expected_outcome="violation",
    )
    monkeypatch.setattr(mutation_module, "known_good", lambda: [surviving_known_good])

    assert mutation_module.main([]) == 2
