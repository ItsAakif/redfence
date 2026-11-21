"""Statistics reporting units (T3.5, ADR-0012).

The statistics layer counts executable scenarios, not facet labels. These tests
use one seed per campaign; the real 25-seed sweep is exercised by the script,
not by the unit suite.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from redfence.bench.dataset import DEV_FAMILIES
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_statistics.py"


def _load_statistics():
    spec = importlib.util.spec_from_file_location("run_statistics_under_test", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def statistics_module():
    return _load_statistics()


@dataclass
class _FakeEvidence:
    outcome: Outcome


@dataclass
class _FakeResult:
    evidence: list[_FakeEvidence]

    @property
    def has_inconclusive(self) -> bool:
        return any(
            item.outcome in (Outcome.INCONCLUSIVE, Outcome.UNSUPPORTED)
            for item in self.evidence
        )


def _fake_result(outcome: Outcome) -> _FakeResult:
    return _FakeResult([_FakeEvidence(outcome)])


def _install_outcomes(monkeypatch, statistics_module, secured, vulnerable) -> None:
    def fake_run(family, profile, seed, template="classic"):
        outcomes = secured if profile is SecurityProfile.SECURED else vulnerable
        return _fake_result(outcomes[seed])

    monkeypatch.setattr(statistics_module, "_run", fake_run)


def test_statistics_families_are_eight_unique_scenarios(statistics_module):
    families = statistics_module.STATISTICS_FAMILIES
    assert len(families) == 8
    assert len(set(families)) == len(families)
    assert families[0] == "revocation"


def test_statistics_families_are_disjoint_from_dev_facets(statistics_module):
    assert set(statistics_module.STATISTICS_FAMILIES) & set(DEV_FAMILIES) == set()


def test_eight_families_have_distinct_scenario_ids(statistics_module):
    results = [
        statistics_module._run(family, SecurityProfile.SECURED, 20260101, "classic")
        for family in statistics_module.STATISTICS_FAMILIES
    ]
    assert len({result.scenario_id for result in results}) == 8


def test_revocation_family_runs_dev_campaign(statistics_module):
    result = statistics_module._run(
        "revocation", SecurityProfile.SECURED, 20260101, "classic"
    )
    assert result.run.scenario_kind == "revocation"


def test_module_import_has_no_side_effects(monkeypatch, capsys):
    calls: list[str] = []

    def fail_campaign(*args, **kwargs):
        calls.append("campaign")
        raise AssertionError("run_campaign called at import time")

    def fail_heldout(*args, **kwargs):
        calls.append("heldout")
        raise AssertionError("run_heldout_scenario called at import time")

    monkeypatch.setattr("redfence.bench.runner.run_campaign", fail_campaign)
    monkeypatch.setattr("redfence.bench.heldout.run_heldout_scenario", fail_heldout)
    _load_statistics()
    captured = capsys.readouterr()
    assert calls == []
    assert captured.out == ""
    assert captured.err == ""


def test_unevaluable_outcome_is_not_clean_and_forces_exit_2(
    statistics_module, monkeypatch
):
    _install_outcomes(
        monkeypatch,
        statistics_module,
        {
            20260101: Outcome.SATISFIED,
            20260102: Outcome.SATISFIED,
        },
        {
            20260101: Outcome.VIOLATION,
            20260102: Outcome.UNSUPPORTED,
        },
    )
    statistic = statistics_module._statistic(
        "revocation", [20260101, 20260102], "classic"
    )
    assert statistic.clusters == 2
    assert statistic.evaluable_clusters == 1
    assert statistic.evaluable is False
    assert statistic.vulnerable_mean == 1.0
    assert statistic.separated is False
    assert statistics_module._exit_code([statistic]) == 2


def test_exit_code_zero_when_every_row_separates(statistics_module, monkeypatch):
    _install_outcomes(
        monkeypatch,
        statistics_module,
        {20260101: Outcome.SATISFIED},
        {20260101: Outcome.VIOLATION},
    )
    statistic = statistics_module._statistic("revocation", [20260101], "classic")
    assert statistic.evaluable is True
    assert statistic.separated is True
    assert statistics_module._exit_code([statistic]) == 0


def test_exit_code_one_when_secured_mean_is_positive(statistics_module, monkeypatch):
    _install_outcomes(
        monkeypatch,
        statistics_module,
        {20260101: Outcome.VIOLATION},
        {20260101: Outcome.VIOLATION},
    )
    statistic = statistics_module._statistic("revocation", [20260101], "classic")
    assert statistic.secured_mean == 1.0
    assert statistics_module._exit_code([statistic]) == 1
