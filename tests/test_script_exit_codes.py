"""Entry-point exit-code contract (T4.2 / ADR-0011).

The scripts expose ``main(argv)`` so these tests can exercise the classification
logic without a real 42-cell sweep or a 25-seed statistics run.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from redfence.bench.runner import run_campaign
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile

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
def heldout_module():
    return _load_script("run_heldout")


@pytest.fixture()
def sweep_module():
    return _load_script("run_template_sweep")


@pytest.fixture()
def statistics_module():
    return _load_script("run_statistics")


@dataclass
class _FakeEvidence:
    oracle_id: str
    outcome: Outcome


@dataclass
class _FakeResult:
    evidence: list[_FakeEvidence] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if any(item.outcome is Outcome.VIOLATION for item in self.evidence):
            return 1
        if any(
            item.outcome in (Outcome.INCONCLUSIVE, Outcome.UNSUPPORTED)
            for item in self.evidence
        ):
            return 2
        return 0


def _result(outcome: Outcome) -> _FakeResult:
    return _FakeResult([_FakeEvidence("oracle.test", outcome)])


def _install_heldout(monkeypatch, module, secured, vulnerable) -> None:
    def fake_scenario(family, profile, **kwargs):
        return secured if profile is SecurityProfile.SECURED else vulnerable

    monkeypatch.setattr(module, "run_heldout_scenario", fake_scenario)


def test_heldout_normal_family_returns_zero(heldout_module, monkeypatch, tmp_path):
    _install_heldout(
        monkeypatch,
        heldout_module,
        _result(Outcome.SATISFIED),
        _result(Outcome.VIOLATION),
    )
    assert heldout_module.main(["--out", str(tmp_path)]) == 0


def test_heldout_secured_violation_returns_one(heldout_module, monkeypatch, tmp_path):
    _install_heldout(
        monkeypatch,
        heldout_module,
        _result(Outcome.VIOLATION),
        _result(Outcome.VIOLATION),
    )
    assert heldout_module.main(["--out", str(tmp_path)]) == 1


def test_heldout_non_discriminating_family_returns_two(
    heldout_module, monkeypatch, tmp_path
):
    _install_heldout(
        monkeypatch,
        heldout_module,
        _result(Outcome.SATISFIED),
        _result(Outcome.SATISFIED),
    )
    assert heldout_module.main(["--out", str(tmp_path)]) == 2


def test_heldout_worker_error_is_measurement_failure(
    heldout_module, monkeypatch, tmp_path
):
    def boom(family, profile, **kwargs):
        raise RuntimeError("oracle worker failed")

    monkeypatch.setattr(heldout_module, "run_heldout_scenario", boom)
    assert heldout_module.main(["--out", str(tmp_path)]) == 2


def test_template_sweep_exit_codes(sweep_module):
    assert sweep_module._exit_code(["classic/secured"], []) == 1
    assert sweep_module._exit_code([], ["classic/fault=x"]) == 2
    assert sweep_module._exit_code(["classic/secured"], ["classic/fault=x"]) == 1
    assert sweep_module._exit_code([], []) == 0


def _statistic_row(module, *, secured_mean, separated, evaluable=True):
    return module.FamilyStatistic(
        family="revocation",
        clusters=1,
        secured_mean=secured_mean,
        secured_ci_low=secured_mean,
        secured_ci_high=secured_mean,
        vulnerable_mean=1.0,
        vulnerable_ci_low=1.0,
        vulnerable_ci_high=1.0,
        mean_difference=None if secured_mean is None else 1.0 - secured_mean,
        difference_ci_low=None,
        difference_ci_high=None,
        separated=separated,
        deterministic_across_seeds=evaluable,
        evaluable=evaluable,
        evaluable_clusters=1 if evaluable else 0,
    )


def test_statistics_exit_codes(statistics_module):
    violation = _statistic_row(
        statistics_module, secured_mean=1.0, separated=True
    )
    invalid = _statistic_row(statistics_module, secured_mean=0.0, separated=False)
    unevaluable = _statistic_row(
        statistics_module, secured_mean=None, separated=False, evaluable=False
    )
    clean = _statistic_row(statistics_module, secured_mean=0.0, separated=True)

    assert statistics_module._exit_code([violation]) == 1
    assert statistics_module._exit_code([invalid]) == 2
    assert statistics_module._exit_code([unevaluable]) == 2
    assert statistics_module._exit_code([clean]) == 0


def test_partial_profile_is_deterministic_and_exits_one():
    first = run_campaign(SecurityProfile.PARTIAL)
    second = run_campaign(SecurityProfile.PARTIAL)

    assert first.exit_code == 1
    assert first.to_dict() == second.to_dict()
    violations = {item.oracle_id for item in first.evidence if item.is_violation}
    assert {
        "oracle.index.acl",
        "oracle.cache.key_scope",
        "oracle.context.exposure",
        "oracle.response.disclosure",
    } <= violations
