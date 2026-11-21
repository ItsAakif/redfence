"""Metric definitions and statistical helpers."""

from __future__ import annotations

import pytest

from redfence.bench.evaluation import cache_hit_findings
from redfence.bench.metrics import (
    clustered_bootstrap_ci,
    compute_metrics,
    paired_cluster_bootstrap_difference,
    rate,
    wilson_interval,
)
from redfence.bench.oracles import CacheLeakOracle
from redfence.bench.runner import run_campaign
from redfence.targets.config import SecurityProfile


def test_wilson_bounds_are_valid():
    low, high = wilson_interval(3, 10)
    assert low is not None and high is not None
    assert 0.0 <= low <= high <= 1.0


def test_rate_undefined_with_zero_denominator():
    result = rate(0, 0)
    assert result.value is None
    assert result.defined is False


def test_rate_value_and_ci():
    result = rate(1, 2)
    assert result.value == 0.5
    assert result.ci_low is not None and result.ci_high is not None


def test_clustered_bootstrap_is_deterministic_and_bounded():
    values = [0.0, 0.0, 1.0, 1.0, 1.0, 0.0]
    clusters = ["a", "a", "b", "b", "c", "c"]
    first = clustered_bootstrap_ci(values, clusters, n_resamples=500, seed=7)
    second = clustered_bootstrap_ci(values, clusters, n_resamples=500, seed=7)
    assert first == second
    assert first[0] is not None and first[1] is not None
    assert 0.0 <= first[0] <= first[1] <= 1.0


def test_paired_cluster_bootstrap_difference():
    before = [0.0, 0.0, 1.0, 1.0]
    after = [1.0, 1.0, 1.0, 1.0]
    low, high = paired_cluster_bootstrap_difference(
        before, after, ["a", "a", "b", "b"], n_resamples=500, seed=11
    )
    assert low is not None and high is not None
    assert low <= high
    assert low >= -1.0 and high <= 1.0


def test_secured_metrics_preserve_utility():
    result = run_campaign(SecurityProfile.SECURED)
    assert result.metrics.benign_task_success.value == 1.0


def test_benign_task_success_is_undefined_without_utility_observation():
    # ADR-0009: a missing utility observation is undefined, not a measured failure.
    result = run_campaign(SecurityProfile.SECURED)
    result.run.utility_obs = None
    metrics = compute_metrics(result.run, result.evidence)
    assert metrics.benign_task_success.defined is False
    assert metrics.benign_task_success.value is None
    assert metrics.benign_task_success.denominator == 0


@pytest.mark.parametrize(
    "profile", [SecurityProfile.SECURED, SecurityProfile.VULNERABLE]
)
def test_cache_metric_numerator_equals_hits_with_findings(profile):
    result = run_campaign(profile)
    hits = [obs for obs in result.run.answer_obs if obs["cache_hit"]]
    assert hits, "the scenario must exercise at least one cache hit"
    expected = sum(1 for obs in hits if cache_hit_findings(obs, result.run.corpus))
    assert result.metrics.cache_leakage.numerator == expected
    assert result.metrics.cache_leakage.denominator == len(hits)


@pytest.mark.parametrize(
    "profile", [SecurityProfile.SECURED, SecurityProfile.VULNERABLE]
)
def test_cache_metric_and_oracle_agree_per_hit(profile):
    result = run_campaign(profile)
    hits = [obs for obs in result.run.answer_obs if obs["cache_hit"]]
    assert hits, "the scenario must exercise at least one cache hit"
    evidence = CacheLeakOracle().score(result.run)
    phases_with_findings = {event.split(":", 1)[0] for event in evidence.events}
    for obs in hits:
        expected = bool(cache_hit_findings(obs, result.run.corpus))
        reported = obs["phase"] in phases_with_findings
        assert expected is reported, f"metric/oracle divergence for {obs['phase']}"


def test_vulnerable_metrics_show_disclosure():
    result = run_campaign(SecurityProfile.VULNERABLE)
    assert result.metrics.attack_success.value == 1.0
    assert result.metrics.data_disclosure.value is not None
    assert result.metrics.data_disclosure.value > 0.0


def test_metrics_report_is_serializable():
    result = run_campaign(SecurityProfile.SECURED)
    payload = result.metrics.model_dump(mode="json")
    assert "unauthorized_retrieval" in payload
    assert "notes" in payload
