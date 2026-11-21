"""Benchmark internals: dataset, scenario, oracles, metrics, runner."""

from redfence.bench.dataset import DATASET_VERSION, Corpus, build_corpus, scenario_id
from redfence.bench.metrics import MetricsReport, Rate, compute_metrics, wilson_interval
from redfence.bench.runner import (
    CampaignResult,
    DiscriminativeValidity,
    discriminative_validity,
    run_campaign,
    run_demo,
)
from redfence.bench.scenario import ScenarioRun, run_revocation_scenario

__all__ = [
    "DATASET_VERSION",
    "CampaignResult",
    "Corpus",
    "DiscriminativeValidity",
    "MetricsReport",
    "Rate",
    "ScenarioRun",
    "build_corpus",
    "compute_metrics",
    "discriminative_validity",
    "run_campaign",
    "run_demo",
    "run_revocation_scenario",
    "scenario_id",
    "wilson_interval",
]
