"""Clustered statistics over the scenario families (G5).

Runs the single development revocation scenario and every held-out family
across many dataset seeds and aggregates the binary security outcome per family
with a *clustered* bootstrap. One seed is one cluster: the paraphrases and
repeated turns produced inside a seed are correlated and must never be treated
as independent samples.

The target is deterministic, so a passing/failing family is expected to be
stable across seeds. That is reported explicitly: a zero-width interval here
means "invariant across seeds", not "a human study with zero variance".
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from redfence.bench.dataset import TEMPLATES
from redfence.bench.heldout import HELDOUT_FAMILIES, run_heldout_scenario
from redfence.bench.metrics import clustered_bootstrap_ci, paired_cluster_bootstrap_difference
from redfence.bench.runner import CampaignResult, run_campaign
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile

# The statistics unit is an executable scenario, not a facet label. The six
# DEV_FAMILIES names are facets of the one revocation scenario and are counted
# once here, never as separate families (see ADR-0012).
STATISTICS_FAMILIES: tuple[str, ...] = ("revocation",) + HELDOUT_FAMILIES


@dataclass
class FamilyStatistic:
    family: str
    clusters: int
    secured_mean: float | None
    secured_ci_low: float | None
    secured_ci_high: float | None
    vulnerable_mean: float | None
    vulnerable_ci_low: float | None
    vulnerable_ci_high: float | None
    mean_difference: float | None
    difference_ci_low: float | None
    difference_ci_high: float | None
    separated: bool
    deterministic_across_seeds: bool
    template: str = "classic"
    evaluable: bool = True
    evaluable_clusters: int = 0


def _outcome(result: CampaignResult) -> float | None:
    """Return 1.0/0.0, or None when the campaign could not be evaluated.

    An inconclusive or unsupported oracle means the campaign did not measure the
    facet; encoding that as a clean 0.0 would overstate separation.
    """

    if result.has_inconclusive:
        return None
    return 1.0 if any(item.outcome is Outcome.VIOLATION for item in result.evidence) else 0.0


def _run(
    family: str,
    profile: SecurityProfile,
    seed: int,
    template: str = "classic",
) -> CampaignResult:
    if family == "revocation":
        return run_campaign(profile, seed=seed, template=template)
    return run_heldout_scenario(family, profile, seed=seed, template=template)


def _statistic(family: str, seeds: list[int], template: str = "classic") -> FamilyStatistic:
    secured: list[float] = []
    vulnerable: list[float] = []
    evaluable_clusters: list[str] = []
    for seed in seeds:
        secured_outcome = _outcome(_run(family, SecurityProfile.SECURED, seed, template))
        vulnerable_outcome = _outcome(_run(family, SecurityProfile.VULNERABLE, seed, template))
        if secured_outcome is None or vulnerable_outcome is None:
            continue
        secured.append(secured_outcome)
        vulnerable.append(vulnerable_outcome)
        evaluable_clusters.append(str(seed))

    if evaluable_clusters:
        secured_ci = clustered_bootstrap_ci(secured, evaluable_clusters, seed=seed_of(seeds))
        vulnerable_ci = clustered_bootstrap_ci(
            vulnerable, evaluable_clusters, seed=seed_of(seeds)
        )
        difference_ci = paired_cluster_bootstrap_difference(
            secured, vulnerable, evaluable_clusters, seed=seed_of(seeds)
        )
        secured_mean = sum(secured) / len(secured)
        vulnerable_mean = sum(vulnerable) / len(vulnerable)
        mean_difference = vulnerable_mean - secured_mean
    else:
        secured_ci = (None, None)
        vulnerable_ci = (None, None)
        difference_ci = (None, None)
        secured_mean = None
        vulnerable_mean = None
        mean_difference = None

    evaluable = len(evaluable_clusters) == len(seeds)
    separated = (
        evaluable
        and secured_mean == 0.0
        and vulnerable_mean == 1.0
    )
    deterministic = (
        evaluable and len(set(secured)) == 1 and len(set(vulnerable)) == 1
    )
    return FamilyStatistic(
        family=family,
        clusters=len(seeds),
        secured_mean=secured_mean,
        secured_ci_low=secured_ci[0],
        secured_ci_high=secured_ci[1],
        vulnerable_mean=vulnerable_mean,
        vulnerable_ci_low=vulnerable_ci[0],
        vulnerable_ci_high=vulnerable_ci[1],
        mean_difference=mean_difference,
        difference_ci_low=difference_ci[0],
        difference_ci_high=difference_ci[1],
        separated=separated,
        deterministic_across_seeds=deterministic,
        evaluable=evaluable,
        evaluable_clusters=len(evaluable_clusters),
        template=template,
    )


def seed_of(seeds: list[int]) -> int:
    return seeds[0] if seeds else 0


def _exit_code(statistics: list[FamilyStatistic]) -> int:
    """ADR-0011: 1 on a secured violation, 2 on invalid statistics, else 0."""

    if any(item.secured_mean is not None and item.secured_mean > 0.0 for item in statistics):
        return 1
    if any(not item.evaluable or not item.separated for item in statistics):
        return 2
    return 0


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=25, help="number of dataset seeds")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--templates",
        action="store_true",
        help="sweep every corpus template instead of classic only",
    )
    args = parser.parse_args(argv)
    seeds = [20260101 + index for index in range(args.seeds)]
    families = list(STATISTICS_FAMILIES)
    templates = list(TEMPLATES) if args.templates else ["classic"]
    statistics = [
        _statistic(family, seeds, template) for template in templates for family in families
    ]

    if args.json:
        print(json.dumps([asdict(item) for item in statistics], indent=2))
        return _exit_code(statistics)

    for item in statistics:
        prefix = f"template={item.template} " if args.templates else ""
        print(f"{prefix}family={item.family}")
        print(
            f"  clusters={item.clusters} evaluable_clusters={item.evaluable_clusters} "
            f"secured={_fmt(item.secured_mean)} "
            f"ci=[{_fmt(item.secured_ci_low)},{_fmt(item.secured_ci_high)}] "
            f"vulnerable={_fmt(item.vulnerable_mean)} "
            f"ci=[{_fmt(item.vulnerable_ci_low)},{_fmt(item.vulnerable_ci_high)}]"
        )
        print(
            f"  difference={_fmt(item.mean_difference)} "
            f"ci=[{_fmt(item.difference_ci_low)},{_fmt(item.difference_ci_high)}] "
            f"separated={item.separated} "
            f"evaluable={item.evaluable} "
            f"deterministic_across_seeds={item.deterministic_across_seeds}"
        )
    family_count = len({item.family for item in statistics})
    separated = sum(1 for item in statistics if item.separated)
    unevaluable = sum(1 for item in statistics if not item.evaluable)
    print(
        f"\nfamilies={family_count} rows={len(statistics)} separated={separated} "
        f"unevaluable={unevaluable} "
        f"all_deterministic={all(item.deterministic_across_seeds for item in statistics)}"
    )
    print(
        "note: zero-width intervals mean the deterministic target is invariant across seeds; "
        "they are not evidence of a zero-variance human sample."
    )
    print(
        f"note: {family_count} scenario families; the six dev facet labels are facets of "
        "one scenario and are not independent samples."
    )
    return _exit_code(statistics)


if __name__ == "__main__":
    raise SystemExit(main())
