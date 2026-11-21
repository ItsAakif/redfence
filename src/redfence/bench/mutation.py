"""Deterministic mutation harness for oracle self-validation (ADR-0016).

Mutants are monkeypatch-based context managers, never source rewrites. A
known-good mutant removes a security control and must be killed by its mapped
oracle; a known-bad mutant is behaviour-preserving and must survive. The
registry is deterministic, writes no files, and runs the secured campaign so a
surviving control is always a harness failure, not a measurement artifact.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from unittest.mock import patch

from redfence.bench.runner import run_campaign
from redfence.core.domain import Answer, CacheEntry, Principal
from redfence.targets.config import SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget


@dataclass(frozen=True)
class Mutant:
    id: str
    description: str
    apply: Callable[[], AbstractContextManager[object]]
    expected_oracle: str
    expected_outcome: str = "violation"


@dataclass(frozen=True)
class MutantResult:
    mutant_id: str
    expected_oracle: str
    expected_outcome: str
    observed_outcome: str
    as_expected: bool

    @property
    def killed(self) -> bool:
        return self.as_expected and self.expected_outcome == "violation"

    @property
    def survived(self) -> bool:
        return self.as_expected and self.expected_outcome == "satisfied"


@dataclass(frozen=True)
class MutationReport:
    results: list[MutantResult]

    @property
    def matched(self) -> int:
        return sum(1 for result in self.results if result.as_expected)

    @property
    def unexpected(self) -> int:
        return len(self.results) - self.matched

    @property
    def killed(self) -> int:
        return sum(1 for result in self.results if result.killed)

    @property
    def survived(self) -> int:
        return sum(1 for result in self.results if result.survived)

    @property
    def score(self) -> float:
        if not self.results:
            return 0.0
        return self.matched / len(self.results)


def _outcome_for(evidence, oracle_id: str) -> str:
    for item in evidence:
        if item.oracle_id == oracle_id:
            return item.outcome.value
    return "missing"


def run_registry(registry: list[Mutant]) -> MutationReport:
    """Apply each mutant, score a secured campaign, and record its outcome."""

    results: list[MutantResult] = []
    for mutant in registry:
        observed = "missing"
        with mutant.apply():
            campaign = run_campaign(SecurityProfile.SECURED)
            observed = _outcome_for(campaign.evidence, mutant.expected_oracle)
        results.append(
            MutantResult(
                mutant_id=mutant.id,
                expected_oracle=mutant.expected_oracle,
                expected_outcome=mutant.expected_outcome,
                observed_outcome=observed,
                as_expected=observed == mutant.expected_outcome,
            )
        )
    return MutationReport(results=results)


def _always_valid(self, entry: CacheEntry, principal: Principal) -> bool:
    """Known-good mutation: skip every cache revalidation check."""

    return True


def _bypass_cache_revalidation() -> AbstractContextManager[object]:
    return patch.object(ConfigurableRAGTarget, "_cache_valid", _always_valid)


_ORIGINAL_ANSWER = ConfigurableRAGTarget.answer


def _preserving_answer(
    self,
    principal: Principal,
    query: str,
    *,
    use_cache: bool = True,
) -> Answer:
    """Known-bad mutation: delegate to the original answer implementation."""

    return _ORIGINAL_ANSWER(self, principal, query, use_cache=use_cache)


def _preserve_answer_behaviour() -> AbstractContextManager[object]:
    return patch.object(ConfigurableRAGTarget, "answer", _preserving_answer)


def known_good() -> list[Mutant]:
    """Mutant that must be killed: cache revalidation is removed."""

    return [
        Mutant(
            id="cache-revalidation-bypass",
            description=(
                "Force ConfigurableRAGTarget._cache_valid to accept every entry, "
                "bypassing principal, revocation, epoch and freshness checks."
            ),
            apply=_bypass_cache_revalidation,
            expected_oracle="oracle.cache.leak",
            expected_outcome="violation",
        )
    ]


def known_bad() -> list[Mutant]:
    """Mutant that must survive: a behaviour-preserving answer wrapper."""

    return [
        Mutant(
            id="answer-passthrough",
            description=(
                "Wrap ConfigurableRAGTarget.answer with a pass-through call to the "
                "original implementation (no behaviour change)."
            ),
            apply=_preserve_answer_behaviour,
            expected_oracle="oracle.cache.leak",
            expected_outcome="satisfied",
        )
    ]


__all__ = [
    "Mutant",
    "MutantResult",
    "MutationReport",
    "known_bad",
    "known_good",
    "run_registry",
]
