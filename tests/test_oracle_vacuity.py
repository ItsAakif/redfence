"""ADR-0008 oracle vacuity policy: zero units must never mean SATISFIED.

Every non-coverage oracle is exercised twice:

* an empty ``ScenarioRun`` (nothing ingested, no observations) must produce
  ``Outcome.UNSUPPORTED`` with an observed string that names the missing unit;
* a realistic secured run must contain at least one unit and produce
  ``Outcome.SATISFIED`` when the invariant holds.

The final tests re-run every scored campaign and assert no scored oracle reports
``SATISFIED`` while its evaluable-unit count is zero.
"""

from __future__ import annotations

import pytest

from redfence.bench.dataset import HELDOUT_FAMILIES, TEMPLATES, build_corpus
from redfence.bench.heldout import run_heldout_scenario
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import run_campaign
from redfence.bench.scenario import ScenarioRun, run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget

NON_COVERAGE_ORACLES = [
    oracle
    for oracle in default_oracles()
    if getattr(oracle, "oracle_id", None) != "oracle.coverage.unsupported"
]

ORACLE_IDS = [oracle.oracle_id for oracle in NON_COVERAGE_ORACLES]

# Specific zero-unit reasons: each observed string must also carry the generic
# "no evaluable observation" phrase, but the unit that was missing must be named.
ZERO_UNIT_REASONS = {
    "oracle.index.acl": "no admitted same-tenant chunk",
    "oracle.index.tenant": "no admitted chunk",
    "oracle.index.deletion": "no deletion observation",
    "oracle.cache.key_scope": "no cache entry",
    "oracle.cache.leak": "no cache-hit answer observation",
    "oracle.cache.freshness": "no cache-hit answer observation",
    "oracle.cache.deletion_propagation": "no deletion observation carrying a propagation payload",
    "oracle.metadata.integrity": "no stored chunk resolvable",
    "oracle.context.exposure": "no context chunk",
    "oracle.response.disclosure": "no answer observation with a canary",
    "oracle.memory.scope": "no memory recall observation",
    "oracle.memory.deletion_propagation": "no deletion observation carrying a propagation payload",
    "oracle.tool.policy": "no tool-call observation",
    "oracle.utility.benign": "no utility observation",
}


def _zero_unit_run() -> ScenarioRun:
    """A run with an ingested-nothing target: every observation set is empty."""

    return ScenarioRun(
        scenario_id="scn_oracle_vacuity_empty",
        profile="vacuity",
        corpus=build_corpus(),
        target=ConfigurableRAGTarget(name="vacuity-empty", faults=FaultFlags()),
    )


def _context_has_canary(run: ScenarioRun, obs: dict[str, object]) -> bool:
    canaries = tuple(run.corpus.canaries.values())
    for meta in obs["context"]:
        chunk = run.target.store.get(str(meta["chunk_id"]))
        if chunk is not None and any(canary in chunk.text for canary in canaries):
            return True
    return False


def _unit_counts(run: ScenarioRun) -> dict[str, int]:
    """Mirror of ADR-0008's binding unit table for campaign sanity checks."""

    same_tenant_admitted = 0
    admitted = 0
    for obs in run.retrieval_obs:
        principal = run.corpus.principal(str(obs["principal_id"]))
        for item in obs["admitted"]:
            admitted += 1
            if item["tenant_id"] == principal.tenant_id:
                same_tenant_admitted += 1

    hits = sum(1 for obs in run.answer_obs if obs["cache_hit"])
    context_chunks = sum(len(obs["context"]) for obs in run.answer_obs)
    disclosure_opportunities = sum(
        1
        for obs in run.answer_obs
        if obs["canaries_present"] or _context_has_canary(run, obs)
    )
    propagation_payloads = sum(
        1 for deletion in run.deletion_obs if deletion.get("propagation")
    )
    resolvable_chunks = 0
    for chunk in run.target.store.all_chunks():
        try:
            run.corpus.document(chunk.doc_id)
        except KeyError:
            continue
        resolvable_chunks += 1

    return {
        "oracle.index.acl": same_tenant_admitted,
        "oracle.index.tenant": admitted,
        "oracle.index.deletion": len(run.deletion_obs),
        "oracle.cache.key_scope": len(run.target.cache),
        "oracle.cache.leak": hits,
        "oracle.cache.freshness": hits,
        "oracle.cache.deletion_propagation": propagation_payloads,
        "oracle.metadata.integrity": resolvable_chunks,
        "oracle.context.exposure": context_chunks,
        "oracle.response.disclosure": disclosure_opportunities,
        "oracle.memory.scope": len(run.memory_obs),
        "oracle.memory.deletion_propagation": propagation_payloads,
        "oracle.tool.policy": len(run.tool_obs),
        "oracle.utility.benign": 0 if run.utility_obs is None else 1,
        # Coverage is a declaration, not a measurement; ADR-0008 exempts it.
        "oracle.coverage.unsupported": 1,
    }


@pytest.fixture(scope="module")
def secured_run() -> ScenarioRun:
    return run_revocation_scenario(SecurityProfile.SECURED)


@pytest.fixture(scope="module")
def scored_campaigns():
    results: list[tuple[str, object]] = []
    for template in TEMPLATES:
        for profile in (SecurityProfile.SECURED, SecurityProfile.VULNERABLE):
            results.append(
                (
                    f"dev.{template}.{profile.value}",
                    run_campaign(profile, template=template),
                )
            )
    for family in HELDOUT_FAMILIES:
        for profile in (SecurityProfile.SECURED, SecurityProfile.VULNERABLE):
            results.append(
                (f"heldout.{family}.{profile.value}", run_heldout_scenario(family, profile))
            )
    return results


@pytest.mark.parametrize("oracle", NON_COVERAGE_ORACLES, ids=ORACLE_IDS)
def test_zero_units_is_unsupported(oracle):
    evidence = oracle.score(_zero_unit_run())

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert evidence.oracle_id == oracle.oracle_id
    assert evidence.facet == oracle.facet
    assert evidence.expected
    assert "no evaluable observation" in evidence.observed
    assert ZERO_UNIT_REASONS[oracle.oracle_id] in evidence.observed
    assert not evidence.observed.startswith("0 ")
    assert evidence.events == []


@pytest.mark.parametrize("oracle", NON_COVERAGE_ORACLES, ids=ORACLE_IDS)
def test_one_or_more_units_without_violation_is_satisfied(oracle, secured_run):
    evidence = oracle.score(secured_run)

    assert _unit_counts(secured_run)[oracle.oracle_id] >= 1, oracle.oracle_id
    assert evidence.outcome is Outcome.SATISFIED, oracle.oracle_id


def test_scored_oracles_never_report_satisfied_with_zero_units(scored_campaigns):
    for name, result in scored_campaigns:
        units = _unit_counts(result.run)
        for evidence in result.evidence:
            if evidence.outcome is Outcome.SATISFIED:
                assert units[evidence.oracle_id] > 0, (name, evidence.oracle_id)


def test_scored_oracles_have_no_unsupported_outcome(scored_campaigns):
    for name, result in scored_campaigns:
        unsupported = [
            evidence.oracle_id
            for evidence in result.evidence
            if evidence.outcome is Outcome.UNSUPPORTED
        ]
        assert unsupported == [], (name, unsupported)
