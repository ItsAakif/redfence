"""Scenario behavior guards: accessor refactor equivalence + template coverage.

The pinned outcome map below was captured from the pre-refactor implementation
(``corpus.principal("p_alpha_reader")``-era code) and must not drift: the
role-accessor refactor is required to be behavior-identical on the classic
template.
"""

from __future__ import annotations

import pytest

from redfence.bench.dataset import TEMPLATES, build_corpus, template_isomorphic
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import run_campaign
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile

# Pinned pre-refactor oracle outcome map (default seed, classic template).
REFERENCE_OUTCOMES = {
    SecurityProfile.SECURED: {
        "oracle.cache.freshness": "satisfied",
        "oracle.cache.key_scope": "satisfied",
        "oracle.cache.leak": "satisfied",
        "oracle.context.exposure": "satisfied",
        "oracle.coverage.unsupported": "satisfied",
        "oracle.index.acl": "satisfied",
        "oracle.index.deletion": "satisfied",
        "oracle.index.tenant": "satisfied",
        "oracle.memory.scope": "satisfied",
        "oracle.metadata.integrity": "satisfied",
        "oracle.response.disclosure": "satisfied",
        "oracle.tool.policy": "satisfied",
        "oracle.utility.benign": "satisfied",
    },
    SecurityProfile.VULNERABLE: {
        "oracle.cache.freshness": "violation",
        "oracle.cache.key_scope": "violation",
        "oracle.cache.leak": "violation",
        "oracle.context.exposure": "violation",
        "oracle.coverage.unsupported": "satisfied",
        "oracle.index.acl": "violation",
        "oracle.index.deletion": "violation",
        "oracle.index.tenant": "violation",
        "oracle.memory.scope": "violation",
        "oracle.metadata.integrity": "violation",
        "oracle.response.disclosure": "violation",
        "oracle.tool.policy": "violation",
        "oracle.utility.benign": "satisfied",
    },
}


@pytest.mark.parametrize("profile", [SecurityProfile.SECURED, SecurityProfile.VULNERABLE])
def test_classic_scenario_matches_reference_outcomes(profile: SecurityProfile):
    """Every pinned pre-refactor outcome must be reproduced exactly.

    New oracles added later extend the map without invalidating the pin: the
    guard asserts the reference outcomes are unchanged, not that the oracle set
    is frozen.
    """

    result = run_campaign(profile)
    observed = {item.oracle_id: item.outcome.value for item in result.evidence}
    for oracle_id, expected in REFERENCE_OUTCOMES[profile].items():
        assert observed.get(oracle_id) == expected, oracle_id


def test_scenario_runs_over_every_template():
    for name in TEMPLATES:
        template_isomorphic(build_corpus(template=name))
        for profile in (SecurityProfile.SECURED, SecurityProfile.VULNERABLE):
            run = run_revocation_scenario(profile, template=name)
            evidence = {
                item.oracle_id: item.outcome
                for item in (o.score(run) for o in default_oracles())
            }
            violations = [oid for oid, item in evidence.items() if item is Outcome.VIOLATION]
            if profile is SecurityProfile.SECURED:
                assert violations == [], (name, violations)
            else:
                assert violations, name


def test_accessors_resolve_contract_roles():
    for name in TEMPLATES:
        corpus = build_corpus(template=name)
        primary = corpus.primary_tenant()
        secondary = corpus.secondary_tenant()
        assert corpus.principal_by_role(primary.id, "reader").tenant_id == primary.id
        assert corpus.principal_by_role(primary.id, "lead").tenant_id == primary.id
        assert corpus.principal_by_role(primary.id, "intern").tenant_id == primary.id
        assert corpus.principal_by_role(secondary.id, "reader").tenant_id == secondary.id
        assert corpus.confidential_doc(primary.id).tenant_id == primary.id
        assert corpus.canary_owner_docs(corpus.canaries["beta"]) == [
            corpus.confidential_doc(secondary.id).id
        ]
