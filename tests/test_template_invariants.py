"""Template invariants: G2 must hold on every corpus template, not just classic."""

from __future__ import annotations

import pytest

from redfence.bench.dataset import TEMPLATES, build_corpus, template_isomorphic
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import SUPPORTED_FAULTS, run_campaign
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FAULT_ORACLE, FaultFlags, SecurityProfile


def test_every_template_secured_has_zero_violations():
    for name in TEMPLATES:
        run = run_revocation_scenario(SecurityProfile.SECURED, template=name)
        evidence = {
            item.oracle_id: item.outcome
            for item in (o.score(run) for o in default_oracles())
        }
        violations = [oid for oid, out in evidence.items() if out is Outcome.VIOLATION]
        assert violations == [], (name, violations)


@pytest.mark.parametrize("template", sorted(TEMPLATES))
@pytest.mark.parametrize("fault", sorted(SUPPORTED_FAULTS))
def test_every_template_discriminates_every_fault(template: str, fault: str):
    template_isomorphic(build_corpus(template=template))
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(**{fault: True}), template=template
    )
    evidence = {
        item.oracle_id: item.outcome for item in (o.score(run) for o in default_oracles())
    }
    assert evidence[FAULT_ORACLE[fault]] is Outcome.VIOLATION, (template, fault)


def test_campaign_rejects_unknown_template():
    with pytest.raises(ValueError):
        run_campaign(SecurityProfile.SECURED, template="does_not_exist")


def test_evidence_ids_are_disjoint_across_templates():
    classic = run_campaign(SecurityProfile.SECURED, template="classic")
    secret_tier = run_campaign(SecurityProfile.SECURED, template="secret_tier")
    classic_ids = {item.evidence_id for item in classic.evidence}
    secret_tier_ids = {item.evidence_id for item in secret_tier.evidence}
    assert classic_ids.isdisjoint(secret_tier_ids)
