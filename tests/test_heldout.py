"""Executable held-out families are real scenarios, not just split labels."""

from __future__ import annotations

from redfence.bench.dataset import DEV_FAMILIES, HELDOUT_FAMILIES
from redfence.bench.heldout import HELDOUT_ORACLE_IDS, run_heldout_scenario
from redfence.targets.config import SecurityProfile


def test_heldout_family_registry_is_consistent():
    """Every family is executable, single-sourced, and has an oracle selection."""

    assert len(HELDOUT_FAMILIES) == 7
    assert set(HELDOUT_FAMILIES).isdisjoint(set(DEV_FAMILIES))
    assert set(HELDOUT_ORACLE_IDS) == set(HELDOUT_FAMILIES)


def test_heldout_families_are_executable_and_discriminate():
    for family in HELDOUT_FAMILIES:
        secured = run_heldout_scenario(family, SecurityProfile.SECURED)
        vulnerable = run_heldout_scenario(family, SecurityProfile.VULNERABLE)
        assert secured.exit_code == 0, family
        assert vulnerable.exit_code == 1, family
        secured_violations = [e.oracle_id for e in secured.evidence if e.is_violation]
        assert secured_violations == [], family
        assert any(e.is_violation for e in vulnerable.evidence), family

    cache_run = run_heldout_scenario("cache.semantic_similarity", SecurityProfile.SECURED)
    replay = next(
        obs for obs in cache_run.run.answer_obs if obs["phase"] == "heldout_cache_replay"
    )
    assert replay["cache_hit"] is True
    assert replay["cache_revalidated"] is True


def test_acl_modify_replay_family_exercises_cache_revalidation():
    """The secured family must hit before the ACL change and miss after it."""

    result = run_heldout_scenario("acl.modify.replay", SecurityProfile.SECURED)
    hits = [obs for obs in result.run.answer_obs if obs["cache_hit"]]
    assert hits, "secured acl.modify.replay must exercise cache reuse"
    assert "pre_modify_replay" in {obs["phase"] for obs in hits}

    pre_replay = next(
        obs for obs in result.run.answer_obs if obs["phase"] == "pre_modify_replay"
    )
    assert pre_replay["cache_hit"] is True
    assert pre_replay["cache_revalidated"] is True

    post_replay = next(
        obs for obs in result.run.answer_obs if obs["phase"] == "post_modify_replay"
    )
    assert post_replay["cache_hit"] is False


def test_heldout_families_have_distinct_scenario_ids():
    ids = {
        run_heldout_scenario(family, SecurityProfile.SECURED).scenario_id
        for family in HELDOUT_FAMILIES
    }
    assert len(ids) == len(HELDOUT_FAMILIES)


def test_heldout_reports_are_named_by_scenario_id(tmp_path):
    result = run_heldout_scenario("acl.modify.replay", SecurityProfile.SECURED, out_dir=tmp_path)
    assert result.json_path is not None
    assert result.json_path.name == f"{result.scenario_id}.json"
    assert result.html_path is not None
    assert result.html_path.name == f"{result.scenario_id}.html"
