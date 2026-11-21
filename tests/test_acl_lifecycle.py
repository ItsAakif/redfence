"""ACL modification as a legitimate lifecycle action (dimension B).

``modify_document_acl`` is an administrative authorization-state change, not a
fault. It invalidates cache entries derived from the modified document through a
per-document ACL epoch, without advancing the global authorization epoch.
"""

from __future__ import annotations

from redfence.bench.dataset import build_corpus
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import run_campaign
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget


def _fresh_target():
    corpus = build_corpus()
    target = ConfigurableRAGTarget(name="acl-lifecycle", faults=FaultFlags())
    for document in corpus.documents:
        target.ingest(document)
    return corpus, target


def test_acl_modify_bumps_epoch_and_invalidates_cache():
    corpus, target = _fresh_target()
    doc_id = corpus.confidential_doc(corpus.primary_tenant().id).id
    alpha = corpus.principal_by_role(corpus.primary_tenant().id, "reader")
    before_epoch = target.current_epoch
    before_doc_epoch = target._doc_acl_epochs[doc_id]
    answer = target.answer(alpha, "nimbus launch code")
    assert answer.cache_hit is False
    assert target.cache, "answer must be cached"
    # The classic ACL grants via role AND group; the modification revokes both.
    assert (
        target.modify_document_acl(doc_id, allowed_roles=["admin"], allowed_groups=["admin-board"])
        is True
    )
    # Invalidation is scoped to the document; the global epoch does not move.
    assert target.current_epoch == before_epoch
    assert target._doc_acl_epochs[doc_id] == before_doc_epoch + 1
    replay = target.answer(alpha, "nimbus launch code")
    assert replay.cache_hit is False, "cached answer must be revalidated after ACL modify"
    assert corpus.canaries["alpha"] not in replay.canaries_present


def test_acl_modify_of_alpha_document_leaves_beta_cache_untouched():
    corpus, target = _fresh_target()
    alpha_doc_id = corpus.confidential_doc(corpus.primary_tenant().id).id
    beta = corpus.principal_by_role(corpus.secondary_tenant().id, "reader")
    beta_query = "borealis access token"
    assert target.answer(beta, beta_query).cache_hit is False
    beta_key = target.cache_key(beta_query, beta)
    assert beta_key in target.cache

    assert target.modify_document_acl(alpha_doc_id, classification="internal") is True

    replay = target.answer(beta, beta_query)
    assert replay.cache_hit is True, "an unrelated tenant's cache entry must survive"
    assert replay.cache_revalidated is True
    assert beta_key in target.cache
    assert corpus.canaries["beta"] in replay.canaries_present


def test_acl_modify_nonexistent_document_is_rejected_without_epoch_change():
    corpus, target = _fresh_target()
    before_epoch = target.current_epoch
    before_doc_epochs = dict(target._doc_acl_epochs)
    assert target.modify_document_acl("doc_does_not_exist", classification="internal") is False
    assert target.current_epoch == before_epoch
    assert target._doc_acl_epochs == before_doc_epochs
    assert [event for event in target.trace.as_list() if event["kind"] == "acl_modify"] == []


def test_acl_modify_secured_replay_denies():
    corpus, target = _fresh_target()
    doc_id = corpus.confidential_doc(corpus.primary_tenant().id).id
    alpha = corpus.principal_by_role(corpus.primary_tenant().id, "reader")
    target.answer(alpha, "nimbus launch code")
    target.modify_document_acl(doc_id, allowed_roles=["admin"], allowed_groups=["admin-board"])
    admitted = target.retrieve(alpha, "nimbus launch code")
    assert all(item.doc_id != doc_id for item in admitted)


def test_acl_modify_is_not_a_fault():
    """A full secured campaign including an ACL modification stays clean."""

    run = run_revocation_scenario(SecurityProfile.SECURED)
    target = run.target
    doc_id = run.corpus.confidential_doc(run.corpus.primary_tenant().id).id
    lead = run.corpus.principal_by_role(run.corpus.primary_tenant().id, "lead")
    assert target.modify_document_acl(doc_id, classification="internal") is True
    evidence = {item.oracle_id: item for item in (o.score(run) for o in default_oracles())}
    violations = [oid for oid, item in evidence.items() if item.outcome is Outcome.VIOLATION]
    assert violations == []
    # An authorized principal still completes the benign task after the change.
    answer = target.answer(lead, "nimbus launch code")
    assert run.corpus.canaries["alpha"] in answer.canaries_present


def test_full_secured_campaign_still_clean_after_lifecycle_controls():
    """Guard: the T4 controls did not disturb the pinned secured outcomes."""

    result = run_campaign(SecurityProfile.SECURED)
    violations = [item.oracle_id for item in result.evidence if item.outcome is Outcome.VIOLATION]
    assert violations == []
    assert result.exit_code == 0


def test_acl_modify_requires_changes():
    corpus, target = _fresh_target()
    assert target.modify_document_acl("doc_alpha_secret") is False
