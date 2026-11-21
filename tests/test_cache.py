"""Cache lifecycle: reuse must revalidate authorization and freshness."""

from __future__ import annotations

from redfence.adapters.deterministic_generator import DeterministicGenerator
from redfence.bench.dataset import Corpus, build_corpus
from redfence.bench.isolated import serialize_run
from redfence.bench.oracle_worker import _reconstruct
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import run_campaign
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.domain import CacheEntry, Principal, RetrievedChunk
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget


def _oracle(run, oracle_id: str) -> Outcome:
    evidence = {item.oracle_id: item for item in (o.score(run) for o in default_oracles())}
    return evidence[oracle_id].outcome


def test_secured_cache_revalidates():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert _oracle(run, "oracle.cache.leak") is Outcome.SATISFIED


def test_secured_cache_keys_are_scoped():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert _oracle(run, "oracle.cache.key_scope") is Outcome.SATISFIED


def test_stale_cache_fault_leaks_after_revocation():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(stale_cache_after_revocation=True)
    )
    assert _oracle(run, "oracle.cache.leak") is Outcome.VIOLATION


def test_unscoped_cache_key_fault_is_flagged():
    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(unscoped_cache_key=True)
    )
    assert _oracle(run, "oracle.cache.key_scope") is Outcome.VIOLATION


def test_secured_run_is_reported_without_violations():
    assert run_campaign(SecurityProfile.SECURED).exit_code == 0


def test_revoked_denial_is_not_reused_for_peer_with_same_entitlements():
    """A denial cached for revoked alpha must not starve non-revoked alpha lead."""

    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert run.utility_obs is not None
    assert run.corpus.canaries["alpha"] in run.utility_obs["canaries_present"]


def test_secured_freshness_check_holds():
    from redfence.bench.oracles import SourceFreshnessOracle

    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert SourceFreshnessOracle().score(run).outcome is Outcome.SATISFIED


def test_missing_source_freshness_fault_leaks_stale_evidence():
    from redfence.bench.oracles import SourceFreshnessOracle

    run = run_revocation_scenario(
        SecurityProfile.SECURED, faults=FaultFlags(missing_source_freshness=True)
    )
    evidence = SourceFreshnessOracle().score(run)
    assert evidence.outcome is Outcome.VIOLATION
    assert "post_document_update" in " ".join(evidence.events)


def test_secured_cache_hit_is_revalidated():
    """Positive control: a legitimate replayed query really does hit the cache."""

    from redfence.bench.dataset import build_corpus
    from redfence.targets.rag_target import ConfigurableRAGTarget

    corpus = build_corpus()
    target = ConfigurableRAGTarget(name="cache-positive", faults=FaultFlags())
    for document in corpus.documents:
        target.ingest(document)
    alpha = corpus.principal("p_alpha_reader")
    first = target.answer(alpha, "nimbus launch code")
    second = target.answer(alpha, "nimbus launch code")
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert second.cache_revalidated is True
    assert corpus.canaries["alpha"] in second.canaries_present


def test_secured_dev_run_exercises_a_revalidated_cache_hit():
    """The dev scenario must contain a real cache hit, not just cache misses."""

    run = run_revocation_scenario(SecurityProfile.SECURED)
    hits = [obs for obs in run.answer_obs if obs["cache_hit"]]
    assert hits, "secured dev run must exercise cache reuse"

    replay = next(
        obs for obs in run.answer_obs if obs["phase"] == "authorized_cache_replay"
    )
    assert replay["cache_hit"] is True
    assert replay["cache_revalidated"] is True


# -- Semantic cache: invalid entries are removed by their own key ------------
#
# A semantic hit is found by similarity, not by exact key. Invalidating it must
# drop the entry's stored key; deleting the paraphrase's lookup key raised
# ``KeyError`` because that key was never inserted.

_PARAPHRASE = "what is the nimbus launch code"


def _semantic_target() -> tuple[Corpus, ConfigurableRAGTarget]:
    corpus = build_corpus()
    target = ConfigurableRAGTarget(
        name="semantic-cache-lifecycle",
        faults=FaultFlags(),
        semantic_cache=True,
    )
    for document in corpus.documents:
        target.ingest(document)
    return corpus, target


def _prime_semantic_cache(
    target: ConfigurableRAGTarget,
    principal: Principal,
    query: str = "nimbus launch code",
) -> str:
    first = target.answer(principal, query)
    assert first.cache_hit is False
    key = target.cache_key(query, principal)
    assert set(target.cache) == {key}
    return key


class _CacheSizeProbe(DeterministicGenerator):
    """Record the cache size at generation time.

    The invalid entry is dropped before generation and the replacement entry is
    inserted after it, so generation observes the cache after the one-entry
    decrease.
    """

    def __init__(self, target: ConfigurableRAGTarget) -> None:
        self.target = target
        self.sizes: list[int] = []

    def generate(self, query: str, context: list[RetrievedChunk]) -> str:
        self.sizes.append(len(self.target.cache))
        return super().generate(query, context)


def test_semantic_cache_revoke_invalidates_entry_without_keyerror():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    entry_key = _prime_semantic_cache(target, alpha)

    target.revoke(alpha)
    answer = target.answer(alpha, _PARAPHRASE)

    assert answer.cache_hit is False
    assert answer.cache_revalidated is False
    assert corpus.canaries["alpha"] not in answer.text
    assert corpus.canaries["alpha"] not in answer.canaries_present
    assert entry_key not in target.cache


def test_semantic_cache_document_update_invalidates_entry():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    entry_key = _prime_semantic_cache(target, alpha)

    assert target.update_document("doc_alpha_secret") == 2
    answer = target.answer(alpha, _PARAPHRASE)

    assert answer.cache_hit is False
    assert answer.cache_revalidated is False
    # The refreshed answer may legitimately read the still-authorized document,
    # so staleness is proven by the empty cached-version stamp: no stale entry
    # was served; the canary comes from a fresh read at version 2.
    assert answer.cache_doc_versions == {}
    assert answer.current_doc_versions == {}
    assert corpus.canaries["alpha"] in answer.canaries_present
    assert entry_key not in target.cache


def test_semantic_cache_acl_modify_invalidates_entry():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    entry_key = _prime_semantic_cache(target, alpha)

    assert target.modify_document_acl("doc_alpha_secret", classification="secret") is True
    answer = target.answer(alpha, _PARAPHRASE)

    assert answer.cache_hit is False
    assert answer.cache_revalidated is False
    assert corpus.canaries["alpha"] not in answer.text
    assert corpus.canaries["alpha"] not in answer.canaries_present
    assert entry_key not in target.cache


def test_semantic_cache_document_deletion_does_not_raise():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    entry_key = _prime_semantic_cache(target, alpha)

    target.mark_document_deleted("doc_alpha_secret")
    assert len(target.cache) == 0

    answer = target.answer(alpha, _PARAPHRASE)

    assert answer.cache_hit is False
    assert corpus.canaries["alpha"] not in answer.text
    assert corpus.canaries["alpha"] not in answer.canaries_present
    assert entry_key not in target.cache
    assert len(target.cache) == 1


def test_semantic_cache_invalid_entry_is_removed_by_its_own_key():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    entry_key = _prime_semantic_cache(target, alpha)

    target.revoke(alpha)
    probe = _CacheSizeProbe(target)
    target.generator = probe
    target.answer(alpha, _PARAPHRASE)

    # One cached entry before, zero when the replacement answer is generated.
    assert probe.sizes == [0]
    assert entry_key not in target.cache
    assert len(target.cache) == 1
    assert target.cache_key(_PARAPHRASE, alpha) in target.cache


# -- Semantic cache: entries are bound to the requesting principal -------------
#
# The exact cache key already includes the principal id, so exact reuse is
# per-principal. Semantic reuse must be per-principal too: otherwise one
# principal's cached answer (or cached denial) is replayed to another, which can
# bypass revocation and per-principal ACL grants.


def test_revoked_reader_cannot_receive_leads_cached_answer_via_paraphrase():
    corpus, target = _semantic_target()
    lead = corpus.principal("p_alpha_lead")
    reader = corpus.principal("p_alpha_reader")

    target.revoke(reader)
    lead_answer = target.answer(lead, "nimbus launch code")
    assert lead_answer.cache_hit is False
    assert corpus.canaries["alpha"] in lead_answer.canaries_present

    answer = target.answer(reader, _PARAPHRASE)

    assert reader.revoked is True
    assert answer.cache_hit is False
    assert answer.cache_revalidated is False
    assert corpus.canaries["alpha"] not in answer.text
    assert corpus.canaries["alpha"] not in answer.canaries_present


def test_non_permitted_reader_cannot_receive_leads_cached_answer():
    corpus = build_corpus()
    target = ConfigurableRAGTarget(
        name="semantic-principal-acl", faults=FaultFlags(), semantic_cache=True
    )
    confidential = corpus.confidential_doc(corpus.primary_tenant().id)
    lead_only_acl = confidential.acl.model_copy(
        update={
            "allowed_roles": [],
            "allowed_groups": [],
            "allowed_principals": ["p_alpha_lead"],
        }
    )
    for document in corpus.documents:
        if document.id == confidential.id:
            target.ingest(document, lead_only_acl)
        else:
            target.ingest(document)

    lead = corpus.principal("p_alpha_lead")
    reader = corpus.principal("p_alpha_reader")
    lead_answer = target.answer(lead, "nimbus launch code")
    assert lead_answer.cache_hit is False
    assert corpus.canaries["alpha"] in lead_answer.canaries_present

    answer = target.answer(reader, _PARAPHRASE)

    assert answer.cache_hit is False
    assert corpus.canaries["alpha"] not in answer.text
    assert corpus.canaries["alpha"] not in answer.canaries_present


def test_authorized_lead_does_not_receive_revoked_readers_cached_denial():
    corpus, target = _semantic_target()
    lead = corpus.principal("p_alpha_lead")
    reader = corpus.principal("p_alpha_reader")

    target.revoke(reader)
    denied = target.answer(reader, "nimbus launch code")
    assert denied.cache_hit is False
    assert corpus.canaries["alpha"] not in denied.canaries_present

    answer = target.answer(lead, "nimbus launch code")

    assert answer.cache_hit is False
    assert answer.cache_revalidated is False
    assert corpus.canaries["alpha"] in answer.canaries_present


def test_exact_hit_still_works_for_same_principal():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")

    assert target.answer(alpha, "nimbus launch code").cache_hit is False
    replay = target.answer(alpha, "nimbus launch code")

    assert replay.cache_hit is True
    assert replay.cache_revalidated is True
    assert corpus.canaries["alpha"] in replay.canaries_present


def test_same_entitlement_second_principal_is_a_semantic_miss():
    """Per-principal semantic reuse is the intended trade-off of principal binding."""

    corpus, target = _semantic_target()
    lead = corpus.principal("p_alpha_lead")
    reader = corpus.principal("p_alpha_reader")
    assert lead.entitlement_fingerprint() == reader.entitlement_fingerprint()

    lead_answer = target.answer(lead, "nimbus launch code")
    assert lead_answer.cache_hit is False

    answer = target.answer(reader, _PARAPHRASE)

    assert answer.cache_hit is False
    assert answer.cache_revalidated is False
    # A fresh, authorized read still completes the benign task.
    assert corpus.canaries["alpha"] in answer.canaries_present


def test_every_target_created_cache_entry_has_a_principal_id():
    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    lead = corpus.principal("p_alpha_lead")

    target.answer(alpha, "nimbus launch code")
    target.answer(alpha, _PARAPHRASE)
    target.answer(lead, "nimbus launch code")

    assert target.cache
    assert all(entry.principal_id for entry in target.cache.values())
    assert {entry.principal_id for entry in target.cache.values()} == {
        alpha.id,
        lead.id,
    }


# -- Snapshot round-trip and legacy cache entries (review finding F5) ---------


def test_snapshot_round_trip_preserves_principal_id_and_doc_acl_epochs():
    run = run_revocation_scenario(SecurityProfile.SECURED)
    assert run.target.cache

    rebuilt = _reconstruct(serialize_run(run))

    assert set(rebuilt.target.cache) == set(run.target.cache)
    for key, original in run.target.cache.items():
        restored = rebuilt.target.cache[key]
        assert restored.principal_id == original.principal_id
        assert restored.doc_acl_epochs == original.doc_acl_epochs
        assert restored.principal_id != ""


def test_revocation_still_bumps_global_epoch_and_invalidates_peer_entries():
    """The new revoked-principal guard must not hide a missing global bump.

    T1.2 requires ``revoke()`` to advance ``current_epoch`` so every cached
    entry is revalidated. If the bump were removed, the revoked principal alone
    would still be protected by ``principal.revoked``; only a peer's entry shows
    whether the global invalidation still happens.
    """

    corpus, target = _semantic_target()
    revoked = corpus.principal("p_alpha_reader")
    peer = corpus.principal("p_alpha_lead")

    assert target.answer(peer, "nimbus launch code").cache_hit is False
    peer_entry = next(iter(target.cache.values()))
    epoch_before = target.current_epoch

    target.revoke(revoked)

    assert target.current_epoch == epoch_before + 1
    assert peer.revoked is False
    # Rejecting the peer entry here can only come from the global epoch bump.
    assert target._cache_valid(peer_entry, peer) is False
    assert target.answer(peer, "nimbus launch code").cache_hit is False


def test_legacy_cache_entry_json_defaults_and_is_ineligible_for_semantic_reuse():
    legacy = CacheEntry.model_validate(
        {
            "key": "legacy-key",
            "query": "nimbus launch code",
            "tenant_id": "t_alpha",
            "entitlement_fingerprint": "",
            "acl_epoch": 1,
            "answer": "LEGACY_ANSWER",
        }
    )
    assert legacy.principal_id == ""
    assert legacy.doc_acl_epochs == {}

    corpus, target = _semantic_target()
    alpha = corpus.principal("p_alpha_reader")
    legacy = legacy.model_copy(
        update={"entitlement_fingerprint": alpha.entitlement_fingerprint()}
    )
    target.cache[legacy.key] = legacy

    assert target._find_semantic_entry(alpha, _PARAPHRASE) is None
    assert target._cache_valid(legacy, alpha) is False

    answer = target.answer(alpha, _PARAPHRASE)

    assert answer.cache_hit is False
    assert answer.text != legacy.answer
    assert corpus.canaries["alpha"] in answer.canaries_present

