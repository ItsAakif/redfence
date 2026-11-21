"""Oracle independence: authoritative ACLs must survive corrupted stored metadata."""

from __future__ import annotations

from redfence.bench.oracles import IndexAclOracle
from redfence.bench.scenario import _retrieval_obs, run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile


def test_oracle_detects_corrupted_stored_chunk_metadata():
    """The target's stored ACL is made permissive; the oracle must still deny.

    The authoritative ACL lives in the corpus, not in the target's mutable chunk
    store. This is the adversarial common-mode test for the oracle.
    """

    run = run_revocation_scenario(SecurityProfile.SECURED)

    corrupted: list[str] = []
    for chunk in run.target.store.all_chunks():
        if chunk.doc_id == "doc_alpha_secret":
            chunk.acl = chunk.acl.model_copy(
                update={
                    "public": True,
                    "classification": "public",
                    "allowed_roles": [],
                    "allowed_groups": [],
                }
            )
            corrupted.append(chunk.id)
    assert corrupted

    intern = run.corpus.principal("p_alpha_intern")
    admitted = run.target.retrieve(intern, "nimbus launch code")
    assert admitted, "corrupted stored metadata should make the target admit the chunk"
    run.retrieval_obs.append(
        _retrieval_obs(
            run.target, "corrupted_metadata_probe", intern, "nimbus launch code", admitted
        )
    )

    evidence = IndexAclOracle().score(run)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.method.startswith("recompute ACL.permits() independent")
