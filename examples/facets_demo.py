"""Run every 0.3.0 library-level facet on built-in deterministic fixtures.

Each new facet (lineage, existence, repair, capability, MCP and retention) is
constructed from the public API and scored with its real oracle registry. The
demo never touches the network or a file outside the repository: the MCP facet
spawns the checked-in stdlib fixture, and every other facet builds in-memory
objects.

Output is one line per oracle::

    facet=<oracle_id> outcome=<satisfied|violation|unsupported> observed=<text>

A deliberate violation is acceptable: the demo proves the oracle ran and
returned evidence, not that the fixture is clean. The exit code is ``0`` when
every facet ran and ``2`` when a facet raised.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from redfence.bench.contract_runner import ContractRun
from redfence.bench.dataset import build_corpus, scenario_id
from redfence.bench.existence import ExistencePair, PermutationOracle, TwinOracle
from redfence.bench.lifecycle_oracles import DerivationOracle
from redfence.bench.lineage import build_lineage
from redfence.bench.mcp import build_observation, fetch_manifest, mcp_oracles
from redfence.bench.repair import RepairPlan, apply_repair, repair_oracles
from redfence.bench.retention_oracles import retention_oracles
from redfence.bench.scenario import ScenarioRun, run_revocation_scenario
from redfence.bench.snapshot import SnapshotStore, SnapshotTarget, SnapshotTools
from redfence.core.capability import (
    CapabilityObservation,
    CapabilityToken,
    CapabilityUse,
    DelegationChain,
    capability_oracles,
)
from redfence.core.evidence import Evidence
from redfence.targets.config import FaultFlags, SecurityProfile
from redfence.targets.rag_target import ConfigurableRAGTarget
from redfence.targets.retention import (
    ReplicaConfig,
    ReplicaObservation,
    ReplicaRead,
    ReplicaStore,
    RetentionObservation,
    StoreObservation,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MCP_FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "mcp_server.py"
_ALPHA_QUERY = "nimbus launch code"
_ALPHA_BENIGN_QUERY = "alpha onboarding"
_BETA_QUERY = "borealis access token"
_OBSERVED_LIMIT = 96


def _format(evidence: Evidence) -> str:
    observed = " ".join(evidence.observed.split())
    if len(observed) > _OBSERVED_LIMIT:
        observed = observed[: _OBSERVED_LIMIT - 3] + "..."
    return (
        f"facet={evidence.oracle_id} "
        f"outcome={evidence.outcome.value} "
        f"observed={observed}"
    )


def _existence_run(pairs: list[ExistencePair]) -> ContractRun:
    """A minimal contract run carrying only the existence pairs under test."""

    return ContractRun(
        contract_id="facets-demo-existence",
        contract_hash="facets-demo",
        adapter="mock",
        capabilities=frozenset(),
        target=SnapshotTarget(
            faults=FaultFlags(),
            cache={},
            store=SnapshotStore([]),
            tools=SnapshotTools([]),
        ),
        existence_obs=list(pairs),
    )


def _lineage_facet() -> list[Evidence]:
    """Build the secured scenario, derive its lineage and score it."""

    scenario = run_revocation_scenario(SecurityProfile.SECURED)
    graph = build_lineage(scenario)
    run = ContractRun(
        contract_id=scenario.scenario_id,
        contract_hash="facets-demo",
        adapter="secured-scenario",
        capabilities=frozenset(),
        target=SnapshotTarget(
            faults=scenario.target.faults,
            cache=dict(scenario.target.cache),
            store=SnapshotStore(scenario.target.store.all_chunks()),
            tools=SnapshotTools([]),
        ),
        retrieval_obs=list(scenario.retrieval_obs),
        answer_obs=list(scenario.answer_obs),
        memory_obs=list(scenario.memory_obs),
        tool_obs=list(scenario.tool_obs),
        deletion_obs=list(scenario.deletion_obs),
        lineage=graph,
    )
    return [DerivationOracle().score(run)]


def _existence_facet() -> list[Evidence]:
    """Identical pairs pass, differing pairs fail, two-sample pairs separate."""

    identical = ExistencePair(
        pair_id="identical",
        query="identical",
        present_hash="same-hash",
        absent_hash="same-hash",
        present_status="allowed",
        absent_status="allowed",
    )
    differing = ExistencePair(
        pair_id="differing",
        query="differing",
        present_hash="present-hash",
        absent_hash="absent-hash",
        present_status="allowed",
        absent_status="denied",
    )
    two_sample_pairs = [
        ExistencePair(
            pair_id=f"pair-{index}",
            query=f"query-{index}",
            present_hash=f"present-{index}",
            absent_hash=f"absent-{index}",
            present_status="allowed",
            absent_status="allowed",
            present_samples=[f"present answer {index}"] * 2,
            absent_samples=["no"] * 2,
        )
        for index in range(4)
    ]
    return [
        TwinOracle().score(_existence_run([identical])),
        TwinOracle().score(_existence_run([differing])),
        PermutationOracle().score(_existence_run(two_sample_pairs)),
    ]


def _repair_facet() -> list[Evidence]:
    """Repair the stale-cache-after-deletion fault with the real helper."""

    corpus = build_corpus()
    target = ConfigurableRAGTarget(
        name="facets-demo-repair",
        faults=FaultFlags(stale_cache_after_deletion=True),
    )
    for document in corpus.documents:
        target.ingest(document)

    alpha = corpus.principal("p_alpha_reader")
    target.answer(alpha, _ALPHA_QUERY)
    target.mark_document_deleted("doc_alpha_secret")
    run = ScenarioRun(
        scenario_id=scenario_id(
            "facets-demo",
            corpus.seed,
            kind="repair",
            template=corpus.template,
        ),
        profile="custom",
        corpus=corpus,
        target=target,
        scenario_kind="repair",
    )
    observation = apply_repair(
        run,
        RepairPlan(purge_cache=True),
        document_id="doc_alpha_secret",
        principal_id=alpha.id,
        query=_ALPHA_QUERY,
        benign_principal_id="p_alpha_lead",
        benign_query=_ALPHA_BENIGN_QUERY,
        collateral_principal_id="p_beta_reader",
        collateral_query=_BETA_QUERY,
    )
    return [oracle.score(observation) for oracle in repair_oracles()]


def _capability_facet() -> list[Evidence]:
    """A two-link delegation chain and one in-scope, in-window use."""

    root = CapabilityToken(
        token_id="tok_root",
        subject="p_root",
        issuer="issuer.root",
        capabilities=frozenset({"docs.search", "files.read"}),
        scope=frozenset({"*"}),
        issued_epoch=1,
        expires_epoch=20,
    )
    child = CapabilityToken(
        token_id="tok_child",
        subject="p_child",
        issuer="p_root",
        capabilities=frozenset({"docs.search"}),
        scope=frozenset({"search_documents"}),
        issued_epoch=2,
        expires_epoch=10,
        delegated_from="tok_root",
    )
    observation = CapabilityObservation(
        chain=DelegationChain(links=[root, child]),
        uses=[
            CapabilityUse(
                token_id="tok_child",
                action="docs.search",
                resource="search_documents",
                epoch=3,
                allowed=True,
            )
        ],
    )
    return [oracle.score(observation) for oracle in capability_oracles()]


def _mcp_facet() -> list[Evidence]:
    """Fetch the benign and poisoned manifests over the stdlib stdio fixture."""

    evidences: list[Evidence] = []
    for mode in ("benign", "poisoned_description"):
        manifest = fetch_manifest([sys.executable, str(_MCP_FIXTURE), mode])
        observation = build_observation([manifest])
        evidences.extend(oracle.score(observation) for oracle in mcp_oracles())
    return evidences


def _retention_facet() -> list[Evidence]:
    """A replica that does not propagate deletion must be detected."""

    corpus = build_corpus()
    replica = ReplicaStore(ReplicaConfig(propagate_deletions=False))
    target = ConfigurableRAGTarget(
        name="facets-demo-retention",
        faults=FaultFlags(),
        replicas=[replica],
    )
    for document in corpus.documents:
        target.ingest(document)

    tenant_id = corpus.primary_tenant().id
    document = corpus.confidential_doc(tenant_id)
    reader = corpus.principal("p_alpha_reader")
    chunk_id = next(
        chunk.id for chunk in target.store.all_chunks() if chunk.doc_id == document.id
    )
    target.mark_document_deleted(document.id)

    retention_observation = RetentionObservation(
        deleted_doc_ids=[document.id],
        stores=[
            StoreObservation(
                store=replica.name,
                readable_doc_ids=replica.readable_doc_ids(),
            )
        ],
    )
    replica_observation = ReplicaObservation(
        reads=[
            ReplicaRead(
                replica=replica.name,
                principal_id=reader.id,
                chunk_id=chunk_id,
                primary_allows=target.store.get(chunk_id) is not None,
                replica_allows=replica.read(reader, chunk_id) is not None,
            )
        ]
    )
    durability, consistency = retention_oracles()
    return [
        durability.score(retention_observation),
        consistency.score(replica_observation),
    ]


_FACETS: tuple[tuple[str, Callable[[], list[Evidence]]], ...] = (
    ("lineage", _lineage_facet),
    ("existence", _existence_facet),
    ("repair", _repair_facet),
    ("capability", _capability_facet),
    ("mcp", _mcp_facet),
    ("retention", _retention_facet),
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run every facet and print one line per oracle. No arguments are used."""

    del argv  # reserved for future flags; the demo is intentionally fixture-only
    failed = False
    for name, facet in _FACETS:
        try:
            evidences = facet()
        except Exception as exc:  # noqa: BLE001 - a facet failure is a demo failure
            failed = True
            print(
                f"facet={name} outcome=unsupported "
                f"observed=not-demonstrable ({type(exc).__name__})"
            )
            continue
        for evidence in evidences:
            print(_format(evidence))
    return 2 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
