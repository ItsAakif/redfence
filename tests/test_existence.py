"""Existence oracles: twin pairing, feature comparison and permutation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from redfence.bench.contract_observations import MatrixObservation
from redfence.bench.contract_runner import ContractRun, _render_json, run_contract
from redfence.bench.existence import (
    ExistencePair,
    PermutationOracle,
    TwinOracle,
    build_existence_pairs,
    permutation_test,
)
from redfence.bench.snapshot import SnapshotStore, SnapshotTarget, SnapshotTools
from redfence.contracts.loader import parse_contract
from redfence.contracts.schema import ContractV1
from redfence.contracts.target import MockContractTarget
from redfence.core.evidence import Outcome
from redfence.targets.config import FaultFlags


def _obs(
    cell_id: str, response_hash: str = "hash", status: str = "allowed"
) -> MatrixObservation:
    return {
        "cell_id": cell_id,
        "identity_id": "alice",
        "source_id": "doc_alpha_secret",
        "action": "read",
        "expected": "allow",
        "observed": "allow" if status == "allowed" else "deny",
        "response_hash": response_hash,
        "status": status,
        "context_refs": ["doc_alpha_secret"],
        "tool_executed": False,
        "truncated": False,
        "error": None,
    }


def _run(observations: list[MatrixObservation] | None = None) -> ContractRun:
    return ContractRun(
        contract_id="t6-existence",
        contract_hash="hash",
        adapter="mock",
        capabilities=frozenset(),
        target=SnapshotTarget(
            faults=FaultFlags(),
            cache={},
            store=SnapshotStore([]),
            tools=SnapshotTools([]),
        ),
        matrix_obs=observations or [],
    )


def _pair(
    pair_id: str = "p1",
    *,
    present_hash: str = "hash",
    absent_hash: str = "hash",
    present_status: str = "allowed",
    absent_status: str = "allowed",
    present_samples: list[str] | None = None,
    absent_samples: list[str] | None = None,
) -> ExistencePair:
    return ExistencePair(
        pair_id=pair_id,
        query=pair_id,
        present_hash=present_hash,
        absent_hash=absent_hash,
        present_status=present_status,
        absent_status=absent_status,
        present_samples=present_samples or [],
        absent_samples=absent_samples or [],
    )


def _with_pairs(pairs: list[ExistencePair]) -> ContractRun:
    run = _run()
    run.existence_obs = list(pairs)
    return run


def _contract() -> ContractV1:
    payload: dict[str, object] = {
        "contract_version": 1,
        "id": "t6-existence",
        "dataset": {
            "version": "redfencebench-0.4.0",
            "template": "classic",
            "seed": 20260101,
        },
        "identities": [
            {
                "id": "alice",
                "tenant": "t_alpha",
                "roles": ["engineer"],
                "groups": ["alpha-eng"],
                "clearance": "confidential",
            }
        ],
        "sources": [
            {
                "id": "doc_alpha_secret",
                "tenant": "t_alpha",
                "classification": "confidential",
                "acl": {"allowed_roles": ["engineer"], "allowed_groups": ["alpha-eng"]},
                "canary_ref": "alpha",
            }
        ],
        "matrix": [
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "allow",
            }
        ],
        "lifecycle": [],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": []},
        "target": {"adapter": "mock"},
    }
    return parse_contract(payload)


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------


def test_build_pairs_matches_by_cell_and_skips_missing_cells():
    present = _run([_obs("a", "h1"), _obs("b", "h2")])
    absent = _run([_obs("a", "h1"), _obs("c", "h3")])

    pairs = build_existence_pairs(present, absent)

    assert [pair.pair_id for pair in pairs] == ["a"]
    pair = pairs[0]
    assert pair.query == "a"
    assert pair.present_hash == "h1"
    assert pair.absent_hash == "h1"
    assert pair.present_status == "allowed"
    assert pair.absent_status == "allowed"


def test_build_pairs_is_sorted_by_cell_id():
    present = _run([_obs("b", "h2"), _obs("a", "h1")])
    absent = _run([_obs("a", "h1"), _obs("b", "h2")])

    pairs = build_existence_pairs(present, absent)

    assert [pair.pair_id for pair in pairs] == ["a", "b"]


def test_existence_pair_is_frozen():
    pair = _pair()
    with pytest.raises(ValidationError):
        pair.pair_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Twin oracle
# ---------------------------------------------------------------------------


def test_identical_twins_are_satisfied():
    present = _run([_obs("a", "h1"), _obs("b", "h2")])
    absent = _run([_obs("a", "h1"), _obs("b", "h2")])
    evidence = TwinOracle().score(_with_pairs(build_existence_pairs(present, absent)))

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.facet == "existence"
    assert evidence.events == []


def test_different_text_hash_is_a_violation():
    pairs = build_existence_pairs(
        _run([_obs("a", "h1")]), _run([_obs("a", "h2")])
    )
    evidence = TwinOracle().score(_with_pairs(pairs))

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["a:hash-differs"]


def test_different_status_is_a_violation():
    pairs = build_existence_pairs(
        _run([_obs("a", "h1", "allowed")]),
        _run([_obs("a", "h1", "denied")]),
    )
    evidence = TwinOracle().score(_with_pairs(pairs))

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["a:status-differs"]


def test_missing_twin_is_not_counted():
    present = _run([_obs("a", "h1"), _obs("b", "h2")])
    absent = _run([_obs("a", "h1")])
    pairs = build_existence_pairs(present, absent)

    assert [pair.pair_id for pair in pairs] == ["a"]
    evidence = TwinOracle().score(_with_pairs(pairs))
    assert evidence.outcome is Outcome.SATISFIED


def test_twin_zero_pairs_and_empty_hashes_are_unsupported():
    empty = TwinOracle().score(_run())
    assert empty.outcome is Outcome.UNSUPPORTED
    assert empty.observed.startswith("no evaluable observation:")

    no_hash = TwinOracle().score(
        _with_pairs([_pair(present_hash="", absent_hash="")])
    )
    assert no_hash.outcome is Outcome.UNSUPPORTED


# ---------------------------------------------------------------------------
# Permutation oracle
# ---------------------------------------------------------------------------


def test_identical_sample_sets_are_satisfied():
    pairs = [_pair(present_samples=["alpha", "beta"], absent_samples=["alpha", "beta"])]
    result = permutation_test(pairs)

    assert result is not None
    assert result.mode == "exact"
    assert result.p_value == 1.0
    assert result.effect == 0.0
    assert PermutationOracle().score(_with_pairs(pairs)).outcome is Outcome.SATISFIED


def test_clearly_separated_samples_are_a_violation():
    pairs = [
        _pair(
            f"p{index}",
            present_samples=["a" * (20 + index), "a" * (21 + index)],
            absent_samples=["b" * (1 + index), "b" * (2 + index)],
        )
        for index in range(4)
    ]
    result = permutation_test(pairs)

    assert result is not None
    assert result.p_value < 0.05
    assert result.effect > 0.2
    evidence = PermutationOracle().score(_with_pairs(pairs))
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events


def test_twelve_pairs_use_exact_enumeration():
    pairs = [
        _pair(
            f"p{index}",
            present_samples=["a" * (index + 1), "a" * (index + 2)],
            absent_samples=["b" * (index + 1), "b" * (index + 2)],
        )
        for index in range(12)
    ]
    result = permutation_test(pairs)

    assert result is not None
    assert result.mode == "exact"
    assert result.units == 12


def test_one_sample_per_twin_is_unsupported():
    pairs = [_pair(present_samples=["a"], absent_samples=["b"])]

    assert permutation_test(pairs) is None
    evidence = PermutationOracle().score(_with_pairs(pairs))
    assert evidence.outcome is Outcome.UNSUPPORTED
    assert evidence.observed == (
        "no evaluable observation: fewer than 2 samples per twin"
    )


def test_zero_pairs_is_unsupported():
    evidence = PermutationOracle().score(_run())

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert evidence.observed == (
        "no evaluable observation: fewer than 2 samples per twin"
    )


def test_monte_carlo_p_value_is_deterministic():
    pairs = [
        _pair(
            f"p{index}",
            present_samples=["x" * (index + 1), "x" * (index + 2)],
            absent_samples=["y" * (index + 1), "y" * (index + 3)],
        )
        for index in range(13)
    ]
    first = permutation_test(pairs)
    second = permutation_test(pairs)

    assert first is not None
    assert second is not None
    assert first.mode == "monte-carlo"
    assert first.p_value == second.p_value
    assert first.effect == second.effect
    first_evidence = PermutationOracle().score(_with_pairs(pairs))
    second_evidence = PermutationOracle().score(_with_pairs(pairs))
    assert first_evidence.observed == second_evidence.observed


# ---------------------------------------------------------------------------
# Additive sidecar
# ---------------------------------------------------------------------------


def test_existence_obs_is_additive_and_does_not_change_report_bytes(
    tmp_path: Path,
):
    contract = _contract()
    first = run_contract(
        contract, MockContractTarget(contract), out_dir=tmp_path / "first"
    )
    second = run_contract(
        contract, MockContractTarget(contract), out_dir=tmp_path / "second"
    )

    assert first.json_path is not None
    assert second.json_path is not None
    assert first.json_path.read_bytes() == second.json_path.read_bytes()
    assert first.run.existence_obs == []
    assert second.run.existence_obs == []

    before = _render_json(first.run)
    first.run.existence_obs.append(
        _pair(
            "p1",
            present_samples=["alpha", "beta"],
            absent_samples=["alpha", "beta"],
        )
    )
    assert _render_json(first.run) == before
    assert second.run.existence_obs == []

    one = _run()
    two = _run()
    one.existence_obs.append(_pair("p2"))
    assert two.existence_obs == []
