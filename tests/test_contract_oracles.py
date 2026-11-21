"""Contract oracles: ADR-0008 vacuity, violations and redaction."""

from __future__ import annotations

import json

from redfence.bench.contract_oracles import _stored_text, contract_oracles
from redfence.bench.contract_runner import run_contract
from redfence.contracts.loader import parse_contract
from redfence.contracts.schema import ContractV1
from redfence.contracts.target import (
    CallableContractTarget,
    ContractResponse,
    MockContractTarget,
)
from redfence.core.evidence import Outcome


def _payload(
    *,
    matrix: list[dict[str, object]] | None = None,
    lifecycle: list[dict[str, object]] | None = None,
    secrets: list[str] | None = None,
    max_requests: int = 32,
) -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "t4-oracles",
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
            },
            {
                "id": "bob",
                "tenant": "t_beta",
                "roles": ["engineer"],
                "groups": ["beta-eng"],
                "clearance": "confidential",
            },
        ],
        "sources": [
            {
                "id": "doc_alpha_secret",
                "tenant": "t_alpha",
                "classification": "confidential",
                "acl": {"allowed_roles": ["engineer"], "allowed_groups": ["alpha-eng"]},
                "canary_ref": "alpha",
            },
            {
                "id": "doc_beta_secret",
                "tenant": "t_beta",
                "classification": "confidential",
                "acl": {"allowed_groups": ["beta-eng"]},
                "canary_ref": "beta",
            },
        ],
        "matrix": matrix if matrix is not None else [],
        "lifecycle": lifecycle if lifecycle is not None else [],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": max_requests,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": secrets or []},
        "target": {"adapter": "mock"},
    }


def _contract(**kwargs: object) -> ContractV1:
    return parse_contract(_payload(**kwargs))  # type: ignore[arg-type]


def _run(contract: ContractV1, target: object | None = None):
    active = target if target is not None else MockContractTarget(contract)
    return run_contract(contract, active)  # type: ignore[arg-type]


def _oracle(oracle_id: str):
    return next(item for item in contract_oracles() if item.oracle_id == oracle_id)


def _read_cell(cell_id: str, identity: str, source: str, expect: str) -> dict[str, object]:
    return {
        "id": cell_id,
        "identity": identity,
        "source": source,
        "action": "read",
        "expect": expect,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_has_four_contract_oracles():
    oracles = contract_oracles()
    assert [item.oracle_id for item in oracles] == [
        "oracle.contract.matrix",
        "oracle.contract.lifecycle",
        "oracle.contract.budget",
        "oracle.contract.redaction",
    ]
    assert all(item.facet == "contract" for item in oracles)


def test_every_oracle_returns_unsupported_with_zero_units():
    result = _run(_contract(matrix=[], lifecycle=[], secrets=[]))
    evidence = [oracle.score(result.run) for oracle in contract_oracles()]

    assert [item.outcome for item in evidence] == [Outcome.UNSUPPORTED] * 4
    assert all(
        item.observed.startswith("no evaluable observation:") for item in evidence
    )


# ---------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------


def test_matrix_oracle_satisfied():
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")]
        )
    )
    evidence = _oracle("oracle.contract.matrix").score(result.run)

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.observed == "1/1 cells matched; 0 violations"
    assert evidence.events == []


def test_matrix_oracle_violation_is_specific():
    matrix = [
        _read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow"),
        _read_cell("bob_reads_alpha", "bob", "doc_alpha_secret", "deny"),
        _read_cell("bob_reads_beta", "bob", "doc_beta_secret", "allow"),
        {
            "id": "alice_answers_alpha",
            "identity": "alice",
            "source": "doc_alpha_secret",
            "action": "answer",
            "expect": "deny",
        },
    ]
    result = _run(_contract(matrix=matrix))
    evidence = _oracle("oracle.contract.matrix").score(result.run)

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.observed == "3/4 cells matched; 1 violation"
    assert len(evidence.events) == 1
    assert "alice_answers_alpha" in evidence.events[0]


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_lifecycle_oracle_unsupported_without_replay():
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            lifecycle=[],
        )
    )
    evidence = _oracle("oracle.contract.lifecycle").score(result.run)

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert "no lifecycle step replayed a cell" in evidence.observed


def test_lifecycle_oracle_satisfied_after_benign_update():
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            lifecycle=[{"id": "update_alpha", "action": "update", "source": "doc_alpha_secret"}],
        )
    )
    evidence = _oracle("oracle.contract.lifecycle").score(result.run)

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.observed == "1/1 lifecycle replays clean; 0 violations"


def test_lifecycle_oracle_satisfied_after_revoke():
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            lifecycle=[{"id": "revoke_alice", "action": "revoke", "identity": "alice"}],
        )
    )
    evidence = _oracle("oracle.contract.lifecycle").score(result.run)

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.observed == "1/1 lifecycle replays clean; 0 violations"
    assert result.exit_code == 0


def test_lifecycle_oracle_satisfied_after_delete():
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            lifecycle=[{"id": "delete_alpha", "action": "delete", "source": "doc_alpha_secret"}],
        )
    )
    evidence = _oracle("oracle.contract.lifecycle").score(result.run)

    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.observed == "1/1 lifecycle replays clean; 0 violations"
    assert result.exit_code == 0


def test_lifecycle_oracle_violation_when_target_ignores_revoke():
    contract = _contract(
        matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
        lifecycle=[{"id": "revoke_alice", "action": "revoke", "identity": "alice"}],
    )
    target = CallableContractTarget(
        lambda req: ContractResponse(
            status="allowed",
            text="ok",
            context_refs=[req.source_id] if req.source_id else [],
        )
    )
    result = _run(contract, target)
    evidence = _oracle("oracle.contract.lifecycle").score(result.run)

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == [
        "revoke_alice: alice_reads_alpha: expected deny after revoke, observed allow"
    ]
    assert result.exit_code == 1


def test_lifecycle_oracle_unsupported_when_no_cell_is_affected():
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            lifecycle=[{"id": "revoke_bob", "action": "revoke", "identity": "bob"}],
        )
    )
    evidence = _oracle("oracle.contract.lifecycle").score(result.run)

    assert result.run.lifecycle_obs[0]["replayed_cell_ids"] == []
    assert evidence.outcome is Outcome.UNSUPPORTED
    assert "no lifecycle step replayed a cell" in evidence.observed


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def test_budget_oracle_unsupported_without_requests():
    result = _run(_contract(matrix=[]))
    evidence = _oracle("oracle.contract.budget").score(result.run)

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert "no adapter request" in evidence.observed


def test_budget_oracle_satisfied_and_over_request_violation():
    one = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")]
        )
    )
    assert _oracle("oracle.contract.budget").score(one.run).outcome is Outcome.SATISFIED

    two = _run(
        _contract(
            matrix=[
                _read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow"),
                _read_cell("bob_reads_beta", "bob", "doc_beta_secret", "allow"),
            ],
            max_requests=1,
        )
    )
    evidence = _oracle("oracle.contract.budget").score(two.run)
    assert evidence.outcome is Outcome.VIOLATION
    assert any("requests" in event for event in evidence.events)


def test_budget_oracle_detects_timeout_truncation_and_egress():
    contract = _contract(
        matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")]
    )
    target = CallableContractTarget(
        lambda _req: ContractResponse(
            status="error",
            text="0123456789",
            error="egress_denied after timeout",
            truncated=True,
        )
    )
    result = _run(contract, target)
    evidence = _oracle("oracle.contract.budget").score(result.run)

    assert evidence.outcome is Outcome.VIOLATION
    assert len(evidence.events) == 3


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_redaction_oracle_set_but_absent_is_satisfied(monkeypatch):
    secret = "t4-super-secret-value"
    monkeypatch.setenv("REDFENCE_TEST_SECRET", secret)
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            secrets=["REDFENCE_TEST_SECRET"],
        )
    )
    evidence = _oracle("oracle.contract.redaction").score(result.run)

    assert result.run.secret_names == ("REDFENCE_TEST_SECRET",)
    assert evidence.outcome is Outcome.SATISFIED
    assert evidence.observed == "0/1 configured secret value leaked"


def test_redaction_oracle_detects_leak_without_echoing_value(monkeypatch):
    secret = "t4-super-secret-value"
    monkeypatch.setenv("REDFENCE_TEST_SECRET", secret)
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            secrets=["REDFENCE_TEST_SECRET"],
        )
    )
    result.run.matrix_obs[0]["error"] = f"leaked {secret}"

    evidence = _oracle("oracle.contract.redaction").score(result.run)

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["REDFENCE_TEST_SECRET:leaked"]
    assert secret not in evidence.observed
    assert all(secret not in event for event in evidence.events)


def test_redaction_oracle_matches_escaped_secret_forms(monkeypatch):
    secret = 'sëcret"\\\t'
    monkeypatch.setenv("REDFENCE_TEST_SECRET", secret)
    contract = _contract(
        matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
        secrets=["REDFENCE_TEST_SECRET"],
    )

    def _leak(req):
        return ContractResponse(
            status="allowed",
            text=f"echo {secret}",
            error=f"token {secret}",
            context_refs=[secret],
            side_effect={"token": secret},
        )

    result = _run(contract, CallableContractTarget(_leak))
    oracle = _oracle("oracle.contract.redaction")
    assert oracle.score(result.run).outcome is Outcome.SATISFIED

    # Simulate a field that kept the raw value: canonical storage escapes it,
    # so only the escaped form is present in the scanned text.
    result.run.matrix_obs[0]["error"] = f"leaked {secret}"
    stored = _stored_text(result.run)
    assert secret not in stored
    assert json.dumps(secret, ensure_ascii=True)[1:-1] in stored

    evidence = oracle.score(result.run)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["REDFENCE_TEST_SECRET:leaked"]
    assert secret not in evidence.observed
    assert all(secret not in event for event in evidence.events)


def test_redaction_oracle_unset_secret_is_unsupported(monkeypatch):
    monkeypatch.delenv("REDFENCE_TEST_SECRET", raising=False)
    result = _run(
        _contract(
            matrix=[_read_cell("alice_reads_alpha", "alice", "doc_alpha_secret", "allow")],
            secrets=["REDFENCE_TEST_SECRET"],
        )
    )
    evidence = _oracle("oracle.contract.redaction").score(result.run)

    assert evidence.outcome is Outcome.UNSUPPORTED
    assert "no configured secret environment variable is set" in evidence.observed
