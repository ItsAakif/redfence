"""Contract runner: matrix, lifecycle replay, redaction and exit codes."""

from __future__ import annotations

import json

from redfence.bench.contract_oracles import contract_oracles
from redfence.bench.contract_runner import (
    _MAX_REDACT_NODES,
    _expected_after,
    run_contract,
)
from redfence.contracts.loader import parse_contract
from redfence.contracts.schema import ContractV1, LifecycleStep, MatrixCell
from redfence.contracts.target import (
    CallableContractTarget,
    ContractRequest,
    ContractResponse,
    MockContractTarget,
)


def _payload(
    *,
    matrix: list[dict[str, object]] | None = None,
    lifecycle: list[dict[str, object]] | None = None,
    secrets: list[str] | None = None,
) -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "t3-contract",
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
        "matrix": matrix if matrix is not None else _matrix(),
        "lifecycle": lifecycle if lifecycle is not None else [],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": secrets or []},
        "target": {"adapter": "mock"},
    }


def _matrix() -> list[dict[str, object]]:
    return [
        {
            "id": "alice_reads_alpha",
            "identity": "alice",
            "source": "doc_alpha_secret",
            "action": "read",
            "expect": "allow",
        },
        {
            "id": "bob_reads_alpha",
            "identity": "bob",
            "source": "doc_alpha_secret",
            "action": "read",
            "expect": "deny",
        },
        {
            "id": "bob_reads_beta",
            "identity": "bob",
            "source": "doc_beta_secret",
            "action": "read",
            "expect": "allow",
        },
        {
            "id": "alice_answers_alpha",
            "identity": "alice",
            "source": "doc_alpha_secret",
            "action": "answer",
            "expect": "allow",
        },
        {
            "id": "alice_posts_web",
            "identity": "alice",
            "action": "tool",
            "tool": "http_post",
            "expect": "deny",
        },
        {
            "id": "alice_searches",
            "identity": "alice",
            "action": "tool",
            "tool": "search_documents",
            "expect": "allow",
        },
    ]


def _contract(**kwargs: object) -> ContractV1:
    return parse_contract(_payload(**kwargs))  # type: ignore[arg-type]


def _run(contract: ContractV1, **kwargs: object):
    return run_contract(contract, MockContractTarget(contract), **kwargs)  # type: ignore[arg-type]


def test_matrix_populates_expected_observed_and_action_observations():
    result = _run(_contract())
    observations = result.run.matrix_obs

    assert [item["cell_id"] for item in observations] == [
        "alice_reads_alpha",
        "bob_reads_alpha",
        "bob_reads_beta",
        "alice_answers_alpha",
        "alice_posts_web",
        "alice_searches",
    ]
    assert [(item["expected"], item["observed"]) for item in observations] == [
        ("allow", "allow"),
        ("deny", "deny"),
        ("allow", "allow"),
        ("allow", "allow"),
        ("deny", "deny"),
        ("allow", "allow"),
    ]
    assert all(item["status"] in {"allowed", "denied"} for item in observations)
    assert all(item["response_hash"] for item in observations)

    assert len(result.run.retrieval_obs) == 3
    assert len(result.run.answer_obs) == 1
    assert len(result.run.tool_obs) == 2
    assert result.run.utility_obs is None
    assert result.run.memory_obs == []
    assert result.run.deletion_obs == []

    admitted = result.run.retrieval_obs[0]["admitted"]
    assert admitted == [
        {
            "chunk_id": "doc_alpha_secret",
            "doc_id": "doc_alpha_secret",
            "tenant_id": "t_alpha",
            "classification": "confidential",
            "deleted": False,
        }
    ]
    assert result.run.answer_obs[0]["cache_hit"] is False
    assert result.run.answer_obs[0]["cache_doc_versions"] == {}
    assert result.run.answer_obs[0]["canaries_present"] == []
    assert result.run.tool_obs[0]["execution"].executed is False
    assert result.run.tool_obs[1]["execution"].executed is True

    assert result.run.budget_obs is not None
    assert result.run.budget_obs["requests"] == 6
    assert result.run.budget_obs["max_requests"] == 32
    assert result.exit_code == 0


def test_matrix_expectation_violation_sets_exit_code_one():
    matrix = [
        {
            "id": "alice_reads_alpha",
            "identity": "alice",
            "source": "doc_alpha_secret",
            "action": "read",
            "expect": "deny",
        }
    ]
    result = _run(_contract(matrix=matrix))

    assert result.run.matrix_obs[0]["expected"] == "deny"
    assert result.run.matrix_obs[0]["observed"] == "allow"
    assert result.exit_code == 1


def test_lifecycle_delete_then_revoke_replays_and_matches_derived_expectation():
    matrix = [
        {
            "id": "alice_reads_alpha",
            "identity": "alice",
            "source": "doc_alpha_secret",
            "action": "read",
            "expect": "allow",
        },
        {
            "id": "bob_reads_beta",
            "identity": "bob",
            "source": "doc_beta_secret",
            "action": "read",
            "expect": "allow",
        },
    ]
    lifecycle = [
        {"id": "delete_alpha", "action": "delete", "source": "doc_alpha_secret"},
        {"id": "revoke_alice", "action": "revoke", "identity": "alice"},
    ]
    result = _run(_contract(matrix=matrix, lifecycle=lifecycle))

    delete_obs, revoke_obs = result.run.lifecycle_obs
    assert delete_obs["step_id"] == "delete_alpha"
    assert delete_obs["replayed_cell_ids"] == ["alice_reads_alpha"]
    assert delete_obs["violations"] == []

    assert revoke_obs["step_id"] == "revoke_alice"
    assert revoke_obs["replayed_cell_ids"] == ["alice_reads_alpha"]
    assert revoke_obs["violations"] == []

    replayed = [
        item
        for item in result.run.retrieval_obs
        if item["phase"] in {"delete_alpha", "revoke_alice"}
    ]
    assert replayed
    assert all(item["admitted"] == [] for item in replayed)
    assert result.run.target.store.get("doc_alpha_secret").deleted is True  # type: ignore[union-attr]
    assert result.exit_code == 0


def test_run_is_deterministic_for_same_contract_and_target(tmp_path):
    contract = _contract(
        lifecycle=[
            {"id": "revoke_alice", "action": "revoke", "identity": "alice"},
            {"id": "delete_alpha", "action": "delete", "source": "doc_alpha_secret"},
        ]
    )
    target = MockContractTarget(contract)
    first = run_contract(contract, target, out_dir=tmp_path / "first")
    second = run_contract(contract, target, out_dir=tmp_path / "second")

    assert json.dumps(first.run.matrix_obs, sort_keys=True) == json.dumps(
        second.run.matrix_obs, sort_keys=True
    )
    assert json.dumps(first.run.lifecycle_obs, sort_keys=True) == json.dumps(
        second.run.lifecycle_obs, sort_keys=True
    )
    assert json.dumps(first.run.retrieval_obs, sort_keys=True) == json.dumps(
        second.run.retrieval_obs, sort_keys=True
    )
    assert first.json_path is not None and second.json_path is not None
    assert first.json_path.read_bytes() == second.json_path.read_bytes()


def test_secret_echo_is_redacted_and_never_stored(monkeypatch, tmp_path):
    secret = "t3-super-secret-value"
    monkeypatch.setenv("REDFENCE_TARGET_TOKEN", secret)
    contract = _contract(
        matrix=[
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "allow",
            },
            {
                "id": "alice_searches",
                "identity": "alice",
                "action": "tool",
                "tool": "search_documents",
                "expect": "allow",
            },
        ],
        secrets=["REDFENCE_TARGET_TOKEN"],
    )

    def _leak(req: ContractRequest) -> ContractResponse:
        if req.action == "tool":
            return ContractResponse(
                status="allowed",
                tool_executed=True,
                side_effect={"token": secret, "nested": [secret]},
            )
        return ContractResponse(
            status="error",
            text=f"echo {secret}",
            error=f"token {secret}",
            context_refs=[secret],
        )

    target = CallableContractTarget(_leak)
    result = run_contract(contract, target, out_dir=tmp_path)

    observation = result.run.matrix_obs[0]
    assert observation["error"] is not None
    assert "[REDACTED]" in observation["error"]
    assert secret not in observation["error"]
    assert observation["context_refs"] == ["[REDACTED]"]
    stored = (
        json.dumps(result.run.matrix_obs)
        + json.dumps(result.run.retrieval_obs)
        + json.dumps(result.run.tool_obs, default=str)
    )
    assert secret not in stored
    assert result.json_path is not None
    assert secret not in result.json_path.read_text(encoding="utf-8")


def test_redaction_violation_in_evidence_sets_exit_code_one(monkeypatch):
    secret = "t3-exit-code-secret"
    monkeypatch.setenv("REDFENCE_TARGET_TOKEN", secret)
    contract = _contract(
        matrix=[_read_cell()],
        secrets=["REDFENCE_TARGET_TOKEN"],
    )
    result = _run(contract)
    result.evidence = [oracle.score(result.run) for oracle in contract_oracles()]
    assert result.exit_code == 0

    result.run.matrix_obs[0]["error"] = f"leaked {secret}"
    result.evidence = [oracle.score(result.run) for oracle in contract_oracles()]
    assert result.exit_code == 1


def test_unsupported_capability_yields_zero_observations():
    class _NoCapabilities:
        name = "none"
        capabilities: frozenset[str] = frozenset()

        def execute(self, _req: ContractRequest) -> ContractResponse:
            raise AssertionError("an unsupported action must not reach the adapter")

        def reset(self) -> None:
            return None

    contract = _contract()
    result = run_contract(contract, _NoCapabilities())

    assert result.run.matrix_obs == []
    assert result.run.retrieval_obs == []
    assert result.run.answer_obs == []
    assert result.run.tool_obs == []
    assert result.run.budget_obs is not None
    assert result.run.budget_obs["requests"] == 0
    assert result.exit_code == 2


def test_zero_cells_and_zero_lifecycle_steps_do_not_crash(tmp_path):
    contract = _contract(matrix=[], lifecycle=[])
    result = run_contract(contract, MockContractTarget(contract), out_dir=tmp_path)

    assert result.run.matrix_obs == []
    assert result.run.lifecycle_obs == []
    assert result.run.budget_obs is not None
    assert result.run.budget_obs["requests"] == 0
    assert result.exit_code == 0
    assert result.json_path == tmp_path / "t3-contract.json"
    assert json.loads(result.json_path.read_text(encoding="utf-8"))["contract_id"] == (
        "t3-contract"
    )


def test_snapshot_target_matches_contract_sources():
    contract = _contract()
    result = _run(contract)
    target = result.run.target

    assert result.run.adapter == "mock"
    assert result.run.capabilities == frozenset(
        {"read", "answer", "tool", "delete", "revoke"}
    )
    assert target.cache == {}
    assert target.faults.enabled() == []
    assert target.tools.spec("search_documents") is None

    alpha = target.store.get("doc_alpha_secret")
    beta = target.store.get("doc_beta_secret")
    assert alpha is not None and beta is not None
    assert (alpha.id, alpha.doc_id, alpha.tenant_id, alpha.deleted) == (
        "doc_alpha_secret",
        "doc_alpha_secret",
        "t_alpha",
        False,
    )
    assert alpha.acl.classification == "confidential"
    assert alpha.acl.allowed_roles == ["engineer"]
    assert alpha.acl.allowed_groups == ["alpha-eng"]
    assert beta.acl.allowed_groups == ["beta-eng"]
    assert target.store.all_chunks() == [alpha, beta]


def test_budget_counts_only_measured_values():
    contract = _contract(
        matrix=[
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "allow",
            }
        ]
    )
    target = CallableContractTarget(
        lambda _req: ContractResponse(
            status="error",
            text="0123456789",
            error="egress_denied after timeout",
            truncated=True,
        )
    )
    result = run_contract(contract, target)

    budget = result.run.budget_obs
    assert budget is not None
    assert budget["requests"] == 1
    assert budget["max_requests"] == 32
    assert budget["timeouts"] == 1
    assert budget["max_response_bytes_seen"] == 10
    assert budget["truncated"] == 1
    assert budget["egress_denied"] == 1
    assert result.run.matrix_obs[0]["observed"] == "error"
    assert result.exit_code == 1


def test_lifecycle_update_calls_adapter_and_records_step():
    contract = _contract(
        matrix=[
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "allow",
            }
        ],
        lifecycle=[{"id": "update_alpha", "action": "update", "source": "doc_alpha_secret"}],
    )
    result = _run(contract)

    assert result.run.lifecycle_obs[0]["action"] == "update"
    assert result.run.lifecycle_obs[0]["replayed_cell_ids"] == ["alice_reads_alpha"]
    assert result.run.lifecycle_obs[0]["violations"] == []
    assert result.exit_code == 0


def _read_cell(
    cell_id: str = "alice_reads_alpha",
    identity: str = "alice",
    source: str = "doc_alpha_secret",
    expect: str = "allow",
) -> dict[str, object]:
    return {
        "id": cell_id,
        "identity": identity,
        "source": source,
        "action": "read",
        "expect": expect,
    }


def test_lifecycle_revoke_denies_an_allowed_cell_without_a_violation():
    contract = _contract(
        matrix=[_read_cell()],
        lifecycle=[{"id": "revoke_alice", "action": "revoke", "identity": "alice"}],
    )
    result = _run(contract)

    observation = result.run.lifecycle_obs[0]
    assert observation["replayed_cell_ids"] == ["alice_reads_alpha"]
    assert observation["violations"] == []
    assert result.exit_code == 0


def test_lifecycle_ignored_revoke_is_a_violation():
    contract = _contract(
        matrix=[_read_cell()],
        lifecycle=[{"id": "revoke_alice", "action": "revoke", "identity": "alice"}],
    )

    def _always_allow(req: ContractRequest) -> ContractResponse:
        return ContractResponse(
            status="allowed",
            text="ok",
            context_refs=[req.source_id] if req.source_id else [],
        )

    result = run_contract(contract, CallableContractTarget(_always_allow))

    assert result.run.lifecycle_obs[0]["violations"] == [
        "alice_reads_alpha: expected deny after revoke, observed allow"
    ]
    assert result.exit_code == 1


def test_lifecycle_delete_denies_a_source_read_cell_without_a_violation():
    contract = _contract(
        matrix=[_read_cell()],
        lifecycle=[{"id": "delete_alpha", "action": "delete", "source": "doc_alpha_secret"}],
    )
    result = _run(contract)

    observation = result.run.lifecycle_obs[0]
    assert observation["replayed_cell_ids"] == ["alice_reads_alpha"]
    assert observation["violations"] == []
    assert result.exit_code == 0


def test_expected_after_derives_only_affected_allow_cells():
    allow_cell = MatrixCell(
        id="alice_reads_alpha",
        identity="alice",
        source="doc_alpha_secret",
        action="read",
        expect="allow",
    )
    deny_cell = MatrixCell(
        id="bob_reads_alpha",
        identity="bob",
        source="doc_alpha_secret",
        action="read",
        expect="deny",
    )
    revoke = LifecycleStep(id="revoke_alice", action="revoke", identity="alice")
    delete = LifecycleStep(id="delete_alpha", action="delete", source="doc_alpha_secret")
    update = LifecycleStep(id="update_alpha", action="update", source="doc_alpha_secret")

    assert _expected_after(allow_cell, revoke) == "deny"
    assert _expected_after(allow_cell, delete) == "deny"
    assert _expected_after(allow_cell, update) == "allow"
    assert _expected_after(deny_cell, revoke) == "deny"
    assert _expected_after(deny_cell, delete) == "deny"


def test_out_dir_is_optional():
    result = _run(_contract(matrix=[]))
    assert result.json_path is None
    assert result.sarif_path is None
    assert result.junit_path is None


def _single_tool_contract(*, secrets: list[str] | None = None):
    return _contract(
        matrix=[
            {
                "id": "alice_searches",
                "identity": "alice",
                "action": "tool",
                "tool": "search_documents",
                "expect": "allow",
            }
        ],
        secrets=secrets,
    )


def _run_side_effect(side_effect: dict[str, object]):
    return run_contract(
        _single_tool_contract(),
        CallableContractTarget(
            lambda _req: ContractResponse(
                status="allowed", tool_executed=True, side_effect=side_effect
            )
        ),
    )


def test_deeply_nested_or_cyclic_side_effect_is_bounded(monkeypatch):
    secret = "deep-side-effect-secret"
    monkeypatch.setenv("REDFENCE_TARGET_TOKEN", secret)
    contract = _single_tool_contract(secrets=["REDFENCE_TARGET_TOKEN"])

    nested: object = "leaf"
    for _ in range(5000):
        nested = {"next": nested}
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    for side_effect in (
        {"token": secret, "deep": nested},
        {"token": secret, "cycle": cyclic},
    ):
        result = run_contract(
            contract,
            CallableContractTarget(
                lambda _req, payload=side_effect: ContractResponse(
                    status="allowed", tool_executed=True, side_effect=payload
                )
            ),
        )
        stored = result.run.tool_obs[0]["execution"].side_effect
        rendered = json.dumps(stored, default=str)
        assert "[TRUNCATED]" in rendered
        assert secret not in rendered


def test_oversized_side_effect_is_truncated():
    side_effect = {"items": list(range(100_000))}
    result = _run_side_effect(side_effect)

    stored = result.run.tool_obs[0]["execution"].side_effect
    items = stored["items"]
    assert isinstance(items, list)
    assert len(items) <= _MAX_REDACT_NODES
    assert items[-1] == "[TRUNCATED]"
