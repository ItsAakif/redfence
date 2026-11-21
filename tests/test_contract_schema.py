"""Contract v1 schema: shape, enums, ids and in-memory bounds."""

from __future__ import annotations

import copy

import pytest

from redfence.contracts import ContractError, ContractV1, parse_contract
from redfence.contracts.schema import CANARY_LABELS


def valid_payload() -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "acme-rag-prod",
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
        "matrix": [
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
                "id": "alice_posts_web",
                "identity": "alice",
                "action": "tool",
                "tool": "http_post",
                "expect": "deny",
            },
        ],
        "lifecycle": [
            {"id": "revoke_alice", "action": "revoke", "identity": "alice"},
            {"id": "delete_beta", "action": "delete", "source": "doc_beta_secret"},
        ],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": ["REDFENCE_TARGET_TOKEN"]},
        "target": {"adapter": "mock"},
    }


def _raise(payload: dict[str, object]) -> ContractError:
    with pytest.raises(ContractError) as caught:
        parse_contract(payload)
    return caught.value


def test_valid_plain_mapping_parses():
    contract = parse_contract(valid_payload())
    assert isinstance(contract, ContractV1)
    assert contract.contract_version == 1
    assert contract.id == "acme-rag-prod"
    assert [item.id for item in contract.identities] == ["alice", "bob"]
    assert contract.matrix[0].expect == "allow"
    assert contract.target.adapter == "mock"


def test_contract_model_config_forbids_extra():
    assert ContractV1.model_config["extra"] == "forbid"


def test_unknown_top_level_key_rejected():
    payload = valid_payload()
    payload["bogus"] = True
    error = _raise(payload)
    assert error.code == "unknown_field"
    assert error.path


def test_unknown_nested_key_rejected():
    payload = valid_payload()
    payload["target"]["bogus"] = "x"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "unknown_field"
    assert error.path == "target.bogus"


def test_missing_required_field_rejected():
    payload = valid_payload()
    del payload["target"]
    error = _raise(payload)
    assert error.code == "missing_field"
    assert error.path == "target"


def test_bad_contract_version_rejected():
    payload = valid_payload()
    payload["contract_version"] = 2
    error = _raise(payload)
    assert error.code == "invalid_contract_version"
    assert error.path == "contract_version"


def test_bad_id_rejected():
    payload = valid_payload()
    payload["identities"][0]["id"] = "Alice"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_id"
    assert error.path == "identities.0.id"


def test_bad_contract_id_rejected():
    payload = valid_payload()
    payload["id"] = "-leading-dash"
    error = _raise(payload)
    assert error.code == "invalid_id"
    assert error.path == "id"


def test_duplicate_identity_ids_rejected():
    payload = valid_payload()
    payload["identities"][1]["id"] = "alice"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "duplicate_id"
    assert error.path == "identities.1.id"


def test_duplicate_matrix_ids_rejected():
    payload = valid_payload()
    payload["matrix"][1]["id"] = payload["matrix"][0]["id"]  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "duplicate_id"
    assert error.path == "matrix.1.id"


def test_bad_action_rejected():
    payload = valid_payload()
    payload["matrix"][0]["action"] = "write"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_action"
    assert error.path == "matrix.0.action"


def test_bad_expect_rejected():
    payload = valid_payload()
    payload["matrix"][0]["expect"] = "maybe"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_expect"
    assert error.path == "matrix.0.expect"


def test_callable_adapter_rejected_from_mapping():
    payload = valid_payload()
    payload["target"]["adapter"] = "callable"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "callable_adapter_forbidden"
    assert error.path == "target.adapter"


def test_env_interpolation_rejected():
    payload = valid_payload()
    payload["target"]["url"] = "https://${TARGET_HOST}/v1"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "env_interpolation"
    assert error.path == "target.url"


def test_path_traversal_rejected():
    payload = valid_payload()
    payload["dataset"]["template"] = "../classic"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "path_traversal"
    assert error.path == "dataset.template"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_ms", 0),
        ("timeout_ms", 60_001),
        ("max_response_bytes", 0),
        ("max_response_bytes", 1_048_577),
        ("max_requests", 0),
        ("max_requests", 1001),
    ],
)
def test_limits_bounds_rejected(field, value):
    payload = valid_payload()
    payload["limits"][field] = value  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "limits_out_of_range"
    assert error.path == f"limits.{field}"


@pytest.mark.parametrize(
    "entry",
    ["https://example.com", "example.com/path", "example.com:443", "-bad.example"],
)
def test_egress_entry_must_be_bare_hostname(entry):
    payload = valid_payload()
    payload["limits"]["egress_allowlist"] = [entry]  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_egress_entry"
    assert error.path == "limits.egress_allowlist.0"


def test_egress_allowlist_accepts_hostnames():
    payload = valid_payload()
    hosts = ["localhost", "127.0.0.1", "example.com"]
    payload["limits"]["egress_allowlist"] = hosts  # type: ignore[index]
    contract = parse_contract(payload)
    assert contract.limits.egress_allowlist == hosts


def test_cleartext_canary_value_rejected():
    payload = valid_payload()
    payload["sources"][0]["canary_ref"] = "CANARY_ALPHA_DEADBEEF"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_canary_ref"
    assert error.path == "sources.0.canary_ref"


def test_all_canary_labels_accepted():
    for label in sorted(CANARY_LABELS):
        payload = valid_payload()
        payload["sources"][0]["canary_ref"] = label  # type: ignore[index]
        assert parse_contract(payload).sources[0].canary_ref == label


def test_secret_must_be_environment_variable_name():
    payload = valid_payload()
    payload["redaction"]["secrets"] = ["lower-case-name"]  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_secret_name"
    assert error.path == "redaction.secrets.0"


def test_non_string_key_rejected():
    payload = valid_payload()
    payload[1] = "x"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "non_string_key"


def test_depth_exceeded_rejected():
    payload = valid_payload()
    nested: object = "leaf"
    for _ in range(40):
        nested = {"level": nested}
    payload["dataset"]["nested"] = nested  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "depth_exceeded"
    assert error.path


def test_cyclic_mapping_rejected():
    payload = valid_payload()
    payload["dataset"]["nested"] = payload  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "depth_exceeded"
    assert error.path == "$"


def test_invalid_field_type_rejected():
    payload = valid_payload()
    payload["dataset"]["seed"] = "not-an-int"  # type: ignore[index]
    error = _raise(payload)
    assert error.code == "invalid_type"
    assert error.path == "dataset.seed"


def _identities(count: int) -> list[dict[str, object]]:
    return [
        {
            "id": f"user_{index}",
            "tenant": "t_alpha",
            "roles": [],
            "groups": [],
            "clearance": "public",
        }
        for index in range(count)
    ]


def _sources(count: int) -> list[dict[str, object]]:
    return [
        {
            "id": f"doc_{index}",
            "tenant": "t_alpha",
            "classification": "public",
            "acl": {},
        }
        for index in range(count)
    ]


def _cells(count: int) -> list[dict[str, object]]:
    return [
        {"id": f"cell_{index}", "identity": "alice", "action": "read", "expect": "allow"}
        for index in range(count)
    ]


def _steps(count: int) -> list[dict[str, object]]:
    return [
        {"id": f"step_{index}", "action": "revoke", "identity": "alice"}
        for index in range(count)
    ]


@pytest.mark.parametrize(
    ("field", "builder", "limit", "code"),
    [
        ("identities", _identities, 128, "too_many_identities"),
        ("sources", _sources, 256, "too_many_sources"),
        ("matrix", _cells, 512, "too_many_matrix_cells"),
        ("lifecycle", _steps, 64, "too_many_lifecycle_steps"),
    ],
)
def test_collection_bounds_rejected(field, builder, limit, code):
    payload = valid_payload()
    payload[field] = builder(limit + 1)
    error = _raise(payload)
    assert error.code == code
    assert error.path == field


def test_contract_error_is_value_error_with_code_and_path():
    payload = valid_payload()
    payload["id"] = "Bad Id"
    error = _raise(payload)
    assert isinstance(error, ValueError)
    assert error.code == "invalid_id"
    assert error.path == "id"
    assert "invalid_id" in str(error)


def test_parse_contract_does_not_mutate_input():
    payload = valid_payload()
    before = copy.deepcopy(payload)
    parse_contract(payload)
    assert payload == before
