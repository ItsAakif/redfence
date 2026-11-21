"""Bounded contract loader: JSON always, YAML only with the optional extra."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from redfence.contracts import ContractError, load_contract
from redfence.contracts.loader import MAX_FILE_BYTES


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


def _write_json(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


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


def _mutate_unknown_key(payload: dict[str, object]) -> None:
    payload["bogus"] = True


def _mutate_missing_field(payload: dict[str, object]) -> None:
    del payload["target"]


def _mutate_bad_id(payload: dict[str, object]) -> None:
    payload["identities"][0]["id"] = "Alice"  # type: ignore[index]


def _mutate_duplicate_id(payload: dict[str, object]) -> None:
    payload["identities"][1]["id"] = "alice"  # type: ignore[index]


def _mutate_bad_action(payload: dict[str, object]) -> None:
    payload["matrix"][0]["action"] = "write"  # type: ignore[index]


def _mutate_bad_expect(payload: dict[str, object]) -> None:
    payload["matrix"][0]["expect"] = "maybe"  # type: ignore[index]


def _mutate_bad_version(payload: dict[str, object]) -> None:
    payload["contract_version"] = 2


def _mutate_traversal(payload: dict[str, object]) -> None:
    payload["dataset"]["template"] = "../classic"  # type: ignore[index]


def _mutate_env(payload: dict[str, object]) -> None:
    payload["target"]["url"] = "https://${TARGET_HOST}/v1"  # type: ignore[index]


def _mutate_callable(payload: dict[str, object]) -> None:
    payload["target"]["adapter"] = "callable"  # type: ignore[index]


def _mutate_limits(payload: dict[str, object]) -> None:
    payload["limits"]["timeout_ms"] = 0  # type: ignore[index]


def _mutate_egress(payload: dict[str, object]) -> None:
    payload["limits"]["egress_allowlist"] = ["https://example.com"]  # type: ignore[index]


def _mutate_canary(payload: dict[str, object]) -> None:
    payload["sources"][0]["canary_ref"] = "CANARY_ALPHA_DEADBEEF"  # type: ignore[index]


def _mutate_secret(payload: dict[str, object]) -> None:
    payload["redaction"]["secrets"] = ["lower-case-name"]  # type: ignore[index]


def _mutate_unknown_cell_identity(payload: dict[str, object]) -> None:
    payload["matrix"][0]["identity"] = "alicee"  # type: ignore[index]


def _mutate_unknown_cell_source(payload: dict[str, object]) -> None:
    payload["matrix"][0]["source"] = "doc_nope"  # type: ignore[index]


def _mutate_unknown_step_identity(payload: dict[str, object]) -> None:
    payload["lifecycle"][0]["identity"] = "alicee"  # type: ignore[index]


def _mutate_unknown_step_source(payload: dict[str, object]) -> None:
    payload["lifecycle"][1]["source"] = "doc_nope"  # type: ignore[index]


def _mutate_type(payload: dict[str, object]) -> None:
    payload["dataset"]["seed"] = "not-an-int"  # type: ignore[index]


def _mutate_depth(payload: dict[str, object]) -> None:
    nested: object = "leaf"
    for _ in range(40):
        nested = {"level": nested}
    payload["dataset"]["nested"] = nested  # type: ignore[index]


def _mutate_identities(payload: dict[str, object]) -> None:
    payload["identities"] = _identities(129)


def _mutate_sources(payload: dict[str, object]) -> None:
    payload["sources"] = _sources(257)


def _mutate_cells(payload: dict[str, object]) -> None:
    payload["matrix"] = _cells(513)


def _mutate_steps(payload: dict[str, object]) -> None:
    payload["lifecycle"] = _steps(65)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (_mutate_unknown_key, "unknown_field"),
        (_mutate_missing_field, "missing_field"),
        (_mutate_bad_id, "invalid_id"),
        (_mutate_duplicate_id, "duplicate_id"),
        (_mutate_bad_action, "invalid_action"),
        (_mutate_bad_expect, "invalid_expect"),
        (_mutate_bad_version, "invalid_contract_version"),
        (_mutate_traversal, "path_traversal"),
        (_mutate_env, "env_interpolation"),
        (_mutate_callable, "callable_adapter_forbidden"),
        (_mutate_limits, "limits_out_of_range"),
        (_mutate_egress, "invalid_egress_entry"),
        (_mutate_canary, "invalid_canary_ref"),
        (_mutate_secret, "invalid_secret_name"),
        (_mutate_unknown_cell_identity, "unknown_identity"),
        (_mutate_unknown_cell_source, "unknown_source"),
        (_mutate_unknown_step_identity, "unknown_identity"),
        (_mutate_unknown_step_source, "unknown_source"),
        (_mutate_type, "invalid_type"),
        (_mutate_depth, "depth_exceeded"),
        (_mutate_identities, "too_many_identities"),
        (_mutate_sources, "too_many_sources"),
        (_mutate_cells, "too_many_matrix_cells"),
        (_mutate_steps, "too_many_lifecycle_steps"),
    ],
    ids=lambda item: getattr(item, "__name__", item),
)
def test_json_path_enforces_every_rule(tmp_path, mutate, code):
    payload = valid_payload()
    mutate(payload)
    path = _write_json(tmp_path, payload)
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == code
    assert caught.value.path


def test_valid_json_loads(tmp_path):
    contract = load_contract(_write_json(tmp_path, valid_payload()))
    assert contract.id == "acme-rag-prod"
    assert contract.target.adapter == "mock"


def test_unsupported_suffix_rejected(tmp_path):
    path = tmp_path / "contract.txt"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "unsupported_format"
    assert caught.value.path == str(path)


def test_oversize_file_rejected(tmp_path):
    path = tmp_path / "contract.json"
    path.write_bytes(b" " * (MAX_FILE_BYTES + 1))
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "file_too_large"
    assert caught.value.path == str(path)


def test_invalid_json_rejected(tmp_path):
    path = tmp_path / "contract.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "invalid_json"


def test_duplicate_json_key_rejected(tmp_path):
    path = tmp_path / "contract.json"
    path.write_text('{"contract_version": 1, "id": "a", "id": "b"}', encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "duplicate_key"
    assert caught.value.path == "id"


def test_deeply_nested_json_object_is_a_bounded_error(tmp_path):
    # A 30k-deep object is under MAX_FILE_BYTES but can overflow the C JSON
    # decoder before the explicit depth walk runs. It must still be typed.
    path = tmp_path / "contract.json"
    depth = 30_000
    path.write_text('{"a":' * depth + "1" + "}" * depth, encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "depth_exceeded"


def test_yaml_without_extra_reports_missing_dependency(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    path = tmp_path / "contract.yaml"
    path.write_text("contract_version: 1\n", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "yaml_extra_missing"
    assert caught.value.path == str(path)


def test_valid_yaml_loads(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(valid_payload()), encoding="utf-8")
    contract = load_contract(path)
    assert contract.id == "acme-rag-prod"


def test_yaml_duplicate_key_rejected(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text("contract_version: 1\nid: a\nid: b\n", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "duplicate_key"


def test_yaml_merge_key_with_alias_is_rejected(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text(
        "contract_version: 1\nbase: &base {id: a}\n<<: *base\n", encoding="utf-8"
    )
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "yaml_anchor_forbidden"


def test_yaml_merge_key_cannot_bypass_duplicate_detection(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text("contract_version: 1\nid: a\n<<: {id: b}\n", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "duplicate_key"
    assert caught.value.path == "id"


def test_yaml_anchor_rejected(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text("a: &shared 1\nb: *shared\n", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "yaml_anchor_forbidden"


def test_yaml_tag_rejected(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text("a: !!python/object:os.system x\n", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "yaml_tag_forbidden"


def test_yaml_non_string_key_rejected(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "contract.yaml"
    path.write_text("1: value\n", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "non_string_key"


def test_yaml_deep_nesting_rejected(tmp_path):
    pytest.importorskip("yaml")
    payload = valid_payload()
    nested: object = "leaf"
    for _ in range(40):
        nested = {"level": nested}
    payload["dataset"]["nested"] = nested  # type: ignore[index]
    path = tmp_path / "contract.yaml"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        load_contract(path)
    assert caught.value.code == "depth_exceeded"


def test_load_contract_accepts_path_object(tmp_path):
    path = _write_json(tmp_path, valid_payload())
    assert isinstance(path, Path)
    assert load_contract(path).id == "acme-rag-prod"


def test_load_contract_accepts_string_path(tmp_path):
    path = _write_json(tmp_path, valid_payload())
    assert load_contract(str(path)).id == "acme-rag-prod"
