"""Contract CLI: validate/test exit codes, reports and determinism."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from redfence.cli import main
from redfence.contracts.target import ContractRequest, ContractResponse


def _payload(
    *,
    matrix: list[dict[str, object]] | None = None,
    lifecycle: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "cli-contract",
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
        "matrix": matrix if matrix is not None else _clean_matrix(),
        "lifecycle": lifecycle if lifecycle is not None else [],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": []},
        "target": {"adapter": "mock"},
    }


def _clean_matrix() -> list[dict[str, object]]:
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
    ]


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_valid_contract_returns_zero(tmp_path, capsys):
    path = _write(tmp_path, _payload())
    assert main(["contract", "validate", str(path)]) == 0
    assert "valid contract=cli-contract" in capsys.readouterr().out


def test_validate_malformed_returns_three(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text('{"contract_version": 1,', encoding="utf-8")

    assert main(["contract", "validate", str(path)]) == 3
    assert "error=invalid_json" in capsys.readouterr().out


def test_validate_unsupported_format_returns_three(tmp_path, capsys):
    path = tmp_path / "contract.md"
    path.write_text("# not a contract\n", encoding="utf-8")

    assert main(["contract", "validate", str(path)]) == 3
    output = capsys.readouterr().out
    assert "error=unsupported_format" in output
    assert f"path={path}" in output


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


def test_contract_test_clean_returns_zero_and_writes_parseable_reports(
    tmp_path, capsys
):
    path = _write(tmp_path, _payload())
    out_dir = tmp_path / "reports"

    assert (
        main(
            [
                "contract",
                "test",
                str(path),
                "--adapter",
                "mock",
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )
    assert "exit=0" in capsys.readouterr().out

    report = json.loads((out_dir / "cli-contract.json").read_text(encoding="utf-8"))
    assert set(report) == {"contract", "matrix", "lifecycle", "metrics", "summary"}
    assert report["summary"]["contract_id"] == "cli-contract"
    assert report["summary"]["exit_code"] == 0
    assert report["summary"]["violations"] == []

    sarif = json.loads((out_dir / "cli-contract.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "RedFence"

    junit = ET.parse(out_dir / "cli-contract.junit.xml").getroot()
    suite = junit.find("testsuite")
    assert suite is not None
    assert suite.get("tests") == "2"
    assert suite.get("failures") == "0"


def test_contract_test_violation_returns_one(tmp_path):
    payload = _payload(
        matrix=[
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "deny",
            }
        ]
    )
    path = _write(tmp_path, payload)
    out_dir = tmp_path / "reports"

    assert (
        main(
            [
                "contract",
                "test",
                str(path),
                "--adapter",
                "mock",
                "--out",
                str(out_dir),
            ]
        )
        == 1
    )

    report = json.loads((out_dir / "cli-contract.json").read_text(encoding="utf-8"))
    assert report["summary"]["exit_code"] == 1
    assert "oracle.contract.matrix" in report["summary"]["violations"]

    sarif = json.loads((out_dir / "cli-contract.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["results"][0]["ruleId"] == "oracle.contract.matrix"
    assert sarif["runs"][0]["results"][0]["level"] == "error"

    junit = ET.parse(out_dir / "cli-contract.junit.xml").getroot()
    suite = junit.find("testsuite")
    assert suite is not None
    assert suite.get("failures") == "1"


def test_contract_test_no_capabilities_returns_two(tmp_path, monkeypatch):
    class _NoCapabilities:
        name = "none"
        capabilities: frozenset[str] = frozenset()

        def execute(self, _req: ContractRequest) -> ContractResponse:
            raise AssertionError("an unsupported action must not reach the adapter")

        def reset(self) -> None:
            return None

    monkeypatch.setattr(
        "redfence.cli._build_contract_target",
        lambda _contract, _adapter: _NoCapabilities(),
    )
    path = _write(tmp_path, _payload())

    assert (
        main(
            [
                "contract",
                "test",
                str(path),
                "--adapter",
                "mock",
                "--out",
                str(tmp_path / "reports"),
            ]
        )
        == 2
    )


def test_contract_test_adapter_exception_returns_two(tmp_path, monkeypatch):
    class _Exploding:
        name = "exploding"
        capabilities = frozenset({"read"})

        def execute(self, _req: ContractRequest) -> ContractResponse:
            raise RuntimeError("adapter exploded")

        def reset(self) -> None:
            return None

    monkeypatch.setattr(
        "redfence.cli._build_contract_target",
        lambda _contract, _adapter: _Exploding(),
    )
    path = _write(tmp_path, _payload())

    assert (
        main(
            [
                "contract",
                "test",
                str(path),
                "--adapter",
                "mock",
                "--out",
                str(tmp_path / "reports"),
            ]
        )
        == 2
    )


def test_contract_test_http_without_url_or_allowlist_returns_three(tmp_path, capsys):
    path = _write(tmp_path, _payload())

    assert (
        main(
            [
                "contract",
                "test",
                str(path),
                "--adapter",
                "http",
                "--out",
                str(tmp_path / "reports"),
            ]
        )
        == 3
    )
    assert "error=missing_target_url" in capsys.readouterr().out


def test_contract_reports_are_byte_identical_across_runs(tmp_path):
    path = _write(tmp_path, _payload())
    first = tmp_path / "first"
    second = tmp_path / "second"

    args = ["contract", "test", str(path), "--adapter", "mock", "--out"]
    assert main([*args, str(first)]) == 0
    assert main([*args, str(second)]) == 0

    for suffix in (".json", ".sarif", ".junit.xml"):
        assert (first / f"cli-contract{suffix}").read_bytes() == (
            second / f"cli-contract{suffix}"
        ).read_bytes()


def test_contract_test_missing_file_returns_three(tmp_path):
    assert (
        main(
            [
                "contract",
                "test",
                str(tmp_path / "absent.json"),
                "--out",
                str(tmp_path / "reports"),
            ]
        )
        == 3
    )


@pytest.mark.parametrize("adapter", ["mock"])
def test_contract_test_default_adapter_is_mock(tmp_path, adapter):
    path = _write(tmp_path, _payload())
    assert (
        main(
            [
                "contract",
                "test",
                str(path),
                "--adapter",
                adapter,
                "--out",
                str(tmp_path / "reports"),
            ]
        )
        == 0
    )
