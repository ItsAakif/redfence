"""Contract reporters: deterministic JSON, minimal SARIF 2.1.0 and JUnit XML."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from redfence.bench.contract_oracles import contract_oracles
from redfence.bench.contract_runner import run_contract
from redfence.contracts.loader import parse_contract
from redfence.contracts.schema import ContractV1
from redfence.contracts.target import MockContractTarget
from redfence.report.contract_report import contract_payload, write_contract_json
from redfence.report.junit import write_junit
from redfence.report.sarif import write_sarif


def _payload(
    *,
    matrix: list[dict[str, object]] | None = None,
    secrets: list[str] | None = None,
) -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "t4-reports",
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
        "lifecycle": [],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": secrets or []},
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


def _violating_matrix() -> list[dict[str, object]]:
    return [
        {
            "id": "alice_reads_alpha",
            "identity": "alice",
            "source": "doc_alpha_secret",
            "action": "read",
            "expect": "deny",
        }
    ]


def _result(**kwargs: object):
    contract: ContractV1 = parse_contract(_payload(**kwargs))  # type: ignore[arg-type]
    result = run_contract(contract, MockContractTarget(contract))
    result.evidence = [oracle.score(result.run) for oracle in contract_oracles()]
    return result


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_contract_json_has_required_keys_and_summary(tmp_path):
    result = _result()
    path = write_contract_json(result, tmp_path / "nested" / "contract.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert set(payload) == {"contract", "matrix", "lifecycle", "metrics", "summary"}
    assert payload["contract"]["id"] == "t4-reports"
    assert payload["contract"]["adapter"] == "mock"
    assert len(payload["matrix"]) == 2
    assert payload["lifecycle"] == []
    assert set(payload["metrics"]) == {"matrix", "lifecycle", "budget"}
    assert set(payload["summary"]) == {
        "contract_id",
        "exit_code",
        "violations",
        "unsupported",
    }
    assert payload["summary"]["contract_id"] == "t4-reports"
    assert payload["summary"]["exit_code"] == 0
    assert "timestamp" not in path.read_text(encoding="utf-8")


def test_contract_json_is_byte_identical_across_writes(tmp_path):
    result = _result()
    first = write_contract_json(result, tmp_path / "first.json")
    second = write_contract_json(result, tmp_path / "second.json")
    assert first.read_bytes() == second.read_bytes()


def test_contract_json_redacts_secret_values(monkeypatch, tmp_path):
    secret = "t4-report-secret-value"
    monkeypatch.setenv("REDFENCE_REPORT_SECRET", secret)
    result = _result(secrets=["REDFENCE_REPORT_SECRET"])
    result.run.matrix_obs[0]["error"] = f"leaked {secret}"

    path = write_contract_json(result, tmp_path / "contract.json")
    text = path.read_text(encoding="utf-8")
    assert secret not in text
    assert "[REDACTED]" in text


def test_reports_redact_raw_and_escaped_secret_forms(monkeypatch, tmp_path):
    secret = 'sëcret"\\\t'
    monkeypatch.setenv("REDFENCE_REPORT_SECRET", secret)
    result = _result(secrets=["REDFENCE_REPORT_SECRET"])
    result.run.matrix_obs[0]["error"] = f"leaked {secret}"

    json_path = write_contract_json(result, tmp_path / "contract.json")
    sarif_path = write_sarif(result, tmp_path / "contract.sarif")
    junit_path = write_junit(result, tmp_path / "contract.junit.xml")

    forms = [
        secret,
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
        json.dumps(secret, ensure_ascii=True)[1:-1],
    ]
    for path in (json_path, sarif_path, junit_path):
        data = path.read_bytes()
        for form in forms:
            assert form.encode("utf-8") not in data
    assert b"[REDACTED]" in json_path.read_bytes()


def test_contract_payload_summary_lists_violation(tmp_path):
    result = _result(matrix=_violating_matrix())
    payload = contract_payload(result)

    assert payload["summary"]["exit_code"] == 1
    assert payload["summary"]["violations"] == ["oracle.contract.matrix"]
    assert "oracle.contract.lifecycle" in payload["summary"]["unsupported"]


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_minimal_shape_and_one_rule_per_oracle(tmp_path):
    result = _result(matrix=_violating_matrix())
    path = write_sarif(result, tmp_path / "contract.sarif")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["version"] == "2.1.0"
    assert payload["$schema"]
    assert len(payload["runs"]) == 1
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "RedFence"
    assert len(run["tool"]["driver"]["rules"]) == len(contract_oracles())

    assert len(run["results"]) == 1
    finding = run["results"][0]
    assert finding["ruleId"] == "oracle.contract.matrix"
    assert finding["level"] == "error"
    assert finding["message"]["text"]
    uri = finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "contract://t4-reports"


def test_sarif_clean_result_has_no_results(tmp_path):
    result = _result()
    path = write_sarif(result, tmp_path / "contract.sarif")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"] == []


def test_sarif_is_byte_identical_across_writes(tmp_path):
    result = _result(matrix=_violating_matrix())
    first = write_sarif(result, tmp_path / "first.sarif")
    second = write_sarif(result, tmp_path / "second.sarif")
    assert first.read_bytes() == second.read_bytes()


# ---------------------------------------------------------------------------
# JUnit
# ---------------------------------------------------------------------------


def test_junit_one_testcase_per_cell_and_failure_on_violation(tmp_path):
    result = _result(matrix=_violating_matrix())
    path = write_junit(result, tmp_path / "nested" / "contract.junit.xml")
    root = ET.parse(path).getroot()

    assert root.tag == "testsuites"
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.get("name") == "t4-reports"
    assert suite.get("tests") == "1"
    assert suite.get("failures") == "1"

    cases = suite.findall("testcase")
    assert len(cases) == 1
    assert cases[0].get("classname") == "contract"
    assert cases[0].get("name") == "alice_reads_alpha"
    failure = cases[0].find("failure")
    assert failure is not None
    assert "expected deny" in (failure.get("message") or "")


def test_junit_clean_result_has_no_failure_elements(tmp_path):
    result = _result()
    path = write_junit(result, tmp_path / "contract.junit.xml")
    root = ET.parse(path).getroot()
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.get("tests") == "2"
    assert suite.get("failures") == "0"
    assert suite.findall(".//failure") == []


def test_junit_is_byte_identical_across_writes(tmp_path):
    result = _result(matrix=_violating_matrix())
    first = write_junit(result, tmp_path / "first.junit.xml")
    second = write_junit(result, tmp_path / "second.junit.xml")
    assert first.read_bytes() == second.read_bytes()


def test_reporters_create_missing_parent_directories(tmp_path):
    result = _result()
    json_path = write_contract_json(result, tmp_path / "a" / "b" / "c.json")
    sarif_path = write_sarif(result, tmp_path / "a" / "b" / "c.sarif")
    junit_path = write_junit(result, tmp_path / "a" / "b" / "c.junit.xml")
    assert all(Path(item).is_file() for item in (json_path, sarif_path, junit_path))
