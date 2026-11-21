"""Optional interop adapters stay lazy and fail helpfully when extras are absent."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from redfence import Evidence, Outcome
from redfence.integrations.inspect_task import redfence_task
from redfence.integrations.otel import export_evidence

_OPTIONAL_MODULES = ("inspect_ai", "opentelemetry", "yaml", "hypothesis")


def _payload() -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "interop-contract",
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


def _write_contract(tmp_path: Path) -> Path:
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    return path


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="ev_1",
        scenario_id="sc_1",
        oracle_id="oracle.index.acl",
        facet="index",
        expected="allow",
        observed="allow",
        outcome=Outcome.SATISFIED,
        method="test",
    )


class _RecordingSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, str] = {}

    def set_attribute(self, key: str, value: str) -> None:
        self.attributes[key] = value

    def __enter__(self) -> _RecordingSpan:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _RecordingTracer:
    def __init__(self) -> None:
        self.spans: list[_RecordingSpan] = []

    def start_as_current_span(self, name: str) -> _RecordingSpan:
        span = _RecordingSpan()
        self.spans.append(span)
        return span


def test_import_redfence_does_not_import_optional_modules() -> None:
    code = (
        "import sys\n"
        "import redfence\n"
        "import redfence.integrations\n"
        f"optional = {_OPTIONAL_MODULES!r}\n"
        "print(','.join(name for name in optional if name in sys.modules))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == ""


def test_integrations_package_exports_nothing() -> None:
    import redfence.integrations as integrations

    assert integrations.__all__ == []


def test_redfence_task_requires_inspect_extra(tmp_path: Path) -> None:
    if importlib.util.find_spec("inspect_ai") is not None:
        pytest.skip("inspect_ai is installed")
    with pytest.raises(RuntimeError, match="inspect extra not installed"):
        redfence_task(_write_contract(tmp_path))


def test_export_evidence_requires_opentelemetry_without_tracer() -> None:
    if importlib.util.find_spec("opentelemetry") is not None:
        pytest.skip("opentelemetry is installed")
    with pytest.raises(RuntimeError, match="opentelemetry extra not installed"):
        export_evidence([_evidence()])


def test_export_evidence_with_injected_tracer_emits_one_span_per_evidence() -> None:
    tracer = _RecordingTracer()
    assert export_evidence([_evidence(), _evidence()], tracer=tracer) == 2
    assert len(tracer.spans) == 2
    assert tracer.spans[0].attributes == {
        "redfence.oracle_id": "oracle.index.acl",
        "redfence.facet": "index",
        "redfence.outcome": "satisfied",
        "redfence.evidence_id": "ev_1",
    }


def test_redfence_task_returns_task_when_inspect_installed(tmp_path: Path) -> None:
    pytest.importorskip("inspect_ai")
    task = redfence_task(_write_contract(tmp_path))
    assert task is not None
    assert len(task.dataset) == 2
    assert [sample.target for sample in task.dataset] == ["allow", "deny"]


def test_export_evidence_emits_when_opentelemetry_installed() -> None:
    pytest.importorskip("opentelemetry")
    assert export_evidence([_evidence(), _evidence()]) == 2
