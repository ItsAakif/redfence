"""Reproducibility: replays must yield identical outcomes."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import redfence
from redfence.bench.dataset import DEFAULT_SEED, scenario_id
from redfence.bench.runner import run_campaign
from redfence.core.clock import FIXED_INSTANT
from redfence.core.domain import CacheEntry
from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import json_digest
from redfence.targets.config import SecurityProfile


def _outcomes(result):
    return {item.oracle_id: item.outcome.value for item in result.evidence}


def _minimal_evidence() -> Evidence:
    return Evidence(
        evidence_id="ev-test",
        scenario_id="scenario-test",
        oracle_id="oracle.test",
        facet="test",
        expected="expected",
        observed="observed",
        outcome=Outcome.SATISFIED,
        method="test",
    )


def test_secured_replay_is_deterministic():
    first = run_campaign(SecurityProfile.SECURED)
    second = run_campaign(SecurityProfile.SECURED)
    assert _outcomes(first) == _outcomes(second)
    assert first.manifest == second.manifest


def test_vulnerable_replay_is_deterministic():
    first = run_campaign(SecurityProfile.VULNERABLE)
    second = run_campaign(SecurityProfile.VULNERABLE)
    assert _outcomes(first) == _outcomes(second)


def test_seed_changes_corpus_but_not_control_outcome():
    first = run_campaign(SecurityProfile.SECURED, seed=20260101)
    second = run_campaign(SecurityProfile.SECURED, seed=20260102)
    assert first.scenario_id != second.scenario_id
    assert first.manifest["canary_markers"] != second.manifest["canary_markers"]
    assert _outcomes(first) == _outcomes(second)


def test_legacy_scenario_id_call_is_supported():
    identifier = scenario_id("secured", 20260101)
    assert identifier.startswith("scenario_")
    assert identifier == scenario_id("secured", seed=20260101)


def test_template_changes_scenario_id():
    classic = scenario_id("secured", DEFAULT_SEED, template="classic")
    secret_tier = scenario_id("secured", DEFAULT_SEED, template="secret_tier")
    assert classic != secret_tier


def test_distinct_custom_fault_sets_have_distinct_ids():
    first = scenario_id("custom", DEFAULT_SEED, faults=("missing_query_acl",))
    second = scenario_id("custom", DEFAULT_SEED, faults=("unscoped_cache_key",))
    assert first != second


def test_dev_and_heldout_kind_have_distinct_ids():
    dev = scenario_id("secured", DEFAULT_SEED, kind="revocation")
    heldout = scenario_id("secured", DEFAULT_SEED, kind="acl.modify.replay")
    assert dev != heldout


def test_manifest_records_provenance():
    result = run_campaign(SecurityProfile.SECURED)
    manifest = result.manifest
    assert manifest["manifest_schema"] == 2
    assert manifest["package_version"] == redfence.__version__
    assert manifest["dataset_version"] == result.run.corpus.dataset_version
    assert manifest["scenario_kind"] == "revocation"
    assert manifest["template"] == "classic"
    assert manifest["faults"] == sorted(result.run.target.faults.enabled())
    assert manifest["faults_sha256"] == json_digest(manifest["faults"])
    assert manifest["oracle_isolation"] == "in_process"
    assert "oracle_pid" not in manifest


def test_manifest_corpus_digest_matches_content():
    manifest = run_campaign(SecurityProfile.SECURED).manifest
    corpus_manifest = manifest["corpus_manifest"]
    assert manifest["corpus_manifest_sha256"] == json_digest(corpus_manifest)
    documents = corpus_manifest["documents"]
    assert documents
    assert all("content_hash" in document for document in documents)


def test_pyproject_version_matches_package_version():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as handle:
        project_version = tomllib.load(handle)["project"]["version"]
    assert project_version == redfence.__version__


def test_evidence_and_cache_default_to_fixed_instant():
    assert _minimal_evidence().timestamp == FIXED_INSTANT
    entry = CacheEntry(
        key="k",
        query="q",
        tenant_id="tenant",
        entitlement_fingerprint="ent",
        acl_epoch=1,
        answer="answer",
    )
    assert entry.created_at == FIXED_INSTANT


def test_replay_evidence_json_is_equal():
    first = run_campaign(SecurityProfile.SECURED)
    second = run_campaign(SecurityProfile.SECURED)
    first_dump = [item.model_dump(mode="json") for item in first.evidence]
    second_dump = [item.model_dump(mode="json") for item in second.evidence]
    assert first_dump == second_dump


def test_cli_reports_are_byte_identical_across_processes(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    outputs = [tmp_path / "run-a", tmp_path / "run-b"]
    for out_dir in outputs:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "redfence.cli",
                "run",
                "--profile",
                "secured",
                "--out",
                str(out_dir),
            ],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
    for pattern in ("*.json", "*.html"):
        report_files = [sorted(out_dir.glob(pattern)) for out_dir in outputs]
        assert all(len(files) == 1 for files in report_files)
        assert report_files[0][0].read_bytes() == report_files[1][0].read_bytes()
