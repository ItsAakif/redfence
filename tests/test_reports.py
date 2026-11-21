"""Report emission."""

from __future__ import annotations

import json

from redfence.bench.metrics import compute_metrics
from redfence.bench.runner import run_campaign
from redfence.report import write_html_report, write_json_report
from redfence.targets.config import SecurityProfile


def test_json_and_html_reports_are_written(tmp_path):
    result = run_campaign(SecurityProfile.SECURED, out_dir=tmp_path)
    assert result.json_path is not None and result.json_path.exists()
    assert result.html_path is not None and result.html_path.exists()


def test_json_report_is_machine_readable(tmp_path):
    result = run_campaign(SecurityProfile.SECURED, out_dir=tmp_path)
    payload = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["exit_code"] == 0
    assert payload["summary"]["violations"] == []
    assert "evidence" in payload and "metrics" in payload


def test_html_report_contains_evidence_and_standards_note(tmp_path):
    result = run_campaign(SecurityProfile.VULNERABLE, out_dir=tmp_path)
    html = result.html_path.read_text(encoding="utf-8")
    assert "oracle.index.acl" in html
    assert "not a certification" in html


def test_distinct_templates_write_distinct_reports(tmp_path):
    classic = run_campaign(SecurityProfile.SECURED, template="classic", out_dir=tmp_path)
    secret_tier = run_campaign(SecurityProfile.SECURED, template="secret_tier", out_dir=tmp_path)
    assert classic.json_path != secret_tier.json_path
    assert classic.html_path != secret_tier.html_path
    assert classic.json_path.exists() and secret_tier.json_path.exists()
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_reports_are_byte_identical_for_identical_inputs(tmp_path):
    first = run_campaign(SecurityProfile.SECURED, out_dir=tmp_path / "first")
    second = run_campaign(SecurityProfile.SECURED, out_dir=tmp_path / "second")
    assert first.json_path is not None and second.json_path is not None
    assert first.html_path is not None and second.html_path is not None
    assert first.json_path.name == second.json_path.name
    assert first.html_path.name == second.html_path.name
    assert first.json_path.read_bytes() == second.json_path.read_bytes()
    assert first.html_path.read_bytes() == second.html_path.read_bytes()


def test_reports_render_undefined_utility_without_crashing(tmp_path):
    result = run_campaign(SecurityProfile.SECURED)
    result.run.utility_obs = None
    result.metrics = compute_metrics(result.run, result.evidence)
    assert result.metrics.benign_task_success.value is None

    json_path = write_json_report(result, tmp_path / "undefined-utility.json")
    html_path = write_html_report(result, tmp_path / "undefined-utility.html")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["metrics"]["benign_task_success"]["value"] is None
    html = html_path.read_text(encoding="utf-8")
    assert "<td>benign_task_success</td><td>0/0</td><td>n/a</td>" in html
