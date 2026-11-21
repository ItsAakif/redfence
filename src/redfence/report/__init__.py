"""Report emission (deterministic JSON + standalone HTML)."""

from redfence.report.contract_report import write_contract_json
from redfence.report.html_report import write_html_report
from redfence.report.json_report import write_json_report
from redfence.report.junit import write_junit
from redfence.report.sarif import write_sarif

__all__ = [
    "write_contract_json",
    "write_html_report",
    "write_json_report",
    "write_junit",
    "write_sarif",
]
