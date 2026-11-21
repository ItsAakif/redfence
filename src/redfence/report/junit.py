"""JUnit XML for a contract matrix.

One ``<testcase>`` is emitted per executed matrix cell, with a ``<failure>``
child when the adapter's decision differs from the declared expectation. The
document is built with :mod:`xml.etree.ElementTree` and contains no timestamp.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING

from redfence.report.contract_report import redact_secrets

if TYPE_CHECKING:  # pragma: no cover
    from redfence.bench.contract_runner import ContractResult


def write_junit(result: ContractResult, path: Path) -> Path:
    """Write a deterministic JUnit XML document for the contract matrix."""

    path.parent.mkdir(parents=True, exist_ok=True)
    root = junit_element(result)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


def junit_element(result: ContractResult) -> ET.Element:
    """Build the ``<testsuites>`` root in memory."""

    matrix = result.run.matrix_obs
    failures = sum(
        1 for item in matrix if item["expected"] != item["observed"]
    )
    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        {
            "name": result.contract_id,
            "tests": str(len(matrix)),
            "failures": str(failures),
        },
    )
    for item in matrix:
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": "contract", "name": item["cell_id"]},
        )
        if item["expected"] != item["observed"]:
            message = (
                f"expected {item['expected']}, observed {item['observed']}"
            )
            ET.SubElement(
                case,
                "failure",
                {"message": redact_secrets(message, result.run)},
            )
    return root


__all__ = ["junit_element", "write_junit"]
