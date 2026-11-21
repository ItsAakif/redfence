"""Minimal valid SARIF 2.1.0 for contract violations.

No third-party SARIF library or validator is used. The document carries one
run, one rule per contract oracle and one result per violation event. Secret
values named by the run are redacted before writing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from redfence.bench.contract_oracles import contract_oracles
from redfence.core.evidence import Outcome
from redfence.report.contract_report import redact_secrets

if TYPE_CHECKING:  # pragma: no cover
    from redfence.bench.contract_runner import ContractResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_RULE_DESCRIPTIONS = {
    "oracle.contract.matrix": "Every declared matrix cell matches its expectation.",
    "oracle.contract.lifecycle": "Cells replayed after a lifecycle step still match.",
    "oracle.contract.budget": "Adapter requests stay inside the declared budget.",
    "oracle.contract.redaction": "Configured secret values never reach stored output.",
}


def write_sarif(result: ContractResult, path: Path) -> Path:
    """Write a minimal SARIF 2.1.0 document for the contract result."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = sarif_payload(result)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.write_text(redact_secrets(text, result.run), encoding="utf-8")
    return path


def sarif_payload(result: ContractResult) -> dict[str, object]:
    """Build the SARIF document in memory."""

    rules = [
        {
            "id": oracle.oracle_id,
            "name": oracle.oracle_id,
            "shortDescription": {
                "text": _RULE_DESCRIPTIONS.get(
                    oracle.oracle_id, oracle.oracle_id
                )
            },
        }
        for oracle in contract_oracles()
    ]
    results = _results(result)
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {"driver": {"name": "RedFence", "rules": rules}},
                "results": results,
            }
        ],
    }


def _results(result: ContractResult) -> list[dict[str, object]]:
    uri = f"contract://{result.contract_id}"
    results: list[dict[str, object]] = []
    for evidence in result.evidence:
        if evidence.outcome is not Outcome.VIOLATION:
            continue
        messages = evidence.events or [evidence.observed]
        for message in messages:
            results.append(
                {
                    "ruleId": evidence.oracle_id,
                    "level": "error",
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri}
                            }
                        }
                    ],
                }
            )
    return results


__all__ = ["sarif_payload", "write_sarif"]
