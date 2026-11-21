"""Deterministic JSON report for a contract run.

The report has five top-level keys: ``contract``, ``matrix``, ``lifecycle``,
``metrics`` and ``summary``. It contains no wall-clock value and no evidence
timestamp, so two runs over the same contract and adapter are byte-identical.
Secret values named by ``contract.redaction.secrets`` are redacted before the
document is written.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from redfence.core.evidence import Outcome

if TYPE_CHECKING:  # pragma: no cover
    from redfence.bench.contract_runner import ContractResult, ContractRun

_REDACTED = "[REDACTED]"


def write_contract_json(result: ContractResult, path: Path) -> Path:
    """Write the contract report as deterministic, sorted JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = contract_payload(result)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.write_text(redact_secrets(text, result.run), encoding="utf-8")
    return path


def contract_payload(result: ContractResult) -> dict[str, object]:
    """Build the in-memory report document (deterministic key ordering on write)."""

    run = result.run
    metrics = result.metrics if result.metrics is not None else _metrics(run)
    return {
        "contract": {
            "id": result.contract_id,
            "hash": run.contract_hash,
            "adapter": run.adapter,
            "capabilities": sorted(run.capabilities),
            "manifest": result.manifest,
        },
        "matrix": [dict(item) for item in run.matrix_obs],
        "lifecycle": [dict(item) for item in run.lifecycle_obs],
        "metrics": _as_json(metrics),
        "summary": {
            "contract_id": result.contract_id,
            "exit_code": contract_exit_code(result),
            "violations": [
                item.oracle_id
                for item in result.evidence
                if item.outcome is Outcome.VIOLATION
            ],
            "unsupported": [
                item.oracle_id
                for item in result.evidence
                if item.outcome is Outcome.UNSUPPORTED
            ],
        },
    }


def contract_exit_code(result: ContractResult) -> int:
    """0 pass, 1 confirmed violation, 2 inconclusive/unsupported/adapter error.

    Delegates to :attr:`ContractResult.exit_code` so the CLI and the Python
    API can never disagree about a run's verdict.
    """

    return result.exit_code


def _secret_forms(value: str) -> list[str]:
    """Every textual form a secret can take inside serialised output."""

    forms: list[str] = []
    for form in (
        value,
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
        json.dumps(value, ensure_ascii=True)[1:-1],
    ):
        if form and form not in forms:
            forms.append(form)
    return forms


def redact_secrets(text: str, run: ContractRun) -> str:
    """Replace every set secret value named by the run with ``[REDACTED]``.

    Reports serialise with ``ensure_ascii=True``, so a secret containing a
    quote, backslash, tab or non-ASCII character only appears in escaped form.
    Both the raw and every escaped form are removed.
    """

    for name in getattr(run, "secret_names", ()):
        value = os.environ.get(name)
        if not value:
            continue
        for form in _secret_forms(value):
            text = text.replace(form, _REDACTED)
    return text


def _metrics(run: ContractRun) -> dict[str, object]:
    budget = run.budget_obs
    return {
        "matrix": {
            "cells": len(run.matrix_obs),
            "matched": sum(
                1 for item in run.matrix_obs if item["expected"] == item["observed"]
            ),
            "violations": sum(
                1 for item in run.matrix_obs if item["expected"] != item["observed"]
            ),
        },
        "lifecycle": {
            "steps": len(run.lifecycle_obs),
            "replayed_cells": sum(
                len(item["replayed_cell_ids"]) for item in run.lifecycle_obs
            ),
            "violations": sum(
                len(item["violations"]) for item in run.lifecycle_obs
            ),
        },
        "budget": {
            "requests": budget["requests"] if budget is not None else 0,
            "max_requests": budget["max_requests"] if budget is not None else 0,
            "timeouts": budget["timeouts"] if budget is not None else 0,
            "truncated": budget["truncated"] if budget is not None else 0,
            "egress_denied": budget["egress_denied"] if budget is not None else 0,
        },
    }


def _as_json(value: object) -> object:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    return value


__all__ = [
    "contract_exit_code",
    "contract_payload",
    "redact_secrets",
    "write_contract_json",
]
