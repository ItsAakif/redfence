"""Oracles for the external-target contract boundary.

Every oracle follows ADR-0008: a verdict needs at least one evaluable unit.
Contract oracles take a :class:`~redfence.bench.contract_runner.ContractRun`
instead of a ``ScenarioRun`` and never read live adapter internals. The
``_verdict`` helper is imported from :mod:`redfence.bench.oracles` so contract
and classic oracles share exactly one vacuity rule.
"""

from __future__ import annotations

import json
import os
from typing import Protocol

from redfence.bench.contract_runner import ContractRun
from redfence.bench.oracles import _verdict
from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import stable_id

_FACET = "contract"


class ContractOracle(Protocol):
    """The interface every contract oracle implements."""

    oracle_id: str
    facet: str

    def score(self, run: ContractRun) -> Evidence: ...


def _no_observation(reason: str) -> str:
    """Observed text for a zero-unit result; never implies a passed check."""

    return f"no evaluable observation: {reason}"


def _evidence(
    run: ContractRun,
    oracle_id: str,
    expected: str,
    observed: str,
    outcome: Outcome,
    *,
    method: str,
    events: list[str] | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=stable_id("ev", run.contract_id, oracle_id),
        scenario_id=run.contract_id,
        oracle_id=oracle_id,
        facet=_FACET,
        expected=expected,
        observed=observed,
        outcome=outcome,
        method=method,
        events=events or [],
    )


class MatrixOracle:
    """Every executed matrix cell must match its declared expectation."""

    oracle_id = "oracle.contract.matrix"
    facet = _FACET

    def score(self, run: ContractRun) -> Evidence:
        observations = run.matrix_obs
        units = len(observations)
        violations = [
            f"{obs['cell_id']}: expected {obs['expected']}, observed {obs['observed']}"
            for obs in observations
            if obs["expected"] != obs["observed"]
        ]
        outcome = _verdict(units, violations)
        if units:
            matched = units - len(violations)
            noun = "violation" if len(violations) == 1 else "violations"
            observed = f"{matched}/{units} cells matched; {len(violations)} {noun}"
        else:
            observed = _no_observation("no matrix cells")
        return _evidence(
            run,
            self.oracle_id,
            "every matrix cell matches its declared expectation",
            observed,
            outcome,
            method="compare the adapter's observed decision with the declared expect",
            events=violations,
        )


class LifecycleOracle:
    """Cells replayed after a lifecycle step must still match their expectation."""

    oracle_id = "oracle.contract.lifecycle"
    facet = _FACET

    def score(self, run: ContractRun) -> Evidence:
        evaluable = [obs for obs in run.lifecycle_obs if obs["replayed_cell_ids"]]
        units = len(evaluable)
        violations = [
            f"{obs['step_id']}: {violation}"
            for obs in evaluable
            for violation in obs["violations"]
        ]
        outcome = _verdict(units, violations)
        if units:
            clean = sum(1 for obs in evaluable if not obs["violations"])
            noun = "violation" if len(violations) == 1 else "violations"
            observed = (
                f"{clean}/{units} lifecycle replays clean; "
                f"{len(violations)} {noun}"
            )
        else:
            observed = _no_observation("no lifecycle step replayed a cell")
        return _evidence(
            run,
            self.oracle_id,
            "every replayed cell matches its expectation after a lifecycle step",
            observed,
            outcome,
            method="replay affected cells after each lifecycle step and compare expectations",
            events=violations,
        )


class BudgetOracle:
    """Adapter requests must stay inside the declared budget and egress policy."""

    oracle_id = "oracle.contract.budget"
    facet = _FACET

    def score(self, run: ContractRun) -> Evidence:
        budget = run.budget_obs
        units = budget["requests"] if budget is not None else 0
        violations: list[str] = []
        if budget is not None and units:
            if budget["requests"] > budget["max_requests"]:
                violations.append(
                    f"requests {budget['requests']} > max {budget['max_requests']}"
                )
            if budget["timeouts"] > 0:
                violations.append(f"{budget['timeouts']} timeout(s)")
            if budget["truncated"] > 0:
                violations.append(f"{budget['truncated']} truncated response(s)")
            if budget["egress_denied"] > 0:
                violations.append(f"{budget['egress_denied']} egress denial(s)")
        outcome = _verdict(units, violations)
        if budget is not None and units:
            observed = (
                f"{budget['requests']}/{budget['max_requests']} requests; "
                f"{budget['timeouts']} timeout(s); "
                f"{budget['truncated']} truncated; "
                f"{budget['egress_denied']} egress denied"
            )
        else:
            observed = _no_observation("no adapter request")
        return _evidence(
            run,
            self.oracle_id,
            "adapter requests stay within the declared budget and never time out, "
            "truncate, or egress-deny",
            observed,
            outcome,
            method="read the runner's measured request, timeout, truncation and egress counters",
            events=violations,
        )


class RedactionOracle:
    """A configured secret value must never reach stored observations."""

    oracle_id = "oracle.contract.redaction"
    facet = _FACET

    def score(self, run: ContractRun) -> Evidence:
        configured = tuple(getattr(run, "secret_names", ()))
        set_values: list[tuple[str, str]] = []
        for name in configured:
            value = os.environ.get(name)
            if value:
                set_values.append((name, value))

        units = len(set_values)
        stored = _stored_text(run)
        violations = [
            f"{name}:leaked"
            for name, value in set_values
            if any(form in stored for form in _secret_forms(value))
        ]
        outcome = _verdict(units, violations)
        if units:
            noun = "value" if units == 1 else "values"
            observed = (
                f"{len(violations)}/{units} configured secret {noun} leaked"
            )
        else:
            observed = _no_observation(
                "no configured secret environment variable is set"
            )
        return _evidence(
            run,
            self.oracle_id,
            "no configured secret value appears in stored observations or manifests",
            observed,
            outcome,
            method="search stored contract observations for every set secret value",
            events=violations,
        )


def _secret_forms(value: str) -> list[str]:
    """Every textual form a secret can take inside canonical stored output.

    Stored observations are serialised with ``ensure_ascii=True``, so a secret
    containing a quote, backslash, tab or non-ASCII character can appear only
    in an escaped form. Compare all forms, deduplicated, never just the raw one.
    """

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


def _stored_text(run: ContractRun) -> str:
    """Canonical text of everything a contract run stores for reports."""

    payload = {
        "contract_id": run.contract_id,
        "contract_hash": run.contract_hash,
        "adapter": run.adapter,
        "capabilities": sorted(run.capabilities),
        "matrix": [dict(item) for item in run.matrix_obs],
        "lifecycle": [dict(item) for item in run.lifecycle_obs],
        "budget": dict(run.budget_obs) if run.budget_obs is not None else None,
        "retrieval": [dict(item) for item in run.retrieval_obs],
        "answer": [dict(item) for item in run.answer_obs],
        "memory": [dict(item) for item in run.memory_obs],
        "tool": [dict(item) for item in run.tool_obs],
        "deletion": [dict(item) for item in run.deletion_obs],
        "utility": run.utility_obs,
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)


def contract_oracles() -> list[ContractOracle]:
    """Return the contract-boundary oracle registry in stable order."""

    return [
        MatrixOracle(),
        LifecycleOracle(),
        BudgetOracle(),
        RedactionOracle(),
    ]


__all__ = [
    "BudgetOracle",
    "ContractOracle",
    "LifecycleOracle",
    "MatrixOracle",
    "RedactionOracle",
    "contract_oracles",
]
