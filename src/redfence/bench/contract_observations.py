"""Contract-run observations that have no classic ``ScenarioRun`` analogue.

The existing observation TypedDicts in :mod:`redfence.bench.observations` stay
frozen. A contract run projects ``read``/``answer``/``tool`` responses into
those unchanged types and keeps matrix, lifecycle and budget facts here.
"""

from __future__ import annotations

from typing import TypedDict


class MatrixObservation(TypedDict):
    """One declared matrix cell and the adapter's observed decision."""

    cell_id: str
    identity_id: str
    source_id: str | None
    action: str
    expected: str
    observed: str
    response_hash: str
    status: str
    context_refs: list[str]
    tool_executed: bool
    truncated: bool
    error: str | None


class LifecycleObservation(TypedDict):
    """One lifecycle step and the cells replayed after it."""

    step_id: str
    action: str
    identity_id: str | None
    source_id: str | None
    replayed_cell_ids: list[str]
    violations: list[str]


class BudgetObservation(TypedDict):
    """Adapter request budget facts measured during one contract run."""

    requests: int
    max_requests: int
    timeouts: int
    max_response_bytes_seen: int
    truncated: int
    egress_denied: int


__all__ = ["BudgetObservation", "LifecycleObservation", "MatrixObservation"]
