"""Typed evidence objects.

A ``Scorer`` never returns a bare boolean. Every verdict is a structured
:class:`Evidence` record that states what was expected, what was observed, how
it was verified, and which event/artifact references support it.

Sensitive markers (canaries, secrets) are recorded only as hashed/redacted
markers, never in cleartext.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from redfence.core.clock import DEFAULT_CLOCK


class Outcome(str, Enum):  # noqa: UP042 - str-Enum keeps Pydantic/serialization compatibility
    """The result of applying one oracle to one observation."""

    SATISFIED = "satisfied"  # invariant held
    VIOLATION = "violation"  # invariant violated (a confirmed finding)
    UNSUPPORTED = "unsupported"  # not evaluated at this milestone
    INCONCLUSIVE = "inconclusive"  # could not be decided


class Evidence(BaseModel):
    """A single, independently verifiable security observation."""

    model_config = {"frozen": True}

    evidence_id: str
    scenario_id: str
    oracle_id: str
    facet: str  # index | cache | memory | tool | context | response | utility
    expected: str
    observed: str
    outcome: Outcome
    method: str
    events: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    markers: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=DEFAULT_CLOCK.now)

    @property
    def is_violation(self) -> bool:
        return self.outcome is Outcome.VIOLATION
