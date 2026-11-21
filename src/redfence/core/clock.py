"""Deterministic logical clock.

Reports claim byte-for-byte reproducibility. A wall clock in the evidence or
cache models breaks that claim, so the default time source is a fixed logical
instant. Callers that genuinely need wall time can pass one explicitly; no
in-repo caller does (ADR-0011).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

# Logical epoch used for every default timestamp in a report.
FIXED_INSTANT = datetime(2026, 1, 1, tzinfo=UTC)


class Clock(Protocol):
    """Minimal time source interface."""

    def now(self) -> datetime: ...


class FixedClock:
    """A clock that always returns :data:`FIXED_INSTANT`."""

    def now(self) -> datetime:
        return FIXED_INSTANT


DEFAULT_CLOCK: Clock = FixedClock()


__all__ = ["DEFAULT_CLOCK", "FIXED_INSTANT", "Clock", "FixedClock"]
