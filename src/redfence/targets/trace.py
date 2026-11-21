"""A small, ordered execution trace."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Event(BaseModel):
    seq: int
    kind: str
    detail: dict[str, object] = Field(default_factory=dict)


class ExecutionTrace:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def record(self, kind: str, **detail: object) -> Event:
        event = Event(seq=len(self.events) + 1, kind=kind, detail=detail)
        self.events.append(event)
        return event

    def as_list(self) -> list[dict[str, object]]:
        return [event.model_dump() for event in self.events]
