"""Configurable targets under test."""

from redfence.targets.config import (
    FAULT_ORACLE,
    UNSUPPORTED_FAULTS,
    FaultFlags,
    SecurityProfile,
    flags_for,
)
from redfence.targets.policy import DefaultToolPolicy
from redfence.targets.rag_target import ConfigurableRAGTarget, chunk_text
from redfence.targets.tools import SyntheticToolRuntime, ToolExecution
from redfence.targets.trace import Event, ExecutionTrace

__all__ = [
    "FAULT_ORACLE",
    "UNSUPPORTED_FAULTS",
    "ConfigurableRAGTarget",
    "DefaultToolPolicy",
    "Event",
    "ExecutionTrace",
    "FaultFlags",
    "SecurityProfile",
    "SyntheticToolRuntime",
    "ToolExecution",
    "chunk_text",
    "flags_for",
]
