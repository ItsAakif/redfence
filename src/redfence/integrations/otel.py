"""Optional OpenTelemetry exporter for RedFence evidence.

``opentelemetry`` is imported inside :func:`export_evidence`, so importing this
module (or ``redfence``) never requires it. A caller may inject any tracer that
implements the small protocol below; that path needs no optional dependency and
keeps tests free of the OpenTelemetry SDK.
"""

from __future__ import annotations

from typing import Protocol, cast

from redfence.core.evidence import Evidence

SPAN_NAME = "redfence.evidence"


class _Span(Protocol):
    def set_attribute(self, key: str, value: str) -> None: ...

    def __enter__(self) -> _Span: ...

    def __exit__(self, *args: object) -> None: ...


class _Tracer(Protocol):
    def start_as_current_span(self, name: str) -> _Span: ...


def export_evidence(evidence: list[Evidence], tracer: object | None = None) -> int:
    """Emit one span per evidence record and return the number emitted.

    Raises:
        RuntimeError: when ``tracer`` is ``None`` and the optional ``otel``
            extra is not installed.
    """

    resolved: _Tracer
    if tracer is None:
        try:
            from opentelemetry import trace
        except ImportError:
            raise RuntimeError("opentelemetry extra not installed") from None
        resolved = cast(_Tracer, trace.get_tracer("redfence"))
    else:
        resolved = cast(_Tracer, tracer)

    emitted = 0
    for item in evidence:
        with resolved.start_as_current_span(SPAN_NAME) as span:
            span.set_attribute("redfence.oracle_id", item.oracle_id)
            span.set_attribute("redfence.facet", item.facet)
            span.set_attribute("redfence.outcome", item.outcome.value)
            span.set_attribute("redfence.evidence_id", item.evidence_id)
        emitted += 1
    return emitted
