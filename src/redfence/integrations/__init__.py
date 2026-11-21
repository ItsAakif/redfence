"""Optional interoperability adapters.

Nothing is imported here on purpose: ``inspect_ai`` and ``opentelemetry`` are
optional extras, and importing this package must not pull either one into
``sys.modules``. Import the submodule you need explicitly.
"""

from __future__ import annotations

__all__: list[str] = []
