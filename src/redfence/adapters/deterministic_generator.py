"""Deterministic generation adapter.

Produces extractive, template-based answers from the assembled context. It
never invents content and is fully reproducible, so response-oracle verdicts are
deterministic. A real model adapter can replace it behind the same call shape.
"""

from __future__ import annotations

from redfence.core.domain import RetrievedChunk


class DeterministicGenerator:
    def generate(self, query: str, context: list[RetrievedChunk]) -> str:
        if not context:
            return "I could not find an answer in the available documents."
        fragments = []
        for item in context:
            # First sentence of each retrieved chunk, deterministic ordering.
            sentence = item.text.split(". ")[0].strip()
            fragments.append(f"[{item.doc_id}] {sentence}.")
        return "Based on the retrieved documents: " + " ".join(fragments)
