"""Deterministic embedding adapter.

A stdlib-only, hash-based bag-of-words embedding. It is *not* semantically
meaningful; it exists so the benchmark does not depend on an external embedding
provider and so replays are bit-reproducible. A real embedding adapter can be
introduced later behind the same interface.
"""

from __future__ import annotations

import hashlib
import math

from redfence.core.domain import DEFAULT_EMBEDDING_DIM
from redfence.core.ids import tokenize


class DeterministicEmbedder:
    """Hash tokens into a fixed-dimension signed vector, then L2-normalize."""

    def __init__(self, dim: int = DEFAULT_EMBEDDING_DIM) -> None:
        if dim <= 0:
            raise ValueError("dim must be positive")
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        for token in tokenize(text):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:8], "big") % self.dim
            sign = 1.0 if digest[8] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        raise ValueError("vector dimension mismatch")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    # Vectors are L2-normalized by the embedder; clamp for numerical safety.
    return max(-1.0, min(1.0, dot))
