"""Deterministic adapter tests."""

from __future__ import annotations

import math

from redfence.adapters import DeterministicEmbedder


def test_embedding_is_deterministic():
    embedder = DeterministicEmbedder()
    assert embedder.embed("nimbus launch code") == embedder.embed("nimbus launch code")


def test_embedding_is_l2_normalized():
    embedder = DeterministicEmbedder()
    vector = embedder.embed("alpha beta gamma")
    norm = math.sqrt(sum(value * value for value in vector))
    assert abs(norm - 1.0) < 1e-9


def test_empty_text_is_zero_vector():
    embedder = DeterministicEmbedder()
    assert all(value == 0.0 for value in embedder.embed(""))
