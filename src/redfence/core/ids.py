"""Stable identifiers and text normalization.

All identifiers are derived deterministically from their inputs so that replays
produce byte-identical artifacts. Nothing here depends on wall-clock time,
random state, or process identity.
"""

from __future__ import annotations

import hashlib
import json
import re

_WHITESPACE = re.compile(r"\s+")
_PUNCT = re.compile(r"[^a-z0-9\s]")


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    """Return a deterministic id of the form ``{prefix}_{hex}``."""

    joined = "||".join(str(part) for part in parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:length]
    return f"{prefix}_{digest}"


def content_hash(text: str) -> str:
    """SHA-256 of the UTF-8 encoding of ``text`` (full digest)."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def json_digest(payload: object) -> str:
    """SHA-256 of the canonical JSON encoding of ``payload``."""

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return content_hash(encoded)


def normalize_query(text: str) -> str:
    """Canonicalize a query for cache keying and equivalence checks."""

    lowered = text.strip().lower()
    lowered = _PUNCT.sub(" ", lowered)
    return _WHITESPACE.sub(" ", lowered).strip()


def tokenize(text: str) -> list[str]:
    """Deterministic whitespace/punctuation tokenizer."""

    return [tok for tok in normalize_query(text).split(" ") if tok]


def redact(value: str) -> str:
    """Return a stable, irreversible marker for a sensitive value."""

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
