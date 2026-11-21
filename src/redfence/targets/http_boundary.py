"""HTTP boundary facade.

The transport and HTTP adapter live with the other contract adapters in
:mod:`redfence.contracts.target` so the contract package has one import surface.
This module keeps the architecture's ``targets/http_boundary`` path available
without importing ``urllib`` until a request is actually sent.
"""

from __future__ import annotations

from redfence.contracts.target import (
    FakeTransport,
    HttpConfig,
    HttpContractTarget,
    Transport,
    UrllibTransport,
)

__all__ = [
    "FakeTransport",
    "HttpConfig",
    "HttpContractTarget",
    "Transport",
    "UrllibTransport",
]
