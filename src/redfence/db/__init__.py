"""Database layer (optional). Requires the ``db`` extra.

Two isolated trust domains with separate SQLAlchemy metadata and credentials:

* ``PlatformBase``  - RedFence's own records (campaigns, evidence, metrics).
* ``SutBase``       - the system-under-test store (tenants, chunks, cache, memory).

The assessment service must not gain unrestricted access to target data beyond
the narrow target adapter.
"""

from redfence.db.models import PlatformBase, SutBase

__all__ = ["PlatformBase", "SutBase"]
