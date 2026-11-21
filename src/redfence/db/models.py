"""SQLAlchemy models for the two trust domains.

Import is guarded so the deterministic core does not require SQLAlchemy. Install
the ``db`` extra to use these models.
"""

from __future__ import annotations

try:  # pragma: no cover - requires optional dependency
    from sqlalchemy import JSON, Float, ForeignKey, Integer, String, Text, UniqueConstraint
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    class PlatformBase(DeclarativeBase):
        """RedFence platform records."""

    class SutBase(DeclarativeBase):
        """System-under-test records (separate credentials/database)."""

    class Campaign(PlatformBase):
        __tablename__ = "campaign"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        scenario_id: Mapped[str] = mapped_column(String(64))
        profile: Mapped[str] = mapped_column(String(32))
        manifest: Mapped[dict] = mapped_column(JSON)

    class Attempt(PlatformBase):
        __tablename__ = "attempt"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        campaign_id: Mapped[str] = mapped_column(ForeignKey("campaign.id"))
        sequence: Mapped[int] = mapped_column(Integer)

    class Finding(PlatformBase):
        __tablename__ = "finding"
        evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        campaign_id: Mapped[str] = mapped_column(ForeignKey("campaign.id"))
        oracle_id: Mapped[str] = mapped_column(String(64))
        facet: Mapped[str] = mapped_column(String(32))
        outcome: Mapped[str] = mapped_column(String(16))

    class EvidenceRecord(PlatformBase):
        __tablename__ = "evidence"
        evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        campaign_id: Mapped[str] = mapped_column(ForeignKey("campaign.id"))
        payload: Mapped[dict] = mapped_column(JSON)

    class MetricSnapshot(PlatformBase):
        __tablename__ = "metric_snapshot"
        id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
        campaign_id: Mapped[str] = mapped_column(ForeignKey("campaign.id"))
        name: Mapped[str] = mapped_column(String(64))
        numerator: Mapped[int] = mapped_column(Integer)
        denominator: Mapped[int] = mapped_column(Integer)
        value: Mapped[float | None] = mapped_column(Float, nullable=True)

    class TenantRow(SutBase):
        __tablename__ = "tenant"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        name: Mapped[str] = mapped_column(String(128))

    class ChunkRow(SutBase):
        __tablename__ = "chunk"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        doc_id: Mapped[str] = mapped_column(String(64), index=True)
        tenant_id: Mapped[str] = mapped_column(String(64), index=True)
        classification: Mapped[str] = mapped_column(String(32))
        acl_epoch: Mapped[int] = mapped_column(Integer)
        text: Mapped[str] = mapped_column(Text)
        acl: Mapped[dict] = mapped_column(JSON)
        deleted: Mapped[int] = mapped_column(Integer, default=0)

    class CacheRow(SutBase):
        __tablename__ = "cache_entry"
        key: Mapped[str] = mapped_column(String(256), primary_key=True)
        tenant_id: Mapped[str] = mapped_column(String(64))
        entitlement_fingerprint: Mapped[str] = mapped_column(String(64))
        acl_epoch: Mapped[int] = mapped_column(Integer)
        answer: Mapped[str] = mapped_column(Text)

    class MemoryRow(SutBase):
        __tablename__ = "memory_record"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        tenant_id: Mapped[str] = mapped_column(String(64), index=True)
        principal_id: Mapped[str] = mapped_column(String(64), index=True)
        text: Mapped[str] = mapped_column(Text)
        source: Mapped[str] = mapped_column(String(64))
        trusted: Mapped[int] = mapped_column(Integer)
        __table_args__ = (UniqueConstraint("id", name="uq_memory_id"),)

except ImportError:  # pragma: no cover
    # Optional dependency absent: the models are unavailable by design.
    PlatformBase = None  # type: ignore[misc, assignment]
    SutBase = None  # type: ignore[misc, assignment]
