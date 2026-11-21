"""Security profiles and independently injectable faults.

A single RAG target implementation is configured by :class:`FaultFlags`. When
the objective is to measure the effect of one control, inject exactly one fault.
`FAULT_ORACLE` maps each fault to the deterministic oracle expected to detect it.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class FaultFlags(BaseModel):
    """Each flag disables exactly one security control when True."""

    model_config = {"frozen": True}

    missing_query_acl: bool = False
    missing_tenant_filter: bool = False
    lost_chunk_acl_metadata: bool = False
    mutable_document_metadata: bool = False
    stale_cache_after_revocation: bool = False
    unscoped_cache_key: bool = False
    missing_source_freshness: bool = False
    deleted_doc_retrievable: bool = False
    stale_cache_after_deletion: bool = False
    stale_memory_after_deletion: bool = False
    unauthorized_memory_content: bool = False
    unauthorized_tool_execution: bool = False

    def enabled(self) -> list[str]:
        return [name for name, value in self.model_dump().items() if value]


class SecurityProfile(str, Enum):  # noqa: UP042 - str-Enum keeps Pydantic/str() compatibility
    SECURED = "secured"
    VULNERABLE = "vulnerable"
    PARTIAL = "partial"


def flags_for(profile: SecurityProfile) -> FaultFlags:
    if profile is SecurityProfile.SECURED:
        return FaultFlags()
    if profile is SecurityProfile.VULNERABLE:
        return FaultFlags(
            missing_query_acl=True,
            missing_tenant_filter=True,
            lost_chunk_acl_metadata=True,
            mutable_document_metadata=True,
            stale_cache_after_revocation=True,
            unscoped_cache_key=True,
            missing_source_freshness=True,
            deleted_doc_retrievable=True,
            stale_cache_after_deletion=True,
            stale_memory_after_deletion=True,
            unauthorized_memory_content=True,
            unauthorized_tool_execution=True,
        )
    # PARTIAL: a plausible "we added a filter somewhere" configuration.
    return FaultFlags(
        missing_query_acl=True,
        unscoped_cache_key=True,
    )


# Fault -> the oracle id expected to confirm it (discriminative validity).
FAULT_ORACLE: dict[str, str] = {
    "missing_query_acl": "oracle.index.acl",
    "missing_tenant_filter": "oracle.index.tenant",
    "lost_chunk_acl_metadata": "oracle.index.acl",
    "stale_cache_after_revocation": "oracle.cache.leak",
    "unscoped_cache_key": "oracle.cache.key_scope",
    "deleted_doc_retrievable": "oracle.index.deletion",
    "stale_cache_after_deletion": "oracle.cache.deletion_propagation",
    "stale_memory_after_deletion": "oracle.memory.deletion_propagation",
    "unauthorized_memory_content": "oracle.memory.scope",
    "unauthorized_tool_execution": "oracle.tool.policy",
    "mutable_document_metadata": "oracle.metadata.integrity",
    "missing_source_freshness": "oracle.cache.freshness",
}

# All configured faults now have an executable oracle at this milestone.
UNSUPPORTED_FAULTS: frozenset[str] = frozenset()
