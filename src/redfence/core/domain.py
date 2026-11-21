"""Core domain models.

These describe the *system under test* (tenants, principals, documents, ACLs,
cache entries, memory records, tool calls) and are intentionally provider
agnostic. Authorization is always evaluated by trusted application code — never
by a model.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from redfence.core.clock import DEFAULT_CLOCK

# Ordered classification ranks. Higher rank == more sensitive.
CLASSIFICATION_RANK: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
}

DEFAULT_EMBEDDING_DIM = 64


class Tenant(BaseModel):
    id: str
    name: str


class Principal(BaseModel):
    """A user / service identity acting within one tenant."""

    id: str
    tenant_id: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    clearance: str = "public"
    capabilities: list[str] = Field(default_factory=list)
    revoked: bool = False
    delegated_from: str | None = None

    @property
    def clearance_rank(self) -> int:
        return CLASSIFICATION_RANK.get(self.clearance, 0)

    def entitlement_fingerprint(self) -> str:
        """Stable fingerprint of the entitlements that shaped an answer."""

        from redfence.core.ids import stable_id

        return stable_id(
            "ent",
            self.tenant_id,
            self.clearance,
            ",".join(sorted(self.roles)),
            ",".join(sorted(self.groups)),
            ",".join(sorted(self.capabilities)),
        )


class Provenance(BaseModel):
    source: str
    ingested_at: str
    content_hash: str
    version: int = 1


class ACL(BaseModel):
    """Chunk/document access-control metadata (AISVS C8.1)."""

    tenant_id: str
    classification: str = "internal"
    allowed_roles: list[str] = Field(default_factory=list)
    allowed_groups: list[str] = Field(default_factory=list)
    allowed_principals: list[str] = Field(default_factory=list)
    public: bool = False
    epoch: int = 1

    @property
    def classification_rank(self) -> int:
        return CLASSIFICATION_RANK.get(self.classification, 0)

    def permits(self, principal: Principal) -> bool:
        """Deterministic authorization decision (never model-mediated)."""

        if principal.revoked:
            return False
        if principal.tenant_id != self.tenant_id:
            return False
        if principal.clearance_rank < self.classification_rank:
            return False
        if self.public:
            return True
        if principal.id in self.allowed_principals:
            return True
        if set(principal.roles) & set(self.allowed_roles):
            return True
        if set(principal.groups) & set(self.allowed_groups):
            return True
        return False


class Document(BaseModel):
    id: str
    tenant_id: str
    title: str
    content: str
    classification: str = "internal"
    owner: str
    acl: ACL
    provenance: Provenance
    canaries: list[str] = Field(default_factory=list)
    malicious: bool = False
    labels: list[str] = Field(default_factory=list)


class Chunk(BaseModel):
    id: str
    doc_id: str
    tenant_id: str
    position: int
    text: str
    acl: ACL
    provenance: Provenance
    content_hash: str
    deleted: bool = False
    embedding: list[float] | None = None


class MemoryRecord(BaseModel):
    id: str
    tenant_id: str
    principal_id: str
    text: str
    source: str
    trusted: bool
    epoch: int = 1
    expires_at_epoch: int | None = None


class CacheEntry(BaseModel):
    key: str
    principal_id: str = ""
    query: str
    tenant_id: str
    entitlement_fingerprint: str
    acl_epoch: int
    answer: str
    context_chunk_ids: list[str] = Field(default_factory=list)
    doc_versions: dict[str, int] = Field(default_factory=dict)
    doc_acl_epochs: dict[str, int] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=DEFAULT_CLOCK.now)


class ToolSpec(BaseModel):
    name: str
    required_capability: str
    high_impact: bool = False
    tenant_scoped: bool = True
    description: str = ""


class ToolCall(BaseModel):
    name: str
    args: dict[str, object] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    required_capability: str | None = None
    matched_rule: str | None = None


class RetrievedChunk(BaseModel):
    chunk_id: str
    doc_id: str
    tenant_id: str
    text: str
    score: float
    acl: ACL
    provenance: Provenance


class Answer(BaseModel):
    text: str
    context_chunk_ids: list[str] = Field(default_factory=list)
    cache_hit: bool = False
    cache_revalidated: bool = False
    canaries_present: list[str] = Field(default_factory=list)
    cache_doc_versions: dict[str, int] = Field(default_factory=dict)
    current_doc_versions: dict[str, int] = Field(default_factory=dict)
    refused: bool = False
