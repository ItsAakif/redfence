"""Configurable RAG target (single implementation, many security profiles).

The same code runs the secured and vulnerable configurations. Every control is
guarded by exactly one :class:`FaultFlags` entry so a fault can be injected
independently. Authorization is performed here, in trusted application code,
before any retrieved content reaches the model.
"""

from __future__ import annotations

from redfence.adapters.deterministic_embedder import DeterministicEmbedder, cosine_similarity
from redfence.adapters.deterministic_generator import DeterministicGenerator
from redfence.adapters.in_memory_vector_store import InMemoryVectorStore
from redfence.core.domain import (
    ACL,
    Answer,
    CacheEntry,
    Chunk,
    Document,
    MemoryRecord,
    Principal,
    RetrievedChunk,
    ToolCall,
)
from redfence.core.ids import content_hash, normalize_query, stable_id
from redfence.targets.config import FaultFlags
from redfence.targets.retention import BackupStore, ReplicaStore, RetentionStore
from redfence.targets.tools import SyntheticToolRuntime, ToolExecution
from redfence.targets.trace import ExecutionTrace

# Sources whose content must never be persisted as trusted agent memory (AISVS 8.2.3).
UNTRUSTED_SOURCES: frozenset[str] = frozenset(
    {"retrieved_document", "tool_output", "tool_result", "email", "web"}
)


def chunk_text(content: str) -> list[str]:
    """Deterministic line-based chunking (one fact per line in the corpus)."""

    return [line.strip() for line in content.splitlines() if line.strip()]


class ConfigurableRAGTarget:
    def __init__(
        self,
        name: str,
        faults: FaultFlags,
        *,
        store: InMemoryVectorStore | None = None,
        generator: DeterministicGenerator | None = None,
        semantic_cache: bool = False,
        semantic_threshold: float = 0.55,
        replicas: list[ReplicaStore] | None = None,
        backups: list[BackupStore] | None = None,
        retention: RetentionStore | None = None,
    ) -> None:
        self.name = name
        self.faults = faults
        self.store = store or InMemoryVectorStore()
        self.generator = generator or DeterministicGenerator()
        self.semantic_cache = semantic_cache
        self.semantic_threshold = semantic_threshold
        self.replicas = list(replicas) if replicas is not None else []
        self.backups = list(backups) if backups is not None else []
        self.retention = retention
        self._semantic_embedder = DeterministicEmbedder()
        self.tools = SyntheticToolRuntime()
        self.trace = ExecutionTrace()
        self.cache: dict[str, CacheEntry] = {}
        self.memory: list[MemoryRecord] = []
        self.retrieval_log: list[dict[str, object]] = []
        self.answer_log: list[dict[str, object]] = []
        self.current_epoch = 1
        self._doc_versions: dict[str, int] = {}
        self._doc_acl_epochs: dict[str, int] = {}
        self._canaries: list[str] = []
        self._doc_canaries: dict[str, list[str]] = {}
        self._doc_chunks: dict[str, list[str]] = {}

    # -- Ingestion ----------------------------------------------------------
    def ingest(self, document: Document, acl: ACL | None = None) -> list[str]:
        base_acl = acl or document.acl
        chunk_ids: list[str] = []
        for position, text in enumerate(chunk_text(document.content)):
            effective_acl = base_acl.model_copy()
            if self.faults.lost_chunk_acl_metadata:
                # FAULT: per-chunk ACL metadata is dropped, leaving a permissive default.
                effective_acl = ACL(
                    tenant_id=document.tenant_id,
                    classification="public",
                    public=True,
                    epoch=base_acl.epoch,
                )
            chunk = Chunk(
                id=stable_id("chunk", document.id, position, content_hash(text)),
                doc_id=document.id,
                tenant_id=document.tenant_id,
                position=position,
                text=text,
                acl=effective_acl,
                provenance=document.provenance,
                content_hash=content_hash(text),
            )
            self.store.upsert(chunk)
            for replica in self.replicas:
                replica.ingest(chunk)
            for backup in self.backups:
                backup.ingest(chunk)
            if self.retention is not None:
                self.retention.ingest(chunk)
            chunk_ids.append(chunk.id)
        self._doc_versions[document.id] = document.provenance.version
        self._doc_acl_epochs[document.id] = base_acl.epoch
        self._doc_canaries[document.id] = list(document.canaries)
        self._doc_chunks[document.id] = chunk_ids
        for canary in document.canaries:
            if canary not in self._canaries:
                self._canaries.append(canary)
        self.trace.record(
            "ingest",
            doc_id=document.id,
            tenant_id=document.tenant_id,
            chunks=len(chunk_ids),
            acl_epoch=base_acl.epoch,
        )
        return chunk_ids

    # -- Authorization state -------------------------------------------------
    def revoke(self, principal: Principal) -> None:
        principal.revoked = True
        self.current_epoch += 1
        self.trace.record(
            "revoke",
            principal_id=principal.id,
            tenant_id=principal.tenant_id,
            new_epoch=self.current_epoch,
        )

    def update_document(self, doc_id: str) -> int:
        """Simulate a source-document update by advancing its version."""

        self._doc_versions[doc_id] = self._doc_versions.get(doc_id, 1) + 1
        self.trace.record("document_update", doc_id=doc_id, version=self._doc_versions[doc_id])
        return self._doc_versions[doc_id]

    def mutate_document_metadata(self, doc_id: str, *, tenant_id: str) -> bool:
        """FAULT: stored metadata can drift away from the authoritative document."""

        if not self.faults.mutable_document_metadata:
            return False
        for chunk in self.store.all_chunks():
            if chunk.doc_id == doc_id:
                chunk.tenant_id = tenant_id
                chunk.acl = chunk.acl.model_copy(update={"tenant_id": tenant_id})
        self.trace.record("metadata_mutation", doc_id=doc_id, tenant_id=tenant_id)
        return True

    def modify_document_acl(
        self,
        doc_id: str,
        *,
        classification: str | None = None,
        allowed_roles: list[str] | None = None,
        allowed_groups: list[str] | None = None,
    ) -> bool:
        """Legitimate lifecycle action: change a document's ACL, bump its epoch.

        This is an administrative authorization-state change, not a fault: the
        secured target performs it and every cache entry derived from this
        document must be revalidated afterwards. The authoritative corpus view is
        deliberately untouched — oracles evaluate *cache revalidation behavior*,
        not whether the modification itself was legitimate.

        Invalidation is scoped by a per-document ACL epoch: it only invalidates
        cache entries whose ``doc_acl_epochs`` stamp names this document. The
        global authorization epoch (``current_epoch``) is deliberately **not**
        advanced, so unrelated tenants' entries stay cached and TTL memory
        (``expires_at_epoch``, measured against ``current_epoch``) is unaffected.
        Do not reintroduce a global bump here.
        """

        update: dict[str, object] = {}
        if classification is not None:
            update["classification"] = classification
        if allowed_roles is not None:
            update["allowed_roles"] = allowed_roles
        if allowed_groups is not None:
            update["allowed_groups"] = allowed_groups
        if not update:
            return False
        new_epoch = self._doc_acl_epochs.get(doc_id, 1) + 1
        modified = 0
        for chunk in self.store.all_chunks():
            if chunk.doc_id == doc_id:
                chunk.acl = chunk.acl.model_copy(update={**update, "epoch": new_epoch})
                modified += 1
        if modified == 0:
            # No such document: reject the no-op without touching any epoch state.
            return False
        self._doc_acl_epochs[doc_id] = new_epoch
        self.trace.record(
            "acl_modify", doc_id=doc_id, chunks=modified, new_epoch=new_epoch, **update
        )
        return True

    def advance_epoch(self, reason: str) -> int:
        """Authorization-state tick (memory expiry, future lifecycle events)."""

        self.current_epoch += 1
        self.trace.record("epoch_advance", reason=reason, new_epoch=self.current_epoch)
        return self.current_epoch

    def mark_document_deleted(self, doc_id: str) -> None:
        if self.faults.deleted_doc_retrievable:
            # FAULT: soft delete only; readers may still see the chunks.
            self.store.mark_deleted(doc_id, self.current_epoch)
        else:
            self.store.hard_delete(doc_id)
        if not self.faults.stale_cache_after_deletion:
            # Control: cached answers derived from the deleted document are purged.
            self._purge_cache_for_doc(doc_id)
        if not self.faults.stale_memory_after_deletion:
            # Control: memory records derived from the deleted document are purged.
            self._purge_memory_for_doc(doc_id)
        for replica in self.replicas:
            replica.mark_deleted(doc_id)
        for backup in self.backups:
            backup.mark_deleted(doc_id)
        if self.retention is not None:
            self.retention.mark_deleted(doc_id)
        self.trace.record(
            "delete",
            doc_id=doc_id,
            cascading=not self.faults.deleted_doc_retrievable,
            cache_purged=not self.faults.stale_cache_after_deletion,
            memory_purged=not self.faults.stale_memory_after_deletion,
        )

    def _purge_cache_for_doc(self, doc_id: str) -> None:
        """Drop cache entries whose evidence came from ``doc_id``.

        Attribution uses the entry's cached document versions and the chunk ids
        captured at ingest time — both are target-local facts, deliberately
        independent of the oracles' authoritative corpus view.
        """

        chunk_ids = set(self._doc_chunks.get(doc_id, ()))
        stale_keys = [
            key
            for key, entry in self.cache.items()
            if doc_id in entry.doc_versions or chunk_ids.intersection(entry.context_chunk_ids)
        ]
        for key in stale_keys:
            del self.cache[key]

    def _purge_memory_for_doc(self, doc_id: str) -> None:
        """Drop memory records derived from ``doc_id``.

        Attribution is canary-based: a record is attributed to the deleted
        document only when its text contains one of that document's canary
        markers. Records without a marker are conservatively retained — the
        deterministic oracles check exactly this attribution, so both sides
        agree on what "derived from" means.
        """

        canaries = self._doc_canaries.get(doc_id, [])
        if not canaries:
            return
        self.memory = [
            record
            for record in self.memory
            if not any(canary in record.text for canary in canaries)
        ]

    # -- Retrieval -----------------------------------------------------------
    def retrieve(self, principal: Principal, query: str, k: int = 5) -> list[RetrievedChunk]:
        raw = self.store.search(query, k=k)
        admitted: list[RetrievedChunk] = []
        for item in raw:
            stored = self.store.get(item.chunk_id)
            if stored is not None and stored.deleted and not self.faults.deleted_doc_retrievable:
                continue
            if not self.faults.missing_tenant_filter and item.tenant_id != principal.tenant_id:
                continue
            if not self.faults.missing_query_acl:
                acl = item.acl
                if self.faults.missing_tenant_filter:
                    # FAULT: tenant identity is not part of the retrieval boundary;
                    # ACLs still enforce role/group/classification, but not tenant.
                    acl = acl.model_copy(update={"tenant_id": principal.tenant_id})
                if not acl.permits(principal):
                    continue
            admitted.append(item)
        self.retrieval_log.append(
            {
                "principal_id": principal.id,
                "tenant_id": principal.tenant_id,
                "revoked": principal.revoked,
                "query": query,
                "raw_chunk_ids": [item.chunk_id for item in raw],
                "admitted_chunk_ids": [item.chunk_id for item in admitted],
                "admitted_doc_ids": [item.doc_id for item in admitted],
            }
        )
        self.trace.record(
            "retrieve",
            principal_id=principal.id,
            query=normalize_query(query),
            raw=len(raw),
            admitted=len(admitted),
        )
        return admitted

    # -- Cache ---------------------------------------------------------------
    def cache_key(self, query: str, principal: Principal) -> str:
        if self.faults.unscoped_cache_key:
            # FAULT: key omits tenant and entitlement scope.
            return normalize_query(query)
        # Include the principal id so a denial cached for one principal (for example a
        # revoked user) is never replayed to a different principal with the same
        # entitlement fingerprint.
        return (
            f"{principal.tenant_id}:{principal.entitlement_fingerprint()}:"
            f"{principal.id}:{normalize_query(query)}"
        )

    def _find_semantic_entry(self, principal: Principal, query: str) -> CacheEntry | None:
        if not self.semantic_cache:
            return None
        query_vector = self._semantic_embedder.embed(normalize_query(query))
        best_entry: CacheEntry | None = None
        best_score = self.semantic_threshold
        for entry in self.cache.values():
            if entry.tenant_id != principal.tenant_id:
                continue
            if entry.entitlement_fingerprint != principal.entitlement_fingerprint():
                continue
            # Semantic reuse is per-principal, exactly like the exact key. A
            # cross-principal hit would replay another principal's answer
            # (including a denial) and could bypass that principal's revocation.
            if not entry.principal_id or entry.principal_id != principal.id:
                continue
            score = cosine_similarity(
                query_vector, self._semantic_embedder.embed(normalize_query(entry.query))
            )
            if score >= best_score:
                best_score = score
                best_entry = entry
        return best_entry

    def _cache_valid(self, entry: CacheEntry, principal: Principal) -> bool:
        # Entries are principal-bound: a cached denial or answer must never be
        # replayed to a different principal, and a revoked requester never
        # receives cached content, even if the entry's entitlement fingerprint
        # is otherwise unchanged.
        if not entry.principal_id or entry.principal_id != principal.id:
            return False
        if principal.revoked:
            return False
        if entry.acl_epoch != self.current_epoch:
            return False
        for doc_id, epoch in entry.doc_acl_epochs.items():
            if self._doc_acl_epochs.get(doc_id, 1) != epoch:
                return False
        if entry.entitlement_fingerprint != principal.entitlement_fingerprint():
            return False
        if not self.faults.missing_source_freshness:
            for doc_id, version in entry.doc_versions.items():
                if self._doc_versions.get(doc_id) != version:
                    return False
        return True

    # -- Memory --------------------------------------------------------------
    def remember(
        self,
        principal: Principal,
        text: str,
        source: str,
        *,
        trusted: bool = True,
        ttl_epochs: int | None = None,
    ) -> MemoryRecord:
        effective_trust = trusted and source not in UNTRUSTED_SOURCES
        if self.faults.unauthorized_memory_content:
            # FAULT: untrusted content is persisted as trusted.
            effective_trust = True
        record = MemoryRecord(
            id=stable_id("mem", principal.id, text, source, len(self.memory)),
            tenant_id=principal.tenant_id,
            principal_id=principal.id,
            text=text,
            source=source,
            trusted=effective_trust,
            epoch=self.current_epoch,
            expires_at_epoch=(
                self.current_epoch + ttl_epochs if ttl_epochs is not None else None
            ),
        )
        self.memory.append(record)
        self.trace.record(
            "memory_write",
            principal_id=principal.id,
            trusted=effective_trust,
            expires_at_epoch=record.expires_at_epoch,
        )
        return record

    def recall(self, principal: Principal, query: str | None = None) -> list[MemoryRecord]:
        if self.faults.unauthorized_memory_content:
            # FAULT: recall ignores tenant/user scope and expiry.
            return list(self.memory)
        return [
            record
            for record in self.memory
            if record.tenant_id == principal.tenant_id
            and record.principal_id == principal.id
            and (
                record.expires_at_epoch is None
                or record.expires_at_epoch > self.current_epoch
            )
        ]

    # -- Tools ---------------------------------------------------------------
    def call_tool(self, principal: Principal, call: ToolCall) -> ToolExecution:
        execution = self.tools.invoke(
            principal, call, bypass_policy=self.faults.unauthorized_tool_execution
        )
        self.trace.record(
            "tool_call",
            principal_id=principal.id,
            tool=call.name,
            policy_checked=execution.policy_checked,
            allowed=execution.decision.allowed,
            executed=execution.executed,
        )
        return execution

    # -- Answer assembly -----------------------------------------------------
    def answer(self, principal: Principal, query: str, *, use_cache: bool = True) -> Answer:
        key = self.cache_key(query, principal)
        entry = self.cache.get(key) if use_cache else None
        if entry is None and use_cache:
            entry = self._find_semantic_entry(principal, query)
        served = False
        revalidated = False

        if entry is not None:
            if self.faults.stale_cache_after_revocation:
                # FAULT: cache is served without revalidating authorization state.
                served = True
            elif self._cache_valid(entry, principal):
                served = True
                revalidated = True
            else:
                # The entry may come from a semantic (not exact) match, so remove
                # it by its own stored key rather than the lookup key.
                self.cache.pop(entry.key, None)

        if served and entry is not None:
            text = entry.answer
            context_ids = list(entry.context_chunk_ids)
        else:
            retrieved = self.retrieve(principal, query)
            context_ids = [item.chunk_id for item in retrieved]
            text = self.generator.generate(query, retrieved)
            if use_cache:
                version_map: dict[str, int] = {}
                for item in retrieved:
                    version_map.setdefault(item.doc_id, self._doc_versions.get(item.doc_id, 1))
                doc_acl_epochs = {
                    doc_id: self._doc_acl_epochs.get(doc_id, 1) for doc_id in version_map
                }
                self.cache[key] = CacheEntry(
                    key=key,
                    principal_id=principal.id,
                    query=query,
                    tenant_id=principal.tenant_id,
                    entitlement_fingerprint=principal.entitlement_fingerprint(),
                    acl_epoch=self.current_epoch,
                    answer=text,
                    context_chunk_ids=context_ids,
                    doc_versions=version_map,
                    doc_acl_epochs=doc_acl_epochs,
                )

        canaries = [canary for canary in self._canaries if canary in text]
        cache_versions = dict(entry.doc_versions) if served and entry is not None else {}
        current_versions = {
            doc_id: self._doc_versions.get(doc_id, 1) for doc_id in cache_versions
        }
        answer = Answer(
            text=text,
            context_chunk_ids=context_ids,
            cache_hit=served,
            cache_revalidated=revalidated,
            canaries_present=canaries,
            cache_doc_versions=cache_versions,
            current_doc_versions=current_versions,
        )
        self.answer_log.append(
            {
                "principal_id": principal.id,
                "tenant_id": principal.tenant_id,
                "revoked": principal.revoked,
                "query": query,
                "cache_key": key,
                "cache_hit": served,
                "cache_revalidated": revalidated,
                "context_chunk_ids": context_ids,
                "canaries_present": canaries,
                "cache_doc_versions": cache_versions,
                "current_doc_versions": current_versions,
            }
        )
        self.trace.record(
            "answer",
            principal_id=principal.id,
            cache_hit=served,
            context=len(context_ids),
            canaries=len(canaries),
        )
        return answer

    # -- Observability -------------------------------------------------------
    def snapshot(self) -> dict[str, object]:
        return {
            "name": self.name,
            "faults": self.faults.model_dump(),
            "epoch": self.current_epoch,
            "store": self.store.snapshot_state(),
            "cache_keys": sorted(self.cache),
            "memory": [record.model_dump() for record in self.memory],
            "tools": [execution.model_dump() for execution in self.tools.executions],
            "trace": self.trace.as_list(),
        }

    def all_canaries(self) -> list[str]:
        return list(self._canaries)
