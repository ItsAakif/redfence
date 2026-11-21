# ADR-0005: Oracles evaluate against the authoritative corpus ACL

- **Status:** accepted
- **Context:** The `lost_chunk_acl_metadata` fault replaces stored chunk ACLs
  with a permissive default. An oracle that recomputed authorization from the
  stored (mutated) ACL would incorrectly conclude the access was authorized and
  would fail to detect the fault.
- **Decision:** Oracles recompute the expected decision from the **corpus
  document ACL** (`redfence.bench.authorization.document_acl`), independently of
  stored metadata, and compare with what the target admitted.
- **Consequence:** Lost/forged metadata and query-time bypasses are detectable.
  This is the core of G3 (deterministic oracle validity). Document metadata
  integrity is a separate control, now covered by `oracle.metadata.integrity`;
  it still runs in the same process as the target, so G3 remains partial on
  process/credential isolation grounds.
