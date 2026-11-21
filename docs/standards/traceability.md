# Standards traceability

Version `redfencebench-0.4.0`. Mappings are **traceability references only** —
not certifications and not claims of compliance. Every row states the standard
and version, the requirement/vulnerability id, the RedFence scenario, the
verification method, the expected evidence, and implementation status.

Status legend: `implemented` (executable oracle) · `partial` · `candidate`
(mapping is plausible but the id/text has not been re-verified against the
pinned upstream document) · `unsupported` (declared, not claimed) · `planned`.

> Identifier caveat: OWASP AISVS requirement ids and MITRE ATLAS technique ids
> below are taken from the sources cited in `docs/prior-art/`. Confirm exact ids
> and version strings against the pinned upstream documents before any external
> publication. `AML.T0070` (RAG Poisoning) and `AML.T0082` (RAG Credential
> Harvesting) were confirmed against ATLAS/D3FEND; `AML.T0053`, `AML.T0071`,
> `AML.T0086` are per the mandate and pending re-verification. The C9 and
> Agentic Top 10 rows added for 0.3.0 are explicitly `candidate`: they map the
> new oracles to plausible requirement ids, but the ids/text have not been
> re-verified for this release.

## OWASP AISVS 1.0 — Chapter C8 (Memory, Embeddings & Vector Database)

| Requirement | Scenario | Verification method | Expected evidence | Status |
|---|---|---|---|---|
| C8.1.1 namespace/tenant uniqueness, no cross-tenant collisions | `revocation` cross-tenant | `oracle.index.tenant` recomputes tenant predicate | no cross-tenant chunk admitted | implemented |
| C8.1.2 metadata immutable after write | `revocation` metadata fault | `oracle.metadata.integrity` | no stored-metadata divergence | implemented |
| C8.1.3 retrieval enforces scope at query time | `revocation` post-revoke | `oracle.index.acl` | no chunk admitted to denied principal | implemented |
| C8.2.1 sensitive fields detected before embedding | `revocation` canaries | canary markers hashed in manifest | no cleartext canary in artifacts | partial |
| C8.2.3 tool outputs not auto-written to trusted memory | `revocation` memory | `oracle.memory.scope` trust check | untrusted source stored as untrusted | implemented |
| C8.2.4 manipulation detected before vectorization | `revocation` malicious doc | declared | — | planned |
| C8.2.5 contradictions trigger alerts | — | — | — | planned |
| C8.3 memory expiry & revocation | `revocation` post-revoke; `memory.ttl.expiry` family | recall scope + epoch + TTL checks | no out-of-scope or expired recall | implemented |
| C8.3 cache invalidation after deletion | `revocation` deletion propagation; `deletion.propagation.cache_memory` family | `oracle.cache.deletion_propagation`, `oracle.memory.deletion_propagation` | no cached answer or memory record derived from a deleted document is served | implemented |

## OWASP AISVS 1.0 — Chapter C9 (Agentic / external targets) — candidate

The C9 ids below are **candidate** mappings added with the 0.3.0 external-target
boundary. They are traceability pointers, not verified requirement text.

| Requirement (candidate) | Scenario | Verification method | Expected evidence | Status |
|---|---|---|---|---|
| C9.5.3 delegated capability is attenuated to a subset of the parent | `delegation.chain`; contract capability cells | `oracle.capability.attenuation`, `oracle.capability.expiry`, `oracle.capability.scope` | no widened scope/capability/expiry; no use after expiry or revocation | candidate |
| C9.5.7 external tool/MCP definitions are pinned and checked for change | MCP fixture modes `benign`, `poisoned_description`, `rug_pull`, `shadowing` | `oracle.mcp.manifest`, `oracle.mcp.rugpull`, `oracle.mcp.shadowing` | no injection markers, no undeclared definition change, pinned server wins | candidate |
| C9.3.x derived state is traceable and deleted copies are removed | lineage, existence and retention runs | `oracle.lineage.derivation`, `oracle.retention.durability`, `oracle.replica.consistency` | every derived artifact reaches an authoritative document; no readable copy after deletion; replica never returns what the primary denies | candidate |

## OWASP LLM Top 10 2026

| Id | Risk | Scenario | Oracle | Status |
|---|---|---|---|---|
| LLM01 | Prompt Injection | `revocation` | `oracle.context.exposure`, `oracle.response.disclosure` | implemented |
| LLM02 | Sensitive Information Disclosure | `revocation` | `oracle.response.disclosure` | implemented |
| LLM03 | Excessive Agency | `revocation` | `oracle.tool.policy` | implemented |
| — | Hidden Context Exposure | `revocation` | `oracle.context.exposure` | implemented |

## OWASP Top 10 for Agentic Applications 2026

| Risk | Scenario | Oracle | Status |
|---|---|---|---|
| Tool misuse / unauthorized action | `revocation` | `oracle.tool.policy` | implemented |
| Cross-tenant / confused deputy | `revocation` | `oracle.index.tenant`, `oracle.tool.policy` | partial |
| ASI03 identity and privilege abuse | `delegation.chain`; contract matrix | `oracle.capability.attenuation`, `oracle.capability.expiry`, `oracle.capability.scope`, `oracle.contract.matrix` | candidate |
| ASI06 memory and context poisoning | memory poisoning; lineage; MCP fixture | `oracle.memory.scope`, `oracle.lineage.derivation`, `oracle.mcp.manifest` | candidate |

## OWASP RAG Security Cheat Sheet

| Control | Scenario | Oracle | Status |
|---|---|---|---|
| ACL metadata stored per chunk | `revocation` lost-metadata fault | `oracle.index.acl` | implemented |
| ACL enforced at retrieval time | `revocation` post-revoke | `oracle.index.acl` | implemented |
| Tenant isolation in vector store | `revocation` cross-tenant | `oracle.index.tenant` | implemented |
| Retrieval logged with identity + metadata | all | `ExecutionTrace`, `retrieval_log` | implemented |

## MITRE ATLAS

| Technique | Scenario | Oracle | Status |
|---|---|---|---|
| AML.T0070 RAG Poisoning | malicious doc | declared | planned |
| AML.T0071 False RAG Entry Injection | malicious doc | declared | planned |
| AML.T0053 AI Agent Tool Invocation | tool misuse | `oracle.tool.policy` | partial |
| AML.T0082 RAG Credential Harvesting | canary disclosure | `oracle.response.disclosure` | partial |
| AML.T0086 Exfiltration via AI Agent Tool Invocation | tool exfil | `oracle.tool.policy` + sink | partial |
| AML.T0053 AI Agent Tool Invocation (0.3.0 extension) | contract tool cells; MCP fixture | `oracle.capability.scope`, `oracle.mcp.shadowing` | candidate |
| AML.T0070 RAG Poisoning (0.3.0 extension) | lineage / twin corpus | `oracle.lineage.derivation`, `oracle.existence.twin` | candidate |

## OWASP Agent Control Standard (ACS) v0.1.4 — hook alignment

The target exposes the state needed to implement these hooks. Only the hooks
exercised by the vertical slice are listed as implemented.

| ACS hook | RedFence event | Status |
|---|---|---|
| `sessionStart` / `turnStart` | scenario step boundary | partial |
| `knowledgeRetrieval` | `retrieve()` → `retrieval_log` | implemented |
| `memoryContextRetrieval` | `recall()` → memory observations | implemented |
| `memoryStore` | `remember()` → trust provenance | implemented |
| `toolCallRequest` | `call_tool()` → PDP decision | implemented |
| `toolCallResult` | `SyntheticToolRuntime.executions` | implemented |
| `agentResponse` | `answer()` → `answer_log` | implemented |
