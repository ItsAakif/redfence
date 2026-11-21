# Architecture

## Design principles

1. Research before implementation; evidence before conclusions.
2. Deterministic verification before LLM judging.
3. Security and benign utility measured together.
4. Small composable abstractions over distributed architecture.
5. Authorization lives in trusted application code, never in the model.
6. Never confuse attack delivery with successful exploitation.

## Component diagram

```
                        +-------------------------------------------+
                        |            RedFence platform             |
                        |                                           |
  dataset ------------->|  bench/                                   |
  (synthetic, seeded)   |    dataset -> scenario -> oracles         |
                        |       |            |          |           |
                        |       v            v          v           |
                        |    Corpus     ScenarioRun   Evidence      |
                        |                     |           |           |
                        |                     v           v           |
                        |               metrics <--- runner ------> report/
                        |                                  (JSON/HTML)|
                        +---------------------|---------------------+
                                              | drives
                                              v
              +---------------------------------------------------------+
              |             System under test (trust domain 2)          |
              |                                                         |
              |  ConfigurableRAGTarget                                  |
              |    - InMemoryVectorStore (RetrievalAdapter)             |
              |    - DeterministicEmbedder / DeterministicGenerator     |
              |    - response cache (scoped key + revalidation)         |
              |    - persistent memory (scope + trust provenance)       |
              |    - SyntheticToolRuntime + DefaultToolPolicy (PDP)     |
              |    - ExecutionTrace                                     |
              +---------------------------------------------------------+
```

## Trust domains

| Domain | Owns | Credentials |
|---|---|---|
| **RedFence platform** (`PlatformBase`) | campaigns, attempts, findings, evidence, metrics, baselines | separate role; may not read SUT data directly |
| **System under test** (`SutBase`) | tenants, chunks, cache, memory, tool state | separate role; reached only through the target adapter |

The target adapter is the *only* interface between domains. The assessment code
observes through it; it does not gain unrestricted database access.

## Protocol seams

`RetrievalAdapter`, `AccessPath`, `Scorer`, `AttackGenerator`, `ToolPolicy`,
`Target` (`src/redfence/core/protocols.py`). Only the adapters required for the
vertical slice are implemented; new implementations must justify the seam.

## Data flow of a finding

1. The scenario changes state (ingest, cache, revoke, delete, tool call).
2. Each step emits a labelled observation.
3. An oracle recomputes the expected policy from the **authoritative corpus ACL**
   and returns typed `Evidence`.
4. Metrics aggregate evidence; the runner assigns an exit code.
5. Reports serialise evidence, metrics and a reproducible manifest.

## Why the authoritative ACL matters

A fault may *mutate stored chunk metadata* (lost/forged ACL). If the oracle
recomputed authorization from the mutated stored ACL it would incorrectly agree
with the target. Oracles therefore evaluate against the corpus document ACL and
compare, which makes metadata-loss detectable. This is the key architectural
decision behind G3.

## Determinism

- Hash-based embedder, template generator, seeded corpus, stable IDs.
- No wall-clock or randomness in the decision path. Timestamps are **logical**:
  `Evidence.timestamp` and `CacheEntry.created_at` default to `FIXED_INSTANT`
  from `core/clock.py`; there is no wall clock in the report path.
- Reports are **byte-identical for fixed inputs**: two runs at the same dataset
  version, kind, profile, template, seed and fault set produce the same JSON and
  HTML bytes.
- Replays reproduce outcomes, evidence and the manifest exactly.

## Scenario identity and manifest provenance

A scenario is identified by the tuple `(dataset_version, kind, profile, template,
seed, sorted faults)`. That tuple drives `scenario_id`, evidence ids and report
filenames, so distinct templates, fault sets, or development-versus-held-out
kinds cannot collide at the same seed. Each run manifest records the same
identity, the package version, the corpus manifest and its canonical digest
(`corpus_manifest_sha256`), the sorted faults and their digest (`faults_sha256`),
and the oracle isolation mode (`in_process` or `subprocess`). No PID or
wall-clock time is stored.

## Contract boundary (0.3.0)

A contract is the only supported way to point RedFence at a system it did not
write. The path is:

```
contract file (JSON/YAML)
      |
      v
contracts/loader.py  bounded parse, reject tags/anchors/aliases/dupes/traversal
      |
      v
contracts/schema.py  ContractV1 (extra="forbid")
      |
      v
contracts/target.py  ContractTarget protocol -> mock | callable | http
      |
      v
bench/contract_runner.py  matrix + lifecycle -> ContractRun
      |
      v
bench/contract_oracles.py + report/{contract_report,sarif,junit}.py
```

### Contract and adapters

`ContractV1` declares identities, sources, a permission matrix, lifecycle steps,
limits and redaction environment-variable names. The loader is stdlib-only for
JSON and imports `yaml` lazily for YAML; a missing extra is a typed
`ContractError`, never an import-time failure. Bounds are enforced before a model
is returned: file size, depth, list sizes, unique ids, limits ranges, bare
hostnames in the egress allowlist, env-var names (never values) for redaction,
corpus canary labels, and no `callable` selection from a file.

`ContractTarget` is a narrow Protocol: `name`, `capabilities`, `execute(req)` and
`reset()`. `MockContractTarget` implements the contract's ACL matrix
deterministically. `CallableContractTarget` is Python-API only. `HttpContractTarget`
posts JSON through a `Transport`; `UrllibTransport` is the stdlib implementation
with redirects disabled, while tests use `FakeTransport` and never open a socket.
An HTTP failure, timeout, redirect, non-2xx status or oversized body becomes
`status="error"` or `truncated=True`; the adapter boundary never raises.

### Runner and the `ContractRun` seam

`run_contract(contract, target)` executes matrix cells in declaration order, then
applies lifecycle steps and replays every cell whose identity or source is
affected. It records a `MatrixObservation` per executed cell and a
`LifecycleObservation` per step.

`ContractRun` is a sibling of `ScenarioRun`, not a replacement. It has the same
field names and value types for `retrieval_obs`, `answer_obs`, `memory_obs`,
`tool_obs`, `deletion_obs` and `utility_obs`, plus adapter-only facts
(`matrix_obs`, `lifecycle_obs`, `budget_obs`, `lineage`). This is the seam that
lets contract oracles reuse the existing TypedDicts and shared predicates without
widening `ScenarioRun`, editing a frozen observation key, or touching
`default_oracles()`. `SnapshotTarget` (promoted to `bench/snapshot.py`) supplies
`.store`/`.cache`/`.tools`/`.faults` so store-reading helpers such as
`_chunk_meta` work unchanged for isolated and contract runs.

Adapters project only facts they can express. Unknown metadata is `"unknown"` and
is resolved against the contract's authoritative sources, never the adapter's
claim. An action the adapter cannot express yields zero units and therefore
`UNSUPPORTED`; the runner never fabricates a `SATISFIED`.

### Lineage

`core/lineage.py` holds pure data (`Span`, `Artifact`, `LineageEdge`,
`LineageGraph`); `bench/lineage.py` reconstructs the graph from observations,
corpus and target snapshot. The target is not instrumented and imports nothing
from `bench`. For external targets, `context_refs` and `sources` are the only
provenance; a missing ref yields no artifact and `oracle.lineage.derivation`
returns `UNSUPPORTED`. The oracle flags a derived artifact with no path to an
authoritative document and any live descendant of a deleted document.

### Existence

`bench/existence.py` builds twin corpora that differ only in the target
document's presence/ACL and compares a response feature vector per query pair
(`status`, text hash, context-ref set, `tool_executed`). Any difference is a
`VIOLATION`. The permutation oracle is exact for ≤12 pairs, otherwise 2000
Monte-Carlo resamples with a fixed seed, and it returns `UNSUPPORTED` unless a
pair has at least two samples per twin. No p-value is printed for the
deterministic synthetic target.

### Repair

`bench/repair.py` applies a declared `RepairPlan` (`purge_cache`, `reingest`,
`delete_memory`, `restore_acl`) to the synthetic target and replays the violating
and benign observations. `oracle.repair.selective` requires the violation to be
gone **and** benign utility preserved; `oracle.repair.collateral` requires an
unrelated principal/source to remain served. Zero opportunities yields
`UNSUPPORTED`. Repair is a pure helper; existing deletion semantics are not
changed.

### Capability

`core/capability.py` defines `CapabilityToken`, `DelegationChain` and token-use
observations. `oracle.capability.attenuation` requires child scope, capabilities
and expiry to be a subset of the parent; `.expiry` rejects use at/after expiry or
after revocation; `.scope` rejects an action outside the token's scope.
`DefaultToolPolicy.decide` gains an additive `token=None` keyword; the existing
`token=None` path is byte-identical.

### MCP fixture

`bench/mcp.py` is a stdlib JSON-RPC 2.0 fixture over stdio (`initialize`,
`tools/list`, `tools/call`) with modes `benign`, `poisoned_description`,
`rug_pull` and `shadowing`. No network and no third-party SDK. The manifest
oracle checks injection markers and a pinned digest, the rug-pull oracle checks a
definition change without a declared update, and the shadowing oracle checks that
resolution picks the pinned server. This is a fixture plus manifest-level
oracles, not a full MCP client.

### Retention and replicas

`targets/retention.py` provides deterministic in-memory `ReplicaConfig`,
`BackupConfig` and `RetentionConfig`. When configured, `mark_document_deleted`
propagates to every store; the default `None` path is byte-identical.
`oracle.retention.durability` requires no readable copy after deletion;
`oracle.replica.consistency` requires a replica never to return what the primary
denies. Retention policy windows and persistence are out of scope.

### Optional imports

`redfence.integrations` exports nothing at import time. `inspect_ai` and
`opentelemetry` are imported inside the adapter functions, and PyYAML is imported
inside the YAML loader. `import redfence` must not import `yaml`, `hypothesis`,
`inspect_ai` or `opentelemetry`; a test asserts this.

## Explicitly deferred

Adaptive attack selection, broad attack catalogue, Redis/distributed workers,
dashboard, real embedding/LLM providers, a full MCP client (only a deterministic
fixture and manifest-level oracles ship), multimodal input, retention policy
windows and persistent replicas/backups.
