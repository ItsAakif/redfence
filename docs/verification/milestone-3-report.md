# RedFence Milestone 3 — Verification, Validity and Research Readiness

Status: **CONDITIONALLY READY**
Date: 2026-11-08

> **Historical snapshot (pre-0.2.0); see
> [`docs/verification/hardening-report.md`](hardening-report.md) for current
> claims.**
>
> **Later update:** the two unsupported faults and the four held-out families were
> implemented and executed after this report, and the G3/G5/G6/G7/G9 gaps were
> then addressed with process-isolated oracles, a Docker isolation fixture and
> clustered per-family statistics. See
> [`next-steps-report.md`](next-steps-report.md) and
> [`isolation-and-statistics-report.md`](isolation-and-statistics-report.md)
> for the status at that milestone (79 tests, 10/10 faults supported, 4/4 held-out
> families executable, separate oracle process, Docker isolation checks passing).

All numbers below are traceable to files in `docs/verification/raw/`. No test,
run or metric in this report was invented. Commands were executed on the
repository checkout with the raw outputs captured as noted.

## 1. Execution environment

| Item | Value | Evidence |
|---|---|---|
| OS | Microsoft Windows 11 Home Single Language, 10.0.26200, build 26200, 64-bit | `raw/00-environment.txt` |
| PowerShell | 5.1.26100.9168 | `raw/00-environment.txt` |
| Python launcher | 3.14 and 3.13 only; `py -3.12` exits 103 (“No suitable Python runtime found”) | `raw/00-environment.txt` |
| Interpreter used | `python` = Python 3.14.7 at `D:\Python-3.14\python.exe` | `raw/00-environment.txt`, `raw/02-dependency-install.txt` |
| Virtualenv | `.venv`, Python 3.14.7 | `raw/02-dependency-install.txt` |
| Project requirement | `requires-python = ">=3.11"` | `pyproject.toml` |

The harness’s `bash` tool was initially unusable because it resolved to
`C:\Program Files\Git\usr\bin\bash.exe`, which was missing. Execution was
restored with a temporary PowerShell command runner; the failed state is retained
in `raw/01-shell-availability.txt` and `docs/verification/blocked.md` records the
resolution. The bridge used a shallow PortableGit32 clone at
`C:\Users\aakif\PortableGit32`; it is environment infrastructure, not shipped
product code. The prior-art clones live under `.prior-art/` (git-ignored).

## 2. Installation results

`py -3.12` was not available. The fallback interpreter, Python 3.14.7, created
the virtualenv successfully. Installation of the project and dev extras
completed with exit code 0. Pip was upgraded to 26.3. Installed versions
included pydantic 2.14.3, pytest 9.2.0, pytest-cov 7.1.0, coverage 7.17.2,
ruff 0.17.4 and mypy 2.4.1. `pip check` reports no broken requirements.

Evidence: `raw/02-dependency-install.txt`, `raw/12-pip-check.txt`.

Optional API, SQLAlchemy/pgvector and Docker infrastructure was **not installed
or executed**; no claim is made about those paths.

## 3. Test results (real numbers)

- Collection: **64 tests** across 13 files.
- Final run: **64 passed, 0 failed, 0 skipped, 0 errors**.
- Wall-clock pytest run: **4.08 s** (final raw file exit line).
- No test was skipped, deleted or weakened.

Evidence: `raw/03-test-collection.txt`, `raw/04-pytest-coverage.txt`.

## 4. Coverage

Final total: **93%** (1,195 statements, 83 missed). Key modules:
`oracles.py` 95%, `runner.py` 97%, `scenario.py` 99%, `metrics.py` 91%,
`rag_target.py` 97%, `authorization.py` 87%, `domain.py` 98%.
`core/protocols.py`, `api/`, and `db/` are 0% because those optional layers are
not exercised. Coverage is not a security claim.

Evidence: `raw/04-pytest-coverage.txt`.

## 5. Fault coverage matrix

Ten faults are configured in `FaultFlags`. Raw evidence: `raw/10-fault-profile-cache-audit.txt`.

| Fault | Vulnerability description | Switch | Expected observable failure | Scenario | Deterministic oracle | Test file | Executed? | Evidence | Class |
|---|---|---|---|---|---|---|---|---|---|
| `missing_query_acl` | Retrieval skips the ACL decision | `FaultFlags(missing_query_acl=True)` | Unauthorized same-tenant chunks admitted | revocation slice | `oracle.index.acl` | `test_discriminative_validity.py`, `test_cache.py` | yes | mapped oracle violation; collateral context/response violations | implemented and tested |
| `missing_tenant_filter` | Retrieval no longer scopes by tenant | `FaultFlags(missing_tenant_filter=True)` | Cross-tenant chunk admitted | revocation slice, beta probe | `oracle.index.tenant` | `test_discriminative_validity.py` | yes | mapped oracle violation | implemented and tested |
| `lost_chunk_acl_metadata` | Per-chunk ACLs replaced by permissive defaults | `FaultFlags(lost_chunk_acl_metadata=True)` | Forged stored ACL admits forbidden chunk | revocation slice | `oracle.index.acl` | `test_discriminative_validity.py` | yes | mapped oracle violation only | implemented and tested |
| `mutable_document_metadata` | Document metadata can diverge from authority | `FaultFlags(mutable_document_metadata=True)` | Metadata-integrity violation | none | `oracle.unsupported.metadata_integrity` | none | no | coverage oracle reports unsupported | **unsupported** |
| `stale_cache_after_revocation` | Cache reuse skips current authorization/epoch | `FaultFlags(stale_cache_after_revocation=True)` | Revoked principal served cached answer | revocation replay | `oracle.cache.leak` | `test_cache.py`, `test_discriminative_validity.py` | yes | hit=true, revalidated=false, canary leaked | implemented and tested |
| `unscoped_cache_key` | Cache key omits tenant/entitlement scope | `FaultFlags(unscoped_cache_key=True)` | Key collision across scope | revocation replay | `oracle.cache.key_scope` | `test_cache.py` | yes | unscoped key `nimbus launch code` | implemented and tested |
| `missing_source_freshness` | Freshness check omitted on reuse | `FaultFlags(missing_source_freshness=True)` | Stale evidence reused | none | `oracle.unsupported.freshness` | none | no | coverage oracle reports unsupported | **unsupported** |
| `deleted_doc_retrievable` | Soft delete leaves chunks retrievable | `FaultFlags(deleted_doc_retrievable=True)` | Deleted document still retrieved | deletion probe | `oracle.index.deletion` | `test_secured_profile.py`, `test_discriminative_validity.py` | yes | 2 retrievable deleted chunks; collateral ACL violation | implemented and tested |
| `unauthorized_memory_content` | Untrusted memory trusted and recall unscoped | `FaultFlags(unauthorized_memory_content=True)` | Cross-principal/untrusted memory returned | memory probe | `oracle.memory.scope` | `test_memory.py` | yes | mapped oracle violation | implemented and tested |
| `unauthorized_tool_execution` | Tool policy bypassed | `FaultFlags(unauthorized_tool_execution=True)` | Unauthorized side effect executes | tool probes | `oracle.tool.policy` | `test_tools.py`, `test_discriminative_validity.py` | yes | mapped oracle violation | implemented and tested |

**Exactly two faults are unsupported:** `mutable_document_metadata` and
`missing_source_freshness`. They have config switches and fault-to-oracle
mappings but no executable oracle; the coverage oracle explicitly reports them as
unsupported instead of passing them.

## 6. Oracle independence analysis

Authoritative ACLs originate in the synthetic `Corpus` / `Document.acl`
(`src/redfence/bench/dataset.py`) and are read through
`src/redfence/bench/authorization.py`. The target stores mutable chunk ACLs in
`InMemoryVectorStore` (`src/redfence/targets/rag_target.py`). The oracles
recompute policy from the corpus ACL and frozen observation metadata, not from
the target’s stored chunk ACL.

The adversarial test `tests/test_oracle_independence.py` corrupts the stored ACL
of every `doc_alpha_secret` chunk to `public` while leaving the corpus ACL
intact. The target then admits three chunks for the low-privilege intern, and
`IndexAclOracle` still reports a violation. Raw evidence:
`raw/10-fault-profile-cache-audit.txt` (“ORACLE INDEPENDENCE”, 3 unauthorized
admissions of 8 checked).

**Remaining common-mode risk:** ground truth, target, oracles, cache and memory
run in the same Python process with in-memory objects. There is no separate
service, database, process or credential scope for the oracle. A shared
implementation error in both target and oracle is therefore not structurally
excluded. G3 is consequently **partial**, despite the adversarial test passing.

## 7. Revocation vs deletion

These are tested as separate invariants.

**Revocation:** the secured scenario revokes `p_alpha_reader`, increments the
authorization epoch, and replays the same query. Post-revoke retrieval admits
zero chunks and the answer context is empty in the secured run. Raw evidence:
`raw/10-fault-profile-cache-audit.txt` (“SECURED METRIC RECONCILIATION” and cache
trace). The vulnerable profile serves the old cached answer after revocation
(`oracle.cache.leak` violation).

**Deletion:** the secured target hard-deletes `doc_beta_secret`; the post-delete
beta retrieval admits zero chunks and the deletion oracle is satisfied. The
vulnerable profile soft-deletes only and leaves 2 chunks retrievable. The
deletion requirement in this benchmark is both logical inaccessibility and
physical removal from the in-memory index; both are reported. Retention,
replicas, backups and deletion propagation into caches/memory are **not**
exercised, so deletion coverage is narrower than the full invariant.

## 8. Cache semantics

Cache trace is in `raw/10-fault-profile-cache-audit.txt`.

- **Secured key format:** `tenant:entitlement_fingerprint:principal_id:query`,
  e.g. `t_alpha:ent_9f98132defd8b792:p_alpha_reader:nimbus launch code`.
- **Positive hit control:** first answer `hit=False`; second answer
  `hit=True`, `revalidated=True`, context contains the protected chunks and the
  alpha canary. This proves the secured path actually selects an existing entry
  rather than merely replaying a denial.
- **Stale-cache fault:** after revocation, the same key produces `hit=True`,
  `revalidated=False`, old context and the alpha canary; `oracle.cache.leak`
  reports a violation (11 leaks across 2 hits in the vulnerable profile).
- **Unscoped-key fault:** keys collapse to `nimbus launch code`;
  `oracle.cache.key_scope` reports 2 unscoped keys. The scenario itself does not
  produce a hit on that unscoped key, so key-scope failure is proven structurally
  and the stale-cache fault proves the revalidation failure.
- **Control that prevented reuse:** epoch/entitlement/principal binding plus
  current-authorization checks. A separate regression test ensures a denial
  cached for revoked alpha is not replayed to non-revoked alpha lead.

## 9. Security-profile comparison and G2

Raw profile matrix: `raw/10-fault-profile-cache-audit.txt`.

| Profile | Exit | Result |
|---|---:|---|
| Secured | 0 | all 11 oracles satisfied; utility preserved; metrics all zero for security violations |
| Vulnerable | 1 | 9 oracles violation; coverage oracle unsupported for the two unsupported faults; utility preserved |
| Partial | 1 | index ACL, cache key scope, context exposure and response disclosure violate; tenant/deletion/memory/tool oracles remain satisfied |

G2 discriminative validity passes on execution (`raw/06-vertical-slice.txt`):
for each of the 8 supported faults, the secured profile is satisfied and the
vulnerable profile is a violation on the mapped oracle. Each single fault is
also run in isolation in `test_discriminative_validity.py`; 16 such checks pass.
Benign utility is preserved for every single-fault run in `raw/10`.

## 10. Dataset integrity and held-out execution

`raw/10-fault-profile-cache-audit.txt` records:

- dataset version `redfencebench-0.1.0`, seed `20260101`;
- 2 tenants, 4 principals, 4 documents;
- canaries unique and represented only by SHA-256 markers in the manifest;
- development and held-out family lists are disjoint;
- deterministic content hashes in the manifest and generated corpus files.

`raw/05-dataset-generation.txt` records successful generation of
`manifest.json`, `manifest.full.json` and `corpus.json`.

**Held-out evaluation is unsupported.** The four held-out family names are
declared, but there are **0 executable held-out scenarios**
(`heldout_executable_scenarios=0`). No transformed/paraphrased held-out template
test exists, because there is no scenario implementation for those families.
G7 is therefore **partial**, not passed.

## 11. Statistical validity

- Wilson intervals are implemented and tested (`metrics.py`,
  `tests/test_metrics.py`).
- Empty denominators return `value=None`; e.g. secured `cache_leakage` is 0/0.
- Point estimates and intervals are separate in JSON/HTML output.
- Repeated paraphrases share one base scenario; the metrics note this and the
  report does not treat paraphrases as independent samples.
- N is one scenario, four documents, a handful of observations. **N is too
  small for any significance claim.** No significance claim is made.
- `false_positive` is a partial proxy (authorized retrieval returning no
  chunks), and `false_negative` counts attack attempts without canary
  disclosure. These are not full FPR/FNR estimators.
- No clustered bootstrap or paired comparison is implemented.

G5 is **partial**.

## 12. Infrastructure isolation (G6)

The benchmark target is a single in-process Python object with an in-memory
vector store. Platform and target do not have separate services, processes,
databases, credentials, network namespaces or restricted file permissions.
`docker-compose.yml` exists but Docker/PostgreSQL/pgvector were not installed or
executed in this run. The synthetic tool runtime does not make real network
calls; the simulated egress sink was not exercised under container isolation.

G6 is **partial**. The repository documentation should not describe this as two
security domains until separate services and credentials are demonstrated.

## 13. Prior-art audit

Eight repositories were shallow-cloned into `.prior-art/` (git-ignored) and
audited at source level. Raw evidence: `raw/13-prior-art.txt`.

| Project | Commit | Licence | Confirmed finding |
|---|---|---|---|
| Promptfoo | `2a6fdf9b2e1600ffa2a204e70e9fea7cb0c14cff` | MIT | 6,027 tracked files; 197 paths under `redteam/plugins`; BOLA/BFLA/cross-session-leak/agentic memory poisoning referenced. The “~157 plugins” figure was not verified exactly and is not used. |
| PyRIT | `c98bdd8ec657696b59a48dea8f19a5634cfa53f7` | MIT | `TraceScorable`, `OtelToolCallScorer`, `FileWriteScorer`, `ProgramExecutionScorer` confirmed. Deterministic state/trace scoring is prior art. |
| garak | `892779207cbc38f65a738ef9cbdfbc1e83aa0b55` | Apache-2.0 | `garak/buffs/base.py` and buff plugins confirmed; lineage-tracking transform layer is a pattern worth adopting. |
| AgentDojo | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT | `utility()` and `ground_truth()` task contracts confirmed in examples. |
| DeepTeam | `6306f0ff319a932955399405af82f78ee91e9370` | Apache-2.0 | 50+ vulnerabilities, LLM-as-judge scoring. |
| SafeRAG | `e8f579743b23e0a3937076dcc0792fe29027cba3` | no licence file at root | Four injection tasks and 14 RAG components described. Treated as unverified for reuse. |
| LeakDojo | `ae3ac6db8f4533c4f408305855af4f73eab2af6a` | Apache-2.0 | Six attacks, LMA/RankerSet/CodeClaim, CCL leakage metric. |
| InjecAgent | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT (`LICENCE`) | 1,054 cases, 17 user tools, 62 attacker tools. |

RedFence’s contribution must be stated as the benchmark composition and
authorization-state lifecycle across index/cache/memory/tool paths, not as the
invention of state oracles. MITRE ATLAS identifiers were not re-verified in this
run; only AML.T0070 (RAG Poisoning) was previously corroborated, and other IDs
remain unverified.

## 14. Acceptance gates G1–G9

| Gate | Result | Evidence / reason |
|---|---|---|
| G1 Metric correctness | **PASS (with limitations)** | Metrics recompute from frozen observations; secured metrics 0/5 unauthorized, 0/4 disclosure; tests pass. Limitations: proxy FPR, 0/0 cache denominator, small N. |
| G2 Discriminative validity | **PASS** | Secured vs vulnerable mapped oracles; 8/8 supported faults; single-fault runs; partial profile; utility preserved. Raw `06`, `10`. |
| G3 Oracle validity | **PARTIAL** | Authoritative corpus ACL + frozen metadata; adversarial stored-metadata test passes. Ground truth is same process/objects, not separate service/DB/credential scope. |
| G4 Reproducibility | **PASS** | Deterministic tests pass (`test_reproducibility.py`), repeated campaigns identical, manifest/seed/hashes recorded, reports regenerated. |
| G5 Statistical validity | **PARTIAL** | Wilson intervals and empty-denominator handling tested; N too small for significance; no clustered bootstrap; proxies documented. |
| G6 Infrastructure isolation | **PARTIAL** | Single in-process target, in-memory store; Docker/Postgres/pgvector not executed; no separate credentials/network/egress boundary demonstrated. |
| G7 Dataset integrity and splits | **PARTIAL** | Deterministic corpus, manifest hashes, canary uniqueness, tenant separation, family-disjoint split. Held-out families have 0 executable scenarios and were not run. |
| G8 Regression integrity | **PASS** | 64/64 pass after fixes; new regression tests for oracle independence, positive cache hit and revoked-denial reuse; no tests skipped/weakened. |
| G9 Safety and containment | **PARTIAL** | Synthetic tool runtime and in-memory target; no real egress/container sandbox exercise; containment claims remain architectural, not demonstrated. |

## Fix protocol record

| Failure | Root cause | Classification | Fix | Regression evidence |
|---|---|---|---|---|
| `CacheKeyOracle` TypeError | Oracle called `entry.entitlement_fingerprint()` but `CacheEntry` stores a string field | Implementation defect | Use the field, not a method | existing cache tests pass (`raw/04`) |
| Secured profile reported ACL/context/response/utility violations | Oracles/metrics used the live, post-revocation principal and post-deletion store for earlier observations | Implementation defect | Freeze principal revocation state and chunk metadata in observations; recompute from frozen metadata | `test_secured_profile.py`, `test_reproducibility.py` pass |
| Revoked alpha’s denial starved non-revoked alpha lead | Cache key omitted principal identity; identical entitlement fingerprints collided | Implementation defect | Include principal id in cache key; add positive-hit and denied-reuse regression tests | `test_cache.py` passes |
| `missing_tenant_filter` not observable | ACL tenant check masked the disabled tenant filter | Implementation defect / benchmark design overlap | When tenant filter is disabled, apply ACL without tenant constraint; synthetic beta reader shares the alpha-eng group so tenant isolation is the sole remaining boundary | mapped oracle violation in `raw/10` |
| Metric reported unauthorized retrieval for valid pre-deletion observation | Metric read live store after later deletion | Implementation defect | Use frozen observation metadata in metrics | secured metric 0/5 in `raw/10` |

## Final decision

**B. CONDITIONALLY READY.**

The architecture works: installation, tests, dataset generation, vertical slice,
JSON/HTML reports, deterministic replay, G2 fault discrimination, and oracle
independence all executed successfully. The remaining restrictions are material:
oracle and target share one process and in-memory store (G3), isolation has not
been demonstrated (G6/G9), held-out scenarios are not executable (G7), and the
sample is far too small for statistical claims (G5). Two of the ten configured
faults are unsupported. The correct next milestone is to demonstrate real
service/credential isolation, implement and execute held-out families, and add
clustered/uncertainty-aware statistics before making a broad benchmark claim.
