# Next Steps — What Changed After Milestone 3

> **Historical snapshot (pre-0.2.0); see
> [`docs/verification/hardening-report.md`](hardening-report.md) for current
> claims.**

Date: 2026-11-10

> **Later update:** the five remaining gaps were addressed after this report:
> process-isolated oracles (G3), a Docker credential/network isolation fixture
> (G6/G9), embedding-backed semantic cache (G7), and clustered per-family
> statistics across 25 seeds (G5). See
> [`isolation-and-statistics-report.md`](isolation-and-statistics-report.md).
> A further lifecycle-breadth round followed (deletion propagation, ACL
> modification, memory expiry, corpus templates); the current state is
> documented in [`lifecycle-breadth-report.md`](lifecycle-breadth-report.md).
> At that update the test count was 79/79; it was 147 tests at the
> lifecycle-breadth milestone. The current count is reported in the hardening
> report.

This document explains the next-step work in plain language first, then gives
the technical record. All numbers are traceable to the new raw files
`docs/verification/raw/20-next-step-*` through `27-next-step-*`.

## 1. Plain-language summary

Milestone 3 proved the core benchmark works, but it had three important gaps:
two of the ten faults had no real detector, the four “held-out” scenario families
were only names, and the statistics layer had no clustered uncertainty method.

We fixed all three:

1. **All ten faults now have a real executable oracle.** The two missing checks —
   “metadata can be changed after write” and “cached evidence can be stale after
   the source document changes” — now have scenarios, oracles and tests.
2. **All four held-out families are real scenarios.** They are executed separately
   from the development slice, and each one passes on the secured profile and
   fails on the vulnerable profile.
3. **Clustered bootstrap statistics were added.** Repeated paraphrases/turns can
   now be resampled as one cluster instead of being treated as independent
   observations.

The benchmark is stronger, but still **not fully isolated**: the target and
oracle still run in the same Python process with an in-memory store. Docker /
separate service / separate credential isolation is still future work.

## 2. What we achieved

| Item | Before | After |
|---|---|---|
| Test count | 64 | **75** |
| Passing tests | 64 | **75 passed, 0 failed, 0 skipped** |
| Coverage | 93% | **93%** (1,382 statements, 96 missed) |
| Supported faults | 8 of 10 | **10 of 10** |
| Unsupported faults | 2 | **0** |
| Held-out families executable | 0 of 4 | **4 of 4** |
| Clustered bootstrap | absent | **implemented + tested** |
| Dev G2 discrimination | 8/8 | **10/10** |
| Held-out discrimination | not executed | **4/4 secured pass, vulnerable fail** |

Evidence:

- `raw/20-next-step-collection.txt` — 75 tests collected.
- `raw/21-next-step-coverage.txt` — 75 passed; 93% coverage; 2.49 s.
- `raw/23-next-step-dev-slice.txt` — development G2 now 10/10.
- `raw/24-heldout-execution.txt` — all four held-out families discriminate.
- `raw/25-next-step-audit.txt` — all 10 faults isolated; 0 unsupported.
- `raw/26-next-step-pip-check.txt` — no broken requirements.

## 3. What changed technically

### 3.1 Two new faults are now supported

**`mutable_document_metadata`**

- Added `ConfigurableRAGTarget.mutate_document_metadata(...)`.
- Added `oracle.metadata.integrity`, which compares stored chunk tenant/ACL
  identity with the authoritative corpus document.
- A secured target refuses the mutation; a faulted target lets stored metadata
  drift.
- New tests in `tests/test_metadata.py`.

**`missing_source_freshness`**

- Added `ConfigurableRAGTarget.update_document(doc_id)`, which advances the
  source document version.
- Cache answers now record the cached document versions and the current document
  versions.
- Added `oracle.cache.freshness`, which flags cache reuse when the cached version
  no longer matches the current version.
- New tests in `tests/test_cache.py`.

The development scenario now includes a source-document update before revocation,
so the freshness check is actually exercised rather than only configured.

### 3.2 Held-out scenarios are real

New module: `src/redfence/bench/heldout.py`.

| Held-out family | What it does | Detected on vulnerable profile |
|---|---|---|
| `delegation.chain` | A delegated principal with only `docs.search` tries a `read_file` tool | `oracle.tool.policy` |
| `memory.poison.persistence` | Untrusted tool output is written to memory and recalled | `oracle.memory.scope` |
| `cache.semantic_similarity` | A normalized paraphrase replays the cache | `oracle.cache.key_scope`, `oracle.cache.leak` |
| `mcp.tool_scope` | A tenant principal tries a high-impact `http_post` without `net.egress` | `oracle.tool.policy` |

New runner: `scripts/run_heldout.py`. It writes JSON and HTML reports to
`reports/heldout/`.

Important limitation: the “semantic similarity” family is a deterministic
lexical-normalization approximation, not an embedding-based semantic cache. It
must not be described as true semantic-cache evaluation yet.

### 3.3 Clustered statistics

Added to `src/redfence/bench/metrics.py`:

- `clustered_bootstrap_ci(values, cluster_ids, ...)`
- `paired_cluster_bootstrap_difference(before, after, cluster_ids, ...)`

They resample whole clusters, not individual observations, and are deterministic
for a fixed seed. Tests are in `tests/test_metrics.py`.

The demo in `raw/25-next-step-audit.txt` returns `(0.0, 1.0)` from three tiny
clusters. That is a method demonstration, **not** a meaningful confidence
interval. N is still far too small for significance claims.

## 4. What is still left

These are the honest remaining gaps:

1. **G3 oracle validity — partial.** [Correction (0.2.0): this section is the
   pre-isolation snapshot. G3 was subsequently closed for **process** isolation
   (separate PID, frozen JSON snapshot), not for credential/service isolation;
   see §5 and the historical `isolation-and-statistics-report.md`.]
   The oracle now uses frozen observations and authoritative corpus ACLs, but
   target and oracle still share one Python process and in-memory store. A shared
   implementation error is not structurally excluded.
2. **G5 statistical validity — partial.** Clustered bootstrap exists, but there is
   still only one development scenario and four small held-out families. No
   significance claims are possible.
3. **G6 infrastructure isolation — partial.** No Docker/Postgres/pgvector run, no
   separate target service, separate credentials or network/egress boundary.
4. **G7 dataset split quality — improved but partial.** Four held-out families are
   executable, but the held-out set is small and the “semantic” cache family is a
   lexical approximation.
5. **G9 safety/containment — partial.** Tool runtime still uses an in-process
   simulated sink; real sandboxed egress has not been demonstrated.
6. **Deletion scope.** Deletion still does not exercise retention, replicas,
   backups or cache/memory propagation beyond the current in-memory target.

## 5. Current gate view

| Gate | Status | Why |
|---|---|---|
| G1 Metric correctness | PASS with limitations | metrics reconcile with oracles; proxy metrics and 0/0 denominators documented |
| G2 Discriminative validity | **PASS** | 10/10 development faults and 4/4 held-out families discriminate |
| G3 Oracle validity | **PASS (process isolation)** | oracles run in a separate PID from a frozen JSON snapshot; same OS user, no separate credential |
| G4 Reproducibility | PASS | deterministic tests and repeated runs |
| G5 Statistical validity | **PARTIAL (improved)** | clustered CIs per family × 25 seeds; target is deterministic so intervals are zero-width |
| G6 Infrastructure isolation | **PASS (fixture)** | executed Docker databases/credentials/internal networks; default run still in-process |
| G7 Dataset integrity and splits | **PARTIAL (improved)** | 4 executable held-out families; embedding-backed cache; still small |
| G8 Regression integrity | PASS | 79/79 tests; new regression tests; no tests skipped/weakened |
| G9 Safety and containment | **PASS (fixture)** | sandbox reaches only its DB + controlled sink; external egress blocked; tool runtime still in-process |

Overall decision remains **B. CONDITIONALLY READY**, but the specific blockers are
narrower than in Milestone 3: all configured faults and all declared held-out
families now execute; process/service isolation and statistical scale remain.

## 6. How to prompt efficiently from here

Useful short prompts:

- “Run the full suite and update the verification raw files.”  
  Expected commands: `.\.venv\Scripts\python.exe -m pytest -q --cov=redfence ...`
- “Run the development slice against all profiles and show the fault matrix.”  
  Expected command: `.\.venv\Scripts\python.exe scripts\run_vertical_slice.py --out reports\...`
- “Run the held-out families and report per-family results.”  
  Expected command: `.\.venv\Scripts\python.exe scripts\run_heldout.py --out reports\heldout`
- “Add real service/credential isolation for G6.”  
  This is the next substantial engineering task; it needs Docker/Postgres or a
  separate target process/service, not more documentation.
- “Audit the stats and produce confidence intervals per family.”  
  Use the clustered bootstrap helpers, but state clearly that N is small.

Avoid asking for “adaptive attacks” or “more features” until G6/G5 are addressed;
the benchmark should first prove it measures safely and statistically.

## 7. Files touched

- `src/redfence/targets/config.py` — all faults mapped to real oracles.
- `src/redfence/targets/rag_target.py` — document update, metadata mutation, cache
  version capture.
- `src/redfence/bench/scenario.py` — freshness and metadata probe steps.
- `src/redfence/bench/oracles.py` — freshness and metadata oracles.
- `src/redfence/bench/metrics.py` — clustered/paired bootstrap.
- `src/redfence/bench/heldout.py` — four executable held-out families.
- `scripts/run_heldout.py` — held-out execution and reports.
- Tests: `test_cache.py`, `test_metadata.py`, `test_heldout.py`,
  `test_metrics.py`, `test_discriminative_validity.py` (parametrization now 10 faults).
- Docs updated: `README.md`, `docs/benchmark-spec.md`, `docs/dataset-card.md`,
  `docs/engineering-report.md`, `docs/decisions/ADR-0005...`,
  `docs/standards/traceability.md`.

No commit, push, or PR was made.
