# Isolation, Statistics and Containment — Closing the Five Gaps

> **Historical snapshot (pre-0.2.0); see
> [`docs/verification/hardening-report.md`](hardening-report.md) for current
> claims.**

Date: 2026-11-10
Status: **B. CONDITIONALLY READY (narrower blockers)**

This document records the work that followed
[`next-steps-report.md`](next-steps-report.md). It addresses the five remaining
verification gaps: G3 (oracle process isolation), G5 (statistical scale), G6
(infrastructure/credential/network isolation), G7 (a real embedding-backed
semantic cache case), and G9 (real egress containment).

Every number here traces to a raw file. Nothing was inferred.

## 1. Plain-language summary

The benchmark already worked, but a reviewer could still ask five fair questions:

1. **G3 — "Is the oracle really independent, or does it just agree with a bug in
   the target?"** Now the oracles can run in a *separate operating-system
   process*. The parent sends a frozen JSON snapshot; the child cannot see or
   mutate the parent's live objects. Evidence: two different PIDs.
2. **G5 — "Are your intervals trustworthy?"** Clustered confidence intervals now
   run per family across 25 dataset seeds. The honest result is that the
   deterministic target is *invariant across seeds*: every interval is
   zero-width. That is a strong determinism result, but it is **not** a
   human-sample variance result, and the report says so.
3. **G6 — "You keep saying 'two trust domains' — prove it."** Docker now runs
   two separate PostgreSQL/pgvector databases with separate users and separate
   internal networks. Cross-credential and cross-network probes both report
   isolation OK.
4. **G7 — "Your 'semantic' cache was just string normalization."** The held-out
   semantic-cache family now uses embedding vectors and cosine similarity.
5. **G9 — "Containment is simulated."** The target container can reach its own
   database and the controlled sink, but **cannot resolve the platform database
   and cannot reach the public internet** (`external_reachable=false`).

The important nuance: these are now **executed isolation fixtures and an
executed separate-process oracle**, not just architecture diagrams. The default
`redfence run` path still executes in-process for determinism, so the fixture is
the reference isolation path, not yet the only execution path.

## 2. Numbers at a glance

| Item | Before (next-steps report) | After |
|---|---|---|
| Tests collected / passed | 75 / 75 | **79 / 79** |
| Failed / skipped | 0 / 0 | **0 / 0** |
| Wall-clock pytest run | 2.49 s | **1.08 s** |
| Coverage | 93% | **93%** (1,489 statements, 110 missed) |
| Supported faults | 10 | **10** |
| Unsupported faults | 0 | **0** |
| Dev G2 discrimination | 10/10 | **10/10** |
| Held-out families executable | 4 | **4** |
| Held-out families discriminate | 4/4 | **4/4** |
| Oracle process separate from target | no | **yes** (`oracle_pid != parent_pid`) |
| Docker isolation fixture executed | no | **yes, all checks pass** |
| External egress from sandbox blocked | not demonstrated | **yes (`false`)** |
| Semantic cache uses embeddings | no (lexical) | **yes (deterministic embedding + cosine)** |
| Clustered CI per family | method only | **10 families × 25 seeds** |

Evidence:

- `raw/40-final-tests.txt` — pytest + coverage, 93%.
- `raw/45-final-test-summary.txt` — 79 collected.
- `raw/46-final-pytest-summary.txt` — **79 passed in 1.08 s**.
- `raw/41-final-statistics.txt` — 10 families × 25 seeds, clustered CIs.
- `raw/42-final-heldout.txt` — 4/4 held-out families discriminate.
- `raw/43-final-isolated-oracles.txt` — separate oracle PIDs.
- `raw/35-infrastructure-isolation.txt` — Docker version, compose hash, all
  isolation checks and the sandbox probe.
- `raw/44-final-pip-check.txt` — no broken requirements.

## 3. G3 — Oracle process isolation

### What changed

- New `src/redfence/bench/isolated.py`:
  - `serialize_run(run)` freezes the corpus, target metadata, cache, chunks,
    tools and every observation into JSON.
  - `run_oracles_isolated(run)` spawns
    `python -m redfence.bench.oracle_worker`, pipes the snapshot over stdin and
    reads typed evidence back.
- New `src/redfence/bench/oracle_worker.py`: reconstructs a read-only snapshot
  (`SnapshotStore`, `SnapshotTools`, `SnapshotTarget`) and recomputes every
  oracle from it.
- `runner.run_campaign(..., isolated_oracles=True)` and the CLI flag
  `--isolated-oracles` on `redfence run` and `redfence demo`.
- The run manifest records `oracle_pid` when isolation is used.

### Why it matters

Before, a target bug could in principle corrupt the same objects the oracle
reads. Now the oracle child only sees a serialized snapshot. It cannot call
`target.answer()` or read live mutable state.

### Real evidence

`raw/43-final-isolated-oracles.txt`:

```
parent_pid=20516
profile=secured exit=0 parent_pid=20516 oracle_pid=8420  separate_process=True
profile=vulnerable exit=1 parent_pid=20516 oracle_pid=13676 separate_process=True
```

Regression coverage:

- `tests/test_oracle_isolation.py::test_oracle_runs_in_a_separate_process`
- `tests/test_oracle_isolation.py::test_isolated_oracle_detects_vulnerable_profile`
- `tests/test_oracle_isolation.py::test_worker_reconstructs_typed_tool_executions`
  (this test found and now guards a real defect: the worker used to pass raw
  dicts where `ToolPolicyOracle` expected `ToolExecution` objects).

### Honest limitation

The child runs as the same OS user on the same machine, with the same
filesystem access. It is *process* isolation, not *credential* or *service*
isolation. A future step is to run the oracle behind its own service identity
and database credential. G3 is therefore **PASS for process isolation, partial
for credential isolation**.

## 4. G6 — Infrastructure, credential and network isolation

### What changed

`docker-compose.yml` now defines:

| Service | Purpose | Network |
|---|---|---|
| `platform-db` | RedFence platform PostgreSQL + pgvector, user `redfence_platform` | `platform` (internal) |
| `sut-db` | system-under-test PostgreSQL + pgvector, user `redfence_sut` | `sut` (internal) |
| `platform-check` | proves platform user cannot use SUT credentials and cannot resolve `sut-db` | `platform` |
| `sut-check` | proves SUT user cannot use platform credentials and cannot resolve `platform-db` | `sut` |
| `sink` | controlled egress sink (`http.server`) | `egress` (internal) |
| `target-sandbox` | target-side probe with a read-only mounted volume | `sut` + `egress` |

All three networks are `internal: true`. That was a real correction: in the first
run the sandbox was also on a non-internal network and `external_reachable` was
`true`. Marking both trust-domain networks internal fixed the boundary.

`scripts/run_infrastructure_isolation.py` brings the services up, runs the three
checks, prints the sink log, and tears everything down.

### Real evidence

`raw/35-infrastructure-isolation.txt` (Docker Desktop 4.90.0, engine 29.7.2,
compose file SHA-256 `9326098370653186EBF680BC1ABA066821CAA84F07BE55941E5D9D680BBF6A57`):

```
PLATFORM_CREDENTIAL_ISOLATION_OK
PLATFORM_NETWORK_ISOLATION_OK
SUT_CREDENTIAL_ISOLATION_OK
SUT_NETWORK_ISOLATION_OK
{"external_reachable": false, "platform_db_connects": false,
 "platform_db_resolves": false, "sink_reachable": true, "sink_status": 200,
 "sut_db_connects": true, "sut_db_resolves": true}
sink-1 | 172.23.0.3 - - [...] "GET / HTTP/1.1" 200 -
infra_exit=0
```

So: each domain reaches only its own database; neither can use the other's
credentials; the target reaches the controlled sink; the target cannot reach the
platform database; the target cannot reach the public internet.

### Honest limitation

The passwords in `docker-compose.yml` (`change_me_*`) are **fixtures, not
secrets**. This demonstrates topology and credential separation, not production
secret management. Also, the default `redfence run` path still runs in-process;
the isolation fixture is the reference deployment, not yet the mandatory one.

## 5. G9 — Containment

G9 is now demonstrated at the container-network level by the same fixture:

- the target container can reach `sut-db:5432` and `sink:8080`;
- it cannot resolve `platform-db`;
- it cannot reach `example.com` (`external_reachable=false`);
- the only captured egress is the controlled sink request.

This is real egress containment, not an in-process list. The synthetic tool
runtime in unit tests still writes to an in-process sink for determinism; that is
a test double, and the report no longer claims it is the containment boundary.

## 6. G5 — Statistics with clustered intervals

### What changed

- `run_campaign(..., seed=...)` and `run_heldout_scenario(..., seed=...)` can
  vary the corpus seed (canaries/content) without changing the control logic.
- New `scripts/run_statistics.py`:
  - runs all 6 development families and all 4 held-out families;
  - uses 25 seeds per family (25 clusters);
  - resamples whole seeds with `clustered_bootstrap_ci` and
    `paired_cluster_bootstrap_difference`;
  - reports secured mean, vulnerable mean, their CIs, the paired difference CI,
    and whether the family is separated and deterministic across seeds.
- New regression test in `tests/test_reproducibility.py` confirms a different
  seed changes the corpus/canaries while preserving the control outcome.

### Real evidence

`raw/41-final-statistics.txt`:

```
families=10 separated=10 all_deterministic=True
note: zero-width intervals mean the deterministic target is invariant across seeds;
they are not evidence of a zero-variance human sample.
```

Every family reports `secured=0.00 ci=[0.00,0.00]`,
`vulnerable=1.00 ci=[1.00,1.00]`, `difference=1.00 ci=[1.00,1.00]`.

### Honest interpretation

This is a *determinism* result, not a *sampling* result. Changing the seed
changes the canaries but not the control decisions, so the clustered intervals
collapse. The remaining G5 limitation is **scenario diversity**, not the
statistics code: there is still one synthetic corpus template and one
authorization-state lifecycle. Do **not** cite these intervals as evidence of
low variance in real deployments.

## 7. G7 — Embedding-backed semantic cache

### What changed

- `ConfigurableRAGTarget` gained `semantic_cache`, `semantic_threshold`, a
  `DeterministicEmbedder`, `_find_semantic_entry()`, and cosine similarity,
  filtered by tenant and entitlement fingerprint.
- The `cache.semantic_similarity` held-out family now pairs
  `"nimbus launch code"` with `"what is the nimbus launch code"` and asserts a
  cache hit **with revalidation** on the secured profile.
- `tests/test_heldout.py` asserts `cache_hit is True` and
  `cache_revalidated is True` for the replay.

### Honest limitation

`DeterministicEmbedder` is a hash-based deterministic vector, not a learned
neural embedding model. It is a genuine vector-space cosine cache, but it should
not be described as evaluating a production semantic-cache model. The held-out
set is still four small families over one corpus.

## 8. Updated acceptance gates

| Gate | Previous | Now | Basis |
|---|---|---|---|
| G1 Metric correctness | PASS (limitations) | **PASS (limitations)** | unchanged proxy/denominator caveats |
| G2 Discriminative validity | PASS | **PASS** | 10/10 dev faults + 4/4 held-out, `raw/42` |
| G3 Oracle validity | PARTIAL | **PASS (process isolation)**; credential isolation partial | separate PID + frozen snapshot, `raw/43` |
| G4 Reproducibility | PASS | **PASS** | 79/79 deterministic; seed test added |
| G5 Statistical validity | PARTIAL | **PARTIAL (improved)** | clustered CIs per family × 25 seeds; deterministic zero-width |
| G6 Infrastructure isolation | PARTIAL | **PASS (fixture)**; default path partial | executed Docker checks, `raw/35` |
| G7 Dataset integrity and splits | PARTIAL | **PARTIAL (improved)** | 4 executable families, embedding cache; small N |
| G8 Regression integrity | PASS | **PASS** | 79/79, no skips/weakening; worker regression test |
| G9 Safety and containment | PARTIAL | **PASS (fixture)**; tool-runtime path partial | external egress blocked, `raw/35` |

### Final decision

**B. CONDITIONALLY READY**, with narrower blockers than before.

The architecture and the isolation/statistics machinery are now exercised, not
just designed. The benchmark is still not *broadly* research-ready because:

1. the default campaign is in-process; the Docker isolation fixture is not yet
   the only execution path;
2. G5 has real statistics machinery but only one synthetic corpus template;
3. the held-out set is four small families;
4. the semantic cache uses deterministic hash embeddings, not a learned model;
5. deletion still does not cover retention, replicas, backups or full
   cache/memory propagation.

Closing those would justify moving from **B** to **A**; the work above does not
yet justify that move.

## 9. Files touched in this round

- `src/redfence/bench/isolated.py` (new), `src/redfence/bench/oracle_worker.py`
  (new) — process-isolated oracle scoring.
- `src/redfence/targets/tools.py` — `all_specs()`.
- `src/redfence/bench/runner.py` — `isolated_oracles`, `oracle_pid`, `seed`.
- `src/redfence/bench/heldout.py` — seed support, semantic cache enablement.
- `src/redfence/targets/rag_target.py` — embedding-backed semantic cache.
- `src/redfence/cli.py` — `--isolated-oracles`.
- `scripts/run_statistics.py` (new), `scripts/run_infrastructure_isolation.py`
  (new), `docker/target/sandbox_probe.py` (new).
- `docker-compose.yml` — two domains, three internal networks, sink, sandbox.
- Tests: `tests/test_oracle_isolation.py` (new), `tests/test_heldout.py`,
  `tests/test_metrics.py`, `tests/test_reproducibility.py`.
- Docs: this report, `next-steps-report.md`, `milestone-3-report.md`,
  `docs/benchmark-spec.md`, `docs/engineering-report.md`, `README.md`.

No commit, push or PR was made.
