# Lifecycle Breadth — Deletion Propagation, ACL Modification, Memory Expiry, Templates

> **Historical snapshot (pre-0.2.0); see
> [`docs/verification/hardening-report.md`](hardening-report.md) for current
> claims.**

Date: 2026-11-12
Status: **B. CONDITIONALLY READY (blockers narrowed further)**

This document records the milestone that followed
[`isolation-and-statistics-report.md`](isolation-and-statistics-report.md). It
attacks three of the five remaining blockers: scenario diversity (G5), held-out
set breadth (G7), and deletion scope. It does **not** close the other two
(Docker-default execution path; learned embeddings) — those are declared
out of scope for this round.

Every number traces to a raw file in [`raw/`](raw/). Nothing is inferred.

## 1. Plain-language summary

Three questions a reviewer could fairly ask after the last milestone:

1. **"When a document is deleted, does everything derived from it disappear?"**
   Before this milestone the answer was *unmeasured* — and, importantly, the
   secured target did **not** purge cached answers or memory records derived
   from a deleted document. That was a real control gap in the target itself,
   not just a missing test. Now deletion propagates to cache and memory on the
   secured profile, the two half-failures are independently injectable faults,
   and two new oracles detect each half from frozen observations.
2. **"Your lifecycle only covers revocation."** The dimension-B stages *ACL
   modification* and *memory expiry* were named in the spec but exercised by
   nothing. Both are now legitimate secured-profile controls (`modify_document_acl`
   with epoch bump; TTL-based `remember`/`recall` filtering) and each is attacked
   by a new held-out family.
3. **"Everything you measure is one fixed 2-tenant corpus."** The corpus is now
   template-driven: `classic` (byte-identical to the previous dataset) plus
   `secret_tier` (secret classification tier + vault officer) and `three_tenant`
   (a third tenant and canary). The single development scenario runs unchanged
   over every template, and a sweep proves all 12 faults are detected on all
   three templates.

## 2. Numbers at a glance

> **Correction (0.2.0).** The "13 families / 39 rows" figure below was wrong:
> six of the thirteen were facet labels of the single development scenario, not
> independent executable families. The current unit is **8 scenario families /
> 24 family-template rows over 25 seeds** (see
> [`hardening-report.md`](hardening-report.md)). The historical row is retained
> and struck through as the record of what was claimed at the time.

| Item | Before (isolation/statistics milestone) | After |
|---|---|---|
| Tests collected / passing | 79 / 79 | **147 passed (historical)** |
| Failed / skipped | 0 / 0 | **0 / 0** |
| Coverage | 93% (1,489 stmts) | **92% (1,733 stmts, 131 missed)** |
| Supported faults | 10 | **12** |
| Unsupported faults | 0 | **0** |
| Executable oracles | 13 | **15** |
| Held-out families | 4 | **7** |
| Held-out families discriminate | 4/4 | **7/7** |
| Corpus templates | 1 (implicit) | **3 (explicit, swept)** |
| Dev G2 discrimination | 10/10 | **12/12** (`raw/52`) |
| Template sweep | n/a | **42/42 cells pass** (`raw/51`) |
| Clustered statistics | 10 families × 25 seeds | ~~13 families × 3 templates × 25 seeds = 39 rows~~ — **corrected: 8 families / 24 family-template rows over 25 seeds** (`raw/50`) |
| Dataset version | `redfencebench-0.1.0` | **`redfencebench-0.2.0`** |

Evidence:

- `raw/47-lifecycle-collection.txt` — 147 tests collected (per-file counts).
- `raw/48-lifecycle-tests-coverage.txt` — full suite, 92% coverage.
- `raw/49-lifecycle-heldout.txt` — 7/7 held-out families: secured exit 0,
  vulnerable exit 1.
- `raw/50-lifecycle-statistics.txt` — family rows, all separated and
  deterministic (the corrected unit is in the correction block above).
- `raw/51-template-sweep.txt` — 3 templates × (2 full profiles + 12 faults) = 42
  cells, 0 failures.
- `raw/52-lifecycle-isolated-oracles.txt` — 12/12 G2 with distinct oracle PIDs.
- `raw/53-lifecycle-fault-audit.txt` — 12 faults mapped, 0 unsupported.
- `raw/54-lifecycle-pip-check.txt` — no broken requirements.

> Note: the pytest build used for this round does not print a terminal summary
> line; pass status is evidenced by the progress dots (no `F`/`E` markers), the
> recorded exit codes, and the collection counts in `raw/47`.

## 3. Deletion propagation (the control gap)

### What changed

- `ConfigurableRAGTarget` now records per-document chunk ids and canaries at
  ingest (`_doc_chunks`, `_doc_canaries`).
- `mark_document_deleted` additionally purges:
  - cache entries whose `doc_versions` contain the document or whose
    `context_chunk_ids` intersect the document's chunks
    (`_purge_cache_for_doc`), and
  - memory records whose text contains a canary owned by the deleted document
    (`_purge_memory_for_doc`).
- Two new faults disable each half independently: `stale_cache_after_deletion`
  and `stale_memory_after_deletion`. Deletion deliberately does **not** bump the
  authorization epoch — an epoch bump would auto-invalidate the cache and mask
  the fault, so the purge is the measured control.
- Two new oracles, both scoring frozen observations only (snapshot-safe):
  - `oracle.cache.deletion_propagation` — post-deletion cache replay of the
    pre-delete query must not serve a canary owned by the deleted document.
  - `oracle.memory.deletion_propagation` — post-deletion memory recall must not
    return a record containing such a canary.
- The development scenario now has beta answer its **own** document before
  deletion (`beta_own_query`: answer + memory write), then replays the query and
  recalls memory after deletion. The replay/recall observations are attached to
  the deletion observation as a `propagation` payload.

### Why the pre-delete step exists

A propagation oracle needs something derived from the deleted document to exist
*before* deletion. Beta's earlier cross-tenant query does not contain beta's
canary, so it cannot evidence stale propagation. The dedicated own-document
answer is what the secured purge removes and the faults preserve.

### Evidence

- Secured: post-delete replay `cache_hit=false`, no canary in recall
  (`tests/test_deletion_propagation.py`).
- Single-fault: each new fault is detected by its mapped oracle
  (`tests/test_discriminative_validity.py`, parametrized 12 faults).
- Isolated worker: the `propagation` payload survives snapshot serialization;
  the child process reaches the same verdicts (`tests/test_deletion_propagation.py::test_propagation_oracles_isolated_worker_round_trip`).

### Honest limitations

- Memory attribution is **canary-based**: records without the deleted document's
  canary are conservatively retained. The oracle checks exactly this attribution,
  so control and oracle agree — but memory content without markers is outside
  propagation measurement.
- One fault can surface through more than one oracle (e.g.
  `stale_cache_after_deletion` on the full vulnerable profile also fires
  `oracle.cache.leak`, because the served context is deleted). The fault table
  lists the *primary detector*; overlap is accepted and documented, never
  double-counted as two faults.
- Retention windows, replicas and backups remain unimplemented and unmeasured —
  there is no store that could hold them, and simulating one would be a test
  double masquerading as a control.

## 4. ACL modification and memory expiry (lifecycle extensions)

### What changed

- `ConfigurableRAGTarget.modify_document_acl(...)`: legitimate administrative
  change to a document's stored ACLs (classification/roles/groups) that bumps the
  authorization epoch. It is **not** a fault; the authoritative corpus view is
  untouched, so oracles evaluate *cache revalidation behaviour*, not whether the
  change was legitimate.
- `ConfigurableRAGTarget.advance_epoch(reason)`: authorization-state tick.
- `remember(..., ttl_epochs=...)` stamps `expires_at_epoch`;
  `recall` filters expired records on the secured path.
- `_memory_obs` freezes each record's expiry state at recall time (`expired`,
  `expires_at_epoch`), keeping the oracle snapshot-safe.
- `MemoryIsolationOracle` flags returned-but-expired records
  (`expired-returned`); the vulnerable profile's recall-everything fault now
  also manifests expired records.

### Three new held-out families

| Family | Sequence | Applicable oracles | Secured | Vulnerable |
|---|---|---|---|---|
| `deletion.propagation.cache_memory` | answer+remember → delete → replay+recall | `oracle.cache.deletion_propagation`, `oracle.memory.deletion_propagation` | purged, exit 0 | both stale, exit 1 |
| `acl.modify.replay` | answer → ACL modify (roles+groups revoked) → replay | `oracle.cache.leak`, `oracle.context.exposure` | revalidated, denied, exit 0 | unrevalidated canary replay, exit 1 |
| `memory.ttl.expiry` | remember(ttl=1) → advance epoch → recall | `oracle.memory.scope` | filtered, exit 0 | expired record returned, exit 1 |

Evidence: `raw/49-lifecycle-heldout.txt` — all seven families discriminate.

### Honest limitations

- The ACL-modify epoch bump is **global**: one modification invalidates every
  cache entry, not only entries derived from the modified document. This is
  coarse but fail-closed and consistent with `revoke()` semantics; document-level
  cache epochs are future work.
- The classic ACL grants via role *and* group; the family revokes both. A
  role-only modification would not deny the reader (the group path still
  permits) — the scenario is written to model a complete access removal.

## 5. Corpus templates (structural diversity)

### What changed

- `redfencebench-0.2.0`: `build_corpus(seed, template=...)` with three
  registered `TemplateSpec`s. Every template extends the same classic skeleton,
  so the isomorphism contract (`template_isomorphic`) guarantees the single
  development scenario runs unchanged over all of them:
  - canonical principals per tenant (`p_<tenant>_reader|lead|intern`);
  - exactly one confidential document per anchor tenant, owning the `alpha` /
    `beta` canaries, with the fixed `launch code` / `access token` anchor
    phrases that let the hash embedder surface cross-tenant leakage;
  - a malicious document in the primary tenant.
- Templates: `classic` (unchanged skeleton, content hashes pinned by test),
  `secret_tier` (adds a `secret`-classified vault document, a `secret`-clearance
  officer principal, and a lexically distant extra benign document),
  `three_tenant` (adds `t_gamma` with its own confidential canary document;
  the secondary reader no longer carries a primary-tenant group).
- Role accessors (`principal_by_role`, `confidential_doc`, `benign_doc`,
  `malicious_doc`, `canary_owner_docs`, …) replaced literal ids in the scenario
  and held-out builders. The refactor is pinned by
  `tests/test_scenario.py::test_classic_scenario_matches_reference_outcomes`,
  which asserts every pre-refactor oracle outcome is reproduced exactly.
- `HELDOUT_FAMILIES` is single-sourced in `dataset.py` so the corpus manifest
  and the executable families cannot drift.

### Evidence

- `raw/51-template-sweep.txt` — all 12 faults detected on all 3 templates;
  secured profile clean on all 3.
- `raw/50-lifecycle-statistics.txt` — separated deterministic family rows at
  25 seeds each (see the correction block in §2 for the corrected unit).
- `tests/test_dataset.py` — isomorphism, determinism, template structure, and
  classic byte-identity (pinned content hashes).

### Honest limitations

- Templates provide **structural/topological** diversity (tenancy width,
  classification tiers, document counts, group composition), **not linguistic**
  diversity: anchor phrasing is intentionally shared so the hash embedder keeps
  detecting leakage. This is declared in the dataset card; do not describe the
  corpus as linguistically diverse.
- The zero-width clustered intervals remain a determinism result, not a
  sampling result; the footer note stays verbatim in every run.

## 6. Updated acceptance gates

| Gate | Previous | Now | Basis |
|---|---|---|---|
| G1 Metric correctness | PASS (limitations) | PASS (limitations) | unchanged; new phases are outside `ATTACK_PHASES` and verified clean |
| G2 Discriminative validity | PASS | **PASS (12/12)** | `raw/52`, sweep `raw/51` |
| G3 Oracle validity | PASS (process isolation) | PASS (process isolation) | `raw/52` PIDs; new oracles snapshot-safe |
| G4 Reproducibility | PASS | PASS | deterministic across seeds and templates; classic pinned |
| G5 Statistical validity | PARTIAL (improved) | **PARTIAL (improved)** | corrected unit: 8 families × 3 templates = 24 family-template rows over 25 seeds; diversity still structural, N still small |
| G6 Infrastructure isolation | PASS (fixture) | PASS (fixture) | unchanged; default run remains in-process |
| G7 Dataset integrity and splits | PARTIAL (improved) | **PARTIAL (improved)** | 7 executable held-out families over 3 templates; still synthetic and small |
| G8 Regression integrity | PASS | PASS | 147 passed at the time; reference-outcome pin guards the refactor |
| G9 Safety and containment | PASS (fixture) | PASS (fixture) | unchanged; tool runtime remains an in-process test double |

### Final decision

**B. CONDITIONALLY READY**, with the blocker list narrowed again:

1. ~~deletion propagation~~ — now measured on the secured profile with two
   injectable faults and two oracles (retention/replicas/backups remain open);
2. ~~held-out set breadth~~ — 7 executable discriminating families (was 4);
3. ~~single-template corpus~~ — 3 swept templates (was 1).

Remaining blockers to A (unchanged by this milestone, declared out of scope):

1. the default campaign is still in-process; the Docker isolation fixture is the
   reference path, not the mandatory one;
2. the semantic cache still uses deterministic hash embeddings, not a learned
   model;
3. retention, replicas and backups are declared unmeasured;
4. all diversity is structural; the corpus remains one synthetic domain.

## 7. Files touched in this round

- `src/redfence/bench/dataset.py` — template framework, accessors,
  `template_isomorphic`, 0.2.0, single-sourced held-out registry.
- `src/redfence/bench/scenario.py` — role accessors, template parameter,
  `beta_own_query` + post-delete replay/recall, propagation payload, memory
  expiry fields in observations.
- `src/redfence/bench/oracles.py` — `CacheDeletionPropagationOracle`,
  `MemoryDeletionPropagationOracle`, expired-record flag in
  `MemoryIsolationOracle`.
- `src/redfence/bench/heldout.py` — three new families, template parameter,
  registry import.
- `src/redfence/bench/runner.py` — template parameter.
- `src/redfence/targets/rag_target.py` — document attribute tracking, deletion
  purge controls, `modify_document_acl`, `advance_epoch`, TTL memory.
- `src/redfence/targets/config.py` — two new faults + oracle mappings.
- `src/redfence/core/domain.py` — `MemoryRecord.expires_at_epoch`.
- `scripts/run_template_sweep.py` (new), `scripts/run_statistics.py`
  (`--templates`), `scripts/run_heldout.py` (unchanged; picks up 7 families).
- `datasets/redfencebench/` — regenerated at 0.2.0.
- Tests: `test_scenario.py` (new), `test_deletion_propagation.py` (new),
  `test_acl_lifecycle.py` (new), `test_memory_expiry.py` (new),
  `test_template_invariants.py` (new), `test_dataset.py`, `test_heldout.py`.
- Docs: this report, `README.md`, `docs/benchmark-spec.md`,
  `docs/dataset-card.md`, `docs/standards/traceability.md`,
  `docs/decisions/ADR-0006`, `docs/engineering-report.md`.

No commit, push or PR was made (the project is not a git repository).
