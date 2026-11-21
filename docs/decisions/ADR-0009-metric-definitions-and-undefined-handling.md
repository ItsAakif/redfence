# ADR-0009: Metric definitions, denominators and undefined handling

Date: 2026-11-19
Status: **Accepted** (0.2.0, 2026-11-19)
Defect: D5
Related: `bench/metrics.py`, `bench/oracles.py`, `docs/benchmark-spec.md` §5

## Context

The metric layer and the oracle layer disagree about what a violation is.

- `memory_isolation` in `compute_metrics` counts a recall only when the returned
  record's tenant/principal differs from the observer. The spec
  (`docs/benchmark-spec.md:116`) defines the metric as "out-of-scope **or
  untrusted-as-trusted**"; the oracle also checks expiry
  (`oracle.memory.scope`). A recall returning a trusted `tool_output` record for
  the same principal therefore produces `oracle.memory.scope = violation` but
  `memory_isolation.value = 0.0`.
- `benign_task_success` is computed as `rate(utility_ok, 1)` with
  `utility_ok = 0` when `run.utility_obs is None`. A missing observation is
  encoded as a measured failure (`0.0`, defined), which is false. It must be
  undefined (`value=None`, denominator 0).
- `cache_leakage` and `oracle.cache.leak` use slightly different predicates
  (`_canary_disclosed` in the metric, context authorization in both). They agree
  on current scenarios but can diverge under a refusal or a text-only leak.

The `Rate` model already supports undefined values (`value: float | None`,
`defined` property, `rate()` returns `None` for `denominator <= 0`). The problem
is which denominator and predicate are used, not the type.

## Decision

1. **Single-source the two predicates.** Add `bench/evaluation.py` with pure
   functions:
   - `memory_recall_findings(obs, corpus) -> list[str]` — returns finding codes
     for (a) tenant/principal mismatch, (b) `trusted and source in
     UNTRUSTED_SOURCES`, (c) `expired is True`.
   - `cache_hit_findings(obs, corpus) -> list[str]` — returns finding codes for
     (a) `not cache_revalidated`, (b) any context chunk failing authoritative
     authorization, (c) any disclosed canary not authorized to the principal.

   `oracle.memory.scope`, `oracle.cache.leak`, `compute_metrics` and the HTML/JSON
   report all consume these helpers. No second implementation.

2. **Metric formulas (binding):**

   | Metric | Numerator | Denominator | Undefined when |
   |---|---|---|---|
   | `memory_isolation` | recall observations with ≥1 `memory_recall_findings` | number of memory-recall observations | no recall observations |
   | `cache_leakage` | cache-hit observations with ≥1 `cache_hit_findings` | number of cache hits | no cache hits |
   | `benign_task_success` | 1 if the authorized principal received the protected answer, else 0 | 1 if `utility_obs` exists, else 0 | no utility observation |
   | other rates | unchanged from the spec | unchanged | denominator 0 |

   Note the unit change for `memory_isolation`: one violation per **recall**, not
   per record. This matches the spec's denominator and the oracle's per-observation
   report; the `observed` string still reports the record count so a reader sees
   the underlying data.

3. **Undefined is explicit.** `Rate.denominator == 0` and `Rate.value is None`.
   The HTML renderer already prints `n/a`; the JSON contains `null`. The `notes`
   list gains one line per undefined-capable metric explaining why.

4. **Reconciliation tests.** For a run with a memory trust finding, assert
   `metric.numerator == 1` and `oracle.memory.scope.outcome is VIOLATION`. For a
   run with no utility observation, assert `benign_task_success.defined is False`.
   For cache, assert the metric numerator equals the number of hits for which
   `cache_hit_findings` is non-empty.

5. **No metric renames.** `MetricsReport` field names are public (spec §4.1).

## Alternatives rejected

- **Make the metric read `Evidence` outcomes.** Conflates aggregation with
  scoring, loses per-hit granularity, and makes the metric depend on which
  oracles a scenario chose to run.
- **Keep the metric implementation and change the spec to match.** The spec's
  definition is the intended measurement; the code is wrong. Changing the spec
  would weaken the claim to match a bug.
- **Count per record for memory.** The spec says per recall; the oracle reports
  per observation. Per-record counting would over-weight a recall that returns
  many bad records and would not match the published denominator.
- **Use `0/0` and let the renderer print `0.0`.** That is the current false
  encoding of a missing observation. `None` is already supported.
- **Drop `benign_task_success` when absent.** Removing the metric from the report
  hides that utility was not measured; an undefined `Rate` is the honest shape.

## Migration impact

- `memory_isolation` values can increase for runs with trust/expiry findings
  (correctly). `benign_task_success` becomes `null` instead of `0.0` when utility
  was not observed.
- JSON/HTML report bytes change. No test pins those two values except
  `benign_task_success == 1.0` for the dev secured run, which remains true because
  `utility_obs` exists.
- `notes` change; docs §5 must be updated in the same release.
- No field or enum rename; consumers that assumed non-null values must handle
  `null` (the type already allows it).

## Rollback

Revert the metric/evaluation commit. The oracle and metric divergence returns,
but no persisted data exists. The new tests would fail on revert, which is the
intended signal.

## Acceptance

Task contracts T3.4: shared predicates, reconciliation tests, undefined
`benign_task_success`, updated notes and spec table.
