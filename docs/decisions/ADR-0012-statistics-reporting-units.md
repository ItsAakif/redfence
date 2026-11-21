# ADR-0012: Statistics reporting units — scenarios, not facet labels

Date: 2026-11-19
Status: **Accepted** (0.2.0, 2026-11-19)
Defect: D4
Related: `scripts/run_statistics.py`, `bench/dataset.py`,
`docs/verification/lifecycle-breadth-report.md`

## Context

`scripts/run_statistics.py` iterates `list(DEV_FAMILIES) + list(HELDOUT_FAMILIES)`
(13 names). For every name in `DEV_FAMILIES`, `_run` calls the same
`run_campaign(profile, seed, template)` — the single permission-revocation
scenario. The six dev labels therefore produce six identical rows per template
and seed. The "13 families × 3 templates × 25 seeds = 39 rows" claim is really
"7 held-out families + 6 copies of one dev scenario".

The dev labels are **facets** of one scenario (`revocation.same_query`,
`revocation.paraphrase`, `cache.revalidate`, `tenant.isolation`,
`tool.authorization`, `deletion.cascade`), not independent executable scenarios.
Counting them as families overstates breadth and makes the "all separated" result
true by construction (the vulnerable dev campaign violates somewhere, so every
copy separates).

A second honesty problem: `_outcome` returns `1.0` iff any oracle reports
`VIOLATION`, else `0.0`. An inconclusive/unsupported campaign is encoded as a
clean `0.0`, so the statistics layer can report separation when it did not
measure.

## Decision

1. **The statistics unit is an executable scenario, not a label.**
   `STATISTICS_FAMILIES = ("revocation",) + HELDOUT_FAMILIES` — 8 unique names.
   `"revocation"` maps to `run_campaign`; the other seven map to
   `run_heldout_scenario`.

2. **`DEV_FAMILIES` stays as documented facet labels.** It is not renamed in
   0.2.0 (owner question Q6); its comment and docs say "facets of the single
   revocation scenario". New code uses `DEV_FACETS = DEV_FAMILIES` if a clearer
   name is needed.

3. **No label is counted twice.** A test asserts the statistics list has no
   duplicates and is disjoint from `DEV_FAMILIES`.

4. **Inconclusive is not clean.** `_outcome` returns `None` for a campaign with
   `has_inconclusive` (any `INCONCLUSIVE` or `UNSUPPORTED` evidence).
   `FamilyStatistic` gains `evaluable: bool` and `evaluable_clusters: int`;
   means are over evaluable clusters; `separated` requires all clusters evaluable
   and the 0.0/1.0 means; an unevaluable row forces exit 2.

5. **Output states the unit.** The footer says "8 scenario families; the six dev
   facet labels are facets of one scenario and are not independent samples." The
   zero-width-interval note stays.

6. **Exit code.** 1 if any secured mean > 0 (confirmed secured regression);
   2 if any row is unevaluable or not all rows separate; 0 otherwise.

## Alternatives rejected

- **Keep six dev labels and add a caveat.** The number "13 families" is the
  claim; a caveat in a footer does not fix the table or the summary line.
- **Map each dev label to a facet-specific predicate.** That would make the rows
  meaningful but still not independent scenarios; the statistics still has one
  dev scenario. It is a reasonable future extension, not the minimal honest fix.
- **Drop the dev scenario entirely and report only held-out families.** Loses the
  reference scenario that anchors G2 and the secured/vulnerable comparison.
- **Treat `UNSUPPORTED` as 0.0.** That is the current overstatement; an
  unevaluable row must not count as a clean pass.
- **Run 25 seeds of a deterministic target and call it variance.** The report
  already says zero-width intervals are a determinism result, not a sample; keep
  that wording.

## Migration impact

- Output shrinks from 39 rows to 24 at `--templates` (8 × 3). The summary line
  says `families=8` per template.
- `FamilyStatistic` gains two fields (script-local; no public package API).
- Docs that cite 13/39 must be corrected or explicitly retracted (T6.1/T6.2).
- No change to the bootstrap functions or their inputs beyond the family set.

## Rollback

Revert the script and docs correction. The duplicate rows return; no persisted
data depends on them. The new tests would fail on revert.

## Acceptance

Task contract T3.5: 8 unique families, distinct scenario ids, no dev-label
duplication, unevaluable handling, and the documented exit codes.
