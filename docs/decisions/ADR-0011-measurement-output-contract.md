# ADR-0011: Measurement-output contract — deterministic artifacts and exit codes

Date: 2026-11-19
Status: **Accepted** (0.2.0, 2026-11-19)
Defect: D9, D10
Related: `core/evidence.py`, `core/domain.py`, `cli.py`, `scripts/*`, `README.md`

## Context

Two output claims are not true of the current code.

1. **Determinism.** The README says reports are "deterministic JSON + HTML"
   (`README.md:44`) and the architecture says replays reproduce the manifest
   "exactly (timestamps aside)" (`docs/architecture.md:80`). `Evidence.timestamp`
   and `CacheEntry.created_at` default to `datetime.now(timezone.utc)`. JSON
   evidence therefore differs on every run; the "timestamps aside" caveat
   concedes the claim. `test_reproducibility` compares outcomes and manifests, not
   report bytes, so the defect is untested.

2. **Exit codes.** `README.md:73-75` promises `0` pass, `1` confirmed regression,
   `2` inconclusive/unsupported for `demo`. `cli._cmd_demo` returns only `0` or
   `2`. `scripts/run_heldout.py` returns `2` when a secured profile fails (a
   confirmed security failure, which should be `1`). `bench/isolated.py` raises
   `RuntimeError`/`TimeoutExpired`; the CLI does not catch them, so the process
   exits `1` via a traceback (infrastructure failure, which should be `2`).

## Decision

### Deterministic logical clock

1. Add `src/redfence/core/clock.py`:

   ```python
   FIXED_INSTANT = datetime(2026, 1, 1, tzinfo=timezone.utc)  # logical epoch

   class Clock(Protocol):
       def now(self) -> datetime: ...

   class FixedClock:
       def now(self) -> datetime: return FIXED_INSTANT

   DEFAULT_CLOCK = FixedClock()
   ```

2. `Evidence.timestamp` and `CacheEntry.created_at` default to
   `DEFAULT_CLOCK.now`. Do **not** remove the fields (they are part of the public
   model and the JSON report); do **not** use `Field(exclude=True)` (it hides
   nondeterminism rather than removing it).
3. No per-run clock threading in 0.2.0. A caller that wants real timestamps can
   pass one explicitly; no current caller does.
4. `grep -R "datetime.now" src/` must return nothing after the change.

### Exit-code contract

One contract for every entry point:

- **0** — all applicable required checks pass.
- **1** — a confirmed security violation or regression. Specifically: a secured
  reference profile records `VIOLATION`, or a previously blocked case now
  succeeds.
- **2** — the measurement or statistics are invalid: `INCONCLUSIVE`,
  `UNSUPPORTED` where a required facet was expected, a failed discriminative
  check, a failed statistical separation, or an infrastructure/worker failure.

Per entry point:

| Entry point | 0 | 1 | 2 |
|---|---|---|---|
| `redfence run` | campaign exit 0 | campaign has a violation | campaign inconclusive/unsupported or worker error |
| `redfence demo` | G2 passes and secured is clean | secured has a violation | G2 fails, any campaign inconclusive/unsupported, or worker error |
| `scripts/run_heldout.py` | every family secured 0 / vulnerable 1 | any secured family has a violation | any family not discriminating, any exit 2, or an exception |
| `scripts/run_vertical_slice.py` | same as `demo` | same as `demo` | same as `demo` |
| `scripts/run_template_sweep.py` | all cells pass | any secured cell has a violation | any fault-detection cell fails |
| `scripts/run_statistics.py` | all rows separated | any secured mean > 0 | any row not separated / invalid |

5. `cli._cmd_run` and `_cmd_demo` catch `RuntimeError` and
   `subprocess.TimeoutExpired`, print a single `error=...` line and return `2`.
   Library callers still see the exception (do not swallow in `bench/`).
6. Scripts expose `main(argv: Sequence[str] | None = None)` so tests can call
   them without `sys.argv`; `__main__` passes `None`.

## Alternatives rejected

- **Remove timestamps.** The mandate explicitly asks for a virtual/seeded clock,
  not removal; evidence provenance benefits from a logical time.
- **Keep wall clock and add `generated_at` exclusion.** Partial determinism with a
  misleading field; two runs still differ in `evidence[].timestamp`.
- **Change the README to say `demo` returns only 0/2.** The README's 1-on-
  regression contract is the more useful one, and `CampaignResult.exit_code`
  already implements 1. Aligning the CLI is smaller than weakening the promise.
- **Return 2 for a secured violation in heldout.** That is a confirmed security
  failure; conflating it with "could not measure" hides the finding.
- **Catch exceptions inside `run_oracles_isolated` and return empty evidence.**
  That would turn an infrastructure failure into a vacuous result. Fail at the
  boundary (CLI/script) only.

## Migration impact

- All `Evidence.timestamp` values become `2026-01-01T00:00:00Z`; any consumer that
  ordered evidence by timestamp loses ordering (none in-repo; evidence order is
  list order).
- Report bytes change (also due to ADR-0007/0008/0009).
- `demo` failure paths can now return 1; heldout can return 1; infra errors return
  2 instead of 1.
- `test_oracle_isolation` changes its manifest assertion (ADR-0007).
- README and benchmark spec §7 are updated in the same release.

## Rollback

Revert the clock commit and the exit-code commit independently. Rolling back the
clock restores wall-clock timestamps and the old report bytes. Rolling back exit
codes restores 0/2 demo behaviour; the tests added for the new contract would
fail, which is the intended signal.

## Acceptance

Task contracts T4.1–T4.2: fixed timestamps, byte-identical report tests (in
process and subprocess), exception-to-2 tests, regression-to-1 tests, and docs
matching the table above.
