# RedFence 0.2.0 — Measurement-Core Hardening Report

Status: **current source of truth for 0.2.0 verification claims.**
Date: 2026-11-19.
Companion records: [`docs/decisions/`](../decisions/) (accepted ADRs) and
[`raw/`](raw/) (immutable captures).

This report replaces the historical claims in
[`isolation-and-statistics-report.md`](isolation-and-statistics-report.md),
[`next-steps-report.md`](next-steps-report.md),
[`lifecycle-breadth-report.md`](lifecycle-breadth-report.md) and
[`milestone-3-report.md`](milestone-3-report.md) for the 0.2.0 release. Those
documents remain as the historical record and carry a banner pointing here.

Every current number below traces to a `raw/60-*` … `raw/69-*` capture. A claim
without such a capture is **NOT VERIFIED** (see §9).

## 1. Scope and non-goals

In scope:

1. Correctness defects that could make a measurement wrong or an artifact
   unreproducible (D1, D8, F1).
2. Provenance: one scenario identity tuple, corpus digest, reproducible manifest
   (D2, D3).
3. Honest measurement: oracle vacuity, metric definitions, statistics units,
   exit codes (D4–D7, D9, D10).
4. Release hygiene: lint, types, CI workflow, installability (D11).
5. Documentation that matches the code (D12).

Explicit non-goals:

- **No Docker work.** No new containers, networks, credentials or isolation
  claims. `docker/`, `docker-compose.yml`, G6 and G9 are historical fixtures.
- No new providers, embeddings, LLMs, MCP, orchestration, persistence,
  dashboards or adaptive attacks.
- No new scenario families, templates, faults or oracles beyond the hardening of
  the existing surface (1 development scenario, 7 held-out families, 3 templates,
  12 faults, 15 oracles).
- No production hardening (auth, deployment, HA, migrations).

## 2. Defect register D1–D12

Status meanings: **fixed** — code/test evidence exists in this release;
**deferred** — acknowledged, not addressed; **not applicable** — no longer a
defect in this surface.

| ID | Severity | Defect | Status | Evidence pointer |
|---|---|---|---|---|
| D1 | HIGH | Semantic-cache invalid path deleted an absent exact key → `KeyError` | fixed | `src/redfence/targets/rag_target.py:438` (`self.cache.pop(entry.key, None)`); `tests/test_cache.py:226` |
| D2 | HIGH | `scenario_id` was profile+seed only → collisions across templates, kinds and custom faults | fixed | `src/redfence/bench/dataset.py:515`; distinctness tests `tests/test_reproducibility.py:53-78` |
| D3 | HIGH | Run manifest omitted template and per-document content hashes; PID contradicted reproducibility | fixed | `src/redfence/bench/runner.py:66-81`; `tests/test_reproducibility.py:85`; `tests/test_dataset.py:130` |
| D4 | HIGH | Statistics ran the same dev campaign for six dev facet labels; "13 families" = 6 copies + 7 real | fixed | `scripts/run_statistics.py:142-149`; [`raw/65`](raw/65-hardening-statistics.txt) |
| D5 | HIGH | `memory_isolation` missed untrusted-as-trusted and expiry; `benign_task_success` was 0.0 instead of undefined | fixed | `src/redfence/bench/evaluation.py:77,99`; `src/redfence/bench/metrics.py:259-264` |
| D6 | MED | Oracles returned vacuous `SATISFIED` with zero evaluable observations | fixed | `src/redfence/bench/oracles.py:63` (`_verdict`); `tests/test_oracle_vacuity.py:150` |
| D7 | MED | `FaultFlags` ↔ `FAULT_ORACLE` coverage was not test-enforced | fixed | `tests/test_fault_coverage.py:52-73` |
| D8 | MED | Global ACL epoch invalidated all cache entries; `modify_document_acl` returned `True` for a nonexistent document | fixed | `src/redfence/targets/rag_target.py:145-190` |
| D9 | MED | Reports claimed deterministic but evidence/cache timestamps were wall-clock | fixed | `src/redfence/core/clock.py:15`; `tests/test_reports.py:43` |
| D10 | MED | Exit-code contract inconsistent across entry points | fixed | `src/redfence/cli.py:38-64`; `scripts/run_heldout.py:14-51`; `tests/test_cli_exit_codes.py:34`; `tests/test_script_exit_codes.py:91` |
| D11 | MED | Lint/type hygiene: 13,723 repo-wide ruff errors, 55 scoped, 61 mypy errors; no CI | fixed | [`raw/67`](raw/67-hardening-ruff.txt); [`raw/68`](raw/68-hardening-mypy.txt); `.github/workflows/ci.yml` |
| D12 | LOW | Docs: broken licence link, stale held-out wording, G3 contradiction, stale counts, generator emitted only `classic` | fixed | `datasets/redfencebench/generator.py:46`; [`README.md`](../../README.md); [`docs/verification/README.md`](README.md) |

No defect in D1–D12 is deferred. The remaining limits are design trade-offs,
listed in §10; they are not unresolved defects from this register.

## 3. Security finding F1 — semantic cache was not principal-scoped

**Finding (HIGH, pre-existing).** Semantic-cache reuse filtered by tenant and
entitlement fingerprint only. `_find_semantic_entry` did not require the cached
entry to belong to the requesting principal, and `_cache_valid` ignored principal
identity and revoked status. A principal could therefore receive a peer's cached
answer even when that peer's authorization state differed.

**Before (reproduction from the Tranche-1.3 review, 2026-11-19).** Prime the
semantic cache as `p_alpha_lead` with `nimbus launch code`, revoke
`p_alpha_reader`, then have the revoked reader ask the paraphrase
`what is the nimbus launch code`. The pre-fix target returned the lead's cached
answer with `cache_hit=True` and the alpha canary present, because the entry
matched tenant and entitlement fingerprint. The exact-key path was already safe:
its key includes `principal.id`.

**After (fix).** Cache entries are principal-bound, and a revoked requester is
never served from cache:

- `_find_semantic_entry` skips entries with no `principal_id` or a different
  `principal_id` (`src/redfence/targets/rag_target.py:308-327`).
- `_cache_valid` rejects a mismatched principal and a revoked principal
  (`src/redfence/targets/rag_target.py:332-339`).

The post-fix behaviour is pinned by
`tests/test_cache.py:251` — the revoked reader gets `cache_hit is False`,
`cache_revalidated is False`, and no alpha canary in the text or
`canaries_present`. A symmetric test (`tests/test_cache.py:302`) proves an
authorized lead does not receive a revoked reader's cached denial. The fix was
applied before Tranche 3 so that cache/oracle measurements could not be
contaminated by cross-principal reuse.

The pre-fix reproduction is recorded in the reviewer addendum (working record,
not a raw capture). The post-fix claim is backed by code and tests; the
end-to-end demo and held-out captures below are post-fix runs.

## 4. Corrected statistics unit

**Retraction.** The earlier "13 families / 39 rows" claim was wrong. Six of the
thirteen were **facet labels of the single development scenario**, not
independent executable families, so the statistics script was measuring the same
dev campaign six extra times.

**Current unit:** **8 scenario families** (`revocation` plus the 7 held-out
families) and **24 family-template rows** (8 families × 3 templates) over 25
seeds per row. The six dev facet labels remain facet labels of one scenario and
are not independent samples.

Capture: [`raw/65`](raw/65-hardening-statistics.txt) reports
`families=8 rows=24 separated=24 unevaluable=0 all_deterministic=True`.

## 5. Measured results

All results below are from the captures linked in §8.

| Check | Measured result |
|---|---|
| Test suite | **259 passed** (`raw/60`) |
| Coverage | **TOTAL 1924 stmts, 121 missed, 94%** (`raw/61`) |
| Demo G2 | **12/12**; secured exit **0**, vulnerable exit **1** (`raw/62`) |
| Isolated-oracle demo | **12/12**; secured exit **0**, vulnerable exit **1** (`raw/66`) |
| Held-out families | **7 families, 7/7 `ok=True`** (`raw/63`) |
| Template sweep | **3 templates, 12 faults, 42 cells, 0 failures** (`raw/64`) |
| Statistics | **families=8 rows=24 separated=24 unevaluable=0 all_deterministic=True** (`raw/65`) |
| Ruff | **All checks passed!** (`raw/67`) |
| Mypy | **Success: no issues found in 38 source files** (`raw/68`) |
| `pip check` | **No broken requirements found.** (`raw/69`) |

Coverage is reported for the full suite as captured; it is not a release gate in
0.2.0.

## 6. Determinism

`Evidence.timestamp` and `CacheEntry.created_at` use a fixed logical clock
(`FIXED_INSTANT = 2026-01-01T00:00:00Z`); no wall-clock value enters a report.
For identical inputs, two independent demo runs produced the same four report
files byte-for-byte, as recorded in
[`raw/66`](raw/66-hardening-isolated-oracles.txt):

| File | SHA-256 (run A = run B) |
|---|---|
| `scenario_15104689767409a4.html` | `c5ea6226e423829d5a5efcafce5697a22e8bc137af53e29c60a517a2d33dc93f` |
| `scenario_15104689767409a4.json` | `01f19b08873b0cab4f8b22d43f4a843d2e56da263d41a1d8202723932a352077` |
| `scenario_2fef19eea7089471.html` | `a37194265458b6e25588b1b262e4694bf56c7c6a709f906963e94398e496f587` |
| `scenario_2fef19eea7089471.json` | `a5872e7c8058f62af9fd9679dec64a8419efc7598a9b77440af0cc4363b05fc2` |

The manifest is reproducible (no PID, no wall-clock field), and the dataset
artifacts are byte-identical to generator output (pinned in
`tests/test_dataset.py`).

## 7. Exit-code contract

Exit codes follow [ADR-0011](../decisions/ADR-0011-measurement-output-contract.md):

| Code | Meaning |
|---|---|
| `0` | all applicable required checks pass |
| `1` | a confirmed security violation or regression |
| `2` | the measurement/statistics are invalid: inconclusive, unsupported where a required facet was expected, a failed discriminative check, a failed separation, or an infrastructure/worker failure |

The contract applies to `redfence run`, `redfence demo`, the held-out runner, the
vertical slice, the template sweep and the statistics script. An inconclusive
result never becomes a passing security result, and a secured violation is `1`,
not `2`. The CLI catches isolated-worker `RuntimeError`/`TimeoutExpired` and
returns `2`; library callers still see the exception.

## 8. Verification captures

| Capture | Command | Exit |
|---|---|---|
| [`raw/60`](raw/60-hardening-tests.txt) | `pytest -o addopts="" -q` | 0 |
| [`raw/61`](raw/61-hardening-coverage.txt) | `pytest -o addopts="" -q --cov=redfence --cov-report=term-missing` | 0 |
| [`raw/62`](raw/62-hardening-demo.txt) | `python -m redfence.cli demo --out reports\hardening-demo` | 0 |
| [`raw/63`](raw/63-hardening-heldout.txt) | `python scripts\run_heldout.py --out reports\hardening-heldout` | 0 |
| [`raw/64`](raw/64-hardening-template-sweep.txt) | `python scripts\run_template_sweep.py` | 0 |
| [`raw/65`](raw/65-hardening-statistics.txt) | `python scripts\run_statistics.py --seeds 25 --templates` | 0 |
| [`raw/66`](raw/66-hardening-isolated-oracles.txt) | `python -m redfence.cli demo --isolated-oracles` plus determinism appendix | 0 |
| [`raw/67`](raw/67-hardening-ruff.txt) | `ruff check . --no-cache` | 0 |
| [`raw/68`](raw/68-hardening-mypy.txt) | `mypy src` | 0 |
| [`raw/69`](raw/69-hardening-pip-check.txt) | `python -m pip check` | 0 |

All ten captures were taken on 2026-11-19, from
`E:\Projects\AI-ML\Redfence`, with Python 3.14.7 on Windows, and record
`commit=NOT_A_GIT_REPO`.

## 9. Not re-run / not verified

- **Docker/G6/G9 not re-run in 0.2.0.** The Docker credential/network isolation
  fixture was captured on 2026-11-10 and is historical only. This release makes
  no current Docker PASS claim and runs no Docker command.
- **CI execution NOT VERIFIED until pushed.** `.github/workflows/ci.yml` exists
  and defines the Windows/Linux × Python 3.11/3.12 matrix, but it has not been
  executed by GitHub Actions.
- **Python 3.11/3.12 NOT VERIFIED.** The host interpreter is Python 3.14.7; the
  project declares `requires-python = ">=3.11"` but this release does not claim
  tested behaviour on 3.11 or 3.12.
- **Linux NOT VERIFIED.** All captures are from Windows.
- The optional `mypy tests` check is not gated and has no 0.2.0 capture; any
  count for it is not asserted here.

## 10. Known limitations carried forward

1. **Per-principal semantic binding removes cross-principal reuse.** A second
   principal with the same tenant and entitlement fingerprint is a semantic miss
   by design (`tests/test_cache.py:331`). This trades cache hit rate for
   authorization safety.
2. **`revoke()` uses a global epoch.** Revoking one principal increments
   `current_epoch` and invalidates every peer's cached entry, not just the
   revoked principal's (`src/redfence/targets/rag_target.py:116-118`). This is
   fail-closed and coarse; per-principal epochs are future work.
3. **Legacy `principal_id=""` entries are ineligible.** Cache entries serialized
   before principal binding load with an empty principal id and are never reused
   (`tests/test_cache.py:410`). This is intentional: they cannot be proven safe.
4. **`mypy tests` has one known error and is not gated.** `mypy src` is the
   release gate and is clean; the test tree is not type-gated in 0.2.0.
5. **Sweep and statistics have no infrastructure-failure guard.**
   [ADR-0011](../decisions/ADR-0011-measurement-output-contract.md) scopes
   exception catching to the CLI boundary; `scripts/run_template_sweep.py` and
   `scripts/run_statistics.py` do not wrap campaign execution, so an unexpected
   library exception would surface as a traceback rather than an explicit `2`.
6. **Statistics precedence is inconclusive→2 even when a violation is present.**
   `_outcome` returns `None` for any campaign with `has_inconclusive`
   (`scripts/run_statistics.py:61-62`), so a row containing both a violation and
   an inconclusive oracle is unevaluable and forces exit `2`; the violation is
   not reported as `1` in that mixed row.

## 11. Decision records

The accepted 0.2.0 decisions are promoted to
[`docs/decisions/`](../decisions/) as ADR-0007 through ADR-0012:

- [ADR-0007 — scenario/corpus identity and manifest provenance](../decisions/ADR-0007-scenario-identity-and-manifest-provenance.md)
- [ADR-0008 — oracle vacuity policy](../decisions/ADR-0008-oracle-vacuity-policy.md)
- [ADR-0009 — metric definitions and undefined handling](../decisions/ADR-0009-metric-definitions-and-undefined-handling.md)
- [ADR-0010 — release hygiene gates](../decisions/ADR-0010-release-hygiene-gates.md)
- [ADR-0011 — measurement-output contract](../decisions/ADR-0011-measurement-output-contract.md)
- [ADR-0012 — statistics reporting units](../decisions/ADR-0012-statistics-reporting-units.md)

ADR-0001 through ADR-0006 are unchanged.
