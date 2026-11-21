# ADR-0016: Mutation, property tests and release gates

Date: 2026-11-20 · Status: **Accepted (0.3.0, 2026-11-20)** · Related: `v030-master-plan.md` §10–§12, T11, T14

## Context
A benchmark can pass its own tests while its oracles are blind. Mutation testing proves the oracle
suite detects a removed control; property tests prove ACL invariants beyond hand-picked cases. Both
are easy to turn into vanity metrics, and their dependencies must not enter the default path.

## Decision
1. **Mutation harness is self-proving.** A known-good mutant (cache revalidation removed) must be
   observed as a violation at `oracle.cache.leak`; a known-bad behaviour-preserving mutant
   (answer passthrough) must be observed as satisfied. Every result records whether the observed
   outcome equals its declared expectation (`as_expected`); if any mutant disagrees, the harness
   fails.
2. Mutants are monkeypatch-based (`unittest.mock.patch.object`), never source rewrites. The
   registry is deterministic and small.
3. `scripts/run_mutation.py` exits 0 only when every mutant's observed outcome matches its
   expected outcome; 2 if the self-test fails; 3 on an invalid registry. The score is
   `matched / total`, where `matched` counts mutants whose observation equals expectation, so a
   registry where every expectation is met scores 1.00 (0.0 when empty). **No CI gate on mutation
   score in 0.3.0**.
4. **Property tests are optional.** `hypothesis` is a `property` extra; tests are marked
   `property` and `pytest.importorskip`. Properties: tenant isolation, revocation denies,
   clearance monotonicity, epoch monotonicity; `derandomize=True`.
5. **Release gates:** 259+ tests green, ruff 0, mypy src 0, `pip check`, classic report byte
   equality, dataset artifact equality, contract validate/test, claim-register paths exist.
6. Optional `inspect`/`otel` adapters are thin, lazy-imported, and never gate the release.
## Alternatives rejected
- **Mutmut/cosmic-ray dependency**: extra toolchain and source rewrites; monkeypatch seams prove
  the same point.
- **Mutation score threshold in CI**: gameable and blocks legitimate new negative tests.
- **Property tests in the default suite**: Hypothesis adds time and a dependency; an optional
  extra keeps the core light.
- **Gate on OTel/Inspect integration tests**: optional extras must not decide release health.
## Migration impact
New script/module/extra and two optional packages; default install and `import redfence` are
unchanged. CI gains a non-gating mutation job and a property job when installed.
## Rollback
Delete `bench/mutation.py`, `scripts/run_mutation.py`, the property tests and the extras. No
runtime or report change.

## Acceptance
T11/T14: known-good killed, known-bad survives, every expectation met (`score=1.00`), property
tests pass/skip cleanly, gate commands recorded in `70-*`, no mutation threshold in CI.
