# ADR-0015: Existence-leak statistics — twin corpus, honest p-values

Date: 2026-11-20 · Status: **Accepted (0.3.0, 2026-11-20)** · Related: `v030-master-plan.md` §7, T6

## Context
An attacker may infer whether a document exists from response differences. The synthetic target is
deterministic, so a naive permutation test has a degenerate null: one observation per query pair
cannot support a p-value. Claiming one would be the false assurance ADR-0008 exists to prevent.

## Decision
1. Build **twin corpora** identical except for the target document's presence/ACL; run the same
   query set against both.
2. `oracle.existence.twin` compares a feature vector per query pair: `status`, text hash,
   context-ref set, `tool_executed`. Any difference → `VIOLATION`; zero pairs → `UNSUPPORTED`.
3. `oracle.existence.permutation` runs **only** with ≥2 samples per twin. Statistic = absolute
   difference in mean feature; exact enumeration for ≤12 pairs, else 2000 Monte-Carlo resamples
   with a fixed seed. `p < 0.05` and effect > 0.2 → `VIOLATION`; no repeated-sample pairs →
   `UNSUPPORTED`.
4. The report states the unit (query pair), sample count, and exact/Monte-Carlo mode. No p-value
   is printed for the deterministic synthetic target.
5. The twin oracle is the release's existence claim; the permutation oracle is an optional
   statistical extension, not a headline result.

## Alternatives rejected
- **Permutation on one deterministic sample**: invalid; would manufacture significance.
- **Use wall-clock timing as a feature**: nondeterministic and outside the deterministic core.
- **Call it membership inference**: over-claims; this is a response-difference audit.
- **Ship only the permutation test**: leaves the deterministic path untested and the release
  without an existence claim.

## Migration impact
New modules and oracles only; `default_oracles()` unchanged. Synthetic runs report the twin
oracle and `UNSUPPORTED` for permutation unless samples are supplied.

## Rollback
Remove `bench/existence.py` and the two oracles. No other module depends on them.

## Acceptance
T6: identical twins SATISFIED, differing twins VIOLATION, one-sample permutation UNSUPPORTED,
p-value deterministic, zero-pair UNSUPPORTED.
