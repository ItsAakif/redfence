# ADR-0008: Oracle vacuity policy — no vacuously SATISFIED verdicts

Date: 2026-11-19
Status: **Accepted** (0.2.0, 2026-11-19)
Defect: D6
Related: `bench/oracles.py`, `bench/scenario.py`, `bench/heldout.py`, `docs/benchmark-spec.md`

## Context

Several oracles count only the things that could violate their invariant and
then return `SATISFIED` when that count is zero. Observed current cases:

- `IndexAclOracle` / `TenantIsolationOracle`: zero admitted chunks → `SATISFIED`.
- `CacheLeakOracle`: zero cache hits → `SATISFIED`.
- `SourceFreshnessOracle`: zero cache hits → `SATISFIED`.
- `ContextExposureOracle`: zero context chunks → `SATISFIED`.
- `MetadataIntegrityOracle`: zero resolvable chunks → `SATISFIED`.
- `ResponseDisclosureOracle`: zero canaries present → `SATISFIED`.
- `MemoryIsolationOracle`: zero records → `SATISFIED`.

Measured baseline: the secured dev campaign has **0 cache hits** (7 answers, 7
admissions, 11 context chunks), so `oracle.cache.leak` and
`oracle.cache.freshness` both report `SATISFIED` without ever observing a cache
hit. The held-out `acl.modify.replay` secured run also has 0 hits. This is a
false assurance: the scenario did not exercise the behaviour being claimed.

The opposite mistake is also possible: treating every zero count as vacuous
would mark honest absence properties (e.g. "an expired record was not returned")
as unsupported. The policy must distinguish **observations evaluated** from
**sub-items inside an observation**.

## Decision

1. **A `SATISFIED` verdict requires at least one evaluable unit.** A unit is the
   concrete observation the invariant constrains, defined per oracle below. Zero
   units → `UNSUPPORTED`, with `observed` saying no evaluable observation and
   `events=[]`.

2. **`UNSUPPORTED` means "not measured"**, not "passed" and not "inconclusive".
   `INCONCLUSIVE` remains reserved for an attempted measurement that could not be
   decided. Campaign exit code 2 applies to both, per ADR-0011.

3. **Implement the rule structurally.** Add a private helper in
   `bench/oracles.py`:

   ```python
   def _verdict(units: int, violations: list[str]) -> Outcome:
       if units == 0:
           return Outcome.UNSUPPORTED
       return Outcome.VIOLATION if violations else Outcome.SATISFIED
   ```

   Every oracle that currently has an implicit zero-count fallback must use it.
   Do not leave a bare `VIOLATION if violations else SATISFIED` in those oracles.

4. **Unit table (binding):**

   | Oracle | Evaluable unit | Zero-unit result |
   |---|---|---|
   | `oracle.index.acl` | same-tenant admitted chunk in a retrieval observation | UNSUPPORTED |
   | `oracle.index.tenant` | admitted chunk in a retrieval observation | UNSUPPORTED |
   | `oracle.index.deletion` | deletion observation (admitted set may be empty) | UNSUPPORTED (already) |
   | `oracle.cache.key_scope` | cache entry | UNSUPPORTED |
   | `oracle.cache.leak` | cache-hit answer observation | UNSUPPORTED |
   | `oracle.cache.freshness` | cache-hit answer observation | UNSUPPORTED |
   | `oracle.cache.deletion_propagation` | deletion observation carrying a propagation payload | UNSUPPORTED (already) |
   | `oracle.memory.deletion_propagation` | deletion observation carrying a propagation payload | UNSUPPORTED (already) |
   | `oracle.metadata.integrity` | stored chunk resolvable to a corpus document | UNSUPPORTED |
   | `oracle.context.exposure` | context chunk in an answer observation | UNSUPPORTED |
   | `oracle.response.disclosure` | answer observation whose assembled context contains at least one canary, or whose text contains one (a disclosure opportunity) | UNSUPPORTED |
   | `oracle.memory.scope` | memory-recall observation (returned set may be empty; an empty recall after TTL expiry is a positive control) | UNSUPPORTED |
   | `oracle.tool.policy` | tool-call observation | UNSUPPORTED |
   | `oracle.utility.benign` | utility observation | UNSUPPORTED (already) |
   | `oracle.coverage.unsupported` | always evaluable (declaration) | n/a |

5. **Scenarios provide positive controls before the policy lands.** Add a second
   authorized answer before the source update in the dev scenario, and a second
   pre-modify answer in `acl.modify.replay`. These create real cache hits without
   changing the pinned secured/vulnerable outcome map. This is a prerequisite,
   not an optional nicety: without it, the secured campaign would correctly report
   `UNSUPPORTED` for cache leak/freshness and exit 2.

6. **Tests are part of the policy.** For every oracle, a test constructs an empty
   `ScenarioRun` (or otherwise zero-unit observation set) and asserts
   `UNSUPPORTED`. `CoverageOracle` is exempt and tested separately.

## Alternatives rejected

- **Keep `SATISFIED` and document the denominator.** The report says "satisfied";
  most readers will not notice a zero denominator. The defect is the claim, not
  the arithmetic.
- **Return `INCONCLUSIVE` instead.** There was no attempted measurement, so
  "inconclusive" overstates what happened. `UNSUPPORTED` already means "not
  evaluated at this milestone".
- **Per-scenario applicability declarations only.** Applicability says the facet
  matters; it does not prove the observation existed. Unit counts are still
  required.
- **Fix only the cache oracles.** The same vacuity exists in index, context,
  metadata, response and memory oracles. A partial policy would leave the same
  false assurance elsewhere.
- **Make every zero sub-count unsupported (e.g. zero returned memory records).**
  That would misclassify honest absence controls (TTL filtering, deletion purge).
  The observation is the unit; the returned set is data within it.

## Migration impact

- Outcomes change from `SATISFIED` to `UNSUPPORTED` only where a scenario truly
  has no evaluable observation. After the positive controls, the dev secured and
  vulnerable campaigns and all scored held-out families retain units, so existing
  `exit_code == 0/1` expectations stay valid.
- `observed` strings and event counts change slightly; report bytes change (also
  affected by ADR-0007/0011).
- Any external consumer that treated `satisfied` as "no observation" must now
  handle `unsupported`; no such consumer is in this repository.

## Rollback

Revert the oracle commit; the previous `SATISFIED` fallback returns. Because the
positive controls are independently useful (they make cache behaviour observable),
they may be kept on revert; if kept, they do not change outcomes.

## Acceptance

Task contracts T3.1–T3.3: empty-run tests for every oracle, positive-control
assertions, fault/oracle coverage, and the full suite green with the pinned
outcome map unchanged.
