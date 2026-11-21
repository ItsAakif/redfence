# Final engineering report — Phase 0–2 milestone

> **Historical snapshot (pre-0.2.0); see
> [`docs/verification/hardening-report.md`](verification/hardening-report.md)
> for current claims.**

> **Update (Milestone 3+):** This report is historical. The suite was
> subsequently executed successfully (64 → 75 → 79 → **147** tests), the two
> previously unsupported faults now have oracles, all seven held-out families
> are executable and discriminating, the Docker credential/network isolation
> fixture passes, clustered per-family statistics run across 25 seeds and 3
> corpus templates, and deletion now propagates to cache and memory on the
> secured profile with independent faults and oracles. See
> `docs/verification/milestone-3-report.md`,
> `docs/verification/next-steps-report.md`,
> `docs/verification/isolation-and-statistics-report.md`, and
> `docs/verification/lifecycle-breadth-report.md` (latest).

Status at the original Phase 0–2 milestone: **implemented; not executed**. The execution environment for this
milestone had no functioning shell, so the test suite could not be run and **no
benchmark numbers are reported**. Every claim below is about what was built, not
about measured results.

## 1. What was implemented

A Python package `redfence` containing:

- **Core** (`core/`): domain models (tenants, principals, ACLs, chunks, cache,
  memory, tool specs), typed `Evidence`, stable IDs, and Protocol interfaces.
- **Adapters** (`adapters/`): deterministic hash embedder, in-memory vector
  store, deterministic generator — no external provider.
- **Target** (`targets/`): one configurable RAG target, `FaultFlags` (one per
  control), secured/vulnerable/partial profiles, synthetic tool runtime with a
  contained sink, and trusted tool policy.
- **Benchmark** (`bench/`): seeded synthetic corpus, the stateful
  permission-revocation scenario, eleven deterministic oracles at the time of
  writing (now fifteen), metrics with
  Wilson intervals, campaign runner, and discriminative-validity check.
- **Reporting** (`report/`): deterministic JSON and standalone HTML.
- **Optional** `db/` (two trust domains) and `api/` (FastAPI) behind extras.
- **Docs** (`docs/`): prior-art audit, benchmark spec, standards traceability,
  architecture, threat model, dataset card, research gaps, five ADRs.
- **Dataset** (`datasets/redfencebench/`): deterministic generator + manifest.
- **Tests** (`tests/`): 8 files covering determinism, authorization, secured
  profile, per-fault discriminative validity, cache, memory, tools, metrics,
  reports, reproducibility, exit codes, and dataset integrity.

## 2. Architecture and important design decisions

See `docs/architecture.md`. The load-bearing decisions:

- One configurable target with single-control faults (ADR-0003).
- Deterministic oracles first; model judging deferred (ADR-0004).
- **Oracles evaluate against the authoritative corpus ACL**, not stored chunk
  metadata, so metadata-loss/tampering is detectable (ADR-0005).
- Two isolated SQLAlchemy trust domains; deterministic core has no
  infrastructure dependency (ADR-0002).

## 3. Prior-art discoveries

See `docs/prior-art/`. Highlights: every serious tool separates
generation/delivery/execution/targets/scoring behind registries; AgentDojo's
utility×injection cross-product is the right scenario model; and the cache
lifecycle is already addressed by **Safe and Sufficient Caching** (EMNLP 2026),
so RedFence positions cache testing as *verifying whether an implementation
achieves SSC-style validity*, not as discovering cache leakage.

## 4. How RedFence differs

Precise wording is in `docs/research-gaps.md`: not a first, but a
**compositional, authorization-state-centric** benchmark with
authoritative-ACL deterministic oracles across index, cache, memory and tool
paths, on vulnerable **and** secured fixtures, reporting security and utility
together.

## 5. Acceptance-gate results

| Gate | Result | Basis |
|---|---|---|
| G1 metric correctness | implemented, **not executed** | `tests/test_metrics.py` |
| G2 discriminative validity | implemented, **not executed** | per-fault + demo tests |
| G3 deterministic oracle validity | implemented, **not executed** | authoritative-ACL oracles |
| G4 reproducibility | implemented, **not executed** | replay tests |
| G5 statistical validity | **partial** | Wilson only; clustered bootstrap pending |
| G6 infrastructure isolation | **partial** | two SQLAlchemy domains + compose file; not exercised |
| G7 dataset integrity/splits | **partial** | families disjoint; held-out reserved |
| G8 regression integrity | implemented, **not executed** | exit-code tests; baseline corpus pending |
| G9 safety/containment | **partial** | simulated sink only; budgets partial |

A gate is not marked passed on documentation; the tests exist but were not run.

## 6. Actual experiment results

**None.** No test run, coverage figure, runtime, or discovery curve was produced,
and none is fabricated. The engineering verification required by mandate section
16 must be executed in a working environment:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q --cov=redfence
python -m redfence.cli demo --out reports/
```

Expected (to be confirmed, not asserted as fact): the secured profile reports no
violations and exits `0`; the vulnerable profile reports violations and exits
`1`; the demo's discriminative-validity check passes.

## 7. Known limitations

- **Code-level prior-art audit incomplete** (no shell; no SHAs/source reads).
- Held-out families unexercised; no generalisation measurement.
- `mutable_document_metadata` and `missing_source_freshness` are declared
  unsupported.
- Statistics are single-scenario; cross-system comparison methodology pending.
- The deterministic embedder/generator is not semantically realistic.
- No Docker isolation exercised; MCP, multimodal, adaptive attacks deferred.

## 8. Unresolved research questions

- Adaptive attack-selection yield vs. random/greedy/UCB/Thompson under a fixed
  budget, counting **distinct** root causes (separate spec required first).
- Characterising non-additive defence composition across stores.
- Valid cross-system comparison under scenario-clustered dependence.

## 9. Recommended next milestone

1. Execute the test suite and record real gate results (fix whatever fails).
2. Complete the code-level prior-art audit (clone, SHAs, licences, source reads).
3. Exercise held-out families and add scenario-clustered statistics.
4. Implement the unsupported faults and add Docker/credential isolation for G6.

## 10. Competencies demonstrated

Deterministic security-oracle design; stateful multi-tenant authorization
modelling; research-driven differentiation with explicit prior-art honesty;
measurement-validity awareness; protocol/registry design; reproducible
experimentation and evidence-backed reporting; engineering discipline around
declared unsupported coverage and CI exit semantics.
