# RedFence

**RedFence** is an open-source AI security assessment and adversarial evaluation
platform. Its core research component, **RedFenceBench**, measures security
invariant violations across the lifecycle of stateful enterprise RAG
applications and tool-using agents.

The central thesis is *stateful enterprise AI security evaluation*: can we
systematically discover, reproduce, measure and verify security invariant
violations as identities, permissions, documents, indexes, caches, memories and
agent capabilities change over time?

RedFence separates two things that are often conflated:

1. an LLM **producing an unsafe response**, and
2. an application **violating an actual security boundary**.

Both matter; they are measured independently, using **deterministic oracles**
and recorded **Evidence**.

> Status: **0.3.0 external-target boundary** release. Contract v1, adapters, new
> lifecycle oracles and a mutation self-test extend the deterministic core. This
> is research software, not a production service. The 0.2.0 measurement-core
> hardening record is kept below as historical context. Full-suite, lint, type
> and script results for 0.3.0 are recorded in the
> [0.3.0 verification report](docs/verification/v030-report.md), backed by
> `docs/verification/raw/70-*` … `raw/84-*`.

## What exists at 0.3.0

- **Contract v1** (JSON or YAML) declares identities, sources, a permission
  matrix, lifecycle events, request limits and a redaction list. A bounded loader
  rejects oversized or deeply nested files, YAML tags/anchors/aliases, duplicate
  keys, non-string keys, path traversal, environment interpolation and unknown
  fields. JSON needs no optional dependency.
- **Adapters**: `mock` (default deterministic reference target), `callable`
  (Python API only) and `http` (JSON over HTTPS or loopback, egress allowlist,
  redirects disabled, response caps). Live HTTP endpoints are **NOT VERIFIED**;
  the HTTP adapter is exercised through a fake transport in the test suite and
  the loopback transport against a real local socket is verified
  (`docs/verification/raw/83-*`).
- **`redfence contract validate`** returns `0` for a valid contract and `3` for
  an invalid or unsafe one. **`redfence contract test`** runs the matrix and
  lifecycle against an adapter and returns `0` pass, `1` confirmed boundary
  violation, `2` inconclusive/unsupported/adapter error, `3` invalid contract.
- **New oracle families**: `contract` (matrix, lifecycle, budget, redaction),
  `lineage` (derivative leakage), `existence` (twin corpus, optional
  permutation), `repair` (selective repair and collateral damage), `capability`
  (attenuation, expiry, scope), `MCP` (manifest, rug-pull, shadowing) and
  `retention`/`replica` (deletion durability and replica consistency). The
  existing fifteen deterministic oracles and `default_oracles()` are unchanged.
- **Lineage** is reconstructed from observations and the corpus, not by
  instrumenting the target; an adapter that discloses no provenance yields
  `UNSUPPORTED`, never a fabricated pass.
- **Mutation self-test**: a known-good control removal must be killed by
  `oracle.cache.leak`; a behaviour-preserving known-bad mutant must survive.
  Mutation score is report-only in 0.3.0.
- **Optional extras**: `contract` (PyYAML), `property` (Hypothesis), `inspect`
  and `otel`. All optional imports are lazy; `import redfence` imports none of
  them.
- **Dataset `redfencebench-0.4.0`**: a provenance-schema/config bump, not a
  content change. Classic document bytes and content hashes are unchanged; four
  deterministic lifecycle configs are added under
  `datasets/redfencebench/configs/`.

The full-suite test count is recorded in
[`docs/verification/v030-report.md`](docs/verification/v030-report.md); it is
deliberately not hard-coded in this README.

## 0.2.0 measurement-core hardening (historical)

The following records the 0.2.0 milestone. It is kept for history and is not a
0.3.0 claim; see
[`docs/verification/hardening-report.md`](docs/verification/hardening-report.md).

- `RedFenceBench` synthetic dataset (deterministic, seeded, multi-tenant) in
  **three structural templates** swept for identical G2 behaviour.
- One **configurable RAG target** with a secured profile, a vulnerable profile,
  and twelve independently injectable faults, each mapped to an executable
  oracle — including **deletion propagation to cache and memory**.
- The **permission-revocation vertical slice**: ingest → authorize → retrieve →
  cache → memory → revoke → replay via every access path.
- **Lifecycle controls**: cascading deletion with cache/memory purge, ACL
  modification with epoch bump, and TTL-based memory expiry.
- **Seven executable held-out families**: delegation chain, memory poisoning,
  cache replay, MCP-like tool scope, deletion propagation, ACL-modify replay,
  memory TTL expiry.
- **Fifteen executable deterministic oracles** for index, cache freshness, cache
  reuse, cache deletion propagation, metadata integrity, memory scope and
  expiry, memory deletion propagation, tool policy, context, response and
  utility.
- **Evidence-backed** findings, **JSON + HTML** reports that are **byte-identical
  for fixed inputs** (logical clock, no wall time), a **reproducible run
  manifest**, and regression tests with CI exit semantics.
- **Process-isolated oracles** (`--isolated-oracles`): scoring runs in a child
  process from a frozen snapshot, in a real different PID from the target.
- **Historical Docker isolation fixture** (two databases, separate credentials,
  internal networks, controlled egress sink) captured **2026-11-10** and **not
  re-run in 0.2.0 or 0.3.0**; default execution is in-process.
- **Clustered statistics** over **8 scenario families / 24 family-template rows
  over 25 seeds** (not 13 labels).

Deliberately deferred **at 0.2.0** (some are now addressed by 0.3.0): adaptive
attack selection, broad attack catalogue, Redis, distributed workers, dashboard,
real LLM/embedding providers, MCP, multimodal, retention/replica/backup stores.

## Quick start

Windows (commands executed on the verification host):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,contract,property,inspect,otel]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -m property -q
.\.venv\Scripts\python.exe examples\facets_demo.py
.\.venv\Scripts\python.exe -m redfence.cli demo --out reports\
.\.venv\Scripts\python.exe -m redfence.cli contract validate examples\contracts\mock.json
.\.venv\Scripts\python.exe -m redfence.cli contract test examples\contracts\mock.json --adapter mock --out reports\contract-demo
.\.venv\Scripts\python.exe scripts\run_heldout.py --out reports\heldout
.\.venv\Scripts\python.exe scripts\run_statistics.py --seeds 25 --templates
.\.venv\Scripts\python.exe scripts\run_template_sweep.py
.\.venv\Scripts\python.exe -m redfence.cli demo --isolated-oracles
.\.venv\Scripts\python.exe scripts\run_mutation.py
# Historical Docker isolation fixture (captured 2026-11-10; not re-run):
.\.venv\Scripts\python.exe scripts\run_infrastructure_isolation.py
```

`demo` runs the revocation scenario against the secured and vulnerable profiles,
checks discriminative validity (G2), writes JSON + HTML reports, and returns an
exit code (`0` pass, `1` confirmed secured regression, `2` inconclusive,
unsupported or infrastructure failure).

`contract test` on the checked-in example writes deterministic JSON, SARIF and
JUnit files and exits `0`; `contract validate` exits `0` for the same file.
The verification host used Python 3.14.7 (`py -3.12` was not installed); the
project declares `requires-python = ">=3.11"`.

## Repository layout

```
src/redfence/
  core/         domain models, Evidence, Protocol interfaces, stable IDs, lineage, capability
  adapters/     deterministic embedder + in-memory vector store
  targets/      configurable RAG target, fault flags, synthetic tool runtime, HTTP boundary, retention
  bench/        dataset generator, scenario, oracles/scorers, metrics, runner, contract runner
  contracts/    contract v1 schema, bounded loader, adapters
  integrations/ optional Inspect/OTel adapters (lazy imports)
  report/       JSON + HTML + contract JSON/SARIF/JUnit reporting
  db/           SQLAlchemy models for the platform/SUT databases (optional)
  api/          FastAPI app (optional)
docs/           benchmark spec, architecture, threat model, claims, standards, decisions
datasets/       RedFenceBench generator + versioned manifests and lifecycle configs
examples/       checked-in example contracts
tests/          deterministic regression tests
```

## Documentation

- [`docs/benchmark-spec.md`](docs/benchmark-spec.md) — dimensions A–D, gates G1–G9, contract v1, oracle table
- [`docs/architecture.md`](docs/architecture.md) — architecture, trust domains, contract seam
- [`docs/threat-model.md`](docs/threat-model.md) — assets, adversaries, boundaries, external-target risks
- [`docs/standards/traceability.md`](docs/standards/traceability.md) — standards mapping
- [`docs/claims.md`](docs/claims.md) — public claim register and evidence status
- [`docs/prior-art/`](docs/prior-art/) — code-level prior-art audit
- [`docs/research-gaps.md`](docs/research-gaps.md) — gaps and differentiation
- [`docs/verification/hardening-report.md`](docs/verification/hardening-report.md) — historical: 0.2.0 measurement-core hardening
- [`docs/verification/lifecycle-breadth-report.md`](docs/verification/lifecycle-breadth-report.md) — historical: deletion propagation, lifecycle extensions, templates
- [`docs/verification/isolation-and-statistics-report.md`](docs/verification/isolation-and-statistics-report.md) — historical: G3/G5/G6/G7/G9 closure
- [`docs/decisions/`](docs/decisions/) — architecture decision records
- [`CHANGELOG.md`](CHANGELOG.md) — release history
- [`SECURITY.md`](SECURITY.md) — supported versions, reporting, safe use
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development, gates and clean-room policy
- [`CITATION.cff`](CITATION.cff) — citation metadata

## Licence

Apache-2.0 (see `LICENSE`). Upstream projects studied during the prior-art audit
are **not** vendored into the shipped tree; see
`docs/prior-art/inventory-and-licences.md`.
