# ADR-0013: External-target boundary and the observation seam

Date: 2026-11-20 · Status: **Accepted (0.3.0, 2026-11-20)** · Related: `v030-master-plan.md` §5, T2–T4

## Context
`ScenarioRun.target` is typed `ConfigurableRAGTarget`; `_chunk_meta` reads `target.store.get`, and
the observation TypedDicts are frozen with required keys. External systems cannot supply a live
target, cache internals or tool specs. Widening `ScenarioRun` would touch held-out methods; adding
optional keys would change the frozen observation contract.

## Decision
1. Keep `ScenarioRun`, `default_oracles()` and the TypedDicts untouched.
2. Add `ContractRun` with the **same field names/types** for the six observation lists, plus
   `target: SnapshotTarget`, `contract`, `matrix_obs`, `lifecycle_obs`, `budget_obs`, `lineage`.
3. Adapters return `ContractResponse`; the runner projects it into the existing TypedDicts.
   Missing fields become `False`/`{}`; unknown metadata becomes `"unknown"` and is resolved
   against the contract's authoritative `sources`, never the adapter's claim.
4. Promote `SnapshotTarget` from `oracle_worker.py` to `bench/snapshot.py` so store-reading
   helpers work for both isolated and contract runs.
5. Declare adapter `capabilities`; an action the adapter cannot express produces **zero units →
   `UNSUPPORTED`**, never a fabricated pass.
6. Contract oracles take `ContractRun`; shared predicates stay in `bench/evaluation.py`.
## Alternatives rejected
- Widen `ScenarioRun.target` to a Protocol: held-out builders call methods the Protocol would
  need, forcing stubs or casts; larger blast radius for no measurement gain.
- Add optional keys to the TypedDicts: breaks the frozen contract and isolated payload equality.
- Accept `object`/`Any` in contract oracles: loses mypy and ADR-0009 predicate sharing.
- Require every external target to expose cache/store internals: unimplementable for an
  OpenAI-compatible endpoint.
## Migration impact
New modules only. `oracle_worker.py` imports the promoted snapshot types; its JSON payload is
unchanged. No existing report bytes change. Unobservable facets report `UNSUPPORTED`.
## Rollback
Delete `contracts/`, `contract_runner.py`, `contract_oracles.py` and the CLI subcommands; restore
the inline snapshot classes. Existing oracles and reports are unaffected.

## Acceptance
T2–T4: mock/callable/fake-transport tests, zero-unit UNSUPPORTED tests, byte-identical classic
reports, isolated-oracle tests green.
