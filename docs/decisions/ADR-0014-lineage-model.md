# ADR-0014: Lineage model — derive, do not instrument the target

Date: 2026-11-20 · Status: **Accepted (0.3.0, 2026-11-20)** · Related: `v030-master-plan.md` §5, T5–T7

## Context
Derivative leakage needs to know which cache entry, answer or memory record descends from which
document/chunk. Instrumenting `ConfigurableRAGTarget` would couple the SUT to the benchmark, add a
hook to a 519-line target, and let external targets forge provenance. The scenario already records
`context_chunk_ids`, cache document versions, memory records and deletion propagation.

## Decision
1. `Artifact` / `Span` / `LineageEdge` / `LineageGraph` live in `core/lineage.py` (pure data, no
   `bench` import).
2. `bench/lineage.py:build_lineage(run)` reconstructs the graph **from observations + corpus +
   target snapshot**; the target is not modified and imports nothing from `bench`.
3. Node kinds: document, chunk, embedding, cache_entry, memory_record, answer, tool_result. Spans
   are character/line ranges within the parent; chunk spans come from `chunk_text`.
4. For external targets, `context_refs` and `sources` are the only provenance; a missing ref
   yields no artifact and the derivative oracle returns `UNSUPPORTED`.
5. `oracle.lineage.derivation`: every derived artifact must reach an authoritative document; a
   deleted document must have no live descendant. Zero artifacts → `UNSUPPORTED`.
6. No `oracle.lineage.span` in 0.3.0; spans are data, not a separate verdict.

## Alternatives rejected
- **Lineage sink/hook on the target**: couples SUT to benchmark, invasive, forgeable.
- **Trust the target's `source` string**: not authoritative; a poisoned record can claim any
  source. The oracle must use corpus ownership (ADR-0005).
- **Per-record span oracle**: over-fits the synthetic chunker and adds little security signal.
- **Store the graph in the report**: bloats report bytes; a digest + summary is enough.

## Migration impact
New modules; `ContractRun.lineage` is optional. No existing report changes. A run whose target
discloses no context refs reports lineage as unsupported rather than guessing.

## Rollback
Remove `core/lineage.py`, `bench/lineage.py` and the lineage oracles. No target or report change
is required to revert.
## Acceptance
T5–T7: deterministic graph, span containment, deleted-descendant VIOLATION, zero-artifact
UNSUPPORTED, classic report bytes unchanged.
