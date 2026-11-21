# RedFence 0.3.0

Stateful enterprise AI security evaluation: a deterministic, lifecycle-aware benchmark for RAG and tool-using agent authorization boundaries.

## Highlights

- Contract v1: bounded JSON/YAML boundary contracts, mock/callable/HTTP adapters, permission matrix and lifecycle runner.
- New oracle families: contract matrix/lifecycle/budget/redaction; lineage derivation; twin existence; selective repair and collateral; capability attenuation/expiry/scope; MCP manifest/rug-pull/shadowing; replica/retention durability.
- Reproducible evidence: byte-identical JSON/HTML, manifest schema 2 with corpus digest, SARIF 2.1.0 and JUnit reporters, exit codes 0/1/2/3.
- Mutation harness with a known-good and known-bad mutant; matching expectations score 1.00.
- Dataset `redfencebench-0.4.0` with lineage/existence/repair/replication configs; classic content hashes unchanged.
- `examples/facets_demo.py` exercises every new facet without network access.

## Verification (local, 2026-11-21)

- 612 tests passed, 2 skipped (the two skips assert the missing-extra behaviour and are skipped when extras are installed).
- 94% coverage; ruff and mypy clean; pip check clean.
- Demo G2 12/12; held-out 7/7; template sweep 42/42; statistics 8 families / 24 rows over 25 seeds.
- Contract validate/test pass; invalid contracts exit 3; lifecycle revocation exits 0.
- Loopback HTTP transport verified; property tests pass with Hypothesis; Inspect and OpenTelemetry adapters import and execute.

## Breaking changes

- Every `scenario_id` and `evidence_id` changed because dataset identity now includes the 0.4.0 version.
- Dataset version moved to `redfencebench-0.4.0`; package version moved to 0.3.0.
- New CLI subcommands (`contract validate|test`), new optional extras (`contract`, `property`, `inspect`, `otel`), exit code 3 for invalid contracts.
- Classic document content and content hashes are unchanged; historical raw captures are not rewritten.

## Not verified

- Live third-party HTTP/OpenAI-compatible endpoints (loopback transport is verified).
- Python 3.11/3.12 and Linux (host verification used Python 3.14.7 on Windows; CI matrix is defined but its result is recorded in the Actions run, not here).
- Docker / G6 / G9: historical fixture captured 2026-11-10, not re-run.

## Known limitations

- Lineage/existence/repair/capability/MCP/retention facets are library-level and runnable via `examples/facets_demo.py`; they are not CLI subcommands in 0.3.0.
- `apply_repair` mutates the run target; use a dedicated run.
- `expire` maps to `revoke` on the adapter wire; `samples` are not stored, so the permutation oracle is API-only.
- Allowlisted hostnames remain a DNS-rebinding residual; YAML requires the `contract` extra.

Research software. Synthetic data. Not a production service or a scanner.
