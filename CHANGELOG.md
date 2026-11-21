# Changelog

All notable changes to RedFence are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
semantic versioning for the package. Dataset versions are tracked separately.

## [0.3.0] — 2026-11-20

External-target boundary release: contract v1, adapters, lifecycle/derivative
oracles, a mutation self-test and release engineering. This is research software,
not a production service.

### Added

- Contract v1 (JSON or YAML) with a bounded loader: `src/redfence/contracts/`.
  Rejects oversized/deep files, YAML tags/anchors/aliases, duplicate or
  non-string keys, path traversal, environment interpolation, unknown fields and
  out-of-range limits. JSON needs no optional dependency.
- Adapters: `mock` (deterministic reference target), `callable` (Python API only)
  and `http` (JSON over HTTPS or loopback, egress allowlist, redirects disabled,
  response caps) with a fake transport for tests.
- Matrix/lifecycle runner and the `ContractRun` sidecar seam; contract JSON,
  minimal SARIF 2.1.0 and JUnit XML reports.
- CLI: `redfence contract validate <path>` and
  `redfence contract test <path> --adapter mock|http --out DIR`. Exit `3` means
  an invalid or unsafe contract; existing `run`/`demo` flags and exit codes are
  unchanged.
- New oracle families: `contract` (matrix, lifecycle, budget, redaction),
  `lineage` (derivation), `existence` (twin, optional permutation), `repair`
  (selective, collateral), `capability` (attenuation, expiry, scope), `MCP`
  (manifest, rug-pull, shadowing), `retention` (durability) and `replica`
  (consistency). The existing fifteen oracles and `default_oracles()` are
  unchanged.
- Lineage graph derived from observations and corpus; twin-corpus existence
  audit; selective-repair plans; capability tokens and delegation chains;
  deterministic stdlib MCP fixture; in-memory replica/backup/retention stores.
- Mutation harness (`scripts/run_mutation.py`) with a known-good mutant that must
  be killed and a known-bad mutant that must survive. Mutation score is
  report-only in 0.3.0.
- Optional extras: `contract` (PyYAML), `property` (Hypothesis), `inspect` and
  `otel`. Optional imports are lazy; `import redfence` imports none of them.
- Dataset `redfencebench-0.4.0` adds four deterministic lifecycle configs
  (`lineage`, `existence`, `repair`, `replication`) under
  `datasets/redfencebench/configs/`.
- Release documentation: claim register, `SECURITY.md`, `CONTRIBUTING.md`,
  `CITATION.cff`, ADR-0013–0016, and an extended CI workflow.

### Changed

- **Breaking:** `scenario_id` and `evidence_id` values change for every scenario
  because the dataset version is part of scenario identity. Report bytes and
  manifest digests change accordingly. Classic document **content** and
  `CLASSIC_CONTENT_HASHES` are unchanged.
- Package version is `0.3.0`; dataset version is `redfencebench-0.4.0`.
- `DefaultToolPolicy.decide` gains an additive `token=None` keyword. The existing
  `token=None` path is byte-identical.
- `ConfigurableRAGTarget` accepts additive `replicas`, `backups` and `retention`
  keywords. The default `None` path is byte-identical.
- CI installs `.[dev,contract]`, runs the full suite, ruff, mypy, `pip check`, an
  import smoke test, contract validate/test and the mutation self-test. Property
  tests run only when `hypothesis` is installed.

### Deprecated

- Nothing is removed or deprecated in 0.3.0. The Docker/G6/G9 isolation fixtures
  remain historical captures from 2026-11-10 and are not re-run.

### Security

- Contract loading is deny-by-default: SafeLoader only, explicit YAML tags and
  anchors/aliases rejected, hard size/depth/list caps, no code selection from a
  file, and `callable` restricted to the Python API.
- HTTP egress requires an explicit allowlist, `https` or loopback, and disables
  redirects. Response bodies are capped and truncation is reported.
- Redaction uses environment-variable **names**, never values; configured secret
  values and corpus canaries are redacted before observations are stored, and a
  redaction oracle re-checks the stored run.
- Optional integrations are lazy-imported and cannot affect `import redfence`.
- **NOT VERIFIED:** live HTTP/OpenAI-compatible endpoints, live Inspect
  integration and live OTel export. These adapters are fake-transport or
  `importorskip` tested only.

### Fixed

- No runtime regression fix is claimed in this release. 0.3.0 is additive; 0.2.0
  behaviour is preserved except the version and scenario-identity changes above.

## [0.2.0] — 2026-11-19

Measurement-core hardening. See
`docs/verification/hardening-report.md` for the full record. Added reproducible
manifests and scenario identity, oracle-vacuity rules, metric definitions,
statistics reporting units, process-isolated oracles and release-hygiene gates.
No Docker work; G6/G9 remain historical fixtures.
