# RedFence

**RedFence** is an open-source benchmark and test harness for security-boundary
failures in stateful RAG and tool-using agents. Its benchmark is **RedFenceBench**.

Most AI security tooling asks whether a model *said* something unsafe. RedFence
asks whether the application crossed a security boundary; a polished answer can
still disclose another tenant's document.

The core idea: test authorization as state changes (revocation, deletion, ACL
edits, TTL expiry) across the index, caches, memory and tools. RedFence is
research software, not a scanner or firewall; it ships synthetic data and
deterministic oracles.

## What it is and what it is not

| It is | It is not |
| --- | --- |
| A benchmark and test harness for application-level boundary violations | A scanner, firewall, or runtime guard |
| Deterministic oracles with no LLM judge in the core | A model-safety or content-moderation benchmark |

## How it works
```
contract -> adapter -> scenario / lifecycle -> observations -> oracle -> Evidence -> report / exit code
```

A contract v1 file declares identities, sources, a permission matrix, lifecycle
events and request limits. An adapter presents the target through `mock`,
`callable`, or `http`; the runner executes the matrix and replays lifecycle
steps. Deterministic oracles emit Evidence, the report layer writes JSON/HTML or
SARIF/JUnit, and the exit code derives from the evidence. Missing observations
become `unsupported`, never a pass.

## Quick start
```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,contract,property,inspect,otel]"
```

```bash
# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,contract,property,inspect,otel]"
```

```bash
python -m pytest -q
python -m redfence.cli demo
python -m redfence.cli contract validate examples/contracts/mock.json
python -m redfence.cli contract test examples/contracts/mock.json --adapter mock --out reports/contract-demo
python examples/facets_demo.py
```
If activation is blocked on Windows, call `.\.venv\Scripts\python.exe` directly.

## What you will see
`demo` runs the revocation scenario against secured and vulnerable profiles: all
twelve faults are discriminated, secured exits `0`, vulnerable exits `1` (add
`--out reports/demo` for JSON and HTML). `contract test` runs the example matrix
against `mock`, exits `0` when clean, and writes JSON, SARIF and JUnit; lifecycle
and redaction rows are `unsupported` here, not passes.

```
Discriminative validity (G2): PASS (12/12 faults discriminated)
secured exit=0 vulnerable exit=1
contract=mock-boundary-demo adapter=mock exit=0
  [  satisfied] oracle.contract.matrix: 3/3 cells matched; 0 violations
```

## Test your own RAG or agent
A contract is all RedFence needs to test a target it did not write. Save this as
`my-contract.yaml` (YAML needs the optional `contract` extra; JSON does not):

```yaml
contract_version: 1
id: my-rag-boundary
dataset: {version: redfencebench-0.4.0, template: classic, seed: 20260101}
identities: [{id: alice, tenant: t_alpha, roles: [engineer], groups: [alpha-eng], clearance: confidential},
             {id: bob, tenant: t_beta, roles: [engineer], groups: [beta-eng], clearance: confidential}]
sources: [{id: doc_alpha_secret, tenant: t_alpha, classification: confidential, acl: {allowed_roles: [engineer], allowed_groups: [alpha-eng]}, canary_ref: alpha}]
matrix: [{id: alice_reads_alpha, identity: alice, source: doc_alpha_secret, action: read, expect: allow},
         {id: bob_reads_alpha, identity: bob, source: doc_alpha_secret, action: read, expect: deny}]
lifecycle: []
limits: {timeout_ms: 2000, max_response_bytes: 65536, max_requests: 32, egress_allowlist: []}
redaction: {secrets: []}
target: {adapter: mock}
```

Identities are principals. Sources are documents with ACLs. The matrix is the
expected allow/deny outcome. Lifecycle steps (none here) mutate state and replay
affected cells.

Run `python -m redfence.cli contract validate my-contract.yaml`, then
`python -m redfence.cli contract test my-contract.yaml --adapter mock --out reports/my-contract`.
For a real endpoint use `--adapter http`, set `target.url`, and give a non-empty
`limits.egress_allowlist`; redirects are off and live third-party HTTP is **NOT VERIFIED** (loopback is).

## Using the library (advanced facets)
Lineage, existence, repair, capability, MCP and retention/replica oracles are
Python-level facets in 0.3.0, exercised by
[`examples/facets_demo.py`](examples/facets_demo.py). They are not CLI
subcommands and are `partial` in the claim register. The demo prints one line
per oracle and exits `0` even on a deliberate `violation`.

## How to test this project
```bash
python -m pytest -o addopts="" -q                         # unit + integration suite
python -m pytest -m property -q                           # Hypothesis invariants
python scripts/run_mutation.py                            # mutation self-test
python scripts/run_heldout.py --out reports/heldout       # seven held-out families
python scripts/run_template_sweep.py                      # templates x faults sweep
python scripts/run_statistics.py --seeds 25 --templates   # clustered statistics
ruff check . --no-cache                                   # lint
mypy src                                                  # type check
```

The suite (`600+` tests; exact count in the verification report) covers
scenarios, oracles, contracts and reporting. Property, mutation, held-out, sweep
and statistics runners cover invariants, harness sensitivity and separation.
Ruff and mypy are the static gate.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All applicable required checks passed. |
| `1` | A confirmed security violation or regression. |
| `2` | Inconclusive, unsupported, or an adapter/infrastructure failure. |
| `3` | Invalid or unsafe contract file (`contract validate` / `contract test`). |

## Verification status

Version 0.3.0. CI is green on Ubuntu and Windows with Python 3.11 and 3.12
across all four matrix cells. Local captures back the suite, demo, contract,
held-out, sweep, statistics, mutation, lint and type results in the
[0.3.0 verification report](docs/verification/v030-report.md); claim status is
in [docs/claims.md](docs/claims.md).

Deliberately unverified: live third-party HTTP endpoints (only loopback is
tested), the historical Docker/G6/G9 fixtures, and library-level facets
(`partial`). The 0.2.0 hardening record is historical: see the
[hardening report](docs/verification/hardening-report.md) and [CHANGELOG.md](CHANGELOG.md).

## Repository map

```
src/redfence/core/      domain models, Evidence, protocols, lineage, capability
src/redfence/bench/     dataset, scenarios, oracles, contract runner, metrics
src/redfence/targets/   configurable RAG target, faults, tools, HTTP, retention
src/redfence/contracts/ contract v1 schema, bounded loader, target adapters
datasets/               RedFenceBench generator, manifests, lifecycle configs
scripts/                held-out, sweep, statistics and mutation runners
docs/                   spec, architecture, threat model, claims, ADRs, verification
tests/                  deterministic suite and fixtures
```

## Documentation
- [Benchmark specification](docs/benchmark-spec.md) - dimensions, gates, contract v1 and the oracle table
- [Architecture](docs/architecture.md) - components, trust domains and the contract seam
- [Threat model](docs/threat-model.md) - assets, adversaries and trust boundaries
- [Claims](docs/claims.md) - public claim register with evidence status
- [Decisions](docs/decisions/) - architecture decision records
- [0.3.0 verification report](docs/verification/v030-report.md) - captures and measured results

## Contributing, security and licence
- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md) for development gates and the clean-room policy.
- Security: see [SECURITY.md](SECURITY.md) for supported versions and safe use.
- Licence: Apache-2.0; see [LICENSE](LICENSE). Upstream prior-art projects are not vendored into the shipped tree.
