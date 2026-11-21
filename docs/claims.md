# Claim register

Every externally visible RedFence claim must point at a capture or at
test-module evidence, or be marked `not verified`. Statuses are limited to
`verified`, `partial` and `not verified`. A `-` evidence path is allowed only
for a `not verified` row. A `verified` or `partial` row must point at a file
that exists in the tree.

The current 0.3.0 captures are `docs/verification/raw/70-*` … `raw/85-*`,
summarised in [`docs/verification/v030-report.md`](verification/v030-report.md).
Historical `60-*` captures remain valid for the 0.2.0 release and are not
edited or reused as 0.3.0 evidence. The historical 0.2.0 claim
`259→507 tests pass` is superseded by the 0.3.0 count below.

All optional extras are installed locally. The YAML, Hypothesis, Inspect AI,
OpenTelemetry and loopback HTTP paths are verified by the captures below
(`raw/70`, `raw/82`, `raw/83`), and `raw/84` confirms that a plain
`import redfence` loads none of the optional modules.

| claim | evidence | status | command |
| --- | --- | --- | --- |
| 613 tests pass, 2 skipped (0.3.0) | `docs/verification/raw/70-v030-tests.txt` | verified | `python -m pytest -o addopts="" -q` |
| Test coverage is 94% over `src/redfence` (4236 statements, 244 missed) | `docs/verification/raw/71-v030-coverage.txt` | verified | `python -m pytest -o addopts="" -q --cov=redfence --cov-report=term-missing` |
| Demo discriminates 12/12 faults (G2 PASS); secured exits 0, vulnerable exits 1 | `docs/verification/raw/72-v030-demo.txt` | verified | `python -m redfence.cli demo --out reports\final-v030-demo` |
| reports are byte-identical for fixed inputs (covered by suite determinism tests; not a dedicated capture) | `docs/verification/raw/70-v030-tests.txt` | partial | `python -m pytest -o addopts="" -q` |
| `contract validate` returns 0 on the checked-in mock contract | `docs/verification/raw/73-v030-contract.txt` | verified | `python -m redfence.cli contract validate examples\contracts\mock.json` |
| `contract test` returns 0 on the checked-in mock contract | `docs/verification/raw/73-v030-contract.txt` | verified | `python -m redfence.cli contract test examples\contracts\mock.json --adapter mock --out reports\final-v030-contract` |
| contract validate returns 3 on invalid input (README.md) | `docs/verification/raw/73-v030-contract.txt` | verified | `python -m redfence.cli contract validate README.md` |
| Contract lifecycle and redaction oracles report `UNSUPPORTED` when no observation is evaluable | `docs/verification/raw/73-v030-contract.txt` | verified | `python -m redfence.cli contract test examples\contracts\mock.json --adapter mock` |
| Seven held-out families separate secured from vulnerable | `docs/verification/raw/74-v030-heldout.txt` | verified | `python scripts\run_heldout.py --out reports\final-v030-heldout` |
| Three templates × 12 faults (42 cells) sweep with 0 failures | `docs/verification/raw/75-v030-sweep.txt` | verified | `python scripts\run_template_sweep.py` |
| 8 families / 24 rows over 25 seeds are separated and deterministic | `docs/verification/raw/76-v030-statistics.txt` | verified | `python scripts\run_statistics.py --seeds 25 --templates` |
| Mutation self-test kills the known-good control and keeps the known-bad mutant (score 1.00, report-only) | `docs/verification/raw/77-v030-mutation.txt` | verified | `python scripts\run_mutation.py` |
| Ruff passes with 0 findings | `docs/verification/raw/78-v030-ruff.txt` | verified | `ruff check . --no-cache` |
| Mypy passes with 0 issues over 63 source files | `docs/verification/raw/79-v030-mypy.txt` | verified | `mypy src` |
| `pip check` reports no broken requirements | `docs/verification/raw/80-v030-pip-check.txt` | verified | `python -m pip check` |
| Lifecycle post-step expectations are derived from the step; a correct target exits 0 (F1) | `docs/verification/raw/70-v030-tests.txt` | verified | `python -m pytest -o addopts="" -q` |
| Redaction compares raw and JSON-escaped secret forms (F2) | `docs/verification/raw/70-v030-tests.txt` | verified | `python -m pytest -o addopts="" -q` |
| Lineage, existence, repair, capability, MCP and retention facets run end-to-end through the public API and `examples/facets_demo.py`; they are not CLI subcommands in 0.3.0 | `docs/verification/raw/81-v030-facets.txt` | partial | `python examples\facets_demo.py` |
| live HTTP adapters work against third-party endpoints (loopback transport verified separately) | `-` | not verified | `-` |
| Loopback HTTP transport works against a real local socket: success, redirect rejection, oversize truncation, egress denial, insecure-scheme rejection and JSON request body | `docs/verification/raw/83-v030-http-loopback.txt` | verified | `python -m pytest -o addopts="" -q tests\test_http_transport.py` |
| Inspect AI execution works with the `inspect` extra installed | `docs/verification/raw/70-v030-tests.txt` | verified | `python -m pytest -o addopts="" -q` |
| OpenTelemetry emission works with the `otel` extra installed | `docs/verification/raw/70-v030-tests.txt` | verified | `python -m pytest -o addopts="" -q` |
| Hypothesis property tests execute with the `property` extra installed | `docs/verification/raw/82-v030-property.txt` | verified | `python -m pytest -m property -q` |
| PyYAML runtime path works with the `contract` extra installed | `docs/verification/raw/70-v030-tests.txt` | verified | `python -m pytest -o addopts="" -q` |
| `import redfence` loads none of `yaml`, `hypothesis`, `inspect_ai` or `opentelemetry` | `docs/verification/raw/84-v030-import-smoke.txt` | verified | `python -c "import redfence, sys; print(redfence.__version__); print([m for m in ('yaml','hypothesis','inspect_ai','opentelemetry') if m in sys.modules])"` |
| CI execution passes | `docs/verification/raw/85-v030-ci.txt` | verified | `gh run view 44899468692` |
| Python 3.11 / 3.12 pass | `docs/verification/raw/85-v030-ci.txt` | verified | `gh run view 44899468692` |
| Linux passes | `docs/verification/raw/85-v030-ci.txt` | verified | `gh run view 44899468692` |
| Docker/G6/G9 re-run | `-` | not verified | `-` |
