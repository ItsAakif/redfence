# Contributing

RedFence is research software. Contributions are welcome when they preserve the
deterministic core, the evidence contract and the honest-measurement rules in the
ADRs.

## Development setup (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,contract]"
.\.venv\Scripts\python.exe -m pytest -o addopts="" -q
```

Optional extras are only needed for their own tests:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[property]"   # Hypothesis tests
.\.venv\Scripts\python.exe -m pip install -e ".[inspect]"    # Inspect adapter
.\.venv\Scripts\python.exe -m pip install -e ".[otel]"       # OTel adapter
```

Python 3.11+ is required. The verification host used Python 3.14.7.

## Gates

Run all of these before proposing a change:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts="" -q
.\.venv\Scripts\ruff.exe check . --no-cache
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -c "import redfence"
.\.venv\Scripts\python.exe -m redfence.cli contract validate examples\contracts\mock.json
.\.venv\Scripts\python.exe -m redfence.cli contract test examples\contracts\mock.json --adapter mock --out reports\contract-demo
.\.venv\Scripts\python.exe scripts\run_mutation.py
```

Property tests are optional and marked `property`:

```powershell
.\.venv\Scripts\python.exe -m pytest -m property -q
```

They skip cleanly when `hypothesis` is not installed.

## Test rules

- **No network and no Docker in the default test path.** Use fakes, fixtures and
  in-process transports. A test that needs a live endpoint is not part of the
  default suite.
- **No wall clock or randomness in the decision path.** Use the logical clock and
  fixed seeds. Report bytes must stay deterministic for fixed inputs.
- **Never fabricate a `SATISFIED`.** A zero-unit facet is `UNSUPPORTED`; an
  unsupported adapter action produces no observation.
- **Keep the frozen observation keys.** Add a sibling model (for example
  `ContractRun`) instead of widening `ScenarioRun` or adding optional keys.
- **Do not edit historical captures** under `docs/verification/raw/`. Add a new
  numbered capture instead.

## Clean-room and prior-art policy

- `.prior-art/` and `.prior-art-clones/` are study material. They are **not**
  vendored, copied or imported into the shipped tree.
- Implement from the documented behaviour and the standards, not from copied
  source. If you consult an upstream project, record it in
  `docs/prior-art/inventory-and-licences.md`.
- Do not paste code, tests, fixtures, prompts or documentation from a project
  whose licence is incompatible with Apache-2.0.

## Licence rules

- New source, tests and docs are contributed under Apache-2.0 (see `LICENSE`).
- Dependencies must be compatible with Apache-2.0. New optional extras must be
  declared in `pyproject.toml`, imported lazily, and must not become a default
  dependency.
- Do not add a dependency that is required by `import redfence`.
- Preserve third-party notices and attribution where required.

## Pull requests

- Keep the change scoped; do not mix a behaviour change with a release-doc edit.
- Add or update a test for every behaviour change. Do not delete a passing test
  to make a change easier.
- Update the claim register (`docs/claims.md`) when a public claim changes. A
  `verified` row must point at an existing capture; otherwise mark it
  `not verified`.
- Record an ADR for a change to a trust boundary, metric definition, exit code or
  observation contract.
