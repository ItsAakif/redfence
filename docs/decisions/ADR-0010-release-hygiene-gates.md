# ADR-0010: Release hygiene gates — lint, type check, CI scope

Date: 2026-11-19
Status: **Accepted** (0.2.0, 2026-11-19)
Defect: D11
Related: `pyproject.toml`, `.gitignore`, `.prior-art/`, `.verify/`

## Context

The repository is intended for public release as a research artifact. Current
state (observed 2026-11-19):

- `ruff check .` reports **13,723** errors. **13,667** come from `.prior-art/`
  (git-ignored upstream clones), **1** from `.verify/`, and **55** from the
  project's own `src`, `tests`, `scripts`, `datasets` trees. `pyproject.toml` has
  no ruff exclude for `.prior-art` or `.verify`.
- `mypy src` reports **61** errors in 6 files, mostly `object`-typed observation
  dictionaries and `default_oracles() -> list[object]` preventing `oracle.score`
  calls from type-checking.
- There is no `.github/` workflow. "CI exit semantics" is claimed in the README
  but nothing runs in CI.
- `.prior-art/` is git-ignored, but a release author who runs `ruff check .` sees
  a five-figure error count and cannot tell project errors from vendored noise.

## Decision

1. **Ruff scope is explicit.** Add to `[tool.ruff]`:

   ```toml
   extend-exclude = [".prior-art", ".prior-art-clones", ".venv", ".verify",
                     "reports", "runs", "build", "dist", ".mypy_cache",
                     ".pytest_cache", ".ruff_cache"]
   ```

   The gate is `ruff check .` (not only a hand-listed set of directories), so new
   project paths are covered automatically.

2. **The project tree must be lint-clean.** Fix all 55 scoped errors, including
   line length, import order, unused imports and modernisation. `UP042`
   (`str, Enum`) is suppressed locally with a one-line reason
   (`# noqa: UP042 — kept for Pydantic/str-Enum compatibility; StrEnum changes
   str() semantics`), not globally ignored.

3. **Mypy scope is `src`.** Gate: `mypy src` = 0. Tests are not part of the
   blocking gate in 0.2.0 (they can follow); `mypy tests` is reported, not gated.
   - Introduce `bench/observations.py` with `TypedDict`s for retrieval, answer,
     memory, tool, deletion and utility observations.
   - Introduce an `Oracle` Protocol in `bench/oracles.py` with
     `oracle_id: str`, `facet: str`, `score(self, run: ScenarioRun) -> Evidence`;
     `default_oracles() -> list[Oracle]`.
   - `Any` is allowed only at JSON boundaries (`oracle_worker`, `isolated`) and
     Pydantic `model_validate` inputs. Do not silence with blanket `# type:
     ignore` or by changing observation dicts to `dict[str, Any]`.
   - The optional `db/` fallback keeps `# type: ignore[misc]` on the two
     `PlatformBase = None` / `SutBase = None` assignments, with a comment.

4. **CI workflow.** Add `.github/workflows/ci.yml`:
   - matrix: `ubuntu-latest` and `windows-latest`; Python `3.11` and `3.12`;
   - `pip install -e ".[dev]"`;
   - `python -m pytest -o addopts="" -q`;
   - `ruff check .`;
   - `mypy src`;
   - `python -m pip check`;
   - `permissions: contents: read`; no Docker, no services, no secrets.
   - Coverage is printed but **not** gated in 0.2.0 (a threshold is an owner
     decision; see `decisions-needed.md`).

5. **Release-tree hygiene is part of the gate.** The checklist verifies that
   `.prior-art/`, `.venv/`, `.verify/`, `reports/`, `runs/`, caches and
   `.coverage` are not shipped. `.prior-art/` is already git-ignored; the workflow
   does not need it.

## Alternatives rejected

- **Exclude only `.prior-art`.** `.verify/` is local scaffolding and should also
  be excluded; a broad explicit exclude list is easier to audit than a growing
  `--exclude` command line.
- **Lint only `src`.** The shipped artifact includes tests, scripts and the
  dataset generator; they must be lint-clean too.
- **Make mypy pass by changing all observation dicts to `Any`.** It would produce
  a green badge with no useful checking. TypedDicts document the observation
  contract that oracles already rely on.
- **Gate `mypy tests` in 0.2.0.** Test typing is lower value and would grow the
  tranche; report it, gate `src`.
- **Add pre-commit.** Another dependency and another local install step for a
  small research repo; CI plus a documented command is sufficient.
- **Gate coverage at 92%.** Coverage can drop for legitimate reasons (new
  negative tests); the baseline is already 92%. Make it a reported number first.

## Migration impact

- No runtime behaviour change. `pyproject.toml` config changes; line wrapping and
  import order change many files mechanically.
- New files: `bench/observations.py`, `.github/workflows/ci.yml`.
- CI has since run: the first push found a Windows/Linux portability defect
  (CRLF vs LF config digests), fixed in `5d6965f`; the `v0.3.0` tag then passed
  all four cells (Ubuntu/Windows × Python 3.11/3.12). See
  `docs/verification/raw/85-v030-ci.txt`.

## Rollback

Revert the config, type and CI commit. The 55/61 errors return; no runtime
behaviour depends on them. CI can be removed independently by deleting the
workflow file.

## Acceptance

Task contracts T5.1–T5.4: `ruff check .` = 0, `mypy src` = 0, workflow present
and syntactically valid, tests green, no blanket suppressions.
