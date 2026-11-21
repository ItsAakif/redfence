# RedFence 0.3.0 - External-Target Boundary Report

Status: **current source of truth for 0.3.0 verification claims.**
Date: 2026-11-21.
Companion records: [`raw/70-*`](raw/70-v030-tests.txt) - [`raw/85-*`](raw/85-v030-ci.txt)
(immutable captures), [`docs/claims.md`](../claims.md) (claim register) and
[`docs/decisions/`](../decisions/) (accepted ADRs).

Every local number below is copied from a `raw/70-*` - `raw/84-*` capture made
on the verification host on 2026-11-21; the CI results in section 3 are copied
from `raw/85-*`. A claim without such a capture is
**NOT VERIFIED**. The 0.2.0 hardening record in
[`hardening-report.md`](hardening-report.md) remains the historical 0.2.0 source
of truth and is not superseded for 0.2.0 numbers.

## 1. Scope

In scope for this release and exercised by the captures:

1. **Contract v1** - schema, bounded loader and adapters; `contract validate`
   and `contract test` exit semantics.
2. **Adapters** - deterministic `mock` reference target and the `callable`
   adapter; the `http` adapter is covered by fake-transport tests in `raw/70`
   and by real loopback-socket tests in `raw/83`.
3. **`ContractRun`** - matrix, lifecycle, budget and redaction contract oracles.
4. **New oracle families** - lineage, existence, repair, capability, MCP and
   retention/replica, alongside the unchanged fifteen deterministic oracles.
5. **Capability** - attenuation, expiry and scope checks.
6. **MCP** - manifest, rug-pull and shadowing checks.
7. **Retention** - deletion durability and replica consistency.
8. **Mutation self-test** - known-good control removal must be killed and a
   behaviour-preserving mutant must survive.
9. **Property tests** - Hypothesis-backed invariants; the `property` extra is
   installed locally and all four property tests pass (`raw/82`).
10. **Interop** - optional Inspect AI and OpenTelemetry adapters behind lazy
    imports, exercised by the full suite in `raw/70`.
11. **Dataset `redfencebench-0.4.0`** - provenance-schema/config bump.

## 2. Measured results

| Area | Capture | Result |
| --- | --- | --- |
| Full suite | [`raw/70`](raw/70-v030-tests.txt) | `613 passed, 2 skipped`, exit `0` |
| Coverage | [`raw/71`](raw/71-v030-coverage.txt) | `94%` total (4236 statements, 244 missed), exit `0` |
| Demo / G2 | [`raw/72`](raw/72-v030-demo.txt) | G2 `PASS`, 12/12 faults discriminated; secured exit `0`, vulnerable exit `1` |
| Contract validate (mock) | [`raw/73`](raw/73-v030-contract.txt) | `valid contract=mock-boundary-demo`, exit `0` |
| Contract test (mock) | [`raw/73`](raw/73-v030-contract.txt) | exit `0`; matrix `3/3` satisfied, budget `3/32` requests, lifecycle and redaction `UNSUPPORTED` (no evaluable observation) |
| Contract validate (invalid) | [`raw/73`](raw/73-v030-contract.txt) | `error=unsupported_format path=README.md`, exit `3` (intentional; header exit is therefore `3`) |
| Held-out families | [`raw/74`](raw/74-v030-heldout.txt) | 7/7 families `ok=True`; every secured run exit `0`, every vulnerable run exit `1` |
| Template sweep | [`raw/75`](raw/75-v030-sweep.txt) | 3 templates, 12 faults, 42 cells, `0` failures |
| Statistics | [`raw/76`](raw/76-v030-statistics.txt) | 8 families, 24 rows over 25 seeds; `24` separated, `0` unevaluable, `all_deterministic=True` |
| Mutation self-test | [`raw/77`](raw/77-v030-mutation.txt) | known-good killed, known-bad survived: `matched=2 unexpected=0 killed=1 survived=1 score=1.00` |
| Ruff | [`raw/78`](raw/78-v030-ruff.txt) | `All checks passed!`, exit `0` |
| Mypy | [`raw/79`](raw/79-v030-mypy.txt) | `no issues found in 63 source files`, exit `0` |
| Dependency check | [`raw/80`](raw/80-v030-pip-check.txt) | `No broken requirements found.`, exit `0` |
| Library-level facets | [`raw/81`](raw/81-v030-facets.txt) | `examples/facets_demo.py` exit `0`; every new oracle registry ran on deterministic fixtures, including two deliberate `violation` outcomes (retention durability, replica consistency) |
| Property tests | [`raw/82`](raw/82-v030-property.txt) | 4 property tests pass, exit `0` |
| Loopback HTTP transport | [`raw/83`](raw/83-v030-http-loopback.txt) | `6 passed`, exit `0` |
| Import smoke | [`raw/84`](raw/84-v030-import-smoke.txt) | prints version `0.3.0` and `[]` for loaded optional modules, exit `0` |

Notes on the measurements:

- The contract lifecycle and redaction oracles return `UNSUPPORTED` on the
  checked-in mock contract because no lifecycle step replays a cell and no
  configured secret environment variable is set. That is an honest
  "no evaluable observation" result, not a pass. The corrected lifecycle
  semantics are exercised by the suite in `raw/70`.
- The statistics intervals are zero-width because the synthetic target is
  deterministic across seeds; they are not evidence about a human sample.
- Mutation score is report-only in 0.3.0.
- The `raw/73` header exit is `3` because the final command deliberately
  validates `README.md`, which is not a supported contract format; the two mock
  commands in the same capture exit `0`.
- The numbers in this table belong to the immutable captures `raw/70`-`raw/84`.

## 3. Verified by CI

The tag `v0.3.0` (commit `5d6965f`) passes the four-cell GitHub Actions matrix
in [`raw/85`](raw/85-v030-ci.txt):

| Run | Ref | Cells | Result |
| --- | --- | --- | --- |
| [44899468692](https://github.com/ItsAakif/redfence/actions/runs/44899468692) | tag `v0.3.0` / `5d6965f` | ubuntu-latest / Python 3.11, ubuntu-latest / Python 3.12, windows-latest / Python 3.11, windows-latest / Python 3.12 | all success, exit `0` |
| [44899274131](https://github.com/ItsAakif/redfence/actions/runs/44899274131) | `main` | same four cells | all success, exit `0` |

The workflow installs `[dev,contract,property,inspect,otel]` and runs the test
suite, ruff, mypy, `pip check`, the import smoke test, the example contract
validate/test, the mutation self-test and the property tests on each cell. This
establishes CI execution, Python 3.11/3.12 and Linux as verified for this
release.

The first push run, [44898592110](https://github.com/ItsAakif/redfence/actions/runs/44898592110),
failed on both Ubuntu cells: `test_config_digests_are_pinned` hashed raw CRLF
bytes on the Linux checkout, so the LF-pinned config digests did not match.
Commit `5d6965f` normalises CRLF to LF before hashing and adds
`test_config_digest_is_line_ending_independent`; all four cells then passed.
This Windows-versus-Linux portability bug is recorded in section 7.

## 4. Review findings fixed

The 2026-11-20 adversarial review raised fourteen findings. The two release
blockers (F1, F2) and the F3/F6/F8/F9/F12 batch are fixed; each one is covered
by the suite in [`raw/70`](raw/70-v030-tests.txt) and, where it changes a
command, by [`raw/73`](raw/73-v030-contract.txt).

- **F1 - lifecycle expectation inversion.** Replayed cells were compared with
  their pre-event `expect`, so a correct target that revoked access was reported
  as a violation and only a broken target passed. The post-step expectation is
  now derived from the step: `deny` stays `deny`; an `allow` cell becomes `deny`
  when `revoke`/`expire` matches its identity, or `delete` matches its source;
  `update` leaves authorization unchanged. A correct target exits `0`
  (`raw/70`; `contract test` exit `0` in `raw/73`).
- **F2 - escaped-secret redaction.** Stored observations are serialised with
  `ensure_ascii=True`, so a secret containing a quote, backslash, tab or
  non-ASCII character can appear only in an escaped form. The redaction oracle
  and the report redactor now compare the raw value plus the
  `json.dumps(value)[1:-1]` forms with `ensure_ascii` both `False` and `True`,
  deduplicated (`raw/70`, `raw/71`). The checked-in mock still reports the
  oracle `UNSUPPORTED` because no configured secret variable is set
  (`raw/73`), which is not a pass.
- **F3 - capability-token subject binding.** `DefaultToolPolicy` now denies a
  token whose `subject` is not the requesting principal and a use before
  `issued_epoch` (`raw/70`).
- **F6 - MCP shadowing false positive.** Shadowing is reported only for a tool
  name declared by more than one manifest, not for a distinct tool legitimately
  owned by a secondary server (`raw/70`).
- **F8 - egress-denial accounting.** The HTTP allowlist is checked before the
  insecure-scheme rule, so an allowlist denial increments
  `budget_obs["egress_denied"]` (`raw/70`; no live HTTP is claimed).
- **F9 - one exit-code API.** `ContractResult.exit_code` now derives from scored
  evidence (`VIOLATION -> 1`, inconclusive/wholly unsupported -> 2, otherwise
  `0`) with the bare-runner observation fallback only when evidence is empty;
  `contract test` exits `0` in `raw/73`.
- **F12 - lifecycle cross-reference validation.** Matrix cells and lifecycle
  steps must name declared identities/sources at load time, so a typo cannot
  become a silent no-op or a spurious violation (`raw/70`).

F11 (mutation-score polarity) was fixed under the mutation task and is captured
at [`raw/77`](raw/77-v030-mutation.txt) with `score=1.00`. F7 (conservative
`..` rejection) was left unchanged: it is a false-positive risk in a model
name, not an authorization bypass.

## 5. Library-level facets

Lineage, existence, repair, capability, MCP and retention/replica are
**library-level facets in 0.3.0**. They are exercised end-to-end through the
public API by [`examples/facets_demo.py`](../../examples/facets_demo.py) and by
the suite, but they are **not** CLI subcommands: `redfence run`, `demo` and
`contract test` still load only `contract_oracles`/`default_oracles`. The claim
status is therefore `partial`, not "shipped as a CLI feature" (F5).

`raw/81` shows one line per oracle for every registry:

- lineage: secured `ScenarioRun` -> `build_lineage` -> `DerivationOracle`;
- existence: identical pair `SATISFIED`, differing pair `VIOLATION`, and four
  two-sample pairs through the exact permutation test;
- repair: stale-cache-after-deletion fixture, `apply_repair(purge_cache=True)`,
  selective and collateral oracles;
- capability: two-link `DelegationChain` plus `CapabilityUse`, attenuation,
  expiry and scope;
- MCP: benign and poisoned-description manifests fetched over stdio from
  `tests/fixtures/mcp_server.py`, manifest/rug-pull/shadowing;
- retention: a replica with `propagate_deletions=False`, durability and replica
  consistency.

The demo exits `0` even when it reports a deliberate `VIOLATION` (the separated
permutation, poisoned manifest and non-propagating replica); it exits `2` only
if a facet raises. Running it loads none of `yaml`, `inspect_ai`,
`opentelemetry` or `hypothesis` (subprocess check in the suite, `raw/70`).

## 6. Limitations and residual risk

- `apply_repair` mutates the live run target (cache/memory/ACL/ingest) and has no
  rollback. Treat it as the last operation on a dedicated `ScenarioRun`; later
  observations on the same run see repaired state (F4).
- Contract `expire` lifecycle steps are sent to the adapter as `revoke`; the two
  are not distinguished on the target boundary in 0.3.0 (F10).
- `ContractResponse.samples` is parsed but not stored, and
  `build_existence_pairs` does not fill samples, so the permutation oracle is
  reachable through the API only, not from any adapter (F13).
- YAML contract loading requires the optional `contract` extra (PyYAML). The
  extra is installed in the verification venv and the YAML path is covered by
  the full suite in `raw/70`; the checked-in mock capture in `raw/73` uses JSON,
  which needs no optional dependency (F14).
- DNS rebinding remains a residual risk for an allowlisted host: the allowlist
  checks the request hostname, not the resolved address. Live third-party HTTP
  is not verified in this release; only the loopback transport is (section 9).
- F7: `..` is rejected in every contract string, including a model name; this is
  intentionally conservative and is a false-positive risk rather than a bypass.

## 7. Version and compatibility break list

- Package version is **`0.3.0`**; dataset version is
  **`redfencebench-0.4.0`**.
- The dataset bump is a **provenance-schema/config change, not a content
  change**: classic document content and `CLASSIC_CONTENT_HASHES` are unchanged.
- Lifecycle **config-digest pins are computed over LF-canonical bytes** (CRLF is
  normalised to LF before hashing), and `tests/test_dataset.py` has a CRLF/LF
  regression test, so the digests agree on Windows and Linux. The first CI run
  found the raw-CRLF digest mismatch on Ubuntu; `5d6965f` fixed it (section 3).
- Because the dataset version is part of scenario identity, **every
  `scenario_id` and every `evidence_id` changes**, as do report bytes and
  manifest digests. Historical `raw/60-*` captures keep their old ids and are
  never edited; the new values belong to `raw/70-*`.
- New CLI surface: `redfence contract validate` and `redfence contract test`.
- New optional extras: `contract` (PyYAML), `property` (Hypothesis), `inspect`
  and `otel`. Optional imports are lazy; `import redfence` imports none of them.
- The existing fifteen deterministic oracles and `default_oracles()` are
  unchanged.

## 8. NOT VERIFIED

The following are **not** exercised by the 0.3.0 captures and must not be read as
verified:

- Live third-party HTTP / OpenAI-compatible endpoints. The loopback transport is
  locally verified (section 9), but no external service is contacted.
- Docker / G6 / G9 (historical 2026-11-10 fixtures, not re-run).

## 9. Verified locally

The following are **verified locally** on the verification host with
`[dev,contract,property,inspect,otel]` installed, each backed by a capture:

- **Optional extras install and dependency consistency** - `raw/80` reports
  `No broken requirements found.` with all extras installed; `raw/84` prints
  `0.3.0` and an empty list of loaded optional modules.
- **YAML loader** - the full suite in `raw/70` exercises the YAML contract path
  (valid load plus duplicate-key, merge-key, anchor, tag, non-string-key and
  deep-nesting rejection) with the `contract` extra installed.
- **Hypothesis properties** - `raw/82` exits `0` with 4 property tests.
- **Inspect AI adapter** - the full suite in `raw/70` builds a task with
  `inspect_ai` installed; the dataset targets are `["allow", "deny"]`.
- **OpenTelemetry export** - the full suite in `raw/70` emits one span per
  evidence item through the installed SDK.
- **Loopback HTTP transport** - `raw/83` exits `0` with 6 tests against a real
  `127.0.0.1` server: success; redirect rejection with zero requests reaching
  the redirect target; oversize truncation; egress denial; `insecure_http`
  rejection before any connection; and a JSON request body carrying the action
  and identity fields.

Live third-party HTTP and Docker remain **NOT VERIFIED** (section 8). CI
execution, Python 3.11/3.12 and Linux are verified by section 3.

## 10. Publication

The repository is prepared for publication at `ItsAakif/redfence`, tagged
`v0.3.0`. The CI workflow installs all extras
(`[dev,contract,property,inspect,otel]`) and runs the suite, lint, type check,
dependency check, import smoke, contract example and property tests. CI
execution is verified on all four cells by the tag run (section 3).

## 11. Evidence index

- [`raw/70-v030-tests.txt`](raw/70-v030-tests.txt)
- [`raw/71-v030-coverage.txt`](raw/71-v030-coverage.txt)
- [`raw/72-v030-demo.txt`](raw/72-v030-demo.txt)
- [`raw/73-v030-contract.txt`](raw/73-v030-contract.txt)
- [`raw/74-v030-heldout.txt`](raw/74-v030-heldout.txt)
- [`raw/75-v030-sweep.txt`](raw/75-v030-sweep.txt)
- [`raw/76-v030-statistics.txt`](raw/76-v030-statistics.txt)
- [`raw/77-v030-mutation.txt`](raw/77-v030-mutation.txt)
- [`raw/78-v030-ruff.txt`](raw/78-v030-ruff.txt)
- [`raw/79-v030-mypy.txt`](raw/79-v030-mypy.txt)
- [`raw/80-v030-pip-check.txt`](raw/80-v030-pip-check.txt)
- [`raw/81-v030-facets.txt`](raw/81-v030-facets.txt)
- [`raw/82-v030-property.txt`](raw/82-v030-property.txt)
- [`raw/83-v030-http-loopback.txt`](raw/83-v030-http-loopback.txt)
- [`raw/84-v030-import-smoke.txt`](raw/84-v030-import-smoke.txt)
- [`raw/85-v030-ci.txt`](raw/85-v030-ci.txt)
