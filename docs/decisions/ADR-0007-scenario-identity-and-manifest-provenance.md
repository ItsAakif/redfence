# ADR-0007: Scenario/corpus identity and run-manifest provenance

Date: 2026-11-19
Status: **Accepted** (0.2.0, 2026-11-19)
Defect: D2, D3
Related: `scripts/run_statistics.py`, `docs/benchmark-spec.md`, `docs/dataset-card.md`

## Context

`scenario_id(profile, seed)` in `bench/dataset.py` ignores the corpus template
and the injected fault set. `run_revocation_scenario` derives the id from
`profile` + `seed` only; held-out families use a separate
`stable_id("heldout", family, profile, seed)` that also ignores template and
faults. Evidence ids embed the scenario id (`stable_id("ev", scenario_id,
oracle_id)`), and the dev runner names reports `{scenario_id}.json`. Therefore:

- the same scenario id is reused across `classic`, `secret_tier` and
  `three_tenant`;
- two different custom fault sets share `scenario_id(..., "custom", seed)`;
- evidence ids collide across templates;
- report files overwrite each other when templates or custom faults share an
  output directory.

`build_manifest` records seed, profile, faults and canary markers, but not the
template or per-document content hashes; it cannot prove which corpus produced a
run. It also injects `oracle_pid` when isolation is enabled, so the "reproducible
manifest" differs on every run.

## Decision

1. **One identity function.** Add a shared `scenario_identity(...)` /
   `scenario_id(...)` in `bench/dataset.py` whose deterministic tuple is:

   ```
   (DATASET_VERSION, kind, profile, template, seed, *sorted(set(faults)))
   ```

   `kind` is `"revocation"` for the dev scenario and the family name for a
   held-out scenario. The profile label is `secured|vulnerable|partial|custom`;
   faults are the enabled `FaultFlags` names. `scenario_id` keeps the legacy
   two-positional-argument call and adds keyword-only `kind`, `template`, `faults`
   and `dataset_version` parameters.

2. **`ScenarioRun` carries its kind.** Add `scenario_kind: str = "revocation"`
   (additive, defaulted). Dev sets `"revocation"`; held-out sets the family.
   `serialize_run`/`_reconstruct` round-trip it and the corpus template.

3. **Evidence ids remain `stable_id("ev", scenario_id, oracle_id)`.** No second
   identity scheme. Fixing the scenario id fixes evidence ids.

4. **Corpus manifest schema 2.** `Corpus.manifest()` adds:
   - `manifest_schema: 2`;
   - per-document `acl_fingerprint` (canonical-JSON SHA-256 of the authoritative
     document ACL);
   - per-document `canary_markers` (hashed markers only; never cleartext);
   - `principal_entitlements: {principal_id: entitlement_fingerprint}`.

   Classic document content and content hashes are unchanged.

5. **Run manifest embeds provenance.** `build_manifest` adds
   `manifest_schema`, `scenario_kind`, `template`, sorted `faults`,
   `faults_sha256`, `corpus_manifest`, `corpus_manifest_sha256`, and
   `oracle_isolation` (`"in_process"` or `"subprocess"`). It uses
   `run.corpus.dataset_version` and `redfence.version.__version__`, not module
   literals. It **does not** contain a PID; `CampaignResult.oracle_pid` remains
   available for the isolation test.

6. **Report filenames derive from `scenario_id`.** Dev runner keeps
   `{scenario_id}.{json,html}`; held-out stops using `{family}.{profile}` and uses
   `{scenario_id}.{json,html}`.

7. **Canonical JSON digest helper.** Add `json_digest(payload)` to
   `core/ids.py` (`json.dumps(..., sort_keys=True, separators=(",", ":"),
   ensure_ascii=True)` then `content_hash`). Use it for ACL, entitlement and
   manifest digests.

## Alternatives rejected

- **Add only `template` to the id.** Custom fault sets still collide; evidence
  ids still collide across custom runs.
- **Hash the whole `ScenarioRun`.** Circular (evidence ids are part of the run),
  and it would include timestamps and observations.
- **Random UUID per run.** Not reproducible; contradicts the research artifact.
- **Keep the ID and change only report filenames.** Evidence ids still collide;
  provenance still cannot distinguish templates.
- **Keep `oracle_pid` in the manifest.** It makes every isolated run's manifest
  differ, directly contradicting "reproducible manifest".
- **Trust `DATASET_VERSION` the module constant in the manifest.** The run's own
  corpus knows its version; using the constant hides drift.

## Migration impact

- Every `scenario_id` and `evidence_id` changes. Tests do not pin old values;
  property tests are added. `docs/verification/raw/*` contain old ids and are
  immutable history (see the spec's raw-file policy).
- Report filenames change for held-out runs. `reports/` is git-ignored.
- `test_oracle_isolation` must assert `oracle_isolation == "subprocess"` and the
  absence of `oracle_pid` in the manifest instead of equality with
  `result.oracle_pid`.
- `DATASET_VERSION` → `0.3.0`; checked-in dataset artifacts regenerate.
- Isolated snapshots gain `template`/`scenario_kind`; defaults keep old payloads
  readable.

## Rollback

Revert the identity/manifest commit. Old ids remain reproducible from the old
code; no persisted state or published index depends on them (confirm with the
owner before release). Dataset artifacts revert with the same revert.

## Acceptance

See task contracts T2.1–T2.3: distinctness tests for template/fault/kind,
legacy call compatibility, manifest digest equality, no PID, isolated manifest
reproducibility, dataset goldens and artifact equality.
