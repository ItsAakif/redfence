# ADR-0006: Corpus templates, role accessors, and deletion propagation

Date: 2026-11-12
Status: Accepted
Context: the milestone recorded in
[`docs/verification/lifecycle-breadth-report.md`](../verification/lifecycle-breadth-report.md).

## Context

Three blockers pointed at the same root cause: the corpus was one hardcoded
2-tenant template, the scenario was written against literal ids
(`p_alpha_reader`, `doc_beta_secret`), and deletion had no propagation control
to cache or memory. Measuring lifecycle breadth required all three to move
together, without breaking the pinned secured/vulnerable outcomes that earlier
gates were verified against.

## Decisions

1. **Templates are additive extensions of one classic skeleton.** Every
   `TemplateSpec` builds the classic corpus and then adds structure (tenants,
   tiers, documents). The `classic` template is byte-identical to
   `redfencebench-0.1.0` (content hashes pinned by test). This keeps the
   reference G2 base stable and makes the isomorphism contract small enough to
   actually test (`template_isomorphic`).
2. **The isomorphism contract fixes structure, not surface text.** Canonical
   principal ids (`p_<tenant>_reader|lead|intern`), one confidential document
   per anchor tenant owning the `alpha`/`beta` canaries, fixed anchor phrases
   (`launch code`, `access token`), and a primary malicious document. Varying
   role/group names would break ACL coordination for no measurement gain;
   diversity is expressed through tenant/doc/tier composition instead.
3. **Role accessors over a step-DSL.** The scenario now resolves principals and
   documents through `Corpus` accessors instead of a lifecycle-scripting
   language. The refactor is pinned by the pre-refactor reference outcome map
   (`tests/test_scenario.py`). A DSL can be introduced later only if template
   lifecycles diverge structurally.
4. **Deletion propagation is a target control, not an oracle convention.** The
   secured target purges cache (by doc versions + chunk attribution) and memory
   (by canary attribution) on delete. Deletion deliberately does not bump the
   authorization epoch: an epoch bump would auto-invalidate the cache and mask
   the fault we want to observe. The two half-failures are separate faults so
   each control is measured independently.
5. **Canary-based memory attribution is accepted.** A memory record is derived
   from a document only when its text contains that document's canary. Records
   without markers are conservatively retained. Control and oracle use the same
   rule, so the measurement is coherent; marker-less memory remains outside
   deletion-propagation measurement (declared limitation).
6. **Multi-oracle overlap is accepted and documented.** One fault may surface
   through several oracles (e.g. a stale post-deletion replay also leaks
   context). `FAULT_ORACLE` names the primary detector; overlap is never
   double-counted as separate fault coverage.
7. **ACL modification is a lifecycle action with a global epoch bump.** The
   modification updates stored chunk ACLs and increments the single
   authorization epoch, invalidating all cache entries. Document-level cache
   epochs are future work; the coarse bump is fail-closed and consistent with
   `revoke()`.
8. **`HELDOUT_FAMILIES` is single-sourced in `dataset.py`.** The corpus manifest
   and the executable family registry cannot drift apart.

## Consequences

- The development scenario, held-out families, runner, and statistics all accept
  a `template` parameter; the sweep (`scripts/run_template_sweep.py`) proves G2
  invariants per template.
- The dataset version is `redfencebench-0.2.0`; the public manifest gains a
  `template` key.
- Deferred: step-DSL lifecycle engine, document-level cache epochs, learned
  embeddings, retention/replica/backup stores, Docker-default execution path.
