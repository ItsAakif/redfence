# ADR-0003: One configurable target, independently injectable faults

- **Status:** accepted
- **Context:** Mandate section 8 requires one RAG target implementation with
  secured/vulnerable/partial profiles and individually controllable faults, not
  two separately developed applications.
- **Decision:** A single `ConfigurableRAGTarget` guarded by `FaultFlags`; exactly
  one flag per security control. Profiles (`secured`, `vulnerable`, `partial`)
  are presets; single-fault runs are supported for discriminative testing.
- **Consequence:** Removing one control provably reproduces its associated
  failure, and the same suite must pass the secured configuration (G2).
