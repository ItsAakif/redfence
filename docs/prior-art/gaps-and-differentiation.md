# Gaps and differentiation (prior-art view)

See the consolidated analysis in [`../research-gaps.md`](../research-gaps.md).

Summary: RedFence is **not** the first RAG security benchmark or the first
adaptive red-teaming platform. Its defensible contribution is a reproducible,
standards-anchored benchmark that treats **authorization state as a first-class,
evolving object** and verifies consistency across **index, cache, memory and
tool** disclosure paths using **deterministic authoritative-ACL oracles**, on
both vulnerable and secured fixtures, reporting security and utility together.

## Existing functionality RedFence must not reproduce

- General LLM vulnerability scanning and jailbreak libraries (garak, PyRIT,
  Promptfoo).
- Adaptive multi-turn attack orchestration as a primary feature (PyRIT,
  Promptfoo).
- RAG poisoning and knowledge-extraction benchmarks (SafeRAG, LeakDojo,
  PoisonedRAG benchmark).
- RAG quality metrics (ARES, RAGAS, TruLens).
- Runtime prompt-injection *defense* products (Lasso, Invariant).

## Limitations and unresolved prior-art questions

- SHAs, source files and licences for all eight repositories are now captured in
  `inventory-and-licences.md` and `docs/verification/raw/13-prior-art.txt`.
  SafeRAG has no licence file at the cloned root and remains unverified for
  reuse; InjecAgent is MIT.
- Whether any single artifact already fuses index+cache+memory+tool lifecycle
  oracles is not fully established; the Hugging Face permission-aware dataset and
  SSC are the closest and remain the main comparison points before any novelty
  claim.
- MITRE ATLAS identifiers were not re-verified in this milestone; only AML.T0070
  (RAG Poisoning) was previously corroborated. Other identifiers remain
  unverified.
