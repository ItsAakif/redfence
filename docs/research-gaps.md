# Research gaps and differentiation

## What already exists (do not reproduce)

- Broad LLM vulnerability scanning: **garak**, **PyRIT**, **Promptfoo**.
- Adaptive/multi-turn attack orchestration: **PyRIT** (Crescendo, TAP, Skeleton
  Key), Promptfoo (Hydra, Meta Agent).
- Agent tool-injection benchmarks: **InjecAgent**, **AgentDojo**, **ASB**,
  **AgentHarm**.
- RAG poisoning benchmarks: **SafeRAG**, PoisonedRAG benchmark.
- RAG knowledge-extraction leakage: **LeakDojo**.
- RAG quality evaluation: **ARES**, RAGAS, TruLens.
- Cache security: semantic cache poisoning and key-collision attacks (NDSS 2026;
  arXiv 2601.23088; "Similarity Is Not Validity"), and **Safe and Sufficient
  Caching** (SSC, EMNLP 2026 Industry Track) as the validity-constraint design.
- Soft-deleted embedding reconstruction: "Ghost Vectors" (arXiv 2606.18497).
- Deletion/permission propagation across RAG stores and caches (industry write-ups).
- Permission-aware RAG evaluation: ContextFence, VaultRAG, ogx-evals, and a
  Hugging Face permission-aware enterprise RAG dataset with `acl_time_travel`.
- Agent memory security: MemSecBench, Trojan Hippo, MemPoison, MPBench, and the
  EMNLP 2026 long-term memory security survey (six-phase lifecycle).
- Embedding inversion via ordered provenance: MIRAGE (EMNLP 2026).
- Standards: OWASP AISVS C8, OWASP LLM/Agentic Top 10, OWASP ACS v0.1.4.

**RedFence must not be described as the first RAG security benchmark or the
first adaptive red-teaming platform.** Those claims are false.

## Gaps that remain insufficiently addressed

1. **Cross-store lifecycle consistency.** Cache, index and memory are usually
   studied separately. No widely-used artifact tests whether a single
   permission/revocation event is consistently honoured at *every* disclosure
   path (direct, cached, memory-mediated, tool-mediated) with **independent**
   oracles per path.
2. **Authoritative-vs-stored ACL oracles.** Metadata-loss/tampering faults are
   hard to detect if the oracle trusts stored metadata. Evaluating against an
   authoritative ACL is a methodological point that is easy to get wrong.
3. **Discriminative-validity fixtures.** Most suites only fail vulnerable
   software. Requiring the same suite to *pass* on a correctly secured
   configuration (per fault) is under-emphasised.
4. **Defence composition is non-monotonic.** Adding semantic layers can increase
   attack success; security–utility trade-offs are rarely reported jointly.
5. **Measurement validity.** LLM-judge ASR is unstable (2026 literature). A
   deterministic-first benchmark with declared judge coverage is uncommon.

## Defensible contribution (precise wording)

> RedFenceBench is a reproducible benchmark that treats **authorization state as
> a first-class, evolving object** and verifies that every disclosure path in a
> stateful RAG+agent application respects it — across the vector **index**, the
> response **cache**, and persistent **memory** — using **deterministic oracles
> evaluated against an authoritative ACL**, on both **vulnerable and secured**
> configurations, while reporting **security and utility together**.

The novelty is composition + methodology, not any single mechanism. Every
individual component is prior art and is cited as such.

## Unresolved research questions

- Does an adaptive attack-selection policy discover more **distinct** confirmed
  vulnerabilities per fixed budget than random/greedy/UCB/Thompson baselines?
  (Separate research spec required before implementation.)
- How should non-additive defence composition be characterised across stores?
- What is a valid cross-system comparison under scenario-clustered dependence?
