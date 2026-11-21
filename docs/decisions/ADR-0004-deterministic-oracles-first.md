# ADR-0004: Deterministic oracles before model judging

- **Status:** accepted
- **Context:** 2026 measurement-validity research shows LLM-judge ASR is
  unstable; the mandate requires deterministic verification first and warns
  never to treat a refusal as proof of authorization.
- **Decision:** Every `Scorer` returns typed `Evidence`. Deterministic oracles
  (canary match, ACL recomputation, tool policy, deletion, memory scope) are
  primary. Model-based judging is deferred to a calibrated, secondary mechanism
  whose precision/recall/agreement are reported.
- **Consequence:** Findings are reproducible and evidence-backed; judge
  coverage is explicitly declared rather than assumed.
