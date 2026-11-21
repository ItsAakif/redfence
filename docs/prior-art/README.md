# Prior-art audit

Code-level audit completed during Milestone 3. Eight repositories were
shallow-cloned into `.prior-art/` (git-ignored, outside the shipped tree).
Raw evidence, including exact commit SHAs, licence text, tracked-file counts and
the source greps, is in `docs/verification/raw/13-prior-art.txt`.

Confirmed source-level findings:

- **PyRIT** provides `TraceScorable`, `OtelToolCallScorer`, `FileWriteScorer`
  and `ProgramExecutionScorer`. Deterministic state/trace scoring is prior art;
  RedFence's contribution is the benchmark composition and authorization-state
  lifecycle, not the idea of a state oracle.
- **garak** has a first-class `buffs` category (`garak/buffs/base.py` and
  encoding/lowercase/paraphrase/low-resource-language buffs). RedFence does not
  yet have a lineage-tracking transform layer.
- **AgentDojo** task examples implement `utility()` and `ground_truth()`,
  confirming the environment-state evaluation model.
- **Promptfoo** has 197 tracked paths under `redteam/plugins` and source/example
  references for BOLA, BFLA, cross-session leak and agentic memory poisoning.
  The "~157 plugins" figure was not used because an exact plugin count was not
  established.
- **DeepTeam** is LLM-as-judge-centric (50+ vulnerabilities).
- **SafeRAG** has no licence file at the cloned root and is treated as
  unverified for reuse. **InjecAgent** is MIT (`LICENCE`).

No upstream code is vendored. The files below remain the required prior-art
deliverables; `inventory-and-licences.md` now contains the real SHAs and
licences.
