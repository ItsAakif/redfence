# Repository and version inventory + licence matrix

Code-level audit completed in Milestone 3. Shallow clones (`git clone --depth 1`)
live under `.prior-art/` (git-ignored, outside the shipped tree). Raw evidence:
`docs/verification/raw/13-prior-art.txt`.

| Project | Repo | SHA | Licence | Files actually read |
|---|---|---|---|---|
| Promptfoo | `promptfoo/promptfoo` | `2a6fdf9b2e1600ffa2a204e70e9fea7cb0c14cff` | MIT (`LICENSE`) | `LICENSE`; `git grep` over `redteam/plugins`; changelog/example references for BOLA/BFLA/cross-session-leak/agentic memory poisoning |
| PyRIT | `microsoft/PyRIT` | `c98bdd8ec657696b59a48dea8f19a5634cfa53f7` | MIT (`LICENSE`) | `LICENSE`; `doc/code/framework.md`; `doc/code/scoring/5_tool_call_scorer.{py,ipynb}`; `6_file_write_scorer` |
| garak | `NVIDIA/garak` | `892779207cbc38f65a738ef9cbdfbc1e83aa0b55` | Apache-2.0 (`LICENSE`) | `LICENSE`; `garak/buffs/base.py`; `garak/buffs/*`; tests/buffs |
| AgentDojo | `ethz-spylab/agentdojo` | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT (`LICENSE`) | `LICENSE`; `examples/counter_benchmark` task `utility()`/`ground_truth()` implementations |
| DeepTeam | `confident-ai/deepteam` | `6306f0ff319a932955399405af82f78ee91e9370` | Apache-2.0 (`LICENSE.md`) | `LICENSE.md`; `README.md` vulnerability/attack/judge descriptions |
| SafeRAG | `IAAR-Shanghai/SafeRAG` | `e8f579743b23e0a3937076dcc0792fe29027cba3` | **No licence file found at repo root** | `README.md` (four injection tasks, 14 RAG components) |
| LeakDojo | `yeasen-z/LeakDojo` | `ae3ac6db8f4533c4f408305855af4f73eab2af6a` | Apache-2.0 (`LICENSE`) | `LICENSE`; `README.md` (six attacks, LMA, CCL metric) |
| InjecAgent | `uiuc-kang-lab/InjecAgent` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT (`LICENCE`) | `LICENCE`; `README.md` (1,054 cases, 17 user tools, 62 attacker tools) |

## What the source confirmed

- **Promptfoo** tracks 6,027 files; 197 tracked paths match `redteam/plugins`.
  Source references confirm `bola`, `bfla`, `cross-session-leak`, and
  `agentic:memory-poisoning`. The specific claim "~157 plugins across 6
  categories" was **not** verified by an exact plugin count and is not used in
  this report.
- **PyRIT** source/docs confirm `TraceScorable`, `OtelToolCallScorer`,
  `FileWriteScorer`, and `ProgramExecutionScorer`. State/trace-based scoring is
  therefore prior art; RedFence's contribution is the benchmark composition, not
  the idea of deterministic state oracles.
- **garak** has a first-class `buffs` plugin category
  (`garak/buffs/base.py`, encoding/lowercase/paraphrase/low-resource-language
  buffs) with selection and configuration plumbing. This is a design pattern
  RedFence has not adopted yet.
- **AgentDojo** task examples implement both `utility()` and `ground_truth()`;
  the environment-state evaluation model is confirmed at code level.
- **DeepTeam** describes 50+ vulnerabilities with LLM-as-judge binary scoring;
  it is judge-centric rather than enforcement-oracle-centric.

## Licences / use

No upstream code is copied into RedFence. SafeRAG has no licence file at the
cloned root, so it is treated as **unverified for reuse**; only its published
description is cited. InjecAgent is MIT (`LICENCE`).
