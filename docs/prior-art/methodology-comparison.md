# Benchmark methodology comparison

| Artifact | What it measures | Oracles/scoring | Statefulness | ACL/permission | Cache/memory |
|---|---|---|---|---|---|
| SafeRAG (ACL 2025) | poisoning: silver noise, inter-context conflict, soft ad, white DoS | F1 + attack failure rate | static | no | no |
| LeakDojo (ACL 2026) | RAG knowledge extraction/leakage | leakage rate = query-gen × instruction strength | static | no | no |
| ARES (NAACL 2024) | RAG quality (context relevance, faithfulness, answer relevance) | fine-tuned judges + PPI | static | no | no |
| InjecAgent | indirect prompt injection in tool agents | attack success / harm | static cases | no | no |
| AgentDojo (NeurIPS 2024) | utility × injection cross-product | environment `utility()`/`ground_truth()` | per-task env | no (single-tenant) | no |
| ASB | agent attacks/defenses | 7 metrics, ASR | static | no | memory attack only |
| Poisoning benchmark (2505.18543) | 13 poisoning attacks / 7 defenses | accuracy under attack | static | no | no |
| SSC (EMNLP 2026) | safe cache reuse | access gating + freshness | evolving corpus | per-requester | cache |
| permission-aware HF dataset | permission-aware retrieval QA | must_not_cite / time-travel ACL | time-travel | yes | no |
| **RedFenceBench** | **stateful boundary violations across index, cache, memory, tools** | **deterministic authoritative-ACL oracles + canaries + tool policy + sink** | **evolving (revocation/epoch/delete)** | **yes (tenant+role+clearance+chunk)** | **cache + memory + tools** |

## Key methodological contrasts

- RedFence **never uses a model to authorize access**; oracles recompute policy
  from the authoritative ACL.
- RedFence **separates** unauthorized retrieval, context exposure, disclosure,
  tool invocation and side effect — never one ambiguous ASR.
- RedFence requires **discriminative validity**: the same suite must pass the
  secured configuration and fail the vulnerable one, per fault.
- RedFence reports **security and utility together**, and declares unsupported
  coverage instead of claiming a pass.
