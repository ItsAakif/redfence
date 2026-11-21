# Architecture and attack/scoring comparison

## Frameworks

| Dimension | Promptfoo | PyRIT | garak | AgentDojo | DeepTeam |
|---|---|---|---|---|---|
| Architecture | config → plugins × strategies → targets; assertions | scenarios → techniques → executors; converters/targets/scorers | generators, probes, detectors, buffs, harness | `TaskSuite[Env]` + pipeline elements | DeepEval-based |
| Main abstractions | plugin, strategy, target, probe, assertion | seed, scenario, technique, executor, converter, target, scorer | probe, detector, generator, buff, attempt | user task, injection task, environment | vulnerability, attack, judge metric |
| Attack generation | plugin payloads + delivery strategies; RAG `indirectInjectionVar`; `rbac` plugin | datasets + converters; Crescendo, TAP, Skeleton Key | broad probe library + buffs | `DirectAttack`, `FixedJailbreakAttack`, `tool_knowledge` | 50+ vulns; single/multi-turn |
| Target interface | HTTP, browser, direct model, provider scripts | web service / embedded | generator plugins | tools + environment state | LLM/provider |
| Scoring | assertions + model-graded metrics | classical ML + self-ask LLM + human-in-loop | keyword + ML detectors | environment `utility()`/`ground_truth()` | LLM-as-judge |
| Reproducibility | config + CI | registry/memory, per-execution conversations | JSON attempt logs | deterministic env state | local runs; judge variance |
| Key limitation | not authorization-first; no cross-store lifecycle oracles | not RAG/ACL-centric; model-based scoring | model/probe-centric; no ACL state | no multi-tenant ACL/cache/memory lifecycle | judge-centric; no enforcement oracles |

## What RedFence adopts / rejects

| Adopt conceptually | Reject / avoid |
|---|---|
| plugin × strategy separation (Promptfoo) | re-implementing a general jailbreak scanner |
| `TaskSuite` utility/injection cross-product (AgentDojo) | LLM-as-judge as the headline metric |
| converters + per-execution conversations (PyRIT) | static attack libraries without adaptive hooks |
| attempt/trace artifacts (garak) | prompt-level "RBAC plugin" as a substitute for real authorization oracles |
| vulnerability taxonomy (DeepTeam) | copying upstream code without attribution review |

## Scoring implementations

- **Promptfoo**: assertions (`contains`, `contains-all`, `equals`, `regex`,
  custom JS) plus model-graded RAG metrics (factuality, answer relevance,
  context adherence/recall/relevance).
- **PyRIT**: extensible scoring engine — classical ML classifiers, self-ask LLM,
  human-in-the-loop.
- **garak**: keyword detectors and ML classifiers over `attempt` outputs.
- **AgentDojo**: deterministic environment-state verification (`utility()`,
  `ground_truth()`), which is the model RedFence's oracles follow.
- **DeepTeam**: LLM-as-judge binary pass/fail per vulnerability.

RedFence is **deterministic-first**: every oracle recomputes expected policy and
returns typed `Evidence`; model-based judging is deferred and secondary.
