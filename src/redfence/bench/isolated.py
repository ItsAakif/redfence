"""Run oracles in a separate OS process.

The target remains in the parent process. The oracle child receives only a
JSON snapshot of the authoritative corpus, frozen observations and target
metadata. It cannot read the parent's live objects, so a target bug cannot
silently mutate oracle state.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass

from redfence.bench.scenario import ScenarioRun
from redfence.core.evidence import Evidence


@dataclass
class IsolatedOracleResult:
    evidence: list[Evidence]
    oracle_pid: int


def serialize_run(run: ScenarioRun) -> dict[str, object]:
    corpus = run.corpus
    return {
        "scenario_id": run.scenario_id,
        "scenario_kind": run.scenario_kind,
        "profile": run.profile,
        "template": corpus.template,
        "steps": run.steps,
        "corpus": {
            "dataset_version": corpus.dataset_version,
            "seed": corpus.seed,
            "tenants": [tenant.model_dump() for tenant in corpus.tenants],
            "principals": [principal.model_dump() for principal in corpus.principals],
            "documents": [document.model_dump() for document in corpus.documents],
            "dev_families": list(corpus.dev_families),
            "heldout_families": list(corpus.heldout_families),
            "canaries": dict(corpus.canaries),
        },
        "target": {
            "faults": run.target.faults.model_dump(),
            "cache": [entry.model_dump(mode="json") for entry in run.target.cache.values()],
            "chunks": [chunk.model_dump(mode="json") for chunk in run.target.store.all_chunks()],
            "tools": [spec.model_dump() for spec in run.target.tools.all_specs()],
        },
        "retrieval_obs": run.retrieval_obs,
        "answer_obs": run.answer_obs,
        "memory_obs": run.memory_obs,
        "tool_obs": [
            {
                **obs,
                "execution": obs["execution"].model_dump(mode="json"),
            }
            for obs in run.tool_obs
        ],
        "deletion_obs": run.deletion_obs,
        "utility_obs": run.utility_obs,
    }


def run_oracles_isolated(run: ScenarioRun, *, timeout: float = 60.0) -> IsolatedOracleResult:
    payload = serialize_run(run)
    process = subprocess.run(
        [sys.executable, "-m", "redfence.bench.oracle_worker"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"isolated oracle worker failed ({process.returncode}): {process.stderr.strip()}"
        )
    try:
        encoded = json.loads(process.stdout)
        evidence = [Evidence.model_validate(item) for item in encoded["evidence"]]
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"invalid isolated oracle response: {error}") from error
    return IsolatedOracleResult(evidence=evidence, oracle_pid=int(encoded["pid"]))
