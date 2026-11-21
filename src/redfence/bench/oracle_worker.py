"""Child process entry point for isolated oracle scoring."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import Any, cast

from redfence.bench.dataset import Corpus
from redfence.bench.observations import ToolObservation
from redfence.bench.oracles import default_oracles
from redfence.bench.scenario import ScenarioRun
from redfence.bench.snapshot import SnapshotStore, SnapshotTarget, SnapshotTools
from redfence.core.domain import (
    CacheEntry,
    Chunk,
    Document,
    Principal,
    Tenant,
    ToolSpec,
)
from redfence.targets.config import FaultFlags
from redfence.targets.tools import ToolExecution


def _reconstruct(payload: Mapping[str, Any]) -> ScenarioRun:
    corpus_data = payload["corpus"]
    corpus = Corpus(
        dataset_version=str(corpus_data["dataset_version"]),
        seed=int(corpus_data["seed"]),
        tenants=[Tenant.model_validate(item) for item in corpus_data["tenants"]],
        principals=[Principal.model_validate(item) for item in corpus_data["principals"]],
        documents=[Document.model_validate(item) for item in corpus_data["documents"]],
        dev_families=tuple(corpus_data["dev_families"]),
        heldout_families=tuple(corpus_data["heldout_families"]),
        canaries=dict(corpus_data["canaries"]),
        template=str(payload.get("template", "classic")),
    )
    target_data = payload["target"]
    cache = {
        entry.key: entry
        for entry in (CacheEntry.model_validate(item) for item in target_data["cache"])
    }
    chunks = [Chunk.model_validate(item) for item in target_data["chunks"]]
    tools = [ToolSpec.model_validate(item) for item in target_data["tools"]]
    target = SnapshotTarget(
        faults=FaultFlags.model_validate(target_data["faults"]),
        cache=cache,
        store=SnapshotStore(chunks),
        tools=SnapshotTools(tools),
    )
    tool_obs: list[ToolObservation] = [
        cast(
            ToolObservation,
            {
                **obs,
                "execution": ToolExecution.model_validate(obs["execution"]),
            },
        )
        for obs in payload["tool_obs"]
    ]
    return ScenarioRun(
        scenario_id=str(payload["scenario_id"]),
        profile=str(payload["profile"]),
        corpus=corpus,
        target=target,  # type: ignore[arg-type]
        scenario_kind=str(payload.get("scenario_kind", "revocation")),
        steps=list(payload["steps"]),
        retrieval_obs=list(payload["retrieval_obs"]),
        answer_obs=list(payload["answer_obs"]),
        memory_obs=list(payload["memory_obs"]),
        tool_obs=tool_obs,
        deletion_obs=list(payload["deletion_obs"]),
        utility_obs=payload["utility_obs"],
    )


def main() -> int:
    payload = json.load(sys.stdin)
    run = _reconstruct(payload)
    evidence = [oracle.score(run) for oracle in default_oracles()]
    json.dump(
        {
            "pid": os.getpid(),
            "evidence": [item.model_dump(mode="json") for item in evidence],
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
