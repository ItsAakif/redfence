"""Deterministic matrix/lifecycle runner for contract v1.

A contract run executes the declared permission matrix against a
:class:`~redfence.contracts.target.ContractTarget` and then applies lifecycle
steps, replaying every cell whose identity or source is affected. The runner
never trusts an adapter's metadata: it builds a read-only
:class:`~redfence.bench.snapshot.SnapshotTarget` from the contract's sources so
shared store-reading helpers (``_chunk_meta``) work unchanged.

Only facts an adapter can express are recorded. Unsupported actions produce no
observation, never a fabricated pass. Report writing is deferred to T4; with an
``out_dir`` the runner writes a deterministic JSON placeholder only.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from redfence.bench.contract_observations import (
    BudgetObservation,
    LifecycleObservation,
    MatrixObservation,
)
from redfence.bench.observations import (
    AnswerObservation,
    DeletionObservation,
    MemoryObservation,
    RetrievalObservation,
    ToolObservation,
)
from redfence.bench.scenario import _chunk_meta
from redfence.bench.snapshot import SnapshotStore, SnapshotTarget, SnapshotTools
from redfence.contracts.schema import (
    ContractV1,
    IdentitySpec,
    LifecycleStep,
    MatrixCell,
    SourceSpec,
)
from redfence.contracts.target import ContractRequest, ContractResponse, ContractTarget
from redfence.core.domain import ACL, Chunk, PolicyDecision, Provenance
from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import content_hash, json_digest
from redfence.targets.config import FaultFlags
from redfence.targets.tools import ToolExecution

if TYPE_CHECKING:
    from redfence.bench.existence import ExistencePair

Observed = Literal["allow", "deny", "error", "unsupported"]

_STATUS_TO_OBSERVED: dict[str, Observed] = {
    "allowed": "allow",
    "denied": "deny",
    "error": "error",
}

_CANARY_RE = re.compile(r"CANARY_[A-Z0-9_]+")
_REDACTED = "[REDACTED]"
_TRUNCATED = "[TRUNCATED]"
_MAX_REDACT_DEPTH = 16
_MAX_REDACT_NODES = 1024
_VIOLATION_ACTIONS = frozenset({"revoke", "expire"})
_SOURCE_ACTIONS = frozenset({"delete", "update"})


def _expected_after(cell: MatrixCell, step: LifecycleStep) -> str:
    """The expectation for ``cell`` after ``step`` has been applied.

    A denied cell stays denied. An allowed cell must become denied when a
    lifecycle step removes the identity or source it depends on; ``update``
    changes content, not authorization, so it leaves the expectation alone.
    """

    if cell.expect == "deny":
        return "deny"
    if step.action in _VIOLATION_ACTIONS and cell.identity == step.identity:
        return "deny"
    if step.action == "delete" and cell.source == step.source:
        return "deny"
    return cell.expect


@dataclass
class ContractRun:
    """A contract run's observations and adapter-only sidecar facts."""

    contract_id: str
    contract_hash: str
    adapter: str
    capabilities: frozenset[str]
    target: SnapshotTarget
    secret_names: tuple[str, ...] = ()
    retrieval_obs: list[RetrievalObservation] = field(default_factory=list)
    answer_obs: list[AnswerObservation] = field(default_factory=list)
    memory_obs: list[MemoryObservation] = field(default_factory=list)
    tool_obs: list[ToolObservation] = field(default_factory=list)
    deletion_obs: list[DeletionObservation] = field(default_factory=list)
    utility_obs: AnswerObservation | None = None
    matrix_obs: list[MatrixObservation] = field(default_factory=list)
    lifecycle_obs: list[LifecycleObservation] = field(default_factory=list)
    budget_obs: BudgetObservation | None = None
    lineage: object | None = None
    existence_obs: list[ExistencePair] = field(default_factory=list)


@dataclass
class ContractResult:
    """The runner's return value; T4 replaces the placeholder metrics/reports."""

    contract_id: str
    run: ContractRun
    evidence: list[Evidence]
    metrics: object
    manifest: dict[str, object]
    json_path: Path | None
    sarif_path: Path | None
    junit_path: Path | None
    _inconclusive: bool = field(default=False, repr=False, compare=False)

    @property
    def exit_code(self) -> int:
        """0 pass, 1 confirmed violation, 2 inconclusive/unsupported/error.

        When the caller has scored oracles, the verdict derives from their
        evidence: any ``VIOLATION`` is 1, an inconclusive or wholly unsupported
        result is 2, and otherwise the run passed. A caller that scored nothing
        (the bare runner API) falls back to the observed matrix/lifecycle state.
        """

        outcomes = [item.outcome for item in self.evidence]
        if not outcomes:
            matrix_violation = any(
                obs["expected"] != obs["observed"] for obs in self.run.matrix_obs
            )
            lifecycle_violation = any(
                obs["violations"] for obs in self.run.lifecycle_obs
            )
            if matrix_violation or lifecycle_violation:
                return 1
            inconclusive = self._inconclusive or any(
                obs["observed"] in {"unsupported", "error"} or obs["truncated"]
                for obs in self.run.matrix_obs
            )
            return 2 if inconclusive else 0

        if any(outcome is Outcome.VIOLATION for outcome in outcomes):
            return 1
        if self._inconclusive:
            return 2
        if any(outcome is Outcome.INCONCLUSIVE for outcome in outcomes):
            return 2
        if any(
            obs["observed"] == "error" or obs["truncated"]
            for obs in self.run.matrix_obs
        ):
            return 2
        if all(outcome is Outcome.UNSUPPORTED for outcome in outcomes):
            return 2
        return 0


class _Runner:
    """Mutable execution state for one contract run."""

    def __init__(
        self,
        contract: ContractV1,
        target: ContractTarget,
        snapshot: SnapshotTarget,
        contract_hash: str,
    ) -> None:
        self.contract = contract
        self.target = target
        self.snapshot = snapshot
        self.identities: dict[str, IdentitySpec] = {
            item.id: item for item in contract.identities
        }
        self.sources: dict[str, SourceSpec] = {item.id: item for item in contract.sources}
        self.revoked: set[str] = {
            item.id for item in contract.identities if item.revoked
        }
        self.secrets = _secret_values(contract.redaction.secrets)
        self.inconclusive = False
        self.requests = 0
        self.timeouts = 0
        self.max_response_bytes_seen = 0
        self.truncated = 0
        self.egress_denied = 0
        self.run = ContractRun(
            contract_id=contract.id,
            contract_hash=contract_hash,
            adapter=target.name,
            capabilities=frozenset(target.capabilities),
            target=snapshot,
            secret_names=tuple(contract.redaction.secrets),
        )

    # -- execution ---------------------------------------------------------

    def execute(self, request: ContractRequest) -> ContractResponse:
        self.requests += 1
        response = self.target.execute(request)
        self.max_response_bytes_seen = max(
            self.max_response_bytes_seen, len(response.text.encode("utf-8"))
        )
        if response.truncated:
            self.truncated += 1
            self.inconclusive = True
        if response.status == "error":
            self.inconclusive = True
            message = (response.error or "").lower()
            if "timeout" in message:
                self.timeouts += 1
            if "egress" in message:
                self.egress_denied += 1
        return response

    def run_matrix(self) -> None:
        for cell in self.contract.matrix:
            if cell.action not in self.run.capabilities:
                self.inconclusive = True
                continue
            request = self._request_for_cell(cell)
            response = self.execute(request)
            self.run.matrix_obs.append(self._observe(cell, response))
            self._record_action(cell, request, response, phase=cell.id)

    def run_lifecycle(self) -> None:
        for step in self.contract.lifecycle:
            self._apply_step(step)
            replayed: list[str] = []
            violations: list[str] = []
            for cell in self._affected_cells(step):
                if cell.action not in self.run.capabilities:
                    self.inconclusive = True
                    continue
                request = self._request_for_cell(cell)
                response = self.execute(request)
                observation = self._observe(cell, response)
                replayed.append(cell.id)
                self._record_action(cell, request, response, phase=step.id)
                expected_after = _expected_after(cell, step)
                if observation["observed"] != expected_after:
                    violations.append(
                        f"{cell.id}: expected {expected_after} after "
                        f"{step.action}, observed {observation['observed']}"
                    )
            self.run.lifecycle_obs.append(
                {
                    "step_id": step.id,
                    "action": step.action,
                    "identity_id": step.identity,
                    "source_id": step.source,
                    "replayed_cell_ids": replayed,
                    "violations": violations,
                }
            )

    # -- lifecycle state ---------------------------------------------------

    def _apply_step(self, step: LifecycleStep) -> None:
        if step.action in _VIOLATION_ACTIONS:
            if step.identity is None:
                self.inconclusive = True
                return
            self.revoked.add(step.identity)
            identity = self.identities.get(step.identity)
            if "revoke" not in self.run.capabilities:
                self.inconclusive = True
                return
            self.execute(
                ContractRequest(
                    action="revoke",
                    identity_id=step.identity,
                    tenant_id=identity.tenant if identity is not None else "",
                    timeout_ms=self.contract.limits.timeout_ms,
                    max_response_bytes=self.contract.limits.max_response_bytes,
                )
            )
            return

        if step.source is None:
            self.inconclusive = True
            return
        source = self.sources.get(step.source)
        if step.action == "delete":
            self._mark_deleted(step.source)
            if "delete" not in self.run.capabilities:
                self.inconclusive = True
                return
            action: Literal["delete", "read"] = "delete"
        else:
            # ContractRequest has no "update" action. Sample the source with a
            # read so the adapter is consulted without inventing a wire action.
            if "read" not in self.run.capabilities:
                self.inconclusive = True
                return
            action = "read"
        actor = self._actor_for_source(step.source)
        self.execute(
            ContractRequest(
                action=action,
                identity_id=actor.id if actor is not None else "",
                tenant_id=(
                    actor.tenant if actor is not None else (source.tenant if source else "")
                ),
                source_id=step.source,
                timeout_ms=self.contract.limits.timeout_ms,
                max_response_bytes=self.contract.limits.max_response_bytes,
            )
        )

    def _mark_deleted(self, source_id: str) -> None:
        chunk = self.snapshot.store.get(source_id)
        if chunk is not None:
            chunk.deleted = True

    def _affected_cells(self, step: LifecycleStep) -> list[MatrixCell]:
        if step.action in _VIOLATION_ACTIONS:
            return [cell for cell in self.contract.matrix if cell.identity == step.identity]
        if step.action in _SOURCE_ACTIONS:
            if step.source is None:
                return []
            return [cell for cell in self.contract.matrix if cell.source == step.source]
        return []

    def _actor_for_source(self, source_id: str) -> IdentitySpec | None:
        source = self.sources.get(source_id)
        if source is not None:
            for identity in self.contract.identities:
                if identity.tenant == source.tenant:
                    return identity
        return self.contract.identities[0] if self.contract.identities else None

    # -- projection --------------------------------------------------------

    def _request_for_cell(self, cell: MatrixCell) -> ContractRequest:
        identity = self.identities.get(cell.identity)
        return ContractRequest(
            action=cell.action,
            identity_id=cell.identity,
            tenant_id=identity.tenant if identity is not None else "",
            source_id=cell.source,
            query=None,
            tool=cell.tool,
            args={},
            timeout_ms=self.contract.limits.timeout_ms,
            max_response_bytes=self.contract.limits.max_response_bytes,
        )

    def _observe(self, cell: MatrixCell, response: ContractResponse) -> MatrixObservation:
        text = _redact(response.text, self.secrets)
        error = _redact(response.error, self.secrets) if response.error is not None else None
        context_refs = [_redact(ref, self.secrets) for ref in response.context_refs]
        response_hash = content_hash(
            text + str(sorted(context_refs)) + str(response.tool_executed)
        )
        return {
            "cell_id": cell.id,
            "identity_id": cell.identity,
            "source_id": cell.source,
            "action": cell.action,
            "expected": cell.expect,
            "observed": _STATUS_TO_OBSERVED.get(response.status, "error"),
            "response_hash": response_hash,
            "status": response.status,
            "context_refs": context_refs,
            "tool_executed": response.tool_executed,
            "truncated": response.truncated,
            "error": error,
        }

    def _record_action(
        self,
        cell: MatrixCell,
        request: ContractRequest,
        response: ContractResponse,
        *,
        phase: str,
    ) -> None:
        context_refs = [_redact(ref, self.secrets) for ref in response.context_refs]
        if cell.action == "read":
            self.run.retrieval_obs.append(
                {
                    "phase": phase,
                    "principal_id": cell.identity,
                    "tenant_id": request.tenant_id,
                    "revoked": cell.identity in self.revoked,
                    "query": request.query or "",
                    "admitted": [
                        _chunk_meta(self.snapshot, None, chunk_id)
                        for chunk_id in context_refs
                    ],
                }
            )
        elif cell.action == "answer":
            context_chunk_ids = context_refs
            self.run.answer_obs.append(
                {
                    "phase": phase,
                    "principal_id": cell.identity,
                    "tenant_id": request.tenant_id,
                    "revoked": cell.identity in self.revoked,
                    "query": request.query or "",
                    "cache_hit": False,
                    "cache_revalidated": False,
                    "context_chunk_ids": context_chunk_ids,
                    "context": [
                        _chunk_meta(self.snapshot, None, chunk_id)
                        for chunk_id in context_chunk_ids
                    ],
                    "canaries_present": [],
                    "cache_doc_versions": {},
                    "current_doc_versions": {},
                    "text_hash": content_hash(_redact(response.text, self.secrets)),
                }
            )
        elif cell.action == "tool":
            self.run.tool_obs.append(
                {
                    "phase": phase,
                    "principal_id": cell.identity,
                    "execution": ToolExecution(
                        seq=len(self.run.tool_obs) + 1,
                        tool=request.tool or "",
                        args=dict(request.args),
                        principal_id=cell.identity,
                        tenant_id=request.tenant_id,
                        policy_checked=True,
                        decision=PolicyDecision(
                            allowed=response.status == "allowed",
                            reason=response.status,
                        ),
                        executed=response.tool_executed,
                        side_effect=_redact_mapping(response.side_effect, self.secrets),
                        state_delta={},
                    ),
                }
            )

    def budget(self) -> BudgetObservation:
        return {
            "requests": self.requests,
            "max_requests": self.contract.limits.max_requests,
            "timeouts": self.timeouts,
            "max_response_bytes_seen": self.max_response_bytes_seen,
            "truncated": self.truncated,
            "egress_denied": self.egress_denied,
        }


def run_contract(
    contract: ContractV1, target: ContractTarget, *, out_dir: Path | None = None
) -> ContractResult:
    """Execute a contract's matrix and lifecycle against ``target``."""

    target.reset()
    snapshot = _build_snapshot(contract)
    contract_hash = json_digest(contract.model_dump(mode="json"))
    runner = _Runner(contract, target, snapshot, contract_hash)
    runner.run_matrix()
    runner.run_lifecycle()
    runner.run.budget_obs = runner.budget()

    manifest = _manifest(contract, runner)
    json_path: Path | None = None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"{contract.id}.json"
        json_path.write_text(_render_json(runner.run), encoding="utf-8")

    return ContractResult(
        contract_id=contract.id,
        run=runner.run,
        evidence=[],
        metrics=None,
        manifest=manifest,
        json_path=json_path,
        sarif_path=None,
        junit_path=None,
        _inconclusive=runner.inconclusive,
    )


def _build_snapshot(contract: ContractV1) -> SnapshotTarget:
    chunks: list[Chunk] = []
    for position, source in enumerate(contract.sources):
        chunks.append(
            Chunk(
                id=source.id,
                doc_id=source.id,
                tenant_id=source.tenant,
                position=position,
                text="",
                acl=ACL(
                    tenant_id=source.tenant,
                    classification=source.classification,
                    allowed_roles=list(source.acl.allowed_roles),
                    allowed_groups=list(source.acl.allowed_groups),
                    allowed_principals=list(source.acl.allowed_principals),
                    public=source.acl.public,
                ),
                provenance=Provenance(
                    source=source.id,
                    ingested_at="",
                    content_hash=content_hash(""),
                ),
                content_hash=content_hash(""),
                deleted=False,
            )
        )
    return SnapshotTarget(
        faults=FaultFlags(),
        cache={},
        store=SnapshotStore(chunks),
        tools=SnapshotTools([]),
    )


def _manifest(contract: ContractV1, runner: _Runner) -> dict[str, object]:
    return {
        "contract_id": contract.id,
        "contract_hash": runner.run.contract_hash,
        "adapter": runner.run.adapter,
        "capabilities": sorted(runner.run.capabilities),
        "dataset": contract.dataset.model_dump(mode="json"),
        "matrix_cells": len(contract.matrix),
        "lifecycle_steps": len(contract.lifecycle),
        "observations": {
            "matrix": len(runner.run.matrix_obs),
            "retrieval": len(runner.run.retrieval_obs),
            "answer": len(runner.run.answer_obs),
            "tool": len(runner.run.tool_obs),
        },
    }


def _render_json(run: ContractRun) -> str:
    payload = {
        "contract_id": run.contract_id,
        "contract_hash": run.contract_hash,
        "adapter": run.adapter,
        "capabilities": sorted(run.capabilities),
        "matrix": [dict(item) for item in run.matrix_obs],
        "lifecycle": [dict(item) for item in run.lifecycle_obs],
        "budget": dict(run.budget_obs) if run.budget_obs is not None else None,
    }
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _secret_values(names: list[str]) -> list[str]:
    values: list[str] = []
    for name in names:
        value = os.environ.get(name)
        if value:
            values.append(value)
    return values


def _redact(text: str, secrets: list[str]) -> str:
    for value in secrets:
        text = text.replace(value, _REDACTED)
    return _CANARY_RE.sub(_REDACTED, text)


def _redact_mapping(value: dict[str, object], secrets: list[str]) -> dict[str, object]:
    """Redact secret values in a structured adapter payload before storage.

    Adapter payloads are untrusted. Depth and total node count are bounded so a
    deeply nested or self-referential ``side_effect`` cannot raise
    ``RecursionError`` or store unbounded data; anything beyond the bound is
    replaced by ``"[TRUNCATED]"``.
    """

    return _redact_dict(value, secrets, 0, [_MAX_REDACT_NODES])


def _redact_dict(
    value: dict[str, object], secrets: list[str], depth: int, budget: list[int]
) -> dict[str, object]:
    if depth > _MAX_REDACT_DEPTH or budget[0] <= 0:
        return {_TRUNCATED: True}
    budget[0] -= 1
    result: dict[str, object] = {}
    for key, item in value.items():
        if budget[0] <= 0:
            result[_TRUNCATED] = True
            break
        result[_redact(str(key), secrets)] = _redact_value(
            item, secrets, depth + 1, budget
        )
    return result


def _redact_value(value: object, secrets: list[str], depth: int, budget: list[int]) -> object:
    if depth > _MAX_REDACT_DEPTH or budget[0] <= 0:
        return _TRUNCATED
    if isinstance(value, str):
        budget[0] -= 1
        return _redact(value, secrets)
    if isinstance(value, dict):
        return _redact_dict(value, secrets, depth, budget)
    if isinstance(value, list):
        budget[0] -= 1
        items: list[object] = []
        for item in value:
            if budget[0] <= 0:
                items.append(_TRUNCATED)
                break
            items.append(_redact_value(item, secrets, depth + 1, budget))
        return items
    budget[0] -= 1
    return value


__all__ = [
    "ContractResult",
    "ContractRun",
    "run_contract",
]
