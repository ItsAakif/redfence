"""Synthetic tool runtime with simulated side effects.

No real email, network, shell or filesystem side effects occur. External
communication is captured by a controlled in-process sink so exfiltration can be
observed and contained (mandate sections 5 and 12).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from redfence.core.domain import PolicyDecision, Principal, ToolCall, ToolSpec


class ToolExecution(BaseModel):
    seq: int
    tool: str
    args: dict[str, object]
    principal_id: str
    tenant_id: str
    policy_checked: bool
    decision: PolicyDecision
    executed: bool
    side_effect: dict[str, object] = Field(default_factory=dict)
    state_delta: dict[str, object] = Field(default_factory=dict)


class SyntheticToolRuntime:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self.sink: list[dict[str, object]] = []
        self.executions: list[ToolExecution] = []
        self._pending_approvals: set[str] = set()
        self._register_builtins()

    def _register_builtins(self) -> None:
        self.register(
            ToolSpec(
                name="search_documents",
                required_capability="docs.search",
                high_impact=False,
                description="Search indexed documents.",
            )
        )
        self.register(
            ToolSpec(
                name="read_file",
                required_capability="files.read",
                high_impact=False,
                description="Read a sandboxed file.",
            )
        )
        self.register(
            ToolSpec(
                name="db_query",
                required_capability="db.read",
                high_impact=False,
                description="Run a read-only query.",
            )
        )
        self.register(
            ToolSpec(
                name="http_post",
                required_capability="net.egress",
                high_impact=True,
                description="POST to the controlled exfiltration sink.",
            )
        )
        self.register(
            ToolSpec(
                name="send_email",
                required_capability="mail.send",
                high_impact=True,
                description="Simulated email send.",
            )
        )
        self.register(
            ToolSpec(
                name="task_execute",
                required_capability="tasks.execute",
                high_impact=True,
                description="Simulated task execution.",
            )
        )

    def register(self, spec: ToolSpec) -> None:
        self._specs[spec.name] = spec

    def spec(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def all_specs(self) -> list[ToolSpec]:
        return [self._specs[name] for name in sorted(self._specs)]

    def grant_approval(self, principal_id: str, tool_name: str) -> None:
        self._pending_approvals.add(f"{principal_id}:{tool_name}")

    def approvals(self) -> set[str]:
        return set(self._pending_approvals)

    def invoke(
        self, principal: Principal, call: ToolCall, *, bypass_policy: bool = False
    ) -> ToolExecution:
        spec = self._specs.get(call.name)
        if spec is None:
            decision = PolicyDecision(
                allowed=False, reason="unknown tool", matched_rule="tool.unknown"
            )
            return self._record(principal, call, decision, policy_checked=True, executed=False)

        if bypass_policy:
            decision = PolicyDecision(
                allowed=True,
                reason="FAULT: policy bypassed",
                required_capability=spec.required_capability,
                matched_rule="FAULT.bypass",
            )
            policy_checked = False
        else:
            from redfence.targets.policy import DefaultToolPolicy

            decision = DefaultToolPolicy().decide(
                principal,
                call,
                spec.required_capability,
                spec.high_impact,
                approvals=self._pending_approvals,
            )
            policy_checked = True

        if not decision.allowed:
            return self._record(
                principal, call, decision, policy_checked=policy_checked, executed=False
            )
        return self._record(principal, call, decision, policy_checked=policy_checked, executed=True)

    def _record(
        self,
        principal: Principal,
        call: ToolCall,
        decision: PolicyDecision,
        *,
        policy_checked: bool,
        executed: bool,
    ) -> ToolExecution:
        side_effect: dict[str, object] = {}
        state_delta: dict[str, object] = {}
        if executed:
            if call.name == "http_post":
                self.sink.append(
                    {
                        "destination": str(call.args.get("url", "")),
                        "payload": str(call.args.get("body", "")),
                        "principal_id": principal.id,
                    }
                )
                side_effect = {"sink_entries": len(self.sink)}
            elif call.name == "send_email":
                side_effect = {"simulated_recipient": str(call.args.get("to", ""))}
            elif call.name == "task_execute":
                state_delta = {"task_created": str(call.args.get("task", "task"))}
        execution = ToolExecution(
            seq=len(self.executions) + 1,
            tool=call.name,
            args=call.args,
            principal_id=principal.id,
            tenant_id=principal.tenant_id,
            policy_checked=policy_checked,
            decision=decision,
            executed=executed,
            side_effect=side_effect,
            state_delta=state_delta,
        )
        self.executions.append(execution)
        return execution
