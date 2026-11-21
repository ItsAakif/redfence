"""Trusted, LLM-independent tool authorization (PDP)."""

from __future__ import annotations

from redfence.core.capability import CapabilityToken
from redfence.core.domain import PolicyDecision, Principal, ToolCall


class DefaultToolPolicy:
    """Capability + tenant + high-impact approval checks.

    Runs outside the model. Fails closed: an unknown or unverifiable request is
    denied.
    """

    def decide(
        self,
        principal: Principal,
        call: ToolCall,
        spec_capability: str,
        high_impact: bool,
        *,
        approvals: set[str] | None = None,
        token: CapabilityToken | None = None,
        now_epoch: int | None = None,
    ) -> PolicyDecision:
        if principal.revoked:
            return PolicyDecision(
                allowed=False,
                reason="principal has been revoked",
                required_capability=spec_capability,
                matched_rule="principal.revoked",
            )
        if spec_capability not in principal.capabilities:
            return PolicyDecision(
                allowed=False,
                reason="principal lacks the required capability",
                required_capability=spec_capability,
                matched_rule="capability.missing",
            )
        if token is not None:
            if token.subject != principal.id:
                return PolicyDecision(
                    allowed=False,
                    reason="capability token was not issued to this principal",
                    required_capability=spec_capability,
                    matched_rule="token.subject",
                )
            if now_epoch is not None and now_epoch < token.issued_epoch:
                return PolicyDecision(
                    allowed=False,
                    reason="capability token is not valid yet",
                    required_capability=spec_capability,
                    matched_rule="token.not_yet_valid",
                )
            if now_epoch is not None and now_epoch >= token.expires_epoch:
                return PolicyDecision(
                    allowed=False,
                    reason="capability token has expired",
                    required_capability=spec_capability,
                    matched_rule="token.expired",
                )
            if spec_capability not in token.capabilities:
                return PolicyDecision(
                    allowed=False,
                    reason="capability token does not grant the required capability",
                    required_capability=spec_capability,
                    matched_rule="token.capability",
                )
            if "*" not in token.scope and call.name not in token.scope:
                return PolicyDecision(
                    allowed=False,
                    reason="capability token scope excludes the requested resource",
                    required_capability=spec_capability,
                    matched_rule="token.scope",
                )
        if high_impact:
            approval_token = f"{principal.id}:{call.name}"
            if not approvals or approval_token not in approvals:
                return PolicyDecision(
                    allowed=False,
                    reason="high-impact action requires an approval bound to this actor and call",
                    required_capability=spec_capability,
                    matched_rule="approval.missing",
                )
        return PolicyDecision(
            allowed=True,
            reason="authorized",
            required_capability=spec_capability,
            matched_rule="capability.granted",
        )
