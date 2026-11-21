"""Capability tokens, delegation attenuation, and capability-use oracles.

A capability token grants a subject a bounded set of capabilities over a bounded
set of resources for a bounded epoch window. Delegation must attenuate: a child
token may only narrow the parent's capabilities, scope, and validity, and must
name the parent it was delegated from. The oracles recompute those invariants
from the observed chain and use record; they never trust the target's decision.

``_verdict`` is reused from :mod:`redfence.bench.oracles` so the zero-unit rule
(ADR-0008) is identical across every facet.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import stable_id

_FACET = "capability"
_WILDCARD = "*"


def _verdict(units: int, violations: list[str]) -> Outcome:
    """Delegate to the shared ADR-0008 helper.

    Imported lazily: ``bench`` imports ``targets`` which imports the policy that
    imports this module, so a top-level ``bench`` import would be circular.
    """

    from redfence.bench.oracles import _verdict as shared_verdict

    return shared_verdict(units, violations)


def _no_observation(reason: str) -> str:
    """Delegate to the shared zero-unit text helper (lazy, see ``_verdict``)."""

    from redfence.bench.oracles import _no_observation as shared_no_observation

    return shared_no_observation(reason)


class CapabilityToken(BaseModel):
    """A signed capability grant with an explicit attenuation boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_id: str
    subject: str
    issuer: str
    capabilities: frozenset[str]
    scope: frozenset[str]  # resource ids; "*" means all
    issued_epoch: int
    expires_epoch: int
    delegated_from: str | None = None
    token_digest: str = ""


class DelegationChain(BaseModel):
    """An ordered issuer -> delegate chain of capability tokens."""

    model_config = ConfigDict(extra="forbid")

    links: list[CapabilityToken]

    def validate_attenuation(self) -> list[str]:
        """Return every attenuation violation, naming the offending child link."""

        violations: list[str] = []
        for parent, child in zip(self.links, self.links[1:], strict=False):
            if not child.capabilities <= parent.capabilities:
                violations.append(f"{child.token_id}:capability-not-attenuated")
            if _WILDCARD not in parent.scope and not child.scope <= parent.scope:
                violations.append(f"{child.token_id}:scope-not-attenuated")
            if child.expires_epoch > parent.expires_epoch:
                violations.append(f"{child.token_id}:expiry-extended")
            if child.issued_epoch < parent.issued_epoch:
                violations.append(f"{child.token_id}:issued-before-parent")
            if child.delegated_from != parent.token_id:
                violations.append(f"{child.token_id}:delegated-from-mismatch")
        return violations


class CapabilityUse(BaseModel):
    """One observed use of a capability token."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_id: str
    action: str
    resource: str
    epoch: int
    revoked: bool = False
    allowed: bool


class CapabilityObservation(BaseModel):
    """The chain under test plus every use observed against it."""

    model_config = ConfigDict(extra="forbid")

    chain: DelegationChain
    uses: list[CapabilityUse]


class CapabilityOracle(Protocol):
    """The interface every capability oracle implements."""

    oracle_id: str
    facet: str

    def score(self, obs: CapabilityObservation) -> Evidence: ...


def _scenario_id(obs: CapabilityObservation) -> str:
    return obs.chain.links[0].token_id if obs.chain.links else _FACET


def _evidence(
    obs: CapabilityObservation,
    oracle_id: str,
    expected: str,
    observed: str,
    outcome: Outcome,
    *,
    method: str,
    events: list[str] | None = None,
) -> Evidence:
    scenario_id = _scenario_id(obs)
    return Evidence(
        evidence_id=stable_id("ev", scenario_id, oracle_id),
        scenario_id=scenario_id,
        oracle_id=oracle_id,
        facet=_FACET,
        expected=expected,
        observed=observed,
        outcome=outcome,
        method=method,
        events=events or [],
    )


def _tokens_by_id(obs: CapabilityObservation) -> dict[str, CapabilityToken]:
    return {link.token_id: link for link in obs.chain.links}


class AttenuationOracle:
    """A delegated token must narrow, never widen, its parent's grant."""

    oracle_id = "oracle.capability.attenuation"
    facet = _FACET

    def score(self, obs: CapabilityObservation) -> Evidence:
        units = max(0, len(obs.chain.links) - 1)
        violations = obs.chain.validate_attenuation()
        outcome = _verdict(units, violations)
        observed = (
            f"{len(violations)} attenuation violation(s) across {units} delegation link(s)"
            if units
            else _no_observation("delegation chain has fewer than two links")
        )
        return _evidence(
            obs,
            self.oracle_id,
            "every delegated token narrows capabilities, scope and validity of its parent",
            observed,
            outcome,
            method="recompute the child/parent subset relations and delegation link",
            events=violations,
        )


class ExpiryOracle:
    """A token must not be used at/after expiry or after revocation."""

    oracle_id = "oracle.capability.expiry"
    facet = _FACET

    def score(self, obs: CapabilityObservation) -> Evidence:
        by_id = _tokens_by_id(obs)
        units = len(obs.uses)
        violations: list[str] = []
        for use in obs.uses:
            token = by_id.get(use.token_id)
            if token is None:
                violations.append(f"{use.token_id}:unknown-token")
                continue
            if use.epoch >= token.expires_epoch:
                violations.append(f"{use.token_id}:expired-use")
            if use.revoked and use.allowed:
                violations.append(f"{use.token_id}:revoked-but-allowed")

        outcome = _verdict(units, violations)
        observed = (
            f"{len(violations)} expiry/revocation violation(s) of {units} use(s)"
            if units
            else _no_observation("no capability use")
        )
        return _evidence(
            obs,
            self.oracle_id,
            "a capability token is never used at/after expiry or after revocation",
            observed,
            outcome,
            method="compare each use epoch with the token expiry and check revocation state",
            events=violations,
        )


class ScopeOracle:
    """An allowed use must stay inside the token's capabilities and scope."""

    oracle_id = "oracle.capability.scope"
    facet = _FACET

    def score(self, obs: CapabilityObservation) -> Evidence:
        by_id = _tokens_by_id(obs)
        allowed_uses = [use for use in obs.uses if use.allowed]
        units = len(allowed_uses)
        violations: list[str] = []
        for use in allowed_uses:
            token = by_id.get(use.token_id)
            if token is None:
                violations.append(f"{use.token_id}:unknown-token")
                continue
            if use.action not in token.capabilities:
                violations.append(f"{use.token_id}:action-out-of-scope")
            if _WILDCARD not in token.scope and use.resource not in token.scope:
                violations.append(f"{use.token_id}:resource-out-of-scope")

        outcome = _verdict(units, violations)
        observed = (
            f"{len(violations)} scope violation(s) of {units} allowed use(s)"
            if units
            else _no_observation("no allowed capability use")
        )
        return _evidence(
            obs,
            self.oracle_id,
            "every allowed use stays within the token's capabilities and resource scope",
            observed,
            outcome,
            method=(
                "recompute capability and scope membership independent of the target decision"
            ),
            events=violations,
        )


def capability_oracles() -> list[CapabilityOracle]:
    """Return the capability oracle registry in stable order."""

    return [
        AttenuationOracle(),
        ExpiryOracle(),
        ScopeOracle(),
    ]


__all__ = [
    "AttenuationOracle",
    "CapabilityObservation",
    "CapabilityOracle",
    "CapabilityToken",
    "CapabilityUse",
    "DelegationChain",
    "ExpiryOracle",
    "ScopeOracle",
    "capability_oracles",
]
