"""Capability tokens, delegation attenuation, and additive policy behaviour."""

from __future__ import annotations

import pytest

from redfence.bench.dataset import HELDOUT_FAMILIES
from redfence.bench.heldout import run_heldout_scenario
from redfence.core.capability import (
    AttenuationOracle,
    CapabilityObservation,
    CapabilityToken,
    CapabilityUse,
    DelegationChain,
    ExpiryOracle,
    ScopeOracle,
    capability_oracles,
)
from redfence.core.domain import Principal, ToolCall
from redfence.core.evidence import Outcome
from redfence.targets.config import SecurityProfile
from redfence.targets.policy import DefaultToolPolicy
from redfence.targets.tools import SyntheticToolRuntime


def _token(
    token_id: str = "tok_root",
    *,
    subject: str = "p_root",
    issuer: str = "issuer.root",
    capabilities: tuple[str, ...] = ("docs.search", "files.read"),
    scope: tuple[str, ...] = ("*",),
    issued: int = 1,
    expires: int = 20,
    delegated_from: str | None = None,
) -> CapabilityToken:
    return CapabilityToken(
        token_id=token_id,
        subject=subject,
        issuer=issuer,
        capabilities=frozenset(capabilities),
        scope=frozenset(scope),
        issued_epoch=issued,
        expires_epoch=expires,
        delegated_from=delegated_from,
    )


def _chain(*links: CapabilityToken) -> DelegationChain:
    return DelegationChain(links=list(links))


def _child(
    *,
    token_id: str = "tok_child",
    subject: str = "p_child",
    issuer: str = "p_root",
    capabilities: tuple[str, ...] = ("docs.search",),
    scope: tuple[str, ...] = ("search_documents",),
    issued: int = 2,
    expires: int = 10,
    delegated_from: str | None = "tok_root",
) -> CapabilityToken:
    return _token(
        token_id,
        subject=subject,
        issuer=issuer,
        capabilities=capabilities,
        scope=scope,
        issued=issued,
        expires=expires,
        delegated_from=delegated_from,
    )


def _use(
    *,
    token_id: str = "tok_child",
    action: str = "docs.search",
    resource: str = "search_documents",
    epoch: int = 3,
    revoked: bool = False,
    allowed: bool = True,
) -> CapabilityUse:
    return CapabilityUse(
        token_id=token_id,
        action=action,
        resource=resource,
        epoch=epoch,
        revoked=revoked,
        allowed=allowed,
    )


def _observation(
    links: list[CapabilityToken], uses: list[CapabilityUse]
) -> CapabilityObservation:
    return CapabilityObservation(chain=DelegationChain(links=links), uses=uses)


# -- attenuation -----------------------------------------------------------


def test_valid_chain_is_satisfied_for_every_oracle():
    obs = _observation([_token(), _child()], [_use()])
    assert obs.chain.validate_attenuation() == []
    for oracle in capability_oracles():
        assert oracle.score(obs).outcome is Outcome.SATISFIED, oracle.oracle_id


def test_single_link_has_zero_attenuation_units():
    obs = _observation([_token()], [])
    assert AttenuationOracle().score(obs).outcome is Outcome.UNSUPPORTED


def test_widened_capability_is_a_violation():
    child = _child(capabilities=("docs.search", "files.read"))
    obs = _observation([_token(capabilities=("docs.search",)), child], [_use()])
    evidence = AttenuationOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert any("tok_child" in event for event in evidence.events)
    assert "tok_child:capability-not-attenuated" in evidence.events


def test_widened_scope_is_a_violation():
    child = _child(scope=("search_documents", "read_file"))
    obs = _observation([_token(scope=("search_documents",)), child], [_use()])
    evidence = AttenuationOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:scope-not-attenuated" in evidence.events


def test_extended_expiry_is_a_violation():
    child = _child(expires=30)
    obs = _observation([_token(expires=20), child], [_use()])
    evidence = AttenuationOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:expiry-extended" in evidence.events


def test_child_issued_before_parent_is_a_violation():
    child = _child(issued=0)
    obs = _observation([_token(issued=1), child], [_use()])
    evidence = AttenuationOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:issued-before-parent" in evidence.events


def test_wrong_delegated_from_is_a_violation():
    child = _child(delegated_from="tok_other")
    obs = _observation([_token(), child], [_use()])
    evidence = AttenuationOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:delegated-from-mismatch" in evidence.events


# -- expiry / revocation ---------------------------------------------------


def test_expired_use_is_a_violation():
    obs = _observation([_token(), _child(expires=10)], [_use(epoch=10)])
    evidence = ExpiryOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:expired-use" in evidence.events


def test_revoked_but_allowed_use_is_a_violation():
    obs = _observation([_token(), _child()], [_use(revoked=True, allowed=True)])
    evidence = ExpiryOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:revoked-but-allowed" in evidence.events


def test_use_before_expiry_is_satisfied():
    obs = _observation([_token(), _child(expires=10)], [_use(epoch=9)])
    assert ExpiryOracle().score(obs).outcome is Outcome.SATISFIED


# -- scope -----------------------------------------------------------------


def test_out_of_scope_tool_is_a_violation():
    obs = _observation(
        [_token(), _child()],
        [_use(action="files.read", resource="read_file")],
    )
    evidence = ScopeOracle().score(obs)
    assert evidence.outcome is Outcome.VIOLATION
    assert "tok_child:action-out-of-scope" in evidence.events
    assert "tok_child:resource-out-of-scope" in evidence.events


def test_wildcard_scope_allows_any_resource():
    token = _child(scope=("*",))
    obs = _observation([_token(), token], [_use(resource="read_file")])
    assert ScopeOracle().score(obs).outcome is Outcome.SATISFIED


def test_denied_use_is_not_a_scope_unit():
    obs = _observation(
        [_token(), _child()],
        [_use(action="files.read", resource="read_file", allowed=False)],
    )
    assert ScopeOracle().score(obs).outcome is Outcome.UNSUPPORTED


# -- zero units ------------------------------------------------------------


def test_zero_links_and_uses_are_unsupported_for_every_oracle():
    obs = _observation([], [])
    for oracle in capability_oracles():
        assert oracle.score(obs).outcome is Outcome.UNSUPPORTED, oracle.oracle_id


def test_zero_uses_leave_expiry_and_scope_unsupported():
    obs = _observation([_token(), _child()], [])
    assert AttenuationOracle().score(obs).outcome is Outcome.SATISFIED
    assert ExpiryOracle().score(obs).outcome is Outcome.UNSUPPORTED
    assert ScopeOracle().score(obs).outcome is Outcome.UNSUPPORTED


# -- policy additive behaviour ---------------------------------------------


def _principal(
    *,
    principal_id: str = "p_test",
    tenant_id: str = "t_alpha",
    display_name: str = "Test",
    capabilities: list[str] | None = None,
    revoked: bool = False,
) -> Principal:
    return Principal(
        id=principal_id,
        tenant_id=tenant_id,
        display_name=display_name,
        capabilities=["docs.search"] if capabilities is None else capabilities,
        revoked=revoked,
    )


def test_policy_without_token_is_unchanged():
    runtime = SyntheticToolRuntime()
    principal = _principal(
        capabilities=[
            "docs.search",
            "files.read",
            "db.read",
            "net.egress",
            "mail.send",
            "tasks.execute",
        ]
    )
    approvals = {f"{principal.id}:{spec.name}" for spec in runtime.all_specs()}
    policy = DefaultToolPolicy()
    for spec in runtime.all_specs():
        call = ToolCall(name=spec.name, args={})
        baseline = policy.decide(
            principal,
            call,
            spec.required_capability,
            spec.high_impact,
            approvals=approvals,
        )
        explicit_none = policy.decide(
            principal,
            call,
            spec.required_capability,
            spec.high_impact,
            approvals=approvals,
            token=None,
        )
        assert explicit_none.model_dump() == baseline.model_dump(), spec.name

    # The denial paths are unchanged too.
    limited = _principal()
    call = ToolCall(name="read_file", args={})
    baseline_denied = policy.decide(limited, call, "files.read", False)
    none_denied = policy.decide(limited, call, "files.read", False, token=None)
    assert none_denied.model_dump() == baseline_denied.model_dump()
    assert none_denied.matched_rule == "capability.missing"


def test_policy_accepts_a_valid_token():
    decision = DefaultToolPolicy().decide(
        _principal(),
        ToolCall(name="search_documents"),
        "docs.search",
        False,
        token=_token(subject="p_test"),
        now_epoch=5,
    )
    assert decision.allowed is True


def test_policy_denies_token_issued_to_another_principal():
    decision = DefaultToolPolicy().decide(
        _principal(principal_id="mallory"),
        ToolCall(name="search_documents"),
        "docs.search",
        False,
        token=_token(subject="alice"),
        now_epoch=5,
    )
    assert decision.allowed is False
    assert decision.matched_rule == "token.subject"


def test_policy_denies_token_used_before_issue():
    decision = DefaultToolPolicy().decide(
        _principal(principal_id="alice"),
        ToolCall(name="search_documents"),
        "docs.search",
        False,
        token=_token(subject="alice", issued=10, expires=20),
        now_epoch=5,
    )
    assert decision.allowed is False
    assert decision.matched_rule == "token.not_yet_valid"


def test_policy_denies_expired_token_only_when_an_epoch_is_supplied():
    policy = DefaultToolPolicy()
    call = ToolCall(name="search_documents")
    expired = policy.decide(
        _principal(),
        call,
        "docs.search",
        False,
        token=_token(subject="p_test", expires=5),
        now_epoch=5,
    )
    assert expired.allowed is False
    assert expired.matched_rule == "token.expired"

    no_epoch = policy.decide(
        _principal(), call, "docs.search", False, token=_token(subject="p_test", expires=5)
    )
    assert no_epoch.allowed is True


def test_policy_denies_capability_outside_the_token():
    decision = DefaultToolPolicy().decide(
        _principal(capabilities=["files.read"]),
        ToolCall(name="read_file"),
        "files.read",
        False,
        token=_token(subject="p_test", capabilities=("docs.search",)),
    )
    assert decision.allowed is False
    assert decision.matched_rule == "token.capability"


def test_policy_denies_resource_outside_the_token_scope():
    decision = DefaultToolPolicy().decide(
        _principal(),
        ToolCall(name="search_documents"),
        "docs.search",
        False,
        token=_token(subject="p_test", scope=("read_file",)),
    )
    assert decision.allowed is False
    assert decision.matched_rule == "token.scope"


def test_policy_wildcard_scope_allows_the_call():
    decision = DefaultToolPolicy().decide(
        _principal(),
        ToolCall(name="search_documents"),
        "docs.search",
        False,
        token=_token(subject="p_test", scope=("*",)),
    )
    assert decision.allowed is True


def test_policy_denies_revoked_principal_even_with_a_token():
    decision = DefaultToolPolicy().decide(
        _principal(revoked=True),
        ToolCall(name="search_documents"),
        "docs.search",
        False,
        token=_token(),
    )
    assert decision.allowed is False
    assert decision.matched_rule == "principal.revoked"


# -- held-out integration --------------------------------------------------


def test_delegation_chain_heldout_outcomes_are_unchanged():
    secured = run_heldout_scenario("delegation.chain", SecurityProfile.SECURED)
    vulnerable = run_heldout_scenario("delegation.chain", SecurityProfile.VULNERABLE)

    assert [e.oracle_id for e in secured.evidence] == ["oracle.tool.policy"]
    assert secured.exit_code == 0
    assert secured.evidence[0].outcome is Outcome.SATISFIED

    assert [e.oracle_id for e in vulnerable.evidence] == ["oracle.tool.policy"]
    assert vulnerable.exit_code == 1
    assert vulnerable.evidence[0].outcome is Outcome.VIOLATION


@pytest.mark.parametrize("family", HELDOUT_FAMILIES)
def test_all_heldout_families_still_discriminate(family: str):
    secured = run_heldout_scenario(family, SecurityProfile.SECURED)
    vulnerable = run_heldout_scenario(family, SecurityProfile.VULNERABLE)
    assert secured.exit_code == 0, family
    assert vulnerable.exit_code == 1, family
