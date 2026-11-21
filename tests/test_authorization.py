"""Authorization predicate tests (the trusted policy, independent of any model)."""

from __future__ import annotations

from redfence.core.domain import ACL, Principal


def _principal(**kwargs) -> Principal:
    base = dict(
        id="p1",
        tenant_id="t1",
        display_name="P",
        roles=["engineer"],
        groups=["g1"],
        clearance="confidential",
        capabilities=["docs.search"],
    )
    base.update(kwargs)
    return Principal(**base)


def test_role_grant_allows():
    acl = ACL(tenant_id="t1", classification="confidential", allowed_roles=["engineer"])
    assert acl.permits(_principal()) is True


def test_missing_role_denies():
    acl = ACL(tenant_id="t1", classification="confidential", allowed_roles=["analyst"])
    assert acl.permits(_principal()) is False


def test_cross_tenant_denies():
    acl = ACL(tenant_id="t2", classification="internal", allowed_roles=["engineer"])
    assert acl.permits(_principal()) is False


def test_clearance_denies():
    acl = ACL(tenant_id="t1", classification="secret", allowed_roles=["engineer"])
    assert acl.permits(_principal(clearance="confidential")) is False


def test_revoked_principal_denies():
    acl = ACL(tenant_id="t1", classification="internal", allowed_roles=["engineer"])
    assert acl.permits(_principal(revoked=True)) is False
