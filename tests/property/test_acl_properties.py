"""Optional Hypothesis-backed ACL invariants (T11 / ADR-0016).

Collection skips cleanly when Hypothesis is absent; install the ``property``
extra to run them. Settings are derandomized so failures reproduce.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from redfence.core.domain import (  # noqa: E402
    ACL,
    CLASSIFICATION_RANK,
    Document,
    Principal,
    Provenance,
)
from redfence.targets.config import FaultFlags  # noqa: E402
from redfence.targets.rag_target import ConfigurableRAGTarget  # noqa: E402

pytestmark = pytest.mark.property

TENANTS = st.sampled_from(["tenant-alpha", "tenant-beta"])
CLEARANCES = st.sampled_from(list(CLASSIFICATION_RANK))
ROLES = st.lists(st.sampled_from(["reader", "lead", "intern"]), max_size=3, unique=True)
GROUPS = st.lists(st.sampled_from(["eng", "ops", "legal"]), max_size=3, unique=True)


def _principal(
    *,
    tenant_id: str,
    clearance: str = "public",
    roles: list[str] | None = None,
    groups: list[str] | None = None,
    revoked: bool = False,
) -> Principal:
    return Principal(
        id="principal-1",
        tenant_id=tenant_id,
        display_name="Property Principal",
        roles=list(roles or []),
        groups=list(groups or []),
        clearance=clearance,
        revoked=revoked,
    )


@given(
    principal_tenant=TENANTS,
    acl_tenant=TENANTS,
    clearance=CLEARANCES,
    public=st.booleans(),
    roles=ROLES,
    groups=GROUPS,
)
@settings(derandomize=True, max_examples=50)
def test_tenant_isolation(
    principal_tenant: str,
    acl_tenant: str,
    clearance: str,
    public: bool,
    roles: list[str],
    groups: list[str],
) -> None:
    """A principal in tenant A never permits a document in tenant B."""

    assume(principal_tenant != acl_tenant)
    principal = _principal(
        tenant_id=principal_tenant, clearance=clearance, roles=roles, groups=groups
    )
    acl = ACL(
        tenant_id=acl_tenant,
        classification="public",
        public=public,
        allowed_roles=list(roles),
        allowed_groups=list(groups),
        allowed_principals=[principal.id],
    )

    assert not acl.permits(principal)


@given(
    tenant=TENANTS,
    clearance=CLEARANCES,
    roles=ROLES,
    groups=GROUPS,
    public=st.booleans(),
)
@settings(derandomize=True, max_examples=50)
def test_revoked_principals_are_denied(
    tenant: str,
    clearance: str,
    roles: list[str],
    groups: list[str],
    public: bool,
) -> None:
    """A revoked principal is denied even when every other check would pass."""

    principal = _principal(
        tenant_id=tenant,
        clearance=clearance,
        roles=roles,
        groups=groups,
        revoked=True,
    )
    acl = ACL(
        tenant_id=tenant,
        classification="public",
        public=public,
        allowed_roles=list(roles),
        allowed_groups=list(groups),
        allowed_principals=[principal.id],
    )

    assert not acl.permits(principal)


@given(
    tenant=TENANTS,
    low_rank=st.integers(min_value=0, max_value=3),
    high_rank=st.integers(min_value=0, max_value=3),
    acl_rank=st.integers(min_value=0, max_value=3),
    roles=ROLES,
    groups=GROUPS,
)
@settings(derandomize=True, max_examples=50)
def test_clearance_monotonicity(
    tenant: str,
    low_rank: int,
    high_rank: int,
    acl_rank: int,
    roles: list[str],
    groups: list[str],
) -> None:
    """Raising clearance never removes a permission for the same roles/groups."""

    assume(low_rank <= high_rank)
    names = list(CLASSIFICATION_RANK)
    acl = ACL(
        tenant_id=tenant,
        classification=names[acl_rank],
        allowed_roles=list(roles),
        allowed_groups=list(groups),
    )
    low = _principal(tenant_id=tenant, clearance=names[low_rank], roles=roles, groups=groups)
    high = _principal(tenant_id=tenant, clearance=names[high_rank], roles=roles, groups=groups)

    if acl.permits(low):
        assert acl.permits(high)


def _target_with_document() -> ConfigurableRAGTarget:
    target = ConfigurableRAGTarget(name="property", faults=FaultFlags())
    document = Document(
        id="doc-property",
        tenant_id="tenant-alpha",
        title="Property document",
        content="line one\nline two",
        classification="internal",
        owner="owner",
        acl=ACL(
            tenant_id="tenant-alpha",
            classification="internal",
            allowed_roles=["reader"],
            epoch=1,
        ),
        provenance=Provenance(
            source="property",
            ingested_at="2026-01-01T00:00:00+00:00",
            content_hash="0" * 64,
            version=1,
        ),
    )
    target.ingest(document)
    return target


@given(classification=CLEARANCES)
@settings(derandomize=True, max_examples=50)
def test_document_acl_epoch_monotonicity(classification: str) -> None:
    """modify_document_acl bumps only the document epoch, never the global epoch."""

    target = _target_with_document()
    global_epoch = target.current_epoch
    before = max(chunk.acl.epoch for chunk in target.store.all_chunks())

    assert target.modify_document_acl("doc-property", classification=classification)

    after = {chunk.acl.epoch for chunk in target.store.all_chunks()}
    assert after == {before + 1}
    assert target.current_epoch == global_epoch
