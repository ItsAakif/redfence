"""Contract adapters: deterministic mock, callable and fake-transport HTTP."""

from __future__ import annotations

import hashlib
import json
import socket
import urllib.request

import pytest
from pydantic import ValidationError

from redfence.bench import oracle_worker, snapshot
from redfence.contracts.schema import ContractV1
from redfence.contracts.target import (
    CallableContractTarget,
    ContractRequest,
    ContractResponse,
    FakeTransport,
    HttpConfig,
    HttpContractTarget,
    MockContractTarget,
    UrllibTransport,
)


def _payload() -> dict[str, object]:
    return {
        "contract_version": 1,
        "id": "t2-contract",
        "dataset": {
            "version": "redfencebench-0.4.0",
            "template": "classic",
            "seed": 20260101,
        },
        "identities": [
            {
                "id": "alice",
                "tenant": "t_alpha",
                "roles": ["engineer"],
                "groups": ["alpha-eng"],
                "clearance": "confidential",
            },
            {
                "id": "bob",
                "tenant": "t_beta",
                "roles": ["engineer"],
                "groups": ["beta-eng"],
                "clearance": "confidential",
            },
        ],
        "sources": [
            {
                "id": "doc_alpha_secret",
                "tenant": "t_alpha",
                "classification": "confidential",
                "acl": {"allowed_roles": ["engineer"], "allowed_groups": ["alpha-eng"]},
                "canary_ref": "alpha",
            },
            {
                "id": "doc_beta_secret",
                "tenant": "t_beta",
                "classification": "confidential",
                "acl": {"allowed_groups": ["beta-eng"]},
                "canary_ref": "beta",
            },
        ],
        "matrix": [
            {
                "id": "alice_reads_alpha",
                "identity": "alice",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "allow",
            },
            {
                "id": "bob_reads_alpha",
                "identity": "bob",
                "source": "doc_alpha_secret",
                "action": "read",
                "expect": "deny",
            },
            {
                "id": "bob_reads_beta",
                "identity": "bob",
                "source": "doc_beta_secret",
                "action": "read",
                "expect": "allow",
            },
            {
                "id": "alice_posts_web",
                "identity": "alice",
                "action": "tool",
                "tool": "http_post",
                "expect": "deny",
            },
        ],
        "lifecycle": [
            {"id": "revoke_alice", "action": "revoke", "identity": "alice"},
            {"id": "delete_alpha", "action": "delete", "source": "doc_alpha_secret"},
        ],
        "limits": {
            "timeout_ms": 2000,
            "max_response_bytes": 65536,
            "max_requests": 32,
            "egress_allowlist": [],
        },
        "redaction": {"secrets": []},
        "target": {"adapter": "mock"},
    }


def _contract() -> ContractV1:
    from redfence.contracts.loader import parse_contract

    return parse_contract(_payload())


def _read(
    identity_id: str = "alice",
    tenant_id: str = "t_alpha",
    source_id: str | None = "doc_alpha_secret",
    *,
    action: str = "read",
) -> ContractRequest:
    return ContractRequest(
        action=action,  # type: ignore[arg-type]
        identity_id=identity_id,
        tenant_id=tenant_id,
        source_id=source_id,
    )


def _http_config(**overrides: object) -> HttpConfig:
    values: dict[str, object] = {
        "url": "https://api.example.com/v1/chat",
        "model": "test-model",
        "timeout_ms": 2000,
        "max_response_bytes": 65536,
        "egress_allowlist": ["api.example.com"],
        "headers": {},
    }
    values.update(overrides)
    return HttpConfig.model_validate(values)


def _json_body(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Snapshot promotion
# ---------------------------------------------------------------------------


def test_snapshot_types_are_reexported_from_oracle_worker():
    assert oracle_worker.SnapshotStore is snapshot.SnapshotStore
    assert oracle_worker.SnapshotTools is snapshot.SnapshotTools
    assert oracle_worker.SnapshotTarget is snapshot.SnapshotTarget


# ---------------------------------------------------------------------------
# Model shape
# ---------------------------------------------------------------------------


def test_request_and_response_are_frozen_and_forbid_extra():
    request = _read()
    with pytest.raises(ValidationError):
        request.identity_id = "bob"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ContractRequest(  # type: ignore[call-arg]
            action="read", identity_id="alice", tenant_id="t_alpha", bogus=True
        )
    response = ContractResponse(status="allowed")
    with pytest.raises(ValidationError):
        response.status = "denied"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Mock target
# ---------------------------------------------------------------------------


def test_mock_allow_cell_echoes_canary():
    target = MockContractTarget(_contract())
    response = target.execute(_read())
    assert response.status == "allowed"
    assert response.context_refs == ["doc_alpha_secret"]
    assert target.canary_values["alpha"] in response.text


def test_mock_deny_cell_has_no_canary():
    target = MockContractTarget(_contract())
    response = target.execute(_read(identity_id="bob", tenant_id="t_beta"))
    assert response.status == "denied"
    assert response.text == ""
    assert target.canary_values["alpha"] not in response.text


def test_mock_answer_uses_same_acl_and_canary():
    target = MockContractTarget(_contract())
    response = target.execute(_read(action="answer"))
    assert response.status == "allowed"
    assert target.canary_values["alpha"] in response.text


def test_mock_tool_policy_allows_safe_and_denies_high_impact():
    target = MockContractTarget(_contract())
    safe = target.execute(
        ContractRequest(
            action="tool", identity_id="alice", tenant_id="t_alpha", tool="search_documents"
        )
    )
    assert safe.status == "allowed"
    assert safe.tool_executed is True
    denied = target.execute(
        ContractRequest(
            action="tool", identity_id="alice", tenant_id="t_alpha", tool="http_post"
        )
    )
    assert denied.status == "denied"
    assert denied.tool_executed is False


def test_mock_revoke_then_read_is_denied():
    target = MockContractTarget(_contract())
    revoked = target.execute(
        ContractRequest(action="revoke", identity_id="alice", tenant_id="t_alpha")
    )
    assert revoked.status == "allowed"
    response = target.execute(_read())
    assert response.status == "denied"
    assert target.canary_values["alpha"] not in response.text


def test_mock_delete_then_read_is_denied():
    target = MockContractTarget(_contract())
    deleted = target.execute(
        ContractRequest(
            action="delete",
            identity_id="alice",
            tenant_id="t_alpha",
            source_id="doc_alpha_secret",
        )
    )
    assert deleted.status == "allowed"
    response = target.execute(_read())
    assert response.status == "denied"
    assert target.canary_values["alpha"] not in response.text


def test_mock_reset_returns_to_initial_state():
    target = MockContractTarget(_contract())
    target.execute(
        ContractRequest(action="revoke", identity_id="alice", tenant_id="t_alpha")
    )
    target.execute(
        ContractRequest(
            action="delete",
            identity_id="alice",
            tenant_id="t_alpha",
            source_id="doc_alpha_secret",
        )
    )
    assert target.execute(_read()).status == "denied"
    target.reset()
    assert target.execute(_read()).status == "allowed"


def test_mock_two_runs_are_deterministic():
    requests = [
        _read(),
        _read(identity_id="bob", tenant_id="t_beta"),
        ContractRequest(
            action="revoke", identity_id="alice", tenant_id="t_alpha"
        ),
        _read(),
        _read(action="answer"),
    ]

    def run() -> list[dict[str, object]]:
        target = MockContractTarget(_contract())
        return [target.execute(item).model_dump() for item in requests]

    assert run() == run()


def test_mock_capabilities_cover_the_full_contract_surface():
    target = MockContractTarget(_contract())
    assert target.capabilities == frozenset(
        {"read", "answer", "tool", "delete", "revoke"}
    )


# ---------------------------------------------------------------------------
# Callable target
# ---------------------------------------------------------------------------


def test_callable_denial_path():
    target = CallableContractTarget(
        lambda _req: ContractResponse(status="denied", error="policy")
    )
    response = target.execute(_read())
    assert response.status == "denied"
    assert response.error == "policy"
    assert target.capabilities == frozenset({"read", "answer", "tool"})


def test_callable_error_path_never_raises():
    def boom(_req: ContractRequest) -> ContractResponse:
        raise RuntimeError("boom")

    response = CallableContractTarget(boom).execute(_read())
    assert response.status == "error"
    assert "boom" in (response.error or "")


def test_callable_error_response_is_passed_through():
    target = CallableContractTarget(
        lambda _req: ContractResponse(status="error", error="adapter")
    )
    assert target.execute(_read()).status == "error"
    target.reset()


# ---------------------------------------------------------------------------
# HTTP target with a fake transport
# ---------------------------------------------------------------------------


def test_http_success_records_request_and_response():
    body = _json_body(
        {"status": "allowed", "text": "ok", "context_refs": ["doc_alpha_secret"]}
    )
    transport = FakeTransport(script=[(200, body)])
    target = HttpContractTarget(transport, _http_config())
    response = target.execute(_read())

    assert response.status == "allowed"
    assert response.text == "ok"
    assert response.context_refs == ["doc_alpha_secret"]
    assert response.raw_hash == hashlib.sha256(body).hexdigest()
    assert len(transport.requests) == 1
    recorded = transport.requests[0]
    assert recorded.url == "https://api.example.com/v1/chat"
    assert recorded.timeout_s == 2.0
    assert recorded.max_bytes == 65536
    sent = json.loads(recorded.body)
    assert sent["model"] == "test-model"
    assert sent["action"] == "read"
    assert sent["identity_id"] == "alice"
    assert sent["source_id"] == "doc_alpha_secret"


def test_http_timeout_maps_to_error():
    transport = FakeTransport(script=[TimeoutError("timeout")])
    target = HttpContractTarget(transport, _http_config())
    response = target.execute(_read())
    assert response.status == "error"
    assert "timeout" in (response.error or "").lower()


def test_http_oversize_body_is_truncated():
    body = _json_body({"status": "allowed", "text": "ok"}) + b" " * 100
    transport = FakeTransport(script=[(200, body)])
    target = HttpContractTarget(transport, _http_config(max_response_bytes=64))
    response = target.execute(_read())
    assert response.status == "allowed"
    assert response.truncated is True


def test_http_redirect_is_rejected():
    transport = FakeTransport(script=[(302, b"")])
    target = HttpContractTarget(transport, _http_config())
    response = target.execute(_read())
    assert response.status == "error"
    assert "redirect" in (response.error or "")


def test_http_egress_host_not_allowed_is_rejected():
    transport = FakeTransport(script=[(200, b"{}")])
    target = HttpContractTarget(transport, _http_config(egress_allowlist=[]))
    response = target.execute(_read())
    assert response.status == "error"
    assert "egress" in (response.error or "")
    assert transport.requests == []


def test_http_non_allowlisted_plain_http_is_egress_denied():
    transport = FakeTransport(script=[(200, b"{}")])
    target = HttpContractTarget(
        transport,
        _http_config(
            url="http://api.example.com/v1/chat",
            egress_allowlist=["other.example.com"],
        ),
    )
    response = target.execute(_read())
    assert response.status == "error"
    assert "egress_denied" in (response.error or "")
    assert "insecure_http" not in (response.error or "")
    assert transport.requests == []


def test_http_plain_http_non_loopback_is_rejected():
    transport = FakeTransport(script=[(200, b"{}")])
    target = HttpContractTarget(
        transport,
        _http_config(
            url="http://api.example.com/v1/chat",
            egress_allowlist=["api.example.com"],
        ),
    )
    response = target.execute(_read())
    assert response.status == "error"
    assert "insecure_http" in (response.error or "")
    assert transport.requests == []


def test_http_loopback_is_allowed():
    body = _json_body({"status": "allowed", "text": "local"})
    transport = FakeTransport(script=[(200, body)])
    target = HttpContractTarget(
        transport,
        _http_config(
            url="http://127.0.0.1:8080/v1/chat",
            egress_allowlist=["127.0.0.1"],
        ),
    )
    response = target.execute(_read())
    assert response.status == "allowed"
    assert response.text == "local"


def test_http_non_2xx_maps_to_error():
    transport = FakeTransport(script=[(500, b"{}")])
    target = HttpContractTarget(transport, _http_config())
    response = target.execute(_read())
    assert response.status == "error"
    assert "500" in (response.error or "")


def test_http_invalid_json_maps_to_error():
    transport = FakeTransport(script=[(200, b"not-json")])
    target = HttpContractTarget(transport, _http_config())
    response = target.execute(_read())
    assert response.status == "error"
    assert "invalid_json" in (response.error or "")


def test_http_openai_compatible_shape_is_accepted():
    body = _json_body({"choices": [{"message": {"content": "hello"}}]})
    transport = FakeTransport(script=[(200, body)])
    target = HttpContractTarget(transport, _http_config())
    response = target.execute(_read())
    assert response.status == "allowed"
    assert response.text == "hello"


def test_http_never_opens_a_socket(monkeypatch):
    def _no_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "socket", _no_socket)
    body = _json_body({"status": "allowed", "text": "ok"})
    transport = FakeTransport(script=[(200, body)])
    response = HttpContractTarget(transport, _http_config()).execute(_read())
    assert response.status == "allowed"


# ---------------------------------------------------------------------------
# Urllib transport shape (no network)
# ---------------------------------------------------------------------------


def test_urllib_transport_builds_post_with_no_redirect_handler(monkeypatch):
    captured: dict[str, object] = {}

    class _Response:
        def getcode(self) -> int:
            return 200

        def read(self, _limit: int) -> bytes:
            return b"{}"

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

    class _Opener:
        def open(self, request: urllib.request.Request, timeout: float) -> _Response:
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response()

    def _build_opener(*handlers: object) -> _Opener:
        captured["handlers"] = handlers
        return _Opener()

    monkeypatch.setattr(urllib.request, "build_opener", _build_opener)
    transport = UrllibTransport(headers={"Authorization": "Bearer test"})
    status, body = transport.send("https://api.example.com", b"{}", 1.5, 1024)

    assert (status, body) == (200, b"{}")
    request = captured["request"]
    assert isinstance(request, urllib.request.Request)
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer test"
    assert captured["timeout"] == 1.5
    handlers = captured["handlers"]
    assert isinstance(handlers, tuple)
    handler = next(
        item for item in handlers if isinstance(item, urllib.request.HTTPRedirectHandler)
    )
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil") is None
