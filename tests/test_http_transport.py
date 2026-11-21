"""Loopback transport tests over a real socket.

These tests are marked ``integration`` but stay in the default suite: they bind
to ``127.0.0.1`` on an ephemeral port and never reach an external network. Each
server is always shut down and closed in ``finally``.
"""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redfence.contracts.target import (
    ContractRequest,
    HttpConfig,
    HttpContractTarget,
    UrllibTransport,
)

pytestmark = pytest.mark.integration

# status, headers, body
Reply = tuple[int, dict[str, str], bytes]


def _json_body(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True).encode("utf-8")


@contextmanager
def _loopback_server(responder: Callable[[bytes], Reply]) -> Iterator[tuple[int, list[bytes]]]:
    """Serve ``responder`` on ``127.0.0.1:0`` and record every request body."""

    requests: list[bytes] = []

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return None

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            requests.append(body)
            status, headers, payload = responder(body)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _handle
        do_POST = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1]), requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _request(**overrides: object) -> ContractRequest:
    fields: dict[str, object] = {
        "action": "read",
        "identity_id": "alice",
        "tenant_id": "t_alpha",
        "source_id": "doc_alpha_secret",
        "query": "alpha secret",
        "timeout_ms": 5000,
    }
    fields.update(overrides)
    return ContractRequest.model_validate(fields)


def _target(port: int, **overrides: object) -> HttpContractTarget:
    values: dict[str, object] = {
        "url": f"http://127.0.0.1:{port}/v1/chat",
        "model": "loopback-target",
        "timeout_ms": 5000,
        "egress_allowlist": ["127.0.0.1"],
    }
    values.update(overrides)
    return HttpContractTarget(UrllibTransport(), HttpConfig.model_validate(values))


def test_loopback_success_round_trip() -> None:
    payload = {
        "status": "allowed",
        "text": "ok",
        "context_refs": ["doc_alpha_secret"],
    }
    reply: Reply = (200, {"Content-Type": "application/json"}, _json_body(payload))
    with _loopback_server(lambda _body: reply) as (port, _requests):
        response = _target(port).execute(_request())

    assert response.status == "allowed"
    assert response.text == "ok"
    assert response.context_refs == ["doc_alpha_secret"]
    assert response.truncated is False


def test_loopback_redirect_is_rejected_without_following() -> None:
    target_reply: Reply = (
        200,
        {"Content-Type": "application/json"},
        _json_body({"status": "allowed", "text": "should-not-be-reached"}),
    )
    with _loopback_server(lambda _body: target_reply) as (target_port, target_requests):
        location = f"http://127.0.0.1:{target_port}/"
        redirect_reply: Reply = (302, {"Location": location}, b"")
        with _loopback_server(lambda _body: redirect_reply) as (port, _redirects):
            response = _target(port).execute(_request())

        assert target_requests == []

    assert response.status == "error"
    assert response.error == "redirect_not_allowed"


def test_loopback_oversize_body_is_truncated() -> None:
    oversized = _json_body({"status": "allowed", "text": "ok"}) + b" " * 80
    reply: Reply = (200, {"Content-Type": "application/json"}, oversized)
    with _loopback_server(lambda _body: reply) as (port, _requests):
        response = _target(port, max_response_bytes=64).execute(_request())

    assert response.status == "allowed"
    assert response.text == "ok"
    assert response.truncated is True


def test_loopback_suffix_host_is_egress_denied() -> None:
    reply: Reply = (200, {"Content-Type": "application/json"}, _json_body({"status": "allowed"}))
    with _loopback_server(lambda _body: reply) as (port, requests):
        target = _target(
            port,
            url=f"http://127.0.0.1.evil.com:{port}/v1/chat",
            egress_allowlist=["127.0.0.1"],
        )
        response = target.execute(_request())

    assert response.status == "error"
    assert "egress" in (response.error or "")
    assert requests == []


def test_allowlisted_non_loopback_http_is_rejected_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _no_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "socket", _no_socket)
    target = _target(
        1,
        url="http://example.invalid/v1/chat",
        egress_allowlist=["example.invalid"],
    )
    response = target.execute(_request())

    assert response.status == "error"
    assert "insecure_http" in (response.error or "")


def test_loopback_request_body_is_json_with_action_and_identity() -> None:
    reply: Reply = (200, {"Content-Type": "application/json"}, _json_body({"status": "allowed"}))
    with _loopback_server(lambda _body: reply) as (port, requests):
        response = _target(port).execute(
            _request(action="tool", tool="search_documents")
        )

    assert response.status == "allowed"
    assert len(requests) == 1
    sent = json.loads(requests[0])
    assert sent["action"] == "tool"
    assert sent["identity_id"] == "alice"
    assert sent["tenant_id"] == "t_alpha"
    assert sent["tool"] == "search_documents"
