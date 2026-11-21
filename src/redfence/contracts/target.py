"""Contract target adapters.

The contract runner talks to a system under test only through
:class:`ContractTarget`. A target answers a :class:`ContractRequest` with a
:class:`ContractResponse`; it never exposes live cache or store internals. The
three adapters are deliberately small:

* :class:`MockContractTarget` is a deterministic in-memory reference target
  built from a contract's identities, sources and ACLs.
* :class:`CallableContractTarget` wraps a Python callable (API-only).
* :class:`HttpContractTarget` posts JSON to an allowlisted endpoint through a
  :class:`Transport`. It never raises: timeouts, bad URLs, redirects and
  oversized bodies all become ``status="error"`` or ``truncated=True``.

HTTP imports are lazy; importing this module does not import ``urllib``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from redfence.contracts.schema import ContractV1, IdentitySpec, SourceSpec
from redfence.core.domain import CLASSIFICATION_RANK
from redfence.core.ids import content_hash, json_digest

_ALLOWED_STATUSES = frozenset({"allowed", "denied", "error"})
_SAFE_TOOLS = frozenset({"search_documents", "read_file", "db_query"})
_LOOPBACK_HOSTS = frozenset({"localhost"})


class ContractRequest(BaseModel):
    """One adapter call, fully described by the contract runner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Literal["read", "answer", "tool", "delete", "revoke"]
    identity_id: str
    tenant_id: str
    source_id: str | None = None
    query: str | None = None
    tool: str | None = None
    args: dict[str, object] = Field(default_factory=dict)
    timeout_ms: int = 2000
    max_response_bytes: int = 65536


class ContractResponse(BaseModel):
    """The only thing an adapter may return to the runner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["allowed", "denied", "error"]
    text: str = ""
    context_refs: list[str] = Field(default_factory=list)
    tool_executed: bool = False
    side_effect: dict[str, object] = Field(default_factory=dict)
    error: str | None = None
    truncated: bool = False
    raw_hash: str = ""
    samples: list[str] = Field(default_factory=list)


class ContractTarget(Protocol):
    name: str
    capabilities: frozenset[str]

    def execute(self, req: ContractRequest) -> ContractResponse: ...

    def reset(self) -> None: ...


class Transport(Protocol):
    def send(
        self, url: str, body: bytes, timeout_s: float, max_bytes: int
    ) -> tuple[int, bytes]: ...


@dataclass(frozen=True)
class RecordedRequest:
    """A transport call captured by :class:`FakeTransport`."""

    url: str
    body: bytes
    timeout_s: float
    max_bytes: int


@dataclass
class FakeTransport:
    """Scripted transport for tests; never opens a socket.

    Each script item is either ``(status, body)`` or an exception instance. A
    missing script item raises, which lets a test catch accidental extra calls.
    """

    script: list[tuple[int, bytes] | BaseException] = field(default_factory=list)
    requests: list[RecordedRequest] = field(default_factory=list)

    def send(
        self, url: str, body: bytes, timeout_s: float, max_bytes: int
    ) -> tuple[int, bytes]:
        self.requests.append(RecordedRequest(url, body, timeout_s, max_bytes))
        if not self.script:
            raise RuntimeError("FakeTransport has no scripted response")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _canary_value(seed: int, label: str) -> str:
    """Reproduce the corpus canary format from a contract seed and label."""

    digest = hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()[:8].upper()
    return f"CANARY_{label.upper()}_{digest}"


class MockContractTarget:
    """Deterministic reference target implementing a contract's ACL matrix."""

    name = "mock"
    capabilities = frozenset({"read", "answer", "tool", "delete", "revoke"})

    def __init__(self, contract: ContractV1) -> None:
        self.contract = contract
        self._identities: dict[str, IdentitySpec] = {
            item.id: item for item in contract.identities
        }
        self._sources: dict[str, SourceSpec] = {item.id: item for item in contract.sources}
        self._canaries: dict[str, str] = {
            source.canary_ref: _canary_value(contract.dataset.seed, source.canary_ref)
            for source in contract.sources
            if source.canary_ref is not None
        }
        self._revoked: set[str] = set()
        self._deleted: set[str] = set()
        self.reset()

    @property
    def canary_values(self) -> dict[str, str]:
        """Canary label -> deterministic marker echoed on allowed reads."""

        return dict(self._canaries)

    def reset(self) -> None:
        """Return to the contract's declared initial state."""

        self._revoked = {item.id for item in self._identities.values() if item.revoked}
        self._deleted = set()

    def execute(self, req: ContractRequest) -> ContractResponse:
        if req.action == "read" or req.action == "answer":
            return self._retrieval(req)
        if req.action == "tool":
            return self._tool(req)
        if req.action == "delete" or req.action == "revoke":
            return self._lifecycle(req)
        return _error_response("unsupported_action")

    def _retrieval(self, req: ContractRequest) -> ContractResponse:
        identity = self._identities.get(req.identity_id)
        if identity is None:
            return _error_response("unknown_identity")
        if identity.tenant != req.tenant_id:
            return _denied_response()
        if req.source_id is None:
            return _denied_response()
        source = self._sources.get(req.source_id)
        if source is None:
            return _error_response("unknown_source")
        if not self._permits(identity, source):
            return _denied_response()
        text = self._text_for(source)
        return ContractResponse(
            status="allowed",
            text=text,
            context_refs=[source.id],
            raw_hash=content_hash(text),
        )

    def _tool(self, req: ContractRequest) -> ContractResponse:
        identity = self._identities.get(req.identity_id)
        if identity is None:
            return _error_response("unknown_identity")
        if identity.tenant != req.tenant_id or identity.id in self._revoked:
            return _denied_response()
        if req.tool is None:
            return _error_response("missing_tool")
        if req.tool in _SAFE_TOOLS:
            side_effect: dict[str, object] = {"tool": req.tool}
            return ContractResponse(
                status="allowed",
                tool_executed=True,
                side_effect=side_effect,
                raw_hash=json_digest(side_effect),
            )
        # High-impact and unknown tools are denied by the reference target.
        return _denied_response()

    def _lifecycle(self, req: ContractRequest) -> ContractResponse:
        if req.action == "revoke":
            if req.identity_id not in self._identities:
                return _error_response("unknown_identity")
            self._revoked.add(req.identity_id)
            side_effect: dict[str, object] = {"revoked": req.identity_id}
        else:
            if req.source_id is None:
                return _error_response("missing_source")
            if req.source_id not in self._sources:
                return _error_response("unknown_source")
            self._deleted.add(req.source_id)
            side_effect = {"deleted": req.source_id}
        return ContractResponse(
            status="allowed",
            side_effect=side_effect,
            raw_hash=json_digest(side_effect),
        )

    def _permits(self, identity: IdentitySpec, source: SourceSpec) -> bool:
        if identity.id in self._revoked or source.id in self._deleted:
            return False
        if identity.tenant != source.tenant:
            return False
        identity_rank = CLASSIFICATION_RANK.get(identity.clearance, 0)
        source_rank = CLASSIFICATION_RANK.get(source.classification, 0)
        if identity_rank < source_rank:
            return False
        acl = source.acl
        if acl.public:
            return True
        if identity.id in acl.allowed_principals:
            return True
        if set(identity.roles) & set(acl.allowed_roles):
            return True
        if set(identity.groups) & set(acl.allowed_groups):
            return True
        return False

    def _text_for(self, source: SourceSpec) -> str:
        if source.canary_ref is None:
            return source.id
        canary = self._canaries.get(source.canary_ref)
        return f"{source.id} {canary}" if canary is not None else source.id


class CallableContractTarget:
    """Adapter for a Python callable; never available from a loaded contract."""

    capabilities = frozenset({"read", "answer", "tool"})

    def __init__(
        self,
        fn: Callable[[ContractRequest], ContractResponse],
        name: str = "callable",
    ) -> None:
        self._fn = fn
        self.name = name

    def execute(self, req: ContractRequest) -> ContractResponse:
        try:
            return self._fn(req)
        except Exception as error:  # noqa: BLE001 - adapter boundary must not raise
            return _error_response(f"{type(error).__name__}: {error}")

    def reset(self) -> None:
        return None


class HttpConfig(BaseModel):
    """Endpoint, budget and egress policy for :class:`HttpContractTarget`."""

    model_config = ConfigDict(extra="forbid")

    url: str
    model: str = "redfence-target"
    timeout_ms: int = 2000
    max_response_bytes: int = 65536
    egress_allowlist: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)


class HttpContractTarget:
    """JSON-over-HTTP adapter with a strict egress boundary."""

    name = "http"
    capabilities = frozenset({"read", "answer", "tool"})

    def __init__(self, transport: Transport, config: HttpConfig) -> None:
        self._transport = transport
        self.config = config

    def reset(self) -> None:
        return None

    def execute(self, req: ContractRequest) -> ContractResponse:
        try:
            self._check_url()
            body = self._encode(req)
            status, raw = self._transport.send(
                self.config.url,
                body,
                self.config.timeout_ms / 1000.0,
                self.config.max_response_bytes,
            )
            return self._decode(status, raw)
        except Exception as error:  # noqa: BLE001 - adapter boundary must not raise
            return _error_response(f"{type(error).__name__}: {error}")

    def _check_url(self) -> None:
        parts = urlsplit(self.config.url)
        if parts.scheme not in {"http", "https"}:
            raise ValueError("unsupported_scheme")
        host = parts.hostname
        if not host:
            raise ValueError("missing_host")
        # Check the allowlist first so the common denial is reported as egress;
        # an allowlisted plain-http non-loopback host is still insecure.
        allowed = {item.lower() for item in self.config.egress_allowlist}
        if host.lower() not in allowed:
            raise ValueError("egress_denied")
        if parts.scheme == "http" and not _is_loopback(host):
            raise ValueError("insecure_http")

    def _encode(self, req: ContractRequest) -> bytes:
        payload = {
            "model": self.config.model,
            "action": req.action,
            "identity_id": req.identity_id,
            "tenant_id": req.tenant_id,
            "source_id": req.source_id,
            "query": req.query,
            "tool": req.tool,
            "args": req.args,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    def _decode(self, status: int, raw: bytes) -> ContractResponse:
        max_bytes = self.config.max_response_bytes
        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]
        raw_hash = hashlib.sha256(raw).hexdigest()

        if 300 <= status < 400:
            return _error_response("redirect_not_allowed", truncated, raw_hash)
        if status < 200 or status >= 300:
            return _error_response(f"http_status_{status}", truncated, raw_hash)
        if not raw:
            return _error_response("empty_response", truncated, raw_hash)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            return _error_response(f"invalid_json: {error}", truncated, raw_hash)
        if not isinstance(payload, dict):
            return _error_response("invalid_response", truncated, raw_hash)

        status_value = payload.get("status")
        if status_value is not None:
            if not isinstance(status_value, str) or status_value not in _ALLOWED_STATUSES:
                return _error_response("invalid_status", truncated, raw_hash)
            return ContractResponse(
                status=cast(Literal["allowed", "denied", "error"], status_value),
                text=_as_text(payload.get("text")),
                context_refs=_as_str_list(payload.get("context_refs")),
                tool_executed=bool(payload.get("tool_executed", False)),
                side_effect=_as_dict(payload.get("side_effect")),
                error=_as_optional_text(payload.get("error")),
                truncated=truncated or bool(payload.get("truncated", False)),
                raw_hash=raw_hash,
                samples=_as_str_list(payload.get("samples")),
            )

        if "error" in payload:
            return ContractResponse(
                status="error",
                error=_as_optional_text(payload.get("error")) or "adapter_error",
                truncated=truncated,
                raw_hash=raw_hash,
            )

        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    return ContractResponse(
                        status="allowed",
                        text=cast(str, message["content"]),
                        truncated=truncated,
                        raw_hash=raw_hash,
                    )

        return _error_response("invalid_response", truncated, raw_hash)


class UrllibTransport:
    """Standard-library transport with redirects disabled.

    ``HttpConfig.headers`` are applied by constructing this transport with
    ``headers=config.headers``; the :class:`Transport` protocol intentionally
    carries no header argument.
    """

    def __init__(self, headers: Mapping[str, str] | None = None) -> None:
        self._headers = dict(headers or {})

    def send(
        self, url: str, body: bytes, timeout_s: float, max_bytes: int
    ) -> tuple[int, bytes]:
        import urllib.error
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                req: Any,
                fp: Any,
                code: int,
                msg: str,
                headers: Any,
                newurl: str,
            ) -> None:
                return None

        request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        request_headers.update(self._headers)
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers=request_headers,
        )
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(request, timeout=timeout_s) as response:
                return int(response.getcode() or 0), response.read(max_bytes + 1)
        except urllib.error.HTTPError as error:
            return int(error.code), error.read(max_bytes + 1)


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _denied_response() -> ContractResponse:
    return ContractResponse(status="denied", raw_hash=content_hash("denied"))


def _error_response(
    message: str, truncated: bool = False, raw_hash: str = ""
) -> ContractResponse:
    return ContractResponse(
        status="error",
        error=message,
        truncated=truncated,
        raw_hash=raw_hash,
    )


def _as_text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _as_optional_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


__all__ = [
    "CallableContractTarget",
    "ContractRequest",
    "ContractResponse",
    "ContractTarget",
    "FakeTransport",
    "HttpConfig",
    "HttpContractTarget",
    "MockContractTarget",
    "RecordedRequest",
    "Transport",
    "UrllibTransport",
]
