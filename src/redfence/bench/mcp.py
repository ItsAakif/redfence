"""Deterministic MCP tool-manifest client and oracles.

The client speaks JSON-RPC 2.0 over a child process's stdio. It never opens a
socket and never raises on a transport failure: a failed fetch returns an empty
manifest carrying a short error code. Oracles consume an
:class:`McpObservation` and follow ADR-0008 through the shared ``_verdict``
helper, so a manifest with no tools is ``UNSUPPORTED`` rather than a pass.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from redfence.bench.oracles import _no_observation, _verdict
from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import json_digest, stable_id

_FACET = "mcp"
_PROTOCOL_VERSION = "2025-06-18"
_INJECTION_MARKERS = ("ignore previous instructions", "system:", "<!--")
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


class McpTool(BaseModel):
    """One tool definition advertised by an MCP server."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    input_schema: dict[str, object] = Field(default_factory=dict)
    digest: str = ""


class McpManifest(BaseModel):
    """The tool manifest observed from one MCP server in one session."""

    model_config = ConfigDict(frozen=True)

    server_id: str
    tools: list[McpTool]
    previous_digest: str | None = None
    declared_update: bool = False
    pinned: bool = True
    error: str = ""

    @property
    def digest(self) -> str:
        """Digest of the currently advertised tool definitions."""

        return manifest_digest(self.tools)


class McpObservation(BaseModel):
    """Everything the MCP oracles need: manifests plus tool resolution."""

    manifests: list[McpManifest]
    resolved: dict[str, str] = Field(default_factory=dict)
    pinned_server: str = ""


class McpOracle(Protocol):
    """The interface every MCP oracle implements."""

    oracle_id: str
    facet: str

    def score(self, observation: McpObservation) -> Evidence: ...


def tool_digest(
    name: str, description: str, input_schema: dict[str, object]
) -> str:
    """Canonical digest of one tool definition, independent of declaration order."""

    return json_digest(
        {
            "name": name,
            "description": description,
            "input_schema": input_schema,
        }
    )


def manifest_digest(tools: list[McpTool]) -> str:
    """Canonical digest of a sorted tool list."""

    ordered = sorted(tools, key=lambda tool: tool.name)
    return json_digest(
        [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
                "digest": tool.digest,
            }
            for tool in ordered
        ]
    )


def build_observation(
    manifests: list[McpManifest], *, pinned_server: str = ""
) -> McpObservation:
    """Merge manifests in priority order and record which server owns each tool.

    The first manifest that declares a tool name wins, so callers express the
    client's resolution order by ordering the list. ``pinned_server`` defaults
    to the first manifest's server id.
    """

    resolved: dict[str, str] = {}
    for manifest in manifests:
        for tool in manifest.tools:
            resolved.setdefault(tool.name, manifest.server_id)
    if not pinned_server and manifests:
        pinned_server = manifests[0].server_id
    return McpObservation(
        manifests=list(manifests),
        resolved=dict(sorted(resolved.items())),
        pinned_server=pinned_server,
    )


def _request_payload() -> str:
    """Three JSON-RPC requests: initialize and two ``tools/list`` calls.

    The second list lets a manifest carry ``previous_digest`` even when the
    caller only invokes ``fetch_manifest`` once. Stateless servers return the
    same definitions twice; a rug-pulling server changes them.
    """

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "redfence", "version": "0.3.0"},
            },
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
    ]
    return "".join(
        json.dumps(request, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        + "\n"
        for request in requests
    )


def _error_manifest(server_id: str, error: str) -> McpManifest:
    return McpManifest(server_id=server_id, tools=[], error=error)


def _parse_lines(stdout: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        decoded = json.loads(stripped)
        if not isinstance(decoded, dict):
            raise ValueError("JSON-RPC message is not an object")
        messages.append(decoded)
    return messages


def _response_by_id(
    messages: list[dict[str, Any]], request_id: int
) -> dict[str, Any] | None:
    for message in messages:
        if message.get("id") == request_id:
            return message
    return None


def _server_id(response: dict[str, Any]) -> str:
    result = response.get("result")
    if not isinstance(result, dict):
        return ""
    server_info = result.get("serverInfo")
    if not isinstance(server_info, dict):
        return ""
    name = server_info.get("name")
    return name if isinstance(name, str) else ""


def _parse_tools(response: dict[str, Any]) -> list[McpTool]:
    if "error" in response:
        raise ValueError("JSON-RPC error response")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ValueError("tools/list result is not an object")
    raw_tools = result.get("tools")
    if not isinstance(raw_tools, list):
        raise ValueError("tools/list result has no tools list")

    tools: list[McpTool] = []
    for raw in raw_tools:
        if not isinstance(raw, dict):
            raise ValueError("tool definition is not an object")
        name = raw.get("name")
        description = raw.get("description", "")
        input_schema = raw.get("inputSchema", {})
        if not isinstance(name, str) or not name:
            raise ValueError("tool name is missing")
        if not isinstance(description, str):
            raise ValueError("tool description is not a string")
        if not isinstance(input_schema, dict):
            raise ValueError("tool inputSchema is not an object")
        declared = raw.get("digest")
        digest = (
            declared
            if isinstance(declared, str) and declared
            else tool_digest(name, description, cast(dict[str, object], input_schema))
        )
        tools.append(
            McpTool(
                name=name,
                description=description,
                input_schema=cast(dict[str, object], input_schema),
                digest=digest,
            )
        )
    tools.sort(key=lambda tool: tool.name)
    return tools


def fetch_manifest(server_cmd: list[str], *, timeout_s: float = 5.0) -> McpManifest:
    """Fetch a deterministic tool manifest from ``server_cmd`` over stdio.

    Timeouts, EOF, spawn failures, non-zero exits and malformed JSON all return
    an empty manifest with ``error`` set; this function never raises.
    """

    fallback_id = stable_id("mcp", *server_cmd)
    try:
        completed = subprocess.run(
            server_cmd,
            input=_request_payload(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _error_manifest(fallback_id, "timeout")
    except (OSError, UnicodeError) as exc:
        return _error_manifest(fallback_id, f"spawn-error:{type(exc).__name__}")

    if completed.returncode != 0:
        return _error_manifest(fallback_id, f"exit:{completed.returncode}")

    try:
        messages = _parse_lines(completed.stdout)
    except (json.JSONDecodeError, ValueError):
        return _error_manifest(fallback_id, "malformed-json")

    if not messages:
        return _error_manifest(fallback_id, "eof")

    initialize = _response_by_id(messages, 1)
    first = _response_by_id(messages, 2)
    second = _response_by_id(messages, 3)
    if initialize is None or first is None:
        return _error_manifest(fallback_id, "incomplete-response")
    if "error" in initialize:
        return _error_manifest(fallback_id, "initialize-error")

    server_id = _server_id(initialize) or fallback_id
    try:
        first_tools = _parse_tools(first)
    except ValueError:
        return _error_manifest(server_id, "malformed-tools")

    # A server that answers only one tools/list still yields a manifest; the
    # second list is only required to establish a previous digest for rug-pull
    # detection.
    if second is None:
        return McpManifest(server_id=server_id, tools=first_tools)

    try:
        second_tools = _parse_tools(second)
    except ValueError:
        return _error_manifest(server_id, "malformed-tools")

    return McpManifest(
        server_id=server_id,
        tools=second_tools,
        previous_digest=manifest_digest(first_tools),
    )


def _has_injection_marker(text: str) -> bool:
    lowered = text.lower()
    if any(marker in lowered for marker in _INJECTION_MARKERS):
        return True
    return any(char in text for char in _BIDI_CONTROLS)


def _evidence(
    observation: McpObservation,
    oracle_id: str,
    expected: str,
    observed: str,
    outcome: Outcome,
    *,
    method: str,
    events: list[str] | None = None,
) -> Evidence:
    server_ids = sorted(manifest.server_id for manifest in observation.manifests)
    scenario_id = stable_id("mcp", *server_ids) if server_ids else "mcp"
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


class ManifestOracle:
    """Tool descriptions must be clean and match their declared digests."""

    oracle_id = "oracle.mcp.manifest"
    facet = _FACET

    def score(self, observation: McpObservation) -> Evidence:
        units = [
            tool for manifest in observation.manifests for tool in manifest.tools
        ]
        violations: list[str] = []
        for tool in units:
            if _has_injection_marker(tool.description):
                violations.append(f"{tool.name}:injection-marker")
            expected_digest = tool_digest(
                tool.name, tool.description, tool.input_schema
            )
            # An empty digest means the server did not declare one; the client
            # fills it in from the definition, so there is nothing to compare.
            if tool.digest and tool.digest != expected_digest:
                violations.append(f"{tool.name}:digest-mismatch")
        outcome = _verdict(len(units), violations)
        observed = (
            f"{len(violations)} violation(s) of {len(units)} tool definition(s)"
            if units
            else _no_observation("no tool definition")
        )
        return _evidence(
            observation,
            self.oracle_id,
            "every tool description is free of injection markers and matches "
            "its declared digest",
            observed,
            outcome,
            method="scan descriptions for prompt-injection markers and recompute "
            "each tool digest",
            events=sorted(set(violations)),
        )


class RugPullOracle:
    """A server must not change a tool definition without declaring the update."""

    oracle_id = "oracle.mcp.rugpull"
    facet = _FACET

    def score(self, observation: McpObservation) -> Evidence:
        units = [
            manifest
            for manifest in observation.manifests
            if manifest.previous_digest is not None
        ]
        violations = [
            f"{manifest.server_id}:undeclared-change"
            for manifest in units
            if manifest.digest != manifest.previous_digest
            and not manifest.declared_update
        ]
        outcome = _verdict(len(units), violations)
        observed = (
            f"{len(violations)} undeclared change(s) across {len(units)} manifest(s)"
            if units
            else _no_observation("no manifest with a previous digest")
        )
        return _evidence(
            observation,
            self.oracle_id,
            "a tool definition does not change between lists without a declared update",
            observed,
            outcome,
            method="compare the current manifest digest with the digest of the "
            "previous tools/list response",
            events=violations,
        )


class ShadowingOracle:
    """A tool name must resolve to the pinned server, not a shadowing server."""

    oracle_id = "oracle.mcp.shadowing"
    facet = _FACET

    def score(self, observation: McpObservation) -> Evidence:
        owners: dict[str, set[str]] = {}
        for manifest in observation.manifests:
            for tool in manifest.tools:
                owners.setdefault(tool.name, set()).add(manifest.server_id)

        units = sorted(observation.resolved.items())
        # A distinct tool legitimately owned by a secondary server is not
        # shadowing; only a name declared by more than one server can shadow.
        violations = [
            f"{tool}:{server}"
            for tool, server in units
            if server != observation.pinned_server
            and len(owners.get(tool, ())) > 1
        ]
        outcome = _verdict(len(units), violations)
        observed = (
            f"{len(violations)} shadowed tool(s) of {len(units)} resolved"
            if units
            else _no_observation("no resolved tool")
        )
        return _evidence(
            observation,
            self.oracle_id,
            "every tool name resolves to the pinned server",
            observed,
            outcome,
            method="compare each resolved tool owner with the pinned server id",
            events=violations,
        )


def mcp_oracles() -> list[McpOracle]:
    """Return the MCP oracle registry in stable order."""

    return [
        ManifestOracle(),
        RugPullOracle(),
        ShadowingOracle(),
    ]


__all__ = [
    "ManifestOracle",
    "McpManifest",
    "McpObservation",
    "McpOracle",
    "McpTool",
    "RugPullOracle",
    "ShadowingOracle",
    "build_observation",
    "fetch_manifest",
    "manifest_digest",
    "mcp_oracles",
    "tool_digest",
]
