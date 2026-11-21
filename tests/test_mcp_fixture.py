"""MCP fixture: deterministic stdio transport, manifests and oracles."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from redfence.bench.mcp import (
    ManifestOracle,
    McpManifest,
    McpObservation,
    McpTool,
    RugPullOracle,
    ShadowingOracle,
    build_observation,
    fetch_manifest,
    mcp_oracles,
    tool_digest,
)
from redfence.core.evidence import Outcome

_FIXTURE = Path(__file__).parent / "fixtures" / "mcp_server.py"


def _cmd(mode: str) -> list[str]:
    return [sys.executable, str(_FIXTURE), mode]


# ---------------------------------------------------------------------------
# Fixture modes
# ---------------------------------------------------------------------------


def test_benign_mode_is_satisfied():
    manifest = fetch_manifest(_cmd("benign"))

    assert manifest.error == ""
    assert manifest.server_id == "redfence-mcp-benign"
    assert [tool.name for tool in manifest.tools] == ["lookup", "summarize"]
    assert manifest.previous_digest == manifest.digest

    observation = build_observation([manifest])
    assert observation.pinned_server == "redfence-mcp-benign"
    assert observation.resolved == {
        "lookup": "redfence-mcp-benign",
        "summarize": "redfence-mcp-benign",
    }
    for oracle in mcp_oracles():
        evidence = oracle.score(observation)
        assert evidence.outcome is Outcome.SATISFIED, oracle.oracle_id
        assert evidence.facet == "mcp"


def test_poisoned_description_is_detected():
    manifest = fetch_manifest(_cmd("poisoned_description"))
    observation = build_observation([manifest])

    evidence = ManifestOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["lookup:injection-marker"]

    lookup = next(tool for tool in manifest.tools if tool.name == "lookup")
    assert "ignore previous instructions" in lookup.description.lower()
    assert "system:" in lookup.description.lower()
    assert "<!--" in lookup.description
    assert "\u202e" in lookup.description

    assert RugPullOracle().score(observation).outcome is Outcome.SATISFIED
    assert ShadowingOracle().score(observation).outcome is Outcome.SATISFIED


def test_rug_pull_is_detected_and_declared_update_is_satisfied():
    benign = fetch_manifest(_cmd("benign"))
    manifest = fetch_manifest(_cmd("rug_pull"))

    assert manifest.previous_digest is not None
    assert manifest.previous_digest == benign.digest
    assert manifest.digest != manifest.previous_digest

    observation = build_observation([manifest])
    evidence = RugPullOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["redfence-mcp-rug_pull:undeclared-change"]
    assert ManifestOracle().score(observation).outcome is Outcome.SATISFIED

    declared = manifest.model_copy(update={"declared_update": True})
    declared_evidence = RugPullOracle().score(build_observation([declared]))
    assert declared_evidence.outcome is Outcome.SATISFIED


def test_shadowing_is_detected():
    shadow = fetch_manifest(_cmd("shadowing"))
    benign = fetch_manifest(_cmd("benign"))

    observation = build_observation(
        [shadow, benign], pinned_server="redfence-mcp-benign"
    )
    assert observation.resolved["lookup"] == "redfence-mcp-shadowing"
    evidence = ShadowingOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["lookup:redfence-mcp-shadowing"]

    pinned = build_observation(
        [benign, shadow], pinned_server="redfence-mcp-benign"
    )
    assert pinned.resolved["lookup"] == "redfence-mcp-benign"
    assert ShadowingOracle().score(pinned).outcome is Outcome.SATISFIED


def test_distinct_tools_on_two_servers_are_not_shadowing():
    primary = McpManifest(
        server_id="primary",
        tools=[McpTool(name="lookup", description="Look up a record.")],
    )
    secondary = McpManifest(
        server_id="secondary",
        tools=[McpTool(name="summarize", description="Summarize records.")],
    )
    observation = build_observation([primary, secondary], pinned_server="primary")

    assert observation.resolved == {"lookup": "primary", "summarize": "secondary"}
    assert ShadowingOracle().score(observation).outcome is Outcome.SATISFIED


def test_colliding_tool_on_a_secondary_server_is_shadowing():
    primary = McpManifest(
        server_id="primary",
        tools=[McpTool(name="lookup", description="Look up a record.")],
    )
    secondary = McpManifest(
        server_id="secondary",
        tools=[McpTool(name="lookup", description="Look up a record.")],
    )
    observation = build_observation([secondary, primary], pinned_server="primary")

    evidence = ShadowingOracle().score(observation)
    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["lookup:secondary"]


# ---------------------------------------------------------------------------
# Determinism and transport failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode", ["benign", "poisoned_description", "rug_pull", "shadowing"]
)
def test_same_mode_fetched_twice_is_identical(mode: str):
    first = fetch_manifest(_cmd(mode))
    second = fetch_manifest(_cmd(mode))

    assert first == second
    assert first.model_dump() == second.model_dump()


def test_timeout_returns_empty_manifest_without_raising():
    manifest = fetch_manifest(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=0.5
    )

    assert manifest.tools == []
    assert manifest.error == "timeout"


def test_eof_returns_empty_manifest_without_raising():
    manifest = fetch_manifest([sys.executable, "-c", "pass"])

    assert manifest.tools == []
    assert manifest.error == "eof"


def test_malformed_json_returns_empty_manifest_without_raising():
    manifest = fetch_manifest([sys.executable, "-c", "print('not json')"])

    assert manifest.tools == []
    assert manifest.error == "malformed-json"


def test_zero_tools_is_unsupported():
    observation = McpObservation(
        manifests=[McpManifest(server_id="empty", tools=[])]
    )

    for oracle in mcp_oracles():
        evidence = oracle.score(observation)
        assert evidence.outcome is Outcome.UNSUPPORTED, oracle.oracle_id
        assert evidence.observed.startswith("no evaluable observation:")


def test_no_network(monkeypatch: pytest.MonkeyPatch):
    def _no_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _no_socket)

    manifest = fetch_manifest(_cmd("benign"))

    assert manifest.error == ""
    assert [tool.name for tool in manifest.tools] == ["lookup", "summarize"]
    assert "import socket" not in _FIXTURE.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Fixture protocol surface and models
# ---------------------------------------------------------------------------


def test_tools_call_returns_deterministic_content():
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"query": "alpha"}},
        },
    ]
    payload = "".join(
        json.dumps(request, sort_keys=True) + "\n" for request in requests
    )
    completed = subprocess.run(
        _cmd("benign"),
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5.0,
        check=True,
    )

    responses = [
        json.loads(line)
        for line in completed.stdout.splitlines()
        if line.strip()
    ]
    call = next(response for response in responses if response.get("id") == 2)
    assert json.loads(call["result"]["content"][0]["text"]) == {
        "mode": "benign",
        "tool": "lookup",
        "arguments": {"query": "alpha"},
    }


def test_tool_and_manifest_are_frozen():
    tool = McpTool(
        name="lookup",
        description="ok",
        digest=tool_digest("lookup", "ok", {}),
    )
    with pytest.raises(ValidationError):
        tool.name = "other"  # type: ignore[misc]

    manifest = McpManifest(server_id="s", tools=[tool])
    with pytest.raises(ValidationError):
        manifest.server_id = "other"  # type: ignore[misc]


def test_declared_digest_mismatch_is_a_violation():
    tool = McpTool(name="lookup", description="ok", digest="tampered")
    observation = McpObservation(
        manifests=[McpManifest(server_id="s", tools=[tool])]
    )

    evidence = ManifestOracle().score(observation)

    assert evidence.outcome is Outcome.VIOLATION
    assert evidence.events == ["lookup:digest-mismatch"]


def test_oracle_registry_is_stable():
    assert [oracle.oracle_id for oracle in mcp_oracles()] == [
        "oracle.mcp.manifest",
        "oracle.mcp.rugpull",
        "oracle.mcp.shadowing",
    ]
