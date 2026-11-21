"""The facets demo runs every library-level facet on deterministic fixtures."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_PATH = REPO_ROOT / "examples" / "facets_demo.py"

# The seven representative facet oracles promised by the demo contract.
SEVEN_ORACLE_IDS = frozenset(
    {
        "oracle.lineage.derivation",
        "oracle.existence.twin",
        "oracle.existence.permutation",
        "oracle.repair.selective",
        "oracle.capability.attenuation",
        "oracle.mcp.manifest",
        "oracle.retention.durability",
    }
)

# The same output also covers the remaining registry members.
ALL_ORACLE_IDS = SEVEN_ORACLE_IDS | frozenset(
    {
        "oracle.repair.collateral",
        "oracle.capability.expiry",
        "oracle.capability.scope",
        "oracle.mcp.rugpull",
        "oracle.mcp.shadowing",
        "oracle.replica.consistency",
    }
)

OPTIONAL_MODULES = ("yaml", "inspect_ai", "opentelemetry", "hypothesis")


def _load_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("facets_demo", DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _oracle_ids(output: str) -> set[str]:
    ids: set[str] = set()
    for line in output.splitlines():
        assert line.startswith("facet=oracle."), line
        ids.add(line.split(" ", 1)[0].removeprefix("facet="))
    return ids


def test_main_returns_zero(capsys):
    module = _load_demo()

    assert module.main([]) == 0

    output = capsys.readouterr().out
    assert output.strip()


def test_output_contains_every_new_oracle_id(capsys):
    module = _load_demo()

    assert module.main([]) == 0
    output = capsys.readouterr().out
    ids = _oracle_ids(output)

    assert SEVEN_ORACLE_IDS <= ids
    assert ALL_ORACLE_IDS <= ids
    assert len(ids) == len(ALL_ORACLE_IDS)


def test_two_runs_produce_identical_output(capsys):
    module = _load_demo()

    assert module.main([]) == 0
    first = capsys.readouterr().out
    assert module.main([]) == 0
    second = capsys.readouterr().out

    assert first == second


def test_running_the_demo_loads_no_optional_dependency():
    script = (
        "import sys; sys.path.insert(0, 'examples'); import facets_demo; "
        "print('RC', facets_demo.main([])); "
        "print('OPTIONAL', ','.join("
        "name for name in ('yaml', 'inspect_ai', 'opentelemetry', 'hypothesis') "
        "if name in sys.modules))"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert "RC 0" in lines
    optional_lines = [line for line in lines if line.startswith("OPTIONAL ")]
    assert optional_lines == ["OPTIONAL "]
