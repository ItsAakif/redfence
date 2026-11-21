"""Documentation integrity checks.

These tests are deliberately stdlib-only: no PyYAML, no markdown parser, no
network. They guard the release docs against the two failure modes that matter
most here: a relative link that points at a file that does not exist, and a
version that drifts between ``pyproject.toml``, ``version.py`` and ``CITATION.cff``.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").rglob("*.md"))]
CLAIMS = REPO_ROOT / "docs" / "claims.md"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_VERSION = re.compile(r'__version__ = "([^"]+)"')
_SEPARATOR = re.compile(r"^:?-{3,}:?$")
_EXTERNAL_PREFIXES = ("#", "http://", "https://", "mailto:")


def _relative_target(raw: str) -> str | None:
    target = raw.strip()
    if not target or target.startswith(_EXTERNAL_PREFIXES):
        return None
    target = target.split("#", 1)[0]
    return target or None


@pytest.mark.parametrize(
    "path", MARKDOWN, ids=lambda item: item.relative_to(REPO_ROOT).as_posix()
)
def test_relative_links_resolve(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    missing: list[str] = []
    for raw in _LINK.findall(text):
        target = _relative_target(raw)
        if target is None:
            continue
        base = REPO_ROOT if target.startswith("/") else path.parent
        candidate = base / target.lstrip("/")
        if not candidate.exists():
            missing.append(target)
    assert not missing, f"{path.relative_to(REPO_ROOT)}: missing {missing}"


def _claim_rows() -> list[dict[str, str]]:
    lines = CLAIMS.read_text(encoding="utf-8").splitlines()
    table = [line for line in lines if line.strip().startswith("|")]
    assert table, "claim register table is missing"
    header = [cell.strip() for cell in table[0].strip().strip("|").split("|")]
    rows: list[dict[str, str]] = []
    for line in table[1:]:
        values = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(_SEPARATOR.match(value) for value in values):
            continue
        rows.append(dict(zip(header, values, strict=True)))
    return rows


def test_claim_register_paths_exist() -> None:
    rows = _claim_rows()
    assert rows
    for row in rows:
        evidence = row["evidence"].strip("`").strip()
        if evidence == "-":
            continue
        assert (REPO_ROOT / evidence).exists(), f"{row['claim']}: {evidence}"


def test_version_is_single_source() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    match = _VERSION.search(
        (REPO_ROOT / "src" / "redfence" / "version.py").read_text(encoding="utf-8")
    )
    assert match is not None, "version.py has no __version__"
    assert match.group(1) == version
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert f'version: "{version}"' in citation


def test_ci_workflow_is_textually_well_formed() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "\t" not in text, "CI YAML must not contain tabs"
    lines = text.splitlines()
    assert any(line.strip() == "jobs:" for line in lines), "CI YAML has no jobs"

    in_block = False
    block_indent = 0
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if in_block:
            if indent > block_indent:
                continue
            in_block = False
        if stripped.endswith(("|", ">")):
            in_block = True
            block_indent = indent
            continue
        assert indent % 2 == 0, f"line {number}: odd indentation"
        assert stripped.startswith("- ") or ":" in stripped, (
            f"line {number}: not a key, list item or block scalar"
        )

    for command in (
        'python -m pytest -o addopts="" -q',
        "ruff check . --no-cache",
        "mypy src",
        "python -m pip check",
        'python -c "import redfence"',
        "contract validate examples/contracts/mock.json",
        "contract test examples/contracts/mock.json --adapter mock",
        "scripts/run_mutation.py",
    ):
        assert command in text, f"CI is missing: {command}"
