"""Claim register: statuses are bounded and every evidence path resolves."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLAIMS_PATH = REPO_ROOT / "docs" / "claims.md"
VALID_STATUSES = frozenset({"verified", "partial", "not verified"})
_SEPARATOR = re.compile(r"^:?-{3,}:?$")


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _rows() -> list[dict[str, str]]:
    lines = CLAIMS_PATH.read_text(encoding="utf-8").splitlines()
    table = [line for line in lines if line.strip().startswith("|")]
    assert table, "claim register table is missing"
    header = _cells(table[0])
    rows: list[dict[str, str]] = []
    for line in table[1:]:
        values = _cells(line)
        if all(_SEPARATOR.match(value) for value in values):
            continue
        rows.append(dict(zip(header, values, strict=True)))
    return rows


def _path(value: str) -> str:
    return value.strip().strip("`").strip()


def test_claim_table_has_required_columns() -> None:
    rows = _rows()
    assert rows
    assert list(rows[0]) == ["claim", "evidence", "status", "command"]


def test_claim_table_has_at_least_four_rows() -> None:
    assert len(_rows()) >= 4


def test_claim_statuses_are_bounded() -> None:
    for row in _rows():
        assert row["status"] in VALID_STATUSES, row["claim"]


def test_referenced_evidence_paths_exist() -> None:
    for row in _rows():
        evidence = _path(row["evidence"])
        if evidence == "-":
            continue
        assert (REPO_ROOT / evidence).exists(), f"{row['claim']}: {evidence}"


def test_dash_is_only_allowed_for_not_verified_rows() -> None:
    for row in _rows():
        evidence = _path(row["evidence"])
        if evidence == "-":
            assert row["status"] == "not verified", row["claim"]
        if row["status"] == "not verified":
            assert evidence == "-" or (REPO_ROOT / evidence).exists(), row["claim"]


def test_required_claims_are_present() -> None:
    text = CLAIMS_PATH.read_text(encoding="utf-8")
    for claim in (
        "259→507 tests pass",
        "reports are byte-identical",
        "contract validate returns 3 on invalid input",
        "live HTTP adapters work",
        "Docker/G6/G9 re-run",
    ):
        assert claim in text
