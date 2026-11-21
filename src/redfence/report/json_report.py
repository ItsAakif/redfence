"""Machine-readable JSON report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from redfence.bench.runner import CampaignResult


def write_json_report(result: CampaignResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    payload["summary"] = {
        "profile": result.profile,
        "exit_code": result.exit_code,
        "violations": [item.oracle_id for item in result.evidence if item.is_violation],
        "unsupported": [
            item.oracle_id for item in result.evidence if item.outcome.value == "unsupported"
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
