"""FastAPI surface (optional). Requires the ``api`` extra.

Minimal by design: the milestone is the deterministic engine, not a service.
"""

from __future__ import annotations

from typing import Any

from redfence.version import __version__


def create_app() -> Any:  # pragma: no cover - requires optional dependency
    from fastapi import FastAPI, HTTPException

    from redfence.bench.runner import run_campaign
    from redfence.targets.config import SecurityProfile

    app = FastAPI(title="RedFence", version=__version__)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/campaigns/run")
    def run(profile: str = "secured") -> dict[str, object]:
        try:
            parsed = SecurityProfile(profile)
        except ValueError as exc:  # pragma: no cover
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        result = run_campaign(parsed)
        return {
            "scenario_id": result.scenario_id,
            "profile": result.profile,
            "exit_code": result.exit_code,
            "manifest": result.manifest,
            "evidence": [item.model_dump(mode="json") for item in result.evidence],
            "metrics": result.metrics.model_dump(mode="json"),
        }

    return app
