"""Campaign runner, run manifest, report emission and discriminative validity."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from redfence.bench.isolated import run_oracles_isolated
from redfence.bench.metrics import MetricsReport, compute_metrics
from redfence.bench.oracles import default_oracles
from redfence.bench.scenario import ScenarioRun, run_revocation_scenario
from redfence.core.evidence import Evidence, Outcome
from redfence.core.ids import json_digest
from redfence.report import write_html_report, write_json_report
from redfence.targets.config import FAULT_ORACLE, SecurityProfile
from redfence.version import __version__

PACKAGE_VERSION = __version__

# Faults whose mapped oracle is implemented at this milestone.
SUPPORTED_FAULTS: tuple[str, ...] = tuple(
    fault for fault, oracle in FAULT_ORACLE.items() if not oracle.startswith("oracle.unsupported")
)


@dataclass
class CampaignResult:
    scenario_id: str
    profile: str
    run: ScenarioRun
    evidence: list[Evidence]
    metrics: MetricsReport
    manifest: dict[str, object]
    json_path: Path | None = None
    html_path: Path | None = None
    oracle_pid: int | None = None

    @property
    def has_violation(self) -> bool:
        return any(item.outcome is Outcome.VIOLATION for item in self.evidence)

    @property
    def has_inconclusive(self) -> bool:
        return any(
            item.outcome in (Outcome.INCONCLUSIVE, Outcome.UNSUPPORTED) for item in self.evidence
        )

    @property
    def exit_code(self) -> int:
        """0 pass, 1 confirmed security violation, 2 inconclusive/unsupported."""

        if self.has_violation:
            return 1
        if self.has_inconclusive:
            return 2
        return 0

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest": self.manifest,
            "evidence": [item.model_dump(mode="json") for item in self.evidence],
            "metrics": self.metrics.model_dump(mode="json"),
        }


def build_manifest(run: ScenarioRun, evidence: list[Evidence]) -> dict[str, object]:
    faults = sorted(run.target.faults.enabled())
    corpus_manifest = run.corpus.manifest()
    return {
        "manifest_schema": 2,
        "package_version": __version__,
        "dataset_version": run.corpus.dataset_version,
        "seed": run.corpus.seed,
        "scenario_id": run.scenario_id,
        "scenario_kind": run.scenario_kind,
        "profile": run.profile,
        "template": run.corpus.template,
        "faults": faults,
        "faults_sha256": json_digest(faults),
        "corpus_manifest": corpus_manifest,
        "corpus_manifest_sha256": json_digest(corpus_manifest),
        "steps": run.steps,
        "oracles": sorted({item.oracle_id for item in evidence}),
        "evidence_outcomes": {item.oracle_id: item.outcome.value for item in evidence},
        "canary_markers": corpus_manifest["canary_markers"],
        "oracle_isolation": "in_process",
    }


def run_campaign(
    profile: SecurityProfile,
    *,
    out_dir: Path | None = None,
    isolated_oracles: bool = False,
    seed: int | None = None,
    template: str = "classic",
) -> CampaignResult:
    run = run_revocation_scenario(profile, seed=seed, template=template)
    oracle_pid: int | None = None
    if isolated_oracles:
        isolated = run_oracles_isolated(run)
        evidence = isolated.evidence
        oracle_pid = isolated.oracle_pid
    else:
        evidence = [oracle.score(run) for oracle in default_oracles()]
    metrics = compute_metrics(run, evidence)
    manifest = build_manifest(run, evidence)
    if isolated_oracles:
        manifest["oracle_isolation"] = "subprocess"
    result = CampaignResult(
        scenario_id=run.scenario_id,
        profile=profile.value,
        run=run,
        evidence=evidence,
        metrics=metrics,
        manifest=manifest,
        oracle_pid=oracle_pid,
    )
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        result.json_path = write_json_report(result, out_dir / f"{run.scenario_id}.json")
        result.html_path = write_html_report(result, out_dir / f"{run.scenario_id}.html")
    return result


@dataclass
class DiscriminativeValidity:
    overall: bool
    checks: list[dict[str, object]] = field(default_factory=list)
    secured_violations: list[str] = field(default_factory=list)


def _outcome_for(result: CampaignResult, oracle_id: str) -> str:
    for item in result.evidence:
        if item.oracle_id == oracle_id:
            return item.outcome.value
    return "missing"


def discriminative_validity(
    secured: CampaignResult, vulnerable: CampaignResult
) -> DiscriminativeValidity:
    """The central G2 test: secured passes, vulnerable fails the mapped oracle.

    A check is only ``ok`` when the secured campaign neither violates nor fails
    to evaluate the facet (``INCONCLUSIVE``/``UNSUPPORTED``) and the vulnerable
    campaign records the expected ``VIOLATION``. An unevaluable secured side is
    a failed measurement, not a pass.
    """

    # ``_outcome_for`` yields the sentinel ``"missing"`` when a campaign carries
    # no evidence for an oracle at all (e.g. it silently skipped the scorer).
    # An absent measurement is not a pass, so ``"missing"`` is unevaluable too;
    # otherwise a secured side that omitted an oracle could make G2 vacuously ok.
    unevaluable = (
        Outcome.INCONCLUSIVE.value,
        Outcome.UNSUPPORTED.value,
        "missing",
    )
    checks: list[dict[str, object]] = []
    for fault, oracle_id in FAULT_ORACLE.items():
        if fault not in SUPPORTED_FAULTS:
            continue
        secured_outcome = _outcome_for(secured, oracle_id)
        vulnerable_outcome = _outcome_for(vulnerable, oracle_id)
        ok = (
            secured_outcome != Outcome.VIOLATION.value
            and secured_outcome not in unevaluable
            and vulnerable_outcome == Outcome.VIOLATION.value
            and vulnerable_outcome not in unevaluable
        )
        checks.append(
            {
                "fault": fault,
                "oracle_id": oracle_id,
                "secured": secured_outcome,
                "vulnerable": vulnerable_outcome,
                "ok": ok,
            }
        )
    secured_violations = [
        item.oracle_id for item in secured.evidence if item.outcome is Outcome.VIOLATION
    ]
    overall = all(bool(check["ok"]) for check in checks) and not secured_violations
    return DiscriminativeValidity(
        overall=overall, checks=checks, secured_violations=secured_violations
    )


def run_demo(
    out_dir: Path | None = None, *, isolated_oracles: bool = False
) -> tuple[DiscriminativeValidity, CampaignResult, CampaignResult]:
    secured = run_campaign(
        SecurityProfile.SECURED, out_dir=out_dir, isolated_oracles=isolated_oracles
    )
    vulnerable = run_campaign(
        SecurityProfile.VULNERABLE, out_dir=out_dir, isolated_oracles=isolated_oracles
    )
    validity = discriminative_validity(secured, vulnerable)
    return validity, secured, vulnerable
