"""Template x profile x fault invariant sweep (G2 breadth across templates).

For every corpus template this sweep checks the two discriminative-validity
invariants that the single-template suite already checks for ``classic``:

1. the full secured campaign produces zero violations;
2. the full vulnerable campaign produces at least one violation;
3. every supported fault, injected alone, is detected by its mapped oracle.

Exit code 0 iff every cell passes; 1 if a secured cell records a violation
(a confirmed security regression); 2 if a fault-detection cell fails (the
measurement did not discriminate). The sweep is deterministic and fast.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from redfence.bench.dataset import TEMPLATES, build_corpus, template_isomorphic
from redfence.bench.oracles import default_oracles
from redfence.bench.runner import SUPPORTED_FAULTS
from redfence.bench.scenario import run_revocation_scenario
from redfence.core.evidence import Outcome
from redfence.targets.config import FAULT_ORACLE, FaultFlags, SecurityProfile


def _score(run):
    return {item.oracle_id: item.outcome for item in (o.score(run) for o in default_oracles())}


def _exit_code(secured_failures: list[str], measurement_failures: list[str]) -> int:
    """ADR-0011: 1 on a secured violation, 2 on a failed discriminative cell."""

    if secured_failures:
        return 1
    if measurement_failures:
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON lines instead of a table")
    args = parser.parse_args(argv)

    secured_failures: list[str] = []
    measurement_failures: list[str] = []
    cells = 0
    for name in TEMPLATES:
        template_isomorphic(build_corpus(template=name))

        secured = run_revocation_scenario(SecurityProfile.SECURED, template=name)
        secured_violations = [
            oid for oid, out in _score(secured).items() if out is Outcome.VIOLATION
        ]
        cells += 1
        if secured_violations:
            secured_failures.append(f"{name}/secured: {secured_violations}")
        if not args.json:
            print(f"template={name:<12} secured_violations={secured_violations or 'none'}")

        vulnerable = run_revocation_scenario(SecurityProfile.VULNERABLE, template=name)
        vulnerable_violations = [
            oid for oid, out in _score(vulnerable).items() if out is Outcome.VIOLATION
        ]
        cells += 1
        if not vulnerable_violations:
            measurement_failures.append(f"{name}/vulnerable: no violations detected")
        if not args.json:
            print(f"template={name:<12} vulnerable_detected={len(vulnerable_violations)} oracle(s)")

        for fault in SUPPORTED_FAULTS:
            run = run_revocation_scenario(
                SecurityProfile.SECURED, faults=FaultFlags(**{fault: True}), template=name
            )
            outcome = _score(run)[FAULT_ORACLE[fault]]
            cells += 1
            if outcome is not Outcome.VIOLATION:
                measurement_failures.append(
                    f"{name}/fault={fault}: {FAULT_ORACLE[fault]}={outcome.value}"
                )
            if args.json:
                print(
                    f'{{"template": "{name}", "fault": "{fault}", '
                    f'"oracle": "{FAULT_ORACLE[fault]}", "outcome": "{outcome.value}"}}'
                )
            else:
                print(
                    f"template={name:<12} fault={fault:<30} "
                    f"{FAULT_ORACLE[fault]}={outcome.value}"
                )

    failures = secured_failures + measurement_failures
    print(
        f"\ntemplates={len(TEMPLATES)} faults={len(SUPPORTED_FAULTS)} cells={cells} "
        f"failures={len(failures)}"
    )
    for failure in failures:
        print(f"FAIL {failure}")
    print(
        "note: templates provide structural diversity (tenancy, tiers, doc counts); "
        "anchor phrasing is intentionally shared so the hash embedder keeps detecting leakage."
    )
    return _exit_code(secured_failures, measurement_failures)


if __name__ == "__main__":
    raise SystemExit(main())
