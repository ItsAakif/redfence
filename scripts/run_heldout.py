"""Run the executable held-out families separately from the development slice."""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Sequence
from pathlib import Path

from redfence.bench.heldout import HELDOUT_FAMILIES, run_heldout_scenario
from redfence.targets.config import SecurityProfile


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="reports/heldout")
    args = parser.parse_args(argv)
    out_dir = Path(args.out)
    secured_regression = False
    measurement_failure = False
    for family in HELDOUT_FAMILIES:
        try:
            secured = run_heldout_scenario(family, SecurityProfile.SECURED, out_dir=out_dir)
            vulnerable = run_heldout_scenario(
                family, SecurityProfile.VULNERABLE, out_dir=out_dir
            )
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"family={family:<28} error={exc}")
            measurement_failure = True
            continue
        secured_violations = [
            e.oracle_id for e in secured.evidence if e.outcome.value == "violation"
        ]
        vulnerable_violations = [
            e.oracle_id for e in vulnerable.evidence if e.outcome.value == "violation"
        ]
        if secured_violations:
            secured_regression = True
        ok = secured.exit_code == 0 and vulnerable.exit_code == 1
        if not ok:
            measurement_failure = True
        print(
            f"family={family:<28} secured_exit={secured.exit_code} "
            f"vulnerable_exit={vulnerable.exit_code} ok={ok}"
        )
        print(f"  secured_violations={secured_violations}")
        print(f"  vulnerable_violations={vulnerable_violations}")
    if secured_regression:
        return 1
    if measurement_failure:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
