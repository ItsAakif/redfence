"""Run the permission-revocation vertical slice and emit reports.

Usage:  python scripts/run_vertical_slice.py [--out reports]
Exit code follows the RedFence semantics (0 pass, 1 violation, 2 inconclusive).
"""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Sequence
from pathlib import Path

from redfence.bench.runner import run_demo


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="reports")
    args = parser.parse_args(argv)

    try:
        validity, secured, vulnerable = run_demo(Path(args.out))
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"error={exc}")
        return 2
    print("G2 discriminative validity:", "PASS" if validity.overall else "FAIL")
    for check in validity.checks:
        print(
            f"  {check['fault']:<34} {check['oracle_id']:<26} "
            f"secured={check['secured']:<11} vulnerable={check['vulnerable']}"
        )
    print("\nSecured evidence:")
    for item in secured.evidence:
        print(f"  [{item.outcome.value:>11}] {item.oracle_id}")
    print("Vulnerable evidence:")
    for item in vulnerable.evidence:
        print(f"  [{item.outcome.value:>11}] {item.oracle_id}: {item.observed}")
    if secured.has_violation:
        return 1
    if not validity.overall or secured.has_inconclusive or vulnerable.has_inconclusive:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
