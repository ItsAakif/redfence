"""Mutation self-test: known-good must be killed, known-bad must survive.

Exit 0 only when every registry expectation holds, 2 otherwise. There is no
mutation-score threshold in CI for 0.3.0 (ADR-0016).
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from redfence.bench.mutation import known_bad, known_good, run_registry


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic mutation self-test.")
    parser.parse_args(argv)

    registry = known_good() + known_bad()
    report = run_registry(registry)
    for result in report.results:
        print(
            f"mutant={result.mutant_id:<28} "
            f"expected={result.expected_outcome:<10} "
            f"observed={result.observed_outcome:<10} "
            f"as_expected={result.as_expected}"
        )
    print(
        f"matched={report.matched} unexpected={report.unexpected} "
        f"killed={report.killed} survived={report.survived} score={report.score:.2f}"
    )

    return 0 if all(result.as_expected for result in report.results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
