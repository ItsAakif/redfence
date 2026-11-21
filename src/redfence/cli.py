"""Command-line entry point.

Exit semantics (mandate section 13):
  0  all applicable required checks pass
  1  a confirmed security violation / regression
  2  inconclusive, unsupported, or infrastructure failure
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from redfence.bench.contract_oracles import contract_oracles
from redfence.bench.contract_runner import run_contract
from redfence.bench.runner import run_campaign, run_demo
from redfence.contracts.loader import load_contract
from redfence.contracts.schema import ContractError, ContractV1
from redfence.contracts.target import (
    ContractTarget,
    HttpConfig,
    HttpContractTarget,
    MockContractTarget,
    UrllibTransport,
)
from redfence.report.contract_report import contract_exit_code, write_contract_json
from redfence.report.junit import write_junit
from redfence.report.sarif import write_sarif
from redfence.targets.config import SecurityProfile


def _cmd_run(args: argparse.Namespace) -> int:
    profile = SecurityProfile(args.profile)
    out_dir = Path(args.out) if args.out else None
    try:
        result = run_campaign(profile, out_dir=out_dir, isolated_oracles=args.isolated_oracles)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"error={exc}")
        return 2
    print(f"profile={result.profile} scenario={result.scenario_id} exit={result.exit_code}")
    for item in result.evidence:
        print(f"  [{item.outcome.value:>11}] {item.oracle_id}: {item.observed}")
    if result.json_path:
        print(f"json={result.json_path}")
    if result.html_path:
        print(f"html={result.html_path}")
    return result.exit_code


def _cmd_demo(args: argparse.Namespace) -> int:
    out_dir = Path(args.out) if args.out else None
    try:
        validity, secured, vulnerable = run_demo(
            out_dir=out_dir, isolated_oracles=args.isolated_oracles
        )
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"error={exc}")
        return 2
    print("Discriminative validity (G2):", "PASS" if validity.overall else "FAIL")
    for check in validity.checks:
        status = "ok " if check["ok"] else "BAD"
        print(
            f"  [{status}] {check['fault']:<34} {check['oracle_id']:<26} "
            f"secured={check['secured']:<11} vulnerable={check['vulnerable']}"
        )
    if validity.secured_violations:
        print("  secured-profile violations:", ", ".join(validity.secured_violations))
    print(f"secured exit={secured.exit_code} vulnerable exit={vulnerable.exit_code}")
    if secured.json_path:
        print(f"secured json={secured.json_path}")
    if vulnerable.html_path:
        print(f"vulnerable html={vulnerable.html_path}")
    if secured.has_violation:
        return 1
    if not validity.overall or secured.has_inconclusive or vulnerable.has_inconclusive:
        return 2
    return 0


def _build_contract_target(
    contract: ContractV1, adapter: str
) -> ContractTarget:
    if adapter == "mock":
        return MockContractTarget(contract)
    if adapter == "http":
        if not contract.target.url:
            raise ContractError(
                "missing_target_url",
                "target.url",
                "the http adapter requires target.url",
            )
        if not contract.limits.egress_allowlist:
            raise ContractError(
                "missing_egress_allowlist",
                "limits.egress_allowlist",
                "the http adapter requires a non-empty egress allowlist",
            )
        config = HttpConfig(
            url=contract.target.url,
            model=contract.target.model or "redfence-target",
            timeout_ms=contract.limits.timeout_ms,
            max_response_bytes=contract.limits.max_response_bytes,
            egress_allowlist=list(contract.limits.egress_allowlist),
        )
        return HttpContractTarget(UrllibTransport(), config)
    raise ContractError("invalid_adapter", "adapter", f"unknown adapter {adapter!r}")


def _cmd_contract_validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        contract = load_contract(path)
    except ContractError as error:
        print(f"error={error.code} path={error.path}")
        return 3
    print(f"valid contract={contract.id}")
    return 0


def _cmd_contract_test(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        contract = load_contract(path)
    except ContractError as error:
        print(f"error={error.code} path={error.path}")
        return 3

    adapter = str(args.adapter)
    try:
        target = _build_contract_target(contract, adapter)
    except ContractError as error:
        print(f"error={error.code} path={error.path}")
        return 3

    try:
        result = run_contract(contract, target)
        result.evidence = [oracle.score(result.run) for oracle in contract_oracles()]
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"error={exc}")
        return 2

    out_dir = Path(args.out) if args.out else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    result.json_path = write_contract_json(
        result, out_dir / f"{contract.id}.json"
    )
    result.sarif_path = write_sarif(result, out_dir / f"{contract.id}.sarif")
    result.junit_path = write_junit(
        result, out_dir / f"{contract.id}.junit.xml"
    )

    exit_code = contract_exit_code(result)
    print(f"contract={contract.id} adapter={adapter} exit={exit_code}")
    for item in result.evidence:
        print(f"  [{item.outcome.value:>11}] {item.oracle_id}: {item.observed}")
    print(f"json={result.json_path}")
    print(f"sarif={result.sarif_path}")
    print(f"junit={result.junit_path}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redfence", description="RedFenceBench CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run one security profile")
    run_parser.add_argument(
        "--profile",
        choices=[p.value for p in SecurityProfile],
        default=SecurityProfile.SECURED.value,
    )
    run_parser.add_argument("--out", default=None, help="report output directory")
    run_parser.add_argument(
        "--isolated-oracles",
        action="store_true",
        help="score oracles in a separate OS process using a frozen snapshot",
    )
    run_parser.set_defaults(func=_cmd_run)

    demo_parser = sub.add_parser("demo", help="run secured + vulnerable and check G2")
    demo_parser.add_argument("--out", default=None, help="report output directory")
    demo_parser.add_argument(
        "--isolated-oracles",
        action="store_true",
        help="run G2 with oracles in a separate OS process",
    )
    demo_parser.set_defaults(func=_cmd_demo)

    contract_parser = sub.add_parser(
        "contract", help="validate and run a contract v1 file"
    )
    contract_sub = contract_parser.add_subparsers(
        dest="contract_command", required=True
    )

    validate_parser = contract_sub.add_parser(
        "validate", help="validate a contract file (exit 3 when invalid)"
    )
    validate_parser.add_argument("path")
    validate_parser.set_defaults(func=_cmd_contract_validate)

    test_parser = contract_sub.add_parser(
        "test", help="run a contract against an adapter"
    )
    test_parser.add_argument("path")
    test_parser.add_argument(
        "--adapter", choices=["mock", "http"], default="mock"
    )
    test_parser.add_argument(
        "--out", default=None, help="report output directory"
    )
    test_parser.set_defaults(func=_cmd_contract_test)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
