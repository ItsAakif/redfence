"""Execute the Docker isolation checks for G6/G9.

Starts the two separate databases and the internal sink, then runs the
credential/network checks and the target sandbox probe. Prints all output and
returns non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def run(*args: str) -> tuple[int, str]:
    process = subprocess.run(args, text=True, capture_output=True, check=False)
    output = (process.stdout + process.stderr).strip()
    print(f"$ {' '.join(args)}")
    print(output)
    return process.returncode, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="leave containers running")
    args = parser.parse_args()
    failures = 0

    rc, _ = run("docker", "compose", "up", "-d", "platform-db", "sut-db", "sink")
    failures += int(rc != 0)

    for service in ("platform-check", "sut-check", "target-sandbox"):
        rc, _ = run("docker", "compose", "run", "--rm", service)
        if rc != 0:
            failures += 1
        print()

    run("docker", "compose", "logs", "--no-color", "sink")
    if not args.keep:
        run("docker", "compose", "down", "-v")
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
