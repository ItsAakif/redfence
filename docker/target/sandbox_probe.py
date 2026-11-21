"""Sandbox probe for the target container.

Checks that the target can reach its own database and the controlled sink, but
cannot resolve the platform database or reach an external host. Exits non-zero
if an isolation expectation fails.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

result: dict[str, object] = {}


def can_resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def can_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


result["sut_db_resolves"] = can_resolve("sut-db")
result["sut_db_connects"] = can_connect("sut-db", 5432)
result["platform_db_resolves"] = can_resolve("platform-db")
result["platform_db_connects"] = can_connect("platform-db", 5432)

try:
    with urllib.request.urlopen("http://sink:8080/", timeout=5) as response:
        result["sink_status"] = response.status
        result["sink_reachable"] = True
except (urllib.error.URLError, OSError) as error:
    result["sink_reachable"] = False
    result["sink_error"] = str(error)

try:
    urllib.request.urlopen("https://example.com/", timeout=5)
    result["external_reachable"] = True
except (urllib.error.URLError, OSError):
    result["external_reachable"] = False

print(json.dumps(result, sort_keys=True))
ok = (
    result.get("sut_db_resolves") is True
    and result.get("sut_db_connects") is True
    and result.get("platform_db_resolves") is False
    and result.get("sink_reachable") is True
    and result.get("external_reachable") is False
)
raise SystemExit(0 if ok else 1)
