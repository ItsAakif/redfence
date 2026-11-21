"""CI exit semantics (mandate section 13 / ADR-0011)."""

from __future__ import annotations

from redfence.bench.runner import discriminative_validity, run_campaign
from redfence.cli import main
from redfence.targets.config import SecurityProfile


def _demo_from(secured, vulnerable):
    return discriminative_validity(secured, vulnerable), secured, vulnerable


def test_secured_run_exits_zero():
    assert run_campaign(SecurityProfile.SECURED).exit_code == 0


def test_vulnerable_run_exits_one():
    assert run_campaign(SecurityProfile.VULNERABLE).exit_code == 1


def test_cli_secured_returns_zero():
    assert main(["run", "--profile", "secured"]) == 0


def test_cli_vulnerable_returns_one():
    assert main(["run", "--profile", "vulnerable"]) == 1


def test_cli_demo_passes_discriminative_validity():
    assert main(["demo"]) == 0


def test_cli_demo_returns_one_on_secured_violation(monkeypatch):
    """A real vulnerable campaign used as the secured side is a regression."""

    vulnerable = run_campaign(SecurityProfile.VULNERABLE)
    monkeypatch.setattr(
        "redfence.cli.run_demo", lambda **_: _demo_from(vulnerable, vulnerable)
    )
    assert main(["demo"]) == 1


def test_cli_demo_returns_two_when_secured_is_not_discriminating(monkeypatch):
    secured = run_campaign(SecurityProfile.SECURED)
    monkeypatch.setattr(
        "redfence.cli.run_demo", lambda **_: _demo_from(secured, secured)
    )
    assert main(["demo"]) == 2


def test_cli_run_worker_error_returns_two(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("oracle worker failed")

    monkeypatch.setattr("redfence.cli.run_campaign", boom)
    assert main(["run"]) == 2


def test_cli_demo_worker_error_returns_two(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("oracle worker failed")

    monkeypatch.setattr("redfence.cli.run_demo", boom)
    assert main(["demo"]) == 2
