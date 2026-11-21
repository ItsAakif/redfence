"""Shared test fixtures."""

from __future__ import annotations

import pytest

from redfence.bench.dataset import build_corpus
from redfence.bench.scenario import run_revocation_scenario
from redfence.targets.config import SecurityProfile


@pytest.fixture(scope="session")
def corpus():
    return build_corpus()


@pytest.fixture(scope="session")
def secured_run():
    return run_revocation_scenario(SecurityProfile.SECURED)


@pytest.fixture(scope="session")
def vulnerable_run():
    return run_revocation_scenario(SecurityProfile.VULNERABLE)
