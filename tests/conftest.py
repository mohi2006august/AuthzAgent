from pathlib import Path

import pytest

from authz import Profile

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def profile() -> Profile:
    return Profile.load(ROOT / "tasks" / "_profile.json")


@pytest.fixture(scope="session")
def suite():
    from authz_bench.tasks import load_suite

    return load_suite(ROOT / "tasks")
