from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from mailatt.config import Config, default_config_for_fixtures
from mailatt.runner import collect

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
FIXED_TIME = datetime(2024, 5, 17, 12, 0, 0, tzinfo=timezone.utc)


def fixed_clock() -> datetime:
    return FIXED_TIME


def write_config(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture()
def demo_config(tmp_path: Path) -> Config:
    return default_config_for_fixtures(FIXTURES, tmp_path / "work")


@pytest.fixture(scope="session")
def demo_run(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    workdir = tmp_path_factory.mktemp("demo-run") / "work"
    config = default_config_for_fixtures(FIXTURES, workdir)
    result = collect(config, clock=fixed_clock)
    return SimpleNamespace(config=config, result=result, workdir=workdir)


@pytest.fixture()
def expected_demo() -> dict:
    return json.loads((FIXTURES / "expected" / "demo_summary.json").read_text(encoding="utf-8"))
