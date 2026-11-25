"""Shared fixtures for the L-6 platform tests. Every test gets its own temporary
database and reports folder; the real demo/live files are never touched."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture
def demo_settings(tmp_path):
    from init_demo import initialise
    from sentinelai.platform.config import Settings

    db = tmp_path / "demo.db"
    reports = tmp_path / "reports"
    initialise(db, reports, log=lambda *_: None)
    return Settings.for_mode("demo", db_path=db, reports_dir=reports)


@pytest.fixture
def api(demo_settings):
    from fastapi.testclient import TestClient
    from sentinelai.platform.api import create_app

    with TestClient(create_app(demo_settings)) as client:
        yield client
