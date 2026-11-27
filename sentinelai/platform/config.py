"""L-6: platform settings (database, reports folder, flow evidence, API address).

Everything can be changed with environment variables, so switching from the
fixture demo to real agent output never needs a code change:

    SENTINELAI_MODE         demo (default) or live
    SENTINELAI_DB           SQLite shared-memory file
    SENTINELAI_REPORTS_DIR  folder the Reporting Agent writes to
    SENTINELAI_FLOWS_CSV    feature CSV whose flow_id column is used to check
                            "flow:" evidence references ("none" = do not check)
    SENTINELAI_API_URL      address the dashboard uses to reach the API
    SENTINELAI_API_HOST     address the API listens on (default 127.0.0.1)
    SENTINELAI_API_PORT     port the API listens on (default 8000)
    SENTINELAI_ALLOWED_HOSTS  comma-separated host names the API answers to
                            (default: 127.0.0.1, localhost and the API host;
                            "*" turns the check off)

Demo and live data always use different files, so demo fixtures can never be
mixed into (or overwrite) a database written by the real agents.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = ROOT / "fixtures"
PLATFORM_DATA_DIR = ROOT / "data" / "platform"

MODES = ("demo", "live")
LOCAL_HOSTS = ("127.0.0.1", "localhost")

_DEFAULTS = {
    "demo": {
        "db": PLATFORM_DATA_DIR / "demo" / "sentinelai_demo.db",
        "reports": PLATFORM_DATA_DIR / "demo" / "reports",
        "flows": FIXTURES_DIR / "features_sample.csv",
    },
    "live": {
        "db": PLATFORM_DATA_DIR / "live" / "sentinelai.db",
        "reports": PLATFORM_DATA_DIR / "live" / "reports",
        "flows": None,
    },
}


@dataclass(frozen=True)
class Settings:
    mode: str
    db_path: Path
    reports_dir: Path
    flows_csv: Path | None
    api_url: str = "http://127.0.0.1:8000"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    # Host header values the API accepts. None skips the check (tests and
    # in-process use); from_env() always sets it.
    allowed_hosts: tuple[str, ...] | None = None

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"SENTINELAI_MODE must be one of {MODES}, not {self.mode!r}")

    @classmethod
    def for_mode(cls, mode: str = "demo", **overrides) -> "Settings":
        if mode not in MODES:
            raise ValueError(f"SENTINELAI_MODE must be one of {MODES}, not {mode!r}")
        defaults = _DEFAULTS[mode]
        values = {
            "mode": mode,
            "db_path": defaults["db"],
            "reports_dir": defaults["reports"],
            "flows_csv": defaults["flows"],
        }
        values.update(overrides)
        return cls(**values)

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        mode = env.get("SENTINELAI_MODE", "demo").strip().lower()
        overrides: dict = {}
        if env.get("SENTINELAI_DB"):
            overrides["db_path"] = Path(env["SENTINELAI_DB"])
        if env.get("SENTINELAI_REPORTS_DIR"):
            overrides["reports_dir"] = Path(env["SENTINELAI_REPORTS_DIR"])
        if "SENTINELAI_FLOWS_CSV" in env:
            value = env["SENTINELAI_FLOWS_CSV"].strip()
            overrides["flows_csv"] = None if value.lower() in ("", "none") else Path(value)
        host = env.get("SENTINELAI_API_HOST", "127.0.0.1")
        port = int(env.get("SENTINELAI_API_PORT", "8000"))
        overrides["api_host"] = host
        overrides["api_port"] = port
        overrides["api_url"] = env.get("SENTINELAI_API_URL", f"http://127.0.0.1:{port}").rstrip("/")
        allowed = [name.strip() for name in env.get("SENTINELAI_ALLOWED_HOSTS", "").split(",") if name.strip()]
        if not allowed:
            allowed = list(LOCAL_HOSTS)
            if host not in allowed and host not in ("0.0.0.0", "::"):
                allowed.append(host)
        overrides["allowed_hosts"] = tuple(allowed)
        return cls.for_mode(mode, **overrides)


def load_flow_ids(flows_csv: Path | None) -> set[str] | None:
    """flow_id values from a feature CSV, or None when no flow file is configured."""
    if flows_csv is None:
        return None
    path = Path(flows_csv)
    if not path.is_file():
        return None
    with path.open(encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if "flow_id" not in (reader.fieldnames or []):
            raise ValueError(f"{path.name} has no flow_id column")
        return {row["flow_id"] for row in reader if row.get("flow_id")}
