"""L-6.1: check that the platform (API + dashboard) can run on this computer.

Prints the Python version and the installed version of every package the
project needs, then checks that the existing SentinelAI modules still import.
Exit code 0 = ready, 1 = something is missing.

    python scripts/check_platform_env.py
"""
from __future__ import annotations

import importlib
import importlib.metadata as metadata
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# (distribution name, import name, needed for)
PACKAGES = [
    ("pandas", "pandas", "existing"),
    ("numpy", "numpy", "existing"),
    ("scikit-learn", "sklearn", "existing"),
    ("joblib", "joblib", "existing"),
    ("pytest", "pytest", "existing"),
    ("fastapi", "fastapi", "L-6 API"),
    ("uvicorn", "uvicorn", "L-6 API server"),
    ("streamlit", "streamlit", "L-6 dashboard"),
    ("requests", "requests", "L-6 dashboard -> API"),
    ("httpx", "httpx", "L-6 API tests"),
    ("altair", "altair", "L-6 charts (installed with streamlit)"),
]

PROJECT_MODULES = [
    "sentinelai.contracts.messages",
    "sentinelai.platform.shared_memory",
    "sentinelai.platform.orchestrator",
    "sentinelai.reporting.reporting_agent",
    "sentinelai.reporting.traceability",
    "sentinelai.response.response_agent",
]


def main() -> int:
    problems = 0
    print(f"Python {sys.version.split()[0]} ({sys.executable})")
    if sys.version_info < (3, 10):
        print("  !! Python 3.10 or newer is needed")
        problems += 1

    print("\nPackages:")
    for dist, module, used_for in PACKAGES:
        try:
            version = metadata.version(dist)
            importlib.import_module(module)
            print(f"  OK       {dist:<13} {version:<10} {used_for}")
        except Exception as exc:  # not installed or broken install
            print(f"  MISSING  {dist:<13} {'-':<10} {used_for}  ({type(exc).__name__})")
            problems += 1

    print("\nExisting SentinelAI modules:")
    for module in PROJECT_MODULES:
        try:
            importlib.import_module(module)
            print(f"  OK       {module}")
        except Exception as exc:
            print(f"  ERROR    {module}: {exc}")
            problems += 1

    config = ROOT / ".streamlit" / "config.toml"
    print(f"\nDashboard config: {'found' if config.exists() else 'MISSING'} ({config.relative_to(ROOT)})")
    problems += 0 if config.exists() else 1

    print("\nREADY" if problems == 0 else f"\nNOT READY: {problems} problem(s)")
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
