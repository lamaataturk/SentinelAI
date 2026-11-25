"""Start the SentinelAI API and dashboard together (local only).

    python scripts/run_platform.py              # demo mode (initialise first: python scripts/init_demo.py)
    python scripts/run_platform.py --init-demo  # initialise the demo database, then start
    python scripts/run_platform.py --mode live  # read the live (agent) database instead

API:       http://127.0.0.1:8000   (docs at /docs)
Dashboard: http://127.0.0.1:8501
Stop both with Ctrl+C.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def wait_for(url: str, seconds: float = 30) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # local: bypass proxies
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.5)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SentinelAI API and dashboard locally.")
    parser.add_argument("--mode", choices=("demo", "live"), default=os.environ.get("SENTINELAI_MODE", "demo"))
    parser.add_argument("--api-port", type=int, default=8000)
    parser.add_argument("--dashboard-port", type=int, default=8501)
    parser.add_argument("--init-demo", action="store_true", help="run scripts/init_demo.py first")
    args = parser.parse_args()

    env = dict(os.environ, SENTINELAI_MODE=args.mode, SENTINELAI_API_PORT=str(args.api_port),
               SENTINELAI_API_URL=f"http://127.0.0.1:{args.api_port}", PYTHONPATH=str(ROOT))
    if args.init_demo:
        if args.mode != "demo":
            print("--init-demo only works with --mode demo", file=sys.stderr)
            return 2
        code = subprocess.call([sys.executable, str(ROOT / "scripts" / "init_demo.py")], cwd=ROOT, env=env)
        if code != 0:
            return code

    api = subprocess.Popen([sys.executable, "-m", "sentinelai.platform.api"], cwd=ROOT, env=env)
    if not wait_for(f"http://127.0.0.1:{args.api_port}/api/health"):
        print("The API did not start. See the messages above.", file=sys.stderr)
        api.terminate()
        return 1
    dashboard = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "sentinelai" / "dashboard" / "app.py"),
         "--server.address", "127.0.0.1", "--server.port", str(args.dashboard_port)],
        cwd=ROOT, env=env)
    wait_for(f"http://127.0.0.1:{args.dashboard_port}/_stcore/health")
    print(f"\nSentinelAI ({args.mode} mode)")
    print(f"  API:       http://127.0.0.1:{args.api_port}  (docs: /docs)")
    print(f"  Dashboard: http://127.0.0.1:{args.dashboard_port}")
    print("Press Ctrl+C to stop both.\n")
    try:
        while api.poll() is None and dashboard.poll() is None:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for process in (dashboard, api):
            if process.poll() is None:
                process.terminate()
        for process in (dashboard, api):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
