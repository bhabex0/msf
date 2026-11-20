"""Convenience launcher: python run.py [--port 8000] [--reload]"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the APK Pentest Platform API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument(
        "--auto-web-ports", action="store_true",
        help="activate all dedicated tool web ports when running on the trigger port (default 8000)",
    )
    args = parser.parse_args()

    cmd = [
        sys.executable, "-m", "uvicorn", "app.main:app",
        "--host", args.host, "--port", str(args.port),
    ]
    if args.reload:
        cmd.append("--reload")
    env = os.environ.copy()
    env["APKPT_PLATFORM_PORT"] = str(args.port)
    if args.auto_web_ports:
        env["APKPT_TOOL_WEB_AUTO"] = "1"
    subprocess.run(cmd, cwd=str(ROOT / "backend"), check=False, env=env)


if __name__ == "__main__":
    main()
