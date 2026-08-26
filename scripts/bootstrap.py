#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    uv = shutil.which("uv")
    if not uv:
        raise SystemExit("uv is required to create the isolated runtime.")
    command = [
        uv,
        "sync",
        "--project",
        str(ROOT),
        "--extra",
        "pdf",
        "--no-editable",
        "--reinstall-package",
        "agent-content-firewall",
    ]
    completed = subprocess.run(command, check=False, env=os.environ.copy())
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
    python = ROOT / ".venv" / "bin" / "python"
    subprocess.run(
        [str(python), "-m", "unittest", "discover", "-s", str(ROOT / "tests"), "-v"],
        check=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    print("Local runtime is ready.")


if __name__ == "__main__":
    main()
