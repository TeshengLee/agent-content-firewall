#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from content_trust_gateway.codex_install import install


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install the local Codex hooks and skill"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the installation. Without this flag, only show the planned targets.",
    )
    parser.add_argument(
        "--skip-bootstrap",
        action="store_true",
        help="Skip creation of the isolated PDF scanning runtime.",
    )
    args = parser.parse_args()
    home = Path.home()
    planned = {
        "install_root": str(home / ".local" / "share" / "agent-content-firewall"),
        "hooks_path": str(home / ".codex" / "hooks.json"),
        "skill_path": str(home / ".agents" / "skills" / "agent-content-firewall"),
        "other_clients": "unchanged",
    }
    if not args.apply:
        print(json.dumps({"mode": "preview", **planned}, indent=2))
        return
    result = install(ROOT, home, bootstrap=not args.skip_bootstrap)
    print(
        json.dumps(
            {"mode": "applied", **result, "other_clients": "unchanged"}, indent=2
        )
    )


if __name__ == "__main__":
    main()
