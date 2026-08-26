#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from content_trust_gateway.hook_protocol import hook_output, safe_evaluate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--client", choices=("codex", "claude", "workbuddy", "raw"), required=True
    )
    parser.add_argument("--phase", choices=("pre", "post"), required=True)
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, TypeError):
        summary = {"status": "error", "files": 0, "codes": ["HOOK_INPUT_INVALID"]}
    else:
        summary = safe_evaluate(payload, args.phase)
    output = hook_output(args.client, args.phase, summary)
    if output:
        print(output)


if __name__ == "__main__":
    main()
