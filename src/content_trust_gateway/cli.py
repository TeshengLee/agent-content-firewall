from __future__ import annotations

import argparse
import json
import sys

from .hook_protocol import hook_output, safe_evaluate
from .scanner import scan_file, scan_text


def main() -> None:
    parser = argparse.ArgumentParser(prog="agent-content-firewall")
    subparsers = parser.add_subparsers(dest="command", required=True)

    file_parser = subparsers.add_parser("file")
    file_parser.add_argument("path")

    text_parser = subparsers.add_parser("text")
    text_parser.add_argument("--stdin", action="store_true", required=True)

    hook_parser = subparsers.add_parser("hook")
    hook_parser.add_argument(
        "--client", choices=("codex", "claude", "workbuddy", "raw"), required=True
    )
    hook_parser.add_argument("--phase", choices=("pre", "post"), required=True)

    args = parser.parse_args()
    if args.command == "file":
        result = scan_file(args.path)
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.status == "clean" else 2)
    if args.command == "text":
        result = scan_text(sys.stdin.read())
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.status == "clean" else 2)

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
