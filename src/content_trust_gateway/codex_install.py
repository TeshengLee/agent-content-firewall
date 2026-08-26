from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PLUGIN_NAME = "agent-content-firewall"
LEGACY_PLUGIN_NAMES = ("content-trust-gateway",)


def _command(root: Path, script: str, arguments: str) -> str:
    return f'python3 "{root / "adapters" / script}" {arguments}'


def _groups(root: Path) -> dict[str, list[dict[str, Any]]]:
    return {
        "SessionStart": [
            {
                "matcher": "startup|resume|clear|compact",
                "hooks": [
                    {
                        "type": "command",
                        "command": _command(root, "policy_hook.py", "--client codex"),
                        "timeout": 10,
                        "statusMessage": "Loading agent firewall policy",
                    }
                ],
            }
        ],
        "PreToolUse": [
            {
                "matcher": "^(Bash|exec_command|execute_command|Read|read_file|view_image|mcp__filesystem__.*)$",
                "hooks": [
                    {
                        "type": "command",
                        "command": _command(
                            root, "common_hook.py", "--client codex --phase pre"
                        ),
                        "timeout": 600,
                        "statusMessage": "Checking commands and untrusted content",
                    }
                ],
            }
        ],
        "PostToolUse": [
            {
                "matcher": "^mcp__.*$",
                "hooks": [
                    {
                        "type": "command",
                        "command": _command(
                            root, "common_hook.py", "--client codex --phase post"
                        ),
                        "timeout": 120,
                        "statusMessage": "Checking tool output",
                    }
                ],
            }
        ],
    }


def _belongs_to_gateway(group: Any) -> bool:
    if not isinstance(group, dict):
        return False
    handlers = group.get("hooks", [])
    if not isinstance(handlers, list):
        return False
    return any(
        isinstance(handler, dict)
        and any(
            name in str(handler.get("command", ""))
            for name in (PLUGIN_NAME, *LEGACY_PLUGIN_NAMES)
        )
        and "adapters" in str(handler.get("command", ""))
        for handler in handlers
    )


def merge_hooks(payload: dict[str, Any], root: Path) -> dict[str, Any]:
    merged = json.loads(json.dumps(payload))
    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise TypeError("hooks.json field 'hooks' must be an object")
    for event, groups in _groups(root).items():
        existing = hooks.setdefault(event, [])
        if not isinstance(existing, list):
            raise TypeError(f"hooks.json event '{event}' must be an array")
        existing[:] = [group for group in existing if not _belongs_to_gateway(group)]
        existing.extend(groups)
    return merged


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _copy_project(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git", ".venv", ".ruff_cache", "__pycache__", "*.pyc", "dist", "build"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != destination.resolve():
        shutil.copytree(source, destination, dirs_exist_ok=True, ignore=ignored)
    for legacy_name in LEGACY_PLUGIN_NAMES:
        stale_skill = destination / "skills" / legacy_name
        if stale_skill.is_symlink():
            stale_skill.unlink()
        elif stale_skill.exists():
            shutil.rmtree(stale_skill)


def install(source: Path, home: Path, *, bootstrap: bool = True) -> dict[str, str]:
    source = source.resolve(strict=True)
    install_root = home / ".local" / "share" / PLUGIN_NAME
    hooks_path = home / ".codex" / "hooks.json"
    hooks_backup = home / ".codex" / "hooks.json.agent-content-firewall-backup"
    skill_target = home / ".agents" / "skills" / PLUGIN_NAME

    legacy_install_root = home / ".local" / "share" / LEGACY_PLUGIN_NAMES[0]
    if legacy_install_root.exists() and not install_root.exists():
        legacy_install_root.rename(install_root)

    legacy_skill_target = home / ".agents" / "skills" / LEGACY_PLUGIN_NAMES[0]
    if legacy_skill_target.exists() and not skill_target.exists():
        legacy_skill_target.rename(skill_target)

    _copy_project(source, install_root)
    if bootstrap:
        subprocess.run(
            [sys.executable, str(install_root / "scripts" / "bootstrap.py")],
            check=True,
            env=os.environ.copy(),
        )

    if hooks_path.exists():
        with hooks_path.open(encoding="utf-8") as stream:
            hooks = json.load(stream)
        if not hooks_backup.exists():
            shutil.copy2(hooks_path, hooks_backup)
    else:
        hooks = {"hooks": {}}
    _write_json_atomic(hooks_path, merge_hooks(hooks, install_root))

    skill_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        install_root / "skills" / PLUGIN_NAME,
        skill_target,
        dirs_exist_ok=True,
    )
    return {
        "install_root": str(install_root),
        "hooks_path": str(hooks_path),
        "hooks_backup": str(hooks_backup),
        "skill_path": str(skill_target),
    }
