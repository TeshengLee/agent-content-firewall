from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .scanner import (
    TARGET_SUFFIXES,
    Finding,
    ScanResult,
    scan_file,
    scan_text,
    summarize,
)

SHELL_TOOL_NAMES = {
    "bash",
    "shell",
    "exec_command",
    "execute_command",
    "run_shell_command",
}

SENSITIVE_SHELL_PATTERNS = (
    re.compile(
        r"(?:^|[\s'\"=:(])(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/\s]+|"
        r"/Users/[^/\s]+)/\.(?:ssh|aws|azure|kube|docker|codex|claude|"
        r"cli-proxy-api|wrangler|config/(?:gh|gcloud|doctl|hub|codex|claude))"
        r"(?:[/\s'\";|)]|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"=:(])(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/\s]+|"
        r"/Users/[^/\s]+)/\.gitconfig(?:$|[\s'\";|)])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[/\s'\";(])\.(?:env(?:\.[\w.-]+)?|npmrc|yarnrc|pypirc|netrc|"
        r"bash_history|zsh_history|python_history)(?:$|[/\s'\";|)])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|credentials(?:\.json)?|"
        r"application_default_credentials\.json|accessTokens\.json|"
        r"azureProfile\.json|hosts\.yml)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:^|[/\s'\";(])auth-dir(?:[/\s'\";|)]|$)", re.IGNORECASE),
)

NETWORK_TOOL_PATTERN = re.compile(
    r"(?:^|[\s;&|()])(?:(?:/usr)?/bin/)?"
    r"(?:curl|wget|http|httpie|nc|ncat|netcat|socat|ssh|scp|sftp|rsync)\b",
    re.IGNORECASE,
)
ENV_DUMP_PATTERN = re.compile(
    r"(?:^|[;&|()])\s*(?:env|printenv)(?:\s|[;&|)]|$)", re.IGNORECASE
)
MASS_CREDENTIAL_DISCOVERY_PATTERN = re.compile(
    r"\bfind\s+/(?:\s|$).{0,800}(?:config\.ya?ml|auth-dir|\.env|credentials|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)|private[_-]?key|api[_-]?key)",
    re.IGNORECASE | re.DOTALL,
)
UPLOAD_PATTERN = re.compile(
    r"(?:\bcurl\b.{0,800}(?:--data(?:-binary|-raw|-urlencode)?\b|-d\b|"
    r"--form\b|-F\b|--upload-file\b|-T\b)|"
    r"\bwget\b.{0,800}--post-(?:data|file)\b)",
    re.IGNORECASE | re.DOTALL,
)
PIPE_UPLOAD_PATTERN = re.compile(
    r"\|.{0,800}\bcurl\b.{0,800}(?:--data(?:-binary|-raw)?\s+@-|"
    r"-d\s+@-|--form\s+[^\s=]+=@-|-[FT]\s+@-)",
    re.IGNORECASE | re.DOTALL,
)
REMOTE_EXECUTION_PATTERN = re.compile(
    r"(?:\b(?:curl|wget)\b[^|\n]{0,1000}\|\s*(?:sh|bash|zsh|python\d*|node)\b|"
    r"\b(?:sh|bash|zsh|python\d*|node|eval)\b.{0,200}\$\(\s*(?:curl|wget)\b|"
    r"\bsource\s+<\(\s*(?:curl|wget)\b)",
    re.IGNORECASE | re.DOTALL,
)
CREDENTIAL_COMMAND_PATTERN = re.compile(
    r"(?:\bsecurity\s+(?:find-generic-password|find-internet-password|"
    r"dump-keychain)\b|\bgh\s+auth\s+token\b|\bgit\s+credential\s+fill\b|"
    r"\bgcloud\s+auth\b.{0,120}\bprint-access-token\b|"
    r"\baws\s+configure\s+get\b)",
    re.IGNORECASE | re.DOTALL,
)


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def _shell_command(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    if tool_name.lower() not in SHELL_TOOL_NAMES:
        return None
    for key in ("command", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
    return None


def _scan_shell_command(command: str) -> ScanResult:
    result = ScanResult(status="clean", kind="shell-command", sha256=None, findings=[])
    sensitive_access = any(
        pattern.search(command) for pattern in SENSITIVE_SHELL_PATTERNS
    )
    environment_dump = ENV_DUMP_PATTERN.search(command) is not None
    mass_discovery = MASS_CREDENTIAL_DISCOVERY_PATTERN.search(command) is not None
    network_tool = NETWORK_TOOL_PATTERN.search(command) is not None
    upload = UPLOAD_PATTERN.search(command) is not None
    credential_command = CREDENTIAL_COMMAND_PATTERN.search(command) is not None

    if REMOTE_EXECUTION_PATTERN.search(command):
        result.add(Finding("SHELL_REMOTE_CODE_EXECUTION", "block", "shell command"))
    if mass_discovery:
        result.add(Finding("SHELL_MASS_CREDENTIAL_DISCOVERY", "block", "shell command"))
    if sensitive_access:
        result.add(Finding("SHELL_SENSITIVE_PATH_ACCESS", "review", "shell command"))
    if environment_dump:
        result.add(Finding("SHELL_ENVIRONMENT_DISCOVERY", "review", "shell command"))
    if credential_command:
        result.add(Finding("SHELL_CREDENTIAL_COMMAND", "block", "shell command"))
    if PIPE_UPLOAD_PATTERN.search(command):
        result.add(Finding("SHELL_PIPE_UPLOAD", "block", "shell command"))
    elif upload and re.search(r"@(?:-|[^\s'\"]+)", command):
        result.add(Finding("SHELL_FILE_UPLOAD", "review", "shell command"))
    if network_tool and (
        sensitive_access or environment_dump or mass_discovery or credential_command
    ):
        result.add(Finding("SHELL_DATA_EXFILTRATION", "block", "shell command"))
    return result


def _scan_sensitive_tool_paths(tool_input: dict[str, Any]) -> ScanResult:
    result = ScanResult(status="clean", kind="tool-input", sha256=None, findings=[])
    for key in ("file_path", "path", "filename", "image_path", "paths", "files"):
        for value in _walk_strings(tool_input.get(key)):
            if any(pattern.search(value) for pattern in SENSITIVE_SHELL_PATTERNS):
                result.add(
                    Finding("TOOL_SENSITIVE_PATH_ACCESS", "review", "tool input")
                )
    return result


def _candidate_paths(tool_name: str, tool_input: dict[str, Any], cwd: str) -> list[str]:
    candidates: list[str] = []
    for key in ("file_path", "path", "filename", "image_path", "paths", "files"):
        candidates.extend(_walk_strings(tool_input.get(key)))

    command = _shell_command(tool_name, tool_input)
    if command is not None:
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        for token in tokens:
            token = token.strip("'\";,()")
            if not token or token.startswith("-"):
                continue
            expanded = os.path.expanduser(token)
            candidate = Path(expanded)
            if not candidate.is_absolute():
                candidate = Path(cwd) / candidate
            if candidate.suffix.lower() in TARGET_SUFFIXES and candidate.is_file():
                candidates.append(str(candidate))

    normalized: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        candidate = Path(os.path.expanduser(value))
        if not candidate.is_absolute():
            candidate = Path(cwd) / candidate
        try:
            resolved = str(candidate.resolve(strict=True))
        except OSError:
            continue
        if Path(resolved).suffix.lower() not in TARGET_SUFFIXES or resolved in seen:
            continue
        seen.add(resolved)
        normalized.append(resolved)
    return normalized


def evaluate(payload: dict[str, Any], phase: str) -> dict[str, object]:
    tool_name = str(payload.get("tool_name") or payload.get("tool") or "")
    cwd = str(payload.get("cwd") or os.getcwd())
    if phase == "pre":
        tool_input = payload.get("tool_input", payload.get("input", {}))
        if not isinstance(tool_input, dict):
            return {"status": "clean", "files": 0, "codes": []}
        paths = _candidate_paths(tool_name, tool_input, cwd)
        results = [scan_file(path) for path in paths]
        sensitive_path_result = _scan_sensitive_tool_paths(tool_input)
        if sensitive_path_result.findings:
            results.append(sensitive_path_result)
        command = _shell_command(tool_name, tool_input)
        if command is not None:
            command_result = _scan_shell_command(command)
            if command_result.findings:
                results.append(command_result)
        summary = summarize(results)
        summary["files"] = len(paths)
        return summary

    response = payload.get(
        "tool_response", payload.get("result", payload.get("content", ""))
    )
    text = "\n".join(_walk_strings(response))
    if not text:
        return {"status": "clean", "files": 0, "codes": []}
    result = scan_text(
        text, kind="tool-output", location=f"{tool_name or 'tool'} result"
    )
    return summarize([result])


def safe_evaluate(payload: dict[str, Any], phase: str) -> dict[str, object]:
    try:
        return evaluate(payload, phase)
    except Exception:  # noqa: BLE001 - a security hook must fail closed on any scanner defect.
        return {"status": "error", "files": 0, "codes": ["SCANNER_FAILURE"]}


def reason(summary: dict[str, object]) -> str:
    codes = ", ".join(str(code) for code in summary.get("codes", []))
    return f"Untrusted content requires review before the agent can continue ({codes or 'scan failure'})."


def hook_output(client: str, phase: str, summary: dict[str, object]) -> str:
    if summary.get("status") == "clean":
        return ""
    message = reason(summary)
    if client == "raw":
        return json.dumps({"decision": "block", "reason": message, "summary": summary})
    if client == "workbuddy":
        if phase == "pre":
            return json.dumps(
                {
                    "continue": False,
                    "stopReason": message,
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": message,
                    },
                }
            )
        return json.dumps({"continue": False, "stopReason": message})
    if phase == "pre":
        return json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": message,
                }
            }
        )
    return json.dumps({"decision": "block", "reason": message})
