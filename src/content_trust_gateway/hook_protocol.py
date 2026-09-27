from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import subprocess
import time
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
        summary["paths"] = paths
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


REVIEW_PROMPT_SECONDS = 120
REVIEW_ALLOW_BUTTON = "放行一次"
REVIEW_DENY_BUTTON = "拒绝"
REVIEW_PROMPT_SCRIPT = f"""on run argv
    set r to display dialog (item 1 of argv) with title "Agent Content Firewall" \
buttons {{"{REVIEW_DENY_BUTTON}", "{REVIEW_ALLOW_BUTTON}"}} \
default button "{REVIEW_DENY_BUTTON}" with icon caution \
giving up after {REVIEW_PROMPT_SECONDS}
    if gave up of r then return "timeout"
    return button returned of r
end run"""


REVIEW_ALERT_SOUND = "/System/Library/Sounds/Glass.aiff"
REVIEW_ALERT_VOICE = "Tingting"
CLIENT_LABELS = {"codex": "Codex", "claude": "Claude", "workbuddy": "WorkBuddy"}


REVIEW_ALERT_COOLDOWN_SECONDS = 60
REVIEW_ALERT_STAMP = (
    Path.home() / ".local/state/agent-content-firewall/last-review-alert"
)


def _claim_alert_slot() -> bool:
    """Return True at most once per cooldown window, even across concurrent hooks."""
    try:
        REVIEW_ALERT_STAMP.parent.mkdir(parents=True, exist_ok=True)
        with open(REVIEW_ALERT_STAMP, "a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.seek(0)
            try:
                last = float(handle.read().strip() or 0)
            except ValueError:
                last = 0.0
            now = time.time()
            if now - last < REVIEW_ALERT_COOLDOWN_SECONDS:
                return False
            handle.seek(0)
            handle.truncate()
            handle.write(str(now))
            return True
    except OSError:
        return True


def announce_review(client: str) -> None:
    """Play a chime and speak the request locally without blocking the dialog."""
    if not _claim_alert_slot():
        return
    spoken = f"{CLIENT_LABELS.get(client, client)} 请求任务放行"
    try:
        subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                '/usr/bin/afplay "$1"; /usr/bin/say -v "$2" "$3"',
                "sh",
                REVIEW_ALERT_SOUND,
                REVIEW_ALERT_VOICE,
                spoken,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


# Review codes that only say "not checked / cannot prove clean" and carry no concrete evidence.
NO_EVIDENCE_REVIEW_CODES = frozenset(
    {"IMAGE_HIDDEN_CHANNELS_NOT_PROVABLE", "UNSUPPORTED_DOCUMENT_FORMAT"}
)
REVIEW_DETAIL_LIMIT = 5
REVIEW_CODE_LABELS = {
    "AGENT_DIRECTED_INSTRUCTION": "文字中出现疑似针对 AI 的指令",
    "INVISIBLE_UNICODE": "文字中夹有零宽等不可见字符",
    "HIDDEN_HTML_TEXT": "网页中有隐藏文字",
    "HIDDEN_DOCX_RUN": "Word 中有隐藏、极小字号或白色文字",
    "PDF_SCANNER_FINDING": "PDF 扫描器报告异常（如隐藏或低对比文字）",
    "ACTIVE_HTML_CONTENT": "网页含脚本或内嵌框架",
    "OOXML_EXTERNAL_RELATIONSHIP": "Office 文件引用外部链接或资源",
    "EPUB_ACTIVE_CONTENT": "电子书含脚本",
    "EPUB_NESTED_ARCHIVE": "电子书内嵌压缩包",
    "EPUB_MIMETYPE_INVALID": "电子书格式声明异常",
    "EPUB_MIMETYPE_MISSING": "电子书缺少格式声明",
    "EPUB_MEMBER_LIMIT_EXCEEDED": "电子书文件数超出扫描上限，未扫完",
    "EPUB_UNCOMPRESSED_LIMIT_EXCEEDED": "电子书解压后过大，未扫完",
    "EPUB_TEXT_LIMIT_EXCEEDED": "电子书文字过多，未扫完",
    "EPUB_IMAGE_LIMIT_EXCEEDED": "电子书图片过多，未扫完",
    "TEXT_LIMIT_EXCEEDED": "文字过长，只扫描了前段",
    "FILE_SIZE_LIMIT_EXCEEDED": "文件过大，未扫描",
    "PDF_PAGE_LIMIT_EXCEEDED": "PDF 页数超出扫描上限，未扫完",
    "PDF_PAGE_COUNT_UNAVAILABLE": "读不出 PDF 页数，未扫描",
    "PDF_RENDER_ERROR": "PDF 渲染失败，未做 OCR",
    "PDF_RENDERER_UNAVAILABLE": "缺少 PDF 渲染工具，未做 OCR",
    "PDF_TEXT_EXTRACTION_ERROR": "PDF 文字层提取失败",
    "PDF_SCANNER_UNAVAILABLE": "缺少 PDF 注入扫描器，未扫描",
    "PDF_ACTIVE_CONTENT_CHECK_ERROR": "PDF 脚本检查失败",
    "PDF_ATTACHMENT_CHECK_ERROR": "PDF 附件检查失败",
    "LOCAL_OCR_ERROR": "本地 OCR 失败，未检查图片文字",
    "LOCAL_OCR_UNAVAILABLE": "缺少本地 OCR，未检查图片文字",
    "SHELL_ENVIRONMENT_DISCOVERY": "命令会读取环境变量等系统信息",
    "SHELL_FILE_UPLOAD": "命令可能上传文件",
    "SHELL_SENSITIVE_PATH_ACCESS": "命令访问敏感路径（如密钥、配置目录）",
    "TOOL_SENSITIVE_PATH_ACCESS": "读取敏感路径（如密钥、配置目录）",
}


def only_no_evidence(summary: dict[str, object]) -> bool:
    codes = {str(code) for code in summary.get("codes", [])}
    return bool(codes) and codes <= NO_EVIDENCE_REVIEW_CODES


def _review_details_text(summary: dict[str, object]) -> str:
    lines: list[str] = []
    details = [
        item
        for item in summary.get("details", [])
        if isinstance(item, dict) and item.get("code") not in NO_EVIDENCE_REVIEW_CODES
    ]
    for item in details[:REVIEW_DETAIL_LIMIT]:
        code = str(item.get("code", ""))
        label = REVIEW_CODE_LABELS.get(code, code)
        lines.append(f"· {label}（{item.get('location', '')}）")
        excerpt = str(item.get("excerpt") or "")
        if excerpt:
            lines.append(f"  命中原文：「{excerpt}」")
    if len(details) > REVIEW_DETAIL_LIMIT:
        lines.append(f"……另 {len(details) - REVIEW_DETAIL_LIMIT} 处")
    return "\n".join(lines)


def ask_user_review(summary: dict[str, object], client: str = "codex") -> bool:
    """Show a local macOS dialog for review-level findings; anything but an explicit allow denies."""
    announce_review(client)
    names = [Path(str(path)).name for path in summary.get("paths", [])]
    text = (
        f"{CLIENT_LABELS.get(client, client)} 请求任务放行。\n"
        "扫描发现以下需要你判断的内容：\n\n"
    )
    if names:
        text += "文件：\n" + "\n".join(names[:10])
        if len(names) > 10:
            text += f"\n……另 {len(names) - 10} 个"
        text += "\n\n"
    text += f"{_review_details_text(summary)}\n\n{REVIEW_PROMPT_SECONDS} 秒内未选择按拒绝处理。"
    try:
        completed = subprocess.run(
            ["/usr/bin/osascript", "-e", REVIEW_PROMPT_SCRIPT, text],
            capture_output=True,
            check=False,
            text=True,
            timeout=REVIEW_PROMPT_SECONDS + 15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and completed.stdout.strip() == REVIEW_ALLOW_BUTTON


def hook_output(client: str, phase: str, summary: dict[str, object]) -> str:
    if summary.get("status") == "clean":
        return ""
    message = reason(summary)
    if client == "codex" and phase == "pre" and summary.get("status") == "review":
        if only_no_evidence(summary) or ask_user_review(summary, client):
            return ""
        message = f"User did not approve review-level content ({', '.join(str(c) for c in summary.get('codes', []))})."
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
