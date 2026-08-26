#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 20 * 1024 * 1024
NOREPLY_SUFFIX = "@" + "users.noreply.github.com"
APPROVED_GIT_NAME = "TeshengLee"
APPROVED_GIT_EMAIL = "55652147+TeshengLee" + NOREPLY_SUFFIX

EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SIGNATURES = [
    ("macOS home path", re.compile(b"/" + b"Users" + rb"/[A-Za-z0-9._-]+/")),
    ("Linux home path", re.compile(b"/" + b"home" + rb"/[A-Za-z0-9._-]+/")),
    (
        "Windows user path",
        re.compile(rb"[A-Za-z]:\\" + b"Users" + rb"\\[A-Za-z0-9._ -]+\\"),
    ),
    ("macOS temporary path", re.compile(b"/var/" + b"folders/")),
    ("clipboard temporary name", re.compile(b"codex-" + b"clipboard-", re.IGNORECASE)),
    (
        "private key",
        re.compile(b"-----BEGIN " + rb"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "GitHub token",
        re.compile(rb"(?:github_" + b"pat_" + rb"|gh[pousr]_[A-Za-z0-9_]{20,})"),
    ),
    ("API key", re.compile(rb"\b" + b"sk-" + rb"[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(rb"\bA" + b"KIA" + rb"[A-Z0-9]{16}\b")),
]


def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _scan_bytes(
    label: str, data: bytes, deny_terms: tuple[bytes, ...] = ()
) -> list[str]:
    findings: list[str] = []
    for name, pattern in SIGNATURES:
        if pattern.search(data):
            findings.append(f"{label}: {name}")
    for match in EMAIL.finditer(data):
        value = match.group().decode("ascii", errors="replace")
        if not value.lower().endswith(NOREPLY_SUFFIX):
            findings.append(f"{label}: public email address")
    lowered = data.lower()
    for term in deny_terms:
        if term and term.lower() in lowered:
            findings.append(f"{label}: custom denied term")
    return findings


def _approved_git_identity(name: str, email: str) -> bool:
    return name == APPROVED_GIT_NAME and email == APPROVED_GIT_EMAIL


def audit(deny_terms: tuple[bytes, ...] = ()) -> list[str]:
    findings: list[str] = []
    tracked = [item for item in _git("ls-files", "-z").split(b"\0") if item]
    for raw_path in tracked:
        path = ROOT / raw_path.decode("utf-8", errors="surrogateescape")
        findings.extend(_scan_bytes("tracked path", raw_path, deny_terms))
        if not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            findings.append("tracked file: exceeds 20 MiB review limit")
            continue
        findings.extend(_scan_bytes("tracked file", path.read_bytes(), deny_terms))

    metadata = _git("log", "--all", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce")
    findings.extend(_scan_bytes("commit metadata", metadata, deny_terms))
    records = [line.split(b"\0") for line in metadata.splitlines() if line]
    for record in records:
        if len(record) != 5:
            findings.append("commit metadata: malformed record")
            continue
        identities = ((record[1], record[2]), (record[3], record[4]))
        for raw_name, raw_email in identities:
            name = raw_name.decode("utf-8", errors="replace")
            email = raw_email.decode("utf-8", errors="replace")
            if not _approved_git_identity(name, email):
                findings.append("commit metadata: unapproved Git identity")

    history = _git("log", "--all", "--format=", "--patch", "--binary", "--no-color")
    findings.extend(_scan_bytes("reachable Git history", history, deny_terms))
    return sorted(set(findings))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check tracked content and Git history for private data"
    )
    parser.add_argument(
        "--deny-term",
        action="append",
        default=[],
        help="Case-insensitive personal term that must not appear. Repeat as needed.",
    )
    args = parser.parse_args()
    deny_terms = tuple(term.encode("utf-8") for term in args.deny_term if term)
    findings = audit(deny_terms)
    if findings:
        print("Privacy audit failed:")
        for finding in findings:
            print(f"- {finding}")
        raise SystemExit(1)
    print(
        "Privacy audit passed: tracked files and reachable history contain no matched private data."
    )


if __name__ == "__main__":
    main()
