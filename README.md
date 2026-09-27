# Agent Content Firewall

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md)

Agent Content Firewall is a local security firewall for AI agents. It blocks malicious content and helps prevent agents from being manipulated.

## What it checks

- PDF text color and size through `pdf-injection-scanner`
- PDF rendering and local OCR through Poppler and Tesseract
- PDF metadata, JavaScript, and embedded attachments
- EPUB container safety, large image collections, and local OCR
- unencrypted AZW3 and MOBI files through isolated KindleUnpack extraction
- hidden DOCX runs, macros, embedded objects, alternative text, and external relationships
- hidden HTML, comments, attributes, active elements, and off-screen styles
- zero-width, bidirectional, and Unicode tag characters
- English and Chinese agent-directed or data-exfiltration instructions
- MCP and other tool results before they return to the agent
- shell commands that access credential paths, collect environment data, upload piped content, or execute downloaded code

Results are `clean`, `review`, `block`, or `error`. Every result other than `clean` stops the hooked operation by default, except for the Codex `review` handling below.

### Codex review prompts (macOS)

For Codex pre-tool checks:

- `block` and `error` results are denied.
- `review` results that carry no concrete evidence are allowed without a prompt. These are `IMAGE_HIDDEN_CHANNELS_NOT_PROVABLE`, which every image receives, and `UNSUPPORTED_DOCUMENT_FORMAT`.
- Other `review` results open a local macOS dialog that lists the files, describes each finding, and shows the matched text. Only 放行一次 (Allow once) lets the tool call proceed. 拒绝 (Deny), a 120-second timeout, or a dialog failure denies it. Codex rejects `permissionDecision: "ask"` from PreToolUse hooks, so the hook asks the user directly.
- The dialog plays a chime and speaks “Codex 请求任务放行” with the `Tingting` voice, at most once every 60 seconds.

Matched text appears only in the local dialog. The deny reason returned to the agent contains finding codes only.

## Local setup

Requirements:

- Python 3.10 or later
- [`uv`](https://docs.astral.sh/uv/)
- Poppler commands: `pdfinfo`, `pdftotext`, `pdftoppm`, and `pdfdetach`
- Tesseract with the languages you need

Create the isolated runtime:

```bash
python3 scripts/bootstrap.py
```

Scan a file directly:

```bash
agent-content-firewall file document.pdf
```

## Codex installation

On macOS, download or clone the repository and double-click `install-codex.command`. The installer shows its target paths and asks for confirmation before applying changes.

For a non-interactive one-command installation after cloning:

```bash
./install-codex.command --yes
```

Preview the local changes:

```bash
python3 scripts/install_codex.py
```

Install only the Codex hooks and user skill:

```bash
python3 scripts/install_codex.py --apply
```

The installer preserves existing Hook groups, creates a one-time Hook configuration backup, installs into the user's local data directory, and does not change Claude Code, Pi, or OpenCode. Restart Codex and review the installed Hooks before testing in a new task.

The repository also contains optional adapters for Claude Code, Pi, OpenCode, DeepSeek Harness, and Tencent WorkBuddy under `adapters/`. Their activation steps and interception limits are documented in `skills/agent-content-firewall/references/integration.md`.

## Security boundaries

This is a tripwire, not proof that content is safe. Direct inline attachments, client-native file references, hosted tools, steganography, parser vulnerabilities, and unsupported formats can exceed Hook coverage. Keep agents least-privileged and require confirmation for uploads, external writes, deletion, credential access, and persistent configuration changes.

A third-party model or API relay can alter assistant responses and tool calls before they reach the agent. Never combine an untrusted relay with full access or unattended execution. Shell-command checks are defense in depth, not a substitute for a trusted model endpoint, sandboxing, approvals, and restricted network access.

No background service or remote semantic classifier is enabled. The scanner supports EPUB, unencrypted AZW3/MOBI, common project configuration formats, PDF, DOCX, HTML, text, and image preflight. Format dependencies are pinned in `uv.lock`; see [Third-Party Notices](THIRD_PARTY_NOTICES.md) for their licenses.

## Development

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
uvx ruff check src adapters scripts tests
```

Run the local privacy gate before publishing:

```bash
python3 scripts/privacy_audit.py
git log --all --format='%h %an <%ae> %cn <%ce>'
```

Add personal names, aliases, or email fragments to the local deny list when needed:

```bash
python3 scripts/privacy_audit.py --deny-term "personal-name" --deny-term "email-fragment"
```

The audit checks tracked file names and contents, all reachable Git patches, commit author and committer identities, home-directory paths, temporary attachment names, private-key markers, and common token formats. Commit author and committer must exactly match the project's approved `TeshengLee` GitHub noreply identity. GitHub's own secret scanning should remain enabled as a second, post-push control.

The project is licensed under the MIT License.
