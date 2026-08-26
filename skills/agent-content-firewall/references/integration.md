# Integration

Run `python3 scripts/bootstrap.py` from the plugin root once. This creates an isolated runtime and installs the pinned PDF and AZW3/MOBI scanners. It does not modify client configuration.

## Codex

Run `install-codex.command` or `python3 scripts/install_codex.py --apply`, then review the installed hooks. Session policy, local file preflight, and MCP result scanning run synchronously. Hosted tools and direct inline attachments are not a complete hook boundary.

## Claude Code

Set `AGENT_CONTENT_FIREWALL_ROOT` to the plugin root and merge `adapters/claude/settings.hooks.json` into the applicable Claude settings file. The configuration adds SessionStart, PreToolUse, and PostToolUse hooks. Claude `@file` references bypass PreToolUse, so the SessionStart policy remains necessary.

## Pi

Add the absolute path of `adapters/pi/content-trust.ts` to the `extensions` array in Pi settings, or place the adapter in an auto-discovered extension directory while keeping its relative path to `adapters/common_hook.py`. The extension blocks suspicious tool calls, replaces suspicious tool results, and appends the trust policy before each agent turn.

## OpenCode

Add the absolute path of `adapters/opencode/content-trust.ts` to the `plugins` array in OpenCode configuration. The adapter uses the V2 context and tool runtime hooks. OpenCode V2 plugins are beta, so revalidate this adapter after client upgrades.

## DeepSeek Harness

DeepSeek Harness is in developer preview. The adapter uses the official `@deepseek-ai/dsh-hooks-codex` bridge rather than importing private harness internals.

Install the bridge into the target profile:

```bash
npx @deepseek-ai/dsh plugin --profile web add @deepseek-ai/dsh-hooks-codex
```

Launch the selected profile through the overlay wrapper:

```bash
adapters/deepseek-harness/run-dsh.sh web
```

The wrapper sets the gateway root and mounts `adapters/deepseek-harness/cordis.patch.yml`. The dedicated Hook configuration scans all tool results before they return to the model. The official bridge currently flattens structured tool output to text and exposes only shell-style command arguments during `PreToolUse`; result scanning is therefore the primary enforcement point for file and web tools. Revalidate the adapter against the pinned official developer-preview revision documented in the repository before adopting a newer Harness release.

## Tencent WorkBuddy

The repository root is also a WorkBuddy plugin through `.workbuddy-plugin/plugin.json`. WorkBuddy and CodeBuddy use Claude Code-compatible Hooks and expose `${CODEBUDDY_PLUGIN_ROOT}` for bundled scripts.

After running the shared bootstrap, load the repository directly for development or local verification:

```bash
codebuddy --plugin-dir /path/to/agent-content-firewall
```

The WorkBuddy-specific Hook configuration is `adapters/workbuddy/hooks.json`. It covers both CLI tool names (`Read`, `Write`, `Edit`, `Bash`, `WebSearch`, `WebFetch`) and IDE aliases (`read_file`, `write_to_file`, `replace_in_file`, `execute_command`, `web_search`, `web_fetch`). `PreToolUse` blocks suspicious input before execution; `PostToolUse` stops suspicious output before it is accepted into the next agent step. Plugin-level Hooks are used so no `allowUntrustedFrontmatterHooks` setting is required. The plugin declares no monitor, MCP server, remote classifier, or background process.

## Enforcement

All clients use the same scanner and verdicts. `clean` continues. `review`, `block`, and `error` stop the operation. The adapters expose finding codes rather than suspicious payload text. No adapter starts a background service or enables remote classification.

Pre-tool checks also inspect shell command text for credential discovery, sensitive path access, piped uploads, and downloaded-code execution. This reduces exposure to malicious tool calls inserted by a third-party model relay, but it cannot reliably detect arbitrary obfuscation or a compromised client. Do not use untrusted relays with full access or unattended execution.
