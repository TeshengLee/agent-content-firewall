# Changelog

## 0.6.0

### Codex review prompts (macOS)

- `review` results from Codex pre-tool checks no longer hard-deny. The hook opens a local macOS dialog; only “放行一次” (Allow once) proceeds, and “拒绝” (Deny), a 120-second timeout, or a dialog failure denies. Codex rejects `permissionDecision: "ask"` from PreToolUse hooks, so the hook asks the user directly.
- `review` results that carry no concrete evidence (`IMAGE_HIDDEN_CHANNELS_NOT_PROVABLE`, `UNSUPPORTED_DOCUMENT_FORMAT`) are allowed without a prompt.
- The dialog lists the files, a Chinese description of each finding, and the matched text.
- A chime and the spoken prompt “Codex 请求任务放行” (`Tingting` voice) accompany the dialog, at most once every 60 seconds across concurrent hooks.
- `block` and `error` results are still denied without a prompt.

### Scanner

- Findings now carry an `excerpt` of the matched text for agent-directed instructions, exfiltration instructions, invisible Unicode, hidden HTML text, hidden DOCX runs, and PDF scanner findings.
- `summarize()` returns review-level `details` (code, location, excerpt), and pre-tool summaries include the scanned `paths`.
- Matched text is shown only in the local dialog. The deny reason returned to the agent contains finding codes only.
