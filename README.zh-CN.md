# Agent Content Firewall

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md)

AI 智能体的本地安全防火墙，拦截恶意内容，防范智能体被操控。

## 检查范围

- 通过 `pdf-injection-scanner` 检查 PDF 文字颜色和字号
- 通过 Poppler 和 Tesseract 完成 PDF 渲染与本地 OCR
- 检查 PDF 元数据、JavaScript 和嵌入附件
- 检查 EPUB 容器、大批量图片及其本地 OCR 结果
- 通过隔离的 KindleUnpack 解包链检查未加密的 AZW3 和 MOBI 文件
- 检查 DOCX 隐藏文字、宏、嵌入对象、替代文本和外部关系
- 检查 HTML 隐藏内容、批注、属性、活动元素和屏幕外样式
- 检查零宽字符、双向控制字符和 Unicode 标签字符
- 检查英文、中文的智能体定向指令或数据外传指令
- 在 MCP 及其他工具结果返回智能体之前进行检查
- 检查访问凭据路径、收集环境信息、通过管道上传数据或执行下载代码的 Shell 命令

检查结果分为 `clean`、`review`、`block` 和 `error`。默认情况下，除 `clean` 以外的结果都会停止相应 Hook 操作，等待进一步核对；Codex 的 `review` 结果按下述方式处理。

### Codex 待判断结果弹窗（macOS）

Codex 调用工具前的检查结果按以下方式处理：

- `block` 和 `error` 直接拒绝。
- 不含具体发现的 `review` 结果直接放行，不弹窗。包括每张图片都会带上的 `IMAGE_HIDDEN_CHANNELS_NOT_PROVABLE`，以及 `UNSUPPORTED_DOCUMENT_FORMAT`。
- 其他 `review` 结果会在本机弹出 macOS 对话框，列明文件、每项发现的中文说明和命中原文。只有点击“放行一次”才继续执行；点击“拒绝”、120 秒内未选择或弹窗失败均按拒绝处理。Codex 的 PreToolUse Hook 不接受 `permissionDecision: "ask"`，因此由 Hook 直接询问用户。
- 弹窗时播放提示音，并用 `Tingting` 语音播报“Codex 请求任务放行”，60 秒内最多播报一次。

命中原文只显示在本机弹窗中，返回给智能体的拒绝理由只包含提示码。

## 本地设置

环境要求：

- Python 3.10 或更高版本
- [`uv`](https://docs.astral.sh/uv/)
- Poppler 命令：`pdfinfo`、`pdftotext`、`pdftoppm`、`pdfdetach`
- 已安装所需语言数据的 Tesseract

创建隔离运行环境：

```bash
python3 scripts/bootstrap.py
```

直接扫描文件：

```bash
agent-content-firewall file document.pdf
```

## 安装到 Codex

macOS 用户下载或克隆仓库后，可以双击 `install-codex.command`。安装器会先显示目标路径，并在应用变更前请求确认。

克隆仓库后，也可以使用一条命令完成非交互安装：

```bash
./install-codex.command --yes
```

先预览本地变更：

```bash
python3 scripts/install_codex.py
```

仅安装 Codex Hooks 和用户 Skill：

```bash
python3 scripts/install_codex.py --apply
```

安装器会保留已有 Hook 分组，建立一次 Hook 配置备份，并安装到用户本地数据目录。它不会修改 Claude Code、Pi 或 OpenCode。安装后请完全退出并重新启动 Codex，在新任务中检查已加载的 Hooks。

仓库的 `adapters/` 目录还包含 Claude Code、Pi、OpenCode、DeepSeek Harness 和腾讯 WorkBuddy 的可选适配器。启用方式及拦截边界详见 `skills/agent-content-firewall/references/integration.md`。

## 安全边界

本项目是一道预警防线，并不构成内容绝对安全的证明。聊天内直接附件、客户端原生文件引用、托管工具、隐写信息、解析器缺陷和未支持格式可能超出 Hook 的覆盖范围。应继续采用最小权限，并对上传、外部写入、删除、凭据访问和持久化配置变更设置确认环节。

第三方模型或 API 中转站可以在响应到达智能体之前篡改回复和工具调用。不要将不可信中转站与完全访问权限或无人值守执行结合使用。Shell 命令检查只是纵深防护，不能替代可信模型端点、沙箱、操作确认和受限网络访问。

本项目不会启动后台服务，也不会启用远程语义分类器。扫描器支持 EPUB、未加密的 AZW3/MOBI、常见项目配置、PDF、DOCX、HTML、文本和图片预检。格式依赖均锁定在 `uv.lock` 中，许可证详见[第三方组件说明](THIRD_PARTY_NOTICES.md)。

## 开发与验证

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
uvx ruff check src adapters scripts tests
```

公开发布前运行本地隐私门禁：

```bash
python3 scripts/privacy_audit.py
git log --all --format='%h %an <%ae> %cn <%ce>'
```

需要排除个人姓名、昵称或邮箱片段时，可以加入本地禁用词：

```bash
python3 scripts/privacy_audit.py --deny-term "personal-name" --deny-term "email-fragment"
```

该门禁会检查已跟踪文件及其名称、全部可达 Git 补丁、作者和提交者身份、用户目录路径、临时附件名称、私钥标记及常见令牌格式。提交作者和提交者必须与项目批准的 `TeshengLee` GitHub 隐私邮箱身份完全一致。GitHub 自带的密钥扫描应继续作为推送后的第二道检查。

本项目采用 MIT License。
