from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

STATUS_RANK = {"clean": 0, "review": 1, "block": 2, "error": 3}
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_TEXT_CHARS = 2_000_000
MAX_EPUB_UNCOMPRESSED_BYTES = 300 * 1024 * 1024
MAX_EPUB_MEMBER_BYTES = 25 * 1024 * 1024
MAX_EPUB_TEXT_CHARS = 20_000_000
MAX_EPUB_IMAGES = 2000
MAX_AZW3_EXTRACTED_BYTES = 300 * 1024 * 1024
MAX_AZW3_EXTRACTED_FILES = 5000
MAX_PDF_PAGES = 5000
PDF_RENDER_BATCH_SIZE = 25
OCR_BATCH_SIZE = 25
EXFIL_CONTEXT_CHARS = 240

ZERO_WIDTH = {
    "\u00ad",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}
BIDI_CODEPOINTS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
TAG_RANGE = range(0xE0000, 0xE0080)

INSTRUCTION_PATTERNS = [
    re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.IGNORECASE
    ),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|above)", re.IGNORECASE),
    re.compile(r"(?:system\s*prompt|new\s+instructions?\s*:)", re.IGNORECASE),
    re.compile(
        r"(?:if\s+you\s+are|you\s+are\s+now)\s+(?:an?\s+)?(?:ai|assistant|model|llm)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:do\s+not|never)\s+(?:mention|reveal|tell).{0,60}(?:instruction|prompt)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:忽略|无视|忽视|跳过|丢弃).{0,12}(?:之前|以上|前面|先前|所有).{0,12}(?:指令|规则|要求|提示)"
    ),
    re.compile(r"(?:新的?指令|新的?规则|新的?要求)\s*[:：]"),
    re.compile(
        r"如果你是.{0,8}(?:AI|人工智能|语言模型|大模型|机器人|助手)", re.IGNORECASE
    ),
    re.compile(
        r"(?:不要|禁止|不准|不许).{0,8}(?:遵守|遵循|执行).{0,12}(?:之前|以上|原始|原来)"
    ),
]

EXFIL_PATTERNS = [
    re.compile(
        r"(?:send|upload|post|transmit|exfiltrat|copy).{0,100}(?:secret|credential|private|sensitive|token|key|file)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:发送|上传|提交|传输|复制|泄露).{0,60}(?:秘密|凭据|隐私|敏感|令牌|密钥|文件)"
    ),
]

AGENT_TERMS = re.compile(
    r"(?:\bAI\b|LLM|assistant|agent|model|人工智能|智能体|语言模型|大模型|助手)",
    re.IGNORECASE,
)

TARGET_SUFFIXES = {
    ".pdf",
    ".epub",
    ".azw3",
    ".mobi",
    ".docx",
    ".docm",
    ".doc",
    ".xlsx",
    ".xlsm",
    ".xls",
    ".pptx",
    ".pptm",
    ".ppt",
    ".html",
    ".htm",
    ".txt",
    ".md",
    ".rtf",
    ".odt",
    ".ods",
    ".odp",
    ".csv",
    ".tsv",
    ".json",
    ".xml",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".eml",
    ".msg",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".tiff",
    ".tif",
}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    location: str


@dataclass
class ScanResult:
    status: str
    kind: str
    sha256: str | None
    findings: list[Finding]

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if STATUS_RANK[finding.severity] > STATUS_RANK[self.status]:
            self.status = finding.severity

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "kind": self.kind,
            "sha256": self.sha256,
            "findings": [asdict(item) for item in self.findings],
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _new_result(kind: str, sha256: str | None = None) -> ScanResult:
    return ScanResult(status="clean", kind=kind, sha256=sha256, findings=[])


def _has_instruction(text: str) -> bool:
    return any(pattern.search(text) for pattern in INSTRUCTION_PATTERNS)


def _has_exfiltration(text: str) -> bool:
    for pattern in EXFIL_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - EXFIL_CONTEXT_CHARS)
            end = min(len(text), match.end() + EXFIL_CONTEXT_CHARS)
            if AGENT_TERMS.search(text[start:end]):
                return True
    return False


def _scan_unicode(text: str, result: ScanResult, location: str) -> None:
    if any(char in ZERO_WIDTH for char in text):
        result.add(Finding("INVISIBLE_UNICODE", "review", location))
    if any(ord(char) in BIDI_CODEPOINTS for char in text):
        result.add(Finding("BIDI_CONTROL", "block", location))
    if any(ord(char) in TAG_RANGE for char in text):
        result.add(Finding("UNICODE_TAG_PAYLOAD", "block", location))


def _scan_language(text: str, result: ScanResult, location: str) -> None:
    _scan_unicode(text, result, location)
    if _has_exfiltration(text):
        result.add(Finding("AGENT_EXFILTRATION_INSTRUCTION", "block", location))
    elif _has_instruction(text):
        result.add(Finding("AGENT_DIRECTED_INSTRUCTION", "review", location))


def scan_text(text: str, kind: str = "text", location: str = "content") -> ScanResult:
    result = _new_result(kind)
    if len(text) > MAX_TEXT_CHARS:
        result.add(Finding("TEXT_LIMIT_EXCEEDED", "review", location))
        text = text[:MAX_TEXT_CHARS]
    _scan_language(text, result, location)
    return result


class _HTMLScanner(HTMLParser):
    HIDDEN_STYLE = re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|"
        r"font-size\s*:\s*0|left\s*:\s*-\d{3,}|text-indent\s*:\s*-\d{3,}",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.hidden_chunks: list[str] = []
        self.visible_chunks: list[str] = []
        self.attribute_chunks: list[str] = []
        self.comments: list[str] = []
        self.active_content = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        hidden = "hidden" in attributes or bool(
            self.HIDDEN_STYLE.search(attributes.get("style", ""))
        )
        if hidden or self.hidden_depth:
            self.hidden_depth += 1
        if tag.lower() in {"script", "iframe", "object", "embed"}:
            self.active_content = True
        for key in ("alt", "aria-label", "title", "content"):
            if attributes.get(key):
                self.attribute_chunks.append(attributes[key])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, _tag: str) -> None:
        if self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.hidden_depth:
            self.hidden_chunks.append(data)
        else:
            self.visible_chunks.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


def _scan_html(text: str, sha256: str) -> ScanResult:
    result = _new_result("html", sha256)
    parser = _HTMLScanner()
    parser.feed(text)
    hidden = " ".join(parser.hidden_chunks).strip()
    auxiliary = " ".join(parser.attribute_chunks + parser.comments).strip()
    visible = " ".join(parser.visible_chunks).strip()
    if hidden:
        result.add(
            Finding(
                "HIDDEN_HTML_TEXT",
                "block" if _has_instruction(hidden) else "review",
                "hidden DOM",
            )
        )
        _scan_language(hidden, result, "hidden DOM")
    if auxiliary:
        _scan_language(auxiliary, result, "HTML attributes/comments")
    if parser.active_content:
        result.add(Finding("ACTIVE_HTML_CONTENT", "review", "document"))
    _scan_language(visible, result, "visible HTML")
    return result


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_R_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _tag(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}"


def _scan_docx(path: Path, sha256: str) -> ScanResult:
    result = _new_result("docx", sha256)
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if any(name.endswith("vbaProject.bin") for name in names):
                result.add(Finding("OFFICE_MACRO", "block", "package"))
            if any(name.startswith("word/embeddings/") for name in names):
                result.add(Finding("OFFICE_EMBEDDED_OBJECT", "block", "package"))

            for name in sorted(names):
                if not name.endswith(".rels"):
                    continue
                try:
                    root = ET.fromstring(archive.read(name))
                except ET.ParseError:
                    result.add(Finding("OOXML_RELATIONSHIP_PARSE_ERROR", "error", name))
                    continue
                for rel in root.findall(_tag(PKG_R_NS, "Relationship")):
                    if rel.attrib.get("TargetMode") == "External":
                        result.add(
                            Finding("OOXML_EXTERNAL_RELATIONSHIP", "review", name)
                        )

            xml_names = [
                name
                for name in names
                if name == "word/document.xml"
                or name.startswith(("word/header", "word/footer"))
                or name
                in {"word/comments.xml", "word/footnotes.xml", "word/endnotes.xml"}
            ]
            visible_text: list[str] = []
            auxiliary_text: list[str] = []
            for name in xml_names:
                try:
                    root = ET.fromstring(archive.read(name))
                except ET.ParseError:
                    result.add(Finding("OOXML_PARSE_ERROR", "error", name))
                    continue
                for element in root.iter():
                    for attr_name in ("descr", "title", "name"):
                        value = element.attrib.get(attr_name)
                        if value:
                            auxiliary_text.append(value)
                for run in root.iter(_tag(W_NS, "r")):
                    text = "".join(
                        node.text or "" for node in run.iter(_tag(W_NS, "t"))
                    )
                    if not text.strip():
                        continue
                    props = run.find(_tag(W_NS, "rPr"))
                    hidden = False
                    tiny = False
                    pale = False
                    if props is not None:
                        hidden = (
                            props.find(_tag(W_NS, "vanish")) is not None
                            or props.find(_tag(W_NS, "webHidden")) is not None
                        )
                        size = props.find(_tag(W_NS, "sz"))
                        if size is not None:
                            raw_size = size.attrib.get(_tag(W_NS, "val"), "")
                            tiny = raw_size.isdigit() and int(raw_size) <= 6
                        color = props.find(_tag(W_NS, "color"))
                        if color is not None:
                            value = color.attrib.get(_tag(W_NS, "val"), "").upper()
                            pale = value in {"FFFFFF", "FEFEFE", "FDFDFD"}
                    if hidden or tiny or pale:
                        severity = "block" if _has_instruction(text) else "review"
                        result.add(Finding("HIDDEN_DOCX_RUN", severity, name))
                        _scan_language(text, result, name)
                    else:
                        visible_text.append(text)

            _scan_language(" ".join(visible_text), result, "visible DOCX")
            _scan_language(" ".join(auxiliary_text), result, "DOCX alternative text")
    except (OSError, zipfile.BadZipFile):
        result.add(Finding("INVALID_OOXML_PACKAGE", "error", "package"))
    return result


def _merge_result(target: ScanResult, source: ScanResult, prefix: str) -> None:
    for finding in source.findings:
        target.add(
            Finding(
                finding.code,
                finding.severity,
                f"{prefix}: {finding.location}",
            )
        )


def _scan_epub(path: Path, sha256: str) -> ScanResult:
    result = _new_result("epub", sha256)
    text_suffixes = {
        ".xhtml",
        ".html",
        ".htm",
        ".xml",
        ".opf",
        ".ncx",
        ".css",
        ".txt",
        ".md",
        ".json",
        ".smil",
    }
    html_suffixes = {".xhtml", ".html", ".htm"}
    image_suffixes = {".png", ".jpg", ".jpeg", ".webp", ".tiff", ".tif", ".gif"}
    active_suffixes = {
        ".js",
        ".mjs",
        ".wasm",
        ".exe",
        ".dll",
        ".sh",
        ".bat",
        ".command",
    }
    nested_suffixes = {".zip", ".epub", ".rar", ".7z", ".tar", ".gz"}
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = {info.filename for info in infos}
            if "mimetype" not in names:
                result.add(Finding("EPUB_MIMETYPE_MISSING", "review", "package"))
            else:
                try:
                    mimetype = (
                        archive.read("mimetype")
                        .decode("ascii", errors="replace")
                        .strip()
                    )
                except (OSError, KeyError, RuntimeError):
                    result.add(Finding("EPUB_MIMETYPE_READ_ERROR", "error", "mimetype"))
                else:
                    if mimetype != "application/epub+zip":
                        result.add(
                            Finding("EPUB_MIMETYPE_INVALID", "review", "mimetype")
                        )

            total_size = sum(info.file_size for info in infos)
            if total_size > MAX_EPUB_UNCOMPRESSED_BYTES:
                result.add(
                    Finding("EPUB_UNCOMPRESSED_LIMIT_EXCEEDED", "review", "package")
                )
                return result

            text_chars = 0
            image_count = 0
            with tempfile.TemporaryDirectory() as directory:
                image_directory = Path(directory)
                images_to_ocr: list[Path] = []
                for index, info in enumerate(infos):
                    if info.is_dir():
                        continue
                    member = info.filename
                    member_path = PurePosixPath(member.replace("\\", "/"))
                    if member_path.is_absolute() or ".." in member_path.parts:
                        result.add(Finding("EPUB_UNSAFE_PATH", "block", member))
                        continue
                    if info.flag_bits & 0x1:
                        result.add(Finding("EPUB_ENCRYPTED_MEMBER", "block", member))
                        continue
                    if info.file_size > MAX_EPUB_MEMBER_BYTES:
                        result.add(
                            Finding("EPUB_MEMBER_LIMIT_EXCEEDED", "review", member)
                        )
                        continue
                    if (
                        info.compress_size > 0
                        and info.file_size > 1024 * 1024
                        and info.file_size / info.compress_size > 1000
                    ):
                        result.add(
                            Finding("EPUB_SUSPICIOUS_COMPRESSION", "block", member)
                        )
                        continue
                    suffix = member_path.suffix.lower()
                    if suffix in active_suffixes:
                        result.add(Finding("EPUB_ACTIVE_CONTENT", "review", member))
                    if suffix in nested_suffixes:
                        result.add(Finding("EPUB_NESTED_ARCHIVE", "review", member))
                        continue
                    try:
                        data = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        result.add(Finding("EPUB_MEMBER_READ_ERROR", "error", member))
                        continue

                    if suffix in text_suffixes or suffix in active_suffixes:
                        text = data.decode("utf-8", errors="replace")
                        text_chars += len(text)
                        if text_chars > MAX_EPUB_TEXT_CHARS:
                            result.add(
                                Finding("EPUB_TEXT_LIMIT_EXCEEDED", "review", "package")
                            )
                            return result
                        if suffix in html_suffixes:
                            _merge_result(result, _scan_html(text, sha256), member)
                        else:
                            _scan_language(text, result, member)
                    elif suffix == ".svg":
                        text = data.decode("utf-8", errors="replace")
                        text_chars += len(text)
                        _scan_language(text, result, member)
                    elif suffix in image_suffixes:
                        image_count += 1
                        if image_count > MAX_EPUB_IMAGES:
                            result.add(
                                Finding(
                                    "EPUB_IMAGE_LIMIT_EXCEEDED", "review", "package"
                                )
                            )
                            return result
                        output = image_directory / f"image-{index}{suffix}"
                        try:
                            output.write_bytes(data)
                        except OSError:
                            result.add(
                                Finding("EPUB_IMAGE_WRITE_ERROR", "error", member)
                            )
                            continue
                        images_to_ocr.append(output)
                _ocr_images(images_to_ocr, result, "EPUB image OCR")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        result.add(Finding("INVALID_EPUB_PACKAGE", "error", "package"))
    return result


def _scan_azw3(path: Path, sha256: str) -> ScanResult:
    result = _new_result(path.suffix.lower().lstrip("."), sha256)
    unpacker = _find_runtime_command("mobiunpack")
    if not unpacker:
        result.add(Finding("AZW3_UNPACKER_UNAVAILABLE", "review", "environment"))
        return result

    try:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unpacked"
            completed = _run([unpacker, str(path), str(output)], timeout=180)
            if completed.returncode != 0 or not output.is_dir():
                result.add(Finding("AZW3_UNPACK_ERROR", "error", "document"))
                return result

            files = [item for item in output.rglob("*") if item.is_file()]
            if any(item.is_symlink() for item in output.rglob("*")):
                result.add(Finding("AZW3_UNSAFE_LINK", "block", "package"))
                return result
            if len(files) > MAX_AZW3_EXTRACTED_FILES:
                result.add(Finding("AZW3_FILE_LIMIT_EXCEEDED", "review", "package"))
                return result
            if sum(item.stat().st_size for item in files) > MAX_AZW3_EXTRACTED_BYTES:
                result.add(Finding("AZW3_SIZE_LIMIT_EXCEEDED", "review", "package"))
                return result

            payloads = sorted(
                item for item in files if item.suffix.lower() in {".epub", ".pdf"}
            )
            if payloads:
                for payload in payloads:
                    if payload.stat().st_size > MAX_FILE_BYTES:
                        result.add(
                            Finding("AZW3_PAYLOAD_LIMIT_EXCEEDED", "review", "package")
                        )
                        continue
                    if payload.suffix.lower() == ".epub":
                        nested = _scan_epub(payload, sha256)
                    else:
                        nested = _scan_pdf(payload, sha256)
                    _merge_result(result, nested, "AZW3 payload")
                return result

            html_files = sorted(
                item
                for item in files
                if item.suffix.lower() in {".html", ".htm", ".xhtml"}
            )
            if not html_files:
                result.add(Finding("AZW3_PAYLOAD_UNSUPPORTED", "review", "package"))
                return result
            for html_file in html_files:
                text = html_file.read_text(encoding="utf-8", errors="replace")
                _merge_result(result, _scan_html(text, sha256), "AZW3 HTML")
            image_files = [
                item
                for item in files
                if item.suffix.lower()
                in {".png", ".jpg", ".jpeg", ".webp", ".tiff", ".tif", ".gif"}
            ]
            if len(image_files) > MAX_EPUB_IMAGES:
                result.add(Finding("AZW3_IMAGE_LIMIT_EXCEEDED", "review", "package"))
                return result
            _ocr_images(image_files, result, "AZW3 image OCR")
    except (OSError, subprocess.SubprocessError):
        result.add(Finding("AZW3_UNPACK_ERROR", "error", "document"))
    return result


def _extract_json_array(output: str) -> list[dict[str, object]] | None:
    for index in range(len(output) - 1, -1, -1):
        if output[index] != "[":
            continue
        try:
            value = json.loads(output[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return None


def _run(command: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
    )


def _find_runtime_command(name: str) -> str | None:
    command = shutil.which(name)
    if command:
        return command
    candidates = [
        Path(sys.executable).parent / name,
        Path(__file__).resolve().parents[2] / ".venv" / "bin" / name,
    ]
    return next(
        (str(candidate) for candidate in candidates if candidate.is_file()), None
    )


@lru_cache(maxsize=1)
def _ocr_languages(tesseract: str) -> str:
    try:
        completed = _run([tesseract, "--list-langs"], timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "eng"
    available = set(completed.stdout.splitlines())
    selected = [
        language for language in ("eng", "chi_sim", "chi_tra") if language in available
    ]
    return "+".join(selected) or "eng"


def _ocr_image(path: Path, result: ScanResult, location: str) -> bool:
    tesseract = shutil.which("tesseract")
    if not tesseract:
        result.add(Finding("LOCAL_OCR_UNAVAILABLE", "review", "environment"))
        return False
    try:
        completed = _run(
            [tesseract, str(path), "stdout", "-l", _ocr_languages(tesseract)],
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError):
        result.add(Finding("LOCAL_OCR_ERROR", "review", location))
        return False
    if completed.returncode != 0:
        result.add(Finding("LOCAL_OCR_ERROR", "review", location))
        return False
    _scan_language(completed.stdout, result, location)
    return True


def _ocr_images(paths: list[Path], result: ScanResult, location: str) -> bool:
    if not paths:
        return True
    tesseract = shutil.which("tesseract")
    if not tesseract:
        result.add(Finding("LOCAL_OCR_UNAVAILABLE", "review", "environment"))
        return False
    for start in range(0, len(paths), OCR_BATCH_SIZE):
        batch = paths[start : start + OCR_BATCH_SIZE]
        try:
            with tempfile.TemporaryDirectory() as directory:
                listing = Path(directory) / "images.txt"
                listing.write_text(
                    "\n".join(str(path) for path in batch) + "\n",
                    encoding="utf-8",
                )
                completed = _run(
                    [
                        tesseract,
                        str(listing),
                        "stdout",
                        "-l",
                        _ocr_languages(tesseract),
                    ],
                    timeout=max(90, len(batch) * 20),
                )
        except (OSError, subprocess.SubprocessError):
            result.add(Finding("LOCAL_OCR_ERROR", "review", location))
            return False
        if completed.returncode != 0:
            result.add(Finding("LOCAL_OCR_ERROR", "review", location))
            return False
        end = start + len(batch)
        _scan_language(completed.stdout, result, f"{location} {start + 1}-{end}")
    return True


def _merge_pdf_scanner_finding(result: ScanResult, finding: dict[str, object]) -> None:
    severity = str(finding.get("severity", "medium")).lower()
    finding_type = str(finding.get("type", "")).lower()
    page = f"page {finding.get('page', '?')}"
    if severity == "high":
        result.add(Finding("PDF_SCANNER_FINDING", "block", page))
        return
    if "suspicious pattern" in finding_type:
        content = str(finding.get("content", ""))
        local = scan_text(content, kind="pdf-scanner", location=page)
        if local.findings:
            _merge_result(result, local, "PDF scanner")
        elif not content:
            result.add(Finding("PDF_SCANNER_FINDING", "review", page))
        return
    result.add(Finding("PDF_SCANNER_FINDING", "review", page))


def _scan_pdf(path: Path, sha256: str) -> ScanResult:
    result = _new_result("pdf", sha256)
    scanner = _find_runtime_command("pdf-scan")
    if scanner:
        try:
            completed = _run([scanner, str(path), "--json"], timeout=90)
            findings = _extract_json_array(completed.stdout)
            if completed.returncode != 0 or findings is None:
                result.add(Finding("PDF_SCANNER_ERROR", "error", "document"))
            else:
                for finding in findings:
                    _merge_pdf_scanner_finding(result, finding)
        except (OSError, subprocess.SubprocessError):
            result.add(Finding("PDF_SCANNER_ERROR", "error", "document"))
    else:
        result.add(Finding("PDF_SCANNER_UNAVAILABLE", "review", "environment"))

    pdftotext = shutil.which("pdftotext")
    if pdftotext:
        try:
            completed = _run([pdftotext, str(path), "-"], timeout=90)
            if completed.returncode == 0:
                _scan_language(completed.stdout, result, "PDF text layer")
            else:
                result.add(Finding("PDF_TEXT_EXTRACTION_ERROR", "review", "document"))
        except (OSError, subprocess.SubprocessError):
            result.add(Finding("PDF_TEXT_EXTRACTION_ERROR", "review", "document"))

    page_count: int | None = None
    pdfinfo = shutil.which("pdfinfo")
    if pdfinfo:
        try:
            information = _run([pdfinfo, str(path)], timeout=30)
            page_match = re.search(
                r"^Pages:\s*(\d+)\s*$", information.stdout, re.MULTILINE
            )
            if information.returncode == 0 and page_match:
                page_count = int(page_match.group(1))
            metadata = _run([pdfinfo, "-meta", str(path)], timeout=30)
            if metadata.returncode == 0:
                _scan_language(metadata.stdout, result, "PDF metadata")
            javascript = _run([pdfinfo, "-js", str(path)], timeout=30)
            if javascript.returncode == 0 and javascript.stdout.strip():
                result.add(Finding("PDF_JAVASCRIPT", "block", "document"))
                _scan_language(javascript.stdout, result, "PDF JavaScript")
        except (OSError, subprocess.SubprocessError):
            result.add(Finding("PDF_ACTIVE_CONTENT_CHECK_ERROR", "review", "document"))

    pdfdetach = shutil.which("pdfdetach")
    if pdfdetach:
        try:
            completed = _run([pdfdetach, "-list", str(path)])
            match = re.search(
                r"(\d+)\s+embedded files?", completed.stdout, re.IGNORECASE
            )
            if match and int(match.group(1)) > 0:
                result.add(Finding("PDF_EMBEDDED_FILE", "block", "document"))
        except (OSError, subprocess.SubprocessError):
            result.add(Finding("PDF_ATTACHMENT_CHECK_ERROR", "review", "document"))

    renderer = shutil.which("pdftoppm")
    if not renderer:
        result.add(Finding("PDF_RENDERER_UNAVAILABLE", "review", "environment"))
        return result
    if page_count is None:
        result.add(Finding("PDF_PAGE_COUNT_UNAVAILABLE", "review", "environment"))
        return result
    if page_count > MAX_PDF_PAGES:
        result.add(Finding("PDF_PAGE_LIMIT_EXCEEDED", "review", "document"))
        return result
    try:
        with tempfile.TemporaryDirectory() as directory:
            for start in range(1, page_count + 1, PDF_RENDER_BATCH_SIZE):
                end = min(page_count, start + PDF_RENDER_BATCH_SIZE - 1)
                prefix = Path(directory) / f"page-{start}"
                completed = _run(
                    [
                        renderer,
                        "-png",
                        "-r",
                        "150",
                        "-f",
                        str(start),
                        "-l",
                        str(end),
                        str(path),
                        str(prefix),
                    ],
                    timeout=180,
                )
                pages = sorted(Path(directory).glob(f"page-{start}-*.png"))
                if completed.returncode != 0 or len(pages) != end - start + 1:
                    result.add(Finding("PDF_RENDER_ERROR", "review", "document"))
                    return result
                if not _ocr_images(pages, result, f"PDF rendered pages {start}-{end}"):
                    return result
                for page in pages:
                    page.unlink()
    except (OSError, subprocess.SubprocessError):
        result.add(Finding("PDF_RENDER_ERROR", "review", "document"))
    return result


def _scan_image(path: Path, sha256: str) -> ScanResult:
    result = _new_result("image", sha256)
    _ocr_image(path, result, "image OCR")
    result.add(Finding("IMAGE_HIDDEN_CHANNELS_NOT_PROVABLE", "review", "document"))
    return result


def scan_file(path_value: str | os.PathLike[str]) -> ScanResult:
    path = Path(path_value).expanduser()
    try:
        path = path.resolve(strict=True)
    except OSError:
        result = _new_result("file")
        result.add(Finding("FILE_NOT_FOUND", "error", "path"))
        return result
    if not path.is_file():
        result = _new_result("file")
        result.add(Finding("NOT_A_REGULAR_FILE", "error", "path"))
        return result
    if path.stat().st_size > MAX_FILE_BYTES:
        result = _new_result("file", _sha256(path))
        result.add(Finding("FILE_SIZE_LIMIT_EXCEEDED", "review", "document"))
        return result

    sha256 = _sha256(path)
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return _scan_pdf(path, sha256)
    if suffix == ".epub":
        return _scan_epub(path, sha256)
    if suffix in {".azw3", ".mobi"}:
        return _scan_azw3(path, sha256)
    if suffix in {".docx", ".docm"}:
        return _scan_docx(path, sha256)
    if suffix in {".html", ".htm"}:
        try:
            return _scan_html(
                path.read_text(encoding="utf-8", errors="replace"), sha256
            )
        except OSError:
            result = _new_result("html", sha256)
            result.add(Finding("FILE_READ_ERROR", "error", "document"))
            return result
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".tiff", ".tif"}:
        return _scan_image(path, sha256)
    if suffix in {
        ".txt",
        ".md",
        ".csv",
        ".tsv",
        ".json",
        ".xml",
        ".toml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".eml",
    }:
        try:
            result = scan_text(
                path.read_text(encoding="utf-8", errors="replace"), kind=suffix[1:]
            )
            result.sha256 = sha256
            return result
        except OSError:
            result = _new_result(suffix[1:], sha256)
            result.add(Finding("FILE_READ_ERROR", "error", "document"))
            return result

    result = _new_result(suffix[1:] or "unknown", sha256)
    result.add(Finding("UNSUPPORTED_DOCUMENT_FORMAT", "review", "document"))
    return result


def summarize(results: Iterable[ScanResult]) -> dict[str, object]:
    values = list(results)
    status = "clean"
    for value in values:
        if STATUS_RANK[value.status] > STATUS_RANK[status]:
            status = value.status
    codes = sorted({finding.code for value in values for finding in value.findings})
    return {"status": status, "files": len(values), "codes": codes}
