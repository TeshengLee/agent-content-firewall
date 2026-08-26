# Agent Content Firewall

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md)

Agent Content Firewall은 AI 에이전트를 위한 로컬 보안 방화벽입니다. 악성 콘텐츠를 차단하고 에이전트가 조작되는 것을 방지합니다.

## 검사 범위

- `pdf-injection-scanner`를 이용한 PDF 텍스트 색상 및 글꼴 크기 검사
- Poppler와 Tesseract를 이용한 PDF 렌더링 및 로컬 OCR
- PDF 메타데이터, JavaScript 및 내장 첨부 파일
- DOCX 숨김 텍스트, 매크로, 내장 개체, 대체 텍스트 및 외부 관계
- HTML 숨김 요소, 주석, 속성, 활성 요소 및 화면 밖 스타일
- 제로 폭 문자, 양방향 제어 문자 및 Unicode 태그 문자
- 영어와 중국어로 작성된 에이전트 대상 지시 및 데이터 전송 지시
- MCP 및 기타 도구 결과가 에이전트로 반환되기 전 검사
- 자격 증명 경로 접근, 환경 정보 수집, 파이프 데이터 업로드 또는 다운로드한 코드 실행을 시도하는 셸 명령

결과는 `clean`, `review`, `block`, `error` 중 하나입니다. 기본적으로 `clean` 이외의 결과가 나오면 Hook 작업을 중단하고 추가 검토를 요청합니다.

## 로컬 설정

필수 환경:

- Python 3.10 이상
- [`uv`](https://docs.astral.sh/uv/)
- Poppler 명령: `pdfinfo`, `pdftotext`, `pdftoppm`, `pdfdetach`
- 필요한 언어 데이터가 설치된 Tesseract

격리된 실행 환경을 생성합니다:

```bash
python3 scripts/bootstrap.py
```

파일을 직접 검사합니다:

```bash
agent-content-firewall file document.pdf
```

## Codex 설치

macOS에서는 저장소를 다운로드하거나 복제한 뒤 `install-codex.command`를 더블 클릭할 수 있습니다. 설치 프로그램은 대상 경로를 먼저 보여 주고 변경 사항을 적용하기 전에 확인을 요청합니다.

복제 후 비대화형 방식으로 설치하려면 다음 한 줄 명령을 실행합니다:

```bash
./install-codex.command --yes
```

로컬 변경 사항을 미리 확인합니다:

```bash
python3 scripts/install_codex.py
```

Codex Hooks와 사용자 Skill만 설치합니다:

```bash
python3 scripts/install_codex.py --apply
```

설치 프로그램은 기존 Hook 그룹을 유지하고 Hook 설정 백업을 한 번 생성한 뒤 사용자 로컬 데이터 디렉터리에 설치합니다. Claude Code, Pi 또는 OpenCode 설정은 변경하지 않습니다. 설치 후 Codex를 완전히 종료하고 다시 시작한 다음 새 작업에서 Hooks를 확인하세요.

`adapters/` 디렉터리에는 Claude Code, Pi, OpenCode, DeepSeek Harness, Tencent WorkBuddy용 선택적 어댑터도 포함되어 있습니다. 활성화 방법과 제한 사항은 `skills/agent-content-firewall/references/integration.md`를 참고하세요.

## 보안 경계

이 프로젝트는 조기 경고 장치이며 콘텐츠의 완전한 안전성을 증명하지는 않습니다. 채팅에 직접 추가된 첨부 파일, 클라이언트 고유 파일 참조, 호스팅 도구, 스테가노그래피, 파서 결함 및 미지원 형식은 Hook 적용 범위를 벗어날 수 있습니다. 최소 권한을 유지하고 업로드, 외부 쓰기, 삭제, 자격 증명 접근 및 영구 설정 변경에는 확인 절차를 두세요.

제3자 모델 또는 API 릴레이는 응답이 에이전트에 도달하기 전에 답변과 도구 호출을 변조할 수 있습니다. 신뢰할 수 없는 릴레이를 전체 접근 권한이나 무인 실행과 함께 사용하지 마세요. 셸 명령 검사는 심층 방어의 일부일 뿐이며 신뢰할 수 있는 모델 엔드포인트, 샌드박스, 승인 및 제한된 네트워크 접근을 대체하지 않습니다.

백그라운드 서비스나 원격 의미 분류기는 사용하지 않습니다. PDF 파서 의존성은 `uv.lock`에 고정되어 있으며 오픈 소스 [`pdf-injection-scanner`](https://github.com/Andy8647/pdf-injection-scanner)를 사용합니다.

## 개발 및 검증

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
uvx ruff check src adapters scripts tests
```

공개 배포 전에 로컬 개인정보 검사를 실행합니다:

```bash
python3 scripts/privacy_audit.py
git log --all --format='%h %an <%ae> %cn <%ce>'
```

개인 이름, 별칭 또는 이메일 일부를 제외 대상에 추가할 수 있습니다:

```bash
python3 scripts/privacy_audit.py --deny-term "personal-name" --deny-term "email-fragment"
```

이 검사는 추적 중인 파일 이름과 내용, 접근 가능한 모든 Git 패치, 작성자와 커미터 신원, 사용자 디렉터리 경로, 임시 첨부 파일 이름, 개인 키 표식 및 일반적인 토큰 형식을 확인합니다. 커밋 작성자와 커미터는 프로젝트에서 승인한 `TeshengLee` GitHub noreply 신원과 정확히 일치해야 합니다. GitHub의 비밀 스캔도 푸시 이후의 추가 점검으로 유지하세요.

이 프로젝트는 MIT License로 제공됩니다.
