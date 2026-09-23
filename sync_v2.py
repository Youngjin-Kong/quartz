import shutil
import os
import re
import subprocess
import sys

# 경로 설정
SOURCE_VAULT = r"C:\Users\QQ\Documents\Obsidian Vault"
DEST_QUARTZ_CONTENT = r"F:\hack\workstation\quartz\content"
QUARTZ_DIR = r"F:\hack\workstation\quartz"

# 발행본에서 가리는 자격 증명 패턴
AWS_ID_RE = re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')
GH_TOKEN_RE = re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36}\b')
B64_40_RE = re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])')
SECRET_MARKER_RE = re.compile(
    r'secret[_ ]?access[_ ]?key|aws_secret|awskey|SecretAccessKey', re.I)

PLACEHOLDER_AWS_ID = '[REDACTED-AWS-KEY-ID]'
PLACEHOLDER_AWS_SECRET = '[REDACTED-AWS-SECRET]'
PLACEHOLDER_GH_TOKEN = '[REDACTED-GITHUB-PAT]'


def filter_publish_false(content_dir):
    """파일 내용을 검사하여 publish: false가 포함된 md 파일 삭제"""
    deleted_count = 0
    for root, dirs, files in os.walk(content_dir):
        for file in files:
            if file.endswith(".md"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        header = f.read(1000) # YAML 분석을 위해 넉넉히 읽음
                        if 'publish: false' in header or 'publish: "false"' in header:
                            os.remove(file_path)
                            print(f"🚫 Excluded by Frontmatter: {file}")
                            deleted_count += 1
                except Exception as e:
                    print(f"⚠️ Error reading {file}: {e}")
    return deleted_count


def _collect_aws_secrets(lines):
    """마커가 같은 줄이나 직전 줄에 있는 40자 토큰만 시크릿으로 인정"""
    found = set()
    for i, line in enumerate(lines):
        window = line if i == 0 else lines[i - 1] + line
        if SECRET_MARKER_RE.search(window):
            found.update(B64_40_RE.findall(line))
    return found


def redact_secrets(content_dir):
    """볼트 원본은 그대로 두고 발행본 사본에서만 자격 증명을 가린다"""
    targets = []
    for root, dirs, files in os.walk(content_dir):
        for file in files:
            if file.lower().endswith(('.md', '.html')):
                targets.append(os.path.join(root, file))

    # 1차 — 트리 전체에서 시크릿 키 수집 (한 파일에서 찾은 값을 다른 파일에서도 가리기 위함)
    aws_secrets = set()
    for path in targets:
        try:
            with open(path, 'r', encoding='utf-8', newline='') as f:
                aws_secrets |= _collect_aws_secrets(f.read().splitlines())
        except Exception:
            continue

    # 2차 — 치환
    redacted = 0
    for path in targets:
        try:
            with open(path, 'r', encoding='utf-8', newline='') as f:
                text = f.read()
        except Exception:
            continue
        new_text = AWS_ID_RE.sub(PLACEHOLDER_AWS_ID, text)
        new_text = GH_TOKEN_RE.sub(PLACEHOLDER_GH_TOKEN, new_text)
        for secret in aws_secrets:
            new_text = new_text.replace(secret, PLACEHOLDER_AWS_SECRET)
        if new_text != text:
            with open(path, 'w', encoding='utf-8', newline='') as f:
                f.write(new_text)
            redacted += 1
    return redacted


def sync_and_deploy():
    try:
        # 1. 로컬 파일 동기화
        if os.path.exists(DEST_QUARTZ_CONTENT):
            shutil.rmtree(DEST_QUARTZ_CONTENT)

        # 고정 제외 패턴
        ignore_func = shutil.ignore_patterns(
            '.obsidian', '.trash', 'private', '*.canvas',
            'pen-200.pdf', '*Extra Mile Offensive Cloud Lab*', '*OSCP-OS-*', 'OSCP-eaxm','storage',
            '무제','PEN-200','_backup','_AUDIT','_HANDOFF','_STATUS','_PLAYBOOK','CLAUDE'
        )
        shutil.copytree(SOURCE_VAULT, DEST_QUARTZ_CONTENT, ignore=ignore_func)

        # Frontmatter 기반 추가 필터링
        filter_publish_false(DEST_QUARTZ_CONTENT)
        print("✅ 1. Local Sync & Filtering Complete")

        # 1-b. 자격 증명 마스킹 (GitHub Push Protection 대응)
        redacted = redact_secrets(DEST_QUARTZ_CONTENT)
        print(f"🔒 1-b. Credentials redacted in {redacted} file(s)")

        # 2. Quartz Sync 실행
        print("🚀 2. Running Quartz Sync...")
        subprocess.run(["npx", "quartz", "sync"], cwd=QUARTZ_DIR, shell=True, check=True)

        # 3. Git Push (Force 제거)
        print("🛠️ 3. Pushing to GitHub (Standard Push)...")

        # 단순 Push 시도. 보안 정책 위반 시 여기서 CalledProcessError 발생
        result = subprocess.run(["git", "push", "origin", "v4"],
                                cwd=QUARTZ_DIR,
                                shell=True,
                                capture_output=True,
                                text=True,
                                encoding='utf-8')

        if result.returncode != 0:
            print("\n❌ Git Push Rejected!")
            print("==================================================")
            print(result.stderr) # GitHub의 Secret Scanning 경고 메시지 출력
            print("==================================================")
            print("💡 치명적인 내용(Secret)이 감지되었거나 히스토리 충돌이 있습니다.")
            print("💡 위 로그의 링크를 확인하여 조치 후 다시 시도하세요.")
            sys.exit(1)

        print("✨ All process finished successfully!")

    except subprocess.CalledProcessError as e:
        print(f"\n❌ 명령 실행 중 오류 발생: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 예상치 못한 오류: {e}")
        sys.exit(1)


if __name__ == "__main__":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    sync_and_deploy()
