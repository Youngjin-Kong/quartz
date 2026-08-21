import shutil
import os
import stat
import subprocess
import sys

# 경로 설정
SOURCE_VAULT = r"C:\Users\QQ\Documents\Obsidian Vault"
DEST_QUARTZ_CONTENT = r"F:\hack\workstation\quartz\content"
QUARTZ_DIR = r"F:\hack\workstation\quartz"

def _force_remove(func, path, exc_info):
    """읽기 전용 파일 때문에 삭제가 막히면 쓰기 권한을 주고 재시도한다.

    git 객체 파일(.git/objects/**)은 설계상 0444로 만들어진다. Windows 에서는
    읽기 전용 속성이 삭제를 막아 shutil.rmtree 가 WinError 5 로 죽는다.
    """
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    else:
        raise


def rmtree_force(path):
    """Python 3.12 부터 onerror 가 deprecated 라 onexc 를 먼저 시도한다."""
    try:
        shutil.rmtree(path, onexc=lambda f, p, e: _force_remove(f, p, e))
    except TypeError:
        shutil.rmtree(path, onerror=_force_remove)


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

def sync_and_deploy():
    try:
        # 1. 로컬 파일 동기화
        if os.path.exists(DEST_QUARTZ_CONTENT):
            rmtree_force(DEST_QUARTZ_CONTENT)

        # 고정 제외 패턴
        #   .git  — 볼트가 git 저장소가 된 뒤부터 필요하다. 이걸 복사하면
        #           (1) 볼트 전체 커밋 이력이 발행물에 섞이고
        #           (2) 읽기 전용 객체 파일 때문에 다음 실행의 rmtree 가 죽는다
        #   실행파일·압축 — 웹에 올릴 이유가 없고 용량만 차지한다.
        #                   노트가 참조하는 이미지는 그대로 복사된다.
        #
        #   내부 운영 문서 — 2026-08-21 추가. 발행 사이트에서 실제로 열려 있었다:
        #     CLAUDE.md 가 /quartz/CLAUDE 에서 16,526자로 렌더됐고 그 안에 Kali 접속
        #     주소·VPN 주소·에이전트 파이프라인 구조가 그대로 들어 있었다.
        #     여기서 막는 것이 quartz.config.ts 의 ignorePatterns 보다 상위 조치다 —
        #     ignorePatterns 는 «렌더»만 막고 원본 .md 는 공개 저장소에 커밋된다.
        #   ⚠️ 이 목록은 볼트의 «작업용» 산출물을 겨눈다. 노트 본체가 아니다.
        ignore_func = shutil.ignore_patterns(
            '.git', '.gitignore', '.gitattributes',
            '.obsidian', '.trash', 'private', '*.canvas',
            '*.exe', '*.msi', '*.dll', '*.zip', '*.7z', '*.rar', '*.tar', '*.gz', '*.iso',
            'pen-200.pdf', '*Extra Mile Offensive Cloud Lab*', '*OSCP-OS-*', 'OSCP-eaxm','*_WRITEUP-STANDARD*',
            # 에이전트 지시·설정 — 훅 스크립트와 서브에이전트 정의가 통째로 들어간다
            '.claude', 'CLAUDE.md',
            # 적대적 검증 산출물 — 「무엇이 틀렸었는지」를 독자가 먼저 보게 된다
            '_AUDIT',
            # 노트 개작 백업 — 같은 글의 옛 판본이 중복 발행된다
            '_backup', '*.bak', '*.bak[0-9]', '*.bak[0-9][0-9]',
            # 색인 파이프라인 소스와 중간 산출물 — 노트가 아니다
            '_tools',
            # 내부 인수인계·진행 관리 문서
            '_HANDOFF.md', '_STATUS.md',
            # 빈 디렉터리·임시 노트
            'storage', '무제',
        )
        shutil.copytree(SOURCE_VAULT, DEST_QUARTZ_CONTENT, ignore=ignore_func)
        
        # Frontmatter 기반 추가 필터링
        filter_publish_false(DEST_QUARTZ_CONTENT)
        print("✅ 1. Local Sync & Filtering Complete")

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