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
        ignore_func = shutil.ignore_patterns(
            '.git', '.gitignore', '.gitattributes',
            '.obsidian', '.trash', 'private', '*.canvas',
            '*.exe', '*.msi', '*.dll', '*.zip', '*.7z', '*.rar', '*.tar', '*.gz', '*.iso',
            'pen-200.pdf', '*Extra Mile Offensive Cloud Lab*', '*OSCP-OS-*', 'OSCP-eaxm'
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