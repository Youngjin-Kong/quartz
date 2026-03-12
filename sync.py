import shutil
import os
import subprocess
import sys

# 경로 설정
SOURCE_VAULT = r"C:\Users\QQ\Documents\Obsidian Vault"
DEST_QUARTZ_CONTENT = r"F:\hack\workstation\quartz\content"
QUARTZ_DIR = r"F:\hack\workstation\quartz"

def sync_and_deploy():
    try:
        # 1. 파일 동기화 (기존 content 삭제 후 복사)
        if os.path.exists(DEST_QUARTZ_CONTENT):
            shutil.rmtree(DEST_QUARTZ_CONTENT)
        
        # 제외 패턴: 대용량 PDF 및 시크릿 포함 파일 확실히 제거
        ignore_func = shutil.ignore_patterns(
            '.obsidian', '.trash', 'private', '*.canvas',
            'pen-200.pdf', 
            '29. Extra Mile Offensive Cloud Lab 01.md', 
            '30. Extra Mile Offensive Cloud Lab 02.md',
            '31. Extra Mile Offensive Cloud Lab 03.md'
        )
        
        shutil.copytree(SOURCE_VAULT, DEST_QUARTZ_CONTENT, ignore=ignore_func)
        print("✅ 1. Local Sync Complete (Sensitive files excluded)")

        # 2. Quartz Sync 실행
        print("🚀 2. Starting Quartz Deploy...")
        # shell=True를 사용해 Windows의 npx를 정상 호출하고, 에러 시 Exception을 발생시킴
        subprocess.run(["npx", "quartz", "sync"], cwd=QUARTZ_DIR, shell=True, check=True)
        
        print("✨ All process finished successfully!")

    except subprocess.CalledProcessError as e:
        print(f"\n❌ Git Push Rejected: 보안 정책 위반이나 네트워크 오류가 발생했습니다.")
        sys.exit(1) # 에러 시 스크립트 비정상 종료 알림
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    sync_and_deploy()