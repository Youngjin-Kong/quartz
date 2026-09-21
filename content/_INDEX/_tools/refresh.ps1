# 머신 노트를 추가한 뒤 이 스크립트를 실행하면 태그와 색인이 다시 계산된다.
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
Write-Host "[1/3] 메타데이터 추출" -ForegroundColor Cyan
python extract.py
Write-Host "[2/3] 프론트매터 갱신" -ForegroundColor Cyan
python inject.py --refresh --apply
Write-Host "[3/3] 색인 재생성" -ForegroundColor Cyan
python build_index.py
Pop-Location
Write-Host "완료. Obsidian에서 Ctrl+R 로 새로고침." -ForegroundColor Green
