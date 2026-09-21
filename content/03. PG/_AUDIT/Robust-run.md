# Robust — 러너 실행 로그

타겟 `192.168.248.200` · Windows (10.0.19042 / Win10 20H2) · Fundamental · 플래그 2/2 확보 · 2026-08-21

## 타임라인 (Kali mtime 기준, KST)

| 시각 | 단계 | 산출물 |
|---|---|---|
| 13:16 | recon.sh — top-1000·전체·UDP·gobuster·스크린샷 (즉시구간 40s) | `_SUMMARY.txt` `nmap-quick.txt` |
| 13:17 | 403 게이트 확인 + XFF 후보 12종 배치 | `xff/*.body` |
| 13:17 | `X-Forwarded-For: 10.10.10.1` 만 통과 | `xff/X-Forwarded-For.body` |
| 13:18 | 엔드포인트 배치 프로빙 → home.php(302+3030B) 발견 | `probe2/*.body` |
| 13:18 | login.php SQLi 배치 — 전부 무반응(미끼) | `sqli/*.body` |
| 13:18 | home.php 컬럼 수 판별 → 4 | `union/c*.body` |
| 13:19 | 엔진 지문 배치 → SQLite | `fp/f*.body` |
| 13:19 | employees 덤프 → Jeff:Mathsisfun123 | `union/creds.body` |
| 13:19 | SSH jeff → user flag | `proof_user.txt` `pty_jeff.txt` |
| 13:21 | harvest.ps1 업로드·실행 + Sticky Notes DB 다운 | `harvest.txt` `sticky/plum.sqlite` |
| 13:21 | plum.sqlite → Administrator:MySupersecurePassword2112 | `sticky/` |
| 13:21 | SSH Administrator → root flag | `proof_root.txt` `pty_admin.txt` |
| 13:22 | 스크린샷 4장 렌더·이관 | `shot_80_*.png` |
| 13:22-25 | 정리(업로드 삭제·tmux 종료·NFS 확인) | `cleanup.txt` |

## 경로

1. **403 IP 게이트** `login.php` — "Only 10.10.10.x is allowed"
2. **XFF 우회** — `X-Forwarded-For: 10.10.10.1` (12종 중 유일)
3. **home.php** — 302 리다이렉트 뒤에도 본문 전량 렌더(인증 우회). 검색 파라미터가 주입점
4. **SQLite UNION SQLi** — 4컬럼, 출력 2·3번, `sqlite_master` → `employees.password`
5. **크리덴셜 재사용** — 앱 로그인 실패, OS SSH 성공 (jeff)
6. **Sticky Notes** `plum.sqlite` `Note` 테이블 평문 → Administrator

## 플래그

- user `c73e61a25344e60d7e3d9fab6711200a` — `C:\Users\jeff\Desktop\local.txt`
- root `d2cdab936a61a5e7a0abd203cd8f4670` — `C:\Users\Administrator\Desktop\proof.txt`

## 도구 판정 (총괄 관심 항목)

- **recon.sh** — Windows 첫 투입, 정상 동작. top-1000·전체·UDP·gobuster·403 스크린샷·엔드포인트 프로빙 전부 회수. gobuster 는 302 와일드카드로 초기 무효(`-b 302,404` 재실행으로 해결) — 이건 도구 결함 아니라 대상의 전역 302 특성.
- **harvest.ps1** — 그대로 사용 가능(SCP 업로드+`-ep bypass -f` 실행). 다만 jeff 계정 권한이 낮아 systeminfo/서비스/스케줄드태스크 섹션이 **접근거부로 공란**. 스크립트 결함 아님(별도 진단 `harvest-gap-check.txt` 로 CIM 접근거부·systeminfo Access denied 실측 확인). 고치지 않음.

## 정리 증거

- 타겟 업로드 `h.ps1`·`harvest.txt`·`rbchk.ps1` 삭제 확인(dir 무출력)
- 계정/설정 변경 없음, plum.sqlite* 읽기만
- Kali 리스너 없음(SSH 경로), tmux 세션 전부 이름 종료, NFS 없음
- 산출물 전량 보존(0바이트 실패 응답 포함) — 총 161 파일
