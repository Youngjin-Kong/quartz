# Wheels.md — 적대적 검증 감사기록 (2026-08-21)

대상: `03. PG/Wheels.md` (감사 시점 untracked 신규 노트, git baseline 없음 → 개작전 커밋 대조 불가, 그 사실 자체를 보고).
백업: `03. PG/_backup/Wheels.md.bak-audit-20260821`.
소요 시간: 약 25분.

## 감사 초점 결과

### ① 터미널 블록 10개 — 전부 실측 일치, 날조 0
| 블록 | 노트 위치 | 대조 산출물 | 판정 |
|---|---|---|---|
| nmap | 36-41 | `nmap.log` | 축약본이나 값 정확(22 OpenSSH 8.2p1 / 80 Apache 2.4.41 / title). ✓ |
| gobuster | 49-52 | `gobuster_root.txt`·`Wheels-run.md` | 정확한 요약. ✓ |
| portal.php 소스 | 69-74 | `websrc_and_cleanup.txt`(bob 가 `sed -n 55,80p` 로 실제 읽음) | **faithful**. `//work[...]/employee` 가 실제 소스와 정확히 일치. ✓ |
| works.xml | 81-83 | `works_xml.txt` | 한 줄 압축이나 구조·bob 평문 일치. ✓ |
| 덤프 GET | 92-93 | 소스 쿼리 결합 검산 | ✓ |
| blind 페이로드 | 98-99 | `dump2.py`(`*[3]`=password, `zzz') or ... or ('1'='2`) | 스크립트와 정확 일치. ✓ |
| ssh id/cat local | 106-112 | `harvest_bob.txt`(WHOAMI)·`proof_user.txt` | uid/hostname/flag 일치, 원위치 cat. ✓ |
| ls -l /opt/get-list | 120-123 | `harvest_bob.txt`(SUID+SGID 양쪽 등재→`-rwsr-sr-x`), Kali copy 16808B, `finish.sh` 가 라이브로 `ls -l` 실행 | 저장파일에 날짜 원문은 없으나 both-s-bit·크기·빌드시기(2022) 전부 정합. 재구성이되 반증 안 됨. |
| objdump 필터 | 127-133 | `get-list` 재디스어셈블 | **strchr 0x3b/0x7c/0x26(=;\|&), strstr customers/employees, snprintf "/bin/cat /root/details/%s", geteuid→setuid→system** 순서까지 정확. ✓ |
| 익스플로잇(bash -p) | 142-151 | `pwn.sh`·`finish.sh`·`proof_root.txt`·`websrc_and_cleanup.txt`(bash 1183448 Apr18) | `employees$(chmod +s /bin/bash)`, euid=0, flag 전부 일치. line143 `...` 는 정직한 생략. ✓ |

- **Kali `┌──(kali㉿kali)` 프롬프트 날조 0건** (`grep -c` = 0). 타겟 `bob@wheels:~$`·`bash-5.0#` 는 실측이라 유지.

### ② 플래그 출처 — 실측·대화형 확인
- user `dad9316...` = `proof_user.txt`(hostname wheels, uid=1000(bob), `/home/bob/local.txt` 33B, 원위치 cat, UTC 07:11). ✓
- root `f7769b...` = `proof_root.txt`(`uid=1000(bob) ... euid=0(root)`, `/root/proof.txt` 33B, UTC 07:15). ✓
- 웹셸 아님(sshpass ssh + bash -p). 총괄 통과 처리 유지.

## 정정한 것 (5건)
| 위치 | 무엇이 틀렸나 | 근거 | 조치 |
|---|---|---|---|
| 4장 "경로 대안"(옛 157행) | `/tmp` 를 `nosuid` 로 단정 | `harvest_bob.txt` 마운트: `/dev/sda2 on / ext4 rw,relatime`, 별도 `/tmp` 마운트 없음 → `/tmp` 는 nosuid 아님. nosuid 는 `/dev/shm` 뿐 | 정정: `/dev/shm`=nosuid, `/tmp`=ext4 루트(가능했지만 in-place 가 더 깔끔해 선택) |
| 「남긴 흔적」 정리확인(옛 200행) | 同 `/tmp·/dev/shm nosuid` 반복 | 同上 | 정정: 임시 SUID 미생성, `/dev/shm` nosuid·`/tmp` 미사용으로 서술 |
| 3장 SSH(옛 114행) | `bob may not run sudo` 를 인용 literal 로 제시 | `harvest_bob.txt` SUDO 섹션엔 `sudo -n` "a password is required" 만. 해당 문장 미관측 | 관측된 사실(`sudo -n` 비번요구, groups=bob 뿐)로 교체, sudo 불가는 `[가정]` |
| 「남긴 흔적」 되돌리지못함(옛 201행) | 문구 정합 | `traces_confirmed.log` | 총괄 확정 문구 "다음 인스턴스에서 소멸"로 정리 |
| 프론트매터 tags | xpathi 누락 | 총괄 지시(XPath injection 이 본 취약점) | `tech/web/xpathi` 추가(auth·cmd 유지) |

- 상단에 `[!warning] 적대적 검증 정정 이력` 콜아웃 신설.
- **삭제 0건.** 전부 정정/강등. 터미널 실측 블록 무손상.

## 진입점 3스레드 + root 경로 — 재현성
1. **이메일 도메인 게이트**: 노트 2장에 재현 가능하게 담김. 비-service 계정→`Access Denied` 23B(`portal.html`), `@wheels.service`→성공(`dump2.py`/`xpath.py` 가 등록 후 검색 성공). 양쪽 증거로 인과 성립.
2. **XPath injection**: 소스(`//work[contains(service,'$work')]/employee`, 단일따옴표)·덤프·blind 오라클 모두 `dump2.py` 와 정합. 재현 가능.
3. **bcrypt 벽 반증(우회 불필요)**: `works.xml` 평문(`bob:Iamrockinginmyroom1212`)이 DB bcrypt 와 별개 저장소. 6장에 "자동도구 오탐 `.serv`"·"0.4s=bcrypt 신호 늦게 읽음" 재료 모두 존재(`writeup_notes.txt` 의 ~0.4s 확인).
- **root**: `/opt/get-list` 명령주입 → `$()` 우회 → `chmod +s /bin/bash`. 바이너리 재분석으로 필터·포맷·setuid 체인 전부 검증. 재현 가능.
- **미시도 대체경로**: XPath 로 나머지 5명 평문(`works_xml.txt` 에 alice/john/dan/alex/selene 전부 존재)은 "미추출"로 정직히 남음(web-entry.md). 노트도 6명 덤프만 언급, 과장 없음.

## 내가 다시 반증한 것 (지적으로 올렸다가 철회)
1. **"portal.php 소스 블록이 날조 아닌가"** — 노트가 "소스(bob 로 확보)"라 표기. 의심했으나 `collect.sh` 의 `sed -n 55,80p /var/www/html/portal.php` 출력이 `websrc_and_cleanup.txt` 에 그대로 있어 **faithful 확정**. 오히려 web-entry.md 의 `//user` 가 부정확했고 노트의 `//work` 가 맞음.
2. **"get-list ls -l 날짜(May 11 2022)가 저장파일에 없다"** — 부재로 날조 판정하려다 철회. SUID+SGID 양쪽 등재(both-s-bit)·크기 16808·`finish.sh` 라이브 실행·타 파일 2022 빌드시기와 정합. 부재≠날조.

## 근거 출처
- Kali `~/PG/Wheels/`: `nmap.log`·`proof_user.txt`·`proof_root.txt`·`works_xml.txt`·`harvest_bob.txt`·`websrc_and_cleanup.txt`·`pwn.sh`·`finish.sh`·`collect.sh`·`xml.sh`·`dump2.py`·`xpath.py`·`gobuster_root.txt`·`traces_confirmed.log`·`writeup_notes.txt`·`portal.html`·`cj.txt`
- 직접 실행: `objdump -d get-list`(strchr 즉값 0x3b/0x7c/0x26 확인), `strings get-list`
- git: Wheels.md untracked(baseline 없음). 볼트 `파일보관\` Wheels 스크린샷 없음. `~/.zsh_history` 무관(SSH 세션 내 명령 미기록 — 부재는 정상)
