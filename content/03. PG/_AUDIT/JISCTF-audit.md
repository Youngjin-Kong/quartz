---
type: audit
target: "[[JISCTF]]"
date: 2026-09-09
---

# JISCTF — 적대적 검증 감사 기록

대상 `03. PG\JISCTF.md` · 465행 → 505행. 박스 정지 상태라 재접속 없이 산출물만으로 검증.

## 근거 출처

| 출처 | 무엇을 확인했나 |
|---|---|
| Kali `~/PG/JISCTF/` 전량 | nmap 4종·`gobuster-80.txt`·`.bg-gobuster.sh`·`robots/*.body` 14개·`web-80/*`·`creds_and_src.txt`·`find_technawi.txt`·`cj.txt`·`shell443.log`·`harvest_wwwdata.txt`(990행)·`harvest_root.txt`(1059행)·`proof_user.txt`·`proof_root.txt`·`up_sh.*.body`·`sh.*`·`writeup_notes.txt`·`recon-preflight.txt`·`svc/*` |
| 볼트 `파일보관\PG-JISCTF-*.png` 6장 | 6장 전부 직접 열어 캡션과 대조 |
| 파일 mtime (`--time-style=full-iso`, Kali 로컬시각 KST) | 시간 서사 반증 |
| Kali 직접 실행 | `strings /usr/libexec/sudo/sudoers.so \| grep sudo_as_admin` — `.sudo_as_admin_successful` 마커의 생성 주체 확인 |
| `F:\project\DOC_TEMPLATE` | `REFERENCE.md` → `report.base.md`(A-1·A-2·A-2-1·A-3·A-4·A-6) → `pg-machine-md\pg-machine.template.md` |

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `숨기려던 경로 8개(…7개 나열…)` · `8개 경로를 배치 확인` · `실제 경로 8개를 그대로 노출` | 자기 문장 안에서 8개라 쓰고 7개를 나열. `robots.txt` 의 `Disallow` 항목은 8개지만 하나는 루트 `/`. 실제 프로브도 `robots/` 14개 파일 = 7경로×2 | 「`Disallow` 항목 8개 중 루트를 뺀 실제 경로 7개」·「14회 배치」로 통일 |
| `top-1000 빠른 스캔(nmap-quick.txt)` | `nmap-quick.txt` 헤더는 `-p 22,80` 서비스 스캔. top-1000 은 `nmap-quick-ports.txt`(`--top-ports 1000`, 0.72초) | 두 파일을 갈라 각각의 역할·소요로 기재 |
| `gobuster …는 login.php·index.php·logout.php·js·css·assets 만 반환 — robots.txt 가 이미 준 정보량에 못 미쳐` | 바로 아래 인용한 `gobuster-80.txt` 13행에 `hint.txt`·`check_login.php` 가 있고 이 둘은 `robots.txt` 가 주지 않은 것. 노트가 자기 증거에 반박당함 | 13행 전량을 「robots.txt 가 이미 준 것 / 새로 나온 것」으로 갈라 기재 |
| `raft 계열 워드리스트 추정` | 추정이 아니라 확인 가능. `.bg-gobuster.sh` 에 `raft-small-words.txt`·`-x php,txt,html,bak,zip,old`·`-b 404,403` 명시 (A-2-1 추론의 본문 잔류) | 실제 인자로 교체 |
| `/hint.txt 도 gobuster 로 존재만 확인되고 내용은 뒤의 권한상승 단계에서 다시 등장` | 시간 서사 역전. `gobuster-80.txt` mtime 11:13:43 > `proof_root.txt` 11:10:12 > `find_technawi.txt` 11:09:08. gobuster 는 root 획득 «뒤» 끝났고 `hint.txt` 를 먼저 집은 것은 `grep -rl technawi` | 세 mtime 을 명시하고 gobuster 를 「사후 대조용」으로 정정 |
| ```` ```text / username : admin / password : 3v1l_H@ck3r ``` ```` — 출처 `creds_and_src.txt`(`===CRED===`) | **출처 오귀속.** `===CRED===` 는 `technawi`/`3vilH@ksor` 이고 admin 자격증명이 아님. admin 값은 이미 위 `robots/admin_area.body` 펜스에 있어 중복이기도 함 | 펜스 삭제, 산문으로 흡수 (원문은 아래 「삭제한 것」) |
| ```` ```text / username = "admin", password = "3v1l_H@ck3r" → check_login.php POST → 302 응답에 Set-Cookie: PHPSESSID ``` ```` — 출처 `cj.txt` | **창작 코드펜스(A-1).** `cj.txt` 는 Netscape 쿠키 파일이고 이런 서술문을 담고 있지 않음 | `cj.txt` 원문 5행(탭 포함)으로 교체 |
| ```` ```text / uid=33… / /home/technawi/local.txt … ← 소유자 technawi, 755 라 … ``` ```` — 출처 `harvest_wwwdata.txt`(요지 발췌) | **재구성 + 주석 삽입(A-1).** 열 순서를 바꾸고 `1`(링크 수)을 떼고 한국어 화살표 주석을 펜스 «안»에 넣음 | `harvest_wwwdata.txt` 26~28행·985~990행 원문 2블록으로 교체, 해설은 펜스 밖으로 |
| ```` ```text / Success / <!DOCTYPE html> / ...(Upload Center 페이지 재출력)... ``` ```` | 생략 표기가 펜스 «안»(A-1 — 생략은 펜스 밖). 실제 본문은 선두에 빈 줄 존재 | 선두 빈 줄 복원, 생략 사실을 캡션으로 이동 |
| `4개 전부 실행 성공(uid=33(www-data))으로 …` | 관측·결론 분리 실패. 산출물이 증명하는 것은 **업로드** 4/4(`up_sh.*.body`). **실행**은 `sh.php` 만 `shell443.log`·그림 6 으로 실측이고 나머지 3개는 응답 원문 미보존 | 업로드/실행을 갈라 각각의 근거를 명시, 나머지 3개는 `writeup_notes.txt` 기재가 근거임을 명기 |
| 리버스셸 페이로드 `bash -c "…0>&1"` | `writeup_notes.txt` 기재 페이로드에 끝의 `&` 존재. 그 `&` 가 `curl -m 8` 이 안 막히게 하는 이유 | `&` 복원 + 이유 한 줄 |
| `그림 6 — 웹셸(sh.php?c=id;ls+-la+/home/technawi) 응답` | 이미지를 직접 열어 보니 `pwd`·`uname -a` 출력도 함께 찍혀 있음. 캡션이 단정한 쿼리 문자열은 화면과 불일치 | 화면에 실제로 찍힌 4항목으로 캡션 교체 |
| ```` ```text ```` 로 태그된 셸 세션 캡처 3곳(`shell443.log`·`proof_user.txt`·`proof_root.txt`) | A-1 표 — 프롬프트가 포함된 셸 세션 캡처는 `bash`. **내용은 한 바이트도 미변경** | 여는 펜스 태그만 `bash` 로 |
| `whoami; id; hostname; hostname -I; date; cat /home/technawi/local.txt` | 실제 실행 줄은 `clear;` 로 시작(`shell443.log`, `creds_and_src.txt` `===BH===`) | `clear;` 복원 + 출처 명시 |
| `whoami; id; … cat /root/proof.txt`(root) | 이 명령 줄은 어느 산출물에도 없음(SSH tmux 세션) | 「명령 줄 원문 미보존」 캡션 추가 |
| `전체 권한(ALL:ALL) ALL)` · 요약의 `` `ALL:ALL` `` | 괄호 깨짐 + 실제 `sudo -l` 표기와 불일치 | `(ALL : ALL) ALL` 로 통일 |
| `644 아닌 640` | 감사 자기수정의 흔적이 본문에 잔류. 노트 어디에도 flag.txt 를 644 라 적은 곳이 없어 독자에게 지시 대상 부재 | 「소유자 `technawi:technawi`·퍼미션 640」 서술로 교체 |
| `사용하지 않음` · `새어 나옴` · `쓰지 않음` | A-4 명사형 어미 | `미사용` · `누출` · `미사용` |
| 200자 초과 산문 8곳 | A-4L | 문장 분할·개조식화 (인과는 유지) |
| `수동 대안` 블록 부재 | `pg-machine.template.md` 가 `Initial Access` 상세·`Privilege Escalation` 각각에 요구 | 2건 신설. 둘 다 실제 실행 형태와 미시도 여부를 명시 |
| `sudo`·`lxd` 그룹 근거가 `writeup_notes.txt` 단독 | 보강 가능 | 그림 6 의 `.sudo_as_admin_successful` 을 독립 근거로 추가. 마커의 생성 주체는 Kali 에서 `strings /usr/libexec/sudo/sudoers.so` 로 직접 확인 |

## 삭제한 것 — 원문 인용

**(1) 오귀속 자격증명 펜스** — `robots/admin_area.body` 펜스와 중복이고 출처가 다른 파일을 가리켰다.

```
확보한 자격증명으로 로그인해 세션 쿠키 획득:

```text
username : admin
password : 3v1l_H@ck3r
```
— 출처: `~/PG/JISCTF/creds_and_src.txt`(`===CRED===` 구간, `hint.txt` 원문과 동일한 낚시 문구 포함)
```

**(2) 창작 코드펜스** — `cj.txt` 는 이런 문장을 담고 있지 않다.

```
```text
username = "admin", password = "3v1l_H@ck3r" → check_login.php POST → 302 응답에 Set-Cookie: PHPSESSID
```
— 출처: `~/PG/JISCTF/cj.txt`(curl 쿠키잼); 로그인 요청 자체의 curl 명령 줄과 HTTP 왕복 원문은 미보존이고, 쿠키잼과 이어지는 인증 세션의 결과로 재구성
```

**(3) 재구성 + 주석 삽입 펜스**

```
```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/home/technawi/local.txt  -rwxr-xr-x 1 technawi technawi 33 Sep  9 05:02  ← 소유자 technawi, 755 라 www-data 도 읽힘
/var/www/html/flag.txt    -rw-r----- technawi technawi 32 Jul 13  2020   ← 그룹 read 불가, technawi 권한 필요
sudo -l → a password is required
```
— 출처: `~/PG/JISCTF/harvest_wwwdata.txt`(요지 발췌 — SUID·SGID·capabilities·cron 은 배포판 표준 목록과 일치해 권한상승 재료 부재)
```

**(4) 일반 교훈 한 문장** — `_PLAYBOOK.md` 9386~9387행·4183~4190행에 이미 등재돼 중복.

```
— 헤드리스 캡처는 찍힌 뒤 반드시 내용을 눈으로 재확인해야 한다는 사례.
```

## 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

| 제기된 의심 | 확인 결과 |
|---|---|
| **`sudo -l` → `(ALL:ALL) ALL` 이 원문 미보존이라는 작성자 판정이 과한 것 아닌가** (harvest.sh 가 `sudo -l` 을 턴다) | **작성자가 옳다.** `harvest_wwwdata.txt` 26~28행의 SUDO 절은 www-data 의 `sudo -n -l` → `a password is required`, `harvest_root.txt` 26~32행은 **root 자신**의 `sudo -l`(`User root may run …`). technawi 의 `sudo -l` 출력은 어느 파일에도 없음. 작성자가 든 대체 근거 2건은 **실재** — `harvest_root.txt` 240~244행 `ps auxf` 계보(technawi `-bash` → `sudo -s` → root `/bin/bash`), 1012행 `SUDO_USER=technawi`(추가로 996·1002행 `SUDO_GID/UID=1000`) |
| **`sudo`·`lxd` 그룹 주장의 독립 근거 부재** | 부분 반증. harvest.sh 는 `/etc/passwd`·shadow 는 뜨나 **`/etc/group` 은 안 뜬다** — 그룹 목록 원문은 없음이 맞다. 다만 그림 6 의 `.sudo_as_admin_successful` 이 「sudo 그룹 사용자가 sudo 를 성공적으로 실행했다」는 마커라 간접 근거가 된다(Kali 실행 확인). 노트에 반영 |
| **`flag.txt` 소유자를 다른 절에서 「root 소유」로 적었을 가능성** | **미실현.** 노트 전체에서 `flag.txt` 소유자를 root 로 적은 곳 부재. 640·`technawi:technawi` 로 일관 (`find_technawi.txt:25`·`harvest_root.txt:1055`·`harvest_wwwdata.txt:987` 3중 일치) |
| **`shot_80_login.png` 와 `shot_80_root.png` 가 20007바이트로 동일 — 캡션 오류 가능성** | **오탐.** `/` 가 `login.php` 로 302 리다이렉트하므로 두 캡처는 같은 화면인 것이 정상. 볼트 반입분 `PG-JISCTF-login.png` 를 직접 열어 확인 — `Login Form` 폼 화면이고 캡션과 일치 |
| **오염된 `view-source:` 스크린샷을 증거로 채택했을 가능성** | **미실현.** 볼트 반입 6장을 전부 열어 확인 — 그림 1 로그인 폼 / 그림 2 robots.txt 8행 / 그림 3 `/backup/` 404 + Apache 푸터 / 그림 4 `The admin area not work :)` / 그림 5 File Upload Center / 그림 6 웹셸 응답. 6장 모두 캡션과 일치하고 오염분(35875바이트 새 탭) 부재 |
| **`┌──(kali㉿kali)` 창작 프롬프트 혼입** | **부재.** 노트 전체에 Kali 프롬프트 0건. 반대로 타겟 pty 프롬프트 3종(`www-data@Jordaninfosec-CTF01:/var/www/html/uploaded_files$`·`:/tmp$`·`root@Jordaninfosec-CTF01:~#`)은 실측이며 **전부 보존**. 펜스 태그만 `text`→`bash` 로 바꿨고 내용은 무편집 |
| **절 순서 이상 — `Initial Access` 가 `Service Enumeration` 앞뒤로 두 번** | **오지적이 될 뻔함.** `pg-machine.template.md` 「골격 주의 4건」 1항이 「`Initial Access` 가 두 번 나오는 것은 OffSec 공식 예시 4장 그대로」라고 명시. 두 제목이 서로 다르게 지어져 있어 규격 준수. **구조 결손 아님** |
| **`[가정]`·「근거부족」 잔류(A-2 위반)** | **0건.** 「원문 미보존」·「해당 없음」은 존치(약속된 토큰) |
| **채점 2/2 근거 — 웹셸로 읽었을 가능성** | **혐의 없음.** `proof_user.txt`(213바이트)·`proof_root.txt`(187바이트) 둘 다 `whoami; id; hostname; hostname -I; date; cat` 한 화면이고 말미에 타겟 pty 프롬프트 존재. `shell443.log` 에 `python3 … pty.spawn` 승격 후 같은 세션에서 `clear; whoami; …` 를 친 기록이 그대로 남아 있음. 웹셸은 harvest 회수·소스 열람에만 사용 |
| **시간 자기모순** | **부재.** `recon-preflight.txt` 가 `02:04:59Z / 11:04:59 KST` 로 환산을 명시. 타겟 `date` 는 EEST(UTC+3) — `05:08:48 EEST` = `02:08:48Z` = `11:08:48 KST`, `proof_user.txt` mtime 11:08:51 KST 와 정합 |

## 총괄 판단이 필요한 것 — 노트에 반영하지 않음

1. **프론트매터가 `pg-machine.template.md` 규격에 미달.** 템플릿은 `tier`·`method`·`machine`·`started`·`user_at`·`root_at`·`stuck_total`·`session_logged`·`tricks_logged`·`ledger`·`date` 와 `tier/*`·`method/*` 태그를 요구하고, 셋(`session_logged`·`tricks_logged`·`ledger`)이 전부 `true` 가 아니면 문서를 미완으로 규정. **JISCTF 만의 문제가 아니라 볼트 전체가 그렇다** — 같은 세션에 작성된 `Covfefe.md`·`Interface.md` 도 동일하게 부재. 한 노트만 고치면 어휘가 갈라지므로 미반영. 실측 — JISCTF 는 `ledger` 참(`_STATUS.md:59`), `tricks_logged` 참(`_PLAYBOOK.md:4183~4190`), `session_logged` **거짓**(`F:\project\OSCP\세션로그\` 에 JISCTF 항목 부재, 3건만 존재)
2. **문체 — 서술형 종결이 노트 전반에 잔류.** A-4 는 파생명사 종결을 요구하나 본문 대부분이 `~했다`·`~이다`·`~한다`. `style-check.ps1` 의 A-4 규칙은 명사형 어미(`~함`·`~임`·`~됨`·`~음`)만 잡으므로 통과했다. **`pg-doc-reviewer` 관할로 이관 대상** — 사실 검증 범위 밖이라 손대지 않음
3. **색인 갱신 필요.** 노트 본문이 40행 늘었으나 `ports`·`services`·태그·CVE 는 불변. `refresh.ps1` 은 공유 인프라라 미실행

## 검산

- `style-check.ps1 -Path "03. PG"` — JISCTF.md 지적 **0건**(초기 9건: A-4 1 · A-4L 8)
- 행수 465 → 505
- 프론트매터 `platform: pg` · `status: solved` · `platform/pg` · `status/solved` 어휘 유지. `manual_tags: true`, `tech_count: 4` 와 `tech/*` 태그 4개 일치. CVE 언급 0건이라 `manual_cves` 해당 없음
- `Port Scan Results` 표 존재 + nmap raw `PORT` 라인(`22/tcp open ssh …`) 보존 — `extract.py` `PORT_RE` 대상 유지
- `Initial Access`·`Privilege Escalation` 각각에 4항목(`Vulnerability Explanation:`·`Vulnerability Fix:`·`Severity:`·`Steps to reproduce the attack:`) 존재
- 터미널 출력·명령·IP·해시·플래그·자격증명 **무편집**. 변경한 것은 여는 펜스의 언어 태그 3곳뿐
