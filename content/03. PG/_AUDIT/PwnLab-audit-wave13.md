---
type: audit
box: PwnLab
platform: pg
date: 2026-08-26
auditor: writeup-auditor (wave 13)
manual_tags: true
manual_cves: true
tags:
  - type/audit
  - platform/pg
---

# PwnLab 적대적 검증 + 정정 (wave 13)

대상: `03. PG\PwnLab.md`(개작 직후 527행 → 정정 후 624행)
기준: `03. PG\_WRITEUP-STANDARD.md` · `CLAUDE.md` §3·§4·§5·§8 · 실물 기준 `03. PG\Robust.md`

## 0. 근거 출처 — 실제로 연 것만

| 출처 | 무엇을 확인했나 |
|---|---|
| `~/PG/PwnLab/` 전 33파일 | nmap 4종 · `src_*.php` 4종 · `sh.gif` · `cookies.txt` · `creds.txt` · `mysql_dump.txt` · `upload_resp.html` · `harvest_www-data.txt` · `harvest_root.txt` · `proof_user.txt` · `proof_root.txt` · `shell_www-data.log` · `traces_confirmed.log` · `writeup_notes.txt` · `try1`~`try5` |
| `grep -al 'kali㉿kali' ~/PG/PwnLab/*` | **`try2_nnmap_alias_notfound.log` 단 1건**(파일 내 2회) |
| 볼트 `파일보관\PG-PwnLab-upload-denied.png` | 직접 열어봄 — `You must be log in.` · 3링크 일치 |
| `03. PG\_backup\PwnLab.md.bak`(869행) | 삭제된 구 0·6·7·8·9장 전문 대조 |
| `03. PG\_AUDIT\PwnLab-playbook.md` | 이관 제안 13건 대조 |
| `_INDEX\_tools\extract.py` | `keep_high` · `MANUAL_PORT_RE` · `DECL_PORT_RE` 동작 확인(실행은 안 함) |
| Kali 직접 실행 | ① `mysql --version` ② `curl -F` 기본 Content-Type nc 재현 ③ SUID `bash -p` C 프로그램 재실행 ④ `findmnt -no OPTIONS /tmp` |

⛔ `find /`·홈 전체 grep·`~/PG` 전수 스캔은 하지 않음(CLAUDE.md §3).

---

## 1. 최우선 지목 — tmux capture-pane 프롬프트 복원

### 실측 결과: 복원 대상은 **`try2` 1건뿐**

`~/PG/PwnLab/` 33개 파일 전수 `grep -al 'kali㉿kali'` → **`try2_nnmap_alias_notfound.log` 하나만 매치.** 그 파일 안에 2회.

복원한 블록(Service Enumeration, 줄바꿈 위치·공백 포함 원문 그대로):

```text
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$ cd ~/PG/PwnLab && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.
248.29 2>&1 | tee nmap.full.txt
```
출처 캡션 `— 출처: ~/PG/PwnLab/try2_nnmap_alias_notfound.log` 부착. pty 폭 80열에서 잘린 것임을 산문으로 명시.

### 복원하지 «않은» 것과 그 근거

- 같은 파일 첫 줄 `zsh:1: command not found: nnmap` 와 그에 딸린 서사는 **시행착오**라 `_WRITEUP-STANDARD` 「시행착오는 박스 노트에 쓰지 않는다」에 따라 노트에 넣지 않음. 이미 `_AUDIT\PwnLab-playbook.md` §1 에 **원문 인용 그대로** 보존돼 있어 소실이 아님.
- `try2` 의 나머지(nmap 결과 본문)는 `nmap.log` 와 동일 내용이고 노트가 이미 `nmap.log` 를 무손실로 싣고 있어 중복 복원하지 않음.

### 관리자 지목 중 반증한 부분 → §5 로

---

## 2. 50118/tcp 판정 — **색인 유지로 뒤집음**

**개작본 서술(삭제)**:
> `-p-` 전체 스캔에서 rpcbind 의 `rpc.statd` 상태 서비스가 50118/tcp 로 하나 더 잡혔으나(raw 아래 참고), **rpcbind 가 매 부팅마다 랜덤 배정하는 동적 포트**라 `ports:` 프론트매터에서는 제외하고 `manual_ports: true` 로 표시함.

**반증 근거 3개:**

1. **양성 증거** — `harvest_root.txt` `===== LISTEN =====` 절:
   ```text
   tcp    LISTEN     0      128                    *:50118                 *:*      users:(("rpc.statd",pid=435,fd=9))
   ```
   프로세스까지 특정된 **실제 리스닝 서비스**다. 「동적 포트라 서비스가 아니다」가 아니라 「동적으로 배정된 실서비스」다.
2. **도구 동작** — `extract.py:344` 의 `keep_high = meta.get("os") == "linux"`. 이 노트는 `os: linux` 이므로 **고포트 자동 제외가 애초에 적용되지 않는다.** 즉 작성자는 도구의 올바른 동작을 `manual_ports` 로 덮어써서 색인에서 지운 것이다. CLAUDE.md §5 의 [[ClamAV]] 60000/tcp 선례와 정확히 같은 사고.
3. **부재 근거의 등급** — 「부팅마다 랜덤」은 재부팅 간 대조 없이는 확인할 수 없다. `rpc.statd` 가 `-p` 없이 뜨는 것은 사실이나(`ps` 에 `/sbin/rpc.statd` 인자 없음 확인), 그것이 「색인에서 빼야 한다」를 지지하지는 않는다.

**정정**:
- `ports: [80, 111, 3306]` → `ports: [80, 111, 3306, 50118]`
- `services: [http, mysql, rpcbind]` → `+ status`(PORT_RE 가 `50118/tcp open status` 에서 뽑을 값과 일치시킴)
- Port Scan Results 표: `TCP: 80, 111, 3306` → `TCP: 80, 111, 3306, 50118`
- 본문: `ss` 출력을 근거로 싣고, 부팅 간 안정성은 `[가정]` + 「관측 없음」으로 강등
- `manual_ports: true` 는 유지(이제 도구가 뽑을 값과 같은 집합을 선언함)

**⚠️ 색인 갱신 필요** — 프론트매터 `ports`/`services` 가 바뀌었다. `refresh.ps1` 은 총괄 몫이라 실행하지 않음.

---

## 3. 고친 것 — 날조·인과·출처

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `— 출처: ~/PG/PwnLab/traces_confirmed.log`(PHP 버전 블록) | **`traces_confirmed.log` 에 `php -v` 출력이 없다.** 전량 확인함 — 그 파일은 auth.log·access.log·wtmp·`/tmp` 목록뿐 | 실제 출처 `proof_root.txt` 로 정정 |
| `— 출처: ~/PG/PwnLab/traces_confirmed.log` 재구성(RCE 응답 블록) | 같은 파일에 `uid=33`·`GIF89a`·`ls -la /home` 이 전부 없음. `grep -aln 'Content-Length' *` → **0건** | §4 참조 — 원문 복원 + 「파일로 저장 안 함」 명시 + 교차근거 3개 제시 |
| `— 출처: ~/PG/PwnLab/cookies.txt`(302 응답 블록) | `cookies.txt` 는 Netscape 쿠키잼이라 **HTTP 헤더를 담지 않는다** | §4 참조 — 헤더 전문 복원 + 「저장 안 함」 명시 + mtime 교차근거 |
| `— 출처: ~/PG/PwnLab/try1_msgmike_histexpand.log`(strings msgmike) | `try1` 에는 `kane@pwnlab:/tmp$ strings ...` **프롬프트 줄이 없다**(발췌본). 프롬프트가 있는 것은 `shell_www-data.log` | 출처를 `shell_www-data.log` 로 바꾸고 `try1` 은 발췌본으로 병기 |
| 심볼 순서 `system` / `setreuid` | 원문 순서는 `setregid` → `setreuid` → `system`. **순서를 바꿔 실었다** | 원문 순서로 복원, 앞뒤 심볼도 실제 것으로 채우고 생략 구간은 `(…생략…)` 로 명시 |
| `— 출처: try4_...`(msg2root strings) | `try4` 는 `.gnu.version_r` 부터 시작 — `strings ... \| head -30` 프롬프트 줄이 없다 | `shell_www-data.log` 우선, `try4` 병기 |
| `(…)` 로만 표시된 msg2root strings 3줄 | `stdin`·`__libc_start_main` 등 실제 심볼을 통째로 `...` 처리 | 원문대로 12줄 복원 |
| `타겟 pty 프롬프트(tmux capture-pane, shell_www-data.log)` | `shell_www-data.log` 는 `nc \| tee` 출력이지 `capture-pane` 결과가 아님 | 「리스너가 받은 스트림 원문」으로 정정 |
| `— 출처: traces_confirmed.log`(남긴 흔적 삭제 확인) | 그 파일의 마지막 블록은 **파일이 아직 남아 있는** `/tmp` 목록이다. 삭제 후 목록은 `proof_root.txt`/`shell_www-data.log` 에 있음 | 출처 정정 |
| `두 파일 모두 /root/messages.txt·.bash_history·.mysql_history 가 전부 /dev/null 심볼릭 링크임을 함께 보여줌` | **거짓.** `proof_user.txt`(kane 홈)·`proof_root.txt`(어디에도 `ls -la /root` 없음) 둘 다 그 내용을 담지 않음 | 삭제하고, 대신 두 파일이 **대화형 셸 프롬프트로 끝난다**는(웹셸 0점 회피 근거) 실제 사실로 대체. `/dev/null` 링크는 새로 복원한 `ls -la /root` 블록으로 이동 |
| `ls -la /root` 는 flag.txt 가 미끼임을 함께 보여준다 | **그 출력 블록이 노트에 없었다.** 캡션만 있고 근거가 없는 상태 | `shell_www-data.log` 의 `ls -la /root` 9줄 원문 복원 |
| `$ ~/suidtest/a  # execl(...)` 2블록 | 에이전트가 비대화형 `ssh kali "..."` 로 돌린 것에 **`$ ` 프롬프트를 창작**했고, **코드펜스 «안»에 한국어/영어 해설 주석**을 섞음. 검증용 바이너리는 이미 삭제돼 재대조 불가 | **2026-08-26 Kali 에서 SUID root C 프로그램 2개를 직접 다시 만들어 실행.** 실측 출력(`--- a (no -p) --- / 1000 / 1000 / --- b (with -p) --- / 0 / 1000`)으로 교체, 주석은 펜스 밖 산문으로 뺌. 결론(`-p` 유무 동작)은 **정확했음** |
| `findmnt -no OPTIONS /tmp` → `rw,nosuid,nodev,...` | 값이 `...` 로 잘려 있었음 | 오늘 재실행한 전문 `rw,nosuid,nodev,size=12463400k,nr_inodes=1048576,inode64` 로 교체 |
| `[[_PLAYBOOK#A-1-10. tmux 에 던진 스캔이 «조용히» 죽는다]]`(히스토리 확장 설명에 부착) | **주제가 다른 앵커.** A-1-10 은 tmux 스캔이 죽는 항목이고, 히스토리 확장 항목은 `_PLAYBOOK` 에 **아직 존재하지 않는다**(`grep '히스토리 확장\|event not found\|set +H' _PLAYBOOK.md` → 0건). 링크는 뜨지만 다른 내용으로 간다 | 오지시 앵커 제거. 대신 원인(`!` 히스토리 확장, 줄을 읽는 시점에 확장)을 두 줄로 본문에 남김. **A-1-10 앵커는 `## 관련` 목록에 그대로 살아 있어 노트에서 사라지지 않음.** 신규 앵커는 만들지 않음 |
| 업로드 검사 「3중」 | `src_upload.php` 에 검사가 **4개**(`substr_count($filetype,'/')>1` → `Error 003` 누락) | 표를 4행으로 확장하고 실패 시 에러 문구 열 추가. 저장 경로 공식도 소스 원문(`$uploaddir . md5(basename(...)) . $file_ext`)으로 명시 |
| `### Privilege Escalation – SUID msg2root 포맷 문자열 커맨드 인젝션` | 「포맷 문자열」은 `%n` 계열 취약점을 가리키는 용어라 오독을 부름. 실제는 `%s` 무필터 치환 후 `system()` | `무필터 커맨드 인젝션` 으로 개칭(요약·본문 서술과도 일치) |
| `## Post-Exploitation` | 실물 기준 `Robust.md` 는 `### Post-Exploitation`(Target #1 블록 안) | `###` 으로 맞춤 |
| `(아래 Privilege Escalation 1단계)` / `(뒤 finding …)` | 상대 참조 | `(Privilege Escalation 1단계)` / `` (`msg2root` finding …) `` 로 고정 참조화 |
| `원인과 재확인 절차는 [[_PLAYBOOK]] 이관(아래 관련 참고)` | 「이관」은 **내부 작업 과정 기록**이고 노트는 공개 발행됨 | 문구 제거, 원인 서술만 남김 |

### 코드펜스 원문성 — 압축돼 있던 것 복원

| 블록 | 빠져 있던 것 |
|---|---|
| `xxd sh.gif` | 4번째 줄 `00000030: 203f 3e0a    ?>.` (52바이트 중 마지막 4바이트) |
| kent `ls -la ~` | `drwxr-x--- 2 kent kent 4096 …  .` / `drwxr-xr-x 6 root root …  ..` |
| kane `ls -la /home/kane` | 같은 `.` / `..` 2줄 |
| mike `ls -la /home/mike` | `total 28` + `.` / `..` 3줄 |
| RCE 응답 | `Date:` · `Server:` · `Vary:` · `Content-Type:` 헤더 4줄, `/home` 의 `.` / `..` 2줄, 끝의 `<html>^M` |
| 302 응답 | `Date:` · `Server:` · `Expires:` · `Cache-Control:` · `Pragma:` · `Content-Type:` 6줄 |
| `ls -la /root` | 블록 전체(9줄)가 부재 |
| msg2root strings | 심볼 9줄 |
| msgmike strings | 심볼 11줄 |

`nmap.log` raw 는 개작본에서 이미 무손실이었음 — 한 줄씩 대조해 **차이 0**. `PORT_RE` 매칭 라인 4개(80/111/3306/50118) 전부 살아 있음.

---

## 4. 「날조 의심 → 반증」 — 이것을 반드시 읽을 것

개작본의 두 HTTP 응답 블록(302 로그인 · 200 RCE)은 **어느 산출물 파일에도 없다**(`grep -aln 'Content-Length' ~/PG/PwnLab/*` → 0건). 처음에는 날조로 판정하려 했다. **되짚어보니 틀렸다.**

`_backup\PwnLab.md.bak`(개작 전 869행 원문)에 두 블록이 **더 긴 형태로** 들어 있고, 헤더의 `Date:` 가 산출물과 초 단위로 맞물린다:

| 블록 | 헤더 `Date` (UTC) | 대조 대상 | 결과 |
|---|---|---|---|
| 302 로그인 | `Thu, 20 Aug 2026 08:38:44 GMT` = 17:38:44 KST | `cookies.txt` mtime `17:38:43.454` | **1초 차** |
| 200 RCE | `Thu, 20 Aug 2026 08:39:05 GMT` = 17:39:05 KST | `harvest_www-data.txt` 의 `DATE` 절 `Thu Aug 20 08:40:34 UTC 2026` | RCE 가 89초 앞섬 — 작업 순서와 일치 |

추가로 RCE 블록의 `/home` 목록 6줄이 `harvest_www-data.txt` 의 `-- homes --` 절과 **한 글자도 다르지 않다**(`total 24` · `.` · `..` · john/kane/kent/mike 모드·소유자·크기·날짜 전부).

**결론**: 두 블록은 러너가 `ssh kali "curl -s -i …"` 출력을 터미널에서 옮겨 적은 **실측 전사**이지 날조가 아니다. 파일로 tee 하지 않은 것이 문제이고, 개작 과정에서 **잘라내고 엉뚱한 파일을 출처로 붙인 것**이 문제다.

**조치**: `.bak` 의 전문을 복원하고, 캡션에 「이 응답은 파일로 저장하지 않았음 + 뒷받침 근거 3개」를 명시. 삭제·강등이 아니라 **복원 + 출처 정직화**로 처리.

> 부재 증거의 등급 상한은 `근거부족` 이다. 이 건은 그 규율이 실제로 삭제 사고를 막은 사례다.

---

## 5. 반증한 것 — 관리자 지시 중 확인해보니 틀렸던 것

### (a) 「작성자가 자기 반증을 반영하지 않았다 = 실측 파괴」 → **부분적으로 틀림**

지목의 사실 부분은 맞다(노트의 `┌──(kali` 매치 0건). 그러나 **「전수 식별해 노트에 복원」의 범위는 1건뿐**이고, 그 1건의 내용은 **시행착오**라 `_WRITEUP-STANDARD` 상 박스 노트가 아니라 `_PLAYBOOK` 행이다. 실제로 `_AUDIT\PwnLab-playbook.md` §1 에 코드펜스까지 원문 인용돼 보존돼 있었다 — **소실된 적이 없다.**

더 중요한 것: **PwnLab 은 CLAUDE.md §3 이 「Kali 프롬프트 창작」 사례로 이름을 박아 인용한 바로 그 박스다**("2026-08-20 PwnLab 감사에서 드러났다"). `.bak` 을 열어보니 `┌──(kali㉿kali)` / `└─$` 가 **9곳**에 붙어 있고, 그 명령들은 전부 에이전트가 비대화형 `ssh kali "..."` 로 돌린 것이다(`~/.zsh_history` 미기록 · 산출물에 프롬프트 없음). 즉 **개작본이 그것들을 지운 것은 규율대로 한 옳은 작업**이었다. `grep -al` 결과가 1건뿐인 것이 그 증거다.

→ 「전수 복원」 지시를 그대로 따랐다면 **CLAUDE.md §3 이 명시적으로 금지한 창작 프롬프트를 8개 되살렸을 것.** 실측으로 갈라 1건만 복원했다.

### (b) 「`Connection to <host> closed.` 를 지우지 마라」 → **대상 없음**

노트에도 `.bak` 에도 `~/PG/PwnLab/` 산출물에도 이 문자열이 **한 건도 없다**(`grep -n "Connection to"` → 0). 이 박스는 `ssh -tt` 를 쓰지 않았다 — 타겟 셸은 `mkfifo` 리버스셸이고 pty 는 `python pty.spawn` 으로 올렸다. 지시가 다른 박스의 사정을 이 박스에 적용한 것.

### (c) 「이관 손실 — `try1`~`try5` 5개 로그의 인과가 사라졌는가」 → **사라지지 않음**

`_AUDIT\PwnLab-playbook.md` 13건을 `.bak` 구 6장·7장과 한 항목씩 대조한 결과, **다섯 로그의 인과가 전부 「지우기 전 원문」과 함께 보존**돼 있었다:

| 로그 | 인과 | playbook 항목 |
|---|---|---|
| `try1` 히스토리 확장 | ✅ `&&` 로 이어붙여 줄 전체 폐기 · `set +H` 같은 줄은 늦음 | §4(신규 A-4) |
| `try2` nnmap 별칭 | ✅ tmux 가 `.zshrc` 를 안 읽음 · 손실 10분 | §1(A-1-10 병합) |
| `try3` mysql SSL | ✅ MariaDB↔Oracle 옵션명 차이 · `1129` 락아웃 | §2(A-24 병합) |
| `try4` 가짜 cat PATH 그림자 | ✅ 3단계 상속 · `exec` 가 줄을 통째로 삼킴 · `echo ---` 판별법 | §5(신규 A-4) |
| `try5` RFI 차단 | ✅ **노트 본문 `[!tip]` 에 남아 있음**(`allow_url_include=Off`) | 이관 대상 아님 |

### (d) 자기 지적 중 되짚어보니 틀렸던 것

1. **「RCE·302 응답 블록은 날조」** → §4 대로 **반증됨.** 타임스탬프 교차 대조로 실측 전사임이 확인돼, 삭제가 아니라 복원으로 방향을 바꿨다. 이것을 안 되짚었으면 **정확했던 실측 두 블록을 지울 뻔했다.**
2. **「`try4` 의 `^H` 잔상을 제거한 것은 개변」** → 되짚어보니 과잉. `tmux send-keys` 입력 에코가 80열에서 겹쳐 찍힌 **터미널 렌더 산물**이고, 명령 문자열은 완전 복원 가능하며 `stty cols 200` 이후 재캡처본(`proof_root.txt`)이 같은 값을 보여준다. 삭제하지 않고 **캡션에 「겹친 잔상만 걷어냄」을 명시**하는 것으로 처리.
3. **「curl 이 `.gif` 에 `image/gif` 를 자동으로 붙인다」를 `[가정]` 으로 강등해야 한다」** → **강등 불필요.** 2026-08-26 Kali 에서 직접 재현(`nc -lvnp 19099` + `curl -s -F 'file=@/tmp/zzq.gif'`)해 파트 헤더 `Content-Type: image/gif` 를 눈으로 확인. 작성자 서술이 정확했다. 오히려 nc 가 받은 실제 두 줄을 코드펜스로 실어 근거를 **올렸다**.
4. **「`mysql` 클라이언트 버전 11.8.3-MariaDB 는 확인 안 된 단정」** → `mysql --version` 직접 실행: `mysql from 11.8.3-MariaDB, client 15.2 for debian-linux-gnu (x86_64)`. **정확했음.**

---

## 6. 삭제한 것 — 원문 전문 인용(되살릴 수 있어야 함)

### (1) 50118 제외 판정 문단

```
`-p-` 전체 스캔에서 rpcbind 의 `rpc.statd` 상태 서비스가 50118/tcp 로 하나 더 잡혔으나(raw 아래 참고), **rpcbind 가 매 부팅마다 랜덤 배정하는 동적 포트**라 `ports:` 프론트매터에서는 제외하고 `manual_ports: true` 로 표시함. 111/50118 은 rpcbind + rpc.statd 뿐이고 NFS(2049)는 열려 있지 않으며 `/etc/exports` 도 비어 있었음 — `mount.nfs` 가 SUID 로 있어 잠깐 눈길이 갔지만 export 가 없어 경로가 아님.
```
사유: §2. 뒷문장(NFS 배제)은 살려서 새 문단에 그대로 옮김.

### (2) 창작 프롬프트가 붙은 SUID 검증 블록

```
이건 이 박스에서 관측한 게 아니라 Kali 에서 별도로 확인한 것이다 — SUID root C 프로그램(`execl("/bin/bash","bash",...)`)으로 `-p` 유무를 재확인:

```text
$ ~/suidtest/a          # execl("/bin/bash","bash","-c","id -u; id -u -r; echo EUID=$EUID UID=$UID")
1000
1000
EUID=1000 UID=1000
$ ~/suidtest/b          # 같은 코드에 "-p" 만 추가
0
1000
EUID=0 UID=1000
```
```
사유: `$ ` 프롬프트 창작 + 펜스 안 해설 주석. **결론은 정확했으므로** 오늘 Kali 에서 같은 실험을 다시 돌려 실측 출력으로 교체(§3 표 참조). 원래 값과 동일한 결론.

### (3) 오지시 `_PLAYBOOK` 앵커 한 줄

```
가짜 `cat` 작성 중 bash 히스토리 확장 함정을 밟았다 — [[_PLAYBOOK#A-1-10. tmux 에 던진 스캔이 «조용히» 죽는다]] 인접 시행착오로 상세는 `_PLAYBOOK` 참고. `set +H` 를 **별도 줄로 먼저** 보내는 것으로 해결했다.
```
사유: 앵커의 주제 불일치(§3 표). 같은 앵커가 `## 관련` 에 살아 있어 노트에서 소실되지 않음. **신규 앵커는 만들지 않았고 기존 앵커 6개는 전부 그대로다.**

### (4) 근거 없는 proof 파일 서술

```
두 파일 모두 `/root/messages.txt`·`.bash_history`·`.mysql_history` 가 전부 `/dev/null` 심볼릭 링크임을 함께 보여줌 — `msg2root` 로 넣은 `hi` 도 root 명령 이력도 아무 데도 안 남는다.
```
사유: 두 파일 어느 쪽에도 `ls -la /root` 가 없다(전량 확인). 내용 자체는 참이고 근거는 `shell_www-data.log` 에 있으므로 **그 블록을 복원해 그 자리에 붙였다** — 정보 소실 없음.

---

## 7. 추가 이관 제안 — `_PLAYBOOK` 에 아직 안 간 2건

`.bak` 대조에서 `_AUDIT\PwnLab-playbook.md` 13건 어디에도 안 들어간 것 2건. **`_PLAYBOOK` 은 직접 쓰지 않으므로 관리자가 반영할 것.**

### (a) 구 0장 「시험 출제 가능성」 문단 — 변형 예측이 통째로 사라짐

```
**시험 출제 가능성** — 높다. LFI→업로드→include 체인은 OSCP 웹 파트의 정석이고, `strings` 로 SUID 바이너리를 열어 상대경로/`system()` 을 찾는 것은 리눅스 권한상승의 기본 반사다. 변형이라면 include 진입점이 쿠키가 아니라 `Accept-Language` 헤더나 세션 파일(`/var/lib/php5/sessions/sess_*`)로 바뀌는 정도.
```
→ playbook §9(신규 B-1 「LFI 싱크가 두 개일 수 있다」) 끝에 붙이면 맞다. **`Accept-Language` 헤더·PHP 세션 파일**이라는 구체적 변형 후보가 시험장에서 값을 한다.

### (b) 구 4-4 「다른 경로였다면」 exim4 배제 — **노트 본문에 복원함**

`.bak` 에만 있고 playbook 13건에 없었다. 실측 `dpkg -l` 출력이 `shell_www-data.log` 에 있어 **근거가 있는 배제 기록**이므로 노트 Privilege Escalation 끝에 복원했다. 단 원문의 「그쪽 경로는 아니었을 것으로 본다 `[가정]`」을 **「배제가 아니라 미검증」**으로 더 명확히 적었다(CLAUDE.md §3 「배제했다」와 「끝까지 못 해봤다」를 구분해 적어라).

---

## 8. 문체 — `pg-doc-reviewer` 로 이관

**문체 이관 21건.** 서술형 종결(`~했다`·`~이다`·`~된다`)이 개조식과 섞여 있음. 대표 위치만 적으면 — 요약 콜아웃 이후 Initial Access 상세 절 전체, `443 아웃바운드가 첫 시도에 통과했다`, `…로 잘못 읽기 쉽다`, `…가 드러난다`, `…를 아꼈다` 등. **사실·인과는 전부 확인했고 문제 없음** — 종결 어미만의 문제다.

⛔ 코드펜스 안 · `[가정]` · 「관측 없음」 · 타겟 pty 프롬프트는 **손대지 말 것**을 이관 시 명시할 것.

---

## 9. 검산

| 항목 | 값 |
|---|---|
| 행수 | 527 → 624 |
| 복원한 tmux capture-pane 프롬프트 블록 | 1(전수 grep 결과 대상이 1건뿐) |
| 정정 건수 | 24(출처 오기 6 · 코드펜스 원문 복원 9 · 판정 뒤집기 1 · 창작 블록 교체 1 · 구조/용어 4 · 상대참조·작업기록 3) |
| 50118 판정 | **색인 유지**(`ports`·`services`·표·본문 4곳 반영) |
| 이관 손실 | 2건(§7) — 둘 다 원문 인용해 남김, 그중 1건은 노트 본문에 복원 |
| 무태그 코드펜스 | **0**(여는 펜스 31개 전부 언어 태그) |
| `PORT_RE` 매칭 라인 | 4(80·111·3306·50118) — 프론트매터 `ports` 와 일치 |
| 플래그 대조 | `local e7fb032dc3da97822fc7dc2d65ffcc18` · `proof 540256bedfbf87d15d54425649220e30` — `proof_user.txt`·`proof_root.txt` 원문과 **한 글자 일치** |
| 자격증명 대조 | `root:H4u%QJ_H99`(`src_config.php` 일치) · base64 3쌍(`mysql_dump.txt`·`creds.txt` 일치) · `PHPSESSID=8a228r4sf2muih5e37huv72r16`(`cookies.txt` 일치) · md5 `63f0276ffd69eb424bf6093795ac9850`(`upload_resp.html` 일치) |
| 타겟 pty 프롬프트 | `www-data@`·`kent@`·`kane@`·`mike@`·`root@pwnlab`·`bash-4.3#` **전부 보존**(지운 것 0, 오히려 `ls -la /root` 블록으로 1개 추가 복원) |
| 4항목 완비 | Initial Access 1 + Privilege Escalation 3 = **4 finding × 4항목 = 16/16**. `Steps` 는 전부 번호 목록(순서만), 4항목 안 상대참조 **0** |
| `_PLAYBOOK` 앵커 | 기존 6개 유지 · 신규 0 · 삭제 0(오지시 인라인 1건은 `## 관련` 에 동일 앵커가 남아 순감 아님) |

**총괄 판단 필요**: ① `refresh.ps1` 재실행(프론트매터 `ports`/`services` 변경) ② §7 두 건의 `_PLAYBOOK` 반영 ③ `_STATUS.md` 판정 — PwnLab **완료 2/2**(local·proof 둘 다 실측 원문 확보, 대화형 셸 프롬프트로 증명)
