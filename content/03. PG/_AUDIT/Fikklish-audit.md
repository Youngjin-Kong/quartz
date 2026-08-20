---
tags:
  - type/audit
  - platform/pg
---
# Fikklish — 적대적 검증 감사 (2026-08-20)

대상: `03. PG\Fikklish.md` (489행 → 652행). 백업: `03. PG\_backup\Fikklish.md.pre-audit`
소요: 약 25분. `refresh.ps1` **돌리지 않음**. 타겟 **접속하지 않음**(산출물 대조만).

증거원: `~/PG/Fikklish/` 47개 파일 · 볼트 `파일보관\` 스크린샷 3장 · `~/.zsh_history`(해당 없음) · 1차 사료(weblate-4.11 태그 소스) · **Kali/로컬 직접 실행 2건**

---

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| 1장 nmap 블록 | `ssh-hostkey` 3행과 robots 항목 3행을 말없이 잘라냄 | 원문 PORT 절 전량 복원 + 생략 범위를 캡션에 명시 | `nmap.log` |
| 1장 `javascript/(403)` | 실제 **301**. `/sass`·`/server-status`·`.ht*` 누락 | gobuster 두 실행의 합집합을 블록으로 제시 | `gobuster_80.txt`·`gobuster_80_big.txt` |
| 1장 "mtime 전부 2015~2016, index.html 만 2022-12-14" | `Last-Modified` 비교를 남긴 산출물이 **없다** | `[가정]` 강등 + 「관측 없음」 명시. 7장 3번도 같이 완화 | 산출물 부재 (등급 `근거부족`) |
| 2장 "4.11.1 에서 `--branch=<값>` 형태로 붙이고 `--` 구분자를 넣는 식으로 고쳤다" | 확인 불가 + 깊이 기준상 **패치 고고학** | "4.11.1 에서 수정됐다" 로 축약 | `_WRITEUP-STANDARD.md` 원칙 1 |
| 2장 "컴포넌트 자체는 '저장소가 아니다' 로 실패" | 저널에 실제로 남은 예외는 `WeblateLockTimeout` | 관측된 예외를 싣고, 첫 시도의 사유는 「관측 없음」 | `traces_confirmed.log` WEBLATE LOG TAIL |
| 3-2 ICMP 블록 | 12행 로그에서 **1·2·7행만 비연속으로 이어 붙임**(`...` 표시 없음) | `icmp.log` 전문 12행 복원. "hg 두 번" 인과는 `[가정]` | `icmp.log` |
| 3-3 리버스셸 블록 | 첫 셸(`rev443`) 리스너 로그와 두 번째 셸(`rev443b`) 화면을 **한 블록에 합침** | 출처를 둘로 분리. 스크롤백 미보존을 명시 | `shell443.log` + `reg_smtp.pcap` |
| 3-3 "`(900)` 은 systemd 서비스의 PID" | 실제로는 `weblate runserver` **마스터 프로세스** | ps 원문 인용으로 교체 | `harvest_root.txt:365` |
| 4장 `tom@fikklish:~$ gem list git` | 그 pty 캡처가 존재하지 않음 (전량 비대화형 실행) | 프롬프트 제거, 출력만 + 정직한 출처 표기 | `harvest_tom.txt` 에 없음 → `근거부족` |
| 4장 `.psql_history` / `ls -la` 블록 | 출처 캡션 없음 | 「tom 세션에서 읽음, 화면 미보존」 + 교차 방증 2건 명시 | `trysudo.sh`·`traces_confirmed.log` |
| 5장 플래그 블록 2개 | `Connection to 192.168.248.19 closed.` 행을 잘라냄 | `proof_*.txt` **전문** 복원 + UTC/KST 환산 문단 추가 | `proof_user.txt`·`proof_root.txt` |
| 6장 도입 "총 63분을 태우고 로그인" | 18:26 착수 → 19:19 로그인 = **53분**. 63+10=73 이 총 62분과 모순 | 53분 / 9분으로 정정 + 항목 소요가 겹친다는 사실 명기 | `writeup_notes.txt` 타임라인, `nmap.log` 시작 18:26:57 |
| 6-1 "세 번째부터 응답이 이상해서" | 실제로는 **5회째**에서 막힘(`RATELIMIT_ATTEMPTS=5`) | "다섯 번째에서 막혔다" | `writeup_notes.txt` [18:32], `settings_dump.txt:265` |
| 6-2(신규) **hydra 누락** | SSH 브루트를 **실제로 두 번 돌렸는데 6장에 한 줄도 없었다** | 절 신설(로그 2개·`-I` 함정·`cewl -c` 형식 함정) | `try1_hydra_theme.log`·`try2_hydra_cewl.log`·`users.txt`·`pw_theme.txt`·`hydra.restore` |
| 6-3 `pwn@[192.168.45.207]` | 실제 사용한 로컬파트는 `catchx` | 정정 | `writeup_notes.txt` [18:58] |
| 6-3 "tcpdump 에 **0패킷**" | 그 필터의 캡처 파일은 **4139패킷**(hydra SSH·ICMP·443) | 「tcp/25 가 0패킷」으로 정밀화 + 캡처 구간 명시 | `reg_smtp.pcap` |
| 6-3 celery/25번 부재 | 서술만 있고 수치 없음 | ps·`ss -lntup`·exim4 패키지 버전으로 보강 | `harvest_root.txt` |
| 6-6 searchsploit 0건 | 근거 없음 → **재실행해 확인함** | `ruby-git` 0건도 추가 | Kali 직접 실행 |
| 남긴 흔적 "`last` 에 우리 세션이 없다" | 실제로 **2건 남았다**(tom 10:26 / root 10:28). 같은 문단 안에서 자기모순 | 원문 2행을 싣고 「비대화형은 wtmp 무기록, auth.log 는 전량 기록」으로 재서술 | `traces_confirmed.log` LAST/WTMP |
| 남긴 흔적 auth.log | `COMMAND=` 언급만 | 원문 2행 인용(`fetch.rb` + 실패한 `sudo -n -l` 의 `COMMAND=list`) + **흔적 확인이 로그를 늘린다**는 자기참조 추가 | 같은 파일 |
| 7장 | 항목 10 이하 재번호 | `id` 의 `groups=` 습관 · 비동기 큐 = "보냈습니다"의 의미 추가. 손절 "10분"→"9분" | — |
| 9장 "`git clone --branch weblate-4.11`" | Kali 에 그 clone 이 **없다** | 실제로 대조 가능한 raw URL 형태로 교체 | `ls ~/weblate` 부재 |

**삭제한 것 — 1건뿐이다.** 2장의 패치 서술. 원문:

> 4.11.1 에서 `--branch=<값>` 형태로 붙이고 `--` 구분자를 넣는 식으로 고쳤다.

근거: (a) 확인할 1차 사료를 손에 넣지 못했고 (b) 깊이 기준이 패치 diff 를 명시적으로 배제한다. 같은 취지의 일반화는 8장에 **일반 원칙 문장**으로 남겼다.

## 추가한 것

- **4장 「안 써먹은 세 번째 경로 — tom 이 `lxd` 그룹이다」.** `harvest_tom.txt:3` 과 `proof_user.txt` 양쪽에 `110(lxd)` 가 실재한다. **시도하지 않았으므로 `[가정]` 으로 명시**했고, lxd 데몬 기동 여부·이미지 유무는 **확인하지 않았다**고 적었다. 7장 10번에 `id` 의 `groups=` 를 끝까지 읽는 습관으로 승격.
- **6-2 hydra 절.** 노트 최대의 누락이었다.

---

## 내가 다시 반증한 것 (지적으로 올렸다가 철회)

1. **3-3 리버스셸 블록이 날조라고 의심했다 — 틀렸다.** `shell443.log` 에는 `listening on`·`connect to ... 57430`·`id;whoami` 출력이 **하나도 없다.** 「다른 실행의 출력 접합」 패턴에 정확히 들어맞아 보였다. 그런데 `reg_smtp.pcap` 에 `19:25:26.171960 IP 192.168.248.19.57430 > 192.168.45.207.443: Flags [S]` 가 있고, 블록 안 `date -u` 의 `10:25:44 UTC`(=KST 19:25:44)가 그 SYN 의 18초 뒤다. **캡처에 없는 값을 삽입한 것이 아니라 두 셸의 출처 표기를 뭉갠 것**이었다. 정정은 삭제가 아니라 출처 분리로 처리했다.
   덤으로 pcap 이 6-5(리스너 `| tee` 버퍼링)까지 뒷받침한다 — 첫 셸이 19:20:11 에 붙어 **19:25:25 까지 5분 14초를 살아 있었고** 작성자는 그걸 못 봤다. 노트 서술 그대로다.
2. **1장 `DEFAULT_PERMISSION_CLASSES = IsAuthenticatedOrReadOnly` 를 의심했다 — 노트가 옳다.** `settings_dump.txt` 의 `REST_FRAMEWORK` 행이 잘려 안 보였지만 `debug_traceback.html` 에 문자열이 실재한다.
3. **6-1 의 `accounts/models.py` 5행 인용을 의심했다 — 한 글자도 안 틀렸다.** `raw.githubusercontent.com/WeblateOrg/weblate/weblate-4.11/weblate/accounts/models.py` 와 대조했다.
4. **1장 META 의 `USER='tom'`·`HOME`·`SERVER_NAME='fikklish'` 를 의심했다 — 전부 실재한다.** `debug_traceback.html` 에서 파싱해 확인: `USER='tom'` / `HOME='/home/tom'` / `SERVER_NAME='fikklish'` / `LOGNAME='tom'`.
5. **cewl 빈도 `Traveler, 8 / Henry, 8 / Clare, 6 / Audrey, 4 / Niffenegger, 4` — 5개 전부 정확.** `cewl.txt` 10·12·44·45·60행.
6. **Editors Note 인용문 — `index80.html` 220~221행과 문자 단위로 일치.**
7. **btmp 10건 — 정확히 10행.**

## 직접 실행한 검증

- **git 인자 주입 재현** (로컬 git 2.50):
  ```
  git init -q . && git fetch poc --upload-pack='sh -c "touch /tmp/aud_hit"'
  → fatal: Could not read from remote repository.   /tmp/aud_hit 는 생성됨
  ```
  노트의 "**fetch 는 실패했는데 명령은 이미 실행됐다**" 가 그대로 재현된다. 이 재현 자체를 4장에 넣었다.
- `searchsploit weblate` / `searchsploit ruby-git` → 둘 다 **0건** (Kali).
- `hg` 는 Kali 에 **미설치**라 `--config=alias.X=!cmd` 는 직접 때려보지 못했다. ICMP 왕복이 실측이므로 동작 자체는 확정, 문법 설명은 그대로 뒀다.

## 프론트매터

- `tech/*` 6개 전부 볼트 실재 leaf 로 확인(`dirbust` 18 · `cmd-injection` 13 · `ssh-key` 12 · `cred/reuse` 12 · `sudo-abuse` 13 · `revshell` 52건 사용 중). **신규 태그 0건 — 작성자 보고가 맞다.**
- **브루트포스 태그는 붙이지 않았다.** hydra·웹 폼 브루트 **전부 실패**했고 비번은 사람이 고른 단어 하나로 뚫렸다. 기준은 "뚫는 데 실제로 썼는가" 이므로 태그 대상이 아니다. (참고: `tech/cred/brute` leaf 는 볼트에 존재하지 않고, `tech/cred/crack`·`spray` 는 이 박스와 의미가 다르다.)
- `manual_tags: true` / `manual_cves: true` **뒤에 주석 없음** 확인.
- `cves: [CVE-2022-23915, CVE-2022-25648]` — 둘 다 실제 악용. 반증용으로 언급한 CVE 없음.
- **Django DEBUG 정보노출에 해당하는 leaf 는 taxonomy 에 없다.** 작성자 보고대로 **발명하지 않았다.** 총괄 판단 대기 — 근거 스크린샷 `PG-Fikklish-django-debug.png` 는 본문 인용문(`The joined path ... outside of the base path component`)과 **문자 단위로 일치**함을 확인했다.

## 「관측 없음」·「확인하지 않았다」로 표시한 것

- `index.html` 의 `Last-Modified` 비교 (1장, `[가정]`)
- 첫 컴포넌트 생성이 어떤 예외로 끝났는지 (2장)
- Weblate 가 hg 를 두 번 부른다는 인과 (3-2, `[가정]`)
- `rev443b` 셸의 tmux 스크롤백 (3-3)
- `.psql_history` / `ls -la` / `gem list` 를 읽은 세션 화면 (4장)
- lxd 데몬 기동 여부·이미지 유무, lxd 경로 자체 (4장, `[가정]` — **시도하지 않음**)
- PostgreSQL 서버 로그 · redis 레이트리밋 키 잔존 · Apache access_log (남긴 흔적 — **원래 명시돼 있었다. 정확하다**)

## ⚠️ 감사자 자체 오류 — 규율을 반대로 적용했다 (2차 정정)

**타겟 pty 프롬프트를 「위반」으로 판정해 제거했다. 정반대다.** Kali 프롬프트(`┌──(kali㉿kali)`)를 붙이지 않는 규율의 목적은 **없던 화면을 지어내지 않는 것**이지, **실제로 있었던 대화형 셸의 표식을 지우는 것이 아니다.** 타겟 프롬프트는 이 프로젝트에서 **플래그를 웹셸이 아닌 대화형 셸에서 읽었다는 판정 근거**라 가장 보존 가치가 높은 증거다.

복원한 것 — **4개 행, 2개 절**. 전부 백업(`_backup/Fikklish.md.pre-audit`) 원문과 문자 단위 일치를 확인했다.

| 절 | 복원한 행 | 성격 |
|---|---|---|
| 4장 | `tom@fikklish:~$ gem list git` | 타겟 pty 프롬프트 |
| 3-3 | `<lib/python3.10/site-packages/data/vcs/poc/rev443b$ id; whoami; hostname; hostname -I; date -u` | 타겟 pty 프롬프트 + 실제로 친 명령 |
| 3-3 | `listening on [any] 443 ...` | tmux capture-pane 원문 |
| 3-3 | `bash: cannot set terminal process group (900)` / `bash: no job control in this shell` (rev443b 쪽) | tmux capture-pane 원문 |

3-3 은 블록을 둘로 나누면서 **두 번째 블록에서 명령 행과 리스너 배너까지 같이 떨어져 나갔다.** 원래 구조로 되돌리되, 출처 구분(`shell443.log` = 첫 셸 `rev443` / capture-pane = 두 번째 셸 `rev443b`)은 유지했다. `rev443$` → `rev443b$` 프롬프트 차이가 두 셸을 가르는 표식이라는 설명을 덧붙였다.

`┌──(kali㉿kali)`·`└─$` 는 **여전히 0건**이다. 그쪽 판정은 그대로 유효하다.

## 표기 규율

- **Kali 프롬프트(`┌──(kali㉿kali)`·`└─$`) 0건.** 노트는 새 규율을 처음부터 지켰다 — 전부 `ssh kali@10.44.44.128 "..."` 실호출 형태이거나 출처 캡션이 붙은 출력 블록이다. **위반 0건.**
- **타겟 pty 프롬프트 2곳 — 전부 보존한다.** 위 「감사자 자체 오류」 참조. 이건 위반이 아니라 실측 표식이다.

## 손대지 않은 것

`_STATUS.md` · `refresh.ps1` · `_INDEX/_tools/*` · 포털 · 브라우저 · 타겟 · tmux · `harvest.sh` · 다른 노트.
Kali 에서는 **읽기 전용 명령만** 냈다(`cat`/`grep`/`tcpdump -r`/`ls`/`searchsploit`). NFS 지연 없음.
