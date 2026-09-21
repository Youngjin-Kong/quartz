---
tags:
  - type/audit
  - platform/pg
---
# Flimsy — 적대적 검증 + 정정 (2026-08-20)

대상: `03. PG/Flimsy.md` (718행 → 811행)
백업: `03. PG/_backup/Flimsy.md.pre-audit`
소요: 약 33분

> [!info] baseline 없음
> `git log -- "03. PG/Flimsy.md"` 가 비어 있다. 이 노트는 신규 생성이라 **개작 전 원본이 존재하지 않는다.** 따라서 "개작 후에만 등장하는 블록" 방식의 대조는 불가능했고, 전량을 산출물·1차 사료와 직접 대조했다.

## 근거 출처

- **Kali 산출물** `~/PG/Flimsy/` — 26개 파일 전수(`ls | wc -l` = 26 확인). 주로 `nmap_quick.log` · `nmap.log` · `gobuster_root.full.txt` · `try1_batch_probe.{sh,log}` · `try2_route_create.log` · `routes_preexisting.json` · `pane_full.txt` · `pane_root.txt` · `proof_user.txt` · `proof_root.txt` · `harvest_franklin.txt` · `harvest_root.txt` · `root_context.txt` · `traces_confirmed.log` · `traces_nginx.log` · `shell443.log` · `writeup_notes.txt`
- **볼트 스크린샷** `파일보관\PG-Flimsy-80-upright-decoy.png` — 직접 열어 확인. Upright 정적 템플릿, lorem ipsum, 하단 "Design:" 귀속 문구. 본문과 모순 없음
- **1차 사료** — apache/apisix `2.8` 태그 `conf/config-default.yaml`, `2.8` 및 `2.12.1` 태그 `apisix/plugins/batch-requests.lua`
- **Kali 직접 실행** — `dash -c '<페이로드>'` / `bash -c '0<&160-; echo survived'` / `sudo apt-get update` 전후 `history.log` diff / `grep` on `/usr/share/nmap/nmap-services`
- `~/.zsh_history` — **Flimsy 관련 항목 0건.** 이 박스의 Kali 명령은 전부 비대화형 `ssh kali "..."` 라 기록되지 않는다. 부재를 미실행 증거로 쓰지 않았다

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| §2 「우회 — batch-requests」 "하위 요청의 클라이언트 IP 를 호출자가 보낸 `X-Real-IP` 헤더에서 가져온다" | **2.8 의 `batch-requests.lua` 에는 클라이언트 IP 를 다루는 코드가 아예 없다.** 하위 요청은 `httpc:request_pipeline` 이 `127.0.0.1` 로 재발행하고, 호출자 헤더가 그대로 실릴 뿐이다 | 메커니즘을 ①루프백 재발행 ②헤더 무검증 두 갈래로 재서술. 2.12.1 의 수정 한 줄(`req.headers[real_ip_hdr] = core.request.get_remote_client_ip()`)을 인용해 근거를 붙임 | apisix 2.8 / 2.12.1 `batch-requests.lua` |
| §3 "안쪽만 넣으면 바깥 요청 자체가 걸러진다" | **반대다.** `set_common_header()` 는 본문 `headers` 를 먼저 깔고 바깥 헤더로 **빈 키만** 메운다. 안쪽이 우선이다. 그리고 `/apisix/batch-requests` 자체에는 IP 제한이 없다 — 우리 외부 IP 요청이 200 을 받은 것이 그 증거다 | 반증 사실을 그대로 적고 "본문 `headers` 하나면 된다"로 정정 | 같은 소스 + `try1_batch_probe.log` |
| §2 "IP 허용목록 — 기본값이 `127.0.0.1` 뿐" | 기본값은 `127.0.0.0/24` | 값 정정 + 기본 `viewer` 키(`4054f7...`) 존재도 추가 | apisix 2.8 `conf/config-default.yaml` |
| §1 "gobuster 를 끝까지 돌렸지만" | **끝까지 안 돌았다.** `gobuster_root.full.txt` 말미가 `[ERROR] ... timeout occurred` 로 도배돼 있다. 사전 소진이 아니라 21:38 강제 종료다 | 정정하고, "80 번에 없다"의 근거를 gobuster 완주가 아니라 **정적 템플릿**으로 옮김. 워드리스트·확장자·스레드도 명시 | `gobuster_root.full.txt` |
| §6-4 "처음 `grep -c` 로 395,013 이 나왔을 때" | grep 종류 차이가 아니다. **로그가 계속 자라고 있었다.** 395,013(21:35) → 419,537(`wc -l`, 21:36) → 419,573(`grep -F`, 21:36), 1분에 24,560행 증가 | 세 값을 시각·출처와 함께 표로 정리하고 인과를 "정지하지 않은 파일을 세면 어떤 카운트도 스냅샷이 아니다"로 교체 | `traces_confirmed.log` · `traces_nginx.log` |
| §6-4 블록 안 `-rw-r----- ... access.log` 줄 | `traces_nginx.log` 의 **다른 섹션**(`### nginx logs present`) 줄을 `wc -l` 출력 뒤에 이어붙여 놨다(비연속 행 이어붙이기) | 섹션 헤더를 살려 원문 순서대로 복원 | `traces_nginx.log` |
| 남긴 흔적 "`/var/log/apt/history.log` — 훅이 걸려 있던 동안의 `apt-get update` 항목" | **`apt-get update` 는 history.log 에 아무것도 쓰지 않는다.** Kali 에서 실행 전후 diff → 무변화. 산출물의 history.log 에도 `unattended-upgrade` 뿐이다 | "우리 항목 없음"으로 정정, 실행 검증 사실 명기 | Kali 직접 실행 + `traces_confirmed.log` |
| §3 PTY 승격 블록 | 실제 친 명령(`pty.spawn(\"/bin/bash\")`, `; id` 포함)이 `pty.spawn('/bin/bash')` 로 정리돼 있었고 PTY 에코가 제거돼 있었다 | `pane_full.txt` 원문으로 복원. 에코 doubling 이 이 노트의 실측 표식이라는 설명 추가 | `pane_full.txt` |
| §4 SUID · CAPS 블록 | 각각 26행 · 2행을 **생략 표시 없이** 잘라놨다 | 생략 행 주석 추가 | `harvest_franklin.txt:31-73, 98-105` |
| §5 "미끼 파일은 없었다" | 미끼를 찾아본 적이 없다. `find` 는 `local.txt`/`proof.txt` 만 겨냥했고 `harvest_root.txt` 의 FLAGS 섹션도 `local.txt` 한 줄뿐이다 | "관측이 없다"로 강등 | `pane_full.txt` · `harvest_root.txt:1492-` |
| §6-5 `[가정]` "인스턴스가 누적됐고" | 우리 산출물이 부분 반증한다. 12:33 `harvest_root.txt` PROCS 에는 `etcd` **1개** + APISIX 워커 **2개**뿐 — 12:16 부터 17회 돌았는데 누적이 없다 | `[가정]` 유지하되 반대 증거를 명시하고 gobuster 부하 쪽이 유력하다고 조정. **삭제하지 않았다** | `harvest_root.txt:376-382` |
| §2 `0<&160-` 해설 "fd 0 을 160 으로 옮기고" | 방향이 반대다(`n<&m-` 은 m→n). "자리를 비워두는 관용구"라는 근거도 없다 | Kali 실측으로 대체 — 160 이 안 열려 있어 `160: Bad file descriptor` 가 나지만 **다음 명령으로 넘어간다**(exit 0) | Kali `bash -c '0<&160-; echo survived'` |
| §1·§7-1 top-1000 일반화 | 근거가 "43500 은 그 안에 없다"뿐이었다(Hub 사례와 같은 형태의 약한 근거) | **43500 은 `nmap-services` 등재 자체가 없고**(top-N 을 아무리 키워도 후보에 못 든다), 9443 은 빈도순 1096위라는 실측 근거로 교체 | Kali `/usr/share/nmap/nmap-services` |
| 남긴 흔적 "21:36 UTC 12:36 이후" | 타임존 표기가 뭉개져 있었다 | `21:36 KST = 12:36 UTC` 로 정정 | — |

**추가로 명시한 것** (틀리진 않았으나 출처가 비어 있던 곳):
- §2 403 블록 — 파일로 보존되지 않았고 `writeup_notes.txt` 21:25 항목이 유일한 근거임을 콜아웃으로 명시
- §4 발화 블록(`ls -la /root` 포함) — tmux 스크롤백 원문이며 파일로 떨구지 않았음을 명시
- §6-5 `http=000` 블록 — 셸 상실 후 확인이라 보존 실패했음을 명시
- §4 `===== SUDO =====` 의 한글 괄호 줄 — `harvest.sh` 가 직접 찍는 줄임을 명시(다음 감사자의 오탐 방지)

## 2. 삭제한 것 — 2건. 둘 다 원문 아래 보존

### (a) §4 「확인」의 `ls -ld` 코드블록

```
franklin@flimsy:/tmp$ ls -ld /etc/apt/apt.conf.d /root
drwxrwxrwx 2 root root 4096 Aug 20 12:28 /etc/apt/apt.conf.d
drwx------ 9 root root 4096 Aug 20 12:18 /root
```

근거: ① 26개 산출물 어디에도 이 명령의 출력이 없다(`grep -rn 'drwxrwxrwx' ~/PG/Flimsy/` → `/tmp/.h` 만 히트) ② **PTY 에코가 없다.** 이 박스의 PTY 이후 타겟 블록은 예외 없이 명령이 두 번 찍히고 80칸에서 접힌다(`pane_full.txt`·`proof_user.txt`·`proof_root.txt`·§4 발화·§6-3 printf). 이 블록만 깨끗하다.

**사실 자체는 맞다** — `/etc/apt/apt.conf.d` 가 franklin 쓰기 가능(`harvest_franklin.txt` WRITABLE), `drwxrwxrwx`(`writeup_notes.txt` 21:30), `/root` 가 `drwx------ 9 root root ... Aug 20 12:18`(§4 발화 블록의 `ls -la /root` 첫 줄). 코드펜스만 걷어내고 이 세 근거를 산문으로 남겼다.

### (b) §6-5 의 Kali 프롬프트 코드블록

```
┌──(kali㉿kali)-[~]
└─$ echo ALIVE; /usr/bin/id; ...
uid=1000(kali) gid=1000(kali) ...
```

근거: 이 박스의 Kali 작업은 전부 비대화형 `ssh kali "..."` 이고 `~/.zsh_history` 에 Flimsy 관련 항목이 0건이다. `┌──(kali㉿kali)` 프롬프트가 찍힐 자리가 없다. **사실(페인이 Kali 로 돌아와 있었다)은 `writeup_notes.txt` 21:38~21:47 항목으로 확인되므로 산문으로 남겼다.**

> ⚠️ 타겟 프롬프트(`franklin@flimsy:...$`, `root@flimsy:/tmp#`)는 **하나도 건드리지 않았다.** 플래그를 대화형 셸에서 읽었다는 증거이므로 보존 대상이다.

## 3. 내가 반증한 것 — 지적으로 올렸다가 철회

| 의심 | 확인 결과 |
|---|---|
| §4 `===== SUDO =====` 안의 `(sudo -n 실패 — 비밀번호 필요)` — 산문 요약을 코드펜스에 넣은 것 아닌가 | **노트가 옳다.** `harvest_franklin.txt:29` 에 그 줄이 그대로 있다. `harvest.sh` 가 찍는 줄이다 |
| §2 dash `/dev/tcp` 서술 — "파싱에서 죽는다"가 맞나 | **노트가 옳다.** Kali 에서 페이로드 원문을 dash 에 던지니 `dash: 1: Syntax error: Bad fd number`. `/dev/tcp` 에 도달조차 못 한다. 오히려 실측 문구를 노트에 추가해 강화했다 |
| §5 플래그 블록의 UTC(12:28/12:33) vs Kali mtime KST(21:28/21:33) 불일치 | **모순 아님.** 정확히 9시간. 타임존 미환산 오판 사례를 피했다 |
| §4 발화 블록의 `ls -la /root` 22행 — 산출물에 없다 | **날조로 판정하지 않았다.** `pane_root.txt` 자체가 잘린 캡처(앞부분 소실)라 스크롤백 소실이 실증된다. `run.sh 154바이트`는 `root_context.txt` 와 일치한다. 등급은 `근거부족`, 조치는 출처 명시 |
| `routes_after_cleanup.json` 이 0바이트 — 산출물 훼손인가 | **원래 0바이트다.** APISIX 가 응답을 안 해서 비어 있었던 것이 정리 실패의 증거다. 21:52 실수 삭제 후 0바이트로 재생성된 내력이 `writeup_notes.txt` 말미에 있다 |
| CVE-2022-24112 영향범위 "1.3~2.12.0, 2.10.x 는 2.10.4 미만" | 벤더 권고("2.12.1 또는 2.10.4 로 올려라")와 일치. 노트 3곳(§1·§8·§9)이 서로 모순 없음. 정정하지 않았다 |

## 4. 감사 초점별 판정

**① 터미널 블록 vs 산출물** — 대조한 실측 블록 12개 중 **바이트 단위 일치 8개**(`nmap_quick.log`·`nmap.log`·`gobuster_root.txt`·`try1_batch_probe.{sh,log}`·`try2_route_create.log`·`proof_user.txt`·`proof_root.txt`·`pane_full.txt` 셸 블록). 손질 4개 = PTY 승격(복원), SUID·CAPS(생략 표기), §6-4(행 이어붙이기 정정). **출처 불명 3개** = 403 · 발화 · `http=000`(전부 출처 명시로 처리, 삭제 안 함). **완전 날조 0건.**

**② 플래그** — 재검증 불필요 지시대로 손대지 않았다. `proof_user.txt`·`proof_root.txt` 원문과 노트가 **줄바꿈 잘림(`dat\ne;`)까지 바이트 일치**함만 확인했다. 손질 없음.

**③ 작성자의 반증 3건** — 전부 근거 있음.
- (a) `nmap_quick.log`(22·80·3306) vs `nmap.log`(+9443, 43500) ✓ 그리고 43500 이 `nmap-services` 에 없다는 더 강한 근거를 추가로 붙였다
- (b) `routes_preexisting.json`·`try1_batch_probe.log` 에 `id=index`/`192.168.118.3`/`create_time 1658799753` ✓. 노트는 §2 콜아웃에서 이전 작업자 흔적을, 「남긴 흔적」에서 우리 것(`pwn1`)만을 다뤄 **명확히 분리**돼 있다
- (c) `root_context.txt` passwd-tail 에 `franklin:x:65534:65534::/home/frank:/bin/bash` ✓, `proof_user.txt` 가 `cd /home/franklin` 을 먼저 한다 ✓

**④ 남긴 흔적 3건** — 셋 다 정확히 적혀 있었다. `pwn1` 은 「남아 있다고 가정」(날조 아님), APISIX 불능은 기록됨(우리 책임 가능성 인정 문구를 강화), 419,573행/43,040,628바이트는 규모까지 기록됨(탐지 불가피성 자각 문구를 추가). 21:52 산출물 실수 삭제·복원 내력은 `shell443.log` 만 밝혀져 있어 `routes_after_cleanup.json` 을 추가했다.

**⑤ 권한상승** — `harvest_franklin.txt` 의 SUDO/SUID/CAPS 세 섹션이 "빈손이었다"의 근거로 실재한다 ✓. 크론 원문(`* * * * * root apt-get update`)이 `/etc/crontab` 인용으로 들어가 있어 "매분"의 근거가 재현 가능하다 ✓. 두 번째 경로는 `[가정]`·「실제로 사용하지 않았다」로 표기돼 있다 ✓.

**⑥ 프롬프트 표기** — Kali 창작 1건 제거, 타겟 프롬프트 전량 보존.

**⑦ 프론트매터** — leaf 7개 전부 볼트 실재(dirbust 16 / default-creds 12 / auth-bypass 5 / cmd-injection 10 / revshell 41 / cron 8 / suid 10건 사용 중). 7개 모두 실제 사용한 기법. `CVE-2022-24112` 등재 ✓. `manual_tags`/`manual_cves` 뒤 주석 없음 ✓. `ports` 에 43500 ✓. `Nmap scan report for 192.168.248.220` 두 블록 모두에 있음 ✓. **변경 없음.**

## 5. 관리자 판단이 필요한 것

없음. 공유 인프라·`_STATUS.md`·`refresh.ps1` 은 건드리지 않았다.

## 6. 수치

- 행수 718 → 811
- 삭제 2블록(둘 다 원문 위에 인용 보존, 사실은 산문으로 존치)
- 원문 복원 1건(PTY 승격), 생략 표기 2건, 행 이어붙이기 정정 1건
- 반증으로 정정 8건, 출처 명시 4건, `[가정]`/「관측 없음」 강등 2건
- Kali 프롬프트 위반 1건 → 0건
- 자기 지적 철회 6건

## 7. 추가 정정 (라인 관리자 지시, 2차)

| 위치 | 무엇을 | 근거 |
|---|---|---|
| 남긴 흔적 `pwn1` | 「남아 있다고 가정」 → **「삭제 확인 못 함 — 박스 정지로 해소」**. ①내가 한 것(21:38 DELETE 1회, 응답 없음, 검증 불가) ②어떻게 해소됐나(박스 정지·리버트, 내가 지운 게 아니다)를 표로 분리. 러너의 「남아 있다고 가정」 판단이 옳았다는 근거도 한 줄 남김. **「지웠다」로 쓰지 않았다** | `writeup_notes.txt` 21:38 항목 · `routes_after_cleanup.json` 0바이트 |
| §6 새 항목 (6) | 21:52 산출물 실수 삭제·복원 내력을 §6-2 콜아웃에서 **독립 절로 승격**. 일반화된 교훈("정리 충동이 향하는 파일이 바로 6장 재료다 — 지우고 싶어지는 건 언제나 작고 비어 있고 실패를 담은 파일이다")과 복원 절차 표(`shell443.log` 세션기록 복원 → `wc -c`=94 검증 / `routes_after_cleanup.json` 0바이트 재생성)를 함께 기록 | `writeup_notes.txt` 말미 |
| §6-2 콜아웃 | 중복을 걷어내고 **복원본 표기**만 남김 — 인용한 mtime `21:26` 은 관측값, 현재 디스크는 `21:55`, 내용은 94바이트 동일. (2차 지시 이전에도 이미 밝혀져 있었고, 문구를 더 명확히 했다) | `ls -la --time-style=full-iso ~/PG/Flimsy/` |

미접촉 확인: `_STATUS.md` · `refresh.ps1` · 포털 · 박스(정지됨) · `harvest.sh`/`harvest.ps1` · 다른 노트 전부.

---

# Flimsy — 3차 감사: OSCP 보고서 구조 개작 검증 (2026-08-26)

대상: `03. PG/Flimsy.md` **684행 → 732행**
개작 전 상태: `03. PG/_backup/Flimsy.md.bak` (796행, `pg-note-forge` 웨이브 11 직전 백업)
이관 제안: `03. PG/_AUDIT/Flimsy-playbook.md` (12건)

> [!info] baseline
> `git log --oneline -- "03. PG/Flimsy.md"` = 커밋 1건(`076525b`)뿐이라 git 원본은 여전히 없음.
> 대신 `_backup\` 에 4세대가 남아 있어 그것을 baseline 으로 씀 — `pre-audit`(718) → `pre-docreview-20260821`(811) → `.bak`(796) → 현재.
> 세대별 **타겟 pty 프롬프트 수는 전부 `franklin@flimsy` 8 · `root@flimsy` 3 으로 동일했고**, 개작본에서만 franklin 이 **7 로 줄어 있었음.** 그 1건이 아래 1-①.

## 근거 출처 (3차)

- `~/PG/Flimsy/` 26개 — `ls -la --time-style=full-iso` 로 mtime 전수 확인. 2026-08-20 21:23:26 ~ 22:19:49
- `~/PG/Flimsy/writeup_notes.txt` (9,295바이트, **본문이 KST 로 명시돼 있음** — mtime `+0900` 과 같은 축이라 환산 불필요)
- `~/.zsh_history` — Flimsy 관련 명령 **0건**. 이 박스는 전량 비대화형 `ssh kali "..."` 로 풀렸고, 노트에 Kali 프롬프트가 0건인 것이 그것과 일치함
- Kali 직접 실행 — `cat -A ~/PG/Flimsy/apt_hook_99zzpwn.conf` · `wc -c` · `strings /usr/lib/x86_64-linux-gnu/libmariadb.so.3` · `mariadb --version`
- 볼트 `파일보관\PG-Flimsy-80-upright-decoy.png` (1장. `Pasted image 20260820*.png` 는 0장이 정상)

## 1. 되살린 것 — 노트에서 사라지고 제안 파일에만 남아 있던 실측 4건

라인 관리자가 지목한 4건 전부 **실측으로 확인됨.** 전량 노트 본문에 코드블록으로 복원.

### ① `printf` 훅 깨짐 — 타겟 pty 블록 + `cat -A` 검증 (가장 중요)

개작본 516행이 이 두 블록을 **산문 한 줄로 요약**해 버렸음(「처음에 `printf` 로 원격에서 만들었더니 내용 끝에 리터럴 `n` 이 붙었음」). 동시에 **이 노트에서 유일하게 사라진 타겟 pty 프롬프트**가 여기였음.

**바이트 단위로 검증됨 — 날조가 아니다:**

| 검사 | 결과 |
|---|---|
| 블록 각 행의 열 수 | 명령 3행·출력 2행이 **전부 정확히 80칸.** tmux 80칸 페인 줄접힘과 일치 |
| `cat -A` 블록의 본문 길이 | 80 + 33 = **113바이트** |
| Kali `apt_hook_99zzpwn.conf` | `wc -c` = **114** = 본문 113 + 개행. `cat -A` 마지막이 `};$` — 블록과 한 바이트도 다르지 않음 |
| 깨진 파일 크기 `114` | `본문(113) + 리터럴 'n'` = 114. **크기가 같아 구분 불가**라는 점까지 산술로 맞음 |
| `traces_confirmed.log` `### files I created` | `-rw-rw-rw- 1 franklin nogroup 114 Aug 20 12:31 /etc/apt/apt.conf.d/99zzpwn` — 블록의 `12:30`(깨진 것) 다음 분에 교체된 것과 일치 |
| `writeup_notes.txt` 21:30 | 「[실패 2] printf 로 훅 파일을 만들었더니 내용 끝에 리터럴 'n' 이 붙었다 … cat -A 로 눈으로 보고 잡았다. 21:31 curl 로 교체」 |

→ `Privilege Escalation` 「훅 배치」 절에 두 블록 복원 + 위 산술 근거를 한 줄로 남김. `[!danger]` 콜아웃은 원인(`send-keys` 가 `\` 를 벗김)만 남기고 나머지는 [[_PLAYBOOK#B-84]] 로 링크.

### ② `shell443.log` 94바이트 블록 + 복원본 유보

`shell443.log` 실물 `cat -A` = 정확히 2행, 94바이트, 포트 **60714**. `pane_full.txt` 의 포트는 **60800** — **다른 연결**임.

개작본은 이 사고를 통째로 지웠는데, 그 결과 노트가 `## 관련` 에서 `shell443.log` 를 산출물로 나열하면서 ⓐ 그 파일이 왜 배너뿐인지 ⓑ **복원본이라는 사실**을 어디에도 적지 않게 됨. 복원본 표기는 「내용에 붙은 인식론적 표시」라 본문에 남아야 하는 것임.

→ `Initial Access` 「셸」 절에 블록 + 복원 유보(현재 mtime 21:55 / 관측 당시 21:26 / `wc -c` 94) 복원. 판별법·조치는 [[_PLAYBOOK#A-31]] 로 링크. 포트 60714 ≠ 60800 도 한 줄로 설명.

### ③ 재획득 실패 화면

개작본은 「43500 TCP open, HTTP 무응답」을 **증거 없는 단정**으로만 남겨 뒀음. 원문 블록(`http=000 time=12.002099` + 포트 상태)은 `writeup_notes.txt` 21:38~21:47 기록과 일치하나 **파일로는 보존되지 않았음.**

→ `Post-Exploitation` 에 블록 복원 + 「파일로 보존하지 못했음. 세션 기록에서 옮긴 것」 캡션. 재획득 4회(21:43~21:47) 사실도 복원.

### ④ 43500 응답불능 `[가정]` + 반대 증거

**반대 증거를 실측으로 재확인함** — `harvest_root.txt:376` 에 `etcd` pid 1143 (12:16 기동) **1개**, `:378`·`:382` 에 APISIX `nginx: worker process` pid 1365·1366 **2개**. 누적이 관측되지 않음. 제안 파일의 서술이 정확했음.

→ 노트 본문에 `[가정]` 과 **반대 증거를 함께** 복원. `[가정]` 만 남기고 반증 재료를 링크 너머로 보내면 그 자리에서 반증할 수 없어짐.

## 2. 정정한 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `gobuster_root.full.txt`(mtime 21:27) … 종료 시각은 21:38 | 개작본이 mtime 을 새로 끼워 넣어 **자기모순처럼 읽히게** 만듦. 실제로 이 파일은 **69행짜리 화면 스냅샷**(배너 12 + 결과 4 + 에러 50, `Progress:`·완료 배너 없음)이고 mtime 은 **스냅샷을 뜬 시각**임 | 「69행 스냅샷」임을 명시. 스캔이 21:38 까지 계속 돈 근거를 nginx `access.log` 성장(21:35 395,013행 → 12:36 UTC 419,537행)으로 제시. 「mtime 은 스캔 종료 시각이 아님」 한 줄 추가 |
| `harvest_franklin.txt:106` · `:1322` (WRITABLE 블록 아래) | **`:106` 은 `===== CRON =====`, `:1322` 가 `===== WRITABLE =====`** 임. 캡션 하나가 WRITABLE 아래에만 붙어 있어 `:106` 이 WRITABLE 을 가리키는 것처럼 읽힘. CRON 블록은 캡션이 아예 없었음 | 캡션 둘로 분리. CRON 에 `:106`(두 크론 줄은 `:131`·`:132`, `...` 는 주석 헤더 생략), WRITABLE 에 `:1322`(전문) |
| `ERROR 2002 (HY000) …` MySQL 블록 | **출처 캡션이 없는 유일한 터미널 블록**이었음(`.bak` 부터 그랬음) | 캡션 추가 — `writeup_notes.txt` 21:24 에는 `Host '…' is not allowed to connect` 부분만 있고 나머지는 세션 기록임을 명시. **날조는 아님**(아래 3-② 참조) |
| `traces_nginx.log` 캡션 | 원문에서 회전 로그 5개·`error.log`·샘플 7행을 **생략 표기 없이** 잘라 인용 | 캡션에 발췌 범위 명시 |
| 코드펜스 언어 태그 | 같은 종류(타겟 pty 세션 캡처)인데 `발화` 블록만 `bash`, `pane_full`·`proof_user`·`proof_root` 는 `text` | STANDARD 「세션 캡처 = `bash`」에 맞춰 3개 통일. **블록 내용은 한 바이트도 건드리지 않았음** |
| 「(위 스크린샷 · 고정된 `Last-Modified`)」 | 「위」 상대 참조 | 「이 절의 스크린샷」 |

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

### ① 작성자의 「gobuster 자기모순」 반증은 **틀렸음**

`pg-note-forge` 가 「§1 이 gobuster 종료를 21:38 로 적었는데 `gobuster_root.full.txt` mtime 은 21:27:23 이라 자기 산출물에 반박당한다」로 보고했음. **이것이 반증됨.**

- **타임존 문제가 아니었음** — `writeup_notes.txt` 첫 줄이 「(2026-08-20, KST)」로 명시하고 `ls` mtime 도 `+0900` 이라 같은 축임
- **21:38 쪽이 맞음** — `traces_confirmed.log` 가 21:35 에 우리 IP 395,013행, `traces_nginx.log` 가 12:36 UTC(=21:36 KST)에 419,537행을 기록함. 1분에 24,560행(≈400 req/s)이 늘고 있었으므로 **gobuster 는 21:35 시점에 확실히 살아 있었음.** 21:27 에 죽었다면 나올 수 없는 숫자임
- 파일 쪽이 스냅샷임 — 69행에 완료 배너·`Progress:` 가 없음

즉 **노트가 산출물에 반박당한 것이 아니라, 개작본이 mtime 을 잘못 해석해 끼워 넣은 것**임. 원본(`.bak`)에는 mtime 언급이 없었음.

### ② MySQL 오류 블록은 **날조가 아님**

`writeup_notes.txt` 에는 `Host '192.168.45.207' is not allowed to connect` 부분만 남아 있어 감싼 문구를 날조로 볼 여지가 있었음. **Kali 에서 직접 반증함:**

```
$ strings /usr/lib/x86_64-linux-gnu/libmariadb.so.3 | grep -i 'authenticity of the following'
Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: %d - %s
$ mariadb --version
mariadb from 11.8.3-MariaDB, client 15.2 for debian-linux-gnu (x86_64)
```

노트의 문구가 이 형식 문자열에 `%d`=1130, `%s`=`Host '…' is not allowed to connect to this MySQL server` 를 넣은 것과 **정확히 일치**함. 등급은 `근거부족`(로그 파일 없음)이지 날조 아님 — 캡션만 붙이고 **내용은 보존**.

### ③ 이관 손실 0 — 제안 파일이 ④항목에 전문을 보존하고 있었음

`_AUDIT\Flimsy-playbook.md` 12건 전부 ④에 지우기 전 원문을 **전문 인용**하고 있었고, 511~518행에서 작성자가 **「노트에서 완전히 사라지고 여기에만 남은 실측 블록 4건」을 스스로 명시**해 뒀음. 「삭제 건수 = append 건수」 검산표(§이관 손실 검산)도 실재함. 인과(「~해서」)·소요 시간·`[가정]`·출처 경로 전부 살아 있음. **영구 손실 0건.**

### ④ 터미널 블록 34개 내용 삭제 0 — 작성자 보고가 맞음

`.bak` ↔ 현재를 블록 단위로 대조함. 무출처 `$` 프롬프트 2블록(`nmap-services` grep · dash 테스트)이 명령/출력 분리 형식으로 바뀐 것뿐이고 **문자열은 그대로**임. 이 둘은 이 박스의 산출물이 아니라 Kali 확인분이므로 「Kali 프롬프트 창작」 규율상 `$` 를 떼는 것이 옳은 방향이었음.

### ⑤ 타겟 pty 프롬프트 — 잃은 것은 정확히 1건

`.bak` 8+3 → 개작본 7+3 → 현재 8+3. 잃었던 1건은 위 1-① 의 `franklin@flimsy:/tmp$` 이고 복원됨. **다른 곳에서 부재를 근거로 지운 흔적은 없음.**

### ⑥ 플래그는 대화형 셸에서 읽음 — 시험 0점 사유 없음

| | |
|---|---|
| `local.txt` `ad396f9bb652fedd964f20285dab04cd` | `proof_user.txt` — `franklin@flimsy:/root$` 프롬프트 + PTY 에코 + `whoami; id; hostname; hostname -I; date; cat` 한 화면. 12:28:10 UTC |
| `proof.txt` `0c8587812f2ae784dbb5642833405d2e` | `pane_root.txt` · `proof_root.txt` — `root@flimsy:/tmp#` 프롬프트, `euid=0(root)`, 12:33:07 / 12:33:22 UTC |

둘 다 `pty.spawn` 승격 후 원위치 `cat`. **웹셸 아님.** 값은 노트와 바이트 일치.

## 4. 삭제한 것

**없음.** 이번 사이클의 편집은 복원 4건 + 정정 6건뿐임.

## 5. 총괄 판단이 필요한 것

- **`services` 프론트매터** — 개작본이 `tungsten-https` 를 지워 `[http, mysql, ssh, ssl/tungsten-https]` 로 만들었으나, `services` 는 `extract.py` 자동 갱신 필드라 `manual_*` 선언이 없음. 다음 `refresh.ps1` 에서 되돌아올 수 있음. 손대지 않았음
- **색인 갱신 필요** — 본문이 바뀌었으므로 `refresh.ps1` 대상. **에이전트는 돌리지 않았음**(공유 인프라)
- **`_PLAYBOOK` 반영 시점** — 위 1-①·②·③·④ 블록이 이제 **노트와 제안 파일 양쪽에 있음.** STANDARD 는 메커니즘·재현 요건의 중복을 허용하나(제안 파일 388행이 같은 판단), 관리자가 `_PLAYBOOK` 에 append 할 때 A-31·A-32·B-84 쪽 사본을 「반사 카드용 요약」으로 줄일지 그대로 둘지는 단독 기록자 판단임

## 6. `_STATUS.md` 판정 (직접 수정하지 않음)

**Flimsy · Fundamental · 완료 2/2** — 유지. 근거는 위 3-⑥.

## 7. 미접촉 확인

`_STATUS.md` · `_PLAYBOOK.md` · `_WRITEUP-STANDARD.md` · `refresh.ps1` · `extract.py` · 포털 · 다른 노트 · Kali 산출물(읽기만) 전부 미변경. 새 `[[_PLAYBOOK#…]]` 앵커 생성 0건(기존 9개 그대로).
