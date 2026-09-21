---
type: audit
box: Compromised
work: forge
---

# Compromised — 노트 신규 작성 기록 · `_PLAYBOOK` 이관 원문

산출 노트 — `03. PG\Compromised.md`
근거 — `~/PG/Compromised/` (`ssh kali@10.44.44.128`) · 볼트 `파일보관\PG-Compromised-*.png` 5장

---

## 1. `_PLAYBOOK` 이관 원문 — 관리자 반영 대기

⛔ **`_PLAYBOOK.md` 직접 편집 부재.** 아래는 그 파일에 반영할 원문. 절 번호는 기존 절 제목 확인 후 관리자가 배정할 것 — 같은 증상 절이 있으면 그 밑에 append, 없을 때만 새 번호.

### A절 (증상별) 후보

#### A-a. "익명 SMB 가 막혔다" — 자동 도구 셋이 동시에 침묵했는데 실제로는 열려 있음

**증상** — `netexec`(nxc) `smb -u '' -p '' --shares` 가 `STATUS_ACCESS_DENIED` + `Error enumerating shares: Error occurs while reading from remote(104)`, `smbmap -u '' -p ''` 가 `[!] Something weird happened on (…) Error occurs while reading from remote(104) on line 1015`, nmap `smb-enum-shares` NSE 가 공유를 반환하지 않음, `rpcclient -U '' -N` 이 `NT_STATUS_ACCESS_DENIED`.

**반응** — **`smbclient -N -L "//<타겟>/"` 을 반드시 직접 칠 것.** Compromised(2026-09-09)에서 위 넷이 전부 실패하는 동안 `smbclient -L` 만 비표준 공유 `Scripts$`·`Users$` 를 반환했고, 그것이 전체 경로의 유일한 입구였음. `smbclient -U 'guest%' -L` 도 같은 목록 반환.

**왜** — 서버가 익명 목록 요청을 거부한 것이 아님. 절단 지점은 미특정 — `netexec`·`smbmap` 이 같은 `Error occurs while reading from remote(104)` 로 끊긴 것은 둘 다 impacket 계열이라는 공통점 `[가정]`. **자격증명 확보 후 같은 `netexec` 를 재실행하면 `Scripts$ READ`·`Users$ READ` 로 정상 열거되므로 실패는 널세션 경로 한정**(출처: `~/PG/Compromised/auth_test.txt`). 확실한 것은 **부정 결과 넷이 부재의 근거가 되지 못했다**는 것.

**일반화** — 「자동 판정을 부재/존재 근거로 쓰지 마라」의 SMB 판. 공유 열거는 도구 4종의 결과가 갈리는 대표 지점이므로 `smbclient -L` 을 최소 한 번은 수동으로 칠 것.

출처 — `~/PG/Compromised/smb_enum.txt` · `~/PG/Compromised/svc/smbmap-null.txt` · `~/PG/Compromised/svc/smb-nmap.txt` · `~/PG/Compromised/svc/rpcclient-null.txt`

#### A-b. "헤드리스 브라우저가 자기서명 HTTPS 를 못 찍는다"

**증상** — PSWA 의 `-UseTestCertificate` 자기서명 인증서를 대상으로:
- chromium 141 — `ERR_SSL_KEY_USAGE_INCOMPATIBLE`. **우회 플래그 부재**(`--ignore-certificate-errors` 로 넘어가지 않음)
- cutycapt(Qt WebEngine) — `net_error -202` (`ERR_CERT_INVALID`)
- playwright firefox — 브라우저 미설치
- `firefox --screenshot` — xvfb 아래에서도 파일 미생성
- `socat TCP-LISTEN:…,fork OPENSSL:…,verify=0` 프록시 — `curl` 은 302 정상 수신인데 **chromium 만 `ERR_CONNECTION_REFUSED`**(원인 미특정). 같은 chromium 이 `python -m http.server` 에는 정상 접속

**반응** — **python `requests` 기반 평문 HTTP 리버스 프록시를 세울 것**(`proxy.py`, 포트 18091). TLS 를 프록시가 종단하고 브라우저에는 평문 HTTP 만 보이므로 인증서 검증 자체가 소멸. 그 뒤 chromium·playwright 정상 렌더.

**비용** — 이 구간에서만 09:23~09:38 소요(작업 로그 기준 약 15분). 플래그는 09:20 에 이미 확보돼 있었으므로 전부 증적 확보 비용.

출처 — `~/PG/Compromised/writeup_notes.txt` · `proxy.py` · `pswa_shot.py` · `ff.log` · `shot_pswa_socat_test*.png`

#### A-c. "PSWA 로그인이 500 을 던진다" — 컴퓨터명 필드 id

**증상** — PowerShell Web Access 로그온 폼 자동 입력 시 서버가 `error.aspx` 로 500 반환.

**반응** — **컴퓨터명 입력 필드의 id 는 `targetNodeTextBox`.** `computerNameTextBox` 가 아님. 나머지는 `userNameTextBox` / `passwordTextBox` / `ButtonLogOn`. 이 필드를 비운 채 제출하면 서버가 500 을 던짐 — 접속 대상을 넣을 것. **이 박스에서 실제로 넣은 값은 `localhost`**(스크린샷 `PG-Compromised-pswa-logon-scripting-creds.png` 의 「Computer name」 필드, 그리고 인증 성공 화면의 "available to you on **localhost**"). 종전 기재 `compromised` 는 스크린샷과 불일치라 정정.

**미완** — Administrator 자격증명으로는 PSWA 인증이 `gateway cannot establish a connection` 으로 실패(원인 미특정). `New Session` 클릭도 프록시의 세션 공유 문제로 500 — **PSWA 콘솔 화면 캡처 미완.** scripting 인증 성공 화면까지만 확보.

출처 — `~/PG/Compromised/writeup_notes.txt` · `pswa_login.py` · `pswa_console.py`

#### A-d. "evil-winrm 으로 올린 파일이 안 보인다" — `upload` 절대경로 백슬래시 소실

**증상** — `upload` 두 번째 인수에 `C:\Users\scripting\Documents\h.ps1` 을 주면 백슬래시가 먹혀 **`C:UsersscriptingDocumentsh.ps1` 이라는 이름의 파일 하나**가 현재 디렉터리에 생성. 실행하려는 경로에는 아무것도 부재.

**반응** — evil-winrm `upload` 대상 경로는 **상대경로로 줄 것.**

**부수** — 그 오타 파일이 타겟에 잔존(원복 부재). 남긴 흔적에 기재 필요.

출처 — `~/PG/Compromised/writeup_notes.txt`

#### A-e. "긴 명령이 도는 중 send-keys 를 밀면 캡처가 엉킨다"

**증상** — evil-winrm 대화형 세션에서 긴 명령 실행 중 tmux `send-keys` 를 추가로 밀면 전부 stdin 큐에 쌓여 `capture-pane` 결과가 뒤엉킴.

**반응** — **비대화형 실행은 `nxc winrm -X` 로 래핑할 것.** Compromised 에서는 `wr.sh` 한 줄로 처리:

```bash
#!/bin/bash
# 비대화형 WinRM 실행기. usage: wr.sh '<powershell>'
nxc winrm 192.168.103.152 -u scripting -p FriendsDontLetFriendsBase64Passwords -X "$1" 2>&1 | sed 's/^WINRM  *192\.168\.103\.152  *5985  *COMPROMISED  *//'
```

대화형 pty 는 **플래그 열람 때만** 쓰고(채점 요건), 열거는 전부 비대화형으로 돌리는 분업.

출처 — `~/PG/Compromised/wr.sh` · `writeup_notes.txt`

#### A-f. "로그에서 찾은 플래그 값을 그대로 제출하면 오답"

**증상** — Compromised 의 빌드 스크립트가 이벤트 로그에 전문으로 남아 있고, 그 안에 플래그 값이 하드코딩돼 있음:

```powershell
Set-Content -path "C:\Users\Administrator\Desktop\proof.txt" "C2E7EA127C0445D64E2123D223E77545"
Set-Content -path "C:\Users\$user\Desktop\local.txt" "216E3F48A242732F9ECE14CBC76A9334"
```

그러나 실측은 `proof.txt` = `bc8d255a2e4a76fd9182e6dd86a8f8db`, `local.txt` = `3c1acd15f6e0489621429cfb29c1fa9a`. **둘 다 불일치.**

**반응** — **플래그는 인스턴스 기동마다 재생성.** 로그·빌드 산출물·백업·워크스루에서 발견한 플래그 형태 문자열을 그대로 제출하지 말 것. 유효한 것은 대화형 셸의 원위치 `type`/`cat` 결과뿐.

**값** — 「플래그는 인스턴스마다 재생성」이 **대상 내부 기록으로 직접 확인된 드문 사례.** 종래에는 포털 제출 실패로만 간접 확인됐음.

출처 — `~/PG/Compromised/build-script-from-eventlog.txt` · `proof_user.txt` · `proof_root.txt`

### B절 (기법 카드) 후보

#### B-a. `Event Log Readers` → PowerShell 클래식 로그의 `HostApplication=` 에서 자격증명 회수

**전제** — 대상 계정이 `BUILTIN\Event Log Readers`(S-1-5-32-573) 소속. 관리자 권한 불요.

**메커니즘** — PowerShell 은 두 계통에 기록:
- `Microsoft-Windows-PowerShell/Operational` 이벤트 4104 — **스크립트 블록 본문**
- `Windows PowerShell`(클래식) 이벤트 400/403/600 — **호출자의 명령줄 전체**를 `HostApplication=` 필드에 보존. `-Enc` 로 넘긴 Base64 인수도 원문 그대로

한쪽만 보면 절반을 놓침. Compromised 에서는 빌드 스크립트 전문이 4104, 관리자 비밀번호 블롭이 클래식 쪽에 있었음.

**절차**

```powershell
whoami /groups                                   # Event Log Readers 확인
Get-WinEvent -ListLog * | ? { $_.LogName -match 'PowerShell' }
Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 200 | % { $_.Message } | Select-String 'HostApplication='
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 400 | ? { $_.Id -eq 4104 } | % { $_.Message }
```

**걸러낼 것** — `HostApplication=` 줄은 대부분 무관. Compromised 실측 분포는 154개 중 인수 없는 `powershell.exe` 96 · `PowerShell_ISE.exe` 19 · `wsmprovhost.exe` 16 · 정기 실행 `C:\freezeScript\win10.ps1` 8 · `-Enc` 블롭 8(고유 1종). **`-Enc`·`-EncodedCommand`·`-Command` 인수를 가진 줄만** 볼 것 — 같은 줄이 이벤트 400/403/600 에 걸쳐 반복되므로 `sort -u` 로 접을 것.

#### B-b. UTF-16LE Base64 + gzip 다중 디코드

**식별** — Base64 문자열의 문자 사이에 널바이트가 끼어 디코드 전 원문이 `RgByAGkAZQBuAGQAcw…` 처럼 대문자·소문자·`A` 가 규칙적으로 반복하면 **UTF-16LE**. PowerShell `-Enc` 인수와 `[System.Text.Encoding]::Unicode` 계열이 전부 이 형태.

```bash
echo '<blob>' | base64 -d | iconv -f UTF-16LE -t UTF-8      # 채택한 형태
echo '<blob>' | base64 -d | tr -d '\0'                       # iconv 부재 시 대안
```

**2단 압축** — 디코드 결과 안에 `FromBase64String("H4sI…")` 가 보이면 그것은 **gzip 스트림의 Base64**(`H4sI` = gzip 매직 `1f 8b` 의 Base64 선두). 난독화 계층을 순서대로 벗길 필요 부재 — 정규식으로 `H4sI` 문자열만 뽑아 압축 해제.

```bash
echo 'H4sIAAAAAAAEAAvJSA3OSM3J8Sz2zUzPKMlMLQrJSMwLAYqW5xelKAIA07xkHB8AAAA=' | base64 -d | gunzip
```

Compromised 의 블롭에는 문자코드 정수 배열(`(83,116,97,114,116,45,83,108,101,101,112,…)` = `Start-Sleep -Seconds 5`)과 `(gv "*mdr*").name[3,11,2]-join''` = `iex` 우회가 섞여 있었으나 **전부 무시 가능** — 필요한 것은 gzip 블롭 하나.

출처 — `~/PG/Compromised/dec.py` · `enc_blob.txt` · `enc_decoded.txt` · `adminpass.txt`

---

## 2. 노트 본문에서 «지운» 것 = 위 이관분

노트는 신규 작성이므로 기존 본문 삭제 부재. 위 항목은 **처음부터 노트에 싣지 않고** 이 파일로 보낸 것. 삭제 건수 0 / append 후보 8건(A 6 · B 2).

노트에 «남긴» 것은 셋뿐이고, 전부 경로의 「왜」를 설명하는 데 필요해서 남김:
- 자동 SMB 도구 셋의 침묵 → `Service Enumeration` 절. 이 한 줄이 없으면 `smbclient -L` 을 왜 따로 쳤는지가 단절
- evil-winrm `upload` 경로 오타로 생긴 파일 → 「남긴 흔적」 표. 잔존 파일의 정체 설명에 필요
- 빌드 스크립트 플래그 값 ≠ 실측 → `Post-Exploitation`. 로그에 플래그가 노출된 박스라 오답 경로를 노트가 직접 차단해야 함

## 3. 「관측 없음」·미완으로 남긴 구간

| 구간 | 상태 | 사유 |
|---|---|---|
| PSWA 콘솔(세션 화면) 캡처 | 미완 | Administrator PSWA 인증이 `gateway cannot establish a connection` 으로 실패, `New Session` 은 프록시 세션 공유 문제로 500. 원인 미특정 |
| SMB 파일 회수 명령 | 원문 미보존 | 회수 결과는 `loot_users/`·`loot_scripts/` 에 보존 |
| 이벤트 로그 추출 명령 | 원문 미보존 | 산출물 `log_winps_hostapp.txt`(109KB)·`log_pshell_op_hits.txt`(115KB) 보존. 노트에는 동등 결과를 내는 재구성 형태를 「재구성」 표기와 함께 기재 |
| evil-winrm 접속 명령 | 원문 미보존 | 세션 캡처 `proof_user.txt`·`proof_root.txt` 보존 |
| `harvest_scripting.txt` 의 CIM 의존 절 | 공란 | 서비스·서비스 바이너리 ACL·스케줄 작업 절이 결과 없이 비었음. 오류 문구는 `systeminfo` 한 곳에만 남음(`cmd : ERROR: Access denied`) — 「전량 Access denied」는 산출물이 뒷받침하지 않으므로 정정 |
| 49666/tcp | 동적 RPC | Windows 노트 색인 제외 대역(≥49152). Port Scan Results 표와 nmap raw 에는 보존, `ports` 프론트매터에서만 제외 |
| gobuster 5985 결과 | 0바이트 | 빈 응답 수신 기록. 「없음」이 아님 |

## 4. 반증한 것 — 상세

### 4-1. OS 가 Windows Server 2016 이 아니라 **Server 2019 Standard**

지시받은 확정 실측은 「Windows Server 2016」. 산출물 대조 결과 셋이 전부 2019 를 가리킴:

| 근거 | 값 | 출처 |
|---|---|---|
| `systeminfo` | `OS Name: Microsoft Windows Server 2019 Standard` / `OS Version: 10.0.17763 N/A Build 17763` | `harvest_admin.txt` |
| SMB 협상 | `Windows 10 / Server 2019 Build 17763 x64` | `smb_enum.txt` |
| nmap OS 추정 | `Aggressive OS guesses: Windows Server 2019 (92%)` | `nmap-full.txt` |

「2016」의 출처는 **PSWA 로그온 페이지가 렌더한 문자열**(`Windows Server 2016` / `© 2016 Microsoft Corporation`). 스크린샷 `PG-Compromised-pswa-logon.png` 에서 직접 확인. 애플리케이션 고정 문자열로 판단하나 그 판단 자체는 `[가정]` — 확실한 것은 **화면 문자열과 `systeminfo` 가 불일치**한다는 것.

**이것이 「자동 도구·화면 판정을 근거로 쓰지 마라」의 또 다른 사례.** 노트 `Service Enumeration` 절에 세 근거와 불일치 사실을 함께 기재.

### 4-2. 이 세션의 Kali tun0 = **192.168.45.247**

`CLAUDE.md` 와 `writeup_notes.txt` 는 `192.168.45.207` 로 기재. 그러나 자동 생성된 `recon-preflight.txt` 는 `kali : kali / tun0=192.168.45.247`.

`writeup_notes.txt` 는 손으로 쓴 요약이고 `recon-preflight.txt` 는 인터페이스에서 직접 읽은 값이므로 **후자 채택.** 이 박스는 리버스셸·리스너 미사용이라 실질 영향 부재 — 노트에는 출처와 함께 기재하고 「LHOST 해당 없음」 명시.

### 4-3. 최종 권한은 SYSTEM 이 아니라 `compromised\administrator`

`proof_root.txt` 의 `whoami` = `compromised\administrator`, 그룹 `BUILTIN\Administrators`. SYSTEM 승격 부재이고 플래그 열람에 불요. 노트에 그대로 기재.

### 4-4. 확정 실측 목록의 나머지는 전부 산출물과 일치

포트·자격증명 2쌍·플래그 2개·공유 이름·`Event Log Readers` 경로·시행착오 5건·타겟 잔존물 목록 — 대조 결과 불일치 부재.

## 5. 태그 판정 — 총괄 확인 필요

`manual_tags: true` 로 4개 선언. 그중 **`tech/win/event-log-readers` 는 볼트에 선례 부재 = 신규 값.**

- 기존 `tech/win/*` — `alwaysinstall`·`gui-lpe`·`potato`·`scheduled-task`·`sebackup`·`sedebugprivilege`·`seimpersonate`·`serestore`·`service-abuse`·`sticky-notes`
- 이 박스의 권한상승은 특권(Se*)도 서비스도 아닌 **그룹 멤버십을 통한 로그 열람**이라 기존 값 중 대응 부재
- 태그 taxonomy 는 공유 인프라이므로 **채택 여부는 총괄 판정.** 반려 시 `tech/cred/config-file` 만 남기고 삭제하면 됨

나머지 셋(`tech/svc/smb`·`tech/cred/config-file`·`tech/exec/winrm`)은 전부 기존 값.

## 6. 색인 파이프라인

`refresh.ps1` 미실행(공유 인프라). 노트 1건 신규 작성이므로 **다음 웨이브 종료 시 재생성 필요.**
