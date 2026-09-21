---
type: audit
box: Compromised
work: adversarial-verify
---

# Compromised — 적대적 검증 · 정정 기록

대상 — `03. PG\Compromised.md` (신규 작성 531행)
근거 출처 — `~/PG/Compromised/` (`ssh kali@10.44.44.128`) · 볼트 `파일보관\PG-Compromised-*.png` 5장 · `03. PG\_AUDIT\Compromised-forge.md` · 규격 정본 `F:\project\DOC_TEMPLATE\`

**재조사 부재.** 박스 정지 상태이므로 `192.168.103.152` 접속 부재. 확인은 산출물·스크린샷·규격 정본 안에서만. 파일시스템 광역 탐색 부재.

---

## 1. 고친 것 — 14건

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `65528 포트가 filtered … ICMP·RST 응답이 억제된 상태` | **자기 산출물이 반박.** `recon-preflight.txt` 는 ping 2/2 수신·ttl 125 로 ICMP echo 정상 응답을 기록. 빌드 스크립트도 `netsh advfirewall firewall add rule … protocol=icmpv4` 로 ICMP 를 명시적 허용. nmap 원문의 경고는 `--defeat-rst-ratelimit` 로 인한 closed→filtered 오보 가능성이지 RST 억제 관측이 아님 | 방화벽 기본 정책(`blockinbound,blockoutbound` + tcp 80·443·ICMPv4 예외)을 filtered 사유로 제시, 135·139·445·5985 예외는 `[가정]` 표기. `-Pn` 은 「예방 조치이지 필수 조건 부재」로 강등 |
| `443/tcp 를 브라우저로 열면 IIS 기본 페이지가 «아니라» PSWA 로그온 폼` | **내부 모순 + 반증.** 같은 노트 111행이 「80 과 443 은 응답 본문이 동일한 IIS 기본 페이지(Size 703)」라 적음. `web-443/root.body` 703바이트 = IIS 기본 페이지, `root.headers` = `HTTP/2 200` | 「443 루트도 80 과 같은 IIS 기본 페이지」로 정정하고, PSWA 는 `/pswa/` → `/pswa/default.aspx?ReturnUrl=%2fpswa` → `/pswa/en-US/logon.aspx` 2단 리디렉트 경로임을 `web_pswa.html`·`pswa_login.html`·`pswa_logon.html` 근거로 기재 |
| 그림 5 캡션 `로그에서 꺼낸 값이 실제 로그인 자격증명임을 «웹 경로에서도 확인»` | **하지 않은 일을 했다고 서술(A-5).** 스크린샷은 입력만 된 로그온 폼(Sign In 결과 부재). `writeup_notes.txt` 09:39 — 「Administrator 는 gateway cannot establish a connection 으로 실패」 | 「이 경로는 미완 · 게이트웨이 오류로 세션 수립 실패(원인 미특정)」로 정정. 유효성 확인 근거를 WinRM(`proof_root.txt`)으로 명시. 캡션도 「투입 시점까지」로 축소 |
| 그림 3 캡션 `「Computer name」 필드에 대상 자신(compromised)을 넣어야` | **스크린샷과 불일치.** `PG-Compromised-pswa-logon-scripting-creds.png` 의 해당 필드 값은 `localhost`. 성공 화면(그림 4)도 "available to you on **localhost**" | `localhost` 로 정정. 500 반환 문구는 `error.aspx` 명시 |
| `smbclient -L 만 … 나머지 «셋»은 전부 실패` | 인용한 4개 명령 중 **2개가 smbclient 이고 둘 다 성공.** `svc/smb-shares-guest.txt`·`smb_enum.txt` 의 `=== smbclient -L guest ===` 절이 익명 절과 동일한 목록 반환 | 「익명(`-N`)과 guest 두 형태 모두 반환, `smbmap`·`rpcclient`·`netexec` 는 실패」로 정정. guest 가 통한 사유(빌드 스크립트 `net user guest /active:yes`) 추가 |
| `그 침묵의 정체는 「익명 접근 차단」이 아니라 «도구 측 실패»` | 관측(셋이 침묵)은 사실이나 결론(도구 측 실패)은 단정. 원인 특정 근거 부재 | 관측/결론 분리 — 「침묵이 익명 차단의 근거로 성립 부재」까지만 단정, 절단 지점은 「미특정」, impacket 공통점은 `[가정]`. 양성 대조로 `auth_test.txt`(자격증명 보유 시 `netexec` 가 `Scripts$ READ`·`Users$ READ` 정상 열거) 추가 → 실패가 널세션 경로 한정임을 근거로 제시 |
| `SMB 디렉터리 목록에는 «DH» 속성과 함께 그대로 표시` (2곳) | `DH` = Directory+Hidden. `profile.ps1` 은 파일이라 성립 부재. 게다가 `WindowsPowerShell\` 내부 목록은 산출물에 부재 = 그 파일의 속성 문자는 미관측 | 관측 가능한 것으로 교체 — 같은 목록의 `AppData DH`·`desktop.ini AHS` 를 예로 들고, 실제 증거는 「다운로드가 그대로 성립」(`loot_users/profile.ps1`)로 대체. `attrib +h` 사실 자체는 빌드 스크립트 143행이 뒷받침하므로 유지 |
| `같은 로그의 «다수» HostApplication= 줄은 freezeScript … -Enc 인수를 가진 줄 «하나»` | 실측 분포와 불일치. 154개 중 freezeScript 는 **8개**뿐이고 최다는 인수 없는 `powershell.exe` **96개**. `-Enc` 줄은 **8회 출현**(고유 1종) | 분포를 분모와 함께 기재(A-3). 「고유 1종이 8회 반복」으로 정정 |
| `빌드 스크립트 전문(204행)` | 204행은 **산출물 파일 전체 행수**. 1~40행은 인접한 다른 스크립트블록(cmdletization), 빌드 스크립트 본문은 41~199행 | 「204행 중 41~199행. 앞뒤는 인접한 다른 스크립트블록」으로 정정 |
| `harvest.ps1 의 WMI 계열 수집이 «전부 Access denied» 로 실패(systeminfo 포함)` | `harvest_scripting.txt` 가 보이는 것은 ①`systeminfo` 의 `cmd : ERROR: Access denied` ②서비스·서비스 바이너리 ACL·스케줄 작업 절의 **공란**. 공란 절에 Access denied 문구 부재이고 `systeminfo` 는 WMI 도구가 아닌 cmd 도구 | 관측된 형태 그대로 재서술 |
| `Windows PowerShell 클래식 로그(400/403/600)는 «세션 시작 시»` | 403 은 엔진 «정지», 600 은 프로바이더 시작. 「세션 시작 시」가 셋을 포괄하지 못함. 실측 로그 본문에도 `Engine state … None to Available` 19건 / `Available to Stopped` 18건 / Provider 351건이 공존 | 「엔진·프로바이더 수명주기 이벤트(400 엔진 시작·403 엔진 정지·600 프로바이더 시작)」으로 정정 |
| `-Enc·-Command 인수는 프로세스 생성 감사·클래식 로그·4104 에 «동시 잔존»` | 4104(스크립트 블록 로깅)와 4688(프로세스 생성 감사)은 **정책이 켜져 있을 때만** 기록. 무조건 잔존은 클래식 로그뿐 | 조건절 부가 |
| `— 출처: enum_whoami.txt (헤더 2행)` 아래 nxc winrm 2행 | 그 2행은 도구가 붙이는 `WINRM  192.168.103.152 5985  COMPROMISED` 접두를 지운 형태 = 코드펜스 안 편집(A-1) | 같은 명령의 **무편집 원문**을 보유한 `auth_test.txt` `=== nxc winrm ===` 절로 교체. 접두 포함 그대로 인용 |
| 인용 블록 생략 미표기 4곳 — `nmap_sv.log` · `smb_enum.txt` · `svc/smbmap-null.txt` · `recon.sh:398-405` | A-1 「잘랐으면 펜스 «밖» 에 생략 사실을 적을 것」 미이행 | 각 캡션에 생략 대상 명시. `smbmap-null.txt` 는 「진행 표시 스피너 문자 제거」 명시 |

### 부가 — 근거 출처 보강 (내용 변경 부재)

- `Everyone` 읽기 공유·`Everyone:(OI)(CI)R` ACL 주장에 빌드 스크립트 원문(`New-SmbShare … -ReadAccess 'Everyone'` · `icacls C:\users\scripting /grant:r "Everyone:(OI)(CI)R" /t`)을 인용으로 붙임. 종전에는 출처 부재 상태의 단정이었으나 **반증이 아니라 근거 보강**
- 권한상승 열거 절 앞에 실행 경로 한 줄 추가 — `nxc winrm -X` 비대화형 실행기(`wr.sh`) 경유라 출력에 셸 프롬프트 부재. 왜 그 블록에만 프롬프트가 없는지가 설명 부재였음

## 2. 삭제한 것

**없음.** 전 건 정정·강등으로 처리. 코드펜스 안 실측 출력·명령·IP·해시·플래그·자격증명은 무편집 유지. 유일한 펜스 내용 변경은 위 `auth_test.txt` 교체이고, 그것은 **편집된 인용을 무편집 원문으로 되돌린 것**.

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

| 초기 지적 | 반증 근거 | 판정 |
|---|---|---|
| **`Initial Access` H3 가 두 번 나오고 두 번째에 4항목 부재 = 구조 결손** | 규격 정본 `pg-machine.template.md` 54~56행 「골격 주의 1」 — **「`Initial Access` 가 두 번 나오는 것은 OffSec 공식 예시 4장 그대로. 앞은 4항목 요약, 뒤는 상세 재현」**, 그리고 「두 제목을 서로 다르게 지을 것」. 노트가 정확히 그 형태 | **노트가 옳음. 내 오독** |
| **`Initial Access` 가 `Service Enumeration` «앞»에 온 것은 순서 오류** | 같은 템플릿 118·136행의 절 순서가 그대로 `Initial Access` → `Service Enumeration` | **노트가 옳음** |
| **`Local.txt value:` 아래 증적 이미지 부재 = A-6 위반** | A-6 「매체 분업 — 화면은 그림, 터미널은 코드펜스. 터미널 «출력» 을 스크린샷으로 대체하지 말 것」. 노트가 그 사유를 본문에 명시 | **노트가 옳음** |
| **프론트매터 `ports` 에 49666 누락** | CLAUDE.md §5 — Windows 노트의 49152 이상 동적 RPC 는 **의도된 제외**. `Port Scan Results` 표와 nmap raw 에는 보존돼 있음 | **노트가 옳음** |
| **`gobuster-5985.txt` 0바이트를 「없음」으로 오기** | 노트가 5985 디렉터리 열거를 **언급 자체 부재**. 오기 성립 부재 | **지적 소멸** |
| 작성자 자기반증 ①「OS 는 Server 2016 이 아니라 **Server 2019 Standard**(Build 17763)」 | 세 근거 전부 확인 — `harvest_admin.txt:64-65` `OS Name: Microsoft Windows Server 2019 Standard` / `OS Version: 10.0.17763 N/A Build 17763`, `smb_enum.txt` `Windows 10 / Server 2019 Build 17763 x64`, `nmap-full.txt` `Aggressive OS guesses: Windows Server 2019 (92%)`. PSWA 화면 문자열을 「애플리케이션 고정 문자열」로 본 해석에 `[가정]` 표기 존재 | **진짜 반증. 유지** |
| 작성자 자기반증 ②「이 세션 tun0 은 `192.168.45.207` 이 아니라 **`192.168.45.247`**」 | `recon-preflight.txt` = `tun0=192.168.45.247`. 추가 확인 — Kali 현재 `ip -4 -o addr show tun0` = **`192.168.45.247/24`**, `~/.zsh_history` 의 `.247` 히트 0 / `.207` 히트 13(과거 세션분). 반대 근거인 `writeup_notes.txt` 머리글의 `.207` 은 손으로 옮긴 값 | **진짜 반증. 유지. 단 §5 로 총괄 이관** |
| 작성자 자기반증 ③「`smbmap` 과 nmap `smb-enum-shares` NSE 도 함께 침묵」 | `svc/smbmap-null.txt` = `Error occurs while reading from remote(104) on line 1015`, 공유 목록 부재. `svc/smb-nmap.txt` = 호스트 스크립트에 `smb2-time`·`smb2-security-mode` 만 존재, `smb-enum-shares`·`smb-os-discovery` 결과 부재 | **진짜 반증. 유지.** 단 「도구 측 실패」라는 결론 부분만 강등(위 §1) |
| 작성자 보고 「Kali 프롬프트(`┌──(kali㉿kali)`) 창작 부재」 | 노트 전문 grep — `kali㉿kali`·`└─$`·`┌──` 히트 **0** | **사실. 확인** |
| 작성자 보고 「스크린샷 5장, 6장째 창작 부재」 | 볼트 `파일보관\` 실재 5개 파일명과 노트의 `![[…]]` 5개 링크가 **정확히 일치**. 6번째 링크 부재 | **사실. 확인** |
| 「단정형 일반 지식」 3건 — `base64 -d \| iconv -f UTF-16LE`, `base64 -d \| tr -d '\0'`, `base64 -d \| gunzip` | Kali 에서 직접 실행. 각각 `FriendsDontLetFriendsBase64Passwords` / 동일 / `TheShellIsMightierThanTheSword!` 반환 | **전부 성립. 유지** |
| 「`(gv "*mdr*").name[3,11,2]-join''` = `iex`」·「문자코드 배열 = `Start-Sleep -Seconds 5`」 | `MaximumDriveCount` 의 `[3,11,2]` = `i`,`e`,`x`. 정수 배열 수동 변환 결과 `Start-Sleep -Seconds 5`. `enc_decoded.txt` 원문과 일치 | **성립. 유지** |
| 「`TestWebSite` 는 `Install-PswaWebApplication -UseTestCertificate` 가 생성하는 자기서명 인증서 표기」 | 벤더 문서가 아니라 **대상 내부 기록으로 확인** — 빌드 스크립트 128행에 `Install-PswaWebApplication -UseTestCertificate` 존재. `web-443/tls-cert.txt` = Issuer·Subject 모두 `CN=PowerShellWebAccessTestWebSite`, sha1WithRSA·1024bit 자기서명 | **성립. 유지** |
| 「빌드 스크립트 값 ≠ 실측 플래그」 함정 | 빌드 스크립트 181·183행이 `C2E7EA127C0445D64E2123D223E77545`·`216E3F48A242732F9ECE14CBC76A9334` 를 심고, 실측은 `bc8d255a2e4a76fd9182e6dd86a8f8db`·`3c1acd15f6e0489621429cfb29c1fa9a`. 노트의 표·서술이 둘을 정확히 가르고 「그대로 제출하지 말 것」 경고까지 기재 | **혼동 부재. 노트가 옳음** |
| 권한상승 인과 ①관측 | `enum_whoami.txt`·`harvest_scripting.txt` — `BUILTIN\Event Log Readers` S-1-5-32-573 소속. `enum_logs2.txt` — 클래식 154건 / Operational 340건. `log_winps_hostapp.txt:1776` — `-Enc` 블롭(3886자, `enc_blob.txt` 와 선두 일치). `dec.py`→`adminpass.txt` — `TheShellIsMightierThanTheSword!`. 빌드 스크립트 148~176행이 gzip→Base64→UTF-16LE→`-Enc` 생성 경로를 그대로 규정 | **관측 전량 사실** |
| 권한상승 인과 ②관측이 결론을 지지하는가 | `Event Log Readers` 없이는 `Get-WinEvent -LogName 'Windows PowerShell'` 이 성립 부재이고, `whoami /all` 상 다른 특권·그룹 부재(`SeChangeNotifyPrivilege`·`SeIncreaseWorkingSetPrivilege` 둘뿐, `BUILTIN\Users` 외 그룹 부재). 대체 경로 후보 부재 | **지지. 결론 유지** |
| 문체(A-4) | `~함`·`~임`·`~됨`·`~음` 및 서술형 종결 전수 grep — 히트 **0** | **위반 부재** |

## 4. 플래그 판정

**완료 2/2.** `_STATUS.md` 현재 기재는 `- [ ] Compromised `0/2`` (98행) — 갱신 필요. **직접 편집 부재**(§6 단독 기록자 규율).

| | 값 | 근거 |
|---|---|---|
| `local.txt` | `3c1acd15f6e0489621429cfb29c1fa9a` | `~/PG/Compromised/proof_user.txt` |
| `proof.txt` | `bc8d255a2e4a76fd9182e6dd86a8f8db` | `~/PG/Compromised/proof_root.txt` |

**ⓐ 실측 여부** — 두 산출물 모두 노트 인용과 바이트 일치. 빌드 스크립트 하드코딩 값과는 불일치하므로 로그 복사 아님.
**ⓑ 대화형 pty 여부** — **성립.** 두 파일 모두 `Evil-WinRM shell v3.7` 배너 → `Info: Establishing connection to remote endpoint` → 프롬프트 `*Evil-WinRM* PS C:\Users\scripting\Documents>` / `*Evil-WinRM* PS C:\Users\Administrator\Documents>` → `clear` 입력 → 본 명령 순으로 세션 흐름이 남아 있음. evil-winrm 은 WinRM PowerShell 원격 세션이지 웹셸 아님. 플래그는 원위치 `type C:\Users\…\Desktop\*.txt` 로 열람 — 파일 이동·다운로드 경유 부재.
**ⓒ 한 화면 형식** — **충족.** `whoami; whoami /groups …; hostname; ipconfig | Select-String IPv4; Get-Date…; type <플래그>` 가 한 명령으로 묶여 채점 3요건(권한·타깃 IP·플래그)이 같은 출력에 공존.

시각 정합 — `proof_root.txt` `Get-Date` = 2026-09-08 17:20:29 (-07:00) = 09-09 09:20:29 KST, 파일 mtime 09:21:03 KST. `proof_user.txt` `Get-Date -Format o` = 17:22:14.917 (-07:00) = 09:22:14 KST, mtime 09:22:36 KST. `harvest_admin.txt` 머리글 17:23:44 (-07:00) = 09:23:44 KST, mtime 09:42:46(SMB `C$` 회수 시점). **UTC/로컬 환산 후 모순 부재.**

## 5. 총괄 판단이 필요한 것

1. **`CLAUDE.md` §1 의 `VPN tun0 = 192.168.45.207` 이 현재 사실과 불일치.** Kali 현재값 `192.168.45.247`(`ip -4 -o addr show tun0` 직접 확인). 리버스셸 LHOST 를 못박은 줄이라 **다음 박스에 그대로 파급.** 공유 문서라 직접 수정 부재
2. **프론트매터 규격 분기.** `pg-machine.template.md` 는 `tier`·`machine`·`method`·`started`·`user_at`·`root_at`·`stuck_total`·`session_logged`·`tricks_logged`·`ledger`·`date` 를 요구하고 `platform: proving-grounds`·`tier/*` 태그를 씀. 볼트 노트는 `platform: pg`·`status: solved` 체계이고 **283개 노트가 그것을 상속.** Compromised 만의 결함 아님(같은 웨이브의 `BlackGate.md` 도 동일) → 노트 단위로 고칠 사안 아니라 **미수정**
3. **태그 `tech/win/event-log-readers` 는 볼트 신규 값.** taxonomy 는 공유 인프라 — 채택 여부 총괄 판정(`Compromised-forge.md` §5 와 동일 사안)
4. **`_STATUS.md` 갱신 필요** — 98행 `- [ ] Compromised `0/2`` → 완료 2/2. 기록 주체는 `pg-line-manager`
5. **색인 재생성 필요** — `refresh.ps1` 미실행(공유 인프라). 신규 노트 1건 + `_AUDIT` 2건 추가

## 6. `_PLAYBOOK` 이관 검사

`Compromised-forge.md` 대조 — 노트는 신규 작성이라 **삭제 0 / append 후보 8건(A 6 · B 2)**. 인과(「~해서」)·소요 시간(09:23~09:38 약 15분)·`[가정]`·출처 경로 전부 보존. 노트에 남긴 3건(SMB 도구 침묵 · evil-winrm 경로 오타 · 빌드 스크립트 플래그 불일치)은 각각 경로의 「왜」에 필요해 이중 기재가 아님. **이관 손실 부재.**

단 forge 파일 자체에 **본 감사에서 반증된 서술 3건**이 있어 `_PLAYBOOK` 반영 전에 정정함(반영 주체는 관리자):

| 위치 | 정정 |
|---|---|
| A-c 「대상 자신을 넣을 것(이 박스에서는 `compromised`)」 | 실제 입력값 `localhost` — 스크린샷 2장이 근거 |
| B-a 「`HostApplication=` 줄 «대부분»은 정기 실행(freezeScript)」 | 154개 중 freezeScript 8 · `powershell.exe` 96 · ISE 19 · `wsmprovhost.exe` 16 · `-Enc` 8(고유 1종). 분포 실측으로 교체하고 `sort -u` 권고 추가 |
| §3 표 「`harvest_scripting.txt` 의 WMI 계열 — 전량 `Access denied`」 | CIM 의존 절은 **공란**이고 Access denied 문구는 `systeminfo` 한 곳뿐 |
| A-a 「네 도구가 각기 다른 지점에서 끊긴 것」 | 절단 지점 미특정으로 강등 + 양성 대조(`auth_test.txt`) 추가 |

## 7. 수치

- 지적 제기 **28건** → 자기반증 단계에서 철회 **14건** → 실제 정정 **14건**(본문 12 · 캡션 2. 인용 생략 표기 4곳은 1건으로 계수)
- 대조 불가로 강등한 터미널 블록 **0개** — 노트의 터미널·코드 블록 34개 전부가 인용 산출물에 대응. 21개 인용 산출물 전량 직접 열람
- 행수 531 → 531 (정정은 전부 동일 행수 치환)
- 삭제 0 · `[가정]` 신규 부여 2(방화벽 예외 추론 · impacket 공통점)
- 문체 이관 **0건**
- 스크린샷 5/5 실재·파일명 일치, 창작 0
- Kali 프롬프트 창작 **0**, 타겟 pty 프롬프트 **3곳 전량 보존**

## A-2-1 이관 — 본문에서 내린 추정 (2026-09-09)

7차 개정 A-2/A-2-1 적용. 「관측 없음」·「미계측」·「해당 없음」·「원문 미보존」은 본문 유지, `[가정]`·「근거부족」은 본문 금지·감사 파일 소관. 노트 본문의 `[가정]` 3건을 아래로 내림. 「근거부족」은 원래 0건.

대상 박스 정지·Kali `10.44.44.128` ping·SSH 전부 timeout 이라 `~/PG/Compromised/` 산출물 재대조는 **확인 불가**. 이관은 본문 텍스트만으로 수행.

### 1. 방화벽 예외 추론 (본문 79행)

**원문 그대로:**

> 전체 65535 중 65528 포트가 `filtered (no-response)`. 빌드 스크립트가 방화벽 기본 정책을 `blockinbound,blockoutbound` 로 두고 tcp 80·443 과 ICMPv4 만 예외로 연 것이 원인이고, 열려 보이는 135·139·445·5985 는 그 뒤의 `New-SmbShare`·`Enable-PSRemoting -Force` 가 추가한 예외 `[가정]`.

**내린 것** — 「열려 보이는 135·139·445·5985 는 그 뒤의 `New-SmbShare`·`Enable-PSRemoting -Force` 가 추가한 예외」.

- **관측분** — 빌드 스크립트에 두 명령이 존재
- **추론분** — 그 두 명령이 그 네 포트의 방화벽 예외를 만들었다는 연결
- **근거 부재** — 방화벽 규칙 목록(`netsh advfirewall firewall show rule`)을 걷은 산출물 부재

**본문에 남긴 것** — 관측분만. 「빌드 스크립트가 방화벽 기본 정책을 `blockinbound,blockoutbound` 로 두고 tcp 80·443 과 ICMPv4 만 예외로 개방」. 65528 filtered 라는 결과를 설명하는 데 이것으로 충분.

**결론 동반 하향 부재** — 이 추론에 얹힌 결론 없음. 뒤따르는 ICMP·`--defeat-rst-ratelimit`·소요 시간 세 항목은 전부 독립 관측.

### 2. PSWA 화면 문자열의 출처 추론 (본문 119행)

**원문 그대로:**

> 세 근거가 같은 결론을 가리켜 **Windows Server 2019 Standard 확정**. 아래 PSWA 로그온 화면이 표시하는 「Windows Server 2016」·「© 2016 Microsoft Corporation」은 실제 OS 와 불일치 — PSWA 웹 애플리케이션이 보유한 고정 문자열로 판단 `[가정]`. **화면 문자열을 버전 판정 근거로 쓰지 말 것.**

**내린 것** — 「PSWA 웹 애플리케이션이 보유한 고정 문자열로 판단」. PSWA 설치본의 리소스 문자열을 직접 열어 본 기록 부재. 규격 A-2-1 이 예시로 든 것과 동일 문형.

**본문에 남긴 것** — 불일치라는 관측과 그로부터 서는 지시. 「화면 문자열을 버전 판정 근거로 쓰지 말 것」은 왜 불일치하는가와 무관하게 성립.

**결론 동반 하향 부재** — 「Server 2019 Standard 확정」은 nmap OS 추정·SMB 협상·`systeminfo` 세 근거에 얹힌 것이라 이 추론과 무관.

### 3. impacket 계열 공통점 추론 (본문 183행)

**원문 그대로:**

> 절단 지점 미특정 — `netexec`·`smbmap` 이 같은 `Error occurs while reading from remote(104)` 로 끊긴 것은 둘 다 impacket 계열이라는 공통점 `[가정]`.

**내린 것** — 「둘 다 impacket 계열이라는 공통점」. 두 도구가 같은 오류 문자열로 끊겼다는 것은 산출물 관측이나, **그 원인이 공유 라이브러리 계열이라는 귀속**은 추론. 두 도구의 의존 스택을 대조한 기록 부재.

**본문에 남긴 것** — 「절단 지점 미특정」(사실 서술)과 같은 오류 문자열로 절단됐다는 관측.

**결론 동반 하향 부재** — 이 절의 결론(「셋의 침묵은 「익명 접근 차단」의 근거로 성립 부재」)은 `smbclient -L` 이 같은 무자격 조건에서 목록을 반환했다는 양성 관측에 얹힌 것이라 그대로 유지.

### 4. 유지 토큰 확인

「원문 미보존」 3곳(238·429행의 개별 표기 · 561행 `## 관련` 의 총괄 항목), 「해당 없음」 3곳(518·546·547행), 「미특정」 2곳 전량 보존. 개작 전후 출현 수 동일. 삭제 0.

### 5. A-4L·A-4 정정 범위

- A-4L 200자 초과 11곳(35·79·112·119·140·183·240·334·362·440·527행)을 사실 단위 불릿으로 분해. 줄머리 볼드로 대상 표시
- A-4 명사형 어미 3곳 — 「권한상승 경로까지 열림」→「동시 개방」, 「`Documents\WindowsPowerShell\` 로 좁혀짐」→「로 축소」, 「gzip 스트림.」→「gzip 스트림 형태.」. 검사기 미검출분 3곳도 동반 정정 — 「같은 곳을 가리킴」→「지시」, 「이 조합을 짚지 못함」→「미포착」, 「우회가 섞여 있음」→「섞인 난독화 둘」
- 코드펜스 34개 내부·타겟 pty 프롬프트 3곳·`![[...]]` 5개와 캡션 전량 무편집

---

## A-2-1·A-4L 적용분 재감사 (2026-09-09, 2차)

대상 — 규격 정정 개작본(564행) 대 개작 전 원본 `03. PG\_backup\Compromised.md.pre-a2-20260909.bak`(531행) 행 단위 대조.
근거 — 규격 정본 `report.base.md` A-2·A-2-1·A-4·A-4L·A-5 · 두 파일 텍스트 · 검사기 `F:\project\DOC_TEMPLATE\bin\style-check.ps1`.

**미검증(대조 불가)** — Kali `10.44.44.128` ping·SSH 전부 timeout. `~/PG/Compromised/` 산출물 재대조 불가. 빌드 스크립트 원문의 방화벽 규칙 문구, 도구 출력 원문 대조가 여기 해당. **부재를 근거로 한 날조 판정 부재** — 등급 상한은 강등.

### 1. 고친 것 — 2건

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 83행 `- **원인** — … tcp 80·443 과 ICMPv4 만 예외로 개방` | **A-5 위반 — 표시만 뗀 자리에 결론 존치.** 원본 79행은 「80·443 만 예외로 연 것이 «원인»」 뒤에 「135·139·445·5985 는 `New-SmbShare`·`Enable-PSRemoting` 이 추가한 예외 `[가정]`」이 붙어 둘이 한 짝이었음. 추정만 내리자 「80·443 «만» 예외」가 65528 filtered 의 «원인» 으로 홀로 서서, 같은 노트 63행 `Port Scan Results`(TCP 7개 open)와 정면 충돌. 개작이 **없던 모순을 새로 만듦** | 「**원인**」 라벨과 「만」을 제거해 관측(기본 정책 `blockinbound,blockoutbound` + tcp 80·443·ICMPv4 명시 예외)까지만 단정. 설명되지 않는 나머지는 「열린 나머지 포트(135·139·445·5985·49666)의 예외 경로 미특정 — 방화벽 규칙 목록 미회수」로 별도 불릿 신설. 결론을 추정과 «함께» 내린 것 |
| 198행 `- **셋의 침묵은 …**` | **A-4L 분할이 지시 대상을 잃음.** 원본 183행은 「`netexec`·`smbmap`·NSE 셋이 동시에 침묵했으나」로 셋을 앞에 열거했으나, 분할 후 「셋」만 남아 159행의 `smbmap`·`rpcclient`·`netexec` 조합과 구분 불가 | 원본의 열거를 복원 — 「`netexec`·`smbmap`·NSE 셋의 침묵은」. 정보량 증감 부재 |

### 2. 삭제한 것

**없음.** 두 건 모두 정정. 코드펜스 34개 내부·타겟 pty 프롬프트 3곳·`![[…]]` 5개와 캡션 무편집.

### 3. 반증한 것 — 지적으로 올랐다가 확인 결과 개작본이 옳았던 것

| 초기 지적 | 반증 근거 | 판정 |
|---|---|---|
| **A-4L 분할 11곳이 원문에 없던 인과·수치·판정을 끼워 넣었다** | 원본 35·112·119·140·240·334·362·440·527행과 분할본을 행 단위 대조. 정보량 증감 부재. 어휘 교체는 「가리키고→지시」·「좁혀짐→축소」·「열림→동시 개방」 3건이고 셋 다 원문이 이미 담은 뜻(「겸해」·「이므로」) 안에 있음. 527행 산출물 목록은 파일명 21개가 순서까지 일치 | **9/11 무해. 나머지 2건만 §1** |
| **A-2-1 이관 3건이 「표시만 뗀 것」이다** | ②PSWA 화면 문자열(원본 119행) — 남은 문장이 규격 A-2-1 의 예시(69~74행)와 «문형까지» 동일. 「Server 2019 확정」은 nmap·SMB 협상·`systeminfo` 세 근거에 얹혀 독립. ③impacket(원본 183행) — 남은 결론이 `smbclient -L` 의 양성 관측에 얹혀 독립 | **②③ 은 작성자 보고가 옳음. ①만 반증** |
| **「결론 동반 하향 0건」이라는 작성자 보고가 틀렸다** | 3건 중 2건은 사실. **①만 오판** — 감사 파일 128행이 「뒤따르는 ICMP·`--defeat-rst-ratelimit`·소요 시간 세 항목은 전부 독립 관측」이라고만 검사하고, «같은 문장 앞부분의 「원인」 단정» 자체가 추정과 한 짝인 것을 못 봄 | **부분 반증** |
| **417행 「gzip 스트림」의 검사기 A-4 검출은 오탐** | 검사기 `$SuffixRe = '(함\|됨\|임\|음\|짐\|김\|옴\|감\|줌\|림)[.」]?$'` — `림` 이 어미 목록에 포함. 「스트림」의 `림` 은 외래어 음역의 일부이지 명사형 어미 부재. **작성자 주장이 옳음.** 우회 형태 「gzip 스트림 형태」도 어색 부재라 유지 | **작성자가 옳음** |
| **547행 「이 세션의 Kali tun0」이 A-5 「작업 조직」 서술이다** | 서술 대상이 조직·순서가 아니라 **공격 환경의 주소값**(S-13 수행 조건). VPN 재접속마다 바뀌는 값이라 「이 세션」이 유효 범위를 한정하는 기능을 짐 — 지우면 다음 세션에 오독을 부름 | **개작본 유지** |
| **유지 토큰이 개작으로 소실됐다** | 전수 grep — 「원문 미보존」 3(238·429·561행)·「해당 없음」 3(518·546·547행)·`[가정]` 0·「근거부족」 0. 개작 전후 동수 | **소실 부재** |
| **감사 파일 37·76·79·84·91행 A-4L 도 이번 스코프다** | 전부 1차 감사분. 이번 개작이 만든 것은 124행 1곳 | **스코프 밖** |

### 4. 검사기 결과

`style-check.ps1 -Path "03. PG"` 재실행 — **`Compromised.md` 위반 0건**(정정 후 재확인). 감사 파일 124행 A-4L(241자)은 불릿 3개로 분해해 해소.

**미해소 — 스코프 밖 1건.** `Compromised-audit.md` 38행 A-4(「설명 부재였음」). 1차 감사분이라 본 감사에서 미수정. 정정안은 「왜 그 블록에만 프롬프트가 없는지의 설명 부재」.

### 5. 플래그 판정

**완료 2/2.** 1차 감사 §4 의 ⓐⓑⓒ 검사를 그대로 승계 — 본 감사에서 뒤집힌 것 부재.

- **근거** — `proof_user.txt`·`proof_root.txt` 의 evil-winrm pty 세션 흐름과 원위치 `type`
- **`_STATUS.md` 98행 `- [ ] Compromised `0/2`` 갱신 필요** — 기록 주체 `pg-line-manager`. 직접 편집 부재

### 6. 수치

- 지적 제기 9건 → 자기 반증으로 철회 7건 → 실제 정정 **2건**(본문 2·캡션 0)
- 행수 564 → 565 (불릿 1행 신설)
- 삭제 0 · 코드펜스 편집 0 · 유지 토큰 증감 0 · `[가정]` 신규 0
- 검사기 `Compromised.md` **0건** · 감사 파일 124행 A-4L 해소. 스코프 밖 잔존 6건(1차 감사분 A-4 1 · A-4L 5)
- 문체 이관 0건
