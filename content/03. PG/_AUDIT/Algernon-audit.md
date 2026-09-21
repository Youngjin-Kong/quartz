---
type: audit
target: "[[Algernon]]"
wave: 17
role: writeup-auditor
date: 2026-08-26
manual_tags: true
manual_cves: true
---

# Algernon — 적대적 검증 · 정정 기록

대조 기준 — `git show aba5a29:"03. PG/Algernon.md"`(1263행, 유일 이력) ↔ 현재본.
개작 후 686행 → 감사 후 **713행**. 정정 **8건**, 삭제 0건, 반증(노트가 옳았음) **9건**.

---

## 0. 최대 위험 두 건의 판정

### ⓐ 삭제폭 584행 — **손실 없음. 재현 가능성 유지**

원본 1263행 중 현재본에도 `_AUDIT\Algernon-playbook.md` 에도 없는 줄이 470행이나, **그중 실측 블록·명령·값은 68행**이고(나머지는 서술형→개조식 개작으로 문자열이 바뀐 산문·헤딩·중복) 내역은 아래와 같음.

| 분류 | 행수 | 판정 |
|---|---|---|
| Kali 프롬프트 `┌──(kali㉿kali)` / `└─$` | 22 | 규율대로 제거. **손실 아님**(§ⓑ) |
| `.NET` 프레임 조립 9줄(`msg += b'.NET'` …) | 9 | `Algernon-playbook.md:660-670` 에 이관 확인 |
| UTF-16LE 변환 명령 5줄 | 5 | 동 `:464-468` 이관 확인 |
| ysoserial 주석 3줄 | 3 | 동 `:806-812` 이관 확인 |
| tmux 주석 2줄 | 2 | 동 `:307-315` 이관 확인 |
| 오류였던 줄(`/scripts → /Scripts/`, `whoami; Get-Date`, 합성 `whoami; hostname; type`, 잘린 `psh_shell ...`) | 5 | **삭제가 정답**(§2) |
| `curl … grep -o` 2줄 · `echo $?` 1줄 · 분석 heredoc 10줄 · `alg80: 1 windows (created …)` 1줄 | 14 | **어디에도 없음** → curl 2줄은 **복원함**(정정 #5), 나머지는 아래 §3 에 원문 인용 |

**재현 가능성 — 유지됨.** 재현 임계 요소인 **1360바이트 패딩** 절(현 노트 `**⚠️ psh_shell 원라이너와 payload base64 는 절대 손대지 말 것 — 1360바이트 제약**` 이하)이 표·계산·실패 모드까지 그대로 살아 있음. Kali 에서 직접 재실행해 **노트의 수치 전량이 재현됨**(§4).

### ⓑ Kali 프롬프트 12 → 0 — **정당. 출력 손실 없음**

- 근거 확인: `~/.zsh_history` 에 `Algernon` 1건, `smartermail`·`telerik` 0건. `~/PG/Algernon/` 산출물 mtime 전량 `2026-08-20` → 비대화형 `ssh kali "..."` 세션. 프롬프트는 화면에 뜬 적 없음 → **창작이었음**.
- **①출력까지 지운 곳 0건.** 12개 블록 전부 명령만 `ssh kali@10.44.44.128 "..."` 실호출 형태로 교체됐고 뒤따르는 출력 블록은 원본 그대로.
- **②타겟 pty 프롬프트 전량 보존.** `PS C:\Windows\system32>` 가 붙은 블록 6개가 모두 남아 있고 `shell_session.log` 와 **바이트 일치**. 감사자가 이것을 제거하는 사고(Fikklish)는 재발하지 않음.
- **③** `Connection to … closed.` 는 원본에도 없었음 — nc 리스너 캡처라 애초에 안 나오는 문자열임. 대신 pty 증거는 `connect to [192.168.45.207] from (UNKNOWN) [192.168.248.65] 49731` + `PS …>` 프롬프트가 짐.

---

## 1. 고친 것 (8건)

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `⚠️ 근거는 **표준 위치 전수 확인까지**임. 전역 재귀 검색 … 하지 않았음(관측 없음)` | 🔴 **산출물이 반박함.** `shell_session.log` 8~9행에 `cmd /c "dir C:\ /s /b 2>/dev/null \| findstr …"` 가 **실제로 실행돼 있음**(출력 0줄). 「안 했다」가 아니라 「했는데 판정 불가」임 | 실측 블록을 복원해 싣고, `2>/dev/null` 이 Windows 리다이렉션이 아니라(`2>NUL`) 명령이 조용히 죽은 것으로 보인다는 `[가정]` 을 붙임. **「배제」가 아니라 「미완」**으로 명시(CLAUDE.md §3) |
| `whoami & hostname & ipconfig \| findstr IPv4 & type …` (```powershell 펜스) | 🔴 **틀린 일반 지식 + 내부 모순.** 이 박스의 셸은 PowerShell 원라이너인데 `&` 는 cmd 구분자임. 직접 때려 확인 — **Windows PowerShell 5.1 은 파싱 단계에서 거절**(`The ampersand (&) character is not allowed…`), **PowerShell 7 은 앞 명령을 백그라운드 잡으로 돌려 출력이 안 나옴**. 즉 노트가 권한 증거를 깨뜨리는 명령을 권고하고 있었음 | PowerShell 판(`;` 구분)을 정본으로 올리고, cmd 판은 ```bat 펜스로 분리해 「cmd 셸일 때만」 단서를 붙임. 두 셸의 실패 양상을 각각 명시 |
| `.NET 9 부터는 클래스 자체가 제거됨` | 부정확. 타입 자체는 호환을 위해 남고 **구현이 제거돼 호출 시 `PlatformNotSupportedException`** | `구현이 제거돼 호출하면 PlatformNotSupportedException 이 남` |
| `DOS 예약 장치명 여덟 개(aux·con·prn·nul·com1~3·lpt1~2)` | 개수 오류 — 나열이 **9개**(aux·con·prn·nul·com1·com2·com3·lpt1·lpt2). `gobuster_9998.txt` 도 9건 | `아홉 개` |
| `LHOST 15자 + LPORT=44444 \| 원라이너 +6자 → b64 약 +8자 → 1344` | 산술 오류. LHOST +1자 · LPORT +3자 = **+4자**. Kali 실측 재계산: 500 → 504자, b64 1336 → **1344**(최종값은 맞았음) | `원라이너 +4자 → b64 +8자 → 1344` |
| `17001 은 nmap-services 에 등재조차 없어` | 부정확. `17001/udp` 는 등재돼 있고 없는 것은 `17001/tcp` | `17001/tcp 는 …` |
| 근거 ①② `stProductBuild` · `login-v-` 출력 블록 | 값을 뽑은 **명령이 통째로 사라져** 재현 절차가 끊김(개작 시 Kali 프롬프트와 함께 유실, 이관 파일에도 없음) | git 원본에서 두 `curl … \| grep -o` 를 **복원**하고 `ssh kali@…` 실호출 형태로 표기. 캡션의 유보(응답 본문 미보존)는 유지 |
| `dean 의 Desktop 에는 … local.txt 는 애초에 배치되지 않음` | 바로 아래 추가된 「전역 검색 미완」 유보와 충돌 | `표준 위치 어디에도 local.txt 가 없음` — 근거 강도에 맞춰 강등 |

---

## 2. 삭제한 것 — 되살릴 수 있게 원문 인용

작성자가 개작 과정에서 지웠고 **감사 결과 삭제가 옳다고 판정한** 것들. 원문은 아래에 남김(git `aba5a29` 에도 있음).

### 2-1. `whoami; Get-Date` 블록 — 등급 `근거부족`, 삭제 유지

원본 §4-1:

```
PS C:\Windows\system32> whoami; Get-Date
nt authority\system

Wednesday, August 19, 2026 7:09:00 PM
```

- `shell_session.log`(1812B, 전량 확인)에 `Get-Date` 문자열이 **없음**. 출처 목록(`~/PG/Algernon/`·`파일보관\`·`~/.zsh_history`) 어디에도 없음
- 다만 **부재만으로 날조로 단정하지 않음.** 값 자체는 타임라인과 모순되지 않음 — nmap 의 `smb2-time: 2026-08-20T02:05:27`(UTC)와 `Aug 19 2026 19:09`(수요일, UTC−7)이 정합함. `shell_session.log` 는 `tmux capture-pane` 산출물이라 **스크롤백이 잘렸을 가능성**이 있음
- **등급 `근거부족`.** 재현·납득에 기여하지 않는 시각 정보라 복원하지 않음
- 같은 블록의 `systeminfo` 부분은 실제 로그(줄바꿈 80칼럼 포함)로 **이미 교체돼 있음** — 원본은 80칼럼 접힘을 손으로 편 «다듬어진» 형태였고, 그것이 실측 파괴였음

### 2-2. tmux 세션 생성 시각

```
# alg80: 1 windows (created Thu Aug 20 11:01:19 2026)
```
현재본·이관 파일 어디에도 없음. 산출물 mtime(`49216.py` 10:59:28 → `exploit_algernon.py` 11:00:09 → gobuster 11:03 → nmap.log 11:05:40)과 정합하는 값이나 **`tmux ls` 출력이 파일로 남지 않아 재확인 불가**. 재현에 불필요해 복원하지 않음.

### 2-3. 1360바이트 분석을 산출한 heredoc(10줄) · `echo $?`

원본 §2-7 의 `python3 - <<'EOF' … print('7bit len decode', …)` 10줄. 현재본은 **출력만** 남기고 캡션으로 출처를 적음. 소스 고고학 축소 취지에 맞아 복원하지 않았고, 대신 **감사자가 Kali 에서 직접 재실행해 출력 전량이 재현됨을 확인함**(§4).

---

## 3. 반증한 것 — 지적으로 올랐다가 «노트가 옳았던» 것 (9건)

검증 절차 자체의 정확도 판단용.

1. **코드블록 절단 의심 → 없음.** nmap 3종(668/3681/744B) · gobuster 2종(91/1797B) · shell 발췌 5종 · 49216.py 헤더까지 **14개 블록 전부 원본 파일과 바이트 일치**. 웨이브 15 의 「줄 중간 81바이트 절단」 유형 재발 0건. md5 불일치 **0**
2. **`Privilege Escalation` 4항목 생략 → 위반 아님.** 지시대로 정본. 실측 근거(`whoami` → `nt authority\system`, `Get-CimInstance … StartName : LocalSystem`)가 그 절에 **바이트 일치로** 실려 있고, 근본 원인(서비스 계정 강등)은 `Initial Access` 의 `Vulnerability Fix:` 4번째 항목이 담고 있음
3. **`### Initial Access` 두 개 → 위반 아님.** `_WRITEUP-STANDARD.md:97·114` 템플릿이 「긴 서술형 제목(4항목)」 → `Service Enumeration` → 「짧은 제목(재현)」 순서를 **명시적으로 규정**함. 현재본이 정확히 그 형태임. `Port Scan Results` 표 존재, nmap raw `PORT` 라인 34개 보존(`extract.py` `PORT_RE` 정상 동작)
4. **`manual_ports`·`manual_services` → 실재 필드.** `extract.py:173·175` 에 `MANUAL_SVC_RE`·`MANUAL_PORT_RE` 존재. **raw 훼손 없음** — `9998/tcp open distinct32` 와 `17001/tcp open remoting` 이 nmap 블록에 그대로 살아 있고 색인만 큐레이션됨. 오탐 `distinct32` 제거는 노트 본문의 「`-sS` 는 포트 번호로 표를 찍을 뿐」 서술과 정합
5. **CVE 오염 → 없음.** `CVE-2019-18935`·`Telerik` 문자열 **0건**. 프론트매터·절 제목·본문 전부 `CVE-2019-7214` 단일
6. **작성자 반증 ①(`/scripts` 정규 표기)** → `gobuster_9998.txt` 실물 확인. `/scripts → /scripts/`, `/Scripts → /Scripts/` 로 **각자 자기 표기 그대로** 리다이렉트. 원본이 `/scripts → /Scripts/` 로 적어 정규 표기를 단정한 것이 오류였음. 작성자 정정이 옳음
7. **작성자 반증 ②(top-1000)** → Kali `nmap-services` 직접 확인. `distinct32 9998/tcp 0.000304`, tcp 빈도순 **682위**, 1000위 빈도 `0.000152`, `17001/tcp` **부재**. 노트의 수치 전량 일치
8. **작성자 반증 ③④(로그 순서·합성 명령줄)** → `Get-ChildItem … Desktop` 행 순서가 `Microsoft Edge.lnk` → `proof.txt` 로 로그와 일치. 원본의 합성 `whoami; hostname; type proof.txt` 는 로그에 없고 실제는 `hostname; type …` 임 — 정정 반영 확인
9. **`TypeConfuseDelegate` 체인 주장 → 사실.** `49216.py` 의 base64 payload 를 디코드해 `SortedSet\`1` · `ComparisonComparer\`1` · `System.DelegateSerializationHolder` · `System.Diagnostics.Process` `Start` 문자열 확인. `_comparison` 필드 교체 구조까지 일치
10. **Metasploit 관련 주장 전량 사실.** `/usr/share/metasploit-framework/modules/exploits/windows/http/smartermail_rce.rb` — `Rank = ExcellentRanking`, `Opt::RPORT(9998, …)`, `OptInt.new('TCP_PORT', …, 17001)`, 설명문에 `patched in Build 6985, where the 17001 port is no longer publicly accessible, although it can be accessible locally at 127.0.0.1:17001` 원문 존재. `post/windows/gather/credentials/smartermail.rb` 도 실재. 「16.x 이하 포함, 빌드 6985 미만」도 모듈 설명 `<= 16.x or … < 6985` 와 일치
11. **스크린샷 대조 통과.** `파일보관\PG-Algernon-smartermail-login.png` 를 직접 열어 확인 — `Welcome to SmarterMail` · Email/Password/Language(English)/Remember Me/Login 만 있고 **버전 표기 없음**. 노트 서술과 일치

---

## 4. 감사자가 직접 실행한 검증

| 명령 | 결과 |
|---|---|
| `ssh kali … "md5sum ~/PG/Algernon/*"` · `wc -c` | 산출물 10개 목록·크기 확정 |
| `scp` 후 파이썬 부분문자열 대조 | 노트 코드블록 14개 ↔ 원본 파일 **바이트 일치** |
| `cd ~/PG/Algernon && diff -u 49216.py exploit_algernon.py` | 노트 diff 블록과 내용·타임스탬프 일치(경로 표기만 절대/상대 차이) |
| payload 디코드 재실행 | `prefix b'\x00\x00\xf2\n'` · `X count: 1360` · `34` · `7bit 1394` — **노트와 전량 일치** |
| `psh_shell` staging 재실행 | `500자 / 1000B / b64 1336 / ljust 1360 / pad 24` — **전량 일치**. 변형 검증: `LPORT=4444`→1340, `LHOST 15자+44444`→1344 |
| `grep 9998/tcp /usr/share/nmap/nmap-services` + 빈도 정렬 | `0.000304` · 682위 · 1000위 `0.000152` · `17001/tcp` 부재 |
| `grep -n 'RPORT\|TCP_PORT\|Rank\|127.0.0.1' smartermail_rce.rb` | 노트의 Metasploit 주장 전량 확인 |
| Windows PowerShell 5.1 `[scriptblock]::Create('whoami & hostname …')` | **PARSE ERROR** — `&` 금지 확인 |
| `pwsh -Command 'whoami & hostname'` (PS7) | `whoami` 가 **BackgroundJob 으로 빠지고** `kali` 만 출력 — 증거 파괴 확인 |
| `cat -A shell_session.log` | 80칼럼 접힘 확인(`tmux capture-pane` `[가정]` 지지) · `cmd /c "dir C:\ /s /b …"` 실행 기록 발견 |
| `Read 파일보관\PG-Algernon-smartermail-login.png` | 화면 내용 대조 |

## 5. 근거 출처

- Kali 산출물 — `~/PG/Algernon/` (`nmap.log` · `nmap_quick.log` · `nmap_lowrate_crosscheck.log` · `nmap_stdout.txt` · `gobuster_80.txt` · `gobuster_9998.txt` · `49216.py` · `exploit_algernon.py` · `shell_session.log` · `pg_algernon_smartermail_login.png`)
- `~/.zsh_history` — `Algernon` 1건 / `smartermail` 0 / `telerik` 0
- 볼트 — `파일보관\PG-Algernon-smartermail-login.png`
- git — `aba5a29:"03. PG/Algernon.md"`(1263행 원본, 유일 이력)
- 이관 대조 — `03. PG\_AUDIT\Algernon-playbook.md`(913행)
- 1차 사료 — Metasploit 모듈 소스 `smartermail_rce.rb`(벤더 어드바이저리 NCC Group 인용 포함), `/usr/share/nmap/nmap-services`(Kali nmap 7.98), Windows PowerShell 5.1 파서 직접 실행

## 6. 총괄에 올릴 것

- **색인 갱신 필요** — 프론트매터에 `manual_ports`·`manual_services` 가 신규 선언됐고 `services` 에서 `distinct32` 가 빠짐. `refresh.ps1` 은 공유 인프라라 감사자가 돌리지 않음
- **`_PLAYBOOK.md` 반영 미확인** — `Algernon-playbook.md` 제안 20건은 총괄이 반영 중이라 손대지 않았음. 다만 §2-2 의 `alg80` 세션 시각 1줄은 이관 파일에도 없으므로 반영 시 누락 확인 필요
- **`_STATUS.md` 판정** — Algernon **완료 1/1**(`proof.txt` = `6126cdddc1ed43d92e8a34f71ecda278`, `local.txt` 미배치). 기록은 `pg-line-manager` 몫
