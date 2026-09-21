---
tags:
  - type/audit
  - platform/pg
---
# Osaka — 적대적 검증 감사 (2026-08-26)

대상: `03. PG\Osaka.md` (1387행 `.bak` → 610행 개작본 → **624행** 정정본)
검증자 = 정정자 동일. 타겟에 패킷을 보내지 않음 — 산출물·git·`~/.zsh_history`·1차 파싱 대조 전용.
개작 전: `03. PG\_backup\Osaka.md.bak` · 개작 직후: `03. PG\_backup\Osaka.md.post-forge.bak`

## 0. 최종 판정

- **날조 0건.** 실측으로 반증된 서술 없음. 코드펜스 15개 중 실측 원본이 존재하는 것은 **전부 바이트 일치**.
- **정정 7건** — 인식론적 표시 복원 2 · 실측 복원 2 · 인과 정정 1 · 근거 정정 1 · 보강 1
- **철회한 자기지적 4건** (§4)
- **이관 손실 4건** — 감사자가 `Osaka-playbook.md` 에 제안 11~13 + 제안 6 정정으로 보완(§3)

## 1. 코드블록 바이트 대조 (지목 ⓑ·ⓓ)

스크립트로 `.bak`·정정본·Kali 원본 3자 대조. 육안 검사 없음.

| 펜스 | 크기 | 판정 |
|---|---|---|
| nmap raw (`### Service Enumeration`) | 3,672B | `~/PG/Osaka/nmap.log`(3,673B) 와 **바이트 일치** (차이는 파일 말미 개행 1B). raw `PORT` 행 전량 보존 — `extract.py` `PORT_RE` 정상 |
| 전체 익스플로잇 (`from pwn import *`) | 3,201B | `~/PG/Osaka/exploit.py`(3,202B) 와 **바이트 일치**. ROP 가젯 16개 주소·셸코드 27행 전부 무손실 |
| ROP 체인 발췌 | 736B | `exploit.py` 의 verbatim 부분문자열 |
| 셸코드 27행 | — | `~/PG/Osaka/shellcode.txt` 와 행 단위 완전 일치 |
| `USER/PASS` 발췌 · `DEBUG %x` 발췌 | 135B·36B | verbatim 부분문자열 |
| 헥사덤프·실행 로그·`whoami /priv`·SYSTEM 셸 | — | `.bak` 과 동일 |

**불일치 3건 / 실손실 2건:**

1. **베이스 역산 펜스 — 원본에 없는 주석이 추가돼 있었음 (실손실).** 개작본:
   ```
   leak_pie = int(leak[0], 16)     # 0x012d10f0
   bin_base = leak_pie - 0x10f0    # 0x012d0000
   ```
   `exploit.py` 원본은 주석이 없고 그 사이에 `leak_ntdll = int(leak[4], 16)` 이 있음. **원문 3행으로 복원**하고 값 해설은 펜스 밖 산문으로 옮김.
2. **`certutil` 세션 캡처 중간 5행 삭제 (실손실).** 타겟 pty 캡처(`C:\Users\Wilson\Desktop>ls` → `'ls' is not recognized...`)가 연속 캡처 한가운데서 잘려 나감. 세션 캡처를 손으로 편집한 것이라 **복원함**. 펜스 크기 1,472B → 1,594B(`.bak` 과 동일).
3. **`local.txt` 펜스 말미의 공백 3칸 줄 제거 (무해).** 명령·출력·값 변화 없음 — 복원하지 않음.

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| ``회수한 `~/PG/Osaka/ftp.exe`(55,971바이트)에서 `strings` 로 발견한 경로`` | ① 회수된 `ftp.exe` 로는 `strings` 가 **불가능**함(§4-1) ② `smbclient -L` 을 근거로 FTP 확보 경로를 통째로 `[가정]` 강등한 것은 과잉(§4-2) | 확보 경로는 `ftp 192.168.243.20`(히스토리)로 확정 서술, `smbclient -L` 이 근거가 못 되는 이유 명시. **`DEBUG` 발견 경로만** `[가정]` 으로 분리 강등하고 그 근거(`.rdata` 부재·`strings` 0건)를 실측으로 기재 |
| `` `admin:admin` 으로 로그인 성공`` 뒤 | `.bak` 227행의 「이 자격증명을 어떻게 얻었는지는 원문에 기록되지 않았다 … [가정]」 **인식론적 표시가 개작에서 소실**. 표시는 「본문에 남는 것」 | 한 줄로 복원 — 「산출물에도 히스토리에도 없음 … 확정 불가 [가정]」 |
| `전송이 중간에 끊긴 쪽에 더 가까움 — 원인은 확정 불가` | 추정을 단정에 가깝게 서술하면서 `[가정]` 표시 없음 | `[가정]` 명시. 더불어 `file ftp.exe` 가 `MS-DOS executable, MZ for MS-DOS` 로 답하는 실측을 근거로 추가 |
| ``주석 `# EDX = 0x1000 (size)` 는 mona 템플릿의 오기`` | 오기라는 판정은 옳으나 **mona 귀속은 미검증** — 그 주석은 `exploit.py` 원본 주석 | 「`exploit.py` 원본 주석 … 는 오기」로 귀속만 정정. `0x1000 = MEM_COMMIT`·크기는 `EBX` 라는 실질 판정은 유지 |
| `` `/DYNAMICBASE`·`/NXCOMPAT`는 이미 적용돼 있었으나(… PE 헤더 재검증 근거)`` | `/GS` 부재는 **PE 헤더로 확인되지 않음**. 헤더 근거로 뭉뚱그림 | 헤더로 확인되는 것(`DllCharacteristics=0x8140`, `GUARD_CF` 부재)과 익스플로잇 성공으로 추론되는 것(`/GS` 부재)을 갈라 서술 |
| `**남긴 흔적**` | Initial Access 가 파일을 남기지 않았다는 사실이 없음 | 「셸코드는 `RETR` 인자로 메모리에만 전달, `VirtualAlloc` RWX 스택 페이지」 한 줄 추가 |
| `certutil` 펜스 · 베이스 역산 펜스 | §1-1·§1-2 | 원문 복원 |

**삭제한 것: 없음.**

## 3. 이관 손실 — 자기신고 검산 (지목 ⓒ)

`Osaka-playbook.md` 10건은 **전부 ①②③④ 형식을 갖췄고 ④에 원문 인용이 실재함.** 자기신고는 형식상 참.

추적 지목 2건:
- `### "커스텀 서비스를 만났다" → 이 순서로 움직인다` (`.bak` 520행) → **제안 1** 에 6단계 전량 + 「3번과 4번 순서를 바꾸지 말 것」 경고까지 보존됨 ✅
- `### 2-11. 완화 기능 조합별 판단 트리` (`.bak` 487행) → **제안 3** 의 「ASLR/DEP 조합별 필요 작업량」 표로 보존됨 ✅

**그러나 제안 10건이 `.bak` 삭제분을 다 덮지 못함.** 아래 4건이 어느 제안에도 없음 — 감사자가 `Osaka-playbook.md` 말미에 **제안 11~13 + 제안 6 정정**으로 추가함.

| `.bak` 위치 | 내용 | 처리 |
|---|---|---|
| 1084~1107행 `② ls를 쳤다 — Linux 반사` | Linux↔cmd↔PowerShell 대응표 8행 + PowerShell 전환 판단 | 제안 11 신설 (실측 캡처는 노트 본문에 복원) |
| 1200~1215행 `⑧ 32비트인지 64비트인지` | 아키텍처 판정 4가지 신호 표 + 「OS가 x64라도 서비스는 x86」 | 제안 12 신설 |
| 1217~1235행 `⑨ 원샷 익스플로잇` | 발사 전 5항목 체크리스트(리스너·LHOST·포트·assert·베이스) | 제안 13 신설 |
| 769~778행 `Windows 셸을 잡자마자 칠 명령` | `whoami /priv` 우선 명령 6줄 | 제안 13 에 병합 |

**제안 6 의 반증 1건** — 「파일은 생기고 `file` 은 여전히 `PE32 executable` 이라 답함」은 **이 박스에서 거짓**. 실측: `file ftp.exe` → `MS-DOS executable, MZ for MS-DOS`. PE 시그니처가 1바이트 밀려 `file` 이 PE 파싱에 실패하기 때문. 제안 6 본문에 정정 각주를 달아 둠.

## 4. 반증한 것 — 지적으로 올랐다가 철회

1. **「`ftp.exe` PE 158,208바이트 계산은 창작이다」 → 철회. 노트가 맞음.**
   `~/PG/Osaka/ftp.exe` 를 직접 파싱: 섹션 5개(`.text` RawPtr 1024/RawSize 116736, `.rdata` 117760/32256, `.data` 150016/2560, `.rsrc` 152576/512, `.reloc` 153088/5120) → **max raw end = 158,208 정확히 일치.** 실제 55,971B = 35.4%, 결손 102,237B = 64.6%. `e_lfanew=0x100` 인데 `PE\0\0` 은 `0xff` — 1바이트 밀림도 재확인. `DllCharacteristics=0x8140`(`DYNAMIC_BASE`+`NX_COMPAT`+`TERMINAL_SERVER_AWARE`, `GUARD_CF` 없음)·`ImageBase=0x400000`·`Machine=0x14c` 전부 노트대로.
   ⚠️ 다만 **부수 발견**: `.rdata` 가 통째로 없어 이 사본에는 문자열 리터럴이 하나도 없음(`strings -a | grep -ci 'ftp|user|pass|debug|retr'` = **0**). 그래서 「이 파일에 `strings` 를 걸어 `DEBUG` 를 찾았다」는 서술만 성립하지 않음 → §2 에서 그 부분만 강등.

2. **「FTP 확보 경로 `[가정]` 강등이 과잉이다」 → 지적 유지, 강등 되돌림.**
   관측(`smbclient -L //192.168.243.20 -N` 이 히스토리에 있음)은 **사실**이나 결론을 **지지하지 않음**. `-L` 은 공유 «목록 나열» 전용이라 파일을 가져올 수 없고, 전송용 `smbclient //<타겟>/<공유>` 호출은 히스토리에 **없음**. 반대로 `ftp 192.168.243.20` 은 히스토리에 있고, ascii 모드형 1바이트 밀림이라는 손상 모양은 SMB(바이트 정확 전송)로는 설명 불가. `.bak` 자신도 「★ 이 박스에서 실제로 쓴 경로」로 기록.
   부수 확인 — `~/.zshrc` 에 `share_history`·`inc_append_history`·`extended_history` **전부 미설정**(51~57행). 히스토리는 셸 종료 시 일괄 기록되고 타임스탬프가 없으므로 **여러 터미널 간 행 순서는 시간 순서가 아님.** 「`smbclient -L` 이 `mv ftp.exe` 앞에 있다」를 시간 근거로 쓸 수 없음.

3. **「`┌──(kali㉿kali)` 프롬프트 블록에 창작이 섞였다」 → 철회. 4블록 전부 실측 근거 있음.**
   | 블록 | `~/.zsh_history` 대조 |
   |---|---|
   | `msfvenom ... -f py -v sc -o shellcode.txt` | 존재. `-b "\x00"` 2회 시도 후 최종형까지 순서 그대로 |
   | `python exploit.py` | 존재(2회) |
   | `rlwrap nc -lnvp 4444` | 존재 |
   | `nnmap 192.168.243.20` | 존재 |
   레거시(사람이 대화형 Kali 터미널에서 푼) 노트이므로 프롬프트는 실측. **강등·삭제 0건.**
   타겟 pty 프롬프트(`C:\Users\Wilson\Desktop>`) 전량 보존, 오히려 §1-2 에서 5행 복원.

4. **「셸코드 배드캐릭터 개수가 근거 없다」 → 철회. 노트가 맞음.**
   `shellcode.txt` 를 실행해 실측: 길이 **324**, `\x00` **12개**, `\x0d` **2개**, `\x0a` **1개** — 노트 서술과 완전 일치. LHOST/포트/`cmd\0` 패턴도 오프셋 189/194/228에 실재.

## 5. 그 밖의 검사 — 지적 없음

- **구조 (지목 ⓐ)** — `## Target #1` 래퍼 아래 `Initial Access`(긴 서술형) → `Service Enumeration` → `Initial Access`(짧은 형) → `Privilege Escalation` → `Post-Exploitation` → `## 관련`. 두 `Initial Access` 제목 상이 ✅. 4항목은 **양쪽 finding 에 4개씩 전부** 있고 첫 절에 4항목 외 혼입 없음. 포맷 스트링(정보유출)과 BOF(코드실행)를 체인으로 묶었으나 **각각 단독으로는 무엇이 부족한지**를 항목별로 갈라 적어 「어느 것이 Initial Access 취약점인가」가 흐려지지 않음.
- **`Port Scan Results` 표** 존재, nmap raw `21/tcp open ftp` 형 행 전량 보존.
- **`ports` 프론트매터 (지목 ⓓ)** — `[21, 135, 139, 445, 3389, 5985, 47001]`. 49664~49670 제외는 Windows 노트의 **의도된 동작**이므로 되돌리지 않음.
- **`nnmap` (지목 ⓖ)** — `~/.zshrc:247` 실측: `alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'`. `nmap.log` 첫 줄의 실제 커맨드라인과 일치. 노트 서술 정확.
- **CVE (지목 ⓗ)** — 프론트매터 `cves` 없음(정상, 커스텀 바이너리). 본문에 CVE 번호 **0건**. `manual_cves` 불요. `manual_tags: true` + `tech_count: 7` 과 실제 `tech/*` 7개 일치, 전부 실제 사용 기법.
- **OSCP 시험 규정 (지목 ⓘ)** — 노트에 금지/허용 판정 서술 자체가 없음(7장 이관됨). 과잉 금지 판정 **0건**. 사용 도구는 `msfvenom`·`nc`·pwntools·공개 PoC 로 전부 허용 범위.
- **남긴 흔적 (지목 ⓙ)** — `nc64.exe`(335B 쓰레기)·`nc64_new.exe`·`SeDebugPrivilegePoC.exe`·certutil 캐시 기재됨. 셸코드는 파일 업로드가 아니라 메모리 전달이므로 그 취지로 한 줄 추가.
- **시간 서사** — mtime(`nmap.log` 08:54:30 → `dev.txt` 09:03:56 → `ftp.exe` 09:04:01 → `shellcode.txt` 09:47:29 → `exploit.py` 09:48:09 → `SeDebugPrivilegePoC/` 10:11:20 → `nc64.exe` 10:14:41, KST)이 노트 서사 순서와 모순 없음.
- **스크린샷** — 볼트 `파일보관\` 에 `Osaka` 이름 0장. 같은 날짜 `Pasted image 20260818*.png` 8장은 **전부 11:04 이후**로 Osaka 작업 종료(10:14) 뒤 — 다른 박스(Butch/Breakout/Codo)의 것. 노트가 스크린샷을 주장하지 않으므로 모순 없음.
- **문체** — `pg-doc-reviewer` 이관 대상 소량 있음(서술형 종결 잔존). 사실 검증 관할 아님.

## 6. 근거 출처

- Kali 산출물 — `~/PG/Osaka/{nmap.log,exploit.py,shellcode.txt,ftp.exe,dev.txt,nc64.exe,SeDebugPrivilegePoC/}`, `ls -la --time-style=full-iso`
- `~/.zsh_history` (2146~2215행 Osaka 구간) · `~/.zshrc:51-57`(히스토리 옵션) · `~/.zshrc:247`(`nnmap` 별칭)
- 직접 실행 — `ftp.exe` PE 섹션 테이블 파이썬 파싱 / `strings -a ftp.exe | grep -ci` / `file ftp.exe` / `shellcode.txt` exec 후 바이트 카운트 / 코드펜스 3자 바이트 대조 스크립트
- 볼트 — `03. PG\_backup\Osaka.md.bak`, `03. PG\_AUDIT\Osaka-playbook.md`, `03. PG\Robust.md`(실물 기준), `파일보관\` 디렉터리 목록
- 1차 사료 — MS Learn `VirtualAlloc` 원형(`MEM_COMMIT=0x1000` · `PAGE_EXECUTE_READWRITE=0x40`), PE/COFF `IMAGE_DLLCHARACTERISTICS_*` 비트 정의

## 7. 총괄 판단이 필요한 것

- **색인 갱신 필요** — 노트 본문이 바뀌었으므로 `refresh.ps1` 이 총괄 손에서 한 번 돌아야 함. 감사자는 실행하지 않음.
- **`_PLAYBOOK` 반영은 관리자 몫** — `Osaka-playbook.md` 제안 13건(원 10 + 감사자 3) + 제안 6 정정 각주.
- **`_STATUS.md` 판정: 완료 2/2.** `local.txt` `1626da9ca8660f809d1df31fa797af30` · `proof.txt` `d75fcc9d6d14a696241176dda9889aa1` — 둘 다 값 보존, 대화형 셸(`C:\Users\Wilson\Desktop>` pty)에서 `type` 으로 읽은 캡처가 본문에 있음(웹셸 아님). 감사자는 `_STATUS.md` 를 건드리지 않음.
