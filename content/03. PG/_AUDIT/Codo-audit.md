---
tags:
  - type/audit
  - platform/pg
type: audit
platform: pg
box: Codo
status: done
manual_tags: true
manual_cves: true
---

# Codo — 적대적 검증 + 정정 (2026-08-26)

대상 `03. PG\Codo.md` (개작 후 424행 → 정정 후 428행) · 이관 제안 `03. PG\_AUDIT\Codo-playbook.md`

## 0. 결론

**369행 소실은 실측 손실이 «아님».** 개작 전 793행 중 삭제분은 전부 **학습 자료(옛 0·2·6·7·8·9장)**이고, 실측 블록·플래그·자격증명·`[가정]` 은 전량 살아 있음. 영구 손실 0.

날조 **0건.** 이 박스는 사람이 대화형 Kali 터미널로 푼 레거시 박스이고, 노트의 Kali 프롬프트 2개·타겟 프롬프트 6개 모두 실측 근거가 있음.

## 1. 증거원

| 출처 | 확인 내용 |
|---|---|
| `~/PG/Codo/nmap.log` (2056B, mtime 2026-08-18 16:03:26) | 노트 nmap 블록·1행 명령줄 대조 — 일치 |
| `~/PG/Codo/50978.py` (8266B, mtime 16:24:49) | 헤더·3개 URL·페이로드 문자열·`randomFileName`·Burp 프록시 하드코딩 대조 — 전부 일치 |
| `~/.zsh_history` 2297~2306 · 2326~2327 | 박스 작업 명령 실재. **2326~2327 = `cd Codo` → `rlwrap nc -lnvp 4444`** (신규 발견) |
| `~/.zshrc:247` | `alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'` — 확인 |
| `파일보관\Pasted image 20260818163517.png` | **직접 열어 확인.** 주소창 `192.168.243.23/admin/index.php?page=config`, 「Upload logo for your forum」 현재값 `codoforum_logo.png`, 파일 선택란에 `payload.php` — 노트 서술과 일치 |
| `_AUDIT\portal-진행도-실측-20260820.md` | `Codo(1/1)` — `local.txt` 부재 근거(양성 증거) |
| Kali 직접 실행 (2026-08-26) | `strings su/sudo` · `echo pass \| su root -c id` · `printf 'whoami\nexit\n' \| bash -i` · `searchsploit codo` · `php-reverse-shell.php:54` |
| git `aba5a29:"03. PG/Codo.md"` (800행) · `03. PG\_backup\Codo.md.bak` (793행) | 개작 전 원본 대조 |

## 2. 코드블록·`[가정]` 검산 — 작성자 보고 재확인

**작성자 보고 「코드블록 11/11 · `[가정]` 3/3 재수록」 — 실질 정확.**

원본 793행의 펜스는 **총 25개**로 작성자가 센 11개보다 많으나, 그 11개가 **실측 블록**이고 나머지 14개는 창작된 교보재 명령임. 실측 11개 전량 보존 확인:

| # | 실측 블록 | 새 노트 |
|---|---|---|
| 1 | nmap 터미널 출력 | ✅ 보존 (PORT 라인 2개 포함 — `extract.py PORT_RE` 무사) |
| 2 | 웹루트 레이아웃 `text` | ✅ |
| 3 | 페이로드 호출 URL | ✅ |
| 4 | `rlwrap nc -lnvp 4444` 리스너 | ✅ (셸 회수 블록에 병합) |
| 5 | 셸 회수 배너 + `whoami` | ✅ |
| 6 | `ls` (sites/default) | ✅ |
| 7 | `cat config.php` 전문 | ✅ |
| 8 | `su root` → `cat proof.txt` | ✅ |
| 9 | 플래그 값 `34f3ce7f...` | ✅ 2회 |
| 10 | 스크린샷 임베드 | ✅ |
| 11 | 남긴 흔적 표 | ✅ |

`[가정]` — 원본 3건 중 **2건은 정당하게 반증돼 제거**(§3), 1건(php-reverse-shell)은 보존·보강. 새 노트는 `[가정]` 7건 · 「관측 없음/기록 없음」 5건으로 오히려 증가.

## 3. 작성자 반증의 재검증 — **전부 옳았음**

### 3-1. 「`su` 는 TTY 를 요구한다」가 틀렸다 → ✅ 반증 성립

Kali 직접 실행 (2026-08-26):

```
$ strings $(which su) | grep -i 'must be run'      → (출력 없음)
$ strings $(which su) | grep -i terminal
 -P, --pty                       create a new pseudo-terminal
 -T, --no-pty                    do not create a new pseudo-terminal (bad security!)
$ strings $(which sudo) | grep -i 'a terminal is required'
a terminal is required to read the password; either use ssh's -t option or configure an askpass helper
$ echo 'wrongpass' | su root -c id
Password: su: Authentication failure          (exit=1)
$ su --version → su from util-linux 2.41.2
```

`su` 바이너리에 그 문자열이 **없고**, 파이프 stdin 에서 비밀번호를 읽음. 그 문구는 `sudo` 것임. 노트가 `[가정]` 으로 남긴 환경 차이(타겟 util-linux 2.34)도 적절함 — 게다가 **이 박스 자체가 PTY 없는 셸에서 `su root` 성공**이라 같은 방향의 실측임.

원본 793행판의 아래 서술은 **틀린 것이 맞고 삭제가 정당**:
> `su` · `ssh` · `passwd` · `sudo`(설정에 따라) 가 **"must be run from a terminal"로 거부**된다 ← 4장에서 결정적
> (`_backup\Codo.md.bak` 376행. 같은 취지가 604·613~620·677~679·734행에도 있었음)

### 3-2. 「`nnmap` 과 출력이 어긋난다 `[가정]`」이 틀렸다 → ✅ 반증 성립

`~/.zshrc:245~248` 실측:
```
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```
`nmap.log` 1행이 `--privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log` 로 확장 결과를 그대로 담고 있음. 원본의 「명령줄만 잘못 붙인 것 `[가정]`」(`.bak` 92~94행)은 반증됨. 삭제 정당.

### 3-3. frontmatter CVE 교체 → ✅ 정당

원본 `cves: [CVE-2018-15473]`. 그 번호는 원본 **108행의 반증 문장**(「SSH 8.2p1에는 실전 원격 취약점이 없다(…CVE-2018-15473은 7.7에서 수정됨)」)에서 자동 스캔이 긁어간 색인 오염이 맞음. `[CVE-2022-31854]` + `manual_cves: true` 로 교체는 옳음.

부수 정정도 옳음 — CVE-2018-15473 은 **7.7 이하 해당·7.8 에서 수정**이고 원본의 「7.7에서 수정」은 틀렸음.

⚠️ **주석 사고 없음** — `cves: [CVE-2022-31854]` · `manual_cves: true` 두 줄 모두 주석 없음. `  - tech/*` 줄에도 주석 없음.

## 4. 정정한 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `명령이 두 번 찍히고 뒤에서 su 비밀번호까지…rlwrap 의 로컬 에코 때문임 [가정]` | **인과 오류.** 두 번 찍히는 것의 절반은 `rlwrap` 이 아니라 **PTY 없는 `bash -i` 자신의 에코**임 | 에코원 ①로컬 터미널 ②원격 bash 로 분리. **Kali 재현으로 `[가정]` → 실측 승격.** 비밀번호 노출은 ①뿐임을 명시 |
| `OpenSSH 8.2p1 에 실전 원격 취약점 없음` | 범위 없는 단정 | 「**무인증 원격 코드 실행으로 알려진 것 없음**」으로 한정 |
| zsh_history 인용 블록 | 원문 2304행 `ls` 가 **말없이 누락**된 채 「2300~2306행」으로 인용 | `ls` 복원 + 「전량」 명시 + 앞 2297~2299행 맥락 추가 |
| PoC 헤더 인용 블록 | `Vendor Homepage`·`Software Link` 2행이 말없이 누락 | 8행 전량 복원(`Software Link` 가 v5.1 배포본 근거) |
| 리스너/셸 회수 블록 캡션 | 출처가 「원본 노트」뿐이라 프롬프트 근거가 약했음 | **`~/.zsh_history` 2326~2327행 (`cd Codo` → `rlwrap nc -lnvp 4444`)** 신규 근거 추가 — 작업 디렉터리·포트가 프롬프트와 일치함 |
| `Local.txt value:` — 「포털 슬롯 1/1」 | 출처 미표기 | `_AUDIT\portal-진행도-실측-20260820.md` 의 `Codo(1/1)` 인용 |
| Post-Exploitation `위 su root 블록` | **절을 건너뛰는 상대 참조**(`_WRITEUP-STANDARD` 금지) | 「`Privilege Escalation` 절의 `su root` 블록」 + **타겟 프롬프트가 대화형 셸 증거임**을 명시(웹셸 0점 판정 근거) |

### 이관 제안 파일 정정 1건

`Codo-playbook.md` 4절의 같은 rlwrap 인과 오류를 정정. **`_PLAYBOOK` 병합 «전»에 잡은 것이라 오류 전파 없음.** 재현 명령·출력을 실측으로 실었음.

## 5. 삭제한 것

**없음.** 정정 6건 · 복원 3건 · 강등 0건. 이 감사에서 노트 본문을 지운 곳은 없음.

## 6. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

| 내 최초 의심 | 확인 결과 |
|---|---|
| 「`rlwrap nc -lnvp 4444` 이 zsh_history 에 없다 → 리스너 블록 창작 의심」 | **틀림.** 2326~2327행에 `cd Codo` → `rlwrap nc -lnvp 4444` 실재. 2300~2306 구간만 보고 부재로 단정할 뻔했음 — **부재 증거의 전형적 오판** |
| 「`┌──(kali㉿kali)` 프롬프트는 에이전트 창작」 | **틀림.** zsh_history 에 대화형 흔적이 실재하는 레거시 박스임. `CLAUDE.md` §3 양방향 규칙대로 **보존이 정답** |
| 「`su root` 가 PTY 없이 통했다는 서술은 지어낸 것」 | **틀림.** Kali 직접 실행으로 `su` 가 파이프 stdin 을 읽음을 확인. 박스 자체의 전사도 같은 방향 |
| 「제품 버전 v5.1 을 확인 못 했는데 CVE 를 붙였다」 | **노트가 이미 `[가정]` 으로 명시**하고 근거 2개(간접)를 밝힘. 지적 불성립 |
| 「`searchsploit codo` 블록이 2026-08-26 재실행이라 원 작업의 실측이 아니다」 | **노트가 캡션에 「재실행」을 명시**함. 재실행 결과도 8행 전부 일치 확인. 정직성 문제 없음 |
| 「업로드가 PoC 로 됐는지 수동인지 불명인데 수동이라 단정」 | **노트가 `[가정]` + 근거 3개**. 스크린샷(브라우저 파일 선택란 `payload.php`)이 네 번째 근거로 이를 지지. 지적 불성립 |

## 7. 이관 손실 검산

**영구 손실 0.** 근거: ① `03. PG\_backup\Codo.md.bak`(793행) 실재 ② git `aba5a29`(800행) ③ 제안 파일이 삭제 원문을 verbatim 인용 또는 `.bak` 행범위로 지목.

제안 파일이 지목한 `.bak` 행범위 — 26~42 · 161~218 · 220~315 · 405~493 · 554~638 · 669~675 · 714 · 733.

⚠️ **미지목 구간 1건** — `.bak` **133~156행(디렉터리 열거 / `gobuster dir` 명령 + 플래그 표)**. 제안 9건 어디에도 없음.
- **실측 아님** — 원본에도 「이 박스에서 실제로 접근한 경로는 `/admin/index.php` 다」뿐이고 gobuster 를 돌린 산출물·히스토리가 없음. 새 노트는 이를 「디렉터리 열거 — 기록 없음」으로 정직하게 대체함
- **`_PLAYBOOK` 중복** — 같은 `gobuster dir -u <타겟> -w /usr/share/wordlists/dirb/common.txt -x php` 형태가 `_PLAYBOOK.md` 2868행([[Cockpit]] 항목)에 이미 있음
- **판정: 이관 불필요.** 다만 제안 파일의 검산표는 「삭제 9 = 제안 9」로 적었는데 실제 삭제 덩어리는 10 이므로 **수치가 1 어긋남**(내용 손실은 아님)

## 8. 남은 것 — 총괄 판단

- **색인 갱신 필요.** `cves: [CVE-2018-15473] → [CVE-2022-31854]` + `manual_cves: true` 신설. `refresh.ps1` 은 돌리지 않았음(공유 인프라)
- **`_STATUS.md` 판정** — Codo · Fundamental · **1/1 완료**. 근거: 포털 실측 `Codo(1/1)` · `proof.txt` `34f3ce7f6374b4993f09078273faa70c` · 타겟 pty 프롬프트로 대화형 셸 획득 확인. 직접 편집하지 않았음
