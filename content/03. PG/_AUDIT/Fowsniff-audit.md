---
tags:
  - type/audit
  - platform/pg
type: audit
platform: pg
manual_tags: true
manual_cves: true
---

# Fowsniff 적대적 검증 + 정정 (2026-08-26)

대상 `03. PG\Fowsniff.md` · 감사 시점 863행 → 864행 · 개작 baseline 은 git `HEAD:03. PG/Fowsniff.md`(774행).
이관 제안 `03. PG\_AUDIT\Fowsniff-playbook.md`(12건) 동반 검증.

---

## 0. 최우선 지목에 대한 답 — 「행수가 늘어난 89행은 창작인가」

**아니다. 새로 지어낸 터미널 출력은 0건.**

코드펜스 42개를 baseline 34개와 바이트 대조하고, 산출물 25개 전량과 다시 대조함.

| 판정 | 건수 | 근거 |
|---|---|---|
| 산출물과 **바이트 일치** | 20블록 | `quick.log`·`nmap.log`·`gobuster.log`(ANSI 제거)·`README.txt`·`security.txt`·`john_cracked.txt`·`creds.txt`·`try2`·`try3`·`mail_seina.txt`·`proof_user.txt`·`proof_root.txt`·`enum_baksteen.log`·`enum2`·`enum3`·`enum4`·`pop3spray.py`·`dump.txt`·`cube.sh.orig` `ls` |
| **명령 블록**(출력 아님) | 14블록 | 재현 절차. 창작 대상 아님 |
| 출처 미보존이나 **다른 산출물로 값 검산됨** | 3블록 | john stdout·`md5sum cube.sh.orig`·dash 에러 |
| 출처 미보존 + `[가정]` 표기 | 1블록 | 리버스셸 리스너 스크롤백 |

행수 증가의 실체는 **OSCP 보고서 형식 골격**(두 finding × 4항목 = 약 40행) + **nmap raw 출력 2종 전문 수록**(baseline 은 OS 지문 블록을 접어 놓았음) + 산출물 캡션 부착이다. 학습 블록 12건은 실제로 잘려 나갔다.

**검산한 것:**
- `md5sum cube.sh.orig` = `377489e75ac90ece2f92fe30519f371c`, 850바이트 → 노트 값과 일치(직접 실행)
- `nmap.full.txt` 는 `nmap.log` 와 **첫 줄·마지막 줄만** 다름 → 노트 서술 그대로(`diff` 실행)
- john stdout 블록의 `Loaded 9 password hashes with no different salts` · `Raw-MD5` · `MD5 128/128 AVX 4x3` · 커맨드라인이 `~/.john/john.log` 494–498행과 일치
- rockyou 행번호 8개(`scoobydoo2` 17577 · `orlando12` 81318 · `apples01` 119135 · `skyler22` 166758 · `mailcall` 622357 · `07011972` 2424341 · `carp4ever` 9279098 · `bilbo101` 9627898) 전부 `grep -n -x` 로 재확인 → john 출력 순서와 일치. **노트가 옳았다**
- `dash -c 'echo hi >& /dev/null'` → `dash: 1: Syntax error: Bad fd number`, exit 2 → 노트 그대로

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `Steps to reproduce` 7번 「메일 수신자 8명에 SSH 스프레이」 | **내부 모순.** 실제 스프레이 대상은 `users.txt` 9명 전원(`try3_ssh_spray.log` 9행). 같은 노트 본문은 「9명 전부 돌림」이라고 적음 | 「`users.txt` 9명 전원에 SSH 스프레이」 |
| `---SUDO` 콜아웃 「`[가정]` 원격 SSH 의 의사터미널 …」 | 개작이 pty 사용을 `[가정]` 으로 강등했으나 **산출물이 pty 를 양성으로 증명함**(아래 §3-1) | 강등 해제. `Connection to … closed.` + CRLF 근거 2줄 추가. `[가정]` 은 「어느 지점에서 잘렸는지」로 범위 축소 |
| `proof_user.txt` 캡션 「타겟 pty 프롬프트가 캡처되지 않았음」 | 결론은 맞으나 **부재 근거 하나뿐**이었음 | 양성 근거 3개로 교체 — ①프롬프트 없음 ②파일 전체 LF 단독(같은 세션 로그는 CRLF 혼재) ③파일 mtime `15:03:59` KST 와 파일 안 타겟 `date` `02:03:59` EDT 가 **초 단위까지 일치** = 원격 출력 직접 리다이렉트 |
| `/opt/cube` 777 `[가정]` 문단 | 강등 자체는 옳으나 근거 서술이 `---GRPWRITE` 만 인용해 **`---WORLDWRITE-BIN` 을 빠뜨림**. 그 절은 모드 674 파일을 뱉었으므로 `-perm -o+w` 가 아니라 `-writable` 계열이고, 디렉터리 제외 여부를 가릴 수 없음 | 「확인도 반증도 되지 않음 — 두 find 의 실제 명령이 로그에 없음」으로 정정. `[가정]` 유지 |
| `known_hosts` 「파일 mtime 도 11:37(작업 시작 14:53 이전) 그대로임」 | **날짜를 빼고 시각만 비교한 잘못된 논증.** 그 11:37 은 2026-08-26 값이고 작업일은 2026-08-20. 게다가 2026-08-26 재확인 시 이미 11:48 로 갱신돼 있었음 | mtime 논증 삭제. 「항목 매칭 0건(2026-08-26 재확인)」만 남기고 왜 mtime 이 근거가 못 되는지 명시 |
| `관련` 「Dovecot 2.2.22 소스 — …」 | **버전이 관측되지 않았음.** nmap 은 `Dovecot pop3d` 까지만 뱉었고 `dpkg -l` 미실행. 소스 파일·심볼 4종 나열은 새 깊이 기준의 소스 고고학 | `[가정]` 부착 + 파일 목록 압축, 수치는 `_PLAYBOOK` 참조로 이관 |
| 「`/usr/bin/procmail` … 표준 패키지 SUID 임」 · 「`getcap` 결과도 전부 배포판 기본」 | **단정형 일반 지식인데 때려보지 않았음.** Kali 에 `procmail` 미설치라 재확인 불가 | 양쪽에 `[가정]` + 확인 못 한 이유 명시 |
| `robots.txt` 「두 줄이 정확히 26바이트임」 | 파일 본문을 회수하지 않았으므로 **산술이 맞아도 내용은 추론** | `[가정]` 부착 |
| `/tmp` 「남은 것은 부팅 때부터 있던 systemd/vmware 디렉터리뿐」 | `writeup_notes.txt` 15:07 은 「/tmp 프로브 파일 삭제 확인」까지만 기록. `ls` 출력 미보존 | `[가정]` + 실제 남은 근거 한 줄 명시 |
| rockyou 행번호 8개 나열 | 새 깊이 기준의 **행번호 고고학**이고 `_PLAYBOOK` 제안 9 와 중복 | 성질만 남기고 수치는 `_PLAYBOOK` 참조로. **본문 자체는 옳으므로 사실 정정 아님** |

부수 정정: 이관 제안 파일(`Fowsniff-playbook.md`)의 「반증 1건」 항목을 **재반증 결과로 교체**하고, 제안 3 의 Dovecot 버전에 `[가정]` 부착.

---

## 2. 삭제한 것 — 이번 감사에서는 **0건**

감사자가 지운 본문 없음. 정정 10건은 전부 **문구 교체 또는 `[가정]` 강등**임.

단, **개작(pg-note-forge)이 지운 펜스 3개**는 이관 제안 파일에도 없으므로 여기에 원문을 남긴다. 되살릴 수 있어야 한다.

**① `ls -la /opt/cube/` (baseline 455–461행)**

```
$ ls -la /opt/cube/
drwxrwxrwx 2 root   root  4096 Feb 28  2020 .
-rw-rwxr-- 1 parede users  850 Feb 28  2020 cube.sh
```

*(이 `ls` 출력은 로그 파일로 저장되지 않았다. 당시 기록에 남은 것은 `-rw-rwxr-- parede:users` 와 850바이트이고, 그 둘은 백업본 `cube.sh.orig` 로 재확인된다. 디렉터리 모드 `777` 은 박스가 내려간 뒤라 재확인할 수 없다.)*

→ **삭제 지지.** 출처 없는 출력을 코드펜스에 담는 것 자체가 `CLAUDE.md` §3 의 실측 표식 오용임. 내용(모드 674·850바이트·`parede:users`)은 현행 노트에 산문으로 살아 있고, 777 은 `[가정]` 으로 살아 있음.

**② `cat /etc/update-motd.d/00-header` (baseline 470–479행)**

```
$ cat /etc/update-motd.d/00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
...
#printf "Welcome to %s (%s %s %s)\n" ...

sh /opt/cube/cube.sh
```

*(이 `cat` 출력도 파일로 저장되지 않았다. `enum2_writable.log` 는 `00-header` 가 `root:root 755`·1248바이트라는 것까지만 남겼고, "`sh /opt/cube/cube.sh` 를 호출한다"는 당시 시간순 기록에 있다.)*

→ **삭제 지지.** 같은 사유. `...` 로 생략된 재구성물이었음. 현행 노트가 `writeup_notes.txt` 출처를 명시해 산문으로 서술함.

**③ `ss -lntp | grep 443` 출력 (baseline 557–561행)**

```
$ tmux new-session -d -s fow_root 'sudo nc -lvnp 443; exec bash'
$ ss -lntp | grep 443
LISTEN 0      1            0.0.0.0:443        0.0.0.0:*
```

→ **삭제 지지.** 출처 없음. 명령과 해설은 현행 노트에 유지됨.

**이관 손실 후보 1건(경미)** — baseline 649행 「`whoami; id; hostname; …` 를 플래그와 한 줄에 묶은 건 시험 증거 형식 연습이다 — 시험에서는 이걸 **한 화면 스크린샷**으로 남겨야 인정된다」가 현행 노트에도 제안 파일에도 없음. 시험 관점 서술이므로 `_PLAYBOOK` `C-3. 플래그·증거` 쪽에 한 줄로 살릴 것을 **총괄에 건의**한다(감사자는 `_PLAYBOOK` 을 쓰지 않음).

---

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

### 3-1. 「`ssh -tt` 로 강제한 의사터미널」 강등은 **잘못이었다** (되돌림)

개작자가 「`~/.zsh_history` 매칭 0건」을 근거로 `[가정]` 강등했다. 이 근거는 **성립하지 않는다** — 이 박스의 명령은 전부 비대화형 `ssh kali "..."` 라 히스토리에 **Fowsniff 관련이 단 한 줄도 없다**(직접 grep, 0건 / 히스토리 총 3149행). 즉 어떤 서술도 반증하지 못하는 부재다.

반대로 **양성 증거가 산출물 안에 있었다.** `enum_baksteen.log` 7행:

```
[sudo] password for baksteen: SoConnection to 192.168.248.18 closed.
```

`Connection to <host> closed.` 는 **tty 를 요청한 ssh 호출에서만** 출력된다. 2026-08-26 Kali 에서 직접 대조:

```
$ ssh kali@10.44.44.128 "echo hi"        → hi                      (그 줄 없음)
$ ssh -tt kali@10.44.44.128 "echo hi"    → hi\r\n
                                            Connection to 10.44.44.128 closed.\r\n
```

`enum_baksteen.log` 에서 CR 을 가진 줄은 정확히 **경고 4줄 + 이 줄뿐**이고(`enum2_writable.log` 도 경고 4줄만 CR), 나머지 본문은 LF 단독이다. **노트 원문이 옳았고 강등이 과했다.** `[가정]` 을 해제했다.

### 3-2. rockyou 행번호 검산은 **진짜였다**

「2026-08-26 재확인」으로 적힌 8개 행번호를 전부 다시 뽑았고 **8개 모두 정확히 일치**했다. 부착 사유(john stdout 이 미보존 블록이라 순서로 검산)도 타당하다. 본문에서 뺀 것은 **깊이 기준(행번호 고고학)** 때문이지 사실 오류가 아니다.

### 3-3. 「local.txt 를 대화형 SSH 셸에서 cat」 → 「SSH 원격 명령」 정정은 **옳았다**(근거만 보강)

개작 근거가 부재 하나뿐이라 재검했으나, 양성 증거가 셋 나왔다(§1 표). 특히 **파일 mtime 과 파일 안 타겟 `date` 가 초 단위까지 일치**하는 것은 원격 출력이 Kali 파일로 곧장 리다이렉트됐다는 뜻이다. 정정 유지, 근거 교체.

⚠️ **다만 이 정정이 시험 판정을 바꾸지는 않는다.** 금지되는 것은 웹셸이고, `ssh user@host 'cmd'` 는 sshd 가 띄운 진짜 셸이다. root proof 는 **대화형 pty** 에서 읽혔다(`proof_root.txt` 말미 `root@fowsniff:/#`).

### 3-4. 「`/opt/cube` 777」 강등은 **옳았다**(근거만 정정)

`---WORLDWRITE-BIN` 절이 모드 674 파일을 뱉었으므로 그 find 는 `-perm -o+w` 가 아니다. 두 find 의 명령이 로그에 없어 디렉터리 제외 여부를 가릴 수 없다. **부재 증거의 상한이 `근거부족`** 이므로 `[가정]` 이 정확한 등급이다. 삭제하지 않았다.

### 3-5. 프롬프트 판정 — 역방향 사고 **없음**

- 타겟 pty 프롬프트 `root@fowsniff:/#` 는 노트에 **7회** 살아 있고, `proof_root.txt`·`enum3_motd_mechanism.log`·`enum4_motd_parent.log` 3개 파일에 실재한다. 지워진 곳 없음
- 에이전트가 새로 붙인 Kali 프롬프트(`┌──(kali㉿kali)` · `└─$`)는 **0건**
- baseline 605·634행에 있던 `root@fowsniff:/# <명령>` 형태 2곳이 개작에서 명령 전용 블록으로 바뀌었으나, **그 두 곳은 산출물에 없는 재구성**이었고 프롬프트 자체는 다른 3곳에 그대로 남아 판정 근거가 훼손되지 않았다. **되돌리지 않음**

### 3-6. 노트 구조는 **기준에 맞다**

`### Initial Access`(긴 제목·4항목) → `### Service Enumeration` → `### Initial Access`(짧은 제목·재현) 순서는 `_WRITEUP-STANDARD.md` 「단일 호스트(템플릿 4장)」 및 실물 기준 `Robust.md` 와 **동일**하다. 두 제목은 서로 다르다. 「Initial Access 가 중복」은 성립하지 않는다.

프론트매터에 `difficulty`·`flags` 가 없는 것도 `Robust.md` 와 같아 하우스 관례에 부합한다.

---

## 4. 형식 점검 결과

| 항목 | 결과 |
|---|---|
| 4항목 완비 | ✅ `Initial Access` · `Privilege Escalation` 각 4항목 |
| `Port Scan Results` 표 | ✅ 존재 |
| nmap raw 포트 행(`22/tcp   open  ssh …`) | ✅ 2블록에 원문 보존 → `extract.py` `PORT_RE` 정상 |
| 코드펜스 언어 태그 | ✅ 42/42 부착, 무태그 **0** |
| 펜스 안 한국어 주석·해설 | ✅ **0** |
| 4항목 안 「아래/위」 상대 참조 | ✅ 없음(있는 「맨 아래」는 파일 내 위치 서술) |
| 「적대적 검증 정정 이력」 콜아웃 | ✅ 본문에 **없음** |
| `manual_tags` 8개 전부 실사용 | ✅ dirbust·osint·crack·spray·reuse·pop3·motd·revshell |
| `tech_count: 8` | ✅ 실제 8개와 일치 |
| `manual_cves: true` / CVE 없음 | ✅ 노트가 「CVE 없음 — 전부 설정·운영 결함」이라 명시 |
| `ports`·`services` | ✅ nmap 과 일치 |

**문체 이관 0건** — `pg-doc-reviewer` 로 넘길 건 없음. 개조식 종결이 전반에 적용돼 있고, 코드펜스·`[가정]`·「관측 없음」이 문체 명목으로 파괴된 곳도 없음.

---

## 5. 총괄 판단이 필요한 것

1. **`_PLAYBOOK` 이관이 아직 실행되지 않았다.** `_PLAYBOOK.md` 의 `Fowsniff` 매칭은 **2건**(기존 상호참조)뿐이고 제안 12건은 미반영이다. 그래서 노트의 「원인과 정확한 수치는 [[_PLAYBOOK]] 의 스프레이 항목에」·「행번호 실측치는 [[_PLAYBOOK]] 크래킹 항목」이 **현재 댕글링**이다. 노트가 거는 기존 앵커 3개(`A-41`·`B-31`·`F-1`)는 실재 확인함.
2. 위 §2 의 이관 손실 후보 1건(시험 증거 형식) 처리.
3. **색인 갱신 필요** — 노트 본문이 바뀌었으므로 `refresh.ps1` 대상. 감사자는 실행하지 않았다.
4. `_STATUS.md` 판정: **Fowsniff · Fundamental · 완료 2/2.** 근거 — `proof_user.txt` `242f9f051ef3715bbe679c90a3a6adf9`(baksteen, 대화형 아님·SSH 원격 명령) · `proof_root.txt` `f64f537d70805222fa0fd2e7a8d2a3ab`(root pty, 프롬프트 캡처됨). 두 값 모두 산출물에 실재.

---

## 6. 근거 출처

- **Kali 산출물** — `~/PG/Fowsniff/` 25개 전량 정독(`quick.log`·`nmap.log`·`nmap.full.txt`·`gobuster.log`·`README.txt`·`security.txt`·`web/`·`dump.txt`·`hashes.txt`·`users.txt`·`john_cracked.txt`·`creds.txt`·`pop3spray.py`·`try1~3*.log`·`mail_seina.txt`·`enum_baksteen.log`·`enum2~4*.log`·`cube.sh.orig`·`proof_user.txt`·`proof_root.txt`·`writeup_notes.txt`)
- **`~/.zsh_history`** — Fowsniff 매칭 **0건**(총 3149행). 부재가 아무것도 반증하지 못하는 이유
- **`~/.john/john.log`** 494–498행 · `~/.john/john.pot`
- **볼트 `파일보관\`** — `Pasted image 20260820*.png` **0장**. 노트의 「스크린샷 없음」 서술과 일치
- **git** — `HEAD:03. PG/Fowsniff.md`(774행) 를 baseline 으로 전체 diff(+433/−344)
- **직접 실행한 명령**(2026-08-26)
  - `md5sum ~/PG/Fowsniff/cube.sh.orig` → `377489e75ac90ece2f92fe30519f371c`
  - `diff ~/PG/Fowsniff/nmap.log ~/PG/Fowsniff/nmap.full.txt` → 1행·45행만 상이
  - `dash -c 'echo hi >& /dev/null'` → `dash: 1: Syntax error: Bad fd number`, exit 2
  - `grep -n -x <평문> /usr/share/wordlists/rockyou.txt` × 8
  - `ssh kali@10.44.44.128 "echo hi"` vs `ssh -tt kali@10.44.44.128 "echo hi"` → `Connection to … closed.` 출력 여부 대조
  - `grep -c $'\r' <산출물>` → CRLF 분포로 pty 사용 구간 판별
  - `ls -la --time-style=full-iso` · `grep -c '248.18' ~/.ssh/known_hosts`(0)
- ⛔ `find /`·홈 전체 grep·`~/PG` 전수 스캔 **미실시**(CLAUDE.md §3 규율)
