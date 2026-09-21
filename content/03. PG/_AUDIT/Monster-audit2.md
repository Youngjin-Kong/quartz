---
tags:
  - type/audit
  - platform/pg
---
# Monster.md 적대적 검증 3차 (웨이브 12 구조 개작본) — 2026-08-26

대상: `03. PG\Monster.md` **831 → 795행**. 백업 `03. PG\_backup\Monster.md.bak2`(개작본 원형).
절삭분의 ④원문 인용은 전부 `03. PG\_AUDIT\Monster-playbook.md` 「감사 2차(2026-08-26) 추가 절삭분」에 있음.
기존 `Monster-audit.md`·`Monster-docreview.md`·`Monster-run.md` 는 미변경.

---

## A. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| A-1 `Vulnerability Fix:` 「Monstra 3.0.4 는 **2014년**이 마지막 릴리스」 | **틀린 사실.** 1차 사료로 반증 — 클론된 `~/PG/Monster/monstra-src/CHANGELOG.md` 첫 항목이 `Monstra 3.0.4, 2016-04-05`, `git tag --sort=-creatordate` 최상단도 `v3.0.4` | 「Monstra 3.0.4(**2016-04-05**)가 마지막 릴리스」로 정정. `## 관련` 의 소스 항목에도 근거 명시 |
| A-2 Nmap 읽기 「`/php-cgi/php-cgi.exe` 가 존재한 것이 **세 번째 독립 근거**」 | `~/PG/Monster/gobuster80.log` 에 `php-cgi` 무매치. 이 관측은 CVE-2024-4577 탐침 때 페인에서만 나왔고 산출물에 없음 → **근거부족** | 문장에서 제외하고, **파일로 확인되는** `/phpmyadmin`·`/webalizer` 403 두 건만 독립 근거로 남김. 그 두 줄을 gobuster 발췌 블록에 **같은 로그 파일에서 원문 그대로** 추가 |
| A-3 「UDP top-100 도 돌렸다. **열린 포트가 없었다**」 | `nmap_udp.log` 실제 = `Not shown: 99 open\|filtered udp ports (no-response)` + `2000/udp closed`. `open` 은 0 이나 99개는 **미확정**이지 「없음」이 아님 | 「`open` 상태 포트 0개(99개 `open\|filtered` = 미확정, 1개 closed)」로 정밀화 + 출처 캡션 |
| A-4 PE-2-b 의 `powershell` 블록 2개 | **코드펜스 안에 한국어 주석**(`(빈 결과 — 한 행도 없음)`·`(없음)`)과 **축약 프롬프트**(`PS C:\...>`)가 섞인 **재구성 블록**. 실측 원문이 아님 | `~/PG/Monster/try8_xampp_paths.log` 의 PATH 1·PATH 2 **원문 16줄**로 교체(`text`), 출처 캡션에 「페인 원문 미보존, 이 파일이 정지 직전 기록」 명시. 값은 전부 동일 |
| A-5 PE-4 의 `icacls`·`GetOwner()` 블록 | 출처 캡션 없음. 프롬프트가 `PS C:\...>` 로 축약돼 있음 | 블록은 유지하고 **캡션 신설** — 페인 원문 미보존, 같은 값이 `try8_xampp_paths.log`(PATH 3)에 기록됨, 프롬프트는 축약 표기임을 명시 |
| A-6 4항목 안의 「(아래 PE-4)」·「(아래 PE-2)」 | `_WRITEUP-STANDARD.md:183` ⛔ **4항목 안 상대 참조 금지** | 「`Privilege Escalation` 절 `PE-4` 가 그 진입점」·「(`PE-2` 표)」로 절 이름 참조 교체 |
| A-7 하위 절 번호 `4-1`~`4-4` | 옛 `§4` 구조의 잔재. 새 골격에 `§4` 가 없어 **가리키는 대상이 없는 번호** | `PE-1`·`PE-2`·`PE-2-b`·`PE-2-c`·`PE-3`·`PE-4` 로 재번호(상호참조 22곳 동기화). `\b` 경계 치환이라 `2022-04-18`·SID 문자열 등 코드펜스 내부 무영향(`diff` 확인) |
| A-8 PE-2 표 15행 출처 `표 6번 + **페인만**` | try8 에 값이 남아 있어 「페인만」이 과소평가 | 출처를 `표 6번 + try8_xampp_paths.log` 로 정정. 「페인만」 4줄(5·11·13·14) 카운트는 불변 |
| A-9 「남긴 흔적 → 확인하지 않은 것」 2건뿐 | **노트가 자기 산출물보다 얇았음.** `traces_confirmed.log` 의 `== NOT CHECKED ==` 에 3건이 더 있음 | Windows 보안 이벤트 로그(4624/4688)·`add_chunk` 의 Monstra 내부 로그 부수효과·실패 업로드 3건의 부분 파일 잔존 여부를 추가해 **5건으로 일치**시킴 |
| A-10 `Proof.txt value:` 근거 | 「`dir` 헤더만 나오고 목록이 빈다」에 출처 없음 | `try_privesc_full_scrollback.log:804` 명시(`===ADMINDESK===` 블록에서 확인) |
| A-11 PE-2 표 아래 `[!danger]` 콜아웃 | 「한때 이 표에 "트리거 없음"으로 올려놨었는데 **틀린 분류였다**」 = **노트 본문의 감사 개정 이력**(`CLAUDE.md` §4 ⛔) | 판정 내용(쓰기 가능·트리거 미확인·`PE-4` 로)은 그대로 두고 **개정 이력 서술만** 제거 |
| A-12 문체 | 산문 서술형 종결 다수(지시서 ⓗ 지목 지점 포함 — `Proof.txt value:` 의 「~못했다」·「~비어서다」·「확인했다」) | 손댄 전 구간을 명사 종결형 개조식으로 전환. **코드펜스 안·`[가정]`·「관측 없음」 미접촉** |
| A-13 `#### Monstra 3.0.4` 도입 「응답 **헤더와** 본문에」 | 아래 블록은 본문 HTML 두 줄뿐. 헤더는 실려 있지 않음 | 「`/blog/` **본문에**」로 정정 |
| A-14 `time` 처리량 블록 | 출처 캡션 없음. 대응 산출물 파일 없고 `~/.zsh_history` 에도 없음(전 작업이 비대화형 `ssh`) | **블록은 유지**(부재 ≠ 날조)하고 캡션에 「파일 미보존·재확인 경로 없음」 명시 |

## B. 삭제한 것 — 전부 `Monster-playbook.md` 에 ④원문 인용 보존

깊이 기준(`_WRITEUP-STANDARD.md` 원칙 1) 재적용. 판정법은 「이 문단을 지우면 심사관이 재현하지 못하거나 납득하지 못하는가」.

| 무엇 | 왜 | 보존 위치 |
|---|---|---|
| `$forbidden_types` 소스 전문 + 「XAMPP 가 이 확장자들도 PHP 핸들러에 문다」 | 소스 고고학. 게다가 이 박스에서 업로드 경로는 **기능 자체가 죽어 쓰이지 않았고**, 인용된 핸들러 단정은 **미검증** | 추가 B |
| `nnmap` 별칭 tmux 함정 | 박스 무관 도구 함정 = `_PLAYBOOK` | 추가 A |
| XPath 인젝션이 동등검사로 막히는 항목 | 시도했다 폐기한 경로 = `_PLAYBOOK`(제안 7 과 중복) | 추가 C |
| PE-2-b 말미 「번들 스택 유추 금지」 일반화 | 기법 카드 = `_PLAYBOOK`(제안 13 과 중복) | 추가 D |
| PE-4 말미 「icacls → 소유자 확인」·「낮은 권한의 없음은 결론이 아니다」 | 기법 카드 = `_PLAYBOOK`(제안 8 과 중복) | 추가 E |
| 44,000건 로그 교훈 문단 | 사실(규모·미삭제)은 **한 줄로 본문에 남기고** 교훈 서술만 `_PLAYBOOK` | 추가 F |
| 색인 고포트 제외 문장 / 「이 절은 두 층이다」 작업과정 문단 / 「2,000명 넘게 푼 박스」(출처 없는 수치) / Kali 운영 정리 상세 4줄 / 감사 개정 이력 1줄 | 볼트 운영·작업 과정 기록 = 본문에서 나가는 것 | 추가 G |

**실측 코드펜스는 요약하지 않았다.** 펜스 내용 `diff` 결과: 추가 2줄(같은 gobuster 로그 원문), 삭제 2블록(소스 4줄 + 합성 재구성 10줄), 교체 1건(합성 → `try8` 원문 16줄). **나머지 전 블록 바이트 동일.**

## C. 반증한 것 — 지적으로 올랐다가 확인 결과 노트/기존 판정이 옳았던 것

1. **🔴 기존 `Monster-audit.md` §E 의 「`icacls httpd.exe`·`mysqld.exe`, PID 5268 Owner, `mysqld.exe` 바이트 수는 페인만이라 재확인 불가」 — 반증됨.** `~/PG/Monster/try8_xampp_paths.log`(2,517B, mtime 2026-08-20 21:24:34)의 PATH 3 에 **같은 값이 전부 기록돼 있다.** 1차 감사가 이 파일을 열지 않아 「근거부족」으로 남긴 것이고, 부재가 아니었다.
2. **타겟 pty 프롬프트 — 전량 실측이고 유지가 옳다.** `~/PG/Monster/ps_rev.ps1` 이 `$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '` 로 프롬프트를 **셸 자신이 만들어 보내는** 구조. `proof_user.txt` 66행이 그 페인 캡처와 바이트 일치. **웹셸이 아닌 대화형 셸 증거이므로 한 줄도 건드리지 않았다.**
3. **`best66.rule` = 「변형 66개」 — 노트가 옳다.** Kali 직접 실행: `wc -l` 90줄이나 주석·공백 제외 실제 규칙이 **정확히 66개**.
4. **`-I` 가 「10초를 잡아먹는」 프롬프트를 건너뛴다 — 노트가 옳다.** `hydra_10k_run.txt` 에 `[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting))` 실재.
5. **XAMPP 정정(「관측은 옳고 결론이 틀렸다」)은 개작본에 온전히 살아 있다.** 상단 요약 · `Privilege Escalation` 4항목 · PE-2 콜아웃 · PE-2-c 말미 · PE-4 다섯 곳이 전부 「배제 아님 = 미완」으로 일관. `try8_xampp_paths.log` 의 `CONCLUSION AT CUTOFF` 와도 일치.
6. **「배제」와 「미완」의 구분도 살아 있다.** PE-2 표 16종 = 배제, PE-4 = 미완, PE-4 후보 4개는 전부 `미확인` 표기. 지시서가 우려한 혼동 없음.
7. **PE-2 표 12행(자동 시작 항목) — `try6_autostart.log` 와 완전 일치**(HKLM Run 2개 · HKCU Edge · mike Startup `xampp-control - Shortcut.lnk` 998바이트).
8. **`notepad.exe` 23개 — `grep -c` 재실행으로 23 확인.** 인용한 스크롤백 901~1005행 범위도 일치(`===PROCOWN===` 이 903행 근처).
9. **`mon9x.chunk.php` 94바이트 = `chunk_payload.php` 94바이트.** 웹셸 생성 주장이 파일 크기로 교차 확인됨(`traces_confirmed.log` ↔ `ls -la`).
10. **프론트매터·플래그·`manual_*` 선언** — 1차 감사 판정 그대로 유효. `tech/*` 4개 전부 실사용, `manual_cves: true` + `cves` 키 부재도 의도대로(악용한 CVE 없음).

## D. 근거 출처

- **Kali 산출물**(`ssh kali@10.44.44.128`, `~/PG/Monster/`): `nmap.log` · `nmap_udp.log` · `gobuster80.log` · `hydra_10k_run.txt` · `hydra_cewl_run.txt` · `hydra_run.txt` · `hydra_monstra.log` · `writeup_notes.txt` · `proof_user.txt`(66행) · `users.txt` · `pw_spray.txt` · `ps_rev.ps1` · `chunk_payload.php` · `cmd.txt` · `send.sh` · `traces_confirmed.log` · `hosts.before_revert` · `try1b_winlogon_filtered.log` · `try2_spray_admin.log` · `try5_sam_acl_shadow.log` · `try6_autostart.log` · `try7_readd_chunk.log` · **`try8_xampp_paths.log`** · `try_privesc_full_scrollback.log`(1,075행)
- **1차 사료**: 클론된 `~/PG/Monster/monstra-src` — `CHANGELOG.md`(3.0.4 = 2016-04-05), `git tag --sort=-creatordate`
- **직접 실행(Kali)**: `grep -vc '^#\|^$' /usr/share/hashcat/rules/best66.rule` → 66 · `grep -c 'notepad.exe' try_privesc_full_scrollback.log` → 23 · `grep -c -i 'monster|248.180' ~/.zsh_history` → **0**(전 작업이 비대화형 `ssh` / 리버스셸 안이라는 기존 판정과 일치) · `sed -n '899,910p;775,785p'` 로 인용 행번호 검증
- **볼트**: `파일보관\PG-Monster-80-{index,blog,admin-login}.png` 3장(노트에서 전부 참조 중). 2026-08-20 날짜 `Pasted image` 는 0장으로 지시서와 일치
- **고정 출처 밖 탐색 미실시** — `find /` · 홈 전체 grep · `~/PG` 전수 스캔 없음

## E. 하지 않은 것

- `refresh.ps1`·`extract.py` **미실행**. `_STATUS.md`·`_WRITEUP-STANDARD.md`·`_PLAYBOOK.md` **미수정**. 기존 `Monster-audit.md`·`Monster-docreview.md`·`Monster-run.md` **미변경**
- 박스·포털·브라우저 미접촉(박스는 이미 정지). Kali 에 파일을 쓰거나 지우지 않음(읽기 전용)

## F. 관리자에게 남기는 판단

- **행수는 795 에서 멈췄다.** 내역: **코드펜스 373행 + 산문 255행 + 공백 167행.** 개작본(831)은 펜스 376 · 산문 269 였으므로 **산문 269→255**, 펜스는 요약 없이 −3(합성 블록 제거분과 `try8` 원문 추가분이 상쇄). 비교 대상 `Robust.md`(293)는 **펜스가 92행**뿐이라 총행수 직접 비교가 성립하지 않는다. 남은 펜스는 nmap raw(44) · `whoami /all`(53) · `icacls`(27) · `PROCOWN`(20) · 삭제 전후 `dir`(18) · hydra(15) · `try8`(16) · 플래그 증거(11) 등 **전부 실측이고 지시서가 요약을 금지한 것들**이다. 더 줄이려면 실측 블록을 서술로 요약해야 하므로 여기서 멈췄다.
- **색인 갱신 필요** — `Monster.md` 본문이 크게 바뀌었고 `_AUDIT` 파일이 1개 늘었다(`refresh.ps1` 실행은 총괄 몫).
- **`_STATUS.md` 판정 — 부분(플래그 1/2).** 근거: `local.txt` = `db85d2fa7033db43da92bb07dde4da5b`(`proof_user.txt` 의 대화형 PowerShell 한 화면), proof 미확보(권한상승 미완, `PE-4` 트리거 미확인). 값 자체는 2026-08-20 인스턴스 것이라 재제출 불가.
