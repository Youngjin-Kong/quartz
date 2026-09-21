---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# Outdated — 적대적 검증 + 정정 (웨이브 9)

대상: `03. PG\Outdated.md` (개작 직후 534행 → 정정 후 556행)
대조: `03. PG\_backup\Outdated.md.bak` · `03. PG\_AUDIT\Outdated-playbook.md` · Kali `~/PG/Outdated/` · 볼트 `파일보관\` · `~/.zsh_history` · 1차 사료(Webmin 1.996 · mPDF v6.0.0 소스)
박스 정지됨 — 타겟 명령 0건.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| ``--data-urlencode` 가 필요한 이유 — … `-d` 로 날것 전송하면 서버가 받는 값이 깨짐` | **인과 오류(직접 실행으로 반증).** `<`·`>`·`"`·`/`·공백은 폼 인코딩에서 특수문자가 아님. Kali 로컬 PHP(`php -S`)에 같은 페이로드를 `-d` 와 `--data-urlencode` 로 각각 POST 한 결과 `$_POST['html']` 값이 **바이트 단위로 동일** | 실제 위험 문자(`&`·`+`·`%`)로 교체하고, 이 페이로드는 `-d` 로도 같은 값이 도달한다고 명시. 「기본 습관으로 둘 것」은 유지 |
| `-H 'Cookie: testing=1'` 이 필요한 이유는 MiniServ 가 쿠키를 못 받는 클라이언트를 **로그인 폼으로 되돌리기** 때문임 | **인과 오류(소스로 반증).** Webmin 1.996 `miniserv.pl` `handle_login` — `$header{'cookie'} !~ /testing=1/` 이면 `&http_error(500, "Cache issue or no cookies support", …)`. 로그인 폼 리다이렉트가 아니라 **500 에러** | 실제 동작(500 + 문구)과 출처(`miniserv.pl` `handle_login`)로 교체 |
| `비번의 &·#·@·! 는 POST 바디에서 «전부» 퍼센트 인코딩해야 함` | **과잉 단정.** 파라미터를 자르는 것은 `&` 뿐. `#`·`@`·`!` 는 폼 바디에서 특수문자가 아님 | 「`&` 는 반드시 / 나머지는 함께 인코딩해 보냄」으로 분리 |
| `content`·`icon`·`title`·`pos-x` — 공개 PoC 관례… **각 속성을 빼면 어떻게 되는지는 관측 없음** | **과잉 강등.** 1차 사료로 확정 가능한 것을 「관측 없음」으로 묻어 둠. mPDF `v6.0.0` `mpdf.php` `case 'ANNOTATION'` 은 `if (isset($attr['CONTENT'])) {…} else { break; }` — `content` 없으면 태그가 통째로 버려짐. `ICON`/`TITLE`/`POS-X` 는 각각 `'Note'`/`''`/`0` 기본값 | `content` = 필수(소스 근거 명시), 나머지 = 선택 + 기본값. 「하나씩 빼 보지 않았음(관측 없음)」은 유지 |
| `— 출처: …/gobuster.log (ANSI 컬러 이스케이프 «포함 원문»)` | **거짓 캡션.** 노트 본문에는 ESC(`0x1b`) 바이트가 없고 `[32m` 잔재만 있음(`cat -A` 로 양쪽 대조) | 「ESC 제어바이트만 빼고 나머지를 그대로 옮긴 것」으로 정정 |
| `**200 으로** 모듈 본문이 돌아온 것 자체가 …` / Steps 3 `「200 으로 열어」` | 그 요청은 `-o pu.html` 로 **본문만** 받았고 상태코드를 캡처한 산출물이 없음 | 상태코드 단정을 제거하고 판정 근거를 「본문이 왔는가」로 통일. 캡처 안 했다는 사실을 한 줄로 명시 |
| Steps 3 `/var/www/html/config/config.php` ↔ 본문 `/config/config.php` | **내부 불일치 + 표기 누락.** LFI 에 넘긴 절대 경로는 산출물 미보존이고, `/var/www/html` 은 Apache Ubuntu 기본값 추론 | Steps 는 「웹루트의 `config/config.php`」로, 본문에 `[가정]` 유보 한 줄 추가 |
| `/etc/passwd` 35줄 블록 (출처 없음) | 근거 캡션 부재 | `try1_annotation_passwd.pdf` 를 `extract_attach.py` 로 추출해 **35줄 · 마지막 줄이 svc-account** 임을 직접 확인하고 출처 캡션 추가 |
| `-rwsrwxrwx 1 root root 1183448 … /tmp/rootbash` | 대응 산출물 없음. 부재 증거이므로 삭제가 아니라 강등 대상 | `[가정]` 유보 추가 + 정합성 근거(모드 4777·owner root·크기·`proof_root.txt` 의 06:36 과 일치) 병기 |
| id_rsa·shadow 읽기 실패 서술 | 산출물·`writeup_notes.txt` 어디에도 대응 기록 없음(`try2`·`try3` 자리 미보존) | 서술 유지 + `[가정]` 유보 한 줄 |
| perl 인용 2블록 | ① `apt-lib.pl` 블록에 **한국어 주석이 삽입**돼 원본처럼 보임 ② `package_install` 블록은 **손으로 축약한 의사코드**였음(원본과 형태가 다름) | ① 주석을 펜스 밖 산문으로 이동 + 출처 캡션 ② 1.996 원본 9줄로 **verbatim 교체** + 출처 캡션 |
| pty 증거 서술 | 근거가 `Connection to … closed.` 한 줄뿐이었음 | 독립 근거 하나 추가 — `proof_user.txt`·`proof_root.txt` 는 **줄끝이 CRLF**(터미널 `ONLCR` 후처리), 같은 디렉터리 `enum_user.txt`·`try4_sudo_l.txt` 는 LF. `cat -A` 로 확인 |

## 2. 삭제한 것

**없음.** 이번 사이클의 정정은 전부 **교체·강등·유보 추가**다. 코드펜스 안의 명령·출력·IP·해시·플래그·자격증명은 한 바이트도 바꾸지 않았다(perl 인용 2건은 «원본으로 되돌린» 것이라 손실이 아님).

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

1. **ⓔ pty 프롬프트 한 줄(`svc-account@outdated:~$ id`)의 제거 — 제거가 옳다. 복원하지 않았다.**
   총괄 지시는 「pty 가 실측으로 확인됐으니 삭제가 아니라 복원+유보가 맞을 가능성이 크다」였다. 확인 결과:
   - pty 할당 자체는 **이중으로 확인됨** — ① `Connection to … closed.` ② proof 두 파일만 **CRLF**(다른 산출물은 LF)
   - 그러나 pty 가 붙어도 **`ssh -tt host "묶은 명령"` 형태에서는 PS1 프롬프트가 렌더되지 않는다.** 실제 산출물이 정확히 그 형태다 — proof 파일은 프롬프트 없이 「묶은 명령 출력 + Connection closed」 한 덩어리이고, 중간에 프롬프트가 한 번도 안 나온다
   - `~/.zsh_history` 3149줄에 이 박스 관련 항목 **0건**(`outdated`·`248.232`·`mpdf`·`annotation`·`webmin` 전부 무매치) → 대화형 터미널 세션 자체가 없었음
   - 따라서 그 블록은 「근거가 없을 뿐인 서술」이 아니라 **일어나지 않은 화면을 그린 것**이다. Fikklish 사고(실측 프롬프트를 지운 것)와는 방향이 반대다
   - 대신 pty 판정 근거를 노트 본문에서 **강화**했다(CRLF 근거 추가). 「웹셸이면 OSCP 0점」 판정에 필요한 것은 프롬프트 문자열이 아니라 **pty 였다는 사실**이고, 그 사실은 산출물로 남아 있다

2. **ⓖ① `data-package-updates="1"` 정정은 진짜 반증이다(새 창작 아님).**
   `exploit_resp.html`(Referer 거부 응답)의 루트 태그를 직접 파싱한 결과 `data-package-updates="1"` 과 `data-access-level="0"` 이 **둘 다 존재**. 노트의 새 서술(둘 다 접근권 근거가 못 됨)이 맞다.

3. **`shot_80_root.png` 이 볼트에 누락됐다 → 자기 지적 반증.**
   `~/PG/Outdated/shot_80_root.png` 가 노트에 안 걸려 있어 「스크린샷 1장뿐」을 의심했으나, md5 가 `39ee345d…` 로 볼트 `파일보관\PG-Outdated-mpdf_80.png` 와 **동일**. 같은 파일을 이름만 바꿔 가져온 것이고 누락 아님. 이미지를 직접 열어 본문 서술(「Convert HTML to PDF Online」·HTML textarea·Convert 버튼)과도 일치 확인.

4. **`Privilege Escalation` 의 `Severity: Critical` → 자기 지적 반증.**
   `_WRITEUP-STANDARD` 등급표는 「인증 후 RCE = High」라 Critical 이 한 칸 높아 보였으나, **실물 기준으로 지정된 [[Robust]]** 도 같은 방식으로 한 칸 올려 적고 있다(자격증명 노출 단독 → 표상 Medium 인데 High). 하우스 관행과 일치하므로 건드리지 않음.

5. **`confirm=1` 의 `[가정]` 강등 → 강등이 옳다(다만 소스는 「불필요」 쪽).**
   Webmin 1.996 소스로 확인: `confirm` 이 없으면 `list_package_operations` → `update_system_operations` 가 `apt-get -s install <quotemeta>` 를 도는데 **이쪽에는 백슬래시를 벗기는 정규식이 없어 주입이 실행되지 않고**, 존재하지 않는 패키지라 `Inst` 행이 없어 `@ops` 가 빈 배열 → `if (@ops) {확인폼} else {설치}` 의 **설치 분기**로 떨어진다. 즉 소스상 `confirm=1` 은 불필요.
   그런데 `writeup_notes.txt` 의 「without confirm=1: only dry-run, no install」은 **관측일 수 없다** — 그 시점의 모든 요청이 Referer 로 막혀 응답이 한 번도 변하지 않았기 때문이다. 노트의 현재 처리(둘의 충돌을 적고 `[가정]` 유지, 재현 시 붙일 것)가 정확하므로 그대로 둠.

6. **`apt-get -y  install` 공백 두 칸의 인과 → 개작본이 «약하게» 적었으나 원본이 옳았다.**
   `.bak` 의 「호출부가 세 번째 인자로 `1` 을 넘겨 `$force` 가 거짓」은 정확하다 — `package_install` 이 `&software::update_system_install($name, undef, 1)` 로 **하드코딩된 1** 을 넘기고 `update_system_install` 안은 `local $force = !$_[2];` 다. 개작본은 「호출부에서 `$force` 가 거짓이 되어」로 약화했으나 여전히 참이므로 오류는 아니어서 손대지 않음.

7. **`/Producer` UTF-16BE 주장 → 참(직접 실행 확인).**
   `strings out1.pdf | grep -i producer` 는 `/Producer (` 까지만 보이고 값이 안 보임. 노트의 파이썬 한 줄을 그대로 돌리면 `'﻿mPDF 6.0'`(선두 BOM은 비가시) — 노트의 출력 블록과 화면상 동일.

8. **`ID=ubuntu` 줄 추가 → 날조 아님.** `enum_user.txt` 원문의 `=== uname ===` 절에 실재한다(`.bak` 이 빠뜨렸던 것).

## 4. 이관 손실 검산 (ⓒ)

`.bak`(529행) 전 구간을 노트·`Outdated-playbook.md` 와 대조. **어디에도 없는 서술은 아래 4건뿐이고 전부 경미하다** — 지운 원문을 여기 남긴다.

1. `.bak` 0장 3번 — 「**자격증명 재사용의 3연타**: config 파일의 비번 하나가 (1) SSH (2) Webmin unix/PAM 로그인 (3) 그 Webmin 을 통한 RCE 로 이어진다.」
   → 세 사실 자체는 노트 본문·P9 에 전부 있으나 「3연타」라는 일반화 한 줄은 어느 쪽에도 없음.
2. `.bak` 8장 2번 — 「`Options -Indexes`, 민감 파일은 웹루트 밖으로」 중 **`Options -Indexes`·`/vendor` 노출** 부분. 노트 `Vulnerability Fix` 는 「설정 파일을 문서 루트 밖으로」만 남김.
3. `.bak` 5장 말미 — 「PG 는 박스를 리버트할 때마다 플래그를 새로 만든다. 위 값은 2026-08-20 인스턴스 한정이고, 재현 자료는 값이 아니라 경로와 획득 방법이다.」
   → 요약 콜아웃의 「(2026-08-20 인스턴스)」로 축약됨.
4. `.bak` 2장 `/etc/passwd` 블록의 생략 형태(`root:x:0:0:…` + `...` + `fwupd-refresh…` + 인라인 한국어 주석) → 노트는 svc-account 한 줄만 남김. **원문 자체가 `...` 생략과 인라인 주석이 섞인 재구성물**이었고, 이번에 실제 산출물(35줄) 출처를 붙여 대체했으므로 손실이 아니라 개선.

**건수 검산** — `Outdated-playbook.md` 이관 제안 15건(P1~P15) + 제거 원문 6건(D1~D6). `.bak` 의 0·6·7장(학습 자료 3개 장) 전량과 4장 산문 일부가 P1~P15 로 대응되며 **누락 없음.** 인과(「~해서」)·소요 시간(12분 / user 4분 / 발화 조건 5분)·`[가정]`·출처 경로 전부 보존 확인.

⚠️ 다만 `Outdated-playbook.md` 자체에 **오류 2건**이 있어 함께 고쳤다(그대로 `_PLAYBOOK` 에 append 되면 오류가 상속된다):
- P8 `--data-urlencode 필수 — `<`·`>`·`"`·`/`·공백이 섞여 `-d` 로는 값이 깨짐` → 위 §1 과 같은 이유로 반증. 정정 완료
- P8 `file 외 속성 … 각각을 빼면 어떻게 되는지는 미검증` → `content` 는 소스로 확정됨. 정정 완료

⚠️ 미정정으로 남긴 것 — P13 시간표는 `try1_annotation_passwd.pdf` mtime(15:25:32)을 「LFI 첫 성공」으로 적었는데 `writeup_notes.txt` 는 `[15:31] LFI confirmed` 로 적는다. **notes 파일의 내부 시각은 전부 15:24~15:36 구간에 뭉쳐 있어 mtime 과 어긋나는 사후 기입**으로 보이며, mtime 쪽이 1차 근거다. 시간표는 그대로 두되 이 불일치를 여기 기록한다 `[가정]`.

## 5. 근거 출처

- Kali 산출물 — `~/PG/Outdated/` 전 25개 파일 + `extract/`(빈 디렉터리)·`notes_init.sh`(0바이트) 존치 확인. `cat -A` 로 줄끝·ANSI 바이트 대조. `try1_annotation_passwd.pdf` 를 `extract_attach.py` 로 실제 추출
- `~/.zsh_history` — 3149줄, 이 박스 항목 0건
- 볼트 `파일보관\PG-Outdated-mpdf_80.png` — md5 `39ee345d6b58f762428794500348492d`, Kali `shot_80_root.png` 와 동일. 이미지 직접 열람
- 1차 사료 — `github.com/webmin/webmin` tag `1.996` 의 `software/apt-lib.pl` · `package-updates/update.cgi` · `package-updates/package-updates-lib.pl` · `miniserv.pl` · `session_login.cgi` / `github.com/mpdf/mpdf` tag `v6.0.0` 의 `mpdf.php`
- 직접 실행 — Kali 에서 `php -S 127.0.0.1:8099` 를 띄우고 `curl -d` vs `curl --data-urlencode` 로 같은 annotation 페이로드를 POST 해 `$_POST['html']` 대조 / `python3 -c "…decode('utf-16-be')"` 로 `/Producer` 디코드 / `strings out1.pdf | grep -i producer`

## 6. 총괄에 올릴 것

- **색인 갱신 필요** — 노트 본문이 바뀌었으므로 `refresh.ps1` 대상(직접 돌리지 않았음).
- `_STATUS.md` 판정: **Outdated = 완료 2/2**(user `a86881c4c605f79f5388ddc73e57866e` · root `b5fd4782fc9d5e2da021442ffb60c9eb`, `proof_user.txt`·`proof_root.txt` 로 증거 확보). 직접 편집하지 않음.
- `Outdated-playbook.md` 는 정정본으로 append 할 것 — 정정 전 판본을 append 하면 위 오류 2건이 `_PLAYBOOK` 에 상속된다.
