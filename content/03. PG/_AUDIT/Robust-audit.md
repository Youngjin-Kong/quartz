# Robust — 적대적 검증 · 정정 기록

대상 `03. PG\Robust.md` · 2026-08-21 · 행수 302 → 327

## 0. 증거 기반

- **git baseline 없음** — `Robust.md` 는 아직 untracked(`git status` → `?? "03. PG/Robust.md"`). 개작 전후 대조가 불가하므로 판정은 전부 Kali 산출물·스크린샷 대조로 함
- Kali `~/PG/Robust/` 161파일 (nmap 4종 · `web-80/` · `probe2/` 36 · `xff/` 12 · `sqli/` 17 · `union/` 18 · `fp/` 6 · `sticky/` · `harvest.txt` · `harvest-gap-check.txt` · `sticky-find.txt` · `cleanup.txt` · `proof_*.txt` · `pty_*.txt` · `render/` 4)
- 볼트 `파일보관\PG-Robust-{403,home,login,sqli}.png` — **4장 전부 직접 열어 봄**
- 직접 실행한 명령: `sqlite3 sticky/plum.sqlite 'select * from Note;'` · `md5sum sqli/*.body applogin.body` · `diff` (xff 본문 vs applogin) · `grep -o 'name="first_name"[^>]*'` (에코된 페이로드 복원) · 응답 본문 `<tr>` 파싱
- `~/.zsh_history` — Robust 관련 항목 **0건**(에이전트가 비대화형 `ssh kali "..."` 로 돌린 박스라 정상)

**핵심 기법 — 페이로드 복원**: `home.php` 는 검색 입력을 `<input name="first_name" value="...">` 로 **되돌려 렌더**한다. 따라서 `union/`·`fp/` 의 모든 `.body` 에서 **그 요청에 쓰인 페이로드 원문을 바이트 그대로 복구**할 수 있었다. 노트의 페이로드 주장을 추정이 아니라 대조로 판정할 수 있었던 이유.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| §3-5 「`password` 컬럼이 last_name 위치에 렌더」 | **틀린 인과.** `SELECT id,first_name,last_name,password` 의 4번째 값은 표의 **`Birth date`** 열에 들어간다. `union/creds.body` 파싱 결과 `['1','Jeff','Hills','Mathsisfun123','']` 이고, **노트가 스스로 링크한 `PG-Robust-sqli.png` 화면에도 `Mathsisfun123` 이 Birth date 열에 찍혀 있다** — 자기 증거에 반박당한 서술 | 「4번째 선택 컬럼이므로 표의 `Birth date` 열에 렌더」로 정정. 출력 블록도 열 머리글을 붙인 형태로 교체 |
| §3-3 「출력 컬럼은 2·3번(first_name·last_name 위치)」 | **틀림.** `fp/f1.body`(`' UNION SELECT 1,2,3,4-- `) 의 주입 행은 `1 2 3 4` 로 **네 자리 전부** 렌더됨 | 「출력 가능한 자리는 4개 전부」로 정정 |
| §4-2 「`plum.sqlite`(+`-wal`,`-shm`) 다운로드」 | **날조 방향의 과장.** `sticky/` 에는 `plum.sqlite` **한 개뿐**. `-wal`·`-shm` 은 타겟에 존재했다는 기록(`sticky-find.txt`)만 있고 회수하지 않음 | 「세 파일이 존재하나 본 DB 만 회수」로 정정. WAL 설명은 일반론으로 유지하되 「이 박스는 본 DB 에 이미 있었을 뿐」로 유보 |
| 상단 요약 「Windows Server (10.0.19042 …)」 | **근거 없는 「Server」.** `pty_*.txt` 배너는 `Microsoft Windows [Version 10.0.19042.1586]`, nmap OS 추정은 `Windows 10 1903 - 21H1 (92%)`. `Get-CimInstance` 접근거부라 ProductType 확인 불가 | 측정된 문자열 그대로 「Windows 10 20H2 (빌드 10.0.19042.1586)」 |
| §1 「7680 은 … 동적 포트, 무의미」 | **틀린 일반 지식.** 7680/tcp 는 Windows Delivery Optimization 의 **고정 포트**다(동적 RPC 대역은 49152+). 또 `-p-` 에서 «추가로 잡힌» 포트인데 「추가 서비스 없음」과 붙어 읽혔다 | 「`-p-` 에서 7680/tcp 가 하나 더 잡혔으나 Delivery Optimization 고정 포트라 공격면 아님」 |
| §6 「time-based 도 무반응」 | **근거 없는 단정.** `sqli/t10*.meta` 에 기록된 것은 `200 1838` 뿐 — **지연 시간을 측정한 기록이 없다** | 「응답 지연 시간은 측정해 두지 않음 — 본문이 같았다는 것까지가 관측」으로 강등. 대신 md5 동일이라는 **더 강한 실측**을 넣음 |
| §3-6 「(`Invalid user or password` — 별개 인증)」 | 관측은 맞으나 **「별개 인증」은 미검증 추론** | 「앱 로그인이 어느 저장소를 참조하는지는 관측 없음」으로 강등 + 출처 `applogin.body` 명시 |
| §3-4 「(다른 테이블 … 등은 미끼)」 | 불완전. `fp/f5.body` 에 테이블 7개가 전부 나와 있는데 3개만 적음 | 7개 전량 나열 + `employees` 의 `CREATE TABLE` 원문 + 「화면 목록은 `emps`, 비번은 `employees`」 구분 추가. 「자격증명 없음」 단정은 미덤프이므로 「덤프해 보지 않았음」으로 |
| pty 블록 2곳 | 실제 캡처의 `(c) Microsoft Corporation. All rights reserved.` 행이 빠져 있었고, `pty_admin.txt` 는 배너 2행이 통째로 빠져 있었음 | 캡처 원문대로 복원 |

## 2. 더한 것 (전부 산출물 실측)

- §3-2 — NULL 1~6, `ORDER BY` 1/5/10 **전 배치**를 복원(`union/c7~c15.body` 에서 페이로드 에코 추출). 「어디서부터 시도했나」가 6장 가치의 핵심인데 비어 있었음. 판정 신호가 **응답 크기**(실패 ~1.87KB / 성공 4.3KB)라는 것도 명시
- §3-3 — `sqlite_version()` 의 **실제 반환값 `3.28.0`**(`fp/f2.body`), 그리고 `information_schema.tables` 페이로드(`fp/f6.body` → 0행). 노트는 fp 6건 중 5건만 적고 있었음
- §3-4 — `sqlite_sequence` 존재 자체가 SQLite 확증이라는 점
- §4-1 — `cmdkey /list` → `* NONE *`, PowerShell 히스토리 없음, `icacls …\config\SAM` → `Access is denied`(SeriousSAM/CVE-2021-36934 배제), 계정 5개 열거, **`netstat -ano` 내부 LISTEN 135/139/445/5040/7680 vs 외부 nmap 미노출 → 호스트 방화벽**. 전부 `harvest.txt` 원문
- §6 — **gobuster 가 0바이트로 죽은 진짜 이유**. `.bg-gobuster.sh` 는 `-b 404,403` 이었고, 이 사이트는 확장자 없는 경로(`/README`·`/admin/`·`/server-status`)를 전부 `302 0` 으로 돌려준다(`web-80/probe-index.txt`). 와일드카드 판정에 걸려 즉시 종료 → `gobuster-80.txt` 0B. `-b 302,404` 재실행분(`gobuster-xff.txt`)에서야 `/login.php`·`/ip.php` 가 나옴

## 3. 삭제한 것 (1건 · 원문 보존)

§4-1 의 콜아웃 하나. **깊이 기준 초과 + `_AUDIT\Robust-run.md` 와 중복**이다 — 심사관에게 필요한 것은 「jeff 권한으로 그 명령이 거부됐다」이지 「우리 내부 스크립트가 정상인가」가 아니고, 그 판정은 이미 `Robust-run.md` §도구 판정에 있다. 사실관계 자체는 틀리지 않았고, 근거가 되는 실측(`systeminfo Access denied`·CIM 접근거부)은 §4-1 불릿으로 **그대로 남아 있다.**

삭제 원문:

> \> [!warning] harvest.ps1 의 빈 섹션은 «스크립트 결함이 아니라 타겟 제약»
> \> SYSTEMINFO/서비스/스케줄드태스크가 비어 온 것은 harvest.ps1 이 깨진 게 아니라 **jeff 계정 권한으로 그 명령이 거부**된 것. 별도 진단(`harvest-gap-check.txt`)으로 `CIM 서버 접근거부`·`systeminfo Access denied` 를 확인. 스크립트 자체는 정상 동작.

부수적으로 §4-2 도입부의 「브리핑의 경로 가정이 실측과 일치」도 문장을 다시 쓰면서 빠졌다(내부 작업 과정 언급이라 공개 노트에 남길 것이 아님). 대체 문구는 「경로는 Sticky Notes 앱의 고정 위치」.

---

## 4. 반증한 것 — 지적으로 올렸다가 **노트가 옳았던** 것

이 절이 이번 감사에서 가장 중요하다. **5건 중 4건이 「부재 증거로 날조를 판정할 뻔한」 사례**였다.

### 4-1. 「`home.php` 가 302 라는 근거가 없다」 → **노트가 옳다**

`probe2/` 에는 `.body` 만 있고 `.meta` 가 없다. 즉 노트 §2-2 의 `302 3030 /home.php` 중 **상태코드는 어디에도 기록돼 있지 않다.** 여기서 「근거부족 강등」으로 갈 뻔했다.

**양성 증거를 찾아 확정했다:**
- `gobuster-xff.txt` 는 `-b 302,404`(302·404 를 블랙리스트)로 돌았고, `/login.php`(200 1770)·`/ip.php`(200 0)를 보고했다
- 워드리스트 `raft-small-words.txt` **140행에 `home` 이 있고**(직접 `grep -n -x` 확인) 스크립트는 `-x php,...` 를 붙였다 → `/home.php` 가 **테스트됐다**
- 그런데 결과에 없다 → 상태코드가 302 또는 404. `probe2/home.php.body` 는 3030B 이고 이 서버의 404 본문은 ~540B(`probe2/admin.php.body` 실물 확인) → **404 아님**
- ∴ **`/home.php` 는 302 다.** 노트 그대로

### 4-2. 「`Invalid user or password` 로 로그인 실패를 판정할 수 없다」 → **노트가 옳다**

`md5sum` 결과 `sqli/p1~p10`·`t101~t106`·`applogin.body` **17개가 전부 동일 해시**(`76e77f15…`)였다. 「어떤 입력을 넣어도 같은 응답 = 그 문자열은 항상 렌더되는 정적 요소」로 의심했다.

**diff 로 반증했다.** 게이트 통과 직후의 로그인 폼(`xff/X-Forwarded-For.body`, 1770B)에는 `Invalid user or password` 가 **없고**(`grep -c` → 0), POST 응답(1838B)에만 정확히 이 68바이트가 추가돼 있다:

```
>   <div class="invalid" id="bad-login">Invalid user or password.</div>
```

즉 저 메시지는 **실제 로그인 거부의 산물**이 맞고, 17개가 동일하다는 것은 「SQLi 페이로드도 정상 자격증명도 전부 같은 방식으로 거부됐다」는 **더 강한 실측**이다. 노트 §6 의 「모든 페이로드 동일 1838B」도 그대로 옳다.

### 4-3. 「`sticky/` 에 DB 가 하나뿐인데 노트는 3개를 받았다고 한다 = 날조」 → **절반만 맞다**

부재 증거로 「Sticky Notes 절 전체 날조」로 갈 수 있는 자리였다. 실제로는 **`sqlite3 sticky/plum.sqlite 'select * from Note;'` 를 직접 실행해 노트의 자격증명 문자열이 그대로 나오는 것을 확인**했다. 틀린 것은 **다운로드 범위 한 구절뿐**이라 그 구절만 정정했다(§1).

### 4-4. 「`Get-ScheduledTask` 접근거부인데 스케줄드태스크를 못 봤다는 건 과장」 → **노트가 옳다**

`harvest-gap-check.txt` 의 `--- schtasks ---` 섹션에는 OneDrive Reporting Task 가 **나온다**. 「schtasks 는 됐으므로 노트가 과장」으로 지적하려 했으나, 노트가 단정한 대상은 `Get-CimInstance`/`Get-ScheduledTask`(CIM 경유)이고 그것은 실제로 `Cannot connect to CIM server. Access denied` 였다. 노트 서술 범위 안에서 정확하다.

### 4-5. 지시(지목 ①)에 대한 반증 — 러너의 「자가 반증 3건」 판정

| 러너 주장 | 판정 |
|---|---|
| DB 엔진이 SQLite | ✅ **진짜 반증.** `fp/f2.body` 에 `3.28.0`, `fp/f5.body` 에 `CREATE TABLE` 7건, `sqlite_sequence` 존재. 노트의 UNION 문법도 SQLite 정합(`sqlite_master` 사용, `information_schema` 는 0행으로 배제) |
| 4→5단계 순서(Sticky Notes 는 SSH 이후가 아니라 jeff→Administrator 피벗) | ✅ **타임라인 정합.** `proof_user.txt` 13:19:59 → `harvest.txt` 13:21:22 → `sticky/plum.sqlite` 13:21:22 → `proof_root.txt` 13:21:31. 단 `pty_jeff.txt` 는 13:21:54, `pty_admin.txt` 는 13:22:10 으로 **플래그 획득 «이후»** 다 — pty 캡처는 증거 확보용 재접속이지 최초 셸이 아니다. 노트는 순서를 주장하지 않으므로 정정 대상 아님 |
| gobuster 초기 무효는 대상의 전역 302 특성 | ✅ **뒷받침됨.** 위 §2 마지막 항목 참조. `-b 404,403`(스크립트 실물) + 확장자 없는 경로의 전역 `302 0`(`probe-index.txt` 9행) → 와일드카드 종료. **다만 노트는 이 내용을 한 줄도 담고 있지 않았다** — 러너 로그에만 있던 것을 6장으로 끌어올림 |

### 4-6. 지시(지목 ⑤)에 대한 반증 — Windows 포트 규칙

「`ports` 프론트매터에서 49152 이상과 5040·7680 이 제외됐는지 확인하라」는 지시였으나, **이 노트에는 `ports` 필드가 아예 없다**(색인 파이프라인 미실행). 제외할 대상이 없다. 본문 nmap 블록도 22·80 만 담고 있어 `extract.py` 가 뽑을 값은 `[22, 80]` 이다. 조치 불필요, 색인 갱신만 필요.

---

## 5. 통과시킨 것 (대조했고 정확했음)

- 플래그 2개 · `pty_jeff.txt`/`pty_admin.txt` 타겟 pty 프롬프트 — **그대로 보존**(오히려 누락 배너를 복원)
- nmap 코드펜스 5행 — `nmap-quick.txt` 원문과 바이트 일치
- `login.php` 403 본문 문자열 — `web-80/probe_login.php` 90B 원문과 일치
- XFF 12종 결과(1770B 1건 / 90B 11건) — `xff/` 실물과 일치. 200 상태코드는 `root-followed.info`(`code=200 size=90`)·`probe-index.txt` 로 교차 확인
- §3-1 주입점(`Desireef'` 0행 / `Desireef' -- ` 1행) — `union/c2.body` 1863B, `c4.body` 2168B(`c1` 2158B + 에스케이프된 페이로드 10B) 로 확인
- 「11행 = 원본10 + 주입1」 — `fp/f1.body` `<tr>` 파싱으로 정확히 11행
- `employees` 1행 — `creds.body` 에 주입 행 1개뿐
- §5 플래그 증거 서술(`whoami /all`+`hostname`+`ipconfig`+`type` 한 화면) — `proof_user.txt`/`proof_root.txt` 구조와 일치
- 「남긴 흔적」 4줄 전량 — `cleanup.txt` 와 일치(업로드 3파일 삭제, 계정·설정 변경 없음, 리스너 없음, tmux `rb-gb3`/`rb-pty`/`rb-pty2`/`rc-Robust-full` 이름 종료, NFS 없음)
- 스크린샷 4장 ↔ 본문 대조 — `render/` 의 HTML 크기가 각각 대응 `.body` + 37B 래퍼와 정확히 맞음(`login.html` 1807=1770+37, `home.html` 3067=3030+37, `sqli.html` 4435=`creds.body` 4398+37). **`PG-Robust-sqli.png` 는 `union/creds.body` 의 렌더가 맞다**
- `manual_tags` 5개(`access-control-bypass`·`sqli`·`sqlite`·`creds/reuse`·`sticky-notes`) — 전부 실제 사용 기법
- `manual_cves: true`, `cves` 필드 없음 — 악용 CVE 없음. §4-1 에 새로 넣은 CVE-2021-36934 는 **배제 근거로만** 언급했고 `manual_cves` 가 스캔을 막으므로 색인 오염 없음

---

## 6. 문체 — 고치지 않고 인계 (`pg-doc-reviewer`)

사실 검증 범위가 아니므로 **손대지 않았다.** 확인된 것 3건:

1. §6 「**자격증명은 발견한 맥락과 다른 서비스에서 통할 수 있다.**」 — 서술형 종결
2. §0 「**DB 엔진이 MySQL 이 아닐 수 있다**」 · 「**Windows Sticky Notes 는 자격증명 저장소다**」 — 소제목이 서술형
3. §2-1·§2-3 콜아웃 도입부의 번역투(「~에 있는 앱은 … 읽음」)

내가 새로 쓴 문장은 명사 종결형으로 맞춰 두었다.

## 7. 관리자에게

- **색인 갱신 필요** — `Robust.md` 는 신규 노트이고 `ports` 프론트매터가 없다. `refresh.ps1` 은 공유 인프라라 돌리지 않았다
- `_STATUS.md` 판정: **Robust = 완료 2/2** (근거 — `proof_user.txt`·`proof_root.txt`·`pty_*.txt`, 포털 Lab Complete). 직접 편집하지 않았다

---

# 2차 — 구조 개작(OSCP 보고서 형식) 적대적 검증 · 2026-08-25

대상 `03. PG\Robust.md` 284 → 285행 · `03. PG\_PLAYBOOK.md` 552 → 554행
개작 주체 `pg-note-forge`(보고서 `_AUDIT\Robust-restructure.md`) · 검증·정정 `writeup-auditor`

## 0. 증거 기반

- **git diff 불가** — `Robust.md`·`_PLAYBOOK.md` 둘 다 여전히 untracked(`?? "03. PG/Robust.md"` · `?? "03. PG/_PLAYBOOK.md"`). 이관 손실 대조는 전부 `_backup\Robust.md.bak`(329행) 과의 수동 diff 로 함
- Kali `~/PG/Robust/` 원문 직접 대조 — `nmap-quick.txt` · `nmap-full.txt` · `harvest.txt` · `sticky-find.txt` · `gobuster-80.txt` · `gobuster-xff.txt` · `_SUMMARY.txt` · `pty_jeff.txt` · `pty_admin.txt` · `xff/`(12) · `sqli/`(p1–p10 + t101–t106 + `.meta`) · `union/`(c1–c15 · creds · tables · ver) · `fp/`(f1–f6) · `probe2/` · `sticky/`
- 직접 실행: 응답 본문 `<tr>` 개수 파싱(`grep -o '<tr' | wc -l`) · 파일 크기 대조 · `.meta` 내용 확인
- 볼트 `파일보관\PG-Robust-{403,login,home,sqli}.png` 4장 — Kali 원본(`shot_80_*.png`)과 **바이트 크기 완전 일치**(10437 · 24404 · 40210 · 63783)
- 파일시스템 전수 스캔 **하지 않음**(CLAUDE.md §3 고정 출처 목록 준수)

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `## Privilege Escalation` — `harvest.ps1 실행.` 뒤 ` ```text ` 블록 | **개작이 새로 만든 가짜 코드펜스.** 원본은 산문 불릿(4-1)이었는데 forge 가 한국어 해설문("hotfix 목록으로 … 통째로 막힘")을 ` ```text ` 로 감쌈. 코드펜스는 실측의 표식(§3)이라 저자 서술을 감싸면 실측처럼 보임 | 펜스 해체 후 불릿으로 되돌림. 아래 불릿 4개와 병합해 7개 불릿 한 덩어리로. 출처 캡션은 산문으로 |
| 같은 절 `netstat -ano` 불릿 | **내부 모순 + 잘못된 인과.** 「내부에는 135·139·445·5040·7680 이 LISTEN. 외부 nmap 에는 안 잡히므로」 — **7680 은 외부 `-p-` 에 잡혔다**(`nmap-full.txt`: `7680/tcp open  pando-pub?`). 같은 노트 `Service Enumeration` 이 스스로 그렇게 적고 있어 노트가 자기 모순. 원본에서 상속된 오류 | 「이 중 외부 `-p-` 스캔에 잡힌 것은 7680 뿐이고 135·139·445 는 안 잡힘」으로 정정. 동적 RPC 49664–49669 도 `harvest.txt` 실측대로 추가 |
| `첫 시도 ' UNION SELECT 1,version()… 엔진 판별 배치를 쏨:` | **리드인이 엉뚱한 블록을 가리킴.** 개작이 원본 3-2(컬럼 수)와 3-3(엔진 지문)을 합치며 3-3 의 리드인을 3-2 블록 «앞»에 놓아, 「엔진 판별 배치」라고 예고한 뒤 NULL/ORDER BY 블록이 나옴 | 리드인을 `fp/` 블록 바로 앞으로 이동. 컬럼 수 블록에는 `NULL 개수 1~6 과 ORDER BY 1/5/10 을 각각 한 배치로 쏨` 이라는 원본 3-2 리드인을 복원 |
| `## Initial Access` — `**Vulnerability Fix:**` | **이관 손실.** 원본 `## 8. 방어 관점` 의 「자격증명을 앱 DB 에 평문 저장 금지 — 해시(bcrypt/argon2)」가 노트·`_PLAYBOOK` 어디에도 도착하지 않음. `employees` 평문 저장이 Initial Access finding 의 핵심 결함인데 remediation 이 빔 | 불릿 추가 — 「자격증명을 앱 DB 에 평문 저장 금지 — bcrypt/argon2 해시로 저장해야 SQLi 로 덤프돼도 즉시 재사용 불가」 |
| `검색 폼: ?action=search…` 뒤 | **이관 손실.** 원본 3-1 「주입점 확인」 전체(`first_name=Desireef'` → 0행 / `Desireef' -- ` → 1행 복귀 / 작은따옴표 문자열 컨텍스트 확정 + 출처 `~/PG/Robust/union/`)가 「`'` 주입 확인」 한 조각으로 축약됨. 숫자·경로는 압축 대상이 아님(STANDARD 문체 절) | 원본 문장 그대로 복원 + 출처 캡션 복원 |
| `컬럼 4개 확정.` | **인과 손실.** 원본 「`ORDER BY 5` 실패 + `UNION SELECT` 4-NULL 성공, 두 방법이 일치」가 사라짐. 왜 4개로 «확정»인지의 근거 | 「컬럼 4개 확정 — `ORDER BY 5` 실패 + `UNION SELECT` 4-NULL 성공, 두 방법이 일치.」로 복원 |
| `whoami /all` 불릿 | 원본 4-1 의 「Medium IL, 그룹은 `BUILTIN\Users` 외에 특권 없음」에서 그룹 절이 탈락. `harvest.txt` GROUP INFORMATION 으로 실측 확인됨 | 복원 |
| `sqlite3 sticky/plum.sqlite …` 블록 | **출처 캡션 오배치.** 캡션이 «명령» 블록 아래 붙어 있고, 정작 `Note` 테이블 «출력» 블록에는 출처가 없음 | 캡션을 출력 블록 아래로 이동 |
| `_PLAYBOOK` B-15 후보 헤더 12종 | **실측과 불일치.** 12번째를 `Forwarded` 로 적었으나 `~/PG/Robust/xff/` 실제 파일명은 `Forwarded-For.body`. RFC 7239 의 `Forwarded` 는 이 박스에서 시험된 적 없음 | `Forwarded-For` 로 정정 + 「`Forwarded` 는 이 12종에 없음. 목록에 추가해 함께 쏠 것」 주석 추가 |
| `_PLAYBOOK` B-43 | **이관 손실.** 원본 4-2 콜아웃의 「`strings plum.sqlite` 로도 보이지만 `sqlite3 'select * from Note'` 가 행 구조를 살려 정확」이 노트·`_PLAYBOOK` 양쪽에서 사라짐 | B-43 악용 절에 복원 |

## 2. 삭제한 것

**없음.** 정정·복원·이동만 함. 유일하게 «제거»한 것은 코드펜스 «표식» 3줄(` ```text ` 여는 줄 / 닫는 줄 / 캡션 형식)이고 그 안의 문장은 한 자도 버리지 않고 불릿으로 옮겼다. 삭제 전 원문:

```
```text
whoami /all       → 특권은 SeShutdown·SeChangeNotify·SeUndock·SeIncreaseWorkingSet·SeTimeZone 5개뿐. SeImpersonatePrivilege 없음 → Potato 계열 불가. Medium IL
systeminfo        → ERROR: Access denied (hotfix 목록으로 커널 익스플로잇을 고르는 경로가 통째로 막힘)
Get-CimInstance Win32_Service → count 0
Get-ScheduledTask → CIM 서버 접근거부 (서비스 바이너리 권한·언쿼티드 경로 점검이 전부 공란)
```
— 출처: `~/PG/Robust/harvest.txt` · `harvest-gap-check.txt`
```

## 3. 반증한 것 — 지적으로 올랐다가 «노트가 옳았던» 것

**이것이 이 감사에서 가장 큰 덩어리다. 지목 ⓐ·ⓑ·ⓓ 는 전부 통과했다.**

| 의심한 것 | 확인 결과 |
|---|---|
| ⓐ 4항목이 한쪽에만 붙었을 것 | **통과.** `Initial Access`·`Privilege Escalation` 양쪽 모두 `Vulnerability Explanation:`·`Vulnerability Fix:`·`Severity:`·`Steps to reproduce the attack:` 4개 완비. Steps 는 양쪽 다 번호 목록(7단계 / 4단계). Severity 등급도 STANDARD 표와 일치(High = 인증우회+자격증명 탈취, Critical = 즉시 관리자) |
| ⓑ Port Scan Results 표가 nmap raw 를 대체했을 것 | **통과.** 표는 «추가»이고 raw 3줄(`PORT STATE SERVICE VERSION` / `22/tcp open  ssh …` / `80/tcp open  http …`)이 `nmap-quick.txt` 원문과 **바이트 동일**하게 살아 있음. `PORT_RE` 대상 라인 2개 확인 |
| ⓓ 언어 태그 없는 코드펜스가 있을 것 | **통과.** 여는 펜스 17개 전부 태그(`text`·`bash`·`sql`) — 정정 후 기준. 블록 내용은 한 바이트도 안 건드림 |
| ⓓ 산문 안 괄호 출처가 남아 있을 것 | **대체로 통과.** 코드블록이 딸린 출처는 전부 캡션 형식. 괄호로 남은 둘(`(~/PG/Robust/applogin.body)` · `(~/PG/Robust/sticky-find.txt)`)은 **대응하는 코드블록이 없는** 산문 참조라 캡션으로 뺄 자리가 없음. 원본에도 같은 형태였음 — 위반으로 보지 않음 |
| forge 가 `_PLAYBOOK` A-15 에 «새로» 써넣은 `gobuster-80.txt`(0바이트)·`gobuster-xff.txt` 는 원본 노트에 없던 파일명이라 날조 의심 | **반증 — 전부 실재하고 내용까지 일치.** `gobuster-80.txt` 는 **정확히 0바이트**, `gobuster-xff.txt` 는 226바이트로 `/login.php`·`/Login.php`·`/ip.php`·`/IP.php` 4히트. forge 가 산출물을 실제로 열어보고 보강한 것 |
| `_PLAYBOOK` A-25 「시간기반 6종은 응답 코드·크기만 기록했고 **응답 지연 시간은 측정해 두지 않음**」이라는 유보가 과장 또는 반대일 가능성 | **반증 — 유보가 정확하다.** `sqli/t101.meta`~`t106.meta` 가 각 8바이트로 `200 1838` 만 담고 있음. 시간 필드 자체가 없음. 이 「관측 없음」 표기는 살려야 할 것이고 실제로 살아 있음 |
| 「응답이 전부 바이트 단위로 동일했고 … 1838B」 | **반증 — 정확.** `sqli/p1–p10.body` + `t101–t106.body` 16개 전부 1838바이트, `applogin.body` 도 1838바이트 |
| 「11행: 원본10 + 주입1」 | **반증 — 정확.** `fp/f1.body` 의 `<tr>` 12개(헤더 1 + 데이터 11) |
| 「`employees` 테이블은 단 1행」 | **반증 — 정확.** `union/creds.body` 에 `Jeff`·`Hills`·`Mathsisfun123` 각 1회, 나머지 10행은 `emps` 원본 행 |
| 「실패 응답은 약 1.87KB, 성공은 4.3KB」 | **반증 — 정확.** 실패군 1863~1901B, 성공군 4277~4359B |
| 「`sqlite_version()` 값 `3.28.0`」·「테이블 7개」 | **반증 — 정확.** `fp/f2.body`·`fp/f5.body` 원문 확인 |
| 타겟 pty 프롬프트가 「Kali 프롬프트 창작 금지」 명목으로 제거됐을 가능성(Fikklish 사고 재발) | **반증 — 둘 다 보존.** `jeff@ROBUST C:\Users\Jeff>`·`administrator@ROBUST C:\Users\Administrator>` 가 `pty_jeff.txt`·`pty_admin.txt` 원문대로 살아 있음. 역방향(`┌──(kali㉿kali)` 신규 생성)도 **0건** |
| 시간 서사 모순 | **반증 — 일치.** `harvest.txt` 헤더의 타겟 로컬 시각 `2026-08-20T21:20:11-07:00` = UTC 2026-08-21T04:20:11 = KST 13:20:11 이고, Kali `harvest.txt` mtime 이 13:21:22 KST. 타임존 환산 후 모순 없음 |
| 스크린샷 임베드가 엉뚱한 절에 갔거나 파일이 없을 가능성 | **반증 — 4장 전부 실재·적절.** 403 → `Service Enumeration`(IP 게이트), login → 게이트 통과 직후, home → `Manage Employees`, sqli → 덤프 결과. 볼트 파일 크기가 Kali 원본과 완전 일치 |
| 플래그·IP·자격증명 변조 | **반증 — 전부 원문.** `c73e61a25344e60d7e3d9fab6711200a` · `d2cdab936a61a5e7a0abd203cd8f4670` · `192.168.248.200` · `Jeff:Mathsisfun123` · `Administrator:MySupersecurePassword2112` |

**forge 보고 중 사실과 다른 것:**
- `Robust-restructure.md` 8행 「코드펜스 언어 태그 전량 확인(누락 0)」 — 태그 자체는 맞으나, **그중 하나가 저자 서술을 감싼 가짜 펜스**였다. 「태그가 붙었는가」만 검사하고 「그 안이 실측인가」는 검사하지 않았다
- 같은 파일 26행 「8 방어관점 → 각 finding Vulnerability Fix 로 흡수」 — 4개 중 **3개만** 흡수됐고 평문 저장 항목이 누락됐다. 매핑표에 「흡수」라고 적어 두면 검산이 안 된다

## 4. 문체

**이관 0건.** 산문 종결이 전량 명사 종결형이고, 서술형으로 잡힌 것은 `_PLAYBOOK` 앵커 링크 제목뿐이다(A-15·A-24·A-25·A-41 — **절 제목이라 바꾸면 링크가 깨지므로 대상 아님**). `pg-doc-reviewer` 로 넘길 것 없음.

## 5. 관리자에게

- **색인 갱신 필요** — 본문만 손댔고 프론트매터(`tags`·`ports`·`cves`·`manual_*`·`tech_count`)는 미변경. `refresh.ps1` 은 공유 인프라라 돌리지 않았다
- `_STATUS.md` 판정 변화 **없음** — Robust = 완료 2/2 유지. 직접 편집하지 않았다
