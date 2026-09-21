---
type: audit
target: "03. PG/Robust.md"
scope: 구조 재정렬 검증 (사실 검증 아님)
baseline: "03. PG/_backup/Robust.md.bak2"
date: 2026-08-25
---

# Robust — 2차 구조 재정렬 감사

**범위** — `pg-note-forge` 의 OffSec 원본 템플릿 4장 재배치(285행 → 290행)만 검증. 사실 판정(익스플로잇 경로·CVE·버전·플래그 값)은 1차 감사에서 종결돼 이번 범위 밖.

**방법** — 노트 본문 ↔ `_backup/Robust.md.bak2` 기계 대조. 파일시스템 탐색 없음.

```
diff <(sed 's/[[:space:]]*$//' _backup/Robust.md.bak2 | grep -v '^$' | sort) \
     <(sed 's/[[:space:]]*$//' Robust.md | grep -v '^$' | sort)
```

정렬 diff 를 쓴 이유 — 재정렬 작업에서는 「줄 순서」가 통째로 바뀌므로 순차 diff 가 전량 불일치로 뜸. 정렬 후 대조하면 **순서 변경은 소거되고 「사라진 줄 / 새로 생긴 줄」만** 남음. 이 대조에서 잔차가 아래 3종뿐이었다는 것이 곧 「나머지 전량 바이트 동일」의 증명임.

---

## 고친 것

**없음.** ⓐ~ⓓ 네 지목 전부 통과. 살아남은 지적 0건.

## 삭제한 것

**없음.**

---

## ⓐ 문장 손실 — 통과

정렬 diff 잔차는 세 종류뿐:

| 잔차 | 성격 |
|---|---|
| H2 → H3 강등 4건 + `## Target #1 – 192.168.248.200` 신설 + 긴 `### Initial Access` 헤딩 신설 | 헤딩 레벨·신설. 예외 대상 |
| `Steps to reproduce the attack:` 7단계 → 6단계 재작성 | 아래 개별 검증 |
| 상세 절에 1문장 신규 추가 (`home.php` 는 `exit`/`die` 없이…) | 요약에서 상세로 **이동**한 것 |

그 외 **모든 줄이 바이트 동일**. 산문·코드블록·출처 캡션·임베드·플래그·자격증명 전부 무손상.

### Steps 축약 7→6 — 포저 주장 4건 개별 확인

포저는 「1건 이동 + 3건은 이미 상세 절에 있어 요약에서 삭제만」이라 보고. **네 건 모두 사실로 확인됨.**

| # | 요약에서 빠진 내용 | 상세 절 소재 | 판정 |
|---|---|---|---|
| 1 | `home.php` 는 `exit`/`die` 없이 인증 뒤 화면 전량 출력. `curl -L` 로 따라가면 놓침 | **신규** L116 — `— 출처: ~/PG/Robust/probe2/` 캡션 바로 아래 | **이동 확인.** bak2 상세 절에는 없던 문장이 실제로 추가됨 |
| 2 | 직원 목록이 보이던 `emps` 와는 별개 테이블 | L157 「화면에 보이던 직원 목록은 `emps`(생년월일·주소 등)이고, `password` 컬럼을 가진 것은 별개 테이블 `employees`」 + L163 | **주장 사실.** bak2·현행 양쪽에 존재 |
| 3 | MySQL 함수는 전부 실패 (SQLite 엔진 지문) | L143 「첫 시도 … MySQL 함수가 통째로 실패」 + L145–152 엔진 판별 배치 블록 + L155 「`sqlite_version()` 만 통하고 값이 `3.28.0` → SQLite」 | **주장 사실** |
| 4 | 컬럼 수 4개 확정 방법 (`ORDER BY` / `UNION SELECT NULL`) | L129–138 배치 출력 블록 + L141 「`ORDER BY 5` 실패 + `UNION SELECT` 4-NULL 성공, 두 방법이 일치」 | **주장 사실** |

부수 축약 2건도 손실 아님:
- 「→ `login.php` 폼 노출」 → 「→ 로그인 폼 노출」. 파일명은 L66(`|_Requested resource was login.php`)·L72·L102 curl 명령에 남음
- 「(`Manage Employees` 직원 검색)」 삭제. L118 에 그대로 존재

**정보 손실 0건.**

## ⓑ 코드블록·출처 캡션 — 통과

| 항목 | bak2 | 현행 |
|---|---|---|
| 펜스 줄 수 | 34 (=블록 17개) | 34 (=블록 17개) |
| 언어 태그 | `text`×11 · `bash`×5 · `sql`×1 | `text`×11 · `bash`×5 · `sql`×1 |
| `— 출처:` 캡션 | 10 | 10 |
| `![[...]]` 임베드 | 4 | 4 |
| nmap raw 라인 (`^[0-9]+/tcp`) | 2 (L64 · L65) | 2 (L64 · L65) |
| 플래그·자격증명·IP 히트 | 19 | 20 (+1 = 신설 헤딩 `## Target #1 – 192.168.248.200` 의 IP) |
| 인코딩 | UTF-8 (CRLF 없음) | UTF-8 (CRLF 없음) |

- 정렬 diff 잔차에 코드블록 줄이 **하나도 없음** → 펜스 내부 바이트 동일
- 펜스 안 산문 유입 **없음**(이번 작업이 만든 것 기준)
- 타겟 pty 프롬프트 2건 **보존** — `jeff@ROBUST C:\Users\Jeff>`(L197) · `administrator@ROBUST C:\Users\Administrator>`(L265). 웹셸이 아닌 대화형 셸에서 플래그를 읽었다는 유일한 증거이므로 손대지 않음
- nmap raw 보존 확인 → `extract.py` `PORT_RE` 가 `ports` 색인을 정상 추출 가능

## ⓒ 헤딩 구조 — 통과

```
L22  > [!info] 요약
L28  ## Target #1 – 192.168.248.200
L30  ### Initial Access – X-Forwarded-For 헤더 위조로 IP 화이트리스트를 우회하고 SQLite UNION SQLi 로 평문 자격증명 탈취
L52  ### Service Enumeration
L82  ### Initial Access – XFF 우회 → SQLite UNION SQLi
L207 ### Privilege Escalation – Sticky Notes 평문 자격증명
L272 ### Post-Exploitation
L284 ## 관련
```

지시된 골격과 **정확히 일치**. 확인 항목:
- 두 `Initial Access` 제목이 서로 다르고, 앞이 길고 뒤가 짧음 ✓
- `## 관련` 이 H2 유지 · `## Target #1` 래퍼 **밖** ✓
- 4항목 라벨 영문 원문 — `**Vulnerability Explanation:**`·`**Vulnerability Fix:**`·`**Severity:**`·`**Steps to reproduce the attack:**` **각 2회**(Initial Access 1 + Privilege Escalation 1) ✓
- `Privilege Escalation` 은 **가르지 않음** — 4항목 + 재현이 한 절 안에 있음 ✓ (지시대로)
- `Port Scan Results` 표 존재 ✓
- 헤딩 앞뒤 빈 줄 정상, 이중 빈 줄·깨진 마크다운 없음 ✓
- `## Target #1` 의 `#1` — Obsidian 태그는 숫자만으로 구성될 수 없으므로 인라인 태그로 오인되지 않음

## ⓓ 「4항목만」 절 순수성 — 통과

L30–L51(앞 `Initial Access`) 안에 `curl` 명령·코드펜스·`![[...]]` 임베드·`— 출처:` 캡션 **전부 없음**. 재현 요소가 뒤 상세 절로 완전히 분리됨.

---

## 반증한 것

**1. 총괄 지시의 「`![[...]]` 임베드 5개」 — 틀림. 실제 4개.**
`Robust.md.bak`·`Robust.md.bak2`·현행 세 판본 모두 4개이고, `파일보관\` 에 존재하는 PNG 도 4개(`PG-Robust-403/home/login/sqli.png`)뿐. 재정렬로 하나가 사라진 것이 아니라 애초에 4개였음. **손실 아님.**

**2. 포저 보고 「3건은 이미 상세 절에 있다」 — 사실이었음.**
「상세 절에 없는데 있다고 주장했을 가능성」을 의심해 세 건을 개별 검색했으나 전부 bak2 시점부터 존재. 복원 불필요.

**3. 자기 지적 「Steps 축약으로 컬럼 수 확정 방법과 엔진 지문 방법이 소실」 — 스스로 기각.**
L141(두 방법 일치)·L143·L145–155(엔진 판별 배치 전량)에 그대로 있음. **부재를 근거로 손실을 단정하지 않고 노트 전체를 검색한 뒤 판정.**

**4. 자기 지적 「H2→H3 강등으로 다른 노트의 헤딩 링크가 깨진다」 — 스스로 기각.**
볼트 전체 `[[Robust` 인바운드 14건이 **전부 앵커 없는 `[[Robust]]`**(`_PLAYBOOK.md` 13건 + `_STATUS.md` 1건). 헤딩 텍스트 변경(`X-Forwarded-For 접근제어 우회` → `XFF 우회`)도 파급 없음. 덧붙여 Obsidian 의 `#헤딩` 링크는 레벨 무관 매칭이라 강등 자체로는 원래 안 깨짐.

**5. 포저 보고 「285행 → 290행」 — 정확.** `wc -l` 실측 일치.

---

## 이번 범위 밖 — 총괄 판단용 관찰 (고치지 않음)

**앞 `Initial Access` 의 `Vulnerability Explanation` 이 취약점 하나를 누락.**
L32 가 「두 취약점이 체인됨」이라 선언하고 ⓐXFF 신뢰 ⓑSQLi 두 개만 나열하는데, L40 의 `Vulnerability Fix` 4번째 항목(「`home.php` 인증 리다이렉트 뒤 반드시 `exit`」)과 `Steps` 2단계는 **세 번째 취약점(302 를 보내면서 본문을 전량 렌더 = 인증 우회)** 을 전제함. 심사관 관점에서 Fix 와 Steps 가 Explanation 에 없는 결함을 참조하는 형태.

- **bak2 시점부터 동일** → 이번 재정렬이 만든 회귀 **아님**. 1차 감사에서도 통과한 서술
- 고치려면 Explanation 에 항목을 **추가**해야 하므로 사실 서술 변경에 해당 → 이번 범위(구조)에 안 들어감. 손대지 않음
- `[가정]` — 별도 지시가 있으면 「세 취약점이 체인됨」으로 바꾸고 302-본문-렌더를 세 번째 불릿으로 올리는 것이 맞다고 봄

**펜스 안 주석형 표기.**
L90–98(헤더 diff)·L109–113(엔드포인트 프로빙)·L129–138·L145–152(페이로드 배치)의 ` ```text ` 블록은 원시 출력이 아니라 **결과를 정리한 표**이고 `←`·`→ 0행` 주석이 붙어 있음. bak2 와 바이트 동일하고 전부 `— 출처:` 캡션을 달고 있어 이번 작업의 사고는 아님. 1차 감사 통과분이므로 유지.

## 색인

- 프론트매터 **미변경**(`manual_tags: true` · `manual_cves: true` · `ports: [22, 80]` 유지). 태그·CVE 큐레이션 변경 없음
- 본문 헤딩 구조가 바뀌었으므로 **`refresh.ps1` 재생성 필요** — 실행은 총괄 몫(CLAUDE.md §5·§8)

## 근거 출처

- `C:\Users\QQ\Documents\Obsidian Vault\03. PG\Robust.md`
- `C:\Users\QQ\Documents\Obsidian Vault\03. PG\_backup\Robust.md.bak2` (재정렬 직전 스냅샷)
- `C:\Users\QQ\Documents\Obsidian Vault\03. PG\_backup\Robust.md.bak` (1차 개작 전, 임베드 수 대조용)
- `C:\Users\QQ\Documents\Obsidian Vault\파일보관\PG-Robust-*.png` (4개)
- `C:\Users\QQ\Documents\Obsidian Vault\03. PG\_PLAYBOOK.md` (인바운드 링크·이관 손실 확인)
- 직접 실행: 정렬 diff · `grep -c '^\`\`\`'` · 언어 태그 열거 · 헤딩 열거 · 4항목 라벨 카운트 · 임베드/캡션/플래그 카운트 · `wc -l` · `file` · 볼트 전역 `[[Robust` grep
