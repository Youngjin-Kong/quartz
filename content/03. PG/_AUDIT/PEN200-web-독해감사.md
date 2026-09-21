---
type: audit
target: "PEN-200 §8~§10 (웹 구간)"
wave: read-audit-W
role: line-manager
date: 2026-09-03
manual_tags: true
manual_cves: true
---

# PEN-200 웹 구간(8·9·10) 적대적 독해 감사

대상 45개 절 · 원문 약 18.5만 자. 기준은 `<작업폴더>\READ-AUDIT.md` 결함 6종.
코드펜스는 대상 아님 — 게이트 넷이 이미 통과했고 수정 금지.

## 착수 시점 게이트 실측 (2026-09-03, 범위 `8 10`)

| 검사기 | 결과 |
|---|---|
| `strictcheck.py` | 노트 코드블록 118개 · 줄 단위 비정렬 **0** |
| `audit2.py` | 합성 **0** · 소실 **0** · 거짓 「추출 손상」 서술 **0** |
| `covercheck.py` | 판정 근거 줄 86개 · 소실 **0** |
| `verify.py` | 45/45 · 결함 **0** |

착수 시점 산문 비율은 전 절 0.23~0.41 — 상한 0.60 대비 여유가 커,
「왜」 복원을 위한 증량이 게이트를 깨지 않는 조건이었음.

## 관리자 직접 대조 표본

실무자 판정을 받기 전에 관리자가 원문과 직접 대조한 절. 교차검증 기준선임.

### 표본 1 — 10.2.2 UNION 기반 페이로드 활용 (착수 시점 비율 0.23, 담당 구간 최저)

| 절 | 유형 | 원문 근거 | 판정 |
|---|---|---|---|
| 10.2.2 | 창작(경미) | 원문은 `Since we already verified the expected output, we can omit the percentage sign and rerun our modified query.` 뿐임 | 노트가 `%` 생략 사유로 「원 검색 결과를 함께 끌고 올 필요가 없음」을 덧붙임. 원문에 없는 «추론»임 — 기술적으로는 타당하나 근거가 원문에 없으므로 `[가정]` 강등 또는 삭제 대상 |
| 10.2.2 | 과잉압축(경미) | 원문 `we'll notice that the username and the DB version are present on the last line, but the current database name is not` | 노트는 「앞쪽 컬럼에 실으면 값이 빠지는 현상」으로 뭉뚱그려, **셋 중 DB 명만 누락되고 사용자·버전은 반환됐다**는 진단 근거가 사라짐. 원인 서술(1번 컬럼=정수형 ID)은 정확히 살아 있음 |

성립 조건 둘(컬럼 «개수» 일치 · 자료형 호환)은 뒤섞이지 않고 정확함.
`ORDER BY` 로 6에서 오류 → 5개 판정도 원문과 일치. 뜻이 뒤집힌 곳은 없음.

### 표본 2 — 8.4.1 Stored XSS와 Reflected XSS 이론 (비율 0.38)

**결함 없음.** 가장 뒤바뀌기 쉬운 자리를 전수 대조했으나 전부 정확함:

- Stored = 저장·캐시 후 방문자 전원에게 표시 → 「하나로 사이트 전체 사용자 공격」 (원문 `A single Stored XSS vulnerability can therefore attack all site users`)
- Reflected = 조작된 요청·링크, 대상은 「그 요청을 보내거나 링크를 방문한 한 명뿐」 (원문 `only attacks the person submitting the request or visiting the link`)
- DOM 기반이 stored·reflected 양쪽 가능하다는 점, 실행 주체가 애플리케이션이 아니라 사용자 브라우저라는 점 모두 보존됨

### 표본 3 — 9.1.1 절대 경로와 상대 경로 (비율 0.28, 착수 시점 담당 구간 최저군)

**결함 없음.** 비율이 낮아 과잉압축을 의심했으나, 이 절의 핵심 「왜」가 온전히 보존돼 있었음:

- 원문 `The number of ../ sequences is only relevant until we reach the root file system ... we could specify a large number of ../ to ensure we reach the root file system` → 노트 「`../` 개수는 루트에 도달할 때까지만 의미가 있음 … 현재 작업 디렉터리를 모를 때 `../` 를 넉넉히 붙이면 루트 도달이 보장됨」으로 인과까지 살아 있음. 디렉터리 탐색 절 전체가 이 성질 위에 서므로 가장 중요한 대목임
- 원문 `If we were to omit the leading slash, the terminal would search for the etc directory in the home directory` → 노트 「앞의 슬래시를 빼면 셸은 현재 디렉터리 안에서 `etc` 를 찾음」으로 정확함

⚠️ **낮은 비율이 곧 과잉압축은 아님이 실측됨.** 원문의 절차 나열이 길어 압축률이 높게 나온 것이지 「왜」가 빠진 것이 아니었음. 비율을 결함 근거로 쓰지 말 것.

### 표본 종합

세 표본 중 **결함 후보는 10.2.2 의 경미한 2건뿐이고 나머지 둘은 무결**함.
함의 — **노트는 대체로 정확하며 결함은 경미한 층에 몰려 있음.**
실무자가 뜻이 뒤집히는 중대 「오역」을 다량 보고하면 그 판정 자체를 의심하고 되짚을 것.

## 관리자 교차검증 — 표본 1(10.2.2) 실무자 수정분 되짚기

관리자가 «수정 전»에 독립 판정한 절을 실무자가 고친 뒤 다시 대조함. 판정 일치 여부가 핵심임.

| 관리자 사전 판정 | 실무자 조치 | 되짚은 결과 |
|---|---|---|
| 과잉압축 — 「셋 중 DB 명만 누락」이 뭉개짐 | 「결과에는 사용자와 버전은 나오는데 **DB 명만 빠짐**」으로 정정 | ✅ **일치.** 원문 `the username and the DB version are present ... but the current database name is not` 와 정확히 부합 |
| 창작 — `%` 생략 사유 「원 검색 결과를 끌고 올 필요 없음」이 원문에 없음 | `%'` 의 역할을 원문 근거로 명시 — 「`LIKE` 조건을 전부 일치로 만들면서 검색 파라미터의 따옴표를 닫음 → 원 `customers` 결과까지 끌고 옴」 | ✅ **해소.** 원문 `Since we want to retrieve all the data from the customers table, we'll use the percentage sign followed by a single quote to close the search parameter` 가 근거임. 삭제가 아니라 **근거를 대는 방식**으로 처리돼 뒤 문장이 추론이 아닌 귀결이 됨 |
| (관리자 미발견) | 현재 DB 명 `offsec` 을 캡션에 추가 | ✅ 원문 `including offsec as the current database name` 에 근거함. 창작 아님 |

**교차검증 판정 — 실무자 판정 신뢰 가능.** 관리자가 독립적으로 찾은 결함을 실무자가 동일하게
찾아 고쳤고, 관리자가 「창작」으로 볼 뻔한 서술은 **지우지 않고 원문 근거를 붙여** 살렸음
(READ-AUDIT 「근거가 없을 뿐인 서술은 강등하되 지우지 마라」에 부합).

## 관리자 교차검증 — 표본 4(8.4.4) 실무자 수정분

챕터 8 담당 실무자 산출물도 표본 대조함. **결함 없음.**

- 「XSS 성립 전제 셋」(① User-Agent 라 공격자 통제 ② `td` 안이라 HTML 본문 컨텍스트 ③ 새니타이즈 없음)은 **창작이 아니라 원문 재구성**임 — 원문 `inserted plainly in the Table Data (td) HTML tag, without any sort of data sanitization. As the User-Agent header is under user control` 가 셋을 모두 담고 있음
- `⚠️ 교재 오류` 표시가 **정확함.** 원문 마지막 문장 `A simple alert window is a somewhat trivial example of what creating a new administrative account.` 가 실제로 문법이 끊겨 있음. 노트는 정정값을 지어내지 않고 **원의도를 `[가정]` 으로 유보**함 — READ-AUDIT 「교재 오류 표시 오류」 유형에 해당하지 않음
- 「저장형이라 플러그인을 여는 모든 관리자에게 제공됨」 = 원문 `it will be served to any administrator that loads the plugin`

## 결함 전량 — 28건

담당 45개 절 전수 통독. 유형별 — **과잉압축 10 · 창작 5 · 오역 4 · 용어 흔들림 4 · 교재 오류 표시 4 · 블록 위치 4**.
수정 파일 16개. 코드펜스 수정 **0**.

### 챕터 8 (18개 절 · 결함 8건 · 수정 5파일)

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 8.4.5 | 오역 | `Since all the session cookies can be sent only via HTTP ... they also cannot be retrieved via JavaScript through our attack vector` | 차단 사유가 「HTTP 로만 전송되므로」로만 적혀 «전송 경로» 문제로 읽혔음 → 「**JavaScript 로는 읽을 수 없어**」를 복원. 같은 노트의 `Secure`/`HttpOnly` 표와 자기모순이던 것이 해소됨 |
| 8.3.3 | 오역 | `send it to the proxy by appending the –proxy 127.0.0.1:8080 ... **Once done**, from Burp's Repeater tab` | 「프록시로 보내**거나** Repeater 에서」(선택지) → 「보낸 **뒤** Repeater 에서」(순차 절차) |
| 8.4.5 | 교재 오류 표시 누락 | `var nonceRegex = /ser" value="([^"]*?)"/g;` vs 교재 서술 `matches any alphanumeric value contained between the string /ser" value="` | 매칭 문자열을 `ser" value="` 로 정정 + `⚠️ 교재 오류` 신설. 앞 `/` 는 정규식 리터럴 구분자이고 `([^"]*?)` 는 「영숫자」가 아니라 큰따옴표 아닌 전 문자를 잡음 |
| 8.3.3 | 교재 오류 표시 오류 | 본문 `listening on port 5001` vs 명령 `:5002` vs 배너 `[+] Url: ...:5001` | 등급 정정 — 불일치는 원문에서 «직접 확인되는 사실»이라 `[가정]` 이 과소 등급이었음 → `⚠️ 교재 오류` 로 승격. 단 「어느 포트가 정답인가」만 `[가정]` 유지 |
| 8.3.3 | 블록 위치 | 리스팅 129(POST→405) · 130(PUT) | POST 결과와 PUT 전환 근거가 두 블록 앞에 뭉쳐 있어 POST 블록을 보기 전에 PUT 설명을 읽게 돼 있었음 → PUT 근거를 POST 블록 뒤로 분리 |
| 8.2.2 | 과잉압축 | `**Along with the active information gathering we performed via Nmap**, we can also **passively** fetch` | 원문의 능동/수동 대조가 소실. 게다가 「수동으로 긁어오는」이 手動(manual)으로 읽혀 受動(passive)과 혼동됨 → 「Nmap = 능동, Wappalyzer = 대상 비접촉 수동」 대조 복원 |
| 8.4.3 · 8.4.4 | 용어 흔들림 | `unsanitized` / `without any sort of data sanitization` | 「위생 처리」 → **「새니타이즈」**. 8.4 가 「데이터 새니타이즈(sanitization)」로 병기 확정했고 9.3.2 도 동일 — 볼트 전체에서 「위생 처리」는 이 두 곳뿐이었음 |

### 챕터 9 전반 (12개 절 · 결함 7건 · 수정 5파일)

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 9.2.2 | 오역(조건 누락) | `php://filter/resource=admin.php` → `shows the same result as Listing 161. This makes sense since the PHP code is **included and executed** via the LFI vulnerability` | 도입부가 「`php://filter` 는 실행하지 않고 표시함」만 단정 → **`resource=` 만 주면 소스가 안 보이고 그대로 실행됨. `.php` 소스를 꺼내려면 `convert.base64-encode` 같은 변환 필터를 반드시 함께 걸 것** 경고 추가. **이번 웨이브 최중대 결함** — 시험장에서 그대로 따라 치면 실패함 |
| 9.1.3 | 교재 오류 표시 불충분 | `we scanned the SAMBA machine ... this directory traversal vulnerability in Apache 2.4.49 on the WEB18 machine` | 「원문만으로 판정 불가 `[가정]`」 → 교재 전체 대조로 확정: §21.1.3 의 WEB18 = `192.168.50.16`(이 절이 치는 IP), §7.3.1 의 SAMBA = `192.168.50.124` — **교재가 서로 다른 두 머신을 하나처럼 이어 서술함** |
| 9.2.1 | 교재 오류 미표시 | Listing 156 의 `input="cat /etc/passwd"`·`$cmd $arg` 에 공백이 있음에도 원문은 `We can then run those commands without using the space character` 로 단정 | 경고 신설 — 교재 예시는 IFS 를 공백으로 «설정»해 문자열을 쪼개는 예일 뿐 **요청에서 공백을 없애는 방법 자체는 보여주지 못함.** 이 절에서 실제로 통한 우회는 URL 인코딩(`%20`)임 |
| 9.3.1 | 블록 위치 | Listing 170(`echo "this is a test" > test.txt`)은 텍스트 업로드 시험용, 웹셸 업로드(Fig 139)는 다음 단계 | 두 단계가 한 문장에 몰려 블록 순서와 어긋남 → 블록 앞뒤로 분리 |
| 9.1.2 | 과잉압축 | `paste it into a file called dt_key` | 파일명이 산문에서 사라져 뒤따르는 `ssh -i dt_key` 의 인자가 근거를 잃었음 → 캡션에 보완 |
| 9.3.1 · 9.3.2 | 용어 흔들림 | `Directory Traversal` | 「디렉터리 트래버설」 3곳 → **「디렉터리 탐색」**(§9.1·9.1.2 제목 및 본문 16회가 정본) |
| 9.3.1 | 용어 흔들림 | — | 「리버스셸」 2곳 → **「리버스 셸」**(9.2.1·9.2.3 표기에 맞춤) |

### 명령어 인젝션 + 챕터 10 (15개 절 · 결함 13건 · 수정 6파일)

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 10.1.2 | 창작 | MySQL 절 원문은 `show databases` 결과에 「기본 DB」 라벨을 붙이지 않음. 다음 단계가 바로 그 `mysql` 시스템 DB 조회임 — `let's retrieve the password of the offsec user present in the mysql database` | 「`information_schema`·`mysql`·`performance_schema`·`sys` 는 기본 DB 라 목표는 그 밖의 커스텀 DB」 → 「접근 가능한 DB 목록」. **노트 자신의 다음 절차와 모순**이던 서술임. 「기본 DB」 구분은 MSSQL 절의 `master`·`tempdb`·`model`·`msdb` 에만 있는데 MySQL 쪽으로 새어 들어간 것 |
| 10.1.2 | 창작 | 원문에 `test` 를 커스텀 DB 로 규정한 문장 없음 | 캡션 「기본 4종 외에 `test` 가 커스텀 DB」 → 「접근 가능한 DB 목록」 |
| 10.2.3 · 10.3.2 | 창작 ×2 | 원문은 `enumerate the entire database for other usernames` · `the process of fetching the entire database's table is quite slow` 뿐 — **「한 글자씩(character-by-character)」 서술이 원문에 없음** | 블라인드 SQLi 를 「한 글자씩 캐냄」으로 단정한 2건을 원문 표현으로 되돌림(「참·거짓을 하나씩 물어 가며」·「응답 지연을 재 가며 값을 하나씩」). 「20분 이상」은 **유지** — 유지된 코드블록 타임스탬프(02:23:49 → 02:48:54)에서 직접 읽히는 값이라 창작 아님 |
| 10.2.2 | 오역 | `the username and the DB version are present ... but the current database name is not` | 「앞쪽 컬럼에 실으면 값이 빠짐」(셋 다 빠진 것처럼 읽힘) → 「사용자와 버전은 나오는데 **DB 명만 빠짐**」. ※ 관리자 독립 판정과 일치(위 표본 1) |
| 10.1.2 | 과잉압축 | `SQLCMD ... allows SQL queries to be run through the Windows command prompt or even remotely from another machine` | 「기본 탑재돼 있음」만 남아 있던 것 → 로컬·원격 양쪽 사용 가능함을 복원 |
| 10.1.2 | 과잉압축 | `Every database management system has its own syntax that we should take into consideration when enumerating a target` | 절의 핵심 경고가 통째로 누락 → 「DBMS 마다 열거 문법이 갈리므로 대상에 맞는 구문을 골라 던질 것」 추가 |
| 10.1.2 | 과잉압축 | `Our query returned the clear text password for both usernames` | 「이 예제의 비밀번호는 **평문**이라 해시 크래킹 없이 그대로 씀」 추가 — MySQL 의 `authentication_string` 해시와 대비되는 지점이 소실돼 있었음 |
| 10.2.1 | 과잉압축 | `The running MySQL version (8.0.28) is included ... we can query the database interactively` | `@@version` 페이로드의 **결과**가 없었음 → 버전 회수·대화형 질의 가능 상태임을 추가 |
| 10.2.2 | 과잉압축 ×2 | `we'll use the percentage sign followed by a single quote to close the search parameter` · `including offsec as the current database name` | `%'` 의 역할(따옴표 닫기 + `LIKE` 전부 일치)과 컬럼 배치 복원, DB 명 `offsec` 보강 |
| 10.2.1 | 블록 위치 | 원문 순서 = 페이로드(Listing 207) → 오류 → `This means that we should only query one column at a time` | 노트가 「한 컬럼만 됨」 결론을 페이로드 **앞**에 두어 인과가 뒤집혀 있었음 → 재배치 |
| 9.4.1 | 블록 위치 | `we'll start a third terminal tab to create a Netcat listener on port 4444` (Listing 186) | 「리스너 올림 + 명령 주입함」이 한 문단으로 nc 블록보다 앞에 있었음 → 리스너 문장은 블록 앞, 주입 명령 설명은 블록 뒤로 분리 |

## 실무자 자기 반증 — 지적했다가 원문 대조로 철회한 것 10건

**「원문에 없어 보이면 먼저 내가 못 찾은 것을 의심하라」가 실제로 작동했음.** 창작 오판을 막은 사례:

| 절 | 처음 의심 | 반증 근거 | 결과 |
|---|---|---|---|
| 10.1.2 | 「MySQL 은 `@@version` 도 받음」이 10.1.2 원문에 없어 창작 — **일단 삭제했음** | 원문 **전체** 재검색에서 10.2.1 의 `MySQL accepts both version() and @@version statements.` 발견 | **복원.** 출처가 다른 절임을 「(§10.2.1)」로 표기 |
| 8.5 | `열거(enumeration)` 병기가 8.5 에서야 나옴 = SPEC §2 「첫 등장 병기」 위반 | 볼트 전수 grep — 같은 병기가 2.3.2·18·22·25·27.1 등 **11개 노트에 반복** 등장. 노트가 각각 단독 진입점이라 **절마다 재병기가 이 라인의 관례** | 결함 아님 |
| 9.2.1 | 교재의 `Input Field Separators (IFS)` 가 오타(정정: Internal) | **POSIX XCU 가 IFS 를 「Input Field Separators」로 정의함**(bash 매뉴얼만 Internal) | 교재 오류 표시를 붙이지 않음 |
| 9.2.3 | LFI/RFI 전제로 `allow_url_fopen` 이 누락됨 | 원문 전체가 `allow_url_include` 만 언급 — 추가하면 창작 | 폐기 |
| 8.4.3 | 원문 「애플리케이션이 해석」을 노트가 「브라우저」로 바꿈 = 오역 | 같은 절 뒷부분 원문이 `the browser will treat them as code elements` | 결함 아님 |
| 8.4.5 | 「nonce 는 저장형 XSS 앞에서 장애물이 아님」의 인과가 창작 | 원문 `the nonce won't be an obstacle for the stored XSS vulnerability` + 리스팅 137 + 8.4.1 의 실행 컨텍스트 서술 | 원문 근거 있는 「왜」 복원 |
| 9.3.2 | 「이번 버전은 Linux 에서 돈다」가 오역(Figure 141 캡션은 "on Windows") | 본문이 `running on Linux` 이고 후속 실측이 Linux 지지. **캡션 쪽이 교재 오류이나 노트가 그 그림을 싣지 않아** 표시 대상 없음 | 폐기 |
| 8.4.2 | 단축키(`C+B+k`)를 옮기지 않은 것이 소실 | PDF 추출에서 수식 키 글리프가 치환된 형태라 조합 특정 불가. 노트가 이미 `[가정]` 명시 | 현행 유지 |
| 9.1.2 | 「navigation bar」를 「주소 표시줄」로 옮긴 것 | 지시 대상이 `index.php` 이고 PHP 판정 인과가 동일 | 폐기 |
| 9.1.1 | 「이 성질이 공격에서 중요함」이 원문에 없는 프레이밍 | 원문이 예로 「현재 작업 디렉터리를 모를 때」를 들고 9.1.2 가 실제로 `../` 9개를 그렇게 씀 | 폐기 |

## 관리자 판정 — 올라온 2건

### ① 10.3.2 `sqlmap` 시험 금지 문구 — **유지하되 출처를 명시함**

원문에 없는 시험 규정 서술이라 SPEC §6 에 형식상 저촉된다는 보고. **관리자 판정 — 삭제하지 않음.**

- 사실로 검증됨(볼트 `CLAUDE.md` §4 금지 도구 표에 `sqlmap` 등재). **반증된 것이 아니라 참인 서술**이므로 READ-AUDIT 「반증된 것만 정정, 근거 없을 뿐인 것은 강등」에 따라 삭제 대상이 아님
- 볼트 최종 목적(시험 당일 참조)에서 이 한 줄의 손실이 큼 — 금지 도구를 모르고 쓰면 시험이 무효가 됨
- ⚠️ **다만 원안은 노트 자신의 목소리로 적혀 교재 서술로 오독될 소지가 있었음.** 관리자가 `> ⚠️ **교재 밖 주의 — OSCP 시험 규정** (원문에 없는 내용임)` 으로 **출처를 명시**해 인용 블록으로 분리함. 내용은 그대로 두고 «누가 한 말인가»만 드러낸 처리임

### ② 9.2.2 Listing 164 명령줄 소실 — **총괄 보고 사항. 이번 웨이브에서 고치지 않음**

원문 `echo "<base64>" | base64 -d` 의 **명령줄이 빠지고 디코드 출력만** 남아 있음. SPEC §3-D 「명령 — 프롬프트가 붙은 실행 줄」 항목에 해당할 소지.

- **코드펜스라 이번 웨이브의 수정 범위 밖임**(READ-AUDIT 「블록에 문제가 보이면 보고만」). 실무자·관리자 모두 손대지 않음
- `covercheck.py` 는 소실 0 으로 통과함 — 검사기가 이 형태를 못 잡는 것인지, 판정 근거 줄이 아니라 통과가 정상인지는 **총괄 판정 몫**
- 산문이 「`base64` 명령에 `-d` 를 주어 디코드함」으로 대체 서술 중이라 **당장의 재현 실패 위험은 낮음** `[가정]`

## 마감 게이트 — 회귀 없음 (범위 `8 10`)

| 검사기 | 착수 시점 | 마감 시점 |
|---|---|---|
| `strictcheck.py` | 비정렬 0 | **비정렬 0** (코드블록 118개) |
| `audit2.py` | 합성 0 · 소실 0 | **합성 0 · 소실 0** |
| `covercheck.py` | 소실 0 | **소실 0** (판정 근거 줄 86개) |
| `verify.py` | 45/45 결함 0 | **45/45 결함 0** |

산문 비율 — 착수 0.23~0.41 → 마감 **0.25~0.44**(최저 10.1.1, 최고 8.2.2). 상·하한(0.15~0.60) 이탈 **0건**.
코드블록 수 118개로 착수 시점과 동일 — **코드펜스 무수정 확인됨.**
