---
tags:
  - type/theory
  - platform/swsec
  - tech/lin/passwd-write
  - tech/web/lfi-rfi
  - tech/web/file-upload
  - tech/web/deserialization
  - tech/web/xss
  - tech/web/ssrf
  - tech/web/cmd-injection
type: theory
platform: swsec
ip: 192.168.0.3
tech_count: 7
---
# SW보안약점 진단원 통합 수험서 (2026.8.8 대비)

> 이 파일 하나로 학습이 완결되도록 구성한 통합본입니다. 원문 근거: 「2026년 SW보안약점 진단원 이수시험 안내서」(행정안전부·KISA 공식), 「소프트웨어 개발보안 가이드」(2021.12.29) — 모든 항목 정의·대책·코드예제는 이 두 문서에서 추출·요약했습니다.

## 목차

1. 시험 정보 및 15일 학습 플랜
2. 설계단계 보안설계 기준 20항목 + 필수 암기사항
3. 구현단계 보안약점 49개 항목별 상세 (정의·대책·코드예제·정탐/오탐)
4. 정탐/오탐 연습문제 + 복합서술형 양식
5. 키워드 점검 문제 40제

---

# 제1장. 시험 정보 및 15일 학습 플랜

> 대상: 재응시자 · 하루 5시간 이상 확보 가능 출처: 「2026년 소프트웨어 보안약점 진단원 이수시험 안내서」(행정안전부·KISA) 공식 확인 완료

### 공식 시험 정보 (안내서 기준)

|구분|시간|문항|배점|과락|가중치|유형|
|---|---|---|---|---|---|---|
|이론시험|60분 (13:00~14:00)|30문항|100점|60점 미만|40%|**전면 객관식(4~5지선다), OMR·컴퓨터용 사인펜**|
|실습시험|100분 (14:30~16:10)|15문항|100점|60점 미만|60%|**서술형(정·오탐 분석 및 보고서 작성), 검은색 볼펜**|

- 합격: 가중 종합점수 **70점 이상** (69.9점 불합격 — 소수점 첫째 자리 기준)
- 실습 유형: ① 단순서술형(보안약점 정·오탐 분석) ② 복합서술형(요구사항정의서·아키텍처설계서·개발가이드 검토 → 보완요청서·진단보고서 작성, 문항당 8점 수준)
- **시험 중 'SW 보안약점 기준 명칭' 자료가 제공됨** → 기준 번호·명칭만 묻는 문제는 출제되지 않음. 명칭 암기보다 **각 기준의 상세 내용 숙지**가 관건 (안내서 FAQ Q4)
- 응시 기회: **총 2회 (자동응시 1회 + 선택응시 1회)**. 1차(8/8) 응시 불가 시 **7/31(금) 13:59까지 반드시 취소** — 무단 불참 시 기회 1회 차감
- 입실: 12:50까지 (이후 입실·응시 불가) / 준비물: 신분증, 검은색 볼펜, 컴퓨터용 사인펜 (연필 금지)
- 합격 발표: 1차 8/21(금), 이메일 개별 통보

### 전략 요약

재응시자의 최대 자산은 "시험장에서 무엇이 나오는지 안다"는 것입니다. 이번 15일은 넓게 다시 훑는 것이 아니라, **배점 60%인 실습시험(정·오탐 분석 + 보완요청서·진단보고서 작성)을 중심축**으로 놓고, 이론시험(전면 객관식 30문항)은 개념·코드 판별 훈련으로 방어하는 구조입니다.

시험 중 '보안약점 기준 명칭'이 제공되므로 명칭 통암기의 부담은 줄었습니다. 대신 점수를 가르는 것은 ① 코드를 보고 해당 약점을 판별하는 눈 ② 정·오탐 사유를 채점 키워드가 들어가게 서술하는 능력 ③ 보완요청서·진단보고서 양식에 맞춘 작성 훈련입니다.

배분 원칙 (하루 5시간 기준):

|시간|내용|
|---|---|
|2시간|구현단계 49개 — 코드 예제 + 정탐/오탐 판단 훈련|
|1.5시간|각 기준의 상세 내용(설명·대응방법) 학습 — 설계 20 / 구현 49|
|1시간|서술 연습 — 정·오탐 사유, 보완요청서·진단보고서를 "손으로" 작성|
|0.5시간|전날 복습 (누적 복습)|

### Phase 1 — 구조 재정비 (7/24 목 ~ 7/26 토, D-15~D-13)

- **7/24(목)**: 카테고리 골격 완전 암기 — 설계 4분야 20항목(10-8-1-1), 구현 7유형 49항목(17-16-2-3-5-4-2). 숫자 구조부터 외우면 시험장 배부 자료를 빠르게 활용할 수 있다는 것이 합격자 공통 조언.
- **7/25(금)**: 설계단계 20항목 — 항목명과 핵심 키워드(요약본 활용) 1차 암기. 지난 시험에서 틀렸던 영역 표시.
- **7/26(토)**: 2021 개정사항 정리(통폐합 4개·신규 6개 — 출제 포인트), 구현단계 "입력데이터 검증 및 표현" 17개 항목명 + 대표 대응책 암기 시작.

### Phase 2 — 구현단계 49개 정면돌파 (7/27 일 ~ 8/1 금, D-12~D-7)

하루 8~9개 항목씩, 항목마다 ① 정의 ② 안전/취약 코드 패턴 ③ 진단방법(정탐 조건·오탐 조건) 세트로 학습.

- **7/27(일)**: 입력데이터 검증 및 표현 1~9 (SQL삽입~XML삽입) — 삽입계열 집중
- **7/28(월)**: 입력데이터 검증 및 표현 10~17 (LDAP삽입~포맷스트링) + CSRF/SSRF 구분
- **7/29(화)**: 보안기능 1~8 (인증·인가·권한·암호화 계열)
- **7/30(수)**: 보안기능 9~16 (난수·전자서명·인증서·쿠키·해쉬 계열)
- **7/31(목)**: 시간및상태 2 + 에러처리 3 + 코드오류 5
- **8/1(금)**: 캡슐화 4 + API오용 2 + 49개 전체 명칭 셀프테스트 (백지 복기)

매일 마지막 1시간: 정탐/오탐 연습 문제 3~4문항을 실제처럼 손으로 서술.

### Phase 3 — 설계단계 심화 + 실전 모드 (8/2 토 ~ 8/6 목, D-6~D-2)

- **8/2(토)**: 설계단계 20항목 설명 내용 학습 (안내서 붙임3의 '설명' 열 수준으로 쓸 수 있게). 채점 예시상 빨간 글씨(핵심 키워드)가 포함되어야 정답 인정 — 키워드 중심 서술 연습.
- **8/3(일)**: 모의 문제 1회분 실전 풀이(시간 재고: 이론 30문항 60분 감각) → 오답 전수 복습
- **8/4(월)**: **복합서술형 집중** — 안내서 붙임2 예시처럼 요구사항정의서·아키텍처설계서·개발가이드를 대조해 불일치를 찾고, 보완요청서(문제 원인 4점 + 해결방안 4점)와 진단보고서 양식을 손으로 2회 이상 작성
- **8/5(화)**: 약점 영역 집중일 — 지난 시험 실패 영역 + 이번 모의에서 틀린 영역만
- **8/6(수)**: 백지 복기 2차: 설계 20 + 구현 49 전체 구조와 각 기준의 핵심 대응방법. 안 나오는 것만 반복.

### Phase 4 — 마무리 (8/7 금 ~ 8/8 토)

- **8/7(금)**: 새 내용 금지. 요약본 2회독 + 정오탐 오답노트만. **준비물(신분증·검은색 볼펜·컴퓨터용 사인펜) 확인**, 시험장 위치 확인, 일찍 취침.
- **8/8(토) 시험일**: **12:50까지 입실 완료** (이후 응시 불가). 직전에는 오답노트와 권고 암호 알고리즘 표만 확인. 이론은 사인펜(OMR), 실습은 볼펜으로 작성 — 필기구 혼동 시 0점 처리 주의.

### 체크포인트 (스스로 통과해야 다음 Phase 진행)

1. D-13: 설계 4분야·구현 7유형 이름과 개수를 백지에 쓸 수 있는가
2. D-7: 구현 49개 항목명을 유형별로 백지 복기할 수 있는가
3. D-4: 임의의 코드를 보고 해당 보안약점 명칭 + 정탐/오탐 + 사유를 **6분 내**(실습 15문항/100분 기준 문항당 평균 6.7분) 서술할 수 있는가
4. D-2: 모의 문제 80% 이상 정답 + 보완요청서·진단보고서를 양식 보지 않고 쓸 수 있는가

### 유의사항

- 시험 형식·일정·배점은 공식 「2026년 이수시험 안내서」에서 직접 확인한 내용입니다. 일정은 내부 사정에 따라 변경될 수 있으므로 swsca.kr 공지를 계속 확인하세요.
- 학습 내용의 최종 기준은 「소프트웨어 개발보안 가이드」(2021.12)와 「소프트웨어 보안약점 진단가이드」(2021.11), 진단원 기본(양성) 교재입니다 (안내서의 공식 참고자료 목록).

---

# 제2장. 설계단계 20항목 + 필수 암기사항

> 기준: 행정안전부·KISA 「소프트웨어 개발보안 가이드」(2021.12.29) 원문 및 「2026년 이수시험 안내서」 붙임3 '소프트웨어 보안약점 기준'으로 검증 완료 구조: **설계단계 20개 항목(4개 분야)** + **구현단계 49개 보안약점(7개 유형)** ※ 시험 중 'SW 보안약점 기준 명칭' 자료가 제공되고, 기준 번호·명칭만 묻는 문제는 출제되지 않음(안내서 FAQ). 따라서 이 요약본은 명칭 통암기용이 아니라 **각 기준의 내용·대응방법을 구조적으로 익히는 용도**로 사용할 것.

---

### 0. 개수 구조 (가장 먼저 암기)

|구분|분야/유형|개수|
|---|---|---|
|설계단계|입력데이터 검증 및 표현|**10**|
|설계단계|보안기능|**8**|
|설계단계|에러처리(예외처리)|**1**|
|설계단계|세션통제|**1**|
||**설계 합계**|**20**|
|구현단계|입력데이터 검증 및 표현|**17**|
|구현단계|보안기능|**16**|
|구현단계|시간 및 상태|**2**|
|구현단계|에러처리|**3**|
|구현단계|코드오류|**5**|
|구현단계|캡슐화|**4**|
|구현단계|API 오용|**2**|
||**구현 합계**|**49**|

암기 코드: 설계 **10-8-1-1**, 구현 **17-16-2-3-5-4-2** (구현 유형 순서: 입·보·시·에·코·캡·A → "**입보시에 코캡에이**")

---

### 1. 설계단계 보안설계 기준 20항목

※ 번호는 개발보안 가이드(2021) 제3장 절 번호 기준(1.1~1.10, 2.1~2.8, 3.1, 4.1). 아래 표의 SR 표기는 같은 순서의 관용 표기.

#### 분야1. 입력데이터 검증 및 표현 (SR1, 10개)

|번호|항목|핵심 키워드 (서술 시 2개 이상 조합)|
|---|---|---|
|SR1-1|DBMS 조회 및 결과 검증|SQL문 파라미터 검증·필터링, Prepared Statement(바인딩), 오류 시 내부정보 미노출|
|SR1-2|XML 조회 및 결과 검증|XPath/XQuery 파라미터 검증, 외부개체(External Entity) 사용 제한|
|SR1-3|디렉토리 서비스 조회 및 결과 검증|LDAP 검색 입력값 필터링, 특수문자 제한|
|SR1-4|시스템 자원 접근 및 명령어 수행 입력값 검증|경로조작 문자(../ 등) 필터링, OS 명령어 화이트리스트, 자원 접근 제한|
|SR1-5|웹 서비스 요청 및 결과 검증|XSS 방지 — 입력·출력값 검증, 스크립트 무력화(인코딩)|
|SR1-6|웹 기반 중요기능 수행 요청 유효성 검증|CSRF 방지 — 토큰, 재인증, 요청 정상 여부 확인|
|SR1-7|HTTP 프로토콜 유효성 검증|응답분할(CR/LF) 방지, 리다이렉트 URL 화이트리스트, 헤더 검증|
|SR1-8|허용된 범위 내 메모리 접근|버퍼오버플로우 방지, 배열 경계·포맷스트링 검증|
|SR1-9|보안기능 입력값 검증|보안기능(인증·권한부여 등) 입력값과 함수(리턴값 포함)의 외부입력값·수행결과에 대한 유효성 검증방법 설계 — 쿠키·히든필드 등 서버측 검증|
|SR1-10|업로드·다운로드 파일 검증|확장자·크기·개수 제한, 저장경로 분리, 실행권한 제거, 파일명 난수화, 무결성 검사|

#### 분야2. 보안기능 (SR2, 8개)

|번호|항목|핵심 키워드|
|---|---|---|
|SR2-1|인증 대상 및 방식|중요기능·자원은 인증 후 사용, 중요기능은 2단계(강화된) 인증, DB테이블 중요도 분류|
|SR2-2|인증 수행 제한|인증 반복시도 제한, 횟수 초과 시 잠금·지연, 불법 인증시도 통지|
|SR2-3|비밀번호 관리|생성규칙(길이·조합), 저장 시 솔트+일방향 해쉬, 변경주기, 초기화·재발급 절차|
|SR2-4|중요자원 접근통제|권한 분류·최소권한, 접근통제 정책 서버측 구현, 우회 불가|
|SR2-5|암호키 관리|안전한 키 생성·분배·접근·파기 절차, 하드코딩 금지|
|SR2-6|암호연산|검증된(표준) 암호 알고리즘, 안전한 키 길이, 안전한 난수(예측 불가)|
|SR2-7|중요정보 저장|중요정보 암호화 저장, 메모리·임시파일 내 노출 최소화, 쿠키에 중요정보 저장 금지|
|SR2-8|중요정보 전송|전송 시 암호화(TLS 등) 또는 암호화 통신채널, 캐시 통제|

#### 분야3. 에러처리 (SR3, 1개)

|SR3-1|예외처리|오류 메시지에 내부정보(스택트레이스·SQL·경로) 미포함, 오류상황 대응(차단·기본값), 예외 누락 없이 처리|
|---|---|---|

#### 분야4. 세션통제 (SR4, 1개)

|SR4-1|세션통제|세션 타임아웃, 재로그인 시 세션ID 재발급, 세션ID 예측 불가, 중복 로그인 통제|
|---|---|---|

---

### 2. 구현단계 보안약점 49개

#### 유형1. 입력데이터 검증 및 표현 (17개)

"외부 입력값을 검증하지 않아 발생" — 삽입/주입 계열 총집합

|#|항목|대표 대응책 한 줄|
|---|---|---|
|1|SQL 삽입|Prepared Statement 바인딩, 입력값 필터링|
|2|코드 삽입 ⭐신규|eval 등 동적 코드 실행에 외부입력 사용 금지·검증|
|3|경로 조작 및 자원 삽입|../, 절대경로 등 경로문자 필터링, 화이트리스트|
|4|크로스사이트 스크립트(XSS)|출력 시 HTML 인코딩, 입력 검증(치환·제거)|
|5|운영체제 명령어 삽입|외부입력을 명령어에 직접 사용 금지, 화이트리스트|
|6|위험한 형식 파일 업로드|확장자·타입 화이트리스트, 실행권한 제거, 경로 분리|
|7|신뢰되지 않는 URL 주소로 자동접속 연결|리다이렉트 대상 화이트리스트 관리|
|8|부적절한 XML 외부개체 참조(XXE) ⭐신규|DTD·외부엔티티 처리 비활성화|
|9|XML 삽입 (XPath·XQuery 통합) ★통폐합|파라미터화된 XPath/XQuery, 특수문자 필터링|
|10|LDAP 삽입|특수문자 이스케이프, 입력값 검증|
|11|크로스사이트 요청 위조(CSRF)|CSRF 토큰, 재인증, Referer 검증|
|12|서버사이드 요청 위조(SSRF) ⭐신규|요청 대상 서버 화이트리스트, 내부망 접근 차단|
|13|HTTP 응답분할|입력값의 CR/LF 제거 후 헤더에 사용|
|14|정수형 오버플로우|연산 전 범위 검증, 부호·크기 확인|
|15|보안기능 결정에 사용되는 부적절한 입력값|쿠키·히든필드 등으로 보안결정 금지, 서버측 검증|
|16|메모리 버퍼 오버플로우|경계 검사, 안전한 함수(strncpy 등) 사용|
|17|포맷 스트링 삽입|외부입력을 포맷문자열로 직접 사용 금지|

#### 유형2. 보안기능 (16개)

"인증·인가·암호·권한을 부적절하게 구현"

|#|항목|대표 대응책 한 줄|
|---|---|---|
|1|적절한 인증 없는 중요기능 허용|중요기능 재인증·인증 강화|
|2|부적절한 인가|서버측에서 접근권한 검사 후 기능 수행|
|3|중요한 자원에 대한 잘못된 권한 설정|설정파일·중요자원 최소권한 부여|
|4|취약한 암호화 알고리즘 사용|DES·MD5·SHA-1 등 금지, 검증된 알고리즘(AES, SHA-256↑)|
|5|암호화되지 않은 중요정보 ★통폐합(평문 저장+전송)|중요정보 저장·전송 시 암호화|
|6|하드코드된 중요정보 ★통폐합(비밀번호+암호화키)|소스에 비밀번호·키 하드코딩 금지, 별도 저장·암호화|
|7|충분하지 않은 키 길이 사용|RSA 2048↑, 대칭키 128비트↑ 등|
|8|적절하지 않은 난수 값 사용|java.util.Random 금지 → SecureRandom 등|
|9|취약한 비밀번호 허용|길이·조합 규칙 강제|
|10|부적절한 전자서명 확인 ⭐신규|서명 검증 후 데이터·코드 사용|
|11|부적절한 인증서 유효성 검증 ⭐신규|인증서 검증 로직 생략·무시 금지|
|12|사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출|영속쿠키에 중요정보 금지, 세션쿠키 사용|
|13|주석문 안에 포함된 시스템 주요정보|배포 전 주석 내 계정·키 제거|
|14|솔트 없이 일방향 해쉬 함수 사용|패스워드 해쉬 시 랜덤 솔트 적용|
|15|무결성 검사 없는 코드 다운로드|다운로드 코드 서명·해쉬 검증 후 실행|
|16|반복된 인증시도 제한 기능 부재|시도횟수 제한·계정 잠금|

#### 유형3. 시간 및 상태 (2개)

|1|경쟁조건: 검사시점과 사용시점(TOCTOU)|공유자원 동기화(synchronized), 검사·사용 원자화|
|---|---|---|
|2|종료되지 않는 반복문 또는 재귀함수|종료조건·최대 반복횟수 설정|

#### 유형4. 에러처리 (3개)

|1|오류 메시지 정보노출 ★통폐합(에러메시지+시스템데이터)|사용자에겐 최소 정보, 상세내용은 서버 로그로|
|---|---|---|
|2|오류상황 대응 부재|오류 발생 시 처리 로직(차단·복구) 구현|
|3|부적절한 예외 처리|광범위 catch(Exception) 지양, 예외별 처리|

#### 유형5. 코드오류 (5개)

|1|Null Pointer 역참조|사용 전 null 검사|
|---|---|---|
|2|부적절한 자원 해제|finally/try-with-resources로 자원 반환|
|3|해제된 자원 사용|해제 후 참조 금지, 포인터 null 처리|
|4|초기화되지 않은 변수 사용|선언 시 초기화|
|5|신뢰할 수 없는 데이터의 역직렬화 ⭐신규|외부 직렬화 데이터 검증, 역직렬화 대상 클래스 제한|

#### 유형6. 캡슐화 (4개)

|1|잘못된 세션에 의한 데이터 정보노출|멤버변수 대신 지역변수(싱글톤·서블릿), 세션간 데이터 공유 금지|
|---|---|---|
|2|제거되지 않고 남은 디버그 코드|배포 전 디버그 코드(main, 테스트 계정) 제거|
|3|Public 메소드로부터 반환된 Private 배열|복제본 반환 또는 수정 불가 처리|
|4|Private 배열에 Public 데이터 할당|외부 배열을 복사해서 할당|

#### 유형7. API 오용 (2개)

|1|DNS lookup에 의존한 보안결정|DNS 결과로 인증·인가 결정 금지, IP·인증 병행|
|---|---|---|
|2|취약한 API 사용|금지 API(gets, strcpy, system 등) 대신 안전한 API|

---

### 3. 2021 개정 포인트 (출제 빈출)

**통폐합 (8개 → 4개)**

|기존|→ 통합 후|
|---|---|
|XPath 삽입 + XQuery 삽입|XML 삽입|
|중요정보 평문 저장 + 평문 전송|암호화되지 않은 중요정보|
|하드코딩된 비밀번호 + 하드코드된 암호화키|하드코드된 중요정보|
|에러 메시지 정보노출 + 시스템 데이터 정보노출|오류 메시지 정보노출|

**신규 6개**: 코드 삽입, 부적절한 XML 외부개체 참조(XXE), 서버사이드 요청 위조(SSRF) — 입력데이터 / 부적절한 전자서명 확인, 부적절한 인증서 유효성 검증 — 보안기능 / 신뢰할 수 없는 데이터의 역직렬화 — 코드오류

**결과**: 2019년 47개 → 2021년 49개

---

### 4. 공식 채점 기준에 등장한 필수 암기 사항 (안내서 붙임2 예시 답안 출처)

**국내 사용 권고 암호 알고리즘 + 안전한 키 길이** — 실습 예시 문제로 실제 출제된 내용

|구분|권고 알고리즘|안전한 키 길이|
|---|---|---|
|대칭키|SEED, ARIA, AES, Blowfish, Camellia, MISTY1, KASUMI|**128bit 이상**|
|비대칭키|RSA, KCDSA, RSAES-OAEP, ECC, ElGamal|**2048bit 이상**|

- 대칭키 vs 비대칭키 선택 논리: 큰 데이터의 빈번한 암·복호 통신 → **대칭키가 적합** (비대칭키는 연산이 많아 속도가 느림) — 채점 시 "속도" 키워드 필수
- 비밀번호 해쉬: **SHA2(SHA-256) 이상** + **솔트 필수**, 해쉬 연산은 클라이언트가 아닌 **서버에서 수행**

**비밀번호 생성 규칙 (KISA 암호이용안내서 기준, 예시 문제 출처)**

- 3가지 유형(영문·숫자·특수문자) 조합 시 **8자 이상**, 2가지 유형 조합 시 **10자 이상**
- 전화번호 등 개인 신상정보 포함 금지, 많이 사용되는 단어 금지, 반복 문자열·키보드 배열 패턴 금지
- 변경주기 **3~6개월**, 이전 비밀번호 연속 재사용 금지, 임시 비밀번호 로그인 시 변경 후 재로그인, 장기 미로그인 계정 만료 처리

**쿠키 보안 속성 (이론 예시 문제 출처)**: setSecure(true) → HTTP로는 쿠키 미전송(HTTPS만), setHttpOnly(true) → document.cookie 등 자바스크립트 접근 차단, 만료시간 과도하게 길게 설정 금지, 쿠키 값 입력 전 CR/LF 제거(응답분할 대비)

### 5. 자주 헷갈리는 짝 정리

- **CSRF vs SSRF**: CSRF는 "사용자 브라우저"가 위조 요청의 주체, SSRF는 "서버"가 공격자가 지정한 곳으로 요청
- **XSS vs SQL삽입**: XSS는 출력(브라우저에서 스크립트 실행), SQL삽입은 DB 질의문 조작
- **부적절한 인가 vs 잘못된 권한 설정**: 인가는 "코드에서 권한검사 누락", 권한 설정은 "자원(파일 등)의 퍼미션 자체가 과다"
- **오류상황 대응 부재 vs 부적절한 예외처리**: 전자는 처리 자체가 없음(빈 catch 포함), 후자는 처리하지만 부적절(광범위 예외 등)
- **설계단계 SR1-9와 구현 '보안기능 결정에 사용되는 부적절한 입력값'**: 같은 개념의 설계/구현 대응 관계

---

# 제3장. 구현단계 보안약점 49개 항목별 상세

> 각 항목: 정의 → 보안대책 → 코드 포인트 → 정탐/오탐 판단 → 코드예제(취약/안전). 실습 서술 답안은 '정탐/오탐 판단'의 논리를 문장으로 풀어 쓰면 됩니다.

|유형|개수|번호|
|---|---|---|
|1. 입력데이터 검증 및 표현|17|1-1 ~ 1-17|
|2. 보안기능|16|2-1 ~ 2-16|
|3. 시간 및 상태|2|3-1 ~ 3-2|
|4. 에러처리|3|4-1 ~ 4-3|
|5. 코드오류|5|5-1 ~ 5-5|
|6. 캡슐화|4|6-1 ~ 6-4|
|7. API 오용|2|7-1 ~ 7-2|

#### 1-1. SQL 삽입

- **정의**: DB와 연동된 웹 응용프로그램에서 입력 데이터의 유효성을 검증하지 않을 경우, 공격자가 입력 폼·URL 입력란에 SQL문을 삽입하여 DB 정보를 열람·조작할 수 있는 보안약점이다. 사용자 입력값을 필터링 없이 넘겨받아 동적 쿼리를 생성하면 개발자가 의도하지 않은 쿼리가 생성되어 정보유출에 악용될 수 있다.
- **보안대책**:
    - PreparedStatement 객체 등을 이용하여 DB에 컴파일된 쿼리문(상수)을 전달한다.
    - DB 쿼리에 사용되는 외부 입력값에 대해 특수문자 및 쿼리 예약어를 필터링한다.
    - Struts, Spring 등 프레임워크 사용 시 외부 입력값 검증모듈·보안모듈을 상황에 맞게 사용한다.
    - MyBatis 쿼리맵 바인딩 시 `$` 대신 `#` 기호를 사용한다.
- **코드 포인트**: 문자열 연결로 쿼리 조립 후 Statement.executeQuery 실행 → PreparedStatement에 `?` 바인딩 변수 + setString으로 파라미터 설정 / MyBatis `${keyword}` → `#{keyword}` / Hibernate 문자열 연결 createQuery → `?` 또는 `:name` 명명 파라미터 바인딩(setString·setParameter)
- **정탐/오탐 판단**: 정탐 — request 파라미터 등 외부입력이 검증·바인딩 없이 문자열 연결로 SQL 쿼리에 포함되어 실행(executeQuery 등)에 도달. 오탐 — PreparedStatement/파라미터 바인딩(?·#·:명명 파라미터·@변수)으로 처리되거나 특수문자·쿼리 예약어 필터링을 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
String gubun = request.getParameter("gubun");
// 외부로부터 입력받은 값을 검증 없이 쿼리 생성에 사용
String sql = "SELECT * FROM board WHERE b_gubun = '" + gubun + "'";
Connection con = db.getConnection();
Statement stmt = con.createStatement();
// 검증 또는 처리 없이 쿼리로 수행되어 안전하지 않다.
ResultSet rs = stmt.executeQuery(sql);
```

**안전 (Java)**

```java
String gubun = request.getParameter("gubun");
// PreparedStatement 사용을 위해 ?문자로 바인딩 변수를 사용한다.
String sql = "SELECT * FROM board WHERE b_gubun = ?";
Connection con = db.getConnection();
PreparedStatement pstmt = con.prepareStatement(sql);
// 파라미터 부분을 setString 등의 메소드로 설정하여 안전하다.
pstmt.setString(1, gubun);
ResultSet rs = pstmt.executeQuery();
```

#### 1-2. 코드 삽입

- **정의**: 공격자가 소프트웨어의 의도된 동작을 변경하도록 임의 코드를 삽입하여 소프트웨어가 비정상적으로 동작하도록 하는 보안약점으로, 프로그래밍 언어 자체의 기능에 의해서만 제한된다는 점에서 운영체제 명령어 삽입과 다르다. 입력값에 코드 포함을 허용하면 공격자는 권한 탈취, 인증 우회, 시스템 명령어 실행 등을 할 수 있다.
- **보안대책**:
    - 동적코드를 실행할 수 있는 함수를 사용하지 않는다.
    - 필요 시 실행 가능한 동적코드를 입력값으로 받지 않도록 외부 입력값을 화이트리스트 방식으로 구현한다.
    - 동적 코드에 사용되는 사용자 입력값은 유효한 문자만 포함하도록 필터링한다.
- **코드 포인트**: 외부 입력 src를 ScriptEngine.eval()로 직접 실행(또는 new Function()으로 실행) → 정규식(`[ \w]*`)으로 특수문자 입력 시 예외 발생 후 실행하거나, 화이트리스트로 유효한 문자일 때만 지정 메소드 호출
- **정탐/오탐 판단**: 정탐 — 외부입력이 검증 없이 eval()·new Function() 등 동적 코드 실행 함수의 인자로 도달. 오탐 — 정규표현식 필터링으로 특수문자를 차단하거나 화이트리스트로 허용된 값만 실행하고 그 외는 예외 처리하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
@RequestMapping(value = "/execute", method = RequestMethod.GET)
public String execute(@RequestParam("src") String src) throws ScriptException {
    ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
    ScriptEngine scriptEngine = scriptEngineManager.getEngineByName("javascript");
    // 외부 입력값인 src를 javascript eval 함수로 실행하고 있어 안전하지 않다.
    String retValue = (String) scriptEngine.eval(src);
    return retValue;
}
```

**안전 (Java)**

```java
@RequestMapping(value = "/execute", method = RequestMethod.GET)
public String execute(@RequestParam("src") String src) throws ScriptException {
    // 정규식을 이용하여 특수문자 입력시 예외를 발생시킨다.
    if (src.matches("[ \\w]*") == false) {
        throw new IllegalArgumentException();
    }
    ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
    ScriptEngine scriptEngine = scriptEngineManager.getEngineByName("javascript");
    String retValue = (String) scriptEngine.eval(src);
    return retValue;
}
```

#### 1-3. 경로 조작 및 자원 삽입

- **정의**: 검증되지 않은 외부 입력값으로 파일 및 서버 등 시스템 자원에 대한 접근 혹은 식별을 허용할 경우, 입력값 조작으로 시스템이 보호하는 자원에 임의로 접근할 수 있는 보안약점이다. 공격자는 자원의 수정·삭제, 시스템 정보누출, 자원 간 충돌로 인한 서비스 장애 등을 유발할 수 있다.
- **보안대책**:
    - 외부 입력을 자원(파일, 소켓의 포트 등)의 식별자로 사용하는 경우 적절한 검증을 거치거나 사전에 정의된 적합한 리스트에서 선택되도록 한다.
    - 외부 입력이 파일명인 경우 경로순회(directory traversal) 공격 위험 문자(`/ \ ..` 등)를 제거하는 필터를 이용한다.
- **코드 포인트**: 외부 입력 파일명을 그대로 `new FileInputStream("C:/datas/" + fileName)`에 사용(../../../ 경로조작 가능) → replaceAll로 경로순회 문자열(`. / \`)을 제거한 후 사용
- **정탐/오탐 판단**: 정탐 — 외부입력(파라미터·인자·환경변수)이 경로조작 문자 검증 없이 파일 경로·자원 식별자로 파일 처리 함수에 도달. 오탐 — 경로순회 문자열(`.. / \`) 제거·탐지 필터를 거치거나 사전 정의된 리스트에서만 자원을 선택하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String fileName = request.getParameter("P");
response.setHeader("Content-Disposition", "attachment;filename=" + fileName + ";");
// 검증 또는 처리 없이 파일처리에 수행되었다. (예: P=../../../rootFile.txt)
FileInputStream fis = new FileInputStream("C:/datas/" + fileName);
BufferedInputStream bis = new BufferedInputStream(fis);
BufferedOutputStream bos = new BufferedOutputStream(response.getOutputStream());
```

**안전 (Java)**

```java
String fileName = request.getParameter("P");
response.setHeader("Content-Disposition", "attachment;filename=" + fileName + ";");
// 외부 입력값에서 경로순회 문자열(. / \)을 제거하고 사용해야 한다.
fileName = fileName.replaceAll("\\.", "").replaceAll("/", "").replaceAll("\\\\", "");
FileInputStream fis = new FileInputStream("C:/datas/" + fileName);
BufferedInputStream bis = new BufferedInputStream(fis);
BufferedOutputStream bos = new BufferedOutputStream(response.getOutputStream());
```

#### 1-4. 크로스사이트 스크립트

- **정의**: 웹 페이지에 악의적인 스크립트를 포함시켜 사용자 측에서 실행되게 유도할 수 있는 보안약점으로, 검증되지 않은 외부 입력이 동적 웹페이지 생성에 사용될 경우 해당 페이지를 열람하는 접속자의 권한으로 부적절한 스크립트가 수행되어 정보유출 등의 공격을 유발할 수 있다. Reflected·Stored·DOM 기반 XSS 공격 방법이 존재한다.
- **보안대책**:
    - 외부 입력값·출력값에 스크립트가 삽입되지 못하도록 문자열 치환 함수로 `& < > " ' / ( )` 등을 HTML 엔티티(`&amp; &lt; &gt; &quot; &#x27;` 등)로 치환한다.
    - JSTL(c:out) 또는 잘 알려진 XSS 방지 라이브러리(NAVER Lucy-XSS-Filter, OWASP ESAPI, OWASP Java-Encoder-Project)를 활용한다.
    - HTML 태그를 허용하는 게시판에서는 허용 태그를 화이트리스트로 만들어 해당 태그만 지원한다.
- **코드 포인트**: 외부 입력 keyword를 검증 없이 `<%=keyword%>`·document.write로 화면 출력 → replaceAll로 스크립트 문자 치환, JSTL `<c:out value="...">` 출력, 또는 Encoder.encodeForJS(Encoder.encodeForHTML()) 적용
- **정탐/오탐 판단**: 정탐 — 외부입력이 검증·인코딩 없이 동적 웹페이지 출력(HTML 응답·DOM 생성)에 도달. 오탐 — 스크립트 문자 치환(HTML 엔티티 인코딩), JSTL c:out 출력, 또는 검증된 XSS 방지 라이브러리 처리를 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
<% String keyword = request.getParameter("keyword"); %>
// 외부 입력값을 검증 없이 화면에 출력 (Reflected XSS)
검색어 : <%=keyword%>
// 게시판 등으로 DB에 저장된 외부값을 검증 없이 화면에 출력 (Stored XSS)
검색결과 : ${m.content}
<script type="text/javascript">
// 검증 없이 브라우저에서 실행 (DOM 기반 XSS)
document.write("keyword:" + <%=keyword%>);
</script>
```

**안전 (Java)**

```java
<% String keyword = request.getParameter("keyword"); %>
// 방법1. 스크립트 공격가능성이 있는 문자열을 치환한다.
keyword = keyword.replaceAll("&", "&amp;");
keyword = keyword.replaceAll("<", "&lt;");
keyword = keyword.replaceAll(">", "&gt;");
keyword = keyword.replaceAll("\"", "&quot;");
keyword = keyword.replaceAll("'", "&#x27;");
검색어 : <%=keyword%>
// 방법2. JSP 출력값에 JSTL c:out을 사용하여 처리한다.
검색결과 : <c:out value="${m.content}"/>
// 방법3. 잘 만들어진 외부 XSS 방지 라이브러리를 활용한다.
document.write("keyword:" + <%=Encoder.encodeForJS(Encoder.encodeForHTML(keyword))%>);
```

#### 1-5. 운영체제 명령어 삽입

- **정의**: 적절한 검증절차를 거치지 않은 사용자 입력값이 운영체제 명령어의 일부 또는 전부로 구성되어 실행되는 경우, 의도하지 않은 시스템 명령어가 실행되어 부적절하게 권한이 변경되거나 시스템 동작·운영에 악영향을 미칠 수 있는 보안약점이다.
- **보안대책**:
    - 웹 인터페이스로 서버 내부로 시스템 명령어를 전달시키지 않도록 응용프로그램을 구성한다.
    - 외부에서 전달되는 값을 검증 없이 시스템 내부 명령어로 사용하지 않는다.
    - 외부 입력에 따라 명령어 생성·선택이 필요한 경우 명령어 생성에 필요한 값들을 미리 지정해 놓고 외부 입력에 따라 선택하여 사용한다.
- **코드 포인트**: 외부 인자 cmd를 그대로 Runtime.getRuntime().exec(cmd) 실행 → allowedCommands 리스트에 포함된 명령어만 실행 / 외부 입력을 명령어 문자열에 연결해 exec → 멀티라인 특수문자(`| ; & :`)와 리다이렉트 문자(`> >>`)를 replaceAll로 제거 후 실행
- **정탐/오탐 판단**: 정탐 — 외부입력이 검증 없이 exec()·system()·Process.Start 등 명령어 실행 함수의 명령 문자열에 도달. 오탐 — 미리 정의된 명령어 화이트리스트에서만 선택하거나 멀티라인·리다이렉트 특수문자(`| ; & : > >>`) 필터링을 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String date = request.getParameter("date");
String command = new String("cmd.exe /c backuplog.bat");
Runtime.getRuntime().exec(command + date);
```

**안전 (Java)**

```java
String date = request.getParameter("date");
String command = new String("cmd.exe /c backuplog.bat");
// 멀티라인 특수문자(| ; & :)와 리다이렉트 특수문자(>)를 제거하여 사용한다.
date = date.replaceAll("|", "");
date = date.replaceAll(";", "");
date = date.replaceAll("&", "");
date = date.replaceAll(":", "");
date = date.replaceAll(">", "");
Runtime.getRuntime().exec(command + date);
```

#### 1-6. 위험한 형식 파일 업로드

- **정의**: 서버 측에서 실행될 수 있는 스크립트 파일(asp, jsp, php 파일 등)이 업로드 가능하고 이 파일을 공격자가 웹으로 직접 실행시킬 수 있는 경우, 시스템 내부명령어를 실행하거나 외부와 연결하여 시스템을 제어할 수 있는 보안약점이다.
- **보안대책**:
    - 화이트리스트 방식으로 허용된 확장자만 업로드를 허용한다.
    - 업로드 파일 저장 시 파일명과 확장자를 외부사용자가 추측할 수 없는 문자열로 변경하여 저장한다.
    - 저장 경로는 'web document root' 밖에 위치시켜 공격자의 웹 직접 접근을 차단한다.
    - 파일 실행 여부를 설정할 수 있는 경우 실행 속성을 제거한다.
- **코드 포인트**: 업로드 파일명을 검증 없이 받아 저장·사용 → 마지막 `.` 기준 확장자를 소문자로 추출해 화이트리스트(gif/jpg/png)에 없으면 업로드 차단, ContentType·ContentLength(크기) 검사 후 저장
- **정탐/오탐 판단**: 정탐 — 업로드 파일의 확장자·타입·크기 검증 없이 파일명이 서버 저장 로직에 도달. 오탐 — 확장자 화이트리스트 검사(마지막 `.` 기준, 대소문자 처리) 또는 파일 타입·크기 제한 검증을 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
MultipartRequest multi = new MultipartRequest(request, savePath, sizeLimit,
        "euc-kr", new DefaultFileRenamePolicy());
// 업로드 되는 파일명을 검증 없이 사용하고 있어 안전하지 않다.
String fileName = multi.getFilesystemName("filename");
......
Thumbnail.create(savePath + "/" + fileName, savePath + "/" + "s_" + fileName, 150);
```

**안전 (Java)**

```java
MultipartRequest multi = new MultipartRequest(request, savePath, sizeLimit,
        "euc-kr", new DefaultFileRenamePolicy());
String fileName = multi.getFilesystemName("filename");
if (fileName != null) {
    // 1. 마지막 "." 기준으로 실제 확장자 여부를 확인하고, 대소문자를 구별한다.
    String fileExt = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
    // 2. 화이트리스트 방식으로 허용되는 확장자만 업로드를 허용한다.
    if (!"gif".equals(fileExt) && !"jpg".equals(fileExt) && !"png".equals(fileExt)) {
        alertMessage("업로드 불가능한 파일입니다.");
        return;
    }
}
Thumbnail.create(savePath + "/" + fileName, savePath + "/" + "s_" + fileName, 150);
```

#### 1-7. 신뢰되지 않는 URL 주소로 자동접속 연결

- **정의**: 사용자로부터 입력되는 값을 외부사이트의 주소로 사용하여 자동으로 연결하는 서버 프로그램은 피싱(Phishing) 공격에 노출되는 취약점을 가질 수 있다. 공격자는 해당 폼의 요청을 변조함으로써 사용자가 위험한 URL로 접속하도록 공격할 수 있다.
- **보안대책**:
    - 자동 연결할 외부 사이트의 URL과 도메인은 화이트리스트로 관리한다.
    - 사용자 입력값을 자동 연결할 사이트 주소로 사용하는 경우 입력된 값이 화이트리스트에 존재하는지 확인한다.
- **코드 포인트**: 외부 입력 redirect 파라미터를 그대로 response.sendRedirect(rd)에 사용 → allowedUrl 배열(화이트리스트)의 인덱스로만 이동 URL을 선택, 또는 로컬 URL 여부(IsLocalUrl) 검증 후 리다이렉트
- **정탐/오탐 판단**: 정탐 — 외부입력 URL이 검증 없이 sendRedirect·Redirect 등 자동접속 연결에 도달. 오탐 — 화이트리스트에서만 URL을 선택하거나 로컬 URL 검증을 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
String bn = request.getParameter("gubun");
// 외부로부터 입력받은 URL이 검증 없이 다른 사이트로 이동이 가능하여 안전하지 않다.
String rd = request.getParameter("redirect");
......
if ("0".equals(rs.getString(1)) && "01AD".equals(bn)) {
    response.sendRedirect(rd);
    return;
}
```

**안전 (Java)**

```java
// 이동할 수 있는 URL 범위를 제한하여 피싱 사이트 등으로 이동하지 못하도록 한다.
String allowedUrl[] = { "/main.do", "/login.jsp", "list.do" };
String rd = request.getParameter("redirect");
try {
    rd = allowedUrl[Integer.parseInt(rd)];
} catch (NumberFormatException e) {
    return "잘못된 접근입니다.";
} catch (ArrayIndexOutOfBoundsException e) {
    return "잘못된 입력입니다.";
}
response.sendRedirect(rd);
```

#### 1-8. 부적절한 XML 외부 개체 참조

- **정의**: XML 문서에 포함될 수 있는 DTD가 XML 엔티티를 정의하는데, 서버에서 XML 외부 엔티티를 처리할 수 있도록 설정된 경우 발생하는 보안약점이다. 취약한 XML parser가 외부 값을 참조하는 XML 값을 처리할 때 공격자가 삽입한 공격 구문이 동작되어 서버 파일 접근, 불필요한 자원 사용, 인증 우회, 정보 노출 등이 발생할 수 있다.
- **보안대책**:
    - 로컬 정적 DTD를 사용하도록 설정하고, 외부에서 전송된 XML 문서에 포함된 DTD를 완전하게 비활성화한다.
    - 비활성화할 수 없는 경우 외부 엔티티 및 외부 문서 유형 선언을 각 파서에 맞는 고유한 방식으로 비활성화한다.
- **코드 포인트**: 외부개체 참조 제한 설정 없이 DocumentBuilderFactory·SAXParser로 수신 XML을 파싱(`<!ENTITY xxe SYSTEM "file:///etc/passwd">` 참조 가능) → dbf.setFeature로 disallow-doctype-decl=true, external-general-entities=false, external-parameter-entities=false, load-external-dtd=false 설정 및 setXIncludeAware(false)·setExpandEntityReferences(false) 적용
- **정탐/오탐 판단**: 정탐 — 외부에서 전송된 XML이 외부 엔티티·DTD 제한 설정 없는 파서의 parse에 도달. 오탐 — doctype 선언 금지·외부 엔티티/외부 DTD 비활성화 등 파서 보안설정(setFeature 등)이 적용된 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// receivedXml 예: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
JAXBContext jaxbContext = JAXBContext.newInstance(Student.class);
Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setNamespaceAware(true);
DocumentBuilder db = dbf.newDocumentBuilder();
Document document = db.parse(receivedXml);
// 외부 엔티티로 만들어진 document를 이용하여 마샬링을 수행하여 안전하지 않다.
Student employee = (Student) jaxbUnmarshaller.unmarshal(document);
```

**안전 (Java)**

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// XML 파서가 doctype을 정의하지 못하도록 설정한다.
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 외부 일반 엔티티를 포함하지 않도록 설정한다.
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
// 외부 파라미터도 포함하지 않도록 설정한다.
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
// 외부 DTD를 비활성화한다.
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document document = db.parse(receivedXml);
Model model = (Model) u.unmarshal(document);
```

#### 1-9. XML 삽입

- **정의**: 검증되지 않은 외부 입력값이 XQuery 또는 XPath 쿼리문을 생성하는 문자열로 사용되어, 공격자가 쿼리문의 구조를 임의로 변경하고 임의의 쿼리를 실행하여 허가되지 않은 데이터를 열람하거나 인증절차를 우회할 수 있는 보안약점이다.
- **보안대책**:
    - XQuery 또는 XPath 쿼리에 사용되는 외부 입력데이터에 대하여 특수문자 및 쿼리 예약어를 필터링한다.
    - 파라미터화된 쿼리문을 지원하는 XQuery를 사용한다.
- **코드 포인트**: 외부 입력을 문자열 연결로 XQuery/XPath 표현식에 삽입(`'1'='1'` 주입 가능) → `$xname` 변수 선언 후 bindString으로 바인딩, external 변수를 선언한 파라미터화된 XQuery 실행, 또는 조작 문자(`' [ ] ,` 등)를 replaceAll로 제거 후 구문 생성
- **정탐/오탐 판단**: 정탐 — 외부입력이 검증·바인딩 없이 문자열 연결로 XQuery/XPath 구문에 포함되어 executeQuery·evaluate에 도달. 오탐 — bindString·external 변수 등 파라미터화된 쿼리로 바인딩되거나 XPath 조작 가능 문자 제거 필터링을 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 외부 입력 값을 검증하지 않고 XQuery 표현식에 사용한다.
String name = props.getProperty("name");
// 외부 입력 값에 의해 쿼리 구조가 변경되어 안전하지 않다. (예: something' or '1'='1)
String es = "doc('users.xml')/userlist/user[uname='" + name + "']";
XQPreparedExpression expr = conn.prepareExpression(es);
XQResultSequence result = expr.executeQuery();
```

**안전 (Java)**

```java
// bindString 함수로 쿼리 구조가 변경되는 것을 방지한다.
String name = props.getProperty("name");
String es = "doc('users.xml')/userlist/user[uname='$xname']";
XQPreparedExpression expr = conn.prepareExpression(es);
expr.bindString(new QName("xname"), name, null);
XQResultSequence result = expr.executeQuery();
```

#### 1-10. LDAP 삽입

- **정의**: 공격자가 외부 입력으로 의도하지 않은 LDAP 명령어를 수행할 수 있는 보안약점으로, 웹 응용프로그램이 사용자 입력을 올바르게 처리하지 못하면 공격자가 LDAP 명령문의 구성을 바꿀 수 있다.
- **보안대책**:
    - DN(Distinguished Name)과 필터에 사용되는 사용자 입력값에 특수문자가 포함되지 않도록 특수문자를 제거한다.
    - 특수문자를 사용해야 하는 경우 특수문자(`= + < > # ; \` 등)가 실행명령이 아닌 일반문자로 인식되도록 처리한다.
- **코드 포인트**: 외부 입력 userSN·userPassword를 검증 없이 문자열 연결로 검색 필터에 사용해 search 실행(`*` 입력 시 항상 참) → 정규식(`[\w\s]*`, `[\w]*`) 검증에 실패하면 예외 발생 후 필터 구성
- **정탐/오탐 판단**: 정탐 — 외부입력이 특수문자 검증 없이 LDAP 검색 필터·DN 문자열에 포함되어 search 실행에 도달. 오탐 — 정규식 검증·특수문자(`* ( ) = + < > # ;` 등) 제거 또는 일반문자 처리 후 필터를 구성하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
DirContext dctx = new InitialDirContext(env);
SearchControls sc = new SearchControls();
String[] attributeFilter = { "cn", "mail" };
sc.setReturningAttributes(attributeFilter);
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";
// userSN과 userPassword 값에 LDAP 필터를 조작할 수 있는 공격 문자열에 대한 검증이 없다.
String filter = "(&(sn=" + userSN + ")(userPassword=" + userPassword + "))";
NamingEnumeration<?> results = dctx.search(base, filter, sc);
```

**안전 (Java)**

```java
DirContext dctx = new InitialDirContext(env);
SearchControls sc = new SearchControls();
sc.setReturningAttributes(new String[] { "cn", "mail" });
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";
// userSN과 userPassword 값에서 LDAP 필터를 조작할 수 있는 문자열을 제거하고 사용
if (!userSN.matches("[\\w\\s]*") || !userPassword.matches("[\\w]*")) {
    throw new IllegalArgumentException("Invalid input");
}
String filter = "(&(sn=" + userSN + ")(userPassword=" + userPassword + "))";
NamingEnumeration<?> results = dctx.search(base, filter, sc);
```

#### 1-11. 크로스사이트 요청 위조

- **정의**: 특정 웹사이트에 대해서 사용자가 인지하지 못한 상황에서 사용자의 의도와는 무관하게 공격자가 의도한 행위(수정, 삭제, 등록 등)를 요청하게 하는 공격이다. 웹 응용프로그램이 사용자로부터 받은 요청에 대해 사용자가 의도한 대로 작성·전송된 것인지 확인하지 않는 경우 발생하며, 사용자가 관리자인 경우 관리자 권한 기능이 공격자의 의도대로 실행될 수 있다.
- **보안대책**:
    - 입력화면 폼 작성 시 GET 방식보다는 POST 방식을 사용한다.
    - 입력화면 폼과 해당 입력을 처리하는 프로그램 사이에 토큰을 사용하여 공격자의 직접적인 URL 사용이 동작하지 않도록 처리한다.
    - 중요한 기능에 대해서는 사용자 세션검증과 더불어 재인증을 유도한다.
- **코드 포인트**: 클라이언트 요청의 정상 요청 여부를 검증하지 않고 처리 → 세션에 UUID 기반 CSRF 토큰 저장 + HIDDEN 필드로 전달 후 요청 파라미터 토큰과 세션 토큰 일치 시에만 처리(C#은 Html.AntiForgeryToken() 사용)
- **정탐/오탐 판단**: 정탐 — 상태 변경(수정·삭제·등록) 요청이 정상 요청 여부(토큰) 검증 없이 처리 로직에 도달. 오탐 — 세션 저장 토큰과 요청 파라미터(HIDDEN 필드) 토큰 비교 검증 또는 AntiForgeryToken 등의 방어가 적용된 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 어떤 형태의 요청이던지 기본적으로 CSRF 취약점을 가질 수 있다.
// (클라이언트 요청의 정상 요청 여부를 검증하지 않고 처리하는 경우)
```

**안전 (Java)**

```java
// 입력화면이 요청되었을 때, 임의의 토큰을 생성한 후 세션에 저장한다.
session.setAttribute("SESSION_CSRF_TOKEN", UUID.randomUUID().toString());
// 입력화면에 임의의 토큰을 HIDDEN 필드항목의 값으로 설정해 서버로 전달되도록 한다.
<input type="hidden" name="param_csrf_token" value="${SESSION_CSRF_TOKEN}"/>
// 요청 파라미터와 세션에 저장된 토큰을 비교해서 일치하는 경우에만 요청을 처리한다.
String pToken = request.getParameter("param_csrf_token");
String sToken = (String) session.getAttribute("SESSION_CSRF_TOKEN");
if (pToken != null && pToken.equals(sToken)) {
    // 일치하는 토큰이 존재하는 경우 -> 정상 처리
} else {
    // 토큰이 없거나 값이 일치하지 않는 경우 -> 오류 메시지 출력
}
```

#### 1-12. 서버사이드 요청 위조

- **정의**: 적절한 검증절차를 거치지 않은 사용자 입력값을 서버 간의 요청에 사용하여 악의적인 행위가 발생할 수 있는 보안약점이다. 공격자는 URL 또는 요청문을 위조하여 접근통제를 우회하는 방식으로 비정상적인 동작을 유도하거나 신뢰된 네트워크에 있는 데이터를 획득할 수 있다.
- **보안대책**:
    - 사용자 입력값을 다른 시스템의 서비스 호출에 사용하는 경우 식별할 수 있는 범위 내에서 화이트리스트 방식으로 필터링한다.
    - 무작위 URL을 받아들여야 한다면 내부의 URL을 블랙리스트로 지정하여 필터링한다.
    - 동일한 내부 네트워크에 있더라도 기기 인증·접근권한을 확인하여 요청이 이루어지도록 한다.
- **코드 포인트**: 외부 입력 url 파라미터로 `new URL(...).openConnection()`을 직접 수행(내부망 IP·admin 페이지 질의 가능) → 사전 정의된 URL 목록을 Map에 담고 키 값으로만 입력받아 매칭되는 URL로 접속
- **정탐/오탐 판단**: 정탐 — 외부입력 URL이 검증 없이 서버 측 요청(openConnection 등) 대상 주소로 도달. 오탐 — 사전 정의 URL 맵(화이트리스트)의 키로만 대상을 선택하거나 내부 URL 블랙리스트 필터링·기기 인증/접근권한 확인이 적용된 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    // 사용자 입력값(url)을 검증 없이 사용하여 안전하지 않다.
    URL url = new URL(req.getParameter("url"));
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
}
```

**안전 (Java)**

```java
// key, value 형식으로 URL의 리스트를 작성한다.
private Map<String, URL> urlMap;

protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    // 사용자에게 urlMap의 key를 입력받아 urlMap에서 URL 값을 참조한다.
    URL url = urlMap.get(req.getParameter("url"));
    // urlMap에서 참조한 값으로 Connection을 만들어 접속한다.
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
}
```

#### 1-13. HTTP 응답분할

- **정의**: HTTP 요청 파라미터가 HTTP 응답헤더에 포함되어 사용자에게 다시 전달될 때, 입력값에 CR(Carriage Return)이나 LF(Line Feed) 같은 개행문자가 존재하면 HTTP 응답이 2개 이상으로 분리될 수 있는 보안약점이다. 공격자는 두 번째 응답에 악의적인 코드를 주입하여 XSS 및 캐시 훼손(Cache Poisoning) 공격 등을 수행할 수 있다.
- **보안대책**:
    - 요청 파라미터의 값을 HTTP 응답헤더(예: Set-Cookie 등)에 포함시킬 경우 CR, LF와 같은 개행문자를 제거한다.
- **코드 포인트**: 외부 입력 lastLogin을 검증 없이 Cookie 값으로 설정해 Set-Cookie 응답헤더로 전달 → replaceAll(`[\r\n]`)로 개행문자를 제거한 후 쿠키 값으로 설정
- **정탐/오탐 판단**: 정탐 — 외부입력이 개행문자 제거 없이 쿠키·응답헤더 설정(addCookie, AddHeader)에 도달. 오탐 — CR/LF 개행문자를 제거한 후 응답헤더 값으로 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String lastLogin = request.getParameter("last_login");
if (lastLogin == null || "".equals(lastLogin)) {
    return;
}
// 쿠키는 Set-Cookie 응답헤더로 전달되므로 개행문자열 포함 여부 검증이 필요
Cookie c = new Cookie("LASTLOGIN", lastLogin);
c.setMaxAge(1000);
c.setSecure(true);
response.addCookie(c);
```

**안전 (Java)**

```java
String lastLogin = request.getParameter("last_login");
if (lastLogin == null || "".equals(lastLogin)) {
    return;
}
// 외부 입력값에서 개행문자(\r\n)를 제거한 후 쿠키의 값으로 설정
lastLogin = lastLogin.replaceAll("[\\r\\n]", "");
Cookie c = new Cookie("LASTLOGIN", lastLogin);
c.setMaxAge(1000);
c.setSecure(true);
response.addCookie(c);
```

#### 1-14. 정수형 오버플로우

- **정의**: 정수형 크기는 고정되어 있는데 저장할 수 있는 범위를 넘어서 크기보다 큰 값을 저장하려 할 때, 실제 저장되는 값이 의도치 않게 아주 작은 수이거나 음수가 되어 프로그램이 예기치 않게 동작될 수 있는 보안약점이다. 특히 반복문 제어, 메모리 할당, 메모리 복사 등의 조건으로 사용자 입력값을 사용하는 과정에서 발생하면 보안상 문제를 유발할 수 있다.
- **보안대책**:
    - 언어/플랫폼별 정수타입의 범위를 확인하여 사용한다.
    - 정수형 변수를 연산에 사용하는 경우 결과 값의 범위를 체크하는 모듈을 사용한다.
    - 외부입력값을 동적 메모리 할당에 사용하는 경우 변수 값이 적절한 범위 내에 존재하는지 확인한다.
- **코드 포인트**: 외부 입력을 Integer.parseInt 후 크기 검증 없이 배열 크기로 사용(오버플로우로 음수 가능) → 파싱 후 `param_ct < 0`이면 예외를 던지는 범위 검사 추가 / C atoi 값으로 배열 접근 → 상·하한 범위 검사 후 접근
- **정탐/오탐 판단**: 정탐 — 외부입력 정수가 범위(음수·상한) 검증 없이 배열 크기/인덱스·메모리 할당·반복문 조건에 도달. 오탐 — 음수·범위 검사(checked 구문, 상·하한 비교) 후 사용하거나 오버플로우 예외 처리가 적용된 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
String tmp = request.getParameter("slf_msg_param_num");
tmp = StringUtil.isNullTrim(tmp);
// 외부 입력값을 정수형으로 사용할 때 입력값의 크기를 검증하지 않고 사용
int param_ct = Integer.parseInt(tmp);
String[] strArr = new String[param_ct];
```

**안전 (Java)**

```java
String tmp = request.getParameter("slf_msg_param_num");
tmp = StringUtil.isNullTrim(tmp);
// 외부 입력값을 정수형으로 사용할 때 입력값의 크기를 검증하고 사용
try {
    int param_ct = Integer.parseInt(tmp);
    if (param_ct < 0) {
        throw new Exception();
    }
    String[] strArr = new String[param_ct];
} catch (Exception e) {
    msg_str = "잘못된 입력(접근) 입니다.";
}
```

#### 1-15. 보안기능 결정에 사용되는 부적절한 입력값

- **정의**: 응용프로그램이 외부 입력값에 대한 신뢰를 전제로 보호메커니즘을 사용하는 경우, 공격자가 입력값을 조작할 수 있다면 보호메커니즘을 우회할 수 있게 되는 보안약점이다. 쿠키, 환경변수, 히든필드 같은 입력값은 조작될 수 없다고 흔히 가정하지만 공격자는 다양한 방법으로 이를 변경할 수 있다.
- **보안대책**:
    - 상태정보나 민감한 데이터, 특히 사용자 세션정보와 같은 중요한 정보는 서버에 저장하고 보안확인 절차도 서버에서 실행한다.
    - 보안결정에 사용되는 입력값을 식별하고, 제공되는 입력값에 의존할 필요가 없는 구조로 변경할 수 있는지 검토한다.
    - 이런 메커니즘이 없는 경우 충분한 암호화·무결성 체크를 수행하고 외부사용자의 입력값을 신뢰하지 않는다.
- **코드 포인트**: 가격(단가)을 히든필드로 클라이언트에 두고 request.getParameter("price")로 받아 계산 → item만 받아 서버가 보유한 가격정보로 계산 / 인증정보를 평문 쿠키에 저장 → 세션(Session)에 저장
- **정탐/오탐 판단**: 정탐 — 쿠키·환경변수·히든필드 등 조작 가능한 외부입력이 검증 없이 인증·인가·가격 등 보안결정 로직에 도달. 오탐 — 보안결정 값을 서버 내부(세션·서버 보유 정보·고정값)에서 가져오거나 충분한 암호화·무결성 체크를 거친 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
<input type="hidden" name="price" value="1000"/>
......
try {
    // 서버가 보유하고 있는 가격(단가) 정보를 사용자 화면에서 받아서 처리
    price = request.getParameter("price");
    quantity = request.getParameter("quantity");
    total = Integer.parseInt(quantity) * Float.parseFloat(price);
} catch (Exception e) {
......
```

**안전 (Java)**

```java
try {
    item = request.getParameter("item");
    // 가격이 아니라 item 항목을 가져와서 서버가 보유하고 있는 가격정보를 이용하여
    // 전체 가격을 계산
    price = productService.getPrice(item);
    quantity = request.getParameter("quantity");
    total = Integer.parseInt(quantity) * price;
} catch (Exception e) {
......
```

#### 1-16. 메모리 버퍼 오버플로우

- **정의**: 연속된 메모리 공간을 사용하는 프로그램에서 할당된 메모리의 범위를 넘어선 위치에 자료를 읽거나 쓰려고 할 때 발생하는 보안약점으로, 스택 메모리 버퍼 오버플로우와 힙 메모리 버퍼 오버플로우가 있다. 프로그램의 오동작을 유발하거나 악의적인 코드 실행으로 공격자가 프로그램을 통제할 수 있는 권한을 획득하게 한다.
- **보안대책**:
    - 메모리 버퍼를 사용할 경우 적절한 버퍼의 크기를 설정하고, 설정된 범위의 메모리 내에서 올바르게 읽거나 쓸 수 있게 통제한다.
    - 문자열 저장 시 널(Null) 문자를 버퍼 범위 내에 삽입하여 널 문자로 종료되도록 한다.
- **코드 포인트**: memcpy에 잘못 계산된 크기 sizeof(구조체 전체)를 사용해 인접 메모리를 덮어쓰고 종료 문자 미첨가 → sizeof(대상 필드)로 정확한 크기를 지정하고 배열 마지막 인덱스에 널 문자(`\0`) 패딩. 크기 무관 입력을 받는 gets() 같은 함수는 복귀 주소 덮어쓰기 유발
- **정탐/오탐 판단**: 정탐 — 버퍼 크기 검증 없는 입력·복사(gets, 잘못된 sizeof 기반 memcpy)가 할당 범위를 넘어 쓰기/읽기에 도달. 오탐 — 대상 버퍼의 정확한 크기로 복사 범위를 제한하고 널 문자 종료 처리가 되어 있는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (C)**

```c
typedef struct _charvoid {
    char x[16];
    void *y;
    void *z;
} charvoid;

void badCode() {
    charvoid cv_struct;
    cv_struct.y = (void *) SRC_STR;
    /* sizeof(cv_struct)의 사용으로 포인터 y에 덮어쓰기 발생 */
    memcpy(cv_struct.x, SRC_STR, sizeof(cv_struct));
    printLine((char *) cv_struct.x);
    printLine((char *) cv_struct.y);
}
```

**안전 (C)**

```c
static void goodCode() {
    charvoid cv_struct;
    cv_struct.y = (void *) SRC_STR;
    /* sizeof(cv_struct.x)로 변경하여 포인터 y의 덮어쓰기를 방지함 */
    memcpy(cv_struct.x, SRC_STR, sizeof(cv_struct.x));
    /* 문자열 종료를 위해 널 문자를 삽입함 */
    cv_struct.x[(sizeof(cv_struct.x) / sizeof(char)) - 1] = '\0';
    printLine((char *) cv_struct.x);
    printLine((char *) cv_struct.y);
}
```

#### 1-17. 포맷 스트링 삽입

- **정의**: 외부로부터 입력된 값을 검증하지 않고 입·출력 함수의 포맷 문자열로 그대로 사용하는 경우 발생할 수 있는 보안약점이다. 공격자는 포맷 문자열을 이용하여 취약한 프로세스를 공격하거나 메모리 내용을 읽거나 쓸 수 있으며, 그 결과 프로세스의 권한을 취득하여 임의의 코드를 실행할 수 있다.
- **보안대책**:
    - printf(), snprintf() 등 포맷 문자열을 사용하는 함수에 사용자 입력값을 직접 포맷 문자열로 사용하거나 포맷 문자열 생성에 포함시키지 않는다.
    - 특히 %n, %hn은 특정 메모리 위치의 값을 변경할 수 있으므로 포맷 스트링 매개변수로 사용하지 않는다.
    - 사용자 입력값은 가능하면 %s 포맷 문자열을 지정하고 2번째 이후의 파라미터로 사용한다.
- **코드 포인트**: 외부 입력을 포맷 문자열에 연결해 printf 실행(`%1$tY` 등으로 내부 정보 노출) → `"%s ..."` 고정 포맷 문자열을 지정하고 입력값을 뒤 파라미터로 전달 / fprintf(stderr, msg) → fputs(msg, stderr)로 포맷 해석 없이 출력
- **정탐/오탐 판단**: 정탐 — 외부입력이 검증 없이 printf·fprintf 등 포맷 함수의 포맷 문자열 인자(또는 그 생성)에 도달. 오탐 — 고정 포맷 문자열(%s 지정)에 입력값을 데이터 파라미터로만 전달하거나 fputs 등 포맷 해석 없는 출력 함수를 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// args[0]의 값으로 "%1$tY-%1$tm-%1$te"를 전달하면 시스템이 가진 날짜 정보가 노출
public static void main(String[] args) {
    Calendar validDate = Calendar.getInstance();
    validDate.set(2014, Calendar.OCTOBER, 14);
    // 외부 입력값의 포맷 문자열 포함 여부를 확인하지 않고 포맷 문자열에 사용
    System.out.printf(args[0]
            + " did not match! HINT: It was issued on %1$terd of some month", validDate);
}
```

**안전 (Java)**

```java
// 외부 입력값이 포맷 문자열 출력에 사용되지 않도록 수정
public static void main(String[] args) {
    Calendar validDate = Calendar.getInstance();
    validDate.set(2014, Calendar.OCTOBER, 14);
    // %s 포맷 문자열을 지정하고 사용자 입력값은 2번째 이후의 파라미터로 사용
    System.out.printf("%s did not match! HINT: It was issued on %2$terd of some month",
            args[0], validDate);
}
```

## 유형 2. 보안기능 (16개)

인증·접근제어·기밀성·암호화·권한관리 등을 적절하지 않게 구현할 때 발생하는 보안약점.

#### 2-1. 적절한 인증 없는 중요기능 허용

- **정의**: 적절한 인증과정 없이 중요정보(계좌이체 정보, 개인정보 등)를 열람하거나 변경할 때 발생하는 보안약점이다.
- **보안대책**:
    - 클라이언트의 보안검사를 우회하여 서버에 접근하지 못하도록 설계한다.
    - 중요한 정보가 있는 페이지는 재인증을 적용한다(은행 계좌이체 등).
    - 안전하다고 검증된 라이브러리·프레임워크(OpenSSL, ESAPI의 보안기능 등)를 사용한다.
- **코드 포인트**: 로그인 사용자(session의 userId)와 수정 요청 사용자의 일치 여부 확인 없이 modifyMember() 실행 → userId.equals(requestUser)로 일치 여부 확인 후에만 수정
- **정탐/오탐 판단**: 정탐 — 회원정보 수정 등 중요기능이 세션 사용자와 요청 사용자의 일치 확인(자격인증) 없이 수행되는 경우. 오탐 — 처리 전에 로그인 사용자와 요청 사용자의 일치 검사 또는 자격인증 과정을 거친 뒤에만 기능을 수행하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
@RequestMapping(value = "/modify.do", method = RequestMethod.POST)
public ModelAndView memberModifyProcess(@ModelAttribute("MemberModel") MemberModel memberModel,
        BindingResult result, HttpServletRequest request, HttpSession session) {
    ModelAndView mav = new ModelAndView();
    // 1. 로그인한 사용자를 불러온다.
    String userId = (String) session.getAttribute("userId");
    String passwd = request.getParameter("oldUserPw");
    // 2. 실제 수정하는 사용자와 일치 여부를 확인하지 않고, 회원정보를 수정하여 안전하지 않다.
    if (service.modifyMember(memberModel)) {
        mav.setViewName("redirect:/board/list.do");
        session.setAttribute("userName", memberModel.getUserName());
        return mav;
    }
}
```

**안전 (Java)**

```java
@RequestMapping(value = "/modify.do", method = RequestMethod.POST)
public ModelAndView memberModifyProcess(@ModelAttribute("MemberModel") MemberModel memberModel,
        BindingResult result, HttpServletRequest request, HttpSession session) {
    ModelAndView mav = new ModelAndView();
    String userId = (String) session.getAttribute("userId");
    // 2. 회원정보를 실제 수정하는 사용자와 로그인 사용자와 동일한지 확인한다.
    String requestUser = memberModel.getUserId();
    if (userId != null && requestUser != null && !userId.equals(requestUser)) {
        mav.addObject("errCode", 1);
        mav.setViewName("/board/member_modify");
        return mav;
    }
    // 3. 동일한 경우에만 회원정보를 수정해야 안전하다.
    if (service.modifyMember(memberModel)) {
        ...
    }
}
```

#### 2-2. 부적절한 인가

- **정의**: 프로그램이 모든 가능한 실행경로에 대해 접근제어를 검사하지 않거나 불완전하게 검사하는 경우, 공격자가 접근 가능한 실행경로로 정보를 유출할 수 있는 보안약점이다.
- **보안대책**:
    - 정보와 기능을 역할에 따라 배분하여 공격노출면(Attack Surface)을 최소화한다.
    - 사용자의 권한에 따른 ACL(Access Control List)을 관리한다.
    - JAAS Authorization Framework, OWASP ESAPI Access Control 등 인증 프레임워크를 사용한다.
- **코드 포인트**: 외부 입력 action 값이 delete면 권한 확인 없이 boardDao.delete(contentId) 수행 → 세션의 사용자 정보로 checkAccessControlList(user, action) 확인 후 삭제
- **정탐/오탐 판단**: 정탐 — 외부 입력값에 따라 삭제 등 작업을 수행하면서 요청 사용자의 작업 권한 확인 통제가 전혀 없는 경우. 오탐 — 세션 저장 사용자 정보 기반 ACL 검사, [Authorize] 속성 등 권한·자격 검사 후에만 작업을 수행하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
private BoardDao boardDao;
String action = request.getParameter("action");
String contentId = request.getParameter("contentId");
// 요청을 하는 사용자의 delete 작업 권한 확인 없이 수행하고 있어 안전하지 않다.
if (action != null && action.equals("delete")) {
    boardDao.delete(contentId);
}
```

**안전 (Java)**

```java
private BoardDao boardDao;
String action = request.getParameter("action");
String contentId = request.getParameter("contentId");
// 세션에 저장된 사용자 정보를 얻어온다.
User user = (User) session.getAttribute("user");
// 사용자정보에서 해당 사용자가 delete작업의 권한이 있는지 확인한 뒤 삭제 작업을 수행한다.
if (action != null && action.equals("delete") && checkAccessControlList(user, action)) {
    boardDao.delete(contentId);
}
```

#### 2-3. 중요한 자원에 대한 잘못된 권한 설정

- **정의**: SW가 중요한 보안관련 자원에 대해 읽기 또는 수정 권한을 의도하지 않게 허가할 경우, 권한을 갖지 않은 사용자가 해당 자원을 사용하게 되는 보안약점이다.
- **보안대책**:
    - 설정파일, 실행파일, 라이브러리 등은 SW 관리자에 의해서만 읽고 쓰기가 가능하도록 설정한다.
    - 설정파일 등 중요한 자원 사용 시 허가받지 않은 사용자의 접근 가능 여부를 검사한다.
    - 파일에는 최소권한을 할당한다(예: 소유자에게만 필요한 권한 부여, C에서는 umask(077)).
- **코드 포인트**: file.setReadable(true, false) 등으로 모든 사용자에게 읽기·쓰기·실행 권한 부여(C: umask(0)) → file.setReadable(true) 등 소유자에게만 최소권한 부여(C: umask(077))
- **정탐/오탐 판단**: 정탐 — 설정파일 등 중요 자원에 모든 사용자 권한 부여(두 번째 파라미터 false, umask(0), "everyone" FullControl)를 하는 경우. 오탐 — 소유자 한정 최소권한 또는 특정 계정에 필요한 권한만 설정하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
File file = new File("/home/setup/system.ini");
// 모든 사용자에게 실행 권한을 허용하여 안전하지 않다.
file.setExecutable(true, false);
// 모든 사용자에게 읽기 권한을 허용하여 안전하지 않다.
file.setReadable(true, false);
// 모든 사용자에게 쓰기 권한을 허용하여 안전하지 않다.
file.setWritable(true, false);
```

**안전 (Java)**

```java
File file = new File("/home/setup/system.ini");
// 소유자에게 실행 권한을 금지하였다.
file.setExecutable(false);
// 소유자에게 읽기 권한을 허용하였다.
file.setReadable(true);
// 소유자에게 쓰기 권한을 금지하였다.
file.setWritable(false);
```

#### 2-4. 취약한 암호화 알고리즘 사용

- **정의**: base64 같은 지나치게 간단한 인코딩이나 취약·비표준 암호화 알고리즘으로는 중요정보를 보호할 수 없으며, RC2, RC4, RC5, RC6, MD4, MD5, SHA1, DES 등 오래된 알고리즘은 짧은 시간 내에 해독될 수 있는 보안약점이다.
- **보안대책**:
    - 자체 개발 알고리즘 대신 학계·업계에서 검증된 표준화된 알고리즘을 사용한다.
    - DES, RC5 등 취약 알고리즘을 3DES, AES, SEED 등 안전한 알고리즘으로 대체한다.
    - 업무내용·개인정보 암호화 시 IT보안인증사무국이 안전성을 확인한 검증필 암호모듈을 사용한다.
    - 최소 안전성 수준 112비트: 블록암호 ARIA(키 128/192/256)·SEED(키 128), 해쉬 SHA-224/256/384/512, RSAES 공개키 2048/3072 등 권고 목록을 따른다.
- **코드 포인트**: Cipher.getInstance("DES") → Cipher.getInstance("AES/CBC/PKCS5Padding")
- **정탐/오탐 판단**: 정탐 — DES 등 취약하다고 알려진 알고리즘(RC2/RC4/RC5/RC6, MD4/MD5, SHA1 포함)으로 암호화를 수행하는 경우. 오탐 — AES, SEED, ARIA, 3DES 등 안전하다고 알려진 표준 알고리즘을 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public class CryptoUtils {
    public byte[] encrypt(byte[] msg, Key k) {
        byte[] rslt = null;
        try {
            // 키 길이가 짧아 취약한 암호화 알고리즘인 DES를 사용하여 안전하지 않다.
            Cipher c = Cipher.getInstance("DES");
            c.init(Cipher.ENCRYPT_MODE, k);
            rslt = c.update(msg);
        }
    }
}
```

**안전 (Java)**

```java
public class CryptoUtils {
    public byte[] encrypt(byte[] msg, Key k) {
        byte[] rslt = null;
        try {
            // 키 길이가 길어 강력한 알고리즘인 AES를 사용하여 안전하다.
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, k);
            rslt = c.update(msg);
        }
    }
}
```

#### 2-5. 암호화되지 않은 중요정보

- **정의**: 사용자 또는 시스템의 중요정보가 포함된 데이터를 평문으로 송·수신하거나 저장할 때, 인가되지 않은 사용자에게 민감한 정보가 노출될 수 있는 보안약점이다.
- **보안대책**:
    - 개인정보(주민등록번호, 여권번호 등), 금융정보(카드번호, 계좌번호 등), 패스워드 등 중요정보는 전송·저장 시 반드시 암호화한다.
    - 필요한 경우 SSL 또는 HTTPS 등 암호채널을 사용하고, 브라우저 쿠키에 중요 데이터를 저장할 때는 쿠키객체에 보안속성을 설정한다.
    - 중요정보 읽기/쓰기 시 권한인증 등으로 적합한 사용자만 접근하도록 한다.
- **코드 포인트**: 입력받은 패스워드를 평문 그대로 DB insert 또는 소켓으로 평문 전송(패킷 스니핑으로 노출) → 솔트를 포함한 SHA-256 해쉬로 변환해 저장, 전송 전 AES/CBC/PKCS5Padding 등으로 암호화
- **정탐/오탐 판단**: 정탐 — 패스워드 등 중요정보를 암호화·해쉬 없이 평문으로 DB 저장·네트워크 전송하는 경우. 오탐 — 저장 전 솔트 포함 해쉬 적용, 전송 전 안전한 알고리즘으로 암호화하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
String id = request.getParameter("id");
// 외부값에 의해 패스워드 정보를 얻고 있다.
String pwd = request.getParameter("pwd");
String sql = " insert into customer(id, pwd, name, ssn, zipcode, addr)"
        + " values (?, ?, ?, ?, ?, ?)";
PreparedStatement stmt = con.prepareStatement(sql);
stmt.setString(1, id);
stmt.setString(2, pwd);
// 입력받은 패스워드가 평문으로 DB에 저장되어 안전하지 않다.
stmt.executeUpdate();
```

**안전 (Java)**

```java
String id = request.getParameter("id");
String pwd = request.getParameter("pwd");
// 패스워드를 솔트값을 포함하여 SHA-256 해쉬로 변경하여 안전하게 저장한다.
MessageDigest md = MessageDigest.getInstance("SHA-256");
md.reset();
md.update(salt);
byte[] hashInBytes = md.digest(pwd.getBytes());
StringBuilder sb = new StringBuilder();
for (byte b : hashInBytes) {
    sb.append(String.format("%02x", b));
}
pwd = sb.toString();
String sql = " insert into customer(id, pwd, name, ssn, zipcode, addr)"
        + " values (?, ?, ?, ?, ?, ?)";
PreparedStatement stmt = con.prepareStatement(sql);
stmt.setString(1, id);
stmt.setString(2, pwd);
stmt.executeUpdate();
```

#### 2-6. 하드코드된 중요정보

- **정의**: 프로그램 코드 내부에 하드코드된 패스워드 또는 암호화키를 포함하여 내부 인증이나 암호화에 사용하면 중요정보(관리자 정보, 암호화된 정보 등)가 유출될 수 있는 보안약점이다.
- **보안대책**:
    - 패스워드는 암호화하여 별도의 파일에 저장하여 사용한다.
    - 중요정보 암호화 시 상수가 아닌 암호화 키를 사용한다.
    - 소스코드 내부에 상수형태의 암호화 키를 저장해서 사용하지 않는다.
- **코드 포인트**: `private final String PASS = "SCOTT"` 또는 `String key = "22df...!@#"`처럼 소스에 패스워드·키를 상수로 하드코딩 → 프로퍼티·외부 파일에서 암호화된 값을 읽어 복호화 후 사용(props.getProperty, getenv 등)
- **정탐/오탐 판단**: 정탐 — DB 접속 패스워드나 암호화 키·IV가 소스코드에 문자열/바이트 상수로 존재하고 인증·암호화에 사용되는 경우. 오탐 — 패스워드·키를 외부 공간(파일, 환경변수)에 암호화하여 보관하고 사용 시 복호화하여 읽어오는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public class MemberDAO {
    private static final String DRIVER = "oracle.jdbc.driver.OracleDriver";
    private static final String URL = "jdbc:oracle:thin:@192.168.0.3:1521:ORCL";
    private static final String USER = "SCOTT"; // DB ID
    // DB 패스워드가 소스코드에 평문으로 저장되어 있다.
    private static final String PASS = "SCOTT"; // DB PW

    public Connection getConn() {
        Connection con = null;
        try {
            Class.forName(DRIVER);
            con = DriverManager.getConnection(URL, USER, PASS);
        }
    }
}
```

**안전 (Java)**

```java
public class MemberDAO {
    private static final String DRIVER = "oracle.jdbc.driver.OracleDriver";
    private static final String URL = "jdbc:oracle:thin:@192.168.0.3:1521:ORCL";
    private static final String USER = "SCOTT"; // DB ID

    public Connection getConn() {
        Connection con = null;
        try {
            Class.forName(DRIVER);
            // 암호화된 패스워드를 프로퍼티에서 읽어들여 복호화해서 사용해야 한다.
            String PASS = props.getProperty("EncryptedPswd");
            byte[] decryptedPswd = cipher.doFinal(PASS.getBytes());
            PASS = new String(decryptedPswd);
            con = DriverManager.getConnection(URL, USER, PASS);
        }
    }
}
```

#### 2-7. 충분하지 않은 키 길이 사용

- **정의**: 검증된 암호화 알고리즘을 사용하더라도 키 길이가 충분히 길지 않으면 짧은 시간 안에 키를 찾아낼 수 있어, 공격자가 암호화된 데이터나 패스워드를 복호화할 수 있게 되는 보안약점이다.
- **보안대책**:
    - RSA 알고리즘은 적어도 2,048비트 이상의 키와 함께 사용한다.
    - 대칭암호화 알고리즘은 적어도 128비트 이상의 키를 사용한다.
- **코드 포인트**: keyGen.initialize(1024)로 짧은 RSA 키 생성 → keyGen.initialize(2048) 등 2048비트 이상으로 설정
- **정탐/오탐 판단**: 정탐 — RSA 키를 2048비트 미만(1024, 512 등)으로 설정하거나 대칭키가 128비트 미만인 경우. 오탐 — RSA 2048비트 이상, 대칭키 128비트 이상으로 키 길이를 설정한 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public static final String ALGORITHM = "RSA";
public static final String PRIVATE_KEY_FILE = "C:/keys/private.key";
public static final String PUBLIC_KEY_FILE = "C:/keys/public.key";

public static void generateKey() {
    try {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        // RSA 키 길이를 1024 비트로 짧게 설정하는 경우 안전하지 않다.
        keyGen.initialize(1024);
        final KeyPair key = keyGen.generateKeyPair();
    }
}
```

**안전 (Java)**

```java
public static final String ALGORITHM = "RSA";
public static final String PRIVATE_KEY_FILE = "C:/keys/private.key";
public static final String PUBLIC_KEY_FILE = "C:/keys/public.key";

public static void generateKey() {
    try {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        // 공개키 암호화에 사용하는 키의 길이는 적어도 2048비트 이상으로 설정한다.
        keyGen.initialize(2048);
        final KeyPair key = keyGen.generateKeyPair();
    }
}
```

#### 2-8. 적절하지 않은 난수값 사용

- **정의**: 예측 불가능한 숫자가 필요한 상황에서 예측 가능한 난수를 사용하면, 공격자가 SW에서 생성되는 다음 숫자를 예상하여 시스템을 공격할 수 있는 보안약점이다.
- **보안대책**:
    - 시드(Seed)값이 고정되면 매번 동일한 난수가 발생하므로, C의 rand()는 srand()로 현재시간 기반 등 매번 변경되는 시드값을 설정한다.
    - 세션 ID, 암호화키 등 보안결정용 난수에는 Random()·Math.random()을 사용하지 말고, 암호학적으로 보호된 java.security.SecureRandom을 사용한다.
- **코드 포인트**: new Random(100) 고정 시드 사용, 또는 인증키 생성에 new Random() 사용 → 보안결정용에는 SecureRandom.getInstance("SHA1PRNG") + setSeed(generateSeed(128)) 사용
- **정탐/오탐 판단**: 정탐 — 고정 시드의 난수 사용, 또는 세션 ID·암호화키·인증키 등 보안결정에 Random/rand() 계열을 사용하는 경우. 오탐 — 보안결정이 아닌 용도로 매번 변경되는 시드의 Random을 쓰거나, 보안결정에 SecureRandom을 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public static int getRandomValue(int maxValue) {
    // 고정된 시드값을 사용하여 동일한 난수값이 생성되어 안전하지 않다.
    Random random = new Random(100);
    return random.nextInt(maxValue);
}

public static String getAuthKey() {
    // 매번 변경되는 시드값을 사용하여 다른 난수값이 생성되나 보안결정을 위한 난수로는 안전하지 않다.
    Random random = new Random();
    String authKey = Integer.toString(random.nextInt());
}
```

**안전 (Java)**

```java
public static int getRandomValue(int maxValue) {
    // 기본값인 현재 시간 기반으로 매번 변경되는 시드값을 사용하도록 한다.
    Random random = new Random();
    return random.nextInt(maxValue);
}

public static String getAuthKey() {
    // 보안결정을 위한 난수로는 암호학적으로 보호된 SecureRandom을 사용한다.
    try {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        secureRandom.setSeed(secureRandom.generateSeed(128));
        String authKey = new String(digest.digest((secureRandom.nextLong() + "").getBytes()));
    } catch (NoSuchAlgorithmException e) {
    }
}
```

#### 2-9. 취약한 비밀번호 허용

- **정의**: 사용자에게 강한 비밀번호 조합규칙을 요구하지 않으면 사용자 계정이 취약하게 되는 보안약점으로, 「패스워드 선택 및 이용 안내서」의 안전한 패스워드 설정규칙을 적용해야 한다.
- **보안대책**:
    - 비밀번호 생성 시 강한 조건 검증을 수행한다.
    - 숫자·영문자·특수문자 등을 혼합하여 정해진 자릿수로 생성되도록 한다.
    - 비밀번호를 주기적으로 변경하도록 한다.
- **코드 포인트**: 자릿수·특수문자 포함 여부 등 복잡도 체크 없이 바로 회원 등록(빈 비밀번호 허용 포함) → 정규식으로 복잡도(영문+숫자/특수문자 조합, 자릿수) 검증 후 등록
- **정탐/오탐 판단**: 정탐 — 가입·인증 시 비밀번호 복잡도(자릿수, 특수문자 등) 검증 없이 처리하거나 빈 비밀번호를 허용하는 경우. 오탐 — 정규식 등으로 조합과 자릿수를 검증한 후에만 승인하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
String id = request.getParameter("id");
String pass = request.getParameter("pass");
UserVo userVO = new UserVo(id, pass);
// 비밀번호의 자릿수, 특수문자 포함 여부 등 복잡도를 체크하지 않고 등록
String result = registerDAO.register(userVO);
```

**안전 (Java)**

```java
String id = request.getParameter("id");
String pass = request.getParameter("pass");
// 비밀번호에 자릿수, 특수문자 포함 여부 등의 복잡도를 체크하고 등록하게 한다.
Pattern pattern = Pattern.compile("((?=.*[a-zA-Z])(?=.*[0-9@#$%]).{9,})");
Matcher matcher = pattern.matcher(pass);
if (!matcher.matches()) {
    return "비밀번호 조합규칙 오류";
}
UserVo userVO = new UserVo(id, pass);
String result = registerDAO.register(userVO);
```

#### 2-10. 부적절한 전자서명 확인

- **정의**: 전자서명은 서명자의 신원을 확인하고 서명된 파일의 무결성을 보장하는 디지털 정보로, 이를 검증하지 않거나 검증절차가 부적절하면 위변조된 파일로 악성코드에 감염될 수 있는 보안약점이다.
- **보안대책**:
    - 전자서명을 포함하는 파일을 사용할 때는 항상 전자서명을 확인한다.
    - 전자서명 파일의 출처 등을 확인하여 신뢰할 수 없는 곳에서 생성된 파일을 사용하지 않는다.
- **코드 포인트**: 다운로드한 JAR을 new JarFile(f)로 서명 확인 없이 사용 → new JarFile(f, true)로 서명 검증을 활성화하고 JarEntry.getCodeSigners()로 서명 주체의 신뢰 여부 확인
- **정탐/오탐 판단**: 정탐 — 신뢰할 수 없는 곳에서 다운로드한 서명 파일(JAR 등)을 서명 검증 없이 로드·사용하는 경우. 오탐 — 서명 검증 옵션으로 파일을 열고 전자서명 주체까지 확인한 후 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 신뢰할 수 없는 곳에서 다운로드 한 JAR 파일의 서명을 확인하지 않고 사용한다.
File f = new File(downloadedFilePath);
JarFile jf = new JarFile(f);
```

**안전 (Java)**

```java
// JarFile 생성자에 boolean형 파라미터를 사용하여 전자서명을 확인한다.
File f = new File(downloadedFilePath);
JarFile jf = new JarFile(f, true);
Enumeration<JarEntry> ens = jf.entries();
while (ens.hasMoreElements()) {
    JarEntry en = ens.nextElement();
    if (!en.isDirectory()) {
        if (en.toString().equals(path)) {
            byte[] data = readAll(jar.getInputStream(en), en.getSize());
            // 전자서명 주체를 신뢰할 수 있는지 확인하여야 한다.
            CodeSigner[] signers = en.getCodeSigners();
        }
    }
}
jf.close();
```

#### 2-11. 부적절한 인증서 유효성 검증

- **정의**: 인증서를 확인하지 않거나 확인 절차를 적절하게 수행하지 않아, 악의적인 호스트에 연결되거나 신뢰할 수 없는 호스트에서 생성된 데이터를 수신하게 되는 보안약점이다.
- **보안대책**:
    - 인증서 사용 전 유효성을 확인한다: Common Name과 실제 호스트의 일치, 신뢰된 발급기관(CA)의 서명 여부, 유효기간, 해지여부, 안전한 암호화 알고리즘 사용 여부.
    - 해지여부 확인을 위해 CRL(인증서 해지목록) 또는 OCSP(실시간 인증서 상태확인)를 사용한다.
- **코드 포인트**: 자체 서명 인증서도 통과시키거나 CN-호스트 일치를 확인하지 않음(중간자 공격 탐지 불가) → 발급자 DN 일치 확인, CA 공개키로 verify(), checkValidity()로 유효기간 검증
- **정탐/오탐 판단**: 정탐 — 자체 서명 인증서를 허용하거나 CN·호스트 일치, 유효기간, 해지여부 등 검증 절차를 생략·부실하게 수행하는 경우. 오탐 — DN 일치, CA 서명 검증, 유효기간·해지 확인(CRL/OCSP) 등 유효성 검증 절차를 구현한 경우.

**코드예제 (가이드 원문 기반)**

**취약 (C)**

```c
cert = SSL_get_peer_certificate(ssl);
if (cert && (SSL_get_verify_result(ssl) == X509_V_OK)) {
    /* CN을 확인하지 않았지만 신뢰하고 진행한다. 이럴 경우, 공격자가 Common Name을
       www.attack.com으로 설정하여 중간자 공격에 사용할 경우 데이터가 중간에서
       복호화 되고 있음을 탐지하지 못한다. */
}
```

**안전 (Java)**

```java
private boolean verifySignature(X509Certificate toVerify, X509Certificate signingCert) {
    // 호스트 인증서(toVerify)와 CA인증서(signingCert)의 DN이 일치하는지 여부를 확인한다.
    if (!toVerify.getIssuerDN().equals(signingCert.getSubjectDN())) return false;
    try {
        // 호스트 인증서가 CA인증서로 서명 되었는지 확인한다.
        toVerify.verify(signingCert.getPublicKey());
        // 호스트 인증서가 유효기간이 만료되었는지 확인한다.
        toVerify.checkValidity();
        return true;
    } catch (GeneralSecurityException verifyFailed) {
        return false;
    }
}
```

#### 2-12. 사용자 하드디스크에 저장되는 쿠키를 통한 정보노출

- **정의**: 브라우저 세션에 관계없이 지속되도록 설정된 영속적인 쿠키(Persistent Cookie)는 디스크에 기록되는데, 여기에 개인정보·인증 정보 등이 저장되면 공격자가 쿠키에 접근할 기회가 많아져 시스템이 취약해지는 보안약점이다.
- **보안대책**:
    - 쿠키의 만료시간은 세션이 지속되는 시간을 고려하여 최소한으로 설정한다.
    - 영속적인 쿠키에는 사용자 권한 등급, 세션ID 등 중요정보가 포함되지 않도록 한다.
- **코드 포인트**: loginCookie.setMaxAge(60_60_24_365)로 만료시간을 1년으로 과도하게 설정 → setMaxAge(60_60*24) 등 기능에 맞춘 최소 만료시간 설정
- **정탐/오탐 판단**: 정탐 — 쿠키 만료시간을 1년 등 과도하게 길게 설정하거나 영속 쿠키에 중요정보를 담는 경우. 오탐 — 만료시간을 해당 기능에 맞춰 최소로 설정하고 중요정보를 포함하지 않는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
Cookie loginCookie = new Cookie("rememberme", "YES");
// 쿠키의 만료시간을 1년으로 과도하게 길게 설정하고 있어 안전하지 않다.
loginCookie.setMaxAge(60*60*24*365);
response.addCookie(loginCookie);
```

**안전 (Java)**

```java
Cookie loginCookie = new Cookie("rememberme", "YES");
// 쿠키의 만료시간은 해당 기능에 맞춰 최소로 사용한다.
loginCookie.setMaxAge(60*60*24);
response.addCookie(loginCookie);
```

#### 2-13. 주석문 안에 포함된 시스템 주요정보

- **정의**: 개발자가 편의를 위해 주석문에 패스워드를 적어두면 완성 후 제거가 매우 어렵고, 공격자가 소스코드에 접근할 수 있다면 아주 쉽게 시스템에 침입할 수 있는 보안약점이다.
- **보안대책**:
    - 주석에는 ID, 패스워드 등 보안과 관련된 내용을 기입하지 않는다.
    - 개발 시 주석문 등에 남겨놓은 사용자 계정·패스워드 정보는 개발 완료 시 확실하게 삭제한다.
- **코드 포인트**: `// DB연결 root / a1q2w3r3f2!@` 처럼 주석에 DB 연결 ID·패스워드 노출 → 해당 주석을 삭제하고 중요정보를 주석에 포함하지 않음
- **정탐/오탐 판단**: 정탐 — 주석문에 실제 계정 ID·패스워드 등 시스템 주요정보가 서술되어 남아 있는 경우. 오탐 — 주석에 보안 관련 정보가 없는 일반 설명 주석만 있는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 주석문으로 DB연결 ID, 패스워드의 중요한 정보를 노출시켜 안전하지 않다.
// DB연결 root / a1q2w3r3f2!@
con = DriverManager.getConnection(URL, USER, PASS);
```

**안전 (Java)**

```java
// ID, 패스워드등의 중요 정보는 주석에 포함해서는 안된다.
con = DriverManager.getConnection(URL, USER, PASS);
```

#### 2-14. 솔트 없이 일방향 해쉬함수 사용

- **정의**: 패스워드를 솔트(Salt) 없이 해쉬하여 저장하면, 공격자가 레인보우 테이블과 같이 해쉬값을 미리 계산하여 패스워드를 찾을 수 있게 되는 보안약점이다.
- **보안대책**:
    - 패스워드 저장 시 패스워드와 솔트를 해쉬함수의 입력으로 하여 얻은 해쉬값을 저장한다.
    - 패스워드만을 해쉬 입력으로 사용하면 레인보우 테이블을 이용한 사전 공격이 가능하므로 솔트를 함께 적용한다.
- **코드 포인트**: md.update(password.getBytes())만으로 해쉬 생성 → md.update(password.getBytes()); md.update(salt); 처럼 솔트를 함께 해쉬에 적용
- **정탐/오탐 판단**: 정탐 — 패스워드 해쉬 생성 시 솔트 없이 패스워드만을 해쉬함수 입력으로 사용하는 경우. 오탐 — 패스워드와 솔트를 함께 해쉬함수에 적용한 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public String getPasswordHash(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    // 해쉬에 솔트를 적용하지 않아 안전하지 않다.
    md.update(password.getBytes());
    byte byteData[] = md.digest();
    StringBuffer hexString = new StringBuffer();
    for (int i = 0; i < byteData.length; i++) {
        String hex = Integer.toHexString(0xff & byteData[i]);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }
    return hexString.toString();
}
```

**안전 (Java)**

```java
public String getPasswordHash(String password, byte[] salt) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(password.getBytes());
    // 해쉬 사용 시에는 원문을 찾을 수 없도록 솔트를 사용하여야 한다.
    md.update(salt);
    byte byteData[] = md.digest();
    StringBuffer hexString = new StringBuffer();
    for (int i = 0; i < byteData.length; i++) {
        String hex = Integer.toHexString(0xff & byteData[i]);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }
    return hexString.toString();
}
```

#### 2-15. 무결성 검사 없는 코드 다운로드

- **정의**: 원격으로부터 소스코드 또는 실행파일을 무결성 검사 없이 다운로드하여 실행하면, 호스트 서버 변조, DNS 스푸핑 또는 전송 시 코드 변조 등으로 공격자가 악의적인 코드를 실행할 수 있게 되는 보안약점이다.
- **보안대책**:
    - DNS 스푸핑을 방어할 수 있는 DNS lookup을 수행한다.
    - 코드 전송 시 신뢰할 수 있는 암호 기법으로 코드를 암호화한다.
    - 다운로드한 코드는 작업 수행에 필요한 최소한의 권한으로 실행한다.
- **코드 포인트**: URLClassLoader로 원격 파일을 무결성 검사 없이 로드 → 로드 전 체크섬 실행 및 공개키 방식 시그니처로 변조 유무 판단
- **정탐/오탐 판단**: 정탐 — 원격에서 받은 코드·파일을 체크섬/시그니처 등 무결성 검사 없이 로드·저장·실행하는 경우. 오탐 — 체크섬 확인·시그니처 검증 등 무결성 검사를 수행한 후 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 원격에서 파일을 다운로드한 뒤 로드하면서, 대상 파일에 대한 무결성 검사를 수행하지 않는다.
URL[] classURLs = new URL[] { new URL("file:subdir/") };
URLClassLoader loader = new URLClassLoader(classURLs);
Class loadedClass = Class.forName("LoadMe", true, loader);
```

**안전 (Java)**

```java
// 공개키 방식의 암호화 알고리즘으로 전송파일에 대한 시그니처를 생성하고 변조유무를 판단한다.
// 서버에서는 Private Key를 가지고 클래스를 암호화한다.
String jarFile = "./download/util.jar";
byte[] loadFile = FileManager.getBytes(jarFile);
loadFile = encrypt(loadFile, privateKey);
FileManager.createFile(loadFile, jarFileName);
// 클라이언트에서는 파일을 다운로드 받을 경우 Public Key로 복호화한다.
URL[] classURLs = new URL[] { new URL("http://filesave.com/download/util.jar") };
URLConnection conn = classURLs.openConnection();
InputStream is = conn.getInputStream();
FileOutputStream fos = new FileOutputStream(new File(jarFile));
while (is.read(buf) != -1) {
    ......
}
loadFile = decrypt(FileManager.getBytes(jarFile), publicKey);
FileManager.createFile(loadFile, jarFile);
URLClassLoader loader = new URLClassLoader(classURLs);
Class loadedClass = Class.forName("MyClass", true, loader);
```

#### 2-16. 반복된 인증시도 제한 기능 부재

- **정의**: 일정 시간 내 여러 번의 인증 시도에도 계정잠금 또는 추가 인증 등의 충분한 조치가 수행되지 않으면, 공격자가 ID·비밀번호 사전(Dictionary)을 만들어 무차별 대입(brute-force)으로 로그인 성공 및 권한획득이 가능한 보안약점이다.
- **보안대책**:
    - 인증시도 횟수를 적절한 횟수로 제한한다.
    - 설정된 인증실패 횟수를 초과했을 경우 계정을 잠금하거나 추가적인 인증과정을 거쳐 시스템에 접근하도록 한다.
- **코드 포인트**: `while (result == FAIL)`처럼 인증 실패에 제한 없이 무한 재시도 허용 → MAX_ATTEMPTS = 5를 정의하고 `while (result == FAIL && count < MAX_ATTEMPTS)`로 시도 횟수를 카운터로 제한
- **정탐/오탐 판단**: 정탐 — 로그인 실패 시 횟수 제한 없이 인증을 계속 재시도할 수 있는 반복 구조인 경우. 오탐 — 카운터로 인증시도 횟수를 제한하고 초과 시 실패 처리하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
private static final String SERVER_IP = "127.0.0.1";
private static final int SERVER_PORT = 8080;
private static final int FAIL = -1;

public void login() {
    String username = null;
    String password = null;
    Socket socket = null;
    int result = FAIL;
    try {
        socket = new Socket(SERVER_IP, SERVER_PORT);
        // 인증 실패에 대해 제한을 두지 않아 안전하지 않다.
        while (result == FAIL) {
            result = verifyUser(username, password);
        }
    }
}
```

**안전 (Java)**

```java
private static final String SERVER_IP = "127.0.0.1";
private static final int SERVER_PORT = 8080;
private static final int FAIL = -1;
private static final int MAX_ATTEMPTS = 5;

public void login() {
    String username = null;
    String password = null;
    Socket socket = null;
    int result = FAIL;
    int count = 0;
    try {
        socket = new Socket(SERVER_IP, SERVER_PORT);
        // 인증 실패 및 시도 횟수에 제한을 두어 안전하다.
        while (result == FAIL && count < MAX_ATTEMPTS) {
            result = verifyUser(username, password);
            count++;
        }
    }
}
```

## 유형 3. 시간 및 상태 (2개)

#### 3-1. 경쟁조건: 검사시점과 사용시점(TOCTOU)

- **정의**: 병렬시스템(멀티프로세스 응용프로그램)에서 자원(파일, 소켓 등)을 검사하는 시점(Time Of Check)과 사용하는 시점(Time Of Use)이 달라, 검사 시 존재하던 자원이 사용 시점에 사라지는 등 자원 상태가 변하여 발생하는 보안약점이다. 동기화 오류뿐만 아니라 교착상태 등의 문제가 발생할 수 있다.
- **보안대책**:
    - 공유자원(예: 파일)을 여러 프로세스가 접근하여 사용할 경우, 동기화 구문(synchronized, mutex 등)을 사용하여 한 번에 하나의 프로세스만 접근 가능하도록 한다.
    - 성능에 미치는 영향을 최소화하기 위해 임계코드 주변만 동기화 구문을 사용한다.
- **코드 포인트**: 두 스레드가 동기화 없이 f.exists() 검사 후 파일 읽기/삭제를 동시 수행(레이스컨디션) → synchronized(SYNC){...}(Java), mutex_lock()/mutex_unlock()(C)으로 공유자원 접근 제한
- **정탐/오탐 판단**: 정탐 — 멀티스레드/멀티프로세스 환경에서 공유자원의 검사와 사용 사이에 동기화 구문 없이 여러 프로세스가 동시 접근 가능한 경우. 오탐 — synchronized, mutex 등 동기화 구문으로 임계코드가 보호되어 한 번에 하나의 프로세스만 접근하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// 멀티쓰레드 환경에서 공유자원에 여러 프로세스가 동시에 접근할 가능성이 있어 안전하지 않다.
public void run() {
    try {
        if (manageType.equals("READ")) {
            File f = new File("Test_367.txt");
            if (f.exists()) {
                BufferedReader br = new BufferedReader(new FileReader(f));
                br.close();
            }
        } else if (manageType.equals("DELETE")) {
            File f = new File("Test_367.txt");
            if (f.exists()) {
                f.delete();
            }
        }
    } catch (IOException e) { /* … */ }
}
```

**안전 (Java)**

```java
private static final String SYNC = "SYNC";

public void run() {
    // 멀티쓰레드 환경에서 synchronized를 사용하여 동시에 접근할 수 없도록 사용해야 한다.
    synchronized(SYNC) {
        try {
            if (manageType.equals("READ")) {
                File f = new File("Test_367.txt");
                if (f.exists()) {
                    BufferedReader br = new BufferedReader(new FileReader(f));
                    br.close();
                }
            } else if (manageType.equals("DELETE")) {
                File f = new File("Test_367.txt");
                if (f.exists()) {
                    f.delete();
                }
            }
        } catch (IOException e) { /* … */ }
    }
}
```

#### 3-2. 종료되지 않는 반복문 또는 재귀함수

- **정의**: 재귀의 순환횟수를 제어하지 못하여 할당된 메모리나 프로그램 스택 등의 자원을 과다하게 사용하는 보안약점이다. 귀납 조건(Base Case)이 없는 재귀 함수는 무한 루프에 빠져 자원고갈을 유발함으로써 시스템의 정상적인 서비스를 제공할 수 없게 한다.
- **보안대책**:
    - 모든 재귀 호출 시 재귀 호출 횟수를 제한한다.
    - 초기값을 설정(상수)하여 재귀 호출을 제한한다.
- **코드 포인트**: 탈출 조건 없이 `return i * factorial(i - 1);`만 수행하는 재귀 → `if (i <= 1) { return 1; }` 귀납조건(Base case)을 먼저 두고 재귀 호출
- **정탐/오탐 판단**: 정탐 — 재귀문·반복문을 빠져나오는 조건(귀납조건·종료조건)이 없어 무한 반복에 빠져 시스템 장애를 유발할 수 있는 경우. 오탐 — 탈출 조건(Base case)이 구현되어 있거나 호출·반복 횟수가 제한되어 있는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (C)**

```c
int factorial(int i)
{
    // 재귀함수 탈출 조건을 설정하지 않아 무한루프가 된다.
    return i * factorial(i - 1);
}

int main()
{
    int num = 5;
    int result = factorial(num);
    printf("%d! : %d\n", num, result);
    return 0;
}
```

**안전 (C)**

```c
int factorial(int i)
{
    // 재귀함수 사용 시에는 아래와 같이 탈출 조건을 사용해야 한다.
    if (i <= 1) {
        return 1;
    }
    return i * factorial(i - 1);
}

int main()
{
    int num = 5;
    int result = factorial(num);
    printf("%d! : %d\n", num, result);
    return 0;
}
```

## 유형 4. 에러처리 (3개)

#### 4-1. 오류 메시지 정보노출

- **정의**: 응용프로그램이 실행환경, 사용자 등 관련 데이터 또는 시스템 내부데이터 등 민감한 정보를 포함하는 오류 메시지를 생성하여 외부에 제공하는 경우, 공격자의 악성 행위를 도울 수 있는 보안약점이다. 예외 발생 시 예외 이름이나 스택 트레이스를 출력하면 프로그램 내부구조를 쉽게 파악할 수 있다.
- **보안대책**:
    - 오류 메시지는 정해진 사용자에게 유용한 최소한의 정보만 포함하도록 한다.
    - 예외 상황은 소스코드 내부적으로 처리하고, 민감한 정보를 포함하는 오류 대신 미리 정의된 메시지를 제공하도록 설정한다.
- **코드 포인트**: e.printStackTrace(); System.err.print(e.getMessage()); 로 스택·시스템 정보 노출 → logger.error("ERROR-01: 파일 열기 에러"); 처럼 에러 코드와 정보를 별도 정의하고 최소 정보만 로깅
- **정탐/오탐 판단**: 정탐 — 예외 이름이나 오류추적 정보(스택 트레이스 등)를 외부(화면)에 출력하여 프로그램 내부 정보가 유출되는 경우. 오탐 — 미리 정의된 에러 코드로 최소한의 정보만 로깅하고 예외 이름·오류추적 정보를 출력하지 않는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
try {
    rd = new BufferedReader(new FileReader(new File(filename)));
} catch(IOException e) {
    // 에러 메시지로 스택 정보가 노출됨
    e.printStackTrace();
}
```

**안전 (Java)**

```java
try {
    rd = new BufferedReader(new FileReader(new File(filename)));
} catch(IOException e) {
    // 에러 코드와 정보를 별도로 정의하고 최소 정보만 로깅
    logger.error("ERROR-01: 파일 열기 에러");
}
```

#### 4-2. 오류 상황 대응 부재

- **정의**: 오류가 발생할 수 있는 부분을 확인하였으나 그 오류에 대하여 예외 처리를 하지 않을 경우, 공격자가 오류 상황을 악용하여 개발자가 의도하지 않은 방향으로 프로그램이 동작하도록 할 수 있는 보안약점이다.
- **보안대책**:
    - 오류가 발생할 수 있는 부분에 대하여 제어문을 사용하여 적절하게 예외 처리한다.
    - C/C++에서는 if와 switch, Java에서는 try-catch 등을 사용한다.
- **코드 포인트**: `catch (NullPointerException e) { }`처럼 오류를 포착만 하고 아무 조치가 없어 인증이 된 것으로 처리됨 → catch 블록에서 메시지 설정·로깅·반환 등 각 예외 사항에 대해 적절한 조치를 수행
- **정탐/오탐 판단**: 정탐 — 오류를 포착(catch)했지만 catch 블록이 비어 있어 아무 조치 없이 프로그램이 계속 실행되는 경우. 오탐 — 포착한 각각의 예외에 대해 로깅·메시지 설정·반환 등 적절한 처리가 수행되는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
try {
    username = s.getParser().getRawParameter(USERNAME);
    password = s.getParser().getRawParameter(PASSWORD);
    if (!"webgoat".equals(username) || !password.equals("webgoat")) {
        s.setMessage("Invalid username and password entered.");
        return (makeLogin(s));
    }
} catch (NullPointerException e) {
    // 요청 파라미터에 PASSWORD가 존재하지 않을 경우 Null Pointer Exception이 발생하고
    // 해당 오류에 대한 대응이 존재하지 않아 인증이 된 것으로 처리
}
```

**안전 (Java)**

```java
try {
    username = s.getParser().getRawParameter(USERNAME);
    password = s.getParser().getRawParameter(PASSWORD);
    if (!"webgoat".equals(username) || !password.equals("webgoat")) {
        s.setMessage("Invalid username and password entered.");
        return (makeLogin(s));
    }
} catch (NullPointerException e) {
    // 예외 사항에 대해 적절한 조치를 수행하여야 한다.
    s.setMessage(e.getMessage());
    return (makeLogin(s));
}
```

#### 4-3. 부적절한 예외 처리

- **정의**: 프로그램 수행 중에 함수의 결과값에 대한 적절한 처리 또는 예외 상황에 대한 조건을 적절하게 검사하지 않을 경우, 예기치 않은 문제를 야기할 수 있는 보안약점이다.
- **보안대책**:
    - 값을 반환하는 모든 함수의 결과값을 검사하여 의도했던 값인지 확인한다.
    - 예외 처리를 사용하는 경우 광범위한 예외 처리 대신 구체적인 예외 처리를 수행한다.
- **코드 포인트**: 다양한 예외가 발생할 수 있음에도 광범위한 `catch (Exception e)` 하나로 처리 → `catch (MalformedURLException e)`, `catch (IOException e)` 처럼 발생 가능한 오류의 종류와 순서에 맞춰 세분화하여 예외처리
- **정탐/오탐 판단**: 정탐 — 예외처리를 세분화할 수 있음에도 광범위한 예외 클래스(Exception)로 처리하거나 함수 결과값을 검사하지 않는 경우. 오탐 — 발생 가능한 예외를 세분화하고 순서에 따라 구체적으로 예외를 처리하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
try {
    reader = new BufferedReader(new InputStreamReader(url.openStream()));
    String line = reader.readLine();
    SimpleDateFormat format = new SimpleDateFormat("MM/DD/YY");
    Date date = format.parse(line);
    // 예외처리를 세분화 할 수 있음에도 광범위하게 사용하여 예기치 않은 문제가 발생할 수 있다.
} catch (Exception e) {
    System.err.println("Exception : " + e.getMessage());
}
```

**안전 (Java)**

```java
try {
    reader = new BufferedReader(new InputStreamReader(url.openStream()));
    String line = reader.readLine();
    SimpleDateFormat format = new SimpleDateFormat("MM/DD/YY");
    Date date = format.parse(line);
    // 발생할 수 있는 오류의 종류와 순서에 맞춰서 예외처리 한다.
} catch (MalformedURLException e) {
    System.err.println("MalformedURLException : " + e.getMessage());
} catch (IOException e) {
    System.err.println("IOException : " + e.getMessage());
} catch (ParseException e) {
    System.err.println("ParseException : " + e.getMessage());
}
```

## 유형 5. 코드오류 (5개)

#### 5-1. Null Pointer 역참조

- **정의**: '일반적으로 그 객체가 널(Null)이 될 수 없다'라는 가정을 위반했을 때 발생하는 보안약점이다. 공격자가 의도적으로 널 포인터 역참조를 발생시키면 그 결과 발생하는 예외 상황을 추후 공격 계획에 이용할 수 있다.
- **보안대책**:
    - 널이 될 수 있는 레퍼런스(Reference)는 참조하기 전에 널 값인지 검사하여 안전한 경우에만 사용한다.
- **코드 포인트**: `if ((null == obj && null == elt) || obj.equals(elt))` 처럼 obj가 null일 수 있는 상태에서 참조 → `(null != obj && obj.equals(elt))` 처럼 참조 전 null 검사 후 사용(&& 단락평가)
- **정탐/오탐 판단**: 정탐 — request.getParameter 등 null 반환 가능 함수에서 얻은 값을 null 검사 없이 참조(equals, length, `*p` 등)하는 경우. 오탐 — 참조 전에 null 검사를 수행하여 안전한 경우에만 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public static int cardinality(Object obj, final Collection col) {
    int count = 0;
    if (col == null) { return count; }
    Iterator it = col.iterator();
    while (it.hasNext()) {
        Object elt = it.next();
        // obj가 null이고 elt가 null이 아닐 경우, Null.equals가 되어 널 포인터 역참조가 발생한다.
        if ((null == obj && null == elt) || obj.equals(elt)) {
            count++;
        }
    }
    return count;
}
```

**안전 (Java)**

```java
public static int cardinality(Object obj, final Collection col) {
    int count = 0;
    if (col == null) { return count; }
    Iterator it = col.iterator();
    while (it.hasNext()) {
        Object elt = it.next();
        // obj가 null인지 검사 후 참조해야 한다.
        if ((null == obj && null == elt) || (null != obj && obj.equals(elt))) {
            count++;
        }
    }
    return count;
}
```

#### 5-2. 부적절한 자원 해제

- **정의**: 열린 파일디스크립터, 힙 메모리, 소켓 등 유한한 자원을 할당받아 사용한 후, 프로그램 오류 또는 에러로 인해 사용이 끝난 자원을 반환하지 못하는 보안약점이다.
- **보안대책**:
    - 자원을 획득하여 사용한 다음에는 반드시 자원을 해제하여 반환한다.
    - 예외 발생 여부와 상관없이 항상 실행되는 finally 블록에서 할당받은 모든 자원을 반드시 반환한다(C#은 using 구문으로 자동 해제).
- **코드 포인트**: try 블록 안에서만 close() 호출(오류 발생 시 미실행) → finally 블록에서 각 자원에 null 검사 후 close(), 또는 try-with-resources/using 구문으로 자동 해제
- **정탐/오탐 판단**: 정탐 — 자원반환 실행 전에 오류가 발생하거나 조기 return으로 close()/fclose()가 실행되지 않는 경로가 존재하는 경우. 오탐 — finally 블록·using 구문에서 자원이 해제되거나 모든 경로에서 해제가 수행되는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
InputStream in = null;
OutputStream out = null;
try {
    in = new FileInputStream(inputFile);
    out = new FileOutputStream(outputFile);
    FileCopyUtils.copy(fis, os);
    // 자원반환 실행 전에 오류가 발생할 경우 자원이 반환되지 않는다.
    in.close();
    out.close();
} catch (IOException e) {
    logger.error(e);
}
```

**안전 (Java)**

```java
InputStream in = null;
OutputStream out = null;
try {
    in = new FileInputStream(inputFile);
    out = new FileOutputStream(outputFile);
    FileCopyUtils.copy(fis, os);
} catch (IOException e) {
    logger.error(e);
// 항상 수행되는 finally 블록에서 할당받은 모든 자원에 대해 각각 null검사 후 자원을 해제한다.
} finally {
    if (in != null) {
        try { in.close(); } catch (IOException e) { logger.error(e); }
    }
    if (out != null) {
        try { out.close(); } catch (IOException e) { logger.error(e); }
    }
}
```

#### 5-3. 해제된 자원 사용

- **정의**: C언어에서 동적 메모리 관리 결함으로, 해제한 메모리를 참조하면 예상치 못한 값 또는 코드를 실행하게 되어 의도하지 않은 결과가 발생하는 보안약점이다.
- **보안대책**:
    - 동적으로 할당된 메모리를 해제한 후 그 포인터를 참조·형 변환·수식의 피연산자 등으로 사용하지 않는다.
    - 메모리 해제 후 포인터에 널(Null)값 또는 다른 적절한 값을 저장하여 의도하지 않은 코드 실행을 막는다.
- **코드 포인트**: free(temp); 후 해제된 포인터를 다시 사용(또는 두 조건에서 이중 해제) → 메모리를 최종 사용 후 마지막에 해제하고, 해제 직후 `data = NULL;` 할당으로 이중 해제 방지
- **정탐/오탐 판단**: 정탐 — free()로 해제한 포인터를 이후 다시 사용하거나 동일 포인터가 이중 해제될 수 있는 경우. 오탐 — 최종 사용 뒤 해제하거나, 해제 후 포인터에 NULL을 할당하여 재사용·이중 해제가 차단된 경우.

**코드예제 (가이드 원문 기반)**

**취약 (C)**

```c
int main(int argc, const char *argv[]) {
    char *temp;
    temp = (char *)malloc(BUFFER_SIZE);
    ......
    free(temp);
    // 해제한 자원을 사용하고 있어 의도하지 않은 결과가 발생하게 된다.
    stmcpy(temp, argv[1], BUFFER_SIZE-1);
}
```

**안전 (C)**

```c
int main(int argc, const char *argv[]) {
    char *temp;
    temp = (char *)malloc(BUFFER_SIZE);
    ......
    // 할당된 자원을 최종적으로 사용하고 해제하여야 한다.
    stmcpy(temp, argv[1], BUFFER_SIZE-1);
    free(temp);
}
```

#### 5-4. 초기화되지 않은 변수 사용

- **정의**: C 언어에서 스택 메모리에 저장되는 지역변수는 생성될 때 자동으로 초기화되지 않으므로, 초기화되지 않은 변수를 사용하면 임의값을 사용하게 되어 의도하지 않은 결과나 예상치 못한 동작이 발생하는 보안약점이다.
- **보안대책**:
    - 초기화되지 않은 스택 변수는 이전 함수에서 사용되었던 내용을 포함하므로 공격자가 이를 악용할 수 있음을 인지한다.
    - 모든 변수를 사용 전에 반드시 올바른 초기값을 할당한다.
- **코드 포인트**: `int x, y;` 선언 후 일부 분기에서만 초기화하여 미초기화 변수가 사용됨 → `int x=1, y=1;` 처럼 선언 시 초기값을 항상 지정한 후 사용
- **정탐/오탐 판단**: 정탐 — switch/case 등 일부 분기에서 초기화되지 않는 변수가 존재하여 임의값으로 사용될 수 있는 경우. 오탐 — 모든 변수에 사용 전 초기값이 지정되어 있는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (C)**

```c
// 변수의 초기값을 지정하지 않을 경우 공격에 사용될 수 있어 안전하지 않다.
int x, y;
switch(position) {
    case 0: x = base_position; y = base_position beak;
    case 1: x = base_position + i; y = base_position - i break;
    default: x=1; break;
}
setCursorPosition(x,y);
```

**안전 (C)**

```c
// 변수의 초기값은 항상 지정하여야 한다.
int x=1, y=1;
switch(position) {
    case 0: x = base_position; y = base_position beak;
    case 1: x = base_position + i; y = base_position - i break;
    default: x=1; break;
}
setCursorPosition(x,y);
```

#### 5-5. 신뢰할 수 없는 데이터의 역직렬화

- **정의**: 직렬화된 정보를 네트워크로 전달·저장하는 과정에서 공격자가 스트림을 조작할 수 있는 경우, 신뢰할 수 없는 역직렬화를 이용하여 무결성 침해, 원격 코드 실행, 서비스 거부 공격 등이 발생할 수 있는 보안약점이다.
- **보안대책**:
    - 신뢰할 수 없는 데이터를 역직렬화하지 않도록 응용프로그램을 구성하고, 암호화 통신을 적용하지 못하는 경우 송신 측 서명 추가·수신 측 서명 확인으로 데이터 무결성을 검증한다.
    - 역직렬화 대상 데이터가 사전에 검증된 클래스만 포함하는지 검증(화이트리스트)하거나, 제한된 실행 권한으로 역직렬화 코드를 실행한다.
- **코드 포인트**: 바이트 배열 입력 값을 검증 없이 ois.readObject()로 역직렬화 → ObjectInputStream을 상속한 클래스에서 resolveClass로 화이트리스트를 비교해 리스트에 없는 클래스면 InvalidClassException 예외 발생
- **정탐/오탐 판단**: 정탐 — 공격자가 조작 가능한 바이트 스트림을 검증 없이 readObject()로 역직렬화하여 악의적인 코드가 실행될 수 있는 경우. 오탐 — 서명 검증으로 위변조를 방지하거나, 화이트리스트 검증된 클래스만 역직렬화하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
class DeserializeExample {
    public static Object deserialize(byte[] buffer)
            throws IOException, ClassNotFoundException {
        Object ret = null;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(buffer)) {
            try (ObjectInputStream ois = new ObjectInputStream(bais)) {
                // 입력 값을 검증 없이 readObject()로 역직렬화하여 악의적인 코드가 실행될 수 있다.
                ret = ois.readObject();
            }
        }
        return ret;
    }
}
```

**안전 (Java)**

```java
public class WhitelistedObjectInputStream extends ObjectInputStream {
    public Set<String> whitelist;
    // WhitelistedObjectInputStream을 생성할 때 화이트리스트를 입력받는다.
    public WhitelistedObjectInputStream(InputStream inputStream, Set<String> wl)
            throws IOException {
        super(inputStream);
        whitelist = wl;
    }
    @Override
    protected Class<?> resolveClass(ObjectStreamClass cls)
            throws IOException, ClassNotFoundException {
        // ObjectStreamClass의 클래스명이 화이트리스트에 있는지 확인한다.
        if (!whitelist.contains(cls.getName())) {
            throw new InvalidClassException("Unexpected serialized class", cls.getName());
        }
        return super.resolveClass(cls);
    }
}
```

## 유형 6. 캡슐화 (4개)

#### 6-1. 잘못된 세션에 의한 데이터 정보노출

- **정의**: 다중 스레드 환경에서 싱글톤 객체 필드에 경쟁조건(Race Condition)이 발생하여 서로 다른 세션 간에 데이터가 공유·노출될 수 있는 보안약점이다. Java 서블릿 등에서는 정보를 저장하는 멤버 변수가 포함되지 않도록 해야 한다.
- **보안대책**:
    - 싱글톤 패턴 사용 시 변수 범위(Scope)에 주의한다.
    - Java에서는 HttpServlet 하위클래스에 멤버 필드를 선언하지 않고, 필요한 경우 지역변수를 선언하여 사용한다.
- **코드 포인트**: JSP 선언부(`<%! %>`)나 @Controller 클래스에 `private int currentPage` 같은 멤버 변수 선언 → 서블릿부(`<% %>`)/메소드 내부에서 지역변수로 선언
- **정탐/오탐 판단**: 정탐 — 서블릿/컨트롤러/JSP 선언부 등 다중 스레드로 공유되는 클래스에 요청별 정보를 저장하는 멤버 필드가 선언된 경우. 오탐 — 해당 값이 지역변수·세션변수로 선언되어 스레드 간 공유가 발생하지 않는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
@Controller
public class TrendForecastController {
    // Controller에서 int 필드가 멤버 변수로 선언되어 스레드간에 공유됨
    private int currentPage = 1;

    public void doSomething(HttpServletRequest request) {
        currentPage = Integer.parseInt(request.getParameter("page"));
    }
}
```

**안전 (Java)**

```java
@Controller
public class TrendForecastController {
    public void doSomething(HttpServletRequest request) {
        // 지역변수로 사용하여 스레드간 공유되지 못하도록 한다.
        int currentPage = Integer.parseInt(request.getParameter("page"));
    }
}
```

#### 6-2. 제거되지 않고 남은 디버그 코드

- **정의**: 디버깅 목적으로 삽입된 코드가 제거되지 않고 배포되어, 설정 등 민감한 정보나 시스템 제어 부분이 노출될 수 있는 보안약점이다. 공격자가 식별 과정을 우회하거나 의도하지 않은 정보·제어 정보가 노출될 수 있다.
- **보안대책**:
    - 소프트웨어 배포 전 반드시 디버그 코드를 확인 및 삭제한다.
    - J2EE 웹응용프로그램에서 디버그 용도로 만든 main() 메소드는 디버깅이 끝나면 삭제한다.
- **코드 포인트**: J2EE 클래스에 디버그용 main() 메소드 잔존, 민감정보·콜스택 출력 코드 잔존 → 릴리즈 시 main() 메소드와 디버그용 출력 코드를 삭제하고 동작 코드만 남김
- **정탐/오탐 판단**: 정탐 — 배포 대상 코드에 디버그용 main() 메소드나 민감정보·콜스택을 출력하는 디버그 코드가 남아 있는 경우. 오탐 — 디버그 코드가 이미 삭제되었거나 배포 전 제거가 확인된 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
class Base64 {
    public static void main(String[] args) {
        if (debug) {
            byte[] a = { (byte) 0xfc, (byte) 0x0f, (byte) 0xc0 };
            byte[] b = { (byte) 0x03, (byte) 0xf0, (byte) 0x3f };
            // ……
        }
    }
    public void otherMethod() { /* … */ }
}
```

**안전 (Java)**

```java
// J2EE와 같은 응용프로그램에서 main() 메소드는 삭제한다.
class Base64 {
    public void otherMethod() { /* … */ }
}
```

#### 6-3. Public 메소드부터 반환된 Private 배열

- **정의**: private로 선언된 배열을 public 메소드로 반환(return)하면 배열의 레퍼런스가 외부에 공개되어, 외부에서 배열 수정과 객체 속성 변경이 가능해지는 보안약점이다.
- **보안대책**:
    - private 배열을 public 메소드로 직접 반환하지 않는다.
    - private 배열의 복사본을 반환하고, 배열 원소는 clone() 메소드로 복사하여 저장한다.
    - 원소가 String 타입 등 변경되지 않는 경우에는 배열의 복사본만 만들어 반환한다.
- **코드 포인트**: `private Color[] colors; public Color[] getColors() { return colors; }` → 새 배열을 생성해 원소까지 clone()으로 복사한 복사본을 반환
- **정탐/오탐 판단**: 정탐 — public 메소드가 private 배열의 레퍼런스를 그대로 return하는 경우. 오탐 — 복사본(가변 객체 원소는 clone() 포함)을 만들어 반환하거나 메소드가 private인 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// private 인 배열을 public인 메소드가 return한다.
private Color[] colors;

public Color[] getUserColors(Color[] userColors) {
    return colors;
}
```

**안전 (Java)**

```java
private Color[] colors;

// 메소드를 private으로 하거나, 복제본 반환, 수정하는 public 메소드를 별도로 만든다.
public Color[] getUserColors(Color[] userColors) {
    // 배열을 복사한다.
    Color[] colors = new Color[userColors.length];
    for (int i = 0; i < colors.length; i++)
        // clone()메소드를 이용하여 배열의 원소도 복사한다.
        colors[i] = this.colors[i].clone();
    return colors;
}
```

#### 6-4. Private 배열에 Public 데이터 할당

- **정의**: public 메소드의 인자가 private 배열에 그대로 저장되면, 외부에서 그 private 배열에 접근하여 배열 수정과 객체 속성 변경이 가능해지는 보안약점이다.
- **보안대책**:
    - public 메소드의 인자를 private 배열에 직접 저장하지 않는다.
    - 인자로 들어온 배열의 복사본을 생성하고 clone() 메소드로 복사된 원소를 저장하여 private 변수에 할당한다.
- **코드 포인트**: `public void setUserRoles(UserRole[] roles) { this.userRoles = roles; }` (사실상 public 필드가 됨) → 새 배열을 생성해 원소를 clone()으로 복사하여 할당
- **정탐/오탐 판단**: 정탐 — public 메소드가 외부에서 받은 배열 인자를 private 배열 필드에 참조 그대로 할당하는 경우. 오탐 — 인자 배열의 복사본(가변 객체 원소는 clone() 포함)을 생성하여 할당하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
// userRoles 필드는 private이지만, public인 setUserRoles()로
// 외부의 배열이 할당되면, 사실상 public 필드가 된다.
private UserRole[] userRoles;

public void setUserRoles(UserRole[] userRoles) {
    this.userRoles = userRoles;
}
```

**안전 (Java)**

```java
// 객체가 클래스의 private member를 수정하지 않도록 한다.
private UserRole[] userRoles;

public void setUserRoles(UserRole[] userRoles) {
    this.userRoles = new UserRole[userRoles.length];
    for (int i = 0; i < userRoles.length; ++i)
        this.userRoles[i] = userRoles[i].clone();
}
```

## 유형 7. API 오용 (2개)

#### 7-1. DNS lookup에 의존한 보안결정

- **정의**: 공격자가 DNS 엔트리를 속일 수 있으므로, 도메인명에 의존해 인증·접근 통제 등의 보안결정을 하면 안 되는 보안약점이다. 로컬 DNS 캐시가 오염되면 트래픽이 공격자를 경유하거나 공격자가 동일 도메인 서버로 위장할 수 있다.
- **보안대책**:
    - 보안결정에서 도메인명을 이용한 DNS lookup을 하지 않는다.
    - DNS lookup에 의한 호스트 이름 비교 대신 실제 서버의 IP 주소를 직접 비교한다.
- **코드 포인트**: `addr.getCanonicalHostName().endsWith("trustme.com")` 등 호스트 이름으로 신뢰 여부 판별 → `ip.equals("127.0.0.1")`처럼 신뢰하는 IP 주소를 직접 비교
- **정탐/오탐 판단**: 정탐 — DNS lookup으로 얻은 도메인/호스트명 비교 결과를 인증·접근 통제 등 보안결정에 사용하는 경우. 오탐 — 호스트명 비교가 아닌 IP 주소 직접 비교로 신뢰 여부를 판별하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (Java)**

```java
public void doGet(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException {
    boolean trusted = false;
    String ip = req.getRemoteAddr();
    InetAddress addr = InetAddress.getByName(ip);
    // 도메인은 공격자에 의해 실행되는 서버의 DNS가 변경될 수 있으므로 안전하지 않다.
    if (addr.getCanonicalHostName().endsWith("trustme.com")) {
        do_something_for_Trust_System();
    }
}
```

**안전 (Java)**

```java
public void doGet(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException {
    String ip = req.getRemoteAddr();
    if (ip == null || "".equals(ip)) return;
    // 이용하려는 실제 서버의 IP 주소를 사용하여 DNS변조에 방어한다.
    String trustedAddr = "127.0.0.1";
    if (ip.equals(trustedAddr)) {
        do_something_for_Trust_System();
    }
}
```

#### 7-2. 취약한 API 사용

- **정의**: 보안상 금지된(banned) 함수이거나 부주의하게 사용될 가능성이 많은 API를 확인 없이 사용하여 보안 문제가 발생하는 보안약점이다. 대표적 금지 API로 gets(), strcat(), strcpy(), strncat(), strncpy(), sprintf() 등이 있다.
- **보안대책**:
    - 금지된 함수 대신 gets_s()/fgets(), strcat_s(), strcpy_s(), strncat_s(), strncpy_s(), sprintf_s() 등 안전한 대체 함수를 사용한다.
    - 금지되지 않았어도 취약하게 쓰일 수 있는 API(strtol 등)에 주의하고, 개발 조직이 취약 API를 명시한 경우 반드시 준수한다.
    - J2EE에서는 소켓 직접 사용 대신 보안기능을 제공하는 프레임워크 메소드를 사용하고, System.exit()를 사용하지 않는다.
- **코드 포인트**: gets(str), J2EE 내 new Socket(...)·System.exit(1) → gets_s(str, sizeof(str))/fgets, url.openConnection()(URLConnection) 사용, System.exit() 호출 제거
- **정탐/오탐 판단**: 정탐 — 금지 API(gets 등)를 사용하거나 J2EE에서 소켓 직접 사용·System.exit() 호출 등 API를 의도된 사용에 반하게 쓰는 경우. 오탐 — 길이 제한이 있는 안전한 대체 함수(_s 계열, fgets)나 프레임워크가 제공하는 보안 메소드를 사용하는 경우.

**코드예제 (가이드 원문 기반)**

**취약 (C)**

```c
#include <stdio.h>

void requestString()
{
    char str[100];
    // gets() 함수는 문자열 길이를 제한 할 수 없어 안전하지 않다.
    gets(str);
}
```

**안전 (C)**

```c
#include <stdio.h>

void requestString()
{
    char str[100];
    // gets_s() 함수는 문자열 길이 제한이 가능하다.
    gets_s(str, sizeof(str));
}
```

---

# 제4장. 정탐/오탐 연습문제 + 복합서술형 양식

> 공식 형식(안내서 확인): 실습시험 100분 / 서술형 15문항 / 100점 / 과락 60점 미만 / 가중치 60% — **문항당 평균 6.7분** 유형: ① 단순서술형(보안약점 정·오탐 분석) ② 복합서술형(산출물 검토 후 보완요청서·진단보고서 작성, 8점 규모) 채점 방식: 예시 답안 기준 **핵심 키워드가 포함되어야 정답 인정** — 길게 쓰는 것보다 키워드가 들어가게 쓰는 훈련이 중요. 검은색 볼펜 지필. 훈련 방식: 각 문제마다 ① **정탐/오탐 판단** ② **사유를 2~3문장으로 서술** (근거 코드 라인 지목 포함). 반드시 손으로 직접 쓴 뒤 해설과 대조할 것. 사유 서술 템플릿: "**[코드의 어느 부분]에서 [외부 입력/자원]이 [검증·보호 여부] 상태로 [사용처]에 사용되므로, [약점 발생/발생하지 않음]. 따라서 정탐(또는 오탐)이다.**"

---

### 문제 1. SQL 삽입 보고

```java
String userId = request.getParameter("id");
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

진단도구 보고: SQL 삽입 (정탐/오탐?)

**정답: 오탐** 외부 입력 userId가 질의문 문자열에 연결(concatenation)되지 않고, PreparedStatement의 바인딩 변수(?)에 setString으로 할당된다. 바인딩된 값은 질의 구조를 변경할 수 없으므로 SQL 삽입이 발생하지 않는다.

---

### 문제 2. SQL 삽입 보고 (변형)

```java
String col = request.getParameter("sortCol");
String sql = "SELECT * FROM board ORDER BY " + col;
PreparedStatement pstmt = conn.prepareStatement(sql);
ResultSet rs = pstmt.executeQuery();
```

진단도구 보고: SQL 삽입 (정탐/오탐?)

**정답: 정탐** PreparedStatement를 사용했지만 외부 입력 col이 바인딩 변수가 아니라 질의문 문자열에 직접 연결된다. ORDER BY 절은 바인딩 처리 대상이 아니며 검증 없이 연결되므로 질의 구조 조작이 가능하다. (대응: 허용 컬럼명 화이트리스트 검증)

---

### 문제 3. 크로스사이트 스크립트(XSS)

```jsp
<%
String keyword = request.getParameter("q");
%>
검색어: <%= keyword %>
```

진단도구 보고: XSS (정탐/오탐?)

**정답: 정탐** 외부 입력 keyword가 어떠한 검증·인코딩 없이 HTML 응답에 그대로 출력된다. `<script>` 등 스크립트 문자열 입력 시 사용자 브라우저에서 실행 가능하므로 반사형 XSS가 성립한다. (대응: 출력 시 HTML 특수문자 인코딩 또는 검증 라이브러리 사용)

---

### 문제 4. XSS (변형)

```java
String keyword = request.getParameter("q");
keyword = keyword.replaceAll("(?i)<script", "");   // script 태그 제거
out.println("검색어: " + keyword);
```

진단도구 보고: XSS (정탐/오탐?)

**정답: 정탐 (함정 문제)** 필터링을 수행하지만 `<script` 문자열만 제거하는 블랙리스트 방식이다. `<img src=x onerror=alert(1)>` 같은 이벤트 핸들러 기반 공격은 그대로 통과하고, `<sc<scriptript>`처럼 제거 후 재조합되는 우회도 가능하다. 특정 패턴 제거만으로는 XSS가 차단되지 않으므로 정탐이다. (대응: 출력 시 `&`를 가장 먼저 포함한 HTML 특수문자 전체 인코딩 — 치환 순서는 `&` → `<` → `>` → `"` → `'`)

---

### 문제 5. 경로 조작 및 자원 삽입

```java
String fileName = request.getParameter("file");
if (fileName != null && fileName.matches("[a-zA-Z0-9_\\-]+\\.(txt|pdf)")) {
    File f = new File("/app/data/" + fileName);
    FileInputStream fis = new FileInputStream(f);
}
```

진단도구 보고: 경로 조작 및 자원 삽입 (정탐/오탐?)

**정답: 오탐** 외부 입력 fileName이 파일 경로에 사용되기 전에 정규식으로 영문·숫자·일부 특수문자와 허용 확장자(txt, pdf)만 통과하도록 검증된다. `../`, `/` 등 경로조작 문자가 정규식상 허용되지 않으므로 상위 디렉토리 접근이 불가능하다.

---

### 문제 6. 운영체제 명령어 삽입

```java
String ip = request.getParameter("ip");
Process p = Runtime.getRuntime().exec("cmd /c ping " + ip);
```

진단도구 보고: 운영체제 명령어 삽입 (정탐/오탐?)

**정답: 정탐** 외부 입력 ip가 검증 없이 OS 명령어 문자열에 직접 연결되어 실행된다. `127.0.0.1 & del *.*`처럼 명령어 구분자를 포함한 입력으로 임의 명령 실행이 가능하다. (대응: IP 형식 정규식 검증, 명령어·인자 분리 실행)

---

### 문제 7. 하드코드된 중요정보

```java
private static final String DB_URL = "jdbc:mysql://10.0.0.5:3306/appdb";
private static final String DB_USER = "admin";
private static final String DB_PASS = "P@ssw0rd123!";
Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
```

진단도구 보고: 하드코드된 중요정보 (정탐/오탐?)

**정답: 정탐** DB 비밀번호가 소스코드에 상수 문자열로 하드코딩되어 있다. 소스·바이너리 유출 시 그대로 노출되며 변경 시 재배포가 필요하다. (대응: 암호화된 외부 설정파일 또는 비밀관리 시스템에 저장 후 로드)

---

### 문제 8. 적절하지 않은 난수 값 사용

```java
SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
byte[] token = new byte[32];
sr.nextBytes(token);
String authToken = Base64.getEncoder().encodeToString(token);
```

진단도구 보고: 적절하지 않은 난수 값 사용 (정탐/오탐?)

**정답: 오탐** 보안 목적(인증 토큰)의 난수 생성에 예측 가능한 java.util.Random이 아니라 암호학적 난수 생성기 SecureRandom을 사용한다. 시드도 임의 지정하지 않아 예측 불가능하므로 약점이 성립하지 않는다.

---

### 문제 9. 취약한 암호화 알고리즘

```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());
saveUserPassword(userId, toHex(hash));
```

진단도구 보고: 취약한 암호화 알고리즘 사용 (정탐/오탐?)

**정답: 정탐** 비밀번호 해쉬에 충돌 취약성이 알려진 MD5를 사용한다. 아울러 솔트 없이 해쉬만 저장하므로 레인보우 테이블 공격에도 취약하다(솔트 없이 일방향 해쉬 함수 사용과 복합). (대응: 솔트 적용 + SHA-256 이상 또는 PBKDF2/bcrypt 계열)

---

### 문제 10. Null Pointer 역참조

```java
String ver = request.getParameter("version");
if (ver != null && ver.equals("2.0")) {
    processV2();
} else {
    processV1();
}
```

진단도구 보고: Null Pointer 역참조 (정탐/오탐?)

**정답: 오탐** 외부 입력 ver를 사용(equals 호출)하기 전에 `ver != null` 검사를 수행하며, && 단락평가로 null인 경우 equals가 호출되지 않는다. 따라서 널 역참조가 발생할 수 없다.

---

### 문제 11. 부적절한 자원 해제

```java
FileInputStream fis = null;
try {
    fis = new FileInputStream(path);
    int data = fis.read();
    process(data);
    fis.close();
} catch (IOException e) {
    logger.error("file error");
}
```

진단도구 보고: 부적절한 자원 해제 (정탐/오탐?)

**정답: 정탐** close()가 try 블록 내부에만 있어, read()나 process()에서 예외가 발생하면 close()가 실행되지 않고 자원이 해제되지 않는다. (대응: finally 블록에서 null 검사 후 close, 또는 try-with-resources 사용)

---

### 문제 12. 오류 메시지 정보노출

```java
try {
    ...
} catch (SQLException e) {
    logger.error("DB 처리 오류", e);
    response.sendRedirect("/error.jsp");
}
```

진단도구 보고: 오류 메시지 정보노출 (정탐/오탐?)

**정답: 오탐** 예외의 상세정보(스택트레이스, SQL 정보)는 서버측 로그에만 기록하고, 사용자에게는 내부정보가 없는 일반 오류 페이지로 이동시킨다. 사용자 화면에 시스템 내부정보가 노출되지 않으므로 약점이 성립하지 않는다.

---

### 문제 13. 위험한 형식 파일 업로드

```java
String fileName = multipartFile.getOriginalFilename();
String ext = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
if (ext.equals("jsp") || ext.equals("php") || ext.equals("exe")) {
    throw new IllegalArgumentException("업로드 불가 파일");
}
multipartFile.transferTo(new File("/var/www/upload/" + fileName));
```

진단도구 보고: 위험한 형식 파일 업로드 (정탐/오탐?)

**정답: 정탐** 블랙리스트 방식이라 jspx, war, sh 등 목록 외 위험 확장자가 통과하며, 이중 확장자(shell.jsp.jpg → 서버 설정에 따라 실행) 우회도 가능하다. 저장 경로가 웹 루트(/var/www) 하위라 업로드 파일이 URL로 직접 실행될 수 있다. (대응: 화이트리스트 검증, 웹루트 외부 저장, 실행권한 제거, 파일명 난수화)

---

### 문제 14. CSRF

```jsp
<form action="/user/changePassword" method="post">
  <input type="hidden" name="csrfToken" value="<%= session.getAttribute("CSRF_TOKEN") %>">
  <input type="password" name="newPassword">
  <input type="submit">
</form>
```

서버측:

```java
String token = request.getParameter("csrfToken");
if (token == null || !token.equals(session.getAttribute("CSRF_TOKEN"))) {
    response.sendError(403); return;
}
changePassword(request.getParameter("newPassword"));
```

진단도구 보고: 크로스사이트 요청 위조 (정탐/오탐?)

**정답: 오탐** 중요기능(비밀번호 변경) 요청에 세션별 CSRF 토큰을 발급하고, 서버가 요청 파라미터의 토큰과 세션 저장 토큰의 일치를 검증한 뒤에만 기능을 수행한다. 공격자는 피해자 세션의 토큰 값을 알 수 없으므로 위조 요청이 차단된다.

---

### 문제 15. 종료되지 않는 반복문

```java
int retry = 0;
while (true) {
    boolean ok = connect(server);
    if (ok) break;
    retry++;
    if (retry >= 3) throw new ConnectException("연결 실패");
    Thread.sleep(1000);
}
```

진단도구 보고: 종료되지 않는 반복문 또는 재귀함수 (정탐/오탐?)

**정답: 오탐** while(true) 형태이지만 성공 시 break, 실패 시 retry 카운터가 3회에 도달하면 예외를 던져 루프를 탈출한다. 모든 경로에 종료조건이 존재하므로 무한루프가 성립하지 않는다.

---

### 복합서술형 대비 — 보완요청서·진단보고서 양식 (안내서 붙임2 공식 예시 기준)

복합서술형은 **요구사항 정의서 → 아키텍처 설계서 → 개발가이드(코드 포함)** 를 대조해 불일치·결함을 찾고 아래 양식으로 작성하는 문제입니다. 공식 예시의 채점 구조는 "문제 원인 4점 + 해결 방안 4점"이며, 원인에는 **어느 산출물의 어느 규칙과 어긋나는지**, 해결에는 **구체적 수정 내용(코드 수준)**이 키워드로 포함되어야 합니다.

**보완요청서 양식**

|항목|기재 내용|
|---|---|
|보안약점 (유형/한글명/설명)|예: 보안기능 / 2-3. 비밀번호 관리 / 생성규칙·저장방법·변경주기 등 정책별 안전한 적용방법 설계|
|보안 요구사항|검토 대상이 지켜야 할 규칙|
|현황 및 문제점|**문제 원인** — 어떤 산출물의 어떤 규칙("개발가이드 2.3.1 비밀번호 생성 규칙")과 코드가 어떻게 어긋나는지|
|해결 방안|**구체적 수정** — 예: "조건절을 `if (password.trim().length() < 8)`처럼 8자리 체크로 수정"|

**진단 보고서 양식**

|항목|기재 내용|
|---|---|
|진단대상|예: 회원정보 관리 프로세스 설계|
|분류|입력데이터 검증 및 표현 / 보안기능 / 에러처리 / 세션통제 중 체크|
|보안설계 기준|예: 2-3. 비밀번호 관리|
|진단결과|Y / N|
|현황 및 문제점|결함 위치·원인 (키워드 포함)|
|관련 산출물 / 증적자료|요구사항분석서, 유즈케이스명세서, 아키텍처정의서 등|
|개선방안|구체적 수정 방법|
|이행담당자 / 보완조치 내역|담당자명 / 조치 내용|

**연습 문제 16 (복합서술형).** 개발가이드에 "비밀번호는 3가지 유형 조합 시 8자 이상"이라 명시되어 있는데, 공통모듈 코드가 다음과 같다:

```java
if (password.trim().length() < 6) {
    return false;
}
```

보완요청서의 '현황 및 문제점'과 '해결 방안'을 작성하시오.

**모범답안 (공식 예시 기준)**

- 현황 및 문제점: 개발가이드 '비밀번호 생성 규칙'에서 **비밀번호 최소길이가 8자리**임에도 공통 모듈의 소스가 잘못되어 `if (password.trim().length() < 6)`으로 인해 **6자리도 통과**된다.
- 해결 방안: 공통모듈의 비밀번호 조건절을 `if (password.trim().length() < 8)`처럼 **8자리로 체크**하도록 수정한다.

---

### 서술 채점 셀프 체크리스트

- [ ] 정탐/오탐 결론을 명시했는가
- [ ] 근거가 되는 코드 위치(변수·라인·함수)를 지목했는가
- [ ] "외부 입력 → 검증 여부 → 사용처(싱크)" 흐름으로 설명했는가
- [ ] 정탐이면 대응방안까지, 오탐이면 왜 안전한지(방어 코드)까지 썼는가

---

# 제5장. 키워드 점검 문제 40제

> 공식 확인 사항: **이론시험은 2025년부터 전면 객관식(4~5지선다) 30문항·OMR**로 진행됩니다. 이 문제집은 객관식 문제를 흉내내는 것이 아니라, 선지를 가려낼 개념과 실습 서술에 쓸 키워드를 점검하는 훈련용입니다. 단답으로 즉답이 되면 객관식은 당연히 풀립니다. 또한 시험 중 'SW 보안약점 기준 명칭' 자료가 제공되고 기준 번호·명칭만 묻는 문제는 출제되지 않으므로(안내서 FAQ), A파트(개수·구조)는 출제 대비가 아니라 **머릿속 색인 구축용**입니다. 사용법: 답을 가리고 손으로 쓴 뒤 채점. 80% 미만이면 해당 영역 요약본 재학습. 정답은 문서 하단에 일괄 수록.

---

### A. 개수·구조 (1~8)

1. 설계단계 보안설계 기준의 4개 분야를 모두 쓰시오.
2. 설계단계 보안설계 기준의 분야별 항목 수(입력데이터 검증 및 표현 / 보안기능 / 에러처리 / 세션통제)를 쓰시오.
3. 구현단계 보안약점의 7개 유형을 순서대로 쓰시오.
4. 구현단계 보안약점의 유형별 개수를 쓰시오.
5. 2021년 개정 가이드에서 구현단계 보안약점은 총 몇 개인가? (2019년 개수도 함께)
6. 2021년 개정 시 신규 추가된 보안약점 6개를 쓰시오.
7. 2021년 개정 시 "XPath 삽입 + XQuery 삽입"이 통합된 항목명은?
8. 2021년 개정 시 "하드코딩된 비밀번호 + 하드코드된 암호화키"가 통합된 항목명은?

### B. 설계단계 (9~18)

9. 설계단계에서 SQL 삽입을 예방하기 위한 항목(SR1-1)의 명칭은?
10. CSRF 방지를 다루는 설계항목(SR1-6)의 명칭은?
11. "인증 반복시도 제한, 초과 시 잠금"을 요구하는 설계항목은?
12. 비밀번호 저장 시 요구되는 두 가지 보호기법은? (SR2-3 관련)
13. 업로드 파일 검증(SR1-10)에서 요구되는 조치를 3가지 이상 쓰시오.
14. 설계단계에서 "허용된 범위 내 메모리 접근"이 예방하고자 하는 대표 구현단계 보안약점 2개는?
15. 세션통제(SR4-1)의 요구사항을 3가지 쓰시오.
16. 중요정보 전송(SR2-8) 시 요구되는 보호조치는?
17. "쿠키·히든필드 등 보안결정에 사용되는 입력값은 서버측에서 검증"을 요구하는 설계항목은?
18. 예외처리(SR3-1)에서 오류 메시지에 포함되면 안 되는 정보의 예를 3가지 쓰시오.

### C. 구현단계 정의 매칭 (19~32)

19. 외부 입력이 동적 SQL 질의문 생성에 검증 없이 사용되어 질의 구조가 변경되는 보안약점은?
20. 서버가 외부 입력으로 지정된 임의의 내부·외부 서버로 요청을 보내게 되는 보안약점은?
21. 검사 시점(Time-Of-Check)과 사용 시점(Time-Of-Use)의 불일치로 발생하는 보안약점은?
22. 외부 입력이 HTTP 응답 헤더에 CR/LF 문자와 함께 삽입되어 응답이 분리되는 보안약점은?
23. `java.util.Random`을 인증 토큰 생성에 사용했을 때 해당하는 보안약점은?
24. DTD/외부 엔티티 처리를 비활성화하지 않아 발생하는 보안약점은?
25. 세션 간 데이터가 싱글톤 객체의 멤버변수를 통해 공유되어 노출되는 보안약점(캡슐화 유형)은?
26. `strcpy`, `gets` 등 안전하지 않은 함수 사용에 해당하는 보안약점(API 오용 유형)은?
27. 도메인 이름 확인 결과만으로 인증·인가를 결정할 때 발생하는 보안약점은?
28. 직렬화된 외부 데이터를 검증 없이 객체로 복원할 때 발생하는 보안약점은?
29. 배포된 소스의 주석에 관리자 계정 정보가 남아 있을 때 해당하는 보안약점은?
30. Public 메소드가 private 배열의 참조를 그대로 반환할 때 발생하는 보안약점은?
31. 오류 발생 시 사용자 화면에 스택트레이스가 출력될 때 해당하는 보안약점은?
32. catch 블록이 비어 있어 오류 발생 시 아무 처리도 하지 않는 경우 해당하는 보안약점은?

### D. 대응책·판단 기준 (33~40)

33. SQL 삽입의 가장 대표적인 대응 기법은?
34. XSS 방지를 위한 출력값 처리에서 가장 먼저 치환해야 하는 문자는?
35. 파일 업로드 검증에서 블랙리스트 방식 대신 사용해야 하는 방식은?
36. 패스워드 일방향 해쉬 저장 시 레인보우 테이블 공격을 막기 위해 추가하는 값은?
37. 국내 사용 권고 대칭키 알고리즘 3개와 비대칭키 알고리즘 2개, 각각의 안전한 키 길이를 쓰시오.
38. 자원 해제를 보장하기 위해 close()를 위치시켜야 하는 블록은? (Java 7 이후의 대안 구문도)
39. CSRF 대응책을 2가지 이상 쓰시오.
40. 무한루프 보안약점을 예방하는 코딩 기법 2가지를 쓰시오.

---

## 정답

**A.**

1. 입력데이터 검증 및 표현, 보안기능, 에러처리(예외처리), 세션통제
2. 10 / 8 / 1 / 1 (총 20개)
3. 입력데이터 검증 및 표현 → 보안기능 → 시간 및 상태 → 에러처리 → 코드오류 → 캡슐화 → API 오용
4. 17 / 16 / 2 / 3 / 5 / 4 / 2 (총 49개)
5. 49개 (2019년은 47개)
6. 코드 삽입, 부적절한 XML 외부개체 참조(XXE), 서버사이드 요청 위조(SSRF), 부적절한 전자서명 확인, 부적절한 인증서 유효성 검증, 신뢰할 수 없는 데이터의 역직렬화
7. XML 삽입
8. 하드코드된 중요정보

**B.** 9. DBMS 조회 및 결과 검증 10. 웹 기반 중요기능 수행 요청 유효성 검증 11. 인증 수행 제한 (SR2-2) 12. 랜덤 솔트(salt) + 일방향 해쉬(안전한 해쉬 알고리즘) 13. 확장자 화이트리스트 검증, 파일 크기·개수 제한, 웹루트 외부 저장(경로 분리), 실행권한 제거, 파일명 난수화 (중 3개) 14. 메모리 버퍼 오버플로우, 포맷 스트링 삽입 (정수형 오버플로우도 인정 가능) 15. 세션 타임아웃 설정, 재로그인 시 세션ID 재발급(예측 불가 세션ID), 중복 로그인 통제 16. 중요정보 암호화 전송 또는 암호화된 통신채널(TLS/SSL) 사용 17. 보안기능 동작에 사용되는 입력값 검증 (SR1-9) 18. 스택트레이스, SQL 질의문/DB 정보, 시스템 내부 경로(서버 설정·버전 정보 등)

**C.** 19. SQL 삽입 20. 서버사이드 요청 위조(SSRF) 21. 경쟁조건: 검사시점과 사용시점(TOCTOU) 22. HTTP 응답분할 23. 적절하지 않은 난수 값 사용 24. 부적절한 XML 외부개체 참조(XXE) 25. 잘못된 세션에 의한 데이터 정보노출 26. 취약한 API 사용 27. DNS lookup에 의존한 보안결정 28. 신뢰할 수 없는 데이터의 역직렬화 29. 주석문 안에 포함된 시스템 주요정보 30. Public 메소드로부터 반환된 Private 배열 31. 오류 메시지 정보노출 32. 오류상황 대응 부재 ※ 25번 유사 개념 구분: 멤버변수 공유는 캡슐화 유형, 영속 쿠키 저장은 보안기능 유형(쿠키를 통한 정보노출)

**D.** 33. Prepared Statement(바인딩 변수) 사용 34. `&` (앰퍼샌드) — 이후 `<`, `>`, `"`, `'` 순 35. 화이트리스트(허용 목록) 방식 36. 솔트(salt) 37. 대칭키: SEED, ARIA, AES (그 외 Blowfish, Camellia, MISTY1, KASUMI) — 128bit 이상 / 비대칭키: RSA, ECC (그 외 KCDSA, RSAES-OAEP, ElGamal) — 2048bit 이상 (안내서 붙임2 공식 답안 기준. 참고: MD5·SHA-1·DES는 취약 알고리즘, 해쉬는 SHA2 이상+솔트) 38. finally 블록 (대안: try-with-resources) 39. CSRF 토큰 검증, 중요기능 재인증, Referer 검증 (중 2개) 40. 루프 종료조건 명시(최대 반복횟수 설정), 재귀함수 종료조건·깊이 제한 설정