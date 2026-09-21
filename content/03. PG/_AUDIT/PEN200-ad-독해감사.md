---
tags:
  - type/audit
  - platform/pen200
type: audit
platform: pen200
manual_tags: true
manual_cves: true
---

# PEN-200 Active Directory 구간 — 적대적 독해 감사 (총괄)

대상 — `read_A.json` 42개 절 (챕터 22 열거 · 23 인증 공격 · 24 측면 이동), 원문 약 24.8만 자.
방식 — 원문 `src\*.md` 전문 ↔ 노트 `05. PEN-200\*.md` 전문 대조. 코드펜스는 기계 게이트 통과분이라 대조·수정 대상에서 제외.

실무 분담 — G1(22~22.3.4, 13절) · G2(22.3.5~23.2.1 + 24.2 지속성, 16절) · G3(23.2.2~24.1.6, 13절).
그룹별 상세는 `PEN200-ad-독해감사-G1.md` · `-G2.md` · `-G3.md`.

## 결함과 정정 — 전 25건

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 22 | 창작 | 원문은 `system administrators often customize it to fit the needs of the organization` 까지만 말함. `attack surface` 는 §22 에 없고 §22.1 에서 **정보량**에 붙은 표현임 | 「그 커스터마이즈가 곧 공격면이 됨」 → 「환경마다 구성이 다름」 |
| 22.1 | 창작 | `Since the DC is such a central domain component, we'll pay close attention to it as we enumerate AD` | 「가장 먼저·가장 오래 들여다보게 됨」 → 「AD 를 열거하는 내내 주의 깊게 들여다보게 됨」 |
| 22.1.1 | 오역(강도) | `the target organization **may have** provided us with user credentials` | 「경우도 많음」 → 「경우도 있음」 |
| 22.1.1 | 오역(강도) | `which is something we **may need to** take into consideration as we move along` | 「이후 작업에서 계속 걸리는 제약」 → 「감안해야 할 수 있는 제약임」 |
| 22.2.1 | 오역(강도) | `you **may** no longer be able to run domain enumeration tools` | 「도메인 열거 도구가 돌지 않음」 → 「더는 못 돌리게 될 수 있음」 |
| 22.2.1 | 창작 | Listing 771 의 실제 그룹명은 `Development Department`·`Management Department` | 축약된 「`Development`·`Management`」 → 전체 이름으로 정정 |
| 22.2.3 | 창작 | `admincount`·`useraccountcontrol`·`pwdlastset` 은 원문 **코드블록 안에만** 존재하고 산문에 설명이 없음. 특히 「계정 활성 여부 판단에 쓰는」은 근거 없음 | 속성 의미 부여 목록을 삭제하고 블록에서 실제로 읽히는 `memberof` 만 남김 |
| 22.2.3 | 과잉압축 | `an Object Class, which is a component of AD that defines the object type` | 객체 클래스 정의(「객체의 유형을 정의하는 AD 구성 요소」) 복원 |
| 22.2.3 | 용어 흔들림 | 같은 현상(PDF 줄접힘)을 두 콜아웃이 「교재 조판」/「PDF 추출 과정」으로 달리 부름 | 「교재 조판에서」로 통일 |
| 22.2.4 | 과잉압축+창작 | `if a user is dormant (they have **not changed their password or logged in** recently) we will cause **less interference and draw less attention**` | 휴면 정의에서 빠진 「비밀번호 미변경」 복원, 원문에 없는 행위자(「사용자 본인이 눈치챔」) 제거 |
| 22.2.4 | 용어 흔들림 | §22.1 이 `객체(object)` 로 병기 확정 | 「사용자 오브젝트」 → 「사용자 객체」 |
| 22.3 | 창작 | `Visualizing the environment can make it easier to find potential attack vectors` — 「나열만으로는 안 보인다」는 원문에 없음 | 원문대로 「환경을 시각화하면 잠재적 공격 경로를 찾기가 쉬워지기 때문임」 |
| 22.3 / 22.3.1 | 용어 흔들림 | 위와 동일 | 본문 오브젝트 → 객체 (22.3 3건, 22.3.1 2건) |
| 22.3.2 | 오역 | `system administrators notice suspicious activity and **disable** the account` — AD 에서 계정 **잠금**(lockout)과 **비활성화**(disable)는 별개 개념임 | 「계정을 잠가도」 → 「계정을 비활성화해도」 |
| 22.3.2 | 오역(예시→근거) | `**For example**, when a user logs in to the domain, their credentials are cached` — 캐싱은 한 예지 유일한 이유가 아님 | 「관계가 핵심인 이유는 캐싱 때문임」 → 「핵심 역할을 하는 대표 예가 캐싱임」 |
| 22.3.2 | 과잉압축 | `**due to permissions**, we can be certain that NetSessionEnum will not be able to obtain this type of information on default Windows 11` | 「원리적으로」(인과 소실) → 「이 권한 구성 때문에 … 못 가져오는 것이 확실함」 |
| 22.3.2 | 교재 오류 표시 오류 | 원문 109행은 `This may be a **false positive**`. 노트가 이를 「거짓 음성」으로 **말없이 뒤집음** — 판정은 옳으나 표시가 없어 교재 대조 시 혼선 | 본문을 「결과가 틀렸을 가능성」으로 중립화하고 `⚠️ 교재 표현` 콜아웃으로 교재의 `false positive` 와 실제로는 false negative 임을 함께 명시 |
| 22.3.2 | 창작 | 「이름으로 보아 도메인 관리자까지 이어질 수 있음」 — `jeffadmin` 의 `Domain Admins` 소속은 §22.2.1 Listing 770 에서 **이미 확인된 사실**. 원문도 `If our enumeration is accurate and we **in fact** have administrative privileges` 로 조건을 검 | 근거를 §22.2.1 실측으로 바꾸고 원문의 조건절 복원 |
| 22.3.4 | 창작 | 원문의 `comes as **no surprise**` 는 **`Domain Admins` 한 건에만** 붙음(원문 1회). 나머지 셋을 「당연함」에 묶은 것은 근거 없음 | `Domain Admins` 만 원문 근거와 함께 남기고 나머지 셋은 `[가정]` 강등 |
| 22.3.4 | 오역(강도) | `so this **may be** a misconfiguration` | 「오설정으로 판단해야 하고」 → 「오설정일 가능성이 높고」 |
| 22.3.4 | 과잉압축 | `often the go-to vectors for attackers **since it can often help us escalate our privileges within the domain**` | 「왜」(도메인 내 권한 상승으로 이어짐) 복원 |
| 22.3.4 | 용어 흔들림 | 위와 동일 | 본문 오브젝트 → 객체 (11건). H1·파일명은 미수정 |
| 22.3.5 | 창작 | Listing 834 의 FILES04 공유 8개 중 `C`·`Windows` 는 Remark 공백·Type 0 으로 노트가 이미 비기본으로 분류한 `docshare`·`Tools`·`Users` 와 **같은 서명**. 원문은 기본/비기본을 열거하지 않음 — 목록 자체가 노트 창작이고 그 안에서 둘이 누락됨 | 비기본 공유 목록에 `C`·`Windows` 추가 |
| 24.1.1 | 오역(적용 범위 드리프트) | 원문 146행 `**For WinRS to work**, the domain user needs to be part of the Administrators or Remote Management Users group` · `Since **winrs** only works for domain users` — 조건의 주어가 `winrs` 유틸리티임 | WinRM 전체의 조건처럼 적힌 불릿을 `winrs` 로 한정. 빠져 있던 「winrs 는 도메인 사용자에게만 동작」과 「WinRM 은 PowerShell 구현 외 다수 내장 유틸리티로 구현됨」 복원 |
| 24.1.1 | 창작(인과 날조) | 원문에 WinRS 셸 시작 디렉터리가 `C:\Users\jen` 인 **이유는 없음**. 두 경로 모두 `corp\jen` 컨텍스트로 도는 것이 노트 코드블록에 보여 「사용자 컨텍스트」는 차이의 원인이 될 수 없음 | 「WinRS 는 사용자 컨텍스트에서 직접 실행되기 때문임」 삭제, 관측만 남기고 원인 추정은 `[가정]` 강등. **삭제 원문**: 「리스너에 붙은 셸은 WMI 경로와 달리 `C:\Users\jen` 에서 시작함 — WinRS 는 사용자 컨텍스트에서 직접 실행되기 때문임.」 |
| 24.1.1 | 창작(근거 없는 부재 단정) | 원문 18행 `If we were logged in on that machine and monitoring **Task Manager, we would see the win32calc.exe process appear** with jen as the user` — 프로세스 목록에는 «보임» | 「대화형 화면에는 안 보임」을 「대화형 데스크톱에 창이 뜨지 않음 / 작업 관리자 프로세스 목록에서는 확인 가능」으로 분리 |

## 무결 판정 — 30개 절 (수정된 절은 12개)

22.2 · 22.2.2 · 22.3.3 · 22.4 · 22.4.1 · 22.4.2 · 22.5 · 23 · 23.1 · 23.1.1 · 23.1.2 · 23.1.3 · 23.2 · 23.2.1 · 24.2 · 24.2.1 · 24.2.2 · 23.2.2 · 23.2.3 · 23.2.4 · 23.2.5 · 23.3 · 24 · 24.1 · 24.1.2 · 24.1.3 · 24.1.4 · 24.1.5 · 24.1.6 · 24.3

## 관리자 직접 대조분 — 실무자 판정을 그대로 받지 않은 것

「이상 없음」 보고는 읽는 사람이 이미 아는 내용일수록 그냥 통과되기 쉬워, 고위험 항목은 관리자가 원문을 따로 떠서 되짚음.

| 항목 | 원문 근거 | 결과 |
|---|---|---|
| **23.1.1 NTLM 단계 수와 주체** | `src\23.1.1` 1행 `The NTLM authentication protocol consists of **seven steps**` | 노트 「일곱 단계」. ①해시 계산 ②클라이언트→서버 사용자명 ③서버→클라이언트 nonce ④클라이언트→서버 response ⑤서버→DC 전달 ⑥DC 검증 ⑦일치 시 성공 — **7단계 전부 주체·방향 일치.** 「6단계」 오염 없음 |
| **24.1.3 PtH 전제·제약** | `src\24.1.3` 1·18행 | SMB 445 · File and Printer Sharing · `ADMIN$` 3전제, NTLM 전용(Kerberos 불가), Service Control Manager API + Named Pipe, 2014 보안 업데이트로 빌트인 로컬 Administrator 외 로컬 관리자 불가 — **전부 일치** |
| **24.1.1 교재 오류 표시** | `src\24.1.1` 1행 `(19152-65535)` | 교재 오식 실재. 정정값 `49152-65535` 정확 |
| **24.2.2 교재 오류 표시** | `src\24.2.2` 66~81행 해시 줄 끝 `</div>` | 지면 잔여물 실재. 표시 정확 |
| **22.2.3 창작 판정(삭제 동반)** | 파서로 산문/코드펜스 분리 검사 | `admincount`·`useraccountcontrol`·`pwdlastset` 이 **산문에 0회, 코드블록에만 존재**함을 확인. 삭제 타당 |
| **22.3.2 교재 표현 판정** | `src\22.3.2` 109행 | `false positive` 실재. 노트의 무표시 반전을 콜아웃으로 바꾼 처리 타당 |
| **24.1.1 winrs 범위 정정** | `src\24.1.1` 146행 | `For WinRS to work` · `Since winrs only works for domain users` 실재. 범위 한정 타당 |
| **누락된 교재 오류 유무** | ch22~24 원문 전수 검색 | HTML 잔여물이 나오는 절은 `23.2.5`·`24.2.2` 둘뿐. `23.2.5` 는 노트가 이미 경고 콜아웃으로 정확히 처리 중. **누락 없음** |

## 실무자가 스스로 반증해 철회한 지적 — 7건

원문에 근거가 실재해 창작이 아니었던 것들. 되살리지 말 것.

- `24.1.4` 「IP 로 지정하면 NTLM 강제돼 티켓 무시」 — 24.1.4 원문엔 없으나 `src\24.2.1` 134행에 원문 그대로 있음. 교차 참조가 정확
- `24.1.1` session 0 서술 — `src\24.1.1` 18행 Info 블록에 실재
- `24.2.1` `/ptt` 설명 — 원문 산문엔 없으나 Listing 918 출력의 `** Pass The Ticket **`·`submitted for current session` 에서 직접 읽힘
- 「PDF 줄 접힘」 주석 3건(`--`/`continue-on-success`, `-`/`OutputDirectory`, `kerberos::golden` 패스워드 인자) — 지목한 접힘이 원문 블록에 전부 실재
- `23.2.4` PAC 검증 — 노트가 「**선택적** 절차 … 실제로 하는 경우가 드묾」으로 적어 원문 `optional`/`rarely` 와 정확히 일치. 「기본 비활성」 과장 없음
- `24.1.1`·`24.1.4` 그림 누락(`PEN200-Fig-311/312`) — `SPEC.md` §4 가 「빼는 것이 기본」으로 규정. 규격상 정상
- `22.3.3` 「호스트명과 포트」 — 원문은 `IP address and port`. SPN 문자열에 실제로 들어 있는 것은 호스트명이고 IP 는 그다음 `nslookup` 으로 얻으므로 노트 쪽이 정확. 차이만 기록하고 유지

## 총괄에 올린 것 — 담당 범위 밖이라 손대지 않음

- **`오브젝트` vs `객체`** — §22.1 이 `객체(object)` 로 병기를 확정했고 볼트 비율도 객체 44 : 오브젝트 18 이라 본문은 객체로 통일함. 다만 `22.3.4` 의 **파일명·H1 이 「오브젝트 권한 열거」**로 남아 있고 이는 `titles_ko.json` 소관이라 미수정
- **`자격 증명` vs `자격증명` 띄어쓰기** — 절마다 갈림(23.1.3·23.2.1·23 은 띄고, 22.3.5·22.4.2·24.2 는 붙임). `23.1.3` H1 이 `titles_ko.json` 확정분이라 절별 강제가 있음. 495개 전체 단위 결정 사안

## 게이트 재검 — 관리자 직접 실행, 범위 `22 24`

```
strictcheck.py  노트 코드블록 159개 검사 · 줄 단위 비정렬 0개
audit2.py       원문 159 / 노트 159 · 합성 0개 · 소실 0개 · 거짓 「추출 손상」 서술 0건
covercheck.py   판정 근거 줄 53개 검사 · 소실 0개
verify.py       완료 42 / 전체 42 · 미생성 0 · 결함 0
```

산문만 수정했고 코드펜스는 한 글자도 건드리지 않음. 분량 비율은 감사 전 0.264~0.452 구간이었고 상한 0.60 까지 여유가 커 산문 복원이 비율을 밀어내지 않음. **회귀 0.**
