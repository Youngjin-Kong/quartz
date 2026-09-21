---
tags:
  - type/audit
  - platform/pen200
type: audit
platform: pen200
manual_tags: true
manual_cves: true
---

# PEN-200 챕터 22 AD 열거 구간 — 적대적 독해 감사 (G1)

담당 13개 절 — 22, 22.1, 22.1.1, 22.2, 22.2.1, 22.2.2, 22.2.3, 22.2.4, 22.3, 22.3.1, 22.3.2, 22.3.3, 22.3.4.
원문 전문 ↔ 노트 전문 대조. 코드펜스는 대조·수정 대상에서 제외(게이트 통과분).

## 무결 판정

**22.2, 22.2.2, 22.3.3** — 결함 없음.

## 결함과 정정

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 22 | 창작 | §22 원문은 `system administrators often customize it to fit the needs of the organization` 까지만 말함. `attack surface` 는 §22 에 없고 §22.1 에서 **정보량**에 붙은 표현임(grep 확인) | 「그 커스터마이즈가 곧 공격면이 됨」 → 「환경마다 구성이 다름」 |
| 22.1 | 창작 | `Since the DC is such a central domain component, we'll pay close attention to it as we enumerate AD` | 「가장 먼저·가장 오래 들여다보게 됨」 → 「AD 를 열거하는 내내 주의 깊게 들여다보게 됨」 |
| 22.1.1 | 오역(강도) | `the target organization **may have** provided us with user credentials` | 「경우도 많음」 → 「경우도 있음」 |
| 22.1.1 | 오역(강도) | `which is something we **may need to** take into consideration as we move along` | 「이후 작업에서 계속 걸리는 제약이라 처음부터 감안해야 함」 → 「감안해야 할 수 있는 제약임」 |
| 22.2.1 | 오역(강도) | `you **may** no longer be able to run domain enumeration tools` | 「도메인 열거 도구가 돌지 않음」 → 「더는 못 돌리게 될 수 있음」 |
| 22.2.1 | 창작(그룹명) | Listing 771 의 실제 그룹명은 `Development Department`·`Management Department` 임 | 「`Development`·`Management`」 → 전체 이름으로 정정 |
| 22.2.3 | 창작 | 원문은 Listing 790 앞에서 `The Listing below shows a partial view of jeffadmin's attributes` 만 말함. `admincount`·`useraccountcontrol`·`pwdlastset` 은 **코드블록 안에만** 존재(grep: 128·141·149행 전부 블록 내부) — 특히 「계정 활성 여부 판단에 쓰는」은 원문에 근거 없음 | 속성 의미 부여 목록을 삭제하고 블록에서 실제로 읽히는 `memberof` 만 남김 |
| 22.2.3 | 과잉압축 | `an Object Class, which is a component of AD that defines the object type` | 객체 클래스 정의(「객체의 유형을 정의하는 AD 구성 요소」)를 복원 |
| 22.2.3 | 용어 흔들림 | 같은 현상(PDF 줄접힘)을 두 콜아웃이 「교재 조판」/「PDF 추출 과정」으로 달리 부름 | 「교재 조판에서」로 통일 |
| 22.2.4 | 과잉압축+창작 | `if a user is dormant (they have **not changed their password or logged in** recently) we will cause **less interference and draw less attention**` | 휴면 정의에서 빠진 「비밀번호 미변경」 복원, 원문에 없는 행위자(「사용자 본인이 눈치챔」) 제거 |
| 22.2.4 | 용어 흔들림 | §22.1 이 `객체(object)` 로 병기 확정 | 「사용자 오브젝트」 → 「사용자 객체」 |
| 22.3 | 창작 | `Visualizing the environment can make it easier to find potential attack vectors` — 「나열만으로는 안 보인다」는 원문에 없음 | 「개별 오브젝트를 나열하는 것만으로는 …」 → 원문대로 「환경을 시각화하면 잠재적 공격 경로를 찾기가 쉬워지기 때문임」 |
| 22.3 / 22.3.1 | 용어 흔들림 | 위와 동일 | 본문 오브젝트 → 객체 (22.3 3건, 22.3.1 2건) |
| 22.3.2 | 오역 | `system administrators notice suspicious activity and **disable** the account` — AD 에서 계정 **잠금**(lockout)과 **비활성화**(disable)는 별개 개념임 | 「계정을 잠가도」 → 「계정을 비활성화해도」 |
| 22.3.2 | 오역(예시→근거) | `**For example**, when a user logs in to the domain, their credentials are cached` — 캐싱은 관계가 중요한 «한 예»지 유일한 이유가 아님 | 「관계가 공격의 핵심인 이유는 캐싱 때문임」 → 「핵심 역할을 하는 대표 예가 캐싱임」 |
| 22.3.2 | 과잉압축 | `**due to permissions**, we can be certain that NetSessionEnum will not be able to obtain this type of information on default Windows 11` | 「원리적으로」(인과 소실) → 「이 권한 구성 때문에 … 못 가져오는 것이 확실함」 |
| 22.3.2 | 교재 오류 표시 오류 | 원문 109행은 `This may be a **false positive**` 라고 적음. 노트는 이를 「거짓 음성」으로 **말없이 뒤집어** 놓았음 — 판정은 옳으나 표시가 없어 교재 대조 시 혼선 | 본문은 「결과가 틀렸을 가능성」으로 중립화하고, `⚠️ 교재 표현` 콜아웃으로 교재의 `false positive` 와 실제로는 false negative 라는 점을 함께 명시 |
| 22.3.2 | 창작 | 「이름으로 보아 도메인 관리자까지 이어질 수 있음」 — `jeffadmin` 의 `Domain Admins` 소속은 §22.2.1 Listing 770 에서 **이미 확인된 사실**이지 이름 추정이 아님. 원문도 `If our enumeration is accurate and we **in fact** have administrative privileges` 로 조건을 검 | 근거를 §22.2.1 실측으로 바꾸고 원문의 조건절(열거가 정확하다면) 복원 |
| 22.3.4 | 창작 | 원문의 `comes as **no surprise**` 는 **`Domain Admins` 한 건에만** 붙음(grep: `no surprise` 1회). 나머지 셋을 「당연함」에 묶은 것은 원문에 없음 | `Domain Admins` 만 원문 근거(도메인 최고 권한)와 함께 남기고, 나머지 셋은 `[가정]` 으로 강등 |
| 22.3.4 | 오역(강도) | `so this **may be** a misconfiguration` | 「오설정으로 판단해야 하고」 → 「오설정일 가능성이 높고」 |
| 22.3.4 | 과잉압축 | `often the go-to vectors for attackers **since it can often help us escalate our privileges within the domain**` | 「왜」(도메인 내 권한 상승으로 이어짐)를 복원 |
| 22.3.4 | 용어 흔들림 | 위와 동일 | 본문 오브젝트 → 객체 (11건). **H1·파일명은 손대지 않음** |

## 검토했으나 정정하지 않은 것

- **22.3.3 「호스트명과 포트」** — 원문 1행은 `We can obtain the **IP address** and port number of applications`. 노트는 「호스트명과 포트」로 적음. SPN 문자열에 실제로 들어 있는 것은 호스트명이고 IP 는 그다음 `nslookup` 으로 얻으므로 노트 쪽이 정확하며, 노트가 곧바로 `nslookup` 단계를 서술해 독자가 오독할 여지가 없음. **원문과의 차이만 기록하고 유지.**
- **22.2.2 「교재 조판 줄접힘」 콜아웃** — `$PDC =` / `...PdcRoleOwner.Nam` / `e` 3행 분할은 실제 PDF 줄바꿈이 맞고, 그대로 입력하면 동작하지 않는다는 판정도 옳음. 유지.
- **22.3.4 권한 이름 대응** — `GenericAll`·`GenericWrite`·`WriteOwner`·`WriteDACL`·`AllExtendedRights`·`ForceChangePassword`·`Self` 는 코드펜스 안 원문 그대로이고 뒤집힌 대응 없음. (지시에 언급된 `WriteProperty` 는 **이 절 원문에 없음** — Listing 824 의 7종에 포함되지 않음.)
- **22.2.2 / 22.2.3 LDAP·ADSI 흐름** — `DirectoryEntry`(LDAP 경로 캡슐화) → `DirectorySearcher`(`SearchRoot` 로 시작 지점 지정) → `FindAll()`(전체 컬렉션 반환)의 주체·순서가 원문과 일치. 뒤바뀜 없음.
- **22.3.2 `Get-NetSession` 실패 원인** — 질의 레벨 0/1/2/10/502 구분, PowerView 기본 레벨 10, `SrvsvcSessionInfo` 권한이 `LanmanServer\DefaultSecurity` 하이브에 정의됨, 빌드 1709 / Server 2019 1809 전후 변경 — 전부 원문과 일치. 뒤집힘·소실 없음.
- **`net` 명령 한계 조건** — `/domain` 유무에 따른 로컬/도메인 구분, `net.exe` 가 그룹 객체와 개별 속성을 못 보여줌 — 원문과 일치.

## 게이트 재검 (챕터 22 전체 18개 절)

```
strictcheck.py  노트 코드블록 82개 검사 · 줄 단위 비정렬 0개
audit2.py       합성 0개 · 소실 0개 · 거짓 「추출 손상」 서술 0건
covercheck.py   판정 근거 줄 5개 검사 · 소실 0개
verify.py       완료 18 / 전체 18 · 미생성 0 · 결함 0
```

산문만 수정했고 코드펜스는 한 글자도 건드리지 않음. 회귀 없음.
