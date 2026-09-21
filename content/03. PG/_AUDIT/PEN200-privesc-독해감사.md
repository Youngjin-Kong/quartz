---
tags:
  - type/audit
  - platform/pen200
type: audit
platform: pen200
manual_tags: true
manual_cves: true
---

# PEN-200 권한 상승 구간 — 적대적 독해 감사

대상 — `05. PEN-200\` 의 **챕터 17(Windows 권한 상승)·18(Linux 권한 상승) 31개 절**, 원문 약 22.2만 자.
기준 — `READ-AUDIT.md`(결함 6종·판정 규율) · `SPEC.md`(작성 표준).
성격 — 기계 게이트 넷이 못 보는 **번역 「내용」의 정확성**을 사람이 원문과 나란히 읽어 잡는 작업.

## 결론

- **31개 절 전량 대조 완료.** 각 절이 **두 번 독립 대조됨**(웨이브 중복 파견 — 아래 §운영 참조)
- **확정 결함 24건 수정**(전부 산문). 코드펜스 **0바이트 변경**
- **자진 철회 지적 다수** — 원문으로 되짚어 「틀리지 않았음」이 확인된 것은 고치지 않음
- 게이트 넷 `17 18` 재실행 **전부 통과**, 분량 비율 0.158~0.498 (밴드 0.15~0.60 내)

## 배치 구성

| 배치 | 범위 | 절 수 | 원문 분량 |
|---|---|---|---|
| A | 17 · 17.1 · 17.1.1~17.1.5 · 17.2 (Windows 열거) | 8 | 67.4k |
| B | 17.2.1~17.2.3 · 17.3 · 17.3.1~17.3.2 · 17.4 (서비스·기타 악용) | 7 | 72.7k |
| C | 18 전체 (Linux 권한 상승) | 16 | 82.4k |

## 관리자 교차검증 — 직접 확인한 것

부하 보고를 그대로 싣지 않고 아래는 관리자가 원문으로 되짚음.

| 확인 항목 | 방법 | 결과 |
|---|---|---|
| **표본 정밀 대조 — 17.2.2 DLL 하이재킹** | 원문 산문 전문 + 노트 전문을 직접 통독 대조 | **무결.** 검색 순서(앱 디렉터리 1순위 · 현재 디렉터리 5순위 · safe 모드 해제 시 2순위), 「DLL 은 애플리케이션을 실행한 사용자 권한으로 돈다」, `NAME NOT FOUND`→System32, `DllMain`/`DLL_PROCESS_ATTACH`, `--shared`, dave3 — 전부 원문과 일치 |
| **「창작」 판정 3건 되짚기** | 원문 전체 검색으로 부재 확인 | **전부 정탐.** ①17.2.3 — 실패 원인 서술은 `line 150`(앞 리스팅)에만 있고 `Restart-Service`(`line 193+`)에는 없음 ②17.3.2 — 원문은 `whoami /priv` 를 커널 익스플로잇 예시의 «도입»으로 배치, 「권한 경로가 닫혀서 커널로 간다」는 인과 없음 ③18.3.1 — `>>` 에 이유를 붙인 서술이 원문에 없음(`detect`/`notice`/`suspicio` 전무) |
| **`자격 증명` 표기 변경** | 볼트 `05. PEN-200\` 전수 집계 | **정당.** 볼트 전체 `자격 증명` 264 / `자격증명` 0 — 변경이 볼트 표준에 «맞춘» 것 |
| **`상황 파악` vs `상황 인식`** | ch17~18 전수 + 볼트 대조 | **17.4 가 outlier.** 「상황 파악」이 절 제목(17.1.2)이자 첫 병기 형태(17.1)이고 8회 사용, 27.4.1 절 제목도 동일. **관리자가 17.4 1건 직접 통일** |
| **`특권` 잔존 1건** | ch17~18 + 볼트 대조 | **결함 아님.** 17.3.2 의 것은 「비특권 사용자」라는 관용 복합어이고 볼트 14개 파일이 같은 용법 |
| **`scheduled tasks` 통일 방향** | ch17 전수 + 볼트 대조 | ⚠️ **실무자 판정이 틀렸음.** 배치 A 가 「예약 작업」→「스케줄 작업」으로 통일했으나, **절 제목이 「예약 작업」**(17.3.1)이고 17.3·17.4 도 같으며 볼트 집계도 예약 7 : 스케줄 3. **관리자가 반대 방향으로 되돌려 3건 통일**(17 · 17.1.3 · 17.1.5) |

⚠️ **관리자 자신의 오류 1건** — 17.2.2 의 `KeePass 2.51.1` 캡션을 창작으로 의심했으나, `grep ... | head -5` 가 결과를 잘라 부재로 오독한 것이었음. 원문 블록에 `KeePass Password Safe 2.51.1` 이 실재함. **부재 증거로 창작을 단정하기 직전이었고, 블록을 직접 열어 반증함.**

## 총괄 판단이 필요한 것

1. **`privilege` 와 `permission` 이 둘 다 「권한」으로 수렴함.** 담당 구간에서는 충돌 지점을 「권한(privilege)」 / 「접근 권한(permission)」으로 갈라 해소했으나, **볼트 전 장에 파급되는 사안**이라 전역 통일은 총괄 판정 사항.
2. **코드펜스 소실 1건(수정 금지라 보고만)** — `17.2.3` 이 원문 Listing 493 을 두 블록으로 나눠 실으면서 그 사이 `Restart-Service GammaService` 실행줄과 오류 출력이 빠짐. SPEC §3-D 「프롬프트 붙은 실행 줄 보존」에 저촉되나 `covercheck` 는 통과. **완화 요인** — 노트 산문이 그 명령을 인라인 코드로 그대로 싣고 있어 시험장에서 명령 자체는 확보됨.
3. **코드펜스 절단 4건(보고만)** — `17.1.2` `route print`(라우팅 테이블 전문이 명령 2줄만 남고 절단, 산문은 그 앞에서 판정을 서술), `17.1.5` 3건(`Basic System Information` 이 `HighIntegrity`·`PartOfDomain` 앞에서, `Users` 가 `steve` 항목 앞에서 절단). 넷 다 해당 절 서술이 의존하는 줄은 아님.

## 운영 — 웨이브 중복 파견

1차 웨이브 3건을 백그라운드로 띄운 뒤 턴이 끊겼고, 유실로 판단해 2차를 파견함. **1차는 살아 있었고 양쪽이 모두 완주함.** 결과적으로 31개 절이 전부 두 번 독립 대조됐고, 2차가 1차 판정을 재검토해 **추가 결함 4건과 1차 오판 2건**을 잡음(아래 각 배치 파일의 「2차」 절). 낭비가 있었으나 산출물 품질에는 이득.

⚠️ **부작용 — 배치 A 의 기록 하나가 덮어써졌음.** B·C 의 2차는 1차 파일을 발견하고 «덧붙였»으나, **A 는 두 실무자가 같은 파일명에 써서 나중 것이 앞의 표를 지웠음.** 노트에 «적용된» 수정 7건은 그대로 살아 있는데 그 기록만 사라진 상태였음. 관리자가 해당 실무자를 되살려 `audit_P_A1.md` 로 회수함 — 아래 「배치 A(1차)」 절이 그것. **적용된 수정과 기록의 어긋남은 해소됨.**

---

# 배치 A(1차) — 17장 Windows 열거 · 회수본

# 적대적 독해 감사 — 17장 Windows 열거 구간 (담당 P_A · 기록 회수본)

> 배치 A 에 실무자가 둘 파견되어 `audit_P_A.md` 가 덮어써짐. 이 파일은 **17.1.4 · 17.1.5 · 17.2 에 실제로 적용된 수정 7건**의 감사 기록을 되살린 것임. 노트는 이번 작업에서 열지 않았음 — 수정은 이미 적용돼 있고 게이트 넷을 통과한 상태임.

대상 8개 절: 17 · 17.1 · 17.1.1 · 17.1.2 · 17.1.3 · 17.1.4 · 17.1.5 · 17.2
원문·노트 전문 대조 완료. 게이트 4종 재실행 결과 회귀 없음(strictcheck 비정렬 0 / audit2 합성 0·소실 0 / covercheck 소실 0 / verify 결함 0).

## 1. 확정 결함 7건과 조치

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 17.1.4 | 교재 오류 표시 (정정값은 옳음, 표시 형식이 비표준) | 원문 산문 `a user needs to be in the local group Windows Management Users to be a valid user for these Cmdlets` — 그러나 §17.1.2 는 `members of Remote Management Users can access it with WinRM`, §17.1.5 winPEAS 실출력은 `\|->Groups: adminteam,Administrators,Remote Management Users,Users`. 전 코퍼스 grep 결과 `Windows Management Users` 는 이 한 줄이 유일 | 괄호 안 주석으로만 있던 정정을 본문 단정(`Remote Management Users` 에 속해야 함)으로 올리고, SPEC §3-A 의 `> ⚠️ **교재 오류**` 표준 마커로 분리해 근거 두 곳(§17.1.2·§17.1.5)을 명시. **정정값 자체는 검증 결과 옳았음 — 값은 바꾸지 않음** |
| 17.1.4 | 오역 (조건 뒤바뀜) | `Administrators can prevent PSReadline from recording commands by setting the -HistorySaveStyle option to SaveNothing... Alternatively, they can clear the history file manually` + `most Administrators clear their history with Clear-History and therefore, the PSReadline history stays untouched` — 둘은 **택일** 수단이고, 남는 이유는 관리자가 `Clear-History` 로 끝났다고 오해하기 때문임 | 「둘 다 하는 관리자는 드묾」(둘 다 필요하다는 뜻이 됨) → 「둘 중 하나면 충분하지만, 관리자 대부분은 `Clear-History` 로 끝났다고 여겨 어느 쪽도 하지 않으므로 PSReadline 히스토리는 그대로 남아 있음」 |
| 17.1.5 | 창작 | 원문은 해당 목록에 대해 `The list of files does not contain asdf.txt` 만 말함. 파일 «성격»에 관한 서술이 원문에 없음. 실제로 `C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml` 은 Microsoft UEV 인박스 템플릿이지 브라우저·Teams 파일이 아님 | 캡션 「전부 브라우저·Teams 가 들고 다니는 시스템 기본 파일임」 → 「winPEAS 가 지목한 비밀번호 파일 후보」 |
| 17.1.5 | 과잉압축 (판정 근거 소실) | `It categorizes results in different colors indicating items worth a deeper inspection (red) and important information about protections (green)` — 빨강/초록의 «뜻»이 판정 근거인데 노트가 「색이 곧 우선순위」로 뭉갬(초록은 우선순위가 아님) | 「색이 곧 우선순위임」 → 「빨강은 객체에 대한 특수 권한이나 오설정, 초록은 보호 기능이 켜져 있음을 뜻함」 |
| 17.1.5 | 용어 흔들림 | `situational awareness` — 17.1 · 17.1.2 는 전부 「상황 파악」(17.1 에서 `상황 파악(situational awareness)` 로 병기) | 15행 「상황 인식」 → 「상황 파악」 |
| 17.1.5 | 용어 흔들림 | `scheduled tasks` — 17 은 「스케줄 작업(Scheduled Tasks)」로 병기, 17.1.3 도 「스케줄 작업」 | 116행 「예약 작업」 → 「스케줄 작업」 |
| 17.2 | 오역 (강도 과장) | `Windows services are one of the main areas to analyze when searching for privilege escalation vectors` — 「main areas 중 하나」이지 최우선이 아님 | 「권한 상승의 1순위 영역임」 → 「권한 상승 벡터를 찾을 때 반드시 분석하는 주요 영역 중 하나임」 |

**수정하지 않은 파일** — 17 · 17.1 · 17.1.1 · 17.1.2 · 17.1.3. 대조 결과 결함 없음.

## 2. 자진 철회 5건 — 지적하려다 원문으로 되짚어 취소한 것

| 절 | 처음 의심한 것 | 무엇으로 반증했는가 |
|---|---|---|
| 17.1.1 | 무결성 수준을 5단계로 적고 `[가정]` 으로 「원문 산문은 4단계」라 단 것이 교재 오류 «오»표시 아닌가 | **노트가 옳았음.** 원문 Listing 423 은 Untrusted 포함 5개인데 뒤 산문이 `processes run on four integrity levels` 로 Untrusted 를 빼는 교재 «내부 모순»이 실재함. Untrusted 는 실존하는 Windows 무결성 수준이므로 리스팅을 정본 삼은 판정이 정확. 손대지 않음 |
| 17.1.2 | 「32비트는 `Wow6432Node` 하위 키, 64비트는 그렇지 않은 키」 매핑이 원문에 없는 창작 아닌가 | **원문에 근거 있었음.** `We begin with the 32-bit applications and then display the 64-bit applications` 가 블록의 쿼리 순서와 맞물려 그 매핑을 확정함. 철회 |
| 17.1.2 | netstat 은 80/443 에 PID 3340 을 보이는데 노트는 「4316 이 Apache」라 함 — 자기모순 아닌가 | **교재 자신의 서술을 그대로 옮긴 것이었음.** 원문 `process ID 3508 belongs to mysqld and ID 4316 to Apache`. 교재 내부 불일치이나 어느 쪽이 옳은지 원문에 근거가 없어 `근거부족` — 노트 미수정, 보고만 함 |
| 17.1.5 | winPEAS 블록 들여쓰기가 NUL 이라는 노트 주석이 과장 아닌가 | **실측으로 확인됨.** 원문 `17.1.5 Automated Enumeration.md` 에 NUL 184개, `od -c` 로 섹션 제목 앞이 `\0` 임을 확인. 주석 정확. 승인된 예외이므로 블록 미변경 |
| 17.1.3 | 원문 Listing 438 하나가 노트에서 코드펜스 «둘»로 쪼개져 있어 합성 아닌가 | **합성 아니었음.** 각 블록이 원문 한 블록의 «연속 슬라이스»이고 SPEC §3-C 가 분할을 명시 허용함. strictcheck 비정렬 0 으로 재확인. 철회 |

## 3. 코드펜스 관련 — 수정 없이 «보고만» 한 것

- **17.1.2 `route print` 블록** — 원문 Listing 432 의 라우팅 테이블 전문이 «명령 2줄만» 남기고 절단됨. 산문은 블록 «앞»에서 「알려지지 않은 네트워크로 가는 경로가 없었다」는 판정을 서술하는데 블록에 그 근거 출력이 없음. 캡션이 「라우팅 테이블 확인 명령」으로 범위를 정직하게 밝히고 covercheck 소실 0 이라 게이트상 문제는 없으나, 판정 근거를 눈으로 대조할 수 없는 구간임. **복원 여부는 관리자 판단 사항**
- **17.1.5 winPEAS 블록의 NUL→공백 치환** — 승인된 예외로 확인. 미변경

## 4. 용어 대장 — 담당 구간(17~17.2)에서 실제로 쓰인 한국어

| 영문 | 이 구간의 한국어 | 비고 |
|---|---|---|
| `privilege` | **권한** | 17.1.1 첫 등장에서 `권한(privilege)` 병기. `privilege escalation` = **권한 상승**(17 에서 병기) |
| `permission` | **권한** (일부 **접근 권한**) | ⚠️ `privilege` 와 같은 낱말로 수렴함. 17.1.1 「권한이 충분하더라도」·17.1.3 「「Log on as a batch job」 접근 권한」. **다른 담당 구간과 대조 필요 — 이 구간 단독으로는 구분 표기가 없음** |
| `access token` | **액세스 토큰** | 17.1.1 첫 등장 `액세스 토큰(access token)` 병기. 파생: `primary token`=**기본 토큰**, `impersonation token`=**가장 토큰** |
| `integrity level` | **무결성 수준** | 17.1.1 첫 등장 병기. 수준값은 영문 그대로(High·Medium·Low·System·Untrusted) |
| `enumeration` | **열거** | 이 구간에 병기 없음(앞 챕터에서 도입된 것으로 보임). 파생: `automated enumeration`=**자동화 열거**(17.1.5 제목)/**자동 열거**(17.1 본문) — 경미한 흔들림, 미수정 |
| `service` | **서비스** | 17.2. `Service Control Manager` 는 영문 유지 |
| `impersonation` | **가장** | `가장 토큰(impersonation token)` 형태로만 등장. 단독 명사로는 이 구간에 없음 |
| `credential` | **자격증명** | 17.1.2·17.1.3·17.1.4 일관. `PSCredential`·`-Credential` 은 영문 유지. ⚠️ `password` 는 **비밀번호**(값)와 **패스워드**(제품·모듈명: 「패스워드 관리자」·「패스워드 공격」 모듈)로 갈라 씀 — 의도적 구분으로 판단해 미수정 |
| `hijacking` | **하이재킹** | 17.2 「실행 파일 하이재킹」·「DLL 하이재킹」 |
| `scheduled task` | **스케줄 작업** | 17 에서 `스케줄 작업(Scheduled Tasks)` 병기. 17.1.5 의 「예약 작업」 1건을 이번에 통일함 |

---

# 배치 A(2차) — 17장 Windows 열거

# 적대적 독해 감사 — 배치 A (17장 Windows 열거 구간 8개 절)

원문 `src\` 와 볼트 `05. PEN-200\` 를 절 단위로 나란히 대조함. 코드펜스는 열지 않음(게이트 기통과 구간).

## 결함 표

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 17 | 없음 | — | 학습 단위 3종·진행 순서·Scheduled Tasks·익스플로잇 마무리까지 원문 순서대로 보존됨 |
| 17.1 | 없음 | — | 학습 목표 5항목·「모든 대상은 고유함」의 근거(OS 버전·패치·설정 차이)·금맥 비유 모두 유지 |
| 17.1.1 | **용어 흔들림** | `Lower-integrity users cannot modify higher-integrity objects, **even with sufficient permissions**.` | 「**권한이** 충분하더라도」 → 「**접근 권한(permission) 이** 충분하더라도 … 접근 권한 검사를 통과해도 별도로 걸리는 관문임」. 같은 절 첫머리에서 `privilege` 를 「권한(privilege)」으로 병기해 놓고 여기서 `permission` 을 다시 맨 「권한」으로 써, 한국어로 두 축이 한 단어에 붙어 있었음. SPEC §2 첫 등장 병기로 분리함 |
| 17.1.2 | 없음 | — | 아래 「검토했으나 결함 아님」 참조 |
| 17.1.3 | **오역**(양태 강화) | `Based on the information found in the previous section, we **can assume** that the users on CLIENTWK220 use a password manager.` | 「사용자들이 패스워드 관리자를 쓴다는 것은 **확인했지만**」 → 「앞 절의 정보로 … 쓴다고 **추정할 수 있지만**」. 앞 절에서 확인된 것은 KeePass 가 **설치돼 있다**는 사실이고 「사용자가 실제로 쓴다」는 원문에서도 추정임. 확정으로 올리면 이후 `.kdbx` 탐색이 빈손으로 끝나는 대목의 인과가 깨짐 |
| 17.1.4 | 없음 | — | `⚠️ 교재 오류` 표시 **정탐 확인**. 아래 참조 |
| 17.1.5 | 없음 | — | winPEAS 범례 의미·2건 누락 서사 모두 정확. 아래 참조 |
| 17.2 | 없음 | — | 아래 참조 |

## 검토했으나 결함 아님 — 판정 근거

**17.1.2** — 배치 지시의 「명령이 무엇을 판정하려는 것인가」 축으로 전수 확인함. `whoami`(호스트명으로 머신 용도 추정) · `whoami /groups`(helpdesk 의 확장 권한, `Remote Desktop Users` → RDP 가능) · `Get-LocalUser`(내장 Administrator 비활성 · admin 문자열 계정 = 표적) · `Get-LocalGroup`(비표준 그룹 3종과 내장 그룹 4종의 «의미» 구분, `Backup Operators` 는 권한 없는 파일까지 백업·복원) · `systeminfo`(빌드 22621 → 22H2, x64 → 32비트에서 64비트 실행 불가) · `route print`·`netstat -ano`(다른 사용자의 RDP 세션 존재 → Mimikatz 후보) · 레지스트리 2키(32/64비트) · `Get-Process`(설치 목록과 대조해 XAMPP 기동 추정). 각 명령의 판정 목적이 모두 살아 있음.

**17.1.4 `⚠️ 교재 오류` 정탐 확인** — 교재는 `a user needs to be in the local group **Windows Management Users**` 로 적음. 원문 `src\` 전수 grep 결과 이 문자열은 **이 한 곳뿐**이고, `Remote Management Users` 는 17.1.2 · 17.1.3 · 17.1.5(2회) · 24.1.1 에서 쓰임. 실제 Windows 내장 그룹명도 `Remote Management Users` 임. 노트의 정정값이 맞고, 근거로 든 두 인용(17.1.2 산문 · 17.1.5 winPEAS `|->Groups: …,Remote Management Users,Users`)도 해당 노트에 실제로 남아 있음.

**17.1.4 경로·기능 혼동 없음** — 배치 지시가 지목한 위험 지점을 개별 확인함. ① PSReadline 히스토리 경로는 `(Get-PSReadlineOption).HistorySavePath` 로 «조회해서» 얻는 것으로 서술됨(경로를 상수로 지어내지 않음). ② `Clear-History` 가 지우는 것은 PowerShell 자체 히스토리 = `Get-History` 대상이고 PSReadline 파일은 남는다는 인과가 보존됨. ③ Transcription(어깨너머 기록, 파일로 저장)과 Script Block Logging(이벤트로 기록, 인코딩된 코드의 원형 포함)의 기능 구분이 뒤섞이지 않음. ④ 「`Start-Transcript` 가 `Enter-PSSession` «보다 먼저» 실행됐으므로 transcript 에 평문 자격증명이 남아 있을 것」이라는 **핵심 인과가 명시적으로 살아 있음**(원문 `Since the PowerShell Transcription started before Enter-PSSession was entered, it may contain the plain-text credential information`).

**17.1.5 색상 의미 정확** — 노트 「빨강은 객체에 대한 특수 권한이나 오설정, 초록은 보호 기능이 켜져 있음」. 원문 리스팅 `Red Indicates a special privilege over an object or something is misconfigured` / `Green Indicates that some protection is enabled or something is well configured` 와 일치. 원문 산문의 축약판(`items worth a deeper inspection (red)`)이 아니라 리스팅 원문 쪽을 옮겨 «무엇이 취약 신호인가»가 더 정확해졌음. Cyan/Blue/LightYellow 는 산문에서 빠졌으나 블록에 그대로 있어 손실 아님.

**17.1.5 도구 한계 서사 보존** — OS 오판(`ProductName: Windows 10 Pro` vs 실제 Windows 11) · transcript 목록 공백 · `asdf.txt` 누락 3건이 각각 「도구를 그대로 믿지 마라」의 근거로 연결돼 있고, 결론이 「쓰지 마라」가 아니라 「한계를 알고 쓰라」로 원문과 같음.

**17.2 — 「즉 서비스 실행 흐름에 끼어들면 그 계정 권한을 그대로 얻으므로」는 원문 논리의 명시화로 판정, [가정] 강등하지 않음.** 원문에 이 문장은 없음. 그러나 ① 원문이 계정 목록(LocalSystem·Network Service·Local Service·도메인/로컬 사용자)을 나열한 «직후» `Windows services are one of the main areas to analyze when searching for privilege escalation vectors` 로 잇고 ② 같은 단락이 `three different ways to elevate our privileges by abusing services` 로 닫으므로, 두 문장을 잇는 인과가 원문 자체의 것임. 버전·경로·조건·수치를 지어낸 것이 아니라 생략된 연결고리를 복원한 것이라 창작으로 보지 않음.

**17.1.1 `[가정]` 유지** — 노트의 「원문 산문은 무결성 수준을 네 단계로 다시 열거하지만 리스팅은 다섯 단계 — 리스팅을 정본으로 삼음」은 원문과 대조해 **정확함**(산문 `processes run on four integrity levels` 에 Untrusted 없음 / Listing 423 에 Untrusted 포함). 실제 Windows 도 5단계이므로 리스팅 쪽이 맞음. 판정은 옳으나 노트가 `[가정]` 으로 유보해 둔 상태이며, 「강등된 것을 지우지 마라」 규율에 따라 그대로 둠.

## 보고만 — 코드펜스는 건드리지 않음

절단 지점 둘이 판정 근거를 스치나, 어느 것도 해당 절의 서술이 의존하는 줄은 아님. 게이트 회귀 위험이 있어 **수정하지 않고 보고만 함.**

| 절 | 절단된 줄 | 판단 |
|---|---|---|
| 17.1.5 | `Basic System Information` 블록이 `CurrentVersion: 6.3` 에서 끊겨 `HighIntegrity: False` · `PartOfDomain: False` 가 빠짐 | 17.1.1 의 무결성 수준 논의와 이어지는 줄이라 남기면 값이 있음. 단 17.1.5 본문은 이 줄을 참조하지 않아 서술 손실은 없음 |
| 17.1.5 | `Users` 블록이 `daveadmin` 에서 끊겨 `CLIENTWK220\steve` 항목 소실 | steve 의 `Remote Management Users` 소속은 17.1.3 `net user steve` 블록에 남아 있어 중복 손실 아님 |
| 17.1.3 | `passwords.txt` 블록에서 `User: newuser` / `Password: wampp` 소실 | 원문 자체가 「미변경 기본값뿐」으로 결론짓고 이후 쓰이지 않음. 손실 없음 |

## 용어 대장

| 영문 | 이 배치에서 쓰인 한국어 | 병기 위치 |
|---|---|---|
| `privilege` | **권한** | 17.1.1 「권한(privilege)」 (17 은 「권한 상승(privilege escalation)」으로 병기) |
| `permission` | **접근 권한** | 17.1.1 「접근 권한(permission)」 ← 이번 감사에서 추가. 17.1.3 은 `access right` 를 「접근 권한」으로 씀(원문이 `Log on as a batch job access right`) |
| `access token` | **액세스 토큰** | 17.1.1 「액세스 토큰(access token)」. 하위 개념은 「기본 토큰(primary token)」·「가장 토큰(impersonation token)」 |
| `integrity level` | **무결성 수준** | 17.1.1 「무결성 수준(integrity level)」. `Mandatory Integrity Control` 은 `MIC(Mandatory Integrity Control)` 로 병기, High/Medium/Low 는 영문 그대로 |
| `enumeration` | **열거** | 이 배치 안에 병기 없음. 2.3.2 에서 「열거(enumeration)」로 최초 병기돼 있어 재병기 불필요. 「수동 열거」·「자동 열거」·「자동화 열거」로 파생 |
| `service` | **서비스** | 병기 없음(SPEC §2 「이미 한국어에 정착한 것」). 8개 절 전부 「서비스」로 일관 |
| `credential` | **자격증명** | 병기 없음. 17.1.2·17.1.3·17.1.4 전부 「자격증명」(띄어쓴 「자격 증명」 용례 0건) |
| `impersonation` | **가장** | 17.1.1 「가장 토큰(impersonation token)」 1회뿐. 단독 명사 `impersonation` 용례는 이 배치에 없음 |

### 다른 배치와 대조 필요

- `situational awareness` — 이 배치는 **「상황 파악」**(17.1 병기 `상황 파악(situational awareness)`, 17.1.2 제목, 17.1.5 본문)으로 일관. 그러나 **`17.4 마무리.md` 는 「상황 인식(situational awareness)」** 을 씀(배치 밖 파일이라 손대지 않음). 관리자 판정 필요 — 이 배치 표기가 절 제목이자 병기 위치이므로 「상황 파악」이 정본으로 보임.
- `password` — 「비밀번호」가 기본이고, 제품·모듈명 맥락에서만 「패스워드 관리자」(password manager)·「패스워드 공격」(Password Attacks 모듈)·「패스워드 해시」로 씀. 의도된 구분으로 보이나 배치 간 일치 확인 권장.

---

# 배치 B — 17장 서비스·기타 악용 (7개 절)

# 적대적 독해 감사 — 17장 Windows 서비스·기타 구성요소 악용 7개 절 (담당 P_B)

대상 7개 절 전수 대조 완료. 산문 문단 단위로 원문 대목을 짚어 대조함.
게이트 넷 재실행 결과(17장 전체): `strictcheck` 비정렬 0 · `audit2` 합성 0/소실 0 · `covercheck` 소실 0 · `verify` 15/15 결함 0.

## 결함·수정 내역

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 17.2.1 | 오역 | `delete our binary mysqld.exe, restore the backed up original binary, and restart the system` — 재시작 대상이 **시스템**임 | 「재시작 순서임」 → 「**시스템 재부팅** 순서임」. 원문대로면 서비스 재시작 권한이 없는 상황이므로 서비스 재시작으로 읽히면 절 전체 논리와 모순됨 |
| 17.2.1 | 용어 흔들림 | `privilege` 를 17.2.1 은 「특권」, 17.3·17.3.2 는 「권한(privilege)」으로 씀 | 17.2.1 첫 등장 자리에 영문 병기 추가 — 「해당 특권(privilege)을」. 통일 여부는 총괄 판단 항목(아래 §총괄 판단) |
| 17.2.2 | 창작 | `even with a missing DLL, the program may still work with restricted functionality` — 「아무도 눈치채지 못한다」는 원문에 없음 | 「기능이 일부 제한될 뿐 프로그램은 대개 돌아가므로 **아무도 눈치채지 못함**」 → 「DLL 이 없어도 기능이 제한될 뿐 프로그램은 대개 돌아감」 |
| 17.2.2 | 오역(단정 강화) | `In most cases, this would still lead us to code execution of the DLL's code` — 원문은 「대부분의 경우」로 한정 | 「**DLL 안의 코드는 실행되므로**」 → 「**대개는 DLL 안의 코드가 실행되므로**」 |
| 17.2.3 | 오역 | `our user steve, as a member of BUILTIN\Users and NT AUTHORITY\AUTHENTICATED Users, has no Write permissions in either of these paths` — 근거는 두 주체 모두에 쓰기가 없다는 것 | 캡션 「`BUILTIN\Users` 는 `(RX)` 뿐이라」 → 「`steve` 가 속한 `BUILTIN\Users`·`Authenticated Users` 어느 쪽에도 쓰기 권한이 없어」. 원 캡션은 같은 블록에 보이는 `Authenticated Users:(OI)(CI)(IO)(M)`·`(AD)` 를 설명하지 못해 오독을 부름 |
| 17.2.3 | 창작(인과) | Listing 493 의 `Restart-Service` 실패에 대해 원문은 **원인을 적지 않음**. 앞 실패의 원인 서술(`does not accept the parameters that are a leftover of the original service binary path`)은 Listing 491 에만 붙어 있음 | 「앞서와 **같은 이유로** 오류를 내지만」 → 「앞서와 마찬가지로 **서비스 시작 오류**를 내지만」. 관측(둘 다 시작 실패)만 남기고 원문에 없는 인과 단정을 제거 |
| 17.3.1 | 오역(단정 강화) | `"interesting" means that the information partially or completely answers one of the three questions` | 「위 세 질문에 **직접** 답하는 필드들임」 → 「부분적으로든 전부든 답을 주는 필드들임」 |
| 17.3 | 없음 | 학습 목표 셋(`Leverage Scheduled Tasks` / `Understand the different types of exploits` / `Abuse privileges to execute code as privileged user accounts`)과 유닛 도입부가 그대로 대응 | 결함 없음 |
| 17.4 | 없음 | 모듈 요약 3항목 · `privileged file writes` · `ever-evolving landscape` · 우회 지침이 전부 대응 | 결함 없음 |
| 17.3.2 | 창작(인과) | 원문은 `whoami /priv` 를 **커널 익스플로잇 예시의 도입**으로 배치했고, 세 번째 계열(권한 악용)은 **커널 예시 뒤**에 논의함. 「권한이 없어서 커널로 간다」는 인과가 원문에 없음 | 캡션 「세 번째 계열(권한 악용) 경로가 닫힘」 → 「세 번째 계열(권한 악용)은 이 계정으로 쓸 수 없음」(원문 정의로부터의 정당한 연역), 본문 「권한 남용 경로가 없으므로 커널 쪽을 봄」 → 「교재는 여기서 커널 익스플로잇 예시로 진행함」(사실 서술로 격하) |

## 반증한 것 — 지적하려다 원문 확인 후 철회

| 초기 지적 | 철회 사유 |
|---|---|
| 17.2.1 「성립 전제 셋」이 원문에 없는 창작 목록 | 원문 첫 문단에 셋이 모두 흩어져 있음 — 쓰기 권한(`allowing full Read and Write access to all members of the Users group`) · 재시작 수단(`restart the service or ... reboot the machine`) · 상위 권한 실행(`executed with the privileges of the service, such as LocalSystem`). 재구성일 뿐 창작 아님 |
| 17.2.2 DLL 검색 순서 서술의 「5순위 ↔ 2순위」가 뒤바뀜 | 원문 `Interestingly, the current directory is at position 5. When safe DLL search mode is disabled, the current directory is searched at position 2` 와 정확히 일치. 순서 오역 없음 |
| 17.2.3 따옴표 없는 경로 후보 생성 규칙 서술이 틀림 | 원문 `the function uses the preceding part as file name by adding .exe and the rest as arguments` 와 일치. 「공백 하나마다 후보 하나」도 Listing 483 과 일치 |
| 17.3.1 「`daveadmin` 이 우리보다 높음」이 원문 미기재 | 원문이 명시하진 않으나, adduser 페이로드가 `net localgroup administrators` 를 성공시킨 사실(Listing 497)과 `if the task runs as ... an administrative user, then a successful attack could lead us to privilege escalation` 로 뒷받침됨. 유지 |
| 17.3.2 `SeImpersonatePrivilege` 기본 할당 대상 목록이 창작 | 원문 `Windows assigns this privilege to members of the local Administrators group as well as the device's LOCAL SERVICE, NETWORK SERVICE, and SERVICE accounts` 와 일치 |
| 17.2.1·17.2.2·17.2.3·17.3.1 의 「교재 PDF 조판으로 줄이 접힘」 주석이 창작 | 해당 블록들은 실제로 명령 한 줄이 두·세 줄로 갈라져 있고, 그대로 붙여넣으면 첫 줄이 인자 없이 실행돼 실패함. SPEC §3-A 의 「교재 결함 표시」 범주에 해당. 유지 |

## 총괄(관리자) 판단이 필요한 것

1. ~~**`privilege` 의 한국어 통일**~~ → **2차에서 해소.** 「권한(privilege)」으로 통일함(근거: 17장 첫 등장 `17.1.1:17`). 남는 것은 **`permission` 과 한국어가 겹치는 문제**뿐이며, 이는 17.1.1 이 이미 확정한 표기라 담당 구간에서 바꿀 사안이 아님 — 다른 배치의 용어 대장과 대조만 필요함.
2. **코드펜스 문제 — 수정하지 않고 보고만**(READ-AUDIT 지시대로):
   - `17.2.3`: 원문 Listing 493 을 두 블록으로 나눠 실었는데 그 사이의 **`Restart-Service GammaService` 명령줄과 오류 출력이 통째로 빠짐**. SPEC §3-D 는 「프롬프트가 붙은 실행 줄」을 살리라고 함. 본문 산문이 명령을 언급해 재현은 가능하나, 살리려면 블록 복원이 필요함(`covercheck` 는 통과 — 판정 근거 줄로 분류되지 않음).
   - `17.2.1`: `Install-ServiceBinary` 오류 블록이 `not modifiable by the current user.` 까지만 남고 스택트레이스가 절단됨 — 판정 근거는 보존돼 문제 없음.

## 수치

**1차** — 검토 7/7 절 · 결함 8건(오역 4 · 창작 3 · 용어 흔들림 1 · 블록위치 0 · 교재오류표시 오류 0) · 수정 파일 5개(17.2.1 / 17.2.2 / 17.2.3 / 17.3.1 / 17.3.2) · 무결 2개(17.3 / 17.4) · 게이트 넷 전부 통과.

**2차(독립 재감사)** — 검토 7/7 절 · 1차 8건 전부 유지 · **추가 수정 2건**(용어 흔들림 1 = 17.2.1 「특권」→「권한」, 창작·미검증 단정 1 = 17.2.3 조판 주석) · 수정 파일 2개(17.2.1 / 17.2.3) · 누적 결함 10건 · 산문만 수정, 코드펜스 무변경.

## 2차 대조 (독립 재감사) — 1차 판정 2건을 뒤집음

1차 기록을 보지 않은 상태에서 7개 절을 원문과 다시 대조함. 1차가 잡은 8건은 **전부 원문 대조로 재확인**돼 유지. 아래 2건만 바뀜.

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 17.2.1 | 용어 흔들림 | `SPEC` §2 첫 등장 병기 규칙. 17장에서 `privilege` 의 **첫 등장은 17.1.1** 이며 거기서 「권한(privilege)」으로 확정됨(`17.1.1:17`). 17.3·17.3.2 도 「권한(privilege)」 | 1차가 「병기만 붙이고 통일은 보류」한 항목을 **해소함.** 17.2.1 의 「특권」 3회 → 「권한」. 근거는 담당 구간 밖(17.1.1)의 선례라 1차가 못 본 것임. `permission` 과 한국어가 겹치는 문제는 남으나, 17.1.1 이 이미 그 표기로 개념 정의를 마쳐 여기만 다르게 쓰는 쪽이 더 큰 손해 |
| 17.2.3 | 창작(단정) | 1차는 「PDF 조판 접힘」 주석 4건을 「첫 줄이 인자 없이 실행돼 실패함」을 근거로 전부 유지 판정함. 그 논리는 17.2.1(`\| Select` 뒤 절단)·17.2.2(`Get-ItemProperty` 단독, `-OutFile` 뒤 절단)·17.3.1(`-Outfile` 뒤 절단)에는 맞으나 **17.2.3 의 `wmic` 블록에는 안 맞음** — 그 블록은 절단 지점이 **파이프 `\|` 뒤**이고, `cmd.exe` 는 파이프로 끝난 줄을 다음 줄과 이어 해석함(`More?` 계속 입력). 즉 「실패한다」가 검증되지 않음 | 「그대로 복사해 쓰면 실패함」 → 「한 줄로 이어 칠 것」. 관측(접힘)만 남기고 미검증 단정을 제거. 나머지 3건의 주석은 근거가 성립하므로 **그대로 둠** |

**2차에서 지적하려다 원문 확인 후 철회한 것:**

- 17.3.1 「셋 다 답이 나와야 벡터가 성립함」이 원문 과장 — 원문 `three pieces of information are vital to obtain` 이 「셋 다 얻어야 함」을 뜻하고, 이어지는 노트 불릿이 `the first two ... if this task is even an option / the third ... determines how` 구분을 그대로 살려둠. 과장 아님
- 17.2.1 「성립 전제 셋」 목록, 17.2.2 검색 순서 5↔2, 17.2.3 후보 생성 규칙, 17.3.2 CVE-2023-29360·KB5027215·22H2 수치 — **전부 원문과 일치.** 이 배치의 최우선 확인 대상이었으므로 재확인 결과를 명시해 둠
- 17.2.2 「악성 DLL 은 애플리케이션을 실행한 사용자 권한으로 돈다」 — 원문 `the privileges the DLL will run with depend on the privileges used to start the application` 과 일치. 살아 있음

## 용어 대장

| 영문 | 담당 구간에서 쓰인 한국어 | 비고 |
|---|---|---|
| `privilege` | **「권한(privilege)」** (17.2.1 · 17.3 · 17.3.2) | ✅ 2차에서 통일 완료. 17.2.1 의 「특권」 3회를 「권한」으로 고침 — 17장 첫 등장인 `17.1.1:17` 이 「권한(privilege)」로 정의함. 파생 형용사 「비특권 사용자」(17.3.2, 원문 `Non-privileged users`)는 그대로 둠 |
| `permission` | 「권한」 · 「쓰기 권한」 · 「Full Access(F)」 | 전 구간 일관. ⚠️ `privilege` 와 한국어가 겹침 — 다른 배치와 대조 필요 |
| `binary` | 「실행 파일」(17.2.1 제목·본문 5회) · 「바이너리」(17.2.1~17.3.2 본문 13회) | ⚠️ 한 파일 안에서 혼용. 뜻은 같고 오독 소지 없어 손대지 않음. 제목은 `titles_ko.json` 고정값이라 「실행 파일」로 확정 |
| `search order` | 「검색 순서(search order)」(17.2.2 첫 등장 병기) · 이후 「검색 순서」 | 일관. SPEC §2 준수 |
| `hijacking` | 「하이재킹」 | 일관 |
| `access token` | **미등장** (17.3.2 에 「토큰(token)」만 — 원문도 `a token with another security context`) | |
| `integrity level` | **미등장** (코드펜스 안 `Mandatory Label\High Mandatory Level` 뿐) | |
| `enumeration` | 「열거(enumeration)」(17.4) · 「열거」(17.2.1, 17.2.3, 17.3.1, 17.3.2) | 일관 |
| `service` | 「서비스」 | 전 구간 일관, 병기 없음(정착어) |
| `impersonation` / `impersonate` | 「가장(impersonate)」(17.3.2) | 첫 등장 병기 있음 |
| `credential` | **미등장** (17.2.2 는 「비밀번호」로 서술) | |
| `scheduled task` | 「예약 작업(Scheduled Tasks)」(17.3) · 「예약 작업」(17.3.1) · 「예약 작업(scheduled tasks)」(17.4) | 일관. 병기가 17.3·17.4 두 번 나오나 파일 분리라 허용 범위 |

---

# 배치 C — 18장 Linux 권한 상승 (16개 절)

# 적대적 독해 감사 — 18장 Linux 권한 상승 (16개 절 전량)

담당: P_C · 대상 노트 `볼트\05. PEN-200\18*.md` 16개 · 원문 `src\18*.md` 16개
방식: 절마다 원문 전문 → 노트 전문 → 노트 산문 문단을 원문 대목에 하나씩 대응시켜 대조.

## 결함과 조치

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 18 | 용어 흔들림 | 학습 단위 열거의 `Insecure File Permissions` — 18.3 절 제목과 **글자 그대로 같은 영문구** | 학습 단위 목록의 「불안전한 파일 권한」→「**취약한 파일 권한**」. 18.3 노트 제목(`취약한 파일 권한`)과 불일치해 색인·검색에서 갈렸음 |
| 18.1.2 | 용어 흔들림 | `cron` (원문은 전부 라틴 표기) | 산문·캡션의 「크론」 3곳을 `cron` 으로 통일 — ①캡션 「현재 사용자(joe)의 크론」 ②「root 크론이 매분」→「root 의 cron 작업이 매분」 ③「root 크론 스크립트」→「root cron 스크립트」. 18.3.1 제목이 `cron 작업 악용` 이라 그쪽에 맞춤 |
| 18.4.1 | 용어 흔들림 | Listing 546·547 캡션 `Inspecting passwd's process credentials` | 「`/proc/<PID>/status` 로 **자격증명**을 직접 확인함」→「**그 프로세스의 UID 값**을 직접 확인함」. 이 볼트에서 「자격증명」은 18.2.x 내내 패스워드·해시를 가리키는 말로 고정돼 있어, 프로세스 UID 에 같은 말을 쓰면 시험장에서 오독 소지 |
| 18.4.3 | 오역(정도 과장) | `This setup will **lower the risks** related to any cross-compilation compatibility issues.` | 「크로스 컴파일 호환성 문제가 **사라짐**」→「문제의 **위험이 줄어듦**」. 원문은 위험 «감소»지 «소멸»이 아님. 대상에서 직접 컴파일해도 실패할 수 있다는 여지를 지우는 서술이었음 |

산문 수정 4건 · 코드펜스 수정 0건 · 삭제 0건 · `[가정]` 강등 0건.

## 지적했다가 «반증해» 철회한 것 — 고치지 않음

| 절 | 처음 의심 | 원문 대조 결과 |
|---|---|---|
| 18.1.2 / 18.4.1 | eUID 정의 충돌 — 18.1.2 는 「상속되는 것이 eUID」, 18.4.1 은 「상속되는 것이 real UID」 | **교재 자신이 모순.** 18.1.2 원문 `it inherits the UID/GID of its initiating script: this is known as effective UID/GID` / 18.4.1 원문 `…: this is known as the real UID/GID`. 노트 18.1.2 의 「이때」는 **직전 문장(SUID 시 소유자 권한으로 실행)** 을 받으므로 「소유자 UID = eUID」로 읽히고, 18.4.1 은 「실행 주체 UID = real UID」로 읽힘 — **양쪽 다 기술적으로 옳고 서로 모순되지 않음.** 노트가 교재 오류를 조용히 정리한 형태라 손대지 않음 |
| 18.4.2 | `-z` 설명이 원문에 없음(창작 의심) — 원문은 GTFOBins 링크만 언급 | **사실 확인 후 유지.** Kali `man tcpdump` 실측: `-z postrotate-command … Used in conjunction with the -C or -G options, this will make tcpdump run "postrotate-command file"`. 노트 서술(「캡처 파일 회전 시 지정한 스크립트를 실행」)과 일치. 원문 블록의 `-W 1 -G 1` 이 그 전제를 이미 갖춤 |
| 18.3.1 | `⚠️ 교재 오류` 표시가 오판인지 | **표시가 정확함.** Listing 542 는 `echo … nc 192.168.118.2 1234` 로 쓰는데 바로 뒤 `cat` 출력은 `nc 10.11.0.4 1234`. Listing 543 리스너는 `connect to [192.168.118.2]` — 정정 방향(118.2 가 맞고 10.11.0.4 가 옛 랩 주소)이 옳음 |
| 18.1.1 | 디렉터리 `r`/`w`/`x` 의미 뒤바뀜 의심 | **일치.** `Read access gives the right to consult the list of its contents. Write access allows creating or deleting files. execute access allows crossing through the directory` → 노트 표(목록 조회 / 생성·삭제 / `cd` 통과) 그대로. 「`x` 만 있으면 정확한 이름을 알아야 접근」도 원문 `only by knowing their exact name` 과 일치 |
| 18.4.3 | 「4.13.9 미만이라 4.4.0-116 포함」이 노트의 추론인지 | 원문 `since it seems to be newer and matches our kernel version as it targets any version below 4.13.9` 에 그대로 있음 |
| 18.2.1 | 「사람이 만든 패스워드는 같은 어근을 재사용」이 창작 | 원문 `building a custom dictionary **derived from the known password**` 의 「왜」를 푼 것이라 유지. 버전·경로·수치 창작이 아님 |
| 18.3.1 | 「`>>` 로 추가할 것 — 원래 백업 동작을 살려 둘 것」이 창작 | 원문 Listing 542 가 실제로 `>>` 를 쓰고 `cat` 결과에 원래 `cp` 줄이 남아 있음 — 블록에서 직접 읽히는 사실이라 유지 |

## 코드펜스 관련 보고 (수정 금지 대상 — 보고만)

- **18.3.1 Listing 542** — 교재 자체의 LHOST 불일치(`192.168.118.2` → `10.11.0.4`). 노트가 블록 밖 `> ⚠️ 교재 오류` 인용문으로 이미 표시함. **정확하므로 유지 권고**
- **18.4.3 원문 산문** — `/etc/issue` 는 `Ubuntu 16.04.4 LTS` 인데 원문 서술은 `running Ubuntu 16.04.3 LTS`. 교재 자체 오타이며 **노트는 산문에서 이 숫자를 쓰지 않아 오류를 상속하지 않음.** 조치 불필요
- **18.3.1 원문 산문** — `we could also inspect the cron log file (/var/log/cron.log)` 라 적고 정작 명령은 `grep "CRON" /var/log/syslog`. 교재 자체 불일치이며 **노트는 경로를 명시하지 않고 「로그로 확인하는 방법」으로 처리**해 상속하지 않음. 조치 불필요

## 관리자 지시 중 전제가 틀렸던 것

- **「18.4.2 의 `(ALL, !root)` negation 우회(CVE-2019-14287) 버전 범위를 대조하라」** — 그런 내용이 **원문에도 노트에도 없다.** `src\` 전체 grep 결과 `14287` 0건 · `ALL, !root` 0건. 18.4.2 의 sudo 악용 소재는 tcpdump(AppArmor 로 차단됨)와 apt-get(GTFOBins `changelog`→`less`→`!/bin/sh`) 둘뿐
- **「18.3.1 의 PATH 하이재킹 성립 조건을 확인하라」** — 18.3.1 원문에 PATH 하이재킹이 **없다.** 소재는 world-writable 스크립트(`-rwxrwxrw-`)에 리버스셸 한 줄을 덧붙이는 것 하나임. 노트도 없는 것을 지어내지 않았음
- **「18.4.3 의 『커널 익스플로잇은 마지막 수단』 이유를 대조하라」** — 18.4.3 원문에 그 서술이 **없다.** 관련 경고(버전 불일치 시 시스템 불안정·크래시, 관리자에게 먼저 발각)는 **18.1.2** 에 있고 그 노트가 이미 담고 있음

## 게이트 재실행 (18장 범위)

```
strictcheck.py 18 18 → 노트 코드블록 62개 · 줄 단위 비정렬 0개
audit2.py     18 18 → 원문 62 / 노트 62 · 합성 0 · 소실 0 · 거짓 서술 0
covercheck.py 18 18 → 판정 근거 줄 81개 · 소실 0
verify.py     18 18 → 완료 16 / 전체 16 · 미생성 0 · 결함 0
```

## 용어 대장 — 18장에서 실제로 쓰인 한국어

| 영문 | 18장 표기 | 비고 |
|---|---|---|
| privilege | **권한** / privilege escalation = **권한 상승** | 18 노트에서 `권한 상승(privilege escalation)` 1회 병기 후 한국어만 |
| permission | **권한** (파일 권한 · sudo 권한 · 쓰기 권한) | privilege 와 같은 낱말을 공유. 「파일 권한 / 권한 상승」 처럼 수식으로 구분됨 |
| enumeration | **열거** | 18 노트에서 `열거(enumeration)` 1회 병기. 「수동 열거 / 자동화 열거」 |
| credential | **자격증명** | 패스워드·해시류에만 사용(18.2.x). 18.4.1 의 프로세스 UID 용례는 이번에 「UID 값」으로 교체 |
| capabilities | **capabilities** (영문 그대로) | 한국어 대응어 안 씀. 개별 값은 `cap_setuid`·`cap_net_raw` 로 원문 표기 |
| setuid | **setuid** / **SUID** / `SUID(Set-User-ID) 플래그` | 원문이 `setuid`·`SUID`·`Set-User-ID` 를 섞어 쓰는 것을 그대로 따름. setgid/SGID 도 동일 |
| cron job | **cron 작업** (절 제목 `18.3.1 cron 작업 악용`), 예약 작업(cron) | 이번에 「크론」 3곳을 `cron` 으로 통일 |
| kernel exploit | **커널 익스플로잇** | 절 제목만 「커널 취약점 익스플로잇」(원문 `Exploiting Kernel Vulnerabilities`) |
| binary | **바이너리** | 절 제목 `setuid 바이너리와 capabilities 악용` |
| owner | **소유자** / owner group = **소유 그룹** / others = **그 외 · others** | 18.1.1 에서 `소유자(owner) · 소유 그룹(owner group) · 그 외(others)` 로 1회 병기 |

---

# 2차 패스 (독립 재감사) — 같은 배치 C, 다른 작업자

⚠️ **경로 충돌.** 이 배치가 **두 번 파견됨.** 위 1차 산출물(13:42)이 이미 존재했고, 2차 작업자는
그것을 모른 채 16개 절을 처음부터 다시 대조함. **1차 표는 지우지 않고 아래에 2차 결과를 덧붙임.**
2차가 1차 수정본 위에서 읽었으므로 **1차 판정의 교차검증을 겸함.**

## 1차 수정 4건의 사후 검증

| 1차 수정 | 2차 판정 |
|---|---|
| 18 「불안전한 파일 권한」→「취약한 파일 권한」 | ✅ 반영 확인. 18.3 노트 제목과 일치 |
| 18.1.2 「크론」→`cron` 3곳 | ⚠️ **미완.** 4번째 occurrence 가 남아 있었음 — 「root **크론** 목록 조회 하나뿐」. 2차에서 「root 의 cron 작업 목록 조회」로 마저 통일 |
| 18.4.1 「자격증명」→「UID 값」 | ✅ 반영 확인. `Uid: 1000 0 0 0` 을 가리키는 문장이라 타당 |
| 18.4.3 「사라짐」→「위험이 줄어듦」 | ✅ 원문 `lower the risks` 와 일치. 정정 방향 옳음 |

## 2차에서 새로 잡은 것

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 18 | 없음 | — | 1차 수정 후 재검토. 학습 단위 4개·MITRE ATT&CK 전술 서술 모두 원문 일치 |
| 18.1 | 없음 | — | 원문 마지막 문장(`refresher on the Linux privilege scheme, then … manual and automated`)만 남긴 압축. 분량비율 **0.158** 로 하한 근접이라 **산문을 줄이는 수정은 하지 않음** |
| 18.1.1 | 없음 | `Read access gives the right to consult the list of its contents … execute access allows crossing through the directory` | 파일/디렉터리 `r`·`w`·`x` 대조표가 원문과 일치. 뒤바뀜 없음 |
| 18.1.2 | 용어 흔들림 | `insecure permissions` · `files with insufficient access restrictions` | 「파일 권한이 **불안전하거나**」→「**취약하거나**」, 「**불안전한** 권한의 파일」→「**취약한** 권한의 파일」. 같은 영문구를 18·18.3·18.3.1·18.5 가 전부 「취약한」으로 쓰는데 이 절만 갈렸음 |
| 18.1.2 | 용어 흔들림(1차 잔여) | `cron` | 「root 크론 목록 조회」→「root 의 cron 작업 목록 조회」 |
| 18.1.3 | 없음 | `standard mode appears to perform a speed-optimized process and should provide a reduced number of false positives` | standard/detailed 대비, 「자동화가 수동을 대체 못 함」의 이유 모두 보존 |
| 18.2 | 오역(빈도 부사 누락) | `often leading to the desired outcome` | 「첫 단추이자 **그대로 목표까지 이어지는 경로가 됨**」(단정) → 「첫 단추임. 그 한 단계가 그대로 목표까지 이어지는 **경우도 잦음**」 |
| 18.2.1 | 없음 | `-t` 로 패턴 지정 · `(ALL : ALL) ALL` · `sudo -i` | env→`.bashrc` 로 「상시 주입되는 값」을 확정하는 2단계 절차, crunch/hydra 인자 설명 모두 원문·블록과 일치 |
| 18.2.2 | 오역(과잉 일반화) | 두 사례 모두 `joe` 계정 — tcpdump 는 `sudo` 를 **받아** 실행함 | 맺음말 「권한이 없어도 **관찰**은 된다」 → 「두 사례 모두 **root 가 아닌 계정**이 root 의 자격증명을 **관찰**해 얻은 것임」. tcpdump 쪽은 sudo 허용이 «있어야» 성립하므로 「권한이 없어도」가 절반은 틀렸음 |
| 18.3 | 없음 | — | 학습 목표 2개 그대로 |
| 18.3.1 | 창작(근거 없는 이유) | Listing 542 — `echo … >> user_backups.sh` 후 `cat` 에 원래 `cp` 줄이 남음 | 「`>>` 로 추가할 것 — 원래 백업 동작을 살려 두어야 **이상 징후가 덜함**」에서 지어낸 이유를 걷고 「**교재 예시도** 원래 `cp` 백업 줄을 남긴 채 리버스셸 줄만 덧붙임」으로 재서술. ⚠️ **1차는 이 항목을 「유지」로 판정했으나 «`>>` 를 쓴다»는 사실과 «탐지를 피한다»는 이유는 다른 주장임** |
| 18.3.2 | 없음 | `it is considered valid for authentication and it takes precedence over the respective entry in /etc/shadow` | 하위 호환·«우선함»·UID/GID 0 의 의미 모두 보존 |
| 18.4 | 없음 | — | 학습 목표 3개 그대로 |
| 18.4.1 | 없음 | `sets the effective UID of the running process to the executable owner's user ID` | setuid=소유자 / setgid=소유 그룹, `+ep`=effective·permitted, real vs effective 구분 모두 정확 |
| 18.4.2 | 없음 | `apparmor="DENIED" operation="exec"` · `aa-status` | sudo 목록 3개의 개별 판정, AppArmor 차단 인과 모두 원문대로 |
| 18.4.3 | 없음 | `matching not only the target's kernel version, but also the operating system flavor` | 배포판 계열까지 맞춰야 한다는 전제, 소스 주석의 테스트 커널 목록으로 적합성 확인하는 절차 보존 |
| 18.5 | 없음 | — | 모듈 요약 4항목 일치 |

2차 산문 수정 **5건**(용어 2 + 1차 잔여 1 + 오역 2 + 창작 재서술 1 중 중복 제외) · 코드펜스 수정 **0** · 삭제 **0** · `[가정]` 강등 **0**.

## 2차가 지적했다가 반증해 철회한 것

| 절 | 처음 의심 | 대조 결과 |
|---|---|---|
| 18.1.2 | 「이때 상속되는 것을 eUID/eGID 라 함」이 교재 오류를 그대로 상속한 것 | **1차 판정과 같은 결론.** 교재가 §18.1.2 와 §18.4.1 에서 서로 다르게 정의하나, 노트의 「이때」는 직전 문장(SUID → 소유자 권한 실행)을 받으므로 「소유자 UID = eUID」로 읽힘. 별도 `⚠️ 교재 오류` 표시를 붙이면 18.4.1 의 `Uid: 1000 0 0 0` 설명과 중복이라 **추가하지 않음** |
| 18.4.1 | 「ELF 저장 위치가 달라 SUID 검색만으로는 안 잡힘」이 원문에 없는 결론 | 원문 `capabilities, setuid, and the setuid flag are located in different places within the Linux ELF file format` 의 귀결이고 `getcap` 을 «따로» 돌리는 절차가 그 근거임. 유지 |
| 18.2.1 | 「닷파일은 안 보인다는 이유로 관리가 느슨함」이 창작 | 버전·경로·조건·수치가 아닌 일반 서술이고 원문의 「관리자가 환경 변수에 자격증명을 둔다」와 같은 방향. 유지 |
| 18.1.2 | 캡션 「인터페이스 — **두 개**의 네트워크」가 원문 `more than one` 의 수치 창작 | 같은 블록의 `ens192`·`ens224` 두 개에서 직접 읽히는 값이라 유지 |

## 2차 게이트 재실행 (2차 수정 반영 후)

```
strictcheck.py 18 18 → 노트 코드블록 62개 · 비정렬 0
audit2.py     18 18 → 원문 62 / 노트 62 · 합성 0 · 소실 0 · 거짓 서술 0
covercheck.py 18 18 → 판정 근거 줄 81개 · 소실 0
verify.py     18 18 → 완료 16 / 16 · 결함 0
ratio         18.1=0.158(하한 근접, 불변) · 나머지 0.207~0.365 · fence 수 원문과 전부 일치
```

## 용어 대장 — 2차 확인

위 1차 대장과 **일치**. 2차에서 바뀐 것 둘:

- **permission** — `insecure permissions` 계열이 「불안전한/취약한」 둘로 갈렸던 것을 **「취약한」으로 통일**(18.1.2 2곳)
- **cron job** — 1차가 남긴 「크론」 1곳을 마저 `cron` 으로 통일

나머지 8개 용어(privilege·enumeration·credential·capabilities·setuid·kernel exploit·binary·owner)는
1차 대장의 표기가 2차 재확인에서도 그대로 유지됨.

### 2차 마감 시점의 외부 변경 — 「자격증명」→「자격 증명」

⚠️ 2차 수정 직후, **이 배치가 아닌 다른 작업자**가 18장 노트 5개(18.1.2·18.2·18.2.1·18.2.2·18.5)의
`credential` 표기를 **「자격증명」→「자격 증명」(띄어쓰기)** 로 일괄 변경함. 마감 시점 확인 결과
**18장 안에서는 혼재 없이 전부 「자격 증명」으로 통일된 상태**임.

- 위 1차·2차 용어 대장의 `credential` 항목 표기(「자격증명」)는 **그 시점 기준이며 현재와 다름**
- 볼트 전체(다른 장)와의 정합은 **관리자가 판정할 사항** — 이 배치는 손대지 않음
