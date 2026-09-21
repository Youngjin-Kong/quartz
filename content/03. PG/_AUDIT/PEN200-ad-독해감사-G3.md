---
type: audit
target: "PEN-200 §23.2.2–24.1.6"
role: read-auditor
group: G3
date: 2026-09-03
manual_tags: true
manual_cves: true
---

# PEN-200 AD 인증·측면 이동 — 적대적 독해 감사 (G3)

담당 13개 절 — 23.2.2, 23.2.3, 23.2.4, 23.2.5, 23.3, 24, 24.1, 24.1.1, 24.1.2, 24.1.3, 24.1.4, 24.1.5, 24.1.6.
방법 — 원문 `src\<번호> <영문제목>.md` 전문 ↔ 노트 `05. PEN-200\<번호> <한국어제목>.md` 전문 대조. 코드펜스는 대조·수정 대상 아님(게이트 통과분).

## 결함 · 정정

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 24.1.1 | 오역(적용 범위 드리프트) | 원문 146행 「**For WinRS to work**, the domain user needs to be part of the Administrators or Remote Management Users group on the target host」 · 「Since **winrs** only works for domain users」 — 조건의 주어가 `winrs` 유틸리티임 | 「전제 조건은 도메인 사용자가 …」로 **WinRM 전체의 조건처럼** 적혀 있던 불릿을 `winrs` 로 한정. 원문에 있으나 빠져 있던 「winrs 는 도메인 사용자에게만 동작」과 「WinRM 은 PowerShell 구현 외 다수 내장 유틸리티로 구현됨」을 복원 |
| 24.1.1 | 창작(인과 날조) | 원문에 WinRS 셸의 시작 디렉터리가 `C:\Users\jen` 인 **이유는 없음**. `grep -in "context\|directory"` 로 원문 전수 확인 — 해당 서술 부재 | 「WinRS 는 사용자 컨텍스트에서 직접 실행되기 때문임」을 삭제하고 관측(시작 경로 차이)만 남긴 뒤 원인 추정은 `[가정]` 으로 강등. **삭제 원문**: 「리스너에 붙은 셸은 WMI 경로와 달리 `C:\Users\jen` 에서 시작함 — WinRS 는 사용자 컨텍스트에서 직접 실행되기 때문임.」 (두 경로 모두 `corp\jen` 컨텍스트로 도는 것은 노트의 코드블록 자체가 보임 → 「사용자 컨텍스트」는 차이의 원인이 될 수 없음) |
| 24.1.1 | 창작(근거 없는 부재 단정) | 원문 18행 「If we were logged in on that machine and monitoring **Task Manager, we would see the win32calc.exe process appear** with jen as the user」 — 프로세스 목록에는 «보임» | session 0 설명 끝의 「대화형 화면에는 안 보임」이 작업 관리자에서도 안 보인다는 뜻으로 오독될 수 있어, 「대화형 데스크톱에 창이 뜨지 않음 / 작업 관리자 프로세스 목록에서는 확인 가능」으로 분리 |

## 무결 판정

23.2.2, 23.2.3, 23.2.4, 23.2.5, 23.3, 24, 24.1, 24.1.2, 24.1.3, 24.1.4, 24.1.5, 24.1.6 — 12개 절 결함 0.

## 이 구간의 핵심 판별 항목 — 전수 대조 결과

| 항목 | 판정 |
|---|---|
| 23.2.2 AS-REP 전제 = 대상 계정의 **사전 인증 비활성**(`Do not require Kerberos preauthentication`), 인증 없이 AS-REQ 가능 | ✅ 원문과 일치 |
| 23.2.3 Kerberoast 전제 = 대상 계정의 **SPN 보유** + 공격자가 **이미 도메인 인증된 상태** | ✅ 일치. 「인증된 도메인 사용자 컨텍스트로 실행」 명시됨 |
| 깨는 대상 — AS-REP=사용자 계정 비밀번호 / TGS-REP=SPN 서비스 계정 비밀번호 | ✅ 양쪽 다 정확 |
| 해시 포맷·모드 — `$krb5asrep$`/18200 vs `$krb5tgs$`/13100 | ✅ 뒤바뀜 없음 |
| 23.2.4 Silver Ticket = **SPN 서비스 계정 해시** 필요, 그 서비스 한정, PAC validation 이 **선택적**이고 실제로 드물게 켜짐 | ✅ 일치. krbtgt(Golden, 24.2.1)와 혼동 없음. `kerberos::golden` 모듈이 둘 다 만든다는 점도 정확히 구분됨 |
| 23.2.5 DCSync 권한 = Replicating Directory Changes / All / in Filtered Set, 기본 보유자 = Domain Admins·Enterprise Admins·Administrators | ✅ 셋 다 정확 |
| 23.2.5 방향 — 공격자가 **DC 를 사칭해** 복제를 요청 | ✅ 뒤집힘 없음 |
| 24.1.3 PtH 입력물 = **NTLM 해시**, NTLM 인증 전용(Kerberos 대상 불가) | ✅ 일치 |
| 24.1.3 제약 — AD 도메인 계정 + **빌트인 로컬 Administrator** 만, 2014 보안 업데이트로 그 외 로컬 관리자 계정 불가 / SMB 445 · File and Printer Sharing · `ADMIN$` | ✅ 일치 |
| 24.1.4 OPtH 입력물 = **NTLM 해시 → Kerberos TGT 전환**, NTLM 을 네트워크에 흘리지 않음 | ✅ 일치 |
| 24.1.5 PtT 입력물 = **이미 존재하는 티켓(TGS)** 을 export 후 재주입. TGT 는 발급 머신 한정 | ✅ 일치 |
| 24.1.1 포트 — WMI: RPC 135 + 고범위 세션 포트 / WinRM: HTTPS 5986 · HTTP 5985 | ✅ 일치(`19152` 교재 오류 표시 포함 정확) |
| 24.1.2 PsExec 조건 — 로컬 Administrators + `ADMIN$` + File and Printer Sharing | ✅ 일치 |
| 24.1.6 DCOM — RPC **TCP 135**, DCOM SCM 호출에 **로컬 관리자** 필요, MMC `Document.ActiveView.ExecuteShellCommand` | ✅ 일치. WMI(135)와 같은 포트를 쓰는 것도 원문 그대로 |

## 반증한 것 — 지적하려다 원문으로 되짚어 철회

| 대상 | 처음 판단 | 반증 근거 |
|---|---|---|
| 24.1.4 말미 「대상은 호스트명으로 지정할 것. IP 로 지정하면 Kerberos 대신 NTLM 이 강제돼 티켓이 무시됨(§24.2.1)」 | 24.1.4 원문에 없어 창작으로 의심 | `src\24.2.1 Golden Ticket.md` 134행 「If we were to connect PsExec to **the IP address** of the domain controller instead of the hostname, we would instead **force the use of NTLM authentication** and access would still be blocked」 — 교차 참조가 정확. 유지 |
| 24.1.1 「WMI 로 만든 프로세스는 session 0 에 뜸」 | 배경지식 주입 의심 | 원문 18행 Info 블록에 그대로 있음. 유지(관리자 사전 확인분과 일치) |
| 24.1.1 · 24.1.4 그림 누락(`PEN200-Fig-311/312`) | 소실로 판정하려 함 | `SPEC.md` §4 「이해에 기여하지 않는 반복 스크린샷은 빼도 된다 — **빼는 것이 기본**이고 남기는 쪽에 이유가 있어야 한다」 — 누락이 규격상 정상. 결함 아님 |
| 23.2.4 「PAC 검증 기본 비활성」 여부 | 노트가 「기본 비활성」이라 단정했을 것으로 예상 | 노트는 「**선택적** 검증 절차 … 실제로 하는 경우가 드묾」으로 적어 원문(`optional` / `rarely perform`)과 정확히 일치. 과장 없음 |

## 게이트 재실행 (23–24장)

```
strictcheck.py 23 24  →  노트 코드블록 77개 검사 · 줄 단위 비정렬 0개
audit2.py      23 24  →  합성 0 / 소실 0 / 거짓 「추출 손상」 서술 0
covercheck.py  23 24  →  판정 근거 줄 48개 검사 · 소실 0
verify.py      23 24  →  완료 24 / 전체 24 · 미생성 0 · 결함 0
```

회귀 없음. 분량 비율도 결함 0 이므로 0.15~0.60 범위 유지.
