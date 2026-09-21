---
tags:
  - type/audit
  - platform/pg
type: audit
manual_tags: true
manual_cves: true
---
# Robust · Detection — 구조 개작분 적대적 검증 (2026-08-25)

범위 — 「이번 개작이 무언가를 깨뜨렸는가」 하나. 사실 판정 재실시 아님(1차 감사 완료분).
출처 — `03. PG\Robust.md` · `03. PG\Detection.md` · `_backup\Robust.md.bak3` · `_backup\Detection.md.bak2` · `_WRITEUP-STANDARD.md`. 외부 접속 없음(박스 정지).

## 방법

- `diff -u` 전문 대조 2건
- **비헤딩 행 다중집합 대조**(`grep -v '^#'` + `sort` + `diff`) — 헤딩 레벨·순서 변경에 가려진 문장 손실을 잡기 위함
- 실측 표식 개수 전후 대조 — 코드펜스 · `— 출처:` · `![[...]]` · `[가정]` · 「관측 없음」 · `[[_PLAYBOOK` · pty 프롬프트 · 플래그 값

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| Detection · 앞 절 Explanation `취약점이 UI 에 광고돼 있음(아래 스크린샷)` | 4항목 블록이 `Service Enumeration` **앞**으로 이동해, 「아래」의 첫 `![[...]]` 가 이제 인덱스 화면(`PG-Detection-changedetection-index-5000.png`)임. 가리키려던 `/settings` 화면은 그 아래 재현 절에 있음 → **참조가 다른 이미지를 먼저 맞힘** | `(아래 재현 절 스크린샷)` |
| Detection · 앞 절 Fix `아래 확인대로 표준 탈출 체인이` | 참조 대상(Kali jinja2 3.1.6 `SecurityError` 블록)이 한 절 건너로 멀어짐. 경쟁 후보는 없어 오도는 아니나 위치 불명확 | `아래 재현 절 확인대로` |

사실 서술 변경 없음. 방향어(「아래」)는 유지 — 두 참조 모두 실제로 아래에 있음.

## 삭제한 것

**없음.** 두 노트 모두 삭제·강등 0건.

## 반증한 것

**① Robust ② 불릿(302 인증 우회)은 창작이 아님 — 노트 내부 관측의 재조합임.**
지시는 「거기 없는 값·수치·메커니즘이 새로 등장했으면 창작」이라 했으나, 신설 불릿의 구성요소가 **전부 개작 전 노트에 이미 있었음**:

- 「인증 리다이렉트」·「302 후에도 본문을 렌더하는 것 자체가 인증 우회」 → `Vulnerability Fix` 4번째 불릿(백업에 존재)
- 「302 뒤에도 인증 뒤 화면을 전량 렌더」 → `Steps to reproduce` 2단계(백업에 존재)
- 「`exit`/`die` 없이 인증 뒤 화면을 전량 출력」 → 상세 절 산문(백업 116행)
- 「302 인데 본문 3030B」 코드펜스 → 상세 절(백업 109–113행)

신규 수치·신규 메커니즘 **0**. 판정 = 창작 아님, 강등 불요.

**② Robust 「세 취약점」 선언은 4항목 정합을 «개선»했음.**
개작 전에는 `Severity` 가 「**인증 우회 후** SQLi 로…」라고 인증 우회를 세는데 Explanation 은 2불릿(XFF·SQLi)뿐이라 **선언↔Severity 가 어긋나 있었음.** 3불릿이 되면서 Explanation ↔ Fix(4불릿) ↔ Severity ↔ Steps(6단계) 가 모두 대응됨.
Fix 가 4불릿인 것은 불일치가 아님 — 3번째(평문 저장 금지)는 체인 링크가 아니라 **가중 요인의 방어책**이고, Explanation 은 「접근 경로의 체인」을 셈.

**③ `Severity: High` 유지가 맞음.** 등급표상 Medium 은 「자격증명 노출 **단독**(코드 실행 아님)」인데 이 finding 은 무인증 상태에서 **대화형 OS 셸(SSH jeff)** 까지 감. Critical 은 「즉시 root/SYSTEM」이라 미달. High 가 유일하게 성립. 변경 없음.

**④ Detection 문장 손실 0 — 개작자 보고가 맞음.** 비헤딩 행 다중집합 대조 결과 차이는 **빈 줄 2개 증가**뿐. 삭제·요약·재작성된 문장 없음.

## 대조 수치

| 항목 | Detection(전→후) | Robust(전→후) |
|---|---|---|
| 행수 | 225 → 229 | 290 → 291 |
| 코드펜스 줄(``` ) | 22 → 22 | 34 → 34 |
| `— 출처:` 캡션 | 9 → 9 | 10 → 10 |
| `![[...]]` 임베드 | 2 → 2 | 4 → 4 |
| `[가정]` | 4 → 4 | 0 → 0 |
| 「관측 없음」 | 0 → 0 | 2 → 2 |
| `[[_PLAYBOOK` 링크 | 9 → 9 | 4 → 4 |
| pty 프롬프트 | `root@detection:~#` 4 → 4 | `jeff@ROBUST` 1 → 1 · `administrator@ROBUST` 1 → 1 |
| 플래그 값 | 1종 2회 유지 | 2종 각 2회 유지 |
| Kali 프롬프트(`kali㉿kali`) | 0 → 0 | 0 → 0 |
| 프론트매터 | 무수정(diff 무차이) | 무수정(diff 무차이) |

## 구조 판정

두 노트 모두 `_WRITEUP-STANDARD` 「단일 호스트(템플릿 4장)」 골격 충족.

```
## Target #1 – <IP>            (H2 래퍼 1개)
### Initial Access – <긴 서술형>   (4항목)
### Service Enumeration          (Port Scan Results 표 + nmap raw)
### Initial Access – <짧은 형>     (재현)
### Privilege Escalation – ...
### Post-Exploitation
## 관련                          (H2 유지)
```

- 두 `Initial Access` 제목 **서로 다름** — Obsidian 앵커 모호성 없음
  - Detection: `무인증 노출된 changedetection.io v0.45.1 알림 템플릿 Jinja2 SSTI 로 root 원격 코드 실행 (CVE-2024-32651)` vs `SSTI → root RCE`
  - Robust: `X-Forwarded-For 헤더 위조로 …` vs `XFF 우회 → SQLite UNION SQLi`
- `Port Scan Results` 표 · nmap raw 라인(`22/tcp   open  ssh …`) 양쪽 보존 → `extract.py` `PORT_RE` 정상 동작
- Detection `### Privilege Escalation – 없음` 절의 **4항목 생략 사유 문장 보존됨** — 「4항목(Explanation/Fix/Severity/Steps)은 생략함 — Initial Access 절이 이미 root 획득까지 포함」. 초기 접근이 곧 root 인 박스에 4항목을 지어 넣지 않은 것이 맞음
- Detection `**Local.txt value:**` = 「없음 — 이 박스는 `/root/proof.txt` 단일 플래그(harvest.sh 전수 탐색·포털 슬롯 1개로 확인)」 보존
- `> [!info] 요약` 콜아웃 내부에 코드펜스 **없음**(양쪽)

## 범위 밖 관찰 — 고치지 않음, 판정만

이번 개작이 만든 것이 아니고 1차 감사 통과분이라 손대지 않았음. 총괄 판단용으로만 기록.

1. **Robust — 「인증 리다이렉트」는 엄밀히는 추론임.** 노트에 남은 실측은 「`/home.php` 가 302 이고 본문 3030B」까지이고, **302 의 목적지(`login.php` 여부)가 산출물 인용에 없음.** 「인증」 리다이렉트라는 성격 규정은 `login.php` 게이트 존재로부터의 추론. 백업에도 동일 서술이 `Fix`·`Steps` 양쪽에 있어 이번 개작이 새로 만든 것은 아님. 강등한다면 `[가정]` 한 개면 충분(현재는 미표기).
2. **Robust — `Severity` 괄호 주석의 내부 긴장.** 「(아직 코드 실행은 아니나 …)」인데 같은 절 `Steps` 6단계가 SSH 로그인(= OS 셸)으로 끝남. 등급 자체는 High 로 정당하나 괄호 문구는 finding 종착점과 어긋남. 백업에도 동일.
3. **Detection — 재현 절의 고아 `---` 수평선.** 스크린샷 캡션과 `**RCE 확인**` 사이. 백업에서도 같은 상대 위치라 이번 개작의 산물 아님. 무해.

## 문체 이관

**0건.** 서술형 종결·번역투 발견 없음(개작이 문장을 새로 쓰지 않았음).
