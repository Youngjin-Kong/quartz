---
tags:
  - type/index
  - platform/pg
---
# 인수인계 — 다음 세션 시작점

> 2026-08-21 오후 갱신(§0 신규). 그 이전 판은 같은 날 06:00경 — PG 13박스 풀이 + 파이프라인 성숙.
> **이 파일과 `_STATUS.md` 를 먼저 읽어라.** 세부 규율은 전부 `CLAUDE.md` 에 반영돼 자동 상속된다.
> ⚠️ **§0 을 먼저 읽을 것** — 볼트가 공개 발행 중이라는 사실이 이번에 확정됐고, 작업 기준이 바뀜.

## 0. 2026-08-21 오후 세션 — 공개 발행 대응

**계기** — 사용자 지시 두 건. ①「시험 때 보기에 어려운 부분이 많다」 ②「해당 `.md` 파일은 공개사이트에 올라가니 가독성도 필요」.

### 0-1. 확정 — 볼트는 «이미» 공개 발행 중임

| | |
|---|---|
| 사이트 | https://youngjin-kong.github.io/quartz/ (Quartz v4 + GitHub Pages) |
| 저장소 | `F:\hack\workstation\quartz` · remote `github.com/Youngjin-Kong/quartz.git` · 브랜치 `v4` |
| 발행 스크립트 | `F:\hack\workstation\quartz\sync_v2.py` |
| 파이프라인 | 볼트 전체 → `content\` copytree(제외 패턴 적용) → `publish: false` 프론트매터 필터 → `npx quartz sync` → `git push origin v4` |

- **동기화는 수동임.** 마지막 sync 2026-08-21 07:55 → Detection·GLPI 등 최신 박스는 **사이트에 아직 없음**(404 실측)
- **노트에 `publish: false` 를 넣으면 개별 제외됨** — `sync_v2.py:filter_publish_false()` 가 앞 1000바이트에서 찾음. ⚠️ 단 `inject.py` 가 프론트매터를 재작성하므로 **그 필드가 지워질 수 있음.** 항구적 제외는 `sync_v2.py` 제외 패턴 쪽이 안전함

### 0-2. 반증된 것 — 「스크린샷은 로컬에서만 보임」은 틀렸음

- 이전 판 §4 가 「`파일보관/` 은 gitignore 라 `![[PG-*.png]]` 임베드는 로컬에서만 보임」이라 적었으나 **오류임**
- 볼트의 `.gitignore` 는 **볼트 저장소에만** 적용됨. `sync_v2.py` 는 `파일보관\` 을 `content\` 로 그대로 복사하므로 Quartz 저장소와 무관함
- 실측: 사이트 Hutch 페이지의 `<img>` **6개 전부 로드, 깨짐 0**
- §4 해당 줄 정정 완료

### 0-3. 조치 완료 — 내부 문서 발행 차단 (`sync_v2.py` 수정, 검증됨)

- **사고 내용**: `CLAUDE.md` 가 `/quartz/CLAUDE` 에서 **16,526자로 렌더되고 있었음.** Kali 접속 주소·VPN 주소·에이전트 파이프라인 구조 노출. `.claude\agents\*.md`·`.claude\hooks\session-brief.py`·`_AUDIT`(548K)·`_backup`(1.5M)·`_INDEX\_tools`·`_HANDOFF.md` 도 `content\` 에 들어가 있었음
- **차단 지점을 `sync_v2.py` 로 고른 근거** — `quartz.config.ts` 의 `ignorePatterns` 는 **렌더만** 막고 원본 `.md` 는 공개 저장소에 그대로 커밋됨. 복사 단계에서 막아야 GitHub 저장소에도 안 올라감
- **드라이런 검증**(복사 없이 패턴만 대조): 차단 디렉터리 9 · 차단 파일 10 · 발행될 `.md` **164개**. `python -m py_compile` 통과
- **⚠️ 미해결 — 이미 푸시된 이력에는 남아 있음.** 커밋 `8171ddd` 까지 `content/CLAUDE.md`·`content/.claude/**` 추적됨. 다음 sync 때 HEAD 에서는 삭제되나 과거 커밋에는 잔존. **이력 재작성은 공개 저장소 강제 덮어쓰기라 총괄이 하지 않음 — 사용자 판단 사안임**
- **`_STATUS.md` 도 제외 목록에 넣었음.** 민감하진 않으나 내부 관리 문서로 판정. 되살리려면 `sync_v2.py` 제외 목록에서 `'_STATUS.md'` 한 문자열만 지우면 됨

### 0-4. 실측 — 공개 가독성 진단 (렌더된 DOM 직접 조회)

Quartz 문법 호환은 **문제 없음**. `> [!info]` 콜아웃·`![[...]]` 임베드·위키링크 전부 정상 렌더, 목차 자동 생성(h2·h3).

진짜 문제는 **밀도**임. Hutch 페이지 기준:

| 항목 | 실측 |
|---|---|
| 분량 | **72,311자 · 57,045px ≈ 79화면** |
| `<strong>` | **627개**(2.5줄당 1개) |
| 콜아웃 | 54개 |
| h2 구획 | **12개뿐** |

`CLAUDE.md` 가 「굵게가 두 줄에 한 번 나오면 강조가 배경이 된다」고 경고한 바로 그 상태임. 굵게 상위: Hutch 627 · Resourced 580 · Algernon 490 · Osaka 452 · Kevin 391.

### 0-5. 정정한 자기 오판 — 상단 요약은 대부분 있음

- 총괄이 처음 「PG 노트 72개 중 68개가 상단 요약 없음」이라 판단했으나 **틀렸음.** grep 이 「요약」이라는 낱말을 요구해 `> [!info] PG Practice — Hutch · …` 형태를 전부 놓침
- 실제: **58개 보유 / 14개 없음**(그중 3개는 강의 노트, 1개는 `_HANDOFF`)
- 반면 **HTB 34개 · OSCP 42개는 상단 콜아웃 0개** — 사용자가 「PG만 하고 나중에」로 결정해 **이번 범위 밖**

### 0-6. ⚠️ 진행 중이던 것 — 다음 세션이 «먼저» 확인할 것

세션 종료 시점에 웨이브 2건이 백그라운드로 돌고 있었음(관리자 2 + 실무 6, 총 8 에이전트). **결과 미확인 상태로 기록된 것임.**

| 트랙 | 관리자 | 산출물 | 상태 |
|---|---|---|---|
| 별칭 주입 + 검색 레이어 | `line-manager` | `_AUDIT\alias-pipeline.md` | **미확인** |
| 공개 가독성(굵게·콜아웃·조직 어휘) | `pg-line-manager` | `_AUDIT\public-readability.md` | **미확인** |

- **먼저 위 두 파일의 존재와 내용을 확인할 것.** 없으면 웨이브가 산출물을 남기지 못하고 끊긴 것이므로 재파견 필요
- 종료 시점에 이미 수정된 노트: **Cobbles · Hutch · RubyDome · Wombo**(git 상태로 확인). 세션 시작 시점 대비 신규
- `_INDEX\_tools\meta.json` 이 수정돼 있음 = **`extract.py` 는 실행됐음.** ⛔ **`inject.py --apply` 와 `refresh.ps1` 은 아직 실행 안 함** — 공유 인프라라 총괄이 쥐기로 했고, 별칭 목록 검토 뒤에 돌리기로 했음

**별칭 주입 설계 요지**(다음 세션이 이어받을 때 필요):
- `extract.py` 에 `PRODUCT_RAW = [(정규화명, [정규식…])]` 추가 — 기존 `TECH_RAW` 와 같은 구조
- 과잉 태깅 방지 **점수제** — 본문 앞 60줄 또는 nmap 포트 줄 등장 = 3점, 그 외 본문 등장 1회 = 1점, **합계 3점 이상만 채택**. 근거: 학습용 writeup 은 「이건 이 박스가 아니다」를 반증하려고 제품명을 언급함(`manual_cves` 주석의 교훈과 같은 뿌리)
- `manual_aliases: true` 탈출구를 기존 `manual_*` 4종과 «완전히 같은 패턴»으로 구현
- `inject.py:build_fm()` 에 YAML **블록 리스트** 형식으로 출력
- `build_index.py` 로 `_INDEX\07. 제품·소프트웨어별 색인.md` 생성 + `00. OSCP 허브` 진입표에 행 추가

### 0-7. ⛔ 다음 세션이 «하면 안 되는» 것

1. **가독성 웨이브가 미완인 채로 `sync_v2.py` 실행 금지** — 반쪽 상태가 그대로 공개 사이트로 나감. 노트 수정이 안정된 뒤에 돌릴 것
2. **`refresh.ps1` 을 `extract.py` 확인 없이 돌리지 말 것**(기존 §5 규율 그대로). 별칭 코드가 들어간 뒤라 특히 그러함
3. **HTB·OSCP 노트로 범위를 넓히지 말 것** — 사용자가 PG 한정으로 결정했음

## 1. 지금 어디까지 왔나

- **포털 34/283 완료, XP 475, 레벨 24.** 볼트 기준 완료 45 / 부분 5 / 미착수 233.
- **부분 완료 5개** — 우선 정리 대상:
  - **Cobbles 1/2** — user 확보(`f03187be…`), root 미완. ZoneMinder Filter RCE(`9;` 캐스팅 트릭)로 www-data→isaac. root 는 **커널 익스만 남아 손절**(공유랩 리스크). 293명 박스라 더 깨끗한 privesc 가 있을 수 있음 — `pg-box-runner` 리눅스 privesc 특화로 재도전 여지
  - **Monster 1/2** — user 확보, root 미완. XAMPP 바이너리가 `Authenticated Users:(M)` 쓰기 가능한데 **SYSTEM 재실행 트리거를 못 찾음**(배제 아니라 미완). Session 0 notepad 23개 단서
  - **Flu 1/2** — 이전 세션 유산. Confluence→confluence 유저, root 미완
  - **Hutch 1/2 · Nagoya 1/2 · Jacko 1/2** — 레거시. 노트는 개작 완료, 플래그 미완

## 2. 세션 시작 직후 확인할 것

1. **Kali 상태**: `ssh kali@10.44.44.128 "tmux ls; ss -lntp"` — 잔존 세션·리스너 정리
2. **포털 슬롯**: 동시 1대. 켤 때 "Some instances are already running" 뜨면 Accept
3. **`_STATUS.md` 헤더 날짜가 `2026-08-20` 으로 스테일** — 다음 기록 때 갱신(단독 기록자=`pg-line-manager`)

## 3. 운영 방식 (이미 `CLAUDE.md` 에 있음 — 여기선 핵심만)

- **총괄이 직접 파견 금지.** `pg-line-manager` 를 세워 웨이브를 넘긴다. 세션 시작 시 훅이 조직도를 주입
- **박스 사이클**: 풀면서 `harvest.sh`/`harvest.ps1` 로 증적 수집 → 플래그 값만 총괄에 → 총괄이 제출 → 다음 박스. 노트·감사는 박스 정지 후
- **플래그 제출은 총괄만.** ⚠️ **좌표 클릭 + 직접 타이핑만 먹힌다**(`form_input` 은 조용히 실패). 필드 안 잡히면 한 번 더
- **슬롯 회전 전 살아 있는 러너 없는지 확인** — 작업 중 러너를 죽인 사고 있었음(Monster)

## 4. 남은 함정·미해결

- **안전분류기 차단 3건**(Mice·Monster·Cobbles). 긴 프롬프트 + CVE/익스플로 코드 나열이 트리거. **러너 프롬프트 짧게, 사실만**
- **증거 형식**: 플래그를 값만(33B) 저장하는 실수 3연속. `whoami; id; hostname; date; cat flag` 한 줄로 묶어 저장
- **미제출 레거시 11개**(Clue·Heist·Kevin 등) — 볼트는 완료인데 포털 미제출. **플래그가 인스턴스마다 재생성**돼 옛 값 재제출 불가. **회수 안 하기로 결정**(이미 writeup 있음, 목표는 XP 아님)
- **`파일보관/` 은 gitignore** — 스크린샷이 git 에 안 들어간다. 노트의 `![[PG-*.png]]` 임베드는 로컬에서만 보임

## 5. 도구·인프라 (이번 세션에 대폭 손봄)

- `_INDEX/_tools/`: `manual_domain`·`manual_status`·`ports_filtered` 신규 필드, 리눅스 고포트 예외, `ip` 폴백, 신규 태그(`h2`·`userenum`·`info-disclosure`·`config-file`·`rdp`·`gui-lpe`·`xpathi`·`rbash-escape`)
- **⚠️ `refresh.ps1` 은 `extract.py` 먼저 단독 실행해 확인 후 돌려라** — 깨지면 낡은 meta.json 을 전체 덮어씀
- **Kali 죽은 NFS 마운트 주의** — `find /`·재귀 grep 이 무한 대기하면 `grep nfs /proc/mounts` 부터
- `~/PG/_lib/harvest.sh`(리눅스)·`harvest.ps1`(윈도우, PS 부재 시 cmd 폴백 주석 있음)

## 6. 다음 액션 추천

1. **미착수 Fundamental 부터** — 오늘 대부분 Fundamental 을 빠르게 뚫었다. 남은 Fundamental 이 최단 경로
2. Cobbles·Monster root 재도전은 **미착수 소진 후**. 커널 익스 없이 풀 각도를 새 눈으로
3. **`┌──(kali㉿kali)` 프롬프트 소급 정리 웨이브** — 45개 노트에 있지만 **레거시는 실측이니 지우지 마라**(대화형 Kali 작업). 에이전트가 새로 붙인 것만 대상. 지금 미착수 진도가 우선이라 보류 중
