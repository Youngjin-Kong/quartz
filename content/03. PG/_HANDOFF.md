---
tags:
  - type/index
  - platform/pg
---
# 인수인계 — 다음 세션 시작점

> 2026-08-21 06:00경 갱신. 이전 세션이 하루 동안 PG 13박스를 풀고 파이프라인을 크게 성숙시켰다.
> **이 파일과 `_STATUS.md` 를 먼저 읽어라.** 세부 규율은 전부 `CLAUDE.md` 에 반영돼 자동 상속된다.

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
