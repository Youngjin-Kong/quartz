---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# 웨이브 15 — `_PLAYBOOK.md` 단독 반영 기록

대상 박스 4개: MiddlewareBypass · Squid · Pelican · Sorcerer
백업: `03. PG\_backup\_PLAYBOOK.md.bak11`(반영 전 6291행)
결과: **6291행 → 6806행 (+515)** · 신규 카드 **8개** · 병합 **23곳** · 기각 **1건**

---

## 1. 처리한 입력 — 제안서 33건 + 감사자 추가 9건 = 42건

⚠️ **과업 지시의 「31건」은 실측과 어긋남.** 제안서 4개의 자체 검산 합계는 **33건**임:

| 파일 | 제안 건수 | 비고 |
|---|---|---|
| `MiddlewareBypass-playbook.md` | 7 | 검산절 「7건(병합 4·신규 3)」 — 감사자 정정 후 값 |
| `Squid-playbook.md` | 13 | 초판 11건 + 감사에서 이관 손실로 추가된 제안 12·13 |
| `Pelican-playbook.md` | 6 | |
| `Sorcerer-playbook.md` | 7 | |
| **합** | **33** | |

여기에 **`Sorcerer-audit.md` §4 「이관 손실 — 제안 7건에도 없는 것」 9건**이 붙어 **42건**임. 나머지 세 박스의 감사 파일에는 `_PLAYBOOK` 행 추가분이 없음(MiddlewareBypass·Pelican 의 「이관 손실 복원」은 전부 **박스 노트 쪽 복원**이었음 — 감사자가 이미 처리).

---

## 2. 신규 카드 8개 — 배정한 번호

| 번호 | 제목 | 출처 제안 |
|---|---|---|
| `A-1-27` | nmap 의 `Did not follow redirect to …` 는 진입 URL 을 통째로 알려준다 | Pelican 제안 2 |
| `A-3-14` | SSH 인증은 되는데 셸이 안 뜬다 — 강제 명령(`command=`)은 자기 자신을 정의하는 파일까지 막지 못한다 | Sorcerer 제안 1 + audit §4-3·§4-9 |
| `A-6-11` | 박스 이름·호스트명이 증거 사슬을 대신하면 시험장에서 무너진다 | MiddlewareBypass 제안 5 |
| `B-1-45` | Next.js 미들웨어 인가 우회 (CVE-2025-29927) — 그리고 앞단 인가 우회 6벡터 | MiddlewareBypass 제안 4 + 자체 발견 손실 |
| `B-1-46` | Tomcat CVE-2017-12617 — PUT + 트레일링 슬래시로 확장자 매퍼 우회 (JSP 업로드 RCE) | Sorcerer 제안 7 |
| `B-2-15` | 모르는 서비스를 만났을 때의 절차 — ZooKeeper 4자 명령이 그 표본 | Pelican 제안 4 |
| `B-3-15` | 코어 덤프에서 평문 자격증명 추출 — `sudo -l` 을 4가지 질문으로 판정하는 법 | Pelican 제안 3 |
| `B-72` | 오픈 프록시로 «셸 없이» 내부 포트를 연다 | Squid 제안 1 |

번호는 각 카테고리의 **현재 최대 다음**으로 배정함(A-1-26→27 · A-3-13→14 · A-6-10→11 · B-1-44→45,46 · B-2-14→15 · B-3-14→15 · B-71→72). **기존 항목의 번호·제목은 한 글자도 바꾸지 않음.**

---

## 3. 병합 23곳

| 대상 | 넣은 것 | 출처 |
|---|---|---|
| `A-1` 절(OS 지문 문단) | MikroTik 오탐 재현 + Pelican 코어 덤프의 `4.19.0-10-amd64` 실측 반증 | MB 제안 2, Pelican(자체 발굴) |
| `A-1-20` | 아카이브 확장자 누락 + `--scan-dir-listings` 요약줄 · `unzip -l` 숨은 파일 | Sorcerer 제안 5 |
| `A-12` | `certutil` 성공 배너의 조용한 실패(Windows 판) | Squid 제안 6 |
| `A-14` | 「대상이 하드코딩됐는가」 확인 항목 + `poc.sh` diff + `chmod`·`./` 셸 실수 | MB 제안 1 |
| `A-15` | feroxbuster auto-filter 가 307 을 지운 함정 · 탈출구 3종 | MB 제안 3 |
| `A-16` | 프록시 경유 300초 미완주 → 타겟형 전환 · 수동 curl 루프 | Squid 제안 8, Sorcerer audit §4-7 |
| `A-24` | 같은 서비스 1회 실패 ≠ 크리덴셜 무효 | MB 제안 6 |
| `A-2-27` | Squid SMB/RPC 배제표 · Pelican 미완 갈래표(JMX·CUPS·Samba) | Squid 제안 13, Pelican 제안 6 |
| `A-31` | 443→4444 포트 전환 흔적(`[가정]`, mtime 근거) | Squid 제안 10 |
| `A-37` | `command=` 래퍼에서도 `-O` 가 답 · `man scp` 인용 · `scp -h` 시행착오 | Sorcerer 제안 2 |
| `A-38` | SSH 셸은 이미 완전한 TTY | Sorcerer audit §4-6 |
| `A-41` | `dir C:\` vs `Get-ChildItem -Recurse` · `find -perm -4000` 선행 하이픈 · 권한상승 후보 비교표 | Squid 제안 9, Sorcerer audit §4-1·§4-8 |
| `B-1-10` | Exhibitor 행 + 감독 UI 일반화 3질문 + 원값 보존 경고 | Pelican 제안 1 |
| `B-1-14` | phpMyAdmin 토큰 갱신 · `trust_env=False` | Squid 제안 7 |
| `B-24` | 컴파일 «전» 소스의 `#define`·"Tested on" 을 읽을 것 | Sorcerer 제안 3(감사 권고대로 병합) |
| `B-2-12` | WampServer 가 렌더한 3307 이 미기동이었음 | Squid 제안 12 |
| `B-33` | `start-stop-daemon -- -p` · already-running exit 1 | Sorcerer 제안 4 + audit §4-2 |
| `B-42` | 스텁 1줄 → FullPowers 원리·출력 리다이렉트·판단 순서 | Squid 제안 2 |
| `B-46` | 빌드별 Potato 계열 비교표 | Squid 제안 3 |
| `B-81` | `INTO DUMPFILE`/`OUTFILE` Errcode 13·17 · `-enc` UTF-16LE · `.bat` 래핑 | Squid 제안 4 + 자체 발견 손실 |
| `B-82` | 스텁 **반증 후 교체**(아래 §4) + scp 후 `diff` 검증 | Squid 제안 5, Sorcerer audit §4-4 |
| `B-83` | 전송 3종 폴백(`wget`→`curl`→`/dev/tcp`) | Sorcerer audit §4-5 |
| `D` 실측표 | 4행 추가(MiddlewareBypass · Squid · Pelican · Sorcerer) | MB 제안 7, Squid 제안 11, Pelican 제안 5, Sorcerer(신규 계산) |

---

## 4. 기존 서술을 «반증»으로 교체한 곳 1건 — `B-82`

⚠️ 규율 ④의 예외 ⓐ에 해당. **제목·번호는 그대로 두고 본문만 교체함.**

**지운 원문(전문):**
> **유명 도구는 파일명만으로 삭제됨.** ([[Squid]] [[Exghost]])

**반증 근거:**
- Defender 에 「파일명 시그니처」 탐지 기전 자체가 없음(내용·행위·ML 기반, 파일명은 *제외 목록*에서만 쓰임)
- 관측된 `RealTimeProtectionEnabled=False` 는 쓰기 시점 스캔이 없었다는 뜻이라 자기 결론을 반박함
- PrintSpoofer 는 실제로 내용 기반 탐지(`HackTool:Win64/PrintSpoofer!MTB`) — 내용 기반이면 이름 변경으로 회피 안 됨

**새 원인은 `[가정]` 등급으로만 적었음** — 산출물은 「파일명 변경」과 「절대경로 지정」이 **동시에** 일어났음만 보여주므로 어느 쪽이 해결이었는지 가를 근거가 없음. **확정된 것은 AV 파일명 이론의 반증까지임.**
**`[[Exghost]]` 근거는 별개 박스라 확인하지 않았음** — 카드 본문에 「그쪽은 그대로 유효할 수 있음」을 명시해 남겼음(원 인용을 통째로 잃지 않도록).

---

## 5. 기각 1건

**Sorcerer 제안 6 — NFS `showmount` 미열거.** 과업 지시 ⑧대로 넣지 않음. 두 근거 모두 확인함:
1. 전제(「열거를 안 하고 넘어갔다」)가 `~/.zsh_history` 의 `showmount -e 192.168.120.100` 실행 기록에 반증됨
2. `F. 포트 → 첫 수` 표에 `111 · 2049 | rpcbind · NFS | 익스포트 목록 → no_root_squash 확인` 이 **이미 있음**(현재 6763행)

「관측 없음」으로 적힌 서술은 이번 반영본에 옮기지 않았음. 대신 **B-1-46(Tomcat)에서 같은 종류의 문구를 실측에 맞게 고쳐 적었음** — 「실행 로그 없음」이 아니라 **「PoC 를 6회 이상 실행했으나 출력이 보존되지 않아 결과는 관측 없음」**(Sorcerer audit §5 의 지적을 반영).

---

## 6. 자체 발견 — 제안서·감사 파일 어디에도 없던 이관 손실 2건

규율 ⑤에 따라 `git show <baseline>:"03. PG/<박스>.md"` 로 최초판을 뽑아 코드블록 단위로 대조함(스크립트: 블록별 줄 존재 여부를 현재 노트 ∪ 제안서 ∪ 감사파일 ∪ `_PLAYBOOK` 전체에서 검색). `.bak` 은 직전 개작본이라 baseline 으로 쓰지 않음.

**⑴ PowerShell `-enc` 의 base64 는 UTF-16LE 임** (Squid, baseline `3171152` 788~797행)
```
`-enc`의 base64는 **UTF-16LE**다 — 리눅스 습관대로 하면 반드시 실패한다:
# 틀림 (UTF-8)     echo -n '<명령>' | base64 -w0
# 맞음 (UTF-16LE)  echo -n '<명령>' | iconv -t UTF-16LE | base64 -w0
```
같은 문단의 **「인용 중첩이 2단을 넘으면 `.bat` 파일로 뺄 것」**(`cmd /c` → `.bat` → `PrintSpoofer -c` → `powershell` 4중)도 함께 소실돼 있었음. **`B-81` 에 복원함.**

**⑵ 앞단 인가 우회 6벡터의 «구체 페이로드 문자열»** (MiddlewareBypass, baseline `aba5a29` 544~551행)
제안 4는 이것을 「인가 우회 6벡터(헤더 주입·경로 정규화·…)는 전부 같은 뿌리」라는 **한 줄 요약**으로만 옮겼음. 실제 원문은 `//admin`·`/./admin`·`/admin/.`·`/%61dmin`·`/%2561dmin`·`/admin;x=1` 같은 **시험장에서 그대로 치는 문자열의 표**였음 — 요약만 남으면 카드의 실용 가치가 사라짐. **`B-1-45` 에 표째로 복원함.**

**소스 고고학은 걷어냄** — 같은 대조에서 나온 MiddlewareBypass 의 `middleware.ts` 취약/안전 코드 비교(2장), Sorcerer 의 Tomcat 매퍼 C 소스·패치 커밋 2건은 **깊이 기준 초과**로 판단해 옮기지 않았음(심사관 재현에 기여하지 않음). 원문은 baseline 커밋과 `_backup\*.bak` 에 그대로 있음.

---

## 7. 직접 실행해 확인한 것 (Kali `10.44.44.128`)

| 확인 대상 | 명령 | 결과 |
|---|---|---|
| feroxbuster 플래그 의미 | `feroxbuster --help` | **2.13.1** · `-D`=`--dont-filter` · `-C`=`--filter-status` · `-r`=`--redirects` · `--scan-dir-listings` 실재 — 제안 3·5의 주장 전부 정확 |
| `start-stop-daemon` 중복 인스턴스 | `start-stop-daemon -S -x /usr/bin/sleep -- 300`(sleep 이미 실행 중) | `/usr/bin/sleep already running.` + **exit 1** |
| `-p` 의 의미 | `start-stop-daemon --help` · `-S -x /bin/sh -p` | `-p`=`--pidfile` 확정. `--` 없으면 `option requires an argument -- 'p'` |

⚠️ **감사자 표현 「조용히 exit 1」은 부정확함** — `<경로> already running.` 을 실제로 «출력»함. 카드에는 실측 문구를 그대로 실었음.

---

## 8. 전수 검증 결과

| 항목 | 결과 |
|---|---|
| 헤딩 번호 중복 | **0** (`####` 241개 파싱) |
| 헤딩 제목 중복 | **0** (`Active Directory` 2건은 `### A-5` / `### B-5` 절 제목으로 **기존**·의도된 것) |
| 헤딩에 `\|` 포함 | **0** |
| 코드펜스 짝 | **균형**(576개, 짝수) |
| 박스 노트 → `_PLAYBOOK` 앵커 | **440건 전수 해석 성공 / 깨진 것 0** (신규 14건 포함) |
| 본문 내 카드 상호참조 | 실재하지 않는 번호 **0** (`B-110` 히트 1건은 14행의 «번호 규칙 설명» 자체) |

⚠️ **`_AUDIT`·`_WRITEUP-STANDARD` 쪽에는 깨진 `_PLAYBOOK#` 앵커가 27건 있으나 전부 «기존»이고 대부분 `…` 같은 축약 표기임**(예: `[[_PLAYBOOK#…]]`). 이번 작업 범위가 아니라 손대지 않았음.

---

## 9. 노트 쪽 변경 — `## 관련` 앵커만

| 노트 | 추가 |
|---|---|
| `MiddlewareBypass.md` | B-1-45 · A-15 · A-6-11 · A-24 (기존의 뭉뚱그린 `[[_PLAYBOOK]] — …여기로 이관` 한 줄을 구체 앵커 4개로 교체) |
| `Squid.md` | B-72 · B-42 · B-46 · B-82 |
| `Pelican.md` | A-1-27 · B-2-15 · B-3-15 |
| `Sorcerer.md` | A-3-14 · B-1-46 · B-24 |

**본문은 손대지 않았음.** `<박스>-playbook.md` 경로는 노트 어디에도 남기지 않았음.

---

## 10. 총괄 판단이 필요한 것

- **색인 갱신** — `refresh.ps1` 은 돌리지 않았음(공유 인프라). `_PLAYBOOK.md` 는 수동 프론트매터라 건너뛰기 대상이지만, 박스 노트 4개의 `## 관련` 링크가 늘어 `links` 메타가 바뀔 수 있음. 갱신 여부는 총괄 판단.
- **`_STATUS.md` 는 손대지 않았음**(§6). 이번 작업은 노트 상태 판정을 바꾸지 않음 — 4개 모두 이미 완료 등급이고 `_PLAYBOOK` 이관만 마무리된 것임.
- **`tech/ssh/*` 네임스페이스** — `Sorcerer-audit.md` §6 이 올린 taxonomy 건은 여전히 미결. 이번 반영으로 `A-3-14` 가 그 기법의 정본 카드가 됐으므로 태그를 살릴지 개명할지 판단이 필요함.
