---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# 웨이브 9 — `_PLAYBOOK` 단독 반영 기록

대상: `03. PG\_PLAYBOOK.md` (2107행/108항목 → **2917행/128항목**)
백업: `03. PG\_backup\_PLAYBOOK.md.bak6` (반영 전 원본)
입력 제안 4건 · **47건 전량 반영** — 신규 20 · 병합 27 · 기각 0
반영일: 2026-08-26

---

## 1. 번호 배정 — 신규 20건

배정 원칙: 각 카테고리의 현재 최대 번호 다음. 9개 초과 시 하이픈 한 번 더.
**기존 항목의 제목·번호는 한 건도 변경하지 않았음**(백업 대비 `grep "^#"` diff 로 검산 — 사라지거나 바뀐 기존 제목 **0건**).

| 번호 | 제목 | 출처 제안 |
|---|---|---|
| `A-1-15` | 웹이 상위 1000 포트 «밖»에만 있다 | Hawat 1 |
| `A-1-16` | Arch Linux 는 경로 관례가 다르다 | Hawat 12 |
| `A-1-17` | nmap 이 `filtered` 라고 적은 포트를 버렸다 | Outdated P5 |
| `A-2-13` | 노출된 소스와 «배포본»이 다르다 — 소스는 지도지 정답지가 아니다 | Hawat 2 |
| `A-2-14` | 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다 | Hawat 3 |
| `A-2-15` | 파일 읽기는 통했는데 «출력이 안 보인다» | Outdated P6 |
| `A-2-16` | 디렉터리 리스팅에 파일명은 보이는데 내용이 안 보인다 | Pebbles 3 |
| `A-2-17` | SQLi 는 찾았는데 데이터가 안 나온다 | Pebbles 4 |
| `A-38` | `python3` 가 없어 TTY 업그레이드가 안 된다 | Hawat 11 |
| `A-39` | 블라인드 RCE 는 되는데 셸이 안 붙는다 — 채널 제약(대소문자·길이·cwd)부터 계측한다 | ClamAV 4 |
| `A-66` | 조건을 바꾸는데 응답이 한 글자도 안 변한다 | Outdated P7 |
| `A-67` | blind 추출 결과를 믿기 전에 «완주했는가»부터 본다 | Pebbles 5 |
| `B-1-21` | 노출된 소스를 «먼저» 확보한다 — 화이트박스가 블랙박스보다 압도적으로 빠르다 | Hawat 6 |
| `B-1-22` | Nextcloud · ownCloud 를 만나면 WebDAV 를 직접 때린다 | Hawat 7 |
| `B-1-23` | 문서 변환기(HTML→PDF)는 서버측 파서다 — mPDF `<annotation>` 임의 파일 읽기 | Outdated P8 |
| `B-1-24` | Webmin package-updates 인증 후 RCE — CVE-2022-36446 | Outdated P9 |
| `B-1-25` | time-based blind SQLi 를 손으로 짠다 — sqlmap 금지 대비 | Pebbles 6 |
| `B-2-11` | clamav-milter black-hole 모드 RCPT TO 명령 주입 — CVE-2007-4560 | ClamAV 5 |
| `B-71` | 내부에만 열린 서비스는 SSH `-L` 로 끌어온다 | Outdated P10 (B-7 첫 항목) |
| `B-87` | 블라인드 RCE 의 오라클은 «내 HTTP 서버 액세스 로그»다 | ClamAV 6 |

**배정 판단 하나 — Hawat 제안 7(Nextcloud WebDAV)은 「B-2 또는 B-1」로 열려 있었음.** WebDAV 는 HTTP 위의 웹앱 프로토콜이고 B-2 는 FTP·SMB·SMTP 같은 비-HTTP 서비스 카드로 채워져 있어 **B-1(웹)로 배정**함(`B-1-22`).

## 2. 병합 27곳 — append 위치

| 대상 절 | 붙인 내용 | 출처 |
|---|---|---|
| `A-11` | 표에 [[Pebbles]] 행(8080 favicon/title Tomcat vs 서버헤더 Apache) + 「배너는 정체가 아님」·저레이트 스캔 서비스명 2단락 | Pebbles 1 |
| `A-12` | SMTP 판 — 554/250/무응답 셋 다 실행됨 + 「무응답 ≠ 큐 적재」 유보 | ClamAV 1 |
| `A-13` | `dpkg` 0.84 vs 실행 `/usr/local/sbin` 0.91 | ClamAV 2 |
| `A-15` | Webmin 「302 인데 본문은 거부 경고」 + `xnavigation=1` 리다이렉트 인과 | Outdated P1 |
| `A-17` | 웹 포트 여럿일 때 「같은 루트」와 「같은 Alias 공유」 구분 | Pebbles 2 |
| `A-31` | ⓐ Hawat 「443만 열림」 강등 ⓑ ClamAV egress 80·443·4444 전부 열림 ⓒ Outdated 「콜백 없음 ≠ 명령 안 돎」 ⓓ ClamAV 메일 큐 유령 wget | Hawat 10 · Outdated P2 · ClamAV 3 |
| `A-41` | SUID·caps·cron 이 전부 표준이면 답은 `ss -lntp` | Outdated P3 |
| `A-61` | 「쓰기 됐다 → DB 가 root」 오추론 + `secure_file_priv IS NULL` 인데 쓰기 성립 | Hawat 4 |
| `A-63` | 「성공한 쪽」 응답을 안 남기는 사고 + `-o resp_<단계>.html` 보험 | Outdated P4 |
| `B-12` | Pebbles(`LIMIT` 뒤 주입 · 해시 교차검증 · `PASSWORD()` 정정) + Hawat(출력채널 3개 봉쇄 표 · 오라클 셸함수 · 이진탐색 병렬 · `-- ` 공백 · `INTO OUTFILE` 3조건) | Pebbles 7 · Hawat 5 |
| `B-1-10` | 자매 사례 표(Cobbles 1.34.23 vs Pebbles 1.29.0) + 1.29 계열 view 3종 + 무인증 판정법 | Pebbles 8 |
| `B-23` | 형제 카드 `B-2-11` 상호 링크 | ClamAV 5 지시 2 |
| `B-34` | 웹서버 자체가 root → 웹셸이 곧 root 셸(Hawat nginx `user root;`) + 「쓴 주체 ≠ 실행 주체」 | Hawat 8 |
| `B-81` | SQL hex 리터럴(Hawat) + 문자 제약 우회로서의 base64(Outdated `/` 잘림) | Hawat 9 · Outdated P11 |
| `B-83` | 셸 잡기 «전»에도 도구 인벤토리 — ClamAV `nc`·`python`·`socat` 부재 | ClamAV 7 |
| `C-1` | filtered 포트 표로 적어두기(Outdated) + MTA/EICAR·`-p-`·`clock-skew`(ClamAV) | Outdated P12 · ClamAV 8 |
| `C-3` | 「목표가 파일 하나면 셸 만들지 마라」는 점수 기준으로 틀림 + 뒤늦게 셸 잡기가 더 어려움 | Pebbles 9 |
| `D` | Hawat 25분 구간표 · Outdated 12분 시간표 · Pebbles 손절표 · ClamAV 10분12초 채널제약 + 박스별 표에 2행 추가 | Hawat 13 · Outdated P13 · Pebbles 10 · ClamAV 9 |
| `E` | Outdated(msf 모듈 미사용 · 웹셸 회피 · `euid=0`≠root셸) · ClamAV(msf 대신 파이썬 30줄) · **Pebbles LOAD_FILE 0점 사례** | Outdated P14 · ClamAV 5 · **추가 판단** |
| `F-2` | `filtered` 포트를 목록에서 지우지 말 것 | Outdated P15 |

## 3. 기존 서술 정정 — 0건

**이번 반영에서 기존 `_PLAYBOOK` 서술을 고친 곳은 없음.** 제안 중 「반증됨」으로 표시된 것들은 전부 **박스 노트 원문**에 대한 반증이지 `_PLAYBOOK` 본문에 대한 것이 아니었음(예: Pebbles 의 `PASSWORD()` 해시, ClamAV 의 try5 길이 51, Hawat 의 「소스 리뷰에 상당한 시간」). 해당 정정 내용은 **새 서술로 append** 했고 원문 주장도 함께 인용해 남겼음.

## 4. 반증한 것 / 지시 검증

**⑴ 「`Connection to <host> closed.` 를 비대화형 신호로 적은 제안이 있으면 정반대이므로 고쳐 넣어라」 — 해당 제안 없음.**
4개 파일 전수 확인 결과 이 문자열이 나오는 곳은 `Outdated-playbook.md` D2 **한 군데뿐**이고, 거기서는 이미 정확하게 적혀 있었음:

> ⚠️ **다만 pty 자체는 실측으로 확인됨** — `proof_*.txt` 말미의 `Connection to 192.168.248.232 closed.` 는 pty 를 할당한 ssh 클라이언트만 출력하는 줄임(2026-08-26 Kali 실측: `ssh -tt host "cmd"` 는 출력, `ssh host "cmd"` 는 미출력). 그러므로 「프롬프트 캡처 없음」이지 「비대화형이었음」이 아님.

또한 D2 는 «노트에서 제거한 것» 절이라 애초에 `_PLAYBOOK` 이관 제안이 아님. **고칠 것이 없었음.**

**⑵ Pebbles 의 `PASSWORD()` 해시 정정을 로컬 재계산으로 독립 검증함.**
제안이 「`*4ACFE…9441` 은 `password` 가 아니라 `admin`」이라 적었는데, 그 주장 자체를 그대로 믿지 않고 직접 계산했음:
```python
'*'+hashlib.sha1(hashlib.sha1(pw.encode()).digest()).hexdigest().upper()
```
```text
password *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
admin    *4ACFE3202A5FF5CF467898FC58AAB1D615029441
zmpass   *C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E
```
**제안이 옳았음.** 세 값 모두 일치하므로 `B-12` 에 실은 세 해시가 전부 검증된 상태임.

**⑶ Pebbles 의 `LOAD_FILE` 0점 사례는 `E` 절에도 값이 있다고 판단해 추가함**(지시 ⑥의 판단 위임 항목).
근거 — `E` 절에 이미 「웹셸만이 아니라 «비대화형 명령 실행» 전부가 같은 지위임」 항목이 있고 거기 나열된 것이 Redis `system.exec`·단발 RCE·인젝션 한 줄임. **DB 채널 읽기(`LOAD_FILE`)는 정확히 그 목록의 빠진 칸**이라 하위 항목으로 붙였음. C-3 병합(제안 9)은 「무엇을 대신 했어야 하나」를 다루고, E 병합은 「규정상 왜 0점인가」를 다뤄 역할이 갈림 — 중복 아님.

**⑷ 제안 중 기각한 것 0건.** 47건 모두 산출물 경로·인과·`[가정]`·「관측 없음」이 붙어 있어 그대로 반영 가능했음.

## 5. 이관 손실 검사

제안의 「지우기 전 원문」과 대조해 아래가 살아 있는지 확인했음 — **손실 0**:

- **인과** — ClamAV `cd` 무시의 `;`/`|` 결합 우선순위 설명, Hawat 「0777 이라 쓰였고 `user root;` 라 root 로 실행됐다」, Outdated `xnavigation=1` 리다이렉트 분기, Pebbles 「`LIMIT` 뒤라 UNION 이 문맥상 까다로움」
- **소요 시간** — Hawat 25분/2분45초, Outdated 12분/4분/5분, Pebbles 31분/2분33초/문자당 10초, ClamAV 2분43초/10분12초/3분28초
- **`[가정]`** — ClamAV 유령 wget 인과·`cd` 가설·인용 없는 주소 미시험, Hawat `secure_file_priv` 오라클 응답 미보존·`userId=0` 강등, Pebbles UNION 시도 응답 미보존·스택 드라이버 표는 일반지식·`/zm` Alias, Outdated `confirm=1` 필수 여부·tcpdump 미보존
- **「관측 없음」** — ClamAV bash `/dev/tcp` 가부·`msg.*` 헤더 수법 미시도·64자 재확인 불가, Outdated `<annotation>` 속성 제거 실험 미실시
- **출처 경로** — `~/PG/<박스>/` 파일명 전량(`oracle.sh`·`blind.py`·`probe.py`·`shell.py`·`gob_*.txt`·`http_stager.log`·`listener443.log`·`shell_session.log`·`enum_user.txt`·`exploit_resp.html`·`resp2.html`·`lfi.sh`·`dbphp.out`·`proof.out` 등)
- **강등 유지** — Hawat 「아웃바운드 443만 열림」은 A-31 에 **강등된 형태로** 실었고(인바운드 스캔은 egress 근거가 아님), 원 단정도 함께 인용함

## 6. 박스 노트 `## 관련` 앵커 추가

| 노트 | 추가한 앵커 | 건수 |
|---|---|---|
| `Hawat.md` | A-1-15 · A-1-16 · A-2-13 · A-2-14 · A-38 · B-1-21 · B-1-22 | 7 |
| `Outdated.md` | A-1-17 · A-2-15 · A-66 · B-1-23 · B-1-24 · B-71 | 6 |
| `Pebbles.md` | A-2-16 · A-2-17 · A-67 · B-1-25 | 4 |
| `ClamAV.md` | A-39 · B-2-11 · B-87 | 3 |

**본문은 `## 관련` 외에 손대지 않았음.** 스테일한 「이관 제안 → `_AUDIT` 참조」 류 줄은 4개 노트 어디에도 없었음(전수 grep 확인).

⚠️ `Outdated.md` 27행의 `> 시행착오·교훈 → [[_PLAYBOOK]] — A-15 · A-31 · A-41 · A-63 · B-81` 은 **링크가 아니라 산문 요약**이라 그대로 뒀음. 틀린 것은 아니고 신규 6건이 빠져 있을 뿐임 — 본문 수정 금지 범위라 판단해 손대지 않았고, 보강이 필요하면 별도 판단 요망.

## 7. 검산

```
box notes scanned: 71 | anchors: 246 | broken: 0
```
- **앵커 전수 검증** — `03. PG\*.md` 박스 노트 71개의 `[[_PLAYBOOK#…]]` **246건 전부 실재하는 헤딩**. 깨진 것 **0**
- **번호 중복 0** — `#### ` 헤딩 128개의 항목번호 전량 유일
- **기존 제목 보존** — 백업 대비 `comm -23` 결과 사라지거나 바뀐 제목 **0건**
- **코드펜스 짝 맞음** — ``` 개수 짝수
- 항목 수 108 → **128**(+20) · 행수 2107 → **2917**(+810)

⚠️ **`_AUDIT` 파일이 하나 늘었으므로 색인 갱신이 필요함**(`refresh.ps1` 은 공유 인프라라 총괄 몫 — 이 작업에서는 실행하지 않았음). `_STATUS.md` 도 수정하지 않았음.
