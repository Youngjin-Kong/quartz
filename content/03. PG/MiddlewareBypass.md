---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
type: machine
platform: pg
os: linux
ip: 192.168.248.215
ports: [22, 3000]
services: [ppp, ssh]
cves: [CVE-2025-29927]
status: solved
tech_count: 1
---
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/MiddlewareBypass]
└─$ nnmap 192.168.248.215
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-19 10:10 +0900
Nmap scan report for 192.168.248.215
Host is up (0.086s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-Powered-By: Next.js
|     ETag: "yh2nq0gvow1u8"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2384
|     Vary: Accept-Encoding
|     Date: Wed, 19 Aug 2026 01:11:02 GMT
|     Connection: close
|     <!DOCTYPE html><html><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width"/><meta name="next-head-count" content="2"/><link rel="preload" href="/_next/static/css/6f9a5cffec7d2852.css" as="style"/><link rel="stylesheet" href="/_next/static/css/6f9a5cffec7d2852.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-8fa1640cc84ba8fe.js" defer=""></script><script src="/_next/static/chunks/framework-64ad27b21261a9ce.js" defer=""></script><script src="/_next/static/chunks/main-876326609259083c.js" defer=""></script><script src="/_nex
|   HTTPOptions:
|     HTTP/1.1 405 Method Not Allowed
|     Allow: GET
|     Allow: HEAD
|     Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
|     X-Powered-By: Next.js
|     ETag: "14ck9o6y74d1o1"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2161
|     Vary: Accept-Encoding
|     Date: Wed, 19 Aug 2026 01:11:03 GMT
|     Connection: close
|     <!DOCTYPE html><html><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width"/><title>405: Method Not Allowed</title><meta name="next-head-count" content="3"/><link rel="preload" href="/_next/static/css/6f9a5cffec7d2852.css" as="style"/><link rel="stylesheet" href="/_next/static/css/6f9a5cffec7d2852.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-8fa1640cc84ba8fe.js" defer=""></script><script src="/_next/static/
|   Help, NCP:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.98%I=7%D=8/19%Time=6A8502A7%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A1E,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20Next\.js\r\nET
SF:ag:\x20\"yh2nq0gvow1u8\"\r\nContent-Type:\x20text/html;\x20charset=utf-
SF:8\r\nContent-Length:\x202384\r\nVary:\x20Accept-Encoding\r\nDate:\x20We
SF:d,\x2019\x20Aug\x202026\x2001:11:02\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n<!DOCTYPE\x20html><html><head><meta\x20charSet=\"utf-8\"/><meta\x20n
SF:ame=\"viewport\"\x20content=\"width=device-width\"/><meta\x20name=\"nex
SF:t-head-count\"\x20content=\"2\"/><link\x20rel=\"preload\"\x20href=\"/_n
SF:ext/static/css/6f9a5cffec7d2852\.css\"\x20as=\"style\"/><link\x20rel=\"
SF:stylesheet\"\x20href=\"/_next/static/css/6f9a5cffec7d2852\.css\"\x20dat
SF:a-n-g=\"\"/><noscript\x20data-n-css=\"\"></noscript><script\x20defer=\"
SF:\"\x20nomodule=\"\"\x20src=\"/_next/static/chunks/polyfills-42372ed1304
SF:31b0a\.js\"></script><script\x20src=\"/_next/static/chunks/webpack-8fa1
SF:640cc84ba8fe\.js\"\x20defer=\"\"></script><script\x20src=\"/_next/stati
SF:c/chunks/framework-64ad27b21261a9ce\.js\"\x20defer=\"\"></script><scrip
SF:t\x20src=\"/_next/static/chunks/main-876326609259083c\.js\"\x20defer=\"
SF:\"></script><script\x20src=\"/_nex")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(NCP,2F,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,9B1
SF:,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nAllow:\x20GET\r\nAllo
SF:w:\x20HEAD\r\nCache-Control:\x20private,\x20no-cache,\x20no-store,\x20m
SF:ax-age=0,\x20must-revalidate\r\nX-Powered-By:\x20Next\.js\r\nETag:\x20\
SF:"14ck9o6y74d1o1\"\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCo
SF:ntent-Length:\x202161\r\nVary:\x20Accept-Encoding\r\nDate:\x20Wed,\x201
SF:9\x20Aug\x202026\x2001:11:03\x20GMT\r\nConnection:\x20close\r\n\r\n<!DO
SF:CTYPE\x20html><html><head><meta\x20charSet=\"utf-8\"/><meta\x20name=\"v
SF:iewport\"\x20content=\"width=device-width\"/><title>405:\x20Method\x20N
SF:ot\x20Allowed</title><meta\x20name=\"next-head-count\"\x20content=\"3\"
SF:/><link\x20rel=\"preload\"\x20href=\"/_next/static/css/6f9a5cffec7d2852
SF:\.css\"\x20as=\"style\"/><link\x20rel=\"stylesheet\"\x20href=\"/_next/s
SF:tatic/css/6f9a5cffec7d2852\.css\"\x20data-n-g=\"\"/><noscript\x20data-n
SF:-css=\"\"></noscript><script\x20defer=\"\"\x20nomodule=\"\"\x20src=\"/_
SF:next/static/chunks/polyfills-42372ed130431b0a\.js\"></script><script\x2
SF:0src=\"/_next/static/chunks/webpack-8fa1640cc84ba8fe\.js\"\x20defer=\"\
SF:"></script><script\x20src=\"/_next/static/");
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
1   85.22 ms 192.168.45.1
2   85.19 ms 192.168.45.254
3   85.87 ms 192.168.251.1
4   86.28 ms 192.168.248.215

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.93 seconds
```

### feroxbuster
```bash
┌──(kali㉿kali)-[~/PG/MiddlewareBypass]
└─$ feroxbuster -u http://192.168.248.215:3000/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.248.215:3000/
 🚩  In-Scope Url          │ 192.168.248.215
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
404      GET        1l       65w     2169c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
308      GET        1l        1w       20c http://192.168.248.215:3000/_next/static/chunks/ => http://192.168.248.215:3000/_next/static/chunks
200      GET        1l        1w      885c http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/_buildManifest.js
200      GET        1l        2w       77c http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/_ssgManifest.js
308      GET        1l        1w       12c http://192.168.248.215:3000/application/ => http://192.168.248.215:3000/application
200      GET        1l      102w     6558c http://192.168.248.215:3000/_next/static/chunks/664-fb5491d3140dd9e7.js
200      GET        1l       57w     1635c http://192.168.248.215:3000/profile
200      GET        1l       73w     1697c http://192.168.248.215:3000/_next/static/chunks/pages/index-f1f5166c2b73a744.js
200      GET        1l     2125w   112594c http://192.168.248.215:3000/_next/static/chunks/polyfills-42372ed130431b0a.js
308      GET        1l        1w       35c http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu/ => http://192.168.248.215:3000/_next/static/y--UTiBhyE-_5xl_ZjRqu
308      GET        1l        1w       13c http://192.168.248.215:3000/_next/static/ => http://192.168.248.215:3000/_next/static
308      GET        1l        1w       26c http://192.168.248.215:3000/_next/static/chunks/pages/ => http://192.168.248.215:3000/_next/static/chunks/pages
308      GET        1l        1w        4c http://192.168.248.215:3000/api/ => http://192.168.248.215:3000/api
200      GET        1l       33w     1430c http://192.168.248.215:3000/_next/static/chunks/webpack-8fa1640cc84ba8fe.js
308      GET        1l        1w        6c http://192.168.248.215:3000/_next/ => http://192.168.248.215:3000/_next
200      GET        1l        9w      471c http://192.168.248.215:3000/_next/static/chunks/pages/_app-87cee5540118d1b4.js
200      GET        3l      182w     7454c http://192.168.248.215:3000/_next/static/css/6f9a5cffec7d2852.css
308      GET        1l        1w       17c http://192.168.248.215:3000/_next/static/css/ => http://192.168.248.215:3000/_next/static/css
200      GET        1l       92w     2212c http://192.168.248.215:3000/logs
200      GET        1l       90w     2211c http://192.168.248.215:3000/reports
200      GET        1l       91w     2223c http://192.168.248.215:3000/settings
200      GET        1l       47w     1868c http://192.168.248.215:3000/_next/static/chunks/pages/logs-e08fbafd4209a311.js
200      GET        1l     2293w   116421c http://192.168.248.215:3000/_next/static/chunks/main-876326609259083c.js
200      GET        1l     2735w   139978c http://192.168.248.215:3000/_next/static/chunks/framework-64ad27b21261a9ce.js
200      GET        1l      115w     2384c http://192.168.248.215:3000/
200      GET        1l       57w     2062c http://192.168.248.215:3000/_next/static/chunks/pages/profile-aebf9cb7e58e98f1.js
200      GET        1l       45w     1863c http://192.168.248.215:3000/_next/static/chunks/pages/reports-38a4bd25a2bb0a76.js
200      GET        1l       46w     1875c http://192.168.248.215:3000/_next/static/chunks/pages/settings-40ca8c5913cdef6d.js
200      GET        1l       62w     1984c http://192.168.248.215:3000/_next/static/chunks/pages/unauthorized-ea91fdd0b13897c5.js
200      GET        1l      107w     2314c http://192.168.248.215:3000/unauthorized
[####################] - 4m    180192/180192  0s      found:29      errors:0
[####################] - 4m    180000/180000  714/s   http://192.168.248.215:3000/  
```

CVE-2025-29927 사용해서 /admin 접근

![[Pasted image 20260819111158.png]]

root:modeling-katja-lad-common

획득한 정보로 ssh 접근

```bash
┌──(kali㉿kali)-[~/PG/MiddlewareBypass/CVE-2025-29927]
└─$ ssh root@192.168.248.215
The authenticity of host '192.168.248.215 (192.168.248.215)' can't be established.
ED25519 key fingerprint is: SHA256:GYats4sApIm2CiXiv6CqklOr+LDIDCrer/01h6J9yFg
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.248.215' (ED25519) to the list of known hosts.
root@192.168.248.215's password:
Permission denied, please try again.
root@192.168.248.215's password:
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Aug 19 02:13:29 AM UTC 2026

  System load:  0.0               Processes:               155
  Usage of /:   56.8% of 9.75GB   Users logged in:         0
  Memory usage: 18%               IPv4 address for ens192: 192.168.248.215
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

137 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Apr 30 12:53:53 2025 from 192.168.118.6
root@nextjs:~# ls
proof.txt
root@nextjs:~# cat proof.txt
ba5f29a3abb6692d4a1676fc93864d6a
```

