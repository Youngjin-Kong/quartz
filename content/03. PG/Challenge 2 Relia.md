---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/unsolved
  - tech/svc/smb
  - tech/enum/dirbust
type: machine
platform: pg
os: windows
ip: 192.168.157.250
ports: [80, 135, 139, 445, 3389, 5985, 5986, 8000, 47001]
services: [http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn, ssl/wsmans]
status: unsolved
tech_count: 2
---
## 192.168.157.250
## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Relia/250]
└─$ nnmap 192.168.157.250
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 15:05 +0900
Nmap scan report for 192.168.157.250
Host is up (0.089s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WINPREP
|   NetBIOS_Domain_Name: WINPREP
|   NetBIOS_Computer_Name: WINPREP
|   DNS_Domain_Name: WINPREP
|   DNS_Computer_Name: WINPREP
|   Product_Version: 10.0.22000
|_  System_Time: 2026-08-13T13:09:06+00:00
| ssl-cert: Subject: commonName=WINPREP
| Not valid before: 2026-07-14T14:43:07
|_Not valid after:  2027-01-13T14:43:07
|_ssl-date: 2026-08-13T13:09:21+00:00; +7h00m00s from scanner time.
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/wsmans?
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T12:59:11
|_Not valid after:  2036-08-10T12:59:11
| tls-alpn:
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/13%OT=135%CT=1%CU=31552%PV=Y%DS=4%DC=T%G=Y%TM=6A7D5F
OS:91%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=101%TI=I%CI=I%TS=U)SEQ(SP=
OS:103%GCD=1%ISR=10E%TI=I%CI=I%TS=U)SEQ(SP=104%GCD=1%ISR=105%TI=I%CI=I%TS=U
OS:)SEQ(SP=107%GCD=1%ISR=108%TI=I%CI=I%TS=U)SEQ(SP=FF%GCD=1%ISR=102%TI=I%TS
OS:=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M540NW8NN
OS:S%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=N
OS:)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%R
OS:D=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=
OS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%U
OS:N=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time:
|   date: 2026-08-13T13:09:08
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   87.47 ms 192.168.45.1
2   87.43 ms 192.168.45.254
3   88.33 ms 192.168.251.1
4   89.49 ms 192.168.157.250

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 204.92 seconds
```

nxc-sweep 진행
```bash
┌──(kali㉿kali)-[~/PG/Relia/250]
└─$ nxc-sweep 192.168.157.250 -u offsec -p lab
[*] Starting NXC sweep for 192.168.157.250 as offsec ...

[+] Port 445 open. Checking smb ...
SMB         192.168.157.250 445    WINPREP          [*] Windows 11 Build 22000 x64 (name:WINPREP) (domain:WINPREP) (signing:False) (SMBv1:False)
SMB         192.168.157.250 445    WINPREP          [+] WINPREP\offsec:lab
SMB         192.168.157.250 445    WINPREP          [*] Enumerated shares
SMB         192.168.157.250 445    WINPREP          Share           Permissions     Remark
SMB         192.168.157.250 445    WINPREP          -----           -----------     ------
SMB         192.168.157.250 445    WINPREP          ADMIN$                          Remote Admin
SMB         192.168.157.250 445    WINPREP          C$                              Default share
SMB         192.168.157.250 445    WINPREP          IPC$            READ            Remote IPC

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.157.250 5985   WINPREP          [*] Windows 11 Build 22000 (name:WINPREP) (domain:WINPREP)
WINRM       192.168.157.250 5985   WINPREP          [-] WINPREP\offsec:lab

[+] Port 3389 open. Checking rdp ...
RDP         192.168.157.250 3389   WINPREP          [*] Windows 10 or Windows Server 2016 Build 22000 (name:WINPREP) (domain:WINPREP) (nla:True)
RDP         192.168.157.250 3389   WINPREP          [+] WINPREP\offsec:lab (Pwn3d!)
```

xfreerdp3 접근 불가
```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /v:192.168.157.250 -u offsec -p lab
[15:32:32:183] [63684:0000f8c4] [ERROR][com.winpr.commandline] - [CommandLineParseArgumentsA]: Failed at index 1 [<censored: build with -DWITH_DEBUG_UTILS_CMDLINE_DUMP=ON for details>]: Invalid sigil

xfreerdp3 - A Free Remote Desktop Protocol Implementation
To show full command line help type
xfreerdp3 /?

```


## 192.168.157.249
## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Relia/249]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Thu Aug 13 16:04:58 2026 as: /usr/lib/nmap/nmap --privileged --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.157.249
Warning: 192.168.157.249 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.157.249
Host is up (0.087s latency).
Not shown: 64137 closed tcp ports (reset), 1383 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: LEGACY
|   NetBIOS_Domain_Name: LEGACY
|   NetBIOS_Computer_Name: LEGACY
|   DNS_Domain_Name: LEGACY
|   DNS_Computer_Name: LEGACY
|   Product_Version: 10.0.20348
|_  System_Time: 2026-08-13T14:06:57+00:00
| ssl-cert: Subject: commonName=LEGACY
| Not valid before: 2026-08-12T12:58:46
|_Not valid after:  2027-02-11T12:58:46
|_ssl-date: 2026-08-13T14:07:08+00:00; +6h59m59s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/wsmans?
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T13:01:25
|_Not valid after:  2036-08-10T13:01:25
8000/tcp  open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.157.249:8000/dashboard/
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/13%OT=80%CT=1%CU=36006%PV=Y%DS=4%DC=T%G=Y%TM=6A7D6D1
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=107%TI=I%CI=I%TS=U)SEQ(SP=1
OS:05%GCD=1%ISR=107%TI=I%CI=I%TS=U)SEQ(SP=105%GCD=1%ISR=10A%TI=I%CI=I%TS=U)
OS:SEQ(SP=108%GCD=1%ISR=109%TI=I%CI=I%TS=U)SEQ(SP=F7%GCD=1%ISR=106%TI=I%CI=
OS:I%TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M540N
OS:W8NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-13T14:06:58
|_  start_date: N/A
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   84.08 ms 192.168.45.1
2   84.02 ms 192.168.45.254
3   85.58 ms 192.168.251.1
4   85.73 ms 192.168.157.249

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 13 16:07:09 2026 -- 1 IP address (1 host up) scanned in 131.01 seconds
```
## Enum

8000포트 웹페이지 발견 후 웹열거
```bash
┌──(kali㉿kali)-[~/PG/Relia/249]
└─$ feroxbuster -u http://192.168.157.249:8000/cms/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.157.249:8000/cms
 🚩  In-Scope Url          │ 192.168.157.249
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
302      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       30w      307c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       30w      348c http://192.168.157.249:8000/cms => http://192.168.157.249:8000/cms/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/media
301      GET        9l       30w      354c http://192.168.157.249:8000/cms/media => http://192.168.157.249:8000/cms/media/
404      GET        9l       33w      304c http://192.168.157.249:8000/.php
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/templates
301      GET        9l       30w      358c http://192.168.157.249:8000/cms/templates => http://192.168.157.249:8000/cms/templates/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/Templates
301      GET        9l       30w      358c http://192.168.157.249:8000/cms/Templates => http://192.168.157.249:8000/cms/Templates/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/images/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/js/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/images/home.png
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/style.css
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/templates/images/favicon.png
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/js/admin.js
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/templates/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/templates/images/
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/
200      GET       36l       82w     1117c http://192.168.157.249:8000/cms/admin.php
404      GET        9l       33w      304c http://192.168.157.249:8000/.txt
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/files
301      GET        9l       30w      354c http://192.168.157.249:8000/cms/files => http://192.168.157.249:8000/cms/files/
200      GET        1l        4w       33c http://192.168.157.249:8000/cms/templates/plain.tpl
200      GET      115l      579w     6063c http://192.168.157.249:8000/cms/templates/mobile.tpl
200      GET      115l      579w     6063c http://192.168.157.249:8000/cms/Templates/mobile.tpl
200      GET       57l      418w     4801c http://192.168.157.249:8000/cms/Templates/photo.css
200      GET      137l      363w     6915c http://192.168.157.249:8000/cms/templates/mobile-old.css
200      GET        3l        9w      306c http://192.168.157.249:8000/cms/templates/editor.css
200      GET       27l      116w     1421c http://192.168.157.249:8000/cms/templates/rss.tpl
200      GET       91l      562w     5989c http://192.168.157.249:8000/cms/templates/default.tpl
200      GET        9l       33w      514c http://192.168.157.249:8000/cms/templates/sitemap.tpl
200      GET       22l       85w     1310c http://192.168.157.249:8000/cms/templates/style.css
200      GET       70l      496w     5845c http://192.168.157.249:8000/cms/templates/photo.tpl
200      GET       57l      418w     4801c http://192.168.157.249:8000/cms/templates/photo.css
200      GET       27l       97w     1375c http://192.168.157.249:8000/cms/templates/mobile.css
200      GET      202l      777w    13659c http://192.168.157.249:8000/cms/templates/common.css
200      GET        4l       11w     1331c http://192.168.157.249:8000/cms/templates/images/bg_subnav.png
200      GET        4l       16w      868c http://192.168.157.249:8000/cms/templates/images/comment_add.png
200      GET        4l        9w      243c http://192.168.157.249:8000/cms/templates/images/checkall.png
200      GET        3l        8w     1128c http://192.168.157.249:8000/cms/templates/images/tick.png
200      GET        5l       11w      325c http://192.168.157.249:8000/cms/templates/images/external_link.png
200      GET        4l       26w      603c http://192.168.157.249:8000/cms/templates/images/favicon.png
200      GET        4l       13w     1159c http://192.168.157.249:8000/cms/templates/images/comments.png
200      GET        9l       33w     2103c http://192.168.157.249:8000/cms/templates/images/enlarge.png
200      GET        9l       56w     3929c http://192.168.157.249:8000/cms/templates/images/ritecms36.png
200      GET       21l       60w     3363c http://192.168.157.249:8000/cms/templates/images/refreshg.png
200      GET        7l       18w     1185c http://192.168.157.249:8000/cms/templates/images/previous.png
200      GET        6l       20w     1638c http://192.168.157.249:8000/cms/templates/images/close.png
200      GET       21l       84w     1030c http://192.168.157.249:8000/cms/templates/subtemplates/overview.default.inc.tpl
200      GET       10l       24w     1240c http://192.168.157.249:8000/cms/templates/images/lock_open.png
200      GET        5l       18w     2371c http://192.168.157.249:8000/cms/templates/images/bg_top.png
200      GET        1l        3w     1241c http://192.168.157.249:8000/cms/templates/images/favicon.ico
200      GET        3l       10w      521c http://192.168.157.249:8000/cms/templates/images/quote.png
200      GET       26l       91w     5170c http://192.168.157.249:8000/cms/templates/images/refreshb.png
200      GET        5l        9w     1321c http://192.168.157.249:8000/cms/templates/images/bg_th.png
200      GET        3l        7w     2330c http://192.168.157.249:8000/cms/templates/images/zip.png
200      GET        6l       22w     1236c http://192.168.157.249:8000/cms/templates/images/rss.png
200      GET       11l       36w     1946c http://192.168.157.249:8000/cms/templates/images/reduce.png
200      GET        3l       17w     1202c http://192.168.157.249:8000/cms/templates/images/homepage.gif
200      GET        5l       17w     1305c http://192.168.157.249:8000/cms/templates/images/lock.png
200      GET        6l        9w     1765c http://192.168.157.249:8000/cms/templates/images/previous_hover.png
200      GET       10l       41w     3166c http://192.168.157.249:8000/cms/templates/images/ritecms28.png
200      GET        5l       14w     1194c http://192.168.157.249:8000/cms/templates/images/next.png
200      GET       34l      190w     2277c http://192.168.157.249:8000/cms/templates/subtemplates/image.inc.tpl
200      GET       32l      141w     1285c http://192.168.157.249:8000/cms/templates/subtemplates/notes.inc.tpl
200      GET        4l       21w     1107c http://192.168.157.249:8000/cms/templates/images/caution.png
200      GET        3l       11w     2002c http://192.168.157.249:8000/cms/templates/images/delete_link.png
301      GET        9l       30w      352c http://192.168.157.249:8000/cms/cms => http://192.168.157.249:8000/cms/cms/
200      GET       36l       82w     1117c http://192.168.157.249:8000/cms/Admin.php
200      GET       80l      546w    51974c http://192.168.157.249:8000/cms/templates/images/download.png
200      GET       64l      425w    36214c http://192.168.157.249:8000/cms/templates/images/404.png
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/cms/js/main.js
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/rss
200      GET        7l       39w     2010c http://192.168.157.249:8000/cms/templates/images/ritecms-powered.png
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/templates/style.css
200      GET       31l      117w     1462c http://192.168.157.249:8000/cms/index.php
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/Files
301      GET        9l       30w      354c http://192.168.157.249:8000/cms/Files => http://192.168.157.249:8000/cms/Files/
200      GET       36l       82w     1117c http://192.168.157.249:8000/cms/ADMIN.php
404      GET        9l       33w      304c http://192.168.157.249:8000/cms/cms/CMS
301      GET        9l       30w      352c http://192.168.157.249:8000/cms/CMS => http://192.168.157.249:8000/cms/CMS/
200      GET        2l        1w        6c http://192.168.157.249:8000/cms/Files/index.html
404      GET        9l       33w      304c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       30w      354c http://192.168.157.249:8000/cms/Media => http://192.168.157.249:8000/cms/Media/
200      GET        2l        1w        6c http://192.168.157.249:8000/cms/files/index.html
200      GET        1l        1w        4c http://192.168.157.249:8000/cms/cms/
301      GET        9l       30w      359c http://192.168.157.249:8000/cms/cms/images => http://192.168.157.249:8000/cms/cms/images/
301      GET        9l       30w      360c http://192.168.157.249:8000/cms/cms/modules => http://192.168.157.249:8000/cms/cms/modules/
301      GET        9l       30w      355c http://192.168.157.249:8000/cms/cms/js => http://192.168.157.249:8000/cms/cms/js/
301      GET        9l       30w      360c http://192.168.157.249:8000/cms/CMS/modules => http://192.168.157.249:8000/cms/CMS/modules/
301      GET        9l       30w      357c http://192.168.157.249:8000/cms/CMS/lang => http://192.168.157.249:8000/cms/CMS/lang/
301      GET        9l       30w      359c http://192.168.157.249:8000/cms/CMS/Images => http://192.168.157.249:8000/cms/CMS/Images/
301      GET        9l       30w      355c http://192.168.157.249:8000/cms/cms/JS => http://192.168.157.249:8000/cms/cms/JS/
301      GET        9l       30w      355c http://192.168.157.249:8000/cms/cms/Js => http://192.168.157.249:8000/cms/cms/Js/
301      GET        9l       30w      354c http://192.168.157.249:8000/cms/FILES => http://192.168.157.249:8000/cms/FILES/
301      GET        9l       30w      359c http://192.168.157.249:8000/cms/CMS/IMAGES => http://192.168.157.249:8000/cms/CMS/IMAGES/
[####################] - 3m   3060942/3060942 0s      found:94      errors:503650
[####################] - 3m    180000/180000  1021/s  http://192.168.157.249:8000/cms/
[####################] - 1s    180000/180000  348837/s http://192.168.157.249:8000/cms/templates/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 3m    180000/180000  1027/s  http://192.168.157.249:8000/cms/media/
[####################] - 3m    180000/180000  1029/s  http://192.168.157.249:8000/cms/files/
[####################] - 7s    180000/180000  25260/s http://192.168.157.249:8000/cms/Templates/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 3m    180000/180000  989/s   http://192.168.157.249:8000/cms/cms/
[####################] - 7s    180000/180000  25341/s http://192.168.157.249:8000/cms/templates/images/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s    180000/180000  25345/s http://192.168.157.249:8000/cms/templates/subtemplates/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 3m    180000/180000  1048/s  http://192.168.157.249:8000/cms/Files/
[####################] - 3m    180000/180000  1015/s  http://192.168.157.249:8000/cms/Media/
[####################] - 3m    180000/180000  1062/s  http://192.168.157.249:8000/cms/CMS/
[####################] - 3m    180000/180000  1088/s  http://192.168.157.249:8000/cms/cms/images/
[####################] - 3m    180000/180000  1052/s  http://192.168.157.249:8000/cms/cms/modules/
[####################] - 3m    180000/180000  1061/s  http://192.168.157.249:8000/cms/cms/js/
[####################] - 3m    180000/180000  1093/s  http://192.168.157.249:8000/cms/CMS/modules/
[####################] - 3m    180000/180000  1028/s  http://192.168.157.249:8000/cms/CMS/lang/
[####################] - 3m    180000/180000  1143/s  http://192.168.157.249:8000/cms/CMS/Images/
[####################] - 3m    180000/180000  1070/s  http://192.168.157.249:8000/cms/cms/JS/
[####################] - 3m    180000/180000  1101/s  http://192.168.157.249:8000/cms/cms/Js/   
```


`admin/admin` 로그인
![[Pasted image 20260813165943.png]]