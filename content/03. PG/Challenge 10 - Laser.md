### Nmap
```bash
┌──(kali㉿kali)-[~/PG/laser]
└─$ nnmap 192.168.144.172
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-12 09:43 +0900
Nmap scan report for 192.168.144.172
Host is up (0.084s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-12 00:43:52Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: laser.com, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: laser.com, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: LASER
|   NetBIOS_Domain_Name: LASER
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: laser.com
|   DNS_Computer_Name: DC01.laser.com
|   DNS_Tree_Name: laser.com
|   Product_Version: 10.0.17763
|_  System_Time: 2026-08-12T00:45:03+00:00
| ssl-cert: Subject: commonName=DC01.laser.com
| Not valid before: 2026-08-11T00:20:11
|_Not valid after:  2027-02-10T00:20:11
|_ssl-date: 2026-08-12T00:45:10+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/wsmans?
| tls-alpn:
|   h2
|_  http/1.1
|_ssl-date: 2026-08-12T00:45:10+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-11T00:21:45
|_Not valid after:  2036-08-09T00:21:45
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49785/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/12%OT=53%CT=1%CU=40965%PV=Y%DS=4%DC=T%G=Y%TM=6A7BC21
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=2%ISR=10F%TI=I%CI=I%TS=U)SEQ(SP=1
OS:06%GCD=1%ISR=109%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=1%ISR=10B%TI=I%CI=I%TS=U)
OS:SEQ(SP=107%GCD=1%ISR=10C%TI=I%CI=I%TS=U)SEQ(SP=109%GCD=1%ISR=109%TI=I%CI
OS:=I%TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M540
OS:NW8NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)EC
OS:N(R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%
OS:F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G
OS:%RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-08-12T00:45:04
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   82.36 ms 192.168.45.1
2   82.40 ms 192.168.45.254
3   83.63 ms 192.168.251.1
4   84.88 ms 192.168.144.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.49 seconds
```

### Nmap
```bash
┌──(kali㉿kali)-[~/PG/laser]
└─$ nnmap 192.168.144.173
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-12 09:47 +0900
Nmap scan report for 192.168.144.173
Host is up (0.085s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/wsmans?
| tls-alpn:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-11T00:23:33
|_Not valid after:  2036-08-09T00:23:33
|_ssl-date: 2026-08-12T00:48:58+00:00; 0s from scanner time.
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
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/12%OT=135%CT=1%CU=41132%PV=Y%DS=4%DC=T%G=Y%TM=6A7BC2
OS:FA%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=
OS:103%GCD=1%ISR=108%TI=I%CI=I%TS=U)SEQ(SP=105%GCD=1%ISR=10C%TI=I%CI=I%TS=U
OS:)SEQ(SP=106%GCD=1%ISR=107%TI=I%CI=I%TS=U)SEQ(SP=109%GCD=1%ISR=10B%TI=I%C
OS:I=I%TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M54
OS:0NW8NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)E
OS:CN(R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O
OS:%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=
OS:G%RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-12T00:48:53
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   83.81 ms 192.168.45.1
2   83.77 ms 192.168.45.254
3   84.90 ms 192.168.251.1
4   84.99 ms 192.168.144.173

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.12 seconds
```

192.168.144.173 
`Eric.Wallows / EricLikesRunning800`

smb 폴더 확인
```bash
┌──(kali㉿kali)-[~/PG/laser]
└─$ nxc smb 192.168.144.173 -u 'Eric.Wallows' -p 'EricLikesRunning800' --shares
SMB         192.168.144.173 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:laser.com) (signing:False) (SMBv1:False)
SMB         192.168.144.173 445    MS01             [+] laser.com\Eric.Wallows:EricLikesRunning800
SMB         192.168.144.173 445    MS01             [*] Enumerated shares
SMB         192.168.144.173 445    MS01             Share           Permissions     Remark
SMB         192.168.144.173 445    MS01             -----           -----------     ------
SMB         192.168.144.173 445    MS01             ADMIN$                          Remote Admin
SMB         192.168.144.173 445    MS01             Apps            READ,WRITE
SMB         192.168.144.173 445    MS01             C$                              Default share
SMB         192.168.144.173 445    MS01             IPC$            READ            Remote IPC
```

```bash
┌──(kali㉿kali)-[~/PG/laser]
└─$ smbclient //192.168.144.173/Apps/ -U 'laser.com/Eric.wallows'
Password for [LASER.COM\Eric.wallows]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Aug 12 13:39:23 2026
  ..                                  D        0  Wed Aug 12 13:39:23 2026
  Event Viewer.lnk                    A     1168  Sat Sep 15 16:12:46 2018
  Print Management.lnk                A     1118  Sat Sep 15 16:13:16 2018
  Services.lnk                        A     1158  Sat Sep 15 16:12:52 2018
  Task Scheduler.lnk                  A     1132  Sat Sep 15 16:12:23 2018

                13106687 blocks of size 4096. 10140597 blocks available
```

