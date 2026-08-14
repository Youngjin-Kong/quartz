## 192.168.157.169
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Feast/169]
└─$ nnmap 192.168.157.169
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 14:11 +0900
Nmap scan report for 192.168.157.169
Host is up (0.089s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-13 05:11:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: feast.com, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: feast.com, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: FEAST
|   NetBIOS_Domain_Name: FEAST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: feast.com
|   DNS_Computer_Name: DC01.feast.com
|   DNS_Tree_Name: feast.com
|   Product_Version: 10.0.17763
|_  System_Time: 2026-08-13T05:13:00+00:00
| ssl-cert: Subject: commonName=DC01.feast.com
| Not valid before: 2026-08-12T05:07:02
|_Not valid after:  2027-02-11T05:07:02
|_ssl-date: 2026-08-13T05:13:07+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/wsmans?
| tls-alpn:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T05:08:28
|_Not valid after:  2036-08-10T05:08:28
|_ssl-date: 2026-08-13T05:13:07+00:00; -1s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/13%OT=53%CT=1%CU=40587%PV=Y%DS=4%DC=T%G=Y%TM=6A7D526
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=I%CI=I%TS=U)SEQ(SP=1
OS:05%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=F7%GCD=1%ISR=103%TI=I%CI=I%TS=U)S
OS:EQ(SP=FC%GCD=1%ISR=106%TI=I%CI=I%TS=U)SEQ(SP=FE%GCD=1%ISR=110%TI=I%CI=I%
OS:TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M540NW8
OS:NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R
OS:=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R
OS:%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RU
OS:CK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-08-13T05:13:00
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   87.55 ms 192.168.45.1
2   87.46 ms 192.168.45.254
3   87.91 ms 192.168.251.1
4   88.33 ms 192.168.157.169

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.07 seconds
```


## 192.168.157.168
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Feast/168]
└─$ nnmap 192.168.157.168
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 14:13 +0900
Nmap scan report for 192.168.157.168
Host is up (0.089s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 d6:6b:4e:5d:40:0c:9b:b5:47:13:8f:da:aa:54:0b:1c (ECDSA)
|_  256 77:83:cd:7f:e5:94:af:17:b7:0f:e7:79:31:6e:d9:a1 (ED25519)
80/tcp open  http    TwistedWeb httpd 24.3.0
|_http-server-header: TwistedWeb/24.3.0
|_http-title: Site doesn''t have a title (text/plain; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/13%OT=22%CT=1%CU=38813%PV=Y%DS=4%DC=T%G=Y%TM=6A7D52B
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=103%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=104%GCD=1%ISR=10E%TI=Z%
OS:CI=Z%II=I%TS=A)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=106%G
OS:CD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M540ST11NW7%O2=M540ST11NW7%O3=M5
OS:40NNT11NW7%O4=M540ST11NW7%O5=M540ST11NW7%O6=M540ST11)WIN(W1=FEF4%W2=FEF4
OS:%W3=FEF4%W4=FEF4%W5=FEF4%W6=FEF4)ECN(R=Y%DF=Y%T=40%W=FC00%O=M540NNSNW7%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD
OS:=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=4
OS:0%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   87.66 ms 192.168.45.1
2   87.61 ms 192.168.45.254
3   88.35 ms 192.168.251.1
4   89.04 ms 192.168.157.168

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.81 seconds
```

## 192.168.157.170

`Eric.Wallows/EricLikesRunning800`
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Feast/170]
└─$ nnmap 192.168.157.170
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 14:19 +0900
Nmap scan report for 192.168.157.170
Host is up (0.088s latency).
Not shown: 65517 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: CloudSync - Your Ultimate File Synchronization Solution
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.2.12)
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: CloudSync - Your Ultimate File Synchronization Solution
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.23 or earlier (unauthorized)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-08-13T05:21:01+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: FEAST
|   NetBIOS_Domain_Name: FEAST
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: feast.com
|   DNS_Computer_Name: MS01.feast.com
|   DNS_Tree_Name: feast.com
|   Product_Version: 10.0.17763
|_  System_Time: 2026-08-13T05:20:52+00:00
| ssl-cert: Subject: commonName=MS01.feast.com
| Not valid before: 2026-08-12T05:10:03
|_Not valid after:  2027-02-11T05:10:03
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/wsmans?
| tls-alpn:
|   h2
|_  http/1.1
|_ssl-date: 2026-08-13T05:21:01+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T05:11:14
|_Not valid after:  2036-08-10T05:11:14
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/13%OT=80%CT=1%CU=34411%PV=Y%DS=4%DC=T%G=Y%TM=6A7D544
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=1
OS:06%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=1%ISR=10A%TI=I%CI=I%TS=U)
OS:SEQ(SP=FB%GCD=1%ISR=110%TI=I%CI=I%TS=U)SEQ(SP=FD%GCD=1%ISR=108%TI=I%CI=I
OS:%TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M540NW
OS:8NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(
OS:R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-13T05:20:53
|_  start_date: N/A

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   87.61 ms 192.168.45.1
2   87.58 ms 192.168.45.254
3   88.12 ms 192.168.251.1
4   88.29 ms 192.168.157.170

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.05 seconds
```

nxc-sweep 
```bash
┌──(kali㉿kali)-[~/PG/Feast/170]
└─$ nxc-sweep 192.168.157.170 -u 'Eric.Wallows' -p 'EricLikesRunning800'
[*] Starting NXC sweep for 192.168.157.170 as Eric.Wallows ...

[+] Port 445 open. Checking smb ...
SMB         192.168.157.170 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:feast.com) (signing:False) (SMBv1:False)
SMB         192.168.157.170 445    MS01             [-] feast.com\Eric.Wallows:EricLikesRunning800 STATUS_LOGON_FAILURE

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.157.170 5985   MS01             [*] Windows 10 / Server 2019 Build 17763 (name:MS01) (domain:feast.com)
WINRM       192.168.157.170 5985   MS01             [-] feast.com\Eric.Wallows:EricLikesRunning800

[+] Port 3389 open. Checking rdp ...
RDP         192.168.157.170 3389   MS01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:MS01) (domain:feast.com) (nla:True)
RDP         192.168.157.170 3389   MS01             [-] feast.com\Eric.Wallows:EricLikesRunning800 (STATUS_LOGON_FAILURE)

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```


80 웹페이지 접근 후 제공된 자격증명으로 로그인
![[Pasted image 20260813143025.png]]















## 192.168.157.171
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Feast/171]
└─$ nnmap 192.168.157.171
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-13 14:22 +0900
Nmap scan report for 192.168.157.171
Host is up (0.089s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/wsmans?
|_ssl-date: 2026-08-13T05:23:41+00:00; -1s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-12T05:11:32
|_Not valid after:  2036-08-10T05:11:32
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/13%OT=135%CT=1%CU=43928%PV=Y%DS=4%DC=T%G=Y%TM=6A7D54
OS:DF%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10F%TI=I%CI=I%TS=U)SEQ(SP=
OS:104%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=105%GCD=1%ISR=10B%TI=I%CI=I%TS=U
OS:)SEQ(SP=107%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=1%ISR=10D%TI=I%C
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
|   date: 2026-08-13T05:23:34
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   86.99 ms 192.168.45.1
2   86.89 ms 192.168.45.254
3   88.39 ms 192.168.251.1
4   90.15 ms 192.168.157.171

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.16 seconds
```

