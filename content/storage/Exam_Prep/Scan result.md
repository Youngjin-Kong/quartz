
## 172.16.115.200

## 172.16.115.202

## 192.168.115.206
```
Scanning 192.168.115.206 [4 ports]
Completed Ping Scan at 12:27, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:27
Completed Parallel DNS resolution of 1 host. at 12:27, 0.50s elapsed
Initiating SYN Stealth Scan at 12:27
Scanning 192.168.115.206 [65535 ports]
Discovered open port 3389/tcp on 192.168.115.206
Discovered open port 80/tcp on 192.168.115.206
Discovered open port 445/tcp on 192.168.115.206
Discovered open port 139/tcp on 192.168.115.206
Discovered open port 443/tcp on 192.168.115.206
Discovered open port 3306/tcp on 192.168.115.206
Discovered open port 135/tcp on 192.168.115.206
Discovered open port 5985/tcp on 192.168.115.206
Discovered open port 49670/tcp on 192.168.115.206
Discovered open port 49665/tcp on 192.168.115.206
Discovered open port 49668/tcp on 192.168.115.206
Discovered open port 49671/tcp on 192.168.115.206
Discovered open port 49671/tcp on 192.168.115.206
SYN Stealth Scan Timing: About 46.09% done; ETC: 12:29 (0:00:36 remaining)
Discovered open port 47001/tcp on 192.168.115.206
Discovered open port 49669/tcp on 192.168.115.206
Discovered open port 1433/tcp on 192.168.115.206
Discovered open port 49667/tcp on 192.168.115.206
Discovered open port 49666/tcp on 192.168.115.206
Discovered open port 49664/tcp on 192.168.115.206
Completed SYN Stealth Scan at 12:29, 66.44s elapsed (65535 total ports)
Nmap scan report for 192.168.115.206
Host is up (0.19s latency).
Not shown: 65517 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
3306/tcp  open  mysql
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 67.30 seconds
           Raw packets sent: 66255 (2.915MB) | Rcvd: 66252 (2.650MB)

```

## 192.168.115.110
```
Scanning 192.168.115.110 [65535 ports]
Discovered open port 22/tcp on 192.168.115.110
Discovered open port 3306/tcp on 192.168.115.110
SYN Stealth Scan Timing: About 23.02% done; ETC: 12:32 (0:01:44 remaining)
SYN Stealth Scan Timing: About 45.90% done; ETC: 12:32 (0:01:12 remaining)
SYN Stealth Scan Timing: About 68.81% done; ETC: 12:32 (0:00:41 remaining)
Discovered open port 873/tcp on 192.168.115.110
Completed SYN Stealth Scan at 12:32, 126.84s elapsed (65535 total ports)
Nmap scan report for 192.168.115.110
Host is up (0.19s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   closed http
443/tcp  closed https
873/tcp  open   rsync
3306/tcp open   mysql

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 127.67 seconds
           Raw packets sent: 131156 (5.771MB) | Rcvd: 92 (3.692KB)

```
## 172.16.115.200
```
Nmap scan report for 172.16.115.200
Host is up (0.38s latency).
Not shown: 65510 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-15 12:25:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49801/tcp open  msrpc         Microsoft Windows RPC
60332/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC20; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-08-15T12:26:42
|_  start_date: N/A
|_clock-skew: -1s
| nbstat: NetBIOS name: DC20, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:8a:62:bd (VMware)
| Names:
|   DC20<20>             Flags: <unique><active>
|   DC20<00>             Flags: <unique><active>
|   OSCP<00>             Flags: <group><active>
|   OSCP<1c>             Flags: <group><active>
|_  OSCP<1b>             Flags: <unique><active>

NSE: Script Post-scanning.
Initiating NSE at 21:27
Completed NSE at 21:27, 0.00s elapsed
Initiating NSE at 21:27
Completed NSE at 21:27, 0.00s elapsed
Initiating NSE at 21:27
Completed NSE at 21:27, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 859.94 seconds
           Raw packets sent: 721180 (31.732MB) | Rcvd: 598 (25.116KB)

```

## 172.168.115.202
```
Nmap scan report for 172.16.115.202
Host is up (4.3s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -2s
| smb2-time: 
|   date: 2026-08-15T12:21:27
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

NSE: Script Post-scanning.
Initiating NSE at 21:25
Completed NSE at 21:25, 0.00s elapsed
Initiating NSE at 21:25
Completed NSE at 21:25, 0.00s elapsed
Initiating NSE at 21:25
Completed NSE at 21:25, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 685.30 seconds
           Raw packets sent: 327873 (14.426MB) | Rcvd: 168 (7.056KB )
```



## 192.168.115.111

```
Scanning 192.168.115.111 [65535 ports]
Discovered open port 445/tcp on 192.168.115.111
Discovered open port 21/tcp on 192.168.115.111
Discovered open port 135/tcp on 192.168.115.111
Discovered open port 8080/tcp on 192.168.115.111
Discovered open port 80/tcp on 192.168.115.111
Discovered open port 443/tcp on 192.168.115.111
Discovered open port 139/tcp on 192.168.115.111
Discovered open port 49666/tcp on 192.168.115.111
Discovered open port 8443/tcp on 192.168.115.111
Discovered open port 5985/tcp on 192.168.115.111
Discovered open port 49667/tcp on 192.168.115.111
Discovered open port 49668/tcp on 192.168.115.111
Discovered open port 5040/tcp on 192.168.115.111
SYN Stealth Scan Timing: About 45.57% done; ETC: 12:37 (0:00:37 remaining)
Discovered open port 49669/tcp on 192.168.115.111
Discovered open port 49664/tcp on 192.168.115.111
Discovered open port 49665/tcp on 192.168.115.111
Discovered open port 47001/tcp on 192.168.115.111
Completed SYN Stealth Scan at 12:37, 67.45s elapsed (65535 total ports)
Nmap scan report for 192.168.115.111
Host is up (0.19s latency).
Not shown: 65518 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
5985/tcp  open  wsman
8080/tcp  open  http-proxy
8443/tcp  open  https-alt
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 68.31 seconds
           Raw packets sent: 67266 (2.960MB) | Rcvd: 66315 (2.653MB)

```
## 192.168.115.112
```
Scanning 192.168.115.112 [65535 ports]
Discovered open port 80/tcp on 192.168.115.112
Discovered open port 135/tcp on 192.168.115.112
Discovered open port 139/tcp on 192.168.115.112
Discovered open port 445/tcp on 192.168.115.112
Discovered open port 3389/tcp on 192.168.115.112
Discovered open port 49666/tcp on 192.168.115.112
Discovered open port 49670/tcp on 192.168.115.112
Discovered open port 49665/tcp on 192.168.115.112
Discovered open port 49664/tcp on 192.168.115.112
Discovered open port 49667/tcp on 192.168.115.112
SYN Stealth Scan Timing: About 45.86% done; ETC: 12:47 (0:00:37 remaining)
Discovered open port 5985/tcp on 192.168.115.112
Discovered open port 47001/tcp on 192.168.115.112
Discovered open port 49668/tcp on 192.168.115.112
Discovered open port 49669/tcp on 192.168.115.112
Completed SYN Stealth Scan at 12:47, 66.63s elapsed (65535 total ports)
Nmap scan report for 192.168.115.112
Host is up (0.19s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 67.48 seconds
           Raw packets sent: 66449 (2.924MB) | Rcvd: 66001 (2.640MB)

```